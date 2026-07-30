mod audit;
mod cli;
mod net;
mod profile;
mod sandbox;
mod security_groups;
mod setup;
mod signing;

use anyhow::{Context, Result};
use clap::Parser;

use cli::Cli;
use cli::Cmd;

fn main() {
    let cli = Cli::parse();
    let rc = match cli.cmd {
        Cmd::Run {
            profile,
            allow_cwd,
            allow,
            read_only,
            block_net,
            allow_domain,
            network_profile,
            print_sid,
            sid,
            cmd,
        } => run_cmd(
            profile,
            allow_cwd,
            allow,
            read_only,
            block_net,
            allow_domain,
            network_profile,
            print_sid,
            sid,
            cmd,
        ),
        Cmd::Ps { json, .. } => ps_cmd(json),
        Cmd::Audit { action } => audit_cmd(action),
        Cmd::Profile { action } => profile_cmd(action),
        Cmd::Setup {
            check_only,
            grant_drive_root,
        } => {
            if let Err(e) = setup::check(check_only, grant_drive_root) {
                eprintln!("[sandbox] setup check failed: {e:#}");
                std::process::exit(1);
            }
            0
        }
    };
    std::process::exit(rc);
}

fn ps_cmd(json: bool) -> i32 {
    // Minimal: list the most recent audit log's sid.
    let dir = match std::env::var_os("LOCALAPPDATA").map(std::path::PathBuf::from) {
        Some(p) => p.join("sandbox").join("audit"),
        None => {
            eprintln!("[sandbox] LOCALAPPDATA not set");
            return 1;
        }
    };
    let mut entries: Vec<(std::time::SystemTime, String)> = Vec::new();
    if let Ok(rd) = std::fs::read_dir(&dir) {
        for e in rd.flatten() {
            if let Some(name) = e.file_name().to_str()
                && let Some(sid) = name.strip_suffix(".ndjson")
                && let Ok(mtime) = e.metadata().and_then(|m| m.modified())
            {
                entries.push((mtime, sid.to_string()));
            }
        }
    }
    entries.sort_by_key(|e| std::cmp::Reverse(e.0)); // newest first
    if json {
        if let Some((_, sid)) = entries.first() {
            println!(r#"{{"session_id":"{sid}","running":false}}"#);
        } else {
            println!(r#"{{"session_id":null,"running":false}}"#);
        }
    } else {
        if let Some((_, sid)) = entries.first() {
            println!("{sid}");
        } else {
            println!("(no sessions)");
        }
    }
    0
}

fn audit_cmd(action: cli::AuditAction) -> i32 {
    use cli::AuditAction;
    match action {
        AuditAction::Show {
            session_id,
            json,
            filter,
        } => audit::show::run_show(&session_id, json, filter.as_deref()),
        AuditAction::Verify { session_id } => audit::verify::run_verify(&session_id),
    }
}

fn profile_cmd(action: cli::ProfileAction) -> i32 {
    use cli::ProfileAction;
    match action {
        ProfileAction::List => {
            let entries = profile::list_profiles();
            if entries.is_empty() {
                let dir = cli::profiles_dir();
                println!("(no profiles in {})", dir.display());
                return 0;
            }
            for e in &entries {
                println!("{}\t{}", e.name, e.source_path.display());
            }
            0
        }
        ProfileAction::Show { name, expanded } => profile::show_profile(&name, expanded),
    }
}

fn commit_audit_root(sid: &str, root: &str) -> Result<()> {
    let key = signing::KeyMaterial::ensure()?;
    let root_bytes =
        decode_hex_vec(root).ok_or_else(|| anyhow::anyhow!("root is not valid hex: {root}"))?;
    let sig = key.sign_root(&root_bytes);
    let sig_hex: String = sig.iter().map(|b| format!("{:02x}", b)).collect();
    let log_path = audit::audit_log_path(sid);
    std::fs::write(log_path.with_extension("root"), root)?;
    std::fs::write(log_path.with_extension("sig"), &sig_hex)?;
    Ok(())
}

fn decode_hex_vec(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn run_cmd(
    profile: Option<String>,
    allow_cwd: bool,
    allow: Vec<String>,
    read_only: Vec<String>,
    block_net: bool,
    allow_domain: Vec<String>,
    network_profile: Option<String>,
    print_sid: bool,
    sid: Option<String>,
    cmd: Vec<String>,
) -> i32 {
    if let Err(e) = setup::check_runtime() {
        eprintln!("[sandbox] {e:#}");
        return 1;
    }

    match run_inner(
        profile.as_deref(),
        allow_cwd,
        &allow,
        &read_only,
        block_net,
        &allow_domain,
        network_profile.as_deref(),
        print_sid,
        sid.as_deref(),
        &cmd,
    ) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("[sandbox] {e:#}");
            1
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn run_inner(
    profile_name: Option<&str>,
    allow_cwd: bool,
    allow: &[String],
    read_only: &[String],
    block_net: bool,
    allow_domain: &[String],
    network_profile: Option<&str>,
    print_sid: bool,
    sid: Option<&str>,
    cmd: &[String],
) -> Result<i32> {
    let cwd = std::env::current_dir().context("get current directory")?;

    // Load + resolve profile (filesystem slice only for this slice).
    let resolved = match profile_name {
        Some(name) => profile::load_and_resolve(name, &cwd)?,
        None => profile::ResolvedProfile::default(),
    };

    // Resolve the network configuration from the profile slice + CLI flags.
    let net_cfg_resolved =
        net::resolve_network(&resolved.network, block_net, allow_domain, network_profile);

    // Merge CLI flags on top of the profile.
    let fs = profile::merge_filesystem(&resolved.filesystem, allow_cwd, allow, read_only, &cwd)?;

    let sid = match sid {
        Some(s) => s.to_string(),
        None => new_session_id(),
    };

    // MXC F-C/F-D: before any host-DACL mutation, reap journals of dead
    // owners (restore their entries, quarantine corrupt ones). Then open
    // this run's journal. Failure to open is a warning only — the run
    // proceeds unjournaled.
    let journal_dir = sandbox::dacl_journal::default_dir();
    sandbox::dacl_journal::recover_orphans(
        &journal_dir,
        &|h| !sandbox::dacl_journal::is_process_alive(h.owner_pid, h.owner_created),
        &|j| sandbox::appcontainer::restore_or_warn(j),
    );
    let run_journal = match sandbox::dacl_journal::DaclJournal::open(
        &journal_dir,
        sandbox::dacl_journal::JournalHeader {
            run_id: sid.clone(),
            owner_pid: std::process::id(),
            owner_created: sandbox::dacl_journal::current_process_creation_time(),
        },
    ) {
        Ok(j) => Some(j),
        Err(e) => {
            eprintln!("[sandbox] warning: DACL journal unavailable: {e}");
            None
        }
    };

    // Ensure the per-session install dirs exist.
    sandbox::ensure_session_dirs(&cwd, &sid)
        .with_context(|| format!("create session dirs for {sid}"))?;

    if print_sid {
        println!("{sid}");
        return Ok(0);
    }

    if cmd.is_empty() {
        return Ok(0);
    }

    // Open the audit writer for this session and emit a SESSION_START leaf so
    // every session has at least one audit event (ensures `verify` can always
    // produce a root, even under the US-3 loopback downgrade where no proxy
    // starts and thus no CONNECT events fire).
    let audit_writer = std::sync::Arc::new(audit::AuditWriter::open(&sid));
    {
        use serde_json::{Map, json};
        let mut e = Map::new();
        e.insert("op".into(), json!("SESSION_START"));
        e.insert("sid".into(), json!(sid));
        e.insert("command".into(), json!(cmd.join(" ")));
        e.insert("disposition".into(), json!("allow"));
        audit_writer.append(e);
    }

    // The localhost-proxy + loopback-exemption mechanism for --allow-domain /
    // --network-profile requires `NetworkIsolationSetAppContainerConfig`, which
    // is admin-only (it sets a system-wide loopback-allow list "for debugging
    // purposes" per MSDN). The unprivileged alternative (a
    // `privateNetworkClientServer` capability SID on the AppContainer token) is
    // tracked as a follow-up. Until that lands, --allow-domain /
    // --network-profile are accepted but downgraded to block-net semantics with
    // a clear warning. --block-net itself works fully unprivileged.
    let net_cfg = match &net_cfg_resolved {
        net::NetworkConfig::Allow { .. } => {
            eprintln!(
                "[sandbox] warning: --allow-domain / --network-profile are deferred in this slice"
            );
            eprintln!(
                "[sandbox]          (the loopback exemption API is admin-only; the unprivileged"
            );
            eprintln!(
                "[sandbox]          privateNetworkClientServer-capability path is a follow-up)."
            );
            eprintln!("[sandbox]          Downgrading this session to --block-net semantics.");
            net::NetworkConfig::Blocked
        }
        other => other.clone(),
    };

    // Build the AppContainer session.
    let session = sandbox::create_session(&sid)
        .with_context(|| format!("create AppContainer session for {sid}"))?;

    // Register loopback for the AC SID BEFORE spawning the proxy (the proxy
    // doesn't need it, but registering before the child starts is the safe
    // order). Skip when blocked (no proxy to reach).
    if !net_cfg.is_blocked()
        && let Err(e) = net::loopback::register_loopback(&session.ac_sid)
    {
        eprintln!("[sandbox] warning: loopback exemption failed: {e}");
        eprintln!("[sandbox]          direct connects to the proxy will be denied.");
    }

    // Start the proxy (if not blocked) and hold the handle until the child
    // exits. The handle MUST outlive `sandbox::spawn` below so the proxy
    // stays up while the child runs.
    let proxy_env: Option<net::ProxyEnv>;
    let _proxy_handle: Option<net::proxy::ProxyHandle> = match &net_cfg {
        net::NetworkConfig::Blocked => {
            proxy_env = None;
            None
        }
        net::NetworkConfig::Allow { allow_domain, .. } => {
            let token = net::token::gen_token().context("generate session token")?;
            let handle = net::proxy::spawn(net::proxy::ProxyConfig {
                session_id: sid.clone(),
                token: token.clone(),
                allow_domain: allow_domain.clone(),
                writer: audit_writer.clone(),
            })
            .context("start localhost proxy")?;
            proxy_env = Some(net::ProxyEnv {
                port: handle.port,
                token,
            });
            Some(handle)
        }
    };

    // Build the full allow-list (Option E per-session dirs + resolved profile entries).
    let entries = sandbox::build_allowlist(&sid, &cwd, &fs)?;

    if let Err(e) = sandbox::grant_access(&session.ac_sid, &entries, run_journal.as_ref()) {
        eprintln!("[sandbox] warning: some ACL grants failed: {e}");
    }

    let env_block = sandbox::build_env_block(&sid, &cwd, proxy_env.as_ref());

    let cmdline = join_cmdline(cmd);

    let job = sandbox::Job::create().context("create Job Object")?;

    let exit_code = sandbox::spawn(&session, &job, &cwd, env_block, &cmdline, !net_cfg.is_blocked())
        .context("spawn sandboxed process")?;

    // US-4a: commit the audit root + signature on clean child exit.
    //
    // IMPORTANT — ProxyHandle::drop does NOT join the proxy thread (it cancels
    // the token and detaches the JoinHandle, then shutdown_background — non-
    // blocking). So if we dropped the proxy handle and then re-opened the log
    // to read the root, we'd race the proxy thread's last `append`. To avoid
    // that, we capture `current_root()` from the still-alive Arc<AuditWriter>
    // BEFORE dropping anything. The `last_hash` Mutex inside the writer is
    // updated synchronously by `append`, so `current_root()` always reflects
    // the latest committed leaf — even if the proxy thread is still flushing
    // the file write (the in-memory hash is set before the file write returns).
    //
    // We then drop the proxy handle + our Arc<AuditWriter> (releasing the file
    // handle) and write the root+sig using the captured root string. No reopen
    // needed.
    let captured_root = audit_writer.current_root();

    // Drop the proxy handle (cancels token, detaches the task — non-blocking).
    // The proxy thread may still be mid-`append` to the file, but the in-memory
    // `last_hash` is already captured above. We sleep briefly to let the proxy
    // thread finish its in-flight file writes after cancellation.
    drop(_proxy_handle);
    std::thread::sleep(std::time::Duration::from_millis(50));

    // Drop our Arc<AuditWriter>. The proxy thread's Arc may still be alive (it
    // was detached), but `AuditWriter::append` holds the file open with
    // `OpenOptions::append(true).create(true)` per call (no long-lived handle),
    // so dropping the Arc just releases the in-memory state. The file on disk
    // is already consistent up to the last `append`.
    drop(audit_writer);

    if let Some(root) = captured_root
        && let Err(e) = commit_audit_root(&sid, &root)
    {
        eprintln!("[sandbox] warning: failed to commit audit root: {e:#}");
        // The log is still readable; verify will report INCOMPLETE.
    }

    // MXC F-C/F-D teardown order matters: restore host DACLs BEFORE deleting
    // the profile (a crash between the two leaves restorable journal state,
    // not re-derivable grants). Journal file is removed ONLY on success.
    if let Some(j) = &run_journal {
        let ok = sandbox::appcontainer::restore_or_warn(j);
        if ok {
            j.remove_file();
        }
    }
    sandbox::appcontainer::delete_profile(&session.ac_name);

    Ok(exit_code as i32)
}

fn new_session_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let pid = std::process::id() as u64;
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u64)
        .unwrap_or(0);
    let seq = (nanos ^ pid.rotate_left(16)) % 100_000;
    let secs = now;
    let dt = chrono_from_unix(secs);
    format!("{dt}-{seq:05}")
}

/// Format the unix timestamp as YYYYMMDD-HHMMSS (UTC). Avoids pulling chrono by
/// implementing a tiny civil-from-days conversion.
fn chrono_from_unix(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let hour = rem / 3600;
    let minute = (rem % 3600) / 60;
    let second = rem % 60;

    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };

    format!("{y:04}{m:02}{d:02}-{hour:02}{minute:02}{second:02}")
}

/// Quote + join command tokens into a single command line for CreateProcessW.
fn join_cmdline(tokens: &[String]) -> String {
    fn quote_arg(a: &str) -> String {
        if a.is_empty() {
            "\"\"".to_string()
        } else if a.contains(' ') || a.contains('\t') {
            let escaped = a.replace('\\', "\\\\").replace('"', "\\\"");
            format!("\"{escaped}\"")
        } else {
            a.to_string()
        }
    }
    tokens
        .iter()
        .map(|t| quote_arg(t))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_id_format() {
        let id = new_session_id();
        // YYYYMMDD-HHMMSS-NNNNN  (8 + 1 + 6 + 1 + 5 = 21).
        assert_eq!(id.len(), 21);
        assert_eq!(id.as_bytes()[8], b'-');
        assert_eq!(id.as_bytes()[15], b'-');
    }

    #[test]
    fn chrono_basic() {
        // 1970-01-01 00:00:00 UTC == 0 seconds.
        assert_eq!(chrono_from_unix(0), "19700101-000000");
        // 1970-01-02 00:00:00 UTC.
        assert_eq!(chrono_from_unix(86_400), "19700102-000000");
        // A known date: 2024-01-01 00:00:00 UTC == 1704067200.
        assert_eq!(chrono_from_unix(1_704_067_200), "20240101-000000");
    }

    #[test]
    fn join_cmdline_quotes_spaces() {
        assert_eq!(
            join_cmdline(&["echo".into(), "hello world".into()]),
            "echo \"hello world\""
        );
        assert_eq!(join_cmdline(&["echo".into(), "".into()]), "echo \"\"");
        assert_eq!(join_cmdline(&["a".into()]), "a");
    }
}
