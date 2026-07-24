mod cli;
mod net;
mod profile;
mod sandbox;
mod security_groups;
mod setup;

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
            print_sid,
            sid,
            cmd,
        ),
        Cmd::Ps { .. } => stub_not_implemented("ps"),
        Cmd::Audit { .. } => stub_not_implemented("audit"),
        Cmd::Profile { .. } => stub_not_implemented("profile"),
        Cmd::Setup { check_only } => {
            if let Err(e) = setup::check(check_only) {
                eprintln!("[sandbox] setup check failed: {e:#}");
                std::process::exit(1);
            }
            0
        }
    };
    std::process::exit(rc);
}

/// Stub for subcommands that aren't implemented in this slice.
fn stub_not_implemented(name: &str) -> i32 {
    eprintln!("[sandbox] `{name}` is not implemented in this MVP slice.");
    2
}

fn run_cmd(
    profile: Option<String>,
    allow_cwd: bool,
    allow: Vec<String>,
    read_only: Vec<String>,
    block_net: bool,
    allow_domain: Vec<String>,
    print_sid: bool,
    sid: Option<String>,
    cmd: Vec<String>,
) -> i32 {
    if block_net {
        eprintln!("[sandbox] --block-net accepted (network filtering not yet implemented)");
    }
    if !allow_domain.is_empty() {
        eprintln!(
            "[sandbox] --allow-domain accepted (network filtering not yet implemented): {}",
            allow_domain.join(", ")
        );
    }

    if let Err(e) = setup::check_runtime() {
        eprintln!("[sandbox] {e:#}");
        return 1;
    }

    match run_inner(
        profile.as_deref(),
        allow_cwd,
        &allow,
        &read_only,
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

fn run_inner(
    profile_name: Option<&str>,
    allow_cwd: bool,
    allow: &[String],
    read_only: &[String],
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

    // Merge CLI flags on top of the profile.
    let fs = profile::merge_filesystem(&resolved.filesystem, allow_cwd, allow, read_only, &cwd)?;

    let sid = match sid {
        Some(s) => s.to_string(),
        None => new_session_id(),
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

    // Build the AppContainer session.
    let session = sandbox::create_session(&sid)
        .with_context(|| format!("create AppContainer session for {sid}"))?;

    // Build the full allow-list (Option E per-session dirs + resolved profile entries).
    let entries = sandbox::build_allowlist(&sid, &cwd, &fs)?;

    if let Err(e) = sandbox::grant_access(&session.ac_sid, &entries) {
        eprintln!("[sandbox] warning: some ACL grants failed: {e}");
    }

    let env_block = sandbox::build_env_block(&sid, &cwd);

    let cmdline = join_cmdline(cmd);

    let job = sandbox::Job::create().context("create Job Object")?;

    let exit_code = sandbox::spawn(&session, &job, &cwd, env_block, &cmdline)
        .context("spawn sandboxed process")?;

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
    let rem = (secs % 86_400) as u64;
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
    tokens.iter().map(|t| quote_arg(t)).collect::<Vec<_>>().join(" ")
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
        assert_eq!(join_cmdline(&["echo".into(), "hello world".into()]), "echo \"hello world\"");
        assert_eq!(join_cmdline(&["echo".into(), "".into()]), "echo \"\"");
        assert_eq!(join_cmdline(&["a".into()]), "a");
    }
}
