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

/// Whether the MXC backend is wired into the session path. P0 lands the seam
/// only; until the launch path routes through it, `--backend mxc` is refused
/// rather than falling back to `appcontainer` (`cli::route_backend`).
const MXC_SESSION_WIRED: bool = false;

/// Serializes the tests that read or mutate process-wide environment variables
/// (`USERPROFILE` in particular). Those tests share one global process state, so
/// an unlocked reader can observe a mutator's temporary value and fail for a
/// reason that has nothing to do with the code under test.
#[cfg(test)]
pub(crate) static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Take [`ENV_LOCK`], tolerating a previous holder's panic (the value it guards
/// is the process environment itself, so a poisoned lock carries no state).
#[cfg(test)]
pub(crate) fn env_lock() -> std::sync::MutexGuard<'static, ()> {
    ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

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
            deny_domain,
            no_prompt,
            network_profile,
            audit_strict,
            backend,
            print_sid,
            sid,
            cmd,
        } => run_cmd(
            backend,
            profile,
            allow_cwd,
            allow,
            read_only,
            block_net,
            allow_domain,
            deny_domain,
            no_prompt,
            network_profile,
            audit_strict,
            print_sid,
            sid,
            cmd,
        ),
        Cmd::Ps { json, .. } => ps_cmd(json),
        Cmd::Audit { action } => audit_cmd(action),
        Cmd::Profile { action } => profile_cmd(action),
        Cmd::Learned {
            subcommand,
            profile,
        } => learned_cmd(subcommand, profile),
        Cmd::Setup {
            check_only,
            grant_drive_root,
            enable_loopback,
        } => {
            if let Err(e) = setup::check(check_only, grant_drive_root, enable_loopback) {
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

fn learned_cmd(action: cli::LearnedSub, profile: Option<String>) -> i32 {
    let base = std::env::var_os("USERPROFILE")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    let (rc, out, err) = learned_cmd_in(action, profile.as_deref(), &base);
    print!("{out}");
    eprint!("{err}");
    rc
}

/// Core of `sandbox learned`, rooted at `base` and returning the exit
/// code plus the stdout/stderr text (printed by [`learned_cmd`]). Split
/// out so the behavior is unit-testable against temp dirs without
/// capturing real process output.
fn learned_cmd_in(
    action: cli::LearnedSub,
    profile: Option<&str>,
    base: &std::path::Path,
) -> (i32, String, String) {
    use cli::LearnedSub;
    match action {
        LearnedSub::List => match net::learned::LearnedStore::load_in(base, profile) {
            Ok(store) => {
                let entries = store.entries();
                if entries.is_empty() {
                    return (0, "(no learned entries)\n".to_string(), String::new());
                }
                // Aligned plain-text columns, no color codes (`sandbox ps`
                // style). Suffix entries keep the `*.` prefix they are
                // stored with, so `list` shows the exact revoke key.
                let host_w = entries
                    .iter()
                    .map(|e| e.0.len())
                    .max()
                    .unwrap_or(0)
                    .max("HOST".len());
                let scope_w = entries
                    .iter()
                    .map(|e| e.1.len())
                    .max()
                    .unwrap_or(0)
                    .max("SCOPE".len());
                let mut out = format!("{:<host_w$}  {:<scope_w$}  DISPOSITION\n", "HOST", "SCOPE");
                for (host, scope, allow) in &entries {
                    let disposition = if *allow { "allow" } else { "deny" };
                    out.push_str(&format!(
                        "{:<host_w$}  {:<scope_w$}  {disposition}\n",
                        host, scope
                    ));
                }
                (0, out, String::new())
            }
            Err(e) => learned_load_failure(e),
        },
        LearnedSub::Revoke { host } => match net::learned::LearnedStore::load_in(base, profile) {
            Ok(mut store) => match store.revoke(&host) {
                Ok(true) => (0, format!("revoked {host}\n"), String::new()),
                // A missing entry fails loudly rather than silently
                // succeeding — honest behavior for a scripted CLI.
                Ok(false) => (
                    1,
                    String::new(),
                    format!(
                        "[sandbox] no learned entry for {host} \
                         (run `sandbox learned list` to see stored keys)\n"
                    ),
                ),
                Err(e) => (
                    1,
                    String::new(),
                    format!("[sandbox] failed to rewrite learned file: {e:#}\n"),
                ),
            },
            Err(e) => learned_load_failure(e),
        },
        LearnedSub::Clear => {
            // [G-5] recovery: a corrupt learned file hard-aborts
            // `sandbox run`, and `clear` is the only non-editorial way
            // out — so it must succeed even when the file cannot be
            // loaded. Happy path reuses `LearnedStore::clear`; the
            // unloadable case rewrites the file empty directly.
            let cleared = match net::learned::LearnedStore::load_in(base, profile) {
                Ok(mut store) => store.clear(),
                Err(_) => net::learned::clear_learned_file_in(base, profile),
            };
            match cleared {
                Ok(()) => (0, String::new(), String::new()),
                Err(e) => (
                    1,
                    String::new(),
                    format!("[sandbox] failed to clear learned file: {e:#}\n"),
                ),
            }
        }
    }
}

/// Load failure for list/revoke: corrupt file, schema mismatch, or a
/// rejected profile name all point the user at the [G-5] recovery path.
fn learned_load_failure(e: anyhow::Error) -> (i32, String, String) {
    (
        1,
        String::new(),
        format!(
            "[sandbox] failed to load learned file: {e:#} \
             (run `sandbox learned clear` to reset it)\n"
        ),
    )
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

/// [G-10] Where the chosen upstream proxy came from.
///
/// Named in diagnostics: when a configured proxy cannot be used, the operator
/// has to know which knob to fix ([G-42]).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum UpstreamSource {
    /// `network.upstreamProxy` in the profile.
    Profile,
    /// The host's `HTTPS_PROXY` / `HTTP_PROXY`.
    HostEnv,
}

impl UpstreamSource {
    fn label(self) -> &'static str {
        match self {
            UpstreamSource::Profile => "profile network.upstreamProxy",
            UpstreamSource::HostEnv => "host HTTPS_PROXY/HTTP_PROXY",
        }
    }
}

/// [G-10] Pick the upstream proxy: profile `network.upstreamProxy`, else host
/// `HTTPS_PROXY`, else host `HTTP_PROXY`, else none.
///
/// `env_get` is injected so the precedence is unit-testable without touching
/// the process environment. The real caller passes `std::env::var`, which on
/// Windows reads through `GetEnvironmentVariableW` and is therefore
/// case-insensitive — one lookup for `HTTPS_PROXY` also finds a `https_proxy`
/// entry. A blank value counts as unset (Windows environments routinely carry
/// an empty `HTTPS_PROXY=`).
///
/// Returns `(chosen_url, warning, source)`. The warning is the [G-42]
/// diagnostic and is present only when the profile value and the host-env
/// value are both set and name *different* endpoints; it names both proxies as
/// `host:port` only ([G-30]: a proxy URL may carry a password). The chosen
/// value is returned verbatim, because the caller has to parse it — only
/// diagnostics are redacted.
fn select_upstream(
    profile: Option<&str>,
    env_get: impl Fn(&str) -> Option<String>,
) -> (Option<String>, Option<String>, Option<UpstreamSource>) {
    let host_env = non_blank(env_get("HTTPS_PROXY")).or_else(|| non_blank(env_get("HTTP_PROXY")));
    let profile = non_blank(profile.map(str::to_string));

    let warn = match (profile.as_deref(), host_env.as_deref()) {
        (Some(p), Some(h)) if !same_upstream_endpoint(p, h) => Some(format!(
            "profile network.upstreamProxy ({}) differs from host HTTPS_PROXY/HTTP_PROXY ({}); \
             using the profile value",
            redact_proxy_url(p),
            redact_proxy_url(h)
        )),
        _ => None,
    };
    let source = match (&profile, &host_env) {
        (Some(_), _) => Some(UpstreamSource::Profile),
        (None, Some(_)) => Some(UpstreamSource::HostEnv),
        (None, None) => None,
    };
    (profile.or(host_env), warn, source)
}

/// Do two configured proxy URLs name the same endpoint?
///
/// Compared as parsed `host:port` when both parse — `http://p:8080` and
/// `http://p:8080/` are the same proxy, and the [G-42] override notice must
/// not fire for an override that overrides nothing — and as raw strings
/// otherwise (an unparsable value has no endpoint to compare, so distinct
/// typos stay distinct).
fn same_upstream_endpoint(a: &str, b: &str) -> bool {
    match (
        net::upstream::ProxyUrl::parse(a),
        net::upstream::ProxyUrl::parse(b),
    ) {
        (Ok(ua), Ok(ub)) => ua.endpoint() == ub.endpoint(),
        _ => a == b,
    }
}

/// Trim a value; blank counts as unset.
fn non_blank(v: Option<String>) -> Option<String> {
    v.map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

/// `host:port` for a proxy URL, else a static placeholder ([G-30]). A proxy URL
/// can carry `user:password@`, so diagnostics never echo one.
fn redact_proxy_url(raw: &str) -> String {
    net::upstream::ProxyUrl::parse(raw)
        .map(|u| u.endpoint())
        .unwrap_or_else(|_| "(unparsable)".to_string())
}

/// Host-env `NO_PROXY` entries for chaining ([G-11]): comma-separated, trimmed,
/// blanks dropped. Deliberately the *host* list — the child's `NO_PROXY` is the
/// loopback-only one we inject, and it says nothing about corporate egress.
///
/// Both spellings go through [`non_blank`], so a blank `NO_PROXY=` (common on
/// Windows) falls through to `no_proxy` instead of swallowing it.
fn host_no_proxy(env_get: impl Fn(&str) -> Option<String>) -> Vec<String> {
    non_blank(env_get("NO_PROXY"))
        .or_else(|| non_blank(env_get("no_proxy")))
        .unwrap_or_default()
        .split(',')
        .map(|e| e.trim().to_string())
        .filter(|e| !e.is_empty())
        .collect()
}

/// The *ungated* degradation line for an upstream URL that will not parse:
/// names the source knob, the redacted endpoint (or `(unparsable)`) and the
/// static reason, and states the consequence.
///
/// Deliberately never the URL ([G-30]: it may carry a password). Kept pure so
/// both sources and the unparsable case are unit-testable.
fn upstream_parse_failure_warning(
    source: UpstreamSource,
    raw: &str,
    reason: &net::upstream::UpstreamError,
) -> String {
    format!(
        "the upstream proxy configured via {} is unusable — {} ({reason}); \
         this session dials direct, with no upstream chaining",
        source.label(),
        redact_proxy_url(raw)
    )
}

/// The session-start facts **known before the launch** (P2.3, review item 5).
///
/// `tier`/`tier_source` are the backend's **identity**, not a probe result: this
/// backend creates the AppContainer profile and grants the host DACLs itself, so
/// it *is* the DACL-appcontainer tier (`tier_source: "structural"`) and needs
/// DACL augmentation by construction. `probe`/`unavailable` describe the MXC
/// probe and would be a lie here.
///
/// `elevated` is THIS supervisor process's token, which is what decides whether
/// the admin-only loopback exemption can be registered — the reason the field is
/// on the leaf at all (ADR-0004: the MXC path removes that dependency, so a
/// reader must be able to tell elevated runs from unelevated ones).
///
/// These are the facts the guard is **armed** with, so a run that dies before the
/// listener binds still records them; `proxy_endpoint` is added by `complete`,
/// which is the only caller that knows a port. `None` under `--block-net`, which
/// binds nothing.
fn appcontainer_session_facts() -> audit::session_start::SessionStartFacts {
    audit::session_start::SessionStartFacts::appcontainer_dacl(setup::is_elevated())
}

#[allow(clippy::too_many_arguments)]
fn run_cmd(
    backend: cli::Backend,
    profile: Option<String>,
    allow_cwd: bool,
    allow: Vec<String>,
    read_only: Vec<String>,
    block_net: bool,
    allow_domain: Vec<String>,
    deny_domain: Vec<String>,
    no_prompt: bool,
    network_profile: Option<String>,
    audit_strict: bool,
    print_sid: bool,
    sid: Option<String>,
    cmd: Vec<String>,
) -> i32 {
    // Backend selection is refused before anything is spawned or created. The
    // decision itself is `cli::route_backend` (pure, table-tested); this is only
    // the boundary that maps a refusal to its user-facing text and an exit code.
    let backend =
        match cli::route_backend(backend, cfg!(feature = "mxc-backend"), MXC_SESSION_WIRED) {
            Ok(backend) => backend,
            Err(refusal) => {
                eprintln!("[sandbox] {}", refusal.message());
                return 2;
            }
        };
    if backend == cli::Backend::Mxc {
        // Only reachable once `MXC_SESSION_WIRED` flips: this function has no MXC
        // session path, so refuse instead of running an AppContainer session
        // under a backend name that promised otherwise.
        eprintln!("[sandbox] {}", cli::MXC_NOT_WIRED);
        return 2;
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
        block_net,
        &allow_domain,
        &deny_domain,
        no_prompt,
        network_profile.as_deref(),
        audit_strict,
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
    deny_domain: &[String],
    no_prompt: bool,
    network_profile: Option<&str>,
    audit_strict: bool,
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
    let net_cfg_resolved = net::resolve_network(
        &resolved.network,
        block_net,
        allow_domain,
        deny_domain,
        no_prompt,
        network_profile,
    );

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

    // Open the audit writer for this session and ARM the session-start leaf
    // (P2.3). The leaf is what gives `verify` a root even under `--block-net`
    // where no proxy starts and thus no CONNECT events fire — and it is armed
    // with the facts that already exist (this backend's tier identity and this
    // process's elevation), so a run that returns early still leaves a root a
    // reader can select on. One root per run, and it is written before the child
    // exists, so no leaf the child causes can precede it.
    let audit_writer = std::sync::Arc::new(audit::AuditWriter::open(&sid, audit_strict)?);
    let session_start = audit::session_start::SessionStart::arm(
        audit_writer.clone(),
        &sid,
        cmd.join(" "),
        appcontainer_session_facts(),
    );

    let net_cfg = net_cfg_resolved.clone();

    // Build the AppContainer session.
    let session = sandbox::create_session(&sid)
        .with_context(|| format!("create AppContainer session for {sid}"))?;

    // Register loopback for the AC SID before spawning the proxy. The
    // privateNetworkClientServer capability SID (Task D-0.1) grants network
    // API rights but does NOT add a Windows Firewall loopback exemption —
    // these are separate mechanisms. This admin-only call adds the SID to
    // the loopback exempt list so the sandboxed process can reach the proxy
    // on 127.0.0.1:<port>. Fails gracefully when unprivileged (degrades to
    // block-net behavior with a warning).
    if !net_cfg.is_blocked()
        && let Err(e) = net::loopback::register_loopback(&session.ac_sid)
    {
        eprintln!("[sandbox] warning: loopback exemption failed: {e}");
        eprintln!("[sandbox]          Re-run 'sandbox run' as administrator (loopback is");
        eprintln!(
            "[sandbox]          registered automatically when elevated), or use --block-net."
        );
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
        net::NetworkConfig::Allow {
            allow_domain,
            deny_domain,
            prompt_enabled,
            on_unavailable,
            prompt_timeout_secs,
            upstream_proxy,
            profile_name,
            ..
        } => {
            // One credential per run (P1.4): the token this run's listener
            // accepts, and the only one its child is given. Minting it here is
            // what makes two concurrent sessions attributable to themselves.
            let token = net::token::RunToken::issue().context("generate session token")?;
            // Task 3.6 Step 5: load the learned policy BEFORE starting the
            // proxy. A corrupt learned file is a hard error by design — the
            // user notices immediately and can fix or revoke it ([G-5]).
            let learned = net::learned::LearnedStore::load(profile_name.as_deref()).context(
                "load learned policy file ('sandbox learned clear' resets a corrupt one)",
            )?;
            // D-4 registry + D-3.5 coordinator: created in the supervisor
            // (all sync) before the proxy runtime exists and Arc-shared
            // into every handler. The registry's `Drop` joins its sweeper
            // once the last reference is gone.
            let intent =
                std::sync::Arc::new(net::intent::IntentRegistry::new(net::intent::DEFAULT_TTL));
            let coordinator = std::sync::Arc::new(net::prompt::PromptCoordinator::new());
            let on_unavailable = if on_unavailable == "allow" {
                net::prompt::PromptPolicy::Allow
            } else {
                net::prompt::PromptPolicy::Deny
            };
            let prompt = net::proxy::PromptGate {
                enabled: *prompt_enabled,
                config: net::prompt::PromptConfig {
                    timeout: std::time::Duration::from_secs(u64::from(*prompt_timeout_secs)),
                    on_unavailable,
                },
                coordinator,
                intent,
                learned: std::sync::Arc::new(std::sync::Mutex::new(learned)),
            };
            // [G-10] Upstream chaining: profile `network.upstreamProxy` > host
            // `HTTPS_PROXY` > `HTTP_PROXY` > none, resolved here once in the
            // supervisor. The child never sees any of it — it keeps the
            // loopback-only proxy env we build for it.
            let (upstream_url, upstream_warn, upstream_source) =
                select_upstream(upstream_proxy.as_deref(), |k| std::env::var(k).ok());
            // [G-42] The override notice rides the SANDBOX_DIAG stream.
            if let Some(w) = upstream_warn
                && std::env::var_os("SANDBOX_DIAG").is_some()
            {
                eprintln!("[sandbox] SANDBOX_DIAG: {w}");
            }
            let upstream = match upstream_url {
                Some(raw) => match net::upstream::UpstreamDialer::from_url(
                    &raw,
                    host_no_proxy(|k| std::env::var(k).ok()),
                ) {
                    Ok(d) => Some(std::sync::Arc::new(d)),
                    Err(e) => {
                        // Policy: a bad proxy URL must not brick the run. Fall
                        // back to direct-only ([G-49] keeps that path alive)
                        // and say why. A session that silently loses its
                        // egress proxy is a security-relevant degradation, so
                        // — like the journal / loopback / ACL warnings above —
                        // this line is NOT SANDBOX_DIAG-gated; the gated line
                        // below adds the parse detail. The reason is static
                        // and the endpoint redacted: the URL itself is never
                        // echoed ([G-30]).
                        if let Some(source) = upstream_source {
                            eprintln!(
                                "[sandbox] warning: {}",
                                upstream_parse_failure_warning(source, &raw, &e)
                            );
                        }
                        if std::env::var_os("SANDBOX_DIAG").is_some() {
                            eprintln!(
                                "[sandbox] SANDBOX_DIAG: ignoring upstream proxy {} ({e}); \
                                 dialing direct",
                                redact_proxy_url(&raw)
                            );
                        }
                        None
                    }
                },
                None => None,
            };
            let handle = net::proxy::spawn(net::proxy::ProxyConfig {
                session_id: sid.clone(),
                token: token.clone(),
                allow_domain: allow_domain.clone(),
                deny_domain: deny_domain.clone(),
                upstream,
                writer: audit_writer.clone(),
                prompt,
            })
            .context("start localhost proxy")?;
            proxy_env = Some(net::ProxyEnv {
                port: handle.port,
                // The child's copy of this run's credential; the listener holds
                // the same value and refuses every other. Cloning the `RunToken`
                // (rather than its `String`) keeps the env edge typed (P1.6(c)).
                token: token.clone(),
            });
            Some(handle)
        }
    };

    // P2.3: the listener exists only now, so that is the one fact `complete`
    // adds — the leaf is written here, still before the child exists, and the
    // guard is disarmed. Every `?` above this point returned through the guard's
    // `Drop`, which wrote the same leaf with the armed tier/elevation and a null
    // endpoint.
    //
    // Note the ordering honestly: the listener is bound at `net::proxy::spawn`
    // above, so a local connection that reaches it in this window is audited by
    // the proxy thread first, and this leaf then lands at `seq > 0`. The guarantee
    // is one root per run, before the child — not "always seq 0".
    session_start.complete(
        proxy_env
            .as_ref()
            .map(|env| audit::session_start::LoopbackEndpoint::new(env.port)),
    )?;

    // Build the full allow-list (Option E per-session dirs + resolved profile entries).
    let entries = sandbox::build_allowlist(&sid, &cwd, &fs)?;

    if let Err(e) = sandbox::grant_access(&session.ac_sid, &entries, run_journal.as_ref()) {
        eprintln!("[sandbox] warning: some ACL grants failed: {e}");
    }

    let env_block = sandbox::build_env_block(&sid, &cwd, proxy_env.as_ref());

    let cmdline = join_cmdline(cmd);

    let job = sandbox::Job::create().context("create Job Object")?;

    let exit_code = sandbox::spawn(
        &session,
        &job,
        &cwd,
        env_block,
        &cmdline,
        !net_cfg.is_blocked(),
    )
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

    /// Unique temp dir per test (learned.rs's pattern) so the learned-CLI
    /// tests run in parallel without racing on a shared directory.
    fn learned_temp_dir(test_name: &str) -> std::path::PathBuf {
        let name = format!("sb-cli-learned-{}-{test_name}", std::process::id());
        let d = std::env::temp_dir().join(name);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn learned_list_missing_file_is_empty() {
        let tmp = learned_temp_dir("list-missing");
        let (rc, out, err) = learned_cmd_in(cli::LearnedSub::List, None, &tmp);
        assert_eq!(rc, 0);
        assert_eq!(out, "(no learned entries)\n");
        assert!(err.is_empty());

        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn learned_list_shows_host_scope_disposition_table() {
        let tmp = learned_temp_dir("list-table");
        {
            let mut store = net::learned::LearnedStore::load_in(&tmp, Some("t37")).unwrap();
            store.record("api.example.com", "host", true).unwrap();
            store.record("*.npmjs.org", "suffix", true).unwrap();
            store.record("evil.com", "host", false).unwrap();
        }
        let (rc, out, err) = learned_cmd_in(cli::LearnedSub::List, Some("t37"), &tmp);
        assert_eq!(rc, 0, "stderr: {err}");
        assert!(out.contains("HOST"), "header: {out}");
        assert!(out.contains("SCOPE"), "header: {out}");
        assert!(out.contains("DISPOSITION"), "header: {out}");
        // Stored representation: suffix entries keep their `*.` prefix.
        assert!(out.contains("api.example.com"), "allow host: {out}");
        assert!(out.contains("*.npmjs.org"), "suffix host: {out}");
        assert!(out.contains("suffix"), "scope: {out}");
        assert!(out.contains("evil.com"), "deny host: {out}");
        assert!(out.matches("allow").count() >= 2, "dispositions: {out}");
        assert!(out.matches("deny").count() >= 1, "dispositions: {out}");

        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn learned_revoke_removes_entry_and_persists() {
        let tmp = learned_temp_dir("revoke");
        {
            let mut store = net::learned::LearnedStore::load_in(&tmp, None).unwrap();
            store.record("api.example.com", "host", true).unwrap();
            store.record("evil.com", "host", false).unwrap();
        }
        let (rc, out, err) = learned_cmd_in(
            cli::LearnedSub::Revoke {
                host: "api.example.com".into(),
            },
            None,
            &tmp,
        );
        assert_eq!(rc, 0, "stderr: {err}");
        assert!(out.contains("revoked api.example.com"), "{out}");
        // The unrelated deny entry is untouched.
        let reloaded = net::learned::LearnedStore::load_in(&tmp, None).unwrap();
        assert!(reloaded.lookup("api.example.com").is_none());
        assert!(reloaded.lookup("evil.com").is_some_and(|d| !d.allow));

        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn learned_revoke_normalizes_input_like_the_store() {
        let tmp = learned_temp_dir("revoke-norm");
        {
            let mut store = net::learned::LearnedStore::load_in(&tmp, None).unwrap();
            store.record("api.example.com", "host", true).unwrap();
        }
        // Case + trailing dot are normalized the same way `record` does.
        let (rc, _out, err) = learned_cmd_in(
            cli::LearnedSub::Revoke {
                host: "API.Example.COM.".into(),
            },
            None,
            &tmp,
        );
        assert_eq!(rc, 0, "stderr: {err}");
        let reloaded = net::learned::LearnedStore::load_in(&tmp, None).unwrap();
        assert!(reloaded.lookup("api.example.com").is_none());

        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn learned_revoke_unknown_host_fails_loudly() {
        let tmp = learned_temp_dir("revoke-unknown");
        let (rc, out, err) = learned_cmd_in(
            cli::LearnedSub::Revoke {
                host: "nope.example.com".into(),
            },
            None,
            &tmp,
        );
        assert_eq!(rc, 1);
        assert!(out.is_empty());
        assert!(
            err.contains("no learned entry for nope.example.com"),
            "{err}"
        );

        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn learned_clear_empties_file() {
        let tmp = learned_temp_dir("clear");
        {
            let mut store = net::learned::LearnedStore::load_in(&tmp, None).unwrap();
            store.record("a.example.com", "host", true).unwrap();
            store.record("b.example.com", "host", false).unwrap();
        }
        let (rc, out, err) = learned_cmd_in(cli::LearnedSub::Clear, None, &tmp);
        assert_eq!(rc, 0, "stderr: {err}");
        assert!(out.is_empty());
        assert!(err.is_empty());
        let reloaded = net::learned::LearnedStore::load_in(&tmp, None).unwrap();
        assert!(reloaded.entries().is_empty());

        std::fs::remove_dir_all(&tmp).ok();
    }

    /// [G-5] corrupt-file recovery: a corrupt learned file hard-aborts
    /// `sandbox run`, and `clear` is the only non-editorial way out — so
    /// it must succeed even though the file cannot be loaded.
    #[test]
    fn learned_clear_resets_corrupt_file() {
        let tmp = learned_temp_dir("clear-corrupt");
        let path = net::learned::learned_file_path_in(&tmp, None);
        std::fs::create_dir_all(path.parent().unwrap()).ok();
        std::fs::write(&path, "}}} not json {{{").ok();
        // List proves the file is unreadable and the error points at the
        // recovery path.
        let (rc, _out, err) = learned_cmd_in(cli::LearnedSub::List, None, &tmp);
        assert_eq!(rc, 1);
        assert!(err.contains("sandbox learned clear"), "hint: {err}");
        // Clear is the recovery path and must succeed despite the corrupt file.
        let (rc, out, err) = learned_cmd_in(cli::LearnedSub::Clear, None, &tmp);
        assert_eq!(rc, 0, "stderr: {err}");
        assert!(out.is_empty() && err.is_empty());
        let reloaded = net::learned::LearnedStore::load_in(&tmp, None).unwrap();
        assert!(reloaded.entries().is_empty());

        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn learned_clear_missing_file_is_ok() {
        let tmp = learned_temp_dir("clear-missing");
        let (rc, out, err) = learned_cmd_in(cli::LearnedSub::Clear, None, &tmp);
        assert_eq!(rc, 0, "stderr: {err}");
        assert!(out.is_empty() && err.is_empty());

        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn learned_profile_selects_learned_file() {
        let tmp = learned_temp_dir("profile");
        {
            let mut store = net::learned::LearnedStore::load_in(&tmp, None).unwrap();
            store.record("api.example.com", "host", true).unwrap();
        }
        // default.json has one entry; the `dev` learned file does not exist.
        let (rc, out, err) = learned_cmd_in(cli::LearnedSub::List, Some("dev"), &tmp);
        assert_eq!(rc, 0, "stderr: {err}");
        assert_eq!(out, "(no learned entries)\n");
        let (rc, out, _err) = learned_cmd_in(cli::LearnedSub::List, None, &tmp);
        assert_eq!(rc, 0);
        assert!(out.contains("api.example.com"), "{out}");
        // Clearing the `dev` file must not touch default.json.
        let (rc, _out, err) = learned_cmd_in(cli::LearnedSub::Clear, Some("dev"), &tmp);
        assert_eq!(rc, 0, "stderr: {err}");
        let (rc, out, _err) = learned_cmd_in(cli::LearnedSub::List, None, &tmp);
        assert_eq!(rc, 0);
        assert!(out.contains("api.example.com"), "{out}");

        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn learned_invalid_profile_name_fails() {
        let tmp = learned_temp_dir("invalid-profile");
        let (rc, _out, err) = learned_cmd_in(cli::LearnedSub::List, Some("a/b"), &tmp);
        assert_eq!(rc, 1);
        assert!(!err.is_empty());
        let (rc, _out, err) = learned_cmd_in(cli::LearnedSub::Clear, Some("../escape"), &tmp);
        assert_eq!(rc, 1);
        assert!(!err.is_empty());

        std::fs::remove_dir_all(&tmp).ok();
    }

    // ---- Task 4.2: [G-10] upstream-proxy selection + [G-11] NO_PROXY ------

    /// A `select_upstream` / `host_no_proxy` env lookup over fixed pairs.
    /// Matching is case-insensitive on purpose: Windows reads the environment
    /// with `GetEnvironmentVariableW`, so one `HTTPS_PROXY` lookup also covers
    /// a `https_proxy` entry. The fake mirrors that.
    fn env_of<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |k| {
            pairs
                .iter()
                .find(|(kk, _)| kk.eq_ignore_ascii_case(k))
                .map(|(_, v)| (*v).to_string())
        }
    }

    #[test]
    fn select_upstream_profile_only() {
        let (chosen, warn, src) = select_upstream(
            Some("http://corp-proxy:8080"),
            env_of(&[("HTTPS_PROXY", "http://corp-proxy:8080")]),
        );
        assert_eq!(chosen.as_deref(), Some("http://corp-proxy:8080"));
        assert!(warn.is_none(), "equal values must not warn: {warn:?}");
        assert_eq!(src, Some(UpstreamSource::Profile));
    }

    #[test]
    fn select_upstream_env_only_prefers_https_proxy() {
        let (chosen, warn, src) = select_upstream(
            None,
            env_of(&[
                ("HTTPS_PROXY", "http://https-proxy:8080"),
                ("HTTP_PROXY", "http://http-proxy:8080"),
            ]),
        );
        assert_eq!(chosen.as_deref(), Some("http://https-proxy:8080"));
        assert!(
            warn.is_none(),
            "host-env-only detection is silent [G-42]: {warn:?}"
        );
        assert_eq!(src, Some(UpstreamSource::HostEnv));
    }

    #[test]
    fn select_upstream_env_only_falls_back_to_http_proxy() {
        let (chosen, warn, _src) =
            select_upstream(None, env_of(&[("HTTP_PROXY", "http://http-proxy:8080")]));
        assert_eq!(chosen.as_deref(), Some("http://http-proxy:8080"));
        assert!(warn.is_none());
    }

    #[test]
    fn select_upstream_none_when_nothing_is_set() {
        let (chosen, warn, _src) = select_upstream(None, env_of(&[]));
        assert!(chosen.is_none());
        assert!(warn.is_none());
    }

    #[test]
    fn select_upstream_blank_values_count_as_unset() {
        let (chosen, warn, _src) =
            select_upstream(None, env_of(&[("HTTPS_PROXY", "   "), ("HTTP_PROXY", "")]));
        assert!(chosen.is_none(), "blank proxy values must not be used");
        assert!(warn.is_none());
    }

    #[test]
    fn select_upstream_profile_over_env_warns_and_redacts() {
        let (chosen, warn, _src) = select_upstream(
            Some("http://alice:s3cret@profile-proxy:8080"),
            env_of(&[("HTTPS_PROXY", "http://bob:hunter2@env-proxy:3128")]),
        );
        // [G-10] the profile wins, and the caller gets the URL verbatim so it
        // can parse it (only diagnostics are redacted).
        assert_eq!(
            chosen.as_deref(),
            Some("http://alice:s3cret@profile-proxy:8080")
        );
        let warn = warn.expect("differing values must warn [G-42]");
        assert!(warn.contains("profile-proxy:8080"), "{warn}");
        assert!(warn.contains("env-proxy:3128"), "{warn}");
        for secret in ["s3cret", "hunter2", "alice", "bob"] {
            assert!(!warn.contains(secret), "warning leaked {secret:?}: {warn}");
        }
    }

    #[test]
    fn select_upstream_unparsable_values_still_warn_without_echoing_them() {
        let (chosen, warn, _src) = select_upstream(
            Some("https://profile-proxy:8443"),
            env_of(&[("HTTPS_PROXY", "http://env-proxy:3128")]),
        );
        assert_eq!(chosen.as_deref(), Some("https://profile-proxy:8443"));
        let warn = warn.expect("differing values must warn [G-42]");
        // No TLS-to-proxy: `https://` is unparsable here, so it is named by a
        // placeholder rather than echoed.
        assert!(warn.contains("(unparsable)"), "{warn}");
        assert!(!warn.contains("profile-proxy:8443"), "{warn}");
    }

    #[test]
    fn upstream_parse_failure_warning_names_the_profile_source_without_credentials() {
        let raw = "https://alice:s3cret@profile-proxy:8443";
        let e = net::upstream::ProxyUrl::parse(raw).expect_err("https is not a proxy scheme");
        let w = upstream_parse_failure_warning(UpstreamSource::Profile, raw, &e);
        assert!(w.contains("profile network.upstreamProxy"), "{w}");
        assert!(w.contains("(unparsable)"), "{w}");
        assert!(w.contains("unsupported upstream proxy scheme"), "{w}");
        assert!(w.contains("direct"), "{w}");
        for secret in ["alice", "s3cret", "profile-proxy:8443"] {
            assert!(!w.contains(secret), "warning leaked {secret:?}: {w}");
        }
    }

    #[test]
    fn upstream_parse_failure_warning_names_the_host_env_source() {
        let raw = "http://proxy.corp:notaport";
        let e = net::upstream::ProxyUrl::parse(raw).expect_err("port does not parse");
        let w = upstream_parse_failure_warning(UpstreamSource::HostEnv, raw, &e);
        assert!(w.contains("host HTTPS_PROXY/HTTP_PROXY"), "{w}");
        assert!(w.contains("(unparsable)"), "{w}");
        assert!(!w.contains("proxy.corp"), "{w}");
    }

    #[test]
    fn select_upstream_trailing_slash_is_not_a_difference() {
        // `http://p:8080` and `http://p:8080/` name the same endpoint, so the
        // [G-42] override notice must not fire for an "override" that changes
        // nothing.
        let (chosen, warn, _src) = select_upstream(
            Some("http://p:8080"),
            env_of(&[("HTTPS_PROXY", "http://p:8080/")]),
        );
        assert_eq!(chosen.as_deref(), Some("http://p:8080"));
        assert!(
            warn.is_none(),
            "equivalent endpoints must not warn: {warn:?}"
        );
    }

    #[test]
    fn host_no_proxy_blank_no_proxy_falls_through_to_the_lowercase_name() {
        // A *blank* `NO_PROXY` counts as unset, like every other env read
        // here (Windows routinely carries `NO_PROXY=`), so the lowercase
        // lookup must still be tried. Case-sensitive fake on purpose: the
        // real Windows lookup is case-insensitive, but the fallback logic is
        // what is under test.
        let env = |k: &str| match k {
            "NO_PROXY" => Some("   ".to_string()),
            "no_proxy" => Some("a.test, b.test".to_string()),
            _ => None,
        };
        assert_eq!(host_no_proxy(env), vec!["a.test", "b.test"]);
    }

    #[test]
    fn host_no_proxy_parses_comma_separated_entries() {
        let entries = host_no_proxy(env_of(&[("NO_PROXY", "a.test, b.test,,c.test ")]));
        assert_eq!(entries, vec!["a.test", "b.test", "c.test"]);
    }

    #[test]
    fn host_no_proxy_missing_is_empty() {
        assert!(host_no_proxy(env_of(&[])).is_empty());
        assert!(host_no_proxy(env_of(&[("NO_PROXY", "  ")])).is_empty());
    }

    /// P2.3 acceptance 1, at the production seam: the AppContainer backend's leaf
    /// facts are its identity (`appcontainer-dacl` / `structural`), never a probe
    /// result, and `elevated` is always known — the one fact a reader uses to tell
    /// an admin run from an unelevated one. Both survive an early death, because
    /// they are the facts the guard is armed with (review item 5).
    #[test]
    fn appcontainer_session_facts_name_the_dacl_tier_by_construction() {
        let facts = appcontainer_session_facts();
        assert_eq!(
            facts.tier().tier.as_deref(),
            Some(audit::session_start::TIER_APPCONTAINER_DACL)
        );
        assert_eq!(
            facts.tier().tier_source,
            Some(audit::session_start::TIER_SOURCE_STRUCTURAL),
            "this backend IS the tier; `probe` would claim a dispatch decision nobody made"
        );
        assert_eq!(
            facts.tier().needs_dacl_augmentation,
            Some(true),
            "the AC backend grants host DACLs by definition"
        );
        assert_eq!(
            facts.elevated(),
            Some(setup::is_elevated()),
            "`elevated` is this process's token, never guessed or defaulted"
        );
        assert!(
            facts.tier().tier.is_some() && facts.tier().tier_source.is_some(),
            "`tier` and `tier_source` travel together or not at all"
        );
    }

    /// P2.3 acceptance 4/5, at the production seam: the endpoint is the bare
    /// loopback authority of the listener this run bound, and `None` when
    /// `--block-net` bound nothing.
    ///
    /// The child's proxy URL (`http://sandbox:<token>@127.0.0.1:<port>`) is
    /// deliberately not what goes on the leaf: `LoopbackEndpoint` takes a `u16`
    /// and nothing else, so a credential cannot be passed at all (review item 3).
    #[test]
    fn the_session_endpoint_is_the_bare_loopback_authority_or_null() {
        let endpoint = audit::session_start::LoopbackEndpoint::new(63_123);
        assert_eq!(endpoint.to_string(), "127.0.0.1:63123");

        // What `complete` writes: the port the listener bound, or nothing.
        assert_eq!(
            appcontainer_session_facts()
                .with_endpoint(endpoint)
                .proxy_endpoint(),
            Some(endpoint)
        );
        assert_eq!(
            appcontainer_session_facts().proxy_endpoint(),
            None,
            "--block-net binds no listener, so there is no endpoint to record"
        );
        // The tier facts are recorded either way: a blocked session is still a
        // session with a containment posture, and an early death still names it.
        assert_eq!(
            appcontainer_session_facts().tier().tier.as_deref(),
            Some(audit::session_start::TIER_APPCONTAINER_DACL)
        );
    }
}
