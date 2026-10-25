mod audit;
mod cli;
mod net;
// Plugins/sidecars are a capability of the mxc backend; without the feature the
// module is compiled but unreachable. Scoped to the feature state rather than a
// blanket `#![allow(dead_code)]`, so genuine rot inside it still shows up in the
// build that uses it.
#[cfg_attr(not(feature = "mxc-backend"), allow(dead_code))]
mod plugin;
mod profile;
mod sandbox;
mod security_groups;
mod setup;
mod signing;

use anyhow::{Context, Result};
use clap::Parser;
// P3.4: `IsTerminal` is what decides whether a session gets this console. Only
// the MXC session path reads it (the AppContainer path has no passthrough
// mode), so a feature-less build must not import it.
#[cfg(feature = "mxc-backend")]
use std::io::IsTerminal;

use cli::Cli;
use cli::Cmd;

/// Whether the MXC backend is wired into the session path.
///
/// P3.0 wires it: [`run_inner`] routes `--backend mxc` to [`run_mxc_session`],
/// which launches through [`net::mxc::launch_session`]. Until this flipped, the
/// flag was refused rather than falling back to `appcontainer`
/// ([`cli::route_backend`]) — the refusal still exists and still fires for a
/// binary built without the feature.
///
/// **The default backend is unchanged** ([`cli::Backend::AppContainer`]): putting
/// MXC on the default path is P3.2 and a separate decision, because it changes
/// what every existing invocation gets.
const MXC_SESSION_WIRED: bool = true;

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
            no_interactive,
            network_profile,
            audit_strict,
            backend,
            print_sid,
            sid,
            plugin,
            plugin_dir,
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
            no_interactive,
            network_profile,
            audit_strict,
            print_sid,
            sid,
            plugin,
            plugin_dir,
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
                eprintln!("[saife] setup check failed: {e:#}");
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
        Some(p) => p.join("saife").join("audit"),
        None => {
            eprintln!("[saife] LOCALAPPDATA not set");
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

/// Core of `saife learned`, rooted at `base` and returning the exit
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
                // Aligned plain-text columns, no color codes (`saife ps`
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
                        "[saife] no learned entry for {host} \
                         (run `saife learned list` to see stored keys)\n"
                    ),
                ),
                Err(e) => (
                    1,
                    String::new(),
                    format!("[saife] failed to rewrite learned file: {e:#}\n"),
                ),
            },
            Err(e) => learned_load_failure(e),
        },
        LearnedSub::Clear => {
            // [G-5] recovery: a corrupt learned file hard-aborts
            // `saife run`, and `clear` is the only non-editorial way
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
                    format!("[saife] failed to clear learned file: {e:#}\n"),
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
            "[saife] failed to load learned file: {e:#} \
             (run `saife learned clear` to reset it)\n"
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
    backend: Option<cli::Backend>,
    profile: Option<String>,
    allow_cwd: bool,
    allow: Vec<String>,
    read_only: Vec<String>,
    block_net: bool,
    allow_domain: Vec<String>,
    deny_domain: Vec<String>,
    no_prompt: bool,
    no_interactive: bool,
    network_profile: Option<String>,
    audit_strict: bool,
    print_sid: bool,
    sid: Option<String>,
    // P4.1/P1.x: `--plugin` / `--plugin-dir`, repeatable and order-sensitive.
    plugin: Vec<String>,
    plugin_dir: Vec<String>,
    cmd: Vec<String>,
) -> i32 {
    // Backend selection is refused before anything is spawned or created. The
    // decision itself is `cli::route_backend` (pure, table-tested); this is only
    // the boundary that maps a refusal to its user-facing text and an exit code.
    // P3.2: the default is the MXC backend in a feature build. A build without
    // the feature keeps working on AppContainer and says so once, instead of
    // refusing every run because the default names a backend it does not have.
    let feature_enabled = cfg!(feature = "mxc-backend");
    let backend = backend.unwrap_or_else(|| {
        if !feature_enabled {
            eprintln!("[saife] {}", cli::MXC_FEATURE_FALLBACK);
        }
        cli::default_backend(feature_enabled)
    });
    let backend = match cli::route_backend(backend, feature_enabled, MXC_SESSION_WIRED) {
            Ok(backend) => backend,
            Err(refusal) => {
                eprintln!("[saife] {}", refusal.message());
                return 2;
            }
        };
    // No blanket `--backend mxc` refusal here any more (P3.0): the routed backend
    // is carried into `run_inner`, which has a session path for both. A binary
    // without the feature never reaches this point (`route_backend` refuses), and
    // `run_inner` re-states that refusal rather than falling back.
    if let Err(e) = setup::check_runtime() {
        eprintln!("[saife] {e:#}");
        return 1;
    }

    match run_inner(
        backend,
        profile.as_deref(),
        allow_cwd,
        &allow,
        &read_only,
        block_net,
        &allow_domain,
        &deny_domain,
        no_prompt,
        no_interactive,
        network_profile.as_deref(),
        audit_strict,
        print_sid,
        sid.as_deref(),
        &plugin,
        &plugin_dir,
        &cmd,
    ) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("[saife] {e:#}");
            1
        }
    }
}

#[allow(clippy::too_many_arguments)]
// `no_interactive` only reaches the MXC path, which a feature-less build does
// not have: the parameter stays (both builds take the same shape) and is
// allowed to go unread there.
#[cfg_attr(not(feature = "mxc-backend"), allow(unused_variables))]
fn run_inner(
    // P3.0: the backend `cli::route_backend` already approved. `AppContainer`
    // keeps the code path below byte for byte; `Mxc` branches out after the
    // shared resolution and never comes back through it.
    backend: cli::Backend,
    profile_name: Option<&str>,
    allow_cwd: bool,
    allow: &[String],
    read_only: &[String],
    block_net: bool,
    allow_domain: &[String],
    deny_domain: &[String],
    no_prompt: bool,
    // P3.4: `--no-interactive`, threaded to the MXC path's stdio decision.
    no_interactive: bool,
    network_profile: Option<&str>,
    audit_strict: bool,
    print_sid: bool,
    sid: Option<&str>,
    // `--plugin` names, in the order given (repeatable).
    plugins: &[String],
    // `--plugin-dir` roots, in the order given (repeatable).
    plugin_dirs: &[String],
    cmd: &[String],
) -> Result<i32> {
    let cwd = std::env::current_dir().context("get current directory")?;

    // Load + resolve profile (filesystem slice only for this slice).
    let resolved = match profile_name {
        Some(name) => profile::load_and_resolve(name, &cwd)?,
        None => profile::ResolvedProfile::default(),
    };

    // Resolve the network configuration from the profile slice + CLI flags.
    // `--plugin` needs the listener (the facade route lives in the proxy) but
    // grants no origin: the allow-list is whatever the operator declared, and an
    // empty one still denies every host that is not a facade mount. `--block-net`
    // remains an explicit "no listener" and refuses `--plugin` downstream.
    let net_cfg_resolved = net::resolve_network_with(
        &resolved.network,
        block_net,
        allow_domain,
        deny_domain,
        no_prompt,
        network_profile,
        !plugins.is_empty(),
    );

    // Merge CLI flags on top of the profile.
    let fs = profile::merge_filesystem(&resolved.filesystem, allow_cwd, allow, read_only, &cwd)?;

    // The session-deadline terms, resolved ONCE: defaults applied and both clamped
    // into range with a warning. A run with no profile resolves
    // `ResolvedProfile::default()`'s empty limits slice, i.e. 60 s + 30 min — the
    // same numbers the CLI-only path has always used. Both consumers (the dialog
    // timeout and the container deadline) read THIS value, so they cannot disagree.
    let limits = resolved.limits.resolve();

    let sid = match sid {
        Some(s) => s.to_string(),
        None => new_session_id(),
    };

    // P3.0: `--backend mxc` runs its own session. Placed here — after the shared
    // resolution (profile, network, filesystem, sid) and BEFORE the DACL journal,
    // the per-session install dirs and every AppContainer call — so the MXC path
    // never touches host ACL state it does not use, and the AppContainer path
    // below is exactly what it was.
    if backend == cli::Backend::Mxc {
        #[cfg(feature = "mxc-backend")]
        {
            return run_mxc_session(
                &sid,
                &cwd,
                &net_cfg_resolved,
                &fs,
                &limits,
                audit_strict,
                print_sid,
                no_interactive,
                plugins,
                plugin_dirs,
                cmd,
            );
        }
        // Unreachable through the CLI: `route_backend` refuses `mxc` in a binary
        // without the feature. Spelled as the same refusal rather than an
        // `unreachable!()` so a future caller that skips the router still fails
        // closed and says why.
        #[cfg(not(feature = "mxc-backend"))]
        {
            anyhow::bail!("{}", cli::MXC_FEATURE_MISSING);
        }
    }

    // Plugins are wired on the MXC path only (POC). Refused by NAME rather than
    // ignored: asking for a capability and silently not getting it is the failure
    // mode this project exists to prevent, and the AppContainer session differs
    // enough (loopback exemption, elevation) that wiring it without a live leg
    // would be a claim rather than a feature.
    if !plugins.is_empty() {
        eprintln!(
            "[saife] plugin_unsupported_backend: --plugin {} (plugins are wired on --backend mxc only)",
            plugins.join(", ")
        );
        return Ok(2);
    }

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
            eprintln!("[saife] warning: DACL journal unavailable: {e}");
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
        && let Err(e) = net::loopback::register_loopback(&session.ac_sid.0)
    {
        eprintln!("[saife] warning: loopback exemption failed: {e}");
        eprintln!("[saife]          Re-run 'saife run' as administrator (loopback is");
        eprintln!(
            "[saife]          registered automatically when elevated), or use --block-net."
        );
    }

    // Start the proxy (if not blocked) and hold the handle until the child exits:
    // the handle MUST outlive `sandbox::spawn` below, so the proxy stays up while
    // the child runs. Extracted in P3.0 so the MXC path starts the *same* listener
    // with the same policy instead of a second implementation of it.
    // An EMPTY registry on this path: plugins are refused above, and an empty
    // registry is a fully-closed facade (`404` for any `*.sandbox.invalid`).
    let proxy = start_session_proxy(
        &net_cfg,
        limits.prompt_timeout_secs,
        &sid,
        audit_writer.clone(),
        std::sync::Arc::new(plugin::FacadeRegistry::new()),
    )?;
    let proxy_port = proxy.as_ref().map(|(handle, _)| handle.port);

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
    session_start.complete(proxy_port.map(audit::session_start::LoopbackEndpoint::new))?;

    // Build the full allow-list (Option E per-session dirs + resolved profile entries).
    let entries = sandbox::build_allowlist(&sid, &cwd, &fs)?;

    if let Err(e) = sandbox::grant_access(&session.ac_sid.0, &entries, run_journal.as_ref()) {
        eprintln!("[saife] warning: some ACL grants failed: {e}");
    }

    let env_block = sandbox::build_env_block(&sid, &cwd, proxy.as_ref().map(|(_, env)| env));

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

    seal_audit(audit_writer, proxy.map(|(handle, _)| handle), &sid);

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

// ---------------------------------------------------------------------------
// P3.0: the MXC session path
// ---------------------------------------------------------------------------

/// Exit code for a session that hit its budget (`timeout(1)`'s convention).
#[cfg(feature = "mxc-backend")]
const EXIT_TIMEOUT: i32 = 124;

/// Exit code for a session a PLUGIN refused: load, spawn, health gate, or a
/// duplicate mount.
///
/// `5` is deliberately distinct from `126` (a guardrail refusal) and `1` (a
/// runtime error): a caller script can tell "the capability I asked for was not
/// available" from "the session ran and failed".
#[cfg(feature = "mxc-backend")]
const EXIT_PLUGIN_REFUSED: i32 = 5;

/// Exit code for a session a guardrail refused.
///
/// `126` is `timeout(1)`'s "found but could not be executed", which is what a
/// refusal means here: the workload may well have run, but this session is not a
/// contained, proven session and its result is not evidence.
#[cfg(feature = "mxc-backend")]
const EXIT_REFUSED: i32 = 126;

/// Run one session through the MXC `processcontainer` backend (P3.0).
///
/// Same resolved inputs as the AppContainer path, on the parts MXC can express,
/// and a named refusal on the ones it cannot:
///
/// * **filesystem** — the workspace read-write, declared read-only grants
///   read-only, profile secret dirs and configured denies denied
///   ([`net::mxc::filesystem_policy`], P1.3 + P3.4). `fs.allow` — the profile's
///   `filesystem.allow` merged with every `--allow <path>` — is granted
///   read-write beside the workspace, which is what makes a tool with state in
///   the profile runnable; the credential directories stay denied and a deny that
///   covers a grant still refuses the session.
/// * **network** — the same in-process listener with a fresh per-run token, or
///   nothing at all under `--block-net`.
/// * **budget** — the resolved [`profile::Limits::session_budget`], so the
///   container's deadline is *this* profile's prompt + workload + slack.
/// * **proof** — [`net::mxc::launch_session`] derives the guardrail leg from the
///   port (`Required` with a proxy, `MustBeAbsent` without) and carries
///   `TierExpectation::Exactly(REQUIRED_TIER)`. A launch that cannot prove the
///   child reached the proxy **fails the session** (exit 126) instead of warning.
/// * **audit** — the session root is written **before** the launch, from the probe
///   of the exact request, the port this run bound and this process's token, so a
///   supervisor killed mid-session leaves a readable chain with no sealed root
///   (`audit verify` says INCOMPLETE — S-55). The launch record afterwards only
///   confirms that root's tier; it never writes it.
///
/// What it deliberately does NOT do: create an AppContainer profile, grant host
/// DACLs, open a DACL journal, register a loopback exemption or create the
/// per-session install dirs. MXC needs none of them — that is the migration's
/// whole point (no elevation) — and doing them would mutate host state for a
/// session that never uses it.
// P3.4 added the stdio decision as an argument, which takes this past clippy's
// default arity. Bundling the session facts into a struct would be a larger
// refactor of a function whose whole point is to be readable top to bottom,
// and `run_inner` (its caller) already carries the same allow.
#[allow(clippy::too_many_arguments)]
#[cfg(feature = "mxc-backend")]
fn run_mxc_session(
    sid: &str,
    cwd: &std::path::Path,
    net_cfg: &net::NetworkConfig,
    fs: &profile::FilesystemSlice,
    limits: &profile::Limits,
    audit_strict: bool,
    print_sid: bool,
    no_interactive: bool,
    plugins: &[String],
    plugin_dirs: &[String],
    cmd: &[String],
) -> Result<i32> {
    // Decision 7: `--print-sid` yields the id and returns, exactly as the
    // AppContainer path does — nothing is launched, so nothing needs a launcher.
    if print_sid {
        println!("{sid}");
        return Ok(0);
    }
    if cmd.is_empty() {
        return Ok(0);
    }

    // (2) D1's wrapper. The container runs `saife-launch.exe`, and that wrapper is
    //     the only way `NO_PROXY` and `SAIFE_PROXY_PORT` reach the child
    //     (mxc-sdk 1.0.1 strips both from `request.environment`).
    let supervisor = std::env::current_exe().context("locate this supervisor binary")?;
    let Some(launcher) = net::mxc::launcher_beside(&supervisor) else {
        eprintln!("[saife] {}", cli::MXC_LAUNCHER_MISSING);
        return Ok(2);
    };

    // (3) Filesystem policy (P1.3). A deny that covers a grant is named by
    //     `filesystem_policy` itself (`DenyCoversGrant`) — refused, never dropped.
    let readonly: Vec<String> = fs
        .read_only
        .iter()
        .map(|p| p.display().to_string())
        .collect();
    let denies: Vec<String> = fs.deny.iter().map(|p| p.display().to_string()).collect();
    let home = std::env::var_os("USERPROFILE").map(std::path::PathBuf::from);
    // P3.4: `fs.allow` is the operator's explicit writable grants — the profile's
    // `filesystem.allow` merged with every `--allow <path>` whose mode is not
    // `read` (the CLI's default is readwrite). They join the workspace as
    // read-write grants instead of being refused: a tool that keeps state in the
    // profile (opencode's `~/.local/share/opencode`, `~/.cache/opencode`) has no
    // other way to run here, and refusing was not a narrower posture but an
    // unusable backend. Every deny below still applies, and a deny that COVERS one
    // of these grants still refuses the session by name.
    let filesystem = match net::mxc::filesystem_policy(
        cwd,
        &fs.allow,
        &readonly,
        &denies,
        home.as_deref(),
        &launcher,
    ) {
            Ok(policy) => policy,
            Err(e) => {
                eprintln!("[saife] mxc: {e}");
                return Ok(2);
            }
        };

    // (4) The audit writer and the ARMED root. The writer must exist before the
    //     listener, because the listener audits through it — and the tier is not
    //     known yet: it comes from `v1::probe` of the exact request, which needs
    //     the bound port. So the guard is armed with this process's elevation, and
    //     the tier arrives from that probe at (7b), before the launch. Every `?`
    //     between here and that write returns through `Drop`, which writes the
    //     armed root: one root per run, even for a session that dies in setup.
    let audit_writer = std::sync::Arc::new(audit::AuditWriter::open(sid, audit_strict)?);
    let session_start = audit::session_start::SessionStart::arm(
        audit_writer.clone(),
        sid,
        cmd.join(" "),
        audit::session_start::SessionStartFacts::measured(
            audit::session_start::TierFacts::default(),
            Some(setup::is_elevated()),
        )
        // P3.5: the enforced filesystem posture, from the SAME value the launch
        // uses — recorded before the child exists, so the root states what was
        // allowed even for a session that then dies.
        .with_filesystem(audit::session_start::FilesystemFacts {
            workspace: Some(cwd.display().to_string()),
            readwrite: filesystem.readwrite_paths.clone(),
            readonly: filesystem.readonly_paths.clone(),
            deny: filesystem.denied_paths.clone(),
        }),
    );

    // (5) The SAME listener the AppContainer path starts, with its own per-run
    //     token; nothing at all under `--block-net`. No loopback exemption is
    //     registered: this backend's ingress policy allows host loopback, which is
    //     why the migration needs no elevation.
    //
    //     The facade registry exists BEFORE the listener so both hold one `Arc`:
    //     the handler reads it per request, and the plugins below fill it once
    //     each sidecar has a port and a token. That ordering is what makes
    //     "proxy binds -> plugins spawn -> child" honest — a request that lands
    //     in between answers `404`, never a stale allow.
    if !plugins.is_empty() && net_cfg.is_blocked() {
        eprintln!(
            "[saife] plugin_requires_proxy: --plugin {} (--block-net starts no listener to route it)",
            plugins.join(", ")
        );
        return Ok(2);
    }
    let facade = std::sync::Arc::new(plugin::FacadeRegistry::new());
    let proxy = start_session_proxy(
        net_cfg,
        limits.prompt_timeout_secs,
        sid,
        audit_writer.clone(),
        std::sync::Arc::clone(&facade),
    )?;
    let proxy_port = proxy.as_ref().map(|(handle, _)| handle.port);
    let token = proxy.as_ref().map(|(_, env)| env.token.value());

    // (5b) Plugins: load, spawn host-side, health-gate, register. Declared AFTER
    //      `proxy`, so they are dropped BEFORE it on every path (locals drop in
    //      reverse declaration order): a sidecar never outlives the route that
    //      points at it, and every `?` below unwinds through both.
    let roots: Vec<std::path::PathBuf> = plugin_dirs.iter().map(std::path::PathBuf::from).collect();
    let mut sidecars: Vec<plugin::sidecar::Sidecar> = Vec::new();
    for name in plugins {
        let loaded = match plugin::load_plugin(name, &roots) {
            Ok(loaded) => loaded,
            Err(e) => {
                eprintln!("[saife] plugin '{name}' refused: {e:#}");
                return Ok(EXIT_PLUGIN_REFUSED);
            }
        };
        let sidecar = match plugin::sidecar::Sidecar::start(&loaded.dir, &loaded.manifest, sid) {
            Ok(sidecar) => sidecar,
            Err(e) => {
                eprintln!("[saife] plugin '{name}' refused: {e:#}");
                return Ok(EXIT_PLUGIN_REFUSED);
            }
        };
        if std::env::var_os("SAIFE_DIAG").is_some() {
            eprintln!(
                "[saife] SAIFE_DIAG: plugin '{}' healthy on 127.0.0.1:{} (pid {:?}, log {})",
                sidecar.mount(),
                sidecar.port(),
                sidecar.pid(),
                sidecar.log_path().display()
            );
        }
        // The mount goes live only now: a duplicate mount (two plugins asking to
        // answer for one name) refuses the session instead of picking a winner.
        if let Err(e) = facade.insert(sidecar.facade_target()) {
            eprintln!("[saife] plugin '{name}' refused: {e:#}");
            return Ok(EXIT_PLUGIN_REFUSED);
        }
        sidecars.push(sidecar);
    }

    // (6) Guardrail 1's proof source. With a proxy it is that listener — the one
    //     the child is pointed at, so the proof cannot come from a different
    //     socket. Under `--block-net` nothing binds and the registry is
    //     unattached: its proof is structurally zero because the session has no
    //     proxy to consult, which is what `MustBeAbsent` asserts.
    let counters = match &proxy {
        Some((handle, _)) => handle.counters(),
        None => net::proxy::LaunchCounters::new(),
    };

    // (7) The request, and the tier it dispatches to — both known BEFORE the
    //     launch, because a refused launch carries no `SessionOutcome` to read the
    //     tier from and a leaf that says `tier: null` for a session that
    //     dispatched to `base-container` is the omission guardrail 2 exists to
    //     prevent.
    let input = net::mxc::MxcSessionInput {
        command: join_cmdline(cmd),
        working_directory: Some(cwd.display().to_string()),
        // The one env marker both backends inject. The rest of the AppContainer
        // block is AppContainer-specific: its `PATH`/`PYTHONPATH` shims point into
        // `.sandbox/<sid>` (which MXC does not use), and the proxy variables come
        // from the SDK's `runtimeConfig.networkProxy`.
        environment: vec![("SAIFE_SESSION_SID".to_string(), sid.to_string())],
        filesystem,
        network: net::mxc::MxcNetworkInput {
            proxy_port,
            // The backend overrides this with its own run token; a caller value
            // could not authenticate against this listener anyway.
            proxy_token: None,
        },
        // The backend always writes `Some(budget.timeout_ms())`; never trusted here.
        timeout_ms: None,
        // P3.4: a real console for the child when this process has one, so an
        // interactive workload (a TUI) can run; captured pipes otherwise, and
        // always when `--no-interactive` asks for them. The decision is
        // `cli::inherit_console` (pure, table-tested); the terminals are read
        // here, at the one place that knows it is the supervisor.
        stdio: if cli::inherit_console(
            no_interactive,
            std::io::stdin().is_terminal(),
            std::io::stdout().is_terminal(),
        ) {
            net::mxc::StdioSelection::Inherit
        } else {
            net::mxc::StdioSelection::Capture
        },
    };
    // Decision 3: the deadline is the RESOLVED profile's `limits`, never the
    // defaults, and never the network slice's (which no longer carries the terms).
    let budget = limits.session_budget();
    let request = net::mxc::request_for_session(
        counters.as_ref(),
        proxy_port,
        token,
        &launcher,
        budget,
        &input,
    )?;
    let probed = net::mxc::probe_tier(&request)?;
    let endpoint = proxy_port.map(audit::session_start::LoopbackEndpoint::new);

    // (7b) THE ROOT — before the child can exist (P3.1, S-55). Every fact the leaf
    //      states is already known at this point: the probe of the exact request
    //      named the tier and its provenance, `start_session_proxy` bound the port,
    //      and the elevation is this process's own token. Writing it here is what
    //      makes a supervisor killed mid-session leave a readable chain with no
    //      sealed root — `audit verify` then says INCOMPLETE, exactly as the
    //      AppContainer path always has. P3.0 wrote this leaf after the launch
    //      returned (taking the tier from the launch record), so a hard kill left
    //      nothing to verify at all.
    //
    //      Guardrail 2's hard half is decided from the SAME probe, so a degraded
    //      tier still refuses before anything runs: root(deny) naming what the
    //      probe reported, then SESSION_REFUSED, no child, no CONNECT leaf.
    let claimed = probed.audit_facts();
    if let Some(mismatch) = pre_launch_tier_refusal(&probed) {
        session_start.with_tier(claimed).refuse(
            endpoint,
            audit::session_start::TierRefusal::tier_mismatch(mismatch.expected),
        )?;
        seal_audit(audit_writer, proxy.map(|(handle, _)| handle), sid);
        eprintln!("[saife] mxc: {mismatch}");
        return Ok(EXIT_REFUSED);
    }
    session_start
        .with_tier(claimed.clone())
        .complete(endpoint)?;

    // (8) The launch. `launch_session` derives the guardrail leg from the port and
    //     builds its backend with `TierExpectation::Exactly(REQUIRED_TIER)`.
    let outcome = match net::mxc::launch_session(
        counters.as_ref(),
        proxy_port,
        token,
        &launcher,
        budget,
        &input,
    ) {
        Ok(outcome) => outcome,
        Err(e) => match refusal_for(&e) {
            Some(refusal) => {
                // A guardrail-1 refusal happens AFTER the child ran, and the refusal
                // carries its result: print what the workload did first, so the
                // operator sees their own command's output next to the reason the
                // session was refused. Losing it made a refused session
                // indistinguishable from one that never started.
                if let net::mxc::MxcError::Unproven(unproven) = &e {
                    emit_child_output(&unproven.outcome);
                }
                // Decision 5: a refused session is refused IN THE CHAIN. Only the
                // refusal leaf is written here — the root is already on disk (7b)
                // and one root per run is the guarantee, so this leaf records how
                // the session ended beside a root that records how it started. That
                // root says `allow` because it was written before the verdict
                // existed, and it is not rewritten to say otherwise.
                audit::session_start::append_refusal(&audit_writer, sid, refusal)?;
                seal_audit(audit_writer, proxy.map(|(handle, _)| handle), sid);
                eprintln!("[saife] mxc: {e}");
                return Ok(launch_failure_exit(&e));
            }
            // Nothing was established (no request, no container, no epoch, an SDK
            // failure): the root from (7b) is the whole record, and no refusal leaf
            // is added — a refusal leaf would claim a gate ran when none did.
            None => return Err(e.into()),
        },
    };

    // (9) The launch record is a CONFIRMATION, not a source (P3.1, S-55). The root
    //     already claims the tier the pre-launch probe of the exact request named,
    //     and the launch gates on its own probe of that same request — so the two
    //     must agree. If they do not, the root is wrong about the containment this
    //     session got, and rewriting it is not an option (one root per run): the
    //     session is refused, and the refusal leaf names the tier it required.
    if !launch_confirms_root(&claimed, &outcome.tier) {
        emit_child_output(&outcome);
        audit::session_start::append_refusal(
            &audit_writer,
            sid,
            audit::session_start::TierRefusal::tier_mismatch(net::mxc::REQUIRED_TIER),
        )?;
        seal_audit(audit_writer, proxy.map(|(handle, _)| handle), sid);
        eprintln!(
            "[saife] mxc: guardrail 2: the launch recorded tier `{}` (source `{}`) but this \
             session's root already claims `{}` — a record that does not confirm the root \
             refuses the session, and the root is not rewritten",
            outcome.tier.tier.as_deref().unwrap_or("no tier"),
            outcome.tier.tier_source,
            claimed.tier.as_deref().unwrap_or("no tier"),
        );
        return Ok(EXIT_REFUSED);
    }

    emit_child_output(&outcome);
    // Guardrail 1's evidence, in the operator's own transcript: since the
    // 2026-10-22 amendment the gate is satisfied by the wrapper's pre-flight
    // probe, and a counter the operator cannot see is a gate nobody can audit
    // after the fact. One line, on stderr, beside the warnings and the timeout
    // reason. Since P3.2a it also carries the epoch's unauthenticated attempts —
    // the leg that catches a client stack which reached the proxy and could not
    // use it — so a refusal and a pass are auditable from the same line.
    eprintln!(
        "[saife] mxc: guardrail 1 proof probes={} accepted={} tunnels={} unauthenticated={}",
        outcome.proxy_proof.probes,
        outcome.proxy_proof.accepted,
        outcome.proxy_proof.tunnels,
        outcome.proxy_proof.unauthenticated
    );
    for warning in &outcome.warnings {
        eprintln!("[saife] mxc: warning: {warning}");
    }
    if let Some(reason) = outcome.timeout {
        // Decision 6: the reason token says whether the operator's command or the
        // supervisor ran the clock out — the two have different remedies.
        eprintln!(
            "[saife] mxc: session ended at its deadline ({} ms = prompt {} s + workload {} s \
             + slack {} s) — reason {reason}",
            budget.session().as_millis(),
            budget.prompt.as_secs(),
            budget.workload.as_secs(),
            budget.slack.as_secs(),
        );
    }

    seal_audit(audit_writer, proxy.map(|(handle, _)| handle), sid);
    Ok(session_exit_code(&outcome))
}

/// How a failed MXC launch is recorded in the chain (P3.0 decision 5, P3.1 S-55).
///
/// `Some(refusal)` means the session reached a state a reader must be able to
/// select on: the root is already on disk (written before the launch, which is the
/// S-55 fix), so
/// the refusal appends a `SESSION_REFUSED` leaf naming the reason. Both of
/// ADR-0004's guardrails are audited that way — the tier gate (which refuses
/// *before* the child exists, so [`pre_launch_tier_refusal`] has already written
/// root(`deny`)) and the proof gate (refused after it ran).
///
/// `None` means nothing was established (a request that could not be built, an SDK
/// error, a second concurrent launch): the root written before the launch is the
/// whole record, and no refusal leaf is added — a refusal leaf would claim a gate
/// ran when none did.
#[cfg(feature = "mxc-backend")]
fn refusal_for(err: &net::mxc::MxcError) -> Option<audit::session_start::TierRefusal<'static>> {
    use audit::session_start::TierRefusal;
    use net::mxc::{MxcError, REQUIRED_TIER};
    match err {
        // Guardrail 1, both shapes of it: `Guard` is the pre-run refusal (no proof
        // source, `Required` without a proxy) and `Unproven` the post-run one. The
        // tier the session required is the refusal's `expected`; the root already
        // carries the tier that was probed.
        // Each guard cause gets its own token: an operator error and a client stack
        // that cannot use a proxy are different diagnoses, and the audit is the only
        // place that distinction survives.
        MxcError::Guard(g) => Some(TierRefusal::refused(g.audit_reason(), REQUIRED_TIER)),
        MxcError::Unproven(_) => Some(TierRefusal::proof_unmet(REQUIRED_TIER)),
        // Guardrail 2, the shape that can only be reached after the root exists:
        // the launch's own probe of the same request disagreed with the pre-launch
        // probe the root was written from. The mismatch carries what was dispatched
        // INSTEAD, and the requirement is the refusal's `expected_tier` — the root
        // is not rewritten to either.
        MxcError::Tier(mismatch) => Some(TierRefusal::tier_mismatch(mismatch.expected)),
        MxcError::Request(_) | MxcError::Sdk(_) | MxcError::Concurrency(_) => None,
    }
}

/// Guardrail 2's hard half, applied to the tier the **pre-launch** probe named
/// (P3.1, S-55).
///
/// This runs before the root is written, from the same [`net::mxc::TierRecord`]
/// the root is filled from — that is what lets a mismatch still be `root(deny) +
/// SESSION_REFUSED` with no child and no CONNECT leaf, while every other session's
/// root goes to disk before `launch_session` is even called.
///
/// `Some` is the refusal: the session requires [`net::mxc::REQUIRED_TIER`] and the
/// probe of the exact request named something else (or nothing at all, which is
/// refused rather than waved through — see [`net::mxc::verify_tier`]).
#[cfg(feature = "mxc-backend")]
fn pre_launch_tier_refusal(probed: &net::mxc::TierRecord) -> Option<net::mxc::TierMismatch> {
    net::mxc::verify_tier(
        probed,
        net::mxc::TierExpectation::Exactly(net::mxc::REQUIRED_TIER),
    )
    .err()
}

/// Does the launch record **confirm** the facts the root already claims?
/// (P3.1, S-55.)
///
/// The root is written from the probe of the exact request before the launch, and
/// the launch gates on its own probe of that same request, so the two must agree.
/// The comparison is made in the leaf's own vocabulary
/// (`audit::session_start::TierFacts`) because the leaf is what a reader of the
/// chain sees: a record that differed would leave the root's `tier` a claim nothing
/// confirmed, which is exactly what guardrail 2 forbids.
#[cfg(feature = "mxc-backend")]
fn launch_confirms_root(
    claimed: &audit::session_start::TierFacts,
    recorded: &net::mxc::TierRecord,
) -> bool {
    recorded.audit_facts() == *claimed
}

/// The exit code a refused MXC session ends with (P3.0 decision 6).
///
/// A child's own code is not distinguishable by value alone — a child may exit 124
/// or 126 itself — so the named reason on stderr is the discriminator. These codes
/// exist so a *script* can tell "the session was refused" from "the command failed"
/// without parsing prose.
#[cfg(feature = "mxc-backend")]
fn launch_failure_exit(err: &net::mxc::MxcError) -> i32 {
    match err {
        net::mxc::MxcError::Guard(_)
        | net::mxc::MxcError::Unproven(_)
        | net::mxc::MxcError::Tier(_) => EXIT_REFUSED,
        _ => 1,
    }
}

/// The exit code a finished MXC session ends with (P3.0 decision 6).
///
/// Mirrors the AppContainer contract — a child that exits `N` returns `N` — except
/// for a kill at the deadline, which is the supervisor's verdict and not the
/// command's, and therefore gets its own code instead of `None`-as-`0`.
#[cfg(feature = "mxc-backend")]
fn session_exit_code(outcome: &net::mxc::SessionOutcome) -> i32 {
    match (outcome.timeout, outcome.exit_code) {
        (Some(_), _) => EXIT_TIMEOUT,
        (None, Some(code)) => code,
        // Neither a code nor a timeout: the SDK gave neither, which is not success.
        (None, None) => 1,
    }
}

/// Replay the child's captured streams for an MXC session.
///
/// The AppContainer path hands the child the console handles directly, so its
/// output is already on our stdout. MXC captures both streams inside the SDK, so
/// the supervisor replays them — before its own verdict line, so a transcript reads
/// "what the command did" and then "what the session concluded".
#[cfg(feature = "mxc-backend")]
fn emit_child_output(outcome: &net::mxc::SessionOutcome) {
    use std::io::Write as _;
    let mut out = std::io::stdout().lock();
    let _ = out.write_all(&outcome.stdout);
    let _ = out.flush();
    let mut err = std::io::stderr().lock();
    let _ = err.write_all(&outcome.stderr);
    let _ = err.flush();
}

/// Start this run's proxy listener, if its network posture has one.
///
/// Extracted from [`run_inner`] **unchanged** in P3.0: the two session paths must
/// not be able to drift on the parts that have to agree — one credential per run
/// (P1.4), the learned policy loaded before the listener starts ([G-5] — a corrupt
/// file is a hard error), the D-4 registry and prompt coordinator, the [G-10]
/// upstream precedence with its inherited `NO_PROXY`, and the ungated degradation
/// warning for an unusable upstream URL.
///
/// `Ok(None)` for a blocked session: nothing binds, so nothing can be proven, and
/// the guardrail leg is [`net::mxc::ProofExpectation::MustBeAbsent`]. Otherwise the
/// listener plus the child's [`net::ProxyEnv`] — the caller MUST hold the handle
/// until the child has exited.
///
/// `prompt_timeout_secs` is the RESOLVED prompt term
/// ([`profile::Limits::prompt_timeout_secs`]), passed in rather than read from
/// `net_cfg`: the session deadline is built from the same value, and the two must
/// never be able to disagree (2026-10-25 moved the term out of the network slice).
fn start_session_proxy(
    net_cfg: &net::NetworkConfig,
    prompt_timeout_secs: u32,
    sid: &str,
    writer: std::sync::Arc<audit::AuditWriter>,
    facade: std::sync::Arc<plugin::FacadeRegistry>,
) -> Result<Option<(net::proxy::ProxyHandle, net::ProxyEnv)>> {
    // The listener MUST outlive the child: the caller holds the handle until the
    // child has exited (see `seal_audit`).
    Ok(match net_cfg {
        net::NetworkConfig::Blocked => None,
        net::NetworkConfig::Allow {
            allow_domain,
            deny_domain,
            prompt_enabled,
            on_unavailable,
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
                "load learned policy file ('saife learned clear' resets a corrupt one)",
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
                    timeout: std::time::Duration::from_secs(u64::from(prompt_timeout_secs)),
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
            // [G-42] The override notice rides the SAIFE_DIAG stream.
            if let Some(w) = upstream_warn
                && std::env::var_os("SAIFE_DIAG").is_some()
            {
                eprintln!("[saife] SAIFE_DIAG: {w}");
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
                        // this line is NOT SAIFE_DIAG-gated; the gated line
                        // below adds the parse detail. The reason is static
                        // and the endpoint redacted: the URL itself is never
                        // echoed ([G-30]).
                        if let Some(source) = upstream_source {
                            eprintln!(
                                "[saife] warning: {}",
                                upstream_parse_failure_warning(source, &raw, &e)
                            );
                        }
                        if std::env::var_os("SAIFE_DIAG").is_some() {
                            eprintln!(
                                "[saife] SAIFE_DIAG: ignoring upstream proxy {} ({e}); \
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
                session_id: sid.to_string(),
                token: token.clone(),
                allow_domain: allow_domain.clone(),
                deny_domain: deny_domain.clone(),
                upstream,
                writer: writer.clone(),
                prompt,
                facade,
            })
            .context("start localhost proxy")?;
            let proxy_env = net::ProxyEnv {
                port: handle.port,
                // The child's copy of this run's credential; the listener holds
                // the same value and refuses every other. Cloning the `RunToken`
                // (rather than its `String`) keeps the env edge typed (P1.6(c)).
                token: token.clone(),
            };
            Some((handle, proxy_env))
        }
    })
}

/// Commit this run's audit root + signature and release the writer (US-4a).
///
/// Extracted from [`run_inner`] in P3.0 so **both** session paths seal the chain
/// the same way. The ordering below is the entire content of the function and is
/// load-bearing; see its comments.
fn seal_audit(
    writer: std::sync::Arc<audit::AuditWriter>,
    proxy: Option<net::proxy::ProxyHandle>,
    sid: &str,
) {
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
    // Seal FIRST: from here no leaf can be appended, so the root below is the last
    // line of the file by construction. The previous shape captured the root, dropped
    // the proxy and slept 50 ms - and a late refusal-aggregate flush in that window
    // produced a log that grew past its own committed root, which `verify` reports as
    // TAMPERED. A sleep is not a happens-before edge.
    let captured_root = writer.seal();

    // The proxy can still be winding down; its late appends are now dropped by the
    // sealed writer instead of racing the file.
    drop(proxy);

    // Drop our Arc<AuditWriter>. The proxy thread's Arc may still be alive (it
    // was detached), but `AuditWriter::append` holds the file open with
    // `OpenOptions::append(true).create(true)` per call (no long-lived handle),
    // so dropping the Arc just releases the in-memory state. The file on disk
    // is already consistent up to the last `append`.
    drop(writer);

    if let Some(root) = captured_root
        && let Err(e) = commit_audit_root(sid, &root)
    {
        eprintln!("[saife] warning: failed to commit audit root: {e:#}");
        // The log is still readable; verify will report INCOMPLETE.
    }
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

    /// A finished MXC session, for the exit-code and refusal tests: what the two
    /// functions read, plus whatever `SessionOutcome` requires.
    #[cfg(feature = "mxc-backend")]
    fn finished_outcome(
        exit_code: Option<i32>,
        timeout: Option<net::mxc::TimeoutReason>,
    ) -> net::mxc::SessionOutcome {
        net::mxc::SessionOutcome {
            exit_code,
            timeout,
            stdout: b"out".to_vec(),
            stderr: b"err".to_vec(),
            warnings: Vec::new(),
            tier: base_container_record(),
            proxy_proof: net::mxc::ProxyProof::default(),
            expectation: net::mxc::ProofExpectation::MustBeAbsent,
            clock: net::mxc::SessionClock::measured(
                net::mxc::SessionBudget::default(),
                std::time::Duration::from_secs(5),
                std::time::Duration::from_secs(1),
                std::time::Duration::ZERO,
            ),
        }
    }

    #[cfg(feature = "mxc-backend")]
    fn base_container_record() -> net::mxc::TierRecord {
        net::mxc::tier_record(net::mxc::ProbeView {
            tier: Some(net::mxc::REQUIRED_TIER),
            needs_dacl_augmentation: Some(false),
        })
    }

    /// P3.0 decision 6: the AppContainer contract is mirrored for a child that
    /// exits `N` (return `N`), and a kill at the deadline is **not** that code — it
    /// gets its own, so "my command exited 124" and "the supervisor killed it at its
    /// budget" are distinguishable to a script. The `TimeoutReason` token beside the
    /// code says which term spent the clock.
    #[cfg(feature = "mxc-backend")]
    #[test]
    fn a_child_exit_code_is_mirrored_and_a_timeout_has_its_own() {
        assert_eq!(session_exit_code(&finished_outcome(Some(3), None)), 3);
        assert_eq!(session_exit_code(&finished_outcome(Some(0), None)), 0);
        let timed_out =
            finished_outcome(None, Some(net::mxc::TimeoutReason::WorkloadBudgetExceeded));
        assert_eq!(session_exit_code(&timed_out), EXIT_TIMEOUT);
        assert_eq!(
            timed_out.timeout.map(|reason| reason.as_str()),
            Some("workload_budget_exceeded"),
            "the operator is told which term ran the clock out"
        );
        assert_ne!(
            EXIT_TIMEOUT, EXIT_REFUSED,
            "a kill and a refusal must differ"
        );
    }

    /// A `TierRecord` for a session that dispatched to the **degraded** tier: the
    /// shape guardrail 2 refuses. The probe named it, so `tier_source` is `probe`
    /// and `needs_dacl_augmentation` is the probe's own `true` — not `None`.
    #[cfg(feature = "mxc-backend")]
    fn degraded_record() -> net::mxc::TierRecord {
        net::mxc::tier_record(net::mxc::ProbeView {
            tier: Some("appcontainer-dacl"),
            needs_dacl_augmentation: Some(true),
        })
    }

    /// A session id no other test can collide with.
    #[cfg(feature = "mxc-backend")]
    fn chain_sid(label: &str) -> String {
        format!(
            "test-p31-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        )
    }

    /// Every leaf of a session's chain, in file order.
    #[cfg(feature = "mxc-backend")]
    fn chain_leaves(sid: &str) -> Vec<serde_json::Value> {
        std::fs::read_to_string(audit::audit_log_path(sid))
            .unwrap_or_default()
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str(l).expect("each leaf is one JSON object"))
            .collect()
    }

    /// Remove a test session's chain, seal included.
    #[cfg(feature = "mxc-backend")]
    fn drop_chain(sid: &str) {
        let p = audit::audit_log_path(sid);
        let _ = std::fs::remove_file(&p);
        let _ = std::fs::remove_file(p.with_extension("root"));
        let _ = std::fs::remove_file(p.with_extension("sig"));
    }

    /// P3.0 decision 5, restated for P3.1 (S-55): only a **gate** refusal is
    /// written into the chain, and it is written as one leaf — the root is already
    /// on disk from before the launch.
    #[cfg(feature = "mxc-backend")]
    #[test]
    fn only_a_gate_refusal_reaches_the_chain() {
        use audit::session_start::{REASON_PROOF_UNMET, REASON_TIER_MISMATCH};
        use net::mxc::{GuardError, MxcError, REQUIRED_TIER, RequestError, TierMismatch};

        // Guardrail 1, pre-run shape. The reason is the guard's own cause, so the
        // five diagnoses stay distinguishable in the record.
        let guard = MxcError::Guard(GuardError::ProbeUnmet);
        let refusal = refusal_for(&guard).expect("guardrail 1 is recorded");
        assert_eq!(refusal.expected, REQUIRED_TIER);
        assert_eq!(refusal.reason, "proxy_probe_unmet");
        assert_eq!(launch_failure_exit(&guard), EXIT_REFUSED);

        // A different cause is a different token - this is what the collapse lost.
        let no_client = MxcError::Guard(GuardError::WorkloadCannotAuthenticate);
        assert_eq!(
            refusal_for(&no_client).expect("recorded").reason,
            "workload_cannot_authenticate"
        );
        let no_source = MxcError::Guard(GuardError::MissingProofSource);
        assert_eq!(
            refusal_for(&no_source).expect("recorded").reason,
            "proxy_proof_unavailable"
        );

        // Guardrail 1, post-run shape: same reason, and the one that carries the
        // workload's own output into the transcript.
        let unproven = MxcError::Unproven(Box::new(net::mxc::Unproven {
            error: GuardError::ProbeUnmet,
            outcome: finished_outcome(Some(0), None),
        }));
        let refusal = refusal_for(&unproven).expect("guardrail 1 is recorded");
        assert_eq!(refusal.reason, REASON_PROOF_UNMET);
        assert_eq!(launch_failure_exit(&unproven), EXIT_REFUSED);

        // Guardrail 2 after the root exists: the refusal names the requirement,
        // never the tier that was dispatched instead — the root already says that,
        // and it is not rewritten.
        let degraded = MxcError::Tier(TierMismatch {
            expected: REQUIRED_TIER,
            observed: Some("appcontainer-dacl".to_string()),
            source: "probe",
        });
        let refusal = refusal_for(&degraded).expect("guardrail 2 is recorded");
        assert_eq!(refusal.reason, REASON_TIER_MISMATCH);
        assert_eq!(refusal.expected, REQUIRED_TIER);
        assert_eq!(launch_failure_exit(&degraded), EXIT_REFUSED);

        // Nothing established: the root from before the launch is the whole
        // record, and a refusal leaf would claim a gate ran when none did.
        let unbuilt = MxcError::Request(RequestError::EmptyCommand);
        assert!(refusal_for(&unbuilt).is_none());
        assert_eq!(launch_failure_exit(&unbuilt), 1);
    }

    /// **S-55 on the MXC path**: the root is written before the launch, so a
    /// supervisor killed from that moment on leaves a readable chain — one root,
    /// the five facts, **no** `.root` seal — and `verify` says INCOMPLETE.
    ///
    /// The crash is expressed the only way a test can: the root is written and then
    /// nothing else happens — no launch, no `seal_audit`, no second leaf, and the
    /// writer is dropped without committing a root. `AuditWriter::append` opens,
    /// writes and closes per leaf ([`audit::AuditWriter::append`]), so the root is
    /// on disk the moment `complete` returns: there is no userspace buffer a
    /// `TerminateProcess` could lose, which is why the ordering alone is the fix.
    ///
    /// Both network postures: S-55 runs `--block-net`, where no listener exists and
    /// the endpoint must stay `null`; a networked session must record the port it
    /// bound, because that is a fact the root is now written early enough to carry.
    #[cfg(feature = "mxc-backend")]
    #[test]
    fn a_kill_after_the_root_leaves_one_root_five_facts_and_no_seal() {
        use audit::session_start::{LoopbackEndpoint, SessionStart, SessionStartFacts, TierFacts};
        use audit::verify::{VerifyOutcome, verify_inner};

        let elevated = setup::is_elevated();
        for (label, port) in [("block-net", None), ("networked", Some(49_152u16))] {
            let sid = chain_sid(label);
            // (4) writer + armed guard, (5) listener bound, (7b) the root — and then
            // the supervisor dies: the launch never happens.
            {
                let writer = std::sync::Arc::new(audit::AuditWriter::open(&sid, false).unwrap());
                SessionStart::arm(
                    writer,
                    &sid,
                    "cmd /c ping -n 30 127.0.0.1",
                    // Armed with what the supervisor knows before the probe — the
                    // probe's tier arrives through `with_tier`, as the session path
                    // does it.
                    SessionStartFacts::measured(TierFacts::default(), Some(elevated)),
                )
                .with_tier(base_container_record().audit_facts())
                .complete(port.map(LoopbackEndpoint::new))
                .unwrap();
            }

            let path = audit::audit_log_path(&sid);
            let leaves = chain_leaves(&sid);
            let sealed = path.with_extension("root").is_file();
            let signed = path.with_extension("sig").is_file();
            let verdict = verify_inner(&sid).unwrap();
            drop_chain(&sid);

            assert_eq!(
                leaves.len(),
                1,
                "{label}: the root is the whole chain: {leaves:?}"
            );
            let root = &leaves[0];
            assert_eq!(root["op"], audit::session_start::OP_SESSION_START);
            assert_eq!(root["seq"], 0, "{label}: the root is the genesis leaf");
            assert_eq!(root["parent"], serde_json::Value::Null);
            assert_eq!(root["disposition"], "allow", "{label}: it started");
            // The five facts, all of them, with no `.root` anywhere in sight.
            assert_eq!(root["tier"], net::mxc::REQUIRED_TIER);
            assert_eq!(root["tier_source"], net::mxc::TIER_SOURCE_PROBE);
            assert_eq!(root["tier_needs_dacl_augmentation"], false);
            assert_eq!(root["elevated"], elevated);
            match port {
                Some(p) => assert_eq!(root["proxy_endpoint"], format!("127.0.0.1:{p}")),
                None => assert_eq!(
                    root["proxy_endpoint"],
                    serde_json::Value::Null,
                    "{label}: --block-net binds nothing, so the endpoint is null"
                ),
            }
            assert!(!sealed, "{label}: a killed supervisor commits no root");
            assert!(!signed, "{label}: and signs nothing");
            match verdict {
                VerifyOutcome::Incomplete(reason) => assert!(
                    reason.contains("no committed root"),
                    "{label}: INCOMPLETE must name the missing seal: {reason}"
                ),
                other => {
                    panic!("{label}: a killed session must verify as INCOMPLETE, got {other:?}")
                }
            }
        }
    }

    /// Requirement (b): on the success path the leaf's facts **equal** the launch
    /// record's tier. Because the record now arrives after the root, the only thing
    /// it may do is confirm it — and a record that disagrees refuses the session
    /// instead of rewriting the root, still leaving exactly one root.
    #[cfg(feature = "mxc-backend")]
    #[test]
    fn the_launch_record_confirms_the_root_it_did_not_write() {
        use audit::session_start::{
            LoopbackEndpoint, OP_SESSION_REFUSED, OP_SESSION_START, SessionStart,
            SessionStartFacts, TierFacts, TierRefusal,
        };

        let sid = chain_sid("confirm");
        let probed = base_container_record();
        let writer = {
            let writer = std::sync::Arc::new(audit::AuditWriter::open(&sid, false).unwrap());
            SessionStart::arm(
                writer.clone(),
                &sid,
                "cmd /c echo MXC-WIRED",
                SessionStartFacts::measured(TierFacts::default(), Some(false)),
            )
            .with_tier(probed.audit_facts())
            .complete(Some(LoopbackEndpoint::new(49_154)))
            .unwrap();
            writer
        };

        // The record a successful launch hands back, for the same request.
        let recorded = base_container_record();
        let leaves = chain_leaves(&sid);
        let root = &leaves[0];
        assert_eq!(leaves.len(), 1, "one root: {leaves:?}");
        assert_eq!(root["op"], OP_SESSION_START);
        // The leaf's facts ARE the record's, field for field.
        assert_eq!(root["tier"], recorded.tier.clone().unwrap_or_default());
        assert_eq!(root["tier_source"], recorded.tier_source);
        assert_eq!(
            root["tier_needs_dacl_augmentation"],
            recorded.needs_dacl_augmentation.unwrap_or(false)
        );
        assert!(
            launch_confirms_root(&probed.audit_facts(), &recorded),
            "the launch record must confirm the facts the root claims"
        );

        // A record from a different tier is NOT confirmed, and step (9) refuses
        // rather than rewriting the root: the refusal leaf is the only write.
        let degraded = degraded_record();
        assert!(
            !launch_confirms_root(&probed.audit_facts(), &degraded),
            "a degraded record must not pass as confirmation"
        );
        audit::session_start::append_refusal(
            &writer,
            &sid,
            TierRefusal::tier_mismatch(net::mxc::REQUIRED_TIER),
        )
        .unwrap();
        drop(writer);

        let leaves = chain_leaves(&sid);
        drop_chain(&sid);
        let roots = leaves
            .iter()
            .filter(|l| l["op"] == OP_SESSION_START)
            .count();
        assert_eq!(roots, 1, "one root per run, even when refused: {leaves:?}");
        assert_eq!(
            leaves[0]["disposition"], "allow",
            "the root is not rewritten to deny after the fact"
        );
        assert_eq!(leaves[0]["tier"], net::mxc::REQUIRED_TIER);
        assert_eq!(leaves[1]["op"], OP_SESSION_REFUSED);
        assert_eq!(
            leaves[1]["reason"],
            audit::session_start::REASON_TIER_MISMATCH
        );
        assert_eq!(
            leaves[1]["parent"], leaves[0]["hash"],
            "the refusal links to the root"
        );
    }

    /// Requirement 2: a tier mismatch is still decided **before** the root is
    /// written, so a refused session's root can still say `deny` and still be the
    /// first leaf — the shape a refused AppContainer session has.
    #[cfg(feature = "mxc-backend")]
    #[test]
    fn a_tier_mismatch_is_decided_before_the_root_so_the_root_can_say_deny() {
        use audit::session_start::{
            LoopbackEndpoint, OP_SESSION_REFUSED, OP_SESSION_START, SessionStart,
            SessionStartFacts, TierFacts, TierRefusal,
        };

        assert!(
            pre_launch_tier_refusal(&base_container_record()).is_none(),
            "the required tier is not a refusal"
        );
        let degraded = degraded_record();
        let mismatch = pre_launch_tier_refusal(&degraded)
            .expect("a degraded tier is refused before anything is launched");
        assert_eq!(mismatch.expected, net::mxc::REQUIRED_TIER);
        assert_eq!(mismatch.observed.as_deref(), Some("appcontainer-dacl"));

        let sid = chain_sid("pre-launch-deny");
        {
            let writer = std::sync::Arc::new(audit::AuditWriter::open(&sid, false).unwrap());
            SessionStart::arm(
                writer,
                &sid,
                "cmd /c echo MXC-WIRED",
                SessionStartFacts::measured(TierFacts::default(), Some(false)),
            )
            .with_tier(degraded.audit_facts())
            .refuse(
                Some(LoopbackEndpoint::new(41_000)),
                TierRefusal::tier_mismatch(mismatch.expected),
            )
            .unwrap();
        }
        let leaves = chain_leaves(&sid);
        drop_chain(&sid);

        assert_eq!(leaves.len(), 2, "root + refusal: {leaves:?}");
        assert_eq!(leaves[0]["op"], OP_SESSION_START);
        assert_eq!(leaves[0]["parent"], serde_json::Value::Null);
        assert_eq!(
            leaves[0]["disposition"], "deny",
            "the root must not claim a start when the next leaf says refused"
        );
        assert_eq!(leaves[0]["tier"], "appcontainer-dacl");
        assert_eq!(
            leaves[0]["tier_needs_dacl_augmentation"], true,
            "the probe's own value, verbatim: the deny root is as complete as the allow one"
        );
        assert_eq!(leaves[1]["op"], OP_SESSION_REFUSED);
        assert_eq!(leaves[1]["expected_tier"], net::mxc::REQUIRED_TIER);
        assert!(
            leaves.iter().all(|l| l["op"] != "CONNECT"),
            "nothing ran, so nothing could reach the proxy: {leaves:?}"
        );
    }

    /// The newest `mtime` under `src/`, so a spawned supervisor can be shown to be
    /// newer than the code this run is testing.
    #[cfg(feature = "mxc-backend")]
    fn newest_source_mtime() -> Option<std::time::SystemTime> {
        fn walk(dir: &std::path::Path, newest: &mut Option<std::time::SystemTime>) {
            let Ok(entries) = std::fs::read_dir(dir) else {
                return;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    walk(&path, newest);
                } else if path.extension().is_some_and(|e| e == "rs")
                    && let Ok(mtime) = entry.metadata().and_then(|m| m.modified())
                    && newest.map(|n| mtime > n).unwrap_or(true)
                {
                    *newest = Some(mtime);
                }
            }
        }
        let mut newest = None;
        walk(std::path::Path::new("src"), &mut newest);
        newest
    }

    /// **S-55, the shape the harness runs** (P3.1): spawn the real supervisor on a
    /// real container, wait for its root, `TerminateProcess` it mid-session, then
    /// read the chain the way `audit verify` does.
    ///
    /// This is the *ordering* test. It asserts the root is on disk **while the child
    /// is still running**, which is exactly what P3.0's post-launch write could not
    /// do: with that ordering the log never appeared at all — `audit show` failed
    /// and `verify` had nothing to call INCOMPLETE. Reproduced against the old
    /// ordering, this test fails on "the root must be on disk while the child is
    /// still running"; with the root moved ahead of the launch it passes.
    #[cfg(feature = "mxc-backend")]
    #[test]
    #[ignore = "launches a real ProcessContainer and hard-kills a real supervisor; run: cargo test --features mxc-backend --bin saife -- --ignored"]
    fn a_supervisor_killed_mid_session_leaves_a_chain_verify_can_read() {
        use audit::verify::{VerifyOutcome, verify_inner};
        use std::time::Duration;

        let exe = std::env::current_exe().expect("current test exe");
        let supervisor = exe
            .parent()
            .and_then(std::path::Path::parent)
            .map(|profile| profile.join("saife.exe"))
            .expect("a profile directory above deps/");
        assert!(
            supervisor.is_file(),
            "build it first: cargo build --features mxc-backend --bin saife ({})",
            supervisor.display()
        );
        assert!(
            net::mxc::launcher_beside(&supervisor).is_some(),
            "saife-launch.exe must sit beside the supervisor: \
             cargo build --features mxc-backend --bin saife-launch"
        );
        // A spawned supervisor is evidence only if it was built from the sources
        // under test: `cargo test --bin saife` builds the TEST harness and leaves
        // `target/debug/saife.exe` alone, so a stale binary would answer for code
        // that has since changed — it inverted this very test's own RED probe.
        if let (Some(built), Some(source)) = (
            std::fs::metadata(&supervisor)
                .and_then(|m| m.modified())
                .ok(),
            newest_source_mtime(),
        ) {
            assert!(
                built >= source,
                "{} is older than src/: rebuild it first \
                 (`cargo build --features mxc-backend --bin saife`), or this run is \
                 measuring a binary that does not contain the code under test",
                supervisor.display()
            );
        }

        let scratch = std::env::temp_dir().join(format!("sandbox-s55-live-{}", std::process::id()));
        std::fs::create_dir_all(&scratch).expect("create the session working directory");
        let sid = chain_sid("s55-live");
        // A reused id would continue an existing chain and land a second root.
        drop_chain(&sid);

        let mut child = std::process::Command::new(&supervisor)
            .args([
                "run",
                "--backend",
                "mxc",
                // The posture S-55 runs: no listener, so no CONNECT leaf and no
                // endpoint to record — the root alone has to carry the session.
                "--block-net",
                "--allow-cwd",
                "--sid",
                &sid,
                "--",
                "cmd",
                "/c",
                // A workload that stays alive without a console, a network or an
                // interpreter the container may not have: S-55's own sleeper
                // (`python`) is not on the container's PATH, and `ping` cannot reach
                // the IP driver inside a `--block-net` container (both observed). A
                // counting loop runs for several seconds and exits on its own if the
                // kill somehow misses it.
                "for /l %i in (1,1,20000000) do @rem",
            ])
            .current_dir(&scratch)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn the supervisor");

        // Wait for the root the way a reader would — the file exists and carries a
        // SESSION_START. A minute is a container launch, not the assertion.
        let deadline = std::time::Instant::now() + Duration::from_secs(60);
        let mut root = None;
        while std::time::Instant::now() < deadline {
            root = chain_leaves(&sid)
                .into_iter()
                .find(|l| l["op"] == audit::session_start::OP_SESSION_START);
            if root.is_some() {
                break;
            }
            if let Ok(Some(status)) = child.try_wait() {
                panic!("the supervisor exited before writing a root: {status}");
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let root = root.expect("the root must be on disk while the child is still running");

        // The property, stated once: the root is on disk **because it was written
        // before the launch**, so the supervisor is still running when the kill
        // arrives. A supervisor that writes the root only after the launch returns
        // has nothing to show a kill — by the time the file exists the session is
        // over, which is what this assertion catches.
        std::thread::sleep(Duration::from_millis(500));
        assert!(
            child.try_wait().expect("poll the supervisor").is_none(),
            "the supervisor must still be running when it is killed; a root that only \
             appears once the launch returns is a root written after the session ended"
        );
        // Stop-Process -Force, as the harness does it.
        let killed = std::process::Command::new("taskkill")
            .args(["/F", "/PID", &child.id().to_string()])
            .output()
            .expect("run taskkill");
        assert!(killed.status.success(), "taskkill failed: {killed:?}");
        let _ = child.wait();

        let path = audit::audit_log_path(&sid);
        let leaves = chain_leaves(&sid);
        let sealed = path.with_extension("root").is_file();
        let verdict = verify_inner(&sid).unwrap();
        drop_chain(&sid);
        let _ = std::fs::remove_dir_all(&scratch);

        // The root the supervisor wrote before the child, with all five facts.
        assert_eq!(root["seq"], 0, "the root is the genesis leaf: {leaves:?}");
        assert_eq!(root["tier"], net::mxc::REQUIRED_TIER);
        assert_eq!(root["tier_source"], net::mxc::TIER_SOURCE_PROBE);
        assert_eq!(root["tier_needs_dacl_augmentation"], false);
        assert_eq!(root["elevated"], setup::is_elevated());
        assert_eq!(
            root["proxy_endpoint"],
            serde_json::Value::Null,
            "--block-net binds nothing, so the endpoint is null"
        );
        let roots = leaves
            .iter()
            .filter(|l| l["op"] == audit::session_start::OP_SESSION_START)
            .count();
        assert_eq!(roots, 1, "one root per run: {leaves:?}");
        assert!(!sealed, "a killed supervisor commits no root");
        match verdict {
            VerifyOutcome::Incomplete(reason) => assert!(
                reason.contains("no committed root"),
                "INCOMPLETE must name the missing seal: {reason}"
            ),
            other => panic!("a killed session must verify as INCOMPLETE, got {other:?}"),
        }
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
    /// `saife run`, and `clear` is the only non-editorial way out — so
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
        assert!(err.contains("saife learned clear"), "hint: {err}");
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
