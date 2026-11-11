mod audit;
mod backend;
mod cli;
mod net;
// Plugins/sidecars are a capability of the mxc backend; without the feature the
// module is compiled but unreachable. Scoped to the feature state rather than a
// blanket `#![allow(dead_code)]`, so genuine rot inside it still shows up in the
// build that uses it.
#[cfg_attr(not(feature = "mxc-backend"), allow(dead_code))]
mod plugin;
mod profile;
mod runner;
mod sandbox;
mod security_groups;
mod setup;
mod signing;

// The MXC helpers the extracted test module still calls: the bodies moved
// into the backend module, the tests did not.
#[cfg(all(test, feature = "mxc-backend"))]
pub(crate) use backend::mxc::{
    launch_confirms_root, launch_failure_exit, pre_launch_tier_refusal, refusal_for,
    session_exit_code, EXIT_TIMEOUT,
};
#[cfg(all(test, feature = "mxc-backend"))]
pub(crate) use backend::EXIT_REFUSED;

use anyhow::{Context, Result};
use clap::Parser;
use cli::Cli;
use cli::Cmd;

/// Whether the MXC backend is wired into the session path.
///
/// P3.0 wired it: [`run_inner`] selects the backend through [`backend::select`]
/// and [`backend::ContainmentBackend::run`] launches through
/// [`net::mxc::launch_session`]. Before that flip, the
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
            expose_credential,
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
            runner,
            allow_host_loopback,
            allow_lan,
            cmd,
        } => run_cmd(
            backend,
            profile,
            allow_cwd,
            allow,
            read_only,
            expose_credential,
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
            runner,
            allow_host_loopback,
            allow_lan,
            cmd,
        ),
        Cmd::Ps { json, .. } => ps_cmd(json),
        Cmd::Audit { action } => audit_cmd(action),
        Cmd::Profile { action } => profile_cmd(action),
        Cmd::Credentials => credentials_cmd(),
        Cmd::Runner { subcommand } => runner_cmd(subcommand),
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

/// `saife credentials list`: the always-denied set, classified.
///
/// The list is the only place an operator can see what a session will deny
/// before launching: the builtin entries with their class (a `secret` can
/// never be exposed; a `tool-credential` can, per session, loudly), plus the
/// machine policy's additions with the file they came from. A policy that
/// cannot be parsed prints its refusal here as well - `saife run` will refuse
/// the session, so `list` must not lie about that.
fn credentials_cmd() -> i32 {
    match crate::profile::effective_denies(&[]) {
        Ok(eff) => {
            let all = crate::profile::credential_denies();
            for d in &all {
                let exposed = if eff.exposed.iter().any(|e| e.path == d.path) {
                    " (exposed)"
                } else {
                    ""
                };
                println!(
                    "{}\t{}\t{}\t{}{}",
                    d.class.as_str(),
                    d.kind.as_str(),
                    d.label,
                    d.path.display(),
                    exposed
                );
            }
            for d in &eff.policy.dirs {
                println!("policy\tdir\t-\t{}", d.display());
            }
            for f in &eff.policy.files {
                println!("policy\tfile\t-\t{}", f.display());
            }
            for s in &eff.policy.sources {
                println!("policy\tsource\t-\t{}", s.display());
            }
            0
        }
        Err(e) => {
            eprintln!("[saife] {e:#}");
            1
        }
    }
}

/// `saife runner ...`: the cache volume and its warm-up.
fn runner_cmd(action: cli::RunnerSub) -> i32 {
    use cli::RunnerSub;

    let endpoint = match crate::runner::docker::Endpoint::resolve() {
        Ok(endpoint) => endpoint,
        Err(e) => {
            eprintln!("[saife] {e:#}");
            return 1;
        }
    };
    let engine = crate::runner::docker::Engine::connect(endpoint);

    match action {
        RunnerSub::Status => {
            if let Err(e) = engine.ping() {
                eprintln!("[saife] no engine: {e:#}");
                return 1;
            }
            let size = engine.cache_volume_bytes().unwrap_or(None);
            let size_text = match size {
                Some(bytes) => format!("{:.0} MB", bytes as f64 / (1024.0 * 1024.0)),
                None => "empty or not reported".to_string(),
            };
            let slots = engine.list_slots().unwrap_or_default();
            println!(
                "cache:   {}  {}",
                crate::runner::docker::CACHE_VOLUME,
                size_text
            );
            println!("image:   {}", crate::runner::docker::RUNNER_IMAGE);
            println!("slots:   {}", slots.len());
            match crate::runner::lifecycle::facts_for_status(&engine) {
                Ok(facts) => {
                    for f in facts {
                        println!(
                            "         {} {} session={} created={} idle since={} owner={}",
                            f.slot_id,
                            if f.running { "running" } else { "stopped" },
                            if f.session.is_empty() {
                                "-"
                            } else {
                                f.session.as_str()
                            },
                            f.created_iso(),
                            f.idle_since_iso().unwrap_or_else(|| "-".to_string()),
                            f.owner_pid
                        );
                    }
                }
                Err(e) => eprintln!("[saife] slot facts unavailable: {e:#}"),
            }
            0
        }
        RunnerSub::Prewarm { project } => {
            let dir = std::path::Path::new(&project);
            if !dir.is_dir() {
                eprintln!("[saife] prewarm: `{project}` is not a directory");
                return 1;
            }
            if let Err(e) = engine.ping() {
                eprintln!("[saife] no engine: {e:#}");
                return 1;
            }
            if let Err(e) = engine.ensure_cache_volume() {
                eprintln!("[saife] {e:#}");
                return 1;
            }
            let tar = match crate::runner::sync::pack_dir(dir, &[".gradle", "build", ".git"]) {
                Ok(tar) => tar,
                Err(e) => {
                    eprintln!("[saife] prewarm: {e:#}");
                    return 1;
                }
            };
            // A prewarm container is the one place with network, and it exists only for the
            // length of the download: visible in the output, removed even on failure.
            let session = format!("prewarm{}", std::process::id());
            let mut spec = crate::runner::docker::SlotSpec::new(&session);
            spec.allow_network = true;
            let slot = match engine.create_slot(&spec) {
                Ok(slot) => slot,
                Err(e) => {
                    eprintln!("[saife] prewarm: {e:#}");
                    return 1;
                }
            };
            let result = (|| -> anyhow::Result<()> {
                engine.start_slot(&slot)?;
                engine.ensure_dirs(&slot.id, &["/src", "/cache"])?;
                engine.put_archive(&slot.id, "/src", &tar)?;
                println!(
                    "[saife] prewarm: filling {} (network on, this once). The first fill \
                     downloads the Gradle distribution and the project's dependencies - on a \
                     slow link that is many minutes, and killing it leaves a cache that fails \
                     offline later with one artifact named",
                    crate::runner::docker::CACHE_VOLUME
                );
                let exec = engine.exec_create(
                    &slot.id,
                    &["sh".to_string(), "-c".to_string(),
                      "cd /src && export GRADLE_USER_HOME=/cache && sh ./gradlew --version && sh ./gradlew dependencies --quiet".to_string()],
                    "/src",
                    &[],
                )?;
                // Flush per chunk, and treat a closed pipe as "the log is gone", not as a
                // reason to kill a download that is already running (T6.2).
                let mut sink = crate::runner::StreamSink::new(std::io::stdout());
                engine.exec_stream(&exec, |chunk| {
                    sink.write(chunk);
                })?;
                let code = engine.exec_exit(&exec)?;
                if code != Some(0) {
                    anyhow::bail!("prewarm exited with {code:?}");
                }
                Ok(())
            })();
            let _ = engine.remove_slot(&slot);
            if let Err(e) = result {
                eprintln!("[saife] prewarm failed: {e:#}");
                return 1;
            }
            let size = engine.cache_volume_bytes().unwrap_or(None).unwrap_or(0);
            println!(
                "[saife] prewarm: cache is now {:.0} MB",
                size as f64 / (1024.0 * 1024.0)
            );
            0
        }
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
        LearnedSub::List if profile.is_none() => {
            // No `--profile`: show every store, labelled. Reading `default` alone
            // hid a deny that was blocking the run (see `stores_in`).
            let mut rendered: Vec<(String, String)> = Vec::new();
            for (name, _) in net::learned::stores_in(base) {
                let label = name.clone().unwrap_or_else(|| "default".to_string());
                match net::learned::LearnedStore::load_in(base, name.as_deref()) {
                    Ok(store) => {
                        if !store.entries().is_empty() {
                            rendered.push((label, learned_table(&store.entries())));
                        }
                    }
                    // [G-5] a corrupt store is never skipped: hiding it would
                    // report "no entries" for a file that hard-aborts `saife run`
                    // and lose the `learned clear` pointer.
                    Err(e) => return learned_load_failure(e),
                }
            }
            if rendered.is_empty() {
                return (0, "(no learned entries)\n".to_string(), String::new());
            }
            // The historical bare table is kept only for `default`, the store a
            // flagless command already addresses. Any other store is labelled even
            // when it is the only one with entries: otherwise the operator sees
            // rules and cannot tell which `--profile` would revoke them.
            if rendered.len() == 1 && rendered[0].0 == "default" {
                return (0, rendered.remove(0).1, String::new());
            }
            let mut out = String::new();
            for (label, table) in rendered {
                out.push_str(&format!("# {label}\n"));
                out.push_str(&table);
            }
            (0, out, String::new())
        }
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
                Ok(false) => {
                    // Without `--profile` the addressed store is `default`. If the
                    // host lives in another store, name it: otherwise the operator
                    // is told "no entry" about a rule that IS blocking them.
                    let elsewhere: Option<String> = if profile.is_none() {
                        net::learned::stores_in(base)
                            .into_iter()
                            .filter_map(|(name, _)| name)
                            .find(|name| {
                                net::learned::LearnedStore::load_in(base, Some(name))
                                    .map(|s| s.entries().iter().any(|e| e.0 == host))
                                    .unwrap_or(false)
                            })
                    } else {
                        None
                    };
                    match elsewhere {
                        Some(name) => (
                            1,
                            String::new(),
                            format!(
                                "[saife] `{host}` is not in the default store; it is in store \
                                 `{name}` - re-run with `--profile {name}` (or `saife learned \
                                 list` to see every store)\n"
                            ),
                        ),
                        None => (
                            1,
                            String::new(),
                            format!(
                                "[saife] no learned entry for {host} \
                                 (run `saife learned list` to see stored keys)\n"
                            ),
                        ),
                    }
                }
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
/// Render the aligned `HOST  SCOPE  DISPOSITION` table for one store.
fn learned_table(entries: &[(String, String, bool)]) -> String {
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
    for (host, scope, allow) in entries {
        let disposition = if *allow { "allow" } else { "deny" };
        out.push_str(&format!(
            "{:<host_w$}  {:<scope_w$}  {disposition}\n",
            host, scope
        ));
    }
    out
}

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

/// Publish `bytes` at `path` as one atomic replace (H5b).
///
/// A sibling temp file plus `MoveFileExW(MOVEFILE_REPLACE_EXISTING |
/// MOVEFILE_WRITE_THROUGH)`: the windows crate is already a dependency (the key
/// publish in `signing.rs` uses the same call), it replaces an existing
/// destination, and it does not return until the rename is in the directory - so a
/// kill either leaves the old file or the new one, never a torn one. The temp is a
/// sibling, so the rename is same-volume by construction and cannot degrade into a
/// non-atomic copy.
fn publish_atomically(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    use windows::Win32::Storage::FileSystem::{
        MOVE_FILE_FLAGS, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    };
    use windows::core::HSTRING;

    let tmp = path.with_extension(format!(
        "tmp-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::write(&tmp, bytes).with_context(|| format!("write {:?}", tmp.display()))?;
    let published = unsafe {
        MoveFileExW(
            &HSTRING::from(tmp.as_os_str()),
            &HSTRING::from(path.as_os_str()),
            MOVE_FILE_FLAGS(MOVEFILE_REPLACE_EXISTING.0 | MOVEFILE_WRITE_THROUGH.0),
        )
    };
    if let Err(e) = published {
        let _ = std::fs::remove_file(&tmp);
        return Err(e).with_context(|| format!("publish audit file {:?}", path.display()));
    }
    Ok(())
}

fn commit_audit_root(sid: &str, root: &str) -> Result<()> {
    // H4: defensive validation at this door too - the writer is not the only
    // way a sid reaches `audit_log_path`. Done before touching the key.
    let sid = audit::normalize_session_id(sid)?;
    let key = signing::KeyMaterial::ensure()?;
    let root_bytes =
        decode_hex_vec(root).ok_or_else(|| anyhow::anyhow!("root is not valid hex: {root}"))?;
    let sig = key.sign_root(&root_bytes);
    let sig_hex: String = sig.iter().map(|b| format!("{b:02x}")).collect();
    let log_path = audit::audit_log_path(&sid);
    // H5b: signature FIRST, root second, each an atomic replace.
    //
    // Order is the whole point. Every state a kill can leave behind is now one
    // `verify` reads as an interrupted commit, never as an edit:
    //   sig published, root missing  -> INCOMPLETE (no committed root)
    //   root published              -> both halves present and consistent
    // The old root-then-sig order left a committed root with no signature (or an
    // older session's signature), which verify reported as BAD_SIGNATURE/TAMPERED
    // - blaming the operator for a crash.
    publish_atomically(&log_path.with_extension("sig"), sig_hex.as_bytes())?;
    // M7: the key fingerprint is a sidecar recorded with the commit, so a later
    // verify can say KEY_CHANGED instead of BAD_SIGNATURE after a rotation. It is
    // written before the root: if the run is killed here, no committed root means
    // verify reports INCOMPLETE and never reads it.
    publish_atomically(&log_path.with_extension("keyfp"), key.fingerprint().as_bytes())?;
    publish_atomically(&log_path.with_extension("root"), root.as_bytes())?;
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
/// The exposures a launch carries, as the audit records them: label, path,
/// class - never the value. Resolved through the same `effective_denies` the
/// filesystem policy uses, so the leaf and the launch cannot disagree; a
/// refused exposure (unknown label, `Secret` class) surfaces here and stops the
/// session before anything is granted.
fn credential_exposure_facts(
    exposed: &[String],
) -> anyhow::Result<Vec<audit::session_start::ExposedCredentialFacts>> {
    if exposed.is_empty() {
        return Ok(Vec::new());
    }
    let eff = profile::effective_denies(exposed)?;
    for x in &eff.exposed {
        eprintln!(
            "[saife] exposing credential `{}` ({}) to this session: the workload can read it. \
             Denied again next run unless named.",
            x.label,
            x.path.display()
        );
    }
    Ok(eff
        .exposed
        .iter()
        .map(|x| audit::session_start::ExposedCredentialFacts {
            label: x.label.clone(),
            path: x.path.display().to_string(),
            class: x.class.as_str(),
        })
        .collect())
}

/// The machine policy in force, as the audit records it (counts plus the file
/// names - the deployment's identity). An unparseable policy refuses the
/// session here, exactly as it does in the filesystem path.
fn credential_policy_facts() -> anyhow::Result<audit::session_start::PolicyFacts> {
    let eff = profile::effective_denies(&[])?;
    Ok(audit::session_start::PolicyFacts {
        dirs: eff.policy.dirs.len(),
        files: eff.policy.files.len(),
        sources: eff
            .policy
            .sources
            .iter()
            .filter_map(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
            .collect(),
    })
}

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
    expose_credential: Vec<String>,
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
    // `--runner`: the build runner's facade mount for this session.
    runner: bool,
    // `--allow-host-loopback`: ADR-0007's session mode.
    allow_host_loopback: bool,
    // M9: `--allow-lan`, the explicit escape hatch for the private/LAN deny.
    allow_lan: bool,
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
    // ADR-0007: the flag is validated against the rest of the command line
    // before anything is spawned, like `route_backend`.
    if let Err(refusal) = cli::check_host_loopback(allow_host_loopback, block_net, backend) {
        eprintln!("[saife] {}", refusal.message());
        return 2;
    }
    if allow_host_loopback {
        eprintln!("{}", cli::HOST_LOOPBACK_WARNING);
    }
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
        &expose_credential,
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
        runner,
        allow_host_loopback,
        allow_lan,
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
fn run_inner(
    // P3.0: the backend `cli::route_backend` already approved. `AppContainer`
    // keeps the code path below byte for byte; `Mxc` branches out after the
    // shared resolution and never comes back through it.
    backend: cli::Backend,
    profile_name: Option<&str>,
    allow_cwd: bool,
    allow: &[String],
    read_only: &[String],
    exposed: &[String],
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
    // `--runner`: wire the build runner's facade mount and listener for this session.
    enable_runner: bool,
    // `--allow-host-loopback`: ADR-0007's session mode, threaded to the MXC path.
    allow_host_loopback: bool,
    // M9: `--allow-lan`, threaded to the listener the MXC path starts.
    allow_lan: bool,
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
    // still resolves to `Blocked` — no origin, no prompt — and the listener such a
    // session needs for its facade is `start_session_proxy`'s decision (T6.1).
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

    // The backend the router chose owns everything from here on. Both paths get
    // the SAME resolved inputs - one `SessionRequest` - so two backends cannot
    // disagree about what the operator asked for, and the dispatch is the only
    // arm a feature state decides. `--backend mxc` in a binary without the
    // feature is the router's refusal restated (fail closed, never a fallback).
    let req = backend::SessionRequest {
        sid: &sid,
        cwd: &cwd,
        net_cfg: &net_cfg_resolved,
        fs: &fs,
        limits: &limits,
        runner_paths: &resolved.runner.paths,
        exposed,
        audit_strict,
        print_sid,
        no_interactive,
        plugins,
        plugin_dirs,
        enable_runner,
        allow_host_loopback,
        allow_lan,
        cmd,
    };
    backend::select(backend)?.run(&req)
}



/// Remove this session's `.sandbox/<sid>` tree at teardown (L-O).
///
/// Called AFTER the DACL restore, because a tree removed while its ACEs are
/// still journaled would leave the journal pointing at paths that no longer
/// exist (the restore tolerates that, but the order costs nothing).
///
/// `.sandbox` itself is left alone: it is the parent every session shares, and
/// removing it would race another session's teardown. `NotFound` is success -
/// a run that never created the tree, or a second teardown, must not be an
/// error.
fn remove_session_sandbox_dir(cwd: &std::path::Path, sid: &str) -> std::io::Result<()> {
    match std::fs::remove_dir_all(cwd.join(".sandbox").join(sid)) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
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
    // T6.1: start the listener even for a blocked session, because this
    // session asked for a facade mount (`--runner`, `--plugin`) and the
    // facade route exists only in the proxy.
    serve_without_egress: bool,
    // M9: `--allow-lan`, the explicit escape hatch for the private/LAN deny.
    allow_lan: bool,
) -> Result<Option<(net::proxy::ProxyHandle, net::ProxyEnv)>> {
    // The listener MUST outlive the child: the caller holds the handle until the
    // child has exited (see `seal_audit`).
    Ok(match net_cfg {
        // Unchanged for a blocked session that asked for nothing: no listener, so
        // nothing binds, nothing can be proven, and the guardrail leg is
        // `MustBeAbsent`.
        net::NetworkConfig::Blocked if !serve_without_egress => None,
        // T6.1: a blocked session that DID ask for a facade still needs the
        // listener. It carries no origin and the `blocked` posture, so exactly the
        // requests that would leave the machine are denied and the host-side
        // capability is reachable. The alternative — what this replaced — was an
        // egress grant (`--allow-domain <anything>`) bought only to obtain a
        // socket, which is a security decision made for the wrong reason.
        net::NetworkConfig::Blocked => {
            let token = net::token::RunToken::issue().context("generate session token")?;
            Some(spawn_session_listener(
                net::proxy::ProxyConfig {
                    session_id: sid.to_string(),
                    token: token.clone(),
                    allow_domain: Vec::new(),
                    deny_domain: Vec::new(),
                    blocked: true,
                    // No chaining: there is no origin to reach, so an upstream
                    // dialer would be a second way out wired up for nothing.
                    upstream: None,
                    // Nothing it can reach has a destination to relax.
                    allow_lan: false,
                    writer,
                    // Nothing to ask: the answer is the session's posture, not a
                    // per-host choice, so the dialog is constructed disabled.
                    prompt: session_prompt_gate(false, "deny", prompt_timeout_secs, None)?,
                    facade,
                },
                token,
            )?)
        }
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
            // The prompt/intent/learned wiring, built by the ONE constructor both
            // postures share (T6.1): a second construction is a second place for
            // the prompt posture to drift.
            let prompt = session_prompt_gate(
                *prompt_enabled,
                on_unavailable,
                prompt_timeout_secs,
                profile_name.as_deref(),
            )?;
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
            // H2 (security review 2026-11-09: partial → Medium). Under chaining
            // saife does not resolve the destination, so its destination
            // hard-deny never runs ([G-22]) and [G-44]'s "no tunnel to host
            // services" holds only as far as the upstream enforces it. A remote
            // corporate proxy is trusted to; the loopback bridge this module
            // recommends (cntlm/px on 127.0.0.1) is not, so say so at startup.
            // Not SAIFE_DIAG-gated: a silently weaker destination policy is
            // exactly the class of fact an operator must not have to ask for.
            if let Some(w) = upstream.as_ref().and_then(|d| d.loopback_bridge_warning()) {
                eprintln!("[saife] warning: {w}");
            }
            Some(spawn_session_listener(
                net::proxy::ProxyConfig {
                    session_id: sid.to_string(),
                    token: token.clone(),
                    allow_domain: allow_domain.clone(),
                    deny_domain: deny_domain.clone(),
                    blocked: false,
                    upstream,
                    allow_lan,
                    writer: writer.clone(),
                    prompt,
                    facade,
                },
                // The child's copy of this run's credential; the listener holds
                // the same value and refuses every other. Cloning the `RunToken`
                // (rather than its `String`) keeps the env edge typed (P1.6(c)).
                token,
            )?)
        }
    })
}

/// The prompt/intent/learned wiring one listener carries.
///
/// Extracted in T6.1 so both postures build their gate in one place. The
/// blocked posture passes `prompt_enabled: false` — nothing it can reach has a
/// per-host answer, so a dialog would be a question with no consequence — but it
/// still loads the learned store, so a corrupt one is reported in both postures
/// instead of only sometimes ([G-5]).
fn session_prompt_gate(
    prompt_enabled: bool,
    on_unavailable: &str,
    prompt_timeout_secs: u32,
    profile_name: Option<&str>,
) -> Result<net::proxy::PromptGate> {
    // Task 3.6 Step 5: load the learned policy BEFORE starting the
    // proxy. A corrupt learned file is a hard error by design — the
    // user notices immediately and can fix or revoke it ([G-5]).
    let learned = net::learned::LearnedStore::load(profile_name)
        .context("load learned policy file ('saife learned clear' resets a corrupt one)")?;
    // D-4 registry + D-3.5 coordinator: created in the supervisor
    // (all sync) before the proxy runtime exists and Arc-shared
    // into every handler. The registry's `Drop` joins its sweeper
    // once the last reference is gone.
    let intent = std::sync::Arc::new(net::intent::IntentRegistry::new(net::intent::DEFAULT_TTL));
    let coordinator = std::sync::Arc::new(net::prompt::PromptCoordinator::new());
    let on_unavailable = if on_unavailable == "allow" {
        net::prompt::PromptPolicy::Allow
    } else {
        net::prompt::PromptPolicy::Deny
    };
    Ok(net::proxy::PromptGate {
        enabled: prompt_enabled,
        config: net::prompt::PromptConfig {
            timeout: std::time::Duration::from_secs(u64::from(prompt_timeout_secs)),
            on_unavailable,
        },
        coordinator,
        intent,
        learned: std::sync::Arc::new(std::sync::Mutex::new(learned)),
    })
}

/// The listener plus the child's [`net::ProxyEnv`], from a fully-built config.
///
/// One spawn site for both postures: the env must name the port the listener
/// actually bound and the credential it accepts, and building those twice is how
/// a child ends up pointed at a proxy that will not admit it.
fn spawn_session_listener(
    cfg: net::proxy::ProxyConfig,
    token: net::token::RunToken,
) -> Result<(net::proxy::ProxyHandle, net::ProxyEnv)> {
    let handle = net::proxy::spawn(cfg).context("start localhost proxy")?;
    let proxy_env = net::ProxyEnv {
        port: handle.port,
        token,
    };
    Ok((handle, proxy_env))
}

/// H5c: the session-end report for leaves that arrived after the seal.
///
/// Sealing is what lets a committed root be trusted, and the proxy's `Drop`-time
/// trailing refusal aggregate *always* arrives after it - so those leaves are
/// dropped by design. But "dropped by design" and "lost silently" read the same to
/// an operator comparing the audit totals with what the proxy claims it accounted.
/// `None` for a clean session so the normal case prints nothing.
fn sealed_drop_line(dropped: u64) -> Option<String> {
    (dropped > 0).then(|| format!("{dropped} audit leaf(s) dropped after seal"))
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
    // sealed writer instead of racing the file. H5c: that drop is where the
    // trailing refusal aggregate goes, so the count is read *after* this drop (the
    // flush) and *before* the writer goes away.
    drop(proxy);
    let dropped_after_seal = writer.dropped_after_seal();

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

    // H5c: the session is over, so this is the last chance to say that the chain is
    // shorter than what the process tried to record. Silence here meant the proxy's
    // "sums to the true total" invariant was already broken with no trace.
    if let Some(line) = sealed_drop_line(dropped_after_seal) {
        eprintln!("[saife] warning: {line}");
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
mod tests;

/// L-O teardown tests: the per-session `.sandbox/<sid>` tree must not survive
/// the run that created it.
///
/// Inline rather than in [`tests`] because it pins a function that only the
/// teardown path calls, and because `tests.rs` is not this slice's file.
#[cfg(test)]
mod session_teardown_tests {
    use super::*;

    /// L-O (verdict: partial - the ACE half was implemented, this half was not):
    /// teardown removes this session's `.sandbox/<sid>` tree, leaves a sibling
    /// session's tree alone, and a second teardown is not an error.
    #[test]
    fn teardown_removes_the_session_sandbox_dir() {
        let cwd = std::env::temp_dir().join(format!(
            "saife-teardown-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&cwd);
        std::fs::create_dir_all(cwd.join(".sandbox").join("sid1").join("bin")).unwrap();
        std::fs::write(cwd.join(".sandbox/sid1/bin/tool.exe"), b"x").unwrap();
        std::fs::write(cwd.join(".sandbox/sid1/pyshim.py"), b"x").unwrap();
        std::fs::create_dir_all(cwd.join(".sandbox").join("sid2")).unwrap();

        remove_session_sandbox_dir(&cwd, "sid1").expect("teardown removes the session dir");

        assert!(
            !cwd.join(".sandbox").join("sid1").exists(),
            "the session's .sandbox/<sid> tree must not survive teardown"
        );
        assert!(
            cwd.join(".sandbox").join("sid2").exists(),
            "another session's tree must not be touched"
        );
        // Idempotent: a run that never created the tree (or a second teardown)
        // is success, not an error at the end of an otherwise clean run.
        remove_session_sandbox_dir(&cwd, "sid1").expect("a second teardown is not an error");

        let _ = std::fs::remove_dir_all(&cwd);
    }
}

/// Regression tests for the audit commit path (H5b/H5c).
///
/// They live here rather than in [`tests`] because they pin the ordering inside
/// [`commit_audit_root`] and [`seal_audit`] - the two functions whose *sequence* of
/// side effects is the safety property.
#[cfg(test)]
mod audit_commit_tests {
    use super::*;

    fn fresh_sid(label: &str) -> String {
        format!(
            "test-commit-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        )
    }

    /// One leaf in the log, returning its hash (the root that would be committed).
    fn one_leaf_chain(sid: &str) -> String {
        let writer = audit::AuditWriter::open(sid, false).unwrap();
        let mut e = serde_json::Map::new();
        e.insert("op".into(), serde_json::json!("CONNECT"));
        e.insert("host".into(), serde_json::json!("commit.example"));
        writer.append(e).unwrap();
        writer.seal().expect("one leaf has a root")
    }

    fn cleanup(sid: &str) {
        let log = audit::audit_log_path(sid);
        let _ = std::fs::remove_file(&log);
        for ext in ["root", "sig", "keyfp"] {
            let p = log.with_extension(ext);
            let _ = std::fs::remove_file(&p);
            let _ = std::fs::remove_dir_all(&p);
        }
        let _ = std::fs::remove_file(audit::lock_path(&log));
    }

    /// H4 (verdict doc): the commit is the third way a sid reaches the
    /// filesystem, so it must validate at its own door - before the key is
    /// loaded and before anything is published.
    #[test]
    fn commit_audit_root_refuses_a_traversal_sid_and_writes_nothing() {
        let pid = std::process::id();
        let bad = format!("..\\..\\h4-commit-{pid}");
        let log = audit::audit_log_path(&bad);
        let root = log.with_extension("root");
        let sig = log.with_extension("sig");
        let keyfp = log.with_extension("keyfp");
        let _ = std::fs::remove_file(&root);
        let _ = std::fs::remove_file(&sig);
        let _ = std::fs::remove_file(&keyfp);

        let err = commit_audit_root(&bad, &"0".repeat(64))
            .expect_err("a traversal sid must be refused before anything is written");
        let text = format!("{err:#}");
        assert!(
            text.to_ascii_lowercase().contains("session id"),
            "the refusal must name the session id, not a file error: {text}"
        );
        assert!(
            !root.exists() && !sig.exists() && !keyfp.exists(),
            "the refusal must write nothing"
        );
    }

    /// M7 (verdict doc: confirmed). The commit must record the fingerprint of
    /// the key that signed, so a later verify can report KEY_CHANGED instead of
    /// silently calling every pre-rotation session a forgery.
    #[test]
    fn commit_audit_root_records_the_signing_key_fingerprint() {
        let sid = fresh_sid("m7-keyfp");
        let root = one_leaf_chain(&sid);

        commit_audit_root(&sid, &root).expect("the commit succeeds");

        let log = audit::audit_log_path(&sid);
        let fp = std::fs::read_to_string(log.with_extension("keyfp")).unwrap();
        let key = signing::KeyMaterial::load_existing().unwrap();
        assert_eq!(fp, key.fingerprint(), "the recorded fingerprint must be the signer's");
        assert_eq!(fp.len(), 64, "the fingerprint is a 32-byte SHA-256 in hex");
        cleanup(&sid);
    }

    /// H5b (verdict doc: confirmed). The pair used to be written root-then-sig with
    /// two `fs::write`s, so a kill in between left a new root with no (or an old)
    /// signature - a state `verify` reported as `BAD_SIGNATURE`/`TAMPERED`, i.e. it
    /// blamed the operator for a crash.
    ///
    /// The signature is now published first. This test blocks the root's
    /// destination (a directory cannot be replaced by a file rename), so the commit
    /// must fail *after* the signature landed and *before* the root did: exactly the
    /// crash window, and the one `verify` reports as `INCOMPLETE`.
    #[test]
    fn commit_audit_root_publishes_the_signature_before_the_root() {
        let sid = fresh_sid("order");
        let root = one_leaf_chain(&sid);
        let log = audit::audit_log_path(&sid);
        let root_path = log.with_extension("root");
        let sig_path = log.with_extension("sig");
        std::fs::create_dir_all(&root_path).unwrap();

        let err = commit_audit_root(&sid, &root)
            .expect_err("a root that cannot be published must be reported, not swallowed");
        assert!(
            format!("{err:#}").to_ascii_lowercase().contains("root"),
            "the error must name what failed: {err:#}"
        );
        assert!(
            sig_path.exists(),
            "the signature must be published before the root: a crash here leaves sig-only"
        );
        assert!(
            std::fs::metadata(&root_path)
                .map(|m| m.is_dir())
                .unwrap_or(false),
            "the root destination must be untouched"
        );

        cleanup(&sid);
    }

    /// The commit is a replace, not an append: a session that is re-run must not
    /// leave the previous pair's bytes behind, and no temp sibling may survive.
    #[test]
    fn commit_audit_root_replaces_a_stale_pair_without_leaving_temporaries() {
        let sid = fresh_sid("replace");
        let root = one_leaf_chain(&sid);
        let log = audit::audit_log_path(&sid);
        std::fs::write(log.with_extension("root"), "0".repeat(64)).unwrap();
        std::fs::write(log.with_extension("sig"), "0".repeat(128)).unwrap();

        commit_audit_root(&sid, &root).expect("the commit replaces the stale pair");

        assert_eq!(
            std::fs::read_to_string(log.with_extension("root")).unwrap(),
            root
        );
        let sig = std::fs::read_to_string(log.with_extension("sig")).unwrap();
        assert_eq!(sig.len(), 128, "the stale signature was replaced");
        assert!(
            !matches!(
                audit::verify::verify_inner(&sid).unwrap(),
                audit::verify::VerifyOutcome::Tampered(_)
            ),
            "a committed pair must never verify as tampered"
        );

        let dir = log.parent().unwrap();
        let prefix = log.file_name().unwrap().to_string_lossy().into_owned();
        let leftovers: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with(&prefix) && n.contains(".tmp"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "atomic publishes must not leave temp files behind: {leftovers:?}"
        );

        cleanup(&sid);
    }

    /// H5c (verdict doc: confirmed). `seal_audit` seals, then drops the proxy -
    /// whose `Drop` flushes the trailing refusal aggregate into an already-sealed
    /// chain. Those leaves are dropped so the file cannot grow past its root, but
    /// the drop used to be silent, so the "sums to the true total" invariant broke
    /// with nothing in the output to say so. The session-end line is that report.
    #[test]
    fn the_session_end_line_names_the_dropped_leaf_count() {
        let line = sealed_drop_line(3).expect("a non-zero count must be reported");
        assert_eq!(line, "3 audit leaf(s) dropped after seal");
        assert!(
            line.contains('3'),
            "the line must name the count, got {line:?}"
        );
        assert!(
            sealed_drop_line(0).is_none(),
            "a clean session must not print a drop line"
        );
    }
}
