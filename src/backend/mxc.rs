//! The MXC backend: the ProcessContainer backend behind the `mxc-backend`
//! feature.
//!
//! The body lives here, behind the trait, unchanged. Nothing here may reorder its steps: the request
//! is built and probed before the launch, the tier gate decides before the root
//! is written, and the guardrails own the exit code.

use super::{ContainmentBackend, SessionRequest, EXIT_REFUSED};
use std::io::IsTerminal;
use crate::{
    audit, cli, credential_exposure_facts, credential_policy_facts, join_cmdline, net,
    plugin, profile, seal_audit, setup, start_session_proxy,
};
use anyhow::{Context, Result};

/// The ProcessContainer backend.
pub struct MxcBackend;

impl ContainmentBackend for MxcBackend {
    fn run(&self, req: &SessionRequest<'_>) -> anyhow::Result<i32> {
        run_mxc_session(
            req.sid,
            req.cwd,
            req.net_cfg,
            req.fs,
            req.limits,
            req.runner_paths,
            req.exposed,
            req.audit_strict,
            req.print_sid,
            req.no_interactive,
            req.plugins,
            req.plugin_dirs,
            req.enable_runner,
            req.allow_host_loopback,
            req.allow_lan,
            req.cmd,
        )
    }
}

// ---------------------------------------------------------------------------
// P3.0: the MXC session path
// ---------------------------------------------------------------------------

/// Exit code for a session that hit its budget (`timeout(1)`'s convention).
#[cfg(feature = "mxc-backend")]
pub(crate) const EXIT_TIMEOUT: i32 = 124;

/// Exit code for a session a PLUGIN refused: load, spawn, health gate, or a
/// duplicate mount.
///
/// `5` is deliberately distinct from `126` (a guardrail refusal) and `1` (a
/// runtime error): a caller script can tell "the capability I asked for was not
/// available" from "the session ran and failed".
#[cfg(feature = "mxc-backend")]
pub(crate) const EXIT_PLUGIN_REFUSED: i32 = 5;

/// Exit code for a session the BUILD RUNNER refused: no engine, no mount, a token it
/// could not mint.
///
/// The same value as [`EXIT_PLUGIN_REFUSED`] and for the same reason — "a capability I
/// asked for was not available" — kept as its own name because the two are different
/// capabilities and a caller reading a script should not have to infer that from 5.
#[cfg(feature = "mxc-backend")]
pub(crate) const EXIT_RUNNER_REFUSED: i32 = 5;

#[cfg(feature = "mxc-backend")]
/// Prints the retry for `e` when it is an availability failure
/// ([`net::mxc::MxcError::suggests_appcontainer`]): the operator's own command
/// line with `--backend appcontainer` in place of the backend that could not
/// run ([`cli::appcontainer_retry_command`]), after
/// [`cli::MXC_UNAVAILABLE_PREFIX`].
///
/// The failure line goes first and keeps its shape (the audit leaf and the exit
/// code are decided from it); this is one copy-paste line beside it, so the
/// operator re-runs the SAME session on the other backend without rebuilding it
/// by hand. A failure that is NOT about availability prints nothing extra — a
/// hint beside an unrelated error would send them to change the wrong thing.
///
/// `std::env::args()` is this supervisor's own command line: the hint is printed
/// from the process the operator started, before any backend-owned re-exec.
pub(crate) fn emit_mxc_unavailable_hint(e: &net::mxc::MxcError) {
    if e.suggests_appcontainer() {
        let argv: Vec<String> = std::env::args().collect();
        eprintln!("{}", mxc_unavailable_line(&argv));
    }
}

/// The full stderr line for an availability failure: the `[saife]` prefix, the
/// issue sentence, and the operator's own command with the other backend. Pure so
/// the test can pin the assembled text the operator actually reads.
#[cfg(feature = "mxc-backend")]
pub(crate) fn mxc_unavailable_line(argv: &[String]) -> String {
    format!(
        "[saife] {}{}",
        cli::MXC_UNAVAILABLE_PREFIX,
        cli::appcontainer_retry_command(argv)
    )
}

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
    // The session profile's `runner.sync.paths`: what a build request that names no paths
    // inherits. Empty is the whole project, i.e. what every profile without the block gets.
    runner_paths: &[String],
    // `--expose-credential`: the builtin deny entries the operator named, resolved
    // (and refused, if a label is unknown or a `Secret`) by `filesystem_policy`.
    exposed: &[String],
    audit_strict: bool,
    print_sid: bool,
    no_interactive: bool,
    plugins: &[String],
    plugin_dirs: &[String],
    // `--runner`: start the build runner and publish its facade mount.
    enable_runner: bool,
    allow_host_loopback: bool,
    // M9: `--allow-lan`, threaded to the listener this path starts.
    allow_lan: bool,
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
        exposed,
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
        })
        // ADR-0007: the loopback reach this session launches with - recorded
        // before the child exists, like every other fact on the leaf.
        .with_loopback(if allow_host_loopback {
            audit::session_start::LOOPBACK_OPEN_UNSCOPED
        } else {
            audit::session_start::LOOPBACK_CLOSED
        })
        // The credential posture this session launches with, resolved through
        // the same `effective_denies` the filesystem policy used - so the leaf
        // cannot describe an exposure the launch does not have.
        .with_exposed_credentials(credential_exposure_facts(exposed)?)
        .with_policy(credential_policy_facts()?),
    );

    // (5) The SAME listener the AppContainer path starts, with its own per-run
    //     token. A `--block-net` session gets one only if it asked for a facade
    //     (`--plugin` here, `--runner` below): that listener serves the mount and
    //     denies every origin (T6.1), so the capability no longer has to be bought
    //     with an `--allow-domain` grant. No loopback exemption is registered:
    //     this backend's ingress policy allows host loopback, which is
    //     why the migration needs no elevation.
    //
    //     The facade registry exists BEFORE the listener so both hold one `Arc`:
    //     the handler reads it per request, and the plugins below fill it once
    //     each sidecar has a port and a token. That ordering is what makes
    //     "proxy binds -> plugins spawn -> child" honest — a request that lands
    //     in between answers `404`, never a stale allow.
    let facade = std::sync::Arc::new(plugin::FacadeRegistry::new());
    let proxy = start_session_proxy(
        net_cfg,
        limits.prompt_timeout_secs,
        sid,
        audit_writer.clone(),
        std::sync::Arc::clone(&facade),
        enable_runner || !plugins.is_empty(),
        allow_lan,
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

    // (5c) The build runner (T1.6, T4.2). Its mount goes into the same registry the
    //      plugins use, so a workload reaches it exactly as it reaches a plugin: an
    //      ordinary proxied request to `http://build.sandbox.invalid/…`, checked against
    //      the declared `(method, path)` and audited by the path that already exists.
    //      Bound after `proxy`, so the wiring is dropped BEFORE it: a route never
    //      outlives the listener it points at, on the clean path and on every `?`.
    // Three values, one lifetime: the wiring (listener + mount), the keeper (this session's
    // slot dies with it) and the watchdog (an idle slot is stopped, but never one with a
    // build in flight). Bound together because dropping any one of them early is the bug.
    let (_runner_session, _runner_keeper, _runner_watchdog) = if enable_runner {
        let endpoint = match crate::runner::docker::Endpoint::resolve() {
            Ok(endpoint) => endpoint,
            Err(e) => {
                eprintln!("[saife] runner refused: {e:#}");
                return Ok(EXIT_RUNNER_REFUSED);
            }
        };
        // The build shares the workload's clock: a build IS work the workload asked for,
        // so `limits.workloadTimeoutSecs` is the deadline rather than a second term an
        // operator would have to discover before a runaway build could be stopped.
        let engine = crate::runner::docker::Engine::connect(endpoint);
        let policy = crate::runner::lifecycle::SlotPolicy::default();
        // Slots whose owner process is gone. Never a live session's: liveness is the owner's
        // pid *and* its creation time, so a recycled pid cannot adopt a slot.
        match crate::runner::lifecycle::sweep(&engine, &crate::runner::lifecycle::owner_is_alive) {
            Ok(swept) if !swept.is_empty() => {
                eprintln!("[saife] runner: swept {} orphaned slot(s)", swept.len());
            }
            Ok(_) => {}
            Err(e) => eprintln!("[saife] runner: sweep skipped: {e:#}"),
        }
        let builds = std::sync::Arc::new(crate::runner::builds::DockerBuilds::new(
            engine.clone(),
            cwd.to_path_buf(),
            sid.to_string(),
            std::time::Duration::from_secs(u64::from(limits.workload_timeout_secs)),
        ));
        let as_engine: std::sync::Arc<dyn crate::runner::server::BuildEngine> = builds.clone();
        match crate::runner::wiring::RunnerWiring::start(
            &facade,
            cwd,
            runner_paths,
            as_engine,
            token,
        ) {
            Ok(wiring) => {
                if std::env::var_os("SAIFE_DIAG").is_some() {
                    eprintln!(
                        "[saife] SAIFE_DIAG: build runner on 127.0.0.1:{} as {}.sandbox.invalid",
                        wiring.port(),
                        crate::runner::wiring::MOUNT
                    );
                }
                let keeper = crate::runner::lifecycle::SlotKeeper::new(engine.clone(), sid);
                let busy = std::sync::Arc::clone(&builds);
                let watchdog = crate::runner::lifecycle::spawn_idle_watchdog(
                    engine,
                    policy,
                    sid.to_string(),
                    std::time::Duration::from_secs(60),
                    std::sync::Arc::new(move |_| busy.busy()),
                )?;
                (Some(wiring), Some(keeper), Some(watchdog))
            }
            Err(e) => {
                eprintln!("[saife] runner refused: {e:#}");
                return Ok(EXIT_RUNNER_REFUSED);
            }
        }
    } else {
        (None, None, None)
    };

    // (6) Guardrail 1's proof source. With a proxy it is that listener — the one
    //     the child is pointed at, so the proof cannot come from a different
    //     socket. Under `--block-net` nothing binds (the runner/plugin case is the
    //     exception, and it DOES bind: that listener is the proxy the child talks
    //     to, so the proof is the same counter as any networked session's) and the
    //     registry is unattached: its proof is structurally zero because the
    //     session has no proxy to consult, which is what `MustBeAbsent` asserts.
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
        allow_host_loopback,
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
    let probed = net::mxc::probe_tier(&request).inspect_err(|e| {
        // The tier could not even be named on this host, so the session never
        // starts: the same remedy line the tier gate prints.
        emit_mxc_unavailable_hint(e);
    })?;
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
        emit_mxc_unavailable_hint(&net::mxc::MxcError::Tier(mismatch.clone()));
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
                emit_mxc_unavailable_hint(&e);
                return Ok(launch_failure_exit(&e));
            }
            // Nothing was established (no request, no container, no epoch, an SDK
            // failure): the root from (7b) is the whole record, and no refusal leaf
            // is added — a refusal leaf would claim a gate ran when none did.
            None => {
                emit_mxc_unavailable_hint(&e);
                return Err(e.into());
            }
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
pub(crate) fn refusal_for(err: &net::mxc::MxcError) -> Option<audit::session_start::TierRefusal<'static>> {
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
pub(crate) fn pre_launch_tier_refusal(probed: &net::mxc::TierRecord) -> Option<net::mxc::TierMismatch> {
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
pub(crate) fn launch_confirms_root(
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
pub(crate) fn launch_failure_exit(err: &net::mxc::MxcError) -> i32 {
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
pub(crate) fn session_exit_code(outcome: &net::mxc::SessionOutcome) -> i32 {
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
pub(crate) fn emit_child_output(outcome: &net::mxc::SessionOutcome) {
    use std::io::Write as _;
    let mut out = std::io::stdout().lock();
    let _ = out.write_all(&outcome.stdout);
    let _ = out.flush();
    let mut err = std::io::stderr().lock();
    let _ = err.write_all(&outcome.stderr);
    let _ = err.flush();
}


#[cfg(all(test, feature = "mxc-backend"))]
mod hint_tests {
    use super::mxc_unavailable_line;

    /// The line an operator reads after the failure: prefix plus their own
    /// command with the backend switched. Pinned as ONE string, end to end,
    /// because this text is the product's answer to the question "and now?" —
    /// both halves (prefix, builder) are pinned separately, and this test
    /// proves the assembled line is what the doc claims it is.
    #[test]
    fn the_unavailable_tier_line_is_prefix_plus_the_operators_own_command() {
        let argv = ["saife", "run", "--allow-cwd", "--", "cmd", "/c", "echo", "ok"]
            .iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(
            mxc_unavailable_line(&argv),
            "[saife] the MXC containment tier did not run on this host - retry with: \
saife run --backend appcontainer --allow-cwd -- cmd /c echo ok"
        );
    }
}
