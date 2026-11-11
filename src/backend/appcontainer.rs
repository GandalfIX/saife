//! The AppContainer backend: the in-repo Windows supervisor.
//!
//! The body still lives in [`crate::run_appcontainer_session`] — this commit only
//! puts it behind the trait, unchanged. Nothing here may reorder its steps: the
//! DACL journal opens before any host mutation, the per-session tree exists
//! before `--print-sid` answers, the audit root is armed before the child
//! exists, and teardown restores DACLs before deleting the profile.

use super::{ContainmentBackend, SessionRequest, EXIT_REFUSED};
use crate::{
    appcontainer_session_facts, audit, join_cmdline, net, plugin, sandbox, seal_audit,
    start_session_proxy,
};
use anyhow::{Context, Result};

/// The Windows AppContainer supervisor.
pub struct AppContainerBackend;

impl ContainmentBackend for AppContainerBackend {
    fn run(&self, req: &SessionRequest<'_>) -> anyhow::Result<i32> {
        run_appcontainer_session(req)
    }
}

/// Run one session through the AppContainer backend.
///
/// Moved here unchanged from `run_inner`; everything that makes a run
/// evidence - the DACL journal, the audit root, the teardown order - is in
/// here and must stay in here.
fn run_appcontainer_session(req: &SessionRequest<'_>) -> Result<i32> {
    // Rebound from the request: no logic, just the names the moved body uses.
    let sid = req.sid;
    let cwd = req.cwd;
    let net_cfg_resolved = req.net_cfg;
    let fs = req.fs;
    let limits = req.limits;
    let audit_strict = req.audit_strict;
    let print_sid = req.print_sid;
    let plugins = req.plugins;
    let enable_runner = req.enable_runner;
    let allow_lan = req.allow_lan;
    let cmd = req.cmd;
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
    // Same rule for the runner: refused BY NAME rather than started or ignored. The
    // facade exists on both backends, so this is a wiring gap and not a containment one
    // — but a capability that silently does not appear is exactly the failure mode this
    // project exists to prevent.
    if enable_runner {
        eprintln!(
            "[saife] runner_unsupported_backend: --runner (the build runner is wired on --backend mxc only)"
        );
        return Ok(2);
    }

    // MXC F-C/F-D: before any host-DACL mutation, reap journals of dead
    // owners (restore their entries, quarantine corrupt ones). Then open
    // this run's journal. Failure to open is a warning only — the run
    // proceeds unjournaled.
    let journal_dir = sandbox::dacl_journal::default_dir();
    // The closure answers "is this journal's OWNER alive". A `!` here used
    // to mean recover_orphans KEPT journals of dead processes and REAPED the
    // journals of LIVE runs - a concurrent session on the shared cwd lost its
    // DACLs (its ACEs were restored out from under it) while old crashes
    // littered the store. Observed 2026-11-11; S-13 was the visible edge.
    sandbox::dacl_journal::recover_orphans(
        &journal_dir,
        &|h| sandbox::dacl_journal::is_process_alive(h.owner_pid, h.owner_created),
        &|j| sandbox::appcontainer::restore_or_warn(j),
    );
    let run_journal = match sandbox::dacl_journal::DaclJournal::open(
        &journal_dir,
        sandbox::dacl_journal::JournalHeader {
            run_id: sid.to_string(),
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
    sandbox::ensure_session_dirs(cwd, sid)
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
    let audit_writer = std::sync::Arc::new(audit::AuditWriter::open(sid, audit_strict)?);
    let session_start = audit::session_start::SessionStart::arm(
        audit_writer.clone(),
        sid,
        cmd.join(" "),
        appcontainer_session_facts(),
    );

    let net_cfg = net_cfg_resolved.clone();

    // Build the AppContainer session.
    let session = sandbox::create_session(sid)
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
        eprintln!("[saife]          registered automatically when elevated), or use --block-net.");
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
        sid,
        audit_writer.clone(),
        std::sync::Arc::new(plugin::FacadeRegistry::new()),
        // Unchanged: this backend refuses `--plugin` and `--runner` by name
        // above, so it never has a mount that would need a listener.
        false,
        allow_lan,
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
    let entries = sandbox::build_allowlist(sid, cwd, fs)?;

    // Fail-close (decision 2026-11-10): a DENY ACE that could not be applied
    // means the session would run with MORE access than the profile allows —
    // `grant_access` says so in its own error ("refusing the session rather
    // than running it with the deny missing"). This used to print that error
    // as a warning and start the child anyway, which made the message a lie:
    // the child ran while the deny was missing (fail-open). The session is now
    // refused: a SESSION_REFUSED leaf names the cause, the grants that DID
    // land come off the host (same teardown order as a normal run), and the
    // process exits `EXIT_REFUSED` — the refusal code the mxc guardrails use.
    if let Err(e) = sandbox::grant_access(&session.ac_sid.0, &entries, run_journal.as_ref()) {
        eprintln!("[saife] refused: the DACL grants could not be applied: {e}");
        eprintln!("[saife]          fail-close: the session is refused rather than run with a deny missing");
        let refusal = audit::session_start::TierRefusal::refused(
            "dacl_apply_failed",
            audit::session_start::TIER_APPCONTAINER_DACL,
        );
        if let Err(aerr) = audit::session_start::append_refusal(&audit_writer, sid, refusal) {
            eprintln!("[saife] warning: could not record the refusal in the audit: {aerr}");
        }
        if let Some(j) = &run_journal
            && sandbox::appcontainer::restore_or_warn(j)
        {
            j.remove_file();
        }
        sandbox::appcontainer::delete_profile(&session.ac_name);
        let _ = crate::remove_session_sandbox_dir(cwd, sid);
        seal_audit(audit_writer, proxy.map(|(handle, _)| handle), sid);
        return Ok(EXIT_REFUSED);
    }

    let env_block = sandbox::build_env_block(sid, cwd, proxy.as_ref().map(|(_, env)| env));

    let cmdline = join_cmdline(cmd);

    let job = sandbox::Job::create().context("create Job Object")?;

    let exit_code = sandbox::spawn(
        &session,
        &job,
        cwd,
        env_block,
        &cmdline,
        !net_cfg.is_blocked(),
    )
    .context("spawn sandboxed process")?;

    seal_audit(audit_writer, proxy.map(|(handle, _)| handle), sid);

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

    // L-O (verdict: partial): the ACE half was already implemented by the DACL
    // journal above; the per-session `.sandbox/<sid>` DIRECTORY was never
    // removed, so every run left one behind. Best-effort on purpose: the tree is
    // litter once its ACEs are restored, and a workload may still hold a file in
    // it - a finished run must not fail over that.
    let _ = crate::remove_session_sandbox_dir(cwd, sid);

    Ok(exit_code as i32)
}

