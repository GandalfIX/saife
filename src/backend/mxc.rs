//! The MXC backend: the ProcessContainer backend behind the `mxc-backend`
//! feature.
//!
//! The body still lives in [`crate::run_mxc_session`] — this commit only puts it
//! behind the trait, unchanged. Nothing here may reorder its steps: the request
//! is built and probed before the launch, the tier gate decides before the root
//! is written, and the guardrails own the exit code.

use super::{ContainmentBackend, SessionRequest};

/// The ProcessContainer backend.
pub struct MxcBackend;

impl ContainmentBackend for MxcBackend {
    fn run(&self, req: &SessionRequest<'_>) -> anyhow::Result<i32> {
        crate::run_mxc_session(
            req.sid,
            req.cwd,
            req.net_cfg,
            req.fs,
            req.limits,
            req.runner_paths,
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
