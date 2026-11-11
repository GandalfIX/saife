//! The AppContainer backend: the in-repo Windows supervisor.
//!
//! The body still lives in [`crate::run_appcontainer_session`] — this commit only
//! puts it behind the trait, unchanged. Nothing here may reorder its steps: the
//! DACL journal opens before any host mutation, the per-session tree exists
//! before `--print-sid` answers, the audit root is armed before the child
//! exists, and teardown restores DACLs before deleting the profile.

use super::{ContainmentBackend, SessionRequest};

/// The Windows AppContainer supervisor.
pub struct AppContainerBackend;

impl ContainmentBackend for AppContainerBackend {
    fn run(&self, req: &SessionRequest<'_>) -> anyhow::Result<i32> {
        crate::run_appcontainer_session(req)
    }
}
