//! The containment backends behind `saife run`.
//!
//! One trait, one implementation per enforcement mechanism:
//!
//! * [`AppContainerBackend`] — the in-repo Windows AppContainer supervisor
//!   (profile + per-session DACLs + job object), [`appcontainer::run_appcontainer_session`].
//! * [`MxcBackend`] — the ProcessContainer backend (`mxc-backend` feature),
//!   [`mxc::run_mxc_session`].
//!
//! The trait exists to make the *third* mechanism cheap: a backend is selected
//! once, from the resolved CLI, and owns its whole session lifecycle — prepare,
//! enforce, launch, prove, tear down. What it must NOT swallow is everything the
//! session needs regardless of mechanism, and everything that is this project's
//! evidence: profile/network/filesystem resolution, the audit chain (root leaf,
//! sealing, exit-code mapping) and the refusal vocabulary. Those stay in
//! [`crate::run_inner`] and the shared helpers beside it.
//!
//! The selection is the only place a feature state is allowed to decide which
//! backends EXIST. A binary without `mxc-backend` refuses `--backend mxc` with
//! the same message [`crate::cli::route_backend`] does, rather than falling back.
//!
//! # Adding a backend
//!
//! The whole extension contract fits in four steps, and the compiler does most
//! of the checking:
//!
//! 1. Write the mechanism as one private module beside the existing ones and
//!    implement [`ContainmentBackend`] — the request carries only
//!    platform-neutral types (paths, strings, slices), so the signature does not
//!    lock the mechanism to an OS.
//! 2. Add the arm to [`select`]. This is the ONLY place a mechanism becomes
//!    reachable, and everything feature-conditional about the platform lives
//!    behind that arm when the backend that needs it actually exists; there is
//!    no preemptive platform gating.
//! 3. Add the [`crate::cli::Backend`] variant. `route_backend`'s matrix is
//!    fail-closed, so an ungated variant refuses until it is wired.
//! 4. Reuse the shared vocabulary instead of inventing exits: refuse BY NAME
//!    (`EXIT_REFUSED` for a session whose guarantee cannot hold, exit 5 for a
//!    capability the operator asked for that this backend cannot carry out, and
//!    mirror the child's code for a session that ran and failed).
//!
//! What a new backend must NOT take over from the crate root: profile,
//! network and filesystem resolution, the audit chain's root, seal and exit
//! mapping, and the per-session id. Two mechanisms must not produce two stories
//! about what the operator asked for.

pub(crate) mod appcontainer;
#[cfg(feature = "mxc-backend")]
pub(crate) mod mxc;

use crate::net;
use crate::profile;

pub use appcontainer::AppContainerBackend;
#[cfg(feature = "mxc-backend")]
pub use mxc::MxcBackend;

use std::path::Path;

/// Everything one session needs, already resolved.
///
/// Built once in [`crate::run_inner`] after the profile, the network slice, the
/// filesystem slice, the limits and the session id are final — so a backend
/// never re-reads the CLI or the profile and two backends cannot disagree about
/// what the operator asked for.
///
/// Borrowed on purpose: no backend needs to own these, and the session id must
/// stay the caller's (it is what the audit chain and the per-session tree are
/// keyed by).
pub struct SessionRequest<'a> {
    pub sid: &'a str,
    pub cwd: &'a Path,
    pub net_cfg: &'a net::NetworkConfig,
    pub fs: &'a profile::FilesystemSlice,
    pub limits: &'a profile::Limits,
    /// The session profile's `runner.sync.paths`: what a build request that names
    /// no paths inherits. Empty is the whole project.
    #[cfg_attr(not(feature = "mxc-backend"), allow(dead_code))]
    pub runner_paths: &'a [String],
    pub audit_strict: bool,
    pub print_sid: bool,
    /// `--no-interactive`: passed through to a backend that can choose its stdio.
    #[cfg_attr(not(feature = "mxc-backend"), allow(dead_code))]
    pub no_interactive: bool,
    /// `--plugin` names, in the order given (repeatable).
    pub plugins: &'a [String],
    /// `--plugin-dir` roots, in the order given (repeatable).
    #[cfg_attr(not(feature = "mxc-backend"), allow(dead_code))]
    pub plugin_dirs: &'a [String],
    /// `--runner`: wire the build runner's facade mount and listener.
    pub enable_runner: bool,
    /// `--allow-host-loopback`: ADR-0007's session mode.
    #[cfg_attr(not(feature = "mxc-backend"), allow(dead_code))]
    pub allow_host_loopback: bool,
    /// `--allow-lan`.
    pub allow_lan: bool,
    /// The workload, verbatim: `argv[0]` is the program, the rest are its words.
    pub cmd: &'a [String],
}

/// Exit code for a session a guardrail refused.
///
/// `126` is `timeout(1)`'s "found but could not be executed", which is what a
/// refusal means here: the workload may well have run, but this session is not a
/// contained, proven session and its result is not evidence.
pub(crate) const EXIT_REFUSED: i32 = 126;

/// One containment mechanism.
///
/// `run` is the whole session: everything from "the inputs are resolved" to the
/// exit code the supervisor reports. A backend that cannot enforce part of the
/// request refuses BY NAME — a capability that silently does not appear is the
/// failure mode this project exists to prevent.
pub trait ContainmentBackend {
    /// Run one session to completion and return the exit code to report.
    fn run(&self, req: &SessionRequest<'_>) -> anyhow::Result<i32>;
}

/// The backend the CLI selected, ready to run.
///
/// The `mxc` arm is the only feature-gated one: a binary built without the
/// feature has no MXC session path at all, so it says so with the same message
/// the router uses. [`crate::cli::route_backend`] already refuses that
/// combination; this is the belt-and-braces second check for a caller that
/// skips the router.
pub fn select(kind: crate::cli::Backend) -> anyhow::Result<&'static dyn ContainmentBackend> {
    static APPCONTAINER: AppContainerBackend = AppContainerBackend;
    #[cfg(feature = "mxc-backend")]
    static MXC: MxcBackend = MxcBackend;

    match kind {
        crate::cli::Backend::AppContainer => Ok(&APPCONTAINER),
        #[cfg(feature = "mxc-backend")]
        crate::cli::Backend::Mxc => Ok(&MXC),
        #[cfg(not(feature = "mxc-backend"))]
        crate::cli::Backend::Mxc => anyhow::bail!("{}", crate::cli::MXC_FEATURE_MISSING),
    }
}
