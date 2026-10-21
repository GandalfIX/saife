//! MXC `processcontainer` containment backend — ADR-0004 Option A.
//!
//! This module is the *only* place the supervisor talks to `mxc-sdk`. It is
//! compiled only with the `mxc-backend` Cargo feature; the AppContainer
//! supervisor is untouched and remains the default backend (P3 flips it).
//!
//! What is here:
//!
//! * [`build_request`] is a **pure** mapping from our resolved session data to a
//!   `ContainerRequest`. No I/O, no SDK calls, so it is fully unit-testable.
//! * The container command is always the wrapper launcher, never the workload
//!   itself: `mxc-sdk 1.0.1` scrubs `NO_PROXY` from `request.environment`, and
//!   without it a proxy-honouring client that is asked to call the D-4 intent
//!   endpoint would send that request into the proxy (plan decision **D1**).
//!   [`launcher_command`] builds `mxc-launch.exe -- "<real command line>"`;
//!   `src/bin/mxc-launch.rs` sets `NO_PROXY`, starts the workload with inherited
//!   stdio and propagates its exit code.
//! * [`MxcBackend`] is a **state-carrying** launch context — proof source, proxy
//!   port, wrapper launcher and run budget — so a request can never describe a
//!   proxy the backend does not own (plan decision **D4**).
//! * Guardrail 1 ([`ProofExpectation`] + [`verify_proxy_proof`]) is a hard gate
//!   with **two** legs: a network session must prove the child reached the proxy
//!   (`Required`), and a blocked/proxy-less session must prove the proxy was
//!   never consulted (`MustBeAbsent`). Both are errors, never warnings (plan
//!   decision **D3**).
//! * Every launch owns an attribution **epoch**: opened before the child starts,
//!   closed on the success *and* the error path ([`EpochGuard`]).
//! * Guardrail 2 ([`probe_tier`]) records the tier of the *exact* request about
//!   to be launched. The audit leaf that persists it lands in P2.3.
//!
//! Not here, by design: the real `ProxyProofSource` over `src/net/proxy.rs` and
//! the per-session proxy bind (P1.4/P2.2), filesystem denied-path policy (P1.3),
//! the session-start audit leaf (P2.3), and the prompt/timeout budget arithmetic
//! (P2.1). [`build_request`] passes the caller's `timeout_ms` through unchanged —
//! `None` means *no deadline*, because the SDK turns a zero timeout into
//! `INFINITE` (`mxc_common::script_runner::get_timeout_milliseconds`) — and
//! [`MxcBackend`] overrides it only when a budget was set explicitly with
//! [`with_budget`](MxcBackend::with_budget). A backend that was never given a
//! budget therefore never discards the caller's deadline.
//!
//! There is no attestation at `mxc-sdk 1.0.1` (ADR-0004): the tier is observed
//! after the fact, and `warnings: []` is never treated as evidence.

// P1 wires the launch path behind `MxcBackend`, but `main.rs` still refuses
// `--backend mxc` (`MXC_SESSION_WIRED = false`), so nothing in the binary
// constructs a backend and *every* item in this module is unreachable from a
// non-test build: `pub` inside a binary crate is not a reachable entry point.
// The allow is scoped to non-test builds so genuine rot still surfaces under
// `cargo test`. Removing it requires a real call site in `main.rs` (the P2/P3
// session wiring), not merely this seam. Unreachable set: the whole public
// surface — `BLOCKED_ENV_KEYS`, `is_blocked_env_key`, `LAUNCHER_EXE_NAME`,
// `launcher_grant`, `launcher_command`,
// `MxcFilesystemInput`, `MxcNetworkInput`, `MxcSessionInput`, `ProxyProof`,
// `ProofExpectation`, `verify_proxy_proof`, `GuardError`, `ProxyProofSource`,
// `TierRecord`, `ProbeView`, `tier_record`, `probe_tier`, `TIER_SOURCE_PROBE`,
// `TIER_SOURCE_UNAVAILABLE`, `RequestError`, `MxcError`, `SessionOutcome`,
// `build_request`,
// `process_container_config`, `MxcBackend`.
#![cfg_attr(not(test), allow(dead_code))]

use std::fmt;
use std::path::{Path, PathBuf};

use mxc_sdk::v1;
use mxc_sdk::v1::configs::{
    ProcessContainerConfig, ProcessContainerSystemSettings, ProcessContainerUi,
    ProcessContainerUiIsolation,
};
use mxc_sdk::v1::{
    ContainerRequest, Containment, FilesystemPolicy, NetworkAction, NetworkEgressPolicy,
    NetworkIngressPolicy, NetworkPolicy, NetworkRuntimeConfig, RunOptions, WaitResult,
};

// ---------------------------------------------------------------------------
// Environment allow-list
// ---------------------------------------------------------------------------

/// Environment keys that must never be copied from the host into the container.
///
/// This is invariant 5 of the migration plan and a direct consequence of
/// ADR-0004: MXC injects its own `HTTP_PROXY`/`HTTPS_PROXY` pointing at the
/// supervisor's proxy and leaves `NO_PROXY` unset. A host value that crossed
/// into the request would either point the child at a proxy we do not control —
/// which makes guardrail 1 unprovable — or disable proxying for a host we
/// intended to route.
///
/// `NO_PROXY` is on this list even though the child *does* need one: the value
/// it needs is the loopback-only one, delivered by the wrapper launcher
/// ([`launcher_command`]) after the SDK has finished sanitising the request
/// environment. A caller-supplied value would still be wrong.
///
/// Matching is ASCII case-insensitive because Windows environment names are.
pub const BLOCKED_ENV_KEYS: [&str; 4] = ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"];

/// Whether `key` is a host proxy variable that must be stripped.
pub fn is_blocked_env_key(key: &str) -> bool {
    let key = key.trim();
    BLOCKED_ENV_KEYS
        .iter()
        .any(|blocked| blocked.eq_ignore_ascii_case(key))
}

// ---------------------------------------------------------------------------
// Wrapper launcher (D1: the only way NO_PROXY reaches the child)
// ---------------------------------------------------------------------------

/// File name of the wrapper launcher, deployed beside the supervisor's own
/// executable (`src/bin/mxc-launch.rs`).
pub const LAUNCHER_EXE_NAME: &str = "mxc-launch.exe";

/// The directory a caller **must** add to `readonly_paths`.
///
/// Filesystem policy in MXC is additive grants, so the container cannot execute
/// the launcher unless its directory is granted; without this the launch fails
/// with a policy denial that names nothing.
pub fn launcher_grant(launcher: &Path) -> Option<String> {
    let dir = launcher.parent()?.display().to_string();
    // A bare file name has no directory to grant; returning `Some("")` would
    // turn into an empty filesystem path in the request.
    (!dir.is_empty()).then_some(dir)
}

/// Quote one argv element so that a `CommandLineToArgvW`-compatible parser
/// (what `CreateProcessW`'s target and Rust's `std::env::args` both use)
/// returns it unchanged.
///
/// This mirrors the algorithm Rust's own `Command` uses on Windows: backslashes
/// are literal unless they precede a quote, where they are doubled, and a
/// backslash run before the closing quote is doubled as well.
///
/// A NUL is **not** rejected here — the function is byte-transparent — but an
/// embedded NUL would truncate the command line at the OS boundary, so
/// [`build_request`] refuses such a command before a request exists
/// ([`RequestError::NulInCommand`]).
fn quote_windows_arg(arg: &str) -> String {
    let needs_quotes = arg.is_empty()
        || arg
            .chars()
            .any(|c| matches!(c, ' ' | '\t' | '"' | '\n' | '\u{b}'));
    if !needs_quotes {
        return arg.to_string();
    }

    let mut out = String::with_capacity(arg.len() + 2);
    out.push('"');
    let mut backslashes = 0usize;
    for c in arg.chars() {
        match c {
            '\\' => backslashes += 1,
            '"' => {
                // 2n+1 backslashes then the quote: n literal backslashes plus
                // the escaping one.
                for _ in 0..(backslashes * 2 + 1) {
                    out.push('\\');
                }
                out.push('"');
                backslashes = 0;
            }
            other => {
                for _ in 0..backslashes {
                    out.push('\\');
                }
                backslashes = 0;
                out.push(other);
            }
        }
    }
    // Trailing backslashes would otherwise escape the closing quote.
    for _ in 0..(backslashes * 2) {
        out.push('\\');
    }
    out.push('"');
    out
}

/// The container command: the wrapper launcher, with the real workload command
/// line as its single argument.
///
/// The workload's command line travels as **one** argument and the wrapper hands
/// it to `CreateProcessW` verbatim, so it keeps exactly the meaning it would
/// have had as the container command itself.
pub fn launcher_command(launcher: &Path, real_command: &str) -> String {
    format!(
        "{} -- {}",
        quote_windows_arg(&launcher.to_string_lossy()),
        quote_windows_arg(real_command)
    )
}

// ---------------------------------------------------------------------------
// Input: our resolved session data (plain, no SDK types)
// ---------------------------------------------------------------------------

/// Filesystem grants as the supervisor resolved them (P1.3 maps policy onto
/// this; for now only explicit grants are passed through).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MxcFilesystemInput {
    pub readwrite_paths: Vec<String>,
    pub readonly_paths: Vec<String>,
    /// Paths the child must not see. Filesystem policy is *additive* in MXC, so
    /// a "workspace only" posture needs explicit denies (ADR-0004).
    pub denied_paths: Vec<String>,
}

/// Network posture for the launch.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MxcNetworkInput {
    /// Loopback port the supervisor's proxy listens on (P1.4 binds it). `None`
    /// means no proxy: the request stays egress-denied and host loopback stays
    /// closed.
    ///
    /// [`MxcBackend`] overrides this with its own port; the field stays so the
    /// pure mapping can be exercised on its own.
    pub proxy_port: Option<u16>,
}

/// One session, as the supervisor resolved it. Plain data — deliberately free
/// of SDK types so the mapping can be tested without the runtime.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MxcSessionInput {
    /// The workload's command line, verbatim. [`build_request`] does not hand it
    /// to the container directly: it becomes the argument of the wrapper
    /// launcher ([`launcher_command`]).
    pub command: String,
    /// Initial working directory; `None` leaves the backend default.
    pub working_directory: Option<String>,
    /// Environment entries the caller wants propagated. Host proxy variables
    /// are removed by [`build_request`] — see [`BLOCKED_ENV_KEYS`].
    pub environment: Vec<(String, String)>,
    pub filesystem: MxcFilesystemInput,
    pub network: MxcNetworkInput,
    /// Wall-clock bound for the whole workload, in milliseconds. `None` — and
    /// `Some(0)` — means **no deadline**: the SDK maps a zero timeout to
    /// `INFINITE` (`mxc_common::script_runner::get_timeout_milliseconds`). P2.1
    /// owns the budget arithmetic; [`build_request`] passes the value through
    /// unchanged, and [`MxcBackend`] overrides it only when it carries an
    /// explicit budget ([`with_budget`](MxcBackend::with_budget)).
    pub timeout_ms: Option<u32>,
}

// ---------------------------------------------------------------------------
// Guardrail 1: post-launch proxy proof (hard gate, two legs)
// ---------------------------------------------------------------------------

/// The supervisor's own count of what its proxy saw for one launch epoch.
///
/// `accepted` counts **proxy consultations** — connections the proxy handled as
/// a proxy (`CONNECT`, or an absolute-form request) — in the epoch; `tunnels`
/// counts those whose origin dial succeeded (i.e. a real `200 Connection
/// Established` was sent). Both are needed: the spike proved that a proxy
/// 502/403 (unresolvable target, loopback target) and a silently misconfigured
/// container both give `accepted >= 1, tunnels == 0`, and that a container that
/// never reached the proxy gives `accepted == 0` while still exiting 0 with
/// `warnings: []`.
///
/// Deliberately *not* counted: a direct, origin-form request to one of our own
/// loopback endpoints (the D-4 intent endpoints). Serving an endpoint is not a
/// proxy consultation, and counting it would make
/// [`ProofExpectation::MustBeAbsent`] unsatisfiable for exactly the sessions it
/// exists for.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ProxyProof {
    pub accepted: u64,
    pub tunnels: u64,
}

/// What guardrail 1 must observe for this launch (plan decision D3).
///
/// Both legs are hard gates, and the caller **must** supply the right one:
///
/// * [`ProofExpectation::Required`] for a network session (a proxy port is
///   configured): the child must have reached the proxy *and* the proxy must
///   have established at least one tunnel. Derive it with
///   [`ProofExpectation::for_network`].
/// * [`ProofExpectation::MustBeAbsent`] for a blocked / proxy-less session: the
///   proxy must never have been consulted, which is the only positive evidence
///   that a no-network session really did not go out.
///
/// Choosing the wrong leg is itself a hard failure — never a skipped check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofExpectation {
    /// `accepted >= 1 && tunnels >= 1`.
    Required,
    /// `accepted == 0 && tunnels == 0`.
    MustBeAbsent,
}

impl ProofExpectation {
    /// The leg a session with this network posture must supply: `Required` when
    /// a proxy port is configured, `MustBeAbsent` when it is not.
    pub fn for_network(proxy_port: Option<u16>) -> Self {
        match proxy_port {
            Some(_) => Self::Required,
            None => Self::MustBeAbsent,
        }
    }
}

/// Why guardrail 1 refused a launch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardError {
    /// No proof source was supplied, so the launch cannot be proven at all.
    MissingProofSource,
    /// `Required` was requested for a session with no proxy port: no launch can
    /// ever satisfy it, so it is refused before the child starts.
    RequiredWithoutProxy,
    /// The child never reached the proxy in this launch's epoch.
    SessionNotAccepted,
    /// The proxy accepted a connection but never established a tunnel (502/403
    /// or a loopback/HostLoopback misconfiguration).
    TunnelNotEstablished,
    /// `MustBeAbsent` was requested but the proxy *was* consulted for this
    /// launch — a session that was supposed to stay offline went out.
    ProxyConsultedUnexpectedly,
}

impl fmt::Display for GuardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Self::MissingProofSource => {
                "no proxy proof source: ADR-0004 guardrail 1 requires a post-launch proxy proof \
                 for every MXC launch"
            }
            Self::RequiredWithoutProxy => {
                "guardrail 1: a network session was expected but the request configures no proxy, \
                 so no launch could ever prove the child reached one"
            }
            Self::SessionNotAccepted => {
                "guardrail 1: no proxy session was accepted in this launch's epoch — the child \
                 never reached the proxy"
            }
            Self::TunnelNotEstablished => {
                "guardrail 1: the proxy accepted a session but established no CONNECT tunnel"
            }
            Self::ProxyConsultedUnexpectedly => {
                "guardrail 1: the proxy was consulted for a session that must never reach it — \
                 the workload is expected to be blocked"
            }
        };
        f.write_str(msg)
    }
}

impl std::error::Error for GuardError {}

/// The hard gate, in both legs.
///
/// `Required` demands `accepted >= 1 && tunnels >= 1`; `MustBeAbsent` demands
/// `accepted == 0 && tunnels == 0`. Anything else fails the launch.
pub fn verify_proxy_proof(
    proof: ProxyProof,
    expectation: ProofExpectation,
) -> Result<(), GuardError> {
    match expectation {
        ProofExpectation::Required => {
            if proof.accepted == 0 {
                return Err(GuardError::SessionNotAccepted);
            }
            if proof.tunnels == 0 {
                return Err(GuardError::TunnelNotEstablished);
            }
            Ok(())
        }
        ProofExpectation::MustBeAbsent => {
            if proof.accepted != 0 || proof.tunnels != 0 {
                return Err(GuardError::ProxyConsultedUnexpectedly);
            }
            Ok(())
        }
    }
}

/// Where the launch path gets its proof from.
///
/// Implemented by the per-session proxy: [`begin_launch`] opens an attribution
/// epoch *before* the child starts, [`proof`] reports the counters for that
/// epoch, and [`close_launch`] closes the window. The launch path calls
/// `close_launch` exactly once per `begin_launch`, on the success and the error
/// path alike (see [`EpochGuard`]), so a `v1::run` error cannot leave an epoch
/// open.
///
/// `Send + Sync`: the epoch is opened on the session's thread while the counters
/// are written from the proxy's I/O threads, and the supervisor's proxy runtime
/// will hold this across `await` points.
///
/// One proxy per launch until P1.4 lands the per-run token (ADR-0004
/// "concurrency caveat").
///
/// [`begin_launch`]: ProxyProofSource::begin_launch
/// [`proof`]: ProxyProofSource::proof
/// [`close_launch`]: ProxyProofSource::close_launch
pub trait ProxyProofSource: Send + Sync {
    /// Open an attribution epoch and return its id.
    fn begin_launch(&self) -> u64;
    /// Counters for the sessions accepted in `epoch`.
    fn proof(&self, epoch: u64) -> ProxyProof;
    /// Close `epoch`'s attribution window. Called exactly once per
    /// [`begin_launch`](ProxyProofSource::begin_launch).
    fn close_launch(&self, epoch: u64);
}

/// Owns one epoch's lifetime: whichever way the launch leaves, the epoch is
/// closed.
///
/// The guard is the structural part of D4 — the alternative (a bare
/// `begin_launch` followed by a `?` on `v1::run`) abandons the window on every
/// error path.
struct EpochGuard<'a> {
    source: &'a dyn ProxyProofSource,
    epoch: u64,
    closed: bool,
}

impl<'a> EpochGuard<'a> {
    fn open(source: &'a dyn ProxyProofSource) -> Self {
        Self {
            source,
            epoch: source.begin_launch(),
            closed: false,
        }
    }

    /// Read the epoch's counters and close the window. The counters are frozen
    /// at this point, so traffic that arrives later cannot satisfy this launch.
    fn finish(&mut self) -> ProxyProof {
        let proof = self.source.proof(self.epoch);
        self.close();
        proof
    }

    fn close(&mut self) {
        if !self.closed {
            self.closed = true;
            self.source.close_launch(self.epoch);
        }
    }
}

impl Drop for EpochGuard<'_> {
    fn drop(&mut self) {
        // `drop` also runs while a panic unwinds, and a panic that escapes a
        // `Drop` *during* an unwind aborts the whole process. `close_launch` is
        // caller-supplied, so a panicking close must not turn a recoverable
        // launch failure into an abort. Nothing can be reported from here: the
        // `closed` flag is already set when the call panics, so the worst case is
        // an epoch window the source never released — a leak, never a false
        // proof, because the proof is read before `close()` is called.
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.close()));
    }
}

/// Run `body` under a fresh launch epoch and return its value with the epoch's
/// proof. The epoch is opened before `body` runs and closed afterwards whether
/// `body` succeeded or failed.
fn run_in_epoch<T>(
    source: &dyn ProxyProofSource,
    body: impl FnOnce() -> Result<T, MxcError>,
) -> Result<(T, ProxyProof), MxcError> {
    let mut guard = EpochGuard::open(source);
    // No `?` here: the epoch must be closed and its proof read before the error
    // is propagated.
    let result = body();
    let proof = guard.finish();
    result.map(|value| (value, proof))
}

// ---------------------------------------------------------------------------
// Guardrail 2: per-session tier record
// ---------------------------------------------------------------------------

/// The isolation tier that was actually dispatched, plus its provenance.
///
/// `tier_source` is `"probe"` when `v1::probe` named a tier and `"unavailable"`
/// when it could not (probe error or no tier). It is never the backend ceiling:
/// ADR-0004 forbids recording a ceiling as if it were the dispatched tier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TierRecord {
    pub tier: Option<String>,
    pub tier_source: &'static str,
    /// Verbatim from the probe: `None` when the probe did not state it. Never
    /// narrowed to `false`, which would assert something the probe declined to
    /// assert.
    pub needs_dacl_augmentation: Option<bool>,
}

/// `tier_source` when `v1::probe` named the dispatched tier.
pub const TIER_SOURCE_PROBE: &str = "probe";
/// `tier_source` when the probe could not name a tier.
pub const TIER_SOURCE_UNAVAILABLE: &str = "unavailable";

/// The subset of `v1::ProbeOutput` guardrail 2 consumes.
///
/// Splitting it out keeps the mapping unit-testable without fabricating the
/// SDK's full probe-fact set.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ProbeView {
    pub tier: Option<&'static str>,
    pub needs_dacl_augmentation: Option<bool>,
}

impl ProbeView {
    pub fn from_probe(probe: &v1::ProbeOutput) -> Self {
        Self {
            tier: probe.tier,
            needs_dacl_augmentation: probe.needs_dacl_augmentation,
        }
    }
}

/// Map a probe result to a [`TierRecord`] (pure).
pub fn tier_record(view: ProbeView) -> TierRecord {
    TierRecord {
        tier: view.tier.map(str::to_string),
        // Never a backend ceiling: a probe that names no tier is recorded as
        // unknown, so the record cannot overstate what was dispatched.
        tier_source: if view.tier.is_some() {
            TIER_SOURCE_PROBE
        } else {
            TIER_SOURCE_UNAVAILABLE
        },
        // Carried through as-is: a probe that says nothing is recorded as
        // "unknown", not as "no augmentation needed".
        needs_dacl_augmentation: view.needs_dacl_augmentation,
    }
}

/// Probe the **exact** request that is about to be launched.
///
/// Never called with a lookalike or a copy: `v1::probe` is the only way to learn
/// which tier *this* request dispatches to, and a tier is observable after
/// dispatch only (there is no `require_tier` at 1.0.1).
pub fn probe_tier(request: &ContainerRequest) -> Result<TierRecord, MxcError> {
    let probe = v1::probe(Some(request))?;
    Ok(tier_record(ProbeView::from_probe(&probe)))
}

// ---------------------------------------------------------------------------
// Errors and outcome
// ---------------------------------------------------------------------------

/// A request the mapping refuses to build.
///
/// Both cases are checked **before** anything is spawned, because both only
/// surface later and misleadingly: an empty command reaches the container as a
/// wrapper launch with nothing to start (a bare `126` that looks like a usage
/// error), and a command line containing NUL is truncated by `CreateProcessW`
/// at the NUL — the child would run a different command from the one the
/// request is recorded as launching.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestError {
    /// The workload command line is empty (or only whitespace).
    EmptyCommand,
    /// The command line contains a NUL, which the OS treats as its end.
    NulInCommand,
}

impl fmt::Display for RequestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Self::EmptyCommand => {
                "the workload command line is empty: there is nothing to start in the container"
            }
            Self::NulInCommand => {
                "the workload command line contains a NUL, which would truncate it at the OS \
                 boundary — the child would run something other than the command named here"
            }
        };
        f.write_str(msg)
    }
}

impl std::error::Error for RequestError {}

/// An MXC launch failure.
#[derive(Debug)]
pub enum MxcError {
    /// Guardrail 1 refused the launch.
    Guard(GuardError),
    /// The request could not be built at all: refused before any spawn, with no
    /// container and no epoch.
    Request(RequestError),
    /// The SDK refused the request or the wait failed.
    Sdk(v1::Error),
}

impl fmt::Display for MxcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Guard(e) => write!(f, "{e}"),
            Self::Request(e) => write!(f, "{e}"),
            Self::Sdk(e) => write!(f, "mxc-sdk: {e}"),
        }
    }
}

impl std::error::Error for MxcError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Guard(e) => Some(e),
            Self::Request(e) => Some(e),
            Self::Sdk(e) => Some(e),
        }
    }
}

impl From<GuardError> for MxcError {
    fn from(e: GuardError) -> Self {
        Self::Guard(e)
    }
}

impl From<RequestError> for MxcError {
    fn from(e: RequestError) -> Self {
        Self::Request(e)
    }
}

impl From<v1::Error> for MxcError {
    fn from(e: v1::Error) -> Self {
        Self::Sdk(e)
    }
}

/// What a launch produced, in the shape P1 feeds into the existing session
/// result path.
///
/// A `SessionOutcome` exists only for launches that passed guardrail 1, so its
/// presence is the proof-carrying success signal.
#[derive(Debug, Clone)]
pub struct SessionOutcome {
    /// `None` when the workload was killed by `timeout_ms`.
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    /// Policy/operational warnings from the container. Never evidence of
    /// network reachability (ADR-0004).
    pub warnings: Vec<String>,
    pub tier: TierRecord,
    pub proxy_proof: ProxyProof,
    /// The leg this launch was gated on, carried so [`success`] cannot re-check
    /// against a different leg than the launch used.
    ///
    /// [`success`]: SessionOutcome::success
    pub expectation: ProofExpectation,
}

impl SessionOutcome {
    /// True only for a clean exit 0 whose proxy proof passes guardrail 1 for the
    /// leg the launch was gated on.
    ///
    /// The proof is re-checked here rather than assumed: a hand-built or
    /// deserialised outcome cannot report success on an unproven launch just by
    /// carrying a zero exit code.
    pub fn success(&self) -> bool {
        self.exit_code == Some(0)
            && !self.timed_out
            && verify_proxy_proof(self.proxy_proof, self.expectation).is_ok()
    }
}

/// The child's result, before the guardrail is applied.
#[derive(Debug, Clone)]
struct ChildRun {
    wait: WaitResult,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    warnings: Vec<String>,
}

// ---------------------------------------------------------------------------
// Request mapping (pure)
// ---------------------------------------------------------------------------

/// The `ProcessContainerConfig` posture, pinned field by field.
///
/// The SDK types are `#[non_exhaustive]` and their `Default` is a *patchable*
/// value, so every field we care about is set here explicitly (plan decision
/// D6) instead of inherited: a bump that changed one of them would otherwise
/// change containment silently. The values are today's SDK defaults and must
/// stay so — `pinned_ui_fields_match_the_sdk_default` is the drift alarm.
fn process_container_config() -> ProcessContainerConfig {
    let mut ui = ProcessContainerUi::default();
    ui.isolation = ProcessContainerUiIsolation::Container;
    ui.desktop_system_control = false;
    ui.system_settings = ProcessContainerSystemSettings::None;
    ui.ime = false;

    let mut config = ProcessContainerConfig::default();
    // No deny-and-record ETL capture: learning mode is a discovery tool, not a
    // containment posture, and it writes a trace.
    config.learning_mode = false;
    // No additional capability SIDs beyond what proxy-only egress implies.
    config.capabilities = Vec::new();
    config.capture_denials = None;
    config.ui = Some(ui);
    // No enumerate-without-read grants.
    config.filesystem = None;
    // Identity-less deployment: `allowedProxyPeer` stays unset (a `host:port`
    // peer fails the request build with `malformed_request`).
    config.network = None;
    config
}

/// Map resolved session data to a `ContainerRequest` (pure: no I/O, no SDK
/// calls).
///
/// Posture, all of it forced by the ADR-0004 prototype:
///
/// * `egress.default = deny` — the child reaches nothing except our proxy.
/// * `ingress.default = allow` **and** `ingress.host_loopback = allow` are
///   mandatory for proxy-only egress, and `processContainer.network
///   .allowedProxyPeer` stays unset: an unpackaged caller-owned proxy has no
///   package identity, and the identity-scoped form fails the request build.
///   This is the deployment upstream labels development/testing compatibility
///   (ADR-0004 risk 2) — the one that actually works unelevated.
/// * `environment` is always an explicit, filtered allow-list — never `None`
///   (which would mean "backend default").
/// * The command is the **wrapper launcher**, not the workload (D1).
///
/// Fails with [`RequestError`] for a workload command that cannot be launched.
/// Both refusals happen here, at map time, rather than once the container
/// exists: an empty command and an embedded NUL only show up as a failed spawn.
pub fn build_request(
    input: &MxcSessionInput,
    launcher: &Path,
) -> Result<ContainerRequest, RequestError> {
    if input.command.trim().is_empty() {
        return Err(RequestError::EmptyCommand);
    }
    // A NUL would end the command line at `CreateProcessW`, so the argv the
    // child sees would stop there — silently, and not what was recorded here.
    if input.command.contains('\0') {
        return Err(RequestError::NulInCommand);
    }

    // Invariant 5: the host's proxy configuration never crosses. Always an
    // explicit list, even when empty — `None` would mean "backend default".
    let environment: Vec<(String, String)> = input
        .environment
        .iter()
        .filter(|(key, _)| !is_blocked_env_key(key))
        .cloned()
        .collect();

    let network = match input.network.proxy_port {
        // Proxy-only egress: everything outbound is denied at the container
        // level and the only path out is the supervisor's loopback proxy.
        Some(port) => NetworkPolicy {
            egress: Some(NetworkEgressPolicy {
                default: Some(NetworkAction::Deny),
                allow: None,
                deny: None,
            }),
            // Both are mandatory for proxy-only egress (ADR-0004 constraint).
            ingress: Some(NetworkIngressPolicy {
                default: Some(NetworkAction::Allow),
                host_loopback: Some(NetworkAction::Allow),
            }),
            runtime_config: Some(NetworkRuntimeConfig {
                network_proxy: Some(format!("http://127.0.0.1:{port}")),
            }),
        },
        // No proxy: no network at all, and no host loopback.
        None => NetworkPolicy {
            egress: Some(NetworkEgressPolicy {
                default: Some(NetworkAction::Deny),
                allow: None,
                deny: None,
            }),
            ingress: Some(NetworkIngressPolicy {
                default: Some(NetworkAction::Deny),
                host_loopback: Some(NetworkAction::Deny),
            }),
            runtime_config: None,
        },
    };

    let mut request = ContainerRequest::new(launcher_command(launcher, &input.command));
    request.filesystem = Some(FilesystemPolicy {
        readwrite_paths: input.filesystem.readwrite_paths.clone(),
        readonly_paths: input.filesystem.readonly_paths.clone(),
        denied_paths: input.filesystem.denied_paths.clone(),
        clear_policy_on_exit: Some(true),
    });
    request.network = Some(network);
    request.timeout_ms = input.timeout_ms;
    // Identity-less deployment: `allowedProxyPeer` is left unset because an
    // unpackaged caller-owned proxy has no package family name, and the
    // identity-scoped form fails the request build with `malformed_request`.
    request.containment = Containment::ProcessContainer(process_container_config());
    request.working_directory = input.working_directory.clone();
    request.environment = Some(environment);
    // D2 — deliberately `Some(true)`. At `mxc-sdk 1.0.1` this block is the
    // user's **profile** environment (`create_default_env_entries` →
    // `CreateEnvironmentBlock(.., bInherit = FALSE)`), never this process's
    // environment, and it is what makes an ordinary workload work at all
    // (PATH/TEMP/USERPROFILE/PSModulePath); `Some(false)` would hand the child a
    // bare allow-list, and the SDK's `validate_required_child_env` exists
    // precisely because that breaks CreateProcessW.
    //
    // It is safe *because* `build_inherited_entries` lays our filtered list on
    // top and then `inject_proxy_vars` strips HTTP_PROXY/HTTPS_PROXY/NO_PROXY/
    // ALL_PROXY (case-insensitive) from the merged block before injecting the
    // configured proxy: no host proxy value can survive into a proxied session.
    // In the proxy-less branch a persisted proxy value does survive, and is
    // inert — `egress.default = deny` and `host_loopback = deny`. Residual risk,
    // accepted: other profile-persisted variables (e.g. a CA-bundle override) do
    // reach the child; filesystem and network policy, not env, are the
    // containment boundary. `NO_PROXY` needs no exception here — the wrapper
    // supplies it (D1).
    request.inherit_default_environment = Some(true);
    Ok(request)
}

// ---------------------------------------------------------------------------
// Launch
// ---------------------------------------------------------------------------

/// The `processcontainer` backend for one launch.
///
/// It carries the launch context — the proof source, the proxy port it listens
/// on, the wrapper launcher and the run budget — so a request cannot be built
/// against a proxy this backend does not own (D4).
pub struct MxcBackend<'a> {
    proof: Option<&'a dyn ProxyProofSource>,
    proxy_port: Option<u16>,
    /// `None` when this backend has no budget of its own, so the caller's
    /// [`MxcSessionInput::timeout_ms`] ships untouched. `Some(budget)` is an
    /// explicit decision — including `Some(None)`, which means "no deadline" —
    /// and wins over the caller's value.
    budget: Option<Option<u32>>,
    launcher: PathBuf,
}

impl<'a> MxcBackend<'a> {
    /// A backend for one launch on `proxy_port`, proofed by `proof`.
    pub fn new(
        proof: &'a dyn ProxyProofSource,
        proxy_port: Option<u16>,
        launcher: impl Into<PathBuf>,
    ) -> Self {
        Self {
            proof: Some(proof),
            proxy_port,
            budget: None,
            launcher: launcher.into(),
        }
    }

    /// A backend with no proof source: every launch is refused by guardrail 1
    /// with [`GuardError::MissingProofSource`]. Exists so that refusal is
    /// expressible rather than accidental.
    pub fn without_proof_source(proxy_port: Option<u16>, launcher: impl Into<PathBuf>) -> Self {
        Self {
            proof: None,
            proxy_port,
            budget: None,
            launcher: launcher.into(),
        }
    }

    /// Set the wall-clock budget for the whole workload, in milliseconds.
    ///
    /// `Some(ms)` is a deadline and `None` explicitly asks for **no** deadline;
    /// either way the budget wins over the caller's
    /// [`MxcSessionInput::timeout_ms`]. A backend that never calls this leaves
    /// the caller's deadline in force. P2.1 owns the real arithmetic.
    pub fn with_budget(mut self, timeout_ms: Option<u32>) -> Self {
        self.budget = Some(timeout_ms);
        self
    }

    /// The port this backend's proxy listens on.
    pub fn proxy_port(&self) -> Option<u16> {
        self.proxy_port
    }

    /// The wrapper launcher this backend launches.
    pub fn launcher(&self) -> &Path {
        &self.launcher
    }

    /// The request this backend would launch for `input`.
    ///
    /// The backend's own proxy port, launcher and budget replace whatever the
    /// caller's input carried: the request must describe the launch that is
    /// actually about to happen, or guardrail 1 would attribute traffic to the
    /// wrong place.
    ///
    /// The budget is replaced only when this backend was given one explicitly
    /// ([`with_budget`](MxcBackend::with_budget)). Overwriting it
    /// unconditionally would discard every caller-supplied deadline — and since
    /// `None` means "no deadline", the workload would then run unbounded.
    ///
    /// Returns [`RequestError`] (wrapped in [`MxcError`]) for a command line that
    /// cannot be launched; see [`build_request`].
    pub fn request_for(&self, input: &MxcSessionInput) -> Result<ContainerRequest, MxcError> {
        let mut effective = input.clone();
        effective.network.proxy_port = self.proxy_port;
        if let Some(budget) = self.budget {
            effective.timeout_ms = budget;
        }
        Ok(build_request(&effective, &self.launcher)?)
    }

    /// Run a short-lived command to completion inside a ProcessContainer.
    ///
    /// Order is the contract: resolve the proof source (refuse early if there is
    /// none), build the request, refuse an unsatisfiable expectation, probe the
    /// tier of the exact request, run inside a launch epoch, then apply
    /// guardrail 1 to that epoch's counters. There is no path from `v1::run`
    /// returning `Ok` to a success without the gate passing.
    ///
    /// `expectation` is the caller's declaration of what the session's network
    /// posture demands — see [`ProofExpectation`].
    pub fn launch(
        &self,
        input: &MxcSessionInput,
        expectation: ProofExpectation,
    ) -> Result<SessionOutcome, MxcError> {
        let source = self
            .proof
            .ok_or(MxcError::Guard(GuardError::MissingProofSource))?;

        let request = self.request_for(input)?;

        // D3: a network expectation without a proxy cannot be satisfied by any
        // run, so refuse before the child starts instead of failing a launch
        // that could never have proven anything.
        if expectation == ProofExpectation::Required && self.proxy_port.is_none() {
            return Err(MxcError::Guard(GuardError::RequiredWithoutProxy));
        }

        // Guardrail 2 on the exact request that is about to be launched: not a
        // lookalike, and not the backend ceiling (which policy can lower).
        let tier = probe_tier(&request)?;

        // The epoch is opened before the child starts, so guardrail 1 cannot be
        // satisfied by traffic from an earlier launch, and it is closed on every
        // path out of the run (success, SDK error, panic unwind).
        let (exec, proof) = run_in_epoch(source, || {
            v1::run(request, RunOptions::default()).map_err(MxcError::from)
        })?;

        gate_outcome(
            tier,
            ChildRun {
                wait: exec.outcome,
                stdout: exec.stdout,
                stderr: exec.stderr,
                warnings: exec.warnings,
            },
            proof,
            expectation,
        )
    }
}

/// Apply guardrail 1 to a finished child and map it into a [`SessionOutcome`].
///
/// Pure on purpose: this is the one place a proof can turn into a success or an
/// error, so it can be tested with the spike's observed outcomes without
/// spawning a container.
fn gate_outcome(
    tier: TierRecord,
    child: ChildRun,
    proof: ProxyProof,
    expectation: ProofExpectation,
) -> Result<SessionOutcome, MxcError> {
    // Guardrail 1 first and unconditionally: `warnings: []` and exit 0 are not
    // evidence, so a failed proof poisons every outcome, timeout included.
    verify_proxy_proof(proof, expectation)?;

    let (exit_code, timed_out) = match child.wait {
        WaitResult::Exited(code) => (Some(code), false),
        WaitResult::TimedOut => (None, true),
    };

    Ok(SessionOutcome {
        exit_code,
        timed_out,
        stdout: child.stdout,
        stderr: child.stderr,
        warnings: child.warnings,
        tier,
        proxy_proof: proof,
        expectation,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Stand-in launcher path: the mapping is pure, so it never has to exist.
    const TEST_LAUNCHER: &str = r"C:\tools\sandbox\mxc-launch.exe";

    fn build(input: &MxcSessionInput) -> ContainerRequest {
        build_request(input, Path::new(TEST_LAUNCHER)).expect("launchable request")
    }

    fn input() -> MxcSessionInput {
        MxcSessionInput {
            command: "cmd /c echo hi".to_string(),
            working_directory: Some(r"C:\work".to_string()),
            environment: vec![
                ("PATH".to_string(), r"C:\Windows".to_string()),
                ("TEMP".to_string(), r"C:\Temp".to_string()),
            ],
            filesystem: MxcFilesystemInput {
                readwrite_paths: vec![r"C:\work".to_string()],
                readonly_paths: vec![r"C:\ref".to_string()],
                denied_paths: vec![r"C:\Users\marku\.ssh".to_string()],
            },
            network: MxcNetworkInput {
                proxy_port: Some(54_321),
            },
            timeout_ms: Some(60_000),
        }
    }

    fn tier() -> TierRecord {
        TierRecord {
            tier: Some("base-container".to_string()),
            tier_source: "probe",
            needs_dacl_augmentation: Some(false),
        }
    }

    fn child(wait: WaitResult) -> ChildRun {
        ChildRun {
            wait,
            stdout: b"hi\n".to_vec(),
            stderr: Vec::new(),
            warnings: Vec::new(),
        }
    }

    fn proven() -> ProxyProof {
        ProxyProof {
            accepted: 1,
            tunnels: 1,
        }
    }

    fn untouched() -> ProxyProof {
        ProxyProof {
            accepted: 0,
            tunnels: 0,
        }
    }

    // ---- D1: launcher command construction -------------------------------

    #[test]
    fn launcher_command_puts_the_real_command_line_behind_the_wrapper() {
        let command = launcher_command(Path::new(TEST_LAUNCHER), "cmd /c echo hi");
        assert_eq!(
            command,
            format!(r#"{TEST_LAUNCHER} -- "cmd /c echo hi""#),
            "the real command line must travel as ONE quoted argument"
        );
    }

    #[test]
    fn launcher_command_quotes_a_launcher_path_with_spaces() {
        let command = launcher_command(Path::new(r"C:\Program Files\sb\mxc-launch.exe"), "x.exe");
        assert_eq!(command, r#""C:\Program Files\sb\mxc-launch.exe" -- x.exe"#);
    }

    #[test]
    fn launcher_command_survives_a_command_line_that_contains_quotes() {
        let real = r#"powershell.exe -Command "Start-Sleep -Seconds 1""#;
        let command = launcher_command(Path::new(TEST_LAUNCHER), real);
        assert_eq!(
            command,
            format!(r#"{TEST_LAUNCHER} -- "powershell.exe -Command \"Start-Sleep -Seconds 1\"""#)
        );
    }

    /// A golden-string test, **not** a round trip: it pins the exact text the
    /// quoting algorithm emits for each shape. A round-trip claim needs a parser
    /// (`shell32!CommandLineToArgvW`) this test does not call. The algorithm was
    /// fuzz-verified against that real parser at review time — 200k generated
    /// inputs, argv compared element by element, zero differences — so this test
    /// exists to catch an *edit* to the algorithm, not to re-prove its
    /// correctness.
    #[test]
    fn quoting_matches_the_documented_argv_rules() {
        assert_eq!(quote_windows_arg("simple"), "simple");
        assert_eq!(quote_windows_arg("a b"), "\"a b\"");
        assert_eq!(quote_windows_arg(""), "\"\"");
        // A quote inside the element is escaped, not dropped.
        assert_eq!(quote_windows_arg("a\"b"), "\"a\\\"b\"");
        // Backslashes before a quote are doubled; trailing ones before the
        // closing quote are doubled as well.
        assert_eq!(quote_windows_arg("a\\\"b"), "\"a\\\\\\\"b\"");
        assert_eq!(quote_windows_arg("a b\\"), "\"a b\\\\\"");
        assert_eq!(quote_windows_arg("a\\"), "a\\");
    }

    #[test]
    fn an_empty_command_is_refused_before_a_request_exists() {
        for blank in ["", "   ", "\t\n"] {
            let mut i = input();
            i.command = blank.to_string();
            assert_eq!(
                build_request(&i, Path::new(TEST_LAUNCHER)).expect_err("empty command"),
                RequestError::EmptyCommand,
                "{blank:?} must not become a container command"
            );
        }
    }

    #[test]
    fn a_nul_in_the_command_is_refused_before_a_request_exists() {
        let mut i = input();
        // This is what would silently become `cmd /c echo hi` for the child:
        // CreateProcessW stops at the NUL.
        i.command = "cmd /c echo hi\0 --injected".to_string();
        assert_eq!(
            build_request(&i, Path::new(TEST_LAUNCHER)).expect_err("NUL command"),
            RequestError::NulInCommand,
            "a NUL would truncate the command line at the OS boundary"
        );
    }

    #[test]
    fn request_for_reports_a_refused_command_as_a_typed_error() {
        let source = RecordingSource::default();
        let backend = MxcBackend::new(&source, Some(49_152), TEST_LAUNCHER);
        let mut i = input();
        i.command = "  ".to_string();

        let err = backend.request_for(&i).expect_err("empty command");
        assert!(
            matches!(err, MxcError::Request(RequestError::EmptyCommand)),
            "got {err:?}"
        );
        // `launch` surfaces this text, so it must name the cause.
        assert!(err.to_string().contains("empty"), "got {err}");
    }

    #[test]
    fn the_launcher_directory_is_the_grant_a_caller_must_declare() {
        assert_eq!(
            launcher_grant(Path::new(TEST_LAUNCHER)).as_deref(),
            Some(r"C:\tools\sandbox")
        );
        assert_eq!(
            launcher_grant(Path::new("mxc-launch.exe")),
            None,
            "a bare file name has no directory to grant"
        );
    }

    // ---- P0.2: request mapping -------------------------------------------

    #[test]
    fn request_carries_working_directory_and_timeout() {
        let req = build(&input());
        assert_eq!(req.working_directory.as_deref(), Some(r"C:\work"));
        assert_eq!(req.timeout_ms, Some(60_000));
    }

    #[test]
    fn request_command_is_the_wrapper_not_the_workload() {
        let req = build(&input());
        assert_eq!(
            req.command,
            launcher_command(Path::new(TEST_LAUNCHER), "cmd /c echo hi")
        );
        assert_ne!(req.command, "cmd /c echo hi");
        assert!(req.command.starts_with(TEST_LAUNCHER));
        assert!(
            req.command.ends_with(r#"-- "cmd /c echo hi""#),
            "the workload command line is the wrapper's single argument: {}",
            req.command
        );
    }

    #[test]
    fn request_selects_process_container_without_a_proxy_peer() {
        let req = build(&input());
        let Containment::ProcessContainer(cfg) = &req.containment else {
            panic!(
                "expected Containment::ProcessContainer, got {:?}",
                req.containment
            );
        };
        // Identity-less deployment: allowedProxyPeer must stay unset, otherwise
        // the request is refused with `malformed_request`.
        assert!(
            cfg.network
                .as_ref()
                .and_then(|n| n.allowed_proxy_peer.as_ref())
                .is_none(),
            "allowedProxyPeer must never be set for an unpackaged proxy"
        );
    }

    #[test]
    fn request_denies_egress_by_default_and_routes_through_loopback_proxy() {
        let req = build(&input());
        let net = req.network.as_ref().expect("network policy");
        let egress = net.egress.as_ref().expect("egress");
        assert_eq!(egress.default, Some(NetworkAction::Deny));
        let ingress = net.ingress.as_ref().expect("ingress");
        assert_eq!(ingress.default, Some(NetworkAction::Allow));
        assert_eq!(ingress.host_loopback, Some(NetworkAction::Allow));
        let runtime = net.runtime_config.as_ref().expect("runtime config");
        assert_eq!(
            runtime.network_proxy.as_deref(),
            Some("http://127.0.0.1:54321")
        );
    }

    #[test]
    fn request_without_a_proxy_keeps_loopback_closed() {
        let mut i = input();
        i.network.proxy_port = None;
        let req = build(&i);
        let net = req.network.as_ref().expect("network policy");
        assert_eq!(
            net.egress.as_ref().and_then(|e| e.default),
            Some(NetworkAction::Deny)
        );
        let ingress = net.ingress.as_ref().expect("ingress");
        assert_eq!(ingress.host_loopback, Some(NetworkAction::Deny));
        assert!(
            net.runtime_config
                .as_ref()
                .and_then(|r| r.network_proxy.as_deref())
                .is_none(),
            "no proxy port => no networkProxy"
        );
    }

    /// Invariant 5 / ADR-0004: the host's proxy environment must never cross
    /// into the container. MXC injects its own proxy env; a host value would
    /// point the child at a proxy we do not control.
    #[test]
    fn host_proxy_env_is_never_copied_into_the_request() {
        let mut i = input();
        i.environment = vec![
            ("PATH".to_string(), r"C:\Windows".to_string()),
            (
                "HTTP_PROXY".to_string(),
                "http://host-proxy:3128".to_string(),
            ),
            (
                "HTTPS_PROXY".to_string(),
                "http://host-proxy:3128".to_string(),
            ),
            (
                "ALL_PROXY".to_string(),
                "socks5://host-proxy:1080".to_string(),
            ),
            ("NO_PROXY".to_string(), "example.com".to_string()),
            (
                "http_proxy".to_string(),
                "http://lower-host-proxy:3128".to_string(),
            ),
            (
                "https_proxy".to_string(),
                "http://lower-host-proxy:3128".to_string(),
            ),
            (
                "all_proxy".to_string(),
                "socks5://lower-host-proxy:1080".to_string(),
            ),
            ("no_proxy".to_string(), "localhost".to_string()),
            (
                "Http_Proxy".to_string(),
                "http://mixed-host-proxy:3128".to_string(),
            ),
        ];
        let req = build(&i);
        let env = req.environment.as_ref().expect("explicit environment list");
        // Explicit set equality, not a re-run of the production predicate: this
        // fails for a leaked key *and* for a key the filter wrongly drops.
        let mut surviving: Vec<&str> = env.iter().map(|(key, _)| key.as_str()).collect();
        surviving.sort_unstable();
        assert_eq!(surviving, ["PATH"], "exact surviving key set: {env:?}");
        // The allow-list still carries the legitimate entry, value included.
        assert!(env.iter().any(|(k, v)| k == "PATH" && v == r"C:\Windows"));
        assert_eq!(env.len(), 1, "only PATH should survive: {env:?}");
    }

    #[test]
    fn environment_is_always_an_explicit_list_never_none() {
        let mut i = input();
        i.environment.clear();
        let req = build(&i);
        assert_eq!(
            req.environment,
            Some(Vec::new()),
            "an empty allow-list must be explicit, not `None` (backend default)"
        );
        // D2: the profile default block is kept deliberately — the SDK strips
        // every proxy name from it before injecting ours.
        assert_eq!(req.inherit_default_environment, Some(true));
    }

    #[test]
    fn filesystem_grants_pass_through_unchanged() {
        let req = build(&input());
        let fs = req.filesystem.as_ref().expect("filesystem policy");
        assert_eq!(fs.readwrite_paths, vec![r"C:\work".to_string()]);
        assert_eq!(fs.readonly_paths, vec![r"C:\ref".to_string()]);
        assert_eq!(fs.denied_paths, vec![r"C:\Users\marku\.ssh".to_string()]);
    }

    // ---- D6: the config posture is pinned, not defaulted ------------------

    #[test]
    fn process_container_config_pins_every_field_explicitly() {
        let cfg = process_container_config();
        assert!(!cfg.learning_mode);
        assert!(cfg.capabilities.is_empty());
        assert!(cfg.capture_denials.is_none());
        assert!(cfg.filesystem.is_none());
        assert!(cfg.network.is_none());

        let ui = cfg.ui.expect("the ui posture is always stated");
        assert_eq!(ui.isolation, ProcessContainerUiIsolation::Container);
        assert!(!ui.desktop_system_control);
        assert_eq!(ui.system_settings, ProcessContainerSystemSettings::None);
        assert!(!ui.ime);
    }

    /// Drift alarm, not a tautology: it fails when a patch bump changes a
    /// `#[non_exhaustive]` default we pinned, which is the moment to re-decide
    /// the posture instead of silently inheriting the new one.
    #[test]
    fn pinned_ui_fields_match_the_sdk_default_they_were_taken_from() {
        let sdk = ProcessContainerConfig::default();
        let pinned = process_container_config();
        assert_eq!(pinned.ui, sdk.ui);
        assert_eq!(pinned.capabilities, sdk.capabilities);
        assert_eq!(pinned.capture_denials, sdk.capture_denials);
    }

    // ---- P0.3 / D3: guardrail 1, both legs -------------------------------

    /// `Required` + pass.
    #[test]
    fn required_passes_when_the_child_reached_the_proxy_and_a_tunnel_was_established() {
        verify_proxy_proof(proven(), ProofExpectation::Required).expect("accepted=1 tunnels=1");
        verify_proxy_proof(
            ProxyProof {
                accepted: 3,
                tunnels: 2,
            },
            ProofExpectation::Required,
        )
        .expect("more traffic than the minimum is fine");
    }

    /// `Required` + fail (two distinct shapes, two distinct errors).
    #[test]
    fn required_fails_without_an_accepted_session_or_without_a_tunnel() {
        assert_eq!(
            verify_proxy_proof(untouched(), ProofExpectation::Required).expect_err("accepted=0"),
            GuardError::SessionNotAccepted
        );
        // The structural case the spike proved matters: proxy 502 (unresolvable
        // target) and loopback-denied both give accepted=1, tunnels=0.
        assert_eq!(
            verify_proxy_proof(
                ProxyProof {
                    accepted: 1,
                    tunnels: 0,
                },
                ProofExpectation::Required
            )
            .expect_err("tunnels=0"),
            GuardError::TunnelNotEstablished
        );
    }

    /// `MustBeAbsent` + pass.
    #[test]
    fn must_be_absent_passes_only_when_the_proxy_was_never_consulted() {
        verify_proxy_proof(untouched(), ProofExpectation::MustBeAbsent)
            .expect("a blocked session that never reached the proxy is the proven case");
    }

    /// `MustBeAbsent` + fail.
    #[test]
    fn must_be_absent_fails_as_soon_as_the_proxy_is_consulted() {
        for proof in [
            ProxyProof {
                accepted: 1,
                tunnels: 0,
            },
            ProxyProof {
                accepted: 1,
                tunnels: 1,
            },
        ] {
            assert_eq!(
                verify_proxy_proof(proof, ProofExpectation::MustBeAbsent)
                    .expect_err("a consulted proxy must fail an offline session"),
                GuardError::ProxyConsultedUnexpectedly,
                "accepted={} tunnels={}",
                proof.accepted,
                proof.tunnels
            );
        }
    }

    #[test]
    fn the_expectation_follows_the_network_posture() {
        assert_eq!(
            ProofExpectation::for_network(Some(8080)),
            ProofExpectation::Required
        );
        assert_eq!(
            ProofExpectation::for_network(None),
            ProofExpectation::MustBeAbsent
        );
    }

    #[test]
    fn all_four_expectation_combinations_are_decided_by_the_gate() {
        // required+pass, required+fail, absent+pass, absent+fail.
        let cases = [
            (ProofExpectation::Required, proven(), true),
            (
                ProofExpectation::Required,
                ProxyProof {
                    accepted: 1,
                    tunnels: 0,
                },
                false,
            ),
            (ProofExpectation::MustBeAbsent, untouched(), true),
            (
                ProofExpectation::MustBeAbsent,
                ProxyProof {
                    accepted: 0,
                    tunnels: 1,
                },
                false,
            ),
        ];
        for (expectation, proof, should_pass) in cases {
            assert_eq!(
                verify_proxy_proof(proof, expectation).is_ok(),
                should_pass,
                "{expectation:?} with accepted={} tunnels={}",
                proof.accepted,
                proof.tunnels
            );
        }
    }

    /// The silent-misconfiguration case: the SDK reported exit 0 with no
    /// warnings, yet no tunnel was established. Success must be impossible.
    #[test]
    fn exited_zero_without_a_tunnel_is_an_error() {
        let err = gate_outcome(
            tier(),
            child(WaitResult::Exited(0)),
            ProxyProof {
                accepted: 1,
                tunnels: 0,
            },
            ProofExpectation::Required,
        )
        .expect_err("exit 0 must not mask a failed proof");
        assert!(matches!(
            err,
            MxcError::Guard(GuardError::TunnelNotEstablished)
        ));
    }

    #[test]
    fn exited_zero_with_a_proven_tunnel_is_a_success() {
        let outcome = gate_outcome(
            tier(),
            child(WaitResult::Exited(0)),
            proven(),
            ProofExpectation::Required,
        )
        .expect("proven launch");
        assert!(outcome.success());
        assert_eq!(outcome.exit_code, Some(0));
        assert!(!outcome.timed_out);
        assert_eq!(outcome.stdout, b"hi\n");
        assert!(outcome.stderr.is_empty());
        // Container warnings are carried for the audit trail, never as evidence
        // of reachability (ADR-0004): the proof below is what gates the launch.
        assert!(outcome.warnings.is_empty());
        assert_eq!(outcome.proxy_proof, proven());
        assert_eq!(outcome.expectation, ProofExpectation::Required);
        assert_eq!(outcome.tier.tier.as_deref(), Some("base-container"));
    }

    #[test]
    fn an_offline_session_that_stayed_offline_is_a_success() {
        let outcome = gate_outcome(
            tier(),
            child(WaitResult::Exited(0)),
            untouched(),
            ProofExpectation::MustBeAbsent,
        )
        .expect("a blocked session that never reached the proxy");
        assert!(outcome.success());
        assert_eq!(outcome.expectation, ProofExpectation::MustBeAbsent);
    }

    /// Hand-built success shape (exit 0, no timeout) with an unproven launch:
    /// `success()` must consult the proof, for either leg.
    #[test]
    fn success_shaped_outcome_without_a_proof_is_not_a_success() {
        let cases = [
            (ProofExpectation::Required, untouched()),
            (
                ProofExpectation::Required,
                ProxyProof {
                    accepted: 1,
                    tunnels: 0,
                },
            ),
            (
                ProofExpectation::MustBeAbsent,
                ProxyProof {
                    accepted: 1,
                    tunnels: 0,
                },
            ),
        ];
        for (expectation, proof) in cases {
            let outcome = SessionOutcome {
                exit_code: Some(0),
                timed_out: false,
                stdout: Vec::new(),
                stderr: Vec::new(),
                warnings: Vec::new(),
                tier: tier(),
                proxy_proof: proof,
                expectation,
            };
            assert!(
                !outcome.success(),
                "an unproven outcome ({expectation:?}, accepted={}, tunnels={}) must never \
                 report success",
                proof.accepted,
                proof.tunnels
            );
        }
    }

    #[test]
    fn non_zero_exit_is_carried_through_and_is_not_a_success() {
        let outcome = gate_outcome(
            tier(),
            child(WaitResult::Exited(3)),
            proven(),
            ProofExpectation::Required,
        )
        .expect("proven launch");
        assert_eq!(outcome.exit_code, Some(3));
        assert!(!outcome.success());
    }

    #[test]
    fn timed_out_child_maps_to_no_exit_code() {
        let outcome = gate_outcome(
            tier(),
            child(WaitResult::TimedOut),
            proven(),
            ProofExpectation::Required,
        )
        .expect("proven launch");
        assert!(outcome.timed_out);
        assert_eq!(outcome.exit_code, None);
        assert!(!outcome.success());
    }

    #[test]
    fn a_failed_proof_fails_even_a_timed_out_child() {
        let err = gate_outcome(
            tier(),
            child(WaitResult::TimedOut),
            untouched(),
            ProofExpectation::Required,
        )
        .expect_err("proof gate applies to every outcome");
        assert!(matches!(
            err,
            MxcError::Guard(GuardError::SessionNotAccepted)
        ));
    }

    #[test]
    fn launch_without_a_proof_source_is_an_error_before_the_child_starts() {
        let err = MxcBackend::without_proof_source(Some(54_321), TEST_LAUNCHER)
            .launch(&input(), ProofExpectation::Required)
            .expect_err("no proof source must refuse the launch");
        assert!(
            matches!(err, MxcError::Guard(GuardError::MissingProofSource)),
            "got {err:?}"
        );
    }

    // ---- D4: backend state + epoch lifecycle ----------------------------

    #[derive(Default)]
    struct RecordingSource {
        next: AtomicU64,
        epochs: Mutex<Vec<u64>>,
        /// `(epoch, proof reads at close time)` — the read-then-close order is
        /// part of the contract, so it is recorded rather than assumed.
        closes: Mutex<Vec<(u64, u64)>>,
        reads: AtomicU64,
        proofs: Mutex<HashMap<u64, ProxyProof>>,
    }

    impl RecordingSource {
        fn set_proof(&self, epoch: u64, proof: ProxyProof) {
            self.proofs.lock().unwrap().insert(epoch, proof);
        }

        fn epochs(&self) -> Vec<u64> {
            self.epochs.lock().unwrap().clone()
        }

        fn closes(&self) -> Vec<(u64, u64)> {
            self.closes.lock().unwrap().clone()
        }
    }

    impl ProxyProofSource for RecordingSource {
        fn begin_launch(&self) -> u64 {
            let epoch = self.next.fetch_add(1, Ordering::SeqCst) + 1;
            self.epochs.lock().unwrap().push(epoch);
            epoch
        }

        fn proof(&self, epoch: u64) -> ProxyProof {
            self.reads.fetch_add(1, Ordering::SeqCst);
            self.proofs
                .lock()
                .unwrap()
                .get(&epoch)
                .copied()
                .unwrap_or_default()
        }

        fn close_launch(&self, epoch: u64) {
            let reads = self.reads.load(Ordering::SeqCst);
            self.closes.lock().unwrap().push((epoch, reads));
        }
    }

    #[test]
    fn a_successful_run_opens_one_epoch_and_closes_it_after_reading_the_proof() {
        let source = RecordingSource::default();
        let (value, proof) = run_in_epoch(&source, || Ok::<_, MxcError>(7)).expect("body ran");
        assert_eq!(value, 7);
        assert_eq!(proof, untouched());
        assert_eq!(source.epochs(), vec![1]);
        // Closed exactly once, and only after the counters were read.
        assert_eq!(source.closes(), vec![(1, 1)]);
    }

    /// The defect D4 names: a `run` error must not abandon an open epoch.
    #[test]
    fn a_failed_run_still_closes_the_epoch() {
        let source = RecordingSource::default();
        let err = run_in_epoch(&source, || {
            Err::<(), _>(MxcError::Guard(GuardError::SessionNotAccepted))
        })
        .expect_err("body failed");
        assert!(matches!(
            err,
            MxcError::Guard(GuardError::SessionNotAccepted)
        ));
        assert_eq!(source.epochs(), vec![1], "the epoch was opened");
        assert_eq!(
            source.closes().len(),
            1,
            "the epoch must be closed on the error path too: {:?}",
            source.closes()
        );
        assert_eq!(source.closes()[0].0, 1);
    }

    #[test]
    fn the_body_runs_while_the_epoch_is_open() {
        let source = RecordingSource::default();
        run_in_epoch(&source, || {
            assert_eq!(source.epochs(), vec![1], "opened before the child starts");
            assert!(
                source.closes().is_empty(),
                "not closed before the child ends"
            );
            Ok::<_, MxcError>(())
        })
        .expect("body ran");
    }

    #[test]
    fn a_panic_in_the_body_still_closes_the_epoch() {
        let source = RecordingSource::default();
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            run_in_epoch(&source, || -> Result<(), MxcError> { panic!("sdk bug") })
        }));
        assert!(outcome.is_err(), "the panic propagates");
        assert_eq!(
            source.closes().len(),
            1,
            "the guard closes the epoch while unwinding: {:?}",
            source.closes()
        );
    }

    /// `close_launch` is caller-supplied. A panic out of `EpochGuard::drop`
    /// while the body is already unwinding would abort the process; the guard
    /// catches it and lets the body's panic continue.
    #[test]
    fn a_panicking_close_does_not_abort_the_unwind() {
        struct PanickyClose;

        impl ProxyProofSource for PanickyClose {
            fn begin_launch(&self) -> u64 {
                1
            }

            fn proof(&self, _epoch: u64) -> ProxyProof {
                untouched()
            }

            fn close_launch(&self, _epoch: u64) {
                panic!("close_launch blew up");
            }
        }

        let source = PanickyClose;
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            run_in_epoch(&source, || -> Result<(), MxcError> { panic!("sdk bug") })
        }));
        assert!(
            outcome.is_err(),
            "the body's panic still propagates; the close's panic was swallowed"
        );
    }

    #[test]
    fn a_new_epoch_does_not_inherit_an_earlier_launch_traffic() {
        let source = RecordingSource::default();
        let first = source.begin_launch();
        source.set_proof(first, proven());
        let (_, proof) = run_in_epoch(&source, || Ok::<_, MxcError>(())).expect("body ran");
        assert_eq!(
            proof,
            untouched(),
            "epoch 2 starts empty even though epoch 1 saw a tunnel"
        );
    }

    #[test]
    fn nothing_is_opened_when_the_launch_is_refused_up_front() {
        // No proof source at all.
        let _ = MxcBackend::without_proof_source(Some(54_321), TEST_LAUNCHER)
            .launch(&input(), ProofExpectation::Required);

        // Unsatisfiable expectation: `Required` with no proxy port.
        let source = RecordingSource::default();
        let err = MxcBackend::new(&source, None, TEST_LAUNCHER)
            .launch(&input(), ProofExpectation::Required)
            .expect_err("Required without a proxy can never pass");
        assert!(
            matches!(err, MxcError::Guard(GuardError::RequiredWithoutProxy)),
            "got {err:?}"
        );
        assert!(
            source.epochs().is_empty(),
            "an unsatisfiable expectation must be refused before the child starts"
        );
        assert!(source.closes().is_empty());
    }

    #[test]
    fn the_backend_owns_the_proxy_port_and_the_budget() {
        let source = RecordingSource::default();
        let backend =
            MxcBackend::new(&source, Some(49_152), TEST_LAUNCHER).with_budget(Some(1_000));
        let mut i = input();
        i.network.proxy_port = Some(1); // a caller-supplied lookalike
        i.timeout_ms = Some(999_999);

        let req = backend.request_for(&i).expect("launchable request");
        assert_eq!(
            req.network
                .as_ref()
                .and_then(|n| n.runtime_config.as_ref())
                .and_then(|r| r.network_proxy.as_deref()),
            Some("http://127.0.0.1:49152"),
            "the request must point at the proxy this backend proves"
        );
        assert_eq!(req.timeout_ms, Some(1_000), "the backend's budget wins");
        assert_eq!(backend.proxy_port(), Some(49_152));
        assert_eq!(backend.launcher(), Path::new(TEST_LAUNCHER));
    }

    #[test]
    fn a_caller_supplied_timeout_survives_a_backend_with_no_budget() {
        let source = RecordingSource::default();
        // No `with_budget`: this backend has no opinion, so the caller's
        // deadline is the one that must ship. Overwriting it with `None` would
        // have discarded it *and* removed the deadline (None = no deadline).
        let backend = MxcBackend::new(&source, Some(49_152), TEST_LAUNCHER);
        let mut i = input();
        i.timeout_ms = Some(1_500);

        let req = backend.request_for(&i).expect("launchable request");
        assert_eq!(
            req.timeout_ms,
            Some(1_500),
            "an unset backend budget must not discard the caller's deadline"
        );
    }

    #[test]
    fn an_explicit_budget_wins_over_the_caller_timeout_in_both_directions() {
        let source = RecordingSource::default();
        let mut i = input();
        i.timeout_ms = Some(999_999);

        let capped = MxcBackend::new(&source, Some(49_152), TEST_LAUNCHER).with_budget(Some(250));
        assert_eq!(
            capped
                .request_for(&i)
                .expect("launchable request")
                .timeout_ms,
            Some(250),
            "an explicit budget narrows the caller's deadline"
        );

        // `with_budget(None)` is a decision ("no deadline"), not a missing value.
        let unbounded = MxcBackend::new(&source, Some(49_152), TEST_LAUNCHER).with_budget(None);
        assert_eq!(
            unbounded
                .request_for(&i)
                .expect("launchable request")
                .timeout_ms,
            None,
            "an explicit `None` budget must win over a caller-supplied timeout"
        );
    }

    #[test]
    fn the_backend_and_its_proof_source_are_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>(_: &T) {}
        fn assert_trait_object(_: &(dyn ProxyProofSource + Send + Sync)) {}

        let source = RecordingSource::default();
        let backend = MxcBackend::new(&source, Some(1), TEST_LAUNCHER);
        assert_send_sync(&backend);
        assert_send_sync(&source);
        assert_trait_object(&source);
    }

    // ---- P0.4: guardrail 2 ----------------------------------------------

    #[test]
    fn a_probed_tier_is_recorded_with_source_probe() {
        let record = tier_record(ProbeView {
            tier: Some("base-container"),
            needs_dacl_augmentation: Some(false),
        });
        assert_eq!(record.tier.as_deref(), Some("base-container"));
        assert_eq!(record.tier_source, "probe");
        assert_eq!(record.needs_dacl_augmentation, Some(false));
    }

    #[test]
    fn dacl_augmentation_is_recorded_when_the_probe_reports_it() {
        let record = tier_record(ProbeView {
            tier: Some("appcontainer-dacl"),
            needs_dacl_augmentation: Some(true),
        });
        assert_eq!(record.tier.as_deref(), Some("appcontainer-dacl"));
        assert_eq!(record.needs_dacl_augmentation, Some(true));
    }

    #[test]
    fn an_unnameable_tier_is_recorded_as_unavailable_not_as_a_ceiling() {
        let record = tier_record(ProbeView {
            tier: None,
            needs_dacl_augmentation: None,
        });
        assert_eq!(record.tier, None);
        assert_eq!(record.tier_source, "unavailable");
        // A probe that declined to state it must not be recorded as `false`.
        assert_eq!(record.needs_dacl_augmentation, None);
    }

    // ---- environment filter ---------------------------------------------

    #[test]
    fn blocked_env_keys_match_case_insensitively_and_only_proxy_vars() {
        for key in [
            "HTTP_PROXY",
            "https_proxy",
            "All_Proxy",
            "no_proxy",
            " HTTP_PROXY ",
        ] {
            assert!(is_blocked_env_key(key), "{key} must be blocked");
        }
        for key in ["PATH", "HTTP_PROXYX", "PROXY", "APPDATA"] {
            assert!(!is_blocked_env_key(key), "{key} must not be blocked");
        }
    }
}

// ---------------------------------------------------------------------------
// Live evidence: a real, unelevated ProcessContainer (ignored by default)
// ---------------------------------------------------------------------------

/// The intent-endpoint proof lives here rather than under `tests/` because this
/// crate has no library target: an integration test cannot import
/// [`MxcBackend`], so the only place a real container can be launched from is a
/// test module inside the crate. It is `#[ignore]`d so the normal suite stays
/// fast:
///
/// ```text
/// cargo build --features mxc-backend --bin mxc-launch
/// cargo test  --features mxc-backend -- --ignored
/// ```
///
/// Nothing here needs elevation, and nothing here mutates host state: the
/// container's filesystem policy is a grant *inside* the container, and the
/// scratch directory removes itself.
#[cfg(test)]
mod live {
    use super::*;
    use std::collections::HashMap;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    /// What the fake endpoint and the proof source share.
    #[derive(Default)]
    struct Shared {
        epoch: AtomicU64,
        counters: Mutex<HashMap<u64, ProxyProof>>,
        closes: Mutex<Vec<u64>>,
        /// `(epoch, request line)` for origin-form requests: a client dialled the
        /// endpoint directly, which is what NO_PROXY is supposed to cause.
        origin: Mutex<Vec<(u64, String)>>,
        /// `(epoch, request line)` for proxy consultations (`CONNECT` or an
        /// absolute-form request).
        proxied: Mutex<Vec<(u64, String)>>,
    }

    struct LiveProof {
        shared: Arc<Shared>,
    }

    impl LiveProof {
        fn last_epoch(&self) -> u64 {
            self.shared.epoch.load(Ordering::SeqCst)
        }
    }

    impl ProxyProofSource for LiveProof {
        fn begin_launch(&self) -> u64 {
            let epoch = self.shared.epoch.fetch_add(1, Ordering::SeqCst) + 1;
            self.shared
                .counters
                .lock()
                .unwrap()
                .insert(epoch, ProxyProof::default());
            epoch
        }

        fn proof(&self, epoch: u64) -> ProxyProof {
            self.shared
                .counters
                .lock()
                .unwrap()
                .get(&epoch)
                .copied()
                .unwrap_or_default()
        }

        fn close_launch(&self, epoch: u64) {
            self.shared.closes.lock().unwrap().push(epoch);
        }
    }

    /// One loopback listener that is **both** the supervisor's proxy (it refuses
    /// loopback targets, as the real one does) and the intent endpoint. Serving
    /// both on one port is what lets the test tell the two apart.
    struct Endpoint {
        port: u16,
        shared: Arc<Shared>,
        stop: Arc<AtomicBool>,
        join: Option<std::thread::JoinHandle<()>>,
    }

    impl Endpoint {
        fn start(nonce: &str) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind endpoint");
            let port = listener.local_addr().expect("endpoint addr").port();
            listener
                .set_nonblocking(false)
                .expect("blocking listener for the accept loop");
            let shared = Arc::new(Shared::default());
            let stop = Arc::new(AtomicBool::new(false));
            let nonce = nonce.to_string();

            let ctx = Arc::clone(&shared);
            let stop_thread = Arc::clone(&stop);
            let join = std::thread::spawn(move || {
                for accepted in listener.incoming() {
                    if stop_thread.load(Ordering::SeqCst) {
                        break;
                    }
                    if let Ok(stream) = accepted {
                        let ctx = Arc::clone(&ctx);
                        let nonce = nonce.clone();
                        std::thread::spawn(move || handle(stream, &ctx, &nonce));
                    }
                }
            });

            Self {
                port,
                shared,
                stop,
                join: Some(join),
            }
        }

        fn url(&self) -> String {
            format!("http://127.0.0.1:{}/sandbox/intent", self.port)
        }

        fn proxy_consultations(&self, epoch: u64) -> Vec<String> {
            let proxied = self.shared.proxied.lock().unwrap();
            proxied
                .iter()
                .filter(|(e, _)| *e == epoch)
                .map(|(_, line)| line.clone())
                .collect()
        }

        fn origin_requests(&self, epoch: u64) -> Vec<String> {
            let origin = self.shared.origin.lock().unwrap();
            origin
                .iter()
                .filter(|(e, _)| *e == epoch)
                .map(|(_, line)| line.clone())
                .collect()
        }

        fn closed(&self, epoch: u64) -> bool {
            self.shared
                .closes
                .lock()
                .map(|closes| closes.contains(&epoch))
                .unwrap_or(false)
        }
    }

    impl Drop for Endpoint {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            // Wake the blocking accept() instead of polling on a sleep.
            let _ = TcpStream::connect(("127.0.0.1", self.port));
            if let Some(join) = self.join.take() {
                let _ = join.join();
            }
        }
    }

    fn bump(shared: &Shared, epoch: u64, f: impl FnOnce(&mut ProxyProof)) {
        let mut counters = shared.counters.lock().unwrap();
        f(counters.entry(epoch).or_default());
    }

    fn handle(mut stream: TcpStream, shared: &Shared, nonce: &str) {
        let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
        let mut buf: Vec<u8> = Vec::new();
        let mut chunk = [0u8; 1024];
        while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
            match stream.read(&mut chunk) {
                Ok(0) => return,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
                Err(_) => return,
            }
            if buf.len() > 16 * 1024 {
                return;
            }
        }

        let head = String::from_utf8_lossy(&buf).to_string();
        let line = head.lines().next().unwrap_or("").trim().to_string();
        let epoch = shared.epoch.load(Ordering::SeqCst);
        let target = line.split_whitespace().nth(1).unwrap_or("").to_string();

        // A proxy consultation is anything a proxy must handle: a CONNECT or an
        // absolute-form request. Both are refused for loopback exactly as the
        // real proxy refuses them (invariant 4), so `tunnels` stays 0.
        if line.starts_with("CONNECT ")
            || target.starts_with("http://")
            || target.starts_with("https://")
        {
            shared.proxied.lock().unwrap().push((epoch, line));
            bump(shared, epoch, |proof| proof.accepted += 1);
            let body = format!("proxy refuses loopback target {target}\n");
            let _ = stream.write_all(&response(403, "Forbidden", &body));
            return;
        }

        // Origin-form: the client dialled us directly, so we are the endpoint.
        shared.origin.lock().unwrap().push((epoch, line));
        if target == "/sandbox/intent" {
            let body = format!("{{\"ok\":true,\"nonce\":\"{nonce}\"}}");
            let _ = stream.write_all(&response(200, "OK", &body));
        } else {
            let _ = stream.write_all(&response(404, "Not Found", "unknown endpoint\n"));
        }
    }

    fn response(code: u16, reason: &str, body: &str) -> Vec<u8> {
        format!(
            "HTTP/1.1 {code} {reason}\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .into_bytes()
    }

    /// The wrapper exe beside the test binary (`target/<profile>/`), built by
    /// `cargo build --features mxc-backend --bin mxc-launch`.
    fn launcher_under_test() -> PathBuf {
        let exe = std::env::current_exe().expect("current test exe");
        let deps = exe.parent().expect("deps directory");
        let candidates = [
            deps.parent().map(|profile| profile.join(LAUNCHER_EXE_NAME)),
            Some(deps.join(LAUNCHER_EXE_NAME)),
        ];
        for candidate in candidates.into_iter().flatten() {
            if candidate.is_file() {
                return candidate;
            }
        }
        panic!(
            "{LAUNCHER_EXE_NAME} not found near {}: run `cargo build --features mxc-backend \
             --bin mxc-launch` first",
            exe.display()
        );
    }

    /// A scratch directory that removes itself, so a failed assertion does not
    /// leave host state behind (the test grants nothing outside it).
    struct Scratch(PathBuf);

    impl Scratch {
        fn new() -> Self {
            let dir = std::env::temp_dir().join(format!(
                "sandbox-mxc-intent-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            std::fs::create_dir_all(&dir).expect("create scratch dir");
            Self(dir)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn live_input(port: u16, scratch: &Path, launcher: &Path, command: String) -> MxcSessionInput {
        MxcSessionInput {
            command,
            working_directory: Some(scratch.display().to_string()),
            environment: Vec::new(),
            filesystem: MxcFilesystemInput {
                readwrite_paths: vec![scratch.display().to_string()],
                readonly_paths: vec![
                    launcher_grant(launcher).expect("launcher directory"),
                    // The workloads below are System32-resident.
                    r"C:\Windows".to_string(),
                ],
                denied_paths: Vec::new(),
            },
            network: MxcNetworkInput {
                proxy_port: Some(port),
            },
            timeout_ms: None,
        }
    }

    fn stdout_of(outcome: &SessionOutcome) -> String {
        String::from_utf8_lossy(&outcome.stdout).to_string()
    }

    fn stderr_of(outcome: &SessionOutcome) -> String {
        String::from_utf8_lossy(&outcome.stderr).to_string()
    }

    const CURL: &str = r"C:\Windows\System32\curl.exe";

    /// `TokenElevation` for this process, so the evidence says whether anything
    /// ran elevated. Same signal as `IsInRole(Administrator)` and as
    /// `src/setup.rs::is_elevated` (private to that module).
    fn process_is_elevated() -> bool {
        use windows::Win32::Foundation::{CloseHandle, HANDLE};
        use windows::Win32::Security::{
            GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
        };
        use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
        // SAFETY: the token handle is closed on every path, and the information
        // buffer is exactly the size passed to the API.
        unsafe {
            let mut token = HANDLE::default();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
                return false;
            }
            let mut elevation = TOKEN_ELEVATION::default();
            let mut ret = 0u32;
            let ok = GetTokenInformation(
                token,
                TokenElevation,
                Some(&mut elevation as *mut _ as *mut _),
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut ret,
            );
            let _ = CloseHandle(token);
            ok.is_ok() && elevation.TokenIsElevated != 0
        }
    }

    fn proxy_lines(stdout: &str) -> Vec<String> {
        stdout
            .lines()
            .filter(|line| line.to_ascii_lowercase().contains("proxy"))
            .map(|line| line.trim().to_string())
            .collect()
    }

    #[test]
    #[ignore = "launches real ProcessContainers; run: cargo test --features mxc-backend -- --ignored"]
    fn intent_endpoint_is_reachable_from_a_container_and_no_proxy_arrives() {
        let launcher = launcher_under_test();
        let endpoint = Endpoint::start("nonce-p1-wave-1");
        let proof = LiveProof {
            shared: Arc::clone(&endpoint.shared),
        };
        let scratch = Scratch::new();
        let scratch_dir = scratch.path().to_path_buf();

        println!("EVIDENCE launcher={}", launcher.display());
        println!(
            "EVIDENCE elevated={} (TokenElevation of the driving process)",
            process_is_elevated()
        );
        println!(
            "EVIDENCE platform_support={}",
            serde_json::to_string(&v1::platform_support()).unwrap_or_else(|e| e.to_string())
        );
        println!(
            "EVIDENCE endpoint_port={} (proxy and intent endpoint share the listener)",
            endpoint.port
        );

        let backend =
            MxcBackend::new(&proof, Some(endpoint.port), &launcher).with_budget(Some(120_000));

        // ---- 1. the child sees NO_PROXY and the SDK's own proxy variables ----
        let outcome = backend
            .launch(
                &live_input(
                    endpoint.port,
                    &scratch_dir,
                    &launcher,
                    "cmd /c set".to_string(),
                ),
                ProofExpectation::MustBeAbsent,
            )
            .expect("environment dump launch");
        let env_dump = stdout_of(&outcome);
        println!(
            "EVIDENCE env_probe exit={:?} success={} proof={:?} proxy_env_lines={:?}",
            outcome.exit_code,
            outcome.success(),
            outcome.proxy_proof,
            proxy_lines(&env_dump)
        );
        assert!(
            outcome.success(),
            "the environment probe must pass guardrail 1: {outcome:?}"
        );
        assert!(
            proxy_lines(&env_dump)
                .iter()
                .any(|line| line == "NO_PROXY=localhost,127.0.0.1,::1"),
            "the child must have NO_PROXY from the launcher: {:?}",
            proxy_lines(&env_dump)
        );
        assert!(
            proxy_lines(&env_dump).iter().any(|line| line
                .eq_ignore_ascii_case(&format!("HTTP_PROXY=http://127.0.0.1:{}", endpoint.port))),
            "the SDK's proxy variable must be present, otherwise NO_PROXY proves nothing: {:?}",
            proxy_lines(&env_dump)
        );

        // ---- 1b. a lowercase lookup resolves to the same value ----
        // Windows environment names are case-insensitive, so `NO_PROXY` and
        // `no_proxy` are one entry; this asserts the spelling a POSIX-emulation
        // client reads resolves, rather than claiming two blocks entries.
        let outcome = backend
            .launch(
                &live_input(
                    endpoint.port,
                    &scratch_dir,
                    &launcher,
                    "cmd /c echo lower=%no_proxy%".to_string(),
                ),
                ProofExpectation::MustBeAbsent,
            )
            .expect("lowercase no_proxy lookup launch");
        let lower = stdout_of(&outcome);
        println!(
            "EVIDENCE no_proxy_lookup exit={:?} stdout={:?}",
            outcome.exit_code,
            lower.trim()
        );
        assert!(
            lower.contains("lower=localhost,127.0.0.1,::1"),
            "a lowercase `no_proxy` lookup must resolve to the loopback list: {lower:?}"
        );

        // ---- 2. the intent endpoint is reachable, directly, from the container ----
        let command = format!("{CURL} -sS -f --max-time 20 {}", endpoint.url());
        let outcome = backend
            .launch(
                &live_input(endpoint.port, &scratch_dir, &launcher, command),
                ProofExpectation::MustBeAbsent,
            )
            .expect("intent endpoint launch");
        let epoch = proof.last_epoch();
        let out = stdout_of(&outcome);
        println!(
            "EVIDENCE intent_get epoch={epoch} exit={:?} stdout={:?} stderr={:?} \
             origin_requests={:?} proxy_consultations={:?}",
            outcome.exit_code,
            out.trim(),
            stderr_of(&outcome),
            endpoint.origin_requests(epoch),
            endpoint.proxy_consultations(epoch)
        );
        assert_eq!(outcome.exit_code, Some(0), "curl failed: {outcome:?}");
        assert!(
            out.contains("nonce-p1-wave-1"),
            "the child's response must come from our endpoint: {out:?}"
        );
        assert!(
            endpoint
                .origin_requests(epoch)
                .iter()
                .any(|line| line.contains("GET /sandbox/intent")),
            "the endpoint must have been called directly (origin form): {:?}",
            endpoint.origin_requests(epoch)
        );
        assert!(
            endpoint.proxy_consultations(epoch).is_empty(),
            "nothing may go through the proxy: {:?}",
            endpoint.proxy_consultations(epoch)
        );
        println!(
            "EVIDENCE guardrail1 epoch={epoch} proof={:?} expectation={:?} closed={} \
             tier={:?} needs_dacl_augmentation={:?}",
            outcome.proxy_proof,
            outcome.expectation,
            endpoint.closed(epoch),
            outcome.tier.tier,
            outcome.tier.needs_dacl_augmentation
        );
        assert!(endpoint.closed(epoch), "the launch epoch must be closed");

        // ---- 3. A/B control: ignore NO_PROXY and the request IS proxied ----
        // Without this leg the positive result above would not show that the
        // proxy is genuinely in the path (`--noproxy ""` empties the list).
        let command = format!(
            r#"{CURL} -sS -f --noproxy "" --max-time 20 {}"#,
            endpoint.url()
        );
        let err = backend
            .launch(
                &live_input(endpoint.port, &scratch_dir, &launcher, command),
                ProofExpectation::Required,
            )
            .expect_err("a proxied loopback request must fail guardrail 1");
        let epoch = proof.last_epoch();
        println!(
            "EVIDENCE ab_control epoch={epoch} err={err} proxy_consultations={:?} \
             origin_requests={:?}",
            endpoint.proxy_consultations(epoch),
            endpoint.origin_requests(epoch)
        );
        assert!(
            matches!(err, MxcError::Guard(GuardError::TunnelNotEstablished)),
            "expected a proxy consultation without a tunnel, got {err:?}"
        );
        assert!(
            !endpoint.proxy_consultations(epoch).is_empty(),
            "with NO_PROXY ignored, the request must reach the proxy"
        );
        assert!(
            endpoint.origin_requests(epoch).is_empty(),
            "with NO_PROXY ignored, nothing may reach the endpoint directly"
        );

        // ---- 4. the workload's own exit code is propagated unchanged ----
        let outcome = backend
            .launch(
                &live_input(
                    endpoint.port,
                    &scratch_dir,
                    &launcher,
                    "cmd /c exit 9".to_string(),
                ),
                ProofExpectation::MustBeAbsent,
            )
            .expect("exit-code launch");
        println!(
            "EVIDENCE exit_code_propagation exit={:?}",
            outcome.exit_code
        );
        assert_eq!(
            outcome.exit_code,
            Some(9),
            "the wrapper must propagate the workload's exit code: {outcome:?}"
        );

        // ---- 5. a failed spawn is a distinct exit code plus a stderr line ----
        let outcome = backend
            .launch(
                &live_input(
                    endpoint.port,
                    &scratch_dir,
                    &launcher,
                    "definitely-not-a-program-p1.exe --flag".to_string(),
                ),
                ProofExpectation::MustBeAbsent,
            )
            .expect("a spawn failure is a normal exit, not a launch error");
        let err_out = stderr_of(&outcome);
        println!(
            "EVIDENCE spawn_failure exit={:?} stderr={:?}",
            outcome.exit_code,
            err_out.trim()
        );
        assert_eq!(
            outcome.exit_code,
            Some(127),
            "a failed spawn must be its own non-zero code: {outcome:?}"
        );
        assert!(
            err_out.contains("mxc-launch: failed to start"),
            "the failure must be named on stderr: {err_out:?}"
        );

        println!(
            "EVIDENCE done: intent endpoint reachable unelevated through the launcher, NO_PROXY delivered"
        );
    }
}
