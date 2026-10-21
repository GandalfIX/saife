//! MXC `processcontainer` containment backend — ADR-0004 Option A, P0 skeleton.
//!
//! This module is the *only* place the supervisor talks to `mxc-sdk`. It is
//! compiled only with the `mxc-backend` Cargo feature; the AppContainer
//! supervisor is untouched and remains the default backend (P3 flips it).
//!
//! Scope of P0 — deliberately narrow:
//!
//! * `build_request` is a **pure** mapping from our resolved session data to a
//!   `ContainerRequest`. No I/O, no SDK calls, so it is fully unit-testable.
//! * `MxcBackend::launch` runs a short-lived command through `v1::run`. The
//!   interactive path (`v1::spawn`, stdin/streaming/kill) is a later phase
//!   (P1) and is not implemented here.
//! * Guardrail 1 (`verify_proxy_proof`, `ProxyProofSource`) is a hard gate:
//!   a launch whose proxy proof is missing or negative is an **error**, never a
//!   warning and never a success.
//! * Guardrail 2 (`probe_tier`) records the tier of the *exact* request about
//!   to be launched. The audit leaf that persists it lands in P2.3.
//!
//! Not here, by design: proxy wiring (P1.1/P1.2 — `MxcSessionInput::network`
//! is an explicit passthrough), filesystem policy beyond explicit grants (P1.3),
//! the session-start audit leaf (P2.3), and any prompt/timeout budget logic
//! (P2.1 — `MxcSessionInput::timeout_ms` is passed through verbatim).
//!
//! There is no attestation at `mxc-sdk 1.0.1` (ADR-0004): the tier is observed
//! after the fact, and `warnings: []` is never treated as evidence.

// P0 lands the backend seam before the supervisor routes through it (P1), so
// the launch path is exercised by its own tests and not yet by `main.rs`. The
// allow is scoped to non-test builds so genuine rot in this module still
// surfaces under `cargo test`. Remove it once P1 wires `--backend mxc` in.
#![cfg_attr(not(test), allow(dead_code))]

use std::fmt;

use mxc_sdk::v1;
use mxc_sdk::v1::configs::ProcessContainerConfig;
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
/// ADR-0004: MXC injects its own `HTTP_PROXY`/`HTTPS_PROXY` (upper and lower
/// case) pointing at the supervisor's proxy and leaves `NO_PROXY` unset. A host
/// value that crossed into the request would either point the child at a proxy
/// we do not control — which makes guardrail 1 unprovable — or disable proxying
/// for a host we intended to route.
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
// Input: our resolved session data (plain, no SDK types)
// ---------------------------------------------------------------------------

/// Filesystem grants as the supervisor resolved them (P1.3 maps policy onto
/// this; P0 only passes it through).
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
    /// Loopback port the supervisor's proxy listens on (P1.1 binds it). `None`
    /// means no proxy: the request stays egress-denied and host loopback stays
    /// closed.
    pub proxy_port: Option<u16>,
}

/// One session, as the supervisor resolved it. Plain data — deliberately free
/// of SDK types so the mapping can be tested without the runtime.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MxcSessionInput {
    /// Command line handed to the container. P1 keeps using a command line (not
    /// an argv vector) because that is what `ContainerRequest` carries.
    pub command: String,
    /// Initial working directory; `None` leaves the backend default.
    pub working_directory: Option<String>,
    /// Environment entries the caller wants propagated. Host proxy variables
    /// are removed by [`build_request`] — see [`BLOCKED_ENV_KEYS`].
    pub environment: Vec<(String, String)>,
    pub filesystem: MxcFilesystemInput,
    pub network: MxcNetworkInput,
    /// Wall-clock bound for the whole workload. P2.1 owns the budget arithmetic;
    /// P0 passes the value through unchanged.
    pub timeout_ms: Option<u32>,
}

// ---------------------------------------------------------------------------
// Guardrail 1: post-launch proxy proof (hard gate)
// ---------------------------------------------------------------------------

/// The supervisor's own count of what its proxy saw for one launch epoch.
///
/// `accepted` counts connections the proxy accepted in the epoch; `tunnels`
/// counts those whose origin dial succeeded (i.e. a real `200 Connection
/// Established` was sent). Both are needed: the spike proved that a proxy
/// 502/403 (unresolvable target, loopback target) and a silently misconfigured
/// container both give `accepted >= 1, tunnels == 0`, and that a container that
/// never reached the proxy gives `accepted == 0` while still exiting 0 with
/// `warnings: []`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ProxyProof {
    pub accepted: u64,
    pub tunnels: u64,
}

/// Why guardrail 1 refused a launch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardError {
    /// No proof source was supplied, so the launch cannot be proven at all.
    MissingProofSource,
    /// The child never reached the proxy in this launch's epoch.
    SessionNotAccepted,
    /// The proxy accepted a connection but never established a tunnel (502/403
    /// or a loopback/HostLoopback misconfiguration).
    TunnelNotEstablished,
}

impl fmt::Display for GuardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Self::MissingProofSource => {
                "no proxy proof source: ADR-0004 guardrail 1 requires a post-launch proxy proof \
                 for every MXC launch"
            }
            Self::SessionNotAccepted => {
                "guardrail 1: no proxy session was accepted in this launch's epoch — the child \
                 never reached the proxy"
            }
            Self::TunnelNotEstablished => {
                "guardrail 1: the proxy accepted a session but established no CONNECT tunnel"
            }
        };
        f.write_str(msg)
    }
}

impl std::error::Error for GuardError {}

/// The hard gate. `accepted >= 1 && tunnels >= 1`, or the launch fails.
pub fn verify_proxy_proof(proof: ProxyProof) -> Result<(), GuardError> {
    if proof.accepted == 0 {
        return Err(GuardError::SessionNotAccepted);
    }
    if proof.tunnels == 0 {
        return Err(GuardError::TunnelNotEstablished);
    }
    Ok(())
}

/// Where the launch path gets its proof from.
///
/// Implemented in P1.1 by the per-session proxy: [`begin_launch`] opens an
/// attribution epoch *before* the child starts, and [`proof`] reports the
/// counters for that epoch *after* it exits. One proxy per launch until P1.4
/// lands the per-run token (ADR-0004 "concurrency caveat").
///
/// [`begin_launch`]: ProxyProofSource::begin_launch
/// [`proof`]: ProxyProofSource::proof
pub trait ProxyProofSource {
    /// Open an attribution epoch and return its id.
    fn begin_launch(&self) -> u64;
    /// Counters for the sessions accepted in `epoch`.
    fn proof(&self, epoch: u64) -> ProxyProof;
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

/// An MXC launch failure.
#[derive(Debug)]
pub enum MxcError {
    /// Guardrail 1 refused the launch.
    Guard(GuardError),
    /// The SDK refused the request or the wait failed.
    Sdk(v1::Error),
}

impl fmt::Display for MxcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Guard(e) => write!(f, "{e}"),
            Self::Sdk(e) => write!(f, "mxc-sdk: {e}"),
        }
    }
}

impl std::error::Error for MxcError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Guard(e) => Some(e),
            Self::Sdk(e) => Some(e),
        }
    }
}

impl From<GuardError> for MxcError {
    fn from(e: GuardError) -> Self {
        Self::Guard(e)
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
}

impl SessionOutcome {
    /// True only for a clean exit 0 whose proxy proof passes guardrail 1.
    ///
    /// The proof is re-checked here rather than assumed: a hand-built or
    /// deserialised outcome cannot report success on an unproven launch just by
    /// carrying a zero exit code.
    pub fn success(&self) -> bool {
        self.exit_code == Some(0) && !self.timed_out && verify_proxy_proof(self.proxy_proof).is_ok()
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
///   (which would mean "backend default"). `inherit_default_environment` stays
///   `Some(true)`, and at `mxc-sdk 1.0.1` that "default" block is the user's
///   **profile** environment (`CreateEnvironmentBlock(token, bInherit =
///   false)`), not this process's environment; when a proxy is configured the
///   SDK also strips `HTTP_PROXY`/`HTTPS_PROXY`/`NO_PROXY`/`ALL_PROXY`
///   (case-insensitive) from it before injecting ours.
pub fn build_request(input: &MxcSessionInput) -> ContainerRequest {
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

    let mut request = ContainerRequest::new(input.command.clone());
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
    request.containment = Containment::ProcessContainer(ProcessContainerConfig::default());
    request.working_directory = input.working_directory.clone();
    request.environment = Some(environment);
    // `Some(true)` adds the SDK's default block. At `mxc-sdk 1.0.1` that block
    // is the user's *profile* environment — `appcontainer_runner` builds it with
    // `CreateEnvironmentBlock(token, bInherit = false)` — not this process's
    // environment, so it is not the host env we filter above. With a proxy
    // configured the SDK strips HTTP_PROXY/HTTPS_PROXY/NO_PROXY/ALL_PROXY
    // (case-insensitive) from that block before injecting our proxy variables.
    // Residual: a proxy value persisted in HKCU\Environment is part of the
    // profile block and survives only in the proxy-less branch, where egress and
    // host_loopback are both `deny` — inert. Whether to keep `Some(true)` is a
    // P1 decision, not this one.
    request.inherit_default_environment = Some(true);
    request
}

// ---------------------------------------------------------------------------
// Launch
// ---------------------------------------------------------------------------

/// Knobs for one launch.
#[derive(Clone, Copy)]
pub struct LaunchOptions<'a> {
    /// The proxy proof source for this launch. `None` is *not* "skip guardrail
    /// 1": it fails the launch with [`GuardError::MissingProofSource`].
    pub proxy_proof: Option<&'a dyn ProxyProofSource>,
}

impl LaunchOptions<'_> {
    /// Options with no proof source — always refused by guardrail 1. Exists so
    /// the refusal is expressible (and testable) rather than accidental.
    pub fn without_proof_source() -> Self {
        Self { proxy_proof: None }
    }
}

/// The `processcontainer` backend.
pub struct MxcBackend;

impl MxcBackend {
    /// Run a short-lived command to completion inside a ProcessContainer.
    ///
    /// Order is the contract: resolve the proof source (refuse early if there is
    /// none), probe the tier of the exact request, open the launch epoch, run,
    /// then apply guardrail 1 to the epoch's counters. There is no path from
    /// `v1::run` returning `Ok` to a success without `accepted >= 1 && tunnels
    /// >= 1`.
    ///
    /// Spawn/interactive workloads (`v1::spawn`, stdin, streaming, kill) are a
    /// later phase (P1) and are not implemented here.
    pub fn launch(
        input: &MxcSessionInput,
        opts: &LaunchOptions<'_>,
    ) -> Result<SessionOutcome, MxcError> {
        let source = opts
            .proxy_proof
            .ok_or(MxcError::Guard(GuardError::MissingProofSource))?;

        let request = build_request(input);

        // Guardrail 2 on the exact request that is about to be launched: not a
        // lookalike, and not the backend ceiling (which policy can lower).
        let tier = probe_tier(&request)?;

        // The epoch is opened before the child starts, so guardrail 1 cannot be
        // satisfied by traffic from an earlier launch.
        let epoch = source.begin_launch();

        let exec = v1::run(request, RunOptions::default())?;

        // ... and read after the child returns, which is the only point where
        // "did the child actually reach the proxy?" is answerable.
        let proof = source.proof(epoch);

        gate_outcome(
            tier,
            ChildRun {
                wait: exec.outcome,
                stdout: exec.stdout,
                stderr: exec.stderr,
                warnings: exec.warnings,
            },
            proof,
        )
    }
}

/// Apply guardrail 1 to a finished child and map it into a [`SessionOutcome`].
///
/// Pure on purpose: this is the one place a proof can turn into a success or an
/// error, so it can be tested with the spike's three observed outcomes without
/// spawning a container.
fn gate_outcome(
    tier: TierRecord,
    child: ChildRun,
    proof: ProxyProof,
) -> Result<SessionOutcome, MxcError> {
    // Guardrail 1 first and unconditionally: `warnings: []` and exit 0 are not
    // evidence, so a failed proof poisons every outcome, timeout included.
    verify_proxy_proof(proof)?;

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
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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

    // ---- P0.2: request mapping -------------------------------------------

    #[test]
    fn request_carries_command_working_directory_and_timeout() {
        let req = build_request(&input());
        assert_eq!(req.command, "cmd /c echo hi");
        assert_eq!(req.working_directory.as_deref(), Some(r"C:\work"));
        assert_eq!(req.timeout_ms, Some(60_000));
    }

    #[test]
    fn request_selects_process_container_without_a_proxy_peer() {
        let req = build_request(&input());
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
        let req = build_request(&input());
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
        let req = build_request(&i);
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
        let req = build_request(&i);
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
        let req = build_request(&i);
        assert_eq!(
            req.environment,
            Some(Vec::new()),
            "an empty allow-list must be explicit, not `None` (backend default)"
        );
        assert_eq!(req.inherit_default_environment, Some(true));
    }

    #[test]
    fn filesystem_grants_pass_through_unchanged() {
        let req = build_request(&input());
        let fs = req.filesystem.as_ref().expect("filesystem policy");
        assert_eq!(fs.readwrite_paths, vec![r"C:\work".to_string()]);
        assert_eq!(fs.readonly_paths, vec![r"C:\ref".to_string()]);
        assert_eq!(fs.denied_paths, vec![r"C:\Users\marku\.ssh".to_string()]);
    }

    // ---- P0.3: guardrail 1 ----------------------------------------------

    #[test]
    fn proof_with_no_accepted_session_is_an_error() {
        let err = verify_proxy_proof(ProxyProof {
            accepted: 0,
            tunnels: 0,
        })
        .expect_err("accepted=0 must fail");
        assert_eq!(err, GuardError::SessionNotAccepted);
    }

    /// The structural case the spike proved matters: proxy 502 (unresolvable
    /// target) and loopback-denied both give accepted=1, tunnels=0.
    #[test]
    fn proof_with_no_tunnel_is_an_error_even_when_a_session_was_accepted() {
        let err = verify_proxy_proof(ProxyProof {
            accepted: 1,
            tunnels: 0,
        })
        .expect_err("tunnels=0 must fail");
        assert_eq!(err, GuardError::TunnelNotEstablished);
    }

    #[test]
    fn proof_with_accepted_session_and_tunnel_passes() {
        verify_proxy_proof(ProxyProof {
            accepted: 1,
            tunnels: 1,
        })
        .expect("accepted=1 tunnels=1 must pass");
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
            ProxyProof {
                accepted: 1,
                tunnels: 1,
            },
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
        assert_eq!(
            outcome.proxy_proof,
            ProxyProof {
                accepted: 1,
                tunnels: 1,
            }
        );
        assert_eq!(outcome.tier.tier.as_deref(), Some("base-container"));
    }

    /// Hand-built success shape (exit 0, no timeout) with an unproven launch:
    /// `success()` must consult the proof, not the shape.
    #[test]
    fn success_shaped_outcome_without_a_proof_is_not_a_success() {
        for proof in [
            ProxyProof {
                accepted: 0,
                tunnels: 0,
            },
            ProxyProof {
                accepted: 1,
                tunnels: 0,
            },
        ] {
            let outcome = SessionOutcome {
                exit_code: Some(0),
                timed_out: false,
                stdout: Vec::new(),
                stderr: Vec::new(),
                warnings: Vec::new(),
                tier: tier(),
                proxy_proof: proof,
            };
            assert!(
                !outcome.success(),
                "an unproven outcome (accepted={}, tunnels={}) must never report success",
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
            ProxyProof {
                accepted: 1,
                tunnels: 1,
            },
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
            ProxyProof {
                accepted: 1,
                tunnels: 1,
            },
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
            ProxyProof {
                accepted: 0,
                tunnels: 0,
            },
        )
        .expect_err("proof gate applies to every outcome");
        assert!(matches!(
            err,
            MxcError::Guard(GuardError::SessionNotAccepted)
        ));
    }

    #[test]
    fn launch_without_a_proof_source_is_an_error() {
        let err = MxcBackend::launch(&input(), &LaunchOptions::without_proof_source())
            .expect_err("no proof source must refuse the launch");
        assert!(
            matches!(err, MxcError::Guard(GuardError::MissingProofSource)),
            "got {err:?}"
        );
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
