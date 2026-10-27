//! Localhost reverse proxy: tokio + hyper + rustls.
//!
//! Architecture: the supervisor (`saife.exe`) spawns the proxy on a
//! random 127.0.0.1 port before launching the sandboxed process. The
//! sandboxed process is configured (via env vars) to route HTTP(S)
//! through this proxy. The proxy runs the full D-1 decision pipeline
//! (Task 3.6): loopback refusal, hard-deny, learned decisions,
//! deny_domain / allow_domain matching, the interactive prompt, and —
//! after admission — DNS-pinned Happy-Eyeballs dialing; it emits CONNECT
//! audit events with the D-5 source/scope/persisted fields and splices
//! the TCP tunnel after admission. On the same listener it serves the
//! D-4 /sandbox/intent endpoints to the sandboxed agent (token-gated like
//! CONNECT).
//!
//! MVP DEVIATION FROM SPEC NARRATIVE: the spec says "the proxy does TLS to
//! the upstream" but for the MVP the proxy does a plain TCP splice for
//! CONNECT — the child speaks TLS end-to-end with the real host. The
//! allow-list is enforced at the CONNECT line (the target host is visible
//! before any bytes flow upstream). This satisfies every US-3 AC (they
//! assert on the CONNECT line and the connection outcome, not on where TLS
//! terminates). Terminating TLS at the proxy is future work tied to
//! credential injection (F-2). rustls + rustls-native-certs are in
//! Cargo.toml but unused in the MVP; they'll be wired in when F-2 lands.
//! Likewise `hyper`, `hyper-util`, `http`, `http-body-util`, and `bytes`
//! are present as deps for that future work and are NOT imported here.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::LazyLock;
use std::sync::Mutex as StdMutex;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result};
use base64::Engine;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::runtime::Runtime;
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;

use crate::audit::AuditWriter;
use crate::net::intent::IntentRegistry;
use crate::net::learned::{LearnedDecision, LearnedStore};
use crate::net::matcher::{self, DenyReason, Verdict};
use crate::net::prompt::{
    OverloadCause, PromptConfig, PromptCoordinator, PromptOutcome, PromptPolicy, PromptResult,
    UnavailableCause, is_loopback_host,
};
use crate::net::token::RunToken;
use crate::net::upstream::{UpstreamDialer, UpstreamError};
use crate::plugin::{FacadeRegistry, FacadeTarget};

/// The complete set of valid `source` values for a CONNECT audit event
/// (D-5 taxonomy). Kept as a const so future validation logic and tests
/// share a single source of truth; no production call site consumes it yet
/// (only tests reference it), so it is `#[allow(dead_code)]` until the D-5
/// validator lands.
/// The deny `reason` for a prompt consultation whose budget elapsed (P2.1).
///
/// One string, produced for both legs (CONNECT and the absolute-form forward):
/// a forward request that had to ask the user and got no answer must read in the
/// audit chain exactly like a CONNECT that did, because the policy answer is the
/// same and the two legs differ only in how the client framed the request.
/// Distinct from [`NO_DIALOG_BACKEND_REASON`] on purpose — a spent budget is this
/// session's own term being consumed, which is what the supervisor's `timeout_ms`
/// has to cover, while a missing backend is a machine with no dialog at all.
pub const PROMPT_TIMEOUT_REASON: &str = "prompt_budget_exhausted";

/// The deny `reason` for a consultation refused because no dialog backend
/// exists (P2.1 review).
///
/// Distinct from [`PROMPT_TIMEOUT_REASON`] for the same reason that one is
/// distinct from a bare "timeout or no dialog backend": a backend that cannot
/// produce a decision at all is a property of the machine, not of this session's
/// prompt budget. It is also the reason a *sticky* refusal carries when the latch
/// was armed by consultations that found no dialog at all (see
/// `prompt::NO_BACKEND_STICKY_AFTER`): the deny names the fact the workload
/// experiences — there is nothing to ask.
pub const NO_DIALOG_BACKEND_REASON: &str = "no_dialog_backend";

/// The deny `reason` for a consultation the fast-fail skipped when the latch was
/// armed by budgets that ELAPSED (P2.1 review round 2, item 8).
///
/// The sibling of [`NO_DIALOG_BACKEND_REASON`], never a synonym: here a dialog was
/// shown and nobody answered it, so the backend demonstrably works and "run
/// interactively" is the wrong remedy. Folding the two back together is exactly
/// what made a session whose dialogs were on screen read as a machine with no
/// desktop — and it is the string an operator greps to tell the two apart.
pub const PROMPT_SUPPRESSED_REASON: &str = "prompt_suppressed_after_budget";

/// The deny `reason` for a consultation refused because the abandoned pool is
/// full ([`crate::net::prompt::MAX_ABANDONED_PROMPTS`]) — dialogs from earlier
/// consultations are still on screen after their budgets elapsed.
pub const PROMPT_ABANDONED_CAPACITY_REASON: &str = "prompt_abandoned_capacity";

/// The deny `reason` for a consultation refused because every consultation slot
/// is in flight ([G-28]). Kept as the prose it has always been — this one is the
/// cap the ADR names, and its wording is what operators have seen since 3.6.
pub const PROMPT_OVERLOAD_REASON: &str = "too many concurrent prompts";

/// Name the pool that ran out (P2.1 review, item 4). Pure so both arms can be
/// pinned without standing up eight live dialogs.
fn overload_reason(cause: OverloadCause) -> &'static str {
    match cause {
        OverloadCause::ConsultationsHeld => PROMPT_OVERLOAD_REASON,
        OverloadCause::AbandonedCapacity => PROMPT_ABANDONED_CAPACITY_REASON,
    }
}

#[allow(dead_code)]
pub const SOURCES: &[&str] = &[
    "hard-deny",
    "learned",
    "blocklist",
    "allowlist",
    "prompt",
    "unavailable",
    "dns",
    "default",
    "prompt_overload",
];

pub struct ProxyConfig {
    pub session_id: String,
    /// This run's own credential (P1.4). The listener accepts **only** this
    /// value: a token minted for another run gets a `407` that is neither
    /// counted nor audited here. See [`RunToken`].
    pub token: RunToken,
    pub allow_domain: Vec<String>,
    /// Domains always denied, checked after hard-deny and before the
    /// allow-list ([G-32, G-33]). Wired in D-3.2; the full prompt/learned-deny
    /// pipeline lands in D-3.6.
    pub deny_domain: Vec<String>,
    /// Upstream chaining dialer ([G-10, G-22]). `None` = direct dial
    /// only. Parsed once by the supervisor at startup and shared by
    /// every handler through the `Arc`.
    pub upstream: Option<Arc<UpstreamDialer>>,
    pub writer: Arc<AuditWriter>,
    /// Prompt/intent/learned wiring (Task 3.6). Built by the supervisor
    /// before `spawn`; see [`PromptGate`].
    pub prompt: PromptGate,
    /// This session's plugin facades. An EMPTY registry is a valid, fully
    /// closed state (the AppContainer path and `--block-net` both pass one): a
    /// `*.sandbox.invalid` request then answers `404` and nothing else changes.
    /// The supervisor fills it after the listener binds, which is why it is
    /// shared rather than owned — see [`FacadeRegistry`].
    pub facade: Arc<FacadeRegistry>,
}

/// The Task 3.6 wiring: everything the D-1 decision pipeline needs
/// beyond the static allow/deny lists — the D-3 prompt coordinator, the
/// D-4 intent registry, the persisted learned store, and the per-profile
/// prompt configuration. All construction is sync in the supervisor
/// (before the proxy runtime exists); every connection handler shares
/// this by `Arc`.
pub struct PromptGate {
    /// `network.promptEnabled` / `--no-prompt` ([G-36, G-47]). Checked
    /// BEFORE any coordinator call: the coordinator itself only models
    /// the zero-timeout (`Disabled`) form of "no prompting".
    pub enabled: bool,
    /// Per-call timeout + on-unavailable policy ([G-46, G-48]).
    pub config: PromptConfig,
    /// Shared dialog coordinator (D-3.5): one per session, so every
    /// handler coalesces through the same waiter map / permit set.
    pub coordinator: Arc<PromptCoordinator>,
    /// Shared intent registry (D-4). Arc: its `Drop` joins the sweeper
    /// thread, so it must outlive every handler holding it.
    pub intent: Arc<IntentRegistry>,
    /// Shared learned store (D-3). `LearnedStore` is `!Sync` by design
    /// (see its doc), so it rides behind a std `Mutex`; the lock is held
    /// only for one lookup/record, never across an `.await`.
    pub learned: Arc<StdMutex<LearnedStore>>,
}

/// Per-listener shared state, immutable after `spawn`.
struct ConnCtx {
    /// This listener's own run token. Every request is checked against it
    /// before anything else happens (P1.4).
    token: RunToken,
    deny: Vec<String>,
    allow: Vec<String>,
    writer: Arc<AuditWriter>,
    upstream: Option<Arc<UpstreamDialer>>,
    prompt: PromptGate,
    /// Per-launch attribution counters (ADR-0004 guardrail 1). Shared with the
    /// handle, so the launch path reads exactly what this listener counted.
    counters: Arc<LaunchCounters>,
    /// This listener's audit budget for credential-less refusals (P1.6(a)).
    no_token: RefusalBudget,
    /// The same budget for a credential that is not this run's (P1.6, blocking
    /// 2). A cap on one refusal arm and not the other caps nothing: the flood is
    /// one extra header away (`Proxy-Authorization: Basic <anything base64>`
    /// takes the `Foreign` arm instead).
    foreign_token: RefusalBudget,
    /// The plugin mounts this session may reach through a facade. Empty for a
    /// session that requested no plugin; a handler that arrives before a mount
    /// is registered answers `404`, never a stale allow.
    facade: Arc<FacadeRegistry>,
}

/// How many refusals of one kind get their own leaf before the aggregate window
/// opens.
///
/// Measured before the cap: 400 credential-less CONNECTs produced 400 leaves
/// (129 KB) with nothing to stop a loop at any size (P1.4 review, P1.6(a)). Eight
/// is enough to see that something is probing and with what shape, and small
/// enough that a flood costs one screen of chain instead of a file.
const LEAF_BUDGET: u64 = 8;

/// Suppressed refusals summarised by one aggregate leaf.
///
/// The window is what makes the count both **exact** and **bounded**: each full
/// window writes one leaf carrying exactly this many refusals, so a reader sums
/// the chain to the true total instead of reading a constant, and a million
/// refusals cost 8 + ~83,000 leaves instead of 1,000,000. (P1.6 review: the
/// previous one-off aggregate wrote `suppressed=1` into `scope` because the
/// count was `n - budget` with `n == budget + 1` — a constant, and a count
/// sitting in a field whose documented domain is rule scope.)
///
/// Twelve rather than a round 100 because the realistic flood here is tens of
/// refusals, not millions: P1.8 made one credential-less attempt per managed
/// connection the steady state, so a window of 100 would leave a 20-refusal
/// burst with no aggregate at all — recording nothing about the refusals that
/// were suppressed, which is the defect being fixed. The bound that matters
/// (leaf volume grows as n/12, never as n) holds at either size.
const SUPPRESSED_LEAF_WINDOW: u64 = 12;

/// What the audit chain should record for one refusal of a budgeted kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RefusalLeaf {
    /// Inside the budget: this refusal gets its own leaf.
    Individual,
    /// This refusal completes a window: write one aggregate leaf standing in for
    /// exactly this many suppressed refusals.
    Aggregate { suppressed: u64 },
    /// Inside a window that is not full yet: write nothing.
    Nothing,
}

/// One refusal kind's leaf budget for one listener (P1.6).
///
/// Plain atomics on the listener state, **not** behind the audit writer's lock:
/// the decision "does this refusal get its own leaf?" must not serialize every
/// 407 behind one mutex, and it must not be a place a slow audit sink can stall a
/// refusal.
///
/// The budget is spent in arrival order and the window is *claimed* with a
/// single atomic rather than decided by a look-then-write, so two refusals racing
/// for a window cannot both write one. Nothing is ever subtracted from
/// `suppressed`, so a concurrent arrival cannot be counted twice or lost.
///
/// Per *listener* rather than per epoch on purpose: the flood this caps is a
/// property of the listener being dialled (an unauthenticated probe loop, or a
/// managed client's uncounted first attempt, see P1.8), and one listener serves
/// one run, so a per-epoch budget would hand a long-lived listener a fresh eight
/// leaves per launch while leaving a single launch's flood uncapped.
struct RefusalBudget {
    /// Refusals of this kind this listener has answered, ever. Decides whether a
    /// refusal is still inside the individual budget.
    seen: AtomicU64,
    /// Refusals past the individual budget, ever — monotonic, never reset.
    suppressed: AtomicU64,
    /// Suppressed refusals already summarised by an aggregate leaf, ever. A
    /// window is due when `suppressed` is a whole window ahead of it, so this is
    /// the window's re-arm state and the arithmetic stays exact across a partial
    /// trailing window (a count of *windows* would not).
    accounted: AtomicU64,
}

impl RefusalBudget {
    const fn new() -> Self {
        Self {
            seen: AtomicU64::new(0),
            suppressed: AtomicU64::new(0),
            accounted: AtomicU64::new(0),
        }
    }

    /// Take one unit of this listener's leaf budget for one refusal.
    ///
    /// The caller writes the leaf this answer names, and nothing more. Refusals
    /// stay uncounted as consultations either way — this decides the *audit*
    /// footprint only, never the proof counters.
    fn spend(&self) -> RefusalLeaf {
        let seen = self.seen.fetch_add(1, Ordering::Relaxed) + 1;
        if seen <= LEAF_BUDGET {
            return RefusalLeaf::Individual;
        }
        let suppressed = self.suppressed.fetch_add(1, Ordering::Relaxed) + 1;
        let accounted = self.accounted.load(Ordering::Relaxed);
        if suppressed < accounted + SUPPRESSED_LEAF_WINDOW {
            return RefusalLeaf::Nothing;
        }
        // The claim *is* the re-arm, and it happens immediately before the
        // caller's append: one window is summarised by exactly one leaf, and no
        // window is re-armed without an attempt following it.
        match self.accounted.compare_exchange(
            accounted,
            accounted + SUPPRESSED_LEAF_WINDOW,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => RefusalLeaf::Aggregate {
                suppressed: SUPPRESSED_LEAF_WINDOW,
            },
            // Another arrival claimed this window between the load and the
            // exchange: its leaf already covers this refusal.
            Err(_) => RefusalLeaf::Nothing,
        }
    }

    /// The refusals a shutting-down listener still owes the chain: whatever the
    /// last partial window holds, claimed so it can be written exactly once.
    ///
    /// A live reader can therefore be short by at most
    /// `SUPPRESSED_LEAF_WINDOW - 1` refusals; closing the listener writes the
    /// remainder, so a completed run's chain sums to the true total.
    fn claim_trailing(&self) -> Option<u64> {
        let accounted = self.accounted.load(Ordering::Relaxed);
        let trailing = self
            .suppressed
            .load(Ordering::Relaxed)
            .saturating_sub(accounted);
        if trailing == 0 {
            return None;
        }
        // This leaf now stands in for the remainder, so a second flush cannot
        // write it again.
        self.accounted
            .compare_exchange(
                accounted,
                accounted + trailing,
                Ordering::Relaxed,
                Ordering::Relaxed,
            )
            .ok()
            .map(|_| trailing)
    }
}

impl ConnCtx {
    /// Write the trailing aggregate of every spent refusal budget.
    ///
    /// Best effort, like every other append on this listener: the writer is
    /// non-strict, so `AuditWriter::append` swallows an I/O error and the count
    /// recorded is an *attempted* count.
    fn flush_refusal_aggregates(&self) {
        for (budget, reason) in [
            (&self.no_token, "no_token_suppressed"),
            (&self.foreign_token, "foreign_token_suppressed"),
        ] {
            if let Some(suppressed) = budget.claim_trailing() {
                let _ = emit_connect(
                    &self.writer,
                    "<unknown>",
                    0,
                    "deny",
                    Some(reason),
                    "default",
                    None,
                    false,
                    Some(u32::try_from(suppressed).unwrap_or(u32::MAX)),
                );
            }
        }
    }
}

/// Emit a CONNECT audit leaf directly through the threaded `AuditWriter`
/// (replaces the per-call `audit::emit_connect` wrapper, which opened the
/// writer fresh on each event).
//
// The positional signature is D-5.1 Step 1's (host, port, disposition, reason,
// source, scope, persisted + writer), extended by P1.6's `suppressed`; folding it
// into a struct would diverge from the spec, so the clippy lint is suppressed
// here only.
#[allow(clippy::too_many_arguments)]
fn emit_connect(
    writer: &AuditWriter,
    host: &str,
    port: u16,
    disposition: &str,
    reason: Option<&str>,
    source: &str,
    scope: Option<&str>,
    persisted: bool,
    suppressed: Option<u32>,
) -> Result<()> {
    use serde_json::{Map, json};
    let mut e = Map::new();
    e.insert("op".into(), json!("CONNECT"));
    e.insert("host".into(), json!(host));
    e.insert("port".into(), json!(port));
    e.insert("disposition".into(), json!(disposition));
    e.insert("reason".into(), json!(reason));
    e.insert("source".into(), json!(source));
    e.insert("scope".into(), json!(scope));
    e.insert("persisted".into(), json!(persisted));
    // How many refusals this leaf stands in for; `null` for a leaf that
    // describes one request. A first-class integer, never text packed into
    // `scope`: `scope` is a documented, filterable enum of *rule scope*
    // (`once` | `host` | `suffix` | null — `audit::filter::KNOWN_KEYS`,
    // `tasks/adr-0001/d-5.1-connect-source-field.md`), so a count written there
    // makes a consumer filtering on scope read a number as a scope. The price of
    // the new key is a `null` in every other leaf, which is the cheap side of
    // that trade: the leaf was always open-shaped (a reader takes the fields it
    // knows), and the alternative is a field whose meaning depends on `reason`.
    e.insert("suppressed".into(), json!(suppressed));
    writer.append(e)?;
    Ok(())
}

/// One facade request, as the chain records it.
///
/// `op: "FACADE"`, and never the facade token or the sidecar's port: the mount
/// and the path answer "which capability did this workload use", while a token in
/// the chain would be a credential in the audit. `path` is `None` for the CONNECT
/// refusal, which carries no origin-form request.
fn emit_facade(
    writer: &AuditWriter,
    mount: &str,
    path: Option<&str>,
    disposition: &str,
    reason: Option<&str>,
) -> Result<()> {
    use serde_json::{Map, json};
    let mut e = Map::new();
    e.insert("op".into(), json!("FACADE"));
    e.insert("mount".into(), json!(mount));
    e.insert("path".into(), json!(path));
    e.insert("disposition".into(), json!(disposition));
    e.insert("reason".into(), json!(reason));
    writer.append(e)?;
    Ok(())
}

/// What one launch epoch's traffic looked like from the proxy's side.
///
/// `consultations` counts connections the proxy handled **as a proxy**:
/// an authenticated `CONNECT`, or an authenticated absolute-form request that
/// named another origin. `upstream_established` counts those whose own dial to
/// the origin succeeded — a `200 Connection Established` after the dial, or a
/// plain-HTTP forward whose upstream connection came up. Serving an
/// origin-form request for one of our own endpoints is **not** a consultation.
///
/// `probes` counts **pre-flight probes** (ADR-0004 guardrail 1, amended
/// 2026-10-22): the wrapper's own `GET /sandbox/probe`, reported before it
/// starts the payload. A probe is neither a consultation nor an upstream
/// connection — it proves the child's PATH to this listener works, which is
/// what the gate needs for a workload that makes no request of its own, and
/// counting it as either would respectively make `MustBeAbsent` unsatisfiable
/// or claim a dial nobody made.
///
/// `unauthenticated` counts refusals answered **without this run's credential**
/// (`no_token` and `foreign_token` alike — P3.2a, ADR-0004 guardrail 1 amended a
/// second time). It exists because the probe alone let a silent misconfiguration
/// through: a GUI / system-proxy client (WinINet, Windows PowerShell 5.1) reaches
/// this listener, gets `407` for ever and never sends a credential, so the path is
/// proven (`probes == 1`) while the application has no egress at all. Scoped to
/// the EPOCH like every other field here — see [`LaunchCounters::note_unauthenticated`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LaunchProofCounters {
    pub consultations: u64,
    pub upstream_established: u64,
    pub probes: u64,
    pub unauthenticated: u64,
}

/// Closed epochs kept for after-the-fact reading.
///
/// One listener serves one run (P1.4: its own token is the only credential it
/// accepts), so this only bounds a listener that serves many sequential
/// launches. The *rule* is the part that matters: **only closed epochs are
/// evictable**. A launch reads its proof before it closes (read-then-close), so
/// an open entry is live by definition, and evicting it would turn a working
/// launch's proof into zeros — a false `SessionNotAccepted` on a session that
/// did everything right. The memory bound is therefore this many closed counters
/// (two `u64`s plus a flag each) plus the open ones, and [`LaunchCounters::begin_epoch`]
/// refuses a second open epoch, so a listener holds at most one open counter.
const MAX_REMEMBERED_EPOCHS: usize = 32;

/// One epoch's attribution window.
#[derive(Debug, Clone, Copy, Default)]
struct EpochEntry {
    counters: LaunchProofCounters,
    /// Set by [`LaunchCounters::close_epoch`]: the window is over, so the entry
    /// is frozen and may be evicted. An open entry never is.
    closed: bool,
}

#[derive(Debug, Default)]
struct CounterState {
    next_epoch: u64,
    /// The epoch traffic is attributed to. `None` outside a launch: traffic
    /// then counts nowhere rather than against a stale launch.
    active: Option<u64>,
    epochs: HashMap<u64, EpochEntry>,
}

/// Refusal for a launch that would overlap one already in flight (P1.4).
///
/// One listener serves one run, whose token is the only credential it accepts,
/// so two open epochs mean two launches sharing one attribution window: the
/// older launch's traffic would land in the newer epoch, and either launch could
/// satisfy its guardrail with the other's consultation. Refused by name, before
/// any child is spawned — never merged silently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EpochAlreadyOpen {
    /// The epoch that is still open.
    pub active: u64,
}

impl fmt::Display for EpochAlreadyOpen {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "launch epoch {} is still open on this proxy: a second concurrent launch would split \
             proxy attribution between two runs, so it is refused",
            self.active
        )
    }
}

impl std::error::Error for EpochAlreadyOpen {}

/// Per-launch attribution counters for this listener (ADR-0004 guardrail 1).
///
/// The proxy's handler tasks write; the launch path opens an epoch before the
/// child starts, reads the counters for that epoch, and closes it. Attribution
/// is by *the epoch active when the connection was classified as a proxy
/// consultation*. Exact because one listener serves exactly one run's token
/// (P1.4), and because a second epoch cannot be opened while one is open.
///
/// `Send + Sync` and **poison-tolerant**: a handler that panicked while holding
/// the lock must not make the launch path panic (a poisoned `Mutex` would turn
/// one broken connection into a process-wide abort of the proof gate).
/// State a listener must reset at every LAUNCH (P2.1 review round 2, item 2).
///
/// The prompt fast-fail latch is the reason this exists: it lives on the
/// coordinator, which is per listener and outlives a launch, so a listener that
/// serves sequential launches would carry launch N's verdict into launch N+1 and
/// deny prompts a session never got to ask.
pub type LaunchReset = Arc<dyn Fn() + Send + Sync>;

/// [`LaunchReset`] with a `Debug` impl: a closure is not printable, and the
/// counters' own `Debug` must stay derivable.
struct LaunchResetHook(LaunchReset);

impl fmt::Debug for LaunchResetHook {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LaunchResetHook(..)")
    }
}

#[derive(Debug, Default)]
pub struct LaunchCounters {
    state: StdMutex<CounterState>,
    /// Time this listener spent inside prompt consultations, in milliseconds
    /// (P2.1).
    ///
    /// Reset at every epoch open, and deliberately outside the epoch lock: it is a
    /// measurement, never a proof. The supervisor needs it to say *which* budget a
    /// killed session spent — a session that dies at its deadline with 60 s of
    /// prompt time behind it exhausted the prompt term, while one with no prompt
    /// time ran out on the workload term or on the handshake. Without this the only
    /// honest report is "timed out", and the causes would share one reason string.
    /// The launch path still reads a DELTA around its run, so the reset and the
    /// delta agree rather than depending on each other.
    prompt_wait_millis: AtomicU64,
    /// What a new launch must forget (P2.1 review round 2, item 2). `None` for
    /// counters nothing shares launch-scoped state with (every test fixture that
    /// only counts traffic).
    launch_reset: StdMutex<Option<LaunchResetHook>>,
}

// With `mxc-backend` off nothing reads the epochs (no launch path is wired), so
// the epoch accessors are only reachable from tests. Scoping the allow to that
// state keeps genuine rot visible in the feature-on build.
#[cfg_attr(not(any(test, feature = "mxc-backend")), allow(dead_code))]
impl LaunchCounters {
    /// A fresh registry, ready for its first epoch.
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Register the state that is scoped to a LAUNCH and must be cleared when one
    /// starts (P2.1 review round 2, item 2).
    ///
    /// The listener calls this once at [`spawn`] with its coordinator's
    /// `begin_launch`, because the listener is the only place that owns both.
    pub fn set_launch_reset(&self, reset: LaunchReset) {
        let mut slot = self
            .launch_reset
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        *slot = Some(LaunchResetHook(reset));
    }

    /// The lock, recovered from poisoning instead of panicking.
    fn lock(&self) -> std::sync::MutexGuard<'_, CounterState> {
        self.state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    /// Open an epoch and make it the attribution target.
    ///
    /// Refuses with [`EpochAlreadyOpen`] when an epoch is already open: closing
    /// the previous one here would attribute two launches' traffic to one
    /// window, and leaving both open would split attribution silently. The
    /// launch path owns closing, so refusal is the only safe answer (P1.4).
    pub fn begin_epoch(&self) -> std::result::Result<u64, EpochAlreadyOpen> {
        let mut state = self.lock();
        if let Some(active) = state.active {
            return Err(EpochAlreadyOpen { active });
        }
        state.next_epoch += 1;
        let epoch = state.next_epoch;
        state.epochs.insert(epoch, EpochEntry::default());
        state.active = Some(epoch);
        state.prune();
        // Item 2: a new launch starts with no prompt history. The epoch open is the
        // one instant every launch path already goes through, so the reset cannot be
        // forgotten by a caller, and the prompt clock restarts with it (the launch
        // path reads a delta, so an inherited total could only ever be over-counted).
        self.prompt_wait_millis.store(0, Ordering::Relaxed);
        let reset = {
            let slot = self
                .launch_reset
                .lock()
                .unwrap_or_else(|poison| poison.into_inner());
            slot.as_ref().map(|hook| Arc::clone(&hook.0))
        };
        // Fired after both locks are released: the callback belongs to another
        // component, and holding a listener lock across it invites a deadlock.
        if let Some(reset) = reset {
            reset();
        }
        Ok(epoch)
    }

    /// Close `epoch`'s window: it is frozen and becomes evictable. Traffic
    /// arriving afterwards is attributed nowhere. Returns whether `epoch` was
    /// the active one.
    pub fn close_epoch(&self, epoch: u64) -> bool {
        let mut state = self.lock();
        let was_active = state.active == Some(epoch);
        if was_active {
            state.active = None;
        }
        if let Some(entry) = state.epochs.get_mut(&epoch) {
            entry.closed = true;
        }
        was_active
    }

    /// The counters recorded for `epoch`, if the epoch was ever opened.
    pub fn counters(&self, epoch: u64) -> Option<LaunchProofCounters> {
        self.lock().epochs.get(&epoch).map(|entry| entry.counters)
    }

    /// The epoch a consultation would currently be attributed to.
    ///
    /// Test-only: no production caller needs to observe the window, and a
    /// reader that branched on it could only re-derive what `begin_epoch`
    /// already decided.
    #[cfg(test)]
    pub fn active_epoch(&self) -> Option<u64> {
        self.lock().active
    }

    /// How many epochs are remembered. Test-only: the bound is what the tests
    /// assert, and no production caller may depend on the map's size.
    #[cfg(test)]
    pub fn remembered_epochs(&self) -> usize {
        self.lock().epochs.len()
    }

    /// Count one proxy consultation (a CONNECT or an absolute-form request that
    /// reached this listener as a proxy).
    pub fn note_consultation(&self) {
        self.bump(|counters| counters.consultations += 1);
    }

    /// Add the wall clock ONE dialog cost (P2.1). Saturating in effect: `u64`
    /// milliseconds is ~584 million years of prompt time.
    ///
    /// Called once per LEADER — the consultation that actually spawned the dialog,
    /// which is what [`crate::net::prompt::PromptCoordinator::prompt_measured`]
    /// reports and a coalesced follower does not. Crediting per REQUEST added one
    /// dialog's wall clock K times (measured: 5.86x for six followers of one 155 ms
    /// dialog), so four concurrent requests to one unlisted host credited 240 s for
    /// 60 s of real blocking and a workload that genuinely overran was recorded as
    /// `prompt_budget_exhausted`.
    ///
    /// Still an aggregate: consultations on DIFFERENT hosts run concurrently, so the
    /// sum can legitimately exceed the session's wall clock. Anything that attributes
    /// a session to a term must therefore clamp it — see
    /// [`crate::net::mxc::SessionClock::measured`].
    pub fn note_prompt_wait(&self, waited: std::time::Duration) {
        let millis = u64::try_from(waited.as_millis()).unwrap_or(u64::MAX);
        self.prompt_wait_millis.fetch_add(millis, Ordering::Relaxed);
    }

    /// Time this listener's dialogs cost since the current launch began (P2.1): one
    /// credit per LEADER, reset at every epoch open, and never a share of wall clock
    /// (see [`LaunchCounters::note_prompt_wait`]). The launch path also takes a DELTA
    /// around one session, so a listener that serves several sequential launches
    /// attributes to each only its own prompt time.
    ///
    /// Read by the launch path (P2.1's session budget), which with the feature off
    /// has no biter: nothing in the binary consumes it yet, so the allow is scoped
    /// exactly like the epoch accessors above rather than hiding rot in the
    /// feature-on build.
    #[cfg_attr(not(any(test, feature = "mxc-backend")), allow(dead_code))]
    pub fn prompt_wait(&self) -> std::time::Duration {
        std::time::Duration::from_millis(self.prompt_wait_millis.load(Ordering::Relaxed))
    }

    /// Count one consultation whose **own upstream connection came up**. For
    /// CONNECT this is the dial behind `200 Connection Established`; for a
    /// plain-HTTP forward it is the forward's upstream dial. Never inferred
    /// from a status code.
    pub fn note_upstream_established(&self) {
        self.bump(|counters| counters.upstream_established += 1);
    }

    /// Count one **pre-flight probe** (ADR-0004 guardrail 1, amended
    /// 2026-10-22).
    ///
    /// The wrapper dials this listener's own control plane
    /// (`GET /sandbox/probe`) and reports back BEFORE the payload starts. It is
    /// recorded here, on the listener, rather than anywhere the workload can
    /// reach: a marker file or a counter in the container is forgeable, this is
    /// not. Only an authenticated probe reaches it — the token gate in
    /// `handle_conn` answers `407` before routing — so a probe under a foreign
    /// credential leaves no observation that could stand in for a broken path.
    pub fn note_probe(&self) {
        self.bump(|counters| counters.probes += 1);
    }

    /// Count one request this listener answered **without this run's credential**
    /// (P3.2a, ADR-0004 guardrail 1 amended a second time).
    ///
    /// Both refusal arms count: `no_token` (a client that never sends a
    /// `Proxy-Authorization` header) and `foreign_token` (one holding somebody
    /// else's). Lateral movement and a GUI client that cannot authenticate are
    /// the same signal here — *something in the container reached the proxy and
    /// could not use it* — and the arms stay separate only for their leaf budgets.
    ///
    /// Epoch-scoped by construction: [`LaunchCounters::bump`] writes to the active
    /// epoch's own [`LaunchProofCounters`], so a second launch on this listener
    /// starts at zero without a reset hook. Deliberately NOT the listener-lifetime
    /// [`RefusalBudget`] counters that drive the leaf budget (`no_token`/`foreign_token`
    /// on [`ConnCtx`]): those are per listener on purpose (the flood cap must
    /// survive launches), and reusing them would refuse launch N+1 on launch N's
    /// refusals.
    ///
    /// The wrapper's pre-flight probe authenticates with the run token, so it can
    /// never bump this — which is what makes `probes >= 1` and
    /// `unauthenticated == 0` independent evidence rather than one counter read
    /// twice.
    pub fn note_unauthenticated(&self) {
        self.bump(|counters| counters.unauthenticated += 1);
    }

    fn bump(&self, f: impl FnOnce(&mut LaunchProofCounters)) {
        let mut state = self.lock();
        if let Some(epoch) = state.active
            && let Some(entry) = state.epochs.get_mut(&epoch)
        {
            f(&mut entry.counters);
        }
    }
}

impl CounterState {
    /// Keep the map bounded **without ever dropping an epoch a live launch could
    /// still be proving against**: only closed epochs are evictable (P1.4).
    ///
    /// An open entry is live by definition (its launch has not read its proof
    /// yet), so it is kept even when the map is over the bound. In practice there
    /// is at most one open entry — `begin_epoch` refuses overlap — so the map
    /// holds `MAX_REMEMBERED_EPOCHS` closed entries plus that one.
    fn prune(&mut self) {
        while self.epochs.len() > MAX_REMEMBERED_EPOCHS {
            let Some(oldest) = self
                .epochs
                .iter()
                .filter(|(epoch, entry)| entry.closed && Some(**epoch) != self.active)
                .map(|(epoch, _)| *epoch)
                .min()
            else {
                return;
            };
            self.epochs.remove(&oldest);
        }
    }
}

/// Every proxy credential that is live in this process right now.
///
/// [`RunToken: Clone`](RunToken) means two `ProxyConfig`s *can* carry the same
/// value, and two listeners that accept one credential is exactly the ambiguity
/// P1.4 removed (which run's traffic was that?). It is unreachable today - one
/// mint per run in `main.rs` - but nothing in the type system said so, so the
/// check lives here instead of in a comment (P1.6(b)).
///
/// Keyed by the run **serial** ([`RunToken::run`]), never by the credential: a
/// process-global set is the last place a second copy of the secret belongs, and
/// the serial is exactly as discriminating — the token module's process-global
/// run counter makes it unique per process by construction, and a clone carries
/// the serial it was cloned from, so a clone of a live token still collides while
/// no copy of the value is retained anywhere.
/// Poison-tolerant, and the lock discipline is one rule — **the registry lock is
/// a leaf**: it is taken for one insert or one remove and never held across a
/// bind, an audit write, a lock the other side might take, or an `.await`. So it
/// cannot deadlock, and a panic elsewhere cannot wedge it (the guard is
/// recovered, house style).
///
/// Note what it is *not*: it does not stop the *same* `ProxyHandle` from serving
/// sequential launches (that is the epoch machinery), and releasing the token in
/// `Drop` does not wait for the old accept loop to drain - a re-spawned listener
/// with the same value may overlap a dying task for a few milliseconds. That is
/// the same credential and the same run, so it is attribution-neutral.
static LIVE_TOKENS: LazyLock<StdMutex<HashSet<u64>>> =
    LazyLock::new(|| StdMutex::new(HashSet::new()));

/// The registry lock, recovered from poisoning instead of panicking.
fn live_tokens() -> std::sync::MutexGuard<'static, HashSet<u64>> {
    LIVE_TOKENS
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
}

/// Record `token` as live, or refuse because another listener already serves it.
fn register_live_token(token: &RunToken) -> std::result::Result<(), TokenAlreadyLive> {
    if !live_tokens().insert(token.run()) {
        return Err(TokenAlreadyLive);
    }
    Ok(())
}

/// Forget `token`. Idempotent: a serial that is not registered is not an error.
fn release_live_token(token: &RunToken) {
    live_tokens().remove(&token.run());
}

/// Refusal for a second listener that would carry a credential already in use.
///
/// Deliberately holds **no field**: the value is a credential (nothing about it
/// belongs in an error string), and a run serial would be wrong for the case this
/// exists for - a clone of a live token is not a new run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenAlreadyLive;

impl fmt::Display for TokenAlreadyLive {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(
            "this run's proxy token is already live on another listener: one credential may \
             serve exactly one listener, so that a connection is attributable to one run - \
             spawn the second session with its own token",
        )
    }
}

impl std::error::Error for TokenAlreadyLive {}

/// The registration [`spawn`] takes before it binds anything.
///
/// Armed on construction and disarmed when the handle adopts it, so every early
/// return between the two (`?` on the runtime build, a failed bind handshake)
/// releases the credential instead of leaking it into the process-global set.
struct LiveTokenClaim {
    token: RunToken,
    armed: bool,
}

impl LiveTokenClaim {
    fn claim(token: &RunToken) -> std::result::Result<Self, TokenAlreadyLive> {
        register_live_token(token)?;
        Ok(Self {
            token: token.clone(),
            armed: true,
        })
    }

    /// Hand the registration to the returned [`ProxyHandle`], which releases it
    /// in `Drop`.
    fn into_handle(mut self) -> RunToken {
        self.armed = false;
        self.token.clone()
    }
}

impl Drop for LiveTokenClaim {
    fn drop(&mut self) {
        if self.armed {
            release_live_token(&self.token);
        }
    }
}

pub struct ProxyHandle {
    pub port: u16,
    /// This listener's per-launch attribution counters. The MXC launch path
    /// takes its proxy proof from exactly this instance (`mxc-backend`).
    ///
    /// Nothing reads it in a non-test build yet: the supervisor still refuses
    /// `--backend mxc` (`MXC_SESSION_WIRED = false`), so the first real caller is
    /// the P2 session wiring. The allow is scoped to non-test builds so rot in
    /// the live tests still surfaces.
    #[cfg_attr(not(test), allow(dead_code))]
    counters: Arc<LaunchCounters>,
    /// This listener's entry in [`LIVE_TOKENS`]: the credential it accepts,
    /// registered by [`spawn`] and released here. Holding it is what makes
    /// "one credential, one listener" true for the process, not just for a
    /// comment (P1.6(b)).
    live_token: RunToken,
    /// This listener's state, kept so `Drop` can write the trailing suppression
    /// aggregates. It cannot be left to the accept loop's exit path: the runtime
    /// is shut down with `shutdown_background`, which drops in-flight tasks
    /// instead of polling them, so "the task observed the cancellation" is not
    /// something this shutdown path may rely on.
    ctx: Arc<ConnCtx>,
    cancel: CancellationToken,
    rt: Option<Runtime>,
    join: Option<tokio::task::JoinHandle<()>>,
}

impl ProxyHandle {
    /// The proof source for this listener (ADR-0004 guardrail 1), for
    /// [`mxc::launch_session`](crate::net::mxc::launch_session).
    ///
    /// Non-test builds have no caller until the P2 session wiring lands; see the
    /// field's note.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn counters(&self) -> Arc<LaunchCounters> {
        Arc::clone(&self.counters)
    }

    /// Synchronously cancel the accept loop. The runtime is shut down
    /// cleanly in `Drop` (which calls `Runtime::shutdown_background` so
    /// the accept-loop task is reaped and the listening socket is
    /// released promptly — see AC-3.14). There is intentionally no
    /// `.await` of the JoinHandle here: `shutdown` may be called from a
    /// sync context (the supervisor is sync), and a JoinHandle cannot be
    /// awaited synchronously.
    ///
    /// Not invoked today: `main.rs` drops `ProxyHandle` directly (the
    /// `Drop` impl already cancels the accept loop). Kept for the
    /// graceful-shutdown path that lands with the proxy follow-up.
    #[allow(dead_code)]
    pub fn shutdown(&mut self) {
        self.cancel.cancel();
    }
}

impl Drop for ProxyHandle {
    fn drop(&mut self) {
        // 0. Release the credential. Last-statement ordering does not matter
        //    (nothing below can fail), but doing it first means a caller that
        //    re-spawns with the same token in the next statement is not racing
        //    this drop at all.
        release_live_token(&self.live_token);
        // 0b. Write whatever a spent refusal budget still owes the chain (the
        //     trailing partial window of each kind). Done here rather than in the
        //     accept task, which `shutdown_background` may drop unpolled.
        self.ctx.flush_refusal_aggregates();
        // 1. Signal the accept loop to break.
        self.cancel.cancel();
        // 2. Drop the JoinHandle (detaches the task; it will finish on
        //    its own once the cancelled select returns). We do NOT
        //    await it — Drop is sync.
        self.join = None;
        // 3. Shut the runtime down in the background. `shutdown_background`
        //    does not block the calling thread; it marks the runtime for
        //    shutdown and lets any in-flight tasks drain. Because the
        //    accept loop has already been cancelled (step 1) it will exit
        //    promptly, which lets the OS release the listening port — this
        //    is what satisfies AC-3.14 (port released within ~1s of exit).
        if let Some(rt) = self.rt.take() {
            rt.shutdown_background();
        }
    }
}

/// Spawn the proxy on a dedicated tokio runtime. Returns once the listener
/// is bound (so the caller knows the port before spawning the child
/// process). The runtime is owned by the returned `ProxyHandle` and is
/// shut down when the handle is dropped.
pub fn spawn(cfg: ProxyConfig) -> Result<ProxyHandle> {
    // `session_id` is retained in ProxyConfig for diagnostics/future use but
    // is not threaded into handle_conn: the AuditWriter holds the log path.
    let ProxyConfig {
        session_id: _session_id,
        token,
        allow_domain,
        deny_domain,
        writer,
        upstream,
        prompt,
        facade,
    } = cfg;
    // One credential, one listener (P1.6(b)). Claimed before a runtime or a
    // socket exists, so a refusal costs nothing and cannot leave a half-built
    // listener behind; `claim` is disarmed only when the handle takes it over.
    let claim = LiveTokenClaim::claim(&token)?;
    let counters = LaunchCounters::new();
    // P2.1 review round 2, item 2: the prompt fast-fail latch is per LISTENER but
    // must be per LAUNCH. This listener is the one place that owns both objects, so
    // it registers the coordinator's reset with the epoch machinery.
    {
        let coordinator = Arc::clone(&prompt.coordinator);
        counters.set_launch_reset(Arc::new(move || coordinator.begin_launch()));
    }
    let ctx = Arc::new(ConnCtx {
        token,
        deny: deny_domain,
        allow: allow_domain,
        writer,
        upstream,
        prompt,
        counters: Arc::clone(&counters),
        no_token: RefusalBudget::new(),
        foreign_token: RefusalBudget::new(),
        facade,
    });

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(1)
        .build()?;

    let (port_tx, port_rx) = oneshot::channel::<u16>();
    let cancel = CancellationToken::new();
    let cancel_for_task = cancel.clone();

    // Kept for `ProxyHandle::drop`, which writes the trailing suppression
    // aggregates itself - see the field's note.
    let ctx_for_handle = Arc::clone(&ctx);
    let join = rt.spawn(async move {
        let listener = match TcpListener::bind("127.0.0.1:0").await {
            Ok(l) => l,
            Err(e) => {
                eprintln!("[proxy] bind failed: {e}");
                let _ = port_tx.send(0);
                return;
            }
        };
        let port = listener.local_addr().ok().map(|a| a.port()).unwrap_or(0);
        let _ = port_tx.send(port);
        // Log the listening port under SAIFE_DIAG so integration tests
        // (S-36, S-38) can parse it from stderr.
        if std::env::var_os("SAIFE_DIAG").is_some() {
            eprintln!("[proxy] listening on 127.0.0.1:{port}");
        }

        let inflight = Arc::new(tokio::sync::Semaphore::new(MAX_INFLIGHT_CONNECTIONS));
        loop {
            tokio::select! {
                _ = cancel_for_task.cancelled() => break,
                accept = listener.accept() => {
                    let (sock, _peer) = match accept {
                        Ok(p) => p,
                        Err(_) => continue,
                    };
                    // Admit or refuse now: `try_acquire` never queues, so a flood
                    // cannot grow the wait list - the extra connection is closed.
                    let permit = match Arc::clone(&inflight).try_acquire_owned() {
                        Ok(p) => p,
                        Err(_) => {
                            drop(sock);
                            continue;
                        }
                    };
                    let ctx = Arc::clone(&ctx);
                    tokio::spawn(async move {
                        let _permit = permit; // released when the connection ends
                        let _ = handle_conn(sock, ctx).await;
                    });
                }
            }
        }
    });

    let port = port_rx.blocking_recv().context("proxy bind handshake")?;
    if port == 0 {
        anyhow::bail!("proxy failed to bind");
    }

    Ok(ProxyHandle {
        port,
        counters,
        live_token: claim.into_handle(),
        ctx: ctx_for_handle,
        cancel,
        rt: Some(rt),
        join: Some(join),
    })
}

/// What this listener made of a client's `Proxy-Authorization` credential.
///
/// Three outcomes rather than two, because the *audit* consequences differ
/// (P1.4): a credential this run does not own must not write into this run's
/// audit chain, while a request that carried no credential at all is worth a
/// leaf.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthVerdict {
    /// This run's own token: serve the request.
    OwnRun,
    /// No usable credential: the field is missing, the scheme is not `Basic`,
    /// the payload is not base64, or there is no `user:password` shape.
    Absent,
    /// A well-formed `Basic` credential carrying a password that is **not** this
    /// run's token. Another run's token and a guess are indistinguishable here,
    /// and neither is evidence about *this* run, so it is refused without a
    /// consultation count and without an audit leaf.
    Foreign,
}

/// The one `407` body both refusal arms send, so they answer byte-identically.
const AUTH_REQUIRED: &[u8] = b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"sandbox\"\r\nContent-Length: 0\r\n\r\n";

/// `GET /sandbox/probe`: the wrapper's pre-flight probe (ADR-0004
/// guardrail 1, amended 2026-10-22).
///
/// Origin-form like the D-4 intent endpoints, behind the same
/// `Proxy-Authorization` gate, and it records ONE probe observation in
/// the current launch epoch. It is deliberately not a second proxy: it
/// answers `204` and touches nothing else.
const PROBE_PATH: &str = "/sandbox/probe";

/// The one answer the probe endpoint gives: `204`, no body, and therefore no
/// `Content-Length` (RFC 9110 15.3.5 forbids a body on a 204).
const PROBE_NO_CONTENT: &[u8] = b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n";

/// Classify `Proxy-Authorization: Basic base64("sandbox:<token>")` against this
/// listener's own run token ([`RunToken::matches`], which is constant-time).
fn classify_auth(head: &str, expected: &RunToken) -> AuthVerdict {
    // Find the Proxy-Authorization header (case-insensitive).
    let auth_value = head.lines().skip(1).find_map(|l| {
        // Match the header name case-insensitively, but slice the *original*
        // line — base64 payload is case-sensitive.
        if l.to_ascii_lowercase().starts_with("proxy-authorization:") {
            Some(l["proxy-authorization:".len()..].trim().to_string())
        } else {
            None
        }
    });

    let Some(auth_value) = auth_value else {
        return AuthVerdict::Absent;
    };

    // Expect "Basic <base64>" — accept any whitespace (RFC 7230 allows 1*SP).
    let mut parts = auth_value.split_whitespace();
    let scheme = parts.next().unwrap_or("");
    let b64 = parts.next().unwrap_or("");
    if !scheme.eq_ignore_ascii_case("Basic") || b64.is_empty() {
        return AuthVerdict::Absent;
    }

    // Decode base64 -> "sandbox:<token>".
    let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(b64) else {
        return AuthVerdict::Absent;
    };
    let Ok(decoded_str) = std::str::from_utf8(&decoded) else {
        return AuthVerdict::Absent;
    };
    // No `user:password` shape is not a credential at all, so it is "absent"
    // rather than "foreign": there is nothing here that could even name a run.
    let Some((_, password)) = decoded_str.split_once(':') else {
        return AuthVerdict::Absent;
    };

    if expected.matches(password) {
        AuthVerdict::OwnRun
    } else {
        AuthVerdict::Foreign
    }
}

/// Map a deny reason to the `source` field of the D-5 audit taxonomy.
/// Metadata DNS names and CIDR/literal-IP denies are hard-denies
/// (non-negotiable, built into the binary); a `deny_domain` blocklist match
/// is the `blocklist` source ([G-32]); a host merely absent from the
/// allow-list is the `default` deny (will become `prompt` once the prompt
/// layer in D-3.5 intercepts unlisted hosts).
fn deny_source(reason: DenyReason) -> &'static str {
    match reason {
        DenyReason::DeniedDns | DenyReason::DeniedCidr => "hard-deny",
        DenyReason::DeniedDomain => "blocklist",
        DenyReason::DomainNotAllowed => "default",
    }
}

// =====================================================================
// Task 3.6 — dialing, formatting and outcome-mapping helpers. Pure
// (unit-tested above); `handle_conn` consumes them below.
// =====================================================================

/// Maximum concurrent dials per Happy Eyeballs batch ([G-12]
/// `maxParallelDials`, RFC 8305 race).
const MAX_PARALLEL_DIALS: usize = 8;

/// RFC 8305 §4 address ordering: alternate the two families, so a MAXIMAL
/// dual-stack answer (8+ addresses of each family) puts 4 IPv6 + 4 IPv4 in
/// the first batch instead of draining every IPv4 answer before any IPv6
/// dial starts. A single-family list keeps its resolver order.
///
/// There is deliberately no RFC 8305 §5 head start: every address in a batch
/// is dialed CONCURRENTLY, so the ONLY effect of this function is batch
/// composition and spawn order. It does not prefer a family at connect time.
///
/// Family is decided by `SocketAddr::is_ipv6()`, which counts an IPv4-mapped
/// `::ffff:a.b.c.d` as IPv6 — such an address takes an IPv6 slot and can lead
/// its batch. Harmless: `matcher::is_hard_denied_ip` unmaps before the
/// hard-deny check, and the kernel dials the embedded v4 target regardless.
fn interleave_families(addrs: Vec<SocketAddr>) -> Vec<SocketAddr> {
    let (v6, v4): (Vec<SocketAddr>, Vec<SocketAddr>) =
        addrs.into_iter().partition(SocketAddr::is_ipv6);
    if v6.is_empty() || v4.is_empty() {
        return v6.into_iter().chain(v4).collect();
    }
    let mut out = Vec::with_capacity(v6.len() + v4.len());
    let mut six = v6.into_iter();
    let mut four = v4.into_iter();
    loop {
        let a = six.next();
        let b = four.next();
        if a.is_none() && b.is_none() {
            break;
        }
        out.extend(a);
        out.extend(b);
    }
    out
}

/// Race the (DNS-pinned) address list in batches of [`MAX_PARALLEL_DIALS`]:
/// the first successful connection wins, stragglers are cancelled. A loser
/// that already connected is closed when its task is dropped — half-open
/// sockets are never spliced into a tunnel.
pub(crate) async fn happy_eyeballs_dial(addrs: Vec<SocketAddr>) -> io::Result<TcpStream> {
    happy_eyeballs_dial_with(addrs, TcpStream::connect).await
}

/// [`happy_eyeballs_dial`] with the connect operation injected.
///
/// `connect` is the ONLY way an address is dialed, so a test can observe the
/// two properties the race actually promises: (1) exactly which addresses are
/// attempted — the anti-rebinding pin, nothing outside the caller's
/// admission-resolved list can be dialed; and (2) that a losing attempt is
/// genuinely CANCELLED, by holding a drop probe across its await. Production
/// calls it with `TcpStream::connect`; there is no test-only parallel path.
async fn happy_eyeballs_dial_with<F, Fut>(
    addrs: Vec<SocketAddr>,
    connect: F,
) -> io::Result<TcpStream>
where
    F: Fn(SocketAddr) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = io::Result<TcpStream>> + Send + 'static,
{
    let addrs = interleave_families(addrs);
    let connect = Arc::new(connect);
    let mut last_err = None;
    for start in (0..addrs.len()).step_by(MAX_PARALLEL_DIALS) {
        let end = (start + MAX_PARALLEL_DIALS).min(addrs.len());
        let batch = &addrs[start..end];
        let (tx, mut rx) = mpsc::channel(batch.len());
        let mut spawned = Vec::with_capacity(batch.len());
        for &addr in batch {
            let tx = tx.clone();
            let connect = Arc::clone(&connect);
            spawned.push(tokio::spawn(async move {
                let _ = tx.send(connect(addr).await).await;
            }));
        }
        drop(tx);
        let mut winner = None;
        for _ in 0..batch.len() {
            match rx.recv().await {
                Some(Ok(s)) => {
                    winner = Some(s);
                    break;
                }
                Some(Err(e)) => last_err = Some(e),
                None => break,
            }
        }
        // Abort AND await. `abort` alone only *requests* cancellation, so a
        // loser's dial future (and the socket it may have opened) could outlive
        // this call; awaiting the aborted handle makes "cancelled" an
        // observable fact by the time the race returns.
        for h in &spawned {
            h.abort();
        }
        for h in spawned {
            let _ = h.await;
        }
        if let Some(s) = winner {
            return Ok(s);
        }
    }
    Err(last_err
        .unwrap_or_else(|| io::Error::new(io::ErrorKind::AddrNotAvailable, "no addresses to dial")))
}

/// Format a `SystemTime` as RFC3339 UTC ("2026-07-30T12:34:56Z") for the
/// GET /sandbox/intent `ts` field (D-4). Whole seconds: the registry
/// stores wall-clock times and sub-second precision adds nothing for an
/// advisory reason's age. Pre-epoch inputs clamp to the epoch.
pub(crate) fn rfc3339_utc(ts: std::time::SystemTime) -> String {
    let secs = ts
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    // Civil date from days since 1970-01-01 (Howard Hinnant's
    // days_from_civil inverse, same algorithm as the session-id date).
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let (y, m) = if m <= 2 { (y + 1, m) } else { (y, m) };
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// The audit-side view of a coordinator outcome: disposition, D-5
/// `source`, `scope`, and whether the decision wants persistence. Pure
/// so the mapping is unit-testable; `prompt_default` combines it with the
/// learned-store write (`persisted = wants_persist && write succeeded`).
struct OutcomeAudit {
    allowed: bool,
    source: &'static str,
    scope: Option<String>,
    wants_persist: bool,
}

fn outcome_audit(outcome: &PromptOutcome) -> OutcomeAudit {
    match outcome {
        PromptOutcome::Decided(PromptResult::Allow { persist, scope, .. }) => OutcomeAudit {
            allowed: true,
            source: "prompt",
            scope: Some(if *persist {
                scope.clone()
            } else if scope == "session" {
                // Not persisted, but not a one-off either: the audit has to tell a
                // standing session answer from a single click, or a reader cannot
                // explain why a host stopped prompting.
                "session".to_string()
            } else {
                "once".to_string()
            }),
            wants_persist: *persist,
        },
        PromptOutcome::Decided(PromptResult::Deny { persist, scope, .. }) => OutcomeAudit {
            allowed: false,
            source: "prompt",
            scope: Some(if *persist {
                scope.clone()
            } else if scope == "session" {
                // Not persisted, but not a one-off either: the audit has to tell a
                // standing session answer from a single click, or a reader cannot
                // explain why a host stopped prompting.
                "session".to_string()
            } else {
                "once".to_string()
            }),
            wants_persist: *persist,
        },
        PromptOutcome::Decided(PromptResult::NeedsIntent) => OutcomeAudit {
            allowed: false,
            source: "prompt",
            scope: None,
            wants_persist: false,
        },
        PromptOutcome::Overloaded { .. } => OutcomeAudit {
            allowed: false,
            source: "prompt_overload",
            scope: None,
            wants_persist: false,
        },
        PromptOutcome::Unavailable { allowed, .. } => OutcomeAudit {
            allowed: *allowed,
            source: "unavailable",
            scope: None,
            wants_persist: false,
        },
        PromptOutcome::Disabled => OutcomeAudit {
            allowed: false,
            source: "default",
            scope: None,
            wants_persist: false,
        },
    }
}

/// One D-1 pipeline outcome, carrying its D-5 audit fields.
struct Decision {
    allowed: bool,
    source: &'static str,
    scope: Option<String>,
    persisted: bool,
    reason: Option<String>,
    /// Denials on the "Explain more" path add `X-Sandbox-Intent-Hint`
    /// ([G-52]): the click rides the intent registry, not the body (a
    /// CONNECTing client may discard response bodies).
    intent_hint: bool,
}

impl Decision {
    /// Post-admission DNS failure ([G-12]): fail-closed.
    fn dns_failure(reason: &str) -> Self {
        Decision {
            allowed: false,
            source: "dns",
            scope: None,
            persisted: false,
            reason: Some(reason.to_string()),
            intent_hint: false,
        }
    }
}

/// A deny straight from a matcher reason (hard-deny / blocklist).
fn denied_by(reason: DenyReason) -> Decision {
    Decision {
        allowed: false,
        source: deny_source(reason),
        scope: None,
        persisted: false,
        reason: Some(reason.as_str().to_string()),
        intent_hint: false,
    }
}

/// Best-effort audit emission for one decision (D-5.2 kept the wrapper
/// non-fatal: an audit I/O error must not change the policy answer).
fn emit_decision(writer: &AuditWriter, host: &str, port: u16, d: &Decision) {
    let _ = emit_connect(
        writer,
        host,
        port,
        if d.allowed { "allow" } else { "deny" },
        d.reason.as_deref(),
        d.source,
        d.scope.as_deref(),
        d.persisted,
        // A decision is one request: nothing is suppressed about it.
        None,
    );
}

/// The D-1 decision pipeline (plan Task 3.6 Step 1, substeps 2-7). The
/// order is load-bearing: it decides which layer a user's remediation
/// targets, and it guarantees the prompt is only ever shown for hosts no
/// static rule already answered.
async fn decide(ctx: &ConnCtx, host: &str, port: u16) -> Decision {
    // (2) Loopback CONNECT is refused outright, before anything that
    // could prompt: the sandbox must never reach services on its own
    // host [G-44]. Dedicated `loopback_refused` reason so the audit can
    // distinguish it from the hard-deny IP set that also covers the
    // literal forms.
    if is_loopback_host(host) {
        return Decision {
            allowed: false,
            source: "hard-deny",
            scope: None,
            persisted: false,
            reason: Some("loopback_refused".into()),
            intent_hint: false,
        };
    }
    // (3) Hard-deny — non-negotiable, built into the binary ([G-18,
    // G-45]): metadata DNS names first, then literal-IP forms. The
    // resolved-IP leg runs post-admission on the DNS-pinned set.
    if matcher::is_hard_denied_host(host) {
        return denied_by(DenyReason::DeniedDns);
    }
    if let Some(ip) = parse_host_ip(host)
        && matcher::is_hard_denied_ip(ip)
    {
        return denied_by(DenyReason::DeniedCidr);
    }
    // (4) Learned permanent deny — a past user decision outranks both
    // the blocklist and the allow-list [G-33].
    let learned = ctx
        .prompt
        .learned
        .lock()
        .expect("learned store lock poisoned")
        .lookup(host);
    if let Some(LearnedDecision {
        allow: false,
        scope,
    }) = &learned
    {
        return Decision {
            allowed: false,
            source: "learned",
            scope: Some(scope.clone()),
            persisted: true,
            reason: Some("learned deny".into()),
            intent_hint: false,
        };
    }
    // (5)+(6) deny_domain blocklist, then allow_domain — through the
    // single matching implementation so the [G-55] wildcard rule is not
    // duplicated. `ips` is empty: the hard-deny IP leg already ran and
    // the post-admission pinned-set check covers the resolved forms.
    match matcher::check(host, &[], &ctx.deny, &ctx.allow) {
        Verdict::Deny(DenyReason::DeniedDomain) => return denied_by(DenyReason::DeniedDomain),
        Verdict::Allow => {
            return Decision {
                allowed: true,
                source: "allowlist",
                scope: None,
                persisted: false,
                reason: None,
                intent_hint: false,
            };
        }
        // Defensive: unreachable while `ips` is empty and hard-deny has
        // already run above — kept so a future edit to `check` cannot
        // open a silent-allow hole [G-46, G-48].
        Verdict::Deny(reason @ (DenyReason::DeniedDns | DenyReason::DeniedCidr)) => {
            return denied_by(reason);
        }
        // Not on any list: fall through to learned-allow / prompt.
        Verdict::Deny(DenyReason::DomainNotAllowed) => {}
    }
    // (6) Learned permanent allow [G-33 step 4].
    if let Some(LearnedDecision { allow: true, scope }) = &learned {
        return Decision {
            allowed: true,
            source: "learned",
            scope: Some(scope.clone()),
            persisted: true,
            reason: None,
            intent_hint: false,
        };
    }
    // (7) Default: ask the user — or apply the no-prompt policy.
    prompt_default(ctx, host, port).await
}

/// Step 1 substep (7): the default branch. `prompt_enabled` is checked
/// BEFORE the coordinator call ([G-36, G-47]) — the coordinator only
/// models the zero-timeout `Disabled` form.
async fn prompt_default(ctx: &ConnCtx, host: &str, port: u16) -> Decision {
    if !ctx.prompt.enabled {
        // [G-48] fail-closed unless the profile explicitly opts into
        // on_unavailable=allow.
        let allowed = ctx.prompt.config.on_unavailable == PromptPolicy::Allow;
        return Decision {
            allowed,
            source: "default",
            scope: None,
            persisted: false,
            reason: if allowed {
                None
            } else {
                Some("prompting disabled; host not allow-listed".into())
            },
            intent_hint: false,
        };
    }
    // [G-17] Enrich the dialog with the agent's declared reason, if any.
    let reason = ctx.prompt.intent.lookup_host(host).await.map(|e| e.reason);
    // P2.1: the consultation's cost is attributed from what the coordinator
    // measured, so a session killed by its deadline reports
    // `prompt_budget_exhausted` only if a prompt really did eat its term. One
    // measurement point because both legs — CONNECT and the absolute-form forward —
    // reach the prompt through here.
    //
    // Round 2, item 1: the credit is the LEADER's and nobody else's. Timing this
    // call (per REQUEST) made K coalesced followers of one dialog each add its wall
    // clock — four concurrent requests to one host crediting 240 s for 60 s of
    // blocking, which recorded a workload that genuinely overran as a prompt
    // timeout. `None` means this request led no dialog (a follower, a skipped latch,
    // a refused pool), so it has nothing to credit.
    let (outcome, leader_wait) = ctx
        .prompt
        .coordinator
        .prompt_measured(host, port, reason, ctx.prompt.config)
        .await;
    if let Some(waited) = leader_wait {
        ctx.counters.note_prompt_wait(waited);
    }
    // Outcome side effects that are not the decision itself.
    if let PromptOutcome::Decided(PromptResult::NeedsIntent) = &outcome {
        // omac's recovery loop: the "Explain more" click rides the intent
        // registry (the deny body may be discarded by the client); the
        // agent's next GET /sandbox/intent observes the one-shot flag.
        ctx.prompt.intent.mark_explain_more(host).await;
    }
    if let PromptOutcome::Unavailable {
        allowed: false,
        cause,
    } = &outcome
    {
        // [G-19] one discoverable stderr line, once per process — and now one
        // line per CAUSE (P2.1): "no dialog backend" and "the budget elapsed
        // with no answer" are different failures with different remediations,
        // and a headless run used to report the first while suffering the
        // second.
        match cause {
            // Item 8: a suppressed latch that was armed by elapsed budgets is a
            // budget fact, so it shares the budget line; only a missing backend
            // warns about a missing backend.
            UnavailableCause::BudgetElapsed | UnavailableCause::SuppressedAfterBudget => {
                warn_prompt_budget_once(ctx.prompt.config.timeout)
            }
            UnavailableCause::NoDialogBackend | UnavailableCause::CallerGone => {
                warn_no_dialog_once()
            }
        }
    }
    let audit = outcome_audit(&outcome);
    // Persist permanent decisions to the learned store [G-56]. The
    // audit `persisted` flag reports whether the write actually landed.
    let mut persisted = false;
    if audit.wants_persist
        && let PromptOutcome::Decided(
            PromptResult::Allow { scope, suffix, .. } | PromptResult::Deny { scope, suffix, .. },
        ) = &outcome
    {
        let allow = matches!(outcome, PromptOutcome::Decided(PromptResult::Allow { .. }));
        persisted = record_learned(ctx, host, scope, suffix.as_deref(), allow);
    }
    let reason = match &outcome {
        PromptOutcome::Decided(PromptResult::Deny { .. }) => Some("denied by user".into()),
        PromptOutcome::Decided(PromptResult::NeedsIntent) => {
            Some("user requested a fuller intent (explain more)".into())
        }
        // P2.1 review: the two pools are different facts, so the denial names
        // which one ran out instead of reporting a concurrency limit for a
        // session whose dialogs are merely unanswered.
        PromptOutcome::Overloaded { cause } => Some(overload_reason(*cause).into()),
        // P2.1: a spent budget and a backend that could not show a dialog are
        // distinct reasons a reader can act on — the first says this session's
        // prompt term was consumed (the supervisor budgets the container around
        // it), the second says the machine has no dialog at all.
        PromptOutcome::Unavailable {
            allowed: false,
            cause,
        } => Some(match cause {
            UnavailableCause::BudgetElapsed => PROMPT_TIMEOUT_REASON.into(),
            // Item 8: the two arming causes keep their own strings. A suppressed
            // budget is not a missing backend — the dialog was shown and nobody
            // answered it — and an operator greps exactly this.
            UnavailableCause::SuppressedAfterBudget => PROMPT_SUPPRESSED_REASON.into(),
            UnavailableCause::NoDialogBackend => NO_DIALOG_BACKEND_REASON.into(),
            UnavailableCause::CallerGone => "prompt unavailable (caller gone)".into(),
        }),
        _ => None,
    };
    Decision {
        allowed: audit.allowed,
        source: audit.source,
        scope: audit.scope,
        persisted,
        reason,
        intent_hint: matches!(outcome, PromptOutcome::Decided(PromptResult::NeedsIntent)),
    }
}

/// Persist a permanent dialog decision to the learned store [G-56].
/// Host-scope entries are keyed by the same normalization the intent
/// registry and the prompt coalescing map use, so all three layers agree
/// on one key; a suffix-scope entry stores the suffix itself (the store
/// matches it against the apex and every subdomain). Returns false —
/// with a stderr warning — if the atomic write fails, keeping the audit
/// `persisted` flag honest.
fn record_learned(
    ctx: &ConnCtx,
    host: &str,
    scope: &str,
    suffix: Option<&str>,
    allow: bool,
) -> bool {
    let entry_host = match (scope, suffix) {
        ("suffix", Some(s)) => crate::net::intent::normalize_host(s),
        _ => crate::net::intent::normalize_host(host),
    };
    let mut store = ctx
        .prompt
        .learned
        .lock()
        .expect("learned store lock poisoned");
    match store.record(&entry_host, scope, allow) {
        Ok(()) => true,
        Err(e) => {
            eprintln!("[saife] warning: failed to persist learned decision for {entry_host}: {e}");
            false
        }
    }
}

/// [G-19] One stderr line, once per process, the first time a prompt is
/// unavailable while the policy denies. A headless run otherwise looks
/// like an unexplained block; this names the cause and the remediations.
fn warn_no_dialog_once() {
    static WARNED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    if !WARNED.swap(true, std::sync::atomic::Ordering::SeqCst) {
        eprintln!(
            "[saife] no dialog backend available — denying; pre-approve hosts via \
             --allow-domain, or set on_unavailable=allow (insecure); set SAIFE_DIAG=1 for details"
        );
    }
}

/// P2.1: the same once-per-process courtesy for the OTHER cause — the prompt
/// budget elapsed with the dialog unanswered.
///
/// The budget is the session's own prompt term (the container's `timeout_ms` is
/// sized around it), so an elapsed budget on a headless request is a *policy*
/// answer, not a broken machine: the request was denied on budget. Saying so
/// once turns "the agent hung for a minute and then failed" into a line an
/// operator can act on (pre-approve the host, or raise `limits.promptTimeoutSecs`).
fn warn_prompt_budget_once(budget: std::time::Duration) {
    static WARNED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    if !WARNED.swap(true, std::sync::atomic::Ordering::SeqCst) {
        eprintln!(
            "[saife] prompt budget elapsed ({}s) with no answer — denying on budget; \
             pre-approve hosts via --allow-domain, or raise limits.promptTimeoutSecs",
            budget.as_secs()
        );
    }
}

/// The [G-52] deny response: 403 + `X-Sandbox: denied` + a plain-text
/// body naming the host, the policy layer, the reason, and the
/// remediation paths (profile, allow-list, learned file). Intent-related
/// denials add `X-Sandbox-Intent-Hint`.
async fn respond_deny(sock: &mut TcpStream, host: &str, port: u16, d: &Decision) -> Result<()> {
    let reason = d.reason.as_deref().unwrap_or("denied");
    let body = format!(
        "sandbox: CONNECT to {host}:{port} was denied by the {source} policy ({reason}).\n\
         Remediation: add the host to --allow-domain or the profile allowDomain list,\n\
         or adjust the learned policy (profile / learned file).\n",
        source = d.source,
    );
    let mut resp = String::from("HTTP/1.1 403 Forbidden\r\nX-Sandbox: denied\r\n");
    if d.intent_hint {
        resp.push_str("X-Sandbox-Intent-Hint: explain-more\r\n");
    }
    resp.push_str(&format!(
        "Content-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    ));
    sock.write_all(resp.as_bytes()).await?;
    Ok(())
}

/// DNS-pin the CONNECT target (Step 2, [G-12]): resolve once into the
/// candidate address list; that exact list is what gets dialed, so a
/// mid-session DNS poison cannot redirect an already-admitted host.
/// Literal IPs never touch the resolver.
///
/// `lookup` is the resolver ([`system_lookup`] in production). It is injected
/// because the literal-IP short-circuit and the single-lookup shape live HERE,
/// ahead of the seam: a test that passes a counting resolver pins the real
/// production path, not a copy of it — a literal host must not call `lookup` at
/// all, and a hostname must call it exactly once and keep its answer verbatim
/// (brackets stripped; case and trailing dot untouched — the resolver owns
/// name normalization).
///
/// `Fut: Send` is a documented CONTRACT, not incidental: production passes
/// [`system_lookup`], whose future is `Send`, and `handle_conn` (the caller)
/// is spawned. Without the bound a non-`Send` resolver would still reach a
/// working monomorphization for synchronous tests and only explode at the
/// spawn site, with an error naming tokio rather than this seam — so the
/// bound is stated here.
async fn resolve_pinned_with<F, Fut>(
    host: &str,
    port: u16,
    lookup: F,
) -> io::Result<Vec<SocketAddr>>
where
    F: FnOnce(String, u16) -> Fut,
    Fut: Future<Output = io::Result<Vec<SocketAddr>>> + Send,
{
    let h = strip_host_brackets(host.trim());
    if let Ok(ip) = h.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    lookup(h.to_string(), port).await
}

/// The real resolver — the one DNS lookup per admitted hostname ([G-12]).
async fn system_lookup(host: String, port: u16) -> io::Result<Vec<SocketAddr>> {
    tokio::net::lookup_host((host, port))
        .await
        .map(|it| it.collect())
}

/// Strip IPv6 brackets from a CONNECT host, if present.
fn strip_host_brackets(host: &str) -> &str {
    host.strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host)
}

/// Parse a host as a literal IP (brackets allowed) — the hard-deny IP
/// leg of the pipeline.
fn parse_host_ip(host: &str) -> Option<IpAddr> {
    strip_host_brackets(host.trim()).parse().ok()
}

/// Fail-closed verdict for the pinned (admission-resolved) address set
/// ([G-12, G-45]): if ANY resolved address lies in a hard-denied CIDR —
/// link-local / metadata — the whole request is denied as `denied_cidr`
/// before a single dial, so a hostname cannot serve as a bridge into a
/// link-local range ([G-22] keeps this leg on the DIRECT path only; chained
/// dials are hostname-only and never produce a pinned set).
///
/// Pure over `&[SocketAddr]`, so the leg is testable with any address list
/// (no resolver seam needed) and the production dial path calls exactly this.
fn pinned_addrs_hard_denied(addrs: &[SocketAddr], permit_loopback: bool) -> Option<Decision> {
    // [G-44]: the proxy must not become a tunnel to host services, and a host-STRING
    // check cannot enforce that - `localtest.me` and `127.0.0.1.nip.io` are public
    // DNS names that resolve to 127.0.0.1, so the operator is shown a harmless name
    // and the workload reaches the Docker API, Ollama or a DevTools port. The pinned
    // set is the first point where the actual destination is known, so the refusal
    // belongs here. Same reason token as the string leg, so the audit record reads
    // the same whichever way the loopback was expressed.
    if !permit_loopback
        && addrs
            .iter()
            .any(|sa| crate::net::matcher::is_loopback_or_unspecified(sa.ip()))
    {
        let mut d = denied_by(DenyReason::DeniedCidr);
        d.reason = Some("loopback_refused".into());
        return Some(d);
    }
    if pinned_addrs_contain_hard_denied(addrs) {
        return Some(denied_by(DenyReason::DeniedCidr));
    }
    None
}

/// The bare predicate behind [`pinned_addrs_hard_denied`]: does ANY address in
/// the pinned set lie in a hard-denied CIDR?
///
/// Split out as `pub(crate)` for exactly one caller — the debug-only
/// defence-in-depth assert in `upstream::DirectDialer::dial` (Task 5.2 spec
/// advisory 3), which must be able to reuse this check without the audit
/// `Decision` type. Sharing the predicate (not a copy) keeps the proxy seam and
/// the direct-dialer seam from drifting apart.
pub(crate) fn pinned_addrs_contain_hard_denied(addrs: &[SocketAddr]) -> bool {
    addrs.iter().any(|sa| matcher::is_hard_denied_ip(sa.ip()))
}

/// How many connections may be in flight at once. The listener is reachable by any
/// local process, including the sandboxed child, so an unbounded spawn-per-connection
/// loop is a local denial of service in the containment root: open sockets, send
/// nothing, and the supervisor allocates a task and a descriptor per connection.
/// 128 leaves room for a browser's parallel connections across hosts.
#[cfg(not(test))]
const MAX_INFLIGHT_CONNECTIONS: usize = 128;
/// Test builds use a small cap so the refusal can be observed without opening 129
/// sockets; the accept path is identical, only the constant differs.
#[cfg(test)]
const MAX_INFLIGHT_CONNECTIONS: usize = 32;

/// How long a connection may take to deliver a complete request head. Without it a
/// silent client parks a task forever - the same local DoS by a slower route.
const HEAD_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// Offset just past the first `\r\n\r\n` in `buf`, if the head is complete.
fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

/// host:port from a CONNECT target. A missing port means 443, as the method
/// allows; ANYTHING ELSE THAT DOES NOT PARSE IS `None`, and the caller answers
/// 400. The previous version used `p.parse().unwrap_or(443)`, so `host:notaport`,
/// `host:` and `host:70000` were silently retried on 443 - a typo turned into a
/// different request than the one the workload asked for. Unbracketed IPv6 is
/// refused for the same reason: it cannot be split unambiguously.
fn parse_connect_target(target: &str) -> Option<(String, u16)> {
    let (host, port) = match target.rsplit_once(':') {
        Some((h, p)) => (h, p),
        None => (target, "443"),
    };
    let bracketed = host.starts_with('[') && host.ends_with(']');
    if host.is_empty() || (host.contains(':') && !bracketed) {
        return None;
    }
    let port: u16 = port.parse().ok()?;
    if port == 0 {
        return None;
    }
    Some((host.to_string(), port))
}

// =====================================================================
// Task 4.2 — upstream chaining in the dial path ([G-22, G-30, G-49])
// =====================================================================

/// Why the post-admission dial produced no tunnel.
enum DialFailure {
    /// Direct path: the pinned answer was empty, resolution failed, or a
    /// pinned address is hard-denied — a fail-closed denial ([G-12]).
    Denied(Decision),
    /// Direct path: no connection could be made. Unchanged 3.6 behaviour —
    /// a bare `502` and no extra audit leaf.
    Direct(io::Error),
    /// Upstream chaining failed ([G-30]): `endpoint` and `body` name the
    /// proxy as `host:port` only, `error` carries the path-neutral reason.
    Upstream {
        endpoint: String,
        body: String,
        error: UpstreamError,
    },
}

/// Resolve (or deliberately not) and dial the admitted CONNECT target.
///
/// Chained (`upstream.is_some() && chains_host(host)`): hostname-only
/// admission — no [`resolve_pinned_with`], no DNS-failure denial, no pinned-IP
/// hard-deny ([G-22]). The upstream proxy resolves the name itself, and a
/// local answer could disagree with what it sees. The hostname-set and
/// IP-literal hard-denies already ran in [`decide`] before admission and need
/// no DNS, so they still apply here.
///
/// Direct: pin once ([G-12]), hard-deny the pinned set, then race the addresses
/// with Happy Eyeballs ([G-49] keeps that path intact).
///
/// `lookup` is the resolver ([`system_lookup`] in production). Injecting it
/// here — rather than only into [`resolve_pinned_with`] — is what makes the
/// [G-12] promise observable at the REAL call site: one resolution per
/// admitted host, and the dial sees nothing but that answer. Unused on the
/// chained branch by design.
///
/// `Fut: Send` mirrors [`resolve_pinned_with`]: this future is awaited inside
/// `handle_conn`, which is spawned, so a resolver whose future is not `Send`
/// must be rejected here — by name — instead of at the spawn site.
async fn dial_upstream<F, Fut>(
    upstream: Option<&UpstreamDialer>,
    host: &str,
    port: u16,
    // `false` in every production path: loopback and the unspecified address are
    // refused so the proxy cannot become a tunnel to host services ([G-44]). The
    // dial-mechanics tests pass `true` because their only upstream is a local
    // stand-in server; that is a property of the test fixture, not of the product.
    permit_loopback: bool,
    lookup: F,
) -> Result<TcpStream, DialFailure>
where
    F: FnOnce(String, u16) -> Fut,
    Fut: Future<Output = io::Result<Vec<SocketAddr>>> + Send,
{
    // One normalization, used by every branch below. `parse_connect_target`
    // keeps an IPv6 literal's brackets, but `chains_host`/`host_matches_no_proxy`
    // compare bare names and `host_port` re-brackets for the CONNECT line — so
    // a decision taken on the bracketed form would disagree with the dial's own
    // `NO_PROXY` re-check (bypass missed here, taken there: direct dial with no
    // pinned addresses, reported as an unreachable proxy).
    let host = strip_host_brackets(host.trim());

    if let Some(dialer) = upstream.filter(|u| u.chains_host(host)) {
        // The pinned list is empty on purpose: under chaining it is never
        // consulted ([G-22]).
        return dialer
            .dial(host, port, &[])
            .await
            .map_err(|error| DialFailure::Upstream {
                endpoint: dialer.proxy_endpoint(),
                body: upstream_error_body(host, port, &dialer.proxy_endpoint(), &error),
                error,
            });
    }

    let addrs = match resolve_pinned_with(host, port, lookup).await {
        Ok(a) if a.is_empty() => {
            return Err(DialFailure::Denied(Decision::dns_failure(
                "DNS resolution returned no addresses",
            )));
        }
        Ok(a) => a,
        Err(e) => {
            return Err(DialFailure::Denied(Decision::dns_failure(&format!(
                "DNS resolution failed: {e}"
            ))));
        }
    };
    // The pinned IP set gets the hard-deny check too: a hostname that resolves
    // into a hard-denied range is refused before any dial (fail-closed
    // [G-12, G-45]).
    if let Some(d) = pinned_addrs_hard_denied(&addrs, permit_loopback) {
        return Err(DialFailure::Denied(d));
    }

    happy_eyeballs_dial(addrs)
        .await
        .map_err(DialFailure::Direct)
}

/// The [G-30] `502` body: target, the proxy as `host:port`, and the
/// path-neutral `Display` reason. Never the proxy URL, its userinfo, or the
/// `Proxy-Authorization` value.
fn upstream_error_body(host: &str, port: u16, endpoint: &str, error: &UpstreamError) -> String {
    format!(
        "sandbox: CONNECT to {host}:{port} could not be established through the upstream \
         proxy {endpoint} ({error}).\n\
         Remediation: check that the upstream proxy is reachable and that \
         network.upstreamProxy / HTTPS_PROXY is correct, or add the host to \
         NO_PROXY to dial it directly.\n"
    )
}

/// The `upstream_error` audit leaf. A transport failure is not a policy
/// answer, but it rides the existing `default` source and a free-form
/// `reason`, so the D-5 taxonomy needs no new value (plan 4.2 Step 3).
fn upstream_error_decision() -> Decision {
    Decision {
        allowed: false,
        source: "default",
        scope: None,
        persisted: false,
        reason: Some("upstream_error".into()),
        intent_hint: false,
    }
}

/// Write the [G-30] `502`: `X-Sandbox: upstream-error` plus the redacted body.
async fn respond_upstream_error(sock: &mut TcpStream, body: &str) {
    write_response(
        sock,
        "502 Bad Gateway",
        "X-Sandbox: upstream-error\r\nConnection: close\r\n",
        body,
    )
    .await;
}

/// Handle one client connection: token gate, then either the CONNECT
/// pipeline (D-1) or the /sandbox/* routing (D-4).
async fn handle_conn(mut sock: TcpStream, ctx: Arc<ConnCtx>) -> Result<()> {
    // Read the request head (up to 8 KiB, terminated by \r\n\r\n). Bytes
    // past the terminator may be a request body — `head_end` keeps them
    // apart so the intent endpoints can read them.
    let read_head = async {
        let mut buf = vec![0u8; 8192];
        let mut filled = 0;
        let mut head_end = None;
        loop {
            if filled >= buf.len() {
                break;
            }
            let n = sock.read(&mut buf[filled..]).await.unwrap_or(0);
            if n == 0 {
                break;
            }
            filled += n;
            if let Some(pos) = find_head_end(&buf[..filled]) {
                head_end = Some(pos);
                break;
            }
        }
        (buf, filled, head_end)
    };
    let (buf, filled, head_end) = match tokio::time::timeout(HEAD_READ_TIMEOUT, read_head).await {
        Ok(v) => v,
        Err(_) => {
            // A client that opens a connection and says nothing used to park a task
            // and a descriptor indefinitely.
            let _ = sock
                .write_all(b"HTTP/1.1 408 Request Timeout\r\nContent-Length: 0\r\n\r\n")
                .await;
            return Ok(());
        }
    };
    let head_end = head_end.unwrap_or(filled);
    let head = std::str::from_utf8(&buf[..head_end]).unwrap_or("");
    let leftover: &[u8] = &buf[head_end..filled];

    // Parse the request line.
    let first_line = head.lines().next().unwrap_or("");
    let mut parts = first_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");

    // Token gate: the same session token guards CONNECT and every
    // /sandbox/* endpoint ([G-7, G-38]). This listener accepts exactly one
    // credential — its own run's (P1.4).
    match classify_auth(head, &ctx.token) {
        AuthVerdict::OwnRun => {}
        AuthVerdict::Absent => {
            // P3.2a: counted on this launch's epoch BEFORE the answer, so the gate
            // can tell "no workload" from "a workload that could not authenticate".
            // Both refusal arms count; this one is the WinINet / system-proxy shape.
            ctx.counters.note_unauthenticated();
            // The response is the same 407 for every credential-less request;
            // only the audit footprint is budgeted (P1.6(a)). Without the cap a
            // loop of these writes one leaf per connection (measured: 400
            // connections -> 400 leaves, 129 KB), and P1.8 made that the *normal*
            // case - every managed client's first attempt on a connection is
            // credential-less, so `no_token` stopped being a signal at all.
            //
            // Audit BEFORE responding, the rule the deny path already states: the
            // append is synchronous, so whoever observes the 407 also observes
            // the leaf. Responding first left a window in which a refusal was on
            // the wire and nothing was in the chain yet - which the P1.4 live test
            // asserted against and lost to twice while P1.6 re-ran it.
            match ctx.no_token.spend() {
                RefusalLeaf::Individual => {
                    let _ = emit_connect(
                        &ctx.writer,
                        "<unknown>",
                        0,
                        "deny",
                        Some("no_token"),
                        "default",
                        None,
                        false,
                        None,
                    );
                }
                RefusalLeaf::Aggregate { suppressed } => {
                    // One leaf per full window of suppressed refusals, carrying
                    // the exact number it stands in for. `scope` stays `null`:
                    // its domain is rule scope, and a count there would make a
                    // scope filter read a number.
                    //
                    // Best effort, and honestly so: `append` on this non-strict
                    // writer swallows I/O errors (`audit::AuditWriter::append`),
                    // so what the leaf records is an ATTEMPTED count, not a
                    // guaranteed one. There is no retry by design — a retry queue
                    // on the refusal path is the cost this budget exists to
                    // avoid — and the window was re-armed by `spend` only as this
                    // append was about to be attempted.
                    let _ = emit_connect(
                        &ctx.writer,
                        "<unknown>",
                        0,
                        "deny",
                        Some("no_token_suppressed"),
                        "default",
                        None,
                        false,
                        Some(u32::try_from(suppressed).unwrap_or(u32::MAX)),
                    );
                }
                RefusalLeaf::Nothing => {}
            }
            let _ = sock.write_all(AUTH_REQUIRED).await;
            return Ok(());
        }
        AuthVerdict::Foreign => {
            // P3.2a: same signal as the `Absent` arm - something reached this
            // listener without this run's credential. Lateral movement and a client
            // stack that cannot authenticate are one question for the gate ("could
            // anything here USE the proxy?"); the arms stay separate only for their
            // leaf budgets.
            ctx.counters.note_unauthenticated();
            // Refused and uncounted, but RECORDED (P1.4 review): a credential
            // that is not this run's is lateral movement, and leaving it
            // invisible in BOTH chains made the one deliberate security event
            // the only one with no evidence. The leaf names no host and never
            // the credential, and because it is not a consultation it can
            // neither satisfy guardrail 1 nor reach `decide()`.
            //
            // Audited before the 407 goes out, for the same reason as the
            // `Absent` arm: the two arms must be indistinguishable to the
            // client, including in what the chain contains by the time the
            // response is readable.
            //
            // Budgeted exactly like the `Absent` arm, with its OWN counter and
            // its own reason (P1.6, blocking 2): without it the flood is one
            // extra header away — any base64 blob in `Proxy-Authorization`
            // reaches this arm instead, and an uncapped arm caps nothing. The
            // budgets stay separate because the two arms answer different
            // questions (a client that lost its credential vs a client holding
            // someone else's), and one flood must not silence the other's
            // evidence.
            match ctx.foreign_token.spend() {
                RefusalLeaf::Individual => {
                    let _ = emit_connect(
                        &ctx.writer,
                        "<unknown>",
                        0,
                        "deny",
                        Some("foreign_token"),
                        "default",
                        None,
                        false,
                        None,
                    );
                }
                RefusalLeaf::Aggregate { suppressed } => {
                    let _ = emit_connect(
                        &ctx.writer,
                        "<unknown>",
                        0,
                        "deny",
                        Some("foreign_token_suppressed"),
                        "default",
                        None,
                        false,
                        Some(u32::try_from(suppressed).unwrap_or(u32::MAX)),
                    );
                }
                RefusalLeaf::Nothing => {}
            }
            let _ = sock.write_all(AUTH_REQUIRED).await;
            return Ok(());
        }
    }

    if method != "CONNECT" {
        return handle_non_connect(sock, ctx, method, target, head, leftover).await;
    }

    // (1) Parse host:port from the CONNECT target.
    let Some((host, port)) = parse_connect_target(target) else {
        let _ = sock
            .write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
            .await;
        return Ok(());
    };
    if host.is_empty() {
        let _ = sock
            .write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
            .await;
        return Ok(());
    }

    // A `CONNECT` to a facade host is refused, declared mount or not: the facade
    // is plain HTTP, and a tunnel would put TLS past the one check that makes
    // `.sandbox.invalid` special. Refused before the consultation counter, so a
    // refused tunnel cannot look like a workload that reached an origin. The leaf
    // goes out before the 403, like every other deny path here.
    if let Some(label) = crate::plugin::facade_mount(&host) {
        let _ = emit_facade(
            &ctx.writer,
            &label.to_ascii_lowercase(),
            None,
            "deny",
            Some("facade_requires_http"),
        );
        write_response(
            &mut sock,
            "403 Forbidden",
            "Content-Type: text/plain\r\nConnection: close\r\n",
            "facade_requires_http: the plugin facade is plain HTTP only; use http://<mount>.sandbox.invalid/\n",
        )
        .await;
        return Ok(());
    }

    // This connection reached us *as a proxy* and is attributable to the
    // launch: count it before the decision, so a denial (403) or a failed
    // upstream dial (502) still shows up as `consultations=1,
    // upstream_established=0` — the shape the spike proved must fail
    // guardrail 1 (ADR-0004). A 407 or a malformed target above is not counted:
    // neither is proof that this launch's proxy path works.
    ctx.counters.note_consultation();

    // (2)-(7) The decision pipeline.
    let decision = decide(&ctx, &host, port).await;
    if !decision.allowed {
        // Audit BEFORE responding: the append is synchronous, so whoever
        // observes the 403 also observes the event (no flush ordering to
        // guess).
        emit_decision(&ctx.writer, &host, port, &decision);
        respond_deny(&mut sock, &host, port, &decision).await?;
        return Ok(());
    }
    emit_decision(&ctx.writer, &host, port, &decision);

    // Admission done — dial (Step 2): chained through the upstream
    // proxy, or DNS-pinned + Happy Eyeballs on the direct path.
    let dialed = dial_upstream(ctx.upstream.as_deref(), &host, port, false, system_lookup).await;
    let mut upstream_stream = match dialed {
        Ok(s) => s,
        Err(DialFailure::Denied(d)) => {
            emit_decision(&ctx.writer, &host, port, &d);
            respond_deny(&mut sock, &host, port, &d).await?;
            return Ok(());
        }
        Err(DialFailure::Direct(e)) => {
            let _ = sock
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                .await;
            eprintln!("[proxy] direct dial to {host}:{port} failed: {e}");
            return Ok(());
        }
        Err(DialFailure::Upstream {
            endpoint,
            body,
            error,
        }) => {
            // The admission leaf was already emitted above, so a chained
            // failure is two leaves: `allow` THEN this `upstream_error`. That
            // differs from the direct 502 path, which emits only the
            // admission leaf — consumers must not assume the pair is
            // universal.
            eprintln!("[proxy] upstream chaining to {host}:{port} via {endpoint} failed: {error}");
            emit_decision(&ctx.writer, &host, port, &upstream_error_decision());
            respond_upstream_error(&mut sock, &body).await;
            return Ok(());
        }
    };
    // The upstream dial succeeded and the 200 is about to go out: this is the
    // "upstream established" the guardrail means (not the status code).
    ctx.counters.note_upstream_established();
    let _ = sock
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await;
    // Splice both directions with `copy_bidirectional`, not two `copy`s under
    // a `join!`: `copy` never shuts down the peer's write half, so a client
    // that closed (a normal end to a CONNECT tunnel) left the
    // upstream→client copy parked against a keep-alive upstream — one leaked
    // handler task and two leaked fds per request (S-83). `copy_bidirectional`
    // forwards a read-side EOF as a FIN, so the upstream responds and closes,
    // and both halves complete. Errors stay swallowed: a mid-tunnel RST is
    // not worth logging.
    let _ = tokio::io::copy_bidirectional(&mut sock, &mut upstream_stream).await;
    Ok(())
}

/// A minimal response: status line, optional extra headers, body.
/// Every part CRLF-terminated with an explicit Content-Length.
async fn write_response(sock: &mut TcpStream, status: &str, headers: &str, body: &str) {
    let r = format!(
        "HTTP/1.1 {status}\r\n{headers}Content-Length: {}\r\n\r\n{body}",
        body.len()
    );
    let _ = sock.write_all(r.as_bytes()).await;
}

/// The declared Content-Length of a request head, if present and valid.
fn content_length(head: &str) -> Option<usize> {
    head.lines().find_map(|line| {
        let (k, v) = line.split_once(':')?;
        k.trim()
            .eq_ignore_ascii_case("content-length")
            .then(|| v.trim().parse().ok())
            .flatten()
    })
}

/// Percent-decode a URL component (plus `+` as space). Invalid escapes
/// are kept verbatim rather than failing the whole request.
fn percent_decode(s: &str) -> String {
    fn hex(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    }
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < b.len() && hex(b[i + 1]).is_some() && hex(b[i + 2]).is_some() => {
                out.push(hex(b[i + 1]).unwrap() * 16 + hex(b[i + 2]).unwrap());
                i += 3;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// One decoded value of a URL query (`?a=1&b=2`), if the key appears.
fn url_query_param(query: &str, key: &str) -> Option<String> {
    query.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        (k == key).then(|| percent_decode(v))
    })
}

/// Read a request body: `leftover` bytes already arrived past the head
/// terminator, plus the remainder from the socket, bounded by the
/// declared Content-Length. The cap sits far above the largest legal
/// intent body; anything past it fails JSON parsing with a 400 anyway.
async fn read_body(sock: &mut TcpStream, head: &str, leftover: &[u8]) -> Vec<u8> {
    const BODY_CAP: usize = 4096;
    let want = content_length(head).unwrap_or(0).min(BODY_CAP);
    let mut body = leftover[..leftover.len().min(want)].to_vec();
    while body.len() < want {
        let mut chunk = vec![0u8; (want - body.len()).min(1024)];
        match sock.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(n) => body.extend_from_slice(&chunk[..n]),
        }
    }
    body
}

/// POST /sandbox/intent: the agent (re-)declares its intent for a
/// target. Body: `{"target": string, "reason": string}`. Malformed
/// bodies, missing fields, or a blank target are a 400 ([G-57, D-4]);
/// oversized reasons are truncated by the registry, never rejected.
async fn intent_record(
    sock: &mut TcpStream,
    ctx: &ConnCtx,
    head: &str,
    leftover: &[u8],
) -> Result<()> {
    let body = read_body(sock, head, leftover).await;
    let v: serde_json::Value = match serde_json::from_slice::<serde_json::Value>(&body) {
        Ok(v) if v.is_object() => v,
        _ => {
            write_response(sock, "400 Bad Request", "", "").await;
            return Ok(());
        }
    };
    let target = v.get("target").and_then(|x| x.as_str()).unwrap_or("");
    let reason = v.get("reason").and_then(|x| x.as_str());
    if target.trim().is_empty() || reason.is_none() {
        write_response(sock, "400 Bad Request", "", "").await;
        return Ok(());
    }
    ctx.prompt.intent.record(target, reason.unwrap_or("")).await;
    // The declaration answers a pending "explain more" click: retire
    // the flag for the same host (omac `RecordAndClearExplainMore`).
    let host = crate::net::intent::normalize_host(target);
    ctx.prompt.intent.clear_explain_more(&host).await;
    write_response(sock, "204 No Content", "", "").await;
    Ok(())
}

/// POST /sandbox/intent/explain: the user clicked "explain more" (or a
/// denial hinted at it). Body: `{"host": string}`.
async fn intent_explain(
    sock: &mut TcpStream,
    ctx: &ConnCtx,
    head: &str,
    leftover: &[u8],
) -> Result<()> {
    let body = read_body(sock, head, leftover).await;
    let v: serde_json::Value = match serde_json::from_slice::<serde_json::Value>(&body) {
        Ok(v) if v.is_object() => v,
        _ => {
            write_response(sock, "400 Bad Request", "", "").await;
            return Ok(());
        }
    };
    let host = v.get("host").and_then(|x| x.as_str()).unwrap_or("");
    if host.trim().is_empty() {
        write_response(sock, "400 Bad Request", "", "").await;
        return Ok(());
    }
    ctx.prompt.intent.mark_explain_more(host).await;
    write_response(sock, "204 No Content", "", "").await;
    Ok(())
}

/// `GET /sandbox/probe`: the wrapper's pre-flight probe (ADR-0004 guardrail 1,
/// amended 2026-10-22).
///
/// Records ONE probe observation in the launch epoch that is active — the
/// wrapper runs before the payload, so "the child's path to this listener" is
/// proven for every network session, including one whose workload makes no
/// request. It answers `204`: nothing is disclosed, no policy runs, and the
/// response itself is not evidence (the counter is).
///
/// Ordered like every other record-then-answer path here: the observation is
/// taken before the `204` goes out, so whoever observes the answer can already
/// see the count.
async fn probe_report(sock: &mut TcpStream, ctx: &ConnCtx) -> Result<()> {
    ctx.counters.note_probe();
    let _ = sock.write_all(PROBE_NO_CONTENT).await;
    Ok(())
}

/// GET /sandbox/intent?host=<host>: is the agent's intent for the host
/// known? 200 with the live entry, 404 otherwise. Both outcomes
/// observe (and consume) the one-shot explain-more hint ([G-26, G-57]).
async fn intent_lookup(sock: &mut TcpStream, ctx: &ConnCtx, query: &str) -> Result<()> {
    let Some(host) = url_query_param(query, "host").filter(|h| !h.trim().is_empty()) else {
        write_response(sock, "400 Bad Request", "", "").await;
        return Ok(());
    };
    let host = crate::net::intent::normalize_host(&host);
    let entry = ctx.prompt.intent.lookup_host(&host).await;
    let explain = ctx.prompt.intent.consume_explain_more(&host).await;
    let (status, body) = match entry {
        Some(e) => (
            "200 OK",
            serde_json::json!({
                "host": host,
                "reason": e.reason,
                "ts": rfc3339_utc(e.ts),
                "hint": if explain { "explain-more" } else { "declared" },
            }),
        ),
        None => (
            "404 Not Found",
            serde_json::json!({
                "host": host,
                "reason": "",
                "hint": if explain { "explain-more" } else { "undeclared" },
            }),
        ),
    };
    write_response(
        sock,
        status,
        "Content-Type: application/json\r\n",
        &body.to_string(),
    )
    .await;
    Ok(())
}

/// One absolute-form `http://` target, split into what the dial needs and what
/// the upstream origin must see.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ForwardTarget {
    /// Bare host, no brackets and no port — what the admission pipeline decides
    /// on.
    host: String,
    port: u16,
    /// Path + optional query, as the upstream origin sees it.
    origin_form: String,
}

/// What an absolute-form request target means to this listener.
#[derive(Debug, Clone, PartialEq, Eq)]
enum AbsoluteTarget {
    /// Plain HTTP for another origin: forwardable after admission.
    Forward(ForwardTarget),
    /// `https://` in absolute form. Only a CONNECT can carry TLS, and forwarding
    /// this as cleartext would send a request the client believed was encrypted.
    HttpsNeedsConnect,
    Malformed,
}

/// `s` without `prefix`, matched ASCII-case-insensitively, or `None` when `s`
/// does not start with it.
///
/// Byte-offset slicing a `&str` panics whenever the cut lands inside a
/// multi-byte character, and this target is chosen by the sandboxed child, so
/// the prefix compare must be UTF-8-safe: `get(..)` yields `None` at a
/// non-boundary index instead of panicking.
fn strip_prefix_ignore_ascii_case<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    let head = s.get(..prefix.len())?;
    if !head.eq_ignore_ascii_case(prefix) {
        return None;
    }
    s.get(prefix.len()..)
}

/// Parse an absolute-form request target (`http://host[:port]/path?q`).
fn parse_absolute_target(target: &str) -> AbsoluteTarget {
    const HTTP: &str = "http://";
    const HTTPS: &str = "https://";
    if strip_prefix_ignore_ascii_case(target, HTTPS).is_some() {
        return AbsoluteTarget::HttpsNeedsConnect;
    }
    let Some(rest) = strip_prefix_ignore_ascii_case(target, HTTP) else {
        return AbsoluteTarget::Malformed;
    };
    // The authority ends at the first `/` or `?`; the remainder is the
    // origin-form target the upstream origin expects.
    let (authority, tail) = match rest.find(['/', '?']) {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    // Client-supplied userinfo is dropped, never forwarded: it is a credential
    // this listener never authorized and the origin never asked it for.
    let authority = authority.rsplit('@').next().unwrap_or(authority);
    let Some((host, port)) = split_authority(authority) else {
        return AbsoluteTarget::Malformed;
    };
    let origin_form = match tail {
        "" => "/".to_string(),
        t if t.starts_with('/') => t.to_string(),
        t => format!("/{t}"),
    };
    AbsoluteTarget::Forward(ForwardTarget {
        host,
        port,
        origin_form,
    })
}

/// `host[:port]` (bracketed IPv6 allowed, default port 80) split into its parts.
///
/// `None` for anything that is not a well-formed authority, including an
/// unbracketed IPv6 literal: RFC 3986 requires the brackets, and accepting the
/// bare form would let `::1` reach the pipeline as a host named `:` — the
/// loopback refusal would miss it.
fn split_authority(authority: &str) -> Option<(String, u16)> {
    if authority.is_empty() {
        return None;
    }
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let (inside, after) = rest.split_once(']')?;
        let port = match after.strip_prefix(':') {
            Some(p) => p.parse::<u16>().ok()?,
            None if after.is_empty() => 80,
            None => return None,
        };
        (inside.to_string(), port)
    } else {
        let (host, port) = match authority.rsplit_once(':') {
            Some((h, p)) => (h, p.parse::<u16>().ok()?),
            None => (authority, 80),
        };
        // An unbracketed IPv6 literal is not a valid authority: RFC 3986 requires
        // the brackets, and accepting the bare form would hand the pipeline a
        // host named `:` — the loopback refusal would miss `::1` entirely.
        if host.contains(':') {
            return None;
        }
        (host.to_string(), port)
    };
    if host.trim().is_empty() || port == 0 {
        return None;
    }
    Some((host, port))
}

/// Headers that describe the client's connection to *us*, plus our own proxy
/// credential. None of them may reach the upstream origin.
///
/// `transfer-encoding` and `trailer` are hop-by-hop by definition (RFC 9110
/// 7.6.1), and `te` names the transfer codings the client would accept from
/// *us*. A forwarded request has exactly one framing signal — a
/// `Content-Length` — so all three are dropped; a `Transfer-Encoding` in the
/// head is refused with a 400 before any rewrite (see [`BodyReject`]).
/// `proxy-authenticate` is a *response* field that no client should send, and
/// passing it on would invite the origin to answer `407` — which this listener
/// rewrites to `502` for the same reason: a proxy challenge must never reach a
/// client that would replay our credential to an origin.
const HOP_BY_HOP_HEADERS: [&str; 9] = [
    "connection",
    "proxy-connection",
    "proxy-authorization",
    "proxy-authenticate",
    "keep-alive",
    "upgrade",
    "transfer-encoding",
    "te",
    "trailer",
];

/// The `Host` value the upstream origin must see: the **validated** authority
/// from the request line, normalised the way RFC 9110 7.2 wants it — IPv6
/// literals bracketed, the default port omitted, any other port included.
///
/// The client's own `Host` is never trusted, or even read. Admission decides on
/// the authority in the request-target, so copying the received `Host` would let
/// `GET http://allowlisted/ HTTP/1.1` plus `Host: victim.internal` be audited as
/// allowlisted while the origin is told to serve `victim.internal`: the audit
/// would name a host the request never went to.
fn upstream_host_value(fwd: &ForwardTarget) -> String {
    match (fwd.host.contains(':'), fwd.port) {
        (true, 80) => format!("[{}]", fwd.host),
        (true, port) => format!("[{}]:{port}", fwd.host),
        (false, 80) => fwd.host.clone(),
        (false, port) => format!("{}:{port}", fwd.host),
    }
}

/// The field names the client's own `Connection:` list marks as
/// connection-scoped (RFC 9110 7.6.1). Whatever it names must not be forwarded:
/// otherwise a client could keep, say, `Upgrade` alive across the hop just by
/// listing it, which is precisely what the fixed hop-by-hop list prevents.
fn connection_listed_fields(head: &str) -> Vec<String> {
    head.split("\r\n")
        .filter_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.trim()
                .eq_ignore_ascii_case("connection")
                .then(|| value.to_ascii_lowercase())
        })
        .flat_map(|value| {
            value
                .split(',')
                .map(|token| token.trim().to_string())
                .collect::<Vec<_>>()
        })
        .filter(|token| !token.is_empty())
        .collect()
}

/// The `Connection:`-listed names that also decide framing — the fields whose
/// loss changes what the bytes on the wire mean.
///
/// [`rewrite_head_for_upstream`] drops whatever the client's `Connection:` list
/// names, which is right for `X-Secret-Hop` and catastrophic for
/// `Content-Length`: the relay still writes that many body bytes, so the origin
/// reads them as a second, unadmitted request — with a `Host` the client chose,
/// because the first request's framing vanished. A request that names any of
/// these is therefore refused before admission (see
/// [`connection_listed_framing_field`]); none of them is ever stripped.
const FRAMING_FIELDS: [&str; 4] = ["content-length", "transfer-encoding", "host", "connection"];

/// The first framing-critical name the client's `Connection:` list names, if
/// any. Such a head is a 400 before admission: it asks this listener to strip
/// the field that frames the body it is about to relay.
fn connection_listed_framing_field(head: &str) -> Option<&'static str> {
    let listed = connection_listed_fields(head);
    FRAMING_FIELDS
        .iter()
        .copied()
        .find(|field| listed.iter().any(|token| token == field))
}

/// Why a header line is not RFC 9110 field syntax, or `None` when it is.
///
/// `field-name = token` (RFC 9110 5.1) and a token contains no whitespace. The
/// rest of this module trims names before comparing them, so
/// `Content-Length : 5` reads as a framing signal to us and forwards *verbatim* —
/// leaving the origin to decide whether `Content-Length ` (with the space) is the
/// framing field it knows. One head must mean one thing on both ends of the hop,
/// so a name carrying whitespace is refused rather than re-interpreted. An empty
/// name (`: v`) and a header line with no colon at all are refused for the same
/// reason: neither is a field the origin is guaranteed to read the way we did.
fn head_field_syntax_error(head: &str) -> Option<&'static str> {
    for line in head.split("\r\n").skip(1).filter(|line| !line.is_empty()) {
        let Some((name, _)) = line.split_once(':') else {
            return Some("header line without a field name");
        };
        if name.is_empty() {
            return Some("empty field name in the request head");
        }
        if name.bytes().any(|b| b.is_ascii_whitespace()) {
            return Some("whitespace in a field name");
        }
    }
    None
}

/// Whether the request carries an `Expect` field, whatever its value.
///
/// `Expect: 100-continue` asks the *receiver* to send `100 Continue` before the
/// body; this listener never sends an interim response and reads exactly one
/// head, so forwarding it would leave the client waiting for a go-ahead that
/// never comes while the origin waits for a body the client is withholding — a
/// deadlock only curl's timer papers over. The behaviour chosen here is the
/// strict one: **refuse the request before admission** (400 +
/// `X-Sandbox: expect-unsupported`) rather than strip the field and answer
/// `100 Continue` ourselves. That needs no new state on the relay and cannot
/// admit a body the origin is not expecting.
///
/// Measured cost (curl 8.21): the field is sent automatically only for bodies
/// above 1 MiB, so ordinary uploads forward untouched, and a larger one fails
/// immediately and visibly (400 + `X-Sandbox: expect-unsupported`) instead of
/// hanging. A client that needs a multi-megabyte plain-HTTP upload can send the
/// field empty (curl: `-H 'Expect:'`) and the request forwards whole; if that
/// ever becomes a real workload, answering `100 Continue` here and dropping the
/// field is the cheap upgrade.
fn has_expect_field(head: &str) -> bool {
    head.split("\r\n")
        .skip(1)
        .filter_map(|line| line.split_once(':'))
        .any(|(name, _)| name.eq_ignore_ascii_case("expect"))
}

/// Rewrite a proxy-form request head into an origin-form one for the upstream:
/// the request line carries `origin_form`, the `Host` is rebuilt from the
/// admitted authority (`host_value`), and every connection-scoped field — the
/// fixed list above, whatever the client's `Connection:` names, the received
/// `Host`, and our own `Proxy-Authorization` — is dropped. `Connection: close`
/// is forced so the upstream ends the exchange (this listener relays bytes and
/// does no keep-alive bookkeeping of its own).
///
/// Two names are never droppable by the client's list: `content-length` and
/// `transfer-encoding` (see [`FRAMING_FIELDS`]). `handle_forward` refuses a head
/// whose `Connection:` names one of them before admission, and the list is
/// filtered here as well so the framing signal cannot be lost even if a caller
/// ever skips that check.
///
/// The head is split on CRLF only, and that is the single framing rule: a head
/// containing a bare LF or CR never reaches here ([`head_framing_error`] answers
/// it with a 400), so this splitter and the LF-aware `str::lines` used by the
/// auth gate and the request-line parse cannot disagree about where a field
/// ends.
fn rewrite_head_for_upstream(head: &str, origin_form: &str, host_value: &str) -> String {
    let mut lines = head.split("\r\n").filter(|line| !line.is_empty());
    let mut request = lines.next().unwrap_or("").split_whitespace();
    let method = request.next().unwrap_or("GET");
    let _target = request.next();
    let version = request.next().unwrap_or("HTTP/1.1");
    debug_assert!(
        connection_listed_framing_field(head).is_none(),
        "a Connection-listed framing field must be refused before the rewrite"
    );
    let listed: Vec<String> = connection_listed_fields(head)
        .into_iter()
        .filter(|token| !FRAMING_FIELDS.contains(&token.as_str()))
        .collect();

    let mut out = String::with_capacity(head.len() + origin_form.len() + host_value.len());
    out.push_str(method);
    out.push(' ');
    out.push_str(origin_form);
    out.push(' ');
    out.push_str(version);
    out.push_str("\r\nHost: ");
    out.push_str(host_value);
    out.push_str("\r\n");
    for line in lines {
        let name = line
            .split(':')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        // `host` goes with the rest: the authority in the request line is the
        // admitted one, and it is the only Host the origin may see.
        let drop = name.is_empty()
            || name == "host"
            || HOP_BY_HOP_HEADERS.iter().any(|hop| *hop == name)
            || listed.contains(&name);
        if drop {
            continue;
        }
        out.push_str(line);
        out.push_str("\r\n");
    }
    out.push_str("Connection: close\r\n\r\n");
    out
}

/// Why this head cannot be framed for forwarding, or `None` when it can.
///
/// One rule for the whole head. The rewriter splits on CRLF — what the wire
/// says — while the auth gate and the request-line parse use `str::lines`, which
/// also splits on a bare LF. A head containing either therefore has two
/// different sets of field boundaries depending on who reads it: `X: y` + bare
/// LF + `Connection: upgrade` is *one* field to the rewriter (name `X`, so it
/// survives the hop-by-hop filter) and *three* to the gate. Strict HTTP/1.1
/// forbids a bare LF or CR as a line terminator, so such a head is refused with
/// a 400 rather than re-interpreted. An obs-fold continuation line is refused
/// for the same reason: it is a second way to hide a field inside another one.
fn head_framing_error(head: &str) -> Option<&'static str> {
    if !head.ends_with("\r\n\r\n") {
        return Some("request head is not CRLF-terminated");
    }
    let bytes = head.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\r' if bytes.get(i + 1) == Some(&b'\n') => i += 2,
            b'\r' => return Some("bare CR in the request head"),
            b'\n' => return Some("bare LF in the request head"),
            _ => i += 1,
        }
    }
    head.split("\r\n")
        .skip(1)
        .find(|line| line.starts_with(' ') || line.starts_with('\t'))
        .map(|_| "obs-fold line in the request head")
}

/// How many body bytes follow the head: exactly one framing signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ForwardBody {
    /// No body. A body can only be declared by `Content-Length` here.
    None,
    /// Exactly this many bytes, after which the request is over.
    Length(usize),
}

/// Why a head cannot be framed as exactly one request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BodyReject {
    /// `Transfer-Encoding` is present. Re-framing chunked into a
    /// `Content-Length` is not something a byte relay can do safely, and
    /// passing it through would let the client pick the origin's framing — the
    /// classic request-smuggling primitive. Refused, whatever it names.
    TransferEncoding,
    /// A `Content-Length` value that is not a plain decimal number.
    BadContentLength,
    /// Repeated `Content-Length` values that disagree.
    ConflictingContentLength,
}

impl BodyReject {
    fn reason(self) -> &'static str {
        match self {
            BodyReject::TransferEncoding => "Transfer-Encoding is not accepted on this path",
            BodyReject::BadContentLength => "Content-Length is not a decimal number",
            BodyReject::ConflictingContentLength => "conflicting Content-Length values",
        }
    }
}

/// Exactly one request per connection, part 1: the body length comes from at
/// most one framing signal.
///
/// Repeated `Content-Length` fields are accepted only when every value is the
/// same number (RFC 9110 8.6 allows exactly that, and refusing it would break
/// clients that re-emit the field); any disagreement is a 400, because the
/// receiver must not pick a favourite between two different body lengths.
fn forward_body_framing(head: &str) -> Result<ForwardBody, BodyReject> {
    let mut lengths: Vec<usize> = Vec::new();
    for line in head.split("\r\n") {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim();
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(BodyReject::TransferEncoding);
        }
        if name.eq_ignore_ascii_case("content-length") {
            for field in value.split(',') {
                let field = field.trim();
                // Only `[0-9]+` frames the body. Rust's `usize` parser also
                // accepts a leading `+` (and the field is forwarded verbatim),
                // so `Content-Length: +5` would be five bytes to us and a
                // rejected or absent field to the origin -- the same
                // two-readings-of-one-head gap the whitespace rule closes.
                if field.is_empty() || !field.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(BodyReject::BadContentLength);
                }
                let Ok(len) = field.parse::<usize>() else {
                    return Err(BodyReject::BadContentLength);
                };
                lengths.push(len);
            }
        }
    }
    match lengths.split_first() {
        None => Ok(ForwardBody::None),
        Some((first, rest)) if rest.iter().all(|len| len == first) => {
            Ok(ForwardBody::Length(*first))
        }
        Some(_) => Err(BodyReject::ConflictingContentLength),
    }
}

/// Why the framed body could not be forwarded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BodyRelayError {
    /// The client sent bytes past the framed body: a second request, which this
    /// listener never admitted and never audits. Refused, never relayed.
    Trailing,
    /// The client read or the upstream write failed.
    Io,
}

/// Exactly one request per connection, part 2: forward exactly `want` body
/// bytes from (`leftover`, `client`) to `upstream`, and not one byte more.
///
/// Nothing past the framed body is ever written upstream, whatever the client
/// appends — that is the difference between a relay and a second, unadmitted
/// request.
async fn relay_framed_body<R, W>(
    client: &mut R,
    upstream: &mut W,
    leftover: &[u8],
    want: usize,
) -> Result<(), BodyRelayError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    const CHUNK: usize = 8192;
    if leftover.len() > want {
        return Err(BodyRelayError::Trailing);
    }
    if !leftover.is_empty() {
        upstream
            .write_all(leftover)
            .await
            .map_err(|_| BodyRelayError::Io)?;
    }
    let mut remaining = want - leftover.len();
    let mut buf = [0u8; CHUNK];
    while remaining > 0 {
        let take = remaining.min(CHUNK);
        let read = client
            .read(&mut buf[..take])
            .await
            .map_err(|_| BodyRelayError::Io)?;
        if read == 0 {
            // The client closed mid-body: the origin must not be left waiting
            // for bytes that will never arrive.
            return Err(BodyRelayError::Io);
        }
        upstream
            .write_all(&buf[..read])
            .await
            .map_err(|_| BodyRelayError::Io)?;
        remaining -= read;
    }
    Ok(())
}

/// What the upstream's **first** head says, judged strictly.
///
/// Only a final `HTTP/1.x` response is ever relayed. Everything else is named
/// and withheld, because this listener reads exactly one head: an interim
/// (`1xx`) head is a promise of a later answer it cannot keep, and a head it
/// cannot parse has no status it may compare.
#[derive(Debug, PartialEq, Eq)]
enum UpstreamHead {
    /// A final response (`status >= 200`): every byte read so far — the head and
    /// any body that arrived with it — plus its status.
    Final { bytes: Vec<u8>, status: u16 },
    /// The first head was interim (`1xx`). Refused; nothing relayed.
    Interim,
    /// The first head does not begin with `HTTP/1.`, or its status line is not
    /// `HTTP/1.x SP 3DIGIT` as read. Refused; nothing relayed. A leading CRLF
    /// lands here — its first line is empty — which is exactly how a challenge
    /// could otherwise be relayed past a status check that read `0`.
    StatusUnparsable,
}

/// Read the upstream response head (up to 8 KiB, terminated by CRLF CRLF) so the
/// status line can be inspected before a byte of it reaches the client. `None`
/// when the upstream closed without answering at all.
async fn read_upstream_head<R>(upstream: &mut R) -> Option<UpstreamHead>
where
    R: AsyncRead + Unpin,
{
    const HEAD_CAP: usize = 8192;
    let mut bytes = Vec::with_capacity(512);
    let mut chunk = [0u8; 1024];
    while find_head_end(&bytes).is_none() && bytes.len() < HEAD_CAP {
        match upstream.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(read) => bytes.extend_from_slice(&chunk[..read]),
        }
    }
    if bytes.is_empty() {
        return None;
    }
    // An incomplete first head (peer closed, or the cap was hit) is not a head
    // this listener can vouch for.
    let Some(head_end) = find_head_end(&bytes) else {
        return Some(UpstreamHead::StatusUnparsable);
    };
    // Only the first line is parsed, and only against the strict grammar: the
    // rest of the head never influences the verdict, and a second head behind
    // this one is never read.
    let head = &bytes[..head_end];
    let line_end = head
        .windows(2)
        .position(|w| w == b"\r\n")
        .unwrap_or(head.len());
    let status_line = String::from_utf8_lossy(&head[..line_end]);
    let Some(status) = parse_upstream_status_line(&status_line) else {
        return Some(UpstreamHead::StatusUnparsable);
    };
    match status {
        100..=199 => Some(UpstreamHead::Interim),
        200..=599 => Some(UpstreamHead::Final { bytes, status }),
        // Three digits, but not a status HTTP defines (RFC 9110 15): `000`-`099`
        // and `600`+ are refused rather than guessed at.
        _ => Some(UpstreamHead::StatusUnparsable),
    }
}

/// The status code of a strict `HTTP/1.x SP 3DIGIT [SP reason-phrase]` line.
///
/// `None` for every other shape: another protocol (`HTTP/2 200`), a lowercase
/// version, two spaces, a two- or four-digit code, no separator at all. There is
/// no `0` sentinel — a head whose status cannot be read is refused before any
/// comparison, never treated as some status.
fn parse_upstream_status_line(line: &str) -> Option<u16> {
    let rest = line.strip_prefix("HTTP/1.")?;
    let mut chars = rest.chars();
    if !chars.next()?.is_ascii_digit() {
        return None;
    }
    if chars.next()? != ' ' {
        return None;
    }
    let mut code = 0u16;
    for _ in 0..3 {
        code = code * 10 + chars.next()?.to_digit(10)? as u16;
    }
    match chars.next() {
        None | Some(' ') => Some(code),
        Some(_) => None,
    }
}

/// The exact bytes the client receives for a final upstream response: the
/// origin's head relayed verbatim — this is a byte relay, not a re-framer, so
/// `Content-Length`/`Transfer-Encoding` and every byte after the head are
/// untouched — except for `Connection`.
///
/// Every `Connection` field the origin sent is dropped (a `keep-alive` would
/// invite a client to reuse a socket this listener closes after every forward)
/// and exactly one `Connection: close` is emitted in its place, so the head the
/// client sees never carries two of them.
fn relayed_response_head(bytes: &[u8]) -> Vec<u8> {
    let head_end = find_head_end(bytes).unwrap_or(bytes.len());
    let (head, rest) = bytes.split_at(head_end);
    let mut out = Vec::with_capacity(head.len() + 19 + rest.len());
    for (index, line) in head_lines(head).into_iter().enumerate() {
        // Index 0 is the status line, which is always relayed as it arrived.
        if index > 0 && (line.is_empty() || response_field_named(line, b"connection")) {
            continue;
        }
        out.extend_from_slice(line);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"Connection: close\r\n\r\n");
    out.extend_from_slice(rest);
    out
}

/// The lines of a CRLF-framed head, without their terminators.
///
/// Splits on CRLF only — the same framing rule the request side applies — so a
/// line that merely looks terminated by a bare LF is never mistaken for a
/// separate field.
fn head_lines(head: &[u8]) -> Vec<&[u8]> {
    let mut lines = Vec::new();
    let mut start = 0;
    let mut index = 0;
    while index + 1 < head.len() {
        if head[index] == b'\r' && head[index + 1] == b'\n' {
            lines.push(&head[start..index]);
            index += 2;
            start = index;
        } else {
            index += 1;
        }
    }
    if start < head.len() {
        lines.push(&head[start..]);
    }
    lines
}

/// Whether `line` is a field whose name is `name` (ASCII case-insensitive).
///
/// The name is the bytes before the first `:` and is compared without trimming:
/// only a `Connection` this proxy can see exactly is rewritten, so a head whose
/// names carry anything extra is relayed as it arrived rather than re-parsed.
fn response_field_named(line: &[u8], name: &[u8]) -> bool {
    let Some(colon) = line.iter().position(|b| *b == b':') else {
        return false;
    };
    line[..colon].eq_ignore_ascii_case(name)
}

/// A plain-HTTP proxy consultation: an absolute-form `http://` request for
/// another origin.
///
/// This is the only path on which the listener forwards a request upstream, and
/// it forwards **after** the whole D-1 admission pipeline — loopback refusal,
/// hard-deny, learned decisions, the deny/allow lists and the prompt — plus the
/// same DNS-pinned dial the CONNECT path uses. It must not be a bypass: the
/// admission decision is taken on the authority in the request line, which is
/// exactly what a CONNECT carries.
///
/// The audit leaf is the same one `decide()` produces for a tunnel
/// (`op: CONNECT`, with `source`/`scope`/`persisted`), so the D-5 taxonomy is
/// untouched; whether a forward deserves its own `op` is P2.3's decision.
/// What the facade does with one absolute-form request.
#[derive(Debug)]
enum FacadeAction {
    /// Not a `.sandbox.invalid` host: the ordinary admission pipeline owns it.
    NotFacade,
    /// Reserved suffix, but no plugin in this session registered that mount.
    UnknownMount,
    /// The mount exists and the method is not one this transport relays.
    MethodUnsupported,
    /// The request is well-formed but the manifest does not declare this
    /// `(method, path)`. The declaration is the operator's reviewed surface, so
    /// anything outside it is refused rather than relayed.
    OperationNotDeclared,
    /// Relay this request to the sidecar behind the mount.
    Relay { mount: String, target: FacadeTarget },
}

/// The facade routing decision, as one pure function so its table is testable
/// without a socket.
///
/// Order is part of the decision and is pinned by `facade_routing_table`: an
/// undeclared mount is `404` whatever the method (nothing is declared under that
/// name), while a known mount with a non-GET method is `501` rather than a
/// denial — the capability exists, this transport does not carry that operation
/// yet. The host label is compared case-insensitively but the mount is
/// canonicalised to the registry's spelling, so audit and `Host` agree.
fn facade_action(
    facade: &FacadeRegistry,
    host: &str,
    method: &str,
    origin_form: &str,
) -> FacadeAction {
    let Some(label) = crate::plugin::facade_mount(host) else {
        return FacadeAction::NotFacade;
    };
    let Some(target) = facade.lookup(&label.to_ascii_lowercase()) else {
        return FacadeAction::UnknownMount;
    };
    if !method.eq_ignore_ascii_case("GET") {
        return FacadeAction::MethodUnsupported;
    }
    // The path the sidecar will receive, with the query stripped: a manifest
    // declares paths, not queries.
    let path = origin_form.split('?').next().unwrap_or(origin_form);
    let declared = target
        .operations
        .iter()
        .any(|op| op.method.eq_ignore_ascii_case(method) && op.path == path);
    if !declared {
        return FacadeAction::OperationNotDeclared;
    }
    FacadeAction::Relay {
        mount: target.mount.clone(),
        target,
    }
}

/// Relay one `GET` to a plugin sidecar and stream the answer back verbatim.
///
/// The client's head is NOT forwarded. The sidecar sees exactly the line the
/// supervisor built — `GET <path> HTTP/1.0`, a `Host` of the mount and the facade
/// token — so a workload cannot smuggle a header, a body or a second request into
/// the deputy. `tokio::io::copy` streams the response instead of buffering it: a
/// 60 KB page is one pass-through, and a later SSE body would arrive as it is
/// produced rather than at the end.
async fn relay_facade(
    sock: &mut TcpStream,
    writer: &AuditWriter,
    mount: &str,
    target: &FacadeTarget,
    path: &str,
) -> Result<()> {
    let mut upstream = match TcpStream::connect(("127.0.0.1", target.port)).await {
        Ok(stream) => stream,
        Err(_) => {
            // Leaf before response, the rule every deny path here follows.
            let _ = emit_facade(
                writer,
                mount,
                Some(path),
                "deny",
                Some("facade_sidecar_unreachable"),
            );
            write_response(
                sock,
                "502 Bad Gateway",
                "Content-Type: text/plain\r\nConnection: close\r\n",
                "facade_sidecar_unreachable\n",
            )
            .await;
            return Ok(());
        }
    };
    let _ = emit_facade(writer, mount, Some(path), "allow", None);
    let request = format!(
        "GET {path} HTTP/1.0\r\nHost: {mount}\r\nX-Facade-Token: {}\r\n\r\n",
        target.token
    );
    if upstream.write_all(request.as_bytes()).await.is_err() {
        return Ok(());
    }
    let _ = tokio::io::copy(&mut upstream, sock).await;
    Ok(())
}

async fn handle_forward(
    mut sock: TcpStream,
    ctx: Arc<ConnCtx>,
    method: &str,
    target: &str,
    head: &str,
    leftover: &[u8],
) -> Result<()> {
    let fwd = match parse_absolute_target(target) {
        AbsoluteTarget::Forward(fwd) => fwd,
        AbsoluteTarget::HttpsNeedsConnect => {
            write_response(
                &mut sock,
                "400 Bad Request",
                "Content-Type: text/plain\r\n",
                "absolute-form https:// request: use CONNECT\n",
            )
            .await;
            return Ok(());
        }
        AbsoluteTarget::Malformed => {
            write_response(&mut sock, "400 Bad Request", "", "").await;
            return Ok(());
        }
    };

    // One framing rule for the head, then exactly one framing signal for the
    // body. Both are decided *before* admission, so a request this listener
    // refuses to frame is never counted as a consultation, never audited and
    // never dialled: a refusal to frame is not a policy answer.
    if let Some(why) = head_framing_error(head) {
        write_response(
            &mut sock,
            "400 Bad Request",
            "Content-Type: text/plain\r\n",
            &format!("{why}\n"),
        )
        .await;
        return Ok(());
    }
    // A field name must be a token (RFC 9110 5.1). The parsers below trim, so a
    // head carrying `Content-Length : 5` would be framed as if the name were
    // `Content-Length` and then forwarded verbatim — leaving the origin to decide
    // whether the space is part of the name. One head must mean one thing on both
    // ends of the hop, so such a head is refused before admission.
    if let Some(why) = head_field_syntax_error(head) {
        write_response(
            &mut sock,
            "400 Bad Request",
            "Content-Type: text/plain\r\nConnection: close\r\n",
            &format!("{why}\n"),
        )
        .await;
        return Ok(());
    }
    // `Connection` may not name a framing field. The rewrite drops whatever the
    // list names, and dropping `Content-Length` would relay the body unframed —
    // the origin would read it as a second, unadmitted request with a `Host` the
    // client chose. Refused here, before admission: nothing dialled, nothing
    // audited, no consultation counted.
    if let Some(field) = connection_listed_framing_field(head) {
        write_response(
            &mut sock,
            "400 Bad Request",
            "Content-Type: text/plain\r\nConnection: close\r\n",
            &format!("Connection names the framing field `{field}`\n"),
        )
        .await;
        return Ok(());
    }
    // `Expect` is refused rather than satisfied (the one behaviour chosen: a
    // strict 400, no 100 Continue machinery). An `Expect: 100-continue` request
    // that were forwarded would leave the client withholding the body until it
    // saw a `100` this listener never sends, and the origin waiting for a body
    // that never comes.
    if has_expect_field(head) {
        write_response(
            &mut sock,
            "400 Bad Request",
            "Content-Type: text/plain\r\nX-Sandbox: expect-unsupported\r\nConnection: close\r\n",
            "Expect is not supported: this proxy never sends 100 Continue\n",
        )
        .await;
        return Ok(());
    }
    let body = match forward_body_framing(head) {
        Ok(body) => body,
        Err(reject) => {
            write_response(
                &mut sock,
                "400 Bad Request",
                "Content-Type: text/plain\r\n",
                &format!("{}\n", reject.reason()),
            )
            .await;
            return Ok(());
        }
    };
    let want = match body {
        ForwardBody::None => 0,
        ForwardBody::Length(len) => len,
    };
    // Exactly one request per connection, part 1: bytes buffered past the head
    // are body bytes or nothing. Anything beyond the framed body is a second
    // request this listener never admitted (and never audits); refusing it here
    // keeps it off the wire entirely.
    if leftover.len() > want {
        write_response(
            &mut sock,
            "400 Bad Request",
            "Content-Type: text/plain\r\n",
            "bytes past the framed request body: one request per connection\n",
        )
        .await;
        return Ok(());
    }

    // Plugin facade: `<mount>.sandbox.invalid` is a capability the supervisor
    // started, not an origin. Dispatched HERE — after the head is framed and
    // before any admission decision — because the name never resolves and must
    // never reach `decide()`, the prompt, or a dial. It is therefore not a
    // consultation either: no origin was contacted on the workload's behalf.
    match facade_action(&ctx.facade, &fwd.host, method, fwd.origin_form.as_str()) {
        FacadeAction::NotFacade => {}
        FacadeAction::UnknownMount => {
            let label = crate::plugin::facade_mount(&fwd.host).unwrap_or("");
            let _ = emit_facade(
                &ctx.writer,
                &label.to_ascii_lowercase(),
                Some(fwd.origin_form.as_str()),
                "deny",
                Some("facade_unknown_mount"),
            );
            write_response(
                &mut sock,
                "404 Not Found",
                "Content-Type: text/plain\r\nConnection: close\r\n",
                "facade_unknown_mount\n",
            )
            .await;
            return Ok(());
        }
        FacadeAction::MethodUnsupported => {
            let label = crate::plugin::facade_mount(&fwd.host).unwrap_or("");
            let _ = emit_facade(
                &ctx.writer,
                &label.to_ascii_lowercase(),
                Some(fwd.origin_form.as_str()),
                "deny",
                Some("facade_method_unsupported"),
            );
            write_response(
                &mut sock,
                "501 Not Implemented",
                "Content-Type: text/plain\r\nConnection: close\r\n",
                "facade_method_unsupported\n",
            )
            .await;
            return Ok(());
        }
        FacadeAction::OperationNotDeclared => {
            let label = crate::plugin::facade_mount(&fwd.host).unwrap_or("");
            let _ = emit_facade(
                &ctx.writer,
                &label.to_ascii_lowercase(),
                Some(fwd.origin_form.as_str()),
                "deny",
                Some("facade_operation_not_declared"),
            );
            write_response(
                &mut sock,
                "403 Forbidden",
                "Content-Type: text/plain\r\nConnection: close\r\n",
                "facade_operation_not_declared\n",
            )
            .await;
            return Ok(());
        }
        FacadeAction::Relay { mount, target } => {
            relay_facade(
                &mut sock,
                &ctx.writer,
                &mount,
                &target,
                fwd.origin_form.as_str(),
            )
            .await?;
            return Ok(());
        }
    }

    // A consultation exactly like a CONNECT, and counted at the same point: a
    // denial below must still read as `consultations=1,
    // upstream_established=0`.
    ctx.counters.note_consultation();

    let decision = decide(&ctx, &fwd.host, fwd.port).await;
    if !decision.allowed {
        emit_decision(&ctx.writer, &fwd.host, fwd.port, &decision);
        respond_deny(&mut sock, &fwd.host, fwd.port, &decision).await?;
        return Ok(());
    }
    emit_decision(&ctx.writer, &fwd.host, fwd.port, &decision);

    let mut upstream = match dial_upstream(
        ctx.upstream.as_deref(),
        &fwd.host,
        fwd.port,
        false,
        system_lookup,
    )
    .await
    {
        Ok(stream) => stream,
        Err(DialFailure::Denied(d)) => {
            emit_decision(&ctx.writer, &fwd.host, fwd.port, &d);
            respond_deny(&mut sock, &fwd.host, fwd.port, &d).await?;
            return Ok(());
        }
        Err(DialFailure::Direct(e)) => {
            write_response(&mut sock, "502 Bad Gateway", "", "").await;
            eprintln!(
                "[proxy] plain-HTTP forward to {}:{} failed: {e}",
                fwd.host, fwd.port
            );
            return Ok(());
        }
        Err(DialFailure::Upstream {
            endpoint,
            body,
            error,
        }) => {
            eprintln!(
                "[proxy] upstream chaining to {}:{} via {endpoint} failed: {error}",
                fwd.host, fwd.port
            );
            emit_decision(&ctx.writer, &fwd.host, fwd.port, &upstream_error_decision());
            respond_upstream_error(&mut sock, &body).await;
            return Ok(());
        }
    };
    // The origin connection is up. This is the forward leg's "upstream
    // established" — the same fact the CONNECT path records before its 200.
    ctx.counters.note_upstream_established();

    // The head the origin sees is built from the admitted authority, never from
    // the client's bytes: request line rewritten to origin-form, `Host`
    // re-derived, connection-scoped fields (including the ones the client's own
    // `Connection:` names) dropped.
    let rewritten = rewrite_head_for_upstream(head, &fwd.origin_form, &upstream_host_value(&fwd));
    if upstream.write_all(rewritten.as_bytes()).await.is_err() {
        return Ok(());
    }
    // Exactly one request per connection, part 2: forward exactly the framed
    // body, then stop reading from the client for good. Only the *response* is
    // relayed from here on, so a smuggled second request has no path upstream.
    // `leftover.len() > want` was refused above, before the dial, so the relay
    // cannot report trailing bytes here: it forwards exactly the framed body and
    // stops. Only an I/O failure remains — a client that closed mid-body or a
    // failed upstream write — and that ends the exchange, because the origin must
    // not be left waiting for bytes that will never arrive.
    debug_assert!(leftover.len() <= want);
    if relay_framed_body(&mut sock, &mut upstream, leftover, want)
        .await
        .is_err()
    {
        return Ok(());
    }

    // The response head is read before it is relayed, so the status line can be
    // checked first: an origin must not be able to answer a *proxy* challenge,
    // and an interim or unparsable head must never stand in for the answer.
    let Some(response) = read_upstream_head(&mut upstream).await else {
        return Ok(());
    };
    let (response_bytes, status) = match response {
        UpstreamHead::Final { bytes, status } => (bytes, status),
        UpstreamHead::Interim => {
            // Exactly one head is read per exchange, so a `1xx` cannot be
            // followed through to the real answer: the client gets a named 502
            // and not one byte of the interim head. Relaying it would hand the
            // client a header block whose fields (a `Link`, or a challenge from a
            // 103-then-407 chain) stand in for a status it never received.
            write_response(
                &mut sock,
                "502 Bad Gateway",
                "X-Sandbox: interim-response-unsupported\r\nConnection: close\r\n",
                "sandbox: the origin answered with an interim (1xx) response.\n",
            )
            .await;
            return Ok(());
        }
        UpstreamHead::StatusUnparsable => {
            // No readable status means no status to compare — so the head is
            // withheld rather than guessed at. A response that opens with CRLF
            // lands here (its first line is empty), which is exactly how a 407
            // used to slip past the challenge check.
            write_response(
                &mut sock,
                "502 Bad Gateway",
                "X-Sandbox: origin-status-unparsable\r\nConnection: close\r\n",
                "sandbox: the origin's status line could not be read.\n",
            )
            .await;
            return Ok(());
        }
    };
    if status == 407 {
        // An origin answering `407`/`Proxy-Authenticate` would make an honest
        // client replay our session token to that origin. Rewritten to 502,
        // with the origin's challenge and body discarded.
        write_response(
            &mut sock,
            "502 Bad Gateway",
            "X-Sandbox: origin-challenge\r\nConnection: close\r\n",
            "sandbox: the origin answered with a proxy authentication challenge, \
             which was withheld.\n",
        )
        .await;
        return Ok(());
    }
    // The listener closes the client socket after every forward, so the head the
    // client receives says `Connection: close` exactly once, whatever the
    // origin's own head said: a client that honoured an origin `keep-alive` would
    // reuse a connection that is already dead.
    let relayed = relayed_response_head(&response_bytes);
    if sock.write_all(&relayed).await.is_err() {
        return Ok(());
    }
    let _ = tokio::io::copy(&mut upstream, &mut sock).await;
    Ok(())
}

/// Route an authenticated non-CONNECT request.
///
/// Two shapes reach this listener, and they are treated differently:
///
/// * **Absolute-form** (`GET http://origin/path`): the client is using us
///   as its proxy, so this is a plain-HTTP forward. It goes through the
///   full D-1 admission pipeline in [`handle_forward`] — never straight
///   upstream. `https://` in absolute form is refused: only a CONNECT can
///   carry TLS.
/// * **Origin-form** (`GET /sandbox/intent`): the client dialled us
///   directly, so it is the D-4 control plane. Only `/sandbox/*` exists
///   there — the D-4 intent endpoints and, since ADR-0004 guardrail 1's
///   2026-10-22 amendment, `GET /sandbox/probe`; anything else is a 400
///   ([G-7, G-38]), because this listener is not a reverse proxy for anyone.
async fn handle_non_connect(
    mut sock: TcpStream,
    ctx: Arc<ConnCtx>,
    method: &str,
    target: &str,
    head: &str,
    leftover: &[u8],
) -> Result<()> {
    // Absolute-form is a proxy consultation: admit it, then forward. An
    // origin-form target starts with `/` and can never contain `://`, so
    // this cannot capture a control-plane request.
    if !target.starts_with('/') && target.contains("://") {
        return handle_forward(sock, ctx, method, target, head, leftover).await;
    }
    if !target.starts_with("/sandbox/") {
        write_response(&mut sock, "400 Bad Request", "", "").await;
        return Ok(());
    }
    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p, q),
        None => (target, ""),
    };
    match path {
        "/sandbox/intent" => match method {
            "GET" => intent_lookup(&mut sock, &ctx, query).await,
            "POST" => intent_record(&mut sock, &ctx, head, leftover).await,
            _ => {
                write_response(
                    &mut sock,
                    "405 Method Not Allowed",
                    "Allow: GET, POST\r\n",
                    "",
                )
                .await;
                Ok(())
            }
        },
        PROBE_PATH => match method {
            "GET" => probe_report(&mut sock, &ctx).await,
            _ => {
                write_response(&mut sock, "405 Method Not Allowed", "Allow: GET\r\n", "").await;
                Ok(())
            }
        },
        "/sandbox/intent/explain" => match method {
            "POST" => intent_explain(&mut sock, &ctx, head, leftover).await,
            _ => {
                write_response(&mut sock, "405 Method Not Allowed", "Allow: POST\r\n", "").await;
                Ok(())
            }
        },
        _ => {
            write_response(&mut sock, "404 Not Found", "", "").await;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests;
