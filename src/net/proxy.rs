//! Localhost reverse proxy: tokio + hyper + rustls.
//!
//! Architecture: the supervisor (`sandbox.exe`) spawns the proxy on a
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
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LaunchProofCounters {
    pub consultations: u64,
    pub upstream_established: u64,
    pub probes: u64,
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
        // Log the listening port under SANDBOX_DIAG so integration tests
        // (S-36, S-38) can parse it from stderr.
        if std::env::var_os("SANDBOX_DIAG").is_some() {
            eprintln!("[proxy] listening on 127.0.0.1:{port}");
        }

        loop {
            tokio::select! {
                _ = cancel_for_task.cancelled() => break,
                accept = listener.accept() => {
                    let (sock, _peer) = match accept {
                        Ok(p) => p,
                        Err(_) => continue,
                    };
                    let ctx = Arc::clone(&ctx);
                    tokio::spawn(async move {
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
            eprintln!(
                "[sandbox] warning: failed to persist learned decision for {entry_host}: {e}"
            );
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
            "[sandbox] no dialog backend available — denying; pre-approve hosts via \
             --allow-domain, or set on_unavailable=allow (insecure); set SANDBOX_DIAG=1 for details"
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
/// operator can act on (pre-approve the host, or raise `promptTimeoutSecs`).
fn warn_prompt_budget_once(budget: std::time::Duration) {
    static WARNED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    if !WARNED.swap(true, std::sync::atomic::Ordering::SeqCst) {
        eprintln!(
            "[sandbox] prompt budget elapsed ({}s) with no answer — denying on budget; \
             pre-approve hosts via --allow-domain, or raise promptTimeoutSecs",
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
fn pinned_addrs_hard_denied(addrs: &[SocketAddr]) -> Option<Decision> {
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

/// Offset just past the first `\r\n\r\n` in `buf`, if the head is complete.
fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

/// host:port from a CONNECT target. Port defaults to 443.
fn parse_connect_target(target: &str) -> (String, u16) {
    let (h, p) = target.rsplit_once(':').unwrap_or((target, "443"));
    (h.to_string(), p.parse().unwrap_or(443))
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
    if let Some(d) = pinned_addrs_hard_denied(&addrs) {
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
    let (host, port) = parse_connect_target(target);
    if host.is_empty() {
        let _ = sock
            .write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
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
    let dialed = dial_upstream(ctx.upstream.as_deref(), &host, port, system_lookup).await;
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
async fn handle_forward(
    mut sock: TcpStream,
    ctx: Arc<ConnCtx>,
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

    let mut upstream =
        match dial_upstream(ctx.upstream.as_deref(), &fwd.host, fwd.port, system_lookup).await {
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
        return handle_forward(sock, ctx, target, head, leftover).await;
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
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

    thread_local! {
        /// The credential of the listener this test thread spawned last.
        ///
        /// The suite runs dozens of listeners in one process, and `spawn` now
        /// refuses a token that is already live (P1.6(b)), so the fixture can no
        /// longer hand every listener one constant value. The request builders
        /// (`auth_header`, `connect_req`, `http_req`) read the value from here
        /// instead, which keeps them matching the listener the test just started.
        /// A test that needs a *different* credential presents it explicitly with
        /// `connect_req_with`.
        static LISTENER_TOKEN: std::cell::RefCell<String> =
            std::cell::RefCell::new(TEST_TOKEN.to_string());
    }

    /// A credential no other live listener in this process can already hold.
    ///
    /// `TEST_TOKEN`-prefixed so a leaked value in a log line is recognisably a
    /// fixture, and serialised so the value is deterministic per process.
    fn unique_test_token() -> RunToken {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let serial = NEXT.fetch_add(1, Ordering::Relaxed);
        RunToken::for_tests(&format!("{TEST_TOKEN}-{serial}"))
    }

    /// The credential `auth_header` presents: the last one spawned on this thread.
    fn listener_token() -> String {
        LISTENER_TOKEN.with(|token| token.borrow().clone())
    }

    fn make_head(auth: &str) -> String {
        format!("CONNECT api.example.com:443 HTTP/1.1\r\nProxy-Authorization: {auth}\r\n\r\n")
    }

    fn basic(token: &str) -> String {
        let creds = base64::engine::general_purpose::STANDARD.encode(format!("sandbox:{token}"));
        format!("Basic {creds}")
    }

    fn own_run() -> RunToken {
        RunToken::for_tests("abc123")
    }

    #[test]
    fn valid_basic_auth_is_the_own_run() {
        assert_eq!(
            classify_auth(&make_head(&basic("abc123")), &own_run()),
            AuthVerdict::OwnRun
        );
    }

    #[test]
    fn missing_auth_header_is_absent() {
        let head = "CONNECT api.example.com:443 HTTP/1.1\r\nHost: api.example.com\r\n\r\n";
        assert_eq!(classify_auth(head, &own_run()), AuthVerdict::Absent);
    }

    /// The distinction P1.4 turns on: another run's token is not "no
    /// credential", it is a credential this listener does not own.
    #[test]
    fn another_runs_token_is_foreign_not_absent() {
        assert_eq!(
            classify_auth(&make_head(&basic("another-runs-token")), &own_run()),
            AuthVerdict::Foreign
        );
    }

    #[test]
    fn wrong_scheme_is_absent() {
        let creds = base64::engine::general_purpose::STANDARD.encode("sandbox:abc123");
        let head = make_head(&format!("Bearer {creds}"));
        assert_eq!(classify_auth(&head, &own_run()), AuthVerdict::Absent);
    }

    #[test]
    fn case_insensitive_header_name_is_the_own_run() {
        let creds = base64::engine::general_purpose::STANDARD.encode("sandbox:abc123");
        let head = format!("CONNECT x:443 HTTP/1.1\r\nproxy-AUTHORIZATION: Basic {creds}\r\n\r\n");
        assert_eq!(classify_auth(&head, &own_run()), AuthVerdict::OwnRun);
    }

    #[test]
    fn undecodable_and_colonless_credentials_are_absent() {
        let colonless =
            base64::engine::general_purpose::STANDARD.encode("sandbox-token-without-a-colon");
        for raw in [
            "Basic".to_string(),
            "Basic ".to_string(),
            "Basic !!!not-base64!!!".to_string(),
            format!("Basic {colonless}"),
        ] {
            assert_eq!(
                classify_auth(&make_head(&raw), &own_run()),
                AuthVerdict::Absent,
                "{raw} is not a credential"
            );
        }
    }

    fn temp_sid(label: &str) -> String {
        format!(
            "test-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        )
    }

    #[test]
    fn emit_connect_writes_source_scope_persisted() {
        let sid = temp_sid("src-emit");
        let writer = crate::audit::AuditWriter::open(&sid, false).unwrap();
        emit_connect(
            &writer,
            "api.anthropic.com",
            443,
            "allow",
            None,
            "allowlist",
            None,
            false,
            None,
        )
        .unwrap();
        let path = crate::audit::audit_log_path(&sid);
        let content = std::fs::read_to_string(&path).unwrap();
        let _ = std::fs::remove_file(&path);

        let line = content.trim_end().lines().next().expect("one event line");
        let v: serde_json::Value = serde_json::from_str(line).unwrap();
        assert_eq!(v["op"], "CONNECT");
        assert_eq!(v["disposition"], "allow");
        assert_eq!(v["source"], "allowlist");
        assert_eq!(v["scope"], serde_json::Value::Null);
        assert_eq!(v["persisted"], false);
        assert!(
            v.get("suppressed").is_some(),
            "every leaf carries the key, so a consumer never has to distinguish \
             'absent' from 'nothing suppressed'"
        );
        assert_eq!(v["suppressed"], serde_json::Value::Null);
    }

    #[test]
    fn emit_connect_scope_null_when_none() {
        let sid = temp_sid("src-null");
        let writer = crate::audit::AuditWriter::open(&sid, false).unwrap();
        emit_connect(
            &writer,
            "evil.example.com",
            443,
            "deny",
            Some("domain_not_allowed"),
            "default",
            None,
            false,
            None,
        )
        .unwrap();
        let path = crate::audit::audit_log_path(&sid);
        let content = std::fs::read_to_string(&path).unwrap();
        let _ = std::fs::remove_file(&path);

        let line = content.trim_end().lines().next().unwrap();
        let v: serde_json::Value = serde_json::from_str(line).unwrap();
        // Option<&str>::None serializes to JSON null, not the string "null".
        assert!(v.get("scope").is_some(), "scope key present");
        assert_eq!(v["scope"], serde_json::Value::Null);
    }

    #[test]
    fn emit_connect_persisted_true_serializes_as_boolean() {
        let sid = temp_sid("src-persisted");
        let writer = crate::audit::AuditWriter::open(&sid, false).unwrap();
        emit_connect(
            &writer,
            "api.anthropic.com",
            443,
            "allow",
            None,
            "allowlist",
            Some("session-42"),
            true,
            None,
        )
        .unwrap();
        let path = crate::audit::audit_log_path(&sid);
        let content = std::fs::read_to_string(&path).unwrap();
        let _ = std::fs::remove_file(&path);

        let line = content.trim_end().lines().next().unwrap();
        let v: serde_json::Value = serde_json::from_str(line).unwrap();
        // persisted must be a JSON boolean true, not the string "true".
        assert!(v["persisted"].is_boolean());
        assert_eq!(v["persisted"], true);
        assert_eq!(v["scope"], "session-42");
    }

    /// P1.6 (blocking 1): the suppressed count is a first-class integer field.
    ///
    /// It used to be written as `scope: "suppressed=1"`, which put a number into
    /// a key whose documented domain is rule scope (`once` | `host` | `suffix` |
    /// null) and made the count a constant, because it was computed as
    /// `n - BUDGET` with `n` always one past the budget. Here the field itself is
    /// pinned: a JSON number when a leaf stands in for several refusals, `null`
    /// when it describes exactly one, and `scope` untouched either way.
    #[test]
    fn emit_connect_writes_suppressed_as_an_integer_or_null() {
        let sid = temp_sid("src-suppressed");
        let writer = crate::audit::AuditWriter::open(&sid, false).unwrap();
        emit_connect(
            &writer,
            "<unknown>",
            0,
            "deny",
            Some("no_token_suppressed"),
            "default",
            None,
            false,
            Some(12),
        )
        .unwrap();
        emit_connect(
            &writer,
            "<unknown>",
            0,
            "deny",
            Some("no_token"),
            "default",
            None,
            false,
            None,
        )
        .unwrap();
        let path = crate::audit::audit_log_path(&sid);
        let content = std::fs::read_to_string(&path).unwrap();
        let _ = std::fs::remove_file(&path);

        let mut lines = content.trim_end().lines();
        let aggregate: serde_json::Value = serde_json::from_str(lines.next().unwrap()).unwrap();
        let single: serde_json::Value = serde_json::from_str(lines.next().unwrap()).unwrap();
        assert!(
            aggregate["suppressed"].is_u64(),
            "a count must be a JSON number, not a string: {aggregate:?}"
        );
        assert_eq!(aggregate["suppressed"], 12);
        assert_eq!(
            aggregate["scope"],
            serde_json::Value::Null,
            "scope's domain is rule scope, never a count: {aggregate:?}"
        );
        assert_eq!(
            single["suppressed"],
            serde_json::Value::Null,
            "one request suppresses nothing: {single:?}"
        );
    }

    #[test]
    fn sources_const_is_complete_and_contains_default() {
        // References SOURCES so it isn't flagged dead_code; also pins the
        // D-5 taxonomy so an accidental rename or drop is caught.
        assert!(SOURCES.contains(&"default"));
        assert!(SOURCES.contains(&"allowlist"));
        assert!(SOURCES.contains(&"hard-deny"));
        assert_eq!(
            SOURCES,
            &[
                "hard-deny",
                "learned",
                "blocklist",
                "allowlist",
                "prompt",
                "unavailable",
                "dns",
                "default",
                "prompt_overload",
            ]
        );
    }

    #[test]
    fn deny_source_maps_reasons_to_taxonomy() {
        assert_eq!(deny_source(DenyReason::DeniedDns), "hard-deny");
        assert_eq!(deny_source(DenyReason::DeniedCidr), "hard-deny");
        assert_eq!(deny_source(DenyReason::DeniedDomain), "blocklist");
        assert_eq!(deny_source(DenyReason::DomainNotAllowed), "default");
    }

    // ====================================================================
    // Task 3.6 — prompt + intent + learned wiring. Strict TDD: each new
    // behavior below was watched RED before its implementation landed.
    // ====================================================================

    use crate::net::intent::{DEFAULT_TTL, IntentRegistry};
    use crate::net::learned::LearnedStore;
    use crate::net::prompt::{
        DialogFn, DialogRequest, DialogUnavailable, PromptConfig, PromptOutcome, PromptPolicy,
        PromptResult,
    };
    use std::path::PathBuf;
    use std::sync::Mutex as StdMutex;
    use std::time::Duration;

    /// Session token used by every 3.6 listener test.
    const TEST_TOKEN: &str = "t36-test-token";

    /// One `Deny once` decision, as the dialog backend would return it.
    fn deny_once_result() -> PromptResult {
        PromptResult::Deny {
            persist: false,
            scope: "host".into(),
            suffix: None,
        }
    }

    /// Run one future to completion on a throwaway runtime — the listener
    /// tests are sync (they block on the proxy's own runtime handshake),
    /// so registry/coordinator probes use this instead of `#[tokio::test]`.
    fn block_on<F: std::future::Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(f)
    }

    // ---- RFC3339 formatter (D-4 `ts` field) ------------------------------

    #[test]
    fn rfc3339_utc_known_values() {
        use std::time::{Duration as StdDuration, UNIX_EPOCH};
        assert_eq!(super::rfc3339_utc(UNIX_EPOCH), "1970-01-01T00:00:00Z");
        // 2024-01-01 00:00:00 UTC == 1704067200.
        assert_eq!(
            super::rfc3339_utc(UNIX_EPOCH + StdDuration::from_secs(1_704_067_200)),
            "2024-01-01T00:00:00Z"
        );
        // Hour/minute/second rendering.
        assert_eq!(
            super::rfc3339_utc(UNIX_EPOCH + StdDuration::from_secs(1_704_067_200 + 3661)),
            "2024-01-01T01:01:01Z"
        );
        // Pre-epoch clamps to the epoch — never panics, never negative.
        assert_eq!(
            super::rfc3339_utc(UNIX_EPOCH - StdDuration::from_secs(5)),
            "1970-01-01T00:00:00Z"
        );
    }

    // ---- Happy Eyeballs dial (D-1, [G-12]) -------------------------------

    async fn local_listener() -> (tokio::net::TcpListener, std::net::SocketAddr) {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let a = l.local_addr().unwrap();
        (l, a)
    }

    #[tokio::test]
    async fn happy_eyeballs_first_wins_over_unreachable_first_addr() {
        let (_l, live) = local_listener().await;
        // Nothing listens on 127.0.0.1:1 — loopback connect fails fast.
        let dead = "127.0.0.1:1".parse().unwrap();
        let s = super::happy_eyeballs_dial(vec![dead, live])
            .await
            .expect("must reach the live addr");
        assert_eq!(s.peer_addr().unwrap().port(), live.port());
    }

    #[tokio::test]
    async fn happy_eyeballs_all_dead_is_an_error() {
        let dead = "127.0.0.1:1".parse().unwrap();
        assert!(super::happy_eyeballs_dial(vec![dead, dead]).await.is_err());
    }

    #[tokio::test]
    async fn happy_eyeballs_reaches_addresses_beyond_the_first_batch() {
        let (_l, live) = local_listener().await;
        let mut addrs = Vec::new();
        for _ in 0..super::MAX_PARALLEL_DIALS {
            addrs.push("127.0.0.1:1".parse().unwrap());
        }
        addrs.push(live); // 9th address — only reachable via the 2nd batch.
        let s = super::happy_eyeballs_dial(addrs)
            .await
            .expect("second batch must dial");
        assert_eq!(s.peer_addr().unwrap().port(), live.port());
    }

    // ---- Task 5.2: pinned (admission-time) resolution --------------------

    /// The resolved-IP hard-deny leg is a pure predicate over the pinned set,
    /// so it is testable with any address list and the production dial path
    /// calls exactly this. RFC 3927 link-local, unrelated to the two named
    /// metadata literals — this is the CIDR leg.
    ///
    /// Table-driven over the /16 edges (Task 5.2 spec advisory 6): the first
    /// and last host in 169.254.0.0/16 must deny, the neighbours just outside
    /// must not — an off-by-one in the prefix or a `<=`/`<` slip shows here.
    #[test]
    fn pinned_addrs_hard_denied_catches_link_local_v4() {
        let public: SocketAddr = "203.0.113.9:443".parse().unwrap();
        let cases = [
            ("169.254.0.1:443", true),      // first host of the /16
            ("169.254.31.7:443", true),     // interior
            ("169.254.255.254:443", true),  // last host of the /16
            ("169.255.0.1:443", false),     // one past the /16
            ("169.253.255.254:443", false), // one before it
        ];
        for (addr, denied) in cases {
            let addrs = [public, addr.parse::<SocketAddr>().unwrap()];
            let verdict = super::pinned_addrs_hard_denied(&addrs);
            assert_eq!(
                verdict.is_some(),
                denied,
                "{addr} must {}be hard-denied",
                if denied { "" } else { "NOT " }
            );
            if let Some(d) = verdict {
                assert!(!d.allowed);
                assert_eq!(d.source, "hard-deny");
                assert_eq!(d.reason.as_deref(), Some("denied_cidr"));
            }
        }
    }

    /// fe80::/10 ([G-45]) — the v6 link-local CIDR. Same edge discipline: the
    /// last address of the /10 (`febf:ffff:…:ffff`) denies and `fec0::1`, the
    /// first address outside it, does not.
    #[test]
    fn pinned_addrs_hard_denied_catches_link_local_v6() {
        let public: SocketAddr = "[2001:db8::9]:443".parse().unwrap();
        let cases = [
            ("[fe80::1]:443", true),            // first host of the /10
            ("[fe80:abcd:1234::ff]:443", true), // interior
            ("[febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:443", true), // last address of the /10
            ("[fec0::1]:443", false),           // one past the /10
            ("[fe70::1]:443", false),           // one before it
        ];
        for (addr, denied) in cases {
            let addrs = [public, addr.parse::<SocketAddr>().unwrap()];
            let verdict = super::pinned_addrs_hard_denied(&addrs);
            assert_eq!(
                verdict.is_some(),
                denied,
                "{addr} must {}be hard-denied",
                if denied { "" } else { "NOT " }
            );
            if let Some(d) = verdict {
                assert_eq!(d.reason.as_deref(), Some("denied_cidr"));
            }
        }
    }

    /// No false positives: a public pinned set (and the empty set, which the
    /// DNS-failure path handles) is not a CIDR denial.
    #[test]
    fn pinned_addrs_hard_denied_allows_public_and_empty_sets() {
        let addrs = [
            "203.0.113.9:443".parse::<SocketAddr>().unwrap(),
            "[2001:db8::9]:443".parse::<SocketAddr>().unwrap(),
        ];
        assert!(super::pinned_addrs_hard_denied(&addrs).is_none());
        assert!(super::pinned_addrs_hard_denied(&[]).is_none());
    }

    /// The gap Task 5.1 recorded: the pinned-IP hard-deny leg had no test.
    /// `dial_upstream` is the production call site — a literal keeps the test
    /// DNS-free, and the leg sees the same `Vec<SocketAddr>` a hostname's
    /// resolver answer produces, so this pins the leg a resolving hostname
    /// would hit too.
    ///
    /// The 2s bound (Task 5.2 spec advisory 5) keeps the test FAST-RED: with
    /// the hard-deny removed it reaches a real connect to 169.254.31.7:80 and
    /// would otherwise fail only after the OS SYN timeout (~20s). The bound
    /// does not weaken it — a dial attempt that is actually attempted cannot
    /// be mistaken for a denial.
    #[tokio::test]
    async fn dial_upstream_denies_a_pinned_link_local_v4_literal() {
        match tokio::time::timeout(
            Duration::from_secs(2),
            super::dial_upstream(None, "169.254.31.7", 80, super::system_lookup),
        )
        .await
        {
            Ok(Err(super::DialFailure::Denied(d))) => {
                assert_eq!(d.source, "hard-deny");
                assert_eq!(d.reason.as_deref(), Some("denied_cidr"));
            }
            Ok(Err(_)) => panic!("expected a Denied dial failure, not a dial attempt"),
            Ok(Ok(_)) => panic!("a link-local pinned address must never be dialed"),
            Err(_) => panic!("the deny must be decided before any dial is awaited"),
        }
    }

    #[tokio::test]
    async fn dial_upstream_denies_a_pinned_link_local_v6_literal() {
        match tokio::time::timeout(
            Duration::from_secs(2),
            super::dial_upstream(None, "[fe80::1]", 80, super::system_lookup),
        )
        .await
        {
            Ok(Err(super::DialFailure::Denied(d))) => {
                assert_eq!(d.reason.as_deref(), Some("denied_cidr"));
            }
            Ok(Err(_)) => panic!("expected a Denied dial failure, not a dial attempt"),
            Ok(Ok(_)) => panic!("a link-local pinned address must never be dialed"),
            Err(_) => panic!("the deny must be decided before any dial is awaited"),
        }
    }

    /// The gap Task 5.1 recorded, in its REAL shape: a hostname whose
    /// admission-time answer is link-local. Same production leg as the literal
    /// tests, but the address list arrives from the resolver exactly as a
    /// poisoned DNS answer would.
    #[tokio::test]
    async fn dial_upstream_denies_a_hostname_that_resolves_to_link_local() {
        let calls = AtomicUsize::new(0);
        let result = tokio::time::timeout(
            Duration::from_secs(2),
            super::dial_upstream(None, "metadata.evil.example", 80, |host, port| {
                calls.fetch_add(1, Ordering::SeqCst);
                assert_eq!((host.as_str(), port), ("metadata.evil.example", 80));
                async { Ok(vec!["169.254.31.7:80".parse::<SocketAddr>().unwrap()]) }
            }),
        )
        .await
        .expect("the deny must be decided before any dial is awaited");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        match result {
            Err(super::DialFailure::Denied(d)) => {
                assert_eq!(d.source, "hard-deny");
                assert_eq!(d.reason.as_deref(), Some("denied_cidr"));
            }
            Err(_) => panic!("expected a Denied dial failure, not a dial attempt"),
            Ok(_) => panic!("a hostname resolving into link-local must never be dialed"),
        }
    }

    /// [G-12] at the real call site: ONE resolution per admitted host, and the
    /// dial is seeded with exactly its answer (the winning peer proves which
    /// address was dialed). A second resolution would either bump `calls` or
    /// dial a different address.
    #[tokio::test]
    async fn dial_upstream_resolves_once_and_dials_only_that_answer() {
        let (_l, live) = local_listener().await;
        let calls = AtomicUsize::new(0);
        let s = match super::dial_upstream(None, "pinned.example", live.port(), |host, port| {
            calls.fetch_add(1, Ordering::SeqCst);
            assert_eq!((host.as_str(), port), ("pinned.example", live.port()));
            async move { Ok(vec![live]) }
        })
        .await
        {
            Ok(s) => s,
            Err(_) => panic!("the pinned answer must be dialed"),
        };
        assert_eq!(s.peer_addr().unwrap(), live);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "exactly one resolution per admitted host"
        );
    }

    /// Step 1 / requirement 4: a literal IP is its own answer — the resolver
    /// seam is never consulted (counted, not merely "returns the same thing",
    /// which `lookup_host` would also do for a literal).
    #[tokio::test]
    async fn resolve_pinned_literal_ip_never_calls_the_resolver() {
        let calls = AtomicUsize::new(0);
        let addrs = super::resolve_pinned_with("192.0.2.7", 8443, |_host, _port| {
            calls.fetch_add(1, Ordering::SeqCst);
            async { Ok(Vec::new()) }
        })
        .await
        .unwrap();
        assert_eq!(addrs, vec!["192.0.2.7:8443".parse::<SocketAddr>().unwrap()]);
        let addrs = super::resolve_pinned_with("[2001:db8::9]", 443, |_host, _port| {
            calls.fetch_add(1, Ordering::SeqCst);
            async { Ok(Vec::new()) }
        })
        .await
        .unwrap();
        assert_eq!(
            addrs,
            vec!["[2001:db8::9]:443".parse::<SocketAddr>().unwrap()]
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "a literal IP must not touch the resolver"
        );
    }

    /// Step 1: exactly ONE resolution per admission, and its answer is used
    /// verbatim (brackets stripped, trailing dot and case preserved — the
    /// resolver owns normalization, this seam must not silently rewrite the
    /// name it pins).
    #[tokio::test]
    async fn resolve_pinned_hostname_resolves_exactly_once() {
        let expected = vec![
            "203.0.113.9:443".parse::<SocketAddr>().unwrap(),
            "203.0.113.10:443".parse::<SocketAddr>().unwrap(),
        ];
        let calls = AtomicUsize::new(0);
        let got = super::resolve_pinned_with("Pinned.Example.", 443, |host, port| {
            calls.fetch_add(1, Ordering::SeqCst);
            assert_eq!((host.as_str(), port), ("Pinned.Example.", 443));
            let answer = expected.clone();
            async move { Ok(answer) }
        })
        .await
        .unwrap();
        assert_eq!(got, expected);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "one resolution per admission"
        );
    }

    /// Step 3 / requirement 3 — anti-rebinding. The audit event carries no
    /// `resolved_ips` field (the D-5 taxonomy has no such key), so the pin is
    /// structural: the address list produced at admission is the ONLY list the
    /// dial seam is handed, no second resolution happens, and the socket that
    /// wins belongs to that set.
    #[tokio::test]
    async fn anti_rebinding_dials_exactly_the_admission_resolved_set() {
        let (_l, live) = local_listener().await;
        let dead = "203.0.113.1:443".parse::<SocketAddr>().unwrap();
        let expected = vec![dead, live];
        let answer = expected.clone();
        let resolve_calls = AtomicUsize::new(0);

        // (1) admission: one resolution, answer recorded.
        let admitted = super::resolve_pinned_with("rebind.example", live.port(), |host, port| {
            resolve_calls.fetch_add(1, Ordering::SeqCst);
            assert_eq!((host.as_str(), port), ("rebind.example", live.port()));
            let answer = answer.clone();
            async move { Ok(answer) }
        })
        .await
        .unwrap();
        assert_eq!(resolve_calls.load(Ordering::SeqCst), 1);

        // (2) the dial: every attempted address is recorded. The barrier makes
        // the recording complete before the winner can return.
        let seen = Arc::new(StdMutex::new(Vec::new()));
        let seen_seam = Arc::clone(&seen);
        let barrier = Arc::new(tokio::sync::Barrier::new(admitted.len()));
        // Timeout-bounded (Task 5.2 quality advisory 1): a regression to fewer
        // concurrent dials would leave the barrier unfulfilled forever, and an
        // unbounded barrier HANGS the suite instead of failing it.
        let s = tokio::time::timeout(
            Duration::from_secs(2),
            super::happy_eyeballs_dial_with(admitted.clone(), move |addr| {
                seen_seam.lock().unwrap().push(addr);
                let barrier = Arc::clone(&barrier);
                let fut: std::pin::Pin<Box<dyn Future<Output = io::Result<TcpStream>> + Send>> =
                    Box::pin(async move {
                        barrier.wait().await;
                        if addr == live {
                            TcpStream::connect(live).await
                        } else {
                            Err(io::Error::from(io::ErrorKind::ConnectionRefused))
                        }
                    });
                fut
            }),
        )
        .await
        .expect("every admitted address must be dialed concurrently")
        .unwrap();
        assert_eq!(s.peer_addr().unwrap(), live);
        assert!(
            expected.contains(&s.peer_addr().unwrap()),
            "the winning socket must be one of the admission-resolved addresses"
        );

        let mut dialed = seen.lock().unwrap().clone();
        let mut want = admitted.clone();
        dialed.sort();
        want.sort();
        assert_eq!(
            dialed, want,
            "the dial set must equal the admission-resolved set"
        );
    }

    // ---- Task 5.2: Happy Eyeballs race shape -----------------------------

    /// Step 2: 8 dials in flight at once ([G-12] maxParallelDials). The
    /// barrier of 8 only releases if all eight are awaited concurrently — a
    /// sequential (or 4-wide) implementation times out here.
    #[tokio::test]
    async fn happy_eyeballs_races_eight_addresses_concurrently() {
        assert_eq!(super::MAX_PARALLEL_DIALS, 8, "[G-12] maxParallelDials");
        let (_l, live) = local_listener().await;
        let mut addrs = vec![live];
        for i in 0..7u8 {
            addrs.push(format!("203.0.113.{}:443", i + 1).parse().unwrap());
        }
        let barrier = Arc::new(tokio::sync::Barrier::new(super::MAX_PARALLEL_DIALS));
        let s = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            super::happy_eyeballs_dial_with(addrs, move |addr| {
                let barrier = Arc::clone(&barrier);
                let fut: std::pin::Pin<Box<dyn Future<Output = io::Result<TcpStream>> + Send>> =
                    Box::pin(async move {
                        barrier.wait().await;
                        if addr == live {
                            TcpStream::connect(live).await
                        } else {
                            Err(io::Error::from(io::ErrorKind::ConnectionRefused))
                        }
                    });
                fut
            }),
        )
        .await
        .expect("8 dials must run concurrently")
        .expect("the live address must win");
        assert_eq!(s.peer_addr().unwrap(), live);
    }

    /// The race is capped at 8 IN FLIGHT — not merely "8 per batch step". Every
    /// dial bumps a high-water mark, yields once so its peers can start, then
    /// fails; a 16-address list must still peak at exactly
    /// [`MAX_PARALLEL_DIALS`]. A wider cap peaks at the batch length, a narrower
    /// one below 8.
    ///
    /// `current_thread` is pinned deliberately (Task 5.2 quality advisory 2):
    /// the exact-equality assert is sound only when `yield_now` hands control
    /// to the other spawned dials before any of them decrements the counter.
    /// On a multi-thread flavor the dials can run on separate workers and
    /// finish before their peers start, giving a lower peak — a flake, not a
    /// regression. Pinning the flavor makes the assumption part of the test.
    #[tokio::test(flavor = "current_thread")]
    async fn happy_eyeballs_caps_concurrency_at_eight() {
        let mut addrs = Vec::new();
        for i in 0..16u8 {
            addrs.push(format!("203.0.113.{}:443", i + 1).parse().unwrap());
        }
        let live = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let out = super::happy_eyeballs_dial_with(addrs, {
            let live = Arc::clone(&live);
            let peak = Arc::clone(&peak);
            move |_addr| {
                let live = Arc::clone(&live);
                let peak = Arc::clone(&peak);
                let fut: std::pin::Pin<Box<dyn Future<Output = io::Result<TcpStream>> + Send>> =
                    Box::pin(async move {
                        let now = live.fetch_add(1, Ordering::SeqCst) + 1;
                        peak.fetch_max(now, Ordering::SeqCst);
                        tokio::task::yield_now().await;
                        live.fetch_sub(1, Ordering::SeqCst);
                        Err(io::Error::from(io::ErrorKind::ConnectionRefused))
                    });
                fut
            }
        })
        .await;
        assert!(out.is_err(), "sixteen dead addresses must all fail");
        assert_eq!(
            peak.load(Ordering::SeqCst),
            super::MAX_PARALLEL_DIALS,
            "the race must peak at MAX_PARALLEL_DIALS in flight"
        );
    }

    /// The interleave CALL SITE (not just the pure function): a resolver
    /// answer with every IPv4 first must still put 4+4 into the first batch.
    /// The first eight addresses to reach the barrier ARE that batch — batch
    /// two is not even spawned until batch one has finished.
    #[tokio::test]
    async fn happy_eyeballs_first_batch_interleaves_both_families() {
        let mut addrs: Vec<SocketAddr> = (1..=8)
            .map(|i| format!("203.0.113.{i}:443").parse().unwrap())
            .collect();
        addrs.extend((1..=8).map(|i| {
            format!("[2001:db8::{i}]:443")
                .parse::<SocketAddr>()
                .unwrap()
        }));
        let seen = Arc::new(StdMutex::new(Vec::new()));
        let seen_seam = Arc::clone(&seen);
        let barrier = Arc::new(tokio::sync::Barrier::new(super::MAX_PARALLEL_DIALS));
        // Timeout-bounded (Task 5.2 quality advisory 1): if the first batch
        // ever stopped holding eight concurrent dials the barrier would never
        // release and this would HANG the suite instead of failing it.
        let _ = tokio::time::timeout(
            Duration::from_secs(2),
            super::happy_eyeballs_dial_with(addrs, move |addr| {
                seen_seam.lock().unwrap().push(addr);
                let barrier = Arc::clone(&barrier);
                let fut: std::pin::Pin<Box<dyn Future<Output = io::Result<TcpStream>> + Send>> =
                    Box::pin(async move {
                        barrier.wait().await;
                        Err(io::Error::from(io::ErrorKind::ConnectionRefused))
                    });
                fut
            }),
        )
        .await
        .expect("the first batch must hold 8 concurrent dials");
        let first_batch: Vec<SocketAddr> = seen
            .lock()
            .unwrap()
            .iter()
            .take(super::MAX_PARALLEL_DIALS)
            .cloned()
            .collect();
        assert_eq!(first_batch.len(), super::MAX_PARALLEL_DIALS);
        assert_eq!(
            first_batch.iter().filter(|a| a.is_ipv6()).count(),
            4,
            "the first batch must be 4 IPv6 + 4 IPv4: {first_batch:?}"
        );
    }

    /// Step 2: the race is capped at 8 in flight — a 9th address is spawned
    /// only after the first batch has finished. With a 16-wide cap the 9th
    /// dial would start alongside the first eight and this goes red.
    #[tokio::test]
    async fn happy_eyeballs_ninth_dial_waits_for_the_first_batch() {
        let (_l, live) = local_listener().await;
        let mut addrs = Vec::new();
        for i in 0..8u8 {
            addrs.push(format!("203.0.113.{}:443", i + 1).parse().unwrap());
        }
        addrs.push(live); // 9th — second batch only
        let order = Arc::new(addrs.clone());
        let log = Arc::new(StdMutex::new(Vec::<(usize, &'static str)>::new()));
        let log_seam = Arc::clone(&log);
        let order_seam = Arc::clone(&order);
        let s = super::happy_eyeballs_dial_with(addrs, move |addr| {
            let idx = order_seam.iter().position(|a| *a == addr).unwrap();
            log_seam.lock().unwrap().push((idx, "start"));
            let log = Arc::clone(&log_seam);
            let fut: std::pin::Pin<Box<dyn Future<Output = io::Result<TcpStream>> + Send>> =
                Box::pin(async move {
                    if addr == live {
                        TcpStream::connect(live).await
                    } else {
                        log.lock().unwrap().push((idx, "done"));
                        Err(io::Error::from(io::ErrorKind::ConnectionRefused))
                    }
                });
            fut
        })
        .await
        .expect("the second batch must dial");
        assert_eq!(s.peer_addr().unwrap(), live);

        let events = log.lock().unwrap().clone();
        let ninth_start = events
            .iter()
            .position(|e| e.0 == 8 && e.1 == "start")
            .expect("the 9th dial must have started");
        let last_first_batch = events
            .iter()
            .rposition(|e| e.0 < 8)
            .expect("the first batch must have run");
        assert!(
            last_first_batch < ninth_start,
            "the 9th dial must not start before the first batch ends: {events:?}"
        );
        assert_eq!(events.iter().filter(|e| e.1 == "start").count(), 9);
    }

    /// Step 2: the losers are CANCELLED, not abandoned. Each loser's dial
    /// future holds a drop probe and never resolves; after the winner returns,
    /// both probes must have been dropped — the production path aborts each
    /// loser task and awaits its handle, so cancellation has completed before
    /// `happy_eyeballs_dial` returns.
    #[tokio::test]
    async fn happy_eyeballs_cancels_the_losing_dials() {
        struct CancelProbe(Arc<AtomicUsize>);
        impl Drop for CancelProbe {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        let (_l, live) = local_listener().await;
        let addrs = vec![
            "203.0.113.1:443".parse::<SocketAddr>().unwrap(),
            live,
            "203.0.113.2:443".parse::<SocketAddr>().unwrap(),
        ];
        let cancelled = Arc::new(AtomicUsize::new(0));
        let started = Arc::new(AtomicUsize::new(0));
        let barrier = Arc::new(tokio::sync::Barrier::new(addrs.len()));
        let outcome = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            super::happy_eyeballs_dial_with(addrs, {
                let cancelled = Arc::clone(&cancelled);
                let started = Arc::clone(&started);
                let barrier = Arc::clone(&barrier);
                move |addr| {
                    started.fetch_add(1, Ordering::SeqCst);
                    let probe = if addr == live {
                        None
                    } else {
                        Some(CancelProbe(Arc::clone(&cancelled)))
                    };
                    let barrier = Arc::clone(&barrier);
                    let fut: std::pin::Pin<Box<dyn Future<Output = io::Result<TcpStream>> + Send>> =
                        Box::pin(async move {
                            let _probe = probe;
                            barrier.wait().await;
                            if addr == live {
                                TcpStream::connect(live).await
                            } else {
                                std::future::pending::<io::Result<TcpStream>>().await
                            }
                        });
                    fut
                }
            }),
        )
        .await
        .expect("the race must not hang");
        let s = outcome.expect("the live address must win");
        assert_eq!(s.peer_addr().unwrap(), live);
        assert_eq!(started.load(Ordering::SeqCst), 3, "all three dials start");
        assert_eq!(
            cancelled.load(Ordering::SeqCst),
            2,
            "both losers must be cancelled, not abandoned"
        );
    }

    /// A loser that already CONNECTED is CLOSED, not leaked: the sockets this
    /// race opens must never escape it. Two live local listeners, and a
    /// barrier AFTER the connect, so both dials reach ESTABLISHED before
    /// either can win — the loser in this race is guaranteed to be holding an
    /// open socket. When the race returns, the winner's tunnel still carries
    /// bytes and the loser's peer has seen EOF. Deterministic: no sleeps, and
    /// no assumption about which listener wins.
    #[tokio::test]
    async fn happy_eyeballs_closes_a_loser_that_already_connected() {
        let (la, a) = local_listener().await;
        let (lb, b) = local_listener().await;
        // Accept up front: each connection is witnessed as ESTABLISHED, so the
        // loser's close is observed on a socket that really exists rather than
        // on a half-open backlog entry.
        let acc_a = tokio::spawn(async move { la.accept().await.map(|(s, _)| s) });
        let acc_b = tokio::spawn(async move { lb.accept().await.map(|(s, _)| s) });

        let barrier = Arc::new(tokio::sync::Barrier::new(2));
        let mut s = tokio::time::timeout(
            Duration::from_secs(2),
            super::happy_eyeballs_dial_with(vec![a, b], move |addr| {
                let barrier = Arc::clone(&barrier);
                let fut: std::pin::Pin<Box<dyn Future<Output = io::Result<TcpStream>> + Send>> =
                    Box::pin(async move {
                        let s = TcpStream::connect(addr).await?;
                        // Both dials have CONNECTED before either reports.
                        barrier.wait().await;
                        if addr == a {
                            Ok(s)
                        } else {
                            // The loser holds its ESTABLISHED socket and never
                            // reports: only cancellation (abort AND await, so
                            // the drop has happened by the time the race
                            // returns) can close it.
                            std::future::pending::<()>().await;
                            unreachable!("the pending dial cannot complete")
                        }
                    });
                fut
            }),
        )
        .await
        .expect("the race must not hang")
        .expect("one of two live listeners must win");

        let winner = s.peer_addr().unwrap();
        assert!(
            winner == a || winner == b,
            "the winner must be one of the dialed addresses"
        );
        let (mut winner_peer, mut loser_peer) = if winner == a {
            (acc_a.await.unwrap().unwrap(), acc_b.await.unwrap().unwrap())
        } else {
            (acc_b.await.unwrap().unwrap(), acc_a.await.unwrap().unwrap())
        };

        // The winner's tunnel is alive in both directions ...
        winner_peer.write_all(b"ping").await.unwrap();
        let mut echo = [0u8; 4];
        s.read_exact(&mut echo).await.unwrap();
        assert_eq!(&echo, b"ping");

        // ... while the loser's socket is closed. `read` returning 0 is EOF,
        // i.e. the client side dropped its TcpStream and sent a FIN. Had the
        // loser been abandoned instead of aborted-and-awaited, its socket
        // would still be open and this read would block until the timeout.
        let mut buf = [0u8; 8];
        let n = tokio::time::timeout(Duration::from_secs(2), loser_peer.read(&mut buf))
            .await
            .expect("a connected loser must be closed when the race returns")
            .expect("the close must be graceful, not a reset");
        assert_eq!(n, 0, "the loser's peer must see EOF");
    }

    /// Step 2 as specced: 8 concurrent is 4 IPv6 + 4 IPv4, so the first batch
    /// must alternate families instead of draining the resolver's IPv4 block
    /// before any IPv6 dial starts (RFC 8305 §4 ordering, IPv6 first).
    #[test]
    fn interleave_families_alternates_v6_and_v4() {
        let v6: Vec<SocketAddr> = (1..=4)
            .map(|i| format!("[2001:db8::{i}]:443").parse().unwrap())
            .collect();
        let v4: Vec<SocketAddr> = (1..=4)
            .map(|i| format!("203.0.113.{i}:443").parse().unwrap())
            .collect();
        let mut input = v4.clone();
        input.extend(v6.clone()); // resolver order: every IPv4 first
        let out = super::interleave_families(input);
        assert_eq!(
            out,
            vec![v6[0], v4[0], v6[1], v4[1], v6[2], v4[2], v6[3], v4[3]]
        );
        let first_batch = &out[..super::MAX_PARALLEL_DIALS];
        assert_eq!(
            first_batch.iter().filter(|a| a.is_ipv6()).count(),
            4,
            "the first batch must carry 4 IPv6 + 4 IPv4"
        );
    }

    #[test]
    fn interleave_families_keeps_a_single_family_order() {
        let v4: Vec<SocketAddr> = (1..=3)
            .map(|i| format!("203.0.113.{i}:443").parse().unwrap())
            .collect();
        assert_eq!(super::interleave_families(v4.clone()), v4);
        // Unequal counts: alternation first, then the remainder in place.
        let mixed = vec![
            v4[0],
            "[2001:db8::1]:443".parse::<SocketAddr>().unwrap(),
            v4[1],
            v4[2],
        ];
        assert_eq!(
            super::interleave_families(mixed),
            vec![
                "[2001:db8::1]:443".parse::<SocketAddr>().unwrap(),
                v4[0],
                v4[1],
                v4[2]
            ]
        );
    }

    // ---- PromptOutcome → D-5 audit mapping (pure) -------------------------

    #[test]
    fn outcome_audit_allow_once() {
        let a = super::outcome_audit(&PromptOutcome::Decided(PromptResult::Allow {
            persist: false,
            scope: "host".into(),
            suffix: None,
        }));
        assert!(a.allowed);
        assert_eq!(a.source, "prompt");
        assert_eq!(a.scope.as_deref(), Some("once"));
        assert!(!a.wants_persist);
    }

    #[test]
    fn outcome_audit_allow_persist_host() {
        let a = super::outcome_audit(&PromptOutcome::Decided(PromptResult::Allow {
            persist: true,
            scope: "host".into(),
            suffix: None,
        }));
        assert!(a.allowed);
        assert_eq!(a.source, "prompt");
        assert_eq!(a.scope.as_deref(), Some("host"));
        assert!(a.wants_persist);
    }

    #[test]
    fn outcome_audit_deny_persist_suffix() {
        let a = super::outcome_audit(&PromptOutcome::Decided(PromptResult::Deny {
            persist: true,
            scope: "suffix".into(),
            suffix: Some("example.com".into()),
        }));
        assert!(!a.allowed);
        assert_eq!(a.source, "prompt");
        assert_eq!(a.scope.as_deref(), Some("suffix"));
        assert!(a.wants_persist);
    }

    #[test]
    fn outcome_audit_deny_once() {
        let a = super::outcome_audit(&PromptOutcome::Decided(PromptResult::Deny {
            persist: false,
            scope: "host".into(),
            suffix: None,
        }));
        assert!(!a.allowed);
        assert_eq!(a.source, "prompt");
        assert_eq!(a.scope.as_deref(), Some("once"));
        assert!(!a.wants_persist);
    }

    #[test]
    fn outcome_audit_needs_intent() {
        let a = super::outcome_audit(&PromptOutcome::Decided(PromptResult::NeedsIntent));
        assert!(!a.allowed);
        assert_eq!(a.source, "prompt");
        assert_eq!(a.scope, None);
        assert!(!a.wants_persist);
    }

    #[test]
    fn outcome_audit_overloaded() {
        let a = super::outcome_audit(&PromptOutcome::Overloaded {
            cause: OverloadCause::ConsultationsHeld,
        });
        assert!(!a.allowed);
        assert_eq!(a.source, "prompt_overload");
        assert_eq!(a.scope, None);
        assert!(!a.wants_persist);
    }

    #[test]
    fn outcome_audit_unavailable_respects_policy() {
        let deny = super::outcome_audit(&PromptOutcome::Unavailable {
            allowed: false,
            cause: UnavailableCause::BudgetElapsed,
        });
        assert!(!deny.allowed);
        assert_eq!(deny.source, "unavailable");
        assert_eq!(deny.scope, None);

        let allow = super::outcome_audit(&PromptOutcome::Unavailable {
            allowed: true,
            cause: UnavailableCause::BudgetElapsed,
        });
        assert!(allow.allowed);
        assert_eq!(allow.source, "unavailable");
    }

    #[test]
    fn outcome_audit_disabled() {
        let a = super::outcome_audit(&PromptOutcome::Disabled);
        assert!(!a.allowed);
        assert_eq!(a.source, "default");
        assert_eq!(a.scope, None);
        assert!(!a.wants_persist);
    }

    // ---- Task 3.6 listener scaffolding ------------------------------------
    //
    // Every pipeline test below drives the REAL spawned proxy (real
    // listener, real audit writer, real tokio runtime) with a scripted
    // fake dialog injected through `PromptCoordinator::with_dialog`. The
    // real `show_dialog` must never run here: no desktop is needed and
    // the suite must stay fast.

    /// A fake dialog that records every request it receives and replies
    /// with the scripted result.
    fn recording_dialog(
        reply: Result<PromptResult, DialogUnavailable>,
    ) -> (DialogFn, Arc<StdMutex<Vec<DialogRequest>>>) {
        let calls: Arc<StdMutex<Vec<DialogRequest>>> = Arc::new(StdMutex::new(Vec::new()));
        let seen = Arc::clone(&calls);
        let f: DialogFn = Arc::new(move |req: &DialogRequest| {
            seen.lock().unwrap().push(req.clone());
            reply.clone()
        });
        (f, calls)
    }

    fn allow_once() -> PromptResult {
        PromptResult::Allow {
            persist: false,
            scope: "host".into(),
            suffix: None,
        }
    }

    fn allow_host_persist() -> PromptResult {
        PromptResult::Allow {
            persist: true,
            scope: "host".into(),
            suffix: None,
        }
    }

    fn allow_suffix_persist(suffix: &str) -> PromptResult {
        PromptResult::Allow {
            persist: true,
            scope: "suffix".into(),
            suffix: Some(suffix.to_string()),
        }
    }

    fn deny_host_persist() -> PromptResult {
        PromptResult::Deny {
            persist: true,
            scope: "host".into(),
            suffix: None,
        }
    }

    /// Everything one pipeline test needs: the live proxy plus the shared
    /// intent registry / learned store it was constructed with.
    struct T36 {
        /// Keep-alive: dropping the handle stops the proxy. Never read.
        #[allow(dead_code)]
        handle: super::ProxyHandle,
        port: u16,
        sid: String,
        intent: Arc<IntentRegistry>,
        learned: Arc<StdMutex<LearnedStore>>,
        learned_base: PathBuf,
    }

    impl Drop for T36 {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(crate::audit::audit_log_path(&self.sid));
            let _ = std::fs::remove_dir_all(&self.learned_base);
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn t36_setup_cfg(
        label: &str,
        allow: &[&str],
        deny: &[&str],
        dialog: DialogFn,
        enabled: bool,
        timeout: Duration,
        policy: PromptPolicy,
        upstream: Option<Arc<UpstreamDialer>>,
    ) -> T36 {
        t36_setup_token_cfg(
            label,
            allow,
            deny,
            dialog,
            enabled,
            timeout,
            policy,
            upstream,
            unique_test_token(),
        )
    }

    /// The same listener, with a run token of its own: what P1.4's two-run tests
    /// need to show that a listener refuses every credential but its own.
    #[allow(clippy::too_many_arguments)]
    fn t36_setup_token_cfg(
        label: &str,
        allow: &[&str],
        deny: &[&str],
        dialog: DialogFn,
        enabled: bool,
        timeout: Duration,
        policy: PromptPolicy,
        upstream: Option<Arc<UpstreamDialer>>,
        token: RunToken,
    ) -> T36 {
        try_t36_token_cfg(
            label, allow, deny, dialog, enabled, timeout, policy, upstream, token,
        )
        .expect("spawn test proxy")
    }

    /// [`t36_setup_token_cfg`], with the spawn result kept: the one test that
    /// asserts a *refused* spawn (a duplicate live credential, P1.6(b)) needs the
    /// error, and every other caller wants it unwrapped. A failed attempt leaves
    /// nothing behind: the scratch state it created is removed here.
    #[allow(clippy::too_many_arguments)]
    fn try_t36_token_cfg(
        label: &str,
        allow: &[&str],
        deny: &[&str],
        dialog: DialogFn,
        enabled: bool,
        timeout: Duration,
        policy: PromptPolicy,
        upstream: Option<Arc<UpstreamDialer>>,
        token: RunToken,
    ) -> Result<T36> {
        let token_value = token.value().to_string();
        let learned_base = std::env::temp_dir().join(format!(
            "sandbox-t36-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&learned_base).unwrap();
        let learned = Arc::new(StdMutex::new(
            LearnedStore::load_in(&learned_base, Some("t36")).expect("empty learned store"),
        ));
        let intent = Arc::new(IntentRegistry::new(DEFAULT_TTL));
        let gate = super::PromptGate {
            enabled,
            config: PromptConfig {
                timeout,
                on_unavailable: policy,
            },
            coordinator: Arc::new(PromptCoordinator::with_dialog(dialog)),
            intent: Arc::clone(&intent),
            learned: Arc::clone(&learned),
        };
        let sid = temp_sid(label);
        let writer = Arc::new(crate::audit::AuditWriter::open(&sid, false).unwrap());
        let handle = match super::spawn(super::ProxyConfig {
            session_id: sid.clone(),
            token,
            allow_domain: allow.iter().map(|s| s.to_string()).collect(),
            deny_domain: deny.iter().map(|s| s.to_string()).collect(),
            upstream,
            writer,
            prompt: gate,
        }) {
            Ok(handle) => handle,
            Err(e) => {
                let _ = std::fs::remove_file(crate::audit::audit_log_path(&sid));
                let _ = std::fs::remove_dir_all(&learned_base);
                return Err(e);
            }
        };
        let port = handle.port;
        // The helpers below build requests for *this* listener's credential.
        LISTENER_TOKEN.with(|current| *current.borrow_mut() = token_value);
        Ok(T36 {
            handle,
            port,
            sid,
            intent,
            learned,
            learned_base,
        })
    }

    /// Default-config test proxy: prompting enabled, 60 s timeout,
    /// deny-on-unavailable.
    fn t36_setup(label: &str, allow: &[&str], deny: &[&str], dialog: DialogFn) -> T36 {
        t36_setup_cfg(
            label,
            allow,
            deny,
            dialog,
            true,
            Duration::from_secs(60),
            PromptPolicy::Deny,
            None,
        )
    }

    /// One blocking request/response round-trip against the test proxy.
    /// The handler closes the socket after answering, so `read_to_end`
    /// ends at EOF; the 5 s timeout bounds a hung handler.
    fn exchange(port: u16, request: &str) -> String {
        use std::io::{Read, Write};
        let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).expect("connect test proxy");
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        s.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
        s.write_all(request.as_bytes()).expect("write request");
        let mut out = Vec::new();
        let _ = s.read_to_end(&mut out);
        String::from_utf8_lossy(&out).into_owned()
    }

    fn auth_header() -> String {
        let creds = base64::engine::general_purpose::STANDARD
            .encode(format!("sandbox:{}", listener_token()));
        format!("Proxy-Authorization: Basic {creds}\r\n")
    }

    fn connect_req(target: &str) -> String {
        format!("CONNECT {target} HTTP/1.1\r\n{}\r\n", auth_header())
    }

    fn connect_req_no_auth(target: &str) -> String {
        format!("CONNECT {target} HTTP/1.1\r\n\r\n")
    }

    fn connect_events(sid: &str) -> Vec<serde_json::Value> {
        std::fs::read_to_string(crate::audit::audit_log_path(sid))
            .unwrap_or_default()
            .lines()
            .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
            .filter(|v| v["op"] == "CONNECT")
            .collect()
    }

    fn last_connect_event(sid: &str) -> serde_json::Value {
        let mut evs = connect_events(sid);
        assert!(!evs.is_empty(), "expected a CONNECT audit event");
        evs.pop().unwrap()
    }

    // ---- (1)-(2): loopback refused before anything else --------------------

    #[test]
    fn connect_loopback_refused_without_prompting() {
        let (dialog, calls) = recording_dialog(Ok(deny_once_result()));
        let t = t36_setup("loopback-ip", &[], &[], dialog);
        let resp = exchange(t.port, &connect_req("127.0.0.1:5432"));
        assert!(resp.starts_with("HTTP/1.1 403"), "got: {resp}");
        assert!(resp.contains("X-Sandbox: denied"), "got: {resp}");
        assert!(
            calls.lock().unwrap().is_empty(),
            "loopback must never prompt"
        );
        let ev = last_connect_event(&t.sid);
        assert_eq!(ev["disposition"], "deny");
        assert_eq!(ev["source"], "hard-deny");
        assert_eq!(ev["reason"], "loopback_refused");
    }

    #[test]
    fn connect_localhost_name_refused() {
        let (dialog, calls) = recording_dialog(Ok(deny_once_result()));
        let t = t36_setup("loopback-name", &[], &[], dialog);
        let resp = exchange(t.port, &connect_req("localhost:8080"));
        assert!(resp.starts_with("HTTP/1.1 403"), "got: {resp}");
        assert!(calls.lock().unwrap().is_empty());
        let ev = last_connect_event(&t.sid);
        assert_eq!(ev["source"], "hard-deny");
        assert_eq!(ev["reason"], "loopback_refused");
    }

    #[test]
    fn loopback_refused_even_when_allowlisted() {
        // [G-44] the loopback refusal is a pre-stage of the hard-deny: an
        // allow_domain entry for `localhost` must not reopen a tunnel to host
        // services. Pins the loopback stage against the allow-list stage.
        let (dialog, calls) = recording_dialog(Ok(allow_once()));
        let t = t36_setup("loopback-allow", &["localhost", "127.0.0.1"], &[], dialog);
        let resp = exchange(t.port, &connect_req("localhost:8080"));
        assert!(resp.starts_with("HTTP/1.1 403"), "got: {resp}");
        assert!(resp.contains("X-Sandbox: denied"), "got: {resp}");
        assert!(calls.lock().unwrap().is_empty());
        let ev = last_connect_event(&t.sid);
        assert_eq!(ev["source"], "hard-deny");
        assert_eq!(ev["reason"], "loopback_refused");
    }

    // ---- (3): hard-deny beats blocklist, allowlist, learned and prompt -----

    #[test]
    fn hard_deny_beats_blocklist_and_prompt() {
        // The host is ALSO on the deny_domain blocklist — hard-deny must
        // still win, because the audit reason distinguishes them.
        let (dialog, calls) = recording_dialog(Ok(deny_once_result()));
        let t = t36_setup("hard-deny-dns", &[], &["metadata.google.internal"], dialog);
        let resp = exchange(t.port, &connect_req("metadata.google.internal:80"));
        assert!(resp.starts_with("HTTP/1.1 403"), "got: {resp}");
        assert!(resp.contains("X-Sandbox: denied"), "got: {resp}");
        assert!(calls.lock().unwrap().is_empty());
        let ev = last_connect_event(&t.sid);
        assert_eq!(ev["source"], "hard-deny");
        assert_eq!(ev["reason"], "denied_dns");
    }

    #[test]
    fn hard_deny_ip_literal_refused() {
        let (dialog, calls) = recording_dialog(Ok(deny_once_result()));
        let t = t36_setup("hard-deny-ip", &[], &[], dialog);
        let resp = exchange(t.port, &connect_req("169.254.169.253:80"));
        assert!(resp.starts_with("HTTP/1.1 403"), "got: {resp}");
        assert!(calls.lock().unwrap().is_empty());
        let ev = last_connect_event(&t.sid);
        assert_eq!(ev["source"], "hard-deny");
        assert_eq!(ev["reason"], "denied_cidr");
    }

    #[test]
    fn hard_deny_bracketed_ipv6_literal_refused() {
        let (dialog, calls) = recording_dialog(Ok(deny_once_result()));
        let t = t36_setup("hard-deny-v6", &[], &[], dialog);
        let resp = exchange(t.port, &connect_req("[fe80::1]:443"));
        assert!(resp.starts_with("HTTP/1.1 403"), "got: {resp}");
        assert!(calls.lock().unwrap().is_empty());
        let ev = last_connect_event(&t.sid);
        assert_eq!(ev["source"], "hard-deny");
        assert_eq!(ev["reason"], "denied_cidr");
    }

    #[test]
    fn hard_deny_beats_learned_deny() {
        let (dialog, _calls) = recording_dialog(Ok(deny_once_result()));
        let t = t36_setup("hard-deny-learned", &[], &[], dialog);
        t.learned
            .lock()
            .unwrap()
            .record("metadata.google.internal", "host", false)
            .unwrap();
        let resp = exchange(t.port, &connect_req("metadata.google.internal:80"));
        assert!(resp.starts_with("HTTP/1.1 403"), "got: {resp}");
        let ev = last_connect_event(&t.sid);
        assert_eq!(ev["source"], "hard-deny", "hard-deny must outrank learned");
        assert_eq!(ev["persisted"], false);
    }

    #[test]
    fn hard_deny_beats_allowlist() {
        // [G-18, G-33] step 1 outranks step 4: an operator who allow-lists a
        // metadata name still cannot reach it, and the audit source names the
        // stage that answered (`allowlist` here would be the bug).
        let (dialog, calls) = recording_dialog(Ok(deny_once_result()));
        let t = t36_setup(
            "hard-deny-allow",
            &["metadata.google.internal", "*.google.internal"],
            &[],
            dialog,
        );
        let resp = exchange(t.port, &connect_req("metadata.google.internal:80"));
        assert!(resp.starts_with("HTTP/1.1 403"), "got: {resp}");
        assert!(resp.contains("X-Sandbox: denied"), "got: {resp}");
        assert!(
            calls.lock().unwrap().is_empty(),
            "hard-deny must not prompt"
        );
        let ev = last_connect_event(&t.sid);
        assert_eq!(ev["source"], "hard-deny");
        assert_eq!(ev["reason"], "denied_dns");
    }

    // ---- (4): learned-deny beats blocklist and allowlist -------------------

    #[test]
    fn learned_deny_beats_blocklist_and_allowlist() {
        let (dialog, calls) = recording_dialog(Ok(allow_once()));
        let t = t36_setup(
            "learned-deny",
            &["*.example.com"],
            &["*.example.com"],
            dialog,
        );
        t.learned
            .lock()
            .unwrap()
            .record("evil.example.com", "host", false)
            .unwrap();
        let resp = exchange(t.port, &connect_req("evil.example.com:443"));
        assert!(resp.starts_with("HTTP/1.1 403"), "got: {resp}");
        assert!(
            calls.lock().unwrap().is_empty(),
            "learned deny must not prompt"
        );
        let ev = last_connect_event(&t.sid);
        assert_eq!(ev["source"], "learned");
        assert_eq!(ev["scope"], "host");
        assert_eq!(ev["persisted"], true);
    }

    // ---- (5): deny_domain blocklist beats allow_domain ---------------------

    #[test]
    fn blocklist_beats_allowlist() {
        let (dialog, _calls) = recording_dialog(Ok(allow_once()));
        let t = t36_setup(
            "blocklist",
            &["evil.example.com"],
            &["*.example.com"],
            dialog,
        );
        let resp = exchange(t.port, &connect_req("evil.example.com:443"));
        assert!(resp.starts_with("HTTP/1.1 403"), "got: {resp}");
        let ev = last_connect_event(&t.sid);
        assert_eq!(ev["source"], "blocklist");
        assert_eq!(ev["reason"], "denied_domain");
    }

    #[test]
    fn blocklist_beats_learned_allow() {
        // [G-33] step 3 outranks step 4's learned-allow half: a deny_domain
        // entry added after the user once allowed the host still wins. The
        // mirror of `learned_deny_beats_blocklist_and_allowlist`, which pins
        // the opposite direction (learned deny is step 2).
        let (dialog, calls) = recording_dialog(Ok(allow_once()));
        let t = t36_setup("blocklist-learned-allow", &[], &["*.example.com"], dialog);
        t.learned
            .lock()
            .unwrap()
            .record("evil.example.com", "host", true)
            .unwrap();
        let resp = exchange(t.port, &connect_req("evil.example.com:443"));
        assert!(resp.starts_with("HTTP/1.1 403"), "got: {resp}");
        assert!(
            calls.lock().unwrap().is_empty(),
            "blocklist must not prompt"
        );
        let ev = last_connect_event(&t.sid);
        assert_eq!(ev["source"], "blocklist");
        assert_eq!(ev["reason"], "denied_domain");
    }

    // ---- (6): allow_domain / learned-allow admit without prompting --------

    #[test]
    fn allowlist_allows_without_prompt() {
        let (dialog, calls) = recording_dialog(Ok(deny_once_result()));
        let t = t36_setup("allowlist", &["nx-allowlist.invalid"], &[], dialog);
        let resp = exchange(t.port, &connect_req("nx-allowlist.invalid:443"));
        assert!(
            resp.starts_with("HTTP/1.1 403") || resp.starts_with("HTTP/1.1 502"),
            "got: {resp}"
        );
        assert!(
            calls.lock().unwrap().is_empty(),
            "allow-listed host must not prompt"
        );
        let ev = last_connect_event(&t.sid);
        let src = ev["source"].as_str().unwrap();
        assert!(
            src == "allowlist" || src == "dns",
            "allow-listed host may only fail at DNS, got {src}"
        );
    }

    #[test]
    fn learned_allow_allows_without_prompt() {
        let (dialog, calls) = recording_dialog(Ok(deny_once_result()));
        let t = t36_setup("learned-allow", &[], &[], dialog);
        t.learned
            .lock()
            .unwrap()
            .record("nx-learned-allow.invalid", "host", true)
            .unwrap();
        let resp = exchange(t.port, &connect_req("nx-learned-allow.invalid:443"));
        assert!(
            resp.starts_with("HTTP/1.1 403") || resp.starts_with("HTTP/1.1 502"),
            "got: {resp}"
        );
        assert!(calls.lock().unwrap().is_empty());
        let ev = last_connect_event(&t.sid);
        let src = ev["source"].as_str().unwrap();
        assert!(
            src == "learned" || src == "dns",
            "learned-allowed host may only fail at DNS, got {src}"
        );
    }

    #[test]
    fn learned_allow_admits_in_allowlist_mode() {
        // [G-33] step 4 is "allow_domain OR learned allow", so a learned allow
        // must still admit when the allow-list is non-empty and lacks the
        // host — i.e. ahead of the step-5 allowlist-mode default, which would
        // prompt here. `learned_allow_allows_without_prompt` covers the same
        // stage with an EMPTY allow-list (pure blocklist mode), so it cannot
        // pin this pair.
        let (dialog, calls) = recording_dialog(Ok(deny_once_result()));
        let t = t36_setup("learned-allow-mode", &["api.allowed.invalid"], &[], dialog);
        t.learned
            .lock()
            .unwrap()
            .record("nx-learned-mode.invalid", "host", true)
            .unwrap();
        exchange(t.port, &connect_req("nx-learned-mode.invalid:443"));
        assert!(
            calls.lock().unwrap().is_empty(),
            "learned allow must not prompt"
        );
        let evs = connect_events(&t.sid);
        assert!(
            evs.iter()
                .any(|e| e["source"] == "learned" && e["disposition"] == "allow"),
            "admission leaf must be a learned allow: {evs:?}"
        );
    }

    // ---- (7): prompt outcomes ----------------------------------------------

    #[test]
    fn prompt_deny_once_is_not_persisted() {
        let (dialog, calls) = recording_dialog(Ok(deny_once_result()));
        let t = t36_setup("prompt-deny-once", &[], &[], dialog);
        let resp = exchange(t.port, &connect_req("prompted-deny.invalid:443"));
        assert!(resp.starts_with("HTTP/1.1 403"), "got: {resp}");
        assert_eq!(
            calls.lock().unwrap().len(),
            1,
            "exactly one dialog expected"
        );
        let ev = last_connect_event(&t.sid);
        assert_eq!(ev["disposition"], "deny");
        assert_eq!(ev["source"], "prompt");
        assert_eq!(ev["scope"], "once");
        assert_eq!(ev["persisted"], false);
        assert!(
            t.learned.lock().unwrap().entries().is_empty(),
            "no persistence expected"
        );
    }

    #[test]
    fn prompt_deny_persist_records_learned_deny() {
        let (dialog, _calls) = recording_dialog(Ok(deny_host_persist()));
        let t = t36_setup("prompt-deny-persist", &[], &[], dialog);
        let resp = exchange(t.port, &connect_req("persist-deny.invalid:443"));
        assert!(resp.starts_with("HTTP/1.1 403"), "got: {resp}");
        let ev = last_connect_event(&t.sid);
        assert_eq!(ev["source"], "prompt");
        assert_eq!(ev["scope"], "host");
        assert_eq!(ev["persisted"], true);
        let learned = t.learned.lock().unwrap().lookup("persist-deny.invalid");
        assert_eq!(
            learned,
            Some(crate::net::learned::LearnedDecision {
                allow: false,
                scope: "host".into()
            })
        );
    }

    #[test]
    fn prompt_allow_persist_host_records_learned_allow() {
        let (dialog, calls) = recording_dialog(Ok(allow_host_persist()));
        let t = t36_setup("prompt-allow-host", &[], &[], dialog);
        let resp = exchange(t.port, &connect_req("persist-allow.invalid:443"));
        assert!(
            resp.starts_with("HTTP/1.1 403") || resp.starts_with("HTTP/1.1 502"),
            "admitted request may only fail at DNS/dial, got: {resp}"
        );
        assert_eq!(calls.lock().unwrap().len(), 1);
        let learned = t.learned.lock().unwrap().lookup("persist-allow.invalid");
        assert_eq!(
            learned,
            Some(crate::net::learned::LearnedDecision {
                allow: true,
                scope: "host".into()
            })
        );
        let ev = last_connect_event(&t.sid);
        if ev["disposition"] == "allow" {
            assert_eq!(ev["source"], "prompt");
            assert_eq!(ev["scope"], "host");
            assert_eq!(ev["persisted"], true);
        } else {
            // Hermetic default: NXDOMAIN for .invalid → denied at DNS.
            assert_eq!(ev["source"], "dns");
        }
    }

    #[test]
    fn prompt_allow_persist_suffix_records_suffix_entry() {
        let (dialog, _calls) = recording_dialog(Ok(allow_suffix_persist("persist-suffix.invalid")));
        let t = t36_setup("prompt-allow-suffix", &[], &[], dialog);
        let resp = exchange(t.port, &connect_req("cdn.persist-suffix.invalid:443"));
        assert!(
            resp.starts_with("HTTP/1.1 403") || resp.starts_with("HTTP/1.1 502"),
            "got: {resp}"
        );
        // The suffix entry must cover both the apex and subdomains.
        let learned = t
            .learned
            .lock()
            .unwrap()
            .lookup("api.persist-suffix.invalid");
        assert_eq!(
            learned,
            Some(crate::net::learned::LearnedDecision {
                allow: true,
                scope: "suffix".into()
            })
        );
        assert!(
            t.learned
                .lock()
                .unwrap()
                .lookup("persist-suffix.invalid")
                .is_some()
        );
    }

    #[test]
    fn prompt_needs_intent_sets_flag_and_hint_header() {
        let (dialog, _calls) = recording_dialog(Ok(PromptResult::NeedsIntent));
        let t = t36_setup("prompt-explain", &[], &[], dialog);
        let resp = exchange(t.port, &connect_req("explain.invalid:443"));
        assert!(resp.starts_with("HTTP/1.1 403"), "got: {resp}");
        assert!(
            resp.contains("X-Sandbox-Intent-Hint: explain-more"),
            "deny for NeedsIntent must carry the intent hint, got: {resp}"
        );
        // The one-shot flag must now be set for the agent to consume.
        let flagged = block_on(t.intent.consume_explain_more("explain.invalid"));
        assert!(flagged, "explain-more flag expected after NeedsIntent");
        let ev = last_connect_event(&t.sid);
        assert_eq!(ev["disposition"], "deny");
        assert_eq!(ev["source"], "prompt");
    }

    #[test]
    fn prompt_unavailable_deny_maps_to_unavailable_source() {
        let (dialog, _calls) = recording_dialog(Err(DialogUnavailable));
        let t = t36_setup("prompt-unavail", &[], &[], dialog);
        let resp = exchange(t.port, &connect_req("unavailable.invalid:443"));
        assert!(resp.starts_with("HTTP/1.1 403"), "got: {resp}");
        assert!(resp.contains("X-Sandbox: denied"), "got: {resp}");
        let ev = last_connect_event(&t.sid);
        assert_eq!(ev["source"], "unavailable");
        assert_eq!(ev["persisted"], false);
    }

    #[test]
    fn prompt_zero_timeout_is_disabled_and_never_shows_a_dialog() {
        let (dialog, calls) = recording_dialog(Ok(allow_host_persist()));
        let t = t36_setup_cfg(
            "prompt-disabled",
            &[],
            &[],
            dialog,
            true, // prompt_enabled, but timeout 0 → coordinator returns Disabled
            Duration::ZERO,
            PromptPolicy::Deny,
            None,
        );
        let resp = exchange(t.port, &connect_req("zero-timeout.invalid:443"));
        assert!(resp.starts_with("HTTP/1.1 403"), "got: {resp}");
        assert!(
            calls.lock().unwrap().is_empty(),
            "zero timeout must never show a dialog"
        );
        let ev = last_connect_event(&t.sid);
        assert_eq!(ev["source"], "default");
    }

    // ---- P2.1: the prompt budget on BOTH legs (D3 addendum) ----------------

    /// A dialog that is still up when the budget elapses: the coordinator
    /// abandons it after `budget` and its late answer is discarded ([G-4]).
    fn slow_dialog(up: Duration) -> DialogFn {
        Arc::new(move |_req: &DialogRequest| {
            std::thread::sleep(up);
            Err(DialogUnavailable)
        })
    }

    /// A dialog that never returns on its own: it blocks until the test drops the
    /// gate, so the coordinator's orphans are *still up* while the test asserts —
    /// the headless case, where nobody can answer the dialog at all.
    fn gated_dialog() -> (DialogFn, std::sync::mpsc::Sender<()>) {
        let (gate, wait) = std::sync::mpsc::channel::<()>();
        let wait = Arc::new(StdMutex::new(wait));
        let dialog: DialogFn = Arc::new(move |_req: &DialogRequest| {
            let rx = wait.lock().unwrap_or_else(|poison| poison.into_inner());
            let _ = rx.recv();
            Err(DialogUnavailable)
        });
        (dialog, gate)
    }

    /// D3 addendum, first half: a **plain-HTTP absolute-form** request to a host
    /// that reaches the prompt policy is bounded by the prompt budget exactly like
    /// CONNECT, gets the deny on the wire, leaves exactly one leaf, and never
    /// dials an origin.
    ///
    /// Before P2.1 the same request in a headless run stalled for the whole
    /// budget with no answer available (measured as curl exit 28 at `-m 15`) and
    /// the audit said "timeout or no dialog backend" — one string for two
    /// different failures, and nothing that named the budget as the cause.
    #[test]
    fn forward_prompt_timeout_is_bounded_by_the_budget_and_never_dials() {
        let fake = FakeUpstream::start(200);
        let t = t36_setup_cfg(
            "fwd-prompt-budget",
            &[],
            &[],
            slow_dialog(Duration::from_millis(800)),
            true,
            Duration::from_millis(200),
            PromptPolicy::Deny,
            Some(dialer(&fake.url(), &[])),
        );
        let counters = t.handle.counters();
        let epoch = counters.begin_epoch().expect("the launch's window");

        let started = std::time::Instant::now();
        let resp = exchange(t.port, &get_req("http://unlisted-forward.invalid/x"));
        let elapsed = started.elapsed();

        // The wire answer: the deny, promptly (bounded by the budget, not by the
        // dialog's own 800 ms), and it names the spent budget as the reason.
        assert!(resp.starts_with("HTTP/1.1 403"), "got: {resp}");
        assert!(resp.contains("X-Sandbox: denied"), "got: {resp}");
        assert!(
            resp.contains(PROMPT_TIMEOUT_REASON),
            "the deny must name the spent budget ({PROMPT_TIMEOUT_REASON}), got: {resp}"
        );
        assert!(
            elapsed < Duration::from_millis(700),
            "the forward leg must be bounded by the prompt budget, not by the dialog: {elapsed:?}"
        );

        // Exactly one leaf for the one timed-out request, with the reason a
        // CONNECT timeout produces.
        let leaves = connect_events(&t.sid);
        assert_eq!(
            leaves.len(),
            1,
            "one leaf per timed-out request: {leaves:?}"
        );
        assert_eq!(leaves[0]["host"], "unlisted-forward.invalid");
        assert_eq!(leaves[0]["port"], 80);
        assert_eq!(leaves[0]["disposition"], "deny");
        assert_eq!(leaves[0]["reason"], PROMPT_TIMEOUT_REASON);
        assert_eq!(leaves[0]["source"], "unavailable");

        // Counters: it WAS a consultation (accepted), and nothing was
        // tunnelled — the deny happened before any dial.
        assert_eq!(
            counters.counters(epoch),
            Some(LaunchProofCounters {
                consultations: 1,
                upstream_established: 0,
                probes: 0,
            }),
            "a denied forward is an accepted consultation with no upstream"
        );
        // The observable proof that no origin was involved: the chaining dialer
        // is the only outbound hop a forward can take, and it saw nothing.
        assert!(
            fake.heads().is_empty(),
            "a denied forward must not reach an origin: {:?}",
            fake.heads()
        );
        assert!(counters.close_epoch(epoch));
    }

    /// D3 addendum, second half: both legs produce the **same leaf shape** for the
    /// same timeout outcome — same keys, same `reason`, same `source` — and one
    /// leaf each. A forward deny must not be a second-class leaf: a consumer
    /// filtering on `reason` cannot be asked to know which leg produced it.
    #[test]
    fn connect_and_forward_prompt_timeouts_emit_the_same_deny_leaf() {
        let t = t36_setup_cfg(
            "prompt-parity",
            &[],
            &[],
            slow_dialog(Duration::from_millis(700)),
            true,
            Duration::from_millis(150),
            PromptPolicy::Deny,
            None,
        );

        let connect = exchange(t.port, &connect_req("parity-connect.invalid:443"));
        let forward = exchange(t.port, &get_req("http://parity-forward.invalid/x"));
        assert!(connect.starts_with("HTTP/1.1 403"), "got: {connect}");
        assert!(forward.starts_with("HTTP/1.1 403"), "got: {forward}");
        assert!(connect.contains(PROMPT_TIMEOUT_REASON), "got: {connect}");
        assert!(forward.contains(PROMPT_TIMEOUT_REASON), "got: {forward}");

        let leaves = connect_events(&t.sid);
        assert_eq!(
            leaves.len(),
            2,
            "one leaf per timed-out request, no doubles: {leaves:?}"
        );
        let keys = |v: &serde_json::Value| {
            let mut k: Vec<String> = v
                .as_object()
                .expect("leaf is an object")
                .keys()
                .cloned()
                .collect();
            k.sort();
            k
        };
        assert_eq!(
            keys(&leaves[0]),
            keys(&leaves[1]),
            "both legs must write the same leaf shape"
        );
        for field in [
            "reason",
            "source",
            "disposition",
            "scope",
            "persisted",
            "op",
        ] {
            assert_eq!(
                leaves[0][field], leaves[1][field],
                "`{field}` must be identical on both legs"
            );
        }
        assert_eq!(leaves[0]["reason"], PROMPT_TIMEOUT_REASON);
        // Not vacuous: the two leaves really are different requests.
        assert_ne!(leaves[0]["host"], leaves[1]["host"]);
        assert_eq!(leaves[0]["port"], 443);
        assert_eq!(leaves[1]["port"], 80);
    }

    /// The measurement the session budget is attributed with (P2.1): the listener
    /// times its own prompt consultations, so a session killed at its deadline can
    /// say *which* term spent the time. The control is the important half — a
    /// decision that never consulted a dialog must add nothing, or every session
    /// would look prompt-bound.
    #[test]
    fn prompt_consultation_time_is_measured_and_a_static_decision_adds_none() {
        let t = t36_setup(
            "prompt-clock",
            &["pre-approved.invalid"],
            &[],
            slow_dialog(Duration::from_millis(120)),
        );
        let counters = t.handle.counters();
        assert_eq!(
            counters.prompt_wait(),
            Duration::ZERO,
            "a fresh listener has spent no prompt time"
        );

        let resp = exchange(t.port, &connect_req("measured.invalid:443"));
        assert!(resp.starts_with("HTTP/1.1 403"), "got: {resp}");
        let waited = counters.prompt_wait();
        assert!(
            waited >= Duration::from_millis(100),
            "a dialog that took 120 ms must be measured, got {waited:?}"
        );
        assert!(waited < Duration::from_secs(5), "got {waited:?}");

        // A static answer (allow-list) consults no dialog: the measure must not move.
        // (An allow-listed host is admitted and then fails at the dial — there is no
        // such name on this network — but it is a `dns` decision, not a prompt.)
        let resp = exchange(t.port, &get_req("http://pre-approved.invalid/x"));
        assert!(resp.starts_with("HTTP/1.1 403"), "got: {resp}");
        assert!(
            resp.contains("dns policy"),
            "an allow-listed forward must be answered by the static layer: {resp}"
        );
        assert_eq!(
            counters.prompt_wait(),
            waited,
            "a decision that never prompted must add no prompt time"
        );
    }

    /// The resource-exhaustion half (P2.1) **and** the fast-fail that now
    /// supersedes it (item 3): a timed-out consultation must not keep its
    /// coordinator slot — eight of them used to consume all
    /// `MAX_CONCURRENT_PROMPTS` permits for the life of the process, so the ninth
    /// request was answered `prompt_overload` without its budget ever being
    /// consulted — and after `NO_BACKEND_STICKY_AFTER` of them the session stops
    /// paying the budget at all.
    ///
    /// Round 2, item 8: the skipped requests are answered on the cause that ARMED
    /// the latch, not on the nearest-looking one. These dialogs were shown and
    /// nobody answered them, so the reason is `prompt_suppressed_after_budget` —
    /// `no_dialog_backend` would tell the operator to run interactively when the
    /// interactive path demonstrably worked.
    ///
    /// Nine sequential requests, each with its dialog still up when the budget
    /// elapses (the routine headless state). The first two are denied on budget,
    /// the rest are denied immediately on `no_dialog_backend`, and *none* of them
    /// is ever an overload denial: the path neither wedges nor keeps stalling.
    #[test]
    fn nine_unanswered_prompts_never_wedge_into_overload_and_stop_paying_the_budget() {
        let budget = Duration::from_millis(80);
        let (dialog, gate) = gated_dialog();
        let t = t36_setup_cfg(
            "prompt-slots",
            &[],
            &[],
            dialog,
            true,
            budget,
            PromptPolicy::Deny,
            None,
        );

        let mut elapsed = Vec::new();
        for i in 0..=crate::net::prompt::MAX_CONCURRENT_PROMPTS {
            let host = format!("slot-{i}.invalid");
            let started = std::time::Instant::now();
            let resp = exchange(t.port, &get_req(&format!("http://{host}/x")));
            elapsed.push(started.elapsed());
            assert!(resp.starts_with("HTTP/1.1 403"), "host {i}: got {resp}");
            assert!(
                !resp.contains(PROMPT_OVERLOAD_REASON)
                    && !resp.contains(PROMPT_ABANDONED_CAPACITY_REASON),
                "host {i} must not be refused for capacity, no dialog is at fault: {resp}"
            );
            let ev = last_connect_event(&t.sid);
            assert_eq!(
                ev["source"], "unavailable",
                "host {i} must reach the prompt layer, got {ev}"
            );
            let expected = if i < crate::net::prompt::NO_BACKEND_STICKY_AFTER {
                PROMPT_TIMEOUT_REASON
            } else {
                PROMPT_SUPPRESSED_REASON
            };
            assert_eq!(
                ev["reason"],
                expected,
                "host {i} must be denied on {}, got {ev}",
                if i < crate::net::prompt::NO_BACKEND_STICKY_AFTER {
                    "the budget"
                } else {
                    "the budget that armed the latch"
                }
            );
            assert_eq!(ev["host"], host);
        }
        assert_eq!(
            connect_events(&t.sid).len(),
            crate::net::prompt::MAX_CONCURRENT_PROMPTS + 1,
            "one leaf per request"
        );
        // The measured cost: the first `NO_BACKEND_STICKY_AFTER` pay the budget,
        // the rest do not.
        for (i, e) in elapsed.iter().enumerate() {
            if i < crate::net::prompt::NO_BACKEND_STICKY_AFTER {
                assert!(
                    *e >= budget / 2,
                    "request {i} must wait for its budget: {e:?}"
                );
            } else {
                assert!(
                    *e < budget / 2,
                    "request {i} must be denied without waiting for the budget: {e:?}"
                );
            }
        }
        println!("EVIDENCE nine-headless budget={budget:?} elapsed={elapsed:?}");
        // Release the orphans so no blocking thread outlives the test.
        drop(gate);
    }

    /// A dialog that takes `up` and then answers: the ordinary interactive case,
    /// where the consultation's cost is the user's own thinking time.
    fn slow_deciding_dialog(up: Duration) -> (DialogFn, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&calls);
        let dialog: DialogFn = Arc::new(move |_req: &DialogRequest| {
            counter.fetch_add(1, Ordering::SeqCst);
            std::thread::sleep(up);
            Ok(deny_once_result())
        });
        (dialog, calls)
    }

    /// **Item 1, sequential half: the counter is a per-listener total, so a session's
    /// own prompt time is the DELTA across it.** Two consultations on one listener
    /// must each be attributed their own wait; a session that inherited the total
    /// would report twice its own budget (and, in the supervisor's arithmetic, claim
    /// a prompt overrun that never happened).
    #[test]
    fn two_sequential_consultations_are_attributed_their_own_prompt_time() {
        let (dialog, calls) = slow_deciding_dialog(Duration::from_millis(150));
        let t = t36_setup("prompt-clock-sequential", &[], &[], dialog);
        let counters = t.handle.counters();
        assert_eq!(counters.prompt_wait(), Duration::ZERO);

        let baseline = counters.prompt_wait();
        let first = exchange(t.port, &connect_req("sequential-a.invalid:443"));
        assert!(first.starts_with("HTTP/1.1 403"), "got: {first}");
        let after_first = counters.prompt_wait();
        let first_delta = after_first.saturating_sub(baseline);

        let second = exchange(t.port, &connect_req("sequential-b.invalid:443"));
        assert!(second.starts_with("HTTP/1.1 403"), "got: {second}");
        let after_second = counters.prompt_wait();
        let second_delta = after_second.saturating_sub(after_first);

        assert_eq!(calls.load(Ordering::SeqCst), 2, "two hosts, two dialogs");
        for (label, delta) in [("first", first_delta), ("second", second_delta)] {
            assert!(
                delta >= Duration::from_millis(120),
                "the {label} consultation's own wait must be measured, got {delta:?}"
            );
            assert!(
                delta < Duration::from_millis(700),
                "the {label} consultation must not inherit the listener's total: {label} \
                 delta {delta:?} of a total {after_second:?}"
            );
        }
        println!(
            "EVIDENCE sequential-prompt-time first={first_delta:?} second={second_delta:?} \
             total={after_second:?}"
        );
    }

    /// **Round 2, item 1: a coalesced follower set is credited ONE dialog.**
    ///
    /// `note_prompt_wait` ran per REQUEST, so K followers of one dialog each added
    /// its wall clock: six followers of one 150 ms dialog measured 5.90x the
    /// session, and with shipped defaults four concurrent requests to one unlisted
    /// host credited 240 s for 60 s of blocking — which labelled a workload that
    /// genuinely overran `prompt_budget_exhausted`. The coordinator credits the
    /// consultation's LEADER only, so the aggregate is the time this listener spent
    /// BLOCKED ON DIALOGS, not a share of the wall clock multiplied by whoever was
    /// parked behind one.
    #[test]
    fn a_coalesced_follower_set_is_credited_its_one_dialog() {
        // FOUR is the review's own scenario (four concurrent requests to one unlisted
        // host credited 240 s for 60 s of blocking with shipped defaults); six is the
        // round-1 measurement's worst case (5.90x). Each count gets its own listener,
        // because the counter it reads is cumulative.
        for followers in [4usize, 6] {
            let (dialog, calls) = slow_deciding_dialog(Duration::from_millis(150));
            let t = t36_setup(
                &format!("prompt-clock-coalesced-{followers}"),
                &[],
                &[],
                dialog,
            );
            let counters = t.handle.counters();

            // One host, K concurrent requests: one dialog, one wait on it.
            let request = connect_req("coalesced-one-host.invalid:443");
            let started = std::time::Instant::now();
            let leaders: Vec<_> = (0..followers)
                .map(|_| {
                    let req = request.clone();
                    let port = t.port;
                    std::thread::spawn(move || exchange(port, &req))
                })
                .collect();
            for l in leaders {
                let resp = l.join().expect("exchange thread");
                assert!(resp.starts_with("HTTP/1.1 403"), "got: {resp}");
            }
            let wall = started.elapsed();
            let aggregate = counters.prompt_wait();

            assert_eq!(calls.load(Ordering::SeqCst), 1, "one host means one dialog");
            assert!(
                aggregate >= Duration::from_millis(120),
                "the one dialog that ran must be credited its own wall clock, got {aggregate:?}"
            );
            assert!(
                aggregate <= wall * 2,
                "{followers} followers of ONE dialog must not multiply it: aggregate \
                 {aggregate:?} against a wall clock of {wall:?}"
            );
            println!(
                "EVIDENCE coalesced-credit followers={followers} wall={wall:?} \
                 aggregate={aggregate:?} ratio={:.2}",
                aggregate.as_secs_f64() / wall.as_secs_f64()
            );
        }
    }

    /// **Round 2, item 2: the fast-fail latch is LAUNCH-scoped, not listener-scoped.**
    ///
    /// The latch lives on the coordinator, which is per LISTENER and outlives a
    /// launch, and nothing reset it: one launch per process hid that, but the P1.4
    /// epoch machinery exists precisely so a listener can serve sequential launches,
    /// and then launch N's stalled prompts denied every prompt of launch N+1. The
    /// listener now registers `PromptCoordinator::begin_launch` as its launch reset
    /// and `begin_epoch` runs it as the attribution window opens.
    #[test]
    fn a_new_launch_on_the_same_listener_starts_with_an_unarmed_prompt_latch() {
        let budget = Duration::from_millis(80);
        let (dialog, gate) = gated_dialog();
        let t = t36_setup_cfg(
            "prompt-launch-scope",
            &[],
            &[],
            dialog,
            true,
            budget,
            PromptPolicy::Deny,
            None,
        );

        // Launch 1 arms the latch: three unanswered consultations (the dialog stays
        // up, which is the routine headless state).
        for i in 0..crate::net::prompt::NO_BACKEND_STICKY_AFTER {
            let resp = exchange(t.port, &get_req(&format!("http://launch-{i}.invalid/x")));
            assert!(resp.starts_with("HTTP/1.1 403"), "host {i}: got {resp}");
            assert_eq!(
                last_connect_event(&t.sid)["reason"],
                PROMPT_TIMEOUT_REASON,
                "host {i} must still pay its budget before the latch arms"
            );
        }
        let armed_started = std::time::Instant::now();
        let resp = exchange(t.port, &get_req("http://launch-armed.invalid/x"));
        assert!(resp.starts_with("HTTP/1.1 403"), "got {resp}");
        assert_eq!(
            last_connect_event(&t.sid)["reason"],
            PROMPT_SUPPRESSED_REASON,
            "the latch is armed, and by elapsed budgets"
        );
        assert!(
            armed_started.elapsed() < budget / 2,
            "an armed latch answers without paying: {:?}",
            armed_started.elapsed()
        );

        // A SECOND launch on the same listener: the epoch machinery's own case.
        let epoch = t
            .handle
            .counters()
            .begin_epoch()
            .expect("a second launch's window");
        assert!(t.handle.counters().close_epoch(epoch));

        // Launch 2's first unlisted host is consulted again: it pays its own budget
        // instead of inheriting launch 1's verdict.
        let second_started = std::time::Instant::now();
        let resp = exchange(t.port, &get_req("http://launch2.invalid/x"));
        assert!(resp.starts_with("HTTP/1.1 403"), "got {resp}");
        assert_eq!(
            last_connect_event(&t.sid)["reason"],
            PROMPT_TIMEOUT_REASON,
            "launch 2 must consult a dialog: it must not inherit launch 1's latch"
        );
        assert!(
            second_started.elapsed() >= budget / 2,
            "launch 2's consultation pays its own budget: {:?}",
            second_started.elapsed()
        );
        // Release the orphans so no blocking thread outlives the test.
        drop(gate);
    }

    /// A backend that reports "no decision" only after doing work of its own:
    /// the headless shape the D3 addendum measured (a dialog nobody answers, and
    /// a client that pays the budget for it). Every call is counted, because the
    /// count is how the test sees that later consultations stopped calling it.
    fn counting_slow_failing_dialog(up: Duration) -> (DialogFn, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&calls);
        let dialog: DialogFn = Arc::new(move |_req: &DialogRequest| {
            counter.fetch_add(1, Ordering::SeqCst);
            std::thread::sleep(up);
            Err(DialogUnavailable)
        });
        (dialog, calls)
    }

    /// **The D3 addendum's symptom, closed.** A headless session has no dialog to
    /// answer, so before the fast-fail every unlisted host cost the client the
    /// whole prompt budget (measured as `curl -m 15` exit 28). Every consultation up
    /// to `NO_BACKEND_STICKY_AFTER` still pays it — enough evidence that no decision
    /// is obtainable, and three rather than two since round 2 item 5 — and from then on
    /// the deny is immediate, audited with `no_dialog_backend` instead of
    /// `prompt_budget_exhausted` (this latch was armed by a backend that failed, so
    /// that is the arming cause — item 8), one leaf per request, and no further dialog
    /// is spawned.
    #[test]
    fn headless_requests_stop_paying_the_budget_for_an_absent_backend() {
        let budget = Duration::from_millis(400);
        let (dialog, calls) = counting_slow_failing_dialog(Duration::from_millis(200));
        let t = t36_setup_cfg(
            "headless-fast-fail",
            &[],
            &[],
            dialog,
            true,
            budget,
            PromptPolicy::Deny,
            None,
        );

        let mut elapsed = Vec::new();
        for i in 0..5 {
            let host = format!("unlisted-headless-{i}.invalid");
            let started = std::time::Instant::now();
            let resp = exchange(t.port, &connect_req(&format!("{host}:443")));
            elapsed.push(started.elapsed());
            assert!(resp.starts_with("HTTP/1.1 403"), "host {i}: got {resp}");
            assert!(
                resp.contains(NO_DIALOG_BACKEND_REASON),
                "host {i} must name the missing backend, not the budget: {resp}"
            );
            let ev = last_connect_event(&t.sid);
            assert_eq!(ev["host"], host);
            assert_eq!(ev["source"], "unavailable");
            assert_eq!(ev["reason"], NO_DIALOG_BACKEND_REASON);
            assert_eq!(ev["disposition"], "deny");
        }

        // The measured claim: the consultations before the threshold pay the
        // backend's own latency, the rest do not pay anything like it.
        for (i, e) in elapsed
            .iter()
            .enumerate()
            .take(crate::net::prompt::NO_BACKEND_STICKY_AFTER)
        {
            assert!(
                *e >= Duration::from_millis(150),
                "request {i} must wait on the backend: {e:?}"
            );
        }
        for (i, e) in elapsed
            .iter()
            .enumerate()
            .skip(crate::net::prompt::NO_BACKEND_STICKY_AFTER)
        {
            assert!(
                *e < budget / 4,
                "request {i} must be denied well inside the budget ({budget:?}), got {e:?}"
            );
        }
        assert_eq!(
            calls.load(Ordering::SeqCst),
            crate::net::prompt::NO_BACKEND_STICKY_AFTER,
            "a known-absent backend must not be consulted again"
        );
        assert_eq!(
            connect_events(&t.sid).len(),
            5,
            "every request is audited, skipped dialog or not"
        );

        println!(
            "EVIDENCE headless-fast-fail budget={budget:?} elapsed={:?} dialog_calls={}",
            elapsed,
            calls.load(Ordering::SeqCst)
        );
    }

    /// Item 4's reason half: the two capacity pools deny with **different**
    /// reasons, and both are greppable tokens a filter can select on.
    #[test]
    fn the_two_overload_pools_deny_with_different_reasons() {
        let consultations = super::overload_reason(OverloadCause::ConsultationsHeld);
        let abandoned = super::overload_reason(OverloadCause::AbandonedCapacity);
        assert_eq!(consultations, PROMPT_OVERLOAD_REASON);
        assert_eq!(abandoned, PROMPT_ABANDONED_CAPACITY_REASON);
        assert_eq!(abandoned, "prompt_abandoned_capacity");
        assert_ne!(
            consultations, abandoned,
            "a full abandoned pool must not read as a concurrency limit"
        );
        // The three prompt-side reasons are three distinct facts: a spent budget,
        // no backend, and which pool ran out.
        let mut all = vec![PROMPT_TIMEOUT_REASON, NO_DIALOG_BACKEND_REASON, abandoned];
        all.sort_unstable();
        all.dedup();
        assert_eq!(all.len(), 3, "reason tokens must be distinct: {all:?}");
        assert!(
            !all.contains(&consultations),
            "the consultation-cap prose is not one of the tokenised reasons"
        );
    }

    /// A dialog that parks every call until the gate drops, counting them: the
    /// 8-leader state the consultation cap exists for.
    fn counting_gated_dialog() -> (DialogFn, Arc<AtomicUsize>, std::sync::mpsc::Sender<()>) {
        let (gate, wait) = std::sync::mpsc::channel::<()>();
        let wait = Arc::new(StdMutex::new(wait));
        let calls = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&calls);
        let dialog: DialogFn = Arc::new(move |_req: &DialogRequest| {
            counter.fetch_add(1, Ordering::SeqCst);
            let rx = wait.lock().unwrap_or_else(|poison| poison.into_inner());
            let _ = rx.recv();
            Err(DialogUnavailable)
        });
        (dialog, calls, gate)
    }

    /// Arm 1 at the wire: with every consultation slot held, a NEW host is
    /// refused as `prompt_overload` whose reason names the consultation cap —
    /// and, unlike the abandoned arm, nothing about abandoned dialogs.
    #[test]
    fn a_full_consultation_pool_denies_with_its_own_reason() {
        let (dialog, calls, gate) = counting_gated_dialog();
        let t = t36_setup_cfg(
            "overload-consultations",
            &[],
            &[],
            dialog,
            true,
            Duration::from_secs(30),
            PromptPolicy::Deny,
            None,
        );
        let port = t.port;

        // Eight leaders, one per distinct host, all parked inside their dialogs.
        // The request strings are built HERE: this listener's credential lives in
        // a test thread-local, so a spawned thread must be handed a finished
        // request rather than building one without it.
        let requests: Vec<String> = (0..crate::net::prompt::MAX_CONCURRENT_PROMPTS)
            .map(|i| connect_req(&format!("held-{i}.invalid:443")))
            .collect();
        let leaders: Vec<_> = requests
            .into_iter()
            .map(|req| std::thread::spawn(move || exchange(port, &req)))
            .collect();
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while calls.load(Ordering::SeqCst) < crate::net::prompt::MAX_CONCURRENT_PROMPTS {
            assert!(
                std::time::Instant::now() < deadline,
                "the eight leaders must reach their dialogs, saw {}",
                calls.load(Ordering::SeqCst)
            );
            std::thread::sleep(Duration::from_millis(2));
        }

        let ninth = exchange(port, &connect_req("one-too-many.invalid:443"));
        assert!(ninth.starts_with("HTTP/1.1 403"), "got: {ninth}");
        assert!(
            ninth.contains(PROMPT_OVERLOAD_REASON),
            "the deny must name the consultation cap: {ninth}"
        );
        assert!(
            !ninth.contains(PROMPT_ABANDONED_CAPACITY_REASON),
            "no dialog was abandoned here: {ninth}"
        );
        let ev = last_connect_event(&t.sid);
        assert_eq!(ev["host"], "one-too-many.invalid");
        assert_eq!(ev["source"], "prompt_overload");
        assert_eq!(ev["reason"], PROMPT_OVERLOAD_REASON);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            crate::net::prompt::MAX_CONCURRENT_PROMPTS,
            "the refused consultation must not have shown a dialog"
        );

        // Release the leaders so no blocking thread outlives the test.
        drop(gate);
        for l in leaders {
            let _ = l.join();
        }
    }

    #[test]
    fn prompt_not_enabled_deny_policy() {
        let (dialog, calls) = recording_dialog(Ok(allow_host_persist()));
        let t = t36_setup_cfg(
            "no-prompt-deny",
            &[],
            &[],
            dialog,
            false,
            Duration::from_secs(60),
            PromptPolicy::Deny,
            None,
        );
        let resp = exchange(t.port, &connect_req("noprompt-deny.invalid:443"));
        assert!(resp.starts_with("HTTP/1.1 403"), "got: {resp}");
        assert!(
            calls.lock().unwrap().is_empty(),
            "--no-prompt must never show a dialog"
        );
        let ev = last_connect_event(&t.sid);
        assert_eq!(ev["source"], "default");
    }

    #[test]
    fn prompt_not_enabled_allow_policy_admits() {
        let (dialog, calls) = recording_dialog(Ok(deny_once_result()));
        let t = t36_setup_cfg(
            "no-prompt-allow",
            &[],
            &[],
            dialog,
            false,
            Duration::from_secs(60),
            PromptPolicy::Allow,
            None,
        );
        let resp = exchange(t.port, &connect_req("noprompt-allow.invalid:443"));
        assert!(
            resp.starts_with("HTTP/1.1 403") || resp.starts_with("HTTP/1.1 502"),
            "on_unavailable=allow must admit, got: {resp}"
        );
        assert!(calls.lock().unwrap().is_empty());
        let ev = last_connect_event(&t.sid);
        if ev["disposition"] == "allow" {
            assert_eq!(ev["source"], "default");
        } else {
            assert_eq!(ev["source"], "dns");
        }
    }

    // ---- [G-17]: the dialog is enriched with the declared intent ----------

    #[test]
    fn prompt_receives_declared_intent_reason() {
        let (dialog, calls) = recording_dialog(Ok(deny_once_result()));
        let t = t36_setup("prompt-reason", &[], &[], dialog);
        block_on(t.intent.record("reasoned.invalid", "fetching model list"));
        let resp = exchange(t.port, &connect_req("reasoned.invalid:443"));
        assert!(resp.starts_with("HTTP/1.1 403"), "got: {resp}");
        let calls = calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(
            calls[0].reason.as_deref(),
            Some("fetching model list"),
            "dialog must receive the declared intent reason"
        );
    }

    // ---- token gate on CONNECT (existing behavior, now listener-level) -----

    // ---- Step 4: /sandbox/intent endpoints (D-4) ---------------------------

    #[test]
    fn connect_without_token_gets_407_and_default_audit() {
        let (dialog, calls) = recording_dialog(Ok(allow_once()));
        let t = t36_setup("auth-407", &["*"], &[], dialog);
        let resp = exchange(t.port, &connect_req_no_auth("api.example.com:443"));
        assert!(resp.starts_with("HTTP/1.1 407"), "got: {resp}");
        assert!(calls.lock().unwrap().is_empty());
        let ev = last_connect_event(&t.sid);
        assert_eq!(ev["host"], "<unknown>");
        assert_eq!(ev["reason"], "no_token");
        assert_eq!(ev["source"], "default");
    }

    // ---- Step 4: /sandbox/intent endpoints (D-4) ---------------------------

    /// CRLF as a runtime value: the request builders below carry no escape
    /// sequences in their literals.
    fn crlf() -> String {
        let mut s = String::new();
        s.push(13u8 as char);
        s.push(10u8 as char);
        s
    }

    /// One authenticated HTTP request: CRLF head, Content-Length, body.
    fn http_req(method: &str, path: &str, json: bool, body: &str) -> String {
        let c = crlf();
        let auth = auth_header();
        let ct = if json {
            format!("Content-Type: application/json{c}")
        } else {
            String::new()
        };
        format!(
            "{method} {path} HTTP/1.1{c}{auth}{ct}Content-Length: {}{c}{c}{body}",
            body.len()
        )
    }

    fn get_req(path: &str) -> String {
        http_req("GET", path, false, "")
    }

    fn post_json(path: &str, body: &str) -> String {
        http_req("POST", path, true, body)
    }

    /// One UNauthenticated request, for the token-gate tests.
    fn http_req_no_auth(method: &str, path: &str, body: &str) -> String {
        let c = crlf();
        format!(
            "{method} {path} HTTP/1.1{c}Content-Length: {}{c}{c}{body}",
            body.len()
        )
    }

    /// The JSON document of a response (after the CRLF CRLF terminator).
    fn json_body(resp: &str) -> serde_json::Value {
        let sep = format!("{}{}", crlf(), crlf());
        let body = resp.split(sep.as_str()).nth(1).unwrap_or("");
        serde_json::from_str(body).unwrap_or_else(|_| panic!("bad JSON body in response: {resp}"))
    }

    #[test]
    fn intent_post_then_get_roundtrip() {
        let (dialog, _c) = recording_dialog(Ok(deny_once_result()));
        let t = t36_setup("intent-rt", &[], &[], dialog);
        let resp = exchange(
            t.port,
            &post_json(
                "/sandbox/intent",
                r#"{"target":"api.example.com","reason":"fetching the model list"}"#,
            ),
        );
        assert!(resp.starts_with("HTTP/1.1 204"), "got: {resp}");
        let resp = exchange(t.port, &get_req("/sandbox/intent?host=api.example.com"));
        assert!(resp.starts_with("HTTP/1.1 200"), "got: {resp}");
        let v = json_body(&resp);
        assert_eq!(v["host"], "api.example.com");
        assert_eq!(v["reason"], "fetching the model list");
        // RFC3339 UTC, whole seconds: YYYY-MM-DDTHH:MM:SSZ.
        let ts = v["ts"].as_str().unwrap();
        assert!(
            ts.len() == 20 && ts.ends_with('Z') && ts.as_bytes()[10] == b'T',
            "ts must be RFC3339, got {ts}"
        );
        assert_eq!(v["hint"], "declared");
    }

    #[test]
    fn intent_get_unknown_host_is_404() {
        let (dialog, _c) = recording_dialog(Ok(deny_once_result()));
        let t = t36_setup("intent-404", &[], &[], dialog);
        let resp = exchange(
            t.port,
            &get_req("/sandbox/intent?host=never-declared.invalid"),
        );
        assert!(resp.starts_with("HTTP/1.1 404"), "got: {resp}");
        let v = json_body(&resp);
        assert_eq!(v["host"], "never-declared.invalid");
        assert_eq!(v["reason"], "");
        assert_eq!(v["hint"], "undeclared");
    }

    #[test]
    fn intent_get_missing_host_param_is_400() {
        let (dialog, _c) = recording_dialog(Ok(deny_once_result()));
        let t = t36_setup("intent-nohost", &[], &[], dialog);
        let resp = exchange(t.port, &get_req("/sandbox/intent"));
        assert!(resp.starts_with("HTTP/1.1 400"), "got: {resp}");
        let resp = exchange(t.port, &get_req("/sandbox/intent?host="));
        assert!(resp.starts_with("HTTP/1.1 400"), "got: {resp}");
    }

    #[test]
    fn intent_post_malformed_body_is_400() {
        let (dialog, _c) = recording_dialog(Ok(deny_once_result()));
        let t = t36_setup("intent-badjson", &[], &[], dialog);
        let resp = exchange(t.port, &post_json("/sandbox/intent", "this is not json"));
        assert!(resp.starts_with("HTTP/1.1 400"), "got: {resp}");
    }

    #[test]
    fn intent_post_blank_fields_are_400() {
        let (dialog, _c) = recording_dialog(Ok(deny_once_result()));
        let t = t36_setup("intent-blank", &[], &[], dialog);
        let resp = exchange(
            t.port,
            &post_json("/sandbox/intent", r#"{"target":"","reason":"x"}"#),
        );
        assert!(resp.starts_with("HTTP/1.1 400"), "got: {resp}");
        let resp = exchange(t.port, &post_json("/sandbox/intent", r#"{"target":"x"}"#));
        assert!(
            resp.starts_with("HTTP/1.1 400"),
            "missing reason must 400, got: {resp}"
        );
    }

    #[test]
    fn intent_post_truncates_long_reason_not_rejects() {
        let (dialog, _c) = recording_dialog(Ok(deny_once_result()));
        let t = t36_setup("intent-trunc", &[], &[], dialog);
        let long = "a".repeat(600);
        let resp = exchange(
            t.port,
            &post_json(
                "/sandbox/intent",
                &format!(r#"{{"target":"api.example.com","reason":"{long}"}}"#),
            ),
        );
        assert!(
            resp.starts_with("HTTP/1.1 204"),
            "oversized reason is truncated, not rejected: {resp}"
        );
        let resp = exchange(t.port, &get_req("/sandbox/intent?host=api.example.com"));
        let v = json_body(&resp);
        assert_eq!(v["reason"].as_str().unwrap().len(), 500);
    }

    #[test]
    fn intent_explain_flag_is_set_by_post_and_consumed_by_get() {
        let (dialog, _c) = recording_dialog(Ok(deny_once_result()));
        let t = t36_setup("intent-explain", &[], &[], dialog);
        block_on(
            t.intent
                .record("api.example.com", "fetching the model list"),
        );
        let resp = exchange(
            t.port,
            &post_json("/sandbox/intent/explain", r#"{"host":"api.example.com"}"#),
        );
        assert!(resp.starts_with("HTTP/1.1 204"), "got: {resp}");
        // First GET observes the one-shot flag AND the declared entry.
        let resp = exchange(t.port, &get_req("/sandbox/intent?host=api.example.com"));
        assert!(resp.starts_with("HTTP/1.1 200"), "got: {resp}");
        let v = json_body(&resp);
        assert_eq!(v["hint"], "explain-more");
        assert_eq!(v["reason"], "fetching the model list");
        // The flag is one-shot: the second GET shows the plain entry.
        let resp = exchange(t.port, &get_req("/sandbox/intent?host=api.example.com"));
        let v = json_body(&resp);
        assert_eq!(v["hint"], "declared");
    }

    #[test]
    fn intent_get_404_still_carries_explain_flag() {
        let (dialog, _c) = recording_dialog(Ok(deny_once_result()));
        let t = t36_setup("intent-explain-404", &[], &[], dialog);
        let resp = exchange(
            t.port,
            &post_json(
                "/sandbox/intent/explain",
                r#"{"host":"undeclared.invalid"}"#,
            ),
        );
        assert!(resp.starts_with("HTTP/1.1 204"), "got: {resp}");
        let resp = exchange(t.port, &get_req("/sandbox/intent?host=undeclared.invalid"));
        assert!(resp.starts_with("HTTP/1.1 404"), "got: {resp}");
        let v = json_body(&resp);
        assert_eq!(v["hint"], "explain-more");
    }

    #[test]
    fn intent_post_retires_explain_flag() {
        let (dialog, _c) = recording_dialog(Ok(deny_once_result()));
        let t = t36_setup("intent-retire", &[], &[], dialog);
        // NeedsIntent clicked, the deny path set the flag...
        block_on(t.intent.mark_explain_more("redeclared.invalid"));
        // ...the agent re-declares via POST /sandbox/intent...
        let resp = exchange(
            t.port,
            &post_json(
                "/sandbox/intent",
                r#"{"target":"redeclared.invalid","reason":"better reason now"}"#,
            ),
        );
        assert!(resp.starts_with("HTTP/1.1 204"), "got: {resp}");
        // ...and the next GET shows the plain declared entry, no hint.
        let resp = exchange(t.port, &get_req("/sandbox/intent?host=redeclared.invalid"));
        let v = json_body(&resp);
        assert_eq!(v["hint"], "declared");
        assert_eq!(v["reason"], "better reason now");
    }

    #[test]
    fn intent_endpoints_require_the_session_token() {
        let (dialog, _c) = recording_dialog(Ok(deny_once_result()));
        let t = t36_setup("intent-auth", &[], &[], dialog);
        // No auth header at all.
        let resp = exchange(
            t.port,
            &http_req_no_auth("GET", "/sandbox/intent?host=x.invalid", ""),
        );
        assert!(resp.starts_with("HTTP/1.1 407"), "got: {resp}");
        // Wrong token.
        let bad = base64::engine::general_purpose::STANDARD.encode("sandbox:wrong");
        let c = crlf();
        let wrong = format!(
            "POST /sandbox/intent HTTP/1.1{c}Proxy-Authorization: Basic {bad}{c}Content-Length: 2{c}{c}{{}}"
        );
        let resp = exchange(t.port, &wrong);
        assert!(resp.starts_with("HTTP/1.1 407"), "got: {resp}");
    }

    /// Absolute-form is a **proxy consultation**: it runs the D-1 pipeline and is
    /// refused when the pipeline denies (403) — never silently forwarded, and no
    /// longer a 400. Origin-form outside `/sandbox/` stays a 400: this listener is
    /// not a reverse proxy for anyone.
    #[test]
    fn absolute_form_is_admitted_and_origin_form_outside_sandbox_is_400() {
        let (dialog, _c) = recording_dialog(Ok(deny_once_result()));
        let t = t36_setup("plain-http-400", &[], &[], dialog);
        let resp = exchange(t.port, &get_req("http://evil.example.com/"));
        assert!(resp.starts_with("HTTP/1.1 403"), "got: {resp}");
        assert!(resp.contains("X-Sandbox: denied"), "got: {resp}");
        // The deny went through the admission pipeline, so it is audited.
        assert_eq!(last_connect_event(&t.sid)["host"], "evil.example.com");
        // Origin-form request to a non-/sandbox path.
        let resp = exchange(t.port, &get_req("/some/path"));
        assert!(resp.starts_with("HTTP/1.1 400"), "got: {resp}");
    }

    /// Guardrail 1's counting rules on a real listener (plan P1 wave 2, item A):
    /// a *denied* consultation is accepted-and-no-tunnel, a *refused* CONNECT is
    /// the same shape, serving our own origin-form endpoint is not counted at
    /// all, and every epoch starts empty.
    #[test]
    fn counters_record_consultations_and_upstream_establishment_per_epoch() {
        let (dialog, _c) = recording_dialog(Ok(deny_once_result()));
        let t = t36_setup("counters", &[], &[], dialog);
        let counters = t.handle.counters();
        let epoch = counters.begin_epoch().expect("the first launch's window");

        // Origin-form to our own endpoint: served, but NOT a proxy consultation.
        let resp = exchange(t.port, &get_req("/sandbox/intent?host=x.invalid"));
        assert!(resp.starts_with("HTTP/1.1 404"), "got: {resp}");
        assert_eq!(
            counters.counters(epoch),
            Some(LaunchProofCounters::default()),
            "serving our own endpoint must never look like a proxy consultation"
        );

        // Absolute-form for another origin, denied by the pipeline.
        let resp = exchange(t.port, &get_req("http://evil.example.com/x"));
        assert!(resp.starts_with("HTTP/1.1 403"), "got: {resp}");
        // CONNECT to loopback, refused before any dial.
        let resp = exchange(t.port, &connect_req("127.0.0.1:9"));
        assert!(resp.starts_with("HTTP/1.1 403"), "got: {resp}");
        assert_eq!(
            counters.counters(epoch),
            Some(LaunchProofCounters {
                consultations: 2,
                upstream_established: 0,
                probes: 0,
            }),
            "both reached us as a proxy; neither established anything upstream"
        );

        // A 407 is not proof of anything and is not counted.
        let resp = exchange(t.port, &connect_req_no_auth("api.example.com:443"));
        assert!(resp.starts_with("HTTP/1.1 407"), "got: {resp}");

        // A new epoch starts empty; the closed one keeps its numbers.
        assert!(counters.close_epoch(epoch));
        let next = counters.begin_epoch().expect("a window after the close");
        assert_eq!(
            counters.counters(next),
            Some(LaunchProofCounters::default())
        );
        exchange(t.port, &connect_req("127.0.0.1:9"));
        assert_eq!(
            counters.counters(next),
            Some(LaunchProofCounters {
                consultations: 1,
                upstream_established: 0,
                probes: 0,
            }),
            "the second epoch must not inherit the first one's traffic"
        );
        assert_eq!(
            counters.counters(epoch),
            Some(LaunchProofCounters {
                consultations: 2,
                upstream_established: 0,
                probes: 0,
            }),
            "a closed epoch keeps its frozen counters"
        );
        assert_eq!(
            counters.counters(9_999),
            None,
            "an unknown epoch has no proof"
        );
        assert!(
            !counters.close_epoch(9_999),
            "closing an unknown epoch is a no-op"
        );
    }

    // ---- ADR-0004 guardrail 1, amended 2026-10-22: the pre-flight probe ----

    /// `GET /sandbox/probe` records ONE probe observation and answers `204`.
    ///
    /// A probe is neither a policy consultation nor an upstream connection: it
    /// is the wrapper's own report that the child's path to THIS listener
    /// works, which is what guardrail 1 gates on now. Counting it as a
    /// consultation would make `MustBeAbsent` unsatisfiable for the sessions
    /// it exists for (the same reason serving an intent endpoint is not one);
    /// counting it as an upstream connection would claim a dial nobody made.
    #[test]
    fn a_probe_is_recorded_as_a_probe_and_answers_204() {
        let (dialog, calls) = recording_dialog(Ok(deny_once_result()));
        let t = t36_setup("probe", &[], &[], dialog);
        let counters = t.handle.counters();
        let epoch = counters.begin_epoch().expect("the launch's window");

        let resp = exchange(t.port, &get_req(PROBE_PATH));
        assert!(resp.starts_with("HTTP/1.1 204"), "got: {resp}");
        assert_eq!(
            counters.counters(epoch),
            Some(LaunchProofCounters {
                consultations: 0,
                upstream_established: 0,
                probes: 1,
            }),
            "the probe must be its own observation - not a consultation, and not an \
             upstream connection"
        );
        assert!(
            calls.lock().unwrap().is_empty(),
            "a probe is not a policy question: it must never reach the dialog"
        );
    }

    /// The property the gate exists for: evidence must be ATTRIBUTABLE.
    ///
    /// A probe under a credential this listener does not own is refused with the
    /// same `407` as every other control-plane request and leaves NO observation
    /// behind, so it can never satisfy guardrail 1 for a session whose own proxy
    /// path is broken (dead listener, blocked loopback, wrong credential).
    #[test]
    fn a_probe_without_the_run_credential_is_407_and_is_not_counted() {
        let (dialog, _c) = recording_dialog(Ok(deny_once_result()));
        let t = t36_setup("probe-cred", &[], &[], dialog);
        let counters = t.handle.counters();
        let epoch = counters.begin_epoch().expect("the launch's window");

        let c = crlf();
        let absent = format!("GET {PROBE_PATH} HTTP/1.1{c}{c}");
        let foreign = probe_req_with("not-this-runs-token");
        for (label, req) in [("absent", absent), ("foreign", foreign)] {
            let resp = exchange(t.port, &req);
            assert!(
                resp.starts_with("HTTP/1.1 407"),
                "{label}: the probe must be gated like every other control-plane \
                 request: {resp}"
            );
            assert!(
                resp.contains("Proxy-Authenticate: Basic"),
                "{label}: the refusal must carry the challenge: {resp}"
            );
        }
        assert_eq!(
            counters.counters(epoch),
            Some(LaunchProofCounters::default()),
            "a refused probe must leave no observation: it cannot stand in for the \
             session's own proxy path"
        );
    }

    /// One probe under a CHOSEN credential (this listener must refuse it).
    fn probe_req_with(token: &str) -> String {
        let creds = base64::engine::general_purpose::STANDARD.encode(format!("sandbox:{token}"));
        let c = crlf();
        format!("GET {PROBE_PATH} HTTP/1.1{c}Proxy-Authorization: Basic {creds}{c}{c}")
    }

    /// A handler that panicked while holding the counter lock must not make the
    /// launch path panic: a poisoned mutex is recovered, not propagated.
    #[test]
    fn counters_survive_a_poisoned_lock() {
        let counters = LaunchCounters::new();
        let epoch = counters.begin_epoch().expect("the first launch's window");
        let poisoner = Arc::clone(&counters);
        let poisoned = std::thread::spawn(move || {
            let _guard = poisoner.state.lock().expect("first lock");
            panic!("handler blew up mid-count");
        });
        assert!(poisoned.join().is_err(), "the handler thread panicked");

        // Every accessor must still work on the same registry.
        assert_eq!(
            counters.counters(epoch),
            Some(LaunchProofCounters::default())
        );
        counters.note_consultation();
        assert_eq!(
            counters.counters(epoch),
            Some(LaunchProofCounters {
                consultations: 1,
                upstream_established: 0,
                probes: 0,
            })
        );
        assert!(counters.close_epoch(epoch));
        assert_eq!(
            counters.begin_epoch().expect("a window after the close"),
            epoch + 1
        );
    }

    // ---- P1.4: concurrency and per-run token attribution ------------------

    /// One CONNECT carrying a chosen credential (the tests below need to present
    /// a token that is *not* this listener's).
    fn connect_req_with(target: &str, token: &str) -> String {
        let creds = base64::engine::general_purpose::STANDARD.encode(format!("sandbox:{token}"));
        let c = crlf();
        format!("CONNECT {target} HTTP/1.1{c}Proxy-Authorization: Basic {creds}{c}{c}")
    }

    /// P1.8: managed clients do **not** send `Proxy-Authorization` pre-emptively.
    ///
    /// Measured inside a real container: .NET 8 (`SocketsHttpHandler`) and pwsh 7
    /// read the credential out of the `HTTP_PROXY` userinfo, try once WITHOUT it,
    /// and authenticate only after a `407` carrying a `Proxy-Authenticate: Basic`
    /// challenge (the first attempt is a deliberate, uncounted refusal, so the run
    /// still reports `accepted: 1`). If this listener ever answered 407 without a
    /// challenge, every managed workload would silently lose egress - so the
    /// header, not just the status, is pinned here.
    #[test]
    fn an_unauthenticated_consultation_gets_the_basic_challenge_managed_clients_need() {
        let token = RunToken::issue().expect("mint a token");
        let (dialog, _keep) = recording_dialog(Ok(allow_once()));
        let cfg = t36_setup_token_cfg(
            "p18-challenge",
            &["*"],
            &[],
            dialog,
            true,
            Duration::from_secs(60),
            PromptPolicy::Deny,
            None,
            token.clone(),
        );
        let c = crlf();
        let unauth = format!("CONNECT 127.0.0.1:9 HTTP/1.1{c}Host: 127.0.0.1:9{c}{c}");
        let resp = exchange(cfg.port, &unauth);
        assert!(resp.starts_with("HTTP/1.1 407"), "{resp}");
        assert!(
            resp.contains("Proxy-Authenticate: Basic"),
            "no challenge means every managed client loses egress: {resp}"
        );
        assert!(resp.contains("realm=\"sandbox\""), "{resp}");

        // The retry the client performs after that challenge is accepted, which
        // proves the challenge is actionable rather than decorative.
        let resp = exchange(cfg.port, &connect_req_with("127.0.0.1:9", token.value()));
        assert!(
            resp.starts_with("HTTP/1.1 403"),
            "an admitted request is loopback-refused, not challenged: {resp}"
        );
    }

    /// P1.4: a listener accepts exactly one credential - its own run's token.
    ///
    /// Two live listeners, each with its own token and port. Each refuses the
    /// other's token with a `407` that is **not** a consultation and leaves **no**
    /// audit leaf, while still serving its own token. Before the P1.4 rule the
    /// foreign token took the same `no_token` path as a missing credential: it
    /// wrote a leaf into an audit chain it does not belong to.
    #[test]
    fn a_listener_refuses_a_foreign_run_token_without_counting_it_and_records_it_once() {
        let (dialog_a, _keep_a) = recording_dialog(Ok(allow_once()));
        let (dialog_b, _keep_b) = recording_dialog(Ok(allow_once()));
        let token_a = RunToken::issue().expect("mint run A's token");
        let token_b = RunToken::issue().expect("mint run B's token");
        assert_ne!(token_a.value(), token_b.value());

        let a = t36_setup_token_cfg(
            "p14-run-a",
            &["*"],
            &[],
            dialog_a,
            true,
            Duration::from_secs(60),
            PromptPolicy::Deny,
            None,
            token_a.clone(),
        );
        let b = t36_setup_token_cfg(
            "p14-run-b",
            &["*"],
            &[],
            dialog_b,
            true,
            Duration::from_secs(60),
            PromptPolicy::Deny,
            None,
            token_b.clone(),
        );
        assert_ne!(
            a.port, b.port,
            "one listener per run means one port per run"
        );

        let epoch_a = a.handle.counters().begin_epoch().expect("A's window");
        let epoch_b = b.handle.counters().begin_epoch().expect("B's window");
        let one_consultation = Some(LaunchProofCounters {
            consultations: 1,
            upstream_established: 0,
            probes: 0,
        });

        // (i) A's own token at A's listener is served and counted.
        let resp = exchange(a.port, &connect_req_with("127.0.0.1:9", token_a.value()));
        assert!(
            resp.starts_with("HTTP/1.1 403"),
            "A must accept its own token: {resp}"
        );
        assert_eq!(a.handle.counters().counters(epoch_a), one_consultation);

        // (ii) B's token at A's listener: refused, uncounted, recorded once
        // as `foreign_token`.
        let leaves_before = connect_events(&a.sid).len();
        let resp = exchange(a.port, &connect_req_with("127.0.0.1:9", token_b.value()));
        assert!(
            resp.starts_with("HTTP/1.1 407"),
            "A must refuse B's token: {resp}"
        );
        assert_eq!(
            a.handle.counters().counters(epoch_a),
            one_consultation,
            "a foreign token is not a consultation"
        );
        assert_eq!(
            connect_events(&a.sid).len(),
            leaves_before + 1,
            "a foreign token must leave exactly one leaf in A's chain"
        );
        assert_eq!(
            last_connect_event(&a.sid)["reason"],
            "foreign_token",
            "the leaf must name the event, and never the credential"
        );
        assert_eq!(
            last_connect_event(&a.sid)["host"],
            "<unknown>",
            "a foreign attempt names no host, because none was admitted"
        );

        // (iii) the other direction: A's token at B's listener.
        let leaves_before = connect_events(&b.sid).len();
        let resp = exchange(b.port, &connect_req_with("127.0.0.1:9", token_a.value()));
        assert!(
            resp.starts_with("HTTP/1.1 407"),
            "B must refuse A's token: {resp}"
        );
        assert_eq!(
            b.handle.counters().counters(epoch_b),
            Some(LaunchProofCounters::default()),
            "a foreign token must not count at B either"
        );
        assert_eq!(
            connect_events(&b.sid).len(),
            leaves_before + 1,
            "a foreign token must leave exactly one leaf in B's chain"
        );
        assert_eq!(last_connect_event(&b.sid)["reason"], "foreign_token");

        // B still serves its own token, so the refusal is about ownership and
        // not a broken listener.
        let resp = exchange(b.port, &connect_req_with("127.0.0.1:9", token_b.value()));
        assert!(resp.starts_with("HTTP/1.1 403"), "{resp}");
        assert_eq!(b.handle.counters().counters(epoch_b), one_consultation);

        // (iv) non-vacuity: a request with NO credential still gets its leaf, so
        // the silence above is the foreign-token rule and not a dead writer.
        let leaves_before = connect_events(&a.sid).len();
        let resp = exchange(a.port, &connect_req_no_auth("127.0.0.1:9"));
        assert!(resp.starts_with("HTTP/1.1 407"), "{resp}");
        assert_eq!(
            connect_events(&a.sid).len(),
            leaves_before + 1,
            "a missing credential is worth a leaf; a foreign one is not"
        );
    }

    // ---- P1.6: hardening ------------------------------------------------

    /// P1.6(a): a credential-less flood is capped per listener, and what it
    /// suppresses is counted exactly.
    ///
    /// Measured before the cap: 400 credential-less CONNECTs wrote 400 `no_token`
    /// leaves (129 KB) with nothing bounding a loop of any size, and P1.8 made it
    /// the *normal* case - every managed client's first request on a connection
    /// carries no credential, so `no_token` had stopped being a signal. The budget
    /// is eight individual leaves, then one aggregate leaf per window of
    /// suppressed refusals; the wire answer is unchanged and a refusal is still
    /// not a consultation.
    ///
    /// 20 refusals are 8 leaves of their own plus 12 suppressed - exactly one
    /// window - which pins all three review findings at once: a real `suppressed`
    /// integer (never text in `scope`), a count that is the true one (12, not a
    /// constant `1`), and a leaf volume that no longer tracks the flood.
    #[test]
    fn credential_less_refusals_are_capped_and_what_they_suppress_is_counted() {
        let (dialog, _keep) = recording_dialog(Ok(deny_once_result()));
        let t = t36_setup("p16-no-token-flood", &["*"], &[], dialog);
        let epoch = t
            .handle
            .counters()
            .begin_epoch()
            .expect("a window to watch");

        let mut statuses = Vec::new();
        for _ in 0..20 {
            let resp = exchange(t.port, &connect_req_no_auth("api.example.com:443"));
            statuses.push(resp.lines().next().unwrap_or("").to_string());
        }
        assert!(
            statuses
                .iter()
                .all(|line| line == "HTTP/1.1 407 Proxy Authentication Required"),
            "every credential-less CONNECT must still get the same 407: {statuses:?}"
        );

        let leaves = connect_events(&t.sid);
        let individual = leaves.iter().filter(|e| e["reason"] == "no_token").count();
        let aggregate: Vec<&serde_json::Value> = leaves
            .iter()
            .filter(|e| e["reason"] == "no_token_suppressed")
            .collect();
        assert_eq!(
            individual, 8,
            "the first eight refusals keep a leaf each: {leaves:?}"
        );
        assert_eq!(
            aggregate.len(),
            1,
            "twelve suppressed refusals are exactly one window: {leaves:?}"
        );
        assert_eq!(
            leaves.len(),
            9,
            "20 refusals must leave 8 + 1 leaves, not 20: {leaves:?}"
        );
        let aggregate = aggregate[0];
        assert_eq!(aggregate["disposition"], "deny");
        assert_eq!(aggregate["source"], "default");
        assert_eq!(aggregate["host"], "<unknown>");
        assert_eq!(aggregate["reason"], "no_token_suppressed");
        assert_eq!(
            aggregate["suppressed"], 12,
            "the aggregate stands in for exactly 20 - 8 refusals: {aggregate:?}"
        );
        assert_eq!(
            aggregate["scope"],
            serde_json::Value::Null,
            "scope means rule scope; a count in it makes a scope filter read a number: \
             {aggregate:?}"
        );

        // The CONTRACT is each field's domain, not a shared key set: `scope` is a
        // rule scope or null, `suppressed` a count or null, `persisted` a boolean,
        // `disposition` one of two words. Asserting "all leaves have the same
        // keys" tested the encoding of the fix (a count squeezed into an existing
        // field) instead of what a consumer is allowed to rely on.
        for leaf in &leaves {
            assert!(
                leaf["scope"].is_null() || leaf["scope"].is_string(),
                "scope must be a rule scope or null: {leaf:?}"
            );
            assert!(
                leaf["suppressed"].is_null() || leaf["suppressed"].is_u64(),
                "suppressed must be a count or null: {leaf:?}"
            );
            assert!(
                leaf["persisted"].is_boolean(),
                "persisted must be a boolean: {leaf:?}"
            );
            assert!(
                leaf["disposition"] == "allow" || leaf["disposition"] == "deny",
                "disposition is a closed vocabulary: {leaf:?}"
            );
            assert!(
                leaf["reason"].is_string() || leaf["reason"].is_null(),
                "reason is text or null: {leaf:?}"
            );
        }
        assert!(
            leaves
                .iter()
                .filter(|e| e["reason"] == "no_token")
                .all(|e| e["suppressed"].is_null()),
            "a leaf that describes one refusal suppresses nothing: {leaves:?}"
        );

        assert_eq!(
            t.handle.counters().counters(epoch),
            Some(LaunchProofCounters::default()),
            "a credential-less refusal is still not a consultation"
        );
        assert!(t.handle.counters().close_epoch(epoch));
    }

    /// P1.6(a): a listener that closes mid-window still writes what it suppressed.
    ///
    /// A partial window cannot be written when it is filled (it never is), so the
    /// chain would be short by up to eleven refusals forever if closing dropped
    /// it. 13 refusals are 8 leaves + a 5-refusal partial window; the aggregate
    /// for those 5 must appear once the handle is dropped, and only once.
    #[test]
    fn the_trailing_suppressed_window_is_written_once_when_the_listener_closes() {
        let (dialog, _keep) = recording_dialog(Ok(deny_once_result()));
        // `T36::drop` unlinks the chain before its fields drop, so the fixture is
        // held undropped and only the handle is dropped in place - the flush is
        // what this test is about, and it must land in the file the listener
        // wrote. The fixture's scratch state is removed by hand below.
        let mut t =
            std::mem::ManuallyDrop::new(t36_setup("p16-no-token-trailing", &["*"], &[], dialog));
        let sid = t.sid.clone();
        for _ in 0..13 {
            let resp = exchange(t.port, &connect_req_no_auth("api.example.com:443"));
            assert!(resp.starts_with("HTTP/1.1 407"), "{resp}");
        }
        assert_eq!(
            connect_events(&sid).len(),
            8,
            "a partial window writes no leaf while the listener runs"
        );

        // SAFETY: the handle is dropped exactly once, and no reference to it is
        // used afterwards.
        unsafe { std::ptr::drop_in_place(&mut t.handle) };

        let leaves = connect_events(&sid);
        let aggregates: Vec<&serde_json::Value> = leaves
            .iter()
            .filter(|e| e["reason"] == "no_token_suppressed")
            .collect();
        assert_eq!(
            aggregates.len(),
            1,
            "closing the listener must write the partial window exactly once: {leaves:?}"
        );
        assert_eq!(
            aggregates[0]["suppressed"], 5,
            "the remainder is the refusals no other leaf accounts for: {aggregates:?}"
        );
        assert_eq!(aggregates[0]["scope"], serde_json::Value::Null);
        assert_eq!(
            leaves.len(),
            9,
            "8 individual leaves + the one flushed aggregate: {leaves:?}"
        );

        // The fixture's own cleanup, since its `Drop` is what we bypassed.
        let _ = std::fs::remove_file(crate::audit::audit_log_path(&sid));
        let _ = std::fs::remove_dir_all(&t.learned_base);
    }

    /// P1.6(a): the leaf volume is bounded, and the chain still sums to the total.
    ///
    /// 44 refusals are 8 leaves of their own plus 36 suppressed - three full
    /// windows - so the chain must hold 8 + 3 leaves, each aggregate carrying
    /// exactly 12. A count that reset per window without being written, or a
    /// window that fired once and then went silent, fails here: the sum of the
    /// aggregates is the number of refusals no other leaf accounts for.
    #[test]
    fn a_long_flood_writes_one_aggregate_per_window_and_they_sum_to_the_total() {
        let (dialog, _keep) = recording_dialog(Ok(deny_once_result()));
        let t = t36_setup("p16-no-token-windows", &["*"], &[], dialog);
        let epoch = t
            .handle
            .counters()
            .begin_epoch()
            .expect("a window to watch");

        for _ in 0..44 {
            let resp = exchange(t.port, &connect_req_no_auth("api.example.com:443"));
            assert!(resp.starts_with("HTTP/1.1 407"), "{resp}");
        }

        let leaves = connect_events(&t.sid);
        let individual = leaves.iter().filter(|e| e["reason"] == "no_token").count();
        let aggregates: Vec<&serde_json::Value> = leaves
            .iter()
            .filter(|e| e["reason"] == "no_token_suppressed")
            .collect();
        assert_eq!(individual, 8, "the budget is eight leaves: {leaves:?}");
        assert_eq!(
            aggregates.len(),
            3,
            "36 suppressed refusals are three windows: {aggregates:?}"
        );
        let suppressed: u64 = aggregates
            .iter()
            .map(|e| e["suppressed"].as_u64().expect("an integer count"))
            .sum();
        assert_eq!(
            suppressed,
            44 - 8,
            "the aggregates must account for every refusal no other leaf does: {aggregates:?}"
        );
        assert_eq!(
            leaves.len(),
            11,
            "44 refusals must cost 8 + 3 leaves, never 44: {leaves:?}"
        );
        assert_eq!(
            t.handle.counters().counters(epoch),
            Some(LaunchProofCounters::default()),
            "none of it is a consultation"
        );
        assert!(t.handle.counters().close_epoch(epoch));
    }

    /// P1.6 (blocking 2): the FOREIGN arm is budgeted too, with its own counter.
    ///
    /// `Proxy-Authorization: Basic <anything base64>` reaches the `Foreign` arm,
    /// so capping only the credential-less arm left the flood one header away.
    /// The budgets are separate on purpose: a foreign flood must not spend the
    /// missing-credential budget (that is the P1.8 steady state), and neither arm
    /// may silence the other's evidence.
    ///
    /// 20 refusals are 8 `foreign_token` leaves plus 12 suppressed - one window -
    /// and the counters stay `{0,0}`: a foreign credential is still not a
    /// consultation, so it can never satisfy guardrail 1.
    #[test]
    fn foreign_token_refusals_are_capped_by_their_own_budget() {
        let token = RunToken::issue().expect("mint the listener's token");
        let intruder = RunToken::issue().expect("mint another run's token");
        let (dialog, _keep) = recording_dialog(Ok(deny_once_result()));
        let t = t36_setup_token_cfg(
            "p16-foreign-flood",
            &["*"],
            &[],
            dialog,
            true,
            Duration::from_secs(60),
            PromptPolicy::Deny,
            None,
            token.clone(),
        );
        let epoch = t
            .handle
            .counters()
            .begin_epoch()
            .expect("a window to watch");

        for _ in 0..20 {
            let resp = exchange(
                t.port,
                &connect_req_with("api.example.com:443", intruder.value()),
            );
            assert!(resp.starts_with("HTTP/1.1 407"), "{resp}");
        }

        let leaves = connect_events(&t.sid);
        let individual = leaves
            .iter()
            .filter(|e| e["reason"] == "foreign_token")
            .count();
        let aggregates: Vec<&serde_json::Value> = leaves
            .iter()
            .filter(|e| e["reason"] == "foreign_token_suppressed")
            .collect();
        assert_eq!(
            individual, 8,
            "the first eight foreign refusals keep a leaf each: {leaves:?}"
        );
        assert_eq!(
            aggregates.len(),
            1,
            "twelve suppressed foreign refusals are one window: {leaves:?}"
        );
        assert_eq!(leaves.len(), 9, "20 refusals must not cost 20 leaves");
        assert_eq!(
            aggregates[0]["suppressed"], 12,
            "20 - 8, exactly: {aggregates:?}"
        );
        assert_eq!(
            aggregates[0]["scope"],
            serde_json::Value::Null,
            "scope means rule scope: {aggregates:?}"
        );
        assert_eq!(aggregates[0]["host"], "<unknown>");
        assert_eq!(
            t.handle.counters().counters(epoch),
            Some(LaunchProofCounters::default()),
            "a foreign token is not a consultation, capped or not"
        );

        // Independence: the missing-credential arm still owns its own budget, so
        // the foreign flood cannot have spent it.
        let before = connect_events(&t.sid).len();
        let resp = exchange(t.port, &connect_req_no_auth("api.example.com:443"));
        assert!(resp.starts_with("HTTP/1.1 407"), "{resp}");
        assert_eq!(
            connect_events(&t.sid).len(),
            before + 1,
            "the no_token budget was untouched by the foreign flood"
        );
        assert_eq!(last_connect_event(&t.sid)["reason"], "no_token");
        assert!(t.handle.counters().close_epoch(epoch));
    }

    /// P1.6(a)/(blocking 1c): windows are exact, and the remainder is claimable.
    ///
    /// Drives the budget directly - no sockets - so the arithmetic is pinned
    /// where it lives: eight individual leaves, one aggregate per full window of
    /// twelve, and whatever the last partial window holds is carried out exactly
    /// once when the listener closes (never twice, never silently dropped).
    #[test]
    fn a_refusal_budget_yields_exact_windows_and_one_flushable_remainder() {
        let budget = super::RefusalBudget::new();
        for i in 1..=8 {
            assert_eq!(
                budget.spend(),
                super::RefusalLeaf::Individual,
                "refusal {i} is still inside the budget"
            );
        }
        let mut aggregates = Vec::new();
        for _ in 0..30 {
            match budget.spend() {
                super::RefusalLeaf::Aggregate { suppressed } => aggregates.push(suppressed),
                super::RefusalLeaf::Nothing => {}
                super::RefusalLeaf::Individual => panic!("the individual budget is spent"),
            }
        }
        assert_eq!(
            aggregates,
            vec![12, 12],
            "30 suppressed refusals are two windows, each carrying exactly its own count"
        );
        assert_eq!(
            budget.claim_trailing(),
            Some(6),
            "the partial window is what the chain still owes"
        );
        assert_eq!(
            budget.claim_trailing(),
            None,
            "a remainder is written exactly once"
        );
        // And a later refusal cannot resurrect a window that was already paid.
        assert_eq!(budget.spend(), super::RefusalLeaf::Nothing);
        assert_eq!(budget.claim_trailing(), Some(1));
    }

    /// P1.6(b): one credential may be live on exactly one listener.
    ///
    /// `RunToken: Clone` meant two `ProxyConfig`s *could* carry the same value and
    /// both listeners would accept it - the P1.4 ambiguity (whose traffic was
    /// that?) reintroduced through a clone. `spawn` now refuses the second one by
    /// name, and the handle's `Drop` releases the credential.
    #[test]
    fn a_run_token_can_be_live_on_only_one_listener() {
        let token = RunToken::issue().expect("mint a token");
        let (dialog, _keep) = recording_dialog(Ok(deny_once_result()));
        let first = t36_setup_token_cfg(
            "p16-dup-first",
            &["*"],
            &[],
            dialog,
            true,
            Duration::from_secs(60),
            PromptPolicy::Deny,
            None,
            token.clone(),
        );

        // A second listener with a CLONE of the live credential: refused, by name,
        // before it binds a socket or builds a runtime.
        let (dialog, _keep) = recording_dialog(Ok(deny_once_result()));
        let err = try_t36_token_cfg(
            "p16-dup-second",
            &["*"],
            &[],
            dialog,
            true,
            Duration::from_secs(60),
            PromptPolicy::Deny,
            None,
            token.clone(),
        )
        .err()
        .expect("a duplicate live credential must be refused");
        assert!(
            err.downcast_ref::<super::TokenAlreadyLive>().is_some(),
            "the refusal must be the named error, not a free-form string: {err:?}"
        );
        let shown = format!("{err}");
        assert!(
            shown.contains("already live"),
            "the error must say what happened: {shown}"
        );
        assert!(
            !shown.contains(token.value()),
            "the refusal must never print the credential: {shown}"
        );

        // The refused spawn did not disturb the listener that holds the token.
        let resp = exchange(first.port, &connect_req_with("127.0.0.1:9", token.value()));
        assert!(
            resp.starts_with("HTTP/1.1 403"),
            "the holder must still serve its own credential (admitted, then loopback-refused): {resp}"
        );

        // Dropping the handle releases the credential.
        let port = first.port;
        drop(first);
        let again = t36_setup_token_cfg(
            "p16-dup-again",
            &["*"],
            &[],
            {
                let (dialog, _keep) = recording_dialog(Ok(deny_once_result()));
                dialog
            },
            true,
            Duration::from_secs(60),
            PromptPolicy::Deny,
            None,
            token.clone(),
        );
        let resp = exchange(again.port, &connect_req_with("127.0.0.1:9", token.value()));
        assert!(
            resp.starts_with("HTTP/1.1 403"),
            "the re-spawned listener must serve the same credential at its own port {port}: {resp}"
        );

        // Two distinct credentials coexist: the rule is one *live* token per
        // listener, not one listener per process.
        let other_token = RunToken::issue().expect("mint another token");
        let other = t36_setup_token_cfg(
            "p16-dup-other",
            &["*"],
            &[],
            {
                let (dialog, _keep) = recording_dialog(Ok(deny_once_result()));
                dialog
            },
            true,
            Duration::from_secs(60),
            PromptPolicy::Deny,
            None,
            other_token.clone(),
        );
        let resp = exchange(
            other.port,
            &connect_req_with("127.0.0.1:9", other_token.value()),
        );
        assert!(
            resp.starts_with("HTTP/1.1 403"),
            "a distinct credential must spawn alongside the first: {resp}"
        );
    }

    /// P1.6 (registry): the live-token set holds run serials, never credentials.
    ///
    /// The registry exists to make "one credential, one listener" true for the
    /// process, and it used to do that by keeping the credential itself in a
    /// process-global `HashSet<String>` - a second plaintext copy of the secret
    /// for the lifetime of the run. Keying on the run serial keeps the property
    /// (a clone carries the serial it was cloned from, so a clone still collides)
    /// and holds no copy at all. The key type is the assertion: `Vec<u64>` below
    /// does not compile against a string-keyed set.
    #[test]
    fn the_live_token_registry_holds_run_serials_and_no_credential() {
        let token = RunToken::issue().expect("mint a token");
        let (dialog, _keep) = recording_dialog(Ok(deny_once_result()));
        let handle = t36_setup_token_cfg(
            "p16-registry-keys",
            &["*"],
            &[],
            dialog,
            true,
            Duration::from_secs(60),
            PromptPolicy::Deny,
            None,
            token.clone(),
        );

        let keys: Vec<u64> = super::live_tokens().iter().copied().collect();
        assert!(
            keys.contains(&token.run()),
            "this listener's run serial must be registered: {keys:?}"
        );
        let dump = format!("{keys:?}");
        assert!(
            !dump.contains(token.value()),
            "the registry must not retain the credential: {dump}"
        );
        assert!(
            !dump.contains(&token.value()[8..]),
            "nor the secret half of it: {dump}"
        );

        // The same credential twice is still refused (a clone is one identity),
        // which is the property the value-keyed registry used to provide.
        let (dialog, _keep) = recording_dialog(Ok(deny_once_result()));
        let err = try_t36_token_cfg(
            "p16-registry-clone",
            &["*"],
            &[],
            dialog,
            true,
            Duration::from_secs(60),
            PromptPolicy::Deny,
            None,
            token.clone(),
        )
        .err()
        .expect("a clone of a live token must still be refused");
        assert!(
            err.downcast_ref::<super::TokenAlreadyLive>().is_some(),
            "{err:?}"
        );

        // The handle's `Drop` releases the serial, so the set does not grow with
        // the number of listeners a process has ever served.
        let run = token.run();
        drop(handle);
        assert!(
            !super::live_tokens().iter().any(|key| *key == run),
            "drop must release the run serial"
        );
    }

    /// P1.4: an epoch that is still open refuses a second launch by name.
    ///
    /// Before the rule, the second `begin_epoch` simply moved `active`: both
    /// launches' traffic landed in the newer window and the older launch's proof
    /// silently went to zero - a split attribution with no error anywhere.
    #[test]
    fn begin_epoch_refuses_a_second_launch_while_one_is_open() {
        let counters = LaunchCounters::new();
        let first = counters.begin_epoch().expect("the first launch's window");
        counters.note_consultation();

        let err = counters
            .begin_epoch()
            .expect_err("a second concurrent launch must be refused");
        assert_eq!(
            err,
            EpochAlreadyOpen { active: first },
            "the refusal must name the open epoch"
        );
        assert_eq!(
            counters.active_epoch(),
            Some(first),
            "a refused launch must not move the attribution window"
        );
        assert_eq!(
            counters.counters(first),
            Some(LaunchProofCounters {
                consultations: 1,
                upstream_established: 0,
                probes: 0,
            }),
            "a refused launch must not steal or reset the open window"
        );
        assert!(
            err.to_string().contains("still open"),
            "the error must say what is wrong: {err}"
        );

        // Non-vacuity: once the window is closed, the next launch is allowed and
        // starts empty, while the closed window keeps its numbers.
        assert!(counters.close_epoch(first));
        let second = counters.begin_epoch().expect("a window after the close");
        assert_eq!(second, first + 1);
        assert_eq!(
            counters.counters(second),
            Some(LaunchProofCounters::default())
        );
        assert_eq!(
            counters.counters(first),
            Some(LaunchProofCounters {
                consultations: 1,
                upstream_established: 0,
                probes: 0,
            })
        );
    }

    /// P1.4: the pruner evicts **only closed** epochs, so the window a live
    /// launch is about to read can never be dropped.
    ///
    /// Before the rule, `prune` skipped the active epoch alone; once the map hit
    /// `MAX_REMEMBERED_EPOCHS` it evicted the oldest entry regardless of whether
    /// a launch was still proving against it, and that launch then read zeros and
    /// failed `SessionNotAccepted` after doing real work.
    #[test]
    fn an_open_epoch_is_never_evicted_by_pruning() {
        let counters = LaunchCounters::new();
        let live = counters.begin_epoch().expect("the launch in flight");
        counters.note_consultation();

        {
            let mut state = counters.lock();
            // The open epochs get the LOWEST ids on purpose: a pruner that
            // evicts oldest-first without looking at `closed` removes exactly
            // these first, which is the defect this test exists for.
            for id in 100..110 {
                state.epochs.insert(
                    id,
                    EpochEntry {
                        counters: LaunchProofCounters::default(),
                        closed: false,
                    },
                );
            }
            for id in 900..(900 + MAX_REMEMBERED_EPOCHS as u64 + 8) {
                state.epochs.insert(
                    id,
                    EpochEntry {
                        counters: LaunchProofCounters::default(),
                        closed: true,
                    },
                );
            }
            state.prune();

            assert!(
                state.epochs.contains_key(&live),
                "the live launch's window must survive pruning"
            );
            for id in 100..110 {
                assert!(
                    state.epochs.contains_key(&id),
                    "open epoch {id} must survive pruning even though it is the oldest: only \
                     closed epochs are evictable"
                );
            }
            assert_eq!(
                state.epochs.len(),
                MAX_REMEMBERED_EPOCHS,
                "closed epochs are still trimmed to the bound"
            );
            assert_eq!(
                state.epochs.values().filter(|entry| entry.closed).count(),
                MAX_REMEMBERED_EPOCHS - 11,
                "the eleven open epochs are kept on top of the closed bound, and every                  over-bound entry removed was a closed one"
            );
        }

        assert_eq!(
            counters.counters(live),
            Some(LaunchProofCounters {
                consultations: 1,
                upstream_established: 0,
                probes: 0,
            }),
            "the surviving window still holds the live launch's traffic"
        );
    }

    /// The bound holds through ordinary open/close cycles: closed epochs are
    /// pruned oldest-first, so a long-lived listener cannot grow without limit.
    #[test]
    fn the_epoch_registry_stays_bounded_as_launches_close() {
        let counters = LaunchCounters::new();
        let mut last = 0;
        for _ in 0..(MAX_REMEMBERED_EPOCHS * 3) {
            last = counters
                .begin_epoch()
                .expect("sequential launches never overlap");
            counters.note_consultation();
            assert!(counters.close_epoch(last));
        }
        assert_eq!(
            counters.remembered_epochs(),
            MAX_REMEMBERED_EPOCHS,
            "the map must not grow with the number of launches"
        );
        assert_eq!(
            counters.counters(last),
            Some(LaunchProofCounters {
                consultations: 1,
                upstream_established: 0,
                probes: 0,
            }),
            "the newest window is still readable"
        );
        assert_eq!(
            counters.counters(1),
            None,
            "the oldest closed window was evicted"
        );
    }

    // ---- P1 wave 2: absolute-form parsing and head rewriting --------------

    #[test]
    fn absolute_targets_split_into_host_port_and_origin_form() {
        let http = |target: &str| match parse_absolute_target(target) {
            AbsoluteTarget::Forward(f) => f,
            other => panic!("{target} should forward, got {other:?}"),
        };
        assert_eq!(
            http("http://origin.example/a?b=1"),
            ForwardTarget {
                host: "origin.example".into(),
                port: 80,
                origin_form: "/a?b=1".into(),
            }
        );
        assert_eq!(
            http("HTTP://Origin.Example:8080"),
            ForwardTarget {
                host: "Origin.Example".into(),
                port: 8080,
                origin_form: "/".into(),
            },
            "no path means /, and the scheme is case-insensitive"
        );
        assert_eq!(
            http("http://[::1]:9000/x").origin_form,
            "/x",
            "a bracketed IPv6 authority is split without its brackets"
        );
        assert_eq!(
            http("http://user:secret@origin.example:81/p"),
            ForwardTarget {
                host: "origin.example".into(),
                port: 81,
                origin_form: "/p".into(),
            },
            "userinfo is dropped, never forwarded"
        );
        assert_eq!(http("http://origin.example?q=1").origin_form, "/?q=1");

        assert_eq!(
            parse_absolute_target("https://origin.example/"),
            AbsoluteTarget::HttpsNeedsConnect,
            "absolute-form https needs CONNECT and must be refused, not downgraded"
        );
        for bad in [
            "ftp://origin.example/",
            "http://",
            "http://:80/",
            "http://origin.example:0/",
            "http://origin.example:notaport/",
            "http://[::1/",
            "http://::1/",
            "/origin-form",
        ] {
            assert_eq!(
                parse_absolute_target(bad),
                AbsoluteTarget::Malformed,
                "{bad} must not be forwardable"
            );
        }
    }

    /// One authenticated absolute-form request: request line, our credential,
    /// `extra` fields (CRLF-terminated), the empty line, then `body`.
    fn fwd_req(method: &str, target: &str, extra: &str, body: &str) -> String {
        let c = crlf();
        let auth = auth_header();
        format!("{method} {target} HTTP/1.1{c}{auth}{extra}{c}{body}")
    }

    #[test]
    fn rewrite_head_makes_it_origin_form_and_drops_connection_scoped_headers() {
        let head = concat!(
            "GET http://origin.example:8080/a?b=1 HTTP/1.1\r\n",
            "Host: origin.example:8080\r\n",
            "Proxy-Authorization: Basic \"***\"\r\n",
            "Proxy-Connection: keep-alive\r\n",
            "Connection: keep-alive\r\n",
            "X-Keep: yes\r\n",
            "\r\n",
        );
        let rewritten = rewrite_head_for_upstream(head, "/a?b=1", "origin.example:8080");
        assert_eq!(
            rewritten,
            concat!(
                "GET /a?b=1 HTTP/1.1\r\n",
                "Host: origin.example:8080\r\n",
                "X-Keep: yes\r\n",
                "Connection: close\r\n\r\n",
            ),
            "origin-form target, no proxy credential, no client connection headers"
        );
        // The method and version survive; only the target changes.
        let post = "POST http://o/x HTTP/1.1\r\nHost: o\r\n\r\n";
        assert!(
            rewrite_head_for_upstream(post, "/x", "o").starts_with("POST /x HTTP/1.1\r\n"),
            "method and version must be preserved"
        );
    }

    /// Admission decides on the request-target authority, so that authority — and
    /// nothing the client put in a header — is the `Host` the origin sees.
    #[test]
    fn rewrite_head_rebuilds_the_host_from_the_admitted_authority() {
        let head = concat!(
            "GET http://allowlisted.example/ HTTP/1.1\r\n",
            "Host: victim.internal\r\n",
            "\r\n",
        );
        let rewritten = rewrite_head_for_upstream(head, "/", "allowlisted.example");
        assert!(
            rewritten.contains("\r\nHost: allowlisted.example\r\n"),
            "the admitted authority must be the Host: {rewritten:?}"
        );
        assert!(
            !rewritten.contains("victim.internal"),
            "the client's Host must never reach the origin: {rewritten:?}"
        );
        assert_eq!(
            rewritten.matches("Host:").count(),
            1,
            "exactly one Host line: {rewritten:?}"
        );
    }

    #[test]
    fn rewrite_head_supplies_a_host_when_the_client_sent_none() {
        let head = "GET http://origin.example/a HTTP/1.1\r\nX-Keep: yes\r\n\r\n";
        let rewritten = rewrite_head_for_upstream(head, "/a", "origin.example");
        assert!(
            rewritten.contains("\r\nHost: origin.example\r\n"),
            "HTTP/1.1 requires a Host, so an absent one is supplied: {rewritten:?}"
        );
    }

    #[test]
    fn host_value_normalises_the_port_and_brackets_ipv6_literals() {
        let value = |target: &str| match parse_absolute_target(target) {
            AbsoluteTarget::Forward(fwd) => upstream_host_value(&fwd),
            other => panic!("{target} should forward, got {other:?}"),
        };
        assert_eq!(value("http://origin.example/"), "origin.example");
        assert_eq!(
            value("http://origin.example:80/"),
            "origin.example",
            "the default port is omitted"
        );
        assert_eq!(
            value("http://origin.example:8080/"),
            "origin.example:8080",
            "a non-default port is included"
        );
        assert_eq!(
            value("http://[2001:db8::1]/p"),
            "[2001:db8::1]",
            "an IPv6 literal keeps its brackets"
        );
        assert_eq!(
            value("http://[2001:db8::1]:8080/p"),
            "[2001:db8::1]:8080",
            "an IPv6 literal with a port stays bracketed"
        );
    }

    #[test]
    fn rewrite_head_drops_fields_named_in_the_clients_connection_list() {
        // RFC 9110 7.6.1: whatever the client's `Connection:` names is
        // connection-scoped for this hop, even if it is not on our fixed list.
        let head = concat!(
            "GET http://origin.example/x HTTP/1.1\r\n",
            "Host: origin.example\r\n",
            "Connection: keep-alive, X-Secret-Hop\r\n",
            "X-Secret-Hop: leak\r\n",
            "X-Keep: yes\r\n",
            "\r\n",
        );
        let rewritten = rewrite_head_for_upstream(head, "/x", "origin.example");
        assert!(
            !rewritten.to_ascii_lowercase().contains("x-secret-hop"),
            "a Connection-listed field must not be forwarded: {rewritten:?}"
        );
        assert!(
            rewritten.contains("X-Keep: yes\r\n"),
            "an unrelated field survives: {rewritten:?}"
        );
        assert!(
            rewritten.ends_with("Connection: close\r\n\r\n"),
            "the hop is closed explicitly: {rewritten:?}"
        );
    }

    #[test]
    fn rewrite_head_drops_te_trailer_and_proxy_authenticate() {
        // The explicit decisions: `TE` (a client's acceptable codings), `Trailer`
        // (meaningless without chunked, which this path refuses) and
        // `Proxy-Authenticate` (a response field; forwarding it invites a 407)
        // are all dropped, while `Content-Length` — the one framing signal — is
        // forwarded untouched.
        let head = concat!(
            "POST http://origin.example/x HTTP/1.1\r\n",
            "Host: origin.example\r\n",
            "TE: trailers\r\n",
            "Trailer: X-Checksum\r\n",
            "Proxy-Authenticate: Basic realm=\"x\"\r\n",
            "Content-Length: 2\r\n",
            "\r\n",
        );
        let rewritten = rewrite_head_for_upstream(head, "/x", "origin.example");
        let lower = rewritten.to_ascii_lowercase();
        for gone in ["te:", "trailer:", "proxy-authenticate"] {
            assert!(
                !lower.contains(gone),
                "{gone} survived the rewrite: {rewritten:?}"
            );
        }
        assert!(
            rewritten.contains("Content-Length: 2\r\n"),
            "the framing signal is forwarded: {rewritten:?}"
        );
    }

    /// The target is chosen by the sandboxed child, so a byte offset inside a
    /// multi-byte character must be a verdict, never a panic.
    #[test]
    fn parse_absolute_target_is_utf8_safe_at_the_scheme_boundary() {
        for target in ["abcd😀://x", "http:/😀x"] {
            assert_eq!(
                parse_absolute_target(target),
                AbsoluteTarget::Malformed,
                "{target:?} must be refused, not panic"
            );
        }
    }

    #[test]
    fn bare_lf_and_obs_fold_are_framing_errors() {
        assert_eq!(
            head_framing_error("GET http://o/x HTTP/1.1\r\n\r\n"),
            None,
            "a plain CRLF head is fine"
        );
        assert_eq!(
            head_framing_error("GET http://o/x HTTP/1.1\nX: y\r\n\r\n"),
            Some("bare LF in the request head")
        );
        assert_eq!(
            head_framing_error("GET http://o/x HTTP/1.1\r\nX: y\r\n z\r\n\r\n"),
            Some("obs-fold line in the request head")
        );
        assert_eq!(
            head_framing_error("GET http://o/x HTTP/1.1\r\nX: y"),
            Some("request head is not CRLF-terminated")
        );
    }

    /// The exact split the framing rule closes: one CRLF field to the rewriter,
    /// three to the LF-aware auth gate and request-line parse.
    #[test]
    fn bare_lf_in_the_head_is_a_400_and_never_reaches_admission() {
        let (dialog, calls) = recording_dialog(Ok(allow_once()));
        let t = t36_setup("bare-lf", &["origin.example"], &[], dialog);
        let smuggled = "X-Hop: a\nConnection: upgrade\nUpgrade: h2c\r\n";
        let resp = exchange(
            t.port,
            &fwd_req("GET", "http://origin.example/x", smuggled, ""),
        );
        assert!(resp.starts_with("HTTP/1.1 400"), "got: {resp}");
        assert!(
            resp.contains("bare LF"),
            "the reason must name the framing fault: {resp}"
        );
        assert!(
            calls.lock().unwrap().is_empty(),
            "a framing refusal is not a policy question"
        );
        assert!(
            connect_events(&t.sid).is_empty(),
            "and it is not a consultation either: {:?}",
            connect_events(&t.sid)
        );
    }

    #[test]
    fn forward_body_framing_accepts_exactly_one_content_length() {
        let head = |fields: &str| format!("POST http://o/x HTTP/1.1{c}{fields}{c}{c}", c = crlf());
        assert_eq!(forward_body_framing(&head("")), Ok(ForwardBody::None));
        assert_eq!(
            forward_body_framing(&head("Content-Length: 7\r\n")),
            Ok(ForwardBody::Length(7))
        );
        assert_eq!(
            forward_body_framing(&head("Content-Length: 7\r\nContent-Length: 7\r\n")),
            Ok(ForwardBody::Length(7)),
            "repeated but identical values are one signal"
        );
        assert_eq!(
            forward_body_framing(&head("Content-Length: 7, 7\r\n")),
            Ok(ForwardBody::Length(7)),
            "a repeated list of identical values is one signal"
        );
        assert_eq!(
            forward_body_framing(&head("content-length: 7\r\nContent-Length: 8\r\n")),
            Err(BodyReject::ConflictingContentLength),
            "two different body lengths must never be resolved by preference"
        );
        assert_eq!(
            forward_body_framing(&head("Content-Length: seven\r\n")),
            Err(BodyReject::BadContentLength)
        );
        assert_eq!(
            forward_body_framing(&head("Content-Length: +5\r\n")),
            Err(BodyReject::BadContentLength),
            "a leading '+' is accepted by Rust's usize parser but is not a decimal number to every origin (RFC 9110 8.6: 1*DIGIT)"
        );
        assert_eq!(
            forward_body_framing(&head("Content-Length: \r\n")),
            Err(BodyReject::BadContentLength),
            "an empty value frames nothing and must not be read as zero"
        );
        assert_eq!(
            forward_body_framing(&head("Content-Length: 0x5\r\n")),
            Err(BodyReject::BadContentLength)
        );
        assert_eq!(
            forward_body_framing(&head("Content-Length:  5 \r\n")),
            Ok(ForwardBody::Length(5)),
            "surrounding OWS is legal and keeps the field decimal"
        );
        assert_eq!(
            forward_body_framing(&head("Transfer-Encoding: chunked\r\n")),
            Err(BodyReject::TransferEncoding)
        );
        assert_eq!(
            forward_body_framing(&head("Transfer-Encoding: identity\r\n")),
            Err(BodyReject::TransferEncoding),
            "any Transfer-Encoding, not only chunked"
        );
    }

    #[test]
    fn transfer_encoding_is_a_400_and_reaches_no_origin() {
        let origin = FakeOrigin::start("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
        let (dialog, _c) = recording_dialog(Ok(allow_once()));
        let t = t36_setup("fwd-te", &[origin.host.as_str()], &[], dialog);
        let extra = "Transfer-Encoding: chunked\r\n";
        let resp = exchange(
            t.port,
            &fwd_req(
                "POST",
                &format!("http://{}/x", origin.authority()),
                extra,
                "0\r\n\r\n",
            ),
        );
        assert!(resp.starts_with("HTTP/1.1 400"), "got: {resp}");
        assert!(
            resp.contains("Transfer-Encoding is not accepted on this path"),
            "Transfer-Encoding cannot be re-framed safely, so it is refused: {resp}"
        );
        assert!(
            origin.requests().is_empty(),
            "nothing may be forwarded: {:?}",
            origin.requests()
        );
    }

    #[test]
    fn conflicting_content_length_is_a_400_and_reaches_no_origin() {
        let origin = FakeOrigin::start("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
        let (dialog, _c) = recording_dialog(Ok(allow_once()));
        let t = t36_setup("fwd-cl", &[origin.host.as_str()], &[], dialog);
        let extra = "Content-Length: 5\r\nContent-Length: 6\r\n";
        let resp = exchange(
            t.port,
            &fwd_req(
                "POST",
                &format!("http://{}/x", origin.authority()),
                extra,
                "hello",
            ),
        );
        assert!(resp.starts_with("HTTP/1.1 400"), "got: {resp}");
        assert!(
            resp.contains("conflicting Content-Length"),
            "the reason must name the conflict: {resp}"
        );
        assert!(
            origin.requests().is_empty(),
            "nothing may be forwarded: {:?}",
            origin.requests()
        );
    }

    /// Exactly one request per client connection: a body followed by a second,
    /// unadmitted request is a 400 and the trailing bytes are never relayed.
    #[test]
    fn body_followed_by_trailing_bytes_is_a_400_and_nothing_is_forwarded() {
        let origin = FakeOrigin::start("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
        let (dialog, _c) = recording_dialog(Ok(allow_once()));
        let t = t36_setup("fwd-trailing", &[origin.host.as_str()], &[], dialog);
        let smuggled = "GET http://origin.example/second HTTP/1.1\r\nHost: origin.example\r\n\r\n";
        let resp = exchange(
            t.port,
            &fwd_req(
                "POST",
                &format!("http://{}/upload", origin.authority()),
                "Content-Length: 5\r\n",
                &format!("hello{smuggled}"),
            ),
        );
        assert!(resp.starts_with("HTTP/1.1 400"), "got: {resp}");
        assert!(
            resp.contains("one request per connection"),
            "the reason must name the rule: {resp}"
        );
        assert!(
            origin.requests().is_empty(),
            "neither the request nor the smuggled second one may be forwarded: {:?}",
            origin.requests()
        );
    }

    #[test]
    fn post_body_is_forwarded_byte_exact_with_the_admitted_host() {
        let origin = FakeOrigin::start("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
        let (dialog, _c) = recording_dialog(Ok(allow_once()));
        let t = t36_setup("fwd-post", &[origin.host.as_str()], &[], dialog);
        let body = "{\"hello\":\"world\"}";
        let authority = origin.authority();
        let extra = format!(
            "Host: victim.internal\r\nContent-Length: {}\r\nContent-Type: application/json\r\n",
            body.len()
        );
        let resp = exchange(
            t.port,
            &fwd_req(
                "POST",
                &format!("http://{authority}/upload?x=1"),
                &extra,
                body,
            ),
        );
        assert!(resp.starts_with("HTTP/1.1 200"), "got: {resp}");
        assert!(
            resp.ends_with("ok"),
            "the origin's body must be relayed: {resp}"
        );

        let seen = origin.requests();
        assert_eq!(seen.len(), 1, "exactly one request: {seen:?}");
        let raw = &seen[0];
        assert!(
            raw.starts_with("POST /upload?x=1 HTTP/1.1\r\n"),
            "the origin sees an origin-form target: {raw:?}"
        );
        assert!(
            raw.contains(&format!("\r\nHost: {authority}\r\n")),
            "the Host is the admitted authority, not the client's: {raw:?}"
        );
        assert!(
            !raw.contains("victim.internal"),
            "the client's Host never reaches the origin: {raw:?}"
        );
        assert!(
            raw.ends_with(&format!("\r\n\r\n{body}")),
            "the body must arrive byte-exact: {raw:?}"
        );
    }

    /// An origin must not be able to answer a *proxy* challenge: an honest client
    /// would replay our session token to it.
    #[test]
    fn origin_407_is_rewritten_to_502_and_the_challenge_is_withheld() {
        let origin = FakeOrigin::start(concat!(
            "HTTP/1.1 407 Proxy Authentication Required\r\n",
            "Proxy-Authenticate: Basic realm=\"origin\"\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        ));
        let (dialog, _c) = recording_dialog(Ok(allow_once()));
        let t = t36_setup("fwd-407", &[origin.host.as_str()], &[], dialog);
        let resp = exchange(
            t.port,
            &fwd_req("GET", &format!("http://{}/x", origin.authority()), "", ""),
        );
        assert!(
            resp.starts_with("HTTP/1.1 502"),
            "an origin 407 must be a 502 to the client: {resp}"
        );
        assert!(
            !resp.contains("Proxy-Authenticate"),
            "the challenge must never reach the client: {resp}"
        );
        assert!(
            !resp.contains("407"),
            "not even the status may be echoed: {resp}"
        );
        assert!(
            resp.contains("X-Sandbox: origin-challenge"),
            "the rewrite is marked for the operator: {resp}"
        );
    }

    // =================================================================
    // Round 3 — the forward path accepts only boring requests and responses
    // =================================================================

    #[test]
    fn field_names_must_be_rfc9110_tokens() {
        assert_eq!(
            head_field_syntax_error("GET http://o/x HTTP/1.1\r\n\r\n"),
            None
        );
        assert_eq!(
            head_field_syntax_error("POST http://o/x HTTP/1.1\r\nContent-Length: 5\r\n\r\n"),
            None,
            "a well-formed framing field is accepted"
        );
        assert_eq!(
            head_field_syntax_error("POST http://o/x HTTP/1.1\r\nContent-Length : 5\r\n\r\n"),
            Some("whitespace in a field name"),
            "a space before the colon is a different name to a strict origin"
        );
        assert_eq!(
            head_field_syntax_error("POST http://o/x HTTP/1.1\r\nX Y: z\r\n\r\n"),
            Some("whitespace in a field name")
        );
        assert_eq!(
            head_field_syntax_error("POST http://o/x HTTP/1.1\r\n: v\r\n\r\n"),
            Some("empty field name in the request head")
        );
        assert_eq!(
            head_field_syntax_error("POST http://o/x HTTP/1.1\r\nnot-a-field\r\n\r\n"),
            Some("header line without a field name"),
            "a line with no colon is not a field this proxy may forward"
        );
    }

    #[test]
    fn connection_may_not_name_a_framing_field() {
        let head = |value: &str| format!("POST http://o/x HTTP/1.1\r\nConnection: {value}\r\n\r\n");
        assert_eq!(connection_listed_framing_field(&head("close")), None);
        assert_eq!(
            connection_listed_framing_field(&head("keep-alive, X-Secret-Hop")),
            None,
            "an ordinary hop-by-hop list is still dropped, not refused"
        );
        assert_eq!(
            connection_listed_framing_field(&head("Content-Length")),
            Some("content-length"),
            "naming the framing field would strip it"
        );
        assert_eq!(connection_listed_framing_field(&head("Host")), Some("host"));
        assert_eq!(
            connection_listed_framing_field(&head("keep-alive, Transfer-Encoding")),
            Some("transfer-encoding")
        );
        assert_eq!(
            connection_listed_framing_field(&head("connection")),
            Some("connection")
        );
    }

    #[test]
    fn expect_is_detected_whatever_its_value() {
        let head = |fields: &str| format!("POST http://o/x HTTP/1.1\r\n{fields}\r\n");
        assert!(
            !has_expect_field(&head("X-Expect-Thing: 1\r\n")),
            "only the field named Expect counts"
        );
        assert!(has_expect_field(&head("Expect: 100-continue\r\n")));
        assert!(
            has_expect_field(&head("expect:\r\n")),
            "presence decides, not the value"
        );
    }

    #[test]
    fn upstream_status_line_must_be_a_strict_http1_status() {
        assert_eq!(parse_upstream_status_line("HTTP/1.1 200 OK"), Some(200));
        assert_eq!(parse_upstream_status_line("HTTP/1.1 404"), Some(404));
        assert_eq!(
            parse_upstream_status_line("HTTP/1.1 103 Early Hints"),
            Some(103),
            "an interim status parses — the caller is what refuses it"
        );
        assert_eq!(
            parse_upstream_status_line("HTTP/1.0 500 Internal Server Error"),
            Some(500)
        );
        for bad in [
            "",
            " 200 OK",
            "HTTP/1.1  200 OK",
            "HTTP/2 200 OK",
            "http/1.1 200 OK",
            "HTTP/1.1 20 OK",
            "HTTP/1.1 2000 OK",
            "HTTP/1.1",
            "HTTP/1.1 abc OK",
            "ICY 200 OK",
        ] {
            assert_eq!(
                parse_upstream_status_line(bad),
                None,
                "{bad:?} must not yield a status"
            );
        }
    }

    #[test]
    fn relayed_response_head_carries_exactly_one_connection_close() {
        // No `Connection` from the origin: exactly one is added, and the rest of
        // the head — framing fields included — is relayed byte for byte.
        let relayed = relayed_response_head(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
        assert_eq!(
            String::from_utf8(relayed).unwrap(),
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
        );

        // `keep-alive` is replaced, not appended to.
        let relayed = relayed_response_head(
            b"HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Length: 2\r\n\r\nok",
        );
        let head = String::from_utf8(relayed).unwrap();
        let lower = head.to_ascii_lowercase();
        assert_eq!(lower.matches("connection:").count(), 1, "{head:?}");
        assert!(head.contains("Connection: close"), "{head:?}");
        assert!(!lower.contains("keep-alive"), "{head:?}");
        assert!(
            head.ends_with("\r\n\r\nok"),
            "the body prefix survives: {head:?}"
        );

        // Two origin fields, in any spelling, collapse to one.
        let relayed = relayed_response_head(
            b"HTTP/1.1 204 No Content\r\nconnection: close\r\nCONNECTION: keep-alive\r\n\r\n",
        );
        let head = String::from_utf8(relayed).unwrap();
        assert_eq!(lower_count(&head), 1, "{head:?}");
        assert!(head.starts_with("HTTP/1.1 204 No Content\r\n"), "{head:?}");
    }

    fn lower_count(head: &str) -> usize {
        head.to_ascii_lowercase().matches("connection:").count()
    }

    async fn classify_upstream(raw: &[u8]) -> UpstreamHead {
        let (mut client, mut feed) = tokio::io::duplex(256);
        let raw = raw.to_vec();
        let writer = tokio::spawn(async move {
            feed.write_all(&raw).await.unwrap();
        });
        let head = read_upstream_head(&mut client)
            .await
            .expect("a non-empty reply is classified");
        writer.await.unwrap();
        head
    }

    /// The classification the relay depends on, independent of the wire tests:
    /// only a final `HTTP/1.x` response with a defined status is relayed.
    #[tokio::test]
    async fn read_upstream_head_only_accepts_a_final_http1_response() {
        assert!(matches!(
            classify_upstream(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").await,
            UpstreamHead::Final { status: 200, .. }
        ));
        assert_eq!(
            classify_upstream(b"HTTP/1.1 103 Early Hints\r\nLink: </x>\r\n\r\n").await,
            UpstreamHead::Interim,
            "an interim head is never an answer"
        );
        assert_eq!(
            classify_upstream(b"\r\nHTTP/1.1 407 Proxy Authentication Required\r\n\r\n").await,
            UpstreamHead::StatusUnparsable,
            "a leading CRLF leaves no first line to read a status from"
        );
        assert_eq!(
            classify_upstream(b"HTTP/2 200 OK\r\n\r\n").await,
            UpstreamHead::StatusUnparsable,
            "only HTTP/1.x is spoken here"
        );
        assert_eq!(
            classify_upstream(b"HTTP/1.1 200").await,
            UpstreamHead::StatusUnparsable,
            "an incomplete head is not vouched for"
        );
    }

    /// BLOCKER 1: an interim head is not an answer. `103` followed by `407` used
    /// to be relayed verbatim — an interim header block standing in for a status
    /// the client never received, with the challenge in it.
    #[test]
    fn interim_103_then_407_never_reaches_the_client() {
        let origin = FakeOrigin::start(concat!(
            "HTTP/1.1 103 Early Hints\r\n",
            "Link: </style.css>; rel=preload\r\n",
            "\r\n",
            "HTTP/1.1 407 Proxy Authentication Required\r\n",
            "Proxy-Authenticate: Basic realm=\"origin\"\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        ));
        let (dialog, _c) = recording_dialog(Ok(allow_once()));
        let t = t36_setup("fwd-103", &[origin.host.as_str()], &[], dialog);
        let resp = exchange(
            t.port,
            &fwd_req("GET", &format!("http://{}/x", origin.authority()), "", ""),
        );
        assert!(
            resp.starts_with("HTTP/1.1 502"),
            "an interim head must not be relayed: {resp}"
        );
        assert!(
            resp.contains("X-Sandbox: interim-response-unsupported"),
            "the refusal is named: {resp}"
        );
        assert!(!resp.contains("Proxy-Authenticate"), "no challenge: {resp}");
        assert!(!resp.contains("407"), "not even the status: {resp}");
        assert!(
            !resp.contains("Early Hints") && !resp.contains("rel=preload"),
            "not one byte of the interim head: {resp}"
        );
        assert_eq!(
            origin.requests().len(),
            1,
            "the request itself was admitted and sent"
        );
    }

    /// BLOCKER 2: a leading CRLF makes the status line empty, so the status check
    /// read `0` and the 407 behind it reached the client.
    #[test]
    fn response_starting_with_crlf_is_refused_and_the_challenge_withheld() {
        let origin = FakeOrigin::start(concat!(
            "\r\n",
            "HTTP/1.1 407 Proxy Authentication Required\r\n",
            "Proxy-Authenticate: Basic realm=\"origin\"\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        ));
        let (dialog, _c) = recording_dialog(Ok(allow_once()));
        let t = t36_setup("fwd-crlf", &[origin.host.as_str()], &[], dialog);
        let resp = exchange(
            t.port,
            &fwd_req("GET", &format!("http://{}/x", origin.authority()), "", ""),
        );
        assert!(
            resp.starts_with("HTTP/1.1 502"),
            "an unparsable head must be refused: {resp}"
        );
        assert!(
            resp.contains("X-Sandbox: origin-status-unparsable"),
            "the refusal is named: {resp}"
        );
        assert!(!resp.contains("Proxy-Authenticate"), "no challenge: {resp}");
        assert!(!resp.contains("407"), "not even the status: {resp}");
    }

    /// BLOCKER 3: `Connection` naming a framing field asks the rewrite to strip
    /// it, which relays the body to the origin as a second, unadmitted request
    /// carrying the client's own `Host`.
    #[test]
    fn connection_naming_a_framing_field_is_a_400_and_reaches_no_origin() {
        let origin = FakeOrigin::start("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
        let (dialog, calls) = recording_dialog(Ok(allow_once()));
        let t = t36_setup("fwd-conn-framing", &[origin.host.as_str()], &[], dialog);
        let smuggled =
            "GET http://victim.internal/second HTTP/1.1\r\nHost: victim.internal\r\n\r\n";
        for (listed, token) in [
            ("Content-Length", "content-length"),
            ("Host", "host"),
            ("Transfer-Encoding", "transfer-encoding"),
            ("connection", "connection"),
        ] {
            let extra = format!(
                "Connection: {listed}\r\nContent-Length: {}\r\n",
                smuggled.len()
            );
            let resp = exchange(
                t.port,
                &fwd_req(
                    "POST",
                    &format!("http://{}/x", origin.authority()),
                    &extra,
                    smuggled,
                ),
            );
            assert!(resp.starts_with("HTTP/1.1 400"), "{listed} -> {resp}");
            assert!(
                resp.contains(&format!("Connection names the framing field `{token}`")),
                "{listed} -> {resp}"
            );
        }
        assert!(
            origin.requests().is_empty(),
            "nothing may be dialled: {:?}",
            origin.requests()
        );
        assert!(
            calls.lock().unwrap().is_empty(),
            "a framing refusal is not a policy question"
        );
        assert!(
            connect_events(&t.sid).is_empty(),
            "and not a consultation either: {:?}",
            connect_events(&t.sid)
        );
    }

    /// DEFECT 4: `Content-Length : 5` is not a field name this proxy may frame
    /// on, while `Content-Length: 5` still is.
    #[test]
    fn whitespace_in_a_field_name_is_a_400_and_a_valid_one_still_forwards() {
        let origin = FakeOrigin::start("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
        let (dialog, calls) = recording_dialog(Ok(allow_once()));
        let t = t36_setup("fwd-field-name", &[origin.host.as_str()], &[], dialog);
        let resp = exchange(
            t.port,
            &fwd_req(
                "POST",
                &format!("http://{}/x", origin.authority()),
                "Content-Length : 5\r\n",
                "hello",
            ),
        );
        assert!(resp.starts_with("HTTP/1.1 400"), "{resp}");
        assert!(
            resp.contains("whitespace in a field name"),
            "the fault is named: {resp}"
        );
        assert!(
            origin.requests().is_empty(),
            "nothing may be dialled: {:?}",
            origin.requests()
        );
        assert!(
            calls.lock().unwrap().is_empty(),
            "a syntax refusal is not a policy question"
        );

        let resp = exchange(
            t.port,
            &fwd_req(
                "POST",
                &format!("http://{}/x", origin.authority()),
                "Content-Length: 5\r\n",
                "hello",
            ),
        );
        assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
        let seen = origin.requests();
        assert_eq!(seen.len(), 1, "exactly one request: {seen:?}");
        assert!(
            seen[0].ends_with("\r\n\r\nhello"),
            "the body arrives byte-exact: {:?}",
            seen[0]
        );
    }

    /// REGRESSION 5: `Expect` is refused before admission — the behaviour chosen
    /// over stripping it and answering `100 Continue` ourselves.
    #[test]
    fn expect_header_is_refused_before_admission() {
        let origin = FakeOrigin::start("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
        let (dialog, calls) = recording_dialog(Ok(allow_once()));
        let t = t36_setup("fwd-expect", &[origin.host.as_str()], &[], dialog);
        let resp = exchange(
            t.port,
            &fwd_req(
                "POST",
                &format!("http://{}/x", origin.authority()),
                "Expect: 100-continue\r\nContent-Length: 5\r\n",
                "hello",
            ),
        );
        assert!(resp.starts_with("HTTP/1.1 400"), "{resp}");
        assert!(
            resp.contains("X-Sandbox: expect-unsupported"),
            "the refusal is named: {resp}"
        );
        assert!(
            origin.requests().is_empty(),
            "nothing may be dialled: {:?}",
            origin.requests()
        );
        assert!(calls.lock().unwrap().is_empty(), "refused before admission");
        assert!(
            connect_events(&t.sid).is_empty(),
            "and not counted: {:?}",
            connect_events(&t.sid)
        );
    }

    /// REGRESSION 6: the listener closes the client socket after every forward, so
    /// the relayed head must say `Connection: close` exactly once — a client that
    /// honoured the origin's `keep-alive` would reuse a dead connection.
    #[test]
    fn relayed_response_tells_the_client_the_connection_closes() {
        let origin = FakeOrigin::start(concat!(
            "HTTP/1.1 200 OK\r\n",
            "Connection: keep-alive\r\n",
            "Content-Length: 2\r\n",
            "\r\n",
            "ok",
        ));
        let (dialog, _c) = recording_dialog(Ok(allow_once()));
        let t = t36_setup("fwd-close", &[origin.host.as_str()], &[], dialog);
        let resp = exchange(
            t.port,
            &fwd_req("GET", &format!("http://{}/x", origin.authority()), "", ""),
        );
        assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
        assert_eq!(
            lower_count(&resp),
            1,
            "exactly one Connection field: {resp}"
        );
        assert!(resp.contains("Connection: close"), "{resp}");
        assert!(
            !resp.to_ascii_lowercase().contains("keep-alive"),
            "the origin's keep-alive must not survive: {resp}"
        );
        assert!(resp.ends_with("ok"), "the body is relayed: {resp}");
    }

    #[tokio::test]
    async fn relay_forwards_exactly_the_framed_body() {
        let (mut client, mut client_feed) = tokio::io::duplex(64);
        let (mut upstream_sink, mut upstream_check) = tokio::io::duplex(64);
        let feed = tokio::spawn(async move {
            client_feed.write_all(b"llo world").await.unwrap();
        });
        relay_framed_body(&mut client, &mut upstream_sink, b"he", 11)
            .await
            .expect("the framed body must be forwarded");
        drop(upstream_sink);
        let mut got = Vec::new();
        upstream_check.read_to_end(&mut got).await.unwrap();
        feed.await.unwrap();
        assert_eq!(got, b"hello world");
    }

    #[tokio::test]
    async fn relay_rejects_leftover_beyond_the_framed_body() {
        let (mut client, _feed) = tokio::io::duplex(64);
        let (mut upstream_sink, _check) = tokio::io::duplex(64);
        assert_eq!(
            relay_framed_body(&mut client, &mut upstream_sink, b"helloGET /x HTTP/1.1", 5).await,
            Err(BodyRelayError::Trailing),
            "bytes past the framed body are a second request, never relayed"
        );
    }

    /// The host's non-loopback IPv4: the forward path refuses loopback targets by
    /// design, so a forwardable origin has to live on a real interface.
    fn route_ipv4() -> std::net::Ipv4Addr {
        let probe = std::net::UdpSocket::bind("0.0.0.0:0").expect("route probe socket");
        probe.connect("1.1.1.1:80").expect("route probe");
        match probe.local_addr().expect("route probe address").ip() {
            std::net::IpAddr::V4(v4) if !v4.is_loopback() => v4,
            other => panic!("this host has no non-loopback IPv4 (probe {other})"),
        }
    }

    /// A local origin the forward path can actually reach, recording the exact
    /// bytes of every request it is sent and answering with a canned response.
    struct FakeOrigin {
        host: String,
        port: u16,
        seen: Arc<StdMutex<Vec<Vec<u8>>>>,
        stop: Arc<std::sync::atomic::AtomicBool>,
        join: Option<std::thread::JoinHandle<()>>,
    }

    impl FakeOrigin {
        fn start(response: &str) -> FakeOrigin {
            use std::io::Write;
            use std::sync::atomic::Ordering;
            let ip = route_ipv4();
            let listener = std::net::TcpListener::bind((ip, 0)).expect("bind fake origin");
            let port = listener.local_addr().unwrap().port();
            listener.set_nonblocking(true).unwrap();
            let seen = Arc::new(StdMutex::new(Vec::new()));
            let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let seen_t = Arc::clone(&seen);
            let stop_t = Arc::clone(&stop);
            let response = response.to_string();
            let join = std::thread::spawn(move || {
                while !stop_t.load(Ordering::SeqCst) {
                    let Ok((mut s, _)) = listener.accept() else {
                        std::thread::sleep(Duration::from_millis(5));
                        continue;
                    };
                    s.set_nonblocking(false).ok();
                    s.set_read_timeout(Some(Duration::from_secs(5))).ok();
                    if let Some(raw) = read_one_request(&mut s) {
                        seen_t.lock().unwrap().push(raw);
                        let _ = s.write_all(response.as_bytes());
                    }
                    let _ = s.shutdown(std::net::Shutdown::Both);
                }
            });
            FakeOrigin {
                host: ip.to_string(),
                port,
                seen,
                stop,
                join: Some(join),
            }
        }

        fn authority(&self) -> String {
            format!("{}:{}", self.host, self.port)
        }

        /// Every request the origin received, verbatim (head plus framed body).
        fn requests(&self) -> Vec<String> {
            self.seen
                .lock()
                .unwrap()
                .iter()
                .map(|raw| String::from_utf8_lossy(raw).into_owned())
                .collect()
        }
    }

    impl Drop for FakeOrigin {
        fn drop(&mut self) {
            self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
            if let Some(join) = self.join.take() {
                let _ = join.join();
            }
        }
    }

    /// One request (head plus its Content-Length body) as it arrived, or `None`
    /// if the peer closed first. Anything past the head that the client pipelined
    /// is kept, so a smuggled second request would show up here.
    fn read_one_request(s: &mut std::net::TcpStream) -> Option<Vec<u8>> {
        use std::io::Read;
        let mut raw = Vec::new();
        let mut chunk = [0u8; 512];
        while find_head_end(&raw).is_none() {
            match s.read(&mut chunk) {
                Ok(0) | Err(_) => return None,
                Ok(n) => raw.extend_from_slice(&chunk[..n]),
            }
            if raw.len() > 64 * 1024 {
                return None;
            }
        }
        let head_end = find_head_end(&raw).unwrap();
        let head = String::from_utf8_lossy(&raw[..head_end]).into_owned();
        let want = content_length(&head).unwrap_or(0);
        while raw.len() < head_end + want {
            match s.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(n) => raw.extend_from_slice(&chunk[..n]),
            }
        }
        Some(raw)
    }

    #[test]
    fn sandbox_unknown_path_is_404() {
        let (dialog, _c) = recording_dialog(Ok(deny_once_result()));
        let t = t36_setup("sandbox-404", &[], &[], dialog);
        let resp = exchange(t.port, &get_req("/sandbox/other"));
        assert!(resp.starts_with("HTTP/1.1 404"), "got: {resp}");
    }

    #[test]
    fn connect_dns_failure_after_admission_is_fail_closed() {
        let (dialog, calls) = recording_dialog(Ok(allow_once()));
        // `*.invalid` can never resolve (RFC 6761): admission passes via
        // the allow-list, then the pinned resolution fails → fail-closed
        // 403 with an audit event sourced "dns" ([G-12]).
        let t = t36_setup("dns-fail", &["*.invalid"], &[], dialog);
        let resp = exchange(t.port, &connect_req("nx.invalid:443"));
        assert!(resp.starts_with("HTTP/1.1 403"), "got: {resp}");
        assert!(resp.contains("X-Sandbox: denied"), "got: {resp}");
        assert!(calls.lock().unwrap().is_empty());
        let ev = last_connect_event(&t.sid);
        assert_eq!(ev["source"], "dns");
    }

    #[test]
    fn intent_wrong_method_gets_405_with_allow() {
        let (dialog, _c) = recording_dialog(Ok(deny_once_result()));
        let t = t36_setup("intent-405", &[], &[], dialog);
        let resp = exchange(t.port, &http_req("PUT", "/sandbox/intent", false, "{}"));
        assert!(resp.starts_with("HTTP/1.1 405"), "got: {resp}");
        assert!(resp.contains("Allow: GET, POST"), "got: {resp}");
        let resp = exchange(t.port, &get_req("/sandbox/intent/explain"));
        assert!(resp.starts_with("HTTP/1.1 405"), "got: {resp}");
        assert!(resp.contains("Allow: POST"), "got: {resp}");
    }

    // =================================================================
    // Task 4.2 — upstream chaining (D-2): [G-10, G-22, G-30, G-49]
    // =================================================================

    /// Read one HTTP head (through CRLFCRLF) a byte at a time, so no byte
    /// of a following tunnel is consumed.
    fn read_head(s: &mut std::net::TcpStream) -> String {
        use std::io::Read;
        let mut out: Vec<u8> = Vec::new();
        let mut b = [0u8; 1];
        loop {
            match s.read(&mut b) {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    out.push(b[0]);
                    if out.ends_with(b"\r\n\r\n") || out.len() >= 8192 {
                        break;
                    }
                }
            }
        }
        String::from_utf8_lossy(&out).into_owned()
    }

    /// A fake upstream proxy: answers each CONNECT head with `status` (200 =
    /// established + echoing tunnel; anything else = refused CONNECT) and
    /// records every head it saw. The accept loop is non-blocking behind a
    /// stop flag so the thread never outlives the test.
    struct FakeUpstream {
        port: u16,
        seen: Arc<StdMutex<Vec<String>>>,
        stop: Arc<std::sync::atomic::AtomicBool>,
        join: Option<std::thread::JoinHandle<()>>,
    }

    impl FakeUpstream {
        fn start(status: u16) -> FakeUpstream {
            use std::io::{Read, Write};
            use std::sync::atomic::Ordering;
            let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind fake upstream");
            let port = l.local_addr().unwrap().port();
            l.set_nonblocking(true).unwrap();
            let seen = Arc::new(StdMutex::new(Vec::new()));
            let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let seen_t = Arc::clone(&seen);
            let stop_t = Arc::clone(&stop);
            let join = std::thread::spawn(move || {
                while !stop_t.load(Ordering::SeqCst) {
                    let Ok((mut s, _)) = l.accept() else {
                        std::thread::sleep(Duration::from_millis(5));
                        continue;
                    };
                    // Windows hands back an accepted socket in the
                    // listener's non-blocking mode; the echo loop needs
                    // blocking reads.
                    s.set_nonblocking(false).ok();
                    s.set_read_timeout(Some(Duration::from_secs(10))).ok();
                    let head = read_head(&mut s);
                    if head.is_empty() {
                        continue;
                    }
                    seen_t.lock().unwrap().push(head);
                    let resp = if status == 200 {
                        "HTTP/1.1 200 Connection Established\r\n\r\n"
                    } else {
                        "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"
                    };
                    if s.write_all(resp.as_bytes()).is_err() || status != 200 {
                        continue;
                    }
                    // Echo the tunnel until the peer closes it.
                    let mut buf = [0u8; 4096];
                    loop {
                        match s.read(&mut buf) {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if s.write_all(&buf[..n]).is_err() {
                                    break;
                                }
                            }
                        }
                    }
                }
            });
            FakeUpstream {
                port,
                seen,
                stop,
                join: Some(join),
            }
        }

        /// `http://127.0.0.1:<port>` — no credentials.
        fn url(&self) -> String {
            format!("http://127.0.0.1:{}", self.port)
        }

        /// The same endpoint with userinfo, for the [G-30] redaction tests.
        fn cred_url(&self) -> String {
            format!("http://alice:s3cret@127.0.0.1:{}", self.port)
        }

        fn heads(&self) -> Vec<String> {
            self.seen.lock().unwrap().clone()
        }
    }

    impl Drop for FakeUpstream {
        fn drop(&mut self) {
            self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
            if let Some(j) = self.join.take() {
                let _ = j.join();
            }
        }
    }

    /// CONNECT through the test proxy; on a 2xx head send `payload` through
    /// the tunnel and read the echo back. Returns `(head, echo)` — `echo` is
    /// empty when the proxy did not establish a tunnel.
    fn tunnel(port: u16, target: &str, payload: &[u8]) -> (String, String) {
        use std::io::{Read, Write};
        let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).expect("connect test proxy");
        s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        s.set_write_timeout(Some(Duration::from_secs(10))).unwrap();
        s.write_all(connect_req(target).as_bytes()).unwrap();
        let head = read_head(&mut s);
        if !head.starts_with("HTTP/1.1 2") {
            return (head, String::new());
        }
        s.write_all(payload).unwrap();
        let mut echo = vec![0u8; payload.len()];
        s.read_exact(&mut echo).expect("tunnel echo");
        (head, String::from_utf8_lossy(&echo).into_owned())
    }

    /// A chaining dialer over `url` with the given `NO_PROXY` entries.
    fn dialer(url: &str, no_proxy: &[&str]) -> Arc<UpstreamDialer> {
        Arc::new(
            UpstreamDialer::from_url(url, no_proxy.iter().map(|s| s.to_string()).collect())
                .expect("test upstream url parses"),
        )
    }

    /// A loopback port nothing listens on: 1 is reserved for tcpmux and never
    /// bound by the toolchain, so `connect` is refused at once — no
    /// bind-then-drop TOCTOU window (a race that could hand the port to
    /// something else between `drop` and the dial).
    const DEAD_PORT: u16 = 1;

    /// The 3.6 fixture with an optional upstream dialer.
    fn t42_setup(label: &str, allow: &[&str], upstream: Option<Arc<UpstreamDialer>>) -> T36 {
        let (dialog, _calls) = recording_dialog(Ok(deny_once_result()));
        t36_setup_cfg(
            label,
            allow,
            &[],
            dialog,
            true,
            Duration::from_secs(60),
            PromptPolicy::Deny,
            upstream,
        )
    }

    // (a) admission → chained CONNECT → the tunnel round-trips.
    #[test]
    fn chained_connect_tunnels_through_upstream_proxy() {
        let fake = FakeUpstream::start(200);
        let t = t42_setup(
            "chain-ok",
            &["api.example.com"],
            Some(dialer(&fake.cred_url(), &[])),
        );
        let (head, echo) = tunnel(t.port, "api.example.com:443", b"hello through the tunnel");
        assert!(head.starts_with("HTTP/1.1 200"), "got: {head}");
        assert_eq!(echo, "hello through the tunnel");

        let heads = fake.heads();
        assert_eq!(heads.len(), 1, "exactly one upstream CONNECT");
        assert!(
            heads[0].starts_with("CONNECT api.example.com:443 HTTP/1.1"),
            "request line: {:?}",
            heads[0]
        );
        assert!(
            heads[0]
                .to_ascii_lowercase()
                .contains("host: api.example.com:443"),
            "Host header: {:?}",
            heads[0]
        );
        // Exact value, not a prefix: the header is `Basic base64(user:pass)`,
        // and a prefix-only check would still pass if the userinfo were
        // dropped on the floor.
        let expected = base64::engine::general_purpose::STANDARD.encode("alice:s3cret");
        assert!(
            heads[0].contains(&format!("Proxy-Authorization: Basic {expected}")),
            "auth header: {:?}",
            heads[0]
        );
        // [G-30] the cleartext userinfo never reaches the wire.
        assert!(
            !heads[0].contains("s3cret"),
            "leaked password: {:?}",
            heads[0]
        );

        let ev = last_connect_event(&t.sid);
        assert_eq!(ev["disposition"], "allow");
        assert_eq!(ev["source"], "allowlist");
    }

    // (b) [G-11, G-49] a NO_PROXY match dials direct: the upstream proxy is
    // never contacted. De-flaked per 3.6: the target is unresolvable here, so
    // the direct leg normally ends in the fail-closed 403, but a resolver that
    // hijacks `.invalid` (some captive/ISP resolvers do) turns it into a
    // direct 502. Both are direct-path outcomes; the security property is
    // "nothing chained", so neither may look like an upstream failure.
    #[test]
    fn no_proxy_match_dials_direct_and_never_contacts_upstream() {
        let fake = FakeUpstream::start(200);
        let t = t42_setup(
            "chain-bypass",
            &["bypass.invalid"],
            Some(dialer(&fake.url(), &["bypass.invalid"])),
        );
        let resp = exchange(t.port, &connect_req("bypass.invalid:443"));
        assert!(
            !resp.contains("X-Sandbox: upstream-error"),
            "a NO_PROXY host must never chain: {resp}"
        );
        assert!(
            fake.heads().is_empty(),
            "NO_PROXY host must never reach the upstream proxy"
        );
        let ev = last_connect_event(&t.sid);
        if resp.starts_with("HTTP/1.1 403") {
            // The un-hijacked case: fail-closed DNS denial.
            assert_eq!(ev["source"], "dns");
        } else {
            assert!(
                resp.starts_with("HTTP/1.1 502"),
                "direct leg expected (403 dns-deny or 502 dial failure): {resp}"
            );
            // The bare 502 adds no leaf, so the admission allow is last.
            assert_eq!(ev["source"], "allowlist");
            assert_eq!(ev["disposition"], "allow");
        }
    }

    // (c) [G-30] upstream unreachable → 502 + X-Sandbox: upstream-error.
    #[test]
    fn upstream_unreachable_returns_502_with_upstream_error_header() {
        let port = DEAD_PORT;
        let t = t42_setup(
            "chain-dead",
            &["api.example.com"],
            Some(dialer(
                &format!("http://alice:s3cret@127.0.0.1:{port}"),
                &[],
            )),
        );
        let resp = exchange(t.port, &connect_req("api.example.com:443"));
        assert!(resp.starts_with("HTTP/1.1 502 Bad Gateway"), "got: {resp}");
        assert!(resp.contains("X-Sandbox: upstream-error"), "got: {resp}");
        assert!(
            resp.contains(&format!("127.0.0.1:{port}")),
            "body must name the proxy host:port: {resp}"
        );
        for secret in ["alice", "s3cret", "@"] {
            assert!(!resp.contains(secret), "body leaked {secret:?}: {resp}");
        }
        let ev = last_connect_event(&t.sid);
        assert_eq!(ev["disposition"], "deny");
        assert_eq!(ev["source"], "default");
        assert_eq!(ev["reason"], "upstream_error");
        // Two leaves: the admission `allow` (emitted before the dial) and then
        // the `upstream_error` denial. The direct 502 path emits only the
        // admission leaf — chained failures are the two-event shape.
        let evs = connect_events(&t.sid);
        assert_eq!(evs.len(), 2, "expected admission + upstream_error: {evs:?}");
        assert_eq!(evs[0]["disposition"], "allow");
        assert_eq!(evs[0]["source"], "allowlist");
    }

    // (d) a non-2xx answer to the chained CONNECT maps to the same 502.
    #[test]
    fn upstream_non_200_returns_502_with_upstream_error_header() {
        let fake = FakeUpstream::start(403);
        let t = t42_setup(
            "chain-403",
            &["api.example.com"],
            Some(dialer(&fake.cred_url(), &[])),
        );
        let resp = exchange(t.port, &connect_req("api.example.com:443"));
        assert!(resp.starts_with("HTTP/1.1 502 Bad Gateway"), "got: {resp}");
        assert!(resp.contains("X-Sandbox: upstream-error"), "got: {resp}");
        assert!(
            resp.contains(&format!("127.0.0.1:{}", fake.port)),
            "body must name the proxy host:port: {resp}"
        );
        assert!(resp.contains("403"), "body should carry the status: {resp}");
        assert!(!resp.contains("s3cret"), "leaked password: {resp}");
        assert_eq!(fake.heads().len(), 1);
        let ev = last_connect_event(&t.sid);
        assert_eq!(ev["source"], "default");
        assert_eq!(ev["reason"], "upstream_error");
    }

    // (e) [G-22] chaining is hostname-only: a name that cannot resolve
    // locally still tunnels, because the upstream proxy does the DNS.
    #[test]
    fn chained_path_skips_local_dns_resolution() {
        let fake = FakeUpstream::start(200);
        let t = t42_setup(
            "chain-no-dns",
            &["*.invalid"],
            Some(dialer(&fake.url(), &[])),
        );
        let (head, echo) = tunnel(t.port, "nx-4-2.invalid:443", b"hostname-only");
        assert!(head.starts_with("HTTP/1.1 200"), "got: {head}");
        assert_eq!(echo, "hostname-only");
        let heads = fake.heads();
        assert_eq!(heads.len(), 1);
        assert!(
            heads[0].starts_with("CONNECT nx-4-2.invalid:443 HTTP/1.1"),
            "the hostname (not an IP) is what chains: {:?}",
            heads[0]
        );
    }

    // (e') the same hostname with no upstream configured dials directly — the
    // contrast that proves (e) skipped local DNS. De-flaked like (b): a
    // resolver that hijacks `.invalid` makes the direct dial succeed, so the
    // pinned property is "never chained", not a single status code.
    #[test]
    fn direct_path_dns_failure_fails_closed() {
        let t = t42_setup("direct-no-dns", &["*.invalid"], None);
        let resp = exchange(t.port, &connect_req("nx-4-2.invalid:443"));
        assert!(
            !resp.contains("X-Sandbox: upstream-error"),
            "no upstream is configured, so nothing may chain: {resp}"
        );
        match resp.split_whitespace().nth(1) {
            Some("403") => {
                assert!(resp.contains("X-Sandbox: denied"), "got: {resp}");
                assert_eq!(last_connect_event(&t.sid)["source"], "dns");
            }
            // Hijacked resolver: the direct leg completed (200) or failed to
            // connect (502). Neither is a chained request.
            Some("200") | Some("502") => {}
            other => panic!("unexpected CONNECT answer {other:?} in: {resp}"),
        }
    }

    // (f) [G-22] the hostname hard-deny still runs before chaining.
    #[test]
    fn hard_deny_hostname_wins_on_chained_path() {
        let fake = FakeUpstream::start(200);
        let t = t42_setup("chain-hard-deny-name", &[], Some(dialer(&fake.url(), &[])));
        let resp = exchange(t.port, &connect_req("metadata.google.internal:80"));
        assert!(resp.starts_with("HTTP/1.1 403"), "got: {resp}");
        assert!(fake.heads().is_empty(), "hard-deny must not chain");
        let ev = last_connect_event(&t.sid);
        assert_eq!(ev["source"], "hard-deny");
        assert_eq!(ev["reason"], "denied_dns");
    }

    // (g) [G-22] the IP-literal hard-deny still runs before chaining.
    #[test]
    fn hard_deny_ip_literal_wins_on_chained_path() {
        let fake = FakeUpstream::start(200);
        let t = t42_setup("chain-hard-deny-ip", &[], Some(dialer(&fake.url(), &[])));
        let resp = exchange(t.port, &connect_req("169.254.169.253:80"));
        assert!(resp.starts_with("HTTP/1.1 403"), "got: {resp}");
        assert!(fake.heads().is_empty(), "hard-deny must not chain");
        let ev = last_connect_event(&t.sid);
        assert_eq!(ev["source"], "hard-deny");
        assert_eq!(ev["reason"], "denied_cidr");
    }

    // (h) bracketed IPv6 target: `parse_connect_target` keeps the brackets,
    // the chained dial must strip them (else `host_port` emits `[[::1]]`).
    #[test]
    fn chained_bracketed_ipv6_target_is_unbracketed_for_the_dial() {
        let fake = FakeUpstream::start(200);
        let t = t42_setup(
            "chain-ipv6",
            &["[2606:4700::1111]"],
            Some(dialer(&fake.url(), &[])),
        );
        let (head, _echo) = tunnel(t.port, "[2606:4700::1111]:443", b"v6");
        assert!(head.starts_with("HTTP/1.1 200"), "got: {head}");
        let heads = fake.heads();
        assert_eq!(heads.len(), 1);
        assert!(
            heads[0].starts_with("CONNECT [2606:4700::1111]:443 HTTP/1.1"),
            "exactly one bracket pair: {:?}",
            heads[0]
        );
    }

    // (i) [G-11, B1] a conventional *bare* IPv6 `NO_PROXY` entry must bypass
    // the upstream for a bracketed CONNECT target. `parse_connect_target`
    // keeps the brackets, so the decision point has to normalize the host
    // once: otherwise `chains_host` misses, the bypass only fires inside
    // `UpstreamDialer::dial`'s own re-check, and that call dials the direct
    // path with no pinned addresses — reporting a proxy that was never
    // contacted as unreachable (502 + a spurious `upstream_error` leaf).
    #[test]
    fn bare_ipv6_no_proxy_entry_bypasses_upstream_for_a_bracketed_target() {
        let fake = FakeUpstream::start(200);
        let t = t42_setup(
            "chain-v6-bare-noproxy",
            &["[::]"],
            Some(dialer(&fake.url(), &["::"])),
        );
        // `::` is the unspecified address: nothing can route to it, so the
        // direct leg fails at once and the test needs no external network.
        let resp = exchange(t.port, &connect_req("[::]:443"));
        assert!(
            !resp.contains("X-Sandbox: upstream-error"),
            "the NO_PROXY bypass must win before any chaining: {resp}"
        );
        assert!(
            fake.heads().is_empty(),
            "the upstream proxy must never be contacted: {:?}",
            fake.heads()
        );
        let evs = connect_events(&t.sid);
        assert_eq!(evs.len(), 1, "only the admission leaf: {evs:?}");
        assert_eq!(evs[0]["disposition"], "allow");
        assert_eq!(evs[0]["source"], "allowlist");
    }

    // (i') the bracket form of the same entry keeps working: entries are
    // normalized to the bare host when the dialer is built, so both spellings
    // of an IPv6 bypass agree with the single normalized host.
    #[test]
    fn bracketed_ipv6_no_proxy_entry_still_bypasses_the_upstream() {
        let fake = FakeUpstream::start(200);
        let t = t42_setup(
            "chain-v6-bracketed-noproxy",
            &["[::]"],
            Some(dialer(&fake.url(), &["[::]"])),
        );
        let resp = exchange(t.port, &connect_req("[::]:443"));
        assert!(
            !resp.contains("X-Sandbox: upstream-error"),
            "a bracketed NO_PROXY entry must bypass as well: {resp}"
        );
        assert!(
            fake.heads().is_empty(),
            "the upstream proxy must never be contacted: {:?}",
            fake.heads()
        );
        assert_eq!(connect_events(&t.sid).len(), 1);
    }

    // =================================================================
    // Task 4.4 — tunnel half-close: the client's EOF must reach the
    // upstream as a FIN.
    //
    // Regression for the 4.2 review's live hang (S-83): the split +
    // `join!(copy, copy)` tunnel never shut down the other side's write
    // half, so a client that closed left `copy(upstream → client)` parked
    // forever against a keep-alive upstream — one leaked task and two leaked
    // fds per request. With `copy_bidirectional` the FIN propagates, the
    // upstream answers with its own EOF, and the handler returns.
    // =================================================================

    /// Async fake upstream proxy for the half-close test: answers the
    /// CONNECT with `200`, echoes until it reads EOF, then closes and
    /// resolves with the number of bytes it echoed. The head is read one
    /// byte at a time so no tunnel byte is swallowed by the CONNECT parse.
    async fn echoing_upstream_until_eof() -> (u16, tokio::task::JoinHandle<usize>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake upstream");
        let port = listener.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.expect("accept fake upstream");
            let mut head = Vec::new();
            let mut one = [0u8; 1];
            loop {
                if s.read(&mut one).await.unwrap_or(0) == 0 {
                    return 0;
                }
                head.push(one[0]);
                if head.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            s.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .expect("write fake 200");
            let mut echoed = 0usize;
            let mut buf = [0u8; 4096];
            loop {
                match s.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        echoed += n;
                        if s.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                }
            }
            echoed
        });
        (port, task)
    }

    /// Minimal `ConnCtx` for a chained tunnel test: `api.example.com` is
    /// allow-listed (so the prompt is never consulted), and the upstream
    /// dialer points at the fake proxy above. Returns the scratch dir too
    /// so the caller can drop it with the context.
    fn tunnel_ctx(label: &str, upstream_port: u16) -> (Arc<ConnCtx>, std::path::PathBuf) {
        let base = std::env::temp_dir().join(format!("sandbox-t44-{}", temp_sid(label)));
        std::fs::create_dir_all(&base).unwrap();
        let (dialog, _calls) = recording_dialog(Ok(deny_once_result()));
        let prompt = PromptGate {
            enabled: false,
            config: PromptConfig {
                timeout: Duration::from_secs(1),
                on_unavailable: PromptPolicy::Deny,
            },
            coordinator: Arc::new(PromptCoordinator::with_dialog(dialog)),
            intent: Arc::new(IntentRegistry::new(DEFAULT_TTL)),
            learned: Arc::new(StdMutex::new(
                LearnedStore::load_in(&base, Some("t44")).expect("empty learned store"),
            )),
        };
        let sid = temp_sid(label);
        let writer = Arc::new(crate::audit::AuditWriter::open(&sid, false).unwrap());
        let ctx = Arc::new(ConnCtx {
            token: RunToken::for_tests(TEST_TOKEN),
            deny: Vec::new(),
            allow: vec!["api.example.com".to_string()],
            writer,
            upstream: Some(dialer(&format!("http://127.0.0.1:{upstream_port}"), &[])),
            prompt,
            counters: LaunchCounters::new(),
            no_token: super::RefusalBudget::new(),
            foreign_token: super::RefusalBudget::new(),
        });
        (ctx, base)
    }

    /// The 4.4 regression: after the client closes its socket the handler
    /// must finish promptly, and only if the EOF crossed the tunnel does the
    /// upstream's read-EOF-terminated loop end.
    #[tokio::test]
    async fn client_eof_reaches_the_upstream_and_the_handler_finishes() {
        let (upstream_port, upstream_task) = echoing_upstream_until_eof().await;
        let (ctx, _base) = tunnel_ctx("half-close", upstream_port);

        // The production accept loop hands `handle_conn` one end of a
        // loopback socket; this listener provides exactly that pair.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_port = listener.local_addr().unwrap().port();

        let client = tokio::spawn(async move {
            let mut s = TcpStream::connect(("127.0.0.1", proxy_port))
                .await
                .expect("connect handler socket");
            s.write_all(connect_req("api.example.com:443").as_bytes())
                .await
                .unwrap();
            let mut head = Vec::new();
            let mut one = [0u8; 1];
            loop {
                if s.read(&mut one).await.unwrap_or(0) == 0 {
                    break;
                }
                head.push(one[0]);
                if head.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            let payload = b"half-close payload";
            s.write_all(payload).await.unwrap();
            let mut echoed = vec![0u8; payload.len()];
            s.read_exact(&mut echoed).await.unwrap();
            // Close the client socket outright — no explicit shutdown, no
            // lingering write half. The handler has to forward this EOF.
            drop(s);
            (String::from_utf8_lossy(&head).into_owned(), echoed)
        });

        let (server, _peer) = listener.accept().await.unwrap();
        let handled = tokio::time::timeout(Duration::from_secs(2), handle_conn(server, ctx)).await;
        assert!(
            handled.is_ok(),
            "handle_conn was still running 2s after the client closed: the client EOF \
             never reached the upstream write half, so a keep-alive upstream parks the \
             handler (and two fds) forever"
        );

        let (head, echoed) = client.await.expect("client task");
        assert!(head.starts_with("HTTP/1.1 200"), "got: {head}");
        assert_eq!(
            echoed,
            b"half-close payload".to_vec(),
            "payload must round-trip before the close"
        );

        // The fake upstream's loop ends only on read-EOF, so a task that
        // resolves proves the FIN crossed the tunnel (and echoes the count).
        let echoed_upstream = tokio::time::timeout(Duration::from_secs(2), upstream_task)
            .await
            .expect("fake upstream never observed the tunnel's EOF")
            .expect("fake upstream task panicked");
        assert_eq!(echoed_upstream, b"half-close payload".len());
    }
}
