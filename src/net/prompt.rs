//! Interactive network prompt dialog (ADR-0001 §D-3, Task 3.5).
//!
//! Port of omac's `internal/netprompt/prompt.go` to the Windows-feasible
//! equivalent: a native `TaskDialogIndirect` prompt (Common Controls v6,
//! Win7+) fired from the proxy path, plus a fire-and-forget toast as the
//! secondary alert ([G-2, G-3]).
//!
//! # Seven custom buttons
//!
//! The ADR's six DECISION buttons ([G-3, G-43]): `Allow once`,
//! `Allow permanently (this host)`, `Allow permanently (*.{suffix})`,
//! `Deny once` (DEFAULT), `Deny permanently (this host)`,
//! `Deny permanently (*.{suffix})` — the suffix hint appears in the button
//! label itself. Derivation for the seventh (`Explain more`): the ADR pins
//! six buttons, but D-4/G-26 (explain-more one-shot flag) and Task 3.4's
//! `IntentRegistry` need a way for the user to ask the agent for intent,
//! and Task 3.6 branches on [`PromptResult::NeedsIntent`] (403 +
//! `X-Sandbox-Intent-Hint`). omac's dialog carries an ELEVENTH option
//! `"Explain more"` → token `needs_intent` → `PromptResult{NeedsIntent:
//! true}` → `recordExplainMore(host)`. We adopt that option; omac's
//! session-scoped options are deliberately NOT ported (the ADR dropped
//! them). Dialog cancel / X / Esc maps to `Deny once` ([G-3, G-43]).
//!
//! # Dialog content, focus, toast
//!
//! Content ([G-17]): `host:port` on the first line and, *if* a reason is
//! passed, a second line `Agent reason: "<reason>"` (quoted, verbatim) in
//! the multi-line `pszContent`; no reason → line omitted. Display-safety
//! (review A4): every user-visible string derived from LLM-influenced
//! input — the reason, the host, the suffix hints in button labels —
//! passes through `display_safe`: `\r\n` collapses to a single space,
//! other control characters (interior NUL included) are stripped, and
//! the length is capped at 1024 chars. Same rationale as omac's
//! `escapePangoMarkup` ("collapse newlines first so a fake 'Origin: …'
//! line cannot be injected"): an embedded newline must not fake an
//! extra `Agent reason:` line. [G-17]'s "verbatim" is preserved
//! semantically — only control characters are removed and the length
//! bounded — and the wired path already caps the reason at 500 chars
//! via the intent registry (D-4). No PID
//! attribution ([G-23]). Focus ([G-37]): the dialog is created
//! foreground-activated with input focus — no `TDF_NO_FOCUS` is set
//! (UAC-like behavior). Toast ([G-2, G-3]): fired fire-and-forget on a
//! separate thread; every error swallowed. An unpackaged console app has
//! no registered AUMID of its own, so the toast borrows PowerShell's
//! (registered via its Start Menu shortcut on stock Windows) —
//! best-effort, may no-op.
//!
//! # Concurrency: coalescing, semaphore, timeout
//!
//! Coalescing ([G-6]): concurrent requests for the same host share one
//! dialog, keyed by normalized hostname only (port ignored). The plan's
//! literal type (`oneshot` in a map) is single-consumer and cannot fan
//! one result out to many waiters; the semantics — single dialog per
//! host, all same-host waiters receive the leader's outcome — are kept
//! with a per-host waiter list (pre-authorized deviation). Only the
//! *leader* takes a semaphore permit; followers never do.
//!
//! Capacities ([G-28]): **two pools, not one.** "At most 8 concurrent
//! prompts" was true of the *consultations* the proxy is blocked on
//! ([`MAX_CONCURRENT_PROMPTS`]); a 9th prompt for a NEW host is refused
//! immediately ([`PromptOutcome::Overloaded`], audited as source
//! `prompt_overload` by 3.6). It was never the number of live windows: a
//! dialog that outlives its budget is abandoned — still on screen, still
//! blocking a thread — and keeps a permit from [`MAX_ABANDONED_PROMPTS`]
//! (16) until its call returns, so **live dialogs are bounded by 16 and
//! consultations by 8** — every dialog holds an abandoned permit for its whole
//! life, which is what makes that second number the bound on windows. Two pools is what lets a timed-out consultation
//! give its slot back (P2.1: an orphaned dialog used to keep it for the life of
//! the process, and eight headless timeouts wedged the whole path into
//! permanent `Overloaded`) without licensing unbounded windows. The refusal
//! names which pool ran out ([`OverloadCause`]).
//!
//! Fast-fail ([P2.1 review]): a session that has had
//! [`NO_BACKEND_STICKY_AFTER`] consecutive consultations produce no decision —
//! no dialog backend, or a budget that elapsed with the dialog unanswered, which
//! is what a dialog with nobody at the desktop looks like — concludes that no
//! answer is obtainable here and stops showing dialogs, applying
//! `on_unavailable` immediately (audited `no_dialog_backend`, one leaf per
//! request). Otherwise every unlisted host in a headless run costs the client
//! the whole prompt budget.
//!
//! Timeout ([G-46], [G-4]): the async caller awaits the blocking dialog
//! under `tokio::time::timeout` (plan Steps 3/6). A `timeout` of
//! [`Duration::ZERO`] means "instant deny": no dialog is attempted and no
//! coalescing entry is created (equivalent to `--no-prompt`, audited as
//! source `default` by 3.6). A positive timeout that fires — or any
//! dialog backend failure ([G-19]) — yields [`PromptOutcome::Unavailable`]
//! with the `on_unavailable` policy applied: a missed prompt never
//! defaults to allow unless the policy explicitly says so. The orphaned
//! dialog keeps running on screen; its late click result is discarded
//! ([G-4]).
//!
//! # Caller-drop safety (review blocking fix)
//!
//! The leader's cleanup (entry removal + follower fan-out) is owned by
//! a detached supervisor task, never by the caller's future: `prompt()`
//! merely awaits the supervisor's report over a oneshot. Dropping the
//! caller's future mid-prompt — the routine proxy case: the agent
//! process is killed or the client disconnects while the dialog is up —
//! detaches the blocking dialog task (it keeps running, [G-4]; its
//! late result is discarded) but never strands the host's coalescing
//! entry: the supervisor notices the dropped report receiver, removes
//! the entry and fans the `on_unavailable` outcome out to parked
//! followers, so the next same-host request elects a fresh leader
//! instead of parking until its own timeout. Cleanup runs exactly once
//! (one `select!` branch), so there is no double fan-out.
//!
//! # Suffix hints and loopback
//!
//! [`compute_suffix_hint`] ([G-43]): host with the leftmost label removed
//! when ≥3 dot-separated labels, else the host; IP literals are never
//! generalized. omac uses publicsuffix/eTLD+1 — the ADR deliberately
//! simplified to the label-count rule (no PSL dependency).
//! [`is_loopback_host`]: `localhost`, `*.localhost`, `127.0.0.1`, `::1`
//! and any IP that parses as loopback — the proxy refuses loopback
//! CONNECT *before* prompting (3.6 wiring).
//!
//! # Design notes / deviations (pre-authorized)
//!
//! - `windows` 0.62 features added: `Win32_UI_Controls` (TaskDialog
//!   types), `UI_Notifications` (WinRT toast — the plan's name was
//!   exact; a `Win32_UI_Notifications` variant does not exist in 0.62),
//!   `Data_Xml_Dom` (`XmlDocument` for the toast payload),
//!   `Win32_System_Com` (`CoInitializeEx` — TaskDialogIndirect wants
//!   COM on its thread), `Win32_UI_WindowsAndMessaging` (gates the
//!   TaskDialog types in 0.62 metadata),
//!   `Win32_System_ApplicationInstallationAndServicing` +
//!   `Win32_System_LibraryLoader` (see the next point).
//! - `TaskDialogIndirect` is resolved at RUNTIME (`LoadLibraryW` +
//!   `GetProcAddress` inside a Common-Controls-v6 activation context
//!   built from a generated `%TEMP%` manifest), NOT via the crate's
//!   static import. The saife binary embeds no manifest (adding one
//!   needs a build.rs, outside this task's file set), so a static
//!   comctl32 import resolves against the in-box **v5** DLL and the
//!   whole exe then fails to load with STATUS_ENTRYPOINT_NOT_FOUND —
//!   observed live. Resolution runs ONCE PER PROCESS (review A1) into
//!   a `OnceLock`-cached (actctx handle, HMODULE, fn pointer); the
//!   module is NEVER freed afterwards (`TaskDialogIndirect` registers
//!   module-owned window classes — an unload/reload cycle between
//!   dialogs is the classic 2nd-dialog crash zone), and per dialog
//!   call only the per-thread activation is redone
//!   (`ActivateActCtx` → call → `DeactivateActCtx`; the handle is
//!   thread-agnostic). The context is created via `CreateActCtxW`
//!   with a real UTF-16 path (review A2: the ANSI `CreateActCtxA`
//!   mis-encodes a non-ASCII %TEMP%, e.g. an umlaut username, into a
//!   permanent DialogUnavailable). A resolution failure is cached once
//!   too: a host that cannot show dialogs cannot show dialogs. Any
//!   failure here is a clean [`DialogUnavailable`] → `on_unavailable`
//!   policy ([G-19]).
//! - Accepted quirks (review checkpoint notes): the courtesy toast is
//!   fired BEFORE the dialog backend resolution is known-good —
//!   purely cosmetic, the toast is [G-2] best-effort and may no-op
//!   anyway; a resolution failure still yields [`DialogUnavailable`]
//!   → policy, only the toast was wasted. The `%TEMP%` manifest is
//!   written once per process (per-pid file name) and deliberately
//!   never deleted; a delete-on-exit pass is a follow-up option, not
//!   part of this task.
//! - `show_dialog` returns `Result<PromptResult, DialogUnavailable>`
//!   instead of the plan's bare `PromptResult`: a bare result would
//!   conflate a backend failure with a user-clicked deny, and 3.6 must
//!   distinguish them (source `unavailable` vs `prompt`, [G-19]).
//! - `PromptResult`/`Outcome`/config types derive `Debug + Clone +
//!   PartialEq` for test ergonomics.
//!
//! # Task 3.6 wiring notes
//!
//! - Hold the [`PromptCoordinator`] as an `Arc` shared by all proxy
//!   handlers; call `prompt(host, port, reason, config)` only for hosts
//!   that passed hard-deny/blocklist/allowlist/learned checks and are
//!   not loopback.
//! - `Decided(Allow { persist: true, scope, suffix })` →
//!   `learned.record(host, scope, allow=true)`; `Decided(Deny { persist:
//!   true, .. })` → same with `allow=false`. Non-persisting decisions
//!   are applied to the single request only.
//! - `Decided(NeedsIntent)` → 403 + `X-Sandbox-Intent-Hint` header +
//!   `intent.mark_explain_more(host)`; audit source `prompt`.
//! - `Overloaded` → 403, audit source `prompt_overload`.
//! - `Unavailable { allowed }` → apply the disposition, audit source
//!   `unavailable`; `Disabled` (zero timeout) → 403, source `default`.
//! - [G-19] first-denial diagnostic: on the FIRST
//!   `Unavailable { allowed: false }`, emit a discoverable one-line
//!   `SAIFE_DIAG` stderr diagnostic (ADR D-3): "no dialog backend
//!   available; all non-allow-listed hosts denied; use `--allow-domain`
//!   or `--network-profile` to pre-approve, or set
//!   `on_unavailable=allow` (insecure)".
//! - `network.promptEnabled` / `--no-prompt` gating ([G-36, G-47]) must
//!   be checked BEFORE calling the coordinator: this module only models
//!   the zero-timeout form (`timeout == 0` → [`PromptOutcome::Disabled`],
//!   audit source `default`); when prompting is disabled outright, 3.6
//!   must not construct a coordinator call at all.
//! - Consider including a live-dialog count in prompt audit events:
//!   dialogs the coordinator stopped waiting on stay up until their
//!   blocking call returns ([G-4]) and hold a permit from
//!   [`MAX_ABANDONED_PROMPTS`] — enough orphans and 3.6 reports
//!   `prompt_overload` while the visible dialogs are the abandoned ones;
//!   [`PromptCoordinator::abandoned_dialogs`] makes that state
//!   diagnosable.
//! - Intent timestamps in audit/registry responses are RFC3339.
//!
//! The module's API is not yet called from the release binary — the
//! proxy pipeline is wired in Task 3.6. Until then the module is
//! `#![allow(dead_code)]` to keep `cargo build --release` clean (same
//! posture as `learned.rs` / `intent.rs`); the coordinator logic is
//! fully exercised by the unit tests below via an injected fake dialog
//! (no test-util feature needed). The real `show_dialog`
//! (`TaskDialogIndirect`) cannot be unit-tested — it requires an
//! interactive desktop; the checkpoint covers it manually.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore, oneshot};
use windows::Data::Xml::Dom::XmlDocument;
use windows::UI::Notifications::{ToastNotification, ToastNotificationManager};
use windows::Win32::Foundation::{FreeLibrary, HANDLE, HMODULE, RPC_E_CHANGED_MODE};
use windows::Win32::System::ApplicationInstallationAndServicing::{
    ACTCTXW, ActivateActCtx, CreateActCtxW, DeactivateActCtx, ReleaseActCtx,
};
use windows::Win32::System::Com::{COINIT_APARTMENTTHREADED, CoInitializeEx, CoUninitialize};
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
use windows::Win32::UI::Controls::{
    TASKDIALOG_BUTTON, TASKDIALOGCONFIG, TDF_ALLOW_DIALOG_CANCELLATION, TDF_SIZE_TO_CONTENT,
    TDF_USE_COMMAND_LINKS,
};
use windows::core::{BOOL, HRESULT, HSTRING, PCWSTR, s, w};

/// Default prompt timeout in seconds ([G-46]; ADR field
/// `limits.promptTimeoutSecs`).
///
/// The number, in the unit the profile speaks, so the resolver
/// ([`crate::profile::LimitsSlice::resolve`]) can use the same constant as the
/// default it applies and the session budget can be sized from the resolved value
/// ([`crate::net::mxc::SessionBudget::from_config`]) rather than from a second
/// literal that could drift (P2.1 review, item 6).
pub const DEFAULT_PROMPT_TIMEOUT_SECS: u32 = 60;

/// Default prompt timeout as a [`Duration`]: [`DEFAULT_PROMPT_TIMEOUT_SECS`],
/// by construction.
pub const DEFAULT_PROMPT_TIMEOUT: Duration =
    Duration::from_secs(DEFAULT_PROMPT_TIMEOUT_SECS as u64);

/// Maximum number of concurrent **consultations** ([G-28]): dialogs the proxy
/// is waiting on, one per leader (coalesced followers never take a permit).
///
/// Not the number of live dialogs: an abandoned dialog is no longer consulted
/// with but is still a window, and it is bounded separately by
/// [`MAX_ABANDONED_PROMPTS`]. The session-wide bound on windows is the sum.
pub const MAX_CONCURRENT_PROMPTS: usize = 8;

/// Maximum number of dialogs that may be *abandoned* — still up after the
/// coordinator stopped waiting on them (P2.1).
///
/// [`MAX_CONCURRENT_PROMPTS`] bounds consultations in flight; a dialog that
/// outlives its budget is no longer one of those (its request was denied on
/// budget), but it is still a window and a blocking thread, so it may not be
/// unbounded either. Two pools rather than one is what makes both properties
/// true at once: slots return when a consultation ends, while live dialogs stay
/// capped. Sixteen is twice the consultation cap — enough that a session keeps
/// answering on budget long past the point where the *old* code wedged, and still
/// a hard bound, because the fallback when it is reached is a named `Overloaded`
/// denial ([G-28]), never an unbounded spawn. It is also the bound on LIVE
/// windows: every dialog holds a permit from this pool for its whole life, so the
/// session-wide number of dialogs is at most sixteen while only eight of them can
/// be consultations the proxy is blocked on.
///
/// **A backstop, not a routine state** (P2.1 review): with the fast-fail at
/// [`NO_BACKEND_STICKY_AFTER`] a DENY-posture session stops opening dialogs after
/// three consecutive consultations produced no decision, so a headless run cannot
/// fill this pool any more — that is the point of the fast-fail. It is still
/// reachable and still has to fail closed, because "cannot happen through that
/// path" is not "cannot happen": the fast-fail does not apply under
/// `on_unavailable = allow` (round 2, item 4), and a latch that has run out its
/// re-probe cooldown opens a dialog again (item 3).
pub const MAX_ABANDONED_PROMPTS: usize = 2 * MAX_CONCURRENT_PROMPTS;

/// How many consecutive consultations may run without a decision before the
/// coordinator stops asking (P2.1 review round 2, item 5).
///
/// **Why remembering is correct.** Whether a dialog can be answered at all is a
/// property of the *environment*, not of the request: a headless session (a
/// service window station, a VM guest with no interactive desktop) has nobody to
/// click, and the machine will not grow a desktop in the next 60 s. Before this,
/// every unlisted host cost the client the whole prompt budget — the D3
/// addendum's `curl -m 15` exit 28, one stall per host. After
/// [`NO_BACKEND_STICKY_AFTER`] consecutive consultations that produced no
/// decision (a backend failure, or a budget that elapsed with the dialog
/// unanswered), later consultations skip the dialog and apply the resolved
/// `on_unavailable` policy immediately.
///
/// **Three, not two** (round 2, item 5). Two consultations that run concurrently
/// start together and elapse at the same deadline, so "two in a row" could be ONE
/// budget's worth of evidence, and it left no grace consultation after the
/// second. Three consecutive observations tolerate two hiccups — a transient
/// COM/activation failure plus a saturated deadline — before a session concludes
/// nobody is at the desk. `observe` runs once per LEADER, so the three are three
/// distinct consultations.
///
/// **The trade, stated.** The cost is the mirror image of the saving: a real
/// desktop whose UI is lost (the dialog stops appearing) degrades to deny rather
/// than stalling the workload for a budget it cannot spend usefully. Refusing
/// fast is the fail-closed side of the same fact the policy already states — a
/// missed prompt never allows unless `onUnavailable` says so — and it applies
/// ONLY to the deny posture (item 4). Under `on_unavailable = allow` a skip would
/// silently *permit* every later unlisted host with no dialog at all, deleting the
/// user's veto, so that configuration keeps consulting and pays the per-host
/// budget: a headless + allow profile is the operator's explicit choice.
///
/// **It is not one-way** (item 3). Once armed nothing spawns a dialog, so the
/// `Decided` reset would be unreachable and an operator who came back and clicked
/// the still-open dialog would have their answer discarded, with no recovery but
/// restarting the run. After [`NO_BACKEND_REPROBE_COOLDOWN`] the next consultation
/// re-probes once: a working dialog un-arms the latch (a decision resets the
/// streak), a failing one re-arms it for another cooldown.
///
/// **It is LAUNCH-scoped, not listener-scoped** (item 2). The coordinator belongs
/// to a listener, and a listener can serve sequential launches — that is what the
/// P1.4 epoch machinery exists for. [`PromptCoordinator::begin_launch`] clears the
/// latch at every epoch open, so launch N's stalled prompts cannot deny every
/// prompt of launch N+1.
///
/// The refusal is named for what ARMED the latch (item 8): `no_dialog_backend`
/// when consecutive consultations found no dialog at all, and
/// `prompt_suppressed_after_budget` when they were budgets that elapsed with the
/// dialog up. Folding those back together is what made a session whose backend
/// demonstrably worked read as a machine with no desktop.
pub const NO_BACKEND_STICKY_AFTER: usize = 3;

/// How long an armed fast-fail waits before it consults a dialog again (P2.1
/// review round 2, item 3).
///
/// Ten minutes: long enough that a headless run does not pay a 60 s budget per
/// host once a minute, short enough that an operator who comes back gets prompts
/// back within one coffee instead of restarting the run. Tests pass a short one
/// through [`PromptCoordinator::with_cooldown`].
pub const NO_BACKEND_REPROBE_COOLDOWN: Duration = Duration::from_secs(600);

// Custom TaskDialog button ids: arbitrary nonzero values that must not
// collide with the reserved common-button ids (IDOK=1, IDCANCEL=2, ...).
const ID_ALLOW_ONCE: i32 = 101;
const ID_ALLOW_PERM_HOST: i32 = 102;
const ID_ALLOW_PERM_SUFFIX: i32 = 103;
const ID_DENY_ONCE: i32 = 104;
const ID_DENY_PERM_HOST: i32 = 105;
const ID_DENY_PERM_SUFFIX: i32 = 106;
const ID_ALLOW_SESSION: i32 = 108;
const ID_DENY_SESSION: i32 = 109;
const ID_EXPLAIN_MORE: i32 = 107;
/// `winuser.h` IDCANCEL, kept as a plain literal: windows-rs types the constant as
/// `MESSAGEBOX_RESULT`, while `TaskDialogIndirect` reports a plain button id. With
/// `TDF_ALLOW_DIALOG_CANCELLATION`, the title-bar X and Esc produce it
/// ([G-3, G-43]: cancel = Deny once).
#[allow(dead_code)] // referenced by the dialog-result tests
const IDCANCEL: i32 = 2;

/// What to do when the prompt cannot produce a user decision (timeout,
/// or no dialog backend) — ADR field `network.onUnavailable`
/// ([G-19, G-48]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PromptPolicy {
    /// Deny the request. Default ([G-48]).
    Deny,
    /// Allow the request (insecure; permissive CI).
    Allow,
}

/// Caller-supplied prompt behavior (ADR fields `limits.promptTimeoutSecs`
/// + `network.onUnavailable`), passed per call by the proxy ([G-46, G-48]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PromptConfig {
    /// How long to wait for the user before applying `on_unavailable`
    /// ([G-46]). `Duration::ZERO` means "instant deny": no dialog is
    /// attempted at all.
    pub timeout: Duration,
    /// Fallback disposition ([G-19, G-46]).
    pub on_unavailable: PromptPolicy,
}

impl Default for PromptConfig {
    /// 60s timeout, deny-on-unavailable ([G-46, G-48]).
    fn default() -> Self {
        Self {
            timeout: DEFAULT_PROMPT_TIMEOUT,
            on_unavailable: PromptPolicy::Deny,
        }
    }
}

/// One user decision from the dialog ([G-3, G-43]).
///
/// `scope` is `"host"` or `"suffix"` — the same strings the learned
/// store (`LearnedEntry::scope`) and the D-5 audit `scope` field use.
/// `suffix` is `Some` exactly for suffix-scoped decisions and carries
/// the suffix hint shown in the clicked button's label.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PromptResult {
    /// Allow the request.
    Allow {
        /// Record the decision in the learned file (3.6 wiring).
        persist: bool,
        /// `"host"` or `"suffix"`.
        scope: String,
        /// The `*.{suffix}` covered by a suffix-scoped decision.
        suffix: Option<String>,
    },
    /// Deny the request.
    Deny {
        persist: bool,
        scope: String,
        suffix: Option<String>,
    },
    /// "Explain more" (see the module header for the derivation): the
    /// user asks the agent to declare intent; 3.6 answers 403 +
    /// `X-Sandbox-Intent-Hint` and sets the registry's one-shot flag.
    NeedsIntent,
}

/// Marker that the dialog backend failed before producing a decision
/// ([G-19]) — the coordinator turns this into
/// [`PromptOutcome::Unavailable`]. A distinct type (rather than folding
/// failure into `PromptResult::Deny`) keeps the 3.6 audit source
/// (`unavailable` vs `prompt`) honest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DialogUnavailable;

/// What the injected dialog backend receives ([test seam]): the leader's
/// original host string (display form), not the normalized key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DialogRequest {
    /// Host to display (leader's original form).
    pub host: String,
    /// Leader's port.
    pub port: u16,
    /// Agent-declared reason, when one is on file ([G-17]).
    pub reason: Option<String>,
    /// Precomputed [`compute_suffix_hint`] for the `*.{suffix}` labels.
    pub suffix_hint: String,
}

/// The coordinator's final answer for one request. The variants carry
/// exactly the distinctions Task 3.6 needs for its D-5 audit `source`
/// strings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PromptOutcome {
    /// The user clicked a button (or cancelled → Deny once). Audit
    /// source `prompt`.
    Decided(PromptResult),
    /// A pool of dialog capacity ran out and this was a NEW host ([G-28]).
    /// Audit source `prompt_overload`; the two pools are different facts and the
    /// denial names which one (see [`OverloadCause`]).
    Overloaded {
        /// Which capacity the consultation could not get (P2.1 review). The
        /// callers' answer is the same — refuse, never spawn unbounded dialogs —
        /// but the remediation is not: a full consultation pool means this
        /// session is asking about many hosts at once, while a full abandoned
        /// pool means earlier dialogs are still on screen and nobody has
        /// answered them.
        cause: OverloadCause,
    },
    /// Timeout or dialog backend failure ([G-4, G-19, G-46]); the
    /// `on_unavailable` policy has already been applied. Audit source
    /// `unavailable`.
    Unavailable {
        /// The applied policy: `true` only when `on_unavailable` is
        /// `Allow` ([G-46]).
        allowed: bool,
        /// **Why** no decision exists (P2.1). The policy answer is the same
        /// either way, but the two are different facts about the session: a
        /// budget that elapsed is this session's own prompt term being spent
        /// (P2.1 budgets the container around it), while a backend failure means
        /// no dialog could appear at all. Folding them together made the audit
        /// leaf say "timeout or no dialog backend" — a reason a reader cannot
        /// act on, and the one string a headless forward request and a broken
        /// desktop would share.
        cause: UnavailableCause,
    },
    /// Zero timeout: the prompt is disabled for this profile ([G-46]).
    /// Instant deny; no dialog was attempted. Audit source `default`
    /// (same as `--no-prompt`).
    Disabled,
}

/// Which of the two capacity pools refused a consultation ([G-28], P2.1).
///
/// Two pools, two causes, because the single `Overloaded` conflated them the way
/// `Unavailable` used to conflate a spent budget with a missing backend: "too many
/// concurrent prompts" was also what a headless session was told when its
/// *abandoned* pool — dialogs nobody answered, still on screen — was full, so the
/// audit read like a concurrency limit with no dialog in sight. Both are
/// fail-closed refusals with no dialog attempted; only the reason differs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverloadCause {
    /// All [`MAX_CONCURRENT_PROMPTS`] consultation slots are held: the proxy is
    /// blocked on that many dialogs right now.
    ConsultationsHeld,
    /// The abandoned pool ([`MAX_ABANDONED_PROMPTS`]) is full: that many earlier
    /// dialogs are still running after their budgets elapsed, so their windows
    /// (and blocking threads) are the capacity this consultation lacks.
    AbandonedCapacity,
}

/// Why a consultation produced no decision ([G-19, G-46], P2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnavailableCause {
    /// The prompt budget elapsed with the dialog still up ([G-4, G-46]): the
    /// dialog is orphaned and its late answer is discarded.
    BudgetElapsed,
    /// The dialog backend could not produce a decision at all — [`show_dialog`]
    /// failed (no interactive desktop, an API error) or the blocking call
    /// panicked ([G-19]).
    NoDialogBackend,
    /// The leader's caller went away before the dialog answered; this outcome
    /// was fanned out to the parked followers ([G-6]). No budget of the
    /// follower's own elapsed, so it is not a timeout of theirs.
    CallerGone,
    /// The fast-fail latch is armed and it was armed by consultations whose
    /// budgets ELAPSED with the dialog up (P2.1 review round 2, item 8) — so this
    /// session is not consulting again, and the reason says which fact stopped it.
    /// Distinct from [`UnavailableCause::NoDialogBackend`]: the backend here
    /// demonstrably worked (a dialog was shown and nobody answered it), and the
    /// remedy is "be at the desk", not "run interactively".
    SuppressedAfterBudget,
}

/// Injected dialog backend ([test seam]): one blocking call that shows
/// one dialog and returns the user's decision, or
/// [`DialogUnavailable`] when no dialog could be shown ([G-19]). The
/// production backend wraps [`show_dialog`]; tests inject fakes so the
/// coalescing / semaphore / timeout logic gets real tests without a
/// desktop.
pub type DialogFn =
    Arc<dyn Fn(&DialogRequest) -> Result<PromptResult, DialogUnavailable> + Send + Sync>;

/// Suffix hint for the `*.{suffix}` buttons ([G-43]): the host with its
/// leftmost label removed when it has ≥3 dot-separated labels, else the
/// host itself. IP literals (v4/v6, optionally `[bracketed]`) are never
/// generalized. Trailing dots are trimmed (the hint appears inside a
/// button label). The caller's case is preserved — the learned store and
/// matcher lowercase at their own boundary.
pub fn compute_suffix_hint(host: &str) -> String {
    let h = strip_brackets(host.trim()).trim_end_matches('.');
    if h.parse::<IpAddr>().is_ok() {
        return h.to_string();
    }
    let labels: Vec<&str> = h.split('.').collect();
    if labels.len() >= 3 && labels.iter().all(|label| !label.is_empty()) {
        labels[1..].join(".")
    } else {
        h.to_string()
    }
}

/// Loopback predicate (D-1 pipeline step 2, [G-44]): `localhost`
/// (case-insensitive), any `*.localhost` name, and any IP literal
/// (optionally `[bracketed]`, trailing dot ignored) that parses as
/// loopback (`127.0.0.0/8`, `::1`). Link-local (`fe80::1`) is NOT
/// loopback. The proxy refuses loopback CONNECT before ever prompting.
pub fn is_loopback_host(host: &str) -> bool {
    let h = strip_brackets(host.trim())
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if h == "localhost" || h.ends_with(".localhost") {
        return true;
    }
    match h.parse::<IpAddr>() {
        Ok(ip) => ip.is_loopback(),
        Err(_) => false,
    }
}

/// `[v6]` → `v6`; any other input unchanged (shared by the suffix and
/// loopback paths — the proxy may pass a bracketed authority form).
fn strip_brackets(host: &str) -> &str {
    if let Some(rest) = host.strip_prefix('[')
        && let Some(close) = rest.find(']')
    {
        &rest[..close]
    } else {
        host
    }
}

/// Escape agent-influenced text for the toast XML payload. Order
/// matters: `&` must go first.
fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// Display-safety cap for dialog strings ([review A4]): dialog content
/// and button labels are bounds-checked so an adversarial reason or
/// host cannot grow the dialog without limit.
const DISPLAY_SAFE_MAX_CHARS: usize = 1024;

/// Make an LLM-influenced string safe to show in the dialog
/// ([G-17] + review A4): a `\r\n` pair collapses to a single space,
/// every other C0 control (interior NUL included), DEL and the C1
/// controls are stripped, and the result is truncated to
/// [`DISPLAY_SAFE_MAX_CHARS`] displayed chars.
///
/// Same rationale as omac's `escapePangoMarkup` (prompt.go: "collapse
/// newlines first so a fake 'Origin: ...' line cannot be injected"):
/// an embedded line break must not be able to synthesize an extra
/// `Agent reason:` line in the multi-line `pszContent`, and an interior
/// NUL must not truncate what the user sees. [G-17]'s "verbatim" is
/// preserved semantically — only control characters are removed and
/// the length bounded, and the wired path already caps the reason at
/// 500 chars via the intent registry (D-4), so the truncation here is
/// a second backstop, not the primary bound.
fn display_safe(s: &str) -> String {
    let mut out = String::with_capacity(s.len().min(DISPLAY_SAFE_MAX_CHARS * 4));
    let mut shown = 0usize;
    let mut chars = s.chars().peekable();
    while shown < DISPLAY_SAFE_MAX_CHARS {
        let Some(c) = chars.next() else {
            break;
        };
        if c == '\r' && chars.peek() == Some(&'\n') {
            chars.next();
            out.push(' ');
            shown += 1;
        } else if !matches!(c, '\0'..='\u{1f}' | '\u{7f}'..='\u{9f}') {
            out.push(c);
            shown += 1;
        }
        // Other controls are dropped without display budget.
    }
    out
}

/// Map a TaskDialog button id to its decision ([G-3, G-43]; the exact
/// ADR table, with `Explain more` for the NeedsIntent derivation — see
/// the module header). Cancel (`IDCANCEL` from X/Esc) and any
/// unrecognized id fail closed to Deny once.
fn button_id_to_result(id: i32, suffix_hint: &str) -> PromptResult {
    match id {
        ID_ALLOW_ONCE => PromptResult::Allow {
            persist: false,
            scope: "host".into(),
            suffix: None,
        },
        ID_ALLOW_SESSION => session_result(true),
        ID_ALLOW_PERM_HOST => PromptResult::Allow {
            persist: true,
            scope: "host".into(),
            suffix: None,
        },
        ID_ALLOW_PERM_SUFFIX => PromptResult::Allow {
            persist: true,
            scope: "suffix".into(),
            suffix: Some(suffix_hint.to_string()),
        },
        ID_DENY_ONCE => deny_once(),
        ID_DENY_SESSION => session_result(false),
        ID_DENY_PERM_HOST => PromptResult::Deny {
            persist: true,
            scope: "host".into(),
            suffix: None,
        },
        ID_DENY_PERM_SUFFIX => PromptResult::Deny {
            persist: true,
            scope: "suffix".into(),
            suffix: Some(suffix_hint.to_string()),
        },
        ID_EXPLAIN_MORE => PromptResult::NeedsIntent,
        _ => deny_once(),
    }
}

/// The fail-closed default decision ([G-3, G-43]: cancel = Deny once).
fn deny_once() -> PromptResult {
    PromptResult::Deny {
        persist: false,
        scope: "host".into(),
        suffix: None,
    }
}

/// Show the native task dialog and block until the user decides
/// ([G-3, G-17, G-37, G-43]). Runs on a `tokio::task::spawn_blocking`
/// thread owned by the coordinator; `TaskDialogIndirect` wants COM
/// initialized on its calling thread, done per call here. Fires the
/// courtesy toast first — separate thread, fire-and-forget, all errors
/// swallowed ([G-2, G-3]).
///
/// Any failure (no interactive desktop, API error) is
/// [`DialogUnavailable`] → the coordinator applies the `on_unavailable`
/// policy ([G-19]).
///
/// Not unit-testable (requires an interactive desktop); the coordinator
/// tests inject a fake backend instead and the checkpoint exercises
/// this function manually.
pub fn show_dialog(
    host: &str,
    port: u16,
    reason: Option<&str>,
    suffix_hint: &str,
) -> Result<PromptResult, DialogUnavailable> {
    spawn_toast(host, port);
    // TaskDialogIndirect requires COM on the calling thread. The thread
    // is fresh (spawn_blocking), so this normally succeeds; S_FALSE
    // (already initialized) is fine and still needs a matching
    // CoUninitialize below.
    let hr = unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED) };
    if hr.is_err() && hr != RPC_E_CHANGED_MODE {
        return Err(DialogUnavailable);
    }
    let result = run_task_dialog(host, port, reason, suffix_hint);
    if hr.is_ok() {
        unsafe { CoUninitialize() };
    }
    result
}

/// Build and show the nine-button task dialog (inner of
/// [`show_dialog`]).
fn run_task_dialog(
    host: &str,
    port: u16,
    reason: Option<&str>,
    suffix_hint: &str,
) -> Result<PromptResult, DialogUnavailable> {
    // [G-17] Content line 1: host:port (IPv6 literals use the standard
    // bracketed authority form). Line 2, only when a reason was passed:
    // the agent's reason, quoted. Host and reason are display-safed
    // ([review A4]: no fake 'Agent reason:' lines via embedded
    // newlines, no NUL truncation, bounded length — [G-17]'s
    // "verbatim" holds semantically).
    let host = display_safe(host);
    let target = if host.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    let content = match reason {
        Some(reason) => format!("{target}\nAgent reason: \"{}\"", display_safe(reason)),
        None => target,
    };

    // [G-3, G-43] Button labels — the suffix hint appears in the label
    // itself so the user sees exactly what a permanent decision covers.
    // "Explain more" is the NeedsIntent derivation (module header). The
    // suffix hint is host-derived, so it is display-safed too ([review
    // A4]: button labels are user-visible).
    let suffix_hint = display_safe(suffix_hint);
    let label_allow_once = HSTRING::from("Allow once");
    // "For this session" is the middle ground the once/permanent pair was missing:
    // it stops the prompting for this host without writing a rule that outlives the
    // session. Host-scoped only - there is no session-wide suffix button.
    let label_allow_session = HSTRING::from("Allow for this session (this host)");
    let label_allow_host = HSTRING::from("Allow permanently (this host)");
    let label_allow_suffix = HSTRING::from(format!("Allow permanently (*.{suffix_hint})"));
    let label_deny_once = HSTRING::from("Deny once");
    let label_deny_session = HSTRING::from("Deny for this session (this host)");
    let label_deny_host = HSTRING::from("Deny permanently (this host)");
    let label_deny_suffix = HSTRING::from(format!("Deny permanently (*.{suffix_hint})"));
    let label_explain_more = HSTRING::from("Explain more");

    let buttons = [
        TASKDIALOG_BUTTON {
            nButtonID: ID_ALLOW_ONCE,
            pszButtonText: PCWSTR(label_allow_once.as_ptr()),
        },
        TASKDIALOG_BUTTON {
            nButtonID: ID_ALLOW_SESSION,
            pszButtonText: PCWSTR(label_allow_session.as_ptr()),
        },
        TASKDIALOG_BUTTON {
            nButtonID: ID_ALLOW_PERM_HOST,
            pszButtonText: PCWSTR(label_allow_host.as_ptr()),
        },
        TASKDIALOG_BUTTON {
            nButtonID: ID_ALLOW_PERM_SUFFIX,
            pszButtonText: PCWSTR(label_allow_suffix.as_ptr()),
        },
        TASKDIALOG_BUTTON {
            nButtonID: ID_DENY_ONCE,
            pszButtonText: PCWSTR(label_deny_once.as_ptr()),
        },
        TASKDIALOG_BUTTON {
            nButtonID: ID_DENY_SESSION,
            pszButtonText: PCWSTR(label_deny_session.as_ptr()),
        },
        TASKDIALOG_BUTTON {
            nButtonID: ID_DENY_PERM_HOST,
            pszButtonText: PCWSTR(label_deny_host.as_ptr()),
        },
        TASKDIALOG_BUTTON {
            nButtonID: ID_DENY_PERM_SUFFIX,
            pszButtonText: PCWSTR(label_deny_suffix.as_ptr()),
        },
        TASKDIALOG_BUTTON {
            nButtonID: ID_EXPLAIN_MORE,
            pszButtonText: PCWSTR(label_explain_more.as_ptr()),
        },
    ];

    let title = HSTRING::from("sandbox: network access");
    let main_instruction = HSTRING::from("The sandboxed process wants to reach:");
    let content = HSTRING::from(content);

    let dialog_result = {
        // Zeroed == TASKDIALOGCONFIG::default() (the unions default to
        // "no icon"); the packed struct cannot be built as a struct
        // literal without naming the anonymous union types.
        let mut config: TASKDIALOGCONFIG = unsafe { std::mem::zeroed() };
        config.cbSize = std::mem::size_of::<TASKDIALOGCONFIG>() as u32;
        // Command links fit the eight long labels; no TDF_NO_FOCUS → the
        // dialog is foreground-activated and grabs input focus ([G-37]);
        // SIZE_TO_CONTENT fits the nine rows without scrolling;
        // ALLOW_DIALOG_CANCELLATION gives X/Esc → IDCANCEL ([G-3, G-43]).
        config.dwFlags =
            TDF_USE_COMMAND_LINKS | TDF_ALLOW_DIALOG_CANCELLATION | TDF_SIZE_TO_CONTENT;
        config.pszWindowTitle = PCWSTR(title.as_ptr());
        config.pszMainInstruction = PCWSTR(main_instruction.as_ptr());
        // [G-17] Multi-line content: host:port, plus the optional
        // `Agent reason: "..."` line.
        config.pszContent = PCWSTR(content.as_ptr());
        config.cButtons = buttons.len() as u32;
        config.pButtons = buttons.as_ptr();
        // [G-3, G-43] The default button is Deny once.
        config.nDefaultButton = ID_DENY_ONCE;

        let mut clicked: i32 = 0;
        show_task_dialog(&config, &mut clicked).map(|hr| (hr, clicked))
    };

    match dialog_result {
        // The user clicked a button (or cancelled); map the clicked id
        // to the decision ([G-3, G-43]).
        Some((hr, clicked)) if hr.is_ok() => Ok(button_id_to_result(clicked, &suffix_hint)),
        // Setup failure (None) or a TaskDialog API failure — [G-19].
        _ => Err(DialogUnavailable),
    }
}

/// `TaskDialogIndirect` fn-pointer type (comctl32 v6 ABI; the four
/// out-params after the config are the clicked button, radio button and
/// verification flags).
type TaskDialogIndirectFn =
    unsafe extern "system" fn(*const TASKDIALOGCONFIG, *mut i32, *mut i32, *mut BOOL) -> HRESULT;

/// Manifest declaring the Common-Controls v6 dependency, written to
/// `%TEMP%` and fed to `CreateActCtxW` (see the module header for why
/// the import cannot be static).
const COMMON_CONTROLS_V6_MANIFEST: &str = "\
<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\
<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\">\
<assemblyIdentity type=\"win32\" name=\"Sandbox.TaskDialogSupport\" version=\"1.0.0.0\"/>\
<dependency>\
<dependentAssembly>\
<assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" \
version=\"6.0.0.0\" processorArchitecture=\"*\" publicKeyToken=\"6595b64144ccf1df\" language=\"*\"/>\
</dependentAssembly>\
</dependency>\
</assembly>";

/// Write the v6 manifest to `%TEMP%` once per process and return its
/// path. `None` when the temp dir is not writable — the dialog is then
/// unavailable ([G-19]).
fn v6_manifest_path() -> Option<std::path::PathBuf> {
    use std::sync::OnceLock;
    static PATH: OnceLock<Option<std::path::PathBuf>> = OnceLock::new();
    PATH.get_or_init(|| {
        let path = std::env::temp_dir().join(format!(
            "sandbox-taskdialog-{}.manifest",
            std::process::id()
        ));
        std::fs::write(&path, COMMON_CONTROLS_V6_MANIFEST).ok()?;
        Some(path)
    })
    .clone()
}

/// Resolve `TaskDialogIndirect` at runtime inside a Common-Controls-v6
/// activation context and call it. Returns `Some(hr)` after the call, or
/// `None` when the backend could not be resolved or its context could
/// not be activated on this thread (no comctl32 v6, API missing, …) —
/// all mapped by the caller to [`DialogUnavailable`] ([G-19]).
fn show_task_dialog(config: &TASKDIALOGCONFIG, clicked: &mut i32) -> Option<HRESULT> {
    let backend = DialogBackend::resolve()?;
    let mut cookie: usize = 0;
    unsafe {
        // Per dialog call only the activation is redone (review A1):
        // activation is per-thread, the cached context/module/fn
        // pointer are thread-agnostic. The context must be active for
        // the whole `TaskDialogIndirect` call — window-class lookup and
        // theming come from the SxS v6 assembly.
        if ActivateActCtx(Some(backend.handle), &mut cookie).is_err() {
            return None;
        }
        let hr = (backend.task_dialog_indirect)(
            config,
            clicked,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );
        let _ = DeactivateActCtx(0, cookie);
        Some(hr)
    }
}

/// The dialog backend resolved ONCE per process (review A1): the
/// Common-Controls-v6 activation context, the v6 `comctl32.dll` module
/// mapped inside it, and the `TaskDialogIndirect` fn pointer. The
/// module is NEVER freed and the context NEVER released afterwards:
/// `TaskDialogIndirect` registers module-owned window classes, so an
/// unload/reload cycle between dialogs is the classic 2nd-dialog crash
/// zone; keeping one mapping alive for the process is both safe and
/// cheaper than re-running the chain per dialog. Per dialog call only
/// the (per-thread) activation is redone — see [`show_task_dialog`].
struct DialogBackend {
    /// Activation-context handle from `CreateActCtxW`. Intentionally
    /// never `ReleaseActCtx`-ed after a successful resolve: one
    /// bounded handle leak per process, by design.
    handle: HANDLE,
    /// The v6 comctl32 mapped inside the context. Intentionally never
    /// `FreeLibrary`-ed after a successful resolve (see the struct
    /// doc); kept in the struct to document the ownership.
    #[allow(dead_code)] // ownership documented, never freed on purpose
    module: HMODULE,
    /// Resolved inside the context; stays valid while the module stays
    /// mapped, i.e. for the whole process.
    task_dialog_indirect: TaskDialogIndirectFn,
}

// HANDLE/HMODULE are process-wide kernel integer values, not borrowed
// memory, and the fn pointer is inert until called on a dialog thread;
// the resolve cache is a `static`, so `Send + Sync` is required and
// sound here.
unsafe impl Send for DialogBackend {}
unsafe impl Sync for DialogBackend {}

impl DialogBackend {
    /// Resolve once per process and cache the result (success AND
    /// failure — a host that cannot show dialogs cannot show dialogs,
    /// and re-running `CreateActCtxW` per request would only churn
    /// ([G-19] keeps the mapping fail-closed either way)).
    fn resolve() -> Option<&'static Self> {
        static BACKEND: std::sync::OnceLock<Option<DialogBackend>> = std::sync::OnceLock::new();
        BACKEND.get_or_init(Self::do_resolve).as_ref()
    }

    /// The one-time chain: manifest → `CreateActCtxW` → activate →
    /// `LoadLibraryW` inside the context → `GetProcAddress`
    /// (`None` on any failure → permanent [`DialogUnavailable`]).
    fn do_resolve() -> Option<Self> {
        use std::os::windows::ffi::OsStrExt;
        unsafe {
            let path = v6_manifest_path()?;
            // Review A2: `CreateActCtxW` with a real UTF-16 path — the
            // ANSI `CreateActCtxA` mis-encodes a non-ASCII %TEMP% (e.g.
            // an umlaut username) into a permanent DialogUnavailable.
            let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
            wide.push(0); // NUL terminator
            let actctx = ACTCTXW {
                cbSize: std::mem::size_of::<ACTCTXW>() as u32,
                lpSource: PCWSTR(wide.as_ptr()),
                ..Default::default()
            };
            let Ok(handle) = CreateActCtxW(&actctx) else {
                return None;
            };
            let mut cookie: usize = 0;
            if ActivateActCtx(Some(handle), &mut cookie).is_err() {
                ReleaseActCtx(handle);
                return None;
            }
            // Context active: comctl32.dll now resolves to the WinSxS
            // v6 assembly, which exports TaskDialogIndirect.
            let module = match LoadLibraryW(w!("comctl32.dll")) {
                Ok(module) => module,
                Err(_) => {
                    let _ = DeactivateActCtx(0, cookie);
                    ReleaseActCtx(handle);
                    return None;
                }
            };
            let Some(proc) = GetProcAddress(module, s!("TaskDialogIndirect")) else {
                // Init-time failure only: no dialog ever ran through
                // this module, so unloading it now cannot break
                // registered classes (the never-unload rule exists to
                // protect classes `TaskDialogIndirect` registered —
                // none did yet).
                let _ = FreeLibrary(module);
                let _ = DeactivateActCtx(0, cookie);
                ReleaseActCtx(handle);
                return None;
            };
            let _ = DeactivateActCtx(0, cookie);
            let task_dialog_indirect: TaskDialogIndirectFn = std::mem::transmute(proc);
            Some(Self {
                handle,
                module,
                task_dialog_indirect,
            })
        }
    }
}

/// The toast queue: ONE process-lifetime STA apartment, lazily created.
///
/// Every toast used to own its thread and `CoUninitialize` it on exit, while the
/// `windows` crate caches the WinRT activation factory in a process-wide static.
/// The second toast therefore reached `IGenericFactory::ActivateInstance` with a
/// factory whose apartment was already gone: `0xC0000005`, reproduced by two
/// toasts 700 ms apart (`successive_toasts_do_not_kill_the_process`) and observed
/// five times in production dumps, each stack `fire_toast ->
/// FactoryCache<XmlDocument>::call`. A *burst* of toasts does NOT reproduce it -
/// they share one live apartment - which is why the first version of that test
/// was green on broken code.
///
/// One apartment for the process keeps every cached factory valid; the thread
/// lives until the process does, so `CoUninitialize` is deliberately never
/// called. This is not an optimisation: it is the only arrangement in which the
/// crate's factory cache cannot outlive its apartment.
fn toast_channel() -> Option<&'static std::sync::mpsc::Sender<(String, u16)>> {
    use std::sync::OnceLock;
    static TX: OnceLock<Option<std::sync::mpsc::Sender<(String, u16)>>> = OnceLock::new();
    TX.get_or_init(|| {
        let (tx, rx) = std::sync::mpsc::channel::<(String, u16)>();
        std::thread::Builder::new()
            .name("sandbox-prompt-toasts".to_string())
            .spawn(move || {
                let hr = unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED) };
                if hr.is_err() && hr != RPC_E_CHANGED_MODE {
                    // No apartment on this thread: dropping `rx` makes every
                    // `send` fail, so toasts become a no-op, as documented.
                    return;
                }
                while let Ok((host, port)) = rx.recv() {
                    let _ = toast_inner(&host, port);
                }
                if hr.is_ok() {
                    unsafe { CoUninitialize() };
                }
            })
            .ok()?;
        Some(tx)
    })
    .as_ref()
}

/// Fire the courtesy toast ([G-2, G-3]). Fire and forget — every error is
/// swallowed by design. The toast is a secondary, non-intrusive channel and may
/// legitimately no-op (no interactive desktop, toasts disabled, AUMID quirks for
/// unpackaged console apps); the dialog alone carries the decision.
fn spawn_toast(host: &str, port: u16) {
    if let Some(tx) = toast_channel() {
        let _ = tx.send((host.to_string(), port));
    }
}

fn toast_inner(host: &str, port: u16) -> windows::core::Result<()> {
    // ToastText02: one bold heading + one body line.
    let body =
        format!("Sandboxed process wants to reach {host}:{port} — a decision dialog is waiting.");
    let xml = format!(
        "<toast><visual><binding template=\"ToastText02\">\
         <text id=\"1\">{}</text><text id=\"2\">{}</text>\
         </binding></visual></toast>",
        xml_escape("sandbox: network request"),
        xml_escape(&body),
    );
    let doc = XmlDocument::new()?;
    doc.LoadXml(&HSTRING::from(xml.as_str()))?;
    let toast = ToastNotification::CreateToastNotification(&doc)?;
    // Unpackaged console apps have no registered AUMID of their own;
    // PowerShell's (registered via its Start Menu shortcut on stock
    // Windows) makes the toast display. Purely best-effort — the Show
    // call may fail or no-op, which is swallowed here ([G-2]).
    let notifier = ToastNotificationManager::CreateToastNotifierWithId(&HSTRING::from(
        "{1AC14E86-1E4C-4D72-9F87-9F11BA3B2B4B}\\WindowsPowerShell\\v1.0\\powershell.exe",
    ))?;
    notifier.Show(&toast)
}

/// Per-host waiter list: the parked followers' oneshot senders ([G-6]).
type Waiters = StdMutex<Vec<oneshot::Sender<PromptOutcome>>>;

/// Normalized hostname → parked followers of the in-flight leader
/// ([G-6]). An `Arc` so the detached supervisor tasks can finish an
/// entry without borrowing the coordinator — a dropped leader's
/// cleanup must not depend on the caller's future.
type WaiterMap = Arc<Mutex<HashMap<String, Arc<Waiters>>>>;

/// Coordinating entry point for the proxy pipeline (Task 3.6 wiring):
/// coalescing ([G-6]), the two capacity pools ([G-28] — [`MAX_CONCURRENT_PROMPTS`]
/// consultations plus [`MAX_ABANDONED_PROMPTS`] abandoned windows) and the
/// timeout + fallback policy ([G-4, G-19, G-46]) around one blocking dialog call.
pub struct PromptCoordinator {
    /// Caps concurrent **consultations** at [`MAX_CONCURRENT_PROMPTS`]
    /// ([G-28]); abandoned windows are bounded by `abandoned` below.
    permits: Arc<Semaphore>,
    /// Normalized hostname → parked followers of the in-flight leader
    /// ([G-6]); shared with the supervisor tasks (see [`WaiterMap`]).
    waiters: WaiterMap,
    /// Dialogs the coordinator stopped waiting on and cannot cancel (P2.1):
    /// [`MAX_ABANDONED_PROMPTS`] permits, one per orphaned dialog, released when
    /// its blocking call returns.
    ///
    /// Separate from `permits` on purpose. `permits` bounds the consultations the
    /// proxy is **blocked on**, and a consultation whose budget elapsed is over:
    /// leaving its slot occupied made eight timed-out consultations (the routine
    /// state of a headless run — no dialog can be answered) wedge the whole
    /// prompt path into permanent `Overloaded` for the rest of the process. This
    /// pool is what keeps that fix bounded: an orphaned dialog still holds a real
    /// window and a blocking thread, so it keeps a permit here until it returns,
    /// and when this pool is exhausted a NEW dialog is refused rather than
    /// spawning an unbounded number of them.
    abandoned: Arc<Semaphore>,
    /// The injected dialog backend (real: [`show_dialog`]; tests: fake).
    dialog: DialogFn,
    /// Standing answers the user gave "for this session" (host → allow), for the
    /// rest of the current LAUNCH. Never persisted: the learned file is the
    /// permanent store, and a session answer must not end up in it. Keyed by the
    /// normalized hostname only — the session buttons are exact-host, so there is
    /// no suffix arithmetic here on purpose.
    session: Arc<StdMutex<HashMap<String, bool>>>,
    /// Session-scoped memory of consultations that produced no decision
    /// ([`NO_BACKEND_STICKY_AFTER`]). Shared with the supervisor tasks, which are
    /// the only place one dialog's outcome is known exactly once.
    backend: Arc<BackendStickiness>,
}

/// What armed the fast-fail — carried so the audit names the arming cause and not
/// the nearest-looking one (P2.1 review round 2, item 8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ArmingCause {
    /// Consecutive consultations found no dialog to show at all ([G-19]).
    NoBackend,
    /// Consecutive consultations spent their budget with the dialog unanswered
    /// ([G-4]): a dialog exists, nobody is clicking it.
    BudgetElapsed,
}

impl ArmingCause {
    /// The cause `outcome` is evidence of, if it is evidence at all.
    fn of(outcome: &PromptOutcome) -> Option<Self> {
        match outcome {
            PromptOutcome::Unavailable {
                cause: UnavailableCause::NoDialogBackend,
                ..
            } => Some(Self::NoBackend),
            PromptOutcome::Unavailable {
                cause: UnavailableCause::BudgetElapsed,
                ..
            } => Some(Self::BudgetElapsed),
            _ => None,
        }
    }

    /// The cause a consultation the latch SKIPPED reports, and with it the audit
    /// reason. The two arming causes stay apart: a suppressed budget and a missing
    /// dialog have different remedies.
    fn skip_cause(self) -> UnavailableCause {
        match self {
            Self::NoBackend => UnavailableCause::NoDialogBackend,
            Self::BudgetElapsed => UnavailableCause::SuppressedAfterBudget,
        }
    }
}

/// The mutable half of the latch — one lock, so a re-probe and the streak it
/// inherits are never observed half-applied.
#[derive(Debug, Default)]
struct StickyState {
    /// Consecutive consultations that produced no user decision.
    streak: usize,
    /// `Some((cause, armed_at))` while the fast-fail is armed. The instant is what
    /// the re-probe cooldown counts from (item 3), and the cause is what the
    /// skipped consultations report (item 8).
    armed: Option<(ArmingCause, std::time::Instant)>,
}

/// Memory of consultations that produced no decision
/// ([`NO_BACKEND_STICKY_AFTER`]), scoped to a LAUNCH (item 2) and cleared by
/// [`PromptCoordinator::begin_launch`].
#[derive(Debug)]
struct BackendStickiness {
    state: StdMutex<StickyState>,
    /// The streak that arms the fast-fail. `usize::MAX` in tests that pin the
    /// two-pool mechanics independently of this policy.
    after: usize,
    /// How long an armed latch waits before it re-probes the backend (item 3).
    cooldown: Duration,
}

/// What one consultation does about the dialog (P2.1 review round 2, item 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StickyPlan {
    /// Consult the dialog (the capacity pools permitting).
    Consult,
    /// Stop asking, and report this cause — the one that armed the latch (item 8).
    Skip(UnavailableCause),
}

impl BackendStickiness {
    fn with_cooldown(after: usize, cooldown: Duration) -> Self {
        Self {
            state: StdMutex::new(StickyState::default()),
            after,
            cooldown,
        }
    }

    /// The lock, recovered from poisoning instead of panicking: the latch is a
    /// policy hint, and a panicking proxy worker would turn it into an outage.
    fn lock(&self) -> std::sync::MutexGuard<'_, StickyState> {
        self.state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    /// Whether this consultation consults a dialog, and if not, which cause to
    /// report.
    ///
    /// Item 4: the fast-fail answer is the DENY posture's answer only. Under
    /// `on_unavailable = allow` a skip would *permit* the host with no dialog —
    /// the opposite of the deny the posture degrades to — so allow keeps
    /// consulting.
    ///
    /// Item 3: an armed latch re-probes after its cooldown. The re-probe is ONE
    /// consultation, and it leaves the streak one short of the threshold, so a
    /// failed re-probe re-arms immediately (the outage continues) while a
    /// successful one resets the streak through [`BackendStickiness::observe`].
    fn plan(&self, policy: PromptPolicy) -> StickyPlan {
        if policy == PromptPolicy::Allow {
            return StickyPlan::Consult;
        }
        let mut state = self.lock();
        let Some((cause, armed_at)) = state.armed else {
            return StickyPlan::Consult;
        };
        if armed_at.elapsed() < self.cooldown {
            return StickyPlan::Skip(cause.skip_cause());
        }
        state.armed = None;
        state.streak = self.after.saturating_sub(1);
        StickyPlan::Consult
    }

    /// Fold one consultation's outcome into the latch. Exactly once per
    /// consultation, and only for the LEADER: a coalesced follower reports the same
    /// dialog's outcome and must not count it again.
    ///
    /// Reset on a decision (the backend works); count a missing backend and an
    /// elapsed budget (no decision was obtainable — the routine headless shape is
    /// the budget one, because a hang is what a dialog with nobody at the desktop
    /// does); leave [`PromptOutcome::Overloaded`] and [`PromptOutcome::Disabled`]
    /// alone, since neither consulted a dialog and neither is evidence either way.
    /// `CallerGone` is not evidence about the backend either: the dialog may be on
    /// screen and answering fine.
    fn observe(&self, outcome: &PromptOutcome) {
        let mut state = self.lock();
        if matches!(outcome, PromptOutcome::Decided(_)) {
            state.streak = 0;
            state.armed = None;
            return;
        }
        let Some(cause) = ArmingCause::of(outcome) else {
            return;
        };
        // Saturating: `usize::MAX` means "never arm" in tests, and a counter that
        // wrapped would arm the fast-fail accidentally.
        state.streak = state.streak.saturating_add(1);
        // Stamped on the ARMING observation only: a consultation the latch already
        // skipped is not new evidence, and re-stamping here would restart the
        // re-probe cooldown on every request, so a session under steady traffic
        // would never re-probe at all (item 3).
        if state.streak >= self.after && state.armed.is_none() {
            state.armed = Some((cause, std::time::Instant::now()));
        }
    }

    /// Forget everything: a new LAUNCH starts with no history (item 2).
    fn begin_launch(&self) {
        *self.lock() = StickyState::default();
    }
}

/// What a leader's consultation will do about the dialog (P2.1 review, item 4).
///
/// Three arms rather than `Option<(permit, handle)>` because "no dialog" has two
/// different reasons and every refusal must still finish the coalescing entry.
enum DialogPlan {
    /// Both permits were acquired: the dialog runs, holding them.
    Show(
        OwnedSemaphorePermit,
        tokio::task::JoinHandle<Result<PromptResult, DialogUnavailable>>,
    ),
    /// Capacity ran out; no dialog was attempted.
    Refused(OverloadCause),
    /// The latch is armed ([`NO_BACKEND_STICKY_AFTER`] consecutive consultations
    /// produced no decision, under the deny posture): no dialog is attempted and no
    /// permit is taken, because there is nothing to wait for. The cause is the one
    /// that ARMED it (item 8), so the audit can tell a suppressed budget from a
    /// missing dialog.
    SkipAbsentBackend(UnavailableCause),
}

impl PromptCoordinator {
    /// Coordinator backed by the real `TaskDialogIndirect` dialog
    /// ([`show_dialog`]).
    pub fn new() -> Self {
        Self::with_dialog(Arc::new(|req: &DialogRequest| {
            show_dialog(&req.host, req.port, req.reason.as_deref(), &req.suffix_hint)
        }))
    }

    /// Coordinator with an injected dialog backend — the test seam that
    /// lets the coalescing / semaphore / timeout logic run under real
    /// tests without a desktop.
    pub fn with_dialog(dialog: DialogFn) -> Self {
        Self::with_dialog_and_stickiness(dialog, NO_BACKEND_STICKY_AFTER)
    }

    /// Coordinator with the caller's fast-fail threshold **and** re-probe cooldown
    /// (P2.1 review round 2, item 3): how long an armed latch waits before it
    /// consults a dialog again. Tests use milliseconds; production uses
    /// [`NO_BACKEND_REPROBE_COOLDOWN`] through
    /// [`PromptCoordinator::with_dialog`].
    fn with_cooldown(dialog: DialogFn, after: usize, cooldown: Duration) -> Self {
        Self {
            permits: Arc::new(Semaphore::new(MAX_CONCURRENT_PROMPTS)),
            abandoned: Arc::new(Semaphore::new(MAX_ABANDONED_PROMPTS)),
            waiters: Arc::new(Mutex::new(HashMap::new())),
            session: Arc::new(StdMutex::new(HashMap::new())),
            dialog,
            backend: Arc::new(BackendStickiness::with_cooldown(after, cooldown)),
        }
    }

    /// Start a new LAUNCH on this listener's coordinator (P2.1 review round 2,
    /// item 2).
    ///
    /// The latch lives on the coordinator, which is per listener and outlives a
    /// launch, and nothing else resets it: one launch per process hid that, but a
    /// listener CAN serve sequential launches (the P1.4 epoch machinery exists for
    /// exactly that), and then launch N's stalled prompts would deny every prompt of
    /// launch N+1 — a session that never prompted reporting
    /// `no_dialog_backend`/`prompt_suppressed_after_budget`.
    ///
    /// Wired to the epoch: `proxy::spawn` registers this as the listener's launch
    /// reset, and `LaunchCounters::begin_epoch` runs it, so the reset happens at the
    /// same instant the attribution window opens.
    pub fn begin_launch(&self) {
        self.backend.begin_launch();
        // A new session starts with no standing answers: the next launch's policy
        // is the user's to decide, not the previous one's to inherit.
        self.session
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clear();
    }

    /// Coordinator with the fast-fail threshold chosen by the caller. Tests that
    /// pin the two capacity pools pass `usize::MAX`: how *many* dialogs may be
    /// live is a bound of its own, and the pool tests must not be re-derived from
    /// a policy that stops opening dialogs after [`NO_BACKEND_STICKY_AFTER`] of them
    /// go unanswered.
    fn with_dialog_and_stickiness(dialog: DialogFn, after: usize) -> Self {
        Self::with_cooldown(dialog, after, NO_BACKEND_REPROBE_COOLDOWN)
    }

    /// Live consultations: slots held by prompts the coordinator is still waiting
    /// on (P2.1). Zero when nothing is being prompted; it must return to zero
    /// after a timeout, because the timed-out consultation is over.
    #[allow(dead_code)] // read by the live lane and the P2.1 budget tests
    pub fn live_consultations(&self) -> usize {
        MAX_CONCURRENT_PROMPTS - self.permits.available_permits()
    }

    /// Dialogs **still running after the coordinator stopped waiting on them**
    /// (P2.1) — the number of windows nobody is waiting for any more. Bounded by
    /// [`MAX_ABANDONED_PROMPTS`]; reaches zero as the orphaned calls return.
    ///
    /// Not "permits held": a dialog the coordinator is *still waiting on* holds
    /// one of the same permits, so the raw permit arithmetic reports every live
    /// consultation a second time — 8 parked consultations read as
    /// `live=8 abandoned=8`, which is exactly the doubled number an incident
    /// reader would take at face value. The subtraction is what makes the two
    /// accessors describe disjoint sets: `live_consultations()` = dialogs being
    /// awaited, `abandoned_dialogs()` = dialogs that outlived their budget and
    /// whose late answer will be discarded.
    #[allow(dead_code)] // read by the live lane (P2.1 abandoned-dialog accounting)
    pub fn abandoned_dialogs(&self) -> usize {
        let held = MAX_ABANDONED_PROMPTS - self.abandoned.available_permits();
        // Saturating: a dialog can return while its consultation is still live
        // (the supervisor has not yet dropped the slot), which makes `held` a
        // hair smaller than `live` — "no abandoned dialog" is the honest answer
        // there, never a wrapped usize.
        held.saturating_sub(self.live_consultations())
    }

    /// Ask the user about one request and await the outcome. `config` supplies the
    /// timeout and fallback policy per call ([G-46, G-48]).
    ///
    /// Test-only: every production caller wants [`Self::prompt_measured`]'s wall
    /// clock, and a second entry point that discards it is how the per-request
    /// accounting drifts. Kept because 37 tests drive the coordinator through it.
    #[cfg(test)]
    pub async fn prompt(
        &self,
        host: &str,
        port: u16,
        reason: Option<String>,
        config: PromptConfig,
    ) -> PromptOutcome {
        self.prompt_measured(host, port, reason, config).await.0
    }

    /// Ask the user about one request and await the outcome, plus the wall clock **the leader of this
    /// consultation** spent on the dialog it led (P2.1 review round 2, item 1).
    ///
    /// `Some` exactly for the leader of a dialog that actually ran; `None` for a
    /// follower (it was parked on somebody else's request, so the dialog is not
    /// its cost), for a consultation the latch skipped, and for one a capacity
    /// pool refused. Crediting per REQUEST is what made four concurrent requests
    /// to one host report four minutes for one minute of blocking, which in turn
    /// labelled a genuine workload overrun `prompt_budget_exhausted`.
    pub async fn prompt_measured(
        &self,
        host: &str,
        port: u16,
        reason: Option<String>,
        config: PromptConfig,
    ) -> (PromptOutcome, Option<Duration>) {
        // [G-46] ZERO timeout = the prompt is disabled for this profile:
        // instant deny, no dialog attempt, no coalescing entry.
        if config.timeout == Duration::ZERO {
            return (PromptOutcome::Disabled, None);
        }

        // [G-6] Key by normalized hostname only (port ignored; case,
        // port and trailing dot normalized the same way as the intent
        // registry).
        let key = crate::net::intent::normalize_host(host);
        // `key` is moved into the coalescing map below; the session record needs it
        // after the consultation.
        let session_key = key.clone();

        // A "for this session" answer covers every later request to this host: no
        // window, no consultation slot, no coalescing entry. Exact host only — the
        // session buttons do not generalize by suffix.
        if let Some(allow) = self
            .session
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&key)
            .copied()
        {
            return (PromptOutcome::Decided(session_result(allow)), None);
        }

        // Election and parking happen atomically under the map lock so a
        // follower can never park on an entry the leader already
        // delivered to.
        enum Role {
            Leader(Arc<Waiters>),
            Follower(oneshot::Receiver<PromptOutcome>),
        }
        let role = {
            let mut map = self.waiters.lock().await;
            if let Some(entry) = map.get(&key) {
                let (tx, rx) = oneshot::channel();
                entry.lock().unwrap_or_else(|p| p.into_inner()).push(tx);
                Role::Follower(rx)
            } else {
                let entry = Arc::new(StdMutex::new(Vec::new()));
                map.insert(key.clone(), Arc::clone(&entry));
                Role::Leader(entry)
            }
        };

        let (outcome, measured) = match role {
            Role::Follower(rx) => {
                // Park on the leader's outcome under OUR own deadline —
                // a follower does not inherit the leader's wait ([G-6,
                // G-46]). Note: if the LEADER's deadline hits first, or
                // the leader's caller is dropped mid-prompt (the
                // supervisor finishes the entry either way), the
                // fanned-out `Unavailable` reflects the leader's
                // policy; a follower with a laxer policy is denied —
                // failing closed ([G-46]). In practice 3.6 passes one
                // profile config for all requests, so the policies
                // coincide.
                let outcome = match tokio::time::timeout(config.timeout, rx).await {
                    Ok(Ok(outcome)) => outcome,
                    // Our own deadline hit — this follower's budget is what
                    // elapsed ([G-46]). The leader vanished without delivering
                    // (a bug path): the follower's budget did not elapse, so the
                    // cause is the leader, not this follower's timeout.
                    Err(_) => unavailable_from(&config, UnavailableCause::BudgetElapsed),
                    Ok(Err(_)) => unavailable_from(&config, UnavailableCause::CallerGone),
                };
                // Item 1: this request parked on a dialog somebody else led, so it
                // credits no prompt time of its own.
                (outcome, None)
            }
            Role::Leader(entry) => {
                // [G-28, P2.1] Only the leader takes a consultation slot, and the
                // slot is held by the supervisor task below — *not* by the
                // blocking dialog call. A dialog that outlives its budget is
                // abandoned (it cannot be cancelled: `spawn_blocking` has no
                // cancellation), and an abandoned dialog used to keep its slot
                // for the life of the process. Eight of those — the routine
                // state of a headless run, where no dialog can be answered —
                // turned every later consultation into `Overloaded`, i.e. the
                // prompt path never recovered and never even consulted its own
                // budget again. The orphan still holds a real window and thread,
                // so it keeps a permit from the separate abandoned pool.
                // Plan Step 3: the dialog runs on the blocking pool so
                // the async handler never blocks a tokio worker. Which pool
                // refused is carried, not folded (P2.1 review): "too many
                // concurrent prompts" is what a full *abandoned* pool used to
                // say too — a concurrency limit for a session whose dialogs are
                // simply unanswered.
                // Item 1: this leader's dialog starts now. The measurement is
                // taken by the leader (not by each caller) because a coalesced
                // follower must credit nothing: one dialog's wall clock added K
                // times is what turned 60 s of blocking into 240 s of "prompt
                // time" and mislabelled a real overrun.
                let leader_started = std::time::Instant::now();
                let plan = match self.backend.plan(config.on_unavailable) {
                    // Items 3-5: enough consecutive consultations produced no
                    // decision, the posture is deny, and the re-probe cooldown has
                    // not run out — so this session has nobody to ask. No permit, no
                    // blocking thread, no orphan: the policy answer is applied now,
                    // under the reason that ARMED the latch (item 8).
                    StickyPlan::Skip(cause) => DialogPlan::SkipAbsentBackend(cause),
                    StickyPlan::Consult => match (
                        Arc::clone(&self.permits).try_acquire_owned(),
                        Arc::clone(&self.abandoned).try_acquire_owned(),
                    ) {
                        (Ok(permit), Ok(abandoned)) => {
                            let req = DialogRequest {
                                host: host.to_string(),
                                port,
                                reason,
                                suffix_hint: compute_suffix_hint(host),
                            };
                            let dialog = Arc::clone(&self.dialog);
                            let handle = tokio::task::spawn_blocking(move || {
                                let _abandoned = abandoned;
                                dialog(&req)
                            });
                            DialogPlan::Show(permit, handle)
                        }
                        // Every consultation slot is in flight ([G-28]). The
                        // permit result is checked first because that is the cap
                        // the ADR names: an exhausted consultation pool is the
                        // more specific fact even when both pools are full.
                        (Err(_), _) => DialogPlan::Refused(OverloadCause::ConsultationsHeld),
                        // The abandoned pool is full: dialogs from earlier
                        // consultations are still running.
                        (_, Err(_)) => DialogPlan::Refused(OverloadCause::AbandonedCapacity),
                    },
                };

                // Supervisor (review blocking fix): a detached task
                // owns the whole timeout→finish pipeline, and
                // `prompt()` merely awaits its report over a oneshot.
                // If the caller's future is dropped mid-prompt — the
                // routine proxy case: the agent process is killed or
                // the client disconnects while the dialog is up — the
                // report receiver vanishes, the supervisor notices
                // (`report_tx.closed()`), finishes the coalescing entry
                // (fanning the `on_unavailable` outcome out to parked
                // followers) and lets the orphaned dialog keep running
                // detached with its late result discarded ([G-4]).
                // Nothing strands: the next same-host request elects a
                // fresh leader instead of parking until its own
                // timeout for the remainder of the process. Cleanup
                // runs exactly once — `select!` takes exactly one
                // branch — so there is no double fan-out, and a gone
                // caller only turns the final report send into an
                // ignored error.
                let (mut report_tx, report) =
                    oneshot::channel::<(PromptOutcome, Option<Duration>)>();
                let waiters = Arc::clone(&self.waiters);
                let supervised_entry = Arc::clone(&entry);
                let backend = Arc::clone(&self.backend);
                tokio::spawn(async move {
                    // `Some` only when a dialog actually ran for this leader (item 1).
                    let mut credit: Option<Duration> = None;
                    let outcome = match plan {
                        DialogPlan::Show(permit, handle) => {
                            // P2.1: held for as long as this consultation is
                            // live — decided, budget elapsed, or caller gone —
                            // and released here, so the slot is reusable the
                            // moment the proxy stops waiting. The orphaned
                            // dialog keeps only its abandoned-pool permit.
                            let _slot = permit;
                            // Plan Step 6: await the dialog under the
                            // caller's timeout.
                            let outcome = tokio::select! {
                                // The caller's future was dropped
                                // mid-prompt: finish now with the
                                // fallback outcome so parked followers
                                // are released promptly ([G-6, G-46]).
                                _ = report_tx.closed() => {
                                    unavailable_from(&config, UnavailableCause::CallerGone)
                                }
                                res = tokio::time::timeout(config.timeout, handle) => {
                                    match res {
                                        Ok(Ok(Ok(result))) => {
                                            PromptOutcome::Decided(result)
                                        }
                                        // Dialog backend failure
                                        // ([G-19]) — a TaskDialog API
                                        // error, or a panic on the
                                        // blocking thread.
                                        Ok(Ok(Err(DialogUnavailable)))
                                        | Ok(Err(_)) => {
                                            unavailable_from(
                                                &config,
                                                UnavailableCause::NoDialogBackend,
                                            )
                                        }
                                        // The prompt budget elapsed: the
                                        // orphaned dialog stays on screen and
                                        // its late result is discarded
                                        // ([G-4]); the policy decides — never
                                        // a silent allow ([G-46]) — and the
                                        // cause says a budget was spent, which
                                        // is what P2.1 reports distinctly.
                                        Err(_) => {
                                            unavailable_from(
                                                &config,
                                                UnavailableCause::BudgetElapsed,
                                            )
                                        }
                                    }
                                }
                            };
                            // The consultation is over: this is what the dialog cost
                            // this session, charged once (item 1).
                            credit = Some(leader_started.elapsed());
                            outcome
                        }
                        // [G-28] A pool ran out: this NEW host was denied
                        // immediately and no dialog was attempted, but the entry
                        // still must be finished — followers that parked in the
                        // election→deny window receive the refusal.
                        DialogPlan::Refused(cause) => PromptOutcome::Overloaded { cause },
                        // Item 3: the backend is known absent, so the policy
                        // answer is the whole answer. The cause is the one that armed
                        // the latch (item 8): `no_dialog_backend` when no dialog could
                        // be shown, `prompt_suppressed_after_budget` when dialogs were
                        // shown and their budgets elapsed — a budget this consultation
                        // never spent either way.
                        DialogPlan::SkipAbsentBackend(cause) => unavailable_from(&config, cause),
                    };
                    // Exactly once per consultation, and only the leader: a
                    // coalesced follower reports the same dialog's outcome and
                    // must not count it again (K followers would arm the
                    // fast-fail after one dialog).
                    backend.observe(&outcome);
                    Self::finish(&waiters, &key, &supervised_entry, outcome.clone()).await;
                    let _ = report_tx.send((outcome, credit));
                });
                match report.await {
                    Ok(report) => report,
                    // The supervisor always finishes cleanup before
                    // reporting; a closed channel means it panicked —
                    // fail closed, never a silent allow ([G-46]).
                    Err(_) => (
                        unavailable_from(&config, UnavailableCause::CallerGone),
                        None,
                    ),
                }
            }
        };
        // The one place that sees the decision and the normalized key together:
        // the leader records it, and coalesced followers record the same value
        // (idempotent), so a decision made under one port answers the next one.
        remember_session(&self.session, &session_key, &outcome);
        (outcome, measured)
    }

    /// Remove this host's entry and fan the leader's outcome out to
    /// all parked followers ([G-6]). Removal happens first so requests
    /// arriving after delivery elect a fresh leader; because election
    /// and parking are atomic under the map lock, no waiter can slip in
    /// between removal and the fan-out.
    ///
    /// An associated function, not `&self`: the detached supervisor
    /// task owns the cleanup and holds the waiter map by `Arc` — the
    /// coordinator itself may be long gone by the time an orphaned
    /// dialog's entry is finished.
    async fn finish(waiters: &WaiterMap, key: &str, entry: &Arc<Waiters>, outcome: PromptOutcome) {
        waiters.lock().await.remove(key);
        let parked = std::mem::take(&mut *entry.lock().unwrap_or_else(|p| p.into_inner()));
        for tx in parked {
            // A waiter may have hit its own deadline already — send
            // errors are expected and ignored.
            let _ = tx.send(outcome.clone());
        }
    }
}

/// The [`PromptResult`] a remembered session answer stands for.
fn session_result(allow: bool) -> PromptResult {
    if allow {
        PromptResult::Allow {
            persist: false,
            scope: "session".to_string(),
            suffix: None,
        }
    } else {
        PromptResult::Deny {
            persist: false,
            scope: "session".to_string(),
            suffix: None,
        }
    }
}

/// Remember a "for this session" decision for the rest of the launch. Anything
/// else - "once", "permanently", "explain more", or no decision at all - leaves
/// the memory untouched: the permanent decisions belong in the learned file, and
/// `once` ends with the request.
fn remember_session(session: &StdMutex<HashMap<String, bool>>, key: &str, outcome: &PromptOutcome) {
    let PromptOutcome::Decided(result) = outcome else {
        return;
    };
    let (persist, scope) = match result {
        PromptResult::Allow { persist, scope, .. } | PromptResult::Deny { persist, scope, .. } => {
            (*persist, scope.as_str())
        }
        PromptResult::NeedsIntent => return,
    };
    if persist || scope != "session" {
        return;
    }
    let allow = matches!(result, PromptResult::Allow { .. });
    session
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .insert(key.to_string(), allow);
}

/// Apply the `on_unavailable` policy to a non-decision ([G-19, G-46]).
///
/// `cause` is carried, not folded away (P2.1): the policy answer is the same for
/// every cause, but the audit reason is not — a spent prompt budget is this
/// session's own term being consumed, while a backend failure is a machine with
/// no dialog. Reporting one string for both is what made a headless forward
/// request indistinguishable from a broken desktop.
fn unavailable_from(config: &PromptConfig, cause: UnavailableCause) -> PromptOutcome {
    PromptOutcome::Unavailable {
        allowed: matches!(config.on_unavailable, PromptPolicy::Allow),
        cause,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    /// Regression (2026-10-23): every toast used to own its own STA thread and
    /// `CoUninitialize` it on exit, while the `windows` crate caches the WinRT
    /// factory in a process-wide static. The SECOND toast then dereferenced a
    /// factory whose apartment had been torn down: `0xC0000005` with the stack
    /// `fire_toast -> FactoryCache<XmlDocument>::call -> IGenericFactory::
    /// ActivateInstance`, observed five times in `%LOCALAPPDATA%\CrashDumps` and
    /// reproduced by a workload that opened several prompts at once (opencode's
    /// five parallel fetches). The toast is best-effort, but "best-effort" must
    /// not mean "kills the supervisor": this test fires several in a burst and
    /// only survives if the WinRT apartment outlives each individual toast.
    #[test]
    fn successive_toasts_do_not_kill_the_process() {
        // SEQUENTIAL with a gap, not a burst: the crash needs the previous
        // toast's apartment to be GONE before the next one activates, which is
        // what production does (prompts arrive seconds apart). A burst of eight
        // passes even on the broken code, because they all share one live
        // apartment - that is why the first version of this test was green.
        for i in 0..4 {
            spawn_toast(&format!("host{i}.example"), 443);
            std::thread::sleep(Duration::from_millis(700));
        }
    }
    use std::sync::Condvar;
    use std::sync::{Arc, Mutex as StdMutex};
    use std::time::{Duration, Instant};

    /// What a fake dialog replies to one invocation.
    type FakeReply = Result<PromptResult, DialogUnavailable>;

    /// Scripted replies + parked-call wakeups for the fake dialog.
    /// Replies are queued PER HOST (review A3): the old single shared
    /// channel made both dialog calls of
    /// `distinct_hosts_do_not_coalesce` serialize through one receiver,
    /// so which host consumed which reply depended on scheduler order.
    /// Per-host queues remove that order dependence; within one host
    /// the queue is FIFO.
    #[derive(Default)]
    struct FakeState {
        /// Replies waiting to be consumed, keyed like the coordinator's
        /// waiters (normalized hostname).
        queues: HashMap<String, VecDeque<FakeReply>>,
        /// Set when the handle drops: parked calls fail closed ([G-19])
        /// so their blocking threads always exit.
        closed: bool,
    }

    /// Handle for inspecting / scripting a fake dialog from tests.
    /// Dropping it closes the fake (`closed` above).
    struct FakeHandle {
        calls: Arc<StdMutex<Vec<DialogRequest>>>,
        state: Arc<(StdMutex<FakeState>, Condvar)>,
    }

    impl FakeHandle {
        fn calls(&self) -> Vec<DialogRequest> {
            self.calls.lock().unwrap().clone()
        }

        /// Program one reply for `host`, consumed by that host's next
        /// dialog call (FIFO within the host).
        fn reply(&self, host: &str, r: FakeReply) {
            let (lock, condvar) = &*self.state;
            let mut st = lock.lock().unwrap();
            st.queues
                .entry(crate::net::intent::normalize_host(host))
                .or_default()
                .push_back(r);
            condvar.notify_all();
        }

        /// Bounded wait until the fake dialog recorded `n` calls.
        async fn wait_for_calls(&self, n: usize) {
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                if self.calls.lock().unwrap().len() >= n {
                    return;
                }
                assert!(
                    Instant::now() < deadline,
                    "timed out waiting for {n} dialog call(s); saw {}",
                    self.calls.lock().unwrap().len()
                );
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        }

        /// Bounded wait until `n` followers are parked on `host`'s leader
        /// (inspects the coordinator's private waiter map — same-module
        /// test access, no production reachability).
        async fn wait_parked(coord: &Arc<PromptCoordinator>, host: &str, n: usize) {
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                {
                    let map = coord.waiters.lock().await;
                    if let Some(entry) = map.get(host)
                        && entry.lock().unwrap().len() >= n
                    {
                        return;
                    }
                }
                assert!(
                    Instant::now() < deadline,
                    "timed out waiting for {n} parked follower(s) on {host}"
                );
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        }

        /// Bounded wait until every scripted reply for `host` has been
        /// consumed by a dialog call — proves a parked dialog task is
        /// still alive (e.g. the orphaned dialog after a caller drop).
        async fn wait_replies_consumed(&self, host: &str) {
            let host = crate::net::intent::normalize_host(host);
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                {
                    let (lock, _condvar) = &*self.state;
                    let st = lock.lock().unwrap();
                    if st.queues.get(&host).is_none_or(VecDeque::is_empty) {
                        return;
                    }
                }
                assert!(
                    Instant::now() < deadline,
                    "timed out waiting for {host}'s scripted replies to be consumed"
                );
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        }
    }

    impl Drop for FakeHandle {
        fn drop(&mut self) {
            // Fail every parked dialog call closed so its blocking
            // thread exits; tests never leak parked threads.
            let (lock, condvar) = &*self.state;
            let mut st = lock.lock().unwrap();
            st.closed = true;
            condvar.notify_all();
        }
    }

    /// Build a fake dialog that records every request and blocks each
    /// call until the test programs a reply for that host (or the
    /// handle is dropped, which maps to a backend failure so the
    /// blocking thread always exits — tests never leak parked
    /// threads).
    ///
    /// Replies are matched by the coordinator's own normalization of
    /// the request host, so the order in which concurrent dialogs
    /// consume replies can never swap decisions between distinct
    /// hosts. The state Mutex is RELEASED while a call is parked on
    /// the condvar (`Condvar::wait` releases, then reacquires) — the
    /// old design held the lock across the blocking `recv()`, which is
    /// what serialized the two calls of
    /// `distinct_hosts_do_not_coalesce` in the first place.
    fn fake_dialog() -> (FakeHandle, DialogFn) {
        let state: Arc<(StdMutex<FakeState>, Condvar)> =
            Arc::new((StdMutex::new(FakeState::default()), Condvar::new()));
        let calls: Arc<StdMutex<Vec<DialogRequest>>> = Arc::new(StdMutex::new(Vec::new()));
        let recorded = Arc::clone(&calls);
        let parked = Arc::clone(&state);
        let dialog: DialogFn = Arc::new(move |req: &DialogRequest| {
            recorded.lock().unwrap().push(req.clone());
            let host = crate::net::intent::normalize_host(&req.host);
            let (lock, condvar) = &*parked;
            let mut st = lock.lock().unwrap();
            loop {
                let reply = st.queues.get_mut(&host).and_then(|q| q.pop_front());
                if let Some(reply) = reply {
                    return reply;
                }
                if st.closed {
                    return Err(DialogUnavailable);
                }
                st = condvar.wait(st).unwrap();
            }
        });
        (FakeHandle { calls, state }, dialog)
    }

    /// `Allow for this session (this host)`: host-scoped, never persisted.
    fn session_allow() -> PromptResult {
        PromptResult::Allow {
            persist: false,
            scope: "session".to_string(),
            suffix: None,
        }
    }

    /// `Deny for this session (this host)`.
    fn session_deny() -> PromptResult {
        PromptResult::Deny {
            persist: false,
            scope: "session".to_string(),
            suffix: None,
        }
    }

    fn allow_once() -> PromptResult {
        PromptResult::Allow {
            persist: false,
            scope: "host".into(),
            suffix: None,
        }
    }

    fn deny_once() -> PromptResult {
        PromptResult::Deny {
            persist: false,
            scope: "host".into(),
            suffix: None,
        }
    }

    fn cfg(timeout: Duration, policy: PromptPolicy) -> PromptConfig {
        PromptConfig {
            timeout,
            on_unavailable: policy,
        }
    }

    // ---- compute_suffix_hint ([G-43]) ----------------------------------

    #[test]
    fn suffix_one_label_unchanged() {
        assert_eq!(compute_suffix_hint("com"), "com");
        assert_eq!(compute_suffix_hint("localhost"), "localhost");
    }

    #[test]
    fn suffix_two_labels_unchanged() {
        assert_eq!(compute_suffix_hint("example.com"), "example.com");
        assert_eq!(compute_suffix_hint("npmjs.org"), "npmjs.org");
    }

    #[test]
    fn suffix_three_labels_strips_leftmost() {
        assert_eq!(compute_suffix_hint("api.example.com"), "example.com");
        // The ADR's label-count rule deliberately ignores the public
        // suffix list ([G-43] simplification vs omac's eTLD+1).
        assert_eq!(compute_suffix_hint("example.co.uk"), "co.uk");
    }

    #[test]
    fn suffix_four_labels_strips_only_leftmost() {
        assert_eq!(compute_suffix_hint("a.b.example.com"), "b.example.com");
    }

    #[test]
    fn suffix_ipv4_literal_unchanged() {
        assert_eq!(compute_suffix_hint("127.0.0.1"), "127.0.0.1");
        assert_eq!(compute_suffix_hint("192.168.1.1"), "192.168.1.1");
    }

    #[test]
    fn suffix_ipv6_literal_unchanged() {
        assert_eq!(compute_suffix_hint("::1"), "::1");
        assert_eq!(compute_suffix_hint("2001:db8::1"), "2001:db8::1");
    }

    #[test]
    fn suffix_trailing_dot_trimmed() {
        // Trailing dots are not meaningful labels ([G-43]); the hint is
        // used in a button label, so it never keeps one.
        assert_eq!(compute_suffix_hint("api.example.com."), "example.com");
        assert_eq!(compute_suffix_hint("example.com."), "example.com");
        assert_eq!(compute_suffix_hint("127.0.0.1."), "127.0.0.1");
    }

    #[test]
    fn suffix_bracketed_ipv6_unwrapped() {
        assert_eq!(compute_suffix_hint("[::1]"), "::1");
        assert_eq!(compute_suffix_hint("[2001:db8::5]"), "2001:db8::5");
    }

    #[test]
    fn suffix_degenerate_input_not_generalized() {
        assert_eq!(compute_suffix_hint(""), "");
        // An empty interior label means this is not a well-formed host:
        // no generalization, return as-is.
        assert_eq!(compute_suffix_hint("a..b.com"), "a..b.com");
    }

    // ---- is_loopback_host ----------------------------------------------

    #[test]
    fn loopback_localhost_and_subdomains() {
        assert!(is_loopback_host("localhost"));
        assert!(is_loopback_host("LocalHost"));
        assert!(is_loopback_host("sub.localhost"));
        assert!(is_loopback_host("deep.sub.localhost"));
    }

    #[test]
    fn loopback_ipv4_whole_127_slash_8() {
        assert!(is_loopback_host("127.0.0.1"));
        assert!(is_loopback_host("127.200.1.1"));
        assert!(is_loopback_host("127.255.255.254"));
    }

    #[test]
    fn loopback_ipv6_forms() {
        assert!(is_loopback_host("::1"));
        assert!(is_loopback_host("0:0:0:0:0:0:0:1"));
        assert!(is_loopback_host("[::1]"));
    }

    #[test]
    fn loopback_trailing_dot_still_loopback() {
        assert!(is_loopback_host("localhost."));
        assert!(is_loopback_host("127.0.0.1."));
    }

    #[test]
    fn not_loopback() {
        // Link-local is NOT loopback.
        assert!(!is_loopback_host("fe80::1"));
        assert!(!is_loopback_host("example.com"));
        assert!(!is_loopback_host("192.168.1.1"));
        assert!(!is_loopback_host("10.0.0.1"));
        assert!(!is_loopback_host(""));
    }

    // ---- button → PromptResult mapping ([G-3, G-43]) --------------------

    #[test]
    fn button_mapping_all_seven_buttons() {
        let s = "example.com".to_string();
        // The session buttons: host-scoped, not persisted - that pair of facts is
        // what keeps the learned file quiet and the prompting quiet for this host.
        assert_eq!(button_id_to_result(ID_ALLOW_SESSION, &s), session_allow());
        assert_eq!(button_id_to_result(ID_DENY_SESSION, &s), session_deny());
        assert_eq!(
            button_id_to_result(ID_ALLOW_ONCE, &s),
            PromptResult::Allow {
                persist: false,
                scope: "host".into(),
                suffix: None,
            }
        );
        assert_eq!(
            button_id_to_result(ID_ALLOW_PERM_HOST, &s),
            PromptResult::Allow {
                persist: true,
                scope: "host".into(),
                suffix: None,
            }
        );
        assert_eq!(
            button_id_to_result(ID_ALLOW_PERM_SUFFIX, &s),
            PromptResult::Allow {
                persist: true,
                scope: "suffix".into(),
                suffix: Some(s.clone()),
            }
        );
        assert_eq!(
            button_id_to_result(ID_DENY_ONCE, &s),
            PromptResult::Deny {
                persist: false,
                scope: "host".into(),
                suffix: None,
            }
        );
        assert_eq!(
            button_id_to_result(ID_DENY_PERM_HOST, &s),
            PromptResult::Deny {
                persist: true,
                scope: "host".into(),
                suffix: None,
            }
        );
        assert_eq!(
            button_id_to_result(ID_DENY_PERM_SUFFIX, &s),
            PromptResult::Deny {
                persist: true,
                scope: "suffix".into(),
                suffix: Some(s.clone()),
            }
        );
        assert_eq!(
            button_id_to_result(ID_EXPLAIN_MORE, &s),
            PromptResult::NeedsIntent
        );
    }

    #[test]
    fn button_mapping_cancel_and_unknown_fail_closed_to_deny_once() {
        let s = "example.com".to_string();
        // Dialog cancel (X / Esc → IDCANCEL) is Deny once ([G-3, G-43]).
        assert_eq!(button_id_to_result(IDCANCEL, &s), deny_once());
        // An unrecognized id cannot happen from our own buttons; fail
        // closed anyway.
        assert_eq!(button_id_to_result(0, &s), deny_once());
        assert_eq!(button_id_to_result(9999, &s), deny_once());
    }

    // ---- defaults --------------------------------------------------------

    #[test]
    fn defaults_match_adr() {
        // 60s prompt timeout ([G-46]), deny-on-unavailable ([G-48]).
        assert_eq!(DEFAULT_PROMPT_TIMEOUT, Duration::from_secs(60));
        assert_eq!(
            PromptConfig::default(),
            PromptConfig {
                timeout: DEFAULT_PROMPT_TIMEOUT,
                on_unavailable: PromptPolicy::Deny,
            }
        );
        assert_eq!(MAX_CONCURRENT_PROMPTS, 8);
        // The real-backend constructor must exist and stay cheap (no
        // dialog is shown at construction).
        let _coord = PromptCoordinator::new();
    }

    // ---- toast payload helper ----------------------------------------------

    #[test]
    fn xml_escape_specials() {
        assert_eq!(
            xml_escape("a<b>&\"c\"'d"),
            "a&lt;b&gt;&amp;&quot;c&quot;&apos;d"
        );
    }

    // ---- display safety for user-visible dialog strings (review A4) ----

    #[test]
    fn display_safe_collapses_crlf_strips_controls() {
        // omac precedent (`escapePangoMarkup`, prompt.go: "collapse
        // newlines first so a fake 'Origin: ...' line cannot be
        // injected"): an embedded line break must not fake an extra
        // `Agent reason:` line in the dialog.
        assert_eq!(display_safe("a\r\nb"), "a b");
        // Lone \r / \n are "other" C0 controls and are stripped
        // outright (no line break can be synthesized from them).
        assert_eq!(display_safe("a\rb"), "ab");
        assert_eq!(display_safe("a\nb"), "ab");
        // An interior NUL must not truncate the rest of the display.
        assert_eq!(display_safe("a\0b"), "ab");
        // DEL and the C1 controls are stripped as well.
        assert_eq!(display_safe("a\u{7f}b\u{9f}c"), "abc");
        // Ordinary text — including non-ASCII — passes through
        // unchanged ([G-17]: verbatim, semantically).
        assert_eq!(display_safe("Börse-Straße 42"), "Börse-Straße 42");
        assert_eq!(display_safe(""), "");
    }

    #[test]
    fn display_safe_bounds_length_at_1024_chars() {
        let long = "x".repeat(5000);
        assert_eq!(display_safe(&long).chars().count(), 1024);
        // Exactly at the bound: unchanged.
        let exact = "y".repeat(1024);
        assert_eq!(display_safe(&exact), exact);
        // The bound counts DISPLAYED chars — stripped controls never
        // earn display budget.
        let mixed = format!("{}{}", "\0".repeat(2000), "z".repeat(2000));
        let out = display_safe(&mixed);
        assert_eq!(out.chars().count(), 1024);
        assert!(out.chars().all(|c| c == 'z'));
    }

    // ---- dynamic TaskDialog resolution ----------------------------------------

    #[test]
    fn task_dialog_backend_resolves_once_per_process() {
        // First resolve proves the whole dynamic chain (manifest →
        // CreateActCtxW → activate → LoadLibraryW → GetProcAddress)
        // works on this host — this is what the manifest-less static
        // import broke at load time. The resolved fn is never CALLED
        // here, so no dialog is shown; a host where this fails is
        // denied closed via [G-19] instead.
        let first = DialogBackend::resolve()
            .expect("TaskDialogIndirect must resolve inside the v6 context");
        // Review A1: resolution must be ONCE PER PROCESS, cached — not
        // re-run per dialog. After the manifest is deleted, a second
        // CreateActCtx would fail (and re-resolving per dialog is the
        // unload/reload comctl32-v6 window-class hazard).
        let path = v6_manifest_path().expect("manifest must exist after first resolve");
        std::fs::remove_file(&path).expect("manifest must be deletable");
        let second = DialogBackend::resolve()
            .expect("resolve must be cached once per process, not re-run per dialog");
        // Both resolves must have returned the SAME cached backend
        // (fn-pointer equality is not meaningful to the compiler, so
        // compare the cached `&'static` references instead).
        assert!(
            std::ptr::eq(first, second),
            "both resolves must be served from the one cached backend"
        );
        // Restore the per-pid manifest (D3: in production it is
        // written once per process and never deleted).
        std::fs::write(&path, COMMON_CONTROLS_V6_MANIFEST).expect("manifest rewrite");
    }

    // ---- session-scoped decisions ----------------------------------------

    /// A decision the user marks "for this session" answers every later request to
    /// that host without a dialog, and is never written to the learned file.
    #[tokio::test]
    async fn a_session_allow_answers_the_next_request_without_a_dialog() {
        let (handle, dialog) = fake_dialog();
        let coord = Arc::new(PromptCoordinator::with_dialog(dialog));
        let cfg = cfg(Duration::from_secs(60), PromptPolicy::Deny);

        let first = {
            let c = Arc::clone(&coord);
            tokio::spawn(async move { c.prompt("session.example.com", 443, None, cfg).await })
        };
        handle.wait_for_calls(1).await;
        handle.reply("session.example.com", Ok(session_allow()));
        assert_eq!(
            first.await.unwrap(),
            PromptOutcome::Decided(session_allow())
        );

        // Same host, different port: answered from the session memory, no window.
        let second = tokio::time::timeout(
            Duration::from_secs(5),
            coord.prompt("session.example.com", 8443, None, cfg),
        )
        .await
        .expect("a session decision must answer without waiting for a dialog");
        assert_eq!(second, PromptOutcome::Decided(session_allow()));
        assert_eq!(
            handle.calls().len(),
            1,
            "the second request must not open another dialog"
        );
    }

    /// The same for a denial: one "for this session" click stops the prompting for
    /// that host instead of asking again on every connection.
    #[tokio::test]
    async fn a_session_deny_answers_the_next_request_without_a_dialog() {
        let (handle, dialog) = fake_dialog();
        let coord = Arc::new(PromptCoordinator::with_dialog(dialog));
        let cfg = cfg(Duration::from_secs(60), PromptPolicy::Deny);

        let first = {
            let c = Arc::clone(&coord);
            tokio::spawn(async move { c.prompt("deny-me.example.com", 443, None, cfg).await })
        };
        handle.wait_for_calls(1).await;
        handle.reply("deny-me.example.com", Ok(session_deny()));
        assert_eq!(first.await.unwrap(), PromptOutcome::Decided(session_deny()));

        let second = tokio::time::timeout(
            Duration::from_secs(5),
            coord.prompt("deny-me.example.com", 80, None, cfg),
        )
        .await
        .expect("a session denial must answer without a dialog");
        assert_eq!(second, PromptOutcome::Decided(session_deny()));
        assert_eq!(handle.calls().len(), 1);
    }

    /// Session memory is per host: deciding about one host says nothing about
    /// another, and it does not generalize by suffix ("no need to have the suffix
    /// match" - the session buttons are exact-host only).
    #[tokio::test]
    async fn session_memory_covers_one_host_and_not_its_siblings() {
        let (handle, dialog) = fake_dialog();
        let coord = Arc::new(PromptCoordinator::with_dialog(dialog));
        let cfg = cfg(Duration::from_secs(60), PromptPolicy::Deny);

        let first = {
            let c = Arc::clone(&coord);
            tokio::spawn(async move { c.prompt("api.example.com", 443, None, cfg).await })
        };
        handle.wait_for_calls(1).await;
        handle.reply("api.example.com", Ok(session_allow()));
        first.await.unwrap();

        // A sibling host still asks, and so does a subdomain of the decided one.
        let sibling = {
            let c = Arc::clone(&coord);
            tokio::spawn(async move { c.prompt("cdn.example.com", 443, None, cfg).await })
        };
        handle.wait_for_calls(2).await;
        handle.reply("cdn.example.com", Ok(allow_once()));
        assert_eq!(sibling.await.unwrap(), PromptOutcome::Decided(allow_once()));
        assert_eq!(
            handle.calls().len(),
            2,
            "a session decision for api.example.com must not answer cdn.example.com"
        );
    }

    /// The memory lives in the LAUNCH, like the backend latch: a new launch of the
    /// same listener asks again, because the next session's policy is the user's
    /// decision to make, not the last session's.
    #[tokio::test]
    async fn a_new_launch_forgets_session_decisions() {
        let (handle, dialog) = fake_dialog();
        let coord = Arc::new(PromptCoordinator::with_dialog(dialog));
        let cfg = cfg(Duration::from_secs(60), PromptPolicy::Deny);

        let first = {
            let c = Arc::clone(&coord);
            tokio::spawn(async move { c.prompt("launch.example.com", 443, None, cfg).await })
        };
        handle.wait_for_calls(1).await;
        handle.reply("launch.example.com", Ok(session_allow()));
        first.await.unwrap();

        coord.begin_launch();

        let second = {
            let c = Arc::clone(&coord);
            tokio::spawn(async move { c.prompt("launch.example.com", 443, None, cfg).await })
        };
        handle.wait_for_calls(2).await;
        handle.reply("launch.example.com", Ok(deny_once()));
        assert_eq!(second.await.unwrap(), PromptOutcome::Decided(deny_once()));
        assert_eq!(
            handle.calls().len(),
            2,
            "the new launch must ask again instead of inheriting the old answer"
        );
    }

    // ---- coalescing ([G-6]) ----------------------------------------------

    #[tokio::test]
    async fn coalesce_concurrent_same_host_shares_one_dialog() {
        let (handle, dialog) = fake_dialog();
        let coord = Arc::new(PromptCoordinator::with_dialog(dialog));
        let cfg = cfg(Duration::from_secs(60), PromptPolicy::Deny);

        let tasks: Vec<_> = (0..5)
            .map(|i| {
                let c = Arc::clone(&coord);
                tokio::spawn(async move {
                    c.prompt(
                        "api.example.com",
                        1000 + i,
                        Some(format!("reason {i}")),
                        cfg,
                    )
                    .await
                })
            })
            .collect();

        handle.wait_for_calls(1).await;
        FakeHandle::wait_parked(&coord, "api.example.com", 4).await;
        assert_eq!(handle.calls().len(), 1, "must coalesce into one dialog");

        handle.reply("api.example.com", Ok(allow_once()));
        let outcomes = futures_of(tasks).await;

        assert_eq!(handle.calls().len(), 1, "still exactly one dialog");
        for out in &outcomes {
            assert_eq!(*out, PromptOutcome::Decided(allow_once()));
        }
        // The one recorded request was the leader's: right host, right
        // suffix hint, one of the leader's ports.
        let reqs = handle.calls();
        assert_eq!(reqs[0].host, "api.example.com");
        assert_eq!(reqs[0].suffix_hint, "example.com");
        assert!((1000..1005).contains(&reqs[0].port));
    }

    #[tokio::test]
    async fn coalesce_key_is_normalized_hostname_port_ignored() {
        // [G-6]: keyed by hostname only, and case/trailing-dot variants
        // of the same host coalesce onto one leader.
        let (handle, dialog) = fake_dialog();
        let coord = Arc::new(PromptCoordinator::with_dialog(dialog));
        let cfg = cfg(Duration::from_secs(60), PromptPolicy::Deny);

        let leader = {
            let c = Arc::clone(&coord);
            tokio::spawn(async move { c.prompt("API.Example.COM.", 443, None, cfg).await })
        };
        handle.wait_for_calls(1).await;

        let follower = {
            let c = Arc::clone(&coord);
            tokio::spawn(async move { c.prompt("api.example.com", 8443, None, cfg).await })
        };
        FakeHandle::wait_parked(&coord, "api.example.com", 1).await;

        handle.reply("api.example.com", Ok(allow_once()));
        assert_eq!(leader.await.unwrap(), PromptOutcome::Decided(allow_once()));
        assert_eq!(
            follower.await.unwrap(),
            PromptOutcome::Decided(allow_once())
        );
        assert_eq!(handle.calls().len(), 1, "port must not fork the dialog");
    }

    #[tokio::test]
    async fn distinct_hosts_do_not_coalesce() {
        let (handle, dialog) = fake_dialog();
        let coord = Arc::new(PromptCoordinator::with_dialog(dialog));
        let cfg = cfg(Duration::from_secs(60), PromptPolicy::Deny);

        let a = {
            let c = Arc::clone(&coord);
            tokio::spawn(async move { c.prompt("a.example.com", 443, None, cfg).await })
        };
        let b = {
            let c = Arc::clone(&coord);
            tokio::spawn(async move { c.prompt("b.example.com", 443, None, cfg).await })
        };

        handle.wait_for_calls(2).await;
        // Per-host replies (review A3): each host's decision is pinned
        // to that host, so scheduler order can no longer swap the two.
        handle.reply("a.example.com", Ok(allow_once()));
        handle.reply("b.example.com", Ok(deny_once()));

        assert_eq!(a.await.unwrap(), PromptOutcome::Decided(allow_once()));
        assert_eq!(b.await.unwrap(), PromptOutcome::Decided(deny_once()));
        assert_eq!(handle.calls().len(), 2);
    }

    #[tokio::test]
    async fn sequential_same_host_prompts_again_after_delivery() {
        // The coalescing entry must be removed when the leader delivers,
        // so a *later* request (not concurrent) prompts afresh.
        let (handle, dialog) = fake_dialog();
        let coord = PromptCoordinator::with_dialog(dialog);
        let cfg = cfg(Duration::from_secs(60), PromptPolicy::Deny);

        handle.reply("api.example.com", Ok(allow_once()));
        handle.reply("api.example.com", Ok(deny_once()));

        assert_eq!(
            coord.prompt("api.example.com", 443, None, cfg).await,
            PromptOutcome::Decided(allow_once())
        );
        assert_eq!(
            coord.prompt("api.example.com", 443, None, cfg).await,
            PromptOutcome::Decided(deny_once())
        );
        assert_eq!(handle.calls().len(), 2, "each sequential request prompts");
    }

    // ---- semaphore ([G-28]) -------------------------------------------------

    #[tokio::test]
    async fn overload_ninth_new_host_denied_immediately() {
        let (handle, dialog) = fake_dialog();
        let coord = Arc::new(PromptCoordinator::with_dialog(dialog));
        let cfg = cfg(Duration::from_secs(60), PromptPolicy::Deny);

        // 8 distinct hosts, each parked inside its own dialog → all 8
        // permits are held by leaders.
        let leaders: Vec<_> = (0..8)
            .map(|i| {
                let c = Arc::clone(&coord);
                tokio::spawn(
                    async move { c.prompt(&format!("h{i}.example.com"), 443, None, cfg).await },
                )
            })
            .collect();
        handle.wait_for_calls(8).await;

        // 9th concurrent prompt for a NEW host: immediate deny, no dialog
        // ([G-28]).
        let start = Instant::now();
        let ninth = coord.prompt("h8.example.com", 443, None, cfg).await;
        assert_eq!(
            ninth,
            PromptOutcome::Overloaded {
                cause: OverloadCause::ConsultationsHeld
            },
            "the denial must name the pool that ran out: every consultation slot is in flight"
        );
        assert_eq!(handle.calls().len(), 8, "no 9th dialog may be shown");
        assert!(
            start.elapsed() < Duration::from_secs(1),
            "overload deny must be immediate"
        );

        // A same-host request for an already-coalesced leader still rides
        // the existing dialog (followers never take a permit).
        let rider = {
            let c = Arc::clone(&coord);
            tokio::spawn(async move { c.prompt("h0.example.com", 8443, None, cfg).await })
        };
        FakeHandle::wait_parked(&coord, "h0.example.com", 1).await;

        // Release everyone so no blocking thread outlives the test.
        for i in 0..8 {
            handle.reply(&format!("h{i}.example.com"), Ok(deny_once()));
        }
        for l in leaders {
            assert_eq!(l.await.unwrap(), PromptOutcome::Decided(deny_once()));
        }
        assert_eq!(
            rider.await.unwrap(),
            PromptOutcome::Decided(deny_once()),
            "same-host rider shares the leader's result"
        );
        assert_eq!(handle.calls().len(), 8);
    }

    // ---- zero timeout ([G-46]) ---------------------------------------------

    #[tokio::test]
    async fn zero_timeout_is_instant_deny_no_dialog() {
        let (handle, dialog) = fake_dialog();
        let coord = PromptCoordinator::with_dialog(dialog);
        let cfg = cfg(Duration::ZERO, PromptPolicy::Allow);

        // Even with on_unavailable=Allow: ZERO timeout means instant
        // deny — the policy is not consulted ([G-46]).
        let out = coord.prompt("api.example.com", 443, None, cfg).await;
        assert_eq!(out, PromptOutcome::Disabled);
        assert!(handle.calls().is_empty(), "no dialog may be attempted");
        // (no wall-clock assertion here: the two assertions above already pin the
        // behaviour, and a 500 ms bound only measures how busy the machine is.)
    }

    // ---- timeout ([G-4, G-46]) ----------------------------------------------

    #[tokio::test]
    async fn timeout_returns_unavailable_deny() {
        let (handle, dialog) = fake_dialog();
        let coord = PromptCoordinator::with_dialog(dialog);
        let cfg = cfg(Duration::from_millis(100), PromptPolicy::Deny);

        let out = coord.prompt("slow.example.com", 443, None, cfg).await;
        assert_eq!(
            out,
            PromptOutcome::Unavailable {
                allowed: false,
                cause: UnavailableCause::BudgetElapsed,
            },
            "a spent budget must be reported as the cause, not as a backend failure"
        );
        assert_eq!(
            handle.calls().len(),
            1,
            "the dialog was shown, then orphaned"
        );
    }

    #[tokio::test]
    async fn timeout_with_allow_policy_returns_unavailable_allow() {
        // A timed-out prompt only defaults to allow when the policy says
        // so — never silently ([G-46]).
        let (handle, dialog) = fake_dialog();
        let coord = PromptCoordinator::with_dialog(dialog);
        let cfg = cfg(Duration::from_millis(100), PromptPolicy::Allow);

        let out = coord.prompt("slow.example.com", 443, None, cfg).await;
        assert_eq!(
            out,
            PromptOutcome::Unavailable {
                allowed: true,
                cause: UnavailableCause::BudgetElapsed,
            }
        );
        assert_eq!(handle.calls().len(), 1);
    }

    #[tokio::test]
    async fn follower_with_shorter_deadline_times_out_independently() {
        let (handle, dialog) = fake_dialog();
        let coord = Arc::new(PromptCoordinator::with_dialog(dialog));

        let leader = {
            let c = Arc::clone(&coord);
            let cfg = cfg(Duration::from_secs(10), PromptPolicy::Deny);
            tokio::spawn(async move { c.prompt("api.example.com", 443, None, cfg).await })
        };
        handle.wait_for_calls(1).await;

        let follower_cfg = cfg(Duration::from_millis(50), PromptPolicy::Deny);
        let follower = {
            let c = Arc::clone(&coord);
            tokio::spawn(async move { c.prompt("api.example.com", 8443, None, follower_cfg).await })
        };
        FakeHandle::wait_parked(&coord, "api.example.com", 1).await;

        // The follower's own deadline applies — it does not inherit the
        // leader's 10s wait ([G-46]).
        let start = Instant::now();
        assert_eq!(
            follower.await.unwrap(),
            PromptOutcome::Unavailable {
                allowed: false,
                cause: UnavailableCause::BudgetElapsed,
            }
        );
        assert!(start.elapsed() < Duration::from_secs(5));

        // The leader later decides Allow; the timed-out follower is NOT
        // retroactively allowed.
        handle.reply("api.example.com", Ok(allow_once()));
        assert_eq!(leader.await.unwrap(), PromptOutcome::Decided(allow_once()));
    }

    // ---- leader caller-drop safety (review blocking) -------------------

    /// Bounded wait until `host`'s coalescing entry is gone from the
    /// waiter map (the cleanup pipeline finished after the leader's
    /// caller went away).
    async fn wait_entry_gone(coord: &Arc<PromptCoordinator>, host: &str) {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            {
                let map = coord.waiters.lock().await;
                if !map.contains_key(host) {
                    return;
                }
            }
            assert!(
                Instant::now() < deadline,
                "timed out waiting for {host}'s coalescing entry to be cleaned up"
            );
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    }

    /// Bounded wait until every semaphore permit is back ([G-28]) — all
    /// dialog calls, including an orphaned one, have returned.
    async fn wait_all_permits_free(coord: &Arc<PromptCoordinator>) {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if coord.permits.available_permits() == MAX_CONCURRENT_PROMPTS {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "timed out waiting for all prompt permits to be released"
            );
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    }

    #[tokio::test]
    async fn dropped_leader_future_does_not_strand_the_coalescing_entry() {
        let (handle, dialog) = fake_dialog();
        let coord = Arc::new(PromptCoordinator::with_dialog(dialog));
        let cfg = cfg(Duration::from_secs(60), PromptPolicy::Deny);

        // A leader is elected; the fake dialog parks on its reply
        // queue.
        let leader = {
            let c = Arc::clone(&coord);
            tokio::spawn(async move { c.prompt("api.example.com", 443, None, cfg).await })
        };
        handle.wait_for_calls(1).await;

        // Drop the leader's future mid-prompt (`abort()` == the runtime
        // dropping the task's future) — the routine proxy case: the
        // agent process is killed or the client disconnects while the
        // dialog is up.
        leader.abort();
        let _ = leader.await;

        // The host's coalescing entry must be cleaned up even though
        // nobody will ever poll the leader again — a stranded entry
        // would park every later same-host request until its own
        // timeout (the review's blocking finding).
        wait_entry_gone(&coord, "api.example.com").await;

        // The next same-host request elects a NEW leader and completes
        // with a dialog decision — it must not park on the dead
        // leader's entry until its own timeout.
        let second = {
            let c = Arc::clone(&coord);
            tokio::spawn(async move { c.prompt("api.example.com", 8443, None, cfg).await })
        };
        handle.wait_for_calls(2).await;
        // Two same-host dialog calls are parked by now (the orphan +
        // the new leader) and race for the host queue — feed both the
        // same value so the new leader's outcome is deterministic
        // whichever reply it pops.
        handle.reply("api.example.com", Ok(allow_once()));
        handle.reply("api.example.com", Ok(allow_once()));
        assert_eq!(second.await.unwrap(), PromptOutcome::Decided(allow_once()));

        // [G-4] The dropped leader's blocking dialog task was NOT
        // aborted: it is still parked, it consumed the reply meant for
        // it (the queue drains only when BOTH calls popped one — if the
        // orphan had died, one reply would sit unconsumed), and its
        // permit is released only when its dialog call returns. Its
        // late result is discarded: nobody holds its JoinHandle, and
        // the second caller's outcome came from its OWN dialog.
        handle.wait_replies_consumed("api.example.com").await;
        wait_all_permits_free(&coord).await;
        assert_eq!(handle.calls().len(), 2);
    }

    // ---- backend failure ([G-19]) ---------------------------------------------

    #[tokio::test]
    async fn backend_failure_returns_unavailable_per_policy() {
        let (handle, dialog) = fake_dialog();
        let coord = PromptCoordinator::with_dialog(dialog);

        handle.reply("api.example.com", Err(DialogUnavailable));
        let out = coord
            .prompt(
                "api.example.com",
                443,
                None,
                cfg(Duration::from_secs(60), PromptPolicy::Deny),
            )
            .await;
        assert_eq!(
            out,
            PromptOutcome::Unavailable {
                allowed: false,
                cause: UnavailableCause::NoDialogBackend,
            },
            "a dialog that could not be shown is NOT a spent budget"
        );

        handle.reply("api.example.com", Err(DialogUnavailable));
        let out = coord
            .prompt(
                "api.example.com",
                443,
                None,
                cfg(Duration::from_secs(60), PromptPolicy::Allow),
            )
            .await;
        assert_eq!(
            out,
            PromptOutcome::Unavailable {
                allowed: true,
                cause: UnavailableCause::NoDialogBackend,
            }
        );

        assert_eq!(handle.calls().len(), 2);
    }

    // ---- P2.1: a timed-out consultation must give its slot back --------------

    /// The bug this pins: the consultation slot used to ride along with the
    /// blocking dialog call, so a dialog that outlived its budget (the routine
    /// state of a headless run, where no dialog can be answered) kept that slot
    /// for the life of the process. Eight of those turned every later
    /// consultation into `Overloaded`: the prompt path never recovered and never
    /// consulted its own budget again — a resource-exhaustion bug behind a
    /// policy-looking denial.
    #[tokio::test]
    async fn timed_out_consultations_release_their_slots() {
        let (handle, dialog) = fake_dialog();
        // The pool/slot mechanics are pinned here, not the fast-fail policy: nine
        // consecutive unanswered consultations are exactly what item 3 now
        // short-circuits in production, so this coordinator never arms it.
        let coord = Arc::new(PromptCoordinator::with_dialog_and_stickiness(
            dialog,
            usize::MAX,
        ));
        // No reply is ever programmed, so every dialog parks until the fake is
        // dropped: these are orphans, not slow dialogs.
        let cfg = cfg(Duration::from_millis(30), PromptPolicy::Deny);

        // Distinct hosts: nothing coalesces, one dialog each.
        for i in 0..MAX_CONCURRENT_PROMPTS {
            let host = format!("slot{i}.example.com");
            let out = coord.prompt(&host, 443, None, cfg).await;
            assert_eq!(
                out,
                PromptOutcome::Unavailable {
                    allowed: false,
                    cause: UnavailableCause::BudgetElapsed,
                },
                "host {i} must time out"
            );
        }

        // Eight dialogs are still parked — they are live windows, not dead
        // requests...
        assert_eq!(coord.abandoned_dialogs(), MAX_CONCURRENT_PROMPTS);
        // ...and not one of them still holds a consultation slot, because the
        // request each belonged to was denied on budget and is over.
        assert_eq!(
            coord.live_consultations(),
            0,
            "a timed-out consultation must give its slot back"
        );

        // The observable consequence. Before P2.1 this 9th consultation was
        // `Overloaded` for the rest of the process.
        let out = coord
            .prompt("after-the-orphans.example.com", 443, None, cfg)
            .await;
        assert_eq!(
            out,
            PromptOutcome::Unavailable {
                allowed: false,
                cause: UnavailableCause::BudgetElapsed,
            },
            "the prompt path must still be consulted after N timeouts"
        );
        assert_eq!(handle.calls().len(), MAX_CONCURRENT_PROMPTS + 1);
    }

    /// The other half of the same fix: releasing a slot must not license an
    /// unbounded number of live windows. Orphans keep a permit from their own,
    /// larger pool, and a full pool refuses the NEW host (`Overloaded`, [G-28])
    /// instead of spawning one more dialog.
    #[tokio::test]
    async fn abandoned_dialogs_stay_bounded_and_fail_closed() {
        let (handle, dialog) = fake_dialog();
        // Pool mechanics only — see `timed_out_consultations_release_their_slots`.
        let coord = Arc::new(PromptCoordinator::with_dialog_and_stickiness(
            dialog,
            usize::MAX,
        ));
        let cfg = cfg(Duration::from_millis(20), PromptPolicy::Deny);

        for i in 0..MAX_ABANDONED_PROMPTS {
            let host = format!("orphan{i}.example.com");
            let _ = coord.prompt(&host, 443, None, cfg).await;
        }
        assert_eq!(coord.abandoned_dialogs(), MAX_ABANDONED_PROMPTS);

        let out = coord
            .prompt("one-too-many.example.com", 443, None, cfg)
            .await;
        assert_eq!(
            out,
            PromptOutcome::Overloaded {
                cause: OverloadCause::AbandonedCapacity
            },
            "a full abandoned pool must refuse the new host, never spawn unbounded dialogs, \
             and the denial must name THAT pool, not the consultation cap"
        );
        assert_eq!(
            handle.calls().len(),
            MAX_ABANDONED_PROMPTS,
            "the refused consultation must not have shown a dialog"
        );
    }

    /// An orphan returning is what empties the abandoned pool — the pool is a
    /// bound on live windows, not a permanent debit.
    #[tokio::test]
    async fn an_orphan_that_returns_frees_its_abandoned_slot() {
        let (handle, dialog) = fake_dialog();
        // Pool mechanics only — see `timed_out_consultations_release_their_slots`.
        let coord = Arc::new(PromptCoordinator::with_dialog_and_stickiness(
            dialog,
            usize::MAX,
        ));
        let cfg = cfg(Duration::from_millis(20), PromptPolicy::Deny);

        for i in 0..MAX_ABANDONED_PROMPTS {
            let host = format!("orphan{i}.example.com");
            let _ = coord.prompt(&host, 443, None, cfg).await;
        }
        assert_eq!(coord.abandoned_dialogs(), MAX_ABANDONED_PROMPTS);

        // Let the parked dialogs answer (their late results are discarded).
        for i in 0..MAX_ABANDONED_PROMPTS {
            handle.reply(&format!("orphan{i}.example.com"), Ok(allow_once()));
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        while coord.abandoned_dialogs() != 0 {
            assert!(
                Instant::now() < deadline,
                "abandoned permits must come back when the orphan returns"
            );
            tokio::time::sleep(Duration::from_millis(2)).await;
        }

        // And the pool is usable again.
        handle.reply("fresh.example.com", Ok(allow_once()));
        let out = coord.prompt("fresh.example.com", 443, None, cfg).await;
        assert_eq!(out, PromptOutcome::Decided(allow_once()));
    }

    /// Item 3: a backend that has just told us twice that it cannot produce a
    /// decision is an **environment property**, so later consultations must not
    /// pay for it again. Today every one of them spawns another doomed blocking
    /// call; the supervisor knows the answer after the second.
    #[tokio::test]
    async fn a_known_absent_dialog_backend_is_not_consulted_a_third_time() {
        let (handle, dialog) = fake_dialog();
        let coord = Arc::new(PromptCoordinator::with_dialog(dialog));
        // A budget long enough that nothing here is a timeout: these are backend
        // failures, not elapsed budgets.
        let cfg = cfg(Duration::from_secs(60), PromptPolicy::Deny);
        // A failing reply for every host: if the fast-fail does not arrive, the
        // later dialogs park (and the test says so) instead of being fed.
        for i in 0..5 {
            handle.reply(&format!("absent-{i}.example.com"), Err(DialogUnavailable));
        }

        for i in 0..5 {
            let host = format!("absent-{i}.example.com");
            let out = coord.prompt(&host, 443, None, cfg).await;
            assert_eq!(
                out,
                PromptOutcome::Unavailable {
                    allowed: false,
                    cause: UnavailableCause::NoDialogBackend,
                },
                "host {i} must be denied for want of a backend"
            );
        }

        assert_eq!(
            handle.calls().len(),
            NO_BACKEND_STICKY_AFTER,
            "a known-absent backend must not be consulted again: {:?}",
            handle
                .calls()
                .iter()
                .map(|c| c.host.clone())
                .collect::<Vec<_>>()
        );
        // No dialog was spawned for the skipped consultations, so neither pool
        // has anything held.
        assert_eq!(coord.live_consultations(), 0);
        assert_eq!(coord.abandoned_dialogs(), 0);
    }

    /// The other half of item 3: the counter is CONSECUTIVE. A dialog that
    /// succeeds proves the backend works and starts the count again, so one
    /// earlier failure plus one later failure must not disable prompts.
    #[tokio::test]
    async fn a_dialog_that_succeeds_resets_the_no_backend_streak() {
        let (handle, dialog) = fake_dialog();
        let coord = Arc::new(PromptCoordinator::with_dialog(dialog));
        let cfg = cfg(Duration::from_secs(60), PromptPolicy::Deny);

        handle.reply("resets-0.example.com", Err(DialogUnavailable));
        handle.reply("resets-1.example.com", Ok(deny_once()));
        handle.reply("resets-2.example.com", Err(DialogUnavailable));
        handle.reply("resets-3.example.com", Ok(allow_once()));

        let mut outcomes = Vec::new();
        for i in 0..4 {
            let host = format!("resets-{i}.example.com");
            outcomes.push(coord.prompt(&host, 443, None, cfg).await);
        }
        assert_eq!(
            outcomes[1],
            PromptOutcome::Decided(deny_once()),
            "the second consultation was answered by a working dialog"
        );
        assert_eq!(
            outcomes[3],
            PromptOutcome::Decided(allow_once()),
            "one success between the failures resets the streak: the fourth \
             consultation must still show a dialog"
        );
        assert_eq!(
            handle.calls().len(),
            4,
            "every consultation here must reach the dialog"
        );
    }

    /// The accessor a reader reaches for during an incident must not double-count:
    /// a LIVE dialog holds an abandoned-pool permit too, so "8 parked
    /// consultations" used to report `live=8 abandoned=8` and made the diagnostic
    /// say twice the number of windows that exist.
    #[tokio::test]
    async fn abandoned_dialogs_does_not_count_the_dialogs_we_are_still_waiting_on() {
        let (handle, dialog) = fake_dialog();
        let coord = Arc::new(PromptCoordinator::with_dialog(dialog));
        // A budget the dialogs cannot outlive: nothing here is abandoned, every
        // dialog is one the coordinator is still waiting on.
        let cfg = cfg(Duration::from_secs(60), PromptPolicy::Deny);

        let leaders: Vec<_> = (0..MAX_CONCURRENT_PROMPTS)
            .map(|i| {
                let c = Arc::clone(&coord);
                tokio::spawn(async move {
                    c.prompt(&format!("live{i}.example.com"), 443, None, cfg)
                        .await
                })
            })
            .collect();
        handle.wait_for_calls(MAX_CONCURRENT_PROMPTS).await;

        assert_eq!(coord.live_consultations(), MAX_CONCURRENT_PROMPTS);
        assert_eq!(
            coord.abandoned_dialogs(),
            0,
            "no dialog has been abandoned: every one of those windows is still being awaited"
        );

        for i in 0..MAX_CONCURRENT_PROMPTS {
            handle.reply(&format!("live{i}.example.com"), Ok(deny_once()));
        }
        assert_eq!(futures_of(leaders).await.len(), MAX_CONCURRENT_PROMPTS);
        assert_eq!(coord.live_consultations(), 0);
        assert_eq!(coord.abandoned_dialogs(), 0);
    }

    // ---- P2.1 review round 2 --------------------------------------------------

    /// **Round 2, item 1: the dialog's cost is credited ONCE, by its leader.**
    ///
    /// `note_prompt_wait` was called per REQUEST, so K coalesced followers of one
    /// dialog each added that dialog's wall clock: four concurrent requests to one
    /// unlisted host credited four minutes for one minute of real blocking, and a
    /// workload that genuinely overran was then recorded as
    /// `prompt_budget_exhausted`. The coordinator now reports the wall clock its
    /// LEADER paid; a follower adds nothing, because the dialog was never its own.
    #[tokio::test]
    async fn one_dialog_is_credited_to_its_leader_and_no_follower_adds_to_it() {
        let (handle, dialog) = fake_dialog();
        let coord = Arc::new(PromptCoordinator::with_dialog(dialog));
        let cfg = cfg(Duration::from_secs(5), PromptPolicy::Deny);
        const FOLLOWERS: usize = 3;
        const DIALOG: Duration = Duration::from_millis(120);

        let leader = {
            let c = Arc::clone(&coord);
            tokio::spawn(async move {
                c.prompt_measured("credit.example.com", 443, None, cfg)
                    .await
            })
        };
        handle.wait_for_calls(1).await;
        let followers: Vec<_> = (0..FOLLOWERS)
            .map(|_| {
                let c = Arc::clone(&coord);
                tokio::spawn(async move {
                    c.prompt_measured("credit.example.com", 443, None, cfg)
                        .await
                })
            })
            .collect();
        FakeHandle::wait_parked(&coord, "credit.example.com", FOLLOWERS).await;
        // The dialog is open for as long as a user would sit in front of it.
        tokio::time::sleep(DIALOG).await;
        handle.reply("credit.example.com", Ok(allow_once()));

        let (out, leader_wait) = leader.await.unwrap();
        assert_eq!(out, PromptOutcome::Decided(allow_once()));
        let leader_wait = leader_wait.expect("the leader led the dialog and paid for it");
        let mut credited = leader_wait;
        for f in followers {
            let (out, follower_wait) = f.await.unwrap();
            assert_eq!(
                out,
                PromptOutcome::Decided(allow_once()),
                "one dialog answers every follower"
            );
            assert_eq!(
                follower_wait, None,
                "a follower was parked on the leader's dialog: it paid nothing of its own"
            );
            credited += follower_wait.unwrap_or(Duration::ZERO);
        }

        assert!(
            leader_wait >= DIALOG,
            "the leader's credit must be the dialog's own wall clock, got {leader_wait:?}"
        );
        assert_eq!(
            credited, leader_wait,
            "the aggregate is ONE dialog's wall clock, never {FOLLOWERS}x it"
        );
        assert_eq!(handle.calls().len(), 1, "one host, one dialog");
        println!("EVIDENCE one-dialog-credit followers={FOLLOWERS} leader_wait={leader_wait:?}");
    }

    /// **Round 2, item 5: two CONCURRENT consultations are one budget, not two
    /// pieces of evidence.** They start together and elapse at the same deadline,
    /// so arming at two let a single stalled dialog disable prompting with no grace
    /// consultation in between. Three consecutive observations tolerate two
    /// hiccups.
    #[tokio::test]
    async fn a_concurrent_pair_does_not_arm_the_fast_fail_but_a_third_consecutive_does() {
        let (handle, dialog) = fake_dialog();
        let coord = Arc::new(PromptCoordinator::with_dialog(dialog));
        let budget = Duration::from_millis(60);
        let cfg = cfg(budget, PromptPolicy::Deny);

        // Two leaders on DISTINCT hosts (same-host requests coalesce into ONE
        // consultation, which is a different question), no reply programmed: both
        // elapse at the same deadline.
        let pair: Vec<_> = ["pair-a.example.com", "pair-b.example.com"]
            .iter()
            .map(|host| {
                let c = Arc::clone(&coord);
                let host = host.to_string();
                tokio::spawn(async move { c.prompt(&host, 443, None, cfg).await })
            })
            .collect();
        for t in pair {
            assert_eq!(
                t.await.unwrap(),
                PromptOutcome::Unavailable {
                    allowed: false,
                    cause: UnavailableCause::BudgetElapsed,
                }
            );
        }
        assert_eq!(handle.calls().len(), 2, "two hosts, two dialogs");

        // A third consecutive consultation is still consulted: a pair that elapsed
        // together is one budget's worth of evidence.
        let third = coord.prompt("pair-c.example.com", 443, None, cfg).await;
        assert_eq!(
            third,
            PromptOutcome::Unavailable {
                allowed: false,
                cause: UnavailableCause::BudgetElapsed,
            },
            "a concurrent pair must not arm the fast-fail: the third still consults"
        );
        assert_eq!(handle.calls().len(), 3);

        // Now it is armed: the fourth is refused without a dialog.
        let fourth = coord.prompt("pair-d.example.com", 443, None, cfg).await;
        assert!(
            matches!(fourth, PromptOutcome::Unavailable { allowed: false, .. }),
            "got {fourth:?}"
        );
        assert_eq!(
            handle.calls().len(),
            3,
            "an armed latch must not spawn another dialog"
        );
    }

    /// **Round 2, item 4: the fast-fail is the DENY posture's answer only.** Under
    /// `on_unavailable = allow` the latch *permitted* every later unlisted host with
    /// no dialog at all - silently removing the user's veto, the opposite of
    /// "degrades to deny". A headless + allow configuration is the operator's
    /// explicit choice, and it keeps consulting (and paying the per-host budget).
    #[tokio::test]
    async fn the_fast_fail_never_applies_to_the_allow_policy() {
        let (handle, dialog) = fake_dialog();
        let coord = Arc::new(PromptCoordinator::with_dialog(dialog));
        let cfg = cfg(Duration::from_millis(40), PromptPolicy::Allow);

        for i in 0..5 {
            let out = coord
                .prompt(&format!("allow-{i}.example.com"), 443, None, cfg)
                .await;
            assert_eq!(
                out,
                PromptOutcome::Unavailable {
                    allowed: true,
                    cause: UnavailableCause::BudgetElapsed,
                },
                "host {i}: allow answers, but only after the dialog was consulted"
            );
        }
        assert_eq!(
            handle.calls().len(),
            5,
            "under allow every host gets its own consultation"
        );
    }

    /// **Round 2, item 3: the latch re-probes after a cooldown, so it is not
    /// one-way.** Nothing spawns a dialog while armed, so the `Decided` reset was
    /// unreachable: an operator who came back and clicked the still-open dialog had
    /// their answer discarded, with no recovery but restarting the run. After the
    /// cooldown one consultation consults again, and an answer un-arms the latch.
    #[tokio::test]
    async fn an_armed_latch_reprobes_after_its_cooldown_and_a_decision_un_arms_it() {
        let (handle, dialog) = fake_dialog();
        // A cooldown long enough to observe the difference between "since the latch
        // armed" and "since the last skipped consultation": the skips below are spread
        // across it (round 2, item 3's clock).
        const COOLDOWN: Duration = Duration::from_millis(100);
        let coord = Arc::new(PromptCoordinator::with_cooldown(
            dialog,
            NO_BACKEND_STICKY_AFTER,
            COOLDOWN,
        ));
        let cfg = cfg(Duration::from_secs(60), PromptPolicy::Deny);
        for i in 0..NO_BACKEND_STICKY_AFTER {
            handle.reply(&format!("armed-{i}.example.com"), Err(DialogUnavailable));
        }

        for i in 0..NO_BACKEND_STICKY_AFTER {
            let out = coord
                .prompt(&format!("armed-{i}.example.com"), 443, None, cfg)
                .await;
            assert_eq!(
                out,
                PromptOutcome::Unavailable {
                    allowed: false,
                    cause: UnavailableCause::NoDialogBackend,
                },
                "host {i} consults (and finds no backend)"
            );
        }
        assert_eq!(handle.calls().len(), NO_BACKEND_STICKY_AFTER);

        // Armed: no dialog while the cooldown runs — and a skipped consultation does
        // NOT restart the cooldown, or a session under steady traffic would push its own
        // re-probe out for ever.
        let skipped = coord.prompt("armed-cold.example.com", 443, None, cfg).await;
        assert_eq!(
            skipped,
            PromptOutcome::Unavailable {
                allowed: false,
                cause: UnavailableCause::NoDialogBackend,
            }
        );
        assert_eq!(
            handle.calls().len(),
            NO_BACKEND_STICKY_AFTER,
            "the cooldown has not run out: nothing is consulted"
        );
        tokio::time::sleep(COOLDOWN / 2).await;
        let skipped_again = coord
            .prompt("armed-colder.example.com", 443, None, cfg)
            .await;
        assert!(
            matches!(skipped_again, PromptOutcome::Unavailable { .. }),
            "still armed halfway through the cooldown: {skipped_again:?}"
        );
        assert_eq!(
            handle.calls().len(),
            NO_BACKEND_STICKY_AFTER,
            "a skipped consultation must not spawn a dialog either"
        );

        // The operator came back: the next consultation after the cooldown — counted
        // from ARMING, not from the last skip — gets a dialog again, and its answer
        // resets the streak.
        tokio::time::sleep(COOLDOWN / 2 + Duration::from_millis(20)).await;
        handle.reply("armed-warm.example.com", Ok(deny_once()));
        let warmed = coord.prompt("armed-warm.example.com", 443, None, cfg).await;
        assert_eq!(
            warmed,
            PromptOutcome::Decided(deny_once()),
            "a returning user must get their dialog back"
        );
        assert_eq!(handle.calls().len(), NO_BACKEND_STICKY_AFTER + 1);

        // ...and the latch is un-armed, so the NEXT host is consulted too rather
        // than waiting for another cooldown.
        handle.reply("armed-after.example.com", Err(DialogUnavailable));
        let next = coord
            .prompt("armed-after.example.com", 443, None, cfg)
            .await;
        assert_eq!(
            next,
            PromptOutcome::Unavailable {
                allowed: false,
                cause: UnavailableCause::NoDialogBackend,
            },
            "one success un-arms the latch: the streak starts again"
        );
        assert_eq!(handle.calls().len(), NO_BACKEND_STICKY_AFTER + 2);
    }

    /// Await a batch of spawned tasks, preserving order.
    async fn futures_of(tasks: Vec<tokio::task::JoinHandle<PromptOutcome>>) -> Vec<PromptOutcome> {
        let mut out = Vec::with_capacity(tasks.len());
        for t in tasks {
            out.push(t.await.unwrap());
        }
        out
    }
}
