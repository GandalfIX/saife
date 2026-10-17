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
//! Semaphore ([G-28]): at most [`MAX_CONCURRENT_PROMPTS`] (8) concurrent
//! dialogs. The 9th prompt for a NEW host is immediately denied
//! ([`PromptOutcome::Overloaded`], audited as source `prompt_overload`
//! by 3.6). The permit is held until the dialog call returns — including
//! by an orphaned dialog after a timeout ([G-4]) — so at most 8 live
//! dialogs exist at any time.
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
//!   static import. The sandbox binary embeds no manifest (adding one
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
//!   `SANDBOX_DIAG` stderr diagnostic (ADR D-3): "no dialog backend
//!   available; all non-allow-listed hosts denied; use `--allow-domain`
//!   or `--network-profile` to pre-approve, or set
//!   `on_unavailable=allow` (insecure)".
//! - `network.promptEnabled` / `--no-prompt` gating ([G-36, G-47]) must
//!   be checked BEFORE calling the coordinator: this module only models
//!   the zero-timeout form (`timeout == 0` → [`PromptOutcome::Disabled`],
//!   audit source `default`); when prompting is disabled outright, 3.6
//!   must not construct a coordinator call at all.
//! - Consider including a live-dialog count in prompt audit events:
//!   orphaned dialogs hold their permits until their dialog completes
//!   ([G-4]) — enough orphans and 3.6 reports `prompt_overload` with no
//!   visible dialogs left on screen; a live count makes that state
//!   diagnosable from the audit trail.
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

#![allow(dead_code)]

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use tokio::sync::{Mutex, Semaphore, oneshot};
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

/// Default prompt timeout: 60 seconds ([G-46]; ADR field
/// `network.promptTimeoutSecs`).
pub const DEFAULT_PROMPT_TIMEOUT: Duration = Duration::from_secs(60);

/// Maximum number of concurrently live dialogs ([G-28]).
pub const MAX_CONCURRENT_PROMPTS: usize = 8;

// Custom TaskDialog button ids: arbitrary nonzero values that must not
// collide with the reserved common-button ids (IDOK=1, IDCANCEL=2, ...).
const ID_ALLOW_ONCE: i32 = 101;
const ID_ALLOW_PERM_HOST: i32 = 102;
const ID_ALLOW_PERM_SUFFIX: i32 = 103;
const ID_DENY_ONCE: i32 = 104;
const ID_DENY_PERM_HOST: i32 = 105;
const ID_DENY_PERM_SUFFIX: i32 = 106;
const ID_EXPLAIN_MORE: i32 = 107;
/// `winuser.h` IDCANCEL (kept as a plain literal: windows-rs types the
/// constant as `MESSAGEBOX_RESULT`, while `TaskDialogIndirect` reports a
/// plain button id). With `TDF_ALLOW_DIALOG_CANCELLATION`, the title-bar
/// X and Esc produce this id ([G-3, G-43]: cancel = Deny once).
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

/// Caller-supplied prompt behavior (ADR fields `network.promptTimeoutSecs`
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
    /// All [`MAX_CONCURRENT_PROMPTS`] permits are held and this was a
    /// NEW host ([G-28]). Audit source `prompt_overload`.
    Overloaded,
    /// Timeout or dialog backend failure ([G-4, G-19, G-46]); the
    /// `on_unavailable` policy has already been applied. Audit source
    /// `unavailable`.
    Unavailable {
        /// The applied policy: `true` only when `on_unavailable` is
        /// `Allow` ([G-46]).
        allowed: bool,
    },
    /// Zero timeout: the prompt is disabled for this profile ([G-46]).
    /// Instant deny; no dialog was attempted. Audit source `default`
    /// (same as `--no-prompt`).
    Disabled,
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

/// Build and show the seven-button task dialog (inner of
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
    let label_allow_host = HSTRING::from("Allow permanently (this host)");
    let label_allow_suffix = HSTRING::from(format!("Allow permanently (*.{suffix_hint})"));
    let label_deny_once = HSTRING::from("Deny once");
    let label_deny_host = HSTRING::from("Deny permanently (this host)");
    let label_deny_suffix = HSTRING::from(format!("Deny permanently (*.{suffix_hint})"));
    let label_explain_more = HSTRING::from("Explain more");

    let buttons = [
        TASKDIALOG_BUTTON {
            nButtonID: ID_ALLOW_ONCE,
            pszButtonText: PCWSTR(label_allow_once.as_ptr()),
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
        // Command links fit the six long labels; no TDF_NO_FOCUS → the
        // dialog is foreground-activated and grabs input focus ([G-37]);
        // SIZE_TO_CONTENT fits the seven rows without scrolling;
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

/// Fire the courtesy toast on a separate thread ([G-2, G-3]). Fire and
/// forget — every error is swallowed by design. The toast is a
/// secondary, non-intrusive channel and may legitimately no-op (no
/// interactive desktop, toasts disabled, AUMID quirks for unpackaged
/// console apps); the dialog alone carries the decision.
fn spawn_toast(host: &str, port: u16) {
    let host = host.to_string();
    let _ = std::thread::Builder::new()
        .name("sandbox-prompt-toast".to_string())
        .spawn(move || {
            let _ = fire_toast(&host, port);
        });
}

/// Toast body ([G-2, G-3]); runs on the toast thread, best-effort.
fn fire_toast(host: &str, port: u16) -> windows::core::Result<()> {
    // WinRT activation needs an apartment on this thread.
    let hr = unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED) };
    if hr.is_err() && hr != RPC_E_CHANGED_MODE {
        return Err(hr.into());
    }
    let result = toast_inner(host, port);
    if hr.is_ok() {
        unsafe { CoUninitialize() };
    }
    result
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
/// coalescing ([G-6]), the 8-dialog semaphore ([G-28]) and the timeout +
/// fallback policy ([G-4, G-19, G-46]) around one blocking dialog call.
pub struct PromptCoordinator {
    /// Caps concurrent live dialogs at [`MAX_CONCURRENT_PROMPTS`]
    /// ([G-28]).
    permits: Arc<Semaphore>,
    /// Normalized hostname → parked followers of the in-flight leader
    /// ([G-6]); shared with the supervisor tasks (see [`WaiterMap`]).
    waiters: WaiterMap,
    /// The injected dialog backend (real: [`show_dialog`]; tests: fake).
    dialog: DialogFn,
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
        Self {
            permits: Arc::new(Semaphore::new(MAX_CONCURRENT_PROMPTS)),
            waiters: Arc::new(Mutex::new(HashMap::new())),
            dialog,
        }
    }

    /// Ask the user about one request and await the outcome. `config`
    /// supplies the timeout and fallback policy per call ([G-46, G-48]).
    pub async fn prompt(
        &self,
        host: &str,
        port: u16,
        reason: Option<String>,
        config: PromptConfig,
    ) -> PromptOutcome {
        // [G-46] ZERO timeout = the prompt is disabled for this profile:
        // instant deny, no dialog attempt, no coalescing entry.
        if config.timeout == Duration::ZERO {
            return PromptOutcome::Disabled;
        }

        // [G-6] Key by normalized hostname only (port ignored; case,
        // port and trailing dot normalized the same way as the intent
        // registry).
        let key = crate::net::intent::normalize_host(host);

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
                entry.lock().expect("prompt waiter list poisoned").push(tx);
                Role::Follower(rx)
            } else {
                let entry = Arc::new(StdMutex::new(Vec::new()));
                map.insert(key.clone(), Arc::clone(&entry));
                Role::Leader(entry)
            }
        };

        match role {
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
                match tokio::time::timeout(config.timeout, rx).await {
                    Ok(Ok(outcome)) => outcome,
                    // Our deadline hit, or the leader vanished without
                    // delivering (a bug) — either way the policy
                    // applies, never a silent allow ([G-46]).
                    Ok(Err(_)) | Err(_) => unavailable_from(&config),
                }
            }
            Role::Leader(entry) => {
                // [G-28] Only the leader takes a permit. If all
                // [`MAX_CONCURRENT_PROMPTS`] are in flight, this NEW
                // host is denied immediately without a dialog.
                let permit = Arc::clone(&self.permits).try_acquire_owned();

                // Plan Step 3: the dialog runs on the blocking pool so
                // the async handler never blocks a tokio worker. The
                // permit rides along and is released exactly when the
                // dialog call returns — including by an orphaned dialog
                // after a timeout ([G-4]) — so at most 8 dialogs are
                // ever live ([G-28]).
                let dialog_task = permit.ok().map(|permit| {
                    let req = DialogRequest {
                        host: host.to_string(),
                        port,
                        reason,
                        suffix_hint: compute_suffix_hint(host),
                    };
                    let dialog = Arc::clone(&self.dialog);
                    tokio::task::spawn_blocking(move || {
                        let _permit = permit;
                        dialog(&req)
                    })
                });

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
                let (mut report_tx, report) = oneshot::channel::<PromptOutcome>();
                let waiters = Arc::clone(&self.waiters);
                let supervised_entry = Arc::clone(&entry);
                tokio::spawn(async move {
                    let outcome = match dialog_task {
                        Some(handle) => {
                            // Plan Step 6: await the dialog under the
                            // caller's timeout.
                            tokio::select! {
                                // The caller's future was dropped
                                // mid-prompt: finish now with the
                                // fallback outcome so parked followers
                                // are released promptly ([G-6, G-46]).
                                _ = report_tx.closed() => {
                                    unavailable_from(&config)
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
                                            unavailable_from(&config)
                                        }
                                        // Timed out: the orphaned
                                        // dialog stays on screen and
                                        // its late result is discarded
                                        // ([G-4]); the policy decides
                                        // — never a silent allow
                                        // ([G-46]).
                                        Err(_) => {
                                            unavailable_from(&config)
                                        }
                                    }
                                }
                            }
                        }
                        // [G-28] All permits held: this NEW host was
                        // denied immediately and no dialog was
                        // attempted, but the entry still must be
                        // finished — followers that parked in the
                        // election→deny window receive the Overloaded
                        // outcome.
                        None => PromptOutcome::Overloaded,
                    };
                    Self::finish(&waiters, &key, &supervised_entry, outcome.clone()).await;
                    let _ = report_tx.send(outcome);
                });
                match report.await {
                    Ok(outcome) => outcome,
                    // The supervisor always finishes cleanup before
                    // reporting; a closed channel means it panicked —
                    // fail closed, never a silent allow ([G-46]).
                    Err(_) => unavailable_from(&config),
                }
            }
        }
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
        let parked = std::mem::take(&mut *entry.lock().expect("prompt waiter list poisoned"));
        for tx in parked {
            // A waiter may have hit its own deadline already — send
            // errors are expected and ignored.
            let _ = tx.send(outcome.clone());
        }
    }
}

/// Apply the `on_unavailable` policy to a non-decision ([G-19, G-46]).
fn unavailable_from(config: &PromptConfig) -> PromptOutcome {
    PromptOutcome::Unavailable {
        allowed: matches!(config.on_unavailable, PromptPolicy::Allow),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
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
        assert_eq!(ninth, PromptOutcome::Overloaded);
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
        let start = Instant::now();
        let out = coord.prompt("api.example.com", 443, None, cfg).await;
        assert_eq!(out, PromptOutcome::Disabled);
        assert!(handle.calls().is_empty(), "no dialog may be attempted");
        assert!(start.elapsed() < Duration::from_millis(500));
    }

    // ---- timeout ([G-4, G-46]) ----------------------------------------------

    #[tokio::test]
    async fn timeout_returns_unavailable_deny() {
        let (handle, dialog) = fake_dialog();
        let coord = PromptCoordinator::with_dialog(dialog);
        let cfg = cfg(Duration::from_millis(100), PromptPolicy::Deny);

        let out = coord.prompt("slow.example.com", 443, None, cfg).await;
        assert_eq!(out, PromptOutcome::Unavailable { allowed: false });
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
        assert_eq!(out, PromptOutcome::Unavailable { allowed: true });
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
            PromptOutcome::Unavailable { allowed: false }
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
        assert_eq!(out, PromptOutcome::Unavailable { allowed: false });

        handle.reply("api.example.com", Err(DialogUnavailable));
        let out = coord
            .prompt(
                "api.example.com",
                443,
                None,
                cfg(Duration::from_secs(60), PromptPolicy::Allow),
            )
            .await;
        assert_eq!(out, PromptOutcome::Unavailable { allowed: true });

        assert_eq!(handle.calls().len(), 2);
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
