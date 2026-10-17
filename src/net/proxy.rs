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

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::Mutex as StdMutex;

use anyhow::{Context, Result};
use base64::Engine;
use subtle::ConstantTimeEq;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::runtime::Runtime;
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;

use crate::audit::AuditWriter;
use crate::net::intent::IntentRegistry;
use crate::net::learned::{LearnedDecision, LearnedStore};
use crate::net::matcher::{self, DenyReason, Verdict};
use crate::net::prompt::{
    PromptConfig, PromptCoordinator, PromptOutcome, PromptPolicy, PromptResult, is_loopback_host,
};
use crate::net::upstream::{UpstreamDialer, UpstreamError};

/// The complete set of valid `source` values for a CONNECT audit event
/// (D-5 taxonomy). Kept as a const so future validation logic and tests
/// share a single source of truth; no production call site consumes it yet
/// (only tests reference it), so it is `#[allow(dead_code)]` until the D-5
/// validator lands.
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
    pub token: String,
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
    token: String,
    deny: Vec<String>,
    allow: Vec<String>,
    writer: Arc<AuditWriter>,
    upstream: Option<Arc<UpstreamDialer>>,
    prompt: PromptGate,
}

/// Emit a CONNECT audit leaf directly through the threaded `AuditWriter`
/// (replaces the per-call `audit::emit_connect` wrapper, which opened the
/// writer fresh on each event).
//
// The 8-arg signature is mandated by D-5.1 Step 1 (host, port, disposition,
// reason, source, scope, persisted + writer); folding into a struct would
// diverge from the spec, so the clippy lint is suppressed here only.
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
    writer.append(e)?;
    Ok(())
}

pub struct ProxyHandle {
    pub port: u16,
    cancel: CancellationToken,
    rt: Option<Runtime>,
    join: Option<tokio::task::JoinHandle<()>>,
}

impl ProxyHandle {
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
    let ctx = Arc::new(ConnCtx {
        token,
        deny: deny_domain,
        allow: allow_domain,
        writer,
        upstream,
        prompt,
    });

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(1)
        .build()?;

    let (port_tx, port_rx) = oneshot::channel::<u16>();
    let cancel = CancellationToken::new();
    let cancel_for_task = cancel.clone();

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
        cancel,
        rt: Some(rt),
        join: Some(join),
    })
}

/// Check `Proxy-Authorization: Basic <base64(sandbox:token)>` against the
/// session token. Constant-time comparison via `subtle::ConstantTimeEq`.
/// Returns false if the header is missing, malformed, or the token doesn't match.
fn check_proxy_auth(head: &str, expected_token: &str) -> bool {
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
        return false;
    };

    // Expect "Basic <base64>" — accept any whitespace (RFC 7230 allows 1*SP).
    let mut parts = auth_value.split_whitespace();
    let scheme = parts.next().unwrap_or("");
    let b64 = parts.next().unwrap_or("");
    if !scheme.eq_ignore_ascii_case("Basic") || b64.is_empty() {
        return false;
    }

    // Decode base64 -> "sandbox:<token>".
    let decoded = match base64::engine::general_purpose::STANDARD.decode(b64) {
        Ok(d) => d,
        Err(_) => return false,
    };
    let decoded_str = match std::str::from_utf8(&decoded) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let (_, password) = decoded_str.split_once(':').unwrap_or(("", ""));

    // Constant-time compare.
    // NOTE: ct_eq leaks length on unequal-length slices; acceptable for a
    // localhost proxy with a fixed-length session token.
    password.as_bytes().ct_eq(expected_token.as_bytes()).into()
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

/// Race the (DNS-pinned) address list in batches of [`MAX_PARALLEL_DIALS`]:
/// the first successful connection wins, stragglers are aborted. A loser
/// that already connected is closed when its task is dropped — half-open
/// sockets are never spliced into a tunnel.
pub(crate) async fn happy_eyeballs_dial(addrs: Vec<SocketAddr>) -> io::Result<TcpStream> {
    let mut last_err = None;
    for start in (0..addrs.len()).step_by(MAX_PARALLEL_DIALS) {
        let end = (start + MAX_PARALLEL_DIALS).min(addrs.len());
        let batch = &addrs[start..end];
        let (tx, mut rx) = mpsc::channel(batch.len());
        let mut spawned = Vec::with_capacity(batch.len());
        for &addr in batch {
            let tx = tx.clone();
            spawned.push(tokio::spawn(async move {
                let _ = tx.send(TcpStream::connect(addr).await).await;
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
        for h in spawned {
            h.abort();
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
        PromptOutcome::Overloaded => OutcomeAudit {
            allowed: false,
            source: "prompt_overload",
            scope: None,
            wants_persist: false,
        },
        PromptOutcome::Unavailable { allowed } => OutcomeAudit {
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
    let outcome = ctx
        .prompt
        .coordinator
        .prompt(host, port, reason, ctx.prompt.config)
        .await;
    // Outcome side effects that are not the decision itself.
    if let PromptOutcome::Decided(PromptResult::NeedsIntent) = &outcome {
        // omac's recovery loop: the "Explain more" click rides the intent
        // registry (the deny body may be discarded by the client); the
        // agent's next GET /sandbox/intent observes the one-shot flag.
        ctx.prompt.intent.mark_explain_more(host).await;
    }
    if let PromptOutcome::Unavailable { allowed: false } = &outcome {
        // [G-19] one discoverable stderr line, once per process.
        warn_no_dialog_once();
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
        PromptOutcome::Overloaded => Some("too many concurrent prompts".into()),
        PromptOutcome::Unavailable { allowed: false } => {
            Some("prompt unavailable (timeout or no dialog backend)".into())
        }
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
async fn resolve_pinned(host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
    let h = strip_host_brackets(host.trim());
    if let Ok(ip) = h.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    tokio::net::lookup_host((h, port))
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
/// admission — no [`resolve_pinned`], no DNS-failure denial, no pinned-IP
/// hard-deny ([G-22]). The upstream proxy resolves the name itself, and a
/// local answer could disagree with what it sees. The hostname-set and
/// IP-literal hard-denies already ran in [`decide`] before admission and need
/// no DNS, so they still apply here.
///
/// Direct: pin once ([G-12]), hard-deny the pinned set, then race the addresses
/// with Happy Eyeballs ([G-49] keeps that path intact).
async fn dial_upstream(
    upstream: Option<&UpstreamDialer>,
    host: &str,
    port: u16,
) -> Result<TcpStream, DialFailure> {
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

    let addrs = match resolve_pinned(host, port).await {
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
    if addrs.iter().any(|sa| matcher::is_hard_denied_ip(sa.ip())) {
        return Err(DialFailure::Denied(denied_by(DenyReason::DeniedCidr)));
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
    // /sandbox/* endpoint ([G-7, G-38]).
    if !check_proxy_auth(head, &ctx.token) {
        let _ = sock
            .write_all(
                b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"sandbox\"\r\nContent-Length: 0\r\n\r\n",
            )
            .await;
        let _ = emit_connect(
            &ctx.writer,
            "<unknown>",
            0,
            "deny",
            Some("no_token"),
            "default",
            None,
            false,
        );
        return Ok(());
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
    let mut upstream_stream = match dial_upstream(ctx.upstream.as_deref(), &host, port).await {
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

/// Route an authenticated non-CONNECT request through the /sandbox/*
/// control plane (D-4). The listener never forwards plain HTTP: a
/// forwarded request would bypass the admission pipeline entirely, so
/// absolute- or origin-form requests outside /sandbox/ get a 400
/// ([G-7, G-38]).
async fn handle_non_connect(
    mut sock: TcpStream,
    ctx: Arc<ConnCtx>,
    method: &str,
    target: &str,
    head: &str,
    leftover: &[u8],
) -> Result<()> {
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

    fn make_head(auth: &str) -> String {
        format!("CONNECT api.example.com:443 HTTP/1.1\r\nProxy-Authorization: {auth}\r\n\r\n")
    }

    #[test]
    fn valid_basic_auth() {
        let token = "abc123";
        let creds = base64::engine::general_purpose::STANDARD.encode(format!("sandbox:{token}"));
        let head = make_head(&format!("Basic {creds}"));
        assert!(check_proxy_auth(&head, token));
    }

    #[test]
    fn missing_auth_header() {
        let head = "CONNECT api.example.com:443 HTTP/1.1\r\nHost: api.example.com\r\n\r\n";
        assert!(!check_proxy_auth(head, "abc123"));
    }

    #[test]
    fn wrong_token() {
        let creds = base64::engine::general_purpose::STANDARD.encode("sandbox:wrong");
        let head = make_head(&format!("Basic {creds}"));
        assert!(!check_proxy_auth(&head, "abc123"));
    }

    #[test]
    fn wrong_scheme() {
        let creds = base64::engine::general_purpose::STANDARD.encode("sandbox:abc123");
        let head = make_head(&format!("Bearer {creds}"));
        assert!(!check_proxy_auth(&head, "abc123"));
    }

    #[test]
    fn case_insensitive_header_name() {
        let token = "abc123";
        let creds = base64::engine::general_purpose::STANDARD.encode(format!("sandbox:{token}"));
        let head = format!("CONNECT x:443 HTTP/1.1\r\nproxy-AUTHORIZATION: Basic {creds}\r\n\r\n");
        assert!(check_proxy_auth(&head, token));
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
        let a = super::outcome_audit(&PromptOutcome::Overloaded);
        assert!(!a.allowed);
        assert_eq!(a.source, "prompt_overload");
        assert_eq!(a.scope, None);
        assert!(!a.wants_persist);
    }

    #[test]
    fn outcome_audit_unavailable_respects_policy() {
        let deny = super::outcome_audit(&PromptOutcome::Unavailable { allowed: false });
        assert!(!deny.allowed);
        assert_eq!(deny.source, "unavailable");
        assert_eq!(deny.scope, None);

        let allow = super::outcome_audit(&PromptOutcome::Unavailable { allowed: true });
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
        let handle = super::spawn(super::ProxyConfig {
            session_id: sid.clone(),
            token: TEST_TOKEN.to_string(),
            allow_domain: allow.iter().map(|s| s.to_string()).collect(),
            deny_domain: deny.iter().map(|s| s.to_string()).collect(),
            upstream,
            writer,
            prompt: gate,
        })
        .expect("spawn test proxy");
        let port = handle.port;
        T36 {
            handle,
            port,
            sid,
            intent,
            learned,
            learned_base,
        }
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
        let creds =
            base64::engine::general_purpose::STANDARD.encode(format!("sandbox:{TEST_TOKEN}"));
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

    #[test]
    fn non_sandbox_non_connect_requests_get_400() {
        let (dialog, _c) = recording_dialog(Ok(deny_once_result()));
        let t = t36_setup("plain-http-400", &[], &[], dialog);
        // Absolute-form (forward-proxy style) request.
        let resp = exchange(t.port, &get_req("http://evil.example.com/"));
        assert!(resp.starts_with("HTTP/1.1 400"), "got: {resp}");
        // Origin-form request to a non-/sandbox path.
        let resp = exchange(t.port, &get_req("/some/path"));
        assert!(resp.starts_with("HTTP/1.1 400"), "got: {resp}");
    }

    #[test]
    fn sandbox_unknown_path_is_404() {
        let (dialog, _c) = recording_dialog(Ok(deny_once_result()));
        let t = t36_setup("sandbox-404", &[], &[], dialog);
        let resp = exchange(t.port, &get_req("/sandbox/other"));
        assert!(resp.starts_with("HTTP/1.1 404"), "got: {resp}");
    }

    #[tokio::test]
    async fn resolve_pinned_literal_ip_skips_the_resolver() {
        let addrs = super::resolve_pinned("192.0.2.7", 8443).await.unwrap();
        assert_eq!(addrs, vec!["192.0.2.7:8443".parse::<SocketAddr>().unwrap()]);
        let addrs = super::resolve_pinned("[2001:db8::9]", 443).await.unwrap();
        assert_eq!(
            addrs,
            vec!["[2001:db8::9]:443".parse::<SocketAddr>().unwrap()]
        );
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
            token: TEST_TOKEN.to_string(),
            deny: Vec::new(),
            allow: vec!["api.example.com".to_string()],
            writer,
            upstream: Some(dialer(&format!("http://127.0.0.1:{upstream_port}"), &[])),
            prompt,
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
