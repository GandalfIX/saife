# MXC ProcessContainer Migration Plan (ADR-0004 Option A)

> **For agentic workers:** task-by-task with TDD where code changes; each task
> ends with gates, a PROGRESS row and a review pass (spec + quality). Steps use
> checkbox syntax for tracking.

**Goal:** replace this project's hand-rolled AppContainer *containment* (network
+ filesystem) with `mxc-sdk 1.0.1`'s `processcontainer`, so network-enabled
sessions run **unelevated** on GA Windows while D-1…D-5 (filter pipeline,
prompts, learned store, intent registry, audit) stay ours and unchanged in
behaviour. The AppContainer supervisor remains available as an explicit
fallback until P3, then its containment code is deleted in P4.

**Architecture:** the supervisor keeps owning the proxy, the decision pipeline,
the dialog and the audit. MXC owns the *container*: it guarantees the child can
reach nothing except our proxy (`egress.default=deny` + `runtimeConfig.networkProxy`
+ `ingress.hostLoopback=allow`) and enforces the filesystem policy declared in
the request. Two guardrails from ADR-0004 are structural: a **post-launch proxy
proof** (hard gate) and a **per-session tier record**.

**Tech Stack:** Rust 2021 (`mxc-sdk = "=1.0.1"` from crates.io, exact pin),
existing tokio proxy, PowerShell 7 harness, Hyper-V disposable-VM runner
(`Invoke-TestsInVM.ps1`, images A and B).

**Evidence:** `docs/adr/0004-mxc-ga-windows-unelevated-egress.md` (Accepted),
`tests/vm/spikes/mxc-ga-spike/` (reproducible: `cargo run --release --bin mxc-ga-spike`).

**Non-goals / what MXC does NOT provide** (verified in the prototype, do not
re-litigate): no prompt/intent dialog, no learned store, no audit taxonomy or
per-request attribution, no hostname egress rules (only CIDR/port), no
`require_tier`, no pre-run attestation, no `NO_PROXY` injection, no proxy
identity for an unpackaged proxy, and no way to opt out of private-network
inbound while proxy mode is on.

---

## Invariants (binding)

1. **No claim of attestation.** ADR-0002's gap stands at 1.0.1; the posture is
   ADR-0003's bounded one. Documentation and CLI help must not imply otherwise.
2. **Guardrail 1 is a hard gate.** A session is successful only if the proxy can
   prove `accepted >= 1 AND tunnels_established >= 1` for *this* launch. There
   is no warn-and-continue path.
3. **Guardrail 2 is mandatory.** The tier actually dispatched is written to a
   **session-start** audit leaf.
4. **The proxy binds 127.0.0.1 only** and never forwards to a loopback target.
5. **Host proxy env never crosses into the container.** `HTTPS_PROXY`/`HTTP_PROXY`
   from the caller's environment must not appear in `request.environment`.
6. **One launch per proxy instance** until P1.4 lands the per-run token.
7. **Fallback stays intact** until P3 parity is proven on both images.

## Constraints discovered in the prototype (design inputs, not options)

- `ingress.default: "allow"` is **required** for proxy-only egress and grants the
  **bidirectional** `privateNetworkClientServer` capability → private-network
  inbound is permitted. Documented in ADR-0004; revisit in R2.
- The only workable deployment for a caller-owned unpackaged proxy is the
  identity-less one upstream labels *development/testing compatibility*
  (`allowedProxyPeer` omitted + `hostLoopback: "allow"`). `allowedProxyPeer`
  takes a package family name / AppContainer profile, never `host:port`
  (a `host:port` peer fails request build with `malformed_request`).
- Filesystem policy is **additive grants**: `C:\Windows\win.ini` stayed readable.
  "Workspace only" therefore needs `deniedPaths`, not omission.
- MXC injects `HTTP_PROXY`/`HTTPS_PROXY` (upper + lower) and leaves `NO_PROXY`
  **unset** — D-4 intent endpoints need `NO_PROXY=localhost,127.0.0.1,::1`
  injected by us.
- `timeout_ms` bounds the **whole workload**, which must therefore fit the
  prompt budget (60 s default) plus the workload budget.

---

## P1 design decisions required before wiring (from the P0 reviews)

**D1 — NO_PROXY cannot be delivered through `request.environment` (blocking for
P1.2).** mxc-sdk 1.0.1 strips `HTTP_PROXY`/`HTTPS_PROXY`/`NO_PROXY`/`ALL_PROXY`
(case-insensitive) when a proxy is configured and re-injects only uppercase
`HTTP_PROXY`/`HTTPS_PROXY` (`appcontainer_runner.rs:86`, `:209-234`,
`:260-272`). The child therefore has no `NO_PROXY`, so a request to
`http://127.0.0.1:<proxy>/sandbox/intent` would be proxied into a loop.

Chosen approach (P1.2a): **wrapper launcher** — the container command becomes a
small supervisor-owned exe that sets `NO_PROXY=localhost,127.0.0.1,::1` (and any
other env we cannot deliver through the request), starts the real workload with
inherited stdio, and propagates the exit code. Fallback if the wrapper proves
too invasive: serve the intent endpoints on a **separate loopback port** and
document that clients bypass the proxy for it. File an upstream ask either way
(allow NO_PROXY through, or inject it alongside the proxy vars).

**D2 — `inherit_default_environment`.** `Some(true)` layers our list over the
user's PROFILE environment (not the caller's process env) and proxy names are
stripped when a proxy is configured. P1 decides between `Some(false)` (strict
allow-list) and `Some(true)` + explicit denials; the code comment must match the
SDK's real semantics either way.

**D3 — guardrail 1 has no offline branch.** `verify_proxy_proof` demands
`tunnels >= 1` while a proxy-less request builds `egress=deny` +
`host_loopback=deny`, so a no-network session can never pass. P1 must either
exempt no-network sessions explicitly (and say so in the ADR) or require a proxy
for every MXC launch.

**D4 — epoch lifecycle and backend state.** `ProxyProofSource` has no `cancel`;
a `v1::run` error abandons an open epoch. P1.1 makes epochs per-launch-object
(or adds a cancel path), turns `MxcBackend` into a state-carrying struct, and
adds `Send + Sync` if the trait is held across an await.

**D5 — timeout budget (corrected in P1 wave 1).** `timeout_ms: None` is carried
as `0` and `get_timeout_milliseconds(0)` returns `u32::MAX` — **no deadline at
all**, not the 30 s the earlier plan text assumed
(`policy/exact/v1_0.rs:311`, `core/mxc_common/script_runner.rs:54-60`). The real
hazard is therefore an UNBOUNDED child, not a silently capped one. P2.1 must set
the budget explicitly (`prompt + workload + slack`), and P1 must not let a
caller-supplied `timeout_ms` be silently replaced by a backend default of None.

**D6 — housekeeping.** Remove `#![cfg_attr(not(test), allow(dead_code))]` from
`src/net/mxc.rs` when main.rs routes through the backend, and set the
`ProcessContainerConfig` UI fields explicitly instead of relying on today's
defaults.

**D7 — in-container probes must not rely on PowerShell (found in P1 wave 1).**
`powershell.exe` exits `0xC0000142` (`STATUS_DLL_INIT_FAILED`) as a container
child in this launch shape on this host, with `warnings=[]` and no output, while
`cmd.exe` and `curl.exe` work. Our harness scenarios S-75/S-77 spawn
`powershell` as the sandbox child (they were rewritten to managed code *inside*
the script, but the interpreter itself is still PowerShell). Under the MXC
backend they would fail with an opaque init error. P2.4/P3 must either ship a
small compiled probe binary (preferred — one exe, no interpreter, works in every
backend) or rewrite those probes in `cmd`/`curl`. Do not "fix" it by switching
shells; the shape is what fails.

**D8 — the child can only authenticate to *our* proxy if the token rides the
proxy URL (found in P1 wave 2, blocks any real proxied session).** mxc-sdk 1.0.1
strips every proxy variable from `request.environment` and then re-injects
`HTTP_PROXY`/`HTTPS_PROXY` from `runtimeConfig.networkProxy` **verbatim**
(`config_parser::convert_wire_proxy_at` → `ProxyAddress::original_url`,
`to_url()` → `inject_proxy_vars`), and `url::Url::parse` accepts `userinfo`. Our
listener requires `Proxy-Authorization: Basic base64("sandbox:<token>")` ([G-7]),
so a credential-less URL makes **every** child request a `407` — which is
deliberately *not* counted as a proxy consultation, so guardrail 1 fails as
`SessionNotAccepted` while the container looks healthy. Measured in the first
wave-2 live run: `curl: (22) The requested URL returned error: 407`, exit 22.
The ADR-0004 spike missed this because its listener answered `200` without
authenticating anyone.

Chosen fix (in code): the request's `networkProxy` carries
`http://sandbox:<token>@127.0.0.1:<port>` (`MxcNetworkInput::proxy_token`,
`MxcBackend::with_proxy_token`, `launch_session(.., proxy_token, ..)`), with the
token restricted to URL-unreserved characters (`RequestError::UnsafeProxyToken`)
so it cannot move the authority. `policy_identity` hashes only host+port and
explicitly excludes userinfo, so the credential neither changes the policy
identity nor becomes a confirmation oracle. No wrapper/argv plumbing was needed.
Open for P1.4/P1.5: the token is now in the *request*, so P1.4 is a *rejection*
rule (a run must not accept another run's token) rather than a delivery problem,
and P1.5 must measure whether the WinHTTP path is given the same userinfo URL.

**Answered by P1.4:** the listener classifies a credential as `OwnRun` / `Absent` / `Foreign`. `Foreign` gets the identical 407, is **not** counted (so it cannot satisfy guardrail 1), and writes exactly one audit leaf (`reason: foreign_token`, `host: <unknown>`) so a cross-run attempt is evidence rather than silence; `Absent` keeps its `no_token` leaf. Two open epochs are impossible (`EpochAlreadyOpen` -> `MxcError::Concurrency`) and the pruner only evicts CLOSED epochs (32 closed + at most one open), so a live launch's window can be neither split nor evicted.

**D9 — the listener forwards absolute-form plain HTTP (recorded 2026-10-21 after
a FAILed review).** Carrying `tunnels` as "upstream established" is only
meaningful if a plain-HTTP session can actually reach an origin, so the listener
now runs absolute-form `http://` through the same D-1 pipeline as CONNECT
(admission, audit leaf, DNS-pinned dial). Rules, all normative:

- `tunnels` counts an upstream connection established on **either** leg (CONNECT
  dial succeeded, or the forward's own dial came up).
- Absolute-form `https://` stays **400** (TLS belongs to CONNECT); origin-form
  outside `/sandbox/` stays **400**.
- **Host is rewritten** from the validated target; the client's Host is dropped
  (RFC 9112 §3.2.2). Without this, admission/audit name one host while the
  origin routes by another.
- **One head framing**: a bare LF in the head, `Transfer-Encoding`, or ambiguous
  duplicate `Content-Length` values are **400**; only a single Content-Length is
  forwarded, byte-exact.
- **Exactly one admitted request per connection**: bytes after the framed body
  are **400**, never relayed as an unadmitted second request.
- Fields named in the client's `Connection:` list are stripped as hop-by-hop.
- An origin `407`/`Proxy-Authenticate` is rewritten to **502** so an honest
  client never re-sends the proxy credential to an origin.
- The audit leaf still says `op: CONNECT` for a forward; the taxonomy question is
  P2.3's, recorded so a D-5 consumer is not silently wrong. **P2.3 did not answer
  it** (it extended `SESSION_START` only, and changing a forward's `op` would
  break every `op=CONNECT` count in the harness), so it stays open with the
  dispatch question it belongs to.

This is a NEW egress surface whose only gate is D-1 — the same trust boundary as
CONNECT, now also carrying cleartext HTTP.

**D10 — the child may enter Win32k, deliberately (recorded 2026-10-21).**

`build_request` now sets `ui.disable = false` explicitly. The SDK's default is the
opposite (`UiPolicy::default().disable = true`, mxc-sdk-1.0.1
`core/mxc_common/models.rs:583`), and that default becomes
`PROCESS_CREATION_MITIGATION_POLICY_WIN32K_SYSTEM_CALL_DISABLE` in the PSEC path
(`base_container_helpers.rs:57`). Measured consequence of leaving it on:
`powershell.exe` exits `0xC0000142`, `dotnet` fails with `coreclr.dll` HRESULT
`0x8007045A` - every managed process dies at load, because `coreclr.dll`
statically imports USER32 and ole32 and their DllMain cannot run. With
`ui.disable = false` both print (`FXOK`, `HELLO-OK`).

**What we give up:** the kernel's user-mode attack surface (Win32k syscalls) is
reachable from the child again. There is no middle setting - the dependency is a
static import, not a call we can gate. **What stays:** the ten
`JOB_OBJECT_UILIMIT_*` restrictions, clipboard `None` (verified: `OpenClipboard`
-> `ACCESS_DENIED`), input injection off, filesystem policy, proxy-only egress and
the AppContainer-shaped low-integrity token.

**Why not fall back:** the SDK's AppContainer tier applies the SAME mitigation
(`appcontainer_runner.rs:858`, `:917`), so a fallback to it would not have
rescued managed workloads either.

**Process lesson:** a suite that never runs a managed process would have called
this a green launch. P3's gate therefore needs an explicit managed-workload leg.

---

## P0 — Backend skeleton behind a flag (default unchanged)

**Files:** `Cargo.toml` (+ optional dep + feature `mxc-backend`),
`src/net/mxc.rs` (new), `src/cli.rs`, `src/main.rs`, `src/net/mod.rs`.

- [ ] **P0.1** Add `mxc-sdk = { version = "=1.0.1", optional = true }` and a
  `mxc-backend` feature (default off). Zero warnings with the feature both on
  and off.
- [ ] **P0.2** `MxcBackend::launch(&ResolvedSession, &LaunchContext)` building a
  `ContainerRequest` (command, working dir, env allow-list, filesystem, network,
  `timeout_ms`), calling `v1::run` for short-lived commands and `v1::spawn` for
  interactive ones; map `WaitResult` into the existing session result type.
- [ ] **P0.3** Guardrail 1 in code: `ProxyEpoch` created per launch; the proxy
  tags accepted sockets with the epoch; the launch gate requires
  `accepted >= 1 && tunnels >= 1`; failure ⇒ session error, never a warning.
- [ ] **P0.4** Guardrail 2 in code: `v1::probe(Some(&request))` on the exact
  request → `tier`, `tier_source`, `needs_dacl_augmentation`; persist into the
  session record (the audit-leaf wiring landed in P2.3).
- [ ] **P0.5** CLI `--backend <appcontainer|mxc>` (default `appcontainer`);
  `--backend mxc` refuses `--concurrency > 1` with a clear message until the concurrency fan-out lands (P3): P1.4 gives every run its own listener, port and token, but the supervisor still runs one session per process, so the refusal must not claim attribution is unimplemented.

**Acceptance:** `cargo test` green both feature states; an unelevated manual run
prints the tier and passes the guardrail; the default path is byte-for-byte the
current behaviour (harness smoke on 5 scenarios).

## P1 — Network + filesystem containment through MXC

**Files:** `src/net/mxc.rs`, `src/net/proxy.rs` (epoch/token plumbing),
`src/net/config.rs`, tests.

- [x] **P1.1** Bind the per-session proxy on 127.0.0.1:0 before launch; pass it
  as `runtimeConfig.networkProxy`; keep the CONNECT allow-list and loopback
  refusal on our side (MXC rules are CIDR/port only).
- [x] **P1.2** Request mapping: `egress.default = "deny"`,
  `ingress.default = "allow"`, `ingress.hostLoopback = "allow"`,
  `processContainer.network.allowedProxyPeer = null`; strip host proxy env;
  inject `NO_PROXY=localhost,127.0.0.1,::1`.
- [x] **P1.3** Filesystem mapping: `readwritePaths = [cwd]`; `readonlyPaths` =
  the declared read-only grants **plus the launcher's directory, inserted before
  the deny list is filtered** (a deny that covers the launcher used to ship,
  because the grant was added later in `build_request`); `deniedPaths` = the
  profile's **four credential subdirectories** (`.ssh`, `.aws`, `.azure`,
  `.gnupg`) + the configured denies. That is a deliberate narrowing: denying the
  whole profile directory breaks every workload that needs `%APPDATA%`, so the
  rest of the profile stays readable and the exposure is recorded rather than
  assumed away. A deny that **contains** a grant (equal to it, or an ancestor of
  it — e.g. `%USERPROFILE%` with the workspace or the launcher inside it) is a
  hard error, `RequestError::DenyCoversGrant`, naming both paths and telling the
  operator to deny the specific subdirectory; the previous behaviour dropped such
  a deny silently, which left `Documents`, `Downloads`, `AppData` and browser
  profiles readable with no warning, no error and no audit trace. Denies that are
  **descendants** of a grant (`%USERPROFILE%\.ssh` under workspace
  `%USERPROFILE%`) are the intended expressible case and keep working. Path
  comparison is normalised — case, separators, trailing dots/spaces, `.`/`..`
  segments, `\\?\` and `\\.\` prefixes — with no filesystem calls. **Recorded
  exposure:** the launcher grant is its whole *parent* directory (MXC grants
  directories, not files), so every container gets read-only visibility of the
  directory the launcher binary lives in — `target\debug` for a repo-local build,
  the installation directory for an installed supervisor; narrowing it to a
  dedicated one-entry launcher directory is deferred. Test asserting the
  workspace-only posture (outside write and read denied, `C:\Windows` readable =
  documented caveat).
- [x] **P1.4** **Concurrency:** per-run token — the supervisor mints a `RunToken` (64 lowercase hex = 8 hex chars of a **process-global run serial** + 224 CNG random bits; the serial makes two runs distinct **within one supervisor process**, while across processes both start at `00000001` and uniqueness rests on the 224 random bits; the serial is diagnostic, and since P1.6 it is also the live-token registry's key), the child's `HTTP_PROXY` userinfo carries it, and the listener rejects any credential that is not this run's — a foreign one gets the identical `407`, is not counted, and leaves exactly one `foreign_token` leaf; two concurrent containers must both pass their own guardrail and neither can satisfy the other's. Alternative (only if the token proves impossible): one proxy instance per run — document the cost. Landed with its reviews, then hardened, as P1.6.
- [x] **P1.5** (risk check) WinHTTP per-container proxy path: does a
  WinHTTP/Chromium-style client honour it? **Measured 2026-10-21: no.** The env is
  the only proxy information in the child (IE/WinHTTP/WinINet config reads
  'direct'), yet the container *forces* HTTP egress to `networkProxy` - proven with
  a WinHTTP session told the deliberately wrong proxy `127.0.0.1:1`, whose request
  still arrived at the container's proxy - and the consultation arrives without
  `Proxy-Authorization`, so WinHTTP/WinINet/Chromium get **407** (raw TCP gets
  `WSAEACCES 10013`; loopback is reachable only on the proxy's port). The only
  credential lives in the env URL, which none of those stacks read. Consequence:
  GUI/browser/system-proxy workloads are **not supported** in MXC proxy-only mode
  and stay on the AppContainer backend; a per-user WinINET/WinHTTP configuration is
  not a fix (HKCU write is `ERROR_ACCESS_DENIED` inside the container, `netsh
  winhttp`/HKLM need admin, and the credential still would not arrive).
  Independently: **the CLR does not start** in this container (coreclr
  `0x8007045A` / `0xC0000142`; the same binary runs under AppContainer) - P3
  blocker, root cause open. Evidence: `docs/research/backends/process-container/winhttp-proxy-path.md`.
- [x] **P1.6** **Harden what P1.4's reviews left open** — the `no_token` leaf flood capped (8 leaves, then one
  aggregate per window of 12 suppressed refusals carrying an integer `suppressed`, with `scope` left alone), the same
  budget on the `foreign_token` arm, the live-token registry keyed on the run serial instead of the credential, and
  the live concurrency test no longer able to retry a failed launch into invisibility. Mechanism, measurements and
  RED evidence: `docs/tasks/mxc-migration/PROGRESS.md` row P1.6.
- [x] **P1.7** **CLR-startup root cause** — the container ran every child with the Win32k-syscall ban because
  `build_request` never set `ui`; `ui.disable = false` restores .NET 8 / `pwsh` while all ten UI job restrictions and
  the AppContainer-shaped token survive (measured, unelevated). Evidence: PROGRESS row P1.7 and
  `docs/research/backends/process-container/clr-startup-failure.md`.
- [x] **P1.8** **Managed proxy-path re-measurement** — .NET 8 `HttpClient` and `pwsh` 7 authenticate after the
  listener's `407` + `Proxy-Authenticate: Basic` challenge and get egress; PS 5.1 / .NET Framework read the
  (direct) WinINet view and never consult the proxy. Evidence: PROGRESS row P1.8 and
  `docs/research/backends/process-container/winhttp-proxy-path.md`.

**Acceptance:** in the VM, unelevated, the network scenarios (S-27..S-36, S-72,
S-75..S-77, S-81..S-87, S-90, S-91) pass against `--backend mxc`; the guardrail
negative test still fails the session; concurrency test passes with two
containers.


**P1.4 review requirement for P2 wiring:** `launch_session(source, proxy_port, proxy_token, launcher, input)` takes the credential as a free-standing argument next to the port and the counters, so a caller can pair listener A's proof source with run B's token and only a runtime 407 catches it. The wiring must take the run's `(port, token, counters)` from ONE object (expose the token on `ProxyHandle`) rather than three loose arguments.

## P2 — Prompt, intent, audit parity

**D3 addendum (2026-10-22, opened while re-baselining the VM suite; rewritten
2026-10-22 after P2.1's reviews, because its first reading was wrong).**

*The observation:* a headless session has no dialog to answer, so a request to a
host that is neither allow- nor block-listed waited for the whole prompt budget
(observed as `curl -m 15` exit 28 at a 60 s budget).

*What was NOT the defect:* the forward leg was **already bounded**. Since D9 both
legs (CONNECT and the absolute-form plain-HTTP forward) reach the coordinator
through one `decide()`, so the one budget covers both and a forward timeout already
produced the same deny leaf a CONNECT timeout did. "The budget must be enforced on
the forward path too" was a misdiagnosis of a measurement that never distinguished
the two legs.

*What WAS the defect — one reason for two causes:* both a spent budget and a missing
dialog backend left the single string `prompt unavailable (timeout or no dialog
backend)`, so the audit could not say which had happened; the probe whose exit code
opened this addendum could not either. P2.1 fixed that with `UnavailableCause`
(`BudgetElapsed` / `NoDialogBackend` / `CallerGone`) and the
`prompt_budget_exhausted` token on both legs.

*What is now CLOSED, not renamed:* nothing short-circuited a **known-absent** dialog
backend, so the deny could only arrive when the budget expired — one budget per
unlisted host, which is the cost the observation measured. P2.1's review fix makes
"no answer is obtainable" sticky: after `NO_BACKEND_STICKY_AFTER` (**3**, raised from
2 in the second review round because two *concurrent* consultations elapse at the
same deadline — one budget's worth of evidence, with no grace consultation after
it) consecutive consultations produce no decision, later consultations skip the
dialog and apply `on_unavailable` immediately, one leaf per request. Measured over
nine unanswered requests at an 80 ms budget: the first three pay, then 0.7-0.9 ms
each (PROGRESS row P2.1).

Three corrections the second review round made to that mechanism, all in
`src/net/prompt.rs::BackendStickiness`:

- **The refusal names the arming cause.** `no_dialog_backend` when the backend
  failed to show a dialog, `prompt_suppressed_after_budget` when the dialogs were
  shown and nobody answered: folding them together told an operator to run
  interactively about a desktop that demonstrably worked.
- **Deny posture only.** Under `on_unavailable = allow` a skip *permitted* every
  later unlisted host with no dialog at all, deleting the user's veto, so allow
  keeps consulting and pays the per-host budget (a headless + allow profile is the
  operator's explicit choice, and it is the posture that has no veto to protect).
- **Not one-way.** Once armed nothing spawned a dialog, so the `Decided` reset was
  unreachable and an operator who returned to a still-open dialog had their answer
  discarded. After `NO_BACKEND_REPROBE_COOLDOWN` (10 min) the next consultation
  re-probes once: a decision un-arms the latch, a failure re-arms it.

The latch is also **launch-scoped**: it lives on the coordinator, which is per
listener, and a listener can serve sequential launches — launch N's stalled prompts
would otherwise deny every prompt of launch N+1. `LaunchCounters::begin_epoch` runs
the reset as the attribution window opens.

*What remains:* the deny body still says "CONNECT to host:port" for a plain-HTTP
forward (`respond_deny` is shared) — recorded, not fixed.

**Files:** `src/net/mxc.rs`, `src/net/prompt.rs`, `src/audit/*.rs`, `src/main.rs`.

- [x] **P2.1** Budget: `timeout_ms = prompt_budget + workload_budget + slack`,
  supervisor-owned constants; a dialog that takes 30 s must not kill the
  container; a workload that exceeds its budget must still be killed with a
  distinct reason. **Landed:** `SessionBudget` with `PROMPT_BUDGET` (60 s, the
  coordinator's own default), `WORKLOAD_BUDGET` (30 min) and `SESSION_SLACK`
  (2 min) = 1 980 000 ms, written unconditionally by `MxcBackend::request_for`
  (`with_budget` takes the type, so `None` is unrepresentable); a kill at the
  deadline is attributed to a term (`TimeoutReason` + the listener's own
  `prompt_wait`) instead of a boolean. Both legs deny a spent budget as
  `prompt_budget_exhausted` with the same leaf, and a timed-out consultation
  releases its coordinator slot. **Review fixes (same task, 2026-10-22, both
  reviewers' six findings):** `prompt_wait` is clamped to the session and the kill
  label is deprivation-based (prompt-bound only when the workload was actually
  starved), the handshake is measured separately (`SessionOutcome::clock` = elapsed
  + handshake_elapsed + prompt_wait) so a container that never became ready is
  `SessionHandshake` instead of the operator's overrun, a known-absent dialog
  backend fast-fails after three consultations (`no_dialog_backend` when the backend
  failed, `prompt_suppressed_after_budget` when the budgets elapsed), deny posture
  only, launch-scoped and self-healing after a re-probe cooldown, `Overloaded`
  names which of the two capacity pools ran out (`prompt_abandoned_capacity`),
  `abandoned_dialogs()` no longer counts dialogs still being waited on, and the
  budget is sized from the RESOLVED profile (`SessionBudget::from_config`) with the
  new `network.workloadTimeoutSecs` knob (default 1800 s, validated `1..=86400`) —
  a longer build must raise it, because the workload term is the tool's first-ever
  session bound. Evidence: PROGRESS row P2.1 and its Event Log entry.
- [x] **P2.2** D-4 endpoints under MXC (NO_PROXY verified end-to-end); S-77
  parity. **Proven by live legs, not by the VM suite** (coverage note below
  P2.4). `d4_intent_roundtrip_from_inside_the_container_is_proven` runs one real
  ProcessContainer, unelevated, against the supervisor's real listener:
  `POST /sandbox/intent` 204 -> `GET ?host=` 200 with the declared reason and an
  RFC3339 `ts` -> `POST /sandbox/intent/explain` 204 -> the next GET reports
  `"hint":"explain-more"` -> the GET after that reports `"hint":"declared"`, so
  the one-shot flag was consumed (the `hint` field is the only observable this
  API has for it); a wrong credential is 407, an undeclared host 404 and a
  malformed body 400. The child carries `NO_PROXY=localhost,127.0.0.1,::1` (each
  of the three spellings asserted, not just the joined string) and derives both
  the endpoint and its own `Basic` credential from the session's `HTTP_PROXY`, so
  no argument is handed to it by the test. The listener's own counters stay
  `{accepted: 0, tunnels: 0}` across all eight calls — `MustBeAbsent` is the gate
  that would otherwise refuse the launch — and the chain holds exactly one leaf,
  the wrong credential's `foreign_token` refusal at `host: "<unknown>"`, never a
  decision about a host. `a_declared_intent_is_the_prompt_reason_from_inside_the_container`
  closes D-4's actual point across the container boundary: the child declares the
  intent and then CONNECTs the host, the dialog seam receives
  `("p22-prompt.example", Some("reason-declared-from-inside-the-container"))`, and
  guardrail 1 fails `ProxyConsultedUnexpectedly` — the proof the consultation
  really reached `decide()`; `prompt_default` reading
  `ctx.prompt.intent.lookup_host(host)` is pinned in-process by
  `prompt_receives_declared_intent_reason`. **S-77 parity, item by item:** S-77
  asserts POST 204, GET 200, the reason, the normalized host,
  `hint: "declared"` and the child's exit 0, with the credential taken from
  `SANDBOX_PROXY_PORT` + the `HTTPS_PROXY` userinfo and a direct dial enforced by
  `UseProxy = $false`; the new leg reproduces every one of those except
  `SANDBOX_PROXY_PORT`, which the MXC launcher does not inject (recorded gap: a
  workload that only knows the D-0.3 contract cannot discover the endpoint under
  MXC until P3), and it adds what S-77 does not check — the explain one-shot, the
  404/400/407 negatives, the three NO_PROXY spellings, the counter proof and the
  audit-chain check. What it cannot reproduce is what only the VM harness
  supplies: the AppContainer baseline itself, the CLI/`Invoke-Sandbox` session
  shape, S-77's loopback-probe precondition and its `--allow-domain/--no-prompt`
  flags, and a second Windows image. Evidence: PROGRESS row P2.2 and its Event
  Log entry (EVIDENCE lines from the run).
- [x] **P2.3** The session-start leaf (`SESSION_START`) carries the tier facts
  under **ADR-0004's** names — `tier`, `tier_source`,
  `tier_needs_dacl_augmentation` (this plan said `needs_dacl_augmentation`; the
  ADR is the accepted decision, so the ADR's spelling won and the plan is
  corrected here), `elevated`, `proxy_endpoint`. **Ordering:** the leaf is armed
  the moment the writer exists (carrying the facts already known: the backend's
  tier identity and `elevated`) and written once the listener has bound — still
  before the child, so nothing the child causes can precede it — and an RAII guard
  writes the armed facts with a `null` endpoint if the run unwinds first. So
  `verify` keeps a root under `--block-net` and on an early error.
  **Scope (P2.3 review): one root per RUN, guaranteed against the child — not
  "always the genesis leaf".** The listener is bound before the root is written
  (`src/main.rs:717` vs `:748`), so a local connection in that window is audited
  first and the root lands at `seq > 0`; and a reused `--sid` continues the
  existing chain, so a second run appends a second root at `seq > 0`. A hard kill
  lands no root, and a non-strict writer swallows a failed root write
  (`--audit-strict` is the fail-closed mode). `tier_source` gains a third value,
  **`structural`**, for a backend that *is* the tier by construction: the AppContainer path records
  `appcontainer-dacl` / `structural` / `tier_needs_dacl_augmentation: true`, where
  `probe`/`unavailable` would claim a dispatch decision nobody made (documented in
  d-5.1). `proxy_endpoint` is `127.0.0.1:<port>` and nothing else: a
  `LoopbackEndpoint` newtype over a private `u16` whose only constructor takes a
  port, inside a `SessionStartFacts` with private fields and no `Default` — so the
  child's `http://sandbox:<token>@…` credential cannot be written into the field at
  all (P2.3 review: the previous all-public struct allowed exactly that literal).
  **A wrong tier is a refused session:** guardrail 2 is now hard
  (`TierExpectation` + `verify_tier` → `MxcError::Tier`), the expectation is a
  **required constructor argument** (no default, no setter — P2.3 review's security
  HIGH), and the check runs before the launch epoch opens, so the refused session
  has no CONNECT leaf — its chain is the root (naming the tier actually dispatched
  **and already marked `disposition: deny`**) plus one `SESSION_REFUSED` leaf.
  `audit verify` still validates the whole chain, and the five new keys (plus
  `expected_tier`) are filterable, including `=null` for a fact nobody established.
- [x] **P2.4** Harness: **S-94 landed; S-93's harness form is DEFERRED to P3.1**
  (the property is pinned meanwhile by an `#[ignore]`d live leg). Suite total:
  **93 scenarios** (numbers 1..=94, with 93 RESERVED out of the run), so the
  recorded VM baseline moves 92 -> 93.
  **Product gap CLOSED — `SANDBOX_PROXY_PORT` under MXC.** The AppContainer path
  injects it (`src/sandbox/appcontainer.rs:1007`) and nothing did under MXC, so a
  workload written to D-0.3 could not discover the D-4 endpoint at all. The
  wrapper now owns it: `mxc-launch.exe --proxy-port <port>` (built by
  `launcher_command` from the same `input.network.proxy_port` that becomes the
  request's `networkProxy`, so the variable and the proxy URL cannot name
  different listeners), written into the child as `SANDBOX_PROXY_PORT`; the
  no-proxy arm writes the name EMPTY, as the AppContainer `None` arm does for its
  four variables, so an inherited profile value cannot point a workload at a
  socket nobody owns. `--env SANDBOX_PROXY_PORT=` is refused as reserved, so only
  `--proxy-port` can set it. Asserted in the P2.2 live leg's env evidence
  (`EVIDENCE child_env … "SANDBOX_PROXY_PORT=<port>"` == the listener's port),
  whose RED was the variable absent from the child's own `cmd /c set` dump.
  **Guardrail 1's NEGATIVE case** (ADR-0004: `warnings: []` is not evidence, a
  session must not be reported successful unless the child provably reached the
  proxy — fail it, never warn-and-continue) is the new live leg
  `a_launch_that_never_reaches_the_proxy_is_refused_not_reported_successful`:
  `ProofExpectation::Required` (a network session) with a workload that writes a
  marker and exits 0 without touching the network is REFUSED with
  `MxcError::Guard(GuardError::SessionNotAccepted)`, its Display naming the
  missing proof; the listener's own counters for epoch 1 read `{0,0}` (with
  `counters(1)` returning `Some`, so "zero" is not the zero of an epoch that never
  existed), the epoch is closed on the refusal path, and the audit chain holds no
  CONNECT leaf and no leaf claiming a decision about a host. Mutation-checked:
  neutering `verify_proxy_proof`'s `Required` arm makes that leg fail on exactly
  the forbidden outcome (`SessionOutcome { exit_code: Some(0), warnings: [],
  proxy_proof: {0,0}, expectation: Required }`). **S-94** (`tests/run-tests.ps1`,
  registration 94) proves a real session SUCCEEDS (exit 0 *and* the marker on
  stdout) and that its `SESSION_START` leaf's `elevated` equals the harness's own
  elevation — read with the same call the leaf is written from,
  `GetTokenInformation(TokenElevation)` (`src/setup.rs::is_elevated`), via
  `Get-TokenElevation`; NOT `setup --check-only` (feature matrix, no elevation)
  and NOT `IsInRole(Administrator)` (group membership). It is an equality test,
  never `elevated=false`: guest true==true, unelevated host false==false; the key
  must also EXIST and be a JSON boolean, so a leaf that dropped it cannot pass an
  unelevated lane for the wrong reason. **S-93 has no harness form here on
  purpose:** guardrail 1 exists only in the MXC backend and the lane cannot select
  it before P3.1 (`main.rs` refuses `--backend mxc`), so a VM scenario today would
  exercise the AppContainer backend and could only pass for the wrong reason; a
  permanently-skipping placeholder was rejected, so 93 is reserved OUT of the run
  and S-93's harness form lands with P3.1.

  **COVERAGE NOTE (standing, P2.2 + P2.4):** until the wiring lands (P3), no VM
  scenario exercises MXC — `main.rs` refuses `--backend mxc` (`MXC_SESSION_WIRED
  = false`, and `cli::route_backend` refuses it before anything is spawned) and
  the harness never passes `--backend` at all (`tests/run-tests.ps1`: zero
  occurrences) — so P2.2 and P2.4's guardrail negative case are proven by
  in-process live legs only, unelevated, on this host; the VM suite remains an
  AppContainer baseline. Consequently: no scenario result in
  `tests/run-tests.ps1` may be cited as MXC coverage before P3.1, S-77 stays the
  AppContainer scenario it is, and S-94 (the one P2.4 scenario that DOES run in
  the VM) asserts the session-start leaf, which both backends write, so it
  survives the P3.1 flip without being evidence about MXC today.

**Acceptance:** S-75/S-76/S-77/S-87…S-92 pass under MXC; audit chain verify OK;
S-93/S-94 pass; no scenario depends on elevation.

**As landed (2026-10-22):** the suite is **93 scenarios** and both images read
`77 pass / 0 fail / 16 skip` (A osBuild 26340, B osBuild 29680, unelevated). S-94 runs in the
harness. S-93 is RESERVED out (`ReservedScenarioNumbers = @(93)`) rather than skipped: guardrail 1
exists only in the MXC path, the harness cannot select that backend until P3, so a VM scenario today
would test the AppContainer backend and pass for the wrong reason. The property is pinned meanwhile by
the `#[ignore]`d live leg `a_launch_that_never_reaches_the_proxy_is_refused_not_reported_successful`;
**the harness form of S-93 lands with P3.1**, when `--backend mxc` is selectable.

**Coverage note (decided 2026-10-22):** until the wiring lands (P3), no VM scenario exercises MXC —
`main.rs` refuses `--backend mxc` and the harness never passes it. P2.2 and the MXC half of P2.4 are
proven by in-process live legs only, unelevated, on this host; the VM suite remains an AppContainer
baseline. Never read a green VM run as MXC coverage.

## P5 - Windows version matrix (FINAL step, after the implementation is done)

**Decided 2026-10-22 (user).** Do this only once the migration itself is finished, not before.
Reason it is last: each image costs 1-2 h to build and ~30 GB, and a matrix run on an unfinished
build measures the wrong thing.

Today's evidence is SINGLE-BUILD: after the 2026-10-22 re-bake both templates are guest build
29680 (an Insider flight), so "passes on both images" means "passes twice on one build". Neither
image is a GA servicing build, which is what users actually run.

- [ ] **P5.1** Build an image per supported GA servicing build from ADR-0004's list and run the
  suite on it, both backends, unelevated where the lane allows:
  - **24H2 `26100.x`** - highest value: it is the OLDEST supported build AND the boundary for
    several gated features (`JOB_OBJECT_UILIMIT_*` incl. injection `0x200` at build 26100, the
    base-container requirement). Boundary builds are where SDK `requested & supported` gating
    bugs live; a build-26100 host that silently loses a UI limit is the kind of finding a
    29680-only matrix can never produce.
  - **25H2 `26200.x`** - the mainstream GA build.
  - **26H2 `26300.9550+`** - the newest GA servicing line (the dev host is 26300.9711).
  - **Server 2025 (`26100` server)** - ONLY if the tool is meant to run on servers; nothing in the
    ADRs claims that, so decide explicitly rather than adding it by habit.
  - Keep one Insider canary (29680) for early warning; label it as canary, never as supported.
- [ ] **P5.2** Per build, record a capability matrix: which gated features are actually available
  and whether the sandbox's behaviour matches the gate it applies (template:
  `docs/research/wbd-d02-capability-matrix.md`). A build where a limit is silently unavailable is a
  DOCUMENTED limitation in the same way `ui.disable` was (D10), not a footnote.
- [ ] **P5.3** Re-run the standard-user lane per build once it is unblocked (see the parked lane)
  so "unelevated" is measured on every build in the matrix, not inherited from the host.
- [ ] **P5.4** Record the matrix in `AGENTS.md`/README as the supported set, naming the minimum
  build and what is refused below it.

**Acceptance:** every build in the matrix runs the full suite with 0 failures, its skip set
explained, and a capability table that states what that build cannot do.

## P3 — Default flip + full parity

- [x] **P3.0 (2026-10-22)** Wire `--backend mxc` behind the flag, default unchanged. Selection branches
  before any AppContainer call; budget from the resolved profile; `Exactly(REQUIRED_TIER)` via
  `supervisor_backend`; guardrail 1 refuses (exit 126) instead of warning; session leaf carries the measured
  tier. Writable-grant-outside-workspace, missing launcher and deny-covers-grant are refused by name.
  **Open for P3.2:** a network-enabled session whose workload makes no request fails guardrail 1 by design.

- [x] **P3.1** Full suite (93 scenarios) against `--backend mxc` in the VM on **both
  images**: A `93/60/0/33`, B `93/60/0/33` (21 AppContainer-only + 12 environmental skips),
  `VM HARNESS: PASS`; AC baseline re-measured on the same tree at `93/78/0/15` (S-74 now executes).
  Took the guardrail-1 probe amendment (P3.1) and the root-before-launch fix (P3.1a).
  **Guardrail 1 is now the wrapper probe** (`GET /sandbox/probe`, token-gated, per-epoch `probes`
  counter): a network session whose workload makes no request PASSES, one whose probe never
  arrives is REFUSED (`proxy_probe_unmet`). Consequence: every successful MXC session writes one
  stderr proof line, so no MXC scenario may assert empty stderr.
  **Elevation caveat stands:** every VM session runs with the guest's elevated token, so this is
  product-logic coverage, not unelevated coverage - that claim rests on host live legs.
- [x] **P3.2a (2026-10-22) Two-part guardrail 1: refuse a session whose epoch saw only
  unauthenticated proxy attempts.** The P3.1 probe amendment proves the child's *path* to the
  listener, not that the workload *used* it: a GUI / system-proxy client (WinINet, Windows
  PowerShell 5.1 — P1.5/P1.8) reaches the proxy, never sends a credential, and yielded
  `probes=1, tunnels=0` — a PASS with no egress, i.e. the silent-misconfiguration class
  guardrail 1 exists for, re-opened by the amendment. The listener now counts BOTH refusal arms
  (`no_token` + `foreign_token`) in a new **per-epoch** proof counter `unauthenticated`
  (`LaunchProofCounters::note_unauthenticated`; epoch-scoped like every proof counter, and
  deliberately NOT the listener-lifetime leaf budgets). `ProofExpectation::Required` = `probes >= 1`
  **AND** `!(unauthenticated > 0 && accepted == 0)`, refused with the new
  `GuardError::WorkloadCannotAuthenticate` / reason token `workload_cannot_authenticate`
  (distinct from `proxy_probe_unmet`). Authenticated-but-denied (403) and 502 sessions still PASS,
  and so does the `407`-then-retry handshake every supported managed client uses (P1.8) — the leg
  refuses "attempted and nothing ever authenticated", not "made a credential-less attempt".
  `--block-net` (`MustBeAbsent`) unchanged. CLI proof line now prints `unauthenticated=…`.
  **What stays outside the gate:** a workload that never attempts anything (unproven either way),
  and a MIXED session whose working client masks a GUI stack that cannot authenticate — that needs
  per-client attestation (peer SID / WFP), which this pin does not provide.
  **This closes P3.2's open item** ("a network session whose workload makes no request fails
  guardrail 1 by design") from both sides: a no-request workload passes, a cannot-authenticate one
  is refused by name.
- [x] **P3.2** Flip the default to `mxc`; keep `--backend appcontainer` as an escape hatch.
  Implemented as a FEATURE-CONDITIONAL default (`cli::default_backend`): `mxc` in a
  `--features mxc-backend` build, AppContainer with a one-line notice otherwise - a hard
  constant would make every `run` on a feature-less build refuse. The escape hatch is now
  also the remedy named by guardrail 1's `workload_cannot_authenticate` refusal.
- [x] **P3.4** Interactive tools under the default backend. Two changes, both
  already expressible in `mxc-sdk 1.0.1`:
  (a) **Console passthrough.** The launch requests `StdioMode::Inherit` when the
  supervisor's stdin and stdout are both terminals, and `Pipes` otherwise (and
  always under `--no-interactive`). The mode is a LAUNCH decision, not a request
  field — the normalized request has no stdio field — so the launch goes through
  `process_container_common::dispatcher::spawn_with_fallback`, the same
  three-tier dispatcher `v1::spawn` reaches; `run_timed` skips the capture
  readers when there is nothing to tee and keeps the deadline, kill and
  exit-code semantics. The decision is `cli::inherit_console` (pure,
  table-tested); no caller changes behaviour, because the default is capture.
  (b) **Operator writable grants.** `filesystem_policy` grants read-write the
  workspace **plus** every explicit grant (profile `filesystem.allow` and each
  `--allow <path>` that is not `:read`), and P3.0 decision 9's refusal — and its
  message — are deleted. `PROFILE_SECRET_DIRS` stay denied on every launch, and
  a deny that **covers** a grant still refuses the session, now naming the grant
  to narrow.
  **Deliberately NOT done, recorded as a blocker:** an ancestor of a grant cannot
  be statted (opencode `lstat`s `C:\Users\<user>` at startup). The SDK's policy
  has four path classes and none means "traverse + read attributes without list
  or content", so there is no minimal fix to wire; four measured arms are in
  ADR-0004's 2026-10-22 amendment. Operator remedy: `--allow <home>:read`, whose
  cost (and whose safety: `~/.ssh` contents stay denied) is documented in
  `docs/USER-GUIDE.md`.
- [x] **P3.3** Docs: README (requirements, backends/privileges, the two obsolete blocks replaced),
  `AGENTS.md` (backends + test lanes), `sandbox-next-step.md`; the broker design is superseded -
  `docs/notes/future-ideas.md` had two sections numbered F-21, and the elevation-free one is now **F-25**
  with a banner saying ADR-0004 removed the need for it (egress only; the AppContainer backend still
  needs its exemption).

**Acceptance:** 0 fail on both images for **both** backends; an unelevated host
run of a network session works with no UAC anywhere.

## P4 — Delete the AppContainer containment path

- [ ] **P4.1** Remove the DACL ancestor walk, the ACL journal, the loopback
  exemption call, the capability-SID plumbing and their tests (the 4.5 defect
  class disappears with them).
- [ ] **P4.2** Remove the elevation warnings and the `--allow-domain` deferral
  text; update checkpoints and manual recipes.
- [ ] **P4.3** Keep a one-page "why we moved" note in `docs/adr/0004` and retire
  the AppContainer fallback after one release of MXC-by-default.

**Acceptance:** `cargo test` green with the reduced suite; VM suite 0 fail on
both images; `sandbox run --allow-domain …` works unelevated on the host.

---

## Checkpoints (user approval gates)

- **CP-A** after P0 — skeleton + guardrails, default unchanged.
- **CP-B** after P1 — unelevated network+filesystem containment proven in-VM,
  concurrency decided and tested.
- **CP-C** after P3 — backend flipped, parity proven on two images.
- **CP-D** after P4 — old containment deleted.

## Risks

| # | Risk | Mitigation |
|---|---|---|
| R1 | Identity-less proxy is the dev/test compatibility mode | P4 evaluate a packaged proxy; document the tier in the ADR |
| R2 | `ingress.default=allow` permits private-network **inbound** | documented; evaluate WFP inbound narrowing via `egress` rules and a follow-up upstream ask |
| R3 | Guardrail 1 could mask a sibling container's failure | P1.4 per-run token (or one proxy per run); concurrency test is mandatory |
| R4 | Tier cannot be required, only observed | guardrail 2 records it; a wrong tier refuses the session |
| R5 | Silent network misconfiguration (`warnings=[]`) | guardrail 1 is the gate; S-93 keeps it honest |
| R6 | `timeout_ms` kills a container mid-dialog | P2.1 explicit budget |
| R7 | WinHTTP clients may not honour the proxy | P1.5 measurement; scope GUI workloads accordingly |
| R8 | Filesystem policy is additive; system dirs readable | P1.3 `deniedPaths`; keep the documented caveat |

## Verification summary

1. `cargo test` / `cargo build --release` / `cargo clippy --release --all-targets`
   — zero warnings, with `mxc-backend` on and off.
2. Spike still green: `cargo run --release --bin mxc-ga-spike` unelevated.
3. VM suite: 0 fail on images A and B, for `--backend mxc` (P3) and
   `--backend appcontainer` (fallback).
4. Unelevated host run of a network session, asserted by S-94 and by a manual
   command in the checkpoint recipe.
