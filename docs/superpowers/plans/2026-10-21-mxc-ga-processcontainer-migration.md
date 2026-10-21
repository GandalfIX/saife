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
  P2.3's, recorded so a D-5 consumer is not silently wrong.

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
  session record (leaf wiring lands in P2.3).
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
- [ ] **P1.4** **Concurrency:** per-run token — the supervisor mints a `RunToken` (64 lowercase hex = 8 hex chars of a **process-global run serial** + 224 CNG random bits; the serial makes two runs distinct **within one supervisor process**, while across processes both start at `00000001` and uniqueness rests on the 224 random bits; the serial is diagnostic only), the child's `HTTP_PROXY` userinfo carries it, and the listener rejects any credential that is not this run's
  the child's `HTTP_PROXY` userinfo carries it, the proxy rejects CONNECTs whose
  token does not match the run; two concurrent containers must both pass their
  own guardrail and neither can satisfy the other's. Alternative (only if the
  token proves impossible): one proxy instance per run — document the cost.
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
  blocker, root cause open. Evidence: `docs/backends/process-container/winhttp-proxy-path.md`.

**Acceptance:** in the VM, unelevated, the network scenarios (S-27..S-36, S-72,
S-75..S-77, S-81..S-87, S-90, S-91) pass against `--backend mxc`; the guardrail
negative test still fails the session; concurrency test passes with two
containers.


**P1.4 review requirement for P2 wiring:** `launch_session(source, proxy_port, proxy_token, launcher, input)` takes the credential as a free-standing argument next to the port and the counters, so a caller can pair listener A's proof source with run B's token and only a runtime 407 catches it. The wiring must take the run's `(port, token, counters)` from ONE object (expose the token on `ProxyHandle`) rather than three loose arguments.

## P2 — Prompt, intent, audit parity

**Files:** `src/net/mxc.rs`, `src/net/prompt.rs`, `src/audit/*.rs`, `src/main.rs`.

- [ ] **P2.1** Budget: `timeout_ms = prompt_budget + workload_budget + slack`,
  supervisor-owned constants; a dialog that takes 30 s must not kill the
  container; a workload that exceeds its budget must still be killed with a
  distinct reason.
- [ ] **P2.2** D-4 endpoints under MXC (NO_PROXY verified end-to-end); S-77
  parity.
- [ ] **P2.3** `session.start` audit leaf extended with `tier`, `tier_source`,
  `needs_dacl_augmentation`, `elevated`, `proxy_endpoint`; `audit verify` still
  validates the chain; a wrong tier is a refused session with no CONNECT leaves.
- [ ] **P2.4** Harness: add S-93 (silent-misconfig must fail the session, i.e.
  the guardrail's negative case) and S-94 (unelevated launch: assert the
  supervisor reports `elevated=false` and the session still works).

**Acceptance:** S-75/S-76/S-77/S-87…S-92 pass under MXC; audit chain verify OK;
S-93/S-94 pass; no scenario depends on elevation.

## P3 — Default flip + full parity

- [ ] **P3.1** Full 92-scenario suite against `--backend mxc` in the VM on **both
  images**, unelevated.
- [ ] **P3.2** Flip the default to `mxc`; keep `--backend appcontainer` as an
  escape hatch for one release.
- [ ] **P3.3** Docs: `AGENTS.md` (the "run tests elevated" rules become
  MXC-specific), README, `sandbox-next-step.md`, supersede F-21 (the broker
  design is no longer needed).

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
