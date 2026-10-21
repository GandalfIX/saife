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

**D5 — timeout budget.** `timeout_ms` is a passthrough; MXC's default is 30 000
ms, which would kill a 60 s prompt. P2.1 owns the budget, but P1 must not ship a
default that silently caps sessions.

**D6 — housekeeping.** Remove `#![cfg_attr(not(test), allow(dead_code))]` from
`src/net/mxc.rs` when main.rs routes through the backend, and set the
`ProcessContainerConfig` UI fields explicitly instead of relying on today's
defaults.

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
  `--backend mxc` refuses `--concurrency > 1` with a clear message until P1.4.

**Acceptance:** `cargo test` green both feature states; an unelevated manual run
prints the tier and passes the guardrail; the default path is byte-for-byte the
current behaviour (harness smoke on 5 scenarios).

## P1 — Network + filesystem containment through MXC

**Files:** `src/net/mxc.rs`, `src/net/proxy.rs` (epoch/token plumbing),
`src/net/config.rs`, tests.

- [ ] **P1.1** Bind the per-session proxy on 127.0.0.1:0 before launch; pass it
  as `runtimeConfig.networkProxy`; keep the CONNECT allow-list and loopback
  refusal on our side (MXC rules are CIDR/port only).
- [ ] **P1.2** Request mapping: `egress.default = "deny"`,
  `ingress.default = "allow"`, `ingress.hostLoopback = "allow"`,
  `processContainer.network.allowedProxyPeer = null`; strip host proxy env;
  inject `NO_PROXY=localhost,127.0.0.1,::1`.
- [ ] **P1.3** Filesystem mapping: `readwritePaths = [cwd]`,
  `deniedPaths = [profile dirs, .ssh, .aws]` (policy-driven), `readonlyPaths`
  for declared read-only grants; a test asserting the workspace-only posture
  (outside write and read denied, `C:\Windows` readable = documented caveat).
- [ ] **P1.4** **Concurrency:** per-run token — the supervisor generates a token,
  the child's `HTTP_PROXY` userinfo carries it, the proxy rejects CONNECTs whose
  token does not match the run; two concurrent containers must both pass their
  own guardrail and neither can satisfy the other's. Alternative (only if the
  token proves impossible): one proxy instance per run — document the cost.
- [ ] **P1.5** (risk check) WinHTTP per-container proxy path: does a
  WinHTTP/Chromium-style client honour it? Record the answer; it decides whether
  GUI/browser workloads are supported in MXC mode.

**Acceptance:** in the VM, unelevated, the network scenarios (S-27..S-36, S-72,
S-75..S-77, S-81..S-87, S-90, S-91) pass against `--backend mxc`; the guardrail
negative test still fails the session; concurrency test passes with two
containers.

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
