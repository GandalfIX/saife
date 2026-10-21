# ADR-0004: MXC `processcontainer` on GA Windows — unelevated proxy-only egress

- **Status:** **Accepted 2026-10-21 — Option A with guardrails** (decided by the product owner).
  ADR-0002's stop-work consequence and ADR-0003's posture are amended accordingly.
- **Date:** 2026-10-21
- **Supersedes:** nothing. Amends the premise of ADR-0002 §"platform" (MXC
  required an Insider build) and leaves ADR-0003's enforcement posture intact.
- **Evidence:** `tests/vm/spikes/mxc-ga-spike/` (crate + `SPIKE-REPORT.md`,
  reproducible with `cargo run --release --bin mxc-ga-spike`), runs
  2026-10-21 on host build 26300.9711.

## Context

ADR-0002 selected `mxc-sdk` as the containment surface and recorded a stop-work
gate: **no product launch path until upstream exposes a created-not-running /
pre-resume attestation handle** (plus an atomic require-tier field, ADR-0003).
At that time MXC's `processcontainer` was thought to require an Insider build,
which is why `sbx-base-b` (build 29680) exists.

Both premises have now been re-checked against upstream `main` (2026-10-21) and
against a real SPIKE built on the published crate:

1. **The Insider requirement is gone.** `docs/backends/process-container/
   os-version-support.md` lists GA servicing builds: 24H2 26100.9278+,
   25H2 26200.9278+, 26H2 26300.9550+, 26H1 28000.2804+. The development host
   (26300.9711) and both test images qualify.
2. **Proxy-only egress runs unelevated.** `networking.md` documents WFP egress
   filters plus a per-container WinHTTP proxy "applied with no UAC prompt per
   launch".

## Spike result (mxc-sdk 1.0.1, crates.io, unelevated)

| Claim | Observed |
|---|---|
| Elevation | `SPIKE: elevated=false` — no UAC prompt at any point |
| Platform support | `isSupported:true`, `availableMethods:["processcontainer"]`, tier **`base-container`**, `needsDaclAugmentation:false`, `warnings:[]` |
| Proxy injection | child env `HTTP_PROXY`/`HTTPS_PROXY` (+ lowercase) = `http://127.0.0.1:<port>`, `NO_PROXY` unset |
| Proxy reachability | `proxy_connect=ok`, `HTTP/1.1 200 Connection Established` |
| **Direct egress containment** | `1.1.1.1:443` and a resolved `104.20.23.154:443` both **denied, os error 10013 PermissionDenied** |
| Filesystem policy | write + read back on the granted dir OK; read/write on a non-granted dir denied (error 5) |
| Capability set | `identitylessLoopbackProxy`, `ingressHostLoopbackAllow`, `captureDenials`, `filesystemDeniedPaths`, `filesystemEnumeratePaths` |

This is the property the current supervisor cannot provide: our AppContainer
path needs an **admin-only loopback exemption** for every network session, which
is the sole reason checkpoints, harness runs and manual verification are
elevated (and the reason F-21 proposed a privileged broker).

### Limits of the evidence

- **Real internet through the proxy is unproven** — the spike's listener answers
  `200` and closes; it never forwards. Egress containment is proven; a complete
  proxied round trip is not.
- Only the **env-var** proxy path was exercised, not the WinHTTP per-container
  proxy.
- UI/clipboard policy, `deniedPaths`, reparse points, inbound/private-network
  direction, stdin/kill/interactive semantics, concurrency, and tier fallback on
  a host without `processmodel.dll` are all untested.
- `C:\Windows\win.ini` remained **readable** inside the container: the policy is
  additive grants, not a blanket deny — the same host-system-dir caveat our own
  probe recorded.

## What is still missing (the gate)

**Attestation is ABSENT at 1.0.1, and structurally worse than a missing
accessor.** A crate-wide search found no `pre_resume`/`preResume`/
`created_not_running`/`createdNotRunning`/`require_tier`/etc.; the only
suspended-spawn primitive is a **private** `AppContainerScriptRunner::
spawn_suspended` returning a private `SpawnedChild`. `ProvisionContainment` has
only `IsolationSession` and `Wslc` variants, so **there is no provision→start
split for ProcessContainer at all** — no created-but-not-running container can
be produced, and run() resumes the child internally. `AvailableBackend.tier` is
a ceiling that policy can lower at dispatch, so a tier can be observed after the
fact but not required.

Therefore **ADR-0002's stop-work gate stands unchanged.**

## Additional risks found

1. **Silent network misconfiguration.** The identity-scoped proxy form requires
   `network.ingress.hostLoopback='deny'` (a conflicting config fails with
   `malformed_request`). In the spike's identity-scoped run the workload exited
   0 with `warnings=[]` while its proxy connect **timed out** — a broken
   deployment that looks successful to anything trusting `warnings`.
2. **The workable proxy mode is the one upstream labels development/testing
   compatibility**: `allowedProxyPeer` omitted + `hostLoopback='allow'`, no peer
   identity, and no way to prove which host process owns the endpoint. The
   strict, identity-scoped form requires packaging the proxy or running it as an
   AppContainer.
3. **`ingress.default='allow'` is mandatory for proxy-only egress** and grants
   the bidirectional `privateNetworkClientServer` capability, so private-network
   **inbound** is also permitted — an attack-surface increase that cannot be
   opted out of while proxy mode is in use.
4. `inheritDefaultEnvironment` semantics: the child lost `USERNAME` while
   keeping `USERPROFILE`.

## Decision

**Option A was chosen, with guardrails.** The two guardrails are normative
requirements of this ADR — not advice — and any launch path that does not
implement both is non-conformant and must fall back to the un-amended
ADR-0002 prohibition.

### Guardrail 1 — post-launch proxy proof (hard gate)

`warnings: []` is **not** evidence that the network works: the spike observed a
run that exited 0 with no warnings while its proxy connect timed out. Therefore
a session MUST NOT be reported as successful unless the supervisor can prove the
child actually reached the proxy — e.g. a connection count on our own listener,
or an in-container probe that reports back. Failure => fail the session, do not
warn-and-continue.

### Guardrail 2 — per-session tier recording

The tier actually selected at dispatch (`base-container` vs
`appcontainer-dacl`) MUST be recorded per session (a session-start audit leaf,
not per-request — the D-5 taxonomy already carries `source`), together with the
request's containment posture. A degraded tier must be visible after the fact
even though it cannot be prevented before execution.

### Prototype evidence for the guardrails (2026-10-21, same host, unelevated)

- **Real HTTPS through a forwarding proxy: PASS.** Inside an unelevated
  ProcessContainer: `CONNECT api.anthropic.com:443` → rustls TLS 1.3 (OS root
  store) → `GET /` → **HTTP 404** (a bare `GET /` 404s on that host; any 1xx-5xx
  was the acceptance rule), 3557 bytes down, 453 up, 211 ms. DNS and TCP to the
  origin provably happened on the proxy side (`160.79.104.10:443`), while the
  child saw only `127.0.0.1` and its own direct egress stayed blocked
  (`WSAEACCES 10013`, raw IP and hostname). No schannel/CRL involvement at all —
  the child used rustls, not schannel.
- **Guardrail 1 implemented and DEMONSTRATED, including the negative case.**
  Each launch takes an attribution epoch on the proxy; the gate requires
  `accepted >= 1 AND tunnels_established >= 1` (a tunnel exists only if the
  proxy's own origin dial succeeded), prints `guardrail_proxy_proof=FAIL` and
  exits 3 on failure — there is no code path that prints success without it.
  Positive: `accepted=1 tunnels=1` → PASS. **Negative (the silent-misconfig
  case): the SDK reported `outcome=exited:0`, `warnings=[]`, the child's proxy
  connect timed out, and the guardrail printed FAIL with `accepted=0` → exit 3.**
  Two further branches show why `tunnels>=1` is required: an unresolvable target
  (proxy 502) and a loopback target (proxy 403) both give `accepted=1,
  tunnels=0` → FAIL.
- **Guardrail 2 implemented.** The tier is taken from `v1::probe()` on the exact
  request being launched (not a lookalike, not the backend ceiling), recorded as
  `tier=base-container`, `tier_source=probe`, `tier_needs_dacl_augmentation=false`,
  and persisted per run to `runs/<utc>-<label>.json`. Product placement: a
  **session-start** audit leaf; a wrong tier is a refused session with no CONNECT
  leaves.

**Concurrency caveat (must be designed before shipping):** guardrail 1 attributes
connections by launch epoch on one proxy instance, so it assumes one launch per
proxy. Concurrent containers require one proxy per run or a per-run token inside
the CONNECT request — MXC provides neither — otherwise one container's success
can mask another's failure.

**Interaction with D-3:** MXC's `timeout_ms` bounds the entire workload, so the
60 s interactive prompt must fit inside the supervisor-owned run budget or the
container is killed mid-dialog. The budget must be explicit, not inherited.

### Options considered (unchanged in substance)

### Option A — CHOSEN: bounded adapter now (UAC removed from network sessions)

Adopt `mxc-sdk 1.0.1`'s `processcontainer` as the enforcement backend for
**network and filesystem containment**, keeping this project's D-1..D-5 logic
(allow/deny pipeline, prompts, learned store, audit) above it. Requires
**amending ADR-0002's gate** from "no product launch path" to ADR-0003's
"bounded, not preventive" posture, with the residual risk written down:
no pre-run attestation; tier observed only after dispatch; silent
misconfiguration must be caught by our own post-launch proxy probe.

- Gain: no UAC for any network-enabled session; deletes the loopback exemption,
  the DACL ancestor walk and the journal (the 4.5 defect class).
- Cost: an explicit, documented security downgrade vs. an attested launch;
  a compatibility-tier proxy; inbound private-network exposure.

### Option B — rejected (retained for the record)

Stay on the AppContainer supervisor for the product; use MXC in the VM/CI lane
to cross-check containment, and drop `sbx-base-b` as the "MXC needs Insider"
artefact (one image now suffices). Re-open Option A when upstream ships
attestation (created-not-running or an atomic require-tier field).

- Gain: no security regression, less test infrastructure.
- Cost: **UAC stays** for product network sessions (F-21's broker remains the
  only elevation-free design under this option).

## Consequences either way

- The test-infrastructure premise changes: `sbx-base-b` is no longer required to
  exercise MXC; the GA host and image A qualify.
- Any future MXC integration MUST verify the proxy is actually reachable after
  launch — `warnings=[]` is not evidence.
- Re-pin policy: prefer the published crate (`mxc-sdk = "1.0.1"`) over a git
  SHA; pin exact versions and re-run this spike on every bump.
