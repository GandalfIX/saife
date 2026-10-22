# ADR-0004: MXC `processcontainer` on GA Windows — unelevated proxy-only egress

- **Status:** **Accepted 2026-10-21 — Option A with guardrails** (decided by the product owner).
  ADR-0002's stop-work consequence and ADR-0003's posture are amended accordingly.
  **Amended 2026-10-22 (P3.1):** guardrail 1's evidence is an **in-container
  pre-flight probe** (`GET /sandbox/probe`, counted on the supervisor's listener),
  not `>= 1 tunnel`. The superseded rule is quoted as history in §"Prototype
  evidence for the guardrails"; the normative consequences of the relaxation and
  what is still proven are stated there.
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
| Proxy injection | child env `HTTP_PROXY`/`HTTPS_PROXY` (+ lowercase) = `http://127.0.0.1:<port>`, `NO_PROXY` unset. **1.0.1 strips HTTP(S)/ALL/NO_PROXY from the request env (any case) and re-injects only uppercase HTTP_PROXY/HTTPS_PROXY** (`appcontainer_runner.rs:86`, `:209-234`, `:260-272`) — so `NO_PROXY` cannot be delivered through `request.environment`; see plan §P1 D1. |
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
warn-and-continue. **Amended 2026-10-21 (plan D9):** the proof is "an upstream
connection was established for this launch", on **either** the CONNECT leg
(dial succeeded) or the plain-HTTP forward leg (its own dial came up) - the
listener is now also a forward proxy for the hosts D-1 admits.

### Guardrail 2 — per-session tier recording

The tier actually selected at dispatch (`base-container` vs
`appcontainer-dacl`) MUST be recorded per session (a session-start audit leaf,
not per-request — the D-5 taxonomy already carries `source`), together with the
request's containment posture. A degraded tier must be visible after the fact
even though it cannot be prevented before execution.

**Amended 2026-10-22 (P2.3):** `tier_source` carries **three** values — `probe`
and `unavailable` describe the MXC probe, `structural` says the backend *is* the
tier by construction (AppContainer: `appcontainer-dacl` + `structural` +
`tier_needs_dacl_augmentation: true`); `null` means *absence*, not a fourth case,
and consumers compare `tier`. The hard half is `TierExpectation` +
`verify_tier` (`MxcError::Tier`), checked **before** the launch epoch, so "a wrong
tier is a refused session with no CONNECT leaves" is structural; the requirement
is a **required constructor argument** of the backend (P2.3 review), so no session
path can be built without stating it, and a refused session's root leaf carries
`disposition: deny`. The leaf is one root **per run**, written before the child:
it is not always the file's `seq 0` (the listener is bound first, and a reused
`--sid` continues the chain). Vocabulary:
`tasks/adr-0001/d-5.1-connect-source-field.md`.

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

  **Amended 2026-10-22 (P3.1) — the rule above is SUPERSEDED, quoted as history:**
  *"the gate requires `accepted >= 1 AND tunnels_established >= 1` (a tunnel
  exists only if the proxy's own origin dial succeeded)"* and *"`tunnels>=1` is
  required"*. Both counters are produced by the **workload**, so that rule refused
  every network-enabled session whose workload makes no request: the four P3.1
  scenarios (S-55, S-77, S-86, S-91 — an intent roundtrip, an audit-log check,
  `cmd /c echo`, a raw 407 probe), and in the product
  `sandbox run --allow-domain api.anthropic.com -- echo hi`, which failed a user
  who did nothing wrong. A gate must prove the **path**, never the workload's use
  of it.

  Guardrail 1's evidence is now an **in-container pre-flight probe**. Before it
  starts the payload, `mxc-launch` sends ONE origin-form `GET /sandbox/probe` to
  `127.0.0.1:<proxy-port>`, carrying the `Basic` credential it derives from its
  **own** `HTTP_PROXY` — never from a command-line flag, because the wrapper's
  command line is part of the child's, where a token is visible to anything that
  can list processes. The listener answers `204` and records one probe
  observation on the launch's epoch in a counter of its own (`probes`: a probe is
  neither a policy consultation nor an upstream connection, and counting it as
  either would respectively make `MustBeAbsent` unsatisfiable or claim a dial
  nobody made). `Required` is satisfied by `probes >= 1`; `accepted` and
  `tunnels` stay in the proof record and in the operator's transcript as
  coverage.

  NORMATIVE consequences of the relaxation:

  1. The probe is **token-gated exactly like every other control-plane request**
     (same `Proxy-Authorization: Basic sandbox:<token>`, same `407`). A probe
     under a foreign or absent credential is counted **nowhere**, so a broken
     path cannot be masked by another process's socket.
  2. The observation lives on the **supervisor's** listener, not in the
     container: a marker file or a counter the workload can reach is forgeable,
     a listener-side counter is not.
  3. The wrapper's probe is **bounded (2 s) and best effort**: a probe that
     cannot connect never fails a launch by itself. The supervisor decides, which
     is what makes "loopback blocked / listener dead / wrong credential" a
     refusal rather than a silent success.
  4. **`--block-net` is unchanged.** A proxy-less session has no listener to
     probe and expects no probe; `MustBeAbsent` (accepted == 0 && tunnels == 0)
     still fails a session that was supposed to stay offline and went out.

  **What is still proven:** that the child's own path to THIS listener works —
  right port, right credential, loopback reachable from inside the container — in
  this launch's epoch (one listener per run, one token per run, one epoch per
  launch). **What is no longer claimed:** that any traffic crossed the proxy.
  That is recorded detail now, and a workload that makes no request legitimately
  has none. A refused launch carries a distinct reason, `proxy_probe_unmet`
  (the audit leaf's `reason` field remains `proxy_proof_unmet`: it names the
  gate, not the leg).
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

## Posture change 2026-10-21: Win32k is reachable from the child

The `processcontainer` request previously left `ui` unset, and the SDK defaults
`UiPolicy::disable` to `true` (mxc-sdk-1.0.1 `core/mxc_common/models.rs:583`),
which the PSEC path maps to
`PROCESS_CREATION_MITIGATION_POLICY_WIN32K_SYSTEM_CALL_DISABLE`
(`base_container_helpers.rs:57`). That ban is incompatible with every managed
runtime on Windows: `coreclr.dll` statically imports USER32 and ole32, so their
DllMain fails (`ERROR_DLL_INIT_FAILED`), and the loader dies before the CLR
exists. Measured: `powershell.exe` -> `0xC0000142`, `dotnet` -> `coreclr.dll`
HRESULT `0x8007045A`; with `ui.disable = false` both run (`FXOK`, `HELLO-OK`).

The migration therefore **accepts Win32k reachability** as a deliberate trade:
without it, MXC cannot run the product's own workloads at all. The mitigations
this ADR relies on are unchanged (proxy-only egress, filesystem policy, low-
integrity AppContainer-shaped token, UI restrictions and no clipboard/injection);
what is lost is kernel attack-surface reduction, which this ADR previously got
for free from the default. The SDK's AppContainer tier applies the same
mitigation, so it is not an alternative posture - and no doc, audit leaf or CLI
text may claim Win32k containment from here on.

## Managed clients depend on the 407 challenge (measured 2026-10-21)

.NET 8 (`SocketsHttpHandler`) and pwsh 7 read `HTTP_PROXY`/`HTTPS_PROXY` and
lift the URL userinfo into a credential, but they do **not** send it
pre-emptively: the first request on a new proxy connection is
unauthenticated, and the client authenticates only after a `407` carrying
`Proxy-Authenticate: Basic`. The listener's challenge is therefore
**load-bearing**: an unauthenticated consultation that is answered any other
way (or answered without the header) silently removes egress from every
managed workload. Pinned by
`an_unauthenticated_consultation_gets_the_basic_challenge_managed_clients_need`.

Measured consequence: Windows PowerShell 5.1 / .NET Framework have **no**
usable egress, because they take the proxy from the WinINet system store,
which reports "direct" inside the container, so they dial directly and fail
with `WSAEACCES 10013` without ever consulting the proxy. Managed workloads
must therefore be `pwsh` 7 / .NET 8+; that is a workload requirement, not a
configuration gap. The alternative - admitting an unauthenticated request
that provably comes from this run's container (peer SID / WFP attribution)
instead of a bearer token - would remove the round trip AND the benign
`no_token` leaf each managed connection currently emits, but it trades away
P1.4's per-run token, so it needs its own decision.
