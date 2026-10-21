# SPIKE: `mxc-sdk 1.0.1` on GA Windows — real proxied HTTPS + the two ADR-0004 guardrails

**Date:** 2026-10-21
**Host:** Windows 11 build **26300.9711** (GA 26H2), user `marku` (THOR), **unelevated**
**Toolchain:** rustc 1.98.1 (48a229cea 2026-09-01) / cargo 1.98.1
**Crate resolved:** `mxc-sdk v1.0.1` from crates.io, exact pin `=1.0.1`
**Spike dir:** `C:/Users/marku/tools/sandbox/tests/vm/spikes/mxc-ga-spike/` (no git writes, no elevation, no UAC)
**This iteration:** replaced the dummy listener with a forwarding HTTP `CONNECT` proxy, ran a **real TLS
request through it from inside an unelevated ProcessContainer**, and implemented the two ADR-0004
guardrails (post-launch proxy proof, per-session tier logging), including the negative test that the
first guardrail catches the silent-misconfiguration case.

## Verdict

| Question | Answer |
|---|---|
| Runs unelevated on GA Windows? | **Yes.** `TokenElevation = 0`, no UAC prompt, no elevation attempt. |
| Tier selected | **`base-container` (Tier 1, PSEC)**, `tier_source=probe` on the exact request, `needsDaclAugmentation=false`, no `wxc-host-prep`. |
| **Real HTTPS from inside the container through the proxy?** | **Yes.** Child → `CONNECT api.anthropic.com:443` → TLS 1.3 (cert chain validated, SNI checked) → **`HTTP/1.1 404 Not Found`** from the real origin. 3557 bytes down / 453 up through the tunnel. |
| Where did DNS + TCP to the origin happen? | **On the proxy side only.** Proxy resolved `api.anthropic.com` → `160.79.104.10:443` and dialled it; the child resolved nothing and only ever connected to `127.0.0.1`. |
| Direct egress still blocked? | **Yes, hard.** `WSAEACCES (10013)`, not a timeout, on a raw IP and on a DNS-resolved host. |
| **Guardrail 1 (post-launch proxy proof)** | **Works.** `PASS` on the real run; `FAIL` on the deliberately wrong identity-scoped run, which itself exits `0` with `warnings=[]`. Gate armed → exit code **3**. |
| **Guardrail 2 (per-session tier)** | **Works.** `SPIKE: tier=base-container`, `SPIKE: tier_source=probe`, persisted in `runs/<timestamp>-<label>.json`. |
| Created-not-running / pre-resume attestation? | **Still absent** from the public API (§8). Unchanged from the previous spike. |

The biggest evidence gap of the first spike — "the listener answers 200 and closes; real forwarding
is unproven" — is **closed**. What remains open is attestation/tier enforcement, not transport.

## 1. What changed in this iteration

| Before | Now |
|---|---|
| `start_proxy()` accepted, replied `200`, closed. | `src/proxy.rs`: real `CONNECT` proxy — parse, allow-list, loopback-target refusal, dial, `200` only after the origin TCP handshake, bidirectional splice, per-session accounting. |
| Workload sent `CONNECT example.com:443` and printed the 200. | `src/bin/workload.rs`: connects to `127.0.0.1`, sends `CONNECT <target>:443`, then runs a **rustls** TLS handshake over that socket and issues `GET <path>`; prints the origin status. |
| Success reported from `outcome=exited:0` + `warnings=[]`. | **Guardrail 1**: success requires ≥ 1 proxy session accepted *in this run's epoch* **and** ≥ 1 established tunnel; otherwise `SPIKE: guardrail_proxy_proof=FAIL` + non-zero exit. |
| Tier printed once at the end from `available_backends()`. | **Guardrail 2**: `v1::probe(Some(&request))` on the request actually launched → `tier` + `tier_source`, printed and persisted. |
| No persisted per-run state. | `runs/<timestamp>-<label>.json` per launch: tier, elevated, proxy port, sessions, guardrail results, origin status, outcome. |

Both guardrail implementations live in `src/main.rs` (`guardrail_proxy_proof`, `select_tier` /
`report_tier`).

## 2. Real forwarding (TASK 1)

### 2.1 Proxy design (`src/proxy.rs`, ~475 lines, std + `serde_json` for the session dump)

- Binds **`127.0.0.1:0` only**; no external listener.
- Parses `CONNECT host:port`, bounded head read (8 KiB, 5 s), rejects non-`CONNECT` with `405`.
- **Refuses `CONNECT` to loopback targets** (`127.0.0.0/8`, `::1`, `localhost`, `*.localhost`,
  `0.0.0.0`) with `403` + `X-Sandbox: denied` — D-1 [G-44], so the proxy can never be used as a
  tunnel back into host services.
- Target **allow-list** is per-process and exact: `["api.anthropic.com:443"]` in this run. Anything
  else gets `403`.
- Dials the resolved addresses itself, first success wins, per-address 5 s / total 10 s budget.
- Sends `200 Connection Established` **only after** the origin TCP connect succeeded; otherwise
  `502` with the dial error.
- Splices both directions with two threads, 20 s socket read timeout, 40 s tunnel budget, 8 MiB
  cap; the first direction to finish tears the tunnel down. No sleeps, no polling.
- Records a `Session` per accepted connection: peer, request line, target, **resolved origin
  address**, `established`, byte counts, duration, and the **epoch** it arrived in.

### 2.2 The child path

```
CHILD: target=api.anthropic.com:443 path=/
CHILD: target_resolved_locally=false (hostname passed to the proxy verbatim)
CHILD: proxy_connect=ok peer=127.0.0.1:56332
CHILD: connect_response="HTTP/1.1 200 Connection Established"
CHILD: connect_tunnel=established
CHILD: tls_roots_loaded=53 store_size=53 store_errors=0
CHILD: https_tls=ok version=TLSv1_3 cipher=TLS13_AES_256_GCM_SHA384
CHILD: https_sni=api.anthropic.com
CHILD: https_status=404
CHILD: https_reason=Not Found
CHILD: https_received_bytes=280
```

Proxy side, independently (stderr, outside the container):

```
PROXY: session=1 established peer=127.0.0.1:56334 target=api.anthropic.com:443 resolved=160.79.104.10:443
PROXY: session=1 closed up=453 down=3557
```

Driver:

```
SPIKE: proxy_session_canonical={"bytesDown":3557,"bytesUp":453,"elapsedMs":211,"epoch":1,"established":true,"id":1,"peer":"127.0.0.1:56334","requestLine":"CONNECT api.anthropic.com:443 HTTP/1.1","resolved":"160.79.104.10:443","status":"tunnel_closed","target":"api.anthropic.com:443"}
SPIKE: dns_locus=proxy target=api.anthropic.com:443 resolved=160.79.104.10:443 (child resolved nothing)
SPIKE: real_https=PASS origin_status=404 target=api.anthropic.com:443 tunneled_bytes_down=3557 tls=ok version=TLSv1_3 cipher=TLS13_AES_256_GCM_SHA384
```

### 2.3 Why a `404` is proof, and why no `401`

`GET /` on `api.anthropic.com` answers **404**, not 401 (401 requires the Messages endpoint without
a key). The brief's acceptance rule was "any 1xx–5xx origin status", so 404 qualifies.

It is a *real* origin response, not something the proxy could have produced:

1. The proxy is a **raw byte splice**; it never sees or speaks TLS. It cannot mint a certificate for
   `api.anthropic.com`.
2. The child's rustls session **validated the certificate chain against the OS root store** (53 roots
   loaded, 0 store errors) with `SNI=api.anthropic.com`, and negotiated TLS 1.3.
3. The status line is parsed from bytes the child decrypted itself.
4. The host-side control matches: `curl` with the same headers (`Connection: close`,
   `User-Agent: mxc-ga-spike/0.0.0`) gets `HTTP/1.1 404 Not Found`, `Transfer-Encoding: chunked`,
   empty body. The child's 280 bytes are exactly that head plus the `0\r\n\r\n` chunk terminator —
   which is also why `https_body_prefix` is `"0"`.
5. Byte counts are consistent with a real TLS 1.3 handshake (~3.3 KiB of certificate records) plus a
   small response.

**No `CRYPT_E_REVOCATION_OFFLINE` was encountered**, by construction: the child uses rustls, which
validates against the OS root store and performs no Windows schannel revocation fetch. That
environment condition cannot masquerade as a containment failure here.

### 2.4 "The child only ever talks to 127.0.0.1"

```
CHILD: direct_egress=blocked peer=1.1.1.1:443 ... os_code=Some(10013) kind=PermissionDenied
CHILD: direct_egress_dns=blocked peer=172.66.147.243:443 ... os_code=Some(10013)
CHILD: target_resolved_locally=false
```

The only socket the child successfully opened was to `127.0.0.1:56332`; every other attempt died on
`WSAEACCES`. The origin hostname travelled **inside** the CONNECT request, and DNS happened in the
parent process (`dns_locus=proxy`).

## 3. Guardrail 1 — post-launch proxy proof (TASK 2)

### 3.1 Implementation

*Attribution by epoch.* `proxy.begin_run()` bumps an epoch counter and returns it; every accepted
connection is tagged with the epoch current **at accept time**. After `v1::run` returns, the driver
asks for `proxy.sessions(epoch)` and gates on **that** slice only. An earlier run's traffic can
therefore never satisfy a later run's gate (structurally, not by convention).

*The gate.*

```rust
let pass = accepted >= 1 && tunnels >= 1;   // reached us, and we reached the origin
```

- `accepted >= 1` is the brief's minimum: the child actually reached the proxy endpoint.
- `tunnels >= 1` is stricter and catches the next failure mode: a child that connects but whose
  CONNECT is denied or whose origin dial fails (allow-list error, dead target) would show
  `accepted=1, tunnels=0`.

On failure the driver prints `SPIKE: guardrail_proxy_proof=FAIL`, a reason string, writes the run
record, and exits **3** — there is no code path that prints success after a failed proof.

### 3.2 Positive case (canonical run)

```
SPIKE: proxy_accepted_canonical=1 proxy_tunnels_canonical=1 proxy_accepts_total=1
SPIKE: guardrail_proxy_proof=PASS
SPIKE: guardrail_proxy_proof_detail label=canonical accepted=1 tunnels_established=1 bytes_down=3557 expected=PASS
SPIKE: real_https=PASS origin_status=404 ...
```

### 3.3 Negative case — the silent misconfiguration, caught

Same workload, same proxy, same port; only the MXC request changes to the **identity-scoped form,
deliberately wrong**: `allowedProxyPeer = "MXC-SpikeUnpackagedProxy"` (no such package/AppContainer
identity) with `ingress.hostLoopback = "deny"`.

```
SPIKE: negative_case=identity_scoped_wrong_peer peer=MXC-SpikeUnpackagedProxy hostLoopback=deny gate_armed=false
SPIKE: negative=ok outcome=exited:0
SPIKE: negative_warnings=[]
CHILD: proxy_connect=fail peer=127.0.0.1:56332 err=connection timed out os_code=None kind=TimedOut
CHILD: proxy_reachable=false
CHILD: https_status=none
SPIKE: proxy_accepted_negative=0 proxy_tunnels_negative=0 proxy_accepts_total=1
SPIKE: guardrail_proxy_proof=FAIL
SPIKE: guardrail_proxy_proof_detail label=negative accepted=0 tunnels_established=0 bytes_down=0 expected=FAIL
SPIKE: guardrail_proxy_proof_reason="no proxy session was accepted in this run's epoch: the child never reached the proxy"
SPIKE: real_https=FAIL origin_status=none ...
SPIKE: guardrail_negative_test=caught
```

The misconfigured run still reports `outcome=exited:0` and `warnings=[]` — exactly the trap — and the
guardrail is the only thing that says "this run did not work". Note `proxy_accepts_total=1` at that
point: the *canonical* run's connection is still in the totals, and the epoch filter is what keeps it
from laundering the negative run's gate.

`--suite=negative` runs the same case with the gate **armed as a hard requirement**, which is the
explicit demonstration of the non-zero exit:

```
SPIKE: guardrail_proxy_proof=FAIL
SPIKE: exit=nonzero code=3 reason="negative-only: guardrail_proxy_proof FAIL (expected)"
$ echo $?   →  3
```

In the default `--suite=all`, the negative run's FAIL is the *expected* outcome, so the process exits
0 only after printing `SPIKE: guardrail_negative_test=caught`; if the guardrail had **missed** it, the
driver exits 5.

### 3.4 Branch coverage of the gate (two extra runs)

The `tunnels >= 1` half of the gate is not decorative. Two runs with `--suite=canonical` and a
modified `MXC_SPIKE_TARGET` (the child still connects to `127.0.0.1` and gets a real proxy answer)
exercise the other failure branches:

| Case | Proxy answer | Session | Guardrail | Exit |
|---|---|---|---|---|
| Target does not resolve (`no-such-host.invalid:443`) | `502 Bad Gateway` | `accepted=1 tunnels=0`, `status=resolve_failed … 11001` | `FAIL` "accepted, but no CONNECT tunnel was established" | 3 |
| Target is loopback (`127.0.0.1:443`) | `403 Forbidden`, `X-Sandbox: denied` | `accepted=1 tunnels=0`, `status=denied_loopback_target` | `FAIL` (same reason) | 3 |

So the gate distinguishes three states — never reached us, reached us but nothing was tunnelled, and
full tunnel — and only the last one passes. Logs: `run-proxy-dialfail.log`,
`run-proxy-loopback-target.log`.


### 3.5 What this guardrail does and does not prove

Proves: a process inside the container reached our proxy during this run's window, and the proxy
reached the named origin. Does **not** prove: *which* child did it (fine for one run per proxy — a
product supervisor needs a per-session proxy or a per-run token, see §9), nor that the policy the
child believes it has is the policy we intended (that is the tier check, §4), nor anything about
requests after the first.

## 4. Guardrail 2 — per-session tier logging (TASK 3)

### 4.1 Implementation

`select_tier(&request, &backends)` calls **`v1::probe(Some(&request))` on the exact request that is
about to be launched** (not on a lookalike, not on `available_backends()` alone), and prints:

```
SPIKE: tier=base-container
SPIKE: tier_source=probe
SPIKE: tier_needs_dacl_augmentation=false
SPIKE: tier_probe_warnings=[]
SPIKE: tier_probe_error=none
SPIKE: tier_backend_ceiling=base-container
SPIKE: guardrail_tier=PASS tier=base-container tier_source=probe expected=base-container
```

`tier_source=probe` when `ProbeOutput.tier` is `Some`; `tier_source=backend` only when the probe
cannot name a tier, in which case `available_backends()[processcontainer].tier` (a documented
*ceiling*, not a promise) is used as a fallback and flagged as weaker evidence. `guardrail_tier` is
informational — the SDK has no way to *require* a tier (§8), so "PASS" means "observed and equal to
what we need", and the supervisor must refuse to run on `FAIL`.

### 4.2 Persisted session record

One JSON file per launch, `runs/<timestamp>-<label>.json` (timestamp is filename-safe UTC, no
colons; `startedUtc` keeps them):

```jsonc
{
  "schema": 1,
  "label": "canonical",
  "startedUtc": "2026-10-21T13:54:22Z",
  "elevated": false,
  "tier": "base-container",
  "tierSource": "probe",
  "tierExpected": "base-container",
  "tierOk": true,
  "needsDaclAugmentation": false,
  "tierProbeWarnings": [],
  "proxy": { "bind": "127.0.0.1", "port": 56332, "endpoint": "127.0.0.1:56332", "epoch": 1,
             "acceptedSessions": 1, "tunnelsEstablished": 1, "sessions": [ /* full Session */ ] },
  "guardrails": { "proxyProof": "PASS", "proxyProofExpected": "PASS", "tier": "PASS", "negativeTest": null },
  "realHttps": { "result": "PASS", "originStatus": 404, "target": "api.anthropic.com:443",
                 "dnsResolvedBy": "proxy" },
  "run": { "outcome": "exited:0", "warnings": [], "elapsedMs": 502 },
  "child": { "https_status": "404", "proxy_connect": "ok peer=127.0.0.1:56332", /* … */ },
  "hardFail": false,
  "hardFailReasons": []
}
```

The negative run writes the same shape with `proxyProof: "FAIL"`, `negativeTest: "caught"`,
`originStatus: null`. Both are left in place.

### 4.3 Where this belongs in a product supervisor

**In the session-start audit leaf, not in per-request leaves.** D-5's taxonomy already has a `source`
field on the `CONNECT` event; the tier is a *launch* property of the session (host probe + policy at
dispatch), constant for the container's lifetime, and the audit tree is a hash-chained leaf log —
duplicating a constant into every request leaf adds no evidentiary value and inflates the log. So:

- emit one `session.start` leaf per container, with `tier`, `tier_source` (`probe`|`backend`),
  `needs_dacl_augmentation`, `elevated`, and the proxy endpoint;
- keep the `CONNECT` leaves carrying `host`, `disposition`, `source`, `scope`, `persisted` exactly as
  D-5 specifies, plus a `session` id to join back;
- if the tier is wrong, the `session.start` leaf records the refusal and no `CONNECT` leaves exist —
  a clean, auditable "we noticed and did not run" instead of a silent downgrade.

The spike's per-run JSON is the same data in the same place, one file per session, before we have the
audit writer wired.

## 5. Product wiring: D-1..D-5 → MXC request fields (TASK 4)

| Our piece (ADR-0001) | MXC surface it maps onto | Verdict |
|---|---|---|
| **D-0** capability-SID loopback fix, admin-only `NetworkIsolationSetAppContainerConfig`, DACL ancestor walk, loopback journal | `Containment::ProcessContainer` + `ingress.hostLoopback` (allow for an unpackaged proxy) / `processContainer.network.allowedProxyPeer` (packaged proxy identity) | **Replaced.** No admin call, no elevation, per-container WFP scoping. The strongest gain of adoption. |
| **D-1** filter pipeline (hard-deny → learned → blocklist → allow → prompt/default), `source` attribution | *No MXC equivalent.* MXC's `egress.allow`/`deny` are `NetworkRulePolicy { to: [peer], ports: [port] }` — address/port rules, not hostnames, with no ordering, no prompt, no attribution. | **Stays above MXC**, in our proxy. MXC's job is to make our proxy the only exit: `egress.default = deny` + `runtimeConfig.networkProxy = http://127.0.0.1:<port>` + `ingress.hostLoopback = allow`. |
| **D-1** DNS pinning + Happy Eyeballs | none (we dial) | **Stays ours.** The spike proxy resolves once and dials; production keeps the pinning + race in the dialer. Under D-2 chaining, hostname-only admission as specified. |
| **D-1** CONNECT-to-loopback refusal, `403` + `X-Sandbox: denied` | none | **Stays ours.** Implemented in the spike proxy already (§2.1). |
| **D-1** proxy auth (`Proxy-Authorization: Basic`, session token in the URL) | only the URL string is injected (`networkProxy`) | **Stays ours**: token generation, `407`, constant-time compare. MXC will inject whatever URL we give it, including userinfo (untested with a token). |
| **D-2** upstream corporate proxy chaining | none — and must not be exposed to the child | **Stays ours.** The child must only ever see `127.0.0.1:<port>`; the host's `HTTPS_PROXY` must never reach `request.environment`. |
| **D-3** prompt dialog, 8-way semaphore, coalescing, learned store, `onUnavailable` | **none** | **Stays ours.** One new interaction: MXC's `timeout_ms` bounds the whole workload, so a 60 s prompt must fit inside it or the container is killed mid-dialog. The supervisor must own the run budget, not inherit a constant. |
| **D-4** intent registry (`POST /sandbox/intent`) | **none** | **Stays ours**, on the same loopback listener. Requires `ingress.hostLoopback = allow`; MXC injects `NO_PROXY` **unset** (observed), so the supervisor must add `NO_PROXY=localhost,127.0.0.1,::1` to `request.environment` itself. |
| **D-5** audit taxonomy (`CONNECT` + `source`/`scope`/`persisted`, `secret.inject`) | **none** — MXC returns only `ExecutionResult { outcome, warnings, stdout, stderr }` | **Stays ours.** Add the `session.start` leaf with the observed tier (§4.3). |
| Filesystem policy | `filesystem.readwritePaths` / `readonlyPaths` / `deniedPaths` / `clearPolicyOnExit` | **Directly usable**, with a caveat: grants are *additive*. The child could read `C:\Windows\win.ini` with only a scratch grant, so "only the workspace is readable" must be expressed with `deniedPaths`, not by omission. |
| Network policy | `network.egress.default`, `egress.allow/deny` (address/port rules), `network.ingress.default`, `ingress.hostLoopback`, `network.runtimeConfig.networkProxy`, `processContainer.network.allowedProxyPeer` | **Mostly usable.** `egress.default=deny` + `networkProxy` is the containment we want. `ingress.default=allow` is **mandatory** for proxy-only egress and grants bidirectional `privateNetworkClientServer`, i.e. private-network **inbound** too — accept it in the threat model or don't ship this mode. |
| UI policy | `ui.disable`, `ui.clipboard` (None/Read/Write/All), `ui.allow_input_injection`; `processContainer.ui` | **Available, unexercised.** Probe reports all ten UI capabilities blockable; nothing was enforced or attempted in this spike (`ui` left at its default `disable: true`). |

### What MXC does **not** give us (the honest gap list)

- **No prompt / intent dialog** — no user interaction surface at all (D-3, D-4).
- **No learned store** and no persistence of decisions (D-3).
- **No audit taxonomy**, no per-request attribution, no `source`/`scope`/`persisted`, no hash chain (D-5).
- **No prompt-overload semaphore / coalescing** — irrelevant to MXC, but it means the "8 concurrent
  prompts then deny" bound remains ours (D-3 [G-28]).
- **No hostname-based egress rules** — only address/port peer rules, so D-1's pipeline cannot be
  delegated even partially.
- **No `require_tier`** — tier is observable after dispatch, never a caller constraint.
- **No pre-run attestation** — no created-not-running handle, no `provision→start` split for
  ProcessContainer (§8).
- **No `NO_PROXY` injection** — must be supplied by us.
- **No proxy identity for an unpackaged proxy** — `allowedProxyPeer` is a package family name /
  AppContainer profile, not `host:port` (validated again this run: a `host:port` peer with
  `hostLoopback=allow` fails request build with `malformed_request`).
- **No exit from private-network inbound** while proxy mode is on.

## 6. API surface actually used (cited from crate source, not docs.rs)

Registry source: `~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/mxc-sdk-1.0.1/`

```rust
pub fn v1::run(request: ContainerRequest, options: RunOptions) -> Result<ExecutionResult, Error>
pub fn v1::spawn(request, SpawnOptions) -> Result<MxcProcess, Error>
#[cfg(windows)] pub fn v1::probe(request: Option<&ContainerRequest>) -> Result<ProbeOutput, Error>
pub fn v1::platform_support() -> PlatformSupport
pub fn v1::available_backends() -> Vec<AvailableBackend>
```

`v1::run` is `wait_with_output(spawn(..))` — in-process engine, no `wxc-exec` subprocess.

```rust
pub struct ContainerRequest { command, filesystem: Option<FilesystemPolicy>,
    network: Option<NetworkPolicy>, ui: Option<UiPolicy>, timeout_ms: Option<u32>,
    containment: Containment, container_name: Option<String>,
    working_directory: Option<String>, environment: Option<Vec<(String,String)>>,
    inherit_default_environment: Option<bool> }          // all fields public

pub struct NetworkPolicy { egress, ingress, runtime_config }
pub struct NetworkEgressPolicy { default, allow: Option<Vec<NetworkRulePolicy>>, deny: … }
pub struct NetworkRulePolicy { to: Option<Vec<NetworkPeerPolicy>>, ports: Option<Vec<NetworkPortPolicy>> }
pub struct NetworkIngressPolicy { default, host_loopback }
pub struct NetworkRuntimeConfig { network_proxy: Option<String> }   // host backends: localhost only
pub struct ProcessContainerNetwork { allowed_proxy_peer: Option<String> }  // identity, not endpoint
pub struct ProbeOutput { tier: Option<&'static str>, needs_dacl_augmentation: Option<bool>,
                         warnings: Vec<String>, probes: ProbeFacts, error: Option<String> }
```

`ProcessContainerConfig` / `ProcessContainerNetwork` are `#[non_exhaustive]`: build with
`Default::default()` + field assignment.

## 7. Existing findings that still stand

- `allowedProxyPeer` is a **package family name / AppContainer profile**, not `host:port`. A `host:port`
  value fails request build: `an identity-scoped ProcessContainer proxy requires
  network.ingress.hostLoopback='deny'` (`malformed_request`). Re-confirmed every run of this spike.
- The deployment for a **caller-owned, unpackaged proxy** is the *identity-less* one:
  `allowedProxyPeer` omitted + `ingress.hostLoopback: "allow"`. `networking.md` labels it
  development/testing compatibility and it is the weakest enforcement option.
- `ingress.default: "allow"` is **bidirectional** — it grants `privateNetworkClientServer`, so the
  container may also *serve* on private networks. Not opt-out-able in proxy mode.
- `inheritDefaultEnvironment: true` does **not** carry `USERNAME` into the child (`USERNAME=None`,
  `USERPROFILE` survives).
- The child can read `C:\Windows\win.ini`: filesystem grants are additive, not a blanket deny. Use
  `deniedPaths`.
- The identity-scoped form enforces **hard and silently**: launch succeeds, `warnings=[]`, exit 0,
  child's proxy connect times out. This is the finding the two guardrails exist for.

## 8. Attestation verdict: still absent

Searched the whole crate, then the public surface: no `pre_resume`/`preResume`/
`created_not_running`/`createdNotRunning`/`require_tier`/`requiredTier`/`requireTier` anywhere. The
only suspended-spawn primitive is **private** (`AppContainerScriptRunner::spawn_suspended` returning
the private `SpawnedChild`). `ProvisionContainment` has only `IsolationSession` and `Wslc`, so there
is **no provision→start split for ProcessContainer at all**: no created-but-not-running container can
be produced, and `run()` resumes the child internally. `AvailableBackend.tier` is a ceiling that
policy can lower at dispatch.

So ADR-0002's stop-work gate stands, and ADR-0004 Option A can only be taken as ADR-0003's
"bounded, not preventive" posture — with the residual risk written down.

## 9. What is still unproven

- **WinHTTP per-container proxy path.** Only the env-var path (`HTTP_PROXY`/`HTTPS_PROXY`) plus an
  explicit `CONNECT` from our own client was exercised. Chromium/WinHTTP clients use the injected
  per-container WinHTTP config, which this spike did not test.
- **Proxy identity-scoped mode with a real packaged proxy.** The working mode needs
  `hostLoopback: allow`; the strict mode requires packaging the proxy (or an AppContainer identity),
  which was not built.
- **Concurrent runs.** Guardrail 1's epoch attribution assumes one launch per proxy instance per
  epoch. A supervisor running N containers concurrently needs N proxy instances (or a per-run token
  in the CONNECT request, which we would have to add — MXC does not).
- **UI/clipboard policy** (`ui.disable`, clipboard modes, input injection) — probe capability only.
- **Filesystem depth**: `deniedPaths`, reparse points, inherited ACEs, `enumerate_paths`.
- **Inbound** private-network reachability (permitted by `ingress.default=allow`, not tested).
- **Long-running / interactive workloads**: one-shot runs only; `spawn` streaming, stdin, kill.
- **Tier fallback** on a host without `processmodel.dll`: typed error vs silent downgrade to
  `appcontainer-dacl`.
- **Proxy robustness**: our proxy is spike-grade — no auth, no HTTP/1.0 fallback, no upstream
  chaining, single allow-list, no rate limiting. None of it is meant to ship; the production proxy is
  ours anyway (D-1..D-4), which is the point.

## 10. What this means for adoption (updated)

**Adopt (Option A), with both guardrails wired as structural gates.**

1. Real egress works unelevated at `base-container`: our proxy can sit between the container and the
   internet and the ORIGIN is reachable only through it. The containment property is now end-to-end,
   not just "the child couldn't connect directly".
2. The silent-misconfiguration failure mode is **detectable in-process**, cheaply, with data we
   already own (our proxy's accept log). It must be wired into the supervisor's success path as a
   gate, not a log line: `run()` returning `exited:0` with `warnings=[]` is not success.
3. Tier must be observed per session and recorded; the supervisor must refuse to run on anything but
   the tier it needs, because MXC cannot be asked to require it.
4. What we keep: the entire decision layer (D-1..D-5) — filter pipeline, prompts, intent, learned
   store, audit, auth. What we delete: container creation, `CREATE_SUSPENDED` + job + resume, WFP
   policy construction, proxy env injection, stdio plumbing, teardown, DACL ancestor walk, the
   admin-only loopback exemption, and the elevation it forced.

**Top risks after this iteration**

1. **Guardrail 1 proves reachability, not identity.** It cannot tell *which* child connected, so
   concurrency needs a per-run proxy or token. Shipping it as-is with concurrent runs would let one
   container's success mask another's failure.
2. **The workable proxy deployment is the dev/test-grade one** (`hostLoopback: allow`, no peer
   identity), until the proxy is packaged.
3. **Tier/attestation are still not a contract.** No `require_tier`, no pre-resume handle — a
   security property that depends on PSEC can only be observed afterwards and refused.
4. **Private-network inbound** comes with proxy mode, unconditionally.

## 11. Artifacts

| Path | What |
|---|---|
| `src/main.rs` | Driver: elevation check, probes, guardrails 1 & 2, run records, negative test, suite selection. |
| `src/proxy.rs` | Real forwarding `CONNECT` proxy: allow-list, loopback-target refusal, dial, splice, per-epoch sessions. |
| `src/bin/workload.rs` | Workload inside the container: CONNECT → rustls TLS 1.3 → `GET`, plus direct-egress and filesystem probes. |
| `run.log`, `run.err.log` | Full `SPIKE:` output and proxy stderr of the default `--suite=all` run (exit 0). |
| `run-negative-only.log`, `run-negative-only.err.log` | `--suite=negative` with the gate armed (exit 3). |
| `runs/<timestamp>-canonical.json` | Guardrail PASS record: tier, elevated, proxy port, session, origin 404. |
| `runs/<timestamp>-negative.json` | Guardrail FAIL record: `negativeTest: "caught"`, `originStatus: null`. |
| `run-proxy-dialfail.log`, `run-proxy-loopback-target.log` | Gate branch coverage: `accepted=1/tunnels=0` for a failed origin dial and for a refused loopback target (both exit 3). Matching records are `runs/*-branch-dialfail.json` / `*-branch-loopback.json`. |
| `scratch/` | Staged `mxc-workload.exe`, `child-wrote.txt` written by the child, `SPIKE-REPORT-v1.md` (previous report). |
| `outside-policy/` | `canary.txt` (read denied to the child); `child-should-not-write.txt` absent — the write was denied. |

## 12. Reproduce (unelevated, no UAC)

```bash
cd C:/Users/marku/tools/sandbox/tests/vm/spikes/mxc-ga-spike
cargo build --offline          # rustls/ring resolve from the local registry cache
./target/debug/mxc-ga-spike.exe                  # exit 0: canonical PASS + negative caught
./target/debug/mxc-ga-spike.exe --suite=negative # exit 3: gate armed, FAIL is hard
./target/debug/mxc-ga-spike.exe --suite=canonical
```

Environment knobs: `MXC_SPIKE_TARGET` (default `api.anthropic.com:443`) and `MXC_SPIKE_PATH`
(default `/`); the proxy allow-list is derived from the target. Wall time: ~0.5 s for the canonical
run, ~5.2 s for the negative run (dominated by the child's 5 s proxy connect timeout), no stray
processes afterwards, no UAC prompts.
