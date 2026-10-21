# SPIKE: `mxc-sdk 1.0.1` on GA Windows — unelevated ProcessContainer with proxy-only egress

**Date:** 2026-10-21
**Host:** Windows 11 build **26300.9711** (GA 26H2), user `marku` (THOR), **unelevated**
**Toolchain:** rustc 1.98.1 (48a229cea 2026-09-01) / cargo 1.98.1 — no newer-Rust requirement
**Crate resolved:** `mxc-sdk v1.0.1` from crates.io (`registry+https://github.com/rust-lang/crates.io-index`), exact pin `=1.0.1`
**Spike dir:** `C:/Users/marku/tools/sandbox/tests/vm/spikes/mxc-ga-spike/` (untracked; no git writes)

## Verdict

| Question | Answer |
|---|---|
| Runs unelevated on GA Windows? | **Yes.** `TokenElevation = 0`, no UAC prompt, no elevation attempt. |
| Tier selected | **`base-container` (Tier 1, PSEC)** — the strongest tier, and it needed **no** `wxc-host-prep`. |
| Proxy reachable from the child? | **Yes.** `HTTP_PROXY`/`HTTPS_PROXY` injected; child's TCP `CONNECT` arrived at the loopback listener (`proxy_hits=1`). |
| Direct egress blocked? | **Yes, hard.** `WSAEACCES (10013)`, not a timeout, on both a raw IP and a DNS-resolved host. |
| Created-not-running / pre-resume attestation? | **Still absent** from the public API. Now also absent from the *lifecycle* API for ProcessContainer specifically (see §6). |

So: the core claim holds. The admin-only loopback exemption in the hand-rolled supervisor is
not needed — PSEC grants `networkLoopback` / per-container WFP scoping instead. But the
"proxy-only egress" story is narrower than the brief assumed, in three concrete ways (§5).

## 1. API surface actually used (cited from crate source, not docs.rs)

Registry source: `~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/mxc-sdk-1.0.1/`

**Entry points** (`src/lib.rs`, `src/sandbox.rs`):

```rust
pub fn v1::run(request: ContainerRequest, options: RunOptions) -> Result<ExecutionResult, Error>
pub fn v1::spawn(request: ContainerRequest, options: SpawnOptions) -> Result<MxcProcess, Error>
pub fn v1::spawn_with_pty(request, options: SpawnWithPtyOptions) -> Result<MxcPtyProcess, Error>
#[cfg(windows)] pub fn v1::probe(request: Option<&ContainerRequest>) -> Result<ProbeOutput, Error>
pub fn v1::platform_support() -> PlatformSupport
pub fn v1::available_backends() -> Vec<AvailableBackend>
```

`v1::run` is `wait_with_output(spawn(..))`, so both share the in-process engine — no
`wxc-exec` subprocess is launched. `v1::run` returns
`ExecutionResult { outcome: WaitResult, warnings: Vec<String>, stdout: Vec<u8>, stderr: Vec<u8>, output_metadata: Option<ExecutionMetadata> }`.

**Lifecycle ops** (`src/state_aware_sdk.rs`, re-exported as `v1::container::*`):

```rust
provision_container(ProvisionRequest, ProvisionOptions) -> Result<ProvisionResult, Error>
start_container(&ContainerId, StartOptions) -> Result<LifecycleResult, Error>
run_in_container(&ContainerId, ExecutionRequest, RunInContainerOptions) -> Result<ExecutionResult, Error>
spawn_in_container(&ContainerId, ExecutionRequest, SpawnInContainerOptions) -> Result<MxcProcess, Error>
stop_container(&ContainerId, StopOptions) -> Result<LifecycleResult, Error>
deprovision_container(&ContainerId, DeprovisionOptions) -> Result<LifecycleResult, Error>
validate_provision / validate_start / validate_stop / validate_deprovision / validate_process
```

**Request types** (`src/policy.rs`, `src/policy/network.rs`, `src/configs/process_container.rs`):

```rust
pub struct ContainerRequest { command, filesystem: Option<FilesystemPolicy>,
    network: Option<NetworkPolicy>, ui: Option<UiPolicy>, timeout_ms: Option<u32>,
    containment: Containment, container_name: Option<String>,
    working_directory: Option<String>, environment: Option<Vec<(String,String)>>,
    inherit_default_environment: Option<bool> }          // all fields public

pub enum Containment { Process, ProcessContainer(ProcessContainerConfig), Seatbelt(..),
                       Lxc(..), Bubblewrap, Wslc(..), IsolationSession }   // #[non_exhaustive]

pub struct FilesystemPolicy { readwrite_paths: Vec<String>, readonly_paths: Vec<String>,
                              denied_paths: Vec<String>, clear_policy_on_exit: Option<bool> }

pub struct NetworkPolicy { egress: Option<NetworkEgressPolicy>,
                           ingress: Option<NetworkIngressPolicy>,
                           runtime_config: Option<NetworkRuntimeConfig> }
pub struct NetworkEgressPolicy { default: Option<NetworkAction>,
                                 allow: Option<Vec<NetworkRulePolicy>>,
                                 deny: Option<Vec<NetworkRulePolicy>> }
pub struct NetworkIngressPolicy { default: Option<NetworkAction>,
                                  host_loopback: Option<NetworkAction> }
pub struct NetworkRuntimeConfig { network_proxy: Option<String> }   // "Host-process backends require localhost"

pub struct ProcessContainerConfig { learning_mode: bool, capabilities: Vec<String>,
    capture_denials: Option<CaptureDenials>, ui: Option<ProcessContainerUi>,
    filesystem: Option<ProcessContainerFilesystem>, network: Option<ProcessContainerNetwork> }
pub struct ProcessContainerNetwork { allowed_proxy_peer: Option<String> }
```

`ProcessContainerConfig` and `ProcessContainerNetwork` are `#[non_exhaustive]`, so out-of-crate
code must build them as `Default::default()` + field assignment, not a struct literal.

**Probe types** (`src/backends/process_container/common/probe.rs`, `src/core/mxc_engine/probe.rs`):

```rust
pub struct ProbeOutput { tier: Option<&'static str>, needs_dacl_augmentation: Option<bool>,
                         warnings: Vec<String>, probes: ProbeFacts, error: Option<String> }
pub struct AvailableBackend { backend: String, tier: Option<String>,
                              capabilities: Vec<BackendCapability>, warnings: Vec<String> }
```

## 2. Exact config JSON used (config A — the run that worked)

Emitted by the spike itself as `SPIKE: request_config_A=…`, unescaped here:

```jsonc
{
  "containment": "processcontainer",
  "command": "C:\\Users\\marku\\tools\\sandbox\\tests\\vm\\spikes\\mxc-ga-spike\\scratch\\mxc-workload.exe 127.0.0.1:49654",
  "workingDirectory": "C:\\Users\\marku\\tools\\sandbox\\tests\\vm\\spikes\\mxc-ga-spike\\scratch",
  "filesystem": {
    "readwritePaths": ["C:\\Users\\marku\\tools\\sandbox\\tests\\vm\\spikes\\mxc-ga-spike\\scratch"],
    "readonlyPaths": [],
    "deniedPaths": []
  },
  "network": {
    "egress":  { "default": "deny" },
    "ingress": { "default": "allow", "hostLoopback": "allow" },
    "runtimeConfig": { "networkProxy": "http://127.0.0.1:49654" }
  },
  "processContainer": { "network": { "allowedProxyPeer": null } },
  "environment": { "inheritDefault": true, "entries": [ /* MXC_SPIKE_* markers only */ ] },
  "timeoutMs": 60000
}
```

### Correction to the brief

The brief said to set `processContainer.network.allowedProxyPeer` to the proxy's **host:port**.
That is not what the field means. `networking.md` and `src/configs/process_container.rs:82`
define it as a **Package Family Name or AppContainer profile name**; the SDK's own tests use
values like `"Contoso.Proxy_123"` and `"S-1-15-2-1"`. A host:port value is rejected:

```
SPIKE: run_conflicting_peer_error code=malformed_request
  message="failed to build request: Configuration parse error: an identity-scoped
           ProcessContainer proxy requires network.ingress.hostLoopback='deny'"
```

(That error is really the `has_conflicting_proxy_identity` check firing — see §5.)

The documented deployment for a **caller-owned, unpackaged, non-AppContainer proxy** — which is
exactly what a hand-rolled supervisor's own proxy process is — is the *identity-less* one:
`allowedProxyPeer` **omitted** + `ingress.hostLoopback: "allow"`. That is config A above, and it
works. `networking.md` calls it the "development/testing compatibility" deployment and flags it as
the lowest-enforcement option.

## 3. Observed output (verbatim `SPIKE:` lines, canonical run)

```
SPIKE: elevated=false
SPIKE: process=pid:10264 user=Some("marku") host=Some("THOR")
SPIKE: parent_direct_egress=connected host_has_internet=true
SPIKE: platform_support={"isSupported":true,"reason":null,"availableMethods":["processcontainer"]}
SPIKE: available_backends=[{"backend":"processcontainer","tier":"base-container","capabilities":["captureDenials","filesystemDeniedPaths","filesystemEnumeratePaths","ingressHostLoopbackAllow","identitylessLoopbackProxy"]},{"backend":"windows_sandbox"}]
SPIKE: proxy_port=49654
SPIKE: workload_staged=C:\Users\marku\tools\sandbox\tests\vm\spikes\mxc-ga-spike\scratch\mxc-workload.exe
SPIKE: request_probe={"tier":"base-container","needsDaclAugmentation":false,"warnings":[],"probes":{"baseContainerApiPresent":true,"nativeCaptureAvailable":true,"guardedCaptureAvailable":false,"bfscfgPresent":false,"bfsCompiledIn":false,"baseContainerSupportsDenyPaths":true,"baseContainerSupportsEnumeratePaths":true,"baseContainerSupportsIngressHostLoopbackAllow":true,"baseContainerSupportsIdentitylessLoopbackProxy":true,"isolationSessionAvailable":false,"hyperlightAvailable":false,"uiCapabilities":{"canBlockClipboardRead":true,"canBlockClipboardWrite":true,"canBlockInputInjection":true,"canBlockInputMethodChanges":true,"canBlockExternalUiObjects":true,"canBlockGlobalUiNamespace":true,"canBlockDesktopSwitching":true,"canBlockLogoffOrShutdown":true,"canBlockSystemParameterChanges":true,"canBlockDisplaySettingsChanges":true}}}
SPIKE: run_elapsed_ms=221
SPIKE: run=ok outcome=exited:0
SPIKE: run_warnings=[]
SPIKE: run_stdout=CHILD: pid=39876
SPIKE: run_stdout=CHILD: env HTTP_PROXY=http://127.0.0.1:49654
SPIKE: run_stdout=CHILD: env HTTPS_PROXY=http://127.0.0.1:49654
SPIKE: run_stdout=CHILD: env http_proxy=http://127.0.0.1:49654
SPIKE: run_stdout=CHILD: env https_proxy=http://127.0.0.1:49654
SPIKE: run_stdout=CHILD: env NO_PROXY=<unset>
SPIKE: run_stdout=CHILD: proxy_connect=ok peer=127.0.0.1:49654
SPIKE: run_stdout=CHILD: proxy_request_sent=true
SPIKE: run_stdout=CHILD: proxy_response="HTTP/1.1 200 Connection Established |  | "
SPIKE: run_stdout=CHILD: proxy_reachable=true
SPIKE: run_stdout=CHILD: direct_egress=blocked peer=1.1.1.1:443 err=Der Zugriff auf einen Socket war aufgrund der Zugriffsrechte des Sockets unzulässig. (os error 10013) os_code=Some(10013) kind=PermissionDenied
SPIKE: run_stdout=CHILD: direct_egress_dns=blocked peer=104.20.23.154:443 err=... (os error 10013) os_code=Some(10013)
SPIKE: run_stdout=CHILD: fs_write_granted_path=ok path=...\scratch\child-wrote.txt
SPIKE: run_stdout=CHILD: fs_readback_granted_path=ok
SPIKE: run_stdout=CHILD: fs_read_outside_policy=denied path=...\outside-policy\canary.txt err=Zugriff verweigert (os error 5) kind=PermissionDenied
SPIKE: run_stdout=CHILD: fs_write_outside_policy=denied path=...\outside-policy\child-should-not-write.txt err=Zugriff verweigert (os error 5) kind=PermissionDenied
SPIKE: run_stdout=CHILD: fs_read_windir=READABLE(!)
SPIKE: run_stdout=CHILD: env USERNAME=None USERPROFILE=Some("C:\\Users\\marku")
SPIKE: proxy_hits_A=1 proxy_peers_A=["127.0.0.1:49656"]
SPIKE: tier=base-container
SPIKE: done
```

Proxy-side observation on stderr, which is the independent confirmation that the
connection really came from inside the container:

```
PROXY: accept peer=127.0.0.1:49656 bytes=59 request="CONNECT example.com:443 HTTP/1.1"
```

**Controls that make this meaningful**

- `parent_direct_egress=connected` — the host itself has internet, so the child's
  `10013` is containment, not a dead network.
- `10013` (`WSAEACCES`) rather than `WSAETIMEDOUT` means the refusal is an ACL/capability
  decision on the socket, not a dropped packet on a broken link. It arrives immediately
  (whole run: 221 ms).
- The exit code is `0` and the workload is a real PE from a directory the child may read and
  write — so the sandboxed process genuinely executed, not a stub.

**Total spike wall time:** ~5.5 s for three sandbox launches plus all probes.
**Stray processes afterwards:** none (`tasklist | grep -i mxc` empty).
**UAC prompts:** none. The process is `TokenElevation=0` for its entire life; a consent prompt
would have blocked the run and could not have produced these timings.

## 4. Tier selection and host prep

`available_backends()` reported:

```json
{"backend":"processcontainer","tier":"base-container","capabilities":[
  "captureDenials","filesystemDeniedPaths","filesystemEnumeratePaths",
  "ingressHostLoopbackAllow","identitylessLoopbackProxy"]}
```

`base-container` is Tier 1 in `fallback_detector::IsolationTier`
(`BaseContainer => "base-container"`, then `appcontainer-bfs`, then `appcontainer-dacl`), selected
because `BaseContainerRunner::is_base_container_api_present()` was true
(`probes.baseContainerApiPresent=true`) — i.e. `processmodel.dll`'s PSEC contract resolved.
`needsDaclAugmentation=false` and `bfsCompiledIn=false` (the `tier2_bfs` feature is off, so Tier 2
is unreachable in this build by construction).

`wxc-host-prep.exe` was **not** run, **not** present on disk, and **not** required. In the crate
source it appears only as a *recommendation string* attached to DACL-tier warnings
(`fallback_detector.rs:445`), never as a precondition on the BaseContainer path. So the
"elevated one-time host setup" applies to the tier we did not use.

## 5. Three ways reality is narrower than the brief

**(a) `allowedProxyPeer` is an identity, not an endpoint.** Covered in §2. The working config for
a caller-owned proxy has no peer field at all and instead spends `hostLoopback: "allow"`.

**(b) `ingress.default: "allow"` really is bidirectional.** `networking.md` is explicit and the
code agrees (`add_default_network_capabilities` gates on it): the single
`privateNetworkClientServer` capability grants private-network **inbound** as well. Config A
therefore lets the container *serve* on private networks. For a desktop agent sandbox that is an
attack-surface regression versus a pure-egress design, and it is not opt-out-able while proxy-only
egress is in use.

**(c) The identity-scoped deployment enforces hard, and fails silently.** Config C
(`allowedProxyPeer = "MXC-SpikeUnpackagedProxy"`, `hostLoopback: "deny"`) launched fine, injected
the proxy env, and then:

```
CHILD: proxy_connect=fail peer=127.0.0.1:49654 err=connection timed out kind=TimedOut
CHILD: proxy_reachable=false
SPIKE: proxy_hits_C=1   (unchanged — no new connection reached the proxy)
```

Two things to note. First, this is *good* evidence that per-endpoint WFP scoping works: the
client can only reach the proxy endpoint whose **peer identity** matches, and everything else on
loopback is dropped (timeout, not RST — consistent with a WFP block). Second, the bad peer name
was **not validated at launch**: the run returned `exited:0`, `warnings=[]`, and the workload
simply could not reach its proxy. Adoption must treat "proxy identity wrong" as a silent
misconfiguration, not an error.

## 6. Attestation verdict: absent

Searched (whole crate source, then the public surface specifically):

| Term | Result |
|---|---|
| `attest*` | Only internal: ETL learning-mode process-lifetime attestation (`process_lifetime.rs`, `etl_filter.rs`, `plm/elevated.rs::attest_job_process`). Not an SDK handle. |
| `pre_resume`, `preResume`, `created_not_running`, `createdNotRunning` | **No matches anywhere.** |
| `require_tier`, `required_tier`, `requireTier`, `requiredTier` | **No matches anywhere.** |
| `resume` | Only private internals: `appcontainer_runner.rs::AppContainerScriptRunner::spawn_suspended` (a **private `fn`**, line 771) returning `SpawnedChild` (a **private `struct`**, line 1352) with a private `resume()`. Not reachable from another crate. |

Two structural findings that matter more than the grep:

1. **`ProvisionContainment` has no ProcessContainer variant.** It is only
   `IsolationSession { app_id }` and `Wslc { image, image_tar_path }`
   (`state_aware_sdk.rs:28`). So for ProcessContainer there is no `provision → start` split *at
   all*: the lifecycle API cannot produce a created-but-not-running processcontainer. The only
   path is create-and-run, where the child is created `CREATE_SUSPENDED`, assigned to its job /
   security environment, and resumed — all inside one synchronous call that hands back nothing
   until the process has already run.
2. **No tier-requirement field on any request type.** `ProcessContainerConfig` exposes
   `learning_mode`, `capabilities`, `capture_denials`, `ui`, `filesystem`, `network` — and no way
   to say "fail rather than degrade below base-container". Tier choice is a host probe result
   (`AvailableBackend.tier`, documented as "a ceiling: policy can still force a weaker tier at
   dispatch"), never a caller constraint. A product that requires PSEC cannot assert it; it can
   only observe `tier` afterwards and refuse to run.

So ADR-0002's two gaps are **still open at 1.0.1**, and the second one got structurally worse:
the pre-resume window does not exist for this backend, not even internally at the API level.

## 7. What did NOT work, and what remains unproven

**Did not work / negative results**

- `allowedProxyPeer = "127.0.0.1:<port>"` → `malformed_request` at build time.
- Identity-scoped proxy with an arbitrary peer name → launches successfully, proxy unreachable
  (silent).
- `run.inherit_default_environment = true` does **not** carry `USERNAME` into the child
  (`CHILD: env USERNAME=None`) although `USERPROFILE` survives. Anything keyed on `USERNAME`
  inside the sandbox will not see it.
- The child can read `C:\Windows\win.ini`. `readwrite_paths` on one scratch dir is an *additive
  grant*, not a blanket deny. Anything relying on "only the scratch dir is readable" is wrong;
  use `denied_paths` for that, and note `filesystemDeniedPaths` is a reported capability.

**Unproven**

- **Real internet through the proxy.** The spike's listener returns `200 Connection Established`
  and closes; it never forwards. Whether an actual HTTPS request survives PSEC's per-container
  WinHTTP proxy + WFP egress filter is untested. This is the single most important gap before
  replacing anything.
- **WinHTTP vs env-var paths.** Only the `HTTP_PROXY`/`HTTPS_PROXY` env path was exercised. The
  per-container WinHTTP configuration (the path that matters for Chromium/WinHTTP clients) was
  not separately verified.
- **Clipboard/UI policy behaviour.** `ProbeOutput` says the host *can* block all ten UI
  capabilities, but nothing was enforced or attempted. `UiPolicy` was left at its default
  (`disable: true`).
- **Filesystem enforcement details** beyond one grant + one canary: no reparse points, no
  inherited-ACE paths, no `denied_paths` behaviour, no `enumerate_paths`.
- **Inbound.** §5(b) says private-network inbound is permitted; it was not tested, and the
  upstream doc separately notes an unresolved limitation where *host-to-container* listener
  connections time out under the proxy mapping on a different build (26691.1002 — not this host).
- **Long-running / interactive workloads.** One shot, 221 ms, exit 0. `spawn` streaming, stdin,
  and `kill` semantics were not exercised.
- **Tier degradation behaviour.** PSEC was present, so the fallback path never ran. What the SDK
  does on a host *without* `processmodel.dll` (typed error vs silent downgrade to AppContainer
  with weaker network enforcement) is unverified — and the doc says proxy requests should fail
  rather than fall back, which is the behaviour a product must be able to rely on.
- **Concurrency.** One container at a time; anonymous per-run AppContainer names, no collision
  testing.

## 8. What this means for replacing the hand-rolled AppContainer supervisor

**Adopt.** The central premise is confirmed on a GA build, unelevated, in-process, at the
strongest tier, with no host prep and no UAC. A `v1::run` call plus a `NetworkPolicy` replaces a
lot of supervisor code: container creation, `CREATE_SUSPENDED` + job assignment + resume,
PSEC/WFP policy construction, proxy env injection, stdio plumbing, and teardown. The
`ExecutionResult` surface (outcome + warnings + captured streams) is directly usable.

**Adopt with eyes open.**

1. *Proxy-only egress is not one configuration, it is three, and the one that fits a
   caller-owned proxy is the weakest one.* `hostLoopback: "allow"` + no peer is explicitly
   labelled development/testing compatibility. The stronger identity-scoped form requires the
   proxy to carry a package/AppContainer identity — which for us means **packaging the proxy**,
   or running it as an AppContainer. That is a real product decision, not a config flag. Until
   then we get endpoint-scoped WFP plus a blanket loopback grant.
2. *`ingress.default: "allow"` buys private-network inbound whether we want it or not.*
   Accept it explicitly in the threat model, or this spike's config is a downgrade on that axis.
3. *The tier is a hope, not a guarantee.* `available_backends()` reports a ceiling and there is
   no `require_tier`. A product that depends on PSEC semantics must check
   `tier == "base-container"` at startup and refuse to run otherwise — and must treat a
   `warnings: []` + `exited: 0` + unreachable-proxy run as a *failure it has to detect itself*.
4. *Attestation is still missing.* Same two gaps as ADR-0002. Adopting at 1.0.1 means keeping
   whatever out-of-band identity check the product needs today.

**Top 3 risks for adoption**

1. **Silent network misconfiguration.** A wrong/absent proxy identity produces a clean launch,
   empty warnings, exit 0, and a workload that cannot reach its proxy (observed in config C). Any
   error surface that trusts `warnings` will report success.
2. **The only viable proxy deployment for an unpackaged proxy is the one upstream calls
   dev/test-grade** — loopback open, no peer identity, and no way to prove which host process owns
   the endpoint. If we upgrade to identity-scoped, our proxy must be packaged.
3. **Tier/attestation are not enforceable contract.** No `require_tier`, no pre-resume handle,
   and no ProcessContainer lifecycle at all — so a PSEC-dependent security property can neither be
   asserted in the request nor attested before the workload runs, and would silently not exist on
   a host that falls back to `appcontainer-dacl`.

## 9. Artifacts

| Path | What |
|---|---|
| `src/main.rs` | Spike driver: elevation check, probes, loopback proxy, three request shapes. |
| `src/bin/workload.rs` | Workload run inside the container (`CHILD:` lines). |
| `run.log` | Full `SPIKE:` output of the last run. |
| `run.err.log` | Proxy accept log (independent confirmation of the connection). |
| `scratch/` | Left for inspection: staged `mxc-workload.exe`, `child-wrote.txt` written by the child. |
| `outside-policy/` | Left for inspection: `canary.txt` (read denied to the child). `child-should-not-write.txt` is **absent** — the child's write was denied (`os error 5`) and never landed. |

Reproduce: `cargo build && ./target/debug/mxc-ga-spike.exe` from the spike directory, unelevated.
