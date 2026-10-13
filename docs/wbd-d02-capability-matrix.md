# WBD D-02: BaseContainer/PSEC capability matrix

Status: COMPLETE. Ticket: `input/WINDOWS_CLI_SANDBOX_WORK_BREAKDOWN.md` D-02
(line 447). All verdict cells cite fetched artifacts from the canonical run;
all source references cite the pinned MXC tree (`5d7a475a…`) fetched via
`raw.githubusercontent.com` at the exact pin (file paths and line numbers are
valid for commit `5d7a475a9fd5626bafb55c2c857989d2e5621245`).

## 1. Provenance

| Item | Value | Evidence |
|---|---|---|
| Canonical run | `20261014-005531-844` (image `sbx-base-b`, mode `testcmd`) | `tests/vm/results/20261014-005531-844/` |
| VM template | `sbx-base-b.vhdx`, 25.44 GB, SHA256 `95DAEA358027DF148620B71E247BD316632E83467E2E7A976317F4BBE202F5BE` | harness log line `[vm-host] template: sbx-base-b.vhdx` |
| Guest OS | Windows 11 Enterprise Insider Preview, build **29680** | `wbd-d01-baseline.json` `os.buildNumber` |
| MXC pin | `5d7a475a9fd5626bafb55c2c857989d2e5621245`, `pinMatches: true` | `wbd-d01-baseline.json` `mxc` |
| Executor | `wxc-exec` 1.0.0+5d7a475a, SHA256 `3FD125498803970B3FC7E63FC36307DD7A3186318FA02B83034F141731006DAC`, 5,772,288 bytes | `wbd-d01-baseline.json` `mxc.wxcExecSha256` |
| Upstream suite | `run_processcontainer_probes_test` 10/10 PASS, exit 0 | `d02-upstream-probes.log` |
| Manifest | 25 artifacts; 24 of 25 hashes verify against the fetched files | `capture-manifest.json` |

Known-benign manifest exception: `testcmd.log` is hashed by the capture
manifest *before* the harness finishes appending the guest console transcript
to it (`Invoke-TestsInVM.ps1:735` tees streamed output line-by-line). The
manifest entry therefore covers a 411-byte prefix of the fetched 538-byte
file. The same pattern exists in the prior canonical run
(`20261013-220007-020`: 319-byte manifest entry vs 446-byte file), so this is
structural harness behavior, not evidence tampering. All 24 evidence-bearing
artifacts hash-verify.

Build-number note: the ticket title names build 29671.1000; per the D-01
decision (2026-10-12, probes-not-build-number authoritative), the image ships
29680.1000 and every verdict below is request-scoped probe evidence, never
inferred from the build number.

## 2. Verdict table — the five WBD request shapes

All eight probed shapes (the ticket's five, with filesystem split rw/ro/denied
like the upstream suite and proxy split into its two model-2 variants)
resolve to `base-container` with `needsDaclAugmentation: false`, exit 0, no
probe warnings, no probe errors. Summary artifact: `d02-matrix.json`
(`ran: true`, `errorCount: 0`). No shape resolved to AppContainer and no
shape returned ambiguous data, so there are no **blocked** rows among the
eight. Capability limits that *would* block other request forms are recorded
in §4/§5 — as source-verified facts, clearly separated from probe-observed
verdicts.

| Shape | Tier | needsDaclAug | Exit | Verdict | Config artifact (SHA256-verified) | Enforcement mechanism (source at pin) |
|---|---|---|---|---|---|---|
| empty | base-container | false | 0 | UNBLOCKED | `d02-config-empty.json` | No policy features; serviceable by definition (`base_container_runner.rs:434-477`) |
| fs-rw | base-container | false | 0 | UNBLOCKED | `d02-config-fs-rw.json` | PSEC `fs_read_write` (`base_container_helpers.rs:62`); no support bit required |
| fs-ro | base-container | false | 0 | UNBLOCKED | `d02-config-fs-ro.json` | PSEC `fs_read_only` (`base_container_helpers.rs:63`); no support bit required |
| fs-denied | base-container | false | 0 | UNBLOCKED | `d02-config-fs-denied.json` | PSEC `fs_deny` (`base_container_helpers.rs:64`), gated by support bit `FileSystemDeny` = **true** (`base_container_runner.rs:464-465`, `secenv.rs:60-62`) |
| ui | base-container | false | 0 | UNBLOCKED | `d02-config-ui.json` | `ui.disable` → `disallow_win32k_system_calls` (`base_container_helpers.rs:60`); clipboard/injection + isolation/desktop/systemSettings/ime → job-object UI-limit mask (`base_container_helpers.rs:47-52`, `job_object.rs:153-165`); all 10 UI bits enforceable on build 29680 (§3.4) |
| deny-all-network | base-container | false | 0 | UNBLOCKED | `d02-config-deny-all-network.json` | PSEC egress table `default_action: deny` (`base_container_helpers.rs:106-119`); ingress default/hostLoopback both deny → no native ingress table needed (`hostLoopback != allow`, `base_container_helpers.rs:123-127`) |
| proxy-identityless | base-container | false | 0 | UNBLOCKED — with §5 caveat | `d02-config-proxy-identityless.json` | PSEC-1.0 proxy-loopback workaround: `networkLoopback` capability + `MXC-Loopback` peer + proxy URL, no native ingress table (`base_container_helpers.rs:41-46,121-127,159-165`; workaround gate `base_container_runner.rs:394-409,467-475`) |
| proxy-identity-scoped | base-container | false | 0 | UNBLOCKED | `d02-config-proxy-identity-scoped.json` | `allowedAppContainerPeer` = `Contoso.Proxy_8wekyb3d8bbwe` + proxy URL (`base_container_helpers.rs:128,159-165`); `hostLoopback: deny` → no unrestricted-loopback check (`base_container_helpers.rs:152-157`) |

Per-shape probe artifacts: `d02-matrix-<shape>.probe.json` (all eight SHA256
`47700E7796DB…` — see §3.1 for why they are byte-identical). Per-shape exit
codes, tiers, and config hashes cross-checked against `d02-matrix.json` rows
and `capture-manifest.json` entries.

## 3. How the probe adjudicates (semantics)

### 3.1 The probe output is two distinct things

`wxc-exec --probe --config <cfg>` emits one JSON object with two halves
(`backends/process_container/common/probe.rs:23-38`):

1. **`probes` — host facts, request-independent.** Same bytes for every valid
   config (`probe.rs:143-165` queries the host, never the policy). This is
   why all eight `d02-matrix-<shape>.probe.json` artifacts are byte-identical
   (SHA256 `47700E7796DB…`) and identical to the D-01 bare probe log
   `d01-wxc-exec-probe.log`.
2. **`tier` / `needsDaclAugmentation` / `warnings` / `error` — the
   request-adjudicated decision.** `run_probe` feeds the parsed request into
   `fallback_detector::choose_backend_tier(request)` (`probe.rs:167-171`),
   which calls `BaseContainerRunner::can_backend_service_request(request)`
   (`fallback_detector.rs:284-305`) — a per-request gate, not a parse check
   (`base_container_runner.rs:434-477`). An unserviceable request yields
   `error` with `tier`/`needsDaclAugmentation` omitted
   (`probe.rs:199-213`). Our eight identical outputs reflect identical
   *decisions* (all Serviceable, zero warnings), not absent adjudication.

### 3.2 The request-level gate, in order (`base_container_runner.rs:434-477`)

1. PSEC api set not present → `Unavailable` (probe bit
   `baseContainerApiPresent`, true here).
2. `leastPrivilegeMode`, or an enabled proxy that was not specified as a
   runtime config → `PolicyIncompatible`. (All our proxy shapes use
   `runtimeConfig.networkProxy`, so they pass.)
3. `captureDenials` requested without native capture →
   `NativeCaptureUnavailable`. (No matrix shape requests capture.)
4. `enumeratePaths` non-empty without `FileSystemEnumerate` support →
   `EnumeratePathsUnsupported`. (No matrix shape uses enumeratePaths.)
5. `deniedPaths` non-empty without `FileSystemDeny` support →
   `DeniedPathsUnsupported`. (True on this host, so fs-denied passes.)
6. `ingress.hostLoopback == "allow"` without `NetworkIngress` support and
   without the PSEC-1.0 proxy workaround → `IngressUnsupported`
   (`base_container_runner.rs:467-475`). This is the gate that
   `proxy-identityless` passes via the workaround (§5.1).

Everything else → `Serviceable` → Tier 1 BaseContainer,
`needsDaclAugmentation: false` by construction (`fallback_detector.rs:324-332`).

## 4. Capability boolean → PSEC contract mapping (21 booleans)

Sources fetched at pin `5d7a475a9fd5626bafb55c2c857989d2e5621245`. The PSEC
host API is `HRESULT QueryProcessSecurityEnvironmentSupport(UINT64*
supportFlags)` (`secenv.rs:109-110`); support bits and required versions are
(`secenv.rs:57-84`): `FileSystemDeny = 0x1` (PSEC **1.0**),
`FileSystemEnumerate = 0x4` (PSEC **1.1**), `NetworkIngress = 0x8`
(PSEC **1.1**). Version queries go through
`QueryProcessSecurityEnvironmentVersion`-backed `supports_version`
(`secenv.rs:494-500`).

### 4.1 Observed values (run `20261014-005531-844`, identical in all 8 probe artifacts + `d01-wxc-exec-probe.log`)

| Probe boolean | Observed | Origin (source at pin) | PSEC dependency |
|---|---|---|---|
| baseContainerApiPresent | true | `is_api_set_implemented(SECURITY_ENVIRONMENT_API_SET)` (`base_container_runner.rs:308-316`) | api-set presence (version-independent) |
| nativeCaptureAvailable | true | api present **and** `LearningModeApi::load().is_ok()` (`base_container_runner.rs:319-335`) | PSEC + Learning-Mode ABI |
| guardedCaptureAvailable | **false** | engine guarded-WPR availability: WPR present + guardian check (`core/mxc_engine/guarded_capture.rs:91-102`, injected at `core/mxc_engine/request_probe.rs:44-47`) | none (WPR/Etw, not PSEC) |
| bfscfgPresent | **false** | `fallback_detector::find_bfscfg_exe()` — `Ok(None)` unconditionally with the `tier2_bfs` feature off (`probe.rs:56-61,148-151`) | none |
| bfsCompiledIn | **false** | `cfg!(feature = "tier2_bfs")` (`probe.rs:152`) — release binary built without Tier-2 BFS | none |
| baseContainerSupportsDenyPaths | true | `query_support(FileSystemDeny)` (`base_container_runner.rs:338-346`, `secenv.rs:503-509`) | bit 0x1, PSEC 1.0 |
| baseContainerSupportsEnumeratePaths | **false** | `query_support(FileSystemEnumerate)` (`base_container_runner.rs:349-352`) | bit 0x4, PSEC 1.1 — **not advertised** |
| baseContainerSupportsIngressHostLoopbackAllow | **false** | `query_support(NetworkIngress)` (`base_container_runner.rs:356-359`) | bit 0x8, PSEC 1.1 — **not advertised** |
| baseContainerSupportsIdentitylessLoopbackProxy | true | ingress support **or** PSEC-1.0-only host: `V1_1` unsupported → `V1_0` supported (`base_container_runner.rs:363-392`) | true *because* the host is 1.0-only (§5.1) |
| isolationSessionAvailable | **false** | backend-static false; engine overlay only when the `isolation_session` feature is compiled in (`probe.rs:80-84`, `request_probe.rs:49-55`) | none |
| hyperlightAvailable | **false** | backend-static false; engine overlay only with the `hyperlight` feature + WHP (`probe.rs:85-88`, `request_probe.rs:57-62`) | none |

### 4.2 `uiCapabilities.canBlock*` (all 10 true)

Origin: `job_object::supported_ui_restrictitions()` (`probe.rs:163`) →
`supported_ui_restrictions_for_build(build)` (`job_object.rs:153-165`) — a
pure build-gated map of `JOB_OBJECT_UILIMIT_*` kernel flags:

| Boolean | Kernel flag | Build gate |
|---|---|---|
| canBlockClipboardRead / canBlockClipboardWrite | `JOB_OBJECT_UILIMIT_READCLIPBOARD` / `_WRITECLIPBOARD` | universal |
| canBlockInputInjection | `JOB_OBJECT_UILIMIT_INJECTION` (0x200) | ≥ build 26100 (`job_object.rs:108-112`) |
| canBlockInputMethodChanges | `JOB_OBJECT_UILIMIT_IME` (0x100) | ≥ build 22621 (`job_object.rs:98-106`) |
| canBlockExternalUiObjects | `JOB_OBJECT_UILIMIT_HANDLES` | universal |
| canBlockGlobalUiNamespace | `JOB_OBJECT_UILIMIT_GLOBALATOMS` | universal |
| canBlockDesktopSwitching | `JOB_OBJECT_UILIMIT_DESKTOP` | universal |
| canBlockLogoffOrShutdown | `JOB_OBJECT_UILIMIT_EXITWINDOWS` | universal |
| canBlockSystemParameterChanges | `JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS` | universal |
| canBlockDisplaySettingsChanges | `JOB_OBJECT_UILIMIT_DISPLAYSETTINGS` | universal |

Guest build 29680 ≥ 26100, so all ten bits are enforceable — consistent with
the observed all-true block. The ui-shape request maps onto these flags via
`resolve_ui_restrictions` (`ui_policy.rs:47-70`; clipboard `"none"` blocks
both directions) and the encoder `to_job_object_uilimit_mask`
(`base_container_helpers.rs:47-52`).

## 5. Host contract findings

### 5.1 This host is PSEC 1.0-only — the proxy-identityless verdict rides a temporary upstream workaround

Evidence chain: `NetworkIngress` (0x8) not advertised →
`supports_ingress_host_loopback_allow() == false`; yet
`baseContainerSupportsIdentitylessLoopbackProxy == true`, which per
`base_container_runner.rs:373-392` is only possible when `V1_1` is
unsupported **and** `V1_0` is supported. The proxy-identityless shape
(`hostLoopback: allow` + runtime proxy, no peer) therefore passes the §3.2
gate 6 only through `psec_1_0_proxy_loopback_workaround`
(`base_container_runner.rs:394-409,467-475`), whose own comment marks it
*temporary*: "Remove once those hosts support PSEC 1.1; keep loopback allow
opt-in." Its PSEC encoding carries the `networkLoopback` capability and the
`MXC-Loopback` peer instead of a native ingress table
(`base_container_helpers.rs:41-46,121-127,159-165`).

**Consequence for the matrix:** the UNBLOCKED verdict for
`proxy-identityless` is correct for pin `5d7a475a` on PSEC-1.0-only hosts,
but it is regression-prone — when the workaround is removed upstream (or on a
host advertising PSEC 1.1), this shape's adjudication changes. Re-verify on
every re-pin; do not treat this row as a stable contract.

### 5.2 Capability limits not exercised by the eight shapes (source-verified, NOT probe-observed)

Recorded as capability-mapping facts; no inference is made that they are
supported:

- **`ingress.hostLoopback = "allow"` without a runtime proxy** is blocked on
  this host: gate 6 fails (`IngressUnsupported`,
  `fallback_detector.rs:303-305`, `probe.rs:622-634` unit test confirms the
  error shape) because `NetworkIngress` (PSEC 1.1) is not advertised and the
  workaround requires a runtime proxy. The matrix's only hostLoopback-allow
  request is the proxy variant in §5.1.
- **`processContainer.filesystem.enumeratePaths`** is blocked:
  `FileSystemEnumerate` (PSEC 1.1) not advertised →
  `EnumeratePathsUnsupported` (`base_container_runner.rs:461-463`,
  `fallback_detector.rs:300-302`). Observed indirectly: the upstream suite's
  P1 records `supportsEnumeratePaths present-but-False`
  (`d02-upstream-probes.log` line 10).
- **Guarded capture (`guardedCaptureAvailable=false`)** and **Tier-2 BFS
  (`bfsCompiledIn=false`)** are unavailable; any `captureDenials` request that
  falls back off base-container with no guarded capture fails closed
  (`probe.rs:186-198`). Not exercised by matrix shapes.

## 6. Acceptance-criteria checklist (D-02, ticket line 456-464)

| Criterion | Result | Evidence |
|---|---|---|
| Empty and planned R1 requests resolve to `base-container` | **Met** — 8/8 shapes, tier `base-container`, `needsDaclAugmentation: false`, zero warnings | `d02-matrix.json` (`ran: true`, `errorCount: 0`); per-shape `d02-matrix-<shape>.probe.json` |
| Each required policy probed as a complete request, not inferred from OS build number | **Met** — all eight configs are complete requests generated by the upstream `New-Config` helper (schema-exact by construction) and adjudicated per request through `choose_backend_tier` → `can_backend_service_request` (`probe.rs:167-171`, `base_container_runner.rs:434-477`); the build number appears only in provenance | `d02-config-<shape>.json` (8 artifacts, SHA256-verified), `d02-matrix.json` rows |
| Any policy resolving to AppContainer or returning ambiguous capability data is marked blocked | **Met vacuously** — no shape resolved to AppContainer and none returned ambiguous data (all eight: exit 0, no warnings, no errors, no omitted `tier`), so there are no blocked rows among the eight; unexercised blocked forms are recorded as source-verified capability limits (§5.2), never inferred as supported | `d02-matrix.json`, §5 |
| Results distinguish symbol presence, PSEC environment creation support, and request compatibility where MXC exposes those distinctions; unobservable distinctions become upstream blockers, not inferred results | **Met** — all three distinctions are exposed and captured: api-set/symbol presence = `baseContainerApiPresent`; PSEC contract support = the `query_support` bits + `supports_version` (§4, `secenv.rs:57-84,494-509`); request compatibility = the request-adjudicated tier decision (§3). No required distinction was unobservable, so no upstream blocker is raised. The probe's one request-independence caveat (identical `probes` blocks, §3.1) is documented rather than inferred away | `d02-matrix-<shape>.probe.json` + §3/§4 |

## 7. Raw-evidence index (canonical run `20261014-005531-844`)

- `d02-matrix.json` — 8-row summary (`ran`, `blocker`, `shapes`, `errorCount`)
- `d02-matrix-<shape>.probe.json` × 8 — verbatim probe output per shape
- `d02-config-<shape>.json` × 8 — the exact complete requests probed
- `wbd-d01-baseline.json` — pin/template identity + embedded `d02Matrix` block
- `d02-upstream-probes.log` — upstream suite 10/10 PASS
- `capture-manifest.json` — 25 artifacts, SHA256 each (§1 caveat on `testcmd.log`)

Supersedes runs `20261013-220007-020` and `20261013-173137-189` for D-02
evidence (both pre-date the matrix section).
