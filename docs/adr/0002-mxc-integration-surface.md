# ADR-0002: MXC integration surface (WBD D-03 — stop-work gate)

> **Status:** Proposed (2026-10-17) — evidence complete; supersedes nothing (first D-03 record)
> **Amended 2026-10-21 by ADR-0004 (Option A):** the binding stop-work consequence below is RELAXED to
> ADR-0003's bounded-adapter posture, on condition of two mandatory guardrails (post-launch proxy proof
> as a hard gate; per-session tier logging). The attestation gap itself is UNCHANGED — still absent at
> mxc-sdk 1.0.1 — so a degraded launch is detectable, not preventable.
> **Scope:** WBD ticket D-03 (`input/WINDOWS_CLI_SANDBOX_WORK_BREAKDOWN.md` line 474, criteria lines 480-492). Consumes D-02 (`docs/research/wbd-d02-capability-matrix.md`). Binds ADR-0003 (D-04) and every product launch-path implementation ticket.
> **Origin:** `docs/design/2026-10-14-wbd-d03-d04-stop-work-gates-design.md` §3.2; implementation plan `docs/plans/2026-10-14-wbd-d03-d04-stop-work-gates.md`.
> **Evidence rule:** every claim below cites a fetched artifact (under `tests/vm/results/<run-id>/`, SHA256-verified against that run's `capture-manifest.json`) or a `file:line` at the pinned tree. Unexposed capabilities are recorded blockers, never inferences.

## 1. Provenance

| Item | Value | Evidence |
|---|---|---|
| MXC pin | `5d7a475a9fd5626bafb55c2c857989d2e5621245` | `d03d04-baseline.json` (both runs): `commit == pinnedCommit`, `pinMatches: true` |
| Template image | `sbx-base-b.vhdx`, SHA256 `95DAEA358027DF148620B71E247BD316632E83467E2E7A976317F4BBE202F5BE` | harness readiness output, both runs |
| Guest OS | build 29680 (Windows 11 Enterprise Insider Preview) — identical to the D-02 canonical guest | `d03d04-baseline.json` (both runs), `docs/research/wbd-d02-capability-matrix.md` §1 |
| Canonical runs | run 1 `20261017-121539-354`, run 2 `20261017-130259-402` (Amendment 1 supplementary; both `VM HARNESS: PASS`, `wxc/sdk/c ran=true`, `errorCount: 0`) | `d03d04-spike.json` + `capture-manifest.json` per run (30 artifacts each hash+size verified; `testcmd.log` is the documented harness caveat — written by the harness, unmanifested) |
| wxc-exec identity | `1.0.0+5d7a475a`, SHA256 `3FD125498803970B3FC7E63FC36307DD7A3186318FA02B83034F141731006DAC` — identical in both runs and equal to the D-02 canonical hash | `d03d04-baseline.json` both runs |
| Spike binary | run 2 SHA256 `45633617961F7C28EFB4EEB745F33D07489E6D00274D2EC3592F92FC462178C8` (run 1 `9B239ABE…` — superseded by the Amendment-1 spike) | `d03d04-baseline.json` per run |
| Guest tree dirty paths | 1 — identical to the D-02 canonical baseline in both runs | `d03d04-baseline.json` both runs |
| D-02 canonical (probe evidence) | run `20261014-005531-844` | `docs/research/wbd-d02-capability-matrix.md` §7 |

Run 1 and run 2 are **both** citable: run 1 recorded the workload-shape findings and the
schema-parse fail-closed behavior (§6); run 2 (Amendment 1: System32-resident
`powershell.exe Start-Sleep` workloads + `readonlyPaths C:\Windows` grants + the nested
`processContainer.filesystem.enumeratePaths` key) discharged the four lifecycle axes run 1
could not reach and moved C1 from schema rejection to adjudication refusal.

## 2. Three-way comparison

Surfaces: **wxc-exec.exe** (documented CLI, `src/tools/wxc`), **mxc-sdk** (Rust library,
in-tree `src/mxc-sdk`, published on crates.io as `mxc-sdk 1.0.0`, 2026-10-06,
`microsoft-oss-releases`, MIT), **src/ffi** (`mxc_ffi`, C ABI over the typed APIs).

| Axis | wxc-exec.exe (subprocess) | mxc-sdk 1.0.0 (library) | src/ffi (FFI) |
|---|---|---|---|
| 1. API support status | **Full lifecycle at runtime.** Exit propagation (0/7), stdio, stdin round-trip, request-level timeout, executor-kill teardown all proven (run 2 A1-A4 artifacts). CLI surface: config positional/`--config`/`--config-base64`, `--probe`, `--debug`, `--audit`/`--audit-verbose`, `--operation`, `--dry-run`, `--delete`, `--setup-hyperlight` (`wxc/src/main.rs:27-203`). **No require-tier flag** — tier forcing is compile-time cargo features only (`src/tools/wxc/Cargo.toml:37-38`). | **Full lifecycle at runtime.** All 8 spike scenarios exit 0 with real outcomes: probe, run-exit (0/7), run-stdio, spawn-stdin, timeout, cancel, force-tier, tier-query (run 2 `d03-sdk-*.json`). Public surface `mxc_sdk::v1`: `probe`, `run`, `spawn` → `MxcProcess::{wait, try_wait, kill, warnings, output_metadata, stdio, id}` (`lib.rs:331/:357`, `sandbox.rs:259`). | **Source-verified, not runtime-spiked.** 48 `#[no_mangle]` C-ABI exports incl. `mxc_spawn_json`, `mxc_run_json`, `mxc_probe_request_json`, `take_stdin/stdout/stderr`, `stream_read/write/flush`, `kill`/`kill_for_timeout`, `sandbox_free` (`src/ffi/mxc_ffi/src/lib.rs`, `streaming.rs:365`). Labeled **"Internal adapters … not SDK authoring APIs"** + `#[doc(hidden)]` (`src/mxc-sdk/src/lib.rs:379-381`); **"not a stable external ABI; regenerate bindings when this surface changes"** (`src/ffi/mxc_ffi/src/lib.rs:63-66`). |
| 2. Redistribution | Out-of-process exe; must be built/shipped and its process supervised. Documented role: non-SDK consumption "for testing or when the SDK cannot be embedded in your app" (upstream README). In the evidence lane it is built in-tree in the guest (D-02 sidecar pattern). | **In-process crate dependency** — the natural fit for the Rust product. Evidence lane uses the path dependency on the pinned tree (offline, warm cache); the crates.io 1.0.0 release exists for normal consumption. | `cdylib`+`staticlib`+`rlib` (`src/ffi/mxc_ffi/Cargo.toml:9-13`); the DLL is bundled by the Node SDK (`sdk/node/build.bat:130-132`) and bound by the .NET SDK via csbindlen (`sdk/dotnet/…/NativeMethods.g.cs`, `build.rs:34-62`). Redistribution model = ship a native DLL per platform. |
| 3. Schema/version coupling | Config crosses as **schema-1.0.0 JSON**, `deny_unknown_fields` (`stable.rs:58-69`); `process.timeout` verified in-contract (`stable.rs:32-53`); nested `processContainer.filesystem.enumeratePaths` (`stable.rs:310-315`). Binary is version+commit-stamped `1.0.0+5d7a475a`. Run 1 C1 proved fail-closed on unknown top-level fields (verbatim error recorded). | Typed `ContainerRequest` adapted to the same schema-1.0.0 wire contract (`config_contract_adapters/v1_0/one_shot.rs:113-119`, `wire.rs:151-153`). `ProcessContainerConfig`/`ProcessContainerFilesystem` are `#[non_exhaustive]` — construction only via `Default` + field mutation (E0639, verified by host `cargo check` at the pin, plan Task 4). | Policy crosses **only as exact-versioned JSON strings**; `experimental`/`dry_run` are i32 args, never JSON fields (`src/ffi/mxc_ffi/src/lib.rs:22-31`). Status codes 1-12 mirror `v1::ErrorCode`; 100-103 FFI-local (panic codes). |
| 4. stdout/stderr streaming | Separate capture per stream proven: `d03-wxc-a2-stdout.json` (`WXC-STDOUT-MARKER`), `d03-wxc-a2-stderr.json` (`WXC-STDERR-MARKER`) — both runs. | Separate capture proven: `d03-sdk-run-stdio.json` — `SDK-STDOUT-MARKER` on stdout only, `SDK-STDERR-MARKER` on stderr only (run 2; run 1 identical). `ExecutionResult { stdout, stderr, warnings }` (`sandbox.rs:236-253`). | `take_stdout`/`take_stderr`/`take_native_stdio`, `stream_read` (`streaming.rs:487/:500/:511/:533/:729`) — source-verified, not runtime-spiked. |
| 5. stdin | **Proven** (run 2): `d03-wxc-a2-stdin.json` = `WXC-STDIN-MARKER` — the forwarded line returned through the executor. (Run 1: unproven — external-command failure under the drive-root CWD fallback; see §6.) | **Proven** (both runs): `d03-sdk-spawn-stdin.json` — `stdinTaken: true`, `roundTrip: true`, stdout `HELLO-STDIN` (run 2). | `take_stdin` + `stream_write`/`flush` (`streaming.rs:487/:773/:811`) — source-verified, not runtime-spiked. |
| 6. Cancellation | Executor termination kills the workload: `d03-wxc-a4-cancel.json` (run 2) — workload alive at kill (PID 6228), `executorKilled: true`, `workloadProcessSurvivors: []`, `treeTornDown: true`. | `MxcProcess::kill` + `wait`: `d03-sdk-cancel.json` (run 2) — `tryWait: null` (running) → kill → `waitAfterKill: {exit: -1}`. | `kill`/`kill_for_timeout` (`src/ffi/mxc_ffi/src/lib.rs:1095/:1124`) — source-verified, not runtime-spiked. |
| 7. Process-tree teardown | **Proven** (run 2, a4): zero survivors after executor kill. Mechanism: `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` — the only limit flag ever set (`job_object.rs:241-249`), handle closed on `Drop` (`job_object.rs:415-425`); the child is assigned to the job **while suspended, before resume** (`base_container_runner.rs:1036-1042` → `:1098`), so a job-assignment failure kills the suspended child fail-closed (`:1058-1063`). | Same runner mechanism under the SDK (dispatcher → backend spawn, `dispatcher.rs:406-416`); runtime: cancel scenario kill+wait proven (above). `sandbox_free` kills the child tree if still running (FFI surface, `lib.rs:1156`). | Source-verified via `sandbox_free`/`kill` (`lib.rs:1095/:1156`). |
| 8. Request-scoped probing | `--probe` (detection-only, before COM init, accepts optional config; `wxc/src/main.rs:1058-1108`). **Not re-probed in this lane** — per spec §3.1 the probe criterion rides on the D-02 canonical run's 8 per-shape probe artifacts (run `20261014-005531-844`). | **Proven**: `v1::probe(Some(&request))` — request-scoped adjudication: empty request → `base-container`, `needsDaclAugmentation: false` (`d03-sdk-probe.json`); enumerate request → the `EnumeratePathsUnsupported` adjudication error verbatim (same artifact); forced request → `appcontainer-dacl` with `needsDaclAugmentation: true` (`d03-sdk-force-tier.json`, `honored: true`). Probe is a dry run of tier selection, not a launch (`probe.rs:8`). | `mxc_probe_request_json` (`lib.rs:546`, `+_with_error :581`) — source-verified, not runtime-spiked. |
| 9. Diagnostics | Backend error objects on failure paths: run 2 a3 `d03-wxc-a3-timeout.json` = `{"error":{"code":"backend_error","message":"script timed out after 3000ms"}}`; run 1's launch failures recorded verbatim (error strings in the wxc rows). `--debug`, `--log-file`, `--audit`/`--audit-verbose` (learning-mode flow `wxc/src/main.rs:1419-1461`); audit events post-launch carry backend/identity/tier/pid (`base_container_runner.rs:1555/:1599/:1614/:1901`). | `warnings` on every result (all `d03-sdk-*.json` carry them, empty when clean); `output_metadata`; upstream launch diagnostics exist for policy-shape failures (`launch_diagnostics.rs:243-250`, `missing_root_readonly` — the pwsh diagnostic, §6); `EnforcementDegraded` events fire pre-spawn/streaming and pre-execution/run (`dispatcher.rs:113-157`, call sites `dispatcher.rs:698`, `run.rs:238`). | `mxc_available_backends_json` (`lib.rs:511`), `mxc_platform_support_json` (`:524`), `output_metadata_json` (`:893`), `warnings_json` (`:936`); every entry point `catch_unwind`-wrapped, panics → `MXC_STATUS_PANIC 102` (`:178-236`). |
| 10. Signing | No Authenticode evidence at this pin: the evidence lane builds wxc-exec in-tree (unsigned dev build, identity pinned by SHA256, §1). Product redistribution signing is an implementation-ticket concern — **recorded, not investigated**. | crates.io source distribution; a library raises no Authenticode question of its own. Provenance controlled by the pin/lockfile (`Cargo.lock`), not signatures — **recorded, not investigated**. | The DLL is bundled unsigned by the Node/.NET SDKs at this pin — **recorded, not investigated**. |
| 11. Update strategy | Re-pin the tree, rebuild, re-run the capture lane; the version string embeds the commit (`1.0.0+5d7a475a`), so drift is detectable in every baseline artifact. | **Re-verify on every re-pin** (extends the D-02 matrix §5.1 caveat pattern to the SDK/FFI surfaces): the crates.io 1.0.0 ↔ pin relationship, the `#[non_exhaustive]` construction shapes, and the `file:line` refs in this ADR are all pin-specific. Semver on crates.io governs the published artifact; the pin governs the evidence. | ABI is explicitly unstable ("regenerate bindings when this surface changes", `lib.rs:63-66`) — any re-pin requires regenerated bindings; consumers are tracked in-tree (`sdk/node`, `sdk/dotnet`). |

**Not runtime-spiked** cells are source-verified at the pin and honestly marked; the FFI
surface was deliberately not exercised (it is an internal adapter layer, §5).

## 3. Investigation record (five mandated items)

1. **Created-but-not-running workloads: UNAVAILABLE at every surface.** The base-container
   runner creates the workload `CREATE_SUSPENDED` (`base_container_runner.rs:770-776`,
   call `:922-935`), attaches the PSEC environment **pre-creation** as a thread attribute
   (`:877-878` → `secenv.rs:175`, `UpdateProcThreadAttribute :231-241`), assigns the job
   object while still suspended (`:1036-1092`), then `ResumeThread` (`:1098`) **before**
   anything is returned (`:1150-1169`). Every early-exit path terminates the suspended
   child (`:1058-1063`, `:1104-1113`). The AppContainer runner's equivalent
   (`spawn_suspended :771`, `SpawnedChild::resume :1377-1397`) is **private**
   (`appcontainer_runner.rs:1352`, `:1385`); its only trait-visible path resumes at
   `:1822` before returning. The public SDK surface (`v1::spawn` `lib.rs:331`,
   `v1::run` `:357`, both via the dispatcher `dispatcher.rs:406-416`) hands back a
   **resumed** process; the `SandboxBackend` trait has no resume/staging method
   (`sandbox_process.rs:565`, `:590-595`); wxc-exec's run-to-completion path is the same
   (`sandbox_process.rs:685-689`). **A created-not-running window exists internally
   but no caller can reach it.** Recorded blocker (criterion 5).
2. **Pre-resume attestation: UNAVAILABLE** — it is a direct consequence of item 1: with no
   caller-reachable pre-resume window there is no point at which a caller can install or
   attest controls before workload code runs. What does exist is **spawn-time** tier
   reporting (`DispatchedProcess { process, tier, warnings }`, `dispatcher.rs:631-638`)
   and post-launch audit events whose tier field is a **hardcoded per-backend literal**
   (`base_container_runner.rs:1368-1377`; `appcontainer_runner.rs:1943-1949`). Recorded
   blocker (criterion 5); the stop-work consequence is §5.
3. **Generation-correlated ownership: PRESENT AS DEAD CODE at this pin.**
   `sandbox_tracking.rs` implements CSPRNG sandbox identities (`sandbox-{16 hex}`,
   `:44-49`), SID derivation (`:56-76`), and `HKCU\…\ProcessSandboxes\Mappings\{SID}`
   registry entries with Origin/CreatedTime/RequestedIdentity (`:9-22`, `:97-134`) — but
   **these functions have no callers** (grep: definitions/tests plus doc references in
   `mxc_common/audit.rs:466/:508/:789`). The base-container runner stamps the static
   literal `<process-security-environment>` as identity (`base_container_runner.rs:605`);
   live correlation exists only as the per-invocation `process_correlation_id`
   (`mxc_common/audit.rs:488-493`). Recorded as a partial capability with dead-code
   status, not as supported.
4. **Job Object resource controls: UI restrictions + kill-on-close only.** The only limit
   flag ever set is `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` (`job_object.rs:241-249`),
   giving abandonment-proof teardown (proven at runtime, run 2 a4). UI restrictions map
   to `JOB_OBJECT_UILIMIT_*` via `set_ui_limits` (`:192-225`, `:269-287`) but are called
   **only on AppContainer tiers** (`appcontainer_runner.rs:1203`); the base-container
   path rides the PSEC spec's `ui_restrictions` instead
   (`base_container_helpers.rs:47-52`, `base_container_runner.rs:1036-1043`).
   **Explicitly absent: memory limits, process-count limits, CPU-rate, affinity, and
   I/O limits** (no `JOB_OBJECT_LIMIT_PROCESS_MEMORY` / `_ACTIVE_PROCESS` /
   JobObjectCpuRateInformation anywhere in the tree). Recorded blocker for any
   resource-quota requirement.
5. **Query-back of effective controls: DENIED post-launch.** `MxcProcess` exposes
   warnings/metadata/id/stdio/wait/kill only — no tier accessor (`sandbox.rs:259`);
   `ExecutionResult`, `ExecutionMetadata`, and `ScriptResponse` carry no tier
   (`models.rs:1233-1240`, `:1198-1214`); `DaclGuardedProcess` holds no tier
   (`dispatcher.rs:745-808`). Tier is returned **at spawn time** on `DispatchedProcess`
   and appears post-launch only as the hardcoded per-backend audit literal (item 2).
   The only tier-reporting surface is the pre-launch probe dry run (`probe.rs:8`,
   `:24-26`, selection `:167-170`). Runtime proof: the tier-query scenario
   (`d03-sdk-tier-query.json`, run 2) — the running workload's own re-probe re-runs
   request adjudication (`tier: base-container`), not live state; the workload's exit
   code 3 is recorded but no per-process effective-tier accessor exists
   (repo-wide grep `effective_tier|query_tier|get_tier|live tier`: zero hits). This is
   the attestation gap ADR-0003 must mitigate.

## 4. Version/commit boundary and upgrade policy

- **Boundary:** all evidence at pin `5d7a475a9fd5626bafb55c2c857989d2e5621245`
  (in-tree `src/mxc-sdk`, path dependency, offline warm cargo cache). The published
  artifact is `mxc-sdk` **1.0.0** on crates.io (2026-10-06, `microsoft-oss-releases`,
  MIT, edition 2021). The ADR records the relationship but does **not** treat the
  crates.io tarball as the evidence lane (spec §6: out of scope).
- **Upgrade policy:** re-verify on every re-pin, extending the D-02 matrix §5.1 caveat
  pattern to the SDK/FFI surfaces. Specifically re-verify: (a) crates.io release vs pin
  drift; (b) `#[non_exhaustive]` construction shapes (E0639-class breakage, plan Task 4);
  (c) every `file:line` ref in this ADR; (d) the §3 verdicts — in particular item 1/2
  (the upstream would only need to make `spawn_suspended`/`resume` public to change the
  launch-path answer) and item 3 (the dead `sandbox_tracking.rs` gaining callers);
  (e) the nested-schema-key location for `enumeratePaths` (`stable.rs:310-315`) — run 1
  proved top-level emission fails closed at schema parse.
- **wxc-exec** is additionally self-identifying: `1.0.0+<commit>` plus the SHA256 in every
  baseline artifact, so a re-pin is detectable from artifacts alone.

## 5. Decision (evidence-constrained) and stop-work consequence

**Selected surface: the `mxc-sdk` Rust library, consumed as an in-process crate
dependency at the pinned tree.** It is the best-documented fit for a Rust product:

- typed request/result API with no subprocess or JSON-string boundary to supervise or
  parse (§2 axes 1-9 all runtime-proven on this surface);
- the full lifecycle the product needs is exposed and proven: probe → run/spawn →
  stdio/stdin → timeout → kill → wait (run 2 `d03-sdk-*.json`);
- the `force-tier-testing` cargo feature exists and is runtime-proven to move tier
  selection (`honored: true`, `appcontainer-dacl`, `needsDaclAugmentation: true`,
  `d03-sdk-force-tier.json`) — the D-04 require-tier seam (ADR-0003 §2);
- wxc-exec remains the **evidence/ops lane**: it is documented for "testing or when the
  SDK cannot be embedded", adds a whole process boundary per workload, and has no
  require-tier input (§2 axis 1);
- src/ffi is **rejected** as a product surface: upstream's own labels mark it internal,
  unstable, and aimed at language bindings (C#/.NET, Node) — for a Rust product it adds
  an ABI boundary with zero capability gain.

**Binding stop-work consequence (criterion 6):** created-not-running and pre-resume
attestation are **unavailable on every surface** (§3 items 1-2), and remain so at mxc-sdk
**1.0.1** (ADR-0004 re-verified crate-wide: no `pre_resume`/`created_not_running`/`require_tier`
symbol, and no provision→start split for ProcessContainer). **AMENDED 2026-10-21 (ADR-0004,
Option A):** the absolute prohibition is replaced by ADR-0003's bounded posture — a product
launch path MAY be implemented against `processcontainer` provided the residual exposure is
documented and the two ADR-0004 guardrails are mandatory (proxy proof after launch; tier
recorded per session). The prohibition below stands whenever either guardrail is absent.
Historically, the rule was: **no product
launch path may be implemented** until an upstream mechanism exists (the minimal upstream
change: make the suspended-spawn/resume pair, or a created-not-running handle, public on
the `SandboxBackend` trait / `v1` surface). Contracts and test infrastructure are not
affected; ADR-0003's preflight+attestation design consumes this verdict and must not
assume a pre-resume staging point at this pin.

## 6. Operational constraints discovered (workload resolution under PSEC)

Recorded from run 1's deviations because they bind product workload shapes:

- **Workload executables must be System32-resident or explicitly granted.** With
  `lpApplicationName = NULL` (`base_container_runner.rs:924`, `:925`) the OS resolves the
  first token through app-dir → CWD → System32 → Windows → caller PATH
  (`core/plm/wpr_path.rs:7-8`); the PSEC token is deny-by-default over the filesystem
  policy (`base_container_helpers.rs:62-65`). `pwsh.exe` (Program Files) is therefore
  unresolvable without a root-drive readonly grant — upstream's own diagnostic:
  `missing_root_readonly` (`launch_diagnostics.rs:243-250`, raised `:371-384`); observed
  as `CreateProcessW` WIN32_ERROR(2) in run 1. `cmd.exe` and `powershell.exe`
  (System32-resident) resolve (run 2 A1-A4).
- **A granted existing directory is required for a usable CWD.** Without one the engine
  falls back to `C:\` traverse-only (`working_directory.rs:41`, `:19-22`; selection order
  `models.rs:1124-1145`), and cmd **external** commands abort with "The current directory
  is invalid." (run 1 a2-stdin; internal `echo` still worked). Amendment 1's
  `readonlyPaths: C:\Windows` grant fixed all four axes (run 2).
- **`ping -n` is not a viable in-container sleeper** ("Unable to contact IP driver" —
  upstream documents the same, `run_processcontainer_process_plumbing_test.ps1:106`);
  the proven sleeper is System32 `powershell.exe -Command "Start-Sleep …"` with the
  readonly grant (upstream's own pattern, `run_processcontainer_crash_recovery_test.ps1:47`).
- **SDK nuance:** under the SDK's default `Containment::Process` + granted
  `FilesystemPolicy`, the powershell sleeper died at DLL init
  (`STATUS_DLL_INIT_FAILED 0xC0000142`, 51 ms — run 2 `d03-sdk-timeout.json`) rather
  than outliving the 3000 ms deadline; the request-timeout **mechanism** is proven on the
  wxc surface (run 2 a3: "script timed out after 3000ms" at 3387 ms) but was not
  distinguishable from natural exit on the SDK path in this run. Recorded as an
  observation (Process vs ProcessContainer produce different token shapes for the same
  `FilesystemPolicy`); not a surface-capability blocker.

## 7. Acceptance-criteria checklist (WBD lines 480-492)

| # | Criterion | Result | Evidence |
|---|---|---|---|
| 1 | Comparison covers all eleven axes | **Met** | §2 table (API status, redistribution, schema/version coupling, stdout/stderr, stdin, cancellation, tree teardown, request-scoped probing, diagnostics, signing, update strategy) |
| 2 | Minimal spike proves probe, launch, output, exit code, timeout, cancellation via documented/source-verified interfaces only | **Met** | Launch/output/exit/timeout/cancel: run 2 A1-A4 + `d03-sdk-run-exit/run-stdio/spawn-stdin/timeout/cancel.json`; probe: D-02 canonical run `20261014-005531-844` per-shape probe artifacts (spec §3.1 advisory) + run 2 `d03-sdk-probe.json`; every interface used is the documented `v1` surface or the pinned `New-Config` helper |
| 3 | Investigation records the five items | **Met** | §3 (items 1-2 blockers, item 3 dead-code partial, item 4 partial with explicit absences, item 5 denied) |
| 4 | Version/commit boundary + upgrade policy named | **Met** | §4 (pin `5d7a475a…`, crate 1.0.0 2026-10-06, re-verify-on-re-pin list) |
| 5 | Unavailable capabilities are recorded blockers, never invented | **Met** | §3 items 1/2/5, §2 axis 10 (signing: recorded-not-investigated), §3 item 4 absences; no interface outside the documented surface appears anywhere in the lane |
| 6 | If created-not-running/pre-resume is unsatisfiable: no product launch path | **Stated as binding** | §5: unavailable on every surface → **no product launch path until an upstream mechanism exists**; ADR-0003 must not assume a pre-resume staging point |

## 8. Raw-evidence index

- Run `20261017-121539-354` (canonical, pre-amendment): `d03d04-spike.json`,
  `d03d04-baseline.json`, `capture-manifest.json` (30 verified), `d03-config-*` (8),
  `d03-wxc-*` (7), `d03-sdk-*` (9 + build log + cargo.toml), `d03-c1-*`/`d03-c2-*`,
  `testcmd.log` (harness caveat).
- Run `20261017-130259-402` (Amendment 1 supplementary): same layout; deltas proving the
  four axes: `d03-wxc-a2-stdin.json` (marker), `d03-wxc-a3-timeout.json` (timeout error
  object), `d03-wxc-a4-cancel.json` (alive-at-kill, zero survivors, tree torn down),
  `d03-c1-launch.json` + `d03-c1-probe.json` (`EnumeratePathsUnsupported` adjudication
  refusal, `baseContainerSupportsEnumeratePaths: false`, marker canary absent),
  `d03-config-c1-enumerate.json` (nested schema key, schema-valid).
- D-02 canonical `20261014-005531-844`: `d02-matrix-<shape>.probe.json` ×8 (probe
  criterion), `d02-config-<shape>.json` ×8.
- Pin source refs: all `file:line` citations resolve at
  `5d7a475a9fd5626bafb55c2c857989d2e5621245`; consolidated verification pack at
  `C:\Users\marku\AppData\Local\hermes\cache\scratch\task8-line-ref-pack-5d7a475a.md`
  (scratch — the ADR is self-contained; the pack is the working record).
