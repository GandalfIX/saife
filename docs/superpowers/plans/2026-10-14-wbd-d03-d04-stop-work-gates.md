# WBD D-03 + D-04 Stop-Work Gates Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete WBD tickets D-03 and D-04 — the stop-work gates: one runtime spike lane (new `tests/vm/wbd-d03-d04-spike.ps1` + a committed Rust spike crate) exercising both leading MXC integration surfaces inside the image-B VM, then two decision records (`docs/adr/0002-mxc-integration-surface.md`, `docs/adr/0003-basecontainer-only-enforcement.md`) written from the fetched artifacts and source refs at the pin.

**Architecture:** One capture script produces all runtime evidence for both tickets in one canonical VM run: Section A drives `wxc-exec.exe` lifecycle (launch/exit/stdio/stdin/timeout/cancellation) as a subprocess; Section B builds a committed spike crate against the pinned tree's `src/mxc-sdk` via path dependency (offline, warm cache) and exercises the documented `mxc_sdk::v1` surface in-process (probe/run/spawn/timeout/cancel/force-tier/tier-query); Section C captures D-04 enforcement evidence (enumeratePaths fail-before-exec with marker-file proof, env-downgrade immunity of the shipping executor, force-tier seam behavior). ADR-0002 (D-03) and ADR-0003 (D-04) are then written from fetched artifacts only.

**Tech Stack:** PowerShell 7 (capture script, guest), Rust 2021 (spike crate, `mxc-sdk` 1.0.0 pinned-tree path dep), Hyper-V disposable-VM harness (`Invoke-TestsInVM.ps1 -TestCmd`), upstream MXC pin `5d7a475a9fd5626bafb55c2c857989d2e5621245`.

**Spec:** `docs/superpowers/specs/2026-10-14-wbd-d03-d04-stop-work-gates-design.md` (approved, spec-reviewer approved, advisories folded in, commits `9ce9364` + `da26bca`).

**PR boundary (binding, per the spec's thread decision):** Tasks 1–9 are **PR1 (D-03)**: spike script + spike crate + canonical run + ADR-0002 + companion updates, one commit batch. Tasks 10 is **PR2 (D-04)**: ADR-0003 + companion updates, consuming ADR-0002's outcome and the same canonical run. PR1 must be complete (and mergeable on its own) before PR2 starts.

**Amendment 1 (2026-10-17, user-approved after canonical run `20261017-121539-354` + the Task 8 source-verification pack):** run 1 proved that `pwsh` workloads cannot resolve under the PSEC token (Program Files-resident + root-drive readonly requirement, `launch_diagnostics.rs:243-250`), that the drive-root `C:\` CWD fallback (`working_directory.rs:41`) breaks cmd's external commands ("The current directory is invalid."), and that top-level `filesystem.enumeratePaths` is schema-rejected (`stable.rs:58-69`) rather than adjudication-refused — leaving the timeout/cancel/stdin axes unproven and C1 refusing one layer early. This amendment (a) swaps sleep workloads to the upstream-proven System32-resident `powershell.exe Start-Sleep` pattern with a `readonlyPaths` `C:\Windows` grant, (b) emits `enumeratePaths` via `New-Config -EnumeratePaths` (the nested schema key), so one supplementary canonical run discharges those axes. Run 1 remains recorded evidence with all findings; the ADRs cite both runs.

---

## Resolved spec open items (upstream evidence, read at the pin 2026-10-14)

All refs are valid at commit `5d7a475a9fd5626bafb55c2c857989d2e5621245`.

1. **SDK public API (Section B surface).** `src/mxc-sdk/README.md`, `docs/api-reference/rust/v1/api.md`, `docs/api-reference/rust/v1/types.md`, `src/mxc-sdk/src/lib.rs`. The versioned API is `mxc_sdk::v1`:
   - `v1::probe(Option<&ContainerRequest>) -> Result<ProbeOutput, Error>` — **request-scoped probing is exposed in-process** (Windows-only). `ProbeOutput { tier: Option<&'static str>, needs_dacl_augmentation, warnings, probes: ProbeFacts, error }`; `ProbeFacts` carries the 11 host booleans + `ui_capabilities` (10 bits) — the same surface as `wxc-exec --probe`.
   - `v1::run(ContainerRequest, RunOptions) -> Result<ExecutionResult, Error>` — captured stdio; `ExecutionResult { outcome: WaitResult, warnings, stdout, stderr, output_metadata }`; `WaitResult::Exited(i32) | TimedOut`. README: "timeouts cancel outstanding reads and return the partial output with `WaitResult::TimedOut`".
   - `v1::spawn(ContainerRequest, SpawnOptions) -> Result<MxcProcess, Error>` — `MxcProcess::{take_stdin, take_stdout, take_stderr, try_wait, id, kill, kill_for_timeout, wait, wait_with_output, stdout_closer, stderr_closer}` (stdin writer + stdout/stderr readers + cancellation).
   - `ContainerRequest { command, timeout_ms: Option<u32>, filesystem, network, ui, containment, container_name, working_directory, environment, inherit_default_environment }` — `timeout_ms` is request-level (JSON: `process.timeout`, default 30000, per fetched `d02-config-fs-rw.json`).
   - `Containment::{Process (default), ProcessContainer(ProcessContainerConfig), …}` — typed backend selection; `ProcessContainerConfig { learning_mode, capabilities, capture_denials, ui, filesystem: Option<ProcessContainerFilesystem{enumerate_paths}>, network: Option<ProcessContainerNetwork{allowed_proxy_peer}> }`.
   - `v1::platform_support()`, `v1::available_backends() -> Vec<AvailableBackend { backend, tier, capabilities, warnings }>` — host-level discovery (advisory).
   - Errors: `Error { code: ErrorCode, message, operation, native_code, remediation }` (Display renders operation/native).
   - Both `run` and `spawn` "use the same in-process native engine; **neither launches an MXC executor binary**" (README).
2. **No effective-tier query-back on a live process.** The documented `MxcProcess` surface exposes warnings/metadata/id/stdio/wait/kill — **no per-process effective-tier accessor**; `available_backends()` is host-level; `v1::probe` re-runs request adjudication (not live state). This gap feeds ADR-0003's attestation design (and possibly an upstream requirement).
3. **Force-tier mechanism (C3).** `src/mxc-sdk/src/backends/process_container/common/fallback_detector.rs`, `choose_backend_tier` doc + `forced_decision`, and `common/test_env.rs`: the seam is the **`MXC_FORCE_TIER` env var**, gated `#[cfg(any(test, feature = "force-tier-testing"))]` — "Normal debug and release builds do not compile this branch. Unit tests always get it; a runnable test executor gets it only through the explicit `force-tier-testing` Cargo feature." Canonical tier strings (generated from one macro): `base-container`, `appcontainer-bfs`, `appcontainer-dacl`. An invalid value is silently ignored (falls through to the real probe chain). `forced_decision` still honors the `DaclFallbackDisabled` guard. Companion test seams: `MXC_FORCE_BC_USABLE`, `MXC_FORCE_NATIVE_CAPTURE_USABLE` (`cfg(test)` only). **The shipped release `wxc-exec.exe` (default features) is therefore immune to env-driven tier downgrade** — the runtime immunity check in Section C (c2) proves it.
4. **C2 demotion finding.** `choose_backend_tier`: `enumeratePaths` and bare `hostLoopback: allow` requests **hard-error** (`FallbackError::EnumeratePathsUnsupported` / `IngressUnsupported`) when BaseContainer cannot service them — they never demote. The only real demotion paths to `appcontainer-dacl` on this host: BaseContainer API unusable (not the case — D-01 `baseContainerApiPresent: true`) or native-deny absent (not the case — `FileSystemDeny` advertised). **Conclusion feeding ADR-0003:** on image B, no policy shape demotes; unsupported forms fail closed; the weaker tier is nonetheless compiled into every build and reachable on hosts without BaseContainer — the product preflight must refuse by tier value, not by demotion absence. `DegradationReason`/`EnforcementDegraded` audit (bounded reason codes) exists for the diagnostics axis.
5. **wxc-exec subprocess surface (Section A).** `src/tools/wxc` — a "thin process entry point that depends on `mxc-sdk`" (crate README "Internal modules and executor binaries"). Documented CLI: `--probe`, `--version`, `--debug`, `--audit`; run mode is the config path positional (`wxc-exec.exe config.json`; README `--debug` example). Upstream classifies it as "non-SDK consumption … Use for testing or when the SDK cannot be embedded in your app".
6. **FFI surface.** `src/mxc-sdk/src/lib.rs` exposes `#[doc(hidden)] pub mod __ffi` — `spawn_container_json`, `run_json`, `spawn_with_pty_json`, `run_lifecycle_json`, `execute_lifecycle_json` ("Internal adapters for the C ABI and native contract tests, **not SDK authoring APIs**"); the `src/ffi` directory builds on it (exact exports read at Task 8). `experimental` backends are an API parameter, deliberately never a JSON field.
7. **C4 (created-not-running / pre-resume).** Deliberately NOT resolved at planning time: `base_container_runner.rs` (145 KB) gets a targeted read at Task 8 (CREATE_SUSPENDED / ResumeThread / PSEC environment attach order). The spike does not depend on the answer; if no surface exposes it, ADR-0002 §3 records the blocker and both ADRs restate the binding stop-work consequence (no product launch path until an upstream mechanism exists).
8. **Config JSON shape at schema 1.0.0** (fetched `d02-config-fs-rw.json`): `{ version, containerId, containment: "processcontainer", process: { commandLine, timeout }, filesystem: { readwritePaths, … }, ui: { disable } }` — the C1 `enumeratePaths` key goes under the NESTED path `processContainer.filesystem.enumeratePaths` — verified at the pin: top-level `Filesystem` is `deny_unknown_fields` with only readwrite/readonly/denied (`stable.rs:58-69`), the nested `ProcessContainerFilesystem` carries `enumeratePaths` (`stable.rs:310-315`), and upstream `New-Config` exposes `-EnumeratePaths` emitting exactly that nested key (`WinProcessContainer.Common.ps1:572`, emitted `:666-668`). Run 1's top-level key was schema-rejected (recorded); the amended script uses `-EnumeratePaths` so the refusal surfaces the adjudication-level `EnumeratePathsUnsupported` (`fallback_detector.rs:238-241`, raised `:301`).

**Workload command choice note (Amendment 1, 2026-10-17):** sleep workloads use System32-resident `powershell.exe -NoLogo -NoProfile -Command "Start-Sleep -Seconds <n>"` plus a `readonlyPaths` grant of `C:\Windows` — the upstream-proven ProcessContainer sleeper pattern (`tests/scripts/run_processcontainer_crash_recovery_test.ps1:47`; `run_processcontainer_process_plumbing_test.ps1:106-116`). Do NOT use `pwsh` (Program Files-resident; requires root-drive readonly, `launch_diagnostics.rs:243-250` `missing_root_readonly` — proven failing in run 1) and do NOT use `ping -n` (dies instantly inside the container: "Unable to contact IP driver", upstream plumbing-test comment :106). `timeout /t` rejects redirected stdin. No network dependence in any scenario.

---

### Task 1: Local mock (write first — TDD)

**Files:**
- Create: `C:\Users\marku\AppData\Local\Temp\opencode\wbd-mock-d03\run-mock.ps1` (scratch; not committed)

The mock drives the REAL capture script in a child pwsh against fake MXC repos. The fake `wxc-exec.exe` is a real small exe compiled once with the .NET Framework csc (always present at `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe`): `--probe`/`--version` → text + exit 0; a config-path positional → reads the JSON, prints `MOCK-STDOUT <containerId>`, and exits 7 if the commandLine contains `exit 7`, else 0. The fake mxc tree additionally carries a **stub `mxc-sdk` crate** so Section B compiles and all eight SDK scenarios run in the mock (validating the full plumbing: template materialization → cargo build → scenario JSON parsing).

- [x] **Step 1: Write the mock**

```powershell
#requires -Version 7
# Mock for wbd-d03-d04-spike.ps1 (WBD D-03/D-04 spike capture).
# Child pwsh console output (Write-Host) flows to the caller's stdout -
# swallow it so only $LASTEXITCODE and the assertions matter.
$ErrorActionPreference = 'Stop'
$mockRoot = Join-Path $env:TEMP ("opencode\wbd-mock-d03-" + (Get-Date -Format 'HHmmss'))
New-Item -ItemType Directory -Path $mockRoot -Force | Out-Null
$csc = Join-Path $env:SystemRoot 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
$spikeDir = 'C:\Users\marku\tools\sandbox\tests\vm\spikes\wbd-d03-sdk-spike'

function New-FakeMxcRepo {
    param([string]$Path, [switch]$WithCommonPs1, [switch]$WithSdkStub)
    New-Item -ItemType Directory -Path (Join-Path $Path 'src\target\release') -Force | Out-Null
    git init --quiet $Path 2>$null
    git -C $Path -c user.name=mock -c user.email=mock@example.com commit --allow-empty --quiet -m init
    # --- fake wxc-exec.exe (compiled once per repo; csc is always present) ---
    $cs = Join-Path $Path 'fake-wxc-exec.cs'
    @'
using System;
using System.IO;
using System.Text.RegularExpressions;
class FakeWxcExec {
    static int Main(string[] args) {
        if (args.Length == 0) { Console.Error.WriteLine("usage"); return 2; }
        if (args[0] == "--probe" || args[0] == "--version") {
            Console.WriteLine("MOCK-" + args[0] + " output");
            return 0;
        }
        if (!File.Exists(args[0])) { Console.Error.WriteLine("no config"); return 2; }
        string json = File.ReadAllText(args[0]);
        Match m = Regex.Match(json, "\"containerId\"\\s*:\\s*\"([^\"]+)\"");
        string id = m.Success ? m.Groups[1].Value : "unknown";
        Console.WriteLine("MOCK-STDOUT " + id);
        Console.Error.WriteLine("MOCK-STDERR " + id);
        return json.Contains("exit 7") ? 7 : 0;
    }
}
'@ | Set-Content -LiteralPath $cs -Encoding utf8
    $exeOut = Join-Path $Path 'src\target\release\wxc-exec.exe'
    & $csc /nologo "/out:$exeOut" $cs
    if ($LASTEXITCODE -ne 0) { throw "csc failed building fake wxc-exec" }
    if ($WithCommonPs1) {
        $libDir = Join-Path $Path 'tests\scripts\lib'
        New-Item -ItemType Directory -Path $libDir -Force | Out-Null
        @'
$Script:SchemaVersion = '1.0.0'
function New-Config {
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$CommandLine,
          [string[]]$ReadWrite = @(), [string[]]$ReadOnly = @(), [string[]]$Denied = @(),
          [string[]]$EnumeratePaths = @(), [string]$Cwd = $null)
    $dir = Join-Path $ScratchRoot 'configs'
    $path = Join-Path $dir "$Name.json"
    $cfg = @{ version = '1.0.0'; containerId = "MxcWinPC-$Name"; containment = 'processcontainer';
        process = @{ commandLine = $CommandLine; timeout = 30000 };
       filesystem = @{ readwritePaths = $ReadWrite; readonlyPaths = $ReadOnly; deniedPaths = $Denied };
       ui = @{ disable = $false } }
    if ($EnumeratePaths.Count) { $cfg.processContainer = @{ filesystem = @{ enumeratePaths = $EnumeratePaths } } }
    $cfg | ConvertTo-Json -Depth 5 | Out-File -LiteralPath $path -Encoding utf8 -Force
    return $path
}
'@ | Set-Content -LiteralPath (Join-Path $libDir 'WinProcessContainer.Common.ps1') -Encoding utf8
    }
    if ($WithSdkStub) {
        $sdkDir = Join-Path $Path 'src\mxc-sdk\src'
        New-Item -ItemType Directory -Path $sdkDir -Force | Out-Null
        @'
[package]
name = "mxc-sdk"
version = "1.0.0"
edition = "2021"

[features]
force-tier-testing = []

[dependencies]
'@ | Set-Content -LiteralPath (Join-Path $Path 'src\mxc-sdk\Cargo.toml') -Encoding utf8
        @'
// Stub of the documented mxc_sdk::v1 surface (docs/api-reference/rust/v1).
// Mirrors EVERY item src/main.rs touches (configs module layout, all 11
// ProbeFacts booleans + 10 ui bits, Default for ProcessContainerConfig and
// ProcessContainerFilesystem (both #[non_exhaustive] at the pin),
// MxcProcess::{wait, warnings, ...}) so the committed spike compiles in the
// mock; the real crate is exercised in the VM run.
pub mod v1 {
    pub mod configs {
        #[derive(Default)]
        pub struct ProcessContainerConfig {
            pub filesystem: Option<ProcessContainerFilesystem>,
        }
        #[derive(Default)]
        pub struct ProcessContainerFilesystem {
            pub enumerate_paths: Vec<String>,
        }
    }
    pub struct UiCapabilitySupport {
        pub can_block_clipboard_read: bool, pub can_block_clipboard_write: bool,
        pub can_block_input_injection: bool, pub can_block_input_method_changes: bool,
        pub can_block_external_ui_objects: bool, pub can_block_global_ui_namespace: bool,
        pub can_block_desktop_switching: bool, pub can_block_logoff_or_shutdown: bool,
        pub can_block_system_parameter_changes: bool, pub can_block_display_settings_changes: bool,
    }
    pub struct ProbeFacts {
        pub base_container_api_present: bool, pub native_capture_available: bool,
        pub guarded_capture_available: bool, pub bfscfg_present: bool,
        pub bfs_compiled_in: bool, pub base_container_supports_deny_paths: bool,
        pub base_container_supports_enumerate_paths: bool,
        pub base_container_supports_ingress_host_loopback_allow: bool,
        pub base_container_supports_identityless_loopback_proxy: bool,
        pub isolation_session_available: bool, pub hyperlight_available: bool,
        pub ui_capabilities: UiCapabilitySupport,
    }
    pub struct ProbeOutput {
        pub tier: Option<&'static str>, pub needs_dacl_augmentation: Option<bool>,
        pub warnings: Vec<String>, pub probes: ProbeFacts, pub error: Option<String>,
    }
    #[derive(Default)]
    pub struct FilesystemPolicy { pub readwrite_paths: Vec<String>, pub readonly_paths: Vec<String>, pub denied_paths: Vec<String> }
    pub enum Containment { Process, ProcessContainer(configs::ProcessContainerConfig) }
    pub struct ContainerRequest {
        pub command: String, pub timeout_ms: Option<u32>,
        pub filesystem: Option<FilesystemPolicy>, pub containment: Containment,
    }
    impl ContainerRequest { pub fn new(command: impl Into<String>) -> Self {
        Self { command: command.into(), timeout_ms: None, filesystem: None, containment: Containment::Process }
    } }
    pub enum WaitResult { Exited(i32), TimedOut }
    pub struct ExecutionResult { pub outcome: WaitResult, pub warnings: Vec<String>, pub stdout: Vec<u8>, pub stderr: Vec<u8> }
    pub struct MxcProcess;
    impl MxcProcess {
        pub fn id(&self) -> u32 { 4242 }
        pub fn try_wait(&mut self) -> std::io::Result<Option<i32>> { Ok(Some(0)) }
        pub fn kill(&mut self) -> std::io::Result<()> { Ok(()) }
        pub fn warnings(&self) -> Vec<String> { Vec::new() }
        pub fn wait(&mut self) -> Result<WaitResult, Error> { Ok(WaitResult::Exited(0)) }
        pub fn take_stdin(&mut self) -> Option<Box<dyn std::io::Write + Send>> {
            Some(Box::new(std::io::sink()))
        }
        pub fn wait_with_output(self) -> std::io::Result<ExecutionResult> {
            Ok(ExecutionResult { outcome: WaitResult::Exited(0), warnings: vec![],
                 stdout: b"MOCK-STDOUT-SPIKE".to_vec(), stderr: Vec::new() })
        }
    }
    #[derive(Debug)]
    pub struct Error { pub message: String }
    impl std::fmt::Display for Error {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str(&self.message) }
    }
    pub struct AvailableBackend { pub backend: String, pub tier: Option<String>, pub warnings: Vec<String> }
    fn stub_probe_facts() -> ProbeFacts {
        ProbeFacts {
            base_container_api_present: true, native_capture_available: true,
            guarded_capture_available: true, bfscfg_present: true,
            bfs_compiled_in: true, base_container_supports_deny_paths: true,
            base_container_supports_enumerate_paths: true,
            base_container_supports_ingress_host_loopback_allow: true,
            base_container_supports_identityless_loopback_proxy: true,
            isolation_session_available: true, hyperlight_available: true,
            ui_capabilities: UiCapabilitySupport {
                can_block_clipboard_read: true, can_block_clipboard_write: true,
                can_block_input_injection: true, can_block_input_method_changes: true,
                can_block_external_ui_objects: true, can_block_global_ui_namespace: true,
                can_block_desktop_switching: true, can_block_logoff_or_shutdown: true,
                can_block_system_parameter_changes: true, can_block_display_settings_changes: true,
            },
        }
    }
    pub fn probe(_request: Option<&ContainerRequest>) -> Result<ProbeOutput, Error> {
        Ok(ProbeOutput { tier: Some("stub-base-container"), needs_dacl_augmentation: Some(false),
            warnings: Vec::new(), probes: stub_probe_facts(), error: None })
    }
    pub fn run(request: ContainerRequest, _o: ()) -> Result<ExecutionResult, Error> {
        let code = if request.command.contains("exit 7") { 7 } else { 0 };
        Ok(ExecutionResult { outcome: WaitResult::Exited(code), warnings: Vec::new(),
             stdout: format!("MOCK-RUN {}", request.command).into_bytes(), stderr: Vec::new() })
    }
    pub fn spawn(request: ContainerRequest, _o: ()) -> Result<MxcProcess, Error> {
        let _ = request; Ok(MxcProcess)
    }
    pub fn available_backends() -> Vec<AvailableBackend> {
        vec![AvailableBackend { backend: "processcontainer".into(), tier: Some("stub-base-container".into()), warnings: vec![] }]
    }
}
'@ | Set-Content -LiteralPath (Join-Path $sdkDir 'lib.rs') -Encoding utf8
    }
}

function Invoke-Capture {
    param([string]$MxcRoot, [string]$ResultsDir)
    $null = & pwsh -NoProfile -ExecutionPolicy Bypass -File `
        "C:\Users\marku\tools\sandbox\tests\vm\wbd-d03-d04-spike.ps1" `
        -MxcRoot $MxcRoot -ResultsDir $ResultsDir -SpikeDir $spikeDir 2>&1
    return $LASTEXITCODE
}

$sdkScenarios = 'probe','run-exit','run-stdio','spawn-stdin','timeout','cancel','force-tier','tier-query'
$wxcScenarios = 'a1-exit0','a1-exit7','a2-stdout','a2-stderr','a2-stdin','a3-timeout','a4-cancel'
$fail = @()

# ---- Scenario A: happy path (Common.ps1 + sdk stub) --------------------
$mxcA = Join-Path $mockRoot 'mxcA'
New-FakeMxcRepo -Path $mxcA -WithCommonPs1 -WithSdkStub
$resA = Join-Path $mockRoot 'resultsA'
$exitA = Invoke-Capture -MxcRoot $mxcA -ResultsDir $resA
if ($exitA -ne 0) { $fail += "A: expected exit 0, got $exitA" }
$summary = Get-Content -Raw (Join-Path $resA 'd03d04-spike.json') | ConvertFrom-Json
if (-not $summary.ran) { $fail += 'A: summary ran=false' }
if ($summary.wxc.ran -ne $true) { $fail += 'A: wxc section ran != true' }
if ($summary.sdk.ran -ne $true) { $fail += 'A: sdk section ran != true (stub build expected to succeed)' }
if ($summary.c.ran -ne $true) { $fail += 'A: c section ran != true' }
if (@($summary.wxc.rows).Count -ne 7) { $fail += "A: expected 7 wxc rows, got $(@($summary.wxc.rows).Count)" }
if (@($summary.sdk.rows).Count -ne 8) { $fail += "A: expected 8 sdk rows, got $(@($summary.sdk.rows).Count)" }
# uniform row schema + real exit values: proves the guarded calls actually
# bound their arguments (a lost -ArgumentList shows up as exit -1 rows)
$wxcByName = @{}
foreach ($row in @($summary.wxc.rows)) { $wxcByName[$row.scenario] = $row }
foreach ($row in @($summary.wxc.rows)) {
    foreach ($k in 'scenario','error','configArtifact','exit','elapsedMs') {
        if (-not ($row.PSObject.Properties.Name -contains $k)) { $fail += "A: wxc row $($row.scenario) missing key $k" }
    }
}
if ($wxcByName['a1-exit0'].exit -ne 0) { $fail += "A: a1-exit0 expected exit 0, got $($wxcByName['a1-exit0'].exit)" }
if ($wxcByName['a1-exit7'].exit -ne 7) { $fail += "A: a1-exit7 expected exit 7 (fake executor maps 'exit 7'), got $($wxcByName['a1-exit7'].exit)" }
foreach ($s in 'a2-stdout','a2-stderr','a2-stdin','a3-timeout') {
    if ($wxcByName[$s].exit -ne 0) { $fail += "A: $s expected exit 0, got $($wxcByName[$s].exit)" }
}
if ($wxcByName['a4-cancel'].executorKilled -ne $true) { $fail += "A: a4-cancel executorKilled != true" }
foreach ($row in @($summary.sdk.rows)) {
    if ($row.exit -ne 0) { $fail += "A: sdk $($row.scenario) expected exit 0, got $($row.exit)" }
}
foreach ($s in $wxcScenarios) {
    if (-not (Test-Path (Join-Path $resA "d03-wxc-$s.json"))) { $fail += "A: missing d03-wxc-$s.json" }
}
foreach ($s in $sdkScenarios) {
    if (-not (Test-Path (Join-Path $resA "d03-sdk-$s.json"))) { $fail += "A: missing d03-sdk-$s.json" }
}
if (-not (Test-Path (Join-Path $resA 'd03-c1-launch.json'))) { $fail += 'A: missing d03-c1-launch.json' }
if (-not (Test-Path (Join-Path $resA 'd03-c2-env-immunity.json'))) { $fail += 'A: missing d03-c2-env-immunity.json' }
$baseA = Get-Content -Raw (Join-Path $resA 'd03d04-baseline.json') | ConvertFrom-Json
if (-not $baseA.d03d04Spike -or -not $baseA.d03d04Spike.ran) { $fail += 'A: baseline missing d03d04Spike block' }
if (-not (Test-Path (Join-Path $resA 'capture-manifest.json'))) { $fail += 'A: missing capture-manifest.json' }

# ---- Scenario B: no mxc checkout -> exit 3 ------------------------------
$mockB = Join-Path $mockRoot 'mxcB'
New-Item -ItemType Directory -Path $mockB -Force | Out-Null
$resB = Join-Path $mockRoot 'resultsB'
$exitB = Invoke-Capture -MxcRoot $mockB -ResultsDir $resB
if ($exitB -ne 3) { $fail += "B: expected exit 3 (prerequisites), got $exitB" }

# ---- Scenario C: sdk crate missing -> build blocker, run completes -----
$mxcC = Join-Path $mockRoot 'mxcC'
New-FakeMxcRepo -Path $mxcC -WithCommonPs1
$resC = Join-Path $mockRoot 'resultsC'
$exitC = Invoke-Capture -MxcRoot $mxcC -ResultsDir $resC
if ($exitC -ne 0) { $fail += "C: expected exit 0 (blocker is evidence), got $exitC" }
$summaryC = Get-Content -Raw (Join-Path $resC 'd03d04-spike.json') | ConvertFrom-Json
if ($summaryC.sdk.ran -or -not $summaryC.sdk.blocker) { $fail += 'C: expected sdk.ran=false with blocker text' }
if (-not $summaryC.wxc.ran) { $fail += 'C: wxc section must still run' }
if (-not $summaryC.c.ran) { $fail += 'C: c section must still run' }

if ($fail.Count) {
    Write-Host "MOCK FAILED ($($fail.Count)):" -ForegroundColor Red
    $fail | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
    exit 1
}
Write-Host "MOCK PASSED (d03d04 scenarios A+B+C; mock root: $mockRoot)" -ForegroundColor Green
exit 0
```

- [x] **Step 2: Run the mock — expect FAIL**

Run: `pwsh -NoProfile -ExecutionPolicy Bypass -File "C:\Users\marku\AppData\Local\Temp\opencode\wbd-mock-d03\run-mock.ps1"`
Expected: `MOCK FAILED` — scenario A fails because `wbd-d03-d04-spike.ps1` does not exist yet (child pwsh exits 61/2; B fails the exit-3 assertion trivially since a missing script also yields a nonzero code — that's fine, it proves the mock exercises new behavior; the meaningful red is A).

---

### Task 2: The committed spike crate

**Files:**
- Create: `tests/vm/spikes/wbd-d03-sdk-spike/Cargo.toml.template`
- Create: `tests/vm/spikes/wbd-d03-sdk-spike/.gitignore`
- Create: `tests/vm/spikes/wbd-d03-sdk-spike/src/main.rs`

- [x] **Step 1: `Cargo.toml.template`** — the capture script materializes `Cargo.toml` from this template by replacing `__MXC_ROOT__` with the `-MxcRoot` value (the materialized file is gitignored and copied into the artifact set for provenance):

```toml
[package]
name = "wbd-d03-sdk-spike"
version = "0.1.0"
edition = "2021"
publish = false

[workspace]

[dependencies]
mxc-sdk = { path = "__MXC_ROOT__/src/mxc-sdk", features = ["force-tier-testing"] }
serde_json = "1"
```

Notes: the empty `[workspace]` table keeps the crate standalone even though it lives inside the monorepo (prevents cargo workspace-member errors). `force-tier-testing` is enabled deliberately — it is a no-dependency cfg gate that compiles the `MXC_FORCE_TIER` seam into a runnable binary (the exact D-03/D-04 behavior under investigation; the shipped executor leaves it off).

- [x] **Step 2: `.gitignore`**:

```
/target
Cargo.toml
Cargo.lock
```

- [x] **Step 3: `src/main.rs`** — one JSON line per scenario on stdout; spoke-level failures are serialized as JSON, never panics (the capture script records exit codes and output verbatim):

```rust
// WBD D-03/D-04 spike: exercises the documented mxc_sdk::v1 surface
// in-process against the pinned tree. Documented surface only - every API
// used here is in docs/api-reference/rust/v1 at pin 5d7a475a; anything not
// exposed is a recorded blocker downstream, never invented here.

use mxc_sdk::v1::{self, configs, ContainerRequest, Containment, WaitResult};
use serde_json::{json, Value};
use std::io::Write;

fn emit(value: Value) {
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{value}");
}

fn fmt_err(e: v1::Error) -> String {
    format!("{e}")
}

fn empty_request() -> ContainerRequest {
    ContainerRequest::new("cmd /d /s /c exit 0")
}

fn granted_request(command: &str, timeout_ms: Option<u32>) -> ContainerRequest {
    // Run-1 finding (20261017-121539-354): without a granted existing directory
    // the engine falls back to a traverse-only C:\ CWD (working_directory.rs:41)
    // and System32-resident external commands fail ("The current directory is
    // invalid."). A readonly SystemRoot grant gives the child a usable CWD
    // (models.rs:1124-1145 first-existing-directory rule).
    let mut fs = v1::FilesystemPolicy::default();
    fs.readonly_paths = vec!["C:\\Windows".into()];
    ContainerRequest {
        filesystem: Some(fs),
        timeout_ms,
        ..ContainerRequest::new(command)
    }
}

fn enumerate_request() -> ContainerRequest {
    let temp = std::env::temp_dir().join("wbd-d03-enumerate-probe");
    // ProcessContainerConfig/ProcessContainerFilesystem are #[non_exhaustive]
    // at the pin: Default + pub-field mutation is the sanctioned out-of-crate
    // construction (struct expressions are E0639 from outside the crate).
    let mut fs = configs::ProcessContainerFilesystem::default();
    fs.enumerate_paths = vec![temp.to_string_lossy().into_owned()];
    let mut cfg = configs::ProcessContainerConfig::default();
    cfg.filesystem = Some(fs);
    ContainerRequest {
        containment: Containment::ProcessContainer(cfg),
        ..empty_request()
    }
}

fn probe_json(out: &v1::ProbeOutput) -> Value {
    let p = &out.probes;
    let ui = &p.ui_capabilities;
    json!({
        "tier": out.tier,
        "needsDaclAugmentation": out.needs_dacl_augmentation,
        "warnings": out.warnings,
        "error": out.error,
        "probes": {
            "baseContainerApiPresent": p.base_container_api_present,
            "nativeCaptureAvailable": p.native_capture_available,
            "guardedCaptureAvailable": p.guarded_capture_available,
            "bfscfgPresent": p.bfscfg_present,
            "bfsCompiledIn": p.bfs_compiled_in,
            "baseContainerSupportsDenyPaths": p.base_container_supports_deny_paths,
            "baseContainerSupportsEnumeratePaths": p.base_container_supports_enumerate_paths,
            "baseContainerSupportsIngressHostLoopbackAllow": p.base_container_supports_ingress_host_loopback_allow,
            "baseContainerSupportsIdentitylessLoopbackProxy": p.base_container_supports_identityless_loopback_proxy,
            "isolationSessionAvailable": p.isolation_session_available,
            "hyperlightAvailable": p.hyperlight_available,
            "uiCapabilities": {
                "canBlockClipboardRead": ui.can_block_clipboard_read,
                "canBlockClipboardWrite": ui.can_block_clipboard_write,
                "canBlockInputInjection": ui.can_block_input_injection,
                "canBlockInputMethodChanges": ui.can_block_input_method_changes,
                "canBlockExternalUiObjects": ui.can_block_external_ui_objects,
                "canBlockGlobalUiNamespace": ui.can_block_global_ui_namespace,
                "canBlockDesktopSwitching": ui.can_block_desktop_switching,
                "canBlockLogoffOrShutdown": ui.can_block_logoff_or_shutdown,
                "canBlockSystemParameterChanges": ui.can_block_system_parameter_changes,
                "canBlockDisplaySettingsChanges": ui.can_block_display_settings_changes,
            },
        },
    })
}

fn scenario_probe() -> Result<Value, String> {
    let host = v1::probe(None).map_err(fmt_err)?;
    let empty = v1::probe(Some(&empty_request())).map_err(fmt_err)?;
    let enumerate = v1::probe(Some(&enumerate_request())).map_err(fmt_err)?;
    Ok(json!({
        "host": probe_json(&host),
        "empty": probe_json(&empty),
        "enumerate": probe_json(&enumerate),
    }))
}

fn run_request(request: ContainerRequest) -> Result<Value, String> {
    let started = std::time::Instant::now();
    let command = request.command.clone();
    let timeout_ms = request.timeout_ms;
    let out = v1::run(request, Default::default()).map_err(fmt_err)?;
    Ok(json!({
        "command": command,
        "timeoutMs": timeout_ms,
        "elapsedMs": started.elapsed().as_millis() as u64,
        "outcome": match out.outcome { WaitResult::Exited(c) => json!({ "exit": c }), WaitResult::TimedOut => json!("TimedOut") },
        "stdout": String::from_utf8_lossy(&out.stdout),
        "stderr": String::from_utf8_lossy(&out.stderr),
        "warnings": out.warnings,
    }))
}

fn run_one(command: &str, timeout_ms: Option<u32>) -> Result<Value, String> {
    run_request(ContainerRequest {
        timeout_ms,
        ..ContainerRequest::new(command)
    })
}

fn scenario_run_exit() -> Result<Value, String> {
    Ok(json!({
        "exit0": run_one("cmd /d /s /c exit 0", None)?,
        "exit7": run_one("cmd /d /s /c exit 7", None)?,
    }))
}

fn scenario_run_stdio() -> Result<Value, String> {
    Ok(json!({
        "stdout": run_one("cmd /d /s /c echo SDK-STDOUT-MARKER", None)?,
        "stderr": run_one("cmd /d /s /c echo SDK-STDERR-MARKER 1>&2", None)?,
    }))
}

fn scenario_spawn_stdin() -> Result<Value, String> {
    let mut proc = v1::spawn(
        granted_request("cmd /d /s /c find /v \"\"", None),
        Default::default(),
    )
    .map_err(fmt_err)?;
    // take_stdin has take semantics - take ONCE, write through the handle,
    // then drop it before wait_with_output consumes the process.
    let mut stdin = proc.take_stdin();
    let stdin_taken = stdin.is_some();
    if let Some(w) = stdin.as_mut() {
        let _ = w.write_all(b"HELLO-STDIN\r\n");
    }
    drop(stdin);
    let result = proc.wait_with_output().map_err(|e| e.to_string())?;
    let stdout = String::from_utf8_lossy(&result.stdout).into_owned();
    Ok(json!({
        "stdinTaken": stdin_taken,
        "stdout": stdout,
        "roundTrip": stdout.contains("HELLO-STDIN"),
        "outcome": match result.outcome { WaitResult::Exited(c) => json!({ "exit": c }), WaitResult::TimedOut => json!("TimedOut") },
    }))
}

fn scenario_timeout() -> Result<Value, String> {
    // Amendment 1: System32-resident powershell.exe sleeper (upstream-proven
    // ProcessContainer pattern, run_processcontainer_crash_recovery_test.ps1:47)
    // with a readonly SystemRoot grant; pwsh failed to resolve in run 1.
    let out = run_request(granted_request(
        "powershell.exe -NoLogo -NoProfile -Command Start-Sleep -Seconds 60",
        Some(3_000),
    ))?;
    Ok(json!({
        "timeout": out,
        "note": "WaitResult::TimedOut expected; README: timeouts cancel outstanding reads and return partial output",
    }))
}

fn scenario_cancel() -> Result<Value, String> {
    let started = std::time::Instant::now();
    let mut proc = v1::spawn(
        granted_request(
            "powershell.exe -NoLogo -NoProfile -Command Start-Sleep -Seconds 120; 'WBD-D03-A4-MARKER'",
            None,
        ),
        Default::default(),
    )
    .map_err(fmt_err)?;
    let id = proc.id();
    let before_kill = json!({ "tryWait": match proc.try_wait() { Ok(v) => json!(v), Err(e) => json!(format!("{e}")) } });
    proc.kill().map_err(|e| e.to_string())?;
    let wait = proc.wait().map_err(|e| e.to_string())?;
    Ok(json!({
        "pid": id,
        "beforeKill": before_kill,
        "waitAfterKill": match wait { WaitResult::Exited(c) => json!({ "exit": c }), WaitResult::TimedOut => json!("TimedOut") },
        "elapsedMs": started.elapsed().as_millis() as u64,
    }))
}

fn scenario_force_tier() -> Result<Value, String> {
    let forced = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "appcontainer-dacl".to_string());
    // SAFETY: single-threaded scenario process; the var dies with this process.
    std::env::set_var("MXC_FORCE_TIER", &forced);
    let empty = v1::probe(Some(&empty_request())).map_err(fmt_err)?;
    let host = v1::probe(None).map_err(fmt_err)?;
    let tier_empty = empty.tier.map(|s| s.to_string());
    let tier_host = host.tier.map(|s| s.to_string());
    std::env::remove_var("MXC_FORCE_TIER");
    Ok(json!({
        "forcedValue": forced,
        "probeEmpty": probe_json(&empty),
        "probeNone": probe_json(&host),
        "honored": tier_empty.as_deref() == Some(forced.as_str()) || tier_host.as_deref() == Some(forced.as_str()),
        "note": "seam compiled via force-tier-testing feature; an invalid value is silently ignored (real probe chain)",
    }))
}

fn scenario_tier_query() -> Result<Value, String> {
    let backends: Vec<Value> = v1::available_backends()
        .into_iter()
        .map(|b| json!({ "backend": b.backend, "tier": b.tier, "warnings": b.warnings }))
        .collect();
    let mut proc = v1::spawn(
        ContainerRequest::new("cmd /d /s /c exit 3"),
        Default::default(),
    )
    .map_err(fmt_err)?;
    let warnings = proc.warnings();
    let id = proc.id();
    let wait = proc.wait().map_err(|e| e.to_string())?;
    let reprobe = v1::probe(Some(&empty_request())).map_err(fmt_err)?;
    Ok(json!({
        "availableBackends": backends,
        "processWarnings": warnings,
        "pid": id,
        "wait": match wait { WaitResult::Exited(c) => json!({ "exit": c }), WaitResult::TimedOut => json!("TimedOut") },
        "reProbe": probe_json(&reprobe),
        "note": "documented MxcProcess surface exposes warnings/metadata/id/stdio/wait/kill only - no per-process effective-tier accessor (ADR-0002 investigation item); re-probe re-runs request adjudication, not live state",
    }))
}

fn main() {
    let scenario = std::env::args().nth(1).unwrap_or_default();
    let result = match scenario.as_str() {
        "probe" => scenario_probe(),
        "run-exit" => scenario_run_exit(),
        "run-stdio" => scenario_run_stdio(),
        "spawn-stdin" => scenario_spawn_stdin(),
        "timeout" => scenario_timeout(),
        "cancel" => scenario_cancel(),
        "force-tier" => scenario_force_tier(),
        "tier-query" => scenario_tier_query(),
        other => Ok(json!({ "scenario": other, "error": "unknown scenario" })),
    };
    match result {
        Ok(value) => emit(json!({ "scenario": scenario, "ok": true, "result": value })),
        Err(e) => emit(json!({ "scenario": scenario, "ok": false, "error": e })),
    }
}
```

Note: `v1::Error` implements `Display`; `probe_json` maps `ProbeOutput` field-by-field because the documented types carry no serde derives we may rely on.

---

### Task 3: The capture script `tests/vm/wbd-d03-d04-spike.ps1`

**Files:**
- Create: `tests/vm/wbd-d03-d04-spike.ps1`

Established patterns reused from `wbd-d01-d02-probes.ps1`: exit codes 0/3/99, prerequisites fail-loud, flat artifacts only (the harness fetch is flat), `Set-Content -Value` never the pipeline, per-step try/catch with blocker-verbatim continuation, `Start-Job` + `Wait-Job -Timeout` hang guard on **every** launch scenario (spec advisory 3; the single documented exception is a4-cancel — it must Stop-Process the executor from the parent and uses only bounded waits — and the Section B cargo build is guarded at 1800s because force-tier-testing changes mxc-sdk's feature fingerprint → full rebuild), pin re-verification, manifest with SHA256. **This script launches workloads — inside the disposable VM only, never on the host, and it never runs `wxc-host-prep`.**

- [x] **Step 1: Write the script**:

```powershell
#Requires -Version 7
<#
.SYNOPSIS
  WBD D-03 + D-04 spike capture inside a disposable VM.
.DESCRIPTION
  Runs INSIDE the image-B VM via the harness' -TestCmd lane
  (Invoke-TestsInVM.ps1 -Image sbx-base-b -TestCmd "pwsh -NoProfile
  -File C:\sbx-repo\tests\vm\wbd-d03-d04-spike.ps1"). Writes every
  evidence artifact into C:\sbx-results (flat - the harness fetches
  top-level files only) and exits. UNLIKE wbd-d01-d02-probes.ps1 this
  lane LAUNCHES WORKLOADS (D-03's spike criterion); that is only safe
  inside the disposable VM. It never runs wxc-host-prep and mutates
  nothing outside the VM.

  Section A - wxc-exec.exe subprocess lifecycle: launch/exit codes
  (nonzero = workload outcome, not setup error), stdout/stderr/stdin,
  request-level timeout (process.timeout in schema 1.0.0), executor
  termination with process-tree survivor check.
  Section B - mxc-sdk in-process lifecycle: the committed spike crate
  tests\vm\spikes\wbd-d03-sdk-spike builds against the PINNED tree's
  src/mxc-sdk via a materialized path dependency (template with
  __MXC_ROOT__ placeholder; the materialized Cargo.toml is copied into
  the artifact set). force-tier-testing is deliberately enabled on the
  dependency to compile the MXC_FORCE_TIER seam for the D-04 evidence.
  Build failure = recorded blocker, run continues (Section A stands
  alone). cargo tries --offline first (warm cache from the tree build),
  then online.
  Section C - D-04 enforcement evidence: enumeratePaths request
  (adjudication-blocked per the D-02 matrix, section 5.2) probed AND
  launched with a marker-file canary proving the workload never
  executed; MXC_FORCE_TIER immunity of the shipped executor (the
  force-tier branch is cfg(any(test, feature=force-tier-testing)) -
  the default-feature release binary must ignore it).

  A failing scenario is EVIDENCE, not a capture error: outcomes are
  recorded verbatim in the artifacts and summary rows.

  Exit codes: 0 = capture complete (all sections attempted); 3 =
  prerequisites missing (no C:\mxc checkout / no wxc-exec.exe); 99 =
  unexpected error.
.PARAMETER MxcRoot
  MXC checkout location (default C:\mxc, per VM-01 Task 6).
.PARAMETER ResultsDir
  Artifact directory (default C:\sbx-results, the -TestCmd contract).
.PARAMETER SpikeDir
  The committed spike crate (default the repo copy inside the VM).
.EXAMPLE
  pwsh -NoProfile -ExecutionPolicy Bypass -File C:\sbx-repo\tests\vm\wbd-d03-d04-spike.ps1
#>
[CmdletBinding()]
param(
    [string]$MxcRoot = 'C:\mxc',
    [string]$ResultsDir = 'C:\sbx-results',
    [string]$SpikeDir = 'C:\sbx-repo\tests\vm\spikes\wbd-d03-sdk-spike'
)

$ErrorActionPreference = 'Stop'

# Helper: run a guest command under the hang guard; returns
# [pscustomobject]@{ text; exit } with strings joined INSIDE the job so
# only strings and the exit code cross deserialization
# (wbd-d01-d02-probes.ps1:378-405 pattern; Stop-Job has no -Force).
function Invoke-Guarded {
    param([scriptblock]$ScriptBlock, [object[]]$ArgumentList = @(), [int]$TimeoutSec = 120)
    $job = Start-Job -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList
    if (Wait-Job -Job $job -Timeout $TimeoutSec) {
        try {
            $r = Receive-Job -Job $job -ErrorAction Stop
            $result = if ($r) { $r } else { [pscustomobject]@{ text = ''; exit = -1 } }
        } catch {
            # a thrown child error becomes recorded evidence, not a lost scenario
            $result = [pscustomobject]@{ text = "job error: $($_.Exception.Message)"; exit = -1 }
        }
    } else {
        Stop-Job -Job $job
        $result = [pscustomobject]@{ text = "timed out after ${TimeoutSec}s (job killed)"; exit = -1 }
    }
    Remove-Job -Job $job -Force
    return $result
}

try {
    New-Item -ItemType Directory -Path $ResultsDir -Force | Out-Null
    $capturedAt = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ssK')

    # ---------------------------------------------------------------------
    # Prerequisites + baseline (self-identifying run; early write for
    # durability before any workload launch).
    # ---------------------------------------------------------------------
    if (-not (Test-Path -LiteralPath (Join-Path $MxcRoot '.git'))) {
        Write-Host "[wbd-spike] no MXC checkout at $MxcRoot - run tests\vm\prepare-mxc.ps1 first." -ForegroundColor Red
        exit 3
    }
    $wxcExec = Join-Path $MxcRoot 'src\target\release\wxc-exec.exe'
    if (-not (Test-Path -LiteralPath $wxcExec)) {
        Write-Host "[wbd-spike] no release wxc-exec.exe at $wxcExec - run tests\vm\prepare-mxc.ps1 first." -ForegroundColor Red
        exit 3
    }

    $os = Get-CimInstance Win32_OperatingSystem
    $pinnedCommit = '5d7a475a9fd5626bafb55c2c857989d2e5621245'
    Push-Location $MxcRoot
    $mxcCommit = (git rev-parse HEAD)
    $pinnedFull = (git rev-parse --verify "$pinnedCommit^{commit}" 2>$null)
    $mxcDirtyPaths = @(git status --porcelain)
    Pop-Location
    $wxcHash = (Get-FileHash -LiteralPath $wxcExec -Algorithm SHA256).Hash

    $baseline = [ordered]@{
        schema       = 1
        capturedAt   = $capturedAt
        ticket       = 'WBD-D-03+D-04'
        os           = [ordered]@{ caption = $os.Caption; version = $os.Version; buildNumber = $os.BuildNumber; architecture = $os.OSArchitecture }
        mxc          = [ordered]@{
            root = $MxcRoot; commit = $mxcCommit; pinnedCommit = $pinnedCommit
            pinMatches = ($pinnedFull -eq $mxcCommit); dirtyPaths = $mxcDirtyPaths.Count
            wxcExecSha256 = $wxcHash
        }
        notes        = @(
            'This lane LAUNCHES workloads inside the disposable VM (D-03 spike criterion).',
            'Section A artifacts: d03-config-<s>.json + d03-wxc-<s>.json; Section B: d03-sdk-<s>.json + d03-sdk-build.log + d03-sdk-cargo.toml; Section C: d03-c1-*.json + d03-c2-env-immunity.json; summary in d03d04-spike.json.',
            'wxc-host-prep was never run; nothing outside the VM was mutated.'
        )
    }
    $baselinePath = Join-Path $ResultsDir 'd03d04-baseline.json'
    Set-Content -LiteralPath $baselinePath -Value ($baseline | ConvertTo-Json -Depth 5) -Encoding utf8
    if ($pinnedFull -ne $mxcCommit) {
        Write-Host "[wbd-spike] WARNING: checked-out MXC commit $mxcCommit is NOT the recorded pin $pinnedCommit - evidence still captured; revisit the pin decision (docs/mxc-source-analysis.md)." -ForegroundColor Yellow
    }

    # ---------------------------------------------------------------------
    # Section A - wxc-exec.exe subprocess lifecycle. Configs come from the
    # upstream New-Config helper (schema-exact by construction); each is
    # copied to a flat artifact. The probe element of D-03's spike list
    # rides on the D-02 canonical-run artifacts for this surface.
    # ---------------------------------------------------------------------
    $wxcCommon = Join-Path $MxcRoot 'tests\scripts\lib\WinProcessContainer.Common.ps1'
    $wxcRan = $false; $wxcBlocker = $null; $wxcRows = @()
    if (-not (Test-Path -LiteralPath $wxcCommon)) {
        $wxcBlocker = "upstream Common.ps1 missing at $wxcCommon - New-Config generator unavailable (Section A blocker)."
    } else {
        try {
            . $wxcCommon
            $ScratchRoot = Join-Path $env:TEMP 'mxc-sbx-d03-spike'
            New-Item -ItemType Directory -Path (Join-Path $ScratchRoot 'configs') -Force | Out-Null
            $markerDir = Join-Path $ScratchRoot 'markers'
            New-Item -ItemType Directory -Path $markerDir -Force | Out-Null

            function Invoke-WxcScenario {
                param([string]$Name, [string]$CommandLine)
                $row = [ordered]@{ scenario = $Name; error = $null; configArtifact = $null; exit = $null; elapsedMs = $null }
                try {
                    $configPath = New-Config -Name "d03-$Name" -CommandLine $CommandLine
                    $row['configArtifact'] = "d03-config-$Name.json"
                    Copy-Item -LiteralPath $configPath -Destination (Join-Path $script:ResultsDir "d03-config-$Name.json") -Force
                    $sw = [System.Diagnostics.Stopwatch]::StartNew()
                    $r = Invoke-Guarded -TimeoutSec 120 -ArgumentList @($wxcExec, $configPath) -ScriptBlock {
                        param($Exe, $Cfg)
                        $out = & $Exe $Cfg 2>&1
                        [pscustomobject]@{ text = (@($out) | ForEach-Object { [string]$_ }) -join [Environment]::NewLine; exit = $LASTEXITCODE }
                    }
                    $sw.Stop()
                    $row['exit'] = $r.exit
                    $row['elapsedMs'] = $sw.ElapsedMilliseconds
                    Set-Content -LiteralPath (Join-Path $script:ResultsDir "d03-wxc-$Name.json") -Value ([string]$r.text) -Encoding utf8
                } catch {
                    $row['error'] = "$($_.Exception.Message)"
                }
                $row
            }

            $wxcRows = @()
            $wxcRows += Invoke-WxcScenario -Name 'a1-exit0' -CommandLine 'cmd /d /s /c exit 0'
            $wxcRows += Invoke-WxcScenario -Name 'a1-exit7' -CommandLine 'cmd /d /s /c exit 7'
            $wxcRows += Invoke-WxcScenario -Name 'a2-stdout' -CommandLine 'cmd /d /s /c echo WXC-STDOUT-MARKER'
            $wxcRows += Invoke-WxcScenario -Name 'a2-stderr' -CommandLine 'cmd /d /s /c echo WXC-STDERR-MARKER 1>&2'

            # stdin forwarding: pipe a marker in; find /v "" echoes it back
            $row = [ordered]@{ scenario = 'a2-stdin'; error = $null; configArtifact = $null; exit = $null; elapsedMs = $null }
            try {
                $configPath = New-Config -Name 'd03-a2-stdin' -CommandLine 'cmd /d /s /c find /v ""' -ReadOnly @('C:\Windows')
                $row['configArtifact'] = 'd03-config-a2-stdin.json'
                Copy-Item -LiteralPath $configPath -Destination (Join-Path $ResultsDir 'd03-config-a2-stdin.json') -Force
                $sw = [System.Diagnostics.Stopwatch]::StartNew()
                $r = Invoke-Guarded -TimeoutSec 120 -ArgumentList @($wxcExec, $configPath) -ScriptBlock {
                    param($Exe, $Cfg)
                    $out = 'WXC-STDIN-MARKER' | & $Exe $Cfg 2>&1
                    [pscustomobject]@{ text = (@($out) | ForEach-Object { [string]$_ }) -join [Environment]::NewLine; exit = $LASTEXITCODE }
                }
                $sw.Stop()
                $row['exit'] = $r.exit
                $row['elapsedMs'] = $sw.ElapsedMilliseconds
                Set-Content -LiteralPath (Join-Path $ResultsDir 'd03-wxc-a2-stdin.json') -Value ([string]$r.text) -Encoding utf8
                $row['stdinRoundTrip'] = ([string]$r.text) -match 'WXC-STDIN-MARKER'
            } catch { $row['error'] = "$($_.Exception.Message)" }
            $wxcRows += $row

            # timeout: request-level process.timeout vs a 60s sleep workload
            $row = [ordered]@{ scenario = 'a3-timeout'; error = $null; configArtifact = $null; exit = $null; elapsedMs = $null }
            try {
                # Amendment 1: System32-resident powershell.exe sleeper with a
                # readonly SystemRoot grant (pwsh failed to resolve in run 1);
                # -TimeoutMs exists at the pin (:543, emitted :602) but the
                # post-New-Config patch of process.timeout is retained - it is
                # the shape already proven schema-valid in run 1.
                $configPath = New-Config -Name 'd03-a3-timeout' -CommandLine 'powershell.exe -NoLogo -NoProfile -Command Start-Sleep -Seconds 60' -ReadOnly @('C:\Windows')
                $a3Json = Get-Content -Raw -LiteralPath $configPath | ConvertFrom-Json
                $a3Json.process.timeout = 3000
                $a3Json | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $configPath -Encoding utf8
                $row['configArtifact'] = 'd03-config-a3-timeout.json'
                Copy-Item -LiteralPath $configPath -Destination (Join-Path $ResultsDir 'd03-config-a3-timeout.json') -Force
                $sw = [System.Diagnostics.Stopwatch]::StartNew()
                $r = Invoke-Guarded -TimeoutSec 120 -ArgumentList @($wxcExec, $configPath) -ScriptBlock {
                    param($Exe, $Cfg)
                    $out = & $Exe $Cfg 2>&1
                    [pscustomobject]@{ text = (@($out) | ForEach-Object { [string]$_ }) -join [Environment]::NewLine; exit = $LASTEXITCODE }
                }
                $sw.Stop()
                $row['exit'] = $r.exit; $row['elapsedMs'] = $sw.ElapsedMilliseconds
                Set-Content -LiteralPath (Join-Path $ResultsDir 'd03-wxc-a3-timeout.json') -Value ([string]$r.text) -Encoding utf8
            } catch { $row['error'] = "$($_.Exception.Message)" }
            $wxcRows += $row

            # cancellation: kill the executor mid-run, then check for
            # surviving workload processes (process-tree teardown)
            # Not under Invoke-Guarded (the single documented exception): the
            # scenario must Stop-Process the executor from the parent, and every
            # wait below is bounded (WaitForExit(15000) + fixed sleeps) - no
            # unbounded synchronous wait on the executor exists.
            $row = [ordered]@{ scenario = 'a4-cancel'; error = $null; configArtifact = $null; exit = $null; elapsedMs = $null }
            try {
                $sw = [System.Diagnostics.Stopwatch]::StartNew()
                $configPath = New-Config -Name 'd03-a4-cancel' -CommandLine "powershell.exe -NoLogo -NoProfile -Command Start-Sleep -Seconds 120; 'WBD-D03-A4-MARKER'" -ReadOnly @('C:\Windows')
                $row['configArtifact'] = 'd03-config-a4-cancel.json'
                Copy-Item -LiteralPath $configPath -Destination (Join-Path $ResultsDir 'd03-config-a4-cancel.json') -Force
                $proc = Start-Process -FilePath $wxcExec -ArgumentList "`"$configPath`"" -PassThru
                Start-Sleep -Seconds 5
                $runningBefore = @(Get-CimInstance Win32_Process -Filter "CommandLine LIKE '%WBD-D03-A4-MARKER%'" -ErrorAction SilentlyContinue)
                # Guarded kill: the mock's fake executor exits in milliseconds,
                # so the PID may already be gone here (real run: mid-workload).
                # wasAliveAtKill carries the liveness evidence (true in the VM,
                # false against the instant-exit fake); executorKilled records
                # that the teardown step completed either way.
                $wasAliveAtKill = $null -ne (Get-Process -Id $proc.Id -ErrorAction SilentlyContinue)
                if ($wasAliveAtKill) { Stop-Process -Id $proc.Id -Force }
                $proc.WaitForExit(15000) | Out-Null
                Start-Sleep -Seconds 3
                $survivors = @(Get-CimInstance Win32_Process -Filter "CommandLine LIKE '%WBD-D03-A4-MARKER%'" -ErrorAction SilentlyContinue)
                $sw.Stop()
                $row['executorKilled'] = $true
                $row['wasAliveAtKill'] = $wasAliveAtKill
                $row['workloadProcessesBeforeKill'] = @($runningBefore | ForEach-Object { $_.ProcessId })
                $row['workloadProcessSurvivors'] = @($survivors | ForEach-Object { $_.ProcessId })
                $row['treeTornDown'] = (@($survivors).Count -eq 0)
                $row['elapsedMs'] = $sw.ElapsedMilliseconds
                @{ scenario = 'a4-cancel'; executorKilled = $true; wasAliveAtKill = $wasAliveAtKill; survivors = @($survivors | ForEach-Object { $_.ProcessId }) } |
                    ConvertTo-Json | Set-Content -LiteralPath (Join-Path $ResultsDir 'd03-wxc-a4-cancel.json') -Encoding utf8
            } catch { $row['error'] = "$($_.Exception.Message)" }
            $wxcRows += $row
            $wxcRan = $true
        } catch {
            $wxcBlocker = "Section A failed to initialize: $($_.Exception.Message)"
        }
    }

    # ---------------------------------------------------------------------
    # Section B - mxc-sdk in-process spike. Materialize Cargo.toml from
    # the committed template, cargo build (offline first, then online),
    # run the 8 scenarios each as its own guarded process invocation.
    # Build failure = recorded blocker (Section A evidence stands alone).
    # ---------------------------------------------------------------------
    $sdkRan = $false; $sdkBlocker = $null; $sdkRows = @(); $buildExit = $null; $buildElapsedMs = $null
    $templatePath = Join-Path $SpikeDir 'Cargo.toml.template'
    if (-not (Test-Path -LiteralPath $templatePath)) {
        $sdkBlocker = "spike crate template missing at $templatePath (Section B blocker)."
    } elseif (-not (Test-Path -LiteralPath (Join-Path $MxcRoot 'src\mxc-sdk\Cargo.toml'))) {
        $sdkBlocker = "pinned tree has no src/mxc-sdk crate at $MxcRoot (layout drift; Section B blocker)."
    } else {
        try {
            $cargoToml = (Get-Content -Raw -LiteralPath $templatePath) -replace '__MXC_ROOT__', ($MxcRoot -replace '\\', '\\')
            Set-Content -LiteralPath (Join-Path $SpikeDir 'Cargo.toml') -Value $cargoToml -Encoding utf8
            Copy-Item -LiteralPath (Join-Path $SpikeDir 'Cargo.toml') -Destination (Join-Path $ResultsDir 'd03-sdk-cargo.toml') -Force

            # Guarded build: force-tier-testing changes mxc-sdk's feature
            # fingerprint -> full rebuild of the upstream tree (~155k lines);
            # a wedged build must become a recorded blocker, not a lost run.
            $buildLog = Join-Path $ResultsDir 'd03-sdk-build.log'
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            $r = Invoke-Guarded -TimeoutSec 1800 -ArgumentList @((Join-Path $SpikeDir 'Cargo.toml'), $buildLog) -ScriptBlock {
                param($Manifest, $Log)
                cargo build --release --offline --manifest-path $Manifest 2>&1 | Tee-Object -FilePath $Log | Out-Null
                $code = $LASTEXITCODE
                if ($code -ne 0) {
                    cargo build --release --manifest-path $Manifest 2>&1 | Tee-Object -FilePath $Log -Append | Out-Null
                    $code = $LASTEXITCODE
                }
                [pscustomobject]@{ text = "cargo exit $code (full log: $Log)"; exit = $code }
            }
            $sw.Stop()
            $buildExit = $r.exit
            $buildElapsedMs = $sw.ElapsedMilliseconds

            $spikeBin = Join-Path $SpikeDir 'target\release\wbd-d03-sdk-spike.exe'
            if ($buildExit -eq 0 -and (Test-Path -LiteralPath $spikeBin)) {
                $baseline['mxc']['spikeBinSha256'] = (Get-FileHash -LiteralPath $spikeBin -Algorithm SHA256).Hash
                foreach ($s in 'probe','run-exit','run-stdio','spawn-stdin','timeout','cancel','tier-query') {
                    $row = [ordered]@{ scenario = $s; error = $null; exit = $null }
                    try {
                        $r = Invoke-Guarded -TimeoutSec 120 -ArgumentList @($spikeBin, $s) -ScriptBlock {
                            param($Bin, $S)
                            $out = & $Bin $S 2>&1
                            [pscustomobject]@{ text = (@($out) | ForEach-Object { [string]$_ }) -join [Environment]::NewLine; exit = $LASTEXITCODE }
                        }
                        $row['exit'] = $r.exit
                        Set-Content -LiteralPath (Join-Path $ResultsDir "d03-sdk-$s.json") -Value ([string]$r.text) -Encoding utf8
                    } catch { $row['error'] = "$($_.Exception.Message)" }
                    $sdkRows += $row
                }
                # force-tier passes the forced value as argv[2]
                $row = [ordered]@{ scenario = 'force-tier'; error = $null; exit = $null; forcedValue = 'appcontainer-dacl' }
                try {
                    $r = Invoke-Guarded -TimeoutSec 120 -ArgumentList @($spikeBin) -ScriptBlock {
                        param($Bin)
                        $out = & $Bin force-tier appcontainer-dacl 2>&1
                        [pscustomobject]@{ text = (@($out) | ForEach-Object { [string]$_ }) -join [Environment]::NewLine; exit = $LASTEXITCODE }
                    }
                    $row['exit'] = $r.exit
                    Set-Content -LiteralPath (Join-Path $ResultsDir 'd03-sdk-force-tier.json') -Value ([string]$r.text) -Encoding utf8
                } catch { $row['error'] = "$($_.Exception.Message)" }
                $sdkRows += $row
                $sdkRan = $true
            } else {
                $sdkBlocker = "spike build failed (cargo exit $buildExit): $($r.text)"
            }
        } catch {
            $sdkBlocker = "Section B failed: $($_.Exception.Message)"
        }
    }

    # ---------------------------------------------------------------------
    # Section C - D-04 enforcement evidence.
    # ---------------------------------------------------------------------
    $cRan = $false; $cBlocker = $null; $cRows = @()
    if (-not $wxcRan) {
        $cBlocker = 'Section C skipped: no upstream New-Config (Section A blocker applies here too).'
    } else {
        try {
            # C1: enumeratePaths request - probed, then LAUNCHED with a
            # marker-file canary. The D-02 matrix proves adjudication
            # blocks it (EnumeratePathsUnsupported); the launch evidence
            # shows which of the spec's two outcomes occurs:
            # (a) refused (nonzero, no marker) or (b) demoted-and-run.
            $c1Marker = Join-Path $markerDir 'c1-ran.txt'
            # Amendment 1: enumeratePaths is a NESTED schema key
            # (processContainer.filesystem.enumeratePaths, stable.rs:310-315);
            # upstream New-Config exposes it directly via -EnumeratePaths
            # (WinProcessContainer.Common.ps1:572, emitted :666-668). Run 1's
            # top-level hand-authored key was schema-rejected (recorded);
            # this form reaches the EnumeratePathsUnsupported adjudication
            # (fallback_detector.rs:238-241, raised :301).
            $c1ConfigArtifact = Join-Path $ResultsDir 'd03-config-c1-enumerate.json'
            $configPath = New-Config -Name 'd03-c1-enumerate' -CommandLine "cmd /d /s /c echo C1-WORKLOAD-RAN > `"$c1Marker`"" -ReadWrite @($markerDir) -EnumeratePaths @('C:\Windows')
            Copy-Item -LiteralPath $configPath -Destination $c1ConfigArtifact -Force

            # probe the hand-authored request (verbatim artifact)
            $r = Invoke-Guarded -TimeoutSec 120 -ArgumentList @($wxcExec, $c1ConfigArtifact) -ScriptBlock {
                param($Exe, $Cfg)
                $out = & $Exe --probe --config $Cfg 2>&1
                [pscustomobject]@{ text = (@($out) | ForEach-Object { [string]$_ }) -join [Environment]::NewLine; exit = $LASTEXITCODE }
            }
            Set-Content -LiteralPath (Join-Path $ResultsDir 'd03-c1-probe.json') -Value ([string]$r.text) -Encoding utf8
            $c1ProbeExit = $r.exit

            # launch it
            $r = Invoke-Guarded -TimeoutSec 120 -ArgumentList @($wxcExec, $c1ConfigArtifact) -ScriptBlock {
                param($Exe, $Cfg)
                $out = & $Exe $Cfg 2>&1
                [pscustomobject]@{ text = (@($out) | ForEach-Object { [string]$_ }) -join [Environment]::NewLine; exit = $LASTEXITCODE }
            }
            Set-Content -LiteralPath (Join-Path $ResultsDir 'd03-c1-launch.json') -Value ([string]$r.text) -Encoding utf8
            $markerExists = Test-Path -LiteralPath $c1Marker
            $c1Outcome = if (-not $markerExists -and $r.exit -ne 0) { 'refused-before-exec' }
                         elseif ($markerExists) { 'demoted-and-ran' } else { 'ambiguous' }
            $cRows += [ordered]@{ scenario = 'c1-enumerate'; probeExit = $c1ProbeExit; launchExit = $r.exit; markerFilePresent = $markerExists; outcome = $c1Outcome }

            # C2: env-downgrade immunity of the shipped executor. The
            # force-tier branch is cfg(any(test, feature=
            # "force-tier-testing")) - the default-feature release
            # binary must ignore MXC_FORCE_TIER entirely.
            $cfgEmpty = New-Config -Name 'd03-c2-empty' -CommandLine 'cmd /c exit 0'
            $prev = $env:MXC_FORCE_TIER
            $env:MXC_FORCE_TIER = 'appcontainer-dacl'
            try {
                $r = Invoke-Guarded -TimeoutSec 120 -ArgumentList @($wxcExec, $cfgEmpty) -ScriptBlock {
                    param($Exe, $Cfg)
                    $out = & $Exe --probe --config $Cfg 2>&1
                    [pscustomobject]@{ text = (@($out) | ForEach-Object { [string]$_ }) -join [Environment]::NewLine; exit = $LASTEXITCODE }
                }
            } finally {
                if ($null -eq $prev) { Remove-Item Env:MXC_FORCE_TIER -ErrorAction SilentlyContinue } else { $env:MXC_FORCE_TIER = $prev }
            }
            Set-Content -LiteralPath (Join-Path $ResultsDir 'd03-c2-env-immunity.json') -Value ([string]$r.text) -Encoding utf8
            $tierStillBase = ([string]$r.text) -match '"tier"\s*:\s*"base-container"'
            $cRows += [ordered]@{ scenario = 'c2-env-immunity'; probeExit = $r.exit; tierStillBaseContainer = $tierStillBase }
            $cRan = $true
        } catch {
            $cBlocker = "Section C failed: $($_.Exception.Message)"
        }
    }

    # ---------------------------------------------------------------------
    # Summary + baseline block + manifest.
    # ---------------------------------------------------------------------
    $summary = [ordered]@{
        schema = 1
        ran    = ($wxcRan -or $sdkRan -or $cRan)
        wxc    = [ordered]@{ ran = $wxcRan; blocker = $wxcBlocker; rows = @($wxcRows) }
        sdk    = [ordered]@{ ran = $sdkRan; blocker = $sdkBlocker; buildExit = $buildExit; buildElapsedMs = $buildElapsedMs; rows = @($sdkRows) }
        c      = [ordered]@{ ran = $cRan; blocker = $cBlocker; rows = @($cRows) }
    }
    $summary.errorCount = @($wxcRows + $sdkRows + $cRows | Where-Object { $_.error }).Count
    $summary | ConvertTo-Json -Depth 7 | Set-Content -LiteralPath (Join-Path $ResultsDir 'd03d04-spike.json') -Encoding utf8

    $baseline['d03d04Spike'] = [ordered]@{
        ran = $summary.ran; wxcRan = $wxcRan; sdkRan = $sdkRan; cRan = $cRan
        blockers = @(@($wxcBlocker, $sdkBlocker, $cBlocker) | Where-Object { $_ })
        summaryArtifact = 'd03d04-spike.json'
    }
    Set-Content -LiteralPath $baselinePath -Value ($baseline | ConvertTo-Json -Depth 7) -Encoding utf8

    Start-Sleep -Milliseconds 100   # let the last writes flush
    $manifest = [ordered]@{
        schema     = 1
        capturedAt = $capturedAt
        artifacts  = @(Get-ChildItem -LiteralPath $ResultsDir -File |
            ForEach-Object {
                [ordered]@{ name = $_.Name; bytes = $_.Length; sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash }
            })
    }
    $manifest | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $ResultsDir 'capture-manifest.json') -Encoding utf8

    Write-Host "[wbd-spike] wxc: ran=$wxcRan | sdk: ran=$sdkRan | c: ran=$cRan"
    Write-Host "[wbd-spike] artifacts written to $ResultsDir (fetched by the harness into tests\vm\results\<runid>\)."
    Write-Host 'WBD SPIKE CAPTURE: DONE' -ForegroundColor Green
    exit 0
} catch {
    Write-Host "[wbd-spike] unexpected error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host 'WBD SPIKE CAPTURE: FAILED' -ForegroundColor Red
    exit 99
}
```

Implementation notes (binding):
- The `summary.ran` gate uses OR (a run where only Section A succeeded still fetched its evidence); each section's own `ran`/`blocker` records the truth. `errorCount` counts per-row `error` fields.
- `Invoke-Guarded` passes job arguments via `Start-Job -ArgumentList` (the D-02 pattern) and turns a thrown child error into recorded evidence (`job error: …`, exit -1) so the scenario artifact is still written — a lost scenario is never acceptable.
- a4-cancel is the single documented exception to the hang-guard rule: the scenario needs the executor PID in the parent to Stop-Process it; every wait is bounded (`WaitForExit(15000)` + fixed sleeps). The Section B cargo build is guarded at 1800s (feature-fingerprint rebuild of ~155k upstream lines) — a wedged build becomes a recorded blocker, never a lost run.
- a3's config patches `process.timeout` after New-Config: the post-patch is retained because it is the shape proven schema-valid in run 1 (upstream `-TimeoutMs` verified at the pin, `WinProcessContainer.Common.ps1:543` emitted `:602` — Task 8 Step 6). Parameters the capture script passes (`-Name`, `-CommandLine`, `-ReadWrite`, `-ReadOnly`, `-EnumeratePaths`) are all verified upstream (`:537-:572`).
- The C1 config's `enumeratePaths` value `C:\Windows` is deliberately a directory the marker-writing workload never touches — the enumerate grant itself is unexercised; only the *adjudication* of the key is under test.
- The C1 key is emitted by upstream `New-Config -EnumeratePaths` as the nested `processContainer.filesystem.enumeratePaths` (verified at the pin; run 1's top-level hand-authored key was schema-rejected — recorded verbatim in the run-1 artifacts). Any schema mismatch surfaces as the probe/launch error text — recorded verbatim either way (evidence, not capture error).
- Baseline gets `Depth 7` (summary rows nest one deeper than D-02's 6).

- [x] **Step 2: Parser check**

Run:
```powershell
$errs = $null; $null = [System.Management.Automation.Language.Parser]::ParseFile("C:\Users\marku\tools\sandbox\tests\vm\wbd-d03-d04-spike.ps1", [ref]$null, [ref]$errs); if ($errs.Count) { $errs | ForEach-Object { "$($_.Message) @ line $($_.Extent.StartLineNumber)" } } else { 'parse OK' }
```
Expected: `parse OK`

---

### Task 4: Host compile check of the spike against the REAL pinned crate

Before burning a capture-lane run on a compile error, `cargo check` the spike against the real `src/mxc-sdk` at the pin. This is a host-side **compile-only** check (temp dir + cargo cache; nothing is executed, no host mutation beyond `%LOCALAPPDATA%\Temp\opencode`):

- [x] **Step 1: Fetch the pin into temp** (scratch, not committed):

```powershell
$pinRoot = Join-Path $env:LOCALAPPDATA 'Temp\opencode\mxc-pincheck'
if (Test-Path $pinRoot) { Remove-Item -Recurse -Force $pinRoot }
git init $pinRoot
git -C $pinRoot remote add origin https://github.com/microsoft/mxc.git
git -C $pinRoot fetch --depth 1 origin 5d7a475a9fd5626bafb55c2c857989d2e5621245
git -C $pinRoot checkout FETCH_HEAD
```

- [x] **Step 2: Materialize + check**

```powershell
$spike = 'C:\Users\marku\tools\sandbox\tests\vm\spikes\wbd-d03-sdk-spike'
(Get-Content -Raw (Join-Path $spike 'Cargo.toml.template')) -replace '__MXC_ROOT__', ($pinRoot -replace '\\', '\\') |
    Set-Content (Join-Path $spike 'Cargo.toml')
cargo check --manifest-path (Join-Path $spike 'Cargo.toml')
```

Expected: exit 0, **zero warnings** (AGENTS.md acceptance bar). If rustc < 1.93 (mxc's pinned toolchain) or a network fetch fails, record the reason and skip — the in-VM build (warm cache, correct toolchain) remains authoritative; note the skip in the Task 5 commit message. Fix any API mismatches this surfaces in `src/main.rs` (the documented API above is the source of truth; do not invent replacements for anything that fails to compile — adjust to the real signature and record drift in the commit message).

- [x] **Step 3: Clean the temp checkout**

```powershell
Remove-Item -Recurse -Force (Join-Path $env:LOCALAPPDATA 'Temp\opencode\mxc-pincheck')
Remove-Item -Recurse -Force (Join-Path $spike 'target') -ErrorAction SilentlyContinue
```

---

### Task 5: Run the mock — expect PASS — commit (PR1 code batch)

- [x] **Step 1: Run the mock**

Run: `pwsh -NoProfile -ExecutionPolicy Bypass -File "C:\Users\marku\AppData\Local\Temp\opencode\wbd-mock-d03\run-mock.ps1"`
Expected: `MOCK PASSED (d03d04 scenarios A+B+C; …)` — Section A completes with fake executor semantics, the stub SDK build succeeds and all 8 scenario JSONs appear, C rows present, baseline + summary + manifest complete; B exits 3; C records the sdk blocker and still completes.

- [x] **Step 2: Fix everything the mock catches, re-run to green** (the mock's job is plumbing drift — e.g. wrong artifact names, row-shape raggedness, blocker paths).

- [x] **Step 3: Clean up the mock root**

Run: `Remove-Item -Path (Join-Path $env:TEMP 'opencode\wbd-mock-d03*'), (Join-Path $env:TEMP 'mxc-sbx-d03-spike') -Recurse -Force -ErrorAction SilentlyContinue` (`-Path`, not `-LiteralPath` — the wildcard must expand; the second path is the capture script's scratch root created by the mock runs).

- [x] **Step 4: Commit** (spike crate + capture script only — the mock is temp scratch):

```powershell
git add tests/vm/wbd-d03-d04-spike.ps1 tests/vm/spikes/wbd-d03-sdk-spike
git commit -m "test(vm): WBD D-03/D-04 spike lane - wxc-exec subprocess lifecycle (launch/exit-as-outcome, stdio, stdin round-trip, request-level timeout, executor kill + process-tree survivor check), mxc-sdk in-process spike crate (8 scenarios: probe/run-exit/run-stdio/spawn-stdin/timeout/cancel/force-tier/tier-query against the documented v1 surface, path-dep on the pinned tree's src/mxc-sdk with force-tier-testing compiled in, template-materialized Cargo.toml recorded as artifact), and D-04 enforcement evidence (enumeratePaths fail-before-exec with marker canary, MXC_FORCE_TIER immunity of the default-feature release executor). Hang-guarded launch scenarios throughout; build failure = recorded blocker; mock-verified A+B+C (happy, no-checkout exit 3, sdk-stub-missing blocker)."
```

---

### Task 6: In-VM capture run (USER-DRIVEN, elevated pwsh)

- [x] **Step 1: Run the capture lane** (maintainer, from `C:\Users\marku\tools\sandbox`):

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File tests\vm\Invoke-TestsInVM.ps1 -Image sbx-base-b -TestCmd "pwsh -NoProfile -ExecutionPolicy Bypass -File C:\sbx-repo\tests\vm\wbd-d03-d04-spike.ps1"
```

Expected: `VM HARNESS: PASS`, `WBD SPIKE CAPTURE: DONE`. Flat artifact set (~31 files): `d03d04-baseline.json`, 8 `d03-config-*.json`, 7 `d03-wxc-*.json`, `d03-sdk-build.log`, `d03-sdk-cargo.toml`, 8 `d03-sdk-*.json`, `d03-c1-probe.json`, `d03-c1-launch.json`, `d03-c2-env-immunity.json`, `d03d04-spike.json`, `capture-manifest.json`.

- [x] **Step 2: Paste the run summary back** to the assistant (harness tail + `wxc: ran=… | sdk: ran=… | c: ran=…` line).

---

### Task 7: Verify the fetched evidence

**Files:**
- Read: `tests/vm/results/<new-runid>/` — all artifacts listed above

- [x] **Step 1: Provenance** — `pinMatches: true`, wxc-exec SHA256 matches `3FD125498803970B3FC7E63FC36307DD7A3186318FA02B83034F141731006DAC`, spike-bin SHA256 present; every artifact hash-verified against `capture-manifest.json` (the `testcmd.log` prefix caveat from D-02 is structural and expected).
- [x] **Step 2: Section A verdicts** — exit codes (0 vs 7 as workload outcomes), stdio markers captured on the right streams, stdin round-trip, timeout elapsed ≈ 3s not 60s, a4: `wasAliveAtKill: true` + no workload-process survivors (tree torn down).
- [x] **Step 3: Section B verdicts** — all 8 scenario JSONs parse; probe reproduces the D-01/D-02 boolean surface; run-exit outcomes `Exited(0)`/`Exited(7)`; timeout outcome `TimedOut`; cancel waits cleanly; force-tier `honored: true` (the feature compiled the seam) with tier string `appcontainer-dacl`; tier-query lists `processcontainer` at `base-container`.
- [x] **Step 4: Section C verdicts** — c1: probe error `EnumeratePathsUnsupported` expected; launch outcome = whichever of `refused-before-exec` / `demoted-and-ran` the artifact shows (both are valid evidence; the spec branches on it); c2: `tierStillBaseContainer: true`.
- [x] **Step 5: Record any deviation verbatim** — every anomaly is a finding for the ADRs, never something to re-run away.

---

### Task 8: Source-verification pack at the pin (ADR line refs)

Targeted `raw.githubusercontent.com` fetches at `5d7a475a9fd5626bafb55c2c857989d2e5621245` (the evidence the ADRs cite; several facts are already verified this session — re-cite, don't re-derive):

- [x] **Step 1: C4 staging point** — `src/mxc-sdk/src/backends/process_container/common/base_container_runner.rs` (145 KB): locate the workload creation sequence — `CREATE_SUSPENDED` / `ResumeThread` / PSEC environment attach order / any created-not-running window. Also check `appcontainer_runner.rs` (`spawn_suspended`/`resume` at e7940f7 per `mxc-source-analysis.md` §2.4 — re-verify at the pin). Verdict recorded either way; **if no surface exposes created-not-running, this is the binding blocker**: ADR-0002 §3 records it, ADR-0003 restates the stop-work consequence.
- [x] **Step 2: wxc-exec CLI surface** — `src/tools/wxc/src/` (list + main): the full flag surface of the shipped executor (no require-tier flag expected; confirm `--experimental` handling); exact line refs for the ADR's subprocess row.
- [x] **Step 3: FFI exports** — `src/ffi/` listing + the C ABI module it wraps (`mxc_sdk::__ffi` in `src/mxc-sdk/src/lib.rs`, already fetched): language targets, stability labels ("not SDK authoring APIs"), consumers (Node/.NET SDKs).
- [x] **Step 4: Job Object controls** — `common/job_object.rs` (29 KB): which resource controls the base-container tier applies (UI limits confirmed in D-02 §4.2; memory/process-count/die-on-close flags feed the D-03 "Job Object resource controls" investigation item).
- [x] **Step 5: Dispatcher launch order + attestation surfaces** — `common/dispatcher.rs` (64 KB): where `choose_backend_tier` is called relative to process creation, what the dispatcher can attest post-launch, generation/correlation identifiers (also `sandbox_tracking.rs`), and the `EnforcementDegraded` audit emission (already seen in `fallback_detector.rs`).
- [x] **Step 6: C1/A3 schema-key confirmation** — the pinned `docs/schema.md` / `schemas/stable` entries for `filesystem.enumeratePaths` (the C1 hand-added key) and `process.timeout` (the a3 patched key), plus the upstream `New-Config` helper's actual parameter surface in `tests/scripts/lib/WinProcessContainer.Common.ps1` (confirm the capture script only passes observed parameters) — confirm or record the drift.
- [x] **Step 7: Assemble the line-ref tables** into the raw material for both ADRs (every ADR claim gets a `file:line` at the pin or a fetched artifact name).

---

### Task 9: ADR-0002 (D-03) + companion updates + PR1 complete

**Files:**
- Create: `docs/adr/0002-mxc-integration-surface.md`
- Modify: `docs/mxc-source-analysis.md`, `docs/superpowers/plans/2026-10-14-wbd-d03-d04-stop-work-gates.md` (run annotation), `tests/vm/BUILD-BASE-IMAGE.md` (capture-lane note, if needed)

- [x] **Step 1: Write ADR-0002** per the spec §3.2 structure: provenance header (pin, template SHA, canonical run id, manifest reference); the **three-way comparison** (wxc-exec subprocess / mxc-sdk 1.0.0 library / `src/ffi` FFI) across the eleven mandated axes, every cell citing a fetched artifact or a `file:line` at the pin; the five investigation items (created-not-running, pre-resume attestation, generation-correlated ownership, Job Object resource controls, effective-control query-back) each with evidence or blocker status; the version/commit boundary + upgrade policy (pin `5d7a475a…`, crates.io `mxc-sdk` 1.0.0 published 2026-10-06 by `microsoft-oss-releases`, re-verify on every re-pin — extends the D-02 matrix §5.1 caveat pattern to the SDK surface); acceptance-criteria checklist (D-03 criteria 1–6 each mapped to its proof artifact or recorded blocker, incl. the probe criterion citing the D-02 canonical-run artifacts per spec advisory 4). The decision itself is **evidence-constrained**: if created-not-running/pre-resume is unavailable on every surface, the selected surface is still named (best documented fit), but the launch-path blocker is recorded and the stop-work consequence is stated — no product launch path until an upstream mechanism exists.
- [x] **Step 2: Companion updates** — `mxc-source-analysis.md` pin block: partial-refresh note for the SDK/FFI/dispatcher/fallback-detector areas read in Tasks 4–8 (findings sections still key to `e7940f7`); plan annotation (canonical run id + headline verdicts); BUILD-BASE-IMAGE.md capture-lane description gains the spike lane if the file lists lanes.
- [x] **Step 3: Cross-check** every ADR table cell against the fetched artifacts and Task 8 line refs one final time.
- [x] **Step 4: Commit** — completes PR1:

```powershell
git add docs/adr/0002-mxc-integration-surface.md docs/mxc-source-analysis.md docs/superpowers/plans/2026-10-14-wbd-d03-d04-stop-work-gates.md tests/vm/BUILD-BASE-IMAGE.md
git commit -m "docs(adr): 0002 - WBD D-03 MXC integration surface decision - <headline: selected surface + the created-not-running verdict>"
```

---

### Task 10: ADR-0003 (D-04) + PR2

**Files:**
- Create: `docs/adr/0003-basecontainer-only-enforcement.md`
- Modify: `docs/superpowers/plans/2026-10-14-wbd-d03-d04-stop-work-gates.md` (final annotation)

- [x] **Step 1: Write ADR-0003** per the spec §3.3 structure: provenance (same canonical run; consumes ADR-0002's selected surface); the no-fallback mechanism decision — grounded in the resolved findings: **no supported require-tier input** (the `MXC_FORCE_TIER` seam is `cfg(any(test, feature = "force-tier-testing"))`, test/feature-only, silently ignored by the shipped executor — runtime-proven by `d03-c2-env-immunity.json` and `d03-sdk-force-tier.json`); no policy shape demotes on this host (unsupported forms hard-error — `d03-c1-*.json`); the adapter mechanism therefore = request-scoped preflight (`v1::probe` / `--probe --config` on the exact rendered request, refusing any tier ≠ `base-container` and any absent required capability) **plus** the strongest post-launch attestation the selected surface allows (per ADR-0002's query-back finding — if none exists before resume, that is recorded as the upstream requirement it is, not waved away); race analysis (probe→launch TOCTOU: no atomic require-tier at the pin → upstream requirement + attestation-before-resume mitigation); the staging-point statement for D-08 (the launch-sequence point where mandatory controls are installed and attested before workload code executes, consuming Task 8's C4 verdict); D-04 criteria 1–5 each mapped to **named** proof artifacts — for the expected refused outcome of C1, criterion 3 (appcontainer machinery exists but never engages without opt-in) discharges via the combination `d03-sdk-tier-query.json` (available_backends shows the appcontainer tier machinery exists in the binary) + `d03-c1-probe.json`/`d03-c1-launch.json` (the same request still fails closed) + the preflight-refuses-tier≠base-container design statement; if the C1 outcome is instead demoted-and-ran, the C1 artifacts become the adapter fixture per the spec's primary path.
- [x] **Step 2: Cross-check** every claim against fetched artifacts + Task 8 line refs.
- [x] **Step 3: Plan annotation + commit** — completes PR2:

```powershell
git add docs/adr/0003-basecontainer-only-enforcement.md docs/superpowers/plans/2026-10-14-wbd-d03-d04-stop-work-gates.md
git commit -m "docs(adr): 0003 - WBD D-04 BaseContainer-only enforcement decision - <headline: preflight + attestation mechanism + the atomic-require-tier upstream gap>"
```

---

### Verification summary (whole plan)

- Mock: scenarios A+B+C pass; parser clean; `cargo check` against the real pinned crate clean (or the skip reason recorded); zero warnings on everything committed.
- In-VM: canonical capture-lane run (`VM HARNESS: PASS`, ~31 flat artifacts manifest-hashed, all three sections' `ran`/`blocker` state recorded) plus the Amendment-1 supplementary run discharging the timeout/cancel/stdin axes; both runs' artifacts manifest-hashed. **Runs (annotated 2026-10-17):** canonical run `20261017-121539-354` (pre-amendment: pwsh/CWD findings, C1 top-level key schema-rejected → fail-closed at parse, all carryover axes PASS); Amendment-1 supplementary run `20261017-130259-402` (all four target axes discharged: a2-stdin roundTrip true, a3 "script timed out after 3000ms" at 3387ms, a4 wasAliveAtKill true + zero survivors + treeTornDown, C1 `EnumeratePathsUnsupported` adjudication refusal via the nested schema key; SDK-side Process-containment sleeper nuance recorded as an observation). Verdict records: scratch `task7-verdicts-20261017-121539-354.md` + `task7-verdicts-20261017-130259-402.md`; decision in `docs/adr/0002-mxc-integration-surface.md`.
- ADRs: every claim cites a fetched artifact or a `file:line` at the pin; both tickets' acceptance criteria each mapped to evidence or a recorded blocker; the created-not-running/pre-resume outcome stated with its binding stop-work consequence if blocked.
- Both PR batches respect the one-ticket-per-PR gate: PR1 = D-03 (Tasks 1–9), PR2 = D-04 (Task 10), PR1 mergeable standalone.
- **Completion record (2026-10-17):** PR1 (D-03, Tasks 1–9) = commits `cb85c0f`, `2c72106` (Amendment 1 plan), `e2be211` (Amendment 1 code), `3dfd2c0` (ADR-0002 + companions). PR2 (D-04, Task 10) = this commit (ADR-0003). Both stop-work gates land the same binding verdict: created-not-running / pre-resume attestation unavailable at pin `5d7a475a` → **no product launch path until an upstream mechanism exists** (ADR-0002 §5, ADR-0003 §4); D-04 additionally records the atomic-require-tier upstream gap (ADR-0003 §3).

@superpowers:test-driven-development (mock-first), @superpowers:verification-before-completion (evidence checks before every "done"), @superpowers:systematic-debugging (any mock/VM deviation).
