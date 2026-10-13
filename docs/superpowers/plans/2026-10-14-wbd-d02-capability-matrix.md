# WBD D-02 Capability Matrix Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete WBD D-02 — capture the five WBD request shapes as read-only `--probe --config` runs inside the image-B disposable VM and write `docs/wbd-d02-capability-matrix.md` from the fetched evidence.

**Architecture:** Extend the existing capture payload `tests/vm/wbd-d01-d02-probes.ps1` with a "D-02 matrix" section that dot-sources the pinned tree's `WinProcessContainer.Common.ps1`, generates the candidate requests with the upstream `New-Config` helper (schema-exact by construction), and probes each request read-only. The matrix document is then written from the fetched artifacts only, with the source-verified capability-boolean → PSEC-contract mapping fetched at the pin.

**Tech Stack:** PowerShell 7 (capture script, guest), Hyper-V disposable-VM harness (`Invoke-TestsInVM.ps1 -TestCmd`), upstream MXC pin `5d7a475a9fd5626bafb55c2c857989d2e5621245`.

**Spec:** `docs/superpowers/specs/2026-10-14-wbd-d02-capability-matrix-design.md` (approved, reviewer-approved).

**Plan-review corrections (binding, 2026-10-14):**

- **The harness artifact fetch is FLAT.** In TestCmd mode, `Invoke-TestsInVM.ps1` enumerates `Get-ChildItem -LiteralPath C:\sbx-results -File` (no `-Recurse`, ~line 765) and fetches each top-level file by name. Nested directories would silently never reach the host. **All matrix artifacts are therefore written as flat files directly in `C:\sbx-results`:** probe outputs as `d02-matrix-<shape>.probe.json`, generated configs as `d02-config-<shape>.json`. The capture manifest (also flat: `Get-ChildItem -File` on the results dir) hashes them automatically — no harness or manifest changes.
- The spec's "configs land in the fetched artifact tree" is satisfied via a **copy** step: `New-Config` still writes to `$ScratchRoot\configs` (its hard-coded layout), then each config is copied to the flat artifact name. The scratch tree (configs + rw/ro/denied grant dirs) lives under `$env:TEMP\mxc-sbx-d02-matrix` inside the guest; the VM is destroyed after the run.

**Resolved spec open items (upstream evidence, read at the pin 2026-10-14):**

- **UI shape values** (from `tests/scripts/run_processcontainer_ui_policy_matrix_test.ps1`): `-UiDisable <bool>`, `-Clipboard all|read|write|none`, `-Injection <bool>`, `-BpUiIsolation desktop|handles|atoms|container`, `-BpUiDesktopControl <bool>`, `-BpUiSystemSettings all|parameters|display|none|<free string>`, `-BpUiIme <bool>`.
- **Proxy shapes** (from `tests/scripts/run_processcontainer_network_proxy_test.ps1`): model 2 = `-EgressDefault 'deny' -IngressDefault 'allow'` + `-NetworkProxy <loopback-url>`; **identity-less** adds `-HostLoopback 'allow'` (no peer), **identity-scoped** adds `-AllowedProxyPeer 'Contoso.Proxy_8wekyb3d8bbwe'` with `-HostLoopback 'deny'`. Both variants are probed (sub-shapes of the WBD "proxy" shape, mirroring how filesystem splits rw/ro/denied): the identity-less variant depends on the `hostLoopback` ingress support bit which the D-01 probe already reports FALSE on this host, so the pair disambiguates a possible blocked row.

**Shape coverage gate (spec §3.1): PASSED.** `New-Config` (fetched from the pinned tree, `tests/scripts/lib/WinProcessContainer.Common.ps1`) accepts every parameter the five shapes need (`-ReadWrite/-ReadOnly/-Denied`, `-UiDisable/-Clipboard/-Injection/-BpUiIsolation/-BpUiDesktopControl/-BpUiSystemSettings/-BpUiIme`, `-EgressDefault/-IngressDefault/-HostLoopback`, `-NetworkProxy/-AllowedProxyPeer`). No fallback needed. Caveats verified: `New-Config` writes via `Out-File` into `$ScratchRoot\configs` (the directory must pre-exist — `Out-File` does not create it), reads `$Script:SchemaVersion` (set to `'1.0.0'` at dot-source time), and always emits `ui.disable=false` when `-UiDisable` is not passed (the "empty" row therefore carries a documented no-op default, noted in the matrix doc).

---

### Task 1: Local mock for the matrix section (write first — TDD)

**Files:**
- Create: `C:\Users\marku\AppData\Local\Temp\opencode\wbd-mock\run-mock.ps1` (scratch; not committed)

The mock drives the REAL capture script in a child pwsh against fake MXC repos, three scenarios:

- **A (happy):** fake `Common.ps1` provides a `New-Config` stub, sidecars present → upstream test invoked + matrix complete. Expect: 8 flat `d02-config-<shape>.json` + 8 flat `d02-matrix-<shape>.probe.json` in the results dir, `d02-matrix.json` with `ran=true` + 8 rows, `d02-probes-results.json`, `FAKE-UPSTREAM` in `d02-upstream-probes.log`, baseline `d02Matrix` block.
- **B (blocker — Common.ps1 missing):** expect `d02-matrix.json` with `ran=false` + blocker text, run still `WBD CAPTURE: DONE` (exit 0), D-01 baseline present.
- **C (regression — sidecars missing):** upstream test skipped with the sidecar blocker recorded; matrix still runs; exit 0.

- [ ] **Step 1: Write the mock**

```powershell
#requires -Version 7
# Mock for wbd-d01-d02-probes.ps1's D-02 matrix section.
# Child pwsh console output (Write-Host) flows to the native process stdout -
# swallow it ($null = & pwsh ...) so only $LASTEXITCODE is returned.
$ErrorActionPreference = 'Stop'
$mockRoot = Join-Path $env:TEMP ("opencode\wbd-mock-" + (Get-Date -Format 'HHmmss'))
New-Item -ItemType Directory -Path $mockRoot -Force | Out-Null

function New-FakeMxcRepo {
    param([string]$Path, [switch]$WithCommonPs1, [switch]$WithSidecars)
    New-Item -ItemType Directory -Path (Join-Path $Path 'src\target\release') -Force | Out-Null
    git init --quiet $Path 2>$null
    git -C $Path -c user.name=mock -c user.email=mock@example.com commit --allow-empty --quiet -m init
    Copy-Item (Join-Path $env:SystemRoot 'System32\where.exe') (Join-Path $Path 'src\target\release\wxc-exec.exe')
    if ($WithSidecars) {
        Copy-Item (Join-Path $env:SystemRoot 'System32\where.exe') (Join-Path $Path 'src\target\release\plm.exe')
        Copy-Item (Join-Path $env:SystemRoot 'System32\where.exe') (Join-Path $Path 'src\target\release\winhttp-proxy-shim.exe')
    }
    $scriptDir = Join-Path $Path 'tests\scripts'
    New-Item -ItemType Directory -Path $scriptDir -Force | Out-Null
    @'
param(
    [string]$ContextJson, [string]$ResultsJson, [string]$RequireTier,
    [switch]$SkipNetwork, [switch]$KeepArtifacts
)
$ctx = Get-Content -Raw -LiteralPath $ContextJson | ConvertFrom-Json
if (-not $ctx.WxcDebug -or -not $ctx.WxcRelease -or -not $ctx.RepoRoot -or -not $ctx.CargoRoot) { throw 'context incomplete' }
Write-Host ("FAKE-UPSTREAM WxcDebug={0} RequireTier={1} SkipNetwork={2}" -f $ctx.WxcDebug, $RequireTier, [bool]$SkipNetwork)
if ($ResultsJson) { @{ schema = 1; fakeResults = $true } | ConvertTo-Json | Set-Content -LiteralPath $ResultsJson -Encoding utf8 }
exit 0
'@ | Set-Content -LiteralPath (Join-Path $scriptDir 'run_processcontainer_probes_test.ps1') -Encoding utf8
    if ($WithCommonPs1) {
        $libDir = Join-Path $scriptDir 'lib'
        New-Item -ItemType Directory -Path $libDir -Force | Out-Null
        @'
$Script:SchemaVersion = '1.0.0'
function New-Config {
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$CommandLine,
          [string[]]$ReadWrite = @(), [string[]]$ReadOnly = @(), [string[]]$Denied = @(),
          [Nullable[bool]]$UiDisable = $null, [string]$Clipboard = $null, [Nullable[bool]]$Injection = $null,
          [string]$BpUiIsolation = $null, [Nullable[bool]]$BpUiDesktopControl = $null,
          [string]$BpUiSystemSettings = $null, [Nullable[bool]]$BpUiIme = $null,
          [Nullable[bool]]$AllowDaclMutation = $null, [int]$TimeoutMs = 30000,
          [string[]]$Env = @(), [string]$Cwd = $null,
          [ValidateSet('allow','deny')][string]$EgressDefault = $null,
          [ValidateSet('allow','deny')][string]$IngressDefault = $null,
          [ValidateSet('allow','deny')][string]$HostLoopback = $null,
          [string]$NetworkProxy = $null, [string]$AllowedProxyPeer = $null,
          [object[]]$EgressAllow = @(), [object[]]$EgressDeny = @(), [switch]$EmptyNetwork)
    $dir = Join-Path $ScratchRoot 'configs'
    $path = Join-Path $dir "$Name.json"
    @{ name = $Name; stub = $true } | ConvertTo-Json | Out-File -LiteralPath $path -Encoding utf8 -Force
    return $path
}
'@ | Set-Content -LiteralPath (Join-Path $libDir 'WinProcessContainer.Common.ps1') -Encoding utf8
    }
}

function Invoke-Capture {
    param([string]$MxcRoot, [string]$ResultsDir)
    $null = & pwsh -NoProfile -ExecutionPolicy Bypass -File "C:\Users\marku\tools\sandbox\tests\vm\wbd-d01-d02-probes.ps1" -MxcRoot $MxcRoot -ResultsDir $ResultsDir 2>&1
    return $LASTEXITCODE
}

$shapes = 'empty','fs-rw','fs-ro','fs-denied','ui','deny-all-network','proxy-identityless','proxy-identity-scoped'
$fail = @()

# ---- Scenario A: happy path (sidecars + Common.ps1) --------------------
$mxcA = Join-Path $mockRoot 'mxcA'
New-FakeMxcRepo -Path $mxcA -WithCommonPs1 -WithSidecars
$resA = Join-Path $mockRoot 'resultsA'
$exitA = Invoke-Capture -MxcRoot $mxcA -ResultsDir $resA
if ($exitA -ne 0) { $fail += "A: expected exit 0, got $exitA" }
$matrix = Get-Content -Raw (Join-Path $resA 'd02-matrix.json') | ConvertFrom-Json
if (-not $matrix.ran) { $fail += 'A: matrix ran=false' }
if (@($matrix.shapes).Count -ne 8) { $fail += "A: expected 8 matrix rows, got $(@($matrix.shapes).Count)" }
foreach ($s in $shapes) {
    if (-not (Test-Path (Join-Path $resA "d02-matrix-$s.probe.json"))) { $fail += "A: missing flat probe artifact d02-matrix-$s.probe.json" }
    if (-not (Test-Path (Join-Path $resA "d02-config-$s.json"))) { $fail += "A: missing flat config artifact d02-config-$s.json" }
}
$baseA = Get-Content -Raw (Join-Path $resA 'wbd-d01-baseline.json') | ConvertFrom-Json
if (-not $baseA.d02Matrix -or -not $baseA.d02Matrix.ran) { $fail += 'A: baseline missing d02Matrix block' }
$d02logA = Get-Content -Raw (Join-Path $resA 'd02-upstream-probes.log')
if ($d02logA -notmatch 'FAKE-UPSTREAM') { $fail += 'A: regression - upstream test not invoked' }

# ---- Scenario B: Common.ps1 missing -> matrix blocker ------------------
$mxcB = Join-Path $mockRoot 'mxcB'
New-FakeMxcRepo -Path $mxcB -WithSidecars
$resB = Join-Path $mockRoot 'resultsB'
$exitB = Invoke-Capture -MxcRoot $mxcB -ResultsDir $resB
if ($exitB -ne 0) { $fail += "B: expected exit 0 (blocker is evidence), got $exitB" }
$matrixB = Get-Content -Raw (Join-Path $resB 'd02-matrix.json') | ConvertFrom-Json
if ($matrixB.ran -or -not $matrixB.blocker) { $fail += 'B: expected ran=false with blocker text' }
if (-not (Test-Path (Join-Path $resB 'wbd-d01-baseline.json'))) { $fail += 'B: D-01 baseline must still complete' }

# ---- Scenario C: sidecars missing -> upstream blocker, matrix runs ------
$mxcC = Join-Path $mockRoot 'mxcC'
New-FakeMxcRepo -Path $mxcC -WithCommonPs1
$resC = Join-Path $mockRoot 'resultsC'
$exitC = Invoke-Capture -MxcRoot $mxcC -ResultsDir $resC
if ($exitC -ne 0) { $fail += "C: expected exit 0, got $exitC" }
$d02logC = Get-Content -Raw (Join-Path $resC 'd02-upstream-probes.log')
if ($d02logC -notmatch 'sidecar build failed|cargo not on PATH') { $fail += "C: expected sidecar blocker, got: $d02logC" }
$matrixC = Get-Content -Raw (Join-Path $resC 'd02-matrix.json') | ConvertFrom-Json
if (-not $matrixC.ran) { $fail += 'C: matrix must still run when only sidecars are missing' }

if ($fail.Count) {
    Write-Host "MOCK FAILED ($($fail.Count)):" -ForegroundColor Red
    $fail | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
    exit 1
}
Write-Host "MOCK PASSED (matrix scenarios A+B+C; mock root: $mockRoot)" -ForegroundColor Green
exit 0
```

- [ ] **Step 2: Run the mock — expect FAIL**

Run: `pwsh -NoProfile -ExecutionPolicy Bypass -File "C:\Users\marku\AppData\Local\Temp\opencode\wbd-mock\run-mock.ps1"`
Expected: `MOCK FAILED` — scenario A fails with missing flat artifacts / `matrix ran=false` (the matrix section does not exist yet; B may pass trivially). This proves the mock exercises new behavior.

---

### Task 2: Implement the D-02 matrix section

**Files:**
- Modify: `tests/vm/wbd-d01-d02-probes.ps1` (new section after the upstream-test section; baseline serialization moved below it; header docs + notes updated)

- [ ] **Step 1: Update the header `.DESCRIPTION`**

Append to the D-02 starter paragraph:

```
  D-02 matrix (second addition): the five WBD request shapes as
  COMPLETE requests, generated with the upstream New-Config helper
  (dot-sourced from the pinned tree - schema-exact by construction;
  each generated config is copied to a flat d02-config-<shape>.json
  artifact because the harness fetches only top-level files), probed
  read-only via --probe --config (no workload launch; the commandLine
  is never executed). Filesystem splits into rw/ro/denied like the
  upstream suite (ro is new evidence); proxy splits into identity-less
  and identity-scoped model-2 variants. Common.ps1 absent or unloadable
  at a future pin is a recorded blocker, never a capture error.
```

- [ ] **Step 2: Update the baseline notes** — in the D-01 section's `notes = @(...)` block (~line 193), add one entry as the last array element:

```powershell
            'D-02 matrix: per-shape probe outputs are d02-matrix-<shape>.probe.json, request configs are d02-config-<shape>.json, summary in d02-matrix.json.'
```

- [ ] **Step 3: Move the baseline serialization below the matrix section**

In the D-01 section, replace the two lines

```powershell
    $baselinePath = Join-Path $ResultsDir 'wbd-d01-baseline.json'
    $baseline | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $baselinePath -Encoding utf8
```

with just

```powershell
    $baselinePath = Join-Path $ResultsDir 'wbd-d01-baseline.json'
```

and delete the `Write-Host "[wbd-capture] D-01 baseline:        $baselinePath"` line (both reappear in Step 5, immediately after the baseline write, so the print stays adjacent to the write).

- [ ] **Step 4: Insert the matrix section** after the upstream-probes `if/else` block, before the manifest section:

```powershell
    # ---------------------------------------------------------------------
    # D-02 matrix: the five WBD request shapes as complete requests.
    # Configs come from the upstream New-Config helper (dot-sourced from
    # the pinned tree) so a config-authoring bug on our side cannot
    # masquerade as a policy verdict. New-Config writes into
    # $ScratchRoot\configs (upstream layout); each config is COPIED to a
    # flat d02-config-<shape>.json artifact because the harness fetches
    # only top-level files (Invoke-TestsInVM.ps1 enumerates without
    # -Recurse), and the manifest hashes flat files. Probing is
    # read-only: --probe --config never launches the commandLine.
    # Common.ps1 absent or unloadable at a future pin is a recorded
    # blocker (layout-drift pattern), never a capture error.
    # ---------------------------------------------------------------------
    $commonPs1 = Join-Path $MxcRoot 'tests\scripts\lib\WinProcessContainer.Common.ps1'
    $matrixRan = $false
    $matrixBlocker = $null
    $matrixRows = @()
    if (-not (Test-Path -LiteralPath $commonPs1)) {
        $matrixBlocker = "upstream Common.ps1 missing at $commonPs1 - New-Config generator unavailable (D-02 matrix blocker)."
    } else {
        try {
            . $commonPs1
            # New-Config Out-Files into $ScratchRoot\configs and reads
            # $Script:SchemaVersion ('1.0.0', set at dot-source time).
            # Scratch lives in the guest TEMP (the VM is destroyed after
            # the run); only the flat copies below are fetched evidence.
            $ScratchRoot = Join-Path $env:TEMP 'mxc-sbx-d02-matrix'
            New-Item -ItemType Directory -Path (Join-Path $ScratchRoot 'configs') -Force | Out-Null
            foreach ($sub in 'rw', 'ro', 'denied') {
                New-Item -ItemType Directory -Path (Join-Path $ScratchRoot $sub) -Force | Out-Null
            }
            $fsRw = Join-Path $ScratchRoot 'rw'
            $fsRo = Join-Path $ScratchRoot 'ro'
            $fsDenied = Join-Path $ScratchRoot 'denied'
            # Loopback URL never dialed: probe mode does not launch the
            # workload. Port is arbitrary; the proxy shapes assert tier
            # resolution, not reachability.
            $proxyUrl = 'http://127.0.0.1:18080'
            # Planned-R1 UI request: maximal restriction (values verified
            # from the pinned tree's ui_policy_matrix area, 2026-10-14).
            # Model-2 proxy shapes per the pinned tree's network_proxy
            # area: egress deny + ingress allow required; identity-less
            # adds hostLoopback=allow, identity-scoped adds the peer with
            # hostLoopback=deny.
            $matrixRows = foreach ($shape in 'empty', 'fs-rw', 'fs-ro', 'fs-denied',
                                             'ui', 'deny-all-network',
                                             'proxy-identityless', 'proxy-identity-scoped') {
                $row = [ordered]@{ shape = $shape; error = $null }
                try {
                    $configPath = switch ($shape) {
                        'empty'                  { New-Config -Name "d02-$shape" -CommandLine 'cmd /c exit 0' }
                        'fs-rw'                  { New-Config -Name "d02-$shape" -CommandLine 'cmd /c exit 0' -ReadWrite @($fsRw) }
                        'fs-ro'                  { New-Config -Name "d02-$shape" -CommandLine 'cmd /c exit 0' -ReadOnly @($fsRo) }
                        'fs-denied'              { New-Config -Name "d02-$shape" -CommandLine 'cmd /c exit 0' -Denied @($fsDenied) }
                        'ui'                     { New-Config -Name "d02-$shape" -CommandLine 'cmd /c exit 0' -UiDisable $true -Clipboard 'none' -Injection $false -BpUiIsolation 'container' -BpUiDesktopControl $false -BpUiSystemSettings 'none' -BpUiIme $false }
                        'deny-all-network'       { New-Config -Name "d02-$shape" -CommandLine 'cmd /c exit 0' -EgressDefault 'deny' -IngressDefault 'deny' }
                        'proxy-identityless'     { New-Config -Name "d02-$shape" -CommandLine 'cmd /c exit 0' -EgressDefault 'deny' -IngressDefault 'allow' -HostLoopback 'allow' -NetworkProxy $proxyUrl }
                        'proxy-identity-scoped'  { New-Config -Name "d02-$shape" -CommandLine 'cmd /c exit 0' -EgressDefault 'deny' -IngressDefault 'allow' -HostLoopback 'deny' -NetworkProxy $proxyUrl -AllowedProxyPeer 'Contoso.Proxy_8wekyb3d8bbwe' }
                    }
                    $configArtifact = Join-Path $ResultsDir "d02-config-$shape.json"
                    Copy-Item -LiteralPath $configPath -Destination $configArtifact -Force
                    $probeOut = & $wxcExec --probe --config $configPath 2>&1
                    $probeCode = $LASTEXITCODE
                    # Set-Content -Value (parameter), never the pipeline -
                    # empty output must still produce the verbatim artifact.
                    $probeText = (@($probeOut) | ForEach-Object { [string]$_ }) -join [Environment]::NewLine
                    Set-Content -LiteralPath (Join-Path $ResultsDir "d02-matrix-$shape.probe.json") -Value $probeText -Encoding utf8
                    $row['configArtifact'] = "d02-config-$shape.json"
                    $row['configSha256'] = (Get-FileHash -LiteralPath $configArtifact -Algorithm SHA256).Hash
                    $row['exit'] = $probeCode
                    $row['tier'] = $null
                    $row['needsDaclAugmentation'] = $null
                    $row['probeError'] = $null
                    try {
                        $parsed = $probeText | ConvertFrom-Json -ErrorAction Stop
                        if ($parsed.PSObject.Properties['tier']) { $row['tier'] = [string]$parsed.tier }
                        if ($parsed.PSObject.Properties['needsDaclAugmentation']) { $row['needsDaclAugmentation'] = [bool]$parsed.needsDaclAugmentation }
                        if ($parsed.PSObject.Properties['error']) { $row['probeError'] = [string]$parsed.error }
                    } catch {
                        $row['probeError'] = 'unparseable probe output (recorded verbatim alongside)'
                    }
                    if ($probeCode -ne 0 -and -not $row['probeError']) { $row['probeError'] = "probe exit $probeCode" }
                } catch {
                    $row['error'] = "$($_.Exception.Message)"
                }
                $row
            }
            $matrixRan = $true
        } catch {
            $matrixBlocker = "dot-sourcing upstream Common.ps1 failed: $($_.Exception.Message)"
        }
    }
    $baseline['d02Matrix'] = [ordered]@{
        ran             = $matrixRan
        blocker         = $matrixBlocker
        shapes          = @($matrixRows)
        summaryArtifact = 'd02-matrix.json'
    }
    if ($matrixRan) {
        Write-Host ("[wbd-capture] D-02 matrix: {0} shapes probed (flat artifacts d02-matrix-<shape>.probe.json)." -f @($matrixRows).Count)
    } else {
        Write-Host "[wbd-capture] D-02 matrix: $matrixBlocker (recorded)" -ForegroundColor Yellow
    }
```

- [ ] **Step 5: Write the summary + serialize the baseline** — immediately after the section above, before the manifest section:

```powershell
    [ordered]@{
        schema  = 1
        ran     = $matrixRan
        blocker = $matrixBlocker
        shapes  = @($matrixRows)
    } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $ResultsDir 'd02-matrix.json') -Encoding utf8
    $baseline | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $baselinePath -Encoding utf8
    Write-Host "[wbd-capture] D-01 baseline:        $baselinePath"
```

Note: `$baseline | ConvertTo-Json` moves from `-Depth 5` to `-Depth 6` (the nested `d02Matrix.shapes` rows need one more level).

- [ ] **Step 6: Parser check**

Run:
```powershell
$errs = $null; $null = [System.Management.Automation.Language.Parser]::ParseFile("C:\Users\marku\tools\sandbox\tests\vm\wbd-d01-d02-probes.ps1", [ref]$null, [ref]$errs); if ($errs.Count) { $errs | ForEach-Object { "$($_.Message) @ line $($_.Extent.StartLineNumber)" } } else { 'parse OK' }
```
Expected: `parse OK`

---

### Task 3: Run the mock — expect PASS

- [ ] **Step 1: Run**

Run: `pwsh -NoProfile -ExecutionPolicy Bypass -File "C:\Users\marku\AppData\Local\Temp\opencode\wbd-mock\run-mock.ps1"`
Expected: `MOCK PASSED (matrix scenarios A+B+C; mock root: ...)`.

- [ ] **Step 2: Clean up the mock root**

Run: `Remove-Item -Path (Join-Path $env:TEMP 'opencode\wbd-mock*') -Recurse -Force -ErrorAction SilentlyContinue`
(Note: `-Path`, not `-LiteralPath` — a literal path treats the `*` as a character and the cleanup would be a silent no-op.)
Expected: no output.

- [ ] **Step 3: Commit**

```powershell
git add tests/vm/wbd-d01-d02-probes.ps1
git commit -m "test(vm): D-02 matrix section - five WBD shapes as complete requests, upstream New-Config generated, probed read-only. 8 shapes (empty, fs-rw, fs-ro, fs-denied, ui, deny-all-network, proxy-identityless, proxy-identity-scoped); configs generated by the dot-sourced upstream New-Config (schema-exact) and copied to flat d02-config-<shape>.json artifacts because the harness fetch is flat; probe outputs d02-matrix-<shape>.probe.json + summary d02-matrix.json; Common.ps1 absence/unload = recorded blocker; baseline gains d02Matrix block (serialization moved below the matrix section, depth 6); mock-verified A+B+C (happy, Common-missing blocker, sidecar-missing blocker)."
```

---

### Task 4: In-VM capture run (USER-DRIVEN, elevated pwsh)

- [ ] **Step 1: Run the capture lane** (maintainer, from `C:\Users\marku\tools\sandbox`):

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File tests\vm\Invoke-TestsInVM.ps1 -Image sbx-base-b -TestCmd "pwsh -NoProfile -ExecutionPolicy Bypass -File C:\sbx-repo\tests\vm\wbd-d01-d02-probes.ps1"
```

Expected: `VM HARNESS: PASS`, `WBD CAPTURE: DONE`, 17 new flat artifacts (8 `d02-matrix-<shape>.probe.json`, 8 `d02-config-<shape>.json`, `d02-matrix.json`) plus the updated `wbd-d01-baseline.json` — 18 new/updated manifest entries total, alongside the previous runs' unchanged artifacts (baseline logs, upstream suite results, context json, sidecar log, manifest).

- [ ] **Step 2: Paste the run summary back** to the assistant.

---

### Task 5: Verify the fetched evidence

**Files:**
- Read: `tests/vm/results/<new-runid>/d02-matrix.json`, `d02-matrix-*.probe.json`, `d02-config-*.json`, `wbd-d01-baseline.json`, `capture-manifest.json`

- [ ] **Step 1: Cross-check** every matrix row against its probe artifact (exit code, tier, error) and against the manifest hashes (18 new/updated entries must appear in `capture-manifest.json`); every `d02-config-<shape>.json` parses as JSON and matches the expected shape keys; `pinMatches` still true; no shape silently missing.
- [ ] **Step 2: Record per-shape verdicts** (the raw input to Task 7's verdict table) — including any rejected shape, which is a legitimate **blocked** row (acceptance criterion 3), most plausibly `proxy-identityless` if the `hostLoopback` ingress support bit gates it.

---

### Task 6: Source-verified PSEC mapping evidence (at the pin)

- [ ] **Step 1: Locate the source files** — fetch the repo tree at the pin:
  `https://api.github.com/repos/microsoft/mxc/git/trees/5d7a475a9fd5626bafb55c2c857989d2e5621245?recursive=1`
  Identify paths for: `fallback_detector.rs`, `base_container_helpers.rs`, `base_container_runner.rs`, `secenv.rs`, `network_policy_helpers.rs` (and the ui-capability source, likely `ui_policy.rs`).
- [ ] **Step 2: Fetch each file** at `https://raw.githubusercontent.com/microsoft/mxc/5d7a475a9fd5626bafb55c2c857989d2e5621245/<path>`.
- [ ] **Step 3: Extract, per probe boolean** — the surface is **21 booleans** (11 top-level in `probes`: baseContainerApiPresent, nativeCaptureAvailable, guardedCaptureAvailable, bfscfgPresent, bfsCompiledIn, baseContainerSupportsDenyPaths, baseContainerSupportsEnumeratePaths, baseContainerSupportsIngressHostLoopbackAllow, baseContainerSupportsIdentitylessLoopbackProxy, isolationSessionAvailable, hyperlightAvailable; plus the 10 `uiCapabilities.canBlock*` bits): for each, record the originating API/probe call, the PSEC contract version it depends on (1.0 / 1.1), and the support-bit constant (e.g. `PSE_SUPPORT_FS_DENY`), with exact file:line references. Where a boolean's origin is NOT observable in source, it becomes an enhanced-diagnostics upstream blocker (acceptance criterion 4) — never an inference.

---

### Task 7: Write `docs/wbd-d02-capability-matrix.md`

**Files:**
- Create: `docs/wbd-d02-capability-matrix.md`

- [ ] **Step 1: Write the document** with the four sections from the spec: provenance header (pin, template SHA256 `95DAEA358027DF148620B71E247BD316632E83467E2E7A976317F4BBE202F5BE`, canonical run id, manifest reference); verdict table (8 rows — shape, resolved tier, needsDaclAugmentation, exit, blocked/unblocked marking with artifact citation per cell); capability-boolean → PSEC-contract mapping (Task 6 findings, with upstream blockers for the known-false bits: `baseContainerSupportsEnumeratePaths=false`, `baseContainerSupportsIngressHostLoopbackAllow=false`); acceptance-criteria checklist (each of the 4 D-02 criteria → the artifacts that prove it or the recorded blocker). Every claim cites a fetched artifact.
- [ ] **Step 2: Cross-check** every table cell against the fetched artifacts one final time.

---

### Task 8: Companion updates + final commit

**Files:**
- Modify: `docs/mxc-source-analysis.md` (update note), `docs/superpowers/plans/2026-10-04-vm-test-infrastructure.md` (annotation), possibly `tests/vm/BUILD-BASE-IMAGE.md` (capture-lane description)

- [ ] **Step 1: mxc-source-analysis.md update note** — record that the capability-boolean → PSEC mapping was re-verified at `5d7a475a` (the matrix doc carries the line refs; the drift caveat for §2.1 refs is partially resolved — note which refs were refreshed and which still key to `e7940f7`).
- [ ] **Step 2: Plan annotation** — record the matrix capture run id + verdict-table headline (all-unblocked vs blocked rows) under the VM-01 Task 6 / WBD follow-up area.
- [ ] **Step 3: Commit**

```powershell
git add docs/wbd-d02-capability-matrix.md docs/mxc-source-analysis.md docs/superpowers/plans/2026-10-04-vm-test-infrastructure.md tests/vm/BUILD-BASE-IMAGE.md
git commit -m "docs(wbd): D-02 capability matrix - <verdict headline: which shapes resolve base-container, which are blocked and why>"
```

(If `BUILD-BASE-IMAGE.md` needed no edit after all, stage is harmless for an unchanged file.)

---

### Verification summary (whole plan)

- Mock: matrix scenarios A+B+C pass; parser clean; zero warnings.
- In-VM: one capture lane run, `VM HARNESS: PASS`, 17 flat artifacts manifest-hashed.
- Matrix doc: every cell artifact-cited; blocked rows carry evidence, never inference; acceptance criteria each mapped.

---

## Post-review hardening (2026-10-14)

The code-quality review of the Task 1-3 implementation (commit f44ea5c)
returned FIX_FIRST; these deltas were applied on top and the mock
(scenarios A+B+C) re-run PASS:

1. **Early baseline write restored** (Step 3 regression): the baseline is
   now written twice - once immediately after `$baselinePath` is
   assigned (pre-D-02 durability, `-Depth 5`, the original behavior),
   and once at the end with the `d02Matrix` block attached. Without
   this, a hung or killed D-02 step would lose all D-01 evidence.
2. **Per-shape probe hang guard**: `--probe --config` now runs in a
   `Start-Job` with `Wait-Job -Timeout 120`; on timeout the job is
   killed, the row records `probe timed out after 120s`, and the run
   continues. Rationale: the harness has no timeout on the guest
   command, and 4 of the 8 shapes are config inputs the pinned binary
   has never been probed with in-VM. The output join moved INSIDE the
   job so only strings and the exit code cross deserialization.
3. **`Set-Content -Value` convention** applied to the two Step 5
   serializations (the plan's own code piped into Set-Content).
4. **Uniform row schema**: all eight row keys pre-initialized to `$null`
   (early-failure rows previously carried only shape + error).
5. **`errorCount`** added to `d02-matrix.json` and the baseline's
   `d02Matrix` block (a run where all shapes fail previously read as
   `ran=true, blocker=null`).
6. **Dot-source hazard note** next to `. $commonPs1` (future pins could
   shadow script-scope variables; verified safe at pin 5d7a475a).

Follow-up (same day): the re-review of the hardening commit caught that
delta 2's timeout branch called `Stop-Job -Force` — `Stop-Job` has no
`-Force` parameter (runtime-verified), so the branch would have thrown
into the per-shape catch instead of recording the timeout. Fixed to
`Stop-Job -Job $probeJob`; `Remove-Job -Force` carries the force. The
mock could not catch this (where.exe never hangs); behavioral timeout
coverage remains static-analysis-verified only.

Advisories NOT taken (with rationale):
- Renaming `d02-matrix-<shape>.probe.json` to `.probe.log` (verbatim
  output may be unparseable): the artifact name is spec'd in the
  approved plan, header, and notes; the Task 5-8 doc generator already
  treats these as verbatim captures. Renaming has high ripple for a
  cosmetic concern.
- Splatting the 8 duplicated `New-Config` common parameters: the
  per-shape one-liners are deliberately explicit evidence (each
  shape's exact request visible at a glance).
