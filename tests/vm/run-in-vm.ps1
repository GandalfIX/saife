#Requires -Version 7
<#
.SYNOPSIS
  Guest-side build + test entry point for the disposable-VM test
  infrastructure (VM-01 Task 4).
.DESCRIPTION
  Runs INSIDE the test VM. Normally invoked via PowerShell Direct by the
  host-side tests\vm\Invoke-TestsInVM.ps1; can also be invoked manually
  (e.g. inside the builder VM) for a smoke test.

  Phases:
    unit        -> cargo build --release, then cargo test --release
                   (both carry --features mxc-backend when -Backend mxc, so the
                   feature build is never clobbered by a feature-less test build)
    integration -> cargo build --release (sandbox.exe), then a child
                   pwsh -NoProfile -ExecutionPolicy Bypass -Command
                   "& <RepoDir>\tests\run-tests.ps1 -Only <ids>"
                   (-Only passthrough; run-tests.ps1 only ever exits
                   0 or 1, and both propagate faithfully through
                   -Command. pwsh -File is NOT used because -File cannot
                   pass an [int[]] parameter - see the note at the
                   integration step.)
    all         -> build once, then unit, then integration

  Every step tees ALL of its output streams to a per-step log under
  -ResultsDir while also streaming to the caller's console. summary.json
  (schema 1) is emitted LAST and is written best-effort even when steps
  fail. Unknown numbers are null in the summary.

  summary.json carries `backend` and `lane` so the host-side harness (and the
  controller reading tests\vm\results\<runid>\summary.json) can tell an
  ADMIN lane run from a STANDARD-USER lane run without inferring it from the
  numbers. The standard-user lane exists because the guest's admin lane can
  never falsify an "egress works unelevated" claim: every session it starts is
  elevated. See Invoke-TestsInVM.ps1 -AsStandardUser and
  tests\vm\standard-user-run.ps1.

  Exit codes:
    0  = every requested step exited 0        (final line: VM RUN: PASS)
    1  = at least one requested step failed,
         or was skipped because the build failed (final line: VM RUN: FAIL)
    99 = unexpected error                     (final line: VM RUN: FAIL)

.PARAMETER Phase
  Which phase(s) to run: unit, integration, or all. Mandatory.
.PARAMETER Only
  Scenario numbers passed through to tests\run-tests.ps1 (integration
  phase only; ignored for the unit phase). NOTE (pwsh platform quirk,
  verified 2026-10-05): because -Only is [int[]], multi-value lists bind
  correctly only when PowerShell itself parses them - invoke this script
  in-process (`& ...run-in-vm.ps1 -Phase integration -Only 1,2,6`) or via
  `pwsh -Command`. When invoked via `pwsh -File`, a comma token like
  "1,2,6" binds as a single culture-parsed int (126); via -File only a
  single scenario id can be passed reliably.
.PARAMETER Backend
  Containment backend passed through to tests\run-tests.ps1 as -Backend:
  appcontainer (default) or mxc. mxc builds with --features mxc-backend (the
  binary refuses --backend mxc without it, and mxc-launch.exe is
  feature-gated in Cargo.toml).
.PARAMETER Lane
  Which lane this run represents: admin (default) or standard-user. It is
  recorded in summary.json and in the log header ONLY - it changes no
  behaviour here, because the guest-side launcher that runs as the standard
  user is the host harness's job (Start-Process -Credential). Labelling is not
  cosmetic: a lane whose numbers cannot be attributed to a token is not
  evidence.
.PARAMETER RepoDir
  Repo root. Defaults to the repo containing this script ($PSScriptRoot\..\..),
  NOT C:\sbx-repo, so manual smoke runs from other locations work.
.PARAMETER ResultsDir
  Directory for logs + summary.json. Created if missing.
  Default: C:\sbx-results.
.EXAMPLE
  pwsh -NoProfile -ExecutionPolicy Bypass -File tests\vm\run-in-vm.ps1 -Phase all
.EXAMPLE
  pwsh -NoProfile -ExecutionPolicy Bypass -File tests\vm\run-in-vm.ps1 -Phase integration -Only 1,2,6
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('unit', 'integration', 'all')]
    [string]$Phase,

    [int[]]$Only,

    [string]$RepoDir,

    [string]$ResultsDir = 'C:\sbx-results',

    [ValidateSet('appcontainer', 'mxc')]
    [string]$Backend = 'appcontainer',

    [ValidateSet('admin', 'standard-user')]
    [string]$Lane = 'admin'
)

$ErrorActionPreference = 'Stop'

# Summary state (schema 1). Every field starts unknown ($null) so the
# summary can always be written; fields fill in as steps run.
$script:Summary = [ordered]@{
    schema      = 1
    started     = (Get-Date).ToString('o')
    finished    = $null
    osBuild     = $null
    osEdition   = $null
    repoDir     = $null
    phase       = $Phase
    # Attribution, not decoration: which backend ran, and which lane (which
    # token) produced the numbers. Both are read back by
    # Invoke-TestsInVM.ps1's verdict block.
    backend     = $Backend
    lane        = $Lane
    build       = @{ ok = $null; exit = $null }
    unit        = @{ requested = $false; exit = $null; log = 'unit.log' }
    integration = @{ requested = $false; exit = $null; total = $null; pass = $null
                     fail = $null; skip = $null; verdict = $null; log = 'integration.log' }
    # Advertise only artifacts that can exist: build.log + summary.json always,
    # plus unit.log/integration.log when their phase was requested (filled in
    # below once the phase flags are known).
    artifacts   = @('build.log', 'summary.json')
}
# 99 (unexpected) until the run proves otherwise; the try block sets 0/1.
$script:RunExit = 99
$script:ResultsRoot = $null

try {
    # -----------------------------------------------------------------------
    # Directories.
    # -----------------------------------------------------------------------
    if (-not $RepoDir) { $RepoDir = Join-Path $PSScriptRoot '..\..' }
    $RepoDir = [System.IO.Path]::GetFullPath($RepoDir)
    if (-not (Test-Path -LiteralPath $RepoDir)) {
        throw "repo dir not found: $RepoDir"
    }
    $script:Summary.repoDir = $RepoDir

    if (-not (Test-Path -LiteralPath $ResultsDir)) {
        New-Item -ItemType Directory -Path $ResultsDir -Force | Out-Null
    }
    $script:ResultsRoot = [System.IO.Path]::GetFullPath($ResultsDir)
    $buildLog = Join-Path $script:ResultsRoot 'build.log'
    $unitLog = Join-Path $script:ResultsRoot 'unit.log'
    $integrationLog = Join-Path $script:ResultsRoot 'integration.log'
    $metricsLog = Join-Path $script:ResultsRoot 'guest-metrics.log'

    # Stale logs from an earlier manual run would corrupt parsing - remove
    # best-effort; each step re-creates its log.
    foreach ($stale in @($buildLog, $unitLog, $integrationLog, $metricsLog)) {
        Remove-Item -LiteralPath $stale -Force -ErrorAction SilentlyContinue
    }

    Write-Host ("[vm-guest] phase={0} lane={1} backend={2} repo={3} results={4}" -f $Phase, $Lane, $Backend, $RepoDir, $script:ResultsRoot)
    Write-Host ("[vm-guest] summary will record lane={0} backend={1}" -f $Lane, $Backend)

    # -----------------------------------------------------------------------
    # OS info for the summary (null on failure - never fatal).
    # -----------------------------------------------------------------------
    try {
        $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
        $script:Summary.osBuild = $osInfo.BuildNumber
        $script:Summary.osEdition = $osInfo.Caption
    } catch {
        Write-Host "[vm-guest] WARNING: could not query OS info: $($_.Exception.Message)" -ForegroundColor Yellow
    }

    $wantUnit = ($Phase -eq 'unit') -or ($Phase -eq 'all')
    $wantIntegration = ($Phase -eq 'integration') -or ($Phase -eq 'all')
    $script:Summary.unit.requested = $wantUnit
    $script:Summary.integration.requested = $wantIntegration
    # Dynamic artifacts: only logs for phases that were actually requested.
    $script:Summary.artifacts = @('build.log')
    if ($wantUnit) { $script:Summary.artifacts += 'unit.log' }
    if ($wantIntegration) { $script:Summary.artifacts += 'integration.log' }
    if ($wantIntegration) { $script:Summary.artifacts += 'guest-metrics.log' }
    $script:Summary.artifacts += 'summary.json'
    if ($Only -and -not $wantIntegration) {
        Write-Host "[vm-guest] NOTE: -Only applies to the integration phase only; ignoring it for phase '$Phase'." -ForegroundColor Yellow
    }

    # -----------------------------------------------------------------------
    # Build (runs in every phase; integration needs sandbox.exe, unit needs
    # the compiled test binary).
    # -----------------------------------------------------------------------
    # --backend mxc needs BOTH the `mxc-backend` feature (src/cli.rs refuses the
    # flag otherwise) and the feature-gated mxc-launch.exe, so the build and the
    # unit-test build carry the SAME feature set: `cargo test --release` builds
    # the bin target too, and a feature-less unit build would silently clobber
    # the binary the integration phase then runs.
    $featureArgs = @()
    if ($Backend -eq 'mxc') { $featureArgs = @('--features', 'mxc-backend') }
    Write-Host ('[vm-guest] step: cargo build --release {0}' -f ($featureArgs -join ' '))
    Push-Location -LiteralPath $RepoDir
    try {
        & cargo build --release @featureArgs 2>&1 | Tee-Object -FilePath $buildLog
        $buildExit = $LASTEXITCODE
    } finally { Pop-Location }
    $script:Summary.build.exit = $buildExit
    $script:Summary.build.ok = ($buildExit -eq 0)

    $anyFailed = ($buildExit -ne 0)
    if ($buildExit -ne 0) {
        Write-Host "[vm-guest] build failed (exit $buildExit); skipping unit/integration phases." -ForegroundColor Red
    }

    # -----------------------------------------------------------------------
    # Unit phase: cargo test --release.
    # -----------------------------------------------------------------------
    if (($buildExit -eq 0) -and $wantUnit) {
        Write-Host ('[vm-guest] step: cargo test --release {0}' -f ($featureArgs -join ' '))
        Push-Location -LiteralPath $RepoDir
        try {
            & cargo test --release @featureArgs 2>&1 | Tee-Object -FilePath $unitLog
            $unitExit = $LASTEXITCODE
        } finally { Pop-Location }
        $script:Summary.unit.exit = $unitExit
        if ($unitExit -ne 0) {
            $anyFailed = $true
            Write-Host "[vm-guest] unit tests failed (exit $unitExit)." -ForegroundColor Red
        } else {
            Write-Host '[vm-guest] unit tests passed.' -ForegroundColor Green
        }
    }

    # -----------------------------------------------------------------------
    # Integration phase: tests\run-tests.ps1 in a child pwsh (its exit code
    # is 0/1; it manages its own scratch working directory).
    # -----------------------------------------------------------------------
    if (($buildExit -eq 0) -and $wantIntegration) {
        $runTestsPath = Join-Path $RepoDir 'tests\run-tests.ps1'
        if (-not (Test-Path -LiteralPath $runTestsPath)) {
            throw "integration suite not found: $runTestsPath"
        }
        # NOTE: pwsh -Command instead of pwsh -File. Verified 2026-10-05:
        # -File cannot pass the [int[]] -Only parameter (the token "1,2,6"
        # binds as a single culture-parsed int, e.g. 126 - silently running
        # the wrong scenarios), while -Command parses "1,2,6" as a PowerShell
        # array literal and binds [int[]] correctly. run-tests.ps1 only ever
        # exits 0 or 1 (its contract), and both propagate faithfully through
        # -Command.
        $escapedPath = $runTestsPath -replace "'", "''"
        $childCommand = "& '$escapedPath' -Backend '$Backend'"
        if ($Only) { $childCommand += (' -Only ' + ($Only -join ',')) }
        $rtArgs = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', $childCommand)
        # Per-scenario metrics go to a guest file (not just the streamed
        # output) so they survive a PS-Direct session-host death - the
        # 20261011-004018 run's mid-suite collapse was invisible to the
        # stream because the host died at S-54. run-tests.ps1 appends one
        # line per scenario; fetched with the other artifacts.
        $env:SBX_GUEST_METRICS = $metricsLog
        Write-Host ("[vm-guest] step: pwsh {0} {1}" -f ($rtArgs[0..3] -join ' '), $childCommand)
        & pwsh @rtArgs 2>&1 | Tee-Object -FilePath $integrationLog
        $integrationExit = $LASTEXITCODE
        $script:Summary.integration.exit = $integrationExit
        if ($integrationExit -ne 0) {
            $anyFailed = $true
            Write-Host "[vm-guest] integration suite failed (exit $integrationExit)." -ForegroundColor Red
        }

        # Parse 'Summary: total=N pass=N fail=N skip=N' and the
        # 'SANDBOX: <verdict>' line from integration.log (tolerant of the
        # '(python scenarios skipped)' / '(gate test S-6 failed)' suffixes).
        # Last match wins; nulls when absent.
        $total = $null; $passedCount = $null; $failedCount = $null
        $skippedCount = $null; $verdict = $null
        foreach ($line in (Get-Content -LiteralPath $integrationLog)) {
            if ($line -match '^\s*Summary:\s*total=(\d+)\s+pass=(\d+)\s+fail=(\d+)\s+skip=(\d+)') {
                $total = [int]$Matches[1]
                $passedCount = [int]$Matches[2]
                $failedCount = [int]$Matches[3]
                $skippedCount = [int]$Matches[4]
            } elseif ($line -match '^\s*(SANDBOX: (?:PASS|FAIL).*)$') {
                $verdict = $Matches[1].Trim()
            }
        }
        $script:Summary.integration.total = $total
        $script:Summary.integration.pass = $passedCount
        $script:Summary.integration.fail = $failedCount
        $script:Summary.integration.skip = $skippedCount
        $script:Summary.integration.verdict = $verdict
        if ($verdict) {
            Write-Host "[vm-guest] integration verdict: $verdict"
        } else {
            Write-Host '[vm-guest] WARNING: no SANDBOX: verdict line found in integration.log.' -ForegroundColor Yellow
        }
    }

    $script:RunExit = 1
    if (-not $anyFailed) { $script:RunExit = 0 }
} catch {
    Write-Host "[vm-guest] unexpected error: $($_.Exception.Message)" -ForegroundColor Red
    $script:RunExit = 99
}

# ---------------------------------------------------------------------------
# summary.json - always written, best effort, LAST artifact.
# ---------------------------------------------------------------------------
$script:Summary.finished = (Get-Date).ToString('o')
$summaryDir = $script:ResultsRoot
if (-not $summaryDir) { $summaryDir = $ResultsDir }
try {
    if (-not (Test-Path -LiteralPath $summaryDir)) {
        New-Item -ItemType Directory -Path $summaryDir -Force | Out-Null
    }
    $summaryPath = Join-Path $summaryDir 'summary.json'
    ConvertTo-Json -InputObject $script:Summary -Depth 5 |
        Set-Content -LiteralPath $summaryPath -Encoding utf8
    Write-Host "[vm-guest] summary written: $summaryPath"
} catch {
    Write-Host "[vm-guest] WARNING: could not write summary.json: $($_.Exception.Message)" -ForegroundColor Yellow
}

if ($script:RunExit -eq 0) {
    Write-Host 'VM RUN: PASS' -ForegroundColor Green
} else {
    Write-Host 'VM RUN: FAIL' -ForegroundColor Red
}
exit $script:RunExit
