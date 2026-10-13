#Requires -Version 7
<#
.SYNOPSIS
  WBD D-01 (+ D-02 starter) probe capture inside a disposable VM.
.DESCRIPTION
  Runs INSIDE the image-B VM via the harness' -TestCmd lane
  (Invoke-TestsInVM.ps1 -Image sbx-base-b -TestCmd "pwsh -NoProfile
  -File C:\sbx-repo\tests\vm\wbd-d01-d02-probes.ps1") or manually in any
  clone. Writes every evidence artifact into C:\sbx-results (the -TestCmd
  contract: the harness fetches ALL files there into
  tests\vm\results\<runid>\ and destroys the VM afterwards).

  D-01 deliverable (WBD): a machine-readable, sanitized host-baseline
  report containing Windows edition/build, architecture, relevant
  optional features, MXC commit/version, wxc-exec.exe hash/version,
  elevation state, and --probe output - captured WITHOUT launching a
  workload. Per the WBD, --probe may perform MXC stale-DACL recovery
  before capability detection; that is a security-state operation, so
  the raw output is retained verbatim for review and a flag records
  the possibility. A second run may only differ in timestamps/fields
  that change per boot.

  D-02 starter: the upstream probe test entry point
  (tests\scripts\run_processcontainer_probes_test.ps1 -RequireTier
  base-container) runs request-scoped probes; its output is captured
  verbatim with its exit code. Building the full D-02 capability matrix
  (empty/fs/UI/deny-all-network/proxy requests, blocked markings) is
  WBD-track analysis on top of this raw evidence - deliberately NOT
  done here (VM-01 Task 6: evidence capture only, no product code).

  This script NEVER runs wxc-host-prep and never launches a workload.

  Exit codes: 0 = capture complete (all sections); 3 = prerequisites
  missing (no C:\mxc checkout / no wxc-exec.exe - run prepare-mxc.ps1);
  99 = unexpected error. A failing --probe or upstream test is EVIDENCE,
  not a script failure: their exit codes are recorded in the artifacts.
.PARAMETER MxcRoot
  MXC checkout location (default C:\mxc, per VM-01 Task 6).
.PARAMETER ResultsDir
  Artifact directory (default C:\sbx-results, the -TestCmd contract).
.EXAMPLE
  pwsh -NoProfile -ExecutionPolicy Bypass -File C:\sbx-repo\tests\vm\wbd-d01-d02-probes.ps1
#>
[CmdletBinding()]
param(
    [string]$MxcRoot = 'C:\mxc',
    [string]$ResultsDir = 'C:\sbx-results'
)

$ErrorActionPreference = 'Stop'

try {
    New-Item -ItemType Directory -Path $ResultsDir -Force | Out-Null
    $capturedAt = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ssK')

    # ---------------------------------------------------------------------
    # Prerequisites: the pinned checkout and the release executor. The
    # probe capture is meaningless without them - fail loudly instead of
    # producing an empty report.
    # ---------------------------------------------------------------------
    if (-not (Test-Path -LiteralPath (Join-Path $MxcRoot '.git'))) {
        Write-Host "[wbd-capture] no MXC checkout at $MxcRoot - run tests\vm\prepare-mxc.ps1 first (see tests\vm\BUILD-BASE-IMAGE.md, image B)." -ForegroundColor Red
        exit 3
    }
    $wxcExec = Join-Path $MxcRoot 'src\target\release\wxc-exec.exe'
    if (-not (Test-Path -LiteralPath $wxcExec)) {
        Write-Host "[wbd-capture] no release wxc-exec.exe at $wxcExec - run tests\vm\prepare-mxc.ps1 first." -ForegroundColor Red
        exit 3
    }

    # ---------------------------------------------------------------------
    # D-01: host baseline (machine-readable + sanitized by construction -
    # only fixed, non-secret fields are selected; nothing from the user
    # profile or network config is collected).
    # ---------------------------------------------------------------------
    $os = Get-CimInstance Win32_OperatingSystem
    $windowsIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $windowsPrincipal = New-Object Security.Principal.WindowsPrincipal($windowsIdentity)
    $elevated = $windowsPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    # "Relevant optional features": the isolation-relevant subset only.
    # The query needs elevation (DISM); inside the -TestCmd lane the PS
    # Direct session is always admin, but a non-elevated manual run must
    # still produce a report - the query error is recorded instead.
    $features = @()
    $featuresError = $null
    try {
        $features = @(Get-WindowsOptionalFeature -Online -ErrorAction Stop |
            Where-Object { $_.FeatureName -match 'Containers|Hyper-V|Subsystem|VirtualMachinePlatform' } |
            ForEach-Object { [ordered]@{ feature = $_.FeatureName; state = [string]$_.State } })
    } catch {
        # The DISM cmdlet's COM class may be unregistered on experimental
        # builds ('Class not registered', run 20261013-142920-051). The
        # Win32_OptionalFeature WMI class reads the same store without
        # the DISM COM registration; when it also fails, the combined
        # error is recorded instead.
        $featuresError = $_.Exception.Message
        try {
            $features = @(Get-CimInstance -ClassName Win32_OptionalFeature -ErrorAction Stop |
                Where-Object { $_.Name -match 'Containers|Hyper-V|Subsystem|VirtualMachinePlatform' } |
                ForEach-Object { [ordered]@{
                    feature = $_.Name
                    state   = if ($_.InstallState -eq 1) { 'Enabled' } elseif ($_.InstallState -eq 2) { 'Disabled' } else { [string]$_.InstallState }
                } })
            if ($features.Count -gt 0) {
                $featuresError = "Get-WindowsOptionalFeature failed ($featuresError); Win32_OptionalFeature fallback used."
            }
        } catch {
            $featuresError = "Get-WindowsOptionalFeature failed ($featuresError); Win32_OptionalFeature fallback also failed ($($_.Exception.Message))."
        }
    }

    # The recorded upstream pin (docs/mxc-source-analysis.md), normalized
    # to its FULL SHA before any comparison: git always reports 40-char
    # SHAs, so comparing HEAD against the short literal fires a false
    # 'NOT the pin' warning on every valid run (observed in run
    # 20261013-142920-051; same bug family as the prepare-mxc.ps1
    # comparison incident fixed the same day).
    $pinnedCommit = 'e7940f7'
    Push-Location $MxcRoot
    $mxcCommit = (git rev-parse HEAD)
    $pinnedFull = (git rev-parse --verify "$pinnedCommit^{commit}" 2>$null)
    $mxcDirtyPaths = @(git status --porcelain)
    Pop-Location

    $wxcItem = Get-Item -LiteralPath $wxcExec
    $wxcHash = (Get-FileHash -LiteralPath $wxcExec -Algorithm SHA256).Hash

    # --probe: raw, verbatim, exit code recorded (may perform MXC stale-
    # DACL recovery before capability detection - the flag below records
    # that possibility for the reviewer; the raw log is the evidence).
    # NOTE: Set-Content -Value (parameter), never the pipeline: piping a
    # command's EMPTY output skips the cmdlet entirely and silently
    # produces no file, which would hollow out the verbatim-retention
    # acceptance criterion (observed in the local mock).
    $probeLog = Join-Path $ResultsDir 'd01-wxc-exec-probe.log'
    $probeOutput = & $wxcExec --probe 2>&1
    $probeExit = $LASTEXITCODE
    $probeText = (@($probeOutput) | ForEach-Object { [string]$_ }) -join [Environment]::NewLine
    Set-Content -LiteralPath $probeLog -Value $probeText -Encoding utf8

    $versionLog = Join-Path $ResultsDir 'd01-wxc-exec-version.log'
    $versionOutput = & $wxcExec --version 2>&1
    $versionExit = $LASTEXITCODE
    $versionText = (@($versionOutput) | ForEach-Object { [string]$_ }) -join [Environment]::NewLine
    Set-Content -LiteralPath $versionLog -Value $versionText -Encoding utf8

    $baseline = [ordered]@{
        schema               = 1
        capturedAt           = $capturedAt
        ticket               = 'WBD-D-01'
        os = [ordered]@{
            caption          = $os.Caption
            version          = $os.Version
            buildNumber      = $os.BuildNumber
            architecture     = $os.OSArchitecture
        }
        elevation            = [ordered]@{ elevated = $elevated; user = $windowsIdentity.Name }
        optionalFeatures     = $features
        optionalFeaturesError = $featuresError
        mxc = [ordered]@{
            root             = $MxcRoot
            commit           = $mxcCommit
            pinnedCommit     = $pinnedCommit
            pinMatches       = ($pinnedFull -eq $mxcCommit)
            dirtyPaths       = $mxcDirtyPaths.Count
            dirtyPathList    = @($mxcDirtyPaths | ForEach-Object { [string]$_ })
            wxcExecSha256    = $wxcHash
            wxcExecSizeBytes = $wxcItem.Length
            fileVersion      = $wxcItem.VersionInfo.FileVersion
            productVersion   = $wxcItem.VersionInfo.ProductVersion
            versionExit      = $versionExit
            probeExit        = $probeExit
            probeMayRecoverDacl = $true   # WBD D-01: --probe may run MXC stale-DACL recovery
        }
        notes = @(
            'Probe output retained verbatim in d01-wxc-exec-probe.log.',
            'No workload was launched; wxc-host-prep was never run.',
            'A second run may differ only in timestamps and per-boot fields.'
        )
    }
    $baselinePath = Join-Path $ResultsDir 'wbd-d01-baseline.json'
    $baseline | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $baselinePath -Encoding utf8
    Write-Host "[wbd-capture] D-01 baseline:        $baselinePath"
    Write-Host ("[wbd-capture] build {0} | mxc {1} | probe exit {2}" -f $os.BuildNumber, $mxcCommit.Substring(0, [Math]::Min(7, $mxcCommit.Length)), $probeExit)
    if ($pinnedFull -ne $mxcCommit) {
        Write-Host "[wbd-capture] WARNING: checked-out MXC commit $mxcCommit is NOT the recorded pin $pinnedCommit - evidence is still captured, but the pin decision must be revisited (docs/mxc-source-analysis.md)." -ForegroundColor Yellow
    }

    # ---------------------------------------------------------------------
    # D-02 starter: the upstream request-scoped probe test, verbatim.
    # Absence of the upstream entry point in the pinned tree is recorded
    # as evidence (upstream layout drift), not as a script error.
    # ---------------------------------------------------------------------
    $d02Log = Join-Path $ResultsDir 'd02-upstream-probes.log'
    $upstreamTest = Join-Path $MxcRoot 'tests\scripts\run_processcontainer_probes_test.ps1'
    if (Test-Path -LiteralPath $upstreamTest) {
        Write-Host '[wbd-capture] running upstream probe test (output to d02-upstream-probes.log) ...'
        $d02Output = & pwsh -NoProfile -ExecutionPolicy Bypass -File $upstreamTest -RequireTier base-container 2>&1
        $d02Exit = $LASTEXITCODE
        $d02Output | Set-Content -LiteralPath $d02Log -Encoding utf8
        Write-Host "[wbd-capture] D-02 upstream test exit: $d02Exit (recorded verbatim; a failure is evidence, not a capture error)"
    } else {
        "upstream probe test not found at $upstreamTest - pinned tree layout drift; record as an upstream blocker (D-02)." |
            Set-Content -LiteralPath $d02Log -Encoding utf8
        Write-Host "[wbd-capture] D-02: upstream entry point missing at $upstreamTest (recorded)" -ForegroundColor Yellow
    }

    # ---------------------------------------------------------------------
    # Manifest: every artifact + SHA256, so the fetched evidence is
    # tamper-evident against the run record.
    # ---------------------------------------------------------------------
    Start-Sleep -Milliseconds 100   # let the last writes flush
    $manifest = [ordered]@{
        schema     = 1
        capturedAt = $capturedAt
        artifacts  = @(Get-ChildItem -LiteralPath $ResultsDir -File |
            ForEach-Object {
                [ordered]@{
                    name   = $_.Name
                    bytes  = $_.Length
                    sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash
                }
            })
    }
    $manifest | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $ResultsDir 'capture-manifest.json') -Encoding utf8

    Write-Host "[wbd-capture] artifacts written to $ResultsDir (fetched by the harness into tests\vm\results\<runid>\)."
    Write-Host 'WBD CAPTURE: DONE' -ForegroundColor Green
    exit 0
} catch {
    Write-Host "[wbd-capture] unexpected error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host 'WBD CAPTURE: FAILED' -ForegroundColor Red
    exit 99
}
