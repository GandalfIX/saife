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