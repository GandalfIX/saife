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
  verbatim with its exit code, plus the suite's own machine-readable
  -ResultsJson. Upstream binary contract (Common.ps1
  Initialize-WpcContext, analyzed 2026-10-13): a standalone area run
  requires BOTH lane binaries to exist and plm.exe /
  winhttp-proxy-shim.exe sidecars beside each lane, even though the
  probes area only ever invokes wxc-exec via --probe. prepare-mxc.ps1
  builds the release lane only, so this script builds the two small
  sidecar crates (release lane, warm cargo cache, ~a minute) inside the
  DISPOSABLE VM - nothing persists - and writes a context JSON
  redirecting the debug lane at the pinned release binary: the
  upstream-documented override mechanism (explicit parameters and
  ContextJson keys both beat the default paths, Common.ps1:1161-1187),
  and both lanes reading the one recorded artifact keeps Assert-BfsSafety
  and the capture-provider probes on the exact binary mxc-build.json
  hashed. -SkipNetwork keeps the read-only phase independent of VM NAT
  reachability. A failing sidecar build or upstream test is EVIDENCE,
  not a capture error: outcomes are recorded in the artifacts. Building
  the full D-02 capability matrix (empty/fs/UI/deny-all-network/proxy
  requests, blocked markings) is WBD-track analysis on top of this raw
  evidence - deliberately NOT done here (VM-01 Task 6: evidence capture
  only, no product code).

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

    # The recorded upstream pin (docs/mxc-source-analysis.md,
    # "Pin decision (2026-10-13)": 5d7a475a9fd5626bafb55c2c857989d2e5621245),
    # normalized to its FULL SHA before any comparison: git always reports
    # 40-char SHAs, so comparing HEAD against the short literal fires a false
    # 'NOT the pin' warning on every valid run (observed in run
    # 20261013-142920-051; same bug family as the prepare-mxc.ps1
    # comparison incident fixed the same day).
    $pinnedCommit = '5d7a475a9fd5626bafb55c2c857989d2e5621245'
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
            'A second run may differ only in timestamps and per-boot fields.',
            'D-02 matrix: per-shape probe outputs are d02-matrix-<shape>.probe.json, request configs are d02-config-<shape>.json, summary in d02-matrix.json.'
        )
    }
    $baselinePath = Join-Path $ResultsDir 'wbd-d01-baseline.json'
    Write-Host ("[wbd-capture] build {0} | mxc {1} | probe exit {2}" -f $os.BuildNumber, $mxcCommit.Substring(0, [Math]::Min(7, $mxcCommit.Length)), $probeExit)
    if ($pinnedFull -ne $mxcCommit) {
        Write-Host "[wbd-capture] WARNING: checked-out MXC commit $mxcCommit is NOT the recorded pin $pinnedCommit - evidence is still captured, but the pin decision must be revisited (docs/mxc-source-analysis.md)." -ForegroundColor Yellow
    }

    # ---------------------------------------------------------------------
    # D-02 starter: the upstream request-scoped probe test, verbatim.
    # Absence of the upstream entry point in the pinned tree is recorded
    # as evidence (upstream layout drift), not as a script error. Same
    # for a failed sidecar build: the blocker text lands in the log and
    # the run continues (D-01 evidence is already complete).
    # ---------------------------------------------------------------------
    $d02Log = Join-Path $ResultsDir 'd02-upstream-probes.log'
    $upstreamTest = Join-Path $MxcRoot 'tests\scripts\run_processcontainer_probes_test.ps1'
    if (Test-Path -LiteralPath $upstreamTest) {
        # Satisfy the upstream binary contract (see .DESCRIPTION): the
        # release-lane sidecars are built here if missing - inside the
        # disposable VM, so nothing persists. Idempotent: a re-run with
        # sidecars already present skips the build entirely.
        $wxcDir = Split-Path -Parent $wxcExec
        $sidecarBuildLog = Join-Path $ResultsDir 'd02-sidecar-build.log'
        $sidecarsMissing = @('plm.exe', 'winhttp-proxy-shim.exe') |
            Where-Object { -not (Test-Path -LiteralPath (Join-Path $wxcDir $_)) }
        $d02Ran = $false
        if (@($sidecarsMissing).Count -eq 0) {
            Set-Content -LiteralPath $sidecarBuildLog -Value 'sidecars already present beside the release binary' -Encoding utf8
            $d02Ran = $true
        } elseif (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
            $blocker = 'cargo not on PATH in this session - cannot build the upstream sidecar crates (plm, wxc_winhttp_proxy_shim)'
            Set-Content -LiteralPath $sidecarBuildLog -Value $blocker -Encoding utf8
            Set-Content -LiteralPath $d02Log -Value $blocker -Encoding utf8
            Write-Host "[wbd-capture] D-02: $blocker (recorded)" -ForegroundColor Yellow
        } else {
            Write-Host ("[wbd-capture] building upstream sidecar crates ({0}) - release lane, warm cargo cache ..." -f ($sidecarsMissing -join ', '))
            Push-Location (Join-Path $MxcRoot 'src')
            try {
                # Same invocation pattern as prepare-mxc.ps1: 2>&1 merge +
                # Tee-Object keeps the compiler output as evidence.
                cargo build --release -p plm -p wxc_winhttp_proxy_shim 2>&1 |
                    Tee-Object -FilePath $sidecarBuildLog | Out-Null
                $sidecarExit = $LASTEXITCODE
            } finally {
                Pop-Location
            }
            $stillMissing = @('plm.exe', 'winhttp-proxy-shim.exe') |
                Where-Object { -not (Test-Path -LiteralPath (Join-Path $wxcDir $_)) }
            if ($sidecarExit -eq 0 -and @($stillMissing).Count -eq 0) {
                $d02Ran = $true
            } else {
                $blocker = "sidecar build failed (cargo exit $sidecarExit; still missing: $(@($stillMissing) -join ', ')) - see d02-sidecar-build.log"
                Set-Content -LiteralPath $d02Log -Value $blocker -Encoding utf8
                Write-Host "[wbd-capture] D-02: $blocker (recorded)" -ForegroundColor Yellow
            }
        }
        if ($d02Ran) {
            # The context JSON is itself an artifact (auditable override):
            # redirect the debug lane at the pinned release binary. Only
            # keys Initialize-WpcContext declares are honored; explicit
            # command-line parameters still beat the file upstream.
            $ctxPath = Join-Path $ResultsDir 'd02-wpc-context.json'
            [ordered]@{
                RepoRoot   = $MxcRoot
                CargoRoot  = (Join-Path $MxcRoot 'src')
                WxcDebug   = $wxcExec
                WxcRelease = $wxcExec
            } | ConvertTo-Json | Set-Content -LiteralPath $ctxPath -Encoding utf8
            Write-Host '[wbd-capture] running upstream probe test (output to d02-upstream-probes.log) ...'
            $resultsJson = Join-Path $ResultsDir 'd02-probes-results.json'
            $d02Output = & pwsh -NoProfile -ExecutionPolicy Bypass -File $upstreamTest -ContextJson $ctxPath -RequireTier base-container -SkipNetwork -ResultsJson $resultsJson 2>&1
            $d02Exit = $LASTEXITCODE
            # Set-Content -Value (parameter), never the pipeline: an EMPTY
            # output stream must still produce the (empty) verbatim log -
            # same empty-output bug fixed for the D-01 logs.
            $d02Text = (@($d02Output) | ForEach-Object { [string]$_ }) -join [Environment]::NewLine
            Set-Content -LiteralPath $d02Log -Value $d02Text -Encoding utf8
            Write-Host "[wbd-capture] D-02 upstream test exit: $d02Exit (recorded verbatim; a failure is evidence, not a capture error)"
        }
    } else {
        "upstream probe test not found at $upstreamTest - pinned tree layout drift; record as an upstream blocker (D-02)." |
            Set-Content -LiteralPath $d02Log -Encoding utf8
        Write-Host "[wbd-capture] D-02: upstream entry point missing at $upstreamTest (recorded)" -ForegroundColor Yellow
    }

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

    [ordered]@{
        schema  = 1
        ran     = $matrixRan
        blocker = $matrixBlocker
        shapes  = @($matrixRows)
    } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $ResultsDir 'd02-matrix.json') -Encoding utf8
    $baseline | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $baselinePath -Encoding utf8
    Write-Host "[wbd-capture] D-01 baseline:        $baselinePath"

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
