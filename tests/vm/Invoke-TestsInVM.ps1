#Requires -Version 7
<#
.SYNOPSIS
  Host-side orchestrator for the disposable-VM test infrastructure (VM-01
  Task 5): spin up, run suites in-VM, collect, destroy.
.DESCRIPTION
  Creates a disposable Generation 2 VM (differencing VHDX off a baked
  template image), copies the working tree into it, runs build + tests
  inside the VM via PowerShell Direct (tests\vm\run-in-vm.ps1), fetches the
  result artifacts back to tests\vm\results\<runid>\, then destroys the VM.
  With -KeepOnFailure a failed run keeps the VM behind (checkpoint
  'failed-run') for debugging. An artifact-fetch failure after a completed
  suite ALWAYS keeps the VM (with the same checkpoint) - results that took
  hours to produce are never thrown away; the manual cleanup path is
  printed.

  Gate order: PowerShell parameter binding (including the -Phase
  ValidateSet) runs first at the engine level; inside the script body the
  ELEVATION gate runs BEFORE any other validation or setup - then the host
  readiness probe (tests\vm\Initialize-VMHost.ps1), the template image, and
  tests\vm\vm-settings.json. Nothing is created until all gates pass.

  Repo transfer reuses the base-image runbook pattern (BUILD-BASE-IMAGE.md):
  robocopy staging -> one archive -> one Copy-VMFile -> one Expand-Archive ->
  file-count verification. The archived staging copy REPLACES the repo copy
  baked into the image (C:\sbx-repo), so the count check is exact and every
  run tests the current working tree.

  Teardown policy (one function; rules that compose):
    - keep   when ((failed AND -KeepOnFailure) or the fetch failed) AND
      the VM exists: checkpoint 'failed-run' BEFORE stopping, keep VM +
      differencing disk (a VM that was never created cannot be kept - its
      orphaned disk is destroyed instead);
    - destroy otherwise: Stop-VM + Remove-VM, then delete the differencing
      disk ONLY when the VM was never registered or its removal succeeded
      (a registered VM must never point at a deleted file), with an
      exact-path guard (<vmsDir>\<vmName>.vhdx only). When Hyper-V cannot
      be queried at teardown time, nothing is deleted and teardown counts
      as failed (manual cleanup path printed).
  Teardown failure is a HARNESS error: the script exits nonzero even when
  the in-VM suite passed, because the leftover sbx-test-* VM/disk would
  collide with the next run. Rollback for a killed or broken run:
  tests\vm\Remove-TestVM.ps1 (only ever touches sbx-test-* VMs and disks
  under tests\vm\vms).

  Every nonzero exit prints a final 'VM HARNESS: FAIL' line before exiting
  (exception: exit 2, the elevation gate, which prints only its single
  remediation line).

  Exit codes:
    0  = suite passed AND teardown succeeded (final line: VM HARNESS: PASS)
    1  = the in-VM run failed or could not be completed - any nonzero
         guest exit code (INCLUDING run-in-vm.ps1's 99) surfaces here -
         guest PowerShell Direct readiness timeout, guest credential
         rejection, repo copy verification failure, artifact fetch failure
         (the VM is then kept), or teardown failed
         (final line: VM HARNESS: FAIL)
    2  = not elevated (single remediation line, no verdict line)
    3  = host readiness probe failed, or the requested template image is
         missing or invalid
    4  = tests\vm\vm-settings.json missing or invalid
    99 = unexpected error (final line: VM HARNESS: FAIL)
.PARAMETER Image
  Template image name; the template VHDX is tests\vm\templates\<Image>.vhdx
  (name only, no extension, no path separators). Default: sbx-base-a.
.PARAMETER Phase
  Which phase(s) run-in-vm.ps1 runs: unit, integration, or all. Default: all.
.PARAMETER Only
  Scenario ids passed through to tests\run-tests.ps1 (integration phase
  only). Same pwsh platform quirk as run-in-vm.ps1's -Only: multi-value
  lists bind correctly only when PowerShell itself parses them - invoke
  in-process or via 'pwsh -Command'. Via 'pwsh -File' only a single id is
  reliable ("1,2,6" would bind as the single int 126).
.PARAMETER KeepOnFailure
  On a failed run: checkpoint the VM as 'failed-run' (BEFORE stopping it)
  and keep it plus the differencing disk for debugging, instead of
  destroying them. Artifacts are always fetched first; when fetching
  itself fails the VM is kept regardless of this switch.
.PARAMETER VMSuffix
  Suffix for the VM name and differencing disk: sbx-test-<suffix>. Default:
  a short run id (yyyyMMdd-HHmmss-fff). The results directory under
  tests\vm\results\ is always keyed by the run id, not by this suffix.
.PARAMETER PSTimeoutMinutes
  Total timeout in minutes for guest PowerShell Direct readiness after
  Start-VM (each individual probe attempt is additionally bounded to 60 s).
  Default: 10.
.EXAMPLE
  pwsh -NoProfile -ExecutionPolicy Bypass -File tests\vm\Invoke-TestsInVM.ps1
  Full run (all phases) on the default sbx-base-a template.
.EXAMPLE
  pwsh -NoProfile -ExecutionPolicy Bypass -File tests\vm\Invoke-TestsInVM.ps1 -Phase unit
  Unit phase only.
.EXAMPLE
  pwsh -NoProfile -Command "& '<repoRoot>\tests\vm\Invoke-TestsInVM.ps1' -Phase integration -Only 1,2,6"
  Integration phase with scenario selection (the -Command wrapper is
  required for a multi-value -Only; see the parameter note above).
#>
[CmdletBinding()]
param(
    [string]$Image = 'sbx-base-a',

    [ValidateSet('unit', 'integration', 'all')]
    [string]$Phase = 'all',

    [int[]]$Only,

    [switch]$KeepOnFailure,

    [string]$VMSuffix,

    [ValidateRange(1, 1440)]
    [int]$PSTimeoutMinutes = 10
)

$ErrorActionPreference = 'Stop'
$script:ThisDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$script:VmsDir = Join-Path $script:ThisDir 'vms'
$script:ResultsBaseDir = Join-Path $script:ThisDir 'results'
$script:RepoRoot = [System.IO.Path]::GetFullPath((Join-Path $script:ThisDir '..\..'))

# ---------------------------------------------------------------------------
# Teardown per the keep/destroy policy documented in the help header.
# Returns $true when the destroy path FAILED (a harness error the caller
# must exit nonzero for); keep paths return $false (kept is intended).
#
# VM state is probed by LISTING all VMs and filtering (Get-VM bare throws
# when the Hyper-V service is unavailable), which distinguishes three
# states: VM exists / VM absent / Hyper-V unqueryable.
#
# Rules (they compose into one policy):
#   keep    - (Failed AND KeepOnFailure) or ForceKeep (artifact-fetch
#             failure: the completed run's results still live in the
#             guest), but only when the VM EXISTS - a VM that was never
#             created cannot be kept, and keeping its orphaned disk would
#             leak it: checkpoint 'failed-run' BEFORE stopping, keep VM +
#             differencing disk, skip destruction entirely.
#   destroy - otherwise. When Hyper-V cannot be queried: delete NOTHING
#             (a registered VM must never point at a deleted file) and
#             report teardown failure. When the VM is registered: Stop-VM
#             + Remove-VM, then delete the differencing disk ONLY when
#             the removal succeeded. When the VM is absent: delete the
#             orphaned disk (New-VM threw after New-VHD). Disk deletion
#             uses an exact-path guard: only <vmsDir>\<vmName>.vhdx is
#             ever deleted.
# ---------------------------------------------------------------------------
function Invoke-TestVmTeardown {
    [CmdletBinding()]
    param(
        [bool]$Failed,
        [bool]$ForceKeep,
        [string]$VmName,
        [string]$VhdxPath,
        [switch]$KeepOnFailure
    )
    $vm = $null
    $vmQueryOk = $false
    $vmQueryError = $null
    try {
        $allVms = @(Get-VM -ErrorAction Stop)
        $vmQueryOk = $true
        $vm = @($allVms | Where-Object { $_.Name -eq $VmName })[0]
    } catch {
        $vmQueryOk = $false
        $vm = $null
        $vmQueryError = $_.Exception.Message
    }
    if ((($Failed -and $KeepOnFailure) -or $ForceKeep) -and $vm) {
        try {
            Checkpoint-VM -Name $VmName -SnapshotName 'failed-run'
            Write-Host ("[vm-run] kept for debugging: {0} (checkpoint failed-run) + artifacts in tests\vm\results\{1}" -f $VmName, $script:RunId) -ForegroundColor Yellow
        } catch {
            Write-Host "[vm-run] WARNING: checkpoint failed, VM stays in its current state: $($_.Exception.Message)" -ForegroundColor Yellow
        }
        return $false
    }
    $teardownFailed = $false
    $vmRemoved = $false
    if (-not $vmQueryOk) {
        # Cannot tell registered from unregistered - deleting the disk now
        # could leave a registered VM pointing at a deleted file.
        Write-Host ("[vm-run] WARNING: could not query Hyper-V for the VM state - nothing removed: {0}" -f $vmQueryError) -ForegroundColor Yellow
        $teardownFailed = $true
    } elseif ($vm) {
        try {
            if ($vm.State -ne 'Off') {
                Stop-VM -Name $VmName -Force
            }
            Remove-VM -Name $VmName -Force
            $vmRemoved = $true
        } catch {
            Write-Host "[vm-run] WARNING: VM removal failed: $($_.Exception.Message)" -ForegroundColor Yellow
            $teardownFailed = $true
        }
    } else {
        # Query OK, VM absent (New-VM threw after New-VHD): the disk is
        # orphaned - deleting it is safe and REQUIRED (no VHDX leak).
        $vmRemoved = $true
    }
    if ($vmRemoved) {
        try {
            $expectedPath = [System.IO.Path]::GetFullPath((Join-Path $script:VmsDir "$VmName.vhdx"))
            if (($VhdxPath -eq $expectedPath) -and (Test-Path -LiteralPath $VhdxPath)) {
                Remove-Item -LiteralPath $VhdxPath -Force
                Write-Host "[vm-run] differencing disk deleted: $VhdxPath"
            }
        } catch {
            Write-Host "[vm-run] WARNING: differencing disk deletion failed: $($_.Exception.Message)" -ForegroundColor Yellow
            $teardownFailed = $true
        }
    }
    if ($teardownFailed) {
        Write-Host "[vm-run] WARNING: teardown incomplete - finish cleanup with: pwsh -NoProfile -ExecutionPolicy Bypass -File tests\vm\Remove-TestVM.ps1 -Name $VmName" -ForegroundColor Yellow
    } else {
        Write-Host "[vm-run] VM destroyed: $VmName"
    }
    return $teardownFailed
}

try {
    # -----------------------------------------------------------------------
    # 1. Elevation gate - FIRST, before any other validation or setup;
    #    Hyper-V cmdlets require an elevated shell (even Get-VM fails
    #    otherwise).
    # -----------------------------------------------------------------------
    $windowsIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $windowsPrincipal = New-Object Security.Principal.WindowsPrincipal($windowsIdentity)
    if (-not $windowsPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host '[vm-run] not elevated - run from an elevated pwsh; one-time prep: tests\vm\Initialize-VMHost.ps1' -ForegroundColor Red
        exit 2
    }

    # -----------------------------------------------------------------------
    # Run identity (computed only past the elevation gate).
    # -----------------------------------------------------------------------
    $script:RunId = (Get-Date).ToString('yyyyMMdd-HHmmss-fff')
    if (-not $VMSuffix) { $VMSuffix = $script:RunId }
    $vmName = "sbx-test-$VMSuffix"
    $vhdxPath = Join-Path $script:VmsDir "$vmName.vhdx"
    $hostResultsDir = Join-Path $script:ResultsBaseDir $script:RunId
    $stageDir = Join-Path $env:TEMP "sbx-repo-stage-$($script:RunId)"
    $zipPath = Join-Path $env:TEMP "sbx-repo-$($script:RunId).zip"

    Write-Host ("[vm-run] run id: {0} | image: {1} | phase: {2} | vm: {3}" -f $script:RunId, $Image, $Phase, $vmName)

    # -----------------------------------------------------------------------
    # 2. Host readiness probe. Its own tagged [vm-host] lines (including the
    #    verdict line) print as-is; a nonzero child exit lands in
    #    $LASTEXITCODE and control returns here (verified 2026-10-05).
    # -----------------------------------------------------------------------
    $initScript = Join-Path $script:ThisDir 'Initialize-VMHost.ps1'
    & $initScript
    if ($LASTEXITCODE -ne 0) {
        Write-Host ("[vm-run] host readiness probe failed (probe exit {0}) - see the [vm-host] verdict above; nothing was created." -f $LASTEXITCODE) -ForegroundColor Red
        Write-Host 'VM HARNESS: FAIL' -ForegroundColor Red
        exit 3
    }

    # -----------------------------------------------------------------------
    # 3. Template image gate (still before anything is created).
    # -----------------------------------------------------------------------
    if ($Image -match '[\\/]') {
        Write-Host "[vm-run] invalid -Image '$Image' - a template name must not contain path separators." -ForegroundColor Red
        Write-Host 'VM HARNESS: FAIL' -ForegroundColor Red
        exit 3
    }
    $templatePath = Join-Path $script:ThisDir ("templates\$Image.vhdx")
    if (-not (Test-Path -LiteralPath $templatePath)) {
        Write-Host "[vm-run] template image not found: $templatePath - build it first (tests\vm\BUILD-BASE-IMAGE.md); nothing was created." -ForegroundColor Red
        Write-Host 'VM HARNESS: FAIL' -ForegroundColor Red
        exit 3
    }
    Write-Host "[vm-run] template image: $templatePath"

    # -----------------------------------------------------------------------
    # 4. Guest credentials from tests\vm\vm-settings.json (gitignored; this
    #    is the only script that may READ it). Validate schema 1 and
    #    non-empty guestUser/guestPassword. The contents are never echoed,
    #    and no parse-error detail is printed (it could quote file
    #    content). Nothing password-shaped ever reaches the console or the
    #    logs.
    # -----------------------------------------------------------------------
    $settingsFile = Join-Path $script:ThisDir 'vm-settings.json'
    $guestCred = $null
    $settingsValid = $false
    try {
        if (Test-Path -LiteralPath $settingsFile) {
            $settings = Get-Content -LiteralPath $settingsFile -Raw | ConvertFrom-Json
            if ($settings -and ($settings.schema -eq 1) -and $settings.guestUser -and $settings.guestPassword) {
                $securePassword = ConvertTo-SecureString -String ([string]$settings.guestPassword) -AsPlainText -Force
                $guestCred = New-Object System.Management.Automation.PSCredential(([string]$settings.guestUser), $securePassword)
                $settingsValid = $true
            }
        }
    } catch {
        $settingsValid = $false
    } finally {
        $settings = $null
        $securePassword = $null
    }
    if (-not $settingsValid) {
        Write-Host "[vm-run] invalid or missing guest settings: $settingsFile (expected schema 1 with non-empty guestUser and guestPassword; created during image build, see tests\vm\BUILD-BASE-IMAGE.md)." -ForegroundColor Red
        Write-Host 'VM HARNESS: FAIL' -ForegroundColor Red
        exit 4
    }
    Write-Host '[vm-run] guest settings loaded (credentials are never printed).'

    # -----------------------------------------------------------------------
    # Hyper-V module (self-contained, same pattern as Remove-TestVM.ps1; the
    #    probe verified it, this makes this script robust on its own).
    # -----------------------------------------------------------------------
    if (-not (Get-Command New-VM -ErrorAction SilentlyContinue)) {
        Import-Module Hyper-V -ErrorAction Stop
    }

    # -----------------------------------------------------------------------
    # 5. Stage the repo host-side (working tree minus build output, VM
    #    artifacts, and the credentials file), then archive the CONTENTS
    #    and record the file count for the post-copy verification.
    #    /XD gets root-anchored ABSOLUTE paths: bare names would exclude
    #    same-named directories tree-wide.
    # -----------------------------------------------------------------------
    Write-Host "[vm-run] staging repo to $stageDir ..."
    $excludeDirs = @(
        (Join-Path $script:RepoRoot 'target'),
        (Join-Path $script:RepoRoot '.git'),
        $script:VmsDir,
        $script:ResultsBaseDir,
        (Join-Path $script:ThisDir 'templates')
    )
    robocopy $script:RepoRoot $stageDir /E /XD $excludeDirs /XF vm-settings.json | Out-Null
    if ($LASTEXITCODE -ge 8) { throw "robocopy staging failed (exit $LASTEXITCODE; 0-7 is success)" }
    $stageCount = @(Get-ChildItem -LiteralPath $stageDir -Recurse -File -Force).Count
    # Archive fallback for very large trees: tar -a -c -f $zipPath -C $stage .
    # (and 'tar -xf' in the guest); Expand-Archive reads bsdtar zips fine.
    Compress-Archive -Path (Join-Path $stageDir '*') -DestinationPath $zipPath -Force
    Write-Host ("[vm-run] staged {0} files into {1} ({2} MB)." -f $stageCount, $zipPath, [math]::Round((Get-Item -LiteralPath $zipPath).Length / 1MB, 1))

    # -----------------------------------------------------------------------
    # 6. Per-run differencing VHDX off the template (never booted
    #    directly).
    # -----------------------------------------------------------------------
    New-Item -ItemType Directory -Path $script:VmsDir -Force | Out-Null
    New-VHD -Path $vhdxPath -Differencing -ParentPath $templatePath | Out-Null
    Write-Host "[vm-run] differencing disk created: $vhdxPath"

    # -----------------------------------------------------------------------
    # 7. VM: Gen 2, 6 GB startup memory, 4 vCPU, the differencing disk as
    #    the boot device. Prefer the 'Default Switch' when present, else
    #    the first Get-VMSwitch result. Then start it.
    # -----------------------------------------------------------------------
    $switch = @()
    try { $switch = @(Get-VMSwitch) } catch { }
    if ($switch.Count -eq 0) { throw 'no virtual switch found (the readiness probe should have caught this)' }
    $chosenSwitch = $switch | Where-Object { $_.Name -eq 'Default Switch' } | Select-Object -First 1
    if (-not $chosenSwitch) { $chosenSwitch = $switch[0] }
    $switchName = $chosenSwitch.Name
    Write-Host "[vm-run] virtual switch selected: $switchName"
    New-VM -Generation 2 -Name $vmName -MemoryStartupBytes 6GB -SwitchName $switchName | Out-Null
    Set-VM -Name $vmName -ProcessorCount 4   # verify at image-build time
    Add-VMHardDiskDrive -VMName $vmName -Path $vhdxPath
    # Boot order: the differencing drive first (verify at image-build time).
    Set-VMFirmware -VMName $vmName -FirstBootDevice (Get-VMHardDiskDrive -VMName $vmName)
    Start-VM -Name $vmName
    Write-Host ("[vm-run] VM started: {0}." -f $vmName)

    # -----------------------------------------------------------------------
    # 8. PowerShell Direct readiness. Bounded twice: the loop honors the
    #    TOTAL -PSTimeoutMinutes deadline, and each probe attempt runs in
    #    a job capped by Wait-Job -Timeout 60 (one hung Invoke-Command
    #    can no longer make the loop unbounded). Probe: return the guest
    #    computer name. An authentication failure (HRESULT 0x80070005 /
    #    'credentials' in the error text) fails fast instead of burning
    #    the full timeout; the remediation points at vm-settings.json
    #    without echoing its contents.
    # -----------------------------------------------------------------------
    $deadline = (Get-Date).AddMinutes($PSTimeoutMinutes)
    $guestReady = $false
    $guestName = $null
    Write-Host ("[vm-run] waiting for PowerShell Direct readiness (timeout: {0} min, 60 s per attempt)..." -f $PSTimeoutMinutes)
    while (((-not $guestReady)) -and ((Get-Date) -lt $deadline)) {
        $attemptError = $null
        $probeJob = Start-Job -ScriptBlock {
            param($VmName, $Credential)
            Invoke-Command -VMName $VmName -Credential $Credential -ScriptBlock { $env:COMPUTERNAME }
        } -ArgumentList $vmName, $guestCred
        $null = Wait-Job -Job $probeJob -Timeout 60
        if ($probeJob.State -eq 'Completed') {
            $probeOut = @(Receive-Job -Job $probeJob)
            if ($probeOut.Count -gt 0) {
                $guestName = [string]$probeOut[0]
                $guestReady = $true
            } else {
                $attemptError = 'probe returned no result'
            }
        } elseif ($probeJob.State -eq 'Failed') {
            $reason = $probeJob.ChildJobs[0].JobStateInfo.Reason
            if ($reason) { $attemptError = $reason.Message } else { $attemptError = 'probe job failed' }
        } else {
            $attemptError = 'probe attempt timed out (60 s)'
        }
        Remove-Job -Job $probeJob -Force
        if ($guestReady) { break }
        if ($attemptError -match '0x80070005' -or $attemptError -match 'credential') {
            Write-Host "[vm-run] ERROR: PowerShell Direct rejected the guest credentials - check guestUser/guestPassword in tests\vm\vm-settings.json (created during image build, see tests\vm\BUILD-BASE-IMAGE.md; its contents are not printed here)." -ForegroundColor Red
            $null = Invoke-TestVmTeardown -Failed $true -VmName $vmName -VhdxPath $vhdxPath -KeepOnFailure:$KeepOnFailure
            Write-Host 'VM HARNESS: FAIL' -ForegroundColor Red
            exit 1
        }
        Write-Host '[vm-run] PowerShell Direct not ready yet; retrying in 15 s...' -ForegroundColor Gray
        Start-Sleep -Seconds 15
    }
    if (-not $guestReady) {
        Write-Host ("[vm-run] ERROR: PowerShell Direct not ready within {0} minutes - tearing down. Re-run with -KeepOnFailure to inspect the boot state." -f $PSTimeoutMinutes) -ForegroundColor Red
        # Teardown return honored: a teardown failure keeps the exit
        # nonzero (it is 1 here either way).
        $null = Invoke-TestVmTeardown -Failed $true -VmName $vmName -VhdxPath $vhdxPath -KeepOnFailure:$KeepOnFailure
        Write-Host 'VM HARNESS: FAIL' -ForegroundColor Red
        exit 1
    }
    Write-Host ("[vm-run] PowerShell Direct ready (guest: {0})." -f $guestName)

    # -----------------------------------------------------------------------
    # 9. Transfer: one Copy-VMFile, one expand session, one count check.
    #    The archive REPLACES the repo copy baked into the image (C:\sbx-repo
    #    still holds bake-time files, incl. a target\ tree from the cargo
    #    warm-up) so that the guest file count equals the staging count.
    # -----------------------------------------------------------------------
    Copy-VMFile -Name $vmName -SourcePath $zipPath -DestinationPath 'C:\sbx-repo.zip' -FileSource Host
    Write-Host '[vm-run] repo archive copied into the guest.'
    Invoke-Command -VMName $vmName -Credential $guestCred -ScriptBlock {
        if (Test-Path -LiteralPath 'C:\sbx-repo') {
            Remove-Item -LiteralPath 'C:\sbx-repo' -Recurse -Force
        }
        Expand-Archive -Path 'C:\sbx-repo.zip' -DestinationPath 'C:\sbx-repo' -Force
        Remove-Item -LiteralPath 'C:\sbx-repo.zip' -Force
    }
    $countVerified = $false
    try {
        Invoke-Command -VMName $vmName -Credential $guestCred -ScriptBlock {
            param($expected)
            $actual = @(Get-ChildItem -LiteralPath 'C:\sbx-repo' -Recurse -File -Force).Count
            if ($actual -ne $expected) {
                throw "expected $expected files under C:\sbx-repo, found $actual"
            }
            Write-Host "repo copy verified: $actual of $expected files present"
        } -ArgumentList $stageCount
        $countVerified = $true
    } catch {
        Write-Host "[vm-run] ERROR: repo copy verification FAILED: $($_.Exception.Message)" -ForegroundColor Red
    }
    if (-not $countVerified) {
        $null = Invoke-TestVmTeardown -Failed $true -VmName $vmName -VhdxPath $vhdxPath -KeepOnFailure:$KeepOnFailure
        Write-Host 'VM HARNESS: FAIL' -ForegroundColor Red
        exit 1
    }
    Write-Host '[vm-run] repo copy verified (file count matches).'

    # -----------------------------------------------------------------------
    # 10. Run the suite via the DOCUMENTED -Command wrapper. Mechanism: a
    #     child 'pwsh -NoProfile -Command' inside the PS Direct session
    #     (a) lets PowerShell itself parse "-Only 1,2,6" as an int array
    #     (pwsh -File cannot - it would bind the single int 126), and
    #     (b) isolates run-in-vm.ps1's exit from the remote session. The
    #     child's exit code is read as $LASTEXITCODE INSIDE the session and
    #     returned alongside the captured output lines in one structured
    #     object; the host prints the lines tagged. Any nonzero guest exit
    #     (0 only is success; run-in-vm.ps1 exits 1 or 99 on failure)
    #     surfaces as harness exit 1 (see the help exit-code table).
    # -----------------------------------------------------------------------
    $escapedRunner = 'C:\sbx-repo\tests\vm\run-in-vm.ps1'.Replace("'", "''")
    $guestCommand = "& '$escapedRunner' -Phase '$Phase' -RepoDir 'C:\sbx-repo' -ResultsDir 'C:\sbx-results'"
    if ($Only) { $guestCommand += ' -Only ' + ($Only -join ',') }
    Write-Host "[vm-run] guest command: pwsh -NoProfile -Command $guestCommand"
    $runResult = Invoke-Command -VMName $vmName -Credential $guestCred -ScriptBlock {
        param([string]$Command)
        $lines = @(& pwsh -NoProfile -Command $Command 2>&1 | ForEach-Object { "$_" })
        [pscustomobject]@{ lines = $lines; exitCode = $LASTEXITCODE }
    } -ArgumentList $guestCommand
    foreach ($line in @($runResult.lines)) {
        # Tag guest lines; run-in-vm.ps1 already tags many of its own lines,
        # so do not double-tag those.
        if (-not ($line -like '[vm-guest]*')) { $line = "[vm-guest] $line" }
        Write-Host $line
    }
    $guestExit = $runResult.exitCode
    Write-Host ("[vm-run] guest suite finished (exit {0})." -f $guestExit)

    # -----------------------------------------------------------------------
    # 11. Fetch artifacts PER FILE, CHUNKED (one PS Direct session per
    #     chunk): each guest file is read in 4 MB slices keyed by
    #     name+offset, Base64-transported, and reassembled host-side, so
    #     no single remoting payload ever carries a whole multi-MB log.
    #     The artifact list comes from the guest summary.json 'artifacts'
    #     field, falling back to the four known names; summary.json is
    #     fetched and written LAST (its presence implies the run reached
    #     completion). A fetch failure NEVER destroys the VM (step 12 is
    #     skipped) - the run's only copy of the results lives there.
    # -----------------------------------------------------------------------
    $summaryFetched = $false
    try {
        $artifactNames = Invoke-Command -VMName $vmName -Credential $guestCred -ScriptBlock {
            param([string[]]$KnownArtifacts)
            $resultsRoot = 'C:\sbx-results'
            $names = $null
            $summaryPath = Join-Path $resultsRoot 'summary.json'
            if (Test-Path -LiteralPath $summaryPath) {
                try {
                    $summary = Get-Content -LiteralPath $summaryPath -Raw | ConvertFrom-Json
                    if ($summary.artifacts) { $names = @($summary.artifacts | ForEach-Object { [string]$_ }) }
                } catch { }
            }
            if (-not $names) { $names = @($KnownArtifacts) }
            $ordered = @($names | Where-Object { $_ -and ($_ -ne 'summary.json') } | Select-Object -Unique)
            $ordered += 'summary.json'
            return @($ordered | ForEach-Object { [System.IO.Path]::GetFileName($_) })
        } -ArgumentList @('build.log', 'unit.log', 'integration.log', 'summary.json')

        New-Item -ItemType Directory -Path $hostResultsDir -Force | Out-Null
        $chunkSize = 4MB
        foreach ($artifactName in @($artifactNames)) {
            $fileInfo = Invoke-Command -VMName $vmName -Credential $guestCred -ScriptBlock {
                param([string]$Name)
                $path = Join-Path 'C:\sbx-results' $Name
                if (Test-Path -LiteralPath $path) {
                    [pscustomobject]@{ present = $true; sizeBytes = (Get-Item -LiteralPath $path).Length }
                } else {
                    [pscustomobject]@{ present = $false; sizeBytes = [long]0 }
                }
            } -ArgumentList $artifactName
            if (-not $fileInfo.present) {
                Write-Host "[vm-run] NOTE: artifact '$artifactName' not present in C:\sbx-results (not fetched)." -ForegroundColor Gray
                continue
            }
            if ($fileInfo.sizeBytes -gt 50MB) {
                Write-Host ("[vm-run] WARNING: artifact '{0}' is {1} MB (> 50 MB) - the chunked fetch may take a while." -f $artifactName, [math]::Round($fileInfo.sizeBytes / 1MB, 1)) -ForegroundColor Yellow
            }
            $fileBytes = New-Object byte[] $fileInfo.sizeBytes
            $offset = [long]0
            while ($offset -lt $fileInfo.sizeBytes) {
                if (($fileInfo.sizeBytes - $offset) -lt $chunkSize) {
                    $chunkLen = [int]($fileInfo.sizeBytes - $offset)
                } else {
                    $chunkLen = $chunkSize
                }
                $chunkB64 = Invoke-Command -VMName $vmName -Credential $guestCred -ScriptBlock {
                    param([string]$Name, [long]$Offset, [int]$Length)
                    $path = Join-Path 'C:\sbx-results' $Name
                    $buffer = New-Object byte[] $Length
                    $stream = [System.IO.File]::OpenRead($path)
                    try {
                        $stream.Position = $Offset
                        $read = 0
                        while ($read -lt $Length) {
                            $n = $stream.Read($buffer, $read, $Length - $read)
                            if ($n -le 0) { break }
                            $read += $n
                        }
                    } finally { $stream.Dispose() }
                    if ($read -ne $Length) {
                        throw "short read for '$Name' at offset $Offset (expected $Length bytes, got $read)"
                    }
                    [Convert]::ToBase64String($buffer)
                } -ArgumentList $artifactName, $offset, $chunkLen
                $chunkBytes = [Convert]::FromBase64String($chunkB64)
                [Array]::Copy($chunkBytes, 0, $fileBytes, $offset, $chunkBytes.Length)
                $offset += $chunkLen
            }
            [System.IO.File]::WriteAllBytes((Join-Path $hostResultsDir $artifactName), $fileBytes)
            if ($artifactName -eq 'summary.json') { $summaryFetched = $true }
            Write-Host ("[vm-run] fetched {0} ({1} bytes)." -f $artifactName, $fileInfo.sizeBytes)
        }
    } catch {
        Write-Host "[vm-run] ERROR: artifact fetch failed: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host ("[vm-run] keeping the VM (checkpoint failed-run) so the completed run's results survive; partial artifacts: {0}" -f $hostResultsDir) -ForegroundColor Yellow
        $null = Invoke-TestVmTeardown -Failed $true -ForceKeep -VmName $vmName -VhdxPath $vhdxPath -KeepOnFailure:$KeepOnFailure
        Write-Host ("[vm-run] manual cleanup when done debugging: pwsh -NoProfile -ExecutionPolicy Bypass -File tests\vm\Remove-TestVM.ps1 -Name {0}" -f $vmName) -ForegroundColor Yellow
        Write-Host 'VM HARNESS: FAIL' -ForegroundColor Red
        exit 1
    }
    if ($summaryFetched) {
        Write-Host "[vm-run] artifacts fetched to $hostResultsDir (summary.json last)."
    } else {
        Write-Host '[vm-run] WARNING: summary.json was not produced by the guest run - the suite died before completion.' -ForegroundColor Yellow
    }

    # -----------------------------------------------------------------------
    # 12. Teardown decision (checkpoint BEFORE stopping when kept; step 11's
    #     failure path already exited above, so a fetch failure never
    #     reaches this destruction).
    # -----------------------------------------------------------------------
    $suitePassed = ($guestExit -eq 0)
    $teardownFailed = Invoke-TestVmTeardown -Failed (-not $suitePassed) -VmName $vmName -VhdxPath $vhdxPath -KeepOnFailure:$KeepOnFailure

    # -----------------------------------------------------------------------
    # 13. Final verdict: summary table from the fetched summary.json, then
    #     one verdict line. Exit 0 iff the suite passed AND teardown
    #     succeeded; a teardown failure is a harness error (nonzero even
    #     when the suite passed).
    # -----------------------------------------------------------------------
    $summary = $null
    $summaryPath = Join-Path $hostResultsDir 'summary.json'
    if (Test-Path -LiteralPath $summaryPath) {
        try { $summary = Get-Content -LiteralPath $summaryPath -Raw | ConvertFrom-Json } catch { $summary = $null }
    }
    Write-Host '[vm-run] ---------------- run summary ----------------'
    if ($summary) {
        $buildOk = if ($null -ne $summary.build.ok) { [string]$summary.build.ok } else { '-' }
        $unitExit = if ($null -ne $summary.unit.exit) { [string]$summary.unit.exit } else { '-' }
        $integrationCounts = '-'
        if ($null -ne $summary.integration.total) {
            $integrationCounts = ("pass={0} fail={1} skip={2}" -f $summary.integration.pass, $summary.integration.fail, $summary.integration.skip)
        }
        $verdict = if ($summary.integration.verdict) { [string]$summary.integration.verdict } else { '-' }
        $osBuild = if ($summary.osBuild) { [string]$summary.osBuild } else { '-' }
        Write-Host ("[vm-run] phase:         {0}" -f $summary.phase)
        Write-Host ("[vm-run] build ok:      {0}" -f $buildOk)
        Write-Host ("[vm-run] unit exit:     {0}" -f $unitExit)
        Write-Host ("[vm-run] integration:   {0}" -f $integrationCounts)
        Write-Host ("[vm-run] verdict:       {0}" -f $verdict)
        Write-Host ("[vm-run] guest osBuild: {0}" -f $osBuild)
    } else {
        Write-Host '[vm-run] no summary.json available (the guest run did not complete).'
    }
    Write-Host ("[vm-run] artifacts:     {0}" -f $hostResultsDir)
    $harnessPassed = ($suitePassed -and (-not $teardownFailed))
    if ($harnessPassed) {
        Write-Host 'VM HARNESS: PASS' -ForegroundColor Green
        exit 0
    }
    Write-Host 'VM HARNESS: FAIL' -ForegroundColor Red
    exit 1
} catch {
    Write-Host "[vm-run] unexpected error: $($_.Exception.Message)" -ForegroundColor Red
    # Best-effort teardown for everything this run created (honors
    # -KeepOnFailure: an unexpected error counts as a failed run). The
    # teardown's own keep/destroy rules apply: the disk is deleted only
    # when the VM was never registered or its removal succeeded. A
    # teardown error here must not mask the harness verdict.
    try {
        if ($vmName -and $vhdxPath -and (Get-Command Get-VM -ErrorAction SilentlyContinue)) {
            $null = Invoke-TestVmTeardown -Failed $true -VmName $vmName -VhdxPath $vhdxPath -KeepOnFailure:$KeepOnFailure
        }
    } catch { }
    Write-Host 'VM HARNESS: FAIL' -ForegroundColor Red
    exit 99
} finally {
    # Host-side staging cleanup (best effort; the guest got its own copy).
    foreach ($tempPath in @($stageDir, $zipPath)) {
        if ($tempPath -and (Test-Path -LiteralPath $tempPath)) {
            Remove-Item -LiteralPath $tempPath -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}
