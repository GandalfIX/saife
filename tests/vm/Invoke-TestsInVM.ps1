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
  With -TestCmd an arbitrary guest command runs INSTEAD of the suite
  (VM-01 Task 6, the WBD D-01/D-02 discovery lane): repo copy, artifact
  fetch, and teardown are identical, but the guest command is whatever
  -TestCmd specifies, its console output is additionally teed into
  C:\sbx-results\testcmd.log, and ALL files under C:\sbx-results are
  fetched (there is no summary.json contract in this mode).
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
      the VM exists: checkpoint 'failed-run', keep VM + differencing
      disk, the VM is left RUNNING for debugging (a VM that was never
      created cannot be kept - its orphaned disk is destroyed instead);
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
    3  = host readiness probe failed, the requested template image is
         missing or invalid, or -TestCmd is empty/whitespace
    4  = tests\vm\vm-settings.json missing or invalid
    99 = unexpected error (final line: VM HARNESS: FAIL)
.PARAMETER Image
  Template image name; the template VHDX is tests\vm\templates\<Image>.vhdx
  (name only, no extension, no path separators). Default: sbx-base-a.
.PARAMETER Phase
  Which phase(s) run-in-vm.ps1 runs: unit, integration, or all. Default: all.
  Ignored when -TestCmd is given.
.PARAMETER TestCmd
  Run this command in the guest INSTEAD of the test suite, via
  'pwsh -NoProfile -Command' inside the PowerShell Direct session.
  Contract: the current working tree is expanded at C:\sbx-repo (as for a
  suite run), artifacts the command wants fetched must be written under
  C:\sbx-results (created by the harness in this mode), and the command's
  console output is teed to C:\sbx-results\testcmd.log. After it exits,
  EVERY file under C:\sbx-results is fetched to tests\vm\results\<runid>\;
  a guest exit code of 0 counts as PASS (any other exit = harness FAIL).
  -Phase/-Only are ignored in this mode. Useful for one-off probe/evidence
  capture such as the WBD D-01/D-02 battery on image B
  (tests\vm\wbd-d01-d02-probes.ps1).
.PARAMETER Only
  Scenario ids passed through to tests\run-tests.ps1 (integration phase
  only). Same pwsh platform quirk as run-in-vm.ps1's -Only: multi-value
  lists bind correctly only when PowerShell itself parses them - invoke
  in-process or via 'pwsh -Command'. Via 'pwsh -File' only a single id is
  reliable ("1,2,6" would bind as the single int 126).
.PARAMETER KeepOnFailure
  On a failed run: checkpoint the VM as 'failed-run' and keep it plus
  the differencing disk for debugging (the VM is left running), instead
  of destroying them. Artifacts are always fetched first; when fetching
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
.EXAMPLE
  pwsh -NoProfile -ExecutionPolicy Bypass -File tests\vm\Invoke-TestsInVM.ps1 -Image sbx-base-b -TestCmd "pwsh -NoProfile -File C:\sbx-repo\tests\vm\wbd-d01-d02-probes.ps1"
  WBD D-01/D-02 probe capture inside the image-B template (the probe
  script ships with the repo copy, so the versioned script always runs).
#>
[CmdletBinding()]
param(
    [string]$Image = 'sbx-base-a',

    [ValidateSet('unit', 'integration', 'all')]
    [string]$Phase = 'all',

    [string]$TestCmd,

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
#             leak it: checkpoint 'failed-run', keep VM (left running for
#             debugging) + differencing disk, skip destruction entirely.
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
        Write-Host "[vm-run] WARNING: teardown incomplete - finish cleanup with: pwsh -NoProfile -ExecutionPolicy Bypass -File tests\vm\Remove-TestVM.ps1 -Name $VmName (removes the VM and/or its orphaned disk)" -ForegroundColor Yellow
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
    # 1b. -TestCmd sanity gate (still before anything is created): an
    #     explicitly supplied but empty/whitespace command is an operator
    #     error, not a request for the suite - fail loudly instead of
    #     silently falling back to a 30+ minute suite run.
    # -----------------------------------------------------------------------
    if ($PSBoundParameters.ContainsKey('TestCmd') -and -not $TestCmd.Trim()) {
        Write-Host '[vm-run] invalid -TestCmd: empty or whitespace - provide the guest command, or omit -TestCmd to run the suite; nothing was created.' -ForegroundColor Red
        Write-Host 'VM HARNESS: FAIL' -ForegroundColor Red
        exit 3
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

    $modeLabel = if ($TestCmd) { "testcmd ($TestCmd)" } else { "suite/$Phase" }
    Write-Host ("[vm-run] run id: {0} | image: {1} | mode: {2} | vm: {3}" -f $script:RunId, $Image, $modeLabel, $vmName)

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
    #    artifacts, the runtime-state dir, and the credentials file), then
    #    archive the CONTENTS and record the file count for the
    #    post-copy verification.
    #    /XD gets root-anchored ABSOLUTE paths: bare names would exclude
    #    same-named directories tree-wide.
    # -----------------------------------------------------------------------
    Write-Host "[vm-run] staging repo to $stageDir ..."
    $excludeDirs = @(
        (Join-Path $script:RepoRoot 'target'),
        (Join-Path $script:RepoRoot '.git'),
        (Join-Path $script:RepoRoot '.sandbox'),
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
    New-VM -Generation 2 -Name $vmName -MemoryStartupBytes 8GB -SwitchName $switchName | Out-Null
    Set-VM -Name $vmName -ProcessorCount 4   # verify at image-build time
    # No auto-checkpoints on disposable run VMs (client-Hyper-V default):
    # one would layer an .avhdx over the differencing disk and leak it on
    # teardown (Remove-TestVM only sweeps VHDX files it knows about).
    Set-VM -Name $vmName -AutomaticCheckpointsEnabled $false
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
            # Receive-Job re-emits the job's error records into THIS session;
            # with $ErrorActionPreference='Stop' a non-terminating remoting
            # error (observed: 'Eine Remotesitzung wurde beendet' on a
            # not-yet-booted guest) would throw and abort the whole harness
            # as an 'unexpected error' on the very first attempt. Surface job
            # errors as a normal attempt failure instead so the loop retries
            # until the deadline.
            $probeErr = $null
            $probeOut = @(Receive-Job -Job $probeJob -ErrorVariable probeErr -ErrorAction SilentlyContinue)
            if ($probeErr) {
                $attemptError = [string]$probeErr[0]
            } elseif ($probeOut.Count -gt 0) {
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

    # A disposable test VM must never reboot itself mid-run: the Insider
    # guest has internet via Default Switch, and a Windows Update reboot
    # kills the in-guest suite with 'Der Hyper-V-Socket-Zielprozess wurde
    # beendet' (2026-10-10, run 011648). Disable the update service for
    # this run's lifetime; the VM is destroyed afterwards anyway.
    $null = Invoke-Command -VMName $vmName -Credential $guestCred -ScriptBlock {
        Stop-Service wuauserv -Force -ErrorAction SilentlyContinue
        Set-Service wuauserv -StartupType Disabled -ErrorAction SilentlyContinue
    } -ErrorAction SilentlyContinue
    Write-Host '[vm-run] Windows Update disabled in the guest for the run.'

    # -----------------------------------------------------------------------
    # 9. Transfer: one Copy-VMFile, one expand session, one count check.
    #    The archive REPLACES the repo copy baked into the image (C:\sbx-repo
    #    still holds bake-time files, incl. a target\ tree from the cargo
    #    warm-up) so that the guest file count equals the staging count.
    #    Copy-VMFile additionally needs the "Guest Service" integration
    #    service - Copy-RepoToVM.ps1 enables it on the BUILDER VM, but every
    #    disposable run VM is fresh (default: disabled) - and even enabled,
    #    the in-guest service starts LATER than PowerShell Direct on a
    #    first-booting clone, hence the bounded retry (observed:
    #    0x80070015 'Das Gerät ist nicht bereit').
    # -----------------------------------------------------------------------
    # Match by the language-independent integration-service Id (GUID), never
    # by name - names are LOCALIZED on non-English hosts (observed 2026-10-10:
    # German 'Gastdienstschnittstelle'; the English filter matched nothing
    # and Copy-VMFile failed 0x80070015 through the whole 5-min retry).
    # Same GUID filter as Copy-RepoToVM.ps1 step 4.
    $guestService = Get-VMIntegrationService -VMName $vmName |
        Where-Object { $_.Id -like '*6C09BB55-D683-4DA0-8931-C9BF705F6480*' }
    if (-not $guestService) {
        Write-Host '[vm-run] WARNING: guest file-copy integration service not found on the VM (Id 6C09BB55-...):' -ForegroundColor Yellow
        Get-VMIntegrationService -VMName $vmName | ForEach-Object { Write-Host ("[vm-run]   {0}  (enabled: {1})" -f $_.Name, $_.Enabled) -ForegroundColor Yellow }
    } elseif (-not $guestService.Enabled) {
        $guestService | Enable-VMIntegrationService
        Write-Host '[vm-run] guest file-copy integration service enabled.' -ForegroundColor Gray
    }
    # The in-guest copy service (vmicguestinterface) is trigger-started; on a
    # first-booting clone it has been observed stopped while PowerShell
    # Direct already answers. Nudge it explicitly - harmless when already
    # running, and the bounded Copy-VMFile retry below remains the safety
    # net.
    try {
        $null = Invoke-Command -VMName $vmName -Credential $guestCred -ScriptBlock {
            Start-Service vmicguestinterface -ErrorAction SilentlyContinue
        } -ErrorAction Stop
    } catch { }
    $copyDeadline = (Get-Date).AddMinutes(5)
    $copied = $false
    while (-not $copied) {
        try {
            Copy-VMFile -Name $vmName -SourcePath $zipPath -DestinationPath 'C:\sbx-repo.zip' -FileSource Host -Force -ErrorAction Stop
            $copied = $true
        } catch {
            if ((Get-Date) -ge $copyDeadline) {
                # Self-serve diagnostics before teardown: PS Direct works even
                # when the copy device does not.
                try {
                    $svc = Invoke-Command -VMName $vmName -Credential $guestCred -ScriptBlock {
                        Get-Service vmic* | Select-Object Name, Status, StartType | Format-Table | Out-String
                    }
                    Write-Host '[vm-run] in-guest integration services at failure time:' -ForegroundColor Yellow
                    Write-Host $svc -ForegroundColor Yellow
                } catch {
                    Write-Host "[vm-run] could not collect in-guest diagnostics: $($_.Exception.Message)" -ForegroundColor Yellow
                }
                throw "Copy-VMFile not ready within 5 minutes: $($_.Exception.Message)"
            }
            Write-Host '[vm-run] guest file-copy service not ready yet; retrying in 30 s...' -ForegroundColor Gray
            Start-Sleep -Seconds 30
        }
    }
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
    #     child's exit code is read as $LASTEXITCODE INSIDE the session
    #     and returned as the session's only pipeline value while its
    #     output STREAMS to the host console line by line (see the comment
    #     below for why it must not be captured). Any nonzero guest exit
    #     (0 only is success; run-in-vm.ps1 exits 1 or 99 on failure)
    #     surfaces as harness exit 1 (see the help exit-code table).
    #     In -TestCmd mode the guest command is the operator's string
    #     instead; the harness pre-creates C:\sbx-results and tees the
    #     streamed lines into C:\sbx-results\testcmd.log so the console
    #     transcript is fetched as an artifact too (step 11 fetches ALL
    #     files there in this mode).
    # -----------------------------------------------------------------------
    if ($TestCmd) {
        $guestCommand = $TestCmd
        $teeToLog = $true
    } else {
        $escapedRunner = 'C:\sbx-repo\tests\vm\run-in-vm.ps1'.Replace("'", "''")
        $guestCommand = "& '$escapedRunner' -Phase '$Phase' -RepoDir 'C:\sbx-repo' -ResultsDir 'C:\sbx-results'"
        if ($Only) { $guestCommand += ' -Only ' + ($Only -join ',') }
        $teeToLog = $false
    }
    Write-Host "[vm-run] guest command: pwsh -NoProfile -Command $guestCommand"

    # Window-station/desktop AAP grant helper for the guest suite session.
    # PS-Direct sessions run on a Service-0x0-*$ window station whose SD
    # carries NO ALL APPLICATION PACKAGES ACE, so sandboxed children that
    # touch user32 (venv/ensurepip's subprocess, ctypes, ...) die with
    # 0xC0000142 and S-9 fails at ensurepip. Interactive WinSta0 carries
    # the ACEs, which is why the same suite passes on the host. Grant AAP
    # GA on the session's winsta + desktop before running the suite -
    # identical to the round-5 battery and tests/vm/confirm-s9-winsta.ps1
    # (verified in-VM 2026-10-12: with the grant, S-9 r1/venv creation
    # passes). The grant lives only in this logon session and evaporates
    # with it; the VM is disposable either way.
    $winstaHelper = @'
using System;
using System.Runtime.InteropServices;

public static class WinSta {
    [DllImport("user32.dll", SetLastError = true)]
    public static extern IntPtr GetProcessWindowStation();
    [DllImport("user32.dll", SetLastError = true)]
    public static extern IntPtr GetThreadDesktop(uint dwThreadId);
    [DllImport("kernel32.dll")]
    public static extern uint GetCurrentThreadId();
    [DllImport("user32.dll", SetLastError = true)]
    public static extern bool GetUserObjectSecurity(IntPtr hObj, ref uint pSecurityInformation, IntPtr pSecurityDescriptor, uint nLength, out uint lpnLengthNeeded);
    [DllImport("user32.dll", SetLastError = true)]
    public static extern bool SetUserObjectSecurity(IntPtr hObj, ref uint SecurityInformation, IntPtr pSecurityDescriptor);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool ConvertSecurityDescriptorToStringSecurityDescriptorW(IntPtr SecurityDescriptor, uint RequestedRevision, uint SecurityInformation, out IntPtr SecurityDescriptorString, out uint SecurityDescriptorStringLength);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(string StringSecurityDescriptor, uint StringSecurityDescriptorRevision, out IntPtr SecurityDescriptor, out uint SecurityDescriptorSize);
    [DllImport("kernel32.dll")]
    public static extern IntPtr LocalFree(IntPtr hMem);

    public const uint DACL_SI = 0x00000004;

    public static string GetSddl(IntPtr hObj) {
        uint si = DACL_SI;
        uint needed;
        GetUserObjectSecurity(hObj, ref si, IntPtr.Zero, 0, out needed);
        if (needed == 0) return "ERR zero length";
        IntPtr sd = Marshal.AllocHGlobal((int)needed);
        string sddl = null;
        try {
            if (!GetUserObjectSecurity(hObj, ref si, sd, needed, out needed)) {
                return "ERR " + Marshal.GetLastWin32Error();
            }
            IntPtr strPtr;
            uint strLen;
            if (ConvertSecurityDescriptorToStringSecurityDescriptorW(sd, 1, si, out strPtr, out strLen)) {
                sddl = Marshal.PtrToStringUni(strPtr);
                LocalFree(strPtr);
            } else {
                sddl = "ERR-conv " + Marshal.GetLastWin32Error();
            }
        } finally {
            Marshal.FreeHGlobal(sd);
        }
        return sddl;
    }

    public static string Grant(IntPtr hObj, string ace) {
        string s = GetSddl(hObj);
        if (s == null || s.StartsWith("ERR")) return "dump failed: " + s;
        int di = s.IndexOf("D:");
        if (di < 0) return "no DACL section in SDDL: " + s;
        int paren = s.IndexOf('(', di);
        string mod = paren < 0 ? s + "D:" + ace : s.Insert(paren, ace);
        IntPtr sd;
        uint size;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(mod, 1, out sd, out size)) {
            return "convert failed: " + Marshal.GetLastWin32Error();
        }
        uint si = DACL_SI;
        bool ok = SetUserObjectSecurity(hObj, ref si, sd);
        int err = Marshal.GetLastWin32Error();
        LocalFree(sd);
        return ok ? "OK" : ("SetUserObjectSecurity failed gle=" + err);
    }
}
'@
    # STREAM each suite line via Write-Host (Information stream) instead of
    # accumulating an in-memory array: the full suite output (cargo + unit
    # tests + the integration suite) plus the cargo build's own memory
    # peaks converge on the guest's PS Direct session host, and Windows
    # terminated it mid-suite ('Der Hyper-V-Socket-Zielprozess wurde
    # beendet', 2026-10-10) even though the guest and the suite survived.
    # The full output still lives in C:\sbx-results\*.log (fetched in step
    # 11); the exit code stays the only pipeline value. A session death no
    # longer aborts the run: the step-11 fetch must always run so results
    # are never stranded in a VM this harness is about to destroy.
    $guestExit = $null
    try {
        $guestExit = Invoke-Command -VMName $vmName -Credential $guestCred -ScriptBlock {
            param([string]$Command, [string]$WinstaHelper, [bool]$TeeToLog)
            # TestCmd mode artifact dir (run-in-vm.ps1 creates it for suite
            # runs; a raw probe command must not have to). Best effort: a
            # failure surfaces as the tee's Add-Content error below.
            if ($TeeToLog) {
                New-Item -ItemType Directory -Path 'C:\sbx-results' -Force | Out-Null
            }
            # Grant ALL APPLICATION PACKAGES GA on this session's window
            # station + desktop BEFORE the suite: the suite's pwsh child
            # stays in this logon session, so every sandboxed process it
            # spawns runs against the granted winsta (see the host-side
            # comment for the full rationale). Non-fatal on failure - only
            # the win32k-dependent scenarios (S-9) need it.
            try {
                Add-Type -TypeDefinition $WinstaHelper
                $wsHandle = [WinSta]::GetProcessWindowStation()
                $dtHandle = [WinSta]::GetThreadDesktop([WinSta]::GetCurrentThreadId())
                $aap = '(A;;GA;;;S-1-15-2-1)'
                $wsGrant = [WinSta]::Grant($wsHandle, $aap)
                $dtGrant = [WinSta]::Grant($dtHandle, $aap)
                Write-Host "[vm-guest] winsta AAP grant: winsta=$wsGrant desktop=$dtGrant"
                if ($wsGrant -ne 'OK' -or $dtGrant -ne 'OK') {
                    Write-Host "[vm-guest] WARNING: winsta/desktop AAP grant failed - S-9 (venv/ensurepip) will likely fail"
                }
            } catch {
                Write-Host "[vm-guest] WARNING: winsta grant helper failed: $($_.Exception.Message)"
            }
            & pwsh -NoProfile -Command $Command 2>&1 | ForEach-Object {
                # NOTE: StartsWith, not -like: '[vm-guest]*' is an INVALID
                # wildcard pattern ([...] is a char class) — with EAP=Stop
                # this error record once killed the whole streaming session.
                if ($_.StartsWith('[vm-guest]')) { Write-Host $_ } else { Write-Host "[vm-guest] $_" }
                if ($TeeToLog) {
                    # [string] on a pipeline object flattens ErrorRecords to
                    # their message; the raw line (without the [vm-guest]
                    # prefix) is what lands in the log.
                    Add-Content -LiteralPath (Join-Path 'C:\sbx-results' 'testcmd.log') -Value ([string]$_)
                }
            }
            $LASTEXITCODE
        } -ArgumentList $guestCommand, $winstaHelper, $teeToLog
    } catch {
        Write-Host "[vm-run] ERROR: suite session died: $($_.Exception.Message)" -ForegroundColor Red
    }
    Write-Host ("[vm-run] guest suite finished (exit {0})." -f $(if ($null -ne $guestExit) { $guestExit } else { 'unknown' }))

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
            param([string[]]$KnownArtifacts, [bool]$AllArtifacts)
            $resultsRoot = 'C:\sbx-results'
            if ($AllArtifacts) {
                # TestCmd mode: no summary.json contract exists - fetch
                # EVERY file the command left behind.
                if (Test-Path -LiteralPath $resultsRoot) {
                    return @(Get-ChildItem -LiteralPath $resultsRoot -File |
                        ForEach-Object { [System.IO.Path]::GetFileName($_.Name) })
                }
                return @()
            }
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
        } -ArgumentList @('build.log', 'unit.log', 'integration.log', 'guest-metrics.log', 'summary.json'), ([bool]$TestCmd)

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
    } elseif ($TestCmd) {
        Write-Host "[vm-run] artifacts fetched to $hostResultsDir (TestCmd mode has no summary.json - all files fetched)."
    } else {
        Write-Host '[vm-run] WARNING: summary.json was not produced by the guest run - the suite died before completion.' -ForegroundColor Yellow
    }

    # -----------------------------------------------------------------------
    # 12. Teardown decision (checkpoint 'failed-run' when kept, the VM is
    #     left running; step 11's failure path already exited above, so a
    #     fetch failure never reaches this destruction).
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
    if ($TestCmd) {
        $guestExitLabel = if ($null -ne $guestExit) { [string]$guestExit } else { 'unknown' }
        Write-Host '[vm-run] mode:          testcmd'
        Write-Host ("[vm-run] guest exit:    {0}" -f $guestExitLabel)
        $fetchedCount = @(Get-ChildItem -LiteralPath $hostResultsDir -File -ErrorAction SilentlyContinue).Count
        Write-Host ("[vm-run] artifacts:    {0} file(s)" -f $fetchedCount)
    } elseif ($summary) {
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
