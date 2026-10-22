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
  With -AsStandardUser the lane runs a NETWORK SUBSET of the integration suite
  as a NON-ADMIN guest account instead of as the interactive admin. Why the
  lane exists: every session the admin lane starts is elevated, so that lane
  can never falsify the P3 premise "egress works without administrator" - a
  green verdict there is a green run of the opposite condition. The lane
  creates (or resets) a local account 'sbx-su' with a per-run RANDOM password,
  member of Users only, grants it read+execute+modify on the staged repo copy
  and on C:\sbx-results (and read+execute on the toolchain roots when they live
  in a profile) and nothing else, then runs
  tests\vm\standard-user-run.ps1 as that account via Start-Process -Credential
  with -Wait, output redirected to files and the exit code captured. That
  runner is the lane's contract: it refuses to report PASS unless (a) its own
  TokenElevation is false AND every SESSION_START leaf of the run says
  elevated=false, (b) the executed scenario count equals the requested subset
  (a filter that matches nothing exits 0), and (c) the PASS details carry a
  REAL proxy decision in both directions (an admitted CONNECT and a refused
  one). The account and its profile directory are deleted before the verdict,
  and a failed deletion fails the harness: the differencing disk is
  disposable, but a lane that leaks guest state between runs is not.
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
  (exception: exit 2, the privilege gate, which prints only its
  remediation lines).

  Exit codes:
    0  = suite passed AND teardown succeeded (final line: VM HARNESS: PASS)
    1  = the in-VM run failed or could not be completed - any nonzero
         guest exit code (INCLUDING run-in-vm.ps1's 99) surfaces here -
         guest PowerShell Direct readiness timeout, guest credential
         rejection, repo copy verification failure, artifact fetch failure
         (the VM is then kept), or teardown failed
         (final line: VM HARNESS: FAIL)
    2  = the token is neither Administrator nor a member of the Hyper-V
         Administrators group (S-1-5-32-578) - remediation lines, no verdict
    3  = host readiness probe failed, the requested template image is
         missing or invalid, -TestCmd is empty/whitespace, or the flag
         combination is refused (-AsStandardUser with -TestCmd, with -Phase
         unit, with -Backend appcontainer, or with a -Only that selects none
         of the standard-user subset)
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
.PARAMETER Backend
  Containment backend passed to the guest suite: appcontainer (default) or
  mxc. mxc requires the feature build; run-in-vm.ps1 adds
  --features mxc-backend itself. -AsStandardUser forces mxc (passing
  'appcontainer' explicitly with it is refused: the AppContainer path needs
  the admin loopback exemption that a standard user does not have, so the
  combination would test the wrong thing).
.PARAMETER AsStandardUser
  Run the standard-user network lane instead of the admin suite: a fixed
  NETWORK SUBSET of scenarios, as a fresh non-admin guest account, with the
  elevation and proxy-decision assertions enforced from inside. Integration
  phase only. The first line of the run summary is then
  'standard-user: pass=N fail=N skip=N', separate from the admin lane's own
  counts, and summary.json records lane=standard-user + backend=mxc.
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

    [ValidateSet('appcontainer', 'mxc')]
    [string]$Backend = 'appcontainer',

    [switch]$AsStandardUser,

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
# Standard-user lane (P3.1).
#
# The NETWORK subset is a deliberate list, not "the suite minus whatever
# fails": every entry asserts the PROXY's DECISION (an audit leaf and/or
# %{http_connect}), which is the only evidence a backend change cannot fake,
# and none of them needs the AppContainer loopback exemption or an admin
# token. S-94 is the elevation leaf itself. Excluded on purpose: S-30/S-31
# (their PASS condition is `curl failed + http_code 000`, which every
# transport failure satisfies - exactly the false pass this lane must not
# inherit), S-35 (two concurrent runs; mxc refuses concurrency by design),
# S-36/S-90/S-91/S-92 (token-gate / loopback-refusal / manual: whether the
# AppContainer-era 407 gate sits on the mxc path is a PRODUCT question this
# harness must not prejudge), and every AppContainer-only scenario in
# tests\run-tests.ps1's $script:AppContainerOnlyScenarios.
$script:StandardUserScenarioIds = @(27, 28, 29, 32, 33, 34, 87, 94)
$script:StandardUserName = 'sbx-su'
$script:SuLanePrepared = $false
$script:SuLaneRemoved = $false
$script:SuCleanupFailed = $false

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

# ---------------------------------------------------------------------------
# STANDARD-USER LANE (P3.1)
#
# Three functions, one per phase, because each runs in a DIFFERENT security
# context and conflating them is how a lane ends up proving nothing:
#   Invoke-StandardUserLane - as the guest ADMIN (via PowerShell Direct): create
#     the account, grant it the minimum, launch the suite as it, return its exit
#     code. The password is generated per run, never printed, and only exists in
#     this process's memory and the in-guest PSCredential.
#   Remove-StandardUser    - as the guest ADMIN: delete the account AND its
#     profile directory, and verify both are gone.
#   Get-StandardUserEvidence - host side: re-read the fetched artifacts so the
#     verdict does not rest on the guest's own word alone.
# ---------------------------------------------------------------------------
function Invoke-StandardUserLane {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$VmName,
        [Parameter(Mandatory)][System.Management.Automation.PSCredential]$GuestCred,
        [Parameter(Mandatory)][int[]]$ScenarioIds,
        [Parameter(Mandatory)][string]$Backend,
        [string]$RepoDir = 'C:\sbx-repo',
        [string]$ResultsDir = 'C:\sbx-results'
    )

    $userName = $script:StandardUserName

    # ---- 1. account + grants, one admin session ---------------------------
    $prep = Invoke-Command -VMName $VmName -Credential $GuestCred -ScriptBlock {
        param([string]$UserName, [string]$RepoDir, [string]$ResultsDir)
        $ErrorActionPreference = 'Stop'
        $notes = New-Object System.Collections.Generic.List[string]

        # Per-run RANDOM password. Never printed, never written to disk, and
        # regenerated on every run so a reset account cannot be logged into
        # with an earlier run's credential.
        $bytes = New-Object byte[] 30
        [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
        $password = 'Sbx-' + [Convert]::ToBase64String($bytes) + '!7a'
        $secure = ConvertTo-SecureString -String $password -AsPlainText -Force

        $existing = Get-LocalUser -Name $UserName -ErrorAction SilentlyContinue
        if ($existing) {
            Set-LocalUser -Name $UserName -Password $secure -PasswordNeverExpires $true -AccountNeverExpires $true
            Enable-LocalUser -Name $UserName
            $notes.Add('reset the existing account with a fresh random password')
        } else {
            New-LocalUser -Name $UserName -Password $secure -PasswordNeverExpires -AccountNeverExpires -Description 'sandbox test harness standard user (per-run)' | Out-Null
            $notes.Add('created the account with a fresh random password')
        }
        $user = Get-LocalUser -Name $UserName
        if (-not $user.Enabled) { Enable-LocalUser -Name $UserName }
        $sid = $user.SID.Value

        # Membership by SID (localized names are a trap on this host: the
        # German images call Administrators 'Administratoren').
        $usersGroup = Get-LocalGroup -SID 'S-1-5-32-545'
        $adminsGroup = Get-LocalGroup -SID 'S-1-5-32-544'
        $inAdmins = @(Get-LocalGroupMember -Group $adminsGroup -ErrorAction SilentlyContinue | Where-Object { $_.SID.Value -eq $sid })
        if ($inAdmins.Count -gt 0) {
            Remove-LocalGroupMember -Group $adminsGroup -Member $UserName -ErrorAction SilentlyContinue
            $notes.Add('removed the account from Administrators')
        }
        $inUsers = @(Get-LocalGroupMember -Group $usersGroup -ErrorAction SilentlyContinue | Where-Object { $_.SID.Value -eq $sid })
        if ($inUsers.Count -eq 0) { Add-LocalGroupMember -Group $usersGroup -Member $UserName -ErrorAction SilentlyContinue }
        $groupsOf = @(Get-LocalGroup -ErrorAction SilentlyContinue | Where-Object {
                @(Get-LocalGroupMember -Group $_ -ErrorAction SilentlyContinue | Where-Object { $_.SID.Value -eq $sid }).Count -gt 0 } |
            ForEach-Object { $_.SID.Value })

        # Grants: the staged repo copy (it must BUILD and write its own
        # artifacts there) and the results dir. Nothing else - no drive-wide ACE.
        # (OI)(CI) inheritance covers files the build creates later; the ACE is
        # re-read from the SDDL below, so an icacls that silently did nothing
        # fails the lane instead of surfacing as a confusing build error.
        if (-not (Test-Path -LiteralPath $ResultsDir)) { New-Item -ItemType Directory -Path $ResultsDir -Force | Out-Null }
        $grantTargets = @($RepoDir, $ResultsDir)
        foreach ($target in $grantTargets) { & icacls $target /grant "*${sid}:(OI)(CI)M" /Q /C 2>&1 | Out-Null }
        $grantMissing = @()
        foreach ($target in $grantTargets) {
            $sddl = (Get-Acl -LiteralPath $target).Sddl
            if ($sddl -notmatch [regex]::Escape($sid)) { $grantMissing += $target }
        }

        # Toolchain: a per-user rustup install lives in another profile, so the
        # account needs READ+EXECUTE on it (never modify). Read-only grants on
        # exactly the toolchain roots, reported by name.
        $toolchainBin = $null; $rustupHome = $null; $cargoHome = $null
        $cargo = Get-Command cargo -ErrorAction SilentlyContinue
        if ($cargo) {
            $toolchainBin = Split-Path -Parent $cargo.Source
            $toolchainRoot = Split-Path -Parent $toolchainBin
            if ($toolchainRoot -like 'C:\Users\*') {
                & icacls $toolchainRoot /grant "*${sid}:(OI)(CI)RX" /T /C /Q 2>&1 | Out-Null
                $notes.Add("read+execute on the toolchain root $toolchainRoot (outside this run's staging; read-only)")
            }
            $candidateRustup = Join-Path $env:USERPROFILE '.rustup'
            if (Test-Path -LiteralPath $candidateRustup) {
                & icacls $candidateRustup /grant "*${sid}:(OI)(CI)RX" /T /C /Q 2>&1 | Out-Null
                $rustupHome = $candidateRustup
                $notes.Add("RUSTUP_HOME=$candidateRustup (read+execute)")
            }
        } else {
            $notes.Add('WARNING: cargo is not on the machine PATH - the standard user will not be able to build')
        }
        # Writable CARGO_HOME outside every profile, seeded from the admin's
        # registry cache so the mxc feature build does not have to re-download.
        $cargoHome = 'C:\sbx-cargo'
        New-Item -ItemType Directory -Path $cargoHome -Force | Out-Null
        $adminCargo = Join-Path $env:USERPROFILE '.cargo'
        if (Test-Path -LiteralPath $adminCargo) {
            & robocopy $adminCargo $cargoHome /E /NFL /NDL /NJH /NJS /R:1 /W:1 | Out-Null
            $notes.Add("seeded CARGO_HOME=$cargoHome from $adminCargo")
        }
        & icacls $cargoHome /grant "*${sid}:(OI)(CI)M" /Q /C 2>&1 | Out-Null
        # Remote Desktop Users (S-1-5-32-555), matched by SID: on this German
        # host the group is 'Remotedesktopbenutzer', and a lookup by the English
        # name fails with 1376 for a group that exists (the same trap as
        # Hyper-V-Administratoren). A bare local user is only in Users, which
        # carries interactive - not REMOTE interactive - logon, so an RDP
        # sign-in as the lane account is refused until this membership exists.
        # The lane needs it to obtain the PROFILE (the launch mechanism below
        # depends on a profile existing); the Hyper-V console would not.
        $rdpGroup = Get-LocalGroup -ErrorAction SilentlyContinue |
            Where-Object { $_.SID.Value -eq 'S-1-5-32-555' } | Select-Object -First 1
        if ($rdpGroup) {
            try {
                Add-LocalGroupMember -Group $rdpGroup -Member $UserName -ErrorAction Stop
                $notes.Add("member of $($rdpGroup.Name) (S-1-5-32-555, for the profile-creating sign-in)")
            } catch {
                $notes.Add("could not add $UserName to $($rdpGroup.Name): $($_.Exception.Message)")
            }
        } else {
            $notes.Add('WARNING: no group with SID S-1-5-32-555 on this guest; the lane account cannot sign in over RDP')
        }
        # The lane's own trees: it builds inside the staging dir and writes its
        # artifacts into the results dir, so both need modify for this account.
        # Without this the .cmd's redirect and the suite's own logs fail with
        # access denied - which looks like a lane defect, not a grant defect.
        foreach ($p in @($RepoDir, $ResultsDir)) {
            if (Test-Path -LiteralPath $p) {
                & icacls $p /grant "*${sid}:(OI)(CI)M" /T /C /Q 2>&1 | Out-Null
                $notes.Add("read+write on $p (lane staging/results)")
            }
        }

        [pscustomobject]@{
            User         = $UserName
            Password     = $password
            Sid          = $sid
            Groups       = @($groupsOf)
            GrantMissing = @($grantMissing)
            ToolchainBin = $toolchainBin
            RustupHome   = $rustupHome
            CargoHome    = $cargoHome
            Notes        = @($notes)
        }
    } -ArgumentList $userName, $RepoDir, $ResultsDir

    foreach ($n in @($prep.Notes)) { Write-Host "[su-lane] prep: $n" -ForegroundColor DarkGray }
    Write-Host ("[su-lane] account: {0} (SID {1}) groups: {2}" -f $prep.User, $prep.Sid, (@($prep.Groups) -join ','))
    if (@($prep.GrantMissing).Count -gt 0) {
        throw ("the standard-user grant did not land on: {0} (icacls reported success or silence, the DACL says otherwise)" -f (@($prep.GrantMissing) -join ', '))
    }
    if (@($prep.Groups) -contains 'S-1-5-32-544') {
        throw "refusing to run the unelevated lane: $($prep.User) is a member of Administrators (S-1-5-32-544)"
    }
    $script:SuLanePrepared = $true

    # ---- 2. the suite, AS THAT USER ---------------------------------------
    $runner = Join-Path $RepoDir 'tests\vm\standard-user-run.ps1'
    $suExit = Invoke-Command -VMName $VmName -Credential $GuestCred -ScriptBlock {
        param($UserName, $Password, $Runner, $RepoDir, $ResultsDir, $Backend, $ScenarioIdList,
              $LogFile, $ToolchainBin, $RustupHome, $CargoHome)
        $ErrorActionPreference = 'Stop'
        $tracePath = Join-Path (Split-Path -Parent $LogFile) 'su-launch-trace.log'
        function Trace([string]$m) {
            try { Add-Content -LiteralPath $tracePath -Value ((Get-Date).ToString('HH:mm:ss') + ' ' + $m) } catch { }
        }
        Trace 'guest: launch block entered'

        if (-not (Test-Path -LiteralPath $Runner)) { throw "standard-user runner not found in the guest: $Runner" }
        try {
        # Start-Process -Credential is CreateProcessWithLogonW, which needs the
        # Secondary Logon service. It is trigger-started and a remote session
        # does not reliably start it on demand, so start it explicitly and fail
        # with a named reason rather than a generic Win32 error.
        Start-Service seclogon -ErrorAction SilentlyContinue
        $svc = Get-Service seclogon -ErrorAction SilentlyContinue
        if (-not $svc -or $svc.Status -ne 'Running') {
            throw 'the Secondary Logon service (seclogon) is not running - Start-Process -Credential cannot create the standard-user logon'
        }
        $secureSu = ConvertTo-SecureString -String $Password -AsPlainText -Force
        $suCred = New-Object System.Management.Automation.PSCredential($UserName, $secureSu)
        $spArgs = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $Runner,
            '-RepoDir', $RepoDir, '-ResultsDir', $ResultsDir,
            '-ScenarioIds', $ScenarioIdList, '-Backend', $Backend)
        if ($ToolchainBin) { $spArgs += @('-ToolchainBin', $ToolchainBin) }
        if ($RustupHome) { $spArgs += @('-RustupHome', $RustupHome) }
        if ($CargoHome) { $spArgs += @('-CargoHome', $CargoHome) }
        $spArgs += @('-LogPath', $LogFile)
        # Resolve pwsh to a full path: the task launches it directly, and a
        # bare image name is not resolved the way an interactive spawn is.
        $pwshPath = (Get-Command -Name pwsh -CommandType Application -ErrorAction Stop |
            Select-Object -First 1).Source
        if (-not (Test-Path -LiteralPath $pwshPath)) {
            throw "pwsh was not found as an application for the standard-user launch (got '$pwshPath')"
        }
        # PREFERRED: Start-Process -Credential with -LoadUserProfile.
        # This only works when the account already HAS a profile - the base
        # image now ships sbx-su with one (created by an interactive sign-in),
        # which is what CreateProcessWithLogonW needs; a minutes-old account
        # with no profile is what returned ERROR_INVALID_PARAMETER (87) before.
        # Redirection stays off (that API inherits no handles); the child owns
        # its transcript via -LogPath.
        try {
            $proc = Start-Process -FilePath $pwshPath -Credential $suCred -LoadUserProfile `
                -WorkingDirectory $RepoDir -ArgumentList $spArgs -Wait -PassThru -ErrorAction Stop
            Trace ("Start-Process -Credential -LoadUserProfile: exit {0}" -f $proc.ExitCode)
            return [int]$proc.ExitCode
        } catch {
            Trace ("Start-Process -Credential failed: {0} - falling back to a scheduled task" -f $_.Exception.Message)
        }
        # FALLBACK: a scheduled task.
        # LAUNCH: a scheduled task, NOT Start-Process -Credential.
        #
        # Start-Process -Credential goes through CreateProcessWithLogonW, which
        # cannot create this logon from a PowerShell Direct session: it returns
        # ERROR_INVALID_PARAMETER (87, "This command cannot be run due to the
        # error: The parameter is incorrect") before pwsh starts - observed with
        # and without redirection, with -LoadUserProfile, and with a full image
        # path (all four variants, 2026-10-22; the guest logs were empty each
        # time). Task Scheduler creates the logon itself, needs no window
        # station, and reports the child's own exit code as LastTaskResult,
        # which is what the lane asserts on.
        #
        # The task runs a tiny .cmd rather than the pwsh command line:
        # registering the full argument list fails with ERROR_FILENAME_EXCED_RANGE
        # ('The filename or extension is too long') because Task Scheduler caps
        # the action's Arguments field. The .cmd also produces a console log for
        # the case where pwsh itself refuses to start - a transcript cannot
        # record a process that never ran.
        $argumentLine = (@($spArgs) | ForEach-Object {
                if ($_ -match '[\s"]') { '"' + ($_ -replace '"', '\"') + '"' } else { $_ }
            }) -join ' '
        $consoleLog = Join-Path $ResultsDir 'su-console.log'
        $cmdPath = 'C:\sbx-su-launch.cmd'
        $cmdBody = @(
            '@echo off'
            ('"{0}" {1} > "{2}" 2>&1' -f $pwshPath, $argumentLine, $consoleLog)
            'exit /b %ERRORLEVEL%'
        ) -join "`r`n"
        Set-Content -LiteralPath $cmdPath -Value $cmdBody -Encoding ASCII
        $taskName = 'sbx-standard-user-lane'
        # Delete only if it EXISTS: schtasks /Delete on a missing task exits 1
        # ('The system cannot find the file specified'), and this script sets
        # $PSNativeCommandUseErrorActionPreference, so that exit is a TERMINATING
        # error - it killed the lane three times while the message pointed at
        # the create call.
        if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
            & schtasks.exe /Delete /TN $taskName /F *> $null
        }
        # schtasks.exe, NOT Register-ScheduledTask: the cmdlet throws
        # ERROR_FILENAME_EXCED_RANGE ('The filename or extension is too long')
        # here even with a two-word action argument, i.e. the limit is inside
        # its own XML marshalling, not in what we asked for. The read-only
        # cmdlets below are used for polling because their state strings are
        # locale-independent (this guest is German: schtasks would report
        # 'Wird ausgeführt', not 'Running').
        # /TR takes 'program args' as ONE string and does not accept nested
        # quotes: '"cmd.exe" /c "x.cmd"' is read as a program literally named
        # with the quotes and fails with 'The system cannot find the file
        # specified'. Neither path has a space, so no quotes are needed.
        # schtasks parses /TR itself: an UNQUOTED program path with arguments is
        # taken as one enormous filename ("The filename or extension is too
        # long"), while quoting BOTH tokens makes it look for a program named
        # with quotes ("cannot find the file specified"). Quote the executable
        # only; the script path has no spaces so it needs none.
        $tr = '"C:\Windows\System32\cmd.exe" /c ' + $cmdPath
        # schtasks.exe writes ADVISORIES to stderr ('Task may not run because
        # /ST is earlier than current time') and this script runs with
        # $ErrorActionPreference = 'Stop': once `2>&1` merges that stream the
        # advisory becomes an error record and TERMINATES the block even though
        # the command succeeded (observed three times). The preference is
        # relaxed for exactly these calls, which are judged by $LASTEXITCODE
        # immediately afterwards.
        $savedEap = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        $PSNativeCommandUseErrorActionPreference = $false
        $createOut = & schtasks.exe /Create /TN $taskName /TR $tr `
            /SC ONCE /ST 00:00 /RU $UserName /RP $Password /RL LIMITED /F 2>&1
        $createExit = $LASTEXITCODE
        if ($createExit -ne 0) {
            throw ("schtasks /Create failed (exit {0}): {1}" -f $createExit, ($createOut -join ' '))
        }
        Trace 'task created'
        $runOut = & schtasks.exe /Run /TN $taskName 2>&1
        $runExit = $LASTEXITCODE
        if ($runExit -ne 0) {
            throw ("schtasks /Run failed (exit {0}): {1}" -f $runExit, ($runOut -join ' '))
        }
        $ErrorActionPreference = $savedEap
        $PSNativeCommandUseErrorActionPreference = $true
        $deadline = (Get-Date).AddHours(2)
        do {
            Start-Sleep -Seconds 3
            $state = (Get-ScheduledTask -TaskName $taskName -ErrorAction Stop).State
        } while ($state -eq 'Running' -and (Get-Date) -lt $deadline)
        $info = Get-ScheduledTaskInfo -TaskName $taskName
        $code = [int]$info.LastTaskResult
        if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
            & schtasks.exe /Delete /TN $taskName /F *> $null
        }
        Trace ("task result {0} state {1}" -f $code, $state)
        Write-Host ("[su-lane] task result: {0} (state {1})" -f $code, $state)
        return $code
        } catch {
            Trace ("EXCEPTION line {0}: {1}" -f $_.InvocationInfo.ScriptLineNumber, $_.Exception.Message)
            throw "su-launch failed at guest line $($_.InvocationInfo.ScriptLineNumber): $($_.Exception.Message)"
        }
    } -ArgumentList $userName, [string]$prep.Password, $runner, $RepoDir, $ResultsDir, $Backend,
        ($ScenarioIds -join ','), (Join-Path $ResultsDir 'su-run.log'),
        [string]$prep.ToolchainBin, [string]$prep.RustupHome, [string]$prep.CargoHome

    Write-Host ("[su-lane] suite exit as {0}: {1}" -f $userName, $suExit)
    # Show the tail of the transcript now: the full file is fetched with the
    # other artifacts, but the operator watching a live run wants the last word
    # of the lane without waiting for the fetch.
    try {
        $tail = Invoke-Command -VMName $VmName -Credential $GuestCred -ScriptBlock {
            param([string]$Path)
            if (-not (Test-Path -LiteralPath $Path)) { return @() }
            @(Get-Content -LiteralPath $Path -Tail 40)
        } -ArgumentList (Join-Path $ResultsDir 'su-run.log')
        foreach ($l in @($tail)) { Write-Host "[su-lane] $l" -ForegroundColor Gray }
    } catch { Write-Host "[su-lane] could not read the standard-user transcript: $($_.Exception.Message)" -ForegroundColor Yellow }

    return [int]$suExit
}

function Remove-StandardUser {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$VmName,
        [Parameter(Mandatory)][System.Management.Automation.PSCredential]$GuestCred,
        [Parameter(Mandatory)][string]$UserName
    )
    try {
        return [string](Invoke-Command -VMName $VmName -Credential $GuestCred -ScriptBlock {
                param([string]$UserName)
                $u = Get-LocalUser -Name $UserName -ErrorAction SilentlyContinue
                if (-not $u) { return 'absent' }
                $sid = $u.SID.Value
                $profileDir = Join-Path 'C:\Users' $UserName
                Remove-LocalUser -Name $UserName -ErrorAction Stop
                # The profile must go too, or the image carries the account's state
                # into the next run (and its audit store with it). Right after the
                # account's processes exit the profile can still be marked in-use
                # for a few seconds, so retry a BOUNDED number of times instead of
                # failing the harness on a lock that clears itself. The assertion
                # is unchanged: all three facts must be gone before 'removed'.
                $attempt = 0
                while ($attempt -lt 5) {
                    $attempt++
                    $profiles = @(Get-CimInstance -ClassName Win32_UserProfile -ErrorAction SilentlyContinue |
                        Where-Object { $_.SID -eq $sid })
                    foreach ($prof in $profiles) { Remove-CimInstance -InputObject $prof -ErrorAction SilentlyContinue }
                    if (Test-Path -LiteralPath $profileDir) {
                        Remove-Item -LiteralPath $profileDir -Recurse -Force -ErrorAction SilentlyContinue
                    }
                    $stillUser = [bool](Get-LocalUser -Name $UserName -ErrorAction SilentlyContinue)
                    $stillDir = Test-Path -LiteralPath $profileDir
                    $stillProfile = @(Get-CimInstance -ClassName Win32_UserProfile -ErrorAction SilentlyContinue |
                        Where-Object { $_.SID -eq $sid })
                    if ((-not $stillUser) -and (-not $stillDir) -and ($stillProfile.Count -eq 0)) { return 'removed' }
                    Start-Sleep -Seconds 2
                }
                $stillProfile = @(Get-CimInstance -ClassName Win32_UserProfile -ErrorAction SilentlyContinue |
                    Where-Object { $_.SID -eq $sid })
                return ("LEFTOVER after {0} attempts: user={1} dir={2} profile={3}" -f $attempt, $stillUser, $stillDir, ($stillProfile.Count -gt 0))
            } -ArgumentList $UserName -ErrorAction Stop)
    } catch {
        return "error $($_.Exception.Message)"
    }
}

function Get-StandardUserEvidence {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ResultsDir)
    $lines = New-Object System.Collections.Generic.List[string]
    $ok = $true
    $identityPath = Join-Path $ResultsDir 'su-identity.txt'
    $leavesPath = Join-Path $ResultsDir 'elevation-leaves.txt'
    $verdictPath = Join-Path $ResultsDir 'su-verdict.txt'

    foreach ($required in @($identityPath, $leavesPath, $verdictPath)) {
        if (-not (Test-Path -LiteralPath $required)) {
            $ok = $false
            $lines.Add("MISSING artifact: $([System.IO.Path]::GetFileName($required)) - the lane did not finish (see su-stdout.log / su-stderr.log)")
        }
    }

    $kv = @{}
    if (Test-Path -LiteralPath $identityPath) {
        foreach ($l in @(Get-Content -LiteralPath $identityPath)) {
            if ($l -match '^([A-Z_]+)=(.*)$') { $kv[$Matches[1]] = $Matches[2] }
        }
        $tokenElev = if ($kv.ContainsKey('TOKEN_ELEVATION')) { [string]$kv['TOKEN_ELEVATION'] } else { '' }
        $adminRole = if ($kv.ContainsKey('IS_IN_ADMIN_ROLE')) { [string]$kv['IS_IN_ADMIN_ROLE'] } else { '' }
        $lines.Add("identity: user=$($kv['USER']) TokenElevation=$tokenElev IsInRole(Administrator)=$adminRole")
        if ($tokenElev -ne 'False') {
            $ok = $false
            $lines.Add('FAIL: the lane process did not report TokenElevation=False')
        }
        if ($adminRole -eq 'True') { $lines.Add('WARNING: the token carries Administrators membership (filtered admin token)') }
    }

    if (Test-Path -LiteralPath $leavesPath) {
        $summaryLine = @(Get-Content -LiteralPath $leavesPath | Where-Object { $_ -match '^SESSION_START_LEAVES=' })[0]
        $lines.Add("leaves: $summaryLine")
        if (-not $summaryLine) {
            $ok = $false
            $lines.Add('FAIL: no SESSION_START_LEAVES line in elevation-leaves.txt')
        } else {
            $n = 0; $et = -1; $em = -1
            if ($summaryLine -match 'SESSION_START_LEAVES=(\d+)') { $n = [int]$Matches[1] }
            if ($summaryLine -match 'elevated_true=(\d+)') { $et = [int]$Matches[1] }
            if ($summaryLine -match 'elevated_missing=(\d+)') { $em = [int]$Matches[1] }
            if ($n -lt 1) { $ok = $false; $lines.Add('FAIL: the run wrote no SESSION_START leaf') }
            if ($et -ne 0) { $ok = $false; $lines.Add("FAIL: $et SESSION_START leaf/leaves report elevated=true") }
            if ($em -ne 0) { $ok = $false; $lines.Add("FAIL: $em SESSION_START leaf/leaves do not carry the elevated key") }
        }
        foreach ($l in @(Get-Content -LiteralPath $leavesPath | Where-Object { $_ -match '^sid=' } | Select-Object -First 20)) { $lines.Add("  $l") }
    }

    if (Test-Path -LiteralPath $verdictPath) {
        $verdictLine = @(Get-Content -LiteralPath $verdictPath | Where-Object { $_ -match '^RESULT=' })[0]
        $reasonLine = @(Get-Content -LiteralPath $verdictPath | Where-Object { $_ -match '^REASON=' })[0]
        $lines.Add("verdict: $verdictLine / $reasonLine")
        if ($verdictLine -ne 'RESULT=PASS') { $ok = $false }
    }

    return @{ Ok = $ok; Lines = @($lines) }
}

try {
    # -----------------------------------------------------------------------
    # 1. Privilege gate - FIRST, before any other validation or setup.
    #
    #    Hyper-V cmdlets authorize on EITHER full Administrator OR membership
    #    in the well-known group S-1-5-32-578 ("Hyper-V Administrators";
    #    localized name, e.g. "Hyper-V-Administratoren" on German Windows).
    #    Accepting the group is the point: it lets the host-side VM lane run
    #    from a normal shell instead of a UAC-elevated one.
    #
    #    Match on the SID, never on the localized name, and never infer absence
    #    from a failed name lookup (an English `net localgroup` on a German
    #    host returns 1376 for a group that exists).
    #
    #    The group is added to a user's token at LOGON: after adding the
    #    account, sign out and back in, or the check still sees the old token.
    # -----------------------------------------------------------------------
    $windowsIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $windowsPrincipal = New-Object Security.Principal.WindowsPrincipal($windowsIdentity)
    $isAdministrator = $windowsPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    $hyperVGroupSid = 'S-1-5-32-578'
    $isHyperVAdmin = $false
    foreach ($group in $windowsIdentity.Groups) {
        if ($group.Value -eq $hyperVGroupSid) { $isHyperVAdmin = $true; break }
    }
    if (-not ($isAdministrator -or $isHyperVAdmin)) {
        Write-Host ('[vm-run] needs Administrator or the Hyper-V Administrators group ({0}) - this token has neither.' -f $hyperVGroupSid) -ForegroundColor Red
        Write-Host '[vm-run] one-time, elevated:  net localgroup "Hyper-V-Administratoren" <user> /add   (then sign out and back in so the token carries it)' -ForegroundColor Yellow
        Write-Host '[vm-run] one-time prep:       tests\vm\Initialize-VMHost.ps1' -ForegroundColor Yellow
        exit 2
    }
    if (-not $isAdministrator) {
        Write-Host '[vm-run] running with Hyper-V Administrators membership (not full Administrator)' -ForegroundColor DarkGray
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
    # 1b. -AsStandardUser is PARKED (2026-10-22): refuse immediately, before any
    #     state change, so a broken lane can never be mistaken for a product
    #     failure. Both non-interactive launch mechanisms available from a
    #     PowerShell Direct session were tried against a re-baked image (account
    #     with a real profile, S-1-5-32-555 membership, fresh password) and both
    #     fail before the child starts:
    #       * Start-Process -Credential (CreateProcessWithLogonW)
    #         -> ERROR_INVALID_PARAMETER (87, 'The parameter is incorrect')
    #            with and without -LoadUserProfile, with redirection removed,
    #            and with a full image path.
    #       * schtasks /Create (Task Scheduler)
    #         -> 'The filename or extension is too long' for every /TR shape,
    #            and Register-ScheduledTask -ErrorAction Stop
    #            -> ERROR_FILENAME_EXCED_RANGE.
    #     The implementation below is kept intact so the work is not lost; two
    #     mechanisms remain untried and are named in
    #     docs/tasks/mxc-migration/PROGRESS.md (P3.1 blocker):
    #     New-CimSession + Win32_Process.Create, and a restricted-token launch.
    #     The elevation claim is currently proven on the HOST (real unelevated
    #     sessions, elevated=false in the leaf) rather than in the VM.
    if ($AsStandardUser) {
        Write-Host '[vm-run] -AsStandardUser is PARKED: the standard-user lane cannot start a process as a second local account from this session (see P3.1 blocker in PROGRESS.md). Nothing was created.' -ForegroundColor Red
        exit 3
    }

    # 1c. -AsStandardUser form gate. Refuse the combinations that would quietly
    #     test the wrong thing, BEFORE anything is created.
    #
    #     * -TestCmd replaces the suite, so there would be no SESSION_START
    #       leaves and no per-scenario decisions for the lane to assert.
    #     * the unit phase builds no sandbox sessions at all.
    #     * -Backend appcontainer needs the admin NetworkIsolation loopback
    #       exemption; a standard user cannot register it, so that combination
    #       cannot answer the question the lane exists for.
    # -----------------------------------------------------------------------
    $suScenarioIds = @()
    if ($AsStandardUser) {
        if ($TestCmd) {
            Write-Host '[vm-run] refused: -AsStandardUser and -TestCmd are incompatible (the lane asserts per-session decisions from a real suite run).' -ForegroundColor Red
            Write-Host 'VM HARNESS: FAIL' -ForegroundColor Red
            exit 3
        }
        if ($Phase -eq 'unit') {
            Write-Host '[vm-run] refused: -AsStandardUser is an INTEGRATION lane; -Phase unit starts no sandbox sessions.' -ForegroundColor Red
            Write-Host 'VM HARNESS: FAIL' -ForegroundColor Red
            exit 3
        }
        if ($PSBoundParameters.ContainsKey('Backend') -and $Backend -ne 'mxc') {
            Write-Host '[vm-run] refused: -AsStandardUser runs the network subset with -Backend mxc; the appcontainer path needs the admin loopback exemption a standard user cannot register.' -ForegroundColor Red
            Write-Host 'VM HARNESS: FAIL' -ForegroundColor Red
            exit 3
        }
        $Backend = 'mxc'
        $suScenarioIds = @($script:StandardUserScenarioIds)
        if ($Only) { $suScenarioIds = @($suScenarioIds | Where-Object { $Only -contains $_ }) }
        if ($suScenarioIds.Count -eq 0) {
            # A filter that matches nothing exits 0 and looks exactly like a
            # lane that ran the whole subset. Refuse before creating anything.
            Write-Host ('[vm-run] refused: -Only {0} selects NONE of the standard-user subset ({1}) - an empty lane would exit 0 and prove nothing.' -f ($Only -join ','), ($script:StandardUserScenarioIds -join ',')) -ForegroundColor Red
            Write-Host 'VM HARNESS: FAIL' -ForegroundColor Red
            exit 3
        }
        Write-Host ('[vm-run] standard-user lane: subset ({0}): {1} | backend mxc' -f $suScenarioIds.Count, (($suScenarioIds | ForEach-Object { "S-$_" }) -join ' ')) -ForegroundColor Cyan
    }

    # -----------------------------------------------------------------------
    # Run identity (computed only past the privilege gate).
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
    # Nested build trees (tests/vm/spikes/*/target) are 2.5 GB of artifacts the
    # guest never needs: they were 5,478 of the 5,478 staged files and 862 MB of
    # the archive, on every run. Discovered as ABSOLUTE paths rather than a bare
    # `/XD target`, because a bare name would exclude same-named directories
    # tree-wide (see the note above).
    $nestedTargets = @(Get-ChildItem -LiteralPath $script:RepoRoot -Directory -Recurse -Filter 'target' -ErrorAction SilentlyContinue |
            Select-Object -ExpandProperty FullName |
            Where-Object { $excludeDirs -notcontains $_ })
    if ($nestedTargets.Count -gt 0) {
        $excludeDirs += $nestedTargets
        Write-Host ("[vm-run] excluding {0} nested target dir(s): {1}" -f $nestedTargets.Count, (($nestedTargets | ForEach-Object { $_.Substring($script:RepoRoot.Length).TrimStart('\') }) -join ', ')) -ForegroundColor DarkGray
    }
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
        # -Backend is passed even when it is the default: the guest then RECORDS
        # the backend it ran (summary.json backend=) instead of leaving the
        # controller to assume it, and a future default flip cannot silently
        # change what an "appcontainer" command line executed.
        $guestCommand = "& '$escapedRunner' -Phase '$Phase' -RepoDir 'C:\sbx-repo' -ResultsDir 'C:\sbx-results' -Backend '$Backend'"
        if ($Only) { $guestCommand += ' -Only ' + ($Only -join ',') }
        $teeToLog = $false
    }
    if ($AsStandardUser) {
        # The suite is NOT started from this admin session: it is launched as
        # the standard user by Invoke-StandardUserLane (step 10b). The label
        # keeps the header honest about what actually runs.
        $guestCommand = ("C:\sbx-repo\tests\vm\standard-user-run.ps1 -RepoDir C:\sbx-repo -ResultsDir C:\sbx-results -ScenarioIds '{0}' -Backend mxc  (launched as {1} via Start-Process -Credential)" -f ($suScenarioIds -join ','), $script:StandardUserName)
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
        if ($AsStandardUser) {
            # 10b. STANDARD-USER lane: the suite runs as the non-admin account
            # in its OWN logon session (Start-Process -Credential), NOT in this
            # admin PowerShell Direct session - that separation is the whole
            # point. Everything the guest admin does around it (prep, grants,
            # teardown) stays in this file.
            $guestExit = Invoke-StandardUserLane -VmName $vmName -GuestCred $guestCred `
                -ScenarioIds $suScenarioIds -Backend $Backend
        } else {
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
        }
    } catch {
        Write-Host "[vm-run] ERROR: suite session died: $($_.Exception.Message)" -ForegroundColor Red
        # The position and stack are what actually identify the failing call:
        # the exception message alone ('The filename or extension is too long',
        # 'The parameter is incorrect') is identical for several different
        # call sites, and guessing at them costs a VM boot per guess.
        if ($_.InvocationInfo) {
            Write-Host "[vm-run]   at: $($_.InvocationInfo.PositionMessage)" -ForegroundColor DarkGray
        }
        if ($_.ScriptStackTrace) {
            Write-Host "[vm-run]   stack: $($_.ScriptStackTrace -replace "`r?`n", ' <- ')" -ForegroundColor DarkGray
        }
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
    # The standard-user lane writes three assertion artifacts plus its own
    # redirected transcript. They are NOT in the guest summary's `artifacts`
    # list (run-in-vm.ps1 does not know about them), so they are appended here
    # explicitly - an artifact the fetch does not name is an artifact the
    # verdict never sees.
    $extraArtifactNames = @()
    if ($AsStandardUser) {
        $extraArtifactNames = @('su-identity.txt', 'elevation-leaves.txt', 'su-verdict.txt', 'su-run.log', 'su-launch-trace.log', 'su-console.log')
    }
    try {
        $artifactNames = Invoke-Command -VMName $vmName -Credential $guestCred -ScriptBlock {
            param([string[]]$KnownArtifacts, [bool]$AllArtifacts, [string[]]$ExtraArtifacts)
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
            foreach ($extra in @($ExtraArtifacts)) {
                if ($extra -and ($ordered -notcontains $extra)) { $ordered += $extra }
            }
            $ordered += 'summary.json'
            return @($ordered | ForEach-Object { [System.IO.Path]::GetFileName($_) })
        } -ArgumentList @('build.log', 'unit.log', 'integration.log', 'guest-metrics.log', 'summary.json'), ([bool]$TestCmd), $extraArtifactNames

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

    # -----------------------------------------------------------------------
    # 12a. STANDARD-USER cleanup - BEFORE the VM teardown (the guest must still
    #      be running to delete the account) and before the verdict (a leaked
    #      account is a harness error, not a footnote). The differencing disk is
    #      disposable, but the NEXT run may reuse this base image, and a reset
    #      account would then carry the previous run's profile - including its
    #      audit store - into a lane that asserts on fresh leaves.
    # -----------------------------------------------------------------------
    if ($AsStandardUser -and $script:SuLanePrepared -and -not $script:SuLaneRemoved) {
        $suRemoval = Remove-StandardUser -VmName $vmName -GuestCred $guestCred -UserName $script:StandardUserName
        $script:SuLaneRemoved = $true
        if ($suRemoval -eq 'removed' -or $suRemoval -eq 'absent') {
            Write-Host ("[vm-run] standard-user account removed: {0} (account + profile dir verified gone)" -f $script:StandardUserName)
        } else {
            $script:SuCleanupFailed = $true
            Write-Host ("[vm-run] WARNING: standard-user cleanup incomplete: {0}" -f $suRemoval) -ForegroundColor Red
            Write-Host ('[vm-run] the image must not leak the account between runs - inspect with: Get-LocalUser -Name {0}; Remove-LocalUser -Name {0}' -f $script:StandardUserName) -ForegroundColor Yellow
        }
    }

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
        Write-Host ("[vm-run] lane:          {0} (backend {1})" -f $summary.lane, $summary.backend)
        Write-Host ("[vm-run] build ok:      {0}" -f $buildOk)
        Write-Host ("[vm-run] unit exit:     {0}" -f $unitExit)
        Write-Host ("[vm-run] integration:   {0}" -f $integrationCounts)
        Write-Host ("[vm-run] verdict:       {0}" -f $verdict)
        Write-Host ("[vm-run] guest osBuild: {0}" -f $osBuild)
        # The lane's counts, on their OWN line: the controller compares
        # `standard-user: pass=N fail=N skip=N` against the admin lane's and
        # must never have to infer which token produced a number.
        if ($AsStandardUser) {
            Write-Host ("[vm-run] standard-user: pass={0} fail={1} skip={2}" -f $summary.integration.pass, $summary.integration.fail, $summary.integration.skip) -ForegroundColor Cyan
        } else {
            Write-Host ("[vm-run] admin lane:    pass={0} fail={1} skip={2}" -f $summary.integration.pass, $summary.integration.fail, $summary.integration.skip)
        }
    } else {
        Write-Host '[vm-run] no summary.json available (the guest run did not complete).'
    }
    Write-Host ("[vm-run] artifacts:     {0}" -f $hostResultsDir)

    # The standard-user lane's central assertions, re-read from the FETCHED
    # artifacts: the guest runner already failed the suite on any of them, but a
    # verdict that only trusts the guest's exit code would accept a run whose
    # artifacts never arrived.
    $suEvidence = @{ Ok = $true; Lines = @() }
    if ($AsStandardUser) {
        $suEvidence = Get-StandardUserEvidence -ResultsDir $hostResultsDir
        Write-Host '[vm-run] ---------------- standard-user assertions ----------------'
        foreach ($l in @($suEvidence.Lines)) {
            $colour = if ($l -match '^(FAIL|MISSING)') { 'Red' } elseif ($l -match '^WARNING') { 'Yellow' } else { 'Gray' }
            Write-Host "[vm-run] $l" -ForegroundColor $colour
        }
        if (-not $suEvidence.Ok) { Write-Host '[vm-run] standard-user assertions FAILED - the lane proves nothing about the unelevated path.' -ForegroundColor Red }
    }
    $harnessPassed = ($suitePassed -and (-not $teardownFailed) -and (-not $script:SuCleanupFailed) -and $suEvidence.Ok)
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
    # Safety net: if the run died before step 12a, still try to delete the
    # standard-user account (the VM may already be gone - then there is nothing
    # to clean and the error is not worth failing over twice).
    if ($AsStandardUser -and $script:SuLanePrepared -and -not $script:SuLaneRemoved -and $vmName) {
        try {
            $suRemovalLate = Remove-StandardUser -VmName $vmName -GuestCred $guestCred -UserName $script:StandardUserName
            $script:SuLaneRemoved = $true
            Write-Host ("[vm-run] standard-user cleanup (late path): {0}" -f $suRemovalLate) -ForegroundColor Yellow
        } catch {
            Write-Host "[vm-run] WARNING: late standard-user cleanup failed: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
    # Host-side staging cleanup (best effort; the guest got its own copy).
    foreach ($tempPath in @($stageDir, $zipPath)) {
        if ($tempPath -and (Test-Path -LiteralPath $tempPath)) {
            Remove-Item -LiteralPath $tempPath -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}
