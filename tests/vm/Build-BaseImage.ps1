#Requires -Version 5.1
<#
.SYNOPSIS
  One-command, interactive base-image build: chains New-BuilderVM.ps1,
  Copy-RepoToVM.ps1, in-guest provisioning and Export-BaseImage.ps1.

.DESCRIPTION
  End-to-end driver for BUILD-BASE-IMAGE.md. Asks for each piece of
  information only when needed; the only manual work left is the
  Windows Setup inside the VM console (an unattended install is a
  documented non-goal). Phases:

    1. Builder VM  - runs tests\vm\New-BuilderVM.ps1 (readiness probe,
       configuration questions, confirmation, VM creation with vTPM,
       starts the VM).
    2. Windows     - asks whether Windows is already installed. If not:
       opens the VM console (vmconnect) and prompts you to install it
       manually (account: sbxadmin, administrator, NON-EMPTY password),
       complete first logon once, and come back. Then collects the
       guest credential and verifies PowerShell Direct connectivity
       (retry loop until reachable or you give up).
    3. Repo copy   - runs tests\vm\Copy-RepoToVM.ps1 (enables Guest
       Service, stages/zips the repo, one Copy-VMFile, expands,
       verifies by file count).
    4. Provisioning- runs prepare-guest.ps1 in the guest via
       PowerShell Direct (Windows PowerShell 5.1 first pass - it
       installs pwsh). Takes 30-60 minutes with little incremental
       output. On failure, offers a reboot-and-retry loop (common
       cause: VS Build Tools reboot-pending). Verifies pwsh afterwards.
    5. Export      - runs tests\vm\Export-BaseImage.ps1 (guest info,
       vm-settings.json, re-bake checkpoint, template VHDX copy,
       SHA256, readiness probe, current-image record).

  The guest credential is collected once (phase 2) and passed
  in-process to phases 3-5; it is never printed or stored anywhere
  except the gitignored tests\vm\vm-settings.json (by Export-BaseImage,
  after confirmation).

  Re-runs are safe: every phase is idempotent or state-checking.

  Exits:
    0   build finished (or user aborted a prompt deliberately)
    1   a phase failed; see the output above for which one
    2/4/99  propagated from the gate/probe of a sub-script
    99  unexpected error

.EXAMPLE
  pwsh -NoProfile -ExecutionPolicy Bypass -File tests\vm\Build-BaseImage.ps1
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$script:ThisDir = Split-Path -Parent $MyInvocation.MyCommand.Path

function Wait-GuestDirect {
    # Polls PowerShell Direct until it answers or the timeout passes.
    param(
        [string]$VmName,
        [pscredential]$GuestCred,
        [int]$TimeoutMinutes = 10
    )
    $deadline = (Get-Date).AddMinutes($TimeoutMinutes)
    while ((Get-Date) -lt $deadline) {
        try {
            $null = Invoke-Command -VMName $VmName -Credential $GuestCred -ScriptBlock { $env:COMPUTERNAME } -ErrorAction Stop
            return $true
        } catch { Start-Sleep -Seconds 15 }
    }
    return $false
}

function Read-YesNo {
    param([string]$Question, [bool]$DefaultYes = $false)
    if ($DefaultYes) { $hint = '(Y/n)' } else { $hint = '(y/N)' }
    $answer = Read-Host "[vm-all] $Question $hint"
    if ($answer.Trim() -eq '') { return $DefaultYes }
    return ($answer.Trim() -match '^(?i)(y|yes)$')
}

try {
    # -----------------------------------------------------------------------
    # Gate: elevation + Hyper-V tools (the sub-scripts re-check, but a
    # doomed run should abort before any prompt).
    # -----------------------------------------------------------------------
    $windowsIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $windowsPrincipal = New-Object Security.Principal.WindowsPrincipal($windowsIdentity)
    if (-not $windowsPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host '[vm-all] not elevated - run from an elevated (administrator) pwsh, then re-run tests\vm\Build-BaseImage.ps1' -ForegroundColor Red
        exit 2
    }
    if (-not (Get-Command Get-VM -ErrorAction SilentlyContinue)) {
        $hyperVModule = Get-Module -ListAvailable Hyper-V
        if (-not $hyperVModule) {
            Write-Host '[vm-all] Hyper-V management tools are missing - see tests\vm\Initialize-VMHost.ps1 remediation.' -ForegroundColor Red
            exit 4
        }
        Import-Module Hyper-V -ErrorAction Stop
    }

    # -----------------------------------------------------------------------
    # Phase 1/5 - builder VM (New-BuilderVM.ps1 asks its own questions).
    # -----------------------------------------------------------------------
    Write-Host ''
    Write-Host '[vm-all] ==================== PHASE 1/5: builder VM ====================' -ForegroundColor Cyan
    & (Join-Path $script:ThisDir 'New-BuilderVM.ps1')
    $phase1 = $LASTEXITCODE
    if ($phase1 -eq 2 -or $phase1 -eq 4 -or $phase1 -eq 99) {
        Write-Host "[vm-all] PHASE 1 failed (exit $phase1) - aborting; nothing further was changed." -ForegroundColor Red
        exit $phase1
    }
    $configPath = Join-Path $script:ThisDir 'build-config.json'
    try {
        $config = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
    } catch {
        Write-Host "[vm-all] no usable build-config.json after phase 1 - aborting." -ForegroundColor Red
        exit 1
    }
    $vmName = [string]$config.vmName
    $vm = Get-VM -Name $vmName -ErrorAction SilentlyContinue
    if (-not $vm) {
        Write-Host "[vm-all] builder VM '$vmName' does not exist (phase 1 was declined or failed) - aborting." -ForegroundColor Red
        exit 1
    }

    # -----------------------------------------------------------------------
    # Phase 2/5 - Windows installation + guest credential.
    # -----------------------------------------------------------------------
    Write-Host ''
    Write-Host '[vm-all] ==================== PHASE 2/5: Windows installation =============' -ForegroundColor Cyan
    $cred = $null
    if (Read-YesNo -Question 'Windows already installed inside the VM (guest account exists)?') {
        $cred = Get-Credential -UserName 'sbxadmin' -Message "Guest credential for $vmName"
        if ($cred -and (-not (Wait-GuestDirect -VmName $vmName -GuestCred $cred))) {
            Write-Host '[vm-all] guest not reachable via PowerShell Direct - falling through to the install path.' -ForegroundColor Yellow
            $cred = $null
        }
    }
    if (-not $cred) {
        Write-Host '[vm-all] opening the VM console - install Windows manually NOW:' -ForegroundColor Gray
        Write-Host '[vm-all]   local account: sbxadmin (administrator, NON-EMPTY password; PowerShell Direct refuses blank passwords)' -ForegroundColor Gray
        Write-Host '[vm-all]   do not reuse a real password of yours; complete first logon at least once.' -ForegroundColor Gray
        Start-Process -FilePath 'vmconnect.exe' -ArgumentList @($env:COMPUTERNAME, $vmName)
        Read-Host '[vm-all] press Enter here once Windows is installed and you logged in once'
        while ($true) {
            $cred = Get-Credential -UserName 'sbxadmin' -Message "Guest credential for $vmName"
            if (-not $cred) {
                if (Read-YesNo -Question 'Credential prompt cancelled - abort the whole build?') { exit 0 }
                continue
            }
            if (Wait-GuestDirect -VmName $vmName -GuestCred $cred) { break }
            Write-Host '[vm-all] still unreachable (VM must be RUNNING; user/password must match; first logon completed once).' -ForegroundColor Yellow
            if (-not (Read-YesNo -Question 'Try again?')) { exit 1 }
        }
    }
    Write-Host "[vm-all] PowerShell Direct OK with the guest credential ($($cred.UserName))." -ForegroundColor Green

    # -----------------------------------------------------------------------
    # Phase 3/5 - repo copy (Copy-RepoToVM.ps1, credential passed along).
    # -----------------------------------------------------------------------
    Write-Host ''
    Write-Host '[vm-all] ==================== PHASE 3/5: copy repo into VM =================' -ForegroundColor Cyan
    & (Join-Path $script:ThisDir 'Copy-RepoToVM.ps1') -Credential $cred
    $phase3 = $LASTEXITCODE
    if ($phase3 -ne 0) {
        Write-Host "[vm-all] PHASE 3 failed (exit $phase3) - aborting; the VM was left running for inspection." -ForegroundColor Red
        exit 1
    }

    # -----------------------------------------------------------------------
    # Phase 4/5 - provisioning in the guest (30-60 min, little output).
    # -----------------------------------------------------------------------
    Write-Host ''
    Write-Host '[vm-all] ==================== PHASE 4/5: provision guest ====================' -ForegroundColor Cyan
    Write-Host '[vm-all] running prepare-guest.ps1 in the guest (VS Build Tools alone: 10-30+ min). Expect little output until the verdict.' -ForegroundColor Gray
    $prepOk = $false
    while (-not $prepOk) {
        $prepCode = 999
        try {
            $prepCode = Invoke-Command -VMName $vmName -Credential $cred -ScriptBlock {
                # PS Direct turns the child process's stdout into pipeline
                # output: unredirected, every [vm-guest] line rides along in
                # the return value next to $LASTEXITCODE, and
                # 'if ($prepCode -eq 0)' then misreads the resulting array -
                # the -eq filter yields @(0), which unwraps to [int]0 = $false
                # in boolean context, looping successful runs through the
                # reboot-retry path forever. Route the child's output through
                # the Information stream instead: Write-Host keeps the lines
                # streaming to the host console live, while the pipeline
                # carries ONLY the exit code (same reasoning as the
                # structured runner in Invoke-TestsInVM.ps1, step 10).
                powershell -NoProfile -ExecutionPolicy Bypass -File C:\sbx-repo\tests\vm\prepare-guest.ps1 -RepoDir C:\sbx-repo 2>&1 |
                    ForEach-Object { Write-Host $_ }
                $LASTEXITCODE
            }
        } catch {
            Write-Host "[vm-all] provisioning session failed: $($_.Exception.Message)" -ForegroundColor Red
        }
        if ($prepCode -eq 0) {
            $pwshVersion = ''
            $pwshOk = $false
            try {
                $pwshVersion = Invoke-Command -VMName $vmName -Credential $cred -ScriptBlock {
                    pwsh -NoProfile -Command '$PSVersionTable.PSVersion.ToString()'
                }
                $pwshOk = $true
            } catch {
                Write-Host "[vm-all] pwsh verification failed: $($_.Exception.Message)" -ForegroundColor Red
            }
            if ($pwshOk) {
                Write-Host "[vm-all] guest provisioned; pwsh $pwshVersion verified." -ForegroundColor Green
                $prepOk = $true
            }
        }
        if (-not $prepOk) {
            Write-Host "[vm-all] provisioning not successful (exit $prepCode) - common cause: VS Build Tools needs a VM reboot; prepare-guest is idempotent." -ForegroundColor Yellow
            if (-not (Read-YesNo -Question 'Reboot the VM and retry provisioning?')) {
                Write-Host '[vm-all] PHASE 4 abandoned - the VM stays running; re-run Build-BaseImage.ps1 (phases are resumable).' -ForegroundColor Yellow
                exit 1
            }
            Write-Host "[vm-all] rebooting '$vmName'..." -ForegroundColor Gray
            Restart-VM -Name $vmName -Force
            if (-not (Wait-GuestDirect -VmName $vmName -GuestCred $cred -TimeoutMinutes 10)) {
                Write-Host '[vm-all] PowerShell Direct did not come back within 10 minutes after reboot - aborting; re-run when the VM is up.' -ForegroundColor Red
                exit 1
            }
        }
    }

    # -----------------------------------------------------------------------
    # Phase 5/5 - export the template (Export-BaseImage.ps1).
    # -----------------------------------------------------------------------
    Write-Host ''
    Write-Host '[vm-all] ==================== PHASE 5/5: export template ====================' -ForegroundColor Cyan
    & (Join-Path $script:ThisDir 'Export-BaseImage.ps1') -Credential $cred
    $phase5 = $LASTEXITCODE
    if ($phase5 -eq 2 -or $phase5 -eq 4 -or $phase5 -eq 99) {
        Write-Host "[vm-all] PHASE 5 failed (exit $phase5) - aborting." -ForegroundColor Red
        exit $phase5
    }
    if ($phase5 -ne 0) {
        Write-Host "[vm-all] PHASE 5 failed (exit $phase5) - the builder VM is untouched; re-run tests\vm\Export-BaseImage.ps1 to resume." -ForegroundColor Red
        exit 1
    }

    Write-Host ''
    Write-Host '[vm-all] BASE IMAGE BUILT: see the current-image record above (paste it into BUILD-BASE-IMAGE.md).' -ForegroundColor Green
    Write-Host '[vm-all] next: run the disposable-VM test harness from an elevated pwsh:' -ForegroundColor Gray
    Write-Host '  pwsh -NoProfile -ExecutionPolicy Bypass -File tests\vm\Invoke-TestsInVM.ps1' -ForegroundColor Gray
    exit 0
} catch {
    Write-Host "[vm-all] unexpected error: $($_.Exception.Message)" -ForegroundColor Red
    exit 99
}
