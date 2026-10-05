#Requires -Version 5.1
<#
.SYNOPSIS
  Host part of BUILD-BASE-IMAGE.md Step 3: enable Guest Services, stage
  and zip the repo, copy it into the builder VM, expand and verify.

.DESCRIPTION
  Run this on the HOST once the builder VM (created by
  New-BuilderVM.ps1) is running and Windows Setup inside it is complete.
  Flow:

    1. Elevation gate, then a Hyper-V management tools check.
    2. Loads tests\vm\build-config.json (created by New-BuilderVM.ps1;
       missing file = run that first). Validates repoRoot and vmName.
    3. Verifies the builder VM exists and is RUNNING (PowerShell Direct
       refuses anything else), then enables the Hyper-V "Guest Service"
       integration service - Copy-VMFile refuses to work without it.
       Idempotent: enabling an already-enabled service is a no-op.
    4. Asks for the guest credential via Get-Credential (the account
       created during Windows Setup, default suggestion: sbxadmin).
       The credential is only ever passed to cmdlets, never printed.
       Cancelling the prompt aborts cleanly.
    5. Stages the repo host-side: robocopy /E with root-anchored
       exclusions (target, .git, .sandbox, tests\vm\vms,
       tests\vm\results, tests\vm\templates) and /XF vm-settings.json,
       then zips the staging CONTENTS (Compress-Archive).
    6. ONE Copy-VMFile of the zip, ONE PowerShell Direct session that
       removes any stale C:\sbx-repo and expands the archive, ONE
       session verifying the guest file count equals the staging count
       (loud failure instead of a silent gap). Host staging dir and zip
       are cleaned up only on success.

  Does NOT run prepare-guest.ps1 - that is the guest part of Step 3;
  the exact command is printed at the end.

  Prints a final verdict line and exits:
    REPO COPIED ...          -> 0
    ABORTED (prompt)         -> 0
    1  configuration invalid, or staging/copy/verify failed
    2  not elevated
    3  builder VM not found or not running
    4  Hyper-V management tools missing
    99 unexpected error

.EXAMPLE
  pwsh -NoProfile -ExecutionPolicy Bypass -File tests\vm\Copy-RepoToVM.ps1
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$script:ThisDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$configPath = Join-Path $script:ThisDir 'build-config.json'

try {
    # -----------------------------------------------------------------------
    # 1. Elevation gate - before any prompt or file work.
    # -----------------------------------------------------------------------
    $windowsIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $windowsPrincipal = New-Object Security.Principal.WindowsPrincipal($windowsIdentity)
    if (-not $windowsPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host '[vm-copy] not elevated - run from an elevated (administrator) pwsh, then re-run tests\vm\Copy-RepoToVM.ps1' -ForegroundColor Red
        exit 2
    }
    if (-not (Get-Command Get-VM -ErrorAction SilentlyContinue)) {
        $hyperVModule = Get-Module -ListAvailable Hyper-V
        if ($hyperVModule) {
            Import-Module Hyper-V -ErrorAction Stop
        } else {
            Write-Host '[vm-copy] Hyper-V management tools are missing - see tests\vm\Initialize-VMHost.ps1 remediation.' -ForegroundColor Red
            exit 4
        }
    }

    # -----------------------------------------------------------------------
    # 2. Configuration (created by New-BuilderVM.ps1).
    # -----------------------------------------------------------------------
    if (-not (Test-Path -LiteralPath $configPath)) {
        Write-Host "[vm-copy] missing configuration: $configPath - run tests\vm\New-BuilderVM.ps1 first." -ForegroundColor Red
        exit 1
    }
    try {
        $config = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
    } catch {
        Write-Host "[vm-copy] invalid JSON in $configPath ($($_.Exception.Message)) - fix or delete the file, then re-run." -ForegroundColor Red
        exit 1
    }
    if ($config.schema -ne 1) {
        Write-Host "[vm-copy] $configPath has schema '$($config.schema)', expected 1 - delete the file and re-run New-BuilderVM.ps1." -ForegroundColor Red
        exit 1
    }
    $repoRoot = [string]$config.repoRoot
    $vmName = [string]$config.vmName
    if (-not (Test-Path -LiteralPath $repoRoot -PathType Container) -or
        -not (Test-Path -LiteralPath (Join-Path $repoRoot 'tests\vm') -PathType Container)) {
        Write-Host "[vm-copy] repoRoot '$repoRoot' from $configPath is not the sandbox tool's repo root - fix the file and re-run." -ForegroundColor Red
        exit 1
    }
    if ($vmName -eq '') {
        Write-Host "[vm-copy] vmName is empty in $configPath - fix the file and re-run." -ForegroundColor Red
        exit 1
    }

    # -----------------------------------------------------------------------
    # 3. Builder VM exists and is RUNNING (PowerShell Direct requirement).
    # -----------------------------------------------------------------------
    $vm = Get-VM -Name $vmName -ErrorAction SilentlyContinue
    if (-not $vm) {
        Write-Host "[vm-copy] VM '$vmName' not found - run tests\vm\New-BuilderVM.ps1 first (or fix vmName in $configPath)." -ForegroundColor Red
        exit 3
    }
    if ($vm.State -ne 'Running') {
        Write-Host "[vm-copy] VM '$vmName' is not running (state: $($vm.State)) - start it first:  Start-VM -Name '$vmName'" -ForegroundColor Red
        exit 3
    }
    Write-Host "[vm-copy] VM '$vmName' is running (state: $($vm.State))." -ForegroundColor Green

    # -----------------------------------------------------------------------
    # 4. Enable the "Guest Service" integration service (Copy-VMFile
    #    refuses to work without it). Idempotent.
    # -----------------------------------------------------------------------
    $guestService = Get-VMIntegrationService -VM $vm |
        Where-Object { $_.Id -like '*6C09BB55-D683-4DA0-8931-C9BF705F6480*' }
    if ($guestService -and $guestService.Enabled) {
        Write-Host '[vm-copy] Guest Service integration already enabled.' -ForegroundColor Green
    } else {
        $guestService | Enable-VMIntegrationService
        Write-Host '[vm-copy] Guest Service integration enabled.' -ForegroundColor Green
    }

    # -----------------------------------------------------------------------
    # 5. Guest credential (asked AFTER all hard gates - never waste a
    #    password prompt on a doomed run; never printed or logged).
    # -----------------------------------------------------------------------
    $cred = Get-Credential -UserName 'sbxadmin' -Message "Guest credential for $vmName (account created during Windows Setup)"
    if (-not $cred) {
        Write-Host '[vm-copy] ABORTED - credential prompt cancelled; nothing was copied.' -ForegroundColor Yellow
        exit 0
    }

    # -----------------------------------------------------------------------
    # 6. Stage the repo host-side (runbook Step 3 exclusions).
    # -----------------------------------------------------------------------
    $stage = Join-Path $env:TEMP 'sbx-repo-stage'
    if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force }
    Write-Host "[vm-copy] staging repo (excluding target, .git, .sandbox, VM artifacts)..." -ForegroundColor Gray
    robocopy $repoRoot $stage /E /XD `
        (Join-Path $repoRoot 'target') `
        (Join-Path $repoRoot '.git') `
        (Join-Path $repoRoot '.sandbox') `
        (Join-Path $repoRoot 'tests\vm\vms') `
        (Join-Path $repoRoot 'tests\vm\results') `
        (Join-Path $repoRoot 'tests\vm\templates') `
        /XF vm-settings.json | Out-Null
    if ($LASTEXITCODE -ge 8) { throw "robocopy failed (exit $LASTEXITCODE)" }
    $stageCount = @(Get-ChildItem -LiteralPath $stage -Recurse -File).Count
    Write-Host "[vm-copy] staged $stageCount files under $stage" -ForegroundColor Green

    # -----------------------------------------------------------------------
    # 7. Zip the staging CONTENTS, ONE Copy-VMFile, ONE expand session,
    #    ONE count-verification session (loud failure, no silent gap).
    # -----------------------------------------------------------------------
    $zipPath = Join-Path $env:TEMP 'sbx-repo.zip'
    if (Test-Path -LiteralPath $zipPath) { Remove-Item -LiteralPath $zipPath -Force }
    Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $zipPath -Force
    Write-Host "[vm-copy] archive ready: $zipPath - copying into the VM (single Copy-VMFile)..." -ForegroundColor Gray
    Copy-VMFile -Name $vmName -SourcePath $zipPath -DestinationPath 'C:\sbx-repo.zip' -FileSource Host -Force

    Invoke-Command -VMName $vmName -Credential $cred -ScriptBlock {
        if (Test-Path -LiteralPath 'C:\sbx-repo') { Remove-Item -LiteralPath 'C:\sbx-repo' -Recurse -Force }
        Expand-Archive -Path 'C:\sbx-repo.zip' -DestinationPath 'C:\sbx-repo' -Force
        Remove-Item -LiteralPath 'C:\sbx-repo.zip' -Force
    }
    Invoke-Command -VMName $vmName -Credential $cred -ScriptBlock {
        param($expected)
        $actual = @(Get-ChildItem -LiteralPath 'C:\sbx-repo' -Recurse -File).Count
        if ($actual -ne $expected) {
            throw "repo copy verification FAILED: expected $expected files under C:\sbx-repo, found $actual - re-run tests\vm\Copy-RepoToVM.ps1"
        }
        Write-Host "repo copy verified: $actual of $expected files present"
    } -ArgumentList $stageCount
    Write-Host "[vm-copy] repo copy verified: $stageCount files expanded under C:\sbx-repo in the guest." -ForegroundColor Green

    # Clean host-side staging only on success (kept for debugging on failure).
    Remove-Item -LiteralPath $zipPath -Force
    Remove-Item -LiteralPath $stage -Recurse -Force

    Write-Host "[vm-copy] REPO COPIED: $stageCount files into '$vmName' at C:\sbx-repo." -ForegroundColor Green
    Write-Host '[vm-copy] next - run provisioning in the guest (BUILD-BASE-IMAGE.md Step 3, chicken-and-egg: Windows PowerShell 5.1 first, it installs pwsh):' -ForegroundColor Gray
    Write-Host "  Invoke-Command -VMName '$vmName' -Credential `$cred -ScriptBlock {" -ForegroundColor Gray
    Write-Host '      powershell -NoProfile -ExecutionPolicy Bypass -File C:\sbx-repo\tests\vm\prepare-guest.ps1 -RepoDir C:\sbx-repo' -ForegroundColor Gray
    Write-Host '      if ($LASTEXITCODE -ne 0) { throw "prepare-guest.ps1 failed (exit $LASTEXITCODE)" }' -ForegroundColor Gray
    Write-Host '  }' -ForegroundColor Gray
    exit 0
} catch {
    Write-Host "[vm-copy] unexpected error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host '[vm-copy] staging dir/zip were kept under $env:TEMP for debugging; nothing inside the VM was harmed beyond the copy attempt.' -ForegroundColor Yellow
    exit 99
}
