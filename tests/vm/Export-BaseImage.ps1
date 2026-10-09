#Requires -Version 5.1
<#
.SYNOPSIS
  Final part of BUILD-BASE-IMAGE.md (Steps 4-5 + current-image record):
  collect guest info, write vm-settings.json, checkpoint and stop the
  builder VM, export the template VHDX, verify host readiness.

.DESCRIPTION
  Run this on the HOST once the builder VM is provisioned
  (prepare-guest.ps1 printed GUEST PREPARED). It extracts everything
  needed for the disposable-VM test harness from the builder VM:

    1. Elevation gate, then a Hyper-V management tools check.
    2. Loads tests\vm\build-config.json (created by New-BuilderVM.ps1).
    3. Starts the VM if needed (guest info needs PowerShell Direct),
       collects Edition + OS build via PS Direct, plus the secure-boot
       state for the record.
    4. Writes tests\vm\vm-settings.json (gitignored) from the guest
       credential: { "schema": 1, "guestUser": ..., "guestPassword": ... }.
       The password is stored in PLAINTEXT by design (machine-local,
       throwaway-image credential; see the security note in
       BUILD-BASE-IMAGE.md Step 4). It is never printed.
    5. Asks for the template name (default: sbx-base-a, the harness's
       -Image default) and refuses to overwrite an existing template
       without confirmation - BEFORE any state change.
    6. Takes the re-bake checkpoint 'sbx-base-a-clean' (skipped when it
       already exists), stops the VM (graceful-first via -Force), copies
       its VHDX to tests\vm\templates\<name>.vhdx, prints the SHA256.
    7. Runs tests\vm\Initialize-VMHost.ps1 and reports the verdict
       (expected: READY, exit 0).
    8. Prints the filled "Current image" record for BUILD-BASE-IMAGE.md.

.PARAMETER Credential
  Optional guest credential; when omitted the script asks via
  Get-Credential. Used by Build-BaseImage.ps1 to pass an
  already-collected credential in-process (never stored in this script,
  except into vm-settings.json as described above; never printed).

  Prints a final verdict line and exits:
    TEMPLATE EXPORTED ...     -> 0
    ABORTED (prompt)         -> 0
    1  configuration invalid, guest unreachable, or copy/probe failed
    2  not elevated
    3  builder VM not found
    4  Hyper-V management tools missing
    99 unexpected error

.EXAMPLE
  pwsh -NoProfile -ExecutionPolicy Bypass -File tests\vm\Export-BaseImage.ps1
#>
[CmdletBinding()]
param(
    [pscredential]$Credential
)

$ErrorActionPreference = 'Stop'
$script:ThisDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$configPath = Join-Path $script:ThisDir 'build-config.json'
$checkpointName = 'sbx-base-a-clean'

try {
    # -----------------------------------------------------------------------
    # 1. Elevation gate - before any prompt or state change.
    # -----------------------------------------------------------------------
    $windowsIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $windowsPrincipal = New-Object Security.Principal.WindowsPrincipal($windowsIdentity)
    if (-not $windowsPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host '[vm-export] not elevated - run from an elevated (administrator) pwsh, then re-run tests\vm\Export-BaseImage.ps1' -ForegroundColor Red
        exit 2
    }
    if (-not (Get-Command Get-VM -ErrorAction SilentlyContinue)) {
        $hyperVModule = Get-Module -ListAvailable Hyper-V
        if ($hyperVModule) {
            Import-Module Hyper-V -ErrorAction Stop
        } else {
            Write-Host '[vm-export] Hyper-V management tools are missing - see tests\vm\Initialize-VMHost.ps1 remediation.' -ForegroundColor Red
            exit 4
        }
    }

    # -----------------------------------------------------------------------
    # 2. Configuration (created by New-BuilderVM.ps1).
    # -----------------------------------------------------------------------
    if (-not (Test-Path -LiteralPath $configPath)) {
        Write-Host "[vm-export] missing configuration: $configPath - run tests\vm\New-BuilderVM.ps1 first." -ForegroundColor Red
        exit 1
    }
    try {
        $config = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
    } catch {
        Write-Host "[vm-export] invalid JSON in $configPath ($($_.Exception.Message)) - fix or delete the file, then re-run." -ForegroundColor Red
        exit 1
    }
    if ($config.schema -ne 1) {
        Write-Host "[vm-export] $configPath has schema '$($config.schema)', expected 1 - delete the file and re-run New-BuilderVM.ps1." -ForegroundColor Red
        exit 1
    }
    $vmName = [string]$config.vmName
    $repoRoot = [string]$config.repoRoot
    $vmDir = [string]$config.vmDir
    $isoPath = [string]$config.isoPath
    if ($vmName -eq '' -or $vmDir -eq '' -or
        -not (Test-Path -LiteralPath (Join-Path $vmDir "$vmName.vhdx") -PathType Leaf)) {
        Write-Host "[vm-export] build-config is missing vmName/vmDir or the builder VHDX does not exist under $vmDir - re-run tests\vm\New-BuilderVM.ps1." -ForegroundColor Red
        exit 1
    }
    $vhdxPath = Join-Path $vmDir "$vmName.vhdx"

    $vm = Get-VM -Name $vmName -ErrorAction SilentlyContinue
    if (-not $vm) {
        Write-Host "[vm-export] VM '$vmName' not found - run tests\vm\New-BuilderVM.ps1 first (or fix vmName in $configPath)." -ForegroundColor Red
        exit 3
    }

    # -----------------------------------------------------------------------
    # 3. Guest info (needs the VM RUNNING for PowerShell Direct).
    # -----------------------------------------------------------------------
    if ($Credential) {
        $cred = $Credential
    } else {
        $cred = Get-Credential -UserName 'sbxadmin' -Message "Guest credential for $vmName (account created during Windows Setup)"
        if (-not $cred) {
            Write-Host '[vm-export] ABORTED - credential prompt cancelled; nothing was changed.' -ForegroundColor Yellow
            exit 0
        }
    }
    if ($vm.State -ne 'Running') {
        Write-Host "[vm-export] VM is $($vm.State) - starting it to collect guest info (needs PowerShell Direct)..." -ForegroundColor Gray
        Start-VM -Name $vmName
        $deadline = (Get-Date).AddMinutes(10)
        $guestUp = $false
        while ((Get-Date) -lt $deadline) {
            try {
                $null = Invoke-Command -VMName $vmName -Credential $cred -ScriptBlock { $env:COMPUTERNAME } -ErrorAction Stop
                $guestUp = $true
                break
            } catch { Start-Sleep -Seconds 15 }
        }
        if (-not $guestUp) {
            Write-Host "[vm-export] VM '$vmName' running but PowerShell Direct did not become ready within 10 minutes - wrong credential? Re-run and re-enter." -ForegroundColor Red
            exit 1
        }
    }
    $guestInfo = Invoke-Command -VMName $vmName -Credential $cred -ScriptBlock {
        Get-CimInstance Win32_OperatingSystem | Select-Object Caption, BuildNumber
    }
    $osEdition = [string]$guestInfo.Caption
    $osBuild = [string]$guestInfo.BuildNumber
    Write-Host "[vm-export] guest: $osEdition (build $osBuild)." -ForegroundColor Green

    $secureBoot = 'unknown'
    try {
        $firmware = Get-VMFirmware -VMName $vmName
        $secureBoot = [string]$firmware.SecureBoot
    } catch {
        Write-Host "[vm-export] WARNING: could not read secure-boot state: $($_.Exception.Message)" -ForegroundColor Yellow
    }

    # -----------------------------------------------------------------------
    # 4. tests\vm\vm-settings.json (harness guest credential; gitignored).
    #    Written from the credential collected above - the password is
    #    stored PLAINTEXT by design; never printed or logged.
    # -----------------------------------------------------------------------
    $guestUser = $cred.UserName
    if ($guestUser -like '*\*') { $guestUser = ($guestUser -split '\\')[-1] }
    $guestPassword = $cred.GetNetworkCredential().Password
    if ($guestUser -eq '' -or $guestPassword -eq '') {
        Write-Host '[vm-export] credential has an empty user or password - PowerShell Direct would not work with it either; aborting.' -ForegroundColor Red
        exit 1
    }
    $settingsPath = Join-Path $script:ThisDir 'vm-settings.json'
    if (Test-Path -LiteralPath $settingsPath) {
        Write-Host "[vm-export] WARNING: $settingsPath already exists." -ForegroundColor Yellow
        $answer = Read-Host "[vm-export] overwrite it with the credential just given (user: $guestUser, password: <hidden>)? (y/N)"
        if ($answer.Trim() -notmatch '^(?i)(y|yes)$') {
            Write-Host '[vm-export] ABORTED - keeping the existing vm-settings.json; nothing else was changed.' -ForegroundColor Yellow
            exit 0
        }
    } else {
        $answer = Read-Host "[vm-export] write $settingsPath (user: $guestUser, password: <hidden>)? (Y/n)"
        if ($answer.Trim() -match '^(?i)(n|no)$') {
            Write-Host '[vm-export] ABORTED - vm-settings.json is required for the test harness; re-run when ready.' -ForegroundColor Yellow
            exit 0
        }
    }
    @{ schema = 1; guestUser = $guestUser; guestPassword = $guestPassword } |
        ConvertTo-Json | Set-Content -LiteralPath $settingsPath -Encoding UTF8
    Write-Host "[vm-export] guest settings written: $settingsPath" -ForegroundColor Green

    # -----------------------------------------------------------------------
    # 5. Template target - confirm overwrite BEFORE any state change.
    # -----------------------------------------------------------------------
    $templatesDir = Join-Path $script:ThisDir 'templates'
    $templateName = Read-Host '[vm-export] template name (default: sbx-base-a; the harness default -Image)'
    if ($templateName -eq '') { $templateName = 'sbx-base-a' }
    if ([System.IO.Path]::GetExtension($templateName) -ne '.vhdx') { $templateName = "$templateName.vhdx" }
    $templatePath = Join-Path $templatesDir $templateName
    if (Test-Path -LiteralPath $templatePath) {
        $answer = Read-Host "[vm-export] template already exists: $templatePath - overwrite it? (y/N)"
        if ($answer.Trim() -notmatch '^(?i)(y|yes)$') {
            Write-Host '[vm-export] ABORTED - keeping the existing template; VM and settings were left as-is.' -ForegroundColor Yellow
            exit 0
        }
    }

    # -----------------------------------------------------------------------
    # 6. Checkpoint, stop, copy the VHDX, hash it.
    # -----------------------------------------------------------------------
    if (Get-VMSnapshot -VMName $vmName -Name $checkpointName -ErrorAction SilentlyContinue) {
        Write-Host "[vm-export] re-bake checkpoint already exists: $checkpointName - keeping it." -ForegroundColor Gray
    } else {
        Checkpoint-VM -Name $vmName -SnapshotName $checkpointName
        Write-Host "[vm-export] re-bake checkpoint taken: $checkpointName (builder VM stays restorable)." -ForegroundColor Green
    }
    if ((Get-VM -Name $vmName).State -eq 'Running') {
        Stop-VM -Name $vmName -Force
        Write-Host "[vm-export] VM stopped (graceful-first)." -ForegroundColor Green
    }

    # Resolve the VM's ACTUAL boot disk - never trust the build-config path.
    # The re-bake checkpoint above (and any earlier checkpoint, e.g. a
    # Hyper-V automatic checkpoint silently taken at Start-VM) makes the
    # live disk an .avhdx differencing leaf; copying the config-path base
    # VHDX instead exports an EMPTY or STALE disk (2026-10-10 incident: a
    # 0.04 GB template). Flatten the live leaf with Convert-VHD instead:
    # the result is a standalone VHDX with the full current state, and the
    # checkpoint chain (the re-bake restore point) stays intact on the
    # builder VM.
    $diskDrives = @(Get-VMHardDiskDrive -VMName $vmName)
    if ($diskDrives.Count -eq 0) {
        Write-Host "[vm-export] no hard disk attached to VM '$vmName' - re-run tests\vm\New-BuilderVM.ps1." -ForegroundColor Red
        exit 1
    }
    if ($diskDrives.Count -gt 1) {
        Write-Host "[vm-export] WARNING: VM has $($diskDrives.Count) hard disks; exporting only the first. Paths:" -ForegroundColor Yellow
        foreach ($d in $diskDrives) { Write-Host "[vm-export]   $($d.Path)" -ForegroundColor Yellow }
    }
    $liveDisk = [string]$diskDrives[0].Path
    if ($liveDisk -ne $vhdxPath) {
        Write-Host '[vm-export] live boot disk differs from the build-config path - using the live disk:' -ForegroundColor Yellow
        Write-Host "[vm-export]   live  : $liveDisk" -ForegroundColor Yellow
        Write-Host "[vm-export]   config: $vhdxPath" -ForegroundColor Yellow
    }
    New-Item -ItemType Directory -Path $templatesDir -Force | Out-Null
    if ([System.IO.Path]::GetExtension($liveDisk) -eq '.avhdx') {
        Write-Host "[vm-export] live disk is a checkpoint differencing disk: $liveDisk" -ForegroundColor Gray
        Write-Host "[vm-export] flattening the checkpoint chain into the template (multi-GB - takes a few minutes):" -ForegroundColor Gray
        Write-Host "  $liveDisk  ->  $templatePath"
        if (Test-Path -LiteralPath $templatePath) { Remove-Item -LiteralPath $templatePath -Force }
        Convert-VHD -Path $liveDisk -DestinationPath $templatePath
    } else {
        Write-Host "[vm-export] copying the VHDX to the template (multi-GB - takes a few minutes):" -ForegroundColor Gray
        Write-Host "  $liveDisk  ->  $templatePath"
        Copy-Item -LiteralPath $liveDisk -Destination $templatePath -Force
    }
    $sha256 = (Get-FileHash -LiteralPath $templatePath -Algorithm SHA256).Hash
    $templateGb = [math]::Round((Get-Item -LiteralPath $templatePath).Length / 1GB, 2)
    if ($templateGb -lt 10) {
        Write-Host "[vm-export] REFUSING to publish a suspiciously small template: $templatePath is only $templateGb GB." -ForegroundColor Red
        Write-Host '[vm-export] a provisioned image (Windows + VS Build Tools + Rust) is far larger; the source disk is wrong or stale - inspect the builder VM before re-exporting.' -ForegroundColor Red
        exit 1
    }
    Write-Host "[vm-export] template: $templateGb GB. SHA256: $sha256" -ForegroundColor Green

    # -----------------------------------------------------------------------
    # 7. Host readiness probe (expected: READY, exit 0).
    # -----------------------------------------------------------------------
    Write-Host '[vm-export] running the readiness probe (Initialize-VMHost.ps1)...' -ForegroundColor Gray
    & (Join-Path $script:ThisDir 'Initialize-VMHost.ps1')
    $probeExit = $LASTEXITCODE
    if ($probeExit -ne 0) {
        Write-Host "[vm-export] probe reports NOT READY (exit $probeExit) - resolve the items listed above, then re-run the probe." -ForegroundColor Red
        exit $probeExit
    }

    # -----------------------------------------------------------------------
    # 8. Filled "Current image" record for BUILD-BASE-IMAGE.md.
    # -----------------------------------------------------------------------
    $buildDate = Get-Date -Format 'yyyy-MM-dd'
    Write-Host ''
    Write-Host '[vm-export] TEMPLATE EXPORTED. Paste this into BUILD-BASE-IMAGE.md "Current image":' -ForegroundColor Green
    Write-Host ''
    Write-Host '| Field                 | Value |'
    Write-Host '|-----------------------|-------|'
    Write-Host ("| Template name         | {0} |" -f (Split-Path -Leaf $templatePath))
    Write-Host ("| Template size (GB)    | {0} |" -f $templateGb)
    Write-Host ("| Edition (Caption)     | {0} |" -f $osEdition)
    Write-Host ("| OS build (BuildNumber)| {0} |" -f $osBuild)
    Write-Host ("| ISO path             | {0} |" -f $(if ($isoPath) { $isoPath } else { '-' }))
    Write-Host ("| Secure boot           | {0} |" -f $secureBoot)
    Write-Host ("| Template SHA256       | {0} |" -f $sha256)
    Write-Host ("| Build date            | {0} |" -f $buildDate)
    Write-Host ''
    Write-Host '[vm-export] next: run the disposable-VM test harness from an elevated pwsh:' -ForegroundColor Gray
    Write-Host '  pwsh -NoProfile -ExecutionPolicy Bypass -File tests\vm\Invoke-TestsInVM.ps1' -ForegroundColor Gray
    exit 0
} catch {
    Write-Host "[vm-export] unexpected error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host '[vm-export] no template was produced; the builder VM is untouched (restorable via the checkpoint when present).' -ForegroundColor Yellow
    exit 99
}
