#Requires -Version 5.1
<#
.SYNOPSIS
  Interactive wrapper for BUILD-BASE-IMAGE.md Steps 0-1: readiness probe,
  guided builder-VM configuration, confirmation, VM creation.

.DESCRIPTION
  Wraps Initialize-VMHost.ps1 and then creates the builder VM from the
  configured ISO. Flow:

    1. Fail-closed gate first: runs tests\vm\Initialize-VMHost.ps1.
       Its exit codes 2 (not elevated), 4 (Hyper-V tools missing) and
       99 (unexpected) are propagated unchanged; nothing is created.
       Exit 3 (NOT READY) is EXPECTED before the image exists (template
       VHDX and vm-settings.json do not exist yet) and only blocks when
       no virtual switch is available - the one missing thing Step 1
       cannot survive. Exit 0 (READY) means a re-bake scenario.
    2. Loads tests\vm\build-config.json when it exists (values used
       directly). Otherwise asks for the values interactively (with
       defaults where sensible) and saves them to that file.
    3. Shows all values (plus the derived VHDX path and a free-disk
       warning) for confirmation. Declining aborts cleanly with no
       changes; edit or delete the config file to change values.
    4. On confirmation executes Step 1 of the runbook: creates vmDir,
       then the VM (generation 2, 8 GB startup memory, 4 vCPU,
       127 GB VHDX, local key protector + vTPM enabled, ISO attached,
       DVD first boot, Default Switch) and starts it.

  Idempotent: an already-existing builder VM is detected and reported;
  nothing is recreated or modified.

  Configuration file (machine-local, gitignored, never committed):
    tests\vm\build-config.json
    { "schema": 1, "repoRoot": "...", "vmName": "...",
      "isoPath": "...", "vmDir": "..." }

  vmName must NOT start with 'sbx-test-': that namespace belongs to
  the test harness and Remove-TestVM.ps1.

  Prints a final verdict line and exits:
    VM CREATED / VM ALREADY EXISTS / ABORTED / ...  -> see codes below
    0  success, clean abort (declined), or VM already exists
    1  invalid or unusable configuration (bad JSON, missing ISO,
       VHDX path already occupied, creation failed)
    2  not elevated (propagated from the probe)
    3  probe NOT READY for a fatal reason (no virtual switch)
    4  Hyper-V management tools missing (propagated)
    99 unexpected error

.EXAMPLE
  pwsh -NoProfile -ExecutionPolicy Bypass -File tests\vm\New-BuilderVM.ps1
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$script:ThisDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$configPath = Join-Path $script:ThisDir 'build-config.json'
$switchName = 'Default Switch'

function Test-ConfigValue {
    # Validates one configuration field; returns $true or an error message.
    param(
        [string]$Field,
        [string]$Value
    )
    switch ($Field) {
        'repoRoot' {
            if (-not (Test-Path -LiteralPath $Value -PathType Container)) {
                return "repoRoot '$Value' is not an existing directory"
            }
            if (-not (Test-Path -LiteralPath (Join-Path $Value 'tests\vm') -PathType Container)) {
                return "repoRoot '$Value' does not contain tests\vm - not the sandbox tool's repo root"
            }
            return $true
        }
        'vmName' {
            if ($Value -eq '') { return 'vmName is empty' }
            if ($Value -like 'sbx-test-*') {
                return "vmName must not start with 'sbx-test-' (that namespace belongs to the test harness and Remove-TestVM.ps1)"
            }
            return $true
        }
        'isoPath' {
            if (-not (Test-Path -LiteralPath $Value -PathType Leaf)) {
                return "isoPath '$Value' does not exist"
            }
            if ([System.IO.Path]::GetExtension($Value) -ne '.iso') {
                return "isoPath '$Value' is not an .iso file"
            }
            return $true
        }
        'vmDir' {
            if ($Value -eq '') { return 'vmDir is empty' }
            if ($Value -notmatch '^[A-Za-z]:') {
                return "vmDir '$Value' must be an absolute path on a lettered drive"
            }
            $drive = $Value.Substring(0, 1)
            if (-not (Test-Path -LiteralPath "$($drive):\")) {
                return "vmDir '$Value' is on a drive that does not exist"
            }
            return $true
        }
    }
    return "unknown field '$Field'"
}

function Read-ValidatedHost {
    # Prompts for one field, validates, re-prompts (max 3 tries).
    param(
        [string]$Field,
        [string]$Prompt,
        [string]$Default = ''
    )
    for ($try = 1; $try -le 3; $try++) {
        if ($Default -ne '') {
            $entered = Read-Host "$Prompt (default: $Default)"
            if ($entered -eq '') { $entered = $Default }
        } else {
            $entered = Read-Host $Prompt
        }
        $result = Test-ConfigValue -Field $Field -Value $entered
        if ($result -eq $true) { return $entered }
        Write-Host "[vm-build] invalid: $result" -ForegroundColor Yellow
    }
    Write-Host "[vm-build] giving up after 3 invalid inputs for '$Field' - aborting." -ForegroundColor Red
    exit 1
}

try {
    # -----------------------------------------------------------------------
    # 1. Readiness probe (fail-closed gate - before any prompt, so a
    #    non-elevated shell can never hang on interactive input).
    # -----------------------------------------------------------------------
    Write-Host '[vm-build] running host readiness probe (Initialize-VMHost.ps1)...' -ForegroundColor Gray
    & (Join-Path $script:ThisDir 'Initialize-VMHost.ps1')
    $probeExit = $LASTEXITCODE
    if ($probeExit -eq 2 -or $probeExit -eq 4 -or $probeExit -eq 99) {
        Write-Host "[vm-build] readiness probe failed (exit $probeExit) - aborting; nothing was created." -ForegroundColor Red
        exit $probeExit
    }
    if ($probeExit -eq 3) {
        # NOT READY is expected pre-build (template VHDX + vm-settings.json
        # missing). The probe cannot say WHICH items are missing, so re-check
        # the one thing Step 1 cannot survive: a usable virtual switch.
        # (Safe to call: the probe already verified elevation + tools.)
        $switches = @()
        try { $switches = @(Get-VMSwitch -ErrorAction Stop) } catch { }
        if ($switches.Count -eq 0) {
            Write-Host '[vm-build] probe NOT READY for a fatal reason: no virtual switch / VMMS unreachable - see probe output above.' -ForegroundColor Red
            exit 3
        }
        Write-Host '[vm-build] probe reports NOT READY (template/settings pending) - expected before the first image build; continuing.' -ForegroundColor Yellow
    }
    if ($probeExit -eq 0) {
        Write-Host '[vm-build] probe reports READY - a template already exists; this is a re-bake scenario.' -ForegroundColor Yellow
    }

    # -----------------------------------------------------------------------
    # 2. Configuration: load existing file, or ask interactively and save.
    # -----------------------------------------------------------------------
    $config = $null
    if (Test-Path -LiteralPath $configPath) {
        Write-Host "[vm-build] using existing configuration: $configPath" -ForegroundColor Gray
        try {
            $config = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
        } catch {
            Write-Host "[vm-build] invalid JSON in $configPath - fix or delete the file, then re-run. ($($_.Exception.Message))" -ForegroundColor Red
            exit 1
        }
        if ($config.schema -ne 1) {
            Write-Host "[vm-build] $configPath has schema '$($config.schema)', expected 1 - delete the file and re-run." -ForegroundColor Red
            exit 1
        }
        $invalid = @()
        foreach ($field in @('repoRoot', 'vmName', 'isoPath', 'vmDir')) {
            $value = ''
            if ($config.PSObject.Properties[$field]) { $value = [string]$config.$field }
            $result = Test-ConfigValue -Field $field -Value $value
            if ($result -ne $true) { $invalid += $result }
        }
        if ($invalid.Count -gt 0) {
            Write-Host "[vm-build] configuration in $configPath is unusable:" -ForegroundColor Red
            foreach ($problem in $invalid) { Write-Host "[vm-build]   - $problem" -ForegroundColor Red }
            Write-Host "[vm-build] edit or delete $configPath, then re-run." -ForegroundColor Yellow
            exit 1
        }
    } else {
        Write-Host "[vm-build] no configuration file yet - asking for values (saved to $configPath)." -ForegroundColor Gray
        $defaultRepoRoot = [System.IO.Path]::GetFullPath((Join-Path $script:ThisDir '..\..'))
        $defaultVmDir = "$env:SystemDrive\hyper-v"

        $config = [pscustomobject]@{
            schema   = 1
            repoRoot = Read-ValidatedHost -Field 'repoRoot' -Prompt '[vm-build] repo root (the sandbox tool)' -Default $defaultRepoRoot
            vmName   = Read-ValidatedHost -Field 'vmName'   -Prompt '[vm-build] builder VM name' -Default 'sbx-base-a-builder'
            isoPath  = Read-ValidatedHost -Field 'isoPath'  -Prompt '[vm-build] path to the downloaded Windows ISO'
            vmDir    = Read-ValidatedHost -Field 'vmDir'    -Prompt '[vm-build] directory for the builder VM (needs ~150 GB free)' -Default $defaultVmDir
        }
        $configJson = $config | ConvertTo-Json
        Set-Content -LiteralPath $configPath -Value $configJson -Encoding UTF8
        Write-Host "[vm-build] configuration saved: $configPath" -ForegroundColor Green
    }

    # -----------------------------------------------------------------------
    # 3. Confirmation: show everything, including the derived VHDX path.
    # -----------------------------------------------------------------------
    $diskPath = Join-Path $config.vmDir "$($config.vmName).vhdx"
    Write-Host ''
    Write-Host '[vm-build] ---- builder VM configuration ----' -ForegroundColor Gray
    Write-Host ("[vm-build]   repo root : {0}" -f $config.repoRoot)
    Write-Host ("[vm-build]   VM name   : {0}" -f $config.vmName)
    Write-Host ("[vm-build]   ISO       : {0}" -f $config.isoPath)
    Write-Host ("[vm-build]   VM dir    : {0}" -f $config.vmDir)
    Write-Host ("[vm-build]   VHDX      : {0}" -f $diskPath)
    Write-Host ("[vm-build]   switch    : {0}" -f $switchName)
    if ($config.vmDir -match '^[A-Za-z]:') {
        $driveLetter = $config.vmDir.Substring(0, 1)
        $freeGb = [math]::Round((Get-PSDrive -Name $driveLetter).Free / 1GB, 1)
        if ($freeGb -lt 150) {
            Write-Host "[vm-build] WARNING: only $freeGb GB free on drive ${driveLetter}: - the runbook recommends ~150 GB (127 GB VHDX plus headroom)." -ForegroundColor Yellow
        } else {
            Write-Host "[vm-build] free disk space on drive ${driveLetter}: $freeGb GB." -ForegroundColor Gray
        }
    }
    Write-Host '[vm-build] --------------------------------------' -ForegroundColor Gray
    $answer = Read-Host '[vm-build] create the builder VM with these values? (y/N)'
    if ($answer.Trim() -notmatch '^(?i)(y|yes)$') {
        Write-Host "[vm-build] ABORTED - no changes made. Configuration stays at $configPath; edit or delete it to change values." -ForegroundColor Yellow
        exit 0
    }

    # -----------------------------------------------------------------------
    # 4. Step 1: create the builder VM (BUILD-BASE-IMAGE.md Step 1).
    # -----------------------------------------------------------------------
    if (Get-VM -Name $config.vmName -ErrorAction SilentlyContinue) {
        Write-Host "[vm-build] VM '$($config.vmName)' already exists - Step 1 appears complete; nothing to do." -ForegroundColor Yellow
        Write-Host "[vm-build] next: runbook Step 2 - vmconnect.exe `$env:COMPUTERNAME $($config.vmName)" -ForegroundColor Gray
        exit 0
    }
    if (Test-Path -LiteralPath $diskPath) {
        Write-Host "[vm-build] VHDX path already occupied: $diskPath - move/delete it or edit $configPath, then re-run." -ForegroundColor Red
        exit 1
    }
    New-Item -ItemType Directory -Path $config.vmDir -Force | Out-Null
    Write-Host "[vm-build] VM directory ready: $($config.vmDir)" -ForegroundColor Green

    New-VM -Name $config.vmName -Generation 2 -MemoryStartupBytes 8GB -NewVHDPath $diskPath -NewVHDSizeBytes 127GB | Out-Null
    Set-VM -Name $config.vmName -ProcessorCount 4
    # vTPM (fresh VM, not yet started): local key protector first,
    # then the virtual TPM.
    Set-VMKeyProtector -VMName $config.vmName -NewLocalKeyProtector
    Enable-VMTPM -VMName $config.vmName
    Add-VMDvdDrive -VMName $config.vmName -Path $config.isoPath
    Connect-VMNetworkAdapter -VMName $config.vmName -SwitchName $switchName
    Set-VMFirmware -VMName $config.vmName -FirstBootDevice (Get-VMDvdDrive -VMName $config.vmName)
    Start-VM -Name $config.vmName

    Write-Host "[vm-build] VM CREATED and started: $($config.vmName)" -ForegroundColor Green
    Write-Host '[vm-build] next steps (see tests\vm\BUILD-BASE-IMAGE.md):' -ForegroundColor Gray
    Write-Host "[vm-build]   Step 2 - install Windows manually:  vmconnect.exe `$env:COMPUTERNAME $($config.vmName)" -ForegroundColor Gray
    Write-Host '[vm-build]     local account: sbxadmin (administrator, NON-EMPTY password; PowerShell Direct refuses blank passwords)' -ForegroundColor Gray
    Write-Host '[vm-build]   Step 3 - repo copy + prepare-guest.ps1 (from this host, once the guest is running)' -ForegroundColor Gray
    exit 0
} catch {
    Write-Host "[vm-build] unexpected error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host '[vm-build] nothing more was created; if a VM or VHDX was created partially, remove it manually (Remove-VM / delete the VHDX).' -ForegroundColor Yellow
    exit 99
}
