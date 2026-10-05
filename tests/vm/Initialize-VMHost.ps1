#Requires -Version 5.1
<#
.SYNOPSIS
  One-time (idempotent) host readiness check and prep for the VM-01
  disposable-VM test infrastructure.
.DESCRIPTION
  Verifies everything the VM test suite needs on the host and creates the
  working directories when missing. Safe to re-run at any time.

  Checks (in order):
    1. elevated shell (Hyper-V management cmdlets require it)
    2. Hyper-V management tools (PowerShell module)
    3. working directories: tests\vm\vms, tests\vm\results, tests\vm\templates
    4. at least one template VHDX under the templates dir (name, size, SHA256)
    5. tests\vm\vm-settings.json (local guest credentials, non-empty)
    6. at least one virtual switch
    7. free disk space on the repo drive (warning below 40 GB, never blocks)

  Prints a final one-line verdict and exits:
    READY: <template-name(s)>    -> exit 0
    NOT READY: <missing things> -> exit 3
    not elevated                -> exit 2
    Hyper-V tools missing       -> exit 4
    unexpected error            -> exit 99

  This script never suggests weakening or disabling a check (fail-closed).
.PARAMETER TemplatesDir
  Optional override for the template VHDX directory.
  Defaults to tests\vm\templates next to this script.
.EXAMPLE
  pwsh -NoProfile -ExecutionPolicy Bypass -File tests\vm\Initialize-VMHost.ps1
#>
[CmdletBinding()]
param(
    [string]$TemplatesDir
)

$ErrorActionPreference = 'Stop'
$script:ThisDir = Split-Path -Parent $MyInvocation.MyCommand.Path

try {
    # -----------------------------------------------------------------------
    # 1. Elevation — must be the first check; Hyper-V cmdlets fail with a
    #    confusing permission error otherwise.
    # -----------------------------------------------------------------------
    $windowsIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $windowsPrincipal = New-Object Security.Principal.WindowsPrincipal($windowsIdentity)
    if (-not $windowsPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host '[vm-host] not elevated — run from an elevated (administrator) pwsh, then re-run tests\vm\Initialize-VMHost.ps1' -ForegroundColor Red
        exit 2
    }

    Write-Host '[vm-host] running elevated; checking host readiness...' -ForegroundColor Gray

    # -----------------------------------------------------------------------
    # 2. Hyper-V management tools (probe without invoking a Hyper-V cmdlet).
    # -----------------------------------------------------------------------
    if (-not (Get-Command New-VM -ErrorAction SilentlyContinue)) {
        $hyperVModule = Get-Module -ListAvailable Hyper-V
        if (-not $hyperVModule) {
            Write-Host '[vm-host] Hyper-V management tools are missing (no New-VM command, no Hyper-V module).' -ForegroundColor Red
            Write-Host '[vm-host] enable them from an elevated pwsh: Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-Management-PowerShell (plus Microsoft-Hyper-V for the role itself), then reboot if prompted.' -ForegroundColor Yellow
            exit 4
        }
        try {
            Import-Module Hyper-V -ErrorAction Stop
        } catch {
            Write-Host "[vm-host] failed to import the Hyper-V module: $($_.Exception.Message)" -ForegroundColor Red
            exit 4
        }
    }
    Write-Host '[vm-host] Hyper-V management tools present.' -ForegroundColor Green

    # -----------------------------------------------------------------------
    # 3. Working directories (create if missing — idempotent).
    # -----------------------------------------------------------------------
    $vmDir = Join-Path $script:ThisDir 'vms'
    $resultsDir = Join-Path $script:ThisDir 'results'
    if ($TemplatesDir) { $templatesDir = [System.IO.Path]::GetFullPath($TemplatesDir) }
    else { $templatesDir = Join-Path $script:ThisDir 'templates' }
    $settingsFile = Join-Path $script:ThisDir 'vm-settings.json'

    foreach ($dir in @($vmDir, $resultsDir, $templatesDir)) {
        if (-not (Test-Path -LiteralPath $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            Write-Host "[vm-host] created directory: $dir" -ForegroundColor Green
        } else {
            Write-Host "[vm-host] directory present: $dir" -ForegroundColor Gray
        }
    }

    # Missing-things accumulator for the final verdict.
    $missing = New-Object System.Collections.Generic.List[string]

    # -----------------------------------------------------------------------
    # 4. Template VHDXs (long-lived base images the test VMs difference
    #    against). A template whose hash fails still counts as present.
    # -----------------------------------------------------------------------
    $templates = @(Get-ChildItem -LiteralPath $templatesDir -File | Where-Object { $_.Extension -eq '.vhdx' })
    if ($templates.Count -gt 0) {
        foreach ($template in $templates) {
            $sizeGb = [math]::Round($template.Length / 1GB, 2)
            try {
                $sha256 = (Get-FileHash -LiteralPath $template.FullName -Algorithm SHA256).Hash
                Write-Host ("[vm-host] template: {0} ({1} GB) SHA256:{2}" -f $template.Name, $sizeGb, $sha256) -ForegroundColor Green
            } catch {
                Write-Host ("[vm-host] template: {0} ({1} GB)" -f $template.Name, $sizeGb) -ForegroundColor Green
                Write-Host "[vm-host] WARNING: could not hash template '$($template.Name)': $($_.Exception.Message)" -ForegroundColor Yellow
            }
        }
    } else {
        $missing.Add('template VHDX')
        Write-Host "[vm-host] NOT READY: no template VHDX found under $templatesDir." -ForegroundColor Red
        Write-Host '[vm-host] build one first — see tests\vm\BUILD-BASE-IMAGE.md.' -ForegroundColor Yellow
    }

    # -----------------------------------------------------------------------
    # 5. Guest-credentials file (local only; gitignored; contents never
    #    read or echoed — existence and non-emptiness only).
    # -----------------------------------------------------------------------
    $settingsItem = Get-Item -LiteralPath $settingsFile -ErrorAction SilentlyContinue
    if ($settingsItem -and ($settingsItem.Length -gt 0)) {
        Write-Host "[vm-host] guest settings present: $settingsFile" -ForegroundColor Green
    } else {
        $missing.Add('vm-settings.json')
        Write-Host "[vm-host] missing or empty: $settingsFile" -ForegroundColor Red
        Write-Host '[vm-host] it is created during base-image build, see tests\vm\BUILD-BASE-IMAGE.md.' -ForegroundColor Yellow
    }

    # -----------------------------------------------------------------------
    # 6. Virtual switch (safe to call now — elevation already verified).
    # -----------------------------------------------------------------------
    $switches = @()
    $switchQueryFailed = $false
    try {
        $switches = @(Get-VMSwitch)
    } catch {
        $switchQueryFailed = $true
        Write-Host "[vm-host] could not query virtual switches: $($_.Exception.Message)" -ForegroundColor Red
    }
    if ($switchQueryFailed) {
        $missing.Add('virtual switch (VMMS not running?)')
        Write-Host '[vm-host] remediation: start the Hyper-V Virtual Machine Management service (VMMS), then re-run.' -ForegroundColor Yellow
    } elseif ($switches.Count -gt 0) {
        $switchNames = ($switches | ForEach-Object { $_.Name }) -join ', '
        Write-Host "[vm-host] virtual switch(es): $switchNames" -ForegroundColor Green
    } else {
        $missing.Add('virtual switch')
        Write-Host '[vm-host] NOT READY: no virtual switch found.' -ForegroundColor Red
        Write-Host "[vm-host] create one (e.g. New-VMSwitch -Name 'sbx-test' -NetAdapterName <adapter>) or ensure the Hyper-V 'Default Switch' is enabled." -ForegroundColor Yellow
    }

    # -----------------------------------------------------------------------
    # 7. Free disk space on the drive hosting the repo (warning only).
    # -----------------------------------------------------------------------
    $repoRoot = [System.IO.Path]::GetFullPath($script:ThisDir)
    if ($repoRoot -match '^[A-Za-z]:') {
        $repoDrive = $repoRoot.Substring(0, 1)
        $freeGb = [math]::Round((Get-PSDrive -Name $repoDrive).Free / 1GB, 1)
        if ($freeGb -lt 40) {
            Write-Host "[vm-host] WARNING: only $freeGb GB free on drive ${repoDrive}: — 40 GB or more is recommended for template + per-run differencing disks." -ForegroundColor Yellow
        } else {
            Write-Host "[vm-host] free disk space on drive ${repoDrive}: $freeGb GB." -ForegroundColor Green
        }
    } else {
        Write-Host "[vm-host] WARNING: repo path '$repoRoot' is not on a lettered drive (UNC?) — free-disk-space check skipped." -ForegroundColor Yellow
    }

    # -----------------------------------------------------------------------
    # 8. Final verdict.
    # -----------------------------------------------------------------------
    if ($missing.Count -eq 0) {
        $templateNames = ($templates | ForEach-Object { $_.Name }) -join ', '
        Write-Host "[vm-host] READY: $templateNames" -ForegroundColor Green
        exit 0
    }
    Write-Host "[vm-host] NOT READY: $($missing -join ', ')" -ForegroundColor Red
    exit 3
} catch {
    Write-Host "[vm-host] unexpected error: $($_.Exception.Message)" -ForegroundColor Red
    exit 99
}
