#Requires -Version 5.1
<#
.SYNOPSIS
  Rollback script: removes disposable test VMs (prefix sbx-test-) and their
  differencing disks. Must exist before any VM is created (AGENTS.md rule).
.DESCRIPTION
  Safety model (name allow-list, mirroring the sandbox tool's own philosophy):
    - Only VMs whose name starts with 'sbx-test-' are ever touched,
      in every mode (-Name, -List, -All).
    - VMs named sbx-base-* (base images) are never touched.
    - On disk, only .vhdx/.avhdx files under tests\vm\vms belonging to the
      removed VM are deleted; the templates directory is never touched.
      (.avhdx = checkpoint differencing disks; deleting a checkpoint disk
      without its parent, or the parent without it, would orphan the chain.)

  Orphaned-disk cleanup: the harness can leave a differencing disk behind
  with no registered VM (run killed between New-VHD and New-VM, or a
  failed cleanup).
    - -Name also removes tests\vm\vms\<Name>.vhdx when no registered VM
      matches (reported as an orphaned disk removed).
    - -All additionally sweeps tests\vm\vms\sbx-test-*.vhdx/.avhdx files
      that do not belong to any registered VM and removes them.
    - Only sbx-test-* prefixed .vhdx/.avhdx files are ever deleted.
    - -List lists orphaned disks too (marked as such); it removes nothing.

  Parameter validation (including the prefix allow-list) runs BEFORE the
  elevation check, so misuse is reported identically regardless of whether
  the shell is elevated.

  Exit codes:
    0  = nothing (left) to remove, or removal succeeded
    1  = at least one matched VM, its disk, or an orphaned disk failed
         to remove
    2  = not elevated (run from an elevated pwsh)
    4  = usage error, name outside the sbx-test- allow-list,
         or Hyper-V management tools/service unavailable
    99 = unexpected error
.PARAMETER Name
  Exact name of a single VM to remove; must start with the sbx-test- prefix.
.PARAMETER List
  Dry run: print what would be removed (matched VMs and orphaned disks),
  remove nothing.
.PARAMETER All
  Remove every VM whose name starts with the sbx-test- prefix.
.EXAMPLE
  pwsh -NoProfile -ExecutionPolicy Bypass -File tests\vm\Remove-TestVM.ps1 -List
.EXAMPLE
  pwsh -NoProfile -ExecutionPolicy Bypass -File tests\vm\Remove-TestVM.ps1 -Name sbx-test-20261004-120000-00001
#>
[CmdletBinding()]
param(
    [string]$Name,
    [switch]$List,
    [switch]$All
)

$ErrorActionPreference = 'Stop'
$script:ThisDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$script:VmsDir = Join-Path $script:ThisDir 'vms'
$script:Prefix = 'sbx-test-'

try {
    # -----------------------------------------------------------------------
    # Parameter validation - first, so usage and allow-list errors surface
    # identically whether or not the shell is elevated.
    # -----------------------------------------------------------------------
    $selectedModes = 0
    if ($Name) { $selectedModes++ }
    if ($List) { $selectedModes++ }
    if ($All) { $selectedModes++ }
    if ($selectedModes -ne 1) {
        Write-Host '[vm] exactly one of -Name, -List, -All must be given.' -ForegroundColor Red
        Write-Host '[vm] usage: pwsh -File tests\vm\Remove-TestVM.ps1 -Name <sbx-test-...> | -List | -All' -ForegroundColor Yellow
        exit 4
    }
    if ($Name -and -not $Name.StartsWith($script:Prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        Write-Host "[vm] refusing: '$Name' is outside the test-VM allow-list - this script only ever touches VMs named 'sbx-test-*'." -ForegroundColor Red
        exit 4
    }

    # -----------------------------------------------------------------------
    # Elevation check (same pattern as Initialize-VMHost.ps1; kept
    # self-contained).
    # -----------------------------------------------------------------------
    $windowsIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $windowsPrincipal = New-Object Security.Principal.WindowsPrincipal($windowsIdentity)
    if (-not $windowsPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host '[vm] not elevated - run from an elevated pwsh; one-time prep: tests\vm\Initialize-VMHost.ps1' -ForegroundColor Red
        exit 2
    }

    # -----------------------------------------------------------------------
    # Hyper-V management tools.
    # -----------------------------------------------------------------------
    if (-not (Get-Command Get-VM -ErrorAction SilentlyContinue)) {
        $hyperVModule = Get-Module -ListAvailable Hyper-V
        if ($hyperVModule) {
            try {
                Import-Module Hyper-V -ErrorAction Stop
            } catch {
                Write-Host "[vm] failed to import the Hyper-V module: $($_.Exception.Message)" -ForegroundColor Red
            }
        }
    }
    if (-not (Get-Command Get-VM -ErrorAction SilentlyContinue)) {
        Write-Host '[vm] Hyper-V management tools are missing - enable them from an elevated pwsh: Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-Management-PowerShell.' -ForegroundColor Red
        exit 4
    }

    # -----------------------------------------------------------------------
    # Helpers.
    # -----------------------------------------------------------------------

    # Candidate disk paths belonging to a VM: the paths recorded in the VM's
    # config (Get-VMHardDiskDrive) plus any .vhdx/.avhdx under tests\vm\vms
    # whose file name, checkpoint name (<vm>_<guid>.avhdx), or a parent
    # folder matches the VM name (per-run differencing disks).
    function Get-VmDiskCandidates {
        param([string]$VmName, [object]$Vm)
        $candidates = New-Object System.Collections.Generic.List[string]
        foreach ($drive in @($Vm | Get-VMHardDiskDrive)) {
            if ($drive.Path) { $candidates.Add($drive.Path) }
        }
        if (Test-Path -LiteralPath $script:VmsDir) {
            Get-ChildItem -LiteralPath $script:VmsDir -Recurse -File -ErrorAction SilentlyContinue |
                Where-Object {
                    ($_.Extension -in '.vhdx', '.avhdx') -and
                    (($_.BaseName -eq $VmName) -or ($_.BaseName.StartsWith("$VmName_", [System.StringComparison]::OrdinalIgnoreCase)) -or (($_.FullName -split '[\\/]') -contains $VmName))
                } |
                ForEach-Object { $candidates.Add($_.FullName) }
        }
        return @($candidates | Sort-Object -Unique)
    }

    # Deletion guard: only .vhdx/.avhdx files physically under tests\vm\vms
    # are deleted, and never anything named sbx-base-* (base templates).
    function Test-IsDeletableDisk {
        param([string]$Path)
        if (-not $Path) { return $false }
        $full = [System.IO.Path]::GetFullPath($Path)
        $vmsRoot = [System.IO.Path]::GetFullPath($script:VmsDir).TrimEnd('\') + '\'
        if (-not $full.StartsWith($vmsRoot, [System.StringComparison]::OrdinalIgnoreCase)) { return $false }
        $ext = [System.IO.Path]::GetExtension($full)
        if ($ext -ne '.vhdx' -and $ext -ne '.avhdx') { return $false }
        if ([System.IO.Path]::GetFileNameWithoutExtension($full) -like 'sbx-base-*') { return $false }
        return $true
    }

    # Orphaned disks: sbx-test-*.vhdx/.avhdx files under tests\vm\vms that do not
    # belong to ANY registered VM (differencing disk whose VM was never
    # registered or whose cleanup failed). Never matches non-sbx-test-
    # files; the deletable-disk guard still applies on deletion.
    function Get-OrphanedDisks {
        param([object[]]$RegisteredVms)
        if (-not (Test-Path -LiteralPath $script:VmsDir)) { return @() }
        $vmNames = @($RegisteredVms | ForEach-Object { $_.Name })
        $orphans = New-Object System.Collections.Generic.List[string]
        Get-ChildItem -LiteralPath $script:VmsDir -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object {
                ($_.Extension -in '.vhdx', '.avhdx') -and
                ($_.BaseName.StartsWith($script:Prefix, [System.StringComparison]::OrdinalIgnoreCase))
            } |
            ForEach-Object {
                $segments = @($_.FullName -split '[\\/]')
                $belongsToVm = $false
                foreach ($vmName in $vmNames) {
                    if (($_.BaseName -eq $vmName) -or ($segments -contains $vmName)) {
                        $belongsToVm = $true
                        break
                    }
                }
                if (-not $belongsToVm) { $orphans.Add($_.FullName) }
            }
        return @($orphans)
    }

    # -----------------------------------------------------------------------
    # Target selection (prefix allow-list applied to every mode).
    # -----------------------------------------------------------------------
    $allVms = @()
    $matchingVms = @()
    try {
        $allVms = @(Get-VM)
        $matchingVms = @($allVms | Where-Object { $_.Name -like "$($script:Prefix)*" })
    } catch {
        Write-Host "[vm] Hyper-V service unavailable - could not enumerate VMs: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host '[vm] the Hyper-V Virtual Machine Management service (VMMS) may not be running; start it, then re-run.' -ForegroundColor Yellow
        exit 4
    }

    if ($List) {
        $orphanedDisks = Get-OrphanedDisks -RegisteredVms $allVms
        if ($matchingVms.Count -eq 0 -and $orphanedDisks.Count -eq 0) {
            Write-Host "[vm] no VMs matching '$($script:Prefix)*' exist - nothing to remove." -ForegroundColor Gray
            exit 0
        }
        if ($matchingVms.Count -gt 0) {
            Write-Host "[vm] DRY RUN: the following $($matchingVms.Count) VM(s) would be removed (nothing is modified):" -ForegroundColor Cyan
            foreach ($vm in $matchingVms) {
                Write-Host ("[vm]   VM: {0} (state: {1})" -f $vm.Name, $vm.State) -ForegroundColor Yellow
                foreach ($disk in Get-VmDiskCandidates -VmName $vm.Name -Vm $vm) {
                    if (Test-IsDeletableDisk -Path $disk) {
                        Write-Host "[vm]     would delete disk: $disk" -ForegroundColor Gray
                    } else {
                        Write-Host "[vm]     would keep disk (not deletable by guard): $disk" -ForegroundColor DarkGray
                    }
                }
            }
        }
        foreach ($orphan in $orphanedDisks) {
            if (Test-IsDeletableDisk -Path $orphan) {
                Write-Host "[vm]   would remove orphaned disk (no matching registered VM): $orphan" -ForegroundColor Yellow
            } else {
                Write-Host "[vm]     would keep orphaned disk (not deletable by guard): $orphan" -ForegroundColor DarkGray
            }
        }
        exit 0
    }

    if ($All) {
        $targets = $matchingVms
    } else {
        $targets = @($matchingVms | Where-Object { $_.Name -eq $Name })
    }

    if ($targets.Count -eq 0) {
        if ($All) {
            # Fall through to the orphan-disk sweep below (empty target list).
            Write-Host "[vm] no VMs matching '$($script:Prefix)*' exist - nothing to remove." -ForegroundColor Gray
        } else {
            # -Name with no matching registered VM: the harness can still
            # have left the differencing disk behind (killed between
            # New-VHD and New-VM, or a failed cleanup) - remove the orphan
            # and any orphaned checkpoint disks (<name>_<guid>.avhdx).
            $removedAny = $false
            $orphanPath = Join-Path $script:VmsDir "$Name.vhdx"
            if ((Test-Path -LiteralPath $orphanPath) -and (Test-IsDeletableDisk -Path $orphanPath)) {
                try {
                    Remove-Item -LiteralPath $orphanPath -Force
                    Write-Host "[vm] orphaned disk removed: $orphanPath" -ForegroundColor Gray
                    $removedAny = $true
                } catch {
                    Write-Host "[vm] FAILED to delete orphaned disk '$orphanPath': $($_.Exception.Message)" -ForegroundColor Red
                    exit 1
                }
            }
            foreach ($ckpt in @(Get-ChildItem -LiteralPath $script:VmsDir -Filter "$($Name)_*.avhdx" -File -ErrorAction SilentlyContinue)) {
                if (-not (Test-IsDeletableDisk -Path $ckpt.FullName)) { continue }
                try {
                    Remove-Item -LiteralPath $ckpt.FullName -Force
                    Write-Host "[vm] orphaned checkpoint disk removed: $($ckpt.FullName)" -ForegroundColor Gray
                    $removedAny = $true
                } catch {
                    Write-Host "[vm] FAILED to delete orphaned checkpoint disk '$($ckpt.FullName)': $($_.Exception.Message)" -ForegroundColor Red
                    exit 1
                }
            }
            if (-not $removedAny) {
                Write-Host "[vm] no VM named '$Name' exists - nothing to remove." -ForegroundColor Gray
            }
            exit 0
        }
    }

    # -----------------------------------------------------------------------
    # Removal. One VM's failure never skips the remaining VMs.
    # -----------------------------------------------------------------------
    $failedCount = 0
    foreach ($vm in $targets) {
        $vmName = $vm.Name
        try {
            Write-Host ("[vm] removing VM: {0} (state: {1})" -f $vmName, $vm.State) -ForegroundColor Yellow
            # Collect disk paths BEFORE Remove-VM (the config disappears with the VM).
            $diskPaths = @(Get-VmDiskCandidates -VmName $vmName -Vm $vm)

            if ($vm.State -ne 'Off') {
                try {
                    Stop-VM -VM $vm -Force
                    Write-Host '[vm]   stopped VM (was not Off).' -ForegroundColor Gray
                } catch {
                    Write-Host "[vm]   Stop-VM failed ($($_.Exception.Message)); attempting Remove-VM anyway." -ForegroundColor DarkYellow
                }
            }
            try {
                Remove-VM -VM $vm -Force
                Write-Host '[vm]   removed VM from Hyper-V.' -ForegroundColor Gray
            } catch {
                Write-Host "[vm]   FAILED to remove VM '$vmName': $($_.Exception.Message)" -ForegroundColor Red
                $failedCount++
                continue
            }

            foreach ($disk in $diskPaths) {
                if (-not (Test-IsDeletableDisk -Path $disk)) {
                    Write-Host "[vm]   keeping disk (guard: outside tests\vm\vms, not a .vhdx/.avhdx, or a sbx-base-* template): $disk" -ForegroundColor DarkGray
                    continue
                }
                if (-not (Test-Path -LiteralPath $disk)) {
                    Write-Host "[vm]   disk already gone: $disk" -ForegroundColor DarkGray
                    continue
                }
                try {
                    Remove-Item -LiteralPath $disk -Force
                    Write-Host "[vm]   deleted differencing disk: $disk" -ForegroundColor Gray
                } catch {
                    Write-Host "[vm]   FAILED to delete disk '$disk': $($_.Exception.Message)" -ForegroundColor Red
                    $failedCount++
                }
            }
        } catch {
            Write-Host "[vm]   FAILED on VM '$vmName': $($_.Exception.Message)" -ForegroundColor Red
            $failedCount++
        }
    }

    if ($All) {
        # Orphan-disk sweep: remove sbx-test-*.vhdx files under tests\vm\vms
        # that belong to no registered VM. Runs AFTER VM removal (a failed
        # Remove-VM keeps the VM registered, so its disk is not swept).
        $remainingVms = $null
        try {
            $remainingVms = @(Get-VM)
        } catch {
            Write-Host "[vm] could not re-enumerate VMs for the orphan-disk sweep - nothing swept: $($_.Exception.Message)" -ForegroundColor Red
            $failedCount++
        }
        if ($null -ne $remainingVms) {
            foreach ($orphan in (Get-OrphanedDisks -RegisteredVms $remainingVms)) {
                if (-not (Test-IsDeletableDisk -Path $orphan)) {
                    Write-Host "[vm]   keeping orphaned disk (guard: outside tests\vm\vms, not a .vhdx/.avhdx, or a sbx-base-* template): $orphan" -ForegroundColor DarkGray
                    continue
                }
                try {
                    Remove-Item -LiteralPath $orphan -Force
                    Write-Host "[vm]   orphaned disk removed: $orphan" -ForegroundColor Gray
                } catch {
                    Write-Host "[vm]   FAILED to delete orphaned disk '$orphan': $($_.Exception.Message)" -ForegroundColor Red
                    $failedCount++
                }
            }
        }
    }

    if ($failedCount -gt 0) {
        Write-Host "[vm] finished with $failedCount failure(s); re-run this script or remove manually." -ForegroundColor Red
        exit 1
    }
    Write-Host '[vm] done.' -ForegroundColor Green
    exit 0
} catch {
    Write-Host "[vm] unexpected error: $($_.Exception.Message)" -ForegroundColor Red
    exit 99
}
