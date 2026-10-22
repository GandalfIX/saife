#Requires -Version 5.1
<#
.SYNOPSIS
  Guest provisioning for the disposable test-VM base image (VM-01 Task 2).
.DESCRIPTION
  Runs INSIDE the image VM (normally via PowerShell Direct, from the copied
  repo at C:\sbx-repo\tests\vm\prepare-guest.ps1), exactly once during image
  build. Idempotent - safe to re-run; every install is guarded by a presence
  check. Windows PowerShell 5.1-compatible on purpose: the first pass may
  run under 5.1 (pwsh is not installed yet - chicken-and-egg), and pwsh is
  one of the things this script installs.

  Steps:
    1. Elevation gate (installs need admin; nothing runs before it).
    2. Winget presence gate. No hand-rolled MSI downloads by design: if
       winget itself is missing, exact remediation is printed and the
       script exits non-zero.
    3. Tool installs, each checked first (idempotence), via winget:
        - PowerShell 7            (Microsoft.PowerShell)
        - Git                     (Git.Git)
        - Python 3, machine-wide, on PATH (Python.Python.3.12; the python
          scenarios need a REAL python.exe - the Microsoft Store execution
          alias degrades to the "Python was not found" stub (exit 9009)
          for AppContainer callers, so it must not count as installed)
        - VS Build Tools 2022 with the C++ workload + Windows SDK
         (Microsoft.VisualStudio.2022.BuildTools, --override
          "--quiet --wait --add Microsoft.VisualStudio.Workload.VCTools
          --includeRecommended") - takes many minutes (10-30+)
       - Rustup                  (Rustlang.Rustup),
         then `rustup default stable-msvc` (idempotent)
    4. Cargo warm-up in -RepoDir: `cargo fetch` + `cargo build --release`.
       Validates the whole MSVC toolchain end-to-end and warms the registry
       cache, which persists in the image. A broken toolchain must be
       discovered at bake time, not test time. Skipped with
       -SkipCargoWarmup (for quick re-runs/tests).
    5. Test-image QoL hardening (best effort, never blocks the verdict):
       Windows Update auto-reboot off, execution policy RemoteSigned
       (LocalMachine), Server Manager auto-open and first-logon animation
       off (skipped when not applicable).

  Prints a final one-line verdict and exits:
    GUEST PREPARED                      -> exit 0
    not elevated                        -> exit 2
    GUEST PREP FAILED: <failed things>  -> exit 3
    winget missing                      -> exit 4 (remediation printed)
    unexpected error                    -> exit 99
.PARAMETER RepoDir
  The copied repo inside the VM (default C:\sbx-repo). Used for the cargo
  warm-up; must exist unless -SkipCargoWarmup is given.
.PARAMETER SkipCargoWarmup
  Skip `cargo fetch` + `cargo build --release` (for quick re-runs/tests).
.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File C:\sbx-repo\tests\vm\prepare-guest.ps1 -RepoDir C:\sbx-repo
  First pass inside the builder VM, under Windows PowerShell 5.1 (pwsh is
  not installed yet; this script installs it).
.EXAMPLE
  pwsh -NoProfile -ExecutionPolicy Bypass -File C:\sbx-repo\tests\vm\prepare-guest.ps1 -SkipCargoWarmup
  Re-run to verify idempotence (skips the multi-minute cargo warm-up).
#>
[CmdletBinding()]
param(
    [string]$RepoDir = 'C:\sbx-repo',
    [switch]$SkipCargoWarmup
)

$ErrorActionPreference = 'Stop'

# Failure accumulator; drives the final GUEST PREP FAILED verdict.
$script:Failed = New-Object System.Collections.Generic.List[string]

function Update-SessionPath {
    # Refresh the current session PATH from Machine + User (installers
    # update those; the running session does not pick them up automatically).
    $machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    $env:Path = "$machinePath;$userPath"
}

function Test-CommandAvailable {
    param([string]$Name)
    return [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

function Test-RealPythonAvailable {
    # True when `python` on PATH is a real interpreter. The Microsoft Store
    # execution alias (.../Microsoft/WindowsApps/python.exe) resolves fine
    # in a normal session but degrades to the "Python was not found" stub
    # (exit 9009) for AppContainer callers - it must NOT count as installed
    # (docs/notes/bugs/2026-08-15-python-store-alias-unusable-in-appcontainer.md).
    $cmd = Get-Command python -ErrorAction SilentlyContinue
    if (-not $cmd) { return $false }
    if ($cmd.Source -match '\\Microsoft\\WindowsApps\\') { return $false }
    $ErrorActionPreference = 'Continue'
    try {
        & $cmd.Source -c "pass" | Out-Null
        return ($LASTEXITCODE -eq 0)
    } catch {
        return $false
    } finally {
        $ErrorActionPreference = 'Stop'
    }
}

function Test-VcToolsInstalled {
    param([string]$VswherePath)
    # True when any installed VS product carries the native C++ workload
    # (which --includeRecommended pairs with the Windows SDK).
    if (-not $VswherePath) { return $false }
    if (-not (Test-Path -LiteralPath $VswherePath)) { return $false }
    try {
        $installPath = & $VswherePath -products * `
            -requires 'Microsoft.VisualStudio.Workload.VCTools' `
            -property 'installationPath'
        if (($LASTEXITCODE -eq 0) -and $installPath) { return $true }
    } catch { }
    return $false
}

function Invoke-ToolCommand {
    # Runs a native tool, streaming its output as tagged console lines.
    # EAP is down-shifted because Windows PowerShell 5.1 turns redirected
    # native stderr into terminating errors under $ErrorActionPreference
    # 'Stop' (routine progress goes to stderr for cargo/rustup/winget).
    param([string]$FilePath, [string[]]$ArgumentList, [string]$WorkingDirectory)
    $ErrorActionPreference = 'Continue'
    try {
        if ($WorkingDirectory) {
            Push-Location -LiteralPath $WorkingDirectory
            try {
                & $FilePath $ArgumentList 2>&1 |
                    ForEach-Object { Write-Host "[vm-guest]   $_" -ForegroundColor DarkGray }
            } finally { Pop-Location }
        } else {
            & $FilePath $ArgumentList 2>&1 |
                ForEach-Object { Write-Host "[vm-guest]   $_" -ForegroundColor DarkGray }
        }
        return $LASTEXITCODE
    } finally {
        $ErrorActionPreference = 'Stop'
    }
}

function Invoke-WingetInstall {
    # -Override REPLACES winget's default silent switches entirely (and must
    # therefore carry its own /quiet etc.) - used when an installer needs
    # exact control, e.g. Python's machine-wide + PrependPath variables.
    param([string]$Id, [string[]]$ExtraArgs, [string]$Override)
    $wingetArgs = @('install', '--id', $Id, '--exact', '--source', 'winget',
        '--accept-package-agreements', '--accept-source-agreements')
    if ($Override) {
        $wingetArgs += @('--override', $Override)
    } else {
        $wingetArgs += '--silent'
        if ($ExtraArgs) { $wingetArgs += $ExtraArgs }
    }
    Write-Host "[vm-guest]   winget $($wingetArgs -join ' ')" -ForegroundColor DarkGray
    return (Invoke-ToolCommand -FilePath 'winget' -ArgumentList $wingetArgs)
}

try {
    # -----------------------------------------------------------------------
    # 1. Elevation - first gate; nothing is installed or changed before it.
    # -----------------------------------------------------------------------
    $windowsIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $windowsPrincipal = New-Object Security.Principal.WindowsPrincipal($windowsIdentity)
    if (-not $windowsPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host '[vm-guest] not elevated - run from an elevated (administrator) shell inside the VM, then re-run prepare-guest.ps1' -ForegroundColor Red
        exit 2
    }
    Write-Host '[vm-guest] running elevated; provisioning guest...' -ForegroundColor Gray
    $RepoDir = [System.IO.Path]::GetFullPath($RepoDir)

    # -----------------------------------------------------------------------
    # 2. Winget gate - no silent skip, no hand-rolled MSI downloads.
    # -----------------------------------------------------------------------
    if (-not (Test-CommandAvailable 'winget')) {
        Write-Host '[vm-guest] winget is missing - tools cannot be installed automatically, and this script does not hand-roll MSI downloads.' -ForegroundColor Red
        Write-Host '[vm-guest] remediation (pick one):' -ForegroundColor Yellow
        Write-Host '[vm-guest]   1. install App Installer (winget) from its GitHub release: https://github.com/microsoft/winget-cli/releases (latest Microsoft.DesktopAppInstaller msixbundle plus its VCLibs/Microsoft.UI.Xaml dependency .appx files, install via Add-AppxPackage), or' -ForegroundColor Yellow
        Write-Host '[vm-guest]   2. install the tools manually with their official installers - VS Build Tools: https://aka.ms/vs/17/release/vs_BuildTools.exe (run with --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended --quiet), Rustup: https://rustup.rs, PowerShell 7: https://github.com/PowerShell/PowerShell/releases, Git: https://git-scm.com/download/win, Python: https://www.python.org/downloads/ (machine-wide: /quiet InstallAllUsers=1 PrependPath=1) -' -ForegroundColor Yellow
        Write-Host '[vm-guest]   In either case, re-run this script afterwards to verify everything is present.' -ForegroundColor Yellow
        exit 4
    }
    Write-Host '[vm-guest] winget present.' -ForegroundColor Green

    # -----------------------------------------------------------------------
    # 3a. PowerShell 7.
    # -----------------------------------------------------------------------
    if (Test-CommandAvailable 'pwsh') {
        Write-Host '[vm-guest] PowerShell 7 already present.' -ForegroundColor Green
    } else {
        Write-Host '[vm-guest] installing PowerShell 7 (Microsoft.PowerShell)...' -ForegroundColor Yellow
        $installExit = Invoke-WingetInstall -Id 'Microsoft.PowerShell'
        Update-SessionPath
        if (($installExit -eq 0) -and (Test-CommandAvailable 'pwsh')) {
            Write-Host '[vm-guest] PowerShell 7 installed.' -ForegroundColor Green
        } else {
            Write-Host "[vm-guest] FAILED: PowerShell 7 install (winget exit $installExit)." -ForegroundColor Red
            $script:Failed.Add('PowerShell 7 (Microsoft.PowerShell)')
        }
    }

    # -----------------------------------------------------------------------
    # 3b. Git.
    # -----------------------------------------------------------------------
    if (Test-CommandAvailable 'git') {
        Write-Host '[vm-guest] Git already present.' -ForegroundColor Green
    } else {
        Write-Host '[vm-guest] installing Git (Git.Git)...' -ForegroundColor Yellow
        $installExit = Invoke-WingetInstall -Id 'Git.Git'
        Update-SessionPath
        if (($installExit -eq 0) -and (Test-CommandAvailable 'git')) {
            Write-Host '[vm-guest] Git installed.' -ForegroundColor Green
        } else {
            Write-Host "[vm-guest] FAILED: Git install (winget exit $installExit)." -ForegroundColor Red
            $script:Failed.Add('Git (Git.Git)')
        }
    }

    # -----------------------------------------------------------------------
    # 3c. Python 3 - machine-wide (InstallAllUsers=1) and on the machine
    #     PATH (PrependPath=1). The test harness's python scenarios run
    #     `python` inside the AppContainer, where the Microsoft Store
    #     execution alias is unusable (stub, exit 9009), so a real
    #     C:\Program Files\Python3xx\python.exe must shadow it. Machine PATH
    #     precedes the user-PATH WindowsApps alias dir, so `python` resolves
    #     deterministically. Program Files carries ALL APPLICATION PACKAGES
    #     read+execute ACEs, so the AppContainer can run it.
    # -----------------------------------------------------------------------
    if (Test-RealPythonAvailable) {
        Write-Host '[vm-guest] real Python (not the Store alias) already present.' -ForegroundColor Green
    } else {
        Write-Host '[vm-guest] installing Python (Python.Python.3.12, machine-wide, on PATH)...' -ForegroundColor Yellow
        $installExit = Invoke-WingetInstall -Id 'Python.Python.3.12' -Override '/quiet InstallAllUsers=1 PrependPath=1'
        Update-SessionPath
        if (($installExit -eq 0) -and (Test-RealPythonAvailable)) {
            Write-Host '[vm-guest] Python installed.' -ForegroundColor Green
        } else {
            Write-Host "[vm-guest] FAILED: Python install (winget exit $installExit)." -ForegroundColor Red
            $script:Failed.Add('Python (Python.Python.3.12)')
        }
    }

    # -----------------------------------------------------------------------
    # 3d. VS Build Tools with the C++ workload + Windows SDK (idempotence
    #     via vswhere; winget would otherwise re-run the VS installer).
    # -----------------------------------------------------------------------
    $vswhere = $null
    if (${env:ProgramFiles(x86)}) {
        $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    }
    if (Test-VcToolsInstalled -VswherePath $vswhere) {
        Write-Host '[vm-guest] VS Build Tools with the C++ workload already present.' -ForegroundColor Green
    } else {
        Write-Host '[vm-guest] installing VS Build Tools 2022 C++ workload + Windows SDK (Microsoft.VisualStudio.2022.BuildTools)...' -ForegroundColor Yellow
        Write-Host '[vm-guest]   this takes many minutes (10-30+); the winget call blocks until the VS installer finishes - do not interrupt it.' -ForegroundColor Yellow
        $vsOverride = '--quiet --wait --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended'
        $installExit = Invoke-WingetInstall -Id 'Microsoft.VisualStudio.2022.BuildTools' -ExtraArgs @('--override', $vsOverride)
        if (Test-VcToolsInstalled -VswherePath $vswhere) {
            Write-Host "[vm-guest] VS Build Tools C++ workload installed (winget exit $installExit)." -ForegroundColor Green
        } else {
            Write-Host "[vm-guest] FAILED: VS Build Tools C++ workload install (winget exit $installExit; if the installer requested a reboot - exit 3010 - reboot the VM once, then re-run this script to verify)." -ForegroundColor Red
            $script:Failed.Add('VS Build Tools C++ workload + Windows SDK (Microsoft.VisualStudio.2022.BuildTools)')
        }
    }

    # -----------------------------------------------------------------------
    # 3e. Rustup + default MSVC toolchain.
    # -----------------------------------------------------------------------
    $rustupPath = Join-Path $env:USERPROFILE '.cargo\bin\rustup.exe'
    $cargoPath = Join-Path $env:USERPROFILE '.cargo\bin\cargo.exe'
    if ((Test-CommandAvailable 'rustup') -or (Test-Path -LiteralPath $rustupPath)) {
        Write-Host '[vm-guest] Rustup already present.' -ForegroundColor Green
    } else {
        Write-Host '[vm-guest] installing Rustup (Rustlang.Rustup)...' -ForegroundColor Yellow
        $installExit = Invoke-WingetInstall -Id 'Rustlang.Rustup'
        Update-SessionPath
        if ((Test-CommandAvailable 'rustup') -or (Test-Path -LiteralPath $rustupPath)) {
            Write-Host "[vm-guest] Rustup installed (winget exit $installExit)." -ForegroundColor Green
        } else {
            Write-Host "[vm-guest] FAILED: Rustup install (winget exit $installExit)." -ForegroundColor Red
            $script:Failed.Add('Rustup (Rustlang.Rustup)')
        }
    }

    $rustupCmd = Get-Command rustup -ErrorAction SilentlyContinue
    $rustupExe = $null
    if ($rustupCmd) { $rustupExe = $rustupCmd.Source }
    elseif (Test-Path -LiteralPath $rustupPath) { $rustupExe = $rustupPath }
    if (-not $rustupExe) {
        Write-Host '[vm-guest] FAILED: rustup not found - cannot set the default toolchain.' -ForegroundColor Red
        $script:Failed.Add('rustup default stable-msvc')
    } else {
        Write-Host '[vm-guest] setting rustup default toolchain to stable-msvc (downloads the MSVC toolchain on the first run)...' -ForegroundColor Yellow
        $rustupExit = Invoke-ToolCommand -FilePath $rustupExe -ArgumentList @('default', 'stable-msvc')
        if ($rustupExit -eq 0) {
            Write-Host '[vm-guest] rustup default toolchain: stable-msvc.' -ForegroundColor Green
        } else {
            Write-Host "[vm-guest] FAILED: rustup default stable-msvc (exit $rustupExit)." -ForegroundColor Red
            $script:Failed.Add('rustup default stable-msvc')
        }
    }

    # -----------------------------------------------------------------------
    # 4. Cargo warm-up - end-to-end toolchain validation + registry cache
    #    that persists in the image. Failures surface at bake time.
    # -----------------------------------------------------------------------
    if ($SkipCargoWarmup) {
        Write-Host '[vm-guest] skipping cargo warm-up (-SkipCargoWarmup).' -ForegroundColor Gray
    } elseif (-not (Test-Path -LiteralPath $RepoDir)) {
        Write-Host "[vm-guest] FAILED: cargo warm-up - repo dir not found: $RepoDir (copy the repo into the VM first; see tests\vm\BUILD-BASE-IMAGE.md)." -ForegroundColor Red
        $script:Failed.Add('cargo warm-up (repo dir missing)')
    } else {
        $cargoCmd = Get-Command cargo -ErrorAction SilentlyContinue
        $cargoExe = $null
        if ($cargoCmd) { $cargoExe = $cargoCmd.Source }
        elseif (Test-Path -LiteralPath $cargoPath) { $cargoExe = $cargoPath }
        if (-not $cargoExe) {
            Write-Host '[vm-guest] FAILED: cargo warm-up - cargo not found (Rustup install failed above?).' -ForegroundColor Red
            $script:Failed.Add('cargo warm-up (cargo not found)')
        } else {
            Write-Host "[vm-guest] cargo fetch in $RepoDir (warming the registry cache; downloads all crate dependencies)..." -ForegroundColor Yellow
            $fetchExit = Invoke-ToolCommand -FilePath $cargoExe -ArgumentList @('fetch') -WorkingDirectory $RepoDir
            if ($fetchExit -ne 0) {
                Write-Host "[vm-guest] FAILED: cargo fetch (exit $fetchExit) - a broken toolchain must be discovered at bake time, not test time." -ForegroundColor Red
                $script:Failed.Add('cargo warm-up (cargo fetch)')
            } else {
                Write-Host '[vm-guest] cargo fetch done; running cargo build --release (validates the full MSVC toolchain end-to-end; several minutes)...' -ForegroundColor Yellow
                $warmBuildExit = Invoke-ToolCommand -FilePath $cargoExe -ArgumentList @('build', '--release') -WorkingDirectory $RepoDir
                if ($warmBuildExit -ne 0) {
                    Write-Host "[vm-guest] FAILED: cargo build --release (exit $warmBuildExit) - a broken toolchain must be discovered at bake time, not test time." -ForegroundColor Red
                    $script:Failed.Add('cargo warm-up (cargo build --release)')
                } else {
                    Write-Host '[vm-guest] cargo warm-up complete (registry cache + release build baked into the image).' -ForegroundColor Green
                }
            }
        }
    }

    # -----------------------------------------------------------------------
    # 5. Test-image QoL hardening (best effort; failures warn, never block).
    # -----------------------------------------------------------------------
    try {
        $wuAuKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
        if (-not (Test-Path -LiteralPath $wuAuKey)) {
            New-Item -Path $wuAuKey -Force | Out-Null
        }
        # Constant registry paths (no wildcards); New-Item/New-ItemProperty
        # take -Path here.
        New-ItemProperty -Path $wuAuKey -Name 'NoAutoRebootWithLoggedOnUsers' -Value 1 -PropertyType DWord -Force | Out-Null
        Write-Host '[vm-guest] Windows Update auto-reboot disabled (NoAutoRebootWithLoggedOnUsers=1).' -ForegroundColor Green
    } catch {
        Write-Host "[vm-guest] WARNING: could not disable Windows Update auto-reboot: $($_.Exception.Message)" -ForegroundColor Yellow
    }

    try {
        Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine -Force
        Write-Host '[vm-guest] execution policy set to RemoteSigned (LocalMachine).' -ForegroundColor Green
    } catch {
        Write-Host "[vm-guest] WARNING: could not set execution policy: $($_.Exception.Message)" -ForegroundColor Yellow
    }

    try {
        $serverManagerKey = 'HKLM:\SOFTWARE\Microsoft\ServerManager'
        if (Test-Path -LiteralPath $serverManagerKey) {
            New-ItemProperty -Path $serverManagerKey -Name 'DoNotOpenServerManagerAtLogon' -Value 1 -PropertyType DWord -Force | Out-Null
            Write-Host '[vm-guest] Server Manager auto-open at logon disabled.' -ForegroundColor Green
        } else {
            Write-Host '[vm-guest] Server Manager key absent (client SKU) - skipped.' -ForegroundColor Gray
        }
    } catch {
        Write-Host "[vm-guest] WARNING: could not disable Server Manager auto-open: $($_.Exception.Message)" -ForegroundColor Yellow
    }

    try {
        $policySystemKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
        New-ItemProperty -Path $policySystemKey -Name 'EnableFirstLogonAnimation' -Value 0 -PropertyType DWord -Force | Out-Null
        Write-Host '[vm-guest] first-logon animation disabled.' -ForegroundColor Green
    } catch {
        Write-Host "[vm-guest] WARNING: could not disable first-logon animation: $($_.Exception.Message)" -ForegroundColor Yellow
    }

    # -----------------------------------------------------------------------
    # 6. Final verdict (fail-closed).
    # -----------------------------------------------------------------------
    if ($script:Failed.Count -eq 0) {
        Write-Host 'GUEST PREPARED' -ForegroundColor Green
        exit 0
    }
    Write-Host "GUEST PREP FAILED: $($script:Failed -join ', ')" -ForegroundColor Red
    exit 3
} catch {
    Write-Host "[vm-guest] unexpected error: $($_.Exception.Message)" -ForegroundColor Red
    exit 99
}
