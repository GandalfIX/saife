#Requires -Version 7.0
<#
.SYNOPSIS
    Checks that everything needed to build SAIFE Sandbox from source is installed.

.DESCRIPTION
    Reports every build prerequisite with the version found, and for anything missing prints the
    exact command that installs it. With -Install it offers to run those commands; it never
    elevates - a step that needs administrator rights is printed and skipped, because a build tool
    should not quietly open a UAC prompt for you.

    Exit codes: 0 everything required is present, 1 something required is missing, 2 usage error.

.PARAMETER Install
    Ask before installing each missing package. Anything that needs an administrator is printed
    instead of run.

.PARAMETER Yes
    With -Install, install everything that can be installed without asking. Administrator-only
    steps are still only printed.

.PARAMETER SkipOptional
    Report required build prerequisites only. The container engine and GitHub CLI are optional.

.PARAMETER Json
    Machine-readable output for CI. Implies no prompting.

.EXAMPLE
    pwsh -File packaging\check-prereqs.ps1

.EXAMPLE
    pwsh -File packaging\check-prereqs.ps1 -Install

.EXAMPLE
    pwsh -File packaging\check-prereqs.ps1 -Json -SkipOptional
#>
[CmdletBinding()]
param(
    [switch]$Install,
    [switch]$Yes,
    [switch]$SkipOptional,
    [switch]$Json
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if ($Json) { $Install = $false }

# winget arguments shared by every step: non-interactive, no prompts, agreement flags.
$wingetBase = @('--source', 'winget', '--accept-package-agreements', '--accept-source-agreements', '--disable-interactivity')

function Test-Command {
    param([string]$Name)
    $null -ne (Get-Command $Name -ErrorAction SilentlyContinue)
}

function Get-FirstLine {
    param([string]$Exe, [string[]]$Arguments)
    try {
        $out = & $Exe @Arguments 2>&1 | Out-String
        return ($out -split "`r?`n" | Where-Object { $_.Trim() } | Select-Object -First 1).Trim()
    } catch {
        return $null
    }
}

function Get-RustVersion {
    if (-not (Test-Command 'rustc')) { return $null }
    $line = Get-FirstLine 'rustc' @('--version')
    if (-not $line) { return $null }
    $m = [regex]::Match($line, 'rustc\s+(\d+\.\d+\.\d+)')
    if (-not $m.Success) { return $line }
    return [version]$m.Groups[1].Value
}

function Get-MsvcInstall {
    # A developer prompt already has link.exe on PATH; otherwise ask the Visual Studio installer.
    if (Test-Command 'link.exe') { return 'on PATH' }
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (-not (Test-Path -LiteralPath $vswhere)) { return $null }
    $path = & $vswhere -products * -latest -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath 2>$null
    if ($path) { return (Split-Path -Leaf $path) }
    return $null
}

function Get-RustComponent {
    param([string]$Name)
    if (-not (Test-Command 'rustup')) { return $false }
    $installed = & rustup component list --installed 2>$null
    return [bool]($installed | Where-Object { $_ -match "^$Name-" })
}

function Get-WindowsBuild { return [Environment]::OSVersion.Version.Build }

# rustc's host triple and the triple this checkout would build for. `--target` on the command line
# cannot be seen from here, which is why the report prints the triple it assumed.
function Get-RustTriple {
    param([string[]]$Arguments)
    if (-not (Test-Command 'rustc')) { return $null }
    $out = & rustc @Arguments 2>$null
    $line = $out | Where-Object { $_ -match '^host:' }
    if (-not $line) { return $null }
    return ($line -replace '^host:\s*', '').Trim()
}

$script:HostTriple = Get-RustTriple '-vV'
$script:TargetTriple = $script:HostTriple
if ($env:CARGO_BUILD_TARGET) {
    $script:TargetTriple = $env:CARGO_BUILD_TARGET
} elseif (Test-Command 'cargo') {
    try {
        $cfg = (& cargo config get build.target 2>$null | Out-String)
        $m = [regex]::Match($cfg, '([a-z0-9_]+-[a-z0-9_]+-[a-z0-9_]+)')
        if ($m.Success) { $script:TargetTriple = $m.Groups[1].Value }
    } catch { }
}
$script:IsArm = [bool]($script:TargetTriple -and $script:TargetTriple -match '^aarch64-')

# One vcvars invocation serves three checks: does cl.exe actually run, which SDK is attached, and
# is the ARM64 toolset present. Cached, because vcvars costs seconds.
$script:MsvcProbe = $null
function Get-MsvcProbe {
    if ($script:MsvcProbe) { return $script:MsvcProbe }
    $r = @{ Ok = $false; Cl = $null; Sdk = $null; VcVars = $false; Why = '' ; Vs = '' }

    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (-not (Test-Path -LiteralPath $vswhere)) {
        $r.Why = 'no Visual Studio installer (vswhere.exe)'
        $script:MsvcProbe = $r; return $r
    }
    $vs = & $vswhere -products * -latest -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath 2>$null
    if (-not $vs) {
        $r.Why = 'no install with the C++ x64 toolset'
        $script:MsvcProbe = $r; return $r
    }
    $r.Vs = Split-Path -Leaf $vs
    $vcvars = Join-Path $vs 'VC\Auxiliary\Build\vcvars64.bat'
    if (-not (Test-Path -LiteralPath $vcvars)) {
        $r.Why = 'VC\Auxiliary\Build\vcvars64.bat is missing (C++ workload incomplete)'
        $script:MsvcProbe = $r; return $r
    }
    $r.VcVars = $true
    $line = & cmd /c "call `"$vcvars`" >nul 2>&1 & set WindowsSDKVersion & cl 2>&1"
    $text = ($line | Out-String)
    $m = [regex]::Match($text, 'Compiler Version\s+([\d.]+)')
    $sdk = [regex]::Match($text, 'WindowsSDKVersion=([\d.]+)')
    if (-not $sdk.Success) { $sdk = [regex]::Match($text, 'WindowsSDKVersion=([^\r\n]+)') }
    if ($m.Success) { $r.Cl = $m.Groups[1].Value }
    if ($sdk.Success) { $r.Sdk = $sdk.Groups[1].Value }
    $r.Ok = [bool]$r.Cl
    if (-not $r.Ok) { $r.Why = 'vcvars64.bat ran but cl.exe did not' }
    $script:MsvcProbe = $r
    return $r
}

function Test-VsComponent {
    param([string]$Component)
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (-not (Test-Path -LiteralPath $vswhere)) { return $false }
    $path = & $vswhere -products * -latest -requires $Component -property installationPath 2>$null
    return [bool]$path
}

function Resolve-Clang {
    # cc-rs runs `c.compiler("clang")`, i.e. it resolves the bare name from PATH. A Visual Studio
    # "C++ Clang compiler for Windows" component puts clang.exe under VC\Tools\Llvm\...\bin and does
    # NOT add it to PATH - so a registered component is not a usable compiler, and reporting it as
    # present is how this check lied once. Only PATH counts as ok.
    $r = @{ OnPath = $null; Elsewhere = @() }

    $cmd = Get-Command 'clang' -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($cmd) {
        $v = & $cmd.Source --version 2>$null | Select-Object -First 1
        $r.OnPath = if ($v) { "$v  ($($cmd.Source))" } else { $cmd.Source }
        return $r
    }

    $candidates = @()
    $llvm = Join-Path ${env:ProgramFiles} 'LLVM\bin\clang.exe'
    if (Test-Path -LiteralPath $llvm) { $candidates += $llvm }

    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (Test-Path -LiteralPath $vswhere) {
        foreach ($vs in @(& $vswhere -products * -property installationPath 2>$null)) {
            if (-not $vs) { continue }
            foreach ($pattern in 'VC\Tools\Llvm\bin\clang.exe', 'VC\Tools\Llvm\*\bin\clang.exe') {
                $candidates += @(Get-ChildItem -Path (Join-Path $vs $pattern) -ErrorAction SilentlyContinue |
                    ForEach-Object { $_.FullName })
            }
        }
    }
    $r.Elsewhere = @($candidates | Where-Object { $_ } | Select-Object -Unique)
    return $r
}

function Get-DockerState {
    if (-not (Test-Command 'docker')) { return $null }
    $server = & docker version --format '{{.Server.Version}}' 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $server) { return 'installed, engine not running' }
    return "engine $server"
}

# Each entry: how to detect it, what it is for, and how to install it. `Admin` marks a step that
# needs an elevated shell; those are printed, never executed.
$checks = @(
    @{
        Name     = 'Rust 1.88+ MSVC toolchain'
        Category = 'required'
        Why      = 'edition 2024, rust-version = 1.88 (Cargo.toml)'
        Probe    = {
            $v = Get-RustVersion
            if (-not $v) { return @{ Ok = $false } }
            if ($v -is [version] -and $v -lt [version]'1.88') {
                return @{ Ok = $false; Found = "$v (too old)" }
            }
            $host_ = & rustc -vV 2>$null | Where-Object { $_ -match '^host:' }
            return @{ Ok = $true; Found = "$v" + $(if ($host_) { " — $($host_ -replace '^host:\s*','')" } else { '' }) }
        }
        Fix      = @(
            @{ Exe = 'winget'; Args = @('install', '--id', 'Rustlang.Rustup', '-e') + $wingetBase; Admin = $false
               Label = 'winget install --id Rustlang.Rustup -e' }
            @{ Exe = 'rustup'; Args = @('default', 'stable-x86_64-pc-windows-msvc'); Admin = $false
               Label = 'rustup default stable-x86_64-pc-windows-msvc' }
        )
        WhenMissing = 'https://rustup.rs'
    }
    @{
        Name     = 'MSVC C++ toolset (cl.exe, link.exe)'
        Category = 'required'
        Why      = 'the linker Rust does not ship; its absence looks like a Rust error'
        Probe    = {
            $p = Get-MsvcProbe
            if ($p.Ok) { return @{ Ok = $true; Found = "cl $($p.Cl) - $($p.Vs)" } }
            if (Get-MsvcInstall) { return @{ Ok = $false; Found = $p.Why } }
            return @{ Ok = $false; Found = $p.Why }
        }
        Fix      = @(
            @{ Exe = 'winget'; Args = @('install', '--id', 'Microsoft.VisualStudio.2022.BuildTools', '-e',
                    '--override', '--quiet --wait --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended') + $wingetBase
               Admin = $true
               Label = 'winget install --id Microsoft.VisualStudio.2022.BuildTools -e --override "--quiet --wait --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"' }
        )
        WhenMissing = 'https://aka.ms/vs/17/release/vs_BuildTools.exe'
    }
    @{
        Name     = 'Windows SDK (um + ucrt libs)'
        Category = 'required'
        Why      = 'every Windows link needs kernel32.lib and the ucrt; a missing SDK fails at link time, not at compile time'
        Probe    = {
            $p = Get-MsvcProbe
            if (-not $p.Ok) { return @{ Ok = $false; Found = 'cannot tell without a working toolset' } }
            if (-not $p.Sdk) { return @{ Ok = $false; Found = 'no Windows SDK reported by vcvars' } }
            $arch = if ($script:IsArm) { 'arm64' } else { 'x64' }
            $lib = Join-Path ${env:ProgramFiles(x86)} "Windows Kits\10\Lib\$($p.Sdk)\um\$arch\kernel32.lib"
            if (Test-Path -LiteralPath $lib) { return @{ Ok = $true; Found = "SDK $($p.Sdk)" } }
            return @{ Ok = $false; Found = "SDK $($p.Sdk) but no $arch kernel32.lib" }
        }
        Fix      = @(
            @{ Exe = 'winget'; Args = @('install', '--id', 'Microsoft.VisualStudio.2022.BuildTools', '-e',
                    '--override', '--quiet --wait --add Microsoft.VisualStudio.Component.Windows11SDK.26100') + $wingetBase
               Admin = $true
               Label = 'winget install --id Microsoft.VisualStudio.2022.BuildTools -e --override "--add Microsoft.VisualStudio.Component.Windows11SDK.26100"' }
        )
        WhenMissing = 'https://developer.microsoft.com/windows/downloads/windows-sdk/'
    }
    @{
        Name     = 'rustfmt component'
        Category = 'required'
        Why      = 'the repo is formatted with rustfmt; rustfmt.toml pins newline_style = Windows'
        Probe    = { @{ Ok = (Get-RustComponent 'rustfmt'); Found = $(if (Get-RustComponent 'rustfmt') { 'installed' } else { '' }) } }
        Fix      = @(@{ Exe = 'rustup'; Args = @('component', 'add', 'rustfmt'); Admin = $false; Label = 'rustup component add rustfmt' })
        WhenMissing = 'https://rustup.rs'
    }
    @{
        Name     = 'clippy component'
        Category = 'required'
        Why      = 'cargo clippy --all-targets must report zero warnings in both feature states'
        Probe    = { @{ Ok = (Get-RustComponent 'clippy'); Found = $(if (Get-RustComponent 'clippy') { 'installed' } else { '' }) } }
        Fix      = @(@{ Exe = 'rustup'; Args = @('component', 'add', 'clippy'); Admin = $false; Label = 'rustup component add clippy' })
        WhenMissing = 'https://rustup.rs'
    }
    @{
        Name     = 'PowerShell 7 (pwsh)'
        Category = 'required'
        Why      = 'every packaging and test script declares #Requires -Version 7'
        Probe    = {
            $v = Get-FirstLine 'pwsh' @('--version')
            if (-not $v) { return @{ Ok = $false } }
            return @{ Ok = $true; Found = $v }
        }
        Fix      = @(@{ Exe = 'winget'; Args = @('install', '--id', 'Microsoft.PowerShell', '-e') + $wingetBase; Admin = $false
                        Label = 'winget install --id Microsoft.PowerShell -e' })
        WhenMissing = 'https://aka.ms/powershell'
    }
    @{
        Name     = 'git'
        Category = 'required'
        Why      = 'sources are CRLF by contract (.gitattributes: *.rs text eol=crlf)'
        Probe    = {
            $v = Get-FirstLine 'git' @('--version')
            if (-not $v) { return @{ Ok = $false } }
            return @{ Ok = $true; Found = $v }
        }
        Fix      = @(@{ Exe = 'winget'; Args = @('install', '--id', 'Git.Git', '-e') + $wingetBase; Admin = $true
                        Label = 'winget install --id Git.Git -e' })
        WhenMissing = 'https://git-scm.com/download/win'
    }
    @{
        Name     = 'Windows PowerShell 5.1'
        Category = 'required'
        Why      = 'scripts that run *inside* a session are 5.1, because that is what stock Windows has'
        Probe    = {
            $ps51 = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
            if (Test-Path -LiteralPath $ps51) { return @{ Ok = $true; Found = 'present' } }
            return @{ Ok = $false }
        }
        Fix      = @()
        WhenMissing = 'Windows Feature: Windows PowerShell 2.0 Engine / built-in (usually disabled by policy)'
    }
    @{
        Name     = 'Windows 11 24H2+ (build 26100)'
        Category = 'runtime'
        Why      = 'needed to RUN the mxc backend, not to build; appcontainer works from Windows 10 1709'
        Probe    = {
            $b = Get-WindowsBuild
            return @{ Ok = ($b -ge 26100); Found = "build $b" }
        }
        Fix      = @()
        WhenMissing = 'Windows Update to 24H2, or use --backend appcontainer'
    }
    @{
        Name     = 'Container engine (runner only)'
        Category = 'optional'
        Why      = 'only for --runner, saife runner prewarm and saife runner status'
        Probe    = {
            $v = Get-DockerState
            if (-not $v) { return @{ Ok = $false } }
            return @{ Ok = ($v -notmatch 'not running'); Found = $v }
        }
        Fix      = @(@{ Exe = 'winget'; Args = @('install', '--id', 'Rancher.RancherDesktop', '-e') + $wingetBase; Admin = $false
                        Label = 'winget install --id Rancher.RancherDesktop -e   (or Docker.DockerDesktop)' })
        WhenMissing = 'https://rancherdesktop.io or https://docs.docker.com/desktop/'
    }
    @{
        Name     = 'GitHub CLI (gh)'
        Category = 'optional'
        Why      = 'the PR flow and reading CI; not needed to build'
        Probe    = {
            $v = Get-FirstLine 'gh' @('--version')
            if (-not $v) { return @{ Ok = $false } }
            return @{ Ok = $true; Found = $v }
        }
        Fix      = @(@{ Exe = 'winget'; Args = @('install', '--id', 'GitHub.cli', '-e') + $wingetBase; Admin = $true
                        Label = 'winget install --id GitHub.cli -e' })
        WhenMissing = 'https://cli.github.com'
    }
)

# Two prerequisites exist only for ARM64 targets, and both are hard requirements there: ring 0.17
# forces `clang` when target.arch == AARCH64 (build.rs:563 - MSVC cl.exe is not accepted for its
# ARM64 assembly), and MSVC's ARM64 toolset is needed to link the result. On x64 neither is used,
# which is why they are dropped rather than reported as missing.
if ($script:IsArm) {
    $checks += @(
        @{
            Name     = 'clang (LLVM) - ARM64 target'
            Category = 'required'
            Why      = 'ring 0.17.14 forces clang for aarch64-pc-windows-msvc; without it the build stops with ToolNotFound: failed to find tool "clang"'
            Probe    = {
                $c = Resolve-Clang
                if ($c.OnPath) { return @{ Ok = $true; Found = $c.OnPath } }
                $first = @($c.Elsewhere | Select-Object -First 1)
                if ($first.Count -gt 0) {
                    $v = & $first[0] --version 2>$null | Select-Object -First 1
                    $what = if ($v) { $v } else { 'did not run' }
                    return @{ Ok = $false; Found = "found at $($first[0]) ($what) but clang is not on PATH - cc-rs resolves it from PATH" }
                }
                return @{ Ok = $false; Found = 'not on PATH and no LLVM install found' }
            }
            Fix      = @(
                # A PATH change is the user's call, so this one is printed and never executed.
                @{ Exe = $null; Admin = $false
                   Label = 'add the LLVM bin directory to PATH for this user, then open a new shell: [Environment]::SetEnvironmentVariable(''Path'', "$env:PATH;<llvm-bin>", ''User'')' }
                @{ Exe = 'winget'; Args = @('install', '--id', 'LLVM.LLVM', '-e') + $wingetBase; Admin = $true
                   Label = 'winget install --id LLVM.LLVM -e   (installs LLVM and puts it on PATH)' }
                @{ Exe = 'winget'; Args = @('install', '--id', 'Microsoft.VisualStudio.2022.BuildTools', '-e',
                        '--override', '--quiet --wait --add Microsoft.VisualStudio.Component.VC.Llvm.Clang --includeRecommended') + $wingetBase
                   Admin = $true
                   Label = 'winget install --id Microsoft.VisualStudio.2022.BuildTools -e --override "--add Microsoft.VisualStudio.Component.VC.Llvm.Clang"   (then add its bin directory to PATH - see above)' }
            )
            WhenMissing = 'https://releases.llvm.org or the Visual Studio installer'
        }
        @{
            Name     = 'MSVC ARM64 toolset - ARM64 target'
            Category = 'required'
            Why      = 'the ARM64 linker and libraries are a separate Visual Studio component from the x64 toolset'
            Probe    = {
                if (Test-VsComponent 'Microsoft.VisualStudio.Component.VC.Tools.ARM64') {
                    return @{ Ok = $true; Found = 'VC.Tools.ARM64' }
                }
                return @{ Ok = $false; Found = 'VC.Tools.ARM64 not installed' }
            }
            Fix      = @(
                @{ Exe = 'winget'; Args = @('install', '--id', 'Microsoft.VisualStudio.2022.BuildTools', '-e',
                        '--override', '--quiet --wait --add Microsoft.VisualStudio.Component.VC.Tools.ARM64 --includeRecommended') + $wingetBase
                   Admin = $true
                   Label = 'winget install --id Microsoft.VisualStudio.2022.BuildTools -e --override "--add Microsoft.VisualStudio.Component.VC.Tools.ARM64"' }
            )
            WhenMissing = 'https://aka.ms/vs/17/release/vs_BuildTools.exe'
        }
    )
}

# Cross-building the arm64 archive on an x64 host is a supported, optional thing to do: ring forces
# clang for aarch64, and `winget install LLVM.LLVM` is sufficient - measured, with no INCLUDE prelude
# and no vcvars shell (that requirement belonged to the llvm-mingw build, not to clang itself).
if (-not $script:IsArm) {
    $checks += @(
        @{
            Name     = 'clang (LLVM) - optional, for -Arch arm64'
            Category = 'optional'
            Why      = 'only needed to CROSS-BUILD the arm64 archive on this x64 host: ring 0.17.14 forces clang for aarch64-pc-windows-msvc. Not needed for the x64 build or to run anything'
            Probe    = {
                $c = Resolve-Clang
                if ($c.OnPath) { return @{ Ok = $true; Found = $c.OnPath } }
                $first = @($c.Elsewhere | Select-Object -First 1)
                if ($first.Count -gt 0) {
                    return @{ Ok = $false; Found = "installed at $($first[0]) but clang is not on PATH" }
                }
                return @{ Ok = $false; Found = 'not on PATH and no LLVM install found' }
            }
            Fix      = @(
                @{ Exe = 'winget'; Args = @('install', '--id', 'LLVM.LLVM', '-e') + $wingetBase; Admin = $true
                   Label = 'winget install --id LLVM.LLVM -e' }
            )
            WhenMissing = 'https://releases.llvm.org - or skip it: only `build-dist.ps1 -Arch arm64` needs it'
        }
    )
}

if ($SkipOptional) {
    $checks = $checks | Where-Object { $_.Category -ne 'optional' }
}

$results = foreach ($c in $checks) {
    $probe = & $c.Probe
    [pscustomobject]@{
        Name     = $c.Name
        Category = $c.Category
        Why      = $c.Why
        Ok       = [bool]$probe.Ok
        Found    = if ($probe.ContainsKey('Found')) { [string]$probe.Found } else { '' }
        Fix      = @($c.Fix | Where-Object { $_ })
        WhenMissing = $c.WhenMissing
    }
}
$results = @($results)

$missing = @($results | Where-Object { -not $_.Ok })

# ---------------------------------------------------------------- install offers
$installedSomething = $false
foreach ($r in $missing) {
    if ($r.Fix.Count -eq 0) { continue }
    if (@($r.Fix | Where-Object { $_.Exe }).Count -eq 0) { continue }

    $blocks = @($r.Fix | Where-Object { $_.Admin })
    $runnable = @($r.Fix | Where-Object { -not $_.Admin -and $_.Exe })

    if (-not $Install) { continue }
    if ($runnable.Count -eq 0) { continue }

    foreach ($step in $runnable) {
        $run = $Yes
        if (-not $Yes) {
            $answer = Read-Host "$($r.Name) is missing. Install it with: $($step.Label)  [i]nstall / [s]kip / [q]uit"
            switch -Regex ($answer) {
                '^(q|quit)$' { Write-Host 'Stopped.'; exit 1 }
                '^(i|y|yes|install)$' { $run = $true }
                default { $run = $false }
            }
        }
        if ($run) {
            Write-Host "running: $($step.Exe) $($step.Args -join ' ')"
            try {
                & $step.Exe @($step.Args)
                if ($LASTEXITCODE -ne 0) { Write-Warning "$($step.Exe) exited $LASTEXITCODE" }
                else { $installedSomething = $true }
            } catch {
                Write-Warning "could not run $($step.Exe): $($_.Exception.Message)"
            }
        }
    }
}

# Re-probe after an install, so the summary is true rather than optimistic.
if ($installedSomething) {
    Write-Host ''
    Write-Host 're-checking after install (a new package may not be on PATH in this shell):'
    $results = foreach ($c in $checks) {
        $probe = & $c.Probe
        [pscustomobject]@{
            Name = $c.Name; Category = $c.Category; Why = $c.Why
            Ok = [bool]$probe.Ok
            Found = if ($probe.ContainsKey('Found')) { [string]$probe.Found } else { '' }
            Fix = @($c.Fix | Where-Object { $_ }); WhenMissing = $c.WhenMissing
        }
    }
    $results = @($results)
    $missing = @($results | Where-Object { -not $_.Ok })
}

# ---------------------------------------------------------------- report
if ($Json) {
    $payload = [pscustomobject]@{
        required_ok = (@($missing | Where-Object { $_.Category -in 'required', 'runtime' }).Count -eq 0)
        checks      = @($results | ForEach-Object {
            [pscustomobject]@{
                name = $_.Name; category = $_.Category; ok = $_.Ok; found = $_.Found
                why = $_.Why
                fix = @($_.Fix | ForEach-Object { $_.Label })
                reference = $_.WhenMissing
            }
        })
    }
    $payload | ConvertTo-Json -Depth 5
    if (-not $payload.required_ok) { exit 1 }
    exit 0
}

# Which triple these checks were computed for: `--target` on the command line is invisible here,
# so the assumption is printed instead of hidden.
$triple = if ($script:TargetTriple) { $script:TargetTriple } else { 'unknown (rustc not found)' }
$hostNote = if ($script:HostTriple -and $script:HostTriple -ne $script:TargetTriple) { " (host $($script:HostTriple))" } else { '' }
Write-Host "target: $triple$hostNote" -ForegroundColor DarkGray
if ($script:IsArm) {
    Write-Host 'ARM64: ring forces clang for this target, and MSVC needs its separate ARM64 toolset' -ForegroundColor DarkGray
}

$width = ($results | ForEach-Object { $_.Name.Length } | Measure-Object -Maximum).Maximum
foreach ($group in @(
        @{ Title = 'BUILD REQUIREMENTS'; Items = @($results | Where-Object { $_.Category -eq 'required' }) }
        @{ Title = 'RUNTIME'; Items = @($results | Where-Object { $_.Category -eq 'runtime' }) }
        @{ Title = 'OPTIONAL'; Items = @($results | Where-Object { $_.Category -eq 'optional' }) }
    )) {
    if ($group.Items.Count -eq 0) { continue }
    Write-Host ''
    Write-Host $group.Title -ForegroundColor Cyan
    foreach ($r in $group.Items) {
        $mark = if ($r.Ok) { '[ok]  ' } else { '[MISS]' }
        $colour = if ($r.Ok) { 'Green' } else { 'Red' }
        $found = if ($r.Ok -and $r.Found) { "  $($r.Found)" } else { '' }
        Write-Host ("  $mark $($r.Name.PadRight($width))$found") -ForegroundColor $colour
        if (-not $r.Ok -and $r.Found) { Write-Host ("         found: $($r.Found)") -ForegroundColor DarkGray }
        if (-not $r.Ok) {
            Write-Host ("         why: $($r.Why)") -ForegroundColor DarkGray
            foreach ($step in $r.Fix) {
                $suffix = if ($step.Admin) { '   (run in an elevated shell)' } else { '' }
                # the command is the actionable part: yellow, so a red row still ends in something
                # the reader can run rather than in more red
                Write-Host ("         fix: $($step.Label)$suffix") -ForegroundColor Yellow
            }
            if ($r.Fix.Count -eq 0 -and $r.WhenMissing) {
                Write-Host ("         see: $($r.WhenMissing)") -ForegroundColor DarkGray
            }
        }
    }
}

$requiredMissing = @($missing | Where-Object { $_.Category -in 'required', 'runtime' })
$optionalMissing = @($missing | Where-Object { $_.Category -eq 'optional' })
Write-Host ''
if ($requiredMissing.Count -eq 0) {
    Write-Host "ready to build: $(@($results | Where-Object { $_.Category -eq 'required' -and $_.Ok }).Count) required checks passed" -ForegroundColor Green
    if ($optionalMissing.Count -gt 0) {
        Write-Host "$($optionalMissing.Count) optional item(s) missing - none blocks the x64 build; see the fix lines above" -ForegroundColor DarkGray
    }
    Write-Host 'next: cargo build --release' -ForegroundColor DarkGray
    exit 0
}

Write-Host "$($requiredMissing.Count) required item(s) missing." -ForegroundColor Yellow
Write-Host 'run with -Install to be offered each command, or copy the fix lines above.' -ForegroundColor DarkGray
exit 1
