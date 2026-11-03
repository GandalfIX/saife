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
        Name     = 'MSVC C++ build tools (link.exe)'
        Category = 'required'
        Why      = 'the linker Rust does not ship; its absence looks like a Rust error'
        Probe    = {
            $found = Get-MsvcInstall
            if ($found) { return @{ Ok = $true; Found = $found } }
            return @{ Ok = $false }
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

    $blocks = @($r.Fix | Where-Object { $_.Admin })
    $runnable = @($r.Fix | Where-Object { -not $_.Admin })

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
        $colour = if ($r.Ok) { 'DarkGray' } else { 'Yellow' }
        $found = if ($r.Found) { "  $($r.Found)" } else { '' }
        Write-Host ("  $mark $($r.Name.PadRight($width))$found") -ForegroundColor $colour
        if (-not $r.Ok) {
            Write-Host ("         why: $($r.Why)") -ForegroundColor DarkGray
            foreach ($step in $r.Fix) {
                $suffix = if ($step.Admin) { '   (run in an elevated shell)' } else { '' }
                Write-Host ("         fix: $($step.Label)$suffix") -ForegroundColor DarkGray
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
        Write-Host "$($optionalMissing.Count) optional item(s) missing - the runner and PR flow need them, the build does not" -ForegroundColor DarkGray
    }
    Write-Host 'next: cargo build --release' -ForegroundColor DarkGray
    exit 0
}

Write-Host "$($requiredMissing.Count) required item(s) missing." -ForegroundColor Yellow
Write-Host 'run with -Install to be offered each command, or copy the fix lines above.' -ForegroundColor DarkGray
exit 1
