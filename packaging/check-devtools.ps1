#Requires -Version 7.0
<#
.SYNOPSIS
    Checks that every local analysis tool the repo's quality gates rely on is installed.

.DESCRIPTION
    The build prerequisites live in packaging/check-prereqs.ps1. This script owns the second
    layer: the offline, free, commercially usable analysis tools (supply-chain audit, mutation
    testing, unused-dependency detection) that a contributor is expected to run BEFORE opening a
    pull request. Every tool installs with `cargo install` into %USERPROFILE%\.cargo\bin, so no
    step here ever needs an administrator and nothing is ever run elevated.

    The default report is the check. With -Install it offers each missing tool; -Yes installs
    without asking. -Json emits the same contract as check-prereqs.ps1 (a `checks` array where
    every entry carries name, category and ok, plus `required_ok`, and the exit code mirrors it).

    Exit codes: 0 everything required is present, 1 something required is missing, 2 usage error.

.EXAMPLE
    pwsh -File packaging\check-devtools.ps1

.EXAMPLE
    pwsh -File packaging\check-devtools.ps1 -Install -Yes

.EXAMPLE
    pwsh -File packaging\check-devtools.ps1 -Json -SkipOptional
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

function Get-CargoBin {
    param([string]$Exe)
    $cmd = Get-Command $Exe -CommandType Application -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    # A cargo install that ran a moment ago is invisible to this shell's PATH. Resolve the known
    # install location directly so the report can say "installed, open a new shell" instead of
    # contradicting the install it just performed.
    $fallback = Join-Path $env:USERPROFILE ".cargo\bin\$Exe.exe"
    if (Test-Path -LiteralPath $fallback) { return $fallback }
    return $null
}

function Get-ToolVersion {
    param([string]$Exe)
    $path = Get-CargoBin $Exe
    if (-not $path) { return $null }
    try {
        $out = (& $path --version 2>&1 | Out-String).Trim()
        # Some cargo subcommand binaries do not register a version flag on the
        # root command (cargo-mutants 27.x rejects --version/-V outright). The
        # version is still reachable the way the tool is actually invoked -
        # through cargo itself. Use the cargo.exe next to the tool: a stale
        # shell PATH must not turn "installed" back into "missing".
        if ($out -match 'unexpected argument|error:') {
            $sub = $Exe -replace '^cargo-', ''
            $cargo = Join-Path (Split-Path $path) 'cargo.exe'
            $out = (& $cargo $sub --version 2>&1 | Out-String).Trim()
        }
        if (-not $out) { return $null }
        return ($out -split "`r?`n" | Where-Object { $_.Trim() } | Select-Object -First 1).Trim()
    } catch {
        return $null
    }
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

function Test-NightlyMiri {
    # Miri cannot execute the Win32 FFI paths, so it is a nightly helper for the pure-Rust units
    # only - presence of the nightly toolchain AND the component, probed through cargo itself.
    if (-not (Test-Command 'cargo')) { return $null }
    $toolchains = & rustup toolchain list 2>$null
    if (-not ($toolchains | Where-Object { $_ -match '^nightly' })) { return $null }
    $v = Get-FirstLine 'cargo' @('+nightly', 'miri', '--version')
    if ($v -match 'miri') { return $v }
    return $null
}

function Test-Command {
    param([string]$Name)
    $null -ne (Get-Command $Name -ErrorAction SilentlyContinue)
}

# Version pins: install steps use an exact --version so a new developer gets today's known-good
# tool set, not whatever crates.io serves next week. Bump a pin deliberately and re-run the gate.
$tools = @(
    @{
        Name     = 'cargo-deny'
        Category = 'required'
        Why      = 'the supply-chain gate: RustSec advisories, license policy, duplicate and banned crates (deny.toml). Run `cargo deny check` before every PR'
        Probe    = {
            $v = Get-ToolVersion 'cargo-deny'
            if (-not $v) { return @{ Ok = $false } }
            return @{ Ok = $true; Found = $v }
        }
        Fix      = @(@{ Exe = 'cargo'; Args = @('install', 'cargo-deny', '--locked', '--version', '0.20.2'); Admin = $false
                        Label = 'cargo install cargo-deny --locked --version 0.20.2' })
        WhenMissing = 'https://github.com/EmbarkStudios/cargo-deny'
    }
    @{
        Name     = 'cargo-mutants'
        Category = 'required'
        Why      = 'mutation testing: proves the tests of the security-critical units (signing, security_groups, profile) actually catch changed behaviour'
        Probe    = {
            $v = Get-ToolVersion 'cargo-mutants'
            if (-not $v) { return @{ Ok = $false } }
            return @{ Ok = $true; Found = $v }
        }
        Fix      = @(@{ Exe = 'cargo'; Args = @('install', 'cargo-mutants', '--locked', '--version', '27.1.0'); Admin = $false
                        Label = 'cargo install cargo-mutants --locked --version 27.1.0' })
        WhenMissing = 'https://sourceforge.net/p/cargo-mutants/'
    }
    @{
        Name     = 'cargo-shear'
        Category = 'required'
        Why      = 'finds dependencies Cargo.toml declares but no source uses; keeps the dependency surface small'
        Probe    = {
            $v = Get-ToolVersion 'cargo-shear'
            if (-not $v) { return @{ Ok = $false } }
            return @{ Ok = $true; Found = $v }
        }
        Fix      = @(@{ Exe = 'cargo'; Args = @('install', 'cargo-shear', '--locked', '--version', '1.14.0'); Admin = $false
                        Label = 'cargo install cargo-shear --locked --version 1.14.0' })
        WhenMissing = 'https://github.com/Boshen/cargo-shear'
    }
    @{
        Name     = 'cargo-geiger'
        Category = 'optional'
        Why      = 'counts `unsafe` usage per crate across the dependency tree; a heuristic for the unsafe surface, not a verdict (your own crate is unsafe-heavy by design: Win32 FFI)'
        Probe    = {
            $v = Get-ToolVersion 'cargo-geiger'
            if (-not $v) { return @{ Ok = $false } }
            return @{ Ok = $true; Found = $v }
        }
        Fix      = @(@{ Exe = 'cargo'; Args = @('install', 'cargo-geiger', '--locked', '--version', '0.14.0'); Admin = $false
                        Label = 'cargo install cargo-geiger --locked --version 0.14.0' })
        WhenMissing = 'https://github.com/geiger-rs/cargo-geiger'
    }
    @{
        Name     = 'cargo-fuzz (needs nightly)'
        Category = 'optional'
        Why      = 'coverage-guided fuzzing of the parsers (profile JSON, manifest). Needs the nightly toolchain; run locally, not as a gate'
        Probe    = {
            $v = Get-ToolVersion 'cargo-fuzz'
            if (-not $v) { return @{ Ok = $false } }
            return @{ Ok = $true; Found = $v }
        }
        Fix      = @(
            @{ Exe = 'rustup'; Args = @('toolchain', 'install', 'nightly', '--profile', 'minimal'); Admin = $false
               Label = 'rustup toolchain install nightly --profile minimal' }
            @{ Exe = 'cargo'; Args = @('install', 'cargo-fuzz', '--locked', '--version', '0.13.2'); Admin = $false
               Label = 'cargo install cargo-fuzz --locked --version 0.13.2' }
        )
        WhenMissing = 'https://github.com/rust-fuzz/cargo-fuzz'
    }
    @{
        Name     = 'Miri (nightly)'
        Category = 'optional'
        Why      = 'UB detection for the PURE-RUST units (signing, base64, profile parsing). Cannot execute the Win32 FFI paths - failures there are out of its reach, passes there are still valuable'
        Probe    = {
            $v = Test-NightlyMiri
            if (-not $v) { return @{ Ok = $false } }
            return @{ Ok = $true; Found = $v }
        }
        Fix      = @(
            @{ Exe = 'rustup'; Args = @('toolchain', 'install', 'nightly', '--profile', 'minimal'); Admin = $false
               Label = 'rustup toolchain install nightly --profile minimal' }
            @{ Exe = 'rustup'; Args = @('component', 'add', 'miri', '--toolchain', 'nightly'); Admin = $false
               Label = 'rustup component add miri --toolchain nightly' }
        )
        WhenMissing = 'https://github.com/rust-lang/miri'
    }
)

if ($SkipOptional) {
    $tools = $tools | Where-Object { $_.Category -ne 'optional' }
}

$results = @()
foreach ($t in $tools) {
    $probe = & $t.Probe
    $results += [pscustomobject]@{
        Name = $t.Name
        Category = $t.Category
        Why = $t.Why
        Ok = [bool]$probe.Ok
        Found = if ($probe.ContainsKey('Found')) { [string]$probe.Found } else { '' }
        Fix = @($t.Fix | Where-Object { $_ })
        WhenMissing = $t.WhenMissing
    }
}
$results = @($results)
$missing = @($results | Where-Object { -not $_.Ok })

# ---------------------------------------------------------------- install offers
# cargo installs land in %USERPROFILE%\.cargo\bin: user scope, never elevated, nothing to print
# and skip. If that directory is not on this shell's PATH, the re-probe resolves it directly and
# the summary says so instead of reporting the tool missing again.
$installedSomething = $false
foreach ($r in $missing) {
    if (-not $Install) { continue }
    foreach ($step in $r.Fix) {
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

if ($installedSomething) {
    Write-Host ''
    Write-Host 're-checking after install:'
    $results = @()
    foreach ($t in $tools) {
        $probe = & $t.Probe
        $results += [pscustomobject]@{
            Name = $t.Name; Category = $t.Category; Why = $t.Why
            Ok = [bool]$probe.Ok
            Found = if ($probe.ContainsKey('Found')) { [string]$probe.Found } else { '' }
            Fix = @($t.Fix | Where-Object { $_ }); WhenMissing = $t.WhenMissing
        }
    }
    $results = @($results)
    $missing = @($results | Where-Object { -not $_.Ok })
}

# ---------------------------------------------------------------- report
if ($Json) {
    $payload = [pscustomobject]@{
        required_ok = (@($missing | Where-Object { $_.Category -eq 'required' }).Count -eq 0)
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

Write-Host 'developer analysis tools (offline, free, permissive licenses):' -ForegroundColor DarkGray
$width = ($results | ForEach-Object { $_.Name.Length } | Measure-Object -Maximum).Maximum
foreach ($group in @(
        @{ Title = 'ANALYSIS TOOLS'; Items = @($results | Where-Object { $_.Category -eq 'required' }) }
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
                Write-Host ("         fix: $($step.Label)") -ForegroundColor Yellow
            }
            if ($r.Fix.Count -eq 0 -and $r.WhenMissing) {
                Write-Host ("         see: $($r.WhenMissing)") -ForegroundColor DarkGray
            }
        }
    }
}

$requiredMissing = @($missing | Where-Object { $_.Category -eq 'required' })
$optionalMissing = @($missing | Where-Object { $_.Category -eq 'optional' })
Write-Host ''
if ($requiredMissing.Count -eq 0) {
    Write-Host "analysis tools ready: $(@($results | Where-Object { $_.Category -eq 'required' -and $_.Ok }).Count) required tools present" -ForegroundColor Green
    if ($optionalMissing.Count -gt 0) {
        Write-Host "$($optionalMissing.Count) optional tool(s) missing - none blocks a PR; see the fix lines above" -ForegroundColor DarkGray
    }
    exit 0
}
Write-Host "$($requiredMissing.Count) required tool(s) missing." -ForegroundColor Yellow
Write-Host 'run with -Install to be offered each command, or copy the fix lines above.' -ForegroundColor DarkGray
exit 1
