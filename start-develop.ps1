#Requires -Version 7.0
<#
.SYNOPSIS
    The one command a new developer runs after cloning the repo.

.DESCRIPTION
    Two layers, in order:

      1. packaging/check-prereqs.ps1 - everything needed to BUILD (Rust toolchain, MSVC,
         Windows SDK, pwsh, git). It offers to install anything missing; steps that need an
         administrator are printed, never run.
      2. packaging/check-devtools.ps1 - the local analysis tools the quality gates rely on
         (cargo-deny, cargo-mutants, cargo-shear). All of them install with `cargo install`
         into %USERPROFILE%\.cargo\bin: user scope, free, commercially usable.

    Exit codes: 0 both layers green, 1 something required is missing, 2 usage error.

.PARAMETER Install
    Offer to install every missing item (both layers).

.PARAMETER Yes
    With -Install, install everything without asking.

.PARAMETER SkipOptional
    Skip optional checks (container engine, gh, cargo-geiger, cargo-fuzz, Miri).

.PARAMETER Json
    One merged machine-readable payload for CI. Implies no prompting.

.PARAMETER SkipBuildPrereqs
    Run the analysis-tool layer only. For a machine that already builds the repo.

.EXAMPLE
    pwsh -File start-develop.ps1

.EXAMPLE
    pwsh -File start-develop.ps1 -Install -Yes

.EXAMPLE
    pwsh -File start-develop.ps1 -Json -SkipBuildPrereqs
#>
[CmdletBinding()]
param(
    [switch]$Install,
    [switch]$Yes,
    [switch]$SkipOptional,
    [switch]$Json,
    [switch]$SkipBuildPrereqs
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if ($Json) { $Install = $false }

$root = $PSScriptRoot
$prereqs = Join-Path $root 'packaging\check-prereqs.ps1'
$devtools = Join-Path $root 'packaging\check-devtools.ps1'

function Invoke-Checker {
    param(
        [string]$Path,
        [bool]$EmitJson,
        [bool]$PassInstall,
        [bool]$PassYes,
        [bool]$PassSkipOptional,
        # Capture mode is for -Json only, where the child's output is parsed into
        # the merged payload. In console mode the child's report MUST reach the
        # terminal: it holds the [MISS] rows and the fix lines the summary's
        # "see the fix lines above" points at. Capturing it there is how the
        # first version lost them (found on a second machine: a wall of
        # "[MISS] ... fix: cargo install ..." was promised and never printed).
        [switch]$Capture
    )
    $args = @('-NoProfile', '-File', $Path)
    if ($EmitJson) { $args += '-Json' }
    if ($PassInstall) { $args += '-Install' }
    if ($PassYes) { $args += '-Yes' }
    if ($PassSkipOptional) { $args += '-SkipOptional' }
    if ($Capture) {
        $out = & pwsh @args 2>&1 | Out-String
        return @{ Text = $out; Exit = $LASTEXITCODE }
    }
    & pwsh @args 2>&1 | Write-Host
    return @{ Exit = $LASTEXITCODE }
}

# ---------------------------------------------------------------- layer 1: build prerequisites
$buildOk = $true
$buildPayload = $null
if (-not $SkipBuildPrereqs) {
    if (Test-Path -LiteralPath $prereqs) {
        if ($Json) {
            $r = Invoke-Checker $prereqs $true $false $false $SkipOptional -Capture
            try {
                $buildPayload = $r.Text | ConvertFrom-Json
                $buildOk = [bool]$buildPayload.required_ok
            } catch {
                Write-Warning "check-prereqs.ps1 -Json did not return a payload (exit $($r.Exit))"
                Write-Host $r.Text
                $buildOk = ($r.Exit -eq 0)
            }
        } else {
            $r = Invoke-Checker $prereqs $false $Install $Yes $SkipOptional
            $buildOk = ($r.Exit -eq 0)
        }
    } else {
        Write-Warning "packaging\check-prereqs.ps1 not found next to this script; skipping the build layer"
    }
}

# ---------------------------------------------------------------- layer 2: analysis tools
if ($Json) {
    $r = Invoke-Checker $devtools $true $false $false $SkipOptional -Capture
    $toolsPayload = $null
    try {
        $toolsPayload = $r.Text | ConvertFrom-Json
    } catch {
        Write-Warning "check-devtools.ps1 -Json did not return a payload (exit $($r.Exit))"
        Write-Host $r.Text
        exit 1
    }
    $toolsOk = [bool]$toolsPayload.required_ok
    $checks = @()
    if ($buildPayload) {
        $checks += @($buildPayload.checks | ForEach-Object { $_.PSObject.Copy() })
    }
    $checks += @($toolsPayload.checks)
    [pscustomobject]@{
        required_ok = ($buildOk -and $toolsOk)
        checks = @($checks)
    } | ConvertTo-Json -Depth 5
    if (-not ($buildOk -and $toolsOk)) { exit 1 }
    exit 0
}

$r = Invoke-Checker $devtools $false $Install $Yes $SkipOptional
$toolsOk = ($r.Exit -eq 0)

# ---------------------------------------------------------------- summary
Write-Host ''
Write-Host '=== setup summary ===' -ForegroundColor Cyan
Write-Host ("build prerequisites : " + $(if ($SkipBuildPrereqs) { 'skipped' } elseif ($buildOk) { 'ready' } else { 'MISSING - see the fix lines above' }))
Write-Host ("analysis tools      : " + $(if ($toolsOk) { 'ready' } else { 'MISSING - see the fix lines above' }))
Write-Host ''
if ($buildOk -and $toolsOk) {
    Write-Host 'next:' -ForegroundColor Green
    Write-Host '  cargo build --release --bin saife --bin saife-launch   # or just: cargo build' -ForegroundColor DarkGray
    Write-Host '  cargo test --bin saife                                 # unit tests' -ForegroundColor DarkGray
    Write-Host '  cargo deny check                                       # supply-chain gate (docs/DEVELOPERS.md)' -ForegroundColor DarkGray
    exit 0
}
Write-Host 'run again with -Install to be offered every missing item:' -ForegroundColor Yellow
Write-Host '  pwsh -File start-develop.ps1 -Install' -ForegroundColor Yellow
exit 1
