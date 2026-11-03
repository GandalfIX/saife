#Requires -Version 7.0
<#
.SYNOPSIS
    Smoke test for packaging/check-prereqs.ps1: the JSON contract and the exit code.
.DESCRIPTION
    Runs the checker and asserts what CI depends on - a `checks` array with every entry carrying a
    name, category and ok flag, and an exit code that agrees with `required_ok`. It does not assert
    that any particular tool is installed: the runner's own host is not the build host.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$checker = Join-Path $PSScriptRoot '..\check-prereqs.ps1'
$raw = & pwsh -NoProfile -File $checker -Json -SkipOptional 2>&1 | Out-String
$exit = $LASTEXITCODE

$payload = $raw | ConvertFrom-Json
$failures = @()

if (-not $payload.PSObject.Properties.Name.Contains('required_ok')) { $failures += 'no required_ok in the payload' }
if (-not $payload.checks -or @($payload.checks).Count -lt 5) { $failures += "expected at least 5 checks, got $(@($payload.checks).Count)" }

foreach ($c in @($payload.checks)) {
    if (-not $c.name) { $failures += 'a check has no name' }
    if (-not $c.category) { $failures += "$($c.name): no category" }
    if ($null -eq $c.ok) { $failures += "$($c.name): no ok flag" }
    if (-not $c.ok -and @($c.fix).Count -eq 0 -and -not $c.reference) {
        $failures += "$($c.name): missing, but neither a fix command nor a reference"
    }
}

# skipped items must not appear at all, or CI would report the container engine on every build host
if (@($payload.checks | Where-Object { $_.category -eq 'optional' }).Count -ne 0) {
    $failures += '-SkipOptional still reported optional checks'
}

# The ARM64 rule is the one that cost a build on another machine: ring forces clang for
# aarch64-pc-windows-msvc, so the checker must switch it on when the target is ARM.
$env:CARGO_BUILD_TARGET = 'aarch64-pc-windows-msvc'
$armRaw = & pwsh -NoProfile -File $checker -Json -SkipOptional 2>&1 | Out-String
Remove-Item Env:CARGO_BUILD_TARGET
$arm = $armRaw | ConvertFrom-Json
$clang = @($arm.checks | Where-Object { $_.name -match 'clang' })
if ($clang.Count -ne 1) {
    $failures += "ARM64 target did not add exactly one clang check (got $($clang.Count))"
} elseif ($clang[0].category -ne 'required') {
    $failures += "ARM64 clang check is '$($clang[0].category)', must be required"
} elseif ($clang[0].ok -and -not $clang[0].found) {
    $failures += 'ARM64 clang check says ok without saying what it found'
}
# A registered VS component is not a usable compiler: cc-rs runs the bare name from PATH. If clang
# is not resolvable on PATH here, the check must say so - this is the false positive that shipped.
$onPath = [bool](Get-Command clang -CommandType Application -ErrorAction SilentlyContinue)
if (-not $onPath -and $clang.Count -eq 1 -and $clang[0].ok) {
    $failures += 'clang is not on PATH but the check reported it ok'
}
if (@($arm.checks | Where-Object { $_.name -match 'ARM64 toolset' }).Count -ne 1) {
    $failures += 'ARM64 target did not add the ARM64 toolset check'
}

$expectedExit = if ($payload.required_ok) { 0 } else { 1 }
if ($exit -ne $expectedExit) { $failures += "exit $exit does not match required_ok=$($payload.required_ok)" }

if ($failures.Count -gt 0) {
    foreach ($f in $failures) { Write-Host "FAIL: $f" -ForegroundColor Red }
    exit 1
}

Write-Host "check-prereqs: JSON contract ok ($(@($payload.checks).Count) checks, required_ok=$($payload.required_ok), exit $exit)"
exit 0
