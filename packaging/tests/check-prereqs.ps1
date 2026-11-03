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

$expectedExit = if ($payload.required_ok) { 0 } else { 1 }
if ($exit -ne $expectedExit) { $failures += "exit $exit does not match required_ok=$($payload.required_ok)" }

if ($failures.Count -gt 0) {
    foreach ($f in $failures) { Write-Host "FAIL: $f" -ForegroundColor Red }
    exit 1
}

Write-Host "check-prereqs: JSON contract ok ($(@($payload.checks).Count) checks, required_ok=$($payload.required_ok), exit $exit)"
exit 0
