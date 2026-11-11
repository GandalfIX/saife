#Requires -Version 7.0
<#
.SYNOPSIS
    Smoke test for packaging/check-devtools.ps1: the JSON contract and the exit code.
.DESCRIPTION
    Runs the checker and asserts what CI depends on - a `checks` array with every entry carrying a
    name, category and ok flag, an exit code that agrees with `required_ok`, and the required tool
    rows the gates rely on present regardless of whether they happen to be installed here.
    It does not assert that any particular tool is installed.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$checker = Join-Path $PSScriptRoot '..\check-devtools.ps1'
$raw = & pwsh -NoProfile -File $checker -Json -SkipOptional 2>&1 | Out-String
$exit = $LASTEXITCODE

$payload = $raw | ConvertFrom-Json
$failures = @()

if (-not $payload.PSObject.Properties.Name.Contains('required_ok')) { $failures += 'no required_ok in the payload' }
if (-not $payload.checks -or @($payload.checks).Count -lt 3) { $failures += "expected at least 3 checks, got $(@($payload.checks).Count)" }

foreach ($c in @($payload.checks)) {
    if (-not $c.name) { $failures += 'a check has no name' }
    if (-not $c.category) { $failures += "$($c.name): no category" }
    if ($null -eq $c.ok) { $failures += "$($c.name): no ok flag" }
    if (-not $c.ok -and @($c.fix).Count -eq 0 -and -not $c.reference) {
        $failures += "$($c.name): missing, but neither a fix command nor a reference"
    }
}

# skipped items must not appear at all, or CI would report the optional tools on every build host
if (@($payload.checks | Where-Object { $_.category -eq 'optional' }).Count -ne 0) {
    $failures += '-SkipOptional still reported optional checks'
}

# The required set is the contract: these three rows must exist and be required, because the
# quality gates and docs/DEVELOPERS.md name them. A missing row here means the gate silently no
# longer checks what the docs say it checks.
$requiredNames = @('cargo-deny', 'cargo-mutants', 'cargo-shear')
foreach ($n in $requiredNames) {
    $row = @($payload.checks | Where-Object { $_.name -eq $n })
    if ($row.Count -ne 1) {
        $failures += "required tool row '$n' missing (got $($row.Count))"
    } elseif ($row[0].category -ne 'required') {
        $failures += "$n is '$($row[0].category)', must be required"
    }
}

# Without -SkipOptional, the optional rows must appear and be optional. This is the regression that
# keeps a tool from being silently promoted to required (which would block every clean clone).
$fullRaw = & pwsh -NoProfile -File $checker -Json 2>&1 | Out-String
$full = $fullRaw | ConvertFrom-Json
foreach ($n in @('cargo-geiger', 'cargo-fuzz (needs nightly)', 'Miri (nightly)')) {
    $row = @($full.checks | Where-Object { $_.name -eq $n })
    if ($row.Count -ne 1) {
        $failures += "optional tool row '$n' missing without -SkipOptional (got $($row.Count))"
    } elseif ($row[0].category -ne 'optional') {
        $failures += "$n is '$($row[0].category)', must be optional"
    }
}

$expectedExit = if ($payload.required_ok) { 0 } else { 1 }
if ($exit -ne $expectedExit) { $failures += "exit $exit does not match required_ok=$($payload.required_ok)" }

if ($failures.Count -gt 0) {
    foreach ($f in $failures) { Write-Host "FAIL: $f" -ForegroundColor Red }
    exit 1
}

Write-Host "check-devtools: JSON contract ok ($(@($payload.checks).Count) checks, required_ok=$($payload.required_ok), exit $exit)" -ForegroundColor Green
exit 0
