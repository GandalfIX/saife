# One-time migration: sandbox -> SAIFE
#
#   pwsh -File packaging\migrate-to-saife.ps1 -WhatIf     # show what would move
#   pwsh -File packaging\migrate-to-saife.ps1            # do it
#
# This is a ONE-TIME, THIS-MACHINE operation (the product was never installed
# elsewhere). It moves, it does not copy: the DPAPI-encrypted audit signing key
# only stays valid because it moves within the same user profile.
#
#   %USERPROFILE%\.sandbox      -> %USERPROFILE%\.saife      (profiles, plugins, learned)
#   %LOCALAPPDATA%\sandbox      -> %LOCALAPPDATA%\saife      (audit chain, signing key, logs)
#
# Nothing is deleted. If a destination already exists the script refuses, because
# a half-merged state is worse than either name.

param(
    [switch]$WhatIf
)

$ErrorActionPreference = 'Stop'

$moves = @(
    @{ Name = 'user state'; From = (Join-Path $env:USERPROFILE '.sandbox'); To = (Join-Path $env:USERPROFILE '.saife') },
    @{ Name = 'machine state'; From = (Join-Path $env:LOCALAPPDATA 'sandbox'); To = (Join-Path $env:LOCALAPPDATA 'saife') }
)

$plan = @()
foreach ($m in $moves) {
    $from = $m.From
    $to = $m.To
    if (-not (Test-Path $from)) {
        Write-Host ("skip  {0}: {1} does not exist" -f $m.Name, $from)
        continue
    }
    if (Test-Path $to) {
        throw ("refusing: destination already exists ({0}). Inspect both trees and merge by hand." -f $to)
    }
    $files = (Get-ChildItem $from -Recurse -File -ErrorAction SilentlyContinue | Measure-Object).Count
    $bytes = (Get-ChildItem $from -Recurse -File -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum
    $plan += [pscustomobject]@{ Name = $m.Name; From = $from; To = $to; Files = $files; MB = [math]::Round($bytes / 1MB, 1) }
}

if ($plan.Count -eq 0) {
    Write-Host 'nothing to migrate'
    return
}

$plan | Format-Table Name, Files, MB, From, To -AutoSize | Out-String | Write-Host

if ($WhatIf) {
    Write-Host 'WhatIf: no change made.'
    return
}

foreach ($step in $plan) {
    Move-Item -LiteralPath $step.From -Destination $step.To
    Write-Host ("moved {0}: {1} -> {2}" -f $step.Name, $step.From, $step.To)
}

# Post-conditions worth asserting rather than assuming: the things a user would
# notice only when they are missing.
Write-Host ''
$checks = @(
    @{ Label = 'profiles'; Path = (Join-Path $env:USERPROFILE '.saife\profiles'); Kind = 'dir' },
    @{ Label = 'plugins';  Path = (Join-Path $env:USERPROFILE '.saife\plugins');  Kind = 'dir' },
    @{ Label = 'audit logs'; Path = (Join-Path $env:LOCALAPPDATA 'saife\audit');  Kind = 'dir' },
    @{ Label = 'dacl journals'; Path = (Join-Path $env:LOCALAPPDATA 'saife\dacl-restore'); Kind = 'dir' },
    @{ Label = 'signing key'; Path = (Join-Path $env:LOCALAPPDATA 'saife\signing\ed25519-key'); Kind = 'file' }
)
foreach ($c in $checks) {
    if (Test-Path $c.Path) {
        if ($c.Kind -eq 'dir') {
            $n = (Get-ChildItem $c.Path -File -ErrorAction SilentlyContinue | Measure-Object).Count
            Write-Host ("ok    {0,-12} {1} ({2} files)" -f $c.Label, $c.Path, $n)
        } else {
            Write-Host ("ok    {0,-12} {1}" -f $c.Label, $c.Path)
        }
    } else {
        Write-Host ("--    {0,-12} absent at {1} (fine if it never existed)" -f $c.Label, $c.Path)
    }
}

Write-Host ''
Write-Host 'next:'
Write-Host '  .\saife.exe setup --check-only          # the signing key must still be reported present'
Write-Host '  .\saife.exe audit verify <sid>          # any session id from the moved audit dir verifies as before'
Write-Host '  .\saife.exe profile list'
