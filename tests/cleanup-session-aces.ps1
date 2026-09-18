# Rollback / manual-recovery script: removes session AppContainer ACEs
# (any S-1-15-2-* EXCEPT the intentional persistent S-1-15-2-2 drive-root
# grant) from the harness temp root, $env:TEMP, and AppData\Local ancestors.
# Run after a killed test run:
#   pwsh -ExecutionPolicy Bypass -File tests\cleanup-session-aces.ps1
# Review before deleting; prints everything it removes.
param([string[]]$Paths = @($env:TEMP, "$env:LOCALAPPDATA"))

$removed = 0
foreach ($p in $Paths | Where-Object { Test-Path $_ }) {
    $acl = Get-Acl -LiteralPath $p
    $dirty = $false
    foreach ($ace in @($acl.Access)) {
        if ($ace.IdentityReference -match '^S-1-15-2-' -and
            $ace.IdentityReference -ne 'S-1-15-2-2' -and
            -not $ace.IsInherited) {
            Write-Host "removing $($ace.IdentityReference) from $p"
            $acl.RemoveAccessRuleSpecific($ace) | Out-Null
            $dirty = $true; $removed++
        }
    }
    if ($dirty) { Set-Acl -LiteralPath $p $acl }
}
Write-Host "$removed session ACE(s) removed."
