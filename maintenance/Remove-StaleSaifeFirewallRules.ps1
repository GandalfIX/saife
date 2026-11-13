#Requires -Version 7.0
<#
    Removes Windows Firewall rules that point at a saife test binary which no
    longer exists.

    Why they exist: until the fixtures moved to loopback, the forward-path tests
    served their origin on the host's own LAN address, and Windows Firewall asks
    once per executable FILE - so every rebuild and every cargo-mutants copy of
    the tree left a new rule behind. The cause is fixed; this script cleans up
    hosts that already have them.

    Only rules whose Program path contains "saife" AND whose file is missing are
    touched. Live binaries keep their rules. Needs an elevated shell; the script
    refuses to run without it rather than half-working.

    Dry run first:  pwsh -File Remove-StaleSaifeFirewallRules.ps1 -WhatIf
    Then:           pwsh -File Remove-StaleSaifeFirewallRules.ps1

    INSTANCE ID: ONE. Run it as an integrated elevated run, not a no-console
    child: MTA COM calls into the firewall policy store fail from a spawned
    worker, the removal then throws NotSpecified.
#>
[CmdletBinding(SupportsShouldProcess)]
param()

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($id)
$elevated = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
# -WhatIf only READS the policy store, which a standard user may do; the
# removal itself needs admin. Keeping the dry run usable unelevated is what lets
# the operator see the exact list before opening an elevated window.
if (-not $elevated -and -not $WhatIfPreference) {
    throw 'This script needs an elevated PowerShell window (firewall rules are admin-only).'
}

$stale = @(
    Get-NetFirewallApplicationFilter |
        Where-Object { $_.Program -like '*saife*' -and -not (Test-Path -LiteralPath $_.Program) }
)

if ($stale.Count -eq 0) {
    Write-Host 'nothing to do: no firewall rule points at a missing saife binary'
    exit 0
}

$orphanPaths = $stale | ForEach-Object { $_.Program } | Sort-Object -Unique
Write-Host ("{0} stale rule(s) across {1} missing binary path(s)" -f $stale.Count, $orphanPaths.Count)

if ($WhatIfPreference) {
    # A dry run only reports. Without this early return it falls through to the
    # "still stale" verification below and reports success as failure.
    $orphanPaths | ForEach-Object { Write-Host ('  would remove rules for: ' + $_) }
    exit 0
}

$removed = 0
foreach ($filter in $stale) {
    $rule = $filter | Get-NetFirewallRule
    Remove-NetFirewallRule -Name $rule.Name -ErrorAction Stop
    $removed++
}

$left = @(
    Get-NetFirewallApplicationFilter |
        Where-Object { $_.Program -like '*saife*' -and -not (Test-Path -LiteralPath $_.Program) }
)
Write-Host ("removed {0} rule(s); {1} stale rule(s) left" -f $removed, $left.Count)
if ($left.Count -ne 0) {
    $left | ForEach-Object { Write-Host ('  still stale: ' + $_.Program) }
    exit 1
}
exit 0
