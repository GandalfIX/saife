#Requires -Version 5.1
<#
.SYNOPSIS
  Remove stale AppContainer (S-1-15-2-*) ACEs left by previous sandbox runs.
.DESCRIPTION
  The sandbox grants the per-session AppContainer SID access on the CWD and
  its ancestor directories. These ACEs persist after the sandbox exits and
  accumulate across runs, eventually causing SetNamedSecurityInfoW to hang
  (observed at ~40+ ACEs on AppData\Local). This script removes them from the
  user profile root, AppData, AppData\Local, and TEMP.

  Safe to run at any time. Idempotent. Does NOT touch non-AppContainer ACEs.
.PARAMETER Paths
  Directories to clean. Defaults to the sandbox-relevant ancestor chain.
.EXAMPLE
  .\tests\cleanup-acls.ps1
.EXAMPLE
  .\tests\cleanup-acls.ps1 -Paths "C:\Users\me\AppData\Local"
#>
[CmdletBinding()]
param(
    [string[]]$Paths = @(
        $env:USERPROFILE,
        (Join-Path $env:USERPROFILE "AppData"),
        (Join-Path $env:USERPROFILE "AppData\Local"),
        $env:TEMP
    )
)

$ErrorActionPreference = 'Stop'

$totalRemoved = 0
foreach ($path in $Paths) {
    if (-not (Test-Path -LiteralPath $path)) { continue }
    $acl = Get-Acl -LiteralPath $path
    $stale = @($acl.Access | Where-Object { $_.IdentityReference.Value -match '^S-1-15-2-\d+-\d+-\d+-\d+-\d+-\d+-\d+' })
    if ($stale.Count -eq 0) {
        Write-Host "[clean] $path : 0 AppContainer ACEs (already clean)"
        continue
    }
    Write-Host "[clean] $path : removing $($stale.Count) AppContainer ACEs"
    foreach ($ace in $stale) {
        $acl.RemoveAccessRuleSpecific($ace) | Out-Null
    }
    Set-Acl -LiteralPath $path -AclObject $acl
    $totalRemoved += $stale.Count
}

Write-Host "[clean] removed $totalRemoved AppContainer ACEs total"

# Verify
foreach ($path in $Paths) {
    if (-not (Test-Path -LiteralPath $path)) { continue }
    $remaining = (& icacls $path 2>&1 | Select-String 'S-1-15-2-\d+-\d+-\d+-\d+-\d+-\d+-\d+').Count
    Write-Host "[clean] $path : $remaining remaining"
}
