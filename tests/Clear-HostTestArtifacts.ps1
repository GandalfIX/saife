# Post-test cleanup gate for HOST-side runs.
#
# Rule (user directive, 2026-10-21): after every block of testing, whatever ran
# on the HOST must leave no permissions, ACEs, processes or state behind. VM
# runs are exempt by construction - they touch a disposable differencing disk,
# not the host - but a host-side run of the AppContainer path writes real ACEs
# (per-session S-1-15-2-* SIDs) on the profile chain and journals them under
# %LOCALAPPDATA%\sandbox\dacl-restore.
#
# The MXC live tests were checked: src/net/mxc.rs and src/net/proxy.rs contain
# no SetSecurityInfo/icacls call, so that path writes no ACEs. It does leave
# %TEMP%\sandbox-mxc-* directories, which this script removes.
#
#   pwsh -File tests\Clear-HostTestArtifacts.ps1              # clean, keep audit
#   pwsh -File tests\Clear-HostTestArtifacts.ps1 -RemoveAudit  # also drop audit logs
#
# Exit codes: 0 = host clean, 1 = something could not be cleaned (see report).
[CmdletBinding()]
param(
    # Audit logs are evidence. Deleting them is opt-in and never implied.
    [switch]$RemoveAudit,
    # Do not kill processes; report them instead (useful mid-investigation).
    [switch]$NoKill
)

$ErrorActionPreference = 'Stop'
$problems = New-Object System.Collections.Generic.List[string]
$needsElevation = New-Object System.Collections.Generic.List[string]

function Write-Step([string]$text) { Write-Host "== $text" }
function Add-Problem([string]$text) { $script:problems.Add($text) | Out-Null; Write-Host "  PROBLEM: $text" }
function Test-SessionAce([string]$path) {
    if (-not (Test-Path -LiteralPath $path)) { return @() }
    return @((Get-Acl -LiteralPath $path -ErrorAction SilentlyContinue).Access | Where-Object {
            $_.IdentityReference -match '^S-1-15-2-' -and
            $_.IdentityReference -ne 'S-1-15-2-2' -and
            -not $_.IsInherited
        })
}
function Remove-SessionAces([string]$path) {
    # Returns 'clean' | 'removed' | 'denied' | 'missing'
    if (-not (Test-Path -LiteralPath $path)) { return 'missing' }
    if ((Test-SessionAce $path).Count -eq 0) { return 'clean' }
    try {
        $acl = Get-Acl -LiteralPath $path
        $changed = $false
        foreach ($ace in @($acl.Access)) {
            if ($ace.IdentityReference -match '^S-1-15-2-' -and
                $ace.IdentityReference -ne 'S-1-15-2-2' -and
                -not $ace.IsInherited) {
                $acl.RemoveAccessRuleSpecific($ace) | Out-Null
                $changed = $true
            }
        }
        if ($changed) { Set-Acl -LiteralPath $path $acl }
        if ((Test-SessionAce $path).Count -eq 0) { return 'removed' }
        return 'denied'
    }
    catch { return 'denied' }
}

# --- 1. stray processes -----------------------------------------------------
Write-Step 'stray sandbox / mxc-launch processes'
$stray = @(Get-Process sandbox, mxc-launch -ErrorAction SilentlyContinue)
if ($stray.Count -eq 0) {
    Write-Host '  none'
}
elseif ($NoKill) {
    Write-Host ("  {0} running (not killed: -NoKill): {1}" -f $stray.Count, (($stray | ForEach-Object { "$($_.ProcessName)#$($_.Id)" }) -join ', '))
    Add-Problem "$($stray.Count) sandbox process(es) still running"
}
else {
    foreach ($p in $stray) {
        try { $p | Stop-Process -Force; Write-Host "  stopped $($p.ProcessName)#$($p.Id)" }
        catch { Add-Problem "could not stop $($p.ProcessName)#$($p.Id): $($_.Exception.Message)" }
    }
}

# --- 2. every path a DACL journal ever granted ------------------------------
Write-Step 'paths named by DACL journals'
$journalDir = Join-Path $env:LOCALAPPDATA 'sandbox\dacl-restore'
$journals = @()
$journalPaths = @{}
if (Test-Path -LiteralPath $journalDir) {
    $journals = @(Get-ChildItem -LiteralPath $journalDir -File -Filter *.jsonl -ErrorAction SilentlyContinue)
    foreach ($file in $journals) {
        $named = @()
        foreach ($line in Get-Content -LiteralPath $file.FullName -ErrorAction SilentlyContinue) {
            if ([string]::IsNullOrWhiteSpace($line)) { continue }
            try { $obj = $line | ConvertFrom-Json } catch { continue }
            if ($obj.PSObject.Properties.Name -contains 'path' -and $obj.path) { $named += [string]$obj.path }
        }
        $journalPaths[$file.FullName] = $named
    }
}
$allPaths = New-Object System.Collections.Generic.List[string]
foreach ($p in @($env:TEMP, $env:LOCALAPPDATA, (Join-Path $env:USERPROFILE 'AppData'), $env:USERPROFILE)) { $allPaths.Add($p) }
foreach ($named in $journalPaths.Values) { foreach ($p in $named) { $allPaths.Add($p) } }
$unique = @($allPaths | Sort-Object -Unique)
Write-Host ("  {0} journal(s) name {1} unique path(s)" -f $journals.Count, $unique.Count)

# --- 3. clean them ---------------------------------------------------------
Write-Step 'session ACEs on those paths'
$removedPaths = 0
foreach ($path in $unique) {
    switch (Remove-SessionAces $path) {
        'removed' { $removedPaths++; Write-Host "  cleaned: $path" }
        'denied' { $needsElevation.Add($path) | Out-Null; Write-Host "  ELEVATION NEEDED: $path" }
    }
}
Write-Host "  cleaned $removedPaths path(s); $($needsElevation.Count) need elevation"

# --- 4. prune journals whose paths are all gone or clean -------------------
Write-Step 'DACL journals'
$pruned = 0
foreach ($file in $journals) {
    $stillDirty = $false
    foreach ($p in @($journalPaths[$file.FullName])) {
        if ((Test-SessionAce $p).Count -gt 0) { $stillDirty = $true; break }
    }
    if (-not $stillDirty) {
        Remove-Item -LiteralPath $file.FullName -Force -ErrorAction SilentlyContinue
        $pruned++
    }
}
Write-Host "  pruned $pruned stale journal(s); $($journals.Count - $pruned) still record a live grant"

# Journals the writer quarantined as unparseable (`*.jsonl.corrupt`). They can
# never drive a restore, so they are not "dirty" - but they are residue and the
# gate must not be blind to them.
$corrupt = @(Get-ChildItem -LiteralPath $journalDir -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like '*.corrupt' })
if ($corrupt.Count -gt 0) {
    Write-Host ("  {0} quarantined journal(s) (*.corrupt, unparseable - no ACEs can be matched from them): {1}" -f $corrupt.Count, (($corrupt | ForEach-Object { $_.Name }) -join ', '))
}

# --- 5. temp directories ---------------------------------------------------
Write-Step 'test temp directories'
$patterns = @(
    'sandbox-test-*', 'sandbox-mxc-*', 'sandbox-p1-*',
    'sandbox-mxc-legs-*', 'c4-*', 'p15-*', 'p18-*',
    # VM-lane staging (the smoke run left 862 MB here). Deliberately narrow:
    # no bare `sbx-*`, which would also match unrelated user directories.
    'sbx-repo-stage-*', 'sbx-repo-*.zip'
)
$removed = 0
foreach ($pattern in $patterns) {
    foreach ($dir in @(Get-ChildItem -LiteralPath $env:TEMP -Directory -Filter $pattern -ErrorAction SilentlyContinue)) {
        try {
            Remove-Item -LiteralPath $dir.FullName -Recurse -Force -ErrorAction Stop
            $removed++
        }
        catch {
            Add-Problem "could not remove $($dir.FullName): $($_.Exception.Message)"
        }
    }
}
Write-Host "  removed $removed directory(ies)"

# The staging archive is a FILE, not a directory - Get-ChildItem -Directory
# never matches it, so it gets its own pass.
$removedZips = 0
foreach ($zip in @(Get-ChildItem -LiteralPath $env:TEMP -File -Filter 'sbx-repo-*.zip' -ErrorAction SilentlyContinue)) {
    try { Remove-Item -LiteralPath $zip.FullName -Force -ErrorAction Stop; $removedZips++ }
    catch { Add-Problem "could not remove $($zip.FullName)" }
}
if ($removedZips -gt 0) { Write-Host "  removed $removedZips staging archive(s)" }

# --- 6. session + audit state ----------------------------------------------
Write-Step 'session and audit state'
$sessions = Join-Path $env:LOCALAPPDATA 'sandbox\sessions'
$audit = Join-Path $env:LOCALAPPDATA 'sandbox\audit'
$sessionCount = if (Test-Path -LiteralPath $sessions) { @(Get-ChildItem -LiteralPath $sessions -File -ErrorAction SilentlyContinue).Count } else { 0 }
$auditCount = if (Test-Path -LiteralPath $audit) { @(Get-ChildItem -LiteralPath $audit -File -ErrorAction SilentlyContinue).Count } else { 0 }
Write-Host "  session records: $sessionCount; audit files: $auditCount"

if ($RemoveAudit) {
    if (Test-Path -LiteralPath $audit) {
        $dropped = @(Get-ChildItem -LiteralPath $audit -File)
        $dropped | Remove-Item -Force -ErrorAction SilentlyContinue
        Write-Host "  removed $($dropped.Count) audit file(s) (-RemoveAudit)"
    }
}
elseif ($auditCount -gt 0) {
    Write-Host '  audit logs kept (evidence; pass -RemoveAudit to drop them)'
}

# --- verdict ---------------------------------------------------------------
if ($needsElevation.Count -gt 0) {
    Add-Problem ("{0} path(s) still carry session ACEs and need an elevated run: {1}" -f $needsElevation.Count, ($needsElevation -join '; '))
}
if ($problems.Count -eq 0) {
    Write-Host 'HOST-CLEAN: no leftover processes, ACEs, journals or temp state'
    exit 0
}
Write-Host ("HOST-DIRTY: {0} problem(s)" -f $problems.Count)
$problems | ForEach-Object { Write-Host "  - $_" }
exit 1
