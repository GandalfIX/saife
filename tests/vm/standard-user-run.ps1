#Requires -Version 7
<#
.SYNOPSIS
  Guest-side runner for the STANDARD-USER test lane (P3.1): run a NETWORK SUBSET
  of tests\run-tests.ps1 as a non-admin guest account and prove BOTH that the
  sessions were unelevated and that the proxy really made a decision.
.DESCRIPTION
  Runs INSIDE the disposable VM, invoked by tests\vm\Invoke-TestsInVM.ps1
  -AsStandardUser. The host harness creates the local standard account, grants it
  the minimum it needs, launches THIS script with
  `Start-Process -Credential <standard user>`, fetches the artifacts this script
  leaves in -ResultsDir, and then deletes the account.

  WHY THIS LANE EXISTS
  The admin lane cannot falsify any "works without administrator" claim: every
  session it starts runs with an elevated token, so a green `elevated=false`
  verdict there would be a green run of the opposite condition. This lane runs
  the same suite from a NON-admin token, which is what makes the answer mean
  something. Two independent facts are asserted, and neither can be faked by the
  suite's own exit code:

    1. ELEVATION. This process's TokenElevation (GetTokenInformation /
       TokenElevation - the call src/setup.rs::is_elevated makes and main.rs
       writes into the SESSION_START leaf) must be FALSE, and so must every
       `elevated` field on every SESSION_START leaf the run wrote. If the launch
       silently ran elevated, the run fails here (exit 9) instead of reporting a
       beautiful, meaningless pass.
    2. A REAL NETWORK DECISION. The suite's PASS details must contain at least one
       ADMITTED CONNECT (an audit `disposition=allow`/`source=allowlist` leaf or
       `%{http_connect}` 200) AND at least one REFUSED one (403, an audit deny
       leaf, or the blocklist stage in the denial body). Exit 0 alone proves
       nothing: a filter that matches no scenario also exits 0, and a run whose
       requests never reached the proxy is indistinguishable from a run the proxy
       denied.

  It also refuses to trust a suite whose scenario count is not the number it
  asked for (see -ScenarioIds), because "the filter matched nothing" is the
  classic silent pass.

  This script is NOT a scenario: it changes no product behaviour and asserts
  nothing about the AppContainer path. It is the lane's harness.
.PARAMETER RepoDir
  Guest crate root (the staged repo copy). Default C:\sbx-repo.
.PARAMETER ResultsDir
  Where tests\vm\run-in-vm.ps1 writes its logs + summary.json, and where this
  script writes su-identity.txt, elevation-leaves.txt and su-verdict.txt.
  Default C:\sbx-results (the harness fetches that directory).
.PARAMETER ScenarioIds
  Comma-separated scenario numbers, e.g. '27,28,29,32,33,34,87,94'. A STRING on
  purpose: `pwsh -File` cannot bind an [int[]] from a single token ("27,28"
  becomes 2728 - the documented platform quirk), so the list is parsed here where
  the mistake is visible. An empty or unparseable list exits 2.
.PARAMETER Backend
  Backend for the suite. Only mxc is meaningful here (the AppContainer path needs
  the admin loopback exemption, which this token does not have); the parameter
  exists so the value is explicit in the logs and in summary.json.
.PARAMETER ToolchainBin
  Optional directory to prepend to PATH so `cargo` resolves for this account
  (used when the toolchain lives outside the machine PATH, e.g. under another
  user's profile that the harness granted read+execute on).
.PARAMETER RustupHome
  Optional RUSTUP_HOME for this run (a rustup shim needs it to find the
  toolchain it was installed into).
.PARAMETER CargoHome
  Optional CARGO_HOME, writable by this account (the harness seeds it), so the
  build never needs write access to another user's profile.
.EXAMPLE
  pwsh -NoProfile -ExecutionPolicy Bypass -File C:\sbx-repo\tests\vm\standard-user-run.ps1 `
      -RepoDir C:\sbx-repo -ResultsDir C:\sbx-results -ScenarioIds 27,28,29,32,33,34,87,94
.NOTES
  Exit codes:
    0  = lane PASS (unelevated + real decisions + the suite's own verdict clean)
    2  = invalid -ScenarioIds (empty/not integers) - fail loudly, never an empty run
    9  = this process (or a SESSION_START leaf) IS elevated - the lane proves nothing
    10 = the suite itself failed (nonzero exit from run-in-vm.ps1)
    11 = summary.json missing/incomplete, wrong lane/backend, or the run executed a
         different number of scenarios than requested
    12 = no SESSION_START leaf, or a leaf that does not say elevated=false
    13 = no real proxy decision observed (no admitted AND refused CONNECT)
    99 = unexpected error
#>
[CmdletBinding()]
param(
    [string]$RepoDir = 'C:\sbx-repo',

    [string]$ResultsDir = 'C:\sbx-results',

    [Parameter(Mandatory)]
    [string]$ScenarioIds,

    [ValidateSet('mxc')]
    [string]$Backend = 'mxc',

    [string]$ToolchainBin,

    [string]$RustupHome,

    [string]$CargoHome,

    # Console transcript written by THIS process. The lane is launched with
    # Start-Process -Credential, which cannot redirect handles
    # (CreateProcessWithLogonW inherits none, so -RedirectStandardOutput fails
    # with 'The parameter is incorrect' before pwsh even starts), so the child
    # has to own its own log. Empty/absent means 'do not transcribe'.
    [string]$LogPath
)

if ($LogPath) {
    try {
        Start-Transcript -Path $LogPath -Force | Out-Null
    } catch {
        # A transcript is diagnostics, never the verdict: losing it must not
        # turn a passing lane into a failing one.
        Write-Warning "could not start the transcript at ${LogPath}: $($_.Exception.Message)"
    }
}

$ErrorActionPreference = 'Stop'

$script:Exit = 99
$script:Lines = New-Object System.Collections.Generic.List[string]

function Write-Lane {
    param([string]$Text, [string]$Color = 'Gray')
    Write-Host "[su-lane] $Text" -ForegroundColor $Color
    $script:Lines.Add($Text)
}

# ---------------------------------------------------------------------------
# TokenElevation: the SAME question src/setup.rs::is_elevated asks its own
# process (GetTokenInformation/TokenElevation), which is what main.rs writes
# into the SESSION_START leaf. `[WindowsPrincipal]::IsInRole(Administrator)` is
# a different signal (group membership as the FILTERED token sees it) and is
# recorded as a secondary fact only - the leaf's contract is TOKEN_ELEVATION.
# ---------------------------------------------------------------------------
function Get-TokenElevation {
    $source = @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

public static class SuToken
{
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetTokenInformation(IntPtr token, int infoClass, out int info, int infoLength, out int returned);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    public static bool IsElevated()
    {
        IntPtr token;
        if (!OpenProcessToken(GetCurrentProcess(), 0x0008, out token))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "OpenProcessToken");
        }
        try
        {
            int elevated;
            int returned;
            if (!GetTokenInformation(token, 20, out elevated, 4, out returned))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "GetTokenInformation");
            }
            return elevated != 0;
        }
        finally
        {
            CloseHandle(token);
        }
    }
}
'@
    if (-not ('SuToken' -as [type])) { Add-Type -TypeDefinition $source -ErrorAction Stop }
    return [bool][SuToken]::IsElevated()
}

function Write-VerdictFile {
    param([string]$Result, [string]$Reason)
    $path = Join-Path $ResultsDir 'su-verdict.txt'
    $body = New-Object System.Collections.Generic.List[string]
    $body.Add("RESULT=$Result")
    $body.Add("REASON=$Reason")
    $body.Add("USER=$([Security.Principal.WindowsIdentity]::GetCurrent().Name)")
    $body.Add("USERPROFILE=$env:USERPROFILE")
    $body.Add("BACKEND=$Backend")
    $body.Add("SCENARIO_IDS=$ScenarioIds")
    $body.Add("FINISHED=$((Get-Date).ToString('o'))")
    $body.Add('---- lane log ----')
    foreach ($l in $script:Lines) { $body.Add($l) }
    try {
        Set-Content -LiteralPath $path -Value ($body -join [Environment]::NewLine) -Encoding utf8
        Write-Host "[su-lane] verdict written: $path"
    } catch {
        Write-Host "[su-lane] WARNING: could not write $path : $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

function Exit-Lane {
    param([int]$Code, [string]$Result, [string]$Reason)
    Write-VerdictFile -Result $Result -Reason $Reason
    # Close the transcript before the process goes away: Start-Transcript keeps
    # the file open, and a hard process exit can leave the last block unflushed
    # (the tail is exactly what an operator reads after a failure).
    if ($LogPath) { try { Stop-Transcript | Out-Null } catch { } }
    $script:Exit = $Code
}

try {
    if (-not (Test-Path -LiteralPath $RepoDir)) { throw "repo dir not found: $RepoDir" }
    if (-not (Test-Path -LiteralPath $ResultsDir)) { New-Item -ItemType Directory -Path $ResultsDir -Force | Out-Null }
    $ResultsDir = [System.IO.Path]::GetFullPath($ResultsDir)
    $RepoDir = [System.IO.Path]::GetFullPath($RepoDir)

    # -----------------------------------------------------------------------
    # 1. The scenario list. Parsed, validated, and NEVER allowed to be empty:
    #    `-Only <nothing>` runs zero scenarios and exits 0, which is exactly as
    #    green as a lane that executed the whole subset.
    # -----------------------------------------------------------------------
    $ids = @()
    foreach ($tok in ($ScenarioIds -split ',')) {
        $t = $tok.Trim()
        if (-not $t) { continue }
        if ($t -notmatch '^\d+$') {
            Write-Lane "FAIL: -ScenarioIds token '$t' is not a scenario number" 'Red'
            Exit-Lane 2 'FAIL' "invalid scenario id '$t'"
            exit 2
        }
        $ids += [int]$t
    }
    $ids = @($ids | Sort-Object -Unique)
    if ($ids.Count -eq 0) {
        Write-Lane 'FAIL: -ScenarioIds resolved to ZERO scenarios - refusing to run (a filter that matches nothing exits 0 and proves nothing)' 'Red'
        Exit-Lane 2 'FAIL' 'empty scenario subset'
        exit 2
    }
    Write-Lane ("scenario subset ({0}): {1}" -f $ids.Count, (($ids | ForEach-Object { "S-$_" }) -join ' '))

    # -----------------------------------------------------------------------
    # 2. Identity + elevation, BEFORE the suite. This is assertion 1 and it is
    #    the one the admin lane cannot make: if this process is elevated, the
    #    run is a rehearsal of the admin lane and must not report a verdict.
    # -----------------------------------------------------------------------
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    $isAdminGroup = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    $elevated = $null
    $elevationError = $null
    try { $elevated = Get-TokenElevation } catch { $elevationError = $_.Exception.Message }

    $identityPath = Join-Path $ResultsDir 'su-identity.txt'
    @(
        "USER=$($identity.Name)",
        "USERPROFILE=$env:USERPROFILE",
        "TOKEN_ELEVATION=$elevated",
        "TOKEN_ELEVATION_ERROR=$elevationError",
        "IS_IN_ADMIN_ROLE=$isAdminGroup",
        "IS_SYSTEM=$($identity.IsSystem)",
        "PROCESS_ID=$PID",
        "BACKEND=$Backend",
        "STARTED=$((Get-Date).ToString('o'))"
    ) | Set-Content -LiteralPath $identityPath -Encoding utf8
    Write-Lane ("identity: user={0} userprofile={1} TokenElevation={2} IsInRole(Administrator)={3}" -f $identity.Name, $env:USERPROFILE, $elevated, $isAdminGroup)

    if ($null -eq $elevated) {
        Write-Lane "FAIL: could not read this process's TokenElevation ($elevationError) - the lane cannot prove it ran unelevated" 'Red'
        Exit-Lane 9 'FAIL' "TokenElevation unreadable: $elevationError"
        exit 9
    }
    if ($elevated) {
        Write-Lane 'FAIL: this process IS ELEVATED - a standard-user lane running elevated proves nothing about the unelevated path' 'Red'
        Exit-Lane 9 'FAIL' 'lane process is elevated (TokenElevation=1)'
        exit 9
    }
    if ($isAdminGroup) {
        Write-Lane 'WARNING: the token reports Administrators membership (filtered admin token?). TokenElevation is 0, so the `elevated` leaf assertion still holds, but the account is not a clean standard user - check the harness user creation.' 'Yellow'
    }

    # Optional environment plumbing for the build (the harness resolves it).
    if ($ToolchainBin) { $env:Path = $ToolchainBin.TrimEnd('\') + ';' + $env:Path }
    if ($RustupHome) { $env:RUSTUP_HOME = $RustupHome }
    if ($CargoHome) { $env:CARGO_HOME = $CargoHome }

    # -----------------------------------------------------------------------
    # 3. Audit store snapshot. The leaf assertion below must read the leaves of
    #    THIS run only: a reset account can carry a previous run's files, and
    #    an old elevated=true leaf would fail the lane for the wrong reason.
    # -----------------------------------------------------------------------
    $auditDir = Join-Path $env:LOCALAPPDATA 'sandbox\audit'
    $auditBefore = @()
    if (Test-Path -LiteralPath $auditDir) {
        $auditBefore = @(Get-ChildItem -LiteralPath $auditDir -Filter '*.ndjson' -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
    }

    # -----------------------------------------------------------------------
    # 4. The suite, as a CHILD pwsh (run-in-vm.ps1 calls `exit`, which would
    #    otherwise terminate this script before the assertions below).
    #    -Command, not -File: "-Only 27,28,29" must parse as an int array
    #    literal (the -File quirk would bind it as one number).
    # -----------------------------------------------------------------------
    $runInVmPath = Join-Path $RepoDir 'tests\vm\run-in-vm.ps1'
    if (-not (Test-Path -LiteralPath $runInVmPath)) { throw "guest runner not found: $runInVmPath" }
    $escapedRunInVm = $runInVmPath.Replace("'", "''")
    $childCommand = "& '$escapedRunInVm' -Phase integration -RepoDir '$($RepoDir.Replace("'", "''"))' -ResultsDir '$($ResultsDir.Replace("'", "''"))' -Backend '$Backend' -Lane 'standard-user' -Only $(($ids -join ','))"
    Write-Lane ("suite command: pwsh -NoProfile -ExecutionPolicy Bypass -Command {0}" -f $childCommand)
    $suiteStart = Get-Date
    & pwsh -NoProfile -ExecutionPolicy Bypass -Command $childCommand 2>&1 | ForEach-Object { Write-Host "[su-lane] $_" }
    $suiteExit = $LASTEXITCODE
    Write-Lane ("suite exit={0} after {1:n0}s" -f $suiteExit, ((Get-Date) - $suiteStart).TotalSeconds)

    # -----------------------------------------------------------------------
    # 5. summary.json arithmetic. `integration.total` must equal the number
    #    requested - not merely be nonzero - so a re-filtered or empty run is a
    #    loud failure rather than a smaller green one.
    # -----------------------------------------------------------------------
    $summaryPath = Join-Path $ResultsDir 'summary.json'
    $summary = $null
    if (Test-Path -LiteralPath $summaryPath) {
        try { $summary = Get-Content -LiteralPath $summaryPath -Raw | ConvertFrom-Json } catch { $summary = $null }
    }
    if (-not $summary) {
        Write-Lane 'FAIL: summary.json missing or unparseable - the suite never reached its summary (exit codes above)' 'Red'
        Exit-Lane 11 'FAIL' 'summary.json missing/unparseable'
        exit 11
    }
    $summaryLane = [string]$summary.lane
    $summaryBackend = [string]$summary.backend
    $total = $summary.integration.total
    $passCount = $summary.integration.pass
    $failCount = $summary.integration.fail
    $skipCount = $summary.integration.skip
    Write-Lane ("summary: lane={0} backend={1} total={2} pass={3} fail={4} skip={5} verdict={6}" -f $summaryLane, $summaryBackend, $total, $passCount, $failCount, $skipCount, $summary.integration.verdict)
    if ($summaryLane -ne 'standard-user' -or $summaryBackend -ne $Backend) {
        Write-Lane ("FAIL: summary.json attributes this run to lane='{0}' backend='{1}' (expected standard-user/{2}) - the numbers cannot be attributed to this lane" -f $summaryLane, $summaryBackend, $Backend) 'Red'
        Exit-Lane 11 'FAIL' "summary attribution lane=$summaryLane backend=$summaryBackend"
        exit 11
    }
    if ($null -eq $total -or [int]$total -ne $ids.Count) {
        Write-Lane ("FAIL: the suite executed {0} scenario(s), {1} were requested - a filter that matches nothing exits 0, so the count IS the proof the subset ran" -f $total, $ids.Count) 'Red'
        Exit-Lane 11 'FAIL' "executed $total of $($ids.Count) requested scenarios"
        exit 11
    }
    if (($null -ne $passCount) -and ($null -ne $skipCount) -and (([int]$passCount + [int]$skipCount) -ne [int]$total)) {
        Write-Lane ("FAIL: pass+skip={0} != total={1} in summary.json - the counts do not add up" -f ([int]$passCount + [int]$skipCount), $total) 'Red'
        Exit-Lane 11 'FAIL' 'pass+skip != total'
        exit 11
    }
    if ($suiteExit -ne 0 -or [int]$failCount -ne 0) {
        Write-Lane ("FAIL: the suite failed (exit={0} fail={1}) - see integration.log in {2}" -f $suiteExit, $failCount, $ResultsDir) 'Red'
        Exit-Lane 10 'FAIL' "suite exit=$suiteExit fail=$failCount"
        exit 10
    }

    # -----------------------------------------------------------------------
    # 6. Assertion 1, second half: EVERY SESSION_START leaf of this run says
    #    elevated=false. Read from the same store the binary writes, so a
    #    supervisor that started an elevated session cannot hide behind a
    #    successful child.
    # -----------------------------------------------------------------------
    $newLeafFiles = @()
    $leafLines = New-Object System.Collections.Generic.List[string]
    $leaves = 0
    $elevatedTrue = 0
    $elevatedFalse = 0
    $elevatedMissing = 0
    if (Test-Path -LiteralPath $auditDir) {
        $newLeafFiles = @(Get-ChildItem -LiteralPath $auditDir -Filter '*.ndjson' -ErrorAction SilentlyContinue |
            Where-Object { $auditBefore -notcontains $_.Name })
    }
    foreach ($f in $newLeafFiles) {
        foreach ($line in (Get-Content -LiteralPath $f.FullName -ErrorAction SilentlyContinue)) {
            if (-not $line -or -not $line.Trim()) { continue }
            try { $leaf = $line | ConvertFrom-Json } catch { continue }
            if ($leaf.op -ne 'SESSION_START') { continue }
            $leaves++
            $hasKey = ($null -ne $leaf.PSObject.Properties['elevated'])
            $val = if ($hasKey) { $leaf.elevated } else { $null }
            if (-not $hasKey -or $null -eq $val) { $elevatedMissing++ }
            elseif ([bool]$val) { $elevatedTrue++ }
            else { $elevatedFalse++ }
            $leafLines.Add(("sid={0} elevated={1} present={2} tier={3} disposition={4} file={5}" -f $leaf.sid, $val, $hasKey, $leaf.tier, $leaf.disposition, $f.Name))
        }
    }
    $leafReport = New-Object System.Collections.Generic.List[string]
    $leafReport.Add(("SESSION_START_LEAVES={0} elevated_false={1} elevated_true={2} elevated_missing={3} scan_dir={4} files_scanned={5}" -f $leaves, $elevatedFalse, $elevatedTrue, $elevatedMissing, $auditDir, $newLeafFiles.Count))
    foreach ($l in $leafLines) { $leafReport.Add($l) }
    try {
        Set-Content -LiteralPath (Join-Path $ResultsDir 'elevation-leaves.txt') -Value ($leafReport -join [Environment]::NewLine) -Encoding utf8
    } catch { Write-Lane "WARNING: could not write elevation-leaves.txt: $($_.Exception.Message)" 'Yellow' }
    Write-Lane ("SESSION_START leaves: n={0} elevated=false:{1} elevated=true:{2} missing-key:{3} (files scanned: {4})" -f $leaves, $elevatedFalse, $elevatedTrue, $elevatedMissing, $newLeafFiles.Count)
    if ($leaves -eq 0) {
        Write-Lane ("FAIL: no SESSION_START leaf was written under {0} - nothing proves how the sessions ran (did the suite write its audit store elsewhere?)" -f $auditDir) 'Red'
        Exit-Lane 12 'FAIL' 'no SESSION_START leaf'
        exit 12
    }
    if ($elevatedTrue -gt 0 -or $elevatedMissing -gt 0) {
        Write-Lane ("FAIL: {0} SESSION_START leaf/leaves report elevated=true and {1} do not carry the key - the sessions were NOT uniformly unelevated" -f $elevatedTrue, $elevatedMissing) 'Red'
        Exit-Lane 12 'FAIL' "elevated=true:$elevatedTrue missing:$elevatedMissing"
        exit 12
    }

    # -----------------------------------------------------------------------
    # 7. Assertion 2: a REAL proxy decision, both directions, in the PASS
    #    details. Exit 0 cannot distinguish "admitted", "denied", "never sent".
    # -----------------------------------------------------------------------
    $integrationLog = Join-Path $ResultsDir 'integration.log'
    $passLines = @()
    if (Test-Path -LiteralPath $integrationLog) {
        $passLines = @(Get-Content -LiteralPath $integrationLog | Where-Object { $_ -match '^\[PASS\]' })
    }
    $allowEvidence = @($passLines | Where-Object {
            $_ -match '(?i)http_connect=''?200' -or $_ -match '(?i)disposition=allow' -or $_ -match '(?i)source=allowlist'
        })
    $denyEvidence = @($passLines | Where-Object {
            $_ -match '(?i)http_connect=''?403' -or $_ -match '(?i)deny leaf=true' -or $_ -match '(?i)disposition=deny' -or $_ -match '(?i)denied by the blocklist policy'
        })
    Write-Lane ("network decisions in PASS details: admitted={0} refused={1} (PASS lines seen: {2})" -f $allowEvidence.Count, $denyEvidence.Count, $passLines.Count)
    foreach ($l in @($allowEvidence | Select-Object -First 2)) { Write-Lane ("  allow-evidence: {0}" -f $l.Trim()) }
    foreach ($l in @($denyEvidence | Select-Object -First 2)) { Write-Lane ("  deny-evidence:  {0}" -f $l.Trim()) }
    if ($allowEvidence.Count -eq 0 -or $denyEvidence.Count -eq 0) {
        Write-Lane 'FAIL: no real proxy decision in both directions - an admitted CONNECT and a refused one are the property this lane exists to prove (a transport failure or a skipped scenario satisfies neither)' 'Red'
        Exit-Lane 13 'FAIL' "allowEvidence=$($allowEvidence.Count) denyEvidence=$($denyEvidence.Count)"
        exit 13
    }

    Write-Lane ("PASS: unelevated sessions (TokenElevation=0, {0} SESSION_START leaf/leaves all elevated=false) and real proxy decisions (admitted={1} refused={2})" -f $leaves, $allowEvidence.Count, $denyEvidence.Count) 'Green'
    Exit-Lane 0 'PASS' "elevated=false on $leaves leaf/leaves; admitted=$($allowEvidence.Count) refused=$($denyEvidence.Count)"
    exit 0
} catch {
    Write-Lane ("FAIL: unexpected error: {0}" -f $_.Exception.Message) 'Red'
    try { Exit-Lane 99 'FAIL' "unexpected: $($_.Exception.Message)" } catch { }
    exit 99
}
