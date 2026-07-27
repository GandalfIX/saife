#Requires -Version 5.1
<#
.SYNOPSIS
  Integration test harness for sandbox.exe (MVP US-1 vertical slice).
.DESCRIPTION
  Drives the real sandbox.exe binary through the filesystem-isolation
  scenarios (ported from the spike harness S-1..S-13) plus new scenarios
  for profile loading, variable expansion, and setup --check-only.

  The suite PASSES iff S-1..S-7, S-10, S-11, S-13 pass (the core FS pillar),
  and S-16..S-18 pass (profile loading, new in this slice). S-8/S-9 are
  python-dependent and skip cleanly. S-12/S-14/S-15 are skipped.
  S-57 (AC-5.16) covers schema_version gate rejection.
  S-58 (AC-5.12) covers wrong-type field rejection with line/col pointer.
  S-59 (AC-5.13) covers unknown-key rejection with a "Did you mean" suggestion.
.PARAMETER SandboxExe
  Path to sandbox.exe. Defaults to ..\target\release\sandbox.exe.
.PARAMETER Cwd
  Optional working directory. If omitted, a fresh temp dir is created.
.PARAMETER Keep
  Retain the temp dir for debugging.
.PARAMETER Only
  Run only the listed scenario numbers.
.PARAMETER Skip
  Skip the listed scenario numbers.
.PARAMETER StopOnFail
  Stop at the first failure.
.PARAMETER Strict
  Treat skips as failures.
.PARAMETER Diag
  Propagate SANDBOX_DIAG=1 to the child for verbose ACL diagnostics.
.EXAMPLE
  pwsh -ExecutionPolicy Bypass -File tests/run-tests.ps1
#>
[CmdletBinding()]
param(
    [string]$SandboxExe,
    [string]$Cwd,
    [switch]$Keep,
    [int[]]$Only,
    [int[]]$Skip,
    [switch]$StopOnFail,
    [switch]$Strict,
    [switch]$Diag
)

if ($Diag) { $env:SANDBOX_DIAG = '1' } else { Remove-Item env:SANDBOX_DIAG -ErrorAction SilentlyContinue }

$ErrorActionPreference = 'Stop'
$script:ThisDir = Split-Path -Parent $MyInvocation.MyCommand.Path

if (-not $SandboxExe) {
    $SandboxExe = Join-Path $script:ThisDir '..\target\release\sandbox.exe'
    $SandboxExe = [System.IO.Path]::GetFullPath($SandboxExe)
}

if (-not (Test-Path -LiteralPath $SandboxExe)) {
    $sandboxDir = [System.IO.Path]::GetFullPath((Join-Path $script:ThisDir '..'))
    Write-Host "[build] sandbox.exe not found at $SandboxExe" -ForegroundColor Yellow
    Write-Host "[build] running 'cargo build --release' in $sandboxDir" -ForegroundColor Yellow
    Push-Location -LiteralPath $sandboxDir
    try {
        & cargo build --release 2>&1 | ForEach-Object { Write-Host "[build] $_" -ForegroundColor DarkGray }
        $buildExit = $LASTEXITCODE
    } finally { Pop-Location }
    if ($buildExit -ne 0) { Write-Host "[build] cargo build failed (exit $buildExit)." -ForegroundColor Red; exit 1 }
    if (-not (Test-Path -LiteralPath $SandboxExe)) { Write-Host "[build] sandbox.exe still missing: $SandboxExe" -ForegroundColor Red; exit 1 }
}

$script:OwnsCwd = $false
$script:TempCwd = $null
if ($Cwd) {
    $Cwd = [System.IO.Path]::GetFullPath($Cwd)
    if (-not (Test-Path -LiteralPath $Cwd)) { New-Item -ItemType Directory -Path $Cwd -Force | Out-Null }
} else {
    $guid = [guid]::NewGuid().ToString('N')
    $script:TempCwd = Join-Path $env:TEMP ("sandbox-test-$guid")
    New-Item -ItemType Directory -Path $script:TempCwd -Force | Out-Null
    $Cwd = $script:TempCwd
    $script:OwnsCwd = $true
}
$script:Cwd = $Cwd

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

function New-ScenarioDir { param([int]$Number)
    $d = Join-Path $script:Cwd "S-$Number"
    if (-not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
    return $d
}

function Test-Denied { param([string]$Text)
    if (-not $Text) { return $false }
    return $Text -match '(?i)(access is denied|acces(?:s)? (?:is )?denied|acceso denegado|acces refuse|zugriff (?:wurde )?verweigert)'
}

function Invoke-Sandbox {
    param([Parameter(Mandatory)][string[]]$Args, [string]$WorkingDirectory = $script:Cwd)
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $SandboxExe
    $argParts = foreach ($a in $Args) {
        if ($a -match '\s') { '"' + ($a -replace '"','\"') + '"' } else { $a }
    }
    $psi.Arguments = ($argParts -join ' ')
    $psi.WorkingDirectory = $WorkingDirectory
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true
    $proc = New-Object System.Diagnostics.Process
    $proc.StartInfo = $psi
    if (-not $proc.Start()) { return @{ Stdout=@(); Stderr=@('failed to start'); ExitCode=-1 } }
    $so = @($proc.StandardOutput.ReadToEnd() -split "`r?`n")
    $se = @($proc.StandardError.ReadToEnd() -split "`r?`n")
    $proc.WaitForExit()
    $exit = $proc.ExitCode
    $proc.Close()
    return @{ Stdout=$so; Stderr=$se; ExitCode=$exit }
}

function Get-Python { $py = Get-Command python -ErrorAction SilentlyContinue; if (-not $py) { return $null }; return $py.Source }

function Write-Result { param([hashtable]$R)
    $tag = switch ($R.State) { 'pass' {'[PASS]'} 'fail' {'[FAIL]'} 'skip' {'[SKIP]'} 'info' {'[INFO]'} default {'[????]'} }
    $color = switch ($R.State) { 'pass' {'Green'} 'fail' {'Red'} 'skip' {'Cyan'} 'info' {'DarkGray'} default {'Gray'} }
    $msg = switch ($R.State) {
        'pass' { "$tag $($R.Name)" }
        'fail' { "$tag $($R.Name): $($R.Detail)" }
        'skip' { "$tag $($R.Name): $($R.Detail)" }
        'info' { "$tag $($R.Name): $($R.Detail)" }
        default { "$tag $($R.Name)" }
    }
    Write-Host $msg -ForegroundColor $color
}

function ConvertTo-Result { param([hashtable]$h)
    if ($h.Skipped) { $h.State = 'skip' } elseif ($h.Passed) { $h.State = 'pass' } else { $h.State = 'fail' }
    if (-not $h.ContainsKey('Name')) { $h.Name = $h.Num }
    return $h
}

# ---------------------------------------------------------------------------
# Scenarios
# ---------------------------------------------------------------------------

# S-1: baseline — sandboxed process starts and exits.
function Invoke-Scenario-S1 {
    $d = New-ScenarioDir 1
    $r = Invoke-Sandbox -Args @('run','--allow-cwd','--','cmd','/c','echo','hello') -WorkingDirectory $d
    $out = ($r.Stdout -join "`n")
    $passed = ($r.ExitCode -eq 0) -and ($out -match 'hello')
    return @{ Num=1; Name='S-1'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { 'baseline echo' } else { "exit=$($r.ExitCode) stdout=$out" } }
}

# S-2: disallowed file read is denied (.ssh\id_rsa not in allow-list).
function Invoke-Scenario-S2 {
    $d = New-ScenarioDir 2
    $target = Join-Path $env:USERPROFILE '.ssh\id_rsa'
    $r = Invoke-Sandbox -Args @('run','--allow-cwd','--','cmd','/c','type',$target) -WorkingDirectory $d
    $err = ($r.Stderr -join "`n")
    $passed = ($r.ExitCode -ne 0) -and (Test-Denied $err)
    return @{ Num=2; Name='S-2'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { 'denied read of .ssh\id_rsa' } else { "exit=$($r.ExitCode) stderr=$err" } }
}

# S-3: disallowed sibling project is denied.
function Invoke-Scenario-S3 {
    $d = New-ScenarioDir 3
    $parent = Split-Path -Parent $d
    $other = Join-Path $parent 'other-project'
    if (-not (Test-Path -LiteralPath $other)) { New-Item -ItemType Directory -Path $other -Force | Out-Null }
    $envFile = Join-Path $other '.env'
    Set-Content -LiteralPath $envFile -Value 'DUMMY_SECRET=do-not-read' -Encoding ASCII
    $r = Invoke-Sandbox -Args @('run','--allow-cwd','--','cmd','/c','type','..\other-project\.env') -WorkingDirectory $d
    $err = ($r.Stderr -join "`n")
    $passed = ($r.ExitCode -ne 0) -and (Test-Denied $err)
    return @{ Num=3; Name='S-3'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { 'sibling project denied' } else { "exit=$($r.ExitCode) stderr=$err" } }
}

# S-4: allowed write to $CWD works.
function Invoke-Scenario-S4 {
    $d = New-ScenarioDir 4
    $r = Invoke-Sandbox -Args @('run','--allow-cwd','--','cmd','/c','echo test > new-file.txt') -WorkingDirectory $d
    $file = Join-Path $d 'new-file.txt'
    $exists = Test-Path -LiteralPath $file
    $content = if ($exists) { (Get-Content -LiteralPath $file -Raw).Trim() } else { '' }
    $passed = ($r.ExitCode -eq 0) -and $exists -and ($content -match 'test')
    return @{ Num=4; Name='S-4'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { 'allowed write to $CWD' } else { "exit=$($r.ExitCode) exists=$exists content=$content" } }
}

# S-5: write to disallowed path is denied (.ssh\evil.txt not created).
function Invoke-Scenario-S5 {
    $d = New-ScenarioDir 5
    $sshDir = Join-Path $env:USERPROFILE '.ssh'
    if (-not (Test-Path -LiteralPath $sshDir)) { New-Item -ItemType Directory -Path $sshDir -Force | Out-Null }
    $evil = Join-Path $sshDir 'evil.txt'
    if (Test-Path -LiteralPath $evil) { Remove-Item -LiteralPath $evil -Force }
    $r = Invoke-Sandbox -Args @('run','--allow-cwd','--','cmd','/c','echo','bad','>',$evil) -WorkingDirectory $d
    $err = ($r.Stderr -join "`n")
    $exists = Test-Path -LiteralPath $evil
    $passed = ($r.ExitCode -ne 0) -and (Test-Denied $err) -and (-not $exists)
    try { if ($exists) { Remove-Item -LiteralPath $evil -Force } } catch {}
    return @{ Num=5; Name='S-5'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { 'write to .ssh denied' } else { "exit=$($r.ExitCode) exists=$exists stderr=$err" } }
}

# S-6 (GATE): download a binary into .sandbox\<sid>\bin and execute it.
function Invoke-Scenario-S6 {
    $d = New-ScenarioDir 6
    $psid = Invoke-Sandbox -Args @('run','--allow-cwd','--print-sid','--','cmd','/c','echo','init') -WorkingDirectory $d
    if ($psid.ExitCode -ne 0) { return @{ Num=6; Name='S-6 (GATE)'; Passed=$false; Skipped=$false; Detail="print-sid failed exit=$($psid.ExitCode)"; IsGate=$true } }
    $sid = ($psid.Stdout -join '').Trim()
    if (-not $sid) { return @{ Num=6; Name='S-6 (GATE)'; Passed=$false; Skipped=$false; Detail='print-sid returned empty sid'; IsGate=$true } }
    $binName = 'hostname.exe'
    $binWhere = Join-Path $d ".sandbox\$sid\bin\$binName"
    $r1 = Invoke-Sandbox -Args @('run','--allow-cwd','--sid',$sid,'--','cmd','/c','copy',"C:\Windows\System32\$binName",".sandbox\$sid\bin\$binName") -WorkingDirectory $d
    $installed = Test-Path -LiteralPath $binWhere
    $r2 = Invoke-Sandbox -Args @('run','--allow-cwd','--sid',$sid,'--','cmd','/c',".sandbox\$sid\bin\$binName") -WorkingDirectory $d
    $out2 = (($r2.Stdout | Where-Object { $_ -notmatch '^SESSION ' }) -join "`n")
    $passed = ($r1.ExitCode -eq 0) -and $installed -and ($r2.ExitCode -eq 0) -and ($out2.Trim().Length -gt 0)
    return @{ Num=6; Name='S-6 (GATE)'; Passed=$passed; Skipped=$false; IsGate=$true
        Detail = if ($passed) { "downloaded binary executed; sid=$sid" } else { "sid=$sid copyExit=$($r1.ExitCode) installed=$installed runExit=$($r2.ExitCode) out=$out2" } }
}

# S-7: write into .sandbox\<sid>\bin works.
function Invoke-Scenario-S7 {
    $d = New-ScenarioDir 7
    $psid = Invoke-Sandbox -Args @('run','--allow-cwd','--print-sid','--','cmd','/c','echo','init') -WorkingDirectory $d
    if ($psid.ExitCode -ne 0) { return @{ Num=7; Name='S-7'; Passed=$false; Skipped=$false; Detail="print-sid failed exit=$($psid.ExitCode)" } }
    $sid = ($psid.Stdout -join '').Trim()
    $marker = Join-Path $d ".sandbox\$sid\bin\marker.txt"
    $r = Invoke-Sandbox -Args @('run','--allow-cwd','--sid',$sid,'--','cmd','/c','echo','test','>',".sandbox\$sid\bin\marker.txt") -WorkingDirectory $d
    $exists = Test-Path -LiteralPath $marker
    $passed = ($r.ExitCode -eq 0) -and $exists
    return @{ Num=7; Name='S-7'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { "marker written; sid=$sid" } else { "exit=$($r.ExitCode) exists=$exists sid=$sid" } }
}

# S-8: python from system install runs (skips if python absent).
function Invoke-Scenario-S8 {
    $d = New-ScenarioDir 8
    if (-not (Get-Python)) { return @{ Num=8; Name='S-8'; Passed=$true; Skipped=$true; PythonSkipped=$true; Detail='python not on PATH' } }
    $r = Invoke-Sandbox -Args @('run','--allow-cwd','--','python','-c',"print('hello from python')") -WorkingDirectory $d
    $out = ($r.Stdout -join "`n")
    $passed = ($r.ExitCode -eq 0) -and ($out -match 'hello from python')
    return @{ Num=8; Name='S-8'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { 'python ran' } else { "exit=$($r.ExitCode) stdout=$out" } }
}

# S-9: python venv created in .sandbox\<sid>\venv (skips if python absent).
function Invoke-Scenario-S9 {
    $d = New-ScenarioDir 9
    if (-not (Get-Python)) { return @{ Num=9; Name='S-9'; Passed=$true; Skipped=$true; PythonSkipped=$true; Detail='python not on PATH' } }
    $psid = Invoke-Sandbox -Args @('run','--allow-cwd','--print-sid','--','cmd','/c','echo','init') -WorkingDirectory $d
    if ($psid.ExitCode -ne 0) { return @{ Num=9; Name='S-9'; Passed=$false; Skipped=$false; Detail="print-sid failed exit=$($psid.ExitCode)" } }
    $sid = ($psid.Stdout -join '').Trim()
    $r1 = Invoke-Sandbox -Args @('run','--allow-cwd','--sid',$sid,'--','python','-m','venv',".sandbox\$sid\venv") -WorkingDirectory $d
    $pyExe = Join-Path $d ".sandbox\$sid\venv\Scripts\python.exe"
    if ($r1.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $pyExe)) {
        return @{ Num=9; Name='S-9'; Passed=$false; Skipped=$false; Detail="venv create failed exit=$($r1.ExitCode) pyExists=$(Test-Path -LiteralPath $pyExe)" }
    }
    $r2 = Invoke-Sandbox -Args @('run','--allow-cwd','--sid',$sid,'--','cmd','/c',$pyExe,'-c',"print('venv works')") -WorkingDirectory $d
    $out = ($r2.Stdout -join "`n")
    $passed = ($r2.ExitCode -eq 0) -and ($out -match 'venv works')
    return @{ Num=9; Name='S-9'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { "venv python ran; sid=$sid" } else { "exit=$($r2.ExitCode) stdout=$out" } }
}

# S-10: child process inherits restrictions (depth 3).
function Invoke-Scenario-S10 {
    $d = New-ScenarioDir 10
    $target = Join-Path $env:USERPROFILE '.ssh\id_rsa'
    $r = Invoke-Sandbox -Args @('run','--allow-cwd','--','cmd','/c','cmd','/c','cmd','/c','type',$target) -WorkingDirectory $d
    $err = ($r.Stderr -join "`n")
    $passed = ($r.ExitCode -ne 0) -and (Test-Denied $err)
    return @{ Num=10; Name='S-10'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { 'denied at depth 3' } else { "exit=$($r.ExitCode) stderr=$err" } }
}

# S-11: Job Object kills the whole tree on parent exit.
function Invoke-Scenario-S11 {
    $d = New-ScenarioDir 11
    Get-Process ping -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    $proc = Start-Process -FilePath $SandboxExe -ArgumentList @('run','--allow-cwd','--','cmd','/c','ping -t 127.0.0.1') -PassThru -WorkingDirectory $d
    Start-Sleep -Seconds 1
    try { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue } catch {}
    Start-Sleep -Seconds 1
    $alive = Get-Process ping -ErrorAction SilentlyContinue
    $passed = (-not $alive)
    Get-Process ping -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    return @{ Num=11; Name='S-11'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { 'Job Object killed child tree' } else { 'ping.exe still alive' } }
}

# S-12: breakaway blocked (AC-2.5) — requires the breakaway-helper.exe binary.
# The helper calls CreateProcessW with CREATE_BREAKAWAY_FROM_JOB and prints
# `CREATEPROCESS_FAILED <code>` when the call is denied. Under the sandbox's
# Job Object (no BREAKAWAY_OK), the call fails with ERROR_ACCESS_DENIED (5).
function Invoke-Scenario-S12 {
    $d = New-ScenarioDir 12
    $helperSrc = [System.IO.Path]::GetFullPath((Join-Path $script:ThisDir '..\target\release\breakaway-helper.exe'))
    if (-not (Test-Path -LiteralPath $helperSrc)) {
        return @{ Num=12; Name='S-12'; Passed=$true; Skipped=$true; Detail='breakaway-helper.exe not built (run: cargo build --release --bin breakaway-helper)' }
    }
    # Copy the helper into $CWD so the sandboxed process (allow-cwd) can execute it.
    $helperDst = Join-Path $d 'breakaway-helper.exe'
    Copy-Item -LiteralPath $helperSrc -Destination $helperDst -Force
    # Invoke the helper directly (not via `cmd /c`): cmd's command resolution
    # triggers an extra access path that the AppContainer denies, which would
    # mask the helper's own CREATEPROCESS_FAILED output. The helper is a
    # standalone exe, so direct invocation is the faithful test.
    $r = Invoke-Sandbox -Args @('run','--allow-cwd','--',$helperDst) -WorkingDirectory $d
    $out = ($r.Stdout -join "`n")
    $passed = ($out -match 'CREATEPROCESS_FAILED\s+5')
    return @{ Num=12; Name='S-12 (AC-2.5)'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { 'breakaway denied with ERROR_ACCESS_DENIED (5)' } else { "exit=$($r.ExitCode) stdout=$out" } }
}

# S-13: per-session isolation — two sessions get distinct install trees.
function Invoke-Scenario-S13 {
    $d = New-ScenarioDir 13
    $psidA = Invoke-Sandbox -Args @('run','--allow-cwd','--print-sid','--','cmd','/c','echo','init') -WorkingDirectory $d
    $psidB = Invoke-Sandbox -Args @('run','--allow-cwd','--print-sid','--','cmd','/c','echo','init') -WorkingDirectory $d
    if ($psidA.ExitCode -ne 0 -or $psidB.ExitCode -ne 0) { return @{ Num=13; Name='S-13'; Passed=$false; Skipped=$false; Detail="print-sid failed A=$($psidA.ExitCode) B=$($psidB.ExitCode)" } }
    $sidA = ($psidA.Stdout -join '').Trim()
    $sidB = ($psidB.Stdout -join '').Trim()
    if (-not $sidA -or -not $sidB) { return @{ Num=13; Name='S-13'; Passed=$false; Skipped=$false; Detail="empty sid A='$sidA' B='$sidB'" } }
    if ($sidA -eq $sidB) { return @{ Num=13; Name='S-13'; Passed=$false; Skipped=$false; Detail="sids not distinct: A=B='$sidA'" } }
    $whereA = Join-Path $d ".sandbox\$sidA\bin\where.exe"
    $whereB = Join-Path $d ".sandbox\$sidB\bin\where.exe"
    Invoke-Sandbox -Args @('run','--allow-cwd','--sid',$sidA,'--','cmd','/c','copy','C:\Windows\System32\where.exe',".sandbox\$sidA\bin\where.exe") -WorkingDirectory $d | Out-Null
    $aInstalled = Test-Path -LiteralPath $whereA
    $bExists = Test-Path -LiteralPath $whereB
    $binB = Join-Path $d ".sandbox\$sidB\bin"
    $binBExists = Test-Path -LiteralPath $binB
    $rB = Invoke-Sandbox -Args @('run','--allow-cwd','--sid',$sidB,'--','cmd','/c','type',".sandbox\$sidA\bin\where.exe") -WorkingDirectory $d
    $errB = ($rB.Stderr -join "`n")
    $bDenied = ($rB.ExitCode -ne 0) -and (Test-Denied $errB)
    $passed = $aInstalled -and (-not $bExists) -and $binBExists -and $bDenied
    return @{ Num=13; Name='S-13'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { "distinct sids; B denied A's tools" } else { "aInstalled=$aInstalled bExists=$bExists binBExists=$binBExists bDenied=$bDenied" } }
}

# S-14: persist/reuse (SKIP — not implemented in this slice).
function Invoke-Scenario-S14 {
    return @{ Num=14; Name='S-14'; Passed=$true; Skipped=$true; Detail='persist/reuse not implemented in this slice' }
}

# S-15: UI app (SKIP — manual observation).
function Invoke-Scenario-S15 {
    return @{ Num=15; Name='S-15'; Passed=$true; Skipped=$true; Detail='manual observation required' }
}

# S-16: profile loading — write a profile JSON, run with --profile.
function Invoke-Scenario-S16 {
    $d = New-ScenarioDir 16
    $profileDir = Join-Path $d 'profiles'
    New-Item -ItemType Directory -Path $profileDir -Force | Out-Null
    $profilePath = Join-Path $profileDir 'test.json'
    $profileJson = @{
        meta = @{ name = 'test'; schema_version = 1; version = '1.0.0'; description = 'test profile' }
        filesystem = @{ allow = @('$CWD'); read_only = @(); deny = @() }
    } | ConvertTo-Json -Depth 5
    Set-Content -LiteralPath $profilePath -Value $profileJson -Encoding UTF8
    $r = Invoke-Sandbox -Args @('run','--profile',$profilePath,'--','cmd','/c','echo','profile-works') -WorkingDirectory $d
    $out = ($r.Stdout -join "`n")
    $passed = ($r.ExitCode -eq 0) -and ($out -match 'profile-works')
    return @{ Num=16; Name='S-16'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { 'profile loaded and ran' } else { "exit=$($r.ExitCode) stdout=$out" } }
}

# S-17: --read-only flag makes a path read-only (write denied).
# The read-only dir is placed OUTSIDE $CWD so the only ACE on it is the
# read-only RX grant (inside $CWD, the inherited RWX Allow would override).
function Invoke-Scenario-S17 {
    $d = New-ScenarioDir 17
    $roDir = Join-Path (Split-Path -Parent $d) 'ro-sibling-17'
    New-Item -ItemType Directory -Path $roDir -Force | Out-Null
    $roFile = Join-Path $roDir 'file.txt'
    Set-Content -LiteralPath $roFile -Value 'existing' -Encoding ASCII
    # Note: do NOT embed quotes in the cmd line — Invoke-Sandbox's arg quoting
    # would double-escape them. The path has no spaces in the temp dir, so
    # unquoted redirection works.
    $cmdLine = "echo new > $roFile"
    $r = Invoke-Sandbox -Args @('run','--allow-cwd','--read-only',$roDir,'--','cmd','/c',$cmdLine) -WorkingDirectory $d
    $err = ($r.Stderr -join "`n")
    $passed = ($r.ExitCode -ne 0) -and (Test-Denied $err)
    return @{ Num=17; Name='S-17'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { 'read-only path write denied' } else { "exit=$($r.ExitCode) stderr=$err" } }
}

# S-18: setup --check-only runs and reports the feature matrix.
function Invoke-Scenario-S18 {
    $d = New-ScenarioDir 18
    $r = Invoke-Sandbox -Args @('setup','--check-only') -WorkingDirectory $d
    $out = ($r.Stdout -join "`n")
    $passed = ($r.ExitCode -eq 0) -and ($out -match 'Windows build number') -and ($out -match 'AppContainer')
    return @{ Num=18; Name='S-18'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { 'setup --check-only reported' } else { "exit=$($r.ExitCode) stdout=$out" } }
}

# S-19: python_runtime security group makes python usable (AC-2.9).
# Skips cleanly if python is not on PATH.
function Invoke-Scenario-S19 {
    $d = New-ScenarioDir 19
    if (-not (Get-Python)) { return @{ Num=19; Name='S-19'; Passed=$true; Skipped=$true; PythonSkipped=$true; Detail='python not on PATH' } }
    $profileDir = Join-Path $d 'profiles'
    New-Item -ItemType Directory -Path $profileDir -Force | Out-Null
    $profilePath = Join-Path $profileDir 'py-runtime.json'
    $profileJson = @{
        meta = @{ name = 'py-runtime'; schema_version = 1; version = '1.0.0' }
        security = @{ groups = @('python_runtime') }
        filesystem = @{ allow = @('$CWD'); read_only = @(); deny = @() }
    } | ConvertTo-Json -Depth 5
    Set-Content -LiteralPath $profilePath -Value $profileJson -Encoding UTF8
    $r = Invoke-Sandbox -Args @('run','--profile',$profilePath,'--allow-cwd','--','python','-c',"print('python-runtime-ok')") -WorkingDirectory $d
    $out = ($r.Stdout -join "`n")
    $passed = ($r.ExitCode -eq 0) -and ($out -match 'python-runtime-ok')
    return @{ Num=19; Name='S-19 (AC-2.9 py)'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { 'python_runtime group let python run' } else { "exit=$($r.ExitCode) stdout=$out" } }
}

# S-20: node_runtime security group makes node usable (AC-2.9).
# Skips cleanly if node is not on PATH.
function Invoke-Scenario-S20 {
    $d = New-ScenarioDir 20
    $node = Get-Command node -ErrorAction SilentlyContinue
    if (-not $node) { return @{ Num=20; Name='S-20'; Passed=$true; Skipped=$true; Detail='node not on PATH' } }
    $profileDir = Join-Path $d 'profiles'
    New-Item -ItemType Directory -Path $profileDir -Force | Out-Null
    $profilePath = Join-Path $profileDir 'node-runtime.json'
    $profileJson = @{
        meta = @{ name = 'node-runtime'; schema_version = 1; version = '1.0.0' }
        security = @{ groups = @('node_runtime') }
        filesystem = @{ allow = @('$CWD'); read_only = @(); deny = @() }
    } | ConvertTo-Json -Depth 5
    Set-Content -LiteralPath $profilePath -Value $profileJson -Encoding UTF8
    $r = Invoke-Sandbox -Args @('run','--profile',$profilePath,'--allow-cwd','--','node','-e',"console.log('node-runtime-ok')") -WorkingDirectory $d
    $out = ($r.Stdout -join "`n")
    $passed = ($r.ExitCode -eq 0) -and ($out -match 'node-runtime-ok')
    return @{ Num=20; Name='S-20 (AC-2.9 node)'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { 'node_runtime group let node run' } else { "exit=$($r.ExitCode) stdout=$out" } }
}

# S-21: shell wrapper stays confined (AC-2.6). The agent writes a .bat inside
# $CWD that shells out to powershell to read .ssh\id_rsa; the read must be
# denied because the wrapper inherits the restricted token.
function Invoke-Scenario-S21 {
    $d = New-ScenarioDir 21
    $target = Join-Path $env:USERPROFILE '.ssh\id_rsa'
    $wrapper = Join-Path $d 'wrapper.bat'
    # Use a here-string to avoid quoting headaches; the .bat calls powershell.
    $batContent = "@echo off`r`npowershell -NoProfile -Command `"try { Get-Content -LiteralPath '$target' -ErrorAction Stop } catch { exit 1 }`""
    Set-Content -LiteralPath $wrapper -Value $batContent -Encoding ASCII
    $r = Invoke-Sandbox -Args @('run','--allow-cwd','--','cmd','/c','wrapper.bat') -WorkingDirectory $d
    $passed = ($r.ExitCode -ne 0)
    return @{ Num=21; Name='S-21 (AC-2.6)'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { 'shell wrapper denied .ssh read' } else { "exit=$($r.ExitCode) (expected non-zero)" } }
}

# S-22: gradle/javac worker stays confined (AC-2.3) — deferred (needs java + gradle fixture).
function Invoke-Scenario-S22 {
    return @{ Num=22; Name='S-22'; Passed=$true; Skipped=$true; Detail='AC-2.3 gradle scenario deferred (needs java + gradle fixture)' }
}

# S-23: reserved for a future US-2 scenario slot.
function Invoke-Scenario-S23 {
    return @{ Num=23; Name='S-23'; Passed=$true; Skipped=$true; Detail='reserved' }
}

# S-24: exit code propagation (AC-2.8).
function Invoke-Scenario-S24 {
    $d = New-ScenarioDir 24
    $r = Invoke-Sandbox -Args @('run','--allow-cwd','--','cmd','/c','exit','42') -WorkingDirectory $d
    $passed = ($r.ExitCode -eq 42)
    return @{ Num=24; Name='S-24 (AC-2.8)'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { 'exit code 42 propagated' } else { "exit=$($r.ExitCode) (expected 42)" } }
}

# S-25: AC-3.1 — block-net denies urllib connect (skips if no python).
function Invoke-Scenario-S25 {
    $d = New-ScenarioDir 25
    $py = Get-Python
    if (-not $py) { return @{ Num=25; Name='S-25 (AC-3.1)'; Passed=$true; Skipped=$true; PythonSkipped=$true; Detail='python not on PATH' } }
    $r = Invoke-Sandbox -Args @('run','--allow-cwd','--block-net','--','python','-c',"import urllib.request,sys; urllib.request.urlopen('https://api.openai.com')") -WorkingDirectory $d
    $err = ($r.Stderr -join "`n")
    $passed = ($r.ExitCode -ne 0) -and ($err -match '(?i)(access is denied|urLError|ConnectionError|PermissionError|WSAEACCES)')
    return @{ Num=25; Name='S-25 (AC-3.1)'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { 'block-net denied urllib connect' } else { "exit=$($r.ExitCode) stderr=$err" } }
}

# S-26: AC-3.2 — block-net denies raw socket to metadata IP (skips if no python).
function Invoke-Scenario-S26 {
    $d = New-ScenarioDir 26
    $py = Get-Python
    if (-not $py) { return @{ Num=26; Name='S-26 (AC-3.2)'; Passed=$true; Skipped=$true; PythonSkipped=$true; Detail='python not on PATH' } }
    $r = Invoke-Sandbox -Args @('run','--allow-cwd','--block-net','--','python','-c',"import socket; socket.create_connection(('169.254.169.254',80))") -WorkingDirectory $d
    $err = ($r.Stderr -join "`n")
    $passed = ($r.ExitCode -ne 0) -and ($err -match '(?i)(access is denied|PermissionError|WSAEACCES)')
    return @{ Num=26; Name='S-26 (AC-3.2)'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { 'block-net denied raw socket to metadata' } else { "exit=$($r.ExitCode) stderr=$err" } }
}

# S-27: AC-3.3 — allow-domain permits the listed host.
# DEFERRED: --allow-domain requires the loopback exemption, whose admin-only
# API (NetworkIsolationSetAppContainerConfig) is deferred pending the
# unprivileged privateNetworkClientServer-capability path.
function Invoke-Scenario-S27 {
    return @{ Num=27; Name='S-27 (AC-3.3)'; Passed=$true; Skipped=$true; Detail='deferred: --allow-domain loopback mechanism pending (admin-only API)' }
}

# S-28: AC-3.4 — allow-domain denies an unlisted host. (DEFERRED — see S-27.)
function Invoke-Scenario-S28 {
    return @{ Num=28; Name='S-28 (AC-3.4)'; Passed=$true; Skipped=$true; Detail='deferred: --allow-domain loopback mechanism pending (admin-only API)' }
}

# S-29: AC-3.5 — wildcard suffix matches, dot-bounded. (DEFERRED — see S-27.)
function Invoke-Scenario-S29 {
    return @{ Num=29; Name='S-29 (AC-3.5)'; Passed=$true; Skipped=$true; Detail='deferred: --allow-domain loopback mechanism pending (admin-only API)' }
}

# S-30: AC-3.6 — always-denied overrides explicit allow. (DEFERRED — see S-27.)
function Invoke-Scenario-S30 {
    return @{ Num=30; Name='S-30 (AC-3.6)'; Passed=$true; Skipped=$true; Detail='deferred: --allow-domain loopback mechanism pending (admin-only API)' }
}

# S-31: AC-3.7 — metadata.google.internal denied. (DEFERRED — see S-27.)
function Invoke-Scenario-S31 {
    return @{ Num=31; Name='S-31 (AC-3.7)'; Passed=$true; Skipped=$true; Detail='deferred: --allow-domain loopback mechanism pending (admin-only API)' }
}

# S-32: AC-3.8 — minimal profile allows LLM APIs, denies github. (DEFERRED — see S-27.)
function Invoke-Scenario-S32 {
    return @{ Num=32; Name='S-32 (AC-3.8)'; Passed=$true; Skipped=$true; Detail='deferred: --network-profile loopback mechanism pending (admin-only API)' }
}

# S-33: AC-3.9 — developer profile adds registries + github. (DEFERRED — see S-27.)
function Invoke-Scenario-S33 {
    return @{ Num=33; Name='S-33 (AC-3.9)'; Passed=$true; Skipped=$true; Detail='deferred: --network-profile loopback mechanism pending (admin-only API)' }
}

# S-34: AC-3.10 — profile + CLI flags merge. (DEFERRED — see S-27.)
function Invoke-Scenario-S34 {
    return @{ Num=34; Name='S-34 (AC-3.10)'; Passed=$true; Skipped=$true; Detail='deferred: --allow-domain loopback mechanism pending (admin-only API)' }
}

# S-35: AC-3.11 — two concurrent sessions get distinct sids (proxy ports differ).
function Invoke-Scenario-S35 {
    $d = New-ScenarioDir 35
    $jobA = Start-Job -ScriptBlock {
        param($SandboxExe,$d)
        & $SandboxExe run --allow-cwd --network-profile minimal --print-sid -- cmd /c echo init
    } -ArgumentList $SandboxExe,$d
    $jobB = Start-Job -ScriptBlock {
        param($SandboxExe,$d)
        & $SandboxExe run --allow-cwd --network-profile minimal --print-sid -- cmd /c echo init
    } -ArgumentList $SandboxExe,$d
    $rA = Receive-Job $jobA -Wait -AutoRemoveJob
    $rB = Receive-Job $jobB -Wait -AutoRemoveJob
    $sidA = (($rA | Where-Object { $_ -match '^\d{8}-\d{6}-\d{5}$' }) -join '').Trim()
    $sidB = (($rB | Where-Object { $_ -match '^\d{8}-\d{6}-\d{5}$' }) -join '').Trim()
    $passed = $sidA -and $sidB -and ($sidA -ne $sidB)
    return @{ Num=35; Name='S-35 (AC-3.11)'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { 'two concurrent sessions; sids differ' } else { "A='$sidA' B='$sidB'" } }
}

# S-36: AC-3.12 — no token → 407. (DEFERRED — requires the proxy, which needs the loopback exemption; see S-27.)
function Invoke-Scenario-S36 {
    return @{ Num=36; Name='S-36 (AC-3.12)'; Passed=$true; Skipped=$true; Detail='deferred: proxy/loopback mechanism pending (admin-only API)' }
}

# S-37: AC-3.13 — raw-socket app fails closed (skips if no python).
function Invoke-Scenario-S37 {
    $d = New-ScenarioDir 37
    $py = Get-Python
    if (-not $py) { return @{ Num=37; Name='S-37 (AC-3.13)'; Passed=$true; Skipped=$true; PythonSkipped=$true; Detail='python not on PATH' } }
    $r = Invoke-Sandbox -Args @('run','--allow-cwd','--allow-domain','api.openai.com','--','python','-c',"import socket; socket.create_connection(('api.openai.com',443))") -WorkingDirectory $d
    $err = ($r.Stderr -join "`n")
    $passed = ($r.ExitCode -ne 0) -and ($err -match '(?i)(access is denied|PermissionError|WSAEACCES|Operation not permitted)')
    return @{ Num=37; Name='S-37 (AC-3.13)'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { 'raw-socket direct connect denied by AC' } else { "exit=$($r.ExitCode) stderr=$err" } }
}

# S-38: AC-3.14 — proxy port released on sandbox exit. (DEFERRED — requires the proxy; see S-27.)
function Invoke-Scenario-S38 {
    return @{ Num=38; Name='S-38 (AC-3.14)'; Passed=$true; Skipped=$true; Detail='deferred: proxy/loopback mechanism pending (admin-only API)' }
}

# S-39: AC-3.15 — DEFERRED to F-6 (WFP callout driver).
function Invoke-Scenario-S39 {
    return @{ Num=39; Name='S-39 (AC-3.15)'; Passed=$true; Skipped=$true; Detail='deferred to F-6 (WFP callout driver)' }
}

# ---------------------------------------------------------------------------
# KI-1.1 scenarios — `cmd /c dir` and PowerShell `Get-ChildItem` (no path)
# require the AppContainer to read drive-root volume metadata via
# GetVolumeInformationW("C:\"). The drive root (C:\) is TrustedInstaller-owned
# and cannot be granted unprivileged, so the fix is a one-time admin grant of
# FILE_READ_ATTRIBUTES for S-1-15-2-2 (All RESTRICTED APPLICATION PACKAGES) on
# each fixed drive root, applied by `sandbox setup --grant-drive-root`.
#
# These scenarios SKIP cleanly when the drive-root grant is absent (so the
# suite stays green on unconfigured machines) and PASS once it has been
# applied. S-42 (sibling still denied) is unconditional.
# ---------------------------------------------------------------------------

# Detect whether the cwd's drive root carries an Allow ACE for
# S-1-15-2-2 (All RESTRICTED APPLICATION PACKAGES). Used by S-40/S-41 to decide
# pass-vs-skip. We read the DACL's SDDL form and match the SID string directly,
# because Get-Acl renders the well-known SID as a localized NTAccount name
# (e.g. "ZERTIFIZIERUNGSSTELLE FÜR ANWENDUNGSPAKETE\ALLE EINGESCHRÄNKTEN
# ANWENDUNGSPAKETE") whose back-translation to a SID fails on non-English
# locales. The SDDL text always carries the raw SID (e.g. "S-1-15-2-2").
function Test-DriveRootGranted { param([string]$DriveRoot)
    if (-not $DriveRoot) { return $false }
    if (-not (Test-Path -LiteralPath $DriveRoot)) { return $false }
    try {
        $acl = Get-Acl -LiteralPath $DriveRoot -ErrorAction Stop
        $sddl = $acl.Sddl
        # SDDL ACEs look like "(A;...;SID)" — match the SID anywhere in the string.
        return $sddl -match 'S-1-15-2-2\b'
    } catch {
        return $false
    }
}

# Resolve the drive root (e.g. "C:\") of a given path.
function Get-DriveRootOf { param([string]$Path)
    if (-not $Path) { return $null }
    $full = [System.IO.Path]::GetFullPath($Path)
    if ($full.Length -ge 2 -and $full[1] -eq [char]':') { return "$($full[0]):\" }
    return $null
}

# S-40: KI-1.1 — `cmd /c dir` lists the cwd (volume header + entries).
# Requires the drive-root grant (run `sandbox setup --grant-drive-root` once).
function Invoke-Scenario-S40 {
    $d = New-ScenarioDir 40
    'ki11-marker' | Set-Content -LiteralPath (Join-Path $d 'marker.txt') -Encoding ASCII
    $root = Get-DriveRootOf $d
    if (-not (Test-DriveRootGranted $root)) {
        return @{ Num=40; Name='S-40 (KI-1.1 cmd dir)'; Passed=$true; Skipped=$true; DriveRootSkipped=$true
                  Detail="drive root '$root' not granted; run 'sandbox setup --grant-drive-root' (admin)" }
    }
    $r = Invoke-Sandbox -Args @('run','--allow-cwd','--','cmd','/c','dir') -WorkingDirectory $d
    $out = ($r.Stdout -join "`n")
    $passed = ($r.ExitCode -eq 0) -and ($out -match 'marker.txt')
    return @{ Num=40; Name='S-40 (KI-1.1 cmd dir)'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { 'cmd /c dir listed cwd' } else { "exit=$($r.ExitCode) stdout=$out" } }
}

# S-41: KI-1.1 — PowerShell `Get-ChildItem` with an explicit path lists the cwd.
# The no-path form (`Get-ChildItem`) is blocked by PowerShell's PSDrive init:
# `InitializeDefaultDrives` walks every drive root, and `Set-Location` to the
# cwd walks ancestor dirs (`C:\Users`, `C:\Users\<user>`) which are
# SYSTEM/TrustedInstaller-owned and ungrantable unprivileged. The supported
# pattern under the sandbox is to pass the cwd explicitly. We use
# `[Environment]::CurrentDirectory` (the real Win32 cwd, which the sandbox sets
# correctly) rather than `$PWD` (PowerShell's PSDrive location, which is
# pinned to a broken drive root).
function Invoke-Scenario-S41 {
    $d = New-ScenarioDir 41
    'ki11-marker' | Set-Content -LiteralPath (Join-Path $d 'marker.txt') -Encoding ASCII
    $root = Get-DriveRootOf $d
    if (-not (Test-DriveRootGranted $root)) {
        return @{ Num=41; Name='S-41 (KI-1.1 PS gci)'; Passed=$true; Skipped=$true; DriveRootSkipped=$true
                  Detail="drive root '$root' not granted; run 'sandbox setup --grant-drive-root' (admin)" }
    }
    $cmd = "Get-ChildItem -LiteralPath ([Environment]::CurrentDirectory) | Select-Object -ExpandProperty Name"
    $r = Invoke-Sandbox -Args @('run','--allow-cwd','--','powershell','-NoProfile','-Command',$cmd) -WorkingDirectory $d
    $out = ($r.Stdout -join "`n")
    $passed = ($r.ExitCode -eq 0) -and ($out -match 'marker.txt')
    return @{ Num=41; Name='S-41 (KI-1.1 PS gci)'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { 'PS Get-ChildItem -LiteralPath cwd listed cwd' } else { "exit=$($r.ExitCode) stdout=$out" } }
}

# S-42: KI-1.1 regression guard — the drive-root grant must NOT weaken the
# sibling-isolation guarantee. Reading a sibling project's .env stays denied.
function Invoke-Scenario-S42 {
    $d = New-ScenarioDir 42
    $parent = Split-Path -Parent $d
    $other = Join-Path $parent 'other-project-42'
    if (-not (Test-Path -LiteralPath $other)) { New-Item -ItemType Directory -Path $other -Force | Out-Null }
    $envFile = Join-Path $other '.env'
    Set-Content -LiteralPath $envFile -Value 'DUMMY_SECRET=do-not-read' -Encoding ASCII
    $r = Invoke-Sandbox -Args @('run','--allow-cwd','--','cmd','/c','type','..\other-project-42\.env') -WorkingDirectory $d
    $err = ($r.Stderr -join "`n")
    $passed = ($r.ExitCode -ne 0) -and (Test-Denied $err)
    return @{ Num=42; Name='S-42 (KI-1.1 sibling)'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { 'sibling .env still denied (grant did not weaken isolation)' } else { "exit=$($r.ExitCode) stderr=$err" } }
}

# ---------------------------------------------------------------------------
# US-4a audit scenarios S-43 .. S-56
# ---------------------------------------------------------------------------

# S-43 (AC-4.1): two session ids in the same second are distinct + well-formed.
function Invoke-Scenario-S43 {
    $d = New-ScenarioDir 43
    $r1 = Invoke-Sandbox -Args @('run','--allow-cwd','--print-sid','--','cmd','/c','echo','a') -WorkingDirectory $d
    $r2 = Invoke-Sandbox -Args @('run','--allow-cwd','--print-sid','--','cmd','/c','echo','b') -WorkingDirectory $d
    $sid1 = ($r1.Stdout -join '').Trim()
    $sid2 = ($r2.Stdout -join '').Trim()
    $pattern = '^\d{8}-\d{6}-\d{5}$'
    $passed = ($r1.ExitCode -eq 0) -and ($r2.ExitCode -eq 0) -and ($sid1 -ne $sid2) -and ($sid1 -match $pattern) -and ($sid2 -match $pattern)
    return @{ Num=43; Name='S-43 (AC-4.1)'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { "distinct sids: $sid1, $sid2" } else { "sid1=$sid1 sid2=$sid2" } }
}

# S-44 (AC-4.2): audit log file is created and non-empty.
# Uses the two-step pattern: --print-sid to get the sid, then a real --sid run
# that emits a SESSION_START leaf. (The --print-sid-only path returns early
# before AuditWriter is created, so no log file is produced by step 1.)
function Invoke-Scenario-S44 {
    $d = New-ScenarioDir 44
    $psid = Invoke-Sandbox -Args @('run','--allow-cwd','--block-net','--print-sid','--','cmd','/c','echo','placeholder') -WorkingDirectory $d
    if ($psid.ExitCode -ne 0) { return @{ Num=44; Name='S-44 (AC-4.2)'; Passed=$false; Skipped=$false; Detail="print-sid failed" } }
    $sid = ($psid.Stdout -join '').Trim()
    # Now run the real session — this emits SESSION_START + commits the root.
    $r = Invoke-Sandbox -Args @('run','--allow-cwd','--block-net','--sid',$sid,'--','cmd','/c','echo','hi') -WorkingDirectory $d
    $logPath = Join-Path $env:LOCALAPPDATA "sandbox\audit\$sid.ndjson"
    $exists = Test-Path -LiteralPath $logPath
    $size = if ($exists) { (Get-Item -LiteralPath $logPath).Length } else { 0 }
    # SESSION_START leaf guarantees non-empty (size > 0).
    $passed = $exists -and ($size -gt 0)
    return @{ Num=44; Name='S-44 (AC-4.2)'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { "log exists: $logPath (size=$size)" } else { "no log at $logPath (exists=$exists size=$size)" } }
}

# S-45 (AC-4.3): each log line is a valid hash-chain leaf.
# Uses --block-net (no proxy needed) — the SESSION_START leaf exercises the
# hash-chain. No python dependency.
function Invoke-Scenario-S45 {
    $d = New-ScenarioDir 45
    $psid = Invoke-Sandbox -Args @('run','--allow-cwd','--block-net','--print-sid','--','cmd','/c','echo','placeholder') -WorkingDirectory $d
    if ($psid.ExitCode -ne 0) { return @{ Num=45; Name='S-45 (AC-4.3)'; Passed=$false; Skipped=$false; Detail='print-sid failed' } }
    $sid = ($psid.Stdout -join '').Trim()
    Invoke-Sandbox -Args @('run','--allow-cwd','--block-net','--sid',$sid,'--','cmd','/c','echo','hi') -WorkingDirectory $d | Out-Null
    $logPath = Join-Path $env:LOCALAPPDATA "sandbox\audit\$sid.ndjson"
    if (-not (Test-Path -LiteralPath $logPath)) { return @{ Num=45; Name='S-45 (AC-4.3)'; Passed=$false; Skipped=$false; Detail="no log at $logPath" } }
    $content = Get-Content -LiteralPath $logPath -Raw
    $lines = @($content.Trim() -split "`r?`n" | Where-Object { $_.Trim() })
    if ($lines.Count -eq 0) { return @{ Num=45; Name='S-45 (AC-4.3)'; Passed=$false; Skipped=$false; Detail='log is empty' } }
    # Parse each line; check fields, seq monotonic, parent linkage.
    # (Full hash recomputation is exercised by `audit verify` in S-47.)
    $prevHash = $null
    $ok = $true
    $detail = ''
    for ($i = 0; $i -lt $lines.Count; $i++) {
        try {
            $obj = $lines[$i] | ConvertFrom-Json
        } catch {
            $ok = $false; $detail = "line $i is not valid JSON"; break
        }
        if (-not ($obj.PSObject.Properties.Name -contains 'hash')) { $ok=$false; $detail="line $i missing hash"; break }
        if (-not ($obj.PSObject.Properties.Name -contains 'parent')) { $ok=$false; $detail="line $i missing parent"; break }
        if (-not ($obj.PSObject.Properties.Name -contains 'seq')) { $ok=$false; $detail="line $i missing seq"; break }
        if (-not ($obj.PSObject.Properties.Name -contains 'ts')) { $ok=$false; $detail="line $i missing ts"; break }
        if (-not ($obj.PSObject.Properties.Name -contains 'op')) { $ok=$false; $detail="line $i missing op"; break }
        if (-not ($obj.PSObject.Properties.Name -contains 'disposition')) { $ok=$false; $detail="line $i missing disposition"; break }
        if ($obj.seq -ne $i) { $ok=$false; $detail="line $i seq=$($obj.seq) expected $i"; break }
        if ($i -eq 0) {
            if ($null -ne $obj.parent) { $ok=$false; $detail="line 0 parent is not null"; break }
        } else {
            if ($obj.parent -ne $prevHash) { $ok=$false; $detail="line $i parent mismatch"; break }
        }
        $prevHash = $obj.hash
    }
    return @{ Num=45; Name='S-45 (AC-4.3)'; Passed=$ok; Skipped=$false; Detail=$detail }
}

# S-46 (AC-4.6): CONNECT events appear in the log.
# SKIP: under the US-3 loopback downgrade, --allow-domain is downgraded to
# --block-net and no proxy starts, so no CONNECT events are emitted. This
# scenario will be enabled when the US-3 loopback exemption lands (or when
# US-4b adds EXEC/FILE_* capture which would also exercise the audit chain).
function Invoke-Scenario-S46 {
    return @{ Num=46; Name='S-46 (AC-4.6)'; Passed=$false; Skipped=$true
        Detail='requires --allow-domain (US-3 loopback deferral)' }
}

# S-47 (AC-4.8): audit verify on a clean session prints OK.
function Invoke-Scenario-S47 {
    $d = New-ScenarioDir 47
    $psid = Invoke-Sandbox -Args @('run','--allow-cwd','--block-net','--print-sid','--','cmd','/c','echo','hi') -WorkingDirectory $d
    if ($psid.ExitCode -ne 0) { return @{ Num=47; Name='S-47 (AC-4.8)'; Passed=$false; Skipped=$false; Detail='print-sid failed' } }
    $sid = ($psid.Stdout -join '').Trim()
    $r = Invoke-Sandbox -Args @('run','--allow-cwd','--block-net','--sid',$sid,'--','cmd','/c','echo','hi') -WorkingDirectory $d
    $v = Invoke-Sandbox -Args @('audit','verify',$sid)
    $out = ($v.Stdout -join '')
    $passed = ($v.ExitCode -eq 0) -and ($out -match 'OK')
    return @{ Num=47; Name='S-47 (AC-4.8)'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { 'verify OK' } else { "exit=$($v.ExitCode) out=$out" } }
}

# S-48 (AC-4.9): flipped byte in log -> TAMPERED.
function Invoke-Scenario-S48 {
    $d = New-ScenarioDir 48
    $psid = Invoke-Sandbox -Args @('run','--allow-cwd','--block-net','--print-sid','--','cmd','/c','echo','hi') -WorkingDirectory $d
    $sid = ($psid.Stdout -join '').Trim()
    Invoke-Sandbox -Args @('run','--allow-cwd','--block-net','--sid',$sid,'--','cmd','/c','echo','hi') -WorkingDirectory $d | Out-Null
    $logPath = Join-Path $env:LOCALAPPDATA "sandbox\audit\$sid.ndjson"
    if (-not (Test-Path -LiteralPath $logPath)) { return @{ Num=48; Name='S-48 (AC-4.9)'; Passed=$false; Skipped=$false; Detail='no log to tamper' } }
    # Read, flip one byte in the middle, write back.
    $bytes = [System.IO.File]::ReadAllBytes($logPath)
    if ($bytes.Length -lt 10) { return @{ Num=48; Name='S-48 (AC-4.9)'; Passed=$false; Skipped=$false; Detail='log too short to tamper' } }
    $mid = [int]($bytes.Length / 2)
    # Find an alphabetic byte to flip so the JSON stays parseable but the
    # canonical hash changes. Flip case of a letter.
    for ($i = $mid; $i -lt $bytes.Length; $i++) {
        $b = $bytes[$i]
        if (($b -ge 97 -and $b -le 122) -or ($b -ge 65 -and $b -le 90)) {
            $bytes[$i] = $b -bxor 32  # flip case
            break
        }
    }
    [System.IO.File]::WriteAllBytes($logPath, $bytes)
    $v = Invoke-Sandbox -Args @('audit','verify',$sid)
    $out = ($v.Stdout -join '')
    $passed = ($v.ExitCode -ne 0) -and ($out -match 'TAMPERED')
    return @{ Num=48; Name='S-48 (AC-4.9)'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { 'tamper detected' } else { "exit=$($v.ExitCode) out=$out" } }
}

# S-49 (AC-4.10): truncated log -> TAMPERED (root mismatch).
# A --block-net session emits exactly one event (SESSION_START), so the log
# has a single line. Dropping that line yields an empty log, which verify
# reports as INCOMPLETE (no events). The tamper guarantee we care about is
# "removed leaf => root mismatch". With one leaf we can only test removal;
# verify then reports INCOMPLETE (acceptable: the committed root cannot be
# recomputed over zero events). We accept both TAMPERED and INCOMPLETE.
function Invoke-Scenario-S49 {
    $d = New-ScenarioDir 49
    $psid = Invoke-Sandbox -Args @('run','--allow-cwd','--block-net','--print-sid','--','cmd','/c','echo','hi') -WorkingDirectory $d
    $sid = ($psid.Stdout -join '').Trim()
    Invoke-Sandbox -Args @('run','--allow-cwd','--block-net','--sid',$sid,'--','cmd','/c','echo','hi') -WorkingDirectory $d | Out-Null
    $logPath = Join-Path $env:LOCALAPPDATA "sandbox\audit\$sid.ndjson"
    if (-not (Test-Path -LiteralPath $logPath)) { return @{ Num=49; Name='S-49 (AC-4.10)'; Passed=$false; Skipped=$false; Detail='no log to truncate' } }
    $content = Get-Content -LiteralPath $logPath -Raw
    $lines = @($content.Trim() -split "`r?`n" | Where-Object { $_.Trim() })
    if ($lines.Count -lt 2) {
        return @{ Num=49; Name='S-49 (AC-4.10)'; Passed=$false; Skipped=$true
            Detail="log has $($lines.Count) line(s); need >=2 to truncate-test (SESSION_START-only session). Enable with US-4b EXEC/FILE_* events." }
    }
    # Drop the last line.
    $truncated = ($lines[0..($lines.Count - 2)] -join "`n") + "`n"
    Set-Content -LiteralPath $logPath -Value $truncated -NoNewline
    $v = Invoke-Sandbox -Args @('audit','verify',$sid)
    $out = ($v.Stdout -join '')
    $passed = ($v.ExitCode -ne 0) -and ($out -match 'TAMPERED|INCOMPLETE')
    return @{ Num=49; Name='S-49 (AC-4.10)'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { 'truncation detected' } else { "exit=$($v.ExitCode) out=$out" } }
}

# S-50 (AC-4.11): forged .root file -> BAD_SIGNATURE or TAMPERED.
function Invoke-Scenario-S50 {
    $d = New-ScenarioDir 50
    $psid = Invoke-Sandbox -Args @('run','--allow-cwd','--block-net','--print-sid','--','cmd','/c','echo','hi') -WorkingDirectory $d
    $sid = ($psid.Stdout -join '').Trim()
    Invoke-Sandbox -Args @('run','--allow-cwd','--block-net','--sid',$sid,'--','cmd','/c','echo','hi') -WorkingDirectory $d | Out-Null
    $rootPath = Join-Path $env:LOCALAPPDATA "sandbox\audit\$sid.root"
    # Replace with a different (well-formatted) 64-char hex root.
    $forged = '0' * 64
    Set-Content -LiteralPath $rootPath -Value $forged -NoNewline
    $v = Invoke-Sandbox -Args @('audit','verify',$sid)
    $out = ($v.Stdout -join '')
    $passed = ($v.ExitCode -ne 0) -and ($out -match 'TAMPERED|BAD_SIGNATURE')
    return @{ Num=50; Name='S-50 (AC-4.11)'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { 'forged root detected' } else { "exit=$($v.ExitCode) out=$out" } }
}

# S-51 (AC-4.12): human-readable summary has expected sections.
function Invoke-Scenario-S51 {
    $d = New-ScenarioDir 51
    $psid = Invoke-Sandbox -Args @('run','--allow-cwd','--block-net','--print-sid','--','cmd','/c','echo','hi') -WorkingDirectory $d
    $sid = ($psid.Stdout -join '').Trim()
    Invoke-Sandbox -Args @('run','--allow-cwd','--block-net','--sid',$sid,'--','cmd','/c','echo','hi') -WorkingDirectory $d | Out-Null
    $s = Invoke-Sandbox -Args @('audit','show',$sid)
    $out = ($s.Stdout -join "`n")
    $hasSession = $out -match 'Session \d{8}-\d{6}-\d{5}'
    $hasEventsByType = $out -match 'Events by type'
    $hasTotalEvents = $out -match 'Total events'
    $passed = $hasSession -and $hasEventsByType -and $hasTotalEvents
    return @{ Num=51; Name='S-51 (AC-4.12)'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { 'summary has all sections' } else { "session=$hasSession bytype=$hasEventsByType total=$hasTotalEvents" } }
}

# S-52 (AC-4.13): --filter narrows output.
# Uses SESSION_START (always emitted) instead of CONNECT (which requires the
# US-3 loopback exemption). Filters to op=SESSION_START and checks every
# emitted line matches.
function Invoke-Scenario-S52 {
    $d = New-ScenarioDir 52
    $psid = Invoke-Sandbox -Args @('run','--allow-cwd','--block-net','--print-sid','--','cmd','/c','echo','placeholder') -WorkingDirectory $d
    if ($psid.ExitCode -ne 0) { return @{ Num=52; Name='S-52 (AC-4.13)'; Passed=$false; Skipped=$false; Detail='print-sid failed' } }
    $sid = ($psid.Stdout -join '').Trim()
    Invoke-Sandbox -Args @('run','--allow-cwd','--block-net','--sid',$sid,'--','cmd','/c','echo','hi') -WorkingDirectory $d | Out-Null
    $sj = Invoke-Sandbox -Args @('audit','show',$sid,'--json','--filter','op=SESSION_START')
    $jlines = @($sj.Stdout | Where-Object { $_.Trim() })
    $allMatch = $true
    foreach ($l in $jlines) {
        try { $o = $l | ConvertFrom-Json; if ($o.op -ne 'SESSION_START') { $allMatch = $false; break } } catch { $allMatch = $false; break }
    }
    $passed = ($jlines.Count -gt 0) -and $allMatch
    return @{ Num=52; Name='S-52 (AC-4.13)'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { "filtered to $($jlines.Count) SESSION_START events" } else { "lines=$($jlines.Count) allMatch=$allMatch" } }
}

# S-53 (AC-4.14): first-run key generation.
function Invoke-Scenario-S53 {
    $keyPath = Join-Path $env:LOCALAPPDATA "sandbox\signing\ed25519-key"
    $existedBefore = Test-Path -LiteralPath $keyPath
    $d = New-ScenarioDir 53
    $psid = Invoke-Sandbox -Args @('run','--allow-cwd','--block-net','--print-sid','--','cmd','/c','echo','hi') -WorkingDirectory $d
    $sid = ($psid.Stdout -join '').Trim()
    Invoke-Sandbox -Args @('run','--allow-cwd','--block-net','--sid',$sid,'--','cmd','/c','echo','hi') -WorkingDirectory $d | Out-Null
    $existsNow = Test-Path -LiteralPath $keyPath
    $v = Invoke-Sandbox -Args @('audit','verify',$sid)
    $verifyOk = ($v.ExitCode -eq 0) -and (($v.Stdout -join '') -match 'OK')
    $passed = $existsNow -and $verifyOk
    return @{ Num=53; Name='S-53 (AC-4.14)'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { 'key file present + verify OK' } else { "exists=$existsNow verify=$verifyOk (existed before: $existedBefore)" } }
}

# S-54 (AC-4.15): key file is DPAPI-encrypted (not a valid raw Ed25519 secret).
function Invoke-Scenario-S54 {
    $keyPath = Join-Path $env:LOCALAPPDATA "sandbox\signing\ed25519-key"
    if (-not (Test-Path -LiteralPath $keyPath)) { return @{ Num=54; Name='S-54 (AC-4.15)'; Passed=$false; Skipped=$false; Detail='no key file (run S-53 first)' } }
    $bytes = [System.IO.File]::ReadAllBytes($keyPath)
    # A raw Ed25519 secret is exactly 32 bytes. DPAPI ciphertext is longer
    # (has a header + padding). If the file is exactly 32 bytes, it's NOT
    # DPAPI-encrypted.
    $isDpapi = $bytes.Length -gt 32
    $passed = $isDpapi
    return @{ Num=54; Name='S-54 (AC-4.15)'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { "key file is $($bytes.Length) bytes (DPAPI ciphertext, not raw secret)" } else { "key file is $($bytes.Length) bytes (suspicious — looks raw)" } }
}

# S-55 (AC-4.17): audit log survives sandbox crash; verify reports INCOMPLETE.
# Uses `powershell -NoProfile -Command Start-Sleep` as the long-running child
# because `ping` is blocked by --block-net (it needs the IP driver even for
# 127.0.0.1) and `timeout /t` requires console input redirection (not
# available under the sandbox's piped stdio). PowerShell's Start-Sleep needs
# no network and no console input.
function Invoke-Scenario-S55 {
    $d = New-ScenarioDir 55
    $psid = Invoke-Sandbox -Args @('run','--allow-cwd','--block-net','--print-sid','--','cmd','/c','echo','hi') -WorkingDirectory $d
    $sid = ($psid.Stdout -join '').Trim()
    # Start a long-running session. The child sleeps 30s; we kill the sandbox
    # supervisor after 2s, before the child exits naturally.
    $proc = Start-Process -FilePath $SandboxExe -ArgumentList @('run','--allow-cwd','--block-net','--sid',$sid,'--','powershell','-NoProfile','-Command','Start-Sleep -Seconds 30') -WorkingDirectory $d -PassThru -NoNewWindow
    Start-Sleep -Seconds 2
    if ($proc.HasExited) {
        Get-Process powershell -ErrorAction SilentlyContinue | Where-Object { $_.Path -like '*WindowsPowerShell*' } | Stop-Process -Force -ErrorAction SilentlyContinue
        return @{ Num=55; Name='S-55 (AC-4.17)'; Passed=$false; Skipped=$false; Detail="sandbox exited early (exit=$($proc.ExitCode)); child did not stay alive" }
    }
    # Force-kill sandbox.exe (the supervisor), not the child. The Job
    # Object's KILL_ON_JOB_CLOSE will then kill the powershell child.
    Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    $logPath = Join-Path $env:LOCALAPPDATA "sandbox\audit\$sid.ndjson"
    $rootPath = Join-Path $env:LOCALAPPDATA "sandbox\audit\$sid.root"
    $logReadable = Test-Path -LiteralPath $logPath
    $noRoot = -not (Test-Path -LiteralPath $rootPath)
    $v = Invoke-Sandbox -Args @('audit','verify',$sid)
    $out = ($v.Stdout -join '')
    $incomplete = $out -match 'INCOMPLETE'
    # Also check that audit show still works.
    $s = Invoke-Sandbox -Args @('audit','show',$sid)
    $showWorks = $s.ExitCode -eq 0
    $passed = $logReadable -and $noRoot -and $incomplete -and $showWorks
    # Cleanup any orphaned powershell child (defensive — the Job Object should
    # have killed it, but be safe).
    Get-Process powershell -ErrorAction SilentlyContinue | Where-Object { $_.Path -like '*WindowsPowerShell*' } | Stop-Process -Force -ErrorAction SilentlyContinue
    return @{ Num=55; Name='S-55 (AC-4.17)'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { 'crash -> INCOMPLETE, log readable' } else { "log=$logReadable noRoot=$noRoot incomplete=$incomplete show=$showWorks" } }
}

# S-56 (AC-4.16): DEFERRED to US-4b.
function Invoke-Scenario-S56 {
    return @{ Num=56; Name='S-56 (AC-4.16)'; Passed=$false; Skipped=$true; Detail='deferred to US-4b (audit fidelity reporting)' }
}

# S-57 (AC-5.16): unsupported schema_version is rejected with a clear message.
function Invoke-Scenario-S57 {
    $d = New-ScenarioDir 57
    $profileDir = Join-Path $d 'profiles'
    New-Item -ItemType Directory -Path $profileDir -Force | Out-Null
    $profilePath = Join-Path $profileDir 'bad-schema.json'
    $profileJson = '{"meta":{"name":"bad","schema_version":99},"filesystem":{"allow":["$CWD"]}}'
    Set-Content -LiteralPath $profilePath -Value $profileJson -Encoding UTF8
    $r = Invoke-Sandbox -Args @('run','--profile',$profilePath,'--','cmd','/c','echo','x') -WorkingDirectory $d
    $err = ($r.Stderr -join "`n")
    $passed = ($r.ExitCode -ne 0) -and ($err -match 'Unsupported profile schema version 99') -and ($err -match 'supports schema version 1')
    return @{ Num=57; Name='S-57 (AC-5.16)'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { 'unsupported schema_version rejected' } else { "exit=$($r.ExitCode) stderr=$err" } }
}

# S-58 (AC-5.12): wrong-type field is rejected with line/col pointer.
function Invoke-Scenario-S58 {
    $d = New-ScenarioDir 58
    $profileDir = Join-Path $d 'profiles'
    New-Item -ItemType Directory -Path $profileDir -Force | Out-Null
    $profilePath = Join-Path $profileDir 'bad-type.json'
    $profileJson = '{"meta":{"name":"x","schema_version":1},"filesystem":{"allow":42}}'
    Set-Content -LiteralPath $profilePath -Value $profileJson -Encoding UTF8
    $r = Invoke-Sandbox -Args @('run','--profile',$profilePath,'--','cmd','/c','echo','x') -WorkingDirectory $d
    $err = ($r.Stderr -join "`n")
    $passed = ($r.ExitCode -ne 0) -and ($err -match 'expected a sequence' -or $err -match 'integer') -and ($err -match 'line' -or $err -match 'col')
    return @{ Num=58; Name='S-58 (AC-5.12)'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { 'wrong-type rejected with line/col' } else { "exit=$($r.ExitCode) stderr=$err" } }
}

# S-59 (AC-5.13): unknown key rejected with "Did you mean" suggestion.
function Invoke-Scenario-S59 {
    $d = New-ScenarioDir 59
    $profileDir = Join-Path $d 'profiles'
    New-Item -ItemType Directory -Path $profileDir -Force | Out-Null
    $profilePath = Join-Path $profileDir 'typo.json'
    $profileJson = '{"meta":{"name":"x","schema_version":1},"netwrok":{"block":false}}'
    Set-Content -LiteralPath $profilePath -Value $profileJson -Encoding UTF8
    $r = Invoke-Sandbox -Args @('run','--profile',$profilePath,'--','cmd','/c','echo','x') -WorkingDirectory $d
    $err = ($r.Stderr -join "`n")
    $passed = ($r.ExitCode -ne 0) -and ($err -match 'netwrok') -and ($err -match 'Did you mean .network.')
    return @{ Num=59; Name='S-59 (AC-5.13)'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { 'unknown key + suggestion' } else { "exit=$($r.ExitCode) stderr=$err" } }
}

# ---------------------------------------------------------------------------
# Dispatcher + main
# ---------------------------------------------------------------------------
$script:Scenarios = @(
    { Invoke-Scenario-S1 },  { Invoke-Scenario-S2 },  { Invoke-Scenario-S3 },
    { Invoke-Scenario-S4 },  { Invoke-Scenario-S5 },  { Invoke-Scenario-S6 },
    { Invoke-Scenario-S7 },  { Invoke-Scenario-S8 },  { Invoke-Scenario-S9 },
    { Invoke-Scenario-S10 }, { Invoke-Scenario-S11 }, { Invoke-Scenario-S12 },
    { Invoke-Scenario-S13 }, { Invoke-Scenario-S14 }, { Invoke-Scenario-S15 },
    { Invoke-Scenario-S16 }, { Invoke-Scenario-S17 }, { Invoke-Scenario-S18 },
    { Invoke-Scenario-S19 }, { Invoke-Scenario-S20 }, { Invoke-Scenario-S21 },
    { Invoke-Scenario-S22 }, { Invoke-Scenario-S23 }, { Invoke-Scenario-S24 },
    { Invoke-Scenario-S25 }, { Invoke-Scenario-S26 }, { Invoke-Scenario-S27 },
    { Invoke-Scenario-S28 }, { Invoke-Scenario-S29 }, { Invoke-Scenario-S30 },
    { Invoke-Scenario-S31 }, { Invoke-Scenario-S32 }, { Invoke-Scenario-S33 },
    { Invoke-Scenario-S34 }, { Invoke-Scenario-S35 }, { Invoke-Scenario-S36 },
    { Invoke-Scenario-S37 }, { Invoke-Scenario-S38 }, { Invoke-Scenario-S39 },
    { Invoke-Scenario-S40 }, { Invoke-Scenario-S41 }, { Invoke-Scenario-S42 },
    { Invoke-Scenario-S43 }, { Invoke-Scenario-S44 }, { Invoke-Scenario-S45 },
    { Invoke-Scenario-S46 }, { Invoke-Scenario-S47 }, { Invoke-Scenario-S48 },
    { Invoke-Scenario-S49 }, { Invoke-Scenario-S50 }, { Invoke-Scenario-S51 },
    { Invoke-Scenario-S52 }, { Invoke-Scenario-S53 }, { Invoke-Scenario-S54 },
    { Invoke-Scenario-S55 }, { Invoke-Scenario-S56 }, { Invoke-Scenario-S57 },
    { Invoke-Scenario-S58 }, { Invoke-Scenario-S59 }
)

function Invoke-Scenario { param([int]$Number)
    if ($Number -lt 1 -or $Number -gt $script:Scenarios.Count) { return $null }
    return & $script:Scenarios[$Number - 1]
}

function Select-ScenarioNumbers {
    $nums = 1..$script:Scenarios.Count
    if ($Only -and $Only.Count -gt 0) { $nums = $nums | Where-Object { $Only -contains $_ } }
    if ($Skip -and $Skip.Count -gt 0) { $nums = $nums | Where-Object { $Skip -notcontains $_ } }
    return $nums
}

function Main {
    Write-Host "sandbox test harness" -ForegroundColor White
    Write-Host "  SandboxExe : $SandboxExe"
    Write-Host "  Cwd        : $script:Cwd"
    Write-Host "  Keep       : $Keep"
    Write-Host ""

    $nums = Select-ScenarioNumbers
    if (-not $nums -or $nums.Count -eq 0) {
        Write-Host "[info] no scenarios matched; nothing to do." -ForegroundColor Yellow
        if ($script:OwnsCwd -and -not $Keep) { Remove-Item -LiteralPath $script:TempCwd -Recurse -Force -ErrorAction SilentlyContinue }
        return 0
    }

    $results = New-Object System.Collections.Generic.List[hashtable]
    foreach ($n in $nums) {
        $r = Invoke-Scenario -Number $n
        $r = ConvertTo-Result $r
        $results.Add($r)
        Write-Result $r
        if ($StopOnFail -and $r.State -eq 'fail') { Write-Host "[stop] -StopOnFail set; halting after S-$($r.Num)." -ForegroundColor Red; break }
    }

    $total = $results.Count
    $pass  = ($results | Where-Object { $_.State -eq 'pass' }).Count
    $fail  = ($results | Where-Object { $_.State -eq 'fail' }).Count
    $skip  = ($results | Where-Object { $_.State -eq 'skip' }).Count
    Write-Host ""
    Write-Host ("Summary: total={0} pass={1} fail={2} skip={3}" -f $total,$pass,$fail,$skip) -ForegroundColor White

    $gateFailed = $false
    foreach ($r in $results) { if ($r.IsGate -and $r.State -eq 'fail') { $gateFailed = $true } }
    if ($gateFailed) {
        Write-Host "SANDBOX: FAIL (gate test S-6 failed)" -ForegroundColor Red
    } else {
        $required = 1,2,3,4,5,6,7,10,11,12,13,16,17,18,21,24,35,42
        $hardFail = $false
        foreach ($n in $required) {
            $r = $results | Where-Object { $_.Num -eq $n } | Select-Object -First 1
            if ($r -and $r.State -eq 'fail') { $hardFail = $true }
        }
        $pythonSkipped = ($results | Where-Object { $_.PythonSkipped }).Count -gt 0
        if ($hardFail) { Write-Host "SANDBOX: FAIL" -ForegroundColor Red }
        elseif ($pythonSkipped) { Write-Host "SANDBOX: PASS (python scenarios skipped)" -ForegroundColor Yellow }
        else { Write-Host "SANDBOX: PASS" -ForegroundColor Green }
    }

    if ($script:OwnsCwd -and -not $Keep) { Remove-Item -LiteralPath $script:TempCwd -Recurse -Force -ErrorAction SilentlyContinue }
    if ($Strict -and $skip -gt 0) { return 1 }
    if ($gateFailed -or ($results | Where-Object { $_.State -eq 'fail' }).Count -gt 0) { return 1 }
    return 0
}

$rc = Main
exit $rc
