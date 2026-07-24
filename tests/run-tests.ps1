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

# S-12: breakaway blocked (SKIP — needs helper binary).
function Invoke-Scenario-S12 {
    return @{ Num=12; Name='S-12'; Passed=$true; Skipped=$true; Detail='deferred - requires breakaway helper binary' }
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
        meta = @{ name = 'test'; version = '1.0.0'; description = 'test profile' }
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

# ---------------------------------------------------------------------------
# Dispatcher + main
# ---------------------------------------------------------------------------
$script:Scenarios = @(
    { Invoke-Scenario-S1 },  { Invoke-Scenario-S2 },  { Invoke-Scenario-S3 },
    { Invoke-Scenario-S4 },  { Invoke-Scenario-S5 },  { Invoke-Scenario-S6 },
    { Invoke-Scenario-S7 },  { Invoke-Scenario-S8 },  { Invoke-Scenario-S9 },
    { Invoke-Scenario-S10 }, { Invoke-Scenario-S11 }, { Invoke-Scenario-S12 },
    { Invoke-Scenario-S13 }, { Invoke-Scenario-S14 }, { Invoke-Scenario-S15 },
    { Invoke-Scenario-S16 }, { Invoke-Scenario-S17 }, { Invoke-Scenario-S18 }
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
        $required = 1,2,3,4,5,6,7,10,11,13,16,17,18
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
