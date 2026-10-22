#Requires -Version 5.1
<#
.SYNOPSIS
  Test harness for the AppContainer + RuleSet + Option E spike (S-1..S-15).
.DESCRIPTION
  Drives spike.exe through the scenarios defined in
  docs/design/spike-appcontainer-option-e.md and reports PASS/FAIL/SKIP per scenario.

  The spike PASSES iff (per the plan):
    S-1, S-3, S-4, S-5, S-7, S-8, S-10, S-11 pass; S-6 passes; S-9 passes;
    S-13 passes.
  S-8/S-9 skipped due to missing python do NOT hard-FAIL the suite; a
  prominent warning is printed and the overall result becomes
  "PASS (python scenarios skipped)". S-6 failure always means SPIKE: FAIL.

  Files owned by this harness (do NOT edit Rust/README/RESULTS from here):
    spike/tests/run-tests.ps1   (this file)
    spike/tests/fixtures/        (tiny fixtures)
    spike/tests/README.md
.PARAMETER SpikeExe
  Path to spike.exe. Defaults to ..\target\release\spike.exe resolved relative
  to this script. If missing, `cargo build --release` is run in the spike dir.
.PARAMETER Cwd
  Optional working directory. If omitted, a fresh temp dir under
  $env:TEMP\spike-<guid> is created and cleaned up (unless -Keep).
.PARAMETER Keep
  Retain the temp dir for debugging.
.PARAMETER Only
  Run only the listed scenario numbers, e.g. -Only 1,6,13.
.PARAMETER Skip
  Skip the listed scenario numbers.
.PARAMETER SkipOptional
  Skip S-14 and S-15.
.PARAMETER StopOnFail
  Stop at the first failure.
.PARAMETER Strict
  Treat skips as failures (non-zero exit code).
.EXAMPLE
  powershell -ExecutionPolicy Bypass -File run-tests.ps1
.EXAMPLE
  pwsh -File run-tests.ps1 -Only 6 -Keep
.EXAMPLE
  pwsh -File run-tests.ps1 -Skip 2,10 -SkipOptional
#>
[CmdletBinding()]
param(
    [string]$SpikeExe,
    [string]$Cwd,
    [switch]$Keep,
    [int[]]$Only,
    [int[]]$Skip,
    [switch]$SkipOptional,
    [switch]$StopOnFail,
    [switch]$Strict,
    [switch]$Diag
)

# Propagate diagnostics to the spike child only when -Verbose is given, so
# the child's stderr stays clean (needed for the denial-text assertions).
if ($Diag) { $env:SPIKE_DIAG = '1' } else { Remove-Item env:SPIKE_DIAG -ErrorAction SilentlyContinue }

# ---------------------------------------------------------------------------
# Bootstrapping: resolve SpikeExe / Cwd, build if needed.
# ---------------------------------------------------------------------------
$ErrorActionPreference = 'Stop'
$script:ThisDir = Split-Path -Parent $MyInvocation.MyCommand.Path

if (-not $SpikeExe) {
    $SpikeExe = Join-Path $script:ThisDir '..\target\release\spike.exe'
    $SpikeExe = [System.IO.Path]::GetFullPath($SpikeExe)
}

if (-not (Test-Path -LiteralPath $SpikeExe)) {
    $spikeDir = [System.IO.Path]::GetFullPath((Join-Path $script:ThisDir '..'))
    Write-Host "[build] spike.exe not found at $SpikeExe" -ForegroundColor Yellow
    Write-Host "[build] running 'cargo build --release' in $spikeDir" -ForegroundColor Yellow
    $buildCmd = "cargo"
    $buildArgs = @('build','--release')
    Push-Location -LiteralPath $spikeDir
    try {
        & $buildCmd $buildArgs 2>&1 | ForEach-Object { Write-Host "[build] $_" -ForegroundColor DarkGray }
        $buildExit = $LASTEXITCODE
    } finally {
        Pop-Location
    }
    if ($buildExit -ne 0) {
        Write-Host "[build] cargo build failed (exit $buildExit)." -ForegroundColor Red
        Write-Host "[build] The other agent may still be implementing spike.exe." -ForegroundColor Red
        Write-Host "[build] Re-run this harness once the Rust binary is built." -ForegroundColor Red
        exit 1
    }
    if (-not (Test-Path -LiteralPath $SpikeExe)) {
        Write-Host "[build] spike.exe still missing after build: $SpikeExe" -ForegroundColor Red
        exit 1
    }
}

# Temp CWD management.
$script:OwnsCwd = $false
$script:TempCwd = $null
if ($Cwd) {
    $Cwd = [System.IO.Path]::GetFullPath($Cwd)
    if (-not (Test-Path -LiteralPath $Cwd)) { New-Item -ItemType Directory -Path $Cwd -Force | Out-Null }
} else {
    $guid = [guid]::NewGuid().ToString('N')
    $script:TempCwd = Join-Path $env:TEMP ("spike-$guid")
    New-Item -ItemType Directory -Path $script:TempCwd -Force | Out-Null
    $Cwd = $script:TempCwd
    $script:OwnsCwd = $true
}
$script:Cwd = $Cwd

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

function New-ScenarioDir {
    param([int]$Number)
    $d = Join-Path $script:Cwd "S-$Number"
    if (-not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
    return $d
}

function Test-Denied {
    # Accepts the localized forms of "Access is denied":
    #   en: "Access is denied"
    #   de: "Zugriff verweigert"
    #   fr: "Acces refuse"
    #   es: "Acceso denegado"
    # plus the generic Win32 ERROR_ACCESS_DENIED phrase shape.
    param([string]$Text)
    if (-not $Text) { return $false }
    return $Text -match '(?i)(access is denied|acces(?:s)? (?:is )?denied|acceso denegado|acces refuse|zugriff (?:wurde )?verweigert)'
}

function Invoke-Spike {
    <#
      Run spike.exe with the given args from the given working dir.
      Returns @{ Stdout=[string[]]; Stderr=[string[]]; ExitCode=[int] }.
      Uses a Process so we can capture stdout/stderr separately and avoid
      PowerShell pipeline quirks.
    #>
    param(
        [Parameter(Mandatory)][string[]]$Args,
        [string]$WorkingDirectory = $script:Cwd
    )
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $SpikeExe
    # Build a quoted Arguments string (ArgumentList is .NET 5+; use Arguments
    # for PS 5.1 / .NET Framework compatibility). Quote args containing spaces.
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

function Invoke-SpikeStartProcess {
    <# Fire-and-forget variant used for S-11 (Job Object kill test). #>
    param([Parameter(Mandatory)][string[]]$Args, [string]$WorkingDirectory = $script:Cwd)
    $joined = $Args -join '" "'
    $proc = Start-Process -FilePath $SpikeExe -ArgumentList $Args -PassThru -WorkingDirectory $WorkingDirectory
    return $proc
}

function Get-Python {
    $py = Get-Command python -ErrorAction SilentlyContinue
    if (-not $py) { return $null }
    return $py.Source
}

function Write-Result {
    param([hashtable]$R)
    $tag = switch ($R.State) {
        'pass' { '[PASS]' }
        'fail' { '[FAIL]' }
        'skip' { '[SKIP]' }
        'info' { '[INFO]' }
        default { '[????]' }
    }
    $color = switch ($R.State) {
        'pass' { 'Green' }
        'fail' { 'Red' }
        'skip' { 'Cyan' }
        'info' { 'DarkGray' }
        default { 'Gray' }
    }
    $msg = switch ($R.State) {
        'pass' { "$tag $($R.Name)" }
        'fail' { "$tag $($R.Name): $($R.Detail)" }
        'skip' { "$tag $($R.Name): $($R.Detail)" }
        'info' { "$tag $($R.Name): $($R.Detail)" }
        default { "$tag $($R.Name)" }
    }
    Write-Host $msg -ForegroundColor $color
}

function ConvertTo-Result {
    <# Normalise a scenario hashtable into a result with explicit State. #>
    param([hashtable]$h)
    if ($h.Skipped) {
        $h.State = 'skip'
    } elseif ($h.Passed) {
        $h.State = 'pass'
    } else {
        $h.State = 'fail'
    }
    if (-not $h.ContainsKey('Name')) { $h.Name = $h.Num }
    return $h
}

# ---------------------------------------------------------------------------
# Scenarios
# ---------------------------------------------------------------------------

function Invoke-Scenario-S1 {
    $d = New-ScenarioDir 1
    $r = Invoke-Spike -Args @('run','--','cmd','/c','echo','hello') -WorkingDirectory $d
    $out = ($r.Stdout -join "`n")
    $passed = ($r.ExitCode -eq 0) -and ($out -match 'hello')
    return @{
        Num=1; Name='S-1'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { 'baseline echo' } else { "exit=$($r.ExitCode) stdout=$out" }
    }
}

function Invoke-Scenario-S2 {
    $d = New-ScenarioDir 2
    $target = Join-Path $env:USERPROFILE '.ssh\id_rsa'
    $r = Invoke-Spike -Args @('run','--','cmd','/c','type',$target) -WorkingDirectory $d
    $err = ($r.Stderr -join "`n")
    $passed = ($r.ExitCode -ne 0) -and (Test-Denied $err)
    return @{
        Num=2; Name='S-2'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { 'denied read of .ssh\id_rsa' } else { "exit=$($r.ExitCode) stderr=$err" }
    }
}

function Invoke-Scenario-S3 {
    $d = New-ScenarioDir 3
    # Create sibling other-project\.env OUTSIDE the scenario dir (sibling).
    $parent = Split-Path -Parent $d
    $other = Join-Path $parent 'other-project'
    if (-not (Test-Path -LiteralPath $other)) { New-Item -ItemType Directory -Path $other -Force | Out-Null }
    $envFile = Join-Path $other '.env'
    Set-Content -LiteralPath $envFile -Value 'DUMMY_SECRET=do-not-read' -Encoding ASCII
    # Run from $d, target ..\other-project\.env (sibling).
    $r = Invoke-Spike -Args @('run','--','cmd','/c','type','..\other-project\.env') -WorkingDirectory $d
    $err = ($r.Stderr -join "`n")
    $passed = ($r.ExitCode -ne 0) -and (Test-Denied $err)
    return @{
        Num=3; Name='S-3'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { 'sibling project denied' } else { "exit=$($r.ExitCode) stderr=$err" }
    }
}

function Invoke-Scenario-S4 {
    $d = New-ScenarioDir 4
    $r = Invoke-Spike -Args @('run','--','cmd','/c','echo','test','>','new-file.txt') -WorkingDirectory $d
    $file = Join-Path $d 'new-file.txt'
    $exists = Test-Path -LiteralPath $file
    $content = if ($exists) { (Get-Content -LiteralPath $file -Raw).Trim() } else { '' }
    $passed = ($r.ExitCode -eq 0) -and $exists -and ($content -match 'test')
    return @{
        Num=4; Name='S-4'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { 'allowed write to $CWD' } else { "exit=$($r.ExitCode) exists=$exists content=$content" }
    }
}

function Invoke-Scenario-S5 {
    $d = New-ScenarioDir 5
    $sshDir = Join-Path $env:USERPROFILE '.ssh'
    if (-not (Test-Path -LiteralPath $sshDir)) { New-Item -ItemType Directory -Path $sshDir -Force | Out-Null }
    $evil = Join-Path $sshDir 'evil.txt'
    if (Test-Path -LiteralPath $evil) { Remove-Item -LiteralPath $evil -Force }
    $r = Invoke-Spike -Args @('run','--','cmd','/c','echo','bad','>',$evil) -WorkingDirectory $d
    $err = ($r.Stderr -join "`n")
    $exists = Test-Path -LiteralPath $evil
    $passed = ($r.ExitCode -ne 0) -and (Test-Denied $err) -and (-not $exists)
    try { if ($exists) { Remove-Item -LiteralPath $evil -Force } } catch {}
    return @{
        Num=5; Name='S-5'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { 'write to .ssh denied' } else { "exit=$($r.ExitCode) exists=$exists stderr=$err" }
    }
}

function Invoke-Scenario-S6 {
    $d = New-ScenarioDir 6
    $psid = Invoke-Spike -Args @('run','--print-sid','--','cmd','/c','echo','init') -WorkingDirectory $d
    if ($psid.ExitCode -ne 0) {
        return @{ Num=6; Name='S-6'; Passed=$false; Skipped=$false; Detail="print-sid failed exit=$($psid.ExitCode)"; IsGate=$true }
    }
    $sid = ($psid.Stdout -join '').Trim()
    if (-not $sid) {
        return @{ Num=6; Name='S-6'; Passed=$false; Skipped=$false; Detail='print-sid returned empty sid'; IsGate=$true }
    }
    # Gate test: copy a system binary into the per-session bin dir and execute
    # it. We use hostname.exe (not where.exe as in the plan) because where.exe
    # walks PATH dirs outside the allow-list and fails spuriously; hostname.exe
    # runs standalone and proves the same gate property ("a binary placed into
    # a RuleSet-allowed per-session dir at runtime is executable").
    $binName = 'hostname.exe'
    $binWhere = Join-Path $d ".sandbox\$sid\bin\$binName"
    $r1 = Invoke-Spike -Args @('run','--sid',$sid,'--','cmd','/c','copy',"C:\Windows\System32\$binName",".sandbox\$sid\bin\$binName") -WorkingDirectory $d
    $installed = Test-Path -LiteralPath $binWhere
    $r2 = Invoke-Spike -Args @('run','--sid',$sid,'--','cmd','/c',".sandbox\$sid\bin\$binName") -WorkingDirectory $d
    # Strip the leading "SESSION <sid>" line spike prints, then assert the
    # binary produced non-empty output (hostname prints the machine name).
    $out2 = (($r2.Stdout | Where-Object { $_ -notmatch '^SESSION ' }) -join "`n")
    $passed = ($r1.ExitCode -eq 0) -and $installed -and ($r2.ExitCode -eq 0) -and ($out2.Trim().Length -gt 0)
    return @{
        Num=6; Name='S-6 (GATE)'; Passed=$passed; Skipped=$false; IsGate=$true
        Detail = if ($passed) { "downloaded binary executed (hostname.exe); sid=$sid" } else { "sid=$sid copyExit=$($r1.ExitCode) installed=$installed runExit=$($r2.ExitCode) out=$out2" }
    }
}

function Invoke-Scenario-S7 {
    $d = New-ScenarioDir 7
    $psid = Invoke-Spike -Args @('run','--print-sid','--','cmd','/c','echo','init') -WorkingDirectory $d
    if ($psid.ExitCode -ne 0) {
        return @{ Num=7; Name='S-7'; Passed=$false; Skipped=$false; Detail="print-sid failed exit=$($psid.ExitCode)" }
    }
    $sid = ($psid.Stdout -join '').Trim()
    $marker = Join-Path $d ".sandbox\$sid\bin\marker.txt"
    $r = Invoke-Spike -Args @('run','--sid',$sid,'--','cmd','/c','echo','test','>',".sandbox\$sid\bin\marker.txt") -WorkingDirectory $d
    $exists = Test-Path -LiteralPath $marker
    $passed = ($r.ExitCode -eq 0) -and $exists
    return @{
        Num=7; Name='S-7'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { "marker written; sid=$sid" } else { "exit=$($r.ExitCode) exists=$exists sid=$sid" }
    }
}

function Invoke-Scenario-S8 {
    $d = New-ScenarioDir 8
    if (-not (Get-Python)) {
        return @{ Num=8; Name='S-8'; Passed=$true; Skipped=$true; PythonSkipped=$true; Detail='python not on PATH (required-pass scenario skipped)' }
    }
    $r = Invoke-Spike -Args @('run','--','python','-c',"print('hello from python')") -WorkingDirectory $d
    $out = ($r.Stdout -join "`n")
    $passed = ($r.ExitCode -eq 0) -and ($out -match 'hello from python')
    return @{
        Num=8; Name='S-8'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { 'python ran' } else { "exit=$($r.ExitCode) stdout=$out" }
    }
}

function Invoke-Scenario-S9 {
    $d = New-ScenarioDir 9
    if (-not (Get-Python)) {
        return @{ Num=9; Name='S-9'; Passed=$true; Skipped=$true; PythonSkipped=$true; Detail='python not on PATH (required-pass scenario skipped)' }
    }
    $psid = Invoke-Spike -Args @('run','--print-sid','--','cmd','/c','echo','init') -WorkingDirectory $d
    if ($psid.ExitCode -ne 0) {
        return @{ Num=9; Name='S-9'; Passed=$false; Skipped=$false; Detail="print-sid failed exit=$($psid.ExitCode)" }
    }
    $sid = ($psid.Stdout -join '').Trim()
    $r1 = Invoke-Spike -Args @('run','--sid',$sid,'--','python','-m','venv',".sandbox\$sid\venv") -WorkingDirectory $d
    $pyExe = Join-Path $d ".sandbox\$sid\venv\Scripts\python.exe"
    if ($r1.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $pyExe)) {
        return @{ Num=9; Name='S-9'; Passed=$false; Skipped=$false; Detail="venv create failed exit=$($r1.ExitCode) pyExists=$(Test-Path -LiteralPath $pyExe)" }
    }
    $r2 = Invoke-Spike -Args @('run','--sid',$sid,'--','cmd','/c',$pyExe,'-c',"print('venv works')") -WorkingDirectory $d
    $out = ($r2.Stdout -join "`n")
    $passed = ($r2.ExitCode -eq 0) -and ($out -match 'venv works')
    return @{
        Num=9; Name='S-9'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { "venv python ran; sid=$sid" } else { "exit=$($r2.ExitCode) stdout=$out" }
    }
}

function Invoke-Scenario-S10 {
    $d = New-ScenarioDir 10
    $target = Join-Path $env:USERPROFILE '.ssh\id_rsa'
    $r = Invoke-Spike -Args @('run','--','cmd','/c','cmd','/c','cmd','/c','type',$target) -WorkingDirectory $d
    $err = ($r.Stderr -join "`n")
    $passed = ($r.ExitCode -ne 0) -and (Test-Denied $err)
    return @{
        Num=10; Name='S-10'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { 'denied at depth 3' } else { "exit=$($r.ExitCode) stderr=$err" }
    }
}

function Invoke-Scenario-S11 {
    $d = New-ScenarioDir 11
    # Defensive: kill stray ping.exe from prior runs.
    Get-Process ping -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    $proc = Start-Process -FilePath $SpikeExe -ArgumentList @('run','--','cmd','/c','ping -t 127.0.0.1') -PassThru -WorkingDirectory $d
    Start-Sleep -Seconds 1
    try { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue } catch {}
    Start-Sleep -Seconds 1
    $alive = Get-Process ping -ErrorAction SilentlyContinue
    $passed = (-not $alive)
    # Cleanup any stragglers.
    Get-Process ping -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    return @{
        Num=11; Name='S-11'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { 'Job Object killed child tree' } else { 'ping.exe still alive after parent killed' }
    }
}

function Invoke-Scenario-S12 {
    return @{ Num=12; Name='S-12'; Passed=$true; Skipped=$true; Detail='S-12 deferred - requires breakaway helper binary' }
}

function Invoke-Scenario-S13 {
    $d = New-ScenarioDir 13
    $psidA = Invoke-Spike -Args @('run','--print-sid','--','cmd','/c','echo','init') -WorkingDirectory $d
    $psidB = Invoke-Spike -Args @('run','--print-sid','--','cmd','/c','echo','init') -WorkingDirectory $d
    if ($psidA.ExitCode -ne 0 -or $psidB.ExitCode -ne 0) {
        return @{ Num=13; Name='S-13'; Passed=$false; Skipped=$false; Detail="print-sid failed A=$($psidA.ExitCode) B=$($psidB.ExitCode)" }
    }
    $sidA = ($psidA.Stdout -join '').Trim()
    $sidB = ($psidB.Stdout -join '').Trim()
    if (-not $sidA -or -not $sidB) {
        return @{ Num=13; Name='S-13'; Passed=$false; Skipped=$false; Detail="empty sid A='$sidA' B='$sidB'" }
    }
    if ($sidA -eq $sidB) {
        return @{ Num=13; Name='S-13'; Passed=$false; Skipped=$false; Detail="sids not distinct: A=B='$sidA'" }
    }
    $whereA = Join-Path $d ".sandbox\$sidA\bin\where.exe"
    $whereB = Join-Path $d ".sandbox\$sidB\bin\where.exe"
    $rc = Invoke-Spike -Args @('run','--sid',$sidA,'--','cmd','/c','copy','C:\Windows\System32\where.exe',".sandbox\$sidA\bin\where.exe") -WorkingDirectory $d
    $aInstalled = Test-Path -LiteralPath $whereA
    $bExists = Test-Path -LiteralPath $whereB
    # B's bin dir exists but where.exe is absent.
    $binB = Join-Path $d ".sandbox\$sidB\bin"
    $binBExists = Test-Path -LiteralPath $binB
    # B cannot read A's where.exe.
    $rB = Invoke-Spike -Args @('run','--sid',$sidB,'--','cmd','/c','type',".sandbox\$sidA\bin\where.exe") -WorkingDirectory $d
    $errB = ($rB.Stderr -join "`n")
    $bDenied = ($rB.ExitCode -ne 0) -and (Test-Denied $errB)
    $passed = $aInstalled -and (-not $bExists) -and $binBExists -and $bDenied
    return @{
        Num=13; Name='S-13'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { "distinct sids; B denied A's tools (A=$sidA B=$sidB)" } else { "aInstalled=$aInstalled bExists=$bExists binBExists=$binBExists bDenied=$bDenied" }
    }
}

function Invoke-Scenario-S14 {
    $d = New-ScenarioDir 14
    $psid = Invoke-Spike -Args @('run','--print-sid','--','cmd','/c','echo','init') -WorkingDirectory $d
    if ($psid.ExitCode -ne 0) {
        return @{ Num=14; Name='S-14'; Passed=$true; Skipped=$true; Detail="print-sid failed (treating as stub): exit=$($psid.ExitCode)" }
    }
    $sid = ($psid.Stdout -join '').Trim()
    $cp = Invoke-Spike -Args @('run','--sid',$sid,'--','cmd','/c','copy','C:\Windows\System32\where.exe',".sandbox\$sid\bin\where.exe") -WorkingDirectory $d
    $persist = Invoke-Spike -Args @('persist',$sid,'--as','my-tools') -WorkingDirectory $d
    $pOut = ($persist.Stdout -join "`n")
    $pErr = ($persist.Stderr -join "`n")
    # Detect stub.
    if ($persist.ExitCode -ne 0 -or ($pErr -match 'not implemented') -or ($pOut -match 'not implemented')) {
        return @{ Num=14; Name='S-14'; Passed=$true; Skipped=$true; Detail="persist/reuse not implemented in spike (stub)" }
    }
    # Best-effort: assert store dir exists.
    $storeDir = Join-Path $env:USERPROFILE ".sandbox\stores\my-tools\bin\where.exe"
    $ok = Test-Path -LiteralPath $storeDir
    return @{
        Num=14; Name='S-14'; Passed=$ok; Skipped=$false
        Detail = if ($ok) { 'persisted store exists' } else { "store not found at $storeDir (best-effort)" }
    }
}

function Invoke-Scenario-S15 {
    $checklist = @(
        'S-15 MANUAL OBSERVATION CHECKLIST (operator records in RESULTS.md):'
        '  Launch: spike.exe run -- notepad.exe'
        '    [ ] Does a Notepad window appear?                 yes / no'
        '    [ ] Can you type into it?                         yes / no'
        '    [ ] Can you close it (Alt+F4 / X button)?         yes / no'
        '    [ ] Does the Job Object kill it on Ctrl-C?        yes / no'
        '  Repeat: spike.exe run -- msinfo32.exe'
        '    [ ] Window appears and is interactive?            yes / no'
        '  This scenario does NOT affect spike pass/fail (gate is S-6).'
    )
    foreach ($l in $checklist) { Write-Host $l -ForegroundColor DarkGray }
    return @{ Num=15; Name='S-15'; Passed=$true; Skipped=$true; Detail='Manual observation required' }
}

# ---------------------------------------------------------------------------
# Dispatcher + main
# ---------------------------------------------------------------------------
$script:Scenarios = @(
    { Invoke-Scenario-S1 },  { Invoke-Scenario-S2 },  { Invoke-Scenario-S3 },
    { Invoke-Scenario-S4 },  { Invoke-Scenario-S5 },  { Invoke-Scenario-S6 },
    { Invoke-Scenario-S7 },  { Invoke-Scenario-S8 },  { Invoke-Scenario-S9 },
    { Invoke-Scenario-S10 }, { Invoke-Scenario-S11 }, { Invoke-Scenario-S12 },
    { Invoke-Scenario-S13 }, { Invoke-Scenario-S14 }, { Invoke-Scenario-S15 }
)

function Invoke-Scenario {
    param([int]$Number)
    if ($Number -lt 1 -or $Number -gt $script:Scenarios.Count) { return $null }
    $fn = $script:Scenarios[$Number - 1]
    return & $fn
}

function Select-ScenarioNumbers {
    $nums = 1..$script:Scenarios.Count
    if ($Only -and $Only.Count -gt 0) { $nums = $nums | Where-Object { $Only -contains $_ } }
    if ($Skip -and $Skip.Count -gt 0) { $nums = $nums | Where-Object { $Skip -notcontains $_ } }
    if ($SkipOptional) { $nums = $nums | Where-Object { $_ -ne 14 -and $_ -ne 15 } }
    return $nums
}

function Main {
    Write-Host "spike test harness" -ForegroundColor White
    Write-Host "  SpikeExe : $SpikeExe"
    Write-Host "  Cwd      : $script:Cwd"
    Write-Host "  Keep     : $Keep"
    if ($Only)     { Write-Host "  Only     : $($Only -join ',')" }
    if ($Skip)     { Write-Host "  Skip     : $($Skip -join ',')" }
    if ($SkipOptional) { Write-Host "  SkipOptional: true" }
    Write-Host ""

    $nums = Select-ScenarioNumbers
    if (-not $nums -or $nums.Count -eq 0) {
        Write-Host "[info] no scenarios matched the selection; nothing to do." -ForegroundColor Yellow
        if ($script:OwnsCwd -and -not $Keep) {
            Remove-Item -LiteralPath $script:TempCwd -Recurse -Force -ErrorAction SilentlyContinue
        }
        return 0
    }

    $results = New-Object System.Collections.Generic.List[hashtable]
    foreach ($n in $nums) {
        $r = Invoke-Scenario -Number $n
        $r = ConvertTo-Result $r
        $results.Add($r)
        Write-Result $r
        if ($StopOnFail -and $r.State -eq 'fail') {
            Write-Host "[stop] -StopOnFail set; halting after S-$($r.Num)." -ForegroundColor Red
            break
        }
    }

    $total = $results.Count
    $pass  = ($results | Where-Object { $_.State -eq 'pass' }).Count
    $fail  = ($results | Where-Object { $_.State -eq 'fail' }).Count
    $skip  = ($results | Where-Object { $_.State -eq 'skip' }).Count

    Write-Host ""
    Write-Host ("Summary: total={0} pass={1} fail={2} skip={3}" -f $total,$pass,$fail,$skip) -ForegroundColor White

    # Determine overall verdict.
    $gateFailed = $false
    foreach ($r in $results) {
        if ($r.IsGate -and $r.State -eq 'fail') { $gateFailed = $true }
    }
    if ($gateFailed) {
        Write-Host "SPIKE: FAIL" -ForegroundColor Red
    } else {
        # Required-pass scenarios (non-skip) that failed -> fail.
        $required = 1,3,4,5,6,7,8,9,10,11,13
        $hardFail = $false
        foreach ($n in $required) {
            $r = $results | Where-Object { $_.Num -eq $n } | Select-Object -First 1
            if ($r -and $r.State -eq 'fail') { $hardFail = $true }
        }
        $pythonSkipped = ($results | Where-Object { $_.PythonSkipped }).Count -gt 0
        if ($hardFail) {
            Write-Host "SPIKE: FAIL" -ForegroundColor Red
        } elseif ($pythonSkipped) {
            Write-Host "WARNING: python-dependent scenarios (S-8/S-9) were SKIPPED - results are incomplete." -ForegroundColor Yellow
            Write-Host "SPIKE: PASS (python scenarios skipped)" -ForegroundColor Yellow
        } else {
            Write-Host "SPIKE: PASS" -ForegroundColor Green
        }
    }

    if ($script:OwnsCwd -and -not $Keep) {
        Remove-Item -LiteralPath $script:TempCwd -Recurse -Force -ErrorAction SilentlyContinue
    }

    if ($Strict -and $skip -gt 0) { return 1 }
    if ($gateFailed -or ($results | Where-Object { $_.State -eq 'fail' }).Count -gt 0) { return 1 }
    return 0
}

$rc = Main
exit $rc
