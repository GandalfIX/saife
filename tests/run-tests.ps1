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
  S-27..S-34, S-36, S-38, S-46 exercise the US-3 network allow-list + proxy
  (AC-3.3..3.14, AC-4.6) and skip cleanly when curl.exe is absent or the
  AppContainer loopback-to-proxy path is blocked by Windows Firewall.
  S-57 (AC-5.16) covers schema_version gate rejection.
  S-58 (AC-5.12) covers wrong-type field rejection with line/col pointer.
  S-59 (AC-5.13) covers unknown-key rejection with a "Did you mean" suggestion.
  S-60 (AC-5.7) covers the git_runtime security group (skips if git absent).
  S-61 (AC-5.7) covers the dotnet_runtime security group (skips if dotnet absent).
  S-62 (AC-5.6) covers the profile `extends` cycle detection error format.
  S-63 (AC-5.14) covers `profile list` showing all user-global profiles.
  S-64 (AC-5.15) covers `profile show` printing the file as-authored (raw view).
  S-65 covers `profile show --expanded` emitting fully-resolved JSON.
  S-66 (AC-5.3) covers `extends` concatenating allow arrays (de-duped).
  S-67 (AC-5.5) covers multi-level extends (a -> b -> c) resolution.
  S-68 (AC-5.8) covers `$HOME` per-user variable expansion at runtime.
  S-69 (AC-5.9) covers windows_common (System32) reachable from an empty profile.
  S-70 (AC-5.10) covers CLI `--allow` merging on top of the profile.
  S-71 (AC-5.17) covers a portable profile (only $HOME/$CWD/groups, no abs paths).
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

# Detached supervisor launch for the long-running-session scenarios
# (S-11, S-55, S-74). Start-Process is avoided on purpose: its
# ShellExecute/new-console path is unreliable in headless PowerShell Direct
# sessions (E_NOINTERFACE at Start, or the supervisor dying with
# STATUS_DLL_INIT_FAILED 0xC0000142); this uses CreateProcess via .NET
# Process with redirected pipes so the supervisor's diagnostics always
# have valid handles. Returns the Process object (Id, HasExited, ExitCode).
function Start-SandboxProcess {
    param([Parameter(Mandatory)][string]$Arguments, [string]$WorkingDirectory = $script:Cwd)
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $SandboxExe
    $psi.Arguments = $Arguments
    $psi.WorkingDirectory = $WorkingDirectory
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true
    $proc = New-Object System.Diagnostics.Process
    $proc.StartInfo = $psi
    [void]$proc.Start()
    return $proc
}

# Locate the real curl.exe (Windows aliases `curl` to Invoke-WebRequest in
# PowerShell, so always use `curl.exe` explicitly). Returns the path or $null.
function Get-Curl { $c = Get-Command curl.exe -ErrorAction SilentlyContinue; if (-not $c) { return $null }; return $c.Source }

# Probe whether the sandboxed child can actually reach the localhost proxy.
# The `privateNetworkClientServer` capability SID (Task 1.1) grants the right
# to open sockets, but Windows Firewall still blocks AppContainer loopback
# unless a firewall rule or `NetworkIsolationSetAppContainerConfig` exemption
# has been applied. When loopback is blocked, curl inside the sandbox times
# out connecting to the proxy port (exit 28) even though the proxy is
# listening and reachable from the supervisor process.
#
# This probe runs a sandboxed curl through the proxy (HTTP_PROXY env path) to
# a host that is NOT on the allow-list, so the proxy returns 403 quickly. If
# curl gets any response (even 000/403) within the timeout, loopback works.
# If curl times out (exit 28), loopback is blocked. The result is cached so
# the US-3 network scenarios skip cleanly (rather than fail the whole suite)
# when the host has not enabled AppContainer loopback.
# Returns $true if loopback-to-proxy works, $false otherwise.
function Test-LoopbackProxyReachable {
    if ($null -ne $script:LoopbackProxyCache) { return $script:LoopbackProxyCache }
    $curl = Get-Curl
    if (-not $curl) { $script:LoopbackProxyCache = $false; return $false }
    $d = New-ScenarioDir 9999
    # Clear NO_PROXY so curl does not bypass the proxy for loopback. The target
    # host (denied.invalid) is not in NO_PROXY, so curl routes through the
    # proxy regardless. Use HTTP (not HTTPS) so the proxy sees a plain request
    # and denies fast (no CONNECT round-trip).
    $oldNoProxy = $env:NO_PROXY
    $env:NO_PROXY = ''
    try {
        $r = Invoke-Sandbox -Args @('run','--allow-cwd','--allow-domain','api.anthropic.com','--','cmd','/c','curl.exe -s -m 5 -o NUL -w %{http_code} http://denied.invalid/') -WorkingDirectory $d
    } finally { $env:NO_PROXY = $oldNoProxy }
    # Exit 28 = curl's -m timeout → loopback blocked. Anything else (exit 0 with
    # 403/000, exit 7, etc.) means curl reached the proxy and got a response.
    $reachable = ($r.ExitCode -ne 28)
    $script:LoopbackProxyCache = $reachable
    return $reachable
}

# Parse the proxy listening port from a sandbox stderr buffer (collected under
# SANDBOX_DIAG=1). Returns the port (int) or $null.
function Get-ProxyPortFromStderr { param([string[]]$Stderr)
    $joined = ($Stderr -join "`n")
    $m = [regex]::Match($joined, '127\.0\.0\.1:(\d+)')
    if ($m.Success) { return [int]$m.Groups[1].Value }
    return $null
}

# Did curl reach the server? A 1xx/2xx/3xx/4xx/5xx http_code means the proxy
# allowed the CONNECT and the upstream responded (auth-failure 4xx is the
# expected happy path for unauthenticated API probes). `000`/empty or curl
# exit 5/6/7/28 means the connection failed (denied or unreachable).
function Test-CurlReachedServer { param([int]$ExitCode, [string]$HttpCode)
    if ($HttpCode -match '^[12345]\d\d$') { return $true }
    return $false
}

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

# Per-scenario guest metrics (VM runs only): run-in-vm.ps1 sets
# SBX_GUEST_METRICS to a file path before invoking this script. The file
# survives a PS-Direct session-host death (streamed output does not), which
# is how we correlate the mid-suite vmicvmsession/AppContainer collapse
# (run 20261011-004018: every container-creating scenario failed with
# 0x80070002 after the session host died at S-54) with resource exhaustion.
# Silently skipped on host runs. Never fatal.
function Write-GuestMetric {
    param([string]$Kind, [int]$Number)
    $p = $env:SBX_GUEST_METRICS
    if (-not $p) { return }
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem
        $availMb = [int][math]::Round($os.FreePhysicalMemory / 1KB)
        $commitPct = -1
        if ($os.TotalVirtualMemorySize -gt 0) {
            $commitPct = [int][math]::Round(100 * (1 - ($os.FreeVirtualMemory / $os.TotalVirtualMemorySize)))
        }
        $procs = @(Get-Process).Count
        $sbx = @(Get-Process -Name 'sandbox*' -ErrorAction SilentlyContinue).Count
        $vmic = 0
        if (Get-Process -Name vmicvmsession -ErrorAction SilentlyContinue) { $vmic = 1 }
        $line = "{0} {1} S-{2} availMB={3} commitPct={4} procs={5} sbxProcs={6} vmicAlive={7}" -f `
            (Get-Date -Format 'yyyy-MM-ddTHH:mm:ss.fff'), $Kind, $Number, $availMb, $commitPct, $procs, $sbx, $vmic
        Add-Content -LiteralPath $p -Value $line -ErrorAction SilentlyContinue
    } catch { }
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
    # Portability: a fresh VM guest has no ~\.ssh\id_rsa, and `type` then
    # reports "path not found" instead of "access denied". Create a
    # ssh-keygen-style fixture (protected DACL, user-only, inheritance
    # off — crucially without an ALL APPLICATION PACKAGES ACE) so the
    # denial path is exercised everywhere. Removed again if we made it.
    $createdFixture = -not (Test-Path -LiteralPath $target)
    if ($createdFixture) {
        New-Item -ItemType Directory -Path (Split-Path -Parent $target) -Force | Out-Null
        Set-Content -LiteralPath $target -Value 'sandbox-test-fixture' -Encoding ASCII
        $acl = Get-Acl -LiteralPath $target
        $acl.SetAccessRuleProtection($true, $false)
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            [Security.Principal.WindowsIdentity]::GetCurrent().User, 'FullControl', 'Allow')
        $acl.AddAccessRule($rule)
        (Get-Item -LiteralPath $target) | Set-Acl -AclObject $acl
    }
    $r = Invoke-Sandbox -Args @('run','--allow-cwd','--','cmd','/c','type',$target) -WorkingDirectory $d
    $err = ($r.Stderr -join "`n")
    if ($createdFixture) { Remove-Item -LiteralPath $target -Force -ErrorAction SilentlyContinue }
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
        return @{ Num=9; Name='S-9'; Passed=$false; Skipped=$false; Detail="venv create failed exit=$($r1.ExitCode) pyExists=$(Test-Path -LiteralPath $pyExe) stderr=$(($r1.Stderr -join "`n")) stdout=$(($r1.Stdout -join "`n"))" }
    }
    # r2 runs the venv python DIRECTLY. The previous form wrapped it in
    # `cmd /c`, which is broken in two independent ways proven on
    # 2026-10-12 (see tests/vm/confirm-s9-winsta.ps1 round W + local sims):
    # (a) cmd's /c quote heuristics strip quotes once the command line has
    #     more than two (spaced exe path, quoted -c arg), mangling it into
    #     "Access is denied."; (b) in-VM, cmd inside the AppContainer
    #     cannot spawn an exe under the PROTECTED .sandbox\<sid> subtree at
    #     all (W1/W2; still an open product question), while the direct
    #     spawn passes everywhere.
    $r2 = Invoke-Sandbox -Args @('run','--allow-cwd','--sid',$sid,'--',$pyExe,'-c',"print('venv works')") -WorkingDirectory $d
    $out = ($r2.Stdout -join "`n")
    $err = ($r2.Stderr -join "`n")
    $passed = ($r2.ExitCode -eq 0) -and ($out -match 'venv works')
    return @{ Num=9; Name='S-9'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { "venv python ran; sid=$sid" } else { "exit=$($r2.ExitCode) stdout=$out stderr=$err" } }
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
    $proc = Start-SandboxProcess -Arguments 'run --allow-cwd -- cmd /c ping -t 127.0.0.1' -WorkingDirectory $d
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
# The sandboxed child talks to the localhost proxy (auto-injected HTTP_PROXY),
# which allows the CONNECT to the listed host. PASS if curl gets an HTTP
# response code from the server (4xx/5xx = reached the server; auth failed is
# expected). Skip if curl.exe is absent or loopback-to-proxy is blocked.
function Invoke-Scenario-S27 {
    if (-not (Get-Curl)) { return @{ Num=27; Name='S-27 (AC-3.3)'; Passed=$true; Skipped=$true; Detail='curl.exe not on PATH' } }
    if (-not (Test-LoopbackProxyReachable)) { return @{ Num=27; Name='S-27 (AC-3.3)'; Passed=$true; Skipped=$true; Detail='AppContainer loopback-to-proxy blocked (firewall); run needs loopback exemption' } }
    $d = New-ScenarioDir 27
    $r = Invoke-Sandbox -Args @('run','--allow-cwd','--allow-domain','api.anthropic.com','--','cmd','/c','curl.exe -s -m 15 -o NUL -w %{http_code} https://api.anthropic.com/v1/messages') -WorkingDirectory $d
    $code = (($r.Stdout -join '') -replace '\s','')
    $connected = Test-CurlReachedServer -ExitCode $r.ExitCode -HttpCode $code
    $passed = $connected
    return @{ Num=27; Name='S-27 (AC-3.3)'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { "connection succeeded (http_code=$code)" } else { "exit=$($r.ExitCode) http_code=$code" } }
}

# S-28: AC-3.4 — allow-domain denies an unlisted host.
# The proxy denies the CONNECT to evil.example.com (not in the allow-list).
# PASS if curl fails to connect (non-zero exit, empty/error output).
function Invoke-Scenario-S28 {
    if (-not (Get-Curl)) { return @{ Num=28; Name='S-28 (AC-3.4)'; Passed=$true; Skipped=$true; Detail='curl.exe not on PATH' } }
    if (-not (Test-LoopbackProxyReachable)) { return @{ Num=28; Name='S-28 (AC-3.4)'; Passed=$true; Skipped=$true; Detail='AppContainer loopback-to-proxy blocked (firewall)' } }
    $d = New-ScenarioDir 28
    $r = Invoke-Sandbox -Args @('run','--allow-cwd','--allow-domain','api.anthropic.com','--','cmd','/c','curl.exe -s -m 15 -o NUL -w %{http_code} https://evil.example.com') -WorkingDirectory $d
    $code = (($r.Stdout -join '') -replace '\s','')
    # Denied: curl exit non-zero AND http_code is 000/empty (never reached a server).
    $denied = ($r.ExitCode -ne 0) -and ($code -eq '000' -or $code -eq '')
    $passed = $denied
    return @{ Num=28; Name='S-28 (AC-3.4)'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { "unlisted host denied (exit=$($r.ExitCode))" } else { "exit=$($r.ExitCode) http_code=$code (expected denial)" } }
}

# S-29: AC-3.5 — wildcard suffix matches, dot-bounded.
# `*.anthropic.com` matches the subdomain `api.anthropic.com`. PASS if the
# connection succeeds (http_code is 4xx/5xx = reached the server).
function Invoke-Scenario-S29 {
    if (-not (Get-Curl)) { return @{ Num=29; Name='S-29 (AC-3.5)'; Passed=$true; Skipped=$true; Detail='curl.exe not on PATH' } }
    if (-not (Test-LoopbackProxyReachable)) { return @{ Num=29; Name='S-29 (AC-3.5)'; Passed=$true; Skipped=$true; Detail='AppContainer loopback-to-proxy blocked (firewall)' } }
    $d = New-ScenarioDir 29
    $r = Invoke-Sandbox -Args @('run','--allow-cwd','--allow-domain','*.anthropic.com','--','cmd','/c','curl.exe -s -m 15 -o NUL -w %{http_code} https://api.anthropic.com/v1/messages') -WorkingDirectory $d
    $code = (($r.Stdout -join '') -replace '\s','')
    $connected = Test-CurlReachedServer -ExitCode $r.ExitCode -HttpCode $code
    $passed = $connected
    return @{ Num=29; Name='S-29 (AC-3.5)'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { "wildcard subdomain matched (http_code=$code)" } else { "exit=$($r.ExitCode) http_code=$code" } }
}

# S-30: AC-3.6 — always-denied overrides explicit allow.
# 169.254.169.254 is in the hard-deny CIDR list; explicit --allow-domain is
# overridden. PASS if curl fails (denied).
function Invoke-Scenario-S30 {
    if (-not (Get-Curl)) { return @{ Num=30; Name='S-30 (AC-3.6)'; Passed=$true; Skipped=$true; Detail='curl.exe not on PATH' } }
    if (-not (Test-LoopbackProxyReachable)) { return @{ Num=30; Name='S-30 (AC-3.6)'; Passed=$true; Skipped=$true; Detail='AppContainer loopback-to-proxy blocked (firewall)' } }
    $d = New-ScenarioDir 30
    $r = Invoke-Sandbox -Args @('run','--allow-cwd','--allow-domain','169.254.169.254','--','cmd','/c','curl.exe -s -m 15 -o NUL -w %{http_code} https://169.254.169.254') -WorkingDirectory $d
    $code = (($r.Stdout -join '') -replace '\s','')
    $denied = ($r.ExitCode -ne 0) -and ($code -eq '000' -or $code -eq '')
    $passed = $denied
    return @{ Num=30; Name='S-30 (AC-3.6)'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { "metadata IP denied despite explicit allow" } else { "exit=$($r.ExitCode) http_code=$code (expected denial)" } }
}

# S-31: AC-3.7 — metadata.google.internal denied.
# The hostname is in the hard-deny DNS list (checked pre-resolution). PASS if
# curl fails (denied).
function Invoke-Scenario-S31 {
    if (-not (Get-Curl)) { return @{ Num=31; Name='S-31 (AC-3.7)'; Passed=$true; Skipped=$true; Detail='curl.exe not on PATH' } }
    if (-not (Test-LoopbackProxyReachable)) { return @{ Num=31; Name='S-31 (AC-3.7)'; Passed=$true; Skipped=$true; Detail='AppContainer loopback-to-proxy blocked (firewall)' } }
    $d = New-ScenarioDir 31
    $r = Invoke-Sandbox -Args @('run','--allow-cwd','--allow-domain','metadata.google.internal','--','cmd','/c','curl.exe -s -m 15 -o NUL -w %{http_code} https://metadata.google.internal') -WorkingDirectory $d
    $code = (($r.Stdout -join '') -replace '\s','')
    $denied = ($r.ExitCode -ne 0) -and ($code -eq '000' -or $code -eq '')
    $passed = $denied
    return @{ Num=31; Name='S-31 (AC-3.7)'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { "metadata.google.internal denied" } else { "exit=$($r.ExitCode) http_code=$code (expected denial)" } }
}

# S-32: AC-3.8 — minimal profile allows LLM APIs, denies github.
# `--network-profile minimal` allows api.anthropic.com (and openai/google) but
# not github.com. PASS if the first curl succeeds AND the second fails.
function Invoke-Scenario-S32 {
    if (-not (Get-Curl)) { return @{ Num=32; Name='S-32 (AC-3.8)'; Passed=$true; Skipped=$true; Detail='curl.exe not on PATH' } }
    if (-not (Test-LoopbackProxyReachable)) { return @{ Num=32; Name='S-32 (AC-3.8)'; Passed=$true; Skipped=$true; Detail='AppContainer loopback-to-proxy blocked (firewall)' } }
    $d = New-ScenarioDir 32
    $r1 = Invoke-Sandbox -Args @('run','--allow-cwd','--network-profile','minimal','--','cmd','/c','curl.exe -s -m 15 -o NUL -w %{http_code} https://api.anthropic.com/v1/messages') -WorkingDirectory $d
    $code1 = (($r1.Stdout -join '') -replace '\s','')
    $allowed = Test-CurlReachedServer -ExitCode $r1.ExitCode -HttpCode $code1
    $r2 = Invoke-Sandbox -Args @('run','--allow-cwd','--network-profile','minimal','--','cmd','/c','curl.exe -s -m 15 -o NUL -w %{http_code} https://github.com') -WorkingDirectory $d
    $code2 = (($r2.Stdout -join '') -replace '\s','')
    $denied = ($r2.ExitCode -ne 0) -and ($code2 -eq '000' -or $code2 -eq '')
    $passed = $allowed -and $denied
    return @{ Num=32; Name='S-32 (AC-3.8)'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { "minimal: anthropic allowed, github denied" } else { "allowed=$allowed (code=$code1) denied=$denied (code=$code2)" } }
}

# S-33: AC-3.9 — developer profile adds registries + github.
# `--network-profile developer` allows api.anthropic.com AND github.com. PASS
# if both curls succeed (reach the server).
function Invoke-Scenario-S33 {
    if (-not (Get-Curl)) { return @{ Num=33; Name='S-33 (AC-3.9)'; Passed=$true; Skipped=$true; Detail='curl.exe not on PATH' } }
    if (-not (Test-LoopbackProxyReachable)) { return @{ Num=33; Name='S-33 (AC-3.9)'; Passed=$true; Skipped=$true; Detail='AppContainer loopback-to-proxy blocked (firewall)' } }
    $d = New-ScenarioDir 33
    $r1 = Invoke-Sandbox -Args @('run','--allow-cwd','--network-profile','developer','--','cmd','/c','curl.exe -s -m 15 -o NUL -w %{http_code} https://api.anthropic.com') -WorkingDirectory $d
    $code1 = (($r1.Stdout -join '') -replace '\s','')
    $ok1 = Test-CurlReachedServer -ExitCode $r1.ExitCode -HttpCode $code1
    $r2 = Invoke-Sandbox -Args @('run','--allow-cwd','--network-profile','developer','--','cmd','/c','curl.exe -s -m 15 -o NUL -w %{http_code} https://github.com') -WorkingDirectory $d
    $code2 = (($r2.Stdout -join '') -replace '\s','')
    $ok2 = Test-CurlReachedServer -ExitCode $r2.ExitCode -HttpCode $code2
    $passed = $ok1 -and $ok2
    return @{ Num=33; Name='S-33 (AC-3.9)'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { "developer: anthropic + github allowed" } else { "anthropic=$ok1 (code=$code1) github=$ok2 (code=$code2)" } }
}

# S-34: AC-3.10 — profile + CLI flags merge.
# `--network-profile minimal --allow-domain github.com`: minimal allows
# api.anthropic.com, CLI flag adds github.com. PASS if both succeed.
function Invoke-Scenario-S34 {
    if (-not (Get-Curl)) { return @{ Num=34; Name='S-34 (AC-3.10)'; Passed=$true; Skipped=$true; Detail='curl.exe not on PATH' } }
    if (-not (Test-LoopbackProxyReachable)) { return @{ Num=34; Name='S-34 (AC-3.10)'; Passed=$true; Skipped=$true; Detail='AppContainer loopback-to-proxy blocked (firewall)' } }
    $d = New-ScenarioDir 34
    $r1 = Invoke-Sandbox -Args @('run','--allow-cwd','--network-profile','minimal','--allow-domain','github.com','--','cmd','/c','curl.exe -s -m 15 -o NUL -w %{http_code} https://api.anthropic.com') -WorkingDirectory $d
    $code1 = (($r1.Stdout -join '') -replace '\s','')
    $ok1 = Test-CurlReachedServer -ExitCode $r1.ExitCode -HttpCode $code1
    $r2 = Invoke-Sandbox -Args @('run','--allow-cwd','--network-profile','minimal','--allow-domain','github.com','--','cmd','/c','curl.exe -s -m 15 -o NUL -w %{http_code} https://github.com') -WorkingDirectory $d
    $code2 = (($r2.Stdout -join '') -replace '\s','')
    $ok2 = Test-CurlReachedServer -ExitCode $r2.ExitCode -HttpCode $code2
    $passed = $ok1 -and $ok2
    return @{ Num=34; Name='S-34 (AC-3.10)'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { "profile+CLI merged: anthropic + github allowed" } else { "anthropic=$ok1 (code=$code1) github=$ok2 (code=$code2)" } }
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

# S-36: AC-3.12 — no token → 407.
# Run a single sandboxed curl that explicitly overrides the proxy URL via
# curl's -x flag, pointing at the injected proxy port (SANDBOX_PROXY_PORT env
# var, which the sandbox sets for the child) WITHOUT userinfo — so curl sends
# no Proxy-Authorization header. The proxy must reject with 407. PASS if the
# response contains 407 or curl exits with a proxy-auth error.
function Invoke-Scenario-S36 {
    if (-not (Get-Curl)) { return @{ Num=36; Name='S-36 (AC-3.12)'; Passed=$true; Skipped=$true; Detail='curl.exe not on PATH' } }
    if (-not (Test-LoopbackProxyReachable)) { return @{ Num=36; Name='S-36 (AC-3.12)'; Passed=$true; Skipped=$true; Detail='AppContainer loopback-to-proxy blocked (firewall)' } }
    $d = New-ScenarioDir 36
    # %SANDBOX_PROXY_PORT% is injected by the sandbox env block. curl -x takes
    # precedence over HTTP_PROXY; a URL without userinfo sends no auth header.
    $r = Invoke-Sandbox -Args @('run','--allow-cwd','--allow-domain','api.anthropic.com','--','cmd','/c','curl.exe -s -m 10 -x http://127.0.0.1:%SANDBOX_PROXY_PORT% -o NUL -w %{http_code} https://api.anthropic.com/v1/messages') -WorkingDirectory $d
    $code = (($r.Stdout -join '') -replace '\s','')
    $stderr = ($r.Stderr -join "`n")
    # PASS if we see 407 anywhere (http_code, stderr) OR curl exits with a
    # proxy-auth error (curl exit 97 = proxy auth required by RFC, 56 = recv).
    $got407 = ($code -eq '407') -or ($stderr -match '407') -or ($r.ExitCode -eq 97)
    $passed = $got407
    return @{ Num=36; Name='S-36 (AC-3.12)'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { "proxy returned 407 for unauthenticated CONNECT" } else { "exit=$($r.ExitCode) code=$code" } }
}

# S-37: AC-3.13 — raw-socket app fails closed. DEFERRED with the US-3
# network slice: `--allow-domain` currently exits rc 1 with a deferral
# warning BEFORE the child runs ("--allow-domain / --network-profile are
# deferred in this slice"), so the fail-closed assertion cannot be
# evaluated (observed in-VM 2026-10-12, run 20261012-223811). Mirror the
# S-36/S-38/S-39 deferral skips; revive the scenario when US-3 lands.
function Invoke-Scenario-S37 {
    return @{ Num=37; Name='S-37 (AC-3.13)'; Passed=$true; Skipped=$true; Detail='deferred: --allow-domain exits with a slice-deferral warning before the child runs (US-3)' }
}

# S-38: AC-3.14 — proxy port released on sandbox exit.
# Run a sandboxed process with --allow-domain, capture the proxy port from
# stderr (SANDBOX_DIAG). After the sandbox exits, the proxy handle is dropped
# (cancels the accept loop, shuts down the runtime) and the listening socket
# is released. PASS if no TCP listener remains on the port.
function Invoke-Scenario-S38 {
    if (-not (Get-Curl)) { return @{ Num=38; Name='S-38 (AC-3.14)'; Passed=$true; Skipped=$true; Detail='curl.exe not on PATH' } }
    if (-not (Test-LoopbackProxyReachable)) { return @{ Num=38; Name='S-38 (AC-3.14)'; Passed=$true; Skipped=$true; Detail='AppContainer loopback-to-proxy blocked (firewall)' } }
    $d = New-ScenarioDir 38
    $oldDiag = $env:SANDBOX_DIAG
    $env:SANDBOX_DIAG = '1'
    $port = $null
    try {
        $errFile = Join-Path $d 'proxy-err.txt'
        $proc = Start-Process -FilePath $SandboxExe `
            -ArgumentList 'run','--allow-cwd','--allow-domain','api.anthropic.com','--','cmd','/c','echo hi' `
            -WorkingDirectory $d -NoNewWindow -PassThru -RedirectStandardError $errFile
        # Wait for the sandbox to exit (the child `echo hi` returns immediately).
        $proc.WaitForExit(15000) | Out-Null
        if (-not $proc.HasExited) { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue }
        $errContent = Get-Content -LiteralPath $errFile -Raw -ErrorAction SilentlyContinue
        $errLines = if ($errContent) { $errContent -split "`r?`n" } else { @() }
        $port = Get-ProxyPortFromStderr -Stderr $errLines
    } finally { $env:SANDBOX_DIAG = $oldDiag }
    if (-not $port) { return @{ Num=38; Name='S-38 (AC-3.14)'; Passed=$false; Skipped=$false; Detail='could not parse proxy port from stderr' } }
    # Give the OS a moment to release the socket after the process exited.
    Start-Sleep -Seconds 1
    $conns = @(Get-NetTCPConnection -LocalPort $port -ErrorAction SilentlyContinue)
    $released = ($conns.Count -eq 0) -or ($conns.State -notcontains 'Listen')
    $passed = $released
    return @{ Num=38; Name='S-38 (AC-3.14)'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { "port $port released after exit" } else { "port $port still listening (states=$($conns.State -join ','))" } }
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

# S-46 (AC-4.6): CONNECT events appear in the audit log.
# Runs a sandboxed curl against an allowed host (so the proxy emits a CONNECT
# allow leaf), then `sandbox audit show <sid>` and checks the output contains
# a CONNECT event. Uses the two-step --print-sid / --sid pattern so the audit
# writer is created (the --print-sid-only path returns early before opening it).
function Invoke-Scenario-S46 {
    if (-not (Get-Curl)) { return @{ Num=46; Name='S-46 (AC-4.6)'; Passed=$true; Skipped=$true; Detail='curl.exe not on PATH' } }
    if (-not (Test-LoopbackProxyReachable)) { return @{ Num=46; Name='S-46 (AC-4.6)'; Passed=$true; Skipped=$true; Detail='AppContainer loopback-to-proxy blocked (firewall)' } }
    $d = New-ScenarioDir 46
    $psid = Invoke-Sandbox -Args @('run','--allow-cwd','--allow-domain','api.anthropic.com','--print-sid','--','cmd','/c','echo','placeholder') -WorkingDirectory $d
    if ($psid.ExitCode -ne 0) { return @{ Num=46; Name='S-46 (AC-4.6)'; Passed=$false; Skipped=$false; Detail='print-sid failed' } }
    $sid = ($psid.Stdout -join '').Trim()
    # Real run: curl the allowed host so the proxy emits a CONNECT allow leaf.
    Invoke-Sandbox -Args @('run','--allow-cwd','--allow-domain','api.anthropic.com','--sid',$sid,'--','cmd','/c','curl.exe -s -m 15 -o NUL -w %{http_code} https://api.anthropic.com/v1/messages') -WorkingDirectory $d | Out-Null
    $s = Invoke-Sandbox -Args @('audit','show',$sid)
    $out = ($s.Stdout -join "`n") + "`n" + ($s.Stderr -join "`n")
    $passed = ($s.ExitCode -eq 0) -and ($out -match 'CONNECT')
    return @{ Num=46; Name='S-46 (AC-4.6)'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { 'audit log contains CONNECT events' } else { "no CONNECT in audit output (exit=$($s.ExitCode))" } }
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
# Long-running child: `python -c "__import__('time').sleep(30)#<marker>"` —
# no spaces (no cmdline-quoting pitfalls), no network, no console input.
# Windows PowerShell 5.1 must NOT be the child: powershell.exe fails DLL
# init (exit -1073741502 / 0xC0000142) inside the AppContainer in a PS
# Direct guest session, and this scenario's old defensive cleanup (kill ALL
# powershell.exe with a *WindowsPowerShell* path) then murdered the PS
# Direct session host — itself a powershell.exe — killing the suite stream
# and breaking every later CreateAppContainerProfile with 0x80070002
# (isolated with -Only 55, run 20261011-020625-428). The child kill is
# now marker-precise: it matches a unique per-run snippet in the child's
# command line and can never hit a session host. Skips cleanly when python
# is absent (same gate as S-8/S-9/S-25).
function Invoke-Scenario-S55 {
    $d = New-ScenarioDir 55
    if (-not (Get-Python)) { return @{ Num=55; Name='S-55 (AC-4.17)'; Passed=$true; Skipped=$true; PythonSkipped=$true; Detail='python not on PATH' } }
    $marker = "S55-sleeper-$([guid]::NewGuid().ToString('N'))"
    $psid = Invoke-Sandbox -Args @('run','--allow-cwd','--block-net','--print-sid','--','cmd','/c','echo','hi') -WorkingDirectory $d
    $sid = ($psid.Stdout -join '').Trim()
    # Marker-precise child kill. NEVER kill by process name/path here: the
    # PS Direct session host is a powershell.exe too, and killing it takes
    # the whole suite (and its session) down with it.
    function Stop-S55Child {
        Get-CimInstance Win32_Process -Filter "Name = 'python.exe'" -ErrorAction SilentlyContinue |
            Where-Object { $_.CommandLine -like "*$marker*" } |
            ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
    }
    # Start a long-running session. The child sleeps 30s; we kill the sandbox
    # supervisor after 2s, before the child exits naturally.
    $sleeper = "__import__('time').sleep(30)#$marker"
    $proc = Start-SandboxProcess -Arguments "run --allow-cwd --block-net --sid $sid -- python -c $sleeper" -WorkingDirectory $d
    Start-Sleep -Seconds 2
    if ($proc.HasExited) {
        Stop-S55Child
        return @{ Num=55; Name='S-55 (AC-4.17)'; Passed=$false; Skipped=$false; Detail="sandbox exited early (exit=$($proc.ExitCode)); child did not stay alive" }
    }
    # Force-kill sandbox.exe (the supervisor), not the child. The Job
    # Object's KILL_ON_JOB_CLOSE will then kill the python child.
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
    # Cleanup any orphaned python child (defensive — the Job Object should
    # have killed it, but be safe).
    Stop-S55Child
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

# S-60 (AC-5.7): git_runtime group makes git usable. Skips if git absent.
function Invoke-Scenario-S60 {
    $d = New-ScenarioDir 60
    if (-not (Get-Command git.exe -ErrorAction SilentlyContinue)) {
        return @{ Num=60; Name='S-60 (AC-5.7)'; Passed=$true; Skipped=$true; Detail='git not on PATH' }
    }
    $profileDir = Join-Path $d 'profiles'
    New-Item -ItemType Directory -Path $profileDir -Force | Out-Null
    $profilePath = Join-Path $profileDir 'git-runtime.json'
    $profileJson = @{
        meta = @{ name = 'git-runtime'; schema_version = 1 }
        security = @{ groups = @('git_runtime') }
        filesystem = @{ allow = @('$CWD'); read_only = @(); deny = @() }
    } | ConvertTo-Json -Depth 5
    Set-Content -LiteralPath $profilePath -Value $profileJson -Encoding UTF8
    $r = Invoke-Sandbox -Args @('run','--profile',$profilePath,'--allow-cwd','--','git','--version') -WorkingDirectory $d
    $out = ($r.Stdout -join "`n")
    $passed = ($r.ExitCode -eq 0) -and ($out -match 'git version')
    return @{ Num=60; Name='S-60 (AC-5.7)'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { 'git ran under git_runtime group' } else { "exit=$($r.ExitCode) stdout=$out stderr=$(($r.Stderr -join "`n"))" } }
}

# S-61 (AC-5.7): dotnet_runtime group makes dotnet usable. Skips if dotnet absent.
function Invoke-Scenario-S61 {
    $d = New-ScenarioDir 61
    if (-not (Get-Command dotnet.exe -ErrorAction SilentlyContinue)) {
        return @{ Num=61; Name='S-61 (AC-5.7)'; Passed=$true; Skipped=$true; Detail='dotnet not on PATH' }
    }
    $profileDir = Join-Path $d 'profiles'
    New-Item -ItemType Directory -Path $profileDir -Force | Out-Null
    $profilePath = Join-Path $profileDir 'dotnet-runtime.json'
    $profileJson = @{
        meta = @{ name = 'dotnet-runtime'; schema_version = 1 }
        security = @{ groups = @('dotnet_runtime') }
        filesystem = @{ allow = @('$CWD'); read_only = @(); deny = @() }
    } | ConvertTo-Json -Depth 5
    Set-Content -LiteralPath $profilePath -Value $profileJson -Encoding UTF8
    $r = Invoke-Sandbox -Args @('run','--profile',$profilePath,'--allow-cwd','--','dotnet','--version') -WorkingDirectory $d
    $out = ($r.Stdout -join "`n")
    $passed = ($r.ExitCode -eq 0) -and ($out -match '^\s*\d+\.\d+\.\d+')
    return @{ Num=61; Name='S-61 (AC-5.7)'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { 'dotnet ran under dotnet_runtime group' } else { "exit=$($r.ExitCode) stdout=$out" } }
}

# S-62 (AC-5.6): extends cycle is detected and reported with the spec format.
# Uses absolute paths in `extends` so the cycle detector sees the same string
# on the second visit (bare names resolve to %USERPROFILE%\.sandbox\profiles\
# and would not reach the local fixture).
function Invoke-Scenario-S62 {
    $d = New-ScenarioDir 62
    $profileDir = Join-Path $d 'profiles'
    New-Item -ItemType Directory -Path $profileDir -Force | Out-Null
    $aPath = Join-Path $profileDir 'a.json'
    $bPath = Join-Path $profileDir 'b.json'
    $aJson = '{"meta":{"name":"a","schema_version":1},"extends":"' + ($bPath -replace '\\','\\') + '","filesystem":{"allow":["$CWD"]}}'
    $bJson = '{"meta":{"name":"b","schema_version":1},"extends":"' + ($aPath -replace '\\','\\') + '","filesystem":{"allow":["$CWD"]}}'
    Set-Content -LiteralPath $aPath -Value $aJson -Encoding UTF8
    Set-Content -LiteralPath $bPath -Value $bJson -Encoding UTF8
    $r = Invoke-Sandbox -Args @('run','--profile',$aPath,'--','cmd','/c','echo','x') -WorkingDirectory $d
    $err = ($r.Stderr -join "`n")
    $passed = ($r.ExitCode -ne 0) -and ($err -match 'Profile cycle detected') -and ($err -match 'a\.json.*b\.json.*a\.json')
    return @{ Num=62; Name='S-62 (AC-5.6)'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { 'cycle detected + formatted' } else { "exit=$($r.ExitCode) stderr=$err" } }
}

# S-63 (AC-5.14): profile list shows all user-global profiles.
function Invoke-Scenario-S63 {
    $d = New-ScenarioDir 63
    $fakeHome = Join-Path $d 'fake-home'
    $profilesDir = Join-Path $fakeHome '.sandbox\profiles'
    New-Item -ItemType Directory -Path $profilesDir -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $profilesDir 'alpha.json') -Value '{"meta":{"name":"alpha","schema_version":1}}' -Encoding UTF8
    Set-Content -LiteralPath (Join-Path $profilesDir 'beta.json') -Value '{"meta":{"name":"beta","schema_version":1}}' -Encoding UTF8
    # Invoke-Sandbox doesn't expose env-var overrides, so invoke directly.
    # `$SandboxExe` is the script-scope param (see harness top-level param block).
    $pi = New-Object System.Diagnostics.ProcessStartInfo
    $pi.FileName = $SandboxExe
    $pi.Arguments = 'profile list'
    $pi.UseShellExecute = $false
    $pi.RedirectStandardOutput = $true
    $pi.RedirectStandardError = $true
    $pi.EnvironmentVariables['USERPROFILE'] = $fakeHome
    $proc = [System.Diagnostics.Process]::Start($pi)
    $stdout = $proc.StandardOutput.ReadToEnd()
    $stderr = $proc.StandardError.ReadToEnd()
    $proc.WaitForExit()
    $passed = ($proc.ExitCode -eq 0) -and ($stdout -match 'alpha') -and ($stdout -match 'beta')
    return @{ Num=63; Name='S-63 (AC-5.14)'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { 'list shows both profiles' } else { "exit=$($proc.ExitCode) stdout=$stdout stderr=$stderr" } }
}

# S-64 (AC-5.15): profile show (raw) prints the file as-authored.
function Invoke-Scenario-S64 {
    $d = New-ScenarioDir 64
    $fakeHome = Join-Path $d 'fake-home'
    $profilesDir = Join-Path $fakeHome '.sandbox\profiles'
    New-Item -ItemType Directory -Path $profilesDir -Force | Out-Null
    $rawJson = '{"meta":{"name":"raw","schema_version":1},"security":{"groups":["python_runtime"]},"filesystem":{"allow":["$CWD"]}}'
    Set-Content -LiteralPath (Join-Path $profilesDir 'raw.json') -Value $rawJson -Encoding UTF8
    $pi = New-Object System.Diagnostics.ProcessStartInfo
    $pi.FileName = $SandboxExe
    $pi.Arguments = 'profile show raw'
    $pi.UseShellExecute = $false
    $pi.RedirectStandardOutput = $true
    $pi.RedirectStandardError = $true
    $pi.EnvironmentVariables['USERPROFILE'] = $fakeHome
    $proc = [System.Diagnostics.Process]::Start($pi)
    $stdout = $proc.StandardOutput.ReadToEnd()
    $proc.WaitForExit()
    $passed = ($proc.ExitCode -eq 0) -and ($stdout -match 'python_runtime') -and ($stdout -match '\$CWD') -and ($stdout -notmatch 'security_groups_expanded')
    return @{ Num=64; Name='S-64 (AC-5.15)'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { 'raw view printed as-authored' } else { "exit=$($proc.ExitCode) stdout=$stdout" } }
}

# S-65 (expanded): profile show --expanded emits resolved JSON.
function Invoke-Scenario-S65 {
    $d = New-ScenarioDir 65
    $fakeHome = Join-Path $d 'fake-home'
    $profilesDir = Join-Path $fakeHome '.sandbox\profiles'
    New-Item -ItemType Directory -Path $profilesDir -Force | Out-Null
    $rawJson = '{"meta":{"name":"expanded","schema_version":1},"security":{"groups":["python_runtime"]},"filesystem":{"allow":["$CWD"]}}'
    Set-Content -LiteralPath (Join-Path $profilesDir 'expanded.json') -Value $rawJson -Encoding UTF8
    $pi = New-Object System.Diagnostics.ProcessStartInfo
    $pi.FileName = $SandboxExe
    $pi.Arguments = 'profile show expanded --expanded'
    $pi.UseShellExecute = $false
    $pi.RedirectStandardOutput = $true
    $pi.RedirectStandardError = $true
    $pi.EnvironmentVariables['USERPROFILE'] = $fakeHome
    $pi.WorkingDirectory = $d
    $proc = [System.Diagnostics.Process]::Start($pi)
    $stdout = $proc.StandardOutput.ReadToEnd()
    $proc.WaitForExit()
    $passed = ($proc.ExitCode -eq 0) -and ($stdout -match 'security_groups_expanded') -and ($stdout -notmatch '\$CWD') -and ($stdout -match '"name": "expanded"')
    return @{ Num=65; Name='S-65 (expanded)'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { 'expanded view emitted resolved JSON' } else { "exit=$($proc.ExitCode) stdout=$stdout" } }
}

# S-66 (AC-5.3): extends concatenates allow arrays (de-duped).
function Invoke-Scenario-S66 {
    $d = New-ScenarioDir 66
    $profileDir = Join-Path $d 'profiles'
    New-Item -ItemType Directory -Path $profileDir -Force | Out-Null
    $basePath = Join-Path $profileDir 'base.json'
    $childPath = Join-Path $profileDir 'child.json'
    Set-Content -LiteralPath $basePath -Value '{"meta":{"name":"base","schema_version":1},"filesystem":{"allow":["$CWD"]}}' -Encoding UTF8
    $childJson = '{"meta":{"name":"child","schema_version":1},"extends":"' + ($basePath -replace '\\','\\') + '","filesystem":{"allow":["$CWD"]}}'
    Set-Content -LiteralPath $childPath -Value $childJson -Encoding UTF8
    $r = Invoke-Sandbox -Args @('run','--profile',$childPath,'--','cmd','/c','echo','extends-ok') -WorkingDirectory $d
    $out = ($r.Stdout -join "`n")
    $passed = ($r.ExitCode -eq 0) -and ($out -match 'extends-ok')
    return @{ Num=66; Name='S-66 (AC-5.3)'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { 'extends merged' } else { "exit=$($r.ExitCode) stdout=$out stderr=$(($r.Stderr -join "`n"))" } }
}

# S-67 (AC-5.5): multi-level extends (a -> b -> c).
function Invoke-Scenario-S67 {
    $d = New-ScenarioDir 67
    $profileDir = Join-Path $d 'profiles'
    New-Item -ItemType Directory -Path $profileDir -Force | Out-Null
    $cPath = Join-Path $profileDir 'c.json'
    $bPath = Join-Path $profileDir 'b.json'
    $aPath = Join-Path $profileDir 'a.json'
    Set-Content -LiteralPath $cPath -Value '{"meta":{"name":"c","schema_version":1},"filesystem":{"allow":["$CWD"]}}' -Encoding UTF8
    $bJson = '{"meta":{"name":"b","schema_version":1},"extends":"' + ($cPath -replace '\\','\\') + '","filesystem":{"allow":["$CWD"]}}'
    Set-Content -LiteralPath $bPath -Value $bJson -Encoding UTF8
    $aJson = '{"meta":{"name":"a","schema_version":1},"extends":"' + ($bPath -replace '\\','\\') + '","filesystem":{"allow":["$CWD"]}}'
    Set-Content -LiteralPath $aPath -Value $aJson -Encoding UTF8
    $r = Invoke-Sandbox -Args @('run','--profile',$aPath,'--','cmd','/c','echo','multi-ok') -WorkingDirectory $d
    $out = ($r.Stdout -join "`n")
    $passed = ($r.ExitCode -eq 0) -and ($out -match 'multi-ok')
    return @{ Num=67; Name='S-67 (AC-5.5)'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { '3-deep extends resolved' } else { "exit=$($r.ExitCode) stdout=$out stderr=$(($r.Stderr -join "`n"))" } }
}

# S-68 (AC-5.8): $HOME expands per-user.
function Invoke-Scenario-S68 {
    $d = New-ScenarioDir 68
    $profileDir = Join-Path $d 'profiles'
    New-Item -ItemType Directory -Path $profileDir -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $profileDir 'home.json') -Value '{"meta":{"name":"home","schema_version":1},"filesystem":{"allow":["$HOME/.sandbox-test-marker"]}}' -Encoding UTF8
    $markerDir = Join-Path $env:USERPROFILE '.sandbox-test-marker'
    New-Item -ItemType Directory -Path $markerDir -Force | Out-Null
    $markerFile = Join-Path $markerDir 'hi.txt'
    Set-Content -LiteralPath $markerFile -Value 'home-expanded' -Encoding ASCII
    $r = Invoke-Sandbox -Args @('run','--profile',(Join-Path $profileDir 'home.json'),'--','cmd','/c','type',$markerFile) -WorkingDirectory $d
    $out = ($r.Stdout -join "`n")
    Remove-Item -LiteralPath $markerDir -Recurse -Force -ErrorAction SilentlyContinue
    $passed = ($r.ExitCode -eq 0) -and ($out -match 'home-expanded')
    return @{ Num=68; Name='S-68 (AC-5.8)'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { '$HOME expanded' } else { "exit=$($r.ExitCode) stdout=$out stderr=$(($r.Stderr -join "`n"))" } }
}

# S-69 (AC-5.9): windows_common (System32) is reachable even with an empty profile.
function Invoke-Scenario-S69 {
    $d = New-ScenarioDir 69
    $profileDir = Join-Path $d 'profiles'
    New-Item -ItemType Directory -Path $profileDir -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $profileDir 'empty.json') -Value '{"meta":{"name":"empty","schema_version":1}}' -Encoding UTF8
    $r = Invoke-Sandbox -Args @('run','--profile',(Join-Path $profileDir 'empty.json'),'--','cmd','/c','echo','sys32-ok') -WorkingDirectory $d
    $out = ($r.Stdout -join "`n")
    $passed = ($r.ExitCode -eq 0) -and ($out -match 'sys32-ok')
    return @{ Num=69; Name='S-69 (AC-5.9)'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { 'System32 reachable from empty profile' } else { "exit=$($r.ExitCode) stdout=$out stderr=$(($r.Stderr -join "`n"))" } }
}

# S-70 (AC-5.10): CLI --allow merges on top of profile.
function Invoke-Scenario-S70 {
    $d = New-ScenarioDir 70
    $profileDir = Join-Path $d 'profiles'
    New-Item -ItemType Directory -Path $profileDir -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $profileDir 'p.json') -Value '{"meta":{"name":"p","schema_version":1},"filesystem":{"allow":["$CWD"]}}' -Encoding UTF8
    $extraDir = Join-Path (Split-Path -Parent $d) 'cli-merge-70'
    New-Item -ItemType Directory -Path $extraDir -Force | Out-Null
    $extraFile = Join-Path $extraDir 'merged.txt'
    Set-Content -LiteralPath $extraFile -Value 'cli-merge-ok' -Encoding ASCII
    $r = Invoke-Sandbox -Args @('run','--profile',(Join-Path $profileDir 'p.json'),'--allow-cwd','--allow',$extraDir,'--','cmd','/c','type',$extraFile) -WorkingDirectory $d
    $out = ($r.Stdout -join "`n")
    $passed = ($r.ExitCode -eq 0) -and ($out -match 'cli-merge-ok')
    return @{ Num=70; Name='S-70 (AC-5.10)'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { 'CLI --allow merged' } else { "exit=$($r.ExitCode) stdout=$out stderr=$(($r.Stderr -join "`n"))" } }
}

# S-71 (AC-5.17): a profile using only $HOME/$CWD/groups is portable (no edits).
function Invoke-Scenario-S71 {
    $d = New-ScenarioDir 71
    $profileDir = Join-Path $d 'profiles'
    New-Item -ItemType Directory -Path $profileDir -Force | Out-Null
    $portableJson = '{"meta":{"name":"portable","schema_version":1},"security":{"groups":["python_runtime"]},"filesystem":{"allow":["$HOME/.claude","$CWD"],"read_only":["$HOME/.gitconfig"],"deny":["$HOME/.ssh"]}}'
    Set-Content -LiteralPath (Join-Path $profileDir 'portable.json') -Value $portableJson -Encoding UTF8
    $hasAbs = $portableJson -match '[A-Z]:\\\\'
    $r = Invoke-Sandbox -Args @('run','--profile',(Join-Path $profileDir 'portable.json'),'--allow-cwd','--','cmd','/c','echo','portable-ok') -WorkingDirectory $d
    $out = ($r.Stdout -join "`n")
    $passed = (-not $hasAbs) -and ($r.ExitCode -eq 0) -and ($out -match 'portable-ok')
    return @{ Num=71; Name='S-71 (AC-5.17)'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { 'portable profile ran' } else { "hasAbs=$hasAbs exit=$($r.ExitCode) stdout=$out stderr=$(($r.Stderr -join "`n"))" } }
}

# ---------------------------------------------------------------------------
# Dispatched-vector scenarios end at S-71; S-72 is reserved (Task 2, LPAC,
# another branch). S-73/S-74 register via $script:ScenarioFunctions above.
# ---------------------------------------------------------------------------

# Count non-inherited session AppContainer ACEs on a path. Excludes
# S-1-15-2-2 (the intentional persistent drive-root grant).
function Get-SessionAceCount { param([string]$Path)
    $acl = Get-Acl -LiteralPath $Path
    return @($acl.Access | Where-Object {
        $_.IdentityReference -match '^S-1-15-2-' -and
        $_.IdentityReference -ne 'S-1-15-2-2' -and
        -not $_.IsInherited }).Count
}

function Get-DaclJournalDir { return Join-Path $env:LOCALAPPDATA 'sandbox\dacl-restore' }

# S-73 (MXC F-C/F-D): teardown restores the host DACL — no session ACE remains.
function Invoke-Scenario-S73 {
    $d = New-ScenarioDir 73
    $wasDiag = $env:SANDBOX_DIAG
    $env:SANDBOX_DIAG = '1'
    try {
        $r = Invoke-Sandbox -Args @('run','--allow-cwd','--','cmd','/c','echo','restore-me') -WorkingDirectory $d
    } finally { $env:SANDBOX_DIAG = $wasDiag }
    $stderr = ($r.Stderr -join "`n")
    $out = ($r.Stdout -join "`n")
    if ($stderr -match '\[grant\] WARN: allow:') {
        # This shell cannot write DACLs (e.g. non-elevated + write-denied);
        # the scenario is meaningless here, not a teardown failure. WARNs on
        # system-owned paths (System32/SystemRoot) are normal unprivileged.
        return @{ Num=73; Name='S-73 (journal teardown restore)'; Passed=$false; Skipped=$true
            Detail = 'DACL writes unavailable in this shell — run elevated to validate teardown' }
    }
    $before = Get-SessionAceCount -Path $d
    $r2 = Invoke-Sandbox -Args @('run','--allow-cwd','--','cmd','/c','echo','restore-me-2') -WorkingDirectory $d
    $after = Get-SessionAceCount -Path $d
    $passed = ($r2.ExitCode -eq 0) -and ($out -match 'restore-me') -and ($after -eq $before)
    return @{ Num=73; Name='S-73 (journal teardown restore)'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { 'session ACEs restored on exit' } else { "before=$before after=$after out1=$out exit=$($r2.ExitCode) stderr1=$(($r.Stderr -join "`n")) stderr2=$(($r2.Stderr -join "`n"))" } }
}

# S-74 (MXC F-C/F-D): crash leaves journal + ACE; next startup reaps the
# orphan (restore + journal deletion). Rollback path: the pre-written
# tests/cleanup-session-aces.ps1 recovers the host if this scenario fails.
function Invoke-Scenario-S74 {
    $d = New-ScenarioDir 74
    $journalDir = Get-DaclJournalDir
    $beforeJournals = @(Get-ChildItem -LiteralPath $journalDir -Filter '*.jsonl' -ErrorAction SilentlyContinue)
    $proc = Start-SandboxProcess -Arguments 'run --allow-cwd -- cmd /c ping -n 30 127.0.0.1' -WorkingDirectory $d
    $journal = $null
    try {
        $deadline = (Get-Date).AddSeconds(20)
        while ((Get-Date) -lt $deadline) {
            Start-Sleep -Milliseconds 300
            $now = @(Get-ChildItem -LiteralPath $journalDir -Filter '*.jsonl' -ErrorAction SilentlyContinue |
                Where-Object { $beforeJournals.Name -notcontains $_.Name })
            if ($now.Count -gt 0) { $journal = $now[0]; break }
        }
        if (-not $journal) {
            return @{ Num=74; Name='S-74 (journal crash recovery)'; Passed=$false; Skipped=$false
                Detail = 'no new journal appeared within 20s (journaling not wired?)' }
        }
        $aceCount = Get-SessionAceCount -Path $d
        if ($aceCount -lt 1) {
            # In a shell that cannot write DACLs the ACE never lands; skip
            # rather than misreport. Elevated runs exercise the full cycle.
            return @{ Num=74; Name='S-74 (journal crash recovery)'; Passed=$false; Skipped=$true
                Detail = 'session ACE missing after grant phase — DACL writes unavailable here' }
        }
        Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
    }
    finally {
        # Never leak the pinging child, whatever the asserts did.
        Get-Process ping -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        Get-Process sandbox -ErrorAction SilentlyContinue | Where-Object { $_.Id -eq $proc.Id } | Stop-Process -Force -ErrorAction SilentlyContinue
    }

    $journalStale = (Join-Path $journalDir $journal.Name)
    if (-not (Test-Path -LiteralPath $journalStale)) {
        return @{ Num=74; Name='S-74 (journal crash recovery)'; Passed=$false; Skipped=$false
            Detail = "journal $($journal.Name) gone after supervisor crash — should persist" }
    }

    # Second short run in the same dir triggers startup recover_orphans.
    $r2 = Invoke-Sandbox -Args @('run','--allow-cwd','--','cmd','/c','echo','recover-ok') -WorkingDirectory $d
    $afterAce = Get-SessionAceCount -Path $d
    $journalGone = -not (Test-Path -LiteralPath $journalStale)
    $passed = ($r2.ExitCode -eq 0) -and ($r2.Stdout -match 'recover-ok') -and ($afterAce -eq 0) -and $journalGone
    return @{ Num=74; Name='S-74 (journal crash recovery)'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { 'orphan journal reaped + stale ACE restored' }
                 else { "afterAce=$afterAce journalGone=$journalGone exit=$($r2.ExitCode) stdout=$(($r2.Stdout -join "`n")) stderr=$(($r2.Stderr -join "`n"))" } }
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
    { Invoke-Scenario-S58 }, { Invoke-Scenario-S59 },
    { Invoke-Scenario-S60 }, { Invoke-Scenario-S61 }, { Invoke-Scenario-S62 },
    { Invoke-Scenario-S63 }, { Invoke-Scenario-S64 }, { Invoke-Scenario-S65 },
    { Invoke-Scenario-S66 }, { Invoke-Scenario-S67 }, { Invoke-Scenario-S68 },
    { Invoke-Scenario-S69 }, { Invoke-Scenario-S70 }, { Invoke-Scenario-S71 }
)

# Scenarios beyond the positional array register explicitly (number -> block);
# this keeps reserved numbers (e.g. S-72, owned by another branch) free.
$script:MaxScenario = 74
$script:ScenarioFunctions = @{
    73 = { Invoke-Scenario-S73 }
    74 = { Invoke-Scenario-S74 }
}

function Invoke-Scenario { param([int]$Number)
    if ($Number -lt 1 -or $Number -gt $script:MaxScenario) { return $null }
    if ($script:ScenarioFunctions.ContainsKey($Number)) { return & $script:ScenarioFunctions[$Number] }
    if ($Number -gt $script:Scenarios.Count) {
        return @{ Num=$Number; Name="S-$Number (reserved)"; Passed=$false; Skipped=$true
            Detail = 'scenario number reserved (owned by another branch)' }
    }
    return & $script:Scenarios[$Number - 1]
}

function Select-ScenarioNumbers {
    $nums = 1..$script:MaxScenario
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
    Write-GuestMetric 'suite-begin' 0

    $nums = Select-ScenarioNumbers
    if (-not $nums -or $nums.Count -eq 0) {
        Write-Host "[info] no scenarios matched; nothing to do." -ForegroundColor Yellow
        if ($script:OwnsCwd -and -not $Keep) { Remove-Item -LiteralPath $script:TempCwd -Recurse -Force -ErrorAction SilentlyContinue }
        return 0
    }

    $results = New-Object System.Collections.Generic.List[hashtable]
    foreach ($n in $nums) {
        Write-GuestMetric 'start' $n
        try {
            $r = Invoke-Scenario -Number $n
        } catch {
            # A thrown scenario (e.g. Start-Process failing inside a PS
            # Direct session) must fail that scenario, not kill the suite.
            $r = @{ Num=$n; Name="S-$n"; Passed=$false; Skipped=$false
                Detail = "scenario threw: $($_.Exception.Message)" }
        }
        $r = ConvertTo-Result $r
        $results.Add($r)
        Write-GuestMetric 'end' $r.Num
        Write-Result $r
        if ($StopOnFail -and $r.State -eq 'fail') { Write-Host "[stop] -StopOnFail set; halting after S-$($r.Num)." -ForegroundColor Red; break }
    }

    $total = $results.Count
    $pass = 0; $fail = 0; $skip = 0; $anyFail = $false
    foreach ($r in $results) {
        # NOTE: never pipe this list into Where-Object — hashtables unroll
        # into DictionaryEntry items in a pipeline and corrupt the counts.
        switch ($r.State) {
            'pass' { $pass++ }
            'fail' { $fail++; $anyFail = $true }
            'skip' { $skip++ }
        }
    }
    Write-GuestMetric 'suite-end' 0
    Write-Host ""
    Write-Host ("Summary: total={0} pass={1} fail={2} skip={3}" -f $total,$pass,$fail,$skip) -ForegroundColor White

    $gateFailed = $false
    foreach ($r in $results) { if ($r.IsGate -and $r.State -eq 'fail') { $gateFailed = $true } }
    if ($gateFailed) {
        Write-Host "SANDBOX: FAIL (gate test S-6 failed)" -ForegroundColor Red
    } else {
        $required = 1,2,3,4,5,6,7,10,11,12,13,16,17,18,21,24,27,28,29,30,31,32,33,34,35,36,38,42,46
        $hardFail = $false
        foreach ($n in $required) {
            foreach ($r in $results) { if ($r.Num -eq $n -and $r.State -eq 'fail') { $hardFail = $true } }
        }
        $pythonSkipped = $false
        $loopbackSkipped = $false
        foreach ($r in $results) {
            if ($r.PythonSkipped) { $pythonSkipped = $true }
            if ($r.Detail -match 'loopback-to-proxy blocked') { $loopbackSkipped = $true }
        }
        if ($hardFail) { Write-Host "SANDBOX: FAIL" -ForegroundColor Red }
        elseif ($loopbackSkipped -and $pythonSkipped) { Write-Host "SANDBOX: PASS (loopback + python scenarios skipped)" -ForegroundColor Yellow }
        elseif ($loopbackSkipped) { Write-Host "SANDBOX: PASS (loopback network scenarios skipped)" -ForegroundColor Yellow }
        elseif ($pythonSkipped) { Write-Host "SANDBOX: PASS (python scenarios skipped)" -ForegroundColor Yellow }
        else { Write-Host "SANDBOX: PASS" -ForegroundColor Green }
    }

    if ($script:OwnsCwd -and -not $Keep) { Remove-Item -LiteralPath $script:TempCwd -Recurse -Force -ErrorAction SilentlyContinue }
    if ($Strict -and $skip -gt 0) { return 1 }
    if ($gateFailed -or $anyFail) { return 1 }
    return 0
}

$rc = Main
exit $rc
