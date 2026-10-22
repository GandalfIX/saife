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
  AppContainer loopback path is blocked by Windows Firewall (run elevated).
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
  S-72, S-75..S-80, S-82..S-84 (ADR-0001 Task 3.8) exercise the D-1/D-3/D-4/D-5
  prompt+intent+learned wiring: deny_domain blocklist, hard-deny IP expansion,
  wildcard apex allow, loopback CONNECT refusal, --no-prompt, /sandbox/intent
  POST+GET, learned list/revoke, and the audit `source` filter. S-78 (learned
  persistence) is a MANUAL scenario and skips. S-81, S-85, S-86 (ADR-0001
  Task 4.3) cover D-2 upstream chaining: S-81 is the NO_PROXY bypass driven
  from the host env (with its negative control), S-85 is upstream-unreachable
  -> 502 + `X-Sandbox: upstream-error` plus the two-leaf audit a chained
  failure produces, and S-86 is the host-env/profile detection warnings [G-42]
  plus the unconditional parse-failure warning (they skip like the other
  network scenarios when child->proxy loopback is blocked; only S-81 dials the
  internet — S-85 and S-86 stay on the loopback with a dead upstream).
  Plan slots S-73/S-74 moved to S-82/S-83 (the
  MXC journal scenarios took those numbers on this branch after the plan was
  written) — see the numbering note above the S-72 section.
  S-87..S-92 (ADR-0001 Task 5.3) close the D-1 pipeline coverage: S-87 (plan
  S-84) deny_domain beats a wildcard allow, S-88 (plan S-85) learned-deny beats
  deny_domain, S-89 (plan S-86) is a DOCUMENTED SKIP for DNS pinning (no
  controlled resolver is available hermetically; the pinning property is pinned
  by three proxy.rs unit tests), S-90 (plan S-87) loopback CONNECT refused even
  when allow-listed, S-91 (plan S-88) a CONNECT with no Proxy-Authorization
  gets the exact 407 + Proxy-Authenticate contract (S-36 covers it loosely),
  and S-92 (plan S-89) prompt_overload is a MANUAL scenario. Plan slots
  S-84..S-89 became S-87..S-92 because S-84..S-86 were already taken on this
  branch - see the numbering note above the S-72 section.
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
  Propagate SANDBOX_DIAG=1 to the child for verbose ACL diagnostics, and
  enable the supervisor-side [G-42] upstream-override notice (S-86 leg b
  depends on it).
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
    param(
        [Parameter(Mandatory)][string[]]$Args,
        [string]$WorkingDirectory = $script:Cwd,
        # Optional child-environment overrides (ADR-0001 Task 4.3). The D-2
        # upstream scenarios must drive the SUPERVISOR's environment, because
        # `select_upstream` reads HTTPS_PROXY/HTTP_PROXY/NO_PROXY from this
        # process — not from the sandboxed child, which always gets the
        # loopback-only proxy vars. A $null value REMOVES the variable (used to
        # drop an inherited SANDBOX_DIAG). Default $null leaves every pre-4.3
        # scenario's environment untouched.
        [hashtable]$Env = $null
    )
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
    if ($null -ne $Env) {
        foreach ($k in @($Env.Keys)) {
            $name = [string]$k
            # Windows env names are case-insensitive but the backing dictionary
            # is not necessarily ordered that way: drop any inherited spelling
            # (e.g. a lowercase `https_proxy`) first, or the child would carry
            # two entries and GetEnvironmentVariableW could pick either.
            foreach ($existing in @($psi.EnvironmentVariables.Keys)) {
                if ([string]::Equals([string]$existing, $name, [System.StringComparison]::OrdinalIgnoreCase)) {
                    $null = $psi.EnvironmentVariables.Remove([string]$existing)
                }
            }
            if ($null -ne $Env[$k]) { $psi.EnvironmentVariables[$name] = [string]$Env[$k] }
        }
    }
    $proc = New-Object System.Diagnostics.Process
    $proc.StartInfo = $psi
    if (-not $proc.Start()) { return @{ Stdout=@(); Stderr=@('failed to start'); ExitCode=-1 } }
    # Read BOTH pipes concurrently: a sequential ReadToEnd on stdout while the
    # child blocks writing a full stderr pipe (or vice versa) deadlocks the
    # child and hangs the harness (observed: S-83 with curl -v stalled >6min).
    $soTask = $proc.StandardOutput.ReadToEndAsync()
    $seTask = $proc.StandardError.ReadToEndAsync()
    # BOUNDED wait: an unbounded WaitForExit turns any supervisor-teardown defect
    # into an indefinite harness hang (observed 2026-10-18: sessions whose child
    # talks to the proxy and ends abnormally — a TLS-abort RST, or a chained 502 —
    # leave sandbox.exe alive; the whole suite stalled). A timed-out child is
    # killed and reported as ExitCode -2 so the scenario fails LOUDLY and fast.
    if (-not $proc.WaitForExit(120000)) {
        try { $proc.Kill() } catch { }
        Start-Sleep -Milliseconds 500
        $so = @($soTask.GetAwaiter().GetResult() -split "`r?`n")
        $se = @($seTask.GetAwaiter().GetResult() -split "`r?`n")
        $se += 'INVOKE-SANDBOX: child did not exit within 120s; killed (supervisor teardown defect)'
        $proc.Close()
        return @{ Stdout=$so; Stderr=$se; ExitCode=-2 }
    }
    $so = @($soTask.GetAwaiter().GetResult() -split "`r?`n")
    $se = @($seTask.GetAwaiter().GetResult() -split "`r?`n")
    $exit = $proc.ExitCode
    $proc.Close()
    return @{ Stdout=$so; Stderr=$se; ExitCode=$exit }
}

# Run a sandbox CLI subcommand with an overridden USERPROFILE — the S-63/
# S-64/S-65 direct-invocation pattern, factored out for the Task 3.8 learned
# scenarios, which must never touch the real %USERPROFILE%\.sandbox\learned\
# store. Returns Stdout/Stderr as single strings + ExitCode.
function Invoke-SandboxCliHome { param([string]$FakeHome, [string]$CliArgs)
    $pi = New-Object System.Diagnostics.ProcessStartInfo
    $pi.FileName = $SandboxExe
    $pi.Arguments = $CliArgs
    $pi.UseShellExecute = $false
    $pi.RedirectStandardOutput = $true
    $pi.RedirectStandardError = $true
    $pi.CreateNoWindow = $true
    $pi.EnvironmentVariables['USERPROFILE'] = $FakeHome
    $proc = [System.Diagnostics.Process]::Start($pi)
    $soTask = $proc.StandardOutput.ReadToEndAsync()
    $seTask = $proc.StandardError.ReadToEndAsync()
    $proc.WaitForExit()
    $stdout = $soTask.GetAwaiter().GetResult()
    $stderr = $seTask.GetAwaiter().GetResult()
    $proc.WaitForExit()
    $rc = $proc.ExitCode
    $proc.Close()
    return @{ Stdout=$stdout; Stderr=$stderr; ExitCode=$rc }
}

# Flatten a captured stream into ONE line, trimmed to $Max characters. Detail
# strings are written with Write-Host on a single line, so a multi-line stderr
# dump (SANDBOX_DIAG runs are verbose) must be collapsed before it lands there.
function Get-LineHead { param([string[]]$Lines, [int]$Max = 240)
    $joined = ((@($Lines) | Where-Object { $_ -and $_.Trim() }) -join ' | ')
    $joined = $joined -replace "`r?`n", ' | '
    if ($joined.Length -gt $Max) { $joined = $joined.Substring(0, $Max) + '...' }
    return $joined
}

# Inner script for the raw CONNECT probe below (ADR-0001 Task 4.3). It runs
# INSIDE the sandbox (the S-75 wrapper-file precedent), so it needs no
# arguments beyond the target host: the session token comes from the injected
# HTTPS_PROXY userinfo and the proxy port from SANDBOX_PROXY_PORT.
#
# Why a raw socket rather than curl: the D-2 upstream-failure response is a
# `502` plus a diagnostic BODY, and a client-side curl on a failed CONNECT
# tunnel never shows that body (it prints "CONNECT tunnel failed, response
# 502" and, under -v, only the headers). Speaking HTTP directly also keeps the
# assertions independent of curl's verbose formatting. The whole response —
# status line, headers, body — is emitted base64-encoded on one line so no
# output framing can mangle it.
$script:ConnectProbeScript = @'
param([string]$TargetHost)
$m = [regex]::Match($env:HTTPS_PROXY, '://sandbox:([^@]+)@')
if (-not $m.Success) { Write-Output 'CONNECT_PROBE_NO_TOKEN'; exit 3 }
$cred = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes('sandbox:' + $m.Groups[1].Value))
$port = [int]$env:SANDBOX_PROXY_PORT
$c = New-Object System.Net.Sockets.TcpClient
try { $c.Connect('127.0.0.1', $port) } catch { Write-Output 'CONNECT_PROBE_DIAL_FAILED'; exit 4 }
$s = $c.GetStream()
$s.ReadTimeout = 10000
$req = "CONNECT ${TargetHost}:443 HTTP/1.1`r`nHost: ${TargetHost}:443`r`nProxy-Authorization: Basic $cred`r`n`r`n"
$bytes = [Text.Encoding]::ASCII.GetBytes($req)
$s.Write($bytes, 0, $bytes.Length)
$s.Flush()
$ms = New-Object System.IO.MemoryStream
$buf = New-Object byte[] 8192
while ($true) {
    $n = 0
    try { $n = $s.Read($buf, 0, $buf.Length) } catch { break }
    if ($n -le 0) { break }
    $ms.Write($buf, 0, $n)
}
$c.Close()
Write-Output ('CONNECT_RAW_B64=' + [Convert]::ToBase64String($ms.ToArray()))
exit 0
'@

# Run the CONNECT probe through the sandbox proxy and decode the response.
# $SandboxArgs must NOT include the `--` separator: the probe invocation is
# appended here. Returns @{ Ok; Raw; ExitCode; Stdout; Stderr }.
function Invoke-ConnectProbe {
    param(
        [Parameter(Mandatory)][string[]]$SandboxArgs,
        [Parameter(Mandatory)][string]$TargetHost,
        [string]$WorkingDirectory = $script:Cwd,
        [hashtable]$Env = $null
    )
    $probePath = Join-Path $WorkingDirectory 'connect-probe.ps1'
    Set-Content -LiteralPath $probePath -Value $script:ConnectProbeScript -Encoding ASCII
    $r = Invoke-Sandbox -Args ($SandboxArgs + @('--','powershell','-NoProfile','-ExecutionPolicy','Bypass','-File','connect-probe.ps1','-TargetHost',$TargetHost)) -WorkingDirectory $WorkingDirectory -Env $Env
    $raw = ''
    $ok = $false
    foreach ($line in @($r.Stdout)) {
        if ($line -like 'CONNECT_RAW_B64=*') {
            try {
                $bytes = [Convert]::FromBase64String($line.Substring($line.IndexOf('=') + 1))
                $raw = [Text.Encoding]::UTF8.GetString($bytes)
                # A read timeout leaves an EMPTY buffer, and an empty buffer still
                # base64-decodes cleanly — so a successful decode is NOT evidence
                # that the proxy answered. Ok requires at least one byte; Raw
                # keeps whatever was decoded either way.
                $ok = ($bytes.Length -gt 0)
            } catch { $ok = $false }
        }
    }
    return @{ Ok = $ok; Raw = $raw; ExitCode = $r.ExitCode
        Stdout = ($r.Stdout -join "`n"); Stderr = ($r.Stderr -join "`n") }
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
# a host that is NOT on the allow-list, so the proxy refuses quickly. If
# curl gets any response (even 000/400) within the timeout, loopback works.
# If curl times out (exit 28), loopback is blocked. The result is cached so
# the US-3 network scenarios skip cleanly (rather than fail the whole suite)
# when the host has not enabled AppContainer loopback.
# Returns $true if loopback-to-proxy works, $false otherwise.
function Test-LoopbackProxyReachable {
    if ($null -ne $script:LoopbackProxyCache) { return $script:LoopbackProxyCache }
    $curl = Get-Curl
    if (-not $curl) {
        # Distinguish "no curl" from "loopback blocked": both skip the same
        # scenarios, but the operator must see WHICH one it was.
        Write-Host '  [probe] curl.exe not found - loopback scenarios will skip'
        $script:LoopbackProxyCache = $false; return $false
    }
    $d = New-ScenarioDir 9999
    $oldNoProxy = $env:NO_PROXY
    $env:NO_PROXY = ''
    # Three attempts with a 15 s timeout. ONE 5 s sample used to decide the fate
    # of ~25 scenarios for the whole run, so a slow first sandbox start (cold
    # cache, AV scan) turned them all into skips while the suite still printed
    # PASS - a green run with silently lost coverage. A real block fails all
    # three; a slow start recovers on the second.
    $attempts = @()
    $reachable = $false
    try {
        for ($i = 1; $i -le 3; $i++) {
            $r = Invoke-Sandbox -Args @('run','--allow-cwd','--allow-domain','api.anthropic.com','--','cmd','/c','curl.exe -s -m 15 -o NUL -w %{http_code} http://denied.invalid/') -WorkingDirectory $d
            $attempts += [int]$r.ExitCode
            if ($r.ExitCode -ne 28) { $reachable = $true; break }
        }
    }
    finally { $env:NO_PROXY = $oldNoProxy }
    $script:LoopbackProxyProbeExitCodes = $attempts
    if (-not $reachable) {
        Write-Host ("  [probe] loopback UNREACHABLE after {0} attempt(s), curl exit codes: {1}" -f $attempts.Count, ($attempts -join ', '))
    }
    elseif ($attempts.Count -gt 1) {
        Write-Host ("  [probe] loopback reachable on attempt {0} (exit codes: {1}) - the first sample was a slow start, NOT a block" -f $attempts.Count, ($attempts -join ', '))
    }
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
# which ADMITS the CONNECT to the listed host. The assertion is that admission
# as the proxy records it: an audit CONNECT leaf for api.anthropic.com with
# disposition=allow and source=allowlist (the allow-list arm of decide(),
# src/net/proxy.rs:654-663 via emit_connect). curl's exit code and
# %{http_connect} are informational Detail only. Why the shift: the CONNECT
# decision is the ADR-0001 D-1 property, while a TLS round trip to a live host
# is ENVIRONMENTAL - with no route to the CRL/OCSP responder the handshake
# fails behind a perfectly good admission (curl exit 35; the same request has
# also been observed as exit 7). --no-prompt keeps an admission regression a
# clean 403 instead of parking the suite on a dialog. Skip if curl.exe is
# absent or loopback-to-proxy is blocked.
function Invoke-Scenario-S27 {
    if (-not (Get-Curl)) { return @{ Num=27; Name='S-27 (AC-3.3)'; Passed=$true; Skipped=$true; Detail='curl.exe not on PATH' } }
    if (-not (Test-LoopbackProxyReachable)) { return @{ Num=27; Name='S-27 (AC-3.3)'; Passed=$true; Skipped=$true; Detail='AppContainer loopback blocked — run tests elevated or with admin loopback exemption' } }
    $d = New-ScenarioDir 27
    $flags = @('run','--allow-cwd','--allow-domain','api.anthropic.com','--no-prompt')
    $psid = Invoke-Sandbox -Args ($flags + @('--print-sid','--','cmd','/c','echo','init')) -WorkingDirectory $d
    if ($psid.ExitCode -ne 0) { return @{ Num=27; Name='S-27 (AC-3.3)'; Passed=$false; Skipped=$false; Detail="print-sid failed exit=$($psid.ExitCode)" } }
    $sid = ($psid.Stdout -join '').Trim()
    # Exactly one %{...} curl variable: cmd.exe expands only DEFINED %VAR%
    # names, so %{http_connect} reaches curl literally on the /c line (checked
    # against curl 8.18 / cmd.exe) - no extra escaping is needed.
    $r = Invoke-Sandbox -Args ($flags + @('--sid',$sid,'--','cmd','/c','curl.exe -s -m 15 -o NUL -w %{http_connect} https://api.anthropic.com/v1/messages')) -WorkingDirectory $d
    $info = (($r.Stdout -join '') -replace '\s','')
    $s = Invoke-Sandbox -Args @('audit','show',$sid,'--json')
    $allowLeaf = $false
    foreach ($l in @($s.Stdout | Where-Object { $_.Trim() })) {
        try { $o = $l | ConvertFrom-Json } catch { continue }
        if ($o.op -eq 'CONNECT' -and $o.host -eq 'api.anthropic.com' -and $o.disposition -eq 'allow' -and $o.source -eq 'allowlist') { $allowLeaf = $true }
    }
    $passed = $allowLeaf
    return @{ Num=27; Name='S-27 (AC-3.3)'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { "proxy admitted api.anthropic.com (audit: disposition=allow source=allowlist); curl info: http_connect='$info' exit=$($r.ExitCode)" }
                 else { "no disposition=allow/source=allowlist CONNECT leaf for api.anthropic.com (sid=$sid exit=$($r.ExitCode) http_connect='$info') audit=$(Get-LineHead -Lines $s.Stderr -Max 120)" } }
}

# S-28: AC-3.4 — allow-domain denies an unlisted host.
# PASS iff the PROXY is seen refusing evil.example.com: either curl's CONNECT
# response is 403 (%{http_connect}) or the audit holds a CONNECT deny leaf for
# that host. A bare "curl exited non-zero with http_code 000" is NOT accepted
# any more: every transport failure satisfies it, which is the signature this
# host produces when the network is unreachable (exit 7, and exit 35 behind an
# admitted tunnel) - the old form passed without the proxy ever seeing the
# request, a false pass by construction. --no-prompt pins the decision to the
# policy's own deny [G-48] (source=default, reason "prompting disabled; host
# not allow-listed") instead of a dialog-backend timeout, so the leaf is
# deterministic. Detail separates "no proxy signal - request never reached the
# proxy" from "denied". Why the shift: the CONNECT decision is the ADR-0001 D-1
# property, while a TLS round trip to a live host is ENVIRONMENTAL - no route
# to the CRL/OCSP responder (curl exit 35; the same request has also been
# observed as exit 7). Skip if curl.exe is absent or loopback-to-proxy blocked.
function Invoke-Scenario-S28 {
    if (-not (Get-Curl)) { return @{ Num=28; Name='S-28 (AC-3.4)'; Passed=$true; Skipped=$true; Detail='curl.exe not on PATH' } }
    if (-not (Test-LoopbackProxyReachable)) { return @{ Num=28; Name='S-28 (AC-3.4)'; Passed=$true; Skipped=$true; Detail='AppContainer loopback blocked — run tests elevated or with admin loopback exemption' } }
    $d = New-ScenarioDir 28
    $flags = @('run','--allow-cwd','--allow-domain','api.anthropic.com','--no-prompt')
    $psid = Invoke-Sandbox -Args ($flags + @('--print-sid','--','cmd','/c','echo','init')) -WorkingDirectory $d
    if ($psid.ExitCode -ne 0) { return @{ Num=28; Name='S-28 (AC-3.4)'; Passed=$false; Skipped=$false; Detail="print-sid failed exit=$($psid.ExitCode)" } }
    $sid = ($psid.Stdout -join '').Trim()
    $r = Invoke-Sandbox -Args ($flags + @('--sid',$sid,'--','cmd','/c','curl.exe -s -m 15 -o NUL -w %{http_connect} https://evil.example.com')) -WorkingDirectory $d
    $connect = (($r.Stdout -join '') -replace '\s','')
    $s = Invoke-Sandbox -Args @('audit','show',$sid,'--json')
    $denyLeaf = $false
    $leafSource = ''
    foreach ($l in @($s.Stdout | Where-Object { $_.Trim() })) {
        try { $o = $l | ConvertFrom-Json } catch { continue }
        if ($o.op -eq 'CONNECT' -and $o.host -eq 'evil.example.com' -and $o.disposition -eq 'deny') { $denyLeaf = $true; $leafSource = [string]$o.source }
    }
    # Two acceptable proxy signals: the 403 on the CONNECT response, or the
    # admission-time deny leaf. Neither can exist if the request never arrived.
    $got403 = ($connect -eq '403')
    $passed = $got403 -or $denyLeaf
    $noSignal = (-not $passed) -and ($connect -eq '' -or $connect -eq '000')
    return @{ Num=28; Name='S-28 (AC-3.4)'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { "proxy refused evil.example.com (http_connect='$connect', audit deny leaf=$denyLeaf source='$leafSource'); no transport-failure pass" }
                 elseif ($noSignal) { "NO PROXY SIGNAL - request never reached the proxy (exit=$($r.ExitCode) http_connect='$connect', no deny leaf; sid=$sid) - this is exactly the old false pass" }
                 else { "no denial from the proxy: exit=$($r.ExitCode) http_connect='$connect' denyLeaf=$denyLeaf (expected 403 or an audit deny leaf)" } }
}

# S-29: AC-3.5 — wildcard suffix matches, dot-bounded.
# `*.anthropic.com` matches the subdomain api.anthropic.com. Same assertion
# shape as S-27: the proxy's admission, read from the audit - a CONNECT leaf
# for api.anthropic.com with disposition=allow and source=allowlist
# (src/net/proxy.rs:654-663, matcher::check owns the [G-55] wildcard rule). The
# wildcard is what the allow-list arm consumed; the leaf proves the pipeline
# admitted the host the wildcard covered. curl exit / %{http_connect} are
# informational only. Why the shift: the CONNECT decision is the ADR-0001 D-1
# property, while a TLS round trip to a live host is ENVIRONMENTAL - no route
# to the CRL/OCSP responder (curl exit 35; the same request has also been
# observed as exit 7). --no-prompt keeps a wildcard regression a clean 403.
# Skip if curl.exe is absent or loopback-to-proxy is blocked.
function Invoke-Scenario-S29 {
    if (-not (Get-Curl)) { return @{ Num=29; Name='S-29 (AC-3.5)'; Passed=$true; Skipped=$true; Detail='curl.exe not on PATH' } }
    if (-not (Test-LoopbackProxyReachable)) { return @{ Num=29; Name='S-29 (AC-3.5)'; Passed=$true; Skipped=$true; Detail='AppContainer loopback blocked — run tests elevated or with admin loopback exemption' } }
    $d = New-ScenarioDir 29
    $flags = @('run','--allow-cwd','--allow-domain','*.anthropic.com','--no-prompt')
    $psid = Invoke-Sandbox -Args ($flags + @('--print-sid','--','cmd','/c','echo','init')) -WorkingDirectory $d
    if ($psid.ExitCode -ne 0) { return @{ Num=29; Name='S-29 (AC-3.5)'; Passed=$false; Skipped=$false; Detail="print-sid failed exit=$($psid.ExitCode)" } }
    $sid = ($psid.Stdout -join '').Trim()
    $r = Invoke-Sandbox -Args ($flags + @('--sid',$sid,'--','cmd','/c','curl.exe -s -m 15 -o NUL -w %{http_connect} https://api.anthropic.com/v1/messages')) -WorkingDirectory $d
    $info = (($r.Stdout -join '') -replace '\s','')
    $s = Invoke-Sandbox -Args @('audit','show',$sid,'--json')
    $allowLeaf = $false
    foreach ($l in @($s.Stdout | Where-Object { $_.Trim() })) {
        try { $o = $l | ConvertFrom-Json } catch { continue }
        if ($o.op -eq 'CONNECT' -and $o.host -eq 'api.anthropic.com' -and $o.disposition -eq 'allow' -and $o.source -eq 'allowlist') { $allowLeaf = $true }
    }
    $passed = $allowLeaf
    return @{ Num=29; Name='S-29 (AC-3.5)'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { "wildcard *.anthropic.com admitted api.anthropic.com (audit: disposition=allow source=allowlist); curl info: http_connect='$info' exit=$($r.ExitCode)" }
                 else { "no disposition=allow/source=allowlist CONNECT leaf for api.anthropic.com (sid=$sid exit=$($r.ExitCode) http_connect='$info') audit=$(Get-LineHead -Lines $s.Stderr -Max 120)" } }
}

# S-30: AC-3.6 — always-denied overrides explicit allow.
# 169.254.169.254 is in the hard-deny CIDR list; explicit --allow-domain is
# overridden. PASS if curl fails (denied).
function Invoke-Scenario-S30 {
    if (-not (Get-Curl)) { return @{ Num=30; Name='S-30 (AC-3.6)'; Passed=$true; Skipped=$true; Detail='curl.exe not on PATH' } }
    if (-not (Test-LoopbackProxyReachable)) { return @{ Num=30; Name='S-30 (AC-3.6)'; Passed=$true; Skipped=$true; Detail='AppContainer loopback blocked — run tests elevated or with admin loopback exemption' } }
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
    if (-not (Test-LoopbackProxyReachable)) { return @{ Num=31; Name='S-31 (AC-3.7)'; Passed=$true; Skipped=$true; Detail='AppContainer loopback blocked — run tests elevated or with admin loopback exemption' } }
    $d = New-ScenarioDir 31
    $r = Invoke-Sandbox -Args @('run','--allow-cwd','--allow-domain','metadata.google.internal','--','cmd','/c','curl.exe -s -m 15 -o NUL -w %{http_code} https://metadata.google.internal') -WorkingDirectory $d
    $code = (($r.Stdout -join '') -replace '\s','')
    $denied = ($r.ExitCode -ne 0) -and ($code -eq '000' -or $code -eq '')
    $passed = $denied
    return @{ Num=31; Name='S-31 (AC-3.7)'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { "metadata.google.internal denied" } else { "exit=$($r.ExitCode) http_code=$code (expected denial)" } }
}

# S-32: AC-3.8 — minimal profile allows LLM APIs, denies github.
# `--network-profile minimal` admits api.anthropic.com and does not admit
# github.com. BOTH halves are asserted as the PROXY's decision, in two sessions
# with stable sids. Allowed host: an audit CONNECT leaf disposition=allow
# source=allowlist - a profile entry lands in the same list the CLI flag feeds
# (src/net/mod.rs:97-98) and the allow-list arm is the only arm that emits
# "allowlist" (src/net/proxy.rs:654-663), so that is the string the code
# actually emits for a profile-granted host. Denied host: an observed refusal,
# %{http_connect}=403 or an audit CONNECT deny leaf for github.com.
# --no-prompt makes the deny the policy's own [G-48] deny (source=default,
# reason "prompting disabled; host not allow-listed") instead of a
# dialog-backend timeout. curl exit/http codes are informational only. Why the
# shift: the CONNECT decision is the ADR-0001 D-1 property, while a TLS round
# trip to a live host is ENVIRONMENTAL - no route to the CRL/OCSP responder
# (curl exit 35; the same request has also been observed as exit 7). Skip if
# curl.exe is absent or loopback-to-proxy is blocked.
function Invoke-Scenario-S32 {
    if (-not (Get-Curl)) { return @{ Num=32; Name='S-32 (AC-3.8)'; Passed=$true; Skipped=$true; Detail='curl.exe not on PATH' } }
    if (-not (Test-LoopbackProxyReachable)) { return @{ Num=32; Name='S-32 (AC-3.8)'; Passed=$true; Skipped=$true; Detail='AppContainer loopback blocked — run tests elevated or with admin loopback exemption' } }
    $d = New-ScenarioDir 32
    $flags = @('run','--allow-cwd','--network-profile','minimal','--no-prompt')
    $psidA = Invoke-Sandbox -Args ($flags + @('--print-sid','--','cmd','/c','echo','init')) -WorkingDirectory $d
    if ($psidA.ExitCode -ne 0) { return @{ Num=32; Name='S-32 (AC-3.8)'; Passed=$false; Skipped=$false; Detail="print-sid (allow leg) failed exit=$($psidA.ExitCode)" } }
    $sidA = ($psidA.Stdout -join '').Trim()
    $rA = Invoke-Sandbox -Args ($flags + @('--sid',$sidA,'--','cmd','/c','curl.exe -s -m 15 -o NUL -w %{http_connect} https://api.anthropic.com/v1/messages')) -WorkingDirectory $d
    $infoA = (($rA.Stdout -join '') -replace '\s','')
    $sA = Invoke-Sandbox -Args @('audit','show',$sidA,'--json')
    $allowLeaf = $false
    foreach ($l in @($sA.Stdout | Where-Object { $_.Trim() })) {
        try { $o = $l | ConvertFrom-Json } catch { continue }
        if ($o.op -eq 'CONNECT' -and $o.host -eq 'api.anthropic.com' -and $o.disposition -eq 'allow' -and $o.source -eq 'allowlist') { $allowLeaf = $true }
    }
    $psidB = Invoke-Sandbox -Args ($flags + @('--print-sid','--','cmd','/c','echo','init')) -WorkingDirectory $d
    if ($psidB.ExitCode -ne 0) { return @{ Num=32; Name='S-32 (AC-3.8)'; Passed=$false; Skipped=$false; Detail="print-sid (deny leg) failed exit=$($psidB.ExitCode)" } }
    $sidB = ($psidB.Stdout -join '').Trim()
    $rB = Invoke-Sandbox -Args ($flags + @('--sid',$sidB,'--','cmd','/c','curl.exe -s -m 15 -o NUL -w %{http_connect} https://github.com')) -WorkingDirectory $d
    $connectB = (($rB.Stdout -join '') -replace '\s','')
    $sB = Invoke-Sandbox -Args @('audit','show',$sidB,'--json')
    $denyLeaf = $false
    $denySource = ''
    $denyReason = ''
    foreach ($l in @($sB.Stdout | Where-Object { $_.Trim() })) {
        try { $o = $l | ConvertFrom-Json } catch { continue }
        if ($o.op -eq 'CONNECT' -and $o.host -eq 'github.com' -and $o.disposition -eq 'deny') { $denyLeaf = $true; $denySource = [string]$o.source; $denyReason = [string]$o.reason }
    }
    $got403 = ($connectB -eq '403')
    $deniedOk = $got403 -or $denyLeaf
    $passed = $allowLeaf -and $deniedOk
    return @{ Num=32; Name='S-32 (AC-3.8)'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { "minimal: api.anthropic.com admitted (allow/allowlist), github.com refused (http_connect='$connectB' denyLeaf=$denyLeaf source='$denySource' reason='$denyReason'); curl info exit=$($rA.ExitCode)/$($rB.ExitCode)" }
                 else { "minimal: allowLeaf=$allowLeaf (http_connect='$infoA' exit=$($rA.ExitCode)) github403=$got403 denyLeaf=$denyLeaf (source='$denySource' reason='$denyReason' http_connect='$connectB' exit=$($rB.ExitCode)) sidA=$sidA sidB=$sidB" } }
}

# S-33: AC-3.9 — developer profile adds registries + github.
# `--network-profile developer` admits api.anthropic.com AND github.com (the
# developer list is minimal plus the registries and github; see
# builtin_profile in src/net/profile.rs). Both halves are asserted as the
# PROXY's decision in two stable-sid sessions: an audit CONNECT leaf
# disposition=allow source=allowlist for each host - profile entries feed the
# same allow list the CLI flag does (src/net/mod.rs:97-98) and the allow-list
# arm is the only arm that emits "allowlist" (src/net/proxy.rs:654-663). curl
# exit / %{http_connect} are informational only. Why the shift: the
# CONNECT decision is the ADR-0001 D-1 property, while a TLS round trip to a
# live host is ENVIRONMENTAL - no route to the CRL/OCSP responder (curl exit
# 35; the same request has also been observed as exit 7). --no-prompt keeps
# a regression a clean 403 instead of a dialog. Skip if curl.exe is absent
# or loopback-to-proxy is blocked.
function Invoke-Scenario-S33 {
    if (-not (Get-Curl)) { return @{ Num=33; Name='S-33 (AC-3.9)'; Passed=$true; Skipped=$true; Detail='curl.exe not on PATH' } }
    if (-not (Test-LoopbackProxyReachable)) { return @{ Num=33; Name='S-33 (AC-3.9)'; Passed=$true; Skipped=$true; Detail='AppContainer loopback blocked — run tests elevated or with admin loopback exemption' } }
    $d = New-ScenarioDir 33
    $flags = @('run','--allow-cwd','--network-profile','developer','--no-prompt')
    $psidA = Invoke-Sandbox -Args ($flags + @('--print-sid','--','cmd','/c','echo','init')) -WorkingDirectory $d
    if ($psidA.ExitCode -ne 0) { return @{ Num=33; Name='S-33 (AC-3.9)'; Passed=$false; Skipped=$false; Detail="print-sid (anthropic leg) failed exit=$($psidA.ExitCode)" } }
    $sidA = ($psidA.Stdout -join '').Trim()
    $rA = Invoke-Sandbox -Args ($flags + @('--sid',$sidA,'--','cmd','/c','curl.exe -s -m 15 -o NUL -w %{http_connect} https://api.anthropic.com')) -WorkingDirectory $d
    $infoA = (($rA.Stdout -join '') -replace '\s','')
    $sA = Invoke-Sandbox -Args @('audit','show',$sidA,'--json')
    $leafA = $false
    foreach ($l in @($sA.Stdout | Where-Object { $_.Trim() })) {
        try { $o = $l | ConvertFrom-Json } catch { continue }
        if ($o.op -eq 'CONNECT' -and $o.host -eq 'api.anthropic.com' -and $o.disposition -eq 'allow' -and $o.source -eq 'allowlist') { $leafA = $true }
    }
    $psidB = Invoke-Sandbox -Args ($flags + @('--print-sid','--','cmd','/c','echo','init')) -WorkingDirectory $d
    if ($psidB.ExitCode -ne 0) { return @{ Num=33; Name='S-33 (AC-3.9)'; Passed=$false; Skipped=$false; Detail="print-sid (github leg) failed exit=$($psidB.ExitCode)" } }
    $sidB = ($psidB.Stdout -join '').Trim()
    $rB = Invoke-Sandbox -Args ($flags + @('--sid',$sidB,'--','cmd','/c','curl.exe -s -m 15 -o NUL -w %{http_connect} https://github.com')) -WorkingDirectory $d
    $infoB = (($rB.Stdout -join '') -replace '\s','')
    $sB = Invoke-Sandbox -Args @('audit','show',$sidB,'--json')
    $leafB = $false
    foreach ($l in @($sB.Stdout | Where-Object { $_.Trim() })) {
        try { $o = $l | ConvertFrom-Json } catch { continue }
        if ($o.op -eq 'CONNECT' -and $o.host -eq 'github.com' -and $o.disposition -eq 'allow' -and $o.source -eq 'allowlist') { $leafB = $true }
    }
    $passed = $leafA -and $leafB
    return @{ Num=33; Name='S-33 (AC-3.9)'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { "developer: audit allow/allowlist for api.anthropic.com AND github.com; curl info http_connect='$infoA'/'$infoB' exit=$($rA.ExitCode)/$($rB.ExitCode)" }
                 else { "developer: anthropicLeaf=$leafA (http_connect='$infoA' exit=$($rA.ExitCode)) githubLeaf=$leafB (http_connect='$infoB' exit=$($rB.ExitCode)) sidA=$sidA sidB=$sidB" } }
}

# S-34: AC-3.10 — profile + CLI flags merge.
# `--network-profile minimal --allow-domain github.com`: minimal admits
# api.anthropic.com, the CLI flag adds github.com. The MERGE is the property,
# so both hosts are asserted as the PROXY's decision in two stable-sid
# sessions, each with the identical flag set: an audit CONNECT leaf
# disposition=allow source=allowlist per host. Both leaves carry the same
# "allowlist" source because the merge happens before matching - the profile
# list and the CLI list are concatenated into one allow list
# (src/net/mod.rs:97-98) consumed by the allow-list arm
# (src/net/proxy.rs:654-663); a dropped profile half fails the anthropic leaf,
# a dropped CLI half fails the github leaf. curl exit / %{http_connect} are
# informational only. Why the shift: the CONNECT decision is the ADR-0001 D-1
# property, while a TLS round trip to a live host is ENVIRONMENTAL - no route
# to the CRL/OCSP responder (curl exit 35; the same request has also been
# observed as exit 7). --no-prompt keeps a regression a clean 403. Skip if
# curl.exe is absent or loopback-to-proxy is blocked.
function Invoke-Scenario-S34 {
    if (-not (Get-Curl)) { return @{ Num=34; Name='S-34 (AC-3.10)'; Passed=$true; Skipped=$true; Detail='curl.exe not on PATH' } }
    if (-not (Test-LoopbackProxyReachable)) { return @{ Num=34; Name='S-34 (AC-3.10)'; Passed=$true; Skipped=$true; Detail='AppContainer loopback blocked — run tests elevated or with admin loopback exemption' } }
    $d = New-ScenarioDir 34
    $flags = @('run','--allow-cwd','--network-profile','minimal','--allow-domain','github.com','--no-prompt')
    $psidA = Invoke-Sandbox -Args ($flags + @('--print-sid','--','cmd','/c','echo','init')) -WorkingDirectory $d
    if ($psidA.ExitCode -ne 0) { return @{ Num=34; Name='S-34 (AC-3.10)'; Passed=$false; Skipped=$false; Detail="print-sid (profile leg) failed exit=$($psidA.ExitCode)" } }
    $sidA = ($psidA.Stdout -join '').Trim()
    $rA = Invoke-Sandbox -Args ($flags + @('--sid',$sidA,'--','cmd','/c','curl.exe -s -m 15 -o NUL -w %{http_connect} https://api.anthropic.com')) -WorkingDirectory $d
    $infoA = (($rA.Stdout -join '') -replace '\s','')
    $sA = Invoke-Sandbox -Args @('audit','show',$sidA,'--json')
    $leafA = $false
    foreach ($l in @($sA.Stdout | Where-Object { $_.Trim() })) {
        try { $o = $l | ConvertFrom-Json } catch { continue }
        if ($o.op -eq 'CONNECT' -and $o.host -eq 'api.anthropic.com' -and $o.disposition -eq 'allow' -and $o.source -eq 'allowlist') { $leafA = $true }
    }
    $psidB = Invoke-Sandbox -Args ($flags + @('--print-sid','--','cmd','/c','echo','init')) -WorkingDirectory $d
    if ($psidB.ExitCode -ne 0) { return @{ Num=34; Name='S-34 (AC-3.10)'; Passed=$false; Skipped=$false; Detail="print-sid (CLI leg) failed exit=$($psidB.ExitCode)" } }
    $sidB = ($psidB.Stdout -join '').Trim()
    $rB = Invoke-Sandbox -Args ($flags + @('--sid',$sidB,'--','cmd','/c','curl.exe -s -m 15 -o NUL -w %{http_connect} https://github.com')) -WorkingDirectory $d
    $infoB = (($rB.Stdout -join '') -replace '\s','')
    $sB = Invoke-Sandbox -Args @('audit','show',$sidB,'--json')
    $leafB = $false
    foreach ($l in @($sB.Stdout | Where-Object { $_.Trim() })) {
        try { $o = $l | ConvertFrom-Json } catch { continue }
        if ($o.op -eq 'CONNECT' -and $o.host -eq 'github.com' -and $o.disposition -eq 'allow' -and $o.source -eq 'allowlist') { $leafB = $true }
    }
    $passed = $leafA -and $leafB
    return @{ Num=34; Name='S-34 (AC-3.10)'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { "profile+CLI merged: audit allow/allowlist for api.anthropic.com (profile) AND github.com (CLI flag); curl info http_connect='$infoA'/'$infoB' exit=$($rA.ExitCode)/$($rB.ExitCode)" }
                 else { "merge incomplete: profileLeaf(anthropic)=$leafA (http_connect='$infoA' exit=$($rA.ExitCode)) cliLeaf(github)=$leafB (http_connect='$infoB' exit=$($rB.ExitCode)) sidA=$sidA sidB=$sidB" } }
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
# The child overrides the proxy URL with curl's -x, pointing at the injected
# proxy port (SANDBOX_PROXY_PORT, set for the child) WITHOUT userinfo, so no
# Proxy-Authorization header is sent. The assertion is the supervisor's own
# token gate, in two independent places: (a) the client must see 407 on the
# CONNECT - %{http_connect}, with curl exit 97 or "407" on stderr accepted as
# equivalent evidence since curl retries a 407 and can disguise the first
# response; (b) the audit must carry the gate's leaf - disposition=deny,
# reason=no_token, source=default, host '<unknown>' - and NO admission leaf
# for the probed host (src/net/proxy.rs:1102-1111; the gate writes before any
# decide(), so an absent admission leaf proves nothing was admitted). A gate
# that stops rejecting fails (a); a gate placed after admission fails (b).
# %{http_connect} rather than %{http_code}: on a refused tunnel http_code stays
# 000, which is indistinguishable from a transport failure. Why the shift: the
# CONNECT decision is the ADR-0001 D-1 property, while a TLS round trip to a
# live host is ENVIRONMENTAL (no route to the CRL/OCSP responder, curl exit 35;
# the same request has also been observed as exit 7) - exit 000 alone proved
# nothing. --no-prompt only keeps a regressed gate from parking on a dialog.
# Skip if curl.exe is absent or loopback-to-proxy is blocked.
function Invoke-Scenario-S36 {
    if (-not (Get-Curl)) { return @{ Num=36; Name='S-36 (AC-3.12)'; Passed=$true; Skipped=$true; Detail='curl.exe not on PATH' } }
    if (-not (Test-LoopbackProxyReachable)) { return @{ Num=36; Name='S-36 (AC-3.12)'; Passed=$true; Skipped=$true; Detail='AppContainer loopback blocked — run tests elevated or with admin loopback exemption' } }
    $d = New-ScenarioDir 36
    $flags = @('run','--allow-cwd','--allow-domain','api.anthropic.com','--no-prompt')
    $psid = Invoke-Sandbox -Args ($flags + @('--print-sid','--','cmd','/c','echo','init')) -WorkingDirectory $d
    if ($psid.ExitCode -ne 0) { return @{ Num=36; Name='S-36 (AC-3.12)'; Passed=$false; Skipped=$false; Detail="print-sid failed exit=$($psid.ExitCode)" } }
    $sid = ($psid.Stdout -join '').Trim()
    # %SANDBOX_PROXY_PORT% is a defined cmd variable and expands; cmd does NOT
    # expand %{http_connect} (undefined name), so it reaches curl intact -
    # verified with curl 8.18 + cmd.exe on the /c command line.
    $r = Invoke-Sandbox -Args ($flags + @('--sid',$sid,'--','cmd','/c','curl.exe -s -m 10 -x http://127.0.0.1:%SANDBOX_PROXY_PORT% -o NUL -w %{http_connect} https://api.anthropic.com/v1/messages')) -WorkingDirectory $d
    $connect = (($r.Stdout -join '') -replace '\s','')
    $stderr = ($r.Stderr -join "`n")
    $s = Invoke-Sandbox -Args @('audit','show',$sid,'--json')
    $tokenLeaf = $false
    $admissionLeaf = $false
    foreach ($l in @($s.Stdout | Where-Object { $_.Trim() })) {
        try { $o = $l | ConvertFrom-Json } catch { continue }
        if ($o.op -ne 'CONNECT') { continue }
        if ($o.disposition -eq 'deny' -and $o.reason -eq 'no_token' -and $o.source -eq 'default' -and $o.host -eq '<unknown>') { $tokenLeaf = $true }
        if ($o.host -eq 'api.anthropic.com') { $admissionLeaf = $true }
    }
    $client407 = ($connect -eq '407') -or ($r.ExitCode -eq 97) -or ($stderr -match '407')
    $passed = $client407 -and $tokenLeaf -and (-not $admissionLeaf)
    return @{ Num=36; Name='S-36 (AC-3.12)'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { "token gate refused the unauthenticated CONNECT (http_connect='$connect' exit=$($r.ExitCode)); audit default/no_token host=<unknown>, no admission leaf for api.anthropic.com" }
                 else { "client407=$client407 (http_connect='$connect' exit=$($r.ExitCode)) tokenLeaf=$tokenLeaf admissionLeaf=$admissionLeaf sid=$sid" } }
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
    if (-not (Test-LoopbackProxyReachable)) { return @{ Num=38; Name='S-38 (AC-3.14)'; Passed=$true; Skipped=$true; Detail='AppContainer loopback blocked — run tests elevated or with admin loopback exemption' } }
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
    if (-not (Test-LoopbackProxyReachable)) { return @{ Num=46; Name='S-46 (AC-4.6)'; Passed=$true; Skipped=$true; Detail='AppContainer loopback blocked — run tests elevated or with admin loopback exemption' } }
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
    # Kept as a direct invocation (this scenario predates Invoke-Sandbox's -Env
    # switch): the USERPROFILE override is the one Invoke-SandboxCliHome applies.
    # `$SandboxExe` is the script-scope param (see harness top-level param block).
    $pi = New-Object System.Diagnostics.ProcessStartInfo
    $pi.FileName = $SandboxExe
    $pi.Arguments = 'profile list'
    $pi.UseShellExecute = $false
    $pi.RedirectStandardOutput = $true
    $pi.RedirectStandardError = $true
    $pi.EnvironmentVariables['USERPROFILE'] = $fakeHome
    $proc = [System.Diagnostics.Process]::Start($pi)
    $soTask = $proc.StandardOutput.ReadToEndAsync()
    $seTask = $proc.StandardError.ReadToEndAsync()
    $proc.WaitForExit()
    $stdout = $soTask.GetAwaiter().GetResult()
    $stderr = $seTask.GetAwaiter().GetResult()
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
    $seTask = $proc.StandardError.ReadToEndAsync()
    $stdout = $proc.StandardOutput.ReadToEnd()
    $proc.WaitForExit()
    [void]$seTask.GetAwaiter().GetResult()
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
    $seTask = $proc.StandardError.ReadToEndAsync()
    $stdout = $proc.StandardOutput.ReadToEnd()
    $proc.WaitForExit()
    [void]$seTask.GetAwaiter().GetResult()
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
# Dispatched-vector scenarios end at S-71; higher numbers register in
# $script:ScenarioFunctions below (numbering above S-71 is per-branch).
#
# ADR-0001 Task 3.8 numbering note: the plan (2026-07-30) numbered its new
# network scenarios S-72..S-80, but the MXC journal scenarios took S-73/S-74
# on this branch on 2026-09-19 (commit 9970ef4, post-dating the plan), so
# the two colliding plan slots moved to the next free numbers: plan S-73
# (hard-deny expansion) -> S-82, plan S-74 (wildcard apex) -> S-83. S-72
# keeps the plan's number (the earlier "reserved for LPAC/Task 2" note
# described another branch's harness copy, not this one). S-84 is the extra
# seeded `*.`-prefixed learned-revoke coverage from the 3.7 review advisory.
#
# ADR-0001 Task 4.3 numbering note (same collision, later plan slots): the plan
# numbered its Phase 4 D-2 scenarios S-81/S-82/S-83 and S-82/S-83 were already
# taken by the two 3.8 scenarios moved above, so the mapping is
#   plan S-81 (NO_PROXY bypass)              -> S-81 (free, kept)
#   plan S-82 (upstream unreachable -> 502)  -> S-85
#   plan S-83 (host-env detection + G-42)    -> S-86 (extended with the
#                                               unconditional parse-failure
#                                               warning: an `https://` upstream
#                                               is rejected by design)
# S-85/S-86 keep their numbers free of the 3.8 block on purpose: inserting
# between S-84 and a later phase would renumber again on the next merge.
#
# ADR-0001 Task 5.3 numbering note (same collision, one phase later): the plan
# numbered this final batch S-84..S-89, but S-84/S-85/S-86 are taken by 3.8's
# extra learned-revoke case and 4.3's upstream-unreachable + host-env
# scenarios, so the mapping is
#   plan S-84 (deny_domain over allow)          -> S-87
#   plan S-85 (learned-deny over deny_domain)   -> S-88
#   plan S-86 (DNS pinning, single resolution)  -> S-89 (documented skip)
#   plan S-87 (loopback CONNECT refused)        -> S-90
#   plan S-88 (missing Proxy-Authorization)     -> S-91
#   plan S-89 (prompt_overload, 9 concurrent)   -> S-92 (manual)
# Plan S-84's literal flags are satisfiable as written (unlike 3.8's S-72,
# whose deny pattern could not match its target), so S-87 uses them verbatim.
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
# ADR-0001 Task 3.8 scenarios — integration coverage for the D-1/D-3/D-4/D-5
# prompt + intent + learned wiring (Tasks 3.1..3.7). Every automated network
# scenario passes --no-prompt as harness safety: each asserted policy stage
# (blocklist, hard-deny, loopback, allow-list) runs BEFORE the prompt in the
# proxy pipeline, so a wrong expectation yields a clean deny/allow outcome
# rather than a modal dialog hanging an unattended run. Scenarios skip
# cleanly without curl.exe or AppContainer loopback (the S-27+ convention).
# ---------------------------------------------------------------------------

# S-72 (D-1): deny_domain blocklist — a host on BOTH the allow-list and the
# deny-list is denied with audit source "blocklist" (blocklist precedes the
# allow-list in the pipeline, [G-32/G-33]).
# Plan note: the plan's literal flags (`--deny-domain *.evil.com` aimed at
# evil.example.com) cannot match — matcher::matches is dot-bounded [G-55],
# and the unit suite's deny_domain_wins_over_allow precedent pairs
# `*.example.com` with `evil.example.com`. The deny pattern is therefore
# `*.example.com`; the target is ALSO explicitly allowed so the scenario
# proves deny-wins-over-allow (the plan matrix labels S-72 "deny_domain
# precedence").
function Invoke-Scenario-S72 {
    if (-not (Get-Curl)) { return @{ Num=72; Name='S-72 (D-1 deny_domain)'; Passed=$true; Skipped=$true; Detail='curl.exe not on PATH' } }
    if (-not (Test-LoopbackProxyReachable)) { return @{ Num=72; Name='S-72 (D-1 deny_domain)'; Passed=$true; Skipped=$true; Detail='AppContainer loopback blocked — run tests elevated or with admin loopback exemption' } }
    $d = New-ScenarioDir 72
    $flags = @('run','--allow-cwd',
        '--allow-domain','api.anthropic.com',
        '--allow-domain','evil.example.com',
        '--deny-domain','*.example.com',
        '--no-prompt')
    $psid = Invoke-Sandbox -Args ($flags + @('--print-sid','--','cmd','/c','echo','placeholder')) -WorkingDirectory $d
    if ($psid.ExitCode -ne 0) { return @{ Num=72; Name='S-72 (D-1 deny_domain)'; Passed=$false; Skipped=$false; Detail="print-sid failed exit=$($psid.ExitCode)" } }
    $sid = ($psid.Stdout -join '').Trim()
    $r = Invoke-Sandbox -Args ($flags + @('--sid',$sid,'--','cmd','/c','curl.exe -s -m 15 -o NUL -w %{http_code} https://evil.example.com')) -WorkingDirectory $d
    $code = (($r.Stdout -join '') -replace '\s','')
    $denied = ($r.ExitCode -ne 0) -and ($code -eq '000' -or $code -eq '')
    # The audit must attribute the deny to the blocklist stage (not
    # prompt/default) — that attribution is the D-5 half of the assertion.
    $s = Invoke-Sandbox -Args @('audit','show',$sid,'--json')
    $blocklistSeen = $false
    foreach ($l in @($s.Stdout | Where-Object { $_.Trim() })) {
        try { $o = $l | ConvertFrom-Json } catch { continue }
        if ($o.op -eq 'CONNECT' -and $o.disposition -eq 'deny' -and $o.source -eq 'blocklist' -and $o.host -eq 'evil.example.com') { $blocklistSeen = $true }
    }
    $passed = $denied -and $blocklistSeen
    return @{ Num=72; Name='S-72 (D-1 deny_domain)'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { 'deny_domain beat the explicit allow; audit source=blocklist' }
                 else { "denied=$denied blocklistAudit=$blocklistSeen exit=$($r.ExitCode) code=$code sid=$sid" } }
}

# S-75 (D-1): a CONNECT to a loopback target is refused pre-prompt with
# 403 + `X-Sandbox: denied` [G-44/G-52]. The inner script (S-21's wrapper-file
# precedent, written into the scenario dir under --allow-cwd) speaks the
# CONNECT itself over a raw TcpClient and authenticates with the session token
# from the injected HTTPS_PROXY userinfo, so it clears the 407 token gate and
# reaches the admission pipeline. No native command appears anywhere: curl's
# own retry and proxy-bypass behaviour is exactly what this scenario controls
# for, and 5.1 cannot invoke native commands inside the AppContainer anyway.
function Invoke-Scenario-S75 {
    if (-not (Test-LoopbackProxyReachable)) { return @{ Num=75; Name='S-75 (D-1 loopback CONNECT)'; Passed=$true; Skipped=$true; Detail='proxy loopback probe failed - EITHER AppContainer loopback is blocked (run tests elevated or with the admin loopback exemption) OR curl.exe is not on PATH (the shared probe shells out to curl; this scenario speaks CONNECT without it)' } }
    $d = New-ScenarioDir 75
    $inner = @'
$m = [regex]::Match($env:HTTPS_PROXY, '://sandbox:([^@]+)@')
if (-not $m.Success) { Write-Output 'S75_NO_TOKEN'; exit 3 }
$port = 0
if (-not [int]::TryParse([string]$env:SANDBOX_PROXY_PORT, [ref]$port) -or $port -le 0) { Write-Output 'S75_NO_PORT'; exit 3 }
$creds = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes('sandbox:' + $m.Groups[1].Value))
# Exit 3 = the proxy was never reached (no connection, or no bytes back);
# exit 4 = connected but nothing arrived inside the read timeout. The harness
# distinguishes the two in the failure detail.
$c = New-Object System.Net.Sockets.TcpClient
try { $c.Connect('127.0.0.1', $port) } catch { Write-Output 'S75_DIAL_FAILED'; exit 3 }
$s = $c.GetStream()
$s.ReadTimeout = 10000
$s.WriteTimeout = 10000
$req = "CONNECT 127.0.0.1:5432 HTTP/1.1`r`nHost: 127.0.0.1:5432`r`nProxy-Authorization: Basic $creds`r`n`r`n"
$bytes = [Text.Encoding]::ASCII.GetBytes($req)
$s.Write($bytes, 0, $bytes.Length)
$s.Flush()
# Bounded HEAD read: stop at CRLF CRLF (the deny head precedes its body) or at
# 64 KiB. No sleeps - the socket read timeout is the only clock in here.
$ms = New-Object System.IO.MemoryStream
$buf = New-Object byte[] 4096
$total = 0
$timedOut = $false
while ($total -lt 65536) {
    $n = 0
    try { $n = $s.Read($buf, 0, $buf.Length) }
    catch { if ($total -eq 0) { $timedOut = $true }; break }
    if ($n -le 0) { break }
    $ms.Write($buf, 0, $n)
    $total += $n
    if ([Text.Encoding]::ASCII.GetString($ms.ToArray()).Contains("`r`n`r`n")) { break }
}
$c.Close()
if ($timedOut) { Write-Output 'S75_TIMEOUT'; exit 4 }
if ($total -le 0) { Write-Output 'S75_NO_RESPONSE'; exit 3 }
$raw = [Text.Encoding]::ASCII.GetString($ms.ToArray())
$split = $raw.IndexOf("`r`n`r`n")
if ($split -lt 0) { $headText = $raw; $bodyText = '' }
else { $headText = $raw.Substring(0, $split); $bodyText = $raw.Substring($split + 4) }
$lines = $headText -split "`r`n"
$status = if ($lines.Count -gt 0) { $lines[0] } else { '' }
$xs = 0
foreach ($ln in $lines) { if ($ln -match '^(?i)X-Sandbox:\s*denied\s*$') { $xs = 1 } }
$bodyFirst = ''
foreach ($ln in @($bodyText -split "`r?`n")) { if ($ln.Trim()) { $bodyFirst = $ln.Trim(); break } }
Write-Output ('S75_STATUS=' + $status)
Write-Output ('S75_HEADER_XS=' + $xs)
Write-Output ('S75_BODY=' + $bodyFirst)
exit 0
'@
    Set-Content -LiteralPath (Join-Path $d 's75-loopback-connect.ps1') -Value $inner -Encoding ASCII
    $flags = @('run','--allow-cwd','--allow-domain','api.anthropic.com','--no-prompt')
    $psid = Invoke-Sandbox -Args ($flags + @('--print-sid','--','cmd','/c','echo','placeholder')) -WorkingDirectory $d
    if ($psid.ExitCode -ne 0) { return @{ Num=75; Name='S-75 (D-1 loopback CONNECT)'; Passed=$false; Skipped=$false; Detail="print-sid failed exit=$($psid.ExitCode)" } }
    $sid = ($psid.Stdout -join '').Trim()
    # Interpreter: `powershell` (5.1), NOT pwsh. In-VM pwsh cannot be spawned as
    # a sandboxed child at all (0x80070520 "A specified logon session does not
    # exist" - the WindowsApps alias / AppContainer token problem), while 5.1
    # runs fine but throws DriveNotFoundException
    # (Microsoft.PowerShell.Core\FileSystem) on ANY native command invocation
    # inside the AppContainer. Hence: 5.1, and the inner script is pure managed
    # .NET (the S-91 precedent) so it never shells out. -File gets an absolute
    # path - the harness rule for anything the child opens.
    $innerScript = Join-Path $d 's75-loopback-connect.ps1'
    $r = Invoke-Sandbox -Args ($flags + @('--sid',$sid,'--','powershell','-NoProfile','-ExecutionPolicy','Bypass','-File',$innerScript)) -WorkingDirectory $d
    $out = ($r.Stdout -join "`n")
    if ($out -match 'S75_NO_TOKEN') { return @{ Num=75; Name='S-75 (D-1 loopback CONNECT)'; Passed=$false; Skipped=$false; Detail='inner script could not extract the session token from HTTPS_PROXY' } }
    if ($out -match 'S75_NO_PORT') { return @{ Num=75; Name='S-75 (D-1 loopback CONNECT)'; Passed=$false; Skipped=$false; Detail='SANDBOX_PROXY_PORT missing or unparsable in the child env' } }
    # Assert on the markers the inner script prints, not on curl stderr: an
    # exact status line (a stray numeric port or header containing "403" must
    # not satisfy it) plus the header-presence flag.
    $status = [regex]::Match($out, 'S75_STATUS=([^\r\n]*)').Groups[1].Value.Trim()
    $bodyShown = [regex]::Match($out, 'S75_BODY=([^\r\n]*)').Groups[1].Value
    $got403 = ($status -eq 'HTTP/1.1 403 Forbidden')
    $gotHeader = ($out -match 'S75_HEADER_XS=1')
    # The audit must show the loopback branch (source hard-deny + the
    # dedicated loopback_refused reason), not a generic deny.
    $s = Invoke-Sandbox -Args @('audit','show',$sid,'--json')
    $loopbackAudit = $false
    foreach ($l in @($s.Stdout | Where-Object { $_.Trim() })) {
        try { $o = $l | ConvertFrom-Json } catch { continue }
        if ($o.op -eq 'CONNECT' -and $o.disposition -eq 'deny' -and $o.source -eq 'hard-deny' -and $o.reason -eq 'loopback_refused' -and $o.host -eq '127.0.0.1') { $loopbackAudit = $true }
    }
    $passed = $got403 -and $gotHeader -and $loopbackAudit
    # Distinguish the inner script's exit codes in the failure detail: 3 = the
    # proxy was never reached, 4 = read timeout.
    $exitHint = switch ($r.ExitCode) { 3 { 'exit 3 = proxy never reached / no response' } 4 { 'exit 4 = read timeout, no response head' } default { '' } }
    $outHead = ((($out -split "`r?`n") | Where-Object { $_.Trim() } | Select-Object -First 4 | ForEach-Object { $_ -replace 'Basic [A-Za-z0-9+/=]+', 'Basic [REDACTED]' }) -join ' | ')
    return @{ Num=75; Name='S-75 (D-1 loopback CONNECT)'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { 'CONNECT 127.0.0.1:5432 refused: 403 Forbidden + X-Sandbox: denied; audit loopback_refused' }
                 else { "status='$status' header=$gotHeader audit=$loopbackAudit exit=$($r.ExitCode) $exitHint body='$bodyShown' out=$outHead err=$(Get-LineHead -Lines $r.Stderr -Max 160)" } }
}

# S-76 (D-3): --no-prompt — an unlisted host is denied with NO dialog and
# audit source "default" (the prompt-disabled branch of the default stage;
# reason "prompting disabled; host not allow-listed").
function Invoke-Scenario-S76 {
    if (-not (Get-Curl)) { return @{ Num=76; Name='S-76 (D-3 no-prompt)'; Passed=$true; Skipped=$true; Detail='curl.exe not on PATH' } }
    if (-not (Test-LoopbackProxyReachable)) { return @{ Num=76; Name='S-76 (D-3 no-prompt)'; Passed=$true; Skipped=$true; Detail='AppContainer loopback blocked — run tests elevated or with admin loopback exemption' } }
    $d = New-ScenarioDir 76
    $flags = @('run','--allow-cwd','--allow-domain','api.anthropic.com','--no-prompt')
    $psid = Invoke-Sandbox -Args ($flags + @('--print-sid','--','cmd','/c','echo','placeholder')) -WorkingDirectory $d
    if ($psid.ExitCode -ne 0) { return @{ Num=76; Name='S-76 (D-3 no-prompt)'; Passed=$false; Skipped=$false; Detail="print-sid failed exit=$($psid.ExitCode)" } }
    $sid = ($psid.Stdout -join '').Trim()
    $r = Invoke-Sandbox -Args ($flags + @('--sid',$sid,'--','cmd','/c','curl.exe -s -m 15 -o NUL -w %{http_code} https://evil.example.com')) -WorkingDirectory $d
    $code = (($r.Stdout -join '') -replace '\s','')
    $denied = ($r.ExitCode -ne 0) -and ($code -eq '000' -or $code -eq '')
    # Audit: the deny must carry source "default", and no prompt-path event
    # (prompt/prompt_overload/unavailable) may exist — the dialog never ran.
    $s = Invoke-Sandbox -Args @('audit','show',$sid,'--json')
    $defaultSeen = $false
    $promptSeen = $false
    foreach ($l in @($s.Stdout | Where-Object { $_.Trim() })) {
        try { $o = $l | ConvertFrom-Json } catch { continue }
        if ($o.op -eq 'CONNECT' -and $o.disposition -eq 'deny') {
            if ($o.source -eq 'default' -and $o.host -eq 'evil.example.com') { $defaultSeen = $true }
            if ($o.source -eq 'prompt' -or $o.source -eq 'prompt_overload' -or $o.source -eq 'unavailable') { $promptSeen = $true }
        }
    }
    $passed = $denied -and $defaultSeen -and (-not $promptSeen)
    return @{ Num=76; Name='S-76 (D-3 no-prompt)'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { 'denied without a dialog; audit source=default' }
                 else { "denied=$denied defaultAudit=$defaultSeen promptAudit=$promptSeen exit=$($r.ExitCode) code=$code sid=$sid" } }
}

# S-77 (D-4): the intent control-plane endpoints, exercised from INSIDE the
# sandbox. The inner script uses System.Net.Http.HttpClient with
# UseProxy = $false, so it dials 127.0.0.1:<port> DIRECTLY instead of routing
# through the injected proxy, and identifies itself with an explicit
# Proxy-Authorization: Basic header carrying the session token from the
# HTTPS_PROXY userinfo - the 3.6 review's child-side note. POST the intent
# (204), then GET it back (200 + the declared reason + hint "declared"). The
# JSON body is a file so no quoting can mangle it. Pure managed .NET, no
# native command (see S-75's interpreter note).
function Invoke-Scenario-S77 {
    if (-not (Test-LoopbackProxyReachable)) { return @{ Num=77; Name='S-77 (D-4 intent endpoint)'; Passed=$true; Skipped=$true; Detail='proxy loopback probe failed - EITHER AppContainer loopback is blocked (run tests elevated or with the admin loopback exemption) OR curl.exe is not on PATH (the shared probe shells out to curl; this scenario speaks HTTP without it)' } }
    $d = New-ScenarioDir 77
    $bodyPath = Join-Path $d 's77-intent-body.json'
    Set-Content -LiteralPath $bodyPath -Value '{"target":"api.example.com","reason":"s77-intent-roundtrip"}' -Encoding ASCII
    $inner = @'
param([string]$BodyPath)
$m = [regex]::Match($env:HTTPS_PROXY, '://sandbox:([^@]+)@')
if (-not $m.Success) { Write-Output 'POST_STATUS=NO_TOKEN'; exit 3 }
$creds = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes('sandbox:' + $m.Groups[1].Value))
$port = 0
if (-not [int]::TryParse([string]$env:SANDBOX_PROXY_PORT, [ref]$port) -or $port -le 0) { Write-Output 'POST_STATUS=NO_PORT'; exit 3 }
Write-Output "DIAG body=$BodyPath exists=$(Test-Path -LiteralPath $BodyPath)"
# HttpClient rather than a native client: UseProxy=$false keeps the loopback
# dial direct (the endpoint is reachable by NO_PROXY semantics, never by
# proxying), UseDefaultCredentials=$false stops .NET attaching host
# credentials, and the token rides an explicit Proxy-Authorization header.
Add-Type -AssemblyName System.Net.Http
$h = [System.Net.Http.HttpClientHandler]::new()
$h.UseProxy = $false
$h.UseDefaultCredentials = $false
$c = [System.Net.Http.HttpClient]::new($h)
$c.Timeout = [TimeSpan]::FromSeconds(8)
$auth = 'Basic ' + $creds
$postStatus = 0
try {
    $post = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Post, "http://127.0.0.1:$port/sandbox/intent")
    [void]$post.Headers.TryAddWithoutValidation('Proxy-Authorization', $auth)
    $bodyText = [IO.File]::ReadAllText($BodyPath)
    $post.Content = [System.Net.Http.StringContent]::new($bodyText, [Text.Encoding]::UTF8, 'application/json')
    $pres = $c.SendAsync($post).GetAwaiter().GetResult()
    $postStatus = [int]$pres.StatusCode
} catch { $postStatus = 0 }
Write-Output ('POST_STATUS=' + $postStatus)
$getStatus = 0
$getBody = ''
try {
    $get = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Get, "http://127.0.0.1:$port/sandbox/intent?host=api.example.com")
    [void]$get.Headers.TryAddWithoutValidation('Proxy-Authorization', $auth)
    $gres = $c.SendAsync($get).GetAwaiter().GetResult()
    $getStatus = [int]$gres.StatusCode
    $getBody = $gres.Content.ReadAsStringAsync().GetAwaiter().GetResult()
} catch { $getStatus = 0 }
$c.Dispose()
Write-Output ('GET_STATUS=' + $getStatus)
Write-Output ('GET_BODY=' + $getBody)
exit 0
'@
    Set-Content -LiteralPath (Join-Path $d 's77-intent.ps1') -Value $inner -Encoding ASCII
    # powershell 5.1, not pwsh - see S-75's interpreter note. The inner script
    # is pure managed code, so 5.1's native-command limitation never applies.
    # $bodyPath is absolute (Join-Path over the resolved scenario dir), so
    # -BodyPath keeps its unchanged contract.
    $innerScript = Join-Path $d 's77-intent.ps1'
    $r = Invoke-Sandbox -Args @('run','--allow-cwd','--allow-domain','api.anthropic.com','--no-prompt','--','powershell','-NoProfile','-ExecutionPolicy','Bypass','-File',$innerScript,'-BodyPath',$bodyPath) -WorkingDirectory $d
    $out = ($r.Stdout -join "`n")
    $err = ($r.Stderr -join "`n")
    $diagOk = ($out -match 'DIAG body=.+ exists=True')
    $post204 = ($out -match 'POST_STATUS=204')
    # Status and body are separate markers now: GET_STATUS carries the code,
    # GET_BODY the JSON the endpoint returned.
    $get200 = ($out -match 'GET_STATUS=200')
    $getReason = ($out -match '"reason":"s77-intent-roundtrip"')
    $getHost = ($out -match '"host":"api.example.com"')
    $getHint = ($out -match '"hint":"declared"')
    $passed = ($r.ExitCode -eq 0) -and $diagOk -and $post204 -and $get200 -and $getReason -and $getHost -and $getHint
    $getBodyShown = [regex]::Match($out, 'GET_BODY=([^\r\n]*)').Groups[1].Value
    return @{ Num=77; Name='S-77 (D-4 intent endpoint)'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { 'POST /sandbox/intent 204; GET 200 returned the declared reason (hint=declared)' }
                 else { "exit=$($r.ExitCode) diag=$diagOk post204=$post204 get200=$get200 reason=$getReason host=$getHost hint=$getHint body='$getBodyShown' out=$($out -replace "`r?`n", ' | ') err=$err" } }
}

# S-78 (D-3): learned persistence across a sandbox restart — run with an
# allow-list, click "Allow permanently" on the interactive dialog, restart
# the sandbox, and the learned host is allowed with no new flags.
# MANUAL APPROVAL REQUIRED — a human must click the TaskDialog; the harness
# never simulates dialog clicks. Harness convention for manual scenarios is a
# clean skip with the manual marker (cf. S-15). The Checkpoint 3 flow (plan
# items 3-4) exercises this live; S-79 seeds the exact persisted state so
# the automated list/revoke leg still runs.
function Invoke-Scenario-S78 {
    return @{ Num=78; Name='S-78 (D-3 learned persistence)'; Passed=$true; Skipped=$true
        Detail='MANUAL APPROVAL required — interactive dialog click; see plan Task 3.8 / Checkpoint 3 items 3-4 (S-79 seeds this state for automation)' }
}

# S-79 (D-3): `sandbox learned list/revoke` round-trip. The plan runs this
# after the MANUAL S-78 approval; since the harness cannot click dialogs,
# this scenario SEEDS the exact state the S-78 "Allow permanently" click
# persists (LearnedStore::record("github.com","suffix",allow=true) — the
# pipeline keys suffix entries by the bare suffix, so list shows
# `github.com`, NOT `api.github.com`; 3.7 review advisory #1). A
# per-scenario fake USERPROFILE isolates the real learned store.
function Invoke-Scenario-S79 {
    $d = New-ScenarioDir 79
    $fakeHome = Join-Path $d 'fake-home'
    $learnedDir = Join-Path $fakeHome '.sandbox\learned'
    New-Item -ItemType Directory -Path $learnedDir -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $learnedDir 'default.json') -Value '{"schema":1,"allow":[{"host":"github.com","scope":"suffix"}],"deny":[]}' -Encoding ASCII
    $list1 = Invoke-SandboxCliHome -FakeHome $fakeHome -CliArgs 'learned list'
    $okList = ($list1.ExitCode -eq 0) -and ($list1.Stdout -match 'github\.com') -and ($list1.Stdout -match 'suffix') -and ($list1.Stdout -match 'allow')
    $rev = Invoke-SandboxCliHome -FakeHome $fakeHome -CliArgs 'learned revoke github.com'
    $okRev = ($rev.ExitCode -eq 0) -and ($rev.Stdout -match 'revoked github\.com')
    $list2 = Invoke-SandboxCliHome -FakeHome $fakeHome -CliArgs 'learned list'
    $okEmpty = ($list2.ExitCode -eq 0) -and ($list2.Stdout -match '\(no learned entries\)')
    $passed = $okList -and $okRev -and $okEmpty
    return @{ Num=79; Name='S-79 (D-3 learned list/revoke)'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { 'list -> revoke -> list-empty over the seeded github.com suffix entry' }
                 else { "list=$okList revoke=$okRev empty=$okEmpty out1='$($list1.Stdout)' rev='$($rev.Stdout)$($rev.Stderr)' out2='$($list2.Stdout)'" } }
}

# S-80 (D-5): the audit `source` filter. The plan wording ("after
# S-72/S-73/S-76") assumed one shared session; the harness gives every
# scenario its own sid, so this scenario is self-contained: ONE session
# fires a blocklist deny, a hard-deny, and an allowlist allow, then asserts
# `--filter "source=hard-deny"` yields ONLY hard-deny events while the
# unfiltered log proves the session really contains the other sources.
# Note (3.6 review advisory #2): post-admission failures log allow-then-
# deny pairs — parse per line, never per connection. The allowlist CONNECT's
# audit event is emitted before the dial, so this scenario does not depend
# on external network success.
function Invoke-Scenario-S80 {
    if (-not (Get-Curl)) { return @{ Num=80; Name='S-80 (D-5 audit source filter)'; Passed=$true; Skipped=$true; Detail='curl.exe not on PATH' } }
    if (-not (Test-LoopbackProxyReachable)) { return @{ Num=80; Name='S-80 (D-5 audit source filter)'; Passed=$true; Skipped=$true; Detail='AppContainer loopback blocked — run tests elevated or with admin loopback exemption' } }
    $d = New-ScenarioDir 80
    $flags = @('run','--allow-cwd','--allow-domain','api.anthropic.com','--deny-domain','*.example.com','--no-prompt')
    $psid = Invoke-Sandbox -Args ($flags + @('--print-sid','--','cmd','/c','echo','placeholder')) -WorkingDirectory $d
    if ($psid.ExitCode -ne 0) { return @{ Num=80; Name='S-80 (D-5 audit source filter)'; Passed=$false; Skipped=$false; Detail="print-sid failed exit=$($psid.ExitCode)" } }
    $sid = ($psid.Stdout -join '').Trim()
    Invoke-Sandbox -Args ($flags + @('--sid',$sid,'--','cmd','/c','curl.exe -s -m 15 -o NUL -w %{http_code} https://evil.example.com')) -WorkingDirectory $d | Out-Null
    Invoke-Sandbox -Args ($flags + @('--sid',$sid,'--','cmd','/c','curl.exe -s -m 15 -o NUL -w %{http_code} https://169.254.169.253')) -WorkingDirectory $d | Out-Null
    Invoke-Sandbox -Args ($flags + @('--sid',$sid,'--','cmd','/c','curl.exe -s -m 15 -o NUL -w %{http_code} https://api.anthropic.com')) -WorkingDirectory $d | Out-Null
    # Filtered view: every line must be a hard-deny event, at least one must
    # exist, and the 169.254.169.253 target must be among them.
    $f = Invoke-Sandbox -Args @('audit','show',$sid,'--json','--filter','source=hard-deny')
    $allHardDeny = $true
    $hardDenyCount = 0
    $sawTarget = $false
    foreach ($l in @($f.Stdout | Where-Object { $_.Trim() })) {
        try { $o = $l | ConvertFrom-Json } catch { $allHardDeny = $false; break }
        if ($o.source -ne 'hard-deny') { $allHardDeny = $false; break }
        if ($o.host -eq '169.254.169.253') { $sawTarget = $true }
        $hardDenyCount++
    }
    # Unfiltered view: the session really contains the other sources, so the
    # filter did the narrowing (not an empty-vs-nonempty artifact).
    $u = Invoke-Sandbox -Args @('audit','show',$sid,'--json')
    $sawBlocklist = $false
    $sawAllowlist = $false
    foreach ($l in @($u.Stdout | Where-Object { $_.Trim() })) {
        try { $o = $l | ConvertFrom-Json } catch { continue }
        if ($o.op -eq 'CONNECT') {
            if ($o.source -eq 'blocklist') { $sawBlocklist = $true }
            if ($o.source -eq 'allowlist') { $sawAllowlist = $true }
        }
    }
    $passed = ($hardDenyCount -ge 1) -and $allHardDeny -and $sawTarget -and $sawBlocklist -and $sawAllowlist
    return @{ Num=80; Name='S-80 (D-5 audit source filter)'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { "filtered to $hardDenyCount hard-deny event(s) only; unfiltered also had blocklist+allowlist" }
                 else { "count=$hardDenyCount allHardDeny=$allHardDeny target=$sawTarget blocklist=$sawBlocklist allowlist=$sawAllowlist sid=$sid filterExit=$($f.ExitCode)" } }
}

# S-82 (D-1; plan slot S-73, renumbered — see the numbering note above):
# hard-deny IP expansion — 169.254.169.253 sits in the same link-local
# block as the canonical metadata address; the CONNECT must be denied with
# audit source "hard-deny" (pre-prompt, overriding everything else).
function Invoke-Scenario-S82 {
    if (-not (Get-Curl)) { return @{ Num=82; Name='S-82 (D-1 hard-deny expansion)'; Passed=$true; Skipped=$true; Detail='curl.exe not on PATH' } }
    if (-not (Test-LoopbackProxyReachable)) { return @{ Num=82; Name='S-82 (D-1 hard-deny expansion)'; Passed=$true; Skipped=$true; Detail='AppContainer loopback blocked — run tests elevated or with admin loopback exemption' } }
    $d = New-ScenarioDir 82
    $flags = @('run','--allow-cwd','--allow-domain','api.anthropic.com','--no-prompt')
    $psid = Invoke-Sandbox -Args ($flags + @('--print-sid','--','cmd','/c','echo','placeholder')) -WorkingDirectory $d
    if ($psid.ExitCode -ne 0) { return @{ Num=82; Name='S-82 (D-1 hard-deny expansion)'; Passed=$false; Skipped=$false; Detail="print-sid failed exit=$($psid.ExitCode)" } }
    $sid = ($psid.Stdout -join '').Trim()
    $r = Invoke-Sandbox -Args ($flags + @('--sid',$sid,'--','cmd','/c','curl.exe -s -m 15 -o NUL -w %{http_code} https://169.254.169.253')) -WorkingDirectory $d
    $code = (($r.Stdout -join '') -replace '\s','')
    $denied = ($r.ExitCode -ne 0) -and ($code -eq '000' -or $code -eq '')
    $s = Invoke-Sandbox -Args @('audit','show',$sid,'--json')
    $hardDenySeen = $false
    foreach ($l in @($s.Stdout | Where-Object { $_.Trim() })) {
        try { $o = $l | ConvertFrom-Json } catch { continue }
        if ($o.op -eq 'CONNECT' -and $o.disposition -eq 'deny' -and $o.source -eq 'hard-deny' -and $o.host -eq '169.254.169.253') { $hardDenySeen = $true }
    }
    $passed = $denied -and $hardDenySeen
    return @{ Num=82; Name='S-82 (D-1 hard-deny expansion)'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { '169.254.169.253 denied; audit source=hard-deny' }
                 else { "denied=$denied hardDenyAudit=$hardDenySeen exit=$($r.ExitCode) code=$code sid=$sid" } }
}

# S-83 (D-1; plan slot S-74, renumbered — see the numbering note above):
# wildcard apex — `*.anthropic.com` must allow the apex `anthropic.com`
# itself ([G-55]: the wildcard covers the apex and subdomains, dot-bounded).
# The contract is the PROXY's CONNECT status, not the origin's http_code:
# this makes a real connection to anthropic.com:443 and PASSes iff the tunnel
# is admitted (`%{http_connect}` == 200). See the assertion note below.
function Invoke-Scenario-S83 {
    if (-not (Get-Curl)) { return @{ Num=83; Name='S-83 (D-1 wildcard apex)'; Passed=$true; Skipped=$true; Detail='curl.exe not on PATH' } }
    if (-not (Test-LoopbackProxyReachable)) { return @{ Num=83; Name='S-83 (D-1 wildcard apex)'; Passed=$true; Skipped=$true; Detail='AppContainer loopback blocked — run tests elevated or with admin loopback exemption' } }
    $d = New-ScenarioDir 83
    $r = Invoke-Sandbox -Args @('run','--allow-cwd','--allow-domain','*.anthropic.com','--no-prompt','--','cmd','/c','curl.exe -s -m 15 -o NUL -w %{http_code}_%{http_connect} https://anthropic.com') -WorkingDirectory $d
    $parts = ((($r.Stdout -join '')).Trim()) -split '_'
    $code = $parts[0]
    $connectCode = if ($parts.Count -gt 1) { $parts[1] } else { '' }
    # ASSERTION CONTRACT: `%{http_connect}` (the proxy's CONNECT reply status).
    # http_connect=200 means the allow-list ADMITTED the tunnel to
    # anthropic.com:443, which is the only claim this scenario makes; a refused
    # CONNECT answers 403 (or 502 for a chained failure) and still fails here.
    # The origin `%{http_code}` is INFORMATIONAL (Detail only, never asserted):
    # this host's schannel cannot validate anthropic.com's chain because the
    # CRL/OCSP responder is unreachable (CRYPT_E_REVOCATION_OFFLINE), so curl
    # exits 35 with http_code 000 BY CONSTRUCTION — a TLS-layer fact that says
    # nothing about the allow-list. Do NOT "fix" this back to an http_code
    # assertion: it would red the suite on every CRL-offline host while proving
    # nothing new (S-81's precedent, and the same reason S-81 asserts
    # http_connect).
    $tunnel = ($connectCode -eq '200')
    $passed = $tunnel
    return @{ Num=83; Name='S-83 (D-1 wildcard apex)'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { "wildcard admitted the apex (CONNECT=200; http_code=$code informational)" } else { "CONNECT not admitted (connect=$connectCode http_code=$code exit=$($r.ExitCode)) err=$((($r.Stderr | Where-Object { $_.Trim() } | Select-Object -First 10) -join ' | '))" } }
}

# S-84 (D-3, extra; 3.7 review advisory #2 — "no test currently revokes a
# `*.`-prefixed stored entry"): seed a wildcard-form entry, list it (list
# shows the stored key — the exact revoke round-trip form), revoke by that
# stored key, and assert the store is empty afterwards.
function Invoke-Scenario-S84 {
    $d = New-ScenarioDir 84
    $fakeHome = Join-Path $d 'fake-home'
    $learnedDir = Join-Path $fakeHome '.sandbox\learned'
    New-Item -ItemType Directory -Path $learnedDir -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $learnedDir 'default.json') -Value '{"schema":1,"allow":[{"host":"*.example.com","scope":"suffix"}],"deny":[]}' -Encoding ASCII
    $list1 = Invoke-SandboxCliHome -FakeHome $fakeHome -CliArgs 'learned list'
    $okList = ($list1.ExitCode -eq 0) -and ($list1.Stdout -match [regex]::Escape('*.example.com')) -and ($list1.Stdout -match 'suffix')
    $rev = Invoke-SandboxCliHome -FakeHome $fakeHome -CliArgs 'learned revoke *.example.com'
    $okRev = ($rev.ExitCode -eq 0) -and ($rev.Stdout -match [regex]::Escape('revoked *.example.com'))
    $list2 = Invoke-SandboxCliHome -FakeHome $fakeHome -CliArgs 'learned list'
    $okEmpty = ($list2.ExitCode -eq 0) -and ($list2.Stdout -match '\(no learned entries\)')
    $passed = $okList -and $okRev -and $okEmpty
    return @{ Num=84; Name='S-84 (D-3 learned revoke *.key)'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { 'list -> revoke-by-stored-key -> list-empty over a `*.`-prefixed entry' }
                 else { "list=$okList revoke=$okRev empty=$okEmpty out1='$($list1.Stdout)' rev='$($rev.Stdout)$($rev.Stderr)' out2='$($list2.Stdout)'" } }
}

# ---------------------------------------------------------------------------
# ADR-0001 Task 4.3 — D-2 upstream chaining (plan Phase 4 S-81/S-82/S-83,
# renumbered per the note above). All three drive the SUPERVISOR's environment
# through Invoke-Sandbox's -Env switch: `select_upstream` reads
# HTTPS_PROXY/HTTP_PROXY/NO_PROXY from the supervisor, while the sandboxed
# child always gets the loopback-only proxy vars (build_env_block), so a
# host-env scenario must not expect the child to see them.
# ---------------------------------------------------------------------------

# S-81 (D-2; plan Phase 4 slot S-81, kept — see the numbering note above):
# NO_PROXY bypass. The plan's `network.noProxy` does not exist (RawNetwork is
# deny_unknown_fields; Task 3.1 added only `upstreamProxy`), so the bypass is
# driven from the HOST env, which is where [G-11] reads it. ONE configuration
# proves both halves of the assertion:
#   (a) api.anthropic.com is in NO_PROXY while the upstream proxy is a dead
#       port, so that host skips chaining and dials DIRECT — the request
#       succeeds (real egress, the same dependency S-83 has);
#   (b) anthropic.com is allow-listed but NOT in NO_PROXY, so the same dead
#       upstream IS used -> 502 + `X-Sandbox: upstream-error`. The direct-dial
#       502 carries neither that header nor a second audit leaf, so (b) proves
#       chaining was attempted for the non-bypassed host (i.e. the bypass in
#       (a) came from the NO_PROXY match, not from chaining being off).
function Invoke-Scenario-S81 {
    if (-not (Get-Curl)) { return @{ Num=81; Name='S-81 (D-2 NO_PROXY bypass)'; Passed=$true; Skipped=$true; Detail='curl.exe not on PATH' } }
    if (-not (Test-LoopbackProxyReachable)) { return @{ Num=81; Name='S-81 (D-2 NO_PROXY bypass)'; Passed=$true; Skipped=$true; Detail='AppContainer loopback blocked — run tests elevated or with admin loopback exemption' } }
    $d = New-ScenarioDir 81
    # Isolate the learned store: USERPROFILE points at a fresh EMPTY directory
    # (the Invoke-SandboxCliHome pattern), so a learned deny/allow for either
    # host in the real %USERPROFILE%\.sandbox\learned store cannot flip the
    # verdict on a machine that has already answered a prompt.
    $fakeHome = Join-Path $d 'home'
    New-Item -ItemType Directory -Path $fakeHome -Force | Out-Null
    # Port 1 is the codebase's conventional dead port. NO_PROXY names only
    # api.anthropic.com, so the same value is "the proxy we cannot reach" for
    # anthropic.com and "the proxy we never try" for api.anthropic.com.
    $envOverrides = @{ 'HTTPS_PROXY' = 'http://127.0.0.1:1'; 'NO_PROXY' = 'api.anthropic.com'; 'USERPROFILE' = $fakeHome }
    $flags = @('run','--allow-cwd','--allow-domain','api.anthropic.com','--allow-domain','anthropic.com','--no-prompt')
    # `%{http_connect}` is the proxy's CONNECT status: 200 proves the tunnel was
    # established (i.e. the direct dial happened), so a bare 5xx from the
    # NO_PROXY path can never be mistaken for success the way an http_code-only
    # check could.
    $direct = Invoke-Sandbox -Args ($flags + @('--','cmd','/c','curl.exe -sS -m 25 -o NUL -w %{http_code}_%{http_connect} https://api.anthropic.com')) -WorkingDirectory $d -Env $envOverrides
    $parts = ((($direct.Stdout -join '')).Trim()) -split '_'
    $code = $parts[0]
    $connectCode = if ($parts.Count -gt 1) { $parts[1] } else { '' }
    # The bypass proof is the CONNECT status: http_connect=200 means the
    # supervisor dialed DIRECT (a chained failure answers 502 instead). The
    # final http_code is informational only — this host's schannel rejects
    # api.anthropic.com's chain with CRYPT_E_REVOCATION_OFFLINE (curl exit 35,
    # code 000) when the CRL server is unreachable, which says nothing about
    # chaining. Deliberately NOT asserted: a CRL-outage host would red the suite.
    $bypassed = ($connectCode -eq '200')
    # Negative control: same env, host NOT in NO_PROXY. Raw CONNECT so the 502
    # status line and the X-Sandbox header are both observable.
    $probe = Invoke-ConnectProbe -SandboxArgs $flags -TargetHost 'anthropic.com' -WorkingDirectory $d -Env $envOverrides
    $raw = $probe.Raw
    $got502 = ($raw -match 'HTTP/1\.1 502 Bad Gateway')
    $gotHeader = ($raw -match 'X-Sandbox: upstream-error')
    $chained = $probe.Ok -and $got502 -and $gotHeader
    $passed = $bypassed -and $chained
    return @{ Num=81; Name='S-81 (D-2 NO_PROXY bypass)'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { "NO_PROXY host dialed direct (connect=200 http_code=$code); non-matching allow-listed host chained to the dead upstream (502 + X-Sandbox: upstream-error)" }
                 else { "bypass=$bypassed connect=$connectCode http_code=$code exit=$($direct.ExitCode) curlErr=$(Get-LineHead -Lines $direct.Stderr -Max 160) probeOk=$($probe.Ok) got502=$got502 header=$gotHeader probeErr=$(Get-LineHead -Lines @($probe.Stderr) -Max 160)" } }
}

# S-85 (D-2; plan slot S-82, renumbered — see the numbering note above):
# upstream unreachable -> `502 Bad Gateway` + `X-Sandbox: upstream-error`
# [G-30/G-42]. The upstream comes from the PROFILE (`network.upstreamProxy`,
# camelCase exactly — a stray `noProxy` key would be a hard load error) and
# points at the conventional dead port. Asserts the status line, the header, a
# body that names the proxy as host:port without echoing its URL or leaking
# credentials, and the TWO-leaf audit shape a chained failure produces: the
# admission `allowlist` allow FIRST, then the `default`/`upstream_error` deny.
# A count-based "one leaf" assertion would fail here (Task 4.2 review).
function Invoke-Scenario-S85 {
    if (-not (Get-Curl)) { return @{ Num=85; Name='S-85 (D-2 upstream unreachable)'; Passed=$true; Skipped=$true; Detail='curl.exe not on PATH' } }
    if (-not (Test-LoopbackProxyReachable)) { return @{ Num=85; Name='S-85 (D-2 upstream unreachable)'; Passed=$true; Skipped=$true; Detail='AppContainer loopback blocked — run tests elevated or with admin loopback exemption' } }
    $d = New-ScenarioDir 85
    # Isolate the learned store (fresh EMPTY fake home, see S-81) and PIN
    # NO_PROXY off: a host entry covering anthropic.com would let the child dial
    # direct, the dead upstream would never be consulted, and this scenario
    # would fail spuriously. A $null value REMOVES the variable (both
    # spellings; the helper also scrubs any other case variant).
    $fakeHome = Join-Path $d 'home'
    New-Item -ItemType Directory -Path $fakeHome -Force | Out-Null
    $envPinned = @{ 'NO_PROXY' = $null; 'USERPROFILE' = $fakeHome }
    $profilePath = Join-Path $d 'upstream-dead.json'
    Set-Content -LiteralPath $profilePath -Value '{"meta":{"name":"s85-upstream-dead","schema_version":1},"network":{"upstreamProxy":"http://127.0.0.1:1"}}' -Encoding ASCII
    $flags = @('run','--allow-cwd','--profile',$profilePath,'--allow-domain','anthropic.com','--no-prompt')
    $psid = Invoke-Sandbox -Args ($flags + @('--print-sid','--','cmd','/c','echo','placeholder')) -WorkingDirectory $d -Env $envPinned
    if ($psid.ExitCode -ne 0) { return @{ Num=85; Name='S-85 (D-2 upstream unreachable)'; Passed=$false; Skipped=$false; Detail="print-sid failed exit=$($psid.ExitCode) err=$(Get-LineHead -Lines $psid.Stderr -Max 160)" } }
    $sid = ($psid.Stdout -join '').Trim()
    $probe = Invoke-ConnectProbe -SandboxArgs ($flags + @('--sid',$sid)) -TargetHost 'anthropic.com' -WorkingDirectory $d -Env $envPinned
    $raw = $probe.Raw
    $got502 = ($raw -match 'HTTP/1\.1 502 Bad Gateway')
    $gotHeader = ($raw -match 'X-Sandbox: upstream-error')
    # Body contract: names the endpoint as host:port, never the URL (G-30) and
    # never a credential-shaped token.
    $namesEndpoint = ($raw -match '127\.0\.0\.1:1')
    $noUrl = -not ($raw -match 'http://127\.0\.0\.1')
    $noCreds = -not ($raw -match '(?i)(proxy-authorization|basic )')
    $bodyOk = $namesEndpoint -and $noUrl -and $noCreds
    # Audit shape: admission allow (source=allowlist) THEN the transport deny.
    $s = Invoke-Sandbox -Args @('audit','show',$sid,'--json')
    $leaves = New-Object System.Collections.Generic.List[object]
    foreach ($l in @($s.Stdout | Where-Object { $_.Trim() })) {
        try { $o = $l | ConvertFrom-Json } catch { continue }
        if ($o.op -eq 'CONNECT' -and $o.host -eq 'anthropic.com') { $leaves.Add($o) }
    }
    $leafCount = $leaves.Count
    $twoLeaves = ($leafCount -eq 2)
    # -and short-circuits, so the indexers only run when both leaves exist.
    $admission = $twoLeaves -and ($leaves[0].disposition -eq 'allow') -and ($leaves[0].source -eq 'allowlist')
    $upstreamLeaf = $twoLeaves -and ($leaves[1].disposition -eq 'deny') -and ($leaves[1].source -eq 'default') -and ($leaves[1].reason -eq 'upstream_error')
    $passed = $probe.Ok -and $got502 -and $gotHeader -and $bodyOk -and $admission -and $upstreamLeaf
    return @{ Num=85; Name='S-85 (D-2 upstream unreachable)'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { 'chained CONNECT failed: 502 + X-Sandbox: upstream-error, body names 127.0.0.1:1 (no URL/creds); audit = allowlist allow + default/upstream_error deny' }
                 else { "probeOk=$($probe.Ok) got502=$got502 header=$gotHeader endpoint=$namesEndpoint noUrl=$noUrl noCreds=$noCreds leaves=$leafCount admission=$admission upstreamLeaf=$upstreamLeaf probeExit=$($probe.ExitCode) probeErr=$(Get-LineHead -Lines @($probe.Stderr) -Max 160) raw=$(Get-LineHead -Lines @($raw) -Max 200)" } }
}

# S-86 (D-2; plan slot S-83, renumbered — see the numbering note above):
# upstream-source detection and both diagnostics [G-10/G-42/G-30], three legs:
#   (a) host HTTPS_PROXY only, NO profile value, SANDBOX_DIAG=1 -> there is
#       nothing to differ from, so NO "differs" line appears on stderr;
#   (b) profile value AND a different host value, SANDBOX_DIAG=1 -> the [G-42]
#       override notice appears, naming BOTH endpoints as host:port and saying
#       the profile wins (never the URLs: a proxy URL may carry a password);
#   (c) an `https://` upstream — rejected by design (no TLS-to-proxy) — is a
#       security-relevant degradation, so its warning is NOT SANDBOX_DIAG-
#       gated. Asserted WITHOUT SANDBOX_DIAG (the variable is removed, since
#       any value including "0" satisfies var_os): the line names the source
#       knob, redacts the URL to `(unparsable)`, never echoes the URL, and the
#       run still succeeds on the direct fallback — and stderr carries no
#       SANDBOX_DIAG marker at all, so a future diag-gating of that warning
#       cannot let this leg pass silently.
# Every leg keeps the network active (an allow-list entry + --no-prompt): with
# an empty allow-list and the prompt off the config resolves to Blocked, no
# proxy starts, and none of this code runs at all.
function Invoke-Scenario-S86 {
    # Every leg runs a real network session (`cmd /c echo` still starts the
    # proxy), so the loopback guard IS required: non-elevated, the session
    # hangs — with register_loopback failed the supervisor still spawns the
    # child, and a lingering conhost holds the child's stdio pipes open, so the
    # supervisor waits for stdout EOF forever (observed 2026-10-18: leg (a) hung
    # >5 minutes with only conhost left under sandbox.exe; every network
    # scenario must stay elevation-guarded until that pre-existing supervisor
    # defect is fixed — candidate fix: CREATE_NO_WINDOW or explicit pipe
    # ownership on the child). The warnings themselves are elevation-independent;
    # it is the session lifecycle that is not.
    if (-not (Test-LoopbackProxyReachable)) { return @{ Num=86; Name='S-86 (D-2 host env detection)'; Passed=$true; Skipped=$true; Detail='AppContainer loopback blocked — run tests elevated or with admin loopback exemption' } }
    $d = New-ScenarioDir 86
    # Fresh EMPTY fake home (see S-81): the real learned store must not reach
    # any leg's verdict.
    $fakeHome = Join-Path $d 'home'
    New-Item -ItemType Directory -Path $fakeHome -Force | Out-Null
    $base = @('run','--allow-cwd','--allow-domain','api.anthropic.com','--no-prompt')
    # (a) host env only: no override notice.
    $a = Invoke-Sandbox -Args ($base + @('--','cmd','/c','echo','host-env-only')) -WorkingDirectory $d -Env @{ 'HTTPS_PROXY' = 'http://127.0.0.1:1'; 'SANDBOX_DIAG' = '1'; 'USERPROFILE' = $fakeHome }
    $aErr = ($a.Stderr -join "`n")
    $aOk = ($a.ExitCode -eq 0) -and ((($a.Stdout -join "`n")) -match 'host-env-only') -and (-not ($aErr -match 'differs from host'))
    # (b) profile value differs from host env: the G-42 notice.
    $pB = Join-Path $d 'upstream-profile.json'
    Set-Content -LiteralPath $pB -Value '{"meta":{"name":"s86-profile","schema_version":1},"network":{"upstreamProxy":"http://127.0.0.1:1"}}' -Encoding ASCII
    $b = Invoke-Sandbox -Args (@('run','--allow-cwd','--profile',$pB,'--allow-domain','api.anthropic.com','--no-prompt','--','cmd','/c','echo','profile-wins')) -WorkingDirectory $d -Env @{ 'HTTPS_PROXY' = 'http://127.0.0.1:2'; 'SANDBOX_DIAG' = '1'; 'USERPROFILE' = $fakeHome }
    $bErr = ($b.Stderr -join "`n")
    $bWarn = $bErr.Contains('SANDBOX_DIAG: profile network.upstreamProxy (127.0.0.1:1) differs from host HTTPS_PROXY/HTTP_PROXY (127.0.0.1:2); using the profile value')
    $bOk = ($b.ExitCode -eq 0) -and ((($b.Stdout -join "`n")) -match 'profile-wins') -and $bWarn
    # (c) unparsable (https) profile value: unconditional warning.
    $pC = Join-Path $d 'upstream-https.json'
    Set-Content -LiteralPath $pC -Value '{"meta":{"name":"s86-https","schema_version":1},"network":{"upstreamProxy":"https://proxy.example:8080"}}' -Encoding ASCII
    $c = Invoke-Sandbox -Args (@('run','--allow-cwd','--profile',$pC,'--allow-domain','api.anthropic.com','--no-prompt','--','cmd','/c','echo','direct-fallback')) -WorkingDirectory $d -Env @{ 'SANDBOX_DIAG' = $null; 'USERPROFILE' = $fakeHome }
    $cErr = ($c.Stderr -join "`n")
    $cWarn = $cErr.Contains('[sandbox] warning: the upstream proxy configured via profile network.upstreamProxy is unusable')
    $cUnparsable = $cErr.Contains('(unparsable)')
    $cNoEcho = -not $cErr.Contains('proxy.example')
    # The marker must be absent ENTIRELY, not merely harmless: without this the
    # leg passes identically whether SANDBOX_DIAG was removed or inherited, so a
    # future diag-gating of the parse-failure warning would go unnoticed.
    $cNoDiag = -not $cErr.Contains('SANDBOX_DIAG')
    $cOk = ($c.ExitCode -eq 0) -and ((($c.Stdout -join "`n")) -match 'direct-fallback') -and $cWarn -and $cUnparsable -and $cNoEcho -and $cNoDiag
    $passed = $aOk -and $bOk -and $cOk
    return @{ Num=86; Name='S-86 (D-2 host env detection)'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { 'host-only: no differs warning; differing values: G-42 notice names both endpoints; https upstream: unconditional (unparsable) warning, URL not echoed, no SANDBOX_DIAG marker' }
                 else { "a=$aOk b=$bOk warnB=$bWarn c=$cOk warnC=$cWarn unparsable=$cUnparsable noEcho=$cNoEcho diagFree=$cNoDiag aErr=$(Get-LineHead -Lines @($aErr) -Max 140) bErr=$(Get-LineHead -Lines @($bErr) -Max 140) cErr=$(Get-LineHead -Lines @($cErr) -Max 140)" } }
}

# ---------------------------------------------------------------------------
# ADR-0001 Task 5.3 - final pipeline integration scenarios (plan S-84..S-89,
# renumbered to S-87..S-92 per the note above the S-72 section).
#
# The prompt-enabled trio (S-87/S-88/S-90) runs with the PROMPT ENABLED (no
# --no-prompt) on purpose: the claim under test is that the decision happens
# BEFORE the prompt, so disabling the prompt would make the "no dialog" half of
# every assertion vacuous. None of them can park a TaskDialog even under a
# pipeline regression, because each host's ALTERNATIVE outcome is also pre-prompt:
# S-87/S-90's hosts are allow-listed (a broken blocklist/loopback stage answers
# 200 or 502, never a prompt) and S-88's host is blocklisted (a broken learned
# stage still gets a blocklist deny). The learned store is isolated with a fake
# USERPROFILE in every member (the 4.3 convention).
# ---------------------------------------------------------------------------

# Prompt note for the trio below (S-87/S-88/S-90): the prompt is enabled ON
# PURPOSE - the claim is "decided before the prompt". The assertions are safe
# against regressions in the stages under test, but an UNRELATED allow-matcher
# regression would fall through to the dialog and stall up to promptTimeoutSecs
# (60 s) before failing - bounded by Invoke-Sandbox's 120 s kill, so slow, never
# a hang.

# S-87 (D-1; plan S-84): pipeline order - the deny_domain blocklist beats the
# allow-list. The plan's flags are satisfiable AS WRITTEN (`--allow-domain
# *.anthropic.com --deny-domain api.anthropic.com`): the wildcard allow really
# does cover api.anthropic.com ([G-55] wildcard = apex + subdomains), so a 403
# can only come from the blocklist stage. Unlike 3.8's S-72 (whose plan
# flags could not match their target under dot-bounded matching), this config
# is exact. A raw CONNECT probe (not curl) makes the status line,
# the `X-Sandbox: denied` header and the deny body's stage attribution readable
# without parsing curl -v output, and PROVES the request reached the pipeline
# (an unparseable/absent response would read as a silent failure).
function Invoke-Scenario-S87 {
    if (-not (Test-LoopbackProxyReachable)) { return @{ Num=87; Name='S-87 (D-1 blocklist beats allow)'; Passed=$true; Skipped=$true; Detail='proxy loopback probe failed - EITHER AppContainer loopback is blocked (run tests elevated or with the admin loopback exemption) OR curl.exe is not on PATH (the shared probe shells out to curl; these scenarios themselves speak CONNECT without it)' } }
    $d = New-ScenarioDir 87
    # Fresh EMPTY fake home: a learned entry for anthropic.com in the real store
    # must not be able to decide this scenario.
    $fakeHome = Join-Path $d 'home'
    New-Item -ItemType Directory -Path $fakeHome -Force | Out-Null
    $envOverrides = @{ 'USERPROFILE' = $fakeHome }
    $flags = @('run','--allow-cwd','--allow-domain','*.anthropic.com','--deny-domain','api.anthropic.com')
    $psid = Invoke-Sandbox -Args ($flags + @('--print-sid','--','cmd','/c','echo','placeholder')) -WorkingDirectory $d -Env $envOverrides
    if ($psid.ExitCode -ne 0) { return @{ Num=87; Name='S-87 (D-1 blocklist beats allow)'; Passed=$false; Skipped=$false; Detail="print-sid failed exit=$($psid.ExitCode) err=$(Get-LineHead -Lines $psid.Stderr -Max 160)" } }
    $sid = ($psid.Stdout -join '').Trim()
    $probe = Invoke-ConnectProbe -SandboxArgs ($flags + @('--sid',$sid)) -TargetHost 'api.anthropic.com' -WorkingDirectory $d -Env $envOverrides
    $raw = $probe.Raw
    $got403 = ($raw -match 'HTTP/1\.1 403 Forbidden')
    $gotHeader = ($raw -match 'X-Sandbox: denied')
    # The deny body names the stage that answered; deterministic, unlike timing.
    $bodyStage = ($raw -match 'denied by the blocklist policy \(denied_domain\)')
    # -Env is deliberately omitted: audit_log_path() resolves under %LOCALAPPDATA%,
    # not the overridden USERPROFILE (fake home). If that ever changes, pass -Env.
    $s = Invoke-Sandbox -Args @('audit','show',$sid,'--json')
    $blocklistDeny = $false
    $allowLeaf = $false
    $promptLeaf = $false
    foreach ($l in @($s.Stdout | Where-Object { $_.Trim() })) {
        try { $o = $l | ConvertFrom-Json } catch { continue }
        if ($o.op -ne 'CONNECT') { continue }
        # Absence of ANY prompt-path leaf is asserted globally: the pipeline must
        # never have reached the dialog, not merely "not for this host".
        if ($o.source -eq 'prompt' -or $o.source -eq 'prompt_overload' -or $o.source -eq 'unavailable') { $promptLeaf = $true }
        if ($o.host -ne 'api.anthropic.com') { continue }
        if ($o.disposition -eq 'deny' -and $o.source -eq 'blocklist' -and $o.reason -eq 'denied_domain') { $blocklistDeny = $true }
        if ($o.disposition -eq 'allow') { $allowLeaf = $true }
    }
    $passed = $probe.Ok -and $got403 -and $gotHeader -and $bodyStage -and $blocklistDeny -and (-not $allowLeaf) -and (-not $promptLeaf)
    return @{ Num=87; Name='S-87 (D-1 blocklist beats allow)'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { 'deny_domain beat the wildcard allow: 403 + X-Sandbox: denied, body names the blocklist stage; audit blocklist/denied_domain, no allow and no prompt leaf' }
                 else { "probeOk=$($probe.Ok) 403=$got403 header=$gotHeader bodyStage=$bodyStage blocklistAudit=$blocklistDeny allowLeaf=$allowLeaf promptLeaf=$promptLeaf probeExit=$($probe.ExitCode) raw=$(Get-LineHead -Lines @($raw) -Max 200)" } }
}

# S-88 (D-1; plan S-85): pipeline order - a LEARNED permanent deny outranks
# deny_domain [G-33]. Both stages answer 403 for this host, so the status is NOT
# the assertion: the audit `source` is ("learned", not "blocklist"), plus the
# learned fields the decision carries (scope, persisted). The seeded file is the
# byte-shape `LearnedStore::record(host, "host", allow=false)` writes - the
# ascii-LOWERCASED key form, because load() lowercases on read and `learned
# list` shows the stored key (3.7 advisory #1) - under a per-scenario fake
# USERPROFILE, so the real %USERPROFILE%\.sandbox\learned store is never
# touched (S-79's pattern).
function Invoke-Scenario-S88 {
    if (-not (Test-LoopbackProxyReachable)) { return @{ Num=88; Name='S-88 (D-1 learned-deny beats blocklist)'; Passed=$true; Skipped=$true; Detail='proxy loopback probe failed - EITHER AppContainer loopback is blocked (run tests elevated or with the admin loopback exemption) OR curl.exe is not on PATH (the shared probe shells out to curl; these scenarios themselves speak CONNECT without it)' } }
    $d = New-ScenarioDir 88
    $fakeHome = Join-Path $d 'home'
    $learnedDir = Join-Path $fakeHome '.sandbox\learned'
    New-Item -ItemType Directory -Path $learnedDir -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $learnedDir 'default.json') -Value '{"schema":1,"allow":[],"deny":[{"host":"evil.example.com","scope":"host"}]}' -Encoding ASCII
    $envOverrides = @{ 'USERPROFILE' = $fakeHome }
    # The host is on BOTH the learned deny and the blocklist; api.anthropic.com
    # keeps the session in allow-list mode so a broken conflict resolution has
    # somewhere to fall through to (still a deny, different source).
    $flags = @('run','--allow-cwd','--allow-domain','api.anthropic.com','--deny-domain','*.example.com')
    $psid = Invoke-Sandbox -Args ($flags + @('--print-sid','--','cmd','/c','echo','placeholder')) -WorkingDirectory $d -Env $envOverrides
    if ($psid.ExitCode -ne 0) { return @{ Num=88; Name='S-88 (D-1 learned-deny beats blocklist)'; Passed=$false; Skipped=$false; Detail="print-sid failed exit=$($psid.ExitCode) err=$(Get-LineHead -Lines $psid.Stderr -Max 160)" } }
    $sid = ($psid.Stdout -join '').Trim()
    $probe = Invoke-ConnectProbe -SandboxArgs ($flags + @('--sid',$sid)) -TargetHost 'evil.example.com' -WorkingDirectory $d -Env $envOverrides
    $raw = $probe.Raw
    $got403 = ($raw -match 'HTTP/1\.1 403 Forbidden')
    $gotHeader = ($raw -match 'X-Sandbox: denied')
    $s = Invoke-Sandbox -Args @('audit','show',$sid,'--json')
    $learnedDeny = $false
    $learnedScope = $false
    $learnedPersisted = $false
    $blocklistDeny = $false
    $allowLeaf = $false
    $promptLeaf = $false
    foreach ($l in @($s.Stdout | Where-Object { $_.Trim() })) {
        try { $o = $l | ConvertFrom-Json } catch { continue }
        if ($o.op -ne 'CONNECT') { continue }
        if ($o.source -eq 'prompt' -or $o.source -eq 'prompt_overload' -or $o.source -eq 'unavailable') { $promptLeaf = $true }
        if ($o.host -ne 'evil.example.com') { continue }
        if ($o.disposition -eq 'deny' -and $o.source -eq 'learned' -and $o.reason -eq 'learned deny') {
            $learnedDeny = $true
            if ($o.scope -eq 'host') { $learnedScope = $true }
            if ($o.persisted -eq $true) { $learnedPersisted = $true }
        }
        if ($o.disposition -eq 'deny' -and $o.source -eq 'blocklist') { $blocklistDeny = $true }
        # Mirror S-87's negative: the winning LEARNED deny must not also leave an
        # allow leaf for the same host (deny-then-admit would still answer 403).
        if ($o.disposition -eq 'allow') { $allowLeaf = $true }
    }
    $passed = $probe.Ok -and $got403 -and $gotHeader -and $learnedDeny -and $learnedScope -and $learnedPersisted -and (-not $blocklistDeny) -and (-not $allowLeaf) -and (-not $promptLeaf)
    return @{ Num=88; Name='S-88 (D-1 learned-deny beats blocklist)'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { 'learned deny outranked deny_domain: 403, audit learned/"learned deny" scope=host persisted=true, no blocklist leaf, no allow leaf, no prompt leaf' }
                 else { "probeOk=$($probe.Ok) 403=$got403 header=$gotHeader learned=$learnedDeny scope=$learnedScope persisted=$learnedPersisted blocklistLeaf=$blocklistDeny allowLeaf=$allowLeaf promptLeaf=$promptLeaf raw=$(Get-LineHead -Lines @($raw) -Max 200)" } }
}

# S-89 (D-1; plan S-86): DNS pinning end-to-end - "one resolution per CONNECT,
# and the dial uses exactly the admission answer". DOCUMENTED SKIP, not a test.
# Observing which IPs leave the supervisor needs a CONTROLLED resolver (a
# multi-A answer whose addresses only the test knows); none is available
# hermetically, and the only way to synthesize one on Windows is editing
# %SystemRoot%\System32\drivers\etc\hosts - a system-wide mutation that is
# neither isolated from the rest of the suite nor reliably reversible after a
# crash, so this harness will not make it. The property is pinned at the
# production seam instead, in src/net/proxy.rs:
#   anti_rebinding_dials_exactly_the_admission_resolved_set  (resolver called
#     once; the dialed set equals the admission set; the winner's peer is in it)
#   dial_upstream_resolves_once_and_dials_only_that_answer
#   dial_upstream_denies_a_hostname_that_resolves_to_link_local (the pinned set
#     feeds the hard-deny leg)
# The plan's suggested assertion - "single CONNECT event in the audit log" -
# would NOT test pinning anyway: that leaf is emitted at admission, before the
# dial, and is exactly 1 whether or not the dialer re-resolved. A vacuous green
# here would be worse than an explicit skip.
function Invoke-Scenario-S89 {
    return @{ Num=89; Name='S-89 (D-1 DNS pinning)'; Passed=$true; Skipped=$true
        Detail='DOCUMENTED SKIP - needs a controlled resolver. A hermetic END-TO-END variant is not merely hard but IMPOSSIBLE without a resolver-injection hook in the binary (a production change): a static hosts entry cannot simulate rebinding, and a hosts edit is machine-global and survives a crash. Pinning is unit-pinned in src/net/proxy.rs (anti_rebinding_dials_exactly_the_admission_resolved_set, dial_upstream_resolves_once_and_dials_only_that_answer, dial_upstream_denies_a_hostname_that_resolves_to_link_local)' }
}

# S-90 (D-1; plan S-87): a loopback CONNECT is refused with 403 +
# `X-Sandbox: denied` even when the loopback host is EXPLICITLY allow-listed
# [G-44] - the loopback stage is step (2) of decide(), ahead of the allow-list.
# End-to-end counterpart of the unit test loopback_refused_even_when_allowlisted
# (proxy.rs). Both name forms are probed in ONE session (127.0.0.1 and
# localhost), each allow-listed, so a regression that admit-lists loopback fails
# twice with distinct evidence. The probe's CONNECT port is its fixed 443 (the
# plan's 8080 is immaterial: the refusal happens before the port is used), and
# nothing asserts on the port. S-75 already exercises this refusal on a NON-443
# port (127.0.0.1:5432), which is what makes probing 443 here lossless.
function Invoke-Scenario-S90 {
    if (-not (Test-LoopbackProxyReachable)) { return @{ Num=90; Name='S-90 (D-1 loopback refused)'; Passed=$true; Skipped=$true; Detail='proxy loopback probe failed - EITHER AppContainer loopback is blocked (run tests elevated or with the admin loopback exemption) OR curl.exe is not on PATH (the shared probe shells out to curl; these scenarios themselves speak CONNECT without it)' } }
    $d = New-ScenarioDir 90
    $fakeHome = Join-Path $d 'home'
    New-Item -ItemType Directory -Path $fakeHome -Force | Out-Null
    $envOverrides = @{ 'USERPROFILE' = $fakeHome }
    $flags = @('run','--allow-cwd','--allow-domain','127.0.0.1','--allow-domain','localhost')
    $psid = Invoke-Sandbox -Args ($flags + @('--print-sid','--','cmd','/c','echo','placeholder')) -WorkingDirectory $d -Env $envOverrides
    if ($psid.ExitCode -ne 0) { return @{ Num=90; Name='S-90 (D-1 loopback refused)'; Passed=$false; Skipped=$false; Detail="print-sid failed exit=$($psid.ExitCode) err=$(Get-LineHead -Lines $psid.Stderr -Max 160)" } }
    $sid = ($psid.Stdout -join '').Trim()
    $probeOk = $true
    $statusOk = $true
    $headerOk = $true
    $probeDetail = ''
    foreach ($h in @('127.0.0.1','localhost')) {
        $probe = Invoke-ConnectProbe -SandboxArgs ($flags + @('--sid',$sid)) -TargetHost $h -WorkingDirectory $d -Env $envOverrides
        $raw = $probe.Raw
        $got403 = ($raw -match 'HTTP/1\.1 403 Forbidden')
        $gotHeader = ($raw -match 'X-Sandbox: denied')
        if (-not $probe.Ok) { $probeOk = $false }
        if (-not $got403) { $statusOk = $false }
        if (-not $gotHeader) { $headerOk = $false }
        if ($probeDetail -eq '' -and -not ($probe.Ok -and $got403 -and $gotHeader)) { $probeDetail = "[$h] exit=$($probe.ExitCode) raw=$(Get-LineHead -Lines @($raw) -Max 120)" }
    }
    $s = Invoke-Sandbox -Args @('audit','show',$sid,'--json')
    $loopbackLeaves = @{}
    $allowLeaf = $false
    $promptLeaf = $false
    foreach ($l in @($s.Stdout | Where-Object { $_.Trim() })) {
        try { $o = $l | ConvertFrom-Json } catch { continue }
        if ($o.op -ne 'CONNECT') { continue }
        if ($o.source -eq 'prompt' -or $o.source -eq 'prompt_overload' -or $o.source -eq 'unavailable') { $promptLeaf = $true }
        if ($o.disposition -eq 'allow') { $allowLeaf = $true }
        if ($o.disposition -eq 'deny' -and $o.source -eq 'hard-deny' -and $o.reason -eq 'loopback_refused') { $loopbackLeaves[$o.host] = $true }
    }
    $bothAudited = $loopbackLeaves.ContainsKey('127.0.0.1') -and $loopbackLeaves.ContainsKey('localhost')
    $passed = $probeOk -and $statusOk -and $headerOk -and $bothAudited -and (-not $allowLeaf) -and (-not $promptLeaf)
    return @{ Num=90; Name='S-90 (D-1 loopback refused)'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { 'loopback CONNECT refused while allow-listed (127.0.0.1 + localhost): 403 + X-Sandbox: denied; audit hard-deny/loopback_refused for both, no allow and no prompt leaf' }
                 else { "probeOk=$probeOk 403=$statusOk header=$headerOk audited127=$($loopbackLeaves.ContainsKey('127.0.0.1')) auditedLocalhost=$($loopbackLeaves.ContainsKey('localhost')) allowLeaf=$allowLeaf promptLeaf=$promptLeaf $probeDetail" } }
}

# S-91 (D-1; plan S-88): a CONNECT carrying NO Proxy-Authorization is rejected
# by the supervisor's own token gate with `407` + `Proxy-Authenticate` [G-7,
# G-27]. S-36 covers this loosely from curl's side (curl retries a 407 and can
# disguise the first response); this scenario is the tight version. An inner
# PowerShell body (ASCII-only, an explicit param for the target, the S-75/S-77
# wrapper-file precedent) speaks the CONNECT itself over a raw TcpClient:
# curl's behaviour around the header is exactly what is being controlled for,
# so curl is removed from the path. The supervisor writes the 407 and CLOSES
# (no dial, no admission), which is cross-checked in the audit: the token gate
# emits disposition deny / reason "no_token" / source "default" / host
# "<unknown>" / port 0, and NO CONNECT leaf for the requested host exists.
# Byte-shape of that leaf is the proxy.rs token-gate code, not an assumption.
function Invoke-Scenario-S91 {
    if (-not (Test-LoopbackProxyReachable)) { return @{ Num=91; Name='S-91 (D-1 missing Proxy-Authorization)'; Passed=$true; Skipped=$true; Detail='proxy loopback probe failed - EITHER AppContainer loopback is blocked (run tests elevated or with the admin loopback exemption) OR curl.exe is not on PATH (the shared probe shells out to curl; these scenarios themselves speak CONNECT without it)' } }
    $d = New-ScenarioDir 91
    $inner = @'
param([string]$TargetHost)
# Deliberately NO Proxy-Authorization header: that absence is the test.
if (-not $env:HTTP_PROXY) { Write-Output 'S91_NO_PROXY_ENV'; exit 5 }
# Read the port as a STRING first: [int]$env:SANDBOX_PROXY_PORT throws a cast
# error on an empty or absent value, which would surface as a raw PowerShell
# error instead of the clean NO_PROXY_PORT marker. Parse, then range-check.
$portRaw = $env:SANDBOX_PROXY_PORT
$port = 0
if (-not [int]::TryParse([string]$portRaw, [ref]$port)) { Write-Output 'S91_NO_PROXY_PORT'; exit 3 }
$m = [regex]::Match($env:HTTP_PROXY, '://(?:[^@/]*@)?([^:/]+):')
$dialHost = if ($m.Success) { $m.Groups[1].Value } else { '127.0.0.1' }
if ($port -le 0) { Write-Output 'S91_NO_PROXY_PORT'; exit 3 }
$c = New-Object System.Net.Sockets.TcpClient
try { $c.Connect($dialHost, $port) } catch { Write-Output 'S91_DIAL_FAILED'; exit 4 }
$s = $c.GetStream()
$s.ReadTimeout = 10000
$req = "CONNECT ${TargetHost}:443 HTTP/1.1`r`nHost: ${TargetHost}:443`r`n`r`n"
$bytes = [Text.Encoding]::ASCII.GetBytes($req)
$s.Write($bytes, 0, $bytes.Length)
$s.Flush()
$ms = New-Object System.IO.MemoryStream
$buf = New-Object byte[] 8192
while ($true) {
    $n = 0
    try { $n = $s.Read($buf, 0, $buf.Length) } catch { break }
    if ($n -le 0) { break }
    $ms.Write($buf, 0, $n)
}
$c.Close()
$raw = [Text.Encoding]::ASCII.GetString($ms.ToArray())
$lines = $raw -split "`r`n"
$status = if ($lines.Count -gt 0) { $lines[0] } else { '' }
$authHdr = 0
foreach ($ln in $lines) { if ($ln -match '^(?i)Proxy-Authenticate:') { $authHdr = 1 } }
Write-Output ('S91_STATUS=' + $status)
Write-Output ('S91_AUTH_HEADER=' + $authHdr)
# The gate's contract is a headers-only 407: assert the DECLARED length of the
# header block, not a measured byte count (a client acts on the declaration).
$clZero = 0
foreach ($ln in $lines) {
    if ($ln -eq '') { break }
    if ($ln -match '^(?i)Content-Length:\s*0\s*$') { $clZero = 1 }
}
Write-Output ('S91_CL_ZERO=' + $clZero)
exit 0
'@
    Set-Content -LiteralPath (Join-Path $d 's91-no-auth-connect.ps1') -Value $inner -Encoding ASCII
    $fakeHome = Join-Path $d 'home'
    New-Item -ItemType Directory -Path $fakeHome -Force | Out-Null
    $envOverrides = @{ 'USERPROFILE' = $fakeHome }
    # The target is deliberately NOT allow-listed: if the token gate ever let
    # this through, the verdict would be a clean 403 instead of real egress.
    $flags = @('run','--allow-cwd','--allow-domain','api.anthropic.com','--no-prompt')
    $psid = Invoke-Sandbox -Args ($flags + @('--print-sid','--','cmd','/c','echo','placeholder')) -WorkingDirectory $d -Env $envOverrides
    if ($psid.ExitCode -ne 0) { return @{ Num=91; Name='S-91 (D-1 missing Proxy-Authorization)'; Passed=$false; Skipped=$false; Detail="print-sid failed exit=$($psid.ExitCode) err=$(Get-LineHead -Lines $psid.Stderr -Max 160)" } }
    $sid = ($psid.Stdout -join '').Trim()
    # Absolute path: the harness rule is absolute paths for anything the child
    # opens. The relative form only worked because spawn.rs passes lpCurrentDirectory.
    $innerScript = Join-Path $d 's91-no-auth-connect.ps1'
    $r = Invoke-Sandbox -Args ($flags + @('--sid',$sid,'--','powershell','-NoProfile','-ExecutionPolicy','Bypass','-File',$innerScript,'-TargetHost','example.com')) -WorkingDirectory $d -Env $envOverrides
    $out = ($r.Stdout -join "`n")
    if ($out -match 'S91_NO_PROXY_PORT' -or $out -match 'S91_NO_PROXY_ENV' -or $out -match 'S91_DIAL_FAILED') {
        return @{ Num=91; Name='S-91 (D-1 missing Proxy-Authorization)'; Passed=$false; Skipped=$false
            Detail = "inner probe could not reach the proxy (exit=$($r.ExitCode)): $(Get-LineHead -Lines @($out) -Max 160)" }
    }
    # Exact status line, not a contains-'407' check: the challenge is the
    # contract, and a numeric port or an unrelated header containing 407 must
    # not satisfy it.
    $got407 = ($out -match 'S91_STATUS=HTTP/1\.1 407 Proxy Authentication Required')
    $gotChallenge = ($out -match 'S91_AUTH_HEADER=1')
    # Headers-only 407: Content-Length: 0 is the token gate's body contract.
    $gotNoBody = ($out -match 'S91_CL_ZERO=1')
    $s = Invoke-Sandbox -Args @('audit','show',$sid,'--json')
    $tokenLeaf = $false
    $admissionLeaf = $false
    foreach ($l in @($s.Stdout | Where-Object { $_.Trim() })) {
        try { $o = $l | ConvertFrom-Json } catch { continue }
        if ($o.op -ne 'CONNECT') { continue }
        if ($o.disposition -eq 'deny' -and $o.reason -eq 'no_token' -and $o.source -eq 'default' -and $o.host -eq '<unknown>') { $tokenLeaf = $true }
        if ($o.host -eq 'example.com') { $admissionLeaf = $true }
    }
    $passed = ($r.ExitCode -eq 0) -and $got407 -and $gotChallenge -and $gotNoBody -and $tokenLeaf -and (-not $admissionLeaf)
    return @{ Num=91; Name='S-91 (D-1 missing Proxy-Authorization)'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { 'CONNECT with no Proxy-Authorization: 407 Proxy Authentication Required + Proxy-Authenticate + Content-Length: 0 (headers only); audit default/no_token (<unknown>), no admission leaf for example.com' }
                 else { "exit=$($r.ExitCode) got407=$got407 challenge=$gotChallenge noBody=$gotNoBody tokenLeaf=$tokenLeaf admissionLeaf=$admissionLeaf out=$(Get-LineHead -Lines @($out) -Max 200) err=$(Get-LineHead -Lines $r.Stderr -Max 160)" } }
}

# S-92 (D-3; plan S-89): prompt_overload - nine concurrent CONNECTs to nine
# distinct unknown hosts must spawn exactly EIGHT dialogs and deny the ninth
# immediately with audit source "prompt_overload" [G-28]. MANUAL APPROVAL
# REQUIRED: the assertion is a human counting native TaskDialogs, and the
# harness never simulates dialog clicks (the S-78 convention). The recipe below
# is the one verified at plan Task 3.8 Checkpoint 3 item 7.
function Invoke-Scenario-S92 {
    return @{ Num=92; Name='S-92 (D-3 prompt_overload)'; Passed=$true; Skipped=$true
        Detail='MANUAL APPROVAL required - 8 dialogs must be counted by eye (plan Task 3.8 Checkpoint 3 item 7). Recipe: ONE session with the prompt ENABLED (no --no-prompt) and --allow-domain api.anthropic.com; inside it run: curl --parallel --parallel-max 9 -s -m 40 -o NUL <nine https URLs, n1.example.com..n9.example.com> (repeat -o NUL once per URL). Expect exactly 8 dialogs and the 9th request denied; confirm with sandbox audit show <sid> --json -> one CONNECT leaf with source=prompt_overload, disposition=deny. The DENIED HOST IS WHICHEVER REQUEST LOSES THE RACE, not necessarily n9, so a different denied host is NOT a failure: the invariant is exactly 8 dialogs + exactly one prompt_overload leaf (source=prompt_overload)' }
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
# this keeps reserved numbers free. Numbering above S-71 is per-branch (see the
# Task 3.8 numbering note above the S-72 section).
$script:MaxScenario = 92
$script:ScenarioFunctions = @{
    72 = { Invoke-Scenario-S72 }
    73 = { Invoke-Scenario-S73 }
    74 = { Invoke-Scenario-S74 }
    75 = { Invoke-Scenario-S75 }
    76 = { Invoke-Scenario-S76 }
    77 = { Invoke-Scenario-S77 }
    78 = { Invoke-Scenario-S78 }
    79 = { Invoke-Scenario-S79 }
    80 = { Invoke-Scenario-S80 }
    81 = { Invoke-Scenario-S81 }
    82 = { Invoke-Scenario-S82 }
    83 = { Invoke-Scenario-S83 }
    84 = { Invoke-Scenario-S84 }
    85 = { Invoke-Scenario-S85 }
    86 = { Invoke-Scenario-S86 }
    87 = { Invoke-Scenario-S87 }
    88 = { Invoke-Scenario-S88 }
    89 = { Invoke-Scenario-S89 }
    90 = { Invoke-Scenario-S90 }
    91 = { Invoke-Scenario-S91 }
    92 = { Invoke-Scenario-S92 }
}

function Invoke-Scenario { param([int]$Number)
    if ($Number -lt 1 -or $Number -gt $script:MaxScenario) { return $null }
    if ($script:ScenarioFunctions.ContainsKey($Number)) { return & $script:ScenarioFunctions[$Number] }
    if ($Number -gt $script:Scenarios.Count) {
        return @{ Num=$Number; Name="S-$Number (reserved)"; Passed=$false; Skipped=$true
            Detail = 'scenario number not registered on this branch (reserved — see the numbering note above the S-72 section)' }
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
            if ($r.Detail -match 'loopback blocked') { $loopbackSkipped = $true }
        }
        if ($hardFail) { Write-Host "SANDBOX: FAIL" -ForegroundColor Red }
        elseif ($loopbackSkipped -and $pythonSkipped) { Write-Host "SANDBOX: PASS (loopback + python scenarios skipped)" -ForegroundColor Yellow }
        elseif ($loopbackSkipped) {
            $probeCodes = if ($script:LoopbackProxyProbeExitCodes) { ($script:LoopbackProxyProbeExitCodes -join ',') } else { 'n/a' }
            Write-Host ("SANDBOX: PASS (loopback network scenarios skipped - probe curl exit codes: {0}; 28 = timeout/blocked)" -f $probeCodes) -ForegroundColor Yellow
        }
        elseif ($pythonSkipped) { Write-Host "SANDBOX: PASS (python scenarios skipped)" -ForegroundColor Yellow }
        else { Write-Host "SANDBOX: PASS" -ForegroundColor Green }
    }

    if ($script:OwnsCwd -and -not $Keep) { Remove-Item -LiteralPath $script:TempCwd -Recurse -Force -ErrorAction SilentlyContinue }
    if ($Strict -and $skip -gt 0) { return 1 }
    if ($gateFailed -or $anyFail) { return 1 }
    return 0
}

function Cleanup-Acls {
    # Remove AppContainer (S-1-15-2-*) ACEs that sandbox runs added to the
    # ancestor directories. These persist and accumulate; if left they
    # eventually cause SetNamedSecurityInfoW to hang (see AGENTS.md).
    $paths = @(
        $env:USERPROFILE,
        (Join-Path $env:USERPROFILE "AppData"),
        (Join-Path $env:USERPROFILE "AppData\Local"),
        $env:TEMP
    )
    $removed = 0
    foreach ($path in $paths) {
        if (-not (Test-Path -LiteralPath $path)) { continue }
        try {
            $acl = Get-Acl -LiteralPath $path -ErrorAction Stop
            $stale = @($acl.Access | Where-Object { $_.IdentityReference.Value -match '^S-1-15-2-\d+-\d+-\d+-\d+-\d+-\d+-\d+' })
            if ($stale.Count -eq 0) { continue }
            foreach ($ace in $stale) { $acl.RemoveAccessRuleSpecific($ace) | Out-Null }
            Set-Acl -LiteralPath $path -AclObject $acl -ErrorAction Stop
            $removed += $stale.Count
        } catch {
            Write-Host "[cleanup] WARN: failed to clean ACL on ${path}: $_" -ForegroundColor Yellow
        }
    }
    if ($removed -gt 0) { Write-Host "[cleanup] removed $removed AppContainer ACEs from ancestor dirs" -ForegroundColor DarkGray }
}

$rc = 0
try {
    $rc = Main
} finally {
    Cleanup-Acls
}
exit $rc
