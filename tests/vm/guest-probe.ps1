# Guest-side diagnostic for the "loopback scenarios skipped" condition.
#
# Run inside the disposable VM (the harness copies the repo to C:\sbx-repo):
#   pwsh -NoProfile -File C:\sbx-repo\tests\vm\guest-probe.ps1
# or from the host:
#   tests\vm\Invoke-TestsInVM.ps1 -Image sbx-base-a -TestCmd "& 'C:\sbx-repo\tests\vm\guest-probe.ps1'"
#
# Answers three questions the suite summary cannot:
#   1. Is the guest session ELEVATED? (the loopback exemption is admin-only)
#   2. What does `sandbox run` print on stderr when it registers loopback?
#   3. What exit code does the loopback probe actually get, and why?
#
# It changes nothing: one `sandbox run` with a 15 s curl timeout.

$ErrorActionPreference = 'Continue'
# script lives at <repo>\tests\vm\guest-probe.ps1 -> repo is THREE levels up
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repo = Split-Path -Parent (Split-Path -Parent $scriptDir)
$exe = Join-Path $repo 'target\release\sandbox.exe'

function Section($t) { Write-Output ''; Write-Output "== $t" }

Section 'identity'
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$pr = New-Object Security.Principal.WindowsPrincipal($id)
Write-Output ("user            : {0}" -f $id.Name)
Write-Output ("IsInRole(Admin) : {0}" -f $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
Write-Output ("token type      : {0}" -f $id.Token)
$integrity = (& whoami /groups | Select-String 'Mandatory Label') -join ' '
Write-Output ("integrity       : {0}" -f $integrity.Trim())
$hyperV = (& whoami /groups | Select-String 'S-1-5-32-578') -join ' '
Write-Output ("Hyper-V admin   : {0}" -f ($(if ($hyperV) { 'yes' } else { 'no' })))

Section 'sandbox exe'
Write-Output ("exe             : {0} (exists: {1})" -f $exe, (Test-Path -LiteralPath $exe))
$curl = (Get-Command curl.exe -ErrorAction SilentlyContinue).Source
Write-Output ("curl.exe        : {0}" -f $curl)

Section 'sandbox run with loopback probe (stderr shown)'
$env:SANDBOX_DIAG = '1'
$outFile = Join-Path $env:TEMP 'probe-out.txt'
$errFile = Join-Path $env:TEMP 'probe-err.txt'
if (-not (Test-Path -LiteralPath $exe)) {
    # -TestCmd mode only stages the source tree; -Phase all is what builds.
    Write-Output "release binary missing - building (this takes a few minutes on a cold target)..."
    Push-Location $repo
    try { & cargo build --release 2>&1 | Select-Object -Last 5 | ForEach-Object { Write-Output "  $_" } }
    finally { Pop-Location }
    if (-not (Test-Path -LiteralPath $exe)) {
        Write-Output "FATAL: cargo build --release did not produce $exe"
        exit 1
    }
}
try {
    $p = Start-Process -FilePath $exe -ArgumentList @(
        'run', '--allow-cwd', '--allow-domain', 'api.anthropic.com', '--',
        'cmd', '/c', 'curl.exe -s -m 15 -o NUL -w %{http_code} http://denied.invalid/'
    ) -WorkingDirectory $env:TEMP -NoNewWindow -PassThru -Wait `
        -RedirectStandardOutput $outFile -RedirectStandardError $errFile
    Write-Output ("exit code       : {0}" -f $p.ExitCode)
}
catch {
    Write-Output ("FATAL: could not start the sandbox: {0}" -f $_.Exception.Message)
    exit 1
}
Write-Output '--- stdout:'
Get-Content -LiteralPath $outFile -ErrorAction SilentlyContinue | ForEach-Object { Write-Output "  $_" }
Write-Output '--- stderr:'
Get-Content -LiteralPath $errFile -ErrorAction SilentlyContinue | ForEach-Object { Write-Output "  $_" }
Write-Output '--- end'
Write-Output ''
Write-Output 'INTERPRETATION: exit 28 = curl timed out (loopback blocked or proxy unreachable);'
Write-Output 'the stderr line "loopback exemption failed" means the guest session could not register it.'
