#requires -Version 7.0
<#
.SYNOPSIS
    Debug the S-9 venv/ensurepip failure inside a kept test VM.

.DESCRIPTION
    Runs the S-9 failure steps DIRECTLY (no venv wrapper hiding the real
    error) via PowerShell Direct in a kept VM, capturing every exit code
    and all stdout/stderr:

      1. sandbox run --allow-cwd -- python -c <print TEMP env + gettempdir()>
         — verifies the per-session TEMP redirect (b5a2b0d) reaches the
           child and that tempfile resolves to .sandbox\<sid>\tmp.
      2. sandbox run --allow-cwd -- python -c <create a temp file>
         — proves the redirected dir is actually writable.
      3. sandbox run --allow-cwd -- python -m venv --without-pip <venv>
         then sandbox run --allow-cwd -- <venv>\Scripts\python.exe -m
         ensurepip -v --upgrade --default-pip
         — reproduces the exact failing step with -v so pip/ensurepip
           cannot fail silently.

    Requires the VM to have the repo staged at C:\sbx-repo and the release
    binary built (i.e. a kept VM from a failed Invoke-TestsInVM run with
    -KeepOnFailure).

.PARAMETER VmName
    Name of the kept VM (e.g. sbx-test-20261011-021559-414).

.EXAMPLE
    pwsh -NoProfile -File tests\vm\debug-s9-in-vm.ps1 -VmName sbx-test-20261011-021559-414
#>
param(
    [Parameter(Mandatory)][string]$VmName
)

$ErrorActionPreference = 'Stop'
$thisDir = $PSScriptRoot
$settingsFile = Join-Path $thisDir 'vm-settings.json'
if (-not (Test-Path -LiteralPath $settingsFile)) {
    throw "vm-settings.json not found: $settingsFile"
}
$settings = Get-Content -LiteralPath $settingsFile -Raw | ConvertFrom-Json
$guestCred = New-Object System.Management.Automation.PSCredential(
    ([string]$settings.guestUser),
    (ConvertTo-SecureString ([string]$settings.guestPassword) -AsPlainText -Force))

Write-Host "[s9dbg] connecting to VM $VmName ..."
$out = Invoke-Command -VMName $VmName -Credential $guestCred -ScriptBlock {
    $ErrorActionPreference = 'Continue'
    $sbx = 'C:\sbx-repo\target\release\sandbox.exe'
    $work = Join-Path $env:TEMP ("s9dbg-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
    New-Item -ItemType Directory -Path $work | Out-Null
    Set-Location -LiteralPath $work

    function Run-Step {
        param([string]$Label, [string[]]$SbxArgs)
        Write-Host ""
        Write-Host "=== $Label ==="
        & $sbx @SbxArgs 2>&1 | ForEach-Object { Write-Host "  $_" }
        Write-Host ("--- exit: $LASTEXITCODE")
    }

    Write-Host "[s9dbg] workdir: $work"
    Write-Host "[s9dbg] sandbox: $sbx"
    & python --version 2>&1 | ForEach-Object { Write-Host "[s9dbg] python: $_" }

    # 1. Where does the child think TEMP is, and what does tempfile pick?
    Run-Step 'TEMP redirect + gettempdir' @(
        'run','--allow-cwd','--','python','-c',
        "import os,tempfile;print('TEMP env  =',os.environ.get('TEMP'));print('TMP env   =',os.environ.get('TMP'));print('gettempdir=',tempfile.gettempdir())")

    # 2. Is the redirected dir actually writable end-to-end?
    Run-Step 'tempfile write' @(
        'run','--allow-cwd','--','python','-c',
        "import tempfile;f=tempfile.NamedTemporaryFile(delete=False);f.write(b'x');f.close();print('wrote:',f.name)")

    # 3. venv without pip (isolates venv creation from ensurepip).
    Run-Step 'venv --without-pip' @(
        'run','--allow-cwd','--','python','-m','venv','--without-pip','.dbgvenv')

    # 4. The exact failing step, verbose. Runs the venv python inside a
    #    fresh sandbox session (like the S-9 flow) but WITHOUT venv's
    #    subprocess wrapper, so pip/ensurepip cannot fail silently.
    Run-Step 'venv python -m ensurepip -v (sandboxed)' @(
        'run','--allow-cwd','--',
        (Join-Path $work '.dbgvenv\Scripts\python.exe'),
        '-m','ensurepip','-v','--upgrade','--default-pip')

    # 5. Same, but unsandboxed inside the VM — the control that must pass.
    Write-Host ""
    Write-Host "=== venv python -m ensurepip -v (unsandboxed control) ==="
    & (Join-Path $work '.dbgvenv\Scripts\python.exe') -m ensurepip -v --upgrade --default-pip 2>&1 |
        ForEach-Object { Write-Host "  $_" }
    Write-Host "--- exit: $LASTEXITCODE"

    Write-Host ""
    Write-Host "[s9dbg] left in VM for further poking: $work"
}
Write-Host "[s9dbg] done."
