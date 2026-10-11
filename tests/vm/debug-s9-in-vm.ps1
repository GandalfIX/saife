#requires -Version 7.0
<#
.SYNOPSIS
    Debug the S-9 venv/ensurepip failure inside a kept test VM (probe battery).

.DESCRIPTION
    S-9 fails with a silent exit 1 from `venv python -m ensurepip`, and the
    2026-10-11 debug runs surfaced two unexplained behaviors:

      a) sandboxed: tempfile's tempdir CHECK fails on every candidate,
         including the granted cwd (run 2), though it passed inside the
         OS-created AC\Temp in run 1;
      b) unsandboxed: the VENV python.exe (created inside the sandbox)
         fails the same check where the SYSTEM python succeeds.

    Instead of a one-shot fix, this script pins the divergence down with
    explicit probes that report the exact winerror for every operation:

      - probe_env      executable / TEMP / TMP / cwd
      - probe_tempdir  replica of tempfile's candidate loop with per-
                       candidate winerrors (no guessing which candidate
                       failed or why)
      - probe_ops      per-op probes in cwd + %TEMP% (or AC temp):
                       plain open, open+unlink, O_TEMPORARY open,
                       mkdtemp+write-inside+rmtree, mkdir+listdir

    Each probe runs in four contexts:
      1. sandboxed system python   2. unsandboxed system python
      3. sandboxed venv python      4. unsandboxed venv python
    Plus an exe-provenance experiment (a pwsh-copied python.exe run
    unsandboxed) and icacls/owner dumps of everything involved.

.PARAMETER VmName
    Name of the kept VM (e.g. sbx-test-20261011-123919-551). The VM must
    have the repo staged at C:\sbx-repo and the release binary built.

.EXAMPLE
    pwsh -NoProfile -File tests\vm\debug-s9-in-vm.ps1 -VmName sbx-test-20261011-123919-551
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
        Write-Host ("--- sandbox exit: $LASTEXITCODE")
    }
    function Run-Py {
        param([string]$Label, [string]$Exe, [string]$Script, [string[]]$ExtraArgs)
        Write-Host ""
        Write-Host "=== $Label ==="
        & $Exe $Script @ExtraArgs 2>&1 | ForEach-Object { Write-Host "  $_" }
        Write-Host "--- exit: $LASTEXITCODE"
    }

    # ------------------------------------------------------------------
    # Probe scripts (written as files: no -c quoting pitfalls).
    # ------------------------------------------------------------------
    Set-Content -LiteralPath (Join-Path $work 'probe_env.py') -Encoding ASCII -Value @'
import os, sys
print('executable:', sys.executable)
print('TEMP     :', os.environ.get('TEMP'))
print('TMP      :', os.environ.get('TMP'))
print('cwd      :', os.getcwd())
'@

    Set-Content -LiteralPath (Join-Path $work 'probe_tempdir.py') -Encoding ASCII -Value @'
import os, tempfile
# Exact replica of tempfile._get_default_tempdir's loop (3.12), but every
# candidate's OSError is reported instead of silently skipped.
flags = getattr(tempfile, '_bin_openflags', None)
if flags is None:
    flags = os.O_RDWR | os.O_CREAT | os.O_EXCL
print('check flags:', oct(flags))
candidates = []
for name in ('TMPDIR', 'TEMP', 'TMP'):
    v = os.environ.get(name)
    if v:
        candidates.append(('env:' + name, v))
gw = getattr(tempfile, '_get_win_temp', None)
if gw:
    try:
        candidates.append(('GetTempPathW', gw()))
    except OSError as e:
        candidates.append(('GetTempPathW', 'RAISED %d %s' % (e.winerror, e.strerror)))
candidates.append(('cwd', os.getcwd()))
seen = set()
for label, d in candidates:
    if not d or d in seen:
        continue
    seen.add(d)
    fn = os.path.join(d, 'probecheck')
    try:
        fd = os.open(fn, flags, 0o600)
    except OSError as e:
        print('  %-14s %-60s OPEN FAIL winerror=%s errno=%s %s'
              % (label, d, e.winerror, e.errno, e.strerror))
        continue
    try:
        os.close(fd)
    finally:
        try:
            os.unlink(fn)
            print('  %-14s %-60s OK' % (label, d))
        except OSError as e:
            print('  %-14s %-60s OPEN OK, UNLINK FAIL winerror=%s %s'
                  % (label, d, e.winerror, e.strerror))
'@

    Set-Content -LiteralPath (Join-Path $work 'probe_ops.py') -Encoding ASCII -Value @'
import os, sys, shutil
def t(label, fn):
    try:
        r = fn()
        print('  %-28s OK %s' % (label, r if r is not None else ''))
    except OSError as e:
        print('  %-28s FAIL winerror=%s errno=%s %s' % (label, e.winerror, e.errno, e.strerror))
for d in [os.getcwd(), os.environ.get('TEMP', '')]:
    if not d:
        continue
    print('dir:', d)
    p = lambda n: os.path.join(d, n)
    t('listdir', lambda: len(os.listdir(d)))
    t('plain open wb', lambda: open(p('p1'), 'wb').write(b'x'))
    def _ou():
        open(p('p2'), 'wb').write(b'x'); os.unlink(p('p2'))
    t('open + unlink', _ou)
    def _ot():
        fd = os.open(p('p3'), os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, 'O_TEMPORARY', 0))
        os.close(fd)
    t('O_TEMPORARY open', _ot)
    def _mk():
        sd = os.path.join(d, 'pd1')
        os.mkdir(sd)
        open(os.path.join(sd, 'f'), 'wb').write(b'x')
        os.listdir(sd)
        shutil.rmtree(sd)
    t('mkdir + write-inside + rmtree', _mk)
'@

    Write-Host "[s9dbg] workdir: $work"
    & python --version 2>&1 | ForEach-Object { Write-Host "[s9dbg] python: $_" }

    # ------------------------------------------------------------------
    # 1. Sandboxed system python: env, tempdir-check replica, per-op probes
    # ------------------------------------------------------------------
    Run-Step 'sandboxed system python: env' @('run','--allow-cwd','--','python','probe_env.py')
    Run-Step 'sandboxed system python: tempdir check replica' @('run','--allow-cwd','--','python','probe_tempdir.py')
    Run-Step 'sandboxed system python: ops in cwd + AC temp' @('run','--allow-cwd','--','python','probe_ops.py')

    # ------------------------------------------------------------------
    # 2. Unsandboxed system python (baseline that works)
    # ------------------------------------------------------------------
    Run-Py 'unsandboxed system python: env' python 'probe_env.py'
    Run-Py 'unsandboxed system python: tempdir check replica' python 'probe_tempdir.py'
    Run-Py 'unsandboxed system python: ops in cwd + TEMP' python 'probe_ops.py'

    # ------------------------------------------------------------------
    # 3. Venv (created inside the sandbox, like S-9) + sandboxed venv python
    # ------------------------------------------------------------------
    Run-Step 'venv --without-pip (created inside sandbox)' @(
        'run','--allow-cwd','--','python','-m','venv','--without-pip','.dbgvenv')
    $venvPy = Join-Path $work '.dbgvenv\Scripts\python.exe'
    if (Test-Path -LiteralPath $venvPy) {
        Run-Step 'sandboxed venv python: tempdir check replica' @(
            'run','--allow-cwd','--',$venvPy,'probe_tempdir.py')
        Run-Py 'unsandboxed venv python: env' $venvPy 'probe_env.py'
        Run-Py 'unsandboxed venv python: tempdir check replica' $venvPy 'probe_tempdir.py'
        Run-Py 'unsandboxed venv python: ops in cwd + TEMP' $venvPy 'probe_ops.py'
    } else {
        Write-Host '[s9dbg] venv python missing, skipping venv probes'
    }

    # ------------------------------------------------------------------
    # 4. Exe provenance: same python.exe, but copied by pwsh (not by the
    #    AC process) — isolates "exe created inside AppContainer".
    # ------------------------------------------------------------------
    Write-Host ""
    Write-Host "=== exe provenance: pwsh-copied python.exe, unsandboxed ==="
    $sysPy = (Get-Command python).Source
    $copyPy = Join-Path $work 'python-copy.exe'
    Copy-Item -LiteralPath $sysPy -Destination $copyPy -Force
    & $copyPy probe_tempdir.py 2>&1 | ForEach-Object { Write-Host "  $_" }
    Write-Host "--- exit: $LASTEXITCODE"

    # ------------------------------------------------------------------
    # 5. ACL / owner dumps of everything involved
    # ------------------------------------------------------------------
    Write-Host ""
    Write-Host "=== icacls: TEMP, cwd, venv python, AC temp dirs ==="
    foreach ($target in @(
        $env:TEMP, $work,
        (Join-Path $work '.dbgvenv'), (Join-Path $work '.dbgvenv\Scripts'),
        $venvPy)) {
        if ($target -and (Test-Path -LiteralPath $target)) {
            Write-Host "--- $target"
            & icacls.exe $target 2>&1 | ForEach-Object { Write-Host "  $_" }
        }
    }
    $pkgsRoot = Join-Path $env:LOCALAPPDATA 'Packages'
    foreach ($acDir in @(Get-ChildItem -LiteralPath $pkgsRoot -Directory -Filter 'sandbox.*.ac' -ErrorAction SilentlyContinue)) {
        $acTemp = Join-Path $acDir.FullName 'AC\Temp'
        if (Test-Path -LiteralPath $acTemp) {
            Write-Host "--- $acTemp"
            & icacls.exe $acTemp 2>&1 | ForEach-Object { Write-Host "  $_" }
            foreach ($sub in @(Get-ChildItem -LiteralPath $acTemp -Directory -ErrorAction SilentlyContinue | Select-Object -First 3)) {
                Write-Host "--- $($sub.FullName)"
                & icacls.exe $sub.FullName 2>&1 | ForEach-Object { Write-Host "  $_" }
            }
        }
    }
    if (Test-Path -LiteralPath $venvPy) {
        $acl = Get-Acl -LiteralPath $venvPy
        Write-Host ("venv python.exe owner: {0}" -f $acl.Owner)
    }
    Write-Host ""
    Write-Host "=== whoami (pwsh session, for token reference) ==="
    & whoami.exe /user 2>&1 | ForEach-Object { Write-Host "  $_" }

    Write-Host ""
    Write-Host "[s9dbg] left in VM for further poking: $work"
}
Write-Host "[s9dbg] done."
