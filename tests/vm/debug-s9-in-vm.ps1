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
      - probe_ops      per-op probes in cwd + %TEMP% (or AC temp), each
                       op reported individually: listdir, plain open,
                       open+unlink, O_TEMPORARY open, mkdir, write-
                       inside, listdir-subdir, chmod-created-file,
                       rmtree, mkdir+rmdir, subprocess spawn
      - venv repro    exact S-9 flow (venv WITH pip) + a direct
                       `ensurepip -v` on the resulting venv python —
                       venv swallows the ensurepip subprocess's stderr,
                       so the direct run is the only way to see the
                       real error
      - probe_mkmode  the S-9 root cause hunt: tempfile.mkdtemp calls
                       os.mkdir(path, 0o600) — an EXPLICIT mode — and
                       that dir denies its own creator (even scandir),
                       while default-mode mkdir dirs work fine. This
                       probe creates dirs at 0o777/0o755/0o700/0o600 in
                       cwd AND the granted AC temp, tries write+listdir
                       inside each, plus the exact mkdtemp+write op, so
                       the icacls dump afterwards shows precisely which
                       ACEs/mask/protection explicit modes produce.

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
    # Surface non-fatal spawn diagnostics (token-owner fixup outcome).
    $env:SANDBOX_DIAG = '1'
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
import os, sys, shutil, subprocess
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
        os.mkdir(p('pd1')); return 'isdir=%s' % os.path.isdir(p('pd1'))
    t('mkdir', _mk)
    def _wi():
        open(p('pd1/f'), 'wb').write(b'x'); return 'size=%s' % os.path.getsize(p('pd1/f'))
    t('write-inside', _wi)
    def _ls():
        return os.listdir(p('pd1'))
    t('listdir subdir', _ls)
    def _ch():
        os.chmod(p('pd1/f'), 0o700)
    t('chmod created file', _ch)
    def _rm():
        shutil.rmtree(p('pd1'))
    t('rmtree subdir', _rm)
    def _rmdir():
        os.mkdir(p('pd2')); os.rmdir(p('pd2'))
    t('mkdir + rmdir', _rmdir)
    def _sp():
        r = subprocess.run([sys.executable, '-c', 'print("subproc-ok")'],
                           capture_output=True, text=True)
        return 'rc=%s out=%r err=%r' % (r.returncode, r.stdout.strip(), r.stderr.strip())
    t('subprocess spawn', _sp)
'@

    Set-Content -LiteralPath (Join-Path $work 'probe_mkmode.py') -Encoding ASCII -Value @'
import os, tempfile
def t(label, fn):
    try:
        r = fn()
        print('  %-34s OK %s' % (label, r if r is not None else ''))
    except OSError as e:
        print('  %-34s FAIL winerror=%s errno=%s %s' % (label, e.winerror, e.errno, e.strerror))
print('TEMP:', os.environ.get('TEMP'))
print('cwd :', os.getcwd())
# Exact mkdtemp+write op that ensurepip's _bootstrap does.
def _mk():
    td = tempfile.mkdtemp()
    open(os.path.join(td, 'whltest'), 'wb').write(b'x')
    return td
t('mkdtemp + write inside', _mk)
for base, blabel in ((os.getcwd(), 'cwd'), (os.environ.get('TEMP', ''), 'temp')):
    if not base:
        continue
    dn = os.path.join(base, 'm_%s_default' % blabel)
    os.mkdir(dn)
    def _w(d=dn):
        open(os.path.join(d, 'f'), 'wb').write(b'x')
    t('%s default mkdir: write' % blabel, _w)
    for m in (0o777, 0o755, 0o700, 0o600):
        d = os.path.join(base, 'm_%s_%o' % (blabel, m))
        def _c(m=m, d=d):
            os.mkdir(d, m)
        t('%s mkdir 0o%o' % (blabel, m), _c)
        def _wm(d=d):
            open(os.path.join(d, 'f'), 'wb').write(b'x')
        t('%s mkdir 0o%o: write' % (blabel, m), _wm)
        def _lm(d=d):
            return os.listdir(d)
        t('%s mkdir 0o%o: listdir' % (blabel, m), _lm)
'@

    Set-Content -LiteralPath (Join-Path $work 'ac_bootstrap.py') -Encoding ASCII -Value @'
import ctypes, os, sys, subprocess, tempfile
from ctypes import wintypes

advapi32 = ctypes.WinDLL('advapi32', use_last_error=True)
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

TOKEN_QUERY = 0x0008
TOKEN_ADJUST_DEFAULT = 0x0100
TokenOwner = 4
TokenAppContainerSid = 25

advapi32.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
advapi32.OpenProcessToken.restype = wintypes.BOOL
advapi32.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
advapi32.GetTokenInformation.restype = wintypes.BOOL
advapi32.SetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
advapi32.SetTokenInformation.restype = wintypes.BOOL
advapi32.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
kernel32.GetCurrentProcess.restype = wintypes.HANDLE
kernel32.LocalFree.argtypes = [ctypes.c_void_p]
kernel32.LocalFree.restype = ctypes.c_void_p

def t(label, fn):
    try:
        r = fn()
        print('[bootstrap] %-36s OK %s' % (label, r if r is not None else ''))
    except OSError as e:
        print('[bootstrap] %-36s FAIL winerror=%s %s' % (label, e.winerror, e.strerror))

hTok = wintypes.HANDLE()
if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_DEFAULT, ctypes.byref(hTok)):
    print('[bootstrap] OpenProcessToken failed err=', ctypes.get_last_error())
    sys.exit(1)

def tok_info(cls):
    need = wintypes.DWORD(0)
    advapi32.GetTokenInformation(hTok, cls, None, 0, ctypes.byref(need))
    buf = ctypes.create_string_buffer(max(8, need.value))
    if not advapi32.GetTokenInformation(hTok, cls, buf, need, ctypes.byref(need)):
        return None
    return buf

def sid_str(buf):
    if buf is None:
        return '<unavailable>'
    psid = ctypes.cast(buf, ctypes.POINTER(ctypes.c_void_p))[0]
    s = wintypes.LPWSTR()
    if not advapi32.ConvertSidToStringSidW(ctypes.c_void_p(psid), ctypes.byref(s)):
        return '?'
    v = s.value
    kernel32.LocalFree(ctypes.cast(s, ctypes.c_void_p))
    return v

# --- control: 0o700 mkdir is expected to FAIL for this process now ---
t('PRE  mkdir 0o700', lambda: os.mkdir('bt700pre', 0o700))
t('PRE  write inside bt700pre', lambda: open('bt700pre/f', 'wb').write(b'x'))

ac_buf = tok_info(TokenAppContainerSid)
ac_sid = sid_str(ac_buf)
print('[bootstrap] AC SID                :', ac_sid)
print('[bootstrap] token owner (before) :', sid_str(tok_info(TokenOwner)))

if ac_buf is None:
    print('[bootstrap] no AppContainer SID - not running inside an AppContainer?')
    sys.exit(1)

ac_psid = ctypes.cast(ac_buf, ctypes.POINTER(ctypes.c_void_p))[0]
TOKEN_OWNER = ctypes.c_void_p * 1
owner_struct = TOKEN_OWNER(ctypes.c_void_p(ac_psid))
rc = advapi32.SetTokenInformation(hTok, TokenOwner, ctypes.byref(owner_struct), ctypes.sizeof(TOKEN_OWNER))
err = ctypes.get_last_error() if not rc else 0
print('[bootstrap] SetTokenInformation(TokenOwner=AC SID): rc=%s err=%s' % (rc, err))
print('[bootstrap] token owner (after)  :', sid_str(tok_info(TokenOwner)))

# --- retest: same process, token owner now the AC SID ---
t('POST mkdir 0o700', lambda: os.mkdir('bt700', 0o700))
t('POST write inside bt700', lambda: open('bt700/f', 'wb').write(b'x'))
t('POST listdir bt700', lambda: os.listdir('bt700'))

def _mk():
    td = tempfile.mkdtemp()
    open(os.path.join(td, 'w'), 'wb').write(b'x')
    return td
t('POST mkdtemp + write (ensurepip op)', _mk)

# --- child test: does the owner survive CreateProcess? (the product fix
#     depends on the spawned target inheriting the owner) ---
r = subprocess.run([sys.executable, '-m', 'venv', '.btvenv'], capture_output=True, text=True)
print('[bootstrap] child `python -m venv .btvenv` rc=', r.returncode)
if r.stdout.strip():
    print('[bootstrap]   stdout:', r.stdout.strip()[-400:])
if r.stderr.strip():
    print('[bootstrap]   stderr:', r.stderr.strip()[-800:])
if r.returncode == 0:
    vp = os.path.join('.btvenv', 'Scripts', 'python.exe')
    rp = subprocess.run([vp, '-m', 'pip', '--version'], capture_output=True, text=True)
    print('[bootstrap] child pip --version rc=', rp.returncode, rp.stdout.strip())
'@

    Write-Host "[s9dbg] workdir: $work"
    & python --version 2>&1 | ForEach-Object { Write-Host "[s9dbg] python: $_" }

    # ------------------------------------------------------------------
    # 0b. Token dump from inside the AC: whoami lists the process token's
    #     SIDs with their attributes (deny-only / use-for-allow-only /
    #     enabled) — settles which SIDs can satisfy allow ACEs, and shows
    #     the integrity level of AppContainer processes.
    # ------------------------------------------------------------------
    Run-Step 'sandboxed whoami /user /groups (AC token dump)' @(
        'run','--allow-cwd','--','whoami','/user','/groups')

    # ------------------------------------------------------------------
    # 1. Sandboxed system python: env, tempdir-check replica, per-op probes
    # ------------------------------------------------------------------
    Run-Step 'sandboxed system python: env' @('run','--allow-cwd','--','python','probe_env.py')
    Run-Step 'sandboxed system python: tempdir check replica' @('run','--allow-cwd','--','python','probe_tempdir.py')
    Run-Step 'sandboxed system python: ops in cwd + AC temp' @('run','--allow-cwd','--','python','probe_ops.py')

    # ------------------------------------------------------------------
    # 1b. mkdir-mode matrix: the mkdtemp mechanism. tempfile.mkdtemp
    #     calls os.mkdir(path, 0o600); that dir denied its own creator
    #     in the ensurepip run while default-mode mkdir dirs work.
    #     Dump every created dir with icacls afterwards (step 5) to see
    #     which ACEs/mask/protection an explicit mode produces.
    # ------------------------------------------------------------------
    Run-Step 'sandboxed system python: mkdir-mode matrix + mkdtemp' @(
        'run','--allow-cwd','--','python','probe_mkmode.py')

    # ------------------------------------------------------------------
    # 1c. THE bootstrap experiment — candidate fix, end to end, inside
    #     the AC: python (ctypes) sets its own TokenOwner to its
    #     AppContainer SID, retests the 0o700/mkdtemp ops, then spawns
    #     `python -m venv` as a child (S-9 chain). CPython's 0o700 DACL
    #     is D:P(SY)(BA)(OW) — the OW (owner-rights) ACE is the only
    #     entry that could authorize the sandboxed process, and it only
    #     matches when the object owner == the process token owner ==
    #     the AC SID (AC tokens have user/group SIDs use-for-allow-only,
    #     but the AC SID itself can satisfy allow ACEs).
    # ------------------------------------------------------------------
    Run-Step 'bootstrap: AC python sets TokenOwner=AC SID, retests, child venv' @(
        'run','--allow-cwd','--','python','ac_bootstrap.py')

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
    # 3b. Exact S-9 reproduction: venv WITH pip inside the sandbox.
    #     The harness sees only venv's "Error: Command ... exit status 1"
    #     because venv suppresses the ensurepip subprocess's stderr —
    #     so immediately afterwards we run ensurepip DIRECTLY (-v) on
    #     the same venv python to capture the real error.
    # ------------------------------------------------------------------
    Run-Step 'venv WITH pip (exact S-9 reproduction)' @(
        'run','--allow-cwd','--','python','-m','venv','.dbgvenv2')
    $venv2Py = Join-Path $work '.dbgvenv2\Scripts\python.exe'
    if (Test-Path -LiteralPath $venv2Py) {
        Run-Step 'direct ensurepip -v on that venv (output venv swallows)' @(
            'run','--allow-cwd','--',$venv2Py,'-m','ensurepip','--upgrade','--default-pip','-v')
        Run-Step 'pip --version in venv (installed at all?)' @(
            'run','--allow-cwd','--',$venv2Py,'-m','pip','--version')
    } else {
        Write-Host '[s9dbg] pip-venv python missing, skipping ensurepip probes'
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
    Write-Host "=== icacls: mode-created probe dirs (mkdir-mode matrix) ==="
    foreach ($md in @(Get-ChildItem -LiteralPath $work -Directory -Filter 'm_*' -ErrorAction SilentlyContinue)) {
        Write-Host "--- $($md.FullName)"
        & icacls.exe $md.FullName 2>&1 | ForEach-Object { Write-Host "  $_" }
        $acl = Get-Acl -LiteralPath $md.FullName
        Write-Host ("  owner: {0}" -f $acl.Owner)
    }
    foreach ($bt in @((Join-Path $work 'bt700pre'), (Join-Path $work 'bt700'), (Join-Path $work '.btvenv'))) {
        if (Test-Path -LiteralPath $bt) {
            Write-Host "--- $bt"
            & icacls.exe $bt 2>&1 | ForEach-Object { Write-Host "  $_" }
            $acl = Get-Acl -LiteralPath $bt
            Write-Host ("  owner: {0}" -f $acl.Owner)
        }
    }
    $pkgsRoot2 = Join-Path $env:LOCALAPPDATA 'Packages'
    foreach ($acDir2 in @(Get-ChildItem -LiteralPath $pkgsRoot2 -Directory -Filter 'sandbox.*.ac' -ErrorAction SilentlyContinue)) {
        $acTemp2 = Join-Path $acDir2.FullName 'AC\Temp'
        if (-not (Test-Path -LiteralPath $acTemp2)) { continue }
        foreach ($sub in @(Get-ChildItem -LiteralPath $acTemp2 -Directory -ErrorAction SilentlyContinue)) {
            Write-Host "--- $($sub.FullName)"
            & icacls.exe $sub.FullName 2>&1 | ForEach-Object { Write-Host "  $_" }
            $acl = Get-Acl -LiteralPath $sub.FullName
            Write-Host ("  owner: {0}" -f $acl.Owner)
        }
    }

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
