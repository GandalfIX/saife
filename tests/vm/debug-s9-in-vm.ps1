#requires -Version 7.0
<#
.SYNOPSIS
    Round-5 S-9 probe battery: the window-station/desktop experiment on
    top of the round-4 DLL-init matrix.

.DESCRIPTION
    State of the hunt after rounds 1-3 (all findings VM-verified):

      - CPython's 0o700 mkdir DACL blocker is fixed (token-owner fixup +
        PYTHONPATH sitecustomize shim); all mkdir modes + mkdtemp now
        work inside the sandbox.
      - pip's vendored platformdirs then dies during config discovery:
        import ctypes fails inside the AC (WinError 1114,
        STATUS_DLL_INIT_FAILED), so platformdirs falls back to its
        registry variant, which queries HKCU\...\Shell Folders for
        'Common AppData' - a value modern Windows no longer writes
        (the host's own hive lacks it too). The registry-grant route
        is exhausted: the key OPENS fine in the AC (31 values, no
        grant needed); the value is simply absent everywhere.
      - So S-9 reduces to one question: why does _ctypes fail DLL init
        inside the AppContainer? Cluster victims observed so far:
        whoami.exe, powershell.exe (PS5) and import ctypes all die
        with 0xC0000142, while python.exe, cmd.exe and the whole
        stdlib probe set run fine.

    This round adds:

      - dllprobe: a zero-dependency Rust crate written and built
        in-guest. For each candidate DLL it reports two
        LoadLibraryExW results:
          probe = DONT_RESOLVE_DLL_REFERENCES (does the image even
                  map? is the file readable by the AC?)
          full  = normal load (deps resolve, every DllMain runs)
        full=FAIL gle=1114 with probe=OK pins a DLL *initialization*
        failure; gle=5 would pin a file-ACL problem instead. The
        candidate matrix covers the import graphs of the victims:
        _ctypes (libffi-8, ole32, oleaut32, combase) and whoami
        (user32, authz, wkscli, netutils, sspicli), plus known-good
        controls (kernel32, ws2_32, python3xx.dll, vcruntime140).
      - The still-missing control: an UNSANDBOXED `python -m venv`
        WITH pip on the same guest. Outside the AC, ctypes works, so
        platformdirs takes the SHGetFolderPathW path and never
        reaches the broken registry fallback.
      - probe_ctypes: the exact import error, plus probe_registry
        baselines both sandboxed and not (expected: OpenKey OK
        everywhere, 'Common AppData' missing everywhere - the
        fallback is broken generally, it is only ever *reached*
        where ctypes is broken).

    VM-only by design: everything it mutates lives in the disposable
    test VM (VM deletion is the rollback).

    Round-5 addition (the state after the round-4 run):

      The in-AC dllprobe matrix split cleanly: user32, gdi32, ole32,
      shell32 and imm32 all fail normal load with gle=1114 while
      DONT_RESOLVE loads succeed - file access is fine, DLL *init*
      fails. gdi32 imports neither user32 nor gdi32 itself; its only
      real dependency is win32u.dll (the win32k syscall layer), so the
      failure sits at the win32k connection, i.e. the window-station
      /desktop access check that raw AppContainer tokens fail while
      the interactive user passes (ole32 fails transitively via its
      static user32/gdi32 imports; oleaut32/combase survive because
      modern builds dropped their user32 dependency).

      This round dumps the supervisor session's window-station and
      desktop security descriptors, grants ALL APPLICATION PACKAGES
      (S-1-15-2-1) generic-all on both, re-runs the whoami flip test,
      the dllprobe matrix, the ctypes import and the FULL S-9 venv
      flow with the grant in place, then restores the original
      security descriptors. If the grant flips everything, S-9 is
      solved and the product fix is a per-spawn grant of the session
      AC SID on winsta+desktop inside spawn.rs.

.PARAMETER VmName
    Name of the kept VM (e.g. sbx-test-20261011-234136-151). The VM must
    have the repo staged at C:\sbx-repo and the release binary built.

.EXAMPLE
    pwsh -NoProfile -File tests\vm\debug-s9-in-vm.ps1 -VmName sbx-test-20261011-234136-151
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

    Set-Content -LiteralPath (Join-Path $work 'probe_shim.py') -Encoding ASCII -Value @'
import os, sys, tempfile
print('python     :', sys.version.split()[0])
print('PYTHONPATH :', os.environ.get('PYTHONPATH'))
print('sitecustomize imported:', 'sitecustomize' in sys.modules)
print('os.mkdir patched     :', getattr(os.mkdir, '_sandbox_pyshim', None) is not None)
try:
    d = tempfile.mkdtemp()
    with open(os.path.join(d, 'f'), 'w') as fp:
        fp.write('x')
    print('mkdtemp + write       : OK', os.path.basename(d))
except Exception as e:
    print('mkdtemp + write       : FAIL', repr(e))
'@

    Set-Content -LiteralPath (Join-Path $work 'probe_registry.py') -Encoding ASCII -Value @'
import winreg

def probe(root, root_name, subkey):
    try:
        k = winreg.OpenKey(root, subkey)
        nvals = winreg.QueryInfoKey(k)[1]
        print('OpenKey', root_name, repr(subkey), ': OK,', nvals, 'values')
    except OSError as e:
        print('OpenKey', root_name, repr(subkey), ': FAIL', e)

probe(winreg.HKEY_CURRENT_USER, 'HKCU',
      r'Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders')
probe(winreg.HKEY_CURRENT_USER, 'HKCU',
      r'Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders')
probe(winreg.HKEY_CURRENT_USER, 'HKCU', r'Environment')
probe(winreg.HKEY_LOCAL_MACHINE, 'HKLM',
      r'SOFTWARE\Microsoft\Windows NT\CurrentVersion')

# Exact call pip/platformdirs makes while discovering its config files.
try:
    key = winreg.OpenKey(
        winreg.HKEY_CURRENT_USER,
        r'Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders')
    v, _t = winreg.QueryValueEx(key, 'Common AppData')
    print('platformdirs call: OK ->', v)
except OSError as e:
    print('platformdirs call: FAIL', e)
'@

    Set-Content -LiteralPath (Join-Path $work 'probe_ctypes.py') -Encoding ASCII -Value @'
# The exact import that decides which platformdirs variant pip uses.
# import ctypes first (pure-python wrapper + C module), then the bare
# C module to strip the wrapper from the picture.
for mod in ('ctypes', '_ctypes'):
    try:
        __import__(mod)
        print('import %-8s: OK' % mod)
    except BaseException as e:
        print('import %-8s: %s: %s' % (mod, type(e).__name__, e))
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

    Write-Host "[s9dbg] workdir: $work"
    & python --version 2>&1 | ForEach-Object { Write-Host "[s9dbg] python: $_" }

    # ------------------------------------------------------------------
    # 1. Victim #1: whoami inside the AC. Run-Step prints the sandbox
    #    exit code - expect -1073741502 (0xC0000142) and thus the whole
    #    point of this round: something in its import graph fails DLL
    #    init inside the AppContainer.
    # ------------------------------------------------------------------
    Run-Step 'sandboxed whoami /user /groups (expect 0xC0000142)' @(
        'run','--allow-cwd','--','whoami','/user','/groups')

    # ------------------------------------------------------------------
    # 2. Sandboxed system python: environment, shim state, tempdir
    #    replica, registry view baseline, ctypes import error.
    # ------------------------------------------------------------------
    Run-Step 'sandboxed system python: env' @('run','--allow-cwd','--','python','probe_env.py')
    Run-Step 'sandboxed system python: shim state + mkdtemp' @('run','--allow-cwd','--','python','probe_shim.py')
    Run-Step 'sandboxed system python: tempdir check replica' @('run','--allow-cwd','--','python','probe_tempdir.py')
    Run-Step 'sandboxed system python: registry view baseline' @(
        'run','--allow-cwd','--','python','probe_registry.py')
    Run-Step 'sandboxed system python: ctypes import error (THE blocker)' @(
        'run','--allow-cwd','--','python','probe_ctypes.py')

    # ------------------------------------------------------------------
    # 3. Unsandboxed system python: control side of 2.
    # ------------------------------------------------------------------
    Run-Py 'unsandboxed system python: registry view (control)' python 'probe_registry.py'
    Run-Py 'unsandboxed system python: ctypes import (control)' python 'probe_ctypes.py'

    # ------------------------------------------------------------------
    # 4. Exact S-9 reproduction: venv WITH pip inside the sandbox, then
    #    a direct ensurepip -v on the resulting venv python (venv
    #    swallows the ensurepip subprocess's stderr) and pip --version.
    #    Current expectation: venv fails; the direct ensurepip traceback
    #    shows the platformdirs 'Common AppData' FileNotFoundError; the
    #    hunt is upstream of that at the _ctypes 0xC0000142 failure.
    # ------------------------------------------------------------------
    Run-Step 'venv WITH pip (exact S-9 reproduction)' @(
        'run','--allow-cwd','--','python','-m','venv','.dbgvenv')
    $venvPy = Join-Path $work '.dbgvenv\Scripts\python.exe'
    if (Test-Path -LiteralPath $venvPy) {
        Run-Step 'direct ensurepip -v on that venv (output venv swallows)' @(
            'run','--allow-cwd','--',$venvPy,'-m','ensurepip','--upgrade','--default-pip','-v')
        Run-Step 'pip --version in venv (installed at all?)' @(
            'run','--allow-cwd','--',$venvPy,'-m','pip','--version')
    } else {
        Write-Host '[s9dbg] pip-venv python missing, skipping ensurepip probes'
    }

    # ------------------------------------------------------------------
    # 5. The still-missing control: UNSANDBOXED venv WITH pip. Outside
    #    the AC, ctypes works, so platformdirs takes the
    #    SHGetFolderPathW path and never reaches the broken registry
    #    fallback. If this passes while step 4 fails, the AppContainer
    #    is the only differing variable for S-9.
    # ------------------------------------------------------------------
    Write-Host ""
    Write-Host "=== unsandboxed baseline: python -m venv WITH pip ==="
    & python -m venv (Join-Path $work 'basevenv') 2>&1 | ForEach-Object { Write-Host "  $_" }
    Write-Host "--- exit: $LASTEXITCODE"
    $basePy = Join-Path $work 'basevenv\Scripts\python.exe'
    if (Test-Path -LiteralPath $basePy) {
        & $basePy -m pip --version 2>&1 | ForEach-Object { Write-Host "  $_" }
        Write-Host "--- exit: $LASTEXITCODE"
    }

    # ------------------------------------------------------------------
    # 6. dllprobe: LoadLibraryExW matrix, written + built in-guest.
    #    probe = DONT_RESOLVE_DLL_REFERENCES (image maps? file readable
    #    by the AC?), full = normal load (dependency graph resolves,
    #    every DllMain runs). full=FAIL gle=1114 with probe=OK pins a
    #    DLL *initialization* failure inside the AppContainer; gle=5
    #    would pin a file-ACL problem instead. Candidates = the import
    #    graphs of the observed victims (_ctypes: libffi-8, ole32,
    #    oleaut32, combase; whoami: user32, authz, wkscli, netutils,
    #    sspicli) plus known-good controls.
    # ------------------------------------------------------------------
    $probeDir = Join-Path $work 'dllprobe'
    New-Item -ItemType Directory -Path (Join-Path $probeDir 'src') -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $probeDir 'Cargo.toml') -Encoding ASCII -Value @'
[package]
name = "dllprobe"
version = "0.1.0"
edition = "2021"
publish = false
'@
    Set-Content -LiteralPath (Join-Path $probeDir 'src\main.rs') -Encoding ASCII -Value @'
use std::ffi::c_void;
use std::ffi::OsString;
use std::os::windows::ffi::OsStrExt;

type HModule = *mut c_void;

#[link(name = "kernel32")]
extern "system" {
    fn LoadLibraryExW(file: *const u16, reserved: *const c_void, flags: u32) -> HModule;
    fn FreeLibrary(module: HModule) -> i32;
    fn GetLastError() -> u32;
}

const DONT_RESOLVE_DLL_REFERENCES: u32 = 0x1;
const LOAD_WITH_ALTERED_SEARCH_PATH: u32 = 0x8;

fn wide(text: &str) -> Vec<u16> {
    OsString::from(text)
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn gle_name(gle: u32) -> &'static str {
    match gle {
        5 => "ERROR_ACCESS_DENIED",
        126 => "ERROR_MOD_NOT_FOUND",
        127 => "ERROR_PROC_NOT_FOUND",
        1114 => "ERROR_DLL_INIT_FAILED",
        193 => "ERROR_BAD_EXE_FORMAT",
        998 => "ERROR_NOACCESS",
        14001 => "SXS_CANT_GEN_ACTCTX",
        _ => "",
    }
}

fn load_result(module: HModule) -> String {
    if module.is_null() {
        let gle = unsafe { GetLastError() };
        let name = gle_name(gle);
        if name.is_empty() {
            format!("FAIL gle={gle}")
        } else {
            format!("FAIL gle={gle} {name}")
        }
    } else {
        unsafe { FreeLibrary(module) };
        "OK".to_string()
    }
}

fn main() {
    for arg in std::env::args().skip(1) {
        let path = wide(&arg);
        let probe = unsafe {
            LoadLibraryExW(path.as_ptr(), std::ptr::null(), DONT_RESOLVE_DLL_REFERENCES)
        };
        let probe_res = load_result(probe);
        let full = unsafe {
            LoadLibraryExW(path.as_ptr(), std::ptr::null(), LOAD_WITH_ALTERED_SEARCH_PATH)
        };
        let full_res = load_result(full);
        println!("{arg:<44} probe={probe_res:<28} full={full_res}");
    }
}
'@
    Write-Host ""
    Write-Host "=== dllprobe: cargo build (in-guest, unsandboxed) ==="
    & cargo build --release --manifest-path (Join-Path $probeDir 'Cargo.toml') 2>&1 |
        ForEach-Object { Write-Host "  $_" }
    $dllprobeExe = Join-Path $probeDir 'target\release\dllprobe.exe'
    if (Test-Path -LiteralPath $dllprobeExe) {
        $pyExe = (Get-Command python).Source
        $pyDir = Split-Path -Parent $pyExe
        $pyDlls = Join-Path $pyDir 'DLLs'
        $pyMainDll = (Get-ChildItem -LiteralPath $pyDir -Filter 'python3*.dll' |
            Select-Object -First 1).FullName
        $sys = Join-Path $env:SystemRoot 'System32'
        $candidates = @(
            (Join-Path $pyDlls 'libffi-8.dll'),
            $pyMainDll,
            (Join-Path $pyDir 'vcruntime140.dll'),
            (Join-Path $sys 'ole32.dll'),
            (Join-Path $sys 'oleaut32.dll'),
            (Join-Path $sys 'combase.dll'),
            (Join-Path $sys 'user32.dll'),
            (Join-Path $sys 'gdi32.dll'),
            (Join-Path $sys 'rpcrt4.dll'),
            (Join-Path $sys 'sechost.dll'),
            (Join-Path $sys 'shell32.dll'),
            (Join-Path $sys 'shlwapi.dll'),
            (Join-Path $sys 'imm32.dll'),
            (Join-Path $sys 'authz.dll'),
            (Join-Path $sys 'wkscli.dll'),
            (Join-Path $sys 'netutils.dll'),
            (Join-Path $sys 'sspicli.dll'),
            (Join-Path $sys 'version.dll'),
            (Join-Path $sys 'msvcrt.dll'),
            (Join-Path $sys 'kernel32.dll'),
            (Join-Path $sys 'ws2_32.dll'),
            (Join-Path $sys 'advapi32.dll')
        ) | Where-Object { $_ -and (Test-Path -LiteralPath $_) }
        Write-Host ""
        Write-Host "=== dllprobe: unsandboxed control matrix ==="
        & $dllprobeExe @candidates 2>&1 | ForEach-Object { Write-Host "  $_" }
        Write-Host "--- exit: $LASTEXITCODE"
        Run-Step 'dllprobe matrix (sandboxed, inside the AC) - THE ANSWER' (@(
            'run','--allow-cwd','--',$dllprobeExe) + $candidates)
    } else {
        Write-Host '[s9dbg] dllprobe build FAILED - skipping matrix'
    }

    # ------------------------------------------------------------------
    # 6b. Window-station/desktop experiment. Baseline dump, AAP grant,
    #     flip tests (whoami / matrix / ctypes / full S-9 venv), then
    #     restore the original security descriptors.
    # ------------------------------------------------------------------
    Write-Host ""
    Write-Host "=== winsta/desktop: dump + AAP grant experiment ==="
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public static class WinSta {
    [DllImport("user32.dll", SetLastError = true)]
    public static extern IntPtr GetProcessWindowStation();
    [DllImport("user32.dll", SetLastError = true)]
    public static extern IntPtr GetThreadDesktop(uint dwThreadId);
    [DllImport("kernel32.dll")]
    public static extern uint GetCurrentThreadId();
    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool GetUserObjectInformation(IntPtr hObj, int nIndex, IntPtr pvInfo, uint nLength, out uint lpnLengthNeeded);
    [DllImport("user32.dll", SetLastError = true)]
    public static extern bool GetUserObjectSecurity(IntPtr hObj, ref uint pSecurityInformation, IntPtr pSecurityDescriptor, uint nLength, out uint lpnLengthNeeded);
    [DllImport("user32.dll", SetLastError = true)]
    public static extern bool SetUserObjectSecurity(IntPtr hObj, ref uint SecurityInformation, IntPtr pSecurityDescriptor);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool ConvertSecurityDescriptorToStringSecurityDescriptorW(IntPtr SecurityDescriptor, uint RequestedRevision, uint SecurityInformation, out IntPtr SecurityDescriptorString, out uint SecurityDescriptorStringLength);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(string StringSecurityDescriptor, uint StringSecurityDescriptorRevision, out IntPtr SecurityDescriptor, out uint SecurityDescriptorSize);
    [DllImport("kernel32.dll")]
    public static extern IntPtr LocalFree(IntPtr hMem);

    public const uint DACL_SI = 0x00000004;
    public const int UOI_NAME = 2;

    public static string GetName(IntPtr hObj) {
        uint needed;
        GetUserObjectInformation(hObj, UOI_NAME, IntPtr.Zero, 0, out needed);
        if (needed == 0) return "<none>";
        IntPtr buf = Marshal.AllocHGlobal((int)needed);
        string name = null;
        if (GetUserObjectInformation(hObj, UOI_NAME, buf, needed, out needed)) {
            name = Marshal.PtrToStringUni(buf);
        }
        Marshal.FreeHGlobal(buf);
        return name;
    }

    public static string GetSddl(IntPtr hObj) {
        uint si = DACL_SI;
        uint needed;
        GetUserObjectSecurity(hObj, ref si, IntPtr.Zero, 0, out needed);
        if (needed == 0) return "ERR zero length";
        IntPtr sd = Marshal.AllocHGlobal((int)needed);
        string sddl = null;
        try {
            if (!GetUserObjectSecurity(hObj, ref si, sd, needed, out needed)) {
                return "ERR " + Marshal.GetLastWin32Error();
            }
            IntPtr strPtr;
            uint strLen;
            if (ConvertSecurityDescriptorToStringSecurityDescriptorW(sd, 1, si, out strPtr, out strLen)) {
                sddl = Marshal.PtrToStringUni(strPtr);
                LocalFree(strPtr);
            } else {
                sddl = "ERR-conv " + Marshal.GetLastWin32Error();
            }
        } finally {
            Marshal.FreeHGlobal(sd);
        }
        return sddl;
    }

    public static string Grant(IntPtr hObj, string ace) {
        string s = GetSddl(hObj);
        if (s == null || s.StartsWith("ERR")) return "dump failed: " + s;
        int di = s.IndexOf("D:");
        if (di < 0) return "no DACL section in SDDL: " + s;
        int paren = s.IndexOf('(', di);
        string mod = paren < 0 ? s + "D:" + ace : s.Insert(paren, ace);
        return SetSddlRaw(hObj, mod);
    }

    public static string SetSddlRaw(IntPtr hObj, string sddl) {
        IntPtr sd;
        uint size;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, out sd, out size)) {
            return "convert failed: " + Marshal.GetLastWin32Error();
        }
        uint si = DACL_SI;
        bool ok = SetUserObjectSecurity(hObj, ref si, sd);
        int err = Marshal.GetLastWin32Error();
        LocalFree(sd);
        return ok ? "OK" : ("SetUserObjectSecurity failed gle=" + err);
    }
}
'@
    $wsHandle = [WinSta]::GetProcessWindowStation()
    $dtHandle = [WinSta]::GetThreadDesktop([WinSta]::GetCurrentThreadId())
    Write-Host ("  winsta : handle={0} name={1}" -f $wsHandle, [WinSta]::GetName($wsHandle))
    Write-Host ("  desktop: handle={0} name={1}" -f $dtHandle, [WinSta]::GetName($dtHandle))
    $wsSddl0 = [WinSta]::GetSddl($wsHandle)
    $dtSddl0 = [WinSta]::GetSddl($dtHandle)
    Write-Host "  winsta sddl (before): $wsSddl0"
    Write-Host "  desktop sddl (before): $dtSddl0"
    $aapAce = '(A;;GA;;;S-1-15-2-1)'
    Write-Host ("  grant winsta  AAP GA: " + [WinSta]::Grant($wsHandle, $aapAce))
    Write-Host ("  grant desktop AAP GA: " + [WinSta]::Grant($dtHandle, $aapAce))

    Run-Step 'whoami flip test (WITH winsta/desktop grant)' @(
        'run','--allow-cwd','--','whoami','/user','/groups')
    if ($dllprobeExe -and (Test-Path -LiteralPath $dllprobeExe)) {
        Run-Step 'dllprobe matrix (WITH winsta/desktop grant)' (@(
            'run','--allow-cwd','--',$dllprobeExe) + $candidates)
    }
    Run-Step 'ctypes import (WITH winsta/desktop grant)' @(
        'run','--allow-cwd','--','python','probe_ctypes.py')
    Run-Step 'venv WITH pip (full S-9 flow, WITH winsta/desktop grant)' @(
        'run','--allow-cwd','--','python','-m','venv','.dbgvenv4')
    $venv4Py = Join-Path $work '.dbgvenv4\Scripts\python.exe'
    if (Test-Path -LiteralPath $venv4Py) {
        Run-Step 'pip --version in venv4 (S-9 complete?)' @(
            'run','--allow-cwd','--',$venv4Py,'-m','pip','--version')
    }
    Write-Host "=== winsta/desktop: restoring original security descriptors ==="
    if ($wsSddl0 -and -not $wsSddl0.StartsWith('ERR')) {
        Write-Host ("  restore winsta : " + [WinSta]::SetSddlRaw($wsHandle, $wsSddl0))
    }
    if ($dtSddl0 -and -not $dtSddl0.StartsWith('ERR')) {
        Write-Host ("  restore desktop: " + [WinSta]::SetSddlRaw($dtHandle, $dtSddl0))
    }

    # ------------------------------------------------------------------
    # 7. pyshim presence dump (one line per session dir)
    # ------------------------------------------------------------------
    Write-Host ""
    Write-Host "=== pyshim dirs in battery sessions ==="
    $sandRoot = Join-Path $work '.sandbox'
    if (Test-Path -LiteralPath $sandRoot) {
        foreach ($sess in @(Get-ChildItem -LiteralPath $sandRoot -Directory -ErrorAction SilentlyContinue)) {
            $shim = Join-Path $sess.FullName 'pyshim\sitecustomize.py'
            $present = Test-Path -LiteralPath $shim
            Write-Host ("  {0}: sitecustomize.py present={1}" -f $sess.Name, $present)
        }
    }

    Write-Host ""
    Write-Host "=== whoami (pwsh session, for token reference) ==="
    & whoami.exe /user 2>&1 | ForEach-Object { Write-Host "  $_" }

    Write-Host ""
    Write-Host "[s9dbg] left in VM for further poking: $work"
}
Write-Host "[s9dbg] done."
