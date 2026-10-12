# confirm-s9-winsta.ps1
#
# Diagnostic for the S-9 in-VM failure, run entirely inside ONE PS-Direct
# session (grant and tests must share the same logon session - every
# session gets its own Service-0x0-*$ winsta):
#   1. dump winsta/desktop name + SDDL (before)
#   2. grant AAP GA (S-1-15-2-1) on winsta + desktop (same helper as the
#      round-5 battery, verified working)
#   3. run-tests.ps1 -Only 9 -Diag -Keep (harness output consumed & echoed
#      line-by-line so the scriptblock returns a clean exit code)
#   4. inspect the kept scenario dir: the .sandbox\<sid>\venv the harness
#      created (Scripts\python.exe present? seeded sitecustomize.py?
#      pyvenv.cfg?)
#   5. reproduce the failing r2 step manually with FULL combined output
#      (the harness Detail only records stdout - the error is on stderr):
#      a) cmd /c venv-python -c "print('venv works')"   (exact harness r2)
#      b) venv-python directly without cmd
#      c) base python in the AC (control)
#      d) venv-python UNSANDBOXED (control for venv validity)
#
# Rollback: none needed - the grant lives only in this logon session and
# evaporates with it; the VM itself is disposable (VM deletion is the
# rollback per AGENTS.md).
#
# All output (every stream, including the PS-Direct session's) is captured
# to a transcript log; default location opencode\vm-logs\, override with
# -LogPath. The log path is printed at the end.
#
# Usage (elevated host pwsh):
#   pwsh -NoProfile -File tests\vm\confirm-s9-winsta.ps1 -VmName sbx-test-20261012-210951-747

param(
    [Parameter(Mandatory)][string]$VmName,
    [string]$LogPath
)

$ErrorActionPreference = 'Stop'
$thisDir = $PSScriptRoot
if (-not $LogPath) {
    $logDir = Join-Path $thisDir '..\..\opencode\vm-logs'
    $LogPath = Join-Path $logDir ("confirm-s9-winsta-{0}.log" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
}
$logParent = Split-Path -Parent $LogPath
if (-not (Test-Path -LiteralPath $logParent)) {
    New-Item -ItemType Directory -Path $logParent -Force | Out-Null
}
Start-Transcript -Path $LogPath | Out-Null
$exitCode = 1
try {

$settingsFile = Join-Path $thisDir 'vm-settings.json'
if (-not (Test-Path -LiteralPath $settingsFile)) {
    throw "vm-settings.json not found: $settingsFile"
}
$settings = Get-Content -LiteralPath $settingsFile -Raw | ConvertFrom-Json
$guestCred = New-Object System.Management.Automation.PSCredential(
    ([string]$settings.guestUser),
    (ConvertTo-SecureString ([string]$settings.guestPassword) -AsPlainText -Force))

Write-Host "[winsta-confirm] connecting to VM $VmName ..."
$testExit = Invoke-Command -VMName $VmName -Credential $guestCred -ScriptBlock {
    $ErrorActionPreference = 'Continue'

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

    Write-Host ""
    Write-Host "=== winsta/desktop state (before grant) ==="
    $wsHandle = [WinSta]::GetProcessWindowStation()
    $dtHandle = [WinSta]::GetThreadDesktop([WinSta]::GetCurrentThreadId())
    Write-Host ("  winsta : name=" + [WinSta]::GetName($wsHandle))
    Write-Host ("  desktop: name=" + [WinSta]::GetName($dtHandle))
    Write-Host ("  winsta sddl (before): " + [WinSta]::GetSddl($wsHandle))
    Write-Host ("  desktop sddl (before): " + [WinSta]::GetSddl($dtHandle))

    Write-Host ""
    Write-Host "=== granting ALL APPLICATION PACKAGES GA on winsta + desktop ==="
    $aapAce = '(A;;GA;;;S-1-15-2-1)'
    Write-Host ("  grant winsta  AAP GA: " + [WinSta]::Grant($wsHandle, $aapAce))
    Write-Host ("  grant desktop AAP GA: " + [WinSta]::Grant($dtHandle, $aapAce))
    $wsSddl1 = [WinSta]::GetSddl($wsHandle)
    $dtSddl1 = [WinSta]::GetSddl($dtHandle)
    Write-Host ("  winsta sddl (after): $wsSddl1")
    Write-Host ("  desktop sddl (after): $dtSddl1")
    # SDDL normalizes S-1-15-2-1 to its well-known alias 'AC'
    # (ALL APPLICATION PACKAGES) - accept either form.
    $granted = (($wsSddl1 -match 'S-1-15-2-1') -or ($wsSddl1 -match ';;;AC\)')) -and
               (($dtSddl1 -match 'S-1-15-2-1') -or ($dtSddl1 -match ';;;AC\)'))
    Write-Host ("  AAP ACE present in both SDs: " + $granted)
    if (-not $granted) {
        Write-Host "  grant failed - aborting"
        return 999
    }

    Write-Host ""
    Write-Host "=== guest python info ==="
    Write-Host ("  Get-Command python: " + (Get-Command python -ErrorAction SilentlyContinue).Source)
    & python -V 2>&1 | ForEach-Object { Write-Host ("  python -V: " + $_) }

    $sbx = 'C:\sbx-repo\target\release\sandbox.exe'
    Write-Host ""
    Write-Host "=== run-tests.ps1 -Only 9 -Diag -Keep ==="
    & pwsh -NoProfile -ExecutionPolicy Bypass -Command "& 'C:\sbx-repo\tests\run-tests.ps1' -Only 9 -Diag -Keep" 2>&1 |
        ForEach-Object { Write-Host "  $_" }
    $rc = $LASTEXITCODE
    Write-Host "  harness exit: $rc"

    # ------------------------------------------------------------------
    # Inspect the kept scenario dir and reproduce r2 with full output.
    # ------------------------------------------------------------------
    $keep = Get-ChildItem $env:TEMP -Directory -Filter 'sandbox-test-*' |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
    Write-Host ""
    Write-Host "=== kept cwd: $($keep.FullName) ==="
    $s9 = Join-Path $keep.FullName 'S-9'
    $sandboxDir = Join-Path $s9 '.sandbox'
    if (-not (Test-Path -LiteralPath $sandboxDir)) {
        Write-Host "  no .sandbox dir under $s9 - nothing to inspect"
        return $rc
    }
    $sidDir = Get-ChildItem -LiteralPath $sandboxDir -Directory | Select-Object -First 1
    $sid = $sidDir.Name
    $venv = Join-Path $sidDir.FullName 'venv'
    $venvPy = Join-Path $venv 'Scripts\python.exe'
    Write-Host "  sid  : $sid"
    Write-Host "  venv : $venv"
    Write-Host "  venv python exists: $(Test-Path -LiteralPath $venvPy)"
    Write-Host "  venv-root sitecustomize.py: $(Test-Path -LiteralPath (Join-Path $venv 'sitecustomize.py'))"
    if (Test-Path -LiteralPath (Join-Path $venv 'pyvenv.cfg')) {
        Write-Host "  pyvenv.cfg:"
        Get-Content -LiteralPath (Join-Path $venv 'pyvenv.cfg') | ForEach-Object { Write-Host "    $_" }
    }
    Write-Host "  Scripts dir:"
    Get-ChildItem -LiteralPath (Join-Path $venv 'Scripts') -ErrorAction SilentlyContinue |
        ForEach-Object { Write-Host ("    " + $_.Name) }
    Write-Host "  Lib\site-packages:"
    Get-ChildItem -LiteralPath (Join-Path $venv 'Lib\site-packages') -ErrorAction SilentlyContinue |
        ForEach-Object { Write-Host ("    " + $_.Name) }

    if (-not (Test-Path -LiteralPath $venvPy)) { return $rc }

    # ------------------------------------------------------------------
    # cmd matrix W: isolate the V3 blocker (cmd cannot spawn the
    # Low-labeled AC-created venv exe; Medium-labeled copies pass).
    # Every test flips exactly ONE variable.
    #   W1 venv python --version via cmd            (known FAIL - reference)
    #   W2 python-Med.exe: copy of venv python in the SAME Scripts dir
    #      (same ACEs via inheritance, Medium label)  -> label theory
    #   W3 whoami-copy Medium via cmd (control, expect PASS)
    #      then set its label to Low and retry        -> label theory
    #   W4 raise venv python.exe label to Medium, retry (then restore)
    #   W5 grant Everyone RX on venv python.exe, retry (then remove)
    #      -> Everyone-ACE theory (vs AC-SID-only ACE set)
    #   W6 base python --version via cmd (control, expect PASS)
    # SANDBOX_DIAG=1 so each spawn prints the child token's integrity
    # and AppContainer SIDs (tokdiag) for comparison with the file ACEs.
    # ------------------------------------------------------------------
    Set-Location -LiteralPath $s9
    $basePy = (Get-Command python).Source
    $env:SANDBOX_DIAG = '1'

    Write-Host ""
    Write-Host "=== ACEs of venv python.exe (before matrix) ==="
    & icacls $venvPy 2>&1 | ForEach-Object { Write-Host ("  " + $_) }

    $tests = @(
        @{ N = 'W1 cmd /c venv python (reference, expect FAIL)'; A = @('run','--allow-cwd','--sid',$sid,'--','cmd','/c',$venvPy,'--version') },
        @{ N = 'W2 cmd /c venv Scripts\python-Med.exe (Medium copy, same dir)'; A = @('run','--allow-cwd','--sid',$sid,'--','cmd','/c',(Join-Path $venv 'Scripts\python-Med.exe'),'--version') }
    )
    Copy-Item $venvPy (Join-Path $venv 'Scripts\python-Med.exe') -Force
    $whoamiCopy = Join-Path $s9 'whoami-copy.exe'
    Copy-Item C:\Windows\System32\whoami.exe $whoamiCopy -Force

    foreach ($t in $tests) {
        Write-Host ""
        Write-Host ("=== " + $t.N + " ===")
        & $sbx @($t.A) 2>&1 | ForEach-Object { Write-Host "  $_" }
        Write-Host ("  exit: " + $LASTEXITCODE)
    }

    Write-Host ""
    Write-Host "=== W3a cmd /c .\whoami-copy.exe (Medium, expect PASS) ==="
    & $sbx run --allow-cwd --sid $sid -- cmd /c ".\whoami-copy.exe" /user 2>&1 |
        ForEach-Object { Write-Host "  $_" }
    Write-Host ("  exit: " + $LASTEXITCODE)
    Write-Host "  (setting whoami-copy label to Low)"
    & icacls $whoamiCopy /setintegritylevel L 2>&1 | ForEach-Object { Write-Host ("  " + $_) }
    Write-Host "=== W3b cmd /c .\whoami-copy.exe (label Low, expect FAIL if label theory) ==="
    & $sbx run --allow-cwd --sid $sid -- cmd /c ".\whoami-copy.exe" /user 2>&1 |
        ForEach-Object { Write-Host "  $_" }
    Write-Host ("  exit: " + $LASTEXITCODE)

    Write-Host ""
    Write-Host "=== W4 raising venv python.exe label to Medium ==="
    & icacls $venvPy /setintegritylevel M 2>&1 | ForEach-Object { Write-Host ("  " + $_) }
    Write-Host "=== W4 cmd /c venv python (label Medium now) ==="
    & $sbx run --allow-cwd --sid $sid -- cmd /c $venvPy --version 2>&1 |
        ForEach-Object { Write-Host "  $_" }
    Write-Host ("  exit: " + $LASTEXITCODE)
    Write-Host "  (restoring label to Low)"
    & icacls $venvPy /setintegritylevel L 2>&1 | ForEach-Object { Write-Host ("  " + $_) }

    Write-Host ""
    Write-Host "=== W5 granting Everyone RX on venv python.exe ==="
    & icacls $venvPy /grant *S-1-1-0:(RX) 2>&1 | ForEach-Object { Write-Host ("  " + $_) }
    Write-Host "=== W5 cmd /c venv python (Everyone RX added) ==="
    & $sbx run --allow-cwd --sid $sid -- cmd /c $venvPy --version 2>&1 |
        ForEach-Object { Write-Host "  $_" }
    Write-Host ("  exit: " + $LASTEXITCODE)
    Write-Host "  (removing Everyone grant)"
    & icacls $venvPy /remove *S-1-1-0 2>&1 | ForEach-Object { Write-Host ("  " + $_) }

    Write-Host ""
    Write-Host "=== W6 control: cmd /c base python (expect PASS) ==="
    & $sbx run --allow-cwd --sid $sid -- cmd /c $basePy --version 2>&1 |
        ForEach-Object { Write-Host "  $_" }
    Write-Host ("  exit: " + $LASTEXITCODE)

    Remove-Item Env:SANDBOX_DIAG -ErrorAction SilentlyContinue

    Write-Host ""
    Write-Host "=== CodeIntegrity events during matrix (block decisions?) ==="
    try {
        Get-WinEvent -LogName 'Microsoft-Windows-CodeIntegrity/Operational' -MaxEvents 10 -ErrorAction Stop |
            ForEach-Object { Write-Host ("    [{0}] {1}: {2}" -f $_.TimeCreated.ToString('HH:mm:ss'), $_.Id, ($_.Message -split "`n")[0]) }
    } catch { Write-Host ("    (no events: " + $_.Exception.Message + ")") }

    Set-Location -LiteralPath $env:TEMP
    return $rc
}

Write-Host ""
Write-Host "[winsta-confirm] remote session exit: $testExit"
if ($testExit -eq 0) {
    Write-Host "[winsta-confirm] CONFIRMED: S-9 passes in-VM with the winsta AAP grant ->"
    Write-Host "[winsta-confirm]   the PS-Direct service-winsta was the only remaining blocker."
    $exitCode = 0
} elseif ($testExit -eq 999) {
    Write-Host "[winsta-confirm] grant itself failed - see SDDL dumps above."
    $exitCode = 2
} else {
    Write-Host "[winsta-confirm] S-9 still fails WITH the winsta grant; see repro output above."
    $exitCode = 1
}

} finally {
    Stop-Transcript | Out-Null
    Write-Host "[winsta-confirm] log: $LogPath"
}
exit $exitCode
