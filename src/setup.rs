use anyhow::{Result, bail};
use windows::Win32::Foundation::*;
use windows::Win32::Security::Authorization::*;
use windows::Win32::Security::*;
use windows::Win32::Storage::FileSystem::{
    GetLogicalDriveStringsW, GetDriveTypeW, FILE_READ_ATTRIBUTES,
};
use windows::Win32::System::Registry::{
    HKEY_LOCAL_MACHINE, KEY_READ, RegCloseKey, RegOpenKeyExW, RegQueryValueExW, REG_DWORD, HKEY,
};
use windows::core::{w, HSTRING, PCWSTR, PWSTR};

/// Minimum supported build: Windows 10 1709 (build 16299) per FR-6.2.
pub const MIN_BUILD: u32 = 16299;

/// S-1-15-2-2 — "All RESTRICTED APPLICATION PACKAGES". Granting this SID on a
/// resource lets every AppContainer process (not just our per-session SID)
/// access it. We use it for the one-time drive-root grant because:
///   (a) per-session SIDs would require re-granting on every `sandbox run`,
///       and the drive root is TrustedInstaller-owned so each grant needs
///       elevation anyway; and
///   (b) FILE_READ_ATTRIBUTES on a drive root is a read-only, low-sensitivity
///       access (volume label + serial) that every unsandboxed user already has.
const ALL_RESTRICTED_APP_PACKAGES_RIDS: [u32; 2] = [2, 2]; // S-1-15-2-2

/// DRIVE_FIXED from Win32 (defined here to avoid pulling the full
/// FileSystem::DRIVE_* constants which are behind an extra feature gate in
/// this windows-rs version). The value is stable per the Win32 API.
const DRIVE_FIXED: u32 = 3;

/// Called from `run` before any spawning — fails fast with a clear error if
/// the host is unsupported (AC-1.9).
pub fn check_runtime() -> Result<()> {
    let build = os_build_number()?;
    if build < MIN_BUILD {
        bail!(
            "AppContainer RuleSet requires Windows 10 1709 (build {MIN_BUILD}) or later. \
             Detected build {build}."
        );
    }
    Ok(())
}

/// Called from `setup`: reports the feature matrix (`--check-only`) and/or
/// applies the one-time drive-root grant (`--grant-drive-root`).
pub fn check(check_only: bool, grant_drive_root: bool, enable_loopback: bool) -> Result<()> {
    if grant_drive_root {
        grant_drive_roots()?;
        // After granting, fall through to the report so the user sees the
        // resulting state.
    } else if enable_loopback {
        // Diagnostic: list the current loopback exempt list. The actual
        // per-session SID does not exist yet (it is created at `sandbox run`
        // time), so we cannot pre-register it here. Runtime registration is
        // performed in `main.rs` after the AppContainer session is created;
        // it succeeds only when elevated and degrades to block-net otherwise.
        println!("[loopback] current LoopbackExempt list (CheckNetIsolation):");
        let out = std::process::Command::new("CheckNetIsolation")
            .args(["LoopbackExempt", "-s"])
            .output();
        match out {
            Ok(o) => {
                let stdout = String::from_utf8_lossy(&o.stdout);
                let stderr = String::from_utf8_lossy(&o.stderr);
                if !stdout.trim().is_empty() {
                    print!("{stdout}");
                }
                if !stderr.trim().is_empty() {
                    eprint!("{stderr}");
                }
            }
            Err(e) => {
                eprintln!("[loopback] CheckNetIsolation not available: {e}");
            }
        }
        println!("[loopback] loopback is registered automatically at runtime when");
        println!("[loopback] `sandbox run` is invoked elevated. Unprivileged users");
        println!("[loopback] need to either run elevated or use --block-net.");
        // Fall through to the report.
    } else if !check_only {
        eprintln!("[sandbox] `setup` without --check-only, --grant-drive-root, or --enable-loopback is not implemented in this slice.");
    }

    let build = os_build_number()?;
    println!("Windows build number      : {build}");
    println!("Minimum supported build   : {MIN_BUILD} (Windows 10 1709)");
    println!(
        "AppContainer + RuleSet     : {}",
        if build >= MIN_BUILD { "available" } else { "MISSING" }
    );
    println!("Job Object                 : available (always, Win9x+)");
    for line in network_report_lines(build) { println!("{line}"); }
    println!("Drive-root grant (KI-1.1)  : {}", drive_root_status());
    println!(
        "Audit (hash-chain + Ed25519): {}",
        if crate::signing::key_exists() {
            "available (signing key present)"
        } else {
            "available (signing key generated on first run)"
        }
    );

    if build < MIN_BUILD {
        bail!("host build {build} is below minimum {MIN_BUILD} (AppContainer RuleSet unavailable)");
    }
    Ok(())
}

/// Network-posture report lines (setup --check-only). Extracted so the
/// documented limitations are unit-testable. The `privateNetworkClientServer`
/// capability (S-1-15-3-7) is BIDIRECTIONAL: it grants egress to loopback +
/// intranet AND lets a listening sandboxed process accept connections from
/// LAN peers. MXC rejects ingress-allow policies on its AppContainer tier for
/// exactly this reason (appcontainer_runner.rs:1747). See ADR-0001 D-0,
/// docs/research/mxc-source-analysis.md F-A.
fn network_report_lines(build: u32) -> Vec<String> {
    vec![
        format!(
            "Network (loopback+intranet) : {}",
            if build >= MIN_BUILD {
                "available via privateNetworkClientServer capability"
            } else {
                "MISSING (requires Windows 10 1709+)"
            }
        ),
        "  NOTE                     : loopback firewall exemption required (admin). Run elevated for --allow-domain.".to_string(),
        "  WARNING (intranet leak)  : raw-socket apps can reach LAN hosts without proxy filtering.".to_string(),
        "  WARNING (inbound surface) : capability is bidirectional - a listening sandboxed process can accept connections from LAN peers.".to_string(),
        "    Strong isolation       : use --block-net (zero network capability SIDs, all connect() denied)".to_string(),
    ]
}

/// One-time admin step: grant S-1-15-2-2 (All RESTRICTED APPLICATION PACKAGES)
/// `FILE_READ_ATTRIBUTES` on every fixed drive root, fixing KI-1.1.
///
/// Why FILE_READ_ATTRIBUTES (not RX): `cmd /c dir` calls
/// `GetVolumeInformationW("C:\\")` which needs only `FILE_READ_ATTRIBUTES`
/// (0x80) on the root directory to read the volume label + serial. We grant
/// the narrowest mask that satisfies the call — not LIST_DIRECTORY, so the
/// AppContainer cannot enumerate the drive root's contents.
///
/// Idempotent: re-running leaves the ACE in place (the SetAccess merge keeps
/// a single entry per trustee). Requires WRITE_DAC on the drive root, which
/// normal users lack — the caller must be elevated.
fn grant_drive_roots() -> Result<()> {
    if !is_elevated() {
        bail!(
            "`setup --grant-drive-root` requires elevation. Re-run from an \
             Administrator shell (the drive root is TrustedInstaller-owned and \
             WRITE_DAC on it needs SeSecurityPrivilege)."
        );
    }

    let sid = all_restricted_app_packages_sid()?;

    for root in fixed_drive_roots()? {
        match grant_read_attributes(&root, sid) {
            Ok(()) => {
                println!("[grant-drive-root] {root} granted S-1-15-2-2 :FILE_READ_ATTRIBUTES (or already present)");
            }
            Err(e) => {
                eprintln!("[grant-drive-root] WARN: {root} failed: {e}");
            }
        }
    }
    // Free the SID we allocated.
    unsafe {
        let _ = windows::Win32::Security::FreeSid(sid);
    }
    Ok(())
}

/// Build the S-1-15-2-2 SID (All RESTRICTED APPLICATION PACKAGES).
fn all_restricted_app_packages_sid() -> Result<PSID> {
    // authority 15 (security manager / app packages), 2 sub-authorities: [2, 2].
    let authority = windows::Win32::Security::SID_IDENTIFIER_AUTHORITY {
        Value: [0, 0, 0, 0, 0, 15],
    };
    let mut buf = vec![0u8; SECURITY_MAX_SID_SIZE as usize];
    let mut sid = PSID(buf.as_mut_ptr() as *mut _);
    unsafe {
        AllocateAndInitializeSid(
            &authority,
            ALL_RESTRICTED_APP_PACKAGES_RIDS.len() as u8,
            ALL_RESTRICTED_APP_PACKAGES_RIDS[0],
            ALL_RESTRICTED_APP_PACKAGES_RIDS[1],
            0,
            0,
            0,
            0,
            0,
            0,
            &mut sid,
        )?;
        let len = windows::Win32::Security::GetLengthSid(sid) as usize;
        let mut owned: Vec<u8> = vec![0u8; len];
        let _ = windows::Win32::Security::CopySid(
            len as u32,
            PSID(owned.as_mut_ptr() as *mut _),
            sid,
        );
        let _ = windows::Win32::Security::FreeSid(sid);
        Ok(PSID(owned.leak().as_mut_ptr() as *mut _))
    }
}

/// Grant `FILE_READ_ATTRIBUTES` to `sid` on `root` (a drive root like "C:\").
///
/// The grant is idempotent in effect: `SetEntriesInAclW` with `SET_ACCESS`
/// produces a single ACE per trustee, so re-running leaves a single entry.
/// We do not pre-check for an existing ACE — the merge is cheap and the
/// check would require walking the ACL (locale-dependent trustee names).
fn grant_read_attributes(root: &str, sid: PSID) -> Result<()> {
    let path_w = HSTRING::from(root);

    // Read the existing DACL so we can merge rather than replace.
    let mut sd: PSECURITY_DESCRIPTOR = PSECURITY_DESCRIPTOR::default();
    let mut existing_dacl: *mut ACL = std::ptr::null_mut();
    let r = unsafe {
        GetNamedSecurityInfoW(
            &path_w,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(&mut existing_dacl),
            None,
            &mut sd,
        )
    };
    if r.0 != ERROR_SUCCESS.0 {
        bail!("GetNamedSecurityInfoW({root}) failed: 0x{:x}", r.0);
    }

    // Build the new ACE: Allow, FILE_READ_ATTRIBUTES, no inheritance (the ACE
    // applies to the root dir itself only — we deliberately do NOT propagate
    // to children, which would grant read-attrs on every file on the volume).
    let mut ea = EXPLICIT_ACCESS_W::default();
    unsafe {
        BuildExplicitAccessWithNameW(
            &mut ea,
            PCWSTR::null(), // unused when TrusteeForm = TRUSTEE_IS_SID
            FILE_READ_ATTRIBUTES.0,
            SET_ACCESS,
            SUB_CONTAINERS_AND_OBJECTS_INHERIT,
        );
    }
    ea.Trustee = TRUSTEE_W {
        TrusteeForm: TRUSTEE_IS_SID,
        TrusteeType: TRUSTEE_IS_GROUP,
        ptstrName: PWSTR(sid.0 as *mut _),
        ..Default::default()
    };

    let mut new_acl: *mut ACL = std::ptr::null_mut();
    let old_acl_opt = if existing_dacl.is_null() {
        None
    } else {
        Some(existing_dacl as *const ACL)
    };
    let set_r = unsafe { SetEntriesInAclW(Some(&[ea]), old_acl_opt, &mut new_acl) };
    unsafe {
        let _ = LocalFree(Some(HLOCAL(sd.0 as *mut _)));
    }
    if set_r.0 != ERROR_SUCCESS.0 {
        bail!("SetEntriesInAclW failed: 0x{:x}", set_r.0);
    }

    // PROTECTED_DACL_SECURITY_INFORMATION would drop inherited ACEs; we want
    // to MERGE, so use UNPROTECTED (preserve inheritance).
    let write_r = unsafe {
        SetNamedSecurityInfoW(
            &path_w,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(new_acl),
            None,
        )
    };
    unsafe {
        let _ = LocalFree(Some(HLOCAL(new_acl as *mut _)));
    }
    if write_r.0 != ERROR_SUCCESS.0 {
        bail!("SetNamedSecurityInfoW({root}) failed: 0x{:x}", write_r.0);
    }
    Ok(())
}

/// Enumerate fixed (hard) drive roots via GetLogicalDriveStringsW + GetDriveTypeW.
fn fixed_drive_roots() -> Result<Vec<String>> {
    let mut buf = [0u16; 512];
    let n = unsafe { GetLogicalDriveStringsW(Some(&mut buf)) };
    if n == 0 {
        return Ok(Vec::new());
    }
    let s = String::from_utf16_lossy(&buf[..n as usize]);
    let mut roots = Vec::new();
    for entry in s.split('\0') {
        if entry.is_empty() {
            continue;
        }
        // Only fixed drives (DRIVE_FIXED). Skip removable, network, etc.
        let w = HSTRING::from(entry);
        let dt = unsafe { GetDriveTypeW(&w) };
        if dt == DRIVE_FIXED {
            roots.push(entry.to_string());
        }
    }
    Ok(roots)
}

/// Is the current process elevated (running with the admin token)?
///
/// `pub(crate)` since P2.3: the session-start leaf records it as `elevated`, and
/// the check must be the same one `setup` gates the drive-root grant on.
pub(crate) fn is_elevated() -> bool {
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    // TOKEN_ELEVATION, TOKEN_QUERY, GetTokenInformation, TokenElevation, and
    // TOKEN_INFORMATION_CLASS all live in Win32::Security in this windows-rs
    // version.
    use windows::Win32::Security::{TOKEN_ELEVATION, TOKEN_QUERY, GetTokenInformation, TokenElevation};
    unsafe {
        let mut token = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return false;
        }
        let mut elevation = TOKEN_ELEVATION::default();
        let mut ret = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut _),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut ret,
        );
        let _ = CloseHandle(token);
        ok.is_ok() && elevation.TokenIsElevated != 0
    }
}

/// Human-readable status of the drive-root grant on the system drive, for the
/// `setup` report. We probe via a fresh read of the DACL's SDDL form.
fn drive_root_status() -> String {
    let system_drive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".to_string());
    let root = format!("{system_drive}\\");
    match check_root_has_grant(&root) {
        Ok(true) => format!("present on {root}"),
        Ok(false) => format!("absent on {root} (run `sandbox setup --grant-drive-root`)"),
        Err(e) => format!("unknown ({e})"),
    }
}

fn check_root_has_grant(root: &str) -> Result<bool> {
    let path_w = HSTRING::from(root);
    let mut sd: PSECURITY_DESCRIPTOR = PSECURITY_DESCRIPTOR::default();
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let r = unsafe {
        GetNamedSecurityInfoW(
            &path_w,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(&mut dacl),
            None,
            &mut sd,
        )
    };
    if r.0 != ERROR_SUCCESS.0 {
        bail!("GetNamedSecurityInfoW({root}) failed: 0x{:x}", r.0);
    }
    // Serialize the security descriptor to SDDL and substring-match the SID.
    // SDDL always emits raw SID strings (e.g. "S-1-15-2-2") regardless of the
    // current locale's display-name rendering.
    let mut sddl_pwsz = PWSTR::null();
    let conv = unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            sd,
            1u32, // SDDL_REVISION_1
            OBJECT_SECURITY_INFORMATION(DACL_SECURITY_INFORMATION.0),
            &mut sddl_pwsz,
            None,
        )
    };
    let found = if conv.is_ok() {
        let sddl = unsafe { sddl_pwsz.to_string().unwrap_or_default() };
        // The SID we granted is S-1-15-2-2.
        sddl.contains("S-1-15-2-2")
    } else {
        false
    };
    if !sddl_pwsz.is_null() {
        unsafe {
            let _ = LocalFree(Some(HLOCAL(sddl_pwsz.0 as *mut _)));
        }
    }
    unsafe {
        let _ = LocalFree(Some(HLOCAL(sd.0 as *mut _)));
    }
    Ok(found)
}

/// Read the OS build number from the registry
/// (`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\CurrentBuild`).
///
/// We use the registry instead of `GetVersionExW` because `GetVersionExW` is
/// subject to manifest-based version lying: an unmanifested binary on
/// Windows 10/11 reports build 9200 (Windows 8) — the manifest-compatible
/// floor. The registry value is not affected by the app manifest and reports
/// the true build. (See PRD AC-1.9.)
fn os_build_number() -> Result<u32> {
    let subkey = w!("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion");
    let value = w!("CurrentBuild");

    unsafe {
        let mut hkey = HKEY::default();
        let status = RegOpenKeyExW(HKEY_LOCAL_MACHINE, subkey, Some(0), KEY_READ, &mut hkey);
        if status.is_err() {
            return Err(anyhow::anyhow!("RegOpenKeyExW failed: 0x{:x}", status.0));
        }

        let mut buf = [0u8; 64];
        let mut len = buf.len() as u32;
        let mut kind = REG_DWORD; // will be overwritten; type hint only.
        let r = RegQueryValueExW(
            hkey,
            value,
            None,
            Some(&mut kind),
            Some(buf.as_mut_ptr()),
            Some(&mut len),
        );
        let _ = RegCloseKey(hkey);
        if r.is_err() {
            return Err(anyhow::anyhow!("RegQueryValueExW failed: 0x{:x}", r.0));
        }

        let utf16: Vec<u16> = buf[..len as usize]
            .as_chunks::<2>().0
            .iter()
            .map(|c| u16::from_le_bytes(*c))
            .collect();
        let s = String::from_utf16_lossy(&utf16)
            .trim_end_matches('\0')
            .to_string();
        let build: u32 = s
            .trim()
            .parse()
            .map_err(|_| anyhow::anyhow!("could not parse CurrentBuild `{s}` as u32"))?;
        Ok(build)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_report_documents_bidirectional_leak() {
        let lines = network_report_lines(26100);
        let joined = lines.join("\n");
        assert!(joined.contains("intranet leak"), "egress leak documented: {joined}");
        assert!(joined.contains("inbound"), "inbound surface documented: {joined}");
        assert!(joined.contains("bidirectional"), "capability semantics documented: {joined}");
    }

    #[test]
    fn network_report_handles_unsupported_build() {
        let lines = network_report_lines(16298);
        assert!(lines.iter().any(|l| l.contains("MISSING")));
    }
}
