use windows::Win32::Foundation::*;
use windows::Win32::Security::Authorization::*;
use windows::Win32::Security::Isolation::*;
use windows::Win32::Security::*;
use windows::Win32::System::SystemServices::*;
use windows::Win32::System::Threading::*;
use windows::core::*;

use crate::allowlist;

pub struct AppContainerSession {
    #[allow(dead_code)]
    pub sid: String,
    pub ac_sid: PSID,
    #[allow(dead_code)]
    pub ac_name: String,
}

/// Create (or re-derive) the AppContainer profile for `sid` and return
/// the AppContainer SID plus a process token.
///
/// # Approach: AppContainer SID + per-directory DACLs
///
/// We use `CreateAppContainerProfile` to mint a per-session AppContainer SID,
/// then call `CreateProcessW` with `PROC_THREAD_ATTRIBUTE_APPCONTAINER_SID`,
/// which makes the kernel build the child's token with the AppContainer SID
/// as a restricting identity. By default an AppContainer process is
/// **deny-by-default**: every securable object it touches must carry an
/// explicit Allow ACE naming the AppContainer SID.
///
/// Rather than driving the formal RuleSet/capability-SID `NtCreateFile`
/// machinery (which windows-rs exposes only awkwardly and which is intended
/// for UWP capability brokering), we grant access the direct way: for each
/// allow-listed directory we set a DACL containing an Allow ACE for the
/// AppContainer SID with the requested mask (Read/Write/Execute). This is
/// what `icacls /grant` does and what Add-AppxPackage-style setup does. The
/// AppContainer SID is still a restricting identity, so anything without an
/// ACE is denied.
pub fn create_session(sid: &str) -> Result<AppContainerSession> {
    let ac_name = format!("spike.{}.ac", sid);
    let ac_name_w = HSTRING::from(&ac_name);

    let ac_sid = unsafe {
        match CreateAppContainerProfile(&ac_name_w, w!("spike"), w!("spike sandbox session"), None)
        {
            Ok(s) => s,
            // Profile already exists for this name — re-derive the SID.
            // Both codes have been observed in the wild across windows-rs
            // versions: ERROR_ALREADY_EXISTS (0x800700B7) and the AppContainer
            // specific 0x80071392.
            Err(e) if e.code() == HRESULT::from_win32(0x800700B7)
                || e.code() == HRESULT::from_win32(0x80071392) =>
            {
                if std::env::var_os("SPIKE_DIAG").is_some() {
                    eprintln!("[appcontainer] profile existed, re-deriving SID");
                }
                DeriveAppContainerSidFromAppContainerName(&ac_name_w)?
            }
            Err(e) => {
                eprintln!("[spike:diag] CreateAppContainerProfile failed: {e}");
                return Err(e);
            }
        }
    };

    // When using PROC_THREAD_ATTRIBUTE_APPCONTAINER_SID with CreateProcessW,
    // the kernel builds the AppContainer token from the SID automatically —
    // no separate token handle is needed.

    Ok(AppContainerSession {
        sid: sid.to_string(),
        ac_sid,
        ac_name,
    })
}

/// Grant the AppContainer SID the requested access on `entries` by writing
/// an explicit DACL onto each directory.
pub fn grant_access(ac_sid: &PSID, entries: &[allowlist::AllowEntry]) -> Result<()> {
    let diag = std::env::var_os("SPIKE_DIAG").is_some();
    for e in entries {
        if let Err(err) = grant_one(ac_sid, e) {
            if diag {
                eprintln!(
                    "[grant] WARN: {:>16} {:?} failed: {err}",
                    if e.deny { format!("{} [deny]", e.label) } else { e.label.to_string() },
                    e.win32_path
                );
            }
        } else if diag {
            eprintln!(
                "[grant] {:>16}  {:?}  mask=0x{:x}{}{}",
                if e.deny { format!("{} [deny]", e.label) } else { e.label.to_string() },
                e.win32_path,
                e.access,
                if e.deny { " DENY" } else { "" },
                if e.protected { " PROTECTED" } else { "" }
            );
        }
    }
    Ok(())
}

fn grant_one(ac_sid: &PSID, e: &allowlist::AllowEntry) -> Result<()> {
    // Use the plain string form (no \\?\ prefix) for the Win32 path APIs.
    let path_str = e.win32_path.to_string_lossy().to_string();
    let path_w = HSTRING::from(&path_str);
    unsafe {
        // Read the existing SD so we can merge our ACE into the current DACL
        // (preserving access for the current user, SYSTEM, Administrators).
        let mut sd = PSECURITY_DESCRIPTOR::default();
        let mut dacl_ptr: *mut ACL = std::ptr::null_mut();
        let r = GetNamedSecurityInfoW(
            &path_w,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(&mut dacl_ptr),
            None,
            &mut sd,
        );
        if r.is_err() {
            return Err(HRESULT::from_win32(r.0).into());
        }

        // Build the new ACE for the AppContainer SID.
        let mut ea = EXPLICIT_ACCESS_W::default();
        ea.grfAccessPermissions = e.access;
        ea.grfAccessMode = if e.deny { DENY_ACCESS } else { SET_ACCESS };
        ea.grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
        ea.Trustee = TRUSTEE_W {
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_GROUP,
            ptstrName: PWSTR(ac_sid.0 as *mut _),
            ..Default::default()
        };

        let mut new_acl: *mut ACL = std::ptr::null_mut();
        // When NOT protected, merge our single ACE onto the existing DACL
        // (preserving inherited + explicit access for user/SYSTEM/Admins).
        // When protected, build a fresh DACL from scratch containing the
        // owner Full-Control ACEs + our AppContainer ACE (no inheritance).
        let set_r = if e.protected {
            let mut all_entries: Vec<EXPLICIT_ACCESS_W> = Vec::new();
            for trustee in owner_trustees() {
                let mut owner_ea = EXPLICIT_ACCESS_W::default();
                owner_ea.grfAccessPermissions = 0x1f01ff; // FILE_ALL_ACCESS
                owner_ea.grfAccessMode = SET_ACCESS;
                owner_ea.grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
                owner_ea.Trustee = trustee;
                all_entries.push(owner_ea);
            }
            all_entries.push(ea);
            SetEntriesInAclW(Some(&all_entries), None, &mut new_acl)
        } else {
            let old_acl_opt = if dacl_ptr.is_null() {
                None
            } else {
                Some(dacl_ptr as *const ACL)
            };
            SetEntriesInAclW(Some(&[ea]), old_acl_opt, &mut new_acl)
        };
        let _ = LocalFree(Some(HLOCAL(sd.0 as *mut _)));
        if set_r.is_err() {
            return Err(HRESULT::from_win32(set_r.0).into());
        }

        // Write the merged DACL. PROTECTED blocks inheritance from the
        // parent (so the $CWD Allow does not reach the per-session subtree);
        // UNPROTECTED keeps inherited ACEs (for the project tree itself).
        let flags = if e.protected {
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION
        } else {
            DACL_SECURITY_INFORMATION | UNPROTECTED_DACL_SECURITY_INFORMATION
        };
        let write_r = SetNamedSecurityInfoW(
            &path_w,
            SE_FILE_OBJECT,
            flags,
            None,
            None,
            Some(new_acl),
            None,
        );
        let _ = LocalFree(Some(HLOCAL(new_acl as *mut _)));
        if write_r.is_err() {
            return Err(HRESULT::from_win32(write_r.0).into());
        }
    }
    Ok(())
}

/// Return TRUSTEE_W entries for the current process user, SYSTEM, and the
/// Administrators alias, so a PROTECTED_DACL can grant them Full Control
/// explicitly (since PROTECTED drops the inherited ACEs that normally
/// grant the owner access). Used for the per-session subtree, which is
/// PROTECTED to block the broad `$CWD` Allow from leaking in.
fn owner_trustees() -> Vec<TRUSTEE_W> {
    let mut trustees = Vec::new();

    // Current process user SID.
    if let Some(user_sid) = current_user_sid() {
        trustees.push(TRUSTEE_W {
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_USER,
            ptstrName: PWSTR(user_sid.0 as *mut _),
            ..Default::default()
        });
    }

    // SYSTEM (S-1-5-18).
    if let Some(system_sid) = well_known_sid(18) {
        trustees.push(TRUSTEE_W {
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_USER,
            ptstrName: PWSTR(system_sid.0 as *mut _),
            ..Default::default()
        });
    }

    // Administrators alias (S-1-5-32-544).
    if let Some(admins_sid) = builtin_admins_sid() {
        trustees.push(TRUSTEE_W {
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_GROUP,
            ptstrName: PWSTR(admins_sid.0 as *mut _),
            ..Default::default()
        });
    }

    trustees
}

/// Get the current process user SID by querying our own token.
fn current_user_sid() -> Option<PSID> {
    unsafe {
        let mut token = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return None;
        }
        let mut needed = 0u32;
        let _ = GetTokenInformation(
            token,
            TokenUser,
            None,
            0,
            &mut needed,
        );
        if needed == 0 {
            let _ = CloseHandle(token);
            return None;
        }
        let mut buf = vec![0u8; needed as usize];
        let ok = GetTokenInformation(
            token,
            TokenUser,
            Some(buf.as_mut_ptr() as *mut _),
            needed,
            &mut needed,
        );
        let _ = CloseHandle(token);
        if ok.is_err() {
            return None;
        }
        let tu = &*(buf.as_ptr() as *const TOKEN_USER);
        // Copy the SID into a stable, owned buffer (the token info buffer is
        // dropped when buf goes out of scope at the end of this fn).
        let src_sid = tu.User.Sid;
        let len = GetLengthSid(src_sid) as usize;
        let mut owned: Vec<u8> = vec![0u8; len];
        let _ = CopySid(len as u32, PSID(owned.as_mut_ptr() as *mut _), src_sid);
        Some(PSID(owned.leak().as_mut_ptr() as *mut _))
    }
}

/// Create a well-known SID by RID (e.g. 18 = SYSTEM, S-1-5-18).
fn well_known_sid(rid: u32) -> Option<PSID> {
    let mut size = SECURITY_MAX_SID_SIZE;
    let mut buf = vec![0u8; size as usize];
    let mut sid = PSID(buf.as_mut_ptr() as *mut _);
    let authority = SID_IDENTIFIER_AUTHORITY { Value: [0, 0, 0, 0, 0, 5] }; // NT_AUTHORITY
    unsafe {
        if AllocateAndInitializeSid(&authority, 1, rid, 0, 0, 0, 0, 0, 0, 0, &mut sid).is_ok() {
            // Hand the SID a stable backing by copying into a boxed slice.
            let len = GetLengthSid(sid) as usize;
            let mut owned: Vec<u8> = vec![0u8; len];
            let _ = CopySid(len as u32, PSID(owned.as_mut_ptr() as *mut _), sid);
            let _ = FreeSid(sid);
            Some(PSID(owned.leak().as_mut_ptr() as *mut _))
        } else {
            None
        }
    }
}

/// Create the BUILTIN\Administrators alias SID (S-1-5-32-544).
fn builtin_admins_sid() -> Option<PSID> {
    let mut size = SECURITY_MAX_SID_SIZE;
    let mut buf = vec![0u8; size as usize];
    let mut sid = PSID(buf.as_mut_ptr() as *mut _);
    let authority = SID_IDENTIFIER_AUTHORITY { Value: [0, 0, 0, 0, 0, 5] };
    unsafe {
        if AllocateAndInitializeSid(&authority, 2, 32, 544, 0, 0, 0, 0, 0, 0, &mut sid).is_ok() {
            let len = GetLengthSid(sid) as usize;
            let mut owned: Vec<u8> = vec![0u8; len];
            let _ = CopySid(len as u32, PSID(owned.as_mut_ptr() as *mut _), sid);
            let _ = FreeSid(sid);
            Some(PSID(owned.leak().as_mut_ptr() as *mut _))
        } else {
            None
        }
    }
}

/// Delete the AppContainer profile (best-effort cleanup).
#[allow(dead_code)]
pub fn delete_profile(ac_name: &str) {
    let w = HSTRING::from(ac_name);
    let _ = unsafe { DeleteAppContainerProfile(&w) };
}

/// Build the child environment block: parent env + `PATH` prepended with
/// `.sandbox\<sid>\bin`.
pub fn build_env_block(sid: &str, cwd: &std::path::Path) -> Vec<u16> {
    let bin_abs = cwd.join(format!(".\\.sandbox\\{}\\bin", sid));
    let bin_path = bin_abs.to_string_lossy().to_string();

    let mut vars: Vec<(String, String)> = Vec::new();
    let mut path_overridden = false;
    for (k, v) in std::env::vars() {
        if k.eq_ignore_ascii_case("PATH") {
            vars.push((k, format!("{};{}", bin_path, v)));
            path_overridden = true;
        } else {
            vars.push((k, v));
        }
    }
    if !path_overridden {
        vars.push(("PATH".to_string(), bin_path));
    }

    // UTF-16 environment block: "K1=V1\0K2=V2\0\0".
    let mut block: Vec<u16> = Vec::new();
    for (k, v) in &vars {
        for c in k.encode_utf16() {
            block.push(c);
        }
        block.push(b'=' as u16);
        for c in v.encode_utf16() {
            block.push(c);
        }
        block.push(0);
    }
    block.push(0);
    block.push(0);
    block
}
