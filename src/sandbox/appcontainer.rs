use windows::Win32::Foundation::*;
use windows::Win32::Security::Authorization::*;
use windows::Win32::Security::Isolation::*;
use windows::Win32::Security::*;
use windows::Win32::System::Threading::*;
use windows::core::*;

use crate::net::ProxyEnv;
use crate::sandbox::allowlist::AllowEntry;

pub struct AppContainerSession {
    pub sid: String,
    pub ac_sid: PSID,
    pub ac_name: String,
}

/// Create (or re-derive) the AppContainer profile for `sid` and return the
/// AppContainer SID plus a process token.
///
/// Uses `CreateAppContainerProfile` to mint a per-session AppContainer SID,
/// then `CreateProcessW` with `PROC_THREAD_ATTRIBUTE_APPCONTAINER_SID` makes
/// the kernel build the child's token with the AppContainer SID as a
/// restricting identity. By default an AppContainer process is
/// deny-by-default: every securable object it touches must carry an explicit
/// Allow ACE naming the AppContainer SID.
///
/// Access is granted the direct way (per-directory DACL Allow ACEs for the
/// AppContainer SID) — what `icacls /grant` does. The AppContainer SID is
/// still a restricting identity, so anything without an ACE is denied.
pub fn create_session(sid: &str) -> Result<AppContainerSession> {
    let ac_name = format!("sandbox.{sid}.ac");
    let ac_name_w = HSTRING::from(&ac_name);

    let ac_sid = unsafe {
        match CreateAppContainerProfile(&ac_name_w, w!("sandbox"), w!("sandbox session"), None) {
            Ok(s) => s,
            // Profile already exists for this name — re-derive the SID.
            // Both error codes appear across windows-rs versions:
            // ERROR_ALREADY_EXISTS (0x800700B7) and the AppContainer-specific
            // 0x80071392.
            Err(e) if e.code() == HRESULT::from_win32(0x800700B7)
                || e.code() == HRESULT::from_win32(0x80071392) =>
            {
                DeriveAppContainerSidFromAppContainerName(&ac_name_w)?
            }
            Err(e) => return Err(e),
        }
    };

    Ok(AppContainerSession {
        sid: sid.to_string(),
        ac_sid,
        ac_name,
    })
}

/// Grant the AppContainer SID the requested access on `entries` by writing
/// an explicit DACL onto each directory. Failures on individual entries are
/// logged to stderr but do not abort (the spike showed that some SystemRoot
/// grants fail on locked-down machines — harmless because those dirs are
/// world-readable).
pub fn grant_access(ac_sid: &PSID, entries: &[AllowEntry]) -> Result<()> {
    let diag = std::env::var_os("SANDBOX_DIAG").is_some();
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

fn grant_one(ac_sid: &PSID, e: &AllowEntry) -> Result<()> {
    let path_str = e.win32_path.to_string_lossy().to_string();
    let path_w = HSTRING::from(&path_str);
    unsafe {
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

/// Owner trustees for PROTECTED_DACLs: current user, SYSTEM, Administrators.
/// PROTECTED drops inherited ACEs, so we re-grant Full Control explicitly.
fn owner_trustees() -> Vec<TRUSTEE_W> {
    let mut trustees = Vec::new();
    if let Some(user_sid) = current_user_sid() {
        trustees.push(TRUSTEE_W {
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_USER,
            ptstrName: PWSTR(user_sid.0 as *mut _),
            ..Default::default()
        });
    }
    if let Some(system_sid) = well_known_sid(18) {
        trustees.push(TRUSTEE_W {
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_USER,
            ptstrName: PWSTR(system_sid.0 as *mut _),
            ..Default::default()
        });
    }
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

fn current_user_sid() -> Option<PSID> {
    unsafe {
        let mut token = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return None;
        }
        let mut needed = 0u32;
        let _ = GetTokenInformation(token, TokenUser, None, 0, &mut needed);
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
        let src_sid = tu.User.Sid;
        let len = GetLengthSid(src_sid) as usize;
        let mut owned: Vec<u8> = vec![0u8; len];
        let _ = CopySid(len as u32, PSID(owned.as_mut_ptr() as *mut _), src_sid);
        Some(PSID(owned.leak().as_mut_ptr() as *mut _))
    }
}

fn well_known_sid(rid: u32) -> Option<PSID> {
    let mut size = SECURITY_MAX_SID_SIZE;
    let mut buf = vec![0u8; size as usize];
    let mut sid = PSID(buf.as_mut_ptr() as *mut _);
    let authority = SID_IDENTIFIER_AUTHORITY { Value: [0, 0, 0, 0, 0, 5] };
    unsafe {
        if AllocateAndInitializeSid(&authority, 1, rid, 0, 0, 0, 0, 0, 0, 0, &mut sid).is_ok() {
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

/// Build the child environment block: parent env + `PATH` prepended with
/// `.sandbox\<sid>\bin`, plus the proxy env vars.
///
/// `proxy: Some(ProxyEnv)` injects `HTTP_PROXY`/`HTTPS_PROXY`/`X-Sandbox-Token`
/// pointing at the localhost proxy and clears `NO_PROXY` (forces the proxy to
/// be used for everything, including localhost — some tools default
/// `NO_PROXY=localhost,127.0.0.1` which would bypass our proxy).
/// `proxy: None` (block-net case) explicitly clears all four vars so a
/// parent shell's proxy settings don't leak into the sandboxed process.
pub fn build_env_block(sid: &str, cwd: &std::path::Path, proxy: Option<&ProxyEnv>) -> Vec<u16> {
    let bin_abs = cwd.join(format!(".\\.sandbox\\{sid}\\bin"));
    let bin_path = bin_abs.to_string_lossy().to_string();

    // Decide the value (or absence) of the four proxy-related env vars.
    // `Some` → inject proxy URL + token, empty NO_PROXY.
    // `None` → set all four to empty (override any inherited parent values).
    let (http_proxy, https_proxy, token_val, no_proxy): (String, String, String, String) =
        match proxy {
            Some(p) => (
                format!("http://127.0.0.1:{}", p.port),
                format!("http://127.0.0.1:{}", p.port),
                p.token.clone(),
                String::new(),
            ),
            None => (
                String::new(),
                String::new(),
                String::new(),
                String::new(),
            ),
        };
    // Names of the four proxy vars, in the order we post-process them.
    // Comparison is case-insensitive (Windows env vars are case-insensitive).
    const PROXY_VARS: [&str; 4] =
        ["HTTP_PROXY", "HTTPS_PROXY", "X-Sandbox-Token", "NO_PROXY"];

    let mut vars: Vec<(String, String)> = Vec::new();
    let mut path_overridden = false;
    // Track which of the 4 proxy vars we've already emitted (by index) so we
    // can fill in any that were missing from the parent env afterwards.
    let mut proxy_seen = [false; 4];
    for (k, v) in std::env::vars() {
        if k.eq_ignore_ascii_case("PATH") {
            vars.push((k, format!("{};{}", bin_path, v)));
            path_overridden = true;
            continue;
        }
        // Check if this is one of the proxy vars we manage.
        if let Some(idx) = PROXY_VARS.iter().position(|name| k.eq_ignore_ascii_case(name)) {
            proxy_seen[idx] = true;
            let replacement = [http_proxy.clone(), https_proxy.clone(), token_val.clone(), no_proxy.clone()][idx].clone();
            vars.push((k, replacement));
        } else {
            vars.push((k, v));
        }
    }
    if !path_overridden {
        vars.push(("PATH".to_string(), bin_path));
    }
    // Append any proxy vars that were not present in the parent env.
    let proxy_values = [http_proxy, https_proxy, token_val, no_proxy];
    for (idx, name) in PROXY_VARS.iter().enumerate() {
        if !proxy_seen[idx] {
            vars.push((name.to_string(), proxy_values[idx].clone()));
        }
    }

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

#[allow(dead_code)]
pub fn delete_profile(ac_name: &str) {
    let w = HSTRING::from(ac_name);
    let _ = unsafe { DeleteAppContainerProfile(&w) };
}
