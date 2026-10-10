use windows::Win32::Foundation::*;
use windows::Win32::Security::Authorization::*;
use windows::Win32::Security::Isolation::*;
use windows::Win32::Security::*;
use windows::Win32::Storage::FileSystem::*;
use windows::Win32::System::Registry::{
    RegCloseKey, RegCreateKeyExW, HKEY, HKEY_CURRENT_USER, KEY_QUERY_VALUE,
    REG_OPTION_NON_VOLATILE,
};
use windows::Win32::System::Threading::*;
use windows::core::*;

use crate::net::ProxyEnv;
use crate::sandbox::allowlist::AllowEntry;
use crate::sandbox::dacl_journal::{DaclJournal, JournalEntry, PriorAce};

/// Fields `sid` and `ac_name` are retained for diagnostics and future
/// tear-down/audit wiring; only `ac_sid` is consumed by `spawn` today.
#[allow(dead_code)]
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

    // DeleteAppContainerProfile removes the profile base resources (the
    // %LOCALAPPDATA%\...\AppContainer\Profiles directory — verified missing
    // on a heavily used host) together with the LAST profile. A pristine
    // test VM carries no other AppContainer profiles, so every sandbox
    // teardown deletes "the last one"; on Windows builds that do not
    // recreate the bases (observed: Insider 26340 guest, ERROR_FILE_NOT_FOUND
    // 0x80070002) every subsequent session creation then fails. Recreate
    // the bases up front and retry once on ERROR_FILE_NOT_FOUND.
    ensure_profile_resources();

    let ac_sid = match try_create_or_derive(&ac_name_w) {
        Ok(s) => s,
        Err(e) if e.code() == HRESULT::from_win32(0x80070002) => {
            ensure_profile_resources();
            try_create_or_derive(&ac_name_w)?
        }
        Err(e) => return Err(e),
    };

    Ok(AppContainerSession {
        sid: sid.to_string(),
        ac_sid,
        ac_name,
    })
}

/// Create the AppContainer profile for `ac_name_w`, or re-derive its SID
/// when a profile of that name already exists.
fn try_create_or_derive(ac_name_w: &HSTRING) -> Result<PSID> {
    unsafe {
        match CreateAppContainerProfile(ac_name_w, w!("sandbox"), w!("sandbox session"), None) {
            Ok(s) => Ok(s),
            // Profile already exists for this name (e.g. a crashed supervisor
            // left it behind) — re-derive the SID. Both error codes appear
            // across windows-rs versions: ERROR_ALREADY_EXISTS (0x800700B7)
            // and the AppContainer-specific 0x80071392.
            Err(e)
                if e.code() == HRESULT::from_win32(0x800700B7)
                    || e.code() == HRESULT::from_win32(0x80071392) =>
            {
                DeriveAppContainerSidFromAppContainerName(ac_name_w)
            }
            Err(e) => Err(e),
        }
    }
}

/// Recreate the AppContainer profile base resources that profile teardown
/// can remove together with the last profile: the file-system Profiles
/// directory and the per-user Storage registry key. Both are plain
/// containers with no data of their own; creating them when missing is
/// harmless and lets CreateAppContainerProfile succeed on Windows builds
/// that do not recreate them themselves.
fn ensure_profile_resources() {
    if let Some(local) = std::env::var_os("LOCALAPPDATA") {
        let profiles = std::path::Path::new(&local).join("Microsoft\\Windows\\AppContainer\\Profiles");
        if !profiles.is_dir() {
            let _ = std::fs::create_dir_all(&profiles);
        }
    }
    unsafe {
        let mut hkey = HKEY::default();
        let r = RegCreateKeyExW(
            HKEY_CURRENT_USER,
            w!("Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\CurrentVersion\\AppContainer\\Storage"),
            None,
            PCWSTR::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_QUERY_VALUE,
            None,
            &mut hkey,
            None,
        );
        if r.is_ok() {
            let _ = RegCloseKey(hkey);
        }
    }
}

/// Grant the AppContainer SID the requested access on `entries` by writing
/// an explicit DACL onto each directory. Failures on individual entries are
/// logged to stderr but do not abort (the spike showed that some SystemRoot
/// grants fail on locked-down machines — harmless because those dirs are
/// world-readable).
///
/// `journal`, when present, receives every grant BEFORE it is applied
/// (MXC filesystem_dacl.rs pattern): teardown replays the journal to
/// restore the host, and a crash leaves a restorable record behind.
pub fn grant_access(
    ac_sid: &PSID,
    entries: &[AllowEntry],
    journal: Option<&DaclJournal>,
) -> Result<()> {
    let diag = std::env::var_os("SANDBOX_DIAG").is_some();
    for e in entries {
        if let Err(err) = grant_one(ac_sid, e, journal) {
            if diag {
                eprintln!(
                    "[grant] WARN: {:>16} {:?} failed: {err}",
                    if e.deny {
                        format!("{} [deny]", e.label)
                    } else {
                        e.label.to_string()
                    },
                    e.win32_path
                );
            }
        } else if diag {
            eprintln!(
                "[grant] {:>16}  {:?}  mask=0x{:x}{}{}",
                if e.deny {
                    format!("{} [deny]", e.label)
                } else {
                    e.label.to_string()
                },
                e.win32_path,
                e.access,
                if e.deny { " DENY" } else { "" },
                if e.protected { " PROTECTED" } else { "" }
            );
        }
    }
    Ok(())
}

fn grant_one(ac_sid: &PSID, e: &AllowEntry, journal: Option<&DaclJournal>) -> Result<()> {
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

        // Snapshot our trustee's explicit ACEs BEFORE mutating (restored on
        // teardown; MXC filesystem_dacl.rs:22-28 — SetEntriesInAclW coalesces
        // same-trustee rights, so per-ACE selective removal is impossible).
        let prior_aces = snapshot_prior_aces(dacl_ptr, ac_sid);
        if let Some(j) = journal {
            if let Ok(sid_str) = sid_to_string(*ac_sid) {
                let entry = JournalEntry {
                    path: path_str.clone(),
                    sid: sid_str,
                    granted_mask: e.access,
                    deny: e.deny,
                    protected: e.protected,
                    inherit: e.inherit,
                    prior_aces,
                };
                if let Err(err) = j.record(&entry) {
                    // Journal failure is a warning: the run proceeds, and
                    // teardown/next startup simply won't restore this path.
                    // Matches grant_access's per-entry error tolerance.
                    eprintln!("[journal] WARN: record failed for {path_str}: {err}");
                }
            } else {
                eprintln!("[journal] WARN: record failed for {path_str}: SID conversion failed");
            }
        }

        let ea = EXPLICIT_ACCESS_W {
            grfAccessPermissions: e.access,
            grfAccessMode: if e.deny { DENY_ACCESS } else { SET_ACCESS },
            // Inheritable ACE only when requested; ancestor traverse grants
            // are non-inheritable (a kernel-handle DACL write with an
            // inheritable ACE on a large tree walks every descendant —
            // e.g. C:\Users\marku\AppData\Local — appearing as a hang).
            grfInheritance: if e.inherit {
                SUB_CONTAINERS_AND_OBJECTS_INHERIT
            } else {
                NO_INHERITANCE
            },
            Trustee: TRUSTEE_W {
                TrusteeForm: TRUSTEE_IS_SID,
                TrusteeType: TRUSTEE_IS_GROUP,
                ptstrName: PWSTR(ac_sid.0 as *mut _),
                ..Default::default()
            },
        };

        let mut new_acl: *mut ACL = std::ptr::null_mut();
        let set_r = if e.protected {
            let mut all_entries: Vec<EXPLICIT_ACCESS_W> = Vec::new();
            for trustee in owner_trustees() {
                let owner_ea = EXPLICIT_ACCESS_W {
                    grfAccessPermissions: 0x1f01ff, // FILE_ALL_ACCESS
                    grfAccessMode: SET_ACCESS,
                    grfInheritance: SUB_CONTAINERS_AND_OBJECTS_INHERIT,
                    Trustee: trustee,
                };
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

        // SetSecurityInfo bypasses aclapi Marta propagation entirely.
        // Marta (ntmarta.dll) hangs when recursively propagating ANY inherited
        // ACEs down a large subtree (e.g. C:\Users\<user>) - not just the new ACE.
        // Using a kernel-handle-based DACL write skips Marta completely: the
        // kernel writes the DACL directly, no userspace tree propagation.
        // (Extracted as `apply_dacl_kernel` so the DACL-restore path uses the
        // identical write mechanism.)
        apply_dacl_kernel(&path_str, new_acl, e.protected)
    }
}

/// Open `path` for a DACL write and apply `new_acl` via kernel-handle
/// `SetSecurityInfo` (the de0b9bf Marta-hang bypass). Frees `new_acl`.
fn apply_dacl_kernel(path_str: &str, new_acl: *mut ACL, protected: bool) -> Result<()> {
    unsafe {
        let mut path_buf: Vec<u16> = path_str.encode_utf16().collect();
        path_buf.push(0); // ensure trailing null
        let open_r = CreateFileW(
            PCWSTR(path_buf.as_ptr()),
            WRITE_DAC.0 | READ_CONTROL.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        );
        let handle = match open_r {
            Ok(h) => h,
            Err(e) => {
                LocalFree(Some(HLOCAL(new_acl as *mut _)));
                return Err(e);
            }
        };
        // call SetSecurityInfo (which uses the kernel) with the handle.
        let flags = if protected {
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION
        } else {
            DACL_SECURITY_INFORMATION | UNPROTECTED_DACL_SECURITY_INFORMATION
        };
        let write_r = SetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            flags,
            None,
            None,
            Some(new_acl),
            None,
        );
        let _ = LocalFree(Some(HLOCAL(new_acl as *mut _)));
        let _ = CloseHandle(handle);
        if write_r.is_err() {
            return Err(HRESULT::from_win32(write_r.0).into());
        }
    }
    Ok(())
}

/// Revoke our trustee's ACEs and re-grant the journaled prior state for
/// every entry in the journal (MXC teardown semantics). Applies through
/// `apply_dacl_kernel` — never through the Marta write path.
pub fn restore_all(journal: &DaclJournal) -> Result<()> {
    for entry in journal.entries() {
        restore_one(&entry)?;
    }
    Ok(())
}

/// Restore + log-on-failure wrapper for `run()` teardown and orphan reaping.
/// Returns true only when every entry was restored (journal then removable);
/// on failure the journal file is KEPT so the next startup retries.
pub fn restore_or_warn(journal: &DaclJournal) -> bool {
    match restore_all(journal) {
        Ok(()) => true,
        Err(e) => {
            eprintln!(
                "[sandbox] warning: DACL restore failed; journal retained for retry at next start: {}",
                journal.path().display()
            );
            eprintln!("[sandbox]          {e:#}");
            false
        }
    }
}

fn restore_one(e: &JournalEntry) -> Result<()> {
    let path_str = e.path.clone();
    let path_w = HSTRING::from(e.path.as_str());
    let sid_w = HSTRING::from(e.sid.as_str());
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

        let mut psid = PSID(std::ptr::null_mut());
        if ConvertStringSidToSidW(&sid_w, &mut psid).is_err() {
            let _ = LocalFree(Some(HLOCAL(sd.0 as *mut _)));
            return Err(Error::from_hresult(HRESULT::from_win32(0x80070057)));
        }

        // The journal records entries BEFORE the grant applies, so a grant
        // that never applied (e.g. system-owned System32/SystemRoot, or a
        // failed write) has nothing to restore. Skip the DACL write when the
        // object carries none of our ACEs and there is no prior state —
        // otherwise the write fails on unwritable system paths and the
        // journal can never be retired.
        let ours_on_object = snapshot_prior_aces(dacl_ptr, &psid);
        if !e.protected && e.prior_aces.is_empty() && ours_on_object.is_empty() {
            let _ = LocalFree(Some(HLOCAL(sd.0 as *mut _)));
            let _ = LocalFree(Some(HLOCAL(psid.0 as *mut _)));
            return Ok(());
        }

        let revoke = EXPLICIT_ACCESS_W {
            grfAccessPermissions: 0,
            grfAccessMode: REVOKE_ACCESS,
            grfInheritance: NO_INHERITANCE,
            Trustee: TRUSTEE_W {
                TrusteeForm: TRUSTEE_IS_SID,
                TrusteeType: TRUSTEE_IS_GROUP,
                ptstrName: PWSTR(psid.0 as *mut _),
                ..Default::default()
            },
        };

        let mut new_acl: *mut ACL = std::ptr::null_mut();
        let set_r = if e.protected {
            // PROTECTED dropped inheritance, so grant_one rebuilt the DACL
            // from scratch: rebuild it the same way (owner trustees + prior
            // state for our trustee), applied with the PROTECTED flag.
            let mut all_entries: Vec<EXPLICIT_ACCESS_W> = Vec::new();
            for trustee in owner_trustees() {
                all_entries.push(EXPLICIT_ACCESS_W {
                    grfAccessPermissions: 0x1f01ff, // FILE_ALL_ACCESS
                    grfAccessMode: SET_ACCESS,
                    grfInheritance: SUB_CONTAINERS_AND_OBJECTS_INHERIT,
                    Trustee: trustee,
                });
            }
            for ea in prior_eas(&e.prior_aces, psid) {
                all_entries.push(ea);
            }
            SetEntriesInAclW(Some(&all_entries), None, &mut new_acl)
        } else {
            let old_acl_opt = if dacl_ptr.is_null() {
                None
            } else {
                Some(dacl_ptr as *const ACL)
            };
            let mut tmp: *mut ACL = std::ptr::null_mut();
            let first = SetEntriesInAclW(Some(&[revoke]), old_acl_opt, &mut tmp);
            if first.is_err() {
                let _ = LocalFree(Some(HLOCAL(sd.0 as *mut _)));
                let _ = LocalFree(Some(HLOCAL(psid.0 as *mut _)));
                return Err(HRESULT::from_win32(first.0).into());
            }
            let prior: Vec<EXPLICIT_ACCESS_W> = prior_eas(&e.prior_aces, psid);
            if prior.is_empty() {
                new_acl = tmp;
                WIN32_ERROR(0)
            } else {
                let second = SetEntriesInAclW(Some(&prior), Some(tmp), &mut new_acl);
                let _ = LocalFree(Some(HLOCAL(tmp as *mut _)));
                second
            }
        };

        let _ = LocalFree(Some(HLOCAL(psid.0 as *mut _)));
        let _ = LocalFree(Some(HLOCAL(sd.0 as *mut _)));
        if set_r.is_err() {
            return Err(HRESULT::from_win32(set_r.0).into());
        }

        apply_dacl_kernel(&path_str, new_acl, e.protected)
    }
}

/// EXPLICIT_ACCESS_W entries that reproduce a journal's prior ACEs verbatim
/// for the session trustee `psid`.
fn prior_eas(prior: &[PriorAce], psid: PSID) -> Vec<EXPLICIT_ACCESS_W> {
    prior
        .iter()
        .map(|a| EXPLICIT_ACCESS_W {
            grfAccessPermissions: a.mask,
            grfAccessMode: if a.deny { DENY_ACCESS } else { SET_ACCESS },
            grfInheritance: windows::Win32::Security::ACE_FLAGS(a.inherit_flags),
            Trustee: TRUSTEE_W {
                TrusteeForm: TRUSTEE_IS_SID,
                TrusteeType: TRUSTEE_IS_GROUP,
                ptstrName: PWSTR(psid.0 as *mut _),
                ..Default::default()
            },
        })
        .collect()
}

/// Explicit (non-inherited) ACEs for `ac_sid` currently on `dacl_ptr` —
/// the prior state we must restore after revoking our grants.
fn snapshot_prior_aces(dacl_ptr: *mut ACL, ac_sid: &PSID) -> Vec<PriorAce> {
    let mut out = Vec::new();
    if dacl_ptr.is_null() {
        return out;
    }
    unsafe {
        let mut count: u32 = 0;
        let mut ea_array: *mut EXPLICIT_ACCESS_W = std::ptr::null_mut();
        if GetExplicitEntriesFromAclW(dacl_ptr, &mut count, &mut ea_array).is_ok()
            && !ea_array.is_null()
        {
            for i in 0..count as usize {
                let ea = ea_array.add(i);
                if (*ea).Trustee.TrusteeForm == TRUSTEE_IS_SID {
                    let sid = PSID((*ea).Trustee.ptstrName.0 as *mut _);
                    if EqualSid(*ac_sid, sid).is_ok() {
                        out.push(PriorAce {
                            deny: (*ea).grfAccessMode == DENY_ACCESS,
                            mask: (*ea).grfAccessPermissions,
                            inherit_flags: (*ea).grfInheritance.0,
                        });
                    }
                }
            }
            let _ = LocalFree(Some(HLOCAL(ea_array as *mut _)));
        }
    }
    out
}

/// SDDL-style string form of `sid` (ConvertSidToStringSidW + LocalFree).
fn sid_to_string(sid: PSID) -> Result<String> {
    unsafe {
        let mut buf = PWSTR::null();
        ConvertSidToStringSidW(sid, &mut buf)?;
        let s = if buf.0.is_null() {
            String::new()
        } else {
            // buf.0 is a NUL-terminated UTF-16 string; decode it as such
            // (reading it as an 8-bit C string would truncate at "S" —
            // the second UTF-16 byte is the NUL).
            let len = (0..).take_while(|i| *buf.0.add(*i) != 0).count();
            String::from_utf16_lossy(std::slice::from_raw_parts(buf.0, len))
        };
        let _ = LocalFree(Some(HLOCAL(buf.0 as *mut _)));
        Ok(s)
    }
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
    let size = SECURITY_MAX_SID_SIZE;
    let mut buf = vec![0u8; size as usize];
    let mut sid = PSID(buf.as_mut_ptr() as *mut _);
    let authority = SID_IDENTIFIER_AUTHORITY {
        Value: [0, 0, 0, 0, 0, 5],
    };
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
    let size = SECURITY_MAX_SID_SIZE;
    let mut buf = vec![0u8; size as usize];
    let mut sid = PSID(buf.as_mut_ptr() as *mut _);
    let authority = SID_IDENTIFIER_AUTHORITY {
        Value: [0, 0, 0, 0, 0, 5],
    };
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
/// `.sandbox\<sid>\bin`, `TEMP`/`TMP` redirected to `.sandbox\<sid>\tmp`,
/// plus the proxy env vars.
///
/// `TEMP`/`TMP` are redirected because the parent's `%TEMP%` is not in the
/// allow-list, and the AppContainer-private `%TEMP%`
/// (`%LOCALAPPDATA%\Packages\<ac>\AC\Temp`) has broken ACL inheritance on
/// some Windows builds — directories created inside it deny their own
/// creator (observed on build 26340), breaking every tool that stages
/// files via the temp dir (pip/ensurepip, installers, compilers). Python's
/// `tempfile` checks env `TEMP`/`TMP` before falling back to `GetTempPathW`
/// (which ignores them for AppContainer tokens), so the redirect takes
/// precedence.
///
/// `proxy: Some(ProxyEnv)` injects `HTTP_PROXY`/`HTTPS_PROXY`/`X-Sandbox-Token`
/// pointing at the localhost proxy and clears `NO_PROXY` (forces the proxy to
/// be used for everything, including localhost — some tools default
/// `NO_PROXY=localhost,127.0.0.1` which would bypass our proxy).
/// `proxy: None` (block-net case) explicitly clears all four vars so a
/// parent shell's proxy settings don't leak into the sandboxed process.
pub fn build_env_block(sid: &str, cwd: &std::path::Path, proxy: Option<&ProxyEnv>) -> Vec<u16> {
    let bin_abs = cwd.join(format!(".sandbox\\{sid}\\bin"));
    let bin_path = bin_abs.to_string_lossy().to_string();
    let tmp_abs = cwd.join(format!(".sandbox\\{sid}\\tmp"));
    let tmp_path = tmp_abs.to_string_lossy().to_string();

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
            None => (String::new(), String::new(), String::new(), String::new()),
        };
    // Names of the four proxy vars, in the order we post-process them.
    // Comparison is case-insensitive (Windows env vars are case-insensitive).
    const PROXY_VARS: [&str; 4] = ["HTTP_PROXY", "HTTPS_PROXY", "X-Sandbox-Token", "NO_PROXY"];
    // Temp vars to redirect into the per-session dir (case-insensitive).
    const TEMP_VARS: [&str; 2] = ["TEMP", "TMP"];

    let mut vars: Vec<(String, String)> = Vec::new();
    let mut path_overridden = false;
    // Track which of the 4 proxy vars we've already emitted (by index) so we
    // can fill in any that were missing from the parent env afterwards.
    let mut proxy_seen = [false; 4];
    // Same for TEMP/TMP.
    let mut temp_seen = [false; 2];
    for (k, v) in std::env::vars() {
        if k.eq_ignore_ascii_case("PATH") {
            vars.push((k, format!("{};{}", bin_path, v)));
            path_overridden = true;
            continue;
        }
        // Check if this is one of the proxy vars we manage.
        if let Some(idx) = PROXY_VARS
            .iter()
            .position(|name| k.eq_ignore_ascii_case(name))
        {
            proxy_seen[idx] = true;
            let replacement = [
                http_proxy.clone(),
                https_proxy.clone(),
                token_val.clone(),
                no_proxy.clone(),
            ][idx]
                .clone();
            vars.push((k, replacement));
        } else if let Some(idx) = TEMP_VARS
            .iter()
            .position(|name| k.eq_ignore_ascii_case(name))
        {
            temp_seen[idx] = true;
            vars.push((k, tmp_path.clone()));
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
    // Append any temp vars that were not present in the parent env.
    for (idx, name) in TEMP_VARS.iter().enumerate() {
        if !temp_seen[idx] {
            vars.push((name.to_string(), tmp_path.clone()));
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

#[cfg(test)]
mod env_block_tests {
    use super::*;

    /// Decode a NUL-separated UTF-16 environment block into (key, value) pairs.
    fn decode(block: &[u16]) -> Vec<(String, String)> {
        let mut out = Vec::new();
        for entry in block.split(|&c| c == 0) {
            if entry.is_empty() {
                continue;
            }
            let s = String::from_utf16_lossy(entry);
            if let Some(eq) = s.find('=') {
                out.push((s[..eq].to_string(), s[eq + 1..].to_string()));
            }
        }
        out
    }

    #[test]
    fn env_block_redirects_temp_and_prepends_path() {
        let sid = "testsid";
        let cwd = std::path::Path::new(r"C:\some\cwd");
        let vars = decode(&build_env_block(sid, cwd, None));
        let get = |name: &str| {
            vars.iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.clone())
                .expect("env var present")
        };
        assert_eq!(
            get("TEMP"),
            r"C:\some\cwd\.sandbox\testsid\tmp",
            "TEMP redirected to per-session dir"
        );
        assert_eq!(get("TMP"), r"C:\some\cwd\.sandbox\testsid\tmp");
        assert!(
            get("PATH").starts_with(r"C:\some\cwd\.sandbox\testsid\bin;"),
            "PATH prepended with session bin dir: {}",
            get("PATH")
        );
        // Block-net mode (proxy: None) clears the proxy vars.
        assert_eq!(get("HTTP_PROXY"), "");
        assert_eq!(get("NO_PROXY"), "");
    }
}
