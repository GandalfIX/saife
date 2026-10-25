use windows::Win32::Foundation::*;
use windows::Win32::Security::Authorization::*;
use windows::Win32::Security::Isolation::*;
use windows::Win32::Security::*;
use windows::Win32::Storage::FileSystem::*;
use windows::Win32::System::Registry::{
    HKEY, HKEY_CURRENT_USER, KEY_QUERY_VALUE, REG_OPTION_NON_VOLATILE, RegCloseKey, RegCreateKeyExW,
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
pub fn ac_profile_name(sid: &str) -> String {
    format!("sandbox.{sid}.ac")
}

/// Path of the AppContainer-private temp dir Windows assigns to this
/// session's child (`%LOCALAPPDATA%\Packages\<ac>\AC\Temp`). Windows
/// rewrites the child's TEMP/TMP env vars to this path — explicit env
/// values do NOT survive CreateProcess for AppContainer tokens (verified
/// on build 26340) — so the sandbox must make this dir usable via a
/// grant instead (see build_allowlist).
pub fn ac_private_temp_path(sid: &str) -> Option<std::path::PathBuf> {
    std::env::var("LOCALAPPDATA").ok().map(|local| {
        std::path::PathBuf::from(local)
            .join("Packages")
            .join(ac_profile_name(sid))
            .join("AC")
            .join("Temp")
    })
}

pub fn create_session(sid: &str) -> Result<AppContainerSession> {
    let ac_name = ac_profile_name(sid);
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
        let profiles =
            std::path::Path::new(&local).join("Microsoft\\Windows\\AppContainer\\Profiles");
        if !profiles.is_dir() {
            let _ = std::fs::create_dir_all(&profiles);
        }
    }
    unsafe {
        let mut hkey = HKEY::default();
        let r = RegCreateKeyExW(
            HKEY_CURRENT_USER,
            w!(
                "Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\CurrentVersion\\AppContainer\\Storage"
            ),
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
    let diag = std::env::var_os("SAIFE_DIAG").is_some();
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
        apply_dacl_kernel(&path_str, new_acl, e.protected)?;

        // The kernel DOES propagate the inheritable ACE to pre-existing
        // children, but via an asynchronous auto-inherit wave — near-instant
        // on small trees, but observably incomplete for seconds on large ones
        // (proven on a 4.6k-file uv python tree: the spawned child raced the
        // wave and could not read its own interpreter DLLs — loader error
        // 0xC0000135). Make the grant deterministic instead: write the ACE
        // onto every pre-existing descendant synchronously before the child
        // is spawned (propagate_grant).
        if should_propagate(e) {
            let stats = propagate_grant(ac_sid, e, journal, PROPAGATE_MAX_OBJECTS);
            if stats.truncated {
                eprintln!(
                    "[saife] warning: grant propagation for {:?} truncated at {PROPAGATE_MAX_OBJECTS} objects; pre-existing files deeper in the tree may be unreadable inside the sandbox",
                    e.win32_path
                );
            }
            if std::env::var_os("SAIFE_DIAG").is_some() {
                eprintln!(
                    "[grant] {:>16}  propagated: applied={} failed={} skipped={}",
                    if e.deny {
                        format!("{} [deny]", e.label)
                    } else {
                        e.label.to_string()
                    },
                    stats.applied,
                    stats.failed,
                    stats.skipped
                );
            }
        }
        Ok(())
    }
}

/// Upper bound on pre-existing objects visited by `propagate_grant` per
/// entry. Bounds both the walk and the journal so a pathological `allow:`
/// tree cannot wedge startup or grow the journal unbounded. Roots beyond
/// the cap keep their own ACE; deeper pre-existing files may stay
/// unreadable to the child (warned).
const PROPAGATE_MAX_OBJECTS: usize = 20_000;

/// Journal+apply batch size for `propagate_grant`: a batch is journaled
/// with a single fsync (`record_many`) and only applied afterwards,
/// preserving the journal-before-apply crash contract at batch
/// granularity.
const PROPAGATE_BATCH: usize = 256;

#[derive(Debug, Default)]
struct PropagateStats {
    /// Children whose ACE write was applied.
    applied: usize,
    /// Children whose ACE write failed (tolerated — mirrors
    /// grant_access's per-entry error tolerance).
    failed: usize,
    /// Children skipped without a write: PROTECTED DACL (inheritance — and
    /// therefore propagation — stops at PROTECTED boundaries; also keeps
    /// sibling sessions' `.sandbox\<sid>` subtrees isolated) or no DACL at
    /// all (a null DACL is world-accessible: the child can already use the
    /// object, and writing one would strip the owner's access).
    skipped: usize,
    /// True when the walk stopped early at `max_objects`.
    truncated: bool,
}

/// One staged descendant write: the journal entry plus the merged DACL,
/// applied by `flush_batch` once the whole batch is on disk.
struct PendingChild {
    path: String,
    entry: JournalEntry,
    acl: *mut ACL,
}

/// Should this entry's ACE be propagated synchronously to its pre-existing
/// descendants? Only inheritable, non-PROTECTED grants — and never
/// anything at/under SystemRoot (System32/SystemRoot are huge,
/// system-owned, and already world-readable; their RX grants stay
/// dir-level, and a failed grant there is harmless).
fn should_propagate(e: &AllowEntry) -> bool {
    e.inherit && !e.protected && !is_under_system_root(&e.win32_path)
}

/// Case-insensitive component-prefix test: is `path` SystemRoot itself or
/// somewhere below it?
fn is_under_system_root(path: &std::path::Path) -> bool {
    let Some(root) = std::env::var_os("SystemRoot") else {
        return false;
    };
    let mut root_comps = std::path::Path::new(&root).components();
    let mut path_comps = path.components();
    loop {
        match root_comps.next() {
            Some(r) => match path_comps.next() {
                Some(p) => {
                    if !r
                        .as_os_str()
                        .to_string_lossy()
                        .eq_ignore_ascii_case(&p.as_os_str().to_string_lossy())
                    {
                        return false;
                    }
                }
                None => return false,
            },
            None => return true,
        }
    }
}

/// Write the entry's ACE onto every pre-existing descendant of the granted
/// root: files and reparse points get a non-inheritable ACE, subdirs an
/// inheritable one (so files created later inherit at creation time).
/// PROTECTED/null-DACL subtrees are skipped and not descended into.
/// Every applied write is journaled, so teardown needs no walk of its own
/// — journal replay covers the children exactly like the roots.
fn propagate_grant(
    ac_sid: &PSID,
    e: &AllowEntry,
    journal: Option<&DaclJournal>,
    max_objects: usize,
) -> PropagateStats {
    let mut stats = PropagateStats::default();
    let mut batch: Vec<PendingChild> = Vec::new();
    let mut stack: Vec<std::path::PathBuf> = vec![e.win32_path.clone()];

    while let Some(dir) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else {
            stats.failed += 1;
            continue;
        };
        for item in rd.flatten() {
            if stats.applied + stats.failed + stats.skipped + batch.len() >= max_objects {
                stats.truncated = true;
                break;
            }
            let Ok(ft) = item.file_type() else {
                stats.failed += 1;
                continue;
            };
            let path = item.path();
            let mut descend = ft.is_dir() && !ft.is_symlink();
            match prepare_child(ac_sid, &path, e, descend, &mut batch) {
                // Queued: the batch flush applies + journals it.
                Ok(true) => {}
                // Skipped (PROTECTED or null DACL): leave untouched and do
                // not descend — the subtree is outside this grant.
                Ok(false) => {
                    stats.skipped += 1;
                    descend = false;
                }
                Err(_) => stats.failed += 1,
            }
            if descend {
                stack.push(path);
            }
            if batch.len() >= PROPAGATE_BATCH {
                flush_batch(journal, &mut batch, &mut stats);
            }
        }
        if stats.truncated {
            break;
        }
    }
    flush_batch(journal, &mut batch, &mut stats);
    stats
}

/// Read one child's DACL and stage its write. Returns Ok(false) when the
/// child must be skipped WITHOUT a write and its subtree must not be
/// walked (PROTECTED DACL or null DACL).
fn prepare_child(
    ac_sid: &PSID,
    path: &std::path::Path,
    e: &AllowEntry,
    inheritable: bool,
    batch: &mut Vec<PendingChild>,
) -> Result<bool> {
    let path_str = path.to_string_lossy().to_string();
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

        let mut control: u16 = 0;
        let mut revision = 0u32;
        let dacl_protected = GetSecurityDescriptorControl(sd, &mut control, &mut revision).is_ok()
            && (control & SE_DACL_PROTECTED.0) != 0;
        if dacl_protected || dacl_ptr.is_null() {
            let _ = LocalFree(Some(HLOCAL(sd.0 as *mut _)));
            return Ok(false);
        }

        // Snapshot our trustee's explicit ACEs BEFORE mutating (same
        // contract as the root grant; restored by journal replay).
        let prior_aces = snapshot_prior_aces(dacl_ptr, ac_sid);
        let entry = JournalEntry {
            path: path_str.clone(),
            sid: sid_to_string(*ac_sid)?,
            granted_mask: e.access,
            deny: e.deny,
            protected: false,
            inherit: inheritable,
            prior_aces,
        };

        let ea = EXPLICIT_ACCESS_W {
            grfAccessPermissions: e.access,
            grfAccessMode: if e.deny { DENY_ACCESS } else { SET_ACCESS },
            grfInheritance: if inheritable {
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
        let set_r = SetEntriesInAclW(Some(&[ea]), Some(dacl_ptr as *const ACL), &mut new_acl);
        let _ = LocalFree(Some(HLOCAL(sd.0 as *mut _)));
        if set_r.is_err() {
            return Err(HRESULT::from_win32(set_r.0).into());
        }
        batch.push(PendingChild {
            path: path_str,
            entry,
            acl: new_acl,
        });
        Ok(true)
    }
}

/// Journal the whole batch, then apply it (journal-before-apply at batch
/// granularity). `apply_dacl_kernel` consumes (frees) every staged ACL.
fn flush_batch(
    journal: Option<&DaclJournal>,
    batch: &mut Vec<PendingChild>,
    stats: &mut PropagateStats,
) {
    if batch.is_empty() {
        return;
    }
    if let Some(j) = journal {
        let entries: Vec<JournalEntry> = batch.iter().map(|c| c.entry.clone()).collect();
        if let Err(err) = j.record_many(&entries) {
            // Matches grant_one's tolerance: a journal failure is a
            // warning; the run proceeds (teardown just won't restore this
            // batch, like an unjournaled grant).
            eprintln!(
                "[journal] WARN: record_many failed for {} children: {err}",
                entries.len()
            );
        }
    }
    for child in batch.drain(..) {
        match apply_dacl_kernel(&child.path, child.acl, false) {
            Ok(()) => stats.applied += 1,
            Err(_) => stats.failed += 1,
        }
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
                "[saife] warning: DACL restore failed; journal retained for retry at next start: {}",
                journal.path().display()
            );
            eprintln!("[saife]          {e:#}");
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
pub(crate) fn sid_to_string(sid: PSID) -> Result<String> {
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

/// Allocate the `privateNetworkClientServer` capability SID (`S-1-15-3-7`).
/// Returns a raw `PSID` that must be freed with `FreeSid` by the caller.
/// Returns `None` if the SID allocation fails (should not happen on any
/// supported Windows build).
pub(crate) fn allocate_private_network_capability_sid() -> Option<PSID> {
    let authority = SID_IDENTIFIER_AUTHORITY {
        Value: [0, 0, 0, 0, 0, 15],
    };
    let mut sid_ptr: PSID = PSID(std::ptr::null_mut());
    // S-1-15-3-7: authority 15 (security manager), 2 sub-authorities.
    // SubAuthority[0] = 3 (capability group), [1] = 7 (privateNetworkClientServer).
    let sub_authorities: [u32; 2] = [3, 7];
    unsafe {
        if AllocateAndInitializeSid(
            &authority,
            sub_authorities.len() as u8,
            sub_authorities[0],
            sub_authorities[1],
            0,
            0,
            0,
            0,
            0,
            0,
            &mut sid_ptr,
        )
        .is_ok()
        {
            Some(sid_ptr)
        } else {
            None
        }
    }
}

/// Build the child environment block: parent env + `PATH` prepended with
/// `.sandbox\<sid>\bin`, `PYTHONPATH` prepended with `.sandbox\<sid>\pyshim`
/// (the CPython 0o700-mkdir interposition — see sitecustomize.py), plus the
/// proxy env vars.
///
/// `TEMP`/`TMP` are NOT redirectable here: Windows rewrites them to the
/// AppContainer-private `%LOCALAPPDATA%\Packages\<ac>\AC\Temp` even when
/// an explicit environment block is passed (verified on build 26340 —
/// the child reported the rewritten values). Usability of that dir is
/// ensured by an inheritable allow-list grant on it instead
/// (see `build_allowlist`).
///
/// `proxy: Some(ProxyEnv)` injects `HTTP_PROXY`/`HTTPS_PROXY` with the proxy
/// URL containing userinfo (`http://sandbox:<token>@127.0.0.1:<port>`) so
/// standard HTTP clients auto-send `Proxy-Authorization: Basic`. Also sets
/// `SAIFE_PROXY_PORT` (for discoverability) and `NO_PROXY=localhost,127.0.0.1,::1`
/// so the child can reach intent endpoints directly (bypassing the proxy —
/// routing through it would loop).
/// `proxy: None` (block-net case) explicitly clears all four vars so a
/// parent shell's proxy settings don't leak into the sandboxed process.
pub fn build_env_block(sid: &str, cwd: &std::path::Path, proxy: Option<&ProxyEnv>) -> Vec<u16> {
    let bin_abs = cwd.join(format!(".sandbox\\{sid}\\bin"));
    let bin_path = bin_abs.to_string_lossy().to_string();
    let pyshim_path = cwd
        .join(format!(".sandbox\\{sid}\\pyshim"))
        .to_string_lossy()
        .to_string();

    // Decide the value (or absence) of the four proxy-related env vars.
    // `Some` → inject proxy URL (with userinfo), port, loopback NO_PROXY.
    // `None` → set all four to empty (override any inherited parent values).
    let (http_proxy, https_proxy, sandbox_proxy_port, no_proxy): (String, String, String, String) =
        match proxy {
            Some(p) => {
                // `RunToken`: the only way a credential reaches this format
                // string, so no unchecked string can become the URL's userinfo
                // (P1.6(c)).
                let proxy_url = format!("http://sandbox:{}@127.0.0.1:{}", p.token.value(), p.port);
                (
                    proxy_url.clone(),
                    proxy_url,
                    format!("{}", p.port),
                    "localhost,127.0.0.1,::1".to_string(),
                )
            }
            None => (String::new(), String::new(), String::new(), String::new()),
        };
    // Names of the four proxy vars, in the order we post-process them.
    // Comparison is case-insensitive (Windows env vars are case-insensitive).
    const PROXY_VARS: [&str; 4] = [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "SAIFE_PROXY_PORT",
        "NO_PROXY",
    ];

    let mut vars: Vec<(String, String)> = Vec::new();
    let mut path_overridden = false;
    let mut pythonpath_overridden = false;
    let mut session_sid_overridden = false;
    // Track which of the 4 proxy vars we've already emitted (by index) so we
    // can fill in any that were missing from the parent env afterwards.
    let mut proxy_seen = [false; 4];
    for (k, v) in std::env::vars() {
        if k.eq_ignore_ascii_case("PATH") {
            vars.push((k, format!("{};{}", bin_path, v)));
            path_overridden = true;
            continue;
        }
        if k.eq_ignore_ascii_case("PYTHONPATH") {
            vars.push((k, format!("{};{}", pyshim_path, v)));
            pythonpath_overridden = true;
            continue;
        }
        // Session marker for the pyshim's active mode (see sitecustomize.py):
        // survives child-side env sanitization (venv strips PYTHONPATH but
        // copies every other var). A nested saife run overrides it.
        if k.eq_ignore_ascii_case("SAIFE_SESSION_SID") {
            vars.push((k, sid.to_string()));
            session_sid_overridden = true;
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
                sandbox_proxy_port.clone(),
                no_proxy.clone(),
            ][idx]
                .clone();
            vars.push((k, replacement));
        } else {
            vars.push((k, v));
        }
    }
    if !path_overridden {
        vars.push(("PATH".to_string(), bin_path));
    }
    if !pythonpath_overridden {
        vars.push(("PYTHONPATH".to_string(), pyshim_path));
    }
    if !session_sid_overridden {
        vars.push(("SAIFE_SESSION_SID".to_string(), sid.to_string()));
    }
    // Append any proxy vars that were not present in the parent env.
    let proxy_values = [http_proxy, https_proxy, sandbox_proxy_port, no_proxy];
    for (idx, name) in PROXY_VARS.iter().enumerate() {
        if !proxy_seen[idx] {
            vars.push((name.to_string(), proxy_values[idx].clone()));
        }
    }

    // `CreateProcessW` requires the block to be sorted by name (Unicode order), and
    // callers that binary-search it - cmd.exe, some C runtimes - silently miss
    // entries when it is not. This block is built by appending PATH/PYTHONPATH/
    // SAIFE_SESSION_SID/proxy vars to the parent's list, so without this sort the
    // very variables the sandbox depends on were the ones a child could fail to find.
    vars.sort_by(|a, b| a.0.cmp(&b.0));

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
mod propagation_tests {
    use super::*;
    use crate::sandbox::allowlist::RWX;
    use crate::sandbox::dacl_journal::{DaclJournal, JournalHeader};
    use windows::Win32::Security::{
        ACE_HEADER, ACL_SIZE_INFORMATION, AclSizeInformation, GetAce, GetAclInformation,
    };

    // ACE type values with the Header/Mask/SidStart layout this helper
    // reads (the ACE_*_ACE_TYPE consts are not exported by windows-rs 0.62).
    const ACE_TYPE_ALLOWED: u8 = 0;
    const ACE_TYPE_DENIED: u8 = 1;

    const TEST_SID: &str = "S-1-15-2-3149-3149-3149";
    const DIR_INHERIT_FLAGS: u8 = 0x3; // SUB_CONTAINERS_AND_OBJECTS_INHERIT

    /// PSID from a SID string (leaks on purpose; tests are short-lived).
    fn make_sid(s: &str) -> PSID {
        let mut psid = PSID(std::ptr::null_mut());
        unsafe {
            ConvertStringSidToSidW(&HSTRING::from(s), &mut psid).unwrap();
        }
        psid
    }

    /// Removes the tree even when the test panics mid-way.
    struct TempDir(std::path::PathBuf);
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn tmp_tag(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("sbx-prop-{tag}-{}", std::process::id()))
    }

    /// All ACEs (explicit AND inherited) for `sid` on `path`: (mask, ace_flags).
    /// Walks the raw ACL — GetExplicitEntriesFromAclW misses inherited ACEs.
    fn trustee_ace_flags(path: &str, sid: &PSID) -> Vec<(u32, u8)> {
        unsafe {
            let path_w = HSTRING::from(path);
            let mut sd = PSECURITY_DESCRIPTOR::default();
            let mut dacl: *mut ACL = std::ptr::null_mut();
            let r = GetNamedSecurityInfoW(
                &path_w,
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                None,
                None,
                Some(&mut dacl),
                None,
                &mut sd,
            );
            assert!(r.is_ok(), "read DACL of {path}");
            let mut out = Vec::new();
            if !dacl.is_null() {
                let mut info = ACL_SIZE_INFORMATION::default();
                if GetAclInformation(
                    dacl,
                    (&mut info as *mut ACL_SIZE_INFORMATION) as *mut _,
                    std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
                    AclSizeInformation,
                )
                .is_ok()
                {
                    for i in 0..info.AceCount {
                        let mut ace: *mut core::ffi::c_void = std::ptr::null_mut();
                        if GetAce(dacl, i, &mut ace).is_err() {
                            continue;
                        }
                        let hdr = &*(ace as *const ACE_HEADER);
                        if hdr.AceType != ACE_TYPE_ALLOWED && hdr.AceType != ACE_TYPE_DENIED {
                            continue;
                        }
                        let mask = *((ace as *const u8).add(4) as *const u32);
                        let ace_sid = PSID((ace as *const u8).add(8) as *mut _);
                        if EqualSid(*sid, ace_sid).is_ok() {
                            out.push((mask, hdr.AceFlags));
                        }
                    }
                }
            }
            let _ = LocalFree(Some(HLOCAL(sd.0 as *mut _)));
            out
        }
    }

    /// Mark `path` as a PROTECTED-DACL dir owned by the current user
    /// (models "someone else's protected subtree" inside a granted tree).
    fn protect_dir(path: &str) {
        unsafe {
            let owner = current_user_sid().expect("current user SID");
            let ea = EXPLICIT_ACCESS_W {
                grfAccessPermissions: 0x1f01ff, // FILE_ALL_ACCESS
                grfAccessMode: SET_ACCESS,
                grfInheritance: SUB_CONTAINERS_AND_OBJECTS_INHERIT,
                Trustee: TRUSTEE_W {
                    TrusteeForm: TRUSTEE_IS_SID,
                    TrusteeType: TRUSTEE_IS_USER,
                    ptstrName: PWSTR(owner.0 as *mut _),
                    ..Default::default()
                },
            };
            let mut acl: *mut ACL = std::ptr::null_mut();
            let set_r = SetEntriesInAclW(Some(&[ea]), None, &mut acl);
            assert!(set_r.is_ok(), "SetEntriesInAclW: {set_r:?}");
            let named_r = SetNamedSecurityInfoW(
                &HSTRING::from(path),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                None,
                None,
                Some(acl as *const ACL),
                None,
            );
            assert!(named_r.is_ok(), "SetNamedSecurityInfoW: {named_r:?}");
            let _ = LocalFree(Some(HLOCAL(acl as *mut _)));
        }
    }

    fn test_entry(root: &std::path::Path) -> AllowEntry {
        AllowEntry {
            win32_path: root.to_path_buf(),
            access: RWX,
            label: "test".into(),
            deny: false,
            protected: false,
            inherit: true,
        }
    }

    #[test]
    fn should_propagate_matches_entry_semantics() {
        // Normal user tree with an inheritable grant: propagate.
        assert!(should_propagate(&test_entry(std::path::Path::new(
            r"C:\Users\u\proj"
        ))));
        // Non-inheritable (ancestor traverse) entries: no propagation.
        assert!(!should_propagate(&AllowEntry {
            inherit: false,
            ..test_entry(std::path::Path::new(r"C:\Users\u"))
        }));
        // PROTECTED rebuild entries (per-session dirs): no propagation.
        assert!(!should_propagate(&AllowEntry {
            protected: true,
            ..test_entry(std::path::Path::new(r"C:\Users\u\proj\.sandbox\sid"))
        }));
        // System32 / SystemRoot: never walked (huge, system-owned, and
        // already world-readable).
        let sysroot = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
        assert!(!should_propagate(&test_entry(
            &std::path::PathBuf::from(&sysroot).join("System32")
        )));
        assert!(!should_propagate(&test_entry(std::path::Path::new(
            &sysroot
        ))));
    }

    #[test]
    fn grant_propagates_to_pre_existing_descendants_and_stops_at_protected() {
        let sid = make_sid(TEST_SID);
        let base = tmp_tag("main");
        let _guard = TempDir(base.clone());
        let root = base.join("root");
        std::fs::create_dir_all(root.join("sub")).unwrap();
        std::fs::create_dir_all(root.join("prot").join("deeper")).unwrap();
        std::fs::write(root.join("a.txt"), b"a").unwrap();
        std::fs::write(root.join("sub").join("b.txt"), b"b").unwrap();
        std::fs::write(root.join("prot").join("deeper").join("d.txt"), b"d").unwrap();
        protect_dir(root.join("prot").to_string_lossy().as_ref());

        let journal = DaclJournal::open(
            &base.join("journal"),
            JournalHeader {
                run_id: format!("r{}", std::process::id()),
                owner_pid: std::process::id(),
                owner_created: 0,
            },
        )
        .unwrap();

        grant_access(&sid, &[test_entry(&root)], Some(&journal)).unwrap();

        // Files: synchronous, non-inheritable ACE with the granted mask.
        let a = trustee_ace_flags(&root.join("a.txt").to_string_lossy(), &sid);
        assert!(!a.is_empty(), "a.txt ACE must exist right after grant");
        assert_eq!(a[0].0, RWX, "a.txt mask must match the grant");
        assert_eq!(a[0].1, 0, "file ACEs are non-inheritable: {:?}", a);
        // Subdirs: inheritable ACE so future files inherit at creation.
        let sub = trustee_ace_flags(&root.join("sub").to_string_lossy(), &sid);
        assert!(
            !sub.is_empty() && (sub[0].1 & DIR_INHERIT_FLAGS) == DIR_INHERIT_FLAGS,
            "sub dir ACE must be inheritable: {sub:?}"
        );
        let b = trustee_ace_flags(&root.join("sub").join("b.txt").to_string_lossy(), &sid);
        assert!(!b.is_empty(), "nested file ACE must exist: {b:?}");
        assert_eq!(b[0].1, 0, "nested file ACE non-inheritable: {b:?}");
        // PROTECTED subtree: untouched, including its descendants.
        assert!(
            trustee_ace_flags(&root.join("prot").to_string_lossy(), &sid).is_empty(),
            "PROTECTED dir must not receive the session ACE"
        );
        assert!(
            trustee_ace_flags(
                &root
                    .join("prot")
                    .join("deeper")
                    .join("d.txt")
                    .to_string_lossy(),
                &sid
            )
            .is_empty(),
            "PROTECTED subtree descendants must not be walked"
        );

        // Teardown via the journal leaves no session ACEs anywhere.
        assert!(restore_or_warn(&journal), "journal replay must succeed");
        for p in [
            root.clone(),
            root.join("a.txt"),
            root.join("sub"),
            root.join("sub").join("b.txt"),
        ] {
            assert!(
                trustee_ace_flags(&p.to_string_lossy(), &sid).is_empty(),
                "no session ACEs may survive teardown on {p:?}"
            );
        }
    }

    #[test]
    fn propagation_respects_cap_and_reports_truncation() {
        let sid = make_sid(TEST_SID);
        let base = tmp_tag("cap");
        let _guard = TempDir(base.clone());
        let root = base.join("root");
        std::fs::create_dir_all(&root).unwrap();
        let files: Vec<std::path::PathBuf> = (0..10)
            .map(|i| {
                let p = root.join(format!("f{i}.txt"));
                std::fs::write(&p, b"x").unwrap();
                p
            })
            .collect();

        let stats = propagate_grant(&sid, &test_entry(&root), None, 4);
        assert!(stats.truncated, "cap must report truncation: {stats:?}");
        assert_eq!(stats.applied, 4, "exactly the cap in applied writes");
        assert_eq!(stats.failed, 0);
        let with_ace = files
            .iter()
            .filter(|f| !trustee_ace_flags(&f.to_string_lossy(), &sid).is_empty())
            .count();
        assert_eq!(with_ace, 4, "only the first 4 visited files carry the ACE");
    }
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
    fn env_block_prepends_path_and_clears_proxy_vars() {
        let sid = "testsid";
        let cwd = std::path::Path::new(r"C:\some\cwd");
        let vars = decode(&build_env_block(sid, cwd, None));
        let get = |name: &str| {
            vars.iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.clone())
                .expect("env var present")
        };
        assert!(
            get("PATH").starts_with(r"C:\some\cwd\.sandbox\testsid\bin;"),
            "PATH prepended with session bin dir: {}",
            get("PATH")
        );
        assert!(
            get("PYTHONPATH").starts_with(r"C:\some\cwd\.sandbox\testsid\pyshim"),
            "PYTHONPATH prepended with session pyshim dir: {}",
            get("PYTHONPATH")
        );
        // Block-net mode (proxy: None) clears the proxy vars.
        assert_eq!(get("HTTP_PROXY"), "");
        assert_eq!(get("NO_PROXY"), "");
        // Session marker: gates the pyshim's active mode and survives
        // child-side env sanitization (venv strips PYTHONPATH but copies
        // every other var).
        assert_eq!(get("SAIFE_SESSION_SID"), "testsid");
    }

    /// P1.6(c): the proxy variables carry *this run's* typed credential.
    ///
    /// Before the typing, `ProxyEnv::token` was a bare `String` and this
    /// interpolation had no check at all: whatever string reached the field became
    /// the URL's userinfo, where `@` ends the userinfo early and `/` ends the
    /// authority - so an unsafe value points the child at a different host or port
    /// than the supervisor bound and then proves (`mxc::proxy_url` has always
    /// refused such a value; this edge only had a `String`). The field is a
    /// [`RunToken`] now, so this test can only be written with a credential, and
    /// the charset assertion below is what makes that typing worth something.
    #[test]
    fn proxy_env_carries_the_runs_own_token_in_the_url() {
        let token = crate::net::token::RunToken::issue().expect("mint a token");
        assert!(
            token
                .value()
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | '~')),
            "a RunToken must stay URL-unreserved, or typing the field buys nothing: {}",
            token.value()
        );
        let proxy = ProxyEnv {
            port: 49_152,
            token: token.clone(),
        };
        let vars = decode(&build_env_block(
            "testsid",
            std::path::Path::new(r"C:\some\cwd"),
            Some(&proxy),
        ));
        let get = |name: &str| {
            vars.iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.clone())
                .expect("env var present")
        };
        let want = format!("http://sandbox:{}@127.0.0.1:49152", token.value());
        assert_eq!(get("HTTP_PROXY"), want);
        assert_eq!(
            get("HTTPS_PROXY"),
            want,
            "both proxy vars carry the same URL"
        );
        assert_eq!(get("SAIFE_PROXY_PORT"), "49152");
        assert_eq!(get("NO_PROXY"), "localhost,127.0.0.1,::1");
    }
}

#[test]
fn private_network_capability_sid_is_s_1_15_3_7() {
    let sid = allocate_private_network_capability_sid().expect("SID allocation should succeed");
    unsafe {
        let mut pwstr = PWSTR::null();
        assert!(ConvertSidToStringSidW(sid, &mut pwstr).is_ok());
        let s = pwstr.to_string().unwrap();
        assert_eq!(s, "S-1-15-3-7");
        let _ = LocalFree(Some(HLOCAL(pwstr.0 as *mut _)));
        let _ = FreeSid(sid);
    }
}
