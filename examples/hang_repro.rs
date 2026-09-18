//! hang_repro — isolated repro for a suspected hang in `SetEntriesInAclW`.
//!
//! Mirrors `grant_one()` in `src/sandbox/appcontainer.rs` (non-protected path):
//!   1. GetNamedSecurityInfoW        -> current DACL of the target path
//!   2. SetEntriesInAclW             -> old DACL + one new SET_ACCESS ACE
//!   3. SetNamedSecurityInfoW       -> write the merged DACL back (SKIPPED
//!      in default dry-run mode)
//!
//! Usage:
//!   hang_repro.exe                 dry-run: steps 1+2 only, DACL NOT modified
//!   hang_repro.exe --apply         actually write the DACL (dangerous, see
//!                                  below). A rollback .cmd script is written
//!                                  BEFORE any change, per AGENTS.md rules.
//!
//! The ACE targets the base AppContainer SID S-1-15-2-1 which does not match
//! any real sandbox session — adding it is harmless (no process runs under
//! that SID), and `--apply` is rolled back via the generated script or
//!   icacls <path> /remove "APPLICATION PACKAGE AUTHORITY\..." S-1-15-2-1
//! (the rollback script uses the SID form, which always works).

use windows::Win32::Foundation::*;
use windows::Win32::Security::Authorization::*;
use windows::Win32::Security::*;
use windows::core::*;

const TARGET_PATH: &str = r"C:\Users\marku\AppData\Local";
const TEST_SID: &str = "S-1-15-2-1";

fn main() -> Result<()> {
    let apply = std::env::args().any(|a| a == "--apply");
    let dry_run = !apply;
    println!("[hang_repro] mode = {}", if dry_run { "DRY-RUN" } else { "APPLY" });
    println!("[hang_repro] target = {TARGET_PATH}");
    fflush();

    let path_w = HSTRING::from(TARGET_PATH);
    let sid_w: Vec<u16> = TEST_SID.encode_utf16().chain(std::iter::once(0)).collect();

    unsafe {
        // --- Resolve the test SID string to a PSID -------------------------
        println!("[1/5] ConvertStringSidToSidW({TEST_SID}) ...");
        fflush();
        let mut ac_sid = PSID::default();
        ConvertStringSidToSidW(PCWSTR(sid_w.as_ptr()), &mut ac_sid)?;
        println!("      ok, sid = {:p}", ac_sid.0);
        fflush();

        // --- Step 1: GetNamedSecurityInfoW ---------------------------------
        // Mirrors grant_one(): reads the current DACL + owning security
        // descriptor.
        println!("[2/5] GetNamedSecurityInfoW ...");
        fflush();
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
        println!("      ok, dacl = {:p}, sd = {:p}", dacl_ptr, sd.0);
        fflush();

        // --- Step 2: build EXPLICIT_ACCESS_W --------------------------------
        // Same args as grant_one(): FILE_ALL_ACCESS mask, SET_ACCESS,
        // SUB_CONTAINERS_AND_OBJECTS_INHERIT, trustee = AppContainer SID.
        println!("[3/5] building EXPLICIT_ACCESS_W (mask=0x1f01ff, SET_ACCESS, SUB_CONTAINERS_AND_OBJECTS_INHERIT)");
        fflush();
        let ea = EXPLICIT_ACCESS_W {
            grfAccessPermissions: 0x1f01ff,
            grfAccessMode: SET_ACCESS,
            grfInheritance: SUB_CONTAINERS_AND_OBJECTS_INHERIT,
            Trustee: TRUSTEE_W {
                TrusteeForm: TRUSTEE_IS_SID,
                TrusteeType: TRUSTEE_IS_GROUP,
                ptstrName: PWSTR(ac_sid.0 as *mut _),
                ..Default::default()
            },
        };

        // --- Step 3: SetEntriesInAclW ---------------------------------------
        // The suspected hang site. EXACT same call pattern as grant_one().
        let old_acl_opt = if dacl_ptr.is_null() {
            None
        } else {
            Some(dacl_ptr as *const ACL)
        };
        let mut new_acl: *mut ACL = std::ptr::null_mut();
        println!("[4/5] SetEntriesInAclW(Some(&[ea]), {old_acl_opt:?}, &mut new_acl) ... <<< suspected hang point");
        fflush();
        let set_r = SetEntriesInAclW(Some(&[ea]), old_acl_opt, &mut new_acl);
        println!("      RETURNED (no hang). result = {set_r:?}, new_acl = {new_acl:p}");
        fflush();
        let _ = LocalFree(Some(HLOCAL(sd.0 as *mut _)));
        if set_r.is_err() {
            return Err(HRESULT::from_win32(set_r.0).into());
        }

        // --- Step 4: SetNamedSecurityInfoW (apply mode only) ----------------
        if dry_run {
            println!("[5/5] SKIPPED SetNamedSecurityInfoW (dry-run). DACL of {TARGET_PATH} NOT modified.");
            fflush();
        } else {
            // AGENTS.md: write a rollback script BEFORE changing anything.
            let rollback = std::env::current_dir()?.join("hang_repro_rollback.cmd");
            std::fs::write(
                &rollback,
                format!(
                    "@echo off\r\nrem Rollback for hang_repro --apply: removes the S-1-15-2-1 ACE\r\nicacls \"{TARGET_PATH}\" /remove *{TEST_SID}\r\n"
                ),
            )
            .expect("failed to write rollback script");
            println!("[5/5] rollback script written: {}", rollback.display());
            println!("      calling SetNamedSecurityInfoW(DACL | UNPROTECTED_DACL) ...");
            fflush();
            let flags = DACL_SECURITY_INFORMATION | UNPROTECTED_DACL_SECURITY_INFORMATION;
            let write_r = SetNamedSecurityInfoW(
                &path_w,
                SE_FILE_OBJECT,
                flags,
                None,
                None,
                Some(new_acl),
                None,
            );
            if write_r.is_err() {
                return Err(HRESULT::from_win32(write_r.0).into());
            }
            println!("      ok. ACE for {TEST_SID} added to {TARGET_PATH}.");
            println!("      To roll back, run: {}", rollback.display());
            fflush();
        }
        let _ = LocalFree(Some(HLOCAL(new_acl as *mut _)));
    }

    println!("[hang_repro] DONE — all calls completed.");
    Ok(())
}

fn fflush() {
    use std::io::Write;
    let _ = std::io::stdout().flush();
}
