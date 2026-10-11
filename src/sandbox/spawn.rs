use windows::Win32::Foundation::*;
use windows::Win32::Security::SECURITY_CAPABILITIES;
use windows::Win32::System::Threading::*;
use windows::core::*;

use crate::sandbox::appcontainer::AppContainerSession;
use crate::sandbox::job::Job;

/// Set the child's token owner to the token's user SID.
///
/// S-9 root cause: CPython's `os.mkdir(path, 0o700)` — used by
/// `tempfile.mkdtemp` (venv/ensurepip/pip staging) — creates the dir with a
/// protected DACL `D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;OW)`.
/// Only the OWNER RIGHTS (`OW`) ACE can authorize the sandboxed process,
/// and it resolves to the object owner, which the child takes from its
/// token owner — Administrators for admin users. In an AppContainer token
/// the Administrators SID cannot satisfy allow ACEs, so the dir denies its
/// own creator (proven in-VM: 0o700 dirs deny scandir+write while 0o600
/// dirs with an inherited user-SID ACE work fine — the user SID CAN
/// satisfy allow ACEs).
///
/// Setting the token owner to the user SID makes `OW` resolve to a SID the
/// process can use — and restores the standard-user semantics under which
/// venv/pip work unsandboxed (for standard users the token owner already
/// is the user). Assigning the user SID is legal for `SetTokenInformation`
/// because it is present in the token; the AppContainer SID is not
/// (ERROR_INVALID_OWNER 0x8007051B, verified on the host).
///
/// Security note: the owner change also grants implicit owner rights
/// (READ_CONTROL/WRITE_DAC) on user-owned objects, but those are gated by
/// the mandatory integrity label (the child runs Low IL and cannot write
/// Medium-labeled objects) and by path traversal, exactly like every
/// other write the child attempts.
///
/// Called on the suspended child right after CreateProcessW; the caller
/// resumes the thread afterwards regardless of the outcome (the fixup is
/// non-fatal: without it everything works except 0o700-mode mkdir dirs).
fn set_child_token_owner_to_user(child: HANDLE) -> Result<()> {
    use windows::Win32::Security::{
        GetTokenInformation, SetTokenInformation, TOKEN_ADJUST_DEFAULT, TOKEN_OWNER, TOKEN_QUERY,
        TOKEN_USER, TokenOwner, TokenUser,
    };
    use windows::Win32::System::Threading::OpenProcessToken;
    let mut token = HANDLE::default();
    unsafe {
        OpenProcessToken(child, TOKEN_QUERY | TOKEN_ADJUST_DEFAULT, &mut token)?;
        let r = (|| -> Result<()> {
            let mut needed: u32 = 0;
            let _ = GetTokenInformation(token, TokenUser, None, 0, &mut needed);
            if needed == 0 {
                return Err(HRESULT::from_win32(GetLastError().0).into());
            }
            let mut buf = vec![0u8; needed as usize];
            GetTokenInformation(
                token,
                TokenUser,
                Some(buf.as_mut_ptr() as *mut _),
                needed,
                &mut needed,
            )?;
            // The SID lives inside `buf`; keep `buf` alive until the
            // SetTokenInformation call below has copied it out.
            let user = &*(buf.as_ptr() as *const TOKEN_USER);
            let owner = TOKEN_OWNER {
                Owner: user.User.Sid,
            };
            SetTokenInformation(
                token,
                TokenOwner,
                &owner as *const TOKEN_OWNER as *const core::ffi::c_void,
                std::mem::size_of::<TOKEN_OWNER>() as u32,
            )
        })();
        let _ = CloseHandle(token);
        r
    }
}

/// Spawn `cmdline` under the AppContainer SID + Job Object.
///
/// stdout/stderr/stdin are inherited from the supervisor so output flows
/// straight through. Returns the child's exit code.
pub fn spawn(
    session: &AppContainerSession,
    job: &Job,
    cwd: &std::path::Path,
    env_block: Vec<u16>,
    cmdline: &str,
) -> Result<u32> {
    let mut cmdw: Vec<u16> = cmdline.encode_utf16().chain(std::iter::once(0)).collect();

    unsafe {
        let mut list_size: usize = 0;
        let _ = InitializeProcThreadAttributeList(None, 2, Some(0), &mut list_size);
        if list_size == 0 {
            return Err(HRESULT::from_win32(GetLastError().0).into());
        }

        let mut attr_buf: Vec<u8> = vec![0u8; list_size];
        let attr_list = LPPROC_THREAD_ATTRIBUTE_LIST(attr_buf.as_mut_ptr() as *mut _);

        InitializeProcThreadAttributeList(Some(attr_list), 2, Some(0), &mut list_size)?;

        let mut job_handles = [job.handle];
        UpdateProcThreadAttribute(
            attr_list,
            0,
            PROC_THREAD_ATTRIBUTE_JOB_LIST as usize,
            Some(job_handles.as_mut_ptr() as *const _),
            std::mem::size_of_val(&job_handles),
            None,
            None,
        )?;

        let mut sec_caps = SECURITY_CAPABILITIES {
            AppContainerSid: session.ac_sid,
            Capabilities: std::ptr::null_mut(),
            CapabilityCount: 0,
            Reserved: 0,
        };
        UpdateProcThreadAttribute(
            attr_list,
            0,
            PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES as usize,
            Some(&mut sec_caps as *mut _ as *const _),
            std::mem::size_of::<SECURITY_CAPABILITIES>(),
            None,
            None,
        )?;

        let mut si = STARTUPINFOEXW {
            StartupInfo: STARTUPINFOW {
                cb: std::mem::size_of::<STARTUPINFOEXW>() as u32,
                ..Default::default()
            },
            lpAttributeList: attr_list,
        };

        let cwd_w = HSTRING::from(cwd);

        let mut pi = PROCESS_INFORMATION::default();
        let result = CreateProcessW(
            PCWSTR::null(),
            Some(PWSTR(cmdw.as_mut_ptr())),
            None,
            None,
            false,
            CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED,
            Some(env_block.as_ptr() as *const _),
            &cwd_w,
            &mut si.StartupInfo as *mut _,
            &mut pi,
        );

        DeleteProcThreadAttributeList(attr_list);

        if let Err(e) = result {
            if std::env::var_os("SANDBOX_DIAG").is_some() {
                eprintln!("[spawn] CreateProcessW failed: {e}");
            }
            return Err(e);
        }

        // Token-owner fixup while the child is suspended (see
        // set_child_token_owner_to_user). Non-fatal by design: log under
        // SANDBOX_DIAG, but always resume the child either way.
        if let Err(e) = set_child_token_owner_to_user(pi.hProcess)
            && std::env::var_os("SANDBOX_DIAG").is_some()
        {
            eprintln!("[spawn] token-owner fixup failed (continuing): {e}");
        }
        let _ = ResumeThread(pi.hThread);

        let _ = WaitForSingleObject(pi.hProcess, INFINITE);

        let mut exit_code: u32 = 0;
        let _ = GetExitCodeProcess(pi.hProcess, &mut exit_code);

        let _ = CloseHandle(pi.hThread);
        let _ = CloseHandle(pi.hProcess);

        Ok(exit_code)
    }
}
