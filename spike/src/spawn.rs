use windows::Win32::Foundation::*;
use windows::Win32::Security::SECURITY_CAPABILITIES;
use windows::Win32::System::Threading::*;
use windows::core::*;

use crate::appcontainer::AppContainerSession;
use crate::job::Job;

/// Spawn `cmdline` under the AppContainer SID + Job Object.
///
/// stdout/stderr/stdin are inherited from the spike process so output flows
/// straight through to the test harness. Returns the child's exit code.
pub fn spawn(
    session: &AppContainerSession,
    job: &Job,
    cwd: &std::path::Path,
    env_block: Vec<u16>,
    cmdline: &str,
) -> Result<u32> {
    let mut cmdw: Vec<u16> = cmdline.encode_utf16().chain(std::iter::once(0)).collect();

    unsafe {
        // 1. Size the attribute list (2 attributes).
        let mut list_size: usize = 0;
        let _ = InitializeProcThreadAttributeList(None, 2, Some(0), &mut list_size);
        if list_size == 0 {
            return Err(HRESULT::from_win32(GetLastError().0).into());
        }

        let mut attr_buf: Vec<u8> = vec![0u8; list_size];
        let attr_list = LPPROC_THREAD_ATTRIBUTE_LIST(attr_buf.as_mut_ptr() as *mut _);

        InitializeProcThreadAttributeList(Some(attr_list), 2, Some(0), &mut list_size)?;

        // JOB_LIST attribute: pointer to an array of one job HANDLE.
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

        // SECURITY_CAPABILITIES attribute: makes the child an AppContainer
        // process. The struct holds the AppContainer SID + capability list
        // (we pass no capability SIDs — just the AppContainer SID for
        // default-deny isolation).
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
            false, // bInheritHandles — do NOT inherit arbitrary handles
            CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT,
            Some(env_block.as_ptr() as *const _),
            &cwd_w,
            &mut si.StartupInfo as *mut _ as *mut STARTUPINFOW,
            &mut pi,
        );

        // Free the attribute list regardless of result.
        DeleteProcThreadAttributeList(attr_list);

        if let Err(e) = result {
            if std::env::var_os("SPIKE_DIAG").is_some() {
                eprintln!("[spawn] CreateProcessW failed: {e}");
            }
            return Err(e);
        }

        // Wait for the child to exit.
        let _ = WaitForSingleObject(pi.hProcess, INFINITE);

        let mut exit_code: u32 = 0;
        let _ = GetExitCodeProcess(pi.hProcess, &mut exit_code);

        let _ = CloseHandle(pi.hThread);
        let _ = CloseHandle(pi.hProcess);

        Ok(exit_code)
    }
}
