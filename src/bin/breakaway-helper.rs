use windows::Win32::Foundation::*;
use windows::Win32::System::Threading::*;
use windows::core::*;

fn main() {
    if std::env::args().nth(1).as_deref() == Some("--child") {
        return;
    }

    let exe = std::env::current_exe().expect("get current exe path");
    let child_cmd = format!("{} --child", quote(&exe.to_string_lossy()));

    let mut cmdw: Vec<u16> = child_cmd.encode_utf16().chain(std::iter::once(0)).collect();
    let mut si: STARTUPINFOW = unsafe { std::mem::zeroed() };
    si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

    let result = unsafe {
        CreateProcessW(
            PCWSTR::null(),
            Some(PWSTR(cmdw.as_mut_ptr())),
            None,
            None,
            false,
            CREATE_BREAKAWAY_FROM_JOB,
            None,
            PCWSTR::null(),
            &si,
            &mut pi,
        )
    };

    match result {
        Ok(_) => {
            unsafe {
                let _ = WaitForSingleObject(pi.hProcess, INFINITE);
                let _ = CloseHandle(pi.hThread);
                let _ = CloseHandle(pi.hProcess);
            }
            println!("CREATEPROCESS_OK");
        }
        Err(_) => {
            let code = unsafe { GetLastError().0 };
            println!("CREATEPROCESS_FAILED {}", code);
        }
    }
}

fn quote(s: &str) -> String {
    if s.contains(' ') {
        format!("\"{}\"", s)
    } else {
        s.to_string()
    }
}
