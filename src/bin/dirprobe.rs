//! Diagnostic binary: probes which Win32 calls `cmd /c dir` depends on fail
//! under the AppContainer. Run inside the sandbox:
//!   sandbox run --allow-cwd -- dirprobe

use windows::Win32::Foundation::{CloseHandle, ERROR_SUCCESS, GetLastError, HANDLE};
use windows::Win32::Storage::FileSystem::{
    FindFirstFileW, FindNextFileW, GetFileAttributesW, FILE_ATTRIBUTE_DIRECTORY,
    WIN32_FIND_DATAW,
};
use windows::core::PCWSTR;

fn report(name: &str, ok: bool, code: u32) {
    let status = if ok { "OK" } else { "FAIL" };
    println!("PROBE {name} {status} 0x{code:08x}");
}

fn drain(h: HANDLE) {
    let mut data = WIN32_FIND_DATAW::default();
    unsafe {
        while FindNextFileW(h, &mut data).is_ok() {}
        let _ = CloseHandle(h);
    }
}

fn probe_findfirst(label: &str, pat_utf16: &[u16]) {
    let mut data = WIN32_FIND_DATAW::default();
    let r = unsafe { FindFirstFileW(PCWSTR(pat_utf16.as_ptr()), &mut data) };
    match r {
        Ok(h) => {
            report(label, true, 0);
            drain(h);
        }
        Err(e) => report(label, false, e.code().0 as u32),
    }
}

fn probe_volume_info(label: &str, root: &str) {
    // GetVolumeInformationW requires a trailing backslash on the root path
    // (e.g. "C:\") and a trailing backslash on a directory path (e.g.
    // "C:\path\"). Normalize: ensure exactly one trailing backslash.
    let mut s: String = root.trim_end_matches('\\').to_string();
    s.push('\\');
    let mut w: Vec<u16> = s.encode_utf16().collect();
    w.push(0);
    let mut name = [0u16; 260];
    let mut serial = 0u32;
    let mut max_len = 0u32;
    let mut flags = 0u32;
    let mut fsname = [0u16; 260];
    // GetVolumeInformationW lives in Win32_System_WindowsProgramming or
    // Win32_Storage_FileSystem depending on windows-rs version. Use the
    // file-system path via the System::WindowsProgramming feature is not
    // enabled, so call through the Storage::FileSystem re-export if present,
    // otherwise fall back to a direct extern.
    unsafe extern "system" {
        fn GetVolumeInformationW(
            lprootpathname: PCWSTR,
            lpvolumenamebuffer: *mut u16,
            nvolumenamesize: u32,
            lpvolumeserialnumber: *mut u32,
            lpmaximumcomponentlength: *mut u32,
            lpfilesystemflags: *mut u32,
            lpfilesystemnamebuffer: *mut u16,
            nfilesystemnamesize: u32,
        ) -> i32;
    }
    let ok = unsafe {
        GetVolumeInformationW(
            PCWSTR(w.as_ptr()),
            name.as_mut_ptr(),
            name.len() as u32,
            &mut serial,
            &mut max_len,
            &mut flags,
            fsname.as_mut_ptr(),
            fsname.len() as u32,
        )
    };
    if ok != 0 {
        report(label, true, ERROR_SUCCESS.0);
    } else {
        report(label, false, unsafe { GetLastError() }.0);
    }
}

fn cwd_abs() -> Vec<u16> {
    // GetCurrentDirectoryW is in Win32_System_WindowsProgramming; call via extern.
    unsafe extern "system" {
        fn GetCurrentDirectoryW(nbufferlength: u32, lpbuffer: *mut u16) -> u32;
    }
    let mut buf = [0u16; 1024];
    let n = unsafe { GetCurrentDirectoryW(buf.len() as u32, buf.as_mut_ptr()) };
    if n == 0 || n as usize > buf.len() {
        return Vec::new();
    }
    buf[..n as usize].to_vec()
}

fn cwd_drive_root() -> String {
    let abs = cwd_abs();
    if abs.len() >= 2 && abs[1] == b':' as u16 {
        // drive letter (without colon) + ":\"
        let drive_letter: String = (abs[..1])
            .iter()
            .map(|&c| char::from_u32(c as u32).unwrap_or('?'))
            .collect();
        format!("{drive_letter}:\\")
    } else {
        String::from("C:\\")
    }
}

fn main() {
    let abs = cwd_abs();
    let abs_str: String = abs
        .iter()
        .take_while(|&&c| c != 0)
        .map(|&c| char::from_u32(c as u32).unwrap_or('?'))
        .collect();
    println!("CWD abs = {abs_str}");

    // Pattern: "*" relative to cwd
    let star: Vec<u16> = "*\0".encode_utf16().collect();
    probe_findfirst("FindFirstFileW(*) cwd", &star);

    // Pattern: "./*"
    let dotstar: Vec<u16> = "./*\0".encode_utf16().collect();
    probe_findfirst("FindFirstFileW(./*)", &dotstar);

    // Pattern: "<abs-cwd>\*"
    if !abs.is_empty() {
        // ensure no nul in the middle
        let mut p: Vec<u16> = abs.iter().take_while(|&&c| c != 0).copied().collect();
        if !p.is_empty() && p[p.len() - 1] != b'\\' as u16 {
            p.push(b'\\' as u16);
        }
        p.push(b'*' as u16);
        p.push(0);
        probe_findfirst("FindFirstFileW(<abs-cwd>\\*)", &p);
    }

    // Volume info on the cwd's drive root.
    let root = cwd_drive_root();
    probe_volume_info(&format!("GetVolumeInformationW({root})"), &root);

    // Volume info on the cwd path itself (does it work on a non-root path?).
    probe_volume_info(&format!("GetVolumeInformationW({abs_str})"), &abs_str);

    // Sanity: is the cwd a directory?
    let mut attr_path = abs.clone();
    if !attr_path.ends_with(&[0]) {
        attr_path.push(0);
    }
    let attrs = unsafe { GetFileAttributesW(PCWSTR(attr_path.as_ptr())) };
    let is_dir = attrs != u32::MAX && (attrs & FILE_ATTRIBUTE_DIRECTORY.0) != 0;
    report("cwd is directory", is_dir, 0);
}
