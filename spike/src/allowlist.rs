use windows::Win32::Foundation::*;
use windows::Win32::Storage::FileSystem::*;
use windows::core::*;

/// One entry in the hard-coded Option E allow-list.
pub struct AllowEntry {
    /// NT device path (for documentation / future RuleSet API use).
    #[allow(dead_code)]
    pub nt_path: String,
    pub win32_path: std::path::PathBuf,
    pub access: u32,
    pub label: &'static str,
    /// If true, this is a Deny ACE (deny the access) rather than an Allow.
    pub deny: bool,
    /// If true, write the DACL with PROTECTED_DACL_SECURITY_INFORMATION so the
    /// object does NOT inherit ACEs from its parent. Used for the per-session
    /// subtree so the broad `$CWD` Allow doesn't leak into sibling session
    /// dirs (per-session isolation, S-13).
    pub protected: bool,
}

pub const RWX: u32 = FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0 | FILE_GENERIC_EXECUTE.0;
pub const RW: u32 = FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0;
pub const RX: u32 = FILE_GENERIC_READ.0 | FILE_GENERIC_EXECUTE.0;

/// Resolve a Win32 path (e.g. `C:\foo`) to its NT device path
/// (`\Device\HarddiskVolume4\foo`) via `QueryDosDeviceW`.
pub fn to_nt_path(win32: &std::path::PathBuf) -> Result<String> {
    let mut win32_clean = win32.clone();
    while win32_clean.to_string_lossy().ends_with('\\') && win32_clean.parent().is_some() {
        win32_clean = win32_clean.parent().unwrap().to_path_buf();
    }
    let s = win32_clean.to_string_lossy().to_uppercase();
    let drive = if s.len() >= 2 && s.as_bytes()[1] == b':' {
        &s[..2]
    } else {
        return Ok(win32_clean.to_string_lossy().replace('/', "\\"));
    };
    let rest = if s.len() > 3 { &s[3..] } else { "" };
    let mut dev_buf = [0u16; 520];
    let drive_w = HSTRING::from(drive);
    let n = unsafe { QueryDosDeviceW(&drive_w, Some(&mut dev_buf)) };
    if n == 0 {
        return Err(HRESULT::from_win32(unsafe { GetLastError().0 }).into());
    }
    let dev = String::from_utf16_lossy(&dev_buf[..n as usize])
        .trim_end_matches('\0')
        .to_string();
    if rest.is_empty() {
        Ok(dev)
    } else {
        Ok(format!("{}\\{}", dev, rest))
    }
}

/// Resolve `python.exe` on PATH and return its containing directory.
pub fn find_python_dir() -> Option<std::path::PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join("python.exe");
        if candidate.is_file() {
            // Return the dir as-is (avoid canonicalize's \\?\ prefix which
            // some Win32 APIs reject).
            return Some(dir);
        }
    }
    None
}

/// Build the Option E allow-list for a given session id + cwd.
///
/// Per-session isolation (S-13): the `.sandbox\<sid>` subtree is granted to
/// the session's AppContainer SID with a **PROTECTED_DACL** — it does NOT
/// inherit the broad `$CWD` Allow. So session B's AppContainer SID, which
/// has an Allow on `$CWD` (inherited), does NOT get an Allow on session A's
/// `.sandbox\<sidA>` subtree. Each session's subtree is an isolated island.
/// The owning session's AppContainer SID is the only one granted there.
pub fn build(sid: &str, cwd: &std::path::PathBuf) -> Vec<AllowEntry> {
    let mut entries = Vec::new();

    // $CWD: broad RWX for the project tree, inheritable. This does NOT reach
    // the per-session subtrees because they are PROTECTED (see below).
    push_entry(&mut entries, cwd.clone(), RWX, "$CWD", false, false);
    // .sandbox itself: the AppContainer SID needs Execute (traverse) to reach
    // its own subtree, but no read of sibling subtrees. Grant minimal RX here
    // (inheritable, but the per-session subtrees are protected so inheritance
    // stops at their boundary). This lets the owning session list/traverse
    // .sandbox to reach .sandbox\<sid> without being able to read siblings.
    push_entry(&mut entries, cwd.join(".sandbox"), RX, ".sandbox", false, false);
    // The per-session subtree: PROTECTED so it inherits nothing from $CWD /
    // .sandbox. Only this session's AppContainer SID is granted (RWX). Other
    // sessions' AppContainer SIDs have no ACE here → denied by default.
    push_entry(
        &mut entries,
        cwd.join(".sandbox").join(sid),
        RWX,
        ".sandbox/<sid>",
        false,
        true,
    );
    push_entry(
        &mut entries,
        cwd.join(".sandbox").join(sid).join("bin"),
        RWX,
        ".sandbox/bin",
        false,
        true,
    );
    push_entry(
        &mut entries,
        cwd.join(".sandbox").join(sid).join("venv"),
        RWX,
        ".sandbox/venv",
        false,
        true,
    );

    if let Some(pydir) = find_python_dir() {
        push_entry(&mut entries, pydir, RX, "python", false, false);
    }

    if let Ok(sysroot) = std::env::var("SystemRoot") {
        push_entry(
            &mut entries,
            std::path::PathBuf::from(&sysroot).join("System32"),
            RX,
            "System32",
            false,
            false,
        );
        push_entry(
            &mut entries,
            std::path::PathBuf::from(sysroot),
            RX,
            "SystemRoot",
            false,
            false,
        );
    }

    entries
}

fn push_entry(
    entries: &mut Vec<AllowEntry>,
    p: std::path::PathBuf,
    access: u32,
    label: &'static str,
    deny: bool,
    protected: bool,
) {
    match to_nt_path(&p) {
        Ok(nt) => entries.push(AllowEntry {
            nt_path: nt,
            win32_path: p,
            access,
            label,
            deny,
            protected,
        }),
        Err(e) => eprintln!(
            "[spike:diag] allowlist NT resolution failed for {label}: {e}",
        ),
    }
}

/// Ensure the per-session install dirs exist on disk.
pub fn ensure_session_dirs(cwd: &std::path::PathBuf, sid: &str) -> std::io::Result<()> {
    let base = cwd.join(".sandbox").join(sid);
    std::fs::create_dir_all(base.join("bin"))?;
    std::fs::create_dir_all(base.join("venv"))?;
    Ok(())
}
