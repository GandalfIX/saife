use windows::Win32::Foundation::*;
use windows::Win32::Storage::FileSystem::*;
use windows::core::*;

use crate::profile::FilesystemSlice;

pub struct AllowEntry {
    pub win32_path: std::path::PathBuf,
    pub access: u32,
    pub label: String,
    pub deny: bool,
    pub protected: bool,
}

pub const RWX: u32 = FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0 | FILE_GENERIC_EXECUTE.0;
pub const RW: u32 = FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0;
pub const RX: u32 = FILE_GENERIC_READ.0 | FILE_GENERIC_EXECUTE.0;

/// Ensure the per-session install dirs exist on disk (Option E roots).
pub fn ensure_session_dirs(cwd: &std::path::Path, sid: &str) -> std::io::Result<()> {
    let base = cwd.join(".sandbox").join(sid);
    std::fs::create_dir_all(base.join("bin"))?;
    std::fs::create_dir_all(base.join("venv"))?;
    Ok(())
}

/// Build the full allow-list for a session: Option E per-session dirs (always),
/// plus the resolved profile + CLI filesystem entries.
///
/// Per-session isolation (S-13): the `.sandbox\<sid>` subtree is granted to
/// the session's AppContainer SID with a PROTECTED_DACL — it does NOT inherit
/// the broad `$CWD` Allow. So session B's AppContainer SID, which has an Allow
/// on `$CWD` (inherited), does NOT get an Allow on session A's subtree.
pub fn build_allowlist(
    sid: &str,
    cwd: &std::path::Path,
    fs: &FilesystemSlice,
) -> Result<Vec<AllowEntry>> {
    let mut entries = Vec::new();

    // Profile allow entries (readwrite = RWX).
    for p in &fs.allow {
        push_entry(&mut entries, p.clone(), RWX, format!("allow:{}", p.display()), false, false);
    }
    // Profile read-only entries (RX).
    for p in &fs.read_only {
        push_entry(&mut entries, p.clone(), RX, format!("ro:{}", p.display()), false, false);
    }
    // Profile deny entries (deny ACE).
    for p in &fs.deny {
        push_entry(&mut entries, p.clone(), 0, format!("deny:{}", p.display()), true, false);
    }

    // .sandbox: minimal RX so the owning session can traverse to reach its own
    // subtree, without being able to read sibling subtrees (the per-session
    // subtrees are PROTECTED so inheritance stops at their boundary).
    push_entry(&mut entries, cwd.join(".sandbox"), RX, ".sandbox".into(), false, false);

    // Per-session subtree: PROTECTED so it inherits nothing from $CWD/.sandbox.
    // Only this session's AppContainer SID is granted (RWX).
    push_entry(&mut entries, cwd.join(".sandbox").join(sid), RWX, ".sandbox/<sid>".into(), false, true);
    push_entry(&mut entries, cwd.join(".sandbox").join(sid).join("bin"), RWX, ".sandbox/bin".into(), false, true);
    push_entry(&mut entries, cwd.join(".sandbox").join(sid).join("venv"), RWX, ".sandbox/venv".into(), false, true);

    // Implicit grants for any Win32 process to start (windows_common group,
    // per the US-1 spec nono comparison): SystemRoot/System32 (RX).
    if let Ok(sysroot) = std::env::var("SystemRoot") {
        push_entry(&mut entries, std::path::PathBuf::from(&sysroot).join("System32"), RX, "System32".into(), false, false);
        push_entry(&mut entries, std::path::PathBuf::from(&sysroot), RX, "SystemRoot".into(), false, false);
    }

    Ok(entries)
}

fn push_entry(
    entries: &mut Vec<AllowEntry>,
    p: std::path::PathBuf,
    access: u32,
    label: String,
    deny: bool,
    protected: bool,
) {
    entries.push(AllowEntry {
        win32_path: p,
        access,
        label,
        deny,
        protected,
    });
}

/// Resolve a Win32 path (e.g. `C:\foo`) to its NT device path
/// (`\Device\HarddiskVolume4\foo`) via `QueryDosDeviceW`. Currently unused
/// (we grant via per-directory DACLs, not the formal RuleSet API), but kept
/// for the future RuleSet implementation.
#[allow(dead_code)]
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
        Ok(format!("{dev}\\{rest}"))
    }
}
