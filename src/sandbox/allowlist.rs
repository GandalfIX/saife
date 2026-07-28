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
pub const RX: u32 = FILE_GENERIC_READ.0 | FILE_GENERIC_EXECUTE.0;

/// Minimal ancestor mask: `FILE_READ_ATTRIBUTES` (stat the dir itself) +
/// `FILE_TRAVERSE` (walk through it to reach children). Does NOT include
/// `FILE_LIST_DIRECTORY`, so sibling directory contents stay hidden.
/// Fixes KI-1.2's `lstat` failures (e.g. Node `fs.lstatSync` on the user
/// home) without weakening sibling isolation.
const ANCESTOR_MASK: u32 = FILE_READ_ATTRIBUTES.0 | FILE_TRAVERSE.0;

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
    let mut ancestor_set: Vec<std::path::PathBuf> = Vec::new();

    // Profile allow entries (readwrite = RWX).
    for p in &fs.allow {
        push_entry(&mut entries, p.clone(), RWX, format!("allow:{}", p.display()), false, false);
        collect_ancestors(p, &mut ancestor_set);
    }
    // Profile read-only entries (RX).
    for p in &fs.read_only {
        push_entry(&mut entries, p.clone(), RX, format!("ro:{}", p.display()), false, false);
        collect_ancestors(p, &mut ancestor_set);
    }
    // Profile deny entries (deny ACE).
    for p in &fs.deny {
        push_entry(&mut entries, p.clone(), 0, format!("deny:{}", p.display()), true, false);
    }
    // Ancestor traverse grants (KI-1.2 fix): for every allowed/RO path, grant
    // the AppContainer SID `FILE_READ_ATTRIBUTES | FILE_TRAVERSE` on each
    // ancestor directory up to the drive root. This lets sandboxed tools stat
    // and traverse their own home directory (`C:\Users\<user>`) without listing
    // sibling contents. Does NOT grant `FILE_LIST_DIRECTORY` on ancestors, so
    // sibling isolation is preserved. Ancestors owned by the current user are
    // grantable unprivileged at run time (no admin needed); grants on
    // system-owned ancestors are attempted and silently skipped if they fail
    // (see `grant_access`).
    for ancestor in &ancestor_set {
        push_entry(
            &mut entries,
            ancestor.clone(),
            ANCESTOR_MASK,
            format!("ancestor:{}", ancestor.display()),
            false,
            false,
        );
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

/// Collect every ancestor directory of `path` up to (but not including) the
/// drive root. The drive root itself is covered by the one-time
/// `setup --grant-drive-root` ACE (or by inheritance on user-owned drives),
/// so we stop there. Dedupes against `out` to avoid redundant ACE writes when
/// multiple granted paths share ancestors (e.g. `$HOME/.local/share/opencode`
/// and `$HOME/.config/opencode` both live under `C:\Users\<user>`).
fn collect_ancestors(path: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
    let mut cur = path.parent();
    while let Some(parent) = cur {
        // Stop at the drive root (e.g. `C:\`): it's handled by the
        // `--grant-drive-root` setup step and is TrustedInstaller-owned.
        let s = parent.to_string_lossy();
        if s.len() <= 3 && s.chars().nth(1) == Some(':') {
            break;
        }
        if !out.iter().any(|e| e.eq(parent)) {
            out.push(parent.to_path_buf());
        }
        cur = parent.parent();
    }
}

/// Resolve a Win32 path (e.g. `C:\foo`) to its NT device path
/// (`\Device\HarddiskVolume4\foo`) via `QueryDosDeviceW`. Currently unused
/// (we grant via per-directory DACLs, not the formal RuleSet API), but kept
/// for the future RuleSet implementation.
#[allow(dead_code)]
pub fn to_nt_path(win32: &std::path::Path) -> Result<String> {
    let mut win32_clean = win32.to_path_buf();
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::FilesystemSlice;

    #[test]
    fn windows_common_system32_always_in_allowlist() {
        let fs = FilesystemSlice::default();
        let entries = build_allowlist("test-sid", std::path::Path::new("C:\\proj"), &fs).unwrap();
        let sysroot = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        let system32 = std::path::PathBuf::from(&sysroot).join("System32");
        assert!(
            entries.iter().any(|e| e.win32_path == system32),
            "System32 must always be in the allowlist; got: {:?}",
            entries.iter().map(|e| &e.win32_path).collect::<Vec<_>>()
        );
    }
}
