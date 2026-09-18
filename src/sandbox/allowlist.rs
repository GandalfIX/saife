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
    /// Whether the ACE should propagate to children (inheritable) or apply
    /// to this directory only (non-inheritable). Ancestor traverse grants
    /// use `false` to avoid recursively rewriting the DACL of every
    /// descendant — a Windows operation that hangs on large trees like
    /// the user profile root (`C:\Users\<user>`).
    pub inherit: bool,
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
        push_entry(
            &mut entries,
            p.clone(),
            RWX,
            format!("allow:{}", p.display()),
            false,
            false,
        );
        collect_ancestors(p, &mut ancestor_set);
    }
    // Profile read-only entries (RX).
    for p in &fs.read_only {
        push_entry(
            &mut entries,
            p.clone(),
            RX,
            format!("ro:{}", p.display()),
            false,
            false,
        );
        collect_ancestors(p, &mut ancestor_set);
    }
    // Profile deny entries (deny ACE).
    for p in &fs.deny {
        push_entry(
            &mut entries,
            p.clone(),
            0,
            format!("deny:{}", p.display()),
            true,
            false,
        );
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
        push_entry_noninherit(
            &mut entries,
            ancestor.clone(),
            ANCESTOR_MASK,
            format!("ancestor:{}", ancestor.display()),
        );
    }

    // .sandbox: minimal RX so the owning session can traverse to reach its own
    // subtree, without being able to read sibling subtrees (the per-session
    // subtrees are PROTECTED so inheritance stops at their boundary).
    push_entry(
        &mut entries,
        cwd.join(".sandbox"),
        RX,
        ".sandbox".into(),
        false,
        false,
    );

    // Per-session subtree: PROTECTED so it inherits nothing from $CWD/.sandbox.
    // Only this session's AppContainer SID is granted (RWX).
    push_entry(
        &mut entries,
        cwd.join(".sandbox").join(sid),
        RWX,
        ".sandbox/<sid>".into(),
        false,
        true,
    );
    push_entry(
        &mut entries,
        cwd.join(".sandbox").join(sid).join("bin"),
        RWX,
        ".sandbox/bin".into(),
        false,
        true,
    );
    push_entry(
        &mut entries,
        cwd.join(".sandbox").join(sid).join("venv"),
        RWX,
        ".sandbox/venv".into(),
        false,
        true,
    );

    // Implicit grants for any Win32 process to start (windows_common group,
    // per the US-1 spec nono comparison): SystemRoot/System32 (RX).
    if let Ok(sysroot) = std::env::var("SystemRoot") {
        push_entry(
            &mut entries,
            std::path::PathBuf::from(&sysroot).join("System32"),
            RX,
            "System32".into(),
            false,
            false,
        );
        push_entry(
            &mut entries,
            std::path::PathBuf::from(&sysroot),
            RX,
            "SystemRoot".into(),
            false,
            false,
        );
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
        inherit: true,
    });
}

/// Like `push_entry` but with `inherit=false` — the ACE applies to this
/// directory only and does NOT propagate to children. Used for ancestor
/// traverse grants to avoid the recursive DACL rewrite that Windows
/// performs when an inheritable ACE is added to a large tree (e.g. the
/// user profile root `C:\Users\<user>`).
fn push_entry_noninherit(
    entries: &mut Vec<AllowEntry>,
    p: std::path::PathBuf,
    access: u32,
    label: String,
) {
    entries.push(AllowEntry {
        win32_path: p,
        access,
        label,
        deny: false,
        protected: false,
        inherit: false,
    });
}

/// Collect every ancestor directory of `path` up to (but not including) the
/// drive root. The drive root itself is covered by the one-time
/// `setup --grant-drive-root` ACE (or by inheritance on user-owned drives),
/// so we stop there. Dedupes against `out` to avoid redundant ACE writes when
/// multiple granted paths share ancestors (e.g. `$HOME/.local/share/opencode`
/// and `$HOME/.config/opencode` both live under `C:\Users\<user>`).
///
/// **Stops at the user profile root (`C:\Users\<user>`) and the `AppData` /
/// `AppData\Local` directories.** Writing an ACE to any of these makes the
/// kernel's recursive DACL propagation walk the whole subtree — an operation
/// that effectively hangs on these large trees (mirrors the ADR-0001 finding;
/// see docs/superpowers/plans/2026-09-16-mxc-derived-hardening.md Task 3B).
/// The AppContainer can already traverse these directories via inherited
/// `Everyone: ReadAndExecute` ACEs, so explicit grants are unnecessary.
fn collect_ancestors(path: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
    // Build the set of directories at which to stop (without canonicalization
    // — Rust's `canonicalize()` adds a `\\?\` prefix on Windows which would
    // defeat the `eq` comparison below).
    let mut stop_dirs: Vec<std::path::PathBuf> = Vec::new();
    if let Some(profile) = std::env::var_os("USERPROFILE").map(std::path::PathBuf::from) {
        stop_dirs.push(profile.clone());
        stop_dirs.push(profile.join("AppData"));
        stop_dirs.push(profile.join("AppData").join("Local"));
    }
    let mut cur = path.parent();
    while let Some(parent) = cur {
        // Stop at the drive root (e.g. `C:\`): it's handled by the
        // `--grant-drive-root` setup step and is TrustedInstaller-owned.
        let s = parent.to_string_lossy();
        if s.len() <= 3 && s.chars().nth(1) == Some(':') {
            break;
        }
        // Stop at (and do NOT include) any of the large profile directories
        // where DACL writes hang (see the doc comment above).
        if stop_dirs.iter().any(|d| paths_eq_ci(parent, d)) {
            break;
        }
        if !out.iter().any(|e| e.eq(parent)) {
            out.push(parent.to_path_buf());
        }
        cur = parent.parent();
    }
}

/// Case-insensitive path comparison (Windows paths are case-insensitive).
/// Avoids `canonicalize()` which adds a `\\?\` prefix.
fn paths_eq_ci(a: &std::path::Path, b: &std::path::Path) -> bool {
    a.to_string_lossy()
        .eq_ignore_ascii_case(&b.to_string_lossy())
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

    #[test]
    fn ancestor_entries_are_non_inheritable() {
        let fs = FilesystemSlice {
            allow: vec![std::path::PathBuf::from("C:\\Users\\test\\proj\\subdir")],
            ..Default::default()
        };
        let entries = build_allowlist(
            "test-sid",
            std::path::Path::new("C:\\Users\\test\\proj"),
            &fs,
        )
        .unwrap();
        let ancestors: Vec<&AllowEntry> = entries
            .iter()
            .filter(|e| e.label.starts_with("ancestor:"))
            .collect();
        assert!(!ancestors.is_empty(), "should have ancestor entries");
        for a in &ancestors {
            assert!(
                !a.inherit,
                "ancestor {:?} should be non-inheritable to avoid recursive DACL propagation",
                a.win32_path
            );
        }
    }

    #[test]
    fn collect_ancestors_stops_at_user_profile_root() {
        let mut out: Vec<std::path::PathBuf> = Vec::new();
        // Use a path under the real user profile so the stop-dir checks
        // trigger. If USERPROFILE is unset, this test still passes because
        // the stop-dir guard is a no-op.
        let profile = std::env::var_os("USERPROFILE")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| std::path::PathBuf::from("C:\\Users\\nonexistent"));
        let deep = profile
            .join("AppData")
            .join("Local")
            .join("Temp")
            .join("proj");
        collect_ancestors(&deep, &mut out);
        for stop in &[
            profile.clone(),
            profile.join("AppData"),
            profile.join("AppData").join("Local"),
        ] {
            assert!(
                !out.iter().any(|p| paths_eq_ci(p, stop)),
                "stop-dir {:?} must not appear in ancestors {:?}",
                stop,
                out
            );
        }
    }

    #[test]
    fn paths_eq_ci_matches_case_insensitively() {
        assert!(paths_eq_ci(
            std::path::Path::new("C:\\Users\\Marku"),
            std::path::Path::new("c:\\users\\marku"),
        ));
        assert!(!paths_eq_ci(
            std::path::Path::new("C:\\Users\\marku"),
            std::path::Path::new("C:\\Users\\other"),
        ));
    }
}
