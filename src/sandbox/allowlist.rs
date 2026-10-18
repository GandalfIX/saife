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

/// Read-write-execute INCLUDING delete. Granted trees must let the child
/// create AND delete files: python's tempfile tempdir check does
/// open+close+unlink on every candidate and rejects any directory whose
/// unlink is denied — without DELETE bits in the inherited ACE the check
/// fails everywhere and pip/ensurepip exit 1 silently (proven in-VM
/// 2026-10-11: "OPEN OK, UNLINK FAIL winerror=5" in the granted cwd, and
/// `open+unlink`/`rmtree` denied with winerror=5). `DELETE` is
/// inherited onto created files (unlink needs it); `FILE_DELETE_CHILD`
/// on directories covers deletions through the parent dir.
pub const RWX: u32 = FILE_GENERIC_READ.0
    | FILE_GENERIC_WRITE.0
    | FILE_GENERIC_EXECUTE.0
    | DELETE.0
    | FILE_DELETE_CHILD.0;
pub const RX: u32 = FILE_GENERIC_READ.0 | FILE_GENERIC_EXECUTE.0;

/// Minimal ancestor mask: `FILE_READ_ATTRIBUTES` (stat the dir itself) +
/// `FILE_TRAVERSE` (walk through it to reach children). Does NOT include
/// `FILE_LIST_DIRECTORY`, so sibling directory contents stay hidden.
/// Fixes KI-1.2's `lstat` failures (e.g. Node `fs.lstatSync` on the user
/// home) without weakening sibling isolation.
const ANCESTOR_MASK: u32 = FILE_READ_ATTRIBUTES.0 | FILE_TRAVERSE.0;

/// The python shim the sandbox injects via PYTHONPATH (see the module
/// docstring in sitecustomize.py for why it must rewrite mode 0o700).
const PYSHIM_SITECUSTOMIZE: &str = include_str!("sitecustomize.py");

/// Ensure the per-session install dirs exist on disk (Option E roots).
/// `pyshim` additionally receives the sitecustomize.py shim itself.
pub fn ensure_session_dirs(cwd: &std::path::Path, sid: &str) -> std::io::Result<()> {
    let base = cwd.join(".sandbox").join(sid);
    std::fs::create_dir_all(base.join("bin"))?;
    std::fs::create_dir_all(base.join("venv"))?;
    let pyshim = base.join("pyshim");
    std::fs::create_dir_all(&pyshim)?;
    std::fs::write(pyshim.join("sitecustomize.py"), PYSHIM_SITECUSTOMIZE)?;
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
    // PYTHONPATH shim dir (read by every python the session spawns; see
    // sitecustomize.py). Same PROTECTED treatment as bin/venv.
    push_entry(
        &mut entries,
        cwd.join(".sandbox").join(sid).join("pyshim"),
        RWX,
        ".sandbox/pyshim".into(),
        false,
        true,
    );

    // AppContainer-private temp dir: Windows rewrites the child's TEMP/TMP
    // env vars to `%LOCALAPPDATA%\Packages\<ac>\AC\Temp` (explicit env
    // values do not survive CreateProcess for AppContainer tokens), and on
    // some builds (26340) directories created inside it do not inherit a
    // usable ACE — mkdtemp() succeeds but writing inside the new dir is
    // denied, breaking pip/ensurepip and any tool that stages files via
    // the temp dir. Create the dir if missing (it is provisioned lazily
    // on first use) and grant the session's AC SID an inheritable RWX ACE
    // so the whole tree works.
    //
    // NOTE: AppContainer processes run at LOW integrity and everything
    // they create inherits a Low mandatory label (`Mandatory
    // Label\Low Mandatory Level:(NW)`) plus owner BUILTIN\Administrators
    // (observed on the 26340 guest). Executables installed by a sandboxed
    // process (e.g. a python venv) therefore start as LOW-integrity
    // processes even OUTSIDE the sandbox and cannot write Medium objects —
    // documented here because it looks like a sandbox bug when it bites.
    if let Some(ac_temp) = crate::sandbox::appcontainer::ac_private_temp_path(sid) {
        let _ = std::fs::create_dir_all(&ac_temp);
        push_entry(&mut entries, ac_temp, RWX, "ac-private-temp".into(), false, true);
    }

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
/// traverse grants, which are deliberately kept non-recursive on the large
/// profile trees (e.g. the user profile root `C:\Users\<user>`) where an ACL
/// write does not complete on this host (see [`collect_ancestors`]).
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

/// The current user's profile directory as *the OS* records it.
///
/// Deliberately NOT `USERPROFILE`: that variable belongs to the caller's
/// environment (the integration harness repoints it at a throwaway directory so
/// the learned store is isolated), and the ancestor-walk stop set below must
/// keep matching the REAL profile tree whatever the environment says
/// (ADR-0001 Task 4.5).
fn system_profile_root() -> Option<std::path::PathBuf> {
    use windows::Win32::System::Com::CoTaskMemFree;
    use windows::Win32::UI::Shell::{FOLDERID_Profile, KF_FLAG_DEFAULT, SHGetKnownFolderPath};
    unsafe {
        let raw = SHGetKnownFolderPath(&FOLDERID_Profile, KF_FLAG_DEFAULT, None).ok()?;
        if raw.is_null() {
            return None;
        }
        let path = known_folder_path_from_wide(raw.as_wide());
        CoTaskMemFree(Some(raw.0 as *const _));
        Some(path).filter(|p| p.is_absolute())
    }
}

/// Decode a known-folder result and normalize it for the textual stop compare.
///
/// Lossy on purpose: an unpaired surrogate must not turn the lookup into
/// `None`, because a `None` here silently leaves the stop set without the OS
/// profile root — i.e. disables the guard rather than falling back to it.
///
/// A verbatim prefix is stripped for the same reason: `\\?\C:\Users\alice`
/// names the same directory as `C:\Users\alice` but is not `eq` to it, so a
/// verbatim return would silently defeat the stop compare in
/// [`collect_ancestors_with_stops`].
fn known_folder_path_from_wide(wide: &[u16]) -> std::path::PathBuf {
    strip_verbatim_prefix(std::path::PathBuf::from(String::from_utf16_lossy(wide)))
}

/// `\\?\C:\x` → `C:\x`, `\\?\UNC\server\share` → `\\server\share`.
///
/// Windows APIs may hand back verbatim (extended-length) paths; the ancestor
/// walk compares paths textually, so the prefix has to go before those paths
/// can match the stop set.
fn strip_verbatim_prefix(path: std::path::PathBuf) -> std::path::PathBuf {
    const VERBATIM: &str = r"\\?\";
    const VERBATIM_UNC: &str = r"\\?\UNC\";
    let Some(s) = path.to_str() else {
        return path;
    };
    if s.get(..VERBATIM_UNC.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(VERBATIM_UNC))
    {
        return std::path::PathBuf::from(format!("{}{}", r"\\", &s[VERBATIM_UNC.len()..]));
    }
    match s.strip_prefix(VERBATIM) {
        Some(rest) => std::path::PathBuf::from(rest),
        None => path,
    }
}

/// Directories at which the ancestor walk stops: the profile root plus its
/// `AppData` and `AppData\Local` children (see [`collect_ancestors`]).
fn profile_stop_dirs() -> Vec<std::path::PathBuf> {
    profile_stop_dirs_from(
        system_profile_root(),
        std::env::var_os("USERPROFILE").map(std::path::PathBuf::from),
    )
}

/// Build the stop set from the authoritative OS profile root plus the
/// `USERPROFILE` hint.
///
/// The OS value wins, but both are kept: an extra stop point that is not on a
/// granted path's ancestor chain is inert, while one that *is* truncates the
/// walk there (it is a stop, not a filter) — and keeping the hint preserves the
/// pre-Task-4.5 behavior on the (unexpected) path where the known-folder
/// lookup fails.
fn profile_stop_dirs_from(
    system_profile: Option<std::path::PathBuf>,
    env_profile: Option<std::path::PathBuf>,
) -> Vec<std::path::PathBuf> {
    let mut stops: Vec<std::path::PathBuf> = Vec::new();
    for root in [system_profile, env_profile].into_iter().flatten() {
        let dirs = [
            root.clone(),
            root.join("AppData"),
            root.join("AppData").join("Local"),
        ];
        for dir in dirs {
            if !stops.iter().any(|s| paths_eq_ci(s, &dir)) {
                stops.push(dir);
            }
        }
    }
    stops
}

/// Collect every ancestor directory of `path` up to (but not including) the
/// drive root. The drive root itself is covered by the one-time
/// `setup --grant-drive-root` ACE (or by inheritance on user-owned drives),
/// so we stop there. Dedupes against `out` to avoid redundant ACE writes when
/// multiple granted paths share ancestors (e.g. `$HOME/.local/share/opencode`
/// and `$HOME/.config/opencode` both live under `C:\Users\<user>`).
///
/// **Stops at the user profile root (`C:\Users\<user>`) and the `AppData` /
/// `AppData\Local` directories.** Empirically, on this host, an ACL write to
/// any of these directories does not return: under the integration harness's
/// faked-`USERPROFILE` configuration the ACE is built but the kernel write
/// never completes (observed via instrumentation; the pre-fix binary hung for
/// more than 20 s in an A/B run, the post-fix binary exits in about 10 s). That
/// is a measured property of these directories here, not a claim about why it
/// happens. The AppContainer can already traverse these directories via
/// inherited `Everyone: ReadAndExecute` ACEs, so explicit grants are
/// unnecessary.
///
/// The stop set is derived from the OS profile root, never from
/// `USERPROFILE` alone: a caller-controlled `USERPROFILE` (harness store
/// isolation) used to move the stop points off their real targets, so the walk
/// planned ACEs for the actual `%LOCALAPPDATA%` / `%APPDATA%` / profile root —
/// the very directories whose ACL write does not complete — stalling the
/// session before the child was ever spawned (ADR-0001 Task 4.5).
fn collect_ancestors(path: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
    collect_ancestors_with_stops(path, &profile_stop_dirs(), out);
}

/// The core of [`collect_ancestors`] with the stop set passed in, so tests can
/// pin the walk's truncation semantics without touching process state.
fn collect_ancestors_with_stops(
    path: &std::path::Path,
    stop_dirs: &[std::path::PathBuf],
    out: &mut Vec<std::path::PathBuf>,
) {
    // The stop set is compared as-is (no canonicalization — Rust's
    // `canonicalize()` adds a `\\?\` prefix on Windows which would defeat the
    // `eq` comparison below).
    let mut cur = path.parent();
    while let Some(parent) = cur {
        // Stop at the drive root (e.g. `C:\`): it's handled by the
        // `--grant-drive-root` setup step and is TrustedInstaller-owned.
        let s = parent.to_string_lossy();
        if s.len() <= 3 && s.chars().nth(1) == Some(':') {
            break;
        }
        // Stop at (and do NOT include) any of the large profile directories
        // where the ACL write does not complete on this host (see the doc
        // comment above).
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
        let _env = crate::env_lock();
        let mut out: Vec<std::path::PathBuf> = Vec::new();
        // Use a path under the user profile so the stop-dir checks trigger.
        // Since Task 4.5 the stop set comes from the OS known folder and
        // `USERPROFILE` is only a hint, so holding `ENV_LOCK` is what keeps the
        // path built here on the same profile tree the walk stops at.
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

    /// The OS profile root always contributes all three stop points, even when
    /// `USERPROFILE` names an unrelated directory (Task 4.5).
    #[test]
    fn profile_stop_dirs_keeps_the_system_profile_when_the_env_disagrees() {
        let system = std::path::PathBuf::from(r"C:\Users\alice");
        let env = std::path::PathBuf::from(r"C:\staging\fake-home");
        let stops = profile_stop_dirs_from(Some(system.clone()), Some(env));

        for expected in [
            system.clone(),
            system.join("AppData"),
            system.join("AppData").join("Local"),
        ] {
            assert!(
                stops.iter().any(|s| paths_eq_ci(s, &expected)),
                "stop {expected:?} missing from {stops:?}"
            );
        }
    }

    /// With no OS answer the env value is the only source: pre-Task-4.5
    /// behavior, kept as the fallback path.
    #[test]
    fn profile_stop_dirs_falls_back_to_the_env_profile() {
        let env = std::path::PathBuf::from(r"C:\Users\alice");
        let stops = profile_stop_dirs_from(None, Some(env.clone()));
        assert_eq!(stops.len(), 3, "{stops:?}");
        assert!(paths_eq_ci(&stops[2], &env.join("AppData").join("Local")));
    }

    #[test]
    fn profile_stop_dirs_dedupes_case_insensitively() {
        let stops = profile_stop_dirs_from(
            Some(std::path::PathBuf::from(r"C:\Users\Alice")),
            Some(std::path::PathBuf::from(r"c:\users\alice")),
        );
        assert_eq!(stops.len(), 3, "{stops:?}");
    }

    /// Ruling 2: the env profile is a real stop point, not an inert extra — an
    /// env profile that IS an ancestor of the granted path truncates the walk
    /// there — while the OS stops stay in force for the real tree.
    #[test]
    fn env_stop_dir_truncates_the_walk_without_weakening_the_system_stops() {
        let system = std::path::PathBuf::from(r"C:\Users\alice");
        let env = std::path::PathBuf::from(r"C:\staging\fake-home");
        let stops = profile_stop_dirs_from(Some(system.clone()), Some(env.clone()));

        // Granted path below the hint: the walk truncates at the hint, so
        // neither the hint nor anything above it is ever granted.
        let granted = env.join("work").join("app").join(".cache");
        let mut under_hint: Vec<std::path::PathBuf> = Vec::new();
        collect_ancestors_with_stops(&granted, &stops, &mut under_hint);
        assert!(
            under_hint
                .iter()
                .any(|p| paths_eq_ci(p, &env.join("work").join("app"))),
            "intermediate dirs below the hint must still be granted: {under_hint:?}"
        );
        for truncated in [env.clone(), env.parent().unwrap().to_path_buf()] {
            assert!(
                !under_hint.iter().any(|p| paths_eq_ci(p, &truncated)),
                "{truncated:?} must not be granted; walk produced {under_hint:?}"
            );
        }

        // The hint must not shadow the real tree: a path under the OS profile
        // still truncates at the OS stop dirs.
        let real = system
            .join("AppData")
            .join("Local")
            .join("Temp")
            .join("proj");
        let mut under_system: Vec<std::path::PathBuf> = Vec::new();
        collect_ancestors_with_stops(&real, &stops, &mut under_system);
        assert!(
            under_system
                .iter()
                .any(|p| paths_eq_ci(p, real.parent().unwrap())),
            "the dir below the OS stop must still be granted: {under_system:?}"
        );
        for stop in [
            system.clone(),
            system.join("AppData"),
            system.join("AppData").join("Local"),
        ] {
            assert!(
                !under_system.iter().any(|p| paths_eq_ci(p, &stop)),
                "OS stop {stop:?} must hold with an unrelated env hint; walk produced {under_system:?}"
            );
        }
    }

    /// The trusted source itself must resolve on a normal Windows host — the
    /// stop set has no other guard against a faked `USERPROFILE`.
    #[test]
    fn system_profile_root_resolves() {
        let root = system_profile_root().expect("known-folder Profile lookup failed");
        assert!(root.is_absolute(), "{root:?}");
        let local_appdata = std::env::var_os("LOCALAPPDATA").map(std::path::PathBuf::from);
        if let Some(local) = local_appdata {
            assert!(
                local.starts_with(&root),
                "LOCALAPPDATA {local:?} must live under the profile root {root:?}"
            );
        }
    }

    /// A known-folder return may be verbatim (`\\?\`) or UNC-verbatim; both must
    /// be normalized before the stop compare, or the OS profile root silently
    /// stops matching the ancestors it is supposed to stop (Task 4.5).
    #[test]
    fn known_folder_paths_lose_their_verbatim_prefix() {
        fn wide(s: &str) -> Vec<u16> {
            s.encode_utf16().collect()
        }

        assert_eq!(
            known_folder_path_from_wide(&wide(r"\\?\C:\Users\alice")),
            std::path::PathBuf::from(r"C:\Users\alice")
        );
        assert_eq!(
            known_folder_path_from_wide(&wide(r"\\?\UNC\server\share\alice")),
            std::path::PathBuf::from(r"\\server\share\alice")
        );
        // The stripped form must still survive the `is_absolute()` filter.
        assert!(known_folder_path_from_wide(&wide(r"\\?\C:\Users\alice")).is_absolute());

        // Plain and non-verbatim device paths pass through untouched.
        for unchanged in [r"C:\Users\alice", r"\\.\C:\Users\alice", r"\\server\share"] {
            assert_eq!(
                known_folder_path_from_wide(&wide(unchanged)),
                std::path::PathBuf::from(unchanged),
                "{unchanged} must not be rewritten"
            );
        }
    }

    /// An unpaired surrogate must not disable the guard: strict decoding used to
    /// fail into `None`, which drops the OS profile root from the stop set
    /// entirely instead of falling back to anything (Task 4.5).
    #[test]
    fn known_folder_paths_decode_lossily_instead_of_dropping_the_guard() {
        let wide = [0xD800u16, u16::from(b'X')]; // lone high surrogate, then 'X'
        assert!(
            String::from_utf16(&wide).is_err(),
            "precondition: the sample must be invalid UTF-16"
        );

        let path = known_folder_path_from_wide(&wide);
        let text = path.to_string_lossy();
        assert!(text.contains('\u{FFFD}'), "expected U+FFFD in {path:?}");
        assert!(
            text.ends_with('X'),
            "expected the tail to survive: {path:?}"
        );
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

    #[test]
    fn ensure_session_dirs_writes_python_shim() {
        let base = std::env::temp_dir().join(format!(
            "sbx-allowlist-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let cwd = base.join("proj");
        std::fs::create_dir_all(&cwd).unwrap();
        let sid = "sid-test";
        ensure_session_dirs(&cwd, sid).unwrap();
        let shim = cwd.join(".sandbox").join(sid).join("pyshim\\sitecustomize.py");
        let content = std::fs::read_to_string(&shim).unwrap();
        assert!(
            content.contains("_sandbox_mkdir"),
            "sitecustomize.py must contain the mkdir interposition"
        );
        assert!(
            content.contains("mode == 0o700"),
            "sitecustomize.py must rewrite the 0o700 mode"
        );
        assert!(
            content.contains("SANDBOX_SESSION_SID"),
            "sitecustomize.py must gate on the session marker (venv-root copies stay inert outside the sandbox)"
        );
        assert!(
            content.contains("setup_python"),
            "sitecustomize.py must interpose venv.EnvBuilder.setup_python to seed the venv-root copy"
        );
        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn allowlist_contains_python_shim_grant() {
        let fs = FilesystemSlice::default();
        let entries =
            build_allowlist("test-sid", std::path::Path::new("C:\\proj"), &fs).unwrap();
        let pyshim = std::path::Path::new(r"C:\proj\.sandbox\test-sid\pyshim");
        assert!(
            entries
                .iter()
                .any(|e| e.win32_path == pyshim && e.access == RWX),
            "pyshim dir must carry an RWX grant; got: {:?}",
            entries.iter().map(|e| &e.label).collect::<Vec<_>>()
        );
    }

    /// ADR-0001 Task 4.5: the ancestor-walk stop set must come from the OS, not
    /// from `USERPROFILE`.
    ///
    /// The supervisor's environment is caller-controlled — the integration
    /// harness points `USERPROFILE` at a throwaway dir so the learned store is
    /// isolated — and an env-derived stop set silently stops matching the REAL
    /// profile tree. The walk then plans traverse ACEs for `%USERPROFILE%`,
    /// `%APPDATA%` and `%LOCALAPPDATA%`, and on this host an ACL write to those
    /// directories does not return under that configuration: the session blocks
    /// inside `grant_access` BEFORE the child is spawned (observed as a
    /// "teardown hang" — no child, a lone conhost, `sandbox.exe` alive forever;
    /// instrumented runs show the ACE built with no kernel-write completion,
    /// the pre-fix binary hung >20 s and the post-fix binary exits in ~10 s).
    #[test]
    fn ancestor_grants_ignore_a_faked_userprofile() {
        let _env = crate::env_lock();
        struct EnvGuard(Option<std::ffi::OsString>);
        impl Drop for EnvGuard {
            fn drop(&mut self) {
                unsafe {
                    match self.0.take() {
                        Some(v) => std::env::set_var("USERPROFILE", v),
                        None => std::env::remove_var("USERPROFILE"),
                    }
                }
            }
        }

        let real_home = std::path::PathBuf::from(
            std::env::var_os("USERPROFILE").expect("USERPROFILE must be set on this host"),
        );
        let pid = std::process::id();
        // A scenario dir where the harness puts it: under %LOCALAPPDATA%\Temp.
        let cwd = std::env::temp_dir().join(format!("sbx-ancestor-test-{pid}"));
        let fake_home = std::env::temp_dir().join(format!("sbx-fake-home-{pid}"));
        std::fs::create_dir_all(&cwd).unwrap();
        std::fs::create_dir_all(&fake_home).unwrap();
        // Non-vacuity: the walk only meets the profile stop dirs if the session
        // dir actually sits inside the REAL profile tree. If the temp dir ever
        // moved outside it, this test would pass no matter what the guard did.
        assert!(
            cwd.starts_with(&real_home),
            "test cwd {cwd:?} must live under the real profile tree {real_home:?}"
        );

        let _guard = EnvGuard(std::env::var_os("USERPROFILE"));
        unsafe { std::env::set_var("USERPROFILE", &fake_home) };

        let fs = FilesystemSlice {
            allow: vec![cwd.clone()],
            ..Default::default()
        };
        let entries = build_allowlist("test-sid", &cwd, &fs).unwrap();

        let _ = std::fs::remove_dir_all(&cwd);
        let _ = std::fs::remove_dir_all(&fake_home);

        for hazardous in [
            real_home.clone(),
            real_home.join("AppData"),
            real_home.join("AppData").join("Local"),
        ] {
            assert!(
                !entries
                    .iter()
                    .any(|e| paths_eq_ci(&e.win32_path, &hazardous)),
                "an ancestor grant on {hazardous:?} must never be planned — the ACL \
                 write does not complete there on this host (Task 4.5). entries: {:?}",
                entries.iter().map(|e| &e.win32_path).collect::<Vec<_>>()
            );
        }
        // The guard must not weaken into "no ancestors at all": %TEMP% is a
        // normal ancestor of the session dir and still needs its grant.
        // (`env::temp_dir()` may carry a trailing separator on Windows.)
        let temp = std::path::PathBuf::from(
            std::env::temp_dir()
                .to_string_lossy()
                .trim_end_matches('\\')
                .to_string(),
        );
        assert!(
            entries.iter().any(|e| paths_eq_ci(&e.win32_path, &temp)),
            "%TEMP% ({temp:?}) must still get its traverse grant; entries: {:?}",
            entries.iter().map(|e| &e.win32_path).collect::<Vec<_>>()
        );
    }
}
