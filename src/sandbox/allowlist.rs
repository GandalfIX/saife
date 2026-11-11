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
pub(crate) const ANCESTOR_MASK: u32 = FILE_READ_ATTRIBUTES.0 | FILE_TRAVERSE.0;

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
#[cfg_attr(not(test), allow(dead_code))]
pub fn build_allowlist(
    sid: &str,
    cwd: &std::path::Path,
    fs: &FilesystemSlice,
) -> Result<Vec<AllowEntry>> {
    build_allowlist_exposed(sid, cwd, fs, &[])
}

/// [`build_allowlist`] with the operator's credential exposures: the labels in
/// `exposed` have their builtin deny dropped for this session (the resolver
/// refuses an unknown label or a `Secret`-class one), and the machine policy's
/// additions join the set. Same resolver the mxc backend consumes, so the two
/// backends cannot drift.
pub fn build_allowlist_exposed(
    sid: &str,
    cwd: &std::path::Path,
    fs: &FilesystemSlice,
    exposed: &[String],
) -> Result<Vec<AllowEntry>> {
    // The built-in deny set is read from the environment here, once, so the body
    // below is a pure function of its arguments and can be tested without mutating
    // process state (the suite has tests that do).
    //
    // The credential FILES are filtered by existence, unlike the directories: a
    // missing file usually means the tool is not installed (`~/.m2/settings.xml`
    // on a machine without Maven), and `grant_one` fails on a missing path, with
    // `grant_access` failing the SESSION on any deny that cannot be applied. A
    // file that does not exist needs no deny. The mxc backend keeps the full
    // list — its `denied_paths` are policy entries, not filesystem objects, so a
    // missing path is inert there.
    // One resolver for both backends: builtin entries minus what the operator
    // exposed by label, plus the machine policy (`%PROGRAMDATA%\saife\deny.d`).
    // A policy that cannot be parsed refuses the session here, before any grant
    // is written - a policy that cannot be trusted to deny must not be silently
    // missing.
    let effective = crate::profile::effective_denies(exposed)
        .map_err(|e| Error::new(E_INVALIDARG, e.to_string()))?;
    // A path that does not exist needs no ACE: `grant_one` fails with
    // 0x80070002, and `grant_access` treats a failed DENY as a refused session
    // (fail-close since 2026-11-10). The dir list needed the same filter the
    // file list always had - on a host without `~/.aws` the three absent tree
    // denies used to fail the grant pass and run the session with a warning
    // instead. The pre-flight on a grant inside such a deny is skipped with the
    // entry; that is the same trade the file denies already make, and the
    // documented one ("a path that does not exist needs no deny").
    let dirs: Vec<std::path::PathBuf> = effective.dirs.into_iter().filter(|p| p.exists()).collect();
    let files: Vec<std::path::PathBuf> =
        effective.files.into_iter().filter(|p| p.exists()).collect();
    build_allowlist_with(sid, cwd, fs, &dirs, &files)
}

pub(crate) fn build_allowlist_with(
    sid: &str,
    cwd: &std::path::Path,
    fs: &FilesystemSlice,
    builtin_denies: &[std::path::PathBuf],
    builtin_deny_files: &[std::path::PathBuf],
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
    // Built-in denies — credentials plus the tool's own control-plane trees.
    // The AppContainer set is a SUPERSET of the mxc backend's: these six are
    // `~/.ssh`, `~/.aws`, `~/.azure`, `~/.gnupg`, `~/.saife` and
    // `%LOCALAPPDATA%\saife`, while mxc's `PROFILE_SECRET_DIRS` names the four
    // credential dirs. The two `.saife` trees are denied here because they hold
    // the plugin manifests whose `command` runs HOST-side on the next
    // `--plugin` run, the learned policy, the audit log and the DPAPI-wrapped
    // signing key.
    //
    // These denies only mean something with a real mask. Until 2026-11-09 every
    // deny on this backend was written with `access = 0` — a no-op ACE that
    // intersects no requested rights — so `--backend appcontainer --allow
    // $USERPROFILE` read all six through the inherited allow (C1). The comment
    // that used to sit here claimed the protection held; it never did on this
    // backend.
    // The pre-flight refuses a session whose grant is INSIDE a deny — for the
    // credential FILES below exactly as for the directories above. That is
    // what makes the file denies safe to add without touching the shipped
    // profile JSONs: a grant of `~/.gradle` (the directory) passes, because
    // the deny names `~/.gradle/gradle.properties` (a descendant), while a
    // grant of the credential file itself is refused by name.
    for deny in builtin_denies.iter().chain(builtin_deny_files.iter()) {
        for grant in fs.allow.iter().chain(fs.read_only.iter()) {
            if crate::profile::path_covers(deny, grant) {
                // windows::core::Result is this module's error type; the message is
                // what the operator sees, so it names both paths and the fix.
                return Err(Error::new(
                    E_INVALIDARG,
                    format!(
                        "deny covers grant: {} is inside the always-denied {} - narrow the \
                         grant or drop it (a deny that swallows a grant is refused, never \
                         silently applied)",
                        grant.display(),
                        deny.display()
                    ),
                ));
            }
        }
    }
    // Deny ACEs carry FILE_ALL_ACCESS (0x1F01FF, the mask the owner ACEs
    // already use). A deny ACE intersects the requested rights, so the mask must
    // be a superset of every allow mask this list can write (RWX, RX,
    // FILE_ALL_ACCESS) or whatever it leaves out stays readable through the
    // covering grant. The trustee is the AppContainer SID, never the user or the
    // supervisor's own token, so this does not reduce the supervisor's access to
    // the deny trees (it reaches its own stores as the supervisor SID).
    for p in &fs.deny {
        push_entry(
            &mut entries,
            p.clone(),
            FILE_ALL_ACCESS.0,
            format!("deny:{}", p.display()),
            true,
            false,
        );
    }
    for deny in builtin_denies {
        push_entry(
            &mut entries,
            deny.clone(),
            FILE_ALL_ACCESS.0,
            format!("builtin-deny:{}", deny.display()),
            true,
            false,
        );
    }
    // M2: builtin credential FILE denies (`gradle.properties`, `settings.xml`,
    // `credentials.toml`, `.git-credentials`, docker/kube configs, the gh
    // config tree, `NuGet.Config`, `.pypirc` — the list lives in
    // `crate::profile::builtin_deny_files`, beside `builtin_deny_dirs`). The
    // shipped `jvm.json` grants `~/.gradle` and `~/.m2` RWX because Gradle and
    // Maven cannot run without those trees; the credentials inside them must
    // not ship with the grant. Whole-dir denies are the explicitly rejected
    // alternative: the deny would contain the grant and the pre-flight above
    // would refuse the session — `jvm.json` would become unlaunchable.
    //
    // Same FILE_ALL_ACCESS mask as the dir denies (a zero-mask deny is a no-op
    // ACE, C1), but NON-INHERITABLE: a file has no children to shield, so an
    // inheritable flag only invites a pointless `should_propagate` walk. The
    // deny applies to the file itself, where the RWX allow on the covering
    // directory would otherwise reach it — an explicit deny beats the
    // inherited allow in the DACL evaluation order.
    for file in builtin_deny_files {
        entries.push(AllowEntry {
            win32_path: file.clone(),
            access: FILE_ALL_ACCESS.0,
            label: format!("builtin-deny-file:{}", file.display()),
            deny: true,
            protected: false,
            inherit: false,
        });
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

    // M5 residual (security review 2026-11-09): `.sandbox` itself is granted
    // with a PROTECTED DACL carrying only traverse + read-attributes, so it
    // inherits NOTHING from `$CWD` — a sibling session's broad `$CWD` allow
    // used to reach this directory and let it enumerate the `<sid>` names,
    // create entries beside them and rename another session's tree. With no
    // FILE_LIST_DIRECTORY the sibling names are not enumerable, and without
    // FILE_ADD_SUBDIRECTORY/FILE_DELETE_CHILD nothing can be created or
    // renamed through it. Sibling isolation therefore rests on BOTH layers:
    // this PROTECTED parent and the per-session PROTECTED `<sid>` DACLs below.
    // The owner trustees keep full control on every PROTECTED DACL
    // (see `grant_one`'s owner re-grant), so the supervisor can still create
    // and tear down the per-session directories.
    push_entry(
        &mut entries,
        cwd.join(".sandbox"),
        ANCESTOR_MASK,
        ".sandbox".into(),
        false,
        true,
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
        push_entry(
            &mut entries,
            ac_temp,
            RWX,
            "ac-private-temp".into(),
            false,
            true,
        );
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
        let shim = cwd
            .join(".sandbox")
            .join(sid)
            .join("pyshim\\sitecustomize.py");
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
            content.contains("SAIFE_SESSION_SID"),
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
        let entries = build_allowlist("test-sid", std::path::Path::new("C:\\proj"), &fs).unwrap();
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
    /// "teardown hang" — no child, a lone conhost, `saife.exe` alive forever;
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
        // The walk only meets the profile stop dirs if the scenario dir sits inside
        // the real profile tree, so build it THERE. `env::temp_dir()` was used for
        // this and is not portable: GitHub's Windows runner puts TEMP on another
        // drive (D:\a\_temp), which made the non-vacuity assertion below fail
        // before the guard was ever exercised.
        // `AppData\Local\Temp` exists in every Windows profile, including CI's, and
        // it is a NORMAL ancestor (unlike the profile stop dirs), so the test can
        // still prove both halves: hazardous dirs are skipped, ordinary ones are not.
        let temp_root = real_home.join("AppData").join("Local").join("Temp");
        let cwd = temp_root.join(format!("sbx-ancestor-test-{pid}"));
        let fake_home = temp_root.join(format!("sbx-fake-home-{pid}"));
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
        // The guard must not weaken into "no ancestors at all": the temp root the
        // session dir lives under is an ordinary ancestor and still needs its grant.
        // Asking for `env::temp_dir()` here would pass locally and fail wherever the
        // host puts TEMP elsewhere (GitHub's runner uses another drive).
        assert!(
            entries
                .iter()
                .any(|e| paths_eq_ci(&e.win32_path, &temp_root)),
            "the temp root ({temp_root:?}) must still get its traverse grant; entries: {:?}",
            entries.iter().map(|e| &e.win32_path).collect::<Vec<_>>()
        );
    }

    /// AppContainer must refuse the same grant the mxc backend refuses: a deny that
    /// swallows a grant is an error, never a silently narrowed DACL.
    #[test]
    fn a_grant_inside_a_builtin_deny_is_refused() {
        let home = std::path::PathBuf::from(r"C:\Users\test");
        let denies = vec![home.join(".saife")];
        let fs = FilesystemSlice {
            allow: vec![home.join(".saife").join("plugins")],
            read_only: Vec::new(),
            deny: Vec::new(),
        };
        let err = match build_allowlist_with(
            "test-sid",
            std::path::Path::new(r"C:\proj"),
            &fs,
            &denies,
            &[],
        ) {
            Ok(_) => panic!("a grant inside .saife must be refused"),
            Err(e) => e,
        };
        assert!(
            err.message().contains("deny covers grant"),
            "the refusal must name the rule: {}",
            err.message()
        );
    }

    /// Both backends deny the same directories, and the entries are labelled so an
    /// operator can see which rule produced a refusal.
    #[test]
    fn builtin_denies_are_entries_on_the_appcontainer_path() {
        let home = std::path::PathBuf::from(r"C:\Users\test");
        let denies = vec![home.join(".saife")];
        let fs = FilesystemSlice {
            allow: vec![std::path::PathBuf::from(r"C:\proj")],
            read_only: Vec::new(),
            deny: Vec::new(),
        };
        let entries = build_allowlist_with(
            "test-sid",
            std::path::Path::new(r"C:\proj"),
            &fs,
            &denies,
            &[],
        )
        .unwrap();
        let want = home.join(".saife");
        let hit = entries
            .iter()
            .find(|e| e.deny && e.win32_path == want)
            .unwrap_or_else(|| {
                let labels: Vec<&str> = entries.iter().map(|e| e.label.as_str()).collect();
                panic!(".saife must be a deny entry; entries: {labels:?}")
            });
        assert!(
            hit.label.starts_with("builtin-deny:"),
            "label: {}",
            hit.label
        );
    }

    /// C1 red test 1: a deny ACE with mask 0 denies nothing — it intersects no
    /// requested rights, so every allow in the DACL still wins and the
    /// "denied" directory stays readable through any inherited grant. Both
    /// deny-producing loops (profile denies and builtin denies) must emit a
    /// non-zero mask.
    #[test]
    fn every_deny_entry_carries_a_non_zero_mask() {
        let home = std::path::PathBuf::from(r"C:\Users\test");
        let builtin = builtin_deny_dir_set(&home);
        let fs = FilesystemSlice {
            allow: vec![std::path::PathBuf::from(r"C:\proj")],
            read_only: Vec::new(),
            deny: vec![home.join("secrets")],
        };
        let entries = build_allowlist_with(
            "test-sid",
            std::path::Path::new(r"C:\proj"),
            &fs,
            &builtin,
            &[],
        )
        .unwrap();
        let denies: Vec<&AllowEntry> = entries.iter().filter(|e| e.deny).collect();
        assert!(
            denies.len() == builtin.len() + 1,
            "expected one deny per builtin dir plus the profile deny; got: {:?}",
            denies.iter().map(|e| &e.label).collect::<Vec<_>>()
        );
        for e in &denies {
            assert!(
                e.access != 0,
                "deny {:?} has a zero access mask — a zero-mask deny ACE is a \
                 no-op, so the directory stays readable (C1)",
                e.win32_path
            );
        }
    }

    /// C1 red test 1 (builtin half): the builtin deny set is exactly the six
    /// credential/control-plane directories, each denied with a non-zero mask.
    #[test]
    fn the_builtin_deny_set_yields_exactly_six_non_zero_denies() {
        let home = std::path::PathBuf::from(r"C:\Users\test");
        let local = home.join("AppData").join("Local");
        let builtin = builtin_deny_dir_set(&home);
        let fs = FilesystemSlice {
            allow: vec![std::path::PathBuf::from(r"C:\proj")],
            read_only: Vec::new(),
            deny: Vec::new(),
        };
        let entries = build_allowlist_with(
            "test-sid",
            std::path::Path::new(r"C:\proj"),
            &fs,
            &builtin,
            &[],
        )
        .unwrap();
        let builtin_denies: Vec<&AllowEntry> = entries
            .iter()
            .filter(|e| e.deny && e.label.starts_with("builtin-deny:"))
            .collect();
        assert_eq!(
            builtin_denies.len(),
            6,
            "the builtin deny set is six directories, not {:?}",
            builtin_denies.iter().map(|e| &e.label).collect::<Vec<_>>()
        );
        let want: Vec<std::path::PathBuf> = [".ssh", ".aws", ".azure", ".gnupg", ".saife"]
            .iter()
            .map(|d| home.join(d))
            .chain(std::iter::once(local.join("saife")))
            .collect();
        for w in &want {
            let hit = builtin_denies
                .iter()
                .find(|e| e.win32_path == *w)
                .unwrap_or_else(|| {
                    panic!(
                        "{w:?} missing from the builtin denies: {:?}",
                        builtin_denies
                            .iter()
                            .map(|e| &e.win32_path)
                            .collect::<Vec<_>>()
                    )
                });
            assert_ne!(
                hit.access, 0,
                "the deny for {w:?} must carry a non-zero mask (C1)"
            );
        }
        // The set is a superset of the mxc backend's PROFILE_SECRET_DIRS
        // (4 credential dirs): it additionally denies the two `.saife`
        // control-plane trees.
        assert!(want.contains(&home.join(".saife")));
        assert!(want.contains(&local.join("saife")));
    }

    /// C1: a grant spelled the ways Win32 accepts for a denied directory must
    /// still be refused by the pre-flight — after the mask is real, the
    /// pre-flight is the only thing standing between a mis-spelled grant and
    /// an allow ACE inside the deny (an explicit allow would beat the
    /// inherited deny on the parent for the AC SID... and worse, a miss here
    /// means the grant ships at all).
    #[test]
    fn the_preflight_refuses_a_grant_spelled_into_a_deny() {
        let home = std::path::PathBuf::from(r"C:\Users\test");
        let denies = vec![home.join(".saife")];
        for grant_spelling in [
            r"C:\Users\test\.saife.",
            r"C:\Users\test\.saife ",
            r"C:\Users\test\.saife\.",
            r"\\?\C:\Users\test\.saife",
        ] {
            let fs = FilesystemSlice {
                allow: vec![std::path::PathBuf::from(grant_spelling)],
                read_only: Vec::new(),
                deny: Vec::new(),
            };
            let res = build_allowlist_with(
                "test-sid",
                std::path::Path::new(r"C:\proj"),
                &fs,
                &denies,
                &[],
            );
            assert!(
                res.is_err(),
                "grant {grant_spelling:?} names the denied .saife (Win32 drops the \
                 trailing dot/space/`\\.` and the `\\\\?\\` prefix) and must be refused"
            );
        }
        // Control: a real sibling still passes the pre-flight.
        let fs = FilesystemSlice {
            allow: vec![home.join(".saife-backup")],
            read_only: Vec::new(),
            deny: Vec::new(),
        };
        assert!(
            build_allowlist_with(
                "test-sid",
                std::path::Path::new(r"C:\proj"),
                &fs,
                &denies,
                &[],
            )
            .is_ok()
        );
    }

    /// C1: the other direction — a grant that COVERS a deny (e.g.
    /// `--allow $USERPROFILE` with the builtin `~/.ssh` deny) must pass the
    /// pre-flight, and the deny entry must carry a real mask so the ACE (not
    /// the pre-flight) does the work of shielding the denied subtree from the
    /// covering grant.
    #[test]
    fn a_grant_covering_a_deny_ships_and_the_deny_keeps_a_real_mask() {
        let home = std::path::PathBuf::from(r"C:\Users\test");
        let denies = vec![home.join(".ssh")];
        let fs = FilesystemSlice {
            allow: vec![home.clone()],
            read_only: Vec::new(),
            deny: Vec::new(),
        };
        let entries = build_allowlist_with(
            "test-sid",
            std::path::Path::new(r"C:\proj"),
            &fs,
            &denies,
            &[],
        )
        .expect("a grant that covers a deny must not be refused - the deny ACE does the work");
        assert!(
            entries.iter().any(|e| !e.deny && e.win32_path == home),
            "the covering grant must stay in the allowlist"
        );
        let deny = entries
            .iter()
            .find(|e| e.deny && e.win32_path == home.join(".ssh"))
            .expect("the deny inside the grant must stay in the allowlist");
        assert_ne!(
            deny.access, 0,
            "the deny under a covering grant needs a real mask - a zero-mask \
             deny is a no-op and the inherited $USERPROFILE allow reads ~/.ssh (C1)"
        );
    }

    /// M5 residual (security review 2026-11-09): `.sandbox` itself used to
    /// inherit the broad `$CWD` RWX grant, so a second session could enumerate
    /// sibling `<sid>` names, create entries under `.sandbox` and rename another
    /// session's tree. The parent is now PROTECTED and granted only traverse +
    /// read-attributes — enough for the owning session to reach its own subtree,
    /// not enough to LIST siblings. (The per-session `<sid>` entries stay
    /// PROTECTED as before; this is the missing second layer.)
    #[test]
    fn m5_sandbox_parent_is_protected_and_grants_no_list_directory() {
        let fs = FilesystemSlice::default();
        let entries = build_allowlist("m5-parent", std::path::Path::new(r"C:\proj"), &fs).unwrap();
        let parent = entries
            .iter()
            .find(|e| e.label == ".sandbox")
            .expect("the .sandbox parent grant must exist");
        assert!(
            parent.protected,
            "`.sandbox` must be PROTECTED so a sibling session's inherited $CWD allow does \
             not reach it: mask=0x{:x} inherit={}",
            parent.access, parent.inherit
        );
        assert_eq!(
            parent.access & FILE_LIST_DIRECTORY.0,
            0,
            "`.sandbox` must NOT grant FILE_LIST_DIRECTORY — sibling <sid> names would be \
             enumerable: mask=0x{:x}",
            parent.access
        );
        assert_ne!(
            parent.access & FILE_TRAVERSE.0,
            0,
            "`.sandbox` must still grant FILE_TRAVERSE so the owning session reaches its \
             own subtree: mask=0x{:x}",
            parent.access
        );
    }

    /// M1: the CLI modes that survive the parser reach the DACL as the
    /// documented masks, not as "everything writable". `:read` is RX,
    /// `:readwrite` and a bare `--allow` are RWX. (`:write`/`:execute` are
    /// refused at the parser, profile.rs, where the mode strings live.)
    #[test]
    fn m1_read_and_readwrite_modes_carry_their_documented_masks() {
        let cwd = std::path::Path::new(r"C:\proj");
        let fs = crate::profile::merge_filesystem(
            &FilesystemSlice::default(),
            false,
            &[
                "C:/grants/rw:readwrite".into(),
                "C:/grants/bare".into(),
                "C:/grants/r:read".into(),
            ],
            &[],
            cwd,
        )
        .expect("the supported modes must parse");
        let entries = build_allowlist_with("m1-sid", cwd, &fs, &[], &[]).unwrap();

        let grant = |path: &str| {
            entries
                .iter()
                .find(|e| !e.deny && paths_eq_ci(&e.win32_path, std::path::Path::new(path)))
                .unwrap_or_else(|| {
                    panic!(
                        "no grant entry for {path}: {:?}",
                        entries.iter().map(|e| &e.label).collect::<Vec<_>>()
                    )
                })
                .access
        };
        assert_eq!(
            grant(r"C:\grants\rw"),
            RWX,
            "`:readwrite` must grant read+write+execute"
        );
        assert_eq!(
            grant(r"C:\grants\bare"),
            RWX,
            "a bare `--allow` is the documented readwrite default"
        );
        assert_eq!(
            grant(r"C:\grants\r"),
            RX,
            "`:read` must grant read+execute only"
        );
    }

    /// M5 pin (partial verdict): the per-session `.sandbox\<sid>` subtree is
    /// granted with a PROTECTED DACL, so it inherits nothing from `$CWD` /
    /// `.sandbox` — session B's inherited `$CWD` allow does not reach session
    /// A's subtree. This pins the already-correct half of M5; the residual
    /// (`.sandbox` itself inheriting RWX) is a separate, not-yet-approved fix,
    /// which is why the parent entry is asserted NOT protected here.
    #[test]
    fn per_session_subtree_entries_are_protected() {
        let fs = FilesystemSlice::default();
        let entries = build_allowlist("m5-sid", std::path::Path::new(r"C:\proj"), &fs).unwrap();
        let subtree: Vec<&AllowEntry> = entries
            .iter()
            .filter(|e| e.label.starts_with(".sandbox/"))
            .collect();
        assert_eq!(
            subtree.len(),
            4,
            "the per-session subtree grants exactly <sid>, bin, venv, pyshim: {:?}",
            subtree.iter().map(|e| &e.label).collect::<Vec<_>>()
        );
        for e in &subtree {
            assert!(
                e.protected,
                "{} must be PROTECTED so the subtree inherits nothing (M5)",
                e.label
            );
        }
        // The `.sandbox` parent is now PROTECTED too (M5 residual closed): the
        // per-session subtrees stop inheritance at their own boundary, and the
        // parent no longer inherits the broad `$CWD` allow either.
        let parent = entries
            .iter()
            .find(|e| e.label == ".sandbox")
            .expect("the .sandbox parent grant must exist");
        assert!(
            parent.protected,
            "the .sandbox parent must be PROTECTED as well (M5 residual)"
        );
    }

    /// M2: a jvm-profile policy must carry descendant deny ACEs for the whole
    /// builtin credential-file set — `~/.gradle/gradle.properties`,
    /// `~/.m2/settings.xml`, `~/.cargo/credentials.toml`,
    /// `~/.git-credentials`, `~/.docker/config.json`, `~/.kube/config`,
    /// `~/.config/gh`, `%APPDATA%\NuGet\NuGet.Config` and `~/.pypirc` — while
    /// the `.gradle`/`.m2` directory grants stay. Whole-dir denies would make
    /// the jvm profile unlaunchable: the deny contains the grant, and the
    /// pre-flight refuses such a session (see the verdict's fix note).
    ///
    /// `~/.npmrc` is deliberately NOT denied — npm must read it to
    /// authenticate at all (trade-off documented in `profiles/README.md`) — so
    /// it is asserted ABSENT from the deny set, not merely left out.
    ///
    /// This drives `build_allowlist_with` with the unfiltered builtin file
    /// set so the assertions pin the policy's shape rather than which
    /// credential files happen to exist on this host (`build_allowlist`
    /// skips missing files at apply time; see its comment).
    #[test]
    fn m2_jvm_profile_denies_gradle_properties_and_maven_settings() {
        let _env = crate::env_lock();
        // `jvm.json` references `$JAVA_HOME` in read_only; the variable is not
        // needed for the deny assertions, so provide a placeholder when the
        // host lacks one (restored on drop, even on panic).
        struct EnvGuard(Option<std::ffi::OsString>);
        impl Drop for EnvGuard {
            fn drop(&mut self) {
                unsafe {
                    match self.0.take() {
                        Some(v) => std::env::set_var("JAVA_HOME", v),
                        None => std::env::remove_var("JAVA_HOME"),
                    }
                }
            }
        }
        let java_guard = EnvGuard(std::env::var_os("JAVA_HOME"));
        if java_guard.0.is_none() {
            unsafe { std::env::set_var("JAVA_HOME", r"C:\java\placeholder") }
        }

        let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let jvm_profile = manifest.join("profiles").join("jvm.json");
        let cwd = manifest.clone();
        let resolved =
            crate::profile::load_and_resolve(jvm_profile.to_string_lossy().as_ref(), &cwd)
                .expect("the shipped jvm profile must load");
        let entries = build_allowlist_with(
            "m2-sid",
            &cwd,
            &resolved.filesystem,
            &crate::profile::credential_denies()
                .into_iter()
                .filter(|c| c.kind == crate::profile::DenyKind::Dir)
                .map(|c| c.path)
                .collect::<Vec<_>>(),
            &crate::profile::credential_denies()
                .into_iter()
                .filter(|c| c.kind == crate::profile::DenyKind::File)
                .map(|c| c.path)
                .collect::<Vec<_>>(),
        )
        .expect("the jvm profile must build an allowlist");

        // M3: the credential-deny base is the OS-known profile root (with a
        // USERPROFILE fallback), so the `want` list is spelled from the same
        // source the production code asks — not from an env variable another
        // test could be repointing under this suite's env lock.
        let home = crate::profile::system_profile_root()
            .or_else(|| std::env::var_os("USERPROFILE").map(std::path::PathBuf::from))
            .expect("the profile root is needed to spell the grants");
        let appdata = std::path::PathBuf::from(
            std::env::var_os("APPDATA").expect("APPDATA is needed to spell NuGet.Config"),
        );
        // The full M2 set, spelled independently of `builtin_deny_files` so a
        // silent deletion from that list fails HERE instead of shipping.
        let want = [
            home.join(".gradle").join("gradle.properties"),
            home.join(".m2").join("settings.xml"),
            home.join(".cargo").join("credentials.toml"),
            home.join(".git-credentials"),
            home.join(".docker").join("config.json"),
            home.join(".kube").join("config"),
            home.join(".config").join("gh"),
            home.join(".pypirc"),
            appdata.join("NuGet").join("NuGet.Config"),
        ];
        let file_denies: Vec<&AllowEntry> = entries
            .iter()
            .filter(|e| e.deny && e.label.starts_with("builtin-deny-file:"))
            .collect();
        assert_eq!(
            file_denies.len(),
            want.len(),
            "every builtin credential file must be denied exactly once (and nothing else may \
             join the set); denies: {:?}",
            file_denies
                .iter()
                .map(|e| &e.win32_path)
                .collect::<Vec<_>>()
        );
        for file in &want {
            let hit = file_denies
                .iter()
                .find(|e| paths_eq_ci(&e.win32_path, file))
                .unwrap_or_else(|| {
                    panic!(
                        "the jvm policy must deny {file:?} (a credential file inside a granted \
                         tree); file denies: {:?}",
                        file_denies
                            .iter()
                            .map(|e| &e.win32_path)
                            .collect::<Vec<_>>()
                    )
                });
            assert_ne!(
                hit.access, 0,
                "the file deny for {file:?} must carry a real mask — a zero-mask deny ACE \
                 denies nothing (C1, applied to files)"
            );
            assert!(
                !hit.inherit,
                "the deny for {file:?} must be non-inheritable: a file has no children to \
                 shield, and an inheritable ACE only invites a pointless propagation walk"
            );
        }
        // The deliberately-undenied credential: ~/.npmrc stays readable because
        // npm needs the token in it to reach any registry at all.
        let npmrc = home.join(".npmrc");
        assert!(
            entries
                .iter()
                .all(|e| !e.deny || !paths_eq_ci(&e.win32_path, &npmrc)),
            "~/.npmrc must NOT be denied: npm reads the token from it to authenticate, and \
             denying it breaks every authenticated install (the trade-off is documented in \
             profiles/README.md, not fixed by a deny)"
        );
        // The directory grants themselves must stay (whole-dir denies are the
        // explicitly rejected alternative).
        for dir in [".gradle", ".m2"] {
            assert!(
                entries
                    .iter()
                    .any(|e| !e.deny && e.win32_path == home.join(dir)),
                "the {dir} directory grant must survive the descendant denies"
            );
        }
    }

    /// M2 pre-flight half: the builtin file denies take part in the same
    /// deny-covers-grant refusal the directory denies use. A grant of the
    /// credential FILE is refused (the operator asked for a credential),
    /// while a grant of the PARENT DIRECTORY passes — the deny applies to
    /// the file, not the tree that holds it. That asymmetry is the whole
    /// point: it is what keeps `jvm.json` launchable with `.gradle`/`.m2`
    /// granted RWX.
    #[test]
    fn m2_a_credential_file_grant_is_refused_but_the_parent_dir_passes() {
        let home = std::path::PathBuf::from(r"C:\Users\test");
        let file = home.join(".gradle").join("gradle.properties");
        // (a) Granting the file itself, ON TOP OF the legitimate directory
        // grant: the pre-flight refuses the session because one grant names a
        // credential file. The directory grant does not rescue it.
        let fs = FilesystemSlice {
            allow: vec![home.join(".gradle"), file.clone()],
            ..Default::default()
        };
        let err = match build_allowlist_with(
            "m2-sid",
            std::path::Path::new(r"C:\proj"),
            &fs,
            &[],
            std::slice::from_ref(&file),
        ) {
            Ok(_) => panic!("a grant of the credential file must be refused"),
            Err(e) => e,
        };
        assert!(
            err.message().contains("deny covers grant"),
            "the refusal must be the pre-flight's named error, not an accident: {}",
            err.message()
        );
        // (b) Granting the parent directory: allowed, and the file deny ships
        // beside it with a real mask.
        let fs = FilesystemSlice {
            allow: vec![home.join(".gradle")],
            ..Default::default()
        };
        let entries = build_allowlist_with(
            "m2-sid",
            std::path::Path::new(r"C:\proj"),
            &fs,
            &[],
            std::slice::from_ref(&file),
        )
        .expect("the parent directory grant must pass - the deny applies to the file, not the dir");
        assert!(
            entries
                .iter()
                .any(|e| !e.deny && e.win32_path == home.join(".gradle")),
            "the .gradle directory grant must stay in the allowlist"
        );
        let deny = entries
            .iter()
            .find(|e| e.deny && e.win32_path == file)
            .expect("the credential-file deny must ship with the parent grant");
        assert_ne!(
            deny.access, 0,
            "the file deny needs a real mask - a zero-mask deny is a no-op and the inherited \
             .gradle allow reads gradle.properties (C1's lesson, applied to files)"
        );
    }

    /// The six builtin deny directories (the AppContainer builtin set — a
    /// superset of the mxc backend's four `PROFILE_SECRET_DIRS`, adding the
    /// two `.saife` control-plane trees).
    fn builtin_deny_dir_set(home: &std::path::Path) -> Vec<std::path::PathBuf> {
        let local = home.join("AppData").join("Local");
        [".ssh", ".aws", ".azure", ".gnupg", ".saife"]
            .iter()
            .map(|d| home.join(d))
            .chain(std::iter::once(local.join("saife")))
            .collect()
    }
    /// 2026-11-10: the exposure resolver sits in front of the pre-flight, so a
    /// session cannot start with a half-understood exposure: a label that names
    /// a private-key tree (`.ssh`) or one that names nothing is refused before
    /// a single ACE is written.
    #[test]
    fn a_secret_or_unknown_exposure_refuses_before_any_grant() {
        let _env = crate::env_lock();
        let home = std::path::PathBuf::from(
            std::env::var_os("USERPROFILE").expect("USERPROFILE must be set"),
        );
        let fs = FilesystemSlice {
            allow: vec![],
            read_only: vec![],
            deny: vec![],
        };

        let err = match build_allowlist_exposed("x-ssh", &home, &fs, &["ssh".to_string()]) {
            Err(e) => e,
            Ok(_) => panic!("a private-key tree is never exposable"),
        };
        assert!(err.to_string().contains("ssh"), "refuses by label: {err}");

        let err = match build_allowlist_exposed("x-typo", &home, &fs, &["ghh".to_string()]) {
            Err(e) => e,
            Ok(_) => panic!("a typo must not silently no-op"),
        };
        assert!(
            err.to_string().contains("ghh") && err.to_string().contains("gh"),
            "names the typo and the real labels: {err}"
        );
    }
}
