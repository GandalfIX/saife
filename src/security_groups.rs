//! Security group expansion (FR-5.4).
//!
//! Profiles may declare `security.groups: ["python_runtime", "node_runtime",
//! ...]`. Each group name expands into a set of concrete filesystem paths
//! that the sandboxed process needs in order to run that toolchain. Group
//! paths are granted READ+EXECUTE (RX) — the toolchain must *run* its
//! binaries and *read* its stdlib, but a compromised agent must not be able
//! to *write* to the shared install.
//!
//! The expansion is pure logic over an injected [`EnvProbe`] so it is fully
//! unit-testable (Tier 1 in `docs/testing-principles.md`) without touching
//! the real registry, PATH, or filesystem.
//!
//! `windows_common` is NOT handled here — it is force-added by
//! `sandbox::allowlist::build_allowlist` and is implicit (not user-selectable
//! in profiles).

use std::path::{Path, PathBuf};

/// Abstraction over the host environment that the group resolver queries.
///
/// In production this is backed by real env vars + `std::fs` existence
/// checks + a `PATH` walk (see [`HostEnv`]). In tests it is backed by a
/// `FakeEnv` with hardcoded values.
pub trait EnvProbe {
    /// Look up an environment variable (`USERPROFILE`, `JAVA_HOME`, …).
    fn env_var(&self, name: &str) -> Option<String>;

    /// Return the `PATH` entries, left-to-right.
    fn path_entries(&self) -> Vec<PathBuf>;

    /// Return the directory containing `bin_name` (e.g. `python.exe`) by
    /// searching `PATH` left to right. `None` if not found.
    fn find_in_path(&self, bin_name: &str) -> Option<PathBuf>;

    /// Return `true` if the path exists on disk.
    fn exists(&self, path: &Path) -> bool;
}

/// Production [`EnvProbe`] backed by real env + filesystem.
pub struct HostEnv;

impl EnvProbe for HostEnv {
    fn env_var(&self, name: &str) -> Option<String> {
        std::env::var_os(name).map(|o| o.to_string_lossy().to_string())
    }

    fn path_entries(&self) -> Vec<PathBuf> {
        std::env::var_os("PATH")
            .map(|p| std::env::split_paths(&p).collect())
            .unwrap_or_default()
    }

    fn find_in_path(&self, bin_name: &str) -> Option<PathBuf> {
        for dir in self.path_entries() {
            let candidate = dir.join(bin_name);
            if std::fs::metadata(&candidate).is_ok() {
                return Some(dir);
            }
        }
        None
    }

    fn exists(&self, path: &Path) -> bool {
        std::fs::metadata(path).is_ok()
    }
}

/// A single resolved grant from a security group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupGrant {
    pub path: PathBuf,
    /// `true` = recursive (subtree). `false` = the dir itself only.
    pub recursive: bool,
    /// A human-readable label identifying the source group, for diagnostics.
    pub label: &'static str,
}

/// Expand a list of security-group names into concrete grants.
///
/// Unknown group names are silently skipped (the toolchain simply isn't
/// installed on this machine). The caller may surface them as warnings.
///
/// Returns the grants in group-declaration order. De-duplication across
/// groups is the caller's responsibility (the allow-list builder already
/// de-dupes via `dedupe_paths`).
pub fn resolve_groups(probe: &dyn EnvProbe, groups: &[String]) -> Vec<GroupGrant> {
    let mut out = Vec::new();
    for g in groups {
        let grants = match g.as_str() {
            "python_runtime" => resolve_python(probe),
            "node_runtime" => resolve_node(probe),
            "rust_runtime" => resolve_rust(probe),
            "java_runtime" => resolve_java(probe),
            "git_runtime" => resolve_git(probe),
            "dotnet_runtime" => resolve_dotnet(probe),
            "windows_common" => {
                // Implicit — added by the allowlist builder, not by profile
                // expansion. Treat as a no-op here so profiles that list it
                // do not error.
                Vec::new()
            }
            _ => {
                eprintln!(
                    "[sandbox] warning: unknown security group `{g}` (skipped)"
                );
                Vec::new()
            }
        };
        out.extend(grants);
    }
    out
}

fn resolve_python(probe: &dyn EnvProbe) -> Vec<GroupGrant> {
    const LABEL: &str = "python_runtime";
    let mut out = Vec::new();
    if let Some(dir) = probe.find_in_path("python.exe") {
        out.push(GroupGrant { path: dir, recursive: false, label: LABEL });
    }
    push_env_dir(probe, "LOCALAPPDATA", &["Programs", "Python"], true, LABEL, &mut out);
    push_env_dir(probe, "LOCALAPPDATA", &["pip", "Cache"], true, LABEL, &mut out);
    push_env_dir(probe, "APPDATA", &["Python"], true, LABEL, &mut out);
    out
}

fn resolve_node(probe: &dyn EnvProbe) -> Vec<GroupGrant> {
    const LABEL: &str = "node_runtime";
    let mut out = Vec::new();
    if let Some(dir) = probe.find_in_path("node.exe") {
        out.push(GroupGrant { path: dir, recursive: false, label: LABEL });
    }
    push_env_dir(probe, "APPDATA", &["npm"], false, LABEL, &mut out);
    push_env_dir(probe, "LOCALAPPDATA", &["pnpm"], false, LABEL, &mut out);
    // npm cache: newer layout under LOCALAPPDATA\npm-cache, older under APPDATA\npm-cache.
    push_env_dir(probe, "LOCALAPPDATA", &["npm-cache"], false, LABEL, &mut out);
    push_env_dir(probe, "APPDATA", &["npm-cache"], false, LABEL, &mut out);
    out
}

fn resolve_rust(probe: &dyn EnvProbe) -> Vec<GroupGrant> {
    const LABEL: &str = "rust_runtime";
    let mut out = Vec::new();
    push_env_dir(probe, "USERPROFILE", &[".cargo"], true, LABEL, &mut out);
    push_env_dir(probe, "USERPROFILE", &[".rustup"], true, LABEL, &mut out);
    out
}

fn resolve_java(probe: &dyn EnvProbe) -> Vec<GroupGrant> {
    const LABEL: &str = "java_runtime";
    let mut out = Vec::new();
    if let Some(jh) = probe.env_var("JAVA_HOME") {
        let p = PathBuf::from(&jh);
        if probe.exists(&p) {
            out.push(GroupGrant { path: p, recursive: true, label: LABEL });
        }
    }
    push_env_dir(probe, "USERPROFILE", &[".gradle"], true, LABEL, &mut out);
    push_env_dir(probe, "ProgramFiles", &["Java"], true, LABEL, &mut out);
    push_env_dir(
        probe,
        "ProgramFiles",
        &["Eclipse Adoptium"],
        true,
        LABEL,
        &mut out,
    );
    out
}

fn resolve_git(probe: &dyn EnvProbe) -> Vec<GroupGrant> {
    const LABEL: &str = "git_runtime";
    let mut out = Vec::new();
    if let Some(dir) = probe.find_in_path("git.exe") {
        out.push(GroupGrant { path: dir, recursive: false, label: LABEL });
    }
    push_env_dir(probe, "USERPROFILE", &[".gitconfig"], false, LABEL, &mut out);
    push_env_dir(probe, "LOCALAPPDATA", &["Programs", "Git"], false, LABEL, &mut out);
    out
}

fn resolve_dotnet(probe: &dyn EnvProbe) -> Vec<GroupGrant> {
    const LABEL: &str = "dotnet_runtime";
    let mut out = Vec::new();
    if let Some(dir) = probe.find_in_path("dotnet.exe") {
        out.push(GroupGrant { path: dir, recursive: false, label: LABEL });
    }
    push_env_dir(probe, "USERPROFILE", &[".nuget", "packages"], true, LABEL, &mut out);
    out
}

/// Push `env_var/...sub` if the env var is set and the resulting path exists.
fn push_env_dir(
    probe: &dyn EnvProbe,
    env_var: &str,
    sub: &[&str],
    recursive: bool,
    label: &'static str,
    out: &mut Vec<GroupGrant>,
) {
    let Some(base) = probe.env_var(env_var) else {
        return;
    };
    let mut p = PathBuf::from(base);
    for s in sub {
        p.push(s);
    }
    if probe.exists(&p) {
        out.push(GroupGrant { path: p, recursive, label });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// A fake environment for deterministic unit tests.
    struct FakeEnv {
        vars: HashMap<String, String>,
        path: Vec<PathBuf>,
        /// Paths that "exist on disk" (case-sensitive string match).
        existing: Vec<PathBuf>,
    }

    impl FakeEnv {
        fn new() -> Self {
            FakeEnv {
                vars: HashMap::new(),
                path: Vec::new(),
                existing: Vec::new(),
            }
        }
        fn set(mut self, k: &str, v: &str) -> Self {
            self.vars.insert(k.to_string(), v.to_string());
            self
        }
        fn path(mut self, entries: &[&str]) -> Self {
            self.path = entries.iter().map(PathBuf::from).collect();
            self
        }
        fn exists_at(mut self, p: &str) -> Self {
            self.existing.push(PathBuf::from(p));
            self
        }
    }

    impl EnvProbe for FakeEnv {
        fn env_var(&self, name: &str) -> Option<String> {
            self.vars.get(name).cloned()
        }
        fn path_entries(&self) -> Vec<PathBuf> {
            self.path.clone()
        }
        fn find_in_path(&self, bin_name: &str) -> Option<PathBuf> {
            for dir in &self.path {
                let candidate = dir.join(bin_name);
                if self.existing.iter().any(|e| e == &candidate) {
                    return Some(dir.clone());
                }
            }
            None
        }
        fn exists(&self, path: &Path) -> bool {
            self.existing.iter().any(|e| e.as_path() == path)
        }
    }

    // --- python_runtime ----------------------------------------------------

    #[test]
    fn python_runtime_resolves_python_on_path() {
        let env = FakeEnv::new()
            .path(&[r"C:\Py312", r"C:\Windows\System32"])
            .exists_at(r"C:\Py312\python.exe")
            .set("LOCALAPPDATA", r"C:\Users\test\AppData\Local")
            .set("APPDATA", r"C:\Users\test\AppData\Roaming")
            .exists_at(r"C:\Users\test\AppData\Local\Programs\Python")
            .exists_at(r"C:\Users\test\AppData\Local\pip\Cache")
            .exists_at(r"C:\Users\test\AppData\Roaming\Python");
        let grants = resolve_groups(&env, &["python_runtime".into()]);
        assert!(grants.iter().any(|g| g.path == Path::new(r"C:\Py312") && g.label == "python_runtime" && !g.recursive));
        assert!(grants.iter().any(|g| g.path == Path::new(r"C:\Users\test\AppData\Local\Programs\Python") && g.recursive));
        assert!(grants.iter().any(|g| g.path == Path::new(r"C:\Users\test\AppData\Local\pip\Cache") && g.recursive));
        assert!(grants.iter().any(|g| g.path == Path::new(r"C:\Users\test\AppData\Roaming\Python") && g.recursive));
    }

    #[test]
    fn python_runtime_skips_missing_dirs() {
        // Python on PATH but the Programs\Python dir does not exist.
        let env = FakeEnv::new()
            .path(&[r"C:\Py312"])
            .exists_at(r"C:\Py312\python.exe")
            .set("LOCALAPPDATA", r"C:\Users\test\AppData\Local")
            .set("APPDATA", r"C:\Users\test\AppData\Roaming");
        let grants = resolve_groups(&env, &["python_runtime".into()]);
        // Only the PATH hit should be present; the non-existent env dirs skipped.
        let paths: Vec<PathBuf> = grants.iter().map(|g| g.path.clone()).collect();
        assert_eq!(paths, vec![PathBuf::from(r"C:\Py312")]);
    }

    #[test]
    fn python_runtime_python_not_on_path_is_silent() {
        let env = FakeEnv::new()
            .set("LOCALAPPDATA", r"C:\Users\test\AppData\Local")
            .set("APPDATA", r"C:\Users\test\AppData\Roaming");
        let grants = resolve_groups(&env, &["python_runtime".into()]);
        assert!(grants.is_empty(), "no python on PATH and no existing dirs -> empty");
    }

    // --- node_runtime ------------------------------------------------------

    #[test]
    fn node_runtime_resolves_node_and_caches() {
        let env = FakeEnv::new()
            .path(&[r"C:\node"])
            .exists_at(r"C:\node\node.exe")
            .set("APPDATA", r"C:\Users\test\AppData\Roaming")
            .set("LOCALAPPDATA", r"C:\Users\test\AppData\Local")
            .exists_at(r"C:\Users\test\AppData\Roaming\npm")
            .exists_at(r"C:\Users\test\AppData\Local\pnpm")
            .exists_at(r"C:\Users\test\AppData\Local\npm-cache");
        let grants = resolve_groups(&env, &["node_runtime".into()]);
        let paths: Vec<PathBuf> = grants.iter().map(|g| g.path.clone()).collect();
        assert!(paths.contains(&PathBuf::from(r"C:\node")));
        assert!(paths.contains(&PathBuf::from(r"C:\Users\test\AppData\Roaming\npm")));
        assert!(paths.contains(&PathBuf::from(r"C:\Users\test\AppData\Local\pnpm")));
        assert!(paths.contains(&PathBuf::from(r"C:\Users\test\AppData\Local\npm-cache")));
        // Non-recursive for node.exe dir + npm/pnpm; cache is also non-recursive.
        for g in &grants {
            assert!(!g.recursive, "node_runtime grants should be non-recursive, got {:?}", g);
        }
    }

    // --- rust_runtime ------------------------------------------------------

    #[test]
    fn rust_runtime_resolves_cargo_and_rustup() {
        let env = FakeEnv::new()
            .set("USERPROFILE", r"C:\Users\test")
            .exists_at(r"C:\Users\test\.cargo")
            .exists_at(r"C:\Users\test\.rustup");
        let grants = resolve_groups(&env, &["rust_runtime".into()]);
        let paths: Vec<PathBuf> = grants.iter().map(|g| g.path.clone()).collect();
        assert_eq!(paths, vec![PathBuf::from(r"C:\Users\test\.cargo"), PathBuf::from(r"C:\Users\test\.rustup")]);
        for g in &grants {
            assert!(g.recursive, "rust_runtime grants should be recursive, got {:?}", g);
        }
    }

    #[test]
    fn rust_runtime_skips_when_cargo_missing() {
        let env = FakeEnv::new()
            .set("USERPROFILE", r"C:\Users\test")
            .exists_at(r"C:\Users\test\.rustup"); // .cargo absent
        let grants = resolve_groups(&env, &["rust_runtime".into()]);
        let paths: Vec<PathBuf> = grants.iter().map(|g| g.path.clone()).collect();
        assert_eq!(paths, vec![PathBuf::from(r"C:\Users\test\.rustup")]);
    }

    // --- java_runtime ------------------------------------------------------

    #[test]
    fn java_runtime_resolves_java_home_and_gradle() {
        let env = FakeEnv::new()
            .set("JAVA_HOME", r"C:\Program Files\Java\jdk-21")
            .set("USERPROFILE", r"C:\Users\test")
            .set("ProgramFiles", r"C:\Program Files")
            .exists_at(r"C:\Program Files\Java\jdk-21")
            .exists_at(r"C:\Users\test\.gradle")
            .exists_at(r"C:\Program Files\Java");
        let grants = resolve_groups(&env, &["java_runtime".into()]);
        let paths: Vec<PathBuf> = grants.iter().map(|g| g.path.clone()).collect();
        assert!(paths.contains(&PathBuf::from(r"C:\Program Files\Java\jdk-21")));
        assert!(paths.contains(&PathBuf::from(r"C:\Users\test\.gradle")));
        assert!(paths.contains(&PathBuf::from(r"C:\Program Files\Java")));
        for g in &grants {
            assert!(g.recursive, "java_runtime grants should be recursive, got {:?}", g);
        }
    }

    #[test]
    fn java_runtime_skips_when_java_home_unset() {
        let env = FakeEnv::new()
            .set("USERPROFILE", r"C:\Users\test")
            .set("ProgramFiles", r"C:\Program Files")
            .exists_at(r"C:\Users\test\.gradle");
        let grants = resolve_groups(&env, &["java_runtime".into()]);
        let paths: Vec<PathBuf> = grants.iter().map(|g| g.path.clone()).collect();
        assert_eq!(paths, vec![PathBuf::from(r"C:\Users\test\.gradle")]);
    }

    // --- multi-group + unknown + windows_common ----------------------------

    #[test]
    fn multiple_groups_concatenate() {
        let env = FakeEnv::new()
            .path(&[r"C:\Py312"])
            .exists_at(r"C:\Py312\python.exe")
            .set("USERPROFILE", r"C:\Users\test")
            .set("LOCALAPPDATA", r"C:\Users\test\AppData\Local")
            .set("APPDATA", r"C:\Users\test\AppData\Roaming")
            .exists_at(r"C:\Users\test\.cargo")
            .exists_at(r"C:\Users\test\.rustup");
        let grants = resolve_groups(&env, &["python_runtime".into(), "rust_runtime".into()]);
        // python_runtime -> python.exe dir (1) + rust_runtime -> .cargo + .rustup (2)
        // (env dirs that don't exist are skipped)
        assert!(grants.len() >= 3);
        assert!(grants.iter().any(|g| g.label == "python_runtime"));
        assert!(grants.iter().any(|g| g.label == "rust_runtime"));
    }

    #[test]
    fn unknown_group_is_silently_skipped() {
        let env = FakeEnv::new();
        let grants = resolve_groups(&env, &["nonexistent_runtime".into()]);
        assert!(grants.is_empty());
    }

    #[test]
    fn windows_common_is_noop_when_listed_in_profile() {
        // Profiles may list windows_common; it must not error or duplicate
        // the implicit grant added by build_allowlist.
        let env = FakeEnv::new()
            .set("SystemRoot", r"C:\Windows")
            .exists_at(r"C:\Windows\System32");
        let grants = resolve_groups(&env, &["windows_common".into()]);
        assert!(grants.is_empty(), "windows_common must not be expanded here");
    }

    #[test]
    fn empty_groups_yields_nothing() {
        let env = FakeEnv::new();
        let grants = resolve_groups(&env, &[]);
        assert!(grants.is_empty());
    }

    #[test]
    fn path_search_is_left_to_right() {
        let env = FakeEnv::new()
            .path(&[r"C:\first", r"C:\second"])
            .exists_at(r"C:\first\python.exe")
            .exists_at(r"C:\second\python.exe");
        let grants = resolve_groups(&env, &["python_runtime".into()]);
        // The first PATH entry containing python.exe wins.
        assert!(grants.iter().any(|g| g.path == Path::new(r"C:\first")));
        assert!(!grants.iter().any(|g| g.path == Path::new(r"C:\second")));
    }

    // --- git_runtime -------------------------------------------------------

    #[test]
    fn git_runtime_resolves_git_exe_and_config() {
        let env = FakeEnv::new()
            .path(&[r"C:\Program Files\Git\cmd"])
            .exists_at(r"C:\Program Files\Git\cmd\git.exe")
            .set("USERPROFILE", r"C:\Users\test")
            .set("LOCALAPPDATA", r"C:\Users\test\AppData\Local")
            .exists_at(r"C:\Users\test\.gitconfig")
            .exists_at(r"C:\Users\test\AppData\Local\Programs\Git");
        let grants = resolve_groups(&env, &["git_runtime".into()]);
        let paths: Vec<PathBuf> = grants.iter().map(|g| g.path.clone()).collect();
        assert!(paths.contains(&PathBuf::from(r"C:\Program Files\Git\cmd")));
        assert!(paths.contains(&PathBuf::from(r"C:\Users\test\.gitconfig")));
        assert!(paths.contains(&PathBuf::from(r"C:\Users\test\AppData\Local\Programs\Git")));
        for g in &grants {
            assert!(!g.recursive, "git_runtime grants should be non-recursive, got {:?}", g);
        }
    }

    #[test]
    fn git_runtime_skips_when_git_not_installed() {
        let env = FakeEnv::new()
            .set("USERPROFILE", r"C:\Users\test")
            .set("LOCALAPPDATA", r"C:\Users\test\AppData\Local");
        // No git.exe on PATH, no existing config/install dirs.
        let grants = resolve_groups(&env, &["git_runtime".into()]);
        assert!(grants.is_empty());
    }

    // --- dotnet_runtime ----------------------------------------------------

    #[test]
    fn dotnet_runtime_resolves_dotnet_exe_and_nuget_cache() {
        let env = FakeEnv::new()
            .path(&[r"C:\Program Files\dotnet"])
            .exists_at(r"C:\Program Files\dotnet\dotnet.exe")
            .set("USERPROFILE", r"C:\Users\test")
            .exists_at(r"C:\Users\test\.nuget\packages");
        let grants = resolve_groups(&env, &["dotnet_runtime".into()]);
        let paths: Vec<PathBuf> = grants.iter().map(|g| g.path.clone()).collect();
        assert!(paths.contains(&PathBuf::from(r"C:\Program Files\dotnet")));
        assert!(paths.contains(&PathBuf::from(r"C:\Users\test\.nuget\packages")));
        let dotnet_grant = grants.iter().find(|g| g.path == Path::new(r"C:\Program Files\dotnet")).unwrap();
        assert!(!dotnet_grant.recursive);
        let nuget_grant = grants.iter().find(|g| g.path == Path::new(r"C:\Users\test\.nuget\packages")).unwrap();
        assert!(nuget_grant.recursive);
    }

    #[test]
    fn dotnet_runtime_skips_when_dotnet_missing() {
        let env = FakeEnv::new()
            .set("USERPROFILE", r"C:\Users\test");
        let grants = resolve_groups(&env, &["dotnet_runtime".into()]);
        assert!(grants.is_empty());
    }
}
