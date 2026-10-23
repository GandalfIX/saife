//! Plugins: host-side sidecars a sandboxed workload reaches only through the
//! session proxy.
//!
//! A plugin is a directory under a *plugin root* — `%USERPROFILE%\.saife\plugins\<name>\`
//! by default, plus any `--plugin-dir <PATH>` the operator names, in the order
//! given — holding a `plugin.json` manifest and whatever its sidecar needs beside
//! it (the POC sample is `python sidecar.py`). The supervisor reads the manifest,
//! starts the sidecar **outside** the container on host loopback with a
//! per-session facade token, waits for its health probe, and registers the mount
//! in [`FacadeRegistry`].
//!
//! Inside the container the workload can only name
//! `http://<mount>.sandbox.invalid/…`: the session proxy recognises the reserved
//! suffix ([`facade_mount`]), relays the request to the sidecar's loopback port
//! with the facade token, and never dials the name (it does not resolve). A
//! `CONNECT` to the same host is refused, so TLS cannot be tunnelled past the
//! check.
//!
//! # Two roots, one trust rule
//!
//! Explicit `--plugin-dir` roots are searched first, then the global root; the
//! first hit for a name wins and a later root is *shadowed*, never merged.
//!
//! Nothing inside a workspace is discovered implicitly. A cloned repository must
//! never gain host-side process execution from the act of running `saife run`
//! in it, so repo-local plugins are usable only when the operator names the
//! directory on the command line.
//!
//! # The deputy boundary
//!
//! The sidecar runs with the supervisor's own token and its network access;
//! whatever it exposes, the untrusted workload can call. That is why a manifest
//! declares `operations` rather than proxying arbitrary URLs, and why the
//! transport is a plain-HTTP facade with its own per-session token instead of a
//! second loopback port or a socket.

// A build WITHOUT `mxc-backend` refuses `--plugin` by name
// (`plugin_unsupported_backend`) because plugins are wired on the MXC session
// path only, so the supervisor half of this module has no reachable production
// caller there — and the manifest is a CONTRACT whose later fields (`secrets`,
// `operations`, `version`) are validated but intentionally unconsumed until the
// secret milestone. Both facts are stated once, here, instead of as a dozen
// per-item gates that would also drop these tests from the
// `--no-default-features` lane. The always-compiled half (`FacadeRegistry`,
// `FacadeTarget`, `facade_mount`) is used by `net::proxy` in every build, and
// every item below has a caller or a test in the default lane.
#![allow(dead_code)]

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{Context, Result, bail};
use serde::Deserialize;

/// The sidecar supervisor: spawn, health gate, teardown.
pub mod sidecar;

/// The reserved host suffix that turns a mount into a facade host.
///
/// `.invalid` is RFC 2606 reserved, so this name never resolves anywhere.
pub const FACADE_SUFFIX: &str = ".sandbox.invalid";

/// The manifest file's name inside a plugin directory.
pub const PLUGIN_ENTRY: &str = "plugin.json";

/// The label printed for the global root in refusals and docs.
pub const GLOBAL_ROOT_LABEL: &str = r"%USERPROFILE%\.saife\plugins";

/// One plugin's parsed `plugin.json`.
///
/// `deny_unknown_fields` is deliberate: a typo in a key must be a refusal, not a
/// silently ignored setting on a process that runs with the supervisor's rights.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PluginManifest {
    /// Manifest schema. Required: an unversioned manifest is not guessable.
    ///
    /// Validated on load; no production caller branches on it yet.
    pub schema_version: u32,
    /// Must equal the directory name (checked by [`read_manifest`]).
    pub name: String,
    /// Documented in the manifest; unread by the POC.
    #[serde(default)]
    pub version: Option<String>,
    /// Documented in the manifest; unread by the POC.
    #[serde(default)]
    pub description: Option<String>,
    /// The facade label: exactly one lowercase DNS label, no dots.
    pub mount: String,
    /// `command[0]` is a program resolved through `PATH`/`PATHEXT`; the rest are
    /// arguments. The sidecar's cwd is the plugin directory.
    pub command: Vec<String>,
    pub health: HealthSpec,
    /// The operations this plugin exposes. Parsed and validated; the POC relays
    /// `GET` only and does not enforce the list itself (the sample sidecar
    /// enforces its own paths).
    /// Declared and validated; the supervisor does not enforce it yet.
    #[serde(default)]
    pub operations: Vec<Operation>,
    /// Secret **names** only. The POC parses and validates these but resolves
    /// none of them: no value is read, stored or passed to the sidecar.
    /// Declared and validated; nothing is resolved until the secret milestone.
    #[serde(default)]
    pub secrets: Vec<SecretDecl>,
    /// Non-secret configuration, one env var per entry
    /// (`SIDECAR_CFG_<UPPER_SNAKE>`; `upstream` also arrives as
    /// `SIDECAR_UPSTREAM`).
    #[serde(default)]
    pub config: BTreeMap<String, String>,
}

/// How the supervisor waits for a sidecar to become usable.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthSpec {
    /// Absolute path (must start with `/`) polled with `GET … HTTP/1.0`.
    pub path: String,
    /// Total budget for the gate.
    pub timeout_ms: u64,
    /// Pause between probes.
    pub interval_ms: u64,
}

/// One `(method, path)` a plugin declares.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Operation {
    pub method: String,
    pub path: String,
}

/// A secret the plugin wants, by **name**. Unused by the POC (see
/// [`PluginManifest::secrets`]).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretDecl {
    pub name: String,
    #[serde(default)]
    pub required: bool,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub pattern: Option<String>,
}

/// One loaded plugin: the directory that is the sidecar's cwd, and its manifest.
#[derive(Debug, Clone)]
pub struct Plugin {
    pub dir: PathBuf,
    pub manifest: PluginManifest,
}

/// One place plugins are looked up, with the label a refusal prints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginRoot {
    pub label: String,
    pub path: PathBuf,
}

/// A mount the facade may relay to: the sidecar's loopback port and the token
/// only the supervisor and that sidecar know.
///
/// `Debug` is hand-written and redacts the token: a `{:?}` of session state must
/// not put a credential in a log line.
#[derive(Clone)]
pub struct FacadeTarget {
    pub mount: String,
    pub port: u16,
    pub token: String,
}

impl std::fmt::Debug for FacadeTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FacadeTarget")
            .field("mount", &self.mount)
            .field("port", &self.port)
            .field("token", &"<redacted>")
            .finish()
    }
}

/// This session's mounts.
///
/// Interior mutability is what lets the supervisor keep the order "proxy binds,
/// then plugins spawn": the listener holds one `Arc` of this registry from the
/// moment it exists, and every mount it can serve is inserted afterwards. A
/// request that arrives before its mount is registered answers `404` — an empty
/// registry is a valid, fully-closed state (the AppContainer path and
/// `--block-net` both use it).
#[derive(Debug, Default)]
pub struct FacadeRegistry {
    by_mount: Mutex<HashMap<String, FacadeTarget>>,
}

impl FacadeRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a mount. A duplicate is refused: two plugins answering for one
    /// facade host would make the audit useless and the routing arbitrary.
    pub fn insert(&self, target: FacadeTarget) -> Result<()> {
        let mut map = self.by_mount.lock().unwrap_or_else(|e| e.into_inner());
        if map.contains_key(&target.mount) {
            bail!(
                "facade_mount_taken: a mount named `{}` is already registered in this session",
                target.mount
            );
        }
        map.insert(target.mount.clone(), target);
        Ok(())
    }

    /// The target for `mount`, cloned: the registry is shared with the async
    /// handlers, so it cannot hand out a reference.
    pub fn lookup(&self, mount: &str) -> Option<FacadeTarget> {
        self.by_mount
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(mount)
            .cloned()
    }
}

/// The mount a facade host names, or `None` when `host` is an ordinary host.
///
/// Exactly one label under [`FACADE_SUFFIX`]: `tngtech.sandbox.invalid` is a
/// mount, while the bare suffix, a two-label prefix (`a.b.sandbox.invalid`) and
/// a lookalike (`x.sandbox.invalid.evil.com`) are not. The case-insensitive
/// compare is on ASCII bytes only, and `get()` keeps a multi-byte host from
/// panicking at a non-boundary index.
pub fn facade_mount(host: &str) -> Option<&str> {
    let idx = host.len().checked_sub(FACADE_SUFFIX.len())?;
    let suffix = host.get(idx..)?;
    if !suffix.eq_ignore_ascii_case(FACADE_SUFFIX) {
        return None;
    }
    let label = host.get(..idx)?;
    if label.is_empty() || label.contains('.') {
        return None;
    }
    Some(label)
}

/// A mount name: one lowercase DNS label, `^[a-z0-9][a-z0-9-]{0,30}$`.
///
/// A dot is refused rather than truncated: `a.b` in a mount would forge a second
/// label in the facade host and let one plugin answer for a name it does not own.
pub fn validate_mount(mount: &str) -> Result<()> {
    let bytes = mount.as_bytes();
    let first_ok = bytes
        .first()
        .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit());
    let rest_ok = bytes
        .iter()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-');
    if !first_ok || !rest_ok || bytes.len() > 31 {
        bail!(
            "plugin_manifest_invalid: mount `{mount}` is not one lowercase DNS label (`^[a-z0-9][a-z0-9-]{{0,30}}$`)"
        );
    }
    Ok(())
}

/// The global plugin root, `%USERPROFILE%\.saife\plugins`.
///
/// `USERPROFILE` rather than a hardcoded account: this file ships to machines
/// whose user is not the developer's.
pub fn global_plugins_root() -> Result<PathBuf> {
    let profile = std::env::var_os("USERPROFILE").context(
        "plugin_roots_unresolved: USERPROFILE is not set, so the global plugin root has no location",
    )?;
    Ok(PathBuf::from(profile).join(".saife").join("plugins"))
}

/// The roots for one session, in discovery order: `--plugin-dir` values exactly
/// as given, then the global root.
pub fn plugin_roots_in(global: &Path, plugin_dirs: &[PathBuf]) -> Vec<PluginRoot> {
    let mut roots: Vec<PluginRoot> = plugin_dirs
        .iter()
        .map(|p| PluginRoot {
            label: format!("--plugin-dir {}", p.display()),
            path: p.clone(),
        })
        .collect();
    roots.push(PluginRoot {
        label: GLOBAL_ROOT_LABEL.to_string(),
        path: global.to_path_buf(),
    });
    roots
}

/// [`plugin_roots_in`] with the global root taken from the environment.
pub fn plugin_roots(plugin_dirs: &[PathBuf]) -> Result<Vec<PluginRoot>> {
    Ok(plugin_roots_in(&global_plugins_root()?, plugin_dirs))
}

/// Load a plugin by name from the session's roots.
pub fn load_plugin(name: &str, plugin_dirs: &[PathBuf]) -> Result<Plugin> {
    let roots = plugin_roots(plugin_dirs)?;
    load_plugin_from(&roots, name)
}

/// Load a plugin by name from an explicit root list (first hit wins).
///
/// A name found in no root is a refusal that names the name **and every root
/// searched**, so an operator can see which `--plugin-dir` was consulted and in
/// what order.
pub fn load_plugin_from(roots: &[PluginRoot], name: &str) -> Result<Plugin> {
    validate_plugin_name(name)?;
    let mut searched = Vec::with_capacity(roots.len());
    for root in roots {
        searched.push(root.label.clone());
        let dir = root.path.join(name);
        let manifest_path = dir.join(PLUGIN_ENTRY);
        if manifest_path.is_file() {
            let manifest = read_manifest(&manifest_path, name)?;
            return Ok(Plugin { dir, manifest });
        }
    }
    bail!(
        "plugin_not_found: {name} (searched: {})",
        searched.join(", ")
    )
}

/// A plugin name is one directory label. Dots and separators are refused so a
/// name can never address a path outside its root.
fn validate_plugin_name(name: &str) -> Result<()> {
    let valid = !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_');
    if !valid {
        bail!(
            "plugin_name_invalid: `{name}` (one directory label: lowercase letters, digits, `-`, `_`)"
        );
    }
    Ok(())
}

/// Read + validate one manifest. Every refusal below is a named error: the
/// session path prints it as-is and exits 5.
fn read_manifest(path: &Path, requested: &str) -> Result<PluginManifest> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("plugin_manifest_unreadable: {}", path.display()))?;
    let manifest: PluginManifest = serde_json::from_str(&raw)
        .map_err(|e| anyhow::anyhow!("plugin_manifest_invalid: {}: {e}", path.display()))?;
    if manifest.name != requested {
        bail!(
            "plugin_name_mismatch: {} declares `{}` but its directory is `{requested}`",
            path.display(),
            manifest.name
        );
    }
    validate_mount(&manifest.mount)?;
    if manifest.command.is_empty() || manifest.command[0].trim().is_empty() {
        bail!(
            "plugin_manifest_invalid: {}: `command` must start with a program",
            path.display()
        );
    }
    if !manifest.health.path.starts_with('/') {
        bail!(
            "plugin_manifest_invalid: {}: `health.path` must be an absolute path",
            path.display()
        );
    }
    if manifest.health.timeout_ms == 0 || manifest.health.interval_ms == 0 {
        bail!(
            "plugin_manifest_invalid: {}: `health.timeout_ms` and `health.interval_ms` must be non-zero",
            path.display()
        );
    }
    Ok(manifest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn scratch(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!(
            "sandbox-plugin-{label}-{}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A valid manifest with `extra` spliced in before the closing brace.
    fn manifest_json(name: &str, mount: &str, extra: &str) -> String {
        format!(
            r#"{{"schema_version":1,"name":"{name}","mount":"{mount}",
               "command":["python","sidecar.py"],
               "health":{{"path":"/status","timeout_ms":15000,"interval_ms":250}},
               "operations":[{{"method":"GET","path":"/"}}]{extra}}}"#
        )
        .replace('\n', "")
    }

    fn install(root: &Path, name: &str, body: &str) {
        let dir = root.join(name);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(PLUGIN_ENTRY), body).unwrap();
    }

    // ---- the repo sample is the parser's fixture -------------------------

    #[test]
    fn the_repo_sample_manifest_parses_and_validates() {
        let json = include_str!("../../plugins/tngtech/plugin.json");
        let m: PluginManifest = serde_json::from_str(json).expect("the sample must parse");
        validate_mount(&m.mount).expect("the sample's mount must be valid");
        assert_eq!(m.schema_version, 1);
        assert_eq!(m.name, "tngtech");
        assert_eq!(m.mount, "tngtech");
        assert_eq!(m.health.path, "/status");
        assert_eq!(m.health.timeout_ms, 15000);
        assert_eq!(m.health.interval_ms, 250);
        assert_eq!(m.command.first().map(String::as_str), Some("python"));
        assert_eq!(
            m.config.get("upstream").map(String::as_str),
            Some("https://www.tngtech.com/")
        );
        assert!(m.secrets.is_empty(), "the POC plugin needs no secret");
        assert_eq!(m.operations.len(), 1);
        assert_eq!(m.operations[0].method, "GET");
        assert_eq!(m.operations[0].path, "/");
    }

    // ---- validation matrix -----------------------------------------------

    #[test]
    fn a_missing_schema_version_is_refused() {
        let root = scratch("no-schema");
        install(
            &root,
            "x",
            r#"{"name":"x","mount":"x","command":["python"],
                "health":{"path":"/status","timeout_ms":1,"interval_ms":1}}"#,
        );
        let err = load_plugin_from(&global_only(&root), "x")
            .expect_err("a manifest without schema_version must be refused");
        assert!(
            err.to_string().contains("schema_version"),
            "the refusal must name the missing field: {err}"
        );
    }

    #[test]
    fn an_unknown_manifest_field_is_refused() {
        let root = scratch("unknown-field");
        install(&root, "x", &manifest_json("x", "x", r#","surprise":true"#));
        let err = load_plugin_from(&global_only(&root), "x")
            .expect_err("deny_unknown_fields must refuse a stray key");
        assert!(
            err.to_string().contains("unknown field"),
            "the refusal must name the unknown field: {err}"
        );
    }

    #[test]
    fn mount_must_be_one_lowercase_dns_label() {
        for bad in [
            "",
            "Tngtech",
            "has.dot",
            "-lead",
            "with space",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ] {
            assert!(
                validate_mount(bad).is_err(),
                "mount {bad:?} must be refused"
            );
        }
        for good in ["tngtech", "a", "a1-b2", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"] {
            validate_mount(good).unwrap_or_else(|e| panic!("mount {good:?} must be valid: {e}"));
        }
    }

    #[test]
    fn an_empty_mount_is_refused_by_the_loader() {
        let root = scratch("empty-mount");
        install(&root, "x", &manifest_json("x", "", ""));
        let err =
            load_plugin_from(&global_only(&root), "x").expect_err("an empty mount must be refused");
        assert!(err.to_string().contains("mount"), "got: {err}");
    }

    #[test]
    fn a_command_that_does_not_start_with_a_program_is_refused() {
        let root = scratch("no-command");
        install(
            &root,
            "x",
            r#"{"schema_version":1,"name":"x","mount":"x","command":[],
                "health":{"path":"/status","timeout_ms":1,"interval_ms":1}}"#,
        );
        let err = load_plugin_from(&global_only(&root), "x")
            .expect_err("an empty command must be refused");
        assert!(err.to_string().contains("command"), "got: {err}");
    }

    #[test]
    fn a_health_path_that_is_not_absolute_is_refused() {
        let root = scratch("bad-health");
        install(
            &root,
            "x",
            r#"{"schema_version":1,"name":"x","mount":"x","command":["python"],
                "health":{"path":"status","timeout_ms":1,"interval_ms":1}}"#,
        );
        let err = load_plugin_from(&global_only(&root), "x")
            .expect_err("a relative health path must be refused");
        assert!(err.to_string().contains("health.path"), "got: {err}");
    }

    #[test]
    fn a_plugin_name_that_is_a_path_is_refused() {
        let root = scratch("bad-name");
        for bad in ["../escape", "a/b", "..", "Upper"] {
            let err = load_plugin_from(&global_only(&root), bad)
                .expect_err("a name that is not one directory label must be refused");
            assert!(
                err.to_string().contains("plugin_name_invalid"),
                "got: {err}"
            );
        }
    }

    // ---- discovery: two root kinds, first hit wins -----------------------

    fn global_only(global: &Path) -> Vec<PluginRoot> {
        plugin_roots_in(global, &[])
    }

    #[test]
    fn explicit_roots_are_searched_before_the_global_root() {
        let global = scratch("order-global");
        let a = scratch("order-a");
        let b = scratch("order-b");
        let roots = plugin_roots_in(&global, &[a.clone(), b.clone()]);
        assert_eq!(roots.len(), 3);
        assert_eq!(roots[0].label, format!("--plugin-dir {}", a.display()));
        assert_eq!(roots[1].label, format!("--plugin-dir {}", b.display()));
        assert_eq!(roots[2].label, GLOBAL_ROOT_LABEL);
        assert_eq!(roots[2].path, global);
    }

    #[test]
    fn the_first_root_holding_a_name_shadows_later_ones() {
        let global = scratch("shadow-global");
        let explicit = scratch("shadow-explicit");
        install(&global, "x", &manifest_json("x", "from-global", ""));
        install(&explicit, "x", &manifest_json("x", "from-explicit", ""));

        let roots = plugin_roots_in(&global, std::slice::from_ref(&explicit));
        let loaded = load_plugin_from(&roots, "x").expect("the explicit copy must load");
        assert_eq!(
            loaded.manifest.mount, "from-explicit",
            "an explicit root must shadow the global copy, never merge with it"
        );
        assert_eq!(
            loaded.dir,
            explicit.join("x"),
            "the sidecar's cwd is the hit"
        );
    }

    #[test]
    fn a_name_found_in_no_root_names_the_name_and_every_root_searched() {
        let global = scratch("missing-global");
        let explicit = scratch("missing-explicit");
        let roots = plugin_roots_in(&global, std::slice::from_ref(&explicit));
        let err = load_plugin_from(&roots, "tngtech").expect_err("nothing is installed here");
        let msg = err.to_string();
        assert!(msg.starts_with("plugin_not_found: tngtech"), "got: {msg}");
        assert!(
            msg.contains(&format!("--plugin-dir {}", explicit.display())),
            "the refusal must list each explicit root: {msg}"
        );
        assert!(msg.contains(GLOBAL_ROOT_LABEL), "got: {msg}");
    }

    // ---- registry --------------------------------------------------------

    fn target(mount: &str, port: u16) -> FacadeTarget {
        FacadeTarget {
            mount: mount.to_string(),
            port,
            token: "0123456789abcdef0123456789abcdef".to_string(),
        }
    }

    #[test]
    fn the_registry_refuses_a_duplicate_mount() {
        let reg = FacadeRegistry::new();
        reg.insert(target("tngtech", 1)).expect("first insert");
        let err = reg
            .insert(target("tngtech", 2))
            .expect_err("a duplicate mount must be refused");
        assert!(err.to_string().contains("facade_mount_taken"), "got: {err}");
        assert_eq!(
            reg.lookup("tngtech").map(|t| t.port),
            Some(1),
            "the refusal must not replace the registered target"
        );
    }

    #[test]
    fn lookup_returns_none_for_an_unregistered_mount() {
        let reg = FacadeRegistry::new();
        assert!(reg.lookup("nope").is_none());
        reg.insert(target("tngtech", 9)).unwrap();
        let hit = reg.lookup("tngtech").expect("registered");
        assert_eq!(hit.port, 9);
        assert!(
            !format!("{hit:?}").contains(&hit.token),
            "Debug must redact the token"
        );
    }

    // ---- facade host parsing --------------------------------------------

    #[test]
    fn facade_hosts_are_exactly_one_label_under_the_reserved_suffix() {
        assert_eq!(facade_mount("tngtech.sandbox.invalid"), Some("tngtech"));
        assert_eq!(
            facade_mount("TNGTECH.Sandbox.Invalid"),
            Some("TNGTECH"),
            "the suffix compare is case-insensitive"
        );
        assert_eq!(
            facade_mount("sandbox.invalid"),
            None,
            "the bare suffix names no mount"
        );
        assert_eq!(
            facade_mount("tngtech.sandbox.invalid.evil.com"),
            None,
            "a lookalike suffix is not a facade host"
        );
        assert_eq!(facade_mount("a.b.sandbox.invalid"), None, "two labels");
        assert_eq!(facade_mount(".sandbox.invalid"), None, "no label");
        assert_eq!(facade_mount("api.example.com"), None);
    }
}
