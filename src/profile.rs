use anyhow::{Context, Result, bail};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// The filesystem slice of a profile, after merging `extends` and CLI flags.
#[derive(Debug, Default, Clone)]
pub struct FilesystemSlice {
    pub allow: Vec<PathBuf>,
    pub read_only: Vec<PathBuf>,
    pub deny: Vec<PathBuf>,
}

/// The network slice of a profile, after merging `extends` and CLI flags.
#[derive(Debug, Default, Clone)]
pub struct NetworkSlice {
    pub block_net: bool,
    pub allow_domain: Vec<String>,
    pub profile_name: Option<String>,
}

/// The full resolved profile (filesystem slice only for this MVP slice).
#[derive(Debug, Default, Clone)]
pub struct ResolvedProfile {
    /// Profile display name (from `meta.name`, falling back to the
    /// `--profile` argument). Populated by `load_and_resolve` but not
    /// consumed by the supervisor yet — reserved for the `profile show`
    /// subcommand and audit log enrichment.
    #[allow(dead_code)]
    pub name: String,
    pub filesystem: FilesystemSlice,
    pub network: NetworkSlice,
}

/// Raw profile JSON (v1 schema).
#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct RawProfile {
    #[serde(default)]
    pub meta: Option<Meta>,
    #[serde(default)]
    pub extends: Option<String>,
    #[serde(default)]
    pub security: Option<Security>,
    #[serde(default)]
    pub filesystem: Option<RawFilesystem>,
    #[serde(default)]
    pub network: Option<RawNetwork>,
    #[serde(default)]
    pub workdir: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Meta {
    #[serde(default)]
    pub name: String,
    /// `meta.version` / `meta.description` are parsed for schema completeness
    /// and the future `profile show` / `profile list` subcommands; not read
    /// by the supervisor path today.
    #[serde(default)]
    #[allow(dead_code)]
    pub version: String,
    #[serde(default)]
    #[allow(dead_code)]
    pub description: String,
    /// Profile schema version (FR-5.2). Required. Only `1` is supported in
    /// this build (AC-5.16). Validated by [`validate_schema_version`].
    #[serde(default, alias = "schema_version")]
    pub schema_version: Option<u32>,
}

/// The schema version this build of `sandbox` understands.
pub const SUPPORTED_SCHEMA_VERSION: u32 = 1;

/// Validate that the profile declares a supported `meta.schema_version`.
/// Called after parsing, before resolution, so a bad version is reported
/// with a clear message (AC-5.16).
pub fn validate_schema_version(raw: &RawProfile) -> Result<()> {
    let Some(meta) = raw.meta.as_ref() else {
        bail!("missing required field `meta` (schema_version 1 required)");
    };
    let Some(v) = meta.schema_version else {
        bail!("missing required field `meta.schema_version`");
    };
    if v != SUPPORTED_SCHEMA_VERSION {
        bail!(
            "Unsupported profile schema version {v}. This build of sandbox supports schema version {SUPPORTED_SCHEMA_VERSION}."
        );
    }
    Ok(())
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Security {
    #[serde(default)]
    pub groups: Vec<String>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct RawFilesystem {
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub read_only: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RawNetwork {
    #[serde(default)]
    pub block_net: bool,
    #[serde(default)]
    pub allow_domain: Vec<String>,
    #[serde(default)]
    pub profile: Option<String>,
}

/// Load a profile by name or path, resolve `extends`, expand variables, and
/// expand `security.groups` into concrete filesystem paths.
pub fn load_and_resolve(name: &str, cwd: &Path) -> Result<ResolvedProfile> {
    let mut seen: Vec<String> = Vec::new();
    let raw = load_raw_chain(name, cwd, &mut seen)?;
    validate_schema_version(&raw)?;
    let mut fs = resolve_filesystem(&raw.filesystem, cwd)?;
    let resolved_name = raw
        .meta
        .as_ref()
        .map(|m| m.name.clone())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| name.to_string());

    // Expand security groups (FR-5.4). Group paths are RX (read_only
    // semantics). They are appended after the profile's own read_only entries
    // so that dedupe_paths — which preserves the first occurrence — keeps any
    // path already granted RWX (in `allow`) at RWX, not downgraded to RX.
    if let Some(sec) = &raw.security
        && !sec.groups.is_empty()
    {
        let probe = crate::security_groups::HostEnv;
        let grants = crate::security_groups::resolve_groups(&probe, &sec.groups);
        for g in grants {
            fs.read_only.push(g.path);
        }
        fs.read_only = dedupe_paths(fs.read_only);
        // Also drop group paths that already appear in `allow` (RWX),
        // since dedupe_paths only dedupes within one vector.
        let allow_keys: std::collections::BTreeSet<String> = fs
            .allow
            .iter()
            .map(|p| p.to_string_lossy().to_lowercase())
            .collect();
        fs.read_only.retain(|p| !allow_keys.contains(&p.to_string_lossy().to_lowercase()));
    }

    Ok(ResolvedProfile {
        name: resolved_name,
        filesystem: fs,
        network: resolve_network_slice(&raw.network),
    })
}

/// Recursively load a profile and its `extends` chain. The deepest parent is
/// loaded first; the child is merged on top (child keys override, arrays
/// concatenate for filesystem.allow / read_only / deny).
fn load_raw_chain(name: &str, cwd: &Path, seen: &mut Vec<String>) -> Result<RawProfile> {
    if seen.iter().any(|s| s == name) {
        bail!("profile `extends` cycle detected: {}", seen.join(" -> "));
    }
    seen.push(name.to_string());

    let path = resolve_profile_path(name, cwd)?;
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("read profile {}", path.display()))?;
    let raw: RawProfile = serde_json::from_str(&text)
        .with_context(|| format!("parse profile {}", path.display()))?;

    let merged = match raw.extends.as_ref() {
        Some(parent_name) => {
            let parent = load_raw_chain(parent_name, cwd, seen)?;
            merge_profiles(parent, raw)
        }
        None => raw,
    };
    Ok(merged)
}

/// Resolve a profile name to a file path.
/// - `--profile claude-code` -> %USERPROFILE%\.sandbox\profiles\claude-code.json
/// - `--profile ./relative/path.json` -> resolved against cwd
/// - `--profile C:\abs\path.json` -> as-is
fn resolve_profile_path(name: &str, _cwd: &Path) -> Result<PathBuf> {
    let p = Path::new(name);
    if p.is_absolute() || name.ends_with(".json") {
        return Ok(p.to_path_buf());
    }
    // Bare name: look in %USERPROFILE%\.sandbox\profiles\<name>.json
    let userprofile = std::env::var_os("USERPROFILE")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    Ok(userprofile
        .join(".sandbox")
        .join("profiles")
        .join(format!("{name}.json")))
}

/// Merge a parent profile and a child profile (child overrides scalars,
/// arrays concatenate for filesystem entries per FR-5.3).
fn merge_profiles(parent: RawProfile, child: RawProfile) -> RawProfile {
    let filesystem = match (parent.filesystem, child.filesystem) {
        (Some(p), Some(c)) => Some(RawFilesystem {
            allow: dedupe_concat(p.allow, c.allow),
            read_only: dedupe_concat(p.read_only, c.read_only),
            deny: dedupe_concat(p.deny, c.deny),
        }),
        (Some(p), None) => Some(p),
        (None, Some(c)) => Some(c),
        (None, None) => None,
    };
    let network = match (parent.network, child.network) {
        (Some(p), Some(c)) => Some(RawNetwork {
            block_net: c.block_net || p.block_net,
            allow_domain: dedupe_concat(p.allow_domain, c.allow_domain),
            profile: c.profile.or(p.profile),
        }),
        (Some(p), None) => Some(p),
        (None, Some(c)) => Some(c),
        (None, None) => None,
    };
    RawProfile {
        meta: child.meta.or(parent.meta),
        extends: None, // chain already resolved
        security: match (parent.security, child.security) {
            (Some(p), Some(c)) => Some(Security {
                groups: dedupe_concat(p.groups, c.groups),
            }),
            (Some(p), None) => Some(p),
            (None, Some(c)) => Some(c),
            (None, None) => None,
        },
        filesystem,
        network,
        workdir: child.workdir.or(parent.workdir),
    }
}

fn dedupe_concat(a: Vec<String>, b: Vec<String>) -> Vec<String> {
    let mut all: Vec<String> = a;
    all.extend(b);
    let mut seen: BTreeMap<String, ()> = BTreeMap::new();
    all.retain(|x| {
        let key = x.to_lowercase();
        if let std::collections::btree_map::Entry::Vacant(e) = seen.entry(key) {
            e.insert(());
            true
        } else {
            false
        }
    });
    all
}

/// Resolve a filesystem slice: expand variables in each path entry.
fn resolve_filesystem(raw: &Option<RawFilesystem>, cwd: &Path) -> Result<FilesystemSlice> {
    let empty = RawFilesystem::default();
    let raw = raw.as_ref().unwrap_or(&empty);
    Ok(FilesystemSlice {
        allow: expand_paths(&raw.allow, cwd)?,
        read_only: expand_paths(&raw.read_only, cwd)?,
        deny: expand_paths(&raw.deny, cwd)?,
    })
}

/// Resolve a network slice from the raw profile (no variable expansion; the
/// proxy layer consumes `profile_name` + `allow_domain` directly).
fn resolve_network_slice(raw: &Option<RawNetwork>) -> NetworkSlice {
    let empty = RawNetwork::default();
    let raw = raw.as_ref().unwrap_or(&empty);
    NetworkSlice {
        block_net: raw.block_net,
        allow_domain: raw.allow_domain.clone(),
        profile_name: raw.profile.clone(),
    }
}

/// Expand `$HOME`, `$CWD`, `$USERPROFILE`, `$TEMP`, `$SID` in each path string.
fn expand_paths(paths: &[String], cwd: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::with_capacity(paths.len());
    for p in paths {
        let expanded = expand_vars(p, cwd)?;
        let pb = PathBuf::from(expanded);
        out.push(pb);
    }
    Ok(out)
}

/// Expand the known variable set in a single string.
pub fn expand_vars(s: &str, cwd: &Path) -> Result<String> {
    let userprofile = std::env::var_os("USERPROFILE")
        .map(|o| o.to_string_lossy().to_string())
        .unwrap_or_default();
    let temp = std::env::var_os("TEMP")
        .map(|o| o.to_string_lossy().to_string())
        .unwrap_or_default();
    let cwd_s = cwd.to_string_lossy().to_string();
    let home = userprofile.clone();

    let mut result = s.to_string();
    // Use distinct placeholder to avoid double-replacing $HOME inside $USERPROFILE.
    result = result.replace("$CWD", &cwd_s);
    result = result.replace("$HOME", &home);
    result = result.replace("$USERPROFILE", &userprofile);
    result = result.replace("$TEMP", &temp);
    // $SID is expanded at a later stage when the session id is known; leave as-is
    // here and the caller will substitute. For now, replace with empty if present
    // in the filesystem slice (per-session dirs are auto-added by the sandbox).
    // We don't error: $SID is allowed but optional.
    if result.contains("$SID") {
        // Leave the literal token; the allowlist builder substitutes it.
    }
    // Normalize forward slashes to backslashes for Win32 APIs.
    Ok(result.replace('/', "\\"))
}

/// Merge the profile filesystem slice with CLI flags.
/// CLI flags append to the profile allow-list (FR-5.5).
pub fn merge_filesystem(
    profile_fs: &FilesystemSlice,
    allow_cwd: bool,
    allow: &[String],
    read_only: &[String],
    cwd: &Path,
) -> Result<FilesystemSlice> {
    let mut allow_paths = profile_fs.allow.clone();
    let mut read_only_paths = profile_fs.read_only.clone();
    let deny = profile_fs.deny.clone();

    if allow_cwd {
        allow_paths.push(cwd.to_path_buf());
    }

    for entry in allow {
        let (path, mode) = parse_allow_entry(entry)?;
        let expanded = expand_vars(&path, cwd)?;
        match mode.as_str() {
            "read" | "readonly" => read_only_paths.push(PathBuf::from(expanded)),
            _ => allow_paths.push(PathBuf::from(expanded)),
        }
    }
    for entry in read_only {
        let expanded = expand_vars(entry, cwd)?;
        read_only_paths.push(PathBuf::from(expanded));
    }

    // Dedupe.
    allow_paths = dedupe_paths(allow_paths);
    read_only_paths = dedupe_paths(read_only_paths);

    Ok(FilesystemSlice {
        allow: allow_paths,
        read_only: read_only_paths,
        deny,
    })
}

/// Parse `--allow path[:mode]`. Mode is one of read|write|readwrite|execute;
/// default is readwrite (which grants RWX). The leading `C:` drive-letter
/// colon is NOT treated as a separator.
fn parse_allow_entry(entry: &str) -> Result<(String, String)> {
    // Find a colon that is not the drive-letter colon at index 1.
    let mode_colon = entry.rfind(':').filter(|&i| i != 1);
    match mode_colon {
        Some(i) => {
            let path = &entry[..i];
            let mode = entry[i + 1..].to_ascii_lowercase();
            match mode.as_str() {
                "read" | "readonly" | "write" | "readwrite" | "execute" => {
                    Ok((path.to_string(), mode))
                }
                _ => bail!("unknown --allow mode `{mode}` in `{entry}`"),
            }
        }
        None => Ok((entry.to_string(), "readwrite".to_string())),
    }
}

fn dedupe_paths(paths: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut seen: BTreeMap<String, ()> = BTreeMap::new();
    let mut out = Vec::with_capacity(paths.len());
    for p in paths {
        let key = p.to_string_lossy().to_lowercase();
        if seen.contains_key(&key) {
            continue;
        }
        seen.insert(key, ());
        out.push(p);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expand_basic() {
        let p = PathBuf::from("C:\\projekte\\myapp");
        assert_eq!(expand_vars("$CWD/.claude", &p).unwrap(), "C:\\projekte\\myapp\\.claude");
    }

    #[test]
    fn expand_multiple() {
        let p = PathBuf::from("C:\\projekte\\myapp");
        let s = expand_vars("$HOME/.ssh and $CWD/x", &p).unwrap();
        assert!(s.starts_with("C:\\Users\\"));
        assert!(s.contains("\\.ssh and C:\\projekte\\myapp\\x"));
    }

    #[test]
    fn merge_extends_arrays_concat() {
        let parent = RawProfile {
            filesystem: Some(RawFilesystem {
                allow: vec!["$CWD".into()],
                read_only: vec!["$HOME/.gitconfig".into()],
                deny: vec!["$HOME/.ssh".into()],
            }),
            ..Default::default()
        };
        let child = RawProfile {
            filesystem: Some(RawFilesystem {
                allow: vec!["$HOME/.claude".into()],
                read_only: vec![],
                deny: vec!["$HOME/.aws".into()],
            }),
            ..Default::default()
        };
        let merged = merge_profiles(parent, child);
        let fs = merged.filesystem.unwrap();
        assert_eq!(fs.allow.len(), 2);
        assert_eq!(fs.read_only.len(), 1);
        assert_eq!(fs.deny.len(), 2);
    }

    #[test]
    fn merge_extends_child_overrides_meta() {
        let parent = RawProfile {
            meta: Some(Meta {
                name: "parent".into(),
                version: "1".into(),
                description: "p".into(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let child = RawProfile {
            meta: Some(Meta {
                name: "child".into(),
                version: "2".into(),
                description: "c".into(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let merged = merge_profiles(parent, child);
        assert_eq!(merged.meta.unwrap().name, "child");
    }

    #[test]
    fn parse_allow_with_mode() {
        let (p, m) = parse_allow_entry("C:/foo:read").unwrap();
        assert_eq!(p, "C:/foo");
        assert_eq!(m, "read");
    }
    #[test]
    fn parse_allow_default_mode() {
        let (p, m) = parse_allow_entry("C:/foo").unwrap();
        assert_eq!(p, "C:/foo");
        assert_eq!(m, "readwrite");
    }
    #[test]
    fn parse_allow_bad_mode() {
        assert!(parse_allow_entry("C:/foo:bad").is_err());
    }

    #[test]
    fn schema_version_supported_passes() {
        let raw = r#"{"meta":{"name":"x","schema_version":1},"filesystem":{"allow":["$CWD"]}}"#;
        let p: RawProfile = serde_json::from_str(raw).expect("v1 parses");
        assert_eq!(p.meta.as_ref().unwrap().schema_version, Some(1));
        validate_schema_version(&p).expect("v1 is supported");
    }

    #[test]
    fn schema_version_unsupported_errors() {
        let raw = r#"{"meta":{"name":"x","schema_version":99}}"#;
        let p: RawProfile = serde_json::from_str(raw).expect("parses structurally");
        let err = validate_schema_version(&p).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("Unsupported profile schema version 99"), "got: {msg}");
        assert!(msg.contains("supports schema version 1"), "got: {msg}");
    }

    #[test]
    fn schema_version_absent_is_treated_as_error() {
        let raw = r#"{"meta":{"name":"x"},"filesystem":{"allow":["$CWD"]}}"#;
        let p: RawProfile = serde_json::from_str(raw).expect("parses structurally");
        let err = validate_schema_version(&p).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("missing required field `meta.schema_version`"), "got: {msg}");
    }

    #[test]
    fn dedupe_paths_case_insensitive() {
        let paths = vec![
            PathBuf::from("C:\\Foo"),
            PathBuf::from("c:\\foo"),
            PathBuf::from("C:\\Bar"),
        ];
        let out = dedupe_paths(paths);
        assert_eq!(out.len(), 2);
    }
}
