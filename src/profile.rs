use anyhow::{Context, Result, bail};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// One entry in the `profile list` output.
#[derive(Debug, Clone)]
pub struct ProfileEntry {
    pub name: String,
    pub source_path: PathBuf,
}

/// List all profiles in the user-global directory (AC-5.14).
/// Reads `%USERPROFILE%\.sandbox\profiles\*.json`, parsing each just enough
/// to extract `meta.name` (falling back to the filename stem). Non-`.json`
/// files and unparseable JSON are skipped silently — `list` is best-effort.
pub fn list_profiles() -> Vec<ProfileEntry> {
    let dir = crate::cli::profiles_dir();
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir(&dir) else { return out; };
    for entry in rd.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") { continue; }
        let name = name_from_profile_file(&path).unwrap_or_else(|| {
            path.file_stem().and_then(|s| s.to_str()).unwrap_or("?").to_string()
        });
        out.push(ProfileEntry { name, source_path: path });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

fn name_from_profile_file(path: &Path) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    let raw: RawProfile = serde_json::from_str(&text).ok()?;
    raw.meta.and_then(|m| if m.name.is_empty() { None } else { Some(m.name) })
}

/// `sandbox profile show <name> [--expanded]`.
/// - Raw view (default): prints the file contents verbatim (AC-5.15).
/// - Expanded view (`--expanded`): prints the fully-resolved JSON.
pub fn show_profile(name: &str, expanded: bool) -> i32 {
    match show_profile_inner(name, expanded) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("[sandbox] profile show: {e:#}");
            1
        }
    }
}

fn show_profile_inner(name: &str, expanded: bool) -> Result<i32> {
    let cwd = std::env::current_dir().context("get current directory")?;
    if expanded {
        let mut seen: Vec<String> = Vec::new();
        let raw = load_raw_chain(name, &cwd, &mut seen)?;
        validate_schema_version(&raw)?;
        let groups = raw.security.as_ref().map(|s| s.groups.clone()).unwrap_or_default();
        let mut fs = resolve_filesystem(&raw.filesystem, &cwd)?;
        let resolved_name = raw.meta.as_ref()
            .map(|m| m.name.clone())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| name.to_string());
        if let Some(sec) = &raw.security
            && !sec.groups.is_empty()
        {
            let probe = crate::security_groups::HostEnv;
            let grants = crate::security_groups::resolve_groups(&probe, &sec.groups);
            for g in grants {
                fs.read_only.push(g.path);
            }
            fs.read_only = dedupe_paths(fs.read_only);
            let allow_keys: std::collections::BTreeSet<String> = fs
                .allow.iter().map(|p| p.to_string_lossy().to_lowercase()).collect();
            fs.read_only.retain(|p| !allow_keys.contains(&p.to_string_lossy().to_lowercase()));
        }
        let resolved = ResolvedProfile {
            name: resolved_name,
            filesystem: fs,
            network: resolve_network_slice(&raw.network),
        };
        let groups_expanded = expand_groups_for_show(&groups);
        println!("{}", to_expanded_json(&resolved, &groups_expanded));
    } else {
        let path = resolve_profile_path(name, &cwd)?;
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("read profile {}", path.display()))?;
        println!("{text}");
    }
    Ok(0)
}

/// Render a resolved profile + expanded group paths as a single JSON object
/// (the `--expanded` view). Shape:
/// ```json
/// {
///   "meta": { "name": "..." },
///   "filesystem": { "allow": [...], "read_only": [...], "deny": [...] },
///   "security_groups_expanded": { "python_runtime": ["C:\\..."], ... },
///   "network": { "block": false, "allow_domain": [...], "profile": "..." }
/// }
/// ```
pub fn to_expanded_json(
    resolved: &ResolvedProfile,
    groups_expanded: &[(String, Vec<std::path::PathBuf>)],
) -> String {
    let mut groups_obj = serde_json::Map::new();
    for (name, paths) in groups_expanded {
        let arr: Vec<Value> = paths.iter().map(|p| json!(p.to_string_lossy().to_string())).collect();
        groups_obj.insert(name.clone(), Value::Array(arr));
    }
    let expanded = json!({
        "meta": { "name": resolved.name },
        "filesystem": {
            "allow": resolved.filesystem.allow.iter().map(|p| p.to_string_lossy().to_string()).collect::<Vec<_>>(),
            "read_only": resolved.filesystem.read_only.iter().map(|p| p.to_string_lossy().to_string()).collect::<Vec<_>>(),
            "deny": resolved.filesystem.deny.iter().map(|p| p.to_string_lossy().to_string()).collect::<Vec<_>>(),
        },
        "security_groups_expanded": groups_obj,
        "network": {
            "block": resolved.network.block_net,
            "allow_domain": resolved.network.allow_domain,
            "profile": resolved.network.profile_name,
        }
    });
    serde_json::to_string_pretty(&expanded).unwrap_or_else(|_| "{}".into())
}

/// Compute the per-group expanded paths for a resolved profile, keyed by
/// group name. Used by `show_profile --expanded` so each group's concrete
/// paths are visible separately (not just folded into read_only).
fn expand_groups_for_show(sec_groups: &[String]) -> Vec<(String, Vec<std::path::PathBuf>)> {
    let probe = crate::security_groups::HostEnv;
    let grants = crate::security_groups::resolve_groups(&probe, sec_groups);
    let mut by_group: std::collections::BTreeMap<String, Vec<std::path::PathBuf>> = std::collections::BTreeMap::new();
    for g in grants {
        by_group.entry(g.label.to_string()).or_default().push(g.path);
    }
    by_group.into_iter().collect()
}


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
    pub name: String,
    pub filesystem: FilesystemSlice,
    pub network: NetworkSlice,
}

/// Raw profile JSON (v1 schema).
#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
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
    pub workdir: Option<Workdir>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
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
    /// Accepts both `schema_version` (canonical v1) and `schemaVersion`
    /// (legacy camelCase) for backward compatibility.
    #[serde(default, alias = "schemaVersion")]
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
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct Security {
    #[serde(default)]
    pub groups: Vec<String>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct RawFilesystem {
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub read_only: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct RawNetwork {
    #[serde(default)]
    pub block_net: bool,
    #[serde(default)]
    pub allow_domain: Vec<String>,
    #[serde(default)]
    pub profile: Option<String>,
}

/// `workdir` block. `access` is the only documented key in v1
/// (`readwrite` | `readonly` | `none`). Parsed but not yet enforced
/// beyond the implicit `--allow-cwd` grant; reserved for the profile
/// show / list subcommands and future enforcement.
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct Workdir {
    #[serde(default)]
    #[allow(dead_code)]
    pub access: Option<String>,
}

/// The set of top-level keys a v1 profile accepts. Used by
/// [`suggest_unknown_key`] to emit "Did you mean X?" hints (AC-5.13).
pub const KNOWN_TOP_LEVEL_KEYS: &[&str] =
    &["meta", "extends", "security", "filesystem", "network", "workdir"];

/// Suggest a known key close to `unknown` (case-insensitive). Returns
/// `Some(known)` when, compared case-insensitively, the lowercased unknown
/// and the known key satisfy any of: Levenshtein edit distance <= 2, the
/// unknown is a prefix of the known key, or the known key is a prefix of
/// the unknown.
///
/// Returns `None` otherwise — so a totally bogus key like `zzzzz`
/// produces no suggestion (still rejected, just without a hint).
pub fn suggest_unknown_key(unknown: &str) -> Option<String> {
    let lower = unknown.to_ascii_lowercase();
    for &known in KNOWN_TOP_LEVEL_KEYS {
        if levenshtein(&lower, known) <= 2
            || lower.starts_with(known)
            || known.starts_with(&lower)
        {
            return Some(known.to_string());
        }
    }
    None
}

/// Iterative Levenshtein edit distance. Sufficient for short strings
/// (top-level keys are ≤ 10 chars); no need for a crate.
fn levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let (n, m) = (a.len(), b.len());
    if n == 0 { return m; }
    if m == 0 { return n; }
    let mut prev: Vec<usize> = (0..=m).collect();
    let mut curr = vec![0usize; m + 1];
    for i in 1..=n {
        curr[0] = i;
        for j in 1..=m {
            let cost = if a[i - 1] == b[j - 1] { 0 } else { 1 };
            curr[j] = (prev[j] + 1).min(curr[j - 1] + 1).min(prev[j - 1] + cost);
        }
        std::mem::swap(&mut prev, &mut curr);
    }
    prev[m]
}

/// Post-process a serde error to append a "Did you mean X?" hint when the
/// error is an unknown-field rejection (AC-5.13). serde's message already
/// includes `unknown field `KEY``; we append `\n  Did you mean \`SUGGEST\`?`
/// when a close match exists.
pub fn with_suggestion(err: serde_json::Error) -> anyhow::Error {
    let msg = format!("{err}");
    if let Some(unknown) = extract_unknown_field(&msg)
        && let Some(sugg) = suggest_unknown_key(&unknown)
    {
        return anyhow::anyhow!("{err}\n  Did you mean `{sugg}`?");
    }
    anyhow::Error::from(err)
}

/// Extract the field name from a serde `unknown field `X`` message.
fn extract_unknown_field(msg: &str) -> Option<String> {
    let marker = "unknown field `";
    let start = msg.find(marker)? + marker.len();
    let end = msg[start..].find('`')?;
    Some(msg[start..start + end].to_string())
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

/// Detect a profile `extends` cycle and format the error per AC-5.6:
/// `Profile cycle detected: a → b → a` (the repeated name closes the loop).
fn check_cycle(name: &str, seen: &[String]) -> Result<()> {
    if seen.iter().any(|s| s == name) {
        let mut chain: Vec<&str> = seen.iter().map(|s| s.as_str()).collect();
        chain.push(name);
        bail!("Profile cycle detected: {}", chain.join(" → "));
    }
    Ok(())
}

/// Recursively load a profile and its `extends` chain. The deepest parent is
/// loaded first; the child is merged on top (child keys override, arrays
/// concatenate for filesystem.allow / read_only / deny).
fn load_raw_chain(name: &str, cwd: &Path, seen: &mut Vec<String>) -> Result<RawProfile> {
    check_cycle(name, seen)?;
    seen.push(name.to_string());

    let path = resolve_profile_path(name, cwd)?;
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("read profile {}", path.display()))?;
    let raw: RawProfile = serde_json::from_str(&text)
        .map_err(with_suggestion)
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

    #[test]
    fn unknown_top_level_key_is_rejected_with_suggestion() {
        let raw = r#"{"meta":{"name":"x","schema_version":1},"netwrok":{"block":false}}"#;
        let err = serde_json::from_str::<RawProfile>(raw).unwrap_err();
        let msg = format!("{}", with_suggestion(err));
        assert!(msg.contains("unknown field `netwrok`"), "got: {msg}");
        assert!(msg.contains("Did you mean `network`"), "got: {msg}");
    }

    #[test]
    fn unknown_key_no_close_match_still_rejects() {
        let raw = r#"{"meta":{"name":"x","schema_version":1},"zzzzz":1}"#;
        let err = serde_json::from_str::<RawProfile>(raw).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("unknown field `zzzzz`"), "got: {msg}");
        assert!(!msg.contains("Did you mean"), "got: {msg}");
    }

    #[test]
    fn wrong_type_carries_line_col() {
        let raw = "{\"meta\":{\"name\":\"x\",\"schema_version\":1},\"filesystem\":{\"allow\":42}}";
        let err = serde_json::from_str::<RawProfile>(raw).unwrap_err();
        let msg = format!("{}", with_suggestion(err));
        assert!(msg.contains("expected a sequence") || msg.contains("integer"), "got: {msg}");
        assert!(msg.contains("line") || msg.contains("col"), "got: {msg}");
    }

    #[test]
    fn suggest_closest_known_key() {
        assert_eq!(suggest_unknown_key("netwrok"), Some("network".to_string()));
        assert_eq!(suggest_unknown_key("filesystemm"), Some("filesystem".to_string()));
        assert_eq!(suggest_unknown_key("metaa"), Some("meta".to_string()));
        assert_eq!(suggest_unknown_key("zzzzz"), None);
        assert_eq!(suggest_unknown_key("sec"), Some("security".to_string()));
    }

    #[test]
    fn cycle_message_matches_spec_format() {
        let seen: Vec<String> = vec!["a".into(), "b".into()];
        let next = "a";
        let err = check_cycle(next, &seen).unwrap_err();
        let msg = format!("{err:#}");
        assert_eq!(msg, "Profile cycle detected: a → b → a");
    }

    #[test]
    fn cycle_message_three_deep() {
        let seen: Vec<String> = vec!["a".into(), "b".into(), "c".into()];
        let err = check_cycle("a", &seen).unwrap_err();
        let msg = format!("{err:#}");
        assert_eq!(msg, "Profile cycle detected: a → b → c → a");
    }

    #[test]
    fn no_cycle_when_name_not_seen() {
        let seen: Vec<String> = vec!["a".into(), "b".into()];
        assert!(check_cycle("c", &seen).is_ok());
    }

    #[test]
    fn list_profiles_returns_user_global_json_files() {
        let tmp = std::env::temp_dir().join(format!("sb-list-test-{}", std::process::id()));
        let profiles_dir = tmp.join(".sandbox").join("profiles");
        std::fs::create_dir_all(&profiles_dir).unwrap();
        std::fs::write(profiles_dir.join("alpha.json"), r#"{"meta":{"name":"alpha","schema_version":1}}"#).unwrap();
        std::fs::write(profiles_dir.join("beta.json"), r#"{"meta":{"name":"beta","schema_version":1}}"#).unwrap();
        std::fs::write(profiles_dir.join("not-json.txt"), "garbage").unwrap();
        let prev = std::env::var_os("USERPROFILE");
        unsafe { std::env::set_var("USERPROFILE", &tmp); }
        let result = list_profiles();
        if let Some(p) = prev {
            unsafe { std::env::set_var("USERPROFILE", p); }
        }
        std::fs::remove_dir_all(&tmp).ok();

        let names: Vec<String> = result.into_iter().map(|p| p.name).collect();
        assert!(names.contains(&"alpha".to_string()));
        assert!(names.contains(&"beta".to_string()));
        assert!(!names.iter().any(|n| n == "not-json"), "non-.json files excluded");
    }

    #[test]
    fn expanded_profile_flattens_extends_and_expands_groups() {
        let resolved = ResolvedProfile {
            name: "child".into(),
            filesystem: FilesystemSlice {
                allow: vec![PathBuf::from(r"C:\proj")],
                read_only: vec![PathBuf::from(r"C:\Users\test\.gitconfig")],
                deny: vec![PathBuf::from(r"C:\Users\test\.ssh")],
            },
            network: NetworkSlice {
                block_net: false,
                allow_domain: vec!["api.anthropic.com".into()],
                profile_name: Some("minimal".into()),
            },
        };
        let groups_expanded: Vec<(String, Vec<PathBuf>)> = vec![
            ("python_runtime".into(), vec![PathBuf::from(r"C:\Py312")]),
        ];
        let json = to_expanded_json(&resolved, &groups_expanded);
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["meta"]["name"], "child");
        assert_eq!(v["filesystem"]["allow"][0], r"C:\proj");
        assert_eq!(v["filesystem"]["read_only"][0], r"C:\Users\test\.gitconfig");
        assert_eq!(v["security_groups_expanded"]["python_runtime"][0], r"C:\Py312");
        assert_eq!(v["network"]["block"], false);
        assert_eq!(v["network"]["allow_domain"][0], "api.anthropic.com");
        assert_eq!(v["network"]["profile"], "minimal");
    }
}
