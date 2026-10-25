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
/// Reads `%USERPROFILE%\.saife\profiles\*.json`, parsing each just enough
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

/// `saife profile show <name> [--expanded]`.
/// - Raw view (default): prints the file contents verbatim (AC-5.15).
/// - Expanded view (`--expanded`): prints the fully-resolved JSON.
pub fn show_profile(name: &str, expanded: bool) -> i32 {
    match show_profile_inner(name, expanded) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("[saife] profile show: {e:#}");
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
            limits: resolve_limits_slice(&raw.limits),
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
///   "network": { "block": false, "allow_domain": [...], "profile": "..." },
///   "limits": { "prompt_timeout_secs": 60, "workload_timeout_secs": 1800 }
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
            "deny_domain": resolved.network.deny_domain,
            "profile": resolved.network.profile_name,
            "prompt_enabled": resolved.network.prompt_enabled,
            "on_unavailable": resolved.network.on_unavailable,
            "upstream_proxy": resolved.network.upstream_proxy,
        },
        // Moved out of `network` on 2026-10-25: the session deadline is not a
        // network policy. `null` means "unset, the resolver's default applies".
        "limits": {
            "prompt_timeout_secs": resolved.limits.prompt_timeout_secs,
            "workload_timeout_secs": resolved.limits.workload_timeout_secs,
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
    pub deny_domain: Vec<String>,
    pub prompt_enabled: Option<bool>,
    pub on_unavailable: Option<String>,
    pub upstream_proxy: Option<String>,
}

/// The session-deadline slice of a profile, after merging `extends`.
///
/// These two terms lived in `network` until 2026-10-25. They are session
/// concerns, not network policy: a `--block-net` session runs a container and is
/// bounded by the same terms, and the deadline is supervisor arithmetic over the
/// prompt and workload terms rather than a host-matching rule. `None` = neither
/// this profile nor its parents set it, so [`LimitsSlice::resolve`] applies the
/// documented default.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct LimitsSlice {
    /// Seconds one prompt consultation may take. `None` = 60 s ([G-46]).
    pub prompt_timeout_secs: Option<u32>,
    /// Seconds the workload may run before the container kills it. `None` = 30 min.
    pub workload_timeout_secs: Option<u32>,
}

/// Default prompt term in seconds: the same constant the prompt layer builds its
/// dialog timeout from and [`crate::net::mxc::PROMPT_BUDGET`] is defined as, so
/// the three cannot drift ([G-46]).
pub const DEFAULT_PROMPT_TIMEOUT_SECS: u32 = crate::net::prompt::DEFAULT_PROMPT_TIMEOUT_SECS;

/// Default workload term in seconds (30 min) — the `limits.workloadTimeoutSecs`
/// default.
pub const DEFAULT_WORKLOAD_TIMEOUT_SECS: u32 = crate::net::DEFAULT_WORKLOAD_TIMEOUT_SECS;

/// Directories denied for EVERY launch, on both backends, whatever the profile says.
///
/// `.ssh`/`.aws`/`.azure`/`.gnupg` are credentials. `.saife` holds the plugin
/// manifests whose `command` is executed HOST-side on the next `--plugin` run, the
/// learned allow/deny policy, and sits beside the audit log and the DPAPI-wrapped
/// signing key in `%LOCALAPPDATA%\saife`. A profile that grants `$HOME` would
/// otherwise let the workload rewrite a plugin that later runs outside the sandbox -
/// a full escape, which is why this is a deny and not a documentation note.
pub fn builtin_deny_dirs() -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    if let Some(home) = std::env::var_os("USERPROFILE").map(std::path::PathBuf::from) {
        for dir in [".ssh", ".aws", ".azure", ".gnupg", ".saife"] {
            out.push(home.join(dir));
        }
    }
    if let Some(local) = std::env::var_os("LOCALAPPDATA").map(std::path::PathBuf::from) {
        out.push(local.join("saife"));
    }
    out
}

/// Does `outer` contain `inner` (equal, or an ancestor)? Component-wise and
/// case-insensitive, because Windows paths are. Used to refuse a session whose
/// deny would swallow a grant instead of silently locking the workload out.
pub fn path_covers(outer: &std::path::Path, inner: &std::path::Path) -> bool {
    fn norm(p: &std::path::Path) -> String {
        p.display()
            .to_string()
            .replace('/', "\\")
            .trim_end_matches('\\')
            .to_lowercase()
    }
    let (o, i) = (norm(outer), norm(inner));
    i == o || i.starts_with(&format!("{o}\\"))
}

/// Ceiling for both `limits` terms: 7 days
/// ([`crate::net::MAX_WORKLOAD_TIMEOUT_SECS`]).
pub const MAX_LIMIT_SECS: u32 = crate::net::MAX_WORKLOAD_TIMEOUT_SECS;

// The cap must stay inside the container contract's `timeout_ms: u32` milliseconds,
// or the derived budget would saturate instead of expressing what the profile asked
// for. A compile-time check, so raising the constant past ~49.7 days cannot ship.
const _: () = assert!((MAX_LIMIT_SECS as u64) * 1000 <= u32::MAX as u64);

/// The session limits ONE run actually uses: defaults applied, both terms
/// validated into `1..=MAX_LIMIT_SECS`.
///
/// Unlike [`LimitsSlice`] these are plain numbers, which is what the session
/// budget and the dialog timeout are built from — nothing downstream has to
/// decide what "unset" means.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// How long one prompt consultation may take.
    pub prompt_timeout_secs: u32,
    /// How long the workload itself may run.
    ///
    /// Read by the session budget only, which exists in an `mxc-backend` build:
    /// the AppContainer path carries no container deadline, so a feature-less
    /// build resolves the term but does not consume it.
    #[cfg_attr(not(feature = "mxc-backend"), allow(dead_code))]
    pub workload_timeout_secs: u32,
}

impl Default for Limits {
    /// The documented defaults — what a run with no profile (or a profile with no
    /// `limits` section) gets.
    fn default() -> Self {
        Self {
            prompt_timeout_secs: DEFAULT_PROMPT_TIMEOUT_SECS,
            workload_timeout_secs: DEFAULT_WORKLOAD_TIMEOUT_SECS,
        }
    }
}

impl LimitsSlice {
    /// Resolve the merged options into the terms a session uses.
    ///
    /// Out-of-range values fall back to the default with a warning, in the same
    /// style as the network slice's other validated knobs - past the cap the only
    /// honest reading is a wedged session.
    ///
    /// The two terms deliberately have different floors. The PROMPT term keeps
    /// `0` as a legal value: [G-46] defines it as "instant deny", the dialog
    /// deadline is built with `Duration::from_secs(0)` so it expires at once, and
    /// moving the field must not change that. The WORKLOAD term needs `>= 1`,
    /// because `0` there would end every session before its child could run.
    pub fn resolve(&self) -> Limits {
        Limits {
            prompt_timeout_secs: clamp_limit_term(
                "promptTimeoutSecs",
                self.prompt_timeout_secs,
                DEFAULT_PROMPT_TIMEOUT_SECS,
                0,
            ),
            workload_timeout_secs: clamp_limit_term(
                "workloadTimeoutSecs",
                self.workload_timeout_secs,
                DEFAULT_WORKLOAD_TIMEOUT_SECS,
                1,
            ),
        }
    }
}

impl Limits {
    /// The container deadline these terms ask for (P2.1): prompt + workload +
    /// [`crate::net::mxc::SESSION_SLACK`].
    ///
    /// **Invariant: the deadline is strictly greater than the sum of the two
    /// terms**, so a session that spends both to the last millisecond is not
    /// killed by arithmetic. The budget must be built from THESE resolved values,
    /// never from the default constants: the dialog gets the resolved prompt term,
    /// so a default-sized budget would kill a legitimate dialog in a profile that
    /// raised it.
    #[cfg(feature = "mxc-backend")]
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn session_budget(&self) -> crate::net::mxc::SessionBudget {
        crate::net::mxc::SessionBudget::from_config(
            self.prompt_timeout_secs,
            self.workload_timeout_secs,
            crate::net::mxc::SESSION_SLACK,
        )
    }
}

fn clamp_limit_term(name: &str, value: Option<u32>, default: u32, min: u32) -> u32 {
    match value {
        Some(v) if v >= min && v <= MAX_LIMIT_SECS => v,
        Some(invalid) => {
            eprintln!(
                "[saife] invalid {name} value {invalid} (must be {min}..={MAX_LIMIT_SECS}), \
                 defaulting to {default}"
            );
            default
        }
        None => default,
    }
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
    pub limits: LimitsSlice,
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
    /// The session-deadline terms (see [`RawLimits`]). Top level, NOT `network.*`.
    #[serde(default)]
    pub limits: Option<RawLimits>,
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
            "Unsupported profile schema version {v}. This build of SAIFE supports schema version {SUPPORTED_SCHEMA_VERSION}."
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
    /// Accept both `allow_domain` (canonical snake_case) and `allowDomain`
    /// (legacy camelCase) for backward compatibility, matching the
    /// `meta.schema_version` alias convention.
    #[serde(default, alias = "allowDomain")]
    pub allow_domain: Vec<String>,
    #[serde(default)]
    pub profile: Option<String>,
    /// Domains always denied, checked before the allow-list (deny wins).
    /// Profile-only (no CLI equivalent); the CLI uses `--deny-domain`.
    #[serde(default, rename = "denyDomain")]
    pub deny_domain: Vec<String>,
    /// Whether the interactive network prompt is shown for unlisted hosts.
    /// Defaults to `true` when the network is active ([G-47]).
    #[serde(default, rename = "promptEnabled")]
    pub prompt_enabled: Option<bool>,
    /// What to do when a host is unavailable / prompt times out:
    /// `"deny"` (default) or `"allow"`. Profile-only ([G-48]).
    #[serde(default, rename = "onUnavailable")]
    pub on_unavailable: Option<String>,
    /// Upstream proxy URL (e.g. `http://corp:8080`). Parsed now, consumed in
    /// Phase 4.
    #[serde(default, rename = "upstreamProxy")]
    pub upstream_proxy: Option<String>,
}

/// `limits` block: the two session-deadline terms.
///
/// **Both keys were `network.promptTimeoutSecs` / `network.workloadTimeoutSecs`
/// and are top level since 2026-10-25** — the deadline belongs to the session, not
/// to the network policy, and a `--block-net` session is bounded by the same
/// terms. The old location is REFUSED, not aliased: `RawNetwork` denies unknown
/// fields, so a profile still carrying it fails to parse (with a hint naming
/// `limits`) instead of silently losing its workload budget.
///
/// Canonical spelling is snake_case (`prompt_timeout_secs`,
/// `workload_timeout_secs`); the camelCase aliases the shipped profiles use are
/// accepted, matching the `allow_domain` / `allowDomain` convention.
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct RawLimits {
    /// Seconds one prompt consultation may take. Default 60; validated
    /// `1..=86400` by [`LimitsSlice::resolve`] ([G-46]).
    #[serde(default, alias = "promptTimeoutSecs")]
    pub prompt_timeout_secs: Option<u32>,
    /// Seconds the workload itself may run before the container kills it.
    /// Default 1800 (30 min); validated `1..=86400`. The session bound is new in
    /// P2.1, so a workload that legitimately runs longer must raise this.
    #[serde(default, alias = "workloadTimeoutSecs")]
    pub workload_timeout_secs: Option<u32>,
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
pub const KNOWN_TOP_LEVEL_KEYS: &[&str] = &[
    "meta",
    "extends",
    "security",
    "filesystem",
    "network",
    "limits",
    "workdir",
];

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
    if let Some(unknown) = extract_unknown_field(&msg) {
        // A key that MOVED between sections gets its new home named: serde's own
        // message can only list what the section accepts now.
        if let Some((key, canonical)) = moved_key(&unknown) {
            return anyhow::anyhow!(
                "{err}\n  `{key}` moved out of `network` into the top-level \
                 `limits` section: use \"limits\": {{ \"{canonical}\": <seconds> }}"
            );
        }
        if let Some(sugg) = suggest_unknown_key(&unknown) {
            return anyhow::anyhow!("{err}\n  Did you mean `{sugg}`?");
        }
    }
    anyhow::Error::from(err)
}

/// Keys that moved between profile sections, as `(spelling, canonical)`.
///
/// 2026-10-25: the two session-deadline terms left `network` for the top-level
/// `limits` section, and both spellings of each are listed so the hint fires for a
/// canonical-snake_case profile as well as for the shipped camelCase ones.
const MOVED_KEYS: &[(&str, &str)] = &[
    ("promptTimeoutSecs", "prompt_timeout_secs"),
    ("prompt_timeout_secs", "prompt_timeout_secs"),
    ("workloadTimeoutSecs", "workload_timeout_secs"),
    ("workload_timeout_secs", "workload_timeout_secs"),
];

/// `Some((spelling, canonical))` when `unknown` is a key that moved sections.
fn moved_key(unknown: &str) -> Option<(&'static str, &'static str)> {
    MOVED_KEYS
        .iter()
        .copied()
        .find(|(from, _)| *from == unknown)
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
        limits: resolve_limits_slice(&raw.limits),
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
/// - `--profile claude-code` -> %USERPROFILE%\.saife\profiles\claude-code.json
/// - `--profile ./relative/path.json` -> resolved against cwd
/// - `--profile C:\abs\path.json` -> as-is
fn resolve_profile_path(name: &str, cwd: &Path) -> Result<PathBuf> {
    let p = Path::new(name);
    if p.is_absolute() {
        return Ok(p.to_path_buf());
    }
    // A relative file path is REFUSED, and this is CR-10 rather than a style rule.
    // `./x.json` is a path inside the workspace by construction, which means the
    // agent under test can write it - and then the next session starts with a policy
    // of the agent's choosing. Resolving it against the session cwd (an earlier fix
    // here) made that explicit instead of accidental, which is worse, not better.
    // Profiles live in %USERPROFILE%\.saife\profiles\ (by name) or at an absolute
    // path the operator typed.
    if name.ends_with(".json") {
        let _ = cwd;
        if p.is_relative() {
            anyhow::bail!(
                "profile path must be absolute: {name:?} would be resolved inside the workspace, \
                 which the sandboxed process can write (CR-10). Put the file in \
                 %USERPROFILE%\\.saife\\profiles\\ and use its name, or pass an absolute path."
            );
        }
        return Ok(p.to_path_buf());
    }
    // Bare name: look in %USERPROFILE%\.saife\profiles\<name>.json
    let userprofile = std::env::var_os("USERPROFILE")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    Ok(userprofile
        .join(".saife")
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
            deny_domain: dedupe_concat(p.deny_domain, c.deny_domain),
            prompt_enabled: c.prompt_enabled.or(p.prompt_enabled),
            on_unavailable: c.on_unavailable.or(p.on_unavailable),
            upstream_proxy: c.upstream_proxy.or(p.upstream_proxy),
        }),
        (Some(p), None) => Some(p),
        (None, Some(c)) => Some(c),
        (None, None) => None,
    };
    // Child overrides a scalar, the parent fills the gaps it left.
    let limits = match (parent.limits, child.limits) {
        (Some(p), Some(c)) => Some(RawLimits {
            prompt_timeout_secs: c.prompt_timeout_secs.or(p.prompt_timeout_secs),
            workload_timeout_secs: c.workload_timeout_secs.or(p.workload_timeout_secs),
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
        limits,
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
        deny_domain: raw.deny_domain.clone(),
        prompt_enabled: raw.prompt_enabled,
        on_unavailable: raw.on_unavailable.clone(),
        upstream_proxy: raw.upstream_proxy.clone(),
    }
}

/// Resolve the limits slice from the raw `limits` block. No validation here: the
/// merged options are clamped where they are USED ([`LimitsSlice::resolve`]), so
/// `profile show --expanded` still shows what the file said.
fn resolve_limits_slice(raw: &Option<RawLimits>) -> LimitsSlice {
    match raw {
        Some(l) => LimitsSlice {
            prompt_timeout_secs: l.prompt_timeout_secs,
            workload_timeout_secs: l.workload_timeout_secs,
        },
        None => LimitsSlice::default(),
    }
}

/// Expand `$HOME`, `$CWD`, `$USERPROFILE`, `$TEMP`, `$LOCALAPPDATA`, `$APPDATA`,
/// `$SID` in each path string.
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
    // The two AppData roots. `$LOCALAPPDATA`/`$APPDATA` before 2026-10-23 were not
    // expandable, so profiles spelled `$USERPROFILE/AppData/Local/...` out — which
    // works but hides the intent, and made every sample look like it knew the
    // layout of this machine. Fall back to the conventional locations when the
    // variables are absent (a service context), so a profile still resolves.
    let localappdata = std::env::var_os("LOCALAPPDATA")
        .map(|o| o.to_string_lossy().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("{userprofile}\\AppData\\Local"));
    let appdata = std::env::var_os("APPDATA")
        .map(|o| o.to_string_lossy().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("{userprofile}\\AppData\\Roaming"));
    let cwd_s = cwd.to_string_lossy().to_string();
    let home = userprofile.clone();

    let mut result = s.to_string();
    // Use distinct placeholder to avoid double-replacing $HOME inside $USERPROFILE.
    result = result.replace("$CWD", &cwd_s);
    result = result.replace("$HOME", &home);
    result = result.replace("$USERPROFILE", &userprofile);
    result = result.replace("$TEMP", &temp);
    // No prefix collision: the `$` makes `$APPDATA` a distinct token from the tail
    // of `$LOCALAPPDATA`, so the order of these two does not matter.
    result = result.replace("$LOCALAPPDATA", &localappdata);
    result = result.replace("$APPDATA", &appdata);
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
        // Reads USERPROFILE ($HOME) below, so it must not race a test that
        // temporarily repoints the variable (see crate::ENV_LOCK).
        let _env = crate::env_lock();
        let p = PathBuf::from("C:\\projekte\\myapp");
        let s = expand_vars("$HOME/.ssh and $CWD/x", &p).unwrap();
        assert!(s.starts_with("C:\\Users\\"));
        assert!(s.contains("\\.ssh and C:\\projekte\\myapp\\x"));
    }

    /// `$LOCALAPPDATA`/`$APPDATA` resolve to this machine's roots rather than to a
    /// spelling that only works on the machine the profile was written on.
    #[test]
    fn expand_appdata_roots() {
        let _env = crate::env_lock();
        let p = PathBuf::from("C:\\projekte\\myapp");
        let local = std::env::var_os("LOCALAPPDATA")
            .map(|o| o.to_string_lossy().to_string())
            .filter(|s| !s.is_empty());
        let s = expand_vars("$LOCALAPPDATA/npm-cache and $APPDATA/npm", &p).unwrap();
        if let Some(local) = local {
            assert!(
                s.starts_with(&local),
                "expected {s:?} to start with LOCALAPPDATA {local:?}"
            );
        }
        assert!(s.contains("npm-cache and "), "both tokens expand: {s:?}");
        assert!(!s.contains('$'), "nothing left unexpanded: {s:?}");
        // The fallback path, when the variable is absent: derived from USERPROFILE.
        let home = std::env::var_os("USERPROFILE")
            .map(|o| o.to_string_lossy().to_string())
            .unwrap_or_default();
        if !home.is_empty() && s.len() > home.len() {
            assert!(s.starts_with(&home), "resolved under the profile: {s:?}");
        }
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
        let _env = crate::env_lock();
        let tmp = std::env::temp_dir().join(format!("sb-list-test-{}", std::process::id()));
        let profiles_dir = tmp.join(".saife").join("profiles");
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
                ..Default::default()
            },
            limits: LimitsSlice::default(),
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

    #[test]
    fn raw_network_parses_camel_case_prompt_fields() {
        let raw = r#"{"meta":{"name":"x","schema_version":1},"network":{"allowDomain":["a.com"],"denyDomain":["*.evil.com"],"promptEnabled":false,"onUnavailable":"allow","upstreamProxy":"http://corp:8080"}}"#;
        let p: RawProfile = serde_json::from_str(raw).expect("parses");
        assert!(p.limits.is_none(), "this profile declares no `limits`");
        let n = p.network.unwrap();
        assert_eq!(n.deny_domain, vec!["*.evil.com"]);
        assert_eq!(n.prompt_enabled, Some(false));
        assert_eq!(n.on_unavailable.as_deref(), Some("allow"));
        assert_eq!(n.upstream_proxy.as_deref(), Some("http://corp:8080"));
    }

    #[test]
    fn raw_network_backward_compat_missing_prompt_fields() {
        let raw = r#"{"meta":{"name":"x","schema_version":1},"network":{"allowDomain":["a.com"]}}"#;
        let p: RawProfile = serde_json::from_str(raw).expect("parses");
        let n = p.network.unwrap();
        assert!(n.deny_domain.is_empty());
        assert_eq!(n.prompt_enabled, None);
        assert_eq!(n.on_unavailable, None);
        assert_eq!(n.upstream_proxy, None);
    }

    #[test]
    fn merge_profiles_concatenates_deny_domain() {
        let parent = RawProfile {
            network: Some(RawNetwork {
                deny_domain: vec!["*.a.com".into()],
                ..Default::default()
            }),
            ..Default::default()
        };
        let child = RawProfile {
            network: Some(RawNetwork {
                deny_domain: vec!["*.b.com".into()],
                ..Default::default()
            }),
            ..Default::default()
        };
        let merged = merge_profiles(parent, child);
        let n = merged.network.unwrap();
        assert_eq!(n.deny_domain.len(), 2);
    }

    #[test]
    fn resolve_network_slice_copies_prompt_fields() {
        let raw = RawNetwork {
            deny_domain: vec!["*.evil.com".into()],
            prompt_enabled: Some(false),
            on_unavailable: Some("allow".into()),
            upstream_proxy: Some("http://corp:8080".into()),
            ..Default::default()
        };
        let slice = resolve_network_slice(&Some(raw));
        assert_eq!(slice.deny_domain, vec!["*.evil.com"]);
        assert_eq!(slice.prompt_enabled, Some(false));
        assert_eq!(slice.on_unavailable.as_deref(), Some("allow"));
        assert_eq!(slice.upstream_proxy.as_deref(), Some("http://corp:8080"));

        // The limits slice resolves separately, from the `limits` block.
        let limits = resolve_limits_slice(&Some(RawLimits {
            prompt_timeout_secs: Some(10),
            workload_timeout_secs: Some(600),
        }));
        assert_eq!(limits.prompt_timeout_secs, Some(10));
        assert_eq!(limits.workload_timeout_secs, Some(600));
        assert_eq!(
            resolve_limits_slice(&None),
            LimitsSlice::default(),
            "a missing `limits` block is the unset slice, not an error"
        );
    }

    #[test]
    fn expanded_json_emits_prompt_fields() {
        let resolved = ResolvedProfile {
            name: "x".into(),
            filesystem: FilesystemSlice::default(),
            network: NetworkSlice {
                allow_domain: vec!["a.com".into()],
                deny_domain: vec!["*.evil.com".into()],
                prompt_enabled: Some(true),
                on_unavailable: Some("deny".into()),
                upstream_proxy: None,
                ..Default::default()
            },
            limits: LimitsSlice {
                prompt_timeout_secs: Some(60),
                workload_timeout_secs: None,
            },
        };
        let json = to_expanded_json(&resolved, &[]);
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["network"]["deny_domain"][0], "*.evil.com");
        assert_eq!(v["network"]["prompt_enabled"], true);
        assert_eq!(v["network"]["on_unavailable"], "deny");
        assert_eq!(
            v["limits"]["prompt_timeout_secs"], 60,
            "the prompt term is a top-level limit now"
        );
        assert!(
            v["limits"]["workload_timeout_secs"].is_null(),
            "unset stays null (the resolver's default applies), it is not invented here"
        );
    }

    // ---------------------------------------------------------------------
    // `limits`: the session deadline moved out of `network` (2026-10-25)
    // ---------------------------------------------------------------------

    /// The old location is REFUSED, not aliased (no backward compatibility): a
    /// profile written before 2026-10-25 still says `network.workloadTimeoutSecs`,
    /// and losing the workload budget silently is worse than a parse error, so
    /// `RawNetwork`'s `deny_unknown_fields` rejects it and the message names
    /// `limits`, the section the key moved to.
    #[test]
    fn a_profile_still_carrying_network_workload_timeout_is_refused() {
        let raw = r#"{"meta":{"name":"x","schema_version":1},"network":{"allow_domain":["a.com"],"workloadTimeoutSecs":3600}}"#;
        let err =
            serde_json::from_str::<RawProfile>(raw).expect_err("the old location must be refused");
        let msg = format!("{}", with_suggestion(err));
        assert!(
            msg.contains("unknown field `workloadTimeoutSecs`"),
            "got: {msg}"
        );
        assert!(
            msg.contains("limits"),
            "the refusal must name the new section, got: {msg}"
        );
    }

    /// Same for the prompt term: `network.promptTimeoutSecs` is gone too, so a
    /// profile that only carries that one is refused as well.
    #[test]
    fn a_profile_still_carrying_network_prompt_timeout_is_refused() {
        let raw = r#"{"meta":{"name":"x","schema_version":1},"network":{"allow_domain":["a.com"],"promptTimeoutSecs":30}}"#;
        let err =
            serde_json::from_str::<RawProfile>(raw).expect_err("the old location must be refused");
        let msg = format!("{}", with_suggestion(err));
        assert!(
            msg.contains("unknown field `promptTimeoutSecs`"),
            "got: {msg}"
        );
        assert!(
            msg.contains("limits"),
            "the refusal must name the new section, got: {msg}"
        );
    }

    #[test]
    fn limits_parse_in_snake_case_and_with_the_camel_case_aliases() {
        let snake = r#"{"meta":{"name":"x","schema_version":1},"limits":{"prompt_timeout_secs":45,"workload_timeout_secs":900}}"#;
        let p: RawProfile = serde_json::from_str(snake).expect("snake_case parses");
        let l = p.limits.expect("limits present");
        assert_eq!(l.prompt_timeout_secs, Some(45));
        assert_eq!(l.workload_timeout_secs, Some(900));

        let camel = r#"{"meta":{"name":"x","schema_version":1},"limits":{"promptTimeoutSecs":45,"workloadTimeoutSecs":900}}"#;
        let p: RawProfile = serde_json::from_str(camel).expect("camelCase aliases parse");
        let l = p.limits.expect("limits present");
        assert_eq!(l.prompt_timeout_secs, Some(45));
        assert_eq!(l.workload_timeout_secs, Some(900));
    }

    #[test]
    fn limits_default_to_60_seconds_and_30_minutes() {
        let default = LimitsSlice::default().resolve();
        assert_eq!(default.prompt_timeout_secs, 60);
        assert_eq!(default.workload_timeout_secs, 1800);
        assert_eq!(
            default,
            Limits::default(),
            "a run with no profile gets the defaults"
        );
        assert_eq!(
            resolve_limits_slice(&None).resolve(),
            default,
            "a profile without a limits section gets them too"
        );
    }

    #[test]
    fn limits_are_clamped_into_range() {
        assert_eq!(MAX_LIMIT_SECS, 604_800, "the documented cap is seven days");

        // The PROMPT term accepts 0: [G-46] defines it as "instant deny", and the
        // dialog deadline is `Duration::from_secs(0)`, which expires at once.
        for accepted in [0, 1, 600, MAX_LIMIT_SECS] {
            let l = LimitsSlice {
                prompt_timeout_secs: Some(accepted),
                workload_timeout_secs: Some(accepted.max(1)),
            }
            .resolve();
            assert_eq!(l.prompt_timeout_secs, accepted, "prompt {accepted} is legal");
            assert_eq!(l.workload_timeout_secs, accepted.max(1));
        }
        // Past the cap the value can only be a wedged session: both fall back, with
        // a warning. `0` is rejected for the WORKLOAD term alone - it would end the
        // session before its child could run.
        for rejected in [MAX_LIMIT_SECS + 1, u32::MAX] {
            let l = LimitsSlice {
                prompt_timeout_secs: Some(rejected),
                workload_timeout_secs: Some(rejected),
            }
            .resolve();
            assert_eq!(
                l.prompt_timeout_secs, DEFAULT_PROMPT_TIMEOUT_SECS,
                "{rejected} must not reach a dialog"
            );
            assert_eq!(
                l.workload_timeout_secs, DEFAULT_WORKLOAD_TIMEOUT_SECS,
                "{rejected} must not reach the session deadline"
            );
        }
        let zero_workload = LimitsSlice {
            prompt_timeout_secs: Some(0),
            workload_timeout_secs: Some(0),
        }
        .resolve();
        assert_eq!(zero_workload.prompt_timeout_secs, 0, "0 stays 'instant deny'");
        assert_eq!(
            zero_workload.workload_timeout_secs, DEFAULT_WORKLOAD_TIMEOUT_SECS,
            "a 0-second workload term is not expressible"
        );
        // Each term is validated on its own.
        let mixed = LimitsSlice {
            prompt_timeout_secs: Some(300),
            workload_timeout_secs: Some(0),
        }
        .resolve();
        assert_eq!(mixed.prompt_timeout_secs, 300);
        assert_eq!(mixed.workload_timeout_secs, DEFAULT_WORKLOAD_TIMEOUT_SECS);
    }

    #[test]
    fn extends_child_overrides_one_limit_and_inherits_the_other() {
        let parent = RawProfile {
            limits: Some(RawLimits {
                prompt_timeout_secs: Some(120),
                workload_timeout_secs: Some(7200),
            }),
            ..Default::default()
        };
        let child = RawProfile {
            limits: Some(RawLimits {
                prompt_timeout_secs: None,
                workload_timeout_secs: Some(900),
            }),
            ..Default::default()
        };
        let merged = merge_profiles(parent, child).limits.expect("merged limits");
        assert_eq!(
            merged.prompt_timeout_secs,
            Some(120),
            "the parent fills the gap"
        );
        assert_eq!(
            merged.workload_timeout_secs,
            Some(900),
            "the child overrides the scalar"
        );
        assert_eq!(
            resolve_limits_slice(&Some(merged)).resolve(),
            Limits {
                prompt_timeout_secs: 120,
                workload_timeout_secs: 900,
            }
        );
    }

    #[test]
    fn expanded_json_reports_limits_at_the_top_level_and_not_in_network() {
        let resolved = ResolvedProfile {
            name: "x".into(),
            filesystem: FilesystemSlice::default(),
            network: NetworkSlice::default(),
            limits: LimitsSlice {
                prompt_timeout_secs: Some(30),
                workload_timeout_secs: Some(3600),
            },
        };
        let v: serde_json::Value = serde_json::from_str(&to_expanded_json(&resolved, &[])).unwrap();
        assert_eq!(v["limits"]["prompt_timeout_secs"], 30);
        assert_eq!(v["limits"]["workload_timeout_secs"], 3600);
        assert!(
            v["network"].get("prompt_timeout_secs").is_none(),
            "the network view must not carry the prompt term"
        );
        assert!(
            v["network"].get("workload_timeout_secs").is_none(),
            "the network view must not carry the workload term"
        );
    }

    /// Behaviour is UNCHANGED for a profile relying on the defaults: 60 s +
    /// 1800 s + 120 s slack, the same numbers the old `network.*` terms (and
    /// `NetworkConfig::session_budget()`) produced.
    /// [G-46] survives the move: a 0-second prompt term means "instant deny", and
    /// the deadline it derives still leaves the workload its own term plus slack.
    #[test]
    #[cfg(feature = "mxc-backend")]
    fn a_zero_prompt_term_still_means_instant_deny_and_keeps_the_workload_term() {
        let limits = LimitsSlice {
            prompt_timeout_secs: Some(0),
            workload_timeout_secs: Some(120),
        }
        .resolve();
        assert_eq!(limits.prompt_timeout_secs, 0);
        let budget = limits.session_budget();
        assert_eq!(budget.prompt, std::time::Duration::from_secs(0));
        assert_eq!(budget.workload, std::time::Duration::from_secs(120));
        assert_eq!(
            budget.session(),
            std::time::Duration::from_secs(120) + crate::net::mxc::SESSION_SLACK,
            "deadline must be prompt + workload + slack even when prompt is 0"
        );
    }

    #[test]
    #[cfg(feature = "mxc-backend")]
    fn the_default_limits_derive_the_same_session_budget_as_before() {
        use crate::net::mxc::{SESSION_SLACK, SessionBudget};

        let budget = Limits::default().session_budget();
        assert_eq!(budget.prompt, std::time::Duration::from_secs(60));
        assert_eq!(budget.workload, std::time::Duration::from_secs(1800));
        assert_eq!(budget.slack, SESSION_SLACK);
        assert_eq!(
            budget.session(),
            std::time::Duration::from_secs(60 + 1800 + 120)
        );
        assert_eq!(budget.timeout_ms(), 1_980_000);
        assert_eq!(
            budget,
            SessionBudget::default(),
            "the defaults cannot drift"
        );
        assert_eq!(
            resolve_limits_slice(&None).resolve().session_budget(),
            SessionBudget::default(),
            "a profile without a limits section asks for the default deadline"
        );
    }

    /// A raised `limits` section widens the deadline, and the terms stay separate:
    /// a dialog that spends its whole raised term still leaves the workload its own
    /// term, so the kill the audit names is the workload's.
    #[cfg(feature = "mxc-backend")]
    #[test]
    #[cfg(feature = "mxc-backend")]
    fn a_raised_limits_section_widens_the_session_deadline() {
        use crate::net::mxc::{SESSION_SLACK, SessionBudget, SessionClock, TimeoutReason};

        let budget = LimitsSlice {
            prompt_timeout_secs: Some(300),
            workload_timeout_secs: Some(5400),
        }
        .resolve()
        .session_budget();
        assert_eq!(
            budget.prompt,
            std::time::Duration::from_secs(300),
            "the prompt term must be the resolved value, not the default"
        );
        assert_eq!(budget.workload, std::time::Duration::from_secs(5400));
        assert_eq!(
            budget.session(),
            std::time::Duration::from_secs(300 + 5400 + SESSION_SLACK.as_secs())
        );
        assert_eq!(budget.timeout_ms(), 5_820_000);
        assert!(
            budget.session() > SessionBudget::default().session(),
            "a raised profile must widen the deadline, not narrow it"
        );

        let clock = SessionClock::measured(
            budget,
            budget.session(),
            std::time::Duration::from_millis(150),
            std::time::Duration::from_secs(300),
        );
        assert_eq!(
            clock.timeout_reason(),
            TimeoutReason::WorkloadBudgetExceeded
        );
    }

    /// The loader's WIRING, not its parts: a three-level `extends` chain read from
    /// real files, resolved through `load_and_resolve`. Every helper below was
    /// tested in isolation while this path had no test at all - a regression that
    /// dropped the cycle check or the merge would have stayed green.
    #[test]
    fn a_three_level_extends_chain_is_flattened_and_merges_child_over_parent() {
        let dir = temp_dir("chain");
        std::fs::create_dir_all(&dir).unwrap();
        write_profile(&dir, "base", r#"{
            "meta": {"name": "base", "version": "1.0.0", "schema_version": 1},
            "filesystem": {"allow": ["C:/a"], "deny": ["C:/secret"]},
            "limits": {"workloadTimeoutSecs": 100},
            "network": {"profile": "minimal", "allow_domain": ["base.example"]}
        }"#);
        write_profile(&dir, "mid", &format!(r#"{{
            "meta": {{"name": "mid", "version": "1.0.0", "schema_version": 1}},
            "extends": "{}",
            "filesystem": {{"read_only": ["C:/ro"]}},
            "limits": {{"promptTimeoutSecs": 5}}
        }}"#, json_escaped(&dir.join("base.json"))));
        write_profile(&dir, "leaf", &format!(r#"{{
            "meta": {{"name": "leaf", "version": "1.0.0", "schema_version": 1}},
            "extends": "{}",
            "filesystem": {{"allow": ["C:/b"]}},
            "limits": {{"workloadTimeoutSecs": 200}},
            "network": {{"allow_domain": ["leaf.example"]}}
        }}"#, json_escaped(&dir.join("mid.json"))));

        let resolved = load_and_resolve(dir.join("leaf.json").to_str().unwrap(), &dir).unwrap();
        let allow: Vec<String> = resolved.filesystem.allow.iter().map(|p| p.display().to_string()).collect();
        assert!(allow.iter().any(|p| p.ends_with("a")), "parent grant kept: {allow:?}");
        assert!(allow.iter().any(|p| p.ends_with("b")), "child grant added: {allow:?}");
        assert!(
            resolved.filesystem.deny.iter().any(|p| p.display().to_string().ends_with("secret")),
            "the grandparent's deny survives two levels: {:?}",
            resolved.filesystem.deny
        );
        assert_eq!(
            resolved.limits.workload_timeout_secs, Some(200),
            "the child overrides an inherited scalar"
        );
        assert_eq!(
            resolved.limits.prompt_timeout_secs, Some(5),
            "an inherited scalar fills the gap"
        );
        let domains: Vec<String> = resolved.network.allow_domain.clone();
        for want in ["base.example", "leaf.example"] {
            assert!(domains.iter().any(|d| d == want), "{want} missing: {domains:?}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// CR-10: a relative profile path is a path inside the workspace, which the
    /// workload can write - so it is refused, naming the alternative. An absolute
    /// path (the operator's explicit choice) still loads.
    #[test]
    fn a_relative_profile_path_is_refused_and_an_absolute_one_loads() {
        let dir = temp_dir("cwd");
        std::fs::create_dir_all(&dir).unwrap();
        write_profile(&dir, "solo", r#"{
            "meta": {"name": "solo", "version": "1.0.0", "schema_version": 1}
        }"#);

        let err = match load_and_resolve("./solo.json", &dir) {
            Ok(_) => panic!("a workspace-relative profile must be refused"),
            Err(e) => format!("{e:#}"),
        };
        assert!(err.contains("CR-10"), "the refusal must cite the decision: {err}");

        let abs = dir.join("solo.json");
        let resolved = load_and_resolve(abs.to_str().unwrap(), &dir)
            .expect("an absolute path is the operator's explicit choice");
        assert_eq!(resolved.name, "solo");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A missing parent names the file it looked for, not just the name.
    #[test]
    fn a_missing_parent_in_the_chain_names_the_path() {
        let dir = temp_dir("missing");
        std::fs::create_dir_all(&dir).unwrap();
        write_profile(&dir, "child", r#"{
            "meta": {"name": "child", "version": "1.0.0", "schema_version": 1},
            "extends": "./nope.json"
        }"#);
        let err = match load_and_resolve(dir.join("child.json").to_str().unwrap(), &dir) {
            Ok(_) => panic!("a missing parent must fail"),
            Err(e) => format!("{e:#}"),
        };
        assert!(err.contains("nope.json"), "the error must name the missing file: {err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let mut d = std::env::temp_dir();
        d.push(format!(
            "saife-profile-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        d
    }

/// A Windows path as a JSON string value: separators doubled, so a profile file
    /// written from a test is valid JSON on this platform.
    fn json_escaped(p: &std::path::Path) -> String {
        p.display().to_string().replace('\\', "\\\\")
    }

    fn write_profile(dir: &std::path::Path, name: &str, body: &str) {
        std::fs::write(dir.join(format!("{name}.json")), body).unwrap();
    }
}
