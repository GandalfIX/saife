use anyhow::{Context, Result, bail};
use serde::Deserialize;
use serde_json::{Value, json};
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
    let Ok(rd) = std::fs::read_dir(&dir) else {
        return out;
    };
    for entry in rd.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let name = name_from_profile_file(&path).unwrap_or_else(|| {
            path.file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("?")
                .to_string()
        });
        out.push(ProfileEntry {
            name,
            source_path: path,
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

fn name_from_profile_file(path: &Path) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    let raw: RawProfile = serde_json::from_str(&text).ok()?;
    raw.meta.and_then(|m| {
        if m.name.is_empty() {
            None
        } else {
            Some(m.name)
        }
    })
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
        let mut stack: Vec<(String, String)> = Vec::new();
        let mut done: Vec<String> = Vec::new();
        let raw = load_raw_chain(name, &cwd, &mut stack, &mut done)?
            .expect("the requested profile is always merged");
        validate_schema_version(&raw)?;
        let groups = raw
            .security
            .as_ref()
            .map(|s| s.groups.clone())
            .unwrap_or_default();
        let mut fs = resolve_filesystem(&raw.filesystem, &cwd)?;
        let resolved_name = raw
            .meta
            .as_ref()
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
                .allow
                .iter()
                .map(|p| p.to_string_lossy().to_lowercase())
                .collect();
            fs.read_only
                .retain(|p| !allow_keys.contains(&p.to_string_lossy().to_lowercase()));
        }
        let resolved = ResolvedProfile {
            name: resolved_name,
            filesystem: fs,
            network: resolve_network_slice(&raw.network),
            limits: resolve_limits_slice(&raw.limits),
            runner: resolve_runner_slice(&raw.runner),
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
///   "limits": { "prompt_timeout_secs": 60, "workload_timeout_secs": 1800 },
///   "runner": { "sync": { "paths": ["apps/payments"] } }
/// }
/// ```
pub fn to_expanded_json(
    resolved: &ResolvedProfile,
    groups_expanded: &[(String, Vec<std::path::PathBuf>)],
) -> String {
    let mut groups_obj = serde_json::Map::new();
    for (name, paths) in groups_expanded {
        let arr: Vec<Value> = paths
            .iter()
            .map(|p| json!(p.to_string_lossy().to_string()))
            .collect();
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
        },
        // The build runner's copy allow-list: `[]` means "the whole project", which is what
        // every profile that predates the field resolves to.
        "runner": {
            "sync": { "paths": resolved.runner.paths },
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
    let mut by_group: std::collections::BTreeMap<String, Vec<std::path::PathBuf>> =
        std::collections::BTreeMap::new();
    for g in grants {
        by_group
            .entry(g.label.to_string())
            .or_default()
            .push(g.path);
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

/// The current user's profile directory as the OS records it, via
/// `SHGetKnownFolderPath(FOLDERID_Profile)` — deliberately NOT the
/// `USERPROFILE` environment variable, which is caller-controlled (the
/// integration harness repoints it at a throwaway directory). The credential
/// denies below are rooted here so an env mismatch cannot move them off the
/// real profile tree (M3, security review 2026-11-09).
///
/// `None` only if the known-folder lookup genuinely fails (no profile, or a
/// broken shell install); callers fall back to `USERPROFILE` and warn then.
pub(crate) fn system_profile_root() -> Option<PathBuf> {
    use windows::Win32::System::Com::CoTaskMemFree;
    use windows::Win32::UI::Shell::{FOLDERID_Profile, KF_FLAG_DEFAULT, SHGetKnownFolderPath};
    unsafe {
        let raw = SHGetKnownFolderPath(&FOLDERID_Profile, KF_FLAG_DEFAULT, None).ok()?;
        if raw.is_null() {
            return None;
        }
        // Lossy on purpose (see allowlist::known_folder_path_from_wide): an
        // unpaired surrogate must not disable the credential denies.
        let path = PathBuf::from(String::from_utf16_lossy(raw.as_wide()));
        CoTaskMemFree(Some(raw.0 as *const _));
        Some(path).filter(|p| p.is_absolute())
    }
}

/// Directories denied for EVERY launch, on both backends, whatever the profile says.
///
/// `.ssh`/`.aws`/`.azure`/`.gnupg` are credentials. `.saife` holds the plugin
/// manifests whose `command` is executed HOST-side on the next `--plugin` run, the
/// learned allow/deny policy, and sits beside the audit log and the DPAPI-wrapped
/// signing key in `%LOCALAPPDATA%\saife`. A profile that grants `$HOME` would
/// otherwise let the workload rewrite a plugin that later runs outside the sandbox -
/// a full escape, which is why this is a deny and not a documentation note.
///
/// **Rooted at the OS profile directory, not `USERPROFILE`** (M3, security review
/// 2026-11-09): `USERPROFILE` is caller-controlled (the integration harness
/// repoints it at a throwaway directory), so deriving the denies from it let a
/// repointed value deny the wrong tree and an unset value remove every deny on
/// BOTH backends. The base now comes from `SHGetKnownFolderPath(FOLDERID_Profile)`
/// via [`system_profile_root`]; `USERPROFILE` is only a fallback when that lookup
/// fails, and a warning is printed then so the degradation is visible. The `%LOCALAPPDATA%`
/// part keeps its env-derived behaviour (the known-folder equivalent is not in
/// this module yet).
/// What kind of filesystem object a credential deny names: a whole tree or one
/// file. The backends treat them differently (a dir deny is inheritable, a file
/// deny is not), so the policy loader must know which shape an entry has.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DenyKind {
    /// A directory, denied with an inheritable ACE (the whole subtree).
    Dir,
    /// A single file, denied with a non-inheritable ACE.
    File,
}

/// Why an entry is always denied. The class is what decides whether an operator
/// may lift the deny for a session: a `Secret` never is, a `ToolCredential` can
/// be, by label, with an audit leaf - because a private key has no legitimate
/// workload reader while `gh` cannot run without its own token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CredentialClass {
    /// A private key or the tool's own control plane. No workload has a
    /// legitimate reason to read it, so no flag exposes it - an exposure
    /// request for one is refused by name.
    Secret,
    /// A credential a tool needs to function (gh, kubectl, docker, cargo, git,
    /// maven, gradle, nuget, pypi). Denied by default - that is what keeps an
    /// ACCIDENT from handing the workload a token - and exposable per session
    /// with `--expose-credential`, loudly. Serving these without exposing the
    /// value at all is F-2 (ADR-0001: credential injection at the proxy, which
    /// needs selective TLS termination).
    ToolCredential,
}

impl DenyKind {
    pub fn as_str(self) -> &'static str {
        match self {
            DenyKind::Dir => "dir",
            DenyKind::File => "file",
        }
    }
}

impl CredentialClass {
    pub fn as_str(self) -> &'static str {
        match self {
            CredentialClass::Secret => "secret",
            CredentialClass::ToolCredential => "tool-credential",
        }
    }
}

/// One entry of the always-denied set, with the identity the operator and the
/// audit use. `label` is the stable name `--expose-credential` takes; it is
/// `&'static str` because the set is code, not configuration - a profile file
/// could not strengthen it, and a policy file cannot weaken it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialDeny {
    pub label: &'static str,
    pub path: std::path::PathBuf,
    pub kind: DenyKind,
    pub class: CredentialClass,
}

/// The authoritative always-denied set: the six trees and nine credential
/// files, each with its label, kind and class. The flat
/// [`builtin_deny_dirs`]/[`builtin_deny_files`] are derivations of this list -
/// one source of truth, because a list that lives twice rots twice (the first
/// review already found the flat list and the mxc list disagreeing).
pub fn credential_denies_with(
    home: Option<&std::path::Path>,
    local_appdata: Option<&std::path::Path>,
    appdata: Option<&std::path::Path>,
) -> Vec<CredentialDeny> {
    let mut out = Vec::new();
    if let Some(home) = home {
        // Class Secret - the trees a private key lives in, plus the tool's own
        // control plane. The order is the flat list's historical order; the
        // count tests pin it.
        for (label, dir) in [
            ("ssh", ".ssh"),
            ("aws", ".aws"),
            ("azure", ".azure"),
            ("gnupg", ".gnupg"),
            ("saife", ".saife"),
        ] {
            out.push(CredentialDeny {
                label,
                path: home.join(dir),
                kind: DenyKind::Dir,
                class: CredentialClass::Secret,
            });
        }
        // Google Cloud's credential store: `credentials.db` and
        // `access_tokens.db` are live OAuth tokens, not config. Windows gcloud
        // defaults to `%APPDATA%\gcloud` (denied below), other platforms to
        // `~/.config/gcloud`; denying both costs nothing and covers a
        // `CLOUDSDK_CONFIG`-less install of either shape.
        out.push(CredentialDeny {
            label: "gcloud",
            path: home.join(".config").join("gcloud"),
            kind: DenyKind::Dir,
            class: CredentialClass::Secret,
        });
        // Class ToolCredential - one entry per tool that cannot run without
        // the credential, in the flat list's order. `label` is what
        // `--expose-credential` takes.
        for (label, dir, file, kind) in [
            (
                "gradle",
                Some(".gradle"),
                "gradle.properties",
                DenyKind::File,
            ),
            ("maven", Some(".m2"), "settings.xml", DenyKind::File),
            ("cargo", Some(".cargo"), "credentials.toml", DenyKind::File),
            ("git", None, ".git-credentials", DenyKind::File),
            ("docker", Some(".docker"), "config.json", DenyKind::File),
            ("kube", Some(".kube"), "config", DenyKind::File),
            // `hosts.yml` inside this directory holds the OAuth token, so the
            // deny has to be inheritable: denying the directory object alone
            // leaves its children readable through a grant on `~/.config` -
            // the tree every other tool also writes to. The entry is the `gh`
            // subtree, never `.config` itself.
            ("gh", Some(".config"), "gh", DenyKind::Dir),
            ("pypi", None, ".pypirc", DenyKind::File),
        ] {
            out.push(CredentialDeny {
                label,
                path: match dir {
                    Some(dir) => home.join(dir).join(file),
                    None => home.join(file),
                },
                kind,
                class: CredentialClass::ToolCredential,
            });
        }
    }
    if let Some(local) = local_appdata {
        out.push(CredentialDeny {
            label: "saife-local",
            path: local.join("saife"),
            kind: DenyKind::Dir,
            class: CredentialClass::Secret,
        });
    }
    if let Some(appdata) = appdata {
        out.push(CredentialDeny {
            label: "nuget",
            path: appdata.join("NuGet").join("NuGet.Config"),
            kind: DenyKind::File,
            class: CredentialClass::ToolCredential,
        });
        // Windows gcloud's default config root, beside the `~/.config/gcloud`
        // tree above - same store, the spelling depends on the platform.
        out.push(CredentialDeny {
            label: "gcloud-appdata",
            path: appdata.join("gcloud"),
            kind: DenyKind::Dir,
            class: CredentialClass::Secret,
        });
    }
    out
}

/// The always-denied set from the process environment (the real machine).
pub fn credential_denies() -> Vec<CredentialDeny> {
    credential_denies_with(
        credential_deny_base().as_deref(),
        std::env::var_os("LOCALAPPDATA")
            .map(std::path::PathBuf::from)
            .as_deref(),
        std::env::var_os("APPDATA")
            .map(std::path::PathBuf::from)
            .as_deref(),
    )
}

/// One exposure an operator requested and the resolver accepted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExposedCredential {
    /// The label the operator named, exactly as accepted.
    pub label: String,
    /// The path whose deny is dropped for this session.
    pub path: std::path::PathBuf,
    /// Always `ToolCredential` - `Secret` entries refuse at resolve time.
    pub class: CredentialClass,
}

/// The deny set a session actually launches with: the builtin entries minus the
/// ones the operator exposed, plus the machine policy's additions.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EffectiveDenies {
    pub dirs: Vec<std::path::PathBuf>,
    pub files: Vec<std::path::PathBuf>,
    pub policy: PolicyDenies,
    pub exposed: Vec<ExposedCredential>,
}

/// Resolve the effective deny set. `exposed` carries the labels the operator
/// named; an unknown label or a `Secret` label is refused here (a typo must not
/// silently no-op, and a private key is not the operator's to give), which is
/// what makes the flag loud by construction. `policy_dir` is the machine
/// policy's `deny.d` directory; `None` skips the policy (tests pin the deny set
/// without the machine's own deployment).
pub fn effective_denies_with(
    exposed: &[String],
    home: Option<&std::path::Path>,
    local_appdata: Option<&std::path::Path>,
    appdata: Option<&std::path::Path>,
    policy_dir: Option<&std::path::Path>,
) -> Result<EffectiveDenies> {
    let all = credential_denies_with(home, local_appdata, appdata);
    let policy = match policy_dir {
        Some(dir) => policy_denies_in(dir)?,
        None => PolicyDenies::default(),
    };
    let mut eff = EffectiveDenies {
        dirs: all
            .iter()
            .filter(|d| d.kind == DenyKind::Dir)
            .map(|d| d.path.clone())
            .collect(),
        files: all
            .iter()
            .filter(|d| d.kind == DenyKind::File)
            .map(|d| d.path.clone())
            .collect(),
        policy,
        exposed: Vec::new(),
    };
    let mut seen = std::collections::HashSet::new();
    for label in exposed {
        if !seen.insert(label.to_lowercase()) {
            continue;
        }
        let entry = all
            .iter()
            .find(|d| d.label.eq_ignore_ascii_case(label))
            .ok_or_else(|| {
                let known: Vec<&str> = all.iter().map(|d| d.label).collect();
                anyhow::anyhow!(
                    "unknown credential label `{}` - the known labels are: {}",
                    label,
                    known.join(", ")
                )
            })?;
        if entry.class == CredentialClass::Secret {
            anyhow::bail!(
                "`{}` is classified `{}` and can never be exposed: it is a private key or the \
                 tool's own control plane, and no workload has a legitimate reason to read it",
                label,
                entry.class.as_str()
            );
        }
        if entry.kind == DenyKind::Dir {
            eff.dirs.retain(|p| !path_covers(p, &entry.path));
        } else {
            eff.files.retain(|p| !path_covers(p, &entry.path));
        }
        eff.exposed.push(ExposedCredential {
            label: label.to_string(),
            path: entry.path.clone(),
            class: entry.class,
        });
    }
    // The machine policy joins the set the backends consume. Additive only:
    // nothing above removed an entry on its behalf, and there is no key in a
    // policy file that could.
    for dir in &eff.policy.dirs {
        if !eff.dirs.iter().any(|p| path_covers(p, dir)) {
            eff.dirs.push(dir.clone());
        }
    }
    for file in &eff.policy.files {
        if !eff.files.iter().any(|p| path_covers(p, file)) {
            eff.files.push(file.clone());
        }
    }
    // The policy directory itself is denied: the file names alone reveal where
    // the org keeps secrets, which is more than a workload needs to know. It
    // exists only when a policy is deployed, and a deny on a missing path is
    // skipped by the backends.
    if let Some(dir) = policy_dir.filter(|dir| dir.exists()) {
        eff.dirs.push(dir.to_path_buf());
    }
    Ok(eff)
}

/// The effective deny set on this machine: builtin entries plus the machine
/// policy, minus the exposure the operator requested.
pub fn effective_denies(exposed: &[String]) -> Result<EffectiveDenies> {
    // Resolve the policy through `policy_denies()` so `saife credentials list`
    // and `saife run` go through ONE load path (and its one error message).
    let policy_dir = policy_dir();
    effective_denies_with(
        exposed,
        credential_deny_base().as_deref(),
        std::env::var_os("LOCALAPPDATA")
            .map(std::path::PathBuf::from)
            .as_deref(),
        std::env::var_os("APPDATA")
            .map(std::path::PathBuf::from)
            .as_deref(),
        policy_dir.as_deref(),
    )
}

/// What the machine policy added, and where it came from - the audit records
/// the sources, not just a count, so a session's leaf names the files in force.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PolicyDenies {
    /// Whole trees the policy denies, in file order (a policy is deployed as
    /// several files; the order is the sorted file order, so two machines read
    /// the same files into the same order).
    pub dirs: Vec<std::path::PathBuf>,
    /// Single files the policy denies, in the same order.
    pub files: Vec<std::path::PathBuf>,
    /// The policy files these entries came from, in load order.
    pub sources: Vec<std::path::PathBuf>,
}

/// The machine-wide policy directory: `%PROGRAMDATA%\saife\deny.d`. It lives
/// under ProgramData deliberately - the point of an additive policy is that an
/// admin can deploy it and a standard user cannot weaken it, and the builtin
/// list is code for the same reason (a floor that lives in a file the workload
/// may reach is not a floor).
pub fn policy_dir() -> Option<std::path::PathBuf> {
    std::env::var_os("PROGRAMDATA")
        .map(|pd| std::path::PathBuf::from(pd).join("saife").join("deny.d"))
}

pub(crate) fn policy_denies_in(dir: &std::path::Path) -> Result<PolicyDenies> {
    if !dir.is_dir() {
        return Ok(PolicyDenies::default());
    }
    let mut files: Vec<std::path::PathBuf> = std::fs::read_dir(dir)
        .with_context(|| format!("read policy directory {}", dir.display()))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| {
            p.is_file()
                && p.extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("json"))
        })
        .collect();
    files.sort_by_key(|p| {
        p.file_name()
            .map(|n| n.to_string_lossy().to_lowercase())
            .unwrap_or_default()
    });
    let mut out = PolicyDenies::default();
    for file in files {
        let text = std::fs::read_to_string(&file)
            .with_context(|| format!("read policy file {}", file.display()))?;
        let raw: RawPolicy = serde_json::from_str(&text)
            .with_context(|| format!("parse policy file {}", file.display()))?;
        if raw.schema_version != 1 {
            anyhow::bail!(
                "{}: schema_version {} is not supported by this build (this build speaks 1)",
                file.display(),
                raw.schema_version
            );
        }
        if raw.deny.dirs.is_empty() && raw.deny.files.is_empty() {
            anyhow::bail!(
                "{} adds no deny entry - an empty policy file is a deployment mistake, not a no-op",
                file.display()
            );
        }
        for entry in &raw.deny.dirs {
            let path = policy_path(entry, &file, dir)?;
            if !out
                .dirs
                .iter()
                .any(|p| path_covers(p, &path) || path_covers(&path, p))
            {
                out.dirs.push(path);
            }
        }
        for entry in &raw.deny.files {
            let path = policy_path(entry, &file, dir)?;
            if !out
                .files
                .iter()
                .any(|p| path_covers(p, &path) || path_covers(&path, p))
            {
                out.files.push(path);
            }
        }
        out.sources.push(file);
    }
    Ok(out)
}

/// Validate one policy path at load time: it must resolve to an ABSOLUTE path
/// with no `..` component. A relative spelling would depend on a cwd a policy
/// does not have (the session's, the supervisor's, whichever ran first), and a
/// `..` climb would make the same file mean different things on different
/// machines. `$CWD`/`$SID` are refused by name: they are per-session values,
/// and a policy that named the session's cwd would deny a different tree per
/// launch - the operator should deny the real path.
fn policy_path(
    raw: &str,
    file: &std::path::Path,
    policy_dir: &std::path::Path,
) -> Result<std::path::PathBuf> {
    if raw.contains("$CWD") || raw.contains("$SID") {
        anyhow::bail!(
            "{}: `{}` uses a per-session variable; a policy denies a real path, not a cwd",
            file.display(),
            raw
        );
    }
    let expanded = expand_vars(raw, policy_dir)
        .with_context(|| format!("{}: expand `{}`", file.display(), raw))?;
    let path = std::path::PathBuf::from(&expanded);
    if !path.is_absolute() {
        anyhow::bail!(
            "{}: `{}` is not absolute after expansion - a policy deny must name the tree it hides",
            file.display(),
            raw
        );
    }
    if path
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        anyhow::bail!("{}: `{}` climbs out with `..`", file.display(), raw);
    }
    Ok(path)
}

/// The schema of one machine-policy file. Additive by construction: there is no
/// `allow` key to remove anything, and `deny_unknown_fields` refuses a moved
/// key rather than aliasing it - the same stance the profile loader takes.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPolicy {
    schema_version: u32,
    deny: RawPolicyDeny,
    /// Optional free text for the human who reads the deployment; carried for
    /// the file's own documentation, never interpreted.
    #[serde(default)]
    #[allow(dead_code)]
    note: Option<String>,
}

#[derive(serde::Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct RawPolicyDeny {
    #[serde(default)]
    dirs: Vec<String>,
    #[serde(default)]
    files: Vec<String>,
}

/// The base the credential denies are rooted at: the OS-known profile
/// directory, falling back to `USERPROFILE` only if the known-folder lookup
/// genuinely fails (and warning then, so the degradation is visible rather
/// than silently re-opening the M3 hole).
fn credential_deny_base() -> Option<std::path::PathBuf> {
    if let Some(root) = system_profile_root() {
        return Some(root);
    }
    let env = std::env::var_os("USERPROFILE").map(std::path::PathBuf::from);
    if env.is_some() {
        eprintln!(
            "[saife] warning: SHGetKnownFolderPath(FOLDERID_Profile) failed; \
             deriving the credential-deny base from %USERPROFILE% instead. \
             A repointed or unset USERPROFILE will move the credential denies \
             off the real profile tree (M3)."
        );
    }
    env
}

/// Does `outer` contain `inner` (equal, or an ancestor)? Component-wise and
/// case-insensitive, because Windows paths are. Used to refuse a session whose
/// deny would swallow a grant instead of silently locking the workload out.
///
/// Comparison happens on [`path_key`], the same normalization the mxc backend's
/// deny-vs-grant check uses (`crate::net::mxc::path_key`), so a deny spelled
/// with a trailing dot/space, a `\\.`/`\\..` segment, a verbatim `\\?\` prefix
/// or a forward-slash separator compares equal to the plain spelling — Win32
/// treats all of these as one directory, and a pre-flight that does not is a
/// grant that ships inside a deny. `path_key` is private to (and feature-gated
/// behind) the mxc module, so the normalization is mirrored here; the two must
/// stay in lock-step.
pub fn path_covers(outer: &std::path::Path, inner: &std::path::Path) -> bool {
    let outer = path_key(&outer.to_string_lossy());
    let inner = path_key(&inner.to_string_lossy());
    // An empty deny covers nothing: an empty deny is a mistake, not a wildcard.
    !outer.is_empty()
        && (inner == outer
            || inner
                .strip_prefix(&outer)
                .is_some_and(|rest| rest.starts_with('\\')))
}

/// Normalized comparison key for a Windows path — a faithful mirror of
/// [`crate::net::mxc::path_key`]. See that function's docs for the full list of
/// spellings this unifies; the short version is: separators become `\\`, a
/// verbatim/device prefix is dropped, each component loses its trailing dots
/// and spaces (before the `.`/`..` tests), `.` is dropped and `..` collapses,
/// and the whole key is upper-cased. Nothing here touches the filesystem.
fn path_key(path: &str) -> String {
    let unified = unify_path_prefix(path);
    let (root, rest) = split_path_root(&unified);

    let mut segments: Vec<&str> = Vec::new();
    for segment in rest.split('\\') {
        // Trailing spaces first, then the `.`/`..` tests, then the dots: Windows
        // ignores a component's trailing dots and spaces *before* deciding what
        // the component means, so `.. ` is the parent directory. Doing it in any
        // other order dropped `.. ` (it trimmed to nothing).
        let segment = segment.trim_end_matches(' ');
        if segment.is_empty() || segment == "." {
            continue;
        }
        if segment == ".." {
            segments.pop();
            continue;
        }
        let segment = trim_component(segment);
        if !segment.is_empty() {
            segments.push(segment);
        }
    }

    let mut key = fold_case(&root);
    for segment in segments {
        if !key.is_empty() && !key.ends_with('\\') {
            key.push('\\');
        }
        key.push_str(&fold_case(segment));
    }
    key
}

/// Separator unification plus verbatim/device-prefix removal. Mirror of
/// `mxc::unify_path_prefix`.
fn unify_path_prefix(path: &str) -> String {
    let raw = path.trim().replace('/', "\\");
    let bytes = raw.as_bytes();
    if bytes.len() < 4
        || !(bytes[..4].eq_ignore_ascii_case(br"\\?\")
            || bytes[..4].eq_ignore_ascii_case(br"\\.\\"))
    {
        return raw;
    }
    let rest = &raw[4..];
    let rest_bytes = rest.as_bytes();
    if rest_bytes.len() >= 4 && rest_bytes[..4].eq_ignore_ascii_case(br"UNC\") {
        return format!("\\\\{}", &rest[4..]);
    }
    rest.to_string()
}

/// Split a unified path into its root (`C:`, `\\server\share`, `\`, or `""`)
/// and the part below it. Mirror of `mxc::split_path_root`.
fn split_path_root(path: &str) -> (String, &str) {
    let bytes = path.as_bytes();
    if bytes.len() >= 2 && bytes[0] == b'\\' && bytes[1] == b'\\' {
        let mut parts = path[2..].splitn(3, '\\');
        let server = parts.next().unwrap_or_default();
        let share = parts.next().unwrap_or_default();
        let end = 2 + server.len() + usize::from(!share.is_empty()) + share.len();
        let root = if share.is_empty() {
            format!("\\\\{}", trim_component(server))
        } else {
            format!("\\\\{}\\{}", trim_component(server), trim_component(share))
        };
        return (root, &path[end..]);
    }
    if bytes.len() >= 2 && bytes[1] == b':' {
        return (path[..2].to_string(), &path[2..]);
    }
    if bytes.first() == Some(&b'\\') {
        return ("\\".to_string(), &path[1..]);
    }
    (String::new(), path)
}

/// One path component as Win32 compares it: trailing dots and spaces are not
/// part of the name. Mirror of `mxc::trim_component`.
fn trim_component(component: &str) -> &str {
    component.trim_end_matches(['.', ' '])
}

/// Win32's case fold, as closely as `std` approximates it: Unicode uppercase.
/// Mirror of `mxc::fold_case`.
fn fold_case(text: &str) -> String {
    text.to_uppercase()
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
    pub runner: RunnerSyncSlice,
}

/// `"extends": "parent"` or `"extends": ["a", "b"]`. Untagged, so the single-parent
/// spelling that every shipped profile uses keeps parsing unchanged.
#[derive(Debug, Clone)]
pub enum OneOrMany {
    One(String),
    Many(Vec<String>),
}

impl OneOrMany {
    fn names(&self) -> Vec<String> {
        match self {
            OneOrMany::One(s) => vec![s.clone()],
            OneOrMany::Many(v) => v.clone(),
        }
    }
}

impl<'de> serde::Deserialize<'de> for OneOrMany {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        #[derive(serde::Deserialize)]
        #[serde(untagged)]
        enum Repr {
            One(String),
            Many(Vec<String>),
        }
        Ok(match Repr::deserialize(d)? {
            Repr::One(s) => OneOrMany::One(s),
            Repr::Many(v) => OneOrMany::Many(v),
        })
    }
}

/// Raw profile JSON (v1 schema).
#[derive(Clone, Debug, Deserialize, Default)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct RawProfile {
    #[serde(default)]
    pub meta: Option<Meta>,
    /// One parent, or several. A workload that needs two unrelated toolchains
    /// (Node and the JVM, say) had to invent an intermediate profile that restated
    /// one parent's slice by hand and drifted from it; composition is a schema
    /// question, not a policy one.
    #[serde(default)]
    pub extends: Option<OneOrMany>,
    #[serde(default)]
    pub security: Option<Security>,
    #[serde(default)]
    pub filesystem: Option<RawFilesystem>,
    #[serde(default)]
    pub network: Option<RawNetwork>,
    /// The session-deadline terms (see [`RawLimits`]). Top level, NOT `network.*`.
    #[serde(default)]
    pub limits: Option<RawLimits>,
    /// What the build runner copies into its container (see [`RawRunner`]).
    #[serde(default)]
    pub runner: Option<RawRunner>,
    #[serde(default)]
    pub workdir: Option<Workdir>,
}

#[derive(Clone, Debug, Deserialize, Default)]
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

#[derive(Clone, Debug, Deserialize, Default)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct Security {
    #[serde(default)]
    pub groups: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Default)]
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
    pub block_net: Option<bool>,
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

/// `runner` block: what the session's build runner is allowed to copy into its container.
///
/// Same shape rule as every other optional section: absent means "no default", so a profile
/// written before this field existed loads and behaves exactly as it did.
#[derive(Clone, Debug, Deserialize, Default)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct RawRunner {
    #[serde(default)]
    pub sync: Option<RawRunnerSync>,
}

/// `runner.sync`: the copy allow-list a build request inherits when it names none.
///
/// Entries are relative to the PROJECT root (never to the workspace), so nothing here is
/// variable-expanded - `$CWD` would name the session's directory, not the project's.
#[derive(Clone, Debug, Deserialize, Default)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct RawRunnerSync {
    #[serde(default)]
    pub paths: Vec<String>,
}

/// The runner slice of a profile, after merging `extends`: the copy allow-list this session
/// hands to a request that names none. Empty = the whole project.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RunnerSyncSlice {
    pub paths: Vec<String>,
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
    "runner",
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
        if levenshtein(&lower, known) <= 2 || lower.starts_with(known) || known.starts_with(&lower)
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
    if n == 0 {
        return m;
    }
    if m == 0 {
        return n;
    }
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
    let mut stack: Vec<(String, String)> = Vec::new();
    let mut done: Vec<String> = Vec::new();
    let raw = load_raw_chain(name, cwd, &mut stack, &mut done)?
        .expect("the root profile is always merged");
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
        fs.read_only
            .retain(|p| !allow_keys.contains(&p.to_string_lossy().to_lowercase()));
    }

    Ok(ResolvedProfile {
        name: resolved_name,
        filesystem: fs,
        network: resolve_network_slice(&raw.network),
        limits: resolve_limits_slice(&raw.limits),
        runner: resolve_runner_slice(&raw.runner),
    })
}

/// Recursively load a profile and its `extends` chain. The deepest parent is
/// loaded first; the child is merged on top (child keys override, arrays
/// concatenate for filesystem.allow / read_only / deny).
fn load_raw_chain(
    name: &str,
    cwd: &Path,
    stack: &mut Vec<(String, String)>,
    done: &mut Vec<String>,
) -> Result<Option<RawProfile>> {
    let path = resolve_profile_path(name, cwd)?;
    // Diamond dedupe keys on the RESOLVED path, not the spelling: `a` and `./a.json`
    // are one profile.
    let key = path.to_string_lossy().to_lowercase();
    if let Some(pos) = stack.iter().position(|(k, _)| k == &key) {
        // Close the chain on the profile the operator can recognise, not on the path
        // it happened to be spelled with.
        let mut chain: Vec<&str> = stack[pos..].iter().map(|(_, n)| n.as_str()).collect();
        chain.push(stack[pos].1.as_str());
        bail!("Profile cycle detected: {}", chain.join(" → "));
    }
    if done.iter().any(|k| k == &key) {
        // Reachable twice (a diamond): merge it ONCE, which is also what keeps a
        // shared parent from looking like two disagreeing ones.
        return Ok(None);
    }

    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("read profile {}", path.display()))?;
    let raw: RawProfile = serde_json::from_str(&text)
        .map_err(with_suggestion)
        .with_context(|| format!("parse profile {}", path.display()))?;

    let display = raw
        .meta
        .as_ref()
        .map(|m| m.name.clone())
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| name.to_string());
    stack.push((key.clone(), display));
    let parents = raw.extends.as_ref().map(|e| e.names()).unwrap_or_default();
    let mut parts: Vec<(String, RawProfile)> = Vec::new();
    for parent in &parents {
        if let Some(p) = load_raw_chain(parent, cwd, stack, done)? {
            parts.push((parent.clone(), p));
        }
    }
    stack.pop();

    let merged = if parts.is_empty() {
        raw
    } else {
        let parent_set = merge_parent_set(&parts, &raw)?;
        merge_profiles(parent_set, raw)
    };
    done.push(key);
    Ok(Some(merged))
}

/// Merge the PARENTS of one profile. Arrays concatenate and dedupe; scalars must
/// AGREE - a profile that silently loses a budget or a security flag is worse than a
/// parse error, which is the same stance as refusing a moved key rather than aliasing
/// it. The child then overrides whatever it sets itself ([`merge_profiles`]).
fn merge_parent_set(parts: &[(String, RawProfile)], child: &RawProfile) -> Result<RawProfile> {
    let mut allow = Vec::new();
    let mut read_only = Vec::new();
    let mut deny = Vec::new();
    let mut groups = Vec::new();
    let mut allow_domain = Vec::new();
    let mut deny_domain = Vec::new();
    let mut block_net: Vec<(String, bool)> = Vec::new();
    let mut net_profile: Vec<(String, String)> = Vec::new();
    let mut prompt_enabled: Vec<(String, bool)> = Vec::new();
    let mut on_unavailable: Vec<(String, String)> = Vec::new();
    let mut upstream_proxy: Vec<(String, String)> = Vec::new();
    let mut prompt_secs: Vec<(String, u32)> = Vec::new();
    let mut workload_secs: Vec<(String, u32)> = Vec::new();
    let mut runner_paths: Vec<String> = Vec::new();

    for (spelled, part) in parts {
        // The refusal must name the PARENT, not the spelling: a profile reached as
        // `C:\...\a.json` is still "a" to the operator reading the error.
        let display = part
            .meta
            .as_ref()
            .map(|m| m.name.clone())
            .filter(|n| !n.is_empty())
            .unwrap_or_else(|| spelled.clone());
        let n = display.as_str();
        if let Some(f) = &part.filesystem {
            allow.extend(f.allow.iter().cloned());
            read_only.extend(f.read_only.iter().cloned());
            deny.extend(f.deny.iter().cloned());
        }
        if let Some(s) = &part.security {
            groups.extend(s.groups.iter().cloned());
        }
        if let Some(net) = &part.network {
            allow_domain.extend(net.allow_domain.iter().cloned());
            deny_domain.extend(net.deny_domain.iter().cloned());
            if let Some(v) = net.block_net {
                block_net.push((n.to_string(), v));
            }
            if let Some(v) = &net.profile {
                net_profile.push((n.to_string(), v.clone()));
            }
            if let Some(v) = net.prompt_enabled {
                prompt_enabled.push((n.to_string(), v));
            }
            if let Some(v) = &net.on_unavailable {
                on_unavailable.push((n.to_string(), v.clone()));
            }
            if let Some(v) = &net.upstream_proxy {
                upstream_proxy.push((n.to_string(), v.clone()));
            }
        }
        if let Some(l) = &part.limits {
            if let Some(v) = l.prompt_timeout_secs {
                prompt_secs.push((n.to_string(), v));
            }
            if let Some(v) = l.workload_timeout_secs {
                workload_secs.push((n.to_string(), v));
            }
        }
        if let Some(r) = &part.runner
            && let Some(s) = &r.sync
        {
            runner_paths.extend(s.paths.iter().cloned());
        }
    }

    // The child decides first: a profile that sets the value itself never sees its
    // parents' disagreement, which is the rule the brief states.
    let child_net = child.network.as_ref();
    let child_lim = child.limits.as_ref();
    let scalar = |key: &str, own: Option<bool>, vals: &[(String, bool)]| -> Result<Option<bool>> {
        match own {
            Some(v) => Ok(Some(v)),
            None => agree(key, vals),
        }
    };

    let network = if allow_domain.is_empty()
        && deny_domain.is_empty()
        && block_net.is_empty()
        && net_profile.is_empty()
        && prompt_enabled.is_empty()
        && on_unavailable.is_empty()
        && upstream_proxy.is_empty()
    {
        None
    } else {
        Some(RawNetwork {
            block_net: scalar(
                "network.block_net",
                child_net.and_then(|n| n.block_net),
                &block_net,
            )?,
            allow_domain: dedupe_vec(allow_domain),
            profile: match child_net.and_then(|n| n.profile.clone()) {
                Some(v) => Some(v),
                None => agree("network.profile", &net_profile)?,
            },
            deny_domain: dedupe_vec(deny_domain),
            prompt_enabled: scalar(
                "network.prompt_enabled",
                child_net.and_then(|n| n.prompt_enabled),
                &prompt_enabled,
            )?,
            on_unavailable: match child_net.and_then(|n| n.on_unavailable.clone()) {
                Some(v) => Some(v),
                None => agree("network.on_unavailable", &on_unavailable)?,
            },
            upstream_proxy: match child_net.and_then(|n| n.upstream_proxy.clone()) {
                Some(v) => Some(v),
                None => agree("network.upstream_proxy", &upstream_proxy)?,
            },
        })
    };

    Ok(RawProfile {
        meta: parts.first().and_then(|(_, p)| p.meta.clone()),
        extends: None,
        security: if groups.is_empty() {
            None
        } else {
            Some(Security {
                groups: dedupe_vec(groups),
            })
        },
        filesystem: Some(RawFilesystem {
            allow: dedupe_vec(allow),
            read_only: dedupe_vec(read_only),
            deny: dedupe_vec(deny),
        }),
        network,
        limits: Some(RawLimits {
            prompt_timeout_secs: match child_lim.and_then(|l| l.prompt_timeout_secs) {
                Some(v) => Some(v),
                None => agree("limits.prompt_timeout_secs", &prompt_secs)?,
            },
            workload_timeout_secs: match child_lim.and_then(|l| l.workload_timeout_secs) {
                Some(v) => Some(v),
                None => agree("limits.workload_timeout_secs", &workload_secs)?,
            },
        }),
        runner: if runner_paths.is_empty() {
            None
        } else {
            Some(RawRunner {
                sync: Some(RawRunnerSync {
                    paths: dedupe_vec(runner_paths),
                }),
            })
        },
        workdir: None,
    })
}

/// The parents must agree on a scalar. `None` when nobody set it; the agreed value
/// when they do; a refusal naming the key, both parents and both values when they
/// do not - never last-parent-wins.
fn agree<T: PartialEq + std::fmt::Display + Clone>(
    key: &str,
    values: &[(String, T)],
) -> Result<Option<T>> {
    let Some((first_name, first)) = values.first() else {
        return Ok(None);
    };
    for (name, value) in &values[1..] {
        if value != first {
            bail!(
                "`{key}` conflicts between parents `{first_name}` and `{name}`: {first} vs {value} \
                 — set it in the child to choose, or make the parents agree"
            );
        }
    }
    Ok(Some((*first).clone()))
}

fn dedupe_vec(items: Vec<String>) -> Vec<String> {
    items
        .into_iter()
        .fold(Vec::new(), |acc, item| dedupe_concat(acc, vec![item]))
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
    let dir = userprofile.join(".saife").join("profiles");
    let candidate = dir.join(format!("{name}.json"));
    // A bare name is a NAME, not a path: resolving it to a file that is not there and
    // letting the read fail produces the OS's own wording ("Das System kann die
    // angegebene Datei nicht finden"), which says nothing about which profile was
    // asked for or which ones exist. This is the message a stale `extends` produces
    // after a profile is retired.
    if !candidate.is_file() {
        let mut available: Vec<String> = std::fs::read_dir(&dir)
            .map(|rd| {
                rd.flatten()
                    .filter_map(|entry| {
                        let path = entry.path();
                        if path.extension().and_then(|e| e.to_str()) != Some("json") {
                            return None;
                        }
                        path.file_stem()
                            .and_then(|s| s.to_str())
                            .map(|s| s.to_string())
                    })
                    .collect()
            })
            .unwrap_or_default();
        available.sort();
        let available = if available.is_empty() {
            "none".to_string()
        } else {
            available.join(", ")
        };
        bail!(
            "no profile named `{name}` in {} (available: {available})",
            dir.display()
        );
    }
    Ok(candidate)
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
            block_net: c.block_net.or(p.block_net),
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
    // Same rule as every other list: arrays concatenate, so a child ADDS to its parent's
    // copy list rather than silently narrowing it (a child cannot revoke a parent's entry;
    // a build request can still win entirely, which is where narrowing belongs).
    let runner = match (parent.runner, child.runner) {
        (Some(p), Some(c)) => Some(RawRunner {
            sync: match (p.sync, c.sync) {
                (Some(p), Some(c)) => Some(RawRunnerSync {
                    paths: dedupe_concat(p.paths, c.paths),
                }),
                (Some(p), None) => Some(p),
                (None, Some(c)) => Some(c),
                (None, None) => None,
            },
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
        runner,
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
        block_net: raw.block_net.unwrap_or(false),
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

/// Resolve the runner slice from the raw `runner` block. No validation here: an entry is
/// checked where it is used ([`crate::runner::BuildRequest::validate_on_disk`]), so
/// `profile show --expanded` keeps showing what the file said.
fn resolve_runner_slice(raw: &Option<RawRunner>) -> RunnerSyncSlice {
    RunnerSyncSlice {
        paths: raw
            .as_ref()
            .and_then(|r| r.sync.as_ref())
            .map(|s| s.paths.clone())
            .unwrap_or_default(),
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
/// The tokens a profile may use. A CLOSED set on purpose: a profile is the policy,
/// so a grant has to come from something the operator can point at in the docs, not
/// from whatever happens to be exported in the shell that started the supervisor.
const PROFILE_VARS: &[&str] = &[
    "$CWD",
    "$HOME",
    "$USERPROFILE",
    "$TEMP",
    "$LOCALAPPDATA",
    "$APPDATA",
    "$JAVA_HOME",
    // Known, but substituted later: the session id does not exist at load time.
    "$SID",
];

/// `%JAVA_HOME%` and friends are set by installers WITH a trailing separator
/// (`C:\Program Files\Java\jdk-25\`), which would otherwise become `...\\bin` - a
/// different string from the same directory spelled without it.
fn strip_trailing_sep(value: impl AsRef<str>) -> String {
    let v = value.as_ref();
    let trimmed = v.trim_end_matches(['\\', '/']);
    // Keep a bare drive root ("C:\") intact: trimming it yields "C:", which is not
    // a directory at all.
    if trimmed.len() == 2 && trimmed.ends_with(':') {
        v.to_string()
    } else {
        trimmed.to_string()
    }
}

fn var_from_env(env_name: &str, token: &str, spelled: &str) -> Result<String> {
    match std::env::var_os(env_name)
        .map(|v| strip_trailing_sep(v.to_string_lossy()))
        .filter(|v| !v.is_empty())
    {
        Some(v) => Ok(v),
        // Empty used to expand to "", so "$HOME/x" became "\x": a RELATIVE path, and
        // the allow-list resolves those against the session cwd. That turned a grant
        // on the profile into a grant on the workspace, silently.
        None => bail!(
            "profile path {spelled:?} uses {token}, but {env_name} is not set. Set it, \
             or write the path out; an empty value would grant a different directory \
             than the profile says."
        ),
    }
}

pub fn expand_vars(s: &str, cwd: &Path) -> Result<String> {
    let mut out = String::with_capacity(s.len() + 32);
    let mut rest = s;
    while let Some(at) = rest.find('$') {
        out.push_str(&rest[..at]);
        let after = &rest[at + 1..];
        let len = after
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .count();
        if len == 0 {
            // A stray '$' that does not start a token (a filename may contain one).
            out.push('$');
            rest = after;
            continue;
        }
        let ident = &after[..len];
        let token = format!("${ident}");
        match ident {
            // Resolved once the session id exists; substituting it here would bake
            // "no session" into a path that is meant to be per-session.
            "SID" => out.push_str("$SID"),
            "CWD" => out.push_str(&strip_trailing_sep(cwd.to_string_lossy())),
            "HOME" | "USERPROFILE" => out.push_str(&var_from_env("USERPROFILE", &token, s)?),
            "TEMP" => out.push_str(&var_from_env("TEMP", &token, s)?),
            "JAVA_HOME" => out.push_str(&var_from_env("JAVA_HOME", &token, s)?),
            // These two have a documented fallback, so a service context (no
            // per-user environment) still resolves to the conventional location.
            "LOCALAPPDATA" | "APPDATA" => {
                let env_name = if ident == "LOCALAPPDATA" {
                    "LOCALAPPDATA"
                } else {
                    "APPDATA"
                };
                let conventional = if ident == "LOCALAPPDATA" {
                    "AppData\\Local"
                } else {
                    "AppData\\Roaming"
                };
                match std::env::var_os(env_name)
                    .map(|v| strip_trailing_sep(v.to_string_lossy()))
                    .filter(|v| !v.is_empty())
                {
                    Some(v) => out.push_str(&v),
                    None => {
                        let home = var_from_env("USERPROFILE", &token, s)?;
                        out.push_str(&home);
                        out.push('\\');
                        out.push_str(conventional);
                    }
                }
            }
            _ => bail!(
                "profile path {:?} uses {token}, which is not a variable this \
                 build expands. Known: {}. Use one of those, or an absolute path.",
                s,
                PROFILE_VARS.join(", ")
            ),
        }
        rest = &after[len..];
    }
    out.push_str(rest);
    // Normalize forward slashes to backslashes for Win32 APIs.
    Ok(out.replace('/', "\\"))
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

/// Parse `--allow path[:mode]`. Mode is one of read|readonly|readwrite;
/// default is readwrite (which grants RWX). The leading `C:` drive-letter
/// colon is NOT treated as a separator.
///
/// `write` and `execute` are recognized and REFUSED by name (M1, security
/// review 2026-11-09): this backend grants a path as ONE DACL mask, and a
/// write-only or execute-only mask is not expressible safely on Windows —
/// write-only still needs read to open what it wrote, and a loader needs
/// read to map an image at all. Widening either to RWX (the old behaviour)
/// silently granted read on a path the operator asked to keep unread, so
/// the honest minimal option is the refusal, pointing at `:readwrite`.
fn parse_allow_entry(entry: &str) -> Result<(String, String)> {
    // Find a colon that is not the drive-letter colon at index 1.
    let mode_colon = entry.rfind(':').filter(|&i| i != 1);
    match mode_colon {
        Some(i) => {
            let path = &entry[..i];
            let mode = entry[i + 1..].to_ascii_lowercase();
            match mode.as_str() {
                "read" | "readonly" | "readwrite" => Ok((path.to_string(), mode)),
                "write" | "execute" => bail!(
                    "mode `{mode}` in `{entry}` is not supported: on Windows a \
                     write-only or execute-only mask cannot be granted safely \
                     (a grant is one mask per path, and writing still needs \
                     read to open what it wrote), so `:write` and `:execute` \
                     would silently widen to full access; the supported modes \
                     are `read` (read+execute) and `readwrite` (read+write+execute, \
                     also the default for a bare `--allow <path>`)"
                ),
                _ => bail!(
                    "unknown --allow mode `{mode}` in `{entry}`: the supported \
                     modes are `read` (read+execute) and `readwrite` \
                     (read+write+execute)"
                ),
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

    /// C1 red test: the pre-flight's deny-vs-grant compare must recognize the
    /// deny directory under every spelling Win32 itself accepts — a trailing
    /// dot, a trailing space, a `\.` segment, a `\..` that still resolves into
    /// the tree, and a verbatim `\\?\` prefix. These name the same directory
    /// the plain spelling does, so a deny spelled any of these ways must still
    /// cover a grant inside it (and a normally-spelled deny must still cover
    /// a grant spelled these ways). Before the normalization the compare was
    /// textual, so all of these slipped past and the grant shipped.
    #[test]
    fn path_covers_normalizes_the_spellings_win32_accepts() {
        let plain = std::path::Path::new(r"C:\Users\u\.ssh");
        let key_inside = std::path::Path::new(r"C:\Users\u\.ssh\id_ed25519");

        // A weirdly-spelled deny must still cover a grant inside ~/.ssh.
        for deny_spelling in [
            r"C:\Users\u\.ssh.",
            r"C:\Users\u\.ssh ",
            r"C:\Users\u\.ssh\.",
            r"C:\Users\u\.ssh\..",
            r"\\?\C:\Users\u\.ssh",
        ] {
            assert!(
                path_covers(std::path::Path::new(deny_spelling), key_inside),
                "deny spelled {deny_spelling:?} must cover the grant inside ~/.ssh"
            );
        }

        // And the mirror direction: a normally-spelled deny must cover a grant
        // spelled the ways Win32 accepts for ~/.ssh itself.
        for grant_spelling in [
            r"C:\Users\u\.ssh.",
            r"C:\Users\u\.ssh ",
            r"C:\Users\u\.ssh\.",
            r"\\?\C:\Users\u\.ssh",
            r"c:/users/u/.ssh",
        ] {
            assert!(
                path_covers(plain, std::path::Path::new(grant_spelling)),
                "grant spelled {grant_spelling:?} is inside the deny and must be refused"
            );
        }

        // Negative controls: a sibling sharing the prefix is NOT inside.
        for sibling in [
            r"C:\Users\u\.ssh2",
            r"C:\Users\u\.ssh2\k",
            r"C:\Users\u\.ss",
        ] {
            assert!(
                !path_covers(plain, std::path::Path::new(sibling)),
                "{sibling:?} is a sibling, not a descendant"
            );
        }
        // `..` resolving OUT of the deny is not covered either.
        assert!(!path_covers(
            plain,
            std::path::Path::new(r"C:\Users\u\.ssh\..")
        ));
    }

    /// M3: a repointed `USERPROFILE` must not move the credential denies.
    /// The base is the OS-known profile directory, so the denies follow the
    /// REAL tree whether `USERPROFILE` points elsewhere or is unset. Exercised
    /// through the injectable seam so the test never mutates the process
    /// environment (the suite has tests that repoint `USERPROFILE`, and a
    /// global mutation would race them). The fake tree is explicitly asserted
    /// ABSENT so the pre-fix "follows the env" behaviour cannot regress.
    #[test]
    fn m3_credential_denies_follow_the_os_profile_not_userprofile() {
        let Some(real) = super::system_profile_root() else {
            // SHGetKnownFolderPath is expected to work on every Windows host
            // this crate runs on; if it ever does not, the fallback path has
            // its own warning, and this test is moot. Skip loudly rather than
            // pass vacuously.
            eprintln!(
                "[test] SHGetKnownFolderPath(FOLDERID_Profile) unavailable on this host; M3 seam test skipped"
            );
            return;
        };
        let fake = std::path::PathBuf::from(r"C:\Users\does-not-exist-fake-m3");

        let real_dirs: Vec<PathBuf> = credential_denies_with(Some(&real), None, None)
            .iter()
            .filter(|c| c.kind == DenyKind::Dir)
            .map(|c| c.path.clone())
            .collect();
        let fake_dirs: Vec<PathBuf> = credential_denies_with(Some(&fake), None, None)
            .iter()
            .filter(|c| c.kind == DenyKind::Dir)
            .map(|c| c.path.clone())
            .collect();
        let none_dirs: Vec<PathBuf> = credential_denies_with(None, None, None)
            .iter()
            .filter(|c| c.kind == DenyKind::Dir)
            .map(|c| c.path.clone())
            .collect();

        assert_eq!(
            real_dirs.len(),
            7,
            "the seven home-rooted tree denies (.ssh/.aws/.azure/.gnupg/.saife, the gh config \
             directory and gcloud's store): {real_dirs:?}"
        );
        for dir in [
            ".ssh",
            ".aws",
            ".azure",
            ".gnupg",
            ".saife",
            ".config\\gh",
            ".config\\gcloud",
        ] {
            assert!(
                real_dirs.iter().any(|d| d == &real.join(dir)),
                "the real profile must deny ~/{dir}: {real_dirs:?}"
            );
        }
        assert_eq!(
            fake_dirs.len(),
            7,
            "the fake root denies a different tree: {fake_dirs:?}"
        );
        assert!(
            !fake_dirs.iter().any(|d| d.starts_with(&real)),
            "the fake tree must not shadow the real denies: {fake_dirs:?}"
        );
        assert!(
            none_dirs.is_empty(),
            "a None base yields no home-rooted denies"
        );

        // The seam is env-independent by construction; the public entry point
        // is the wiring proof. After M3 it derives the base from the OS known
        // folder (== `real`) and never reads USERPROFILE, so a concurrent test
        // repointing USERPROFILE cannot race this call.
        let dirs: Vec<PathBuf> = credential_denies()
            .iter()
            .filter(|c| c.kind == DenyKind::Dir)
            .map(|c| c.path.clone())
            .collect();
        assert!(
            dirs.iter().any(|d| d == &real.join(".ssh")),
            "builtin_deny_dirs() must root at the OS profile, not USERPROFILE: {dirs:?}"
        );
        let files: Vec<PathBuf> = credential_denies()
            .iter()
            .filter(|c| c.kind == DenyKind::File)
            .map(|c| c.path.clone())
            .collect();
        assert!(
            files
                .iter()
                .any(|f| f == &real.join(".gradle").join("gradle.properties")),
            "builtin_deny_files() must root at the OS profile too: {files:?}"
        );
    }

    /// M3: an UNSET `USERPROFILE` must not remove the credential denies. The
    /// seam, with both bases supplied directly, yields the full deny set with
    /// no dependency on any environment variable — proving the denies survive
    /// a missing USERPROFILE without mutating the process env.
    #[test]
    fn m3_credential_denies_survive_an_unset_userprofile() {
        let Some(real) = super::system_profile_root() else {
            eprintln!(
                "[test] SHGetKnownFolderPath(FOLDERID_Profile) unavailable on this host; M3 seam test skipped"
            );
            return;
        };
        let dirs: Vec<PathBuf> = credential_denies()
            .iter()
            .filter(|c| c.kind == DenyKind::Dir)
            .map(|c| c.path.clone())
            .collect();
        assert!(
            dirs.iter().any(|d| d == &real.join(".ssh")),
            "the credential dir denies must be present with no env input: {dirs:?}"
        );
        let files: Vec<PathBuf> = credential_denies()
            .iter()
            .filter(|c| c.kind == DenyKind::File)
            .map(|c| c.path.clone())
            .collect();
        assert!(
            files
                .iter()
                .any(|f| f == &real.join(".gradle").join("gradle.properties")),
            "the credential file denies must be present with no env input: {files:?}"
        );
    }

    #[test]
    fn expand_basic() {
        let p = PathBuf::from("C:\\projekte\\myapp");
        assert_eq!(
            expand_vars("$CWD/.claude", &p).unwrap(),
            "C:\\projekte\\myapp\\.claude"
        );
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

    /// `$JAVA_HOME` (and the other toolchain roots) come from the environment, so a
    /// shipped profile stops naming one machine's JDK version. `JAVA_HOME` is set
    /// WITH a trailing separator on Windows installers, and that must not survive
    /// into the grant.
    #[test]
    fn expand_java_home_trims_the_installers_trailing_separator() {
        let _env = crate::env_lock();
        let saved = std::env::var_os("JAVA_HOME");
        unsafe { std::env::set_var("JAVA_HOME", "C:\\Program Files\\Java\\jdk-25\\") };
        let p = PathBuf::from("C:\\projekte\\myapp");
        let s = expand_vars("$JAVA_HOME/bin/java.exe", &p).unwrap();
        match saved {
            Some(v) => unsafe { std::env::set_var("JAVA_HOME", v) },
            None => unsafe { std::env::remove_var("JAVA_HOME") },
        }
        assert_eq!(s, "C:\\Program Files\\Java\\jdk-25\\bin\\java.exe");
        assert!(!s.contains("\\\\bin"), "no doubled separator: {s:?}");
    }

    /// A variable the profile uses but the environment does not define is an ERROR.
    /// The old behaviour expanded it to the empty string, so `"$HOME/x"` silently
    /// became `"\\x"` - a relative path, which the allow-list resolves against the
    /// session cwd: a grant on the workspace, spelled as a grant on the profile.
    #[test]
    fn expand_refuses_a_variable_that_is_not_set() {
        let _env = crate::env_lock();
        let saved = std::env::var_os("JAVA_HOME");
        unsafe { std::env::remove_var("JAVA_HOME") };
        let p = PathBuf::from("C:\\projekte\\myapp");
        let err = expand_vars("$JAVA_HOME/lib", &p).unwrap_err();
        match saved {
            Some(v) => unsafe { std::env::set_var("JAVA_HOME", v) },
            None => unsafe { std::env::remove_var("JAVA_HOME") },
        }
        let msg = format!("{err:#}");
        assert!(msg.contains("JAVA_HOME"), "names the variable: {msg}");
        assert!(
            msg.contains("$JAVA_HOME"),
            "names the token as written: {msg}"
        );
    }

    /// An unknown token is refused rather than left in the path: `$NOPE/x` used to
    /// survive to the DACL setup as a directory literally named `$NOPE`.
    #[test]
    fn expand_refuses_an_unknown_variable() {
        let p = PathBuf::from("C:\\projekte\\myapp");
        let err = expand_vars("$NOPE/tools", &p).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("$NOPE"), "names the token: {msg}");
        assert!(
            msg.contains("$JAVA_HOME") && msg.contains("$LOCALAPPDATA"),
            "lists the ones it knows: {msg}"
        );
    }

    /// `$SID` belongs to a later stage (the session id does not exist yet), so it
    /// stays literal here instead of being treated as unknown.
    #[test]
    fn expand_leaves_sid_for_the_later_stage() {
        let p = PathBuf::from("C:\\projekte\\myapp");
        let s = expand_vars("$TEMP/$SID/out", &p).unwrap();
        assert!(s.contains("$SID"), "left for the session: {s:?}");
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

    /// M1 (security review 2026-11-09, confirmed): `--allow <path>:write` and
    /// `:execute` were parsed and then folded into the RWX list, while
    /// `docs/USER-GUIDE.md` promised "write only". Neither mask is expressible
    /// safely here — a DACL grant is one mask per path, write-only still needs
    /// read to open what it wrote, and execute-without-read cannot load an
    /// image on Windows — so they are REFUSED by name instead of silently
    /// widened to RWX.
    #[test]
    fn parse_allow_refuses_write_and_execute_with_the_supported_modes() {
        for mode in ["write", "execute"] {
            let err = parse_allow_entry(&format!("C:/foo:{mode}"))
                .expect_err("a write-only/execute-only mode must be refused");
            let msg = format!("{err:#}");
            assert!(
                msg.contains(&format!("`{mode}`")) && msg.contains("not supported"),
                "the refusal must name the mode it rejected: {msg}"
            );
            assert!(
                msg.contains("readwrite") && msg.contains("read"),
                "the refusal must name the supported modes (read, readwrite): {msg}"
            );
            assert!(
                msg.contains("Windows"),
                "the refusal must say WHY it cannot be honoured: {msg}"
            );
            assert!(
                msg.contains("C:/foo"),
                "the refusal must quote the entry it rejected: {msg}"
            );
        }
    }

    /// The supported spellings still parse, and they keep their documented
    /// meaning: `:read`/`:readonly` land on the read-only list (RX),
    /// `:readwrite` and a bare `--allow` land on the writable list (RWX).
    #[test]
    fn allow_modes_map_to_the_documented_grant_lists() {
        let fs = merge_filesystem(
            &FilesystemSlice::default(),
            false,
            &[
                "C:/rw:readwrite".into(),
                "C:/r:read".into(),
                "C:/ro:readonly".into(),
                "C:/bare".into(),
            ],
            &[],
            Path::new("C:/proj"),
        )
        .expect("the supported modes must parse");
        let allow: Vec<String> = fs.allow.iter().map(|p| p.display().to_string()).collect();
        let ro: Vec<String> = fs
            .read_only
            .iter()
            .map(|p| p.display().to_string())
            .collect();
        assert_eq!(allow, vec![r"C:\rw".to_string(), r"C:\bare".to_string()]);
        assert_eq!(ro, vec![r"C:\r".to_string(), r"C:\ro".to_string()]);
    }

    /// `merge_filesystem` is the CLI boundary, so the refusal must happen
    /// there too — not only in the parser's own unit test.
    #[test]
    fn merge_filesystem_refuses_a_write_only_allow() {
        let err = merge_filesystem(
            &FilesystemSlice::default(),
            false,
            &["C:/foo:write".into()],
            &[],
            Path::new("C:/proj"),
        )
        .expect_err("a write-only --allow must be refused at the CLI boundary");
        assert!(
            format!("{err:#}").contains("not supported"),
            "the refusal must be the named one: {err:#}"
        );
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
        assert!(
            msg.contains("Unsupported profile schema version 99"),
            "got: {msg}"
        );
        assert!(msg.contains("supports schema version 1"), "got: {msg}");
    }

    #[test]
    fn schema_version_absent_is_treated_as_error() {
        let raw = r#"{"meta":{"name":"x"},"filesystem":{"allow":["$CWD"]}}"#;
        let p: RawProfile = serde_json::from_str(raw).expect("parses structurally");
        let err = validate_schema_version(&p).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("missing required field `meta.schema_version`"),
            "got: {msg}"
        );
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
        assert!(
            msg.contains("expected a sequence") || msg.contains("integer"),
            "got: {msg}"
        );
        assert!(msg.contains("line") || msg.contains("col"), "got: {msg}");
    }

    #[test]
    fn suggest_closest_known_key() {
        assert_eq!(suggest_unknown_key("netwrok"), Some("network".to_string()));
        assert_eq!(
            suggest_unknown_key("filesystemm"),
            Some("filesystem".to_string())
        );
        assert_eq!(suggest_unknown_key("metaa"), Some("meta".to_string()));
        assert_eq!(suggest_unknown_key("zzzzz"), None);
        assert_eq!(suggest_unknown_key("sec"), Some("security".to_string()));
    }

    #[test]
    fn list_profiles_returns_user_global_json_files() {
        let _env = crate::env_lock();
        let tmp = std::env::temp_dir().join(format!("sb-list-test-{}", std::process::id()));
        let profiles_dir = tmp.join(".saife").join("profiles");
        std::fs::create_dir_all(&profiles_dir).unwrap();
        std::fs::write(
            profiles_dir.join("alpha.json"),
            r#"{"meta":{"name":"alpha","schema_version":1}}"#,
        )
        .unwrap();
        std::fs::write(
            profiles_dir.join("beta.json"),
            r#"{"meta":{"name":"beta","schema_version":1}}"#,
        )
        .unwrap();
        std::fs::write(profiles_dir.join("not-json.txt"), "garbage").unwrap();
        let prev = std::env::var_os("USERPROFILE");
        unsafe {
            std::env::set_var("USERPROFILE", &tmp);
        }
        let result = list_profiles();
        if let Some(p) = prev {
            unsafe {
                std::env::set_var("USERPROFILE", p);
            }
        }
        std::fs::remove_dir_all(&tmp).ok();

        let names: Vec<String> = result.into_iter().map(|p| p.name).collect();
        assert!(names.contains(&"alpha".to_string()));
        assert!(names.contains(&"beta".to_string()));
        assert!(
            !names.iter().any(|n| n == "not-json"),
            "non-.json files excluded"
        );
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
            runner: RunnerSyncSlice::default(),
        };
        let groups_expanded: Vec<(String, Vec<PathBuf>)> =
            vec![("python_runtime".into(), vec![PathBuf::from(r"C:\Py312")])];
        let json = to_expanded_json(&resolved, &groups_expanded);
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["meta"]["name"], "child");
        assert_eq!(v["filesystem"]["allow"][0], r"C:\proj");
        assert_eq!(v["filesystem"]["read_only"][0], r"C:\Users\test\.gitconfig");
        assert_eq!(
            v["security_groups_expanded"]["python_runtime"][0],
            r"C:\Py312"
        );
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

    /// `runner.sync.paths` is the session profile's copy allow-list. It is PROJECT-relative,
    /// so it is not variable-expanded, and a profile without the block is the empty slice -
    /// which is what keeps every existing profile loading unchanged.
    #[test]
    fn a_profile_can_default_the_runner_copy_paths() {
        let raw: RawProfile = serde_json::from_str(
            r#"{"meta":{"name":"m","schema_version":1},"runner":{"sync":{"paths":["apps/payments","settings.gradle.kts"]}}}"#,
        )
        .expect("the runner block parses");
        assert_eq!(
            resolve_runner_slice(&raw.runner).paths,
            vec!["apps/payments", "settings.gradle.kts"]
        );

        let bare: RawProfile = serde_json::from_str(r#"{"meta":{"name":"m","schema_version":1}}"#)
            .expect("a profile without `runner` still parses");
        assert!(
            resolve_runner_slice(&bare.runner).paths.is_empty(),
            "absent means the whole project, not an error"
        );
    }

    /// Arrays concatenate across `extends`, the rule every other list in a profile follows.
    /// A child that wanted to NARROW a parent's list therefore cannot do it by restating a
    /// shorter one - the runner's own rule is that the request wins entirely, and this is
    /// the profile half of the same sentence.
    #[test]
    fn merge_profiles_concatenates_runner_sync_paths() {
        let parent = RawProfile {
            runner: Some(RawRunner {
                sync: Some(RawRunnerSync {
                    paths: vec!["apps/payments".into()],
                }),
            }),
            ..Default::default()
        };
        let child = RawProfile {
            runner: Some(RawRunner {
                sync: Some(RawRunnerSync {
                    paths: vec!["apps/checkout".into()],
                }),
            }),
            ..Default::default()
        };
        let merged = resolve_runner_slice(&merge_profiles(parent, child).runner);
        assert_eq!(merged.paths, vec!["apps/payments", "apps/checkout"]);
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
            runner: RunnerSyncSlice::default(),
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
            assert_eq!(
                l.prompt_timeout_secs, accepted,
                "prompt {accepted} is legal"
            );
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
        assert_eq!(
            zero_workload.prompt_timeout_secs, 0,
            "0 stays 'instant deny'"
        );
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
            runner: RunnerSyncSlice::default(),
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
        assert_eq!(
            v["runner"]["sync"]["paths"],
            serde_json::json!([]),
            "no list is the empty list here too, which is what means 'the whole project'"
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
        write_profile(
            &dir,
            "base",
            r#"{
            "meta": {"name": "base", "version": "1.0.0", "schema_version": 1},
            "filesystem": {"allow": ["C:/a"], "deny": ["C:/secret"]},
            "limits": {"workloadTimeoutSecs": 100},
            "network": {"profile": "minimal", "allow_domain": ["base.example"]}
        }"#,
        );
        write_profile(
            &dir,
            "mid",
            &format!(
                r#"{{
            "meta": {{"name": "mid", "version": "1.0.0", "schema_version": 1}},
            "extends": "{}",
            "filesystem": {{"read_only": ["C:/ro"]}},
            "limits": {{"promptTimeoutSecs": 5}}
        }}"#,
                json_escaped(&dir.join("base.json"))
            ),
        );
        write_profile(
            &dir,
            "leaf",
            &format!(
                r#"{{
            "meta": {{"name": "leaf", "version": "1.0.0", "schema_version": 1}},
            "extends": "{}",
            "filesystem": {{"allow": ["C:/b"]}},
            "limits": {{"workloadTimeoutSecs": 200}},
            "network": {{"allow_domain": ["leaf.example"]}}
        }}"#,
                json_escaped(&dir.join("mid.json"))
            ),
        );

        let resolved = load_and_resolve(dir.join("leaf.json").to_str().unwrap(), &dir).unwrap();
        let allow: Vec<String> = resolved
            .filesystem
            .allow
            .iter()
            .map(|p| p.display().to_string())
            .collect();
        assert!(
            allow.iter().any(|p| p.ends_with("a")),
            "parent grant kept: {allow:?}"
        );
        assert!(
            allow.iter().any(|p| p.ends_with("b")),
            "child grant added: {allow:?}"
        );
        assert!(
            resolved
                .filesystem
                .deny
                .iter()
                .any(|p| p.display().to_string().ends_with("secret")),
            "the grandparent's deny survives two levels: {:?}",
            resolved.filesystem.deny
        );
        assert_eq!(
            resolved.limits.workload_timeout_secs,
            Some(200),
            "the child overrides an inherited scalar"
        );
        assert_eq!(
            resolved.limits.prompt_timeout_secs,
            Some(5),
            "an inherited scalar fills the gap"
        );
        let domains: Vec<String> = resolved.network.allow_domain.clone();
        for want in ["base.example", "leaf.example"] {
            assert!(
                domains.iter().any(|d| d == want),
                "{want} missing: {domains:?}"
            );
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
        write_profile(
            &dir,
            "solo",
            r#"{
            "meta": {"name": "solo", "version": "1.0.0", "schema_version": 1}
        }"#,
        );

        let err = match load_and_resolve("./solo.json", &dir) {
            Ok(_) => panic!("a workspace-relative profile must be refused"),
            Err(e) => format!("{e:#}"),
        };
        assert!(
            err.contains("CR-10"),
            "the refusal must cite the decision: {err}"
        );

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
        write_profile(
            &dir,
            "child",
            r#"{
            "meta": {"name": "child", "version": "1.0.0", "schema_version": 1},
            "extends": "./nope.json"
        }"#,
        );
        let err = match load_and_resolve(dir.join("child.json").to_str().unwrap(), &dir) {
            Ok(_) => panic!("a missing parent must fail"),
            Err(e) => format!("{e:#}"),
        };
        assert!(
            err.contains("nope.json"),
            "the error must name the missing file: {err}"
        );
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
    // ------------------------------------------------------------------
    // Multi-parent `extends` (docs/design/2026-10-25-multi-extends-design.md)
    // ------------------------------------------------------------------

    /// `"extends": ["a", "b"]` parses, and the single-parent spelling still does.
    #[test]
    fn extends_accepts_a_name_or_an_array() {
        let one: RawProfile =
            serde_json::from_str(r#"{"meta":{"name":"c","schema_version":1},"extends":"a"}"#)
                .expect("the single-parent spelling keeps parsing");
        assert_eq!(one.extends.unwrap().names(), vec!["a".to_string()]);

        let many: RawProfile =
            serde_json::from_str(r#"{"meta":{"name":"c","schema_version":1},"extends":["a","b"]}"#)
                .expect("an array of parents parses");
        assert_eq!(
            many.extends.unwrap().names(),
            vec!["a".to_string(), "b".to_string()]
        );
    }

    /// The composition the design exists for: two parents' grants add up, and a
    /// scalar set by one parent comes through.
    #[test]
    fn two_parents_compose_their_grants_and_scalars() {
        let dir = temp_dir("multi-compose");
        std::fs::create_dir_all(&dir).unwrap();
        write_profile(
            &dir,
            "a",
            r#"{"meta":{"name":"a","schema_version":1},"filesystem":{"allow":["C:/x"]},"network":{"block_net":true},"limits":{"workloadTimeoutSecs":600}}"#,
        );
        write_profile(
            &dir,
            "b",
            r#"{"meta":{"name":"b","schema_version":1},"filesystem":{"allow":["C:/y"]}}"#,
        );
        write_profile(
            &dir,
            "c",
            &format!(
                r#"{{"meta":{{"name":"c","schema_version":1}},"extends":["{}","{}"]}}"#,
                json_escaped(&dir.join("a.json")),
                json_escaped(&dir.join("b.json"))
            ),
        );

        let resolved = load_and_resolve(dir.join("c.json").to_str().unwrap(), &dir).unwrap();
        let allow: Vec<String> = resolved
            .filesystem
            .allow
            .iter()
            .map(|p| p.display().to_string())
            .collect();
        assert!(
            allow.iter().any(|p| p.ends_with("x")),
            "parent a's grant: {allow:?}"
        );
        assert!(
            allow.iter().any(|p| p.ends_with("y")),
            "parent b's grant: {allow:?}"
        );
        assert!(resolved.network.block_net, "the scalar a set comes through");
        assert_eq!(resolved.limits.workload_timeout_secs, Some(600));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A child that sets the value itself wins; the parents' disagreement is moot.
    #[test]
    fn a_child_scalar_overrides_disagreeing_parents() {
        let dir = temp_dir("multi-override");
        std::fs::create_dir_all(&dir).unwrap();
        write_profile(
            &dir,
            "a",
            r#"{"meta":{"name":"a","schema_version":1},"network":{"block_net":true}}"#,
        );
        write_profile(
            &dir,
            "b",
            r#"{"meta":{"name":"b","schema_version":1},"network":{"block_net":false}}"#,
        );
        write_profile(
            &dir,
            "c",
            &format!(
                r#"{{"meta":{{"name":"c","schema_version":1}},"extends":["{}","{}"],"network":{{"block_net":false}}}}"#,
                json_escaped(&dir.join("a.json")),
                json_escaped(&dir.join("b.json"))
            ),
        );

        let resolved = load_and_resolve(dir.join("c.json").to_str().unwrap(), &dir)
            .expect("the child decides, so the parents' disagreement is moot");
        assert!(!resolved.network.block_net, "the child's value wins");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Parents that disagree and a child that stays silent: refused, naming the key,
    /// both parents and both values - never last-parent-wins.
    #[test]
    fn parents_disagreeing_on_a_scalar_are_refused() {
        let dir = temp_dir("multi-conflict");
        std::fs::create_dir_all(&dir).unwrap();
        write_profile(
            &dir,
            "a",
            r#"{"meta":{"name":"a","schema_version":1},"network":{"block_net":true}}"#,
        );
        write_profile(
            &dir,
            "b",
            r#"{"meta":{"name":"b","schema_version":1},"network":{"block_net":false}}"#,
        );
        write_profile(
            &dir,
            "c",
            &format!(
                r#"{{"meta":{{"name":"c","schema_version":1}},"extends":["{}","{}"]}}"#,
                json_escaped(&dir.join("a.json")),
                json_escaped(&dir.join("b.json"))
            ),
        );

        let err = match load_and_resolve(dir.join("c.json").to_str().unwrap(), &dir) {
            Ok(_) => panic!("disagreeing parents must be refused"),
            Err(e) => format!("{e:#}"),
        };
        for needle in ["network.block_net", "`a`", "`b`", "true", "false"] {
            assert!(
                err.contains(needle),
                "the refusal must name {needle:?}: {err}"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A parent reachable through both sides merges once: no duplicate grant, and no
    /// spurious conflict from seeing it twice.
    #[test]
    fn a_diamond_merges_the_shared_parent_once() {
        let dir = temp_dir("multi-diamond");
        std::fs::create_dir_all(&dir).unwrap();
        write_profile(
            &dir,
            "base",
            r#"{"meta":{"name":"base","schema_version":1},"filesystem":{"allow":["C:/shared"]},"network":{"block_net":true}}"#,
        );
        for side in ["l", "r"] {
            write_profile(
                &dir,
                side,
                &format!(
                    r#"{{"meta":{{"name":"{side}","schema_version":1}},"extends":"{}"}}"#,
                    json_escaped(&dir.join("base.json"))
                ),
            );
        }
        write_profile(
            &dir,
            "d",
            &format!(
                r#"{{"meta":{{"name":"d","schema_version":1}},"extends":["{}","{}"]}}"#,
                json_escaped(&dir.join("l.json")),
                json_escaped(&dir.join("r.json"))
            ),
        );

        let resolved = load_and_resolve(dir.join("d.json").to_str().unwrap(), &dir)
            .expect("a shared parent is not a conflict");
        let shared = resolved
            .filesystem
            .allow
            .iter()
            .filter(|p| p.display().to_string().ends_with("shared"))
            .count();
        assert_eq!(shared, 1, "the shared grant appears exactly once");
        assert!(resolved.network.block_net);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Order must not matter when the parents agree.
    #[test]
    fn extends_order_does_not_change_the_result() {
        let dir = temp_dir("multi-order");
        std::fs::create_dir_all(&dir).unwrap();
        write_profile(
            &dir,
            "a",
            r#"{"meta":{"name":"a","schema_version":1},"filesystem":{"allow":["C:/x"]},"network":{"allow_domain":["a.example"]}}"#,
        );
        write_profile(
            &dir,
            "b",
            r#"{"meta":{"name":"b","schema_version":1},"filesystem":{"allow":["C:/y"]},"network":{"allow_domain":["b.example"]}}"#,
        );
        let (pa, pb) = (dir.join("a.json"), dir.join("b.json"));
        write_profile(
            &dir,
            "ab",
            &format!(
                r#"{{"meta":{{"name":"ab","schema_version":1}},"extends":["{}","{}"]}}"#,
                json_escaped(&pa),
                json_escaped(&pb)
            ),
        );
        write_profile(
            &dir,
            "ba",
            &format!(
                r#"{{"meta":{{"name":"ba","schema_version":1}},"extends":["{}","{}"]}}"#,
                json_escaped(&pb),
                json_escaped(&pa)
            ),
        );

        let ab = load_and_resolve(dir.join("ab.json").to_str().unwrap(), &dir).unwrap();
        let ba = load_and_resolve(dir.join("ba.json").to_str().unwrap(), &dir).unwrap();
        // Behaviour, not bytes: the CHILD's own name differs by construction, and a
        // grant list is a set. Compare every list sorted, with `meta.name` removed.
        let normalised = |r: &ResolvedProfile| {
            let mut v: serde_json::Value = serde_json::from_str(&to_expanded_json(r, &[])).unwrap();
            v["meta"].as_object_mut().map(|m| m.remove("name"));
            for key in ["filesystem", "network"] {
                if let Some(section) = v.get_mut(key).and_then(|s| s.as_object_mut()) {
                    for (_, value) in section.iter_mut() {
                        if let Some(arr) = value.as_array_mut() {
                            arr.sort_by_key(|x| x.to_string());
                        }
                    }
                }
            }
            v
        };
        assert_eq!(
            normalised(&ab),
            normalised(&ba),
            "reordering the extends array must not change the resolved policy"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A cycle that runs through a diamond is still a cycle.
    #[test]
    fn a_cycle_through_a_diamond_is_refused() {
        let dir = temp_dir("multi-cycle");
        std::fs::create_dir_all(&dir).unwrap();
        write_profile(
            &dir,
            "a",
            &format!(
                r#"{{"meta":{{"name":"a","schema_version":1}},"extends":["{}"]}}"#,
                json_escaped(&dir.join("b.json"))
            ),
        );
        write_profile(
            &dir,
            "b",
            &format!(
                r#"{{"meta":{{"name":"b","schema_version":1}},"extends":["{}"]}}"#,
                json_escaped(&dir.join("a.json"))
            ),
        );

        let err = match load_and_resolve(dir.join("a.json").to_str().unwrap(), &dir) {
            Ok(_) => panic!("a cycle must be refused"),
            Err(e) => format!("{e:#}"),
        };
        assert!(
            err.contains("cycle"),
            "the message keeps the cycle shape: {err}"
        );
        assert!(
            err.contains("a → b → a") || err.contains("b → a → b"),
            "the refusal spells out the chain it walked: {err}"
        );
        assert_eq!(
            err.matches('→').count(),
            2,
            "the chain is spelled a → b → a, not a bare 'cycle': {err}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A bare name that names nothing must say so, and list what does exist - a raw
    /// "cannot find the file" in the OS locale is not an operator-facing error, and
    /// it is what a stale `extends` produces after a profile is retired.
    #[test]
    fn a_missing_profile_name_lists_the_ones_that_exist() {
        let _env = crate::env_lock();
        let tmp = std::env::temp_dir().join(format!("sb-missing-{}", std::process::id()));
        let profiles = tmp.join(".saife").join("profiles");
        std::fs::create_dir_all(&profiles).unwrap();
        std::fs::write(
            profiles.join("present.json"),
            r#"{"meta":{"name":"present","schema_version":1}}"#,
        )
        .unwrap();

        let saved = std::env::var_os("USERPROFILE");
        unsafe { std::env::set_var("USERPROFILE", &tmp) };
        let err = match load_and_resolve("absent", &tmp) {
            Ok(_) => panic!("a name that resolves to nothing must be refused"),
            Err(e) => format!("{e:#}"),
        };
        match saved {
            Some(v) => unsafe { std::env::set_var("USERPROFILE", v) },
            None => unsafe { std::env::remove_var("USERPROFILE") },
        }
        let _ = std::fs::remove_dir_all(&tmp);

        assert!(
            err.contains("no profile named `absent`"),
            "the message names the profile that is missing: {err}"
        );
        assert!(
            err.contains("present"),
            "and lists what exists, so the typo is visible: {err}"
        );
    }

    /// Every JSON example in the docs that declares `meta` must still LOAD. The README
    /// shipped an example missing `meta.schema_version` for weeks: the one snippet a
    /// new user copies first was refused by the binary it documented. A fenced block
    /// that is deliberately invalid belongs in a `text` fence, not a `json` one.
    #[test]
    fn every_documented_profile_example_still_loads() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let docs = [
            "README.md",
            "docs/USER-GUIDE.md",
            "docs/FAQ.md",
            "docs/DEVELOPERS.md",
            "profiles/README.md",
        ];
        let dir = temp_dir("doc-examples");
        std::fs::create_dir_all(&dir).unwrap();
        // An example that says `"extends": ["node", "jvm"]` means the profiles that
        // SHIP, and a bare name resolves in the installed store - empty on a fresh
        // machine and on CI. Provision it from the repo, which also makes this a
        // check that the docs only name profiles the repo actually ships.
        let store = dir.join("store");
        let shipped = store.join(".saife").join("profiles");
        std::fs::create_dir_all(&shipped).unwrap();
        for entry in std::fs::read_dir(root.join("profiles")).unwrap().flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("json") {
                std::fs::copy(&path, shipped.join(path.file_name().unwrap())).unwrap();
            }
        }
        // jvm.json grants `$JAVA_HOME`, so a machine without a JDK (CI) must still be
        // able to load the docs: point it at a directory instead of skipping the
        // example, which would quietly stop checking it.
        let jdk = store.join("jdk");
        std::fs::create_dir_all(&jdk).unwrap();
        let _env = crate::env_lock();
        let saved = std::env::var_os("USERPROFILE");
        let saved_jdk = std::env::var_os("JAVA_HOME");
        unsafe {
            std::env::set_var("USERPROFILE", &store);
            std::env::set_var("JAVA_HOME", &jdk);
        }
        let mut checked = 0;
        for doc in docs {
            let Ok(text) = std::fs::read_to_string(root.join(doc)) else {
                continue; // a doc that moved is a different test's problem
            };
            let mut rest = text.as_str();
            let mut n = 0;
            while let Some(start) = rest.find("```json") {
                let body_start = match rest[start..].find('\n') {
                    Some(i) => start + i + 1,
                    None => break,
                };
                let Some(end) = rest[body_start..].find("```") else {
                    break;
                };
                let body = &rest[body_start..body_start + end];
                rest = &rest[body_start + end..];
                n += 1;
                let Ok(value) = serde_json::from_str::<serde_json::Value>(body) else {
                    panic!("{doc} example #{n} is not valid JSON");
                };
                // Fragments (a `limits` block to paste into an existing profile) are
                // not complete profiles and are not expected to load on their own.
                if value.get("meta").is_none() {
                    continue;
                }
                let file = dir.join(format!("{}-{n}.json", doc.replace(['/', '.'], "_")));
                std::fs::write(&file, body).unwrap();
                let loaded = load_and_resolve(file.to_str().unwrap(), &dir);
                assert!(
                    loaded.is_ok(),
                    "{doc} example #{n} does not load: {}",
                    loaded.err().map(|e| format!("{e:#}")).unwrap_or_default()
                );
                checked += 1;
            }
        }
        // Restore before asserting: a panic would otherwise leak a fake %USERPROFILE%
        // into every later test in this process.
        let checked_ok = checked >= 3;
        let count = checked;
        match saved {
            Some(v) => unsafe { std::env::set_var("USERPROFILE", v) },
            None => unsafe { std::env::remove_var("USERPROFILE") },
        }
        match saved_jdk {
            Some(v) => unsafe { std::env::set_var("JAVA_HOME", v) },
            None => unsafe { std::env::remove_var("JAVA_HOME") },
        }
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            checked_ok,
            "expected to check the documented examples, found {count}"
        );
    }

    // ---- The classified credential-deny set ----
    //
    // The builtin deny list was one flat opinion. It is now classified: the
    // entries a workload has NO legitimate reason to read (private keys, the
    // control plane) can never be exposed, and the entries a tool needs to
    // function (gh, kubectl, docker, cargo, git, maven, gradle, nuget, pypi)
    // can be exposed per session by label, loudly and audited. The flat
    // `builtin_deny_dirs`/`builtin_deny_files` keep their exact output for
    // callers that do not name an exposure - including the order, which the
    // existing count tests below pin.

    #[test]
    fn every_credential_deny_carries_a_label_and_a_class() {
        let home = PathBuf::from(r"C:\Users\u");
        let local = PathBuf::from(r"C:\Users\u\AppData\Local");
        let appdata = PathBuf::from(r"C:\Users\u\AppData\Roaming");
        let denies = credential_denies_with(
            Some(home.as_path()),
            Some(local.as_path()),
            Some(appdata.as_path()),
        );
        assert_eq!(denies.len(), 17, "8 secret trees + 9 tool credentials");
        for d in &denies {
            assert!(
                !d.label.is_empty(),
                "an unlabeled entry cannot be named by a flag"
            );
        }
        let secrets: Vec<_> = denies
            .iter()
            .filter(|d| d.class == CredentialClass::Secret)
            .map(|d| d.label)
            .collect();
        assert_eq!(
            secrets,
            [
                "ssh",
                "aws",
                "azure",
                "gnupg",
                "saife",
                "gcloud",
                "saife-local",
                "gcloud-appdata"
            ]
        );
        let tools: Vec<_> = denies
            .iter()
            .filter(|d| d.class == CredentialClass::ToolCredential)
            .map(|d| d.label)
            .collect();
        assert_eq!(
            tools,
            [
                "gradle", "maven", "cargo", "git", "docker", "kube", "gh", "pypi", "nuget"
            ]
        );
        // `gh` is a config DIRECTORY, unlike its eight siblings: a file-kind
        // deny on it would leave `hosts.yml` readable through a grant on
        // `~/.config`, which is precisely the hole the deny exists to close.
        let gh = denies.iter().find(|d| d.label == "gh").expect("gh entry");
        assert_eq!(
            gh.kind,
            DenyKind::Dir,
            "`~/.config/gh` is a tree, not a file"
        );
        assert_eq!(
            gh.path,
            home.join(".config").join("gh"),
            "the gh subtree, never .config"
        );
    }

    #[test]
    fn exposing_a_tool_credential_removes_exactly_that_entry() {
        let home = PathBuf::from(r"C:\Users\u");
        let local = PathBuf::from(r"C:\Users\u\AppData\Local");
        let appdata = PathBuf::from(r"C:\Users\u\AppData\Roaming");
        let eff = effective_denies_with(
            &["gh".to_string()],
            Some(home.as_path()),
            Some(local.as_path()),
            Some(appdata.as_path()),
            None,
        )
        .expect("a valid label");
        let eff_files: Vec<PathBuf> = eff.files.clone();
        assert!(
            eff_files.contains(&home.join(".kube").join("config")),
            "an unexposed sibling stays denied"
        );
        assert!(
            !eff_files.iter().any(|p| p.ends_with(".config\\gh")),
            "gh is gone"
        );
        assert_eq!(eff.exposed.len(), 1);
        assert_eq!(eff.exposed[0].label, "gh");
        assert_eq!(eff.exposed[0].class, CredentialClass::ToolCredential);
    }

    #[test]
    fn exposing_a_secret_is_refused_by_name() {
        let err = effective_denies_with(
            &["ssh".to_string()],
            Some(&PathBuf::from(r"C:\Users\u")),
            None,
            None,
            None,
        )
        .expect_err("a private key is never exposable");
        let text = err.to_string();
        assert!(text.contains("ssh"), "the refusal names the label: {text}");
        assert!(text.contains("never"), "the refusal says why: {text}");
    }

    #[test]
    fn an_unknown_exposure_label_is_refused_with_the_known_ones() {
        let err = effective_denies_with(
            &["ghh".to_string()],
            Some(&PathBuf::from(r"C:\Users\u")),
            None,
            None,
            None,
        )
        .expect_err("a typo must not silently no-op");
        let text = err.to_string();
        assert!(
            text.contains("ghh") && text.contains("gh"),
            "names the typo and the real labels: {text}"
        );
    }

    #[test]
    fn the_policy_dir_adds_dirs_and_files_in_sorted_order() {
        let dir = std::env::temp_dir().join(format!("saife-policy-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("b-gcloud.json"),
            r#"{"schema_version": 1, "deny": {"dirs": ["C:/ProgramData/Corp/gcloud"], "files": ["C:/Users/u/.netrc"]}}"#,
        )
        .unwrap();
        std::fs::write(
            dir.join("a-vault.json"),
            r#"{"schema_version": 1, "deny": {"dirs": ["C:/ProgramData/Corp/vault-tokens"], "files": []}}"#,
        )
        .unwrap();
        let policy = policy_denies_in(&dir).expect("valid policy files");
        assert_eq!(
            policy.dirs,
            vec![
                PathBuf::from("C:/ProgramData/Corp/vault-tokens"),
                PathBuf::from("C:/ProgramData/Corp/gcloud")
            ],
            "sorted by FILE name, not by the paths inside them"
        );
        assert_eq!(policy.files, vec![PathBuf::from("C:/Users/u/.netrc")]);
        assert_eq!(policy.sources.len(), 2, "the audit wants the file names");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_policy_file_with_an_unknown_key_is_refused_naming_the_file() {
        let dir = std::env::temp_dir().join(format!("saife-policy-test-{}-2", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("bad.json");
        std::fs::write(
            &f,
            r#"{"schema_version": 1, "deny": {"dirs": []}, "allow": ["C:/temp"]}"#,
        )
        .unwrap();
        let err = policy_denies_in(&dir).expect_err("an unknown key is a moved key, not an alias");
        assert!(
            err.to_string().contains("bad.json"),
            "names the file: {err}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_policy_file_with_a_relative_path_is_refused_naming_the_file() {
        let dir = std::env::temp_dir().join(format!("saife-policy-test-{}-3", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("rel.json"),
            r#"{"schema_version": 1, "deny": {"dirs": ["secrets"]}}"#,
        )
        .unwrap();
        let err = policy_denies_in(&dir)
            .expect_err("a relative deny depends on a cwd the policy has none of");
        assert!(
            err.to_string().contains("rel.json"),
            "names the file: {err}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_policy_file_that_adds_nothing_is_refused() {
        let dir = std::env::temp_dir().join(format!("saife-policy-test-{}-4", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("empty.json"),
            r#"{"schema_version": 1, "deny": {"dirs": [], "files": []}}"#,
        )
        .unwrap();
        let err = policy_denies_in(&dir)
            .expect_err("an empty policy file is a deployment mistake, not a no-op");
        assert!(
            err.to_string().contains("empty.json"),
            "names the file: {err}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_policy_deny_reaches_the_effective_set_and_the_policy_root_denies_itself() {
        let dir = std::env::temp_dir().join(format!("saife-policy-test-{}-5", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("p.json"),
            r#"{"schema_version": 1, "deny": {"dirs": ["C:/ProgramData/Corp/secrets"], "files": []}}"#,
        )
        .unwrap();
        let eff = effective_denies_with(
            &[],
            Some(&PathBuf::from(r"C:\Users\u")),
            None,
            None,
            Some(&dir),
        )
        .expect("policy loads");
        assert!(
            eff.policy
                .dirs
                .contains(&PathBuf::from("C:/ProgramData/Corp/secrets"))
        );
        assert!(
            eff.dirs
                .contains(&PathBuf::from("C:/ProgramData/Corp/secrets")),
            "the policy reaches the set the backends consume, not just the report"
        );
        assert!(
            eff.dirs.contains(&dir),
            "the policy directory itself is denied - the file names alone reveal where the org keeps secrets"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_exposed_label_and_a_policy_deny_coexist() {
        let home = PathBuf::from(r"C:\Users\u");
        let local = PathBuf::from(r"C:\Users\u\AppData\Local");
        let appdata = PathBuf::from(r"C:\Users\u\AppData\Roaming");
        let dir = std::env::temp_dir().join(format!("saife-policy-test-{}-6", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("p.json"),
            r#"{"schema_version": 1, "deny": {"dirs": ["C:/ProgramData/Corp/secrets"], "files": []}}"#,
        )
        .unwrap();
        let eff = effective_denies_with(
            &["kube".to_string()],
            Some(home.as_path()),
            Some(local.as_path()),
            Some(appdata.as_path()),
            Some(&dir),
        )
        .unwrap();
        let names: Vec<PathBuf> = eff.files.clone();
        assert!(!names.contains(&home.join(".kube").join("config")));
        assert!(names.contains(&appdata.join("NuGet").join("NuGet.Config")));
        assert!(
            eff.dirs
                .contains(&PathBuf::from("C:/ProgramData/Corp/secrets"))
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
