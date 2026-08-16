//! Persisted learned-policy store (ADR-0001 §D-3).
//!
//! Permanent allow/deny decisions from the interactive prompt are written
//! here immediately and atomically. Loaded at startup into the filter
//! pipeline (D-3.6). Our own camelCase format ([G-20, G-39]).
//!
//! The store's public API (`LearnedStore`, `learned_file_path`, etc.) is
//! not yet called from the release binary — it is wired in by D-3.6
//! (pipeline) and D-3.7 (`sandbox learned` CLI). Until then the whole
//! module is `#[allow(dead_code)]` to keep `cargo build --release` clean.
//! Tests exercise the full API, so the code is verified even though the
//! non-test binary does not yet link it in.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// On-disk schema version for the learned file.
const LEARNED_SCHEMA_VERSION: u32 = 1;

/// One entry in the learned file. `scope` is `"host"` (exact match) or
/// `"suffix"` (matches host + subdomains).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LearnedEntry {
    pub host: String,
    pub scope: String,
}

/// The on-disk file format ([G-20, G-39]). `disposition` is implied by
/// membership in `allow` vs `deny` arrays (we use the word "disposition"
/// to match US-4 audit field naming, not omac's "decision").
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct LearnedFile {
    schema: u32,
    allow: Vec<LearnedEntry>,
    deny: Vec<LearnedEntry>,
}

impl LearnedFile {
    fn empty() -> Self {
        LearnedFile {
            schema: LEARNED_SCHEMA_VERSION,
            allow: vec![],
            deny: vec![],
        }
    }
}

/// A resolved decision from `lookup`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LearnedDecision {
    pub allow: bool,
    pub scope: String,
}

/// In-memory learned store. Loaded once at startup; `record` writes
/// through to disk atomically.
///
/// Not `Sync` by design — single-threaded use, or wrap in
/// `Arc<Mutex<LearnedStore>>` for cross-thread access (see D-3.6).
#[derive(Debug, Clone)]
pub struct LearnedStore {
    file_path: PathBuf,
    allow: BTreeMap<String, String>, // host → scope
    deny: BTreeMap<String, String>,  // host → scope
}

impl LearnedStore {
    /// Load the learned file for `profile_name` from the user profile.
    /// Unnamed profile → `default.json`. Missing file → empty store (not
    /// an error). Corrupt file → error (so the user notices and can
    /// fix/revoke).
    pub fn load(profile_name: Option<&str>) -> Result<Self> {
        let base = std::env::var_os("USERPROFILE")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."));
        Self::load_in(&base, profile_name)
    }

    /// Load the learned file for `profile_name` rooted at `base` (the
    /// `%USERPROFILE%\.sandbox\learned\` parent). Test-friendly + used by
    /// `load`. Same semantics as `load` otherwise: missing file → empty
    /// store, corrupt file → error, schema mismatch → error.
    ///
    /// Validates `profile_name` via [`validate_profile_name`] before
    /// constructing the path, so a malicious/typo'd name cannot escape the
    /// `.sandbox/learned/` directory (path-traversal defense).
    pub fn load_in(base: &Path, profile_name: Option<&str>) -> Result<Self> {
        if let Some(name) = profile_name {
            validate_profile_name(name)?;
        }
        let path = learned_file_path_in(base, profile_name);
        if !path.exists() {
            return Ok(Self {
                file_path: path,
                allow: BTreeMap::new(),
                deny: BTreeMap::new(),
            });
        }
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("read learned file {}", path.display()))?;
        let parsed: LearnedFile = serde_json::from_str(&text)
            .with_context(|| format!("parse learned file {}", path.display()))?;
        if parsed.schema != LEARNED_SCHEMA_VERSION {
            anyhow::bail!(
                "unsupported learned schema version {} in {} (expected {})",
                parsed.schema,
                path.display(),
                LEARNED_SCHEMA_VERSION
            );
        }
        let mut allow = BTreeMap::new();
        let mut deny = BTreeMap::new();
        for e in parsed.allow {
            allow.insert(e.host.to_ascii_lowercase(), e.scope);
        }
        for e in parsed.deny {
            deny.insert(e.host.to_ascii_lowercase(), e.scope);
        }
        Ok(Self { file_path: path, allow, deny })
    }

    /// Look up a host. Suffix entries match the host itself and any
    /// subdomain. Returns `Some` on the first match (deny checked first
    /// per [G-33] pipeline ordering: learned-deny is step 2, before
    /// deny_domain; learned-allow is step 4).
    pub fn lookup(&self, host: &str) -> Option<LearnedDecision> {
        let h = host.trim_end_matches('.').to_ascii_lowercase();
        // Deny first (matches the pipeline: learned-deny precedes allow).
        if let Some(scope) = self.match_entry(&h, &self.deny) {
            return Some(LearnedDecision { allow: false, scope });
        }
        if let Some(scope) = self.match_entry(&h, &self.allow) {
            return Some(LearnedDecision { allow: true, scope });
        }
        None
    }

    /// Match `h` against the entry map using host-exact or suffix semantics.
    fn match_entry(&self, h: &str, map: &BTreeMap<String, String>) -> Option<String> {
        // Exact host match first.
        if let Some(scope) = map.get(h) {
            return Some(scope.clone());
        }
        // Suffix match: an entry whose scope is "suffix" matches `h` if `h`
        // is the apex or any subdomain of the entry's host. The entry host
        // may carry a leading `*.` (the wildcard form used at the prompt,
        // matching the `matcher::matches` convention); strip it to recover
        // the bare suffix, then require `h == suffix` (apex) or `h` ends with
        // `.suffix` (subdomain). The leading-dot boundary prevents suffix
        // crossing dots (`npmjs.org.evil.io` does not match `npmjs.org`).
        for (entry_host, scope) in map {
            if scope == "suffix" {
                let suffix = entry_host.strip_prefix("*.").unwrap_or(entry_host);
                if h == suffix || h.ends_with(&format!(".{suffix}")) {
                    return Some(scope.clone());
                }
            }
        }
        None
    }

    /// Record a permanent decision. `scope` is `"host"` or `"suffix"`.
    /// Persists immediately + atomically ([G-56]).
    pub fn record(&mut self, host: &str, scope: &str, allow: bool) -> Result<()> {
        let h = host.trim_end_matches('.').to_ascii_lowercase();
        if allow {
            self.allow.insert(h.clone(), scope.to_string());
            self.deny.remove(&h);
        } else {
            self.deny.insert(h.clone(), scope.to_string());
            self.allow.remove(&h);
        }
        self.persist()
    }

    /// Remove an entry (for `sandbox learned revoke`). Atomically rewrites.
    /// Returns `true` if an entry was present and removed.
    pub fn revoke(&mut self, host: &str) -> Result<bool> {
        let h = host.trim_end_matches('.').to_ascii_lowercase();
        let was_in_allow = self.allow.remove(&h).is_some();
        let was_in_deny = self.deny.remove(&h).is_some();
        if was_in_allow || was_in_deny {
            self.persist()?;
        }
        Ok(was_in_allow || was_in_deny)
    }

    /// Remove all entries (for `sandbox learned clear`).
    pub fn clear(&mut self) -> Result<()> {
        self.allow.clear();
        self.deny.clear();
        self.persist()
    }

    /// Iterate all entries for `sandbox learned list`. Returns
    /// `(host, scope, allow)` triples sorted by host.
    pub fn entries(&self) -> Vec<(String, String, bool)> {
        let mut out = Vec::new();
        for (host, scope) in &self.allow {
            out.push((host.clone(), scope.clone(), true));
        }
        for (host, scope) in &self.deny {
            out.push((host.clone(), scope.clone(), false));
        }
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }

    /// Write the file atomically: write-temp + `MoveFileEx(MOVEFILE_REPLACE_EXISTING)`
    /// with 3x retry + 50ms backoff, fallback to direct write ([G-56]).
    fn persist(&self) -> Result<()> {
        let file = LearnedFile {
            schema: LEARNED_SCHEMA_VERSION,
            allow: self
                .allow
                .iter()
                .map(|(h, s)| LearnedEntry {
                    host: h.clone(),
                    scope: s.clone(),
                })
                .collect(),
            deny: self
                .deny
                .iter()
                .map(|(h, s)| LearnedEntry {
                    host: h.clone(),
                    scope: s.clone(),
                })
                .collect(),
        };
        let json = serde_json::to_string_pretty(&file).context("serialize learned file")?;
        ensure_parent(&self.file_path)?;
        atomic_write(&self.file_path, json.as_bytes())
    }
}

/// Validate a learned-file profile name. Rejects anything that could
/// escape the `.sandbox/learned/` directory or corrupt the path:
/// - path separators (`/` or `\`)
/// - `..` as a path component (parent-directory traversal)
/// - NUL bytes (Win32 path terminator)
/// - control characters (`\0`–`\x1F`)
/// - empty after trimming whitespace
///
/// Allowed: letters, digits, hyphens, underscores, dots (within a
/// component, e.g. `my.profile`). The `default` name (used when
/// `profile_name` is `None`) also passes. Call this before
/// `learned_file_path`/`learned_file_path_in` when the name comes from
/// untrusted input (D-3.7 CLI). `load_in` calls it internally.
pub fn validate_profile_name(name: &str) -> Result<()> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        anyhow::bail!("learned profile name is empty");
    }
    if trimmed.contains('\0') {
        anyhow::bail!("learned profile name contains NUL byte");
    }
    if trimmed.contains('/') || trimmed.contains('\\') {
        anyhow::bail!("learned profile name contains a path separator: {trimmed:?}");
    }
    // Reject `..` as a standalone component (e.g. "..", "foo/..", "..bar").
    // Splitting on `.` lets us catch `..` even when the user writes it
    // without separators (the earlier separator check already blocks the
    // path-traversal form; this blocks the literal `..` token as well).
    for component in trimmed.split('.') {
        if component.is_empty() || component == ".." {
            anyhow::bail!("learned profile name has empty or `..` component: {trimmed:?}");
        }
    }
    if trimmed.chars().any(|c| c.is_control()) {
        anyhow::bail!("learned profile name contains a control character: {trimmed:?}");
    }
    Ok(())
}

/// Compute the learned file path: `%USERPROFILE%\.sandbox\learned\<name>.json`.
/// Unnamed → `default.json` ([G-5]).
///
/// Does **not** validate `profile_name` — callers passing untrusted input
/// (e.g. D-3.7 CLI) must call [`validate_profile_name`] first. `load_in`
/// validates internally.
pub fn learned_file_path(profile_name: Option<&str>) -> PathBuf {
    let base = std::env::var_os("USERPROFILE")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    learned_file_path_in(&base, profile_name)
}

/// Compute the learned file path rooted at `base`:
/// `<base>\.sandbox\learned\<name>.json`. Unnamed → `default.json` ([G-5]).
/// Pure (no env read) so tests can drive it deterministically.
///
/// Does **not** validate `profile_name` — callers passing untrusted input
/// must call [`validate_profile_name`] first. `load_in` validates
/// internally.
pub fn learned_file_path_in(base: &Path, profile_name: Option<&str>) -> PathBuf {
    let name = profile_name
        .filter(|s| !s.is_empty())
        .unwrap_or("default");
    base.join(".sandbox").join("learned").join(format!("{name}.json"))
}

fn ensure_parent(path: &Path) -> Result<()> {
    // `create_dir_all` returns Ok for an existing path, so the `.ok()`
    // only swallows genuine permission failures — in which case the
    // subsequent `atomic_write` fails with a clearer message anyway.
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    Ok(())
}

/// Atomic write via temp file + MoveFileEx. Falls back to direct write
/// if the rename fails after retries (e.g. on FAT32 where rename-over-
/// existing is not atomic). [G-56]
fn atomic_write(path: &Path, data: &[u8]) -> Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::{MoveFileExW, MOVEFILE_REPLACE_EXISTING};

    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, data)
        .with_context(|| format!("write temp file {}", tmp.display()))?;

    let path_w: Vec<u16> = path.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
    let tmp_w: Vec<u16> = tmp.as_os_str().encode_wide().chain(std::iter::once(0)).collect();

    let backoff = Duration::from_millis(50);
    for attempt in 0..3u32 {
        let result = unsafe {
            MoveFileExW(
                PCWSTR(tmp_w.as_ptr()),
                PCWSTR(path_w.as_ptr()),
                MOVEFILE_REPLACE_EXISTING,
            )
        };
        if result.is_ok() {
            return Ok(());
        }
        if attempt < 2 {
            std::thread::sleep(backoff);
        }
    }

    // Fallback: direct write (non-atomic, but the data lands). If this
    // also fails, clean up the temp file before propagating the error so
    // we don't leave a stale `.json.tmp` on disk.
    let fallback = std::fs::write(path, data)
        .with_context(|| format!("fallback direct write {}", path.display()));
    let _ = std::fs::remove_file(&tmp);
    fallback?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each test gets its own unique temp dir (pid + test name) so tests
    /// can run in parallel without racing on a shared directory or a
    /// shared env var. No `USERPROFILE` mutation → race-free.
    fn temp_dir(test_name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("sb-learned-{}-{test_name}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn load_missing_file_is_empty() {
        let tmp = temp_dir("load-missing");
        let store = LearnedStore::load_in(&tmp, Some("nonexistent-profile")).unwrap();
        assert!(store.lookup("any.host.com").is_none());
        assert!(store.entries().is_empty());
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn record_and_reload() {
        let tmp = temp_dir("record-reload");

        let mut store = LearnedStore::load_in(&tmp, Some("test-record")).unwrap();
        store.record("api.example.com", "host", true).unwrap();
        store.record("*.npmjs.org", "suffix", true).unwrap();
        store.record("evil.com", "host", false).unwrap();

        let decision = store.lookup("api.example.com").unwrap();
        assert!(decision.allow);
        assert_eq!(decision.scope, "host");

        // Reload from disk.
        let reloaded = LearnedStore::load_in(&tmp, Some("test-record")).unwrap();
        assert_eq!(reloaded.entries().len(), 3);

        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn suffix_match() {
        let tmp = temp_dir("suffix");

        let mut store = LearnedStore::load_in(&tmp, Some("test-suffix")).unwrap();
        store.record("*.npmjs.org", "suffix", true).unwrap();
        // [G-55] suffix matches apex + subdomain.
        assert!(store.lookup("npmjs.org").is_some_and(|d| d.allow));
        assert!(store.lookup("registry.npmjs.org").is_some_and(|d| d.allow));
        assert!(store.lookup("sub.registry.npmjs.org").is_some_and(|d| d.allow));
        // Does not cross dots.
        assert!(store.lookup("npmjs.org.evil.io").is_none());

        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn deny_precedence_in_lookup() {
        // [G-33] deny checked before allow in lookup.
        let tmp = temp_dir("deny-prec");

        let mut store = LearnedStore::load_in(&tmp, Some("test-deny-prec")).unwrap();
        store.record("dual.com", "host", true).unwrap();
        store.record("dual.com", "host", false).unwrap(); // overwrite → deny
        let d = store.lookup("dual.com").unwrap();
        assert!(!d.allow);

        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn revoke_removes_entry() {
        let tmp = temp_dir("revoke");

        let mut store = LearnedStore::load_in(&tmp, Some("test-revoke")).unwrap();
        store.record("api.example.com", "host", true).unwrap();
        assert!(store.lookup("api.example.com").is_some());
        let removed = store.revoke("api.example.com").unwrap();
        assert!(removed);
        assert!(store.lookup("api.example.com").is_none());
        // Reload to confirm persistence.
        let reloaded = LearnedStore::load_in(&tmp, Some("test-revoke")).unwrap();
        assert!(reloaded.lookup("api.example.com").is_none());

        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn clear_empties_store() {
        let tmp = temp_dir("clear");

        let mut store = LearnedStore::load_in(&tmp, Some("test-clear")).unwrap();
        store.record("a.com", "host", true).unwrap();
        store.record("b.com", "host", false).unwrap();
        store.clear().unwrap();
        assert!(store.entries().is_empty());
        let reloaded = LearnedStore::load_in(&tmp, Some("test-clear")).unwrap();
        assert!(reloaded.entries().is_empty());

        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn entries_sorted_for_display() {
        let tmp = temp_dir("sort");

        let mut store = LearnedStore::load_in(&tmp, Some("test-sort")).unwrap();
        store.record("zebra.com", "host", true).unwrap();
        store.record("alpha.com", "host", false).unwrap();
        let entries = store.entries();
        assert_eq!(entries[0].0, "alpha.com");
        assert_eq!(entries[1].0, "zebra.com");

        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn unnamed_profile_uses_default_json() {
        let tmp = temp_dir("unnamed");
        let path = learned_file_path_in(&tmp, None);
        assert!(path.to_string_lossy().ends_with("learned\\default.json"));
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn named_profile_uses_name_json() {
        let tmp = temp_dir("named");
        let path = learned_file_path_in(&tmp, Some("developer"));
        assert!(path.to_string_lossy().ends_with("learned\\developer.json"));
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn corrupt_file_errors() {
        let tmp = temp_dir("corrupt");
        let path = learned_file_path_in(&tmp, Some("corrupt"));
        std::fs::create_dir_all(path.parent().unwrap()).ok();
        std::fs::write(&path, "not json").ok();
        let result = LearnedStore::load_in(&tmp, Some("corrupt"));
        assert!(result.is_err());

        std::fs::remove_dir_all(&tmp).ok();
    }

    /// The `bail!` branch for `parsed.schema != LEARNED_SCHEMA_VERSION`
    /// must error (not panic, not succeed). Writes a structurally-valid
    /// file with a future schema number and expects load to reject it.
    #[test]
    fn schema_mismatch_errors() {
        let tmp = temp_dir("schema-mismatch");
        let path = learned_file_path_in(&tmp, Some("schema-mismatch"));
        std::fs::create_dir_all(path.parent().unwrap()).ok();
        // Valid shape, wrong schema version.
        let raw = "{\
            \"schema\": 999,\
            \"allow\": [{\"host\": \"a.com\", \"scope\": \"host\"}],\
            \"deny\": []\
        }";
        std::fs::write(&path, raw).ok();
        let result = LearnedStore::load_in(&tmp, Some("schema-mismatch"));
        assert!(result.is_err(), "schema mismatch must error");
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("schema version"),
            "error should mention schema version: {msg}"
        );

        std::fs::remove_dir_all(&tmp).ok();
    }

    /// Path-traversal defense: `validate_profile_name` rejects names that
    /// could escape `.sandbox/learned/` or corrupt the path.
    #[test]
    fn validate_profile_name_accepts_valid_names() {
        assert!(validate_profile_name("developer").is_ok());
        assert!(validate_profile_name("valid-name_1").is_ok());
        assert!(validate_profile_name("my.profile").is_ok());
        assert!(validate_profile_name("default").is_ok());
        assert!(validate_profile_name("a").is_ok());
    }

    #[test]
    fn validate_profile_name_rejects_path_traversal() {
        assert!(validate_profile_name("../escape").is_err(), "parent traversal");
        assert!(validate_profile_name("a/b").is_err(), "forward slash");
        assert!(validate_profile_name("a\\b").is_err(), "backslash");
        assert!(validate_profile_name("..").is_err(), "bare ..");
    }

    #[test]
    fn validate_profile_name_rejects_empty_and_control_chars() {
        assert!(validate_profile_name("").is_err(), "empty");
        assert!(validate_profile_name("   ").is_err(), "whitespace only");
        assert!(validate_profile_name("name\0").is_err(), "NUL byte");
        assert!(validate_profile_name("na\x01me").is_err(), "control char");
    }

    /// `load_in` must reject a path-traversing profile name (defense at
    /// the load boundary, not just at the pure validator).
    #[test]
    fn load_in_rejects_path_traversal_profile_name() {
        let tmp = temp_dir("load-traversal");
        let result = LearnedStore::load_in(&tmp, Some("../escape"));
        assert!(result.is_err(), "load_in must reject ../escape");
        let result2 = LearnedStore::load_in(&tmp, Some("a/b"));
        assert!(result2.is_err(), "load_in must reject a/b");
        std::fs::remove_dir_all(&tmp).ok();
    }

    /// The production entry point `learned_file_path` reads `USERPROFILE`.
    /// This test never mutates the env, so it is race-safe; it only asserts
    /// the suffix so the real USERPROFILE value does not matter.
    #[test]
    fn production_learned_file_path_suffix() {
        let path = learned_file_path(None);
        assert!(path.to_string_lossy().ends_with("learned\\default.json"));
        let path2 = learned_file_path(Some("developer"));
        assert!(path2.to_string_lossy().ends_with("learned\\developer.json"));
    }

    /// The on-disk format is camelCase + schema-versioned ([G-20, G-39]).
    #[test]
    fn roundtrip_file_format_is_camel_case() {
        let tmp = temp_dir("roundtrip");
        let mut store = LearnedStore::load_in(&tmp, Some("roundtrip")).unwrap();
        store.record("api.example.com", "host", true).unwrap();
        store.record("evil.com", "suffix", false).unwrap();
        // Read the raw file and check the camelCase shape.
        let path = learned_file_path_in(&tmp, Some("roundtrip"));
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(raw.contains("\"schema\""), "schema field present: {raw}");
        assert!(raw.contains("\"allow\""), "allow field present: {raw}");
        assert!(raw.contains("\"deny\""), "deny field present: {raw}");
        assert!(raw.contains("\"host\""), "host field present: {raw}");
        assert!(raw.contains("\"scope\""), "scope field present: {raw}");

        std::fs::remove_dir_all(&tmp).ok();
    }
}
