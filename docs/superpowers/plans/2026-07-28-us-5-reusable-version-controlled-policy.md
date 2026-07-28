# US-5: Reusable, version-controlled policy — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete the US-5 profile system — strict schema validation with typo suggestions, `schema_version` enforcement, `git_runtime` + `dotnet_runtime` security groups, formatted cycle-detection errors, and the `sandbox profile list` / `sandbox profile show [--expanded]` subcommands — so that all 17 US-5 acceptance criteria pass.

**Architecture:** The profile loader (`src/profile.rs`) and security-group resolver (`src/security_groups.rs`) already exist from US-1/US-2 and cover AC-5.1–5.5, 5.8, 5.10, 5.11, 5.17. This plan layers on the missing pieces: (a) tighten the serde schema with `deny_unknown_fields` + a Levenshtein-1 typo suggester; (b) add `meta.schema_version` + version-gate; (c) two new security groups; (d) a structured cycle-error message; (e) the `profile` subcommand (currently a stub returning exit 2) with a `--expanded` view that emits fully-resolved JSON. Each task is TDD and independently committable.

**Tech Stack:** Rust (edition 2024), `serde` + `serde_json` (existing), `clap` v4 (existing). No new dependencies. Typo suggestion is a 25-line in-house Levenshtein-1 implementation — no `strsim` crate.

**Spec:** `docs/specs/us-5-reusable-version-controlled-policy/spec.md` — the "Acceptance Criteria" (AC-5.1..5.17) and "Built-in security groups" table are authoritative. The spec's "Implementation-ready detail" section is TODO; this plan fills it.

**Branch:** `feature/windows-sandbox` (current). All work continues on this branch — US-1..US-4a landed here too. A worktree is optional (see skill `using-git-worktrees`); not required because the changes are additive and non-conflicting with in-flight work.

**Out of scope for this plan:**
- Profile registry / `sandbox profile pull` (future-ideas F-9, namespace reserved, no-op).
- Profile Sigstore signing (future F-5).
- `add_deny_commands` (future F-16).
- GUI/TUI profile editor (future F-12).
- `--reuse`/`persist` store caching (FR-2.8.4, deferred from spike).
- `workdir.access` enforcement beyond parsing (current code parses `workdir` as `serde_json::Value`; this plan keeps that — workdir is already effectively `readwrite` via `--allow-cwd`).

**Key constraint — zero-warnings acceptance (AGENTS.md):** every task must end with `cargo build` and `cargo clippy` emitting zero warnings. `cargo test --lib` must pass. The PowerShell integration suite (`tests/run-tests.ps1`) must continue to pass S-1..S-56 (with the existing SKIPs for S-46/S-52/S-56).

---

## File Structure

| File | Status | Responsibility |
|---|---|---|
| `src/profile.rs` | Modify | Add `deny_unknown_fields` to all raw structs, `schema_version` to `Meta`, typed `Workdir` struct, `ExpandedProfile` view + `to_expanded_json()`, tightened cycle error, `suggest_unknown_key()`, `validate_schema_version()`. |
| `src/profile/` (new dir) | — | NOT created. Keep `src/profile.rs` as a single file — it is 471 lines today and stays under ~650 after edits. Splitting is premature. |
| `src/security_groups.rs` | Modify | Add `resolve_git()` + `resolve_dotnet()`; register in `resolve_groups` match arm. |
| `src/cli.rs` | Modify | Add `--expanded` flag to `ProfileAction::Show`; the `ProfileAction::List` variant already exists. |
| `src/main.rs` | Modify | Replace `Cmd::Profile => stub_not_implemented("profile")` with a real `profile_cmd()` dispatcher calling `profile::list_profiles()` / `profile::show_profile()`. |
| `tests/run-tests.ps1` | Modify | Add S-57..S-71 covering AC-5.6 (cycle msg), 5.7 (git/dotnet), 5.9 (windows_common), 5.12 (invalid type), 5.13 (unknown key + suggestion), 5.14 (list), 5.15 (show raw), 5.16 (schema_version), expanded view, multi-level extends, variable per-user, CLI merge. |
| `Cargo.toml` | No change | All deps already present. |

---

## Task 1: `schema_version` field + version gate (AC-5.16)

**Files:**
- Modify: `src/profile.rs`
- Modify: `tests/run-tests.ps1` (one new scenario S-57)

**Why first:** Adds the `schema_version` field to `Meta`. Later tasks (strict validation) build on this. AC-5.16 is self-contained and testable in isolation.

- [ ] **Step 1: Write the failing unit test**

Add to the `#[cfg(test)] mod tests` block in `src/profile.rs`, after the existing `parse_allow_bad_mode` test:

```rust
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
        // schema_version is required per spec AC-5.16 / FR-5.2 schema.
        let raw = r#"{"meta":{"name":"x"},"filesystem":{"allow":["$CWD"]}}"#;
        let p: RawProfile = serde_json::from_str(raw).expect("parses structurally");
        let err = validate_schema_version(&p).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("missing required field `meta.schema_version`"), "got: {msg}");
    }
```

- [ ] **Step 2: Run the tests — confirm they fail to compile**

Run: `cargo test --lib profile::tests::schema_version`
Expected: compile errors — `Meta` has no `schema_version` field; `validate_schema_version` does not exist.

- [ ] **Step 3: Add `schema_version` to `Meta` + the validator function**

In `src/profile.rs`, modify the `Meta` struct (currently at lines 53–67). Replace:

```rust
#[derive(Debug, Deserialize)]
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
}
```

with:

```rust
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
    #[serde(default)]
    pub schema_version: Option<u32>,
}
```

> **Existing-test fixup:** `src/profile.rs::merge_extends_child_overrides_meta` (lines ~423–442) constructs `Meta` as a struct literal. Adding `#[derive(Default)]` to `Meta` lets those literals use `..Default::default()` for the new field — but they currently spell out every field. Update both `Meta { ... }` literals in that test to append `..Default::default()` so they compile against the new struct. Alternatively, add `schema_version: None,` to each — `..Default::default()` is more future-proof.

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
```

- [ ] **Step 4: Wire the validator into `load_and_resolve`**

In `src/profile.rs::load_and_resolve` (around line 100), insert the version check right after the raw chain is loaded. Replace:

```rust
pub fn load_and_resolve(name: &str, cwd: &Path) -> Result<ResolvedProfile> {
    let mut seen: Vec<String> = Vec::new();
    let raw = load_raw_chain(name, cwd, &mut seen)?;
    let mut fs = resolve_filesystem(&raw.filesystem, cwd)?;
```

with:

```rust
pub fn load_and_resolve(name: &str, cwd: &Path) -> Result<ResolvedProfile> {
    let mut seen: Vec<String> = Vec::new();
    let raw = load_raw_chain(name, cwd, &mut seen)?;
    validate_schema_version(&raw)?;
    let mut fs = resolve_filesystem(&raw.filesystem, cwd)?;
```

- [ ] **Step 5: Run the unit tests — confirm they pass**

Run: `cargo test --lib profile::tests::schema_version`
Expected: 3 tests pass.

- [ ] **Step 6: Build the whole crate + confirm zero warnings**

Run: `cargo build && cargo clippy -- -D warnings`
Expected: builds clean, no warnings. (The new `validate_schema_version` is now called from `load_and_resolve`, so no dead-code warning.)

- [ ] **Step 7: Add integration scenario S-57 (AC-5.16)**

In `tests/run-tests.ps1`, find the `Invoke-Scenario-S56` function (the US-4b deferral skip, near line 981). Insert a new scenario after it. Following the existing scenario-function pattern (see `Invoke-Scenario-S16` at line 356 for the template — `New-ScenarioDir`, `Invoke-Sandbox`, return the hashtable):

```powershell
# S-57 (AC-5.16): unsupported schema_version is rejected with a clear message.
function Invoke-Scenario-S57 {
    $d = New-ScenarioDir 57
    $profileDir = Join-Path $d 'profiles'
    New-Item -ItemType Directory -Path $profileDir -Force | Out-Null
    $profilePath = Join-Path $profileDir 'bad-schema.json'
    $profileJson = '{"meta":{"name":"bad","schema_version":99},"filesystem":{"allow":["$CWD"]}}'
    Set-Content -LiteralPath $profilePath -Value $profileJson -Encoding UTF8
    $r = Invoke-Sandbox -Args @('run','--profile',$profilePath,'--','cmd','/c','echo','x') -WorkingDirectory $d
    $err = ($r.Stderr -join "`n")
    $passed = ($r.ExitCode -ne 0) -and ($err -match 'Unsupported profile schema version 99') -and ($err -match 'supports schema version 1')
    return @{ Num=57; Name='S-57 (AC-5.16)'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { 'unsupported schema_version rejected' } else { "exit=$($r.ExitCode) stderr=$err" } }
}
```

Then find the `$scenarios = @(...)` array registration (search for `Invoke-Scenario-S56` in the array — it is the last entry). Append `Invoke-Scenario-S57` to the array. Also update the suite header comment at line 11 to mention S-57.

- [ ] **Step 8: Run the integration suite (only S-57 + a regression spot-check)**

Run: `cargo build --release && pwsh -File tests/run-tests.ps1 -SandboxExe target\release\sandbox.exe -Only 16,57`
Expected: S-16 (profile load regression) and S-57 both pass.

- [ ] **Step 9: Commit**

```bash
git add src/profile.rs tests/run-tests.ps1
git commit -m "feat(us-5): schema_version field + version gate (AC-5.16)"
```

---

## Task 2: Strict schema validation + typo suggester (AC-5.12, AC-5.13)

**Files:**
- Modify: `src/profile.rs`
- Modify: `tests/run-tests.ps1` (S-58, S-59)

**Why:** AC-5.12 requires a clear field-pointer for wrong types ("expected array, got integer at line 5 col 12"); AC-5.13 requires unknown keys to be rejected with a "Did you mean X?" hint. Both need `#[serde(deny_unknown_fields)]` + a custom error post-processor. serde's default error already gives line/col for parse errors, so AC-5.12 is mostly about *preserving* serde's message rather than wrapping it.

- [ ] **Step 1: Write the failing unit tests**

Append to the `mod tests` block in `src/profile.rs`:

```rust
    #[test]
    fn unknown_top_level_key_is_rejected_with_suggestion() {
        let raw = r#"{"meta":{"name":"x","schema_version":1},"netwrok":{"block":false}}"#;
        let err = serde_json::from_str::<RawProfile>(raw).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("unknown field `netwrok`"), "got: {msg}");
        assert!(msg.contains("Did you mean `network`"), "got: {msg}");
    }

    #[test]
    fn unknown_key_no_close_match_still_rejects() {
        let raw = r#"{"meta":{"name":"x","schema_version":1},"zzzzz":1}"#;
        let err = serde_json::from_str::<RawProfile>(raw).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("unknown field `zzzzz`"), "got: {msg}");
        // No suggestion when nothing is close.
        assert!(!msg.contains("Did you mean"), "got: {msg}");
    }

    #[test]
    fn wrong_type_carries_line_col() {
        // filesystem.allow: 42 (integer instead of array) — serde reports line/col.
        let raw = "{\"meta\":{\"name\":\"x\",\"schema_version\":1},\"filesystem\":{\"allow\":42}}";
        let err = serde_json::from_str::<RawProfile>(raw).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("allow"), "got: {msg}");
        assert!(msg.contains("line") || msg.contains("col"), "got: {msg}");
    }

    #[test]
    fn suggest_closest_known_key() {
        // The suggester is a free function so we can unit-test it directly.
        assert_eq!(suggest_unknown_key("netwrok"), Some("network".to_string()));
        assert_eq!(suggest_unknown_key("filesystemm"), Some("filesystem".to_string()));
        assert_eq!(suggest_unknown_key("metaa"), Some("meta".to_string()));
        assert_eq!(suggest_unknown_key("zzzzz"), None);
        assert_eq!(suggest_unknown_key("sec"), Some("security".to_string()));
    }
```

- [ ] **Step 2: Run the tests — confirm they fail**

Run: `cargo test --lib profile::tests::unknown_top_level_key_is_rejected_with_suggestion`
Expected: the first test fails because `RawProfile` currently uses `#[serde(default)]` on every field and no `deny_unknown_fields` — unknown keys are silently dropped, so `from_str` succeeds.

- [ ] **Step 3: Add `deny_unknown_fields` to every raw struct**

In `src/profile.rs`, add `#[serde(deny_unknown_fields)]` to: `RawProfile`, `Meta`, `Security`, `RawFilesystem`, `RawNetwork`. Also add a typed `Workdir` struct (replacing `Option<serde_json::Value>`) so unknown keys inside `workdir` are caught too.

Replace the `RawProfile` block (lines 36–51) and the structs below it with:

```rust
/// Raw profile JSON (v1 schema).
#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
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

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Meta {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    #[allow(dead_code)]
    pub version: String,
    #[serde(default)]
    #[allow(dead_code)]
    pub description: String,
    #[serde(default)]
    pub schema_version: Option<u32>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Security {
    #[serde(default)]
    pub groups: Vec<String>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RawFilesystem {
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub read_only: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
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
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Workdir {
    #[serde(default)]
    #[allow(dead_code)]
    pub access: Option<String>,
}
```

- [ ] **Step 4: Implement `suggest_unknown_key` (Levenshtein-1)**

Add as a free function in `src/profile.rs` (above `load_and_resolve`):

```rust
/// The set of top-level keys a v1 profile accepts. Used by
/// [`suggest_unknown_key`] to emit "Did you mean X?" hints (AC-5.13).
pub const KNOWN_TOP_LEVEL_KEYS: &[&str] =
    &["meta", "extends", "security", "filesystem", "network", "workdir"];

/// Suggest the closest known key within edit distance 1 (case-insensitive).
/// Returns `None` if no known key is within distance 1 — so a totally
/// bogus key like `zzzzz` produces no suggestion (still rejected, just
/// without a hint).
pub fn suggest_unknown_key(unknown: &str) -> Option<String> {
    let lower = unknown.to_ascii_lowercase();
    for &known in KNOWN_TOP_LEVEL_KEYS {
        if levenshtein(&lower, known) <= 1 {
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
        if let Some(sugg) = suggest_unknown_key(&unknown) {
            return anyhow::anyhow!("{err}\n  Did you mean `{sugg}`?");
        }
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
```

- [ ] **Step 5: Wire `with_suggestion` into the parse call site**

In `src/profile.rs::load_raw_chain` (around line 153), replace:

```rust
    let raw: RawProfile = serde_json::from_str(&text)
        .with_context(|| format!("parse profile {}", path.display()))?;
```

with:

```rust
    let raw: RawProfile = serde_json::from_str(&text)
        .map_err(with_suggestion)
        .with_context(|| format!("parse profile {}", path.display()))?;
```

- [ ] **Step 6: Run the unit tests — confirm they pass**

Run: `cargo test --lib profile::tests`
Expected: all profile tests pass, including the 4 new ones.

- [ ] **Step 7: Build + clippy (zero warnings)**

Run: `cargo build && cargo clippy -- -D warnings`
Expected: clean. Note: `RawProfile` previously had `workdir: Option<serde_json::Value>` — replacing it with `Option<Workdir>` removes a `dead_code` allowance on the Value; the new `Workdir::access` keeps its own `#[allow(dead_code)]` because enforcement is out of scope.

- [ ] **Step 8: Add integration scenarios S-58 (AC-5.12) + S-59 (AC-5.13)**

In `tests/run-tests.ps1`, after `Invoke-Scenario-S57`, add:

```powershell
# S-58 (AC-5.12): wrong-type field is rejected with line/col pointer.
function Invoke-Scenario-S58 {
    $d = New-ScenarioDir 58
    $profileDir = Join-Path $d 'profiles'
    New-Item -ItemType Directory -Path $profileDir -Force | Out-Null
    $profilePath = Join-Path $profileDir 'bad-type.json'
    # filesystem.allow: 42 (integer, not array) on line 1.
    $profileJson = '{"meta":{"name":"x","schema_version":1},"filesystem":{"allow":42}}'
    Set-Content -LiteralPath $profilePath -Value $profileJson -Encoding UTF8
    $r = Invoke-Sandbox -Args @('run','--profile',$profilePath,'--','cmd','/c','echo','x') -WorkingDirectory $d
    $err = ($r.Stderr -join "`n")
    $passed = ($r.ExitCode -ne 0) -and ($err -match 'allow')
    return @{ Num=58; Name='S-58 (AC-5.12)'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { 'wrong-type rejected' } else { "exit=$($r.ExitCode) stderr=$err" } }
}

# S-59 (AC-5.13): unknown key rejected with "Did you mean" suggestion.
function Invoke-Scenario-S59 {
    $d = New-ScenarioDir 59
    $profileDir = Join-Path $d 'profiles'
    New-Item -ItemType Directory -Path $profileDir -Force | Out-Null
    $profilePath = Join-Path $profileDir 'typo.json'
    $profileJson = '{"meta":{"name":"x","schema_version":1},"netwrok":{"block":false}}'
    Set-Content -LiteralPath $profilePath -Value $profileJson -Encoding UTF8
    $r = Invoke-Sandbox -Args @('run','--profile',$profilePath,'--','cmd','/c','echo','x') -WorkingDirectory $d
    $err = ($r.Stderr -join "`n")
    $passed = ($r.ExitCode -ne 0) -and ($err -match 'netwrok') -and ($err -match 'Did you mean .network.')
    return @{ Num=59; Name='S-59 (AC-5.13)'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { 'unknown key + suggestion' } else { "exit=$($r.ExitCode) stderr=$err" } }
}
```

Register both in the `$scenarios` array.

- [ ] **Step 9: Run the new scenarios + regression**

Run: `cargo build --release && pwsh -File tests/run-tests.ps1 -SandboxExe target\release\sandbox.exe -Only 16,57,58,59`
Expected: all four pass.

- [ ] **Step 10: Commit**

```bash
git add src/profile.rs tests/run-tests.ps1
git commit -m "feat(us-5): strict schema + typo suggester (AC-5.12, AC-5.13)"
```

---

## Task 3: `git_runtime` + `dotnet_runtime` security groups (AC-5.7)

**Files:**
- Modify: `src/security_groups.rs`
- Modify: `tests/run-tests.ps1` (S-60, S-61)

**Why:** Spec's "Built-in security groups" table lists `git_runtime` and `dotnet_runtime`; current code resolves only python/node/rust/java. Adding them makes AC-5.7's "concrete paths the group expands to" testable for the full documented set.

- [ ] **Step 1: Write the failing unit tests**

Append to `mod tests` in `src/security_groups.rs` (after the existing `path_search_is_left_to_right` test):

```rust
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
        // dotnet.exe dir non-recursive; NuGet cache recursive (subtree of packages).
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
```

- [ ] **Step 2: Run the tests — confirm they fail**

Run: `cargo test --lib security_groups::tests::git_runtime`
Expected: fail — `resolve_groups` returns empty for `git_runtime` (falls into the `_ => unknown` warning arm).

- [ ] **Step 3: Implement `resolve_git` + `resolve_dotnet` and register them**

In `src/security_groups.rs`, add two new match arms in `resolve_groups` (after `"java_runtime"`):

```rust
            "git_runtime" => resolve_git(probe),
            "dotnet_runtime" => resolve_dotnet(probe),
```

Then add the two resolver functions (after `resolve_java`):

```rust
fn resolve_git(probe: &dyn EnvProbe) -> Vec<GroupGrant> {
    const LABEL: &str = "git_runtime";
    let mut out = Vec::new();
    if let Some(dir) = probe.find_in_path("git.exe") {
        out.push(GroupGrant { path: dir, recursive: false, label: LABEL });
    }
    push_env_dir(probe, "USERPROFILE", &[".gitconfig"], false, LABEL, &mut out);
    push_env_dir(probe, "LOCALAPPDATA", &["Programs", "Git"], true, LABEL, &mut out);
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
```

> **Note on `.gitconfig` as a "dir":** `push_env_dir` calls `probe.exists(&p)` — for a file this returns true if the file exists, and the grant is treated as a path (the allowlist builder grants RX on the path whether it is a file or dir; AppContainer RuleSet applies the ACE to the path). This is the same mechanism `read_only` uses for `$HOME/.gitconfig` in the profile's own `read_only` array. Non-recursive is correct for a file.

- [ ] **Step 4: Run the unit tests — confirm they pass**

Run: `cargo test --lib security_groups`
Expected: all pass (existing + 4 new).

- [ ] **Step 5: Build + clippy**

Run: `cargo build && cargo clippy -- -D warnings`
Expected: clean.

- [ ] **Step 6: Add integration scenarios S-60 (git_runtime) + S-61 (dotnet_runtime)**

These mirror S-19 (python_runtime). Both skip cleanly if the tool is not installed.

```powershell
# S-60 (AC-5.7): git_runtime group makes git usable. Skips if git absent.
function Invoke-Scenario-S60 {
    $d = New-ScenarioDir 60
    if (-not (Get-Command git.exe -ErrorAction SilentlyContinue)) {
        return @{ Num=60; Name='S-60 (AC-5.7)'; Passed=$true; Skipped=$true; Detail='git not on PATH' }
    }
    $profileDir = Join-Path $d 'profiles'
    New-Item -ItemType Directory -Path $profileDir -Force | Out-Null
    $profilePath = Join-Path $profileDir 'git-runtime.json'
    $profileJson = @{
        meta = @{ name = 'git-runtime'; schema_version = 1 }
        security = @{ groups = @('git_runtime') }
        filesystem = @{ allow = @('$CWD'); read_only = @(); deny = @() }
    } | ConvertTo-Json -Depth 5
    Set-Content -LiteralPath $profilePath -Value $profileJson -Encoding UTF8
    $r = Invoke-Sandbox -Args @('run','--profile',$profilePath,'--allow-cwd','--','git','--version') -WorkingDirectory $d
    $out = ($r.Stdout -join "`n")
    $passed = ($r.ExitCode -eq 0) -and ($out -match 'git version')
    return @{ Num=60; Name='S-60 (AC-5.7)'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { 'git ran under git_runtime group' } else { "exit=$($r.ExitCode) stdout=$out" } }
}

# S-61 (AC-5.7): dotnet_runtime group makes dotnet usable. Skips if dotnet absent.
function Invoke-Scenario-S61 {
    $d = New-ScenarioDir 61
    if (-not (Get-Command dotnet.exe -ErrorAction SilentlyContinue)) {
        return @{ Num=61; Name='S-61 (AC-5.7)'; Passed=$true; Skipped=$true; Detail='dotnet not on PATH' }
    }
    $profileDir = Join-Path $d 'profiles'
    New-Item -ItemType Directory -Path $profileDir -Force | Out-Null
    $profilePath = Join-Path $profileDir 'dotnet-runtime.json'
    $profileJson = @{
        meta = @{ name = 'dotnet-runtime'; schema_version = 1 }
        security = @{ groups = @('dotnet_runtime') }
        filesystem = @{ allow = @('$CWD'); read_only = @(); deny = @() }
    } | ConvertTo-Json -Depth 5
    Set-Content -LiteralPath $profilePath -Value $profileJson -Encoding UTF8
    $r = Invoke-Sandbox -Args @('run','--profile',$profilePath,'--allow-cwd','--','dotnet','--version') -WorkingDirectory $d
    $out = ($r.Stdout -join "`n")
    $passed = ($r.ExitCode -eq 0) -and ($out -match 'Version:')
    return @{ Num=61; Name='S-61 (AC-5.7)'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { 'dotnet ran under dotnet_runtime group' } else { "exit=$($r.ExitCode) stdout=$out" } }
}
```

Register both in the `$scenarios` array.

- [ ] **Step 7: Run the new scenarios + regression**

Run: `cargo build --release && pwsh -File tests/run-tests.ps1 -SandboxExe target\release\sandbox.exe -Only 16,19,60,61`
Expected: S-16, S-19 pass; S-60/S-61 pass OR skip cleanly depending on host install.

- [ ] **Step 8: Commit**

```bash
git add src/security_groups.rs tests/run-tests.ps1
git commit -m "feat(us-5): git_runtime + dotnet_runtime security groups (AC-5.7)"
```

---

## Task 4: Cycle-detection message format (AC-5.6)

**Files:**
- Modify: `src/profile.rs`
- Modify: `tests/run-tests.ps1` (S-62)

**Why:** AC-5.6 specifies the exact message: `*"Profile cycle detected: a → b → a"*. Current code emits `profile \`extends\` cycle detected: a -> b` — wrong wording, wrong arrow, no closing back-to-start segment.

- [ ] **Step 1: Write the failing unit test**

Append to `mod tests` in `src/profile.rs`:

```rust
    #[test]
    fn cycle_message_matches_spec_format() {
        // Build a fake `seen` chain a -> b -> a and trigger the cycle check.
        let mut seen: Vec<String> = vec!["a".into(), "b".into()];
        // The check fires when we try to load "a" again (it's already in seen).
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
```

- [ ] **Step 2: Run — confirm failure**

Run: `cargo test --lib profile::tests::cycle_message_matches_spec_format`
Expected: compile error — `check_cycle` doesn't exist.

- [ ] **Step 3: Extract `check_cycle` + format per spec**

In `src/profile.rs`, refactor the inline cycle check in `load_raw_chain` into a testable function. Replace the current top of `load_raw_chain` (lines 144–148):

```rust
fn load_raw_chain(name: &str, cwd: &Path, seen: &mut Vec<String>) -> Result<RawProfile> {
    if seen.iter().any(|s| s == name) {
        bail!("profile `extends` cycle detected: {}", seen.join(" -> "));
    }
    seen.push(name.to_string());
```

with:

```rust
fn load_raw_chain(name: &str, cwd: &Path, seen: &mut Vec<String>) -> Result<RawProfile> {
    check_cycle(name, seen)?;
    seen.push(name.to_string());
```

And add the `check_cycle` function above `load_raw_chain`:

```rust
/// Detect a profile `extends` cycle and format the error per AC-5.6:
/// `Profile cycle detected: a → b → a` (the repeated name closes the loop).
fn check_cycle(name: &str, seen: &[String]) -> Result<()> {
    if seen.iter().any(|s| s == name) {
        let mut chain: Vec<&str> = seen.iter().map(|s| s.as_str()).collect();
        chain.push(name); // close the loop
        bail!("Profile cycle detected: {}", chain.join(" → "));
    }
    Ok(())
}
```

> The `→` is U+2192 RIGHTWARDS ARROW. Source files are UTF-8 (Rust requires it); Windows consoles since Win10 1903 render it correctly in PowerShell 7+ (the test harness). If you prefer ASCII safety, the spec uses `→` literally — keep it.

- [ ] **Step 4: Run the unit tests — confirm pass**

Run: `cargo test --lib profile::tests::cycle`
Expected: 3 tests pass.

- [ ] **Step 5: Build + clippy**

Run: `cargo build && cargo clippy -- -D warnings`
Expected: clean.

- [ ] **Step 6: Add integration scenario S-62 (AC-5.6)**

```powershell
# S-62 (AC-5.6): extends cycle is detected and reported with the spec format.
function Invoke-Scenario-S62 {
    $d = New-ScenarioDir 62
    $profileDir = Join-Path $d 'profiles'
    New-Item -ItemType Directory -Path $profileDir -Force | Out-Null
    $aPath = Join-Path $profileDir 'a.json'
    $bPath = Join-Path $profileDir 'b.json'
    Set-Content -LiteralPath $aPath -Value '{"meta":{"name":"a","schema_version":1},"extends":"b","filesystem":{"allow":["$CWD"]}}' -Encoding UTF8
    Set-Content -LiteralPath $bPath -Value '{"meta":{"name":"b","schema_version":1},"extends":"a","filesystem":{"allow":["$CWD"]}}' -Encoding UTF8
    $r = Invoke-Sandbox -Args @('run','--profile',$aPath,'--','cmd','/c','echo','x') -WorkingDirectory $d
    $err = ($r.Stderr -join "`n")
    $passed = ($r.ExitCode -ne 0) -and ($err -match 'Profile cycle detected') -and ($err -match 'a.*b.*a')
    return @{ Num=62; Name='S-62 (AC-5.6)'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { 'cycle detected + formatted' } else { "exit=$($r.ExitCode) stderr=$err" } }
}
```

Register in `$scenarios`.

- [ ] **Step 7: Run + commit**

Run: `cargo build --release && pwsh -File tests/run-tests.ps1 -SandboxExe target\release\sandbox.exe -Only 16,62`
Expected: both pass.

```bash
git add src/profile.rs tests/run-tests.ps1
git commit -m "feat(us-5): cycle-detection error format per AC-5.6"
```

---

## Task 5: `profile list` subcommand (AC-5.14)

**Files:**
- Modify: `src/profile.rs` (add `list_profiles`)
- Modify: `src/main.rs` (wire dispatcher)
- Modify: `tests/run-tests.ps1` (S-63)

- [ ] **Step 1: Write the failing unit test**

Append to `mod tests` in `src/profile.rs`:

```rust
    #[test]
    fn list_profiles_returns_user_global_json_files() {
        // Use a temp USERPROFILE so we don't pollute the real one.
        let tmp = std::env::temp_dir().join(format!("sb-list-test-{}", std::process::id()));
        let profiles_dir = tmp.join(".sandbox").join("profiles");
        std::fs::create_dir_all(&profiles_dir).unwrap();
        std::fs::write(profiles_dir.join("alpha.json"), r#"{"meta":{"name":"alpha","schema_version":1}}"#).unwrap();
        std::fs::write(profiles_dir.join("beta.json"), r#"{"meta":{"name":"beta","schema_version":1}}"#).unwrap();
        std::fs::write(profiles_dir.join("not-json.txt"), "garbage").unwrap();
        // Save + restore USERPROFILE.
        let prev = std::env::var_os("USERPROFILE");
        std::env::set_var("USERPROFILE", &tmp);
        let result = list_profiles();
        if let Some(p) = prev { std::env::set_var("USERPROFILE", p); }
        std::fs::remove_dir_all(&tmp).ok();

        let names: Vec<String> = result.into_iter().map(|p| p.name).collect();
        assert!(names.contains(&"alpha".to_string()));
        assert!(names.contains(&"beta".to_string()));
        assert!(!names.iter().any(|n| n == "not-json"), "non-.json files excluded");
    }
```

- [ ] **Step 2: Run — confirm failure**

Run: `cargo test --lib profile::tests::list_profiles`
Expected: compile error — `list_profiles` doesn't exist.

- [ ] **Step 3: Implement `list_profiles` + a `ProfileEntry` struct**

Add to `src/profile.rs` (near `cli::profiles_dir` usage or as a free function):

```rust
/// One entry in the `profile list` output.
#[derive(Debug, Clone)]
pub struct ProfileEntry {
    pub name: String,
    pub source_path: std::path::PathBuf,
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

fn name_from_profile_file(path: &std::path::Path) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    let raw: RawProfile = serde_json::from_str(&text).ok()?;
    raw.meta.and_then(|m| if m.name.is_empty() { None } else { Some(m.name) })
}
```

- [ ] **Step 4: Wire the dispatcher in `main.rs`**

Replace the `Cmd::Profile { .. } => stub_not_implemented("profile")` line (line 44) with a call to a new `profile_cmd` function. Add the function below `audit_cmd`:

```rust
fn profile_cmd(action: cli::ProfileAction) -> i32 {
    use cli::ProfileAction;
    match action {
        ProfileAction::List => {
            let entries = profile::list_profiles();
            if entries.is_empty() {
                let dir = cli::profiles_dir();
                println!("(no profiles in {})", dir.display());
                return 0;
            }
            for e in &entries {
                println!("{}\t{}", e.name, e.source_path.display());
            }
            0
        }
        ProfileAction::Show { name, expanded } => {
            profile::show_profile(&name, expanded)
        }
    }
}
```

And update the `Cmd::Profile` arm to call it:

```rust
        Cmd::Profile { action } => profile_cmd(action),
```

> Note: this references `ProfileAction::Show { name, expanded }` and `profile::show_profile` — both are added in Task 6. To keep this task independently committable, either (a) add the `--expanded` CLI flag and the `show_profile` stub now (returning exit 2), or (b) defer the `ProfileAction::Show` arm to Task 6 and only handle `List` here. **Prefer (a):** add the `--expanded` flag to `cli.rs` and a stub `show_profile` returning `eprintln!("not implemented"); 2` now, so the dispatcher compiles; Task 6 fills in the body.

- [ ] **Step 5: Add the `--expanded` flag to `cli.rs` + stub `show_profile`**

In `src/cli.rs`, modify the `ProfileAction::Show` variant:

```rust
    /// Show a profile's resolved contents.
    Show {
        name: String,
        /// Show the fully-resolved profile (extends flattened, security
        /// groups expanded to concrete paths, variables expanded).
        #[arg(long)]
        expanded: bool,
    },
```

In `src/profile.rs`, add a stub (to be filled in Task 6):

```rust
/// `sandbox profile show <name> [--expanded]`. Filled in by Task 6.
pub fn show_profile(_name: &str, _expanded: bool) -> i32 {
    eprintln!("[sandbox] profile show: not implemented in this slice");
    2
}
```

- [ ] **Step 6: Run the unit test + build**

Run: `cargo test --lib profile::tests::list_profiles && cargo build && cargo clippy -- -D warnings`
Expected: test passes; build clean. (`show_profile` is `#[allow(dead_code)]`-free because it's called from `main.rs::profile_cmd`.)

- [ ] **Step 7: Add integration scenario S-63 (AC-5.14)**

```powershell
# S-63 (AC-5.14): profile list shows all user-global profiles.
function Invoke-Scenario-S63 {
    $d = New-ScenarioDir 63
    # Point USERPROFILE at a temp dir with known profiles.
    $fakeHome = Join-Path $d 'fake-home'
    $profilesDir = Join-Path $fakeHome '.sandbox\profiles'
    New-Item -ItemType Directory -Path $profilesDir -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $profilesDir 'alpha.json') -Value '{"meta":{"name":"alpha","schema_version":1}}' -Encoding UTF8
    Set-Content -LiteralPath (Join-Path $profilesDir 'beta.json') -Value '{"meta":{"name":"beta","schema_version":1}}' -Encoding UTF8
    # Invoke-Sandbox doesn't expose env-var overrides, so invoke directly.
    # `$SandboxExe` is the script-scope param (see harness top-level param block).
    $pi = New-Object System.Diagnostics.ProcessStartInfo
    $pi.FileName = $SandboxExe
    $pi.Arguments = 'profile list'
    $pi.UseShellExecute = $false
    $pi.RedirectStandardOutput = $true
    $pi.RedirectStandardError = $true
    $pi.EnvironmentVariables['USERPROFILE'] = $fakeHome
    $proc = [System.Diagnostics.Process]::Start($pi)
    $stdout = $proc.StandardOutput.ReadToEnd()
    $stderr = $proc.StandardError.ReadToEnd()
    $proc.WaitForExit()
    $passed = ($proc.ExitCode -eq 0) -and ($stdout -match 'alpha') -and ($stdout -match 'beta')
    return @{ Num=63; Name='S-63 (AC-5.14)'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { 'list shows both profiles' } else { "exit=$($proc.ExitCode) stdout=$stdout stderr=$stderr" } }
}
```

> **Note on `$SandboxExe`:** it is the script-scope `param` declared at the top of `tests/run-tests.ps1` (line 34). It is accessible from scenario functions without explicit passing — `Invoke-Sandbox` itself relies on this (it reads `$SandboxExe` directly at line 99 without a `param` block). There is **no** `Resolve-SandboxExe` helper; use `$SandboxExe` directly whenever you need to spawn the binary outside `Invoke-Sandbox` (e.g. when overriding env vars like `USERPROFILE`).

- [ ] **Step 8: Run + commit**

Run: `cargo build --release && pwsh -File tests/run-tests.ps1 -SandboxExe target\release\sandbox.exe -Only 63`
Expected: S-63 passes.

```bash
git add src/profile.rs src/cli.rs src/main.rs tests/run-tests.ps1
git commit -m "feat(us-5): profile list subcommand (AC-5.14)"
```

---

## Task 6: `profile show` + `--expanded` view (AC-5.15, expanded view)

**Files:**
- Modify: `src/profile.rs` (implement `show_profile` + `ExpandedProfile`)
- Modify: `tests/run-tests.ps1` (S-64, S-65)

**Why:** AC-5.15 requires the raw view (file as-authored, `extends`/`security.groups` unresolved). The user chose the expanded view to emit **full resolved JSON**: `extends` flattened, `security.groups` expanded to concrete per-group path lists, variables expanded to absolute paths.

- [ ] **Step 1: Write the failing unit tests**

Append to `mod tests` in `src/profile.rs`:

```rust
    #[test]
    fn expanded_profile_flattens_extends_and_expands_groups() {
        // Build a resolved profile by hand to test to_expanded_json in isolation.
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
```

- [ ] **Step 2: Run — confirm failure**

Run: `cargo test --lib profile::tests::expanded_profile_flattens_extends_and_expands_groups`
Expected: compile error — `to_expanded_json` doesn't exist.

- [ ] **Step 3: Implement `to_expanded_json` + `show_profile`**

Add to `src/profile.rs`:

```rust
use serde_json::{json, Value};

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
        // Resolve extends + variables + groups, then emit the expanded JSON.
        // We need the raw profile's security.groups list (the resolved profile
        // folds them into read_only). Load the raw chain once, validate, then
        // resolve — reusing `load_raw_chain` + `validate_schema_version` rather
        // than `load_and_resolve` so we keep the raw `security.groups` around.
        let mut seen: Vec<String> = Vec::new();
        let raw = load_raw_chain(name, &cwd, &mut seen)?;
        validate_schema_version(&raw)?;
        let groups = raw.security.as_ref().map(|s| s.groups.clone()).unwrap_or_default();
        // Re-run the resolve path on the already-loaded raw chain to avoid a
        // second disk read. `resolve_filesystem` + `resolve_network_slice` are
        // the pure halves of `load_and_resolve`; we call them directly.
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
        // Raw view: the file as-authored.
        let path = resolve_profile_path(name, &cwd)?;
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("read profile {}", path.display()))?;
        println!("{text}");
    }
    Ok(0)
}
```

- [ ] **Step 4: Run the unit test + build + clippy**

Run: `cargo test --lib profile::tests::expanded_profile && cargo build && cargo clippy -- -D warnings`
Expected: test passes; build clean. **Also:** now that `to_expanded_json` reads `ResolvedProfile::name`, the `#[allow(dead_code)]` on that field (profile.rs:29) is no longer needed — remove it as part of this task so clippy stays clean.

- [ ] **Step 5: Add integration scenarios S-64 (raw) + S-65 (expanded)**

```powershell
# S-64 (AC-5.15): profile show (raw) prints the file as-authored.
function Invoke-Scenario-S64 {
    $d = New-ScenarioDir 64
    $fakeHome = Join-Path $d 'fake-home'
    $profilesDir = Join-Path $fakeHome '.sandbox\profiles'
    New-Item -ItemType Directory -Path $profilesDir -Force | Out-Null
    $rawJson = '{"meta":{"name":"raw","schema_version":1},"security":{"groups":["python_runtime"]},"filesystem":{"allow":["$CWD"]}}'
    Set-Content -LiteralPath (Join-Path $profilesDir 'raw.json') -Value $rawJson -Encoding UTF8
    $pi = New-Object System.Diagnostics.ProcessStartInfo
    $pi.FileName = $SandboxExe
    $pi.Arguments = 'profile show raw'
    $pi.UseShellExecute = $false
    $pi.RedirectStandardOutput = $true
    $pi.RedirectStandardError = $true
    $pi.EnvironmentVariables['USERPROFILE'] = $fakeHome
    $proc = [System.Diagnostics.Process]::Start($pi)
    $stdout = $proc.StandardOutput.ReadToEnd()
    $proc.WaitForExit()
    # Raw view must contain the unresolved extends/groups markers.
    $passed = ($proc.ExitCode -eq 0) -and ($stdout -match 'python_runtime') -and ($stdout -match '\$CWD') -and ($stdout -notmatch 'security_groups_expanded')
    return @{ Num=64; Name='S-64 (AC-5.15)'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { 'raw view printed as-authored' } else { "exit=$($proc.ExitCode) stdout=$stdout" } }
}

# S-65 (expanded): profile show --expanded emits resolved JSON.
function Invoke-Scenario-S65 {
    $d = New-ScenarioDir 65
    $fakeHome = Join-Path $d 'fake-home'
    $profilesDir = Join-Path $fakeHome '.sandbox\profiles'
    New-Item -ItemType Directory -Path $profilesDir -Force | Out-Null
    $rawJson = '{"meta":{"name":"expanded","schema_version":1},"security":{"groups":["python_runtime"]},"filesystem":{"allow":["$CWD"]}}'
    Set-Content -LiteralPath (Join-Path $profilesDir 'expanded.json') -Value $rawJson -Encoding UTF8
    $pi = New-Object System.Diagnostics.ProcessStartInfo
    $pi.FileName = $SandboxExe
    $pi.Arguments = 'profile show expanded --expanded'
    $pi.UseShellExecute = $false
    $pi.RedirectStandardOutput = $true
    $pi.RedirectStandardError = $true
    $pi.EnvironmentVariables['USERPROFILE'] = $fakeHome
    $pi.WorkingDirectory = $d
    $proc = [System.Diagnostics.Process]::Start($pi)
    $stdout = $proc.StandardOutput.ReadToEnd()
    $proc.WaitForExit()
    $passed = ($proc.ExitCode -eq 0) -and ($stdout -match 'security_groups_expanded') -and ($stdout -notmatch '\$CWD') -and ($stdout -match '"name": "expanded"')
    return @{ Num=65; Name='S-65 (expanded)'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { 'expanded view emitted resolved JSON' } else { "exit=$($proc.ExitCode) stdout=$stdout" } }
}
```

Register both in `$scenarios`.

- [ ] **Step 6: Run + commit**

Run: `cargo build --release && pwsh -File tests/run-tests.ps1 -SandboxExe target\release\sandbox.exe -Only 63,64,65`
Expected: all three pass.

```bash
git add src/profile.rs tests/run-tests.ps1
git commit -m "feat(us-5): profile show + --expanded view (AC-5.15)"
```

---

## Task 7: Coverage scenarios for AC-5.3, 5.5, 5.8, 5.9, 5.10, 5.17

**Files:**
- Modify: `tests/run-tests.ps1` (S-66..S-71)

**Why:** Several ACs are covered by existing unit tests (extends merge, variable expansion) but lack an integration scenario that exercises the real `sandbox.exe` binary end-to-end. This task adds the integration coverage for completeness and to catch regressions in the wiring layer (CLI → profile loader → allowlist). AC-5.9 (`windows_common` always present) currently has no test at all — even a unit test — so it gets one too.

- [ ] **Step 1: Add a unit test for AC-5.9 (windows_common always present)**

In `src/sandbox/allowlist.rs`, find the `build_allowlist` function (around line 33). Add a `#[cfg(test)] mod tests` block at the bottom of the file if one doesn't exist, with:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::FilesystemSlice;

    #[test]
    fn windows_common_system32_always_in_allowlist() {
        // Even an empty profile (no allow, no read_only) gets SystemRoot\System32.
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
}
```

Run: `cargo test --lib sandbox::allowlist::tests`
Expected: passes (the existing code already does this — the test pins it as AC-5.9).

- [ ] **Step 2: Add integration scenarios S-66..S-71**

```powershell
# S-66 (AC-5.3): extends concatenates allow arrays (de-duped).
function Invoke-Scenario-S66 {
    $d = New-ScenarioDir 66
    $profileDir = Join-Path $d 'profiles'
    New-Item -ItemType Directory -Path $profileDir -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $profileDir 'base.json') -Value '{"meta":{"name":"base","schema_version":1},"filesystem":{"allow":["$CWD"]}}' -Encoding UTF8
    Set-Content -LiteralPath (Join-Path $profileDir 'child.json') -Value '{"meta":{"name":"child","schema_version":1},"extends":"base","filesystem":{"allow":["$CWD"]}}' -Encoding UTF8
    $r = Invoke-Sandbox -Args @('run','--profile',(Join-Path $profileDir 'child.json'),'--','cmd','/c','echo','extends-ok') -WorkingDirectory $d
    $out = ($r.Stdout -join "`n")
    $passed = ($r.ExitCode -eq 0) -and ($out -match 'extends-ok')
    return @{ Num=66; Name='S-66 (AC-5.3)'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { 'extends merged' } else { "exit=$($r.ExitCode) stdout=$out" } }
}

# S-67 (AC-5.5): multi-level extends (a -> b -> c).
function Invoke-Scenario-S67 {
    $d = New-ScenarioDir 67
    $profileDir = Join-Path $d 'profiles'
    New-Item -ItemType Directory -Path $profileDir -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $profileDir 'c.json') -Value '{"meta":{"name":"c","schema_version":1},"filesystem":{"allow":["$CWD"]}}' -Encoding UTF8
    Set-Content -LiteralPath (Join-Path $profileDir 'b.json') -Value '{"meta":{"name":"b","schema_version":1},"extends":"c","filesystem":{"allow":["$CWD"]}}' -Encoding UTF8
    Set-Content -LiteralPath (Join-Path $profileDir 'a.json') -Value '{"meta":{"name":"a","schema_version":1},"extends":"b","filesystem":{"allow":["$CWD"]}}' -Encoding UTF8
    $r = Invoke-Sandbox -Args @('run','--profile',(Join-Path $profileDir 'a.json'),'--','cmd','/c','echo','multi-ok') -WorkingDirectory $d
    $out = ($r.Stdout -join "`n")
    $passed = ($r.ExitCode -eq 0) -and ($out -match 'multi-ok')
    return @{ Num=67; Name='S-67 (AC-5.5)'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { '3-deep extends resolved' } else { "exit=$($r.ExitCode) stdout=$out" } }
}

# S-68 (AC-5.8): $HOME expands per-user.
function Invoke-Scenario-S68 {
    $d = New-ScenarioDir 68
    $profileDir = Join-Path $d 'profiles'
    New-Item -ItemType Directory -Path $profileDir -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $profileDir 'home.json') -Value '{"meta":{"name":"home","schema_version":1},"filesystem":{"allow":["$HOME/.sandbox-test-marker"]}}' -Encoding UTF8
    # Create the marker dir so the sandboxed cmd can echo a file inside it.
    $markerDir = Join-Path $env:USERPROFILE '.sandbox-test-marker'
    New-Item -ItemType Directory -Path $markerDir -Force | Out-Null
    $markerFile = Join-Path $markerDir 'hi.txt'
    Set-Content -LiteralPath $markerFile -Value 'home-expanded' -Encoding ASCII
    $r = Invoke-Sandbox -Args @('run','--profile',(Join-Path $profileDir 'home.json'),'--','cmd','/c','type',$markerFile) -WorkingDirectory $d
    $out = ($r.Stdout -join "`n")
    Remove-Item -LiteralPath $markerDir -Recurse -Force -ErrorAction SilentlyContinue
    $passed = ($r.ExitCode -eq 0) -and ($out -match 'home-expanded')
    return @{ Num=68; Name='S-68 (AC-5.8)'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { '$HOME expanded' } else { "exit=$($r.ExitCode) stdout=$out" } }
}

# S-69 (AC-5.9): windows_common (System32) is reachable even with an empty profile.
function Invoke-Scenario-S69 {
    $d = New-ScenarioDir 69
    $profileDir = Join-Path $d 'profiles'
    New-Item -ItemType Directory -Path $profileDir -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $profileDir 'empty.json') -Value '{"meta":{"name":"empty","schema_version":1}}' -Encoding UTF8
    # cmd.exe lives in System32; it must be runnable even with no allow entries.
    $r = Invoke-Sandbox -Args @('run','--profile',(Join-Path $profileDir 'empty.json'),'--','cmd','/c','echo','sys32-ok') -WorkingDirectory $d
    $out = ($r.Stdout -join "`n")
    $passed = ($r.ExitCode -eq 0) -and ($out -match 'sys32-ok')
    return @{ Num=69; Name='S-69 (AC-5.9)'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { 'System32 reachable from empty profile' } else { "exit=$($r.ExitCode) stdout=$out" } }
}

# S-70 (AC-5.10): CLI --allow merges on top of profile.
function Invoke-Scenario-S70 {
    $d = New-ScenarioDir 70
    $profileDir = Join-Path $d 'profiles'
    New-Item -ItemType Directory -Path $profileDir -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $profileDir 'p.json') -Value '{"meta":{"name":"p","schema_version":1},"filesystem":{"allow":["$CWD"]}}' -Encoding UTF8
    $extraDir = Join-Path (Split-Path -Parent $d) 'cli-merge-70'
    New-Item -ItemType Directory -Path $extraDir -Force | Out-Null
    $extraFile = Join-Path $extraDir 'merged.txt'
    Set-Content -LiteralPath $extraFile -Value 'cli-merge-ok' -Encoding ASCII
    $r = Invoke-Sandbox -Args @('run','--profile',(Join-Path $profileDir 'p.json'),'--allow-cwd','--allow',$extraDir,'--','cmd','/c','type',$extraFile) -WorkingDirectory $d
    $out = ($r.Stdout -join "`n")
    $passed = ($r.ExitCode -eq 0) -and ($out -match 'cli-merge-ok')
    return @{ Num=70; Name='S-70 (AC-5.10)'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { 'CLI --allow merged' } else { "exit=$($r.ExitCode) stdout=$out" } }
}

# S-71 (AC-5.17): a profile using only $HOME/$CWD/groups is portable (no edits).
# Reuses S-16's pattern but asserts the profile has NO absolute paths.
function Invoke-Scenario-S71 {
    $d = New-ScenarioDir 71
    $profileDir = Join-Path $d 'profiles'
    New-Item -ItemType Directory -Path $profileDir -Force | Out-Null
    $portableJson = '{"meta":{"name":"portable","schema_version":1},"security":{"groups":["python_runtime"]},"filesystem":{"allow":["$HOME/.claude","$CWD"],"read_only":["$HOME/.gitconfig"],"deny":["$HOME/.ssh"]}}'
    Set-Content -LiteralPath (Join-Path $profileDir 'portable.json') -Value $portableJson -Encoding UTF8
    # Assert the profile contains no drive-letter absolute path.
    $hasAbs = $portableJson -match '[A-Z]:\\\\'
    $r = Invoke-Sandbox -Args @('run','--profile',(Join-Path $profileDir 'portable.json'),'--allow-cwd','--','cmd','/c','echo','portable-ok') -WorkingDirectory $d
    $out = ($r.Stdout -join "`n")
    $passed = (-not $hasAbs) -and ($r.ExitCode -eq 0) -and ($out -match 'portable-ok')
    return @{ Num=71; Name='S-71 (AC-5.17)'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { 'portable profile ran' } else { "hasAbs=$hasAbs exit=$($r.ExitCode) stdout=$out" } }
}
```

Register S-66..S-71 in `$scenarios`. Update the suite header comment.

- [ ] **Step 3: Run the full integration suite**

Run: `cargo build --release && pwsh -File tests/run-tests.ps1 -SandboxExe target\release\sandbox.exe -Skip 8,9,12,14,15,46,52,56`
Expected: all non-skipped scenarios pass (S-1..S-71 minus the skipped set). The skips are pre-existing (python-dependent, deferred).

- [ ] **Step 4: Final clippy + unit-test sweep**

Run: `cargo clippy -- -D warnings && cargo test --lib`
Expected: zero warnings, all unit tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/sandbox/allowlist.rs tests/run-tests.ps1
git commit -m "test(us-5): AC-5.3/5.5/5.8/5.9/5.10/5.17 integration + windows_common unit"
```

---

## Task 8: Spec doc update + final verification

**Files:**
- Modify: `docs/specs/us-5-reusable-version-controlled-policy/spec.md` (fill the TODO section)
- Modify: `docs/specs/README.md` if it tracks per-US status (check first)

- [ ] **Step 1: Fill the spec's "Implementation-ready detail" section**

Replace the two TODO blocks at the bottom of `docs/specs/us-5-reusable-version-controlled-policy/spec.md` (lines 342–352 — note it's duplicated; collapse to one) with a pointer to this plan + a summary of what shipped:

```markdown
## Implementation-ready detail

Implemented in `docs/superpowers/plans/2026-07-28-us-5-reusable-version-controlled-policy.md`. Summary of what landed:

- **JSON schema (serde):** `RawProfile`, `Meta`, `Security`, `RawFilesystem`, `RawNetwork`, `Workdir` — all `#[serde(deny_unknown_fields)]`. `meta.schema_version: Option<u32>` is required (validated by `validate_schema_version`; only `1` supported).
- **Typo suggester:** `suggest_unknown_key` (Levenshtein-1, case-insensitive, over `KNOWN_TOP_LEVEL_KEYS`). Wired via `with_suggestion` at the parse call site. AC-5.13.
- **Extends-merge:** `merge_profiles` — child overrides scalars, `filesystem.*` / `network.allow_domain` / `security.groups` arrays concatenate via `dedupe_concat` (case-insensitive de-dup).
- **Variable expansion:** `expand_vars` — `$HOME`, `$CWD`, `$USERPROFILE`, `$TEMP`. Forward slashes normalized to backslashes.
- **Security groups:** `resolve_groups` in `src/security_groups.rs` — `python_runtime`, `node_runtime`, `rust_runtime`, `java_runtime`, `git_runtime`, `dotnet_runtime`. `windows_common` is implicit (added by `sandbox::allowlist::build_allowlist`, not expandable here).
- **Cycle detection:** `check_cycle` formats `Profile cycle detected: a → b → a` (U+2192 arrow) per AC-5.6.
- **Search-path resolution:** `resolve_profile_path` — absolute path or `*.json`-suffixed name used as-is; bare name → `%USERPROFILE%\.sandbox\profiles\<name>.json`.
- **`profile list`:** `list_profiles` reads `*.json` from the user-global dir, extracts `meta.name` (falls back to filename stem), sorts alphabetically.
- **`profile show`:** raw view prints the file verbatim (AC-5.15); `--expanded` emits `to_expanded_json` — a single JSON object with `extends` flattened, `security.groups` expanded to per-group concrete path lists, variables expanded.
- **Error message format:** `anyhow` chains with `with_context`; parse errors carry serde's line/col; cycle + schema-version errors use the exact spec wording.
```

- [ ] **Step 2: Verify the suite one final time**

Run: `cargo build --release && cargo clippy -- -D warnings && cargo test --lib && pwsh -File tests/run-tests.ps1 -SandboxExe target\release\sandbox.exe -Skip 8,9,12,14,15,46,52,56`
Expected: zero warnings; all unit tests pass; all non-skipped integration scenarios pass.

- [ ] **Step 3: Commit**

```bash
git add docs/specs/us-5-reusable-version-controlled-policy/spec.md
git commit -m "docs(us-5): fill implementation-ready detail; mark spec implemented"
```

---

## Verification Matrix (AC → Task → Scenario)

| AC | Task | Unit test | Integration scenario |
|---|---|---|---|
| 5.1 (user-global load) | (pre-existing) | — | S-16 (pre-existing) |
| 5.2 (explicit path) | (pre-existing) | — | S-16 (uses explicit path) |
| 5.3 (extends concat) | 7 | `merge_extends_arrays_concat` (pre-existing) | S-66 |
| 5.4 (extends override scalar) | (pre-existing) | `merge_extends_child_overrides_meta` | (covered by S-66) |
| 5.5 (multi-level extends) | 7 | — | S-67 |
| 5.6 (cycle detection) | 4 | `cycle_message_*` (3 tests) | S-62 |
| 5.7 (security groups expand) | 3 | `git_runtime_*`, `dotnet_runtime_*` (4 tests) + pre-existing | S-19 (py), S-60 (git), S-61 (dotnet) |
| 5.8 (variables per-user) | 7 | `expand_basic`, `expand_multiple` (pre-existing) | S-68 |
| 5.9 (windows_common always) | 7 | `windows_common_system32_always_in_allowlist` | S-69 |
| 5.10 (CLI flags merge) | (pre-existing) | — | S-70 |
| 5.11 (--block-net overrides) | (pre-existing) | — | (covered by US-3 S-39..S-42) |
| 5.12 (invalid type clear msg) | 2 | `wrong_type_carries_line_col` | S-58 |
| 5.13 (unknown key + suggest) | 2 | `unknown_top_level_key_*`, `suggest_closest_known_key` (4 tests) | S-59 |
| 5.14 (profile list) | 5 | `list_profiles_returns_user_global_json_files` | S-63 |
| 5.15 (show raw) | 6 | — | S-64 |
| 5.16 (schema_version check) | 1 | `schema_version_*` (3 tests) | S-57 |
| 5.17 (portable profile) | 7 | — | S-71 |
| expanded view | 6 | `expanded_profile_flattens_extends_and_expands_groups` | S-65 |

**Total new scenarios:** S-57..S-71 (15 scenarios). **Total new unit tests:** ~18.
