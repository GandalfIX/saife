# US-5: Reusable, version-controlled policy

> **Status:** Draft — narrative + acceptance criteria stage.
> Next: compare with nono, then expand to implementation-ready.
>
> **DECISION (2026-07-23, CR-10):** The repo-local profile search path
> (`./.sandbox/profiles/`) is **dropped**. Profiles live only in
> `%USERPROFILE%\.saife\profiles\`, outside the writable workspace, so a
> sandboxed agent cannot rewrite the policy applied to the next session
> (config-based sandbox escape). The user story's "commit profiles to the
> repo" goal is served by committing them to the repo and copying / symlinking
> into the user-global dir, or by referencing via `--profile <absolute-path>`
> (which works for repo paths but the file must be readable, not writable, by
> the sandboxed process). See `docs/design/critical-review.md` CR-10.

## User Story

As a developer, I want to commit `profiles/myproject.json` to my repo so that
anyone who runs an agent against the project gets the same access scope,
reviewed in PRs alongside the code — and I want built-in security groups for
common toolchains so profiles stay concise.

## Narrative

Profiles are JSON files in **one** location:

- **User-global**: `%USERPROFILE%\.saife\profiles\<name>.json` — the only
  directory `--profile <name>` searches. This directory is **outside the
  sandbox's writable boundary** (it is not in any sanctioned install dir
  and not under `$CWD`), so a sandboxed agent cannot modify the profiles
  that govern future sessions.

`--profile <name>` resolves to `<name>.json` in the user-global dir.
`--profile ./path/to/file.json` or an absolute path loads that exact file
(useful for profiles committed to a repo — load them via
`--profile C:\projekte\myapp\sandbox-profile.json`); the file must be
readable by the sandboxed process, but since the sandboxed process only
*reads* (not writes) profile files at startup, repo paths work as long as
they are on the allow-list's `read_only` entries.

Profiles compose in three ways:

- **`extends`**: a profile can extend a base profile, inheriting all its
  fields. `filesystem.allow` and `network.allow_domain` arrays concatenate
  (de-duplicated); all other keys are overridden by the child.
- **Security groups**: `security.groups: ["node_runtime", "python_runtime"]`
  references built-in, `saife`-maintained path sets for common toolchains.
  Expanded at load time to concrete allow-list entries; the expanded form is
  visible via `saife profile show <name> --expanded`.
- **CLI flags**: `--allow`, `--read-only`, `--allow-domain`, `--block-net`,
  `--network-profile` all merge **on top of** the loaded profile. CLI
  entries append to the profile's arrays; CLI `--block-net` overrides the
  profile's `network.block: false`.

Variables `$HOME`, `$CWD`, `$USERPROFILE`, `$TEMP` are expanded at load time
so a profile committed to a repo is portable across users and machines
without per-user edits.

### Built-in security groups

| Group | Contents |
|---|---|
| `node_runtime` | `node.exe` directory, npm/pnpm/yarn bin dirs, `%APPDATA%\npm`, `%LOCALAPPDATA%\pnpm`, `%LOCALAPPDATA%\node_modules` cache, `%APPDATA%\Roaming\npm-cache` |
| `python_runtime` | `python.exe` location, `%LOCALAPPDATA%\Programs\Python\*`, `%APPDATA%\Python\*`, pip cache `%LOCALAPPDATA%\pip\Cache` |
| `rust_runtime` | `%USERPROFILE%\.cargo` (bin + registry), `%USERPROFILE%\.rustup` |
| `java_runtime` | `JAVA_HOME`, `%USERPROFILE%\.gradle`, JDK install dir under `%ProgramFiles%\Java\*` or `%LOCALAPPDATA%\Programs\*jdk*` |
| `dotnet_runtime` | `dotnet.exe` location, NuGet cache `%USERPROFILE%\.nuget\packages` |
| `git_runtime` | `git.exe` location, `%USERPROFILE%\.gitconfig` (read), `%LOCALAPPDATA%\Programs\Git\*` |
| `windows_common` | `%TEMP%`, `%SystemRoot%\System32` (read), `%SystemRoot%` (read) — minimum paths any process needs to start |

`windows_common` is **always** added to every profile implicitly; it cannot
be removed. The other groups are opt-in via `security.groups`.

### Profile schema (v1)

```json
{
  "meta": {
    "name": "claude-code",
    "version": "1.0.0",
    "description": "Anthropic Claude Code CLI agent",
    "schema_version": 1
  },
  "extends": "base-coding-agent",
  "security": {
    "groups": ["node_runtime", "python_runtime", "git_runtime"]
  },
  "filesystem": {
    "allow": ["$HOME/.claude", "$CWD"],
    "read_only": ["$HOME/.gitconfig", "$HOME/.npmrc"],
    "deny": ["$HOME/.ssh", "$HOME/.aws", "$HOME/.config/gcloud"]
  },
  "network": {
    "profile": "minimal",
    "allow_domain": ["api.anthropic.com"],
    "block": false
  },
  "workdir": {
    "access": "readwrite"
  }
}
```

## Scope (MVP)

In scope:

- JSON profile loading from the user-global location
  (`%USERPROFILE%\.saife\profiles\`) and explicit `--profile <path>` for
  repo-committed profiles. No repo-local search path (CR-10 decision).
- `extends` chain (multi-level, cycle detection).
- `security.groups` expansion to concrete paths.
- Variable expansion: `$HOME`, `$CWD`, `$USERPROFILE`, `$TEMP`.
- CLI flag merging on top of profile.
- `saife profile list`, `saife profile show <name>`,
  `saife profile show <name> --expanded`.
- Schema validation with clear error messages (missing required fields,
  unknown keys, wrong types).
- Profile schema version 1 only.

Out of scope:

- Profile registry / `saife profile pull` — future-ideas F-9 (namespace
  reserved in CLI, no-op in MVP).
- Profile signing / Sigstore verification — future-ideas F-5.
- Profile inheritance with deny-list subtraction (child can only add to
  allow-lists; it cannot remove parent denies — matches nono's
  irrevocability-by-composition model).
- GUI profile editor — future-ideas F-12.

## Acceptance Criteria

### AC-5.1 — Profile loads from user-global dir
**Given** `%USERPROFILE%\.saife\profiles\myapp.json` exists,
**When** the user runs `saife run --profile myapp --allow-cwd -- cmd` from
any directory,
**Then** the user-global profile is loaded (verified by `saife profile show
myapp` printing the user-global path).

### AC-5.2 — Explicit repo path loads that file
**Given** a profile committed at `C:\projekte\myapp\sandbox-profile.json`,
**When** the user runs
`saife run --profile C:\projekte\myapp\sandbox-profile.json --allow-cwd -- cmd`,
**Then** that exact file is loaded. (The path must be on the allow-list's
`read_only` entries so the sandboxed process can read it, or loaded before
the sandbox is applied — see implementation note.)

### AC-5.3 — `extends` inherits and merges
**Given** `base.json` has `filesystem.allow: ["$HOME/.cache"]` and
`child.json` has `"extends": "base"` and
`filesystem.allow: ["$CWD"]`,
**When** the user runs `saife profile show child --expanded`,
**Then** the effective allow-list is `["$HOME/.cache", "$CWD"]` (concatenated,
de-duplicated).

### AC-5.4 — `extends` overrides scalar keys
**Given** `base.json` has `network.block: true` and `child.json` has
`"extends": "base"` and `network.block: false`,
**When** the user runs `saife profile show child --expanded`,
**Then** the effective `network.block` is `false` (child overrides).

### AC-5.5 — Multi-level extends
**Given** `a.json` extends `b.json` extends `c.json`,
**When** the user runs `saife profile show a --expanded`,
**Then** the effective profile is the merge of c ← b ← a (deepest base
applied first).

### AC-5.6 — Cycle detection
**Given** `a.json` extends `b.json` extends `a.json`,
**When** the user runs `saife run --profile a -- cmd`,
**Then** `saife` exits non-zero with: *"Profile cycle detected: a → b → a"*.

### AC-5.7 — Security groups expand to concrete paths
**Given** a profile with `security.groups: ["python_runtime"]`,
**When** the user runs `saife profile show <name> --expanded`,
**Then** the output includes the concrete paths (e.g.
`C:\Users\marku\AppData\Local\Programs\Python\Python312`, pip cache dir,
etc.) that the group expands to on this machine.

### AC-5.8 — Variables expand per-user
**Given** the same profile is used by two users,
**When** each runs `saife profile show <name> --expanded`,
**Then** `$HOME` expands to each user's own home directory — the profile
needs no per-user edits.

### AC-5.9 — `windows_common` is always present
**Given** any profile, even an empty `{}`,
**When** the user runs `saife profile show <name> --expanded`,
**Then** the effective allow-list always includes `%TEMP%` and
`%SystemRoot%\System32` (read). There is no way to remove these.

### AC-5.10 — CLI flags merge on top of profile
**Given** a profile with `filesystem.allow: ["$CWD"]` and the CLI flag
`--allow $HOME/.config/foo`,
**When** the sandbox runs,
**Then** the effective allow-list is `["$CWD", "$HOME/.config/foo"]` and the
sandboxed process can access both.

### AC-5.11 — CLI `--block-net` overrides profile
**Given** a profile with `network.block: false` and `network.allow_domain:
["api.anthropic.com"]`,
**When** the user runs `saife run --profile <name> --block-net -- cmd`,
**Then** all network is blocked, regardless of the profile's allow_domain.

### AC-5.12 — Invalid profile is rejected with a clear message
**Given** a profile with `"filesystem": {"allow": 42}` (wrong type),
**When** the user runs `saife run --profile <name> -- cmd`,
**Then** `saife` exits non-zero with a message like:
*"Invalid profile <name>: filesystem.allow: expected array, got integer at
line 5 col 12"* — pointing at the offending field.

### AC-5.13 — Unknown keys are rejected
**Given** a profile with a top-level key `"netwrok"` (typo),
**When** the user runs `saife run --profile <name> -- cmd`,
**Then** `saife` exits non-zero with: *"Unknown profile key 'network'. Did
you mean 'network'?"* — schema-strict, no silent ignore.

### AC-5.14 — `saife profile list` shows all user-global profiles
**Given** three user-global profiles exist in
`%USERPROFILE%\.saife\profiles\`,
**When** the user runs `saife profile list`,
**Then** all three are listed with their source path. (No repo-local
profiles exist — CR-10 decision.)

### AC-5.15 — `profile show` without `--expanded` shows the raw file
**Given** a profile that extends another and uses security groups,
**When** the user runs `saife profile show <name>` (no `--expanded`),
**Then** the output is the raw JSON of the file as written, with `extends`
and `security.groups` unresolved — useful for reviewing the policy as
authored.

### AC-5.16 — Schema version check
**Given** a profile with `"meta": {"schema_version": 99}`,
**When** the user runs `saife run --profile <name> -- cmd`,
**Then** `saife` exits non-zero with: *"Unsupported profile schema version
99. This build of sandbox supports schema version 1."*

### AC-5.17 — Profile is git-friendly
**Given** a committed profile uses only `$HOME`, `$CWD`, and security groups
(no absolute paths),
**When** the user clones the repo on a different machine and runs
`saife run --profile <name> --allow-cwd -- cmd`,
**Then** it works with no edits — variables expand to the new machine's
paths and the new user's home directory.

## nono comparison

### What we match

- **JSON profile format**: same shape — `meta` (name, version, description),
  `security.groups`, `filesystem.allow` / `read_file` / `deny`,
  `network.allow_domain` / `block`, `workdir.access`. We rename `read_file`
  to `read_only` for clarity (nono's `read_file` is a list of read-only
  paths — the name is misleading; we document the rename).
- **`extends` inheritance**: same semantics — child inherits parent, arrays
  concatenate (de-dup), scalars override. Multi-level with cycle detection.
- **Security groups** (`node_runtime`, `python_runtime`, `rust_runtime`):
  direct equivalents. We add `java_runtime`, `dotnet_runtime`, `git_runtime`,
  `windows_common` for Windows-specific toolchains.
- **Variable expansion** (`$HOME`, `$CWD`): same syntax, same portability
  goal. We add `$USERPROFILE` (alias for `$HOME` on Windows) and `$TEMP`.
- **Profile is version-controlled alongside code**: same explicit goal —
  "sandbox policy gets the same review process as everything else: diffs in
  pull requests, history in git." This is a core shared principle.
- **Profile composition with CLI flags**: nono's `--allow` /
  `--allow-domain` append to the profile; same merge semantics on our side.

### What we differ on (Windows-specific)

| Aspect | nono (Linux) | sandbox (Windows) |
|---|---|---|
| Profile search path | `$HOME/.config/nono/profiles/` (user-global) + registry | `%USERPROFILE%\.saife\profiles\` (user-global only). **No repo-local search path** (CR-10 decision: profiles must live outside the writable workspace to prevent config-based sandbox escape). Repo-committed profiles are loaded via `--profile <absolute-path>`. |
| Path separators in profiles | `/` only | Both `/` and `\` accepted, normalized internally to `\` for Win32 and NT paths. |
| Path case sensitivity | Case-sensitive (Linux) | **Case-insensitive** — `C:\Users\Foo` and `c:\users\foo` are the same path. RuleSet comparison must case-fold. Documented because it affects de-duplication (two profile entries differing only in case must collapse). |
| `read_file` vs. `read_only` | nono uses `read_file` for the read-only path list | We rename to `read_only` (clearer — it's not just files, it accepts dirs too). Documented rename. |
| Security group contents | Linux paths: `/usr/bin`, `~/.npm`, `~/.cache/pip`, `~/.cargo/bin` | Windows paths: `%ProgramFiles%\nodejs`, `%APPDATA%\npm`, `%LOCALAPPDATA%\Programs\Python\Python312`, `%USERPROFILE%\.cargo\bin`. Group *names* match nono; *contents* are Windows-specific. |
| `windows_common` forced group | No analog | **We add this** — every Win32 process needs `%SystemRoot%\System32` (read) and `%TEMP%` to start. nono doesn't need an analog because Linux processes don't need an "OS runtime paths" group. Forced: cannot be removed by any profile. |
| `add_deny_access` / `add_deny_commands` policy composition | nono profiles can deny specific paths and commands on top of an extended profile | **Deferred** — our MVP `filesystem.deny` exists (path deny-list) but `add_deny_commands` (command deny-list) is deferred to future F-16 (capability brokering). Documented in US-2. |
| Registry pull | `nono search`, `nono run --profile <registry-name>` pulls signed profiles from `registry.nono.sh` | **Deferred** — `saife profile pull` namespace reserved but no-op in MVP (future F-9). |
| Profile signing (Sigstore) | nono verifies signed profiles from the registry | **Deferred** — future F-5 (Sigstore Provenance). MVP profiles are unsigned local files. |
| `wsl2_proxy_policy` field | nono's profile schema has a WSL2-specific field | N/A — we're native Windows, no WSL2-specific profile fields. |

### What we add that nono doesn't have

- **`windows_common` forced implicit group**: necessary for Win32 processes
  to start at all. Documented in US-5 AC-5.9.
- **`java_runtime`, `dotnet_runtime`, `git_runtime` groups**: Windows
  developers commonly use Java (gradle, android), .NET, and git — we
  include these groups; nono's `rust_runtime`/`node_runtime`/
  `python_runtime` cover the Linux agent workload but Windows has a broader
  toolchain surface.
- **Schema-strict validation with typo suggestions**: "Unknown profile key
  'netwrok'. Did you mean 'network'?" — nono's behavior on unknown keys is
  not documented; we make strict validation a first-class feature (AC-5.13)
  to catch profile errors before a session starts.

### What nono has that we explicitly defer

| nono feature | Status | Where deferred |
|---|---|---|
| `nono search` / `nono run --profile <registry-name>` (registry) | Deferred — namespace reserved | future F-9 |
| Profile Sigstore signing & verification | Deferred | future F-5 |
| `add_deny_commands` (command deny-list) | Deferred — FS allow-list covers binary paths in MVP | future F-16 |
| `nono setup --check-only` WSL2 feature matrix report | N/A — we have our own `setup --check-only` (AC-1.9, AC-4.16) but it reports Windows build + AppContainer + ETW fidelity, not WSL2 limits | — |

### nono example profiles vs. ours

nono's `profiles/claude-code.json` example:

```json
{
  "meta": { "name": "claude-code", "version": "1.0.0", "description": "Anthropic Claude Code CLI agent" },
  "security": { "groups": ["node_runtime", "python_runtime", "rust_runtime"] },
  "filesystem": { "allow": ["$HOME/.claude"], "read_file": ["$HOME/.gitconfig"] },
  "network": { "block": false },
  "workdir": { "access": "readwrite" },
  "undo": { "exclude_patterns": ["node_modules", ".next", "target"] }
}
```

Our equivalent (MVP, `undo` deferred):

```json
{
  "meta": { "name": "claude-code", "version": "1.0.0", "description": "Anthropic Claude Code CLI agent", "schema_version": 1 },
  "security": { "groups": ["node_runtime", "python_runtime", "rust_runtime", "git_runtime"] },
  "filesystem": {
    "allow": ["$HOME/.claude", "$CWD"],
    "read_only": ["$HOME/.gitconfig"],
    "deny": ["$HOME/.ssh", "$HOME/.aws"]
  },
  "network": { "profile": "minimal", "allow_domain": ["api.anthropic.com"], "block": false },
  "workdir": { "access": "readwrite" }
}
```

Differences: we add `schema_version`, `git_runtime` group, explicit `deny`
list, and `network.profile` (nono relies on CLI `--network-profile` flag or
a `network.network_profile` field — we support both). `undo` is omitted
(deferred). `read_file` → `read_only` (renamed).

## Implementation-ready detail

Implemented in `docs/plans/2026-07-28-us-5-reusable-version-controlled-policy.md`. Summary of what landed:

- **JSON schema (serde):** `RawProfile`, `Meta`, `Security`, `RawFilesystem`, `RawNetwork`, `Workdir` — all `#[serde(rename_all = "snake_case", deny_unknown_fields)]`. `meta.schema_version: Option<u32>` is required at validation time (validated by `validate_schema_version`; only `1` supported). `Meta` derives `Default` so struct-literal tests can use `..Default::default()`.
- **Typo suggester:** `suggest_unknown_key` (Levenshtein ≤ 2 OR either string is a prefix of the other; case-insensitive; over `KNOWN_TOP_LEVEL_KEYS`). Wired via `with_suggestion` at the parse call site. AC-5.13.
- **Extends-merge:** `merge_profiles` — child overrides scalars, `filesystem.*` / `network.allow_domain` / `security.groups` arrays concatenate via `dedupe_concat` (case-insensitive de-dup).
- **Variable expansion:** `expand_vars` — `$HOME`, `$CWD`, `$USERPROFILE`, `$TEMP`. Forward slashes normalized to backslashes.
- **Security groups:** `resolve_groups` in `src/security_groups.rs` — `python_runtime`, `node_runtime`, `rust_runtime`, `java_runtime`, `git_runtime`, `dotnet_runtime`. `windows_common` is implicit (added by `sandbox::allowlist::build_allowlist`, not expandable here).
- **Cycle detection:** `check_cycle` formats `Profile cycle detected: a → b → a` (U+2192 arrow) per AC-5.6.
- **Search-path resolution:** `resolve_profile_path` — absolute path or `*.json`-suffixed name used as-is; bare name → `%USERPROFILE%\.saife\profiles\<name>.json`.
- **`profile list`:** `list_profiles` reads `*.json` from the user-global dir, extracts `meta.name` (falls back to filename stem), sorts alphabetically.
- **`profile show`:** raw view prints the file verbatim (AC-5.15); `--expanded` emits `to_expanded_json` — a single JSON object with `extends` flattened, `security.groups` expanded to per-group concrete path lists, variables expanded.
- **Error message format:** `anyhow` chains with `with_context`; parse errors carry serde's line/col; cycle + schema-version errors use the exact spec wording.
