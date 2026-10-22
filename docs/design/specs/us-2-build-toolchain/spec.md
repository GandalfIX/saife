# US-2: Build toolchain runs inside the sandbox

> **Status:** Draft — narrative + acceptance criteria stage.
> Next: compare with nono, then expand to implementation-ready.

## User Story

As a developer whose coding agent invokes `gradle build`, `python -m pytest`,
`npm install`, or `cargo test`, I want those child processes to **inherit** the
sandbox automatically — same filesystem allow-list, same network restrictions
— with no extra configuration, so that a malicious build script or a
compromised dependency cannot escape the boundary the agent was given.

## Narrative

The agent is started under `sandbox run` and decides on its own to spawn
helpers: it shells out to `gradle`, runs `pytest`, calls `npm ci`. From the
agent's perspective these are ordinary subprocess launches and they all work
normally — they can read/write the project directory, reach the package
registry the profile permits, and so on.

The critical property the user cares about is **transitivity**: a build script
that tries to read `~/.ssh` is denied, even though the agent itself never
attempted it. A `postinstall` hook that tries to `curl` an attacker's server
is denied, even though the agent's own network allowance was broader.

There is no way for the agent, by setting environment variables, writing a
wrapper script, or launching a helper binary, to grant its children more access
than it has. The AppContainer token is inherited verbatim by every process in
the tree; the Job Object prevents any descendant from escaping
(`JOB_OBJECT_LIMIT_BREAKAWAY_OK` is **not** set, so breakaway job assignment
is forbidden).

## Scope (MVP)

In scope:

- Verification that AppContainer tokens are inherited by `CreateProcessW`
  children without `CREATE_BREAKAWAY_FROM_JOB` (which is blocked anyway).
- Test matrix proving: nested children (N levels deep), common toolchains
  (gradle, python, node, cargo, java/javac), and indirect launches via
  shell wrappers all remain confined.
- Documentation of the toolchain **runtime security groups** the profile can
  reference so that e.g. `python_runtime` grants read access to the Python
  install directory and pip cache, which the agent *and* its children need
  for `python` to even start.
- Job Object configuration: `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`,
  `JOB_OBJECT_LIMIT_BREAKAWAY_OK = false`, UI restrictions off.

Out of scope:

- Dynamic per-child expansion of the allow-list (that is US-7 Runtime
  Supervisor — future-ideas F-4).
- Time-travel debugging of the process tree (future-ideas F-19).

## Acceptance Criteria

### AC-2.1 — Direct child inherits restrictions
**Given** a sandboxed `cmd.exe` running with `filesystem.allow: ["$CWD"]` only,
**When** it runs `cmd /c type C:\Users\marku\.ssh\id_rsa`,
**Then** the read is denied with `Access is denied.` — the child `cmd` did
not inherit broader rights than its parent.

### AC-2.2 — Grandchild at depth N inherits restrictions
**Given** a sandboxed process,
**When** it runs `cmd /c cmd /c cmd /c type C:\Users\marku\.ssh\id_rsa` (depth
4),
**Then** the read is still denied. The restrictions hold to any depth.

### AC-2.3 — Gradle child stays in sandbox
**Given** a sandboxed `gradle build` invocation with `$CWD` and
`$HOME\.gradle` in the allow-list,
**When** gradle forks a `javac` worker,
**Then** that worker can read its JDK install (because `java_runtime` group is
in the profile) and write to `$CWD\build\`, but cannot read `$HOME\.ssh`.

### AC-2.4 — npm postinstall hook stays confined
**Given** a sandboxed `npm install` with `$CWD`, `$HOME\.npm`, and
`node_runtime` group in the allow-list, network limited to
`registry.npmjs.org`,
**When** a dependency's `postinstall` script runs `node exfil.js`,
**Then** `exfil.js` is denied network access to anything outside the profile's
network allow-list, and denied filesystem access outside the profile's FS
allow-list.

### AC-2.5 — Breakaway is blocked
**Given** a sandboxed process attempts to launch a child with
`CREATE_BREAKAWAY_FROM_JOB`,
**When** `CreateProcessW` returns,
**Then** the call fails with `ERROR_ACCESS_DENIED` — the child cannot escape
the Job Object, so cannot escape the sandbox.

### AC-2.6 — Variable-based shell wrappers stay confined
**Given** the agent writes a `.bat` file inside `$CWD` that does
`powershell -c "Get-Content $env:USERPROFILE\.ssh\id_rsa"`,
**When** the agent runs that `.bat`,
**Then** the `Get-Content` is denied. The wrapper inherits the agent's
restricted token regardless of which interpreter it shells out to.

### AC-2.7 — Job Object kills the whole tree
**Given** a sandboxed agent has spawned a 4-level deep tree including gradle
daemons and a `python -m http.server` background process,
**When** the user kills `sandbox.exe` with `Ctrl-C`,
**Then** every process in the tree — including background daemons that
re-parented — is terminated within 1 second.

### AC-2.8 — Exit code propagation
**Given** a sandboxed child exits with code N,
**When** `sandbox run` returns,
**Then** `sandbox.exe` exits with the same code N (so CI / scripts can react).

### AC-2.9 — Security groups make toolchains actually usable
**Given** a profile with `security.groups: ["python_runtime"]`,
**When** the user runs `sandbox run --profile P --allow-cwd -- python -m
pytest`,
**Then** python starts successfully (can read its own install dir and pip
cache). Without the group, the same command would fail to start with
`python.exe not found` or `Permission denied` on the stdlib path.

## nono comparison

### What we match

- **Automatic inheritance by child processes**: nono achieves this via
  Landlock's per-thread rules inherited across `fork()`/`execve()`. We achieve
  it via AppContainer token inheritance — children spawned by a sandboxed
  process automatically get the same token and SID. The user-visible property
  is identical: nested children at any depth stay confined.
- **No "breakaway" escape**: nono's Landlock rules cannot be dropped by a
  child. We prevent the Windows equivalent — `CREATE_BREAKAWAY_FROM_JOB` —
  by not setting `JOB_OBJECT_LIMIT_BREAKAWAY_OK` on the Job Object, so
  `CreateProcessW` with that flag returns `ERROR_ACCESS_DENIED`.
- **Security groups for toolchain paths**: nono's `node_runtime`,
  `python_runtime`, `rust_runtime` groups map directly to our equivalents.
  Same concept: `sandbox` maintains the path lists so profiles stay concise
  as toolchain layouts change.
- **`add_deny_commands` / deny-list commands**: nono profiles can deny
  specific commands (`docker`, `kubectl`). Our MVP does **not** implement
  command deny-listing (deferred — future F-16 capability brokering covers it
  better as a positive list). We document this gap explicitly: a sandboxed
  process can launch `docker.exe` if `docker.exe` is on the filesystem
  allow-list and has execute permission. Mitigation: leave `docker.exe`'s
  directory out of the allow-list.

### What we differ on (Windows-specific)

| Aspect | nono (Linux) | sandbox (Windows) |
|---|---|---|
| Inheritance mechanism | Landlock per-thread rules | AppContainer token + Job Object |
| Grandchild depth | Unlimited via `fork` | Unlimited via `CreateProcessW` — but Windows has no `fork`, so each level is a fresh `CreateProcessW` with token inheritance. Verified by AC-2.2. |
| Toolchain group contents | Linux paths: `/usr/bin`, `/usr/lib`, `~/.npm`, `~/.cache/pip`, `~/.cargo/bin` | Windows paths: `%ProgramFiles%\nodejs`, `%APPDATA%\npm`, `%LOCALAPPDATA%\Programs\Python\Python312`, `%USERPROFILE%\.cargo\bin`, `%USERPROFILE%\.gradle`, JDK under `%ProgramFiles%\Java\*` |
| Process tree kill | nono: children die when nono exits (Landlock is per-process) | Windows: daemons can re-parent to `services.exe` and survive parent death. Job Object with `KILL_ON_JOB_CLOSE` is **required** to guarantee whole-tree kill (AC-2.7). nono doesn't need this because Linux orphans die when their parent does (modulo re-parenting to init, which nono handles by scope). |
| `CREATE_BREAKAWAY_FROM_JOB` | No analog | Explicitly blocked — Windows-specific escape vector. |
| Exit code propagation | nono exits with the child's code | Same — `sandbox.exe` calls `GetExitCodeProcess` and returns it. |
| Toolchain process models | Linux: gradle daemon, npm cache, pip — all file-system based | Windows: same tools exist but use different cache paths (e.g. `%USERPROFILE%\.gradle` vs `~/.gradle`) and different binary locations. Group contents differ; concept is identical. |

### What we add that nono doesn't have

- **`windows_common` forced group**: any Win32 process needs
  `%SystemRoot%\System32` (read) and `%TEMP%` to start at all. nono doesn't
  need an analog because Linux processes don't need a "common OS paths" group
  to boot. We document and force-add this in US-5.
- **Job Object `KILL_ON_JOB_CLOSE`**: required on Windows to kill orphaned
  daemons (gradle daemon, npm background processes) that re-parent away from
  the agent. nono's Linux model handles this differently.

### What nono has that we explicitly defer

- **`add_deny_commands`**: nono profiles can deny specific binaries from
  being executed. We defer this; the MVP's filesystem allow-list already
  prevents executing binaries in denied paths. A positive-capability
  command broker (future F-16) is the planned long-term solution.
- **seccomp-notify capability elevation**: nono's Runtime Supervisor can
  dynamically grant a child new file/network access at runtime. Deferred to
  future F-4.

### nono WSL2-specific behavior (informational)

On WSL2, nono disables seccomp-notify capability elevation (kernel bug) and
defaults credential proxy enforcement to fail-secure. Our native-Windows
design is unaffected by these WSL2 limitations. We list them here only so
future contributors don't try to "fix" problems that don't exist in our
target environment.

## Implementation-ready detail

This section is the contract the US-2 implementation must satisfy. It is the
single source of truth for flag values, path resolution rules, and the
acceptance-criterion verification matrix.

### 1. Job Object flags (reference — already implemented)

Reference: `sandbox/src/sandbox/job.rs`.

- `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` **is** set. When the Job Object handle
  is released (i.e. `sandbox.exe` exits, including via `Ctrl-C`), every process
  assigned to the job — including re-parented daemons — is terminated.
- `JOB_OBJECT_LIMIT_BREAKAWAY_OK` **is NOT** set. Consequently any
  `CreateProcessW` call inside the sandbox that passes
  `CREATE_BREAKAWAY_FROM_JOB` fails with `ERROR_ACCESS_DENIED` (5). This is the
  Windows-specific escape vector AC-2.5 verifies is closed.
- **No UI limits** are imposed for the MVP (no
  `JOB_OBJECT_UILIMIT_*` flags). The AppContainer token already restricts
  window-station / clipboard access; redundant Job UI limits add no security
  value for MVP and would complicate debugging.
- **No CPU / memory / commit limits** are imposed for the MVP. Resource
  quotas are out of scope (potential future work; not tracked under US-2).

### 2. `CreateProcessW` flags (reference — already implemented)

Reference: `sandbox/src/sandbox/spawn.rs`.

The sandbox launches the agent process with:

- `dwCreationFlags = CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT`.
  - `CREATE_UNICODE_ENVIRONMENT`: environment block is UTF-16.
  - `EXTENDED_STARTUPINFO_PRESENT`: an `STARTUPINFOEX` is supplied, enabling
    the attribute list below.
- Attribute list contains:
  - `PROC_THREAD_ATTRIBUTE_JOB_LIST` — assigns the new child to the Job
    Object. This is what makes the whole-tree kill (AC-2.7) work.
  - `PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES` — binds the per-session
    AppContainer SID (created from the user's session + a sandbox-specific
    capability) to the child process. The AppContainer SID is the
    filesystem-allow-list identity: the token's user is the AppContainer SID,
    and the DACL built in `appcontainer.rs` grants that SID RX/RWX on the
    allow-listed paths.
- **Token inheritance to descendants**: nothing extra is required. Children
  spawned by the sandboxed process inherit the same AppContainer token
  automatically — Windows default behavior when the parent's token is the
  AppContainer token and the child does not pass `CREATE_BREAKAWAY_FROM_JOB`
  (which is blocked anyway). This is the mechanism AC-2.1, AC-2.2, and AC-2.6
  rely on.

### 3. Security groups — path resolution (the new US-2 work)

This is the core implementation gap US-2 closes. Profiles declare
`security.groups: ["python_runtime", ...]` and the loader expands each group
name into a concrete set of filesystem paths **before** building the allow-list
in `build_allowlist` (`sandbox/src/sandbox/allowlist.rs`).

Groups grant **READ + EXECUTE (RX)** by default. The toolchain needs to *run*
its binaries and *read* its stdlib, but must **not** be writable by the
sandboxed process — a compromised agent should not be able to poison the
shared Python / Node / JDK install on the host.

#### Group definitions (FR-5.4)

**`python_runtime`**
- Resolve `python.exe`: iterate `PATH` entries left-to-right; the first
  directory containing `python.exe` gets RX. If not found on `PATH`, skip this
  entry silently (the toolchain isn't installed on this machine).
- `%LOCALAPPDATA%\Programs\Python\` (recursive, RX) — covers Microsoft Store
  and python.org per-user installs.
- `%LOCALAPPDATA%\pip\Cache` (RX) — pip download cache.
- `%APPDATA%\Python\` (recursive, RX) — covers per-user `Scripts` dirs
  (e.g. `pip`, `black`, `pytest` shims).

**`node_runtime`**
- Resolve `node.exe`: iterate `PATH` entries left-to-right; the directory
  containing `node.exe` gets RX. If absent, skip silently.
- `%APPDATA%\npm` (RX) — global npm bin dir.
- `%LOCALAPPDATA%\pnpm` (RX) — global pnpm bin dir, **if it exists** (see
  existence rule below).
- npm cache: `%LOCALAPPDATA%\npm-cache` (RX) if it exists, otherwise
  `%APPDATA%\npm-cache` (RX) for older layouts. Check both; grant whichever
  is present. If neither exists, skip.

**`rust_runtime`**
- `%USERPROFILE%\.cargo` (recursive, RX) — cargo binaries + registry cache.
  Note: `.cargo\bin` needs execute; granting RX on the entire `.cargo` tree
  is acceptable for MVP.
- `%USERPROFILE%\.rustup` (recursive, RX) — toolchain installs.

**`java_runtime`**
- `JAVA_HOME` env var, if set: RX on the JDK install dir recursively.
- `%USERPROFILE%\.gradle` (recursive, RX) — gradle caches + wrapper dists.
- `%ProgramFiles%\Java\*` (RX) — system JDK installs (legacy Java 8 layout).
- `%ProgramFiles%\Eclipse Adoptium\*` (RX) — common modern JDK install
  location; grant only if it exists.

**`windows_common`** (implicit — force-added, **NOT** user-selectable in
profiles)
- `%SystemRoot%\System32` (RX) — required for any Win32 process to start.
- `%SystemRoot%` (RX) — minimal traversal.
- `%TEMP%` — for MVP we **rely on the AppContainer's default temp-dir
  redirect** rather than granting an explicit RWX. The current implementation
  in `allowlist.rs` only adds `System32` and `SystemRoot`; the OS handles temp
  redirection. A future revision may add an explicit TEMP grant. Documented
  here so the gap is visible.
- This group is added by `build_allowlist` automatically, **not** via profile
  expansion. Profiles do **not** need to list it; if they do, it is a no-op
  (the addition is idempotent — `dedupe_paths` collapses the duplicate).

#### Resolution rules

- **"Search `PATH` for `X.exe`"**: iterate `PATH` entries left-to-right;
  return the first directory containing the binary. If none, skip the entry
  silently — the toolchain simply isn't installed. (Logging at debug level via
  `tracing` is deferred; for now silent.)
- **Recursive grants**: the path itself + all descendants. The DACL mechanism
  in `appcontainer.rs` already uses `SUB_CONTAINERS_AND_OBJECTS_INHERIT`, so a
  single grant on the directory covers the subtree — no need to walk it.
- **Existence check**: for env-var-derived paths (`JAVA_HOME`, `.cargo`,
  `.rustup`, `.gradle`, pnpm dir, etc.), if the resolved path does not exist
  on disk, skip it silently. **Do NOT error** — profiles are shared across
  machines with different toolchains installed.
- **De-duplication**: after expansion, de-dup against existing allow entries
  (case-insensitive, per `dedupe_paths` in `profile.rs`). A path already
  granted RWX (e.g. `$CWD` explicitly listed in `allow`) must **not** be
  downgraded to RX by a group.

#### Loader algorithm

1. Load raw profile JSON (already implemented in `profile.rs`).
2. After merging `extends` chains (already implemented), collect
   `security.groups` into a `Vec<String>`.
3. For each group name, call a resolver
   `resolve_group(name: &str) -> Vec<(PathBuf, u32)>` returning
   `(path, access-mask)` pairs (mask is RX for all group grants). Unknown
   group names print a warning to stderr but do **not** abort — be forgiving —
   and contribute no paths.
4. Merge resolved group paths into the profile's `FilesystemSlice.read_only`
   (RX semantics match). **Exception**: if a path is already present in
   `allow` (RWX), leave it at RWX — do not downgrade. The `dedupe_paths`
   function preserves the first occurrence, so add profile `allow` entries
   first, then group paths to `read_only`; the existing merge order handles
   the conflict correctly.
5. `windows_common` is **not** handled in the profile expansion step — it is
   force-added by `build_allowlist` in `allowlist.rs` (already implemented).
   The profile expansion only handles user-selectable groups.

### 4. Test fixtures and commands (the AC verification matrix)

Each US-2 AC maps to a PowerShell integration scenario in
`tests/run-tests.ps1` (S-numbered). Existing scenarios are noted; new ones
are added under their assigned numbers.

- **AC-2.1** (direct child inherits) — already covered by **S-2**.
  Command:
  ```powershell
  sandbox run --allow-cwd -- cmd /c type $env:USERPROFILE\.ssh\id_rsa
  ```
  Assert: exit code ≠ 0, stderr contains `Access is denied.`

- **AC-2.2** (grandchild depth N) — already covered by **S-10** (depth 3).
  Command:
  ```powershell
  sandbox run --allow-cwd -- cmd /c cmd /c cmd /c type <denied path>
  ```
  Assert: read denied at depth 4.

- **AC-2.3** (gradle / javac) — **new scenario S-23**.
  Requires `java_runtime` group + a gradle project fixture under
  `tests/fixtures/gradle-project/`. Marked `requires java installed` — the
  scenario skips cleanly if `java -version` and `gradle -version` both fail.
  Command:
  ```powershell
  sandbox run --profile gradle-test --allow-cwd -- gradle build
  ```
  Assert: build succeeds, and a worker forked by gradle is denied a read of
  `$env:USERPROFILE\.ssh\id_rsa`.

- **AC-2.4** (npm postinstall) — **no new scenario here**. The filesystem
  confinement portion is verified by AC-2.1 / AC-2.2. The network-denial
  portion of this AC depends on US-3 (network filtering) which is not yet
  implemented. Note in `run-tests.ps1`: *"AC-2.4 network portion verified
  post-US-3."*

- **AC-2.5** (breakaway blocked) — **new scenario S-22**.
  Requires a helper binary `breakaway-helper.exe` that calls
  `CreateProcessW` with `CREATE_BREAKAWAY_FROM_JOB` and prints the resulting
  error code. The helper is built as a small separate Rust binary under
  `tests/fixtures/breakaway-helper/`. Command:
  ```powershell
  sandbox run --allow-cwd -- breakaway-helper.exe
  ```
  Assert: helper prints `ERROR_ACCESS_DENIED (5)`.

- **AC-2.6** (shell wrapper confinement) — **new scenario S-21**.
  The agent writes a `.bat` file inside `$CWD` containing:
  ```bat
  powershell -c "Get-Content $env:USERPROFILE\.ssh\id_rsa"
  ```
  Then runs:
  ```powershell
  sandbox run --allow-cwd -- cmd /c .\wrapper.bat
  ```
  Assert: the `Get-Content` is denied (exit ≠ 0, stderr contains
  `Access is denied.`).

- **AC-2.7** (Job Object kills tree) — already covered by **S-11**.

- **AC-2.8** (exit code propagation) — **new scenario S-24**.
  Command:
  ```powershell
  sandbox run --allow-cwd -- cmd /c exit 42
  ```
  Assert: `sandbox.exe` exits with code `42`.

- **AC-2.9** (security groups make toolchain usable) — **new scenarios
  S-19 and S-20**.
  Both skip cleanly if the toolchain is absent.
  - **S-19** (python_runtime):
    ```powershell
    sandbox run --profile python-runtime-test --allow-cwd -- python -c "print('ok')"
    ```
    Assert: stdout contains `ok`. Without the `python_runtime` group in the
    profile, the same command would fail to start (cannot read stdlib).
  - **S-20** (node_runtime):
    ```powershell
    sandbox run --profile node-runtime-test --allow-cwd -- node -e "console.log('ok')"
    ```
    Assert: stdout contains `ok`. Without the `node_runtime` group, `node`
    cannot start.

### 5. Out-of-scope reminder (for the implementer)

- **Network filtering** (the network portion of AC-2.4) is **US-3** — not
  US-2. The FS-confinement portion of AC-2.4 is already covered by AC-2.1 /
  AC-2.2.
- **Audit logging of process spawns** is **US-4** — not US-2.
- **Dynamic permission expansion at runtime** is future **F-4** (Runtime
  Supervisor, US-7) — not US-2. The US-2 allow-list is static, built from the
  profile at sandbox-start time.
