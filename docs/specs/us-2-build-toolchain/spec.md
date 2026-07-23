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

## Implementation-ready detail (to be filled in last step)

TODO: Job Object flag values, `CreateProcessW` flags, test fixtures, exact
toolchain group path lists.

## Implementation-ready detail (to be filled in last step)

TODO: Job Object flag values, `CreateProcessW` flags, test fixtures, exact
toolchain group path lists.
