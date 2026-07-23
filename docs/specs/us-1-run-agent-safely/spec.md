# US-1: Run a coding agent safely

> **Status:** Draft — narrative + acceptance criteria stage.
> Next: compare with nono, then expand to implementation-ready.

## User Story

As a solo developer running Claude Code (or OpenCode, Codex, …) on my Windows
machine, I want to start it with

```
sandbox run --profile claude-code --allow-cwd -- claude
```

so that the agent can read and write my project directory and reach the LLM
API, **but it cannot**:

- read my `~/.ssh` private keys,
- read `~/.aws/credentials` or `~/.config/gcloud` application-default creds,
- read `.env` files in sibling project directories,
- connect to anything except the LLM endpoint,
- spawn a child process that escapes any of the above.

## Narrative

The user opens PowerShell in `C:\Users\marku\projekte\myapp`, types the
command, and Claude Code starts normally. From the user's perspective it
behaves identically to running `claude` directly — the prompt works, file
edits land in the project, LLM calls succeed. The difference is invisible
until something tries to cross a boundary:

- An agent that tries `Get-Content $HOME\.ssh\id_rsa` gets `Access is
  denied.`
- An agent that tries `Invoke-WebRequest https://evil.example.com` gets a
  connection refused (denied by the network proxy, logged).
- An agent that tries to `cd ../other-project` and read its `.env` gets
  `Access is denied.` on the file open.

The sandbox is set up before the agent's first instruction executes and is
irrevocable for the entire process tree — neither the agent nor any subprocess
it spawns can widen the scope.

## Scope (MVP)

In scope:

- AppContainer profile creation with a per-session SID.
- RuleSet built from profile + CLI flags, applied to the process token.
- `CreateProcessW` with the restricted token + Job Object.
- Default-deny for any path not on the allow-list.
- Variable expansion: `$HOME`, `$CWD`, `$USERPROFILE`, `$TEMP`, `$SID`.
- **Option E sanctioned install directories** (per-session): the allow-list
  grants `Read/Write/Execute` on `.sandbox/$SID/bin/`, `.sandbox/$SID/venv/`,
  `.sandbox/$SID/npm/`, `.sandbox/$SID/cargo/`, `.sandbox/$SID/tmp/`, plus
  `Read/Write` on `$CWD`. The agent can install arbitrary tools into these
  dirs mid-session and execute them without re-profiling. See
  `docs/critical-review.md` Option E.
- **Per-session isolation**: two concurrent sandboxed processes in the same
  `$CWD` get distinct `$SID`-scoped install trees; neither can read the
  other's. See `docs/critical-review.md` "Per-session isolation".
- **Opt-in caching via persist/reuse**: `sandbox persist <sid> [--as <name>]`
  promotes a session's install tree to a named durable store;
  `sandbox run --reuse <name> -- …` starts a new session aliased to that
  store (read-only by default; `--reuse-rw` for writable). Reused stores
  live under `%USERPROFILE%\.sandbox\stores\<name>\` (outside any
  workspace). See `docs/critical-review.md` "Caching via persist / reuse".
- `--allow`, `--read-only`, `--allow-cwd` CLI flags on top of profile.
- Profile loading (`--profile <name>` resolves to
  `%USERPROFILE%\.sandbox\profiles\<name>.json`) — full profile schema is
  US-5; here we only need the filesystem slice.

Out of scope (covered by other US):

- Network filtering — US-3.
- Audit logging — US-4.
- Child-process inheritance mechanics — US-2 (here we just inherit by virtue
  of the same token; US-2 specifies the test matrix).
- Credential injection — future-ideas F-2.

## Acceptance Criteria

### AC-1.1 — Happy path: agent starts and runs
**Given** a valid profile `claude-code.json` exists in
`%USERPROFILE%\.sandbox\profiles\` with `filesystem.allow: ["$CWD",
"$HOME/.claude"]`,
**When** the user runs `sandbox run --profile claude-code --allow-cwd --
claude` from `C:\Users\marku\projekte\myapp`,
**Then** `claude` starts, prints its normal prompt, accepts input, and exits
with the same exit code it would have without `sandbox`.

### AC-1.2 — Disallowed file read is denied
**Given** a sandboxed process started with an allow-list that does not include
`$HOME\.ssh`,
**When** the process executes `Get-Content $HOME\.ssh\id_rsa`,
**Then** the OS returns `ERROR_ACCESS_DENIED` and PowerShell prints
`Access is denied.` — no file content is returned.

### AC-1.3 — Disallowed sibling project is denied
**Given** the sandbox is started in `C:\projekte\myapp` with `--allow-cwd`
and `filesystem.deny: ["$HOME/.ssh", "$HOME/.aws"]`,
**When** the process executes `Get-Content ..\other-project\.env`,
**Then** the read is denied with `ERROR_ACCESS_DENIED`.

### AC-1.4 — Allowed write works
**Given** the sandbox is started with `$CWD` in `filesystem.allow` (readwrite
implied),
**When** the agent writes `C:\projekte\myapp\new-file.txt`,
**Then** the file is created on disk and is visible to the user outside the
sandbox after the session ends.

### AC-1.5 — Read-only path cannot be written
**Given** `$HOME\.gitconfig` is listed under `filesystem.read_only`,
**When** the agent attempts to overwrite it,
**Then** the write is denied with `ERROR_ACCESS_DENIED`, while reads still
succeed.

### AC-1.6 — Irrevocability
**Given** a sandboxed process is running,
**When** the process calls any `sandbox.exe` subcommand or any Win32 API that
would attempt to loosen the AppContainer RuleSet,
**Then** no change to the running process's effective allow-list is possible.
There is no code path in `sandbox.exe` that exposes a "loosen" operation.

### AC-1.7 — Variable expansion across users
**Given** the same profile is used by two different users on the same machine,
**When** each runs `sandbox run --profile X --allow-cwd -- cmd`,
**Then** `$HOME` expands to each user's own profile directory and neither
user can reach the other's files unless explicitly listed by absolute path.

### AC-1.8 — Job Object kills descendants on parent exit
**Given** a sandboxed process has spawned child processes,
**When** `sandbox.exe` (the supervisor) exits — normally or via `Ctrl-C`,
**Then** all descendant processes are terminated by the Job Object
(`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`) within 1 second, leaving no orphans.

### AC-1.9 — Setup check fails fast on unsupported OS
**Given** `sandbox` is run on Windows 10 build 15063 (pre-1709),
**When** the user runs `sandbox run -- …`,
**Then** the command exits non-zero with a clear error message: *"AppContainer
RuleSet requires Windows 10 1709 (build 16299) or later. Detected build 15063."*
before any process is spawned.

### AC-1.10 — Init latency budget
**Given** a reference machine (SSD, 8 GB RAM, Win10 22H2),
**When** `sandbox run` is invoked,
**Then** the time from `sandbox.exe` entry to `CreateProcessW` returning is
under 50 ms (p95) for a profile with ≤ 20 allow-list entries.

### AC-1.11 — Option E: agent can install a binary and run it
**Given** a sandboxed process started with the Option E allow-list (which
grants `Read/Write/Execute` on `.sandbox/$SID/bin/`),
**When** the agent runs `Invoke-WebRequest -OutFile .sandbox\$SID\bin\jq.exe
<url>` (or copies from a readable source) and then invokes
`.sandbox\$SID\bin\jq.exe …`,
**Then** the binary executes successfully — no profile edit, no restart, no
admin. The agent can extend its own toolset at runtime within the sanctioned
dir.

### AC-1.12 — Per-session isolation: two sessions get distinct install trees
**Given** two `sandbox run` invocations started concurrently in the same
`$CWD`, producing session ids `$SID_A` and `$SID_B`,
**When** session A writes `.sandbox\$SID_A\bin\tool.exe`,
**Then** (a) `$SID_A` ≠ `$SID_B`, (b) the file exists only under
`.sandbox\$SID_A\bin\`, not under `.sandbox\$SID_B\bin\`, and (c) session B
cannot read `.sandbox\$SID_A\bin\tool.exe` (the path is not on B's
allow-list — `Access is denied`).

### AC-1.13 — Per-session isolation: no cross-session PATH poisoning
**Given** session A has installed a `git.exe` in `.sandbox\$SID_A\bin\` and
session B is running with `PATH` prepended with `.sandbox\$SID_B\bin\`,
**When** session B runs `git`,
**Then** it resolves to the system `git.exe` (or fails if none), **not** to
session A's `.sandbox\$SID_A\bin\git.exe`. A's installs cannot influence B's
PATH.

### AC-1.14 — Per-session cleanup
**Given** a session has ended (normally or via `Ctrl-C`),
**When** the user lists `$CWD\.sandbox\`,
**Then** the `.sandbox\$SID\` tree is removed (default retention: wipe on
session end) **unless** `sandbox persist <sid>` was called for that session,
in which case the tree has been moved to
`%USERPROFILE%\.sandbox\stores\<name>\` and `.sandbox\$SID\` no longer exists
in the workspace.

### AC-1.15 — `persist` promotes a session tree to a named store
**Given** a session `$SID` has installed tools in `.sandbox\$SID\bin\`,
**When** the user runs `sandbox persist $SID --as my-tools`,
**Then** the tree is moved to `%USERPROFILE%\.sandbox\stores\my-tools\` and
a manifest of file hashes is written at
`%USERPROFILE%\.sandbox\stores\my-tools\.manifest.json`. The original
`.sandbox\$SID\` is removed.

### AC-1.16 — `--reuse` runs a new session against a persisted store (read-only)
**Given** a persisted store `my-tools` exists,
**When** the user runs `sandbox run --reuse my-tools --allow-cwd -- cmd`,
**Then** the new session's install dirs alias to
`%USERPROFILE%\.sandbox\stores\my-tools\bin\` etc.; the sandboxed process
can read and execute tools from the store, but **cannot write to it** (writes
return `Access is denied`). The audit log records that the session reused
`my-tools`.

### AC-1.17 — `--reuse-rw` makes the store writable (single-writer)
**Given** a persisted store `my-tools` exists,
**When** the user runs `sandbox run --reuse-rw my-tools --allow-cwd -- cmd`,
**Then** the session can write new tools into the store (incremental
accumulation). If a second `--reuse-rw` against the same store is started
concurrently, it is denied with a clear error: *"store 'my-tools' is in
read-write use by session $SID_X; wait for it to finish or use --reuse
(read-only)."*. A `--reuse` (read-only) against a store currently in
`--reuse-rw` use is allowed (multiple readers, one writer).

### AC-1.18 — `--reuse` verifies the store manifest
**Given** a persisted store `my-tools` with a `.manifest.json`,
**When** the user runs `sandbox run --reuse my-tools -- …`,
**Then** `sandbox` recomputes the hash of every file in the store and
compares to the manifest. If any file has been tampered with externally,
`sandbox` exits non-zero with: *"store 'my-tools' manifest mismatch: file
'bin/jq.exe' hash differs from manifest"* — refusing to run the session
with a corrupted store.

## nono comparison

### What we match

- **`run` subcommand shape**: `sandbox run --profile X --allow-cwd -- <cmd>`
  mirrors `nono run --profile X --allow-cwd -- <cmd>`. The `--` separator,
  `--profile`, `--allow`, `--allow-cwd`, `--read-only` flags have identical
  semantics.
- **Default-deny filesystem**: paths not on the allow-list are denied. This
  is nono's core property and ours.
- **Irrevocability**: applied before first instruction, cannot be loosened
  for the lifetime of the process tree. AppContainer RuleSet is the Windows
  analog of Landlock's irrevocable ruleset.
- **Per-process, unprivileged, no daemon**: matches nono's "no root, no
  containers, no overhead" positioning. AppContainer + Job Object require no
  service, no admin, no driver for the MVP.
- **Variable expansion** (`$HOME`, `$CWD`) in profiles: same syntax and
  semantics as nono.

### What we differ on (Windows-specific)

| Aspect | nono (Linux) | sandbox (Windows) |
|---|---|---|
| Isolation mechanism | Landlock LSM (ABI v5) — per-path read/write/execute rules at syscall layer | AppContainer + RuleSet — per-path capability rules at object-manager layer |
| Rule granularity | Per-syscall-type (`LANDLOCK_ACCESS_FS_*`) — separate rules for read/write/execute/make-dir/remove-file/etc. | Coarser: per-path access mask (`Read`, `Write`, `Execute` capability bits) at `IRP_MJ_CREATE` time. No per-operation-type (delete vs rename vs set-attr) granularity. We document this as a known fidelity gap; the minifilter driver (future F-7) closes it. |
| Default capability set | Landlock starts from "everything allowed" and the ruleset *removes* access | AppContainer starts from "nothing allowed" and the RuleSet *grants* access — same end-state (default-deny allow-list), opposite construction. |
| Inheritance | Per-thread via `restrict_self()`, inherited by `fork()`/`execve()` children | Per-token: children spawned under the same AppContainer SID automatically inherit. Equivalent effect, different mechanism. |
| Path normalization | Linux paths, case-sensitive, `/` separators, symlink-resolved at rule-add time | Windows paths, **case-insensitive**, `\` or `/` separators (Win32 layer accepts both), `\\?\` long paths. We must normalize to canonical form (resolve `\\`, `..`, case-fold) before adding rules — nono does the same for symlink resolution. |
| Drive letters / UNC | Not applicable | Rules must scope by drive letter and UNC share (`\\server\share`); AppContainer RuleSet works on NT paths so we translate `C:\foo` → `\Device\HarddiskVolume3\foo` at rule-add time. The translation is opaque to the user (profile stays `C:\foo`). |
| `windows_common` implicit group | nono has no analog (Linux apps don't need a "common" group) | **We add this**: any Win32 process needs `%SystemRoot%\System32`, `%TEMP%` to even start. nono's `node_runtime`/`python_runtime` groups cover toolchain paths but Linux needs no implicit "OS runtime" group. This is a forced divergence, not a design choice. |
| Backslash in profile JSON | nono profiles use `/` | We accept both `/` and `\` in profiles and normalize internally. Documented in US-5. |
| "Warning, ABI too old" | nono degrades gracefully if kernel < ABI v5 | We fail fast on build < 16299 (AC-1.9). No graceful degradation — AppContainer either works or it doesn't on a given Windows build. |

### What we add that nono doesn't have

- **Job Object kill-on-close**: nono's child processes die when nono exits
  because Landlock rules die with the process. We add an explicit
  `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` Job Object so the entire process
  tree is killed even if a daemon re-parented to `services.exe` (a
  Windows-specific orphan pattern). This is necessary because Windows
  background processes do not always die with their parent.
- **Option E sanctioned install directories (per-session)**: nono's
  profiles enumerate paths and the agent is expected to stay within them.
  We additionally grant the agent a small set of per-session install roots
  (`.sandbox/$SID/bin/`, `.sandbox/$SID/venv/`, etc.) where it can drop
  arbitrary new tools at runtime and execute them without re-profiling. This
  answers OpenAI's rejection of AppContainer ("the agent picks binaries at
  runtime") by making the *directories* the pre-declared unit, not the
  tools. See `docs/critical-review.md` Option E.
- **Per-session install isolation**: two concurrent agents in the same
  `$CWD` get distinct `$SID`-scoped install trees; neither can read or
  poison the other. nono doesn't address concurrent-agent-same-workspace
  isolation explicitly.
- **Opt-in caching via persist/reuse**: a session's install tree can be
  promoted to a named durable store and reused read-only (or read-write,
  single-writer) by future sessions. Manifest-verified at reuse time. nono
  has no equivalent — its profiles are static path lists, not install
  trees.

### What nono has that we explicitly defer

- **Capability elevation via seccomp-notify** (nono warns "disabled on WSL2"):
  deferred to Runtime Supervisor (future F-4). The MVP has no dynamic
  expansion — if the agent lacks access it fails immediately.

### Non-normative: nono's Windows/WSL2 path

nono's stated Windows support runs inside WSL2 and applies Landlock to the
Linux kernel inside it. That gives full feature parity for *Linux* processes
but cannot sandbox native Win32 binaries. Our design targets native Win32
directly — a different niche. The two tools are complementary, not
competing on the same workload.

## Implementation-ready detail (to be filled in last step)

TODO: exact Win32 calls, data structures, error codes, test commands.

## Implementation-ready detail (to be filled in last step)

TODO: exact Win32 calls, data structures, error codes, test commands.
