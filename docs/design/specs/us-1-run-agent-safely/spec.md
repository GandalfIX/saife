# US-1: Run a coding agent safely

> **Status:** Draft — narrative + acceptance criteria stage.
> Next: compare with nono, then expand to implementation-ready.

## User Story

As a solo developer running Claude Code (or OpenCode, Codex, …) on my Windows
machine, I want to start it with

```
saife run --profile claude-code --allow-cwd -- claude
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
  `docs/design/critical-review.md` Option E.
- **Per-session isolation**: two concurrent sandboxed processes in the same
  `$CWD` get distinct `$SID`-scoped install trees; neither can read the
  other's. See `docs/design/critical-review.md` "Per-session isolation".
- **Opt-in caching via persist/reuse**: `saife persist <sid> [--as <name>]`
  promotes a session's install tree to a named durable store;
  `saife run --reuse <name> -- …` starts a new session aliased to that
  store (read-only by default; `--reuse-rw` for writable). Reused stores
  live under `%USERPROFILE%\.saife\stores\<name>\` (outside any
  workspace). See `docs/design/critical-review.md` "Caching via persist / reuse".
- `--allow`, `--read-only`, `--allow-cwd` CLI flags on top of profile.
- Profile loading (`--profile <name>` resolves to
  `%USERPROFILE%\.saife\profiles\<name>.json`) — full profile schema is
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
`%USERPROFILE%\.saife\profiles\` with `filesystem.allow: ["$CWD",
"$HOME/.claude"]`,
**When** the user runs `saife run --profile claude-code --allow-cwd --
claude` from `C:\Users\marku\projekte\myapp`,
**Then** `claude` starts, prints its normal prompt, accepts input, and exits
with the same exit code it would have without `saife`.

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
**When** the process calls any `saife.exe` subcommand or any Win32 API that
would attempt to loosen the AppContainer RuleSet,
**Then** no change to the running process's effective allow-list is possible.
There is no code path in `saife.exe` that exposes a "loosen" operation.

### AC-1.7 — Variable expansion across users
**Given** the same profile is used by two different users on the same machine,
**When** each runs `saife run --profile X --allow-cwd -- cmd`,
**Then** `$HOME` expands to each user's own profile directory and neither
user can reach the other's files unless explicitly listed by absolute path.

### AC-1.8 — Job Object kills descendants on parent exit
**Given** a sandboxed process has spawned child processes,
**When** `saife.exe` (the supervisor) exits — normally or via `Ctrl-C`,
**Then** all descendant processes are terminated by the Job Object
(`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`) within 1 second, leaving no orphans.

### AC-1.9 — Setup check fails fast on unsupported OS
**Given** `saife` is run on Windows 10 build 15063 (pre-1709),
**When** the user runs `saife run -- …`,
**Then** the command exits non-zero with a clear error message: *"AppContainer
RuleSet requires Windows 10 1709 (build 16299) or later. Detected build 15063."*
before any process is spawned.

### AC-1.10 — Init latency budget
**Given** a reference machine (SSD, 8 GB RAM, Win10 22H2),
**When** `saife run` is invoked,
**Then** the time from `saife.exe` entry to `CreateProcessW` returning is
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
**Given** two `saife run` invocations started concurrently in the same
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
session end) **unless** `saife persist <sid>` was called for that session,
in which case the tree has been moved to
`%USERPROFILE%\.saife\stores\<name>\` and `.sandbox\$SID\` no longer exists
in the workspace.

### AC-1.15 — `persist` promotes a session tree to a named store
**Given** a session `$SID` has installed tools in `.sandbox\$SID\bin\`,
**When** the user runs `saife persist $SID --as my-tools`,
**Then** the tree is moved to `%USERPROFILE%\.saife\stores\my-tools\` and
a manifest of file hashes is written at
`%USERPROFILE%\.saife\stores\my-tools\.manifest.json`. The original
`.sandbox\$SID\` is removed.

### AC-1.16 — `--reuse` runs a new session against a persisted store (read-only)
**Given** a persisted store `my-tools` exists,
**When** the user runs `saife run --reuse my-tools --allow-cwd -- cmd`,
**Then** the new session's install dirs alias to
`%USERPROFILE%\.saife\stores\my-tools\bin\` etc.; the sandboxed process
can read and execute tools from the store, but **cannot write to it** (writes
return `Access is denied`). The audit log records that the session reused
`my-tools`.

### AC-1.17 — `--reuse-rw` makes the store writable (single-writer)
**Given** a persisted store `my-tools` exists,
**When** the user runs `saife run --reuse-rw my-tools --allow-cwd -- cmd`,
**Then** the session can write new tools into the store (incremental
accumulation). If a second `--reuse-rw` against the same store is started
concurrently, it is denied with a clear error: *"store 'my-tools' is in
read-write use by session $SID_X; wait for it to finish or use --reuse
(read-only)."*. A `--reuse` (read-only) against a store currently in
`--reuse-rw` use is allowed (multiple readers, one writer).

### AC-1.18 — `--reuse` verifies the store manifest
**Given** a persisted store `my-tools` with a `.manifest.json`,
**When** the user runs `saife run --reuse my-tools -- …`,
**Then** `saife` recomputes the hash of every file in the store and
compares to the manifest. If any file has been tampered with externally,
`saife` exits non-zero with: *"store 'my-tools' manifest mismatch: file
'bin/jq.exe' hash differs from manifest"* — refusing to run the session
with a corrupted store.

## nono comparison

### What we match

- **`run` subcommand shape**: `saife run --profile X --allow-cwd -- <cmd>`
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
  tools. See `docs/design/critical-review.md` Option E.
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

## Known issues

> **Index** (cross-referenced to fixes in `docs/notes/future-ideas.md`):
>
> | KI | Status | Title | Fix / follow-up |
> |---|---|---|---|
> | KI-1.1 | Resolved | `cmd /c dir` fails (drive-root `GetVolumeInformationW`) | `setup --grant-drive-root`; general fix F-21 |
> | KI-1.2 | Open | PowerShell no-path commands resolve to `C:\` | F-21 (RuleSet) or F-22 (ancestor grants) |
> | KI-1.3 | Open | cmd `del`/`ren`/`rmdir` fail (RWX lacks DELETE bit) | add `DELETE`/`FILE_DELETE_CHILD` to RWX |
> | KI-1.4 | Open | `fc` / `where` / PATH search impaired | needs procmon; F-21 (System32 access) |
> | KI-1.5 | Open | `Get-Acl` / module autoloading impaired | F-21 (module-dir access) |
>
> Common-command survey results that informed these KIs are summarised in
> `docs/design/specs/us-1-run-agent-safely/spec.md` (KI-1.1 "What works/What fails"
> and the KI-1.2–1.5 reproduce blocks).

### KI-1.1 — `cmd /c dir` fails with "Access is denied" under `--allow-cwd`

**Status:** Resolved. Root cause confirmed by direct Win32 probing; fix
shipped as `saife setup --grant-drive-root` (one-time, elevated).

**Reproduce:**
```powershell
saife run --allow-cwd -- cmd /c dir
# -> "Zugriff verweigert" (Access is denied), exit 1
```

**What works:** `cmd /c echo works` succeeds. `cmd /c type <file-in-cwd>`
succeeds. `cmd /c mkdir`, `cmd /c copy`, `findstr`, `more`, `sort` succeed.
`.NET [System.IO.Directory]::EnumerateFileSystemEntries('.')` succeeds (so the
cwd grant is correct and directory enumeration itself works). `cmd /c dir /b`
(bare, no header) **also fails** — so the failure is not the volume-label
*display*.

**What fails:** `cmd /c dir` (any form: `dir`, `dir .`, `dir <abs-cwd>`,
`dir /b`, `dir marker.txt`), `cmd /c vol`, `cmd /c tree` (silent garbage).
PowerShell `Get-ChildItem` (no `-Path`) also fails, because
`InitializeDefaultDrives` enumerates `C:\` at startup.

**Confirmed root cause (probe-verified):**

A diagnostic binary (`src/bin/dirprobe.rs`) calls the suspect Win32 APIs in
turn under the sandbox:

```
PROBE FindFirstFileW(*) cwd                                  OK   0x00000000
PROBE FindFirstFileW(./*)                                    OK   0x00000000
PROBE FindFirstFileW(<abs-cwd>\*)                            OK   0x00000000
PROBE GetVolumeInformationW(C:\)                             FAIL 0x00000005   (ERROR_ACCESS_DENIED)
PROBE cwd is directory                                       OK   0x00000000
```

`cmd`'s `dir` builtin always calls `GetVolumeInformationW("C:\\")` (even with
`/b`) to read the volume label + serial. The AppContainer SID has no ACE on
`C:\` (deny-by-default), so the call returns `ERROR_ACCESS_DENIED` (0x5) and
`dir` aborts. `FindFirstFileW` on the cwd is **not** the problem — it succeeds
(the cwd's `(OI)(CI)(RX,W)` grant includes `FILE_LIST_DIRECTORY`).

`C:\` is owned by `NT SERVICE\TrustedInstaller`; writing a DACL ACE on it
requires `SeSecurityPrivilege` (admin). The per-directory-DACL mechanism used
by `run` therefore cannot grant the per-session AppContainer SID on `C:\`
unprivileged. `SeChangeNotifyPrivilege` (bypass traverse checking) is already
enabled in the child token, so ancestor traversal is **not** the issue — the
original KI-1.1 hypothesis ("ancestor traversal") was incomplete.

**Fix — `saife setup --grant-drive-root` (one-time, elevated):**

`saife setup --grant-drive-root` (run from an Administrator shell) grants
`S-1-15-2-2` (All RESTRICTED APPLICATION PACKAGES) `FILE_READ_ATTRIBUTES` on
every fixed drive root (`C:\`, `D:\`, …). `FILE_READ_ATTRIBUTES` is the
narrowest mask that satisfies `GetVolumeInformationW` — it does **not** include
`FILE_LIST_DIRECTORY`, so the AppContainer still cannot enumerate the drive
root's contents (only read volume metadata, which every unsandboxed user can
already do). The grant uses `S-1-15-2-2` (not the per-session SID) so it is
applied once and applies to every future session; the per-session SID would
require re-granting on every `run` and each grant needs elevation anyway.

`saife setup --check-only` reports the grant status:

```
Drive-root grant (KI-1.1)  : present on C:\
```

**Tests (TDD):**

- `S-40 (KI-1.1 cmd dir)` — `cmd /c dir` lists the cwd (incl. a known marker
  file). Skips cleanly when the drive-root grant is absent; passes once
  `setup --grant-drive-root` has been run.
- `S-41 (KI-1.1 PS gci)` — `Get-ChildItem -LiteralPath
  ([Environment]::CurrentDirectory)` lists the cwd. Uses the explicit-path
  form (the no-path form is blocked by PSDrive init walking ancestor dirs
  `C:\Users`, `C:\Users\<user>` which are SYSTEM/TrustedInstaller-owned and
  ungrantable unprivileged — a separate, harder limitation, see below).
- `S-42 (KI-1.1 sibling)` — regression guard: reading a sibling project's
  `.env` stays denied (the drive-root grant does **not** weaken isolation).

**Remaining limitation (not fixed by this change):**

PowerShell's `InitializeDefaultDrives` enumerates every drive root at startup
and `Set-Location` to the cwd walks ancestor directories (`C:\Users`,
`C:\Users\<user>`), which are SYSTEM-owned and cannot be granted unprivileged.
Consequences under the sandbox:

- `Get-Location` reports `C:\` (broken PSDrive location), not the real cwd.
- Relative paths in PowerShell resolve to `C:\`, not the cwd.
- `[Environment]::CurrentDirectory` IS correct (Win32 cwd is set properly).

Workaround: pass the cwd explicitly (`Get-ChildItem -LiteralPath <cwd>`,
`Get-Content <cwd>\file`, `Set-Location <cwd>` only works if ancestors are
grantable). The fully general fix for the no-path PowerShell form requires
either ancestor grants (admin, per-user — not a one-time drive-root grant) or
the kernel-level AppContainer RuleSet API (grants NT paths without DACL
writes); both are tracked as follow-ups — see KI-1.2 and `docs/notes/future-ideas.md`
F-21. `cmd /c dir` is the primary KI-1.1 complaint and is fully fixed by
`setup --grant-drive-root`.

**Severity:** Medium → Resolved (for `cmd /c dir`; PowerShell no-path form
remains a documented limitation, tracked as KI-1.2).

---

### KI-1.2 — PowerShell no-path commands resolve to `C:\` (broken PSDrive)

**Status:** Open. Surfaced during the KI-1.1 common-command survey (sub-agent
investigation of cmd + PowerShell builtins under `--allow-cwd`).

**Reproduce:**
```powershell
saife run --allow-cwd -- powershell -NoProfile -Command "Get-Location"
# -> Path: C:\   (expected: the real cwd)
saife run --allow-cwd -- powershell -NoProfile -Command "Get-ChildItem | Select-Object Name"
# -> lists C:\ contents (e.g. WINDOWS.~BT, XboxGames) — NOT the cwd
saife run --allow-cwd -- powershell -NoProfile -Command "Get-Content marker.txt"
# -> PathNotFound C:\marker.txt   (file exists in cwd; resolved against C:\)
```

**Root cause:** PowerShell's `InitializeDefaultDrives` enumerates every drive
root (`C:\`, `D:\`, …) at provider startup. When that fails (the AppContainer
SID has no ACE on `C:\` except the KI-1.1 `FILE_READ_ATTRIBUTES` grant, which
does not include `FILE_LIST_DIRECTORY`), the FileSystem provider's default
drive is left in a broken state and the location is pinned to `C:\`.
`Set-Location <cwd>` then fails because it walks ancestor directories
(`C:\Users`, `C:\Users\<user>`) which are SYSTEM/TrustedInstaller-owned and
ungrantable unprivileged. `[Environment]::CurrentDirectory` IS correct (the
Win32 cwd is set properly by `CreateProcessW`'s `lpCurrentDirectory`), but
PowerShell's PSDrive location is decoupled from it.

**What works:** explicit-path forms — `Get-ChildItem -LiteralPath
([Environment]::CurrentDirectory)`, `Get-Content <cwd>\file`, `env:` /
`variable:` / `function:` PSDrives, and all in-memory cmdlets (`1+1`,
`Get-Date`, `Get-Process`). See test S-41.

**What fails:** any relative path or no-path filesystem cmdlet — `Get-ChildItem`
(no path), `Get-Content marker.txt`, `Test-Path .`, `Set-Location ..`,
`New-Item newfile.txt`, `mkdir sub2` (silently no-ops or resolves to `C:\`).

**Fix options (both tracked as follow-ups):**

1. **Ancestor grants (admin, per-user)** — at `setup --grant-ancestors <cwd>`
   time, grant `S-1-15-2-2` `FILE_TRAVERSE` (traverse-only, no LIST, so
   sibling dir contents stay hidden) on each ancestor of a configured set of
   workspace roots up to the drive root. Requires admin (ancestors like
   `C:\Users`, `C:\Users\<user>` are SYSTEM-owned). Per-user, not one-time.
   Partial fix: `Set-Location` would succeed, but `InitializeDefaultDrives`
   enumerating `D:\`/`H:\` etc. may still warn.
2. **AppContainer RuleSet API** — replace/augment the per-directory-DACL
   mechanism with the kernel-level RuleSet that grants NT paths
   (`\Device\HarddiskVolume3\…`) without writing on the target's DACL. This
   unblocks `C:\` and ancestor access unprivileged. Architectural change;
   tracked as `docs/notes/future-ideas.md` F-21.

**Severity:** Medium. Workaround: pass the cwd explicitly. Agents that emit
PowerShell with relative paths will misbehave; agents using `cmd.exe` or
explicit paths are unaffected.

---

### KI-1.3 — cmd DELETE/RENAME operations fail (RWX grant lacks DELETE bit)

**Status:** Open. Surfaced during the KI-1.1 common-command survey.

**Reproduce:**
```powershell
saife run --allow-cwd -- cmd /c "echo x > file.txt"          # OK (write)
saife run --allow-cwd -- cmd /c "del file.txt"               # Access is denied
saife run --allow-cwd -- cmd /c "ren file.txt other.txt"     # Access is denied
saife run --allow-cwd -- cmd /c "rmdir sub"                  # Access is denied
```

**Root cause:** the cwd is granted `RWX = FILE_GENERIC_READ | FILE_GENERIC_WRITE
| FILE_GENERIC_EXECUTE`. `FILE_GENERIC_WRITE` for a directory includes
`FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY | ...` but **not** `FILE_DELETE_CHILD`
(the right to delete children from the directory), and for files it does not
include `DELETE` (the right to delete the file itself). `del`/`rmdir`/`ren`
need these bits. Reads, writes, and creates succeed; only delete/rename fail.

**Fix:** add `DELETE` (file) and `FILE_DELETE_CHILD` (dir) to the cwd grant's
access mask when the entry is read-write. The mask is computed in
`src/sandbox/allowlist.rs` (`RWX` constant); the `protected` per-session
subtree grants would also need it. Straightforward change; the reason it was
not done in the KI-1.1 pass is scope (KI-1.1 was the `dir` bug; this is a
separate, pre-existing gap surfaced by the survey).

**Severity:** Medium. `del`/`ren`/`rmdir` are common; agents hit them.
Workaround: use PowerShell `Remove-Item`/`Rename-Item` with an explicit path
(which goes through `CreateFileW` with `DELETE` and is governed by the file's
own DACL, where the inherited ACE does grant `DELETE` via `FILE_ALL_ACCESS`
on user-owned files — needs verification).

---

### KI-1.4 — `fc`, `where`, and PATH-based executable search impaired

**Status:** Open. Surfaced during the KI-1.1 common-command survey.

**Reproduce:**
```powershell
saife run --allow-cwd -- cmd /c "fc /b marker.txt marker.txt"
# -> FC: Kann MARKER.TXT nicht öffnen - Datei oder Ordner nicht vorhanden (exit 2)
saife run --allow-cwd -- cmd /c "where cmd"
# -> INFORMATION: Es konnten keine Dateien … gefunden werden (exit 1)
```

**Root cause (suspected, unconfirmed):**

- `fc` opens files with a share-deny or canonicalization path that the
  AppContainer token rejects as "not found" (distinct from `type`/`findstr`/
  `more`/`sort` which open the same file successfully). Needs procmon-level
  tracing to pin the exact access mask `fc` requests.
- `where` walks every `PATH` entry searching for the executable. The sandbox
  prepends `.sandbox\<sid>\bin` to `PATH` (correct), but `where cmd` then
  searches `C:\Windows\System32` (which the AC can read because it's
  world-readable, but `where`'s stat/open may hit a different access path) and
  reports nothing found. Likely related to `FindFirstFileW` on System32
  entries — the AC SID has no explicit ACE on System32 (the `System32` grant
  in `allowlist.rs` fails with Access Denied because `C:\Windows` is
  TrustedInstaller-owned), so the AppContainer relies on the world-readable
  inherited `Users:RX` ACE, which may not satisfy the restricting-SID check
  for the stat call `where` uses.

**Fix:** needs procmon diagnosis first to confirm the exact failing call.
Candidates: (a) grant the AC SID `FILE_READ_ATTRIBUTES` on `System32` (the
`grant_one` call already attempts this but fails on `C:\Windows` — same
TrustedInstaller problem as KI-1.1, fixable via `setup --grant-drive-root`'s
mechanism extended to `SystemRoot`), or (b) accept as documented limitation.

**Severity:** Low. `fc` is rarely used by agents; `where` has PowerShell
equivalents (`Get-Command`). Workaround: `Get-Command cmd` in PowerShell, or
`type`/`findstr` instead of `fc`.

---

### KI-1.5 — PowerShell `Get-Acl` and module autoloading impaired

**Status:** Open. Surfaced during the KI-1.1 common-command survey.

**Reproduce:**
```powershell
saife run --allow-cwd -- powershell -NoProfile -Command "Get-Acl marker.txt"
# -> CommandNotFoundException: Microsoft.PowerShell.Security module could not be autoloaded
```

**Root cause (suspected, unconfirmed):** the `Microsoft.PowerShell.Security`
module (which provides `Get-Acl`/`Set-Acl`) lives under
`C:\Windows\System32\WindowsPowerShell\v1.0\Modules\`. Autoloading it requires
enumerating that directory, which the AppContainer can't reach (no explicit
ACE; `System32` grant fails per KI-1.4). The module isn't pre-loaded with
`-NoProfile`, so the on-demand load fails.

**Fix:** same direction as KI-1.4 — grant `FILE_READ_ATTRIBUTES` (or RX) on
the PowerShell module directories, or pre-load the module in the sandbox env
block. Low priority; `Get-Acl` is rarely needed by agents inside the sandbox.

**Severity:** Low. Workaround: none inside the sandbox; run `Get-Acl` outside
if needed for inspection.
