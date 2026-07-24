# Spike: AppContainer + Option E (sanctioned install directories)

> **This is a SPIKE — a throwaway proof-of-concept.** It is not production
> code. It validates whether Windows AppContainer isolation can sandbox an
> open-ended agent that downloads and runs new binaries mid-session.

## What it does

`spike.exe` creates a per-session AppContainer profile, grants the
AppContainer SID read/write/execute access on a small set of sanctioned
directories (the Option E allow-list), and spawns a child process inside the
AppContainer + a kill-on-close Job Object.

The allow-list (hard-coded, per the spike plan):

| Path | Access | Purpose |
|------|--------|---------|
| `$CWD` | Read + Write | The project tree the agent works in |
| `$CWD\.sandbox` | Read + Write | The session install root |
| `$CWD\.sandbox\<sid>\bin` | Read + Write + Execute | Per-session install dir (downloaded binaries land here) |
| `$CWD\.sandbox\<sid>\venv` | Read + Write + Execute | Per-session Python venv |
| Python install dir (from PATH) | Read + Execute | System Python |
| `%SystemRoot%\System32` | Read + Execute | Minimum system binaries |
| `%SystemRoot%` | Read + Execute | `cmd.exe` etc. |

## Approach: AppContainer SID + per-directory DACLs

The spike uses `CreateAppContainerProfile` to mint a per-session AppContainer
SID, then spawns the child via `CreateProcessW` with
`PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES` (a `SECURITY_CAPABILITIES`
struct holding the AppContainer SID). This makes the kernel build the child's
token with the AppContainer SID as a restricting identity — the process is
**deny-by-default**: every securable object it touches must carry an explicit
Allow ACE naming the AppContainer SID.

Rather than driving the formal RuleSet/capability-SID `NtCreateFile` machinery
(which windows-rs exposes only awkwardly and which is designed for UWP
capability brokering, not arbitrary directory grants), we grant access the
direct way: for each allow-listed directory we set a DACL containing an Allow
ACE for the AppContainer SID with the requested mask
(Read/Write/Execute). This is exactly what `icacls /grant` does and what the
Add-AppxPackage-style setup does. The AppContainer SID is still a restricting
identity, so anything without an ACE is denied — the isolation guarantee is
the same as the formal RuleSet approach.

Access is granted via `SetEntriesInAclW` (merging with the existing DACL to
preserve access for the current user / SYSTEM / Administrators) +
`SetNamedSecurityInfoW` with `UNPROTECTED_DACL_SECURITY_INFORMATION` (so
inherited ACEs from the parent are kept).

## Build

```powershell
cargo build --release
```

The binary is at `target\release\spike.exe`.

## CLI

```
spike.exe run [--sid <id>] [--print-sid] [--reuse <name>] -- <cmd> [args...]
spike.exe persist <sid> --as <name>
spike.exe test
```

### `run`

- No `--sid`: generates a new 16-hex-char session id, creates the
  AppContainer profile, builds the per-session allow-list, creates
  `.sandbox\<sid>\bin\` and `.sandbox\<sid>\venv\` under `$CWD`, and spawns
  `<cmd>` under the AppContainer + Job Object. `PATH` is prepended with
  `.sandbox\<sid>\bin`.
- The **first line of stdout** is `SESSION <sid>` (for the test harness to
  capture). Then the child's stdout/stderr flow through unchanged. The child's
  exit code becomes spike's exit code.
- `--sid <id>`: reuses an existing session (re-derives its profile + ACLs).
- `--print-sid`: creates the session + dirs + profile, prints **only** `<sid>`
  to stdout, and exits 0 without spawning. (`-- <cmd>` may be present but is
  ignored.)
- `--reuse <name>`: **stubbed** — prints "not implemented in spike" and exits 1.
  (S-14 is optional per the spike plan.)

### `persist`

**Stubbed** — prints "not implemented in spike" and exits 1. (S-14 optional.)

### `test`

Shells out to `powershell -ExecutionPolicy Bypass -File tests/run-tests.ps1`.
If the harness file is missing, prints a friendly message and exits 0. (The
harness is written by another agent — this binary does not create it.)

## Run

From a temp directory (the test harness sets `$CWD` to a temp dir):

```powershell
# Basic: a sandboxed echo
spike.exe run -- cmd /c echo hello
# stdout:
#   SESSION 18c50bf9b4bee4e8
#   hello

# Print-only: create session + dirs, no spawn
spike.exe run --print-sid -- cmd /c echo init
# stdout:
#   18c50c0cdd7dd6e8
# creates .sandbox\<sid>\bin\ and .sandbox\<sid>\venv\
```

## Known gaps / caveats

- **`--reuse` and `persist` are stubbed** (S-14 is optional per the plan).
- **System32 / SystemRoot ACL grants fail** with Access Denied — we can't
  modify the DACL on system directories. This is fine: those directories are
  already world-readable, so the AppContainer child can access them without an
  explicit grant.
- **No profile cleanup on exit** — AppContainer profiles accumulate in the
  user's profile store. Re-running with the same `--sid` re-derives the
  existing SID rather than creating a duplicate.
- **No tests inside the crate** — this is a spike. The test harness
  (`tests/run-tests.ps1`) is written by another agent.
- `$CWD` is the current working directory of `spike.exe` (via
  `std::env::current_dir`), NOT the directory where `spike.exe` lives.
