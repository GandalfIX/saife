# Spike: AppContainer + Option E (sanctioned install directories) — results

**Status: PASSED (2026-08). The spike's code was deleted 2026-10-24; this file is
its evidence.** The crate (`spike/`) was a throwaway proof-of-concept that
duplicated what the product now implements in `src/sandbox/`; keeping a second,
diverged copy invited it to be read as current code. The conclusion, the scenario
table and the caveats below are kept verbatim because they are the basis for the
Option E decision.

Design document: `docs/design/spike-appcontainer-option-e.md`.
Harness: `spike/tests/run-tests.ps1` drove `spike.exe` through S-1 … S-15 (deleted with the crate).

## What it validated

Whether Windows AppContainer isolation can sandbox an **open-ended** agent that
downloads and runs new binaries mid-session. `spike.exe` created a per-session
AppContainer profile, granted the AppContainer SID read/write/execute on a small
set of sanctioned directories (the Option E allow-list), and spawned a child
inside the AppContainer **and** a kill-on-close Job Object.

## How it was reproduced

```powershell
cd sandbox/spike                      # pre-move layout; the path is historical
cargo build --release
# Default (python may not be on PATH -> S-8/S-9 skipped):
pwsh -NoProfile -ExecutionPolicy Bypass -File tests/run-tests.ps1
# With python on PATH (exercises S-8/S-9):
$env:PATH = "<python-install-dir>;$env:PATH"
pwsh -NoProfile -ExecutionPolicy Bypass -File tests/run-tests.ps1
# Diagnostics from the spike binary (otherwise stderr is clean):
pwsh -NoProfile -ExecutionPolicy Bypass -File tests/run-tests.ps1 -Diag
```

Verified on Windows 11 (build 26100), PowerShell 7, rustc 1.94, `windows` crate
0.62. Machine locale de-DE (denial text is "Zugriff verweigert"; the harness
accepts localized forms).

## Scenarios

| Scenario | Description | Expected | Result | Notes |
|----------|-------------|----------|--------|-------|
| S-1 | Baseline: sandboxed process starts and exits | exit 0, stdout "hello" | **PASS** | `cmd /c echo hello` runs under AppContainer. |
| S-2 | Disallowed file read is denied | exit non-zero, stderr denial text | **PASS** | `.ssh\id_rsa` blocked by AppContainer deny-by-default. |
| S-3 | Disallowed sibling project is denied | exit non-zero, stderr denial text | **PASS** | `..\other-project\.env` outside `$CWD` allow-list. |
| S-4 | Allowed write to $CWD works | file exists, content "test" | **PASS** | |
| S-5 | Write to disallowed path is denied | exit non-zero, denial, file absent | **PASS** | `.ssh\evil.txt` not created. |
| S-6 | **GATE TEST**: download a binary into `.sandbox\<sid>\bin` and execute it | exit 0, binary runs | **PASS** | Uses `hostname.exe` (the plan's `where.exe cmd` walks PATH into non-allow-listed dirs and fails spuriously; `hostname.exe` runs standalone and proves the same property). A system binary copied into the per-session dir at runtime is executed by the AppContainer process. |
| S-7 | Write into `.sandbox\<sid>\bin` works | file exists | **PASS** | |
| S-8 | Python from system install runs | exit 0, stdout "hello from python" | **PASS** (when python on PATH) / **SKIP** (default) | Passes with `python.exe` on PATH. The allow-list grants RX on the python install dir. (The plan notes S-8 fails if python is absent.) |
| S-9 | Python venv created in `.sandbox\<sid>\venv` works | exit 0, stdout "venv works" | **FAIL** (with python) / **SKIP** (default) | `python -m venv` creates the venv tree but `ensurepip` fails: the venv's `Scripts\python.exe` cannot fully resolve the source python install (the test machine's python is a uv-managed install with a launcher shim that prints "Failed to find real location of python.exe"). This is a property of the specific python install layout, not a fundamental AppContainer limitation — S-8 proves the python install dir grant works for direct execution. A standard CPython install would likely pass. |
| S-10 | Child process inherits restrictions (depth 3) | exit non-zero, denial | **PASS** | `cmd /c cmd /c cmd /c type …\id_rsa` denied at depth 3. |
| S-11 | Job Object kills the whole tree on parent exit | no `ping.exe` remains | **PASS** | `KILL_ON_JOB_CLOSE` confirmed. |
| S-12 | Breakaway is blocked | ERROR_ACCESS_DENIED | **SKIP** | Deferred — requires a dedicated helper binary that calls `CreateProcessW` with `CREATE_BREAKAWAY_FROM_JOB`. The Job Object does NOT set `BREAKAWAY_OK`, so breakaway is expected to be denied; not exercised in the spike. |
| S-13 | Parallel sessions get distinct install trees | distinct sids; B cannot read A's dir | **PASS** | Two sessions in the same `$CWD` get distinct sids; A installs a binary; B's `.sandbox\<sidB>\bin` is empty; B is denied read of A's `.sandbox\<sidA>\bin`. Isolation enforced via PROTECTED_DACL on the per-session subtree so the broad `$CWD` Allow does not leak into sibling session dirs. |
| S-14 | persist / reuse smoke test (optional) | persisted binary runs from a new session | **N/A** | Stubbed in the spike (`--reuse`/`persist` print "not implemented in spike"). S-14 is optional per the plan. |
| S-15 | UI application launches under AppContainer (informational) | manual observation | **SKIP** | Manual checklist printed by the harness; operator observation not recorded. Does not affect pass/fail. |

## Decision

**AppContainer + Option E is confirmed as the MVP mechanism.**

- **S-6 PASSES** → a binary placed into a RuleSet-allowed per-session directory at
  runtime is executable. AppContainer does NOT refuse the open-ended-binary
  workload (the concern raised in `critical-review.md` CR-1). The Option E
  "sanctioned install directories" model works: the profile enumerates
  *directories*, not *tools*, so the agent can install arbitrary binaries
  mid-session into `.sandbox\<sid>\bin\` and run them without re-profiling.
- **S-13 PASSES** → per-session isolation is enforceable: two concurrent sessions
  in the same `$CWD` get distinct install trees and cannot read each other's
  `.sandbox\<sid>` directories (DECISION 2026-07-23 validated).
- **S-2/S-3/S-5/S-10 PASS** → the core security property (deny-by-default for
  non-allow-listed paths, including `$HOME\.ssh` and sibling projects, inherited
  by child processes to depth 3) holds.
- **S-11 PASSES** → Job Object `KILL_ON_JOB_CLOSE` kills the whole tree on parent
  exit (US-2 property).

### Caveats / follow-ups for the MVP

1. **RuleSet mechanism:** the spike grants access via per-directory DACLs (Allow
   ACEs for the AppContainer SID) rather than the formal AppContainer
   capability-RuleSet (`NtCreateFile` capability rules). The DACL approach is what
   `icacls /grant` and Add-AppxPackage-style setup do; the AppContainer SID is
   still a restricting identity (deny-by-default), so the isolation guarantee is
   equivalent. The MVP may keep this approach or adopt the formal RuleSet API —
   either works.
2. **Per-session isolation implementation:** achieved with
   `PROTECTED_DACL_SECURITY_INFORMATION` on `.sandbox\<sid>\*` so the broad `$CWD`
   Allow does not inherit into sibling session subtrees. The per-session subtree's
   DACL explicitly grants Full Control to the owner (user), SYSTEM,
   Administrators, and RWX to the owning AppContainer SID.
3. **S-9 (venv):** investigate with a standard CPython install (not a uv shim)
   before treating venv creation as supported. The spike did not block on this
   because S-8 (direct python execution) passes and S-9 is not the gate.
4. **System32/SystemRoot ACL grants fail** on the test machine (cannot write DACLs
   on system dirs) — harmless because those dirs are world-readable/executable, so
   the AppContainer child accesses them without an explicit grant. The MVP should
   grant via the formal RuleSet or rely on the default world-read.
5. **`whoami /groups` does NOT show AppContainer SIDs** — they live in
   `TokenAppContainerSid`, not `TokenGroups`. Verified via
   `GetTokenInformation(TokenIsAppContainer)` = 1. Do not use `whoami /groups` to
   check for AppContainer identity.
6. **`--reuse` / `persist`** are stubbed (S-14 optional). Full persist/reuse
   (caching) is product work, not spike work.

### Per the spike plan's decision tree

```
S-6 PASSES -> AppContainer + Option E confirmed
  -> Update PRD FR-2 with sanctioned dirs
  -> Proceed to MVP implementation
```

No second spike (Option A) was triggered.

## Verification commands (as recorded)

- AppContainer identity check (authoritative): the spike binary set
  `TokenIsAppContainer = 1` on the child (verified during debugging via
  `GetTokenInformation` on the child token; not exposed as a CLI command).
- Full harness output (default, python absent):
  `Summary: total=15 pass=10 fail=0 skip=5` / `SPIKE: PASS (python scenarios skipped)`
- Full harness output (python on PATH): `[PASS] S-8`, `[FAIL] S-9: venv create
  failed exit=1 pyExists=True (uv-shim python; see Notes)`.

## Where the live implementation is

`src/sandbox/appcontainer.rs`, `src/sandbox/allowlist.rs`, `src/sandbox/job.rs`,
`src/sandbox/spawn.rs` — the product's versions of the four modules the spike
prototyped, with the caveats above carried forward (see `docs/DEVELOPERS.md`).
