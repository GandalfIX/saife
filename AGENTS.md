# sandbox

`sandbox` is a native Windows process-sandboxing tool that runs any program —
primarily AI coding agents (Claude Code, OpenCode, Codex, …) and their build
toolchains — with only the resources the user has explicitly granted.

The goal is a Windows-native equivalent of [nono](https://nono.sh/), but
without WSL: pure Win32 / NT kernel primitives, a single unprivileged Rust
binary, no container runtime, no daemon, no VM.

## MVP pillars

1. **Filesystem isolation** — irrevocable, kernel-enforced allow-lists
   (AppContainer + RuleSet).
2. **Audit trail** — tamper-evident Merkle-tree log of every operation,
   signed with an Ed25519 key.
3. **Network filtering** — default-deny outbound network with a domain
   allow-list, enforced by a localhost reverse proxy the sandboxed process
   is restricted to.

Out of scope for the MVP: undo/rollback, credential injection, ghost sessions,
runtime supervisor, Sigstore provenance, GUI/TUI, multi-user mode.

See `docs/prd/prd-sandbox.md` for the full product requirements and
`docs/critical-review.md` for a critical review of the chosen mechanism.

## Testing

Must follow: If a test needs to change anything on the host system, like setting permissions, ACLs or similar, 
before the change is performed a "rollback script" needs to be written. 
So in case the test is killed and the cleanup cannot be performed the user is able to clean up manually.

**VM-first rule (2026-10-04):** Tests that change anything on the host (ACLs,
permissions, AppContainer profiles, network configuration) must be written to
run inside the disposable test VM via `tests/vm/Invoke-TestsInVM.ps1` — see
`docs/superpowers/plans/2026-10-04-vm-test-infrastructure.md`. For VM-run
tests, VM deletion is the rollback. For any test that still runs on the
physical host, the rollback-script rule above remains mandatory.

### ACL / ACE cleanup after every test run

The sandbox grants the per-session AppContainer SID access on the CWD and its
ancestor directories (e.g. `$env:TEMP`, `AppData\Local`) via
`SetNamedSecurityInfoW`. These ACEs **persist on the host** after the sandbox
exits — they are never removed automatically. Over many test runs they
accumulate until the ACL on the ancestor directory becomes so large that
`SetNamedSecurityInfoW` / `GetNamedSecurityInfoW` hangs (observed at ~40+ ACEs
on `AppData\Local`, causing `sandbox run --block-net` to deadlock in
`grant_access`).

**Rule:** every test run that exercises `sandbox run` (or anything that calls
`grant_access` / `build_allowlist`) MUST clean up the ACEs it created
afterwards. Two complementary mechanisms:

1. **Per-session cleanup (Rust):** `sandbox run` should remove the ACEs it
   added to the CWD ancestor directories on exit (after the child process
   returns, before the supervisor exits). The per-session `.sandbox\<sid>`
   directory is also removed. This is the primary defense — it runs
   automatically. *(Not yet implemented; tracked as a follow-up.)*
2. **Test harness cleanup (PowerShell):** `tests/run-tests.ps1` must, after the
   suite completes (on success OR failure), remove any `S-1-15-2-*`
   (AppContainer) ACEs that the run added to `$env:TEMP`, `AppData\Local`, and
   the user profile root. The cleanup runs in a `finally` block so it executes
   even if the harness is killed with Ctrl-C. A standalone cleanup script
   (`tests/cleanup-acls.ps1`) is also provided so a user can manually recover
   from a killed run.

**Before running the test harness**, verify the ancestor ACLs are not already
bloated:
```powershell
(icacls $env:TEMP | Select-String "S-1-15-2").Count
```
If the count is > 10, run `.\tests\cleanup-acls.ps1` first.
