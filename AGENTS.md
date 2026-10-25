# sandbox

`saife` is a native Windows process-sandboxing tool that runs any program —
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

See `docs/design/prd/prd-sandbox.md` for the full product requirements and
`docs/design/critical-review.md` for a critical review of the chosen mechanism.

## Where to start

**`docs/DEVELOPERS.md`** is the architecture and workflow map: repository layout,
how a run works on both backends, the audit model, test gates, recipes for adding
a scenario/audit field/flag, and the invariants a change must keep. This file
holds the rules; that one holds the map.

## Backends, privileges and the default

Two containment backends, selected with `--backend`:

- **`mxc`** (the DEFAULT in every build since 2026-10-22; `mxc-backend` is a default feature) - the
  MXC `processcontainer` backend. **Network sessions run UNELEVATED**: the proxy
  is this process's own listener and the SDK gives the container no other route
  out. Guardrail 1 proves the child reached that listener before the session is
  reported successful.
- **`appcontainer`** - the original AppContainer supervisor. It stays the escape
  hatch for workloads whose client stack cannot use a proxy (**WinINet /
  PowerShell 5.1 / system-proxy apps**: they reach the proxy and never
  authenticate). Those sessions need administrator rights for the loopback
  exemption, so `--backend appcontainer` is the flag to reach for when a GUI
  tool has no egress.

A build WITHOUT the feature falls back to `mxc`'s absence loudly (it prints
`--backend appcontainer` is in use) rather than refusing to run. The default is
decided by `cli::default_backend(feature_enabled)`, not by a constant, because a
constant would name a backend a feature-less binary cannot execute.

**Guardrail 1 refusals are informative, not generic:** `proxy_probe_unmet` means
the child never reached this listener (blocked loopback, dead listener, wrong
credential); `workload_cannot_authenticate` means something DID reach it without
the run's credential and nothing in the session ever authenticated - the
WinINet/system-proxy class, whose remedy is `--backend appcontainer`.
`guardrail 1 proof probes=N accepted=N tunnels=N unauthenticated=N` is printed on
stderr for every successful session so the evidence is auditable.

Session deadlines are supervisor arithmetic, not a caller value:
`promptTimeoutSecs + workloadTimeoutSecs + slack` (profile top-level `limits`
section; defaults 60 s + 30 min + 2 min). Moved 2026-10-25: both keys used to be
`network.*`, and that location is now REFUSED. A workload that legitimately runs
longer must raise `limits.workloadTimeoutSecs` - there is no "no deadline" mode.

## Testing

Must follow: If a test needs to change anything on the host system, like setting permissions, ACLs or similar, 
before the change is performed a "rollback script" needs to be written. 
So in case the test is killed and the cleanup cannot be performed the user is able to clean up manually.

**VM-first rule (2026-10-04):** Tests that change anything on the host (ACLs,
permissions, AppContainer profiles, network configuration) must be written to
run inside the disposable test VM via `tests/vm/Invoke-TestsInVM.ps1` — see
`docs/plans/2026-10-04-vm-test-infrastructure.md`. For VM-run
tests, VM deletion is the rollback. For any test that still runs on the
physical host, the rollback-script rule above remains mandatory.

### Test lanes after the backend flip

- `tests/run-tests.ps1 -Backend appcontainer|mxc` selects the backend for every
  scenario (default `appcontainer`, so the recorded AC baseline stays
  reproducible). AppContainer-only scenarios SKIP with a named reason under
  `mxc`; they are listed in `$script:AppContainerOnlyScenarios`.
- The suite verdict is "any failure fails" - it does NOT consult a scenario
  allow-list any more (that list printed `PASS` over seven failures on
  2026-10-22).
- A VM session always runs with the GUEST's token, which is elevated. The VM
  therefore proves product logic, **not** elevation. The unelevated claim is
  carried by host live legs. The standard-user lane that would close this is
  PARKED (no non-interactive second-account launch works from a PS-Direct
  session) - see PROGRESS.md, "P3.1 blocker".
- Live (`#[ignore]`) legs execute `target/debug/saife.exe`, not the test
  binary: run `cargo build --features mxc-backend --bin saife` first or the
  kill-leg's freshness guard fails the lane.

### ACL / ACE cleanup after every test run

The sandbox grants the per-session AppContainer SID access on the CWD and its
ancestor directories (e.g. `$env:TEMP`, `AppData\Local`) via
`SetNamedSecurityInfoW`. These ACEs **persist on the host** after the sandbox
exits — they are never removed automatically. Over many test runs they
accumulate until the ACL on the ancestor directory becomes so large that
`SetNamedSecurityInfoW` / `GetNamedSecurityInfoW` hangs (observed at ~40+ ACEs
on `AppData\Local`, causing `saife run --block-net` to deadlock in
`grant_access`).

**Rule:** every test run that exercises `saife run` (or anything that calls
`grant_access` / `build_allowlist`) MUST clean up the ACEs it created
afterwards. Two complementary mechanisms:

1. **Per-session cleanup (Rust):** `saife run` should remove the ACEs it
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
