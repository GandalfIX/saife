# Spike: AppContainer + RuleSet + Option E (sanctioned install dirs)

> **Status:** Planned. Gates the PRD mechanism choice (AppContainer vs.
> write-restricted token).
>
> **Goal:** Answer one question with working code: *can a sandboxed process,
> running under an AppContainer + RuleSet that grants `Read/Write/Execute`
> on `.sandbox/<sid>/bin/` and `$CWD` and `Read/Execute` on the system
> Python install, download a new binary into `.sandbox/<sid>/bin/` and
> execute it — while being denied access to `$HOME\.ssh` and other
> non-allow-listed paths?*
>
> **Per-session model (DECISION 2026-07-23):** install roots are scoped by
> session id: `.sandbox/<session-id>/bin/`, `.sandbox/<sid>/venv/`, etc.
> Two concurrent agents get distinct trees — no races, no cross-session
> poisoning. The spike must validate this. Caching is opt-in via
> `persist`/`reuse` (out of scope for this spike — the spike tests the
> per-session isolation only).

## Why this spike exists

The critical review (`../critical-review.md` CR-1) found that OpenAI
evaluated and rejected AppContainer for the Codex Windows sandbox because
*"AppContainer is a capability-based isolation model for apps that know up
front exactly what they need to access… Codex is not a single,
narrowly-scoped app."*

Option E (constrained-open-ended via sanctioned install directories) is our
answer: the profile enumerates *directories*, not *tools*, so the agent can
install arbitrary binaries mid-session into `.sandbox/bin/` and run them
without re-profiling. **This spike tests whether AppContainer actually
permits that workflow** — whether a binary downloaded at runtime into a
RuleSet-allowed directory can be executed by the sandboxed process.

If the spike succeeds → AppContainer + Option E is the MVP mechanism (no
admin for the sandbox itself; admin only for setup of users/firewall per
OQ-2). If the spike fails → fall back to Option A (OpenAI's write-restricted
token composition) with the Option E directory model layered on top.

## Scope

**In scope for the spike:**

- A minimal Rust binary (`spike.exe`) that:
  1. Creates an AppContainer profile with a per-session SID.
  2. Builds a RuleSet granting:
      - `Read | Write | Execute` on `$CWD\.sandbox\<sid>\bin\`
     - `Read | Write` on `$CWD` (the project tree)
     - `Read | Execute` on the system Python install dir (resolved from
       `python.exe` on `PATH`)
     - `Read` on `%SystemRoot%\System32` (minimum to start)
  3. Spawns a child process under the AppContainer token + a Job Object
     (`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`).
  4. Passes the child a `PATH` prepended with `.sandbox\bin`.
- A test script (PowerShell) that drives the spike and asserts outcomes.

**Out of scope for the spike:**

- Network filtering (US-3) — no proxy, no firewall. The spike binary has no
  network code.
- Audit trail (US-4) — no ETW, no log.
- Profiles (US-5) — the allow-list is hard-coded in the spike binary.
- Credential injection, ghost sessions, runtime supervisor — all out of
  scope.
- The OpenAI composition (write-restricted token + dedicated users) — this
  spike tests AppContainer only. If it fails, a second spike for the
  OpenAI composition is triggered.

## Test scenarios

Each scenario is a PowerShell snippet the test script runs and asserts on.

The spike prints the session id on the first stdout line of `spike.exe run`
(in the format `SESSION <sid>`); test scripts capture it with
`$sid = (spike.exe run -- … | Select-Object -First 1).Split(' ')[1]` so they
can reference the per-session install dir. (Or `spike.exe run --print-sid …`
prints only the sid and exits before running the command — useful for
setup-only invocations. The test harness uses whichever is convenient.)

### S-1 — Baseline: sandboxed process starts and exits

```powershell
# Arrange: $CWD is a temp dir; spike creates .sandbox\<sid>\bin\ on launch
spike.exe run -- cmd /c echo hello
# Assert: exit code 0, stdout contains "hello"
```

### S-2 — Disallowed file read is denied (the core security property)

```powershell
spike.exe run -- cmd /c type $env:USERPROFILE\.ssh\id_rsa
# Assert: exit code non-zero, stderr contains "Access is denied"
```

### S-3 — Disallowed sibling project is denied

```powershell
spike.exe run -- cmd /c type ..\other-project\.env
# Assert: exit code non-zero, stderr contains "Access is denied"
```

### S-4 — Allowed write to $CWD works

```powershell
spike.exe run -- cmd /c echo test > new-file.txt
# Assert: file exists on disk, content is "test"
```

### S-5 — Write to disallowed path is denied

```powershell
spike.exe run -- cmd /c echo bad > $env:USERPROFILE\.ssh\evil.txt
# Assert: exit code non-zero, stderr "Access is denied", file does not exist
```

### S-6 — THE GATE TEST: download a binary into .sandbox\<sid>\bin and execute it

This is the scenario that decides whether AppContainer + Option E is viable.

```powershell
# Capture the session id so the test can reference the per-session dir.
$sid = (spike.exe run --print-sid -- cmd /c echo init).Trim()

# The sandboxed process "downloads" a binary by copying from a readable
# source (here, a system binary) into its per-session install dir.
spike.exe run --sid $sid -- cmd /c copy C:\Windows\System32\where.exe .sandbox\$sid\bin\where.exe
# Assert: exit code 0, .sandbox\$sid\bin\where.exe exists

# Now execute the newly-installed binary from within the same session:
spike.exe run --sid $sid -- cmd /c .sandbox\$sid\bin\where.exe cmd
# Assert: exit code 0, stdout contains "C:\Windows\System32\cmd.exe"
# THIS IS THE DECISIVE ASSERTION. If this passes, AppContainer + Option E
# works: a binary placed into a RuleSet-allowed per-session dir at runtime
# is executable.
```

> Note: in the spike, `--sid <id>` reuses a session (its install dir + RuleSet).
> In the real product this is the `--reuse` mechanism; the spike exposes it
> as `--sid` for test convenience.

### S-7 — Write into .sandbox\<sid>\bin works

```powershell
$sid = (spike.exe run --print-sid -- cmd /c echo init).Trim()
spike.exe run --sid $sid -- cmd /c echo test > .sandbox\$sid\bin\marker.txt
# Assert: file exists
```

### S-8 — Python from system install runs (security-group model)

```powershell
spike.exe run -- python -c "print('hello from python')"
# Assert: exit code 0, stdout contains "hello from python"
```

### S-9 — Python venv created in .sandbox\<sid>\venv works

```powershell
$sid = (spike.exe run --print-sid -- cmd /c echo init).Trim()
spike.exe run --sid $sid -- python -m venv .sandbox\$sid\venv
spike.exe run --sid $sid -- cmd /c .sandbox\$sid\venv\Scripts\python.exe -c "print('venv works')"
# Assert: exit code 0, stdout contains "venv works"
# Tests that the agent can install a per-session Python environment and
# run it, exercising the Option E model for runtime-specific tool dirs.
```

### S-10 — Child process inherits restrictions (depth 3)

```powershell
spike.exe run -- cmd /c cmd /c cmd /c type $env:USERPROFILE\.ssh\id_rsa
# Assert: exit code non-zero, stderr "Access is denied"
# Proves inheritance to depth 3 — the key US-2 property.
```

### S-11 — Job Object kills the whole tree on parent exit

```powershell
# Start a sandboxed process that spawns a long-running child
$proc = Start-Process spike.exe -ArgumentList "run","--","cmd","/c","ping -t 127.0.0.1" -PassThru
Start-Sleep -Seconds 1
# Kill the spike.exe supervisor
Stop-Process -Id $proc.Id -Force
Start-Sleep -Seconds 1
# Assert: no ping.exe is still running (Get-Process ping -ErrorAction SilentlyContinue is null)
```

### S-12 — Breakaway is blocked

```powershell
# This requires a child that tries CREATE_BREAKAWAY_FROM_JOB. A simple test:
# use a small Rust/C# helper that calls CreateProcessW with the flag and
# reports the error code. For the spike, document the expected outcome:
# ERROR_ACCESS_DENIED (5). Deferred to a dedicated test binary in the spike
# repo; not a PowerShell one-liner.
```

### S-13 — Parallel sessions get distinct install trees (per-session isolation)

This validates the DECISION 2026-07-23: two concurrent sandboxed processes
in the same `$CWD` must not share install dirs.

```powershell
# Start two sessions in the same $CWD and capture their sids.
$sidA = (spike.exe run --print-sid -- cmd /c echo init).Trim()
$sidB = (spike.exe run --print-sid -- cmd /c echo init).Trim()

# Assert: $sidA -ne $sidB (distinct session ids)

# Session A installs a binary; session B does not see it.
spike.exe run --sid $sidA -- cmd /c copy C:\Windows\System32\where.exe .sandbox\$sidA\bin\where.exe

# Assert: .sandbox\$sidA\bin\where.exe exists
# Assert: .sandbox\$sidB\bin\where.exe does NOT exist (B's tree is empty)
# Assert: .sandbox\$sidB\bin\ directory exists but is empty

# Session B cannot read session A's install dir (it's not on B's allow-list).
spike.exe run --sid $sidB -- cmd /c type .sandbox\$sidA\bin\where.exe
# Assert: exit code non-zero, stderr "Access is denied"
# (Critical: proves per-session isolation is enforced by the RuleSet, not
# just by convention. A cannot poison B's PATH; B cannot read A's tools.)
```

### S-14 — `persist` / `reuse` smoke test (caching, optional for spike)

Optional — the `persist`/`reuse` mechanism is full-product work, but a
smoke test confirms the path-aliasing works.

```powershell
$sid = (spike.exe run --print-sid -- cmd /c echo init).Trim()
spike.exe run --sid $sid -- cmd /c copy C:\Windows\System32\where.exe .sandbox\$sid\bin\where.exe
spike.exe persist $sid --as my-tools
# Assert: %USERPROFILE%\.sandbox\stores\my-tools\bin\where.exe exists

# New session reuses the persisted store (read-only by default).
$sid2 = (spike.exe run --print-sid --reuse my-tools -- cmd /c echo init).Trim()
spike.exe run --sid $sid2 --reuse my-tools -- cmd /c .sandbox\$sid2\bin\where.exe cmd
# NOTE: with --reuse, the per-session bin dir IS the store dir (aliased).
# Assert: exit code 0, stdout contains "C:\Windows\System32\cmd.exe"
# (The reused binary runs even though session 2 never installed it.)

# --reuse is read-only: writes to the store are denied.
spike.exe run --sid $sid2 --reuse my-tools -- cmd /c echo bad > .sandbox\$sid2\bin\evil.txt
# Assert: exit code non-zero, stderr "Access is denied", file does not exist
```

### S-15 — UI application launches under AppContainer (informational)

> **Not a gate test.** The MVP targets CLI/console apps; UI is best-effort.
> This scenario documents what happens when a GUI app runs under the
> spike's AppContainer, so we know whether to mark UI as supported,
> partial, or post-MVP.

AppContainer was designed for UWP/Store apps (which are UI), so windows
*should* display. The unknowns for our use case are: (a) does a plain
desktop `.exe` launched via `CreateProcessW` + AppContainer SID display its
window at all, (b) does input work, (c) which cross-process window/clipboard
interactions fail. See
[AppContainer isolation docs — Window isolation](https://learn.microsoft.com/en-us/windows/win32/secauthz/appcontainer-isolation).

```powershell
# Launch a trivial GUI app under the spike and observe.
spike.exe run -- notepad.exe
# Manual assertions (operator observes, then records in RESULTS.md):
#   - Does a Notepad window appear?                       [ ] yes  [ ] no
#   - Can you type into it?                               [ ] yes  [ ] no
#   - Can you close it normally (Alt+F4 / X button)?      [ ] yes  [ ] no
#   - Does the spike's Job Object kill it on Ctrl-C?      [ ] yes  [ ] no

# Repeat with a slightly richer GUI app (e.g. a tiny WinForms/WPF
# hello-world.exe placed in .sandbox\<sid>\bin\, or a system binary
# like msinfo32.exe) to confirm the notepad result isn't a fluke.
spike.exe run -- msinfo32.exe
#   - Window appears and is interactive?                   [ ] yes  [ ] no
```

**Recording outcomes** (fill into `RESULTS.md`):

- If windows appear and are interactive: mark UI as **best-effort
  supported** in the PRD; do not add UI capability flags yet; document that
  clipboard/drag-drop/cross-process `HWND` interactions *may* fail.
- If windows do not appear, or appear but are non-interactive: mark UI as
  **post-MVP**; document the failure mode; the MVP remains CLI-only.
- Either way, this scenario does **not** affect the pass/fail of the spike
  (the gate is S-6). It only informs the PRD's UI positioning.

## Pass / fail criteria

The spike **PASSES** if all of the following hold:

- S-1, S-3, S-4, S-5, S-7, S-8, S-10, S-11 pass (the baseline FS +
  inheritance + Job Object properties).
- **S-6 passes** (the gate test: a binary downloaded at runtime into
  `.sandbox\<sid>\bin\` is executable).
- S-9 passes (the venv scenario: a runtime-specific per-session dir works).
- **S-13 passes** (per-session isolation: two sessions get distinct trees
  and cannot read each other's install dirs).
- S-14 is optional but should pass if implemented; if `persist`/`reuse` is
  deferred from the spike, mark it N/A.
- S-15 is **informational only** — it does not affect pass/fail. It records
  whether UI apps work under AppContainer, to inform the PRD's UI
  positioning. Either outcome is acceptable; the gate is S-6.

The spike **FAILS** if S-6 fails — meaning AppContainer refuses to execute
a binary placed into a RuleSet-allowed directory at runtime, even though the
directory has `Execute` capability. This would confirm OpenAI's finding that
AppContainer does not fit the open-ended-binary workload, and we pivot to
Option A.

Failure of S-2 (the security property) is a separate, harder failure — it
would mean the AppContainer RuleSet isn't enforcing default-deny at all. If
this happens, stop and investigate the RuleSet construction; the spike code
is buggy, not the approach.

## Spike implementation plan

### Phase 0 — Project skeleton (≈ 1h)

1. `cargo init --name spike` in `sandbox/spike/`.
2. Add `windows` crate (windows-rs) with features:
   `Win32_Foundation`, `Win32_Security_AppContainer`,
   `Win32_Security_Authorization`, `Win32_System_JobObjects`,
   `Win32_System_Threading`, `Win32_Storage_FileSystem`.
3. Add `clap` for the `run` subcommand.
4. `cargo build` — confirm it links.

### Phase 1 — AppContainer profile + RuleSet (≈ 1 day)

1. Implement `create_app_container_profile(sid, display_name, description)`
   using `CreateAppContainerProfile`.
2. Implement `build_ruleset(allow_list)` using
   `CreateAppContainerProfileCapabilities` / the RuleSet API
   (`NtCreateFile`-style capability rules). Reference the
   [Microsoft AppContainer isolation docs](https://learn.microsoft.com/en-us/windows/win32/secauthz/appcontainer-isolation).
3. Resolve the allow-list entries to NT paths (`C:\foo` →
   `\Device\HarddiskVolume3\foo` via `QueryDosDevice`).
4. Hard-code the Option E allow-list (the per-session dir patterns
   `.sandbox\<sid>\bin\`, `.sandbox\<sid>\venv\`, etc., with `<sid>` filled
   from the session id at spawn time).

### Phase 2 — Token + spawn (≈ 0.5 day)

1. `CreateProcessW` with the AppContainer token, `EXTENDED_STARTUPINFO_PRESENT`,
   `PROC_THREAD_ATTRIBUTE_JOB_LIST`.
2. Create the Job Object with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, no
   `BREAKAWAY_OK`.
3. Set the child's `PATH` env var to
   `.sandbox\<sid>\bin;<system PATH>` (and the runtime-specific subdirs).
4. Verify S-1 (echo hello) works.

### Phase 3 — Test harness (≈ 0.5 day)

1. Write `spike/tests/run-tests.ps1` with all S-1…S-13 scenarios (S-14
   optional).
2. Each scenario sets up a temp `$CWD`, runs `spike.exe`, asserts.
3. `spike test` subcommand runs the PowerShell script and reports PASS/FAIL
   per scenario.

### Phase 4 — Run the gate test (≈ 0.5 day)

1. Run S-6 specifically. Capture the exact result.
2. If S-6 passes → run the full suite, document results, mark the spike
   PASSED. Update the PRD to confirm AppContainer + Option E.
3. If S-6 fails → capture the exact error code and message. Investigate
   whether a different RuleSet capability flag fixes it. If not after 0.5
   day of investigation, mark the spike FAILED and trigger the Option A
   fallback spike.

### Phase 5 — Document the outcome (≈ 0.25 day)

1. Write `spike/RESULTS.md` with: pass/fail per scenario, exact error codes
   on any failure, the decision (AppContainer + Option E confirmed, or
   pivot to Option A).
2. Update `docs/design/critical-review.md` Recommendation with the outcome.
3. If PASSED: update `docs/design/prd/prd-sandbox.md` FR-2 to reflect Option E
   sanctioned directories and confirm AppContainer.
4. If FAILED: write a second spike plan for Option A (write-restricted
   token + dedicated users + firewall) with the Option E directory model
   layered on top.

**Estimated total: 3–4 days.**

## Spike deliverables

```
sandbox/spike/
  Cargo.toml
  README.md            # how to build and run
  RESULTS.md           # filled in at Phase 5
  src/
    main.rs            # clap entry, run subcommand
    appcontainer.rs    # profile + SID + RuleSet
    job.rs             # Job Object
    spawn.rs           # CreateProcessW + env transform
    allowlist.rs       # Option E hard-coded allow-list + path resolution
  tests/
    run-tests.ps1      # S-1 … S-11
    fixtures/
      hello.exe        # tiny test binary (or use where.exe copy)
```

## What the spike does NOT decide

- **Network filtering mechanism** — the spike has no network code. If
  AppContainer is confirmed, the network design from US-3 (AppContainer
  network cap + loopback exemption + localhost proxy) proceeds as written.
  If we pivot to Option A, network is Windows firewall matched to the
  dedicated user principal (per OpenAI's design).
- **Audit fidelity** — the spike has no audit. The ETW-vs-hook two-tier
  design (US-4) proceeds independently.
- **Profile format** — the spike hard-codes the allow-list. The US-5
  profile format is unaffected, except: per the CR-10 decision, the
  repo-local profile search path (`./.sandbox/profiles/`) is **dropped** —
  profiles live only in `%USERPROFILE%\.sandbox\profiles\`, outside the
  writable workspace.

## Decision tree

```
Run spike
  │
  ├─ S-6 PASSES → AppContainer + Option E confirmed
  │   → Update PRD FR-2 with sanctioned dirs
  │   → Proceed to MVP implementation
  │
  └─ S-6 FAILS → AppContainer rejected for this workload
      → Trigger Option A spike (write-restricted token + dedicated users)
      → Option E directory model layered on top (mechanism-agnostic)
      → Admin for setup (per OQ-2 decision)
```
