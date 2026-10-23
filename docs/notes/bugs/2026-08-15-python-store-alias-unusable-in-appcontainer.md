# BUG: Python Store alias unusable inside AppContainer — integration tests S-8/S-9/S-19/S-26/S-37 fail

> **Status:** Open
> **Reported:** 2026-08-15
> **Severity:** Low (test-only) — does not affect `saife run` functionality; only affects scenarios that invoke `python` inside the sandbox
> **Affects:** Integration test harness scenarios S-8, S-9, S-19, S-26, S-37

---

## Summary

Integration tests that invoke `python` inside the sandbox fail with exit code `9009` ("command not found") or `1`. The root cause is that `python` on the host PATH resolves to the **Microsoft Store Python alias** (`C:\Users\marku\AppData\Local\Microsoft\WindowsApps\python.exe`), which is a stub/redirector that opens the Microsoft Store instead of running Python. This stub does not work inside the AppContainer because it depends on Windows Shell/Store APIs that are blocked.

## Symptoms

```
[FAIL] S-8: exit=9009 stdout=
[FAIL] S-9: venv create failed exit=1 pyExists=False
[FAIL] S-19 (AC-2.9 py): exit=9009 stdout=
[FAIL] S-26 (AC-3.2): exit=9009 ...
[FAIL] S-37 (AC-3.13): exit=9009 ...
```

Exit code `9009` is Windows' "command not found" (STATUS_ILLEGAL_INSTRUCTION / cmd.exe's "command not recognized"). The Store alias prints (in German): *"Python wurde nicht gefunden; ohne Argumente ausfuhren, um aus dem Microsoft Store zu installieren..."*

## Environment

- Host Python: `C:\Users\marku\AppData\Local\Microsoft\WindowsApps\python.exe` (Store alias)
- Real Python 3.10.11 installed at `C:\Program Files\WindowsApps\PythonSoftwareFoundation.Python.3.10_3.10.3056.0_x64__qbz5n2kfra8p0`
- The Store alias is on PATH before the real install, so `Get-Command python` resolves to the alias.
- `python --version` works on the host (the alias redirects to the real install), but inside the AppContainer the redirect fails because the Store activation APIs are blocked.

## Root Cause

The sandbox's `build_env_block` inherits the host PATH. The AppContainer can execute `C:\Windows\System32\cmd.exe` (granted via the implicit System32 RX grant), and cmd resolves `python` via PATH. The first match is `WindowsApps\python.exe` — the Store alias. When cmd runs it, the alias tries to activate the Store app, which requires:

1. The `WindowsApps` directory to be accessible (it's under `AppData\Local\Microsoft`, which is NOT in the allowlist).
2. The Windows Shell/Store activation COM APIs, which are blocked in the AppContainer.

Result: the alias prints the "Python not found" message and exits `9009`/`1`.

## Why it's not an ADR-0001 concern

This is a **US-1/US-2 runtime resolution** issue (how the sandbox resolves interpreters on PATH inside the AppContainer), not a network hardening issue. It predates the ADR-0001 work and is unrelated to Phase 1 (D-0) or the ACL hang fix. The failing tests (S-8, S-9, S-19, S-26, S-37) all involve invoking `python`; non-Python tests pass.

## Potential fixes (not yet implemented)

1. **Prefer real installs over Store aliases** — when building the env block, reorder PATH so `C:\Program Files\*` Python entries come before `WindowsApps`. Requires the sandbox to detect Store aliases (check for the `MicrosoftWindowsApps` path segment) and either skip them or resolve to the real executable.

2. **Grant `WindowsApps` to the AppContainer** — add `C:\Users\marku\AppData\Local\Microsoft\WindowsApps` to the allowlist. This would let the alias run, but it may still fail on the Store activation COM APIs inside the AppContainer.

3. **Resolve the alias to the real executable** — before spawning, replace `python` in the cmdline with the full path to the real Python (`C:\Program Files\WindowsApps\PythonSoftwareFoundation.Python.3.10_...\python.exe`). This is the `security_groups.rs` approach already used for Node/Rust/Java runtimes — extend it to Python.

4. **Disable the Store alias** — the user can disable "App execution aliases" in Windows Settings > Apps > Advanced app settings > App execution aliases. This removes `WindowsApps\python.exe` from PATH. Not a code fix, but a workaround.

## Workaround

Disable the Python Store alias in Windows Settings, or run the integration harness with `Get-Python` returning the real Python path. The 5 failing scenarios can be skipped by ensuring `Get-Python` returns `$null` (the harness skips Python scenarios when Python is absent).

## Related artifacts

- Integration harness: `tests/run-tests.ps1` (S-8/S-9/S-19/S-26/S-37)
- Runtime resolution: `src/security_groups.rs` (Node/Rust/Java/Python resolution)
- Phase 1 progress: `docs/tasks/adr-0001/PROGRESS.md`
