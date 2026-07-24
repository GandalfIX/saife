# spike test harness

PowerShell harness that drives `spike.exe` through scenarios **S-1 … S-15**
defined in [`../docs/spike-appcontainer-option-e.md`](../../docs/spike-appcontainer-option-e.md).

> **S-6 is the gate.** If S-6 fails, the spike is FAIL regardless of other
> results. See "Pass / fail criteria" in the spike plan.

## Build first

The harness expects `spike.exe` at `..\target\release\spike.exe` (resolved
relative to this script). If that file is missing, the harness runs
`cargo build --release` in the spike dir automatically. To build manually:

```powershell
cd ..\..
cargo build --release   # from the spike dir (the one containing Cargo.toml)
```

## Run

```powershell
# Default: all scenarios, fresh temp CWD (auto-cleaned).
powershell -ExecutionPolicy Bypass -File run-tests.ps1

# PowerShell 7+:
pwsh -File run-tests.ps1
```

### Options

| Parameter      | Type      | Default                                   | Description                                                        |
|----------------|-----------|-------------------------------------------|-------------------------------------------------------------------|
| `-SpikeExe`    | string    | `..\target\release\spike.exe`             | Path to spike.exe. Built automatically if missing.                |
| `-Cwd`         | string    | `$env:TEMP\spike-<guid>` (created/cleaned) | Working directory. Harness owns/cleans it unless `-Keep`.         |
| `-Keep`        | switch    | off                                       | Retain the temp CWD for debugging.                                |
| `-Only`        | int[]     | all                                       | Run only the listed scenario numbers, e.g. `-Only 1,6,13`.        |
| `-Skip`        | int[]     | none                                      | Skip the listed scenario numbers.                                 |
| `-SkipOptional`| switch    | off                                       | Skip S-14 and S-15.                                               |
| `-StopOnFail`  | switch    | off                                       | Stop at the first failure.                                         |
| `-Strict`      | switch    | off                                       | Treat skips as failures (non-zero exit code).                     |

### Examples

```powershell
# Run only the gate test, keep the temp dir.
pwsh -File run-tests.ps1 -Only 6 -Keep

# Run everything except the python venv scenario, skip optional.
pwsh -File run-tests.ps1 -Skip 9 -SkipOptional

# Stop at first failure for fast triage.
pwsh -File run-tests.ps1 -StopOnFail
```

## Output

Per-scenario lines:

- `[PASS] S-N — <name>`
- `[FAIL] S-N — <name>: <detail>`
- `[SKIP] S-N — <name>: <reason>`
- `[INFO] S-N — <name>: <detail>`

Followed by a `Summary: total=N pass=N fail=N skip=N` line and a final
verdict:

- `SPIKE: PASS` — all required scenarios passed.
- `SPIKE: PASS (python scenarios skipped)` — required scenarios passed but
  S-8/S-9 were skipped because python was not on PATH. Surfaced as a
  prominent warning; not a hard failure.
- `SPIKE: FAIL` — a required scenario failed, or S-6 (the gate) failed.

**Exit code:** `0` on PASS, `1` on FAIL. Skips do not cause a non-zero exit
unless `-Strict` is passed.

## Scenario → plan mapping

| #   | Name                                                              | Role          |
|-----|-------------------------------------------------------------------|---------------|
| S-1 | Baseline: sandboxed process starts and exits                     | required      |
| S-2 | Disallowed file read is denied (core security property)           | required      |
| S-3 | Disallowed sibling project is denied                              | required      |
| S-4 | Allowed write to `$CWD` works                                     | required      |
| S-5 | Write to disallowed path is denied                                | required      |
| S-6 | **THE GATE: download binary into `.sandbox\<sid>\bin` & execute** | **gate**      |
| S-7 | Write into `.sandbox\<sid>\bin` works                             | required      |
| S-8 | Python from system install runs                                    | required*     |
| S-9 | Python venv in `.sandbox\<sid>\venv` works                        | required*     |
| S-10| Child inherits restrictions (depth 3)                              | required      |
| S-11| Job Object kills the whole tree on parent exit                    | required      |
| S-12| Breakaway is blocked                                              | deferred      |
| S-13| Parallel sessions get distinct install trees                     | required      |
| S-14| `persist` / `reuse` smoke test                                    | optional      |
| S-15| UI application launches under AppContainer                        | informational |

\* S-8/S-9 are skipped (not failed) when python is absent from PATH; the
verdict becomes `SPIKE: PASS (python scenarios skipped)`.

## Notes

- Each scenario runs in its own per-scenario subdir `S-N` under `$CWD` to
  avoid cross-scenario contamination.
- S-3 creates its `..\other-project\.env` fixture inline under the scenario
  parent dir; the `fixtures\other-project\.env` file in this repo is a
  reference copy and is not required at runtime.
- S-11 defensively kills stray `ping.exe` at start to avoid false positives
  from prior runs.
- The harness is PowerShell 5.1+ and 7+ compatible (uses `ProcessStartInfo`
  with `ArgumentList` via string array; avoids shell-isms).
