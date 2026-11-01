# Manual QA — build runner (2026-11-01)

Branch `feat/gradle-build-runner`, PR #25. Not in any released build; this is the pass that
decides whether it can be.

Automated coverage at HEAD: 760 unit/integration tests, 30 ignored live legs, clippy clean in both
feature states, and two live session legs (needle: `docs/tasks/gradle-build-runner/PROGRESS.md`).
**Do not re-test what CI proves.** The cases below are the ones a machine cannot judge: a cold
machine, a real user's hands, Windows file behaviour, and the install path.

Run order matters: 1 → 9 build on each other; 10 → 14 are independent; 15 is the cleanup you must
not skip.

---

## Group A — a machine that has never built anything (the cold path)

### QA-01 · cold engine, no cache
1. Stop Rancher Desktop / Docker Desktop completely (`docker info` must fail).
2. `saife run --block-net --runner --allow-cwd -- cmd /c echo hi`
   - **expect**: `[saife] runner refused: …` and exit code `5` (`EXIT_RUNNER_REFUSED`). Not a hang,
     not a panic, not a silent success.
3. Start the engine. `saife runner status`
   - **expect**: `cache: saife-runner-cache  empty or not reported`, `image: eclipse-temurin@sha256:83f4…`,
     `slots: 0`.
4. `saife runner prewarm C:\Users\marku\projekte\temp\sample-gradle`
   - **expect**: it prints the fill banner, streams Gradle output, ends with `cache is now <N> MB`,
     exit `0`. On a cold link this takes **minutes, not seconds** — that is not a hang. If you kill
     it halfway, the next offline build fails naming one artifact (see QA-05) — that is the honest
     failure, not a bug.

### QA-02 · first build in a session
Same command shape as the live leg: from `C:\Users\marku\projekte\temp`, run
`saife run --block-net --runner --allow-cwd -- powershell -File <leg.ps1>` where the script POSTs
`{"project":"sample-gradle","task":"build","profile":"gradle"}` to `http://build.sandbox.invalid/build`
and then streams `&follow=1`.
- **expect**: `{"id":"b1"}`, `BUILD SUCCESSFUL`, `[saife] artifacts -> …\build\libs`,
  `[saife] build {"exited":0}`, exit `0`.
- **judge for yourself**: is the log readable while it runs, or only at the end? That is the
  difference between a usable runner and a 90-second staring contest.

---

## Group B — the container is gone when the session is

### QA-03 · slot dies with the session
1. Run a build, and while it runs open another terminal: `docker ps --filter label=saife.runner=1`
   - **expect**: one container, `Up`, named `saife-runner-<sid>`.
2. Let the session end. Repeat the `docker ps` command.
   - **expect**: **empty**. A container that outlives its session is a containment bug, not a leak.

### QA-04 · one slot, reused
Run two builds in the same session. The second must not pay a cold daemon.
- **expect**: second build reports `FROM-CACHE`/`UP-TO-DATE` tasks and finishes in single-digit
  seconds; `docker ps` still shows **one** container between them.

---

## Group C — the failures a user will actually hit

### QA-05 · cold cache (the message is the product)
1. `docker volume rm -f saife-runner-cache` (or prewarm a project you have never built).
2. Build offline through the session.
- **expect**: Gradle's own `No cached version of <group>:<artifact>:<version> available for offline
  mode`, surfaced through the stream, build `Failed(1)`.
- **judge**: could you tell from the message what to do next (run `saife runner prewarm <project>`)?
  If not, the message needs work — that is a finding.

### QA-06 · a build past its deadline
1. Copy `profiles/gradle-runner.json` into `%USERPROFILE%\.saife\profiles\` and set
   `limits.workloadTimeoutSecs` to `5`.
2. `saife run --block-net --runner --profile gradle-runner --allow-cwd -- <leg>`
- **expect**: `TimedOut`, a log line naming `limits.workloadTimeoutSecs`, **no container left**,
  and the supervisor's own exit code (not the build's).

### QA-07 · the refusals still refuse
- `saife run --backend appcontainer --runner -- cmd /c echo hi` → `runner_unsupported_backend`, exit `2`.
- `saife run --runner` with the engine stopped → exit `5` (QA-01).
- `saife run --block-net -- cmd /c echo hi` (**no** `--runner`) → unchanged: no listener, and
  `saife audit verify` still passes with `proxy_endpoint: null`.

---

## Group D — what a workload may not do

### QA-08 · no field for an escape
POST bodies that must be refused with `400` and a reason, never executed:
- `{"project":"..","task":"build","profile":"gradle"}`
- `{"project":"C:\\Windows","task":"build","profile":"gradle"}`
- `{"task":"build","profile":"gradle","image":"evil:latest"}` ← unknown field: **must be rejected,
  not ignored**
- `{"task":"rm -rf /","profile":"gradle"}` ← not in the allow-list

Also: create a junction inside the workspace pointing at `%USERPROFILE%`
(`mklink /J ws\leak C:\Users\marku`), then request `project: "leak"` → refused by name
(`a link or junction is not a way out of it`).

### QA-09 · the listener is not a public door
Take the port from `SAIFE_DIAG=1` output (`build runner on 127.0.0.1:<port>`), then from the host:
- plain `POST http://127.0.0.1:<port>/build` with no credential → refused, and the session's audit
  shows nothing accepted.
- the same with the **proxy** token → still refused: the runner has its own (T1.4).

### QA-10 · egress really is closed
Inside the session: `curl -sS -o NUL -w "%{http_code}" http://example.com/` → `403`.
- **and check the reason**: audit/console must say `network_blocked`, not "dns failed" or a prompt.
- A prompt appearing here is a bug: there is nothing to ask.

---

## Group E — Windows file semantics (the honest-limits list)

These four are **documented as limitations**. Your job is to confirm the documentation tells the
truth and the failure is visible, not to demand they pass.

### QA-11 · delete and rename are not propagated
Build, then delete a source file, then build again in the same session.
- **expect (today)**: the container still sees the deleted file; the build may still succeed using
  a stale source. **Judge**: does the README/USER-GUIDE say so plainly? If it reads as if it works,
  that is a docs bug worth fixing before release.

### QA-12 · a locked file refuses the pack
Open a source file in an editor that holds a lock (or use `[System.IO.File]::Open` with
`FileShare.None` in another window), then build.
- **expect**: the pack fails **naming the file**, not a truncated copy and not a mystery.

### QA-13 · long paths and case
- A path over 260 characters → refused or fails by name (no `\\?\` support claimed).
- Two files differing only by case (`Foo.java` / `foo.java`) → last writer wins; visible in the log
  or at least not silent corruption of the build.

### QA-14 · CRLF survives
Commit a CRLF source file; build; then check the same file on the host is still CRLF.
- **expect**: byte-identical — the copy is verbatim, `.gitattributes` is the project's business.

---

## Group F — packaging and install (never exercised on this branch)

### QA-15 · the artifact a user would download
1. `pwsh -File packaging\build-dist.ps1 -ReleaseVersion 0.4.0`
   - **expect**: the flat `saife-0.4.0-x64.zip`, not a nested `saife-<commit>.zip`
     (`build-dist.ps1` line ~163 needs the flag — a trap that has bitten twice).
2. `pwsh -File packaging\install-local.ps1`
   - **expect**: installs, reports `SAIFE Sandbox 0.4.0`, and the installed binary contains
     `--runner` (`saife.exe run --help | Select-String runner`).
3. `saife --version`, then run QA-02 with the **installed** binary, not the debug build.
- **judge**: would you ship this zip to someone who has never seen the project?

---

## Cleanup (do not skip)

- `docker ps -aq --filter label=saife.runner=1` → empty; `docker volume ls` → only
  `saife-runner-cache`.
- Remove any junction you made in QA-08 (`rmdir ws\leak`).
- Restore the profile you edited in QA-06.
- `saife audit verify` on the last session must still pass.
- Remove test session state you created under `%USERPROFILE%\.saife`.
