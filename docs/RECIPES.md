# Recipes

Task first. Every entry has the same five parts: **what you want**, **what it needs**, **the
command**, **what you should see**, and **if it fails**. The *why* lives in
[`USER-GUIDE.md`](USER-GUIDE.md) and the [ADRs](adr/); this page does not repeat it.

| I want to… | recipe |
|---|---|
| run a repository's tests | [R1](#r1-run-a-repositorys-tests) |
| build a Gradle project | [R2](#r2-build-a-gradle-project) |
| use a toolchain installed outside the workspace | [R3](#r3-use-a-toolchain-installed-outside-the-workspace) |
| let one program reach one API host | [R4](#r4-let-one-program-reach-one-api-host) |
| run an AI agent with its own config directory | [R5](#r5-run-an-ai-agent-with-its-own-config-directory) |
| keep secrets out of a session | [R6](#r6-keep-secrets-out-of-a-session) |
| build only part of a monorepo | [R7](#r7-build-only-part-of-a-monorepo) |
| find out why a session failed | [R8](#r8-find-out-why-a-session-failed) |
| clean up after a session | [R9](#r9-clean-up-after-a-session) |

---

## R1 · Run a repository's tests

**Needs:** nothing beyond the sandbox — the test run needs its working directory and, for Rust,
the toolchain directories (R3).

```powershell
cd C:\src\my-repo
saife run --allow-cwd -- cmd /c cargo test
```

**You should see** the test output, then the proof line:

```text
test result: ok. 42 passed; 0 failed
[saife] mxc: guardrail 1 proof probes=1 accepted=0 tunnels=0 unauthenticated=0
```

**If it fails:**

| symptom | meaning |
|---|---|
| `failed to start 'cargo': … file not found (0x80070002)` | the toolchain is not granted — go to R3 |
| `denied path … contains the granted path` | a `deny` in the profile covers your grant |
| tests hang on a host lookup | no network by default: add `--allow-domain <host>` (R4), or mock it |

**Why:** a test run that reaches the network is a test run that can leak. The default is nothing.

---

## R2 · Build a Gradle project

**Needs:** a running container engine (Rancher Desktop or Docker Desktop), and one prewarm before
the first build.

1. **Prewarm once** — this is the only step with a network:

```powershell
saife runner prewarm C:\src\my-gradle-project
```

2. **Run a session with the runner**, from the parent directory of the project:

```powershell
cd C:\src
saife run --block-net --runner --allow-cwd -- powershell -NoProfile
```

3. **Ask for the build** at the session's prompt:

```powershell
$body = '{"project":"my-gradle-project","task":"build","profile":"gradle"}'
Set-Content -NoNewline -Encoding ascii "$env:TEMP\body.json" $body
$start = curl.exe -sS -m 60 -X POST "http://build.sandbox.invalid/build" -H "Content-Type: application/json" --data-binary "@$env:TEMP\body.json"
$start
$id = ($start | ConvertFrom-Json).id
curl.exe -sS -N -m 300 "http://build.sandbox.invalid/build?id=$id&follow=1"
```

**You should see** the id, then the log streaming, then a verdict:

```text
{"id":"b1"}
BUILD SUCCESSFUL in 9s
[saife] artifacts -> C:\src\my-gradle-project\build\libs
[saife] build {"exited":0}
```

**If it fails:**

| symptom | meaning | fix |
|---|---|---|
| `No cached version of g:a:v available for offline mode` | the dependency is not in the cache | re-run step 1 to completion — a build never goes to the network |
| `400 … key must be a string` | PowerShell stripped the quotes out of the body | send it from a file, as above |
| `runner_engine_unavailable`, exit 5 | no container engine | start Rancher/Docker Desktop |
| `timed_out` | `limits.workloadTimeoutSecs` ran out | narrower task (`assemble` not `build`), or raise the limit in the profile |
| `runner_slot_cap_reached` | 4 slots already running | close an idle session; slots die after 10 idle minutes |

**The loop while developing:** edit `build.gradle.kts` → back to step 1 (prewarm) → build.
Only `build/libs` comes back to the host.

---

## R3 · Use a toolchain installed outside the workspace

**Needs:** the absolute path of the toolchain's directory.

```powershell
saife run --allow-cwd `
  --read-only C:\Users\<you>\.cargo `
  --read-only C:\Users\<you>\.rustup `
  -- cmd /c C:\Users\<you>\.cargo\bin\cargo.exe build
```

**You should see** `Finished` from the tool, then the proof line with `probes=0` (nothing reached
the network).

**If it fails:** `failed to start '<tool>': … file not found (0x80070002)` means *not granted*, not
*not installed* — a denied path reaches the child as "file not found". Add the directory and retry.
Note the launch path is absolute in the example: the grant makes it *visible*, the absolute path
makes it *found*.

**Why read-only:** a toolchain is not something a build should be able to rewrite.

---

## R4 · Let one program reach one API host

**Needs:** the host name, exactly as the client spells it.

```powershell
saife run --allow-cwd --allow-domain api.example.com -- cmd /c tool.exe fetch
```

**You should see** the request succeed, and the proof line showing `accepted=1` — the workload
reached the proxy.

**If it fails:**

| symptom | meaning |
|---|---|
| a dialog appears, or the run hangs | the host is not allow-listed: approve it once, or deny it and use `--no-prompt` in unattended runs |
| `403` with `deny` in the audit, though the host is listed | a `deny` (from `--deny-domain`, a profile, or a **learned** entry) outranks the allow-list |
| `workload_cannot_authenticate` | the client stack cannot use a proxy at all (WinINet, PS 5.1) → `--backend appcontainer` |

**Why:** exact host, no suffix matching. `api.example.com` is not `example.com`.

---

## R5 · Run an AI agent with its own config directory

**Needs:** a profile that describes the app's paths — the shipped ones are measured, not guessed.

```powershell
saife run --profile opencode-desktop --allow-cwd -- opencode
```

**You should see** the agent start, and its network use appear as `allow <host>` lines in the
terminal as it fetches.

**If it fails:** `no profile named '<x>'` also prints the available names. `profile show <name>
--expanded` prints what a profile *actually* grants after expansion — check there first if an app
cannot find its config.

**Why a profile:** an agent needs a writable app-data directory and read-only program files, and
those paths differ per app. Guessing them is how a session ends up acting on the wrong directory.

---

## R6 · Keep secrets out of a session

**Needs:** the directory that holds the secrets, named in a **profile** — path denies are a policy
thing, so they live in the profile rather than on the command line.

```json
{
  "filesystem": {
    "allow": ["$CWD"],
    "deny": ["$USERPROFILE/.ssh", "$USERPROFILE/.aws", "$USERPROFILE/.config/gh"]
  }
}
```

```powershell
saife run --profile my-agent --allow-cwd -- cmd /c agent.exe
```

**You should see** the agent run, and any read of a denied path refused and logged as a deny.

**If it fails:**

| symptom | meaning |
|---|---|
| `denied path … contains the granted path` | a deny covers one of your writable grants — deny a subdirectory instead of the whole tree |
| the agent still reads the file | the path was granted by a **parent** `allow`; deny beats allow only for paths that are *matched*, so name the file's directory |

**And check every learned store, not just the default one:**

```powershell
saife learned list
```

Learned denies are per network profile and they **outrank an allow-list**. A deny you cannot see is
the worst failure shape, which is why `learned list` prints a `# <store>` header per profile;
`saife learned revoke --profile <store> <host>` removes one.

**Why:** `.saife` itself is denied on every backend — a session must not be able to read or rewrite
its own policy.

---

## R7 · Build only part of a monorepo

**Needs:** the paths that make a *closed* build — the root settings, the wrapper, every
`includeBuild(...)` root, and the modules you want.

Use `paths` on the request (or set `runner.sync.paths` in a profile as the default):

```json
{"project":"monorepo","task":"test","profile":"gradle",
 "paths":["settings.gradle.kts","gradle","gradlew","build-logic","apps/payments","libs/common"]}
```

**You should see** the log header name the allow-list it copied, then the build.

**If it fails:** a configuration error naming a missing module means the set was not closed — add
the missing `include(...)` member or its `includeBuild` root. A missing entry is refused by name
rather than silently skipped.

**Why closed sets:** a copy that silently grows to make the build pass is a copy nobody can
predict. Measured: 20 000 files copy in 1.98 s, a 10 % allow-list in 0.196 s — so narrowing is
worth doing, but correctness comes from naming the closure, not from guessing it.

---

## R8 · Find out why a session failed

**Needs:** the terminal output of the run.

1. **Read the proof line** — it is the summary of the network question:

```text
[saife] mxc: guardrail 1 proof probes=1 accepted=0 tunnels=0 unauthenticated=0
```

`probes` = the child tried the proxy; `accepted` = a request was allowed; `tunnels` and
`unauthenticated` must be `0` — anything else is a containment failure, not a tool failure.

2. **Read the audit**, which answers *what was asked* rather than *what happened*:

```powershell
saife audit verify
```

`INCOMPLETE` is expected after a kill; the leaves are still valid evidence.

3. **Match the message** against `USER-GUIDE.md` §9 (symptom → cause → fix). Every refusal has a
   name (`network_blocked`, `runner_slot_owned_elsewhere`, `denied path …`), and the name is the
   thing to search for.

**If nothing matches:** keep the proof line and the audit leaf — that pair is what a bug report
needs, and neither contains a credential.

---

## R9 · Clean up after a session

**Needs:** nothing; all of this is host state a session can leave behind.

```powershell
# runner slots: they should be gone when the session ends
docker ps -aq --filter label=saife.runner=1

# a denied firewall prompt leaves a Block rule for the binary that asked
Get-NetFirewallRule -Action Block | Where-Object { $_.DisplayName -match 'SAIFE' }

# test leftovers: junctions you made, plugin copies, edited profiles
```

**You should see** no containers, and no rules for binaries that no longer exist.

**If something is left:** remove it by hand — `docker rm -f <id>`,
`Remove-NetFirewallRule` (elevated), `cmd /c rmdir <junction>`. A runner slot that outlives its
session is a containment bug rather than clutter: report it with the container's labels
(`docker inspect -f '{{.Config.Labels}}' <id>`).

**Why it matters:** slots carry a shared cache volume (`saife-runner-cache`) and a session's
grants are restored on exit — but a container, a firewall rule or a junction is not something the
supervisor can know about, so the cleanup is yours to finish.
