# FAQ — SAIFE Sandbox

Collected from real debugging/support sessions. Each entry starts from a symptom
a user actually saw, gives the verified cause, and states what to do (and what
NOT to do). New entries go in the same shape; an entry without a verification
record (control run, probe output, audit) is a hypothesis, not a FAQ entry.

Entries are ordered by how likely a user is to hit them.

---

## Why does PowerShell inside the sandbox print "Fehler beim Ausführen des InitializeDefaultDrives-Vorgangs für den Anbieter \"FileSystem\"." at startup?

**Symptom.** A PowerShell command run under the sandbox prints, before any
output, one line like

```
Fehler beim Ausführen des InitializeDefaultDrives-Vorgangs für den Anbieter "FileSystem".
```

(on German-locale hosts; on other locales the message names the same
`InitializeDefaultDrives` operation for the `FileSystem` provider). It recurs on
**every** PowerShell 5.1 (`powershell.exe`) child the session spawns — for
agent CLIs that shell out through PS, that means one line per executed command.
The command itself still succeeds and prints correct output afterwards.

**Verified by A/B probe** (same command, same cwd, in and out of the sandbox):

| Observation | outside the sandbox | inside the sandbox |
|---|---|---|
| PowerShell 5.1 startup | clean | the error line above |
| mapped network drives (`H:`/`M:`/`T:`/`U:` → `\\yggdrasil2\…`) | `ready=True`, volume labels readable | `type=Network ready=False`, volume labels empty, unreadable |
| `Get-PSDrive` | all drives listed | only `C:` remains |
| the command itself (`Get-ChildItem`) | correct output | correct output |

**Cause.** Windows exposes the logon session's mapped network drives to every
process, but the sandbox's container blocks raw SMB egress (network access is
loopback-proxy-only: HTTPS through the local proxy, only for allowlisted or
user-approved hosts — `saife audit show <sid>` records those decisions; no SMB
leaf exists). So the mapped drives are in the drive list but unreachable, and
PowerShell's `FileSystem` provider throws once while inspecting them during
startup, then continues normally. The line is the sandbox's network posture
surfacing through PowerShell's own startup diagnostics.

**Verdict: harmless. Ignore it.**

- It is NOT a failed command, NOT a file-access denial, and NOT evidence of a
  missing grant. The audit trail shows nothing denied.
- Do **not** work around it by granting SMB/UNC access (`\\server\share` paths
  or the WKSS/redirector) — that would open raw network egress and break the
  sandbox's network model. A file that lives on a share should be copied into
  the workspace by the operator, not reached from inside the session.

### Related trivia (do not confuse with the above)

- `Get-ChildItem`/dir listings *of the workspace* failing is a different thing
  — that is a filesystem grant question (`fs_readwrite` in
  `saife audit show <sid>`), and it leaves no trace in the audit when refused.
- PowerShell 7 (`pwsh`) inside the sandbox is its own topic: it may refuse to
  start sandboxed at all depending on host conditions; that phrasing
  (`A specified logon session does not exist (0x80070520)`) is unrelated to
  this entry.

## How do I run Gradle (or a JVM build / local server test) inside the sandbox?

**Symptom.** A `gradlew.bat build` inside a sandboxed agent session fails with
some combination of:

- `SocketException: Permission denied: getsockopt` connecting to
  `services.gradle.org` (deps never download) — while PowerShell downloads in
  the same session succeed;
- `Could not connect to the Gradle daemon` / a loopback connect that fails with
  access denied (`WSAEACCES` on a `127.0.0.1` probe);
- write access to `~/.gradle` denied (wrapper dists, lock files).

**Cause, per symptom.**

1. *Direct TCP fails.* Sandbox egress is **proxy-only by design** in every
   backend: HTTPS through the local proxy, only for allowlisted or
   user-approved hosts; raw outbound TCP is never grantable. PowerShell worked
   because .NET honors the injected `HTTP_PROXY`/`HTTPS_PROXY` env vars — **the
   JVM ignores them**, so Gradle tried a direct connect. Fix: point the JVM at
   the session proxy via system properties (recipe below); the child can
   derive everything from its own env (`HTTP_PROXY` carries
   `sandbox:<token>@127.0.0.1:<port>`, `SAIFE_PROXY_PORT` is injected too).
2. *Loopback fails.* The Gradle daemon listens on `127.0.0.1` and the client
   connects to it over loopback; `--no-daemon` does NOT avoid this (Gradle
   forks a single-use daemon anyway). Under the default `mxc` backend loopback
   is unreachable by design, so `gradle build` **cannot work under `mxc`**.
   The `appcontainer` backend exempts the session SID for loopback, so the
   daemon (and a Spring Boot server binding `127.0.0.1`, curled from the same
   session) works there — but `appcontainer` network sessions require an
   elevated shell.
3. *`~/.gradle` denied.* A profile grant question: add `$USERPROFILE/.gradle`
   (and the JDK install tree read-only, or bare `java` fails with `0x80070002`
   and reads like "not installed"). The repo's `jvm` sample profile carries
   all of this; `opencode` `extends` it.

**The backend dilemma (measure before choosing).** The two backends price a
grant differently: `mxc` takes ONE path entry per grant, while the
`appcontainer` DACL walk caps at 20 000 objects per grant and truncates with a
warning. On this machine (measured 2026-10-24): an agent session's own state
easily exceeds the cap (`.local/share/opencode` ≈ 24k objects, a tool cache
≈ 20k), while the `jvm` grants are cheap (`.gradle` ≈ 11k, JDK tree ≈ 600,
`.m2` empty). Consequence: **an opencode session under `appcontainer` is not
viable** (its own grants truncate), but a **separate, lean session for the
build** is:

- agent/edit session: default backend (`mxc`), unelevated — Java file work,
  `javac`/`java`, and Maven (in-process, no daemon) all work there;
  `gradlew build` and server bind-and-curl tests do not.
- build/test session: elevated, `--backend appcontainer`, profile `jvm`,
  started at the **project root**.

**Procedure (build session; verified mechanism-by-mechanism, not yet run
end-to-end — treat as the working recipe until a green run):**

```powershell
# elevated PowerShell, project root:
saife run --profile jvm --backend appcontainer -- powershell.exe -NoProfile -File _gradle-inside.ps1
```

`_gradle-inside.ps1`:

```powershell
$u  = [Uri]$env:HTTP_PROXY
# PS 5.1 quirk: Uri.UserName/.Password are EMPTY even with userinfo present.
$sandbox, $token = ($u.UserInfo -split ':', 2)
$env:GRADLE_OPTS = "-Dhttps.proxyHost=$($u.Host) -Dhttps.proxyPort=$($u.Port) " +
                   "-Dhttp.proxyHost=$($u.Host) -Dhttp.proxyPort=$($u.Port) " +
                   "-Dhttps.proxyUser=$sandbox -Dhttps.proxyPassword=$token " +
                   "-Dhttp.proxyUser=$sandbox -Dhttp.proxyPassword=$token"
.\gradlew.bat build
# server tests work in the same session: loopback is exempted for it
```

Two PowerShell 5.1 traps this recipe avoids: `[Uri].UserName`/`.Password`
return empty strings even when the URL carries userinfo (parse
`[Uri].UserInfo` instead), and `$ErrorActionPreference='Stop'` turns a
redirected native-stderr stream (`java -version 2>&1`) into a terminating
`NativeCommandError` — redirect inside `cmd /c` if you must capture it.

Verify with `saife audit show <sid>`: `CONNECT … allowed` leaves for
`services.gradle.org`, `plugins.gradle.org`, `repo.maven.apache.org`
(`downloads.gradle.org`, `repo1.maven.org` as needed).

**Do NOT:**

- ask for "outbound TCP/443 from any process" or "allow loopback" as a grant —
  the first does not exist (egress is proxy-only), the second is a backend
  design constraint, not a profile setting;
- expect `--no-daemon` to fix the daemon connect;
- widen the profile to `$HOME` to silence grant errors — narrow grants plus the
  secret-dir denies are the point;
- run the build inside the agent session on `appcontainer` — the agent's own
  state dirs exceed the 20k-object grant cap before Gradle is even involved.

## Do I need to clean up grants after a crash (or regularly)?

**Short answer: no schedule needed — but know the one residue that does
accumulate.**

**Filesystem grants (AppContainer DACLs) are self-healing.** Every session ACE
the supervisor writes is journaled to
`%LOCALAPPDATA%\saife\dacl-restore\<runid>.jsonl`, whose header carries the
supervisor's pid AND its process-creation time (so PID reuse cannot make a dead
owner look alive). Normal teardown restores the host DACLs *before* deleting
the journal. If the supervisor is killed or crashes, the next `saife run`
reaps the orphans before it touches any DACL itself: for every journal whose
owner is no longer alive it re-applies (restores) the recorded entries and
deletes the journal; unparseable journals are quarantined as `*.jsonl.corrupt`,
never silently dropped (`src/sandbox/dacl_journal.rs::recover_orphans`).

Practical consequences:

- A crash costs nothing as long as you start another sandbox session at some
  point — recovery rides along. Only if saife is never started again do stale
  ACEs linger on the paths the crashed session had granted.
- Check after a crash: `icacls <granted-path> | findstr S-1-15-2` — a session
  SID that matches no live `saife` process is residue. A belt-and-braces
  sweep exists (`tests/Clear-HostTestArtifacts.ps1`; some paths need
  elevation — it names them instead of failing silently), and
  `tests/cleanup-session-aces.ps1` handles the kernel-written session ACEs
  that `icacls /findsid` cannot match.
- Live sessions look identical to residue: an ACE belongs to a live session
  while its supervisor (and the journal) exists. Two `saife` processes in
  `Get-Process` mean two sessions' ACEs are LEGITIMATELY on disk — do not
  strip ACEs while a session is running; you would break its containment
  grants mid-run.

**Loopback exemptions do accumulate.** `register_loopback` adds the session's
AppContainer SID to the machine's loopback-exemption list
(`NetworkIsolationSetAppContainerConfig`) and nothing deregisters it at
teardown — the API has no per-run removal and the exemption is all-or-nothing
per SID. Each `--backend appcontainer` network session therefore leaves one
exemption behind. A dead session's random SID is not reused, so the residue
does not grant anything to new processes, but it is real machine state: audit
it with `CheckNetIsolation LoopbackExempt -s` and treat a growing list as
cleanup debt (no shipped sweeper yet).

**What needs NO cleanup:** the audit trail (`%LOCALAPPDATA%\saife\audit`,
`.root`/`.sig`/`.ndjson` per session) is evidence by design and is never
pruned by saife; journals are deleted after successful restore; `mxc` sessions
write no host ACLs at all (only `%TEMP%` scratch dirs).

### Maven and Gradle under `mxc`: the proxy must be handed to the JVM

Java ignores the injected `HTTP_PROXY`/`HTTPS_PROXY` env vars entirely, so
`gradlew`/`mvn` try direct connects and die with
`SocketException: Permission denied: getsockopt` even when the profile
allow-lists their hosts and PowerShell downloads work in the same session. The
build tool has to be pointed at the session proxy explicitly, and the session
env carries everything needed to do it:

```powershell
$u = [Uri]$env:HTTP_PROXY                      # http://sandbox:<token>@127.0.0.1:<port>
$sandbox, $token = ($u.UserInfo -split ':', 2) # PS 5.1: [Uri].UserName/.Password are EMPTY
$env:GRADLE_OPTS = "-Dhttps.proxyHost=$($u.Host) -Dhttps.proxyPort=$($u.Port) " +
                   "-Dhttp.proxyHost=$($u.Host) -Dhttp.proxyPort=$($u.Port) " +
                   "-Dhttps.proxyUser=$sandbox -Dhttps.proxyPassword=$token " +
                   "-Dhttp.proxyUser=$sandbox -Dhttp.proxyPassword=$token"
```

Verified on Gradle 9.2.0 (2026-10-24): with these props the wrapper reached the
proxy and was **challenged 407** — but never authenticated, because the
dist-download step of the wrapper uses plain `HttpURLConnection`, which ignores
`proxyUser`/`proxyPassword` (those properties are read by Gradle's OWN build
client, not by Java's URL stack). The proxy turned the session into a
`workload_cannot_authenticate` guardrail refusal. Consequence: bootstrap the
wrapper distribution OUTSIDE the sandbox first (`gradlew.bat --version` once on
the host so `~/.gradle/wrapper/dists` holds the unpacked dist); the in-sandbox
wrapper then never downloads, and dependency resolution rides Gradle's own
client, which honors the properties.

Verify via the audit (`saife audit show <sid>`): `CONNECT … allow` leaves for
`services.gradle.org` + `downloads.gradle.org` (wrapper dist) and
`plugins.gradle.org` + `repo.maven.apache.org` (dependency resolution). A
`workload_cannot_authenticate` guardrail line means a client stack reached the
proxy but answered no credential — the 407 story above, not a deny rule.

**No-daemon mode does not rescue this — measured, not assumed.** The current
Gradle docs claim that with `org.gradle.daemon=false` *and* the client JVM's
args matching `org.gradle.jvmargs` the daemon is skipped entirely and the
build runs in the client JVM. On Gradle 9.2.0 under `mxc` we tried four
configurations (plain `--no-daemon`; `daemon=false` + `GRADLE_OPTS` args
matching the default daemonOpts; `daemon=false` + `org.gradle.jvmargs`
mirrored in `gradle.properties` with the proxy props moved out of
`GRADLE_OPTS` so they could not break the equality; the same mirrored into
`JAVA_OPTS` as well). All four still forked a single-use daemon and died with
`Could not connect to the Gradle daemon` at the refused loopback. Until the
in-client path can actually be triggered, treat **any Gradle build under
`mxc` as impossible**; the daemon-free path remains a design question
(F-6 loopback) or a sidecar-deputy job.

## Why did my session just end with "workload_budget_exceeded"?

```
[saife] mxc: session ended at its deadline (1980000 ms = prompt 60 s + workload 1800 s + slack 120 s) - reason workload_budget_exceeded
```

**This is the session budget expiring by design, not a crash.** Every session
has a hard deadline built from three terms:

| term | default | what it covers |
|---|---|---|
| prompt | 60 s | how long an unlisted host's permission prompt may wait |
| workload | 1800 s (30 min) | the container's own budget for the workload |
| slack | 120 s | teardown/recovery head-room on top |

Total ≈ 33 minutes. A long build, a downloaded dependency graph, or a
long-running agent session can legitimately spend the workload term, and the
supervisor then kills the container and reports which term ran the clock out
(the `reason` token, here `workload_budget_exceeded`). The process exit code is
**124** (`EXIT_TIMEOUT`), deliberately distinct from a refused session and from
the child's own exit code — a script can tell "my command failed" from "saife
ended it at its budget".

The session still seals its audit chain and prints the guardrail proof line
(`accepted=` / `tunnels=` are the egress counters — `accepted=3 tunnels=0` just
means three authenticated proxy requests, zero completed tunnels; it is not an
error).

**Raise the workload term in the profile** (top-level `limits` section, cap
7 days = 604800):

```json
{
  "network": {
    "block_net": false,
    "profile": "developer",
    "allow_domain": ["..."]
  },
  "limits": {
    "promptTimeoutSecs": 60,
    "workloadTimeoutSecs": 14400
  }
}
```

`workloadTimeoutSecs` is validated `1..=604800` and `promptTimeoutSecs`
`0..=604800` (`0` still means "instant deny"); an out-of-range value falls back to
the default (30 min / 60 s) with a warning line,
so check the resolved value with `saife profile show <name> --expanded` (it
prints them under `limits`). Both keys were `network.*` until 2026-10-25 and that
location is **refused** now, so an installed or copied old profile fails with
`unknown field `workloadTimeoutSecs`` plus a hint naming `limits`.

There is no CLI flag for it — profile only, and like every grant it belongs in
BOTH the installed profile (`%USERPROFILE%\.saife\profiles\`) and the repo
sample (`profiles/`).

## Why is a session in my home directory refused ("writable grant … contains the launcher")?

```
[saife] mxc: writable grant "C:\\Users\\marku" contains the launcher "C:\\Users\\marku\\AppData\\Local\\Programs\\saife\\saife-launch.exe": the launcher runs on the host at the next launch, so a workload that can replace it is scheduling code to run with the supervisor's rights. Narrow the grant.
```

**Why (the short reason):** the `mxc` backend starts the container through
`saife-launch.exe`, which sits beside the supervisor — and that launcher is
executed **on the host at the NEXT launch** (it is what carries `NO_PROXY` /
`SAIFE_PROXY_PORT` into the child). A writable grant that contains it therefore
lets the workload swap the binary and get its own code run with the
supervisor's rights next time. So a grant covering your home directory (which
contains `AppData\Local\Programs\saife\`) — or any ancestor of it, e.g.
`C:\Users` — is refused **before the child starts**: no container is created,
no audit session is opened for it at all (no new file under
`%LOCALAPPDATA%\saife\audit`, not even a `SESSION_START` root), and the exit
code is **2** (a refusal, deliberately distinct from the workload's own exit
code and from the 124 deadline kill). This is a designed refusal, not a bug.
Measured on the installed build and on a clean `target/release` build.

**What to do:** run in the project directory (the workspace is granted anyway),
or grant the specific directories the workload needs (`--allow <path>`) instead
of `$HOME`. Do not try to work around it by moving the launcher: the refusal
follows the launcher's location. Note it is an `mxc`-backend rule — the
`appcontainer` backend has no host-side launcher wrapper.

<!-- NEXT FAQ ENTRY GOES HERE -->

