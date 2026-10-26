# User guide

How to run things under `saife`, and what to do when it says no.

For building the binary see `README.md`; for changing the code see
`docs/DEVELOPERS.md`. Every example below was run on this repository's release
build (Windows 11, unelevated, default `mxc` backend) and is pasted from a real
session.

---

## 1. The model in one minute

A run gets **only what you grant it**:

- **Filesystem**: nothing is readable or writable unless it is inside a grant.
  `--allow-cwd` grants the current directory read+write+execute; `--allow`,
  `--read-only` add more.
- **Network**: nothing leaves unless you allow it. With no network flag there is
  no proxy at all; `--allow-domain` and profiles open specific hosts;
  `--block-net` refuses everything.
- **Everything is audited**: each run writes a hash-chained, signed log you can
  inspect afterwards (`saife audit show|verify`).

The program you run is unchanged; it just cannot reach anything you did not
grant.

```powershell
saife run --allow-cwd -- cmd /c echo hello
```

```text
hello
[saife] mxc: guardrail 1 proof probes=0 accepted=0 tunnels=0 unauthenticated=0
```

The `[saife] mxc: guardrail 1 proof ...` line is the supervisor telling you
what it proved about this run — see §6.

---

## 2. Running simple tools

### 2.1 A command that needs only its working directory

```powershell
cd C:\work\myproject
saife run --allow-cwd -- cmd /c build.bat
```

### 2.2 Build tools (cargo, npm, …)

The toolchain lives **outside** the workspace, and every path outside the
workspace is denied by default. Grant it read-only:

```powershell
saife run --allow-cwd `
  --read-only C:\Users\<you>\.cargo `
  --read-only C:\Users\<you>\.rustup `
  -- cmd /c C:\Users\<you>\.cargo\bin\cargo.exe build
```

Verified here:

```text
cargo 1.98.1 (797e8a9bc 2026-08-05)
[saife] mxc: guardrail 1 proof probes=0 accepted=0 tunnels=0 unauthenticated=0
```

> **If you see `failed to start 'cargo': ... file not found (0x80070002)`**, the
> grant is missing — not the install. A denied path reaches the child as
> "file not found". Add `--read-only <toolchain dir>` and try again.

### 2.3 Interpreters and scripts

Same rule: grant the interpreter's directory and call it by absolute path.

```powershell
saife run --allow-cwd --read-only C:\Python312 -- C:\Python312\python.exe .\script.py
```

### 2.4 PowerShell one-liners

`powershell` (5.1) runs inside the container. Expect one harmless startup line
on the `mxc` backend (`InitializeDefaultDrives ... FileSystem provider`); it comes
from the container's restricted filesystem view, not from your command.

```powershell
saife run --allow-cwd -- powershell -NoProfile -Command "Get-ChildItem | Measure-Object"
```

### 2.5 An AI coding agent

Give the agent its project and the hosts it may talk to:

```powershell
saife run --allow-cwd `
  --allow-domain api.anthropic.com `
  --allow-domain github.com `
  --allow-domain '*.githubusercontent.com' `
  -- claude
```

An agent that only needs local work gets no network at all:

```powershell
saife run --allow-cwd --block-net -- opencode
```

Two hard limits worth knowing before you put an agent behind this:

- **One run per supervisor process.** A second concurrent `saife run` on the
  same listener is refused; start a second supervisor instead.
- **GUI / system-proxy applications** (WinINet, PowerShell 5.1, .NET Framework)
  cannot use the proxy: they reach it and never authenticate, so the session is
  refused with `workload_cannot_authenticate`. Run those with
  `--backend appcontainer` (which needs admin for network).

---

## 3. Filesystem grants

| Flag | Meaning |
|---|---|
| `--allow-cwd` | read+write+execute on the current directory |
| `--allow <path>` | read+write+execute on a path (repeatable) |
| `--allow <path>:read` | read+execute only |
| `--allow <path>:write` | write only |
| `--read-only <path>` | read-only on a path (repeatable) |

Read-only grants are enforced by the container's policy, not by hope:

```powershell
saife run --allow-cwd --read-only C:\data -- powershell -NoProfile -Command "Get-Content C:\data\notes.txt"
# secret-data

saife run --allow-cwd --read-only C:\data -- powershell -NoProfile -Command "Set-Content C:\data\new.txt x"
# UnauthorizedAccessException: Access to the path 'C:\data\new.txt' is denied.
```

A **writable** grant outside the workspace is honoured on both backends
(P3.4). That is what makes a tool which keeps state in your profile usable —
opencode, for instance, writes `~/.local/share/opencode`, `~/.cache/opencode`,
`~/.config/opencode` and `~/.local/state/opencode`:

```powershell
saife run --profile opencode --allow $HOME\.local\share\opencode `
            --allow $HOME\.cache\opencode --allow $HOME\.config\opencode `
            --allow $HOME\.local\state\opencode -- opencode
```

The grants are a closed set — the workspace plus what you name — and they do
**not** weaken the two protections on top of them:

* the profile's credential directories (`~/.ssh`, `~/.aws`, `~/.azure`,
  `~/.gnupg`) stay denied even when their parent is granted writable, so a
  workload cannot read your keys through a generous grant; and
* a `deny` that **covers** a grant (the same path, or a parent of it) refuses
  the session with `denied path ... contains the granted path ...` rather than
  being dropped silently. Narrow the deny to a subdirectory, or move the grant,
  and the session starts.

### 3.1 Interactive tools (TUIs)

A session whose **stdin and stdout are both terminals** hands the workload this
console, so an interactive tool renders and reads keys exactly as it would
outside the sandbox:

```powershell
# opencode, verified 2026-10-22: TUI renders, keys work, egress authenticated
saife run --profile opencode --allow-cwd -- opencode
```

Start it **at the project's git root** — the directory `git rev-parse
--show-toplevel` prints. opencode resolves its project from the repository, and
from a subdirectory it reads the parent's `.git` and `.opencode`, which the
container denies: the failure is `Error: Unexpected server error. Check server
logs for details.` (exit 1) with nothing in opencode's own log, because it dies
in the client before its server starts. Running it at the root of the same
repository works, and so does staying in the subdirectory if the repository root
is granted read-only — measured all three ways with the same binary and profile:

```powershell
# from a subdirectory: let it see the repository root, read-only
saife run --profile opencode --allow-cwd --allow <repo-root>:read -- opencode
```

The shipped profile allow-lists only the **provider** (`*.trustedtokens.eu`).
opencode also fetches a model catalogue at start-up (`models.opencode.ai`,
`models.dev`), and that host is deliberately **not** allow-listed: it prompts.
Answer the prompt and the session continues; deny it, or let it time out, and
opencode dies before it ever calls the model, with
`Failed to fetch models.dev … 403` — a crash that reads like the sandbox
refusing the provider when the provider was never contacted. For a headless or
unattended run, allow the catalogue explicitly:

```powershell
saife run --profile opencode --allow-cwd --allow-domain models.opencode.ai `
  --allow-domain models.dev -- opencode
```

Two filesystem grants make that work, and the shipped `profiles/opencode.json`
carries both:

* the four state directories it writes (`~/.local/share/opencode`,
  `~/.cache/opencode`, `~/.config/opencode`, `~/.local/state/opencode`) — they
  are outside the workspace, which the MXC backend accepts;
* `%LOCALAPPDATA%\Microsoft\WinGet` **read-only**, purely so the executable can
  be *found*: an installed program lives in a directory the container cannot
  see, so its bare name does not resolve on the inherited `PATH`. Grant the
  install tree and the name works.

Two consequences worth knowing:

* The child's output goes straight to your terminal, so the supervisor has no
  copy of it: a refused session still shows you what your command printed, but
  there is no captured `stdout` to inspect afterwards.
* `--no-interactive` forces the captured mode. Use it in scripts, schedulers and
  CI, where stdin/stdout are redirected anyway — the flag exists so a pipeline
  that reads the session's output never has it disappear onto a console.

When either stream is redirected, the captured mode is chosen automatically and
nothing changes for existing callers.

> **Known limitation (mxc-sdk 1.0.1): a stat of an ANCESTOR of a granted path is
> refused.** Writing *inside* a grant works (path resolution through the
> ancestors is implicit); reading their attributes is not, and
> `--allow $HOME:read` only partly closes it (measured).
>
> In practice this does **not** stop opencode 1.19.1: with its four state
> directories granted it starts, renders and runs, even though the same session
> refuses `if exist %USERPROFILE%`. Measured 2026-10-22 on the default backend,
> unelevated — if a tool does fail on that call, this is the limitation to blame,
> not the grant configuration.
>
> There is no clean fix to configure: the SDK's policy has four path classes
> (read-write, read-only, deny, enumerate-without-read) and none means "traverse
> and read attributes, without listing or reading". `--allow $HOME:read` is the
> closest, and it is **partial** — measured, it makes the home directory's
> entries statable and the directory listable, but the directory's own `lstat`
> is still refused, so a tool that insists on that exact call still fails. It
> also makes the rest of your profile readable (the credential directories stay
> denied: `~/.ssh` names become visible, their contents do not). Granting
> ancestors automatically is therefore not done — it would be a silent
> over-grant — and this is recorded as an SDK-level blocker in ADR-0004.

---

## 4. Network

### 4.1 Nothing at all

```powershell
saife run --allow-cwd --block-net -- cmd /c echo offline
```

No proxy is started and every `connect()` is kernel-denied.

### 4.2 Allowing hosts

```powershell
saife run --allow-cwd --allow-domain api.anthropic.com --no-prompt -- `
  cmd /c C:\Windows\System32\curl.exe -sS --ssl-no-revoke -o NUL -w "http_code=%{http_code}" https://api.anthropic.com/
```

```text
http_code=404
[saife] mxc: guardrail 1 proof probes=1 accepted=1 tunnels=1 unauthenticated=0
```

`404` is the origin answering — the sandbox admitted the tunnel (`tunnels=1`).
That distinction matters: **the sandbox's decision is the proxy result, not the
origin's status.**

### 4.3 Denying wins

```powershell
saife run --allow-cwd --allow-domain '*.anthropic.com' --deny-domain api.anthropic.com --no-prompt -- `
  cmd /c C:\Windows\System32\curl.exe -sS -o NUL https://api.anthropic.com/
```

```text
curl: (7) CONNECT tunnel failed, response 403
```

The deny-list is checked before the allow-list, so a wildcard allow cannot
override an explicit deny.

### 4.4 Profiles

`--network-profile none|minimal|developer` picks a built-in set of hosts
(`none` = block, `minimal` = the Anthropic API, `developer` = common dev hosts).

### 4.5 The prompt

For a host that is neither allowed nor denied, the interactive prompt asks:

| Button | Effect |
|---|---|
| Allow once | this request only |
| Allow for host | remembered for the host for this session |
| Allow for suffix | remembered for the domain suffix |
| Deny once / Deny for host / Deny for suffix | the mirror image |
| Explain more | the agent's declared intent is shown (D-4), then the prompt returns |

Decisions can be remembered permanently (`learned` store), and shown again with
`saife learned list`.

`--no-prompt` disables the dialog entirely: unlisted hosts are denied (or
allowed, per the profile's `onUnavailable`). In a headless context — CI, a
service, a container — there is no dialog to answer, so after two consecutive
unanswered consultations the configured `onUnavailable` policy applies
immediately instead of waiting out the prompt budget per host.

---

## 5. Profiles

A profile is a JSON file in `%USERPROFILE%\.saife\profiles\<name>.json`:

```json
{
  "meta": { "name": "demo", "version": "1.0", "description": "Docs example", "schema_version": 1 },
  "filesystem": {
    "read_only": ["C:/Users/you/.cargo", "C:/Users/you/.rustup"]
  },
  "network": {
    "allow_domain": ["api.anthropic.com"],
    "promptEnabled": false
  },
  "limits": {
    "promptTimeoutSecs": 60,
    "workloadTimeoutSecs": 3600
  }
}
```

`meta.schema_version` is **required**. Fields are snake_case, except the network
options `denyDomain`, `promptEnabled` and `onUnavailable`, and the two
session-deadline terms `promptTimeoutSecs` / `workloadTimeoutSecs`, which live in
their own top-level `limits` section. That section is new: the same two keys
under `network` are now **refused** (the error names `limits`), so a profile
written before it has to move them.

Paths may use `$CWD`, `$HOME`, `$USERPROFILE`, `$TEMP`, `$LOCALAPPDATA`,
`$APPDATA`, `$JAVA_HOME` and `$SID` — a closed set, listed by the error if you use
another one. `%VAR%` is **not** expanded and is refused like any other unknown
token: a profile that keeps `$NOPE/tools` as a literal directory name grants
nothing, and one that expands to an empty string grants the working directory. A
token whose variable is not set in the environment is refused too, naming both,
because an empty expansion is a different path than the profile says. `$JAVA_HOME`
is the reason the set exists: shipped profiles name the toolchain, not one
machine's JDK version (`jvm.json` grants `$JAVA_HOME` read-only, so the same file
keeps working after a JDK upgrade). Inspect the result with
`saife profile show <name> --expanded`.

```powershell
saife profile list
saife profile show demo                # the file as written
saife profile show demo --expanded     # extends flattened, variables expanded
saife run --profile demo --allow-cwd -- cmd /c C:\Users\you\.cargo\bin\cargo.exe --version
```

### 5.0 Composing profiles

`--profile` takes exactly **one** name (or a file path). Composition is done with
`extends`, not with repeated flags:

```json
{
  "meta": { "name": "opencode", "version": "1.0.0", "schema_version": 1 },
  "extends": ["node", "jvm"],
  "filesystem": { "allow": ["$USERPROFILE/.gradle"] },
  "network": { "allow_domain": ["repo.maven.apache.org"] }
}
```

`extends` takes one parent (`"extends": "node"`) or several
(`"extends": ["node", "jvm"]`). A child inherits its parents' grants: lists
(`filesystem.allow`/`read_only`/`deny`, `network.allow_domain`/`deny_domain`) are
concatenated and deduplicated, and anything the child sets itself wins.

Settings that only make sense once — the timeouts, `block_net`, the network
profile, the prompt and upstream settings — must **agree** across the parents. If
two parents set the same one differently and the child does not decide, the
profile is refused and the message names the key and both parents:

    [saife] profile show: `network.block_net` conflicts between parents `a` and `b`:
    true vs false — set it in the child to choose, or make the parents agree

That refusal is deliberate: silently letting the last parent win would mean a
session running on a policy the file does not visibly state. The order of the
array does not matter, a parent reachable through two paths is merged once, and a
cycle is still refused. CLI flags (`--allow`, `--read-only`,
`--allow-domain`, `--deny-domain`) append on top of whatever the profile says, so
a one-off extra grant does not need a profile at all.

Verified: a child that extends `node` and adds `$USERPROFILE/.gradle` produced a
session whose audited `fs_readwrite` contained the workspace, `npm-cache`,
`AppData\Roaming\npm` **and** `.gradle`.

Session deadline is `limits.promptTimeoutSecs + limits.workloadTimeoutSecs +
slack` (defaults 60 s + 30 min + 2 min). Both terms live in the top-level
`limits` section — the deadline bounds the session, not the network policy, so a
`--block-net` session uses the same terms. If a build or download legitimately
runs longer, raise `limits.workloadTimeoutSecs` up to the cap of seven days
(604800 s; `promptTimeoutSecs` accepts `0` = instant deny up to the same cap) —
there is no unlimited mode. The cap is a guard against a typo, not a platform
limit: an out-of-range value warns and falls back to the default. A session that
stops doing anything still holds its deadline, so a seven-day term is a backstop
for a run you meant to leave going, not a substitute for supervising it.

### 5.1 Ready-made profiles

`profiles/` in the repository ships working samples with the reasoning for every
path and host, and the verified status of each:

| profile | covers | verified |
|---|---|---|
| `node.json` | Node.js, npm (cache, global prefix, nvm trees) | `npm install` + `require` inside the sandbox |
| `jvm.json` | JDK, Gradle, Maven (`~/.gradle`, `~/.m2`) | `javac`/`java` yes; **Gradle no** — its daemon needs loopback |
| `opencode.json` | the opencode TUI and its state directories | TUI renders, keys work, model round-trip |

Copy one to `%USERPROFILE%\.saife\profiles\` and use `--profile <name>`. Two
Windows facts they document: batch shims (`npm`, `gradle`, `mvn`, `npx`) need
`cmd /c "npm ..."`, because the launcher does not apply `PATHEXT`; and Gradle's
daemon cannot connect over loopback under this backend, so Gradle builds belong
on `--backend appcontainer` (or wait for a policy decision on loopback egress).

---

## 6. Plugins (sidecars)

A **plugin** is a small HTTP service that runs on the host — outside the
container — and is reachable from inside the session only as
`http://<mount>.sandbox.invalid/` through the proxy. The workload holds no
credential for it: the facade hop carries a per-session token that never enters
the container.

A plugin is a directory with a manifest:

```
%USERPROFILE%\.saife\plugins\<name>\plugin.json
```

`--plugin <name>` loads one (repeatable). `--plugin-dir <PATH>` adds another
root, searched **before** the global one, in the order given (repeatable). The
first root that holds the name wins; a later copy is shadowed, never merged.

**Nothing inside a workspace is discovered automatically.** A cloned repository
must not gain host-side code execution from the act of running `saife run` in
it, so repo-local plugins are usable only when you name the directory:

```powershell
saife run --plugin-dir .\.saife\plugins --plugin tngtech -- <workload>
```

Plugins are wired on `--backend mxc` (the default) only, and they need the
session proxy: `--block-net` refuses `--plugin`.

### The sample: `tngtech`

`plugins/tngtech/` in this repository is a stdlib-only Python sidecar that serves
`https://www.tngtech.com/` at `GET /`; `GET /status` is its health probe. It
proves the transport end to end before any secret handling exists.

```powershell
New-Item -ItemType Directory -Force "$env:USERPROFILE\.saife\plugins" | Out-Null
Copy-Item -Recurse -Force plugins\tngtech "$env:USERPROFILE\.saife\plugins\"
cargo build --bin saife --bin saife-launch
target\debug\saife.exe run --no-prompt --plugin tngtech -- cmd /c "curl.exe -s -o NUL -w facade=%{http_code} http://tngtech.sandbox.invalid/ & curl.exe -s -o NUL -w direct=%{http_connect} https://www.tngtech.com/"
```

Expected, in one session: `facade=200` (the homepage came through the facade) and
`direct=403` (the container's own egress is still denied — no `--allow-domain`
was granted). The session's proof line agrees: `tunnels=0`.

`--no-prompt` is there to keep the deny half deterministic. An unattended run has
no dialog to answer, and a prompt that IS answered with "allow and remember this
host" writes a learned entry that legitimately admits it — check
`saife learned list`, and `saife learned clear` resets it.

Requirements: working internet, a `python` on `PATH` (resolved as
`python.exe`; `.cmd`/`.bat` entry points are refused), and the plugin installed
under `%USERPROFILE%` — the sidecar runs on the host, not in the container.

A plugin that cannot be loaded, spawned or made healthy **refuses the session**
with exit code **5** and one line naming the plugin and the reason, e.g.
`sidecar_unhealthy{tngtech}: …` or
`plugin_not_found: tngtech (searched: --plugin-dir C:\x\plugins, %USERPROFILE%\.saife\plugins)`.
There is no "run without it" fallback. Sidecars are killed on every exit path,
before the proxy that routes to them goes away.

What the facade carries today: `GET` only (anything else is
`501 facade_method_unsupported`), an undeclared mount is `404 facade_unknown_mount`,
and `CONNECT <mount>.sandbox.invalid:443` is `403 facade_requires_http` so TLS
cannot be tunnelled past the check. Every facade request writes one audit leaf:

```powershell
saife audit show <sid> --filter 'op=FACADE'
```

Not in this POC: secret resolution, non-GET methods, per-operation enforcement by
the supervisor, AppContainer wiring, and `saife plugin list`.

---

## 7. Reading the proof line

Every successful session prints, on stderr:

```text
[saife] mxc: guardrail 1 proof probes=1 accepted=1 tunnels=1 unauthenticated=0
```

| Field | Meaning |
|---|---|
| `probes` | the wrapper's own pre-flight probe reached this run's proxy |
| `accepted` | requests this run authenticated and the policy decided |
| `tunnels` | upstream connections actually established |
| `unauthenticated` | requests that reached the proxy **without** this run's credential |

A session is refused when the probe never arrived (`proxy_probe_unmet` — the
child could not reach the proxy at all) or when something tried and nothing ever
authenticated (`workload_cannot_authenticate` — the GUI/system-proxy class;
remedy: `--backend appcontainer`).

---

## 8. Audit

Every run writes `%LOCALAPPDATA%\saife\audit\<sid>.ndjson` plus a signed root.

```powershell
saife run --allow-cwd --print-sid -- cmd /c echo audit-demo     # prints the session id
saife run --allow-cwd --sid 20261022-205214-43984 -- cmd /c echo audit-demo
saife audit show 20261022-205214-43984
saife audit show 20261022-205214-43984 --json --filter 'disposition=deny'
saife audit verify 20261022-205214-43984
```

`show` gives a per-session summary and the events by type; `--filter` takes
`key=value`, `key~=substring`, `key>=number` joined with `&`. `verify` recomputes
the chain and checks the signature:

- `OK` — the chain is intact and matches the signed root.
- `INCOMPLETE` — the session did not end cleanly (for example the supervisor was
  killed). The leaves that were written are still readable and still chained;
  that is the point of writing the root before the child starts.

### What the audit does and does not answer

`SESSION_START` also records the **enforced filesystem posture**, so a question
like "was `.ssh` really denied in that session?" is answered from the record
instead of from the profile on disk (which is not necessarily what the launch
used):

```powershell
saife audit show 20261022-224340-89068 --json --filter 'fs_deny~=.ssh'
saife audit show 20261022-224340-89068 --json --filter 'fs_readwrite~=opencode'
```

* `fs_workspace` — the working directory the session ran in.
* `fs_readwrite` / `fs_readonly` / `fs_deny` — the granted and denied paths, as
  enforced. These are arrays: `=` matches any element, `~=` matches any element
  containing the text.

They appear on `mxc` sessions. The AppContainer path does not record them yet
(its DACL grants are computed later in the run).

What the audit cannot answer is what was **attempted**: the backend reports no
denial events, so a refused file open leaves no trace. The record states the
policy, not the accesses — for that, run with the failure in view.

The `SESSION_START` leaf records the containment tier (`tier`, `tier_source`,
`tier_needs_dacl_augmentation`), whether the supervisor was `elevated`, and the
`proxy_endpoint`. A refused session carries `disposition: deny` on the root plus
a `SESSION_REFUSED` leaf naming the reason.

Learned (permanent) prompt decisions:

```powershell
saife learned list
saife learned revoke api.example.com
saife learned clear
```

---

## 9. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `failed to start '<tool>': ... file not found` | the tool's directory is not granted, so the path is invisible | `--read-only <dir>` and/or an absolute path |
| `denied path ... contains the granted path` | a `deny` in the profile covers a writable grant | deny a subdirectory instead of the whole tree, or move the grant |
| `workload_cannot_authenticate` | the workload's client stack cannot use a proxy (WinINet, PS 5.1) | `--backend appcontainer` |
| `proxy_probe_unmet` | the child never reached the proxy (loopback blocked, dead listener, wrong credential) | check the run is unelevated/loopback is reachable; report with the leaf |
| The run seems to hang on an unlisted host | a prompt is waiting in a context with no dialog | `--no-prompt`, or set `onUnavailable` |
| `this build was made with --no-default-features ... falling back` | the binary was built without the default backend | rebuild without `--no-default-features` |
| `audit verify` says `INCOMPLETE` | the session did not end cleanly | expected after a kill; the leaves are still valid evidence |
| PowerShell prints `InitializeDefaultDrives ... provider "FileSystem"` | PS 5.1 startup noise in the container's filesystem view | ignore |

---

## 10. Limits

- **GUI and system-proxy applications** have no egress on `mxc`; use
  `--backend appcontainer`.
- **One session per supervisor** on `mxc`; a second concurrent run is refused.
- **`appcontainer` needs admin** for networked sessions (loopback exemption).
- **Windows version support rests on ADR-0004's reading of the MXC SDK's build
  list** (Windows 11 24H2 / build 26100 or later). The per-build test matrix is
  still to come (plan step P5); until then the tested images are Insider builds,
  so treat other builds as untested rather than supported.
- **Sibling-session isolation inside a workspace** is not expressible on `mxc`:
  the filesystem policy is additive over the workspace, so two sessions share
  what the workspace already allows.
