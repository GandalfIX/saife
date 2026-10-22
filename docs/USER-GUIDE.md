# User guide

How to run things under `sandbox`, and what to do when it says no.

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
  inspect afterwards (`sandbox audit show|verify`).

The program you run is unchanged; it just cannot reach anything you did not
grant.

```powershell
sandbox run --allow-cwd -- cmd /c echo hello
```

```text
hello
[sandbox] mxc: guardrail 1 proof probes=0 accepted=0 tunnels=0 unauthenticated=0
```

The `[sandbox] mxc: guardrail 1 proof ...` line is the supervisor telling you
what it proved about this run — see §6.

---

## 2. Running simple tools

### 2.1 A command that needs only its working directory

```powershell
cd C:\work\myproject
sandbox run --allow-cwd -- cmd /c build.bat
```

### 2.2 Build tools (cargo, npm, …)

The toolchain lives **outside** the workspace, and every path outside the
workspace is denied by default. Grant it read-only:

```powershell
sandbox run --allow-cwd `
  --read-only C:\Users\<you>\.cargo `
  --read-only C:\Users\<you>\.rustup `
  -- cmd /c C:\Users\<you>\.cargo\bin\cargo.exe build
```

Verified here:

```text
cargo 1.98.1 (797e8a9bc 2026-08-05)
[sandbox] mxc: guardrail 1 proof probes=0 accepted=0 tunnels=0 unauthenticated=0
```

> **If you see `failed to start 'cargo': ... file not found (0x80070002)`**, the
> grant is missing — not the install. A denied path reaches the child as
> "file not found". Add `--read-only <toolchain dir>` and try again.

### 2.3 Interpreters and scripts

Same rule: grant the interpreter's directory and call it by absolute path.

```powershell
sandbox run --allow-cwd --read-only C:\Python312 -- C:\Python312\python.exe .\script.py
```

### 2.4 PowerShell one-liners

`powershell` (5.1) runs inside the container. Expect one harmless startup line
on the `mxc` backend (`InitializeDefaultDrives ... FileSystem provider`); it comes
from the container's restricted filesystem view, not from your command.

```powershell
sandbox run --allow-cwd -- powershell -NoProfile -Command "Get-ChildItem | Measure-Object"
```

### 2.5 An AI coding agent

Give the agent its project and the hosts it may talk to:

```powershell
sandbox run --allow-cwd `
  --allow-domain api.anthropic.com `
  --allow-domain github.com `
  --allow-domain '*.githubusercontent.com' `
  -- claude
```

An agent that only needs local work gets no network at all:

```powershell
sandbox run --allow-cwd --block-net -- opencode
```

Two hard limits worth knowing before you put an agent behind this:

- **One run per supervisor process.** A second concurrent `sandbox run` on the
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
sandbox run --allow-cwd --read-only C:\data -- powershell -NoProfile -Command "Get-Content C:\data\notes.txt"
# secret-data

sandbox run --allow-cwd --read-only C:\data -- powershell -NoProfile -Command "Set-Content C:\data\new.txt x"
# UnauthorizedAccessException: Access to the path 'C:\data\new.txt' is denied.
```

A **writable** grant outside the workspace is honoured on both backends
(P3.4). That is what makes a tool which keeps state in your profile usable —
opencode, for instance, writes `~/.local/share/opencode`, `~/.cache/opencode`,
`~/.config/opencode` and `~/.local/state/opencode`:

```powershell
sandbox run --profile opencode --allow $HOME\.local\share\opencode `
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
sandbox run --profile opencode --allow-cwd `
  --read-only "$env:LOCALAPPDATA\Microsoft\WinGet" -- opencode
```

The `--read-only` grant is only for *finding* the executable: an installed
program lives in a directory the container cannot see, so its name does not
resolve on the inherited `PATH`. Grant its install tree read-only and the bare
name works. Everything opencode *writes* comes from its profile
(`~/.local/share/opencode`, `~/.cache/opencode`, `~/.config/opencode`,
`~/.local/state/opencode`), which the profile grants writable.

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
sandbox run --allow-cwd --block-net -- cmd /c echo offline
```

No proxy is started and every `connect()` is kernel-denied.

### 4.2 Allowing hosts

```powershell
sandbox run --allow-cwd --allow-domain api.anthropic.com --no-prompt -- `
  cmd /c C:\Windows\System32\curl.exe -sS --ssl-no-revoke -o NUL -w "http_code=%{http_code}" https://api.anthropic.com/
```

```text
http_code=404
[sandbox] mxc: guardrail 1 proof probes=1 accepted=1 tunnels=1 unauthenticated=0
```

`404` is the origin answering — the sandbox admitted the tunnel (`tunnels=1`).
That distinction matters: **the sandbox's decision is the proxy result, not the
origin's status.**

### 4.3 Denying wins

```powershell
sandbox run --allow-cwd --allow-domain '*.anthropic.com' --deny-domain api.anthropic.com --no-prompt -- `
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
`sandbox learned list`.

`--no-prompt` disables the dialog entirely: unlisted hosts are denied (or
allowed, per the profile's `onUnavailable`). In a headless context — CI, a
service, a container — there is no dialog to answer, so after two consecutive
unanswered consultations the configured `onUnavailable` policy applies
immediately instead of waiting out the prompt budget per host.

---

## 5. Profiles

A profile is a JSON file in `%USERPROFILE%\.sandbox\profiles\<name>.json`:

```json
{
  "meta": { "name": "demo", "version": "1.0", "description": "Docs example", "schema_version": 1 },
  "filesystem": {
    "read_only": ["C:/Users/you/.cargo", "C:/Users/you/.rustup"]
  },
  "network": {
    "allow_domain": ["api.anthropic.com"],
    "promptEnabled": false,
    "workloadTimeoutSecs": 3600
  }
}
```

`meta.schema_version` is **required**. Fields are snake_case, except the network
options `denyDomain`, `promptEnabled`, `onUnavailable`, `promptTimeoutSecs` and
`workloadTimeoutSecs`.

```powershell
sandbox profile list
sandbox profile show demo      # resolved contents, including inherited fields
sandbox run --profile demo --allow-cwd -- cmd /c C:\Users\you\.cargo\bin\cargo.exe --version
```

Session deadline is `promptTimeoutSecs + workloadTimeoutSecs + slack`
(defaults 60 s + 30 min + 2 min). If a build or download legitimately runs
longer, raise `workloadTimeoutSecs` — there is no unlimited mode.

---

## 6. Reading the proof line

Every successful session prints, on stderr:

```text
[sandbox] mxc: guardrail 1 proof probes=1 accepted=1 tunnels=1 unauthenticated=0
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

## 7. Audit

Every run writes `%LOCALAPPDATA%\sandbox\audit\<sid>.ndjson` plus a signed root.

```powershell
sandbox run --allow-cwd --print-sid -- cmd /c echo audit-demo     # prints the session id
sandbox run --allow-cwd --sid 20261022-205214-43984 -- cmd /c echo audit-demo
sandbox audit show 20261022-205214-43984
sandbox audit show 20261022-205214-43984 --json --filter 'disposition=deny'
sandbox audit verify 20261022-205214-43984
```

`show` gives a per-session summary and the events by type; `--filter` takes
`key=value`, `key~=substring`, `key>=number` joined with `&`. `verify` recomputes
the chain and checks the signature:

- `OK` — the chain is intact and matches the signed root.
- `INCOMPLETE` — the session did not end cleanly (for example the supervisor was
  killed). The leaves that were written are still readable and still chained;
  that is the point of writing the root before the child starts.

The `SESSION_START` leaf records the containment tier (`tier`, `tier_source`,
`tier_needs_dacl_augmentation`), whether the supervisor was `elevated`, and the
`proxy_endpoint`. A refused session carries `disposition: deny` on the root plus
a `SESSION_REFUSED` leaf naming the reason.

Learned (permanent) prompt decisions:

```powershell
sandbox learned list
sandbox learned revoke api.example.com
sandbox learned clear
```

---

## 8. Troubleshooting

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

## 9. Limits

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
