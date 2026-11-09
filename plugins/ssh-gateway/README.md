# ssh-gateway — a credentialed SSH sidecar

A **plugin sidecar** that runs declared `ssh` verbs on declared hosts for a
sandboxed workload. The SSH keys live host-side (typically `%USERPROFILE%\.ssh`)
and never enter the container; the workload talks plain HTTP to the facade mount
`http://ssh.sandbox.invalid/` and receives the remote bytes.

This is the TNG-sidecar pattern applied to SSH: the credential holder and the
network dial live outside the sandbox, the workload only names an operation.

## Install

```powershell
New-Item -ItemType Directory -Force "$env:USERPROFILE\.saife\plugins" | Out-Null
Copy-Item -Recurse -Force plugins\ssh-gateway "$env:USERPROFILE\.saife\plugins\"
```

Write your hosts to `%USERPROFILE%\.saife\ssh-gateway.json` (see
`ssh-gateway.example.json`). The sidecar reads that file at session start; a
missing or broken file means zero hosts, never a crash.

The plugin ships an **empty** `known_hosts` beside `sidecar.py`, and every ssh
it spawns runs with `UserKnownHostsFile=<that file>` and
`StrictHostKeyChecking=yes` (see *Host keys* below). Seed it before the first
session or every verb refuses with `502 host_key_unknown`.

`ssh.exe` must exist: the Windows *OpenSSH Client* optional feature, or any ssh
on `PATH`. The sidecar resolves it **once at startup** —
`%SystemRoot%\System32\OpenSSH\ssh.exe` first, then `PATH` — and refuses to
start with `ssh_executable_not_found` when nothing resolves, instead of spawning
a bare name a file in the plugin directory could shadow.

### Host keys: seed `known_hosts` once per host

`ssh-keyscan` is the supported seeding tool. Run it on the host you trust, then
review the line before it is trusted:

```powershell
ssh-keyscan -p 22 logs.example.invalid >> "$env:USERPROFILE\.saife\plugins\ssh-gateway\known_hosts"
```

Pin a key type when you want an exact algorithm:

```powershell
ssh-keyscan -p 22 -t ed25519 logs.example.invalid >> "$env:USERPROFILE\.saife\plugins\ssh-gateway\known_hosts"
```

A per-host `"known_hosts": "%USERPROFILE%\.saife\srv1.known_hosts"` entry in the
gateway JSON overrides the plugin-local file for that one host.

There is deliberately **no** trust-on-first-use: the sidecar never writes to the
file and never touches `%USERPROFILE%\.ssh\known_hosts`, so an unknown key is a
refusal (`502 host_key_unknown` naming the file to seed), not a silent accept.

## Run

```powershell
saife run --profile <p> --plugin ssh-gateway -- <workload>
```

Inside the session:

```powershell
curl.exe -s http://ssh.sandbox.invalid/status
curl.exe -s http://ssh.sandbox.invalid/hosts
curl.exe -s -X POST -d "{\"host\":\"srv1\",\"verb\":\"version\"}" http://ssh.sandbox.invalid/exec
```

## Protocol

| request | answer |
|---|---|
| `GET /status` | `{"ok":true,...}` — health probe, no token |
| `GET /hosts` | declared hosts with their allowed verbs (no identity paths) |
| `POST /exec` | body `{"host":..., "verb":..., "args":..., "stdin":...}`; `200` + remote stdout, `502` + remote stderr, `403 host_not_declared` / `403 command_not_declared`, `400` malformed or unsupported framing, `502 host_key_unknown` (seed the plugin-local `known_hosts`) |

## Security invariants

1. **Declared hosts only.** An undeclared host, or a verb not in that host's
   `commands`, is refused before any process is spawned.
2. **Default-deny verbs.** `"commands": ["*"]` admits any verb *for that host* —
   generosity is per host, never per network.
3. **No shell lines.** `ssh` is spawned as an argv list; `verb` and `args` are
   charset-checked with a `\Z` anchor (no quotes, no `;`, no `$`, no trailing
   newline - `$` alone would accept `"list\n"` and a wildcard host would run two
   remote commands), so the sidecar cannot be used to inject remote shell syntax.
   A `verb` may not begin with `-`: it is a command name, and one that reads like
   an ssh option would be a trap for a future reordering of the argv (`run_ssh`
   refuses it with `400`). The same checks run twice on purpose - once in the
   HTTP handler, once again at the sink - because a sink that trusts its caller is
   one refactor away from trusting the network. A host entry whose `target`
   starts with `-` or contains whitespace, or whose numeric fields are not
   integers, is **dropped at load** with a named warning.
3b. **The user's ssh config does not govern the connection.** `ssh` runs with
   `-F ssh_config` (an empty file shipped beside the sidecar) and explicit
   `ClearAllForwardings=yes`, `ForwardAgent=no`, `PermitLocalCommand=no`, so a
   `~/.ssh/config` entry or `Match` block cannot add a `ProxyCommand`, forward the
   agent, or bind a local port behind the manifest's back.
3c. **Host keys are pinned, never trust-on-first-use.** ssh runs with
   `UserKnownHostsFile=<the plugin's own known_hosts>` and
   `StrictHostKeyChecking=yes`, so an unknown host key is a refusal (a named
   `502 host_key_unknown` carrying ssh's own error), not a silent accept — and
   the key is never appended to the user's global
   `%USERPROFILE%\.ssh\known_hosts`. Seed the plugin-local file with
   `ssh-keyscan` (see *Host keys* above); a per-host `known_hosts` entry
   overrides it for that host.
3d. **ssh is resolved once, absolutely.** The binary is resolved at startup
   (`%SystemRoot%\System32\OpenSSH\ssh.exe`, then `PATH`) and spawned by that
   absolute path — CreateProcess searches the child's cwd before System32, and
   the sidecar's cwd is the plugin directory, so a bare-name spawn could be
   shadowed by a dropped-in `ssh.exe`. No resolution, no start (exit 2,
   `ssh_executable_not_found`).
4. **Keys stay host-side.** The sidecar reads identities itself; `GET /hosts`
   never echoes identity paths.
5. **Bounded, and bounded in the right place.** `args`/`stdin` are size-capped;
   stdout is read through a **bounded reader**, so `max_output_mb` caps the
   sidecar's MEMORY and the child is killed at the cap (buffering first and
   checking afterwards bounds the reply, not the RSS). A spent `command_timeout`
   and a **hung-up client** both kill the child instead of leaving an orphan for
   the rest of the budget. `/exec` holds one of `max_concurrent` slots (default
   4); over-cap callers get a named `503 sidecar_busy` - a bound, not a queue, so
   one workload can neither exhaust the host nor flood the remote sshd into a
   fail2ban ban of its own account.
6. **Token-gated.** Everything except `/status` requires the per-session facade
   token; a caller that reaches the sidecar port directly cannot pass it.
7. **Audited twice, from both sides of the boundary.** The supervisor writes one
   `op=FACADE` leaf per call (mount, path, disposition, and the sidecar's HTTP
   status), and the sidecar writes one structured `EXEC` line to its log for
   every `/exec` - refused or run: `host`, `verb`, `args_len`, `args_sha256`
   (a digest, never the argument text), `stdin_bytes`, `status`, `outcome`,
   `exit`, `output_bytes`, `duration_ms`. The facade leaf answers "did the
   boundary open"; the EXEC line answers "what ran where, and how did it end" -
   the question an incident report actually asks.

   Note the transport reality: the facade body cap is 4 KiB, so `stdin` is a
   small JSON text field in practice (the sidecar's 4 MiB cap is unreachable
   through the proxy). Bulk data streams as the verb's **stdout** (e.g. a remote
   `tar czf -`), which is why `max_output_mb` is the knob that matters.

## Keep the server-side guard

This sidecar removes the KEY from the session, not the REMOTE from the
equation. Keep the sshd `ForceCommand` on the target account: it bounds what
any verb can do regardless of what this sidecar admits.
