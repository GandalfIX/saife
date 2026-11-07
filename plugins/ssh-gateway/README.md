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
| `POST /exec` | body `{"host":..., "verb":..., "args":..., "stdin":...}`; `200` + remote stdout, `502` + remote stderr, `403 host_not_declared` / `403 command_not_declared`, `400` malformed |

## Security invariants

1. **Declared hosts only.** An undeclared host, or a verb not in that host's
   `commands`, is refused before any process is spawned.
2. **Default-deny verbs.** `"commands": ["*"]` admits any verb *for that host* —
   generosity is per host, never per network.
3. **No shell lines.** `ssh` is spawned as an argv list; `verb` and `args` are
   charset-checked (no quotes, no `;`, no `$`), so the sidecar cannot be used to
   inject remote shell syntax.
4. **Keys stay host-side.** The sidecar reads identities itself; `GET /hosts`
   never echoes identity paths.
5. **Bounded.** `args` and `stdin` are size-capped, output is capped at
   `max_output_mb`, every ssh call has a timeout.
6. **Token-gated.** Everything except `/status` requires the per-session facade
   token; a caller that reaches the sidecar port directly cannot pass it.
7. **Audited.** Every facade request writes one `op=FACADE` audit leaf —
   unlike a direct host-side ssh, which leaves nothing.

## Keep the server-side guard

This sidecar removes the KEY from the session, not the REMOTE from the
equation. Keep the sshd `ForceCommand` on the target account: it bounds what
any verb can do regardless of what this sidecar admits.
