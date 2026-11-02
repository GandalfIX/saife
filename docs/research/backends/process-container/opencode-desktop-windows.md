# opencode desktop on Windows: what actually happens under a saife session

**Status:** measured on a real install, 2026-10-30, Windows 11 (build 26300), `saife` 0.3.1 + the
unreleased resolver fix, `mxc` GA (`mxc-sdk 1.0.1`), unelevated. Every row below is an observation,
not a reading of opencode's source.

This is the §6 A/B evidence for
[`docs/plans/2026-10-29-opencode-desktop-profile.md`](../../plans/2026-10-29-opencode-desktop-profile.md),
which guessed several paths from the product name. Two of those guesses are wrong (§1), and the
topology the plan recommends (§3, "server inside, desktop outside") **does not work** — not because
of opencode, but because host→container ingress is not usable under `mxc` (§3).

---

## 1. The install is named by appId, not product name

| plan said (§1.1) | measured | note |
|---|---|---|
| `%LOCALAPPDATA%\Programs\OpenCode` | `%LOCALAPPDATA%\Programs\ai.opencode.desktop` | `OpenCode.exe` lives here; `...\Programs\OpenCode` does not exist |
| `%APPDATA%\OpenCode` | `%APPDATA%\ai.opencode.desktop` | Electron `userData`; holds `cli\`, `Cache`, `Local Storage` |
| `…\cli\<version>-<arch>\opencode-cli.exe` | `%APPDATA%\ai.opencode.desktop\cli\2.2.2-x64\opencode-cli.exe` | correct shape, wrong root |
| `resources\opencode-cli.exe` + `.version` | present, version file reads `2.2.2` | same version as the staged copy |
| userData ≠ install dir | confirmed | install dir is read-only for the sandbox; userData is read-write |

A profile written from the product name grants two directories that a real install never creates.
That is not a cosmetic error: the server writes its registration and the staged CLI into userData,
so a wrong userData grant means a server that cannot register at all.

`profiles/opencode-desktop.json` now carries the measured paths.

## 2. The app adopts only a healthy, version-compatible service

Measured with the app running normally:

| fact | value |
|---|---|
| registration file | `%USERPROFILE%\.local\state\opencode\service.json` |
| content (secret redacted) | `url: http://127.0.0.1:28894`, `version: 2.2.2`, `pid: <server>` |
| listening socket | `127.0.0.1:28894`, owned by `opencode-cli.exe` under `…\cli\2.2.2-x64\` |
| bundled CLI | `…\resources\opencode-cli.exe`, `opencode-cli.version` = `2.2.2` |

Windows port remap confirmed: `0xC0DE` → `28894`.

`auth.json` on this machine targets providers `anthropic`, `skainet`, `skainet-external`,
`trustedtokens`. The shipped profiles allow only `*.trustedtokens.eu`, so three of the four
providers are refused by the proxy regardless of the sandbox. Keys were not read.

## 3. The split topology fails on ingress, and fails safely

Attempt: `saife run --profile opencode-desktop --allow-cwd -- "<install>\resources\opencode-cli.exe"
serve --service` under `--backend mxc`, unelevated; then `OpenCode.exe` launched normally.

| leg | result |
|---|---|
| sandboxed server starts, binds, registers | **ok** — `service.json` written with the sandboxed `pid`, listener on 28894 |
| desktop launched outside | **spawns its own** `opencode-cli.exe` from `%APPDATA%\…\cli\2.2.2-x64\`, i.e. outside the sandbox |
| that second server | **cannot bind** (the sandboxed one holds 28894) and exits |
| host → `127.0.0.1:28894` | **TCP connect times out** (registered socket visible in the host's TCP table) |
| desktop UI | disconnected: it neither adopted the sandboxed server nor got a working one of its own |

Two facts follow, and they are the important ones:

1. **Inbound is not a supported direction — by design, not by accident.** `src/net/mxc.rs` sets
   `ingress.default = allow` + `ingress.host_loopback = allow` whenever a proxy exists, but those
   fields are the ADR-0004 requirement for the *container → supervisor proxy* path, not a grant that
   outside processes may connect in. Measured with a probe listener inside a session, in **both**
   postures (`--block-net` and proxy + `allow_domain`): the host's `connect()` **times out** (not
   refused — the socket is visible in the host's TCP table), and the container cannot connect to
   **its own** loopback listener either: `10013`. Loopback is closed in both directions; the single
   cross-boundary channel is the proxy, and it is one-directional. Reading this as broken ingress
   would send the next reader looking for a bug that does not exist.
2. **The containment trap is real but self-limiting.** The desktop spawned an unsandboxed server
   exactly as §3.3 predicts. It did not take over the session because the fixed port was already
   bound, and the registration file kept pointing at the sandboxed pid. So the failure mode is "no
   containment *and* no UI", never "silent unsandboxed agent" — in this configuration.

## 4. Why the other placements do not rescue it

| placement | wall |
|---|---|
| all-in-one under `mxc` | renderer → server is loopback **inside** the container → `WSAEACCES 10013` (same wall as the Gradle daemon) |
| split under `mxc` | host → container ingress (§3, measured) |
| either under `appcontainer` | DACL propagation stops at 20 000 objects; opencode's state tree exceeds it, so the grants are truncated and the session is not the one the profile describes |

## 5. What would make it work

Only one of these is small:

- **Loopback egress (sibling plan) + all-in-one.** Once a session may connect to `127.0.0.1:28894`,
  the renderer and the server can live in the *same* container and talk to each other over container
  loopback — no ingress needed. This inverts the plan's recommendation: the all-in-one shape becomes
  the intended answer, and the risk to accept is Electron under a ProcessContainer (GPU, shared
  memory, single-instance lock) — unproven, per §5.7.
- **Ingress support in `mxc`** (host → container connect) — a product gap, not a profile fix; it also
  widens the boundary for every session, so it wants a decision, not a patch.
- **A supervisor relay** for the service port — a byte-stream tunnel through the supervisor, i.e. a
  new hole that has to be reasoned about per connection; rejected in the sibling plan for the Gradle
  case for the same reason.

## 6. Reproduce

```powershell
# 1. no host server may be running (fixed port + shared registration file)
Get-Process OpenCode,opencode-cli -ErrorAction SilentlyContinue | Stop-Process
Get-NetTCPConnection -LocalPort 28894 -State Listen      # must be empty

# 2. sandbox the server, from a project dir (not a tree holding saife-launch.exe)
saife run --profile opencode-desktop --allow-cwd -- `
  "$env:LOCALAPPDATA\Programs\ai.opencode.desktop\resources\opencode-cli.exe" serve --service

# 3. the desktop, outside
& "$env:LOCALAPPDATA\Programs\ai.opencode.desktop\OpenCode.exe"

# 4. the measurements above
(Get-Content "$env:USERPROFILE\.local\state\opencode\service.json" | ConvertFrom-Json).pid
(Get-NetTCPConnection -LocalPort 28894 -State Listen).OwningProcess
Test-NetConnection 127.0.0.1 -Port 28894                  # TcpTestSucceeded: False (times out)
Get-Process opencode-cli | Select-Object Id,Path         # a second, unsandboxed one appears
```

**Cleanup after each block** (AGENTS.md): stop every `OpenCode`, `opencode-cli`, `saife` and
`saife-launch` process; confirm 28894 is free. No ACLs were written on the host in these legs —
`mxc` sessions do not leave host DACLs — so nothing else needs unwinding.
