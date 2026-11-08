# `opencode` profile

For running the opencode agent CLI (`opencode`, `opencode run`, `--standalone`)
inside the sandbox, so its shell commands, edits and tool calls stay contained.

## Why it extends `node` AND `jvm`

`extends: ["node", "jvm"]` is not decoration — it is what the tool actually
needs, and both halves are load-bearing:

- **node** — opencode is distributed as a Node program (npm/winget package).
  It boots a Node runtime, resolves its own CLI through npm machinery, and
  installs/updates plugins through the npm registry. Without the `node` grants
  and the `registry.npmjs.org` decision, `npx`/plugin operations fail and the
  PATH-adjacent install directory is unreadable (see `node.README.md`).
- **jvm** — what the *agent does*, not what opencode is built from. The agent
  is asked to work on Java projects: `javac`, `mvn`, `gradle`, and it reads and
  writes `~/.gradle` / `~/.m2`. An agent that cannot see the JDK produces
  confident nonsense about Java code, so the JDK is granted read-only and the
  build caches read-write.

Multi-parent `extends` (merged) exists precisely so this profile does not have
to restate either parent. The retired `node-jvm.json` was the single-parent
workaround.

## Grants, and why each is what it is

| grant | why |
|---|---|
| `allow: $CWD` | the project the agent works on. |
| `allow: $HOME/.local/share/opencode`, `~/.local/state/opencode`, `~/.cache/opencode`, `~/.config/opencode`, `%APPDATA%\opencode`, `%LOCALAPPDATA%\opencode` | opencode's own state: config, sessions/database, caches, logs. The agent cannot function without writing these (a session store is how v2 works). |
| `read_only: $HOME/.gitconfig` | git identity for commits; nothing should rewrite it. |
| `read_only: $HOME/.local/bin` | where `opencode.exe` and the `uv` shims live. **RX**: launchable, not replaceable — a workload that can overwrite the binary it runs from is the launcher hazard again, one level out. Measured reason it must be granted at all: an unreadable PATH directory is reported as `0x80070002` (file not found) by `CreateProcess`, which sent a previous user chasing a phantom missing binary. |
| `read_only: $APPDATA/uv` | `uv`-managed Python interpreters. The `python.exe` shim starts, then fails with `uv trampoline failed to spawn Python child process … os error 5` when the interpreter tree is unreadable. Agents run Python constantly; this is the Python half of "the agent can work". |
| `read_only: %LOCALAPPDATA%\Microsoft\WinGet` | opencode's winget package directory — this is where the installed launcher actually lives on a winget install. |
| `deny: $HOME/.ssh`, `$HOME/.aws` | the agent must never read your keys, whatever it is asked to do. Note the consequence: agents cannot `git push` over SSH or use `ssh` directly. That is the intent; use the `ssh-gateway` plugin when a workload needs SSH. |

## Network

- `*.trustedtokens.eu` — the model API. The whole profile is pointless without it.
- `models.opencode.ai` — the model **catalogue** opencode is built on. opencode
  keeps no static model list: at start-up, and then on a five-minute refresh, it
  fetches `api.json` from this host and rebuilds its **provider registry** from
  that answer. The model list the TUI shows, the provider a prompt is routed to,
  and the per-model capability metadata all come from the catalogue. The local
  cache is a convenience, not a fallback: a failed fetch leaves the registry
  without providers, and a session with an empty registry cannot route a prompt —
  it stalls because there is no model to send to. So this host is not an
  ordinary third-party endpoint to be prompted about; it is part of how the tool
  resolves its own models, and it belongs in the allow-list beside the model API
  it complements.

Everything else — npm registry included, via `node` — stays a per-host prompt.

## Limits

`workloadTimeoutSecs: 14400` — four hours. Agent sessions are long; the budget
is `prompt + workload + slack`, and the default 30 minutes ends a session
mid-thought. A deadline hit is exit code 124 with the audit root still sealed.

## Operating notes

- **Use `--standalone`.** Without it, the CLI attaches to the *shared* opencode
  service — and if that service runs on the host (it usually does), every tool
  call executes **outside** the sandbox, with your full rights. With
  `--standalone` the server is born inside the session and containment applies
  to the tools. On hosts where the shared service holds port `28894`, a
  non-standalone in-session start also dies with "port already in use".
- **`--allow-host-loopback` is not the fix for loopback needs**; it opens
  loopback *unscoped* (every host service, no decision point). Prefer
  `--standalone`, and reach host services through a plugin facade.
- opencode logs `failed to watch directory … EPERM` for ungranted paths
  (`C:\Users`, `C:\ProgramData`). Harmless: file-watching degrades, the session
  does not.
