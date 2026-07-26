# sandbox

A native Windows process-sandboxing tool that runs any program — primarily
AI coding agents (Claude Code, OpenCode, Codex, …) and their build
toolchains — with only the resources the user has explicitly granted.

Pure Win32 / NT kernel primitives, a single unprivileged Rust binary, no
container runtime, no daemon, no VM. Windows-native equivalent of
[nono](https://nono.sh/) without WSL.

## Status

MVP, under active development. Implemented pillars:

- **Filesystem isolation** (US-1, US-2) — AppContainer + per-directory
  DACL allow-lists, irrevocable for the lifetime of the process tree.
- **Network filtering (partial)** (US-3) — `--block-net` works fully
  unprivileged; `--allow-domain` / `--network-profile` are deferred
  pending an unprivileged loopback mechanism (see
  [Network filtering status](#network-filtering-status) below).
- **Audit trail** (US-4) — planned.

Out of scope for the MVP: undo/rollback, credential injection, ghost
sessions, runtime supervisor, Sigstore provenance, GUI/TUI, multi-user
mode. See `docs/prd/prd-sandbox.md` for the full PRD and
`docs/future-ideas.md` for the deferred roadmap.

## Requirements

- Windows 10 1709 (build 16299) or later — AppContainer RuleSet requires it.
- No admin rights needed to run `sandbox` (the design goal is unprivileged).
- Rust toolchain (for building; only needed by developers, not end users).

## Build

```powershell
cargo build --release
.\target\release\sandbox.exe setup --check-only
```

`setup --check-only` reports the host build number, AppContainer
availability, Job Object availability, and the network proxy status. It
exits non-zero if the host is below the minimum build or any required
capability is missing.

## Usage

### Run a command in the sandbox

```powershell
sandbox run --allow-cwd -- cmd /c echo hello
```

`--allow-cwd` grants read+write+execute on the current working directory.
The sandboxed process can read and write your project tree but cannot
read `~/.ssh`, `~/.aws`, sibling project directories, or anything else
not explicitly listed.

### Grant additional paths

```powershell
# Read+write+execute (default):
sandbox run --allow-cwd --allow $HOME\.claude -- claude

# Read-only:
sandbox run --allow-cwd --read-only $HOME\.gitconfig -- cmd /c type %USERPROFILE%\.gitconfig

# Read-only with explicit mode:
sandbox run --allow-cwd --allow $HOME\.npm:read -- npm install
```

`--allow <path>` (repeatable) grants access on an additional path. Format:
`<path>[:<mode>]` where mode is `read|write|readwrite|execute` (default
`readwrite` = read+write+execute). `--read-only <path>` (repeatable) is a
shorthand for `--allow <path>:read`.

The leading `C:` drive-letter colon is NOT treated as a mode separator.

### Block all network access

```powershell
sandbox run --allow-cwd --block-net -- cmd /c echo no-network
```

`--block-net` removes the AppContainer network capability entirely. Every
`connect()` from the sandboxed process (raw socket or proxied) is
kernel-denied with `WSAEACCES` / `ERROR_ACCESS_DENIED`. No proxy is
started, no loopback exemption is registered. This works fully
unprivileged.

A prompt-injected dependency that tries to POST your source code to an
attacker's server: the connection is refused at the kernel, no packet
leaves the machine.

### Profiles

```powershell
sandbox run --profile claude-code --allow-cwd -- claude
```

`--profile <name>` resolves to `%USERPROFILE%\.sandbox\profiles\<name>.json`
(or a path ending in `.json`). The profile JSON can specify `filesystem`
and `network` slices. CLI flags merge on top of the profile (arrays
concatenate, CLI overrides for scalars).

Example profile (`%USERPROFILE%\.sandbox\profiles\claude-code.json`):

```json
{
  "meta": { "name": "claude-code", "version": "1.0.0" },
  "filesystem": {
    "allow": ["$CWD", "$HOME/.claude"],
    "read_only": ["$HOME/.gitconfig"],
    "deny": ["$HOME/.ssh", "$HOME/.aws"]
  },
  "network": {
    "block_net": false,
    "allow_domain": ["api.anthropic.com", "*.anthropic.com"],
    "profile": "minimal"
  }
}
```

Variables expanded in paths: `$HOME`, `$CWD`, `$USERPROFILE`, `$TEMP`,
`$SID` (the session id). Forward slashes are normalized to backslashes.

`network.block_net: true` is equivalent to `--block-net`.
`network.allow_domain` concatenates with `--allow-domain` CLI flags.
`network.profile` is one of `none` (alias for `--block-net`), `minimal`
(LLM APIs only), `developer` (adds npm/PyPI/crates.io/GitHub). The
`--network-profile` CLI flag overrides `network.profile` in the JSON.

### Per-session install directories (Option E)

Every `sandbox run` invocation gets a unique session id of the form
`YYYYMMDD-HHMMSS-NNNNN` and a per-session install tree under
`.\.sandbox\<sid>\bin\` (and `venv\`). The sandboxed process can install
arbitrary binaries into these dirs at runtime and execute them — no
profile edit, no restart, no admin. Two concurrent sessions in the same
`$CWD` get distinct trees; neither can read or poison the other.

`--print-sid` prints the session id and exits before spawning the child
(useful for setup-only invocations). `--sid <id>` reuses an existing
session's install tree (its RuleSet + per-session dirs).

### Setup check

```powershell
sandbox setup --check-only
```

Reports the Windows build number, AppContainer + Job Object availability,
and the network proxy status. Exits non-zero if the host is unsupported.

## Network filtering status

**`--block-net` works fully unprivileged.** It removes the AppContainer
network capability — every `connect()` is kernel-denied. Backs AC-3.1,
AC-3.2, AC-3.13 from the spec.

**`--allow-domain` / `--network-profile` are deferred.** The spec's
chosen loopback mechanism (`NetworkIsolationSetAppContainerConfig`) is
admin-only — MSDN documents it as "used for debugging purposes" and it
sets a system-wide loopback-allow list. Running unprivileged it returns
`ERROR_ACCESS_DENIED (0x5)`, so the sandboxed process cannot reach the
localhost proxy without admin. The proxy, token, env injection, and
audit plumbing are all implemented and unit-tested, but the loopback
gate blocks end-to-end unprivileged use.

Until the unprivileged loopback mechanism lands, `--allow-domain` and
`--network-profile` are accepted but **downgraded to `--block-net`
semantics with a clear warning** — so the flags don't silently fail.

The planned unprivileged fix is to add a `privateNetworkClientServer`
capability SID to the AppContainer token (instead of the admin-only
`NetworkIsolationSetAppContainerConfig` call). This capability allows
loopback + intranet but NOT public internet, so raw-socket direct
connects to public hosts still fail closed and the proxy enforces the
allow-list. Tracked as a follow-up in
`docs/specs/us-3-network-exfiltration-blocked/spec.md`.

When the fix lands, the integration scenarios S-27..S-34, S-36, S-38
(`tests/run-tests.ps1`) flip from SKIP to active.

## How it works

1. `sandbox.exe` creates an AppContainer profile with a per-session SID.
2. It writes explicit DACL Allow ACEs on the allow-listed directories
   (the AppContainer SID is a restricting identity, so anything without
   an ACE is denied).
3. It spawns the child under the AppContainer SID + a Job Object
   (`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, no `BREAKAWAY_OK`).
4. The child and all its descendants inherit the restrictions. The whole
   tree dies when `sandbox.exe` exits (or is killed via Ctrl-C).
5. For `--block-net`, no network capability is granted — every
   `connect()` is kernel-denied. For `--allow-domain` (once the
   loopback fix lands), a localhost reverse proxy is started on a random
   `127.0.0.1` port, the child is configured (via `HTTP_PROXY` /
   `HTTPS_PROXY` / `X-Sandbox-Token` env vars) to route through it, and
   the proxy enforces the domain allow-list + always-denied list (cloud
   metadata endpoints, link-local CIDRs) and emits `CONNECT` audit
   events.

## Testing

```powershell
# Rust unit tests (domain matcher, profiles, token, audit, profile merge):
cargo test --release

# PowerShell integration suite (S-1..S-39):
pwsh -ExecutionPolicy Bypass -File tests\run-tests.ps1
```

The integration suite drives the real `sandbox.exe` binary through
filesystem-isolation, Job-Object, breakaway, per-session, profile-loading,
and network scenarios. Python/curl-dependent scenarios skip cleanly when
those binaries aren't on `PATH`.

## Documentation

- `docs/prd/prd-sandbox.md` — full product requirements.
- `docs/specs/us-3-network-exfiltration-blocked/spec.md` — US-3 spec
  (including the loopback-exemption deferral finding).
- `docs/superpowers/plans/2026-07-25-us-3-network-exfiltration-blocked.md`
  — US-3 implementation plan.
- `docs/critical-review.md` — critical review of the chosen mechanism.
- `docs/future-ideas.md` — deferred roadmap (F-1..F-19).
- `agent.md` — high-level project overview.
- `docs/testing-principles.md` — testing philosophy for the project.
