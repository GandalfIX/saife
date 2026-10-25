# SAIFE Sandbox

```text
███████╗ █████╗ ██╗███████╗███████╗
██╔════╝██╔══██╗██║██╔════╝██╔════╝
███████╗███████║██║█████╗  █████╗
╚════██║██╔══██║██║██╔══╝  ██╔══╝
███████║██║  ██║██║██║     ███████╗
╚══════╝╚═╝  ╚═╝╚═╝╚═╝     ╚══════╝
        Secure AI Frontier Environment
```

**SAIFE** (*Secure AI Frontier Environment*) is a native Windows
process-sandboxing tool that runs any program — primarily
AI coding agents (Claude Code, OpenCode, Codex, …) and their build
toolchains — with only the resources the user has explicitly granted.

Pure Win32 / NT kernel primitives, a single unprivileged Rust binary, no
container runtime, no daemon, no VM. Windows-native equivalent of
[nono](https://nono.sh/) without WSL.

## Status

MVP, under active development. Implemented pillars:

- **Filesystem isolation** (US-1, US-2) - `mxc`: an additive policy over the
  workspace plus read-only extra grants; `appcontainer`: per-directory DACL
  allow-lists. Irrevocable for the lifetime of the process tree.
- **Network filtering** (US-3) - `--block-net` is fully unprivileged; a domain
  allow/deny-list, block-list, learned denies and an interactive prompt sit in
  front of every request, and plain-HTTP as well as CONNECT goes through the
  same pipeline. Unelevated by default (see
  [Backends and privileges](#backends-and-privileges)).
- **Audit trail** (US-4) - a tamper-evident hash chain per session, signed with
  an Ed25519 key, with `saife audit show|verify` and a session-start leaf that
  records the containment tier, elevation and proxy endpoint. `verify` reports
  `INCOMPLETE` for a session that did not end cleanly rather than silently
  accepting it.

Default backend is `mxc` in a build with `--features mxc-backend` (P3.2);
`--backend appcontainer` remains for workloads whose client stack cannot use a
proxy. Out of scope for the MVP: undo/rollback, credential injection, ghost
sessions, runtime supervisor, Sigstore provenance, GUI/TUI, multi-user mode.
See `docs/design/prd/prd-sandbox.md` for the PRD and `docs/notes/future-ideas.md` for the
deferred roadmap.

## Requirements

- **Windows 11 24H2 (build 26100.x) or a later supported servicing build** for
  the default `mxc` backend — the MXC process container requires it. Builds older
  than 24H2 cannot run that backend at all.
- The `appcontainer` backend runs on Windows 10 1709 (build 16299) and later.
- **Administrator rights: not needed for `mxc`.** Network sessions through the
  default backend run unelevated. They ARE needed for `--backend appcontainer`
  when the session has network (`--allow-domain`, a profile with a network
  policy): that backend registers a system-wide loopback exemption for the
  AppContainer SID, which is an admin-only API.
- Rust toolchain (for building; only needed by developers, not end users).

## Backends and privileges

`--backend mxc` (the default) runs the
workload in an MXC process container: filesystem policy is additive over the
workspace, egress is forced through this process's own proxy listener, and no
DACLs, no loopback exemption, no admin rights are involved.

`--backend appcontainer` is the original AppContainer supervisor and remains the
**escape hatch for workloads whose network stack cannot use a proxy** — WinINet /
system-proxy applications and PowerShell 5.1 / .NET Framework programs reach the
proxy but never authenticate, so they have no egress under `mxc`. Use the flag
for those.

Every successful proxied session prints its proof to stderr:

```text
[saife] mxc: guardrail 1 proof probes=1 accepted=0 tunnels=0 unauthenticated=0
```

`probes` is this run's own pre-flight probe (the child's path to the proxy
works), `accepted`/`tunnels` are the traffic it actually made, and
`unauthenticated` counts attempts that reached the proxy without the run's
credential. If nothing in the session ever authenticated while something tried,
the session is **refused** with `workload_cannot_authenticate` and the remedy is
`--backend appcontainer`.

Session deadlines are `limits.promptTimeoutSecs + limits.workloadTimeoutSecs +
slack` (defaults 60 s + 30 min + 2 min). Both terms live in the profile's
top-level `limits` section (`network` no longer accepts them). Raise
`limits.workloadTimeoutSecs` for long builds or downloads; there is no unlimited
mode.

## Build

```powershell
cargo build --release
.\target\release\saife.exe setup --check-only
```

The default build includes the `mxc-backend` feature, so `saife run` starts the
unelevated MXC backend (and builds `saife-launch.exe` beside it). To build an
AppContainer-only binary — bootstrap without the SDK, or a host older than
Windows 11 24H2 — opt out explicitly:

```powershell
cargo build --release --no-default-features   # prints a notice at startup
```

Gates: `cargo test --bin saife` is 611 tests in the default build and 490 with
`--no-default-features`; `cargo clippy --all-targets` must be warning-free in
both.

`setup --check-only` reports the host build number, AppContainer
availability, Job Object availability, and the network proxy status. It
exits non-zero if the host is below the minimum build or any required
capability is missing.

## Usage

### Run a command in the sandbox

```powershell
saife run --allow-cwd -- cmd /c echo hello
```

`--allow-cwd` grants read+write+execute on the current working directory.
The sandboxed process can read and write your project tree but cannot
read `~/.ssh`, `~/.aws`, sibling project directories, or anything else
not explicitly listed.

### Grant additional paths

```powershell
# Read+write+execute (default):
saife run --allow-cwd --allow $HOME\.claude -- claude

# Read-only:
saife run --allow-cwd --read-only $HOME\.gitconfig -- cmd /c type %USERPROFILE%\.gitconfig

# Read-only with explicit mode:
saife run --allow-cwd --allow $HOME\.npm:read -- npm install
```

`--allow <path>` (repeatable) grants access on an additional path. Format:
`<path>[:<mode>]` where mode is `read|write|readwrite|execute` (default
`readwrite` = read+write+execute). `--read-only <path>` (repeatable) is a
shorthand for `--allow <path>:read`.

The leading `C:` drive-letter colon is NOT treated as a mode separator.

### Block all network access

```powershell
saife run --allow-cwd --block-net -- cmd /c echo no-network
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
saife run --profile claude-code --allow-cwd -- claude
```

`--profile <name>` resolves to `%USERPROFILE%\.saife\profiles\<name>.json`
(or a path ending in `.json`). The profile JSON can specify `filesystem`
and `network` slices. CLI flags merge on top of the profile (arrays
concatenate, CLI overrides for scalars).

Example profile (`%USERPROFILE%\.saife\profiles\claude-code.json`):

```json
{
  "meta": { "name": "claude-code", "version": "1.0.0", "schema_version": 1 },
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

`meta.schema_version` is required; a profile without it is refused, which is the
one field the example above used to omit.

Variables expanded in paths: `$HOME`, `$CWD`, `$USERPROFILE`, `$TEMP`,
`$LOCALAPPDATA`, `$APPDATA`, `$SID` (the session id). Forward slashes are
normalized to backslashes. Working examples you can copy rather than retype are in
`profiles/` (`node`, `jvm`, `opencode`); `packaging/README.txt` lists what the
download contains.

`network.block_net: true` is equivalent to `--block-net`.
`network.allow_domain` concatenates with `--allow-domain` CLI flags.
`network.profile` is one of `none` (alias for `--block-net`), `minimal`
(LLM APIs only), `developer` (adds npm/PyPI/crates.io/GitHub). The
`--network-profile` CLI flag overrides `network.profile` in the JSON.

### Per-session install directories (Option E)

Every `saife run` invocation gets a unique session id of the form
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
saife setup --check-only
```

Reports the Windows build number, AppContainer + Job Object availability,
and the network proxy status. Exits non-zero if the host is unsupported.

## Network filtering status

**`--block-net` works fully unprivileged.** It removes the AppContainer
network capability (or, under `mxc`, provides no proxy at all) - every
`connect()` is kernel-denied. Backs AC-3.1, AC-3.2, AC-3.13 from the spec.

**`--allow-domain` / `--network-profile` work, and under the default `mxc`
backend they work UNELEVATED.** The supervisor opens its own loopback listener,
the child is given `HTTP_PROXY`/`HTTPS_PROXY` pointing at it with the run's
token, and every request is decided by the D-1 pipeline (hard deny, learned
deny, allow-list, block-list, prompt). D-9 also admits plain-HTTP absolute-form
requests through the same pipeline, and guardrail 1 refuses a session whose
child never reached the listener.

**`--backend appcontainer` still needs administrator rights for networked
sessions.** That backend relies on the loopback exemption registration
(`NetworkIsolationSetAppContainerConfig`), an admin-only, system-wide API; an
unprivileged child cannot reach the listener and fails with
`WSAEACCES (10013)`, which the supervisor reports as a warning plus a
degraded, network-less session. This is the measured reason the `mxc` migration
exists - see ADR-0004.

Prompting: when the policy reaches the prompt stage and no dialog can be shown
(headless/CI), the configured `on_unavailable` policy applies immediately after
two consecutive unanswered consultations instead of paying the full budget per
host, and the refusal reason says which happened
(`prompt_budget_exhausted`, `no_dialog_backend`, `prompt_suppressed_after_budget`).

## How it works

1. `saife.exe` creates an AppContainer profile with a per-session SID.
2. It writes explicit DACL Allow ACEs on the allow-listed directories
   (the AppContainer SID is a restricting identity, so anything without
   an ACE is denied).
3. It spawns the child under the AppContainer SID + a Job Object
   (`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, no `BREAKAWAY_OK`).
4. The child and all its descendants inherit the restrictions. The whole
   tree dies when `saife.exe` exits (or is killed via Ctrl-C).
5. For `--block-net`, no network capability is granted — every
   `connect()` is kernel-denied. For `--allow-domain` (once the
   loopback fix lands), a localhost reverse proxy is started on a random
   `127.0.0.1` port, the child is configured (via `HTTP_PROXY` /
   `HTTPS_PROXY` / `X-Sandbox-Token` env vars) to route through it, and
   the proxy enforces the domain allow-list + always-denied list (cloud
   metadata endpoints, link-local CIDRs) and emits `CONNECT` audit
   events.
6. Every ACE grant is journaled before it is applied; on exit the
   journal is replayed to restore the host. If `saife.exe` is killed,
   the next run reaps and restores orphaned journals (quarantining
   unparseable ones as `.corrupt`).

## Testing

```powershell
# Rust unit tests (domain matcher, profiles, token, audit, profile merge):
cargo test --release

# Integration suite (93 scenarios; add -Backend mxc for the default backend):
pwsh -ExecutionPolicy Bypass -File tests\run-tests.ps1
```

The integration suite drives the real `saife.exe` binary through
filesystem-isolation, Job-Object, breakaway, per-session, profile-loading,
and network scenarios. Python/curl-dependent scenarios skip cleanly when
those binaries aren't on `PATH`.

**Tier 2/3 tests are moving into a disposable VM.** The integration suite
mutates ACLs and AppContainer state on the machine it runs on; the approved
default is to run it hermetically inside a disposable Hyper-V VM with
`pwsh tests\vm\Invoke-TestsInVM.ps1 -Phase all` (one-time host/image prep:
`tests\vm\Initialize-VMHost.ps1`, `tests\vm\BUILD-BASE-IMAGE.md`). Direct
host runs of `tests\run-tests.ps1` are for smoke only. See
`docs/plans/2026-10-04-vm-test-infrastructure.md` and the binding
rule in `docs/design/testing-principles.md`.

## Documentation

- **`docs/USER-GUIDE.md` — start here to USE it**: running commands and toolchains,
  filesystem grants, network allow/deny and the prompt, profiles, reading the proof
  line and the audit log, plus a troubleshooting table. Every example was executed.
- **`docs/DEVELOPERS.md` — start here to change the code**: repository map, how a
  run works on both backends, the audit model, build/test gates, recipes and the
  invariants a change must keep. `AGENTS.md` holds the house rules for agents.
- `docs/adr/` — accepted decisions (0001 network hardening, 0002 MXC integration
  surface, 0003 base-container enforcement, 0004 GA unelevated egress).
- `docs/design/prd/prd-sandbox.md` — full product requirements.
- `docs/design/specs/us-3-network-exfiltration-blocked/spec.md` — US-3 spec
  (including the loopback-exemption deferral finding).
- `docs/plans/2026-07-25-us-3-network-exfiltration-blocked.md`
  — US-3 implementation plan.
- `docs/design/critical-review.md` — critical review of the chosen mechanism.
- `docs/notes/future-ideas.md` — deferred roadmap (F-1..F-25; F-25 is superseded for egress by ADR-0004).
- `docs/design/testing-principles.md` — testing philosophy for the project.
- `docs/plans/2026-10-04-vm-test-infrastructure.md` — VM-01:
  disposable-VM test harness (binding default for Tier 2/3 tests).
- `docs/research/impact-analysis-windows-cli-sandbox-wbd.md` — impact analysis of the
  external work breakdown in `input/WINDOWS_CLI_SAIFE_WORK_BREAKDOWN.md`
  (MXC BaseContainer/PSEC track, two-track recommendation, VM amendment).
