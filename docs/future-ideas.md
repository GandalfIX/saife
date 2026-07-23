# Future Ideas — Post-MVP Roadmap for `sandbox`

This document captures the features explicitly deferred in the MVP PRD
(`prd-sandbox.md`, Non-Goals NG-1 through NG-10) plus additional ideas that
surfaced during analysis but did not fit even the post-MVP phases. They are
recorded here so they are not lost, with a rough ordering by likely phase.

## Phase 1 — Security hardening & parity with nono

### F-1. Undo & Rollback
SHA-256 content-addressed snapshots of every file in the sandbox scope taken
**before** the agent starts and **after** it exits. Stored in a deduplicating
content store under `%LOCALAPPDATA%\sandbox\contentstore\`.

- `sandbox rollback list` — sessions with file-change counts.
- `sandbox rollback restore <id>` — atomically restore pre-session state.
- `sandbox rollback show <id> --diff` — file/line-level diff.
- `--rollback-exclude` profile key (default excludes `node_modules`,
  `target`, `.gradle`, `__pycache__`, `.next`).
- Optional VSS (Volume Shadow Copy) backend for large trees — requires admin
  but gives near-instant snapshots.

### F-2. Credential Injection
Reverse proxy injects credentials as HTTP headers; the agent never sees the
raw secret. Keystore backend is **Windows Credential Manager (CredMan)** with
DPAPI at rest, plus optional `1password://` and `apple-password://`-style
URI resolvers (1Password Windows app exposes a local API).

- `--credential <service>` — proxy injection (recommended).
- `--env-credential <key>` — environment-variable injection (simpler, less
  secure; secret zeroised from memory after `CreateProcessW`).
- Built-in routes: `openai`, `anthropic`, `gemini`, `github`.
- Custom routes via profile `network.custom_credentials` with four injection
  modes: `header`, `url_path`, `query_param`, `basic_auth`.
- Audit log records `ALLOW REVERSE openai POST /v1/chat/completions -> 200`
  but never the credential value.

### F-3. Ghost Sessions
Detached sessions that persist after the user closes the terminal, using
**Job Object + named-pipe IPC** between the supervisor and the attachable
client.

- `sandbox run --detached -- …` — start in background, print session id.
- `sandbox ps [--all] [--json]` — list running and exited sessions.
- `sandbox attach <id>` / `sandbox detach <id>` — connect/drop a terminal.
  Default detach key sequence `Ctrl-] d` (configurable in
  `%USERPROFILE%\.sandbox\config.toml`).
- `sandbox stop <id> [--force] [--timeout <s>]` — graceful / forceful stop.
- `sandbox inspect <id> [--json]` — session metadata (profile, pid, started,
    cwd, audit path).
- `sandbox prune [--older-than <d>] [--keep <n>] [--dry-run]`.
- Security model: local-only, same-user only; named pipe ACL set to current
  user SID; kernel peer-credential checks on connect.

### F-4. Runtime Supervisor
Dynamic permission expansion at runtime so the agent can ask the operator for
new file/network/command access mid-session instead of failing hard.

- IPC channel (named pipe) between sandboxed process and supervisor.
- `sandbox run --supervised -- …` enables it.
- Approval prompts via terminal, webhook, or API; responses are
  session-scoped (do not persist after exit) and audit-logged.
- Capabilities: `FILE_EXPANSION` (grant new paths, pattern-constrained),
  `NETWORK_EXPANSION` (approve new hosts, optional `*.suffix` patterns),
  `COMMAND_APPROVAL` (allowlist extra commands).
- Windows implementation note: there is no exact seccomp-notify equivalent.
  Approach options to spike:
  1. **Supervisor-side open**: agent calls a helper shim (`sandbox-ask.exe`
     injected into its PATH) that opens the file out-of-sandbox and passes the
     handle via `DuplicateHandle` — works for FS, not net/exec.
  2. **Detours-based syscall trap**: inject a small DLL that traps
     `NtCreateFile` / `connect` / `CreateProcessW`, asks the supervisor over
     the named pipe, and either returns `ACCESS_DENIED` or proxies the call
     from the supervisor and forwards the handle. Coarser than seccomp but
     functional.
  3. **Minifilter driver** (Phase 3) — true kernel interception with a
     supervisor userland process via `FltGetMessage`.

### F-5. Sigstore Provenance
Verify that instruction files (`AGENTS.md`, `CLAUDE.md`, `SKILLS.md`,
`scripts/*.py` referenced by agent config) were signed by a trusted identity
before the sandboxed process is allowed to start.

- `sandbox trust sign --keyless <file>…` — Sigstore keyless signing via OIDC
  (GitHub Actions / Google / Microsoft identity), Fulcio cert, Rekor
  transparency log. Uses `sigstore-rs` crate, fully cross-platform.
- Trust policy per profile: `trust_policy.json` with `publishers` (issuer,
  repository, workflow, ref-pattern), `blocklist` (digests),
  `enforcement: deny|warn`.
- At `sandbox run`, every instruction file in the workdir is verified; unsigned
  or untrusted-identity files block startup (or warn, per policy).
- `--trust-override` escape hatch (discouraged, audit-logged).

## Phase 2 — Kernel-mode hardening (admin for setup)

### F-6. WFP Callout Driver
A small Windows Filtering Platform callout driver for true kernel-level
per-host / per-port network rules, replacing the userspace reverse proxy as
the network enforcement mechanism.

- Admin install (attestation signing — no WHQL required for load on Win10+,
  but WHQL recommended for stable long-term support).
- Per-process network rules keyed off the Job Object process set.
- Replaces the loopback-proxy workaround; eliminates the env-var proxy
  bypass risk for raw-socket apps.
- The userspace proxy can remain as the **credential injection** frontend on
  top of the driver.

### F-7. Minifilter FS Driver
A kernel minifilter for per-syscall file interception, replacing AppContainer
RuleSet for finer-grained control (per-syscall `IRP_MJ_CREATE` /
`IRP_MJ_SET_INFORMATION` decisions, content inspection, inline rewriting).

- True equivalent of Landlock's per-operation-type rules.
- Enables inline supervisor decisions (F-4 option 3).
- WHQL signing required for stable operation; attestation-signed variant
  works on Win10+ for testing.
- Replaces ETW-for-audit with synchronous event capture (events are emitted
  by the driver itself, no separate consumer needed).

### F-8. VSS-Based Snapshots
Use Volume Shadow Copy for instant before/after snapshots of large trees
(replaces the content-addressed copy-on-write store from F-1 for the
large-project case).

- Admin for setup; per-snapshot is unprivileged once the VSS writer is
  registered.
- Integrates with F-1 rollback as an optional backend.

## Phase 3 — Ecosystem & scale

### F-9. Profile Registry
A public registry of signed, versioned profiles — equivalent to
`registry.nono.sh`. Reserve the namespace now (per PRD Open Question 4).

- `sandbox profile pull <url>` — fetch and verify a signed profile into the
  local cache.
- `sandbox profile publish` — sign with Sigstore and upload.
- Registry runs as a static site + Sigstore Rekor entries; no central server
  authority needed.

### F-10. PowerShell Module
A `Sandbox` PowerShell module wrapping `sandbox.exe` to expose cmdlet-style
usage: `Start-Sandbox`, `Get-SandboxSession`, `Stop-Sandbox`,
`Show-SandboxAudit`, `Restore-Sandbox`. Better Windows-native fit for users
who live in PowerShell.

### F-11. SDKs
- `sandbox-python` — launch and control sandboxes from Python.
- `sandbox-typescript` — same for Node.js, via a small bundled binary.
- `sandbox-dotnet` — native C# binding via P/Invoke into `sandbox.exe` or a
  linked `sandbox.dll`.

### F-12. TUI / GUI Console
A `sandbox tui` mode (ratatui) showing live sessions, audit stream, and
supervisor prompts; plus an optional WPF/WinUI GUI for users who want a
managed console. Deferred indefinitely — CLI is the priority.

### F-13. CI Mode
- `--ci` flag: non-interactive, machine-readable output, exit code reflects
  policy violations, audit log committed as build artifact.
- GitHub Actions / Azure Pipelines integration samples.

## Phase 4 — Experimental / speculative

### F-14. Windows Sandbox (lightweight VM) Backend
Windows 10 Pro+ ships with **Windows Sandbox** — a disposable, lightweight
Hyper-V VM that runs Win32 apps. `sandbox run --backend wsb` could generate a
`.wsb` config, launch the VM, mount the project as a read-only shared folder,
and run the agent inside. Stronger isolation (full VM boundary) at the cost of
~5 s startup and a Windows Pro/Enterprise license. Useful for running truly
untrusted binaries the user does not want in their AppContainer scope.

### F-15. Multi-User / Server Mode
Run `sandbox` as a service accepting per-user session requests, for shared
Windows jump-boxes or CI fleets. Named-pipe ACLs per user, central audit
store, quota enforcement. Out of scope for the solo-developer MVP target but
kept here for the future enterprise case.

### F-16. Cross-Process Capability Brokering
A `sandbox-broker.exe` running as the user (outside any sandbox) that
sandboxed agents can call (via a constrained named pipe) to perform privileged
operations on their behalf — git push, docker build, kubectl — each gated by
the supervisor (F-4). Replaces nono's `add_deny_commands` /
`add_deny_access` profile pattern with a positive-capability model instead of
a deny list.

### F-17. Memory Isolation
AppContainer does not provide memory isolation (a bug in the sandboxed
process can read its own heap — that's by design). For workloads needing
stronger guarantees, integrate with **Windows Defender Application Guard**
(WDAG) or full Hyper-V VMs. Investigated in F-14; this item is the general
principle: document a clear ladder (AppContainer → WDAG → Hyper-V) so users
can pick the right isolation strength.

### F-18. Network Content Inspection
Beyond domain allow-listing, optionally inspect request/response bodies for
secret-shaped strings (AWS key patterns, credit-card numbers, private keys)
and block exfiltration attempts even to allowed domains. Post-MVP; the audit
trail (F-1 + FR-4) gives the data, content inspection is a layer on top.

### F-19. Time-Travel Debugging
Given the audit trail records every FS op and every child exec, a `sandbox
replay <id>` mode could re-execute the session with the same file states,
letting the user debug what the agent did step by step. Speculative — depends
on rollback (F-1) and a deterministic exec recorder.

### F-20. Cross-Platform Convergence
Long-term: factor the codebase so the Windows backend is one of several, with
Linux (Landlock) and macOS (Seatbelt) backends sharing the profile format,
audit trail, and CLI. This would make `sandbox` a true cross-platform nono
equivalent. Very long-term; mentioned so the architecture does not lock in
Windows-only assumptions (e.g. keep paths as a generic `OsPath` abstraction,
not `\\`-hardcoded strings).
