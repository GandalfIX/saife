# Future Ideas — Post-MVP Roadmap for `sandbox`

This document captures the features explicitly deferred in the MVP PRD
(`prd-sandbox.md`, Non-Goals NG-1 through NG-10) plus additional ideas that
surfaced during analysis but did not fit even the post-MVP phases. They are
recorded here so they are not lost, with a rough ordering by likely phase.

## Phase 1 — Security hardening & parity with nono

### F-21. AppContainer RuleSet API (kernel-level NT-path grants)

Replace or augment the per-directory-DACL grant mechanism (`grant_one` in
`src/sandbox/appcontainer.rs`, which writes an Allow ACE onto each target
directory — "what `icacls /grant` does") with the kernel-level AppContainer
RuleSet that grants NT paths (`\Device\HarddiskVolume3\…`) without writing on
the target object's DACL.

**Why:** the per-directory-DACL approach cannot grant access to objects the
user does not own (no `WRITE_DAC`). This blocks:

- `C:\` (drive root, TrustedInstaller-owned) — causes KI-1.1; currently worked
  around by the one-time elevated `sandbox setup --grant-drive-root` (F-style
  setup step, grants `S-1-15-2-2:FILE_READ_ATTRIBUTES` on fixed drive roots).
- `C:\Users`, `C:\Users\<user>` (SYSTEM-owned) — causes KI-1.2 (PowerShell
  no-path commands resolve to `C:\` because `Set-Location` can't walk
  ancestors). Not fixable by the one-time drive-root grant; needs per-user
  ancestor grants (admin) OR the RuleSet API.
- `C:\Windows\System32` (TrustedInstaller-owned) — the `System32` grant in
  `allowlist.rs` fails with Access Denied today; harmless because System32 is
  world-readable and the AppContainer can read it via inherited `Users:RX`,
  but explicit-ACE-requiring calls (e.g. `where`'s stat path, KI-1.4) fail.

**Design:**

- `src/sandbox/allowlist.rs` already has a `to_nt_path` helper (currently
  `#[allow(dead_code)]`) that resolves `C:\foo` → `\Device\HarddiskVolumeN\foo`
  via `QueryDosDeviceW`, reserved for this future implementation.
- Build a RuleSet object, add per-path rules (`Read` / `Write` / `Execute`
  capability bits at `IRP_MJ_CREATE` time — coarser than Landlock's
  per-syscall-type rules, documented as a fidelity gap in the US-1 nono
  comparison), and apply it to the process token before `CreateProcessW`.
- The RuleSet is enforced by the object manager, so it grants access to paths
  the user doesn't own — no `WRITE_DAC` needed, no admin.
- Keeps the default-deny model: paths not on the RuleSet are denied (the
  AppContainer SID is still a restricting identity).

**Scope:** architectural change to the sandbox core (`grant_access` /
`build_allowlist` / `spawn`). The per-directory-DACL path can remain as a
fallback or for user-owned paths where inheritance is desired, but the
RuleSet becomes the primary grant mechanism for system-owned roots and
ancestors.

**Resolves:** KI-1.1 fully (no setup-time admin step needed), KI-1.2 (ancestor
traversal/listing for `Set-Location`), KI-1.4 partially (`System32` access for
`where`).

### F-22. Ancestor traverse grants (admin, per-user)

Companion to F-21 for environments where the RuleSet API is not yet available.
A `sandbox setup --grant-ancestors <workspace-root>` step (elevated) grants
`S-1-15-2-2` `FILE_TRAVERSE` (traverse-only, **no** `FILE_LIST_DIRECTORY`) on
each ancestor directory of the configured workspace root up to the drive root,
plus `FILE_LIST_DIRECTORY` on the drive root (already done by
`--grant-drive-root`). Per-user (each user's home dir path differs), not
one-time.

**Why:** fixes KI-1.2 (PowerShell `Set-Location` to the cwd) without the full
RuleSet rewrite. Traverse-only on ancestors preserves the sibling-isolation
guarantee (the AppContainer can walk *through* `C:\Users\<user>` but cannot
*list* its contents or read sibling projects).

**Resolves:** KI-1.2 (the `Set-Location` part; `InitializeDefaultDrives`
enumerating other drives may still warn).

### F-23. UI / Win32k restriction Job Object flags (AI-agent hardening)

Mirror the UI-restriction layer from Microsoft's MXC `processcontainer`
backend (`docs/process-container/os-version-support.md`, "UI restrictions"
matrix) into our own Job Object setup. MXC applies these in **both** its T1
(BaseContainer) and T3 (AppContainer+DACL) tiers via
`src/backends/appcontainer/common/src/job_object.rs`, so they are orthogonal
to the grant mechanism and can land on top of our existing code with no
architectural change.

**Why:** an escaping prompt-driven agent should not be able to (a) read the
clipboard the user may have just copied a secret into, (b) enumerate or inject
into other windows, or (c) call win32k syscalls it doesn't need. These are
cheap, kernel-enforced, and independent of the filesystem/network policy.

**Design:**

- Extend the Job Object setup (currently `KILL_ON_JOB_CLOSE`, no
  `BREAKAWAY_OK`) with `JOB_OBJECT_UILIMIT_*` flags:
  - `HANDLES` / `GLOBALATOMS` — UI isolation (`ui.isolation`)
  - `READCLIPBOARD` / `WRITECLIPBOARD` — clipboard control (`ui.clipboard`)
  - `SYSTEMPARAMETERS` / `DISPLAYSETTINGS` (`ui.systemSettings`)
  - `DESKTOP` / `EXITWINDOWS` (`ui.desktopSystemControl`)
  - `IME` (`0x100`, requires build 22621+ → always available on supported
    hosts; MXC gate: `MIN_BUILD_FOR_IME_LIMIT`)
  - `INJECTION` (`0x200`, requires build 26100+ → Win11 24H2; MXC gate:
    `MIN_BUILD_FOR_INJECTION_LIMIT`). Build-gate this one: 23H2 kernel
    rejects it, so use MXC's `requested & supported` mask pattern — never
    hand the kernel a flag it would reject.
- Add the `disallowWin32kSystemCalls` process mitigation as `ui.disable`
  (available 23H2+).
- Expose as profile `ui.*` slice plus CLI (e.g. `--ui-lockdown`,
  `--no-clipboard`). Effective mask = `requested & supported_for_build`.
- `sandbox setup --check-only` reports which UI limits the host can enforce
  (equivalent to MXC's `wxc-exec --probe` output).

**Scope:** contained — touches Job Object creation + process-attribute
(mitigation) setup in `src/sandbox/`, plus CLI/profile plumbing. No change to
the AppContainer/DACL path. Works on our existing Windows 10 1709+ floor
(except `INJECTION`, which simply no-ops below 26100).

**Resolves:** clipboard/window/IME/injection escape surface for unattended
agent runs; parity with the MXC UI-restriction surface without adopting MXC.

### F-24. Denial-capture / learning-mode audit for policy authoring

Mirror MXC's `--audit` (Permissive Learning Mode) developer-inner-loop
feature: run the sandbox in a permissive mode where denied operations are
**logged but allowed**, capture what the workload *actually* touches, and emit
an adjusted profile. From MXC: it starts a PLM (Permissive Learning Mode) ETW
trace alongside the workload and always prints an artifact dir containing
`trace.etl`, `denials.json`, and any adjusted config.

**Why:** authoring a tight filesystem/network allow-list by hand is painful
guess-work ("which paths does `npm install` really need?"). A capture-driven
flow turns policy authoring from trial-and-error into: run once in learning
mode → review `denials.json` → promote the entries you agree with into the
profile. This directly feeds US-4 (audit trail) and makes F-22 (ancestor
grants) and per-app profiles (claude-code, opencode, codex) much easier to
write correctly.

**Design:**

- New `sandbox audit <profile> -- <cmd>` subcommand (separate from
  `sandbox run` so the permissive mode is opt-in and explicit, never a
  default).
- Backend A (no OS changes, ship first): run the child *without* the DACL
  deny-by-default (grants-only), attach an ETW file-access + `connect()`
  listener (US-4 plumbing already planned), emit
  `.\.sandbox\<sid>\audit\denials.json` listing every path/host the child
  touched that was *not* in the profile. Fail-closed alternatives stay in
  `sandbox run` only.
- Backend B (later, if a capable Windows build is present): key off the OS
  BaseContainer Learning-Mode export set MXC probes for
  (`StartLearningModeTrace` / `StopLearningModeTrace` / `CloseLearningModeTrace`,
  requires the full V2 contract) so kernel AppContainer denials are captured
  natively instead of running permissive. Build-gate behind a runtime probe;
  fall back to Backend A otherwise.
- Output: `denials.json` + a suggested profile delta (paths to add to
  `filesystem.allow`, hosts to add to `network.allow_domain`), plus a
  human-readable summary. Include the "never silently granted" note in the
  report header so it's obvious the audit run did **not** enforce policy.
- Hard rules (from DX/security): cannot be combined with a production
  profile's enforcement; the permissive mode is *rejected* for any backend
  that doesn't honor learning mode; reserved capability names
  (`learningModeLogging`, `permissiveLearningMode`) are rejected in normal
  profiles (matching MXC's restriction).

**Scope:** new subcommand + ETW/session wiring (reuses US-4 audit backend) +
report writer. Backend A is most of the value and is unprivileged; Backend B
is an optional refinement gated on Windows capability.

**Resolves:** policy-authoring pain (FR for US-1/US-3 profile correctness),
US-4 (audit trail) gains real data, reduces the "just give it `--allow-cwd`
and everything under `$HOME`" profile-bloat antipattern.

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

### F-25. Elevation-free operation via install-time privilege (SUPERSEDED for egress, 2026-10-22)

> **Status: superseded for the network case by ADR-0004.** The MXC
> `processcontainer` backend runs the proxy path with no administrator rights at
> all (`sandbox run` is unelevated, guardrail 1 proves the child's path), so the
> broker/install-time designs below are NOT needed to obtain unelevated egress
> and must not be built for that purpose. They remain relevant only for the
> AppContainer backend, which still needs the loopback exemption for network
> sessions (ADR-0002), and as history for why the migration was worth its cost.
> Renumbered from a duplicate F-21 on 2026-10-22 - this file's numbering had
> two sections called F-21.
Today's ONLY admin dependency is the AppContainer loopback exemption that lets
the child reach the supervisor's proxy listener (`0x80070005` unprivileged).
Filesystem isolation already runs as the current user (per-session ACEs on
owned dirs), so nothing else needs elevation. Three install-once designs:

1. **Stable container SID + install-time exemption** — fix the AppContainer
   profile name (today derived from the session id) so the SID is stable, then
   register the exemption once from an elevated installer. No service, no
   per-run admin. Trade-off: all sessions share one container identity, so
   OS-level separation between CONCURRENT sessions weakens (granted paths and
   audit stay per session). The exemption is per-SID and port-agnostic; only a
   future firewall rule would need a fixed port policy.
2. **Privileged broker service** — a service installed once registers
   exemptions (and any future protected-resource grants) for product-created
   containers over authenticated IPC, keeping per-session SIDs. Cost: a new
   privileged attack surface; policy must accept only product containers,
   verify the caller, and never honour arbitrary SIDs/paths, or the broker
   becomes a local privilege-escalation primitive.
3. **Packaged identity (MSIX) + `privateNetworkClientServer`** — verify FIRST
   whether the capability actually unblocks host loopback (the loopback block
   may be independent of capabilities and still require the exemption list);
   otherwise it adds packaging friction without the benefit.

Threat-model note (all variants): the exemption is per-SID, so it covers the
whole product identity including a compromised agent inside it — that is the
intended containment boundary (the agent is meant to reach the proxy), but it
should be stated explicitly. MXC does not answer this either way: its backend
network model is still open at the pinned mxc-sdk version. Recommend spiking
(1) first (smallest change, matches the current architecture), then (2) if
per-session SIDs must be preserved, then (3) only if packaging is on the table.
