# PRD: `saife` — Native Windows Process Sandbox for AI Agents

> **STATUS NOTE (2026-07-24):** The AppContainer + Option E spike
> (`../spike-appcontainer-option-e.md`) has **PASSED**. The gate test
> (S-6) confirmed that a binary downloaded at runtime into a
> RuleSet-allowed per-session directory (`.sandbox/<sid>/bin/`) is
> executable by the sandboxed AppContainer process, and per-session
> isolation (S-13) is enforced. OpenAI's finding that AppContainer does
> not fit the open-ended-binary workload is **not** confirmed for the
> Option E directory model. **AppContainer + Option E is the MVP
> mechanism; no Option A fallback is triggered.**
>
> Earlier decisions (retained):
> - **Mechanism (FR-2)**: AppContainer + Option E **confirmed** by the
>   spike. (Previously: pending the spike.)
> - **Admin for setup (G4, FR-6)**: accepted — "admin for setup,
>   unprivileged to run." Matches OpenAI's shipped design.
> - **Option E sanctioned install dirs**: per-session
>   `.sandbox/<sid>/{bin,venv,npm,cargo,tmp}/` for open-ended binary
>   execution. Plus opt-in `persist`/`reuse` for caching. See
>   `../critical-review.md` Option E. **Validated by S-6 and S-13.**
> - **Profiles location (FR-5.1)**: confirmed user-global only
>   (`%USERPROFILE%\.saife\profiles\`); no repo-local search path
>   (CR-10 config-based sandbox escape).
> - **WSL2 backend**: rejected — native Windows only.
> The PRD body below will be updated to reflect these decisions once the
> spike concludes the mechanism question.

## Introduction / Overview

`saife` is a native Windows process-sandboxing tool that lets a user run
**any** program — primarily AI coding agents (Claude Code, OpenCode, Codex,
etc.) and the toolchains they spawn (gradle, python, npm, cargo, …) — with
**only the resources the user has explicitly granted**. The goal is a native
Windows equivalent of [nono](https://nono.sh/), but without WSL: pure Win32 /
NT kernel primitives, single Rust binary, unprivileged operation, no container
runtime, no daemon, no virtual machine.

The MVP delivers three pillars on top of an AppContainer-based isolation core:

1. **Filesystem isolation** — irrevocable, kernel-enforced allow-lists.
2. **Audit trail** — tamper-evident Merkle-tree log of every operation.
3. **Network filtering** — domain-level allow-list via a localhost reverse proxy
   the sandboxed process is restricted to.

Undo/rollback, credential injection, ghost sessions, runtime supervisor and
Sigstore provenance are **explicitly out of scope** for the MVP (see Non-Goals)
but the architecture is designed to admit them in later phases without rework.

### Why native Windows, no WSL

nono's Windows story runs inside WSL2 and applies Landlock to the Linux kernel
that powers it. That works, but:

- It forces a Linux runtime onto a Windows user who may not want one.
- It cannot sandbox native Win32 processes (gradle.cmd, python.exe, node.exe
  running on Windows) — only Linux processes inside WSL.
- Cross-filesystem access (`/mnt/c`) adds overhead and semantic gaps.

`saife` targets the Windows kernel directly so it can sandbox **native Win32
and console processes** that real Windows developers actually run.

## Goals

- **G1. Run any native Windows process in a sandbox** — console apps, GUI apps,
  agent CLIs, build tools, interpreters — started by `saife run -- <cmd>`.
- **G2. Irrevocable filesystem allow-list** — the sandboxed process and all
  children can only touch paths the user explicitly granted; rules cannot be
  loosened at runtime, only tightened.
- **G3. Zero runtime overhead** — enforcement happens in the kernel
  (AppContainer + Job Object), not in a monitoring userspace process.
- **G4. Unprivileged operation** — installs and runs as the user; no admin
  rights, no service, no driver for the MVP. (Admin-only paths are documented
  where they would unlock additional capabilities — see Technical
  Considerations.)
- **G5. Tamper-evident audit trail** — every network decision and session
  lifecycle event is recorded as a Merkle leaf; the signed root lets the user
  verify after the fact that the log was not tampered with.
  *Corrected 2026-10-25 (independent review F-7):* the original wording promised
  every filesystem operation and every spawn. What ships records the **resolved
  filesystem policy** (grants and denies) in `SESSION_START`, not individual
  accesses — no kernel event source is wired. `FILE_*` and `EXEC` in FR-4.3 are
  therefore unrealised; either an ETW consumer or a minifilter would be needed.
- **G6. Domain-level network filtering** — default-deny outbound network with
  an explicit allow-list of domains; optional full block (`--block-net`); the
  sandboxed process is restricted to a localhost proxy port.
- **G7. nono-compatible CLI surface** — `saife run`, `saife ps`,
  `saife audit`, `saife rollback` (stub for MVP), so nono users feel at
  home and migration is mechanical.
- **G8. Composable JSON profiles** — local, git-versionable profile files
  ($HOME/.sandbox/profiles/*.json) with `$HOME` / `$CWD` variable expansion,
  security groups, and profile inheritance (`"extends"`).

## User Stories

### US-1: Run a coding agent safely
> As a solo developer running Claude Code on my Windows machine, I want to
> start it with `saife run --profile claude-code --allow-cwd -- claude` so
> that it can read and write my project directory and reach the Anthropic API,
> but it cannot read my `~/.ssh`, `~/.aws/credentials`, `.env` files in other
> projects, or connect to anything but the LLM endpoint.

### US-2: Build toolchain runs inside the sandbox
> As a developer whose agent invokes `gradle build` or `python -m pytest`, I
> want those child processes to **inherit** the sandbox automatically — same
> filesystem allow-list, same network restrictions — with no extra
> configuration, so a malicious build script cannot escape.

### US-3: Network exfiltration blocked
> As a developer, I want to run an agent with `--block-net` so that even if a
> prompt-injected dependency tries to POST my source code to an attacker's
> server, the connection is refused at the proxy and logged.

### US-4: Verify what the agent did
> As a developer, after a sandboxed session ends I want to run
> `saife audit show <session-id>` to see every file the agent touched, every
> network call it attempted (allowed and denied), and every child process it
> spawned — and I want a Merkle-root proof that the log was not tampered with.

### US-5: Reusable, version-controlled policy
> As a developer, I want to commit `profiles/myproject.json` to my repo so
> that anyone who runs an agent against the project gets the same access
> scope, reviewed in PRs alongside the code.

### US-6: Reject unsigned instructions (future)
> As a developer, I want `saife` to refuse to run if `AGENTS.md` /
> `CLAUDE.md` in the working directory is not signed by a trusted identity
> (deferred to post-MVP — provenance feature).

## Functional Requirements

### FR-1 — Command Line Interface
- **FR-1.1** Single executable `saife.exe` (Rust, single static binary,
  `x86_64-pc-windows-msvc`).
- **FR-1.2** Subcommands:
  - `saife run [--profile <name>] [--allow <path>...] [--allow-cwd]
    [--read-only <path>...] [--block-net | --allow-domain <d>...] |
    --network-profile <name>] [--audit] [--json] -- <command> [args...]`
  - `saife ps [--all] [--json]` — list sessions (MVP: returns the single
    running session or empty; full ghost-session support is post-MVP).
  - `saife audit show <session-id> [--json] [--filter <expr>]`
  - `saife audit verify <session-id>` — recompute Merkle root, compare to
    committed root, report OK/TAMPERED.
  - `saife profile list` / `saife profile show <name>`
  - `saife setup --check-only` — report AppContainer/WFP availability,
    Windows version, feature matrix.
  - `saife --version`, `saife --help`.
- **FR-1.3** `run` is the only command that spawns a sandboxed process; all
  other commands are read-only metadata / log accessors.

### FR-2 — Filesystem Isolation (MVP core)
> **Spike-validated (2026-07-24).** The AppContainer + Option E spike
> (`../spike-appcontainer-option-e.md`) confirmed S-6 (a binary downloaded
> at runtime into `.sandbox/<sid>/bin/` is executable) and S-13 (per-session
> isolation). See `../spike/RESULTS.md`. Implementation notes below encode
> the spike's findings.

- **FR-2.1** The sandboxed process is launched inside an **AppContainer**
  profile with a freshly-generated per-session **AppContainer SID**
  (`CreateAppContainerProfile`; re-derived via
  `DeriveAppContainerSidFromAppContainerName` on `--sid`/`--reuse`). The
  child is a genuine AppContainer process: its token has
  `TokenIsAppContainer = 1` and the AppContainer SID in
  `TokenAppContainerSid`. (Note: AppContainer SIDs do **not** appear in
  `TokenGroups`/`whoami /groups`; verify via `GetTokenInformation`.)
- **FR-2.2** A **RuleSet** is built from the resolved allow-list and
  applied to the process token before `CreateProcessW` runs. The spike
  validated two equivalent grant mechanisms:
  (a) per-directory DACL Allow ACEs for the AppContainer SID (what `icacls
  /grant` / Add-AppxPackage-style setup do), and
  (b) the formal AppContainer capability-rule RuleSet (`NtCreateFile` /
  `CreateAppContainerProfile` + capability SIDs).
  Both rely on the AppContainer SID being a restricting identity
  (deny-by-default); the MVP picks one (recommend (b) for purity, (a) for
  simplicity — the spike used (a)).
- **FR-2.3** Allow-list entries support:
  - directory path, recursive flag
  - file path
  - access mode: `read`, `write`, `readwrite`, `execute`
  - variable expansion: `$HOME`, `$CWD`, `$USERPROFILE`, `$TEMP`
- **FR-2.4** **Irrevocability**: the RuleSet is committed before the process
  executes its first instruction; no API path in `saife.exe` exposes a way to
  loosen it. (Tightening — adding more deny entries at runtime — is deferred to
  the Runtime Supervisor phase, post-MVP.)
- **FR-2.5** **Inheritance**: child processes spawned by the sandboxed process
  automatically inherit the same AppContainer token and Job Object, so the
  same rules apply transitively. Verified by a test that launches `cmd /c
  python -c "open(r'C:\Users\marku\.ssh\id_rsa').read()"` and asserts it fails.
  (Spike S-10 confirmed denial at depth 3: `cmd /c cmd /c cmd /c type …`.)
- **FR-2.6** A **Job Object** is attached with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`
  so that when the parent `saife.exe` exits, all descendants are killed — no
  orphaned sandboxed processes survive. `JOB_OBJECT_LIMIT_BREAKAWAY_OK` is
  **not** set, so children cannot escape the job. (Spike S-11 confirmed the
  kill-the-tree property; S-12 breakaway-blocking is deferred pending a
  dedicated helper binary.)
- **FR-2.7** Default-deny: paths not in the allow-list return
  `ERROR_ACCESS_DENIED` to the sandboxed process. (Spike S-2/S-3/S-5
  confirmed `.ssh` reads and sibling-project reads/writes are denied.)

#### FR-2.8 — Option E sanctioned install directories (spike-validated)

The profile enumerates **directories**, not **tools**, so the agent can
install arbitrary binaries mid-session into the sanctioned install roots
and run them without re-profiling. Install roots are scoped by session id
(DECISION 2026-07-23): two concurrent agents get distinct trees — no
races, no cross-session poisoning.

- **FR-2.8.1** Per-session install roots under `$CWD/.sandbox/<sid>/`:
  - `bin/` — general binaries; prepended to the child's `PATH`
    (`Read | Write | Execute`)
  - `venv/` — per-session Python virtualenvs (`R | W | X`)
  - `npm/`, `cargo/`, `tmp/` — runtime-specific install/cache dirs
    (same model; MVP includes at least `bin/` and `venv/`)
- **FR-2.8.2** **Per-session isolation (S-13, validated):** each
  `.sandbox/<sid>/` subtree is granted to its owning AppContainer SID
  with a **PROTECTED_DACL** (`PROTECTED_DACL_SECURITY_INFORMATION`) so it
  does **not** inherit the broad `$CWD` Allow. Session B's AppContainer
  SID therefore has no Allow ACE on session A's subtree → denied by
  default. The subtree's DACL explicitly grants Full Control to the
  owner (user), SYSTEM, Administrators, and `R|W|X` to the owning
  AppContainer SID. (The naive "Deny on `.sandbox/`" approach **failed**
  in the spike — the inherited `$CWD` Allow overrode the deny; PROTECTED
  is the correct mechanism.)
- **FR-2.8.3** The sandboxed process "downloads" a binary by writing into
  `bin/` (e.g. `copy`, `pip install`, `cargo install`); the binary is
  immediately executable. (Spike S-6 gate test.)
- **FR-2.8.4** **Opt-in caching (`persist`/`reuse`)**: a session's `bin/`
  may be persisted to `%USERPROFILE%/.sandbox/stores/<name>/bin/` and
  reused (read-only) by a later session via `--reuse <name>`. With
  `--reuse`, the per-session `bin/` IS the store dir (aliased). Not
  required for the open-ended-binary property; deferred from the spike
  (stubbed).

### FR-3 — Network Filtering (MVP)
- **FR-3.1** `--block-net` mode: the AppContainer's default network capability
  is withheld; the process cannot `connect()` to any host. Verified by test.
- **FR-3.2** `--allow-domain` / `--network-profile` mode: a localhost HTTP(S)
  **reverse proxy** is started on a random `127.0.0.1` port inside
  `saife.exe` (Tokio + `hyper`). The sandboxed process is configured
  (via environment variables `HTTP_PROXY` / `HTTPS_PROXY` and a session token
  `X-Sandbox-Token`) to route all outbound traffic through it.
- **FR-3.3** The proxy resolves the target host and enforces the domain
  allow-list (exact match and `*.suffix` wildcard). Denied connections are
  dropped and logged as `DENY CONNECT <host>:<port>`.
- **FR-3.4** **Always-denied destinations** (cannot be overridden by any
  profile): `169.254.169.254`, `169.254.0.0/16`, `fe80::/10`,
  `metadata.google.internal`.
- **FR-3.5** The sandboxed process's AppContainer token is restricted so that
  only `127.0.0.1:<proxy-port>` is reachable directly; the proxy itself runs
  outside the AppContainer and has normal network access. (Implementation note:
  this uses the AppContainer network capability + a `LOOPBACK` exemption rule
  scoped to the proxy port; see Technical Considerations.)
- **FR-3.6** Built-in network profiles: `minimal` (LLM APIs only: openai,
  anthropic, gemini), `developer` (above + package registries + github),
  `none` (alias for `--block-net`).
- **FR-3.7** Audit log entries for every connection attempt:
  `ALLOW CONNECT api.openai.com:443`, `DENY CONNECT 169.254.169.254:80
  reason=denied_cidr`.

### FR-4 — Audit Trail (MVP)
- **FR-4.1** Every sandboxed session has a unique 64-bit session id
  (`YYYYMMDD-HHMMSS-NNNNN`).
- **FR-4.2** The audit log is an append-only file at
  `%LOCALAPPDATA%\saife\audit\<session-id>.ndjson` — one JSON object per
  line, each line a Merkle leaf.
- **FR-4.3** Recorded event types — **as shipped**: `SESSION_START`,
  `SESSION_REFUSED`, `CONNECT`, `HTTP`, `FACADE`.
  *Not shipped:* `FILE_READ`, `FILE_WRITE`, `FILE_CREATE`, `FILE_DELETE` and
  `EXEC`. The ETW provider described below was never built; see the G5 correction
  above. The policy an access was judged against IS recorded, which is what makes
  "was this path denied?" answerable after the fact — "was it touched?" is not.
  - File events: captured via an ETW provider (`Microsoft-Windows-Kernel-File`
    + a custom `sandbox-audit` provider) consuming kernel events for processes
    inside the Job Object.
  - Connect events: captured from the proxy (FR-3) — every allow/deny
    decision is logged.
  - Exec events: captured via `WMI Win32_ProcessStartTrace` or ETW
    `Microsoft-Windows-Kernel-Process` for processes in the Job.
- **FR-4.4** Each leaf contains: `seq`, `ts`, `pid`, `tid`, `op`, `target`,
  `disposition` (`allowed`/`denied`), `hash` (SHA-256 of canonicalized leaf
  body excluding `hash` and `parent`), `parent` (hash of previous leaf, or
  `null` for the genesis leaf). This forms a hash chain; the chain root is the
  **Merkle root** of the session.
- **FR-4.5** At session end, the chain root is committed to a sidecar file
  `<session-id>.root` and signed with an Ed25519 keypair stored in
  `%LOCALAPPDATA%\saife\signing-key` (generated on first run, protected by
  DPAPI at rest). `saife audit verify` recomputes the root and checks the
  signature.
- **FR-4.6** `saife audit show <id>` prints a human-readable summary
  (session header, event count, deny count, changed-files list, root + sig
  status). `--json` emits the structured log for SIEM / jq pipelines.
- **FR-4.7** `--filter` supports `op=`, `disposition=`, `path~=`,
  `host~=`, `ts>=`, `ts<=`.

### FR-5 — Profiles
- **FR-5.1** Profile files live in `%USERPROFILE%\.saife\profiles\*.json`.
  A `--profile <name>` resolves to `<name>.json`. A `--profile
  ./relative/path.json` or absolute path is also accepted.
- **FR-5.2** Profile JSON schema (v1):
  ```json
  {
    "meta": { "name": "claude-code", "version": "1.0.0", "description": "…" },
    "extends": "base-coding-agent",
    "security": { "groups": ["node_runtime", "python_runtime"] },
    "filesystem": {
      "allow": ["$HOME/.claude", "$CWD"],
      "read_only": ["$HOME/.gitconfig", "$HOME/.npmrc"],
      "deny": ["$HOME/.ssh", "$HOME/.aws"]
    },
    "network": {
      "profile": "minimal",
      "allow_domain": ["api.anthropic.com"],
      "block": false
    },
    "workdir": { "access": "readwrite" }
  }
  ```
- **FR-5.3** `"extends"` merges: child keys override parent; `filesystem.allow`
  and `network.allow_domain` arrays concatenate (de-duplicated).
- **FR-5.4** **Security groups** are built-in named path sets maintained by
  `saife` itself, expanded at profile-load time:
  - `node_runtime` — `node.exe`, `npm`/`pnpm`/`yarn` bin dirs, `npm-cache`,
    `%APPDATA%\npm`, `%LOCALAPPDATA%\pnpm`
  - `python_runtime` — `python.exe` location, `%LOCALAPPDATA%\Programs\Python`,
    `pip` cache, `%APPDATA%\Python`
  - `rust_runtime` — `%USERPROFILE%\.cargo`, `%USERPROFILE%\.rustup`
  - `java_runtime` — `JAVA_HOME`, `%USERPROFILE%\.gradle`, `%LOCALAPPDATA%\…\jdk*`
- **FR-5.5** CLI flags (`--allow`, `--allow-domain`, …) merge on top of the
  profile; flag paths append to profile allow-lists.

### FR-6 — Setup & Compatibility
- **FR-6.1** `saife setup --check-only` reports: Windows build number,
  AppContainer availability, RuleSet support (build ≥ 16299), WFP availability
  (for future network hardening), ETW provider permissions, signing-key
  presence. Exits non-zero if any MVP-required capability is missing.
- **FR-6.2** Minimum supported OS: **Windows 10 1709 (build 16299)** — the
  first build with `CreateAppContainerProfile` + RuleSet capability rules.
- **FR-6.3** `saife` is a single `saife.exe`, statically linked Rust,
  ~10–15 MB, no runtime dependencies, no installer required (drop in `PATH`).

## Non-Goals (Out of Scope for MVP)

- **NG-1. No kernel-mode driver.** WFP callout driver and minifilter FS driver
  are explicitly deferred. The MVP uses AppContainer + Job Object + userspace
  proxy only. A driver would unlock stronger network filtering and FS
  interception but requires WHQL/attestation signing, admin install, and
  months of additional work.
- **NG-2. No Undo / Rollback.** SHA-256 content-addressed snapshots are
  deferred. The audit trail records what changed; restoring it is post-MVP.
- **NG-3. No Credential Injection.** Reverse-proxy header injection and
  Windows Credential Manager integration are post-MVP. The MVP blocks network
  by default and allows domains explicitly; the agent itself is responsible
  for its own auth headers.
- **NG-4. No Ghost Sessions / detach-attach.** `saife ps` exists but
  returns only the current session. Detached sessions via Job Object +
  named-pipe IPC are post-MVP.
- **NG-5. No Runtime Supervisor / dynamic permission expansion.** No
  seccomp-notify-equivalent IPC for the agent to ask the operator for new
  access mid-session. Permissions are static for the whole session.
- **NG-6. No Sigstore / instruction-file provenance.** Deferred.
- **NG-7. No registry, no GUI, no TUI.** CLI only for MVP.
- **NG-8. No multi-user / server mode.** Single-user, single-machine.
- **NG-9. No support for UWP / Store apps.** Win32 / console processes only.
- **NG-10. No support for Windows 7 / 8 / Server 2012 R2.** 1709+ only.

## Design Considerations

### Why AppContainer + RuleSet over the alternatives

| Approach | Pros | Cons (for this MVP) |
|---|---|---|
| **AppContainer + RuleSet (chosen)** | Native to Win10 1709+, unprivileged, per-process, capability SID gives true kernel-enforced FS allow-list, auto-inherited by children, no driver. | RuleSet granularity is coarser than Landlock (path-based, not per-syscall); no per-port network rules (network is all-or-nothing per capability, hence the userspace proxy). |
| Job Object + Restricted Token only | Works on every Windows version. | No real FS allow-list — only token-group removal; cannot grant per-path. |
| Minifilter driver | True per-syscall FS interception. | Requires WHQL-signed driver, admin install, kernel-mode crash risk. Post-MVP. |
| WFP callout driver | True kernel network rules per-host/port. | Same driver-signing burden; post-MVP. |

AppContainer is the only unprivileged, native, kernel-enforced FS allow-list
mechanism on Windows. Its network model is coarse (capabilities, not per-port),
which is why the MVP pairs it with a userspace localhost proxy (FR-3) — the
same architectural choice nono makes on Linux when Landlock ABI < v4.

### Network proxy architecture

```
+-----------------------+         +-------------------------+
| sandboxed process     | HTTP(S) | saife.exe supervisor  |
| (AppContainer token)  |-------->| (outside AppContainer)  |
| only 127.0.0.1:PORT   |         | - domain allow-list      |
| reachable             |         | - always-deny list       |
+-----------------------+         | - ETW audit logging      |
                                  | - outbound TCP to real   |
                                  |   hosts on allow-list    |
                                  +-------------------------+
```

The sandboxed process is forced (via `HTTP_PROXY`/`HTTPS_PROXY` env vars
overwritten in the spawned environment, plus the AppContainer token lacking
any network capability except the loopback exemption for the proxy port) to
route through the proxy. Apps that ignore env-var proxies (raw socket users)
fall back to `--block-net` behavior because their direct connect attempts hit
the AppContainer network cap denial.

### Irrevocability

AppContainer profiles and the applied token are immutable for the lifetime of
the process tree. `saife.exe` exposes no API to mutate them after
`CreateProcessW` returns. This matches nono's Landlock irrevocability
guarantee. (Future Runtime Supervisor will use a **second, looser** AppContainer
for the supervisor itself and IPC for the agent to request expansions — never
loosening the original process's token.)

### Audit via ETW

The MVP uses **ETW** (Event Tracing for Windows) for kernel-level event
capture — file and process events come from the built-in
`Microsoft-Windows-Kernel-File` and `Microsoft-Windows-Kernel-Process`
providers, scoped to the Job Object's process set. ETW requires no driver and
runs unprivileged for the consumer session (admin only for some kernel
providers; see Technical Considerations). Network events come from the proxy
directly (no ETW needed). The hash-chain + Ed25519 root signature is computed
in userspace by `saife.exe` as events stream in.

## Technical Considerations

### Privilege discussion (per user requirement)

The user asked: unprivileged preferred, admin-for-setup acceptable *if
necessary and justified*. Decision per feature:

| Feature | Unprivileged? | Notes |
|---|---|---|
| AppContainer profile creation + RuleSet | **Yes** | `CreateAppContainerProfile` and capability-rule application work unprivileged on 1709+. |
| Job Object | **Yes** | Always unprivileged. |
| Reverse proxy (Tokio/hyper) | **Yes** | Plain userspace TCP. |
| Ed25519 signing-key generation + DPAPI | **Yes** | DPAPI `CryptProtectData` with user scope is unprivileged. |
| ETW kernel-file / kernel-process providers | **Admin for full fidelity** | The kernel file/process ETW providers emit to any consumer, but enabling them as a *real-time* consumer session with `EVENT_ENABLE_PROPERTY_SID` filter requires the consumer to be admin OR the user to be granted `SeSystemProfilePrivilege`. **Mitigation**: for the MVP, if the user is non-admin, fall back to a userspace hook (Detours-style `CreateFileW`/`NtCreateFile`/`connect` interception in the spawned process via `PROC_THREAD_ATTRIBUTE` + a small injected DLL) — coarser but unprivileged. Document this clearly in `setup --check-only`. Admin users get full ETW fidelity. |
| WFP callout driver (future) | Admin install | Deferred — not in MVP. |

**Conclusion**: the MVP runs fully unprivileged. Admin rights unlock
higher-fidelity audit (kernel ETW vs. userspace hook) but are not required for
any MVP feature.

### Rust crates (planned)

- `windows` (windows-rs) — `CreateProcessW`, `CreateAppContainerProfile`,
  `CreateJobObject`, `SetInformationJobObject`, token manipulation.
- `tokio` + `hyper` (with `rustls`) — reverse proxy.
- `ed25519-dalek` — root signing.
- `sha2` — leaf hashing.
- `serde` + `serde_json` — profile + log format.
- `clap` v4 — CLI.
- `tracing` + `tracing-subscriber` — internal logging (separate from audit).

### Repo layout

```
sandbox/
  Cargo.toml
  README.md
  prd-sandbox.md            # this file
  src/
    main.rs                 # clap entrypoint, subcommand dispatch
    cli/                    # run.rs, ps.rs, audit.rs, profile.rs, setup.rs
    profile/                # schema, loader, security groups, extends-merge
    sandbox/                # appcontainer.rs, job.rs, token.rs, spawn.rs
    proxy/                  # reverse proxy, domain allow-list, always-deny
    audit/                  # etw consumer, hash chain, signing, verify
    signing/                # ed25519 keypair, DPAPI storage
  tests/
    integration/            # powershell-driven end-to-end tests
    fixtures/                # profiles, sample programs
```

### Test strategy

- **Unit tests** in each module (Rust `#[test]`).
- **Integration tests** in PowerShell: spawn `saife run --allow <tmp> -- cmd
  /c echo hi`, assert exit code; spawn with a path outside allow-list, assert
  access denied; spawn with `--block-net`, assert `Test-NetConnection` fails;
  run audit verify, assert OK; tamper with the log, assert verify fails.
- A `--self-test` flag runs the full battery against a temp profile and
  reports PASS/FAIL — used by `setup --check-only`.

### Performance budget

- Sandbox init (profile load + RuleSet build + AppContainer + Job + token):
  target < 50 ms.
- Per-file-operation overhead: 0 (kernel-enforced, no userspace path).
- Per-network-connection overhead: one localhost hop through the proxy —
  measured < 1 ms added latency on loopback.
- Audit log size: ~200 bytes per event; a typical agent session (1k file ops,
  100 connections) ≈ 220 KB.

## Success Metrics

- **SM-1.** A sandboxed `cmd /c type C:\Users\marku\.ssh\id_rsa` returns
  `Access is denied.` in 100% of integration test runs.
- **SM-2.** A sandboxed `python -c "import urllib.request;
  urllib.request.urlopen('https://evil.example.com')"` is denied and logged
  when `--block-net` is set, in 100% of runs.
- **SM-3.** `saife audit verify <id>` returns `OK` for an untampered log and
  `TAMPERED` for a log with one byte flipped, in 100% of runs.
- **SM-4.** Sandbox init latency < 50 ms (p95) on a reference machine.
- **SM-5.** `saife setup --check-only` runs to completion without admin
  rights on Windows 10 22H2 and reports a usable feature matrix.
- **SM-6.** A child process spawned by the sandboxed process
  (`cmd /c cmd /c type …`) is still denied access to disallowed paths, in
  100% of runs — proving inheritance.

## Open Questions

1. **AppContainer vs. AppContainer + Win32 App Isolation (1903+ "Desktop Bridge"
   / `Win32 App Isolation` with `WindowsApps` capability)** — the latter gives
   a more declarative manifest but requires MSIX-style packaging. Decision
   deferred to spike in week 1 of implementation; AppContainer is the safe
   default.
2. **ETW fallback fidelity** — is the userspace Detours-style hook sufficient
   for the audit trail to be useful for non-admin users, or should the MVP
   require admin and use ETW only? Recommend: ship both paths, default to
   whichever the user's privilege allows, document the fidelity difference in
   `setup --check-only`.
3. **Proxy scope for non-HTTP traffic** — the MVP proxy handles HTTP/HTTPS
   (covers all LLM APIs and most agent network use). Raw TCP (e.g. git over
   SSH, gRPC) bypasses the proxy and falls back to `--block-net`. Is this
   acceptable for MVP, or do we need a SOCKS5 proxy mode? Recommend: HTTP/HTTPS
   only for MVP, SOCKS5 post-MVP.
4. **Profile registry** — MVP is local files only. Do we want to reserve the
   `saife profile pull <url>` namespace now so a future registry fits
   cleanly? Recommend: yes, reserve but no-op.
5. **Signing key backup** — the Ed25519 audit-signing key is generated on first
   run and DPAPI-protected. Should `saife setup` offer to export a
   recovery-encrypted backup? Recommend: out of MVP scope, document as
   post-MVP.
