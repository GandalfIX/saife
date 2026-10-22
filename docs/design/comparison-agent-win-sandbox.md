# Comparison: `agent-win-sandbox` vs. our `sandbox`

> **Reviewed:** 2026-09-16 · Repo: <https://github.com/fmuecke/agent-win-sandbox>
> (MIT, PowerShell). Sources: README, `docs/threat-model.md`, **and full code
> review** of all 14 scripts (setup, launcher, checker, attack-surface test,
> removal, bootstrap, wrappers, managed settings, surface canary) at commit
> `359769b` (2026-09-15). Our side: `agent.md`, README, PRD, and
> `critical-review.md`.
>
> Code-level verification results are in
> [Code review: documentation vs. implementation](#code-review-documentation-vs-implementation)
> below. Summary: the documentation is accurate, with two caveats — one
> real supply-chain weakness (`Invoke-Expression` of a remote installer) and
> one stale header comment.

## TL;DR

`agent-win-sandbox` is **identity-based isolation**: run the agent as a
separate, dedicated local Windows user (`AgentSandbox`) with its own profile,
logon session, and workspace, protected by conventional ACLs and account-scoped
firewall rules. It is explicitly positioned as *blast-radius reduction, not
hard containment*.

Our `sandbox` is **capability-based isolation**: keep the agent in the user's
session but strip its token to a deny-by-default AppContainer identity where
every filesystem access and network connect must be explicitly granted at the
kernel.

They win on **friction and identity separation** (any per-user tool just
works; the developer's credentials, token caches, and browser state are
structurally outside the sandbox identity). We win on **enforcement strength**
(kernel-enforced read *and* write confinement, irrevocable; total network
deny without admin; process-tree lifetime control). Their own threat model
concedes every one of those gaps.

## What agent-win-sandbox is

PowerShell scripts (`Setup-`, `Start-`, `Check-`, `Remove-`,
`Test-AttackSurfaces.ps1`) plus a downloaded third-party `launch-as` broker.
Built-in wrappers for Claude Code and Copilot CLI; any other agent (OpenCode,
…) can be installed per-user and run. Requires **admin for setup**, removal,
and policy changes; the daily launch is passwordless via the broker.

Core mechanics:

- **Separate OS identity** — local standard user `AgentSandbox`; separate
  profile, Credential Manager, per-user agent installs. The agent never runs
  as the developer.
- **Separate logon session** — `launch-as-broker` creates an independent
  logon session and noninteractive desktop (ConPTY + named pipes only).
  Their "verified broker boundary": the child lacks the developer's shared
  logon SID, so it cannot use default-DACL grants for process-memory reads
  or termination of the developer's processes.
- **Fixed workspace** — `C:\AgentSandbox` gets Modify for the sandbox user;
  expected agent writes stay there.
- **Protected control plane** — launcher/bootstrap/checker/managed-policy
  files are admin-write in ProgramData/Program Files.
- **Account hardening** — deny network logon, deny remote-interactive logon,
  hidden from the login screen.
- **Account-scoped firewall blocks** — outbound deny rules for SMB/NetBIOS
  (139/445/137/138), RPC (135), RDP (3389), WinRM (5985/5986) attributed to
  the `AgentSandbox` SID. **HTTPS and everything else stays open.**
- **Agent-layer policy** — a Claude `managed-settings.json` disables bypass
  mode, locks hooks/MCP sideloads, denies WebFetch/WebSearch, blocks edits
  to `.git`/`.claude`/`.mcp.json`. The actual file does more than the README
  describes: it also restricts Claude's own `Read`/`Edit` to
  `$SANDBOXDIR/**` (substituted with the real workspace path at setup) and
  allow-lists a narrow Bash set (`git status/diff/log/show`, `msbuild`,
  `cl`, `cmake`, `ctest`, `dir`) — agent-layer, prompt-based read
  confinement on top of the OS boundary.
- **Honest threat model** — explicit non-goals, STRIDE table, residual risks,
  and an excellent analysis of cooperative-proxy weakness and broker-based
  exfiltration (BITS, WebClient/WebDAV, DNS).

It is, in effect, a simplified OpenAI Codex "Elevated Sandbox"
(see `critical-review.md` Option A): dedicated principal user + firewall —
but **without** the write-restricted token, and **without** a mandatory
proxy. A data point in itself: the OpenAI composition was apparently heavy
enough that a solo project shipped the identity-split alone.

## Side-by-side

| Axis | agent-win-sandbox | our `sandbox` |
|---|---|---|
| Primitive | Separate user identity, default ACLs, firewall | AppContainer SID + RuleSet/DACL allow-lists, Job Object |
| Admin needed | Setup, removal, policy changes | None for FS + `--block-net` (admin-for-setup accepted for future network work) |
| FS **reads** | Not confined: everything readable by ordinary Users (all of Program Files, Windows, machine-wide tools); developer profile blocked only by default profile ACLs | Kernel default-deny: only explicitly granted paths |
| FS **writes** | Conventional: workspace by expectation; the sandbox user can write anywhere a standard user can (its profile, Users-writable dirs) | Kernel default-deny: only explicitly granted paths |
| Enforcement durability | ACL hygiene dependent; checker must be re-run after policy changes; drift is a documented failure mode | Irrevocable for process-tree lifetime; tied to the token |
| Network | HTTPS wide open; port-blocks for SMB/RPC/RDP/WinRM; proxy env vars documented as cooperative-only | `--block-net`: kernel-denied `connect()`, fully unprivileged; domain allow-list deferred (loopback gate), planned `privateNetworkClientServer` fix |
| Credentials | Separate Credential Manager/Kerberos/git/PATs from the developer's; sandbox-owned, scoped PATs; plaintext env var storage (documented risk) | Agent must have its credential dirs *granted in* (e.g. `--allow $HOME\.claude`), so the LLM credential is inside the boundary; credential injection is out of MVP scope |
| Logon session/desktop | Independent logon session, noninteractive desktop, ConPTY; "verified broker boundary" | Child runs in the developer's session (AppContainer restricting SIDs should deny cross-process handle opens, but we haven't documented/tested this — see actions) |
| Process tree | No job object, no resource limits (DoS is a documented residual risk) | Job Object `KILL_ON_JOB_CLOSE`, no `BREAKAWAY_OK` |
| Parallelism | One active sandbox session; every process of the sandbox user can read the whole sandbox profile (incl. the PAT) | Per-session SIDs, distinct install trees, `PROTECTED_DACL` cross-session isolation; session B cannot even *read* session A's tree |
| Open-ended binaries | Trivial: whole sandbox profile is writable, any per-user install works | Option E: sanctioned per-session dirs (`.sandbox/<sid>/bin/…`), bounded, no re-profiling |
| Config escape (CR-10) | Agent config locked admin-write; covers the files they thought of | Profiles live in `%USERPROFILE%\.sandbox\profiles\` — outside *any* writable workspace, enforced by the sandbox boundary itself |
| Workflow | Repos must live in the fixed `C:\AgentSandbox`; separate terminal/identity | `sandbox run` in the real checkout, in place |
| Audit | None (documented residual risk) | Planned: Merkle + Ed25519, proxy `CONNECT` events |
| Agent integrations | Ships today: claude/copilot wrappers, managed settings, checker, attack-surface test | MVP: profiles, no per-agent policy yet |

## What they do better — and what to adopt

1. **Identity separation protects the developer's credential stores.** In
   their model the developer's `.claude` OAuth token, git credentials, and
   browser state are structurally outside the sandbox identity. In ours the
   agent is *the user*, so `~/.claude` must be granted into the sandbox for
   the agent to function — a prompt-injected dependency can read (and, if
   granted readwrite, modify) the primary LLM credential. This is our
   biggest genuine weakness relative to them; credential injection
   (currently out of MVP scope, `prd-sandbox.md` Non-Goals) is the answer.
2. **Verified logon-session boundary.** Their independent logon session
   removes the shared-logon-SID default-DACL grant (process-memory reads,
   termination). We run in the developer's session and rely on AppContainer
   restricting-SID semantics for the same effect — plausible, but
   unverified. **Action:** port their `sandbox-surfaces` diagnostic as a
   non-destructive check (`Test-AttackSurfaces` equivalent) / integration
   scenario: can the sandboxed process open handles to the user's
   processes, read their memory, or touch the interactive desktop?
3. **Ship-today agent integration.** Managed agent policy
   (`managed-settings.json`) as a defense-in-depth layer on top of the OS
   boundary is a good pattern. **Action (future):** our profiles could
   optionally deploy/verify agent-layer policy for wrapped agents.
4. **Granular online-mode network story.** Their explicit lateral-movement
   port denies (SMB/RPC/RDP/WinRM) while keeping HTTPS is more usable than
   our current all-or-nothing (`--block-net` only, allow-list deferred).
   More importantly: when our allow-list mode lands via the
   `privateNetworkClientServer` capability, **loopback *and intranet*
   become reachable** — SMB/RPC to internal hosts may no longer be gated.
   **Action:** add explicit lateral-movement denies (or verify AppContainer
   capability SIDs already gate those protocols) to the US-3 follow-up
   design.
5. **Threat-model depth worth mining.** Their analysis of broker-mediated
   exfiltration (BITS, WebClient/WebDAV, localhost listeners, docker-users,
   WSL/Hyper-V filtering planes) and of firewall rule precedence (an
   explicit block cannot be paired with an overlapping allow to re-enable a
   proxy path) applies to our future proxy/WFP work. Cite it in the US-3
   spec.

## What we do better

1. **Read confinement.** Their sandbox reads *everything* readable by
   ordinary Users: the whole of Program Files, Windows, machine-wide tools,
   and any broadly readable file. Their threat model says so. We deny
   reads of anything not granted (`~/.ssh`, sibling projects, other
   sessions' trees — S-2/S-3/S-5/S-13 pass).
2. **Write confinement that is actually enforced.** Their "expected agent
   writes stay in the workspace" is convention; the sandbox user can write
   anywhere a standard user can. Ours is a kernel allow-list, irrevocable
   for the process tree.
3. **Network.** `--block-net` is a total, kernel-enforced, unprivileged
   deny. Their model leaves HTTPS fully open (exfiltration over allowed
   protocols is a documented non-goal), their proxy variables are
   cooperative, and their own doc explains why that is not a boundary.
4. **No admin, no ACL-hygiene dependence.** Their boundary decays with ACL
   drift and requires periodic checker runs and manual audits; ours cannot
   be loosened at runtime by anything.
5. **Process-tree control and resource containment.** Job Object kill-on-
   close, no breakaway; they have neither (DoS residual risk).
6. **Parallel sessions with cross-session poisoning protection.** They
   allow one session, and any process of the sandbox user can read the
   entire sandbox profile including stored tokens.
7. **In-place workflow.** No fixed workspace, no separate terminal
   identity, no moving repos to `C:\AgentSandbox`.
8. **Audit (planned).** They have none and list it as a residual risk;
   US-4 is one of our MVP pillars.

## Open questions their work raises for us

- **DNS exfiltration under `--block-net`?** They flag the DNS Cache service
  as a possible low-bandwidth exfil channel for firewall-based models. For
  us: `getaddrinfo` resolves via a system service; does a
  network-capability-less AppContainer still get name resolution (the
  query performed by the service, not the sandboxed process)? Needs a test;
  if it resolves, add DNS exfil to the US-3 threat list and to
  `docs/design/specs/us-3-…/spec.md`.
- **COM broker reachability from AppContainer.** Their BITS/WebDAV broker
  concerns may not apply to us: AppContainer COM activation generally
  requires server opt-in. Verify; if it holds, our design blocks a whole
  exfil class their model is vulnerable to — worth documenting as a
  security property.
- **Surfaces test.** As above: verify and document the process-handle /
  desktop / window-station exposure of an AppContainer child in the
  developer's own logon session.

## Code review: documentation vs. implementation

Full read of all scripts at commit `359769b`. Their documentation turns out
to be **accurate and honest** — every threat-model claim checked out against
the code. Findings:

### Confirmed in code (matches docs)

- **Firewall rules** — exactly 3 outbound Block rules SID-scoped via
  `-LocalUser "D:(A;;CC;;;<SID>)"`: TCP 139/445, UDP 137/138, TCP
  135/3389/5985/5986. Web/HTTPS untouched, confirming "not full egress
  isolation."
- **Account hardening** — `secedit` sets `SeDenyNetworkLogonRight` +
  `SeDenyRemoteInteractiveLogonRight`, leaves interactive logon intact
  (the checker even fails if interactive is accidentally denied — the
  launcher would break). Account hidden via `SpecialAccounts\UserList`.
- **ProgramData control plane** — `icacls /inheritance:r` locks every
  launcher/bootstrap/wrapper/config file to Admins/SYSTEM full, Users RX.
- **Copilot PAT** — stored plaintext in the user environment
  (`[Environment]::SetEnvironmentVariable(..., 'User')`), exactly the
  documented weakness.
- **launch-as** — download is SHA-256-pinned; removal refuses to delete a
  broker-managed account without unenrolling it first.
- **`Check-AgentSandbox.ps1`** — genuinely thorough: config-drift
  comparison, admin-write ACL verification on every artifact, firewall rule
  drift (ports/protocol/SID scoping), secedit rights re-verification,
  profile broad-read detection, and a PATH scan for Claude installs outside
  the sandbox user that could leak in via machine PATH.
- **`Test-AttackSurfaces` + surface canary** — the diagnostic is really
  read-only (`OpenProcess(PROCESS_VM_READ|PROCESS_TERMINATE)` and
  `OpenInputDesktop` probes, no memory reads). The canary pair
  (`tools/surface-canary/`) is exemplary: a SHA-256-verified 32-byte
  synthetic buffer and a known window title, so a positive cross-user
  result is bounded, reproducible evidence without touching real secrets.
- **No Job Object / resource limits anywhere** — the DoS residual risk in
  their STRIDE table is confirmed by absence in code.

### Findings the docs do not mention

1. **`claude-wrapper.ps1:59` executes a remote script with no verification:**
   `Invoke-RestMethod 'https://claude.ai/install.ps1' | Invoke-Expression`.
   This is inconsistent with their own hygiene (launch-as is hash-pinned,
   Copilot is verified against `SHA256SUMS.txt`) — the primary agent
   install path is trust-on-download. Whoever controls `claude.ai` DNS/TLS
   at install time gets code execution as `AgentSandbox`. Low-priv user,
   but it runs *before* the sandbox boundary matters (agent binaries land
   in the sandbox profile). Worth remembering when we design our own agent
   bootstrap: pin or signature-verify anything we execute.
2. **Stale header comment in `Setup-AgentSandbox.ps1`** — the file header
   claims they "add EXPLICIT DENY only on the current user's sensitive
   dirs as belt-and-suspenders," but section 4 deliberately does the
   opposite (comment in code: explicit denies are brittle; verify profile
   ACLs and warn loudly instead). The implementation is the *weaker* of
   the two: developer-profile protection is default-ACLs + a runtime
   warning, with no deny ACEs at all. Our "ACL-hygiene dependent"
   assessment is therefore accurate — if anything it understates it.
3. **Managed settings are stricter than documented** (see above) — Claude's
  Read/Edit is confined to the workspace at the *prompt* layer. Still
  agent-layer, bypassable by any child process the user approves, but a
  meaningful second boundary.
4. **Setup/check asymmetry on GPO firewalls** — if firewall policy is
   GPO-managed (`LocalPolicyModifyState != 0`), setup only *warns and
   continues* while the checker *fails*. Rules may silently not apply on
   domain-joined machines.

### Code quality impression

Careful, defensive PowerShell: wrapper scripts refuse to run outside the
`AgentSandbox` identity, removal supports `-WhatIf`, requires typing
`REMOVE`, refuses while the profile is loaded, and guards legacy
version combinations. The security diagnostics (surfaces + canary) are the
best-engineered parts of the repo and are directly reusable as patterns
for our own test suite.

## Verdict

Two honest designs with different centers of gravity. agent-win-sandbox is
the pragmatic, ships-today, low-friction answer for "don't let the agent be
*me*" — at the cost of an ACL-hygiene-dependent boundary, open HTTPS egress,
no read confinement, and admin for lifecycle. Our `sandbox` is the stronger
*boundary* — kernel-enforced, default-deny, irrevocable, unprivileged — but
still an MVP, with the allow-list network mode deferred and credential
handling unresolved (their strongest argument against our model).

The most valuable takeaways are their `sandbox-surfaces` diagnostic concept,
the lateral-movement/intranet concerns for our future online mode, and the
broker/DNS exfil analysis for the US-3 threat model.
