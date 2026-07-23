# Critical Review: Challenging the AppContainer-based approach

> **Status:** Critical re-evaluation of `prd-sandbox.md` after reading OpenAI's
> "Building the Codex Windows sandbox" (May 2026) and the agentpatterns-ai
> "Windows Sandboxing for Coding Agents" analysis (June 2026).
>
> **TL;DR:** Our PRD's core mechanism choice — AppContainer + RuleSet as the
> FS isolation foundation — is **the exact primitive OpenAI evaluated and
> rejected** for the same workload we are targeting. We need to either justify
> why our case differs from theirs or pivot the design. This document lists
> every critique found, then proposes options.

## What the two sources say

### OpenAI's Codex Windows sandbox post — key findings

OpenAI built a Windows sandbox for Codex (a coding agent that runs arbitrary
binaries — git, node, pip, MSBuild, user scripts — against the user's real
checkout). Their engineering journey:

1. **Evaluated AppContainer** → **rejected.** Quote: *"AppContainer is the
   native Windows sandbox, a capability-based isolation model for apps that
   know up front exactly what they need to access… Codex is not a single,
   narrowly-scoped app. It supports open developer workflows: shells, git,
   python, package managers, build tools, and any other binaries the agent
   requires. In practice AppContainer did not fit the problem."*

2. **Evaluated Windows Sandbox (disposable Hyper-V VM)** → **rejected** for
   the coding-agent workload (needs to act on the real checkout, not a
   throwaway desktop; also unavailable on Windows Home).

3. **Evaluated Mandatory Integrity Control (MIC)** → **rejected** because
   labeling the workspace as Low integrity mutates the real filesystem and
   lets *any* Low-integrity process (browsers, renderers, other agents)
   write into it — leaks the boundary.

4. **First prototype ("Unelevated Sandbox")**: synthetic `sandbox-write` SID +
   write-restricted token + ACLs + env-var network suppression
   (`HTTPS_PROXY=http://127.0.0.1:9`, `GIT_SSH_COMMAND=cmd /c exit 1`,
   a `denybin` dir prepended to PATH). **Worked for FS writes.** Network
   was *"advisory"* — a process can ignore env, bypass PATH, open sockets
   directly. *"Too risky."*

5. **Why env-var network failed even with effort**: Windows firewall rules
   can't match the *non-principal* identity of a restricted token. A rule
   on `codex.exe` doesn't follow child `git.exe`/`python.exe` processes.
   Per-user rules match the real Windows user, not the sandboxed execution
   context. Per-binary-path rules are too coarse (block all `python.exe`,
   not just this sandbox's python). Port/address rules are the wrong shape.

6. **Shipped solution ("Elevated Sandbox")**: dedicated local users
   (`CodexSandboxOffline`, `CodexSandboxOnline`) as the token *principal*
   so Windows firewall has a stable identity to match. **Requires admin
   for setup** (create users, store credentials with DPAPI, create firewall
   rules, grant read ACLs on common dirs). Split into three binaries:
   `codex.exe` (real user), `codex-windows-sandbox-setup.exe` (elevated,
   setup only), `codex-command-runner.exe` (runs as sandbox user, applies
   restricted token, launches the child via `CreateProcessAsUserW`).
   `CreateProcessAsUserW` from the real-user side failed due to a
   privilege boundary — they needed a process *already running as the
   sandbox user* to do the restriction + launch.

7. **Honest about tradeoffs**: their FS write-scoping is an AND-gate (user
   SID + restricted SID list), not airtight containment. Reads are not
   confined by the token. Config-Based Sandbox Escape (writing the CLI's
   own config from inside the sandbox) is a known class of attack. They
   say: *"Treat it as write-scoping, not containment."*

### agentpatterns-ai analysis — key findings

The article distills four requirements a coding-agent sandbox on Windows
must satisfy:

1. **Open-ended binary execution** — agent picks binaries at runtime.
2. **Host workspace read-write** — agent edits the user's real checkout.
3. ~~**No admin elevation**~~ — **DECISION (2026-07-23):** admin for setup is
   acceptable. Setup creates local users, firewall rules, and DPAPI-protected
   credentials; per-task launch and the agent itself run unprivileged. This
   matches OpenAI's shipped "Elevated Sandbox" design and unblocks Option A.
4. **Policy propagates down the process tree** — children inherit.

Then maps each primitive:

| Primitive | Fails requirement | Why |
|---|---|---|
| AppContainer | 1 (open-ended binaries) + 4 (firewall rules don't follow children) | Capability model requires up-front enumeration; firewall can't match non-principal identity |
| Windows Sandbox | 2 (host workspace) + SKU-limited | Disposable VM, not host checkout; no Hyper-V on Home |
| MIC | 2 (mutates host SACLs) + 4 (leaks to other Low-integrity procs) | Labels persist on disk and apply to every Low-integrity process |

**The composition that works** (OpenAI's shipped one): synthetic SID +
write-restricted token + dedicated principal user. The agentpatterns doc is
explicit: *"No single Windows primitive sandboxes a coding agent cleanly."*

**Known leak**: `Everyone` sits in the restricted SID list, so any directory
granting `Everyone` write access silently weakens the boundary.

**Strictly-stronger fallback**: *"WSL2 with Landlock/bubblewrap isolates more
strongly than restricted-token composition. The cost is filesystem drift and
slow small-file I/O."* — this is nono's approach.

## Critiques of our PRD, point by point

### CR-1. AppContainer is the wrong primitive for an open-ended coding agent

Our PRD (FR-2.1, FR-2.2) chose AppContainer + RuleSet as the FS isolation
foundation, calling it *"the only unprivileged, native, kernel-enforced FS
allow-list on Windows."* OpenAI evaluated exactly this and rejected it for
exactly our workload, with a specific reason:

> AppContainer is "a capability-based isolation model for apps that know up
> front exactly what they need to access" — a coding agent does not know up
> front. It picks git, node, pip, MSBuild, and user scripts at runtime.

Our PRD tries to mitigate this with **security groups**
(`node_runtime`, `python_runtime`, `rust_runtime`, `java_runtime`, etc.) that
pre-grant access to known toolchain paths. But this is precisely the
"enumerate up front" model OpenAI says doesn't fit. The agent can invoke an
arbitrary binary the user just installed (a new Go toolchain, a custom
`.exe` in `%LOCALAPPDATA%`, a portable app on a USB drive) and our sandbox
would deny it unless the user pre-declared the path. We either:

- grant broad access (weakening the sandbox), or
- force the user to enumerate every possible tool (recreating the
  "approve every command" friction Codex was built to eliminate).

**Verdict:** This is a serious design flaw. We need to either (a) justify why
our target workload is narrower than Codex's, or (b) pivot to the
write-restricted-token approach.

### CR-2. Our network story has the same weakness OpenAI abandoned

Our PRD (FR-3) uses a localhost reverse proxy + `HTTP_PROXY`/`HTTPS_PROXY` env
vars + an AppContainer network cap that denies all direct `connect()`. We
claim raw-socket apps "fail closed" because the AppContainer token lacks
network capability.

The problem: **this only works if AppContainer is the isolation mechanism.**
OpenAI rejected AppContainer (CR-1), so they never got to use its network-cap
denial. They fell back to env-var proxying alone, found it advisory and
bypassable, and moved to Windows firewall + dedicated users.

If we keep AppContainer, our network story is actually **stronger** than
OpenAI's unelevated attempt (kernel-level cap denial vs. env-var hope). But
if we drop AppContainer (because of CR-1), we fall into the same trap they
did: env-var proxying is advisory, raw-socket apps bypass it, and we have no
kernel-level network denial without admin (firewall) or a driver (WFP, deferred).

**Verdict:** Our network design is internally consistent *only if AppContainer
is viable*. The moment we pivot off AppContainer, the network story collapses
to OpenAI's abandoned "advisory" approach — and we'd need admin + firewall +
dedicated users just like they did.

### CR-3. "Unprivileged" may be the same trap OpenAI fell into

Our PRD (G4, FR-6) makes unprivileged operation a goal. OpenAI's first
prototype was also unprivileged ("Unelevated Sandbox") and they explicitly
abandoned it because network suppression was too weak without admin/firewall.
Their shipped solution requires admin for setup.

The agentpatterns doc lists "no admin elevation" as a requirement but then
documents that the *working* composition requires admin for setup. The
"no admin" requirement is aspirational; the shipping reality is "admin for
setup, unprivileged to run tasks."

Our PRD already accepts a privilege split for audit (ETW admin vs. userspace
hook non-admin — FR-4.3, Technical Considerations). We should be honest that
the same split may be forced for the sandbox itself.

**Verdict:** Our "fully unprivileged MVP" claim is likely unrealizable for
the full feature set. We should reframe as "admin for setup, unprivileged
to run" — matching OpenAI's final design — or explicitly accept weaker
network isolation in the unprivileged mode.

### CR-4. AppContainer does not give us what we claimed re: read confinement

Our PRD says AppContainer "starts from nothing allowed and the RuleSet grants
access" — implying read confinement. But the OpenAI/agentpatterns analysis
says the write-restricted-token approach *"confines only the filesystem
[writes]… reads are not confined by the token."*

AppContainer *does* confine reads (default-deny on the RuleSet). So in this
one respect our approach is stronger than OpenAI's write-only gate — **if**
AppContainer actually works for the open-ended binary workload. CR-1 says it
doesn't. So this "advantage" is moot.

### CR-5. Our "security groups" don't solve the open-ended-binary problem

The agentpatterns doc is explicit: the failure mode of AppContainer is
*"the agent picks binaries at runtime."* Our security groups pre-declare
common toolchains, but:

- A user installs a new tool mid-session → the sandbox denies it.
- A user has a non-standard install location → the group doesn't cover it.
- The agent runs a project-local script needing access to unusual paths →
  denied.
- A build tool spawns a helper binary in a temp dir → denied.

We'd either expand groups to cover the world (losing isolation) or force
the user to maintain the allow-list manually (losing the "just works"
property). This is the exact friction OpenAI built their sandbox to
eliminate.

**Verdict:** Security groups are a partial mitigation, not a solution. They
work for the 80% common case but break the open-ended workflow that is the
whole point of a coding agent.

### CR-6. The `Everyone` leak applies to the write-restricted-token approach too

If we pivot to OpenAI's approach (write-restricted token + synthetic SID), we
inherit their known leak: `Everyone` is in the restricted SID list, so any
directory granting `Everyone` write access silently weakens the boundary.
OpenAI documents this honestly. We would need to as well — and it's a real
attack surface on a multi-user or shared machine.

**Verdict:** Not a blocker, but we'd inherit it. Documented, not hidden.

### CR-7. We dismissed WSL2 too quickly

Our PRD's introduction argues against WSL2 because it "forces a Linux runtime"
and "cannot sandbox native Win32 processes." The agentpatterns doc says
*"WSL2 with Landlock/bubblewrap isolates more strongly than restricted-token
composition"* and calls it the strictly-stronger fallback — at the cost of
filesystem drift and slow small-file I/O.

nono's entire Windows story is WSL2-based. If our goal is "nono for native
Windows," we're choosing native-fidelity over isolation-strength. That's a
defensible product choice (Windows developers want to run native Win32 tools,
not Linux tools), but we should frame it honestly as a tradeoff, not as
"WSL2 is wrong."

**Verdict:** Our anti-WSL2 stance is a product-positioning decision, not a
technical superiority claim. Document it as such. The MVP could even *offer*
a WSL2 backend (future F-14) for users who want stronger isolation and don't
mind the Linux filesystem view.

### CR-8. We claimed "zero runtime overhead" — true for AppContainer, questionable for the alternative

Our PRD (G3) says "Zero runtime overhead — enforcement happens in the kernel."
AppContainer RuleSet enforcement is indeed in-kernel at `IRP_MJ_CREATE`. But
OpenAI's write-restricted-token approach does an extra ACL check on every
write (the AND-gate) — also in-kernel, so near-zero, but not "zero." And if
we add a localhost proxy for network, every HTTP request takes a loopback
hop. We should soften this claim to "near-zero" or "kernel-enforced, no
userspace monitor."

### CR-9. Our audit two-tier story (ETW admin vs. hook non-admin) is fine but orthogonal

This critique doesn't change our audit design — ETW-for-admin and
userspace-hook-for-non-admin is still the right call. But it reinforces CR-3:
we already accept a privilege split for audit fidelity. The same honesty
should apply to the sandbox itself.

### CR-10. We ignored the "config-based sandbox escape" attack class

The agentpatterns doc cites Cymulate (2026) on "Configuration-Based Sandbox
Escape": writing the CLI's own config from inside the sandbox turns startup
into an escape primitive. If the sandboxed agent can write to
`~/.sandbox/profiles/` or `~/.config/sandbox/`, it can rewrite the policy
that will be applied to the *next* session. Our PRD's profile search path
includes `./.sandbox/profiles/` (repo-local, inside the workspace) — if the
workspace is writable by the agent, the agent can write a malicious profile
that widens the next session's allow-list.

**Verdict:** Real issue. The profile directory must be either outside the
writable workspace or the profile must be integrity-checked (hash-pinned in
the session record, verified at next launch). Add to MVP or document as a
known gap.

## Summary: the core problem

Our PRD chose **AppContainer + RuleSet** as the foundation. OpenAI's team,
working on the same workload (a coding agent running arbitrary binaries on a
user's real Windows checkout), **explicitly evaluated AppContainer and
rejected it** because AppContainer's capability model requires up-front
enumeration of what the app will access — and a coding agent's binary set
is open-ended.

OpenAI's shipped solution uses a *different* composition: synthetic SID +
write-restricted token + dedicated principal user + Windows firewall, with
admin for setup. This is the working pattern the agentpatterns-ai article
endorses.

Our PRD is, in effect, betting that AppContainer works for a workload OpenAI
already proved it doesn't work for.

## Options

### Option A — Pivot to the OpenAI composition (recommended to evaluate)

> **DECISION (2026-07-23): admin for setup accepted.** This option is now
> viable and is the leading candidate.

Adopt the proven pattern: synthetic `sandbox-write` SID + write-restricted
token + dedicated local users (`SandboxOffline`/`SandboxOnline`) + Windows
firewall for network. Admin for setup, unprivileged for run.

**Pros:**
- Proven by OpenAI in production for the exact same workload.
- Solves the open-ended-binary problem (the token gates writes, not binary
  enumeration — any binary can run, only writes are scoped).
- Solves network via Windows firewall matched to the dedicated user
  principal (no env-var advisory hack).
- agentpatterns-ai endorses this composition.

**Cons:**
- Requires admin for setup (creates local users, firewall rules, DPAPI
  credential storage, read-ACL grants). Violates our G4 "unprivileged" goal.
- Inherits the `Everyone`-in-restricted-SID-list leak (documented).
- Only confines writes, not reads (we'd need a separate read-confinement
  story — or accept read-openness as OpenAI does).
- More complex: three binaries (main, setup, command-runner) instead of one.
- `CreateProcessAsUserW` requires the command-runner to run as the sandbox
  user — a real implementation wrinkle OpenAI hit.

**Reframe:** "admin for setup, unprivileged to run" — matches OpenAI's
shipped reality and our existing audit-tier split.

### Option B — Keep AppContainer, narrow the target workload

Argue that our sandbox is for a *narrower* workload than Codex: not "any
binary the agent picks" but "binaries declared in a profile." This is closer
to nono's model (profiles enumerate paths) and works if the user is willing
to maintain the allow-list.

**Pros:**
- Stays unprivileged (AppContainer needs no admin).
- Keeps our existing PRD, specs, and security-group design.
- Network story is strong (AppContainer network cap + loopback exemption).
- Read confinement works (default-deny RuleSet).

**Cons:**
- OpenAI explicitly rejected this for the coding-agent workload. We'd be
  betting against their finding.
- Security groups are a partial mitigation, not a solution (CR-5). The
  open-ended-binary friction remains.
- We'd have to honestly scope the product as "sandbox for pre-declared
  workflows, not open-ended coding agents" — which may not match what users
  actually want.

### Option C — Hybrid: AppContainer default, elevated composition optional

Ship both: an unprivileged AppContainer mode (Option B) for the common case
and an elevated OpenAI-style mode (Option A) for users who need open-ended
binary execution with strong network. `sandbox setup --check-only` reports
which mode is active and why.

**Pros:**
- Covers both the "I just want my agent sandboxed" user and the "I need
  open-ended binary execution" user.
- Honest about the tradeoff.
- Matches our existing two-tier pattern (audit admin/non-admin).

**Cons:**
- Two code paths to maintain.
- More documentation surface ("which mode am I in?").
- The AppContainer mode still has CR-1's fundamental issue for any user who
  ventures beyond pre-declared toolchains.

### Option E — Constrained-open-ended: sanctioned install directories (leading candidate)

> **DECIDED (2026-07-23): this is the direction.** Resolves CR-1 without
> requiring the agent to pre-declare every tool.

The agent may install new tools mid-session, but **only into a small fixed
set of sanctioned install directories**. The allow-list enumerates the
*directories*, not the tools — so it stays small and stable while the
agent's tool set is dynamic but bounded.

#### Model

The profile grants read+write+execute on a handful of per-workspace,
**per-session** "install roots". Conventional choices:

| Sanctioned dir (under `$CWD`) | What goes there | Example workflow |
|---|---|---|
| `.sandbox/<sid>/bin/` | Arbitrary `.exe` / `.bat` / `.ps1` the agent downloads or compiles | agent runs `Invoke-WebRequest -OutFile .sandbox\<sid>\bin\jq.exe`, then `.sandbox\<sid>\bin\jq.exe …` |
| `.sandbox/<sid>/venv/` | Python virtualenv | agent runs `python -m venv .sandbox\<sid>\venv && .sandbox\<sid>\venv\Scripts\pip install requests` |
| `.sandbox/<sid>/npm/` | npm prefix (per-project `node_modules` lives in `$CWD\node_modules` already) | `npm install --prefix .sandbox\<sid>\npm <pkg>` |
| `.sandbox/<sid>/cargo/` | `CARGO_HOME` for per-project rust builds | `CARGO_HOME=$CWD\.sandbox\<sid>\cargo cargo install ripgrep` |
| `.sandbox/<sid>/tmp/` | Scratch space (downloads, extracted archives) | anything, but not on `PATH` so not directly executable |
| `$CWD` itself | The project source tree (the agent's primary job) | the normal read/write workspace |

Plus the built-in `windows_common` and runtime security groups
(`node_runtime`, `python_runtime`, `rust_runtime`, `java_runtime`,
`dotnet_runtime`, `git_runtime`) which grant **read** access to the
system-installed toolchains the agent invokes *by name* (the system
`python.exe`, `node.exe`, `cargo.exe`, etc. — installed by the user, not the
agent).

#### Per-session isolation (DECISION 2026-07-23)

> Two agents running in parallel on the same machine — even against the same
> `$CWD` — must get **individual** install trees. A shared `.sandbox/bin/`
> would let agent A drop a trojan `git.exe` that agent B picks up, and the
> two agents' installs would race.

The install roots are therefore scoped by **session id**:
`.sandbox/<session-id>/bin/`, `.sandbox/<session-id>/venv/`, etc. The
session id is the same one used by the audit trail (US-4,
`YYYYMMDD-HHMMSS-NNNNN`), so every installed file is attributable to exactly
one session in the audit log.

This gives:

- **No install races**: agent A's `jq.exe` v1 and agent B's `jq.exe` v2
  land in `.sandbox/<sid-A>/bin/` and `.sandbox/<sid-B>/bin/` respectively.
- **No cross-session poisoning**: agent A cannot drop a binary where agent B
  will execute it.
- **Clean attribution**: every file under `.sandbox/<sid>/` belongs to one
  session in the audit log.
- **Trivial cleanup**: wipe `.sandbox/<sid>/` on session end (or per a
  retention policy).

#### Caching via persist / reuse (DECISION 2026-07-23)

> Per-session is the safety default. But re-installing a 2 GB Python venv or
> a cargo toolchain with 500 crates every session is a real UX cost. We
> solve this with an explicit, user-visible **persist / reuse** mechanism —
> caching is opt-in, not silent.

Lifecycle commands:

- `sandbox persist <sid> [--as <name>]` — promote a session's install tree
  to a named, durable store. The session's `.sandbox/<sid>/` is moved (or
  hardlinked) to `%USERPROFILE%\.sandbox\stores\<name>\`, which is outside
  the writable workspace of any future session by default. A manifest of
  file hashes is recorded for later integrity checking.
- `sandbox run --reuse <name> -- …` — start a new session whose install
  roots are bind-mounted (or path-aliased) to the named store instead of a
  fresh `.sandbox/<new-sid>/`. The reused store is **read-only** by default
  (the agent can call its tools but cannot modify them); a `--reuse-rw`
  flag opts into a writable reused store for incremental accumulation.
- `sandbox store list` / `sandbox store rm <name>` — manage durable stores.
- Default retention for unnamed session trees: wiped at session end (or
  after a configurable TTL, e.g. 7 days, to allow `persist` after the fact).

Why this design:

- **Security default stays tight**: per-session, ephemeral, no sharing
  unless the user explicitly asks for it.
- **Caching is visible**: the user typed `--reuse`, so they know they're
  loading a prior session's tools. The audit trail records which store a
  session used.
- **Integrity check ready**: the manifest of hashes recorded at `persist`
  time can be verified at `--reuse` time (future hardening, ties into
  Sigstore provenance F-5).
- **No per-tool semantics needed**: unlike a "share cargo cache but not
  arbitrary exes" split, the user persists the whole session tree as a
  unit. Simpler model, no tool-specific knowledge in `sandbox`.

#### How this resolves CR-1

- **System-installed tools**: the agent calls `python`, `node`, `gradle`,
  `git`, `cargo`, `npm` — these live in system locations covered by security
  groups (read + execute). No enumeration of *which* python packages or
  *which* npm packages is needed; the runtime binary is allowed, and the
  per-session install dir is where its packages go.
- **New tools the agent needs**: the agent installs them into
  `.sandbox/<sid>/bin/` (or the relevant runtime-specific dir). The
  allow-list already grants execute on `.sandbox/<sid>/bin/` so any new
  binary there just runs — no profile edit, no restart, no admin.
- **Bounded**: the agent can install *anything* — but only into
  `.sandbox/<sid>/**`. It cannot install a malicious binary into
  `C:\Windows\System32\`, `%USERPROFILE%\.cargo\bin\`, or anywhere else on
  `PATH` outside the sanctioned dirs. A malicious dependency that tries to
  drop a payload into a system dir is denied at the FS layer.
- **Parallel-safe**: two concurrent agents in the same `$CWD` get distinct
  `<sid>`-scoped trees — no races, no cross-poisoning.
- **Profile stays small**: the profile lists ~6 sanctioned directory
  *patterns* plus the security groups. The `<sid>` is a runtime variable,
  expanded at spawn time. The profile does not need to know whether the
  agent will use `jq`, `ripgrep`, `httpie`, or a custom `.exe`. All of
  those land in `.sandbox/<sid>/bin/` and just work.

#### Composition with the isolation mechanism

Option E is **mechanism-agnostic** — it works with either:

- **AppContainer + RuleSet** (Option B): grant `Read/Write/Execute` on the
  sanctioned dirs (with `<sid>` expanded), `Read/Execute` on security-group
  paths, `Read/Write` on `$CWD`. Default-deny everything else. The agent
  can install into `.sandbox/<sid>/bin/` because it has write there; the
  new binary runs because it has execute there. Read confinement still
  works (RuleSet is default-deny).
- **Write-restricted token** (Option A): grant `sandbox-write` SID on the
  sanctioned dirs (with `<sid>` expanded) + `$CWD`. Same effect for writes;
  reads unconfined as per the token model.

For `--reuse <name>`: the RuleSet (or token) simply points at
`%USERPROFILE%\.sandbox\stores\<name>\bin\` instead of
`.sandbox/<sid>/bin\`. Read-only by default (no Write capability on the
store dir); `--reuse-rw` adds Write.

#### Decisions still needed

- **Is AppContainer viable with Option E?** It may be. The CR-1 objection
  ("AppContainer requires up-front enumeration") is weakened: we enumerate
  *directory patterns*, not *tools*. The agent's tool set is dynamic but
  always lands in `.sandbox/<sid>/**`. The profile is stable. **This needs
  a spike** — try building the Option-E AppContainer RuleSet and running
  an agent that installs `jq.exe` into `.sandbox/<sid>/bin/` and executes
  it. If it works, we get read confinement + unprivileged network cap +
  no admin. If AppContainer has undocumented issues with
  execute-from-arbitrary-dirs, fall back to Option A (write-restricted
  token) + Option E directory model.
- **PATH handling**: the sandboxed process's `PATH` should be prepended
  with `.sandbox/<sid>/bin` and the runtime-specific dirs
  (`.sandbox/<sid>/venv/Scripts`, `.sandbox/<sid>/npm`,
  `.sandbox/<sid>/cargo/bin`) so newly-installed tools resolve first. This
  is an env-var transform at spawn time, not a policy decision.
- **Cleanup**: `.sandbox/<sid>/` is per-session, git-ignorable (ship a
  default `.gitignore` entry for `.sandbox/`). Wiped at session end by
  default unless `persist` was called; a TTL-based sweeper cleans up
  abandoned trees.

#### Pros

- Resolves CR-1: the agent gets a dynamic toolset without re-profiling.
- Keeps the profile small and stable (enumerate dir patterns, not tools).
- Mechanism-agnostic — works with AppContainer or write-restricted token.
- Bounded: a malicious dependency can only write into `.sandbox/<sid>/**`,
  not system dirs or other projects.
- Parallel-safe: per-session trees prevent cross-agent poisoning and races.
- No admin needed for *running* (only setup, per CR-3 decision).
- Per-workspace: each project has its own `.sandbox/`, no cross-project
  pollution.
- Opt-in caching: `persist`/`reuse` gives users control without silent
  sharing.

#### Cons

- The agent must cooperate (install into `.sandbox/<sid>/**`). A tool that
  insists on installing to a global location (e.g. `npm install -g`) is
  denied. We mitigate by setting `npm_config_prefix=.sandbox/<sid>/npm`
  etc. in the spawned env, but some tools ignore env config. Documented as
  a workflow constraint, not a sandbox failure.
- `.sandbox/<sid>/bin/` on `PATH` means a malicious binary there is
  *auto-run* if the agent shells out to a bare name that collides with a
  system tool (e.g. the agent installs a trojan `git.exe` in
  `.sandbox/<sid>/bin/` and then runs `git`). Mitigation:
  `.sandbox/<sid>/bin` is prepended to `PATH` *after* the security-group
  system dirs, so system `git.exe` resolves first by default; the agent
  has to explicitly call `.sandbox/<sid>/bin/git.exe` to get the trojan.
  Alternatively, prepend `.sandbox/<sid>/bin` *first* (so the agent's
  installs win) and rely on the audit trail to catch trojans. This is a
  policy choice — expose as a profile option `path_order: system_first |
  sandbox_first` (default `system_first` for safety).
- If the agent writes a malicious binary into `.sandbox/<sid>/bin/` and
  then runs it, that binary runs with the agent's (sandboxed) privileges —
  same as any tool the agent runs. The sandbox boundary is still intact
  (the binary can't escape the FS allow-list), but the agent has been
  "tricked" into running attacker code. This is the prompt-injection
  threat, not a sandbox escape; the audit trail catches it.
- Per-session default means **no caching** unless the user opts in via
  `persist`/`reuse`. Re-installing large toolchains every session is the
  cost of the safe default. Mitigated by `persist` for users who want it.
- `--reuse-rw` creates a shared writable tree that multiple concurrent
  `--reuse-rw` sessions could race on. Document: `--reuse` is read-only and
  parallel-safe; `--reuse-rw` is single-writer (the second `--reuse-rw`
  against the same store is denied with a clear error).

#### Relationship to nono and Codex

- **nono**: nono's profiles enumerate paths and the agent is expected to
  stay within them. Option E is a generalization: enumerate *directories
  that can hold arbitrary tools*, not the tools themselves. nono doesn't
  document this pattern explicitly but its security groups are a similar
  idea (pre-grant common toolchain dirs).
- **Codex (OpenAI)**: Codex rejected AppContainer because "the agent picks
  binaries at runtime" and AppContainer wants up-front enumeration. Option
  E answers that objection: the agent can pick binaries at runtime *as long
  as they live in `.sandbox/bin/`*, which was pre-declared. We should
  verify the spike (see "Decisions still needed") actually satisfies the
  open-ended-binary requirement in practice — if the agent can `curl` a
  binary into `.sandbox/bin/` and run it, the requirement is met.



> **REJECTED (2026-07-23): native Windows only.** WSL2 requires
> virtualization, which is not available on every target host, and if WSL2
> were acceptable we would just use nono. This option is removed from
> consideration.

## Recommendation

> **UPDATED (2026-07-23):** Option E (constrained-open-ended via sanctioned
> install directories) is the chosen direction, combined with admin-for-setup
> (per OQ-2 decision) and native-Windows-only (per OQ-3 decision).

**Spike Option E with AppContainer first; fall back to the OpenAI composition
if the spike fails.** The plan:

1. **Spike**: build a minimal AppContainer + RuleSet that grants
   `Read/Write/Execute` on `.sandbox/bin/`, `$CWD`, and `Read/Execute` on
   the system python.exe. Launch a sandboxed process that downloads `jq.exe`
   into `.sandbox/bin/` and runs it. If this works, AppContainer + Option E
   is viable — proceed to update the PRD accordingly.
2. **If the spike fails** (AppContainer has undocumented issues with
   execute-from-arbitrary-dirs, or the RuleSet doesn't compose the way we
   need): pivot to Option A (OpenAI's write-restricted token + dedicated
   users + firewall, admin for setup) **with the Option E directory model
   layered on top**. Option E is mechanism-agnostic — it works with either
   approach.
3. **Either way**: the profile enumerates sanctioned *directories*, not
   tools. This is the key insight that resolves CR-1: the agent gets a
   dynamic toolset without re-profiling, and the allow-list stays small and
   stable.

The worst outcome is to ship AppContainer pretending it solves the
open-ended coding-agent problem when OpenAI has already shown it doesn't —
Option E is our answer to that objection, and the spike will tell us if it
holds.

## Open questions for the user

1. ~~Is the target workload truly open-ended (agent runs arbitrary binaries
   the user installs mid-session) or pre-declared (user maintains a
   profile)?~~ **DECIDED (2026-07-23): constrained-open-ended.** The agent
   may install new tools mid-session, but only into a small fixed set of
   **sanctioned install directories** (e.g. `.sandbox/bin/` for arbitrary
   exes, a sandbox-local venv for Python packages). The allow-list enumerates
   the *directories*, not the tools — so it stays small and stable while the
   agent's tool set is dynamic but bounded. See Option E below.
2. ~~Is "admin for setup" acceptable~~ **DECIDED (2026-07-23): yes.** Admin
   for setup, unprivileged to run — matches OpenAI's shipped design. This
   unblocks Option A.
3. ~~Is a WSL2 backend (Option D) worth offering as a strong-isolation escape
   hatch, or do we hold the "native Windows only" line?~~ **DECIDED
   (2026-07-23): native Windows only.** WSL2 is out of scope — if WSL were an
   option we would just use nono. Additionally WSL2 requires
   virtualization, which is not available on every host we want to target
   (including Windows Home and locked-down corporate endpoints). This removes
   Option D entirely.
4. ~~How do we handle the config-based sandbox escape (CR-10)? Pin profile
   hashes in the session record, move the profile dir outside the writable
   workspace, or both?~~ **DECIDED (2026-07-23): option (b) — keep profiles
   outside the writable workspace.** Drop the repo-local profile search path
   (`./.sandbox/profiles/`) introduced in US-5. Profiles live only in
   `%USERPROFILE%\.sandbox\profiles\`, which the sandboxed process cannot
   write to. The agent therefore cannot rewrite the policy that will be
   applied to the next session. (Hash-pinning in the session record remains
   a possible future hardening, but is not needed for MVP since the writable
   boundary excludes the profile dir.)
