# Developer guide

How this repository is built, how the pieces fit, and what a change has to keep
true. It is the map for someone changing the code; the user-facing description
lives in `README.md`, the rules an agent must follow in `AGENTS.md`, and the
decisions in `docs/adr/`.

Task-oriented usage (running commands, grants, network, profiles, audit) is in
`docs/USER-GUIDE.md`. Read this first, then `docs/adr/0004-mxc-ga-windows-unelevated-egress.md` (the
backend you will work on by default) and the current plan under
`docs/plans/`.

---

## 1. Orientation

One Rust binary (`sandbox`) enforces a policy on a child process. Two backends:

| Backend | How containment works | Elevation |
|---|---|---|
| `mxc` (default in a `--features mxc-backend` build) | MXC `processcontainer`: additive filesystem policy, egress forced through this process's own loopback proxy | **none** |
| `appcontainer` (escape hatch) | AppContainer token + per-directory DACL grants + admin loopback exemption | **admin** for networked sessions |

`mxc-launch` is a second binary: a supervisor-owned wrapper that builds the
container's environment and proves the child's path to the proxy before the
payload runs. It is compiled only with the feature.

The tool is bin-only: there is no library target, so every test run is
`--bin sandbox` / `--bins`. `cargo test --lib` fails by design.

---

## 2. Repository map

| Path | What lives there |
|---|---|
| `src/main.rs` | CLI dispatch, `run_inner`, the two session paths, exit codes |
| `src/cli.rs` | clap surface, `resolve_backend` / `route_backend` / `default_backend`, refusal constants |
| `src/net/mod.rs` | network config resolution, `session_budget()`, `ProxyEnv` |
| `src/net/proxy.rs` | the listener: CONNECT, absolute-form forward, control-plane endpoints, decisions, counters, refusal budgets |
| `src/net/mxc.rs` | the only module that talks to `mxc-sdk`: request building, launch, tier gate, proof gate, session clock |
| `src/net/prompt.rs` | interactive dialog, coordinator, slots, headless fast-fail |
| `src/net/token.rs` | `RunToken` (one per run, constant-time compare, redacted Debug) |
| `src/net/matcher.rs` | hard-deny sets, allow/deny matching (pure) |
| `src/net/learned.rs`, `intent.rs` | persisted learned policy, D-4 intent registry |
| `src/net/upstream.rs` | corporate upstream proxy chaining (D-2) |
| `src/audit/` | chain core (`mod`), session-start leaf (`session_start`), `verify`, `show`, `filter` |
| `src/sandbox/` | AppContainer specifics: `appcontainer`, `allowlist`, `spawn`, `dacl_journal`, `job` |
| `src/profile.rs` | profile schema, load, merge, resolve |
| `src/setup.rs`, `security_groups.rs`, `signing.rs` | setup checks + elevation probe, group expansion, Ed25519 signing |
| `src/bin/mxc-launch.rs` | wrapper launcher: env, probe, child spawn, exit code |
| `tests/run-tests.ps1` | the integration suite (93 scenarios), `-Backend` switch |
| `tests/vm/` | disposable-VM lane (stages the repo, runs the suite in a guest) |
| `tests/Clear-HostTestArtifacts.ps1` | host cleanup gate (`HOST-CLEAN` / `HOST-DIRTY`) |
| `docs/adr/`, `docs/plans/`, `docs/tasks/*/PROGRESS.md` | decisions, plan, per-task record |

---

## 3. How a run works

### 3.1 Common front half (`run_inner`)

1. Resolve the profile and the network config (`net::resolve_network`).
2. Resolve the backend: `--backend` or `cli::default_backend(feature_enabled)`,
   then `route_backend` (refuses a backend the binary cannot execute — exit 2).
3. Open the audit writer and **arm** the session-start guard.
4. Branch: `mxc` session path or AppContainer session path.

### 3.2 MXC path

1. Bind the proxy listener on `127.0.0.1:0`; mint one `RunToken`.
2. Build the session request (`request_for_session`) and **probe the tier** of
   that exact request (`probe_tier`).
3. Apply guardrail 2: `TierExpectation::Exactly("base-container")`. A degraded
   or unnamed tier → root(`deny`) + `SESSION_REFUSED(tier_mismatch)`, no child.
4. **Write the session-start root now** — before the child can run — with
   `tier`/`tier_source`/`tier_needs_dacl_augmentation` from the probe,
   `elevated` from the process token and `proxy_endpoint` from the bound port.
   A supervisor kill after this point leaves a readable chain that `verify`
   reports as `INCOMPLETE`.
5. Launch through `launch_session` (wrapper runs its probe, then the payload).
6. Guardrail 1 on the epoch: `probes >= 1` **and not**
   (`unauthenticated > 0 && accepted == 0`). Otherwise refuse
   (exit 126, `proxy_probe_unmet` / `workload_cannot_authenticate`).
7. Mirror the child's exit code; report `124` for a deadline kill with the
   `TimeoutReason` (`workload_budget_exceeded`, `prompt_budget_exhausted`,
   `session_handshake_timeout`, `session_teardown_timeout`).

### 3.3 AppContainer path

Creates the AppContainer profile, builds the per-session `.sandbox/<sid>` tree
(shims, venv), grants DACLs (journaled first), registers the loopback exemption
(admin), spawns the child with a restricted token, and removes what it granted
on teardown.

### 3.4 The proxy pipeline

Every request — CONNECT, absolute-form plain HTTP, and the control plane — goes
through `decide()`: hard deny → learned deny → allow-list → block-list →
prompt. Requests that need an interactive decision are coalesced per host (one
dialog, many followers). The listener authenticates every request with the
run token first; a wrong or missing credential is refused with `407` +
`Proxy-Authenticate: Basic` and is **not** counted as a consultation.

Forwarded (absolute-form) requests are held to one request per connection, one
head framing, a rewritten `Host`, no `Expect`, and an origin `407` is converted
to `502` (`docs/adr/0001`, D9).

### 3.5 Audit model

- One NDJSON file per session under `%LOCALAPPDATA%\sandbox\audit\`, plus
  `<sid>.root` (sealed root) and `<sid>.sig` (Ed25519).
- Leaves are hash-chained (`hash` over the canonical body, `parent` = previous
  hash). `sandbox audit verify` recomputes the chain, checks the signature, and
  reports `INCOMPLETE` when a session did not end cleanly.
- The **root is `SESSION_START`** and is written before any child can run. On a
  refused session it carries `disposition: deny`, followed by `SESSION_REFUSED`.
- Leaves are written **before** the response they describe.

---

## 4. Build and test

```bash
cargo build --release                        # default: mxc + mxc-launch
cargo build --release --no-default-features  # AppContainer only (says so at startup)
cargo test  --bin sandbox                    # 611 + 10 ignored  (default)
cargo test  --bin sandbox --no-default-features  # 490
cargo test  --bin mxc-launch                 # 19 (default build only)
cargo clippy --all-targets [--no-default-features] # must be 0 warnings
```

`mxc-backend` is a **default feature**: the plain build everyone runs contains the
default backend and the wrapper binary. Opting out is explicit
(`--no-default-features`) and the resulting binary prints a notice instead of
silently behaving differently.

Gates for any change: both feature states green (default and `--no-default-features`), clippy 0 in dev and release,
`cargo build --release` 0 warnings, touched files `rustfmt`-clean, CRLF
preserved (byte counts, not `grep`: this host's `grep` hides CR).

**Live legs** (`--ignored`) start real containers and **execute
`target/debug/sandbox.exe`**, not the test binary — run
`cargo build --features mxc-backend --bin sandbox` first, or the kill-leg's
freshness guard fails the lane (and you will be debugging a stale binary).

**VM lane** (disposable guest, where the full suite runs):

```powershell
pwsh -File tests\vm\Invoke-TestsInVM.ps1 -Image sbx-base-a -Backend mxc -Phase all
```

**The VM lane and the window station.** PowerShell Direct sessions run on a
`Service-0x0-*$` window station whose security descriptor carries **no
ALL APPLICATION PACKAGES ACE** (`S-1-15-2-1`). A sandboxed child that touches
`user32` — `venv`/`ensurepip`'s subprocess, `ctypes`, any managed runtime — dies
at load with `0xC0000142`, and scenario S-9 fails at `ensurepip`. Interactive
`WinSta0` carries those ACEs, which is why the same suite passes on a desktop.
The harness therefore grants `(A;;GA;;;S-1-15-2-1)` on the session's window
station and desktop before running the suite, non-fatally, and prints whether the
grant succeeded; it lives only in that logon session. If a VM-only failure looks
like a load-time kill (`0xC0000142`, `ERROR_DLL_INIT_FAILED`), check that line in
the harness output before suspecting the product.

A VM session always runs with the guest's token, which is elevated: the VM
proves product logic, **not** elevation. The standard-user lane that would close
that gap is parked (see §8). End every host block with
`tests\Clear-HostTestArtifacts.ps1` → `HOST-CLEAN`; it reports what needs an
elevated run instead of failing silently.

---

## 5. Recipes

**Add an integration scenario.** Write `Invoke-Scenario-S<n>` in
`tests/run-tests.ps1`, register it in the scenario map, bump `$script:MaxScenario`,
and — if it depends on AppContainer-specific mechanisms (DACLs, the per-session
tree, the loopback exemption, concurrent sessions) — add it to
`$script:AppContainerOnlyScenarios` with the reason. Assert the **decision**
(an audit leaf, `%{http_connect}`, a status code), never "exit 0 plus a
transport failure". Parse-check the file (`[Parser]::ParseFile`) before running.

**Add an audit field.** Extend the emitting function, add the key to
`audit::filter`'s `KNOWN_KEYS` (plus `BOOL_KEYS`/`ENUM_KEYS` when it is not a
free string, so `=true` and `=null` behave), keep `verify` untouched (it is
field-agnostic), and document the field where the rest of the taxonomy lives
(`docs/tasks/adr-0001/d-5.1-*.md`).

**Add a CLI flag.** `cli.rs` (with a doc comment stating the default and the
refusal behaviour) → `run_inner` → `README.md` if user-visible.

**Change a security gate.** Amend the ADR in place (dated status line, the
superseded rule quoted as history, the new evidence and what it still does not
prove), then implement with tests in **both** directions: the case the gate must
refuse, and the legitimate case it must not.

---

## 6. Invariants a change must not break

1. **The root exists before the child.** Exactly one `SESSION_START` per run,
   `seq 0`, `parent null`, facts complete.
2. **The audit leaf is written before the response it describes.**
3. **One credential per run.** One listener per process; a second live token is
   refused (`TokenAlreadyLive`); the token never appears in a URL that is
   logged, in an audit leaf, or in a diagnostic.
4. **Refusals are not consultations.** A `407`, a malformed request, or a
   foreign token must not advance `accepted`/`tunnels`.
5. **Refusal evidence is bounded but exact.** 8 individual leaves per arm, then
   one aggregate per window carrying the exact count.
6. **Decisions are taken on the same normalized string the action uses**
   (host case, IPv6 brackets, trailing dot).
7. **A forward request is one request.** No pipelined second request, no
   `Host` from the client, no origin `407` relayed.
8. **A gate's scope is stated.** "Listener lifetime" and "launch epoch" are
   different counters; mixing them lets one launch inherit another's evidence.

---

## 7. Where decisions are recorded

Folder layout under `docs/` (the two guides are the only files at its root):

| Folder | Contents |
|---|---|
| `adr/` | accepted decisions (0001 network hardening, 0002 MXC integration surface, 0003 base-container enforcement, 0004 GA unelevated egress) |
| `design/` | requirements (`design/prd/`, `design/specs/`), critical review, comparison, spikes, testing principles, plan-design docs |
| `research/` | external-source analysis, impact analysis, capability matrices, backend findings (`research/backends/process-container/`) |
| `plans/` | implementation plans, one per task or phase |
| `tasks/` | per-task records: `PROGRESS.md` row tables, review verdicts, commit references |
| `notes/` | future ideas and bug write-ups |

The row tables under `tasks/<task>/PROGRESS.md` are the status of record: per
task, the review verdicts and the commit that landed it.

When evidence moves, amend the ADR in place and keep the superseded rule
visible; never leave two documents contradicting each other and never relax a
gate silently.

---

## 8. Known open items

- **The standard-user VM lane is parked.** No mechanism available from a
  PowerShell Direct session starts a process as a second local account
  (`CreateProcessWithLogonW` → 87, Task Scheduler → 206, both reproduced against
  a re-baked image with a real profile). Two untried mechanisms are named in
  `PROGRESS.md` ("P3.1 blocker").
- **Both test templates are the same guest build (29680)** after the 2026-10-22
  re-bake, so "both images" is single-build evidence. Neither image is a GA
  servicing build; the version matrix is plan step **P5**.
- **The last refusal window is flushed on listener drop, not on the fly.** Per
  window the aggregate count is exact, but a reader of a LIVE chain can be short
  by up to `SUPPRESSED_LEAF_WINDOW - 1` (11) refusals until the run ends.
- **Audit-chain linearity rests on a single writer thread.** `append` takes
  `last_hash` and re-sets it after the write; two concurrent appenders could
  each emit `parent: null`. Fine while the proxy uses one worker; add a
  `debug_assert` before widening it.
