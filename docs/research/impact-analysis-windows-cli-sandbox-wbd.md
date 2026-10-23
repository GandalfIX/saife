# Impact Analysis: Windows CLI Sandbox Work Breakdown (WBD) on the Current Plan and Implementation

> **Status:** Analysis, 2026-10-04.
> **Input:** `input/WINDOWS_CLI_SAIFE_WORK_BREAKDOWN.md` (referred to below as
> "the WBD" — 2,337 lines, sections 0–17, tickets D-01…Q-07, releases R0–R4,
> gates G0/G0S/G1–G5).
> **Scope of this document:** What the WBD changes for (a) the current `saife`
> product plan (PRD, specs, in-flight plans), (b) the current state of
> implementation, and (c) our process — most concretely the binding amendment
> that **all host-dependent testing moves into a disposable VM**, with a new
> plan step that spins one up
> (`docs/plans/2026-10-04-vm-test-infrastructure.md`).
> This document analyzes and recommends; it does not silently rewrite the PRD.
> Adoption decisions are listed in §5.

---

## 1. Executive summary

1. **The WBD is not an increment to our current plan — it specifies a different
   execution core.** It mandates Microsoft MXC's BaseContainer/PSEC path as the
   *only* backend and explicitly forbids the mechanism our current tool is built
   on: *"It must never run a workload through AppContainer+BFS, AppContainer+DACL,
   an unsandboxed process, WSL, Hyper-V, or another fallback backend"* (WBD §1).
   Our MVP *is* AppContainer + per-directory DACL allow-lists.

2. **The WBD product cannot ship where our current product ships.** It targets
   **Windows Experimental Future Platforms build `29671.1000` Enterprise x64** —
   an experimental build. Our dev machine is build `26200`. MXC discovery
   evidence (D-01…D-13) therefore *cannot* be produced on this host at all;
   it requires a machine (or VM) running that exact build. This independently
   forces VM-based testing for the WBD track.

3. **Both tracks stay "preview" for different reasons.** The WBD hard-gates any
   production security claim on G0S (upstream MXC must retract its *"profiles
   must not be treated as security boundaries"* warning). Our interim
   AppContainer tool makes no formal boundary claim either but is *usable on
   stable Windows today*. These are complementary, not competing, postures —
   which is why we recommend a two-track strategy (§4, D1).

4. **Regardless of the track decision, testing moves into VMs** (user directive,
   2026-10-04). The current integration suite mutates host ACLs and AppContainer
   profiles on the dev machine (the rollback-script rule in `AGENTS.md` exists
   precisely because of this); the WBD additionally requires dedicated
   build-29671.1000 runners (Q-01), clean-machine VM tests (G3, Q-04), and a
   Hyper-V-isolated reference oracle (D-13). The VM step is defined as a plan of
   its own and slots in **before** all further host-dependent work: see
   `docs/plans/2026-10-04-vm-test-infrastructure.md`.

---

## 2. Current-state baseline (2026-10-04, branch `feature/windows-sandbox`)

| Area | State |
|---|---|
| Execution core | AppContainer profile + per-directory DACL Allow ACEs (allow-list deny-by-default), per-session Option E install trees (`.sandbox/<sid>/{bin,venv}` with PROTECTED DACLs) |
| Job Object | `KILL_ON_JOB_CLOSE`, no `BREAKAWAY_OK` — tree teardown works |
| DACL hygiene | Crash-safe journal + teardown restore + orphan recovery just landed (`dacl_journal.rs`, commits `e794e7b`, `9970ef4`); `tests/cleanup-session-aces.ps1` rollback script exists |
| Network | `--block-net` fully working unprivileged (capability SID withheld). `--allow-domain`: proxy + matcher + token implemented, but loopback gate is admin-only (`NetworkIsolationSetAppContainerConfig`), so the flag currently **downgrades to block-net semantics with a warning**. ADR-0001 hardening in flight in a worktree (mid Phase 3; capability-SID `privateNetworkClientServer` work, upstream dialer, learned approvals, prompt dialog; resumes at task 3.4) |
| Audit | Proxy `CONNECT` events, hash chain, Ed25519 signing, `audit show/verify`, `--filter` implemented. Kernel file/exec capture (PRD FR-4.3) **not** implemented (Tier-3 hard part) |
| Profiles | JSON, user-global only (`%USERPROFILE%\.saife\profiles\`), `extends` merge, security groups; workspace files cannot widen grants (matches WBD stance) |
| Doctor | `setup --check-only` (build, AppContainer, Job, network report) |
| MXC-derived hardening plan | Tasks 0, 3A, 3B done. Task 1 (ingress warning) and Task 2 (`--lpac`) open |
| Tests | `cargo test` unit suite; `tests/run-tests.ps1` scenarios S-1…S-74 run **on the dev host** and mutate ACLs/profiles; documented host-mutation bugs (SetEntriesInAclW hang; python store alias) |
| Host | Windows 10 Pro, build 26200, x64, hypervisor present (Hyper-V capable) |

---

## 3. What the WBD changes

### 3.1 Hard conflicts with the current design

| # | Topic | Current plan/implementation | WBD requirement | Conflict |
|---|---|---|---|---|
| C1 | Execution backend | AppContainer + DACL allow-lists | MXC BaseContainer/PSEC **only**; AppContainer+BFS and AppContainer+DACL explicitly forbidden (§1) | **Fundamental.** The current execution core is a prohibited backend for the WBD product |
| C2 | OS floor | Windows 10 1709+ (stable), any supported build | Build `29671.1000` Enterprise x64, experimental; runtime probes decide | WBD product runs nowhere we can currently test without a dedicated machine/VM |
| C3 | Host-side DACL mutation | Core mechanism (ACE grants, journal, restore) | BaseContainer grants need **no host DACL mutation**; the whole journal/restore machinery has no WBD counterpart | Current crown-jewel work (F-C/F-D) becomes obsolete *on the WBD track* — but the crash-safe journaling *pattern* maps directly to B-07 (durable generation journal) and F-05A (audit durability) |
| C4 | Network downgrade | `--allow-domain` downgrades to `--block-net` with a warning | "No compatibility mode silently drops a requested … network restriction"; unsupported network posture is an **error**, never a downgrade (§1, R2/R3 rules) | Ours warns (not silent), but the WBD would require fail-closed. Interim acceptable; target must fail closed |
| C5 | Release claim | MVP preview, no formal boundary claim | Preview **mandated** until G0S; labeling rules; per-release evidence sets | Aligned in spirit; WBD is far stricter (signed required-controls manifests, detached promotion evidence) |
| C6 | Profiles | JSON v1, user-global, CLI merge on top | Versioned **TOML**, four trust layers (engine invariants / machine ceiling / user profiles / project request), monotonic composition, project files may only **narrow** | Redesign for the WBD product. Our "user-global only, workspace can't widen" decision (CR-10) is validated and carries over as a subset |

### 3.2 What survives, ports, or gets redesigned

| Current asset | WBD equivalent | Action |
|---|---|---|
| Path canonicalization / allow-list resolution (`allowlist.rs`, variable expansion) | S-01 canonical path validator, S-02 grant-overlap validator, F-04 plan paths | **Port** — the Tier-1 logic and its test battery are the most valuable reusable code; WBD adds reparse-point/TOCTOU depth (S-03) |
| Domain matcher, always-deny CIDRs, network profiles (`net/matcher.rs`) | N-01/N-02 network policy semantics + pure decision engine | **Port** — same pure-predicate design, extended (IDNA, DNS rebinding, address classes, operation observability) |
| Audit hash chain + Ed25519 signing + filter (`audit/*`, `signing.rs`) | F-05 events (OCSF-aligned) + F-05A protected durable sink | **Split**: keep the chain/signing as the integrity layer; adopt the OCSF-aligned event schema, bounded/redaction rules, and fail-closed sink contract |
| Session ids, per-session install trees (Option E) | Typed launch generations; C-06 synthetic user dirs; S-13 hard storage quota | **Evolve**: per-session trees become quota-backed session roots; generation identity binds plan + resources |
| Job Object kill-on-close, breakaway blocking | S-07 resource ceilings (process count, committed memory) pre-resume; D-08 discovery (Job coexistence with MXC ownership is an open blocker!) | **Extend**; note D-08 is a stop-work gate: if MXC's Job ownership conflicts with pre-resume controls, R1 is blocked |
| DACL journal module + orphan recovery | B-07 crash-consistent generation ownership; F-05A audit durability | **Retire on the WBD track, port the discipline** (write-before-apply, keep-on-failure, quarantine-on-corrupt, PID-reuse guards) |
| `setup --check-only` | B-01 `doctor` (side-effect-minimal, never launches workload code, no fallback suggestions) | **Port**; note WBD's warning that `--probe` performs stale-DACL recovery — treat probing as a security-state operation |
| `tests/run-tests.ps1` S-1…S-74, tiered testing philosophy | Q-01 layered pipeline, Q-02 release gate suite | **Move into VMs** (see §4 amendment A1); scenario structure and "denial discriminators" carry over |
| Proxy implementation (`net/proxy.rs`, token auth) | N-03 policy proxy + N-04 PSEC/WFP integration | **Supersede eventually**; ADR-0001's current slice remains valuable only for the interim track |
| In-flight ADR-0001 (capability SID, learned approvals, prompt dialog) | Interim-only on the WBD track (R3 supersedes: WFP + identity-bound proxy + manual revisioned approvals) | **Finish the current slice or consciously park** (§5 D4) |
| mxc-derived Task 1 (ingress warning) | Interim-only (BaseContainer has no `privateNetworkClientServer` capability) | **Land** — cheap, documents a real limitation |
| mxc-derived Task 2 (`--lpac` / AAP opt-out) | Interim-only (AAP SID is an AppContainer concept) | Optional; deprioritize if pivoting |
| PRD / specs / critical-review | WBD becomes governing for the *new* product; PRD stays governing for the interim tool | **Keep both, explicitly labeled** (§5 D1) |

### 3.3 Process and posture impact

- **Everything becomes evidence-first.** The WBD's core discipline: no guessed
  MXC/PSEC APIs, no invented capabilities, runtime probes (not build numbers)
  decide support, every launch is attested, every claim has a ticket and a
  machine-readable artifact. Our current fail-closed philosophy aligns; the
  evidence bar rises by an order of magnitude.
- **"One ticket per agent per PR" with dependency gates** (D-03/D-04 are
  stop-work gates) — stricter than our current user-story flow. Adopt for the
  WBD track.
- **Security-claims posture:** the WBD hard-codes that MXC upstream currently
  disclaims security-boundary status (G0S). Our docs must not let the two-track
  strategy blur claims: the interim AppContainer tool and the WBD preview
  artifact make *different* claims on *different* Windows builds.

### 3.4 The blocking fact for local WBD work

The WBD assumes an R&D host on build `29671.1000`. Our host is build `26200`.
Every discovery ticket (D-01…D-13) requires reproducible evidence from that
build, recorded with the pinned MXC commit. **Until we have a machine or VM
image of that build, the entire WBD Phase 0 is blocked.** This makes the VM
step (below) not just a safety improvement but the *prerequisite* for the WBD
track, and it makes VM testing mandatory for the current track as well
(host-mutation hygiene).

---

## 4. Amendments adopted from this analysis

### A1 — VM testing amendment (binding, in effect for both tracks)

> All Tier 2 / Tier 3 (host-dependent) tests run inside a **disposable VM**, not
> on the developer host. This applies retroactively to the existing
> `tests/run-tests.ps1` suite (S-1…S-74) and prospectively to every WBD
> discovery, E2E, fuzz, and packaging lane. A new early step — **VM-01 "VM test
> infrastructure"** — is inserted **before P0** of the WBD and before any further
> host-run integration testing of the current tool. It becomes the seed of the
> WBD's Q-01 "dedicated BaseContainer-capable runner" lane and the G3/Q-04
> clean-machine lane.

Implementation plan: `docs/plans/2026-10-04-vm-test-infrastructure.md`.
Policy updates: `docs/design/testing-principles.md`, `sandbox/AGENTS.md`, `README.md`
(all updated 2026-10-04). The AGENTS.md rollback-script rule remains mandatory
for any test that still runs on the physical host; in-VM runs get rollback by
construction (VM deletion / checkpoint revert).

### A2 — Documentation split

- `input/WINDOWS_CLI_SAIFE_WORK_BREAKDOWN.md` stays **unmodified** as external
  input (repo convention: inputs are read-only).
- The WBD is treated as the authoritative plan **for the new product**, subject
  to the amendments recorded here (currently only A1). Any further local
  amendments get recorded in this document, not by editing the input.

---

## 5. Decisions required (owner: maintainer)

| # | Decision | Options | Recommendation |
|---|---|---|---|
| D1 | Track strategy | (a) Hard-switch: abandon AppContainer tool, build only the WBD product. (b) Two-track: keep the current tool as the *interim* MVP on stable Windows; start the WBD product in parallel. | **(b) Two-track.** The current tool is the only thing usable on stable Windows today; the WBD product is blocked on an experimental-build VM image and months of discovery. The interim tool also de-risks UX, profiles, proxy policy, and audit design that port forward. |
| D2 | Home for the WBD product | (a) Sibling directory `C:\Users\marku\tools\windows-agent-sandbox\` per the monorepo rule and the WBD's expected shape (with `mxc/` pinned checkout as its own sibling). (b) Subdirectory under `sandbox/`. | **(a) Sibling**, matching both the WBD's workspace assumptions and the repo's "one tool per directory" rule. Requires the rename ADR the WBD mentions only if we later move it. |
| D3 | Build `29671.1000` access | Do we have ISO/VHDX access for the experimental build, or a designated R&D host? | **DECIDED 2026-10-12: acquired.** The `29671.1000` media was superseded by a later flight of the same Experimental Future Platforms channel: `Windows11_InsiderPreview_EnterpriseVL_x64_en-gb_29680_1000.iso` accepted by the maintainer. Image B build unblocked (VM plan Task 6); capability probes remain the authoritative evidence, not the build number. |
| D4 | In-flight work | (a) Finish ADR-0001 slice (proxy/approvals) + mxc-derived Tasks 1–2. (b) Park everything now. | **(a) Land Task 1 (ingress warning) and complete or cleanly park ADR-0001 at its next checkpoint; drop Task 2 (`--lpac`) unless the interim track stays active.** Rationale: half-finished worktrees rot; the slice still serves the interim product that users run on stable Windows. |
| D5 | Interim feature freeze | Keep evolving the AppContainer tool (e.g., US-4 kernel audit, `--reuse` stores) vs freeze after in-flight work? | **Freeze new interim features after the in-flight slice**; route new capability work into the WBD track where it isn't throwaway (e.g., audit event schema design, quota research feeding D-12). |

---

## 6. Immediate next steps

1. **Land VM-01** (plan exists as of today): base image A + harness; move
   `tests/run-tests.ps1` into the VM; dev-host runs become smoke-only.
2. **Record the D1/D2 decisions as a short ADR** in `docs/adr/` once taken.
3. **Acquire build `29671.1000`** (D3) → build VM image B → run WBD D-01/D-02
   first evidence capture inside it. **Done 2026-10-12: ISO acquired
   (`29680_1000.iso`, a later flight accepted per D3) — image B build and
   the D-01/D-02 capture are next.**
4. **Finish or park in-flight work** (D4) so exactly one interim branch state is
   left clean.
5. When the WBD track starts: create `windows-agent-sandbox/` per the WBD's
   repository shape, pin `mxc/`, and begin with D-01 — *not* with product code
   (D-03/D-04 are stop-work gates for everything beyond contracts and test
   infrastructure).

## 7. What must NOT happen now

- Do **not** run MXC `wxc-host-prep` (the WBD flags it as a signal the host is
  on the wrong path for a BaseContainer-only project).
- Do **not** fill unknown MXC/PSEC interfaces with guessed APIs or build-number
  checks (WBD §17).
- Do **not** let the interim tool inherit WBD claims (or vice versa) — different
  backends, different builds, different evidence.
- Do **not** run further host-mutating test suites on the dev machine once VM-01
  lands.
