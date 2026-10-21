# ADR-0003: BaseContainer-only enforcement (WBD D-04 — stop-work gate)

> **Status:** Proposed (2026-10-17) — evidence complete; consumes ADR-0002
> **Amended 2026-10-21 by ADR-0004 (Option A):** the bounded posture in §3 is now the ADOPTED product
> posture for `processcontainer` (unelevated on GA Windows), with ADR-0004's two guardrails as hard
> requirements. The upstream asks (created-not-running/pre-resume, atomic require-tier) remain open; this
> ADR's residual-exposure wording applies verbatim.
> **Scope:** WBD ticket D-04 (`input/WINDOWS_CLI_SANDBOX_WORK_BREAKDOWN.md` line 494, criteria lines 500-508). Depends on D-03 (ADR-0002, selected surface: **mxc-sdk in-process**). Binds the product's launch gate and every D-08/control-implementation ticket.
> **Origin:** `docs/superpowers/specs/2026-10-14-wbd-d03-d04-stop-work-gates-design.md` §3.3; implementation plan `docs/superpowers/plans/2026-10-14-wbd-d03-d04-stop-work-gates.md`.
> **Evidence rule:** same as ADR-0002 — fetched artifacts (SHA256-verified per run manifest) or `file:line` at pin `5d7a475a…`; blockers recorded, never waved away.

## 1. Provenance

Same canonical runs as ADR-0002 (image `sbx-base-b`, guest build 29680, pin
`5d7a475a…`, `pinMatches: true` in both baselines):

- Run `20261017-121539-354` — Section C evidence (c1 schema-rejection variant; c2
  immunity; force-tier/tier-query SDK scenarios).
- Run `20261017-130259-402` — Section C evidence (c1 adjudication-refusal variant —
  the authoritative form; c2 re-proven identically).
- D-02 canonical `20261014-005531-844` — the adjudication-blocked form inventory
  (`docs/wbd-d02-capability-matrix.md` §5.2) the gate is designed against.

Relevant artifacts: `d03-c1-launch.json`, `d03-c1-probe.json`,
`d03-c2-env-immunity.json`, `d03-sdk-probe.json`, `d03-sdk-force-tier.json`,
`d03-sdk-tier-query.json`, `d03-config-c1-enumerate.json` (all run 2 unless stated).

## 2. No-fallback mechanism decision

**Question:** does MXC natively support a force/require-tier input the product can
use to guarantee `base-container`-only execution?

**Answer at this pin: NO runtime mechanism exists.** The evidence:

- **`force-tier-testing` is a compile-time cargo feature, not a runtime input:**
  the `MXC_FORCE_TIER` read is behind
  `#[cfg(any(test, feature = "force-tier-testing"))]`
  (`fallback_detector.rs:313`; comment `:310-312`: "Normal debug and release
  builds do not compile this branch"). It is a feature dependency only
  (`src/tools/wxc/Cargo.toml:37-38` = `force-tier-testing =
  ["mxc-sdk/force-tier-testing"]`; wxc-exec has **no require-tier CLI flag** —
  source-verified, `wxc/src/main.rs:27-203`); there is no tier/backend field in
  the schema-1.0.0 request contract (`stable.rs:32-53` — process carries only
  `commandLine` + `timeout`).
- **Runtime proof the seam works but is test-only:** with the feature compiled in,
  forcing works (`d03-sdk-force-tier.json`, run 2: `honored: true`, forced
  `appcontainer-dacl`, `needsDaclAugmentation: true`); the artifact also records
  upstream's own note that an invalid value is *silently ignored* — a test seam,
  not a security gate.
- **Runtime proof the release executor is immune to environment coercion:**
  `d03-c2-env-immunity.json` (both runs) — `MXC_FORCE_TIER=appcontainer-dacl` set
  in the executor's environment left the default-feature release executor at
  `tier: base-container`, `needsDaclAugmentation: false`. The product consumes
  release builds, so the feature seam is unavailable to it by construction.

- **No policy shape silently demotes on this host:** the tier ladder is
  BaseContainer → AppContainer+BFS (only with the `tier2_bfs` feature) →
  AppContainer+DACL (requires `allow_dacl_mutation` + `WRITE_DAC` on every
  target, `fallback_detector.rs:254-275`); on this PSEC-1.0-only host the
  adjudication-blocked forms **hard-error instead** — D-02 §5.2
  (`EnumeratePathsUnsupported`, bare `hostLoopback` `IngressUnsupported`) and
  run 2's `d03-c1-launch.json` agree. Fallback risk on this host is therefore
  *refusal* risk, not silent demotion — which the adapter's preflight converts
  into a clean refuse-before-exec.

**Therefore the product adapter owns the gate**, as a two-layer mechanism on the
ADR-0002-selected mxc-sdk surface:

1. **Request-scoped preflight (refuse-before-exec):** before any launch, call
   `v1::probe` with the **exact rendered request** and refuse unless the probe
   returns `tier == "base-container"` AND `needsDaclAugmentation == false` AND no
   `error` AND no `warnings` AND every capability bit the request needs is
   advertised. Runtime-proven components: the probe adjudicates complete requests,
   not shapes (D-02 matrix §6 criterion 2; `d03-sdk-probe.json`), and incompatible
   requests are refused with the adjudication error verbatim
   (`EnumeratePathsUnsupported`, `fallback_detector.rs:238-241`, raised `:301` —
   `d03-c1-probe.json`).
2. **Post-launch effective-tier check (best available at this pin):** the SDK
   returns the selected tier **at spawn time** (`DispatchedProcess { process,
   tier, warnings }`, `dispatcher.rs:631-638`), and a pre-spawn
   `EnforcementDegraded` audit event fires whenever enforcement degrades
   (`dispatcher.rs:113-157`, streaming call site `:698`, run-to-completion
   `run.rs:238`). The adapter records the spawn-time tier + warnings on every
   launch and **kills the workload immediately** if tier ≠ `base-container` or
   warnings are non-empty (kill + tree teardown proven: run 2 `d03-wxc-a4-cancel.json`,
   job kill-on-close `job_object.rs:241-249`).

**What is NOT claimed:** "attestation before resume." ADR-0002 §3 established that
no caller-reachable pre-resume point exists at this pin — the workload is already
running when the spawn-time tier is observable. Layer 2 is therefore
**detection-and-kill**, not prevention; the prevention gap is closed only by the
upstream requirements in §3.

## 3. Race analysis (criterion 4 — never waved away)

- **The race:** host capability state can change between the preflight probe and
  the actual launch (PSEC contract version advertised, DACL state, feature
  availability). MXC offers **no atomic require-tier operation** at this pin: no
  request-schema tier field (§2), no probe-and-launch transaction, no
  created-not-running handle (ADR-0002 §3 item 1).
- **Named upstream requirements (blocking the prevention gap):**
  1. a **request-schema require-tier field** honored atomically by
     `choose_backend_tier` (fail the request rather than fall back), or
  2. a **caller-reachable created-not-running / pre-resume window** so the
     effective tier can be attested *before the first instruction of workload
     code executes* (the ADR-0002 §3 item-1 blocker, restated from the D-04
     side: the two tickets converge on the same upstream ask).
- **Mitigation at this pin (bounded exposure):** preflight (layer 1) closes the
  static-incompatibility races by refusing incompatible requests before launch;
  the remaining dynamic window (probe→launch drift) is bounded by layer 2's
  spawn-time tier check + immediate kill: a degraded launch is detected at spawn
  return and the workload tree is terminated (`job_object.rs:241`,
  runtime-proven teardown). Residual exposure — workload code may execute for the
  interval between resume and the adapter's spawn-return check — is **accepted
  only as an interim posture** and disappears when either upstream requirement
  lands. It is not silently accepted: it is the recorded consequence of the
  upstream blocker, per criterion 4.

## 4. Staging point (criterion 5 — consumes ADR-0002)

**No product-attestable staging point exists at this pin.** The internal launch
sequence does install controls before workload code runs — PSEC environment
attached pre-creation (`base_container_runner.rs:877-878`), job object assigned
**while the child is suspended** (`:1036-1092`), fail-closed kill if job setup
fails (`:1058-1063`), resume only after (`:1098`) — but every step is internal;
no surface (SDK `v1`, wxc-exec, FFI) exposes the suspended child to a caller
(ADR-0002 §3 item 1; `SandboxBackend` trait has no staging method,
`sandbox_process.rs:565/:590-595`).

**Consequence (binding, same as ADR-0002 §5):** D-08 and every
control-installation/attestation implementation ticket are **blocked on the
upstream mechanism** — no product launch path may be implemented until it exists.
When it lands, the staging point is: *suspended child, PSEC attached, job
assigned — attestation goes exactly there, before `ResumeThread`.*

## 5. Acceptance-criteria checklist (WBD lines 500-508)

| # | Criterion | Result | Evidence |
|---|---|---|---|
| 1 | Selected mechanism backed by source or runtime evidence | **Met** | §2: no runtime require-tier input (source: `wxc/src/main.rs:27-203`, `stable.rs:32-53`, `Cargo.toml:37-38`); adapter mechanism built entirely from runtime-proven primitives (probe adjudication `d03-sdk-probe.json`; spawn-time tier `dispatcher.rs:631-638`; kill/teardown run 2 `d03-wxc-a4-cancel.json`) |
| 2 | Deliberately PSEC-incompatible request fails before workload code executes | **Met** | §2 layer 1 + runtime: `d03-c1-launch.json` (run 2) — `enumeratePaths` request refused, `markerFilePresent: false` (the workload's own canary never ran), outcome `refused-before-exec`, exit 1; refusal text = the `EnumeratePathsUnsupported` adjudication (`fallback_detector.rs:238-241`) |
| 3 | AppContainer+DACL availability does not make the product request succeed | **Met** | Prescribed trio: (a) the AppContainer machinery demonstrably exists in the same binary — `d03-sdk-tier-query.json`: `availableBackends` lists `processcontainer` at `base-container` while the forced-probe path (`d03-sdk-force-tier.json`: `appcontainer-dacl`, `needsDaclAugmentation: true`) shows the weaker tier is reachable; (b) the incompatible request still fails closed on both surfaces — `d03-c1-probe.json`/`d03-c1-launch.json` (refusal verbatim, canary absent); (c) the product design statement: preflight refuses any tier ≠ `base-container` (§2 layer 1). Supporting: `d03-c2-env-immunity.json` — the release executor cannot even be coerced (`MXC_FORCE_TIER` immunity, both runs) |
| 4 | Race analysis covers capability change between probe and launch; no atomic require-tier → upstream requirement + mitigation, never waved away | **Met** | §3: TOCTOU stated, two named upstream requirements, bounded interim mitigation (preflight + spawn-time tier check + immediate kill) with residual exposure explicitly recorded rather than assumed away |
| 5 | Launch sequence identifies and proves a staging point where mandatory controls are installed and attested before workload code executes | **Recorded blocker — unattestable at this pin** | §4: the internal suspended-create sequence is the point (PSEC attach → job assign → resume) but is not caller-reachable (ADR-0002 §3 item 1); D-08/implementation tickets blocked upstream, stop-work consequence restated |

## 6. Raw-evidence index

- Run `20261017-130259-402`: `d03-c1-launch.json` (adjudication refusal, canary
  absent), `d03-c1-probe.json` (`baseContainerSupportsEnumeratePaths: false`,
  same refusal), `d03-c2-env-immunity.json` (force-tier immunity),
  `d03-sdk-probe.json` (request-scoped adjudication incl. the enumerate-request
  error), `d03-sdk-force-tier.json` (feature seam honored, `appcontainer-dacl`,
  `needsDaclAugmentation: true`), `d03-sdk-tier-query.json` (no post-launch tier
  accessor — the query-back gap this ADR's layer 2 must live with),
  `d03-wxc-a4-cancel.json` (kill/teardown primitive).
- Run `20261017-121539-354`: Section C equivalents (c1 as the schema-rejection
  variant; c2 identical).
- D-02 canonical `20261014-005531-844` + matrix §5.2: the adjudication-blocked
  form inventory (enumeratePaths, bare `hostLoopback: allow`) the preflight gate
  is designed to refuse.
- Decision dependency: `docs/adr/0002-mxc-integration-surface.md` (selected
  surface, §3 investigation, §5 stop-work).
