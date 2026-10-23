# WBD D-03 + D-04 — Stop-Work Gates: Integration Surface & BaseContainer-Only Enforcement — Design

> **Date:** 2026-10-14
> **Status:** approved design (maintainer), pending spec review
> **WBD source:** `input/WINDOWS_CLI_SAIFE_WORK_BREAKDOWN.md`, D-03 (line 474), D-04 (line 494)
> **Depends on:** D-01 (complete), D-02 (complete — `docs/research/wbd-d02-capability-matrix.md`)
> **Thread structure (decided in-session):** one shared spec, **two PRs** — D-03 first, D-04 second (one
> ticket per agent per PR, per impact-analysis §3.3; D-04 depends on D-03)

## 1. Goal

Complete WBD tickets D-03 and D-04 — the two **stop-work gates** that consume the
D-02 capability matrix. Until both decision records land, no product
implementation beyond contracts and test infrastructure may start
(WBD line 489-492; impact-analysis §5 note 5).

**D-03 deliverable (binding):** architecture decision record comparing
subprocess execution through `wxc-exec.exe`, available MXC library surfaces,
and available FFI surfaces. Acceptance criteria (WBD lines 480-492):

1. Comparison covers API support status, redistribution, schema/version
   coupling, stdout/stderr streaming, stdin, cancellation, process-tree
   teardown, request-scoped probing, diagnostics, signing, and update strategy.
2. A minimal spike proves probe, launch, output, exit code, timeout, and
   cancellation using only documented or source-verified interfaces.
3. Investigation records whether the selected surface supports
   created-but-not-running workloads, pre-resume attestation,
   generation-correlated ownership, Job Object resource controls, and
   query-back of effective controls.
4. The decision names the MXC version/commit boundary and upgrade policy.
5. Any unavailable capability becomes a follow-up discovery blocker rather
   than an invented interface.
6. If the selected supported surface cannot satisfy the created-not-running
   and pre-resume requirements, **no product launch path may be implemented**
   until an upstream mechanism is available.

**D-04 deliverable (binding):** decision record for preventing fallback,
including whether MXC supports a force/require-tier input or whether the
adapter must combine request-scoped preflight with post-launch
effective-tier attestation. Acceptance criteria (WBD lines 500-508):

1. The selected mechanism is backed by source or runtime evidence.
2. A deliberately PSEC-incompatible request fails before workload code executes.
3. A test demonstrates that AppContainer+DACL availability does not make the
   product request succeed.
4. A race analysis covers capability change between probe and launch; if MXC
   offers no atomic require-tier operation, this is raised as an upstream
   requirement or mitigated by effective-tier attestation before resume —
   never waved away.
5. The launch sequence identifies and proves a staging point at which
   mandatory controls can be installed and attested before workload code
   executes (D-08 and implementation tickets prove each specific control
   there).

## 2. Context (what exists already)

- **D-02 complete** (`docs/research/wbd-d02-capability-matrix.md`, canonical run
  `20261014-005531-844`): all eight shapes resolve `base-container`,
  `needsDaclAugmentation: false`; the host is PSEC **1.0-only**
  (`FileSystemDeny` yes; `FileSystemEnumerate`/`NetworkIngress` no);
  `enumeratePaths` and bare `hostLoopback: allow` are adjudication-blocked
  forms (matrix §5.2) — the built-in incompatible-request fixtures D-04 needs.
- **Image B** (`sbx-base-b.vhdx`, SHA256 `95DAEA35…02F5BE`) at MXC pin
  `5d7a475a9fd5626bafb55c2c857989d2e5621245`, wxc-exec
  `1.0.0+5d7a475a`, guest build 29680, warm cargo cache, in-tree sidecar
  build pattern proven by the D-02 capture script.
- **Upstream surfaces at the pin** (verified 2026-10-14):
  - `wxc-exec.exe` — documented CLI (`--probe --config`, `--debug`,
    `--audit`; README: non-SDK consumption "for testing or when the SDK
    cannot be embedded in your app").
  - **`src/mxc-sdk`** — the Rust SDK crate, **published on crates.io as
    `mxc-sdk` 1.0.0** (2026-10-06, `microsoft-oss-releases`, MIT, edition
    2021, ~155k lines, "Importable library for starting MXC sandboxes
    in-process, with streaming stdio"). Feature list includes
    **`force-tier-testing`** (directly relevant to D-04's require-tier
    question), `tier2_bfs`, `isolation_session`, `hyperlight`, `wslc`.
    Documented API reference: `docs/api-reference/rust`.
  - **`src/ffi`** — a real in-tree FFI surface; shape source-verified at
    implementation time.
  - Node/.NET SDKs (`sdk/node`, `sdk/dotnet`) bundle native runtime assets —
    comparison-relevant as redistribution models, not candidate surfaces for
    a Rust product.
- All D-track evidence rules (impact-analysis A1/A2, `docs/design/testing-principles.md`):
  disposable-VM runs only, flat artifacts, blocker-as-evidence, fetched
  artifacts are the only citable evidence, source refs verified at the pin.

## 3. Design

### 3.1 Runtime spike lane — `tests/vm/wbd-d03-d04-spike.ps1` (new script)

A **new** capture script (not an extension of `wbd-d01-d02-probes.ps1` —
this lane *launches workloads*, a different posture than the read-only
probes). Established harness patterns reused verbatim: flat artifacts in
`C:\sbx-results` (flat manifest), per-step try/catch with
blocker-recorded-verbatim continuation, `Set-Content -Value` convention
(empty output still writes the file), pin/hash baseline re-verification
first, mock-first TDD locally before the real run.

**Section A — wxc-exec.exe subprocess lifecycle.** Configs authored via the
pinned tree's `New-Config` (dot-source pattern; schema-exact by
construction; config files are fetched evidence). The `probe` element of
D-03's spike list rides on the D-02 canonical-run probe artifacts for this
surface (`d02-matrix-<shape>.probe.json`, run `20261014-005531-844`) — the
ADR-0002 checklist cites them directly rather than re-probing. **Every
launch scenario in every section (A, B, C) runs under the established hang
guard**
(`Start-Job` + `Wait-Job -Timeout`, `wbd-d01-d02-probes.ps1:378-405`
pattern): A3/A4 deliberately create long-running workloads against
*unproven* timeout/cancellation enforcement, and one hung synchronous wait
must not lose the run — a guard timeout is recorded as that scenario's
blocker row. Scenarios, each producing one artifact + one summary row:

| # | Scenario | Expected evidence |
|---|---|---|
| A1 | `launch-exit` | `cmd.exe /d /s /c exit 0` and `exit 7` — exit codes 0 and 7; **nonzero is a workload outcome, not a saife setup error** (B-04 criterion) |
| A2 | `stdio` | distinct markers on stdout and stderr, both captured separately; a small stdin-forwarding test (executors "reserve standard input, output, and error for the workload" — README) |
| A3 | `timeout` | request-level `timeoutMs` (schema location verified at implementation) vs a sleeping workload — timeout enforcement, exit path, teardown |
| A4 | `cancellation` | long-running workload, terminate the executor process — process-tree teardown evidence: does the contained child die with the executor? |

**Section B — mxc-sdk in-process lifecycle.** A minimal **committed** spike
crate `tests/vm/spikes/wbd-d03-sdk-spike/` (Rust, part of the repo tree the
harness copies into the VM) with `mxc-sdk = { path = "<pinned-tree>/src/mxc-sdk" }`
— offline, warm cargo cache, **exact pin** (not the crates.io tarball;
the ADR records the 1.0.0/pin relationship). The spike binary emits one JSON
line per scenario: probe/preflight equivalent, launch, streamed stdout/stderr,
exit code, timeout, cancel, effective-tier query-back — **each only if the
SDK exposes it**.

**Shape-coverage gate (first implementation step, before any spike code):**
read the pinned SDK's public API (`docs/api-reference/rust` +
`src/mxc-sdk` sources at the pin) and confirm which of the six spike
operations are exposed. Anything not exposed is a recorded blocker in the
artifacts and ADR — never an invented interface (ticket criterion 5).

Build in-VM (`cargo build --release`, warm cache; the D-02 sidecar pattern);
the built binary, build log, and emitted scenario JSON are all artifacts.
Build failure is a recorded blocker, not a capture error.

**Section C — D-04 enforcement evidence** (same run):

- **C1 fail-before-exec:** launch — not just probe — the `enumeratePaths`
  request shape that D-02 proved adjudication-blocked
  (`EnumeratePathsUnsupported`, matrix §5.2). Two recorded outcomes are both
  acceptable evidence; the plan branches on whichever the artifact shows:
  (a) **refused** — nonzero exit, error object recorded verbatim, and a
  marker file written by the workload command proves the workload **never
  executed** (direct criterion-2 proof); or (b) **demoted-and-run** — the
  backend serves the shape on a weaker tier, in which case criterion 2's
  proof path shifts to ADR-0003's adapter mechanism (request-scoped
  preflight on the probe error + tier gate refusing any tier ≠
  `base-container`), and the demotion artifact becomes C2's fixture.
- **C2 AppContainer irrelevance:** the artifact that discharges ticket
  criterion 3 is: plain-launch evidence that the raw backend *does* serve a
  demoted shape on the `appcontainer-dacl` tier (C1 outcome (b), or a
  fixture request resolved at implementation from `fallback_detector.rs` +
  runtime probe), **combined with** the probe/tier evidence that the
  product's preflight design (ADR-0003 §2) refuses — demonstrating that the
  weaker tier's availability does not make the product request succeed.
  Product code is out of scope; the refusal is proven at the evidence level
  (probe error object + tier ≠ base-container), not by implementing the gate.
- **C3 force-tier surface:** source-verify what exists at the pin —
  the `force-tier-testing` crate feature, any request-schema tier/backend
  field, any SDK require-tier API — and runtime-exercise whatever exists.
  This settles "does MXC support a force/require-tier input" with evidence.
- **C4 staging point:** source-verify whether the base-container launch
  sequence exposes created-not-running / pre-resume (e.g. suspended
  creation before PSEC environment attach, resume-after-attest). Spike it
  if exposed through the selected surface; otherwise record the upstream
  blocker — **binding consequence per ticket criterion 6: no product launch
  path may be implemented until an upstream mechanism is available.**

**Summary:** `d03d04-spike.json` (per-scenario rows, pre-initialized schema,
`ran`/`blocker`/`errorCount` like the D-02 summary) + `d03d04Spike` block in
the D-01 baseline JSON + flat manifest entries.

### 3.2 ADR-0002 — D-03 integration-surface decision

`docs/adr/0002-mxc-integration-surface.md`:

1. **Provenance header** — pin, template SHA256, canonical run ID, manifest
   reference; every claim cites a fetched artifact or a source ref at the pin.
2. **Three-way comparison** — `wxc-exec.exe` subprocess vs `mxc-sdk` 1.0.0
   library vs `src/ffi` FFI — across the eleven mandated axes: API support
   status, redistribution, schema/version coupling, stdout/stderr streaming,
   stdin, cancellation, process-tree teardown, request-scoped probing,
   diagnostics, signing, update strategy. "Unexposed" cells are recorded
   blockers, never inferences.
3. **Investigation record** — created-not-running, pre-resume attestation,
   generation-correlated ownership, Job Object resource controls,
   effective-control query-back: each with artifact/source citation or
   blocker status.
4. **Boundary + upgrade policy** — pin `5d7a475a…`, crate 1.0.0 (published
   2026-10-06), re-verify on every re-pin (extends the matrix §5.1
   re-pin caveat pattern to the SDK/FFI surfaces).
5. **Acceptance-criteria checklist** — each criterion mapped to its proof
   artifact or recorded blocker.

### 3.3 ADR-0003 — D-04 BaseContainer-only enforcement decision

`docs/adr/0003-basecontainer-only-enforcement.md`:

1. **Provenance header** (same run; consumes ADR-0002's selected surface).
2. **No-fallback mechanism decision** — what MXC natively offers at the pin
   (C3 evidence) vs adapter-owned combination: request-scoped preflight
   (probe gate on the exact rendered request, refusing any tier ≠
   `base-container` and any absent required capability) **plus**
   post-launch effective-tier attestation **before resume**.
3. **Race analysis** — probe→launch TOCTOU on capability change; if no
   atomic require-tier operation exists at the pin, raised as a named
   upstream requirement **and** mitigated by attestation-before-resume —
   never waved away (ticket criterion 4).
4. **Staging point** — the launch-sequence point where mandatory controls
   are installed and attested before workload code executes, consuming
   ADR-0002's created-not-running finding; D-08/implementation tickets
   prove each specific control there (ticket criterion 5).
5. **Acceptance-criteria checklist** per ticket.

### 3.4 PR split and sequencing

- **PR1 (D-03):** spike script + spike crate + canonical capture run +
  ADR-0002 + companion updates (`mxc-source-analysis.md` pin-block partial
  refresh for the SDK/FFI/dispatcher areas read; runbook Image-B record;
  plan annotations).
- **PR2 (D-04):** ADR-0003 + companion updates, cross-referencing the same
  canonical run. Merges after PR1; consumes ADR-0002's outcome.
- One implementation plan document covers both, with the PR boundary stated
  explicitly.

## 4. Error handling

- Missing upstream pieces (SDK API absent, `New-Config` drift, ffi surface
  gone) → recorded blocker verbatim, run continues (layout-drift pattern).
- Spike-crate build failure in-VM → recorded as blocker evidence; the run
  still completes with the wxc-exec sections (Section A stands alone).
- Nonzero workload exits, timeout fires, cancellation paths → recorded
  verbatim per scenario; **failure is evidence**, never retried or hidden.
- The capture script launches workloads only inside the disposable VM;
  it never runs on the host, never runs `wxc-host-prep`, and mutates
  nothing outside the VM (rollback = VM deletion, per A1).
- If created-not-running / pre-resume is unavailable on every surface: the
  ADRs record it as the upstream blocker the WBD anticipates, and the
  stop-work consequence is restated in both ADRs (no product launch path).

## 5. Verification

1. **Local mock-first TDD** of the capture script: fake pinned tree +
   fake wxc-exec.exe (real small exe) + fake SDK stub — happy path,
   missing-pinned-tree blocker, spike-build-failure blocker.
2. **Parser check** on the capture script (zero warnings).
3. **One real capture-lane run** (maintainer's elevated pwsh, the same
   `-TestCmd` invocation as the canonical runs).
4. **ADRs written from fetched artifacts only** — provenance cross-checked
   against the capture manifest; source claims re-fetched at the pin.

## 6. Out of scope

- Product code of any kind (both tickets are stop-work gates).
- D-05/D-06 and later discovery tickets.
- Q-01 `prepare-mxc.ps1` debug-lane extension.
- crates.io tarball spike (the pin path-dependency is the evidence lane;
  the 1.0.0↔pin relationship is recorded in the ADR, not re-spiked).
- Any host-run test.

## 7. Open items (resolved at implementation time, from the pinned tree)

- Exact SDK public API surface: which of probe/preflight, launch, stdio
  streaming, timeout, cancel, effective-tier query-back are exposed, and
  the `force-tier-testing` feature's actual mechanism.
- Exact `src/ffi` surface shape (language target, stability, consumers).
- Request-schema location of `timeoutMs` and any tier/backend field.
- Cancellation semantics of both surfaces (executor termination vs SDK
  cancel; process-tree teardown guarantee).
- Whether the base-container runner creates the workload suspended (the
  pre-resume staging question) and what the selected surface exposes of it.
- The C2 fixture request that falls back to `appcontainer-dacl` on plain
  launch (resolved from `fallback_detector.rs` + runtime probe).
