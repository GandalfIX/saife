# WBD D-02 Capability Matrix — Design

> **Date:** 2026-10-14
> **Status:** approved design (maintainer), pending spec review
> **WBD source:** `input/WINDOWS_CLI_SAIFE_WORK_BREAKDOWN.md`, D-02
> **Depends on:** D-01 (complete), the image-B evidence lane (complete)

## 1. Goal

Complete WBD ticket D-02: the **capability matrix** for empty, filesystem,
UI, deny-all-network, and proxy requests on the Experimental Future
Platforms build — the WBD names build `29671.1000` in its heading; the
evidence runs on `29680.1000` per impact-analysis decision **D3**
(2026-10-12: the later flight of the same channel was accepted, and the
capability probes — never the build number — are the authoritative
evidence). The deliverable includes raw request-scoped probe evidence and
a source-verified mapping from MXC's exposed capability booleans to the
required PSEC contract versions and support bits.

D-02 acceptance criteria (from the WBD, binding):

1. Empty and planned R1 requests resolve to `base-container`.
2. Each required policy is probed as a **complete request** — never
   inferred from the OS build number.
3. Any policy that resolves to AppContainer or returns ambiguous
   capability data is **marked blocked**.
4. Results distinguish symbol presence, PSEC environment-creation
   support, and request compatibility where MXC exposes those
   distinctions; where a required distinction is not observable,
   **enhanced diagnostics become an upstream blocker** rather than an
   inferred result.

## 2. Context (what exists already)

- Image B (`sbx-base-b.vhdx`, SHA256 `95DAEA35…02F5BE`) at MXC pin
  `5d7a475a9fd5626bafb55c2c857989d2e5621245`, wxc-exec
  `1.0.0+5d7a475a`.
- Canonical capture run `20261013-220007-020` (VM HARNESS: PASS):
  D-01 baseline (`pinMatches: true`, probe exit 0, tier `base-container`)
  and the upstream `run_processcontainer_probes_test.ps1
  -RequireTier base-container` — **10/10 PASS**, covering the empty,
  rw-paths and denied-paths shapes with `needsDaclAugmentation=False`
  everywhere.
- The empty-policy `--probe` JSON (evidence artifact
  `d01-wxc-exec-probe.log`) exposes the boolean surface the matrix maps:
  `baseContainerApiPresent`, `nativeCaptureAvailable`,
  `baseContainerSupportsDenyPaths` (true),
  `baseContainerSupportsEnumeratePaths` (false),
  `baseContainerSupportsIngressHostLoopbackAllow` (false),
  `baseContainerSupportsIdentitylessLoopbackProxy` (true),
  `isolationSessionAvailable` (false), `hyperlightAvailable` (false),
  plus the ten `uiCapabilities.canBlock*` bits (all true).
- Upstream binary contract satisfied by the capture script
  (sidecars + debug-lane redirect via context JSON).

Decisions already taken (this design session):

- **Scope:** exactly the five WBD shapes — empty, filesystem (rw/ro/denied),
  UI, deny-all-network, proxy. No directional-network refinements, no
  full-schema sweep.
- **Doc home:** `sandbox/docs/research/wbd-d02-capability-matrix.md` (new file;
  the other WBD-track documents — `mxc-source-analysis.md`,
  `impact-analysis-windows-cli-sandbox-wbd.md` — already live flat in
  `sandbox/docs/`).
- **Mechanism:** upstream `New-Config` generator (Approach 1), extending
  the existing capture script.

## 3. Design

### 3.1 Capture extension — `tests/vm/wbd-d01-d02-probes.ps1`

A new "D-02 matrix" section runs **after** the existing upstream-suite
invocation (which is unchanged; its 10/10 result remains evidence for the
empty/fs-rw/fs-denied rows).

**Config generation.** The script dot-sources the pinned tree's
`tests\scripts\lib\WinProcessContainer.Common.ps1` and uses its `New-Config`
helper — the exact generator the upstream suite uses, defaulting to
schema version `1.0.0`, matching the pinned contracts. This is
schema-exact by construction: a config-authoring bug on our side cannot
masquerade as a policy verdict. `$ScratchRoot` is set to a scratch
directory under the results directory so `New-Config` writes the generated
requests into the artifact tree; the generated config files themselves are
fetched evidence (`d02-configs\`), so every matrix cell traces to the
exact request JSON that produced it.

**Shape-coverage gate (first implementation step).** The upstream suite
only exercises the empty/rw/denied shapes through `New-Config`; UI,
deny-all-network and proxy authoring via the generator is
**unverified until read**. The plan's first step therefore reads
`Common.ps1` in the pinned tree and confirms `New-Config`'s parameter
surface can express all five shapes (including the `processContainer.ui`
and `network` blocks). If a shape cannot be expressed, the fallback is
recorded in the implementation plan as an explicit per-shape decision:
either hand-author that one shape against the pinned `docs/schema.md`
(with the config still recorded verbatim as evidence, so the matrix cell
remains traceable), or record it as a blocked shape in the artifacts.
The existing layout-drift blocker path covers `Common.ps1`/`New-Config`
being *absent*; this gate covers *present but insufficient*.

Layout drift handling (established pattern): if `Common.ps1` (or
`New-Config` in it) is missing at a future pin, the section records the
blocker verbatim into its artifacts and the run continues — absence of an
upstream entry point is evidence, not a capture error.

**The seven probes** (each a complete request via
`& $wxcExec --probe --config <path>` — the WBD's listed entry point;
read-only, no workload launch; `New-Config` never executes the
`process.commandLine`):

| # | Shape | Request authored via `New-Config` |
|---|-------|-----------------------------------|
| 1 | `empty` | minimal request: version + containment + process only (no fs/ui/network keys) |
| 2 | `fs-rw` | `filesystem.readwritePaths` = scratch `rw` dir |
| 3 | `fs-ro` | `filesystem.readonlyPaths` = scratch `ro` dir (the upstream suite never probes ro — new evidence) |
| 4 | `fs-denied` | `filesystem.deniedPaths` = scratch `denied` dir |
| 5 | `ui` | `ui.disable` + the `processContainer.ui` block parameters, authored to mirror the upstream UI area's own request shapes — exact enum values are read from the pinned tree at implementation time, never guessed |
| 6 | `deny-all-network` | `network.egress.default=deny` + `network.ingress.default=deny` |
| 7 | `proxy` | `runtimeConfig.networkProxy` (a loopback URL — nothing dials it in probe mode) + `processContainer.network.allowedProxyPeer` (value verified from the pinned network area at implementation time) |

**Artifacts per probe:** the verbatim `--probe --config` stdout JSON and
exit code land in `d02-matrix\<shape>.probe.json` (empty output still
produces the file — the Set-Content `-Value` pattern, per the fixed
empty-output bug family). A summary `d02-matrix.json` records, per shape:
config path, exit code, resolved `tier`, `needsDaclAugmentation`,
`error`/`warnings` when present, and the SHA256 of the config that
produced it.

**Baseline additions:** the D-01 baseline JSON gains a `d02Matrix` block
(shapes, artifact names, exit codes) so a single fetched file describes
the whole D-02 capture surface.

### 3.2 Matrix deliverable — `docs/research/wbd-d02-capability-matrix.md`

Structure:

1. **Provenance header** — pin, template SHA256, canonical run ID,
   evidence-manifest reference. Every cell in the document cites a fetched
   artifact; the capture manifest hashes make the citations
   tamper-evident.
2. **Verdict table** — one row per shape: resolved tier,
   `needsDaclAugmentation`, exit code, blocked/unblocked marking. A row is
   **blocked** when the shape resolves to `appcontainer-dacl`, errors, or
   returns ambiguous/absent data (acceptance criterion 3). Blocked is a
   recorded state with the artifact reference, never an inference.
3. **Capability-boolean mapping** — each `probes.*` boolean from the D-01
   empty-policy probe mapped to the PSEC contract version and support bit
   that backs it, **source-verified at the pinned commit**
   (`5d7a475a9fd5626bafb55c2c857989d2e5621245`) via targeted re-reads of
   `fallback_detector.rs`, `secenv.rs`, and `base_container_helpers.rs`.
   Line references land in the matrix document, and a short update note
   (refreshed refs, drift caveat resolved) is added to
   `docs/research/mxc-source-analysis.md`.
   Already-visible gaps become recorded upstream blockers, not inferred
   results: `baseContainerSupportsEnumeratePaths=false`,
   `baseContainerSupportsIngressHostLoopbackAllow=false`.
4. **Acceptance-criteria checklist** — each of the four D-02 criteria
   mapped to the artifact(s) that prove it, or to the recorded blocker.

The document claims **nothing** that a fetched artifact does not show;
where MXC does not expose a distinction the acceptance criteria require
(symbol presence vs. PSEC environment-creation support vs. request
compatibility), the document records the missing distinction as an
upstream (enhanced-diagnostics) blocker per criterion 4.

### 3.3 Verification

1. **Local mock** (before any VM run): a fake `Common.ps1` exposing a
   minimal `New-Config` stub plus a fake `wxc-exec.exe` (real small exe)
   verifies: dot-source path, `$ScratchRoot` handling, config files
   recorded into the artifact set, per-shape probe artifacts, summary
   assembly, and the layout-drift blocker path (no `Common.ps1` → run
   still completes).
2. **Parser check** on the modified capture script (zero warnings).
3. **One real capture-lane run** (maintainer's elevated pwsh, the same
   `-TestCmd` invocation as the canonical runs).
4. **Matrix written from fetched artifacts only** — provenance cross-
   checks against the capture manifest.

## 4. Error handling

- Missing upstream `Common.ps1` / `New-Config` → recorded blocker, run
  completes (layout-drift pattern).
- `--probe --config` non-zero exit → recorded verbatim per shape; the
  summary marks the shape's verdict from the artifact, and the analysis
  marks it blocked. Never retried, never hidden.
- Dot-source failure (parse error in upstream lib) → caught, recorded as
  blocker, run continues.
- The capture script never launches a workload, never runs
  `wxc-host-prep`, and mutates nothing outside the disposable VM.

## 5. Out of scope

- Directional-network refinements beyond the two deny defaults (egress
  allow-rules, hostLoopback shapes) — later WBD network tickets.
- Full 1.0.0-schema sweep (lifecycle, telemetry, captureDenials,
  learningMode, capability lists).
- D-03 (integration-surface ADR) and D-04 (no-fallback enforcement) —
  they *consume* this matrix.
- `prepare-mxc.ps1` extension (native debug lane) — remains a Q-01
  dedicated-runner follow-up.
- Product code of any kind (D-03/D-04 are stop-work gates; impact-analysis
  §5 decisions still pending).

## 6. Open items (resolved at implementation time, from the pinned tree)

- Exact `processContainer.ui` enum values for the UI shape (read from the
  upstream UI area script / `docs/schema.md` at the pin).
- Exact `allowedProxyPeer` value shape for the proxy request (read from
  the upstream network area at the pin).
