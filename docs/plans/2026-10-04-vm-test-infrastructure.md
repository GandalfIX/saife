# VM Test Infrastructure Plan (VM-01)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans or
> superpowers:subagent-driven-development to implement this plan task-by-task.
> Steps use checkbox (`- [ ]`) syntax for tracking.
>
> **Status:** Approved direction 2026-10-04 (user directive: "testing should
> happen in a VM; add a step that can spin up a VM and use it for testing").
> Context and impact:
> `docs/research/impact-analysis-windows-cli-sandbox-wbd.md` (amendment A1).

**Goal:** One command spins up a disposable Windows VM, runs the repo's
host-dependent test suites inside it, copies the results back, and destroys the
VM — leaving **zero residue on the developer host**. This becomes the default
way to run Tier 2/3 tests for the current AppContainer product and, later, the
dedicated runner lane for the MXC/BaseContainer track (WBD Q-01) and the
clean-machine packaging lane (WBD G3 / Q-04).

**Why (in priority order):**

1. **Host hygiene.** The current suite (`tests/run-tests.ps1`, S-1…S-74) mutates
   host ACLs, AppContainer profiles, and per-session trees on the dev machine.
   The `AGENTS.md` rollback-script rule exists because of exactly this class of
   risk (see also `docs/notes/bugs/2026-08-04-setentriesinaclw-hang-toolchain.md`).
   A disposable VM makes rollback structural: delete the VM.
2. **The WBD track requires it.** The work breakdown targets Windows
   Experimental Future Platforms build `29671.1000`; our host is build `26200`.
   No WBD discovery evidence can be produced on this host — it needs a VM on
   that build (image B, Task 6, blocked on image acquisition).
3. **Hermetic, parallel, repeatable runs.** Differencing-disk clones of a
   prepared base image give every run a pristine OS state and allow concurrent
   runs without cross-contamination (the same property we enforce between
   sandbox sessions, applied to our own tests).

**Tech stack:** Hyper-V + PowerShell Direct (`New-VM`, `Invoke-Command -VMName`,
`Copy-VMFile`), PowerShell 7. Host: Windows 10 Pro, build 26200, x64, hypervisor
present. No third-party dependencies.

**Non-goals:** CI-hosted runners (GitHub Actions) — this plan covers the local
dev/research loop; CI wiring is a follow-up. Cloud VMs. Nested virtualization
gymnastics. Building Windows images from ISO fully automatically on day one
(first base image is built once, manually, from an install ISO; automation is a
later refinement).

---

## Decisions

| # | Decision | Rationale |
|---|---|---|
| V1 | **Hyper-V**, not Windows Sandbox / VirtualBox / WSL2 | Windows Sandbox is single-instance, desktop-oriented, and explicitly rejected by the WBD for our purposes; VirtualBox adds a third-party dependency; WSL2 is a Linux guest. Hyper-V is built into the host edition, supports PowerShell Direct (no network dependency for control), checkpoints, and differencing disks. The WBD itself standardizes on Hyper-V for its reference oracle (D-13). |
| V2 | **Template base image + differencing VHDX per run** | The base VHDX is never booted directly. Each run creates a differencing disk, so runs are hermetic, parallelizable, and the template stays pristine. VM deletion is the rollback — nothing to "restore". |
| V3 | **Two named images**: `sbx-base-a` (stable Windows, for the current AppContainer suite) and `sbx-base-b` (build `29671.1000` + pinned MXC, for WBD R0 discovery) | Image A is unblocked and serves the current product. Image B is blocked on image acquisition (decision D3 in the impact analysis) and slots directly into the WBD's dedicated-runner requirement. **Update 2026-10-12: unblocked — ISO acquired (`29680_1000.iso`, accepted in place of 29671.1000, see Task 6).** |
| V4 | **In-guest entry point is a single script** (`tests/vm/run-in-vm.ps1`) that builds and runs the suites and emits a machine-readable summary | Keeps the guest contract stable while the host-side harness evolves; the same entry point is reusable by CI later. |
| V5 | **Rollback scripts first (AGENTS.md rule)** | `Remove-TestVM.ps1` is written before the first VM is created, so a killed harness run can always be cleaned up manually. This satisfies the repo's testing rule at the infrastructure level. |

**Naming / layout (all new files under `tests/vm/`):**

```text
tests/vm/
  Invoke-TestsInVM.ps1     # host-side: spin up → copy → run → collect → destroy
  run-in-vm.ps1            # guest-side: build + run suites, emit summary JSON
  Remove-TestVM.ps1        # rollback: remove VM + differencing disk by name pattern
  Initialize-VMHost.ps1    # one-time host prep + readiness check (Hyper-V management requires an ELEVATED pwsh on this host — verified 2026-10-04: even Get-VM fails non-elevated; every host-side script must fail with a clear elevation hint, never flail with permission errors)
  BUILD-BASE-IMAGE.md      # runbook for preparing sbx-base-a (and later sbx-base-b)
  results/<runid>/         # fetched artifacts (logs, summary.json), host side
  vms/                     # VM working dir (differencing VHDXs); gitignored
```

---

## Branch topology

Single branch, off `feature/windows-sandbox` (the trunk dev branch): new files
only plus the three doc updates listed in Task 5. No conflicts expected with the
ADR-0001 worktree (it does not touch `tests/vm/` or these doc sections).

Merge order: independent; merge any time.

---

## Task 1: One-time host preparation and readiness check

**Files:**
- Create: `tests/vm/Initialize-VMHost.ps1`
- Modify: `.gitignore` (add `sandbox/tests/vm/vms/` and `sandbox/tests/vm/results/`)

- [x] **Step 1: Write `Initialize-VMHost.ps1`** — parameterless, idempotent,
  safe to re-run. It must:
  1. Check the Hyper-V management tools are available
     (`Get-Command New-VM`, `Get-WindowsOptionalFeature -FeatureName
     Microsoft-Hyper-V` — note this specific query needs elevation; instead
     probe `Get-VMSwitch` and report a clear remediation message if missing).
  2. Check/create the working directories (`tests/vm/vms`, `tests/vm/results`).
  3. Check a template base VHDX exists (`$VHDTemplates` dir, see Task 2) and
     print its name/size/hash; report `NOT READY` with a pointer to
     `BUILD-BASE-IMAGE.md` otherwise.
  4. Check free disk space (warn below 40 GB) and that a virtual switch exists
     (`Get-VMSwitch`; the Default Switch is sufficient).
  5. Print a one-line readiness verdict (`READY: <image>` or
     `NOT READY: <missing things>`) and exit non-zero when not ready. No output
     may suggest disabling the checks (fail-closed, in the spirit of the
     project).
- [x] **Step 2: Update `.gitignore`** for the two working directories.
- [x] **Step 3: Verify:** run it twice; second run prints only the same
  readiness verdict (idempotent). Run on a machine without Hyper-V tools (or
  simulate) and confirm the non-zero exit + remediation text.

## Task 2: Base image A runbook (`sbx-base-a`)

> **Update (2026-10-04):** the user is downloading the insider ISO that is the
> correct experimental build for MXC. That single ISO therefore serves **both**
> tracks initially: base image A (current AppContainer suite) is built from it,
> and it later becomes image B (MXC discovery) by adding the pinned `mxc/`
> checkout per Task 6 — same template or a derived one. If the experimental
> build proves too unstable for the AppContainer suite, add a stable-Windows
> template later; the harness is image-agnostic.

**Files:**
- Create: `tests/vm/BUILD-BASE-IMAGE.md`
- Create: `tests/vm/prepare-guest.ps1` (guest-side provisioning script invoked
  inside the image exactly once)

Manual, one-time, documented — automation of image creation is a non-goal for
v1. The runbook must produce a **template VHDX** (`sbx-base-a.vhdx`) that is:

- Stable Windows (the edition/license we have locally; **Enterprise preferred**
  to match the WBD Q-04 posture — record the exact edition/build in the runbook
  header once built).
- Provisioned with: PowerShell 7, Git, Rust via `rustup` (MSVC toolchain),
  and a **pre-warmed cargo registry cache** (run `cargo fetch` + one debug and
  one release build of this repo inside the image; this makes later VM runs
  offline-capable except for the repo copy itself).
- Configured for unattended PowerShell Direct access: a local admin account
  whose credentials the harness passes per run (documented in the runbook,
  stored on the host in a local settings file `tests/vm/vm-settings.json`,
  gitignored; never committed).
- Checkpointed (`sbx-base-a-clean`) and **stopped**; the VHDX is registered as
  the template in `Initialize-VMHost.ps1`'s template directory.

- [x] **Step 1: Write `prepare-guest.ps1`** (idempotent: installs pwsh/rustup if
  missing via winget, runs the cargo warm-up, disables Windows Update
  auto-reboot, sets execution policy for the admin user) and reference it from
  the runbook.
- [x] **Step 2: Write the runbook:** exact VM creation parameters (generation 2,
  dynamic memory off or fixed 8 GB, 4 vCPU, 127 GB VHDX), install steps,
  `prepare-guest.ps1` invocation, `sysprep` — **not** (the template is only
  ever cloned, never reused as a domain-joined/activated daily driver),
  checkpoint + stop + register instructions.
- [ ] **Step 3: Build the image** following the runbook; record edition, build - [BLOCKED on ISO: image not built yet; steps 1-2 done, scripts landed]
  number, and template SHA256 in the runbook's "current image" section.
- [ ] **Step 4: Verify:** `Initialize-VMHost.ps1` prints `READY: sbx-base-a`. - [BLOCKED on ISO]

## Task 3: Rollback script (before any VM exists — AGENTS.md rule)

**Files:**
- Create: `tests/vm/Remove-TestVM.ps1`

- [x] **Step 1: Write it.** Semantics: removes every VM whose name matches the
  harness prefix `sbx-test-` (and only that prefix — a name whitelist, like
  the product's own allow-lists), force-stops it, deletes the VM and its
  differencing VHDX; `-Name <specific>` for targeted removal; `-List` dry-run
  mode that prints what would be removed without removing. Templates and
  `sbx-base-*` VMs are never touched. Prints everything it removes.
- [x] **Step 2: Verify:** `-List` against a fake-named registered VM object (or
  simulate) shows the planned removal; targeted mode refuses names outside the
  prefix.

## Task 4: Guest entry point

**Files:**
- Create: `tests/vm/run-in-vm.ps1`

- [x] **Step 1: Write it.** Parameters: `-Phase` (`unit | integration | all`),
  `-Only <scenario-numbers>` (passed through to `run-tests.ps1`). Behavior:
  1. `cargo build --release` (fail → summary with build failure).
  2. `cargo test --release` (unit/Tier-1).
  3. `pwsh -ExecutionPolicy Bypass -File tests\run-tests.ps1` (integration;
     `-Only` passthrough), from a scratch working directory as required by the
     suite.
  4. Collects: exit codes, `run-tests.ps1` scenario table, stdout/stderr logs
     to `C:\sbx-results\`.
  5. Emits `C:\sbx-results\summary.json` (versioned shape:
     `{ schema: 1, started, finished, build_ok, unit: {…}, integration: {…},
     artifacts: [...] }`).
- [ ] **Step 2: Verify in-VM manually** (boot a clone by hand once, run it, - [BLOCKED on ISO: guest entry point landed + mock-verified; in-VM smoke pending image]
  inspect summary.json) before wiring the host harness.

## Task 5: Host-side harness + doc wiring

**Files:**
- Create: `tests/vm/Invoke-TestsInVM.ps1`
- Modify: `README.md` (Testing section), `docs/design/testing-principles.md`,
  `AGENTS.md` (Testing section — wording prepared in this plan, Step 5c)
- Modify: `tests/vm/vm-settings.json` convention documented in
  `BUILD-BASE-IMAGE.md` (gitignored)

- [x] **Step 1: Write `Invoke-TestsInVM.ps1`.** Parameters: `-Image sbx-base-a`
  (template name), `-Phase`, `-Only`, `-KeepOnFailure` (switch: keep VM +
  checkpoint instead of destroying, for debugging), `-VMSuffix` (default:
  short run id). Sequence:
  1. `Initialize-VMHost.ps1` readiness probe (fail → exit non-zero, no VM).
  2. Create differencing VHDX `vms/sbx-test-<suffix>.vhdx` off the template.
  3. `New-VM -Name sbx-test-<suffix>` (Gen 2, 2 vCPU, 4–8 GB, Default Switch),
     attach differencing disk, boot.
  4. Wait for PowerShell Direct readiness (retry loop on
     `Invoke-Command -VMName … -Credential …` — the loop must have a timeout,
     default 10 min → fail + `-KeepOnFailure` behavior).
  5. `Copy-VMFile` the repo (working tree minus `target/`, `.git` optional;
     use `robocopy /MIR /XD target .git` semantics host-side into a staging
     folder, then `Copy-VMFile` it in — simpler and restartable).
  6. Invoke `run-in-vm.ps1` via PowerShell Direct with the chosen phase/only
     args; stream its console output back.
  7. Fetch artifacts: read `C:\sbx-results\*` via the PS Direct session
     (byte-stream/base64 for binaries) into `tests/vm/results/<runid>/`.
  8. Teardown: unless `-KeepOnFailure` and the run failed — `Stop-VM -Force`,
     `Remove-VM`, delete differencing VHDX. Print the summary table and exit
     with the suite's aggregated result code.
- [x] **Step 2: Verify end-to-end:** run - [DONE 2026-10-12: (a) green full run
  20261012-224437 (pass=49 fail=0 skip=25); (b) `Get-VM sbx-test-*` empty after
  run; (d) `Remove-TestVM.ps1 -List` prints nothing; (c) residue check around
  run 20261012-230919: TEMP/LOCALAPPDATA ACLs and `~\.sandbox` identical
  before/after, no staging leftovers — the only new TEMP files were a VS Code
  auto-updater log + GUID .tmp, unrelated to the harness]
  `pwsh tests/vm/Invoke-TestsInVM.ps1 -Image sbx-base-a -Phase all` on a clean
  template and assert: (a) S-1…S-74 results match a known-good host run
  (modulo scenarios that legitimately depend on host specifics), (b) afterwards
  `Get-VM sbx-test-*` returns nothing, (c) **host residue check**: `icacls`
  diff on `$env:TEMP`, `$env:LOCALAPPDATA`, and the scenario roots before/after
  shows zero changes on the dev host, (d) `Remove-TestVM.ps1 -List` prints
  nothing.
- [x] **Step 3: Repeat-run check:** run it twice back-to-back; second run must - [DONE
  2026-10-12: runs 20261012-224437 and 20261012-230919 executed the identical
  committed harness (1a3d30e) back-to-back and produced identical results
  (pass=49 fail=0 skip=25), each VM destroyed cleanly — differencing-disk
  hermeticity proven, no stale state]
- [x] **Step 4: Parallel check:** two concurrent runs with distinct suffixes - [DONE
  2026-10-12: parallel runs par1/par2 (Start-Process, distinct -VMSuffix) both
  green — SANDBOX: PASS each, VMs sbx-test-par1/-par2 destroyed cleanly, logs
  vmtests-par1.log/vmtests-par2.log. VM/VHDX keyed by suffix, results keyed by
  RunId — no collisions]
- [x] **Step 5c: Doc wording (commit exactly these edits):**
  - `README.md` Testing section gains, after the two existing commands:
    > **Tier 2/3 tests run in a disposable VM.** The integration suite mutates
    > ACLs and AppContainer state; run it hermetically with
    > `pwsh tests\vm\Invoke-TestsInVM.ps1 -Phase all` (one-time host/image prep:
    > `tests\vm\Initialize-VMHost.ps1`, `tests\vm\BUILD-BASE-IMAGE.md`). Direct
    > host runs of `tests\run-tests.ps1` are for smoke only.
  - `docs/design/testing-principles.md` gains the VM requirement section (see the
    2026-10-04 amendment there).
  - `AGENTS.md` Testing section gains the VM-first rule (see Step 5c content in
    the plan's Task 5 list above; final text below):
    > Tests that change anything on the host (ACLs, permissions, AppContainer
    > profiles, network configuration) must be written to run inside the
    > disposable test VM (`tests/vm/Invoke-TestsInVM.ps1`); see
    > `docs/plans/2026-10-04-vm-test-infrastructure.md`. For any
    > test that still runs on the physical host, the rollback-script rule below
    > remains mandatory. For VM-run tests, VM deletion is the rollback; write
    > rollback scripts only for host-run tests.
- [x] **Step 6: Commit** — single branch; message:
  `test(infra): disposable-VM test harness (VM-01): spin up, run suites in-VM, collect, destroy`

## Task 6 (UNBLOCKED 2026-10-12): Base image B + WBD discovery lane

**ISO decision (2026-10-12, maintainer):** the originally pinned build
`29671.1000` media was never acquired; the maintainer accepted the later
flight of the same Experimental Future Platforms channel instead:
`Windows11_InsiderPreview_EnterpriseVL_x64_en-gb_29680_1000.iso` (in
`Downloads`, 2026-10-05). All build references below therefore target
`29680.1000`; the capability probes (not the build number) remain the
authoritative evidence per the WBD. Scope:

- [x] **Extend `BUILD-BASE-IMAGE.md` for `sbx-base-b`**: same provisioning plus the
  **pinned MXC commit checked out at `C:\mxc`** with `wxc-exec.exe` built
  (release), hash recorded. — done 2026-10-13: image-B section (single-image
  `build-config.json` handling, same-credential rule, `prepare-mxc.ps1` step,
  `sbx-base-b` export incl. derived `sbx-base-b-clean` checkpoint, image-B
  record table, troubleshooting entries). `tests\vm\prepare-mxc.ps1` (guest
  clone/pin `e7940f7`/release build/SHA256 record to `C:\mxc\mxc-build.json`;
  never runs `wxc-host-prep`) and `tests\vm\wbd-d01-d02-probes.ps1` (D-01
  baseline JSON + verbatim `--probe`/`--version`/upstream-D-02 logs + SHA256
  artifact manifest into `C:\sbx-results`) landed with it; both parser-checked
  and locally mock-verified (prereq gates, capture round-trip, empty-output
  Set-Content fix).
- [x] **`Invoke-TestsInVM.ps1 -Image sbx-base-b -TestCmd <probe/evidence command>`
  gains a generic `-TestCmd` parameter** so WBD D-01/D-02 probe capture runs
  inside the image and writes evidence artifacts into `results/`. — done
  2026-10-13: `-TestCmd` runs the given command via the PS-Direct session
  instead of the suite (same repo copy, winsta grant, streaming, teardown);
  output teed to `C:\sbx-results\testcmd.log`; ALL files under
  `C:\sbx-results` fetched (no `summary.json` contract);   empty/whitespace
  `-TestCmd` fails at a pre-creation gate (exit 3). Parser-checked; binding +
  elevation gate + tee/fetch-all logic locally mock-verified. In-VM smoke
  DONE 2026-10-13: the image-B capture lane run `20261013-142920-051`
  exercised `-TestCmd` end-to-end (WBD CAPTURE: DONE; all artifacts fetched;
  VM destroyed cleanly).
- [x] **Build image B** from `29680_1000.iso` per the runbook section (manual
  Windows Setup in the VM console is the only hands-on step), then run the
  evidence-capture lane once and record the D-01/D-02 artifacts under
  `tests\vm\results\`. — image BUILT 2026-10-13 (record in
  BUILD-BASE-IMAGE.md: Enterprise Insider Preview build 29680, secure boot
  on, MXC pin e7940f7…5b32 / wxc-exec 0.8.0+e7940f7c, template SHA256
  FD24D7…EE944D, 23.72 GB; double-export artifact renamed to the harness
  contract `sbx-base-b.vhdx` after hash verification; stray builder
  checkpoint `sbx-base-b-clean-clean` to be removed before re-bake).
  Capture lane run `20261013-150837-253` (canonical; WBD CAPTURE: DONE;
  artifacts under `tests\vm\results\20261013-150837-253`, manifest-hashed;
  superseding first run `20261013-142920-051`). D-01
  probe green (exit 0, tier base-container): baseContainerApiPresent,
  nativeCaptureAvailable, baseContainerSupportsDenyPaths and all ten UI
  block capabilities TRUE; guardedCaptureAvailable, bfscfgPresent/
  bfsCompiledIn, baseContainerSupportsEnumeratePaths,
  baseContainerSupportsIngressHostLoopbackAllow, isolationSessionAvailable,
  hyperlightAvailable FALSE. All classic isolation optional features
  (Containers/Hyper-V/WSL/VirtualMachinePlatform) report Disabled while
  baseContainerApiPresent is TRUE — the tier does not depend on them.
  D-02 BLOCKED upstream: the pinned tree has no
  `tests\scripts\run_processcontainer_probes_test.ps1` (layout drift,
  recorded in d02-upstream-probes.log — WBD-track follow-up).
  Capture-script fixes (pin-comparison false warning,
  Win32_OptionalFeature fallback for the DISM 'Class not registered'
  gap, pinMatches/dirtyPathList baseline fields) verified by the
  canonical re-run (pinMatches: true, 13 features captured,
  dirtyPathList = [mxc-build.json] only).
  **Re-pin re-bake (2026-10-13, same day):** the D-02 blocker above was
  resolved by re-pinning image B from `e7940f7` to
  `5d7a475a9fd5626bafb55c2c857989d2e5621245` (maintainer decision; rationale
  and D-02's upstream `e4619e7f` suite-split requirement recorded in
  `docs/research/mxc-source-analysis.md`, "Pin decision (2026-10-13)"). Builder VM
  re-prepared (fresh `mxc-build.json`: wxc-exec 1.0.0+5d7a475a, SHA256
  `3FD125…06DAC`), old-pin checkpoint `sbx-base-b-clean` removed after
  `MXC PREPARED` and re-taken at the new pin; template re-exported
  (SHA256 `95DAEA…02F5BE`, 25.44 GB), superseding the FD24…/e7940f7
  template above. `prepare-mxc.ps1` default `-Commit` and
  `wbd-d01-d02-probes.ps1` `$pinnedCommit` updated to the new pin.
  Capture run `20261013-173137-189` (canonical for the new pin, supersedes
  `20261013-150837-253` which referred to the old pin/template): pinMatches
  true against the full SHA, probe exit 0, tier base-container; D-01 facts
  identical to the e7940f7 runs (same OS build 29680, same 13 optional
  features, all classic isolation features Disabled). D-02: the upstream
  probes test now EXISTS and EXECUTES, but aborts at its binary-contract
  gate — `Initialize-WpcContext` (Common.ps1:1215) requires a debug-lane
  `wxc-exec.exe` AND `plm.exe`/`winhttp-proxy-shim.exe` sidecars beside
  each lane even for standalone runs; `prepare-mxc.ps1` builds the release
  lane only (recorded verbatim in d02-upstream-probes.log — genuine
  evidence, exit 1 ≠ capture error). Upstream contract fully analyzed
  (2026-10-13): ContextJson can redirect the debug lane at the release
  binary (documented override mechanism), but the two sidecar crates must
  still be built — the minimal unblock is `cargo build -p plm -p
  wxc_winhttp_proxy_shim --release` + a context JSON redirecting WxcDebug
  to the release path.
  **D-02 UNBLOCKED (2026-10-13, capture-time fix; maintainer decision: no
  re-bake):** `wbd-d01-d02-probes.ps1` now satisfies the upstream binary
  contract inside the disposable VM — it builds the two sidecar crates
  (release lane) if missing and passes a context JSON (`d02-wpc-context.json`,
  itself a fetched artifact) redirecting the debug lane at the pinned
  release binary, plus `-SkipNetwork` (read-only phase; no VM-NAT
  dependency) and `-ResultsJson` (the upstream suite's machine-readable
  results land in the fetched artifacts). Locally mock-verified in both
  branches (idempotent sidecar skip + redirect forwarding; cargo-failure
  recorded as evidence, run still completes). Canonical run
  `20261013-220007-020` (supersedes `20261013-173137-189`): **D-02 upstream
  probes test 10/10 PASS, exit 0** — P0 tier prerequisite (host selects
  base-container), P1 empty/rw/denied-policy probes all resolve
  tier=base-container with needsDaclAugmentation=False (BaseContainer
  enforces natively, incl. denied paths — matches the D-01
  baseContainerSupportsDenyPaths=TRUE), allowDaclMutation=false is a no-op
  on this tier, supportsEnumeratePaths reported present-but-False (matches
  D-01). Bonus finding: the re-bake's full-workspace `cargo build --release`
  in prepare-mxc had already produced the sidecar binaries beside wxc-exec,
  so the idempotency check skipped the build — the debug-lane redirect was
  the only gap. The prepare-mxc extension (native full artifact set incl.
  the debug lane) stays recorded as a dedicated-runner (Q-01) follow-up.
  **D-02 matrix capture (2026-10-14, run `20261014-005531-844`, supersedes
  `20261013-220007-020`):** the eight WBD request shapes (empty, fs rw/ro/
  denied, ui, deny-all-network, proxy identity-less + identity-scoped) were
  probed as complete requests — configs generated by the upstream New-Config
  helper, flat artifacts `d02-config-<shape>.json` +
  `d02-matrix-<shape>.probe.json` + summary `d02-matrix.json` (25-entry
  manifest, 24/25 hash-verified; the exception is the benign testcmd.log
  prefix snapshot — the harness appends console lines after the capture
  script writes the manifest). **All eight resolve `base-container`,
  needsDaclAugmentation=false, exit 0, errorCount=0 — no blocked rows.**
  Verdict table + source-verified boolean → PSEC mapping:
  `docs/research/wbd-d02-capability-matrix.md`. Key finding: the host advertises a
  PSEC 1.0-only contract, so the proxy-identityless shape passes via a
  temporary upstream PSEC-1.0 proxy-loopback workaround — flagged for
  re-verification on every re-pin.
- This lane is the seed of the WBD's Q-01 dedicated-runner tier; do not build
  product code from this evidence until the impact-analysis §5 decisions are
  recorded.

**Acceptance criteria (whole plan):**

- One command produces a full integration-suite run in a pristine VM and
  leaves no trace on the dev host (verified by before/after ACL diff).
- Repeated and concurrent runs are hermetic and independent.
- Failure keeps a debuggable VM behind (checkpoint + artifacts on host).
- Docs (`README.md`, `testing-principles.md`, `AGENTS.md`) all state the VM-first
  rule; the AGENTS.md rollback rule is explicitly scoped to host-run tests.
- A killed harness run is recoverable with `tests/vm/Remove-TestVM.ps1` alone.

**Out of scope / follow-ups:**

- GitHub Actions Windows runners with a hosted image (CI wiring).
- Automated ISO→VHDX image build (first image is manual).
- Image B work (unblocked 2026-10-12, see Task 6).
- Hyper-V isolated-container oracle (that is the WBD's D-13, a separate
  ticket on the WBD track).
