# MXC (microsoft/mxc) Source-Code Analysis — Findings Reference

> **Analyzed:** `https://github.com/microsoft/mxc` @ `e7940f7` (2026-09-16, shallow clone)
> **Method:** Direct source read of the Windows `process_container` backend and shared
> crates, cross-referenced against our `sandbox` implementation (main + ADR-0001 worktree).
> **Why:** assess maturity (see `docs/comparison-agent-win-sandbox.md` lineage), evaluate
> whether MXC's technology can replace ours, and extract techniques.
> **Companion plan:** `docs/superpowers/plans/2026-09-16-mxc-derived-hardening.md`
> (turns the actionable findings into scheduled work).

### Pin decision (2026-10-13)

**New pin: `5d7a475a9fd5626bafb55c2c857989d2e5621245`** (upstream `main` HEAD as of
2026-10-13, "docs: Add versioned containment policy references (#1471)"; contracts
0.9.0-alpha, 1.0.0, 1.1.0-alpha).

- **Why re-pin:** WBD D-02 evidence capture requires the per-area test-suite split
  introduced upstream in `e4619e7f` (2026-09-22, PR #1217), which added
  `tests/scripts/run_processcontainer_probes_test.ps1`, the `-RequireTier` gate, and
  schema-0.8 directional network coverage (`hostLoopback`, `allowedProxyPeer`). The
  previous pin `e7940f7` predates the split and only has the monolithic
  `WinProcessContainer-Tests.ps1` (97 KB, pre-split, "almost no positive network
  coverage" per upstream).
- **Maintainer decision (2026-10-13):** re-pin to current main rather than pinning to
  `e4619e7f`, so D-02 runs against the suite as it exists today.
- **Effect on this document:** all findings below were analyzed at `e7940f7`
  (2026-09-16). Source line references may have drifted at the new pin; re-verify
  them on the next quarterly analysis pass. Update the "Analyzed" header above when
  that happens.
- **Partial refresh (2026-10-14, WBD D-02):** the fallback/serviceability chain
  was re-verified at `5d7a475a` for the capability-boolean → PSEC contract
  mapping — `fallback_detector.rs` (§2.1's subject), `base_container_runner.rs`,
  `base_container_helpers.rs`, `secenv.rs`, `probe.rs`, `request_probe.rs`,
  `job_object.rs`, `ui_policy.rs`, `network_policy_helpers.rs`. The at-pin line
  references live in `docs/wbd-d02-capability-matrix.md` §4; the refs in the
  findings sections below (including §2.1) still key to `e7940f7` until the
  quarterly pass. Substantive new finding at the pin: the image-B host
  (build 29680) advertises a PSEC **1.0-only** contract — `FileSystemDeny`
  yes, `FileSystemEnumerate`/`NetworkIngress` (PSEC 1.1) no — so the
  identity-less loopback proxy rides a temporary upstream PSEC-1.0 workaround
  (matrix doc §5.1; re-verify on every re-pin).

## 1. Executive summary

1. **MXC's stable-Windows story is architecturally identical to ours**: AppContainer +
   per-directory DACL ACEs + Job Object + network-capability removal + loopback proxy.
   Our design equals their weakest fallback tier (T3). Their stronger tiers depend on
   OS APIs that only exist on Insider build 26340+ today.
2. **Microsoft independently validates AppContainer for the agent/code-execution
   workload** — the strongest counter-evidence yet against critical-review CR-1
   (OpenAI's rejection). They also invest in OS-level APIs (PSEC, BaseContainer,
   Learning Mode) to fix AppContainer's known weaknesses, which means our chosen
   primitive is the one Microsoft is actively hardening at the kernel level.
3. **Our planned/implemented `privateNetworkClientServer` fix (ADR-0001 D-0) is
   confirmed flawed by MXC's source** — but in a *narrower* way than we documented:
   the capability is **bidirectional** (egress + ingress/listen), and MXC *rejects*
   policy combinations that claim ingress-denied while it is present. Our ADR already
   documents the intranet-egress leak; the **inbound/listen surface is not yet
   documented** (plan Task 1).
4. **We are missing one hardening MXC has at spawn time**: the LPAC opt-out
   (`PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY`), which strips the implicit
   `ALL APPLICATION PACKAGES` read grants. Without it our read confinement is weaker
   than our CR-4 claim (plan Task 2).
5. **MXC's crash-safe DACL journaling solves the exact problem our AGENTS.md tracks
   as an unimplemented follow-up** ("per-session cleanup (Rust): sandbox run should
   remove the ACEs it added on exit — not yet implemented"). Their `filesystem_dacl.rs`
   (3,138 lines) is the reference design (plan Task 3).

## 2. MXC architecture as revealed by source (not by README)

### 2.1 Three-tier fallback system (`fallback_detector.rs`, `dispatcher.rs`)

Tier selection is strongest-first with explicit degradation reasons:

| Tier | Mechanism | Source refs | Availability |
|---|---|---|---|
| T1 | **PSEC / BaseContainer**: `Experimental_CreateProcessInSandbox`; policy passed as a flatbuffer spec (`ProcessSecurityEnvironmentT`): FS readwrite/readonly/denied/enumerate paths, per-CIDR+port+protocol egress rules, ingress policy, per-peer loopback | `base_container_runner.rs`, `base_container_helpers.rs`, `secenv.rs` | Windows Insider 26340+ only |
| T2 | **BFS broker** (`bfscfg.exe --addpolicy --policybroker`) — Brokered File System per-AppContainer policy | `filesystem_bfs.rs` (feature `tier2_bfs`) | feature-gated build |
| T3 | **AppContainer + DACL ACEs** (their stable-Windows fallback; our current design) | `appcontainer_runner.rs`, `wxc_common/src/filesystem_dacl.rs` | stable Windows |

T1 is also what powers Learning Mode natively: `CreateProcessSecurityEnvironment` →
`StartLearningModeTrace` (before child launch) → attach env via
`PROC_THREAD_ATTRIBUTE_SECURITY_ENVIRONMENT` → `CreateProcessW` → child exits →
`StopLearningModeTrace` → sealed ETL → `Close*`. See `native_capture.rs` (RAII
`CaptureSession` with exact OS-required ordering).

### 2.2 Network policy (the part relevant to our US-3/ADR-0001)

- `network_policy_helpers.rs`: capability names owned by policy:
  `internetClient`, `internetClientServer`, `privateNetworkClientServer`,
  `networkLoopback`. Egress-allow ⇒ `internetClient`; ingress-default-allow ⇒
  `privateNetworkClientServer`.
- **The critical validation** (`appcontainer_runner.rs:1740-1764`, test at `:2886-2930`):
  the AppContainer fallback **rejects**:
  - `ingress.default='allow'` combined with denied egress — *"privateNetworkClientServer
    grants bidirectional private-network access"*, and
  - `host_loopback='allow'` entirely — *"not supported by the AppContainer fallback"*.
- MXC's real per-endpoint loopback solution: **`allowedProxyPeer`** — loopback granted
  only to a *named AppContainer peer* (`LOOPBACK_NETWORK_PEER = "MXC-Loopback"`,
  `base_container_helpers.rs:25,251-257`) via the PSEC T1 spec. Proxy-only egress
  ("PSEC proxy", mutually exclusive with direct egress rules) blocks direct network and
  permits only the loopback proxy endpoint.
- **Confirmed: on stable Windows there is no unprivileged per-endpoint loopback
  mechanism — for anyone, including Microsoft.** MXC either requires Insider PSEC or
  rejects the policy. This validates our ADR-0001 Task 1.5/1.6 finding (capability SID
  alone does not open loopback; admin-only `NetworkIsolationSetAppContainerConfig`
  needed as a separate mechanism) and our current "downgrade to `--block-net` with
  warning" stopgap. Their long-term fix direction (per-peer kernel loopback) aligns
  with our F-6 (WFP driver) end-state; `allowedProxyPeer` is the interim once PSEC
  APIs reach stable Windows.
- Guarded fallback for Learning Mode on stable Windows: **elevated** PLM guardian over
  an authenticated named pipe driving host-wide WPR (`guarded_capture.rs`, `plm`
  crate) — i.e. elevation-assisted, same conclusion as our F-24 Backend A/B split.

### 2.3 Filesystem DACL manager (`src/core/wxc_common/src/filesystem_dacl.rs`, 3,138 lines)

Reference design for host-DACL mutation, directly applicable to our AGENTS.md-tracked
ACE-cleanup follow-up:

- **Write-before-apply journal**: every ACE persisted to
  `%LOCALAPPDATA%\Microsoft\MXC\dacl-restore\<run-id>.json` *before* the Win32 call;
  startup `recover_orphaned_state` reaps entries whose owner process is dead.
- **Restore semantics**: `REVOKE_ACCESS` for the SID (atomic strip of *all* their
  contributions — necessary because `SetEntriesInAclW(GRANT)` **coalesces** rights for
  the same trustee), then re-grant each snapshot's prior explicit ACE verbatim.
- **Prior-state snapshot**: before each apply, capture every explicit (non-inherited)
  ACE for their SID into `AppliedAce::prior_state`.
- **Concurrency**: per-path named mutex (`Local\Microsoft.MXC.Dacl.<hash16>`) for the
  whole scan/persist/apply sequence.
- **Access masks**: `readwrite` = read+write+execute+delete, with documented rationale —
  `FILE_GENERIC_EXECUTE` is required so the child can `SetCurrentDirectoryW`
  (`FILE_TRAVERSE` = `0x20` = `FILE_EXECUTE`); OI|CI inheritance deliberately
  propagates execute to file descendants for compile-and-run workloads. (We reached the
  same insight independently: our minimal ancestor mask in `allowlist.rs:18-22` and
  the `traverse` grant in KI-1.2.)
- **Crash-safety details** worth copying: `.tmp` + atomic rename for journal writes;
  `.corrupt` quarantine for unparseable journals; failed restores **retain** their
  journal entries for the next startup to retry.

### 2.4 Spawn-time hardening we do not have yet

| Hardening | MXC source | Our status |
|---|---|---|
| **LPAC opt-out**: `PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY` = `PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT (1)` — strips implicit `ALL APPLICATION PACKAGES` (S-1-15-2-1) read grants from the child token | `appcontainer_runner.rs:73-78, 905-919` | **Missing** — our AppContainer keeps broad system read access (Plan Task 2) |
| `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` — restricts inherited handles at spawn | `appcontainer_runner.rs:29` | Missing (candidate follow-up) |
| `CREATE_SUSPENDED` + resume — no window where the child runs before all attributes are applied | `appcontainer_runner.rs:26` (spawn_suspended/resume) | Missing (low risk today; needed once Learning Mode attaches pre-launch) |
| Win32k syscall disable: `PROCESS_CREATION_MITIGATION_POLICY_WIN32K_SYSTEM_CALL_DISABLE_ALWAYS_ON` (`1<<28`) via `PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY`; kernel-applied before first user instruction | `process_mitigation.rs` (whole file) | Already tracked: **F-23** |
| Job Object UI limits: clipboard r/w, desktop, display settings, global atoms, handles, exit windows + **undocumented `JOB_OBJECT_UILIMIT_INJECTION` (0x200, build 26100+) and `UILIMIT_IME` (0x100, build 22621+)**, encoded as `requested & supported` per build | `job_object.rs:86-140` | Already tracked: **F-23** (gates confirmed correct) |
| Executable-search-order hijacking defense: helper (`bfscfg.exe`) resolved once, passed verbatim as `lpApplicationName` | `filesystem_bfs.rs:20-24` | Note for any future helper-binary calls |

### 2.5 Details confirming parity or our lead

- **NULL-cwd trap**: under a deny-by-default token, a `NULL` cwd makes the kernel
  *silently relocate* the child to the drive root (`working_directory.rs:1-16`). We
  already pass a concrete cwd — documented as a regression-guard pattern worth keeping.
- **Option E / sanctioned install dirs**: no MXC equivalent. Their answer to
  open-ended binaries is Learning Mode policy-authoring instead; our
  directories-not-tools insight remains a differentiator.
- **Audit**: MXC has opt-in ETW telemetry only — no tamper-evidence. Our signed
  Merkle-tree trail (US-4) remains ahead.
- **Session/install trees, profiles, CLI UX**: no MXC equivalent (headless SDK product).

## 3. Findings mapped to our roadmap

| # | Finding | Affects | Action / where scheduled |
|---|---|---|---|
| F-A | `privateNetworkClientServer` is **bidirectional** (inbound/listen surface from LAN), and MXC *rejects* claiming ingress-denied while it is in the token | ADR-0001 D-0 (implemented, Checkpoint 1 pending) | Plan **Task 1**: amend ADR-0001 limitation + `setup --check-only` warning; long-term fix stays F-6 (WFP) / future PSEC `allowedProxyPeer` |
| F-B | We lack the LPAC opt-out ⇒ broad `ALL APPLICATION PACKAGES` system read survives our "read confinement" | US-1/US-2 core claim (critical-review CR-4) | Plan **Task 2**: `--lpac` flag; flip default after profile validation (pairs with F-24) |
| F-C | Crash-safe DACL journaling + teardown restore | AGENTS.md-tracked follow-up "per-session cleanup (Rust) — not yet implemented"; observed ~40-ACE bloat hangs `SetNamedSecurityInfoW` | **LANDED on trunk**: `src/sandbox/dacl_journal.rs` + `appcontainer::restore_all`/`recover_orphans`; scenarios S-73/S-74 |
| F-D | SID re-derivation exposure in **our** code (found during this comparison): per-session ACEs are never removed, and AppContainer SIDs are deterministically derived from the (predictable, timestamp-based) profile name — any same-user process could re-mint a past session's SID and inherit its leftover grants | US-1/US-2 | **LANDED on trunk**: teardown restore removes session ACEs on exit and at next startup; profiles deleted on exit |
| F-E | Win32k disable + UI-limit job mask (incl. `0x200` injection, `0x100` IME, build gates 26100+/22621+) | future-ideas **F-23** | No change — source **validates** F-23's design (gates match exactly) |
| F-G | Learning Mode = PSEC OS APIs (`CreateProcessSecurityEnvironment` / `StartLearningModeTrace` / `StopLearningModeTrace` / `CloseLearningModeTrace`, attach via `PROC_THREAD_ATTRIBUTE_SECURITY_ENVIRONMENT`), Insider-only; stable-Windows fallback is elevation-assisted guarded WPR | future-ideas **F-24** | No change — F-24 Backend B now has concrete API names to probe for |
| F-H | Per-peer loopback (`allowedProxyPeer`) is MXC's end-state for proxy-only egress | future-ideas **F-6** / US-3 end-state | No change — note as interim option once PSEC reaches stable Windows |

## 4. Reusability verdict (unchanged from initial analysis, now source-confirmed)

- **Do not adopt MXC as a dependency or backend now**: pre-release, self-declared
  "not a security boundary", full Windows features gated on Insider builds, and we lead
  on Option-E install trees, audit tamper-evidence, and agent CLI UX.
- **Do mine it**: it is MIT-licensed and its `filesystem_dacl.rs`, `job_object.rs`
  build gates, and network-validation stance are directly portable. Clone kept at
  `%LOCALAPPDATA%\Temp\opencode\mxc-analysis` (shallow, disposable).
- **Re-check quarterly**: the maturity signal to watch is removal of the README
  "not a security boundary" warning; `allowedProxyPeer`-class loopback APIs reaching
  stable Windows would unblock our US-3 end-to-end without F-6.
