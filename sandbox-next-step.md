# sandbox: current next steps (updated 2026-10-18)

## 0. DONE 2026-10-17 - WBD D-03 + D-04 stop-work gates COMPLETE (both ADRs landed)

The full D-03+D-04 plan (`docs/plans/2026-10-14-wbd-d03-d04-stop-work-gates.md`,
all 10 tasks) is executed and committed on `feature/windows-sandbox`:

- PR1 (D-03): `cb85c0f` (spike lane, mock-verified), `2c72106`+`e2be211`
  (user-approved Amendment 1: System32 `powershell.exe Start-Sleep` sleepers +
  `readonlyPaths C:\Windows` grants + nested `processContainer.filesystem.
  enumeratePaths` — plan↔repo kept byte-identical), `3dfd2c0`
  (**ADR-0002** `docs/adr/0002-mxc-integration-surface.md` + companions:
  mxc-source-analysis partial-refresh note, BUILD-BASE-IMAGE spike-lane section,
  plan run annotations).
- PR2 (D-04): `e701db1` (**ADR-0003** `docs/adr/0003-basecontainer-only-enforcement.md`).
- Evidence: canonical runs `20261017-121539-354` + Amendment-1 `20261017-130259-402`
  (32 artifacts each, manifests hash-verified; run 2 discharged all four lifecycle
  axes: stdin round-trip, request-level timeout @3000ms, kill teardown with zero
  survivors, EnumeratePathsUnsupported adjudication refusal refused-before-exec).
  Verdict records in scratch `task7-verdicts-<runid>.md` (both runs).

**Binding stop-work verdict (both ADRs):** selected surface = mxc-sdk in-process
crate dep; created-not-running / pre-resume attestation UNAVAILABLE at pin
`5d7a475a` on every surface → **no product launch path may be implemented until
upstream exposes a mechanism** (minimal change: public suspended-spawn/resume or
created-not-running handle on SandboxBackend/v1). D-04 adds the second upstream
ask: an atomic require-tier request field. ADR-0003's interim adapter posture
(preflight + spawn-time tier check + immediate kill) is recorded as bounded, not
preventive.

**Manual use verified on host (2026-10-17):** the existing AppContainer sandbox
works for hands-on testing — `target/release/sandbox.exe run --allow-cwd --
<cmd>` (no elevation needed): reads/writes outside the granted dir denied
("Zugriff verweigert", secret intact), inside granted dir read+write OK.
Caveat: OS/system dirs remain READABLE inside the sandbox on this host
(machine carries AAP/ARAP read ACEs on system dirs) — probe with user files,
not OS files. Network flags are stubs in this slice.

**What may proceed now** (per the gates): contracts and test infrastructure only,
plus the two upstream asks to track. Natural next candidates:
- Track/file the upstream requirements (require-tier field; created-not-running
  surface) against pin `5d7a475a` and watch for them on every re-pin (ADR-0002 §4
  re-verify list).
- The D-02/ADR-0002 re-pin caveat: both ADRs' file:line refs are pin-specific.
- Anything in sections 2/4/5 below (open product question cmd-in-AC/PROTECTED,
  LPAC opt-out S-72 redesign, ADR-0001 Task 3.4).

## 1. DONE 2026-10-12 - S-9 in-VM green, VM-01 Task 5 fully verified

Full evidence trail in commits `1a3d30e` (harness fixes) and `6940dc9`
(VM-01 plan annotations).

- S-9 (venv-with-pip) passes in-VM. Root causes fixed across the week:
  signing-key race (`d4d0822`), per-session TEMP redirect (`b5a2b0d`),
  deterministic grant propagation + `SANDBOX_SESSION_SID` (`bc805f5`),
  pyshim venv-root channel (`576da08`), and on 2026-10-12 the two
  harness-side fixes (`1a3d30e`): S-9 r2 spawns the venv python directly
  (no `cmd /c`), and `Invoke-TestsInVM.ps1` grants the PS-Direct session's
  winsta + desktop an AAP ACE (children touching user32 died on the bare
  service winsta otherwise).
- S-37 converted to a deferral skip like S-36/S-38/S-39: `--allow-domain`
  exits with a slice-deferral warning before the child runs (US-3), so the
  fail-closed assertion can't be evaluated until the network slice lands.
- VM-01 Task 5 Steps 2-4 verified and recorded in the plan (`6940dc9`):
  green full run, no leftover VMs, host-residue check clean (TEMP/
  LOCALAPPDATA ACLs + `~\.sandbox` identical before/after), same-commit
  back-to-back repeat identical, parallel par1/par2 runs both green.
- The 2026-10-11 mid-suite 0x80070002 session-host collapse did NOT recur
  in any of the four green full runs today (224437, 230919, par1, par2) -
  treat as closed unless it reappears.
- Kept debug VMs removed; `Remove-TestVM.ps1 -List` is empty.

## 2. OPEN product question: cmd-in-AC cannot spawn from PROTECTED subtree

In-VM only (not on host): a sandboxed `cmd.exe` cannot CreateProcess any
exe under the PROTECTED `.sandbox\<sid>` subtree, while python spawns the
same binary fine. Evidence rounds (M/V/W matrices in
`sandbox/tests/vm/confirm-s9-winsta.ps1` + commit `1a3d30e`) killed the
label theory (Low-labeled whoami-copy passes elsewhere), the file-ACE
theory (Everyone:RX grant doesn't help), and the directory theory
(Medium-labeled copy in the same Scripts dir fails; same binary from
Program Files passes). Next step: a procmon/kernel-audit round inside a
kept VM to pin the exact denial. Affects real toolchains that spawn
freshly-built exes via cmd wrappers. Harness works around it by spawning
directly; the product question remains.

## 3. Small warts / backlog

- `join_cmdline` (src/main.rs:448) doubles ALL backslashes in quoted args;
  only those preceding a quote should be doubled. Harmless for current
  scenarios (unit test covers the space-quoting path).
- BUILD-BASE-IMAGE.md Current-image ISO row: isoPath says `29680_1000.iso`
  while image A's guest build is 26340. Resolved by fact-checking on 2026-10-18:
  image A = build 26340, image B = build 29680 (the ISO in that row belongs to
  B). Fix the doc to state both images' builds explicitly instead of one row.
- ~100 stale `sandbox.*.ac` profile dirs in host Packages (profiles are not
  deleted at teardown); same count of HKCU AppContainer `Mappings` keys in
  the guest. Backlog cleanup pass.
- S-74 skips in-VM ("DACL writes unavailable here"): the PS-Direct guest
  session can't write the DACLs the crash-recovery scenario needs. Host-run
  of S-74 would need a rollback script per AGENTS.md.
- S-49/S-56 remain deferred to US-4b (audit fidelity events).
- `sandbox/tests/debug-2026-10-11-0057.txt` is stale debug evidence -
  disposable.

## 4. LPAC opt-out (mxc plan Task 2) - worktree ready, S-72 needs redesign

Worktree `.worktrees/lpac-opt-out` (branch `feature/lpac-opt-out`), rebased
onto trunk 9970ef4. Blocker before coding: S-72 probe redesign - AAP-only
probe is denied in the plain sandbox; system dirs carry AAP+ARAP both.

## 5. ADR-0001 network hardening - COMPLETE, LANDED, AND VM-RUN

`feature/windows-sandbox` (de-facto trunk) is now at `0cb7e8e`: ADR-0001 was
rebased from its old base `9970ef4` onto trunk `e701db1` and fast-forwarded in
(63 commits). Pre-rebase head kept as tag `adr-0001-pre-rebase-20261018`
(`5680716`). `master` was NOT touched - it is the backup-tool lineage.

Gates on the landed tree: 390 tests / 0 failures / 0 clippy / 0 build warnings.
Conflicts resolved by keeping both sides (harness helpers, AGENTS.md sections,
test blocks in appcontainer.rs/allowlist.rs, clippy formatting hunks).

The merged harness HAS now been executed - in-VM, on two OS builds (see section 6).
So the earlier "merge needs an elevated host run" caveat is discharged for the
harness itself; what remains is the nine scenario failures below.

Post-ADR follow-ups (recorded in PROGRESS.md): AppData known folders;
empty-stop-set fail-fast; stale pre-fix traverse ACEs; incremental Happy-Eyeballs
batch advance; JoinSet on caller drop; DNS timeout on system_lookup;
Invoke-ConnectProbe relative path; F-21 elevation-free install-time exemption.

## 6. DONE 2026-10-21 - VM full suite green on BOTH images

Repair completed; both OS builds now run the whole suite clean:

| image | OS build | integration | verdict |
|---|---|---|---|
| sbx-base-a | 26340 | 92 total: **76 pass / 0 fail / 16 skip** (run `20261021-002251-603`) | SANDBOX: PASS |
| sbx-base-b | 29680 | 92 total: **77 pass / 0 fail / 15 skip** (run `20261021-003055-905`) | SANDBOX: PASS |

Baseline was 67/9/16 on both builds. The four causes (all harness-side, none a
product defect - details in PROGRESS.md event log):

1. Windows PowerShell 5.1 cannot invoke NATIVE commands inside the AppContainer
   (`DriveNotFoundException`) -> S-75/S-77 rewritten as pure managed code.
2. `pwsh` cannot be spawned as a sandboxed child at all in the guest
   (`0x80070520`) -> the "switch to pwsh" remedy was wrong; managed code under
   5.1 is the durable pattern (S-91 precedent). Remember this for any future
   scenario that needs a shell inside the container.
3. Live TLS is environmental, not a pipeline property (argv matrix proved nine
   variants identical; admitted cases show `http_connect=200` then `exit=35`
   from an unreachable CRL) -> S-27/29/32/33/34/36 and S-83 assert the proxy
   decision, origin codes informational.
4. S-28 was a FALSE PASS (`exit!=0 && code=000` is satisfied by any transport
   failure) -> now requires `http_connect=403` or an audit deny leaf.

Left over (small, not blockers): `Test-CurlReachedServer` is unused since the
rewrite - delete in a cleanup pass. The temporary `tests/vm-probe.ps1` matrix
probe was deleted and never committed.

## 7. IN PROGRESS - MXC migration (ADR-0004 Option A, plan 2026-10-21)

**Landed so far** (all on `feature/windows-sandbox` = de-facto trunk):
- `a067461`/`6933a89` - ADR-0004 Accepted + ADR-0002/0003 amended (Option A with
  two normative guardrails); spike crate proves unelevated base-container +
  proxy-only egress + direct-egress denial.
- `5c0c051` - migration plan + tracker (`tasks/mxc-migration/PROGRESS.md`).
- `f2c1136`/`7ca2504` - **P0**: `mxc-sdk = "=1.0.1"` behind `mxc-backend`
  (default off), pure `build_request`, both guardrails, `--backend` fail-closed.
- `52614f2`/`39951f8` - **P1 wave 1**: `mxc-launch` wrapper delivers `NO_PROXY`
  (the SDK scrubs it); epoch lifecycle; `ProofExpectation::{Required,
  MustBeAbsent}`; D2/D6 decisions. Live test proves it unelevated.
- `7481b96`/`ade9fd1` - **P1 wave 2**: the real `ProxyProofSource` over the
  listener's own counters, per-session port, fail-closed filesystem policy, and
  **plain-HTTP forwarding (plan D9)**, which took THREE security review rounds
  (7 blockers, 2 self-inflicted) before PASS. It is now strict-reject: interim or
  unparsable origin heads -> 502, `Connection:` naming a framing field -> 400,
  whitespace in a field name -> 400, `Expect` -> 400, origin 407 -> 502 with the
  challenge withheld, exactly one admitted request per connection, `Host`
  rebuilt from the admitted authority. Gates: 432 / 511+2 ignored, 0 clippy.

- `486ac8d`/`095c7b0` - **P1.4**: `RunToken` (run-serial prefix + 224 CNG bits,
  constant-time compare, redacted Debug), `OwnRun`/`Absent`/`Foreign` auth
  classification, overlap-refusing epochs (`MxcError::Concurrency`), prune of
  CLOSED epochs only, and the mandatory **two-container** live test: both proofs
  `{1,1}`, cross-token 407 uncounted, closing B leaves A serving. Both reviews
  PASS; a post-review fix gave `Foreign` its own `foreign_token` audit leaf
  (silence in both chains was the wrong default) and corrected the stale
  `--concurrency` message. Gates: 439 / 519+3, 0 clippy.

- `bed32dd`/`1938afe`/`f19b6ac` - **P1.5 + P1.7**: two findings that change the
  migration's shape.
  1. **Only env-reading clients have egress.** curl works; WinHTTP and WinINet are
     *forced* to our proxy by the container but send no credentials (407), and
     `HKCU\...\Internet Settings` cannot be opened for write from inside
     (`ERROR_ACCESS_DENIED`), so per-user proxy configuration is not possible:
     GUI/system-proxy workloads need the AppContainer backend or an OS-attested
     peer, not a bearer token.
  2. **Every managed process died at load** (`0xC0000142`, `coreclr.dll`
     `0x8007045A`) because `build_request` omitted `ui`, and the SDK default
     (`UiPolicy::default().disable = true`) bans Win32k syscalls; user32/gdi32/
     ole32 DllMain then fails, and coreclr statically imports user32+ole32.
     Fixed by stating `ui.disable = false`; a live leg now proves
     `powershell` prints FXOK inside the container. **Recorded posture change
     (D10 / ADR-0004): the child may enter Win32k, so the kernel attack-surface
     containment the default gave us is gone.** The SDK's AppContainer tier
     applies the same ban, so falling back would not have helped.

- `eff8e40` - **P1.8**: managed proxy paths measured against the REAL listener.
  .NET 8 `SocketsHttpHandler` and pwsh 7 **work** (CONNECT and absolute-form), but
  only through a 407-then-retry handshake: they read the credential from the
  `HTTP_PROXY` userinfo and send it only after `Proxy-Authenticate: Basic`.
  **The challenge is load-bearing** and now pinned by a test.
  Windows PowerShell 5.1 / .NET Framework have **no egress at all** - they take
  the proxy from the WinINet store, which reports 'direct' in the container, so
  they dial direct and die on `WSAEACCES 10013`. Consequence: **managed workloads
  must be pwsh 7 / .NET 8+**.

**Next:** P2 (prompt/intent/audit parity) or row P1.6 hardening - P1.6(a) is now a
steady-state concern, because every managed connection emits one benign `no_token`
leaf. Open design question for a spike: admit an OS-attested peer (SID/WFP)
instead of a bearer token, which would remove the 407 round-trip, the leaves and
the credential-delivery problem in one move - at the cost of P1.4's per-run token.

**Known-good gates right now:** 420 tests (feature off) / 489 + 2 ignored
(feature on), 0 clippy warnings both states, both live legs green unelevated.

**Still true:** nothing in the product path has changed - `--backend mxc` refuses,
`MXC_SESSION_WIRED = false`, and every network session still needs UAC. The flip
is P3, gated on the full 92-scenario suite passing against the MXC backend on
both VM images, unelevated.

## 8. NEXT - resume the feature plan (Phase 6 onwards)

Trunk is clean and both VM images verify green (A 76/0/16, B 77/0/15, host
elevated 7/7). Feature work can proceed in parallel with the migration. Before
starting: re-read the plan's Phase 6 section, confirm its scenario numbers
against the harness (S-72..S-94 will be taken once P2.4 lands), and keep the
standing rule - VM suite at 0 fail on BOTH images before a phase is called done.

## Host state and the cleanup gate

**Rule:** every test block that touched the HOST ends with
`pwsh -File tests\Clear-HostTestArtifacts.ps1` and must print `HOST-CLEAN`.
VM runs are exempt - they touch a disposable differencing disk, not the host.

State as of 2026-10-21 20:5x (unelevated pass already run):
- 9 of 18 dirty paths cleaned, 28 stale DACL journals pruned.
- **9 paths still need ONE elevated run:** `C:\Users` itself, two
  `AppData\Local\Packages\sandbox.*.ac\AC\Temp` dirs, and the
  `.worktrees\adr-0001-network\sandbox\sandbox\target\release\.sandbox\{20261017-230736-76548,20261017-231155-57568}\{,,bin,venv}`
  chain. Run elevated:
  `Start-Process pwsh -Verb RunAs -ArgumentList '-NoProfile','-File','C:\Users\marku\projekte\saife\tests\Clear-HostTestArtifacts.ps1'`
- 4003 host audit logs are KEPT (evidence). `-RemoveAudit` drops them.

**VM lane needs elevation** and cannot run unelevated today:
`tests/vm/Invoke-TestsInVM.ps1:252` hard-gates on
`IsInRole(Administrator)` and exits 2, because Hyper-V cmdlets require admin or
membership in *Hyper-V Administrators* - and that local group does not exist on
this host (`net localgroup "Hyper-V Administrators"` -> error 1376). Tests INSIDE
the VM run as the guest's own admin on a disposable disk, so they never touch
host permissions. To get unelevated VM runs later: create that group once as
admin, add the account, then change the harness gate to accept group membership
instead of full Administrator.

## VM lane: unelevated, and the baseline it produces

**The host-side VM lane no longer needs UAC.** `Invoke-TestsInVM.ps1` and
`Initialize-VMHost.ps1` now accept either Administrator or membership in
S-1-5-32-578 ("Hyper-V-Administratoren"); match on the SID, never the localized
name (an English `net localgroup` on a German host returns 1376 for a group that
exists). The account must be added once and the token refreshed by a logon.

## FINAL STEP (user, 2026-10-22): Windows version matrix

When the implementation is finished (P3.3 done, lane resolved or explicitly dropped), build one
test VM per supported Windows build and run the suite on each - 24H2 `26100.x` first (oldest
supported AND the gated-feature boundary), then 25H2 `26200.x`, 26H2 `26300.9550+`, optionally
Server 2025 only if server use is in scope; keep one Insider (29680) as a labelled canary. Per
build: full suite on both backends, a capability table (`docs/research/wbd-d02-capability-matrix.md` as the
template), and the standard-user lane once unblocked. Plan section **P5**. Do not start it before
the implementation is done - an unfinished build measures the wrong thing.

## OPEN (not done, do not mistake for done)

**The standard-user VM lane does not work and is PARKED (2026-10-22).**
`tests/vm/Invoke-TestsInVM.ps1 -AsStandardUser` refuses with exit 3 and points here. Reason: from a
PowerShell Direct session, nothing available starts a process as a second local account -
`Start-Process -Credential` (CreateProcessWithLogonW) returns `ERROR_INVALID_PARAMETER 87` and
`schtasks /Create` / `Register-ScheduledTask` return `ERROR_FILENAME_EXCED_RANGE` (206), tried 15 times
against a RE-BAKED image whose account already had a real profile, S-1-5-32-555, a fresh password and
grants. Each attempt fixed a real layer (no handle inheritance under -Credential, parameter sets, the
262-char action cap, deleting a missing task under $ErrorActionPreference=Stop, native stderr advisories,
/TR quoting) without reaching the child. Untried: (a) `New-CimSession -ComputerName . -Credential` +
`Win32_Process.Create`; (b) restricted-token launch (`runas /trustlevel`), which needs `seclogon`.
Full evidence: PROGRESS.md, "P3.1 blocker".

Consequence to keep visible: **every VM session currently runs with the guest's elevated token**, so the
VM suite proves product logic but NOT the elevation claim. "Works unelevated" rests on HOST evidence -
real `--backend mxc` sessions on this host with `elevated=false` in the leaf and `http_connect=200`
through the proxy. Never quote a green VM run as unelevated coverage.

**Baseline, measured 2026-10-22, both images, UNELEVATED, 93-scenario suite:**
- **AppContainer** (default), image A: `total=93 pass=78 fail=0 skip=15` (S-74 now executes)
- **`--backend mxc`**, image A: `total=93 pass=60 fail=0 skip=33` (21 AppContainer-only + 12 environmental)
- **`--backend mxc`**, image B: `total=93 pass=60 fail=0 skip=33` (identical)

S-93 is RESERVED out of the run (guardrail 1 is MXC-only; the harness cannot select that backend
until P3), so 93 = numbers 1..94 minus S-93. The guardrail-1 refusal is pinned by an ignored live leg
instead. A suite run needs `cargo build --release` first: the harness does not rebuild a present
`sandbox.exe`, and a stale binary is how S-94's first cut read a leaf with no `elevated` key.

Both match the old elevated baseline, so removing UAC cost no coverage. This is
the number every later phase is measured against.

Two harness defects found while getting there, both fixed:
- The loopback probe (`Test-LoopbackProxyReachable`) took ONE 5 s sample and
  cached it for the whole run, so a slow start turned ~25 network scenarios into
  silent skips while the suite printed PASS. It now retries 3x at 15 s, reports
  the exit codes, and prints them in the verdict line.
- The same probe lacked `--no-prompt`. Since D9 forwards absolute-form plain
  HTTP, its request to an unlisted host went to the prompt policy, which has no
  dialog in a headless guest; curl expired at `-m 15` with exit 28 and the probe
  read that as "loopback blocked" - a false negative that skipped 25 scenarios.
  Verified cause: stderr shows `loopback exemption registered` and the proxy
  listening; loopback was never blocked.

**Staging cost**: only the root `target` was excluded, so `tests/vm/spikes/*/target`
(2.5 GB) was zipped into the VM on every run (862 MB / 5,478 files). Now every
`target` dir is excluded by absolute path (robocopy resolves a bare `/XD` name
against the *destination*, so `'target'` excluded nothing). Measured: **176 files / 2.3 MB**,
down from 5,478 files / 862 MB. Both the test lane (`Invoke-TestsInVM.ps1`) and the
image-build lane (`Copy-RepoToVM.ps1`) had the same defect.

**Open product finding from the same investigation**: with the prompt enabled, a
plain-HTTP request to an unknown host now waits on a dialog that may have nobody
to answer it - a client-visible stall until the prompt times out. P2's D-3 budget
must cover the FORWARD path, not just CONNECT.

## IMAGE FACTS (2026-10-22)
The re-baked `sbx-base-a.vhdx` (SHA256 `B5BA5A73...`, re-exported 16:52 after adding the
standard-user profile) reports **guest build 29680**, not the 26340 it had before - so **both
templates are now the SAME build**. Consequences to keep in mind when reading evidence:

- "both images" no longer means two builds: the P3.1 runs (`93/60/0/33` on each) are SINGLE-build
  evidence, measured twice.
- Baselines recorded before 16:52 today (image A = 26340, `77/0/16`) are historical and not
  comparable field-for-field with runs after it.
- Neither image is a GA servicing build (A 26340 and B 29680 are both Insider flights). The
  "supported build" argument rests on ADR-0004's reading of the SDK's list, not on measurement; a
  24H2 `26100.x` image would close that, and 26100 is also the boundary for several gated features.

To restore build diversity cheaply: the builder keeps an Oct-5 checkpoint (`sbx-base-a-clean`);
revert it and re-run `Export-BaseImage.ps1` (~15 min). The only loss is the standard-user profile,
which is worthless while that lane is parked.
