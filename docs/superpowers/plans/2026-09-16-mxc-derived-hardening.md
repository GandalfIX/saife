# MXC-Derived Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Port three verified hardening techniques from Microsoft's MXC source (analyzed in `docs/mxc-source-analysis.md`): the bidirectional-ingress limitation warning for `privateNetworkClientServer`, the LPAC opt-out spawn attribute, and crash-safe DACL journaling with teardown restore.

**Architecture:** Four tasks with explicit branch targets. Task 0 lands the reference docs on the trunk. Task 1 extends the already-implemented ADR-0001 D-0 capability-SID work with MXC's finding that the capability is bidirectional (inbound + outbound). Task 2 adds one spawn attribute (`PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY` opt-out) stripping the implicit `ALL APPLICATION PACKAGES` system-read grants. Task 3 makes host-DACL mutation crash-safe (write-before-apply journal, teardown restore, startup orphan recovery) — the robust version of the AGENTS.md-tracked "per-session cleanup (Rust)" follow-up, which also closes the stale-ACE / SID re-derivation exposure (finding F-D).

**Tech Stack:** Rust (windows crate 0.62.2), Win32 security APIs, PowerShell integration harness (`tests/run-tests.ps1`, scenarios S-1..S-71; new scenarios are **S-72+**).

**Source analysis:** `docs/mxc-source-analysis.md` (MXC @ `e7940f7`).

---

## Branch topology and sequencing (WHEN to implement each task)

Current worktrees (verified 2026-09-16):

| Worktree | Branch | State |
|---|---|---|
| `C:\Users\marku\tools` | `feature/windows-sandbox` | Trunk dev branch. Contains **`de0b9bf`** (kernel-handle `SetSecurityInfo` ntmarta-hang bypass) — trunk-only. |
| `C:\Users\marku\tools\.worktrees\adr-0001-network\sandbox` | `feature/adr-0001-network-hardening` | **Mid Phase 3** — tasks 3.1–3.3 complete (155 tests), resumes at 3.4. Based on `244da75`. Contains spawn.rs capability-SID work **and** its own `appcontainer.rs` ancestor-grant changes (commits `0f3e163`, `1b5afce`, `5192dfc`) plus `tests/cleanup-acls.ps1`. |

**Overlap warning (verified):** the ADR branch **did** modify `appcontainer.rs`
(ancestor-ACE grant path). Therefore Task 3's grant-path integration must NOT be
based on the trunk alone — it needs both `de0b9bf` (trunk) and `5192dfc` (ADR).
Task 3 is split accordingly: **3A** (journal module, pure-fs unit tests, cleanup
script — new files only, no conflicts) can start now off the trunk; **3B**
(appcontainer.rs/main.rs integration + integration scenarios) starts **after** the
ADR branch merges back to the trunk.

| Task | Branch / worktree | When | Why |
|---|---|---|---|
| **0. Land docs** | `feature/windows-sandbox` (main checkout) | **Now, first** | `docs/mxc-source-analysis.md` + this plan are untracked; Tasks 1–3 reference them from other branches |
| **1. Ingress warning** | `feature/adr-0001-network-hardening` (existing ADR worktree) | **Now**, as ADR task **1.7** (before Checkpoint 3) | Extends D-0's documented limitation; touches only `setup.rs` + ADR docs — zero overlap with remaining tasks 3.4–3.8 (intent/prompt/proxy) |
| **2. LPAC opt-out** | New worktree **off `feature/adr-0001-network-hardening`** (`feature/lpac-opt-out`) | **Now, in parallel** — `spawn.rs` is stable for the rest of ADR Phases 3–5 | Must build on the ADR branch's spawn.rs (capability SID); merge after ADR → trunk |
| **3A. Journal module** | New worktree **off `feature/windows-sandbox`** (`feature/dacl-journal`) | **Now, in parallel** — new files only | Pure-Rust module + unit tests + rollback script; no branch overlap |
| **3B. Grant-path integration** | Same worktree, **after ADR merge** into trunk, rebase `feature/dacl-journal` | **After ADR Checkpoint 5 / merge** | `appcontainer.rs`/`main.rs` diverged between trunk (de0b9bf) and ADR (`5192dfc`); integrating on the merged trunk avoids a three-way conflict in `grant_one` |

**Merge order:** (1) `feature/adr-0001-network-hardening` → `feature/windows-sandbox`
after Checkpoint 5; (2) `feature/lpac-opt-out` rebase + merge; (3) `feature/dacl-journal`
rebase (resolving `appcontainer.rs` against both `de0b9bf` and `5192dfc`) + merge.

**Explicitly NOT scheduled here** (already tracked, source-validated —
`docs/mxc-source-analysis.md` §3): F-23 (Win32k + UI-limit job mask), F-24
(learning-mode audit), F-6 (WFP driver — end-state for both intranet and ingress
leaks; MXC `allowedProxyPeer` is the interim once PSEC reaches stable Windows).

---

### Task 0: Land the reference documents on the trunk

**Files:**
- Add (commit): `docs/mxc-source-analysis.md`, `docs/superpowers/plans/2026-09-16-mxc-derived-hardening.md`

- [x] **Step 1: Commit both docs on `feature/windows-sandbox`** (main checkout)

```bash
git add docs/mxc-source-analysis.md docs/superpowers/plans/2026-09-16-mxc-derived-hardening.md
git commit -m "docs(sandbox): MXC source-code analysis + mxc-derived hardening plan"
```

Do **not** cherry-pick these into the ADR worktree — the ADR branch will receive
them via merge; Task 1's ADR edits cite the doc by path (resolvable after merge).

---

### Task 1: Bidirectional ingress limitation — setup warning + ADR amendment

**Why:** MXC's `appcontainer_runner.rs:1740-1752` rejects ingress-allow policies with
the rationale *"privateNetworkClientServer grants bidirectional private-network
access"*. Our ADR-0001 D-0 documents only the *outbound* intranet leak; the
inbound/listen surface (a sandboxed process that calls `listen()` accepts
connections from LAN peers) is undocumented, and `setup --check-only` warns only
about egress.

**Files:**
- Modify: `src/setup.rs` (report block, current lines 92–102)
- Modify: `docs/adr/0001-omac-derived-network-hardening.md` (D-0 bullet at line 29 + Negative consequence at line 181)
- Modify: `docs/superpowers/tasks/adr-0001/PROGRESS.md` (add row 1.7 + Event Log line)
- Test: `src/setup.rs` (`#[cfg(test)] mod tests` — the file has none today)

Work in the **ADR worktree** (`C:\Users\marku\tools\.worktrees\adr-0001-network\sandbox\sandbox`), branch `feature/adr-0001-network-hardening`.

- [x] **Step 1: Write the failing unit test**

Append to `src/setup.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_report_documents_bidirectional_leak() {
        let lines = network_report_lines(26100);
        let joined = lines.join("\n");
        assert!(joined.contains("intranet leak"), "egress leak documented: {joined}");
        assert!(joined.contains("inbound"), "inbound surface documented: {joined}");
        assert!(joined.contains("bidirectional"), "capability semantics documented: {joined}");
    }

    #[test]
    fn network_report_handles_unsupported_build() {
        let lines = network_report_lines(16298);
        assert!(lines.iter().any(|l| l.contains("MISSING")));
    }
}
```

- [x] **Step 2: Run the test to verify it fails**

Run: `cargo test network_report --release`
Expected: FAIL — `cannot find function network_report_lines`.

- [x] **Step 3: Extract the report block verbatim + add the inbound line**

In `src/setup.rs`, replace the six `println!` calls for lines 92–102 (from
`Network (loopback+intranet)` through `Strong isolation`) with:

```rust
    for line in network_report_lines(build) { println!("{line}"); }
```

and add (keep every existing line **verbatim**, including the 2- and 4-space
leading alignment of the current file, and keep the NOTE/WARNING lines
**unconditional** exactly as today — only the new line is added content):

```rust
/// Network-posture report lines (setup --check-only). Extracted so the
/// documented limitations are unit-testable. The `privateNetworkClientServer`
/// capability (S-1-15-3-7) is BIDIRECTIONAL: it grants egress to loopback +
/// intranet AND lets a listening sandboxed process accept connections from
/// LAN peers. MXC rejects ingress-allow policies on its AppContainer tier for
/// exactly this reason (appcontainer_runner.rs:1747). See ADR-0001 D-0,
/// docs/mxc-source-analysis.md F-A.
fn network_report_lines(build: u32) -> Vec<String> {
    vec![
        format!(
            "Network (loopback+intranet) : {}",
            if build >= MIN_BUILD {
                "available via privateNetworkClientServer capability"
            } else {
                "MISSING (requires Windows 10 1709+)"
            }
        ),
        "  NOTE                     : loopback firewall exemption required (admin). Run elevated for --allow-domain.".to_string(),
        "  WARNING (intranet leak)  : raw-socket apps can reach LAN hosts without proxy filtering.".to_string(),
        "  WARNING (inbound surface) : capability is bidirectional - a listening sandboxed process can accept connections from LAN peers.".to_string(),
        "    Strong isolation       : use --block-net (zero network capability SIDs, all connect() denied)".to_string(),
    ]
}
```

- [x] **Step 4: Verify**

Run: `cargo test network_report --release` → PASS. Then `cargo test --release`
(all pass), `cargo clippy --release -- -D warnings` (zero warnings), and
`cargo run --release -- setup --check-only` — expected output shows the new
`WARNING (inbound surface)` line.

- [x] **Step 5: Amend ADR-0001's documented limitation**

In `docs/adr/0001-omac-derived-network-hardening.md`, in D-0's "Intranet leak
(documented limitation)" bullet (line 29), append:

```markdown
**Bidirectional (validated by MXC source, 2026-09-16):** the capability also grants
**inbound** private-network access — a sandboxed process that calls `listen()`
accepts connections from LAN peers. MXC's AppContainer fallback *rejects*
ingress-allow policies while this capability is present ("privateNetworkClientServer
grants bidirectional private-network access", `appcontainer_runner.rs:1747`).
Mitigation identical to the egress case: documented limitation, `--block-net`
escape hatch, F-6 (WFP) the real fix; a future `allowedProxyPeer`-style PSEC
loopback grant is the interim once the OS APIs reach stable Windows. See
`docs/mxc-source-analysis.md` (F-A).
```

Mirror the same note into "Negative consequences / Intranet leak (D-0)" (line 181).

- [x] **Step 6: Record in PROGRESS.md**

Add row `| 1.7 Ingress-surface warning (MXC F-A) | [x] | impl | pass | pass | <sha> | setup.rs report extracted + bidirectional warning; ADR amended. |` to the Phase 1 table and an Event Log line dated today.

- [x] **Step 7: Commit (in the ADR worktree)**

```bash
git add src/setup.rs docs/adr/0001-omac-derived-network-hardening.md docs/superpowers/tasks/adr-0001/PROGRESS.md
git commit -m "docs(adr-0001): document bidirectional ingress surface of privateNetworkClientServer (MXC F-A)"
```

---

### Task 2: LPAC opt-out spawn attribute

**Why:** MXC's T3 runner always sets
`PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY =
PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT (1)`
(`appcontainer_runner.rs:73-78, 905-919`). Without it the child token carries the
implicit `ALL APPLICATION PACKAGES` SID (S-1-15-2-1) with read ACEs on most of the
system — our "read confinement works (default-deny)" claim (critical-review CR-4)
is currently weaker than documented. One attribute fixes it.

**Scope guard:** ship as opt-in `--lpac` (default OFF) this slice. Flipping the
default is a follow-up after real profiles are validated (pairs with F-24).

**Files:**
- Modify: `src/sandbox/spawn.rs` (ADR-worktree version, 129 lines)
- Modify: `src/cli.rs` — the **`Cmd::Run` clap variant** (lines 18–77; NOT the `RunArgs` struct at line 164, which is `#[allow(dead_code)]` and unwired)
- Modify: `src/main.rs` — thread the flag through **every signature in the run path** (`run_cmd` → `run_inner` → `sandbox::spawn`; the run path currently passes ~13 bare variables, spawn call at ~line 317)
- Modify: `tests/run-tests.ps1` (new **S-72**)
- Modify: `README.md`

Work in a **new worktree** off `feature/adr-0001-network-hardening`, branch `feature/lpac-opt-out`.

- [ ] **Step 1: Write the failing integration scenario (S-72)**

In `tests/run-tests.ps1`, following the existing scenario pattern (see
`Invoke-Scenario-S6`, lines 225–240; helpers `New-ScenarioDir`, `Invoke-Sandbox`),
add — note the **denial discriminator**: the plain leg must succeed AND the LPAC
leg must fail with an *access-denied* signature, not merely a nonzero exit (a
clap "unexpected argument" error would otherwise make the scenario pass
pre-implementation — that is the point of the discriminator):

```powershell
# S-72 (MXC LPAC): --lpac strips implicit ALL APPLICATION PACKAGES read grants.
# Preflight finds a file readable only via the AAP SID (S-1-15-2-1) outside the
# allowlist. Under --lpac the read must be DENIED (access-denied signature);
# without --lpac it succeeds (documents current posture; canary flips when the
# default changes).
function Invoke-Scenario-S72 {
    $d = New-ScenarioDir 72
    $aapDir = Get-ChildItem 'C:\Program Files' -Directory -ErrorAction SilentlyContinue |
        Where-Object { (Get-Acl $_.FullName).Access |
            Where-Object { $_.IdentityReference -like 'ALL APPLICATION PACKAGES*' -and
                           $_.AccessControlType -eq 'Allow' } } | Select-Object -First 1
    $aapFile = if ($aapDir) { Get-ChildItem $aapDir.FullName -File -ErrorAction SilentlyContinue | Select-Object -First 1 }
    if (-not $aapFile) { return @{ Num=72; Name='S-72'; Passed=$true; Skipped=$true;
        Detail='no AAP-readable file found; nothing for --lpac to strip' } }
    $target = $aapFile.FullName
    # 1. Without --lpac: read succeeds (implicit AAP grant present).
    $rPlain = Invoke-Sandbox -Args @('run','--allow-cwd','--','cmd','/c','type',$target) -WorkingDirectory $d
    # 2. With --lpac: read denied at the kernel - same discriminator the S-2/S-5
    #    denial scenarios use on stderr.
    $rLpac  = Invoke-Sandbox -Args @('run','--allow-cwd','--lpac','--','cmd','/c','type',$target) -WorkingDirectory $d
    $denied = ((($rLpac.Stdout + $rLpac.Stderr) -join "`n") -match 'denied|verweigert')
    $passed = ($rPlain.ExitCode -eq 0) -and ($rLpac.ExitCode -ne 0) -and $denied
    return @{ Num=72; Name='S-72 (LPAC)'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { "LPAC denied read of $target" }
                 else { "plainExit=$($rPlain.ExitCode) lpacExit=$($rLpac.ExitCode) denied=$denied target=$target" } }
}
```

Register `Invoke-Scenario-S72` in the runner table like S-13 (non-gate). The
scenario grants nothing outside `--allow-cwd`; scenario-dir cleanup is the
harness's existing responsibility.

- [ ] **Step 2: Run the scenario to verify it fails**

Run: `pwsh -ExecutionPolicy Bypass -File tests\run-tests.ps1 -Only 72`
Expected: S-72 **FAIL** with `lpacExit=<nonzero> denied=False` — clap rejects the
unknown `--lpac` flag (usage error), which does not match the denial signature.

- [ ] **Step 3: Implement the attribute in spawn.rs**

In `src/sandbox/spawn.rs` (ADR-worktree version — has `is_network_active` + capability SID):

3a. Add near the top:

```rust
/// `PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT` — opts the child out of
/// the implicit `ALL APPLICATION PACKAGES` (S-1-15-2-1) token grants, turning
/// the AppContainer into a Less-Privileged AppContainer (LPAC) for read
/// confinement. Mirrors MXC `appcontainer_runner.rs:73-78` (their T3 runner
/// always sets it). See docs/mxc-source-analysis.md F-B.
const PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT: u32 = 1;
```

3b. Extend the signature: add `lpac: bool` after `is_network_active`.

3c. Raise the attribute count from `2` to `3` in **both** `InitializeProcThreadAttributeList` calls (lines 25 and 33).

3d. After the `SECURITY_CAPABILITIES` `UpdateProcThreadAttribute` block (after line 78), add:

```rust
if lpac {
    let lpac_value: u32 = PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT;
    UpdateProcThreadAttribute(
        attr_list,
        0,
        PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY as usize,
        Some(&lpac_value as *const _ as *const _),
        std::mem::size_of::<u32>(),
        None,
        None,
    )?;
}
```

(`PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY` is exported by windows
0.62.2 `Win32::System::Threading`; the file already glob-imports it and the
Cargo feature `Win32_System_Threading` is enabled — verified, no dependency change.)

- [ ] **Step 4: Add the CLI flag and thread it through the run path**

4a. In `src/cli.rs`, in the **`Cmd::Run`** clap variant (lines 18–77, alongside
the existing `#[arg(long)]` booleans like `--allow-cwd`):

```rust
/// Opt out of implicit ALL APPLICATION PACKAGES read grants (LPAC mode).
/// Strips broad system-read access; may require tighter profiles.
#[arg(long)]
lpac: bool,
```

4b. In `src/main.rs`, thread `lpac` through **every** signature in the run path:
`Cmd::Run` match arm → `run_cmd(...)` → `run_inner(...)` → the `sandbox::spawn(...)`
call (~line 317). The run path passes ~13 bare variables today; add `lpac: bool` to
each signature and each call site, and append `lpac` to the final `sandbox::spawn(...)`
argument list (after `is_network_active`). Do NOT touch the unwired `RunArgs` struct.

- [ ] **Step 5: Verify**

Run: `cargo build --release` (zero warnings), `cargo test --release` (all pass),
`cargo clippy --release -- -D warnings` (zero warnings), then
`pwsh -ExecutionPolicy Bypass -File tests\run-tests.ps1 -Only 72`
Expected: S-72 PASS (`LPAC denied read of <path>`).

- [ ] **Step 6: README note**

In `README.md` usage section, after `--block-net`:

```markdown
### Strip implicit system-read grants (LPAC)

```powershell
sandbox run --allow-cwd --lpac -- cmd /c echo hello
```

`--lpac` opts the child out of the implicit `ALL APPLICATION PACKAGES` token
grants, removing broad read access to system directories (Program Files,
most of Windows). Stricter profiles may be required; pair with `sandbox audit`
(F-24) to discover needed paths. Default OFF; flipping the default is planned
after profile validation.
```

- [ ] **Step 7: Commit**

```bash
git add src/sandbox/spawn.rs src/cli.rs src/main.rs tests/run-tests.ps1 README.md
git commit -m "feat(us-1): --lpac spawn opt-out strips implicit ALL APPLICATION PACKAGES read grants (MXC F-B)"
```

**Follow-up (not this slice):** flip default to ON after validating
`claude-code`/`opencode`/`codex` profiles under `--lpac`; S-72's plain-leg canary
then flips to assert denial-by-default.

---

### Task 3A: DACL journal module (pure-Rust, no branch conflicts)

**Why:** AGENTS.md tracks as an unimplemented follow-up: *"sandbox run should
remove the ACEs it added on exit — not yet implemented"*, with observed failure
mode ~40 accumulated session ACEs hang `SetNamedSecurityInfoW`. MXC's
`filesystem_dacl.rs` is the reference design. Restoring also closes finding
**F-D**: leftover per-session ACEs are re-derivable (AppContainer SIDs are
deterministic hashes of the predictable session-id profile names, so a same-user
process could re-mint a past session's SID and inherit its stale grants) — and
trunk `main.rs` never calls `delete_profile` today, so profiles accumulate too.

Work in a **new worktree** off `feature/windows-sandbox`, branch `feature/dacl-journal`. New files only — safe to run in parallel with ADR Phase 3.

**Files:**
- Create: `src/sandbox/dacl_journal.rs`
- Modify: `src/sandbox/mod.rs` (register module)
- Create: `tests/cleanup-session-aces.ps1` (rollback script — AGENTS.md rule; **the trunk branch has no `cleanup-acls.ps1`; that file exists only on the ADR branch**, so this is new infrastructure here)

- [x] **Step 1: Create the module with failing-first tests**

Create `src/sandbox/dacl_journal.rs` containing the test module plus `todo!()`
stubs for `DaclJournal::open`, `record`, `entries`, `remove_file`,
`recover_orphans`, `read_header`:

```rust
//! Crash-safe journal for host-DACL mutations (MXC filesystem_dacl.rs pattern).
//! Every ACE is journaled BEFORE the Win32 apply call; teardown replays the
//! journal to restore the host; startup reaps journals orphaned by dead
//! owners. See docs/mxc-source-analysis.md F-C/F-D.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct PriorAce {
    pub deny: bool,
    pub mask: u32,
    pub inherit_flags: u32,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct JournalHeader {
    pub run_id: String,
    pub owner_pid: u32,
    /// Owner process creation time (PID-reuse guard), raw FILETIME i64.
    pub owner_created: i64,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct JournalEntry {
    pub path: String,
    pub sid: String,
    pub granted_mask: u32,
    pub deny: bool,
    pub protected: bool,
    pub prior_aces: Vec<PriorAce>,
}

pub struct DaclJournal {
    file: PathBuf,
    pub header: JournalHeader,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir()
            .join(format!("sbx-journal-test-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn header(pid: u32) -> JournalHeader {
        JournalHeader { run_id: format!("r{pid}"), owner_pid: pid, owner_created: 0 }
    }

    fn entry(path: &str) -> JournalEntry {
        JournalEntry {
            path: path.into(), sid: "S-1-15-2-42".into(), granted_mask: 0x1f01ff,
            deny: false, protected: false,
            prior_aces: vec![PriorAce { deny: true, mask: 1, inherit_flags: 0 }],
        }
    }

    #[test]
    fn record_before_apply_roundtrip() {
        let d = tmpdir("roundtrip");
        let j = DaclJournal::open(&d, header(4242)).unwrap();
        j.record(&entry("C:\\x")).unwrap();
        assert_eq!(j.entries().len(), 1);
        assert_eq!(j.entries()[0].sid, "S-1-15-2-42");
    }

    #[test]
    fn orphans_of_dead_owners_are_reaped_and_live_journals_kept() {
        let d = tmpdir("orphan");
        let dead = DaclJournal::open(&d, header(99999)).unwrap();
        dead.record(&entry("C:\\y")).unwrap();
        let _live = DaclJournal::open(&d, header(4242)).unwrap();
        let reaped = recover_orphans(&d, &|h| h.owner_pid == 4242, &|_| {});
        assert_eq!(reaped, 1, "dead-owner journal reaped exactly once");
        assert!(d.join("r99999.jsonl").exists() == false, "dead journal deleted");
        assert!(d.join("r4242.jsonl").exists(), "live journal untouched");
    }

    #[test]
    fn unparseable_journal_is_quarantined_not_dropped() {
        let d = tmpdir("corrupt");
        fs::write(d.join("bad.jsonl"), "not json\n").unwrap();
        let reaped = recover_orphans(&d, &|_| false, &|_| {});
        assert_eq!(reaped, 0, "no reap of unparseable journal");
        assert!(d.join("bad.jsonl.corrupt").exists(), "quarantined for inspection");
        assert!(!d.join("bad.jsonl").exists(), "original removed");
    }
}
```

- [x] **Step 2: Run the tests to verify they fail (todo! panics)**

Add `pub mod dacl_journal;` to `src/sandbox/mod.rs` FIRST (without registration the
test binary runs 0 tests and silently "passes"). Then:
Run: `cargo test dacl_journal --release`
Expected: FAIL/panic — `not yet implemented` from the `todo!()` stubs.

- [x] **Step 3: Implement the module**

```rust
impl DaclJournal {
    /// Open (create) this run's journal. Header line is written first.
    pub fn open(dir: &Path, header: JournalHeader) -> std::io::Result<Self> {
        fs::create_dir_all(dir)?;
        let file = dir.join(format!("{}.jsonl", header.run_id));
        let mut f = fs::OpenOptions::new().create(true).append(true).open(&file)?;
        if f.metadata()?.len() == 0 {
            writeln!(f, "{}", serde_json::to_string(&header).unwrap())?;
            f.sync_all()?;
        }
        Ok(Self { file, header })
    }

    /// Journal an entry BEFORE the caller applies the ACE to the host.
    /// Append + fsync: a torn tail line is skipped by the parser, so a
    /// crash mid-write loses at most one not-yet-applied entry (safe:
    /// never applied ⇒ nothing to restore).
    pub fn record(&self, entry: &JournalEntry) -> std::io::Result<()> {
        let mut f = fs::OpenOptions::new().create(true).append(true).open(&self.file)?;
        writeln!(f, "{}", serde_json::to_string(entry).unwrap())?;
        f.sync_all()?;
        Ok(())
    }

    /// Every entry (header line excluded). Unparseable lines are skipped.
    pub fn entries(&self) -> Vec<JournalEntry> {
        fs::read_to_string(&self.file)
            .unwrap_or_default()
            .lines()
            .skip(1)
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect()
    }

    pub fn remove_file(&self) {
        let _ = fs::remove_file(&self.file);
    }
}

/// Startup recovery: for every journal in `dir` whose owner is no longer
/// alive, invoke `reap(&journal)` (restore its entries), then delete it.
/// Unparseable journals are quarantined as `.corrupt`, never silently
/// dropped. Returns the number of journals reaped. `is_alive` is injected
/// for tests (real impl: OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION) +
/// GetProcessTimes vs `owner_created`).
pub fn recover_orphans(
    dir: &Path,
    is_alive: &dyn Fn(&JournalHeader) -> bool,
    reap: &dyn Fn(&DaclJournal),
) -> usize {
    let mut reaped = 0;
    let Ok(files) = fs::read_dir(dir) else { return 0 };
    for f in files.flatten() {
        let path = f.path();
        if path.extension().and_then(|e| e.to_str()) != Some("jsonl") { continue; }
        let Some(header) = read_header(&path) else {
            let _ = fs::rename(&path, path.with_extension("jsonl.corrupt"));
            continue;
        };
        if header.owner_pid == std::process::id() { continue; }
        if is_alive(&header) { continue; }
        let journal = DaclJournal { file: path, header };
        reap(&journal);
        journal.remove_file();
        reaped += 1;
    }
    reaped
}

fn read_header(path: &Path) -> Option<JournalHeader> {
    let first = fs::read_to_string(path).ok()?.lines().next()?.to_string();
    serde_json::from_str(&first).ok()
}
```

Run: `cargo test dacl_journal --release` → PASS (3 tests);
`cargo clippy --release -- -D warnings` → zero warnings.
(`serde`/`serde_json` are already dependencies — no Cargo.toml change.)

- [x] **Step 4: Create the rollback script (AGENTS.md rule — BEFORE any scenario mutates ACLs)**

Create `tests/cleanup-session-aces.ps1` on this branch (new infrastructure here;
the trunk harness has no ACL cleanup yet):

```powershell
# Rollback / manual-recovery script: removes session AppContainer ACEs
# (any S-1-15-2-* EXCEPT the intentional persistent S-1-15-2-2 drive-root
# grant) from the harness temp root, $env:TEMP, and AppData\Local ancestors.
# Run after a killed test run:
#   pwsh -ExecutionPolicy Bypass -File tests\cleanup-session-aces.ps1
# Review before deleting; prints everything it removes.
param([string[]]$Paths = @($env:TEMP, "$env:LOCALAPPDATA"))

$removed = 0
foreach ($p in $Paths | Where-Object { Test-Path $_ }) {
    $acl = Get-Acl -LiteralPath $p
    $dirty = $false
    foreach ($ace in @($acl.Access)) {
        if ($ace.IdentityReference -match '^S-1-15-2-' -and
            $ace.IdentityReference -ne 'S-1-15-2-2' -and
            -not $ace.IsInherited) {
            Write-Host "removing $($ace.IdentityReference) from $p"
            $acl.RemoveAccessRuleSpecific($ace) | Out-Null
            $dirty = $true; $removed++
        }
    }
    if ($dirty) { Set-Acl -LiteralPath $p $acl }
}
Write-Host "$removed session ACE(s) removed."
```

- [x] **Step 5: Commit**

```bash
git add src/sandbox/dacl_journal.rs src/sandbox/mod.rs tests/cleanup-session-aces.ps1
git commit -m "feat(us-1): crash-safe DACL journal module + session-ACE rollback script (MXC F-C/F-D)"
```

---

### Task 3B: Grant-path integration + teardown restore (AFTER ADR merge)

**Prerequisite:** `feature/adr-0001-network-hardening` merged into
`feature/windows-sandbox` (Task 3B touches `appcontainer.rs::grant_one`, which
diverged — trunk `de0b9bf` kernel-handle write vs ADR `5192dfc` ancestor-grant
changes). Rebase `feature/dacl-journal` onto the merged trunk first.

**Files:**
- Modify: `src/sandbox/appcontainer.rs` (`grant_access`/`grant_one`; snapshot + record around the kernel-handle apply)
- Modify: `src/main.rs` (journal open at run start; `recover_orphans` call; restore + `delete_profile` at teardown — trunk never deletes profiles today)
- Modify: `tests/run-tests.ps1` (S-73, S-74)
- Modify: `README.md` + worktree `AGENTS.md`

- [x] **Step 1: Write the failing integration scenarios**

**S-73 (teardown restore):** in a scenario dir, snapshot `(icacls $d | Select-String 'S-1-15-2-(?!2)').Count` before; run `sandbox run --allow-cwd -- cmd /c echo x`; after exit the count must equal the before-count (session ACEs removed — nothing left to re-derive, F-D). The regex excludes `S-1-15-2-2` (persistent drive-root grant) and inherited ACEs must be filtered (`-not IsInherited` in a Get-Acl variant if `icacls` output proves ambiguous).

**S-74 (crash recovery):** start `sandbox run --allow-cwd -- cmd /c ping -n 30 127.0.0.1` in a scenario dir; `Stop-Process` the supervisor mid-run; assert a `<sid>.jsonl` journal remains in `%USERPROFILE%\.sandbox\dacl-restore\` and the session ACE is still present (crash left both); run a second short `sandbox run` in the same dir (triggers startup `recover_orphans`); assert the stale ACE is gone and the old journal file was deleted. Verify via `tests/cleanup-session-aces.ps1` semantics; on harness failure the pre-written rollback script (Task 3A Step 4) recovers the host — AGENTS.md rule satisfied.

Register both in the runner table (non-gate). Verify: `pwsh -ExecutionPolicy Bypass -File tests\run-tests.ps1 -Only 73` / `-Only 74`
Expected: FAIL (no journaling wired yet).

- [x] **Step 2: Snapshot prior explicit ACEs in the grant path**

In `src/sandbox/appcontainer.rs`, add `use crate::sandbox::dacl_journal::{DaclJournal, JournalEntry, PriorAce};`.
Add a snapshot helper using `GetExplicitEntriesFromAclW` (returns **explicit, non-inherited** entries only — exactly the prior state we must restore; avoids manual ACE parsing):

```rust
/// Snapshot every explicit (non-inherited) ACE for `ac_sid` on `path_w`,
/// before we mutate the DACL. Restore re-grants these verbatim after
/// REVOKE-ing all our contributions (SetEntriesInAclW coalesces
/// same-trustee rights, so per-ACE selective removal is impossible —
/// MXC filesystem_dacl.rs:22-28 pattern).
fn snapshot_prior_aces(ac_sid: &PSID, path_w: &HSTRING) -> Result<Vec<PriorAce>> {
    unsafe {
        let mut sd = PSECURITY_DESCRIPTOR::default();
        let mut dacl_ptr: *mut ACL = std::ptr::null_mut();
        let r = GetNamedSecurityInfoW(path_w, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
            None, None, Some(&mut dacl_ptr), None, &mut sd);
        if r.is_err() { return Err(HRESULT::from_win32(r.0).into()); }
        let mut out = Vec::new();
        if !dacl_ptr.is_null() {
            let mut count: u32 = 0;
            let mut ea_array: *mut EXPLICIT_ACCESS_W = std::ptr::null_mut();
            if GetExplicitEntriesFromAclW(dacl_ptr, &mut count, &mut ea_array).is_ok()
                && !ea_array.is_null() {
                for i in 0..count as usize {
                    let ea = ea_array.add(i);
                    if (*ea).Trustee.TrusteeForm == TRUSTEE_IS_SID {
                        let sid = (*ea).Trustee.ptstrName.0 as PSID;
                        if EqualSid(*ac_sid, sid).as_bool() {
                            out.push(PriorAce {
                                deny: (*ea).grfAccessMode == DENY_ACCESS,
                                mask: (*ea).grfAccessPermissions,
                                inherit_flags: (*ea).grfInheritance,
                            });
                        }
                    }
                }
                let _ = LocalFree(Some(HLOCAL(ea_array as *mut _)));
            }
        }
        let _ = LocalFree(Some(HLOCAL(sd.0 as *mut _)));
        Ok(out)
    }
}
```

Import `GetExplicitEntriesFromAclW` from `Win32::Security::Authorization` (already
glob-imported via the file's existing `use` — verify; if not, extend that import).
Compile-check against windows 0.62.2 metadata and adjust signature details
accordingly (this snippet must be treated as a starting point, not gospel).

- [x] **Step 3: Journal in `grant_access`, before each `grant_one` write**

Change `grant_access(ac_sid, entries)` → `grant_access(ac_sid, entries, journal: Option<&DaclJournal>)`
and pass `journal` into `grant_one` (add the parameter). In `grant_one`, before the
DACL write (the kernel-handle `SetSecurityInfo` from `de0b9bf`):

```rust
let prior_aces = snapshot_prior_aces(ac_sid, &path_w).unwrap_or_default();
if let Some(j) = journal {
    let sid_str = sid_to_string(ac_sid); // helper: ConvertSidToStringSidW + LocalFree
    let entry = JournalEntry {
        path: path_str.clone(),
        sid: sid_str,
        granted_mask: e.access,
        deny: e.deny,
        protected: e.protected,
        prior_aces,
    };
    if let Err(err) = j.record(&entry) {
        // Journal failure is a warning: the run proceeds, and teardown/next
        // startup simply won't restore this path. Matches grant_access's
        // per-entry error tolerance.
        eprintln!("[journal] WARN: record failed for {path_str}: {err}");
    }
}
```

Notes: `AllowEntry` on the merged trunk carries `deny`/`protected`/`access`
(verify `inherit` exists there after the merge — the ADR branch added it; if the
merged struct keeps it, also record `inherit: e.inherit` and add the field to
`JournalEntry`). `diag` is a local of `grant_access`; either pass it down or use
plain `eprintln!` as above.

- [x] **Step 4: Teardown restore in main.rs**

In `src/main.rs`'s run path (`run_inner`), after the child exits:

```rust
// Teardown order matters: restore host DACLs BEFORE deleting the profile
// (a crash between the two leaves restorable state, not re-derivable grants).
let restore_ok = sandbox::appcontainer::restore_all(journal).is_ok();
if restore_ok {
    journal.remove_file();
} else {
    eprintln!(
        "[sandbox] warning: DACL restore failed; journal retained for retry at next start: {}",
        journal.file.display()
    );
}
sandbox::appcontainer::delete_profile(&ac_profile_name);
```

**Hard rule (MXC `filesystem_dacl.rs:46-51`):** remove the journal file **only on
successful restore**; failed restores keep their entries so the next startup's
`recover_orphans` retries. (The snippet above implements this.)

Implement `pub fn restore_all(journal: &DaclJournal) -> Result<()>` in
`appcontainer.rs`: for each `JournalEntry`, (1) `SetEntriesInAclW` with one
`EXPLICIT_ACCESS_W { REVOKE_ACCESS, Trustee = entry.sid }` to atomically strip all
our contributions; (2) re-grant each `prior_ace` via `SetEntriesInAclW`
(`SET_ACCESS` or deny mode, mask + inherit flags verbatim); (3) apply via the
**same kernel-handle path as `grant_one`** (open with `WRITE_DAC |
FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT`, then `SetSecurityInfo`
— `de0b9bf` bypass; do not reintroduce the Marta-hang `SetNamedSecurityInfoW`
write path). For `protected` entries, restore the owner-trustee ACEs as `grant_one`
does (reuse `owner_trustees()`).

At run **start**: build `JournalHeader { run_id: session sid, owner_pid, owner_created }`
(`GetProcessTimes` on the current process) and call `recover_orphans` once before
any grants, with the real `is_alive`.

Trunk `main.rs` does **not** call `delete_profile` today — adding it here also
stops the per-session profile accumulation (F-D facet 2).

- [x] **Step 5: Verify**

Run: `cargo build --release` (zero warnings), `cargo test --release`,
`cargo clippy --release -- -D warnings`, then
`pwsh -ExecutionPolicy Bypass -File tests\run-tests.ps1` (full suite).
Expected: S-73, S-74 PASS; no regressions in S-1..S-72.

- [x] **Step 6: Update docs**

- `README.md` "How it works": append — *"6. Every ACE grant is journaled before it is applied; on exit the journal is replayed to restore the host. If sandbox.exe is killed, the next run reaps and restores orphaned journals (quarantining unparseable ones as `.corrupt`)."*
- Worktree `AGENTS.md` ACE-cleanup section: mark the "per-session cleanup (Rust)" follow-up as **implemented** (keep the harness-cleanup rule; `tests/cleanup-session-aces.ps1` is the manual recovery path).
- `docs/mxc-source-analysis.md` F-C/F-D rows: mark landed (this file is on the trunk after Task 0 — edit it in this trunk-based worktree).

- [x] **Step 7: Commit**

```bash
git add src/sandbox/appcontainer.rs src/main.rs tests/run-tests.ps1 README.md AGENTS.md docs/mxc-source-analysis.md
git commit -m "feat(us-1): journal-backed DACL restore on teardown + orphan recovery (MXC F-C/F-D)"
```

**Deviations from this spec as implemented on trunk (2026-09-18):**
- Journal dir is `%LOCALAPPDATA%\sandbox\dacl-restore` (codebase convention), not `%USERPROFILE%\.sandbox\dacl-restore`.
- `apply_dacl_kernel` opens the write handle with `WRITE_DAC | READ_CONTROL` — a handle opened with `WRITE_DAC` alone made kernel-handle `SetSecurityInfo` return ACCESS_DENIED on this machine (pre-existing trunk grant bug, found while wiring; root cause of the all-grants-fail warnings in `err-main*.txt`).
- Ancestor traverse grants are non-inheritable and `collect_ancestors` stops at `USERPROFILE`/`AppData`/`AppData\Local` (ported from ADR commit `5192dfc`): with inheritable ancestor ACEs, even the kernel-handle write performs the recursive subtree DACL walk and hangs on large trees. This must merge cleanly with `5192dfc` during the ADR rebase.
- `recover_orphans` deletes a journal only when `reap` reports success (MXC hard rule: failed restores keep their entries for retry); `restore_one` skips entries whose object carries none of our ACEs and has no prior state (never-applied grants, e.g. system-owned SystemRoot, would otherwise keep the journal alive forever).
- S-73/S-74 register via an explicit function table so S-72 stays reserved for Task 2 (LPAC).

---

## Out of scope (recorded, not planned)

- `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` and `CREATE_SUSPENDED` spawn hardening (MXC §2.4) — small follow-ups in the same file after Task 2; file as future-ideas F-25 candidates if wanted.
- Default-on LPAC flip — after profile validation (Task 2 follow-up note).
- F-23 / F-24 / F-6 remain on their existing roadmap slots (validated by source, no design change).
