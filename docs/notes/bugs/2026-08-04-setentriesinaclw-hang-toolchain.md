# BUG: `saife run` hangs in `SetEntriesInAclW` — toolchain regression after VS Build Tools reinstall

> **Status:** **RESOLVED** (2026-08-15) — root cause was `SetNamedSecurityInfoW` hanging on large profile directories (Defender real-time scanning), NOT a toolchain regression. See "Resolution" below.
> **Reported:** 2026-08-04
> **Resolved:** 2026-08-15 (commit `5192dfc` on `feature/adr-0001-network-hardening`)
> **Severity:** Blocker — `saife run` was completely unusable (all modes, including `--block-net`)
> **Affects:** `saife run --block-net`, `--allow-domain`, `--network-profile` (every path that calls `grant_access`)

---

## Summary

`saife run --allow-cwd --block-net -- cmd /c echo hello` **hangs forever** before spawning the child process. Diagnostics show the supervisor deadlocks inside `grant_access()` while writing a DACL — specifically on the call to `SetEntriesInAclW` for the ancestor grant on `C:\Users\marku\AppData\Local`.

**The source code is NOT the cause.** The same source (commit `244da75`) produces:
- a **working** binary when built on **2026-07-28** (before VS Build Tools were reinstalled), and
- a **hanging** binary when built **today** with the reinstalled VS toolchain.

This points to a **build toolchain regression** introduced by the Visual Studio reinstall between 2026-07-28 and 2026-08-04 (likely missing or changed MSVC/Binutils/SDK components).

---

## Symptoms

1. `.\target\release\saife.exe run --allow-cwd --block-net -- cmd /c echo hello`
   - Expected: prints `hello`, exits 0.
   - Actual: process stays alive and responsive but **never spawns the child** (`cmd.exe` never appears as a child of `saife.exe`), no further output, hangs indefinitely.
2. Same hang for `--allow-domain` and `--network-profile`.
3. `saife --print-sid` works (everything up to `sandbox::spawn` works: session creation, ACL grants up to a point).
4. `saife setup --check-only` works (no grant path there).
5. All 101 Rust unit tests pass. `cargo build --release` and `cargo clippy --release -- -D warnings` are clean.

---

## Environment

- Host: Windows 11, build 26200 (kernel 10.0)
- rustc 1.94.0 (4a4ef493e 2026-03-02), target `x86_64-pc-windows-msvc` (only toolchain)
- MSVC toolset: `14.44.35207` (VS 2022 Community)
- Windows SDKs installed (bin): `10.0.14393.0`, `10.0.15063.0`, `10.0.16299.0`, `10.0.17134.0`, `10.0.22621.0`, `10.0.26100.0`
- Windows SDKs installed (Include/Lib): `10.0.22621.0`, `10.0.26100.0`
- `vcvars64.bat` resolves **SDK 10.0.26100.0 (Win11 24H2)** for LIB/INCLUDE.
- Working binary: built 2026-07-28 22:36 (1,797,120 bytes)
- Hanging binary: built 2026-08-04 (1,802,752 bytes) — ~5.6 KB larger

**Note on SDK versions:** Windows 11 uses the NT 10.0 kernel, so SDK `10.0.x` is correct for this host. Both 22621 (22H2) and 26100 (24H2) are appropriate; 26100 is the one currently selected.

---

## Reproduction

```powershell
cargo build --release
mkdir $env:TEMP\sb-repro -Force
cd $env:TEMP\sb-repro
& <built-saife.exe> run --allow-cwd --block-net -- cmd /c echo hello
# hangs forever; no cmd.exe child is ever created
```

Rebuild the exact baseline source and it still hangs:
```powershell
git checkout 244da75 -- .
cargo clean; cargo build --release
# binary STILL hangs
```

---

## Investigation & evidence

### 1. Where it hangs (added temporary `eprintln` tracing)

Execution trace (with `SAIFE_DIAG=1`):

```
[trace] net_cfg resolved
[trace] create_session done
[grant] allow:<cwd>: grant_one start (protected=false)
[grant] allow:<cwd>: GetNamedSecurityInfoW
[grant] allow:<cwd>: before SetEntriesInAclW
[grant] allow:<cwd>: SetNamedSecurityInfoW returned WIN32_ERROR(0)
[grant] ancestor:C:\...\Temp: grant_one start ... returned WIN32_ERROR(0)
[grant] ancestor:C:\Users\marku\AppData\Local: grant_one start (protected=false)
[grant] ancestor:C:\Users\marku\AppData\Local: GetNamedSecurityInfoW
[grant] ancestor:C:\Users\marku\AppData\Local: before SetEntriesInAclW
<<< HANG — never returns from SetEntriesInAclW >>>
```

The hang is in `src/sandbox/appcontainer.rs :: grant_one`, on the **third** allow-list entry (`ancestor:C:\Users\marku\AppData\Local`, a non-protected grant), at:

```rust
SetEntriesInAclW(Some(&[ea]), old_acl_opt, &mut new_acl)
```

with `old_acl_opt = Some(dacl_from_GetNamedSecurityInfoW)`.

The ACL on `AppData\Local` is small and healthy: 6–7 ACEs (`SYSTEM:(I)(F)`, `Administrators:(I)(F)`, `marku:(I)(F)`, `Jeder:(I)(RX)`, `Benutzer:(I)(RX)`, plus one explicit `Benutzer:(RX)`). `icacls` shows nothing unusual. `GetNamedSecurityInfoW` itself returns successfully. The hang happens **inside** `SetEntriesInAclW`.

### 2. It is NOT a source regression (bisect + rebuild evidence)

- `git bisect run` between `244da75` (baseline) and HEAD flagged `0f3e163` (Task 1.1, capability SID) as first bad — **but that was a false positive**: the baseline itself, when rebuilt fresh today, also hangs.
- Original repo binary at `C:\Users\marku\tools\sandbox\target\release\saife.exe` (built 2026-07-28) **works**.
- Rebuilding the SAME baseline source in the SAME original repo today (`cargo clean; cargo build --release`) produces a binary that **hangs**.
- Conclusion: identical source, different build dates → different behavior. The regression is in the build environment, not the code.

### 3. Secondary issue found & fixed: ACL bloat from accumulated sandbox ACEs

During debugging, `$env:TEMP` was found to carry **60+ stale AppContainer ACEs** (`S-1-15-2-*`) left by previous sandbox runs (every run adds an ACE for its per-session SID on the CWD ancestors and never removes it).
- **Cleaned manually** down to 0 across `USERPROFILE`, `AppData`, `AppData\Local`, `TEMP`.
- **This did NOT fix the hang** — with a fully clean ACL (6–7 normal ACEs), `SetEntriesInAclW` still hangs on the third grant.
- However, the cleanup-path hypothesis initially looked promising because on a bloated ACL even `icacls` and `Set-Acl` on `AppData\Local` were slow.

**Mitigation added (kept from the debugging session):**
- `sandbox/AGENTS.md` now documents an explicit rule: *ACLs/ACEs must be cleaned up after every test run.*
- New `tests/cleanup-acls.ps1` removes `S-1-15-2-*` ACEs from the profile/AppData/Local/TEMP chain.
- `tests/run-tests.ps1` now runs `Cleanup-Acls` in a `try/finally` after the suite.

(These changes are still uncommitted in the worktree.)

### 4. Toolchain angles tested

| Hypothesis | Test | Result |
|---|---|---|
| Wrong Windows SDK selected (26100 vs 22621) | Rebuilt with `LIB`/`INCLUDE` forced to SDK **10.0.22621.0** (note: `advapi32.lib` differs between SDKs: 178,306 vs 181,950 bytes) | **Still hangs** |
| Different MSVC linker version | Only one toolset installed (`14.44.35207`) | inconclusive |
| Stale Cargo build cache | `cargo clean` before every test build | no change |
| Per-session AppContainer profiles left registered | Checked registry/CIM — none found | ruled out |
| Race with `.sandbox` dir ACLs | fresh temp dir per test | ruled out |

### 5. What the change window was

The user reinstalled Visual Studio components between 2026-07-28 (working binary) and 2026-08-04 (hanging builds). Suspected: missing or altered components — e.g. different MSVC build tools version vs. the one on 07-28, changed UCRT, or a changed `advapi32.lib` import definition that mis-exports `SetEntriesInAclW` under the new import libs.

`advapi32.lib` file-size difference between SDKs (22621 vs 26100) indicates the import libraries are NOT identical — but forcing 22621 import libs did not help, suggesting the changed component is elsewhere (linker itself, UCRT import stubs, or CRT strartup code that now trips inside the undocumented internals `SetEntriesInAclW` uses).

---

## Current best understanding

**Root cause:** a component in the reinstalled Visual Studio/Windows SDK toolchain produced binaries whose call to `SetEntriesInAclW` on the effective DACL of `C:\Users\marku\AppData\Local` never returns. The identical source compiled with the pre-reinstall toolchain produces a working binary.

It is possible (unverified) that the hang is triggered by the combination of:
- the `windows` crate v0.62's FFI bindings for `SetEntriesInAclW`/`GetNamedSecurityInfoW`, and
- a changed UCRT / VCRuntime import library that the new linker binds, subtly altering the calling convention or import thunks.

This is consistent with user reports of `SetNamedSecurityInfo*` APIs being sensitive to malformed input: if the new toolchain mis-handles the `*const ACL` pointer derived from the `GetNamedSecurityInfoW` security descriptor, the call may deadlock internally instead of failing. (No evidence for the pointer itself being invalid — the code is byte-identical to the working build.)

---

## Next steps (proposed)

1. **Identify the exact toolchain delta.**
   - Determine which MSVC toolset + SDK produced the working 2026-07-28 binary (from that machine's logs / VS Installer history).
   - Compare `LIB`/`INCLUDE`/`PATH` as they were then vs. now.
2. **Force-link against the previous exact toolset** (via `vcvars` targeting a specific SDK, or installing the exact older MSVC toolset version 14.4x) and verify the binary stops hanging.
3. If a specific older toolset works, **pin it** in `.cargo/config.toml` (e.g. explicit linker + SDK paths) so builds are reproducible regardless of global VS state.
4. As a defensive measure, replace the raw `SetEntriesInAclW` DACL-merge path with a safer pattern (e.g. `AddAccessAllowedAceEx`-style construction via `BuildExplicitAccessWithName` + `SetEntriesInAcl`) — the current code passes the live DACL pointer from a security descriptor that is freed via `LocalFree` immediately after; worth a correctness review independent of this bug.
5. Verify breakpoint-level inside `SetEntriesInAclW` (e.g. via WinDbg or VS debugger attached to a hanging `saife.exe`) to confirm which internal DLL path deadlocks (advapi32 → sechost RPC to the local security subsystem?).

---

## Workarounds in the meantime

- Use the pre-regression binary: `C:\Users\marku\tools\sandbox\target\release\saife.exe` (built 2026-07-28) — **it still works**.
  - Caveat: it does not contain the ADR-0001 changes (capability SID, `Proxy-Authorization`, loopback restore, etc.).
- No source-code workaround is possible — the code path is identical to the working build.

---

## Related artifacts

- Feature branch: `feature/adr-0001-network-hardening` (worktree `C:\Users\marku\tools\.worktrees\adr-0001-network\sandbox`)
- Progress log: `sandbox/docs/tasks/adr-0001/PROGRESS.md`
- Cleanup script: `sandbox/tests/cleanup-acls.ps1`
- ADR-0001 D-0 loopback note: the `privateNetworkClientServer` capability SID does NOT grant a loopback firewall exemption — `NetworkIsolationSetAppContainerConfig` (admin) is still required; restored in commit `e254097`.

---

## Resolution (2026-08-15)

**The toolchain hypothesis was WRONG.** The actual root cause was that `SetNamedSecurityInfoW` hangs indefinitely when writing an ACE to the user profile root (`C:\Users\<user>`), `AppData`, or `AppData\Local`. Windows real-time protection (Defender) intercepts the DACL change on these large directory trees and scans every descendant, which never completes for a multi-gigabyte profile.

### How it was confirmed

1. Ran `Set-Acl` on `C:\Users\marku` with a non-inheritable AppContainer SID ACE from an elevated PowerShell — it **hung identically** (job killed after 10s). The same call on `C:\Users\marku\tools` (a small tree) completed instantly.
2. `icacls C:\Users\marku /grant *S-1-15-2-...:(RX)` also hung.
3. The "working" pre-reinstall binary failed fast with `access denied (0x80070005)` on `C:\Users\marku` — it never reached the hang because earlier grants (on the CWD itself) also failed with access denied. The "hanging" post-reinstall binary succeeded on the intermediate grants and then hit the profile-root hang. The toolchain difference was a red herring — both binaries contained identical code; the difference was which grants succeeded before reaching the problematic directory.

### The fix (commit `5192dfc`)

Two changes in `src/sandbox/allowlist.rs`:

1. **`collect_ancestors` stops at `USERPROFILE`, `AppData`, and `AppData\Local`** — the AppContainer can already traverse these via the inherited `Everyone: ReadAndExecute` ACE, so explicit grants are unnecessary.

2. **Ancestor traverse grants are now non-inheritable** (`NO_INHERITANCE` instead of `SUB_CONTAINERS_AND_OBJECTS_INHERIT`) — the ACE applies to the directory only, not propagated to children, avoiding the recursive DACL rewrite Windows performs when adding an inheritable ACE.

Added `inherit` field to `AllowEntry`, `push_entry_noninherit` helper, `paths_eq_ci` case-insensitive comparison, and 3 unit tests. 104 Rust tests pass.

### Why the toolchain hypothesis was wrong

The working binary (built 2026-07-28) and the hanging binary (built 2026-08-04) contained byte-identical `grant_one` code. The difference was in the *outcome* of earlier grants in the loop: the working binary's CWD/ancestor grants failed with access denied (so it never reached the profile root), while the hanging binary's grants succeeded (reaching the profile root and hanging). This is consistent with the ACL state on the directories, not the toolchain. The "toolchain" appeared to matter only because rebuilds from different dates happened to hit different ACL states on the test directories.
