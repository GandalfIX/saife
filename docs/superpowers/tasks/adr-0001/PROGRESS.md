# ADR-0001 Implementation Progress

**Branch:** `feature/adr-0001-network-hardening`
**Worktree:** `C:\Users\marku\tools\.worktrees\adr-0001-network\sandbox\sandbox`
**Base SHA:** `244da75` (baseline: 95 tests pass, 0 warnings)
**Plan:** `docs/superpowers/plans/2026-07-30-adr-0001-omac-derived-network-hardening.md`

## How this file is used

The controller (subagent-driven-development) updates this file after each task
completes (implementer + spec review + code quality review). Checkpoints are
manual gates — implementation halts until the user approves.

## Status Legend

- [ ] Not started
- [~] In progress
- [x] Complete (implementer + 2 reviews passed)
- [!] Blocked / needs attention
- [-] Skipped / deferred

## Phase 1: D-0 — Capability SID fix (keystone)

| Task | Status | Implementer | Spec | Quality | Commit | Notes |
|------|--------|-------------|------|---------|--------|-------|
| 1.1 Capability SID in spawn | [x] | impl | pass | pass | d60703f | Capability SID S-1-15-3-7, conditional on is_network_active. 96 tests pass. |
| 1.2 Remove loopback + downgrade | [x] | impl | pass | pass | 6ec0a5a | Deleted loopback.rs, downgrade block, register_loopback call. Updated CLI comments. 96 tests. |
| 1.3 Proxy-Authorization: Basic | [x] | impl | pass | pass | 19cd627 | Basic auth + userinfo URL + NO_PROXY + SANDBOX_PROXY_PORT. 101 tests. |
| 1.4 Setup report update | [x] | impl | pass | pass | bb32a4a | Network row + intranet-leak warning grouped. Removed redundant Ed25519 row. |
| 1.5 Un-skip network tests | [x] | impl | pass | n/a | c2b8f9f | Test logic correct (spec pass). All 11 scenarios skip due to loopback blocker. |
| 1.6 Restore loopback exemption | [x] | impl | pass | pass | ecb5e54 | Restored loopback.rs + runtime call (admin, graceful fail). Added --enable-loopback diagnostic. |

**CHECKPOINT 1** — STOP for user approval

## Phase 2: D-5 — Audit event taxonomy

| Task | Status | Implementer | Spec | Quality | Commit | Notes |
|------|--------|-------------|------|---------|--------|-------|
| 2.1 source/scope/persisted on CONNECT | [ ] | | | | | |
| 2.2 Reserve secret.inject schema | [ ] | | | | | |
| 2.3 --audit-strict flag | [ ] | | | | | |
| 2.4 Audit filter keys | [ ] | | | | | |

**CHECKPOINT 2** — STOP for user approval

## Phase 3: D-3 + D-4 — Interactive prompt + intent registry

| Task | Status | Implementer | Spec | Quality | Commit | Notes |
|------|--------|-------------|------|---------|--------|-------|
| 3.1 Profile + CLI fields | [ ] | | | | | |
| 3.2 Hard-deny expansion + deny_domain + wildcard apex | [ ] | | | | | |
| 3.3 Learned-policy store | [ ] | | | | | |
| 3.4 Intent registry | [ ] | | | | | |
| 3.5 Interactive prompt dialog | [ ] | | | | | |
| 3.6 Wire prompt + intent + learned into proxy | [ ] | | | | | |
| 3.7 sandbox learned CLI | [ ] | | | | | |
| 3.8 Integration tests | [ ] | | | | | |

**CHECKPOINT 3** — STOP for user approval

## Phase 4: D-2 — Upstream corporate proxy chaining

| Task | Status | Implementer | Spec | Quality | Commit | Notes |
|------|--------|-------------|------|---------|--------|-------|
| 4.1 Upstream proxy dialer | [ ] | | | | | |
| 4.2 Wire upstream into proxy | [ ] | | | | | |
| 4.3 Upstream integration tests | [ ] | | | | | |

**CHECKPOINT 4** — STOP for user approval

## Phase 5: D-1 — Full filter pipeline integration

| Task | Status | Implementer | Spec | Quality | Commit | Notes |
|------|--------|-------------|------|---------|--------|-------|
| 5.1 Verify pipeline ordering | [ ] | | | | | |
| 5.2 DNS pinning + Happy Eyeballs | [ ] | | | | | |
| 5.3 Comprehensive integration tests | [ ] | | | | | |

**CHECKPOINT 5** — STOP for user approval

## Event Log

- 2026-07-31: Worktree created at `.worktrees/adr-0001-network/sandbox`. Baseline verified: `cargo build --release` (0 warnings), `cargo test` (95 passed).
- 2026-07-31: Task 1.1 complete (commit d60703f). Capability SID S-1-15-3-7 added conditionally on `is_network_active`. 96 tests pass.
- 2026-07-31: Task 1.2 complete (commit 6ec0a5a). loopback.rs deleted, downgrade block removed, CLI comments updated. 96 tests pass.
- 2026-07-31: Task 1.3 complete (commit 19cd627). Proxy-Authorization: Basic + userinfo URL + NO_PROXY + SANDBOX_PROXY_PORT. 101 tests pass.
- 2026-07-31: Task 1.4 complete (commit bb32a4a). Setup report updated with intranet-leak warning. 101 tests pass.
- 2026-08-02: Task 1.5 — **BLOCKER discovered.** The `privateNetworkClientServer` capability SID (S-1-15-3-7) grants the AppContainer process the *capability* to use network APIs, but does **NOT** add a Windows Firewall loopback exemption. The proxy listens on 127.0.0.1:<port>, but the sandboxed process's `connect()` to that loopback address is blocked by Windows Firewall. Confirmed empirically: `sandbox run --allow-domain api.anthropic.com -- cmd /c curl https://api.anthropic.com` hangs (curl exit 28 = timeout). The deleted `NetworkIsolationSetAppContainerConfig` API was adding the AppContainer SID to the loopback exempt list (`CheckNetIsolation LoopbackExempt`), which is a **separate mechanism** from capability SIDs. All 11 un-skipped scenarios (S-27..S-34, S-36, S-38, S-46) skip rather than pass because the proxy is unreachable from inside the AppContainer. The ADR-0001 D-0 assumption that the capability SID alone replaces the loopback exemption is **flawed**. Requires user decision on how to proceed.
- 2026-08-02: User chose "Add firewall rule via setup". Implemented Task 1.6 (commit e254097 + ecb5e54): restored `loopback.rs` with admin-only runtime `register_loopback` call (fails gracefully when unprivileged), added `sandbox setup --enable-loopback` diagnostic, updated setup report + warning messages. The capability SID (D-0.1) is kept — it's still needed for network API rights; the loopback exemption is a *separate* mechanism that must also be registered. Network now works when elevated; degrades to block-net with a clear warning when unprivileged. 101 Rust tests pass.
- 2026-08-15: **Checkpoint 1 verification — ACL hang bug found and fixed (uncommitted).** While verifying Checkpoint 1 item 2 (`sandbox run --allow-cwd --block-net -- cmd /c echo hello`), the command hung. Root cause: `SetNamedSecurityInfoW` on `C:\Users\marku` (and `AppData`, `AppData\Local`) hangs — Windows real-time protection (Defender) intercepts the DACL write on these large directory trees and scans every descendant, which never completes. Confirmed by running `Set-Acl` on `C:\Users\marku` with an AppContainer SID ACE from PowerShell — it hung identically. Fix in `allowlist.rs`: (1) `collect_ancestors` now stops at `USERPROFILE`, `AppData`, and `AppData\Local` (the AppContainer can traverse these via inherited `Everyone: ReadAndExecute`); (2) ancestor traverse grants are now non-inheritable (`NO_INHERITANCE`) to avoid recursive DACL propagation. Added `inherit` field to `AllowEntry`, `push_entry_noninherit` helper, and 3 unit tests. 104 Rust tests pass (101 baseline + 3 new). Integration harness: 48 pass / 5 fail (all pre-existing Python Store-alias issues) / 18 skip (network — not elevated). Items 3 & 4 (network) require an elevated shell to register the loopback exemption.
