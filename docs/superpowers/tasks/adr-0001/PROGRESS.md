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
| 1.7 Ingress-surface warning (MXC F-A) | [x] | impl | pass | pass | b54977f | setup.rs report extracted + bidirectional warning; ADR amended. |

**CHECKPOINT 1** — STOP for user approval

## Phase 2: D-5 — Audit event taxonomy

| Task | Status | Implementer | Spec | Quality | Commit | Notes |
|------|--------|-------------|------|---------|--------|-------|
| 2.1 source/scope/persisted on CONNECT | [x] | impl | pass | pass | dc70fb0 | emit_connect signature + SOURCES const + deny_source helper. 5 tests. 109 tests. |
| 2.2 Reserve secret.inject schema | [x] | impl | pass | pass | ee62660 | Doc comment + SECRET_INJECT_SCHEMA const. 1 test. 110 tests. |
| 2.3 --audit-strict flag | [x] | impl | pass | pass | 37c28947 | AuditWriter::open/append -> Result, strict mode, open_at helper. 2 tests. 112 tests. |
| 2.4 Audit filter keys | [x] | impl | pass | pass | c5c051b | source/scope/persisted in KNOWN_KEYS, eq_match boolean + case-sensitive branches. Doc grammar updated. 6 tests. 118 tests. |

**CHECKPOINT 2** — ✅ APPROVED (2026-08-15)

Manual verification (elevated shell, loopback exemption registered):
1. `sandbox run --allow-cwd --allow-domain api.anthropic.com -- cmd /c curl --ssl-no-revoke -s -o NUL -w "%{http_code}" https://api.anthropic.com/v1/messages` → `405` (connection works; `--ssl-no-revoke` needed because Schannel's CRL/OCSP fetch to CA servers is outside allow-list).
2. `sandbox audit show <sid> --json` → CONNECT event includes `"source":"allowlist","scope":null,"persisted":false`.
3. `sandbox audit show <sid> --filter "source=allowlist"` → narrows to 1 CONNECT event (SESSION_START filtered out).
4. `sandbox run --allow-cwd --allow-domain api.anthropic.com --audit-strict -- cmd /c echo hi` → `hi` (session starts normally, log writable).

## Phase 3: D-3 + D-4 — Interactive prompt + intent registry

| Task | Status | Implementer | Spec | Quality | Commit | Notes |
|------|--------|-------------|------|---------|--------|-------|
| 3.1 Profile + CLI fields | [x] | impl | pass | pass | 2e03260 + a51beb1 | on_unavailable validation + deny-only/no-prompt-empty edge tests. |
| 3.2 Hard-deny expansion + deny_domain + wildcard apex | [x] | impl | pass | pass | a15d55a + 0278fed | Allocation-free matches() + precomputed denied IP literals. |
| 3.3 Learned-policy store | [x] | impl | pass | pass | 4c14769 + f396527 | Atomic persistence + profile_name validation + concurrency doc + schema test. |
| 3.4 Intent registry | [x] | impl | pass | pass | b19ff63 | 25 tests: normalization, TTL (lazy + sweeper), explain one-shot (bounded), 500-cap seq eviction, 500-char truncation. |
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
- 2026-08-15: **Phase 2 (D-5 audit event taxonomy) complete.** All 4 tasks implemented via subagent-driven development (implementer + spec review + code quality review per task). Tasks 2.1-2.4 added: `source`/`scope`/`persisted` fields on CONNECT events with `SOURCES` taxonomy const and `deny_source` helper; reserved `secret.inject` schema (doc comment + const, no emission); `--audit-strict` flag with `AuditWriter::open`/`append` returning `Result` (strict mode propagates open/SESSION_START failures, CONNECT events remain best-effort via `let _ =` in proxy); `source`/`scope`/`persisted` filter keys with boolean handling for `persisted` and case-sensitive matching for `source`/`scope`. 14 new tests (5+1+2+6). 118 Rust tests pass (104 baseline + 14 new). `cargo build --release` and `cargo clippy --release --all-targets`: 0 new warnings (1 pre-existing in `allowlist.rs:250`). Final holistic review: Phase 2 is coherent, cross-task integration verified (field names match filter keys, Result signatures ripple correctly, strict-mode semantics correct). Checkpoint 2 manual items pending (audit show with source/scope/persisted fields; filter `source=allowlist`; `--audit-strict` normal start).
- 2026-08-15: **Checkpoint 2 approved.** Verified in elevated shell (loopback exemption registered): (1) `curl --ssl-no-revoke https://api.anthropic.com/v1/messages` returns `405` (connection works — `--ssl-no-revoke` required because Schannel's CRL/OCSP fetch is outside the allow-list); (2) `audit show --json` shows CONNECT event with `"source":"allowlist","scope":null,"persisted":false`; (3) `audit show --filter "source=allowlist"` narrows correctly (1 CONNECT, SESSION_START filtered out); (4) `--audit-strict` session starts normally (log writable). Note: the uncommitted ACL-hang fix in `allowlist.rs` (see 2026-08-15 entry above) still needs to be committed — Checkpoint 1 manual item 2 (`--block-net` regression) passed once that fix is in place.
- 2026-09-16: **Phase 3 resumed.** Tasks 3.1-3.3 found complete in git log but unrecorded here (commits 2e03260+a51beb1, a15d55a+0278fed, 4c14769+f396527); PROGRESS.md rows updated retroactively. Baseline re-verified before task 3.4: `cargo test` → 155 passed, 0 failed. Task 3.4 (intent registry) in progress.
- 2026-09-19: **Rebased onto trunk `9970ef4`** (crash-safe DACL journal: journal-before-apply, teardown restore, orphan recovery, kernel-handle `apply_dacl_kernel`). All 24 branch commits rebased with `-Xignore-space-change`; conflicts resolved in 5 (`allowlist.rs`/`appcontainer.rs` cosmetics → took trunk, identical semantics; `main.rs` → took branch `resolve_network` signature with `deny_domain`/`no_prompt`; `PROGRESS.md` → took branch Phase-2 rows). Post-rebase verification: `cargo build --release` 0 warnings, `cargo test` → 158 passed (155 baseline + 3 journal), `cargo clippy --release --all-targets` clean, harness total=74 pass=51 fail=4 skip=19 → SANDBOX: PASS (4 fails pre-existing: python Store-alias S-9/S-19/S-26 + S-37 loopback needs elevation). Cleanup after an aborted harness run: 74 stale session ACEs removed from the `.worktrees\adr-0001-network` chain, 4 orphaned journal files (dead owner PIDs) deleted from `%LOCALAPPDATA%\sandbox\dacl-restore`. Operational note: `icacls /findsid`/`/remove` cannot match our kernel-written session ACEs — use `tests\cleanup-session-aces.ps1` (.NET `Set-Acl`) for manual cleanup.
- 2026-09-19: **Task 1.7 complete (commit b54977f + progress commit).** Bidirectional ingress warning added per MXC F-A: extracted the network-posture report block in `setup.rs` into `network_report_lines(build)` (unit-testable) and added a new unconditional `WARNING (inbound surface)` line documenting that `privateNetworkClientServer` is bidirectional — a listening sandboxed process can accept connections from LAN peers (MXC rejects ingress-allow policies on its AppContainer tier, `appcontainer_runner.rs:1747`). ADR-0001 amended in both places (D-0 bullet + Negative consequences). TDD: 2 new unit tests in `setup.rs` watched failing first (E0425 `cannot find function network_report_lines`). Verification: `cargo test --release` → 160 passed (158 baseline + 2 new), `cargo clippy --release --all-targets` clean, `cargo run --release -- setup --check-only` prints the new inbound WARNING line. Preceding chore commit `5477369` fixed two pre-existing clippy 1.98 lints (`chunks_exact`→`as_chunks` in `setup.rs`, `sort_by`→`sort_by_key` in `main.rs`) to satisfy the zero-warnings policy; 158 tests pass there too.
- 2026-10-17: **Task 3.4 complete (commit b19ff63 + this progress commit).** Intent registry in `src/net/intent.rs`: `IntentRegistry` with TTL expiry (lazy purge on lookup + background std-thread sweeper at TTL/2, condvar-parked so `close()`/`Drop` wake + join it promptly; `new()`/`close()` stay sync because D-3.6 constructs the registry in the supervisor before the proxy runtime exists), target normalization (URL / `host:port` / `[v6]:port` / userinfo / trailing dot → lowercase bare host; empty port treated as no port), one-shot explain-more flags (separate set independent of intent entries; pending set bounded at 500 — implementation bound, not ADR-mandated), 500-entry cap with deterministic seq-based oldest-record eviction, char-based 500-char reason truncation. All data ops `async` behind `tokio::sync::Mutex` (D-3.6 callers are async proxy handlers; `blocking_lock` would panic in their runtime). 25 new tests (strict TDD red-first); `cargo test` → 185 passed (160 baseline + 25), `cargo build --release` + `cargo clippy --release --all-targets` 0 warnings, intent.rs rustfmt-clean. Spec + quality reviews passed (0 blocking; reviews flagged the empty-port normalization corner — fixed with TDD). D-3.6 wiring notes: share as `Arc<IntentRegistry>` (Drop joins the sweeper, no explicit close path needed); `Entry.ts` is `SystemTime` and the GET `/sandbox/intent` response needs an RFC3339-style formatter (do NOT `format!("{:?}", ts)`); consider logging explain-mark drops beyond the 500 pending cap.
