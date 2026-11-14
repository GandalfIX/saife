# Mutation-testing triage: what the evidence says and what we do about it

Status: **re-baselined on `main`; first fixes landed on `test/mutant-gaps`**
(branch only, no PR).

## Correction: the first evidence was stale

The 461-survivor figure came from a tree (`06b9d43`, branch
`chore/teardown-scenarios`) that is 7 commits behind `main`. A fresh baseline on
current `main` for the same lane (profile.rs + net glue, 106 mutants) gives
**54 caught, 50 unviable, 1 missed, 1 timeout** - the 0.6.0 suite already kills
almost all of it. Consequences for this document:

- the old per-file counts below are kept only as a **hunting map**, not as truth;
- every fix is proven by a scoped run on `main`, never by the old list;
- the parallel-lane baseline run that produced "timeouts" of 3 hours did so under
  four concurrent mutant runs on one CPU: **run mutation baselines sequentially**,
  or timeouts become noise.

Fresh, main-based baselines are running (audit subtree + proxy, one process) and
overwrite this section when they finish.

## Survivors fixed on this branch

Proven on the branch itself with scoped `--iterate` runs (the audit proof run
went **10 missed -> 6 caught + 4 excluded = 0 missed**):

| Mutation (proven by scoped run only after the baseline completes) | Fix |
|---|---|
| `audit/mod.rs` iso8601 date arithmetic + `-> "xyzzy"` | `iso8601_utc` split into clock-free `iso8601_from_unix`; known-value test (epoch edges, leap days incl. the 2000 century one) |
| `civil_from_days` arithmetic, incl. the negative-era branch | table extended: pre-epoch, era boundary, non-leap century, month rollovers, ISO-year-0 leap day |
| `AuditWriter::open_at` `seq > 0` -> `>=` | test: a NEW chain (`seq == 0`) must keep a stale `<sid>.root`; H5b only drops it for a continuation |
| `open_at` NotFound tolerance (3 mutants) | a continuation WITHOUT a root pair opens; a stale pair that is a DIRECTORY refuses a strict continuation |
| `Filter::parse` `idx + 1` -> `idx - 1` | test: `req_id=7` matches the number 7 (not `"=7"`) |
| `ordered_match` `Op::Lte` arms / `!=` boundary | test: `<=`/`>=` include equality for `ts` and integers |
| `show_profile_inner` `retain(!allow)` delete | step extracted as `drop_readonly_duplicated_by_allow`; test: an allow-listed group grant disappears from `read_only` |
| `render_summary` deny split, two denial shapes, half-committed pair | counted split (2 allowed + 1 denied breaks the symmetric false-green), CONNECT vs fs denial rendering, root-without-signature is ABSENT/NOT COMMITTED |
| `truncate_for_error`, `run_show`/`run_verify` exit codes, `holder_is_alive` created==0, `validate_session_id` length boundary, `session_start` accessors | each pinned to its observable contract |
| `net/proxy.rs` `rfc3339_utc` date arithmetic | the duplicate civil-date algorithm DELETED: `rfc3339_utc` now calls `crate::audit::civil_from_days` (one implementation, two callers) |
| `percent_decode` grammar (~25 mutants) | table: both hex cases, `%2b` vs `+`, truncated/non-hex/dangling escapes verbatim, adjacent escapes |
| `parse_connect_target` / `split_authority` refusals | bad port, port 0, overflow, empty host, userinfo, unbracketed IPv6 |
| `find_head_end` (was a TIMEOUT), `head_framing_error`, `head_lines`, `relayed_response_head` | framing table: offset past CRLFCRLF, bare CR/LF, obs-fold, CRLF-only split, status line kept while proxy-hop fields are stripped |
| `interleave_families` `||` -> `&&` | **exclusion (equivalent)**, documented in `.cargo/mutants.toml` |

Exclusion register (`.cargo/mutants.toml`), every entry with a written reason:
clock-free wrapper, cwd-isolated branch, non-183 lock error, stderr-only
warning, the interleave equivalence.

## The evidence and its limits

- `cargo mutants` ran in the **main checkout on branch `chore/teardown-scenarios`**
  (tree `06b9d43` + one uncommitted `dacl_journal.rs` edit). That tree is **not**
  `origin/main`: `main` has 7 newer commits and `profile.rs` alone differs by
  ~850 lines. The survivor list is therefore a **hypothesis**, not a verdict;
  every lane below re-baselines against current `main` with a fresh scoped run.
- The run evaluated **478 of ~1,300 mutants** and was stopped partway
  (`runner/docker.rs`, `sandbox/*` were never reached).
- The per-mutant logs prove the harness was sound: the full test suite
  (921 tests on that tree) ran against every mutant, and the baseline passed.
  The survivors are **real assertion gaps**, not tooling failure.
- Headline numbers on the evaluated subset: **461 missed (96%), 1 caught,
  16 timeouts**.

## Classification of the 461 survivors + 16 timeouts

| Class | missed | timeout | Decision |
|---|---|---|---|
| pure logic, no test asserts it | 393 | 16 | **tests** — highest-value first: CONNECT/URL parsing, path canonicalisation, audit timestamps, session budget |
| OS/FFI-bound (DPAPI, drive grants, elevation, env probes) | 35 | 0 | **exclude with written reason** — unit tests cannot create the OS state; the VM/host lanes cover these |
| GUI (TaskDialog, toast, warn-once) | 16 | 0 | **exclude with written reason** — no dialog backend in unit tests |
| CLI dispatch wrappers (`*_cmd`, `run_show`, `run_verify`, `main`) | 10 | 0 | **tests where cheap** (call the function with args, assert exit code); remainder documented |
| `fmt`/`Display`/`Debug` impls | 4 | 0 | **tests** for error-message surfaces (product contract: "informative refusals"), exclude the cosmetic rest |
| `Drop`/`close`/lifecycle | 3 | 0 | **exclude with written reason** — resource release is unobservable in unit tests |
| timeouts (mutation makes the suite hang) | — | 16 | **manual look** — a hang mutant often marks a real unbounded-loop condition near that code |

Largest single files in the evaluated set: `net/proxy.rs` (87), `main.rs` (56),
`profile.rs` (56), `setup.rs` (40), `bin/dirprobe.rs` (32), `audit/mod.rs` (32),
`net/mxc.rs` (29), `net/prompt.rs` (24).

## Policy decided

1. **No new dependency for annotations.** `#[mutants::skip]` would require the
   `mutants` crate as a dependency — rejected for supply-chain reasons. Exclusions
   live in `.cargo/mutants.toml` via `exclude_re` (mutant-name regex) /
   `exclude_globs`, one written reason per entry. The file is the single
   exception register; without a reason, an exclusion is rejected in review.
2. **Tests assert observable behaviour**, never mirror the implementation. Every
   new test must be proven to kill its mutant by a scoped `cargo mutants --file
   <file>` run on the branch, not by reading the code.
3. **Exclusions are for mutants a unit test cannot observe** (needs elevation, a
   real container, a dialog backend, or a resource to leak). Everything else
   either gets a test or stays on the books as named debt in the per-lane
   reports — silently dropping a survivor is forbidden.
4. **Timeouts are manual cases**: a mutation that hangs the suite often marks a
   real unbounded path (e.g. `find_head_end` in the HTTP head parser). Each gets
   looked at, not auto-excluded.
5. **Per-module campaigns**, not one big-bang: the register keeps the gate
   honest per file; each follow-up PR raises one module's kill rate and moves
   its remainder into the register or the debt list.

## Work split (four lanes, disjoint files, each on its own branch off `main`)

| Lane | Files | Branch |
|---|---|---|
| audit + signing + security_groups + cli | `src/audit/**`, `src/signing.rs`, `src/security_groups.rs`, `src/cli.rs` | `test/mutant-audit` |
| profile + net glue | `src/profile.rs`, `src/net/{mod,learned,intent,upstream,mxc}.rs` | `test/mutant-net` |
| proxy parsers | `src/net/proxy.rs` (+ its test module) | `test/mutant-proxy` |
| orchestration + CLI + bins | `src/main.rs` + `src/tests.rs`, `src/bin/*`, `src/setup.rs`, `src/backend/*`, `src/plugin/mod.rs`, `src/net/prompt.rs`, `src/runner/mod.rs` | `test/mutant-orchestration` |

Each lane: re-baseline survivors on current `main` → write tests / propose
exclusions → prove kills → report per-file before/after counts.

## What lands on `test/mutant-gaps`

- this document (updated with the lanes' final numbers),
- `.cargo/mutants.toml` exclusion register (assembled from the lanes' verified
  candidates),
- the lanes' test commits, merged in,
- gates: both feature states green, clippy 0, `cargo deny`/`cargo shear` green,
  and a fresh full-run kill-rate comparison on the branch as the closing
  measurement.

## Proxy lane: named debt (batch 2 close-out, 2026-11-11)

Scoped `--iterate` over `src/net/proxy.rs`: 320 tested, 266 caught, 19 unviable.
Remaining, each inspected (testable mutants never go in the register):

- **`find_head_end -> None` and the loop-arithmetic timeouts** (`+=` -> `*=` in
  `percent_decode`, `head_framing_error`, `head_lines`, `handle_conn`): the
  `*= 2` from zero arms hang forever. Product finding, not a test gap: those
  scanners have no iteration bound, so a mutant can turn a bounded scan into an
  unbounded one. Candidate hardening: an iteration/byte cap in the scan loops.
- **`read_body` cap comparisons** (`body.len() < want` variants): needs a body
  at the exact cap through a socket pair; the socket fixtures exist, the test
  is just timing-shaped. Next batch.
- **`read_upstream_head` `&&`/`<` variants**: same shape - reads past the head
  only differ on a socket that sends a partial head and stalls.
- **`handle_forward` content-length `>` -> `>=`**: boundary body at exactly
  `MAX_FACADE_BODY`; heavy async fixture.
- **`handle_non_connect` absolute-form `&&` -> `||`**: origin-form request must
  survive the widened check; covered end-to-end only through the listener.
- **`MAX_FACADE_RESPONSE_HEAD` / `RELAY_HEAD_TIMEOUT` constants**: observable
  only by driving a >64 KiB sidecar head through the relay; clippy rejects
  constant-vs-constant assertions (`assertions_on_constants`), so a pin would
  be noise. Left as documented values.

Register additions this batch (12 patterns total): intent object guards
(subsumed by field validation), warn-once (stderr), `LaunchResetHook` Debug
elision, `LiveTokenClaim::drop` / `ProxyHandle::shutdown` (lifecycle),
`system_lookup` (OS resolver), and two argued equivalences
(`parse_connect_target` bracket flag, `relayed_response_head` status-line
index).

## Proxy lane: closed (2026-11-11)

Closing scoped proof (cargo mutants --file src/net/proxy.rs --iterate):
**17 tested, 7 missed, 9 timeouts, 1 unviable**; 1335 previously caught or
unviable mutants were skipped by the iteration. Every survivor is in the debt
list above or the register: 82 survivors + 6 timeouts at campaign start ->
7 misses + 9 argued hang-mutants.

Note: --iterate makes successive scoped runs cheap (it skips caught/unviable),
but a mutants run killed mid-flight has no resume point - outcomes.json stops
at the last finished mutant (end_time: null); re-running --iterate picks up.

## setup lane (2026-11-11)

Baseline: 51 mutants, 40 missed - all one class (functions whose input is the
live Windows host). Two decision cores extracted and tested (build_supported,
parse_current_build); 11 register patterns with per-function reasons.

Round-trip test added: a_read_attributes_grant_round_trips_on_an_owned_directory
creates a tempo directory, grants FILE_READ_ATTRIBUTES to the app-package SID,
reads the ACE back, re-grants (idempotence) and cleans up. It runs
unprivileged and kills the trustee-pointer deletion (delete ptstrName), so the
grant_read_attributes / check_root_has_grant register entries are gone.

Two survivors are TOOL-LIMITED, not test-limited:
- delete field TrusteeForm / delete field TrusteeType in the TRUSTEE_W literal.
  cargo-mutants 27.1.0 does NOT apply --re/--exclude-re to struct-field
  deletion mutants (upstream bug; fixed only in Unreleased). Both fields
  refill from ..Default::default() to values the ACL API treats identically at
  the only call site, so no test distinguishes them.
  Close by: bump cargo-mutants when the fix releases, then add an exclude_re
  entry; or add the mutants dev-dependency and mark the literal
  #[cfg_attr(test, mutants::skip)].

## prompt lane (2026-11-11)

Baseline: 118 tested, 18 missed, 7 timeouts, 56 caught, 37 unviable. Closing
proof: **1 missed, 4 caught, 0 timeouts** (95 caught/unviable skipped).

The lane taught the campaign's most transferable lesson: a TIMEOUT verdict is
usually a TEST-INFRASTRUCTURE property, not a product property. Two hang
sources had to go before the divergence mutants could fail:

1. Unbounded outcome awaits in tests (19 sites now through a bounded helper).
2. Per-item bounds SUMMED in loop tests (eight leaders, follower batches,
   futures_of): each collection takes ONE bound now.
3. Test configs inherited the production 60 s prompt timeout: a mutant that
   breaks the flow before the dialog is consulted waited the whole term
   (60 s) before failing - longer than the 49 s suite cap. Sixteen test
   configs use 2 s.

With those fixed, the four latch/coordinator divergence mutants
(ArmingCause::of, observe, plan, finish) are caught by direct tests.

Residue:
- MAX_ABANDONED_PROMPTS = 2 * MAX_CONCURRENT_PROMPTS: constant value, pinned
  as a documented value (same treatment as the proxy relay constants).
- Register: dialog/toast layer (TaskDialog HRESULT handling, flags, COM
  apartment incl. RPC_E_CHANGED_MODE), and the equivalent ID_DENY_ONCE arm.
