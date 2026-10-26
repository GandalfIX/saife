# Code scanning (CodeQL) triage — SAIFE Sandbox

> **For Hermes:** use subagent-driven-development to implement this plan task-by-task.
> A task is not "done" until its exit criterion has been *observed* (alert state
> read back from the API), not assumed.

> **Status: PLAN ONLY, 2026-10-26.** Nothing was executed: no alert dismissed, no
> code changed, no commit. The findings below were read from the live API
> (`code-scanning/alerts?state=open`) at HEAD `83e7a00` (v0.3.1).

**Goal:** take the 15 open CodeQL alerts on `GandalfIX/saife` from "unknown noise"
to a defensible state: the four with a real (if small) mechanism fixed in code,
the eleven that are test-only, intentional or provably false dismissed with a
written reason — and a triage rule in `docs/DEVELOPERS.md` so the next batch is
cheap.

**Approach:** fix first, dismiss second, document third. Fixing before dismissing
is what lets the rescan *prove* the fixes (CodeQL closes them as `fixed`, not
`dismissed`) and keeps the dismissal list honest. Do not switch analysis setup,
do not add a paths filter, do not change the query suite.

**Tech stack:** CodeQL (GitHub **default setup**, Rust in preview), `gh` CLI 2.x,
Rust 2024 crate `saife` (bin-only, `cargo test --bin saife`).

---

## 1. Where we are (measured 2026-10-26 12:15 CEST)

| Fact | Value |
|---|---|
| Analysis setup | **default setup**, `state: configured` |
| Languages | `actions`, `python`, `rust` |
| Query suite / threat model | `default` / `remote` |
| Schedule | `weekly`, plus the default push/PR triggers |
| Config file | **none** — no `.github/workflows/codeql.yml`, so no `paths`/`paths-ignore`, no query filters |
| Repo | **public** — the alerts below are publicly visible |
| Open alerts | **15** — 4 critical, 11 high, all `rust/*`, all created 2026-10-25 (first scan) |
| `gh` | `C:/Program Files/GitHub CLI/gh.exe` (not on PATH of this bash), logged in as `GandalfIX` |
| Token scopes | `admin:public_key`, `gist`, `read:org`, `repo` — **no `security_events`**, so dismissal *writes* will 403 until the token is refreshed |
| Test baselines | `cargo test --bin saife`: 673 + 15 ignored; `--no-default-features`: 542; `saife-launch`: 19 |

Two consequences of "default setup, no config file": we cannot exclude test paths
from the analysis (Option B in §6), and a dismissal is **per alert**, not per rule
— the same query firing on new code still opens a new alert. That second point is
what makes dismissal safe here.

## 2. The findings, evaluated

Eleven of the fifteen are in code that never ships: `src/net/mxc/live.rs` is
`#[cfg(test)] mod live;` (declared at `src/net/mxc.rs:3058`), `src/tests.rs` is
`#[cfg(test)] mod tests;` (`src/main.rs:1575`), `src/sandbox/appcontainer.rs:1238`
sits inside `mod propagation_tests` (`#[cfg(test)]`, line 1166), and
`tests/vm/spikes/mxc-ga-spike` is a spike crate. `#[cfg(test)] mod live;` means
the four *critical* findings are not compiled into `saife.exe` at all.

| # | Sev | Rule | Location | What it actually is | Verdict | Action |
|---|---|---|---|---|---|---|
| 12 | critical | hard-coded-cryptographic-value | `src/net/mxc/live.rs:391` | `const NONCE: &str = "nonce-p1-wave-2"` — a **body marker** both live legs search for in a proxy response, so a `200` from anything else cannot pass | Not a nonce, not a key, test-only, `#[ignore]` live leg | Dismiss **used in tests** |
| 13 | critical | hard-coded-cryptographic-value | `src/net/mxc/live.rs:1644` | `Endpoint::start("nonce-p1-wave-1")` — same class, one constant per leg | Same | Dismiss **used in tests** |
| 14 | critical | hard-coded-cryptographic-value | `src/net/mxc/live.rs:2734` | `Origin::start_with_nonce("p14-origin-run-a")` — deliberately distinct from run B so a crossed body fails | Same | Dismiss **used in tests** |
| 15 | critical | hard-coded-cryptographic-value | `src/net/mxc/live.rs:2735` | `Origin::start_with_nonce("p14-origin-run-b")` | Same | Dismiss **used in tests** |
| 1 | high | access-invalid-pointer | `src/sandbox/appcontainer.rs:1238` | `let hdr = &*(ace as *const ACE_HEADER)` — the ACE pointer from `GetAce` is dereferenced with **no null guard**, and Mask/SID are read with `.add(4)`/`.add(8)` byte arithmetic | No reachable bug (`GetAce` only sets a valid pointer on success, and `AceType` is filtered before the offset reads), but the code as written *does* deref a pointer it has not proven non-null — query is literally right | **Fix** (C3) |
| 4 | high | cleartext-logging | `src/net/proxy/tests.rs:5505` | `assert!(!resp.contains(secret), "body leaked {secret:?}: {resp}")` — a negative assertion whose **failure message echoes the credential and the body that leaked it** | Real (tiny) defect: the leak-detection test's own panic logs the leak. Fake credentials, test-only | **Fix** (C2) |
| 5 | high | cleartext-logging | `src/tests.rs:889` | Same shape over `["s3cret", "hunter2", "alice", "bob"]` | Same | **Fix** (C2) |
| 6 | high | cleartext-logging | `src/tests.rs:917` | Same shape over `["alice", "s3cret", "profile-proxy:8443"]` | Same | **Fix** (C2) |
| 2 | high | cleartext-logging | `src/audit/verify.rs:385` | `assert!(m.contains("belongs to session"), "...: {m}")` — the verdict string names the session it examined | Session id is the diagnostic the test exists to check; test-only | Dismiss **used in tests** |
| 3 | high | cleartext-logging | `src/audit/verify.rs:417` | same shape, `seq`/`parent` verdict | Same | Dismiss **used in tests** |
| 7 | high | cleartext-logging | `src/audit/show.rs:62` | `println!("Session {session_id}")` — the operator-facing summary header of `saife audit show` | Intentional CLI output; session id is an identifier, not a credential (§3) | Dismiss **won't fix** |
| 8 | high | cleartext-logging | `src/audit/verify.rs:17` | `println!("TAMPERED: {reason}")` — the verdict names the session whose chain failed | Intentional; same reason | Dismiss **won't fix** |
| 9 | high | cleartext-logging | `src/main.rs:683` | `println!("{sid}")` under `if print_sid` — the AppContainer half of `--print-sid` | Documented interface: the operator *asks* for the id, scripts capture it | Dismiss **won't fix** |
| 10 | high | cleartext-logging | `src/main.rs:873` | same, MXC half (Decision 7 parity) | Same | Dismiss **won't fix** |
| 11 | high | cleartext-logging | `tests/vm/spikes/mxc-ga-spike/src/bin/workload.rs:94-98` | prints `added`, `roots.len()`, `loaded.errors.len()` — **three `usize`s**; no certificate, no key, no secret | False positive: the query treats the cert-load result as a secret and the `println!` as the sink | Dismiss **false positive** |

## 3. Why the session-id alerts are not the credential exposure `SECURITY.md` names

`SECURITY.md` puts "a token or secret … written into the audit, a log, or an
error message" in scope, so this had to be answered rather than waved away:

- The **network credential** is the per-run `RunToken` (minted at launch, one live
  instance per process, never printed, audited only as a refusal counter). The
  session id is a different value on a different path.
- `new_session_id()` (`src/main.rs:1515-1530`) builds `YYYYMMDD-HHMMSS-NNNNN` from
  clock + pid: it is the **name** of the audit log, the DACL-journal run id, and
  the `.saife/<sid>` directory — an identifier that a reader selects on
  (`saife audit show <sid>`, `saife audit verify <sid>`).
- It authorises nothing. Knowing a session id grants no access the caller did not
  already have (the audit directory is user-scoped and the chain is signed).

**Recorded invariant (goes into docs, C5):** the session id must never become an
authorization token — no command may treat "knows the sid" as permission. It is
low-entropy by design (clock + counter), so it must stay a selector.

## 4. Decisions needed (answer before C2/C4)

**D1 — the four critical nonce findings: dismiss or refactor?**

- **A (recommended).** Dismiss all four as *used in tests* with the comment
  "test fixture body marker in a `#[cfg(test)]` live leg; not a cryptographic
  nonce and not compiled into the shipped binary". Cost: zero. Optics: four
  publicly visible *dismissed* criticals instead of four open ones.
- **B.** Rename `NONCE` → `BODY_MARKER` and derive per run
  (`format!("origin-a-{}", stamp())`), which removes the "hard-coded" premise and
  closes the alerts as `fixed`. Cost: edits four `#[ignore]` live legs, which then
  need a real re-run (`cargo build --features mxc-backend --bin saife` first, then
  `cargo test --features mxc-backend -- --ignored`, container + elevation
  depending on the leg) to prove nothing broke. Only worth it if you want zero
  critical dismissals.

**D2 — §6 Option B (advanced setup + `paths-ignore`): keep default setup?**
Recommendation: **keep default setup.** Excluding `**/tests.rs`, `src/net/mxc/live.rs`
and friends would also blind us to a *real* credential committed in a fixture, and
it costs a hand-maintained workflow for three languages. Revisit only if the alert
count per scan grows past ~10 again.

**D3 — `verify.rs` assert messages (#2/#3): dismiss, or redact like C2?**
Recommendation: **dismiss.** There the verdict string *is* the evidence the test
asserts on, and it carries an id we have established is not a credential.

## 5. Tasks

### C0 — Capture the baseline (read-only, ~5 min)

**Objective:** a snapshot you can diff the rescan against.

```bash
GH="/c/Program Files/GitHub CLI/gh.exe"
$GH api "repos/GandalfIX/saife/code-scanning/alerts?state=open&per_page=100" \
  > "$TMPDIR/saife-alerts-before.json"
$GH api "repos/GandalfIX/saife/code-scanning/alerts?state=open&per_page=100" \
  --jq '[.[] | {n: .number, sev: .rule.security_severity_level, rule: .rule.id, path: .most_recent_instance.location.path, line: .most_recent_instance.location.start_line}]'
```

**Expected:** 15 rows, `4 critical / 11 high`, matching §2 exactly. If the numbers
differ, re-derive §2 before continuing — the doc, not the memory, is the source.

### C1 — Give the token write access to code scanning (~2 min)

**Objective:** dismissal calls must not 403.

```bash
$GH auth refresh -h github.com -s security_events
$GH auth status   # expect security_events in the scopes line
```

**Note:** if you prefer not to widen the token, dismiss in the UI
(`Security → Code scanning → alert → Dismiss`) — same three reasons, same
comments. Do not paste comments ad hoc then; use the bank in C4.

### C2 — Stop the leak-detecting assertions from echoing what they detect (~15 min)

**Problem:** three negative assertions put the credential *and* the text that
leaked it into their panic message. The test proves "the warning is redacted" and
then, on failure, prints the unredacted warning into CI output. Test-only and fake
values, so impact ≈ 0 — but it is the exact class `SECURITY.md` calls in scope,
it is three lines, and fixing it closes #4/#5/#6 as `fixed` instead of dismissed.

**Files:**
- Modify: `src/tests.rs:888-890` and `src/tests.rs:916-918`
- Modify: `src/net/proxy/tests.rs:5504-5506`
- Test: same files (`#[cfg(test)] mod tests`)

**Step 1: write the red first (mutation, not new code).** Temporarily make the
warning echo the raw URLs — in `select_upstream` (`src/main.rs:361-366`) replace
`redact_proxy_url(p)` with `p` and `redact_proxy_url(h)` with `h` — then run:

```bash
cargo test --bin saife select_upstream_profile_over_env_warns_and_redacts
```
**Expected:** FAIL, message currently containing `s3cret` / `hunter2`. That failure
*is* the leak being demonstrated; keep the output for PROGRESS.

**Step 2: change the assertion messages** (with the mutation still in place, the
new message must pass the "red gone" check as well):

```rust
// src/tests.rs — select_upstream_profile_over_env_warns_and_redacts
for (i, secret) in ["s3cret", "hunter2", "alice", "bob"].iter().enumerate() {
    // The failure message must not carry the value it is asserting absent:
    // a redaction test that prints the credential fails the rule it tests.
    assert!(!warn.contains(secret), "warning leaked credential #{} (values withheld)", i + 1);
}

// src/tests.rs — upstream_parse_failure_warning_names_the_profile_source_without_credentials
for (i, secret) in ["alice", "s3cret", "profile-proxy:8443"].iter().enumerate() {
    assert!(!w.contains(secret), "warning leaked credential #{} (values withheld)", i + 1);
}

// src/net/proxy/tests.rs — the 502 body test
for (i, secret) in ["alice", "s3cret", "@"].iter().enumerate() {
    assert!(!resp.contains(secret), "body leaked credential #{} (values withheld)", i + 1);
}
```

**Step 3: run the same three tests with the mutation still in place.**

```bash
cargo test --bin saife select_upstream_profile_over_env_warns_and_redacts
cargo test --bin saife upstream_parse_failure
cargo test --bin saife upstream_unreachable_returns_502_with_upstream_error_header
```
**Expected:** FAIL as before, message now `warning leaked credential #1 (values
withheld)` — no `s3cret`, no `hunter2`, no URL. That is the red that proves C2.

**Step 4: restore the redaction** (`git diff` must show only the three assertion
loops), then green:

```bash
git diff --stat            # 2 files, ~6 lines
cargo test --bin saife     # 673 passed, 15 ignored
cargo test --bin saife --no-default-features   # 542 passed
```

**Step 5: commit.**

```bash
git add src/tests.rs src/net/proxy/tests.rs
git commit -m "test: redact the values a leak assertion proves absent"
```

### C3 — Harden the DACL walker's ACE dereference (~30 min)

**Problem:** `trustee_ace_flags` (`src/sandbox/appcontainer.rs:1207-1252`) walks the
raw ACL with `GetAce` and then does `&*(ace as *const ACE_HEADER)` on the returned
pointer, reading Mask at `+4` and the SID at `+8` with byte arithmetic. No bug is
reachable today (the pointer is valid on `GetAce` success; `AceType` is filtered to
allow/deny before the offset reads), but "unchecked pointer + magic offsets" is
both what the query reports and what the *next* editor breaks.

**Files:**
- Modify: `src/sandbox/appcontainer.rs` — add a `#[repr(C)] struct StdAce` above
  `trustee_ace_flags`, rewrite the loop body at 1233-1246
- Test: the same module's DACL propagation tests (`mod propagation_tests`)

**Step 1: run the tests that use the helper first (green before, so a later red is yours).**

```bash
cargo test --bin saife propagation
```
**Expected:** PASS. Note the count — it becomes the "still green" number.

**Step 2: typed layout + null guard.**

```rust
/// A standard (non-object) ACE: `ACE_HEADER` is 4 bytes, then `Mask`, then the
/// SID. `ACCESS_ALLOWED_ACE` and `ACCESS_DENIED_ACE` share this layout; the
/// `AceType` filter below is what makes that true.
#[repr(C)]
struct StdAce {
    header: ACE_HEADER,
    mask: u32,
    sid_start: [u8; 4],
}

// ... inside the AceCount loop:
if GetAce(dacl, i, &mut ace).is_err() || ace.is_null() {
    continue;
}
let a = &*(ace as *const StdAce);
if a.header.AceType != ACE_TYPE_ALLOWED && a.header.AceType != ACE_TYPE_DENIED {
    continue;
}
if EqualSid(*sid, PSID(a.sid_start.as_ptr() as *mut _)).is_ok() {
    out.push((a.mask, a.header.AceFlags));
}
```

**Step 3: green + gates.**

```bash
cargo test --bin saife propagation
cargo test --bin saife                          # 673 + 15 ignored
cargo test --bin saife --no-default-features    # 542
cargo clippy --release --all-targets            # 0 warnings
```
**Expected:** identical counts to Step 1, clippy silent.

**Step 4: commit.**

```bash
git add src/sandbox/appcontainer.rs
git commit -m "test(appcontainer): null-guard the GetAce pointer and read ACE fields by type"
```

### C4 — Dismiss the eleven, with the reason on the record (~15 min)

**Order:** only after C2 and C3 are committed and pushed — otherwise a "fixed"
alert cannot be told apart from a dismissed one.

```bash
GH="/c/Program Files/GitHub CLI/gh.exe"
dismiss() { # n reason comment
  $GH api -X PATCH "repos/GandalfIX/saife/code-scanning/alerts/$1" \
    -f state=dismissed -f dismissed_reason="$2" -f dismissed_comment="$3" \
    --jq '{n: .number, state, reason: .dismissed_reason}'
}
```

**Comment bank** (use verbatim; keep each ≤ 280 chars):

| # | reason | comment |
|---|---|---|
| 12,13,14,15 | `used in tests` | `Test fixture body marker in the #[cfg(test)] live leg (src/net/mxc/live.rs, declared at src/net/mxc.rs:3058). Not a cryptographic nonce or key, and not compiled into the shipped binary.` |
| 2,3 | `used in tests` | `Test-only assertion message. The verdict string names the session under test; the session id is a selector, not a credential (see docs/DEVELOPERS.md 3.5).` |
| 7 | `won't fix` | `Intentional operator-facing output: "saife audit show" names the session it summarises. The session id is a selector, not a credential; the network credential is the per-run RunToken, which is never printed.` |
| 8 | `won't fix` | `Intentional diagnostic: the verify verdict names the session whose chain failed. Session id is a selector, not a credential (docs/DEVELOPERS.md 3.5).` |
| 9,10 | `won't fix` | `Intentional documented interface: --print-sid prints the id to stdout so a script can capture it. Session id is a selector, not a credential; the per-run RunToken is never printed.` |
| 11 | `false positive` | `Logs three usize counts (certs added / store size / error count). No certificate, key or secret reaches the log. Spike crate under tests/vm/spikes, kept as reproducible evidence.` |

**Step: read every one back.**

```bash
$GH api "repos/GandalfIX/saife/code-scanning/alerts?state=dismissed&per_page=100" \
  --jq '[.[] | {n: .number, reason: .dismissed_reason, comment: .dismissed_comment}] | length'
```
**Expected:** 4 nonces + 2 verify asserts + 2 print-sid + 1 show + 1 verify + 1
spike = **11**, each with the comment above.

### C5 — Write the triage rule down (~20 min)

**Files:**
- Modify: `docs/DEVELOPERS.md` §3.5 "Audit model" — one paragraph: session id is a
  selector, never a credential; no command may gate on knowing it.
- Modify: `docs/DEVELOPERS.md` §4 "Build and test" — new subsection
  `### Code scanning (CodeQL)` after the gates paragraph: default setup facts
  (languages, suite, weekly + push, no config file → no path filters), alert URL,
  the credential test (`is it needed to obtain access the caller did not already
  have?` → no ⇒ selector), the `gh` read/dismiss commands from C0/C4, and the two
  standing rules: *fix before dismissing*, and *dismiss per alert with a reason —
  never argue for a rule's removal*.
- Modify: `docs/tasks/codeql-triage/PROGRESS.md` — rows + Event Log for C0-C6.

**Verify:** every command in the new subsection must be executed verbatim before
committing (`gh api` read + the `--jq` shapes), and `docs/DEVELOPERS.md` must not
claim a config file exists.

```bash
git add docs/DEVELOPERS.md docs/tasks/codeql-triage/PROGRESS.md
git commit -m "docs: record the CodeQL triage rule and where the alerts live"
```

### C6 — Prove the end state from the API (~10 min + rescan wait)

**Objective:** the numbers, not a screenshot.

```bash
$GH api "repos/GandalfIX/saife/code-scanning/alerts?state=open&per_page=100"   --jq 'length'
$GH api "repos/GandalfIX/saife/code-scanning/alerts?state=dismissed&per_page=100" --jq 'length'
$GH api "repos/GandalfIX/saife/code-scanning/alerts?state=fixed&per_page=100" --jq '[.[].number]'
$GH api "repos/GandalfIX/saife/code-scanning/analyses?per_page=1" --jq '.[0] | {commit_sha, created_at, results_count}'
```

**Expected:** `open = 0`; `dismissed = 11`; `fixed` contains `1, 4, 5, 6`; the
newest analysis is on the fix commit and postdates C4. A scan takes a few minutes
after the push — poll, do not assume. If a CV-fix alert comes back `open`, the fix
did not land where CodeQL looks: re-read the alert's `most_recent_instance` lines
against the current source before re-dismissing anything (never dismiss a
regression as noise).

## 6. Options considered and rejected for now

- **A. Dismiss everything, including #1/#4/#5/#6** — cheapest, but it throws away
  three genuinely improvable lines and leaves "critical, open, public" optics on
  the four nonces with a blanket excuse. Rejected: fix first.
- **B. Advanced setup + `.github/codeql/codeql-config.yml` with
  `paths-ignore: ['tests/**', '**/tests.rs', 'src/net/mxc/live.rs']`.** Would make
  eleven alerts vanish without a decision. Rejected for now: it hides real
  credentials committed in fixtures, needs a maintained workflow for three
  languages, and replaces default setup's automatic updates. (Rust *is* listed as
  supporting `paths-ignore`, so this stays available if the noise returns.)
- **C. `security-extended` query suite** — more findings, not fewer. Not now.
- **D. Inline suppression comments** — no Rust support in code scanning; per-alert
  dismissal is the mechanism. Do not sprinkle `allow` attributes hoping the
  analyzer reads them.

## 7. Open questions

1. **D1:** dismiss the four test nonces (recommended), or refactor them to
   per-run markers and re-run the ignored live lane to close them as `fixed`?
2. **C4 the two `verify.rs` asserts (#2/#3):** dismiss (recommended) or redact like
   C2 — accepting that the assertion then reports "a verdict mismatch" without
   naming the session, which makes a failure harder to diagnose?
3. **C1:** widen the `gh` token with `security_events`, or dismiss the eleven by
   hand in the UI (no token change, more clicks, easier to drift from the comment
   bank)?

## 8. Risks

- **Dismissals are public.** Eleven dismissed alerts on a public security-focused
  repo invite "they turned the alarm off". Mitigation: C5's written rule, the
  comment bank, and fixing #1/#4/#5/#6 rather than dismissing them.
- **Dismissal is per alert, not per rule** — a *new* credential leak in test code
  still opens a new alert, so C2's pre-existing dismissals do not mask the future.
  Say this in the docs so nobody "cleans up" by disabling the query.
- **Rust CodeQL is preview**: query sets and severities can move under us; an
  alert that reappears after a suite update is a decision to re-make, not a bug.
- **C3 touches a `#[cfg(test)]` DACL helper that runs real Win32 calls**: the
  failure mode is a test helper reading the wrong offsets, which would make
  propagation assertions pass or fail for the wrong reason. Mitigation: keep the
  `AceType` filter *before* any offset read (as today), and treat the propagation
  count changing at all as a stop-and-look.
- **C4 before C2/C3** would bake "dismissed" into the record for code that is about
  to be fixed — order matters more than speed here.
