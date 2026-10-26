# Code scanning (CodeQL) triage — progress

Plan: [2026-10-26-codeql-triage.md](../../plans/2026-10-26-codeql-triage.md)
Analyser: GitHub CodeQL, **default setup** (languages `actions`/`python`/`rust`,
suite `default`, threat model `remote`, weekly + push). No workflow file, so no
path filters.
Baseline re-read on `71f8ab8`, after a concurrent session merged `#15`-`#19` while
the plan was being written: **15 open alerts — 4 critical, 11 high**, all `rust/*`,
all created 2026-10-25, same 15 (path:line) pairs as the plan.

Status legend: `[ ]` not started · `[~]` in progress · `[x]` done and gated · `[!]` blocked

## Rows

| # | Task | Status | Evidence |
|---|---|---|---|
| C0 | Capture the open-alert baseline (ids, rule, path, line) | [x] | 15 open, `{critical: 4, high: 11}`, same 15 (path:line) pairs as the plan. |
| C1 | Give the `gh` token `security_events` (or decide to dismiss in the UI) | [ ] | |
| C2 | Redact the three leak assertions (#4, #5, #6); mutation-red proves the leak | [x] | `4475426`. RED first: `warning leaked "s3cret": profile network.upstreamProxy (http://alice:s3cret@profile-proxy:8080) differs from host HTTPS_PROXY/HTTP_PROXY (http://bob:hunter2@env-proxy:3128)…` — the test printed the credential it asserts absent. With the message changed and the mutation still applied: `warning leaked credential #1 (values withheld)`. Mutation reverted (`git diff src/main.rs` empty); 3 tests green; CRLF intact (1048/1048, 6249/6249). |
| C3 | Null-guard + typed `StdAce` in the DACL walker (#1) | [x] | `5573a7b`. `propagation` 3/3 before and after; `GetAce(..).is_err() \|\| ace.is_null()`; `#[repr(C)] StdAce { header, mask, sid_start }` replaces `.add(4)`/`.add(8)`; the `AceType` filter still runs before any field past the header is read. |
| C4 | Dismiss the remaining eleven with the comment bank | [ ] | |
| C5 | Record the triage rule in `docs/DEVELOPERS.md` §3.5 + §4 | [x] | §3.5 gains the selector-not-a-credential bullet; §4 gains "Code scanning (CodeQL)" — default-setup facts, the four-step rule, the `gh` read/dismiss pair, the scope caveat. The documented read command was executed verbatim before committing. |
| C6 | Prove the end state from the API: open 0, dismissed 11, fixed {1,4,5,6} | [ ] | |

## Gates (this change set)

| Gate | Result |
|---|---|
| `cargo test --bin saife` | 690 passed, 15 ignored |
| `cargo test --bin saife --no-default-features` | 560 passed, 1 ignored |
| `cargo test --bin saife-launch` | 19 passed |
| `cargo clippy --all-targets` / `--release --all-targets` | 0 warnings |
| `cargo build --release` | 0 warnings |
| CRLF preserved in all three touched files | yes (`lf == crlf`) |

`DEVELOPERS.md` §4 still records `673 + 15` / `542`; the four commits merged
between the plan and the work (`#15`–`#19`) added tests. Left alone — a stale
number in a doc this change does not own.

## Decisions

| # | Decision | Status | Ruling |
|---|---|---|---|
| D1 | Four critical nonces: dismiss as *used in tests* (A) vs refactor to per-run markers (B) | [x] | **A** — user: "implement as recommended". |
| D2 | Keep default setup (recommended) vs advanced setup + `paths-ignore` | [x] | **Keep default setup**; no `paths-ignore`. |
| D3 | `verify.rs` asserts (#2/#3): dismiss vs redact | [x] | **Dismiss** — the verdict string is the evidence the test asserts on. |

## Event Log

- **2026-10-26:** plan written from the live API; nothing dismissed, no code
  changed. Findings evaluated: 11/15 are in `#[cfg(test)]` code or a spike crate
  (the four *critical* ones are in `#[cfg(test)] mod live;` and are not compiled
  into `saife.exe`); 3 are a real (small) defect in leak-detecting assertions; 1 is
  an unchecked `GetAce` pointer in a test helper; 4 are intentional session-id
  output, where the session id is a selector and the network credential is the
  per-run `RunToken`.
- **2026-10-26:** C2 + C3 landed on `fix/codeql-triage` (`4475426`, `5573a7b`).
  Fix-first, so the rescan can close #1/#4/#5/#6 as `fixed` rather than
  `dismissed`. C1/C4/C6 open: dismissal writes need the `security_events` scope,
  which the current `gh` token does not carry.
