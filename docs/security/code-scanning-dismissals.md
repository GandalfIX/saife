# Code scanning: decisions on dismissed alerts

Every dismissal in this repo names the alert id, the reason, and the condition
that would make it a true positive. Dismissed does not mean "ignore the rule":
the rule keeps running everywhere, and a new instance elsewhere opens a new
alert.

## Why not suppress in code

- **Rust has no in-code suppression.** CodeQL's suppression comments
  (`// codeql[query-id]`, `// lgtm[query-id]`) are implemented per language by
  an `AlertSuppression.ql` query. The Rust query pack does not ship one
  (github/codeql#11427: the supported mechanism is a UI dismissal).
- **The repository uses default setup.** Default setup reads no configuration
  file, so a `codeql-config.yml` with path or query filters does not apply.
- **A `query-filters` exclusion would be global.** Excluding a rule through a
  config file excludes it for the WHOLE repository - unacceptable here, where
  the same rule guards `net/proxy.rs`, `net/prompt.rs` and `plugin/sidecar.rs`,
  the places real credentials actually travel.

The decision therefore lives in this file, and the alerts carry the reason
"used in tests" with a comment pointing here.

## `rust/cleartext-logging` on the audit module (9 alerts, PR #55)

**Alerts:** code-scanning 43-49 (`src/audit/show.rs`) and 50-51
(`src/audit/verify.rs`).

**What the query reports:** the `session_id` parameter of `render_summary`
reaches a log-like sink - in all nine cases the failure message of an
`assert!(...)` in an in-module `#[cfg(test)]` test, which interpolates the
rendered report (`{out}`, `{r}`).

**Why it is a false positive:**

1. **The value is not a secret.** `session_id` is a validated name, not a
   credential: [`validate_session_id`](../src/audit/mod.rs) accepts 1-64
   characters of `[A-Za-z0-9._-]` and refuses `.`/`..`. The bearer credential
   in this product is the per-session facade token (`BCryptGenRandom`,
   `X-Facade-Token`), and the signing key is CNG-held; neither appears in these
   flows. The query marks the parameter sensitive by NAME heuristic
   (session-identifier shaped), not by tracing it to a secret.
2. **Writing the session id is the module's contract.** The audit chain exists
   to record which session did what; `render_summary` starts with
   `Session {session_id}` and `saife audit show` prints it by design. The
   production sink for that value (`print!` in `show.rs`) is not flagged.
3. **The sinks are test assertions.** They run only on failure, into the test
   harness capture, and carry fixture values (`"sid-render"`,
   `"mutant-gaps-show-sig"`).

**What would make it a true positive** - reopen then:

- the session id gains credential semantics (used as an authentication token,
  a shared secret, or a capability rather than a label);
- a facade token, signing key or a credential-file CONTENT joins a flow to a
  log sink or a test assertion message;
- `render_summary` (or a successor) starts writing to a file or a remote sink
  outside the ACL-restricted audit directory.

## Adding a dismissal

Add a section here first, then dismiss the alert with the matching reason and
a link to the section. A dismissal without a section here is a review finding
against the change that dismissed it.
