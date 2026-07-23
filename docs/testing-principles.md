# Testing Principles for `sandbox`

> **Status:** Principles established pre-implementation. Apply when writing any
> test; review this doc before starting each user-story implementation.
>
> **Source question:** "How much automated testing is possible? I want a high
> confidence level that things actually work… however much of what we handle is
> actually hard to test." — answered 2026-07-23.

The codebase splits cleanly into three testability tiers. Treat each tier with a
different discipline. Do not pretend a Tier-3 concern is Tier-1, and do not skip
TDD on Tier 1 just because Tier 3 is hard.

---

## Tier 1 — Pure logic: strict TDD, ~100% coverage achievable

Pure functions, no I/O, no kernel, no async. **Write the test first, watch it
fail, implement.** These modules hold the bulk of the *security-relevant
decision logic* and are the place TDD pays off most.

- **Profile loading, JSON schema validation, `extends` merge, security-group
  expansion** (FR-5) — input JSON in, resolved allow-list out. Deterministic.
- **Variable expansion** (`$HOME`, `$CWD`, `$SID`, `$USERPROFILE`, `$TEMP`) —
  string in, string out. AC-1.7 (cross-user) is just feeding two different env
  maps.
- **Path canonicalization** (case-fold, `\\`→`\`, resolve `..`, drive-letter /
  UNC normalization, `C:\foo` → NT path) — the trickiest pure module, and the
  one most worth TDDing. **Path bugs cause silent sandbox escapes.** Give it the
  largest test battery of any module.
- **Domain allow-list matching** (exact + `*.suffix` wildcard, always-deny
  CIDR check: `169.254.0.0/16`, `fe80::/10`, metadata host) — pure predicate
  on `(host, port)`. FR-3.3/3.4.
- **Hash-chain / Merkle root** (leaf canonicalization, SHA-256, parent linking)
  — AC-4.3. AC-4.9/4.10/4.11 (tamper / truncate / forged-root) are *perfect* TDD
  cases: deterministic, fast, and they encode the core security guarantee.
- **Ed25519 sign/verify round-trip** — deterministic with a fixed seed.
- **`--filter` grammar** (`op=`, `disposition=`, `path~=`, `host~=`, `ts>=`,
  `ts<=`) — parser + predicate, pure.
- **Session-id generation** (`YYYYMMDD-HHMMSS-NNNNN`, counter disambiguation)
  — AC-4.1.
- **CLI parsing** (clap) — declarative, tested via `assert_cmd` or direct
  dispatch.
- **Store manifest hash verification** (AC-1.18) — read files, hash, compare.
  Pure logic over a dir tree.

~50–60% of the codebase by line count. **Do not skip TDD here, ever.**

---

## Tier 2 — Integration tests on a real Windows box, deterministic-ish

Not unit-testable (kernel state involved), but each AC maps to one concrete
spawn-and-assert test. The PRD's PowerShell integration suite already sketches
these. They require Windows runners (GitHub Actions `windows-latest` works) and
a real `sandbox.exe` build.

- **AppContainer + RuleSet enforcement** — AC-1.2 / 1.3 / 1.5:
  `sandbox run --allow <tmp> -- cmd /c type <denied>` → assert
  `Access is denied`. The kernel is the oracle; you cannot mock it.
- **Inheritance** — AC-1.12 / 1.13, SM-6: `cmd /c cmd /c type …` still denied.
  Two concurrent `run` invocations, distinct SIDs, cross-read denied.
- **Job Object kill-on-close** — AC-1.8: start a child, `Stop-Process
  sandbox.exe`, assert no orphans via `Get-CimInstance Win32_Process`.
- **Option E install dirs** — AC-1.11: drop a binary in
  `.sandbox/$SID/bin/`, exec it, assert success.
- **`persist` / `--reuse` / `--reuse-rw`** — AC-1.15–1.18: filesystem moves +
  lock semantics. Single-writer contention test spawns two `--reuse-rw` and
  asserts the second is rejected.
- **Reverse proxy end-to-end** — AC-4.6, SM-2: spin a local HTTP test server
  as the "allowed" target and a denied one; sandboxed
  `curl` / `Invoke-WebRequest` hits the proxy; assert allowed connects, denied
  drops, both logged. Proxy runs in the test, not mocked.
- **`--block-net`** — SM-2: `Test-NetConnection` fails.
- **`setup --check-only`** — AC-1.9 / 4.16: assert non-zero on the pre-1709
  message path (inject a fake build number), report correct fidelity tier for
  admin vs non-admin.
- **Audit `show` / `verify` on a real session** — AC-4.4 / 4.8: run a session
  that does known ops, assert the expected events appear and `verify` returns
  `OK`.

Slow (process spawns, ~100ms–1s each) but reliable. Run as a separate
`cargo test --test integration` suite. **Confidence: high.**

### Authoring rule
Each AC in Tier 2 is already written as Given/When/Then. **Transcribe the AC
directly into a `#[test]` before implementing the feature it covers.** This is
TDD at the integration level — the test fails (no impl yet), you implement, the
test passes.

---

## Tier 3 — Hard to test: accept lower coverage, be honest

Don't pretend TDD covers these. Document the gap, mitigate where possible.

- **ETW kernel event capture** (admin path) — events are async, kernel-buffered,
  timing-dependent. A test can do *N* file ops and assert *≥N* `FILE_*` events
  appear within a timeout, but it is inherently racy. **Mitigate:** assert
  *content* of events (right paths, right dispositions) rather than exact count
  or order. Generous timeouts, retry on flake. Accept a small flake rate.
- **Userspace DLL-injection hook** (non-admin fallback) — the injection
  mechanism (`PROC_THREAD_ATTRIBUTE` + injected DLL hooking `CreateFileW` /
  `NtCreateFile` / `connect` / `CreateProcessW`) is the single most fragile
  component. The *hook functions* can be unit-tested by calling them directly
  with fake inputs (Tier 1). The *injection + interception in a real spawned
  process* can only be integration-tested. **Plan for this to be the
  highest-maintenance test area.** Keep the hook surface tiny and isolated so
  the integration test is the only fragile piece.
- **Latency budget** (AC-1.10, SM-4: p95 < 50ms) — a benchmark, not a pass/fail
  test. Run as `cargo bench` with a **loose regression gate** (e.g. fail if
  p95 > 200ms in CI, not 50ms) so CI noise doesn't flap. The 50ms number is a
  design target, not a CI assertion.
- **Irrevocability** (AC-1.6) — you cannot *prove* no loosening path exists by
  testing; it is a property of the code surface. Cover with: a CLI test
  asserting `sandbox.exe` exposes no `loosen` / `expand` / `grant` subcommand,
  plus a code-review checklist item. Kernel immutability holds by construction.
- **Cross-user behavior** (true two-user isolation) — needs two real user
  profiles; impractical in CI. Unit-test the expansion logic (Tier 1) and
  document the cross-user property as a manual `--self-test` step.
- **DPAPI at-rest protection** (AC-4.15) — assert the key file bytes are *not*
  a raw Ed25519 secret (length / prefix check) and that `sandbox` can still
  load + use it. "Only DPAPI can decrypt" is not meaningfully testable beyond
  just calling DPAPI.
- **Crash behavior** (AC-4.17) — `Stop-Process -Force` the supervisor
  mid-session, assert `verify` reports `INCOMPLETE` and `show` still reads the
  log. Doable; treat as Tier 2.5 (process-lifecycle test).

---

## Recommendations (binding on implementation)

1. **Strict TDD for all of Tier 1.** Highest confidence per minute spent; most
   security-critical logic lives here (matching, canonicalization, crypto).
   The path normalizer gets the largest test battery — sandbox escapes are
   born there.
2. **One integration test per AC for Tier 2**, written *before* the
   implementation that satisfies it. The AC text is already Given/When/Then —
   transcribe directly.
3. **For Tier 3, write the test that's honest, not the test that looks good.**
   A flaky ETW count assertion is worse than a robust content assertion with a
   timeout. Mark latency tests as benchmarks, not unit tests.
4. **`sandbox --self-test` command** runs the Tier-2 battery against a temp
   profile on the user's own machine. This is how we get confidence on the
   ETW/hook and AppContainer paths *on the actual deployment machine*, where CI
   cannot reach. (Already mentioned in the PRD.)
5. **Test failure modes, not just happy paths.** AC-4.9 / 4.10 / 4.11
   (tamper / truncate / forged-root) are the model — each tests a specific way
   the guarantee can break. Mirror for the sandbox: denied-read, denied-net,
   orphan-killed, cross-session-denied. **"It correctly denies" tests are more
   valuable than "it correctly allows" tests.**
6. **CI constraint to flag now:** the entire Tier 2/3 suite requires Windows.
   No Linux/mac coverage is meaningful there. Plan Windows-only CI plus a
   `--self-test` for developer machines.

---

## Net

Tier 1 (pure logic) is most of the security decision logic and is fully
TDD-able. Tier 2 is one test per AC and gives high end-to-end confidence. Tier 3
— ETW fidelity and the DLL-injection hook — is the genuinely hard part; budget
for it, but do not let it block TDD on everything else.

### Test-file layout (to be created at implementation start)

```
src/
  <module>.rs           # `#[cfg(test)] mod tests` for Tier 1 unit tests
tests/
  integration/          # `#[test]` per AC — Tier 2 (Windows-only)
    us1_run_agent.rs
    us2_toolchain.rs
    us3_network.rs
    us4_audit.rs
    us5_profiles.rs
  fixtures/             # profiles, sample programs, test servers
benches/
  init_latency.rs       # Tier 3 latency — `cargo bench`, loose gate
```

Tier 3 ETW / hook tests live in `tests/integration/` too, marked
`#[ignore]` by default and run explicitly (or via `--self-test`) to keep the
default CI suite green.
