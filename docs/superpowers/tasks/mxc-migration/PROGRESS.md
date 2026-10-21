# MXC ProcessContainer Migration — PROGRESS

Plan: `docs/superpowers/plans/2026-10-21-mxc-ga-processcontainer-migration.md`
Decision: ADR-0004 (Accepted 2026-10-21, Option A with guardrails)
Status legend: `[ ]` pending · `[~]` in progress · `[x]` done · `[!]` blocked

## Task table

| Task | Status | Implementer | Spec | Quality | Commit | Notes |
|------|--------|-------------|------|---------|--------|-------|
| P0.1 mxc-sdk dep + feature flag | [x] | impl | pass | pass | f2c1136 | exact pin `=1.0.1`, feature default off; 82 transitive crates, default graph unchanged |
| P0.2 MxcBackend::launch + result mapping | [x] | impl | pass | pass | f2c1136 | pure `build_request`; env filter proven by exact surviving-key-set test; spawn deferred to P1 |
| P0.3 Guardrail 1 (proxy proof, hard gate) | [x] | impl | pass | pass | f2c1136 | accepted>=1 && tunnels>=1 BEFORE exit mapping; missing source is an error; `success()` now consults the proof |
| P0.4 Guardrail 2 (tier probe + record) | [x] | impl | pass | pass | f2c1136 | probes the exact request; tier_source probe/unavailable; `needs_dacl_augmentation: Option<bool>` |
| P0.5 CLI --backend + concurrency refusal | [x] | impl | pass | pass | f2c1136 | default appcontainer; table-tested `route_backend` fail-closed in all 8 cells; no silent fallback |
| P1.1 Per-session proxy + networkProxy | [ ] | | | | | 127.0.0.1 only |
| P1.2 Request mapping + NO_PROXY injection | [ ] | | | | | strip host proxy env |
| P1.3 Filesystem mapping + workspace-only test | [ ] | | | | | additive grants caveat |
| P1.4 Concurrency: per-run token (or proxy per run) | [ ] | | | | | mandatory test with 2 containers |
| P1.5 WinHTTP path measurement | [ ] | | | | | decides GUI workload support |
| P2.1 Prompt budget vs timeout_ms | [ ] | | | | | 60 s dialog must survive |
| P2.2 D-4 endpoints under MXC | [ ] | | | | | S-77 parity |
| P2.3 session.start tier leaf + audit verify | [ ] | | | | | D-5 extension |
| P2.4 Harness S-93 (misconfig) + S-94 (unelevated) | [ ] | | | | | |
| P3.1 Full suite on both images (MXC backend) | [ ] | | | | | unelevated |
| P3.2 Flip default + keep fallback flag | [ ] | | | | | |
| P3.3 Docs + supersede F-21 | [ ] | | | | | |
| P4.1 Delete DACL walk/journal/loopback exemption | [ ] | | | | | the 4.5 class goes |
| P4.2 Remove elevation text from CLI | [ ] | | | | | |
| P4.3 Retire appcontainer fallback (after one release) | [ ] | | | | | |

**CHECKPOINT A** (after P0) — READY for user approval. P0 landed as f2c1136: 400 tests
(feature off) / 421 (feature on), zero warnings in all four build/clippy combos,
`cargo doc` adds no new warnings from our file. Both reviews PASS with no blocking
findings; nine advisories applied. Host-elevated harness 7/7 green (81/85/86/87/88/90/91).
P1 must read the plan's D1-D6 block first (NO_PROXY is scrubbed by the SDK, so intent
endpoints need the wrapper launcher).
**CHECKPOINT B** (after P1) — STOP for user approval
**CHECKPOINT C** (after P3) — STOP for user approval
**CHECKPOINT D** (after P4) — STOP for user approval

## Event Log

- 2026-10-21: Plan created from the ADR-0004 prototype evidence (spike commits
  `a067461`, `be59a60`; ADR amendments `6933a89`). No implementation started.
  Baseline for this plan: trunk `be59a60`, 390 unit tests, harness 92 scenarios
  0-fail on images A (26340) and B (29680).
- 2026-10-21: **P0 complete (f2c1136 + this docs commit).** `mxc-sdk = "=1.0.1"` behind `mxc-backend`
(default off, 82 transitive crates, default graph unchanged). `src/net/mxc.rs`: pure `build_request`
(egress deny; ingress+host_loopback allow only when a proxy port is given; identity-less ProcessContainer;
host proxy vars filtered case-insensitively - the leak test asserts the EXACT surviving key set, not a
re-derived predicate); guardrail 1 as a structural gate (`accepted>=1 && tunnels>=1`, evaluated BEFORE the
exit code is mapped, missing proof source = error, `success()` verifies the proof); guardrail 2 probing the
exact request with `tier_source` limited to probe/unavailable and `needs_dacl_augmentation: Option<bool>`.
CLI: `--backend appcontainer|mxc` with `route_backend` table-tested across all 8 (backend x feature x wired)
cells, so both fail-closed refusals cannot silently soften; default path unchanged. Reviews: spec PASS
(per-task conformance; feature-off provably inert) and quality PASS (error types, purity, test honesty,
dead_code scoping), no blocking. NINE advisories applied, two of which were test honesty: a vacuous
`matches!` and a tautological env loop replaced by exact-set assertions. **P1 design facts recorded in the
plan (D1-D6):** (D1) mxc-sdk 1.0.1 STRIPS `NO_PROXY` (and lowercase variants) when a proxy is configured
and re-injects only uppercase HTTP(S)_PROXY - so the plan's 'inject NO_PROXY ourselves' is impossible via
`request.environment`; chosen fix is a wrapper launcher (fallback: separate intent port; upstream ask
filed in the plan); (D2) `inherit_default_environment=Some(true)` layers over the PROFILE environment, not
the caller's; (D3) guardrail 1 has no offline branch, so a proxy-less launch can never pass; (D4) the
epoch never closes on a `run` error; (D5) MXC's 30 s default timeout would kill a 60 s prompt; (D6) drop
the module `allow(dead_code)` when P1 wires the launch path. ALSO recorded: host-elevated run of the
rewritten scenarios 7/7 PASS (S-81/85/86/87/88/90/91), closing the last gap from the harness merge.
