# MXC ProcessContainer Migration — PROGRESS

Plan: `docs/superpowers/plans/2026-10-21-mxc-ga-processcontainer-migration.md`
Decision: ADR-0004 (Accepted 2026-10-21, Option A with guardrails)
Status legend: `[ ]` pending · `[~]` in progress · `[x]` done · `[!]` blocked

## Task table

| Task | Status | Implementer | Spec | Quality | Commit | Notes |
|------|--------|-------------|------|---------|--------|-------|
| P0.1 mxc-sdk dep + feature flag | [ ] | | | | | exact pin `=1.0.1` |
| P0.2 MxcBackend::launch + result mapping | [ ] | | | | | run vs spawn split |
| P0.3 Guardrail 1 (proxy proof, hard gate) | [ ] | | | | | epoch attribution |
| P0.4 Guardrail 2 (tier probe + record) | [ ] | | | | | leaf wiring in P2.3 |
| P0.5 CLI --backend + concurrency refusal | [ ] | | | | | default stays appcontainer |
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

**CHECKPOINT A** (after P0) — STOP for user approval
**CHECKPOINT B** (after P1) — STOP for user approval
**CHECKPOINT C** (after P3) — STOP for user approval
**CHECKPOINT D** (after P4) — STOP for user approval

## Event Log

- 2026-10-21: Plan created from the ADR-0004 prototype evidence (spike commits
  `a067461`, `be59a60`; ADR amendments `6933a89`). No implementation started.
  Baseline for this plan: trunk `be59a60`, 390 unit tests, harness 92 scenarios
  0-fail on images A (26340) and B (29680).
