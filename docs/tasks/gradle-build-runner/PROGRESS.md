# Gradle build runner — progress

Plan: [2026-10-30-gradle-build-runner.md](../../plans/2026-10-30-gradle-build-runner.md)
Related: [gradle-daemon-loopback](../../plans/2026-10-28-gradle-daemon-loopback.md) (the in-session alternative this plan may not need)

Status: **plan only.** Nothing implemented, nothing measured. S-0 is a blocking gate.

Status legend: `[ ]` not started · `[~]` in progress · `[x]` done and gated · `[!]` blocked

## Rows

| # | Task | Status | Evidence |
|---|---|---|---|
| S0.1 | Facade can stream a 10-minute build log | [ ] | |
| S0.2 | Substrate attach latency measured (docker exec / start / WSL2) | [ ] | |
| S0.3 | Bind-mount throughput for ~20 k files, vs in-volume copy | [ ] | |
| S0.4 | Container → saife proxy reachability (offline vs relayed) | [ ] | |
| S0.5 | `docs/research/build-runner/measurements.md` written | [ ] | |
| S0.6 | Endpoint discovery: `/_ping` over npipe from Rust; containerd-mode has no Docker API | [ ] | Rancher Desktop 29.5.3 (moby) is the v1 engine; `Test-Path` on the pipe lies, the API does not |
| T1.1 | `BuildRequest` type + validation; no image/mount/command field | [ ] | |
| T1.2 | Declared facade operations (`POST/GET/DELETE /build`) + 403 fixture | [ ] | |
| T1.3 | Streaming response path | [ ] | |
| T1.4 | Per-session runner token, distinct from the proxy token | [ ] | |
| T2.1 | Slot spawn with pinned digest + readiness probe | [ ] | |
| T2.2 | Attach path with timeout and named failure | [ ] | |
| T2.3 | Idle kill, recycle, invalidate on digest/JDK change | [ ] | |
| T2.4 | Single-session ownership, kill on end, start-up sweep | [ ] | |
| T2.5 | Caps + slot facts (`slot_id`, digest) | [ ] | |
| T2.6 | `src/runner/engine.rs`: endpoint + probe + quirks + `RunnerEngine` trait | [ ] | |
| T3.1 | Project root resolution: reparse/UNC/subst/install-dir refusals | [ ] | |
| T3.2 | `/src` and `/cache` mounts, HOME inside | [ ] | |
| T3.3 | Outputs visible on host; nothing writable outside `/src` | [ ] | |
| T3.4 | Windows semantics documented (case, CRLF, locks, long paths) | [ ] | |
| T4.1 | `profiles/gradle-runner.json` + README row | [ ] | |
| T4.2 | Invocation, JAVA_HOME, exit codes, timeout/cancel | [ ] | |
| T4.3 | Prewarm at image build time, documented refresh step | [ ] | |
| T4.4 | Offline failure UX naming the missing dependency | [ ] | |
| T4.5 | Live leg: warm attach < 2 s, daemon reused on the second build | [ ] | |
| T5.1 | ADR-0006 build runner | [ ] | |
| T5.2 | FAQ rewrite, `--no-daemon` evidence kept, appcontainer fallback | [ ] | |
| T5.3 | DEVELOPERS invariants | [ ] | |
| T5.4 | Cross-link the sibling loopback plan | [ ] | |
