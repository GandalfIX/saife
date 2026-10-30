# Gradle build runner — progress

Plan: [2026-10-30-gradle-build-runner.md](../../plans/2026-10-30-gradle-build-runner.md)
Related: [gradle-daemon-loopback](../../plans/2026-10-28-gradle-daemon-loopback.md) (the in-session alternative this plan may not need)

Status: **plan only.** Nothing implemented, nothing measured. S-0 is a blocking gate.

Status legend: `[ ]` not started · `[~]` in progress · `[x]` done and gated · `[!]` blocked

## Rows

| # | Task | Status | Evidence |
|---|---|---|---|
| S0.1 | Facade can stream a 10-minute build log | [ ] | |
| S0.2 | Substrate attach latency measured (docker exec / start / WSL2) | [~] | info 93 ms, run --rm 497 ms, start 37 ms, exec 73 ms (Rancher moby 29.5.3). Open: Gradle daemon cost |
| S0.3 | Bind-mount throughput for ~20 k files, vs in-volume copy | [x] | bind 53.6 s vs volume 0.76 s (2.65 vs 0.038 ms/file); tar-pipe populate 2.8 s. §4 rewritten: sync, not mount |
| S0.4 | Container → saife proxy reachability (offline vs relayed) | [ ] | |
| S0.5 | `docs/research/build-runner/measurements.md` written | [~] | three legs recorded; S0.1, S0.4 and the daemon cost pending |
| S0.6 | Endpoint discovery: `/_ping` over npipe from Rust; containerd-mode has no Docker API | [~] | npipe from a plain .NET client: 200 OK, /version api=1.54 min=1.41 engine=29.5.3; Rust leg pending |
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
| T3.2 | Sync in (delta) into `/src` volume, `/cache`, HOME inside | [ ] | |
| T3.3 | Sync out (declared outputs, filtered); agent edits never overwritten | [ ] | |
| T3.4 | Windows semantics documented (case, CRLF, locks, long paths) | [ ] | |
| T3.5 | Sync semantics tests: delete, rename, exec bit, CRLF, mid-build edit | [ ] | |
| T4.1 | `profiles/gradle-runner.json` + README row | [ ] | |
| T4.2 | Invocation, JAVA_HOME, exit codes, timeout/cancel | [ ] | |
| T4.3 | Prewarm at image build time, documented refresh step | [ ] | |
| T4.4 | Offline failure UX naming the missing dependency | [ ] | |
| T4.5 | Live leg: warm attach < 2 s, daemon reused on the second build | [ ] | |
| T5.1 | ADR-0006 build runner | [ ] | |
| T5.2 | FAQ rewrite, `--no-daemon` evidence kept, appcontainer fallback | [ ] | |
| T5.3 | DEVELOPERS invariants | [ ] | |
| T5.4 | Cross-link the sibling loopback plan | [ ] | |
