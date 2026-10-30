# Gradle build runner — progress

Plan: [2026-10-30-gradle-build-runner.md](../../plans/2026-10-30-gradle-build-runner.md)
Related: [gradle-daemon-loopback](../../plans/2026-10-28-gradle-daemon-loopback.md) (the in-session alternative this plan may not need)

Status: **plan only.** Nothing implemented, nothing measured. S-0 is a blocking gate.

Status legend: `[ ]` not started · `[~]` in progress · `[x]` done and gated · `[!]` blocked

## Rows

| # | Task | Status | Evidence |
|---|---|---|---|
| S0.1 | Facade can stream a 10-minute build log | [x] | live leg with the stream-sidecar fixture: 20 lines over 20 s, first byte 1 ms, last 20 010 ms, no buffering. Also found the facade is GET-only (501) → T1.5 |
| S0.2 | Substrate attach latency measured (docker exec / start / WSL2) | [x] | info 93 ms, run --rm 497 ms, exec 73 ms; sample project: cold 88.6 s (904 MB downloads), warm 1.67 s, ephemeral 4.95-13.6 s, `--offline` clean 8.5 s, daemon 479 MB. Decision: long-lived container |
| S0.3 | Bind-mount throughput for ~20 k files, vs in-volume copy | [x] | bind 53.6 s vs volume 0.76 s (2.65 vs 0.038 ms/file); tar-pipe populate 2.8 s. §4 rewritten: sync, not mount |
| S0.4 | Container → saife proxy reachability (offline vs relayed) | [x] | reachable via host.docker.internal (407 realm `sandbox`) — and so is every 127.0.0.1 host service; runner container is not a network boundary → v1 uses `--network none` |
| S0.5 | `docs/research/build-runner/measurements.md` written | [~] | three legs recorded; S0.1, S0.4 and the daemon cost pending |
| S0.6 | Endpoint discovery: `/_ping` over npipe from Rust; containerd-mode has no Docker API | [~] | npipe from a plain .NET client: 200 OK, /version api=1.54 min=1.41 engine=29.5.3; Rust leg pending |
| T1.1 | `BuildRequest` type + validation; no image/mount/command field | [x] | `src/runner/mod.rs`: project/task/profile only, `deny_unknown_fields` names any extra key; task and profile allow-lists; `..`, rooted, UNC and device paths refused. 5 tests |
| T1.2 | Declared runner operations + refusal fixtures | [x] | `runner::server::OPERATIONS` = `POST /build`, `GET /build`; the build id travels as a query because the declaration grammar is exact-path. Server answers 404 for every other method/path |
| T1.3 | Streaming response path | [x] | `GET /build?id=..&follow=1` writes lines as the engine produces them (close-delimited, 100 ms poll); test proves the first line arrives while the build is still running |
| T1.5 | Facade relays declared methods + request bodies (403 not 501 for undeclared) | [x] | GET gate removed; declaration is the control; undeclared → 403 `facade_operation_not_declared`, non-token → 400 `facade_method_invalid`, body ≤ 4 KiB forwarded (`413 facade_body_too_large` past). 3 new tests; live S0.1 re-run green (last chunk 20 008 ms) |
| T1.4 | Per-session runner token, distinct from the proxy token | [~] | the listener requires `X-Facade-Token` and refuses a wrong one (401 `runner_token_invalid`); distinctness from the proxy token is asserted when the session wiring exists |
| T2.1 | Slot spawn with pinned digest + readiness probe | [x] | Engine API over the npipe (no CLI): ping, version, create (digest-pinned, `NetworkMode: none`, session label), start, inspect, list-by-label, remove. Live leg green in 0.27 s: create → start → running → visible to the sweep → removed |
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
