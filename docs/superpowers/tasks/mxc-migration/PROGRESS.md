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
| P1.1 Per-session proxy + networkProxy | [x] | impl | PASS | PASS | 52614f2 + wave 2 | Wave 1: launch wiring + epoch lifecycle. Wave 2: the REAL proof source is the listener's own `LaunchCounters` (`begin_epoch`/`counters`/`close_epoch`, poison-tolerant, `Send+Sync`), `ProxyHandle::counters()` is the source, `127.0.0.1:0` is the session port, and `launch_session` derives the guardrail leg from the port instead of trusting the caller. Counting: `accepted` = authenticated CONNECT or absolute-form consultation (NOT origin-form to our own intent endpoints, NOT a 407); `tunnels` = upstream established (CONNECT 200 after the dial **or** a plain-HTTP forward whose upstream dial came up). |
| P1.2 Request mapping + NO_PROXY injection | [x] | impl | PASS | PASS | 52614f2 + wave 2 | D1 via the `mxc-launch` wrapper (proven again live). Wave 2: the request's `networkProxy` is the supervisor's own bound port **and carries the session token as userinfo** (plan D8) - without it every child request was a 407 and Required failed as `SessionNotAccepted`; the SDK copies that URL verbatim into HTTP(S)_PROXY, and `policy_identity` excludes userinfo from the hash. Also: absolute-form `http://` requests are now admitted through the full D-1 pipeline and forwarded (the previous blanket 400 made a plain-HTTP-only session unprovable). Tokens are restricted to URL-unreserved chars. |
| P1.3 Filesystem mapping + workspace-only test | [x] | impl | PASS | PASS | wave 2 + 3 fixers | `filesystem_policy`: readwrite = [workspace], readonly = declared + the **launcher's directory (added before the deny list is filtered — the ordering defect that shipped a deny covering the launcher is fixed)**, denied = profile `.ssh/.aws/.azure/.gnupg` + configured denies (deduped, case-folded). **Fail-closed:** an operator deny that is equal to or an *ancestor of* any grant (workspace, declared readonly, launcher) is a hard `RequestError::DenyCoversGrant` naming both paths — the old silent drop left Documents/Downloads/AppData/browser profiles readable with no warning and no audit trace; denies that are *descendants* of a grant are kept. `path_key`/`covers` normalise case, separators, trailing dots/spaces, `.`/`..` and `\\?\`/`\\.\` prefixes with no filesystem calls, and `covers` has direct boundary tests. Recorded exposure: the launcher grant is its whole parent directory (`target\debug` for a repo-local build). Unit tests + a live leg: granted write OK, denied read/write refused, ungranted path refused, and `C:\Windows\win.ini` readable = the recorded additive-grants caveat (asserted as the caveat, so it cannot be "fixed" by denying System32). |
| P1.4 Concurrency: per-run token (or proxy per run) | [x] | impl | PASS | PASS | P1.4 | `RunToken` (run-serial prefix + 224 CNG bits, redacted Debug, constant-time `matches`); the listener classifies `OwnRun`/`Absent`/`Foreign`, refuses a foreign credential with the SAME 407, counts it as nothing, and records exactly one `foreign_token` leaf - the reviews caught that the first cut left cross-run probing invisible in BOTH chains. `begin_epoch` refuses overlap (`MxcError::Concurrency`); the pruner evicts only CLOSED epochs (32 + at most 1 open). One listener per run was already true - pinned by a live **two-container** test: both proofs `{1,1}` (not `{2,2}`), cross-token 407 with counters frozen, closing B leaves A serving and still refusing B. |
| P1.5 WinHTTP path measurement | [x] | measure | n/a | n/a | none (measurement only) | 22 legs, unelevated, against a real ProcessContainer + a token-gated stand-in proxy. **env-only is enough for env-reading clients and for nobody else.** Child sees `HTTP_PROXY`/`HTTPS_PROXY` = `http://sandbox:<token>@127.0.0.1:P` and `NO_PROXY=localhost,127.0.0.1,::1`, while the IE/WinHTTP/WinINet config in the same child is 'direct'. WinHTTP (`AUTOMATIC_PROXY`, `DEFAULT_PROXY`) and WinINet (`PRECONFIG`) **never read the env**, yet their HTTP egress is **forced to `networkProxy` by the container**: a WinHTTP session told the deliberately wrong proxy `127.0.0.1:1` still arrived at the container's proxy in absolute-form, and the same legs reached it with the proxy variables deleted inside the child. The consultation arrives **unauthenticated -> 407** (WinHTTP reaches 200 + tunnel only when given `WinHttpSetCredentials(PROXY,BASIC)`; WinINet's pre-emptive `INTERNET_OPTION_PROXY_USERNAME/PASSWORD` were rejected, so it needs a 407 prompt no GUI session can answer). Raw TCP is refused at connect with **WSAEACCES 10013** for the LAN target *and* for `127.0.0.1:<any port but the proxy's>` - no silent direct escape, and `hostLoopback=allow` is not general loopback (the D-4 intent endpoint works only because it shares the proxy's port). `NO_PROXY` is honoured by curl (measured both ways) and is meaningless to WinHTTP/WinINet. `HKCU\...\Internet Settings` cannot even be opened for write inside (**5 ERROR_ACCESS_DENIED**), and `netsh winhttp`/HKLM need admin. **The CLR does not start in this container at all**: CoreCLR `0x8007045A` from `coreclr.dll` DllMain (exit `0xC0000409`), .NET Framework exit `0xC0000142` - same binary runs under the AppContainer backend, native RWX control rules out code-integrity, broadened grants change nothing. So the `SocketsHttpHandler` / `UseProxy=$false` legs are **not runnable** (recorded as such, not claimed). Decision: GUI/system-proxy workloads are **out of scope** for MXC proxy-only mode; keep AppContainer for them. Full measurements + costs in `docs/backends/process-container/winhttp-proxy-path.md`. |
| P1.6 Harden what P1.4's reviews left open | [ ] | | | | | pre-commit hardening, not blocking P1 | (a) **`no_token` leaf flood** - measured 400 credential-less CONNECTs -> 400 leaves / 129 KB, no cap: cap per epoch (first N, then one aggregate leaf with the suppressed count); (b) `RunToken: Clone` lets two `ProxyConfig`s share one credential (unreachable today; a process-global live-token set checked in `proxy::spawn` closes it); (c) `Absent` vs `Foreign` differ in TIMING (644 vs 355 us) because only the absent arm flushed a leaf before this change - not an oracle over the token, and the comment now says 'bytes' rather than 'byte-identically'; (d) the constant-time property is unpinned (swapping `ct_eq` for `==` leaves the suite green) - keep it inside `matches` so removal is a visible diff; (e) `ProxyEnv.token` is a bare `String` at the env edge with no charset check - make it `&RunToken` before P2; (f) live-test honesty: distinct nonce per Origin, assert B's port refuses connections after `drop`, add a launch barrier so 'concurrent' is observed. |
| P1.7 CLR-startup root cause | [x] | diagnose | PASS | n/a | none (measurement only) | **Root cause: the container runs every child with the kernel mitigation `PROCESS_CREATION_MITIGATION_POLICY_WIN32K_SYSTEM_CALL_DISABLE`.** `build_request` never sets `ContainerRequest::ui`, and the SDK's `UiPolicy::default()` is `disable: true` (`core/mxc_common/models.rs:583`; wire default `config_parser.rs:1597`), which the PSEC path maps straight to `disallow_win32k_system_calls` (`base_container_helpers.rs:57`). Consequence: `user32`/`gdi32`/`ole32` `DllMain` fail -> `ERROR_DLL_INIT_FAILED` 1114 -> `coreclr.dll` cannot be *loaded by a native probe*, and the image dies `0xC0000142` (PS 5.1) / `0x8007045A`+`0xC0000409` (.NET 8). The CLR is a victim, not the cause. **Fix is one field we own:** `request.ui = Some(UiPolicy{disable:false, clipboard:None, allow_input_injection:false})` -> **verified live**: `powershell` prints `FXOK` (exit 0) and `dotnet hello.dll` prints `HELLO-OK`, with the `mxc-launch` wrapper and with the production proxy policy, and without either. Cost is measured, not assumed: all ten `JOB_OBJECT_UILIMIT_*` restrictions survive (`OpenClipboard` -> `5 ERROR_ACCESS_DENIED`) and the AppContainer-shaped Low-IL token, filesystem and proxy-only egress are unchanged; what is lost is the Win32k ban itself. Eliminated with evidence: token/LPAC + AC ACEs (both arms carry the *same* token shape and the CLR files are readable in the failing arm), filesystem grants (widening them, incl. `Program Files`, `%LOCALAPPDATA%`, `ProgramData`, `Windows\Microsoft.NET`, changes nothing), registry (`reg.exe` reads `.NETFramework` in both arms), TEMP/env (container-remapped, writable, override changes nothing), job UI limits (`0x0` in both arms), cwd, ACG/CIG (`0x0` in both arms), and the wrapper. Not an SDK limitation to wait on, but worth reporting upstream: `ProcessContainerConfig` cannot express `ui.disable`, so a caller that pins every `processContainer.ui` field has still said nothing about the Win32k ban. Full evidence: `docs/backends/process-container/clr-startup-failure.md`. **P3 impact:** ship `ui.disable=false` before P3.1, revise P1.5's "GUI/.NET out of scope, keep AppContainer" decision (its .NET legs are runnable now), and make sure no doc/audit leaf claims a Win32k mitigation we no longer have. Tier-2 AppContainer fallback would NOT have rescued this - the SDK applies the same mitigation (`appcontainer_runner.rs:858,917`). |
| P1.8 Managed proxy-path re-measurement | [x] | measure | n/a | n/a | `an_unauthenticated_consultation_gets_the_basic_challenge_managed_clients_need` (the measurement's env-dependent live leg was REMOVED before commit: it skipped itself unless scratch-built DLLs were present, i.e. a test that could pass without testing anything; the durable property - the challenge that makes managed clients work - is now pinned deterministically) | **The P1.5 ".NET is not runnable" note is retired: re-measured now that `build_request` sets `ui.disable = false`.** 15 legs in real unelevated ProcessContainers against a token-gated stand-in listener that records consultations *in order, with and without `Proxy-Authorization`*, plus a real TLS origin for the `CONNECT` path; then 7 of the same legs re-run against the **shipped** `net::proxy::spawn` listener and asserted on its `LaunchProofCounters` (`p18_managed_clients_consult_or_miss_the_real_proxy`), so no verdict rests on the client's own claim. **Works:** .NET 8 `HttpClient` default handler (`HttpEnvironmentProxy` reads `HTTP_PROXY`, HTTP **200** and HTTPS **200** through a `CONNECT` tunnel) and `pwsh` 7.6.7 `Invoke-WebRequest` (200) - both **only after a 407**: the first request on a connection carries no credential, the listener's `407` + `Proxy-Authenticate: Basic` challenge draws the retry, which authenticates. `accepted = 1`, not 2, on the real listener (the `Absent` arm is uncounted). An explicit `WebProxy` + `NetworkCredential` also works (200). **Does not work:** (a) **Windows PowerShell 5.1 / .NET Framework** - `[WebRequest]::DefaultWebProxy` is the WinINet/IE view, which is 'direct' inside the container, so `Invoke-WebRequest` **never consults the proxy at all** and dies on `WSAEACCES 10013` (worse than P1.5's WinINet row, which at least reached the proxy: .NET Framework takes only its *configuration* from WinINet and then does its own WinSock connect); (b) `new WebProxy(new Uri("http://sandbox:<token>@host:P"))` - `WebProxy` does **not** lift URI userinfo into `Credentials` (`proxy_credentials_set = false`), so the `407` reaches the application. **Controls:** `UseProxy = false` -> 0 consultations + `10013`; `NO_PROXY = <that host>` -> 0 consultations + `10013` (honoured, and it does *not* silently succeed). **New consequence:** because the wrapper injects `NO_PROXY=localhost,127.0.0.1,::1`, a .NET client bypasses the proxy for loopback - a loopback origin is `10013` and a URL on the proxy's own port arrives in **origin-form without a credential** -> `407`. So a managed workload cannot reach the loopback intent endpoint by URL today. **And for P1.6(a):** every managed connection now produces one benign `deny/no_token` audit leaf (the 407 attempt), which hollows out `no_token` as a signal - no longer hypothetical, it is the steady state of any .NET workload. **Decision:** managed egress is usable for CoreCLR clients **only because the listener issues a Basic challenge**; PS 5.1/Framework cannot be fixed client-side (system proxy unwritable/needs elevation, and WinINet has no pre-emptive credential API), so either require `pwsh` 7 / .NET 8 for managed workloads or make the P1.5 admission change (OS-attested unauthenticated peer), which removes the 407 round-trip and the `no_token` leaves together. **Load-bearing:** the 407 must carry `Proxy-Authenticate: Basic`; without it no managed client ever authenticates (pinned by the test named above). **New steady state:** every managed connection emits one benign `no_token` leaf, so P1.6(a)'s leaf-flood cap is now a normal-case concern, not an adversarial one. Evidence and per-client table: `docs/backends/process-container/winhttp-proxy-path.md`. |
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

- 2026-10-21 (P1.4): **concurrency + per-run token attribution.** (A) **Per-run token**: `src/net/token.rs`
  is now `RunToken` (was `gen_token() -> String`): the value is 8 lowercase hex chars of this process's
  **run serial** followed by 224 bits of `BCryptGenRandom`, so uniqueness per run is *structural* rather
  than an incidental property of the RNG; `RunToken` has a redacted `Debug`, a constant-time `matches`,
  and is the only way to construct `ProxyConfig`/`ConnCtx` (`token: RunToken`), so a listener cannot exist
  without its own run's credential. `main.rs` mints one per run and hands the same value to the listener
  and to the child's proxy URL. (B) **Foreign-token refusal**: `check_proxy_auth` (bool) became
  `classify_auth` (`OwnRun`/`Absent`/`Foreign`). A well-formed `Basic` credential that is not this run's
  token is answered with the identical `407` as before but is *not* counted as a consultation and writes
  **no audit leaf**; a request with no usable credential keeps its `no_token` leaf (the distinction is
  ownership, so the silence cannot hide a dead audit writer - proven non-vacuously in the test). (C)
  **Overlap refusal**: `LaunchCounters::begin_epoch` returns `Result<u64, EpochAlreadyOpen>` and refuses
  when a window is already open; `ProxyProofSource::begin_launch` now returns that `Result`, `EpochGuard`
  refuses before the body runs, and `MxcError::Concurrency` carries the named error. Nothing is spawned
  and the open window is untouched, so there is no silent split (the previous behaviour moved `active`,
  which sent the older launch's traffic to the newer window). (D) **Eviction**: an epoch entry carries
  `closed`; `prune` evicts only closed, non-active entries, so a live launch's proof can no longer be
  deleted at the bound. Memory bound documented: 32 closed counters (~24 B each) plus the one open
  window (a second is refused). `RecordingSource`/`LiveProof` fakes enforce the same contract, and the
  old `a_new_epoch_does_not_inherit...` test was restated because its manual `begin_launch` + launch
  sequence is exactly the overlap now refused. RED EVIDENCE (each revert restored byte-identically,
  `cmp` clean): treating `Foreign` as `Absent` fails
  `a_listener_refuses_a_foreign_run_token_without_counting_or_auditing_it` (leaf count 2 != 1); dropping
  the open-epoch check fails `begin_epoch_refuses_a_second_launch_while_one_is_open` (a second window
  opened); pruning on `!= active` alone fails `an_open_epoch_is_never_evicted_by_pruning` (the oldest
  *open* epoch was evicted); issuing an unsalted random token fails
  `every_run_gets_its_own_token_and_its_own_serial`. LIVE (unelevated, `elevated=false`): two concurrent
  containers, each on its own listener/port/token, A over CONNECT and B over absolute-form plain HTTP -
  both exit 0, each proof exactly `{1,1}` (not `{2,2}`), each origin saw only its own path; A's token at
  B's listener and B's at A's returned `HTTP/1.1 407` with counters `{0,0}` and no new audit leaf in
  either chain; closing B left A's counters frozen, A still serving its own token and still refusing B's.
  GATES: 439 tests (feature off) / 519 + 3 ignored (feature on), 0 clippy warnings in both states, the
  three touched source files `rustfmt --check` clean and uniformly CRLF.

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
epoch never closes on a `run` error; (D5, CORRECTED in P1 wave 1) `timeout_ms: None` becomes
`u32::MAX` i.e. NO deadline — the hazard is an unbounded child, not a capped prompt; (D6) drop
the module `allow(dead_code)` when P1 wires the launch path. ALSO recorded: host-elevated run of the
rewritten scenarios 7/7 PASS (S-81/85/86/87/88/90/91), closing the last gap from the harness merge.
- 2026-10-21: **P1 wave 1 (52614f2).** D1 solved by a wrapper launcher (`src/bin/mxc-launch.rs`, bin target gated on
`mxc-backend`): the container command is always the wrapper, the real command line travels as ONE quoted argument
re-emitted verbatim through `CreateProcessW(lpApplicationName=NULL)`, and the wrapper injects
`NO_PROXY=localhost,127.0.0.1,::1` (upper+lower) because mxc-sdk 1.0.1 scrubs it. Proven UNELEVATED on this host by an
`#[ignore]`d live test: child env has HTTPS_PROXY + NO_PROXY, intent GET arrives ORIGIN-FORM with
`proxy_consultations=[]`, and the A/B control (`--noproxy ""`) makes the same request arrive PROXY-FORM so the
`Required` leg refuses - i.e. the guardrail and the NO_PROXY delivery are both load-bearing. Exit codes propagate (9,
7) and a failed spawn is 127 + a `mxc-launch: failed to start` stderr line. D3: `ProofExpectation::{Required,
MustBeAbsent}` - network sessions must prove accepted>=1 && tunnels>=1; blocked sessions must prove accepted==0 &&
tunnels==0; Required without a proxy port is refused BEFORE the child. D4: MxcBackend is state-carrying and every
launch runs inside an EpochGuard (read-then-close, closed on success/error/panic, no double close, drop made
panic-safe). D2: inherit_default_environment stays Some(true) with the SDK's real semantics written down (profile env,
proxy names stripped). D6: the module allow(dead_code) is kept with the REAL removal condition (a main.rs call site),
and ProcessContainerConfig is pinned field-by-field with a drift test. Reviews: spec PASS (and it CORRECTED plan D5 -
`timeout_ms: None` is `u32::MAX`, i.e. NO deadline, not a 30 s cap; a caller-supplied budget must not be silently
replaced, both now tested) and quality PASS after fuzzing the argv quoting against the real `shell32!CommandLineToArgvW`
(200k inputs, zero argv changes). TEN advisories applied, several load-bearing: launcher rejects proxy-family `--env`
(it could defeat D1), `WaitForSingleObject` checked (a failed wait used to report exit 0), `args_os` (no panic on
non-Unicode argv), empty command/NUL refused before spawn, panic-safe epoch drop, no NULL std handles, and the
CWD-first search order of `lpApplicationName=NULL` documented (a planted `curl.exe` in the session dir was executed in
review - contract-preserving, but callers must pass absolute paths). NEW FINDING recorded as plan D7: `powershell.exe`
exits 0xC0000142 as a container child in this launch shape (cmd/curl work), so S-75/S-77 - which still spawn
`powershell` - will fail under MXC; P2.4/P3 must ship a compiled probe binary instead of switching shells. Gates: 400
tests (feature off) / 447 + 10 launcher tests (feature on), 0 clippy warnings both states, live test passes.

- 2026-10-21: **P1 wave 2 (P1.1/P1.2 completed, P1.3 done).** (A) The real `ProxyProofSource`: `src/net/proxy.rs`
gained `LaunchCounters` (per-epoch `consultations`/`upstream_established`, poison-tolerant lock, bounded epoch
memory, `Send+Sync`) shared with every handler through `ConnCtx`; `impl ProxyProofSource for LaunchCounters` in
`src/net/mxc.rs` maps them to `ProxyProof { accepted, tunnels }`. Counting rules are normative and documented on the
trait: `accepted` = an authenticated CONNECT-or-absolute-form consultation that reached OUR listener (a 407 and an
origin-form request to our own D-4 endpoints are not consultations); `tunnels` = **upstream established**, i.e. the
200 that follows a successful CONNECT dial OR a plain-HTTP forward whose upstream dial came up - so a plain-HTTP-only
session can satisfy `Required` instead of being failed spuriously. That required the listener to actually forward
plain HTTP: absolute-form `http://` is now admitted through the whole D-1 pipeline (loopback refusal, hard-deny,
learned, deny/allow, prompt), dialed with the same DNS pinning, rewritten to origin-form with hop-by-hop headers and
our `Proxy-Authorization` stripped, and relayed byte-wise (`Connection: close`); `https://` absolute-form is refused
(only CONNECT can carry TLS) and origin-form outside `/sandbox/` is still a 400. This changed one existing test on
purpose (`non_sandbox_non_connect_requests_get_400` -> `absolute_form_is_admitted_and_origin_form_outside_sandbox_is_400`).
(B) `build_request` inserts the launcher grant itself (`ensure_launcher_grant`, case/separator-insensitive), so a
caller that omits it still gets a launchable request. (C) `filesystem_policy` builds `denied_paths` from policy.
(D) New plan decision **D8**: mxc-sdk re-injects `networkProxy` verbatim, `url::Url::parse` accepts userinfo, and our
proxy authenticates - so the token rides the proxy URL's userinfo (`http://sandbox:<token>@127.0.0.1:<port>`). The
first live run failed exactly there (`curl: (22) ... 407`, guardrail `SessionNotAccepted`); the fix is one mapping
plus `RequestError::UnsafeProxyToken`. Live evidence (unelevated, `elevated=false`, #[ignore]d): CONNECT leg exit 0
`accepted=1 tunnels=1` through a real local origin on the host's LAN address with the nonce body; plain-HTTP leg exit 0
`accepted=1 tunnels=1` with the child's own `--trace-ascii` showing `GET http://...` and **no** CONNECT; blocked leg
exit 7, proof `0/0`, `MustBeAbsent` passes, origin never saw it; filesystem: granted write OK, denied read/write and
an ungranted path all refused ("Zugriff verweigert"), `C:\Windows\win.ini` readable (caveat recorded). Also learned:
MXC accepts `deniedPaths` entries that do not exist (`.aws/.azure/.gnupg` were absent on this host), so the policy
may deny them unconditionally. Gates: 404 tests (feature off) / 461 + 10 launcher + 2 live (feature on), 0 clippy
warnings in all four build/clippy combos, `cargo fmt --check` clean for both touched files.
- 2026-10-21: **P1 wave 2 REVIEWS FAILED - not committed.** Two independent reviews (spec + security)
both returned FAIL on the plain-HTTP forward path and the filesystem policy. BLOCKING: (1) AUTHORITY
CONFUSION / AUDIT LAUNDERING - the client's `Host` was copied verbatim while admission used the
request-target authority, so `GET http://allowlisted/` + `Host: victim.internal` was admitted and
AUDITED as allowlisted but routed to victim.internal; (2) PRODUCTION PANIC on untrusted bytes -
`&target[..7]` sliced at a fixed offset and a multibyte target panics the proxy task (reachable by the
sandboxed child); (3) SMUGGLING PRIMITIVE - the head was split on `\r\n` in the rewriter but parsed with
`.lines()` elsewhere, so a bare LF let `Connection: upgrade` ride inside another field past the
hop-by-hop filter; (4) UNADMITTED REQUESTS - bytes read past the head were relayed as a second request
with no admission and no audit leaf; (5) P1.3 ORDERING DEFECT - the deny-vs-grant contradiction filter ran
BEFORE the launcher grant was added, so a deny covering the launcher directory shipped; (6) SILENT DENY
DROP - a deny covering a grant (e.g. `%USERPROFILE%` with the workspace inside it) was discarded whole,
leaving Documents/Downloads readable with no warning. The reviews also confirmed what DID hold: counting
semantics (403/502 -> accepted=1/tunnels=0; 407 not counted; origin-form excluded), fail-closed epochs,
D8 token charset and no credential in our own logs, launcher-grant idempotence, and the live evidence
(4 legs, unelevated). New normative decision **D9** records the forward path (Host rewrite, one head
framing, exactly one admitted request, origin 407 -> 502, `tunnels` = upstream established on either
leg); ADR-0004's guardrail-1 definition is amended to match. A security fixer is applying the four
blocking proxy fixes plus two cheap must-fixes (origin 407 -> 502, redacting Debug on the token-bearing
inputs); the filesystem items follow.
- 2026-10-21: **P1.3 filesystem findings fixed (review items 5 and 6, plus three cheap must-fixes).**
  ORDERING: `filesystem_policy` inserts the launcher grant (`ensure_launcher_grant`) *before* it filters
  the deny list, and the policy's `readonlyPaths` is the grant set the filter saw, so a deny of
  `%USERPROFILE%` (or `C:\Users\<user>\tools`) can no longer ship with the launcher grant underneath it;
  `build_request` repeats the coverage check after its own idempotent insertion, so a hand-built
  `MxcFilesystemInput` cannot bypass it either. SILENT DENY DROP replaced by FAIL-CLOSED: a deny equal to,
  or an ancestor of, any grant is the new `RequestError::DenyCoversGrant { deny, grant }` (carrying both
  paths; `RequestError` therefore lost `Copy`), whose Display tells the operator to deny the specific
  subdirectory; denies that are *descendants* of a grant (`%USERPROFILE%\.ssh` under workspace
  `%USERPROFILE%`) keep working. PATH NORMALISATION: `path_key` strips trailing dots/spaces per component,
  collapses `.`/`..`, unifies `\\?\`/`\\.\` (including `\\?\UNC\`) and duplicate separators — still no
  filesystem calls — and `covers` gained direct boundary tests (sibling vs child, trailing dot, UNC vs
  verbatim, empty, drive root). DOC: `ensure_launcher_grant` records the whole-parent-directory exposure
  (`target\debug` for a repo-local build) and the plan's P1.3 row now matches the code: four credential
  subdirs denied, the rest of the profile readable, narrowing decision recorded. Red evidence: removing
  the pre-filter grant insertion fails `a_profile_deny_that_contains_the_launcher_grant_is_refused`;
  restoring the silent drop fails `a_deny_equal_to_a_grant_is_refused` and
  `a_deny_that_is_an_ancestor_of_a_grant_is_refused_and_names_both_paths`.
- 2026-10-21 (round 3): **focused re-review - filesystem PASS, forward path FAIL again.** The filesystem
fixes were verified real (ordering holds on every path including hand-built policies; the silent drop is
now `RequestError::DenyCoversGrant` naming both paths; descendant and unrelated denies still work).
Should-fixes applied, `src/net/mxc.rs` only (red evidence below): UNICODE CASE FOLD - `path_key` folds every
segment with `to_uppercase` (`fold_case`) instead of ASCII lowercase, so `C:\Users\Ä` and `C:\Users\ä` reach one
key and a deny of either covers a grant under the other; `std`'s full-vs-Windows' simple uppercase mapping is
documented as an over-match only (fail-closed: refused, never shipped). ABSOLUTE PRECONDITION - `absolute_path`
resolves cwd and launcher with `std::path::absolute` at both boundaries (`filesystem_policy`, and `build_request`
for its launcher argument) and refuses what it cannot resolve with the new
`RequestError::PathNotAbsolute { what, path }`; a relative launcher used to key as `tools\sandbox` and
`cwd: "."` as empty, so no absolute deny could cover them. `..` ORDERING - a component's trailing spaces are
trimmed before the `.`/`..` test, so `.. ` collapses to the parent instead of trimming to nothing and being
dropped. UNC ROOT TRIM - `split_path_root` (now returning an owned root) trims the server/share components like
every other component, so `\\srv\share.\x` == `\\srv\share\x`. SECOND FILTER - a hand-built policy whose deny is
an *ancestor* of the launcher directory (not equal to it) has its own test, and the live filesystem leg now
*asserts* the launcher grant and all four credential denies instead of only printing the policy. DOC -
`path_key` records what it deliberately cannot compare (8.3 short names, junction/symlink aliases,
drive-relative `C:work`, root-relative `\Windows`, ADS `file:stream`), and `DenyCoversGrant` plus
`filesystem_policy` record the trap: a workspace inside a BUILT-IN credential deny
(`%USERPROFILE%\.ssh|.aws|.azure|.gnupg`) is unlaunchable with no override, so the operator is not left hunting
for a setting they never wrote. RED EVIDENCE - reverting the fold, the absolute resolution, the trim order and
the UNC trim fails 7 tests: `unicode_case_folds_to_one_key_in_both_directions`,
`a_unicode_cased_deny_that_covers_the_workspace_is_refused`,
`a_relative_launcher_is_resolved_before_the_deny_comparison`, `a_relative_cwd_behaves_like_its_absolute_form`,
`build_request_resolves_a_relative_launcher_in_the_command_line`,
`a_dotdot_with_a_trailing_space_still_collapses_to_the_parent`,
`unc_root_components_lose_their_trailing_dots_and_spaces`. FILE GATES: `rustfmt --check` clean, no clippy
warning from `mxc.rs` in either feature state, 431 tests (feature off) / 510 + 10 launcher + 2 live (feature
on), both ignored live tests pass. The FORWARD PATH failed with three NEW blockers, two of them created by
the previous fix: (1) an origin 407 still reaches the client when a `103 Early Hints` precedes it (only
the first head was inspected); (2) one leading CRLF before the status line parses status 0 and bypasses
the check; (3) `Connection: Content-Length` makes the Connection-list strip delete the framing field
while the relay still sends that many body bytes, turning the body into an unadmitted second request
with a client-chosen Host - rules 1, 3 and 4 in one header. Also: `Content-Length : 5` accepted and
forwarded verbatim; `Expect: 100-continue` can stall the relay; the response head is relayed without
`Connection: close` while we close the socket.
  METHOD CHANGE: round 3 fixes under a **strict-reject posture** - accept only boring requests and
  responses; anything unusual (1xx or non-`HTTP/1.` origin head, whitespace in a field name, `Expect`,
  a Connection list naming a framing field) is refused with a named status instead of parsed leniently.
  DECISION POINT: if the next focused review finds another blocker, the forward path is REVERTED to a
  plain 400 (its pre-wave-2 behaviour) and recorded as future work with these findings as its design
  requirements - the plain-HTTP leg is auxiliary to the migration and must not delay P3.
- 2026-10-21 (wave 2 landed): **P1.1/P1.2/P1.3 complete - all reviews PASS after three rounds.** The forward
path took three security rounds (7 blockers, 2 of them introduced by an earlier fix) before the final
PASS; it is now strict-reject: only boring requests and responses are accepted, everything else is a
named 4xx/502. Final round's attacks all held - late-pipelined and trickle-fed smuggled requests never
reached the origin, `userinfo`/`Host` mismatches never moved the authority, ten loopback spellings
refused, nine origin-407 shapes withheld the challenge, multibyte/9 KiB-unterminated heads did not
panic, and refusal counters stayed `{0,0}` with zero audit leaves (proven non-vacuous: `{1,1}` after an
admitted forward). The review also corrected the standing assumption about `Expect`: curl sends
`100-continue` only above 1 MiB, not 1 KiB (measured: 1,048,576 forwards, 1,048,577 is a named 400).
Controller-applied fix after the PASS: `Content-Length: +5` was accepted by Rust's `usize` parser and
forwarded verbatim (a one-head-two-meanings gap); the field is now `[0-9]+` or a 400, with OWS still
legal. Filesystem: Unicode case folding (Ä/ä), absolute-path precondition, `..` trim order and UNC root
trim fixed; `RequestError::PathNotAbsolute` and `DenyCoversGrant` documented including the built-in
credential-deny trap. Gates: 432 (feature off) / 511 + 2 ignored (feature on), 0 clippy both states,
both files rustfmt-clean and uniformly CRLF, both live legs green unelevated.
- 2026-10-21 (P1.4 reviews, both PASS): two advisories were worth acting on before the commit, and one was a
regression the spec review caught. (1) **A foreign token left NO audit evidence.** Pre-P1.4 every bad credential
wrote a `no_token` leaf; the first cut made `Foreign` silent in both chains, with only a `SANDBOX_DIAG`-gated
eprintln - i.e. the one deliberate security event was the only one with no evidence, contradicting this repo's
own rule that security-relevant degradation is not diag-gated. `Foreign` now writes exactly one leaf
(`disposition: deny`, `reason: foreign_token`, `host: <unknown>`, `source: default`) and STILL counts as no
consultation, so guardrail 1 is unaffected; the proxy unit test and all three live legs were updated to assert
`+1` leaf with the reason (the positive control - `Absent` also adds one - keeps the assertion non-vacuous).
(2) `MXC_CONCURRENCY_REFUSED` told the user 'per-run proxy attribution is not implemented yet', which P1.4 made
false; it now says one session per supervisor process and names P1.4. (3) `RunToken::run()` became dead when the
diag line went; it is now `#[cfg(test)]`-gated (the tests use it) rather than `allow(dead_code)`, which would
hide a real dead path later. Recorded, not fixed: the `no_token` leaf flood, `RunToken: Clone` sharing, the
absent/foreign timing delta, the unpinned constant-time property, the untyped env-edge token, and three
live-test honesty gaps - all in row **P1.6**. Plan amended: D8's closing paragraph now records P1.4's answer;
P1.4's token wording states the serial is process-local; P0.5 no longer claims attribution is unimplemented;
P2 gains a requirement to pass `(port, token, counters)` from ONE object.
- 2026-10-21 (P1.5, measurement): the open question was whether env-only proxying is enough, because `mxc-sdk` scrubs every proxy variable except the two it injects and our wrapper supplies only `NO_PROXY`. Measured with 22 legs in real unelevated ProcessContainers (scratch harness, no repo code): a token-gated stand-in proxy that records consultations verbatim, a LAN origin the container cannot reach directly, and native probes (no CLR - see below).
  **Four results, all reproducible.** (1) *env-only works for env-reading clients*: curl with `http_proxy` + `NO_PROXY=127.0.0.1` dialled loopback directly, with `NO_PROXY` cleared it went to the proxy in absolute-form. (2) *the system stacks are forced through the proxy anyway*: `WinHttpOpen(AUTOMATIC_PROXY)` and `(DEFAULT_PROXY)` and `InternetOpen(PRECONFIG)` all consulted the proxy - proven to be container enforcement, not env, by a WinHTTP session told the deliberately wrong proxy `127.0.0.1:1` (its request still arrived at the container's proxy, absolute-form) and by legs with the proxy variables deleted inside the child (identical). (3) *the credential is the only missing piece*: those consultations carry no `Proxy-Authorization` -> **407**; WinHTTP completes 200 + tunnel the moment it is given `WinHttpSetCredentials(PROXY, BASIC)`, while WinINet's pre-emptive `INTERNET_OPTION_PROXY_USERNAME/PASSWORD` are rejected on the session handle and its 407 answer is an interactive prompt. (4) *there is no silent direct path*: raw `connect()` to the LAN target and to `127.0.0.1:<non-proxy port>` both fail with **WSAEACCES 10013** at connect, so `hostLoopback = allow` is not general loopback - the D-4 intent endpoint is reachable only because it shares the proxy's port, which is worth knowing before anyone relies on `NO_PROXY` for a second loopback service.
  **The blocker nobody ordered: the CLR cannot start.** `.NET 8 hello` fails in `coreclr.dll`'s DllMain (`HRESULT 0x8007045A`, exit `0xC0000409`) and `powershell.exe` 5.1 fails with `0xC0000142`, while a native `VirtualAlloc` RW -> `VirtualProtect` RX -> call probe succeeds (so not ACG) and broadening grants to `C:\ProgramData`, `%LOCALAPPDATA%` and `C:\Windows\Temp` changes nothing (so not the filesystem policy). The same `powershell.exe` prints `FXOK` under the AppContainer backend, so it is the ProcessContainer configuration, not the binary. Root cause not determined; the `SocketsHttpHandler` and `UseProxy=$false` legs are therefore recorded as **not runnable**, and no managed GUI or console workload can run under MXC until this is understood - a P3 blocker independent of the proxy question.
  **Decision for P2/P3:** env-only stays for CLI/agent workloads (honest failure mode: 407, never a leak); GUI/system-proxy workloads are scoped **out** of MXC proxy-only mode and stay on the AppContainer backend. Per-user WinINET/WinHTTP configuration is not a viable fix - `HKCU\...\Internet Settings` cannot even be opened for write inside the container (`5 ERROR_ACCESS_DENIED`), `netsh winhttp`/HKLM need admin, `WinHttpSetDefaultProxyConfiguration` is per-process and child-only, and even configured the credential still cannot be delivered. If GUI support ever becomes a requirement the change belongs in proxy *admission* (OS-attested local peer instead of a bearer token), not in client configuration - recorded as its own spike, not a P2 patch. Not run: system-context (`NETWORK SERVICE`) child - needs `SeAssignPrimaryToken`/`SeImpersonate` or stored credentials; and no real browser was launched (that consequence is inferred from the measured WinINet path). Evidence and per-client table: `docs/backends/process-container/winhttp-proxy-path.md`.
- 2026-10-21 (P1.8, measurement): P1.5 recorded the `.NET`/`SocketsHttpHandler` legs as *not runnable* because no CLR would start; P1.7 showed that was the `ui.disable` default, not the primitive, so they were re-measured rather than trusted.
  **Instrument, in two halves.** A scratch harness (`p18`, same request shape as `build_request` incl. `ui.disable = false`) with a stand-in listener that records each consultation *in order and with or without `Proxy-Authorization`*, refuses loopback, forwards absolute-form and tunnels `CONNECT` to a real TLS origin - 15 legs. Then the same questions against the **real** `net::proxy::spawn` listener, as an `#[ignore]`d live leg asserting on `LaunchProofCounters` - 7 legs, green.
  **The 407 is the hinge.** .NET 8's `HttpEnvironmentProxy` does read `HTTP_PROXY` (and `NO_PROXY`), but it does **not** send the userinfo credential pre-emptively: connection 1 is unauthenticated -> `407 Proxy Authentication Required` + `Proxy-Authenticate: Basic`, connection 2 carries the credential -> 200. Measured on both listeners; the real one reports `accepted: 1`, not 2, because `AuthVerdict::Absent` is a refusal it does not count. HTTPS works the same way through `CONNECT` (tunnel established, `P18TLSOK` read over TLS). `pwsh` 7 is the same code path; `Invoke-WebRequest` there returns 200 unchanged.
  **PS 5.1 is the outlier, and it is worse than P1.5 recorded.** `[System.Net.WebRequest]::DefaultWebProxy` is `WebProxyWrapper` (the WinINet/IE view, "direct" in the container), so `Invoke-WebRequest` never consults the proxy — no 407, no consultation, just `WSAEACCES 10013` from its own WinSock connect. `WebProxy(new Uri(...userinfo...))` also fails (userinfo is not lifted into `Credentials`; the 407 reaches the caller), while `WebProxy{Credentials=...}` works — so the stack *can* carry the credential, just not from a proxy URL.
  **Two consequences worth carrying into P2/P3.** (1) `NO_PROXY=localhost,127.0.0.1,::1` means a managed client bypasses the proxy for loopback: any loopback port is `10013`, and the proxy's own port is reached in origin-form with no credential -> 407, so the loopback intent endpoint is not reachable by URL from a .NET workload. (2) Each managed connection now writes one benign `deny/no_token` audit leaf (the 407 attempt) — exactly the flood P1.6(a) is about, but now as steady state rather than an adversarial case.
  **Decision:** managed egress through the supervisor proxy is **usable today for CoreCLR clients** (.NET 8 `HttpClient`, `pwsh` 7) and **not** for .NET Framework/Windows PowerShell 5.1 or for `WebProxy(uri-with-userinfo)`; the platform-side options are to require `pwsh` 7/.NET 8 for managed workloads, or to make the P1.5 admission change (OS-attested unauthenticated local peer), which would also remove the 407 round-trip and the `no_token` leaves. Full table and error texts: `docs/backends/process-container/winhttp-proxy-path.md`.
