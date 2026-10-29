# Gradle in the sandbox — loopback egress for same-session listeners (Implementation Plan)

**Goal:** `gradlew build` (and any toolchain with the same shape — Maven's daemon, a test fork
that talks to a harness over TCP, a language server the build starts) runs **inside** a `mxc`
session, unelevated, without giving the workload a general path to host loopback.

**Architecture (one paragraph):** the session's container policy gains an **address-scoped,
port-scoped loopback egress allowance** — `egress.allow = 127.0.0.1/32 : <port>` — so the child's
`connect()` to a loopback listener is permitted by the kernel while Docker (2375), Ollama (11434),
DevTools and other agents' proxies stay unreachable. Because the Gradle daemon's port is ephemeral
by default, the supervisor **pins** it (one free port per session, chosen and proven before launch)
and hands it to the child through `org.gradle.daemon.port` + `org.gradle.daemon.registry.base`, so
the allowance is a fixed single-port rule instead of a 28 000-port range. The supervisor does not
relay the daemon traffic: the daemon is the session's own child, the connection is loopback, and a
relay would add a hole (a byte-stream tunnel through the supervisor) without adding a control.

**Tech stack:** existing crate, no new dependencies. `mxc-sdk =1.0.1`'s `NetworkEgress.allow`
rules (`contract::NetworkEgressRule`), `src/net/mxc.rs` request mapping, `src/net/mod.rs` policy
resolution, `src/bin/saife-launch.rs` `--env`, the built-in `GetExtendedTcpTable` + ToolHelp
ancestry walk already used in `src/plugin/sidecar.rs`.

**Evidence this plan is built on:** `docs/research/backends/process-container/winhttp-proxy-path.md`
(loopback refused at `connect()` with `WSAEACCES 10013`), `docs/FAQ.md` ("Gradle builds do not run
under the default backend", four measured `--no-daemon` configurations), `profiles/README.md` (the
`jvm` profile and its recorded limitation), and the TNG engineering blog post *"Letting your agent
run gradle while inside a sandbox"* (2026-09-25), which reaches the same wall from the omac/nono
side and solves it by moving the build out of the sandbox entirely. See §2 for why that conclusion
does **not** carry over to this backend.

---

## 1. Why this is a different problem on Windows than on Linux

The blog's blocker is two-layered, and only the second layer applies here:

| # | Landlock (omac / nono) | MXC `processcontainer` (saife) |
|---|---|---|
| 1 | **Port-scoped, not address-scoped.** Allowing a connect port allows it on *every* host, so a port allow-list is network isolation with extra steps. | **Not true here.** MXC egress rules are per-CIDR **+ port + protocol** (`docs/research/mxc-source-analysis.md:91`). `127.0.0.1/32` + one port is expressible, and it is strictly narrower than anything Landlock can say. |
| 2 | The daemon binds port 0, so the port is ephemeral per run and per worker; covering the client side needs the whole ephemeral range. | **Also true here**, but this one is solvable *outside* the kernel policy: Gradle accepts a pinned port (see §1.1), so the rule can name one port. |

So the blog's conclusion — *"if Gradle can't run inside the sandbox, it has to run outside"* — is
correct for Landlock and **not forced** for a backend that can scope by address. What is left is one
mechanical question (§5, S-1) that must be answered by measurement before any product code is
written.

### 1.1 Can Gradle be pinned to a port? Yes — with two knobs, not one

`org.gradle.daemon.port` pins the port, but the client does not dial that port directly: the chain is

```
client JVM → <registry base>/<version>/registry.bin → daemon 127.0.0.1:<port>
```

`registry.bin` is written by whichever daemon started, is keyed on the daemon's JVM arguments, and
lives in `~/.gradle/daemon` by default — which in this sandbox is a **shared, read-write grant**
(`profiles/jvm.json`). Without pinning the registry base, a daemon started by an earlier session (or
by the host, outside the sandbox) can be discovered, and its port is one the session's policy does
not allow. Therefore:

| knob | where | why it is load-bearing |
|---|---|---|
| `org.gradle.daemon.port=<P>` | `GRADLE_OPTS` (client JVM args, inherited by a forked daemon) | the port both sides use |
| `org.gradle.daemon.registry.base=<session dir>` | `GRADLE_OPTS` | the registry the client reads, so no foreign daemon is discovered and no session inherits another's port |
| `org.gradle.daemon.idletimeout=<ms>` | `gradle.properties` / `GRADLE_OPTS` | bounds how long the daemon outlives the build inside the session window |
| `GRADLE_USER_HOME` | env | a copy-in of `daemon/` into a session-local home removes the cross-session reuse trap entirely; the wrapper dists and caches still come from the granted `~/.gradle` (read-write, hashed by exact `distributionUrl`) |

`--no-daemon` and `org.gradle.daemon=false` are **not** part of this plan: both were measured to
fork a disposable daemon anyway (`docs/FAQ.md:240-255`, and the blog reports the same with
gradle/gradle#16110, #16435, #25272).

---

## 2. Rejected alternatives (with the reason each one loses)

| alternative | why not |
|---|---|
| **Docker/Compose build container + Squid allow-list** (the blog's solution) | Violates the project's defining constraint: `AGENTS.md` — native Windows primitives, *"no container runtime, no daemon, no VM"*. It also duplicates the session proxy (Squid) and loses per-session audit attribution, and a container shared by sessions turns a granted folder into an unattributed side channel. Recorded as prior art, not adopted. |
| **Sidecar relay (supervisor tunnels the daemon protocol)** | The daemon is the session's own child and the connection is loopback; a relay must therefore be an opaque bidirectional byte tunnel through the supervisor — a *hole* in proxy-only egress with no control of its own, plus a new audit op and its own refusal taxonomy. Only worth it if §5 S-1 comes back red or if the daemon must live outside the container (§6.5). |
| **`--backend appcontainer`** | Works today (per-SID loopback exemption), but requires elevation and exempts the SID for **all** loopback on the host. Stays the documented escape hatch; it is not the answer for the default backend. |
| **Allow a port range / all of `127.0.0.0/8`** | A policy widening with no bound on *which* loopback services are reachable, and — unlike a single pinned port — it is not explainable in one line of the audit or the CLI. Range support is a follow-up knob (§4 T3.4), never the default. |
| **In-client build (`org.gradle.daemon=false`) / matching JVM args** | Measured dead end on both projects; re-litigating it is out of scope by decision. The plan must *not* claim it works. |
| **WFP callout driver (F-6)** | The real long-term answer (per-process, per-port), but it is a kernel driver: admin install, signing, out of MVP scope. Recorded as the end state this design should be replaceable by. |

---

## 3. Invariants this change must keep

1. **The proxy keeps refusing loopback targets.** `decide()`'s `loopback_refused`
   (`src/net/proxy.rs:1482`) and the pinned-address leg (`src/net/proxy.rs:1846`) stay as they are.
   Loopback reachability comes from the container policy, never from the listener — otherwise an
   allow-listed hostname that resolves to `127.0.0.1` becomes an SSRF path through the proxy.
2. **Egress stays `default = deny`.** The loopback allowance is one explicit `allow` rule with one
   CIDR and one port. No posture change for anything else.
3. **Guardrail 1 is unchanged.** A loopback-only session still proves what it claims: with a proxy,
   the wrapper's authenticated `GET /sandbox/probe`; without one, `ProofExpectation::MustBeAbsent`
   stays satisfiable (a loopback-only session is *not* a network session for this gate — that
   distinction must be explicit in `ProofExpectation::for_network`, see T2.4).
4. **The allowance is a session-start fact.** Whatever widens the child's reach must be visible in
   the audit root and on stderr, in the same place `proxy_endpoint` and `tier` already are.
5. **No new default.** A profile that says nothing gets today's byte-identical request; a loopback
   allowance is always the operator's explicit line (or an explicit `--allow-loopback` flag).
6. **`appcontainer` does not silently widen.** That backend's exemption is all-or-nothing per SID;
   a port-scoped request there is either refused by name or accepted as *all* loopback with a
   warning and an audit fact — decided in T2.5, never left implicit.

---

## 4. Phases and tasks

Every code task is TDD (red first, byte-identical restore verified), every phase ends with the
standing gates: `cargo test --bin saife` in **both** feature states, `cargo clippy` 0, rustfmt,
CRLF preserved, live `#[ignore]` legs run against a freshly built `target/debug/saife.exe`.

### S-0 — Measurement (blocking gate; no product code before this is green)

- [ ] **S0.1** Two legs in `tests/vm/spikes/mxc-ga-spike/src/main.rs`, request built by the
      production shape (`model2_request`, `:146`):
      - **A** `egress.allow = [{cidr: 127.0.0.1/32, ports: [P]}]` **without** `runtimeConfig.networkProxy`;
      - **B** the same **with** `runtimeConfig.networkProxy` (what Gradle actually needs: dependencies
        *and* the daemon in one session).
      Each leg: a host-side listener on P; `cmd /c` child tries `connect()` to `127.0.0.1:P` and to a
      second loopback port `Q` that is **not** allowed. Expect `P` reachable, `Q` refused with
      `WSAEACCES 10013` — the negative is what proves the rule is port-scoped and not a general
      loopback grant.
- [ ] **S0.2** Record whether the proxy-shaped request (B) is **accepted** or refused
      `malformed_request`. `docs/research/mxc-source-analysis.md:114-116` claims PSEC proxy mode is
      *"mutually exclusive with direct egress rules"*; at `1.0.1` this may or may not hold, and the
      PSEC-1.0 identity-less workaround
      (`docs/research/wbd-d02-capability-matrix.md:55`, `:176`) may change the answer.
      **This single result decides between §5 T3 (native) and §6.5 (relay fallback).**
- [ ] **S0.3** Write the result into `docs/research/backends/process-container/loopback-egress.md`
      (new file, same shape as `winhttp-proxy-path.md`: method, legs, table, mechanism), and cite it
      from ADR-0005. A negative result is a recorded result, not a failed spike.
- [ ] **S0.4** Promote the two shapes to `#[ignore]` live legs in `src/net/mxc/live.rs` so a later
      SDK bump cannot quietly change the answer.

**Exit criterion:** both legs measured, the exclusivity question answered, and — if the answer is
"proxy mode and egress rules cannot coexist" — a decision recorded in this plan before T3 starts.

### S-1 — Profile and CLI surface (policy, both backends)

- [ ] **T1.1** `src/profile.rs`: new `network.loopback` object in `NetworkSlice`
      (`deny_unknown_fields` stays): `{ mode: "deny" | "ports" | "allow", ports: [<u16> | "auto"] }`.
      Default absent = `deny` = today. Validation: `ports` refused under `mode: "deny"`, refused
      empty under `"ports"`, refused outside `1..=65535`, `"auto"` at most once, cap the list length
      (e.g. 8) so a profile cannot become an allow-everything document by volume.
- [ ] **T1.2** CLI: `--allow-loopback <PORT|auto>` (repeatable) on `run`, merged with the profile the
      way `--allow-domain` is; a session with no network flags is unaffected.
- [ ] **T1.3** `src/net/mod.rs::resolve_network_with`: resolve to a new
      `LoopbackPolicy { Deny, Ports(Vec<u16>) }` carried by **both** `NetworkConfig::Allow` **and**
      `NetworkConfig::Blocked` — a local-server test is a legitimate `--block-net`-plus-loopback
      posture, and forcing a proxy on it would be a surprising coupling.
- [ ] **T1.4** Port allocation for `"auto"`: bind `127.0.0.1:0`, read the assigned port, **hold the
      listener** until the container is created, then close it (a bind-then-close-then-launch
      sequence has a TOCTOU window in which another process can take the port; holding the socket
      until the last responsible moment shrinks it to the launch itself). A second `"auto"` gets a
      second port. Measured, not assumed: log the picked port and the listener's lifetime in
      `SAIFE_DIAG`.
- [ ] **T1.5** `src/net/profile.rs` + `profiles/jvm.json` + `profiles/README.md`: the `jvm` sample
      gains the loopback stanza **only after** S-0 is green; until then the README keeps its honest
      "does not run under the default backend" paragraph.
- [ ] **T1.6** `appcontainer` decision (invariant 6): `mode: "ports"` is refused by name with a
      remedy (`--backend mxc`, or `mode: "allow"` which is *all* loopback for that SID), and
      `mode: "allow"` prints the warning + writes the audit fact. Rationale: an all-or-nothing
      exemption must never be described as port-scoped.

### S-2 — MXC request mapping (the enforcement)

- [ ] **T2.1** `src/net/mxc.rs::build_request`: build `egress.allow` from the resolved ports instead
      of `Default::default()` (`:2146`):
      `NetworkEgressRule { cidr: 127.0.0.1/32, ports: [P1..Pn], protocol: tcp, action: Allow }`
      (the exact contract shape is S-0's finding, not a guess). IPv6 `::1/128` is deliberately
      **not** in this phase: Gradle binds IPv4 loopback, and adding a second CIDR doubles the rule
      surface for a case nobody has measured. Tracked in T3.5.
- [ ] **T2.2** `MxcNetworkInput` gains the resolved `LoopbackPolicy` (pure data, so the mapping stays
      unit-testable with no container). Tests: absent → `allow` stays empty (byte-identical request to
      today, asserted as a whole-struct comparison); `Deny` + a port in the profile → refusal, not a
      silent downgrade; `Ports([P])` → exactly one rule, exactly that port.
- [ ] **T2.3** `src/net/mxc.rs::launcher_command` / `src/bin/saife-launch.rs`: deliver the pinned
      port(s) to the child as `--env GRADLE_OPTS=…` (the wrapper's reserved-name list must stay
      unchanged: `GRADLE_OPTS` is not a proxy variable) **and** a discovery variable
      `SAIFE_LOOPBACK_PORTS=<p1,p2>` next to `SAIFE_PROXY_PORT`, so a workload written to the D-0.3
      contract can find them without string-parsing an unrelated tool's options.
- [ ] **T2.4** `ProofExpectation`: a loopback-only session (no proxy port, `Ports` non-empty) must
      **not** be classified as a network session for guardrail 1 — `MustBeAbsent` is the correct
      posture and a `Required` classification would refuse a session that was never meant to egress.
      A session with **both** a proxy and loopback ports keeps `Required` (the proxy proof stands).
      Test both shapes, and one mixed shape.
- [ ] **T2.5** The allowance is a **root fact**: `SessionStart` carries `loopback_ports: [u16]` and
      `loopback_source: "profile" | "cli" | "auto"` alongside `proxy_endpoint`, plus one stderr line
      (`[saife] loopback: 127.0.0.1:PORT (auto) — reachable from the child`). `KNOWN_KEYS` in
      `src/audit/filter.rs` updated in the same change, and a grep-test that no other leaf invents a
      second spelling.
- [ ] **T2.6** Tier/refusal interaction: a host whose PSEC rejects egress rules (fallback to a lower
      tier) must fail the session by name (`loopback_egress_unsupported`) rather than launch without
      the allowance — a silent drop would reproduce exactly the "Gradle cannot connect but the
      session looks fine" failure this plan exists to remove.

### S-3 — Gradle recipe and pinning (the part the operator uses)

- [ ] **T3.1** `profiles/jvm.json` gains, **guarded by S-0**, `network.loopback: {mode: "ports",
      ports: ["auto"]}` and a documented `inject` stanza is **not** added: the plan deliberately does
      not put toolchain-specific knobs in the profile schema (that is how profiles rot). The
      supervisor sets `SAIFE_LOOPBACK_PORTS`; the *recipe* (documentation) says how to translate that
      into `GRADLE_OPTS`.
- [ ] **T3.2** `_gradle-inside.ps1` recipe in `docs/FAQ.md`, rewritten from the current
      `--backend appcontainer` recipe: derive the port from `SAIFE_LOOPBACK_PORTS`, set
      `GRADLE_OPTS` = proxy props (`JAVA_TOOL_OPTIONS`, not `GRADLE_OPTS`, for proxy props — the JVM
      ignores `HTTP_PROXY`, and a forked daemon must inherit them too) **plus**
      `-Dorg.gradle.daemon.port=<p>` + `-Dorg.gradle.daemon.registry.base=<session temp>` +
      `-Dorg.gradle.daemon.idletimeout=<bounded>`. Two traps the recipe must state: `[Uri].UserInfo`
      instead of `.UserName` (PS 5.1), and that a forked daemon inherits `GRADLE_OPTS`.
- [ ] **T3.3** Prewarm the wrapper distributions **outside** the sandbox, documented as a step, not
      automated: the session proxy sees only CONNECT hostnames, so `services.gradle.org` →
      GitHub release assets is a blind spot for any allow-list; `GRADLE_USER_HOME=$HOME/.gradle
      ./gradlew --version` once per distinct `distributionUrl` (the install dir is a hash of the URL
      string, so `-bin` vs `-all` and mirrors differ) removes the download from the session
      entirely. Same class of advice for `npm`/`maven`.
- [ ] **T3.4** Range support, only if asked: `ports: ["auto", {range: [9000, 9010]}]` → one rule per
      port, capped. Recorded so the schema does not have to change later.
- [ ] **T3.5** `::1/128` support, gated on a measurement (a JVM that binds IPv6-only loopback).

### S-4 — Proof: it is really the daemon, and really scoped

- [ ] **T4.1** `#[ignore]` live leg (`src/net/mxc/live.rs`): a real ProcessContainer, a real Gradle
      build. A tiny fixture project (`tests/fixtures/gradle-smoke`, wrapper pinned to a prewarmed
      distribution) runs `gradlew --offline build` inside the session; asserts exit 0, the daemon
      started on the pinned port, and `SAIFE_DIAG` evidence of the loopback rule. `--offline` so the
      leg does not depend on the network; dependency resolution is T4.3.
- [ ] **T4.2** The **negative** live leg, which is the security claim: in the same session, a
      listener on a *different* loopback port is **refused** at `connect()` (`10013`). Without this
      leg, "port-scoped" is a comment.
- [ ] **T4.3** A leg with dependencies: `gradlew build` against the allow-listed repositories,
      proving the proxy leg and the loopback leg coexist (this is S-0's leg B at product level).
- [ ] **T4.4** Freshness guard as in the existing live legs (refuse to run against a `saife.exe`
      older than `src/`), because a stale binary silently inverted a previous RED probe.
- [ ] **T4.5** Harness: a scenario in `tests/run-tests.ps1` for the **refusal** paths that need no
      container (profile validation, the `appcontainer` refusal, the audit root fact), and the
      classification note that the loopback *mechanism* is backend-specific so the mxc-only legs
      SKIP with a named reason under `--backend appcontainer`.

### S-5 — Documentation, decisions, and the honest limits

- [ ] **T5.1** New **`docs/adr/0005-loopback-egress-scoping.md`**: address-scoped loopback on MXC vs
      Landlock's port-only rules (§1), the pinned-port mechanism (§1.1), the rejected alternatives
      (§2), the invariants (§3), and the explicit statement that **the allowance is port-scoped, not
      owner-scoped** — see the risk below, which is the single most important sentence in the ADR.
- [ ] **T5.2** Amend `docs/adr/0004-mxc-ga-windows-unelevated-egress.md` (the posture it records is
      no longer "loopback only to the proxy") and `docs/adr/0001` (G-44's rationale becomes
      "loopback is not reachable *by default*").
- [ ] **T5.3** `docs/FAQ.md`: replace the "Gradle cannot work under `mxc`" answer (and the
      `appcontainer`/two-session workaround it currently recommends) with the new recipe, keeping
      the measured `--no-daemon` evidence and the `appcontainer` escape hatch as fallbacks.
      `profiles/README.md` and `AGENTS.md` (the backends section) updated in the same sweep.
- [ ] **T5.4** Record the omac comparison: the blog's Docker+Squid design and why saife does not
      adopt it (§2), in the ADR's "alternatives", so the next reader does not re-derive it.
- [ ] **T5.5** `docs/DEVELOPERS.md` §6 (invariants) gains "a widening is a root fact"; the repository
      map gains nothing (no new module) — worth stating explicitly so a reviewer does not look for
      one.

---

## 5. The risk this design does NOT remove (must be stated, not hidden)

**A port-scoped allowance is not an owner-scoped allowance.** Windows grants the container's token
the right to *connect to that port on loopback*, not the right to connect *to this session's own
listener*. Consequences, all of which must appear in ADR-0005 and in the session's stderr line:

1. **A hijack race.** Between the supervisor releasing the auto-allocated port and the daemon
   binding it, another same-user process could bind it first and receive the build's traffic
   (including source paths and, if it is a proxy, credentials meant for the daemon). Mitigations in
   this plan: hold the listener until the launch (T1.4), prefer an explicitly pinned port for
   unattended runs, and record the port in the audit root so a suspicion can be checked afterwards.
   A real fix needs owner identity at connect time — WFP keyed on the PID set (F-6) — which is the
   stated end state, not this phase.
2. **Another session on the host can reach the same port** if it happens to be allowed there too
   (two sessions each with `"auto"` will pick different ports, but a profile naming a fixed port
   twice is a collision the operator created). Detected, not prevented: a bind failure on a pinned
   port is a session refusal with that explanation.
3. **Loopback is where the host's privileged surfaces live.** The allowance is one port, so Docker,
   Ollama, DevTools, SSH agents and other agents' proxies are *not* reachable — but a host process
   that happens to listen on the chosen port **is**. Hence: the port must never be guessable-by-
   default for an unattended run, and `mode: "auto"` must log the chosen port loudly.
4. **Same-session containment of the daemon is not implemented here.** The daemon is a child of the
   workload, so it inherits the container's filesystem policy — which is the desired answer (it can
   write `build/`, it cannot read `.ssh`). It is *not* separately sandboxed with its own policy, so a
   daemon that outlives the container (idle timeout) is a process the container no longer contains.
   Bounded by `org.gradle.daemon.idletimeout` (T3.2) and by the session deadline; stated in the ADR.

---

## 6. Open questions to settle before or during the phases

1. **S-0 leg B (proxy + egress rules).** If refused, the native plan is unavailable for sessions
   that need *both* dependency downloads and the daemon. Options then: (a) prewarm **everything**
   (wrapper + dependency cache) outside the session and run the build `--offline` with a
   loopback-only policy — viable for a warm cache and honestly documented; (b) split the build into
   a fetch session (proxy, no loopback) and a build session (loopback, no proxy) sharing `~/.gradle`
   — ugly but auditable; (c) the relay fallback (§6.5).
2. **Two daemons at once.** Parallel `gradlew` invocations, or a build that forks a disposable daemon
   while a long-lived one runs, need two ports. `ports: ["auto", "auto"]` covers it; the recipe must
   tell the child which is which, which Gradle does not support (one `org.gradle.daemon.port` per
   client JVM). Accepted limitation: a build that needs two simultaneous daemons needs `mode:
   "allow"` or explicit `["ports"]` including a range — documented, not solved.
3. **`GRADLE_USER_HOME` copy-in vs. shared `~/.gradle`.** Copy-in is cleaner (no foreign registry)
   but copies a cache that is frequently ~GBs. Decide per machine: the plan's default is *shared
   `~/.gradle` with a pinned registry base*, and copy-in is documented as the belt-and-braces
   variant.
4. **What else wants the same allowance.** Local-server tests (Spring Boot + curl in one session),
   Maven's daemon, `sbt`, `npm run dev` + browser tests, and language servers the build starts. The
   mechanism is generic on purpose; the plan names Gradle first because it is the measured case, and
   §4 T3.4/T3.5 are the generic extensions.
5. **Relay fallback, if S-0 lands red and prewarm/offline is not enough.** Then — and only then — a
   supervisor-owned relay becomes worth its cost, and it must be built as its own decision: a new
   transport (opaque bidirectional stream), a new audit op, a destination allow-list, per-session
   tokens, and the same "no transparent proxy" rule that governs `plugins/`. It must **not** be
   implemented by widening the facade (which is `GET`-only plain HTTP by rule,
   `src/net/proxy.rs:3438`) nor by reusing a plugin sidecar (whose egress is the supervisor's own,
   unrestricted).

---

## 7. Files likely to change

```
src/profile.rs                 network.loopback slice, validation
src/net/mod.rs                 resolve_network_with, LoopbackPolicy
src/net/mxc.rs                 build_request (egress.allow), launcher env, proof classification
src/net/mxc/tests.rs           pure mapping tests (byte-identical default, one-rule port)
src/net/mxc/live.rs            S-0 promoted legs, T4.1/T4.2/T4.3 live legs
src/main.rs                    allocation lifetime, root facts, stderr line
src/cli.rs                     --allow-loopback
src/sandbox/appcontainer.rs    refuse port-scoped / warn on allow (T1.6)
src/audit/session_start.rs     loopback_ports / loopback_source
src/audit/filter.rs            KNOWN_KEYS
src/bin/saife-launch.rs        SAIFE_LOOPBACK_PORTS, --env passthrough
tests/vm/spikes/mxc-ga-spike   S0.1 legs
tests/run-tests.ps1            refusal scenarios, mxc-only skip reasons
tests/fixtures/gradle-smoke    the fixture project for T4.1
profiles/jvm.json,
profiles/README.md             the sample profile + its honest limits
docs/adr/0005-loopback-egress-scoping.md
docs/adr/0001-…, 0004-…         amended in place, superseded rule kept visible
docs/research/backends/process-container/loopback-egress.md
docs/FAQ.md, docs/DEVELOPERS.md, AGENTS.md
docs/tasks/gradle-loopback/PROGRESS.md
```

## 8. Verification

- **Unit:** profile validation matrix; `Deny`/`Ports`/`auto` resolution; the default request stays
  byte-identical (whole-struct comparison, not a field spot-check); exactly one rule for one port;
  proof classification for the three postures (proxy only, loopback only, both); audit root keys.
- **Live (`#[ignore]`, unelevated):** `gradlew --offline build` inside a real container (T4.1); a
  different loopback port refused with `10013` (T4.2, the security claim); a build with dependencies
  through the proxy (T4.3); the launch record confirming the root's `loopback_ports`.
- **Audit:** `saife audit show <sid>` shows `loopback_ports`/`loopback_source` in the root and no
  other leaf invents a spelling; `audit verify` OK; a killed session leaves the root with the fact.
- **Refusals:** a profile asking for ports under `mode: "deny"`; an empty list; a port outside range;
  `appcontainer` with `mode: "ports"`; `--block-net` + loopback (allowed, and *not* a network session
  for guardrail 1).
- **Host clean:** `tests/Clear-HostTestArtifacts.ps1` stays `HOST-CLEAN`; the loopback socket is
  closed on every exit path (asserted by binding it again after the session).
- **Doc sweep:** grep for the old claim ("Gradle builds do not run under the default backend") to zero
  matches outside the amended history sections.

## 9. Out of scope

- Undo/rollback and credential injection (project non-goals).
- WFP/driver-level per-process loopback (F-6) — the stated end state that replaces this design.
- A Docker/WSL build container (rejected in §2).
- Relay transport (only as §6.5, as its own plan).
- A generic "allow any local port" flag with no port list: `mode: "allow"` exists only for the
  AppContainer backend, where per-port scoping is impossible, and it always warns and audits.
- Auto-detecting the daemon's port by watching the child's sockets (`GetExtendedTcpTable`): an
  interesting detective control, deliberately not the mechanism — a policy that flips after the
  fact is not a policy. Kept as a possible *verification* leg (assert the daemon bound the port we
  allowed) rather than as an enforcement path.
