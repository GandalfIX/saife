# Gradle build runner — a facade sidecar that builds in a container (Implementation Plan)

> **Status:** proposal, 2026-10-30. **Nothing is implemented.** S-0 is partly measured
> (`docs/research/build-runner/measurements.md`): endpoint, container lifecycle and mount
> throughput are answered, and the mount answer **changed §4** - the project is synced into the
> runner, not bind-mounted. Still open and still gating: facade streaming (S0.1), container ->
> proxy reachability (S0.4), and the Gradle daemon cost that decides long-lived vs ephemeral
> containers.

**Goal:** `gradlew build` runs inside a saife session on Windows, unelevated, **without**
granting the workload loopback, without a new inbound path, and without a new privileged
channel it can drive.

**Architecture (one paragraph):** the build does not happen in the session. A sidecar (the
*runner*) builds in a container or VM, and the session reaches that sidecar through the
**supervisor's existing proxy facade** — `FacadeTarget { mount, port, token, operations }`,
already implemented for plugin sidecars, where the proxy refuses any `(method, path)` the
manifest did not declare with `403 facade_operation_not_declared`. The runner holds the
policy, not the workload: a pinned image digest, a fixed mount set (the project directory
read-write plus a private cache volume), one declared verb, no docker socket, no image or
flag parameters. Builds are served from a **warm slot** — a pre-booted runner with the JDK,
the Gradle distribution, a populated dependency cache and a live Gradle daemon — so a build
costs an attach (sub-second), not a boot. Gradle's daemon/worker loopback never reaches
saife's network policy, because it does not happen in the session.

**Tech stack:** existing facade (`src/plugin/sidecar.rs`, `src/plugin/mod.rs`), the proxy's
declaration check, a new `src/runner/` module, Docker Desktop / Podman machine / a bare WSL2
distro as the substrate (chosen by S-0, not by taste), no new Rust dependencies beyond a
substrate client.

---

## 1. Why the facade, and not a loopback port

Measured on this host, 2026-10-30 (`docs/research/backends/process-container/opencode-desktop-windows.md`):

| leg | result |
|---|---|
| container → its own `127.0.0.1` listener | `10013` AccessDenied |
| container → own listener, proxy session | `10013` AccessDenied |
| host → container listener | connect times out (socket visible in host TCP table) |

Loopback is closed in **both** directions under `mxc`. A runner that the session reaches over
`127.0.0.1:<port>` would therefore need the sibling plan's egress work **and** an inbound hole
that MXC 1.0.1 does not offer. The facade needs neither: the workload makes an ordinary HTTP
request to the proxy it is already allowed to reach, and the proxy routes it by mount.

Three properties come for free and are the reason this is worth doing at all:

1. **No new enforcement primitive.** The 403-on-undeclared-operation check already exists and
   is tested (`src/plugin/mod.rs:176-179`).
2. **Auditability.** Every build request is a proxy request, so it lands in the session's
   audit chain by construction — not by a second logging path that can drift.
3. **One channel, one token.** The runner token is per session and scoped to that mount, so a
   leaked build token is not a leaked network token.

**Caveat that must be measured (S0.1):** the facade has only been used for short
request/response exchanges. A build emits logs for minutes. The proxy's `HEAD_READ_TIMEOUT`
(15 s) covers reading the request head, not the response body — but nobody has proven a
10-minute streaming response survives it, the connection cap (`MAX_INFLIGHT_CONNECTIONS`), or
the client's own read timeouts. If a build log cannot stream, this plan needs a different
transport and §9 changes before any code is written.

## 2. The contract: the runner is policy, not an executor

If the workload can name the image, the command, the mounts or the flags, the sidecar is a
sandbox escape with a JSON API — `docker run -v C:\:/host`, `--privileged`, or a mount of
`\\.\pipe\docker_engine`. So the request carries **only** what the user legitimately chooses:

| field | from the workload | validation |
|---|---|---|
| project | the session's own CWD | must resolve to the session workspace; no reparse point, no UNC, no `..` |
| task | `build`, `test`, `assemble`, … | matched against an allow-list pattern, never passed to a shell |
| profile | name | must exist in the runner's table |

Everything else is a **runner-side constant**, compiled into the runner and pinned in the
image reference: image digest, mount list, environment, CPU/memory caps, network mode, user
id inside the container, and the wrapper invocation. There is no field for any of them, and a
test asserts the request struct has no such field — a future "convenience" parameter is how
this becomes a bypass.

Rejected shapes, recorded so they are not re-proposed: a generic `POST /exec` (escape), a
mounted docker socket (root-equivalent by definition), and letting the profile JSON carry the
image digest (a profile is user-editable; the digest must come from the shipped binary).

## 3. Latency: the engine is assumed up, the daemon is not

**Assumption (2026-10-30, user), now measured on the development machine:** the container
engine's VM is already running, so no design decision here is about booting a VM. Engine-down
is an explicit *state*, not a delay we absorb.

| fact | value |
|---|---|
| engine | Rancher Desktop **29.5.3**, `Rancher Desktop WSL Distribution`, linux/x86_64 — dockerd/moby, not containerd |
| client | `29.6.2-rd`, `C:\Program Files\Rancher Desktop\resources\resources\win32\bin\docker.exe` |
| endpoint | `npipe:////./pipe/docker_engine` — the only context (`default`) |
| trap | `Test-Path \\.\pipe\docker_engine` returns **False** while the API answers fine |

That last row is a design constraint: endpoint discovery must be a real API call (`/_ping`,
then a version negotiation), never a path existence check.

Starting a container is not one cost, and only one of the rows is about containers at all:

| step | measured on this host | when it is paid |
|---|---|---|
| `docker info` reachability probe | **93 ms** | every build |
| `docker run --rm` (create+start+remove) | **497 ms** | only if the container is ephemeral |
| `docker start` of a stopped container | 37 ms | only if the container is ephemeral |
| `docker exec` into a running container | **73 ms** | the long-lived shape |
| sync 20 k files in or out (tar pipe) | **2.8 s** each way | every build, unless the volume is persistent and synced as a delta |
| JVM + Gradle daemon start (ephemeral container, same volumes) | **4.95 s** warm page cache / 13.6 s first | every build if the container is ephemeral |
| same build, daemon already alive (long-lived container) | **1.67 s** | the long-lived shape |
| first build ever (downloads distribution + deps, 904 MB) | **88.6 s** | once per image, moved to image build time |
| Gradle configuration + execution | the build | — |

The engine is cheap; the **daemon** is not. Measured with the sample project
(`C:\Users\marku\projekte\temp\sample-gradle` — Spring Boot, composite build, dependency
locking, toolchain Java 25): an ephemeral container pays **4.95-13.6 s per build** for the
daemon, a long-lived container pays **1.67 s**, and the first build anywhere pays 88.6 s
because it downloads the distribution and dependencies (904 MB).

**Decision (2026-10-30): one long-lived container per session**, idle-killed at 10 minutes, with
the distribution and dependency cache baked into the image so a session's first build is an
`--offline` clean build (~8.5 s measured) rather than an 88 s download.

So "spin up a container per build" costs **3–8 s of overhead**, and most of it is the cold
Gradle daemon, not the container. Attaching to a container that has already built once costs
**30–80 ms**. The decision therefore is not "how fast can we start a container" but "how often
do we throw the daemon away":

- **v1: one long-lived container per session.** Started on the first build, `exec`ed into
  afterwards, idle-killed after 10 minutes. The Gradle daemon warms itself on the first build
  and is reused; the idle cost of an empty container is a few MB, and the 0.5–1.5 GB of a live
  daemon only exists between the first build and the idle kill.
- **Persistent cache volume** in both variants (`/cache`), because a container without it
  re-downloads dependencies on every start — a cost far larger than any of the rows above.
- **Ephemeral container per build** is the fallback if S0.2 shows container start is cheap
  enough on the chosen substrate *and* statelessness is worth 3–8 s per build. That is a
  decision for numbers, not for taste.
- **Engine down** → fail immediately with `runner_engine_unavailable` and a message naming
  the engine; never sit in a 40 s retry inside a tool call. Optional `--start-engine` may
  later start it explicitly and say so.

The unavoidable first-run cost — pulling the image, prewarming the wrapper distribution and
the dependency cache — belongs to **install time**, documented as a step, exactly as the
Gradle plan already recommends for the in-session variant (§T3.3 there).

### The engine abstraction, built in from the first line

The runner talks to the **Docker Engine REST API over a configurable endpoint** and never
shells out to a CLI. That single decision is what makes Rancher, Docker Desktop and Podman
the same backend with different endpoints instead of three integrations:

| piece | responsibility |
|---|---|
| `EngineEndpoint` | resolve `DOCKER_HOST` (`npipe://`, `unix://`, `http(s)://`), else the docker context, else the platform default; refuse `tcp://` in v1 (a remote engine silently moves where builds run) |
| `EngineProbe` | `/_ping` + `GET /version`, then a capability set: pull policy, `/containers/{id}/archive`, exec TTY, events, stats, mount path visibility |
| `EngineQuirks` | the small per-engine table the probe fills: path translation needed?, archive supported?, exec TTY quirks?, `HostConfig` fields silently ignored? |
| `RunnerEngine` (trait) | create/start/exec/stop/remove/inspect — the only surface the slot lifecycle sees |

Support statement this buys, to be written into the ADR verbatim:

| engine | status |
|---|---|
| Rancher Desktop, **moby** (this machine) | **target for v1**, verified end to end |
| Docker Desktop | expected to pass the same probe; verified when someone runs the legs |
| Podman machine (`podman system service`) | expected, **unverified** — its compat API ignores fields rather than erroring, so the probe has to catch that |
| Rancher Desktop, **containerd** mode | **refused by name** — no Docker API at all |
| remote engine (`tcp://`) | **refused in v1**, deliberately |

Because the engine is reachable only from the runner and never from the workload, none of
this touches the containment invariants — it changes latency, licensing and API gaps only.

## 4. The project is synced, not mounted

Measured (S0.3, `docs/research/build-runner/measurements.md` §3): a live Windows bind mount
costs **2.65 ms per file** on this engine — 53 s to read 20 000 small files — while the same
tree inside a volume costs 0.76 s, and pulling the whole tree *into* the volume costs 2.8 s.
Gradle opens tens of thousands of files per build, so a bind mount is not a percentage slower,
it is a different order of magnitude. The plan therefore syncs:

1. **Copy in** the project into a per-project volume (an archive stream; measured 2.8 s for
   20 k files), then build inside the volume.
2. **Copy out** the declared outputs (`build/`, `target/`, test reports) back into the project
   directory through a filter — never the whole tree, or the copy-out overwrites the agent's
   edits with stale snapshot content.
3. **The volume is persistent per project** and the sync is a delta (size + mtime, or the
   archive's own index). Without persistence every build pays the sync *and* loses Gradle's
   incremental state.

Sync semantics are a feature surface with tests, not an implementation detail:

- **deletions and renames** — a copy that never deletes leaves stale sources, and the build then
  compiles files the agent removed;
- **file modes** — the executable bit on `gradlew` must survive the round trip;
- **line endings** — CRLF working tree vs a Linux filesystem, and which side normalises;
- **a snapshot, not a live tree** — the build sees a point in time, which removes the TOCTOU
  risk §10 listed and adds a new one: an edit made during a build is invisible to it.

Path safety is unchanged and still mandatory, because the *sync root* is what gets copied:
resolve the project root, refuse reparse points/junctions (a junction to `%USERPROFILE%` would
copy `.ssh` into the runner), refuse UNC and `subst` drives, and refuse the saife install
directory for the same reason the launcher guard exists.

## 5. Network inside the runner

Two shapes; only one is honest in v1:

- **Offline (default, v1).** `--offline` builds against a prewarmed cache; the runner has no
  network at all. Missing dependencies fail with a message that names the dependency and the
  documented refresh step.
- **Relayed (later, if asked).** The container cannot reach saife's proxy on the host's
  `127.0.0.1`, so the runner would relay CONNECTs into the proxy — which makes the runner a
  network chokepoint holding a proxy token, i.e. the one place an unaudited path can appear.
  It is not in v1, and if it lands it needs its own audit facts.

What must never happen: the runner reaching the internet directly. That is an egress path
outside the session's policy and outside the audit chain, and it would be one line of
configuration away at all times.

## 6. Audit and facts

The facade already records requests. What is missing is the outcome: for each build, the
session's facts should carry `build_runner: { image_digest, slot_id, task, exit_code,
duration_ms }` — enough for a reader to answer "what ran, from which image, and did it pass"
without reading container logs. `KNOWN_KEYS` in `src/audit/filter.rs` grows in the same
change, and no second spelling is invented.

The honest limit: anything the runner does that is not a facade request is invisible to
saife's audit. That is the price of a second containment domain, and it belongs in ADR-0006
in those words.

## 7. Rejected alternatives

| alternative | why not |
|---|---|
| port-scoped loopback egress only (sibling plan) | keeps Gradle — and its daemons, workers and JVM — inside the session; the four `--no-daemon` configurations in `docs/FAQ.md` already fail, so this is not sufficient on its own. Still worth having for *other* tools. |
| generic executor sidecar | escape by design (§2) |
| docker socket passthrough | root-equivalent on the host; the whole point is to not hand the sandbox root |
| one VM per build | latency (§3); a 5–20 s boot per `gradlew build` is not a developer experience |
| `--backend appcontainer` for Gradle (today's workaround) | elevated, and the DACL propagation cap (20 000 objects) truncates on large trees; it also gives the workload broad loopback |
| run Gradle on a remote CI and rsync | works, but leaves saife with no local answer, and the artifact path becomes manual |

## 8. Invariants

1. **No new hole in the session.** The runner is reachable only through the facade; the
   session gains no port, no inbound path, no DNS exemption.
2. **The workload cannot name the image, the command, the mounts or the flags** — asserted by
   a test over the request type, not by review.
3. **The runner receives no credentials** from the session. A private registry needs its own
   story (out of scope, deny first).
4. **One session per slot**, and a slot dies with its session.
5. **The image carries the toolchain.** The sample project's conventions require Java 25; a
   project whose toolchain the image lacks is refused by name (`runner_toolchain_missing`),
   never left to Gradle's auto-provisioning (which needs network and a resolver).
6. **The facade relays only what a manifest declares** — including the method. Widening it
   (T1.5) must not turn the facade into a general proxy: declared `(method, path)`, a body size
   cap, no header pass-through beyond what the relay already does.
7. **Failure is a refusal, not a fallback.** If no slot can be prepared, the build fails with
   the reason; it never silently runs on the host.
8. **The audit answers "which image, which task, which exit code".**

## 9. Phases and tasks

Every code task is TDD (red first), every phase ends with the standing gates:
`cargo test --bin saife` in both feature states, `cargo clippy` 0, rustfmt on touched files
with `--config skip_children=true`, CRLF preserved, and the host left clean (no containers,
no slots) per AGENTS.md.

### S-0 — Measurement (blocking gate; no product code before this is answered)

- [x] **S0.1** Facade streaming — **measured and passing**: 20 lines over 20 s arrived with the
      first byte at 1 ms and the last at 20 010 ms, no buffering, past the 15 s head deadline.
      The same leg found that the facade is **GET-only** (`501` for anything else, before the
      declaration is consulted) — recorded as T1.5.
- [x] **S0.2** Latency decomposition — **measured, including the daemon**: `info` 93 ms,
      `run --rm` 497 ms, `exec` 73 ms; ephemeral per build 4.95-13.6 s, long-lived 1.67 s, first
      build 88.6 s (904 MB of downloads), `--offline` clean build 8.5 s, daemon RSS 479 MB.
      Decides §3: long-lived container.
- [x] **S0.3** Mount throughput — **measured, and it changed §4**: bind mount 53.6 s vs volume
      0.76 s for 20 k small files (2.65 ms/file vs 0.038 ms); tar-pipe populate 2.8 s. The
      project is synced, not mounted.
- [ ] **S0.4** Runner → proxy reachability: can a container reach saife's proxy at all
      (`host.docker.internal`, host-gateway)? Decides offline-only (v1) vs relayed (§5).
- [x] **S0.6** Endpoint discovery — **measured**: from a plain named-pipe client (no docker
      CLI), `/_ping` → `200 OK` and `GET /version` → `api=1.54 min=1.41 engine=29.5.3
      linux/amd64`; `Test-Path` on the pipe returns False while the API answers. Rust-client leg
      and the containerd-mode refusal still to confirm.
- [~] **S0.5** `docs/research/build-runner/measurements.md` written for the three measured legs;
      the remaining legs append to it. A negative result — e.g. streaming cannot work — is a
      recorded result and changes the plan, not a failed spike.

**Exit criterion:** the four answers exist, and this plan is either confirmed or amended
before S-1 starts.

### S-1 — The contract and the facade wiring

- [ ] **T1.1** `src/runner/mod.rs`: `BuildRequest { project, task, profile }` with validation
      (workspace-contained path, allow-listed task, known profile). A test asserts the type
      has no field for image/mount/command/env.
- [ ] **T1.2** Declared operations on the runner's facade target: `POST /build`,
      `GET /build/{id}` (log stream), `DELETE /build/{id}`. Anything else → `403
      facade_operation_not_declared` (existing behaviour, new fixtures).
- [ ] **T1.3** Streaming response path per S0.1's answer (chunked, flushed per line, cancel on
      client disconnect).
- [ ] **T1.5** Let the facade relay any **declared** method and forward request bodies: replace
      the hard-coded GET gate in `facade_action` with the declaration check, forward the body to
      the sidecar with a size cap and a declared content type, and refuse undeclared methods with
      `403` rather than `501` (the manifest is the control; the GET gate refuses what the operator
      declared). Tests: declared `POST` reaches the sidecar with its body; undeclared method →
      `403`; oversized body → `413`.
- [ ] **T1.4** Per-session runner token, distinct from the MXC proxy token; a test asserts the
      two are never the same value and that the runner token does not authorise a proxied host.

### S-2 — Slot lifecycle (on top of the engine abstraction)

- [ ] **T2.6** `src/runner/engine.rs`: `EngineEndpoint` + `EngineProbe` + `EngineQuirks` +
      the `RunnerEngine` trait from §3. Tests: `DOCKER_HOST` parsing for all three schemes,
      `tcp://` refused by name, containerd-mode Rancher refused by name, and a probe fixture
      that reports a missing capability instead of failing at first build.

- [ ] **T2.1** Slot spawn with a pinned digest and a readiness probe; the digest is a binary
      constant, not a profile field.
- [ ] **T2.2** Attach path with a timeout and a named failure (`runner_slot_unavailable`).
- [ ] **T2.3** Idle kill (10 min), recycle after N builds, invalidate on digest/JDK change.
- [ ] **T2.4** Single-session ownership, kill on session end, start-up sweep of orphaned slots.
- [ ] **T2.5** Caps and reporting: CPU/memory limits, and the slot visible in the session's
      facts (`slot_id`, image digest).

### S-3 — Mounts

- [ ] **T3.1** Resolve the project root; refuse reparse points, UNC, `subst`, and the saife
      install directory. Tests for each refusal, with the message naming the reason.
- [ ] **T3.2** Sync in: project → `/src` volume as a delta (archive stream), persistent
      per-project volume, `/cache` for dependencies, HOME set inside.
- [ ] **T3.3** Sync out: declared outputs only, filtered; prove the agent's edits are never
      overwritten by stale snapshot content, and nothing outside the outputs changes.
- [ ] **T3.5** Sync semantics tests: deletion, rename, executable bit, CRLF, and an edit made
      during a build (snapshot behaviour is the documented answer).
- [ ] **T3.4** Document the Windows semantics from §4, with the case-collision test case.

### S-4 — Gradle integration

- [ ] **T4.1** `profiles/gradle-runner.json` + `profiles/README.md` row: project grant, no
      network, runner profile name.
- [ ] **T4.2** Invocation: `gradlew --offline <task>` with `JAVA_HOME` from the image; exit
      code propagated; timeout and cancel wired to the session deadline.
- [ ] **T4.3** Prewarm at image build time (wrapper distribution + dependencies), documented as
      an install/refresh step.
- [ ] **T4.4** Offline failure UX: missing dependency → message naming it and the refresh
      command, not a 400-line Gradle stack trace.
- [ ] **T4.5** Live leg (`#[ignore]`): a fixture project builds green through the runner, warm
      attach < 2 s, and a second build reuses the daemon (measurably faster).

### S-5 — Documentation and decisions

- [ ] **T5.1** `docs/adr/0006-build-runner.md`: the trust model (a second containment domain),
      why the facade and not loopback, what the runner may and may not be asked for, and the
      audit gap in plain words.
- [ ] **T5.2** `docs/FAQ.md`: the Gradle answer points at the runner, keeps the measured
      `--no-daemon` evidence, and keeps `appcontainer` as a fallback with its costs.
- [ ] **T5.3** `docs/DEVELOPERS.md` invariants: "the runner is policy, not an executor", and
      "a build request carries no image, mount, command or flag".
- [ ] **T5.4** Cross-link the sibling plan: loopback egress is still the answer for tools that
      must talk loopback *inside* the session; the runner is the answer for toolchains whose
      daemons make that impractical.

## 10. The risks this design does NOT remove

1. **A second containment domain is not a stronger guarantee.** The workload is contained;
   the runner is trusted code running on the host with docker/podman rights. Its IPC is
   therefore part of saife's attack surface, and §2 is the only thing keeping it small.
2. **The project tree crosses the boundary twice** (sandbox writes, runner builds), so a
   build's inputs can change mid-build, and Windows file locks can fail a build in ways a
   native build would not.
3. **The engine is assumed running, and that assumption can be false.** Rancher/Docker
   Desktop may be closed, updating, or in a broken state; the runner must detect it in
   milliseconds and refuse by name rather than wait.
4. **The substrate is a dependency we do not control.** Docker Desktop requires a paid
   subscription for larger organisations, updates itself, and is itself a VM; Podman machine
   and a bare WSL2 distro are alternatives with different gaps. S-0 picks one on numbers.
4. **Audit stops at the facade.** Container-internal actions are invisible to saife.
5. **Warm slots cost RAM** even when idle, and a leaked slot is a stale build environment —
   hence the start-up sweep, which has to be right.
6. **Nested isolation can look like more than it is.** "Gradle runs in a container" does not
   mean the container cannot reach the network; §5 is what makes it true.

## 11. Open questions

1. **Resolved 2026-10-30:** Rancher Desktop in **moby** mode is the engine for v1 (it is what
   the development machine runs), reached through the Engine API abstraction in §3. Remaining:
   whether Docker Desktop and Podman pass the same probe unchanged (run the legs; do not
   promise them in the README until someone has), and whether a bare WSL2 distro is worth
   supporting at all.
2. Do we ship a pinned image, or require the user to supply a digest? (Shipping means owning
   its CVE stream; requiring means a config step that can be wrong.)
3. Offline-only in v1 — confirmed by S0.4, or does the relay have to exist on day one?
4. Does the runner need `.git`? Some Gradle plugins read it; it is inside the project mount,
   so the answer is yes, and that should be said explicitly in the ADR.
5. Interaction with `--backend appcontainer`: the facade exists on both backends, so the
   runner should be backend-agnostic — worth a test rather than an assumption.

## 12. Files likely to change

- `src/runner/mod.rs` (new), `src/runner/slot.rs` (new), `src/runner/engine.rs` (new — endpoint,
  probe, quirks, trait)
- `src/plugin/mod.rs`, `src/plugin/sidecar.rs` — facade operation declarations, token scope
- `src/net/proxy.rs` — nothing expected, but S0.1 decides; the declaration check is already
  there
- `src/audit/session_start.rs`, `src/audit/filter.rs` — build facts and `KNOWN_KEYS`
- `src/main.rs`, `src/cli.rs` — `saife build` (or `saife run --runner`), if it gets a verb
- `profiles/gradle-runner.json`, `profiles/README.md`
- `docs/adr/0006-build-runner.md`, `docs/FAQ.md`, `docs/DEVELOPERS.md`
- `tests/run-tests.ps1` — refusal scenarios and the slot sweep

## 13. Verification

- **Unit:** request validation (path escape, unknown task, unknown profile), "no image field"
  assertion, digest pinning, token separation.
- **Harness:** a fixture project built through the runner; negative legs — undeclared path
  `403`, project root outside the workspace refused, junction/symlink refused, image override
  impossible.
- **Live (`#[ignore]`):** the fixture `C:\Users\marku\projekte\temp\sample-gradle` (Spring
  Boot + composite build + dependency locking, Java 25): `gradlew build` exit 0 with
  `sample-gradle.jar` synced back; warm build < 3 s (measured 1.67 s); a second build reuses the daemon; session end leaves no container behind
  (`HOST-CLEAN` analogue: `docker ps --filter label=saife.session=…` empty).
- **Performance budget:** engine overhead ≤ ~1 s per build (measured: 497 ms container start or
  73 ms exec) plus sync ≤ 3 s per direction on a 20 k-file tree (measured 2.8 s full, less as a
  delta). Everything beyond that must be Gradle itself. A live bind mount cannot meet this —
  measured at 53 s for the same read.

## 14. Out of scope

- Serving the build over the network (remote builder, multi-host).
- Registry credentials inside the runner.
- Windows-native build toolchains without a container/VM (MSBuild, `dotnet`) — same shape,
  different image, later.
- Making Gradle work *inside* the session — that is the sibling plan's job.
- Replacing Docker Desktop; we use whatever S-0 says is fastest and acceptable to ship.

## 15. Reproduce (S-0)

```powershell
# 1. facade streaming (needs a declared operation that emits for 10 minutes)
#    measure: bytes reached the workload, latency per line, proxy log lines
# 2. substrate latency
docker run -d --label probe=1 --entrypoint sleep alpine 600
Measure-Command { docker exec (docker ps -q --filter label=probe=1) true }
Measure-Command { docker start (docker ps -aq --filter label=probe=1) }
# 3. mount throughput: 20k small files, read + write, bind mount vs in-volume copy
# 4. runner -> proxy: from inside a container,
#    Invoke-WebRequest http://host.docker.internal:<proxy-port>/ -Proxy ...
```

Cleanup after each block (AGENTS.md): `docker rm -f` every probe container,
`docker ps --filter label=probe=1` empty, no `saife` processes left.
