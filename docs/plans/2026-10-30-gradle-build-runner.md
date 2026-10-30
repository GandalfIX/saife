# Gradle build runner — a facade sidecar that builds in a container (Implementation Plan)

> **Status:** proposal, 2026-10-30. **Nothing is implemented and nothing is measured.** The
> four experiments in §9 S-0 decide whether this plan is built at all, and two of them can
> kill it.

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

## 3. Warm slots: what "starts fast" costs

Cold paths are disqualifying and should be said plainly:

| substrate | cold | warm |
|---|---|---|
| Docker Desktop, daemon down | tens of seconds to minutes | — |
| Docker container, daemon up, image present | ~0.3–1 s | `exec` into a running container: tens of ms |
| Linux VM boot | 5–20 s | snapshot resume: ~0.1–0.3 s |
| bare WSL2 distro | seconds | fast, no snapshot |

So a build must never boot anything. The unit of reuse is a **slot**:

- spawned once per session (or per project, at most one warm slot per project), with the image
  digest pinned and a readiness probe before it is advertised;
- holds a live Gradle daemon and a populated `~/.gradle`; the daemon's idle timeout is set
  long enough that consecutive builds reuse it;
- attached per build (`exec`, not `run`), with the project mounted at `/src`;
- idle-killed after N minutes (default 10), recycled after N builds (default 20), invalidated
  when the image digest or the JDK version changes;
- owned by exactly one session, killed when that session ends (a container label plus the
  session id, swept on start-up so a crashed supervisor cannot leak slots);
- memory budget is real and must be documented: a warm daemon is ~0.5–1.5 GB, a warm VM 1–2 GB.

The unavoidable first-run cost — pulling the image, prewarming the wrapper distribution and
the dependency cache — belongs to **install time**, documented as a step, exactly as the
Gradle plan already recommends for the in-session variant (§T3.3 there).

## 4. Mounts and path safety

- Mount the **project directory only**, read-write, at `/src`; plus a private cache volume at
  `/cache`. Nothing else from the host.
- **Resolve before mounting.** A junction or symlink inside the project pointing at
  `%USERPROFILE%` smuggles the home directory (and `.ssh`) into the runner. The mount root
  must resolve to a real directory with no reparse points on the path, and the runner must
  refuse UNC paths and `subst` drives.
- Refuse the saife install directory as a project root — the same reasoning as the launcher
  guard (`mxc: writable grant … contains the launcher`): a workload that can write the
  supervisor's tree is scheduling code to run with the supervisor's rights.
- Outputs land back through the same mount, so `build/` is visible to the agent without a
  copy-back step; that is also what keeps incremental builds meaningful.
- Windows semantics that must be stated, not discovered: case-insensitive source paths vs a
  case-sensitive Linux filesystem (two files differing only in case collide), CRLF in
  checked-in scripts, file locks (a running Windows process holding a file the build wants to
  rewrite), long paths, and antivirus scanning the mount.

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
5. **Failure is a refusal, not a fallback.** If no slot can be prepared, the build fails with
   the reason; it never silently runs on the host.
6. **The audit answers "which image, which task, which exit code".**

## 9. Phases and tasks

Every code task is TDD (red first), every phase ends with the standing gates:
`cargo test --bin saife` in both feature states, `cargo clippy` 0, rustfmt on touched files
with `--config skip_children=true`, CRLF preserved, and the host left clean (no containers,
no slots) per AGENTS.md.

### S-0 — Measurement (blocking gate; no product code before this is answered)

- [ ] **S0.1** Facade streaming: a declared operation that emits a line per second for 10
      minutes. Does the response stream through the proxy, or is it buffered/cut by
      `HEAD_READ_TIMEOUT`, the 128-connection cap, or a client read timeout? Record what the
      workload sees and what the proxy logs.
- [ ] **S0.2** Substrate latency on this host: `docker exec` into a warm container, `docker
      start` of a stopped one, a Podman machine, a bare WSL2 distro. Numbers for attach, not
      for boot.
- [ ] **S0.3** Mount throughput: a Gradle-sized tree (~20 k small files) read and rebuilt
      inside the runner over a Windows bind mount, versus copied into the runner's volume.
      Wall clock for `gradlew build` both ways.
- [ ] **S0.4** Runner → proxy reachability: can a container reach saife's proxy at all
      (`host.docker.internal`, host-gateway)? Decides offline-only (v1) vs relayed (§5).
- [ ] **S0.5** Write `docs/research/build-runner/measurements.md` (method, legs, table) and
      update this plan's status block. A negative result — e.g. streaming cannot work — is a
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
- [ ] **T1.4** Per-session runner token, distinct from the MXC proxy token; a test asserts the
      two are never the same value and that the runner token does not authorise a proxied host.

### S-2 — Slot lifecycle

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
- [ ] **T3.2** Mount `/src` (project) and `/cache` (private volume); set HOME inside.
- [ ] **T3.3** Prove outputs land on the host and that nothing outside `/src` is writable.
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
3. **The substrate is a dependency we do not control.** Docker Desktop requires a paid
   subscription for larger organisations, updates itself, and is itself a VM; Podman machine
   and a bare WSL2 distro are alternatives with different gaps. S-0 picks one on numbers.
4. **Audit stops at the facade.** Container-internal actions are invisible to saife.
5. **Warm slots cost RAM** even when idle, and a leaked slot is a stale build environment —
   hence the start-up sweep, which has to be right.
6. **Nested isolation can look like more than it is.** "Gradle runs in a container" does not
   mean the container cannot reach the network; §5 is what makes it true.

## 11. Open questions

1. Substrate: Docker Desktop, Podman machine, or a bare WSL2 distro? (S0.2, licensing, and
   whether we want to own a distro.)
2. Do we ship a pinned image, or require the user to supply a digest? (Shipping means owning
   its CVE stream; requiring means a config step that can be wrong.)
3. Offline-only in v1 — confirmed by S0.4, or does the relay have to exist on day one?
4. Does the runner need `.git`? Some Gradle plugins read it; it is inside the project mount,
   so the answer is yes, and that should be said explicitly in the ADR.
5. Interaction with `--backend appcontainer`: the facade exists on both backends, so the
   runner should be backend-agnostic — worth a test rather than an assumption.

## 12. Files likely to change

- `src/runner/mod.rs` (new), `src/runner/slot.rs` (new), `src/runner/substrate.rs` (new)
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
- **Live (`#[ignore]`):** warm attach < 2 s; `gradlew build` exit 0 with the artifact on the
  host; a second build reuses the daemon; session end leaves no container behind
  (`HOST-CLEAN` analogue: `docker ps --filter label=saife.session=…` empty).
- **Performance budget:** build wall clock within 20 % of a native build on the same machine
  (S0.3 establishes the baseline; if the bind mount cannot meet it, the plan changes here).

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
