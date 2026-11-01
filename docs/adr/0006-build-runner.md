# ADR-0006: the build runner — a supervisor-owned container behind the facade

- **Status:** **Accepted 2026-10-30** (design decision, product owner). The implementation lives
  on `feat/gradle-build-runner` and is **not in any released build**: `saife runner status`
  and `saife runner prewarm` exist there, the session-facing mount does not yet.
- **Date:** 2026-10-30
- **Supersedes:** nothing. It adds a second containment domain that ADR-0004's egress rules do
  not describe, and it changes no rule in ADR-0001, ADR-0002, ADR-0003 or ADR-0004.
- **Evidence:** `docs/research/build-runner/measurements.md` (S-0, seven legs, measured on this
  host, Windows 11 build 26300, Rancher Desktop 29.5.3 / moby, `npipe:////./pipe/docker_engine`);
  plan `docs/plans/2026-10-30-gradle-build-runner.md`; tracker
  `docs/tasks/gradle-build-runner/PROGRESS.md`.

## Context

Gradle cannot run inside a session, and the cause is structural rather than a missing grant. The
daemon, the workers and the compiler daemons talk over loopback, and loopback is closed in
**both** directions under `mxc` — measured 2026-10-30:

| leg | result |
|---|---|
| a container connects to its own `127.0.0.1` listener | `WSAEACCES` **10013** |
| the same, inside a proxy session | `WSAEACCES` **10013** |
| the host connects to a container's listener | connect times out (the socket is visible in the host's TCP table) |

`--no-daemon` is not a way out: four configurations were measured in this repository (plain
`--no-daemon`; `daemon=false` with matching `GRADLE_OPTS`; the same with `org.gradle.jvmargs`
mirrored; both mirrored into `JAVA_OPTS`) and every one forked a single-use daemon and died at
the refused loopback connect. See `docs/FAQ.md`, "Why `--no-daemon` is not the answer".

The remaining options are (a) widen the session's egress policy to admit one loopback
address/port — that is the sibling plan `docs/plans/2026-10-28-gradle-daemon-loopback.md`, which
is still behind its own measurement gate; or (b) do not run the build in the session at all. This
ADR decides (b), and the measurement that settled it is not about Gradle:

| fact | measured |
|---|---|
| a container on this engine reaches the session proxy through `host.docker.internal` | yes — `407 Proxy Authentication Required`, realm `sandbox` |
| the same container reaches **any** host service bound to `127.0.0.1` | yes (host gateway `192.168.127.254`) |
| anything through the bridge gateway `172.17.0.1` | refused |

A container is therefore **not** a network boundary against the host. "Give the runner no
network" became a containment requirement in the same measurement that proved the relay
technically possible.

## Decision

The build happens in a container the **supervisor** owns, and the workload asks for it through
the facade it already uses. Seven parts, each one load-bearing.

### D-1. A supervisor-owned container, one per session

A slot (`saife-runner-<session>`) is created on the session's first build and reused; the engine
API is spoken to directly (one request per connection over the named pipe), never through the
`docker` CLI. Measured cost of the shape: `docker exec` into a running container **73 ms**,
`docker run --rm` **497 ms**, engine round trip **93 ms**; a Gradle build with a live daemon
**1.67 s** against **4.95–13.6 s** when the daemon has to start, and the daemon is **479 MB**
RSS. The expensive object is the daemon, not the container, so the container is kept.

The idle kill (10 min), the recycle rule and the start-up sweep are **not implemented yet**
(T2.3, T2.4). Until they are, a slot lives as long as the supervisor that made it, and the only
sweep in the code removes a stale container of the *same* session name before creating a new one
(`builds.rs::ensure_slot`).

### D-2. Copy in, copy out — the project is never mounted

A live Windows bind mount costs **2.65 ms per file** on this engine and **0.038 ms** in a volume:
53.6 s against 0.76 s for a 20 000-file tree, and a tar round trip of the same tree is **2.8 s**.
Gradle opens tens of thousands of files per build, so a mount is not a percentage slower, it is a
different order of magnitude. The project is packed (`pack_dir`) and `PUT` as an archive into
`/src`; the declared outputs come back with `GET /archive` through a filter, and only
`build/libs` is fetched today.

The semantics this creates are part of the feature, not an implementation detail — deletions are
not propagated, CRLF is not normalised, a case-only collision landing on NTFS is last-writer-wins,
a locked file fails the pack by name, paths over 260 characters are unsupported, and the build
sees a **snapshot** rather than a live tree. Each one is written down in
`docs/USER-GUIDE.md` §8a ("What the copy does to a Windows tree") with its status: handled,
refused, or known limitation.

### D-3. `NetworkMode: none`, always

Every slot is created with `"NetworkMode": "none"` (`SlotSpec::allow_network` is false on every
session path). The single exception in the design is `saife runner prewarm`, an explicit command
that prints what it is doing, runs one networked container to fill the cache, and removes it
whether it succeeded or not. There is no relayed variant in v1: a relay would make the runner the
one place an unaudited byte stream can appear, and it would be a weaker boundary than it looks,
because the same container can dial every other service on the host's loopback directly.

### D-4. One global cache volume, `saife-runner-cache`

An offline build needs a warm `~/.gradle` — **904 MB** for one Spring Boot project, **88.6 s** of
download for the first build that does not have it. The volume is created once, mounted at
`/cache` in every slot, and never evicted in v1: its size is reported (`saife runner status`), and
removing it is a deliberate `docker volume rm`. It is **shared state and trusted state** — a
build in one session can influence what another session's build reads. That is accepted for a
single-user machine, said out loud in the user guide, and reversible by switching to a
per-session volume, which costs the 88.6 s again per session. The prewarm and refresh step, and
what an interrupted fill costs, are documented at §8a.

### D-5. The facade, with declared operations — not a port, not a socket

The workload reaches the runner by making an ordinary HTTP request to the proxy it is already
allowed to reach; the proxy routes it by mount (`FacadeTarget { mount, port, token, operations }`)
and refuses any `(method, path)` the runner did not declare with
`403 facade_operation_not_declared`. The declared surface is exactly two exact paths:
`POST /build` and `GET /build` (the build id travels as a query parameter because the declaration
grammar has no wildcard). Streaming was measured before the design depended on it: a 20-line log
over 20 s arrived with the first byte at **1 ms** and the last at **20 010 ms**, past the 15 s
head deadline, unbuffered.

The workload can carry a token that starts a build and nothing else: the runner's token is
per session and scoped to that mount, so a leaked build token is not a leaked network token.

### D-6. The engine is an API, and its support statement is a refusal list

The runner speaks the Docker Engine REST API over a configurable endpoint (`DOCKER_HOST` npipe /
unix, else the docker context, else the platform default) and never shells out to a CLI, which is
what makes Rancher, Docker Desktop and Podman one backend with different endpoints. Endpoint
discovery must be an API call: `Test-Path \\.\pipe\docker_engine` returns **False** while the
API answers `200 OK`.

| engine | status |
|---|---|
| Rancher Desktop, **moby** (this machine) | **target for v1**, verified end to end |
| Docker Desktop | expected to pass the same probe; verified when someone runs the legs |
| Podman machine (`podman system service`) | expected, **unverified** — its compat API ignores fields rather than erroring |
| Rancher Desktop, **containerd** mode | **refused by name** — no Docker API at all |
| remote engine (`tcp://`) | **refused in v1**, deliberately: it silently moves where builds run |

### D-7. What a request may carry, and what it may not

| field | from the workload | validation |
|---|---|---|
| `project` | a path inside the session workspace | lexical (`..`, rooted, UNC, device) at parse; canonicalised and required to contain itself in the workspace on disk, refusing any reparse point on the path |
| `task` | `assemble`, `build`, `check`, `clean`, `test` | allow-list, never interpolated: the argv is `./gradlew --offline --console=plain <task>` |
| `profile` | `gradle` | the runner's own table, not a saife profile |

Everything else — image digest, mount list, environment, CPU/memory caps, network mode, user id,
the wrapper invocation — is a constant of the shipped binary. `BuildRequest` has no field for any
of them and `deny_unknown_fields` refuses an extra key **by name**, asserted by a test: a future
"convenience" parameter is how this becomes a bypass.

## Consequences

### Positive

- **The session gains no hole.** No port, no inbound path, no DNS exemption, no new privileged
  channel: the runner is reached through the facade that already exists and already refuses
  undeclared operations.
- **Every build is in the audit chain by construction**, because a build request is a proxy
  request. A second logging path cannot drift from it.
- **Gradle's loopback never reaches saife's policy**, because the loopback never happens in the
  session. The toolchain's shape stops being a policy question.
- **The measurement work is reusable**: the engine abstraction means a different substrate (a
  Podman machine, a Docker Desktop install) is a different endpoint, not a second integration.
- **The cost is bounded and known**: engine overhead ≤ ~1 s per build, sync ≤ ~3 s per direction
  on a 20 000-file tree, `1.67 s` for a warm build, `8.5 s` for a clean `--offline` build.

### Negative

- **This is a second containment domain, and that is not a stronger guarantee.** The workload is
  contained; the runner is trusted code on the host with container-engine rights, so its IPC is
  part of saife's attack surface, and D-7 is the only thing keeping it small.
- **The audit stops at the facade.** What happens inside the container is invisible to saife —
  the price of a second domain, said plainly rather than papered over with a second log. The
  per-build facts the plan sketches (`build_runner: { image_digest, slot_id, task, exit_code,
  duration_ms }`) are not emitted yet, so today a build is visible as facade requests and
  nothing more.
- **The project crosses the boundary twice** (sandbox writes it, runner builds it), so the build
  sees a snapshot and Windows file locks can fail a build a native one would have survived.
- **The engine is assumed running**, and that assumption can be false (closed, updating, broken).
  The runner detects it in milliseconds and refuses by name (`runner_engine_unavailable`) instead
  of waiting.
- **The substrate is a dependency we do not control.** Docker Desktop is paid for larger
  organisations, updates itself, and is itself a VM; Podman machine and a bare WSL2 distro are
  alternatives with different gaps, and neither is verified.
- **The cache is shared trust** (D-4). Reversible, but not free: per-session volumes pay the
  cold fill again.
- **A live daemon costs 479 MB** until the idle kill exists, and a leaked container is a stale
  build environment — which is why the sweep has to be right and is not written yet.
- **Nested isolation can look like more than it is.** "Gradle runs in a container" is only a
  containment claim because D-3 makes it one.

### Neutral

- The runner is **backend-agnostic** in principle (the facade exists on both backends) and
  **backend-tested** only on `mxc` so far.
- `.git` is excluded from the copy today, so a build that stamps the commit hash sees no
  repository. The plan's §11 assumed the opposite; the code is the fact, and this is open.
- Nothing in the default path gains a runtime dependency: without an engine the runner refuses by
  name, and every existing session behaves exactly as before.

## Rejected alternatives

| alternative | why not |
|---|---|
| **bind mounts** (`-v project:/src`) | measured **2.65 ms per file** — 53.6 s to read a 20 000-file tree against 0.76 s in a volume. Minutes per build, not a percentage. It is also a live tree the workload could widen, which the copy-in does not allow. |
| **an ephemeral container per build** | pays the Gradle daemon every time: **4.95–13.6 s** against 1.67 s warm, for the sake of statelessness. Kept as the fallback if a substrate makes container start cheaper than the daemon. |
| **a networked slot** (`bridge`, or a relay into the proxy) | the container reaches every host service bound to `127.0.0.1` through the host gateway (measured), so "network" is not "the internet". A relay would also put a proxy token and an unaudited byte stream inside the deputy. |
| **a sidecar on the host** (a small helper that runs `gradlew` with the user's own toolchain) | it runs the build with the user's full token and filesystem view, so there is no policy to enforce and no boundary to describe; its egress is unmediated and unaudited, which is exactly the property the sandbox exists to remove. It also makes the toolchain the host's problem again, which is what the image exists to fix. |
| **a generic executor sidecar** (`POST /exec`) | an escape by design: the request would name the command. |
| **docker socket passthrough** | root-equivalent on the host; the point is not to hand the sandbox root. |
| **one VM per build** | a VM boot per `gradlew build` is not a developer experience, the image/toolchain story is the same one, and the daemon problem simply moves inside the VM. |
| **`--backend appcontainer` for Gradle** | works today but needs an admin shell, exempts the session SID for **all** loopback, and cannot hold the agent session that would drive the build: its DACL walk truncates at 20 000 objects and an agent's own state dirs exceed that, so only a separate lean build session is viable. Stays the documented fallback, not the answer. |
| **remote CI and rsync** | leaves saife with no local answer and makes the artifact path manual. |

## What this ADR does not decide

- Whether a **relayed** (networked, audited) runner ever exists. Not in v1; if it does, it needs
  its own audit facts and its own argument about the host-loopback exposure above.
- Whether the **pinned image is shipped** by saife or supplied by the user as a digest. Shipping
  means owning a CVE stream; requiring means a config step that can be wrong.
- **Registry credentials** inside the runner (deny first, out of scope).
- The **idle kill, recycle and start-up sweep** (T2.3, T2.4) and the **session wiring** that
  mounts the runner listener as a facade target — the design is decided here, the code is not
  complete.

## References

- `docs/research/build-runner/measurements.md` — S-0, seven legs, this host.
- `docs/plans/2026-10-30-gradle-build-runner.md` — the implementation plan and its task list.
- `docs/plans/2026-10-28-gradle-daemon-loopback.md` — the in-session alternative (one pinned
  loopback port), on branch `feat/gradle-daemon-loopback`.
- `docs/tasks/gradle-build-runner/PROGRESS.md` — what is done, with evidence per row.
- `docs/USER-GUIDE.md` §8a — the user-facing shape, the cache rules and the sync semantics.
- `docs/FAQ.md` — the Gradle entry and the measured `--no-daemon` evidence.
- `src/runner/` — `mod.rs` (request + path checks), `docker.rs` (engine, slots, cache volume),
  `server.rs` (declared operations), `sync.rs` (copy in/out), `builds.rs` (the state machine).
