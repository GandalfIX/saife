# Build runner — S-0 measurements

**Status:** 2026-10-30. Six of seven legs measured, including facade streaming (§6) and the one
that decides the slot model (§5). Only `S0.4` (container → proxy) is open, and it needs a live
session with a listener.

**Host:** Windows 11 (build 26300), 24 vCPU, 33.6 GB visible to the engine.
**Engine:** Rancher Desktop 29.5.3 — dockerd/moby in the `Rancher Desktop WSL Distribution`
(linux/amd64), overlayfs, cgroup v2. Client `29.6.2-rd`.
**Endpoint:** `npipe:////./pipe/docker_engine`.

Everything below is one machine. The numbers are not portable; the ratios are what the design
should be read against.

---

## 1. Endpoint and API (S0.6)

The Docker CLI works, but the runner must not depend on it. A plain .NET named-pipe client,
no docker binary involved:

| leg | result |
|---|---|
| `NamedPipeClientStream(".", "docker_engine")` connect | ok (3 s timeout, connects immediately) |
| `GET /_ping` | `HTTP/1.1 200 OK`, body `OK` |
| `GET /version` | `api=1.54`, `min=1.41`, `engine=29.5.3`, `linux/amd64` |

Two traps recorded for the implementation:

- `Test-Path \\.\pipe\docker_engine` returns **False** while the API answers fine. Discovery
  must be an API call, never a filesystem check.
- With `Connection: close`, the server closes the pipe after the response; a second request on
  the same stream throws "broken pipe". A request-per-connection client is the simple correct
  shape, and keep-alive (if wanted later) needs explicit half-close handling.

`GET /version` is also the version negotiation: 1.54 is the ceiling, 1.41 the floor, so a
client pinning anything in that range is safe on this engine.

## 2. Container lifecycle latency (S0.2)

Medians on a warm engine, image present, nothing else running:

| operation | median |
|---|---|
| `docker info` (API round trip) | **93 ms** |
| `docker run --rm` (create + start + remove) | **497 ms** |
| `docker create` | 71 ms |
| `docker start` (stopped container, image present) | **37 ms** |
| `docker exec` into a running container | **73 ms** |

Reading: container lifecycle is *cheap* on this engine. An ephemeral container per build costs
~0.5 s, and attaching to a running one costs ~73 ms. The plan's §3 assumption holds — what
remains unmeasured is the expensive part, the Gradle daemon (JVM start + daemon registration),
which needs a JDK image and is the next leg.

## 3. Mount throughput (S0.3) — this one changes the design

A 20 000-file tree (1 KB each, 200 directories) and a single 512 MB file, read from a Windows
bind mount and from a named volume, inside the same image:

| operation | bind mount | volume | ratio |
|---|---|---|---|
| read 20 000 files (`find -exec cat`) | **53.6 s** | **0.76 s** | **70×** |
| copy 20 000 files to container disk | **38.2 s** | 2.50 s | 15× |
| read 512 MB single file | 3.16 s (162 MB/s) | 0.48 s (1058 MB/s) | 6.5× |
| populate volume from the host (tar pipe) | — | **2.8 s** (20 k files) / 2.9 s (512 MB) | — |

**Per-file cost is the whole story:** bind ≈ **2.65 ms per file**, volume ≈ **0.038 ms**. The
bandwidth penalty is real but minor; the metadata path (open/stat per file across 9p/virtiofs)
is not. Gradle does tens of thousands of open/stat calls per build, so a live bind mount on this
engine is a minutes-per-build proposition, not a percentage.

The tar-pipe populate is the important number: pulling the *entire* tree into the runner costs
2.8 s, i.e. **19× less than reading it once through the mount**.

## 4. What this changes in the plan

1. **§4 stops mounting the project and starts syncing it.** Copy-in (tar or an equivalent
   archive stream) into a per-project volume, build there, sync results back with a filter.
   The claim "outputs land back through the same mount, so no copy-back step" is dead.
2. **The volume must be persistent per project**, or the sync cost is paid on every build *and*
   incremental build state is lost. A delta sync (mtime/size, or the archive's own diffing) is
   part of the feature, not an optimisation.
3. **Sync semantics become a feature surface:** deletions and renames (a copy that never deletes
   leaves stale sources), file modes, and CRLF normalisation all have to be decided and tested.
4. **Snapshot semantics replace live-tree semantics.** The build sees a point-in-time copy
   instead of a tree the agent is still editing — that removes the TOCTOU risk §10 listed, and
   adds a new one: the agent's edits land only at the next sync.
5. **The performance budget in §13 must be restated** against copy-in/out, using 20 k files as
   the reference workload: the engine overhead is ~3 s of sync per direction plus ~0.5 s of
   container lifecycle; anything beyond that is Gradle itself.

## 5. The sample project: cold, warm, ephemeral (S0.2, the daemon leg)

**Fixture:** `C:\Users\marku\projekte\temp\sample-gradle` — Spring Boot, Kotlin DSL,
composite build (`build-logic`), dependency locking (`gradle.lockfile`), `integrationTest`
suite, Gradle **9.8.2** wrapper, toolchain **Java 25**. 26 files / 304 KB of source.

| leg | wall | notes |
|---|---|---|
| sync in (tar pipe, 26 files) | **0.58 s** | 304 KB |
| build 1, fresh container (downloads distribution + dependencies, starts the daemon) | **88.6 s** | 1 m 27 s Gradle time, 24 tasks, 904 MB added to `/cache` |
| build 2, same container (daemon alive, all up-to-date) | **1.67 s** | Gradle reports 1 s |
| build 3, same container, `clean build` (build cache hit) | **1.49 s** | 6 executed, 10 from cache |
| `clean build --offline` (daemon alive) | 8.5 s | the dependency cache is complete; `--offline` is viable |
| **ephemeral container**, same volumes, up-to-date build | **13.6 s** / **4.95 s** | first / second; daemon has to start every time |
| Gradle daemon RSS after a build | **479 MB** | one JVM |

**The daemon is the whole cost.** Container start is 0.5 s (§2) and the project sync is 0.6 s;
everything expensive is the JVM + Gradle daemon (≈3–12 s when started per build) and the
first-time download (88 s, 904 MB).

Consequences recorded in the plan:

- **One long-lived container per session** (§3): warm builds are ~1.5 s against ~5–14 s
  ephemeral, and the daemon's 479 MB is bounded by the idle kill.
- **The first build must be moved to image build time.** Baking the Gradle distribution, the
  dependency cache and a warm-up build into the runner image turns the session's first build
  from 88 s into the same ~8 s `--offline` clean build measured above.
- **The image must carry the toolchain the project asks for.** This fixture requires Java 25;
  Gradle's auto-provisioning would need network and a resolver. Missing toolchain must be a
  named refusal (`runner_toolchain_missing`), not a silent download attempt inside a build.
- **`--offline` is the default that works** (§5 of the plan): the cache is complete, and an
  offline clean build succeeds in 8.5 s.

## 6. Facade streaming (S0.1) — it streams, and the facade is GET-only

**Instrument:** `tests/fixtures/stream-sidecar` (a Python sidecar) plus the live leg
`plugin::sidecar::tests::a_build_log_streams_through_the_facade_past_the_head_timeout`. The
sidecar answers the health gate on `/status`, then writes one line per second for 20 s on
`/build`; the test drives it through a real session proxy and timestamps every chunk the
workload receives.

| observation | value |
|---|---|
| lines received | 20 of 20 |
| first body bytes at the workload | **1 ms** |
| last chunk | **20 010 ms** (test wall time 20.8 s) |
| buffering | none — the proxy relays each write as it happens |

So a build log can stream through the facade for longer than the 15 s `HEAD_READ_TIMEOUT`
(which covers the request head, not the response), and the relay does not accumulate the body.
**S0.1 passes.**

**But the leg also found a product gap.** The first attempt used `POST /build` and got
`501 Not Implemented`: `facade_action` in `src/net/proxy.rs` returns `MethodUnsupported` for any
method that is not GET, *before* consulting the manifest's declared `(method, path)` list. A build
request wants to be a POST with a small body (task, profile), and neither the method gate nor
request-body forwarding exists today. That is now `T1.5` in the plan:

- relay any method the manifest declares (the declaration is the control; the GET gate is both
  redundant and wrong — it refuses a method the operator explicitly declared);
- forward the request body to the sidecar, with a size cap and a declared content type;
- tests: declared POST reaches the sidecar with its body; undeclared method → 403 (not 501);
  oversized body → 413.

**Closed the same day (T1.5):** `facade_action` no longer refuses non-GET, the manifest's
`(method, path)` declaration is the control, an undeclared method is `403
facade_operation_not_declared`, a non-token method is `400 facade_method_invalid`, and a declared
body is forwarded up to 4 KiB (`413 facade_body_too_large` past it). Verified by three tests plus
the live streaming leg re-run: `S0.1: 20 lines, first body at 1 ms, last chunk at 20 008 ms`.

The timing leg ran with GET so it measured the response direction alone. The response direction
is method-independent, so the answer above stands regardless of T1.5.

## 7. Still open

| leg | why it is not answered |
|---|---|
| ~~S0.1 facade streaming~~ | **measured** (§6): 20 lines, first byte at 1 ms, last at 20 s. Passed. |
| **S0.4** container → proxy | needs a live saife session with a proxy listener, and a container that tries to reach it. |
| JVM/Gradle daemon cost | **measured** (§5): 3–12 s per build when the daemon starts, ~1.5 s when it is already alive; 479 MB RSS. |

## 8. Reproduce

```powershell
# endpoint without the CLI
$p = [System.IO.Pipes.NamedPipeClientStream]::new(".", "docker_engine", "InOut"); $p.Connect(3000)
$sw = [System.IO.StreamWriter]::new($p); $sw.AutoFlush = $true
$sw.Write("GET /_ping HTTP/1.1`r`nHost: docker`r`nConnection: close`r`n`r`n")
[System.IO.StreamReader]::new($p).ReadToEnd()

# latency
Measure-Command { docker info }
Measure-Command { docker run --rm alpine:3.20 true }
Measure-Command { docker exec <running> true }

# mount vs volume: 20 k files of 1 KB under C:\Users\marku\projekte\runner-probe\tree
docker run --rm -v C:/Users/marku/projekte/runner-probe:/src:ro alpine:3.20 `
  sh -c "time sh -c 'find /src/tree -type f -exec cat {} + > /dev/null'"
docker volume create probevol
tar -C C:/Users/marku/projekte/runner-probe -cf - tree | `
  docker run --rm -i -v probevol:/dst alpine:3.20 tar -xf - -C /dst
docker run --rm -v probevol:/dst:ro alpine:3.20 `
  sh -c "time sh -c 'find /dst/tree -type f -exec cat {} + > /dev/null'"
```

Cleanup after each block (AGENTS.md): `docker rm -f` probes, `docker volume rm probevol`,
`docker ps -a` and `docker volume ls` free of `probe*`, and the scratch tree removed.
