# Build runner — S-0 measurements

**Status:** partial, 2026-10-30. Three of the six legs are measured; `S0.1` (facade streaming)
and `S0.4` (container → proxy) need product code or a live session before they mean anything.

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

## 5. Still open

| leg | why it is not answered |
|---|---|
| **S0.1** facade streaming | needs a declared facade operation that emits for 10 minutes; that is the first slice of product code. Until then the only fact is that `HEAD_READ_TIMEOUT` (15 s) covers the request *head*, not the response body. |
| **S0.4** container → proxy | needs a live saife session with a proxy listener, and a container that tries to reach it. |
| Gradle daemon cost (part of S0.2) | needs a JDK image plus a fixture project; this is the number that decides long-lived container vs ephemeral per build. |

## 6. Reproduce

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
