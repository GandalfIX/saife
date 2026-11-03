# Building a Gradle project inside a saife session — what an agent needs to know

This is the reference an agent skill should be written from. It describes the contract as it is
implemented on `feat/gradle-build-runner`, not as it was once planned.

## The one thing that governs everything else

Inside a saife session **there is no network and no loopback**. Gradle cannot run there: its
daemon, its workers and its compiler daemons all speak over loopback, and `connect()` fails with
`WSAEACCES 10013` in both directions. `--no-daemon` does not help, because Gradle forks a
single-use daemon anyway.

So the build does not happen where you are. You **ask** for it, over the session's own proxy, and
the supervisor runs it in a container it owns. You never invoke `./gradlew` yourself.

## The contract

```
POST http://build.sandbox.invalid/build
{"project":"app","task":"build","profile":"gradle","paths":["settings.gradle.kts","app"]}
```

```json
{"id":"b1"}
```

then

```
GET http://build.sandbox.invalid/build?id=b1&follow=1
```

streams the log while the build runs, and ends with a verdict:

| ending | meaning |
|---|---|
| `{"exited":0}` | success |
| `{"failed":N}` | the build failed with Gradle's exit code N — read the log, do not retry |
| `{"timed_out":true}` | `limits.workloadTimeoutSecs` ran out; the slot was removed |
| `runner_build_id_missing` | your request had no `id` — check the POST's answer first |

**Fields, and the limits on them:**

| field | values |
|---|---|
| `task` | `assemble`, `build`, `check`, `clean`, `test` — an allow-list, not a pattern |
| `project` | path inside the session workspace; no `..`, no drive, no UNC, no junction |
| `profile` | `gradle` |
| `paths` | optional allow-list of relative paths to copy; absent = the whole project |

**There is no field for an image, a mount, an environment variable, a command line or a flag.**
Those are constants on the supervisor's side. A request that could name them would be a sandbox
escape, so the type simply has nowhere to put one. If a build seems to need one, it is not a build
this runner supports — say so instead of working around it.

The body must be under 4 KiB, and the proxy only relays the `(method, path)` pairs the runner
declares: `POST /build` and `GET /build`. Anything else answers `403 facade_operation_not_declared`.

## Starting a session that can build (host-side, not from inside)

```
saife run --block-net --runner --allow-cwd -- powershell -NoProfile
```

`--runner` works with `--block-net`: the proxy carries the facade and denies all egress
(`network_blocked`), which is the posture a build wants. Without `--runner` there is no facade at
all. `--backend appcontainer` refuses with `runner_unsupported_backend`; no engine running gives
exit code **5**.

## The copy, and why `paths` matters

The project is packed into a tar and copied into the container. `build/`, `.gradle/` and `.git/`
are always skipped, at every level. Two consequences:

- a build sees a **snapshot**: edits made while it runs are invisible to that build
- a monorepo should be **named**, not copied whole, when you only need part of it:

```json
{"project":"monorepo","task":"test",
 "paths":["settings.gradle.kts","gradle","gradlew","build-logic","apps/payments"]}
```

The list is a **closed set**: Gradle needs the root settings and every `includeBuild(...)` root,
so listing `apps/payments` alone gives a build that fails at configuration time. A missing path is
refused by name rather than silently copied around. A profile can carry the default
(`runner.sync.paths`); a request that names `paths` wins entirely.

## Prewarm: the only step with a network

Builds run `./gradlew --offline` in a container with `NetworkMode: none`. Anything a task needs
must already be in the shared cache volume, or the build fails on one named artifact.

```
saife runner prewarm <project>
```

resolves **every** resolvable configuration (compile, runtime, test-compile, test-runtime), so a
new `implementation`/`testImplementation` is picked up by re-running it. It takes seconds when
warm and **minutes when cold** — that is a download, not a hang. Interrupting it leaves a cache
that fails later with `No cached version of <group>:<artifact>:<version> available for offline
mode` — the fix is to run prewarm again, to completion.

So the development loop is: **edit `build.gradle.kts` → `saife runner prewarm <project>` → build.**

## What to do when it fails

| what you see | what it means | what to do |
|---|---|---|
| `No cached version of X available for offline mode` | the cache lacks an artifact (new dependency, or an interrupted prewarm) | run `saife runner prewarm <project>` to completion, then retry the build |
| `runner: the project copy did not take (…) ; retrying` | the copy is being retried (3 × 20 s) | wait; if it fails 3×, remove the container it names and re-run |
| `runner_toolchain_missing` | the pinned image lacks the JDK the build asks for | report it; do not edit the build to lower the requirement |
| `runner_engine_unavailable` / exit 5 | no container engine is running | start it; the runner will not wait |
| `403 facade_operation_not_declared` | you used a method/path the runner does not declare | use `POST /build` and `GET /build` |
| `400 … key must be a string` | the JSON body was mangled on the way in (PowerShell strips quotes for native commands) | send the body from a file: `--data-binary "@body.json"` |
| `timed_out` | the build exceeded `limits.workloadTimeoutSecs` | narrow the task (`assemble` not `build`), or raise the limit in the profile |
| `runner_slot_cap_reached` | 4 slots already running on this machine | stop an idle session; slots are killed after 10 minutes of idleness |

## Rules for the agent

1. **Never run `gradlew` in the session.** It cannot work there, and a failure that looks like a
   Gradle problem is a policy refusal.
2. **Never invent a field.** If the runner refuses your request, the fix is a supported field, not
   a new one.
3. **Read the log before retrying.** A failed build is usually a real compile error; the exit code
   says so.
4. **Prewarm is a user action, not a silent fallback.** A build never goes to the network; if the
   cache is cold, say so and ask for a prewarm rather than retrying the build.
5. **Artifacts come back automatically** — only `build/libs` is synced, into the project directory
   on the host. Everything else stays in the container.
6. **Judge success by the verdict and the artifacts**, not by a quiet terminal: the log streams, so
   silence mid-build means a slow task, not a dead one.

## Seeing what happens

- the log streams per line; a file redirect shows it live, a pipe may not (see the tool's notes)
- the container is a normal container while it runs: `docker ps --filter label=saife.runner=1`,
  then `docker exec <id> ps -eo args`, `du -sm /cache`
- `docker logs <id>` is empty: the output travels over the engine's exec API, not the container's
  stdout
