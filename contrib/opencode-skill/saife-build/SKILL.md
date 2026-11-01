---
name: saife-build
description: "Use when the user asks to build, test or check a JVM/Gradle project inside a saife session. Runs the build in saife's runner (a container reached through the facade), never in the session."
---

# Building with saife's runner

Gradle cannot build inside a saife session: its daemon, workers and compiler daemons all talk
over loopback, and loopback is closed in both directions in a session (`connect()` fails with
`WSAEACCES 10013`). `--no-daemon` does not help - Gradle forks a single-use daemon anyway.

The build therefore happens **outside** the session, in a container the supervisor manages, and
the result is synced back. You trigger it; you do not run `gradlew` yourself.

## How to trigger a build

```powershell
saife-build                 # task "build", project "."
saife-build test            # any of: assemble, build, check, clean, test
saife-build build ../other  # a project directory inside the session workspace
```

`saife-build` is a two-line HTTP client over the session proxy. Everything it can ask for is
what the runner accepts:

```http
POST http://build.sandbox.invalid/build
{"project":"app","task":"build","profile":"gradle"}
```

## What you cannot ask for - on purpose

There is **no field** for an image, a mount, an environment variable, a command line or a flag.
Those are constants on the supervisor's side, because a request that could name them would be a
sandbox escape (`-v C:\:/host`, `--privileged`). If a task seems to need one, it is not a task
this runner supports - say so instead of trying to work around it.

The only free choices are:

| field | allowed values |
|---|---|
| `task` | `assemble`, `build`, `check`, `clean`, `test` |
| `project` | a path inside the session workspace (no `..`, no absolute or UNC path) |
| `profile` | `gradle` |

## Reading the result

- The log streams **while the build runs** (line per line, not at the end). Watch it; do not
  assume success from a quiet terminal.
- The exit code is the build's. A non-zero code means the build failed: read the log rather
  than retrying.
- Artifacts appear in the project directory on the host (`build/libs/*.jar`), synced back when
  the build ends. Everything else in `build/` stays in the container.

## Common failures, and what they mean

| message | meaning |
|---|---|
| `runner_engine_unavailable` | no container engine is running (Rancher/Docker Desktop is closed). Start it; the runner will not wait for it. |
| `runner_toolchain_missing` | the pinned image does not carry the JDK your build asks for. Not something to fix by editing the build - report it. |
| a dependency resolution failure with `--offline` | the cache is cold or missing that artifact. Ask the user to run `saife runner prewarm <project>`; a build never goes to the network. |
| `runner_build_id_missing`, `runner_operation_unknown` | your request was malformed - use `saife-build`, not hand-rolled HTTP. |

## What this skill is not

It is documentation, not enforcement. The control is the facade: the supervisor relays only the
`(method, path)` pairs the runner declares (`POST /build`, `GET /build`), the request type has no
field for anything else, and every request is in the session's audit chain. If this skill and the
socket disagree, the socket is right.
