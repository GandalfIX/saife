---
name: saife-build
description: "Use when asked to build, test or check a Gradle project inside a saife session. Asks the supervisor's runner to run Gradle in a container, because Gradle cannot run in the session itself."
---

# Building with saife's runner

Gradle cannot run inside a saife session: there is no network and no loopback, and Gradle's
daemon, workers and compiler daemons all speak over loopback (`WSAEACCES 10013` in both
directions). `--no-daemon` does not help - Gradle forks a single-use daemon anyway.

So you do not run `./gradlew`. You ask for a build over the session's own proxy, and the
supervisor runs it in a container it owns.

## Ask for a build

```powershell
# the shim, if it is on PATH inside the session
saife-build build
saife-build test ../other

# or by hand - the body goes through a FILE: PowerShell 5.1 strips quotes when handing
# arguments to a native command, and the runner then answers "key must be a string"
$body = '{"project":"app","task":"build","profile":"gradle"}'
Set-Content -NoNewline -Encoding ascii "$env:TEMP\body.json" $body
$start = curl.exe -sS -m 60 -X POST "http://build.sandbox.invalid/build" -H "Content-Type: application/json" --data-binary "@$env:TEMP\body.json"
$start
$id = ($start | ConvertFrom-Json).id
curl.exe -sS -N -m 300 "http://build.sandbox.invalid/build?id=$id&follow=1"
```

The log **streams** while the build runs and ends with a verdict: `{"exited":0}`,
`{"failed":N}`, or `{"timed_out":true}`.

## What you may ask for

| field | values |
|---|---|
| `task` | `assemble`, `build`, `check`, `clean`, `test` |
| `project` | a path inside the session workspace (no `..`, no drive, no UNC, no junction) |
| `paths` | optional allow-list of relative paths to copy; absent = the whole project |
| `profile` | `gradle` |

There is **no field** for an image, a mount, an environment variable or a command line. Those are
constants on the supervisor's side, because a request that could name them would be a sandbox
escape. If a task seems to need one, it is not a task this runner supports - say so.

The body must stay under 4 KiB, and only `POST /build` and `GET /build` are relayed; anything else
is `403 facade_operation_not_declared`.

## Prewarm, and the offline failure

Builds run `./gradlew --offline` in a container with no network. Anything not already in the cache
fails with `No cached version of <group>:<artifact>:<version> available for offline mode`.

That is not something you can fix by retrying, and you cannot run it yourself - prewarm happens on
the host, before or between sessions. **Host-side, not yours:** the user runs

```
saife runner prewarm <project>
```

which resolves every configuration (compile, runtime, test-compile, test-runtime) and takes
seconds when warm, minutes when cold. So the loop is: **edit `build.gradle.kts` -> prewarm ->
build**, and a build never goes to the network.

## Failures, and what they mean

| message | meaning |
|---|---|
| `No cached version of …` | cache is cold or missing that artifact -> prewarm |
| `the project copy did not take (…); retrying` | the copy is retried 3x; if it still fails, say so |
| `runner_toolchain_missing` | the pinned image lacks the required JDK -> report it, do not lower the requirement |
| `runner_engine_unavailable`, exit 5 | no container engine is running -> start it |
| `timed_out` | `limits.workloadTimeoutSecs` ran out -> narrower task, or raise the limit |
| `runner_slot_cap_reached` | 4 slots busy -> close an idle session |

## Rules

1. Never invoke `gradlew` in the session - it cannot work there, and the failure looks like a
   Gradle problem when it is a policy refusal.
2. Never invent a field; a refused request means a supported field was missing.
3. Read the log before retrying: a failed build is usually a real compile error.
4. Only `build/libs` comes back, into the project directory on the host.
5. Judge success by the verdict and the artifacts, not by a quiet terminal - the log streams, so
   silence mid-build is a slow task, not a dead one.

Fuller reference, including the copy/monorepo rules and how to watch the container:
`EXPLANATION.md` next to this file.
