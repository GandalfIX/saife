# `gradle-runner` profile

For Gradle builds under containment: the build itself runs in the supervisor's
**build runner** container; the sandboxed workload only *asks* for it.

## How it works

`--runner` turns on the build facade: the workload `POST`s its build request to
`build.sandbox.invalid` (a host the proxy routes to the supervisor, not to the
internet) and follows the result. The runner keeps a pinned toolchain and a warm
cache, so Gradle's daemon and its loopback needs never appear inside the
session. This is ADR-0006's declared-operations facade.

## Why every setting is what it is

| setting | why |
|---|---|
| `block_net: true` | the session needs **no egress at all**: the build travels over the facade, which needs the proxy, not an allow-list. Zero network capability SIDs is the strongest posture a session can have, and a workload that only edits code loses nothing. |
| `allow: $CWD` only | the runner syncs the project itself (`runner.sync.paths: ["."]`); the session needs its own working directory and nothing else — no Gradle cache, no JDK. The toolchain is pinned inside the runner. |
| `read_only: $HOME/.gitconfig` | git identity for commits made in the session. |
| `deny: $HOME/.ssh`, `$HOME/.aws` | credentials stay out. |
| `workloadTimeoutSecs: 7200` | a cold build downloads and compiles; two hours, same as `jvm`. |

## Run

```powershell
saife run --profile gradle-runner --runner -- <workload>
```

`--runner` is opt-in on purpose: it costs a long-lived container and a second
mount, and a workload that never builds should pay neither.

## What this profile is for

Editing, analysis, tests that do not need the network, and asking for builds.
It is the contained answer to "Gradle cannot build here": instead of opening
loopback (`--allow-host-loopback` opens it **unscoped**), the build is declared,
pinned and executed by the supervisor.
