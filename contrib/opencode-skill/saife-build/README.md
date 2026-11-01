# saife-build (opencode skill)

The trigger for saife's build runner, for an agent working **inside** a session.

| file | what it is |
|---|---|
| `SKILL.md` | the skill: when to build, the one command, what it may not ask for, how to read failures |
| `saife-build.ps1` | the shim it tells you to run: two `curl` calls through the session proxy |

## Why a shim instead of just a skill

A skill is prompt-level advice; a model can misremember a URL or invent a flag. The shim makes
the common case one command, and the facade makes the wrong case impossible: the supervisor
relays only the `(method, path)` pairs the runner declares, the request type has no field for an
image, a mount or a command, and every request lands in the session's audit chain.

Neither file is enforcement. If they disagree with the socket, the socket wins.

## Install (not automated)

```powershell
# inside the session, on PATH
Copy-Item .\saife-build.ps1 "$env:USERPROFILE\.local\bin\saife-build.ps1"

# skill, for opencode
Copy-Item .\SKILL.md "$env:USERPROFILE\.config\opencode\skills\saife-build\SKILL.md"
```

Not wired into `saife` yet: the runner is being implemented on `feat/gradle-build-runner`, and
these files document its intended contract before the code that enforces it is finished.
