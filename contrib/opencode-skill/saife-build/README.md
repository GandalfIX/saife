# saife-build (opencode skill)

The trigger for saife's build runner, for an agent working **inside** a session.

| file | what it is |
|---|---|
| `EXPLANATION.md` | the reference the skill is written from: the contract, the copy rules, prewarm, the failure table, and the rules for an agent |
| `SKILL.md` | the skill itself, written from that reference |
| `saife-build.ps1` | a two-call shim: `POST /build`, then stream `&follow=1` |

## Why a shim *and* a skill

A skill is prompt-level advice; a model can misremember a URL or invent a flag. The shim makes the
common case one command, and the facade makes the wrong case impossible: only the declared
`(method, path)` pairs are relayed, the request type has no field for an image, a mount or a
command, and every request lands in the session's audit chain.

Neither file is enforcement. If they disagree with the socket, the socket wins.

## Install (not automated)

```powershell
# inside the session, on PATH
Copy-Item .\saife-build.ps1 "$env:USERPROFILE\.local\bin\saife-build.ps1"

# skill, for opencode
Copy-Item .\SKILL.md "$env:USERPROFILE\.config\opencode\skills\saife-build\SKILL.md"
```

These live in the repo, not in an installed build. They describe `feat/gradle-build-runner`,
which is not in any released version yet.
