# saife-maven (opencode skill)

The Maven trigger for an agent working **inside** a saife session.

| file | what it is |
|---|---|
| `SKILL.md` | the skill: the three defaults that break, the command, the failure table, five rules |
| `EXPLANATION.md` | the reference behind it: why Maven needs no runner, the bootstrap, `settings.xml`, the required flags, the measurements |
| `saife-maven.ps1` | a shim: bootstrap Maven if absent, generate `settings.xml` from `$env:HTTP_PROXY`, run the goal |

## Why a shim *and* a skill

A skill is prompt-level advice, and the two things that break here are easy to get subtly wrong: the
repository path must be inside the grant, and the proxy credentials must be read from
`$env:HTTP_PROXY` on every session because the port and token rotate. The shim makes that the
default, and it holds no credential of its own - it copies the session's, at run time, into a file
that `.gitignore` must exclude.

## Maven versus Gradle: different skills, different reasons

Gradle cannot run in a session at all: its daemon speaks over loopback, which is closed in both
directions. Gradle therefore goes through saife's runner (`saife-build`, a container the supervisor
owns).

Maven builds in-process, so it runs **inside** the session, and this skill is about making the proxy
and the repository work there. Nothing here weakens containment: egress still passes the supervisor's
proxy and the allow-list, and loopback is still refused.

## Install (not automated)

```powershell
# inside the session, on PATH
Copy-Item .\saife-maven.ps1 "$env:USERPROFILE\.local\bin\saife-maven.ps1"

# skill, for opencode
Copy-Item .\SKILL.md "$env:USERPROFILE\.config\opencode\skills\saife-maven\SKILL.md"
```

Add `.m2/settings.xml` and `.m2/apache-maven-*/` to the built project's `.gitignore`; the first
contains this session's token.

These files live in the repo, not in an installed build.
