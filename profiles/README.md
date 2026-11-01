# Sample profiles

Copy the one you need to `%USERPROFILE%\.saife\profiles\` and run
`saife run --profile <name> --allow-cwd -- <command>`.

Paths use the variables the loader expands: `$CWD`, `$HOME`, `$USERPROFILE`,
`$TEMP`, `$LOCALAPPDATA`, `$APPDATA`, `$JAVA_HOME`, `$SID`. (`$LOCALAPPDATA`/`$APPDATA` were
added on 2026-10-23; before that the samples spelled `AppData/Local` out.
`$JAVA_HOME` was added on 2026-10-25 so `jvm.json` stops naming one JDK version;
it must be set in the environment the supervisor starts in, and is refused
otherwise rather than expanding to nothing.)

These profiles were built from the toolchains installed on this machine and each
one was exercised in a real sandboxed run, not just parsed.

## Windows caveat: `.cmd` and `.bat` entry points

`saife`, `npm`, `npx`, `gradle`, `mvn`, `yarn` and `pnpm` are batch shims on
Windows (`npm.cmd`, `gradle.bat`, ...). The launcher starts the program directly
and does **not** apply `PATHEXT`, so:

```powershell
saife run --profile node --allow-cwd -- npm --version        # fails: file not found
saife run --profile node --allow-cwd -- cmd /c "npm --version"   # works
saife run --profile node --allow-cwd -- npm.cmd --version    # also works
```

Use `cmd /c "..."` (or the explicit extension). This is a known launcher gap, not
a profile restriction.

## `node.json` — Node.js / npm

| access | path | why |
|---|---|---|
| read-write | `$CWD` | the project, `node_modules` |
| read-write | `$LOCALAPPDATA\npm-cache` | npm's content cache |
| read-write | `$APPDATA\npm` | global installs and shims |
| read-only | `$LOCALAPPDATA\nvm` | the Node versions nvm-windows manages |
| read-only | `C:\nvm4w` | the `NVM_SYMLINK` that `node`/`npm` resolve through |
| read-only | `$HOME\.npmrc` | user config |
| network | `registry.npmjs.org`, `registry.npmjs.com`, `nodejs.org` | packages, and nvm version downloads |

Verified: `npm install left-pad` from a scratch project completed and `require`d
the package inside the sandbox (`v24.13.0` resolved through the nvm symlink,
npm `11.6.2`).

The npm cache is 23k objects / ~2 GB. That is fine on the default backend — the
grants are path rules in a kernel policy. On `--backend appcontainer` this path
is **not** fully granted: that backend stops propagating DACLs at 20,000 objects,
which is the `grant propagation ... truncated` warning.

## `jvm.json` — Java, Gradle, Maven

| access | path | why |
|---|---|---|
| read-write | `$CWD` | the project, `build/`, `target/` |
| read-write | `$HOME\.gradle` | Gradle caches, wrapper distributions, daemon logs |
| read-write | `$HOME\.m2` | Maven local repository |
| read-only | `$JAVA_HOME` | the JDK, wherever this machine keeps it |
| network | `repo.maven.apache.org`, `repo1.maven.org`, `plugins.gradle.org`, `services.gradle.org`, `downloads.gradle.org` | dependencies and wrapper downloads |

`$JAVA_HOME` rather than the install path: the grant is the JDK directory itself,
not its parent (`C:\Program Files\Microsoft` also holds `OneDrive`, which must not
be readable), and the profile survives a JDK upgrade. If `JAVA_HOME` is unset the
profile is refused instead of granting an empty path — set it, or write the path
out.

Verified: `javac Hello.java && java Hello` printed `JVM-OK 25.0.4.1`, and
`gradle --version` started with launcher JVM 25.0.4.1.

**Gradle builds do not run under the default backend.** `gradle build` fails with
`Could not connect to the Gradle daemon`: the daemon listens on `127.0.0.1:<port>`
and connects the client over loopback, which the session's egress policy denies
(`WSAEACCES` on `Connect` to `127.0.0.1`; measured in-sandbox). This is the
policy working as designed — proxy-only egress has no loopback exception — not a
missing grant, and `--no-daemon` does not help because Gradle forks a single-use
daemon and connects to it anyway. Options: run the build under
`--backend appcontainer` (elevated, with loopback), or decide an ADR-level change
to permit loopback egress. `javac`/`java` and Maven, which build in-process, are
unaffected.

`~/.m2` does not exist on this machine and Maven is not installed: the profile
carries the paths, but it is unverified until Maven is. Create the directory
first (`mkdir %USERPROFILE%\.m2`) — an allow entry cannot create the root it
grants.

## `gradle-runner.json` — a session that builds through the runner

**Not in a released build.** The runner lives on `feat/gradle-build-runner`; the
commands named below do not exist in 0.3.x, and this profile is documented so
the shape is reviewable before the code is merged.

| access | path | why |
|---|---|---|
| read-write | `$CWD` | the sources the runner copies **in**, and `build/libs` it copies **back** |
| read-only | `$HOME/.gitconfig` | git's identity, for the commit a build session usually ends with |
| deny | `$HOME/.ssh`, `$HOME/.aws` | the same secrets every other sample denies |
| network | **none** (`block_net: true`) | the build's network is the container's, and the container has none |
| limits | `workloadTimeoutSecs: 7200` | a build session is a long session; the default is 30 min |

What it deliberately does **not** grant: the JDK and `$USERPROFILE/.gradle`. The
image carries the toolchain (the sample project's conventions require Java 25,
and the pinned digest is a JDK 25 image), and the cache volume carries
`~/.gradle` *inside* the container at `/cache`. Granting either on the host
would hand the session back exactly what moving the build out of it was for;
`jvm.json` is the profile that needs both, because it runs Gradle on the host.

**The runner's `profile` field is not this file.** A build request names
`"profile": "gradle"`, which is one of the runner's own names
(`src/runner/mod.rs::PROFILES`), not a saife profile. This file is the session
posture *around* the runner: what the agent may touch, and that it has no
network at all.

**The one honest gap.** `block_net: true` names **no listener**
(`net::resolve_network_with` returns `NetworkConfig::Blocked`; test
`a_facade_does_not_survive_block_net`), and the runner is reached through the
supervisor's facade, which lives in that listener. So this is the "build-only,
no egress at all" posture. A session that has to *ask* the runner for a build
needs the facade flag rather than `block_net`, and that wiring does not exist
yet (nothing outside `src/runner/` calls `runner::server::spawn` or
`DockerBuilds`). When it lands, the choice between "no listener" and "a listener
with an empty allow-list" belongs to that task, not to a profile.

## `opencode.json` — see the user guide

`opencode` has its own section in `docs/USER-GUIDE.md` (interactive tools); its
profile additionally grants the three AppData state directories, the WinGet tree
read-only (so the executable is found), and its model-catalogue and provider
hosts.
