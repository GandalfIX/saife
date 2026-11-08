# `jvm` profile

For Java work: the JDK toolchain, Maven and Gradle caches.

## Verified

`javac` and `java` inside the sandbox. **Gradle builds are NOT verified under the
`mxc` backend** — see "Known constraints".

## Grants, and why each is what it is

| grant | why |
|---|---|
| `allow: $CWD` | the workspace. |
| `allow: $USERPROFILE/.gradle` | Gradle's user home: wrapper distributions, caches, daemon registry. Gradle writes here on every build, so read-only would break the first `gradlew` run. |
| `allow: $USERPROFILE/.m2` | Maven's local repository. Same reasoning: `mvn` downloads into it. |
| `read_only: $JAVA_HOME` | the JDK. RX: compile and run, but never replace a JDK binary from an uncontained build script. |
| `deny: $HOME/.ssh`, `$HOME/.aws` | credentials stay out. |

## Network

`repo.maven.apache.org`, `repo1.maven.org`, `plugins.gradle.org`,
`services.gradle.org`, `downloads.gradle.org`. These are the five hosts a clean
Maven/Gradle build needs before it can compile anything.

## Why the JVM stack needs its own proxy configuration

Java ignores `HTTP_PROXY`/`HTTPS_PROXY`. SAIFE injects them, but the JVM will
not read them, so a build over the session proxy needs the proxy spelled out:

- Gradle: `GRADLE_OPTS` system properties (`https.proxyHost`, `https.proxyPort`,
  `https.proxyUser`, `https.proxyPassword`).
- Maven: `<proxies>` in `~/.m2/settings.xml`.

Port **and** token change every session — generate them from `%HTTP_PROXY%`
inside the session, never hard-code them. PS 5.1 reports
`[Uri].UserName`/`.Password` as empty for these URLs; parse `[Uri].UserInfo`
instead.

## Limits

`workloadTimeoutSecs: 7200` — two hours. A cold build downloads a toolchain and
hundreds of artifacts; the default 30 minutes is a guess that expires mid-build.
The budget is `prompt + workload + slack`, so the session ends at roughly 7200 s
plus a couple of minutes.

## Known constraints

- **Gradle's daemon needs loopback.** Client and daemon meet on `127.0.0.1`,
  which the `mxc` backend denies by design. Two supported shapes:
  `profiles/gradle-runner.json` (the supervisor builds through the
  `build.sandbox.invalid` facade) or `--backend appcontainer` from an elevated
  shell. `--no-daemon` does not help the daemon case; `--allow-host-loopback`
  works but opens loopback **unscoped**, and its consequences are not subtle.
- Maven can also be run fully offline: populate `.m2` on the host once
  (`mvn dependency:go-offline`), then `mvn -o` inside — no sockets at all.
