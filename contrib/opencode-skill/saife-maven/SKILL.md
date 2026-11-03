---
name: saife-maven
description: "Use when asked to build, test or package a Maven project inside a saife session. Maven runs in-process, so it needs no runner - only the session proxy, a writable repository, and two flags."
---

# Building with Maven inside a saife session

Maven does **not** need saife's build runner. Gradle does, because its daemon and workers speak over
loopback and loopback is closed in both directions; Maven builds in-process, so it runs where you
are. What it needs is the session proxy, a repository inside a writable directory, and two flags.

## The three things that break by default

| default | why it fails here | what to do |
|---|---|---|
| `~\.m2` | outside the workspace, so not writable | keep Maven and the repository in the project: `-Dmaven.repo.local=<project>\.m2\repository` |
| no proxy settings | the sandbox is proxy-only; there is no direct egress | generate `settings.xml` from `$env:HTTP_PROXY` (below) |
| JDK HttpClient resolver | ignores the proxy credentials in `settings.xml`; the tunnel is reset | `-Dmaven.resolver.transport=wagon` |

The proxy host, port and token **rotate per session**, so never commit `settings.xml` and never
hardcode a port. Regenerate it from the environment every time; `saife-maven.ps1` does exactly that.

## Use it

```powershell
# bootstrap (once), settings.xml (every session), then build - one command
.\saife-maven.ps1 package

# or by hand, three lines that matter
$env:MAVEN_ARGS = "-Dmaven.repo.local=$PWD\.m2\repository -Dmaven.resolver.transport=wagon -Dmaven.compiler.fork=true"
.\.m2\apache-maven-3.9.11\bin\mvn.cmd -s .m2\settings.xml package
```

Whether the repository host is reachable was decided **before you started**: the session either
allows `repo.maven.apache.org` or it does not, and nothing inside the session changes that. A
download refused with `network_blocked` is therefore not a Maven problem and not something to retry -
report it, and say which host was refused.

## Reading the proxy, correctly

```powershell
$p = [Uri]$env:HTTP_PROXY        # uppercase only - saife-launch strips and re-injects it upper
$idx = $p.UserInfo.IndexOf(':')
$user = $p.UserInfo.Substring(0, $idx)
$pass = $p.UserInfo.Substring($idx + 1)
```

**PowerShell 5.1 returns empty strings for `.UserName` and `.Password`** on an `http` URI - measured,
not assumed: `UserInfo` is `sandbox:<token>` while both properties are `""`. Split `UserInfo`
yourself. PowerShell 7 gets it right, which is exactly the kind of difference that makes a script
work on one machine and fail in a session.

## Failures, and what each means

| message | meaning | fix |
|---|---|---|
| `BUILD FAILURE` with `Connection reset` / `softwaregesteuert abgebrochen` | the proxy was reached but the credentials were not sent | `-Dmaven.resolver.transport=wagon` |
| `Permission denied: getsockopt` | the proxy port rotated under you | re-read `$env:HTTP_PROXY`, regenerate `settings.xml` |
| `Schwerwiegender Fehler: Compiler-Ressourcen koennen nicht geschlossen werden` | the in-process compiler holds a jar lock | `-Dmaven.compiler.fork=true` |
| `CRYPT_E_REVOCATION_OFFLINE` | Schannel cannot check revocation through the proxy | `curl.exe --ssl-revoke-best-effort` for downloads |
| `Access is denied` writing `~\.m2` | the repository is outside the workspace | `-Dmaven.repo.local` inside it |
| a download never reaches Maven (`network_blocked`) | the session was not started with that host allowed | report it to the user; it is a host-side decision, not retryable |

## Rules

1. **Never commit `settings.xml`** - it carries the session token. Add `.m2/settings.xml` to
   `.gitignore` in the project you are building.
2. **`curl.exe` for downloads**, not `Invoke-WebRequest`: Windows PowerShell 5.1's
   `Invoke-WebRequest` ignores the proxy environment variables.
3. **Do not smoke-test a server you started.** Loopback is refused by policy, so a bind-and-curl
   check cannot work inside the session; verify by `package` and say the run belongs on the host.
4. **Read `$env:HTTP_PROXY`, nothing else.** `SAIFE_PROXY_PORT` matches it and is useful for
   logging, but the URL is the contract.
5. **`BUILD SUCCESS` is the success line.** Maven has no `BUILD OK`.

Fuller reference, including the bootstrap and the JVM checks: `EXPLANATION.md`.
