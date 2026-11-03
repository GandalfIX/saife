# Maven inside a saife session - the reference

This is the long form of `SKILL.md`. It exists so the skill can stay short without losing the
measurements and the failure table a first-time reader needs.

## Why Maven and Gradle take different routes

| | Gradle | Maven |
|---|---|---|
| execution model | daemon + workers + compiler daemons, all over **loopback** | one JVM, in-process, no daemon |
| inside a session | impossible: loopback is closed in both directions (`WSAEACCES 10013`) | works, given the proxy and a writable repository |
| needs saife's runner | yes (`--runner`, facade, container) | **no** |

The session's containment is unchanged: egress still goes through the supervisor's proxy, every
request is still checked against the allow-list, and loopback is still refused. Maven is not
exempted from anything; it simply does not need the one thing the sandbox forbids.

Measured on the dev host: an `mxc` session with a workspace grant runs `javac`/`java` and Maven;
`gradlew build` and any server bind-and-curl test do not.

## Proxy facts

- `HTTP_PROXY` (and `HTTPS_PROXY`) carry the endpoint **with the session token as userinfo**, e.g.
  `http://sandbox:<token>@127.0.0.1:<port>`.
- `SAIFE_PROXY_PORT` carries the same port; useful in a log line, never as the source of truth.
- The supervisor re-injects the variables in **uppercase only**; `http_proxy` is not set.
- The port and token rotate per session. A committed `settings.xml` is therefore not a convenience
  trade-off, it is a guaranteed failure on the next run.

## Bootstrap

Maven is usually not installed, and the Maven Wrapper's own downloader is a Java HTTP client that
does not authenticate to the proxy. Download the distribution with `curl.exe`:

```powershell
curl.exe --ssl-revoke-best-effort -fsSL `
  -o "$env:TEMP\apache-maven.zip" `
  "https://repo.maven.apache.org/maven2/org/apache/maven/apache-maven/3.9.11/apache-maven-3.9.11-bin.zip"
Expand-Archive -Path "$env:TEMP\apache-maven.zip" -DestinationPath ".m2" -Force
```

`--ssl-revoke-best-effort` exists because Schannel cannot reach the revocation endpoint through the
proxy and answers `CRYPT_E_REVOCATION_OFFLINE`. If deleting the zip is denied afterwards, ignore it -
`%TEMP%` is not the problem you are solving.

Pin the version deliberately: `3.9.11` is what this skill was written against; a different version
is a different bootstrap URL and nothing else.

## settings.xml, generated every session

```powershell
$p = [Uri]$env:HTTP_PROXY
$idx = $p.UserInfo.IndexOf(':')
$user = $p.UserInfo.Substring(0, $idx)
$pass = $p.UserInfo.Substring($idx + 1)

@"
<?xml version="1.0" encoding="UTF-8"?>
<settings xmlns="http://maven.apache.org/SETTINGS/1.2.0">
    <proxies>
        <proxy>
            <id>saife-http</id><active>true</active><protocol>http</protocol>
            <host>$($p.Host)</host><port>$($p.Port)</port>
            <username>$user</username><password>$pass</password>
        </proxy>
        <proxy>
            <id>saife-https</id><active>true</active><protocol>https</protocol>
            <host>$($p.Host)</host><port>$($p.Port)</port>
            <username>$user</username><password>$pass</password>
        </proxy>
    </proxies>
</settings>
"@ | Set-Content -Path ".m2\settings.xml" -Encoding ASCII
```

Both protocol entries are needed: Maven matches a proxy by the **repository's** protocol, and
Central is `https`. One entry works until the first `http` mirror appears, which is the worst kind of
latent breakage.

`[Uri].UserName` and `.Password` look like the obvious way to get the credentials. Under Windows
PowerShell 5.1 they return empty strings for an `http` URI while `UserInfo` holds them - verified in
this repo, not quoted from documentation. Split `UserInfo` at the first `:`.

## Required flags

```
-Dmaven.repo.local=<project>\.m2\repository
-Dmaven.resolver.transport=wagon
-Dmaven.compiler.fork=true
```

- **`wagon`** - the default resolver transport (JDK `HttpClient`) does not apply the proxy
  credentials from `settings.xml`; the CONNECT tunnel is reset and Maven reports a connection
  failure that looks like the proxy is down. Wagon (Apache HttpClient) honours them.
- **`compiler.fork=true`** - the in-process compiler cannot release the jar it read; the build dies
  with `Compiler-Ressourcen koennen nicht geschlossen werden` (`cannot close compiler resources`).
- **`repo.local`** - `~\.m2` is outside the workspace, so writes to it are refused. Keep the
  repository inside the grant.

Keep them in `MAVEN_ARGS` so they survive being invoked through the wrapper.

**Do not put `|` in `MAVEN_OPTS`** (a `nonProxyHosts=localhost|127.0.0.1` looks harmless): `mvn.cmd`
expands it through `cmd` and the pipe breaks the command line. Java's defaults already exclude
localhost.

## Verifying without a server

Loopback is refused, so a started application cannot be reached from inside the session - not by
`curl`, not by `Invoke-RestMethod`. Verify the build (`package`), report the artifact path, and say
plainly that running the server is a host-side step.

If you need to prove the JVM can reach the repository through the proxy, this is the shape:

```powershell
java "-Dhttps.proxyHost=$($p.Host)" "-Dhttps.proxyPort=$($p.Port)" -cp <classes> Probe
```

TLS additionally needs an `Authenticator` carrying the proxy credentials and
`-Djdk.http.auth.tunneling.disabledSchemes=` (empty), because the JDK refuses Basic auth over a
tunnel by default. Quote every `-D` argument: an unquoted one can arrive split, and the error then
names a bogus main class.

## Failure table

| message | cause | fix |
|---|---|---|
| `Connection reset`, `Eine bestehende Verbindung wurde softwaregesteuert durch den Hostcomputer abgebrochen` | proxy reached, credentials not sent | `-Dmaven.resolver.transport=wagon` |
| `Permission denied: getsockopt` | stale proxy port (it rotated) | re-read `$env:HTTP_PROXY` |
| `Compiler-Ressourcen koennen nicht geschlossen werden` | in-process compiler jar lock | `-Dmaven.compiler.fork=true` |
| `CRYPT_E_REVOCATION_OFFLINE` | Schannel revocation through the proxy | `curl.exe --ssl-revoke-best-effort` |
| `Access is denied` on `~\.m2` | repository outside the workspace | `-Dmaven.repo.local` inside it |
| proxy refuses with `network_blocked` | host not allow-listed | `--allow-domain repo.maven.apache.org` |
| `BUILD FAILURE` with no network message | a real compile or test failure | read it; do not retry |

## What this skill does not cover

- Gradle: it needs the runner. See `../saife-build/`.
- The Maven Wrapper (`.mvn\wrapper`): it works outside the sandbox and its downloader does not work
  inside it. Bootstrap with curl, as above.
- Tests that bind a port: they will fail on the bind, and that is the sandbox being correct.
