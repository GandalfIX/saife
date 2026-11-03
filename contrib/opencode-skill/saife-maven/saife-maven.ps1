<#
  saife-maven - build a Maven project inside a saife session.

  Maven does not need saife's runner: it builds in-process, so it runs in the session. What it
  needs is the session proxy (host, port and token rotate per session), a repository inside the
  writable grant, and two flags that the defaults get wrong.

  usage: saife-maven [goal] [project]
         saife-maven package
         saife-maven verify ..\other

  Holds no credential of its own: the proxy URL is read from $env:HTTP_PROXY at run time and written
  to <project>\.m2\settings.xml, which must not be committed.
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)][string]$Goal = 'package',
    [Parameter(Position = 1)][string]$Project = '.',
    [string]$MavenVersion = '3.9.11',
    [Parameter(ValueFromRemainingArguments = $true)][string[]]$Rest,
    # `-v` cannot be passed as a goal (PowerShell reads a leading dash as a parameter name), so the
    # version check that proves the bootstrap worked gets its own switch.
    [switch]$SelfTest
)

$ErrorActionPreference = 'Stop'

if (-not $env:HTTP_PROXY) {
    Write-Error 'saife-maven: no HTTP_PROXY in this session - run inside "saife run", not on the host'
    exit 2
}

$m2 = Join-Path $Project '.m2'
$repoDir = Join-Path $m2 'repository'
$dist = Join-Path $m2 "apache-maven-$MavenVersion"
$mvn = Join-Path $dist 'bin\mvn.cmd'

if (-not (Test-Path -LiteralPath $mvn)) {
    Write-Host "saife-maven: bootstrapping Maven $MavenVersion into $dist"
    New-Item -ItemType Directory -Force -Path $m2 | Out-Null
    $zip = Join-Path $env:TEMP "apache-maven-$MavenVersion.zip"
    $url = "https://repo.maven.apache.org/maven2/org/apache/maven/apache-maven/$MavenVersion/apache-maven-$MavenVersion-bin.zip"
    # --ssl-revoke-best-effort: Schannel cannot check revocation through the proxy
    & curl.exe --ssl-revoke-best-effort -fsSL -o $zip $url
    if ($LASTEXITCODE -ne 0) { Write-Error "saife-maven: download failed ($LASTEXITCODE) - is repo.maven.apache.org allowed for this session?"; exit 1 }
    Expand-Archive -Path $zip -DestinationPath $m2 -Force
}

# settings.xml from the session proxy, every run: port and token rotate
$p = [Uri]$env:HTTP_PROXY
$idx = $p.UserInfo.IndexOf(':')
if ($idx -lt 1) { Write-Error "saife-maven: HTTP_PROXY has no userinfo - expected http://user:token@host:port"; exit 1 }
$user = $p.UserInfo.Substring(0, $idx)
$pass = $p.UserInfo.Substring($idx + 1)
$settings = Join-Path $m2 'settings.xml'

$xml = @"
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
"@
Set-Content -Path $settings -Value $xml -Encoding ASCII

# the three flags that are not optional here, plus anything the caller passed
$env:MAVEN_ARGS = "-Dmaven.repo.local=$repoDir -Dmaven.resolver.transport=wagon -Dmaven.compiler.fork=true"

Write-Host "saife-maven: $Goal ($Project) via proxy $($p.Host):$($p.Port)"
if ($SelfTest) {
    & $mvn -s $settings -B -v
    exit $LASTEXITCODE
}
& $mvn -s $settings -B @Goal @Rest
exit $LASTEXITCODE
