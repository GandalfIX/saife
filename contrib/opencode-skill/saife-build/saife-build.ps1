<#
  saife-build - trigger a build in saife's runner, from inside a session.

  The session already carries everything needed: HTTP_PROXY points at the supervisor's proxy
  with the session token, and the runner is reached as http://build.sandbox.invalid/ through
  it. Nothing here holds a credential of its own.

  usage: saife-build [task] [project]
         saife-build build .
         saife-build test ../other
#>
param(
    [string]$Task = "build",
    [string]$Project = "."
)

$ErrorActionPreference = "Stop"

if (-not $env:HTTP_PROXY) {
    Write-Error "saife-build: no HTTP_PROXY in this session - run inside 'saife run', not on the host"
    exit 2
}

$body = @{ project = $Project; task = $Task; profile = "gradle" } | ConvertTo-Json -Compress
$start = & curl.exe -sS --proxy $env:HTTP_PROXY --max-time 30 `
    -X POST "http://build.sandbox.invalid/build" `
    -H "Content-Type: application/json" --data-binary $body
if ($LASTEXITCODE -ne 0) {
    Write-Error "saife-build: the runner is not reachable through the facade (exit $LASTEXITCODE)"
    exit $LASTEXITCODE
}

$id = if ($start -match '"id"\s*:\s*"([^"]+)"') { $Matches[1] } else { $null }
if (-not $id) {
    Write-Error "saife-build: unexpected answer from the runner: $start"
    exit 1
}
Write-Host "saife-build: $Task $Project -> build $id"

# -N: no buffering, so the log arrives as it is produced rather than at the end.
& curl.exe -sS -N --proxy $env:HTTP_PROXY --max-time 7200 `
    "http://build.sandbox.invalid/build?id=$id&follow=1"
exit $LASTEXITCODE
