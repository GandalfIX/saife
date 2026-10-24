# checkpoint4.ps1 - ADR-0001 Checkpoint 4 driver (run in an ELEVATED PowerShell).
# Prereq: mock-proxy.ps1 already running in a second elevated window.
# Each stage prints PASS/FAIL-style "CHECK <name>: ..." lines.
$ErrorActionPreference = 'Continue'
# Paths are derived from this script so the checkout can live anywhere: the repo
# moved out of the tools monorepo on 2026-10-24 and absolute paths went stale.
$repo = Split-Path -Parent $PSScriptRoot
$exe = Join-Path $repo 'target\release\saife.exe'
$mockLog = Join-Path $PSScriptRoot 'mock-proxy.log'
$profMock = Join-Path $PSScriptRoot 'profile-mock.json'
$profDead = Join-Path $PSScriptRoot 'profile-dead.json'
$work = Join-Path $env:TEMP ('c4-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $work | Out-Null

function Count-Tunnels([string]$host_) {
    if (-not (Test-Path $mockLog)) { return 0 }
    return @(Select-String -Path $mockLog -Pattern ('TUNNEL-UP: ' + [regex]::Escape($host_)) -SimpleMatch:$false).Count
}

Write-Host "== C4.1 CHAINED REQUEST (profile -> mock proxy) =="
Remove-Item Env:HTTPS_PROXY, Env:HTTP_PROXY, Env:NO_PROXY -ErrorAction SilentlyContinue
$before = Count-Tunnels 'anthropic.com:443'
$r = & $exe run --profile $profMock --allow-cwd --allow-domain anthropic.com --no-prompt -- `
    cmd /c curl.exe -sS -o NUL -w "connect=%{http_connect} http=%{http_code}" https://anthropic.com 2>&1
$after = Count-Tunnels 'anthropic.com:443'
Write-Host "CHECK c4.1: output=[$r] tunnelsBefore=$before tunnelsAfter=$after"
Write-Host "  EXPECT: connect=200 (a real tunnel) and tunnelsAfter > tunnelsBefore (mock saw the CONNECT)"
Write-Host "  mock log tail:"; if (Test-Path $mockLog) { Get-Content $mockLog -Tail 6 }

Write-Host ""
Write-Host "== C4.2 NO_PROXY BYPASS (host env, direct dial) =="
$env:NO_PROXY = 'anthropic.com'
$before2 = Count-Tunnels 'anthropic.com:443'
$r2 = & $exe run --profile $profMock --allow-cwd --allow-domain anthropic.com --no-prompt -- `
    cmd /c curl.exe -sS -o NUL -w "connect=%{http_connect} http=%{http_code}" https://anthropic.com 2>&1
$after2 = Count-Tunnels 'anthropic.com:443'
Remove-Item Env:NO_PROXY -ErrorAction SilentlyContinue
Write-Host "CHECK c4.2: output=[$r2] tunnelsBefore=$before2 tunnelsAfter=$after2"
Write-Host "  EXPECT: connect=200 and tunnelsAfter == tunnelsBefore (mock saw NOTHING - dialed direct)"

Write-Host ""
Write-Host "== C4.3 G-42 OVERRIDE WARNING (profile vs host HTTPS_PROXY) =="
$env:HTTPS_PROXY = 'http://127.0.0.1:1'
$env:SANDBOX_DIAG = '1'
$r3 = & $exe run --profile $profMock --allow-cwd --allow-domain anthropic.com --no-prompt -- cmd /c echo hi 2>&1
Remove-Item Env:HTTPS_PROXY, Env:SANDBOX_DIAG -ErrorAction SilentlyContinue
$diagnostic = ($r3 | Out-String)
$has42 = $diagnostic -match 'differs from host HTTPS_PROXY/HTTP_PROXY \(127\.0\.0\.1:1\); using the profile value'
Write-Host "CHECK c4.3: g42Notice=$has42"
if (-not $has42) { Write-Host "  stderr/stdout was:"; Write-Host $diagnostic }
Write-Host "  EXPECT: g42Notice=True and the notice names only host:port values (no userinfo)"

Write-Host ""
Write-Host "== C4.4 DEAD UPSTREAM -> 502 + X-Sandbox: upstream-error + TWO audit leaves =="
$sid = (& $exe run --allow-cwd --allow-domain anthropic.com --no-prompt --print-sid -- cmd /c echo hi | Select-Object -Last 1).Trim()
$headers = & $exe run --profile $profDead --allow-cwd --allow-domain anthropic.com --no-prompt --sid $sid -- `
    cmd /c curl.exe -sS -D - -o NUL https://anthropic.com 2>&1
$h = ($headers | Out-String)
$is502 = $h -match 'HTTP/1\.1 502 Bad Gateway'
$hasHeader = $h -match 'X-Sandbox: upstream-error'
$namesProxy = $h -match '127\.0\.0\.1:1'
$audit = (& $exe audit show $sid --json | Out-String)
$leaves = @(($audit -split "`r?`n") | Where-Object { $_ -match '"op":"CONNECT"' -and $_ -match 'anthropic\.com' })
$firstAllow = $leaves.Count -ge 1 -and $leaves[0] -match '"source":"allowlist"' -and $leaves[0] -match '"disposition":"allow"'
$secondDeny = $leaves.Count -ge 2 -and $leaves[1] -match '"source":"default"' -and $leaves[1] -match '"reason":"upstream_error"'
Write-Host "CHECK c4.4: status502=$is502 header=$hasHeader namesProxy=$namesProxy leaves=$($leaves.Count) firstAllow=$firstAllow secondDeny=$secondDeny"
Write-Host "  EXPECT: status502=True header=True namesProxy=True leaves=2 firstAllow=True secondDeny=True"

Write-Host ""
Write-Host "== C4.5 MOCK LOG CONTENT =="
if (Test-Path $mockLog) {
    Get-Content $mockLog -Tail 12
    Write-Host "EXPECT: CONNECT-REQ: CONNECT anthropic.com:443 HTTP/1.1"
    Write-Host "        HDR: Proxy-Authorization: Basic ...   (profile had user:pass)"
    Write-Host "        TUNNEL-UP / TUNNEL-DOWN lines for the chained run"
} else {
    Write-Host "no mock log - was mock-proxy.ps1 running?"
}
Write-Host ""
Write-Host "work dir: $work (safe to delete)"
