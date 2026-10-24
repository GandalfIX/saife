# mock-proxy.ps1 - minimal HTTP CONNECT proxy for ADR-0001 Checkpoint 4.
# Listens on 127.0.0.1:18080, logs every CONNECT request line + auth header,
# dials the target for real and splices bytes both ways.
# Start it in a SECOND elevated PowerShell window:
#   pwsh -NoProfile -File C:\Users\marku\tools\sandbox-checkpoint4\mock-proxy.ps1
param(
    [int]$Port = 18080,
    [string]$Log = "$PSScriptRoot\mock-proxy.log"
)
$ErrorActionPreference = 'Continue'
function Write-Log([string]$m) { "$(Get-Date -Format 'HH:mm:ss.fff') $m" | Out-File -Append -FilePath $Log -Encoding utf8 }

"=== mock CONNECT proxy on 127.0.0.1:$Port ($(Get-Date -Format HH:mm:ss)) ===" | Out-File -Append -FilePath $Log -Encoding utf8
$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $Port)
$listener.Start()
Write-Host "mock proxy listening on 127.0.0.1:$Port - log: $Log"

while ($true) {
    $client = $listener.AcceptTcpClient()
    # Accepted sockets inherit the listener's non-blocking mode - force blocking.
    $client.Client.Blocking = $true
    $null = Start-ThreadJob -ArgumentList $client, $Log -ScriptBlock {
        param($c, $log)
        function L([string]$m) { "$(Get-Date -Format 'HH:mm:ss.fff') $m" | Out-File -Append -FilePath $log -Encoding utf8 }
        try {
            $s = $c.GetStream()
            $s.ReadTimeout = 15000
            $buf = New-Object byte[] 8192
            $sb = New-Object System.Text.StringBuilder
            while ($true) {
                $n = $s.Read($buf, 0, $buf.Length)
                if ($n -le 0) { break }
                [void]$sb.Append([Text.Encoding]::ASCII.GetString($buf, 0, $n))
                if ($sb.ToString().Contains("`r`n`r`n")) { break }
            }
            $head = $sb.ToString()
            $first = ($head -split "`r`n")[0]
            L "CONNECT-REQ: $first"
            foreach ($line in ($head -split "`r`n")) {
                if ($line -match '^(Host|Proxy-Authorization):') { L "  HDR: $line" }
            }
            if ($first -notmatch '^CONNECT\s+([^\s:]+):(\d+)\s+HTTP/1\.[01]$') {
                L "UNSUPPORTED: $first"
                $r = [Text.Encoding]::ASCII.GetBytes("HTTP/1.1 405 Method Not Allowed`r`nContent-Length: 0`r`n`r`n")
                $s.Write($r, 0, $r.Length); $c.Close(); return
            }
            $target = $Matches[1]; $tport = [int]$Matches[2]
            $up = [System.Net.Sockets.TcpClient]::new()
            $up.Connect($target, $tport)
            $us = $up.GetStream()
            $ok = [Text.Encoding]::ASCII.GetBytes("HTTP/1.1 200 Connection Established`r`n`r`n")
            $s.Write($ok, 0, $ok.Length)
            L "TUNNEL-UP: ${target}:$tport"
            $t1 = $s.CopyToAsync($us)
            $t2 = $us.CopyToAsync($s)
            [void][System.Threading.Tasks.Task]::WaitAny(@($t1, $t2))
            L "TUNNEL-DOWN: ${target}:$tport"
            $c.Close(); $up.Close()
        } catch {
            L "ERR: $($_.Exception.Message)"
            try { $c.Close() } catch { }
        }
    }
}
