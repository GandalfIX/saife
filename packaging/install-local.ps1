# Install a locally built SAIFE release on this machine.
#
#   pwsh -File packaging\install-local.ps1                 # use the newest saife-*-x64.zip
#   pwsh -File packaging\install-local.ps1 -Zip .\saife-0.2.0-x64.zip
#   pwsh -File packaging\install-local.ps1 -WhatIf
#
# What it does: verifies the archive, extracts it to
# %LOCALAPPDATA%\Programs\saife (or -Destination), and puts that directory on the
# USER PATH so `saife` resolves in new shells.
#
# Why not `winget install --manifest`: a Winget manifest's InstallerUrl must be
# http(s); Winget downloads the asset from the release URL. For a local build there
# is nothing to download, so this script is the local equivalent - and it is what
# the published package does to the same archive.

param(
    [string]$Zip,
    [string]$Destination = (Join-Path $env:LOCALAPPDATA 'Programs\saife'),
    [switch]$WhatIf,
    [switch]$NoPathEntry
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot

if (-not $Zip) {
    $candidate = Get-ChildItem $root -Filter 'saife-*-x64.zip' -File |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if (-not $candidate) { throw "no saife-*-x64.zip in $root - run packaging\build-dist.ps1 -ReleaseVersion <v> first" }
    $Zip = $candidate.FullName
}
if (-not (Test-Path $Zip)) { throw "archive not found: $Zip" }

$hash = (Get-FileHash $Zip -Algorithm SHA256).Hash
Write-Host ("archive: {0}" -f $Zip)
Write-Host ("sha256:  {0}" -f $hash)
Write-Host ("target:  {0}" -f $Destination)

# The manifest is the record of what SHOULD ship; compare when it is available so a
# hand-built archive cannot silently differ from the one being distributed.
$manifest = Join-Path $PSScriptRoot 'winget\GandalfIX.SAIFE-Sandbox.installer.yaml'
if (Test-Path $manifest) {
    $expected = (Select-String -Path $manifest -Pattern 'InstallerSha256:\s*([0-9A-Fa-f]+)' |
        Select-Object -First 1).Matches[0].Groups[1].Value
    if ($expected) {
        if ($expected.ToUpper() -eq $hash) {
            Write-Host 'manifest: InstallerSha256 matches'
        } else {
            Write-Warning ("manifest: InstallerSha256 is {0}, archive is {1} - the manifest is stale (bump it before publishing)" -f $expected, $hash)
        }
    }
}

if ($WhatIf) { Write-Host 'WhatIf: nothing extracted, PATH untouched.'; return }

if (Test-Path $Destination) {
    $existing = Join-Path $Destination 'saife.exe'
    if (Test-Path $existing) {
        $old = (Get-Item $existing).VersionInfo.FileVersion
        Write-Host ("replacing existing install (file version '{0}')" -f $old)
    }
    Remove-Item $Destination -Recurse -Force
}
New-Item -ItemType Directory -Path $Destination -Force | Out-Null
Expand-Archive -Path $Zip -DestinationPath $Destination -Force

$exe = Join-Path $Destination 'saife.exe'
$launcher = Join-Path $Destination 'saife-launch.exe'
foreach ($f in @($exe, $launcher)) {
    if (-not (Test-Path $f)) { throw "archive did not contain $(Split-Path -Leaf $f)" }
}

Write-Host ''
Write-Host '== installed, self-check:'
& $exe --version
& $exe setup --check-only | Select-Object -First 4

if (-not $NoPathEntry) {
    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    $parts = @($userPath -split ';' | Where-Object { $_ })
    if ($parts -notcontains $Destination) {
        $newPath = (@($parts) + $Destination) -join ';'
        [Environment]::SetEnvironmentVariable('Path', $newPath, 'User')
        Write-Host ('PATH (user): added {0} - open a NEW shell for saife to resolve' -f $Destination)
    } else {
        Write-Host 'PATH (user): already present'
    }
}

Write-Host ''
Write-Host 'next:'
Write-Host '  saife --version                     # in a NEW shell'
Write-Host '  saife run --allow-cwd -- cmd /c echo ok'
Write-Host ("  uninstall: Remove-Item '{0}' -Recurse -Force  (and drop it from PATH)" -f $Destination)
