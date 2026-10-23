# Assemble the shippable bundle: dist/ + a versioned zip.
#
#   pwsh -File packaging/build-dist.ps1              # build, assemble, zip
#   pwsh -File packaging/build-dist.ps1 -SkipBuild   # assemble what is already built
#
# The executables are built with a STATIC C runtime so the target machine needs no
# VC++ redistributable; that build lives in target-static/ so it never invalidates
# the normal debug/release artifacts used by the test lanes.

param(
    [switch]$SkipBuild,
    # When set, ALSO produce the release asset Winget consumes:
    # saife-<version>-x64.zip, FLAT (no wrapper directory) and with the binary
    # named saife.exe, because NestedInstallerFiles paths are relative to the
    # archive root. The human bundle (dist/ + sandbox-<sha>.zip) stays wrapped.
    [string]$ReleaseVersion
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot          # sandbox/
$dist = Join-Path $root 'dist'
$staticTarget = Join-Path $root 'target-static'
$repo = Join-Path (Split-Path -Parent $root) '.git'

if (-not $SkipBuild) {
    Write-Host '== building static-CRT binaries'
    $env:CARGO_TARGET_DIR = $staticTarget
    $env:RUSTFLAGS = '-C target-feature=+crt-static'
    Push-Location $root
    try {
        & cargo build --release --bin sandbox --bin mxc-launch
        if ($LASTEXITCODE -ne 0) { throw "cargo build failed ($LASTEXITCODE)" }
    } finally {
        Pop-Location
        Remove-Item Env:CARGO_TARGET_DIR -ErrorAction SilentlyContinue
        Remove-Item Env:RUSTFLAGS -ErrorAction SilentlyContinue
    }
}

$bin = Join-Path $staticTarget 'release'
foreach ($exe in 'sandbox.exe', 'mxc-launch.exe') {
    if (-not (Test-Path (Join-Path $bin $exe))) {
        throw "$exe not found in $bin - run without -SkipBuild once"
    }
}

Write-Host '== assembling dist/'
if (Test-Path $dist) { Remove-Item $dist -Recurse -Force }
New-Item -ItemType Directory -Path (Join-Path $dist 'profiles'), (Join-Path $dist 'plugins') | Out-Null

Copy-Item (Join-Path $bin 'sandbox.exe'), (Join-Path $bin 'mxc-launch.exe') -Destination $dist
Copy-Item (Join-Path $root 'profiles/opencode.json'), (Join-Path $root 'profiles/node.json'),
          (Join-Path $root 'profiles/jvm.json') -Destination (Join-Path $dist 'profiles')

# Portable demo profile: the tracked one is not shipped, and the operator's local
# copy may carry machine-specific paths.
$demo = @'
{
  "meta": { "name": "demo", "version": "1.0", "description": "Portable docs example", "schema_version": 1 },
  "filesystem": {
    "read_only": ["$TEMP/sbx-demo", "$USERPROFILE/.cargo", "$USERPROFILE/.rustup"]
  },
  "network": {
    "allow_domain": ["api.anthropic.com"],
    "promptEnabled": false,
    "workloadTimeoutSecs": 3600
  }
}
'@
Set-Content -Path (Join-Path $dist 'profiles/demo.json') -Value $demo -NoNewline

$pluginSrc = Join-Path $root 'plugins/tngtech'
$pluginDst = Join-Path $dist 'plugins/tngtech'
New-Item -ItemType Directory -Path (Join-Path $pluginDst 'agents/opencode') -Force | Out-Null
Copy-Item (Join-Path $pluginSrc 'plugin.json'), (Join-Path $pluginSrc 'sidecar.py') -Destination $pluginDst
Copy-Item (Join-Path $pluginSrc 'agents/opencode/SKILL.md') -Destination (Join-Path $pluginDst 'agents/opencode')

Copy-Item (Join-Path $PSScriptRoot 'README.txt') -Destination $dist

Write-Host '== provenance + checksums'
$sha = 'unknown'; $branch = 'unknown'
if (Test-Path $repo) {
    $sha = (& git -C (Split-Path -Parent $root) rev-parse --short HEAD)
    $branch = (& git -C (Split-Path -Parent $root) rev-parse --abbrev-ref HEAD)
}
$version = @(
    "commit:      $sha"
    "branch:      $branch"
    "built:       $((Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm')) UTC"
    'target:      x86_64-pc-windows-msvc'
    'runtime:     static C runtime (no VC++ redistributable)'
    "sandbox.exe: $((Get-Item (Join-Path $dist 'sandbox.exe')).Length) bytes"
    "mxc-launch:  $((Get-Item (Join-Path $dist 'mxc-launch.exe')).Length) bytes"
) -join "`r`n"
Set-Content -Path (Join-Path $dist 'VERSION.txt') -Value $version

# LF, not CRLF: `sha256sum -c SHA256SUMS.txt` reads a trailing CR as part of the
# file name and fails on every line (measured: 11 failed opens). Windows users can
# still use Get-FileHash; the manifest has to be portable.
$sums = Get-ChildItem $dist -Recurse -File |
    Where-Object { $_.Name -ne 'SHA256SUMS.txt' } |
    Sort-Object FullName |
    ForEach-Object {
        $rel = $_.FullName.Substring($dist.Length + 1).Replace('\', '/')
        '{0}  {1}' -f (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower(), $rel
    }
[IO.File]::WriteAllText(
    (Join-Path $dist 'SHA256SUMS.txt'),
    (($sums -join "`n") + "`n"),
    (New-Object System.Text.UTF8Encoding($false)))

Write-Host '== zipping'
$zip = Join-Path $root "sandbox-$sha.zip"
$stage = Join-Path $env:TEMP "sandbox-$sha"
if (Test-Path $stage) { Remove-Item $stage -Recurse -Force }
Copy-Item $dist $stage -Recurse
if (Test-Path $zip) { Remove-Item $zip -Force }
Compress-Archive -Path $stage -DestinationPath $zip
Remove-Item $stage -Recurse -Force

$zipInfo = Get-Item $zip
Write-Host ''
Write-Host ("bundle: {0}  ({1:N0} files, {2:N0} KB)" -f $zip, (Get-ChildItem $dist -Recurse -File).Count, ($zipInfo.Length / 1KB))

if ($ReleaseVersion) {
    Write-Host "== release asset for Winget ($ReleaseVersion, flat)"
    $relStage = Join-Path $env:TEMP "saife-rel"
    if (Test-Path $relStage) { Remove-Item $relStage -Recurse -Force }
    New-Item -ItemType Directory -Path $relStage | Out-Null

    # The binary ships under its brand name; the launcher keeps its own name and is
    # found beside the supervisor.
    Copy-Item (Join-Path $bin 'sandbox.exe') -Destination (Join-Path $relStage 'saife.exe')
    Copy-Item (Join-Path $bin 'mxc-launch.exe') -Destination $relStage
    Copy-Item (Join-Path $dist 'profiles'), (Join-Path $dist 'plugins') -Destination $relStage -Recurse
    Copy-Item (Join-Path $dist 'README.txt') -Destination $relStage

    $relZip = Join-Path $root "saife-$ReleaseVersion-x64.zip"
    if (Test-Path $relZip) { Remove-Item $relZip -Force }
    Compress-Archive -Path (Join-Path $relStage '*') -DestinationPath $relZip
    Remove-Item $relStage -Recurse -Force

    $hash = (Get-FileHash $relZip -Algorithm SHA256).Hash
    Write-Host ("release: {0}  ({1:N0} KB)" -f $relZip, ((Get-Item $relZip).Length / 1KB))
    Write-Host ("sha256:  {0}" -f $hash)
    Write-Host 'Update InstallerSha256 in packaging/winget/*.installer.yaml with the value above.'
}
