#Requires -Version 7.0
# Assemble the shippable bundle: dist/ + versioned zips, one per architecture.
#
#   pwsh -File packaging/build-dist.ps1                    # this host's architecture
#   pwsh -File packaging/build-dist.ps1 -Arch arm64        # cross-build for ARM64
#   pwsh -File packaging/build-dist.ps1 -Arch all          # both archives, one SHA256SUMS.txt
#   pwsh -File packaging/build-dist.ps1 -SkipBuild         # assemble what is already built
#
# The executables are built with a STATIC C runtime so the target machine needs no
# VC++ redistributable; that build lives in target-static/<triple>/ so it never
# invalidates the normal debug/release artifacts used by the test lanes.
#
# --target is explicit even for the host architecture. Without it cargo writes to
# target-static/release/ and "which architecture is this binary" becomes a question
# about the machine that ran the build; with it the artifact path names the
# architecture, and a cross-build cannot be mistaken for a native one.

[CmdletBinding()]
param(
    [switch]$SkipBuild,
    # x64 | arm64 | all. Default: this host's architecture, from PROCESSOR_ARCHITECTURE.
    [string]$Arch,
    # Produce the release assets Winget consumes: saife-<version>-<arch>.zip, FLAT (no
    # wrapper directory) and with the binary named saife.exe, because
    # NestedInstallerFiles paths are relative to the archive root. The human bundle
    # (dist/ + saife-<sha>.zip) stays wrapped and is built either way.
    [switch]$Release,
    # Must-match override of the Cargo.toml version - a typo here publishes an asset
    # whose name disagrees with the binary inside it, so a mismatch is refused.
    [string]$ReleaseVersion
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'lib\arch.ps1')

$root = Split-Path -Parent $PSScriptRoot          # sandbox/
$dist = Join-Path $root 'dist'
$staticTarget = Join-Path $root 'target-static'
$repo = Join-Path $root '.git'
# SAIFE is its own repository since 2026-10-24 (it used to be <monorepo>/sandbox), so
# the probed commit is this directory's, not its parent's.

$hostArch = Resolve-HostArch
$requested = Resolve-ArchParam -Arch $Arch
# Fixed order, not host-first: the archive names and the sums file are diffed between
# runs, and an order that depended on the build machine would be noise. @() around the
# if: a single-element array is otherwise unrolled to a string, and $archs[0] would
# then be its first character.
$archs = @(if ($requested -eq 'all') { 'x64', 'arm64' } else { $requested })

# One number, one place: `Cargo.toml` owns the version and everything below derives
# from it. `-ReleaseVersion` is a must-match override, not a second source - a typo
# there would publish `saife-0.4.0-x64.zip` containing a 0.3.0 binary.
$toml = Get-Content (Join-Path $root 'Cargo.toml') -Raw
if ($toml -notmatch '(?sm)\[package\].*?^\s*version\s*=\s*"([^"]+)"') {
    throw "cannot read the package version from $root\Cargo.toml"
}
$version = $Matches[1]
if ($ReleaseVersion -and $ReleaseVersion -ne $version) {
    throw ("-ReleaseVersion {0} does not match Cargo.toml ({1}); bump Cargo.toml or drop the flag" -f $ReleaseVersion, $version)
}
# Windows resource version: the numeric core padded to four components (`0.3.0.0`).
$core = ($version -split '[-+]')[0]
$resVersion = (@($core -split '\.') + @('0', '0', '0', '0'))[0..3] -join '.'

Write-Host ("arch:  {0}   (this host is {1})" -f ($archs -join ', '), $hostArch)

$builds = [ordered]@{}
foreach ($arch in $archs) {
    $triple = Get-RustTarget -Arch $arch
    $bin = Join-Path $staticTarget (Join-Path $triple 'release')
    if (-not $SkipBuild) {
        Write-Host "== building static-CRT binaries for $arch ($triple)"
        $env:CARGO_TARGET_DIR = $staticTarget
        $env:RUSTFLAGS = '-C target-feature=+crt-static'
        Push-Location $root
        try {
            & cargo build --release --target $triple --bin saife --bin saife-launch
            if ($LASTEXITCODE -ne 0) { throw "cargo build failed for $arch ($triple), exit $LASTEXITCODE" }
        } finally {
            Pop-Location
            Remove-Item Env:CARGO_TARGET_DIR -ErrorAction SilentlyContinue
            Remove-Item Env:RUSTFLAGS -ErrorAction SilentlyContinue
        }
    }
    foreach ($exe in 'saife.exe', 'saife-launch.exe') {
        if (-not (Test-Path (Join-Path $bin $exe))) {
            throw "$exe not found in $bin - run without -SkipBuild once (rust target $triple)"
        }
    }
    $builds[$arch] = $bin
}

# Ask the binaries what they are, rather than trusting the manifest or the directory
# name: a stale target-static/ build passes every name-based check and ships the old
# number, and a cross-build that silently produced a host-architecture binary is
# exactly the failure a name-only check cannot see. The PE machine field answers both
# questions without starting the image, which is the point for a cross-build.
Write-Host '== verifying the built binaries'
foreach ($arch in $archs) {
    $bin = $builds[$arch]
    $expectedMachine = Get-ArchMachine -Arch $arch
    foreach ($exe in 'saife.exe', 'saife-launch.exe') {
        $path = Join-Path $bin $exe
        $machine = Get-PeMachine -Path $path
        if ($machine -ne $expectedMachine) {
            throw ("{0} is a 0x{1:X4} image but {2} was requested (expected 0x{3:X4}) - the build did not produce a {2} binary" -f $path, $machine, $arch, $expectedMachine)
        }
        $actual = (Get-Item $path).VersionInfo.FileVersion
        if ($actual -ne $resVersion) {
            throw ("{0} carries FileVersion '{1}', expected {2} - the VERSIONINFO step did not run (build.rs needs rc.exe from the Windows SDK)" -f $exe, $actual, $resVersion)
        }
    }
    # Only this host's architecture can be started here: x64 Windows cannot run an
    # ARM64 image (the reverse runs under emulation, which is why install.ps1 falls
    # back there - this check deliberately does not pretend to be symmetric).
    if ($arch -eq $hostArch) {
        $probe = (& (Join-Path $bin 'saife.exe') --version) -join ' '
        $expectedProbe = "SAIFE Sandbox $version"
        if ($probe -notlike "*$expectedProbe*") {
            throw ("{0} reports '{1}', Cargo.toml says {2} - rebuild (drop -SkipBuild)" -f (Join-Path $bin 'saife.exe'), $probe.Trim(), $expectedProbe)
        }
        Write-Host ("   {0}: PE machine 0x{1:X4}, FileVersion {2}, reports '{3}'" -f $arch, $expectedMachine, $resVersion, $probe.Trim())
    } else {
        Write-Host ("   {0}: PE machine 0x{1:X4}, FileVersion {2} - not executed (this host is {3})" -f $arch, $expectedMachine, $resVersion, $hostArch)
    }
}

# The human bundle is a developer artifact, not a release asset. Assemble it from an
# architecture this machine can probe whenever one was built.
$distArch = if ($archs -contains $hostArch) { $hostArch } else { $archs[0] }
$bin = $builds[$distArch]

Write-Host "== assembling dist/ (from the $distArch build)"
if (Test-Path $dist) { Remove-Item $dist -Recurse -Force }
New-Item -ItemType Directory -Path (Join-Path $dist 'profiles'), (Join-Path $dist 'plugins') | Out-Null

Copy-Item (Join-Path $bin 'saife.exe'), (Join-Path $bin 'saife-launch.exe') -Destination $dist
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
    "promptEnabled": false
  },
  "limits": {
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
    $sha = (& git -C $root rev-parse --short HEAD)
    $branch = (& git -C $root rev-parse --abbrev-ref HEAD)
}
$versionTxt = @(
    "version:     $version"
    "commit:      $sha"
    "branch:      $branch"
    "built:       $((Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm')) UTC"
    "target:      $(Get-RustTarget -Arch $distArch)"
    'runtime:     static C runtime (no VC++ redistributable)'
    "saife.exe:   $((Get-Item (Join-Path $dist 'saife.exe')).Length) bytes"
    "saife-launch: $((Get-Item (Join-Path $dist 'saife-launch.exe')).Length) bytes"
) -join "`r`n"
Set-Content -Path (Join-Path $dist 'VERSION.txt') -Value $versionTxt

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
$zip = Join-Path $root "saife-$sha.zip"
$stage = Join-Path $env:TEMP "saife-$sha"
if (Test-Path $stage) { Remove-Item $stage -Recurse -Force }
Copy-Item $dist $stage -Recurse
if (Test-Path $zip) { Remove-Item $zip -Force }
Compress-Archive -Path $stage -DestinationPath $zip
Remove-Item $stage -Recurse -Force

$zipInfo = Get-Item $zip
Write-Host ''
Write-Host ("bundle: {0}  ({1:N0} files, {2:N0} KB, {3})" -f $zip, (Get-ChildItem $dist -Recurse -File).Count, ($zipInfo.Length / 1KB), $distArch)

if ($Release -or $ReleaseVersion) {
    Write-Host "== release assets ($version, flat, one per architecture)"
    $produced = @()
    foreach ($arch in $archs) {
        $archBin = $builds[$arch]
        $relStage = Join-Path $env:TEMP "saife-rel-$arch"
        if (Test-Path $relStage) { Remove-Item $relStage -Recurse -Force }
        New-Item -ItemType Directory -Path $relStage | Out-Null

        # Both ship under their brand names; the launcher is found beside the supervisor.
        Copy-Item (Join-Path $archBin 'saife.exe') -Destination $relStage
        Copy-Item (Join-Path $archBin 'saife-launch.exe') -Destination $relStage
        Copy-Item (Join-Path $dist 'profiles'), (Join-Path $dist 'plugins') -Destination $relStage -Recurse
        Copy-Item (Join-Path $dist 'README.txt') -Destination $relStage

        $relZip = Join-Path $root (Get-AssetName -Version $version -Arch $arch)
        if (Test-Path $relZip) { Remove-Item $relZip -Force }
        Compress-Archive -Path (Join-Path $relStage '*') -DestinationPath $relZip
        Remove-Item $relStage -Recurse -Force

        $produced += [pscustomobject]@{
            Arch = $arch
            Name = (Split-Path -Leaf $relZip)
            Path = $relZip
            Hash = (Get-FileHash $relZip -Algorithm SHA256).Hash
        }
        Write-Host ("release: {0}  ({1:N0} KB)" -f $relZip, ((Get-Item $relZip).Length / 1KB))
    }

    # packaging/release.ps1 uploads every saife-<version>-<arch>.zip it finds and then
    # writes the sums file for exactly the hashes it saw, so an archive left over from
    # an earlier run (another toolchain, another commit) would be uploaded alongside a
    # checksum that describes nothing. Remove it rather than ship unknown bytes.
    $producedNames = @($produced | ForEach-Object { $_.Name })
    foreach ($leftover in Get-ChildItem -Path $root -Filter "saife-$version-*.zip" -File) {
        if ($producedNames -notcontains $leftover.Name) {
            Remove-Item $leftover.FullName -Force
            Write-Host ("removed stale {0} (not built in this run)" -f $leftover.Name)
        }
    }

    $sumsPath = Join-Path $root 'SHA256SUMS.txt'
    $sumLines = $produced | ForEach-Object { '{0}  {1}' -f $_.Hash.ToLower(), $_.Name }
    [IO.File]::WriteAllText(
        $sumsPath,
        (($sumLines -join "`n") + "`n"),
        (New-Object System.Text.UTF8Encoding($false)))

    Write-Host ''
    foreach ($entry in $produced) {
        Write-Host ("sha256:  {0}  {1}" -f $entry.Hash.ToLower(), $entry.Name)
    }
    Write-Host ("sums:    {0}  ({1} archive(s))" -f $sumsPath, $produced.Count)
    Write-Host 'packaging/release.ps1 rewrites the manifests from these hashes; do not edit them by hand.'
}
