#Requires -Version 7.0
# Install a locally built SAIFE release on this machine.
#
#   pwsh -File packaging\install-local.ps1                 # the archive matching Cargo.toml
#   pwsh -File packaging\install-local.ps1 -Zip .\saife-0.3.0-x64.zip
#   pwsh -File packaging\install-local.ps1 -Arch arm64      # the arm64 archive
#   pwsh -File packaging\install-local.ps1 -WhatIf
#   pwsh -File packaging\install-local.ps1 -AllowVersionMismatch   # deliberate, e.g. testing an old build
#
# What it does: verifies the archive, extracts it to
# %LOCALAPPDATA%\Programs\saife (or -Destination), and puts that directory on the
# USER PATH so `saife` resolves in new shells.
#
# Why not `winget install --manifest`: a Winget manifest's InstallerUrl must be
# http(s); Winget downloads the asset from the release URL. For a local build there
# is nothing to download, so this script is the local equivalent - and it is what
# the published package does to the same archive.
#
# The version rules are the point of the script:
#   - `Cargo.toml` declares the version; an archive whose NAME disagrees is refused,
#     so a stale zip cannot be installed by accident (the failure mode that looks
#     like success: "installed, and `saife --version` shows the old number").
#   - after extraction the binary is asked for its version and must agree with the
#     archive name, so a mislabelled build is caught even when the name matches.
#   - the winget manifest is compared only when it describes the same version: a
#     0.2.0 manifest cannot speak for a 0.3.0 archive.

param(
    [string]$Zip,
    # x64 | arm64; default: this host's architecture. Only an archive of this
    # architecture can be installed - the other one will not start here.
    [string]$Arch,
    [string]$Destination = (Join-Path $env:LOCALAPPDATA 'Programs\saife'),
    [switch]$WhatIf,
    [switch]$NoPathEntry,
    [switch]$AllowVersionMismatch,
    # Install an archive that predates the source tree (a rebuild is the fix).
    [switch]$AllowStaleArchive,
    # Install a local rebuild of a version that is already published: the winget
    # manifest still carries the PUBLISHED hash, so a mismatch is expected here and
    # only meaningful at publish time.
    [switch]$AllowUnpublishedBuild
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'lib\arch.ps1')
$root = Split-Path -Parent $PSScriptRoot

# Installing is always for THIS machine, so there is no 'all': the archive of the other
# architecture does not start here, and picking it silently would install a device of
# the wrong kind (Windows will refuse it with a bare "not a valid Win32 application").
$targetArch = Resolve-ArchParam -Arch $Arch
if ($targetArch -eq 'all') {
    throw ("-Arch all installs nothing: pick one architecture, e.g. -Arch {0}" -f (Resolve-HostArch))
}

$toml = Get-Content (Join-Path $root 'Cargo.toml') -Raw
if ($toml -notmatch '(?sm)\[package\].*?^\s*version\s*=\s*"([^"]+)"') {
    throw "cannot read the package version from $root\Cargo.toml"
}
$declared = $Matches[1]

function Get-ArchiveVersion([string]$Path) {
    $name = Split-Path -Leaf $Path
    if ($name -match '^saife-(?<v>[0-9A-Za-z][0-9A-Za-z.\-]*)-(?<arch>x64|arm64)\.zip$') { return $Matches['v'] }
    return $null
}

function Get-ArchiveArch([string]$Path) {
    $name = Split-Path -Leaf $Path
    if ($name -match '^saife-(?<v>[0-9A-Za-z][0-9A-Za-z.\-]*)-(?<arch>x64|arm64)\.zip$') { return $Matches['arch'] }
    return $null
}

$buildCommand = "pwsh -File packaging\build-dist.ps1 -Release -Arch $targetArch"
if (-not $Zip) {
    # Two homes, on purpose: `build-dist.ps1 -Release` leaves the asset at the repo
    # root, `release.ps1` archives it under dist/release/ before publishing.
    $candidates = @(
        (Join-Path $root "saife-$declared-$targetArch.zip"),
        (Join-Path $root "dist/release/saife-$declared-$targetArch.zip")
    )
    $matching = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $matching) {
        $any = Get-ChildItem $root, (Join-Path $root 'dist/release') -Filter "saife-*-$targetArch.zip" -File -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending | Select-Object -First 1
        $found = if ($any) { " (found $((Get-ArchiveVersion $any.FullName)) instead)" } else { '' }
        throw ("no saife-{0}-{1}.zip in {2}{3} - run: {4}" -f $declared, $targetArch, $root, $found, $buildCommand)
    }
    $Zip = $matching
}
if (-not (Test-Path $Zip)) { throw "archive not found: $Zip" }

$archiveArch = Get-ArchiveArch $Zip
if (-not $archiveArch) {
    throw ("cannot read an architecture from '{0}' - expected saife-<version>-x64.zip or saife-<version>-arm64.zip" -f $Zip)
}
if ($archiveArch -ne $targetArch) {
    throw ("{0} is the {1} archive but {2} was requested - the {1} binary does not run on an {2} host. Build the one you need: {3}  (or pass -Arch {1})" -f (Split-Path -Leaf $Zip), $archiveArch, $targetArch, $buildCommand)
}
$archiveVersion = Get-ArchiveVersion $Zip
if ($archiveVersion -ne $declared) {
    if ($AllowVersionMismatch) {
        Write-Warning ("archive is {0} but Cargo.toml declares {1} - installing anyway (-AllowVersionMismatch)" -f $archiveVersion, $declared)
    } else {
        throw ("archive is {0} but Cargo.toml declares {1}. Rebuild with: {2}  (or pass -AllowVersionMismatch to install the older build on purpose)" -f $archiveVersion, $declared, $buildCommand)
    }
}

# The version check above cannot tell two builds of the SAME version apart, which is
# the normal state between a merge and the next bump. Installing an archive built
# before the change then "succeeds" and the new feature is simply absent - measured
# exactly once, with a freshly merged prompt button missing from a 0.3.1 install.
$archiveTime = (Get-Item $Zip).LastWriteTime
$watched = @(
    (Join-Path $root 'src'),
    (Join-Path $root 'Cargo.toml'),
    (Join-Path $root 'Cargo.lock')
) | Where-Object { Test-Path $_ }
$newest = Get-ChildItem -Path $watched -Recurse -File -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending | Select-Object -First 1
# Two seconds of slack: a zip's timestamp has coarser granularity than a checkout's.
if ($newest -and $newest.LastWriteTime -gt $archiveTime.AddSeconds(2)) {
    $detail = "archive is {0:yyyy-MM-dd HH:mm}, {1} is {2:yyyy-MM-dd HH:mm}" -f $archiveTime, $newest.FullName.Substring($root.Length + 1), $newest.LastWriteTime
    if ($AllowStaleArchive) {
        Write-Warning ("stale archive: {0} - installing anyway (-AllowStaleArchive)" -f $detail)
    } else {
        throw ("stale archive: {0}. Same version, older build: the newest changes are NOT in it. Rebuild with: pwsh -File packaging\build-dist.ps1 -ReleaseVersion {1} -Arch $targetArch  (or pass -AllowStaleArchive to install it anyway)" -f $detail, $archiveVersion)
    }
}

$hash = (Get-FileHash $Zip -Algorithm SHA256).Hash
Write-Host ("version: {0}  ({1})" -f $archiveVersion, $archiveArch)
Write-Host ("built:   {0:yyyy-MM-dd HH:mm}" -f $archiveTime)
Write-Host ("archive: {0}" -f $Zip)
Write-Host ("sha256:  {0}" -f $hash)
Write-Host ("target:  {0}" -f $Destination)

# The manifest is the record of what SHOULD ship, but only for ITS version: compare
# when it describes the archive in hand, and say so plainly when it does not (that
# is the normal state between a version bump and the release).
$manifest = Join-Path $PSScriptRoot 'winget\GandalfIX.SAIFE-Sandbox.installer.yaml'
if (Test-Path $manifest) {
    $manifestVersion = (Select-String -Path $manifest -Pattern 'PackageVersion:\s*(\S+)' |
        Select-Object -First 1).Matches[0].Groups[1].Value
    # One Installer block per architecture: the hash to compare against is the one under
    # THIS archive's Architecture: line. Taking the first InstallerSha256 in the file
    # would compare an arm64 archive against the x64 hash and report a false mismatch.
    $expected = $null
    $manifestArch = $null
    foreach ($line in [IO.File]::ReadAllLines($manifest)) {
        $archLine = [regex]::Match($line, '^\s*-\s*Architecture:\s*(\S+)\s*$')
        if ($archLine.Success) { $manifestArch = $archLine.Groups[1].Value; continue }
        if ($manifestArch -ne $archiveArch) { continue }
        $hashLine = [regex]::Match($line, '^\s*InstallerSha256:\s*([0-9A-Fa-f]+)')
        if ($hashLine.Success) { $expected = $hashLine.Groups[1].Value; break }
    }

    if ($manifestVersion -ne $archiveVersion) {
        Write-Host ("manifest: describes {0}, archive is {1} - not comparable (regenerate it at release time)" -f $manifestVersion, $archiveVersion)
    } elseif (-not $expected) {
        Write-Warning ("manifest: has no InstallerSha256 for Architecture: {0} to compare" -f $archiveArch)
    } elseif ($expected.ToUpper() -eq $hash) {
        Write-Host 'manifest: PackageVersion and InstallerSha256 match'
    } elseif ($AllowUnpublishedBuild) {
        Write-Host ("manifest: describes the published {0} archive ({1}...), this one is a local rebuild ({2}...) - installing anyway (-AllowUnpublishedBuild)" -f $manifestVersion, $expected.Substring(0, 8), $hash.Substring(0, 8))
    } else {
        throw ("manifest: InstallerSha256 is {0} but the archive hashes to {1}. If this is a local rebuild of an already-published version that is expected - pass -AllowUnpublishedBuild. If you are about to publish it, the manifest is stale: re-run packaging\release.ps1." -f $expected, $hash)
    }
}

if ($WhatIf) { Write-Host 'WhatIf: nothing extracted, PATH untouched.'; return }

# Windows will not replace a running .exe, and the raw error is "Access to the path
# ... is denied" with no hint about why. Name the processes instead: a session the
# user forgot about is the normal cause, and it looks like a permissions problem.
if (Test-Path $Destination) {
    $running = @(
        Get-Process -ErrorAction SilentlyContinue | Where-Object {
            try { $_.Path -and $_.Path.StartsWith($Destination, [StringComparison]::OrdinalIgnoreCase) } catch { $false }
        }
    )
    if ($running.Count -gt 0) {
        $names = ($running | ForEach-Object { "{0} ({1})" -f $_.ProcessName, $_.Id }) -join ', '
        throw ("{0} is in use - still running from it: {1}. Close that session (or end the process) and run this again; Windows cannot replace a running executable." -f $Destination, $names)
    }
}

if (Test-Path $Destination) {
    $existing = Join-Path $Destination 'saife.exe'
    if (Test-Path $existing) {
        # No VERSIONINFO yet (R0.3), so FileVersion may be empty; fall back to asking.
        $old = (Get-Item $existing).VersionInfo.FileVersion
        if (-not $old) { $old = ((& $existing --version) -join ' ') -replace '.*\s', '' }
        Write-Host ("replacing existing install (version '{0}')" -f $old)
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

# The archive name is a claim; the binary is the evidence. A build labelled 0.3.0
# that reports 0.2.0 is a packaging bug, and finding it here costs one process.
$reported = ((& $exe --version) -join ' ').Trim()
if ($reported -notmatch [regex]::Escape($archiveVersion)) {
    throw ("the extracted binary reports '{0}', which is not {1} - the archive is mislabelled" -f $reported, $archiveVersion)
}
Write-Host ''
Write-Host '== installed, self-check:'
Write-Host ("{0}  (matches the archive name)" -f $reported)
# Capture first, then show four lines. Piping straight into `Select-Object -First 4` stops the
# pipeline early, which CLOSES the child's stdout while `saife setup` is still printing: the next
# write fails with ERROR_NO_DATA (232) and Rust panics in the stdio formatter ("failed printing to
# stdout: Die Pipe wird gerade geschlossen"), so a clean install looks like a crash. The command is
# fast and cheap, so let it finish and cut the text afterwards.
$selfCheck = & $exe setup --check-only 2>&1
$selfCheck | Select-Object -First 4

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
