# Cut the release that Cargo.toml declares - in two steps, neither of which pushes to
# main.
#
#   pwsh -File packaging/release.ps1 -DryRun      # build, probe, validate; change nothing
#   pwsh -File packaging/release.ps1              # build, rewrite manifests, open a PR
#   pwsh -File packaging/release.ps1 -Publish     # after the merge: tag, publish, verify
#   pwsh -File packaging/release.ps1 -VerifyOnly  # re-check an already published release
#
# Rules, and why each exists:
#   * `Cargo.toml` -> `[package] version` is the only source of the number. The git
#     tag must equal `v<version>`, the asset name derives from it, and the manifests
#     are rewritten from it. Nothing here takes a version argument: a flag would be a
#     second source, and the mismatch it allows is what publishes the wrong bytes.
#   * `main` is never pushed to (AGENTS.md). The manifest rewrite travels in a pull
#     request, and the tag is applied to the merged commit - which is also why -Publish
#     checks that origin/main already describes this exact asset.
#   * The asset is built once, in the prepare step, and reused by -Publish. A rebuild
#     is not byte-identical (zips embed timestamps), so it would no longer match the
#     hash the manifests and the release commit carry.
#   * The asset is probed before it is published: extracted into a temp directory,
#     `saife.exe --version` must report the declared version, and the archive must be
#     FLAT because winget's NestedInstallerFiles are relative to the archive root.
#   * After publishing, the release URL is downloaded again and hashed. "gh said ok"
#     is not evidence that the bytes a user gets are the bytes that were built.
#   * The two architectures are two assets: saife-<v>-x64.zip and saife-<v>-arm64.zip.
#     The archive NAME is all that tells them apart - both contain saife.exe, because
#     winget's NestedInstallerFiles are relative to the archive root - so every archive
#     present in dist/release is uploaded and every one has its own Installer entry.
#     An architecture with no archive is a refusal, never a manifest that points at a
#     404.
#
# Exit codes: 0 success, 1 a gate refused or a step failed.

param(
    [switch]$DryRun,
    [switch]$SkipTests,
    [switch]$Prepare,
    [switch]$Publish,
    # Publish without waiting for the `ci` workflow on the release commit.
    [switch]$SkipCiCheck,
    # Re-download and verify the published release instead of building anything.
    [switch]$VerifyOnly,
    # Release notes: default is the CHANGELOG section for this version.
    [string]$NotesFile,
    # x64 | arm64 | all: which archives to build and publish. Default 'all' - a release
    # that silently drops an architecture is a surprise to the people running on it.
    # -Arch x64 still works, but the manifest then has to lose its arm64 entry, and the
    # script says so instead of publishing a URL that 404s.
    [string]$Arch = 'all',
    [string]$Repository = 'GandalfIX/saife'
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$wingetDir = Join-Path $root 'packaging/winget'
. (Join-Path $PSScriptRoot 'lib\arch.ps1')

function Step([string]$message) {
    Write-Host ''
    Write-Host "== $message" -ForegroundColor Cyan
}

function Refuse([string]$message) {
    throw "release refused: $message"
}

# Everything the release uploads must be on disk BEFORE the tag moves. `gh release
# create` is the next step after tagging, so a missing side file there leaves a
# PUSHED TAG WITH NO RELEASE behind it - and a published tag is immutable, so that
# failure is permanent rather than retryable. (It happened once: publishing from a
# clean clone that carried the asset and the notes but not SHA256SUMS.txt.)
function Assert-ReleaseSideFiles([string]$dir, [string]$name, [string]$hash) {
    $sumsPath = Join-Path $dir 'SHA256SUMS.txt'
    if (-not (Test-Path $sumsPath)) {
        Refuse "no SHA256SUMS.txt in $dir - the release uploads it beside the asset, and a tag pushed without it cannot be withdrawn"
    }
    $entries = @{}
    foreach ($line in (Get-Content $sumsPath)) {
        if ($line -notmatch '^\s*([0-9a-fA-F]{64})\s+\*?(\S.*?)\s*$') { continue }
        $entries[$Matches[2]] = $Matches[1].ToLowerInvariant()
    }
    if (-not $entries.ContainsKey($name)) {
        Refuse "SHA256SUMS.txt does not list $name (it lists: $(($entries.Keys | Sort-Object) -join ', '))"
    }
    if ($entries[$name] -ne $hash.ToLowerInvariant()) {
        Refuse "SHA256SUMS.txt records $($entries[$name]) for $name, the asset hashes to $hash - repackaging changes the hash, so rewrite the sums rather than the expectation"
    }
}

# Rewrite one Installer entry per architecture. The single-arch version replaced the
# first InstallerUrl/InstallerSha256 in the file; with two entries that writes the same
# URL and hash into both, so the arch each block belongs to is tracked while the file
# is walked. CRLF is rebuilt explicitly (the manifests are CRLF and .gitattributes pins
# it). Every architecture that has an archive must have an entry, and every entry must
# have an archive: either mismatch publishes a URL that 404s or a hash for bytes that
# were never built.
function Update-WingetInstaller([string]$text, [hashtable]$installers, [string]$fileName) {
    $lines = [regex]::Split($text, "`r`n|`n")
    $current = $null
    $seen = @{}
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $line = $lines[$i]
        $m = [regex]::Match($line, '^\s*-\s*Architecture:\s*(\S+)\s*$')
        if ($m.Success) { $current = $m.Groups[1].Value; continue }
        if (-not $current) { continue }
        if ($line -match '^(\s*)InstallerUrl:') {
            if (-not $installers.ContainsKey($current)) {
                Refuse "$fileName declares Architecture: $current, but no saife-$version-$current.zip was built - build it (-Arch all), or delete that installer entry"
            }
            $seen[$current] = $true
            $lines[$i] = $Matches[1] + 'InstallerUrl: ' + $installers[$current].Url
        } elseif ($line -match '^(\s*)InstallerSha256:') {
            if (-not $installers.ContainsKey($current)) { continue }
            $seen[$current] = $true
            $lines[$i] = $Matches[1] + 'InstallerSha256: ' + $installers[$current].Sha256
        }
    }
    foreach ($arch in @($installers.Keys)) {
        if (-not $seen.ContainsKey($arch)) {
            Refuse "$fileName has no 'Architecture: $arch' installer entry, but saife-$version-$arch.zip was built - add one, or that archive is not installable through winget"
        }
    }
    return ($lines -join "`r`n")
}

if ($Prepare -and $Publish) { Refuse 'pass -Prepare or -Publish, not both' }
if ($VerifyOnly -and $Publish) { Refuse 'pass -VerifyOnly or -Publish, not both' }
$mode = if ($Publish) { 'publish' } elseif ($VerifyOnly) { 'verify' } else { 'prepare' }

# ---------------------------------------------------------------- the one number

$toml = Get-Content (Join-Path $root 'Cargo.toml') -Raw
if ($toml -notmatch '(?sm)\[package\].*?^\s*version\s*=\s*"([^"]+)"') {
    Refuse "cannot read [package] version from $root\Cargo.toml"
}
$version = $Matches[1]
$tag = "v$version"
$releaseBranch = "chore/release-$tag"
$releaseDir = Join-Path $root 'dist/release'
$hostArch = Resolve-HostArch
# Fixed order: the sums file and the manifest are compared between runs.
$archNames = @('x64', 'arm64')

function Get-AssetUrl([string]$name) {
    return "https://github.com/$Repository/releases/download/$tag/$name"
}

# Every architecture that has an archive on disk, with the facts the manifests and the
# upload need. Discovery rather than a name the caller supplies: a release publishes
# what was built, and refuses loudly when that is nothing.
function Get-ReleaseAssets {
    $found = @()
    foreach ($arch in $archNames) {
        $name = Get-AssetName -Version $version -Arch $arch
        $path = Join-Path $releaseDir $name
        if (-not (Test-Path $path)) { continue }
        $found += [pscustomobject]@{
            Arch   = $arch
            Name   = $name
            Path   = $path
            Url    = (Get-AssetUrl $name)
            Sha256 = (Get-FileHash $path -Algorithm SHA256).Hash
        }
    }
    if ($found.Count -eq 0) {
        Refuse "no saife-$version-<arch>.zip in $releaseDir - build one with: pwsh -File packaging/build-dist.ps1 -Release -Arch $Arch"
    }
    return $found
}

Write-Host "mode: $mode   version: $version   tag: $tag   host: $hostArch"
if ($version -match '-') {
    Write-Host 'note: this version carries a pre-release suffix; GitHub will not mark it "latest" unless published as such.' -ForegroundColor Yellow
}

$gh = (Get-Command gh -ErrorAction SilentlyContinue).Source
if (-not $gh) {
    $candidate = Join-Path $env:ProgramFiles 'GitHub CLI/gh.exe'
    if (Test-Path $candidate) { $gh = $candidate }
}
if (-not $gh) { Refuse 'the GitHub CLI (gh) is not on PATH; install it or finish by hand' }

function Invoke-Git {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$arguments)
    $output = & git -C $root @arguments
    if ($LASTEXITCODE -ne 0) { Refuse "git $($arguments -join ' ') failed" }
    return $output
}

function Save-ReleaseNotes([string]$text) {
    if (-not (Test-Path $releaseDir)) { New-Item -ItemType Directory -Path $releaseDir -Force | Out-Null }
    $path = Join-Path $releaseDir 'RELEASE_NOTES.md'
    [IO.File]::WriteAllText($path, $text + "`n", (New-Object System.Text.UTF8Encoding($false)))
    return $path
}

# Extract the asset, insist on the flat layout, and ask the binary what it is. The
# binary is only STARTED when the archive matches this host's architecture: an arm64
# archive cross-built on an x64 host cannot be executed here, so its PE machine field
# is what proves the bytes are ARM64 - the one check that works cross-architecture and
# the one that catches a "cross-build" that quietly produced a host binary.
function Test-Asset([string]$zipPath, [string]$arch) {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = [IO.Compression.ZipFile]::OpenRead($zipPath)
    try { $entries = $zip.Entries.FullName } finally { $zip.Dispose() }
    $leaf = [IO.Path]::GetFileName($zipPath)
    # THIRD-PARTY-LICENSES.md and the SBOMs are required, not decorative: shipping
    # the binaries without them violates the dependency licenses and misses the
    # EU Cyber Resilience Act. The SBOM names carry the version, so a stale
    # archive from an older release fails here too.
    $required = @(
        'saife.exe',
        'saife-launch.exe',
        'README.txt',
        'THIRD-PARTY-LICENSES.md',
        "saife-$version-sbom-x64.cdx.json",
        "saife-$version-sbom-arm64.cdx.json"
    )
    foreach ($name in $required) {
        if ($entries -notcontains $name) {
            Refuse "$leaf is not flat: '$name' is not at the archive root (entries: $($entries -join ', '))"
        }
    }
    $probeDir = Join-Path ([IO.Path]::GetTempPath()) ("saife-probe-" + [guid]::NewGuid().ToString('N'))
    try {
        Expand-Archive -Path $zipPath -DestinationPath $probeDir
        $machine = Get-PeMachine -Path (Join-Path $probeDir 'saife.exe')
        $expected = Get-ArchMachine -Arch $arch
        if ($machine -ne $expected) {
            Refuse ("{0} carries a 0x{1:X4} image but its name says {2} (expected 0x{3:X4})" -f $leaf, $machine, $arch, $expected)
        }
        if ($arch -eq $hostArch) {
            $probe = (& (Join-Path $probeDir 'saife.exe') --version) -join ' '
            if ($probe -notlike "*SAIFE Sandbox $version*") {
                Refuse "$leaf contains a binary that reports '$($probe.Trim())'"
            }
            Write-Host ("probe: {0}  (PE machine 0x{1:X4}, {2})" -f $probe.Trim(), $machine, $arch)
        } else {
            Write-Host ("probe: PE machine 0x{0:X4} ({1}) - not executed, this host is {2}" -f $machine, $arch, $hostArch)
        }
    } finally {
        Remove-Item $probeDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Get-PublishedHash([string]$url) {
    $head = Invoke-WebRequest -Uri $url -Method Head -MaximumRedirection 5 -SkipHttpErrorCheck
    if ($head.StatusCode -ne 200) { return $null }
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ("saife-verify-" + [guid]::NewGuid().ToString('N') + '.zip')
    try {
        Invoke-WebRequest -Uri $url -OutFile $tmp | Out-Null
        return [pscustomobject]@{ Hash = (Get-FileHash $tmp -Algorithm SHA256).Hash; Size = (Get-Item $tmp).Length }
    } finally {
        Remove-Item $tmp -ErrorAction SilentlyContinue
    }
}

# ---------------------------------------------------------------- shared preconditions

$branch = ((Invoke-Git 'rev-parse' '--abbrev-ref' 'HEAD') -join '').Trim()
if ($branch -ne 'main') { Refuse "on branch '$branch'; a release is cut from main" }

$dirty = Invoke-Git 'status' '--porcelain'
if ($dirty) {
    Write-Host $dirty
    Refuse 'the working tree is not clean; commit or stash first (the tag would not describe the bytes)'
}

Invoke-Git 'fetch' '--quiet' 'origin' 'main' | Out-Null
$ahead = [int](Invoke-Git 'rev-list' '--count' 'origin/main..HEAD')
$behind = [int](Invoke-Git 'rev-list' '--count' 'HEAD..origin/main')
if ($ahead -ne 0 -or $behind -ne 0) { Refuse "HEAD is $ahead ahead / $behind behind origin/main; land the change through a pull request, then pull" }

$existing = Invoke-Git 'tag' '-l' $tag
if ($existing -and $mode -ne 'verify') { Refuse "tag $tag already exists; a published version is never re-cut (bump Cargo.toml)" }

# The changelog is the release notes, so its section must exist before anything is built.
$changelog = Join-Path $root 'CHANGELOG.md'
if (-not (Test-Path $changelog)) { Refuse 'CHANGELOG.md is missing' }
$text = [IO.File]::ReadAllText($changelog)
$pattern = "(?ms)^## \[$([regex]::Escape($version))\].*?(?=^## \[|\z)"
if ($text -notmatch $pattern) { Refuse "CHANGELOG.md has no '## [$version]' section" }
$section = ($Matches[0].TrimEnd() -replace '(?m)^## \[[^\]]+\][^\r\n]*\r?\n?', '').Trim()
if (-not $section) { Refuse "the CHANGELOG section for $version is empty" }
if ($NotesFile -and -not (Test-Path $NotesFile)) { Refuse "notes file $NotesFile does not exist" }
Write-Host '--- release notes ---'
if ($NotesFile) { Write-Host (Get-Content $NotesFile -Raw) } else { Write-Host $section }
Write-Host '---------------------'

# ---------------------------------------------------------------- verify only

if ($mode -eq 'verify') {
    Step "verifying the published release $tag"
    $checked = 0
    foreach ($arch in $archNames) {
        $name = Get-AssetName -Version $version -Arch $arch
        $url = Get-AssetUrl $name
        $local = Join-Path $releaseDir $name
        $published = Get-PublishedHash $url
        if (-not $published) {
            Write-Host "not published: $name"
            continue
        }
        $checked++
        if (Test-Path $local) {
            $localHash = (Get-FileHash $local -Algorithm SHA256).Hash
            if ($localHash -ne $published.Hash) {
                Refuse "published hash $($published.Hash) for $name differs from the local build $localHash"
            }
            Write-Host "hash matches the local build: $name $localHash"
        } else {
            Write-Host "published hash: $name $($published.Hash)  ($([math]::Round($published.Size / 1KB)) KB)"
        }
    }
    if ($checked -eq 0) { Refuse "no saife-$version-<arch>.zip is published for $tag" }
    exit 0
}

# ---------------------------------------------------------------- prepare

if ($mode -eq 'prepare') {
    if (-not $SkipTests) {
        Step 'tests and lints (the same gate CI runs on the pull request)'
        & cargo test --bin saife
        if ($LASTEXITCODE -ne 0) { Refuse 'cargo test failed' }
        & cargo clippy --all-targets -- -D warnings
        if ($LASTEXITCODE -ne 0) { Refuse 'clippy is not clean' }
    }

    Step 'build and package (static CRT, flat release asset per architecture)'
    & (Join-Path $PSScriptRoot 'build-dist.ps1') -Release -Arch $Arch
    if (-not (Test-Path $releaseDir)) { New-Item -ItemType Directory -Path $releaseDir -Force | Out-Null }
    foreach ($arch in $archNames) {
        $built = Join-Path $root (Get-AssetName -Version $version -Arch $arch)
        if (-not (Test-Path $built)) { continue }
        Move-Item $built (Join-Path $releaseDir (Split-Path -Leaf $built)) -Force
    }
    $assets = Get-ReleaseAssets

    Step 'probe every asset (flat layout, reports the declared version)'
    foreach ($asset in $assets) { Test-Asset $asset.Path $asset.Arch }

    foreach ($asset in $assets) {
        Write-Host ("asset:  {0}  ({1:N0} KB)" -f $asset.Path, ((Get-Item $asset.Path).Length / 1KB))
        Write-Host ("sha256: {0}" -f $asset.Sha256)
    }

    # LF, because sha256sum -c reads a trailing CR as part of the file name.
    $sumLines = $assets | ForEach-Object { '{0}  {1}' -f $_.Sha256.ToLower(), $_.Name }
    [IO.File]::WriteAllText(
        (Join-Path $releaseDir 'SHA256SUMS.txt'),
        (($sumLines -join "`n") + "`n"),
        (New-Object System.Text.UTF8Encoding($false)))

    # The notes file is written after packaging: build-dist.ps1 recreates dist/ wholesale.
    if (-not $NotesFile) {
        $NotesFile = Save-ReleaseNotes $section
        Write-Host "release notes: $NotesFile"
    }

    Step 'winget manifests'
    # In a dry run the rewrite happens on a copy: a dry run that leaves tracked files
    # modified is a dry run someone has to clean up by hand.
    $manifestTarget = if ($DryRun) { Join-Path ([IO.Path]::GetTempPath()) 'saife-winget-dryrun' } else { $wingetDir }
    if ($DryRun) {
        if (Test-Path $manifestTarget) { Remove-Item $manifestTarget -Recurse -Force }
        Copy-Item $wingetDir $manifestTarget -Recurse
    }
    # One Installer block per architecture; `installers` is what each one is rewritten to.
    $installers = @{}
    foreach ($asset in $assets) {
        $installers[$asset.Arch] = @{ Url = $asset.Url; Sha256 = $asset.Sha256 }
    }
    foreach ($file in Get-ChildItem $manifestTarget -Filter '*.yaml') {
        $raw = [IO.File]::ReadAllText($file.FullName)
        $before = $raw
        # `[^\r\n]*` rather than `.*$`: .NET's `.` matches CR, so `.*$` swallows the
        # carriage return and leaves one LF line among CRLFs.
        $raw = [regex]::Replace($raw, '(?m)^PackageVersion:[^\r\n]*', "PackageVersion: $version")
        if ($file.Name -match '\.installer\.ya?ml$') {
            $raw = Update-WingetInstaller $raw $installers $file.Name
        }
        if ($raw -ne $before) {
            Write-Host ("rewrote {0} -> {1}" -f $file.Name, $version)
            if (-not $DryRun) {
                [IO.File]::WriteAllText($file.FullName, $raw, (New-Object System.Text.UTF8Encoding($false)))
            }
        }
        if ($raw -match 'mxc-launch\.exe') {
            Refuse "$($file.Name) names 'mxc-launch.exe'; the launcher is saife-launch.exe"
        }
    }

    $winget = (Get-Command winget -ErrorAction SilentlyContinue).Source
    if (-not $winget) { Refuse 'winget is not on PATH, so the manifests cannot be validated' }
    & $winget validate --manifest $manifestTarget
    if ($LASTEXITCODE -ne 0) { Refuse "winget validate rejected $manifestTarget" }
    if ($DryRun) { Remove-Item $manifestTarget -Recurse -Force }

    if ($DryRun) {
        Step 'dry run: stopping before the branch and the pull request'
        foreach ($asset in $assets) { Write-Host ("would publish: {0}  ({1})" -f $asset.Name, $asset.Sha256) }
        Write-Host "would commit:  packaging/winget (PackageVersion $version, one InstallerUrl + InstallerSha256 per architecture)"
        Write-Host "would push:    branch $releaseBranch (never main)"
        Write-Host "would open:    a pull request $releaseBranch -> main"
        Write-Host 'then:          merge it, and run  pwsh -File packaging/release.ps1 -Publish'
        exit 0
    }

    Step "commit the manifests on $releaseBranch and open a pull request"
    # Never on main: main only moves through reviewed merges, and the tag is applied to
    # the merged commit afterwards.
    $localBranch = Invoke-Git 'branch' '--list' $releaseBranch
    if ($localBranch) { Refuse "branch $releaseBranch already exists locally; delete it first" }
    Invoke-Git 'switch' '--create' $releaseBranch | Out-Null
    Invoke-Git 'add' 'packaging/winget' | Out-Null
    $staged = Invoke-Git 'status' '--porcelain'
    if ($staged) {
        Invoke-Git 'commit' '--quiet' '--message' "chore(release): $tag manifests" | Out-Null
    } else {
        Write-Host 'the manifests already carried this version; nothing to commit'
    }
    Invoke-Git 'push' '--quiet' '--set-upstream' 'origin' $releaseBranch | Out-Null

    $assetLines = ($assets | ForEach-Object { "- {0} -> {1} ({2})" -f $_.Name, $_.Url, $_.Sha256 }) -join "`n"
    $body = @'
Rewrites the winget manifests for {0} from the assets built by packaging/release.ps1.

- PackageVersion -> {1}
{2}

winget validate passes on this set. Merge it, then on main:

    pwsh -File packaging/release.ps1 -Publish

which tags the merge commit, publishes the release and re-verifies the published
archives. Do not rebuild between the merge and -Publish: the assets are published from
the machine that built them, because a zip is not byte-reproducible.
'@ -f $tag, $version, $assetLines

    $prUrl = & $gh pr create --repo $Repository --base main --head $releaseBranch --title "chore(release): $tag manifests" --body $body
    if ($LASTEXITCODE -ne 0) { Refuse 'gh pr create failed' }

    Step 'prepared - nothing published, main untouched'
    Write-Host "pull request: $prUrl"
    foreach ($asset in $assets) { Write-Host ("asset kept:   {0}  ({1})" -f $asset.Path, $asset.Sha256) }
    Write-Host ''
    Write-Host 'Next: merge the pull request, then'
    Write-Host '   git switch main; git pull; pwsh -File packaging/release.ps1 -Publish'
    exit 0
}

# ---------------------------------------------------------------- publish

Step 'publish preconditions'
# origin/main must already describe these exact bytes: the merge is what turns a local
# build into published bytes, and the tag must describe the merge, not the branch.
$assets = Get-ReleaseAssets
$mainInstaller = (Invoke-Git 'show' "origin/main:packaging/winget/GandalfIX.SAIFE-Sandbox.installer.yaml" | Out-String)
if ($mainInstaller -notmatch "(?m)^PackageVersion:\s*$([regex]::Escape($version))\s*$") {
    Refuse "origin/main's manifests are not at $version yet; merge the release pull request first"
}
foreach ($asset in $assets) {
    if ($mainInstaller -notmatch "(?m)^\s*InstallerSha256:\s*$([regex]::Escape($asset.Sha256))\s*$") {
        Refuse "origin/main's InstallerSha256 does not match $($asset.Name) ($($asset.Sha256)); publish from the machine that built it (a rebuild changes the hash)"
    }
    # Uploaded after the tag: prove every one of them exists first, per asset.
    Assert-ReleaseSideFiles $releaseDir $asset.Name $asset.Sha256
}
Write-Host ("origin/main describes {0}" -f (($assets | ForEach-Object { $_.Name }) -join ', '))

if ($NotesFile) {
    if (-not (Test-Path $NotesFile)) { Refuse "notes file $NotesFile does not exist" }
} else {
    # Written before the tag rather than after it: generating release notes is the
    # step most likely to fail (a missing CHANGELOG section), and failing here costs
    # nothing.
    $NotesFile = Save-ReleaseNotes $section
}
Write-Host ("release files present: {0}, SHA256SUMS.txt, {1}" -f (($assets | ForEach-Object { $_.Name }) -join ', '), (Split-Path -Leaf $NotesFile))

Step 'probe every asset before tagging'
foreach ($asset in $assets) { Test-Asset $asset.Path $asset.Arch }

if (-not $SkipCiCheck) {
    Step 'CI on the release commit'
    $sha = ((Invoke-Git 'rev-parse' 'HEAD') -join '').Trim()
    $runs = & $gh run list --repo $Repository --commit $sha --workflow ci.yml --limit 5 --json status,conclusion
    if ($LASTEXITCODE -ne 0) { Refuse 'gh run list failed; check CI by hand or pass -SkipCiCheck' }
    $parsed = @($runs | ConvertFrom-Json)
    if (-not $parsed) { Refuse "no ci run for $sha yet; wait for it, or pass -SkipCiCheck" }
    $unfinished = @($parsed | Where-Object { $_.status -ne 'completed' })
    if ($unfinished.Count -gt 0) { Refuse "ci for $sha is still $($unfinished[0].status); wait for it, or pass -SkipCiCheck" }
    $green = @($parsed | Where-Object { $_.conclusion -eq 'success' })
    if ($green.Count -eq 0) { Refuse "ci for $sha concluded '$($parsed[0].conclusion)'; fix it, or pass -SkipCiCheck" }
    Write-Host "ci green for $sha"
}

Step 'tag and push the tag'
Invoke-Git 'tag' '--annotate' $tag '--message' "SAIFE Sandbox $version" | Out-Null
Invoke-Git 'push' '--quiet' 'origin' $tag | Out-Null

Step "publish the GitHub release $tag"
$assetPaths = @($assets | ForEach-Object { $_.Path })
& $gh release create $tag --repo $Repository --title "SAIFE Sandbox $version" --verify-tag --notes-file $NotesFile @assetPaths (Join-Path $releaseDir 'SHA256SUMS.txt')
if ($LASTEXITCODE -ne 0) { Refuse 'gh release create failed' }

Step 'verify what a user would download'
foreach ($asset in $assets) {
    $published = Get-PublishedHash $asset.Url
    if (-not $published) { Refuse "$($asset.Url) did not answer 200 after publishing" }
    if ($published.Hash -ne $asset.Sha256) {
        Refuse "the published $($asset.Name) hashes to $($published.Hash), the built one to $($asset.Sha256)"
    }
    Write-Host ("published asset verified: {0} {1}" -f $asset.Name, $asset.Sha256)
}

Step 'tidy up'
# The manifest branch is normally deleted by the merge that lands it, so the remote ref is often
# already gone by the time publishing finishes. That is the expected state, not a failure: the
# release is published at this point, and reporting "refused" after a successful publish makes the
# operator re-read a run that worked (it did, on 0.4.0).
$remoteHeads = (& git -C $root ls-remote --heads origin $releaseBranch) 2>$null
if ($remoteHeads) {
    Invoke-Git 'push' '--quiet' 'origin' '--delete' $releaseBranch
    Write-Host "deleted branch $releaseBranch"
} else {
    Write-Host "branch $releaseBranch already gone (the merge deleted it)"
}
$localExists = (& git -C $root branch --list $releaseBranch)
if ($localExists) { & git -C $root branch -D $releaseBranch | Out-Null }

Write-Host ''
Write-Host "release: https://github.com/$Repository/releases/tag/$tag"
