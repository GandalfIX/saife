# Publish the release that Cargo.toml declares: build, package, rewrite the winget
# manifests, tag, publish, re-verify from the published URL.
#
#   pwsh -File packaging/release.ps1 -DryRun     # everything except commit/tag/publish
#   pwsh -File packaging/release.ps1             # the real thing
#   pwsh -File packaging/release.ps1 -VerifyOnly # re-check an already published release
#
# Rules, and why each exists:
#   * `Cargo.toml` -> `[package] version` is the only source of the number. The git
#     tag must equal `v<version>`, the asset name derives from it, and the manifests
#     are rewritten from it. Nothing here takes a version argument: a flag would be a
#     second source, and the mismatch it allows is what publishes the wrong bytes.
#   * The tree must be clean and level with origin/main, because the tag is applied to
#     the commit that is published.
#   * The asset is probed before it is published: extracted into a temp directory,
#     `saife.exe --version` must report the declared version, and the archive must be
#     FLAT because winget's NestedInstallerFiles are relative to the archive root.
#   * After publishing, the release URL is downloaded again and hashed. "gh said ok"
#     is not evidence that the bytes a user gets are the bytes that were built.
#
# Exit codes: 0 published (or dry run succeeded), 1 a gate refused or a step failed.

param(
    [switch]$DryRun,
    [switch]$SkipTests,
    # Re-download and verify the published release instead of building anything.
    [switch]$VerifyOnly,
    # Release notes: default is the CHANGELOG section for this version.
    [string]$NotesFile,
    [string]$Repository = 'GandalfIX/saife'
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$wingetDir = Join-Path $root 'packaging/winget'

function Step([string]$message) {
    Write-Host ''
    Write-Host "== $message" -ForegroundColor Cyan
}

function Refuse([string]$message) {
    throw "release refused: $message"
}

# ---------------------------------------------------------------- the one number

$toml = Get-Content (Join-Path $root 'Cargo.toml') -Raw
if ($toml -notmatch '(?sm)\[package\].*?^\s*version\s*=\s*"([^"]+)"') {
    Refuse "cannot read [package] version from $root\Cargo.toml"
}
$version = $Matches[1]
$tag = "v$version"
$assetName = "saife-$version-x64.zip"
$assetUrl = "https://github.com/$Repository/releases/download/$tag/$assetName"
$releaseDir = Join-Path $root 'dist/release'
$assetPath = Join-Path $releaseDir $assetName

Write-Host "version: $version   tag: $tag   asset: $assetName"
if ($version -match '-') {
    Write-Host 'note: this version carries a pre-release suffix; GitHub will not mark it "latest" unless published as such.' -ForegroundColor Yellow
}

$gh = (Get-Command gh -ErrorAction SilentlyContinue).Source
if (-not $gh) {
    $candidate = Join-Path $env:ProgramFiles 'GitHub CLI/gh.exe'
    if (Test-Path $candidate) { $gh = $candidate }
}
if (-not $gh) { Refuse 'the GitHub CLI (gh) is not on PATH; install it or publish by hand' }

# ---------------------------------------------------------------- published check

function Get-PublishedHash([string]$url) {
    $response = Invoke-WebRequest -Uri $url -Method Head -MaximumRedirection 5 -SkipHttpErrorCheck
    if ($response.StatusCode -ne 200) { return $null }
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ("saife-verify-" + [guid]::NewGuid().ToString('N') + '.zip')
    try {
        Invoke-WebRequest -Uri $url -OutFile $tmp | Out-Null
        $hash = (Get-FileHash $tmp -Algorithm SHA256).Hash
        # The published archive must still contain the version it is named after.
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $zip = [IO.Compression.ZipFile]::OpenRead($tmp)
        try { $entries = $zip.Entries.FullName } finally { $zip.Dispose() }
        return [pscustomobject]@{ Hash = $hash; Entries = $entries; Size = (Get-Item $tmp).Length }
    } finally {
        Remove-Item $tmp -ErrorAction SilentlyContinue
    }
}

if ($VerifyOnly) {
    Step "verifying the published release $tag"
    $published = Get-PublishedHash $assetUrl
    if (-not $published) { Refuse "$assetUrl is not published (or requires auth)" }
    $local = Join-Path $releaseDir $assetName
    if (Test-Path $local) {
        $localHash = (Get-FileHash $local -Algorithm SHA256).Hash
        if ($localHash -ne $published.Hash) {
            Refuse "published hash $($published.Hash) differs from the local build $localHash"
        }
        Write-Host "hash matches the local build: $localHash"
    } else {
        Write-Host "published hash: $($published.Hash)  ($([math]::Round($published.Size / 1KB)) KB)"
    }
    Write-Host ("archive entries: {0}" -f (($published.Entries | Sort-Object) -join ', '))
    exit 0
}

# ---------------------------------------------------------------- preconditions

Step 'preconditions'
Push-Location $root
try {
    $branch = (& git rev-parse --abbrev-ref HEAD).Trim()
    if ($branch -ne 'main') { Refuse "on branch '$branch'; a release is cut from main" }

    $dirty = (& git status --porcelain)
    if ($dirty) {
        Write-Host $dirty
        Refuse 'the working tree is not clean; commit or stash first (the tag would not describe the bytes)'
    }

    & git fetch --quiet origin
    if ($LASTEXITCODE -ne 0) { Refuse 'git fetch failed' }
    $ahead = [int](& git rev-list --count 'origin/main..HEAD')
    $behind = [int](& git rev-list --count 'HEAD..origin/main')
    if ($ahead -ne 0 -or $behind -ne 0) { Refuse "HEAD is $ahead ahead / $behind behind origin/main; push or pull first" }

    $existing = (& git tag -l $tag)
    if ($existing -and -not $DryRun) { Refuse "tag $tag already exists; a published version is never re-cut (bump Cargo.toml)" }

    # The changelog is the release notes, so its section must exist before the build.
    $changelog = Join-Path $root 'CHANGELOG.md'
    if (-not (Test-Path $changelog)) { Refuse 'CHANGELOG.md is missing' }
    $text = [IO.File]::ReadAllText($changelog)
    $pattern = "(?ms)^## \[$([regex]::Escape($version))\].*?(?=^## \[|\z)"
    if ($text -notmatch $pattern) { Refuse "CHANGELOG.md has no '## [$version]' section" }
    $section = $Matches[0].TrimEnd() -replace '(?m)^## \[[^\]]+\][^\r\n]*\r?\n?', ''

    if (-not $section.Trim()) { Refuse "the CHANGELOG section for $version is empty" }
    if ($NotesFile -and -not (Test-Path $NotesFile)) { Refuse "notes file $NotesFile does not exist" }
    Write-Host '--- release notes ---'
    if ($NotesFile) { Write-Host (Get-Content $NotesFile -Raw) } else { Write-Host $section.Trim() }
    Write-Host '---------------------'

    if (-not $SkipTests) {
        Step 'tests and lints (the release gate; CI runs the same on push)'
        & cargo test --bin saife
        if ($LASTEXITCODE -ne 0) { Refuse 'cargo test failed' }
        & cargo clippy --all-targets -- -D warnings
        if ($LASTEXITCODE -ne 0) { Refuse 'clippy is not clean' }
    }

    Step 'build and package (static CRT, flat release asset)'
    & (Join-Path $PSScriptRoot 'build-dist.ps1') -Release
    $builtAsset = Join-Path $root $assetName
    if (-not (Test-Path $builtAsset)) { Refuse "$builtAsset was not produced" }
    New-Item -ItemType Directory -Path $releaseDir -Force | Out-Null
    Move-Item $builtAsset $assetPath -Force

    Step 'probe the asset (flat layout, reports the declared version)'
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = [IO.Compression.ZipFile]::OpenRead($assetPath)
    try { $entries = $zip.Entries.FullName } finally { $zip.Dispose() }
    foreach ($required in 'saife.exe', 'saife-launch.exe', 'README.txt') {
        if ($entries -notcontains $required) {
            Refuse "$assetName is not flat: '$required' is not at the archive root (entries: $($entries -join ', '))"
        }
    }
    $probeDir = Join-Path ([IO.Path]::GetTempPath()) ("saife-probe-" + [guid]::NewGuid().ToString('N'))
    try {
        Expand-Archive -Path $assetPath -DestinationPath $probeDir
        $probe = (& (Join-Path $probeDir 'saife.exe') --version) -join ' '
        if ($probe -notlike "*SAIFE Sandbox $version*") {
            Refuse "$assetName contains a binary that reports '$($probe.Trim())'"
        }
        Write-Host "probe: $($probe.Trim())"
    } finally {
        Remove-Item $probeDir -Recurse -Force -ErrorAction SilentlyContinue
    }

    $hash = (Get-FileHash $assetPath -Algorithm SHA256).Hash
    $size = (Get-Item $assetPath).Length
    Write-Host ("asset:  {0}  ({1:N0} KB)" -f $assetPath, ($size / 1KB))
    Write-Host "sha256: $hash"

    # Published checksums: the asset line first, then the bundle's own manifest so a
    # downloader has one file to check. LF, because sha256sum -c reads CR as part of
    # the file name.
    [IO.File]::WriteAllText(
        (Join-Path $releaseDir 'SHA256SUMS.txt'),
        "$($hash.ToLower())  $assetName`n",
        (New-Object System.Text.UTF8Encoding($false)))

    # The notes file is written here, not before the build: `build-dist.ps1` deletes
    # and recreates dist/ wholesale, so anything written into it earlier is gone.
    if (-not $NotesFile) {
        $NotesFile = Join-Path $releaseDir 'RELEASE_NOTES.md'
        [IO.File]::WriteAllText($NotesFile, $section.Trim() + "`n", (New-Object System.Text.UTF8Encoding($false)))
        Write-Host "release notes: $NotesFile"
    }

    Step 'winget manifests'
    # In a dry run the rewrite happens on a copy: a dry run that leaves the tracked
    # manifests modified is a dry run that has to be cleaned up by hand.
    $manifestTarget = if ($DryRun) { Join-Path ([IO.Path]::GetTempPath()) 'saife-winget-dryrun' } else { $wingetDir }
    if ($DryRun) {
        if (Test-Path $manifestTarget) { Remove-Item $manifestTarget -Recurse -Force }
        Copy-Item $wingetDir $manifestTarget -Recurse
    }
    foreach ($file in Get-ChildItem $manifestTarget -Filter '*.yaml') {
        $raw = [IO.File]::ReadAllText($file.FullName)
        $before = $raw
        # `[^\r\n]*` rather than `.*$`: .NET's `.` matches CR, so `.*$` swallows the
        # carriage return and leaves the file with one LF line among CRLFs.
        $raw = [regex]::Replace($raw, '(?m)^PackageVersion:[^\r\n]*', "PackageVersion: $version")
        $raw = [regex]::Replace($raw, '(?m)^(\s*)InstallerUrl:[^\r\n]*', "`${1}InstallerUrl: $assetUrl")
        $raw = [regex]::Replace($raw, '(?m)^(\s*)InstallerSha256:[^\r\n]*', "`${1}InstallerSha256: $hash")
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
        Step 'dry run: stopping before commit, tag and publish'
        Write-Host "would commit: packaging/winget (PackageVersion $version, InstallerUrl, InstallerSha256)"
        Write-Host "would tag:    $tag"
        Write-Host "would push:   main + $tag to origin"
        Write-Host "would publish $assetName ($hash) with notes from $NotesFile"
        exit 0
    }

    Step 'commit the rewritten manifests, tag, push'
    & git add 'packaging/winget'
    if ((& git status --porcelain)) {
        & git commit --quiet -m "chore(release): $tag manifests"
        if ($LASTEXITCODE -ne 0) { Refuse 'manifest commit failed' }
    }
    & git tag -a $tag -m "SAIFE Sandbox $version"
    if ($LASTEXITCODE -ne 0) { Refuse "git tag $tag failed" }
    & git push --quiet origin main
    if ($LASTEXITCODE -ne 0) { Refuse 'git push main failed' }
    & git push --quiet origin $tag
    if ($LASTEXITCODE -ne 0) { Refuse "git push $tag failed" }

    Step "publish the GitHub release $tag"
    & $gh release create $tag --repo $Repository --title "SAIFE Sandbox $version" --verify-tag --notes-file $NotesFile $assetPath (Join-Path $releaseDir 'SHA256SUMS.txt')
    if ($LASTEXITCODE -ne 0) { Refuse "gh release create failed" }

    Step 'verify what a user would download'
    $published = Get-PublishedHash $assetUrl
    if (-not $published) { Refuse "$assetUrl did not answer 200 after publishing" }
    if ($published.Hash -ne $hash) {
        Refuse "the published asset hashes to $($published.Hash), the built one to $hash"
    }
    Write-Host "published asset verified: $hash"
    Write-Host ''
    Write-Host "release: https://github.com/$Repository/releases/tag/$tag"
} finally {
    Pop-Location
}
