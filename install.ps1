<#
.SYNOPSIS
    Download, verify and install the latest SAIFE Sandbox release from GitHub.

.EXAMPLE
    iwr https://raw.githubusercontent.com/GandalfIX/saife/main/install.ps1 -OutFile install.ps1; .\install.ps1

.EXAMPLE
    .\install.ps1 -Version 0.3.0 -Destination C:\tools\saife

.NOTES
    Why a script and not a package manager: there is no winget package. This script
    is the supported install, and it verifies the SHA256 of the archive against the
    release's own SHA256SUMS.txt before a single byte is extracted, so a corrupted or
    swapped download is refused rather than installed.

    The archive is chosen by architecture: an ARM64 host gets saife-<version>-arm64.zip,
    an x64 host gets saife-<version>-x64.zip and never the arm64 one (which cannot run
    there). An ARM64 host whose release carries only the x64 archive gets that, with a
    warning that it runs under emulation.

    It needs no administrator rights: everything goes into the user's profile and
    onto the USER Path. Nothing is written to the registry and no service is
    registered, so "uninstall" is deleting the directory (the last line it prints).
#>
param(
    # Version to install, with or without the leading "v". Default: the latest release.
    [string]$Version,
    [string]$Destination = (Join-Path $env:LOCALAPPDATA 'Programs\saife'),
    # Install the files but leave the user Path alone (e.g. for a portable copy).
    [switch]$NoPathEntry,
    # Print what would happen, download nothing, change nothing.
    [switch]$WhatIf,
    [string]$Repository = 'GandalfIX/saife'
)

$ErrorActionPreference = 'Stop'

# Windows PowerShell 5.1 still defaults to TLS 1.0 against api.github.com.
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
# 5.1's progress bar makes Invoke-WebRequest an order of magnitude slower.
$ProgressPreference = 'SilentlyContinue'

function Fail([string]$message) {
    Write-Host "install failed: $message" -ForegroundColor Red
    exit 1
}

function Step([string]$message) {
    Write-Host "== $message" -ForegroundColor Cyan
}

# ---------------------------------------------------------------- which archive

# Verbatim copies of Resolve-HostArch and Select-AssetForHost from
# packaging/lib/arch.ps1. This script is downloaded and run on its own, so it cannot
# dot-source a file from the repository; packaging/tests/arch.ps1 extracts both copies
# and fails if they drift, so the library stays the single definition to edit.
#
# Written in Windows PowerShell 5.1 syntax on purpose: the shell a user downloads this
# with is 5.1, not pwsh 7.

function Resolve-HostArch {
    [CmdletBinding()]
    param()

    $values = @()
    foreach ($raw in @($env:PROCESSOR_ARCHITECTURE, $env:PROCESSOR_ARCHITEW6432)) {
        if (-not $raw) { continue }
        $values += $raw.Trim().ToUpperInvariant()
    }
    if ($values.Count -eq 0) { return 'x64' }
    if ($values -contains 'ARM64') { return 'arm64' }
    if ($values -contains 'AMD64') { return 'x64' }
    throw ("unsupported PROCESSOR_ARCHITECTURE '{0}': expected AMD64 or ARM64, and PROCESSOR_ARCHITEW6432 '{1}' did not settle it either" -f $env:PROCESSOR_ARCHITECTURE, $env:PROCESSOR_ARCHITEW6432)
}

function Select-AssetForHost {
    [CmdletBinding()]
    param(
        [string[]]$Assets = @(),
        [string]$HostArch
    )

    $found = @{}
    foreach ($name in $Assets) {
        if (-not $name) { continue }
        $m = [regex]::Match($name, '^saife-(?<v>[0-9A-Za-z][0-9A-Za-z.\-]*)-(?<arch>x64|arm64)\.zip$')
        if (-not $m.Success) { continue }
        $arch = $m.Groups['arch'].Value
        if (-not $found.ContainsKey($arch)) { $found[$arch] = $m.Value }
    }

    if ($HostArch -eq 'arm64') {
        if ($found.ContainsKey('arm64')) { return $found['arm64'] }
        if ($found.ContainsKey('x64')) {
            Write-Warning ("this host is ARM64 and the release has no arm64 archive: using {0}, which runs under x64 emulation - slower, and this build has not been run on ARM hardware" -f $found['x64'])
            return $found['x64']
        }
        return $null
    }
    if ($HostArch -eq 'x64') {
        if ($found.ContainsKey('x64')) { return $found['x64'] }
        if ($found.ContainsKey('arm64')) {
            Write-Warning ("this host is x64 and the release has only {0}; an ARM64 binary cannot run on an x64 host" -f $found['arm64'])
        }
        return $null
    }
    throw ("unsupported host architecture '{0}' (expected x64 or arm64)" -f $HostArch)
}

# A host whose application-control policy refuses to execute the download.
#
# Smart App Control, AppLocker and WDAC all fail the same way: Windows refuses to
# create the process and PowerShell surfaces it as an ApplicationFailedException.
# The wording is LOCALIZED, so detection keys on the shape (an exception from the
# call) rather than on English text; every caller treats *any* such failure as
# "this host will not run the binary", and names the policy families to check.
function Show-ExecutionBlocked([string]$path, [string]$detail) {
    Write-Host ''
    Write-Host "install failed: this host's application-control policy refuses to run $path" -ForegroundColor Red
    Write-Host "   $detail"
    Write-Host ''
    Write-Host '   saife ships UNSIGNED, and Smart App Control / AppLocker / WDAC commonly block'
    Write-Host '   unsigned executables - often specifically from user-writable paths (%TEMP%,'
    Write-Host '   %LOCALAPPDATA%), which is where a fresh download lives.'
    Write-Host ''
    Write-Host '   Diagnose on this machine:'
    Write-Host '      # WHICH policy blocked it - the 3033/3077 events carry the policy id (Win32_DeviceGuard'
    Write-Host '      # answers "Invalid class" on some builds, so the events are the reliable source):'
    Write-Host "      Get-WinEvent -LogName 'Microsoft-Windows-CodeIntegrity/Operational' -MaxEvents 60 |"
    Write-Host '        Where-Object { $_.Id -in 3033,3077 } | Select-Object -First 4 |'
    Write-Host '        ForEach-Object { "--- $($_.TimeCreated) Id=$($_.Id)"; $_.Message }'
    Write-Host '      # Smart App Control (0=off 1=on 2=evaluation):'
    Write-Host '      (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy" -ErrorAction SilentlyContinue).VerifiedAndReputablePolicyState'
    Write-Host '      # AppLocker (<AppLockerPolicy Version="1" /> = no rules, so not AppLocker):'
    Write-Host '      Get-AppLockerPolicy -Effective -Xml'
    Write-Host '      # active Code Integrity policies (presence alone is normal; the events say what blocked):'
    Write-Host '      Get-ChildItem "C:\Windows\System32\CodeIntegrity\CiPolicies\Active" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name'
    Write-Host ''
    Write-Host '   Options:'
    Write-Host "      1. allow $installDir (or this binary) in the AppLocker/WDAC policy - needs an admin"
    Write-Host '      2. sign the release with a code-signing certificate - the product-level fix'
    Write-Host '      3. install on a host without that policy'
    Write-Host ''
}

# ------------------------------------------------------------------ what to fetch

if ($Version) {
    $Version = $Version.TrimStart('v', 'V')
    $releaseUrl = "https://api.github.com/repos/$Repository/releases/tags/v$Version"
} else {
    $releaseUrl = "https://api.github.com/repos/$Repository/releases/latest"
}

Step "resolving the release ($releaseUrl)"

# Smart App Control (1 = on) refuses UNSIGNED binaries outright, on every path. Say
# so BEFORE the download: nothing this script does can change that verdict, and a
# 2 MB download followed by a refusal reads like a broken release.
$sacState = $null
try {
    $sacState = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy' -ErrorAction SilentlyContinue).VerifiedAndReputablePolicyState
} catch { }
if ($sacState -eq 1) {
    Write-Host 'warning: Smart App Control is ON on this machine (VerifiedAndReputablePolicyState=1).' -ForegroundColor Yellow
    Write-Host '         It refuses UNSIGNED binaries on every path, so this release will download,'
    Write-Host '         verify and then be blocked when it is executed.'
    Write-Host '         Turn SAC off (Windows Security > App & browser control > Smart App Control;'
    Write-Host '         the switch is one-way) or install on a host where it is off.'
    Write-Host "         Diagnosis and options: docs/FAQ.md, 'An Application Control policy has blocked'."
    Write-Host ''
}
try {
    $release = Invoke-RestMethod -Uri $releaseUrl -Headers @{
        'User-Agent' = 'saife-install'
        'Accept'     = 'application/vnd.github+json'
    }
} catch {
    Fail "cannot read the release from GitHub: $($_.Exception.Message)"
}

$tag = $release.tag_name
$version = $tag.TrimStart('v', 'V')
Write-Host "   version: $version   (tag $tag, published $($release.published_at))"

# Which archive this machine can actually run. PROCESSOR_ARCHITECTURE decides, not a
# preference: an ARM64 host may run the x64 build under emulation (slower, and the
# build has not been run natively on ARM), an x64 host cannot run an ARM64 one at all.
try {
    $hostArch = Resolve-HostArch
} catch {
    Fail "cannot tell this host's architecture: $($_.Exception.Message)"
}
$assetNames = @($release.assets | ForEach-Object { $_.name })
$zipName = Select-AssetForHost -Assets $assetNames -HostArch $hostArch
if (-not $zipName) {
    Fail ("release {0} has no {1} archive for this host (assets: {2})" -f $tag, $hostArch, ($assetNames -join ', '))
}
$zipAsset = $release.assets | Where-Object { $_.name -eq $zipName } | Select-Object -First 1
$sumsAsset = $release.assets | Where-Object { $_.name -eq 'SHA256SUMS.txt' } | Select-Object -First 1
if (-not $sumsAsset) {
    # Refused rather than skipped: an unverifiable download of a containment tool is
    # exactly the delivery path this project exists to distrust.
    Fail "release $tag has no SHA256SUMS.txt, so the download cannot be verified"
}
Write-Host "   archive: $($zipAsset.name)   (this host is $hostArch)"

$installDir = $Destination
$existing = Join-Path $installDir 'saife.exe'
$existingVersion = $null
if (Test-Path $existing) {
    # A host that blocks execution throws here as well; report "unknown" rather than
    # aborting before the download even starts.
    try {
        $existingVersion = ((& $existing --version) -join ' ') -replace '.*?(\d+\.\d+\.\d+\S*).*', '$1'
    } catch {
        $existingVersion = 'an existing build this host will not execute'
    }
}

if ($WhatIf) {
    Write-Host ''
    Write-Host 'WhatIf: nothing downloaded, nothing changed.'
    Write-Host "   would download: $($zipAsset.name)  ($([math]::Round($zipAsset.size / 1KB)) KB)"
    Write-Host "   would verify:   SHA256 against $($sumsAsset.name)"
    Write-Host "   would install:  $installDir"
    if ($existingVersion) { Write-Host "   would replace:  $existingVersion" }
    if (-not $NoPathEntry) { Write-Host "   would add to:   user Path" }
    exit 0
}

# ------------------------------------------------------------------ download + verify

$stage = Join-Path ([IO.Path]::GetTempPath()) ("saife-install-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $stage | Out-Null
try {
    $zipPath = Join-Path $stage $zipAsset.name
    $sumsPath = Join-Path $stage $sumsAsset.name

    Step "downloading $($zipAsset.name) ($([math]::Round($zipAsset.size / 1KB)) KB)"
    try {
        Invoke-WebRequest -Uri $zipAsset.browser_download_url -OutFile $zipPath -UseBasicParsing
        Invoke-WebRequest -Uri $sumsAsset.browser_download_url -OutFile $sumsPath -UseBasicParsing
    } catch {
        Fail "download failed: $($_.Exception.Message)"
    }

    Step 'verifying the SHA256 against the release checksum'
    # The sums file is "<hash>  <name>" with LF endings; match on the file name so a
    # rename or an extra line cannot make the check silently pass.
    $expected = $null
    foreach ($line in Get-Content $sumsPath) {
        if ($line -match '^\s*([0-9A-Fa-f]{64})\s+\*?(.+?)\s*$' -and $Matches[2] -eq $zipAsset.name) {
            $expected = $Matches[1]
        }
    }
    if (-not $expected) { Fail "$($sumsAsset.name) has no line for $($zipAsset.name)" }
    $actual = (Get-FileHash $zipPath -Algorithm SHA256).Hash
    if ($actual -ne $expected.ToUpper()) {
        Fail "hash mismatch: download is $actual, the release says $($expected.ToUpper())"
    }
    Write-Host "   ok: $actual" -ForegroundColor Green

    Step 'extracting'
    $unpacked = Join-Path $stage 'unpacked'
    Expand-Archive -Path $zipPath -DestinationPath $unpacked
    foreach ($required in 'saife.exe', 'saife-launch.exe') {
        if (-not (Test-Path (Join-Path $unpacked $required))) {
            Fail "$($zipAsset.name) does not contain $required at its root"
        }
    }

    # Ask the binary what it is before installing it: a mislabelled build passes every
    # check on the file name alone. A host whose application-control policy refuses to
    # execute this %TEMP% copy cannot answer here - that is a HOST condition, not a
    # mislabelled release, so the probe is deferred to the installed copy (checked
    # below) instead of being reported as a broken download.
    $stagedProbe = $null
    try {
        $stagedProbe = ((& (Join-Path $unpacked 'saife.exe') --version) -join ' ')
    } catch {
        Write-Warning "cannot execute the staged copy on this host: $($_.Exception.Message)"
        Write-Warning 'the version probe moves to the installed copy (user-writable paths such as %TEMP% are commonly blocked by application-control policy)'
    }
    if ($stagedProbe) {
        if ($stagedProbe -notlike "*SAIFE Sandbox $version*") {
            Fail "the downloaded saife.exe reports '$($stagedProbe.Trim())', the release is $version"
        }
        Write-Host "   ok: $($stagedProbe.Trim())" -ForegroundColor Green
    }

    # ------------------------------------------------------------------ install

    Step "installing to $installDir"
    if (Test-Path $installDir) {
        if ($existingVersion) { Write-Host "   replacing $existingVersion" }
        Remove-Item $installDir -Recurse -Force -ErrorAction Stop
    }
    New-Item -ItemType Directory -Path $installDir -Force | Out-Null
    Copy-Item (Join-Path $unpacked '*') -Destination $installDir -Recurse -Force

    $installed = Join-Path $installDir 'saife.exe'

    # The installed copy is the one that has to run: verify the version HERE, before
    # the user Path is touched, and say plainly when the host refuses to start it.
    try {
        $reported = ((& $installed --version) -join ' ')
    } catch {
        Show-ExecutionBlocked $installed $_.Exception.Message
        Fail 'the files were copied, but this host will not execute them; nothing was added to the user Path'
    }
    if ($reported -notlike "*SAIFE Sandbox $version*") {
        Fail "the installed saife.exe reports '$($reported.Trim())', the release is $version"
    }
    Write-Host "   ok: $($reported.Trim())" -ForegroundColor Green

    if (-not $NoPathEntry) {
        $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
        $entries = @($userPath -split ';' | Where-Object { $_ })
        if ($entries -notcontains $installDir) {
            $newPath = (@($entries) + $installDir) -join ';'
            [Environment]::SetEnvironmentVariable('Path', $newPath, 'User')
            Write-Host "   added to the user Path (open a NEW shell for 'saife' to resolve)"
        } else {
            Write-Host '   already on the user Path'
        }
    }

    Step 'self-check'
    # Not fatal: setup reports an unsupported host, and the tool is then installed but
    # useless on this machine. Saying so is better than a green line that lies.
    & $installed setup --check-only
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "saife setup reports an unsupported or incomplete host (exit $LASTEXITCODE); see its output above"
    }

    Write-Host ''
    Write-Host "SAIFE Sandbox $version installed in $installDir" -ForegroundColor Green
    Write-Host ''
    Write-Host 'Next:'
    Write-Host '   saife setup --check-only'
    Write-Host '   saife run --allow-cwd -- cmd /c echo ok'
    Write-Host ''
    Write-Host "Uninstall: remove $installDir, remove it from the user Path, then delete"
    Write-Host '   %USERPROFILE%\.saife and %LOCALAPPDATA%\saife (profiles, audit chain, signing key).'
} finally {
    Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue
}
