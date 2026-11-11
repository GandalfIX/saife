# Guards the compliance artifacts, in the same script-text style as
# release-side-files.ps1: the checked fact is read from the SHIPPED script, so a
# copy here cannot keep passing after the real guard changed.
#
# THIRD-PARTY-LICENSES.md (dependency license texts) and the CycloneDX SBOMs must
# travel with every release asset: MIT/Apache-2.0/BSD/ISC/Unlicense/Unicode-3.0
# require the text in every distribution of the binary, and the EU Cyber
# Resilience Act requires a machine-readable SBOM. If any check here fails, an
# asset can be published without them.
#
#   pwsh -File packaging/tests/licenses-guard.ps1
#
# No Pester: this has to run on a machine that only has pwsh.

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$packaging = Split-Path -Parent $here
$releaseScript = Join-Path $packaging 'release.ps1'
$distScript = Join-Path $packaging 'build-dist.ps1'
$generator = Join-Path $packaging 'licenses/generate.ps1'
$config = Join-Path $packaging 'licenses/about.toml'

$failures = 0
function Check([string]$case, [bool]$ok, [string]$detail) {
    if ($ok) { Write-Host "PASS  $case" }
    else {
        Write-Host "FAIL  $case - $detail"
        $script:failures++
    }
}

foreach ($script in $releaseScript, $distScript, $generator) {
    if (-not (Test-Path $script)) { throw "cannot find $script" }
}

$release = Get-Content $releaseScript -Raw
$dist = Get-Content $distScript -Raw

# 1. The pre-tag guard in release.ps1 demands the artifacts inside every asset.
$requiredBlock = [regex]::Match($release, '(?ms)\$required = @\(.*?\)').Value
Check 'release.ps1 demands THIRD-PARTY-LICENSES.md inside every asset' `
    ($requiredBlock -match "'THIRD-PARTY-LICENSES\.md'") `
    'the $required list in release.ps1 does not name it'

Check 'release.ps1 demands the x64 SBOM inside every asset' `
    ($requiredBlock -match 'saife-\$version-sbom-x64\.cdx\.json') `
    'the $required list in release.ps1 does not name it'

Check 'release.ps1 demands the arm64 SBOM inside every asset' `
    ($requiredBlock -match 'saife-\$version-sbom-arm64\.cdx\.json') `
    'the $required list in release.ps1 does not name it'

# 2. build-dist.ps1 cannot be talked into a release without the artifacts.
Check 'build-dist.ps1 refuses -SkipLicenses on the release path' `
    ($dist -match 'if \(\$SkipLicenses -and \(\$Release -or \$ReleaseVersion\)\)') `
    'the refusal for -SkipLicenses + -Release is gone'

Check 'build-dist.ps1 runs packaging/licenses/generate.ps1' `
    ($dist -match 'licenses\\generate\.ps1') `
    'the generation step is gone from build-dist.ps1'

# 3. The generator still sources its config from about.toml (the gate that fails
#    the build on an unknown license), and the gate admits no copyleft license.
$about = Get-Content $config -Raw
Check 'about.toml accepts no copyleft license' `
    ($about -notmatch '(?i)^(?!#).*\b(GPL|LGPL|AGPL|MPL|CDDL|EPL|SSPL)\b') `
    'a copyleft/weak-copyleft identifier appeared in accepted - read that license first, then remove it from the list here as well'
