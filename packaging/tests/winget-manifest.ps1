#Requires -Version 7.0
<#
.SYNOPSIS
    Offline test of the per-architecture winget manifest rewrite in packaging/release.ps1.
.DESCRIPTION
    release.ps1 rewrites one Installer block per architecture. That is the step the
    single-architecture regex could not do without writing the same URL and hash into
    both blocks, and it is the step that only runs during a real release (main branch,
    clean tree, gh, winget). This test runs the SHIPPED function against the SHIPPED
    manifest text, so "the manifest was rewritten" is evidence rather than a claim.

    No network, no winget, no Pester.
#>

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$packaging = Split-Path -Parent $here
$releaseScript = Join-Path $packaging 'release.ps1'
$manifestPath = Join-Path $packaging 'winget/GandalfIX.SAIFE-Sandbox.installer.yaml'
foreach ($required in @($releaseScript, $manifestPath)) {
    if (-not (Test-Path $required)) { throw "cannot find $required" }
}

$text = Get-Content $releaseScript -Raw
$match = [regex]::Match($text, '(?ms)^function Update-WingetInstaller.*?^\}')
if (-not $match.Success) { throw 'Update-WingetInstaller is not defined in release.ps1' }

# The function reads two script-scope values and refuses through Refuse().
function Refuse([string]$message) { throw "release refused: $message" }
$version = '0.4.0'
Invoke-Expression $match.Value

$script:failures = 0
$script:passes = 0

function Assert-True([string]$case, [bool]$condition, [string]$detail = '') {
    if ($condition) {
        Write-Host "PASS  $case"
        $script:passes++
    } else {
        Write-Host ("FAIL  $case" + $(if ($detail) { " - $detail" } else { '' }))
        $script:failures++
    }
}

function Assert-Equal([string]$case, $expected, $actual) {
    if ($expected -eq $actual) {
        Write-Host "PASS  $case"
        $script:passes++
    } else {
        Write-Host "FAIL  $case - expected '$expected', got '$actual'"
        $script:failures++
    }
}

function Assert-Throws([string]$case, [scriptblock]$body, [string]$expectIn) {
    $message = $null
    try { & $body | Out-Null } catch { $message = "$_" }
    if (-not $message) {
        Write-Host "FAIL  $case - expected a refusal, nothing was thrown"
        $script:failures++
        return
    }
    if ($expectIn -and -not $message.Contains($expectIn)) {
        Write-Host "FAIL  $case - expected '$expectIn' in: $message"
        $script:failures++
        return
    }
    Write-Host "PASS  $case"
    $script:passes++
}

# Values that cannot be confused with each other, so a crossed assignment shows up.
$installers = @{
    x64   = @{ Url = 'https://example.invalid/v0.4.0/saife-0.4.0-x64.zip'; Sha256 = ('a' * 64).ToUpper() }
    arm64 = @{ Url = 'https://example.invalid/v0.4.0/saife-0.4.0-arm64.zip'; Sha256 = ('b' * 64).ToUpper() }
}

$manifest = [IO.File]::ReadAllText($manifestPath)
Assert-True 'the shipped manifest declares an x64 installer' ($manifest -match '(?m)^\s*-\s*Architecture:\s*x64\s*$')
Assert-True 'the shipped manifest declares an arm64 installer' ($manifest -match '(?m)^\s*-\s*Architecture:\s*arm64\s*$')
Assert-True 'the shipped manifest is CRLF' (-not [regex]::IsMatch($manifest, "(?<!\r)\n"))

# ------------------------------------------------------------ the real manifest
$rewritten = Update-WingetInstaller $manifest $installers 'GandalfIX.SAIFE-Sandbox.installer.yaml'

Assert-True 'the x64 block gets the x64 URL' ($rewritten -match '(?m)^\s*InstallerUrl:\s*https://example\.invalid/v0\.4\.0/saife-0\.4\.0-x64\.zip\s*$')
Assert-True 'the arm64 block gets the arm64 URL' ($rewritten -match '(?m)^\s*InstallerUrl:\s*https://example\.invalid/v0\.4\.0/saife-0\.4\.0-arm64\.zip\s*$')
Assert-True 'the x64 block gets the x64 hash' ($rewritten -match ('(?m)^\s*InstallerSha256:\s*' + ('a' * 64) + '\s*$'))
Assert-True 'the arm64 block gets the arm64 hash' ($rewritten -match ('(?m)^\s*InstallerSha256:\s*' + ('b' * 64) + '\s*$'))
Assert-True 'no stale 0.3.1 URL survives' (-not ($rewritten -match 'v0\.3\.1/saife'))
Assert-True 'the rewrite keeps CRLF' (-not [regex]::IsMatch($rewritten, "(?<!\r)\n"))

# The URL and hash must sit in the SAME block, in the right order: the arm64 URL with
# the x64 hash would install one architecture and verify it against the other.
$armIndex = $rewritten.IndexOf('- Architecture: arm64', [StringComparison]::Ordinal)
$armUrl = $rewritten.IndexOf('saife-0.4.0-arm64.zip', [StringComparison]::Ordinal)
$armHash = $rewritten.IndexOf(('B' * 64), [StringComparison]::Ordinal)
$x64Url = $rewritten.IndexOf('saife-0.4.0-x64.zip', [StringComparison]::Ordinal)
Assert-True 'the arm64 entry follows the x64 entry' ($x64Url -lt $armIndex)
Assert-True 'the arm64 URL is inside the arm64 block' ($armUrl -gt $armIndex)
Assert-True 'the arm64 hash is inside the arm64 block' ($armHash -gt $armIndex)
Assert-Equal 'the manifest still has exactly two installer entries' 2 ([regex]::Matches($rewritten, '(?m)^\s*-\s*Architecture:').Count)
Assert-True 'everything else is untouched (line count)' (([regex]::Split($rewritten, "`r`n")).Count -eq ([regex]::Split($manifest, "`r`n")).Count)

# ------------------------------------------------------------ refusals
Assert-Throws 'an archive for an architecture the manifest does not declare is refused' {
    Update-WingetInstaller $manifest @{ x64 = $installers.x64; arm64 = $installers.arm64; arm = @{ Url = 'u'; Sha256 = 'h' } } 'test.yaml'
} "no 'Architecture: arm' installer entry"

$onlyX64 = @"
PackageVersion: 0.4.0
Installers:
  - Architecture: x64
    InstallerUrl: https://example.invalid/old/saife-0.3.1-x64.zip
    InstallerSha256: 1111111111111111111111111111111111111111111111111111111111111111
ManifestType: installer
"@
Assert-Throws 'a manifest with only an x64 entry is refused when both archives exist' {
    Update-WingetInstaller $onlyX64 $installers 'test.yaml'
} "no 'Architecture: arm64' installer entry"

Assert-Throws 'an arm64 entry with no arm64 archive is refused (not left pointing at a 404)' {
    Update-WingetInstaller $manifest @{ x64 = $installers.x64 } 'GandalfIX.SAIFE-Sandbox.installer.yaml'
} 'declares Architecture: arm64'

# ------------------------------------------------------------ the caller
$release = Get-Content $releaseScript -Raw
Assert-True 'release.ps1 rewrites the installer manifest through that function' ($release -match 'Update-WingetInstaller\s+\$raw\s+\$installers')
Assert-True 'release.ps1 no longer replaces the first InstallerUrl in the file' (-not ($release -match "InstallerUrl:\[\^"))
Assert-True 'release.ps1 discovers assets by architecture, not by a baked name' ($release -match 'Get-ReleaseAssets' -and -not ($release -match 'saife-\$version-x64'))

Write-Host ''
Write-Host ("{0} passed, {1} failed" -f $script:passes, $script:failures)
if ($script:failures -gt 0) { exit 1 }
Write-Host 'all cases passed'
