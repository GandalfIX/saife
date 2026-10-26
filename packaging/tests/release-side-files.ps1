# Verifies the guard that packaging/release.ps1 runs before it tags: the asset, its
# SHA256SUMS.txt entry and the notes file must all exist before `gh release create`
# runs, because a tag pushed without them cannot be withdrawn (immutable releases).
#
# The function under test is taken from the SHIPPED script text rather than copied
# here - a copy would keep passing after the real guard changed.
#
#   pwsh -File packaging/tests/release-side-files.ps1
#
# No Pester: this has to run on a machine that only has pwsh.

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$releaseScript = Join-Path (Split-Path -Parent $here) 'release.ps1'
if (-not (Test-Path $releaseScript)) { throw "cannot find $releaseScript" }

$text = Get-Content $releaseScript -Raw
$match = [regex]::Match($text, '(?ms)^function Assert-ReleaseSideFiles.*?^\}')
if (-not $match.Success) { throw 'Assert-ReleaseSideFiles is not defined in release.ps1' }

# Refuse() is the script's own refusal: it throws "release refused: ...".
function Refuse([string]$message) { throw "release refused: $message" }
Invoke-Expression $match.Value

$hash = '83e8edf8b82e32f3fe16675c97264ce2b7f544190c9fe9c35b275eecb58a97b2'
$name = 'saife-0.3.1-x64.zip'
$failures = 0

function New-ReleaseDir([string]$sums) {
    $dir = Join-Path ([IO.Path]::GetTempPath()) ("side-files-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    if ($sums) {
        [IO.File]::WriteAllText((Join-Path $dir 'SHA256SUMS.txt'), $sums, (New-Object System.Text.UTF8Encoding($false)))
    }
    return $dir
}

function Check([string]$case, [scriptblock]$body, [string]$expectIn) {
    try { & $body } catch { $message = "$_" } finally { }
    if ($expectIn) {
        if ($message -and $message.Contains($expectIn)) {
            Write-Host "PASS  $case"
        } else {
            Write-Host "FAIL  $case - expected a refusal mentioning '$expectIn', got: $message"
            $script:failures++
        }
    } else {
        if ($message) {
            Write-Host "FAIL  $case - expected no refusal, got: $message"
            $script:failures++
        } else {
            Write-Host "PASS  $case"
        }
    }
}

$ok = New-ReleaseDir "$hash  $name`n"
$missing = New-ReleaseDir $null
$otherName = New-ReleaseDir "$hash  saife-0.3.0-x64.zip`n"
$otherHash = New-ReleaseDir ("0" * 64 + "  $name`n")

Check 'asset and sums agree' { Assert-ReleaseSideFiles $ok $name $hash } $null
Check 'sums missing' { Assert-ReleaseSideFiles $missing $name $hash } 'no SHA256SUMS.txt'
Check 'sums does not list the asset' { Assert-ReleaseSideFiles $otherName $name $hash } 'does not list'
Check 'sums records another hash' { Assert-ReleaseSideFiles $otherHash $name $hash } 'records'

foreach ($dir in @($ok, $missing, $otherName, $otherHash)) { Remove-Item $dir -Recurse -Force }

if ($failures -gt 0) {
    Write-Host "$failures case(s) failed"
    exit 1
}
Write-Host 'all cases passed'
