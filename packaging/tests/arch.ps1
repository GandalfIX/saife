#Requires -Version 7.0
<#
.SYNOPSIS
    Tests the architecture helper and the release-asset selection install.ps1 runs on.
.DESCRIPTION
    No Pester: this has to run on a machine that only has pwsh.

    Two of the functions have a second home: install.ps1 is downloaded and run on its
    own, so it cannot dot-source packaging/lib/arch.ps1 and carries verbatim copies of
    Resolve-HostArch and Select-AssetForHost. Those copies are extracted from the
    SHIPPED script here - not duplicated in this file - so a drift fails the test
    instead of shipping a library that is right and an installer that is wrong.

    Nothing here touches the network or the filesystem beyond reading the two scripts
    and (for the PE check) the running pwsh.exe.
#>

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$packaging = Split-Path -Parent $here
$repo = Split-Path -Parent $packaging
$lib = Join-Path $packaging 'lib/arch.ps1'
$installer = Join-Path $repo 'install.ps1'
foreach ($required in @($lib, $installer)) {
    if (-not (Test-Path $required)) { throw "cannot find $required" }
}
. $lib

$script:failures = 0
$script:passes = 0

function Assert-Equal([string]$case, $expected, $actual) {
    if ($expected -eq $actual) {
        Write-Host "PASS  $case"
        $script:passes++
    } else {
        Write-Host "FAIL  $case - expected '$expected', got '$actual'"
        $script:failures++
    }
}

function Assert-True([string]$case, [bool]$condition, [string]$detail = '') {
    if ($condition) {
        Write-Host "PASS  $case"
        $script:passes++
    } else {
        Write-Host ("FAIL  $case" + $(if ($detail) { " - $detail" } else { '' }))
        $script:failures++
    }
}

function Assert-Throws([string]$case, [scriptblock]$body, [string]$expectIn) {
    $message = $null
    try { & $body | Out-Null } catch { $message = "$_" }
    if (-not $message) {
        Write-Host "FAIL  $case - expected a throw, nothing was thrown"
        $script:failures++
        return
    }
    if ($expectIn -and -not $message.Contains($expectIn)) {
        Write-Host "FAIL  $case - expected a message containing '$expectIn', got: $message"
        $script:failures++
        return
    }
    Write-Host "PASS  $case"
    $script:passes++
}

# PROCESSOR_ARCHITECTURE is process state, so every case sets it explicitly and the
# originals are put back at the end.
$savedArch = $env:PROCESSOR_ARCHITECTURE
$savedWow = $env:PROCESSOR_ARCHITEW6432
function Set-HostEnv([string]$arch, [string]$wow = '') {
    $env:PROCESSOR_ARCHITECTURE = $arch
    if ($wow) { $env:PROCESSOR_ARCHITEW6432 = $wow }
    else { Remove-Item Env:PROCESSOR_ARCHITEW6432 -ErrorAction SilentlyContinue }
}

function Get-FunctionText([string]$path, [string]$name) {
    $text = [IO.File]::ReadAllText($path)
    $m = [regex]::Match($text, '(?ms)^function\s+' + [regex]::Escape($name) + '\s*\{.*?^\}')
    if (-not $m.Success) { throw "no function $name in $path" }
    return ($m.Value -replace "`r`n", "`n").TrimEnd()
}

try {
    # ------------------------------------------------------------ host architecture
    Set-HostEnv 'AMD64'
    Assert-Equal 'AMD64 is x64' 'x64' (Resolve-HostArch)

    Set-HostEnv 'arm64'
    Assert-Equal 'arm64 (lower case, as a user would type it) is arm64' 'arm64' (Resolve-HostArch)

    Set-HostEnv 'AMD64' 'ARM64'
    Assert-Equal 'a WOW64/x64-emulated process on ARM64 reports the native ARM64' 'arm64' (Resolve-HostArch)

    # The case that matters most: a 32-bit or x64-emulated shell on an ARM64 host.
    Set-HostEnv 'ARM64' 'AMD64'
    Assert-Equal 'ARM64 outranks a stale AMD64 in PROCESSOR_ARCHITEW6432' 'arm64' (Resolve-HostArch)

    Set-HostEnv 'x86' 'AMD64'
    Assert-Equal 'a 32-bit process on an x64 host is still x64' 'x64' (Resolve-HostArch)

    Set-HostEnv ''
    Assert-Equal 'no PROCESSOR_ARCHITECTURE at all falls back to x64' 'x64' (Resolve-HostArch)

    Set-HostEnv 'IA64'
    Assert-Throws 'an unknown non-empty PROCESSOR_ARCHITECTURE throws' { Resolve-HostArch } 'AMD64 or ARM64'

    Set-HostEnv 'x86'
    Assert-Throws 'a 32-bit-only Windows (x86, nothing native) throws' { Resolve-HostArch } 'AMD64 or ARM64'

    # ------------------------------------------------------------ -Arch validation
    Set-HostEnv 'AMD64'
    Assert-Equal 'no -Arch means this host' 'x64' (Resolve-ArchParam -Arch '')
    Assert-Equal '-Arch x64' 'x64' (Resolve-ArchParam -Arch 'x64')
    Assert-Equal '-Arch ARM64 is case-insensitive' 'arm64' (Resolve-ArchParam -Arch 'ARM64')
    Assert-Equal '-Arch all is accepted where building both is meaningful' 'all' (Resolve-ArchParam -Arch 'all')
    Assert-Throws '-Arch arm (32-bit ARM) is refused' { Resolve-ArchParam -Arch 'arm' } 'unknown -Arch'
    Assert-Throws '-Arch x86 is refused' { Resolve-ArchParam -Arch 'x86' } 'unknown -Arch'

    # ------------------------------------------------------------ targets and names
    Assert-Equal 'the x64 rust target' 'x86_64-pc-windows-msvc' (Get-RustTarget -Arch 'x64')
    Assert-Equal 'the arm64 rust target' 'aarch64-pc-windows-msvc' (Get-RustTarget -Arch 'arm64')
    Assert-Throws 'all is not a rust target' { Get-RustTarget -Arch 'all' } 'no rust target'

    Assert-Equal 'asset name, x64' 'saife-0.4.0-x64.zip' (Get-AssetName -Version '0.4.0' -Arch 'x64')
    Assert-Equal 'asset name, arm64' 'saife-0.4.0-arm64.zip' (Get-AssetName -Version '0.4.0' -Arch 'arm64')
    Assert-Equal 'asset name, pre-release version' 'saife-0.4.0-rc.1-arm64.zip' (Get-AssetName -Version '0.4.0-rc.1' -Arch 'arm64')
    Assert-Throws 'asset names are never "all"' { Get-AssetName -Version '0.4.0' -Arch 'all' } 'no rust target'

    # ------------------------------------------------------------ PE machine field
    Assert-Equal 'IMAGE_FILE_MACHINE_AMD64' 0x8664 (Get-ArchMachine -Arch 'x64')
    Assert-Equal 'IMAGE_FILE_MACHINE_ARM64' 0xAA64 (Get-ArchMachine -Arch 'arm64')
    $self = (Get-Process -Id $PID).Path
    if ($self -and (Test-Path $self)) {
        # A real PE image, read the way build-dist.ps1 reads a cross-built one.
        Assert-Equal 'Get-PeMachine reads a real x64 image' 0x8664 (Get-PeMachine -Path $self)
    } else {
        Write-Host 'SKIP  Get-PeMachine against the running pwsh.exe (path unknown)'
    }
    Assert-Throws 'Get-PeMachine refuses a file that is not a PE image' {
        $tmp = Join-Path ([IO.Path]::GetTempPath()) ('notape-' + [guid]::NewGuid().ToString('N') + '.bin')
        [IO.File]::WriteAllText($tmp, ('x' * 200))
        try { Get-PeMachine -Path $tmp } finally { Remove-Item $tmp -Force -ErrorAction SilentlyContinue }
    } 'PE header offset'


    # ------------------------------------------------------------ which asset to install
    $both = @('saife-0.4.0-x64.zip', 'saife-0.4.0-arm64.zip')
    $warnings = @()
    $pick = Select-AssetForHost -Assets $both -HostArch 'arm64' -WarningVariable warnings -WarningAction SilentlyContinue
    Assert-Equal 'an ARM64 host takes the arm64 archive' 'saife-0.4.0-arm64.zip' $pick
    Assert-Equal 'an ARM64 host with an arm64 archive warns about nothing' 0 $warnings.Count

    $warnings = @()
    $pick = Select-AssetForHost -Assets @('saife-0.4.0-x64.zip') -HostArch 'arm64' -WarningVariable warnings -WarningAction SilentlyContinue
    Assert-Equal 'an ARM64 host falls back to x64 when that is all the release has' 'saife-0.4.0-x64.zip' $pick
    Assert-True 'the ARM64 fallback warns' ($warnings.Count -ge 1)
    Assert-True 'the fallback warning says it runs under emulation' ([bool]((($warnings | ForEach-Object { $_.Message }) -join ' ') -match 'emulation'))

    $warnings = @()
    $pick = Select-AssetForHost -Assets $both -HostArch 'x64' -WarningVariable warnings -WarningAction SilentlyContinue
    Assert-Equal 'an x64 host takes the x64 archive' 'saife-0.4.0-x64.zip' $pick
    Assert-Equal 'an x64 host with both archives warns about nothing' 0 $warnings.Count

    $warnings = @()
    $pick = Select-AssetForHost -Assets @('saife-0.4.0-arm64.zip') -HostArch 'x64' -WarningVariable warnings -WarningAction SilentlyContinue
    Assert-Equal 'an x64 host never picks an arm64 archive' $null $pick
    Assert-True 'an x64 host with only arm64 warns' ($warnings.Count -ge 1)

    Assert-Equal 'no archives means no selection, not a guess' $null (Select-AssetForHost -Assets @() -HostArch 'x64')
    Assert-Equal 'the human bundle saife-<sha>.zip is not an asset' $null (Select-AssetForHost -Assets @('saife-259be6d.zip') -HostArch 'x64')
    Assert-Equal 'a pre-release version still parses' 'saife-0.4.0-rc.1-arm64.zip' (Select-AssetForHost -Assets @('saife-0.4.0-rc.1-x64.zip', 'saife-0.4.0-rc.1-arm64.zip') -HostArch 'arm64')
    Assert-Throws 'an unsupported host architecture is refused' { Select-AssetForHost -Assets $both -HostArch 'x86' } 'unsupported host architecture'

    # ------------------------------------------------------------ install.ps1 copies
    $installHost = Get-FunctionText $installer 'Resolve-HostArch'
    $installSelect = Get-FunctionText $installer 'Select-AssetForHost'
    Assert-Equal 'install.ps1 carries Resolve-HostArch verbatim' (Get-FunctionText $lib 'Resolve-HostArch') $installHost
    Assert-Equal 'install.ps1 carries Select-AssetForHost verbatim' (Get-FunctionText $lib 'Select-AssetForHost') $installSelect

    $installText = [IO.File]::ReadAllText($installer)
    Assert-True 'install.ps1 selects the asset through that function' ([regex]::IsMatch($installText, 'Select-AssetForHost\s+-Assets'))
    Assert-True 'install.ps1 no longer matches an x64-only asset name' (-not [regex]::IsMatch($installText, "saife-\.\*-x64"))

    # The shipped copy, executed in a child scope, must behave like the library one.
    $behaviour = & {
        param($hostText, $selectText)
        Invoke-Expression $hostText
        Invoke-Expression $selectText
        $armWarnings = @()
        $arm = Select-AssetForHost -Assets @('saife-0.4.0-x64.zip', 'saife-0.4.0-arm64.zip') -HostArch 'arm64' -WarningVariable armWarnings -WarningAction SilentlyContinue
        $x64 = Select-AssetForHost -Assets @('saife-0.4.0-x64.zip', 'saife-0.4.0-arm64.zip') -HostArch 'x64' -WarningAction SilentlyContinue
        $fallbackWarnings = @()
        $fallback = Select-AssetForHost -Assets @('saife-0.4.0-x64.zip') -HostArch 'arm64' -WarningVariable fallbackWarnings -WarningAction SilentlyContinue
        $never = Select-AssetForHost -Assets @('saife-0.4.0-arm64.zip') -HostArch 'x64' -WarningAction SilentlyContinue
        [pscustomobject]@{
            Arm      = $arm
            X64      = $x64
            Fallback = $fallback
            Never    = $never
            FallbackWarned = $fallbackWarnings.Count -ge 1
        }
    } $installHost $installSelect

    Assert-Equal 'install.ps1: an ARM64 host picks arm64' 'saife-0.4.0-arm64.zip' $behaviour.Arm
    Assert-Equal 'install.ps1: an x64 host picks x64' 'saife-0.4.0-x64.zip' $behaviour.X64
    Assert-Equal 'install.ps1: an ARM64 host falls back to x64' 'saife-0.4.0-x64.zip' $behaviour.Fallback
    Assert-True 'install.ps1: the fallback warns' $behaviour.FallbackWarned
    Assert-Equal 'install.ps1: an x64 host never picks arm64' $null $behaviour.Never
} finally {
    if ($savedArch) { $env:PROCESSOR_ARCHITECTURE = $savedArch } else { Remove-Item Env:PROCESSOR_ARCHITECTURE -ErrorAction SilentlyContinue }
    if ($savedWow) { $env:PROCESSOR_ARCHITEW6432 = $savedWow } else { Remove-Item Env:PROCESSOR_ARCHITEW6432 -ErrorAction SilentlyContinue }
}

Write-Host ''
Write-Host ("{0} passed, {1} failed" -f $script:passes, $script:failures)
if ($script:failures -gt 0) { exit 1 }
Write-Host 'all cases passed'
