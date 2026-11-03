#Requires -Version 7.0
<#
.SYNOPSIS
    The architecture primitives the packaging scripts share: which architecture this
    host is, which one to build, where cargo puts it, what the asset is called, and
    which release asset a given host should install.
.DESCRIPTION
    Dot-source this file (`. (Join-Path $PSScriptRoot 'lib\arch.ps1')`).

    Every function here is pure: it reads environment variables, strings, and - for
    Get-PeMachine - the first bytes of a file. Nothing is executed, no module is
    required and nothing is written, so packaging/tests/arch.ps1 can call all of it
    directly and the build scripts can use it without side effects.

    The bodies are deliberately Windows PowerShell 5.1-compatible even though the
    scripts that dot-source this file are pwsh 7 only: install.ps1 runs on a stock
    Windows 5.1 shell, cannot dot-source a file from the repository (users download
    that one script), and therefore carries verbatim copies of Resolve-HostArch and
    Select-AssetForHost. packaging/tests/arch.ps1 fails if those copies drift.
#>

# AMD64 and ARM64 are the only values Windows sets for a 64-bit host. A 32-bit (or
# x64-emulated) process on a 64-bit host reports x86/AMD64 in PROCESSOR_ARCHITECTURE
# and the real architecture in PROCESSOR_ARCHITEW6432 - which is why that variable is
# consulted at all, and why ARM64 outranks AMD64 when the two disagree.
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

# -Arch is validated here rather than with a ValidateSet, because its default is
# whatever this host is - and because 'all' is a legitimate request to the scripts
# that build, but never to the ones that name a single rust target.
function Resolve-ArchParam {
    [CmdletBinding()]
    param([string]$Arch)

    if (-not $Arch) { return (Resolve-HostArch) }
    $value = $Arch.Trim().ToLowerInvariant()
    if ($value -eq 'x64' -or $value -eq 'arm64' -or $value -eq 'all') { return $value }
    throw ("unknown -Arch '{0}': expected x64, arm64 or all" -f $Arch)
}

function Get-RustTarget {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Arch)

    switch ($Arch.Trim().ToLowerInvariant()) {
        'x64' { return 'x86_64-pc-windows-msvc' }
        'arm64' { return 'aarch64-pc-windows-msvc' }
        default { throw ("no rust target for architecture '{0}' (known: x64, arm64)" -f $Arch) }
    }
}

# The asset name is a contract: install.ps1, install-local.ps1, the winget manifests
# and the release URL all derive from it, so it is produced in exactly one place.
function Get-AssetName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Version,
        [Parameter(Mandatory = $true)][string]$Arch
    )

    $triple = Get-RustTarget -Arch $Arch   # also rejects 'all' and typos
    if (-not $triple) { throw ("no rust target for architecture '{0}'" -f $Arch) }
    return ("saife-{0}-{1}.zip" -f $Version, $Arch.Trim().ToLowerInvariant())
}

# IMAGE_FILE_MACHINE_* from winnt.h: the field a build can be checked against
# without running it, which is the only option for a cross-built binary.
function Get-ArchMachine {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Arch)

    switch ($Arch.Trim().ToLowerInvariant()) {
        'x64' { return 0x8664 }      # IMAGE_FILE_MACHINE_AMD64
        'arm64' { return 0xAA64 }    # IMAGE_FILE_MACHINE_ARM64
        default { throw ("no PE machine type for architecture '{0}' (known: x64, arm64)" -f $Arch) }
    }
}

# Reads the COFF machine field: offset 0x3C holds the PE header offset, the signature
# follows it, and the machine is the 2 bytes after the signature. 0x8664 = x64,
# 0xAA64 = ARM64.
function Get-PeMachine {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) { throw "no such file: $Path" }
    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
    try {
        if ($stream.Length -lt 0x40) { throw ("{0} is too short to be a PE image" -f $Path) }
        $reader = New-Object IO.BinaryReader($stream)
        $stream.Position = 0x3C
        $peOffset = $reader.ReadInt32()
        if ($peOffset -le 0 -or ($peOffset + 6) -gt $stream.Length) {
            throw ("{0} has no usable PE header offset ({1})" -f $Path, $peOffset)
        }
        $stream.Position = $peOffset
        $signature = $reader.ReadUInt32()
        if ($signature -ne 0x00004550) {
            throw ("{0} carries no PE signature at {1} (read 0x{2:X8})" -f $Path, $peOffset, $signature)
        }
        return [int]$reader.ReadUInt16()
    } finally {
        $stream.Dispose()
    }
}

# Which release archive this host should install.
#
#   arm64 host: the arm64 archive; if the release has none, the x64 one WITH a warning,
#               because Windows 11 on ARM runs x64 binaries under emulation.
#   x64 host:   the x64 archive only. An ARM64 binary cannot run on an x64 host, so
#               arm64 is never selected there - not even as a fallback.
#   no match:   $null. The caller decides how to fail; guessing here would install
#               bytes this machine cannot execute.
#
# Returns the asset NAME (not a path or an object) so both the installer and the tests
# can call it with nothing but a list of names from the release API.
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
