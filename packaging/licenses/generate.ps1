#Requires -Version 7.0
<#
.SYNOPSIS
    Generates the two compliance artifacts from Cargo.lock.

.DESCRIPTION
    THIRD-PARTY-LICENSES.md (cargo about) and the per-architecture CycloneDX
    SBOMs (cargo cyclonedx) are generated, not written: the MIT, Apache-2.0,
    BSD, ISC, Unlicense and Unicode-3.0 licenses all require the license text
    and copyright notice to be reproduced in every distribution of the binary,
    and the EU Cyber Resilience Act requires a machine-readable SBOM for
    products with digital elements. The outputs are never hand-edited; when a
    build fails here, the fix is a deliberate change to
    packaging/licenses/about.toml (a new accepted license), not an edit of the
    artifact.

    Both tools must be on PATH; check-prereqs.ps1 reports them:
        cargo install cargo-about --locked --features cli
        cargo install cargo-cyclonedx --locked

.PARAMETER Version
    The product version from Cargo.toml; names the SBOM files.

.PARAMETER LicensesPath
    Output path for THIRD-PARTY-LICENSES.md.

.PARAMETER SbomDir
    Output directory for saife-<version>-sbom-<arch>.cdx.json.

.EXAMPLE
    pwsh -File packaging/licenses/generate.ps1 -Version 0.5.0 `
        -LicensesPath dist/THIRD-PARTY-LICENSES.md -SbomDir dist
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Version,
    [Parameter(Mandatory)][string]$LicensesPath,
    [Parameter(Mandatory)][string]$SbomDir
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)   # repository root

foreach ($tool in 'cargo-about', 'cargo-cyclonedx') {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
        throw "$tool is not on PATH. Install it with: cargo install $tool --locked$(if ($tool -eq 'cargo-about') { ' --features cli' })"
    }
}

# Windows targets only: what the shipped binaries contain. A crate that builds
# on unix only is never part of the product for a compliance file.
$targets = @('x86_64-pc-windows-msvc', 'aarch64-pc-windows-msvc')

Push-Location $root
try {
    # Deterministic timestamps: cargo-cyclonedx honours SOURCE_DATE_EPOCH, so the
    # SBOM of one commit does not change on every rebuild (the serial number is
    # random either way; the timestamp is what makes two files diffable).
    if (-not $env:SOURCE_DATE_EPOCH) {
        $epoch = & git -C $root log -1 --format=%ct 2>$null
        if ($LASTEXITCODE -eq 0 -and $epoch) { $env:SOURCE_DATE_EPOCH = $epoch.Trim() }
    }

    Write-Host '== THIRD-PARTY-LICENSES.md (cargo about)'
    # --frozen: one Cargo.lock produces one license file; if the resolution
    # would touch the lockfile, stop instead of writing something else.
    & cargo-about generate `
        --config (Join-Path $PSScriptRoot 'about.toml') `
        --frozen `
        (Join-Path $PSScriptRoot 'about.hbs') `
        -o $LicensesPath
    if ($LASTEXITCODE -ne 0) {
        throw "cargo-about generate failed (exit $LASTEXITCODE). A dependency almost certainly carries a license outside `accepted` in packaging/licenses/about.toml - read it, then extend `accepted` deliberately. Never edit the .md by hand."
    }

    foreach ($target in $targets) {
        # The archive names use the short form: x64 | arm64.
        $short = if ($target.StartsWith('x86_64')) { 'x64' } else { 'arm64' }
        $name = "saife-$Version-sbom-$short.cdx.json"
        $out = Join-Path $SbomDir $name
        Write-Host "== $name (cargo cyclonedx, $target)"
        # Run through cargo: the bare cargo-cyclonedx binary is a dispatcher
        # that only accepts the `cyclonedx` subcommand, not the options.
        # --override-filename cannot be combined with --describe, so the file
        # is named by the tool after the package and moved into place below.
        & cargo cyclonedx `
            --manifest-path (Join-Path $root 'Cargo.toml') `
            --format json `
            --spec-version 1.6 `
            --target $target `
            --describe crate `
            --all
        if ($LASTEXITCODE -ne 0) {
            throw "cargo-cyclonedx failed for $target (exit $LASTEXITCODE)"
        }
        # The tool writes next to the manifest, not to an output path we choose.
        $written = @(Get-ChildItem $root -Filter '*.cdx.json' -File)
        if ($written.Count -ne 1) {
            throw "expected exactly one .cdx.json next to the manifest, found: $($written.Name -join ', ') - move the file explicitly"
        }
        if (Test-Path $out) { Remove-Item $out -Force }

        # Normalize before shipping. Cargo knows the crate as `sandbox`; the
        # product is `saife`. And the tool stamps every bom-ref with the ABSOLUTE
        # workspace path - a shipped artifact must not carry this machine's
        # directory layout, or two identical builds produce different files.
        # This is a rename, not an edit of the SBOM's content.
        $source = $written[0].FullName
        $bom = Get-Content $source -Raw | ConvertFrom-Json
        $bom.metadata.component.name = 'saife'
        $bom.metadata.component.purl = "pkg:cargo/saife@$Version"
        function Repair-Ref([object]$node) {
            if ($node -is [System.Array]) {
                foreach ($item in $node) { Repair-Ref $item }
            } elseif ($node -is [System.Management.Automation.PSCustomObject]) {
                foreach ($prop in $node.PSObject.Properties) {
                    if ($prop.Value -is [string]) {
                        $replacement = $prop.Value
                        # path+file:///C:/...#sandbox@0.5.0 bin-target-0 -> saife@0.5.0 bin-target-0
                        if ($replacement.StartsWith('path+file:///')) {
                            $replacement = $replacement -replace '^path\+file:///.*?#', ''
                        }
                        $prop.Value = $replacement -replace "sandbox@$Version", "saife@$Version"
                    } else {
                        Repair-Ref $prop.Value
                    }
                }
            }
        }
        Repair-Ref $bom | Out-Null
        $bom | ConvertTo-Json -Depth 100 | Set-Content -Path $out -NoNewline
        Remove-Item $source -Force
    }
} finally {
    Pop-Location
}
