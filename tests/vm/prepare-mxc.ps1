#Requires -Version 7
<#
.SYNOPSIS
  Guest-side MXC provisioning for base image B (VM-01 Task 6).
.DESCRIPTION
  Runs INSIDE the image-B builder VM, after prepare-guest.ps1 (this script
  needs git + cargo + the MSVC toolchain). Idempotent - safe to re-run:

    1. Elevation gate (C:\mxc needs admin; nothing runs before it).
    2. Tool gate: git AND cargo must be on PATH, else exit 3 with the
       remediation (run prepare-guest.ps1 first). No silent degradation.
    3. Clone microsoft/mxc to -MxcRoot if absent; otherwise reuse the
       existing checkout. A dirty tree is NEVER reset - abort loudly
       instead (the operator decides; a disposable VM makes this cheap,
       but no script in this repo destroys state unasked).
    4. Check out the pinned -Commit (detached HEAD). If the commit is
       not found, one `git fetch origin <sha>` retry (GitHub serves
       arbitrary SHAs); still unreachable = exit 4.
    5. `cargo build --release` in <MxcRoot>\src (the pinned MXC Rust
       workspace; -SkipBuild skips for quick re-runs). Full build output
       goes to <MxcRoot>\mxc-build.log; failure tail is printed.
    6. Verify <MxcRoot>\src\target\release\wxc-exec.exe exists, record
       its SHA256 + VersionInfo + the pinned commit in
       <MxcRoot>\mxc-build.json, and print the record.

  The pinned default is the analyzed upstream commit recorded in
  docs/research/mxc-source-analysis.md (shallow clone 2026-09-16). Per the WBD,
  this script NEVER runs `wxc-host-prep` (flagged as a stop signal) and
  never launches a workload.

  Prints a final one-line verdict and exits:
    MXC PREPARED                       -> exit 0
    not elevated                       -> exit 2
    git/cargo missing                  -> exit 3 (remediation printed)
    clone/checkout failed (dirty tree,
    unreachable commit)                -> exit 4
    cargo build failed                 -> exit 5
    wxc-exec.exe missing after build    -> exit 6
    unexpected error                    -> exit 99
.PARAMETER MxcRoot
  Checkout location inside the VM. Default: C:\mxc (VM-01 Task 6).
.PARAMETER Commit
  Pinned upstream commit to check out. Default: 5d7a475a9fd5626bafb55c2c857989d2e5621245
  (the image-B pin re-decided 2026-10-13; see docs/research/mxc-source-analysis.md,
  "Pin decision (2026-10-13)").
.PARAMETER SkipBuild
  Skip the release build (quick re-runs; exit 6 is then reachable if
  the binary was never built).
.EXAMPLE
  pwsh -NoProfile -ExecutionPolicy Bypass -File C:\sbx-repo\tests\vm\prepare-mxc.ps1
  Provision C:\mxc in the image-B builder VM.
#>
[CmdletBinding()]
param(
    [string]$MxcRoot = 'C:\mxc',
    [string]$Commit = '5d7a475a9fd5626bafb55c2c857989d2e5621245',
    [switch]$SkipBuild
)

$ErrorActionPreference = 'Stop'

$windowsIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
$windowsPrincipal = New-Object Security.Principal.WindowsPrincipal($windowsIdentity)
if (-not $windowsPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host '[mxc-prep] not elevated - run from an elevated shell inside the VM (the PS Direct session is).' -ForegroundColor Red
    exit 2
}

foreach ($tool in @('git', 'cargo')) {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
        Write-Host "[mxc-prep] $tool is not on PATH - run tests\vm\prepare-guest.ps1 first (it installs git, rustup and the MSVC toolchain)." -ForegroundColor Red
        exit 3
    }
}

try {
    # --- Clone or reuse ----------------------------------------------------
    if (-not (Test-Path -LiteralPath $MxcRoot)) {
        Write-Host "[mxc-prep] cloning microsoft/mxc to $MxcRoot ..."
        git clone --quiet https://github.com/microsoft/mxc $MxcRoot
        if ($LASTEXITCODE -ne 0) {
            Write-Host "[mxc-prep] clone failed (exit $LASTEXITCODE) - check guest internet access (Default Switch)." -ForegroundColor Red
            exit 4
        }
    } elseif (-not (Test-Path -LiteralPath (Join-Path $MxcRoot '.git'))) {
        Write-Host "[mxc-prep] $MxcRoot exists but is not a git checkout - refusing to touch it; move it away and re-run." -ForegroundColor Red
        exit 4
    }

    Push-Location $MxcRoot
    try {
        $dirty = @(git status --porcelain)
        if ($dirty.Count -gt 0) {
            Write-Host "[mxc-prep] $MxcRoot is dirty ($($dirty.Count) changed path(s)) - aborting; a dirty pinned checkout is not valid image state. Reset manually if this throwaway VM's changes do not matter." -ForegroundColor Red
            exit 4
        }
        # Resolve the pinned -Commit to its FULL SHA once. git checkout and
        # rev-parse HEAD always report the 40-char form, so comparing either
        # against the literal parameter (a short prefix like 'e7940f7')
        # rejects validly pinned checkouts and re-enters the fetch path on
        # every idempotent re-run (2026-10-13 incident). --verify prints
        # NOTHING on stdout for unknown revisions, so an empty result
        # reliably means 'not present locally (yet)'.
        $commitFull = (git rev-parse --verify "$Commit^{commit}" 2>$null)
        if ($LASTEXITCODE -ne 0 -or -not $commitFull) {
            # Not present locally yet - one broad fetch, then one explicit
            # fetch of the SHA (GitHub serves arbitrary SHAs).
            git fetch --quiet origin
            if ($LASTEXITCODE -ne 0) { $null = git fetch --quiet origin $Commit 2>$null }
            $commitFull = (git rev-parse --verify "$Commit^{commit}" 2>$null)
        }
        if ($LASTEXITCODE -ne 0 -or -not $commitFull) {
            Write-Host "[mxc-prep] pinned commit $Commit is not reachable in the upstream repository - the history may have been rewritten. Record the new pin decision in docs/research/mxc-source-analysis.md, do not guess." -ForegroundColor Red
            exit 4
        }
        $head = (git rev-parse HEAD 2>$null)
        if ($head -ne $commitFull) {
            # Idempotence + offline tolerance: skip the fetch round-trip
            # entirely when the pinned commit is already checked out.
            git -c advice.detachedHead=false checkout --quiet $commitFull
            if ($LASTEXITCODE -ne 0) {
                git fetch --quiet origin $Commit
                if ($LASTEXITCODE -eq 0) {
                    git -c advice.detachedHead=false checkout --quiet $commitFull
                }
            }
            if ($LASTEXITCODE -ne 0) {
                Write-Host "[mxc-prep] checkout of $commitFull failed (exit $LASTEXITCODE) - see the fetch messages above." -ForegroundColor Red
                exit 4
            }
        }
        $pinned = (git rev-parse HEAD)
        if ($pinned -ne $commitFull) {
            Write-Host "[mxc-prep] checkout landed on $pinned instead of $commitFull - refusing to continue." -ForegroundColor Red
            exit 4
        }
        Write-Host "[mxc-prep] checkout at pinned commit: $pinned"

        # --- Release build ----------------------------------------------------
        $workspaceDir = Join-Path $MxcRoot 'src'
        if (-not (Test-Path -LiteralPath (Join-Path $workspaceDir 'Cargo.toml'))) {
            Write-Host "[mxc-prep] no Cargo.toml under $workspaceDir - the pinned workspace layout no longer matches the documented one (<MxcRoot>\src); update this script together with the new pin decision." -ForegroundColor Red
            exit 4
        }
        $wxcExec = Join-Path $workspaceDir 'target\release\wxc-exec.exe'
        if (-not $SkipBuild) {
            Write-Host '[mxc-prep] cargo build --release (this can take a while on first run) ...'
            $buildLog = Join-Path $MxcRoot 'mxc-build.log'
            # Full build output goes to the log; only the verdict and the
            # failure tail reach the console.
            Push-Location $workspaceDir
            try {
                cargo build --release 2>&1 | Tee-Object -FilePath $buildLog | Out-Null
                $buildExit = $LASTEXITCODE
            } finally {
                Pop-Location
            }
            if ($buildExit -ne 0) {
                Write-Host "[mxc-prep] cargo build --release failed (exit $buildExit) - tail of $buildLog :" -ForegroundColor Red
                Get-Content -LiteralPath $buildLog -Tail 25 | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
                exit 5
            }
        }
        if (-not (Test-Path -LiteralPath $wxcExec)) {
            Write-Host "[mxc-prep] $wxcExec does not exist - the workspace built without producing the release executor; check $MxcRoot\mxc-build.log." -ForegroundColor Red
            exit 6
        }

        # --- Record ------------------------------------------------------------
        $item = Get-Item -LiteralPath $wxcExec
        $hash = (Get-FileHash -LiteralPath $wxcExec -Algorithm SHA256).Hash
        $record = [ordered]@{
            schema      = 1
            mxcCommit   = $pinned
            wxcExec     = $wxcExec
            wxcExecSize = $item.Length
            wxcExecSha256 = $hash
            fileVersion = $item.VersionInfo.FileVersion
            productVersion = $item.VersionInfo.ProductVersion
            builtAt     = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ssK')
            osBuild     = [System.Environment]::OSVersion.Version.ToString()
            built       = (-not $SkipBuild)
        }
        $recordPath = Join-Path $MxcRoot 'mxc-build.json'
        $record | ConvertTo-Json | Set-Content -LiteralPath $recordPath -Encoding utf8
        Write-Host "[mxc-prep] wxc-exec.exe SHA256: $hash"
        Write-Host "[mxc-prep] build record:        $recordPath"
    } finally {
        Pop-Location
    }

    Write-Host 'MXC PREPARED' -ForegroundColor Green
    exit 0
} catch {
    Write-Host "[mxc-prep] unexpected error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host 'MXC PREP FAILED' -ForegroundColor Red
    exit 99
}
