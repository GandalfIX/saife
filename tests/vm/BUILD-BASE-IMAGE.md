# BUILD-BASE-IMAGE — disposable test-VM base image (`sbx-base-a`) runbook

> **VM-01, Task 2.** One-time, **manual** runbook. Fully automated
> ISO→image builds are a documented non-goal for v1 (see
> `docs/superpowers/plans/2026-10-04-vm-test-infrastructure.md`); likewise
> unattended Windows Setup and CredSSP. The template is only ever **cloned**
> (differencing VHDX per run), never booted directly and never reused as a
> daily driver — so **no sysprep** is performed.

**Image role.** The downloaded ISO is the insider/experimental build that
also serves the later MXC discovery track: **one image serves both tracks
initially** — base image A (current AppContainer suite) is built from it,
and the same template (or a derived one) later becomes image B by adding
the pinned `mxc/` checkout (plan Task 6). If the experimental build proves
too unstable for the AppContainer suite, add a stable-Windows template
later; the harness is image-agnostic.

> **Hyper-V command caveat:** the Hyper-V module cannot be imported in a
> non-elevated shell on the dev host, so the commands below could not be
> syntax-checked with `Get-Command`. Commands marked **verify at image-build
> time** should be double-checked against `Get-Help <cmdlet>` if one of
> them errors.

---

## Step 0 — Prereqs

Run everything below from an **elevated pwsh on the host**.

1. **Hyper-V management tools** —
   `pwsh -NoProfile -ExecutionPolicy Bypass -File tests\vm\Initialize-VMHost.ps1`
   must print `Hyper-V management tools present.` (The template and
   `vm-settings.json` checks report `NOT READY` until this runbook is
   finished — that is expected.)
2. **Disk space** — ~150 GB free on the drive that will hold the builder
   VM (up to 127 GB VHDX) plus the template copy.
3. **ISO** — the downloaded insider ISO. Record the exact path now; the
   operator records the exact ISO and resulting OS build in the
   [Current image](#current-image) section at the end.

Set these once and copy-paste the blocks in order:

```powershell
# Adjust to your machine, then keep this shell for all steps below.
$repoRoot = 'C:\Users\marku\tools\sandbox'   # the sandbox tool's repo root
$vmName   = 'sbx-base-a-builder'
$isoPath  = '<path-to-iso>'                  # exact path of the downloaded ISO
$vmDir    = 'D:\hyper-v'                     # drive with ~150 GB free
$diskPath = Join-Path $vmDir "$vmName.vhdx"
```

## Step 1 — Create the builder VM

```powershell
New-VM -Name $vmName -Generation 2 -MemoryStartupBytes 8GB -NewVHDPath $diskPath -NewVHDSizeBytes 127GB
Set-VM -Name $vmName -ProcessorCount 4
# Optional: fix memory instead of dynamic (verify at image-build time):
# Set-VM -Name $vmName -StaticMemory
Add-VMDvdDrive -VMName $vmName -Path $isoPath
Connect-VMNetworkAdapter -VMName $vmName -SwitchName 'Default Switch'
# Boot the ISO before the (empty) VHDX (verify at image-build time):
Set-VMFirmware -VMName $vmName -FirstBootDevice (Get-VMDvdDrive -VMName $vmName)
Start-VM -Name $vmName
```

**Secure boot:** try booting **with** secure boot on (the default; Gen 2).
ONLY if the experimental build fails to boot with it on (boot loop /
`Secure Boot violation` on the VM console):

```powershell
Set-VMFirmware -VMName $vmName -EnableSecureBoot Off
```

Record the choice (on/off) in [Current image](#current-image). The builder
VM name `sbx-base-*` is outside `Remove-TestVM.ps1`'s `sbx-test-` allow-list,
so the rollback script never touches it.

## Step 2 — Install Windows (manual)

Open the VM console and walk through Windows Setup **manually**:

```powershell
vmconnect.exe $env:COMPUTERNAME $vmName
```

- Recommended local account name: **`sbxadmin`** (make it an administrator).
- The account **must have a non-empty password** — PowerShell Direct refuses
  blank-password logons. Do not reuse a real password of yours.
- Complete first logon at least once (PowerShell Direct needs no interactive
  logon afterwards).

## Step 3 — Copy the repo and run provisioning (PowerShell Direct, from the host)

The VM must be **RUNNING**. Get the guest credential once:

```powershell
$cred = Get-Credential -UserName 'sbxadmin' -Message 'Guest password for sbx-base-a-builder'
```

Stage the repo on the host, excluding `target\` and `.git` (git is not
needed inside the image):

```powershell
$stage = Join-Path $env:TEMP 'sbx-repo-stage'
if (Test-Path $stage) { Remove-Item -LiteralPath $stage -Recurse -Force }
robocopy $repoRoot $stage /E /XD target .git
if ($LASTEXITCODE -ge 8) { throw "robocopy failed ($LASTEXITCODE)" }   # robocopy 0-7 = success (1 = files copied)
```

> **Why one archive, not per-file copies:** `Copy-VMFile` moves a single
> file per call. Copying a repo tree file-by-file would open thousands of
> PowerShell Direct sessions, cannot resume after a transient failure, and
> a failed `Copy-VMFile` does not raise an error under the default
> `EAP Continue` — missing files would only surface later as a confusing
> cargo failure at bake time. One archive = one PS Direct session,
> restartable, and verifiable by file count.

Compress the staging tree (contents only — no top-level folder), copy ONE
file, expand it in the guest (one session), then verify the copy by file
count (one session):

```powershell
# Host: count + compress + single-file copy.
$stageCount = @(Get-ChildItem -LiteralPath $stage -Recurse -File).Count
$zipPath = Join-Path $env:TEMP 'sbx-repo.zip'
if (Test-Path -LiteralPath $zipPath) { Remove-Item -LiteralPath $zipPath -Force }
Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $zipPath -Force
Copy-VMFile -Name $vmName -SourcePath $zipPath -DestinationPath 'C:\sbx-repo.zip' -FileSource Host -Force
```

> **Archive caveat:** `Compress-Archive` can be slow on large trees, and
> older Windows PowerShell 5.1 versions fail past 2 GB. If it struggles,
> use the built-in bsdtar instead (ships with Windows 10+); the guest can
> keep using `Expand-Archive` (it reads bsdtar zips) or `tar -xf`:
>
> ```powershell
> # Host: tar -a -c -f $zipPath -C $stage .
> # Guest: replace Expand-Archive in the session below with: tar -xf C:\sbx-repo.zip -C C:\sbx-repo
> ```

```powershell
# Guest: expand (single PS Direct session).
Invoke-Command -VMName $vmName -Credential $cred -ScriptBlock {
    Expand-Archive -Path 'C:\sbx-repo.zip' -DestinationPath 'C:\sbx-repo' -Force
    Remove-Item -LiteralPath 'C:\sbx-repo.zip' -Force
}

# Guest: end-of-copy verification against the host-side staging count
# (single PS Direct session; loud failure instead of a silent gap).
Invoke-Command -VMName $vmName -Credential $cred -ScriptBlock {
    param($expected)
    $actual = @(Get-ChildItem -LiteralPath 'C:\sbx-repo' -Recurse -File).Count
    if ($actual -ne $expected) {
        throw "repo copy verification FAILED: expected $expected files under C:\sbx-repo, found $actual - re-run the copy step"
    }
    Write-Host "repo copy verified: $actual of $expected files present"
} -ArgumentList $stageCount
```

Run provisioning. **Chicken-and-egg:** on the first pass pwsh is not
installed inside the guest yet, so run `prepare-guest.ps1` once under
**Windows PowerShell 5.1** (it is 5.1-compatible and installs pwsh):

```powershell
Invoke-Command -VMName $vmName -Credential $cred -ScriptBlock {
    powershell -NoProfile -ExecutionPolicy Bypass -File C:\sbx-repo\tests\vm\prepare-guest.ps1 -RepoDir C:\sbx-repo
    if ($LASTEXITCODE -ne 0) { throw "prepare-guest.ps1 failed (exit $LASTEXITCODE)" }
}
```

Then **verify `pwsh` exists** (later passes and `run-in-vm.ps1` need it):

```powershell
Invoke-Command -VMName $vmName -Credential $cred -ScriptBlock {
    pwsh -NoProfile -Command '$PSVersionTable.PSVersion.ToString()'
}
```

Notes:

- This step takes a long time (VS Build Tools alone: 10–30+ minutes; plus
  the cargo warm-up). Expect the whole step to run 30–60 minutes.
- `prepare-guest.ps1` is idempotent; re-running with
  `-SkipCargoWarmup` is a quick way to verify idempotence.
- Success is the line `GUEST PREPARED` (exit 0). Any other verdict means the
  bake failed — fix it here, at bake time, not at test time.

## Step 4 — Create `tests/vm/vm-settings.json` (host side)

Create `<repoRoot>\tests\vm\vm-settings.json` with EXACTLY this shape:

```json
{
  "schema": 1,
  "guestUser": "sbxadmin",
  "guestPassword": "<the password you typed during setup>"
}
```

> **Security note.** This file is machine-local and gitignored
> (`sandbox/.gitignore`) — never commit it, never echo its contents. A
> plaintext credential here is acceptable ONLY because the image is a
> disposable throwaway that is never exposed to any network beyond the
> Default Switch, and the password is used solely for PowerShell Direct
> over the VM bus. Do NOT reuse a real password.

## Step 5 — Template copy (plus re-bake checkpoint)

The VHDX **file copy** below becomes the immutable template; an optional
checkpoint taken first is the builder VM's re-bake restore point. The
builder VM itself stays untouched by the copy, so it can be kept for
re-bakes (revert to the checkpoint, re-run provisioning, refresh the
template copy):

```powershell
# Optional but recommended BEFORE stopping: the re-bake restore point.
Checkpoint-VM -Name $vmName -SnapshotName 'sbx-base-a-clean'
Stop-VM -Name $vmName
$templateDir  = Join-Path $repoRoot 'tests\vm\templates'
$templatePath = Join-Path $templateDir 'sbx-base-a.vhdx'
New-Item -ItemType Directory -Path $templateDir -Force | Out-Null
Copy-Item -LiteralPath $diskPath -Destination $templatePath
Get-FileHash -LiteralPath $templatePath -Algorithm SHA256
```

(The copy of a multi-GB VHDX takes a few minutes.)

**Keep the builder VM** and refresh the template copy after every re-bake
(checkpoint `sbx-base-a-clean` → revert → re-run `prepare-guest.ps1` →
Stop-VM → `Copy-Item` again). `Initialize-VMHost.ps1` must then list the
template and print `READY`:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File (Join-Path $repoRoot 'tests\vm\Initialize-VMHost.ps1')
```

Expected final line: `READY: sbx-base-a.vhdx` (exit 0).

## Current image

Fill in after the build (the operator records the exact ISO and resulting
OS build here):

| Field            | Value |
|------------------|-------|
| Template name    | sbx-base-a.vhdx |
| Edition (Caption)| _fill in_ |
| OS build (BuildNumber) | _fill in_ |
| ISO path         | _fill in_ |
| Secure boot      | on / off |
| Template SHA256  | _fill in (Get-FileHash output above)_ |
| Build date       | _fill in_ |

Collect guest values (PowerShell Direct needs the VM RUNNING again, so
start it first; if it just booted, retry after a few seconds):

```powershell
Start-VM -Name $vmName
Invoke-Command -VMName $vmName -Credential $cred -ScriptBlock {
    Get-CimInstance Win32_OperatingSystem | Select-Object Caption, BuildNumber
}
```

## Troubleshooting

- **Secure-boot boot loop / `Secure Boot violation`** — disable secure boot
  for this experimental image: `Set-VMFirmware -VMName $vmName -EnableSecureBoot Off`,
  record it in Current image.
- **`winget` missing on the experimental build** (`prepare-guest.ps1`
  exits 4 and prints remediation) — either install App Installer (winget)
  from its GitHub release (`https://github.com/microsoft/winget-cli/releases`,
  msixbundle + dependency .appx via `Add-AppxPackage`), or install the
  tools manually with their official installers (VS Build Tools
  bootstrapper `https://aka.ms/vs/17/release/vs_BuildTools.exe` with
  `--add Microsoft.VisualStudio.Workload.VCTools --includeRecommended`,
  rustup `https://rustup.rs`, PowerShell 7 and Git from their official
  releases), then re-run `prepare-guest.ps1` to verify everything is
  present. The script never hand-rolls MSI downloads.
- **PowerShell Direct `failed to connect to the guest`** — the VM must be
  **RUNNING** (`Start-VM -Name $vmName`); the guest must have completed
  first logon once; the credential is the guest-local account with a
  non-empty password.
- **`prepare-guest.ps1` exits 2 via PowerShell Direct** — the session was
  not elevated; open an elevated shell inside the guest console
  (`vmconnect.exe $env:COMPUTERNAME $vmName`) and run the script there.
- **Cargo warm-up failure** (`GUEST PREP FAILED: cargo warm-up ...`) —
  common causes: insufficient disk (check free space in the guest), missing
  Windows SDK / MSVC because the VS Build Tools install did not complete
  (re-run `prepare-guest.ps1`; verify with vswhere:
  `& "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe" -products * -requires Microsoft.VisualStudio.Workload.VCTools -property installationPath`),
  or the rustup toolchain missing (`rustup default stable-msvc`). A
  reboot-pending VS install (exit 3010) needs one VM reboot, then a re-run.
- **robocopy "failed"** — robocopy exit codes 0–7 are success (1 = files
  copied); only ≥ 8 is an error.
