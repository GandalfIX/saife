# BUILD-BASE-IMAGE — disposable test-VM base-image runbook (`sbx-base-a`, `sbx-base-b`)

> **VM-01, Task 2 (image A) / Task 6 (image B).** One-time, **manual**
> runbook per image. Fully automated
> ISO→image builds are a documented non-goal for v1 (see
> `docs/superpowers/plans/2026-10-04-vm-test-infrastructure.md`); likewise
> unattended Windows Setup and CredSSP. The template is only ever **cloned**
> (differencing VHDX per run), never booted directly and never reused as a
> daily driver — so **no sysprep** is performed.

**Image roles.** Two templates exist, each built from its own ISO:

- **`sbx-base-a`** (current AppContainer suite) — installed from the
  Dev Channel ISO (build 26340); see the [Current image](#current-image)
  section.
- **`sbx-base-b`** (WBD R0 discovery / MXC lane, VM-01 Task 6) — built
  from the Experimental Future Platforms ISO `29680_1000.iso` with the
  pinned MXC checkout added; see
  [Image B](#image-b-sbx-base-b--wbdmxc-discovery-vm-01-task-6) below.
  Same clone-only rules apply.

> **Hyper-V command caveat:** the Hyper-V module cannot be imported in a
> non-elevated shell on the dev host, so the commands below could not be
> syntax-checked with `Get-Command`. Commands marked **verify at image-build
> time** should be double-checked against `Get-Help <cmdlet>` if one of
> them errors.

---

## One-command build (recommended)

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File tests\vm\Build-BaseImage.ps1
```

`tests\vm\Build-BaseImage.ps1` drives the ENTIRE runbook interactively,
asking only for what it needs at each point:

1. **Phase 1** runs `New-BuilderVM.ps1` (probe, configuration questions,
   confirmation; creates and starts the builder VM with vTPM).
2. **Phase 2** opens the VM console and prompts you to install Windows
   manually (this is the only manual work — unattended installs are a
   documented non-goal). You come back and press Enter when done; it then
   collects the guest credential and verifies PowerShell Direct.
3. **Phase 3** runs `Copy-RepoToVM.ps1` (Guest Service, staging, zip,
   single copy, expand, count verification).
4. **Phase 4** runs `prepare-guest.ps1` in the guest (30–60 min), with a
   reboot-and-retry loop for reboot-pending VS installs, and verifies
   pwsh.
5. **Phase 5** runs `Export-BaseImage.ps1` (Steps 4–5 below plus the
   current-image record) and finishes with the readiness probe.

The guest credential is asked once and passed in-process; it is never
printed. Re-runs are safe — every phase is idempotent or state-checking.

The step-by-step sections below remain the manual alternative and the
reference for what the scripts do.

---

## Step 0 — Prereqs and configuration

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
   [Current image](#current-image) section at the end (with the wrapper
   it is also preserved in `tests\vm\build-config.json`).

**Recommended: let the wrapper do Steps 0-1** —

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File tests\vm\New-BuilderVM.ps1
```

The interactive wrapper (`tests\vm\New-BuilderVM.ps1`):

- runs the readiness probe first (fail-closed: a non-elevated shell or
  missing Hyper-V tools aborts immediately; a `NOT READY` for the missing
  template/`vm-settings.json` is **expected** before the first build and
  only blocks when no virtual switch exists),
- asks for the values below (defaults where sensible) and stores them in
  `tests\vm\build-config.json` — machine-local and gitignored; an existing
  file is used directly, edit or delete it to change values,
- shows all values including the derived VHDX path for confirmation
  (decline aborts cleanly with no changes), then creates `vmDir` and the
  builder VM (Step 1) and starts it,
- is idempotent: an already-existing builder VM is reported, not
  recreated.

Then continue with [Step 2 — Install Windows](#step-2--install-windows-manual).

**Manual alternative:** set these once and copy-paste the blocks in order
(the wrapper stores exactly these values, so both paths stay equivalent):

```powershell
# Adjust to your machine, then keep this shell for all steps below.
$repoRoot = 'C:\Users\marku\tools\sandbox'   # the sandbox tool's repo root
$vmName   = 'sbx-base-a-builder'
$isoPath  = '<path-to-iso>'                  # exact path of the downloaded ISO
$vmDir    = 'D:\hyper-v'                     # drive with ~150 GB free
$diskPath = Join-Path $vmDir "$vmName.vhdx"
```

## Step 1 — Create the builder VM (manual path only)

> Skipped if you used `New-BuilderVM.ps1` in Step 0 — the wrapper performs
> this step (plus creating `$vmDir`).

```powershell
New-VM -Name $vmName -Generation 2 -MemoryStartupBytes 8GB -NewVHDPath $diskPath -NewVHDSizeBytes 127GB
Set-VM -Name $vmName -ProcessorCount 4
# vTPM (fresh VM, not yet started): local key protector first, then the virtual TPM.
Set-VMKeyProtector -VMName $vmName -NewLocalKeyProtector
Enable-VMTPM -VMName $vmName
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

The VM must be **RUNNING**. Two prerequisites this step depends on:

- the Hyper-V **Guest Service** integration service must be enabled
  (`Copy-VMFile` refuses to work without it), and
- the guest credential (account created during Windows Setup).

**Recommended: let the wrapper do the host half** —

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File tests\vm\Copy-RepoToVM.ps1
```

The interactive wrapper (`tests\vm\Copy-RepoToVM.ps1`) loads the values
saved by `New-BuilderVM.ps1` (`tests\vm\build-config.json`), verifies the
VM is running, **enables the Guest Service** (idempotent), asks for the
guest credential via `Get-Credential`, stages and zips the repo with the
exclusions below, performs the single `Copy-VMFile`, expands and verifies
the copy by file count — then prints the exact `prepare-guest.ps1`
command to run next. Continue with the provisioning command under
[Run provisioning](#run-provisioning) below.

**Manual alternative** — the same operations spelled out. Get the guest
credential once:

```powershell
$cred = Get-Credential -UserName 'sbxadmin' -Message 'Guest password for sbx-base-a-builder'
```

Enable the Guest Service (idempotent; required by `Copy-VMFile`):

```powershell
$vm = Get-VM $vmName
Get-VMIntegrationService -VM $vm |
  Where-Object Id -like '*6C09BB55-D683-4DA0-8931-C9BF705F6480*' |
  Enable-VMIntegrationService
```

Stage the repo on the host, excluding `target\` and `.git` (git is not
needed inside the image):

```powershell
$stage = Join-Path $env:TEMP 'sbx-repo-stage'
if (Test-Path $stage) { Remove-Item -LiteralPath $stage -Recurse -Force }
robocopy $repoRoot $stage /E /XD target .git vms results templates /XF vm-settings.json
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
# Guest: expand (single PS Direct session; remove a stale C:\sbx-repo
# first so re-runs stay idempotent and the count check stays meaningful).
Invoke-Command -VMName $vmName -Credential $cred -ScriptBlock {
    if (Test-Path -LiteralPath 'C:\sbx-repo') { Remove-Item -LiteralPath 'C:\sbx-repo' -Recurse -Force }
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

### Run provisioning

**Chicken-and-egg:** on the first pass pwsh is not
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

> **Recommended:** `tests\vm\Export-BaseImage.ps1` (or the overall
> `Build-BaseImage.ps1`, phase 5) performs Steps 4–5 below plus the
> current-image collection — it asks for the template name, writes
> `vm-settings.json` from the credential you already entered (after
> confirmation, password never printed), takes the checkpoint, stops the
> VM, copies + hashes the template and runs the readiness probe. The
> blocks below are the manual alternative.

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
OS build here) — `Export-BaseImage.ps1` prints this table ready-to-paste
with all values collected automatically:

| Field                 | Value |
|-----------------------|-------|
| Template name         | sbx-base-b.vhdx |
| Template size (GB)    | 24,19 |
| Edition (Caption)     | Microsoft Windows 11 Enterprise Insider Preview |
| OS build (BuildNumber)| 29680 |
| ISO path             | C:\Users\marku\Downloads\Windows11_InsiderPreview_EnterpriseVL_x64_en-gb_29680_1000.iso |
| Secure boot           | On |
| Template SHA256       | 095F62F20ED753CD75DDC2D7E98E0622B592973167474AEBDAC07BF4979B3AE3 |
| Build date            | 2026-10-13 |

Collect guest values (PowerShell Direct needs the VM RUNNING again, so
start it first; if it just booted, retry after a few seconds):

```powershell
Start-VM -Name $vmName
Invoke-Command -VMName $vmName -Credential $cred -ScriptBlock {
    Get-CimInstance Win32_OperatingSystem | Select-Object Caption, BuildNumber
}
```

### Image B record (`sbx-base-b`) — fill in after the build

`Export-BaseImage.ps1` prints most of this table ready-to-paste; the
MXC fields come from `C:\mxc\mxc-build.json` inside the image
(collect them the same way, with the VM running).

| Field            | Value |
|------------------|-------|
| Template name    | sbx-base-b.vhdx |
| Edition (Caption)| Microsoft Windows 11 Enterprise Insider Preview |
| OS build (BuildNumber) | 29680 |
| ISO path         | C:\Users\marku\Downloads\Windows11_InsiderPreview_EnterpriseVL_x64_en-gb_29680_1000.iso |
| Secure boot      | On |
| Template size (GB) | 25.44 |
| MXC commit       | 5d7a475 (5d7a475a9fd5626bafb55c2c857989d2e5621245) |
| wxc-exec.exe SHA256 | 3FD125498803970B3FC7E63FC36307DD7A3186318FA02B83034F141731006DAC |
| wxc-exec version | 1.0.0+5d7a475a |
| Template SHA256  | 95DAEA358027DF148620B71E247BD316632E83467E2E7A976317F4BBE202F5BE |
| Build date       | 2026-10-13 |

> **Re-pin re-bake (2026-10-13, supersession):** the WBD D-02 entry point
> (`tests\scripts\run_processcontainer_probes_test.ps1 -RequireTier`) only
> exists upstream since `e4619e7f` (2026-09-22 suite split), so the maintainer
> re-pinned image B from `e7940f7` to `5d7a475a9fd56…` (see
> `docs/mxc-source-analysis.md`, "Pin decision (2026-10-13)"). This re-bake
> **supersedes the first export** (template SHA256
> `FD24D717FAA155724BFF8A3C7993390F7CE122BCD404A6678E805B8E08EE944D`,
> 23.72 GB, wxc-exec 0.8.0+e7940f7c): the old template file was overwritten
> in place by the export's overwrite prompt. The builder VM's first-pin
> checkpoint `sbx-base-b-clean` was removed after `MXC PREPARED` and
> re-taken by the export at the new pin. Evidence runs before 2026-10-13
> (results `20261013-142920-051`, `20261013-150837-253`) refer to the
> superseded pin; their D-01 baseline facts remain valid (same OS build).

> **Export note (2026-10-13, superseded by the re-pin re-bake above):** the
> first export ran twice (template-name prompt answered `sbx-base-b`, then
> `sbx-base-b-clean`), both after `MXC PREPARED` — same guest state, two
> physical files. Kept the recorded 23.72 GB template (hash-verified) and
> renamed it `sbx-base-b-clean.vhdx` → `sbx-base-b.vhdx` to match the harness
> contract; the duplicate was deleted. The stray second checkpoint
> `sbx-base-b-clean-clean` this produced was removed before the re-pin
> re-bake.

## Image B (`sbx-base-b`) — WBD/MXC discovery (VM-01 Task 6)

Purpose: the WBD R0 discovery lane — D-01/D-02 first evidence capture on
the Experimental Future Platforms build. Everything in Steps 0-5 above is
**identical** except for the values below; `Build-BaseImage.ps1`'s phase
flow is reused unchanged.

**ISO (decision 2026-10-12):**
`Windows11_InsiderPreview_EnterpriseVL_x64_en-gb_29680_1000.iso` —
accepted in place of the originally pinned `29671.1000` (a superseded
flight of the same channel; recorded in impact-analysis D3 and the VM-01
plan Task 6). Per the WBD, the capability probes — never the build
number — are the authoritative evidence.

Differences from the image-A build:

1. **`build-config.json` is single-image** (machine-local, gitignored).
   Move the image-A config aside first, then run `New-BuilderVM.ps1` and
   answer with the image-B values:

   ```powershell
   Rename-Item tests\vm\build-config.json build-config.base-a.json
   pwsh -NoProfile -ExecutionPolicy Bypass -File tests\vm\New-BuilderVM.ps1
   ```

   - vmName: `sbx-base-b-builder` (still outside `Remove-TestVM.ps1`'s
     `sbx-test-` allow-list)
   - isoPath: the 29680 ISO above
   - vmDir / repoRoot: unchanged

   Keep whichever config matches the image you re-bake next; values are
   trivially re-entered.
2. **Guest credential:** use the SAME `sbxadmin` password as image A so
   the shared `tests\vm\vm-settings.json` serves both images.
3. **Extra provisioning step** — run after `prepare-guest.ps1` (which
   installs git + rustup + the MSVC toolchain), before the export:

   ```powershell
   Invoke-Command -VMName sbx-base-b-builder -Credential $cred -ScriptBlock {
       pwsh -NoProfile -ExecutionPolicy Bypass -File C:\sbx-repo\tests\vm\prepare-mxc.ps1
       if ($LASTEXITCODE -ne 0) { throw "prepare-mxc.ps1 failed (exit $LASTEXITCODE)" }
   }
   ```

    `prepare-mxc.ps1` clones `microsoft/mxc` to `C:\mxc`, checks out the
    pinned commit `5d7a475a9fd5626bafb55c2c857989d2e5621245` (the image-B
    pin re-decided 2026-10-13; recorded in `docs/mxc-source-analysis.md`,
    "Pin decision (2026-10-13)" — the script default matches), runs
    `cargo build --release` in the workspace, and records the `wxc-exec.exe`
    SHA256 + VersionInfo in `C:\mxc\mxc-build.json`. Because the build is
    whole-workspace, the upstream suite's sidecar binaries (`plm.exe`,
    `winhttp-proxy-shim.exe`) land beside `wxc-exec.exe` for free
    (observed run `20261013-220007-020`); only the debug lane is absent,
    which the capture script's context redirect handles. It never runs
    `wxc-host-prep` (a WBD stop signal) and launches no workload. Expect
    the build to take a while on first run (fresh cargo cache inside the
    image).
    > **Stale guest copy caveat:** `C:\sbx-repo` inside the *builder* VM is
    > only refreshed by an explicit repo copy — a plain re-bake does NOT
    > update it. The 2026-10-13 re-pin re-bake ran with `-Commit
    > 5d7a475a9fd5626bafb55c2c857989d2e5621245` passed explicitly because
    > the guest copy predates the new default; after the NEXT
    > `Copy-RepoToVM.ps1` push to the builder, the bare command above is
    > correct again. If in doubt, always pass `-Commit` explicitly.
4. **Export:** `Export-BaseImage.ps1` asks for the template name —
   answer `sbx-base-b`. The re-bake checkpoint is derived from it
   (`sbx-base-b-clean`). `Initialize-VMHost.ps1` must then print
   `READY: sbx-base-b.vhdx`.

**Evidence-capture lane (the point of image B):**

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File tests\vm\Invoke-TestsInVM.ps1 -Image sbx-base-b -TestCmd "pwsh -NoProfile -ExecutionPolicy Bypass -File C:\sbx-repo\tests\vm\wbd-d01-d02-probes.ps1"
```

`wbd-d01-d02-probes.ps1` captures the WBD D-01 baseline (edition/build,
architecture, isolation-relevant optional features, MXC commit,
`wxc-exec.exe` hash/version, elevation state, `--probe` and `--version`
output verbatim with exit codes) plus the D-02 upstream probe test
(`run_processcontainer_probes_test.ps1 -RequireTier base-container`), and
writes `wbd-d01-baseline.json`, the raw logs and a SHA256 artifact
manifest into `C:\sbx-results`; the harness fetches everything into
`tests\vm\results\<runid>\` and destroys the VM. `--probe` may perform
MXC stale-DACL recovery before capability detection (a security-state
operation, recorded in the baseline) — which is exactly why it only ever
runs inside disposable clones.

D-02 binary contract (2026-10-13): upstream standalone area runs
require a debug-lane `wxc-exec.exe` and `plm.exe` /
`winhttp-proxy-shim.exe` sidecars beside each lane (Common.ps1
`Initialize-WpcContext`), but `prepare-mxc.ps1` builds the release lane
only. The capture script satisfies the contract in the disposable VM: it
builds the two sidecar crates (release lane, warm cargo cache) if
missing and passes a context JSON (`d02-wpc-context.json`, itself a
fetched artifact) that redirects the debug lane at the pinned release
binary — the upstream-documented override mechanism — plus
`-SkipNetwork` (the probes phase is read-only; no dependency on VM NAT
reachability) and `-ResultsJson` so the upstream suite's own
machine-readable results land in the fetched artifact set. If the image
is ever re-provisioned to build the full artifact set natively (debug
lane + sidecars, dedicated-runner Q-01 track), the capture script's
idempotency check skips the build and the context redirect stays
harmless.

**Scope guard (VM-01 Task 6):** this lane is evidence capture only. Do
not build product code from this evidence until the impact-analysis §5
decisions are recorded.

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
  releases, Python from `https://www.python.org/downloads/` — machine-wide:
  `/quiet InstallAllUsers=1 PrependPath=1`), then re-run
  `prepare-guest.ps1` to verify everything is present. The script never
  hand-rolls MSI downloads.
- **Python scenarios fail with `exit=9009` / "Python wurde nicht gefunden"**
  — the image has no real Python, only the Microsoft Store execution
  alias, which degrades to the "Python was not found" stub for
  AppContainer callers (see
  `docs/bugs/2026-08-15-python-store-alias-unusable-in-appcontainer.md`).
  `prepare-guest.ps1` installs a real machine-wide Python on the machine
  PATH (shadowing the alias); a missing/failed install is caught at bake
  time by the `Test-RealPythonAvailable` gate, which deliberately does
  NOT accept the WindowsApps alias as "installed".
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
- **`New-BuilderVM.ps1` refuses an unusable configuration** ("configuration
  in ... is unusable") — a value saved in `tests\vm\build-config.json` no
  longer holds (typically the ISO was moved or deleted, or `repoRoot`
  points elsewhere). Edit or delete the file and re-run; the wrapper
  re-asks for values.
- **`New-BuilderVM.ps1`: "VHDX path already occupied"** — a previous
  partial run left `<vmDir>\<name>.vhdx` on disk. Delete it (or pick a
  different VM name) and re-run.
- **robocopy "failed"** — robocopy exit codes 0–7 are success (1 = files
  copied); only ≥ 8 is an error.
- **`prepare-mxc.ps1` exits 4 (commit unreachable / dirty tree)** — the
  upstream history was rewritten, or the checkout has local changes
  (never reset by the script). Record the new pin decision in
  `docs/mxc-source-analysis.md` first, then re-run with
  `-Commit <new-pin>`.
- **`prepare-mxc.ps1` exits 5 (cargo build)** — same toolchain causes as
  the prepare-guest cargo warm-up (see above); the full build log is at
  `C:\mxc\mxc-build.log` inside the VM.
- **`prepare-mxc.ps1` exits 6 (`wxc-exec.exe` missing)** — the pinned
  workspace built without producing the release executor; check
  `C:\mxc\mxc-build.log` and the pinned layout assumptions in the
  script.
