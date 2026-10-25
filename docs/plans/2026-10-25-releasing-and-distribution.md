# Releasing and distributing SAIFE Sandbox — implementation plan

> **For Hermes:** use subagent-driven-development to implement this task-by-task.
> A phase is not "done" until its exit criteria have been *observed*, not assumed.

> **Status: PARKED 2026-10-25** at R0.1 + repo hygiene. Nothing published.
> Resume with the visibility decision (private repo on a free plan blocks winget
> and the security features), then R0.2. See `docs/tasks/release/PROGRESS.md`.

**Goal:** turn "a zip I can build and install locally" into a versioned, signed,
auto-published release that `winget install GandalfIX.SAIFE-Sandbox` can serve,
with every number derived from one source.

**Architecture:** `Cargo.toml` version → build (`build.rs` VERSIONINFO) →
`packaging/build-dist.ps1` produces the flat asset and its SHA256 →
`packaging/release.ps1` refuses a tag/version mismatch, publishes the GitHub
release and rewrites the winget manifests → a submitter opens the winget-pkgs PR.
CI runs the parts that GitHub's Windows runners can actually run; the VM lane
stays local because it needs Hyper-V.

**Tech stack:** Rust 2024, PowerShell 7 (packaging) / 5.1 (inside the sandbox),
GitHub Actions `windows-latest`, winget 1.30+, optional Azure Trusted Signing.

---

## Where we are (measured 2026-10-25)

- `Cargo.toml` says `version = "0.2.0"`; `src/cli.rs` hardcodes
  `"SAIFE Sandbox 0.2.0"` in a test, so the number exists twice already.
- `packaging/build-dist.ps1 -ReleaseVersion <v>` takes the version from the
  **command line**, and `dist/VERSION.txt` has no `version:` line at all.
- **No git tags.** `git tag | wc -l` → 0. No `CHANGELOG.md`.
- **No CI.** `.github/workflows/` does not exist.
- **No `build.rs`**, so `saife.exe` carries no FileVersion/ProductVersion —
  Explorer's Details tab and Add/Remove Programs would show nothing.
- **No `LICENSE`** in the repo, while the winget manifest says
  `License: Proprietary`. One of the two is wrong.
- `packaging/winget/*.installer.yaml` points at
  `https://github.com/GandalfIX/saife/releases/download/v0.2.0/saife-0.2.0-x64.zip`
  — a URL that 404s today, so a winget submission would validate and then fail
  at install time.
- Manifests are `PackageVersion: 0.2.0`, `MinimumOSVersion: 10.0.26100.0`,
  `InstallerType: zip` + `NestedInstallerType: portable`, alias `saife`.
- Versioning policy: `docs/design/versioning.md` (this plan implements it).

## Decisions needed before R1/R3 (blocking, cheap now, expensive later)

1. **Licence.** `Proprietary` with no LICENSE file is not a licence. Pick one:
   proprietary-with-EULA (then ship a `LICENSE.txt` and say so in the manifest),
   or an OSI one (MIT/Apache-2.0) — winget requires the manifest to match what
   the repository says. *Recommendation: decide before the first public tag; the
   winget PR reviewer will check.*
2. **Code signing.** Unsigned binaries trigger SmartScreen's "unknown publisher"
   on every first run. Options: Azure Trusted Signing (~/low monthly, needs an
   identity check), an OV certificate (annual, HSM-backed), or none for now.
   *Recommendation: R1 ships unsigned with a documented warning; signing becomes
   a 1.0 gate rather than a launch blocker.*
3. **First public version.** `0.3.0` (the `limits` move and the packaging fixes
   are already on `main` and are breaking, which under the policy is a MINOR in
   the 0.x era) — or call it `0.2.1` and pretend nothing broke. *Recommendation:
   `0.3.0`.*
4. **MSI/enterprise installer.** YAGNI unless someone needs Group Policy
   deployment. winget's portable install covers the personal-workstation case.
   *Recommendation: defer to R4, only on demand.*

---

## R0 — One version, in every place it is consumed

**Exit criteria:** `cargo test` fails if any version literal is wrong; the built
exe reports its version in Explorer; `dist/VERSION.txt` states it; the release
asset is named from it without a human passing a flag.

### Task R0.1 — Make the CLI test read the real version

**Files:** `src/cli.rs` (test `cli_identity_is_saife_sandbox_with_the_release_version`, ~line 815)

**Step 1:** change the assertion to build the expected string from
`env!("CARGO_PKG_VERSION")`, so a version bump cannot leave a stale literal.
**Step 2:** `cargo test --bin saife -- cli_identity` → PASS.
**Step 3:** prove the test still bites: temporarily set `version = "9.9.9"` in
`Cargo.toml`, run it, watch it FAIL for the right reason, revert.

### Task R0.2 — `VERSION.txt` states the version, and the asset is named from it

**Files:** `packaging/build-dist.ps1`

**Step 1:** derive `$version` from the built binary's product version (see R0.3)
or from `Cargo.toml` — never from a mandatory flag. Keep `-ReleaseVersion` as an
**override that must match**, and refuse when it does not.
**Step 2:** add `version:     <x.y.z>` as the first line of `VERSION.txt`.
**Step 3:** build twice, once with no flag and once with a wrong
`-ReleaseVersion 9.9.9`; expect a clear refusal in the second case.

### Task R0.3 — Windows VERSIONINFO on both binaries

**Files:** new `build.rs`, `Cargo.toml` (`[package]` `build = "build.rs"`,
`license`, `repository`, `authors`)

**Step 1:** generate a `.rc`/`winres` resource with `FileVersion` and
`ProductVersion` = `<major>.<minor>.<patch>.0`, `ProductName` = `SAIFE Sandbox`,
`CompanyName` = `GandalfIX`, `LegalCopyright`, and the product description.
**Step 2:** `cargo build --release --bin saife --bin saife-launch`.
**Step 3:** verify without opening Explorer:
`(Get-Item target\release\saife.exe).VersionInfo | Format-List FileVersion,ProductVersion,ProductName,CompanyName`
**Step 4:** note that a pre-release reports the numeric triple (see
`docs/design/versioning.md` §Windows resource version).

### Task R0.4 — The tag is the release, and it must agree

**Files:** new `packaging/release.ps1`

**Step 1:** the script reads `Cargo.toml` version and `git describe --tags
--exact-match`, and refuses unless they match `v<version>`.
**Step 2:** dry run on a scratch tag: `git tag v0.3.0-rc.test`, expect
`release.ps1 -DryRun` to pass, then a mismatched tag to fail. Delete the tag.
**Step 3:** the script prints the version, commit, hash and asset path it *would*
publish, and does nothing else under `-DryRun`.

### Task R0.5 — Retire the second hand-typed number

**Files:** `packaging/winget/*.yaml`, `packaging/winget-README.md`

**Step 1:** add a `-WhatIf`-style manifest rewrite to `release.ps1`
(`PackageVersion` in all three files + `InstallerSha256` + `InstallerUrl`).
**Step 2:** run it against a thrown-away copy; `winget validate --manifest` on
the result must pass.
**Step 3:** document in `packaging/winget-README.md` that manifests are generated,
and that hand edits will be overwritten.

---

## R1 — A release is a tag

**Exit criteria:** `git tag v0.3.0 && pwsh -File packaging/release.ps1` produces a
GitHub release with the asset, `SHA256SUMS.txt`, and a changelog section that
matches the tag; re-running it is refused.

### Task R1.1 — `CHANGELOG.md` in Keep-a-Changelog shape

Sections: `Added`, `Changed`, `Fixed`, `Security`, `Behaviour changes`,
`Breaking`. Write `0.3.0` from the actual commits (`git log --oneline
10624f1..HEAD`-style ranges), not from memory. `release.ps1` refuses to publish
without an `## [<version>]` heading.

### Task R1.2 — Release notes and asset set

Assets per release: `saife-<v>-x64.zip`, `SHA256SUMS.txt`,
`saife-<v>-x64.zip.sha256` (single-line, for the manifest), `VERSION.txt`.
Signing (if enabled) happens **before** zipping — see the anti-rule in the
versioning doc.

### Task R1.3 — Publish, then re-verify from the outside

`gh release create v0.3.0 …`, then in a **clean temp dir**: download the asset,
`Get-FileHash`, compare to `SHA256SUMS.txt`, `Expand-Archive`, run
`saife --version` and `saife run --allow-cwd -- cmd /c echo ok`. A release is not
published until a stranger's path works.

### Task R1.4 — Rehearsal on a throwaway tag

Do the whole R1 on `v0.3.0-rc.1` first, delete the release and tag, then repeat
for real. This is where the "wrong hash in the manifest" class of mistake gets
caught cheaply.

---

## R2 — Automation that can actually run

**Exit criteria:** pushing `v<version>` builds, tests, packages and publishes
without a human; a broken build publishes nothing.

### Task R2.1 — Workflow on tag and on `main`

`.github/workflows/release.yml`, `windows-latest`: `cargo test --bin saife`,
`--no-default-features`, `clippy --all-targets`, build release, package, hash,
`gh release create` (token), then run the manifest rewrite. **Do not** try to run
the VM lane in CI: it needs Hyper-V and a host-side guest — that stays local and
remains a release-checklist item, not a CI step.

### Task R2.2 — Gate on the version

The workflow fails if `Cargo.toml` version ≠ tag, if the changelog has no
section, or if the packaged asset's hash changes between the build and the
upload (upload the exact file that was hashed).

### Task R2.3 — Audit format number (additive, so MINOR)

Add `schema: 1` to `SESSION_START`; `audit verify` reports it; old chains without
it keep verifying. Update `KNOWN_KEYS`/filter. This is what lets a later reader
say "this chain was written by format 1" instead of guessing.

---

## R3 — winget

**Exit criteria:** `winget install GandalfIX.SAIFE-Sandbox` works on a clean
machine from the published package; `winget upgrade` moves 0.3.0 → 0.3.1;
`winget uninstall` leaves no PATH entry and no orphaned `saife-launch.exe`.

### Task R3.1 — Make the manifest describe a real asset

`InstallerUrl` must be the published `releases/download/v<ver>/saife-<ver>-x64.zip`
(already the shape in the file), `InstallerSha256` the bytes actually uploaded.
`License` must match the repository decision from the top of this plan.

### Task R3.2 — Submit

`wingetcreate submit --token <gh> packaging/winget` (or a manual PR to
`microsoft/winget-pkgs` under `manifests/g/GandalfIX/SAIFE-Sandbox/<ver>/`).
Two review traps already recorded in `packaging/winget-README.md`: prose files
inside the manifest directory break `winget validate` (it parses every file), and
`PortableCommandAlias: saife` is what makes the bare name resolve — the launcher
is deliberately not aliased.

### Task R3.3 — Prove upgrade and uninstall

On a clean VM (P5's 24H2 image is the right one): install 0.3.0, upgrade to
0.3.1, uninstall, then check `Get-Command saife` fails and
`%LOCALAPPDATA%\Microsoft\WinGet\Packages\GandalfIX.SAIFE-Sandbox*` is gone.
Record the transcript in `docs/tasks/release/evidence/`.

### Task R3.4 — What winget will not do for us

Portable installs do **not** self-update; users must run `winget upgrade`. `saife
setup` runs after install only if the user runs it — winget has no post-install
script for portable packages. Document both in the USER-GUIDE, and make `saife
--version`-adjacent advice ("run `winget upgrade GandalfIX.SAIFE-Sandbox`") part
of the doctor output when a newer release exists (optional; needs a network call
the tool does not make today — YAGNI unless users ask).

---

## R4 — Other channels, in the order that earns its keep

1. **Direct download** — the GitHub Release page plus a `README` "Install"
   section is already the lowest-friction channel; it needs only R1.
2. **Scoop** — a manifest in our own bucket (`GandalfIX/scoop-bucket`), 20 lines;
   `scoop install saife`. Good fit for the same audience as winget.
3. **Chocolatey** — a `chocolateyinstall.ps1` wrapping the same zip; needs an API
   key and a package review. Only if asked.
4. **MSI (WiX)** — only if someone needs GPO/Intune deployment. It also fixes the
   portable package's one real weakness: no Add/Remove Programs entry.

Each channel is a separate task with the same acceptance test: install → run →
upgrade → uninstall on a clean VM.

---

## R5 — Support policy, so "supported" means something

Write into `docs/USER-GUIDE.md` (and the README):

- which Windows builds are supported, per `ADR-0004` and whatever P5 measures
  (24H2 `26100.x`+, 25H2 `26200.x`, 26H2 `26300.9550+`; Insider builds are a
  canary, never "supported");
- that fixes land on the newest minor, security fixes on the newest minor too —
  no long-term branches while it is a one-person project;
- the security disclosure route (GitHub private advisory), and what counts as a
  containment bug (anything that lets a session reach a host it should not);
- that the winget package tracks stable releases only.

**1.0.0 gate:** the four conditions in `docs/design/versioning.md` §The 0.x era.

---

## Tests and validation per phase

| Phase | Command | Expected |
|---|---|---|
| R0 | `cargo test --bin saife` | all pass; version literal test derives |
| R0 | `(Get-Item target\release\saife.exe).VersionInfo.FileVersion` | `0.3.0.0` |
| R1 | `pwsh -File packaging/release.ps1 -DryRun` on a mismatched tag | refuses, exit ≠ 0 |
| R1 | download → hash → extract → run in a temp dir | hash matches, `--version` matches the tag |
| R2 | push a tag | release exists with 4 assets, manifest rewritten, `winget validate` passes |
| R3 | clean VM: install/upgrade/uninstall | all three succeed, transcript recorded |
| R4 | per channel, same script | same |

## Risks and tradeoffs

- **Unsigned binaries are the biggest adoption tax.** SmartScreen's warning looks
  like malware to a first-time user; this is why signing is a 1.0 gate.
- **CI cannot run the VM lane**, so "green CI" will always be weaker than the
  local gate. The release checklist must keep the local VM run explicit.
- **A portable winget package has no uninstaller of its own** — winget removes
  the link and the package dir, but anything `saife setup` wrote
  (`%USERPROFILE%\.saife`, `%LOCALAPPDATA%\saife`) survives by design. Say so.
- **Version-in-three-places is the recurring defect** (two already exist today);
  every R0 task exists to remove one copy, and the release script is the thing
  that fails loudly when a fourth appears.
- **Pre-1.0 schema churn** is a feature and a risk: users copying profiles
  between minors will hit refusals. The refusal message naming the fix is the
  mitigation, not a compatibility shim.
