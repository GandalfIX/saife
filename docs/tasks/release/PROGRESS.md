# Releasing and distributing SAIFE Sandbox — progress

Plan: [2026-10-25-releasing-and-distribution.md](../../plans/2026-10-25-releasing-and-distribution.md)
Policy: [docs/design/versioning.md](../../design/versioning.md) (SemVer, single source of truth)
Version at plan time: `0.2.0` in `Cargo.toml`, **no tags**, no CI, no LICENSE, no exe VERSIONINFO.

**Released 2026-10-26: `v0.3.0`, the first public release.** The repository is
public, the release is immutable, and the published asset was downloaded again after
publishing and hash-compared (`9DD85C4E…`).

What is left is not release-blocking: a tag-driven CI pipeline (R2), the winget-pkgs
review (R3.2, PR open, CLA signature pending), the clean-VM install proof (R3.3,
which needs an elevated one-time `winget settings --enable LocalManifestFiles` on the
test machine), and signing as the 1.0 gate (D2).

Status legend: `[ ]` not started · `[~]` in progress · `[x]` done and gated · `[!]` blocked

## Rows

| # | Task | Status | Evidence |
|---|---|---|---|
| R0.1 | CLI version test derives from `CARGO_PKG_VERSION` instead of the literal `"SAIFE Sandbox 0.2.0"` | [x] | `src/cli.rs` now asserts `format!("SAIFE Sandbox {}", env!("CARGO_PKG_VERSION"))`; `saife --version` prints `SAIFE Sandbox 0.3.0` from `Cargo.toml` alone. |
| R0.2 | `VERSION.txt` carries `version:`; asset name derived, `-ReleaseVersion` becomes a must-match override | [x] | `packaging/build-dist.ps1` reads `[package] version`, refuses a mismatched `-ReleaseVersion`, writes `version:` into `dist/VERSION.txt`, derives `saife-<version>-x64.zip` from it, and probes the built exes (`--version` and `FileVersion`) instead of trusting their file names. |
| R0.3 | `build.rs` VERSIONINFO: FileVersion/ProductVersion/ProductName/CompanyName on both exes | [x] | `build.rs` (winresource) stamps FileVersion `0.3.0.0`, ProductVersion `0.3.0`, ProductName and CompanyName on both exes; verified with `(Get-Item .\target\release\saife.exe).VersionInfo`. |
| R0.4 | `packaging/release.ps1`: tag must equal `Cargo.toml`, `-DryRun` prints what it would publish | [x] | `packaging/release.ps1`: refuses a dirty tree, a branch other than `main`, a HEAD that is not level with `origin/main`, an existing tag and a missing CHANGELOG section; runs tests + clippy; `-DryRun` builds, probes and validates, then stops before commit/tag/publish. |
| R0.5 | Manifest rewrite in `release.ps1` (`PackageVersion` ×3, `InstallerSha256`, `InstallerUrl`), then `winget validate` | [x] | release.ps1 rewrites `PackageVersion`, `InstallerUrl` and `InstallerSha256` in all three manifests from the built asset, then `winget validate` (`Die Manifestüberprüfung war erfolgreich.`). |
| R1.1 | `CHANGELOG.md` (Keep a Changelog) with `Breaking` / `Behaviour changes` sections | [x] | `CHANGELOG.md` (Keep a Changelog) with `## [0.3.0] - 2026-10-26`; that section is the release notes file the release was published with. |
| R1.2 | Asset set: flat zip, `SHA256SUMS.txt`, single-line `.sha256`, `VERSION.txt`; sign before zipping | [~] | published: flat `saife-0.3.0-x64.zip` + `SHA256SUMS.txt` (LF). The single-line `.sha256` was dropped as redundant with the sums file. Signing stays a 1.0 gate (D2), so the assets are unsigned. |
| R1.3 | Publish + re-verify from a clean temp dir (hash, extract, `--version`, a real run) | [x] | release.ps1 re-downloads `releases/download/v0.3.0/...` after publishing and compares the hash; a manual download hashed identically, extracted flat, and `saife run --allow-cwd -- cmd /c type note.txt` printed `hello` plus the guardrail line. |
| R1.4 | Full rehearsal on a throwaway `-rc` tag before the real one | [~] | rehearsed with `-DryRun` (asset built, probed, manifests rewritten on a copy and validated) rather than a throwaway `-rc` tag; the real cut then ran the same pipeline. |
| R2.1 | GitHub Actions `release.yml` on tag: tests, clippy, build, package, publish (VM lane stays local) | [ ] | no `.github/workflows/` yet; Hyper-V is not available on hosted runners |
| R2.2 | Workflow gates: version == tag, changelog section exists, uploaded bytes == hashed bytes | [ ] | |
| R2.3 | `schema: 1` on `SESSION_START`; `audit verify` reports it; old chains unaffected | [ ] | additive, so a MINOR under the policy |
| R3.1 | Manifest describes a real, published asset; `License` matches the repository decision | [x] | manifests name `v0.3.0` and the published hash `9DD85C4E…`; `winget show --manifest` resolves the package (name, moniker, licence, description). |
| R3.2 | Submit to `microsoft/winget-pkgs` (wingetcreate or manual PR) | [~] | [microsoft/winget-pkgs#462047](https://github.com/microsoft/winget-pkgs/pull/462047) is open on the 1.12 schema; the Microsoft CLA signature is a one-time browser step by the maintainer. |
| R3.3 | Clean-VM proof: install → upgrade → uninstall → `Get-Command saife` fails | [~] | not proven on a clean VM: `winget install --manifest` needs an elevated `winget settings --enable LocalManifestFiles`, which is off on this host. What was proven instead: the archive installs and runs by hand, and `winget validate`/`winget show` accept the manifests. |
| R3.4 | Document what winget does not do: no self-update, no post-install script, state dirs survive uninstall | [x] | README states what winget does not do: no profile creation, no post-install step, and `%USERPROFILE%\.saife` + `%LOCALAPPDATA%\saife` survive uninstall. |
| R4.1 | Direct download section in README + release page as the primary channel | [x] | `README.md` gained `## Install`: winget (index + local manifest) and direct download with hash verification, then a two-command verification. |
| R4.2 | Scoop manifest in `GandalfIX/scoop-bucket` | [ ] | optional, cheap |
| R4.3 | Chocolatey package | [ ] | only if asked |
| R4.4 | MSI (WiX) for GPO/Intune, with Add/Remove Programs entry | [ ] | only on demand |
| R5.1 | Support policy in USER-GUIDE (builds, fix policy, disclosure route, winget = stable only) | [ ] | |
| R5.2 | 1.0.0 gate: P5 matrix green, schema stable two minors, signed, install/upgrade/uninstall proven | [ ] | |

## Decisions blocking R1/R3

| # | Decision | Status | Notes |
|---|---|---|---|
| D1 | Licence: proprietary-with-EULA vs OSI (manifest says `Proprietary`, repo has no `LICENSE`) | **MIT** | `LICENSE` added, `Cargo.toml` `license = "MIT"`, manifest `License: MIT` + `LicenseUrl`; `winget validate` passes. |
| D2 | Code signing: Azure Trusted Signing / OV cert / none for now | open (shipped unsigned) | analysis: Artifact Signing (ex-Trusted Signing) is org-only in the EU (individuals US/CA only); OV cert needs an HSM/token; self-signed CA is internal-only. Recommendation stands: unsigned at launch, signing as a 1.0 gate. |
| D3 | First public version: `0.3.0` (breaking schema move already on `main`) vs `0.2.1` | **0.3.0** | `Cargo.toml` bumped; the `limits` move is the MINOR that justifies it. |
| D4 | MSI scope | **deferred** | R4, only on demand (GPO/Intune). |
