# Releasing and distributing SAIFE Sandbox — progress

Plan: [2026-10-25-releasing-and-distribution.md](../../plans/2026-10-25-releasing-and-distribution.md)
Policy: [docs/design/versioning.md](../../design/versioning.md) (SemVer, single source of truth)
Version at plan time: `0.2.0` in `Cargo.toml`, **no tags**, no CI, no LICENSE, no exe VERSIONINFO.

Status legend: `[ ]` not started · `[~]` in progress · `[x]` done and gated · `[!]` blocked

## Rows

| # | Task | Status | Evidence |
|---|---|---|---|
| R0.1 | CLI version test derives from `CARGO_PKG_VERSION` instead of the literal `"SAIFE Sandbox 0.2.0"` | [x] | `src/cli.rs` now asserts `format!("SAIFE Sandbox {}", env!("CARGO_PKG_VERSION"))`; `saife --version` prints `SAIFE Sandbox 0.3.0` from `Cargo.toml` alone. |
| R0.2 | `VERSION.txt` carries `version:`; asset name derived, `-ReleaseVersion` becomes a must-match override | [ ] | `dist/VERSION.txt` currently has commit/branch/built only |
| R0.3 | `build.rs` VERSIONINFO: FileVersion/ProductVersion/ProductName/CompanyName on both exes | [ ] | no `build.rs` exists; Explorer's Details tab is empty today |
| R0.4 | `packaging/release.ps1`: tag must equal `Cargo.toml`, `-DryRun` prints what it would publish | [ ] | |
| R0.5 | Manifest rewrite in `release.ps1` (`PackageVersion` ×3, `InstallerSha256`, `InstallerUrl`), then `winget validate` | [ ] | hand-edited manifests are the known drift source |
| R1.1 | `CHANGELOG.md` (Keep a Changelog) with `Breaking` / `Behaviour changes` sections | [ ] | no changelog exists |
| R1.2 | Asset set: flat zip, `SHA256SUMS.txt`, single-line `.sha256`, `VERSION.txt`; sign before zipping | [ ] | |
| R1.3 | Publish + re-verify from a clean temp dir (hash, extract, `--version`, a real run) | [ ] | |
| R1.4 | Full rehearsal on a throwaway `-rc` tag before the real one | [ ] | |
| R2.1 | GitHub Actions `release.yml` on tag: tests, clippy, build, package, publish (VM lane stays local) | [ ] | no `.github/workflows/` yet; Hyper-V is not available on hosted runners |
| R2.2 | Workflow gates: version == tag, changelog section exists, uploaded bytes == hashed bytes | [ ] | |
| R2.3 | `schema: 1` on `SESSION_START`; `audit verify` reports it; old chains unaffected | [ ] | additive, so a MINOR under the policy |
| R3.1 | Manifest describes a real, published asset; `License` matches the repository decision | [ ] | `InstallerUrl` points at `v0.2.0`, which does not exist (404) |
| R3.2 | Submit to `microsoft/winget-pkgs` (wingetcreate or manual PR) | [ ] | prose files inside the manifest dir break `winget validate` |
| R3.3 | Clean-VM proof: install → upgrade → uninstall → `Get-Command saife` fails | [ ] | needs P5's 24H2 image |
| R3.4 | Document what winget does not do: no self-update, no post-install script, state dirs survive uninstall | [ ] | |
| R4.1 | Direct download section in README + release page as the primary channel | [ ] | |
| R4.2 | Scoop manifest in `GandalfIX/scoop-bucket` | [ ] | optional, cheap |
| R4.3 | Chocolatey package | [ ] | only if asked |
| R4.4 | MSI (WiX) for GPO/Intune, with Add/Remove Programs entry | [ ] | only on demand |
| R5.1 | Support policy in USER-GUIDE (builds, fix policy, disclosure route, winget = stable only) | [ ] | |
| R5.2 | 1.0.0 gate: P5 matrix green, schema stable two minors, signed, install/upgrade/uninstall proven | [ ] | |

## Decisions blocking R1/R3

| # | Decision | Status | Notes |
|---|---|---|---|
| D1 | Licence: proprietary-with-EULA vs OSI (manifest says `Proprietary`, repo has no `LICENSE`) | **MIT** | `LICENSE` added, `Cargo.toml` `license = "MIT"`, manifest `License: MIT` + `LicenseUrl`; `winget validate` passes. |
| D2 | Code signing: Azure Trusted Signing / OV cert / none for now | open | analysis: Artifact Signing (ex-Trusted Signing) is org-only in the EU (individuals US/CA only); OV cert needs an HSM/token; self-signed CA is internal-only. Recommendation stands: unsigned at launch, signing as a 1.0 gate. |
| D3 | First public version: `0.3.0` (breaking schema move already on `main`) vs `0.2.1` | **0.3.0** | `Cargo.toml` bumped; the `limits` move is the MINOR that justifies it. |
| D4 | MSI scope | **deferred** | R4, only on demand (GPO/Intune). |
