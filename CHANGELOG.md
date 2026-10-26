# Changelog

All notable changes to SAIFE Sandbox are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the version numbers
follow `docs/design/versioning.md`: SemVer adapted to a containment product, where
a change that loosens a default is never a patch. While the project is 0.x, a
minor release may break the profile schema; the error message names the fix.

## [Unreleased]

## [0.3.1] - 2026-10-26

Documentation, distribution and output only: no profile, no default and no exit
code changes, so a setup that worked under 0.3.0 works unchanged.

### Added

- `install.ps1`: one-command install (download, hash-verify against the release's
  `SHA256SUMS.txt`, extract, version-check, user-PATH entry, self-check). It is the
  supported install channel and needs no administrator rights.
- `saife setup --check-only` prints an `MXC tier (probe)` line: it probes a
  representative base request and reports the verdict, so a machine whose probe
  names no tier is visible before a run refuses.

### Changed

- `packaging/release.ps1` no longer pushes `main`. Releasing is two steps: prepare
  (build, probe, rewrite manifests, open a pull request) and `-Publish` (on `main`
  after the merge: tag, publish, verify). `main` only moves through pull requests now
  - see `AGENTS.md`.
- No winget package is provided. `packaging/winget/` remains for local
  `winget install --manifest` use; `install.ps1` is the supported install.
- The guardrail-2 refusal for a host whose MXC tier probe names no tier now ends
  with the way out - use `--backend appcontainer`, or run `saife setup
  --check-only` - instead of a dead end.
- The winget manifests moved to the 1.12 schema, and the manifest rewrite keeps the
  file's CRLF endings.

### Docs

- FAQ entry for the writable-grant-covers-launcher refusal: why `--allow-cwd` in the
  home directory is refused for the mxc backend, with the measured contract (message,
  exit code 2, no audit session) and the workaround.

## [0.3.0] - 2026-10-26

First public release. Early stages: the tool works end to end, but the profile
schema and the CLI still move, and a 0.x minor release can break a profile that
worked before.

- Windows 11 24H2 (build 26100) or newer, x64. No administrator rights, no service
  and no installer are needed for the default `mxc` backend.
- Start with `README.md` for install and a first run, then `docs/USER-GUIDE.md` for
  every flag, the guardrail proof line and the audit log.
- The binaries are unsigned, so Windows SmartScreen warns about an unknown
  publisher on first run. Check the download against `SHA256SUMS.txt` on the
  release page.
