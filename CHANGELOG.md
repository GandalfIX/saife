# Changelog

All notable changes to SAIFE Sandbox are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the version numbers
follow `docs/design/versioning.md`: SemVer adapted to a containment product, where
a change that loosens a default is never a patch. While the project is 0.x, a
minor release may break the profile schema; the error message names the fix.

## [Unreleased]

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
