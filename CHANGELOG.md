# Changelog

All notable changes to SAIFE Sandbox are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the version numbers
follow `docs/design/versioning.md`: SemVer adapted to a containment product, where
a change that loosens a default is never a patch. While the project is 0.x, a
minor release may break the profile schema; the error message names the fix.

## [Unreleased]

## [0.4.0] - 2026-11-04

The release that adds the **build runner**, and the first one that ships an **arm64** archive.
Containment is unchanged or stricter; the one behaviour that loosens is that `--runner` may now be
used with `--block-net`, which previously refused to start at all.

### Added

- **Build runner.** Toolchains whose daemons need loopback - Gradle, a TCP test harness - cannot run
  inside a session, and loopback is closed in both directions. `saife run --runner` publishes a
  facade the session reaches at `build.sandbox.invalid`; the build runs in a digest-pinned container
  the supervisor owns, with no network, reached only through declared `(POST|GET /build)`
  operations. Slots are owned by pid **and** creation time, capped, and reaped when idle.
- `saife runner prewarm` fills a shared cache volume with every resolvable Maven-style configuration
  (compile, runtime, test-compile, test-runtime), so an offline build has what it needs; `saife
  runner status` reports slots and cache size.
- **Allow-list for what is copied into the container**: `paths` on the build request, defaulted by
  `runner.sync.paths` in a profile. A closed set - the settings closure travels or the build fails -
  and a missing entry is refused by name.
- **arm64 archives**: `saife-<version>-arm64.zip` next to the x64 one, with architecture-aware
  `build-dist.ps1`, `release.ps1`, `install-local.ps1` and `install.ps1` (an ARM64 host prefers the
  native archive and falls back to x64 with an emulation warning; an x64 host never gets arm64).
  The winget manifest carries one `Installer` block per architecture.
- `packaging/check-prereqs.ps1`: reports each build prerequisite, prints the exact install command
  for anything missing, offers to run it, and never elevates. It compares the Windows *servicing*
  level and reads the PE machine of built binaries rather than trusting a file name.
- Two opencode skills: `saife-build` (trigger the runner from inside a session) and `saife-maven`
  (Maven builds in-process, so it needs the proxy and a writable repository, not the runner).

### Changed

- A session can serve its facades **with no egress at all**: the proxy gains a blocked posture that
  denies every request at the tier check while still routing facade hosts. `--runner --block-net` is
  therefore the recommended pairing - previously it refused to start.
- `saife setup` names a tier it would have to **refuse**, instead of printing a degraded tier as if
  it were a green light.
- `learned list` shows every profile's store and says which one a revoke missed; profile grants are
  de-duplicated after expansion and share one resolver.
- `install-local.ps1` refuses a stale build of the same version; `install.ps1` diagnoses an
  application-control block (Smart App Control, AppLocker, WDAC) instead of dumping a stack trace.

### Fixed

- Gradle builds no longer fail on a missing executable bit, or on a container copy that races the
  slot's own `mkdir` (`404 /src`).
- `pack_dir` applies its skip list at every level, so a composite build no longer ships its own
  `build/` directories into the container.
- `prewarm` resolves every configuration, not just `runtimeClasspath`, so a new `testImplementation`
  is picked up by re-running it.

### Notes

- Profile schema: `runner.sync.paths` is new and additive. No key was removed or renamed, so a 0.3.x
  profile loads unchanged.
- The runner is **not** enabled by default and never runs a build with network.
- The arm64 archive is cross-built and has **not been run on ARM hardware**; the README says so, and
  an ARM64 host can install the x64 archive under emulation instead.


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
