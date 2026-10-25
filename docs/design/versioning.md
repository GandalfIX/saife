# SAIFE Sandbox — version numbering

**Status:** proposed 2026-10-25. **Applies from:** the first published release.
**SemVer:** 2.0.0 semantics, `v`-prefixed git tags (`v0.3.0`).

## The one rule

`Cargo.toml` → `[package] version` is the **single source of truth**. Every other
place a version appears is derived, generated or checked — never typed twice:

| Where it shows up | How it gets there | Owner |
|---|---|---|
| `saife --version` / `--help` | clap renders `CARGO_PKG_VERSION` | automatic |
| `dist/VERSION.txt` | packaging script writes `version:` line | R0 |
| `saife-<version>-x64.zip` | packaging script, **from the binary's version** | R0 |
| git tag `v<version>` | `packaging/release.ps1` refuses a mismatched tag | R1 |
| `saife.exe` FileVersion/ProductVersion | `build.rs` VERSIONINFO from `CARGO_PKG_VERSION` | R0 |
| winget `PackageVersion` (3 files) | release script rewrites them, then `winget validate` | R3 |
| `CHANGELOG.md` heading | written by hand at release time, checked against the tag | R1 |

A version typed by hand in a second place is a bug: today `src/cli.rs` hardcodes
`"SAIFE Sandbox 0.2.0"` in a test, and the packaging script takes
`-ReleaseVersion` from the command line while `Cargo.toml` says something else.
Both are R0 work.

## What a bump means for a containment product

The usual open-source rules do not fit a tool whose job is to *not* run things.
A change that quietly lets a session do more is not a patch, however small the
diff:

**MAJOR — the contract or the guarantee changed**
- profile schema break: a field removed, renamed, moved or newly refused (the
  `limits` move on 2026-10-25 is exactly this class)
- a default that weakens containment: different default backend, `block_net`
  default flipped, prompt default becoming allow, `ui.disable` becoming `true`
- the audit chain stops verifying for chains written by an older version, or a
  field is repurposed with a different meaning
- a documented exit code changes meaning (0/2/5/124/126 are product surface)
- `MinimumOSVersion` rises (a machine that could install can no longer)
- a CLI command or flag is removed

**MINOR — capability added, existing sessions behave the same**
- a new backend, a new audited operation, new `SESSION_START` fields
- a new profile knob whose default preserves today's behaviour
- new CLI surface; a new guardrail leg that only refuses what previously *failed
  silently* (worth a "Behaviour changes" note, not a major)
- tightening a check that used to pass invalid input (a profile that never
  worked now errors)

**PATCH — no visible change to a valid setup**
- bug fixes, performance, messages, docs, dependency bumps
- a security fix that does **not** change any default or schema: it still gets a
  CHANGELOG "Security" entry and a GHSA advisory if users must act

**Always:** a fix that changes how an existing valid session behaves gets a
"Behaviour changes" section in the CHANGELOG regardless of the number.

## The 0.x era

We are pre-1.0 on purpose: the profile schema is still moving and the Windows
version matrix (P5) has not been measured on a GA build. While 0.x:

- **MINOR may break** the profile schema, provided the CHANGELOG says so under
  `### Breaking` and the error message names the fix (as the `limits` move does).
- **PATCH never breaks** anything, including the schema.
- Installed profiles are migrated by the release notes, not by a compatibility
  reader — the tool refuses the old shape loudly instead of guessing.

**1.0.0 is declared when all four hold** (each is a gate, not a date):
1. P5 green on at least 24H2 `26100.x` and one newer GA servicing build, for both
   backends, including the unelevated lane.
2. Profile schema unchanged for two consecutive minor releases.
3. Binaries signed, so SmartScreen does not greet every install with "unknown
   publisher" (see the signing decision in the plan).
4. Install → upgrade → uninstall proven through winget on a clean machine.

## Pre-releases

`0.4.0-beta.1`, `0.4.0-rc.1` — SemVer precedence applies, tags carry the suffix
(`v0.4.0-rc.1`). Rules:

- pre-releases go to GitHub Releases only; **not** to winget (winget will not
  serve a pre-release unless the user passes `--prerelease`, and a package that
  most clients cannot see is worse than none)
- a pre-release never reuses the number of a final release
- build metadata (`+<sha>`) is allowed in `VERSION.txt` and release notes, never
  in a tag — SemVer says metadata does not affect precedence, so two tags
  differing only by metadata would be ambiguous

## Independent version numbers (do not conflate)

Three numbers evolve separately, and mixing them is how migrations become
impossible:

| Number | Lives in | Bumps when |
|---|---|---|
| product version | `Cargo.toml`, tags | any user-visible release |
| profile `meta.schema_version` | profile files | the profile schema breaks (today: `1`) |
| audit format | audit writer + `audit verify` | the chain/record format changes incompatibly |

The audit format has no explicit number today — `audit verify` simply reads what
it finds. R2 adds a `schema` field to `SESSION_START` so a reader can state what
it is reading; that is additive, therefore MINOR.

## Windows resource version

Windows wants four parts. `FileVersion` and `ProductVersion` are
`<major>.<minor>.<patch>.0`; the MSI/`ProductVersion` (if we ever ship one) is
`<major>.<minor>.<patch>`. A pre-release is *not* expressible in the resource, so
a pre-release binary reports the numeric triple of the release it precedes —
documented here so nobody "fixes" it later by inventing a fourth number.

## Anti-rules

- **Never reuse a version.** A bad build gets a new patch, never a re-uploaded
  asset — the winget manifest's `InstallerSha256` is pinned to the bytes.
- **Never publish with a tag that disagrees with `Cargo.toml`.** The release
  script compares them and refuses.
- **Never hand-edit a winget manifest.** A release with a stale manifest is how
  `winget upgrade` silently keeps serving an old hash.
- **Never sign a build after packaging it.** Sign the binaries, then zip, then
  hash — otherwise the published hash describes bytes nobody ever ran.
