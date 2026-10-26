# WinGet manifests — SAIFE Sandbox

Three manifests (version, installer, default locale), validated with the real
client on every edit:

    winget validate --manifest packaging/winget
    -> Die Manifestüberprüfung war erfolgreich.        (for a German host)

Install the built package:

    winget install --manifest packaging/winget

Three facts that are easy to get wrong here, each of which the manifest encodes:

1. The release archive must be FLAT (no wrapper directory), because
   `NestedInstallerFiles[].RelativeFilePath` is resolved against the archive root.
   `packaging/build-dist.ps1 -ReleaseVersion <v>` produces exactly that.
2. `saife-launch.exe` is extracted but deliberately NOT given a
   `PortableCommandAlias`: the supervisor finds it beside itself, and putting it
   on PATH would invite running the launcher directly.
3. `InstallerSha256` must be the hash of the release asset, not of the human
   bundle (`sandbox-<sha>.zip`). The build script prints it:

       pwsh -File packaging/build-dist.ps1 -Release
       # -> release: .../saife-<version>-x64.zip (1.889 KB)
       # -> sha256:  477BB4FF...

This file lives OUTSIDE `packaging/winget/` on purpose: `winget validate`
scans every file in the manifest directory, and a prose file beside the manifests
is parsed as YAML (a line ending in a colon fails as
`[YAML:Scanner] ... [line 4; col 21]`, naming nothing useful).

The manifests are not edited by hand any more: `packaging/release.ps1` rewrites
`PackageVersion`, `InstallerUrl` and `InstallerSha256` from the asset it just
built, validates the directory with the real client, and only then tags and
publishes. A hand-typed hash is the drift source this replaces.

Submitting to `microsoft/winget-pkgs` (once per version):

    wingetcreate submit --token <PAT> packaging/winget
    # or copy packaging/winget to manifests/g/GandalfIX/SAIFE-Sandbox/<version>/ in
    # a fork of microsoft/winget-pkgs and open the PR by hand

The first submission also requires signing Microsoft's CLA (a one-time browser
step). Until the PR is merged, `winget install --id GandalfIX.SAIFE-Sandbox` fails
with "no package found" while `winget install --manifest packaging/winget` works -
that is why the README documents both.

Rationale for the other non-obvious fields — `MinimumOSVersion`, the moniker, the
nested portable installer, and the release ritual — is in
`docs/design/saife-brand.md` §5.
