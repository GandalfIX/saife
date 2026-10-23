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
2. `mxc-launch.exe` is extracted but deliberately NOT given a
   `PortableCommandAlias`: the supervisor finds it beside itself, and putting it
   on PATH would invite running the launcher directly.
3. `InstallerSha256` must be the hash of the release asset, not of the human
   bundle (`sandbox-<sha>.zip`). The build script prints it:

       pwsh -File packaging/build-dist.ps1 -ReleaseVersion 0.1.0
       # -> release: .../saife-0.1.0-x64.zip (1.889 KB)
       # -> sha256:  477BB4FF...

Placeholders that need a decision before submission to microsoft/winget-pkgs:
`InstallerUrl` and `PackageUrl` (GitHub repository), `PublisherSupportUrl`, and
`License: Proprietary` (confirm the licence; winget requires the field).

Rationale for the other non-obvious fields — `MinimumOSVersion`, the moniker, the
nested portable installer, and the release ritual — is in
`docs/design/saife-brand.md` §5.
