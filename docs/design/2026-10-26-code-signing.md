# Code signing: how SAIFE could ship a signed `saife.exe`

**Status:** exploration, decision pending (release decision D2). Research date 2026-10-26.
**Question:** the release assets are unsigned, so Windows shows "Unknown publisher"
and SmartScreen warns on download. What are the ways to get a *trusted* signature,
what do they cost, and what does each require of this project?

## What a signature buys - and what it does not

Buys:

- **A publisher name** in the UAC prompt, in SmartScreen and in the file's
  Digital Signatures tab, instead of "Unknown publisher".
- **Integrity**: the bytes are provably the ones the publisher signed, and a
  timestamp keeps the signature valid after the certificate expires.
- **SmartScreen reputation** that accumulates with download volume.

Does not buy:

- **Silence from SmartScreen.** Since March 2024 Microsoft removed EV's distinct
  SmartScreen status; EV and OV now build reputation the same way, through
  downloads. A newly signed binary from an unknown publisher can still warn.
- **Anything in winget.** The client does not check Authenticode, and the index
  channel is closed anyway (the CLA decision).
- **A fix for a compromised build machine.** The signature attests who signed, not
  that the machine was clean. That is what the reproducible-ish release flow
  (build once, hash, verify after download) is for.

## The constraints that actually decide this

- **Individual in Germany, no legal entity.** This is the single most limiting
  fact: Azure Artifact Signing (ex-Trusted Signing) issues *Public Trust*
  certificates to organizations in the EU - but **individual developers only in the
  US and Canada** (Microsoft Learn, Artifact Signing quickstart, checked 2026-10-26).
- **MIT-licensed, public, released.** `v0.3.1` exists and the repository documents
  the product, which is exactly what the free open-source signing programmes ask for.
- **Two binaries plus a zip.** `saife.exe` and `saife-launch.exe` both need
  signatures; the zip itself is not signed, it carries them.
- **Signing must happen before zipping.** `SHA256SUMS.txt` and the manifests'
  `InstallerSha256` must describe the *signed* bytes, so the order is
  sign -> verify -> zip -> hash -> manifests.
- **The release runs on the maintainer's machine.** CI holds no signing secret
  today; a CI-based signer changes that.

## Options

| Route | Publisher shown | Cost | Key storage | Unattended CI | Eligible here |
|---|---|---|---|---|---|
| **SignPath Foundation** | `SignPath Foundation` | free | their HSM | **yes**, GitHub Action | OSS, maintained, released, no proprietary components |
| **Certum Open Source Code Signing, Cloud (SimplySign)** | `Open Source Developer <legal name>` | from ~$58/yr (list) | Certum HSM, FIPS 140-2 L3 | semi - a session opened with a mobile OTP | individual developer, OSS |
| **Certum Open Source, on card** | same | ~EUR 69 + reader + courier | crypto card | no | same |
| **Azure Artifact Signing** | legal entity name | ~$10/month (Basic; confirm on the pricing page) | Microsoft HSM | **yes** | **organizations** in the EU/UK/US/CA/AU/NZ/JP/KR/SG/CH/NO/IL - not a German individual |
| **Commercial OV** (SSL.com, Sectigo, DigiCert) | company or verified individual | quoted; roughly $130-$350/yr depending on CA and term | token (FIPS) or their cloud HSM | only with a cloud-HSM variant | anyone who passes vetting |
| **EV** | entity, "Sole Proprietor EV" for individuals at SSL.com | $349/yr at SSL.com (1 year, verified) + $379 YubiKey or eSigner | token/HSM | only with eSigner/HSM | not needed: no kernel drivers, no Partner Center, and no SmartScreen shortcut since 2024 |
| **Self-signed CA** | your CA | free | anywhere | yes | internal machines only (GPO/Intune trust) - useless for public downloads |

Notes that cost money if missed:

- Certum's **card** variant cannot sign in CI at all, and needs a courier delivery.
  The **cloud** variant (SimplySign) needs the desktop app and a code from a phone
  to *open a session*; scripts can then sign until the session ends. Fully
  unattended signing of an unattended build is not what it sells.
- Certum's OSS certificate puts **"Open Source Developer"** in the subject, which is
  the publisher string users see. It is not "Gandalf IX" alone.
- SignPath Foundation issues the certificate to the **foundation**, so the publisher
  is `SignPath Foundation`. That is honest and common for OSS Windows tools, but it
  is not the maintainer's name. Its conditions also exclude "hacking tools" -
  software that circumvents the security of its execution environment. SAIFE
  *restricts* a workload; worth raising explicitly in the application rather than
  discovering it in review.
- Azure's advantage is that it is the only route here that is both cheap and fully
  automatic with a real organizational identity - and it needs a registered
  business (GmbH, UG, e.K., or a registered Einzelunternehmen) plus identity
  validation.

## Recommendation

1. **Keep 0.3.x unsigned.** The mitigation that already exists (published
   `SHA256SUMS.txt`, verified by `install.ps1`, plus "download, read, run" ahead of
   the one-liner) is what D2 accepted for the 0.x era. Nothing here changes before
   1.0.
2. **For 1.0, apply to SignPath Foundation first.** Free, no hardware, no secret on
   a laptop, and signing happens in the same GitHub Actions run that produced the
   binaries. The cost is the publisher name.
3. **If the publisher must read as you,** Certum's OSS cloud certificate at ~$58/yr
   is the cheapest legitimate public-trust route; accept an attended session and
   the "Open Source Developer ..." subject.
4. **Azure Artifact Signing becomes the best option the moment a legal entity
   exists** - cheapest automated path with a real organization identity.
5. **Do not buy EV.** No drivers, no Partner Center, and the SmartScreen advantage
   it used to carry was removed in March 2024.

## What implementing it costs (repo side)

**S0 - make the pipeline signature-aware, with no certificate (~half a day).**
The order changes and the release must refuse to publish unsigned bytes when a
certificate is configured:

- `release.ps1`: after the static build, sign both binaries
  (`signtool sign /fd sha256 /tr <RFC3161 url> /td sha256`), then
  `signtool verify /pa /all`, and only then zip, hash and rewrite the manifests.
- `-Sign <thumbprint|pfx|simplysign>` plus `-RequireSignature`; publish mode
  refuses an asset whose binaries are not `Valid` per `Get-AuthenticodeSignature`.
- `Test-Asset` prints the signer subject and whether a timestamp is present, so the
  publish log records what actually shipped.
- Acceptance: extracted `saife.exe` and `saife-launch.exe` both report a valid
  signature with a timestamp; `SHA256SUMS.txt` and `InstallerSha256` match the
  signed zip; `install.ps1` still verifies on a clean machine.

**S1 - SignPath Foundation (~a day, once accepted).** A workflow that builds,
uploads the two binaries as an artifact, submits a signing request (action pinned
by SHA like the others), downloads the signed files, then zips, hashes and
publishes. Requires a `SIGNPATH_API_TOKEN` secret, an artifact configuration, and
that every job feeding the signing request runs on GitHub-hosted agents.

**S2 - Certum cloud or Azure (unchanged shape).** Signing stays in the `prepare`
step on the maintainer's machine; only the credential source differs.

## Open questions

1. Is `SignPath Foundation` acceptable as the publisher string, or must it be the
   maintainer's name? This decides free-vs-$58, and CI-vs-attended.
2. Is a legal entity planned? If yes, Azure becomes the cheapest fully automatic
   route and the answer changes.
3. Is an attended signing session (mobile OTP per release) acceptable, or is
   unattended signing a hard requirement?

## Sources

- Microsoft Learn, *Artifact Signing quickstart* - Public Trust eligibility by
  country, individual vs organization (checked 2026-10-26).
- signpath.org, *conditions for Open Source projects* - licence, maintenance,
  "sign your own binaries", no-hacking-tools clause.
- certum.store, *Open Source Code Signing in the Cloud* - from $58, SimplySign,
  HSM FIPS 140-2 L3, subject prefixed "Open Source Developer".
- shop.certum.eu, *Open Source Code Signing - set* - from EUR 69 with card + reader.
- ssl.com, *EV Code Signing* - $349/yr, $379 YubiKey, and the March 2024 note that
  EV no longer carries a distinct SmartScreen status.
