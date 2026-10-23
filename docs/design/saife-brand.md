# SAIFE Sandbox — name, help surface, logo, packaging

Status: draft (2026-10-23). Nothing here is implemented yet except where it says
"verified"; the rename is still ahead of us.

## 1. Name and positioning

- **Name:** SAIFE Sandbox
- **CLI:** `saife`
- **Meaning:** Secure AI Frontier Environment
- **Positioning:** "SAIFE Sandbox isolates and audits AI agents with production
  grade Windows containment policies, turning experimental code into accountable
  actors."

What the name should make obvious, and what the product already does:

| claim in the name | mechanism in the code |
|---|---|
| *Secure* | explicit filesystem grants, proxy-only egress, per-session tokens |
| *AI Frontier* | built for agents that fetch, spawn and write — TUIs, MCP servers, sidecars |
| *Environment* | a session, not a VM: one containment policy, one audit chain, no admin |
| *audits* | hash-chained, Ed25519-signed `SESSION_START` root + per-decision leaves |

Canonical example, the one to use everywhere:

```
saife run -- opencode
```

## 2. `saife --help` (draft)

The version line comes from the crate; the rename has to change it (today it
prints `saife 0.1.0`). Commands, options and exit codes below are the real
ones, verified against the binary.

```
SAIFE Sandbox 0.1.0
Secure AI Frontier Environment

Isolate and audit AI agents with production-grade Windows containment policies.

Usage: saife <COMMAND>

Commands:
  run      Run a command inside a contained, audited session
  ps       List sessions (one per supervisor process)
  audit    Inspect or verify a session's audit chain
  profile  Manage profiles: filesystem grants, network, budgets
  learned  Manage the learned allow/deny store
  setup    Check host compatibility and feature availability
  help     Print this message or the help of a given subcommand

Options:
  -h, --help     Print help
  -V, --version  Print version

Common invocations:
  saife run --allow-cwd -- cmd /c dir
  saife run --profile opencode --allow-cwd -- opencode
  saife run --allow-domain api.anthropic.com -- claude
  saife run --block-net -- python train.py
  saife run --plugin jira --allow-cwd -- cmd /c "curl.exe -s http://jira.sandbox.invalid/"
  saife audit verify <sid>
  saife setup --check-only

Session model:
  Filesystem  exactly what you grant: --allow-cwd, --allow <path>[:mode],
              --read-only <path>. Everything else is unreadable and unwritable.
  Network     proxy-only egress. Allow-listed hosts are admitted, every other
              host is prompted for when a desktop is available and refused
              otherwise; --block-net removes the network entirely.
  Plugins     host-side sidecars reachable only at http://<mount>.sandbox.invalid/
              (--plugin <name>, --plugin-dir <path>).
  Audit       every session writes a signed, hash-chained log.

Exit codes:
  0    success
  2    usage error, or a session the supervisor refused to start
  5    a plugin could not be loaded, spawned or made healthy
  124  the session deadline expired
  126  guardrail refusal (for example: the workload never authenticated to the proxy)

Files:
  profiles   %USERPROFILE%\.saife\profiles\<name>.json
  plugins    %USERPROFILE%\.saife\plugins\<name>\plugin.json
  audit      %LOCALAPPDATA%\saife\audit\<sid>.ndjson (+ .root, .sig)

Run 'saife <command> --help' for a command's full options.
```

`saife run --help` groups its options the same way; the flags are `--profile`,
`--allow-cwd`, `--allow`, `--read-only`, `--block-net`, `--allow-domain`,
`--deny-domain`, `--no-prompt`, `--no-interactive`, `--network-profile`,
`--audit-strict`, `--backend`, `--plugin`, `--plugin-dir`.

## 3. Logo

Three sizes. All are monospace-only, carry no colour dependency, and each has a
plain-ASCII fallback for consoles that mangle box-drawing characters.

**Banner** (39 columns × 6 lines) — README headers, release notes, installer
banner, `saife --version --verbose` if we ever add one:

```
███████╗ █████╗ ██╗███████╗███████╗
██╔════╝██╔══██╗██║██╔════╝██╔════╝
███████╗███████║██║█████╗  █████╗
╚════██║██╔══██║██║██╔══╝  ██╔══╝
███████║██║  ██║██║██║     ███████╗
╚══════╝╚═╝  ╚═╝╚═╝╚═╝     ╚══════╝
        Secure AI Frontier Environment
```

**Compact** (2 lines) — TUI title bars, session headers, compact docs:

```
█▀▀ ▄▀█ █ █▀▀ █▀▀
▄██ █▀█ █ █▀▀ ██▄
```

**Inline** — one-line contexts (log prefixes, package descriptions):

```
[ SAIFE ] Secure AI Frontier Environment
```

**ASCII fallback** — cmd.exe with a legacy code page, CI logs, anything that
cannot be trusted with UTF-8:

```
+====================================+
|  S A I F E   S A N D B O X         |
|  Secure AI Frontier Environment    |
+====================================+
```

Rules: never colour the banner as the only signal; never use the 39-column
banner in help output (it must stay readable at 80 columns with the usage text);
the compact form is the default for anything printed per session.

## 4. Usage examples worth shipping in docs

```powershell
# the canonical one
saife run -- opencode

# a build that needs its working directory and one registry
saife run --profile node --allow-cwd -- cmd /c "npm install"

# nothing leaves the machine
saife run --block-net -- python .\train.py

# a capability that holds its own credential, host-side
saife run --plugin jira --allow-cwd -- cmd /c "curl.exe -s http://jira.sandbox.invalid/issue/ABC-1"

# what happened?
saife audit show <sid> --filter 'op=CONNECT'
saife audit verify <sid>
```

## 5. WinGet package

Three manifests, in `packaging/winget/`:

```
GandalfIX.SAIFE-Sandbox.yaml                  version
GandalfIX.SAIFE-Sandbox.installer.yaml        zip + nested portable installer
GandalfIX.SAIFE-Sandbox.locale.en-US.yaml     publisher, description, tags, notes
```

Verified with the real client:

```
winget validate --manifest packaging/winget
-> Die Manifestüberprüfung war erfolgreich.      (validation succeeded)
```

Design points that are not obvious:

- **`InstallerType: zip` + `NestedInstallerType: portable`** is what makes a
  two-binary product installable without an MSI: winget unpacks the archive,
  keeps `saife.exe` and `mxc-launch.exe` side by side, and symlinks only
  `saife.exe` onto PATH. The launcher must be extracted but **not** aliased — it is
  found next to the supervisor, and putting it on PATH would invite running it
  directly.
- **The release archive must be flat** (no wrapper directory), because
  `RelativeFilePath` is relative to the archive root. The human bundle under
  `dist/` is wrapped for tidiness; the release asset is not.
- **`MinimumOSVersion: 10.0.26100.0`** states the 24H2 floor instead of failing at
  runtime. The AppContainer backend works on older builds, but the package's
  default path does not, so the floor belongs in the manifest.
- **`PackageIdentifier: GandalfIX.SAIFE-Sandbox`**, `Moniker: saife`.
  Keep PROSE OUT of the manifest directory: `winget validate --manifest <dir>`
  scans every file in it, so a `README.md` sitting beside the manifests is parsed
  as YAML — a line ending in a colon produces
  `[YAML:Scanner] mapping values are not allowed in this context [line 4; col 21]`,
  an error that names neither the file nor the real problem. (Measured 2026-10-23,
  winget 1.30: the same three manifests validate with the README one directory up
  and fail with it inside. An earlier reading of this as an identifier-casing rule
  was wrong.) The prose lives in `packaging/winget-README.md` for that reason. The moniker is
  what makes `winget install saife` work.
- Two values are placeholders until the repository exists: `PackageUrl` /
  `InstallerUrl` (GitHub) and `License: Proprietary` — both need your decision.

Release ritual (each version):

```
pwsh -File packaging/build-dist.ps1 -ReleaseVersion <version>
#   builds, assembles dist/, writes SHA256SUMS.txt, and ALSO emits the flat
#   release asset saife-<version>-x64.zip with saife.exe inside, printing its
#   SHA256 for InstallerSha256
# then: bump PackageVersion in all three manifests, paste the hash, and
winget validate --manifest packaging/winget
```

The archive currently at the repo root, `saife-0.1.0-x64.zip`, was produced by that command: flat layout, `saife.exe`
(the current supervisor copied under its brand name — verified to run: `saife.exe
run --allow-cwd --block-net -- cmd /c echo SAIFE-OK`) plus `mxc-launch.exe`,
SHA256 `477bb4ffc58bd197ac0dbec55fcbf58b098fffa02bdd3f4045e354d0afe956f3`.

## 6. What the rename actually touches

Everything below still says "sandbox" today. This is the checklist, not a wish
list — each item is a real string or path in the tree.

| surface | today | target |
|---|---|---|
| binary name | `saife.exe` | `saife.exe` |
| launcher | `mxc-launch.exe` | `saife-launch.exe` (and the "beside the supervisor" rule follows) |
| version line | `saife 0.1.0` | `SAIFE Sandbox 0.1.0` |
| stderr prefix | `[saife] …` | `[saife] …` |
| profile dir | `%USERPROFILE%\.sandbox\profiles` | `%USERPROFILE%\.saife\profiles` |
| plugin dir | `%USERPROFILE%\.sandbox\plugins` | `%USERPROFILE%\.saife\plugins` |
| audit + signing + logs | `%LOCALAPPDATA%\sandbox\…` | `%LOCALAPPDATA%\saife\…` |
| env markers | `SAIFE_SESSION_SID`, `SAIFE_PROXY_PORT`, `SAIFE_FACADE_MOUNTS` | `SAIFE_*` |
| plugin sidecar env | `SIDECAR_*` (keep; it is plural-friendly and not brand-specific) | unchanged |
| doc set | USER-GUIDE, DEVELOPERS, README, AGENTS, plan/ADR text | rewritten around `saife` |
| packaging | `build-dist.ps1` paths, `dist/`, zip names | `saife-<version>-x64.zip` |
| winget | `RelativeFilePath: saife.exe` (already target-state) | matches once renamed; identifier `GandalfIX.SAIFE-Sandbox`, URLs under github.com/GandalfIX/saife |

Two decisions:

1. **Hard rename or compatibility period?** There are no external users, so a
   hard rename with a one-shot `saife migrate` (move `.sandbox` → `.saife`,
   `LOCALAPPDATA\sandbox` → `LOCALAPPDATA\saife`, leaving the DPAPI key intact
   because it moves within the same user) is cheaper than a dual-path reader.
   Recommendation: hard rename + migrate.
2. **Audit schema stays.** `op=CONNECT`, `FACADE`, `SESSION_START` are evidence
   vocabulary, not branding; renaming them would invalidate every existing chain
   for no gain.
