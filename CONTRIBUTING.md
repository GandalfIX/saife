# Contributing

Thanks for looking. This is a small project with a strict gate; the gate is the
point, because the product's claim is that it contains things.

## Build and test

```powershell
cargo build --release --bin saife --bin saife-launch
cargo test --bin saife                        # unit tests
cargo test --bin saife --no-default-features  # the feature-less build must also work
cargo clippy --all-targets                    # must be 0 warnings, both states
```

Two things the default build order will trip you on:

- **Rebuild with default features before probing the CLI by hand.** A
  `--no-default-features` run leaves a feature-less binary in `target/debug`, and
  every later manual check answers for the wrong build.
- **The VM lane is local on purpose.** `tests/vm/` needs Hyper-V and a guest
  image; CI cannot run it. A green CI run does not replace it.

A fresh machine sets itself up with `pwsh -File start-develop.ps1 -Install` (build
prerequisites plus the analysis tools; never elevated). Before opening the pull
request, run the local analysis pass — details and the failure playbook in
`docs/DEVELOPERS.md`, §4:

```powershell
cargo deny check                        # advisories, licenses, duplicates (deny.toml)
cargo shear                             # unused dependencies
cargo mutants --list --file src/signing.rs   # then drop --list to actually run it
```

## House rules

- **Tests first.** Write the failing test, watch it fail for the right reason,
  then implement. Pure refactors are exempt but must be covered by existing
  tests.
- **Zero warnings.** `cargo build --release` and `cargo clippy --all-targets`
  must both be clean, in both feature states.
- **CRLF.** Rust, PowerShell and JSON files are CRLF in the working tree. Do not
  run a repo-wide `cargo fmt`; format touched files only and keep the endings.
- **Audit vocabulary is product surface.** `SESSION_START`, `SESSION_REFUSED`,
  `CONNECT`, `HTTP`, `FACADE`, and the exit codes 0/2/5/124/126 have documented
  meanings; changing them is a breaking change.
- **Never log secrets.** Proxy URLs carry the session token as userinfo; it must
  never reach the audit, a log line, or an error message. Use `[REDACTED]`.
- **Plans live in `docs/plans/`, progress in `docs/tasks/<name>/PROGRESS.md`.**
  Decisions that will be argued about later go in `docs/adr/`.

## Branches and pull requests

Nothing lands on `main` directly. Branch, push, open a pull request, and merge it once
CI is green:

```bash
git switch -c fix/<slug>
git push -u origin fix/<slug>
gh pr create --fill --base main
```

The gate on the pull request is `.github/workflows/ci.yml` (both feature states, clippy
in both, a release build). The VM lane stays local - see below.

The ruleset `main-protection` enforces that path. A pull request is required for
`main`, and three checks must be green before it can be merged: `test`, `CodeQL` and
`Analyze (rust)`. **No approving review is required** - and none can be supplied on a
solo repository, because GitHub does not let an author approve their own pull request.
The ruleset has no bypass actors, so this applies to the maintainer too: documentation
and `docs/tasks/*/PROGRESS.md` updates travel by pull request like everything else. If a
check is red for an unrelated reason, fix the check or amend the ruleset - do not add
yourself as a bypass.

Keep the single commit identity (`gandalfix@gandalfix.de`): a commit whose author email
is not linked to a GitHub account counts as *unattributed*, and the ruleset asks for an
extra approval for those - which a solo maintainer cannot give.

## Commits

Conventional-commit subjects (`feat(profile): ...`, `fix(vm-tests): ...`,
`docs: ...`, `test: ...`, `chore: ...`), one logical change per commit, and a
body that says *why* when the diff cannot. Sign off your commits (`git commit -s`)
to certify the Developer Certificate of Origin; there is no CLA, and the licence
is MIT.

## Reporting security issues

Not here - see [SECURITY.md](SECURITY.md). A containment escape in a public issue
is a disclosure.
