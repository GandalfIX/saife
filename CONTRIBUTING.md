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

## Commits

Conventional-commit subjects (`feat(profile): ...`, `fix(vm-tests): ...`,
`docs: ...`, `test: ...`, `chore: ...`), one logical change per commit, and a
body that says *why* when the diff cannot. Sign off your commits (`git commit -s`)
to certify the Developer Certificate of Origin; there is no CLA, and the licence
is MIT.

## Reporting security issues

Not here - see [SECURITY.md](SECURITY.md). A containment escape in a public issue
is a disclosure.
