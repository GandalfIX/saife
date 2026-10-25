## What and why

<!-- One paragraph: what changes, and the problem it solves. -->

## Type

- [ ] fix
- [ ] feature
- [ ] refactor (no behaviour change)
- [ ] docs
- [ ] test / harness
- [ ] breaking (profile schema, CLI surface, exit code, default that weakens containment)

## Gates (paste the tails)

```
cargo test --bin saife                        ->
cargo test --bin saife --no-default-features  ->
cargo clippy --all-targets                    ->   (both feature states, 0 warnings)
```

- [ ] Tests were written first and failed for the right reason (or N/A: docs)
- [ ] A release build is clean: `cargo build --release --bin saife --bin saife-launch`
- [ ] CRLF preserved in touched `.rs`/`.ps1`/`.json`; no repo-wide `cargo fmt`
- [ ] New behaviour is covered by a test, including the refusal path
- [ ] Audit/log output contains no credential, URL userinfo or secret (use `[REDACTED]`)
- [ ] If this touches the VM lane: it ran locally, and the verdict line is pasted here
- [ ] Docs updated where the behaviour is described (USER-GUIDE / profiles/README)
- [ ] If the profile schema changed: `CHANGELOG` has a `Breaking` entry and the
      error message names the fix
