# Multi-parent `extends` — goal brief

> **Date:** 2026-10-25
> **Status:** proposed — goal description, ready for an implementer to turn into
> a plan/task dir. No code has been written for this yet.
> **Owner of the next step:** whoever picks up the plan in `docs/plans/`.
> **Related:** `docs/FAQ.md` (Gradle/JVM entry), `profiles/opencode.json`,
> `profiles/node-jvm.json`, `src/profile.rs`.
>
> **Status 2026-10-25:** implemented on `feature/multi-extends`. §5 decided the open
> question the hard way: `opencode.json` now extends `["node", "jvm"]`, the expanded
> output is byte-identical to the `node-jvm` chain it replaced, and
> `profiles/node-jvm.json` was deleted from the repo and from the installed profile
> store.

## 1. Goal

A profile must be able to inherit **more than one parent**:

```json
{
  "meta": { "name": "opencode", "version": "1.0.0", "schema_version": 1 },
  "extends": ["node", "jvm"]
}
```

`extends` today is `Option<String>` (`src/profile.rs:361`, resolved by
`load_raw_chain`). One parent means a workload that needs two unrelated
toolchains (an agent CLI needing both the Node and the JVM trees) has to chain
through an invented intermediate profile (`profiles/node-jvm.json` exists only
for that reason) — which restates one parent's slice by hand and then silently
drifts from it. That is the whole motivation: the sandbox has always been able
to combine toolchains (grants are just path sets); only the authoring schema
cannot express the composition.

Success is: `extends` accepts a string (unchanged) **or an array of names**, the
resolver merges every parent plus the child's own sections with the semantics
below, `saife profile show <name> --expanded` shows the merged result, and every
existing single-parent profile resolves **byte-identically** to today.

## 2. Required semantics (decisions — the implementer must not re-litigate)

1. **Array fields concatenate and dedupe** across all parents and the child:
   `filesystem.allow`, `filesystem.read_only`, `filesystem.deny`,
   `network.allow_domain`, `network.deny_domain` (reuse the existing merge and
   dedupe helpers; case-insensitive comparison where the current code is).
2. **Child scalars win** over parents (existing rule, unchanged): `meta`,
   `network.block_net` / `profile` / `promptEnabled` / `onUnavailable` /
   `upstreamProxy`, and every `limits.*` key.
3. **Parents must AGREE on scalars.** If two parents set the same scalar to
   different values and the child does not override it, the profile is
   **refused** with a message naming the key, both parents and both values —
   never last-parent-wins. Rationale is the repo's standing stance: a profile
   that silently loses a security- or budget-relevant value is worse than a
   parse error (precedent: the 2026-10-25 move of the deadline terms into
   `limits` *refuses* the old location rather than aliasing it).
4. **Merge order is irrelevant when values agree.** Parents resolve depth-first
   in list order, but the result must be order-insensitive for arrays and
   order-independent for agreeing scalars — a reordered `extends` array must not
   change behaviour, and a test must pin that.
5. **A profile reachable twice (diamond) merges once.** Dedupe by resolved
   profile path, not by name spelling.
6. **Cycle detection covers the DAG**, not only a chain: a cycle that runs
   through a diamond must still be refused, keeping the AC-5.6 error shape.
7. **Parent resolution rules are unchanged**: a parent is a profile name
   (→ `%USERPROFILE%\.saife\profiles\<name>.json`) or a path, exactly as today.
8. **Error style unchanged**: keep the `[saife] profile show: …` prefix and the
   existing context lines; add the scalar-conflict message (shape:
   `` `network.block_net` conflicts between parents `a` and `b`: true vs false
   `` — final wording at implementation, but it must name key + both parents +
   both values).
9. **No CLI change**: `--profile` still takes exactly one name. CLI flags
   (`--allow`, `--read-only`, `--allow-domain`) keep appending on top of the
   merged result, as they do now.

## 3. Non-goals

- A profile registry / remote resolution (future-ideas F-9).
- Multi-dimensional policy algebra (deny-over-grant recomputation beyond what
  the existing arrays already do).
- Version pinning of parents (no `name@version` syntax).
- Changing `--profile` to accept several names.
- Migrating existing profiles: single-parent files stay valid as written.

## 4. Acceptance criteria (executable)

1. **Composition fixture**: `a: {allow: [X]}`, `b: {allow: [Y]}`, `c extends
   ["a","b"]` → expanded `allow` = `[X, Y]` (both present, deduped if X == Y),
   and a scalar set only by a parent comes through.
2. **Child override**: the child's own scalar beats a parent's value (no error).
3. **Scalar conflict**: two parents disagreeing on `block_net` (child silent)
   → exit 1, message names key + both parents + both values. The same fixture
   with the child setting the value explicitly resolves fine.
4. **Diamond**: `d extends ["a","b"]` with both reaching `base` → `base` merges
   once (observable via duplicate dedupe and by the absence of a spurious
   conflict when `base` is reachable twice).
5. **Cycle through a diamond** is refused (existing cycle text shape).
6. **Regression**: for every profile shipped today (`node`, `jvm`, `node-jvm`,
   `opencode`, `demo`), `profile show <name> --expanded` is **byte-identical**
   before and after the change — capture the golden output first, then diff.
7. Gates: `cargo test --bin saife` (crate is bin-only), zero warnings from
   `cargo build --release` and `cargo clippy --release --all-targets`, strict
   TDD (red first: the string-or-array parse test and the conflict test are
   valid reds).

## 5. Touchpoints the implementer must cover

- `src/profile.rs`: `RawProfile.extends` (string-or-array, untagged or custom
  deserializer), `load_raw_chain` → iterate parents, cycle/seen bookkeeping for
  a DAG, scalar-conflict detection, error formatting; unit tests in the existing
  test module.
- Docs that assert the current single-parent rule (grep before bothering to
  search): `docs/USER-GUIDE.md` (profile section),
  `docs/DEVELOPERS.md` (profile resolution), `docs/FAQ.md` (if it repeats the
  rule), and the operator skill's `references/profile-authoring.md` — its
  "extends names a SINGLE parent" sentence becomes wrong the moment this lands.
  Replace the claim; do not append a correction beneath it.
- Profiles: after landing, `opencode` becomes `"extends": ["node", "jvm"]` and
  `node-jvm.json` can be deleted — or kept as a one-line convenience alias.
  Decide that in the plan, and update BOTH copies of every profile
  (`%USERPROFILE%\.saife\profiles\` and the tracked `profiles/` sample).

## 6. Why now (evidence)

2026-10-25, while wiring Gradle/npx for a sandboxed agent session: the session
needed `C:/nvm4w` (node shims, `npx.cmd`) **and** `~/.gradle` + the JDK tree +
Gradle/Maven domains. `extends` allows one parent, so `node-jvm.json` was
created restating the JVM slice; within the same hour the JVM deadline schema
changed (`network.workloadTimeoutSecs` → `limits.*`) and the restated copy in
`node-jvm.json` was instantly stale — it only failed loudly because the old
location is refused. Any restated slice has that failure mode; the fix is
composition, not discipline.
