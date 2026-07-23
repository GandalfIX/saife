# Sandbox specs

Per-user-story specification documents for the `sandbox` tool. Each
subdirectory corresponds to a user story from the PRD
(`../prd/prd-sandbox.md`) and is structured in three stages:

1. **Narrative + acceptance criteria** (current state)
2. **nono comparison** (next step — fill in the `## nono comparison` section
   of each spec)
3. **Implementation-ready detail** (final step — fill in the
   `## Implementation-ready detail` section)

## Specs

| US | Title | Spec |
|---|---|---|
| US-1 | Run a coding agent safely | [us-1-run-agent-safely/spec.md](us-1-run-agent-safely/spec.md) |
| US-2 | Build toolchain runs inside the sandbox | [us-2-build-toolchain/spec.md](us-2-build-toolchain/spec.md) |
| US-3 | Network exfiltration blocked | [us-3-network-exfiltration-blocked/spec.md](us-3-network-exfiltration-blocked/spec.md) |
| US-4 | Verify what the agent did | [us-4-verify-what-the-agent-did/spec.md](us-4-verify-what-the-agent-did/spec.md) |
| US-5 | Reusable, version-controlled policy | [us-5-reusable-version-controlled-policy/spec.md](us-5-reusable-version-controlled-policy/spec.md) |

US-6 (reject unsigned instructions) is explicitly post-MVP and is tracked in
[`../future-ideas.md`](../future-ideas.md) as feature F-5 (Sigstore Provenance).

## Document hierarchy

```
docs/
  prd/
    prd-sandbox.md          # Product Requirements Document (top level)
  specs/
    README.md              # this file
    us-1-run-agent-safely/spec.md
    us-2-build-toolchain/spec.md
    us-3-network-exfiltration-blocked/spec.md
    us-4-verify-what-the-agent-did/spec.md
    us-5-reusable-version-controlled-policy/spec.md
  future-ideas.md          # Post-MVP roadmap (deferred features)
```
