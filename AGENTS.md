# sandbox

`sandbox` is a native Windows process-sandboxing tool that runs any program —
primarily AI coding agents (Claude Code, OpenCode, Codex, …) and their build
toolchains — with only the resources the user has explicitly granted.

The goal is a Windows-native equivalent of [nono](https://nono.sh/), but
without WSL: pure Win32 / NT kernel primitives, a single unprivileged Rust
binary, no container runtime, no daemon, no VM.

## MVP pillars

1. **Filesystem isolation** — irrevocable, kernel-enforced allow-lists
   (AppContainer + RuleSet).
2. **Audit trail** — tamper-evident Merkle-tree log of every operation,
   signed with an Ed25519 key.
3. **Network filtering** — default-deny outbound network with a domain
   allow-list, enforced by a localhost reverse proxy the sandboxed process
   is restricted to.

Out of scope for the MVP: undo/rollback, credential injection, ghost sessions,
runtime supervisor, Sigstore provenance, GUI/TUI, multi-user mode.

See `docs/prd/prd-sandbox.md` for the full product requirements and
`docs/critical-review.md` for a critical review of the chosen mechanism.

## Testing

Must follow: If a test needs to change anything on the host system, like setting permissions, ACLs or similar, 
before the change is performed a "rollback script" needs to be written. 
So in case the test is killed and the cleanup cannot be performed the user is able to clean up manually.