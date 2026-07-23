# US-4: Verify what the agent did

> **Status:** Draft — narrative + acceptance criteria stage.
> Next: compare with nono, then expand to implementation-ready.

## User Story

As a developer, after a sandboxed session ends I want to run
`sandbox audit show <session-id>` to see every file the agent touched, every
network call it attempted (allowed and denied), and every child process it
spawned — and I want a Merkle-root proof that the log was not tampered with.

## Narrative

Every sandboxed session gets a unique id of the form
`YYYYMMDD-HHMMSS-NNNNN` (e.g. `20260723-144521-48291`). While the session is
running, `sandbox.exe` writes an append-only audit log to:

```
%LOCALAPPDATA%\sandbox\audit\<session-id>.ndjson
```

One JSON object per line. Each line is a Merkle leaf: it contains the event
fields plus `hash` (SHA-256 of the canonicalized leaf body) and `parent` (the
hash of the previous leaf, `null` for the first). This forms a hash chain;
the chain's final hash is the **Merkle root** of the session.

At session end, the root is written to `<session-id>.root` and signed with an
Ed25519 keypair stored in
`%LOCALAPPDATA%\sandbox\signing\ed25519-key` (generated on first run,
protected at rest by DPAPI). The signature goes to `<session-id>.sig`.

The user can then:

- `sandbox audit show <id>` — human-readable summary: session header, total
  event count, deny count, list of files changed, network hosts contacted,
  child processes spawned, plus the root + signature verification status.
- `sandbox audit show <id> --json` — the raw structured log, suitable for jq
  or SIEM ingestion.
- `sandbox audit show <id> --filter "op=FILE_WRITE&disposition=denied"` —
  filtered subset.
- `sandbox audit verify <id>` — recompute the Merkle root from the .ndjson
  file, compare against the committed `.root`, check the Ed25519 signature
  on the `.sig`. Prints `OK` or `TAMPERED` with a description of the first
  mismatch.

If any line is modified, added, removed, or reordered, the recomputed root
differs from the committed one and verification fails — same construction as
git's object database and certificate-transparency logs.

### Event types recorded

| Event type | Source | Fields |
|---|---|---|
| `FILE_READ` | ETW / hook | path, disposition |
| `FILE_WRITE` | ETW / hook | path, disposition |
| `FILE_CREATE` | ETW / hook | path, disposition |
| `FILE_DELETE` | ETW / hook | path, disposition |
| `CONNECT` | proxy | host, port, disposition, reason |
| `EXEC` | ETW / WMI | path, args, disposition |
| `POLICY_VIOLATION` | supervisor | op, target, reason |

### Privilege discussion

ETW kernel providers (`Microsoft-Windows-Kernel-File`,
`Microsoft-Windows-Kernel-Process`) emit to any consumer but a real-time
consumer session with `EVENT_ENABLE_PROPERTY_SID` filter requires admin or
`SeSystemProfilePrivilege`. For non-admin users the MVP falls back to a
userspace hook (Detours-style `CreateFileW`/`NtCreateFile`/`connect`/`
CreateProcessW` interception in the spawned process via an injected DLL).
This is coarser (only the Win32 surface, not the raw NT layer) but
unprivileged. `sandbox setup --check-only` reports which path is active.

The hash chain, signing, and verification logic are identical regardless of
event source — only the event-capture fidelity differs.

## Scope (MVP)

In scope:

- Session-id generation (timestamp + counter).
- Append-only `.ndjson` log with hash-chain leaves.
- Event types `FILE_READ`, `FILE_WRITE`, `FILE_CREATE`, `FILE_DELETE`,
  `CONNECT`, `EXEC`, `POLICY_VIOLATION`.
- ETW consumer for admin users; userspace hook fallback for non-admin.
- Network events captured directly from the US-3 proxy (no ETW needed).
- Ed25519 keypair generation on first run, DPAPI-protected at rest.
- Root + signature commit on session end.
- `sandbox audit show` (human + `--json`), `--filter`, `sandbox audit verify`.
- `sandbox ps --json` shows the current/last session id.

Out of scope:

- Remote / centralized audit shipping (SIEM forwarder) — future-ideas F-13.
- Merkle tree proofs for individual leaves (inclusion proofs) — the MVP does
  full recompute; sublinear proofs are post-MVP.
- Multiple audit signing keys / key rotation — future-ideas.

## Acceptance Criteria

### AC-4.1 — Session id is unique and well-formed
**Given** two `sandbox run` invocations started in the same second,
**When** each generates its session id,
**Then** the ids are distinct (the counter disambiguates) and match
`^\d{8}-\d{6}-\d{5}$`.

### AC-4.2 — Log file is created on session start
**Given** a sandboxed session is running,
**When** the user lists `%LOCALAPPDATA%\sandbox\audit\`,
**Then** a file named `<session-id>.ndjson` exists and is growing as events
arrive.

### AC-4.3 — Each log line is a valid hash-chain leaf
**Given** any `.ndjson` file produced by `sandbox`,
**When** parsed as one JSON object per line,
**Then** every line has `hash`, `parent`, `seq`, `ts`, `op`, `disposition`
fields, `seq` is monotonically increasing from 0, `parent` of leaf N equals
`hash` of leaf N-1 (and `null` for the first leaf), and `hash` equals
SHA-256 of the line body excluding the `hash` and `parent` fields.

### AC-4.4 — File operations are recorded
**Given** a sandboxed process creates, writes, reads, and deletes a file
inside the allow-list,
**When** the session ends and the user runs `sandbox audit show <id>`,
**Then** the log contains `FILE_CREATE`, `FILE_WRITE`, `FILE_READ`,
`FILE_DELETE` events for that path with `disposition: "allowed"`.

### AC-4.5 — Denied operations are recorded
**Given** a sandboxed process attempts to read a denied path,
**When** the user runs `sandbox audit show <id>`,
**Then** the log contains a `FILE_READ` event with
`disposition: "denied"` for that path, and `sandbox audit show` prints it in
the "Denied operations" section.

### AC-4.6 — Network events come from the proxy
**Given** a sandboxed process makes allowed and denied network calls,
**When** the user runs `sandbox audit show <id> --filter "op=CONNECT"`,
**Then** the log contains `CONNECT` events with `disposition: "allowed"` for
allowed hosts and `disposition: "denied"` with `reason: "domain_not_allowed"`
or `reason: "denied_cidr"` for denied ones.

### AC-4.7 — Child-process spawns are recorded
**Given** the sandboxed process spawns `cmd`, `python`, and a `.bat` wrapper,
**When** the user runs `sandbox audit show <id> --filter "op=EXEC"`,
**Then** the log contains an `EXEC` event for each spawn with the path and a
truncated args string.

### AC-4.8 — Verify succeeds on an honest log
**Given** a session ended normally and produced `.ndjson`, `.root`, `.sig`,
**When** the user runs `sandbox audit verify <id>`,
**Then** the command prints `OK` and exits 0.

### AC-4.9 — Verify fails on a tampered log
**Given** the same session,
**When** the user flips one byte in the `.ndjson` file and runs
`sandbox audit verify <id>`,
**Then** the command prints `TAMPERED` with the leaf index and expected vs
actual hash, and exits non-zero.

### AC-4.10 — Verify fails on a truncated log
**Given** the same session,
**When** the user deletes the last 3 lines of the `.ndjson` file and runs
`sandbox audit verify <id>`,
**Then** the command prints `TAMPERED` (root mismatch) and exits non-zero.

### AC-4.11 — Verify fails on a forged root
**Given** the user replaces the `.root` file with a different (correctly
formatted) root,
**When** the user runs `sandbox audit verify <id>`,
**Then** signature verification fails (`BAD_SIGNATURE`) because the signature
was over the original root, and the command prints `TAMPERED` and exits
non-zero.

### AC-4.12 — Human-readable summary is useful
**Given** a session with 200 file events, 50 connects, 10 spawns, 5 denies,
**When** the user runs `sandbox audit show <id>`,
**Then** the output shows: session header (id, started, command), total
events by type, denied operations section with one line each, changed-files
list, hosts contacted, child processes spawned, root + signature status line.

### AC-4.13 — `--filter` works
**Given** the same session,
**When** the user runs `sandbox audit show <id> --filter "op=CONNECT&
disposition=denied"`,
**Then** only denied `CONNECT` events are printed, in order.

### AC-4.14 — First-run key generation
**Given** `sandbox` has never been run on this user profile,
**When** the user starts their first sandboxed session,
**Then** `%LOCALAPPDATA%\sandbox\signing\ed25519-key` is created, the session
is signed with it, and `sandbox audit verify` succeeds.

### AC-4.15 — Key is DPAPI-protected at rest
**Given** the ed25519 key file exists,
**When** the user inspects its raw bytes with `Get-Content` (not via `sandbox`),
**Then** the bytes are not a valid Ed25519 secret — they are DPAPI-encrypted
ciphertext. `sandbox.exe` is the only thing that can decrypt it via the
user's DPAPI master key.

### AC-4.16 — `setup --check-only` reports audit fidelity
**Given** the user is non-admin on Win10 22H2,
**When** they run `sandbox setup --check-only`,
**Then** the output includes a line like
`audit: userspace hook (non-admin) — file/process events captured at Win32 layer`
and, for an admin user,
`audit: ETW kernel providers (admin) — full-fidelity file/process/network events`.

### AC-4.17 — Audit log survives sandbox crash
**Given** a sandboxed session is running and `sandbox.exe` is killed
forcefully (`Stop-Process -Force`),
**When** the user runs `sandbox audit verify <id>`,
**Then** verification reports `INCOMPLETE: no committed root` (no `.root`
was written) but the `.ndjson` log up to the crash is still readable via
`sandbox audit show`. (The session is unverifiable but its raw event stream
is preserved.)

## nono comparison

### What we match

- **Merkle-root commitment at session end**: same construction — every
  operation is a leaf, ordered sequence of leaf hashes produces a root,
  root is committed and verifiable. Any modification, addition, removal,
  or reordering of a leaf produces a different root and fails verification.
- **Append-only log during session**: same — events stream to an append-only
  file, root is sealed at session end.
- **Event types recorded**: nono records file reads/writes/creates/deletes,
  network connection attempts (allowed/denied), command executions
  (allowed/denied), supervisor prompts/responses, policy violations. We
  match this set (`FILE_READ`, `FILE_WRITE`, `FILE_CREATE`, `FILE_DELETE`,
  `CONNECT`, `EXEC`, `POLICY_VIOLATION`). Supervisor prompts are deferred
  (future F-4) — when added, they become `POLICY_VIOLATION` or a new
  `SUPERVISOR` event type.
- **JSON export for SIEM / jq**: nono's `nono audit show --json` emits
  structured JSON. Our `sandbox audit show <id> --json` does the same —
  `.ndjson` is already line-delimited JSON.
- **Filtering by date range, operation type, disposition**: nono supports
  filter expressions; we match with `--filter "op=…&disposition=…&ts>=…"`.

### What we differ on (Windows-specific)

| Aspect | nono (Linux) | sandbox (Windows) |
|---|---|---|
| Event capture mechanism | Landlock violations are visible to the calling process (denied syscalls return `EACCES`); nono also hooks via seccomp-notify for allowed operations that match a logged policy. | **Two-tier**: admin users get ETW kernel providers (`Microsoft-Windows-Kernel-File`, `Microsoft-Windows-Kernel-Process`) for full-fidelity file/process events. Non-admin users get a userspace hook (Detours-style DLL injection trapping `CreateFileW`/`NtCreateFile`/`connect`/`CreateProcessW`). Documented in `setup --check-only` (AC-4.16). |
| Fidelity guarantee | Single mechanism, single fidelity level | Two fidelity levels depending on privilege. This is a forced divergence — Windows ETW kernel providers require admin for real-time consumer sessions with SID filtering. |
| Network event source | nono's proxy logs connections directly (same as us) | Same — our proxy (US-3) emits `CONNECT` events. No ETW needed for network. |
| Signing key storage | nono uses an Ed25519 keypair (implied by "cryptographic" commitment; specific storage not documented on the marketing pages) | Ed25519 keypair in `%LOCALAPPDATA%\sandbox\signing\`, DPAPI-protected at rest. Windows-specific storage mechanism. |
| Crash behavior | nono seals the root on clean exit; on crash the session is "incomplete" | Same — AC-4.17: on forced kill, no `.root` is written, `verify` reports `INCOMPLETE`, but the raw `.ndjson` is still readable. |

### What we add that nono doesn't document

- **Linear hash chain as degenerate Merkle tree**: nono's marketing says
  "Merkle tree" but the construction (ordered leaf sequence, root = hash of
  chain) is a linear hash chain — a degenerate Merkle tree with no branching.
  We use the same construction and **document it explicitly** as a hash chain
  rather than implying a balanced binary Merkle tree. A true balanced Merkle
  tree (with sublinear inclusion proofs) is post-MVP. The verification
  guarantee (tamper-evidence) is identical for both constructions; only proof
  generation efficiency differs.
- **Ed25519 signature on the root**: nono commits the Merkle root but their
  public docs don't specify the signature mechanism for the root itself. We
  sign the root with an Ed25519 keypair stored under DPAPI. This gives
  non-repudiation of the *commitment* (not just tamper-evidence of the log).
- **`--filter` grammar**: we specify a concrete filter grammar
  (`op=…&disposition=…&path~=…&host~=…&ts>=…&ts<=…`) rather than leaving it
  unspecified.
- **Two-tier fidelity reporting**: `setup --check-only` explicitly tells the
  user which audit path is active and what it captures. nono doesn't need
  this (single mechanism) but we do (privilege-dependent).

### What nono has that we explicitly defer

| nono feature | Status | Where deferred |
|---|---|---|
| Merkle tree with sublinear inclusion proofs (verify a single leaf without reading the whole log) | Deferred — MVP recompute is O(n) per verification | future F-1 / F-19 |
| Rekor transparency log integration (publish the root to a public append-only ledger for third-party verification) | Deferred — tied to Sigstore provenance | future F-5 |
| Centralized / remote audit shipping (SIEM forwarder) | Deferred | future F-13 |
| Multiple signing keys / key rotation | Deferred | future |

### nono's "What Gets Recorded" vs. ours

| nono records | We record (MVP) | Notes |
|---|---|---|
| File reads, writes, creates, deletes | ✅ all four | via ETW or userspace hook |
| Network connection attempts (allowed and denied) | ✅ `CONNECT` | from the proxy (US-3) |
| Command executions (allowed and denied) | ✅ `EXEC` | via ETW process provider or hook |
| Supervisor approval prompts and responses | ❌ deferred | Runtime Supervisor is future F-4 |
| Sandbox policy violations | ✅ `POLICY_VIOLATION` | emitted by the supervisor when a denied op is attempted and logged |

### Verification guarantee equivalence

nono: *"Any modification — even changing a single byte of a single operation
— produces a different root and fails verification."*

Our AC-4.9 (one byte flipped → `TAMPERED`), AC-4.10 (truncated log →
`TAMPERED`), AC-4.11 (forged root → `BAD_SIGNATURE` → `TAMPERED`) together
establish the same guarantee. The construction is identical; only the
signature-on-root step is an addition we make explicit.

## Implementation-ready detail (to be filled in last step)

TODO: exact ETW provider GUIDs, real-time session setup, userspace-hook DLL
injection mechanism, leaf canonicalization algorithm, Ed25519 sign/verify
crate, DPAPI storage format, filter expression grammar.

## Implementation-ready detail (to be filled in last step)

TODO: exact ETW provider GUIDs, real-time session setup, userspace-hook DLL
injection mechanism, leaf canonicalization algorithm, Ed25519 sign/verify
crate, DPAPI storage format, filter expression grammar.
