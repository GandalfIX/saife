# US-4: Verify what the agent did

> **Status:** Spec complete (US-4a implementation-ready). US-4b (FILE_*/EXEC
> event capture via ETW or userspace hook) is **split out** as a separate
> follow-up plan because the AppContainer enforcement model means the
> supervisor never observes denied file operations in-band — they return
> `EACCES` to the sandboxed process directly. Event capture therefore
> requires either ETW (admin) or Detours-style DLL injection (non-admin),
> both of which are large research-heavy subsystems. US-4a delivers the
> cryptographic core, signing, `audit show`, `audit verify`, the filter
> grammar, and full CONNECT-event coverage (CONNECT events already flow
> from US-3 via `src/audit.rs`).
>
> **Decisions locked (2026-07-27 review):**
> - **Split:** US-4a (crypto core) now; US-4b (FILE_*/EXEC capture) later.
> - **Leaf canonicalization (AC-4.3):** SHA-256 over the leaf re-serialized
>   with `hash` and `parent` removed, keys sorted alphabetically, no
>   whitespace (serde_json with `BTreeMap`-based serialization). See
>   "Leaf canonicalization" below.
> - **Root commit timing (AC-4.17):** `.root` and `.sig` are written **only
>   on clean child exit + supervisor reaching its return path**. No
>   best-effort Drop/panic write. Forced kill → no root → verify reports
>   `INCOMPLETE` (literal AC-4.17).
> - **`--json` output shape:** raw NDJSON stream (the `.ndjson` file
>   contents verbatim, one JSON object per line). Pipes directly to `jq -c`.
>   No wrapper object.
> - **Session-id counter (AC-4.1):** accept the existing probabilistic
>   generator (`nanos ^ pid % 100_000` in `src/main.rs:231`). The "counter
>   disambiguates" guarantee in AC-4.1 is satisfied probabilistically;
>   collisions are negligibly unlikely and detectable at verify time
>   (two sessions in the same second would still produce distinct files
>   by sid). A monotonic file-backed counter is post-MVP.

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
| `SESSION_START` | supervisor | sid, command, allow-list summary |
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

US-4 is split into two phases. This spec's MVP scope is **US-4a**; US-4b
is tracked under "Deferred to US-4b" below.

### US-4a — cryptographic audit core (in scope)

- Session-id generation (timestamp + counter). *(Already implemented in
  `src/main.rs:231` — `new_session_id`.)*
- Append-only `.ndjson` log with **hash-chain leaves**. US-3's
  `emit_connect` (`src/audit.rs:26`) currently writes raw NDJSON without
  `hash`/`parent`; US-4a wraps the writer to compute and append those
  fields on every line, retroactively hashing US-3 CONNECT lines too.
- Event types covered in 4a:
  - `SESSION_START` — emitted by the supervisor itself when a session
    begins (not by the sandboxed process). Carries the session id, command
    line, and resolved config summary. Ensures every session has at least
    one audit leaf so `verify` can always produce a root (matters under the
    US-3 loopback downgrade where no proxy starts and thus no CONNECT events
    are emitted).
  - `CONNECT` — from US-3 proxy (only when the proxy actually starts; under
    the US-3 loopback deferral, the proxy is downgraded to block-net and
    emits no CONNECT events).
  - `FILE_*` and `EXEC` are empty in 4a — they arrive in 4b.
- Ed25519 keypair generation on first run, DPAPI-protected at rest.
- Root + signature commit on session end (clean exit only).
- `sandbox audit show` (human + `--json`), `--filter`, `sandbox audit verify`.
- `sandbox ps --json` shows the current/last session id (best-effort:
  reads the most recent `.ndjson` in the audit dir).

### Deferred to US-4b — event capture (out of scope for 4a)

- ETW consumer for admin users (`Microsoft-Windows-Kernel-File`,
  `Microsoft-Windows-Kernel-Process`).
- Userspace hook fallback for non-admin (Detours-style DLL injection
  trapping `CreateFileW`/`NtCreateFile`/`CreateProcessW`).
- `FILE_READ`, `FILE_WRITE`, `FILE_CREATE`, `FILE_DELETE`, `EXEC`,
  `POLICY_VIOLATION` event types (4a reserves the schema for them but
  emits none).
- `setup --check-only` audit-fidelity reporting (AC-4.16) — reports
  `audit: not yet implemented in this slice` until 4b lands.

AC-4.4, AC-4.5, AC-4.7, AC-4.16 are **deferred to US-4b** and marked
SKIP in the 4a test harness with `Detail='deferred to US-4b'`.

### Out of scope (both phases)

- Remote / centralized audit shipping (SIEM forwarder) — future-ideas F-13.
- Merkle tree proofs for individual leaves (inclusion proofs) — the MVP
  does full recompute; sublinear proofs are post-MVP.
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

## Implementation-ready detail (US-4a)

### Leaf canonicalization (AC-4.3)

Each NDJSON line is a Merkle leaf. The `hash` field is computed as:

1. Parse the line as a `serde_json::Value` (object).
2. Remove the `hash` and `parent` keys.
3. Serialize the remaining object using `serde_json` with **alphabetical
   key ordering** — achieved by deserializing into a
   `BTreeMap<String, serde_json::Value>` and re-serializing. This is
   deterministic regardless of the original insertion order.
4. Compact serialization: no whitespace, no trailing newline.
5. `hash = SHA-256(canonical_bytes).hex()`.

The `parent` field is the `hash` of the previous leaf, or `null` for the
first leaf. The chain root (Merkle root) is the `hash` of the last leaf.

**Rationale:** alphabetical-key BTreeMap serialization is the simplest
deterministic canonicalization available without pulling a JSON canonical
form library (RFC 8785). It is sufficient for tamper-evidence: any
mutation of a leaf's fields changes its canonical bytes, which changes
its hash, which breaks the chain at the next leaf.

### Audit writer seam

US-3's `emit_connect` (`src/audit.rs:26`) currently writes raw NDJSON.
US-4a replaces the writer internals with a hash-chain-aware emitter
while keeping the public signature stable so `src/net/proxy.rs` needs
no changes. The new structure:

```rust
// src/audit.rs (revised)
pub struct AuditWriter {
    path: PathBuf,
    last_hash: Mutex<Option<String>>,  // previous leaf's hash, or None
    seq: AtomicU64,
}

impl AuditWriter {
    pub fn open(session_id: &str) -> Self { /* create dir, init last_hash by
        scanning existing lines (for --reuse / crash recovery) */ }

    /// Append a leaf. `event` is the op-specific payload (op, host, path,
    /// etc.) WITHOUT hash/parent/seq/ts — those are added here.
    pub fn append(&self, mut event: serde_json::Map<String, Value>) {
        let seq = self.seq.fetch_add(1, Ordering::Relaxed);
        let ts = iso8601_utc();
        event.insert("seq".into(), json!(seq));
        event.insert("ts".into(), json!(ts));
        // canonicalize: remove hash/parent (not present yet), sort keys via BTreeMap
        let canonical = canonicalize(&event);
        let hash = sha256_hex(&canonical);
        let parent = self.last_hash.lock().take();
        event.insert("hash".into(), json!(hash));
        event.insert("parent".into(), json!(parent));
        let line = serde_json::to_string(&event).unwrap();
        // append line + '\n' to file (OpenOptions append)
        *self.last_hash.lock() = Some(hash);
    }
}
```

The existing `emit_connect` becomes a thin wrapper that constructs the
event map and calls `writer.append(...)`. The writer is held in a
`OnceCell<AuditWriter>` keyed by session id, or threaded through the
`run_inner` call chain. Threading is cleaner (no global state); see
the plan's task breakdown.

### Ed25519 signing

- **Crate:** `ed25519-dalek` (`=2.1`, `rand_core` feature for keypair
  generation; we feed `OsRng` which on Windows uses `BCryptGenRandom`).
- **Keypair file:** `%LOCALAPPDATA%\sandbox\signing\ed25519-key`.
- **Format at rest:** DPAPI-encrypted bytes of the 32-byte secret key.
  `CryptProtectData` with `CRYPTPROTECT_LOCAL_MACHINE` **unset** (user
  scope) — only the same user on the same machine can decrypt.
  - Raw bytes layout: 32 bytes secret key. We store the secret key only
    (public key is derived via `VerifyingKey::from(&secret)`).
  - DPAPI call via `windows::Win32::Security::Cryptography::CryptProtectData`
    (feature `Win32_Security_Cryptography`, already enabled in Cargo.toml).
- **On first run:** generate keypair, encrypt, write to file with
  `0600`-equivalent ACL (restrictive DACL: owner + SYSTEM only). The
  restrictive ACL is best-effort; DPAPI provides the primary protection.
- **Root signature:** at session end, compute the chain root (last
  leaf's `hash`), sign it with the secret key, write:
  - `<sid>.root` — the 32-byte root as lowercase hex (64 chars + trailing newline).
  - `<sid>.sig` — the 64-byte Ed25519 signature as lowercase hex (128 chars + trailing newline).

### `audit verify` algorithm

```
fn verify(sid) -> Result<VerifyOutcome> {
    let ndjson = read all lines from <sid>.ndjson
    if ndjson.is_empty() { return INCOMPLETE_NO_EVENTS }

    let mut prev_hash: Option<String> = None
    let mut computed_root: Option<String> = None
    for (i, line) in ndjson.lines().enumerate() {
        let leaf: Value = parse(line) or return TAMPERED { leaf: i, reason: "invalid_json" }
        let stored_hash = leaf["hash"].as_str() or return TAMPERED { leaf: i, reason: "missing_hash" }
        let stored_parent = leaf["parent"].as_str() (or null)
        // recompute hash over canonical body minus hash+parent
        let canonical = canonicalize(leaf minus hash+parent)
        let recomputed = sha256_hex(canonical)
        if recomputed != stored_hash { return TAMPERED { leaf: i, expected: stored_hash, actual: recomputed } }
        // check parent linkage
        match (&prev_hash, &stored_parent) {
            (None,    Null)     => {}  // genesis ok
            (Some(p), Some(sp)) if p == sp => {}  // link ok
            _ => return TAMPERED { leaf: i, reason: "parent_mismatch" }
        }
        prev_hash = Some(stored_hash.to_string())
        computed_root = Some(stored_hash.to_string())
    }

    let committed_root = read <sid>.root or return INCOMPLETE_NO_ROOT { events: ndjson.len() }
    if committed_root != computed_root { return TAMPERED { reason: "root_mismatch" } }

    let sig_hex = read <sid>.sig or return BAD_SIGNATURE { reason: "no_sig_file" }
    let sig = decode_hex(sig_hex) or return BAD_SIGNATURE { reason: "sig_not_hex" }
    let pubkey = derive_public_key(secret_key) or read signing key file & decrypt
    if !pubkey.verify(computed_root_bytes, &sig) { return BAD_SIGNATURE }

    return OK
}
```

Exit codes: `OK` → 0; `TAMPERED`/`BAD_SIGNATURE`/`INCOMPLETE*` → 1.

### `audit show` output

**Human-readable (default):**

```
Session 20260723-144521-48291
Started  2026-07-23T14:45:21Z
Command  cmd /c echo hello

Events by type:
  CONNECT    12  (10 allowed, 2 denied)

Denied operations:
  CONNECT evil.example.com:443  reason=domain_not_allowed
  CONNECT 169.254.169.254:80    reason=denied_cidr

Hosts contacted (allowed):
  api.anthropic.com:443   x8
  registry.npmjs.org:443  x2

Root    3a7f...e1b2
Sig     OK (verified)

Total events: 12
```

**`--json`:** the raw `.ndjson` file contents verbatim (one JSON object
per line, no wrapper). This is already line-delimited, so `jq -c` works
directly. The human summary is not emitted in `--json` mode.

**`--filter "expr"`:** filters the *displayed* events (does not affect
the log file or the root). Applied after reading the .ndjson, before
output. See filter grammar below.

### Filter grammar (AC-4.13)

A minimal `key=value` grammar, `&`-separated (no URL-encoding needed;
values are matched as substrings for `~=` and exact for `=`):

```
filter      := clause ( "&" clause )*
clause      := key ( "=" | "~=" | ">=" | "<=" ) value
key         := "op" | "disposition" | "host" | "path" | "ts" | "pid" | "seq"
value       := bare-string   // no & or = chars; values with those need
                             // not be supported in MVP
```

Semantics:
- `op=CONNECT` — exact match on the `op` field.
- `disposition=denied` — exact match on `disposition`.
- `host~=anthropic` — substring match on `host` (case-insensitive).
- `path~=src/` — substring match on `path` (case-insensitive).
- `ts>=2026-07-23T14:00:00Z` — ISO-8601 string comparison (lexicographic
  works for UTC `Z`-suffixed timestamps of the same format).
- `ts<=...` — symmetric.
- `pid=1234` — exact integer match.
- `seq>=100` — integer comparison.

Multiple clauses AND together (no OR in MVP). An empty or missing
`--filter` returns all events. Malformed filters cause `audit show` to
exit non-zero with a diagnostic (no silent "return everything").

Implementation: a `Filter` struct parsed from the string, with an
`matches(leaf: &Value) -> bool` method. Pure function, unit-tested.

### Session end / root commit

In `run_inner` (`src/main.rs:100`), after `sandbox::spawn` returns the
child exit code:

1. Flush the audit writer (drop the `AuditWriter` handle, which closes
   the file).
2. Compute the root from the last leaf's `hash`.
3. Load (or generate) the Ed25519 secret key, decrypt via DPAPI.
4. Sign the root, write `<sid>.root` and `<sid>.sig`.
5. Return the child's exit code.

If the supervisor is killed (Ctrl-C, `Stop-Process -Force`, panic) the
`.root` and `.sig` are **not** written — AC-4.17. The `.ndjson` up to
the last flushed append is preserved on disk; `audit show` can still
read it; `audit verify` reports `INCOMPLETE: no committed root`.

### `sandbox ps` (minimal)

`Cmd::Ps` is currently a stub (`src/main.rs:41`). 4a implements a
minimal version: scan `%LOCALAPPDATA%\sandbox\audit\*.ndjson`, pick the
newest by mtime, print its sid. `--json` emits `{"session_id": "<sid>",
"running": false}`. `--all` lists all sids found. "Running" detection
(whether a `sandbox.exe` is alive for that sid) is not implemented in
4a — `running` is always `false`. (True running detection needs a PID
file or named-pipe heartbeat; deferred.)

### File map

- `Cargo.toml` — add `ed25519-dalek = { version = "2.1", features =
  ["rand_core"] }`, `sha2 = "0.10"`. DPAPI uses the already-enabled
  `Win32_Security_Cryptography` feature.
- `src/audit.rs` — rewrite: `AuditWriter` struct, `append()` with
  hash-chain computation, `canonicalize()`, `sha256_hex()`. Keep
  `emit_connect` as a thin wrapper. Keep `audit_log_path`,
  `Disposition`, `iso8601_utc`, `civil_from_days`. The static `SEQ:
  AtomicU64` moves into the `AuditWriter` instance.
- `src/signing.rs` (new) — `ensure_keypair() -> SecretKey`, `sign_root
  (sk, root_bytes) -> SignatureBytes`, `verify_root(pk, root, sig) ->
  bool`, DPAPI encrypt/decrypt wrappers, file I/O with restrictive ACL.
- `src/audit/show.rs` (new) — `run_show(sid, json, filter) -> i32`.
  Human summary + `--json` (raw NDJSON dump) + `--filter`.
- `src/audit/verify.rs` (new) — `run_verify(sid) -> i32`. Implements
  the algorithm above. Returns `OK`/`TAMPERED`/`BAD_SIGNATURE`/
  `INCOMPLETE*`.
- `src/audit/filter.rs` (new) — `Filter` struct, `parse(expr) ->
  Result<Filter>`, `matches(leaf) -> bool`.
- `src/audit/mod.rs` (new) — re-exports. The existing `src/audit.rs`
  becomes `src/audit/mod.rs` with the writer + `emit_connect` staying,
  and `show.rs`/`verify.rs`/`filter.rs` as siblings.
- `src/cli.rs` — `AuditAction::Show` and `Verify` already exist; no
  changes needed.
- `src/main.rs` — replace `Cmd::Audit => stub_not_implemented("audit")`
  and `Cmd::Ps => stub_not_implemented("ps")` with real dispatchers.
  In `run_inner`: thread an `AuditWriter` through to `net::proxy::spawn`
  (replacing the `session_id: String` arg with `writer: Arc<AuditWriter>`
  so the proxy appends directly), and add the post-spawn root-commit
  block.
- `src/net/proxy.rs` — change `emit_connect(sid, ...)` calls to
  `writer.append(...)`. The `AuditWriter` is `Clone` (wraps `Arc`).
- `src/setup.rs` — update the two "not yet implemented in this slice"
  lines: ETW line stays (deferred to 4b); Ed25519 line becomes
  "Ed25519 signing key        : <present|absent>" by probing the key
  file path.
- `tests/run-tests.ps1` — add S-43..S-55 for AC-4.1, 4.2, 4.3, 4.6,
  4.8, 4.9, 4.10, 4.11, 4.12, 4.13, 4.14, 4.15, 4.17. Mark S-44, S-45,
  S-47, S-16 (AC-4.4, 4.5, 4.7, 4.16) as SKIP with `Detail='deferred
  to US-4b'`.

### Test commands (integration tests S-43 .. S-55)

| AC | Scenario | Command in harness | Assert |
|---|---|---|---|
| 4.1 | S-43 | two `sandbox run --print-sid` in the same second | sids are distinct, match `^\d{8}-\d{6}-\d{5}$` |
| 4.2 | S-44 | `sandbox run --allow-cwd --block-net -- cmd /c echo hi`, then list audit dir | `<sid>.ndjson` exists and is non-empty |
| 4.3 | S-45 | run any session, parse each `.ndjson` line | every line has `hash`,`parent`,`seq`,`ts`,`op`,`disposition`; `seq` monotonic from 0; `parent[N] == hash[N-1]`; `hash == sha256(canonicalize(leaf minus hash+parent))` |
| 4.4 | (SKIP) | — | `Detail='deferred to US-4b (FILE_* capture)'` |
| 4.5 | (SKIP) | — | `Detail='deferred to US-4b (FILE_* capture)'` |
| 4.6 | S-46 | `sandbox run --allow-cwd --block-net -- cmd /c python -c "...urllib..."` (skip if no python), then `audit show <sid> --filter op=CONNECT` | log has CONNECT events with `disposition=denied` (block-net denies all) |
| 4.7 | (SKIP) | — | `Detail='deferred to US-4b (EXEC capture)'` |
| 4.8 | S-47 | run a session to clean exit, `audit verify <sid>` | prints `OK`, exit 0 |
| 4.9 | S-48 | flip one byte in `<sid>.ndjson` line 2, `audit verify <sid>` | prints `TAMPERED` with leaf index, exit 1 |
| 4.10 | S-49 | delete last 3 lines of `<sid>.ndjson`, `audit verify <sid>` | `TAMPERED` (root mismatch), exit 1 |
| 4.11 | S-50 | replace `<sid>.root` with a different valid-format root, `audit verify <sid>` | `BAD_SIGNATURE`, exit 1 |
| 4.12 | S-51 | run a session with ≥5 CONNECT events, `audit show <sid>` | output has session header, events-by-type, denied section, hosts contacted, root+sig line |
| 4.13 | S-52 | `audit show <sid> --filter "op=CONNECT&disposition=denied"` | only denied CONNECT events, in order |
| 4.14 | S-53 | delete `%LOCALAPPDATA%\sandbox\signing\`, run a session, check file exists, `audit verify <sid>` | key file created, verify OK |
| 4.15 | S-54 | `Get-Content -Raw ed25519-key`, try to parse as Ed25519 secret | not a valid secret (DPAPI ciphertext) |
| 4.16 | (SKIP) | — | `Detail='deferred to US-4b (audit fidelity reporting)'` |
| 4.17 | S-55 | start a session, `Stop-Process -Name sandbox -Force`, `audit verify <sid>` | `INCOMPLETE: no committed root`, exit 1; `audit show <sid>` still readable |
