# Architectural review — SAIFE Sandbox (2026-10-25)

**Scope:** the whole crate at `cf76dc3`, reviewed on branch `review/arch-20261025`.
**Method:** five independent read-only reviewers (architecture, Rust idioms/errors,
unsafe/FFI/concurrency, tests/DX, security invariants). Every P0/P1 claim below was
then re-checked against the source by the reviewer of record; the *Verification*
column says who confirmed it. `V` = controller read the code and confirmed the
mechanism, `E` = reviewer evidence accepted without an independent read (line
numbers checked, mechanism not re-derived), `Q` = qualified/rejected.

**Verdict.** The containment core is competently written and the failure posture is
usually right. Three things are not: the **audit chain is not linearizable**, the
**loopback refusal can be walked around by DNS**, and the tool's **own control
plane sits inside the namespace it hands to workloads**. Structurally, there is no
library target, so the crate is three binaries that duplicate a protocol by string
literal, the session lifecycle exists twice and has already diverged, and 53 % of
the source is inline test code.

---

## 1. Measured baseline (controller's own numbers, not the reviewers')

| metric | value |
|---|---|
| lines `src/**/*.rs` | 41,635 in 33 files |
| inline test code | 22,230 lines (**53 %**) |
| largest production modules | `net/mxc.rs` 2,973 · `net/proxy.rs` 3,558 · `net/prompt.rs` 1,676 · `main.rs` 1,563 |
| test share, worst files | `mxc.rs` 71 % · `proxy.rs` 63 % · `upstream.rs` 54 % |
| production `unsafe` blocks | 84 (of 90 total) |
| production `unwrap()` / `expect()` | 24 / 14 |
| `#[allow(dead_code)]` | 31, of which 4 are module-wide |
| `#[allow(clippy::too_many_arguments)]` | 9 |
| `cfg(feature = …)` attributes | 32 |
| traits in the crate | **2** (`EnvProbe`, `ProxyProofSource`) |
| `lib.rs` | none — three `[[bin]]`, modules declared in `main.rs` |
| `rustfmt.toml` / `clippy.toml` / `[lints]` / `rust-version` / CI | none / none / none / absent / none |

---

## 2. Findings

### P0 — containment or evidence can be wrong today

**F-01 · The audit chain is not linearizable; concurrent appends fabricate TAMPERED. [V]**
`src/audit/mod.rs:145-178`. `append` takes `last_hash`, **takes the value out**
(`.take()`), releases the lock, writes the file, then re-locks to store the new
hash. Two appends in that window both observe `None` and both emit
`"parent": null`; `verify` reads a non-genesis null parent as `Tampered`
(`verify.rs:85-88`) and the committed root no longer matches. This is reachable:
the proxy runtime appends per connection (`proxy.rs:413/437`) while `ProxyHandle::drop`
flushes aggregates *before* cancelling the loop, and `shutdown_background()` does
not wait. `seq` is also allocated outside the critical section, so file order and
seq order can disagree, and verify does not check seq at all.
*Fix:* one `Mutex<ChainState { last, seq }>` held across compute → write → commit.
*Effort:* M.

**F-02 · Loopback is refused by host string only; a name that resolves to 127.0.0.1 tunnels to every host service. [V]**
`proxy.rs:1461` refuses `is_loopback_host(host)`; the resolved-address leg
(`pinned_addrs_hard_denied`, `proxy.rs:1819`) refuses only the metadata literals
plus `169.254/16` and `fe80::/10` (`matcher.rs:10-39`) — **there is no
`127.0.0.0/8`, no `0.0.0.0/8`, no `::1`**. `https://localtest.me` or
`https://127.0.0.1.nip.io` shows a harmless-looking name in the prompt, resolves to
127.0.0.1, and the proxy splices: Docker API (`:2375`), Ollama (`:11434`), DevTools
(`:9222`). This voids [G-44]'s stated purpose verbatim.
*Fix:* `is_loopback`/unspecified rejection on the pinned addresses, `loopback_refused`.
*Effort:* S.

**F-03 · `%USERPROFILE%\.saife` and `%LOCALAPPDATA%\saife` are on no deny list. [V]**
`PROFILE_SECRET_DIRS` is `[".ssh", ".aws", ".azure", ".gnupg"]` (`mxc.rs:687`);
the AppContainer deny set is built only from `filesystem.deny` (`allowlist.rs:99`).
`.saife` holds **the plugin manifests whose `command` is executed host-side**
(`plugin/mod.rs:270`, `sidecar.rs`), the learned-policy file that can add permanent
allows, and (next door) the audit log and the DPAPI-wrapped signing key. A profile
that grants `$HOME` — which the shipped `opencode` profile nearly does — lets the
workload rewrite a plugin that a later run executes outside the sandbox. That is a
full escape, not a leak.
*Fix:* deny `.saife` and `%LOCALAPPDATA%\saife` in both backends, with the existing
deny-covers-grant refusal. *Effort:* S.

### P1 — a documented guarantee is absent, or lost on one path

**F-04 · Two backends, one hardened. [V/E]** Built-in credential denies
(`mxc.rs:795`), deny-covers-grant refusal (`mxc.rs:826`), and guardrail 1
(`verify_proxy_proof`, called only from the mxc launch) exist **only on `--backend mxc`**.
The AppContainer path — the documented escape hatch for WinINet/PowerShell 5.1
workloads — has none of the three, so the documented properties are properties of
the default backend. USER-GUIDE:155 says credential dirs "stay denied even when
their parent is granted writable"; with `--backend appcontainer` that is false.

**F-05 · The audit proves possession of a local key, not the session's conduct. [E]**
No leaf carries `sid`; `verify` never compares `sid` or `seq`, and it derives the
public key from the **secret** key on the same disk (`verify.rs:132`). Copying a
clean session's three files over another's names verifies OK. Signature without a
recorded public key and without session binding is a checksum with extra steps.

**F-06 · The session lifecycle is implemented twice, and the copies diverge. [V/E]**
`main.rs:540` `run_inner` and `main.rs:852` `run_mxc_session` repeat the same eight
steps; plugins are refused on AppContainer but mounted on MXC; the tier probe
exists only on MXC. Same CLI flags, different semantics by backend.

**F-07 · No library target, so the cross-binary protocol is string literals. [V]**
No `src/lib.rs`; `PROBE_PATH` exists in `saife-launch.rs:319` and the proxy parses
that path independently. The env-key sets differ already
(`BLOCKED_ENV_KEYS` `[&str;4]` vs `RESERVED_ENV_NAMES` `[&str;5]`). Nothing can
link the supervisor, which is why the only integration tests are PowerShell.

**F-08 · Unbounded connection admission in the containment root. [V]**
No `Semaphore` in `proxy.rs`; the accept loop spawns per connection and the head
read has no deadline, so any local process (including the child) can open sockets
and send nothing. *Fix:* `timeout` around the head read + `try_acquire` cap.

**F-09 · `FreeSid` called on a Rust heap pointer. [V]** — `setup.rs:168` frees the
SID returned by `all_restricted_app_packages_sid()` (`setup.rs:203`), which is
`owned.leak().as_mut_ptr()` from a `Vec<u8>`. Wrong deallocator on the **elevated**
`--grant-drive-root` path: heap corruption, not a leak. The comment says the
opposite of what the code does.

**F-10 · Profile loading is untested and one argument is silently dropped. [V]**
`resolve_profile_path(name, _cwd)` ignores its `cwd` while its doc promises
"`./relative/path.json` → resolved against cwd". The load path
(`load_and_resolve` → `load_raw_chain` → `merge_profiles`) has no test that enters
through the wiring, so a regression that drops `check_cycle` stays green.

**F-11 · `parse_connect_target` fails open. [V]** — `proxy.rs:1844`:
`p.parse().unwrap_or(443)`, so `CONNECT host:notaport`, `host:` and `host:99999`
are all silently retried on 443 instead of refused with 400. Its sibling
`split_authority` refuses correctly and is the only one with tests.

### P2 / P3 — hygiene that will cost later

- **P2** `GuardError`'s five distinct causes collapse to one audit token
  `proxy_proof_unmet` (`main.rs:1220`), so the refusal that distinguishes a
  misconfigured operator from a silent client stack is erased from the record.
- **P2** Stringly-typed audit vocabulary: `Disposition` exists but is
  `#[cfg(test)]`; 13 `source:` literals, 9 `"deny"/"allow"`, inline reason strings
  next to named constants — a typo compiles and the leaf is invisible to `--filter`.
- **P2** 17-19 positional parameters with 6 same-typed bools (`main.rs:458/493/852`),
  forwarded 1:1 from a clap struct that already names them; every
  `too_many_arguments` allow is a receipt.
- **P2** Lock-poison policy is inconsistent: poison-recovering everywhere except
  `prompt.rs:1432`, `intent.rs:289`, and `audit/mod.rs:152` — the latter being the
  chain hash for every later append.
- **P2** SID/descriptor ownership hand-rolled four times, no `OwnedSid`, no
  scope guard: one early return already skips `LocalFree` (`appcontainer.rs:501`).
- **P2** The `CreateProcessW` environment block is appended to, never sorted
  (`appcontainer.rs:1018-1075`), against a documented contract.
- **P2** The plugin `operations` allowlist is parsed, documented as a control, and
  **never enforced** (`proxy.rs:3115` checks mount + method only).
- **P2** A relative `--plugin-dir` shadows a trusted global plugin with no warning.
- **P3** `EXIT_REFUSED = 126` collides with the launcher's `EXIT_USAGE = 126` and
  with any child that returns 126, defeating the "a script can tell" contract.
- **P3** `--sid` is unvalidated and used as a path component (`audit_log_path`).
- **P3** 4 module-wide `#[allow(dead_code)]` hide stale docs that claim modules are
  unreachable while production calls them (`intent.rs`, `learned.rs`).
- **P3** Wall-clock assertions (`prompt.rs:2346`, `proxy.rs:5870`) are the only
  flake surface; `SOURCES` exists only to be asserted.
- **P3** No CI, no `rustfmt.toml`, no `clippy -D warnings`, no `rust-version`; the
  gate numbers in `DEVELOPERS.md` are stale (611/490 vs the real 656/530).

### Qualified / rejected

- **`proxy.rs` is tokio, not `std::net` + threads** — my initial brief was wrong,
  and the reviewer corrected it. Shutdown is sound; the defect is admission (F-08).
- **"proxy has a second copy of the probe path literal"** — it parses
  `/sandbox/probe` in comments and by pattern, not via a duplicated constant; the
  duplication is the launcher constant plus the parser, weaker than claimed (F-07).
- **Deliberate, documented trade-offs** (not findings): `ui.disable = false`
  (D10), the sidecar's port TOCTOU (documented), the process-lifetime STA/ActCtx
  leak ("one bounded leak by design").

---

## 3. Remediation plan

**Phase 0 — stop the bleeding (est. 1-2 days, all small diffs, all testable)**
1. F-01 audit: `Mutex<ChainState>` held across the whole append; a concurrent-append
   test that runs verify afterwards (RED on today's code: two threads, 50 leaves).
2. F-01b: `serde_json` failure must be an error, never the literal `{}`; `scan_existing`
   failure must refuse to extend, never restart the chain silently.
3. F-02 loopback: add `127/8`, `0.0.0.0/8`, `::1`, `::` to the pinned-address deny;
   a test with `127.0.0.1` in the resolved set.
4. F-03 `.saife` denies in both backends + deny-covers-grant refusal.
5. F-09 `FreeSid` on the Rust pointer — return an owned allocation instead.
6. F-11 `parse_connect_target` → `Option<u16>`, refuse with 400.
7. F-10 `resolve_profile_path` honours `cwd`; add the five load-path tests.
8. F-06 partial: keep `run_inner` as the only orchestration and route the backend
   through it (the trait comes in Phase 2).

**Phase 1 — parity or an honest deprecation (2-4 days)**
- Either give AppContainer the three mxc-only invariants (F-04), or state in the
  USER-GUIDE and the ADR that AppContainer is *unproven* and keep it behind a
  flag. Both are defensible; shipping one backend's guarantees under the other's
  name is not.
- F-05: stamp `sid` into every leaf, check `seq` monotonicity in verify, record the
  public key beside the audit (not the secret), and sign `sid‖root`.

**Phase 2 — structure (1-2 weeks)**
- `src/lib.rs`; each bin becomes `fn main`. Move live tests to `tests/`.
- `Session` orchestrator + `Containment` trait; delete the second transaction script.
- Split `net/mxc.rs` (launcher/path/policy/attest/request/budget/child) and
  `net/proxy.rs` (http1 codec, control plane, listener, decision).
- Delete the six unused HTTP/TLS dependencies (hyper, hyper-util, http,
  http-body-util, rustls, rustls-native-certs) or adopt them; fix the module doc.
- Shared leaf module for `ProxyEnv`, `RunToken`, `Tier`, `SessionBudget`; break the
  net→plugin→sandbox→net cycle.

**Phase 3 — gates (1 day)**
- CI: both feature states, `clippy -- -D warnings`, `fmt --check`, MSRV pin.
- Purge the 4 module-wide `dead_code` allows; delete or wire what they hide.
- `proptest` for the six parsers on the containment boundary.

---

## 4. What is genuinely good

Worth saying because the phase plan should not rebuild it: the prompt path is
fail-closed on every branch (absent backend, timeout, closed channel, panic);
`RunToken`/`FacadeTarget` redact in `Debug`; deny-before-allow is one ordered
implementation shared by both the string and address legs; guardrail 1's
"attempted and nothing authenticated" rule is the correct shape; `ProxyHandle` and
`Job` are proper RAII; `saife-launch` handles its Win32 wait/close correctly; and
`DEVELOPERS.md` is a real module map rather than a directory listing.

---

## 5. Status after the fix pass (2026-10-25, branch `review/arch-20261025`)

| id | severity | state | what changed |
|---|---|---|---|
| F-01 | P0 | **fixed** | `ChainState { last, seq }` behind one mutex, held across compute → write → commit; a corrupt existing log is refused instead of restarted; the `"{}"` fallbacks are gone |
| F-02 | P0 | **fixed** | loopback/unspecified refused on the pinned addresses (`loopback_refused`), as policy — not in `is_hard_denied_ip`, which also feeds the dialer assertion |
| F-03 | P0 | **fixed** | `builtin_deny_dirs()` (credentials + `.saife` + `%LOCALAPPDATA%\saife`) used by both backends; granting inside one is refused |
| F-04 | P1 | **partial** | AppContainer now gets the same built-in denies and the deny-covers-grant refusal; guardrail 1 is still MXC-only, because it needs the wrapper/probe mechanism on a path that spawns the workload directly |
| F-05 | P1 | **partial** | leaves carry `sid`, verify checks `sid` and `seq` (closes substitution, which needs no key); verify still derives the public key from the on-disk secret — closing that needs a recorded public key and a decision on where it lives |
| F-06 | P1 | **deferred** | the two session scripts are one refactor with F-07 (a `Session` + `Containment` trait); doing it inside a fix pass would mix a rewrite with security fixes |
| F-07 | P1 | **deferred** | adding `src/lib.rs` moves every module path and makes the live tests integration tests; same pass as F-06 |
| F-08 | P1 | **fixed** | one permit per in-flight connection (refused, not queued) and a 15 s head deadline answering 408 |
| F-09 | P1 | **fixed** | `OwnedSid` frees with `FreeSid` in `Drop`; no more `Vec::leak` handed to a Win32 free |
| F-10 | P1 | **fixed** | a relative profile resolves against the session cwd; three tests now enter through `load_and_resolve` (three-level chain, relative path, missing parent) |
| F-11 | P1 | **fixed** | `parse_connect_target` returns `Option`; an unparsable port is a 400, not a silent 443; bracketed IPv6 stays legal |

Gates on this branch after the pass: **670 passed / 15 ignored** (default), **542 / 1**
(`--no-default-features`), clippy **0 warnings** in both states.

The three deferred items share one property: they are restructurings, not corrections.
F-04's guardrail leg needs a mechanism (the wrapper probe) that does not exist on the
AppContainer path; F-05's remaining half needs a key-management decision; F-06 and F-07
are the Phase 2 refactor and should not be done while security fixes are being verified.
