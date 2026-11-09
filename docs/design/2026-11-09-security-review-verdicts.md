# Security review 2026-11-09 — independent verdicts

- **Status:** verdicts complete; fixes not started.
- **Basis:** `0a55236` (`feat/ssh-gateway-plugin`, PR #39 head), branch `security/review-20261109`.
- **Review under test:** an external security review with 39 points (2 Critical, 5 High,
  16 Medium, 16 Low). Point ids below are that review's ids.
- **Method:** 18 independent reviewers, each read-only, each told to falsify its point
  rather than confirm it. Every verdict cites the code, not the review. Junction
  semantics, `Content-Length` handling and the Rust `FileType` classification were
  probed empirically, not reasoned from documentation.
- **Rules:** nothing was pushed. No production code was changed to produce this
  document.

## Summary

| Verdict | Count (42 sub-verdicts) |
|---|---|
| Confirmed | 29 |
| Partially confirmed | 12 |
| Wrong | 1 (H1) |

Severity moves: H1 **wrong**, H2 High→Medium, H3 High→Low/Medium, H4 High→Medium,
M5 headline wrong (residual Low). C1 and C2 stand at Critical.

Two findings matter more than their id suggests:

- **M14 is a functional stop-ship**: the shipped `ssh-gateway` manifest cannot be
  parsed, so the plugin never ran. It is a one-character fix plus a missing test.
- **H5d is understated**: a failed non-strict audit write still advances the chain,
  so an honestly degraded log can verify as `TAMPERED`.

## Verdict table

Rows marked *fix* carry a red test in the implementation plan (§ Implementation).
`evidence` paths are relative to the repo root at `0a55236`.

### Critical

| id | verdict | one-line finding |
|---|---|---|
| C1 | **confirmed** | Every profile/builtin deny ACE is written with mask `0`, so it denies nothing on the AppContainer backend. Credential read is fully exploitable. |
| C2 | **confirmed** | Build-runner sync-out unpacks through a workload-planted junction into any user-writable host path. |

### High

| id | verdict | one-line finding |
|---|---|---|
| H1 | **wrong** | `is_dir()` is false for junctions (they classify as symlinks), so `walk` never recurses into one; the pack fails instead. A symlink-to-file vector remains, privilege-gated. |
| H2 | partial → **Medium** | Chained dials really skip resolution and hard-deny checks. Real for the loopback bridge, but operator opt-in; `[G-22]`'s rationale is unsound, not the mechanism. |
| H3 | partial → **Low/Medium** | No `env_clear`; docstring lies. But a malicious plugin is already supervisor-privileged code and the workload cannot install one. |
| H4 | partial → **Medium** | Reader-side sid path traversal is real but suffix-locked (`*.ndjson`, `*.root`) and same-user. Fix at the two entry points. |
| H5a | **confirmed** | No cross-process lock: two writers on one sid fork the chain, and `verify` calls an unedited log `TAMPERED`. No `--reuse` flag exists; the vector is `--sid`. |
| H5b | **confirmed** | `.root` and `.sig` are two separate writes; a kill between them leaves an inconsistent pair. Fails loudly, tiny window. |
| H5c | **confirmed** | A sealed append returns `Ok(())`, so the proxy's trailing refusal aggregate is silently dropped on every clean exit — the "sums to the true total" invariant is already broken. Test at `mod.rs:751-790` codifies the drop. |
| H5d | **confirmed, understated** | Non-strict write failures are swallowed **and** the chain still advances, so the next leaf names a parent that is not in the file → false `TAMPERED`. |

### Medium

| id | verdict | one-line finding |
|---|---|---|
| M1 | **confirmed** | `:write` and `:execute` are parsed, then discarded into the RWX list; `USER-GUIDE.md:131` promises "write only". |
| M2 | partial | `.npmrc` read-only and `.gradle`/`.m2` RWX are real; security groups are RX not RWX; `.npmrc` is an inherent trade-off. Fix with per-file descendant denies. |
| M3 | **confirmed** | Credential denies derive from `USERPROFILE`; unset → all four vanish on both backends, repointed → wrong tree denied. |
| M4 | **confirmed** | Unreadable DACL journal parses as empty, reports success, and is then deleted — the comment states the opposite. |
| M5 | partial | `.sandbox/<sid>` is already PROTECTED. Residual: `.sandbox` itself inherits RWX, allowing sibling enumeration/rename. |
| M6 | **confirmed** | `audit verify` mints a new signing key when the file is missing; key loss and tampering become the same verdict. |
| M7 | **confirmed** | The promised key DACL does not exist, no DPAPI entropy, no fingerprint. Real issue is the false claim and a missing `KEY_CHANGED`. |
| M8 | **confirmed** | An allow leaf precedes the dial that can deny it; one request can produce allow+deny with no correlation id; `show` counts both. |
| M9 | **confirmed** | No RFC1918/CGNAT/ULA deny on resolved IPs (direct path). Loopback *is* denied; LAN reach needs an escape hatch. |
| M10 | **confirmed** | Build log retains an uncapped `Vec<String>` and an uncapped partial line; only the build deadline bounds it. |
| M11 | partial | Shared `/cache` is RW and unguarded → cross-session code execution. This is the plan's declared accepted limit; a read-only mount breaks Gradle. |
| M12 | **confirmed** | No memory/CPU/PID/user limits; builds run as root. Tracked as T2.5. |
| M13 | **confirmed** | `StrictHostKeyChecking=accept-new` with no plugin-local `known_hosts`: TOFU, appends to the user's real file. The empty `ssh_config` blocks `~/.ssh/config` only. |
| M14 | **confirmed** | `"max_concurrent": 4` cannot deserialize into `BTreeMap<String,String>` → `plugin_manifest_invalid`; the plugin is unrunnable. |
| M15 | **confirmed** | Declaration matches the query-stripped path, relay keeps the query. Latent (shipped sidecars 404 on any query). |
| M16 | partial | `Content-Length: -1` does reach `read(-1)`, but the facade writes its own valid length and the token gates first; workload cannot trigger it. |

### Low

| id | verdict | one-line finding |
|---|---|---|
| L-A | **confirmed** | `CONNECT user@host:443` keeps userinfo into policy matching; dies at the resolver today. Reject `@`. |
| L-B | **confirmed** | `Proxy-Authenticate` is relayed on any status except 407; request-side strip prevents a real credential leak. |
| L-C | **confirmed** | No timeout on `read_body`; 128 authenticated connections can park every permit for the session. Self-DoS. |
| L-D | **confirmed** | Runner token compared with `!=` while the proxy uses `ct_eq`. No realistic timing oracle; consistency fix. |
| L-E | partial | No read timeout/connection cap, but the facade frames every request; only host-local or opt-in loopback exposure. |
| L-F | **confirmed** | Case-sensitive sid compare on case-insensitive NTFS → self-inflicted `TAMPERED`. Fails closed. |
| L-G | **confirmed** | `decode_hex` byte-slices a `&str`; a non-ASCII `.sig` panics `audit verify` (exit 101) instead of a verdict. |
| L-H | partial | `sid`/`seq` are checked only when present; stripping them from a leaf breaks the hash anyway, so this is defense-in-depth. |
| L-I | **confirmed** | `audit show` prints `Sig OK` from file existence alone. |
| L-J | partial | Torn tail blocks the run, but "forever" is false and the error already names the remedy (move the file aside). Truncation would be worse. |
| L-K | **confirmed** | Pre-epoch clock stamps 1970. Unreachable on Windows (1980 floor); no integrity impact. |
| L-L | **confirmed, understated** | Key bytes are unwiped **and** `ed25519-dalek`'s `zeroize` feature is disabled in `Cargo.toml`, so even its own Drop does not scrub. |
| L-M | **confirmed** | `ssh` resolves through PATH with the plugin dir as cwd; write access to that dir is already game-over. Resolve absolute. |
| L-N | partial | `paths` reaches log lines unfiltered, but Win32 forbids newlines in file names and build output can forge lines anyway. |
| L-O | partial | ACE restore **is** implemented (journal); only `.sandbox/<sid>` dirs accumulate and `AGENTS.md:156` is stale. |
| L-P | **confirmed** | Releases unsigned, checksum same-origin, no `cargo deny`/CodeQL. Documented D2 deferral; cheapest step is a pinned minisign key. |

## Critical detail

### C1 — AppContainer deny ACEs deny nothing

**Evidence.** `src/sandbox/allowlist.rs:136-155` pushes every profile deny and every
builtin deny with `access = 0` (`push_entry` hardcodes `inherit = true`).
`src/sandbox/appcontainer.rs:270-288` passes that value into
`EXPLICIT_ACCESS_W { grfAccessPermissions: 0, grfAccessMode: DENY_ACCESS }` with the
AppContainer SID as trustee. A zero-mask deny intersects no requested rights: it is a
no-op ACE. `git log -L 136,155` shows the mask has been zero since the MVP, so the
comment at `allowlist.rs:111-116` ("fixed") never held for this backend.

The builtin set is real — `profile.rs:250-261` lists `~/.ssh`, `~/.aws`, `~/.azure`,
`~/.gnupg`, `~/.saife`, `%LOCALAPPDATA%\saife`. The pre-flight only refuses a grant
*inside* a deny (`allowlist.rs:117-134` → `profile.rs:266-276`), so
`--allow "$USERPROFILE"` passes, and the inherited RWX allow reaches all six.
The tests at `allowlist.rs:887-930` assert that the deny entry exists, never that its
mask is non-zero. `should_propagate` (`appcontainer.rs:403-405`) is true for every
deny, so each run walks the deny trees writing no-op ACEs and journal entries.

**Correction to the review.** The write half of the impact is independently blocked:
AppContainer runs at Low integrity and Windows defaults to no-write-up, so the
workload cannot modify the medium-IL credential and control-plane files even with a
broken DACL. The guaranteed harm is **read**: `~/.ssh` keys, `~/.aws/credentials`,
`~/.azure`, `~/.gnupg` keyrings, and both `.saife` trees are readable. That alone
justifies Critical.

**Fix.** Use a real deny mask (`FILE_ALL_ACCESS = 0x1F01FF`, already used for owner
ACEs at `appcontainer.rs:295`, or the union of allow masks in the DACL). Once the mask
is real, **keep** propagation: pre-existing descendants under `~/.ssh` must be covered
before the inheritance wave completes. Harm to legitimate access is nil — deny dirs
are never ancestors of granted paths, and the supervisor reaches its own stores as the
supervisor SID. Normalize `path_covers` to the `mxc::path_key` standard
(`mxc.rs:238-267`) so `C:\Users\u\.ssh.` or a trailing space cannot slip past the
pre-flight after the mask is enforced.

**Red tests.**
1. `allowlist` unit: every entry with `deny == true` has `access != 0`; the builtin
   list produces exactly six non-zero denies.
2. AppContainer DACL (live, ignored by default): after arming, `AccessCheck` for the
   AC SID against `~/.ssh` denies `FILE_READ_DATA`.
3. `path_covers`: `.ssh.`, `.ssh ` (trailing space), `.ssh\.` and `..` spellings are
   recognized as the deny directory.

### C2 — sync-out follows a workload-created junction

**Evidence.** `src/runner/builds.rs:350-380`: `sync_out` fetches `/src/build/libs` as
a tar and calls `sync::unpack_into_at(&tar, &dest, true, &|_| true)` with
`dest = project.join("build").join("libs")`. No reparse check. `validate_on_disk`
(`runner/mod.rs:262-317`) canonicalizes the project and walks its **ancestors**; it
never inspects descendants, and `build/` is in `SKIP_IN_PROJECT` (`builds.rs:20`), so
it is never a listed path. The workspace is the supervisor's cwd, which is also the
workload's granted tree (`main.rs:815`, `:1327-1334`, `:1386`) — the same filesystem
object. The grant mask includes `FILE_ADD_SUBDIRECTORY` and `FILE_WRITE_ATTRIBUTES`
(`allowlist.rs:30-34`), which is exactly what junction creation needs, with no
privilege and no access to the target.

The tar crate does not save it: `Entry::unpack` → `validate_inside_dst` canonicalizes
both the destination and the entry's parent, so a junction destination passes the
"inside" check transparently. `unpack_into_at`'s own checks are lexical, and
`keep = |_| true` keeps everything.

**Correction.** The in-container build script cannot create a host junction (Linux
container, `/src` is a tar copy). The **workload** creates the junction on the host;
the build script supplies the payload files in `/src/build/libs`. The symlink/hardlink
tar-entry variant is weak on Windows (symlink creation fails without privilege and
aborts the unpack), so the junction is the working vector.

**Fix.** After `create_dir_all`, canonicalize `dest` and refuse if it is not under the
canonical project; additionally `symlink_metadata` each component of
`project/build` / `project/build/libs` and refuse `FILE_ATTRIBUTE_REPARSE_POINT`
(reuse `refuse_reparse_in_chain` with a descendant walk). Restrict sync-out tar
entries to `Regular` and `Directory`. The check must live in `sync_out`, not at build
start: the workload can plant the junction while the build runs.

**Red tests.**
1. Unit: create `project/build/libs` as a junction to a scratch directory, call
   `sync_out` with a one-file tar; assert a named refusal and no file written at the
   target.
2. Unit: a tar containing a `symlink` entry is refused for sync-out.
3. Negative control: a normal project syncs out unchanged.

## High detail

### H1 — falsified

`sync::walk` recurses on `entry.file_type()?.is_dir()` (`runner/sync.rs:105`). On the
repo toolchain (rustc 1.99.1), `FileType::is_dir()` is `!is_symlink && is_directory`
(`std` `sys/fs/windows.rs:1197-1207`), and a junction is classified as a symlink
because its reparse tag has the name-surrogate bit set. Probe: a scratch junction
reports tag `0xa0000003` and `is_dir == false`; `File::open` on it (no
`FILE_FLAG_BACKUP_SEMANTICS`) returns `ERROR_ACCESS_DENIED`, so `append_file` errors,
`pack_dir` fails, and the build never starts. Nothing is packed.

The real sub-claim — `refuse_reparse_below` is only called for explicit `paths`
(`mod.rs:283-314`) — is true, and leaves two defects: a junction produces an opaque
pack failure, and `append_file` **does** follow a symlink-to-**file** (no
`OPEN_REPARSE_POINT`), so a symlink `loot → ~/.ssh/id_rsa` would be packed. That
variant needs symlink-creation privilege (Developer Mode or the privilege), so it is
Medium at most.

**Decision.** Keep the proposed unconditional reparse refusal as defense-in-depth, and
turn the opaque failure into a named refusal. Do not record H1 as an exfiltration
finding.

**Red tests.** (a) A junction inside the project yields a named refusal, not an
`ERROR_ACCESS_DENIED` pack failure. (b) A symlink-to-file inside the project is
refused rather than packed.

### H2 — chained dials

Mechanism confirmed: `proxy.rs:2017-2028` passes the pinned list as `&[]` and returns
before `resolve_pinned_with` / `pinned_addrs_hard_denied` (`:2030-2048`).
`dial_via_proxy` (`upstream.rs:541-573`) sends a raw CONNECT with no local DNS, and
`decide()` sees only the host string. `[G-22]` (ADR-0001 §D-1/D-2) accepts this: "the
upstream proxy's defense to own". That rationale is unsound for the bridge the module
itself recommends (`upstream.rs:26-29`, cntlm/px on 127.0.0.1, which has no
rebinding defense), so `[G-44]`'s "no tunnel to host services" is silently false in
that deployment.

Severity Medium: the upstream is operator-controlled, chaining is opt-in, and the
remote case is defensible. Fix: warn when the configured upstream is loopback; push
the destination hard-deny into the recommended bridge (or ship a bridge wrapper); and
document that `[G-44]` does not hold under loopback chaining. A local pre-dial check
is a tripwire only — split-horizon DNS can differ between local and upstream.

**Red test.** `decide` + dial with a chained upstream and a name resolving to
loopback: assert the emitted leaf and the documented warning (a unit test can assert
the warning path and that the doc's claim is scoped).

### H3 — sidecar environment

`sidecar.rs:90-109` adds `SIDECAR_*` and config but never calls `env_clear`; the
docstring at `:5` promises "and nothing else". Confirmed. Severity Low/Medium: the
plugin is supervisor-privileged code by design (`plugin/mod.rs:31`), `.saife` is
denied to the workload (`mxc.rs:827-838`), and repo-local plugins need an operator
`--plugin-dir`. Fix: `env_clear` + explicit `PATH`, `SYSTEMROOT`, `TEMP`,
`LOCALAPPDATA`, `SIDECAR_*`.

**Red test.** Spawn the fake sidecar with a sentinel variable in the supervisor env;
assert the child's environment does not contain it and does contain `PATH` and
`SIDECAR_FACADE_TOKEN`.

### H4 — audit sid traversal

`validate_session_id` runs only in `AuditWriter::open` (`audit/mod.rs:139`);
`audit_log_path` (`:66-73`) joins the raw sid, and `show`/`verify`
(`show.rs:19`, `verify.rs:36`) pass the CLI string straight in. `--json` dumps valid
JSON lines; `show.rs:37` embeds one raw line in an error; `commit_audit_root`
(`main.rs:520-530`) writes `.root`/`.sig` from an unvalidated sid.

Corrections: the forced `.ndjson` suffix limits reads to `*.ndjson` (plus `*.root`
content via the mismatch message and a `*.sig` existence oracle); `--json` output is
same-user stderr/stdout, so no privilege boundary is crossed unless the sid comes from
an untrusted source (CI wrapper — the premise the code itself documents). Medium.

**Fix.** Validate at the two reader entry points and in `commit_audit_root`; do not
change `audit_log_path`'s signature (about 40 call sites).

**Red tests.** `audit show`/`verify` with `..\..\x`, an absolute path, and a UNC path
return an error and read no file; `commit_audit_root` with a traversal sid writes
nothing.

### H5 — audit lifecycle

- **H5a** No cross-process exclusion anywhere in `audit/` (no `flock`/`LockFileEx`);
  `ChainState` is process-local (`mod.rs:102-127`). `--sid` is caller-supplied and
  `open_at` continues an existing chain (`:146-197`), so two overlapping runs
  interleave leaves; `verify` reports `seq` mismatch (`verify.rs:83-89`) on an
  unedited log. Sequential reuse after a clean seal is supported and verifies.
- **H5b** `main.rs:527-528` does two `fs::write`s. A kill yields a new root with an
  old signature or a truncated root; `verify` reports `BAD_SIGNATURE`/`TAMPERED`
  rather than "crashed". `open_at` never cleans stale `.root`/`.sig`.
- **H5c** A sealed append returns `Ok(())` (`mod.rs:207-212`). `seal_audit` seals
  (`main.rs:1920`) before `ProxyHandle` drop (`:1924`), and the drop's trailing
  refusal aggregate (`proxy.rs:991`) is therefore dropped on every clean exit with
  residue — breaking the documented invariant at `proxy.rs:331-332`. The test at
  `mod.rs:751-790` asserts the drop is intentional, not that the loss is counted.
- **H5d** Non-strict writes swallow errors (`mod.rs:242-244`) **and** lines 247-248
  advance `seq`/`last` unconditionally — contradicting the comment at `:245-246`. The
  next successful leaf then names a phantom parent, or the root mismatches, so a
  transient failure can manufacture `TAMPERED`.

**Fix.** (a) Hold an OS lock on the log for the writer's lifetime (open handle +
`LockFileEx`, or `O_EXCL` lockfile with the PID-reuse guard already used in
`dacl_journal.rs`); fail closed. (b) Write `.sig` before `.root` and replace each
atomically (`MoveFileExW(REPLACE|WRITE_THROUGH)`); delete stale pairs when continuing.
(c) Return `AppendOutcome::DroppedSealed` and count it; print the count at session
end. (d) Do not advance `seq`/`last` when the non-strict write failed; keep the
dropped-leaf counter.

**Red tests.** Two writers on one sid: the second refuses (or blocks) instead of
forking. Simulated kill: root without sig → `INCOMPLETE`/`KEY`-class verdict, never
`TAMPERED`. Sealed append: returns `DroppedSealed` and increments the counter. Failed
write: force it (read-only file), assert the next append's parent is the last
**written** leaf.

## Medium detail (fix notes)

| id | evidence | fix | red test |
|---|---|---|---|
| M1 | `profile.rs:1369-1375`, `:1393-1411`; `USER-GUIDE.md:131` | Refuse `:write`/`:execute` with a message pointing at `:readwrite`, or map to real masks; correct the guide either way. | Table test: each mode string → expected grant list; `:write` must not yield RWX. |
| M2 | `node.json:16`; `jvm.json:10-11`; `opencode.json:7-9`; `security_groups.rs:144`, `:158` | Add builtin **file** denies as descendants (`gradle.properties`, `settings.xml`, `credentials.toml`, `.git-credentials`, `.docker/config.json`, `.kube/config`, `.config/gh`, `NuGet.Config`, `.pypirc`). Whole-dir denies would make `jvm.json` unlaunchable. Document the `.npmrc` trade-off. | A jvm-profile policy contains descendant denies for `gradle.properties`/`settings.xml` while the dir grant stays; DACL check denies read of that file. |
| M3 | `main.rs:1172`; `mxc.rs:817-825`; `profile.rs:250-261`; correct pattern `allowlist.rs:308-341` | Derive from `SHGetKnownFolderPath(FOLDERID_Profile)`; push secret denies unconditionally; fail closed if lookup fails. | Unset `USERPROFILE` → denies still present (both backends); repointed value → denies point at the real profile. |
| M4 | `dacl_journal.rs:111-120`; `appcontainer.rs:652-657`; `main.rs:1044-1047` | `entries()` → `Result`; on read failure keep/quarantine the journal and report failure; count `reaped` only on success. | Locked journal file → teardown keeps it, reports failure, removes no file. |
| M5 | already protected `allowlist.rs:186-221`, `appcontainer.rs:291-311`, `:626-630`; residual `:177-184` | Give `.sandbox` itself a PROTECTED DACL; correct the comment at `:174-176`. | DACL mask test: a second session's SID has no `FILE_LIST_DIRECTORY` on `.sandbox`. |
| M6 | `verify.rs:161`; `signing.rs:44-77` | Add `load_existing()`; `verify` uses it and returns a distinct "key missing" verdict; never mint during verify. | Delete the key → verify reports key-missing and creates no file. |
| M7 | `signing.rs:6-7` vs `:50-53`; entropy `:153-161`, `:180` | Either implement the DACL or delete the claim; add a key fingerprint to the root and report `KEY_CHANGED`. | Verify with a rotated key → `KEY_CHANGED`, not `BAD_SIGNATURE`. |
| M8 | `proxy.rs:2327`/`:2335`, `:3643`/`:3656`; `show.rs:116-125` | Add a request id to the facade leaf; count a terminal disposition per request in `show`. | Loopback-refused request → exactly one counted "contact"; show reports zero hosts contacted. |
| M9 | `matcher.rs:10-33`; loopback via `prompt.rs:559`, `proxy.rs:1882-1890` | Default-on, configurable RFC1918/CGNAT/ULA deny with an escape hatch (`NO_PROXY` CIDR or a profile flag). | Resolved `10.0.0.1` denied when enabled; `NO_PROXY=10.0.0.0/8` still allows. |
| M10 | `builds.rs:46-48`, `:118-127`, `:238-249`, `:328-334` | Ring buffer with a line **and** byte budget; cap the partial line; keep an absolute line counter for `follow=1`. | 10× budget emitted → retained lines bounded, truncation marker present, follower indices monotonic. |
| M11 | `docker.rs:378`, `:1010-1014`; plan `:207-210` | Per-session volume seeded from the shared base; correct the docs to say "code execution", not "poison what B reads". | Live/ignored: A writes `init.d/x.gradle`, B's build does not execute it. |
| M12 | `docker.rs:1007-1015`; plan T2.5 | `PidsLimit` ~512-1024, `NanoCpus`, `Memory` 4-8 GiB configurable. Non-root needs an ownership plan for `/src` and `/cache` first. | Unit: the HostConfig builder emits the limits; integration: a fork bomb is contained. |
| M13 | `sidecar.py:261`, `:274-276`; `ssh_config` empty | Ship a plugin-local `known_hosts`; pass `UserKnownHostsFile` + `StrictHostKeyChecking=yes`; fail closed on unknown host. | Sidecar with no entry refuses before spawning ssh; with a pinned entry it proceeds. |
| M14 | `plugin.json:21`; `mod.rs:112-113`; test `mod.rs:450` | `"4"`; add a test that parses and validates **every** shipped `plugins/*/plugin.json`. | Manifest test fails on the current file (red), passes after the fix. |
| M15 | `proxy.rs:3289-3293` vs `:3617-3626`, `:3345-3346` | Relay the matched (query-stripped) path, or match the full origin-form. | Facade request with `?x=1` → sidecar receives the stripped path. |
| M16 | `sidecar.py:426-427` | `max(0, …)`, `try/except ValueError → 400`, reject `Transfer-Encoding`. | Python tests for `-1`, `abc`, `Transfer-Encoding: chunked`. |

## Low detail (fix notes)

| id | evidence | fix / decision | red test |
|---|---|---|---|
| L-A | `proxy.rs:1936-1950`; asymmetry `:2653` | Reject `@` in `parse_connect_target`. | Parser test: `CONNECT user@host:443` returns `None`. |
| L-B | `proxy.rs:3175-3190`, `:3748` | Strip `Proxy-Authenticate`/`-Info` from every relayed head. | A 401 with the header relays without it. |
| L-C | `proxy.rs:2466-2478` | Wrap `read_body` in a timeout (covers the facade call site too). | Declared body, no payload → closed after the timeout. |
| L-D | `server.rs:189`; `token.rs:125` | Use `ct_eq` for consistency. | Equal-length wrong tokens compare false (functional only). |
| L-E | `server.rs:133-144`, `:160-173` | Head/body read timeout. | Idle connection closed after the timeout. |
| L-F | `mod.rs:187-190`; `verify.rs:76-77` | Lowercase at intake (sids are ASCII alnum + `._-`). | `ABC` then `abc` verifies OK. |
| L-G | `verify.rs:169-171` | Operate on bytes; return `None` off-boundary. | `"a€"` → `None`, no panic. |
| L-H | `verify.rs:76`, `:83` | Require `sid` and `seq` on every leaf. | A leaf without `sid` verifies `TAMPERED`. |
| L-I | `show.rs:137-143` | Print `PRESENT (not verified)`. | Show output never says `OK` without a verification. |
| L-J | `mod.rs:175-186` | No code change; the remedy is already named. Optionally add it to `--help`. | Error text names the remedy. |
| L-K | `mod.rs:301` | Info; a one-time warning is enough. | — |
| L-L | `Cargo.toml:71`; `signing.rs:47`, `:79-84`, `:135-143` | Enable `ed25519-dalek`'s `zeroize` feature; wrap intermediates in `Zeroizing`. | Compile-time assertion that `SigningKey: ZeroizeOnDrop`. |
| L-M | `sidecar.py:254-255`; `sidecar.rs:93-94` | Resolve `ssh.exe` at startup; refuse to run without it. | Startup with an empty PATH fails cleanly, not at first exec. |
| L-N | `builds.rs:25-31`, `:210-215`; `mod.rs:119-153` | Reject control characters in relative paths. | `"a\nb"` is refused by `refuse_unsafe_relative`. |
| L-O | `main.rs:1044-1050`; stale note `AGENTS.md:156` | Remove `.sandbox/<sid>` at teardown; update the note to reflect implemented ACE restore. | Teardown leaves no session dir. |
| L-P | `install.ps1:244-264`; `release.ps1:493`; `docs/design/2026-10-26-code-signing.md` | Keep the D2 deferral; optionally pin a minisign key for `SHA256SUMS.txt`. Track `cargo deny`/CodeQL separately. | — |

## Implementation plan (test-first)

Every item lands as red → green: the failing test is written and observed failing
before the fix, and the test stays as the regression guard.

**Gate per slice:** `cargo test --bin saife` in both feature states, `cargo clippy
--all-targets -D warnings` in both, `rustfmt --check`, `python
plugins/ssh-gateway/test_sidecar.py`.

1. **Containment (C1, C2).** Red tests first, including an AppContainer `AccessCheck`
   test (live, ignored) and a junction sync-out test. Highest risk of a test that
   cannot fail: assert the applied ACE mask, not just the entry.
2. **Shipped-plugin breakage (M14).** One-character fix plus the parse-all-manifests
   test; the test is the real deliverable.
3. **Audit integrity (H5d, H5a, M6, H5c, H5b, M4).** Order by harm: false `TAMPERED`
   first, then forks, then key minting, then sealed-drop accounting, then atomicity.
4. **Policy (M1, M3, M2, M5 residual).** Each is a policy-shape test, not an
   end-to-end run: masks and deny lists are assertable without spawning.
5. **Network (M9, M8, M15, H2, L-A, L-B, L-C).** Prefer resolver `lookup` injection
   over real DNS; the existing proxy tests already fake lookups.
6. **ssh-gateway (M13, M16, L-M).** Python tests with a fake `ssh` on PATH.
7. **Runner (M10, M12, M11 docs, L-E).** Limits are unit-testable on the HostConfig
   builder; cross-session cache isolation is a live/ignored test.
8. **Low hygiene (L-*).** Batch as one slice once the above are green.

### Do not implement as written

- **H1's enterprise**: no junction recursion exists. Add the refusal for predictable
  failure and the symlink-to-file case, and record it as Low.
- **M5's headline**: `.sandbox/<sid>` is already PROTECTED; only the parent needs work.
- **L-J's truncation**: truncating at the last complete line would destroy evidence and
  desynchronize a committed root. Keep the refusal.
- **M11's read-only cache**: it breaks every Gradle build. Use a per-session seeded
  volume or accept and document the limit.

## Corrections to the review (for the record)

1. H1's central premise (`is_dir()` true for junctions) is false on Rust 1.99.1; the
   junction pack fails instead of exfiltrating.
2. C1's write/escape impact is blocked by Low-IL no-write-up; the read impact is not.
3. C2's actor split is inverted: the workload creates the junction, the build script
   supplies the payload.
4. H2/H3/H4 are overstated by one severity step each (see table).
5. M2's security-group grants are RX, not RWX.
6. M5's protected-DACL treatment already exists for `<sid>`.
7. M16's `Content-Length` bug is unreachable from the workload (facade re-frames).
8. L-J's "forever" is false; the error names the remedy.
9. L-O's ACE half is implemented; only directory cleanup and a stale note remain.
10. L-L is understated: the `zeroize` feature is disabled outright.

## Open questions for the product owner

1. C1: a real deny mask changes DACL contents on host files for the AppContainer
   backend. Confirm the trade-off (deny on `~/.ssh` etc. even when `--allow
   $USERPROFILE`).
2. M1: refuse `:write`/`:execute`, or implement true write-only masks? Refusing is
   honest; write-only is awkward on Windows.
3. M9: is LAN reach a supported case for any shipped profile (`host.docker.internal`)?
   If yes, the deny needs an explicit escape hatch.
4. L-P: pin a minisign key for `SHA256SUMS.txt` before 1.0, or wait for SignPath?
