# ADR-0001: omac-derived network hardening — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Each task is designed to be dispatched to a sub-agent.
>
> **Spec:** `docs/adr/0001-omac-derived-network-hardening.md` (authoritative; all decisions marked **[G-N]** trace to grilling questions).
> **Branch:** `feature/adr-0001-network-hardening`
> **Worktree:** `C:\Users\marku\tools\.worktrees\adr-0001-network\sandbox`

## Architecture summary

Five decisions (D-0 through D-5) layered on top of the existing US-3 proxy infrastructure:

- **D-0** (keystone): replace admin-only `NetworkIsolationSetAppContainerConfig` with `privateNetworkClientServer` capability SID. Unblocks all network features unprivileged.
- **D-1**: full filter pipeline (hard-deny → learned-deny → deny_domain → allow → prompt/default), DNS pinning + Happy Eyeballs, `Proxy-Authorization: Basic` auth, raw-tunnel (no TLS termination), loopback-CONNECT refusal.
- **D-2**: upstream corporate proxy chaining (CONNECT-only, `NO_PROXY` direct-dial bypass).
- **D-3**: interactive `TaskDialogIndirect` prompt with 6 buttons, learned persistence, `--no-prompt`, `sandbox learned` CLI.
- **D-4**: intent registry (`/sandbox/intent*` endpoints on the proxy listener).
- **D-5**: audit `source`/`scope`/`persisted` fields on `CONNECT` events, `secret.inject` schema reserved, `--audit-strict` flag.

## Checkpoints

The plan has **5 user-facing checkpoints** where the user should manually test before proceeding. Each is marked **🛑 CHECKPOINT**. Tests that cannot be automated (interactive dialogs, corporate proxy, toast notifications) require explicit user approval, marked **👤 MANUAL APPROVAL**.

---

## Phase 1: D-0 — Capability SID fix (task zero, keystone)

**Goal:** Replace the admin-only loopback exemption with a `privateNetworkClientServer` capability SID on the AppContainer token. Remove `loopback.rs` and the downgrade-to-block-net logic. Unprivileged `--allow-domain` works end-to-end after this phase.

**Files:**
- Modify: `src/sandbox/spawn.rs` (populate `SECURITY_CAPABILITIES`)
- Modify: `src/sandbox/appcontainer.rs` (pass capabilities through)
- Modify: `src/main.rs` (delete downgrade block + `register_loopback` call)
- Modify: `src/net/mod.rs` (delete `pub mod loopback;`)
- Delete: `src/net/loopback.rs`
- Modify: `src/setup.rs` (update network row + intranet-leak warning)
- Modify: `src/cli.rs` (update stale comments on `--block-net`/`--allow-domain`)
- Modify: `tests/run-tests.ps1` (un-skip S-27..S-34, S-36, S-38, S-46)

### Task 1.1: Add `privateNetworkClientServer` capability SID to spawn

- [ ] **Step 1:** In `src/sandbox/spawn.rs`, populate the `SECURITY_CAPABILITIES` struct (currently `Capabilities = null_mut`, `CapabilityCount = 0` at lines 47–48). Build a `SID_AND_ATTRIBUTES` array containing the `privateNetworkClientServer` SID (`S-1-15-3-7`) via `AllocateAndInitializeSid`. The SID array must outlive `CreateProcessW` — store it in a local that lives until after `CreateProcessW` returns.
- [ ] **Step 2:** Gate on network mode: if `NetworkConfig::Blocked`, pass `CapabilityCount = 0` (preserve `--block-net` strong isolation). If `NetworkConfig::Allow`, pass the capability SID. The spawn function signature gains a `capabilities: &[SidAndAttributes]` parameter (or `NetworkConfig` directly).
- [ ] **Step 3:** Add a Rust unit test verifying the SID is correctly constructed as `S-1-15-3-7` (test the `AllocateAndInitializeSid` result via `ConvertSidToStringSid`).

### Task 1.2: Remove loopback module + downgrade logic

- [ ] **Step 1:** Delete `src/net/loopback.rs` entirely.
- [ ] **Step 2:** In `src/net/mod.rs`, delete `pub mod loopback;` (line 4).
- [ ] **Step 3:** In `src/main.rs`, delete the downgrade block (lines 250–267 — the `if net_cfg_resolved is Allow { warn...; net_cfg = Blocked }` logic).
- [ ] **Step 4:** In `src/main.rs`, delete the `register_loopback` call (lines 276–281).
- [ ] **Step 5:** Verify `cargo build --release` succeeds with zero warnings.
- [ ] **Step 6:** Verify `cargo test` passes (existing unit tests should be unaffected).

### Task 1.3: Update env block for `Proxy-Authorization: Basic` (D-1 prerequisite, done early)

- [ ] **Step 1:** In `src/sandbox/appcontainer.rs` `build_env_block` (lines 280–352): change `HTTP_PROXY`/`HTTPS_PROXY` from `http://127.0.0.1:{port}` to `http://sandbox:{token}@127.0.0.1:{port}` (userinfo in URL). Drop the `X-Sandbox-Token` env var. Set `NO_PROXY=localhost,127.0.0.1,::1` (not empty — so the child reaches the intent endpoints directly in D-4).
- [ ] **Step 2:** Update the `PROXY_VARS` const (line 304) to remove `X-Sandbox-Token`.
- [ ] **Step 3:** Add `SANDBOX_PROXY_PORT` env var (the port as a string) for D-4 discoverability.
- [ ] **Step 4:** Update the proxy.rs `handle_conn` token check (lines 197–205) to accept `Proxy-Authorization: Basic` with constant-time compare (`subtle::ConstantTimeCompare` — add `subtle` crate to `Cargo.toml`). Parse `Basic <base64>`, decode, split on `:`, compare the password part to the session token. Missing/invalid → `407 Proxy Authentication Required`.
- [ ] **Step 5:** Add Rust unit tests for the `Proxy-Authorization` parsing + comparison logic.

### Task 1.4: Update setup report

- [ ] **Step 1:** In `src/setup.rs` (line 63), update the network row from `"available (US-3)"` to: `Network (privateNetworkClientServer) : available (loopback + intranet; raw-socket LAN leak possible — use --block-net for strong isolation)`.
- [ ] **Step 2:** Verify `sandbox setup --check-only` prints the new line.

### Task 1.5: Un-skip network integration tests

- [ ] **Step 1:** In `tests/run-tests.ps1`, un-skip S-27..S-34, S-36, S-38, S-46 (remove the "deferred: loopback mechanism pending" skip guard). These tests exercise `--allow-domain`, `--network-profile`, token auth, and proxy port release.
- [ ] **Step 2:** Run the full harness: `.\tests\run-tests.ps1 -StopOnFail`. Expect S-27..S-34 to now pass (the proxy receives traffic, the allow-list works). S-36 (no-token → 407) needs the `Proxy-Authorization` change from Task 1.3. S-38 (port release) should pass.

### 🛑 CHECKPOINT 1 — User tests unprivileged network

**👤 MANUAL APPROVAL REQUIRED.** The user must manually verify:
1. `sandbox setup --check-only` shows the updated network row with the intranet-leak warning.
2. `sandbox run --allow-cwd --block-net -- cmd /c echo hello` still denies all network (regression check).
3. `sandbox run --allow-cwd --allow-domain api.anthropic.com -- cmd /c curl -s -o NUL -w "%{http_code}" https://api.anthropic.com/v1/messages` — the connection succeeds (http_code 4xx from Anthropic = connection worked, auth failed = expected).
4. `sandbox run --allow-cwd --allow-domain api.anthropic.com -- cmd /c curl -s https://evil.example.com` — denied by the proxy.
5. The integration test harness passes: `.\tests\run-tests.ps1 -StopOnFail`.

**Do not proceed to Phase 2 until the user approves.**

---

## Phase 2: D-5 — Audit event taxonomy (cheapest, no dependencies)

**Goal:** Add `source`/`scope`/`persisted` fields to the `CONNECT` audit event. Reserve `secret.inject` schema. Add `--audit-strict` flag. Update the audit filter.

**Files:**
- Modify: `src/net/proxy.rs` (emit_connect signature)
- Modify: `src/audit/mod.rs` (strict mode in open/append)
- Modify: `src/audit/filter.rs` (new filter keys)
- Modify: `src/cli.rs` (`--audit-strict` flag)
- Modify: `src/main.rs` (thread strict flag to AuditWriter)
- Modify: `Cargo.toml` (add `subtle` crate if not already present)

### Task 2.1: Add `source`/`scope`/`persisted` to CONNECT event

- [ ] **Step 1:** In `src/net/proxy.rs`, change the `emit_connect` function signature to accept `source: &str`, `scope: Option<&str>`, `persisted: bool` in addition to the existing `disposition`/`reason`. Add these fields to the JSON map. Existing callers pass `source: "default"`, `scope: None`, `persisted: false` (will be refined in D-1/D-3).
- [ ] **Step 2:** Define the `source` enum values as a Rust const array for documentation: `["hard-deny", "learned", "blocklist", "allowlist", "prompt", "unavailable", "dns", "default", "prompt_overload"]`.
- [ ] **Step 3:** Update existing `emit_connect` call sites in `handle_conn` to pass appropriate `source` values: `"allowlist"` for allow, `"blocklist"` for deny_domain (once D-1 adds it), `"hard-deny"` for metadata/CIDR, `"default"` for not-in-allowlist.
- [ ] **Step 4:** Add Rust unit tests verifying the new fields appear in the NDJSON output.

### Task 2.2: Reserve `secret.inject` event schema

- [ ] **Step 1:** In `src/audit/mod.rs`, add a doc comment documenting the `secret.inject` event schema: `{"op": "secret.inject", "name": "<secret-name>", "seq": ..., "ts": ..., "hash": ..., "parent": ...}`. No emission code — schema reservation only.
- [ ] **Step 2:** Add a Rust unit test verifying the doc comment is present (compile-time check).

### Task 2.3: Add `--audit-strict` flag

- [ ] **Step 1:** In `src/cli.rs`, add `--audit-strict` flag to `RunCmd`.
- [ ] **Step 2:** In `src/audit/mod.rs`, add a `strict: bool` field to `AuditWriter`. In `open()`, if `strict` and the log can't be opened, return `Err`. In `append()`, if `strict` and the write fails, return `Err` (propagated to the caller which aborts the run).
- [ ] **Step 3:** In `src/main.rs`, thread `--audit-strict` into `AuditWriter::open`.
- [ ] **Step 4:** Add Rust unit tests: strict mode refuses to open on unwritable path; strict mode aborts on write failure.

### Task 2.4: Update audit filter keys

- [ ] **Step 1:** In `src/audit/filter.rs`, add `"source"`, `"scope"`, `"persisted"` to `KNOWN_KEYS` (line 34).
- [ ] **Step 2:** Add Rust unit tests: `source=hard-deny` filter matches; `source!=allowlist` excludes allows; `persisted=true` matches only persisted decisions.

### 🛑 CHECKPOINT 2 — User verifies audit output

**Automated:** `cargo test` passes (all new audit unit tests).
**👤 MANUAL APPROVAL REQUIRED:**
1. Run a sandboxed session with `--allow-domain api.anthropic.com -- cmd /c curl https://api.anthropic.com`.
2. Run `sandbox audit show <sid> --json` and verify the `CONNECT` events now include `source`, `scope`, `persisted` fields.
3. Run `sandbox audit show <sid> --filter "source=allowlist"` and verify filtering works.
4. Run with `--audit-strict` and verify the session starts normally (log is writable).

---

## Phase 3: D-3 + D-4 — Interactive prompt + intent registry (co-dependent)

**Goal:** Add the interactive network prompt with `TaskDialogIndirect`, learned persistence, and the intent registry endpoints. These are co-dependent: the prompt displays the agent's declared intent.

**Files:**
- Create: `src/net/prompt.rs` (dialog + learned store + coalescing + semaphore)
- Create: `src/net/intent.rs` (intent registry + endpoints)
- Modify: `src/net/proxy.rs` (wire prompt + intent into the request handler)
- Modify: `src/net/mod.rs` (add modules, add prompt config to `NetworkConfig::Allow`)
- Modify: `src/profile.rs` (add `promptEnabled`/`onUnavailable`/`promptTimeoutSecs`/`upstreamProxy` to `RawNetwork`/`NetworkSlice`)
- Modify: `src/cli.rs` (add `--no-prompt`, `--deny-domain`)
- Modify: `src/main.rs` (load learned file, thread prompt config)
- Modify: `Cargo.toml` (add `windows` features for TaskDialog + Toast)
- Modify: `tests/run-tests.ps1` (add prompt/intent/learned scenarios)

### Task 3.1: Profile + CLI fields for prompt configuration

- [ ] **Step 1:** In `src/profile.rs`, add fields to `RawNetwork` and `NetworkSlice`:
  - `deny_domain: Vec<String>` (D-1, but needed now so the profile parses)
  - `prompt_enabled: Option<bool>` (default `true` when network active)
  - `on_unavailable: Option<String>` (default `"deny"`)
  - `prompt_timeout_secs: Option<u32>` (default `60`)
  - `upstream_proxy: Option<String>` (D-2, but parse it now)
  - Use `#[serde(default)]` on all new fields for backward compat. Field names in JSON are camelCase (`promptEnabled`, `onUnavailable`, `promptTimeoutSecs`, `upstreamProxy`, `denyDomain`).
- [ ] **Step 2:** Update `merge_profiles` (line 454) to concatenate `deny_domain` (like `allow_domain`). Update `resolve_network_slice` to copy new fields.
- [ ] **Step 3:** Update `to_expanded_json` to emit the new fields.
- [ ] **Step 4:** In `src/cli.rs`, add `--no-prompt` flag and `--deny-domain <DOMAIN>` (repeatable).
- [ ] **Step 5:** In `src/net/mod.rs`, extend `NetworkConfig::Allow` with: `deny_domain: Vec<String>`, `prompt_enabled: bool`, `on_unavailable: String`, `prompt_timeout_secs: u32`, `upstream_proxy: Option<String>`, `profile_name: Option<String>` (for learned-file path).
- [ ] **Step 6:** Update `resolve_network` to populate the new fields from profile + CLI. `--no-prompt` sets `prompt_enabled = false`. `--deny-domain` concatenates with `network.denyDomain`.
- [ ] **Step 7:** Add Rust unit tests for the new profile fields + CLI flag parsing.

### Task 3.2: Hard-deny list expansion + `deny_domain` + wildcard apex match (D-1 core)

- [ ] **Step 1:** In `src/net/matcher.rs`, expand the hard-deny lists:
  - `ALWAYS_DENIED_V4_HOSTS`: add `169.254.169.253`
  - `ALWAYS_DENIED_DNS`: add `metadata.azure.internal`, `metadata.tencentyun.com`
  - Add a new `ALWAYS_DENIED_IP_LITERALS` const: `["169.254.169.254", "169.254.169.253", "100.100.100.200"]`
  - Split `is_always_denied` into `is_hard_denied_host(host: &str) -> bool` (hostname set, case-insensitive, trailing-dot-stripped) and `is_hard_denied_ip(ip: IpAddr) -> bool` (IP set + link-local CIDR). The pipeline calls both.
- [ ] **Step 2:** Update `matches()` (line 47): `*.suffix` now matches the bare apex (`host == suffix || host ends with "."+suffix`). Update the existing test that asserts the apex does NOT match.
- [ ] **Step 3:** Add `deny_domain` to the `check()` function: after `is_always_denied` and before `is_allowed`, check `matches(host, deny_list)` → `Deny(DenyReason::DeniedDomain)`. Update `Verdict`/`DenyReason` accordingly.
- [ ] **Step 4:** Update all existing unit tests for the new wildcard semantics and add tests for `deny_domain` precedence (deny wins over allow).
- [ ] **Step 5:** Run `cargo test` — all matcher tests must pass.

### Task 3.3: Learned-policy store

- [ ] **Step 1:** Create `src/net/learned.rs` with a `LearnedStore` struct:
  - `load(profile_name: &str) -> LearnedStore` — reads `%USERPROFILE%\.sandbox\learned\<profile_name>.json`. Unnamed → `default.json`. Missing file → empty store.
  - `lookup(host: &str) -> Option<LearnedDecision>` — returns `Some(LearnedDecision { allow: bool, scope: String })` if found. Suffix entries match the host itself and any subdomain.
  - `record(host: &str, scope: &str, allow: bool) -> Result<()>` — persists immediately. Write-temp + `MoveFileEx(MOVEFILE_REPLACE_EXISTING)` with 3x retry + 50ms backoff, fallback to direct write.
  - File format (our own, camelCase): `{"schema":1,"allow":[{"host":"...","scope":"host"|"suffix"}],"deny":[{"host":"...","scope":"host"|"suffix"}]}`
- [ ] **Step 2:** Add Rust unit tests: load missing file → empty; record + reload; suffix match; host match; atomic write with retry.

### Task 3.4: Intent registry

- [ ] **Step 1:** Create `src/net/intent.rs` with an `IntentRegistry`:
  - `new(ttl: Duration) -> IntentRegistry` — starts a background sweeper at TTL/2.
  - `record(target: &str, reason: &str)` — normalize target (lowercase hostname, strip port/path/URL), truncate reason to 500 chars, store with timestamp.
  - `lookup_host(host: &str) -> Option<Entry>` — returns the live intent for the host, or None if missing/expired.
  - `mark_explain_more(host: &str)` — sets one-shot flag.
  - `consume_explain_more(host: &str) -> bool` — reads + clears the flag (one-shot).
  - `clear_explain_more(host: &str)` — clears without reading.
  - `close()` — stops the sweeper.
  - Max 500 entries; on overflow, evict oldest.
  - All operations behind a `tokio::sync::Mutex`.
- [ ] **Step 2:** Add Rust unit tests: record + lookup; TTL expiry (use short TTL in test); explain-more one-shot; normalization (URL → host, host:port → host); overflow eviction; max reason length truncation.

### Task 3.5: Interactive prompt dialog

- [ ] **Step 1:** Add `windows` features to `Cargo.toml`: `Win32_UI_Controls` (for `TaskDialogIndirect`), `UI_Notifications` (for toast). Verify the build resolves.
- [ ] **Step 2:** Create `src/net/prompt.rs` with:
  - `struct PromptConfig { timeout: Duration, on_unavailable: PromptPolicy }`
  - `enum PromptPolicy { Deny, Allow }`
  - `enum PromptResult { Allow { persist: bool, scope: String, suffix: Option<String> }, Deny { persist: bool, scope: String, suffix: Option<String> }, NeedsIntent }`
  - `fn show_dialog(host: &str, port: u16, reason: Option<&str>, suffix_hint: &str) -> PromptResult` — calls `TaskDialogIndirect` with 6 custom buttons. Steals focus. Fires a fire-and-forget toast on a separate thread.
  - `fn compute_suffix_hint(host: &str) -> String` — host with leftmost label removed when ≥3 labels, else the host. IP literals return the host itself.
  - `fn is_loopback_host(host: &str) -> bool` — `localhost`, `*.localhost`, `127.0.0.1`, `::1`, and any IP that parses as loopback.
- [ ] **Step 3:** Implement the dialog via `tokio::task::spawn_blocking`. The async caller awaits the `JoinHandle` with `tokio::time::timeout`.
- [ ] **Step 4:** Implement coalescing: a `tokio::sync::Mutex<HashMap<String, Arc<oneshot::Sender<PromptResult>>>>` keyed by hostname. First request for a host becomes the leader (shows the dialog); concurrent requests for the same host park on the leader's result.
- [ ] **Step 5:** Implement the semaphore: `Arc<Semaphore::new(8)>`. Before showing a dialog, `acquire()` a permit. If `acquire()` would block (8 in flight), immediately return `Deny` with `source: "prompt_overload"`.
- [ ] **Step 6:** Handle the orphaned-dialog timeout: `tokio::time::timeout(timeout, spawn_blocking(...))` — on timeout, return `Deny` (or `Allow` per `on_unavailable`). The dialog stays on screen (accepted quirk, G-4).
- [ ] **Step 7:** Add Rust unit tests for `compute_suffix_hint` and `is_loopback_host` (pure functions). The dialog itself cannot be unit-tested (requires a desktop) — manual test in the checkpoint.

### Task 3.6: Wire prompt + intent + learned into the proxy

- [ ] **Step 1:** In `src/net/proxy.rs`, restructure `handle_conn` to implement the full D-1 pipeline:
  1. Parse host:port from CONNECT/forward request.
  2. Refuse loopback CONNECT → `403` + `X-Sandbox: denied` header.
  3. Check hard-deny (hostname set + IP set) → `403` + `source: "hard-deny"`.
  4. Check learned-deny → `403` + `source: "learned"`.
  5. Check `deny_domain` → `403` + `source: "blocklist"`.
  6. Check `allow_domain` / learned-allow → allow + `source: "allowlist"` or `source: "learned"`.
  7. Default: if `prompt_enabled`, show the dialog (with intent reason if available). On `Allow` with persist, call `learned.record(...)`. On `Deny`, `403` + body. On `NeedsIntent`, `403` + `X-Sandbox-Intent-Hint` header + `source: "prompt"`. If not `prompt_enabled`, apply `on_unavailable` → `source: "unavailable"` or `source: "default"`.
- [ ] **Step 2:** After admission (Allow), perform DNS resolution (pin IPs) + Happy Eyeballs dial (8 concurrent, first wins). Under upstream chaining (D-2, Phase 4), skip DNS and dial through the upstream proxy.
- [ ] **Step 3:** Emit `CONNECT` audit events with the correct `source`/`scope`/`persisted` for every decision.
- [ ] **Step 4:** On the same listener, route non-CONNECT requests to `/sandbox/*` paths:
  - `POST /sandbox/intent` → `intent.record(target, reason)` → `204`.
  - `GET /sandbox/intent?host=<host>` → `intent.lookup_host(host)` → `200` with JSON or `404`.
  - `POST /sandbox/intent/explain` → `intent.mark_explain_more(host)` → `204`.
  - Non-`/sandbox/` non-CONNECT → `400 Bad Request`.
  - All endpoints require `Proxy-Authorization: Basic` (same token as CONNECT).
- [ ] **Step 5:** In `src/main.rs`, load the `LearnedStore` before starting the proxy. Create the `IntentRegistry`. Pass both + `PromptConfig` into `ProxyConfig`.
- [ ] **Step 6:** In `src/sandbox/appcontainer.rs`, inject `SANDBOX_PROXY_PORT` env var (from Task 1.3).
- [ ] **Step 7:** Verify `cargo build --release` and `cargo test` pass.

### Task 3.7: `sandbox learned` CLI subcommand

- [ ] **Step 1:** In `src/cli.rs`, add `Cmd::Learned { subcommand: LearnedSub, profile: Option<String> }` with `LearnedSub::List`, `LearnedSub::Revoke { host: String }`, `LearnedSub::Clear`.
- [ ] **Step 2:** Implement `sandbox learned list` — prints a table of host/scope/disposition from the learned file.
- [ ] **Step 3:** Implement `sandbox learned revoke <host>` — removes the entry, atomically rewrites the file.
- [ ] **Step 4:** Implement `sandbox learned clear` — empties the file.
- [ ] **Step 5:** Add Rust unit tests for the CLI parsing.

### Task 3.8: Integration tests for prompt + intent + learned

- [ ] **Step 1:** In `tests/run-tests.ps1`, add scenarios:
  - **S-72** (D-1 deny_domain): `--allow-domain api.anthropic.com --deny-domain *.evil.com`, curl `evil.example.com` → denied with `source: "blocklist"` in audit. (Automated.)
  - **S-73** (D-1 hard-deny expansion): curl `169.254.169.253` → denied with `source: "hard-deny"`. (Automated.)
  - **S-74** (D-1 wildcard apex): `--allow-domain *.anthropic.com`, curl `anthropic.com` (apex) → allowed. (Automated.)
  - **S-75** (D-1 loopback CONNECT refused): the agent issues `CONNECT 127.0.0.1:5432` → `403` + `X-Sandbox: denied`. (Automated — use `curl -x` to force a CONNECT to loopback.)
  - **S-76** (D-3 `--no-prompt`): `--allow-domain api.anthropic.com --no-prompt`, curl `evil.example.com` → denied, no dialog spawned, `source: "default"` in audit. (Automated.)
  - **S-77** (D-4 intent endpoint): inside the sandbox, `curl -H "Proxy-Authorization: Basic ..." http://127.0.0.1:$SANDBOX_PROXY_PORT/sandbox/intent -d '{"target":"api.example.com","reason":"test"}'` → `204`. Then `GET /sandbox/intent?host=api.example.com` → `200` with the reason. (Automated — use a script as the inner command.)
  - **S-78** (D-3 learned persistence): run with `--allow-domain api.anthropic.com`, interactively allow `github.com` permanently, restart sandbox, curl `github.com` without `--allow-domain github.com` → allowed (learned). (**👤 MANUAL APPROVAL** — requires interactive dialog click.)
  - **S-79** (D-3 `sandbox learned list/revoke`): after S-78, run `sandbox learned list` → shows `github.com`, run `sandbox learned revoke github.com`, run `sandbox learned list` → empty. (Automated if S-78 is done first.)
  - **S-80** (D-5 audit source field): after S-72/S-73/S-76, run `sandbox audit show <sid> --filter "source=hard-deny"` → only hard-deny events. (Automated.)

### 🛑 CHECKPOINT 3 — User tests interactive prompt

**👤 MANUAL APPROVAL REQUIRED.** The following cannot be automated:
1. Run `sandbox run --allow-cwd --allow-domain api.anthropic.com -- cmd /c curl https://evil.example.com` — verify the `TaskDialogIndirect` dialog appears with 6 buttons, steals focus, and shows host:port. Click "Deny once" — verify curl gets a 403.
2. Inside the sandbox (via `cmd /c`), POST an intent: `curl -H "Proxy-Authorization: Basic ..." http://127.0.0.1:%SANDBOX_PROXY_PORT%/sandbox/intent -d "{\"target\":\"api.github.com\",\"reason\":\"fetching releases\"}"`. Then curl `https://api.github.com` — verify the dialog now shows `Agent reason: "fetching releases"`.
3. Click "Allow permanently (*.github.com)" — verify the curl succeeds. Restart the sandbox and curl `api.github.com` again — verify it succeeds without a dialog (learned).
4. Run `sandbox learned list` — verify `api.github.com` appears with scope `suffix`. Run `sandbox learned revoke api.github.com`. Run `sandbox learned list` — verify it's gone.
5. Run with `--no-prompt` — verify no dialog appears and unknown hosts are silently denied.
6. Verify the audit trail: `sandbox audit show <sid> --json | findstr "source"` — verify `source` values appear (`hard-deny`, `allowlist`, `prompt`, `learned`, `default`).
7. Fire 9 concurrent requests to 9 distinct unknown hosts — verify the 9th gets an immediate deny (`source: "prompt_overload"`) and only 8 dialogs appear.

**Do not proceed to Phase 4 until the user approves.**

---

## Phase 4: D-2 — Upstream corporate proxy chaining

**Goal:** Chain allowed requests through a corporate egress proxy via HTTP CONNECT. Support `NO_PROXY` direct-dial bypass. CONNECT-only (no plain-HTTP forwarding through upstream).

**Files:**
- Create: `src/net/upstream.rs` (upstream proxy dialer)
- Modify: `src/net/proxy.rs` (fork direct-dial vs upstream-dial)
- Modify: `src/net/mod.rs` (read host env HTTPS_PROXY, warn on override)
- Modify: `src/main.rs` (detect upstream proxy, build dialer)

### Task 4.1: Upstream proxy dialer

- [ ] **Step 1:** Create `src/net/upstream.rs` with an `UpstreamDialer`:
  - `struct UpstreamDialer { proxy_url: Url, proxy_auth: Option<String>, no_proxy: Vec<String>, direct: DirectDialer }`
  - `fn new(proxy_url: Url, no_proxy: Vec<String>) -> UpstreamDialer` — extracts Basic auth from URL userinfo.
  - `fn chains_host(host: &str) -> bool` — `!host_matches_no_proxy(host, &no_proxy)`.
  - `fn dial(ctx, host, port, pinned_addrs) -> Result<TcpStream>` — if `NO_PROXY` matches, delegate to `DirectDialer` (with Happy Eyeballs). Otherwise, dial the upstream proxy, send `CONNECT host:port`, send `Proxy-Authorization: Basic <creds>`, read response, on `200` return the spliced tunnel.
  - `fn host_matches_no_proxy(host: &str, entries: &[String]) -> bool` — suffix match (`host == entry || host ends with "."+entry`), case-insensitive. (Reuse the same logic as `matcher::matches` but for exact-host + suffix, not `*.` wildcards.)
  - `fn proxy_auth_header() -> Option<String>` — returns `"Basic <base64>"` or None.
- [ ] **Step 2:** Create a `DirectDialer` (or extract from existing proxy.rs) that dials pinned IPs with Happy Eyeballs (8 concurrent, first wins).
- [ ] **Step 3:** Add Rust unit tests for `host_matches_no_proxy` and `chains_host`.

### Task 4.2: Wire upstream dialer into proxy

- [ ] **Step 1:** In `src/net/proxy.rs`, extract the upstream-connect logic (lines 241–269) into a `dial_upstream` function that branches: `if upstream.is_some() && upstream.chains_host(host) { upstream.dial(...) } else { direct.dial(pinned_addrs) }`.
- [ ] **Step 2:** Under upstream chaining, skip local DNS resolution (run `CheckHost` — hostname-only admission). The upstream proxy does its own DNS.
- [ ] **Step 3:** Handle upstream errors: `UpstreamError` (proxy unreachable, non-200 response). Return `502 Bad Gateway` with `X-Sandbox: upstream-error` header + body naming the upstream proxy (no credentials). Log to audit with `source: "default"`, `reason: "upstream_error"`.
- [ ] **Step 4:** In `src/main.rs`, detect upstream proxy: if `network.upstreamProxy` is set in the profile, use it. Else if host env `HTTPS_PROXY`/`HTTP_PROXY` is set, use it (emit `SANDBOX_DIAG` warning if both are set and differ). Else `None` (direct dial only).
- [ ] **Step 5:** Pass the `UpstreamDialer` (or `None`) into `ProxyConfig`.

### Task 4.3: Integration tests for upstream chaining

- [ ] **Step 1:** In `tests/run-tests.ps1`, add scenarios:
  - **S-81** (D-2 NO_PROXY bypass): set `HTTPS_PROXY=http://127.0.0.1:9999` (non-existent), `network.noProxy=["api.anthropic.com"]`, curl `api.anthropic.com` → succeeds (NO_PROXY bypass, direct dial). (**👤 MANUAL APPROVAL** — requires a corporate proxy or a local mock proxy to test the chaining path. The NO_PROXY bypass can be automated by pointing at a non-existent upstream and verifying the NO_PROXY host still works.)
  - **S-82** (D-2 upstream unreachable): set `network.upstreamProxy=http://127.0.0.1:9999` (non-existent), curl any host → `502 Bad Gateway` + `X-Sandbox: upstream-error`. (Automated.)
  - **S-83** (D-2 host env detection): set host env `HTTPS_PROXY`, no profile `upstreamProxy`, verify `SANDBOX_DIAG` does NOT warn. Set both and differ → verify `SANDBOX_DIAG` warns. (Automated — check stderr.)

### 🛑 CHECKPOINT 4 — User tests upstream proxy

**👤 MANUAL APPROVAL REQUIRED.** The full chaining path requires a real or mock corporate proxy:
1. Start a local mock proxy (e.g. `python -m http.server` won't work for CONNECT; use `mitmproxy` or `squid` or a simple TCP relay). Point `network.upstreamProxy` at it.
2. Run `sandbox run --allow-cwd --allow-domain api.anthropic.com -- cmd /c curl https://api.anthropic.com` — verify the request chains through the mock proxy (check mock proxy logs).
3. Set `network.noProxy=["api.anthropic.com"]` — verify the request goes direct (not through the mock proxy).
4. Set `network.upstreamProxy` and host env `HTTPS_PROXY` to different values — verify the `SANDBOX_DIAG` override warning appears.
5. Point `network.upstreamProxy` at a non-existent proxy — verify `502 Bad Gateway` + `X-Sandbox: upstream-error`.

**Do not proceed to Phase 5 until the user approves.**

---

## Phase 5: D-1 finalization — Full filter pipeline integration

**Goal:** Wire the complete D-1 pipeline end-to-end with all components (hard-deny expansion, deny_domain, learned, prompt, DNS pinning, Happy Eyeballs, loopback refusal, Proxy-Authorization). Most of this is already done in Phase 3 — this phase is the integration verification + edge cases.

**Files:**
- Modify: `src/net/proxy.rs` (final pipeline integration)
- Modify: `src/net/matcher.rs` (verify pipeline order)
- Modify: `tests/run-tests.ps1` (comprehensive pipeline tests)

### Task 5.1: Verify pipeline ordering

- [ ] **Step 1:** Audit the `handle_conn` flow in `src/net/proxy.rs` to confirm the exact pipeline order from the ADR [G-33]:
  1. Hard-deny (hostname set + IP set + link-local CIDR on resolved IPs)
  2. Learned permanent deny
  3. `deny_domain` blocklist
  4. `allow_domain` / learned permanent allow
  5. Default (prompt / on_unavailable)
- [ ] **Step 2:** Add a Rust integration test that mocks the filter components and verifies the ordering: a host that's both in `deny_domain` and `allow_domain` → denied with `source: "blocklist"` (not `"allowlist"`). A host that's both learned-deny and in `deny_domain` → denied with `source: "learned"`.

### Task 5.2: DNS pinning + Happy Eyeballs integration

- [ ] **Step 1:** In `src/net/proxy.rs`, replace the best-effort `lookup_host` (lines 229–234) with a single pinned resolution. Store the resolved IPs and pass them to the dialer.
- [ ] **Step 2:** Implement Happy Eyeballs in the `DirectDialer`: race up to 8 concurrent `TcpStream::connect` calls (one per pinned IP), first success cancels the rest, losers that connected are closed. Use `tokio::select!` or `futures::select_all`.
- [ ] **Step 3:** Verify the anti-rebinding property: the IPs dialed are the ones resolved at admission time, never re-resolved.
- [ ] **Step 4:** Add a Rust unit test for the Happy Eyeballs logic (mock addresses, verify first-success-cancels-rest).

### Task 5.3: Comprehensive integration tests

- [ ] **Step 1:** In `tests/run-tests.ps1`, add final scenarios:
  - **S-84** (D-1 pipeline ordering — deny_domain over allow): `--allow-domain *.anthropic.com --deny-domain api.anthropic.com`, curl `api.anthropic.com` → denied with `source: "blocklist"`. (Automated.)
  - **S-85** (D-1 pipeline ordering — learned-deny over deny_domain): pre-populate learned file with a deny for a host that's also in `deny_domain`, verify `source: "learned"` in audit. (Automated — write the learned file before the run.)
  - **S-86** (D-1 DNS pinning): curl a host that resolves to multiple IPs — verify only one connection is made. (Automated — check audit log for single CONNECT event.)
  - **S-87** (D-1 loopback CONNECT refused): `curl -x http://sandbox:<token>@127.0.0.1:<port> https://127.0.0.1:8080/` → `403` + `X-Sandbox: denied`. (Automated.)
  - **S-88** (D-1 Proxy-Authorization missing → 407): curl without `Proxy-Authorization` → `407 Proxy Authentication Required`. (Automated — already S-36, verify it still passes.)
  - **S-89** (D-3 prompt_overload): fire 9 concurrent CONNECTs to 9 distinct unknown hosts, verify 8 dialogs + 1 immediate deny with `source: "prompt_overload"`. (**👤 MANUAL APPROVAL** — requires interactive dialog counting.)

### 🛑 CHECKPOINT 5 — User tests full pipeline

**👤 MANUAL APPROVAL REQUIRED.**
1. Full end-to-end: `sandbox run --allow-cwd --network-profile developer -- cmd` — inside the sandbox:
   - `curl https://api.anthropic.com` → allowed (in developer profile).
   - `curl https://registry.npmjs.org` → allowed.
   - `curl https://evil.example.com` → dialog appears → click "Deny once" → 403.
   - `curl https://evil.example.com` again → dialog appears again → click "Deny permanently (*.evil.com)" → 403. Restart sandbox, curl again → denied without dialog (learned).
   - `curl https://169.254.169.254` → denied immediately (hard-deny, no dialog).
2. Verify `sandbox audit show <sid> --json` shows CONNECT events with correct `source` values for each decision type.
3. Run the full test harness: `.\tests\run-tests.ps1 -StopOnFail` — all non-manual scenarios pass.

---

## Test plan summary

### Automated tests (Rust unit tests + PowerShell harness)

| ID | Phase | What | Type |
|---|---|---|---|
| Task 1.1 | D-0 | Capability SID construction (`S-1-15-3-7`) | Rust unit |
| Task 1.3 | D-0 | `Proxy-Authorization: Basic` parsing + constant-time compare | Rust unit |
| Task 2.1 | D-5 | CONNECT event `source`/`scope`/`persisted` fields in NDJSON | Rust unit |
| Task 2.3 | D-5 | `--audit-strict` refuse-to-open / abort-on-write-failure | Rust unit |
| Task 2.4 | D-5 | Audit filter `source`/`scope`/`persisted` keys | Rust unit |
| Task 3.1 | D-3 | Profile `promptEnabled`/`onUnavailable`/`promptTimeoutSecs`/`upstreamProxy` fields | Rust unit |
| Task 3.2 | D-1 | Hard-deny list expansion, `deny_domain`, wildcard apex match | Rust unit |
| Task 3.3 | D-3 | Learned store: load, record, lookup, atomic write | Rust unit |
| Task 3.4 | D-4 | Intent registry: record, lookup, TTL, explain-more, normalization | Rust unit |
| Task 3.5 | D-3 | `compute_suffix_hint`, `is_loopback_host` | Rust unit |
| Task 3.7 | D-3 | `sandbox learned list/revoke/clear` CLI parsing | Rust unit |
| Task 4.1 | D-2 | `host_matches_no_proxy`, `chains_host` | Rust unit |
| Task 5.1 | D-1 | Pipeline ordering (deny_domain over allow, learned over deny_domain) | Rust integration |
| Task 5.2 | D-1 | Happy Eyeballs first-success-cancels-rest | Rust unit |
| S-27..S-34 | D-0 | `--allow-domain`/`--network-profile` allow/deny/wildcard/profile-merge | PowerShell |
| S-36 | D-0 | No-token → 407 | PowerShell |
| S-38 | D-0 | Proxy port released on exit | PowerShell |
| S-46 | D-0 | CONNECT audit events | PowerShell |
| S-72 | D-1 | `deny_domain` precedence | PowerShell |
| S-73 | D-1 | Hard-deny expansion (169.254.169.253) | PowerShell |
| S-74 | D-1 | Wildcard apex match | PowerShell |
| S-75 | D-1 | Loopback CONNECT refused | PowerShell |
| S-76 | D-3 | `--no-prompt` denies silently | PowerShell |
| S-77 | D-4 | Intent endpoint POST + GET | PowerShell |
| S-79 | D-3 | `sandbox learned list/revoke` | PowerShell |
| S-80 | D-5 | Audit filter `source=hard-deny` | PowerShell |
| S-81 | D-2 | `NO_PROXY` bypass (direct dial) | PowerShell |
| S-82 | D-2 | Upstream unreachable → 502 | PowerShell |
| S-83 | D-2 | Host env detection + override warning | PowerShell |
| S-84 | D-1 | Pipeline: deny_domain over allow | PowerShell |
| S-85 | D-1 | Pipeline: learned-deny over deny_domain | PowerShell |
| S-86 | D-1 | DNS pinning (single CONNECT per host) | PowerShell |
| S-87 | D-1 | Loopback CONNECT refused (via `curl -x`) | PowerShell |
| S-88 | D-1 | Proxy-Authorization missing → 407 | PowerShell |

### Manual tests (require user interaction or external infrastructure)

| ID | Phase | What | Why manual |
|---|---|---|---|
| Checkpoint 1.3 | D-0 | Unprivileged `--allow-domain` works end-to-end | Verify the capability SID fix |
| Checkpoint 1.4 | D-0 | `setup --check-only` shows intranet-leak warning | Visual inspection |
| Checkpoint 2.4 | D-5 | Audit `source` field in `audit show` output | Visual inspection |
| Checkpoint 3.1 | D-3 | `TaskDialogIndirect` appears with 6 buttons, steals focus | Requires desktop session |
| Checkpoint 3.2 | D-3 | Intent reason displayed in dialog | Requires dialog interaction |
| Checkpoint 3.3 | D-3 | "Allow permanently (*.github.com)" persists across restarts | Requires dialog + restart |
| Checkpoint 3.4 | D-3 | `sandbox learned list/revoke` after interactive allow | Requires prior dialog |
| Checkpoint 3.5 | D-3 | `--no-prompt` suppresses dialog | Verify no dialog |
| Checkpoint 3.6 | D-5 | Audit `source` values in `audit show` | Visual inspection |
| Checkpoint 3.7 | D-3 | 8 concurrent dialogs + 9th prompt_overload deny | Requires counting dialogs |
| Checkpoint 4.1 | D-2 | Request chains through mock corporate proxy | Requires mock proxy |
| Checkpoint 4.2 | D-2 | `NO_PROXY` bypass goes direct | Requires mock proxy |
| Checkpoint 4.3 | D-2 | Override warning when profile + env differ | Visual inspection |
| Checkpoint 4.4 | D-2 | Upstream unreachable → 502 | Verify error body |
| Checkpoint 5.1 | D-1 | Full end-to-end pipeline with all decision types | Requires desktop + dialog |
| Checkpoint 5.2 | D-1 | Audit trail with correct `source` values | Visual inspection |
| S-78 | D-3 | Learned persistence across restart | Requires interactive dialog click |
| S-89 | D-1 | Prompt overload (9 concurrent, 8 dialogs + 1 deny) | Requires counting dialogs |

---

## Sub-agent dispatch guide

Each task in this plan is designed to be dispatched to a sub-agent. The dispatching agent should:

1. **Create the worktree** before dispatching the first task.
2. **Dispatch one phase at a time** — tasks within a phase have dependencies. Tasks across phases are gated by checkpoints.
3. **For each task:** give the sub-agent the task description, the relevant ADR section(s) [G-N], the file list, and the exact line numbers from the exploration summary. Instruct the sub-agent to write code + tests, run `cargo build --release` and `cargo test`, and report back.
4. **After each phase:** the dispatching agent runs the checkpoint (automated tests first, then presents manual tests to the user).
5. **Do not proceed** to the next phase until the user approves the checkpoint.

**Parallelism:** within a phase, some tasks can be parallelized:
- Phase 2: Tasks 2.1–2.4 are independent (different files) — dispatch in parallel.
- Phase 3: Tasks 3.3 (learned) + 3.4 (intent) are independent — dispatch in parallel. Task 3.2 (matcher) is independent of 3.3/3.4. Task 3.5 (prompt) depends on 3.4 (intent, for the reason display). Task 3.6 (wire-in) depends on all of 3.2–3.5. Task 3.7 (CLI) depends on 3.3.
- Phase 4: Task 4.1 is independent; Task 4.2 depends on 4.1.
- Phase 5: Task 5.1 depends on Phase 3; Task 5.2 is independent; Task 5.3 depends on 5.1 + 5.2.

---

## Out of scope for this plan

- F-2 (credential injection) — `secret.inject` schema reserved, emission deferred.
- F-4 FILE_EXPANSION / COMMAND_APPROVAL — only NETWORK_EXPANSION via prompt.
- F-6 (WFP driver) — the real fix for the intranet leak.
- F-18 (network content inspection / TLS termination) — raw tunnel only.
- Per-PID attribution in dialogs [G-23].
- Auto-detection of headless mode [G-36].
- NTLM/Kerberos native support [G-14] — `winhttp` spike noted as follow-up.
- Plain-HTTP forwarding through upstream proxy [G-24].
- Retry cap / prompt-storm protection [G-26].
- omac sidecar/skills/facade architecture.
