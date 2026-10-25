# ADR-0001: omac-derived network hardening (filter pipeline, prompts, intent, upstream chaining, audit)

> **Status:** Proposed (2026-07-30) — specification complete, awaiting plan + implementation
> **Scope:** Cross-cutting. Touches US-3, US-4, and future-ideas F-1 / F-2 / F-4.
> **Origin:** Analysis of [`TNG/oh-my-agentic-coder`](https://github.com/TNG/oh-my-agentic-coder) (`omac`), a Go sandbox facade+supervisor for agentic coders. omac wraps Seatbelt (macOS) / bubblewrap+Landlock (Linux) the way our `saife` wraps AppContainer. Its `internal/netproxy`, `internal/netprompt`, `internal/intent`, and `internal/audit` packages implement patterns directly applicable to our deferred features.
> **Grilling:** 60 design questions resolved in a structured review session. Decisions are marked **[G-N]** where N is the question number. This document is the authoritative specification; the implementation plan derives from it.

## Context

Our `saife` MVP ships three pillars: AppContainer FS isolation (US-1/US-2 + Option E), an audit trail (US-4), and network filtering (US-3). US-3's spec is fully drafted but its `--allow-domain`/`--network-profile` path is **non-functional unprivileged** today: the chosen loopback-exemption API (`NetworkIsolationSetAppContainerConfig`) is admin-only and system-wide, so the proxy, token plumbing, and filter logic are implemented and unit-tested but cannot be exercised end-to-end without admin. The unprivileged fix (`privateNetworkClientServer` capability SID on the AppContainer token) is tracked as a follow-up in the US-3 spec.

Several adjacent features are explicitly deferred to `future-ideas.md`:
- **F-1** — upstream corporate proxy chaining, raw TCP/SOCKS5, per-endpoint filtering, `--open-port`/`--listen-port` IPC.
- **F-2** — credential injection via the proxy (header/url/query/basic_auth modes), keystore backend.
- **F-4** — runtime supervisor (dynamic mid-session permission expansion), noted as having "no seccomp-notify equivalent on Windows."

omac solves all of these *on top of* a localhost CONNECT proxy that is architecturally identical to the one our US-3 spec already designs. omac's implementations are battle-tested (the repo has 227 commits, e2e tests, audit trail, multi-harness support) and the code is small enough to port the *patterns* without adopting the Go runtime.

## Decision

Adopt five omac-derived patterns plus a keystone fix (task zero), each scoped to a concrete deliverable, each ported to Rust on top of our existing US-3 proxy. They are listed in dependency order; later ones build on earlier ones.

### D-0. Capability SID fix (task zero — unblocks D-1, D-3, D-4)

**[G-1, G-21, G-34, G-53, G-58]** Replace the admin-only `NetworkIsolationSetAppContainerConfig` loopback exemption with a `privateNetworkClientServer` capability SID on the AppContainer token. This is a runtime token attribute (passed to `CreateProcessW` via `PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES`), not a system-wide config call — no admin required, no `saife setup` step.

- **Remove `src/net/loopback.rs` entirely** and the downgrade-to-`--block-net` logic. The admin-only API was system-wide (modifies a global loopback-allow list for *all* AppContainers) — keeping it as a fallback would be a security regression (broader scope than the per-process capability SID). **[G-58]**
- **No `saife setup` step for network.** `setup --check-only` reports the effective network posture but performs no admin action for network. The only setup steps remain the existing FS-related ones (drive-root grant, signing key generation). **[G-53]**
- **Intranet leak (documented limitation):** the `privateNetworkClientServer` capability grants loopback **+ intranet** (e.g. `192.168.*`, `10.*`, `fc00::/7`), not public internet. Raw-socket apps can reach LAN hosts directly without proxy filtering. `--block-net` (zero capability SIDs) remains the strong-isolation escape hatch. The WFP callout driver (F-6) is the real fix for this gap. Documented in `setup --check-only` with an explicit warning. **[G-21, G-34]** **Bidirectional (validated by MXC source, 2026-09-16):** the capability also grants **inbound** private-network access — a sandboxed process that calls `listen()` accepts connections from LAN peers. MXC's AppContainer fallback *rejects* ingress-allow policies while this capability is present ("privateNetworkClientServer grants bidirectional private-network access", `appcontainer_runner.rs:1747`). Mitigation identical to the egress case: documented limitation, `--block-net` escape hatch, F-6 (WFP) the real fix; a future `allowedProxyPeer`-style PSEC loopback grant is the interim once the OS APIs reach stable Windows. See `docs/research/mxc-source-analysis.md` (F-A).

**Sequencing:** D-0 is task zero. D-1, D-3, and D-4 cannot be exercised end-to-end without it (they live in the proxy path, which receives zero traffic unprivileged until the capability SID lands). D-2 and D-5 can be written against unit tests independently but should integrate after D-0. **[G-1]**

### D-1. Filter decision pipeline with DNS pinning (closes US-3 unprivileged gap)

**[G-12, G-18, G-22, G-27, G-29, G-32, G-33, G-44, G-45, G-55]** Port omac's `internal/netproxy/filter.go` decision pipeline as the authoritative implementation of our US-3 AC-3.3–3.7. The pipeline is:

1. **Hard deny** (never promptable, overrides everything): **[G-18, G-45]**
   - Hostname set (string match, case-insensitive, trailing dot stripped): `169.254.169.254`, `169.254.169.253`, `metadata.google.internal`, `metadata.azure.internal`, `metadata.tencentyun.com`.
   - IP set (parse literal, compare): `169.254.169.254`, `169.254.169.253`, `100.100.100.200`.
   - Link-local CIDR check on resolved IPs: `169.254.0.0/16`, `fe80::/10` (incl. IPv4-mapped IPv6 forms, after unmapping).
   - Two separate checks (hostname set + IP set) so audit `source: "hard-deny"` attribution is precise.
   - The list is a compiled-in constant, **not** profile-configurable (matching omac's "never promptable" semantics). Users add deny entries via `deny_domain` (which *is* profile-configurable). **[G-18]**
2. **Learned permanent deny** (from the persisted learned-policy file — see D-3).
3. **`deny_domain` blocklist** match. **[G-32]** New: our US-3 spec had no `deny_domain`. Add `--deny-domain <d>` CLI flag (repeatable) and `network.denyDomain` profile field. Checked before allow-list so a deny always wins over an allow. **[G-33]**
4. **Allow** if matched by `allow_domain` or a learned permanent allow. Wildcard `*.suffix` matches the apex (`suffix` itself) and any subdomain (`*.suffix` → `host == suffix || host ends with "."+suffix`). **[G-55]**
5. **Default**: if prompt enabled (D-3), prompt the user; else deny if `allow_domain` is non-empty (allowlist mode); else allow (pure blocklist mode).

**Pipeline ordering is load-bearing** for audit `source` attribution: learned-deny (step 2) reports `source: "learned"`, `deny_domain` (step 3) reports `source: "blocklist"`. A host that's both learned-denied and blocklisted reports `learned` (the user's explicit past decision is more informative). **[G-33]**

**DNS pinning (anti-rebinding):** resolve the hostname *once* per request via the system resolver, then dial the resolved IPs directly — never re-resolve. **[G-12]**

**Happy Eyeballs (RFC 8305):** race the pinned addresses concurrently, capped at 8 parallel dials (`maxParallelDials`), first winner cancels the rest, losers that already connected are closed. Handles the dead-AAAA-record case (common on Windows VPNs that break IPv6). ~80 lines of tokio (`futures::select_all` or `tokio::select!` over a semaphored set). **[G-12]**

**Under upstream chaining (D-2):** skip local DNS and IP pinning entirely — run hostname-only admission (`CheckHost` in omac's terms). The upstream proxy performs its own DNS; a local resolution that returns link-local might be wrong for the corporate proxy's view. Link-local-via-DNS-rebinding is the upstream proxy's defense to own. The hostname-based hard-deny list catches known-bad metadata names regardless of chaining. **[G-22]**

**Proxy auth: `Proxy-Authorization: Basic` with userinfo in the proxy URL** (`http://sandbox:<token>@127.0.0.1:<port>`), replacing the `X-Sandbox-Token` header approach. Standard HTTP clients (`curl`, Python `requests`, Node `fetch`, `git`, `npm`, `pip`) auto-send `Proxy-Authorization` with no extra configuration. Constant-time token comparison. `407 Proxy Authentication Required` on missing/invalid token. The token is session-scoped (256-bit, `BCryptGenRandom`), rotated per session. **[G-27, G-54]**

**Raw tunnel, no TLS termination:** the proxy filters on hostname only, splices bytes for CONNECT. TLS is end-to-end between the sandboxed process and the real host. The proxy never sees keys, paths, or bodies. `rustls` is dropped from the proxy's hot path (it's only needed if F-2/F-18 later add selective TLS termination for credentialed routes). **[G-29]**

**CONNECT to loopback refused:** the proxy refuses `CONNECT` to any loopback host (`127.0.0.1`, `::1`, `localhost`, `*.localhost`) with `403` + `X-Sandbox: denied` header. The child reaches the intent endpoints (D-4) via non-CONNECT HTTP (covered by `NO_PROXY`), not via CONNECT. Prevents the proxy from becoming a tunnel to host services. **[G-44]**

### D-2. Upstream corporate proxy chaining (closes F-1, HTTP/HTTPS case)

**[G-10, G-11, G-14, G-22, G-24, G-30, G-42, G-49]** Port omac's `internal/netproxy/dialer.go` `upstreamProxyDialer` as a second `Dialer` implementation alongside the direct dialer. When `HTTPS_PROXY`/`HTTP_PROXY` is set in the host environment (or `network.upstreamProxy` in the profile), the proxy chains allowed requests through the corporate egress proxy via HTTP CONNECT.

**Precedence:** profile `network.upstreamProxy` > host env `HTTPS_PROXY`/`HTTP_PROXY` (read at launch, never forwarded to child) > none (direct dial). **[G-10]**

**Warning on override:** if profile `upstreamProxy` is set *and* host `HTTPS_PROXY` is also set and they differ, emit a `SAIFE_DIAG` warning. **[G-42]**

**Child env isolation:** the child always gets our loopback-only `HTTP_PROXY`/`HTTPS_PROXY` (`http://sandbox:<token>@127.0.0.1:<port>`) and `NO_PROXY=localhost,127.0.0.1,::1` — never the upstream's env vars. The upstream chaining is entirely a supervisor-side concern. **[G-10]**

**CONNECT-only through upstream:** we do not support plain-HTTP forwarding through the upstream proxy (the `X-Sandbox-Token`/`Proxy-Authorization` strip footgun). Plain-HTTP forwarding remains on the direct path only; through upstream, CONNECT tunnels are opaque. **[G-24]**

**`NO_PROXY` matching:** hosts matching an entry bypass the upstream proxy and dial the server-pinned IPs directly (with Happy Eyeballs). Matching is hostname-suffix (`host == entry || host ends with "."+entry`), case-insensitive. No leading-dot form, no CIDR — consistent with our `allow_domain`/`deny_domain` wildcard matching. **[G-11]**

**Both dial paths preserved:** `NO_PROXY` matches dial direct (with pinned IPs + Happy Eyeballs); non-matches chain through upstream (hostname-only, no Happy Eyeballs). Mutually exclusive per-request. **[G-49]**

**Basic auth** via the proxy URL (`http://user:password@proxy:8080`), sent as `Proxy-Authorization: Basic`. Credentials held in the dialer struct for the proxy's lifetime (needed for each new CONNECT). Never forwarded to child, never logged, never in error bodies (upstream error bodies redact the proxy URL to host:port only). `ZeroizingString` as a drive-by if cheap. **[G-30]**

**NTLM/Kerberos:** not supported. Document the `cntlm`/`px` local-bridge workaround. A spike to evaluate `winhttp` for native NTLM is tracked as a follow-up in `future-ideas.md` — a potential Windows differentiator over omac, but not on the critical path. **[G-14]**

### D-3. Interactive network prompt + learned persistence (implements F-4's network-expansion case)

**[G-2, G-3, G-4, G-5, G-6, G-15, G-17, G-19, G-20, G-23, G-28, G-36, G-37, G-40, G-43, G-46, G-47, G-48, G-51, G-52, G-56]** Port omac's `internal/netprompt` as the Windows-feasible equivalent of the seccomp-notify runtime supervisor. The prompt lives **in the proxy path**, not in a syscall trap.

**Dialog backend:** `TaskDialogIndirect` (Common Controls v6, Win7+) with all six custom buttons. Run via `tokio::task::spawn_blocking` so the async proxy handler awaits without blocking tokio worker threads. Fire-and-forget toast notification (`ToastNotificationManager`) on a separate `spawn_blocking` thread as a secondary alert. **[G-2, G-3]**

**Six buttons:** `Allow once`, `Allow permanently (this host)`, `Allow permanently (*.{suffix})`, `Deny once`, `Deny permanently (this host)`, `Deny permanently (*.{suffix})`. The suffix hint is in the button label itself (e.g. "Allow permanently (*.npmjs.org)") so the user sees exactly what the permanent decision covers. Default: `Deny once`. Dialog cancel = `Deny once`. **[G-3, G-43]**

**Suffix computation:** host with leftmost label removed when ≥3 labels, else the host itself. IP literals are never suffix-generalized. **[G-43]**

**Focus-stealing:** the dialog grabs input focus (no `TDF_NO_FOCUS`), matching UAC behavior. The toast is the non-intrusive secondary alert. **[G-37]**

**Dialog content:** shows `host:port` and, *if* an intent is on file (D-4), appends `Agent reason: "<reason>"` (quoted, verbatim). If no intent, the reason line is omitted. Multi-line `pszContent` field. **[G-17]**

**No PID attribution in the dialog** for this ADR. The audit trail records the PID per `net.decision` event for forensics, but the dialog shows only host:port + agent reason. Per-PID attribution via `GetExtendedTcpTable` is a post-MVP polish item. **[G-23]**

**Timeout:** `network.promptTimeoutSecs` profile field, default 60s. Profile-only, no CLI flag. A value of `0` means "instant deny" (equivalent to `--no-prompt` but per-profile). Timeout → `onUnavailable` policy. A timed-out prompt **must never** default to allow unless `onUnavailable` is explicitly `allow`. **[G-46]**

> **Amended 2026-10-25 (session `limits` section).** The field is **`limits.promptTimeoutSecs`** now: a top-level section beside `network`, because the term bounds the SESSION (and its `workloadTimeoutSecs` sibling does too) rather than host matching — a `--block-net` session is bounded by the same terms. `network.promptTimeoutSecs` is rejected, not aliased. The terms keep the semantics documented above: the prompt term is validated `0..=86400`, where `0` **still** means "instant deny" (the dialog deadline is `Duration::from_secs(0)` and expires at once), and the workload term is validated `1..=86400` because `0` there would end a session before its child ran. Out-of-range values fall back to their default with a warning. `crate::profile::Limits::session_budget()` derives the container deadline from the resolved limits (`SessionBudget::from_config`), and `NetworkConfig` no longer carries either term.

**Orphaned dialog on timeout:** the `TaskDialogIndirect` call keeps running on the blocking thread even after the timeout fires and the proxy returns a deny. The dialog stays until the user clicks; the click result is discarded. Accepted quirk, matching omac's behavior on macOS. **[G-4]**

**Semaphore cap:** at most 8 concurrent prompts via `tokio::sync::Semaphore`. The 9th concurrent prompt for a *new* host is immediately denied with `source: "prompt_overload"` and an audit event. Bounds resource usage; the agent sees denials instead of orphaned dialogs. **[G-28]**

> **Amended 2026-10-22 (P2.1 reviews).** The sentence above is true of the **consultations** the proxy is blocked on, and it was never the bound on live dialogs. Since [G-4] a dialog that outlives its prompt budget is *abandoned*: still on screen, still a blocking thread, no longer waited on — so "at most 8 concurrent prompts" stopped describing the process the moment a budget could elapse. The bound is **two pools**: `MAX_CONCURRENT_PROMPTS` = 8 consultations, plus `MAX_ABANDONED_PROMPTS` = 16 abandoned windows, which is also the bound on **live dialogs** because every dialog holds an abandoned permit for its whole life. **Normative: 8 consultations, at most 16 live dialogs.** The refusal stays fail-closed and stays `source: "prompt_overload"`, but it now names which pool ran out (`reason: "too many concurrent prompts"` vs `prompt_abandoned_capacity`): one reason for two causes is what made a headless session's audit read as a concurrency limit with no dialog on screen. Separately, three consecutive consultations that produce no decision arm a fast-fail that applies the `onUnavailable` policy immediately instead of paying another budget per host: `reason: "no_dialog_backend"` when no dialog could be shown, `reason: "prompt_suppressed_after_budget"` when the dialogs were shown and nobody answered. **Normative bounds of that latch (armed 2026-10-22, second P2.1 review round):** three consecutive LEADER consultations, deny posture only (under `onUnavailable: allow` a skip would *permit* every later unlisted host and delete the user's veto), cleared at every launch (a listener serves one run's token but may serve sequential launches), and re-probed once after a cooldown so an operator who returns to a still-open dialog is answered rather than ignored — see [G-19] and [G-46].

**Coalescing:** concurrent requests for the same host share one dialog (mutex + `tokio::sync::oneshot`; followers park on the leader's result). Keyed by hostname only (not host:port), consistent with the host-based allow-list. **[G-6]**

**Headless/no-dialog-backend:** `onUnavailable` policy applies. Default `deny` with a discoverable `SAIFE_DIAG` stderr diagnostic on first denial: "no dialog backend available; all non-allow-listed hosts denied; use `--allow-domain` or `--network-profile` to pre-approve, or set `on_unavailable=allow` (insecure)." **[G-19]**

**Prompt enablement:** `network.promptEnabled` profile field. Default `true` when network is active (i.e. not `--block-net`). Network active implies prompt active unless explicitly disabled via `network.promptEnabled: false` or `--no-prompt`. **[G-47, G-59]**

**`--no-prompt` CLI flag:** disables the dialog entirely; sets `onUnavailable=deny` without trying to spawn a dialog. Distinct from `onUnavailable=deny` (which means "try to prompt, fall back to deny"): `--no-prompt` → `source: "default"` (no prompt attempt); `onUnavailable=deny` → `source: "unavailable"` (prompt attempted, failed). They compose: `--no-prompt` + `onUnavailable=allow` means "don't prompt, allow unclassified" (permissive CI). **[G-36, G-48]**

**`onUnavailable` policy:** `network.onUnavailable: "deny" | "allow"` profile field, default `"deny"`. **[G-48]**

**`--block-net` interaction:** under `--block-net` (zero network capability SIDs, no proxy), the prompt never fires. The prompt setting is silently ignored. The agent gets `ERROR_ACCESS_DENIED` from the kernel. **[G-15]**

**`--no-prompt` and learned entries:** `--no-prompt` disables prompting only; learned entries (read at startup) still apply. A CI runner reusing a profile with learned-allows from a prior interactive session gets those allows. No new learned entries are created under `--no-prompt` (no prompt → no user decision → nothing to persist). **[G-40]**

**Learned persistence:**
- Permanent decisions (host or suffix scope) persisted immediately and atomically (write-temp + `MoveFileEx(MOVEFILE_REPLACE_EXISTING)` with 3x retry + 50ms backoff for AV locks, fallback to direct write). **[G-56]**
- Stored at `%USERPROFILE%\.saife\learned\<profile-name>.json` (outside `$CWD`, CR-10 defense). Unnamed profile → `learned/default.json`. **[G-5]**
- **Our own format** (not nono-compatible), aligned with US-5 camelCase conventions: `{"schema":1,"allow":[{"host":"...","scope":"host"|"suffix"}],"deny":[{"host":"...","scope":"host"|"suffix"}]}`. Uses `disposition` (matching US-4 audit field naming), not omac's `decision`. **[G-20, G-39]**
- Loaded into the filter on every launch (steps 2 and 4 of the D-1 pipeline). **[G-33]**

**`saife learned` CLI subcommand:** `saife learned list` / `saife learned revoke <host>` / `saife learned clear`. Discoverable revocation — the user doesn't need to edit JSON. The learned file remains human-editable as a fallback. **[G-51]**

**Deny response shape:** `403 Forbidden` with `X-Sandbox: denied` header + plain-text body naming the host, the policy reason, and remediation paths (profile, allow-list, learned file). For intent-related denials, add `X-Sandbox-Intent-Hint` header (since HTTPS clients discard the body). Dual-channel: body for humans, headers for machines. **[G-52]**

### D-4. Agent-declared intent registry (new UX layer on D-3)

**[G-7, G-8, G-16, G-25, G-26, G-35, G-38, G-57]** Port omac's `internal/intent/registry.go` as a TTL-evicted in-memory store where the agent POSTs "I want to reach host X because Y" *before* the network request, and the prompt dialog displays that reason.

**Endpoints** (mounted on the proxy's loopback listener under `/sandbox/` prefix, same listener + same `Proxy-Authorization: Basic` token): **[G-7, G-38]**
- `POST /sandbox/intent` — body: `{"target":"api.example.com","reason":"fetching latest model list"}` → `204 No Content`. `400 Bad Request` on malformed body. Reasons >500 chars are truncated (not rejected). **[G-57]**
- `GET /sandbox/intent?host=<host>` → `200 OK` with `{"host":"api.anthropic.com","reason":"fetching model list","ts":"2026-07-30T..."}` or `404 Not Found`. **[G-57]**
- `POST /sandbox/intent/explain` — body: `{"host":"..."}` → `204 No Content`. Records one-shot "Explain more" flag. **[G-57]**

**Same listener, same token:** the child reaches these via `NO_PROXY=localhost,127.0.0.1,::1` bypass (direct, not through the proxy). A `SAIFE_PROXY_PORT` env var is injected for discoverability. **[G-7, G-35]**

**Normalization:** target is canonicalized to lowercased hostname (port stripped, path stripped, URL form → hostname, `host:port` → host). Accepts URL / `host:port` / bare host. Consistent with D-3's host-only coalescing. **[G-8]**

**Timing:** intent POST and CONNECT are independent requests; the registry is eventually-consistent (in-memory map, lock-protected). The agent cooperates by declaring first. If the agent issues CONNECT before the POST completes, the prompt shows no reason. **[G-25]**

**"Explain more" recovery loop:** one-shot flag (consumed on read). No retry cap — rely on the one-shot semantics + the user's "Deny permanently" button to stop storms. A looping agent burns its own context window; the audit trail records the pattern. **[G-26]**

**In-memory only, no disk persistence.** Lost on supervisor restart — the agent re-declares and re-prompts, which is the correct recovery path. **[G-16]**

**TTL + bounds:** 10-minute default TTL, background sweeper at TTL/2. Max 500 entries; on overflow, evict the oldest. Max reason length 500 chars (truncated). **[G-16]**

**Trust boundary:** no auth of its own — reachable only via the proxy's loopback listener (already token-gated). Agent-supplied reasons are advisory: shown to the user, never auto-grant. Same-user local process could plant intents, but such a process already sits outside the sandbox — accepted (matching omac's posture). **[from omac `registry.go:54-63`]**

### D-5. Audit event taxonomy alignment (extends US-4)

**[G-9, G-13, G-31, G-50]** Adopt omac's audit event types and source-attribution scheme in our US-4 audit schema.

**Augment existing `CONNECT` event** (do not rename to `net.decision`): **[G-9]**
- Add `source` enum: `hard-deny` / `learned` / `blocklist` / `allowlist` / `prompt` / `unavailable` / `dns` / `default` / `prompt_overload`.
- Add `scope` (nullable: `once` / `host` / `suffix`).
- Add `persisted` (bool).
- Keep existing `disposition` (`allow` / `deny`) and optional `reason` free-text field.
- `source` subsumes the free-text `reason` for common cases; `reason` remains for detail (e.g. `source: "dns"`, `reason: "SERVFAIL"`).

**`secret.inject` event:** schema defined now (name only, never value), emission deferred until F-2 (credential injection) lands. Reserved in the taxonomy so F-2 doesn't need a schema change. **[G-50]**

**Canonicalization:** no change to US-4's field-agnostic canonicalization (SHA-256 over the leaf with `hash` and `parent` removed, `BTreeMap`-sorted). New fields are automatically included in the hash. No schema versioning needed — adding enum values later doesn't break old logs. **[G-31]**

**`--audit-strict` flag:** default **off** (fail-open: write error → stderr warning, run continues). Opt-in fail-closed (refuse to start if log can't be opened; abort if a write fails mid-session). Flip default to fail-closed when F-2 lands (secret-injection makes unrecorded `net.decision` a security gap). **[G-13]**

## Consequences

### Positive

- **Closes the US-3 unprivileged gap** with a reference implementation that has the edge cases worked out (D-0 + D-1). No admin required for network.
- **Closes F-1 (upstream proxy, HTTP/HTTPS case)** and **F-4 (network runtime supervisor)**, both previously deferred, using infrastructure (the proxy) we already have to build.
- **D-3 + D-4 together** transform the network UX from "deny everything not pre-allowed" to "prompt with agent-declared context, learn permanently" — the model nono ships and our critical-review.md endorses.
- **D-5** makes the audit trail immediately more useful with near-zero implementation cost (one enum field, a few new event types).
- All patterns are **mechanism-agnostic** — they sit above the AppContainer layer, so they survive a future pivot to the OpenAI composition (Option A) or a WFP driver (F-6) without rework.

### Negative

- **Adds UI surface.** D-3 introduces a native dialog; on headless/CI hosts it falls back to `onUnavailable=deny` with a `SAIFE_DIAG` diagnostic. The `--no-prompt` flag is the explicit opt-out.
- **Intranet leak (D-0).** The `privateNetworkClientServer` capability grants loopback + intranet. Raw-socket apps can reach LAN hosts without proxy filtering. `--block-net` is the strong-isolation escape hatch; F-6 (WFP driver) is the real fix. Documented in `setup --check-only`. The leak is **bidirectional** (validated by MXC source, 2026-09-16): the capability also grants **inbound** private-network access — a sandboxed process that calls `listen()` accepts connections from LAN peers, and MXC's AppContainer fallback *rejects* ingress-allow policies while this capability is present ("privateNetworkClientServer grants bidirectional private-network access", `appcontainer_runner.rs:1747`). Mitigation identical to the egress case — documented limitation, `--block-net` escape hatch, F-6 (WFP) the real fix; a future `allowedProxyPeer`-style PSEC loopback grant is the interim once the OS APIs reach stable Windows. See `docs/research/mxc-source-analysis.md` (F-A).
- **D-3's learned-policy file** is a new config-based-sandbox-escape vector if stored inside the writable workspace. Mitigated by storing under `%USERPROFILE%\.saife\learned\` (CR-10 defense).
- **D-2's NTLM/Kerberos gap** — users behind NTLM proxies need a local `cntlm`/`px` bridge. A `winhttp` spike is tracked as a follow-up.
- **Porting effort:** D-1+D-2+D-3+D-4 are roughly 1000–1500 lines of Rust. D-5 is ~100 lines. Bounded, with a working reference for every behavior.
- **Orphaned dialogs on timeout** — the dialog stays on screen until the user clicks; the result is discarded. Accepted quirk, matching omac.

### Neutral

- This ADR does **not** adopt omac's sidecar/facade/skills architecture. F-2 (credential injection) sketches a simpler proxy-header-injection variant. omac's `secrets:`/`config:` schema is a reference for a future skill/plugin system, out of scope here.
- omac's seatbelt/bwrap profile generation is platform-specific and not portable. The grant-set struct shape is a clean model worth comparing to our `ResolvedProfile`, but no code is shared.

## Explicitly deferred (not in this ADR)

- **F-2** credential injection (`secret.inject` emits at F-2).
- **F-4** FILE_EXPANSION / COMMAND_APPROVAL (only NETWORK_EXPANSION via prompt).
- **F-6** WFP callout driver (the real fix for intranet leak + per-port loopback scoping).
- **F-18** network content inspection (TLS termination).
- **Per-PID attribution** in dialogs. **[G-23]**
- **Auto-detection** of headless mode. **[G-36]**
- **NTLM/Kerberos** native support (`winhttp` spike). **[G-14]**
- **Plain-HTTP forwarding** through upstream proxy. **[G-24]**
- **Retry cap / prompt-storm protection.** **[G-26]**
- **omac sidecar/skills/facade architecture.**

## Implementation sequencing

**[G-1]** Task zero (D-0) is the critical path — D-1, D-3, D-4 cannot be exercised end-to-end without it. After D-0:

1. **D-5** (audit fields) — cheapest, no dependencies, ~100 lines.
2. **D-3 + D-4** (prompt + intent) — co-dependent, the prompt consumes the intent.
3. **D-2** (upstream chaining) — independent of D-3/D-4.
4. **D-1** (full filter pipeline) — integrates everything, exercised end-to-end after D-0.

## References

- omac repo (cloned locally for reference, not part of this repo): `https://github.com/TNG/oh-my-agentic-coder`
- omac design doc: `oh-my-agentic-coder.md` (§5 architecture, §9 env contract, §10 CLI, §12 start lifecycle, §13 proxy semantics)
- omac filter pipeline: `internal/netproxy/filter.go`
- omac proxy server + upstream chaining: `internal/netproxy/server.go`, `internal/netproxy/dialer.go`
- omac interactive prompt spec: `openspec/changes/native-sandbox/specs/sandbox-network/spec.md`
- omac intent registry: `internal/intent/registry.go`, `internal/intent/hints.go`
- omac audit: `internal/audit/` (event types in `event.go`, redaction in `redact.go`)
- Our related specs: `docs/design/specs/us-3-.../spec.md` (network), `docs/design/specs/us-4-.../spec.md` (audit), `docs/notes/future-ideas.md` (F-1, F-2, F-4, F-6)
- Our critical review: `docs/design/critical-review.md` (CR-1, CR-3, CR-10)
