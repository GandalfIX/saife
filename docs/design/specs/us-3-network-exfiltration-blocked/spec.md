# US-3: Network exfiltration blocked

> **Status:** Implemented (partial) — `--block-net` works unprivileged;
> `--allow-domain` / `--network-profile` / proxy deferred pending
> unprivileged loopback mechanism.
> **Implementation finding (2026-07-26):** the spec's chosen loopback
> mechanism (`NetworkIsolationSetAppContainerConfig`) is admin-only — MSDN
> documents it as "used for debugging purposes" and it sets a system-wide
> loopback-allow list. Running unprivileged it returns
> `ERROR_ACCESS_DENIED (0x5)`, making `--allow-domain` non-functional
> without admin. `--block-net` needs no loopback exemption and works
> fully unprivileged. The unprivileged alternative (a
> `privateNetworkClientServer` capability SID on the AppContainer token)
> is tracked as a follow-up. See "Implementation-ready detail → Loopback
> exemption deferral" below.
> Next: compare with nono, then expand to implementation-ready.

## User Story

As a developer, I want to run an agent with `--block-net` so that even if a
prompt-injected dependency tries to POST my source code to an attacker's
server, the connection is refused at the proxy and logged. And I want
`--allow-domain` to give me a precise allow-list of hosts the agent may
reach, so that legitimate LLM API calls work while everything else is denied.

## Narrative

The user starts an agent with a network profile: `--network-profile minimal`
(only LLM APIs) or `--allow-domain api.anthropic.com`, or `--block-net` for
total network denial.

Two enforcement layers compose:

1. **AppContainer network capability**: by default the sandboxed process has
   no network capability at all — direct `connect()` to any host is denied by
   the kernel. The supervisor `sandbox.exe`, running **outside** the
   AppContainer, starts a localhost HTTP(S) reverse proxy on a random
   `127.0.0.1` port.
2. **Loopback exemption**: the sandboxed process's token is granted a loopback
   capability scoped to `127.0.0.1:<proxy-port>` only, so it can talk to the
   proxy and nothing else.

The sandboxed process is configured (via `HTTP_PROXY`/`HTTPS_PROXY`
environment variables set in its spawned environment, plus a session token in
`X-Sandbox-Token`) to route all outbound HTTP(S) through the proxy. The proxy
resolves the target host, checks it against the domain allow-list (exact match
or `*.suffix` wildcard), and either forwards the request (logging
`ALLOW CONNECT host:port`) or drops it (logging
`DENY CONNECT host:port reason=...`).

Apps that respect env-var proxies (curl, Python `requests`, Node `fetch`
with `HTTPS_PROXY`, dotnet `HttpClient`) just work. Apps that ignore
env-var proxies and try raw sockets (git over SSH, gRPC, custom TCP) hit the
AppContainer network-cap denial and fail closed — they get
`ERROR_ACCESS_DENIED` on `connect()`. This is the documented MVP behavior;
SOCKS5 support for raw-socket apps is future-ideas F-1.

Always-denied destinations (cloud metadata endpoints) are blocked even when
explicitly allow-listed:

- `169.254.169.254` — AWS/GCP/Azure metadata
- `169.254.0.0/16` — IPv4 link-local
- `fe80::/10` — IPv6 link-local
- `metadata.google.internal` — GCP metadata DNS name

## Scope (MVP)

In scope:

- `--block-net` flag: no network capability, no proxy, all `connect()` denied.
- `--allow-domain <d>` repeatable flag; `*.suffix` wildcard support.
- `--network-profile <name>` with built-in profiles `minimal`, `developer`,
  `none` (alias for `--block-net`).
- Profile `network.allow_domain` array, merged with CLI flags.
- Localhost reverse proxy (Tokio + hyper + rustls) started by `sandbox.exe`
  before the sandboxed process launches.
- `HTTP_PROXY` / `HTTPS_PROXY` / `X-Sandbox-Token` env vars injected into the
  sandboxed process.
- AppContainer token with loopback exemption scoped to the proxy port.
- Always-denied CIDR / DNS list, non-overridable.
- Audit-log entries for every connection attempt (allowed and denied) — the
  event schema is US-4; here we only specify what gets emitted.
- Proxy rejects unknown session tokens with HTTP `407 Proxy Authentication
  Required` (so a misbehaving app that ignores the env vars and tries to
  reach `127.0.0.1:<proxy-port>` directly is still blocked).

Out of scope:

- Raw TCP / SOCKS5 proxy — future-ideas F-1 (open question OQ-3 in PRD).
- Per-port localhost IPC (`--open-port` / `--listen-port`) — future-ideas
  F-1.
- Endpoint-level filtering (`--allow-endpoint openai:POST:/v1/chat/...`) —
  future-ideas F-1.
- Upstream corporate proxy chaining — future-ideas F-1.
- WFP callout driver for kernel-level rules — future-ideas F-6.

## Acceptance Criteria

### AC-3.1 — `--block-net` denies all connections
**Given** `sandbox run --allow-cwd --block-net -- cmd`,
**When** the sandboxed process executes
`python -c "import urllib.request; urllib.request.urlopen('https://api.openai.com')"`,
**Then** `urlopen` raises `URLError`/`ConnectionError`; the OS denied the
`connect()` because the AppContainer token has no network capability.

### AC-3.2 — `--block-net` denies raw sockets too
**Given** `--block-net` is active,
**When** the sandboxed process executes
`python -c "import socket; socket.create_connection(('169.254.169.254',80))"`,
**Then** `create_connection` raises `PermissionError` (or the Windows
equivalent). No packet leaves the machine.

### AC-3.3 — `--allow-domain` permits the listed host
**Given** `sandbox run --allow-cwd --allow-domain api.anthropic.com -- cmd`,
**When** the sandboxed process does
`curl https://api.anthropic.com/v1/messages` (and curl honors
`HTTPS_PROXY`),
**Then** the request succeeds. The proxy logged
`ALLOW CONNECT api.anthropic.com:443`.

### AC-3.4 — `--allow-domain` denies an unlisted host
**Given** the same invocation as AC-3.3,
**When** the sandboxed process does `curl https://evil.example.com`,
**Then** the proxy drops the connection and logs
`DENY CONNECT evil.example.com:443 reason=domain_not_allowed`. curl reports
a proxy error.

### AC-3.5 — Wildcard suffix matches
**Given** `--allow-domain *.anthropic.com`,
**When** the process connects to `api.anthropic.com` and
`console.anthropic.com`,
**Then** both are allowed. A connection to `anthropic.com.evil.io` is denied
(the wildcard does not match across dots).

### AC-3.6 — Always-denied list overrides explicit allow
**Given** `--allow-domain 169.254.169.254 --allow-domain api.anthropic.com`,
**When** the process connects to `169.254.169.254`,
**Then** the connection is denied and logged as
`DENY CONNECT 169.254.169.254:80 reason=denied_cidr` — even though the user
explicitly listed it.

### AC-3.7 — `metadata.google.internal` is denied
**Given** any network configuration,
**When** the process connects to `metadata.google.internal`,
**Then** it is denied (the DNS name is on the always-denied list before
resolution).

### AC-3.8 — Built-in `minimal` profile covers LLM APIs
**Given** `--network-profile minimal`,
**When** the process connects to `api.openai.com`, `api.anthropic.com`,
`generativelanguage.googleapis.com`,
**Then** all three are allowed. Connections to `github.com` or
`registry.npmjs.org` are denied.

### AC-3.9 — Built-in `developer` profile adds registries + GitHub
**Given** `--network-profile developer`,
**When** the process connects to LLM APIs, npm/PyPI/crates.io, and
`github.com`,
**Then** all are allowed.

### AC-3.10 — Profile + CLI flags merge
**Given** a profile with `network.allow_domain: ["api.anthropic.com"]` and the
CLI flag `--allow-domain github.com`,
**When** the process connects to both,
**Then** both are allowed.

### AC-3.11 — Proxy port is randomized
**Given** two concurrent `sandbox run` invocations,
**When** each starts its proxy,
**Then** they bind to different random `127.0.0.1` ports; neither fails with
`EADDRINUSE`.

### AC-3.12 — Direct connect to proxy port without token is rejected
**Given** a sandboxed process knows the proxy port but not the session token,
**When** it sends an HTTP request to `127.0.0.1:<port>` without
`X-Sandbox-Token`,
**Then** the proxy responds `407 Proxy Authentication Required` and does not
forward the request.

### AC-3.13 — Apps ignoring env-var proxies fail closed
**Given** `--allow-domain api.openai.com` is set and `HTTPS_PROXY` env var is
injected,
**When** a sandboxed raw-socket app ignores `HTTPS_PROXY` and tries
`socket.connect(('api.openai.com', 443))` directly,
**Then** the AppContainer token denies the connect (it only allows
`127.0.0.1:<proxy-port>`). The app fails closed. The audit log records
`DENY CONNECT api.openai.com:443 reason=direct_connect_blocked`.

### AC-3.14 — Proxy shuts down with the sandbox
**Given** a sandboxed session is running with the proxy active,
**When** `sandbox.exe` exits — normally or via `Ctrl-C`,
**Then** the proxy port is released within 1 second (no lingering listener).

### AC-3.15 — Loopback-only scope
**Given** a sandboxed process with a proxy on `127.0.0.1:51234`,
**When** the process tries `socket.connect(('127.0.0.1', 51235))` (a
different loopback port),
**Then** the connect is denied — the loopback exemption is scoped to the
proxy port only, not the whole loopback range.

## nono comparison

### What we match

- **`--block-net`**: identical semantics — all outbound network denied,
  kernel-enforced.
- **`--allow-domain <d>`** with `*.suffix` wildcard: same matching algorithm
  (suffix match, dot-bounded — `*.anthropic.com` does not match
  `anthropic.com.evil.io`).
- **Always-denied destinations**: identical list — `169.254.169.254`,
  `169.254.0.0/16`, `fe80::/10`, `metadata.google.internal`. Non-overridable
  by any profile.
- **Built-in network profiles**: `minimal` (LLM APIs only) and `developer`
  (adds package registries + GitHub) map directly. We add `none` as an alias
  for `--block-net`.
- **Localhost reverse proxy architecture**: same design — proxy on a random
  `127.0.0.1` port, sandboxed process routed via env vars + session token.
  nono does this on Linux when Landlock ABI < v4 (per-port rules unavailable);
  we do it unconditionally because AppContainer has no per-port rules.
- **`X-Sandbox-Token` session authentication**: mirrors nono's 256-bit session
  token. Direct connects to the proxy without the token get `407 Proxy
  Authentication Required`.
- **Profile + CLI flag merging**: `network.allow_domain` from profile
  concatenates with `--allow-domain` flags. Same merge semantics.

### What we differ on (Windows-specific)

| Aspect | nono (Linux) | sandbox (Windows) |
|---|---|---|
| Enforcement layer for direct connects | Landlock per-port TCP rules (ABI v4+, Linux 6.7+) — kernel denies `connect()` to non-proxy ports directly | AppContainer network capability — no per-port granularity. We grant a loopback exemption scoped to `127.0.0.1:<proxy-port>` only; all other `connect()` attempts hit `ERROR_ACCESS_DENIED` at the kernel. Coarser but equivalent effect. |
| Apps that ignore `HTTPS_PROXY` | On Linux with Landlock ABI v4+, they're denied at the kernel per-port rule. | On Windows, they're denied at the AppContainer network-cap layer (no network capability except the loopback exemption). Same outcome (fail closed), different mechanism. |
| `--open-port` / `--listen-port` IPC | nono supports localhost IPC ports even under `--block-net` | **Deferred** — future F-1. Not in MVP. |
| WSL2 limitations | nono disables domain filtering on WSL2 by default (kernel limitation); `--block-net` works, `--allow-domain` doesn't. | N/A — we're native Windows, no WSL2 limitations apply to us. This is a significant advantage over nono's Windows story. |
| Proxy TLS | nono's proxy does TLS to the upstream (real API host) | Same — our proxy (hyper + rustls) does TLS termination to the upstream. The sandboxed process talks plain HTTP to `127.0.0.1` (CONNECT-style for HTTPS) or the proxy upgrades. |
| IPv6 handling | nono blocks `fe80::/10` link-local | Same — we block `fe80::/10` and `169.254.0.0/16`. |

### What we add that nono doesn't have

- **Explicit "fail closed for raw sockets" documentation**: nono relies on
  Landlock per-port rules to catch raw-socket apps. We rely on AppContainer
  network-cap denial. We document this prominently (AC-3.13) because Windows
  has more raw-socket apps (git over SSH, gRPC, custom TCP) than the typical
  Linux agent workload, and users need to know they fail closed, not silently
  bypass.

### What nono has that we explicitly defer

| nono feature | Status | Where deferred |
|---|---|---|
| `--allow-endpoint openai:POST:/v1/chat/completions` (per-endpoint filtering) | Deferred | future F-1 |
| `--open-port` / `--listen-port` (localhost IPC under `--block-net`) | Deferred | future F-1 |
| `--upstream-proxy` / `--upstream-bypass` (corporate proxy chaining) | Deferred | future F-1 |
| WFP callout driver (kernel-level per-host rules) | Deferred | future F-6 |
| Credential injection via the proxy (`--credential openai`) | Deferred | future F-2 |
| `codex`, `claude-code`, `enterprise` built-in network profiles | Partial — we ship `minimal`, `developer`, `none`. `claude-code`/`codex`/`enterprise` deferred until we have credential injection (F-2) since they reference credential routes. | future F-2 |

### nono's `--block-net` vs. ours

nono's `--block-net` on native Linux removes all network access via Landlock.
On WSL2 it works but domain filtering is disabled. Our `--block-net` removes
the AppContainer network capability entirely — no proxy is started, no
loopback exemption is granted, all `connect()` returns
`ERROR_ACCESS_DENIED`. This is **stronger** than nono on WSL2 (where
`--block-net` works but is the only network option) and equivalent to nono
on native Linux.

## Implementation-ready detail

### Capability / network-cap layer

AppContainer processes are **deny-by-default for network** — a fresh
AppContainer SID with no capability SIDs in its `SECURITY_CAPABILITIES`
list cannot `connect()` to anything (kernel returns `WSAEACCES` /
`ERROR_ACCESS_DENIED`). We exploit this:

- **`--block-net` / `none` profile**: pass `Capabilities = null,
  CapabilityCount = 0` to `CreateProcessW` via
  `PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES`. No loopback exemption
  is registered. Every `connect()` (raw socket or proxied) is
  kernel-denied. No proxy is started. (AC-3.1, AC-3.2, AC-3.13.)
- **`--allow-domain` / `--network-profile` (non-`none`)**: still pass no
  internet capability SIDs (so direct connects to the internet fail
  closed), but register a **loopback exemption** for the AppContainer SID
  via `NetworkIsolationSetAppContainerConfig` /
  `Win32::Networking::WinSock::NetworkIsolation`, scoped to the
  AppContainer SID. The sandboxed process can then `connect()` to
  `127.0.0.1` (the proxy) but still nothing else.

> **AC-3.15 deferred to F-6.** Native AppContainer loopback exemption is
> all-or-nothing per SID — it cannot be scoped to a single port. Per-port
> loopback scoping requires a Windows Filtering Platform (WFP) callout
> driver (future-ideas **F-6**). For the MVP we grant full loopback and
> rely on the proxy's `X-Sandbox-Token` gate (AC-3.12) plus the fact that
> other loopback services won't honor our token to provide the
> practical isolation. The acceptance test for AC-3.15 is **deferred**
> and marked SKIP in the harness with `Detail='deferred to F-6 (WFP
> driver)'`.

> **Loopback exemption deferral (implementation finding 2026-07-26).**
> The `NetworkIsolationSetAppContainerConfig` API chosen above is
> **admin-only** — MSDN documents it as "used for debugging purposes"
> and it sets a system-wide loopback-allow list. Running unprivileged it
> returns `ERROR_ACCESS_DENIED (0x5)`, so `--allow-domain` /
> `--network-profile` are non-functional without admin. The current
> implementation:
> - **`--block-net` works fully unprivileged** (no loopback exemption
>   needed; AC-3.1, AC-3.2, AC-3.13 hold).
> - **`--allow-domain` / `--network-profile` are accepted but downgraded**
>   to block-net semantics with a clear warning, so the flags don't
>   silently fail. The proxy, token, env injection, and audit plumbing
>   are all implemented and unit-tested, but the loopback exemption gate
>   blocks them from being exercised end-to-end unprivileged.
> - The **unprivileged fix** is to add a `privateNetworkClientServer`
>   capability SID to the AppContainer token in `spawn.rs` (instead of
>   the admin-only `NetworkIsolationSetAppContainerConfig` call). This
>   capability allows loopback + intranet but NOT public internet, so
>   raw-socket direct connects to public hosts still fail closed
>   (AC-3.13 holds) and the proxy enforces the allow-list. This is
>   tracked as a follow-up; when it lands, the S-27..S-34, S-36, S-38
>   integration scenarios flip from SKIP to active.

### Proxy

- **Runtime**: tokio (mt, multi-thread scheduler, 1 worker thread —
  enough for a single agent's traffic).
- **HTTP stack**: hyper 1.x server on `tokio::net::TcpListener` bound to
  `127.0.0.1:0` (OS-assigned port, AC-3.11). The bound port is read back
  after bind and injected into the child env.
- **TLS to upstream**: rustls with `rustls-native-certs` to load the
  system root store. The proxy terminates TLS to the upstream host for
  `CONNECT` tunnels (it speaks plain HTTP to the sandboxed process, TLS
  to the real host). Plain HTTP requests (non-CONNECT, rare) are
  forwarded as-is.
- **Request handling**:
  1. Read request line + headers.
  2. Check `X-Sandbox-Token` header. If absent or ≠ session token →
     respond `407 Proxy Authentication Required` and close (AC-3.12).
  3. For `CONNECT host:port`: extract `host`. For plain `GET/POST
     http://host/...`: extract `host` from the URL. Strip any
     `:port` suffix for domain matching; keep `host:port` for the log.
  4. Resolve `host`:
     - If `host` is a literal IP → check against always-denied CIDRs.
     - If `host` is `metadata.google.internal` → deny (AC-3.7).
     - Else → DNS-resolve to IpAddr(s); each resolved IP is checked
       against always-denied CIDRs (catches DNS names that resolve into
       link-local, e.g. a poisoned `/etc/hosts`).
  5. Domain allow-list check: exact match (case-insensitive, trailing
     dot stripped) OR wildcard suffix match (see "Domain matching"
     below). If neither → deny with `reason=domain_not_allowed`
     (AC-3.4).
  6. If all checks pass → forward (CONNECT: open TCP to `host:port`,
     upgrade to TLS via rustls, splice bytes; HTTP: forward request),
     emit `ALLOW CONNECT host:port` (AC-3.3). Else → drop, emit
     `DENY CONNECT host:port reason=...` (AC-3.4, AC-3.6).
- **Lifecycle**: tokio task runs on a dedicated std thread spawned
  before `CreateProcessW`. A `tokio_util::sync::CancellationToken` (or
  a `oneshot::Sender`) is held by the supervisor; on `Drop` of the
  `ProxyHandle` the token is cancelled, the listener stops accepting,
  in-flight connections are given 200 ms to drain, then the port is
  released (AC-3.14). The handle is dropped when `sandbox.exe` returns
  or panics, and the Job Object's `KILL_ON_JOB_CLOSE` handles
  Ctrl-C / forced kill.

### Domain matching

```
fn matches(host: &str, entry: &str) -> bool {
    let h = host.trim_end_matches('.').to_ascii_lowercase();
    let e = entry.trim_end_matches('.').to_ascii_lowercase();
    if let Some(suffix) = e.strip_prefix("*.") {
        // *.anthropic.com matches api.anthropic.com and
        // console.anthropic.com but NOT anthropic.com.evil.io
        // (the latter's last two labels are evil.io, not anthropic.com)
        // and NOT anthropic.com (the bare apex).
        let dot = format!(".{suffix}");
        h.ends_with(&dot)
    } else {
        h == e
    }
}
```

The host is allowed if it matches **any** entry in the merged
allow-list. The always-denied list is checked first and overrides any
allow-list match (AC-3.6, AC-3.7).

### Always-denied destinations

```
const ALWAYS_DENIED_V4_CIDRS: &[&str] = &["169.254.0.0/16"];
const ALWAYS_DENIED_V4_HOSTS: &[&str] = &["169.254.169.254"];
const ALWAYS_DENIED_V6_CIDRS: &[&str] = &["fe80::/10"];
const ALWAYS_DENIED_DNS: &[&str] = &["metadata.google.internal"];
```

CIDR matching: parse IpAddr, mask by prefix length, compare to the
network address. Hand-rolled (no `ipnet` dep) — 30 lines.

### Session token

256-bit random, hex-encoded (64 chars). Generated with
`BCryptGenRandom` from the `windows` crate (`Win32_Security_Cryptography::BCryptGenRandom`)
— no extra `rand` dep. Injected as `X-Sandbox-Token` env var in the
child and required on every request to the proxy (AC-3.12).

### Env injection

`build_env_block` (in `src/sandbox/appcontainer.rs`) gains an optional
`ProxyConfig { port, token }` parameter. When present, the env block
gets:

- `HTTP_PROXY=http://127.0.0.1:<port>`
- `HTTPS_PROXY=http://127.0.0.1:<port>`  (scheme is `http` even for
  HTTPS — the proxy is plain HTTP; TLS is between proxy and upstream)
- `X-Sandbox-Token=<hex>`
- `NO_PROXY=`  (empty — make sure nothing bypasses the proxy; some
  tools default `NO_PROXY=localhost,127.0.0.1` which would defeat us)

When `--block-net`, none of these are set (and the proxy isn't started).

### Profiles

Profile JSON gains a `network` slice. Schema:

```json
{
  "network": {
    "blockNet": false,
    "allowDomain": ["api.anthropic.com", "*.anthropic.com"],
    "profile": "minimal"
  }
}
```

- `network.blockNet` (bool) — equivalent to `--block-net`.
- `network.allowDomain` (string array) — equivalent to repeatable
  `--allow-domain`. Concatenates with CLI flags (dedupe,
  case-insensitive).
- `network.profile` (string) — one of `none`, `minimal`, `developer`.
  Resolves to a built-in allow-list (see below) and merges with
  `allowDomain` and CLI flags.

CLI precedence: `--network-profile` flag overrides `network.profile`
in the JSON; `--block-net` flag forces `none` regardless of profile;
`--allow-domain` flags concatenate with `network.allowDomain`.

Built-in profiles (live in code, not on disk):

- `none` → `blockNet=true`, no proxy, no allow-list.
- `minimal` → `["api.openai.com", "api.anthropic.com",
  "generativelanguage.googleapis.com"]`.
- `developer` → `minimal` + `["registry.npmjs.org",
  "registry.npmjs.com", "pypi.org", "files.pythonhosted.org",
  "crates.io", "static.crates.io", "github.com",
  "objects.githubusercontent.com", "raw.githubusercontent.com",
  "codeload.github.com"]`.

### Audit event emission

US-3 emits `CONNECT` events; US-4 owns the hash chain and signing. The
seam is a single function in a new `src/audit.rs`:

```rust
pub fn emit_connect(session_id: &str, host: &str, port: u16,
                    disposition: Allow, reason: Option<&str>);
```

For US-3, this writes one NDJSON line to
`%LOCALAPPDATA%\sandbox\audit\<sid>.ndjson` (creating the dir if
missing) and also to stderr under `SANDBOX_DIAG`. The line shape matches
the US-4 `CONNECT` schema:

```json
{"ts":"2026-07-25T14:45:21Z","seq":12,"op":"CONNECT",
 "host":"api.anthropic.com","port":443,"disposition":"allow",
 "reason":null}
```

(US-4 will later wrap this writer to add `parent`/`hash` fields and
sign the root. US-3 deliberately does not compute the hash chain.)

### Test commands (integration tests S-25 .. S-38)

| AC | Scenario | Command in harness | Assert |
|---|---|---|---|
| 3.1 | S-25 | `sandbox run --allow-cwd --block-net -- cmd /c python -c "import urllib.request,sys; urllib.request.urlopen('https://api.openai.com')"` (skip if no python) | exit ≠ 0, stderr matches `(?i)(access is denied|connection|urLError|PermissionError)` |
| 3.2 | S-26 | `sandbox run --allow-cwd --block-net -- cmd /c python -c "import socket; socket.create_connection(('169.254.169.254',80))"` (skip if no python) | exit ≠ 0, no packet leaves |
| 3.3 | S-27 | `sandbox run --allow-cwd --allow-domain api.anthropic.com -- cmd /c curl -s -o NUL -w "%{http_code}" https://api.anthropic.com/v1/messages` (skip if no curl) | http_code in 4xx (anthropic returns 401 without auth — the *connection* succeeded) |
| 3.4 | S-28 | same as 3.3 but `--allow-domain api.anthropic.com` and `curl https://evil.example.com` | curl exits non-zero, proxy log shows `DENY CONNECT evil.example.com:443 reason=domain_not_allowed` (under `SANDBOX_DIAG`) |
| 3.5 | S-29 | `--allow-domain *.anthropic.com`, curl `api.anthropic.com` and `console.anthropic.com` then `anthropic.com.evil.io` | first two connect, third denied |
| 3.6 | S-30 | `--allow-domain 169.254.169.254 --allow-domain api.anthropic.com`, connect to `169.254.169.254` | denied with `reason=denied_cidr` in the diag log |
| 3.7 | S-31 | any profile, connect to `metadata.google.internal` | denied with `reason=denied_dns` |
| 3.8 | S-32 | `--network-profile minimal`, connect to `api.openai.com`, `api.anthropic.com`, `generativelanguage.googleapis.com`, then `github.com` | first three connect, github denied |
| 3.9 | S-33 | `--network-profile developer`, connect to all of the above plus `registry.npmjs.org`, `github.com` | all connect |
| 3.10 | S-34 | profile JSON with `network.allowDomain=["api.anthropic.com"]` + CLI `--allow-domain github.com`, connect to both | both connect |
| 3.11 | S-35 | two concurrent `sandbox run` invocations | proxy ports differ, neither fails with EADDRINUSE |
| 3.12 | S-36 | sandboxed process knows port but not token, sends request without `X-Sandbox-Token` | proxy responds `407` |
| 3.13 | S-37 | `--allow-domain api.openai.com`, sandboxed raw-socket python app ignores `HTTPS_PROXY` and `connect()`s directly | `connect()` raises `PermissionError`; log records `DENY CONNECT api.openai.com:443 reason=direct_connect_blocked` (this is the AppContainer network cap, not the proxy) |
| 3.14 | S-38 | start sandbox w/ proxy, kill `sandbox.exe`, check the proxy port is released within 1 s | port closed (next `Test-NetConnection` or `Get-NetTCPConnection` returns no listener) |
| 3.15 | (SKIP) | — | `Detail='deferred to F-6 (WFP driver)'` |

Tests that need python/curl skip cleanly when the binary is missing,
mirroring the existing S-8/S-9/S-19 pattern.

### File map

- `Cargo.toml` — add `tokio`, `hyper`, `hyper-util`, `rustls`,
  `rustls-native-certs`, `http`, `bytes`, `http-body-util`,
  `tokio-util` (CancellationToken), `h2` optional (skip for MVP — HTTP/1.1
  only). New windows features: `Win32_Networking_WinSock` for
  `NetworkIsolation` (loopback exemption) and
  `Win32_Security_Cryptography` for `BCryptGenRandom`.
- `src/cli.rs` — add `--network-profile <name>`, keep `--block-net`
  and `--allow-domain`. Update `RunArgs` + `from_cli`.
- `src/profile.rs` — add `NetworkSlice` to `ResolvedProfile`, parse
  `network` JSON (currently a `serde_json::Value` black box), merge
  with CLI flags, expose `NetworkSlice::allow_domain`, `block_net`,
  `profile_name`.
- `src/net/mod.rs` (new) — facade: `NetworkConfig`, `resolve_network()`,
  re-exports.
- `src/net/matcher.rs` (new) — `matches(host, entry)`, `is_allowed(host,
  &allow_list)`, `is_always_denied(host_or_ip)`. Pure functions, unit
  tests inline.
- `src/net/profile.rs` (new) — `builtin_profile(name) -> Vec<String>`
  for `minimal`/`developer`/`none`.
- `src/net/proxy.rs` (new) — tokio/hyper/rustls CONNECT proxy,
  `ProxyHandle`, `spawn(token, allow_list, audit_sink) -> ProxyHandle`.
- `src/net/token.rs` (new) — `gen_token()` via BCryptGenRandom,
  hex-encode.
- `src/net/loopback.rs` (new) — `register_loopback(ac_sid)` via
  `NetworkIsolationSetAppContainerConfig`. (Best-effort; failures
  logged under `SANDBOX_DIAG`.)
- `src/audit.rs` (new) — `emit_connect(...)`. Thin; US-4 owns the rest.
- `src/sandbox/appcontainer.rs` — `build_env_block` gains optional
  `ProxyConfig { port, token }`.
- `src/sandbox/spawn.rs` — pass `SECURITY_CAPABILITIES` with no internet
  caps (already does — verify). Loopback exemption registered before
  spawn when a proxy is configured.
- `src/main.rs` — wire `--block-net` / `--allow-domain` /
  `--network-profile` into `run_inner`; start the proxy (or not), build
  the env block, pass the proxy port+token to spawn.
- `src/setup.rs` — `setup --check-only` now reports the proxy / network
  cap status (replace the "not yet implemented" lines).
- `tests/run-tests.ps1` — add S-25 .. S-38, mark S-39 (AC-3.15) as
  SKIP.
