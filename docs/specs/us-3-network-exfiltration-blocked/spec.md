# US-3: Network exfiltration blocked

> **Status:** Draft — narrative + acceptance criteria stage.
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

## Implementation-ready detail (to be filled in last step)

TODO: exact AppContainer network capability flags, loopback exemption API,
proxy implementation, domain matching algorithm, audit event shape.

## Implementation-ready detail (to be filled in last step)

TODO: exact AppContainer network capability flags, loopback exemption API,
proxy implementation, domain matching algorithm, audit event shape.
