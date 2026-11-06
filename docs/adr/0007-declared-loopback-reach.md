# ADR-0007: declared loopback reach — the facade forwarder, and what it cannot do

- **Status:** **Proposed — spike run 2026-11-06, and it changed the mechanism.** What works is not
  a per-port allowance but a session mode: drop `runtimeConfig.networkProxy`, let the supervisor
  inject the proxy environment, and loopback is open while the internet still leaves only through
  the audited proxy. S1–S3 are measured below. The open decision is a product one — whether to
  offer a session mode with unscoped loopback — and it is yours, not this document's.
- **Date:** 2026-11-06
- **Supersedes:** nothing. It extends ADR-0004's egress model and generalises ADR-0006's facade
  pattern; it changes no rule in ADR-0001..0006.
- **Evidence:** the FAQ's opencode v2 entry (commit `0a26d84`, measured 2026-11-04); ADR-0006's
  measured loopback legs (2026-10-30); the capability matrix
  (`docs/design/2026-10-14-wbd-d02-capability-matrix-design.md`); opencode v2's documented
  server/client architecture (opencode.ai/docs/server).

## Context

Loopback is closed under `mxc` in **both** directions, and both legs are measured:

| leg | result |
|---|---|
| container connects to its own `127.0.0.1` listener | `WSAEACCES` **10013** — a policy refusal, not a closed port |
| the same probe outside a session | `WSAECONNREFUSED` — a normal closed port |
| the host connects to a container's listener | connect **times out** (the socket is visible in the host's TCP table) |

The middle row is the diagnosis in one line: inside the session the socket is refused *by policy*,
outside it is merely *closed*. The third row is the one this ADR turns on: the container shares the
host's TCP table, but WFP filters connects by identity in both directions.

opencode v2 makes this concrete. It is a **thin client plus a local HTTP server**: the server owns
sessions, configuration, tools and permissions, and every client — including the TUI — speaks to it
over `127.0.0.1:<port>`. Under `mxc` every mode hangs (measured, FAQ `0a26d84`): `--standalone`
means "private server", not "no server"; `opencode service set disabled true` stops only the shared
service; `--server http://localhost:4096` is the same loopback.

**Why the server must be inside the session, not on the host:** the server is the component that
executes the agent's tools — file writes, shell commands, network calls. Run it on the host and the
sandbox contains nothing worth containing; the "sandbox" would guard a TUI. So for opencode the
goal is exactly what the user stated: **open the server _and_ the client inside the sandbox**, and
let them meet.

Today's only working answer is the `appcontainer` backend from an elevated shell, where the
loopback exemption registers automatically. That is a containment downgrade this ADR treats as
unacceptable for the agent tier: the exemption is machine-wide, all-or-nothing per SID, and
**accumulates on the machine** (`src/net/loopback.rs`, FAQ 2026-11-03). And even that path is
weaker than it reads, measured in the same effort (session analysis, 2026-11-04): unelevated, the
backend itself warns `loopback exemption failed ... Re-run 'saife run' as administrator`; elevated,
it works, but opencode's own state directories blow the per-grant **20,000-object DACL cap** — the
same launch log truncates `.local/share/opencode`, `npm-cache` and `.gradle` — so files deeper in
those trees are unreadable inside the session. For the agent tier the "supported path" is thus
elevated **and** partially blind.

Two further measured facts narrow the problem to exactly loopback: `--standalone` was verified fully
functional *outside* the sandbox (it reached the provider; only a stale API key failed), and inside
the sandbox the standalone server *starts* — it is the client's connect that dies on `10013` while
the CLI retries, which is the observed hang. So opencode v2 needs nothing from this ADR except a
loopback path between two of its own processes.

## The three topologies — what "server and client" can mean

| | server | client | solvable by a forwarder? |
|---|---|---|---|
| T1 | on the host | in the session | **yes** — the forwarder's definition |
| T2 | in the session | on the host | **no** — host→container connects time out (measured) |
| T3 | in the session | in the session | **not by a forwarder** — see D-3 |

T3 is the opencode case, and it kills the naive version of this ADR: a supervisor-owned forwarder
accepts the client's connection on a facade host, then dials the real target — but the real target
is a listener *inside the session*, and the measured third leg says the supervisor cannot reach it.
A forwarder can only bridge to targets on the host side.

## Decision

**D-1 — the rule does not change.** There is no undeclared channel. Loopback reach is granted only
as *declared, session-scoped, connect-only, per-service* reach. A blanket `--allow-loopback` is
rejected (see Rejected alternatives): it would reopen exactly the per-listener boundary collapse
that closing loopback exists to prevent.

**D-2 — Mechanism 1, the facade forwarder (works today, host-side targets).** A facade host
(`<name>.sandbox.invalid`) is routed to a supervisor-owned listener; the listener token-gates like
every facade request, then splices raw TCP to a declared target. No protocol knowledge, no
buffering — so streaming protocols (SSE, which opencode's event endpoint uses) pass through.
Auditability is complete: every connection crosses the decision pipeline.

This solves T1: a test database on the host, a service the supervisor starts, a declared API shim.
**It does not solve opencode v2.** Stating that here, in the ADR that proposes the mechanism, is
the point: the forwarder is worth having, and it is not the thing that fixes the agent tier.

**D-3 — Mechanism 2: the rules-mode session (in-session targets). Measured; the per-port idea is
dead.** The spike (2026-11-06) established four facts, three of them negative:

1. **A per-port allowance cannot coexist with the proxy.** Adding any `egress.allow` rule to a
   proxied session is refused by the contract:
   `runtimeConfig.networkProxy requires network.egress.default='deny' with no direct allow or deny rules`.
2. **Without `networkProxy` the rules are legal — and loopback is open anyway.** A session carrying
   a single unrelated allow rule (`10.9.9.9/32:8080`) still connected to `127.0.0.1:4095` and `:4096`;
   a session with **no** rules did the same.
3. **Loopback ignores the rules entirely.** An explicit `deny` for `127.0.0.1/32` did not stop a
   loopback connect either. There is no port scoping and no deny to build one from.
4. **What stays closed is what matters.** Direct egress (`1.1.1.1:443`) is still `10013`, and the
   host still cannot reach a listener inside the session (connect times out, measured with the
   listener held open).

So the closure measured in proxy mode is a property of **that mode**, not of egress policy: the
substrate's `identitylessLoopbackProxy` posture both grants the proxy port and shuts the rest of
loopback; the rules mode has no such posture and leaves loopback alone.

The mechanism that works is therefore a session mode, not a flag with a port list:

- **no `runtimeConfig.networkProxy`**; `egress.default = deny` with no allow rules;
- the supervisor injects `HTTP_PROXY`/`HTTPS_PROXY` (and `NO_PROXY` empty) into the child, pointing
  at its own listener — measured working: a real `CONNECT example.com:443` through that listener
  returned `HTTP/1.1 200 Connection Established` from inside the session, so **all internet traffic
  still passes the audited decision pipeline**;
- loopback is open in both directions *within* the session and reachable to the host's loopback
  services, which is the whole point — and the whole cost.

The cost, stated plainly: the session can reach **any** service on the host's loopback — Ollama,
a dev server, a database, Jupyter — and no rule can close individual ones. That is the
prompt-injection lateral-movement surface this ADR's D-1 exists to prevent, and there is no
mitigation inside the substrate. It stays acceptable only because the mode is explicit, per
session, never a default, and the audit leaf records `loopback=open, scoped=false`.

**D-4 — scope of the guarantee.** In a rules-mode session the containment claim is precisely
worded: internet egress is proxied and audited exactly as before, direct egress is still denied and
inbound is still refused — but **loopback is unscoped and unaudited**, and the session can reach
every loopback service on the host. Sessions in this mode are recorded as such, and any
documentation that says "loopback is closed" or "audited" must exempt them.

## The spike — results (2026-11-06)

Run on this host, throwaway code only (an env-gated egress rule in the request builder, reverted
afterwards; no branch, no PR). Each leg is a real `mxc` session with a PowerShell probe inside it.

| leg | configuration | measured |
|---|---|---|
| baseline, proxy session | as shipped | self-loopback `10013`; `1.1.1.1:443` `10013`; proxy port connects |
| S1a | proxy **+** `egress.allow 127.0.0.1/32:4096` | **refused**: `runtimeConfig.networkProxy requires egress.default='deny' with no direct allow or deny rules` |
| S1b | no `networkProxy`, allow rule `127.0.0.1/32:4096` | self-loopback **OK** — and port 4095 also **OK** |
| S1c | no `networkProxy`, allow rule for `10.9.9.9/32:8080` only | loopback `4095` and `4096` **OK** — the rule is irrelevant |
| S1d | no `networkProxy`, **no** allow rules | loopback **OK** |
| S1e | no `networkProxy`, `deny 127.0.0.1/32` + allow 4096 | loopback **OK** — the deny is ignored |
| S1f | rules-mode session, supervisor-injected `HTTP_PROXY` | `CONNECT example.com:443` → `HTTP/1.1 200 Connection Established`; `1.1.1.1:443` still `10013` |
| S2 | host → listener inside a rules-mode session | connect **times out** (inbound stays closed) |
| S3 | `opencode serve --port 4096` inside a rules-mode session, client from the same session | server process alive; `GET http://127.0.0.1:4096/global/health` → the app answered |

S3 is the acceptance test this ADR exists for, and it passes: **opencode v2's server and client run
in one `mxc` session**, over the loopback connect that is refused in proxy mode.

Still unmeasured, and stated so rather than implied: the full TUI with a real provider (needs an API
key and a check that opencode's Bun client honours `HTTP_PROXY` for its model calls — the health
probe used `--noproxy`), and two concurrent sessions (whether one session's open loopback can reach
another's listener; the host path times out, but that is not the same test).

## Consequences

### Positive

- T1 workloads (test databases, declared host services) work inside sessions with a full audit
  trail, without opening loopback — that is D-2 and it is independently useful.
- **Measured**: opencode v2's server and client run in one `mxc` session under the rules-mode
  mode, with internet egress still proxied and audited, direct egress still denied and inbound
  still refused. The `appcontainer`-elevated workaround stops being the only answer for the agent
  tier.
- The generalisation holds for the whole class the FAQ names: any client + local-server tool
  (Gradle daemon, LSP over TCP, dev servers, Testcontainers) gets the same declared path.

### Negative

- **Loopback is all-or-nothing, and unaudited.** The per-port scoping this ADR wanted does not
  exist: the rules mode leaves the whole of loopback open and ignores both allow and deny rules for
  it. A prompt-injected session can reach every loopback service on the host.
- The proxy environment is injected by the supervisor instead of the substrate, so the
  `identitylessLoopbackProxy` posture is not in play in that mode — a second code path to own and
  to keep honest about.
- The audit wording must diverge: "no undeclared channels" holds for the internet, not for loopback,
  in this mode.

### Neutral

- The facade forwarder and the per-port allowance share one explanation ("declared loopback
  reach"), which is also how they should be documented: one rule, two mechanisms, chosen by where
  the other end lives.

## Rejected alternatives

- **Blanket `--allow-loopback`** — reopens the per-listener boundary collapse; equivalent to the
  `appcontainer` posture while claiming `mxc`'s.
- **Bind/ingress allowances** — an in-session listener the host can reach is an inbound door;
  `ingressHostLoopbackAllow` is unsupported at base-container and this ADR does not ask for it.
- **Run the server on the host, forward in-session clients to it** — the T1 shape, and for
  opencode specifically it empties the sandbox of its purpose: the server is the component that
  executes tools.
- **A reverse tunnel the in-session server dials** — elegant on paper (both legs travel the
  allowed container→facade direction and get spliced host-side), but stock servers do not
  participate; it requires every workload to embed a tunnel client.
- **Learned/persisted loopback grants** — a standing hole; loopback reach is per-session or
  nothing.

## What this ADR does not decide

- Whether the mxc config surface can express D-3 at all — that is S1, and until it is answered the
  mechanism is a design, not a feature.
- Whether opencode's Bun-based client honors proxy env for facade hosts — S2.
- The flag's final name and CLI shape (`--allow-loopback-port` is a placeholder).
- Whether Mechanism 2 should also cover named pipes/UDS transports if opencode ever offers one —
  filesystem IPC is not WFP-filtered and needs no grant at all; if upstream adds a socket
  transport, the whole question dissolves for that transport.

## References

- FAQ, "Why does opencode v2 hang in the sandbox — even with `--standalone`?" (commit `0a26d84`)
- ADR-0006, the build runner — the facade pattern this ADR generalises
- ADR-0004, MXC `processcontainer` — the egress model and the proxy proof gates
- `docs/design/2026-10-14-wbd-d02-capability-matrix-design.md` — the capability flags quoted above
- opencode server docs — client/server architecture, `--server`, `OPENCODE_SERVER_PASSWORD`
