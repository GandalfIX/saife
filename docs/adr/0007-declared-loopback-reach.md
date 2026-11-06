# ADR-0007: declared loopback reach — the facade forwarder, and what it cannot do

- **Status:** **Proposed — spike-gated.** The mechanism is decided; the shipping decision is not.
  No PR opens before the opencode v2 spike (S1–S4 below) has run, because opencode v2 is the
  acceptance test this ADR exists for.
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

**D-3 — Mechanism 2, the per-port loopback allowance (in-session targets; substrate-dependent).**
The substrate already whitelistens one loopback port per session: the proxy. That is the
`identitylessLoopbackProxy` capability — a host listener the container may connect to by policy
rather than by exposure. The open question is whether the mxc config surface can whitelist
*additional* ports the same way. If it can, the shape is:

- `--allow-loopback-port 4096` — enumerated ports, **connect-only**, per-session, never learned,
  never persisted, printed at startup;
- the audit leaf records `loopback_ports=4096` and says plainly that traffic on allowed ports is
  **not content-audited** — the decision pipeline sees nothing; at best WFP 5-tuples exist;
- **the squatting hole is closed by an ownership check.** Because the container shares the host TCP
  table, a port allowance has a failure mode the forwarder does not: if a *host* service already
  holds the port, the in-session bind fails and the session's client happily connects to the host's
  service instead — an exfiltration channel wearing the grant's name. The supervisor therefore
  verifies, when the allowance is armed and again when the first connect succeeds, that the socket
  bound on the allowed port is owned by a process **in this session's job** (the owning PID is
  visible in the host's TCP table — that is what makes the check possible). A foreign owner refuses
  the allowance.
- **the port must be pinned by the workload.** The allowance is enumerated; a client+server tool
  that picks a random port at startup — opencode's TUI does, unless given `--port` — defeats the
  enumeration. Profiles for such tools pin the port, and arming the allowance refuses if the pinned
  port is already bound by a foreign owner (the same ownership check as above, run up front).
- ingress stays closed. `baseContainerSupportsIngressHostLoopbackAllow` is `false` at
  base-container (capability matrix), and this ADR does not want it: a listener inside the session
  that the host can reach is an inbound door, which is a different and worse grant than this one.

**D-4 — scope of the guarantee.** With D-3 armed, the containment claim for that session is
precisely worded: no boundary is crossed by an allowed loopback connection (both ends are inside
the same session; ingress remains blocked), but the session has gained a channel the audit cannot
describe beyond 5-tuples. Sessions with the allowance are recorded as such, and any documentation
that says "audited" must exempt them.

## The spike — the gate for any PR

**S1 — the substrate question (decides everything).** Read `mxc-sdk` 1.0.1's config surface
(`New-Config` generator, the same one the capability matrix was captured with): can a
processcontainer policy express loopback *connect* allowances beyond the injected proxy port?
Then measure: bind a listener inside a session, connect to it from the same session, with and
without a candidate config knob. Expected without a knob: `10013` (already measured). Any other
result is the finding.

**S2 — opencode's client and the proxy.** Does the TUI's HTTP client honor `HTTP_PROXY` for
`--server http://opencode.sandbox.invalid:4096`? The runner proved the facade pattern with curl and
the build daemon; opencode's client is Bun's fetch and is unproven. If it ignores the proxy env for
facade hosts, D-2's path is dead for opencode regardless of S1.

**S3 — end-to-end if S1 succeeds.** One `mxc` session: server inside with the port pinned
(`--port 4096` — the TUI's random port would defeat the enumerated allowance), TUI inside, client
pointed at `127.0.0.1:4096` under a per-port allowance. The baseline is already established:
standalone mode works outside the sandbox, so any remaining failure inside is the allowance, not
opencode. Acceptance: a prompt completes; the server
executes a tool whose file write lands inside the writable grant; egress from the session is still
`10013`; the audit leaf carries the allowance and the ownership check; a second session cannot
reach the first's port (cross-session check).

**S4 — if S1 fails.** Document that T3 is unsolvable under 1.0.1 and file the upstream question
(per-port loopback allowance; or `isolationSessionAvailable`). The honest product answer until then
remains the FAQ's: `appcontainer` elevated for opencode, `mxc` for outbound-only workloads. The
forwarder (D-2) may still ship for T1 — it is useful and independent — but it must not be
marketed as the opencode fix.

## Consequences

### Positive

- T1 workloads (test databases, declared host services) work inside sessions with a full audit
  trail, without opening loopback.
- If S1 succeeds: the agent tier's flagship case — opencode v2, server and client in one session —
  works under `mxc` with a grant that is one port wide, connect-only, session-scoped, and
  ownership-checked. The `appcontainer`-elevated workaround stops being the answer for the tier
  this product is for.
- The generalisation holds for the whole class the FAQ names: any client + local-server tool
  (Gradle daemon, LSP over TCP, dev servers, Testcontainers) gets the same declared path.

### Negative

- The audit claim is weakened **for sessions that use the allowance**, and the wording must say so.
  This is the price of D-3 and the reason D-1 still stands for everything else.
- One more surface to own: the ownership check, the port enumeration, the startup printing.
- Upstream dependency: if S1 fails, the agent tier stays on the `appcontainer` workaround or waits
  for upstream — this ADR cannot fix the substrate.

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
