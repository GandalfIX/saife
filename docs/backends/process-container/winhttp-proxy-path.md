# WinHTTP / WinINet / .NET proxy path inside a ProcessContainer (P1.5, managed legs re-measured in P1.8)

Status: **measured 2026-10-21**, unelevated, Windows 11 26300.9711, `mxc-sdk 1.0.1`.
Decision input for P2/P3: **env-only proxying is sufficient only for stacks that read
`HTTP_PROXY`; the Windows system stacks (WinHTTP, WinINet, therefore browsers and
services) reach the proxy but arrive unauthenticated and get 407. They have no usable
egress.** .NET workloads did **not** start at all in this measurement; that turned out to
be a request-configuration defect (`clr-startup-failure.md`), not a property of the
container, so the managed legs are re-measured in
[Re-measurement: managed clients (P1.8)](#re-measurement-managed-clients-p18) below, which
**supersedes** the two `.NET`/`.NET Framework` rows in the table above.

## The question

`mxc-sdk` delivers the proxy **only** as `HTTP_PROXY` / `HTTPS_PROXY`, with the run
token as URL userinfo, plus `NO_PROXY` which our `mxc-launch` wrapper injects because
the SDK scrubs it. Which client stacks inside the container honour that, and which
bypass it?

## Method

A scratch harness (`%LOCALAPPDATA%/hermes/cache/scratch/p15`) launched real
ProcessContainers through `mxc_sdk::v1::run`, with the production request shape:
`mxc-launch` as the container command, `egress.default = deny`,
`ingress.hostLoopback = allow`, `networkProxy = http://sandbox:<token>@127.0.0.1:<port>`,
`inherit_default_environment = true`, workspace readwrite, `C:\Windows` + runtimes
readonly. The listening proxy is a token-gated stand-in that records every
consultation verbatim, refuses loopback targets (as the real proxy does), forwards
absolute-form HTTP, and counts tunnels.

Two targets make the answer unambiguous:

* **E** — the host's LAN address, *not* in `NO_PROXY`, not reachable directly inside
  the container. Only a proxy consultation can reach it.
* **L** — `127.0.0.1`. Used with curl to measure `NO_PROXY`, and (non-proxy port) to
  measure what loopback access the container actually grants.

Probes are **native** (raw `Win32` FFI in Rust), because managed probes cannot run
(see "The CLR does not start"). 22 legs, one container per leg, one log line each.

## Measured results

Child environment, verbatim (`cmd /c set`):

```
HTTP_PROXY=http://sandbox:p15measure-token-...@127.0.0.1:62484
HTTPS_PROXY=http://sandbox:p15measure-token-...@127.0.0.1:62484
NO_PROXY=localhost,127.0.0.1,::1
```

and the config the system stacks see *in the same child*:

```
ie_auto_detect=0   ie_proxy=            (WinHttpGetIEProxyConfigForCurrentUser)
winhttp_machine_access_type=1           (WINHTTP_ACCESS_TYPE_NO_PROXY: direct)
wininet_proxy_access_type=1             (INTERNET_OPEN_TYPE_DIRECT)
```

| Client stack | Target | Proxy consulted | Origin | Result |
|---|---|---|---|---|
| `curl --proxy http://sandbox:<token>@P` (control) | E | yes, absolute-form | **yes** | 200, 1 tunnel |
| `curl` with `http_proxy` env, `NO_PROXY` empty | L (proxy port) | yes, absolute-form | n/a | proxy path taken |
| `curl` with `http_proxy` env, `NO_PROXY=127.0.0.1` | L (proxy port) | no — **direct dial**, origin-form | n/a | `NO_PROXY` honoured |
| `WinHttpOpen(AUTOMATIC_PROXY)` | E | yes, absolute-form | no | **407** |
| `WinHttpOpen(DEFAULT_PROXY)` | E | yes, absolute-form | no | **407** |
| `WinHttpOpen(NAMED_PROXY 127.0.0.1:1)` — deliberately wrong | E | yes, to the container's proxy | no | **407** (client's own choice ignored) |
| `WinHttpOpen(NAMED_PROXY P)` + `WinHttpSetCredentials(PROXY, BASIC)` | E | yes | **yes** | 200, 1 tunnel |
| `InternetOpen(PRECONFIG)` (WinINet) | E | yes, absolute-form | no | **407** |
| `InternetOpen(PRECONFIG)` | L (loopback, non-proxy port) | no | no | **12029** `ERROR_INTERNET_CANNOT_CONNECT` |
| `InternetOpen(NAMED_PROXY P)` | E | yes | no | **407** |
| `InternetOpen(NAMED_PROXY P)` + `InternetSetOption(43/44)` credentials | E | yes | no | **407** (both options rejected) |
| Write `HKCU\...\Internet Settings` (`ProxyEnable`/`ProxyServer`) | — | — | — | `RegOpenKeyExW(KEY_READ_WRITE)` = **5 `ERROR_ACCESS_DENIED`** |
| raw `connect()` to E | E | n/a | n/a | **WSAEACCES 10013** at connect |
| raw `connect()` to `127.0.0.1:<non-proxy port>` | L | n/a | n/a | **WSAEACCES 10013** at connect |
| raw `connect()` + origin-form to `127.0.0.1:<proxy port>` | P | yes, origin-form | n/a | 407 |
| .NET 8 (CoreCLR) "hello" | — | — | — | **does not start**: `Failed to load ... coreclr.dll, HRESULT 0x8007045A`, exit `0xC0000409` — *superseded by P1.8* |
| .NET Framework 4.8 (`powershell.exe` 5.1) | — | — | — | **does not start**: exit `0xC0000142` `STATUS_DLL_INIT_FAILED` — *superseded by P1.8* |
| native `VirtualAlloc` RW → `VirtualProtect` RX → call it | — | — | — | works (rules out ACG/code-integrity) |

## The mechanism

1. **Nothing in the container is configured as a proxy.** The IE per-user config is
   empty, the machine WinHTTP config is "direct", WinINet's proxy view is "direct".
   The env vars are the only proxy information in the child.
2. **HTTP egress is nevertheless forced to `networkProxy` by the container.** Proof is
   the bogus-proxy leg: WinHTTP was told `127.0.0.1:1`, and its request still arrived
   at the container's proxy, in absolute-form. The two `-noenv` legs (proxy variables
   deleted inside the child) behave identically. So the proxy path is enforced below
   the client, not by the environment — it is not possible to "ignore the env and go
   direct" with an HTTP stack.
3. **Raw sockets cannot escape.** A plain `connect()` to the LAN target is refused at
   connect with `WSAEACCES 10013`, so there is no silent direct attempt. Loopback is
   not generally reachable either: `connect()` to the loopback **endpoint** port
   (any port other than the proxy's) is also `10013`, while the proxy's own port
   accepts. So the D-4 intent endpoint is reachable because it shares the proxy's
   listener, not because `hostLoopback = allow` grants loopback.
4. **The credential never arrives.** Only the env URL carries the token. WinHTTP and
   WinINet do not read `HTTP_PROXY` at all, so their consultations are unauthenticated
   and the proxy answers 407 — a *hard* failure the app sees, not a downgrade to
   direct. WinHTTP can use the proxy fully when it is *given* the credentials
   (`WinHttpSetCredentials`, PROXY/BASIC → 200): the only missing piece is delivery.
   WinINet has no equivalent pre-emptive API — `INTERNET_OPTION_PROXY_USERNAME`/
   `PASSWORD` on the session handle were rejected, and its normal answer to a 407 is
   an interactive credential prompt, which no GUI session here can answer.
5. **`NO_PROXY` reaches only env-reading clients.** curl honours it (measured both
   ways). WinHTTP/WinINet ignore the env entirely, so `NO_PROXY` is meaningless to
   them: a loopback target is not diverted around the proxy for them, it is sent to
   the proxy like any other target (not measured against a loopback target; the
   real proxy refuses loopback targets by policy).

## The CLR does not start in this container

Both CLR flavours fail identically and immediately: CoreCLR `0x8007045A`
`ERROR_DLL_INIT_FAILED` from `coreclr.dll`'s `DllMain` (host fail-fast `0xC0000409`),
.NET Framework `0xC0000142` for `powershell.exe`. A native probe proves generated code
is allowed (`VirtualAlloc` RW → `VirtualProtect` RX → execute), and broadening the
grants to `C:\ProgramData`, `%LOCALAPPDATA%`, `C:\Windows\Temp` (RW) changed nothing,
so this is **not** a filesystem-grant or code-integrity gap. The same
`powershell.exe -Command "Write-Output FXOK"` runs fine under the **AppContainer
backend** of this repo, so it is specific to the ProcessContainer configuration the
migration maps. Consequence: no managed (.NET) GUI or console workload can run at all, and
the .NET/SocketsHttpHandler legs of this measurement are therefore **not runnable** (they
would also be the only stacks whose env handling is documented to work).

> **Resolved in P1.7** (`clr-startup-failure.md`): this is not the CLR and not the
> containment primitive. The container runs every child with the kernel mitigation
> "disallow Win32k system calls", which `mxc-sdk` derives from `ui.disable` and which
> defaults to `true` when `ContainerRequest::ui` is unset. Setting
> `request.ui = Some(UiPolicy{ disable: false, .. })` makes `powershell` print `FXOK` and
> `dotnet` run, so the .NET legs above are runnable after that one field is set.

## Consequence for GUI workloads

* A browser or a system service gets **no usable egress**: Chromium/Edge on Windows
  take their proxy configuration from the WinINet/system layer, not from the env; the
  system layer here reports "direct" and has no credentials, the container forces the
  request to the supervisor's proxy, and the proxy answers **407**. There is no path
  to the origin.
* A .NET (WinForms/WPF/console) app **does not start**, which is a stronger exclusion
  than the proxy question.
* Only an app that (a) reads `HTTP_PROXY` itself *and* (b) can act on URL userinfo can
  work: curl measured yes; Go/Rust/Node/Python clients are expected to behave the same
  but were **not** measured here.
* `NO_PROXY` cannot rescue any of this: it only affects (a)-type clients.

## Recommendation (P2/P3)

1. **Do not plan on per-user WinINET/WinHTTP proxy configuration.** It cannot be
   installed from inside the container: `HKCU\...\Internet Settings` cannot even be
   opened for write (`ERROR_ACCESS_DENIED`), `netsh winhttp set proxy` and the WinHTTP
   machine store need elevation and are machine-wide, and `WinHttpSetDefaultProxyConfiguration`
   is per-process and only callable by the child itself. Even if configured, the
   credential still could not be delivered (WinINet has no pre-emptive proxy
   credential API; browsers would prompt).
2. **Scope GUI/system-proxy workloads out of MXC proxy-only mode for GA**, and keep
   the AppContainer backend for them (measured to start and run the CLR). Record it as
   a supported-mode limit in the ADR rather than as a defect.
3. **If GUI workload support becomes a requirement**, the design change is in the
   proxy's *admission*, not in client configuration: let the listener accept
   unauthenticated consultations that provably come from the container's own identity
   (peer SID / WFP attribution) instead of a bearer token. That is a P1.4-level change
   — it trades the per-run token for an OS-attested local-peer check — and should be
   its own spike, not a P2 patch.
4. **Keep env-only for CLI/agent workloads.** It is honest and works for every stack
   that reads it; the failure mode for the others is a clean 407, never a leak.

## Reproduce

```text
cargo build --features mxc-backend --bin mxc-launch        # the wrapper the harness launches
# scratch harness (not in the repo):
#   p15/probe      -> p15probe.exe : containers, proxy, targets, legs
#   p15/http       -> p15http.exe  : native WinHTTP / WinINet / registry probe
#   p15/native     -> p15native.exe: executable-memory control
#   p15/hello      -> .NET 8 app   : CLR start control
P15_ONLY=<leg> p15probe.exe     # one leg;   no filter = all 22 legs
```

Nothing here mutates host state: the registry leg restores the values it wrote (it
could not write them at all inside the container) and every listener is bound to
`127.0.0.1:0` or the host's own LAN address for the duration of a leg.

## Not run, and why

* ~~**.NET `HttpClient` / `SocketsHttpHandler` (default and `UseProxy=$false`)** — the CLR
  cannot start in this container~~ — **run in P1.8**, after `build_request` began setting
  `ui.disable = false`. The CLR was never the obstacle; see the re-measurement section.
* **A `NETWORK SERVICE`/system-context child** — creating a process with another
  account's token needs `SeAssignPrimaryToken`/`SeImpersonate` (elevation) or stored
  credentials; unavailable unelevated, and the SDK launches with the caller's token
  only.
* **A real browser or system service** — not launched; the browser consequence is
  inferred from the measured WinINet/WinHTTP path (proxy forced, no credentials -> 407),
  not from a browser run.

## Re-measurement: managed clients (P1.8)

Status: **measured 2026-10-21**, unelevated, Windows 11 26300.9711, `mxc-sdk 1.0.1`,
.NET 8.0.32 (CLR 8.0.32), .NET Framework 4.8 (`5.1.26100.9711`, CLR `4.0.30319.42000`),
`pwsh` 7.6.7 (CoreCLR 10.0.13).

The P1.5 rows above recorded both CLR flavours as "does not start". That was
`request.ui` unset → `UiPolicy::default().disable = true` → the kernel bans Win32k
syscalls (`clr-startup-failure.md`), not anything to do with the proxy. With that one
field stated in `build_request` (1938afe) every managed leg below runs, so this section
**replaces** the "not runnable" note rather than trusting it.

### What was measured, and what is authoritative

Two instruments, because they answer different halves of the question:

1. **Scratch harness** `%LOCALAPPDATA%\hermes\cache\scratch\p18` — one real
   ProcessContainer per leg through `mxc_sdk::v1::run`, request shape identical to
   `build_request` *including* `ui.disable = false`, `egress.default = deny`,
   `ingress.hostLoopback = allow`, `networkProxy = http://sandbox:<token>@127.0.0.1:<port>`,
   `inherit_default_environment = true`. A token-gated stand-in listener records every
   consultation **in order, with and without `Proxy-Authorization`**, so a pre-emptive
   credential and a 407-then-retry are distinguishable; it forwards absolute-form HTTP and
   tunnels `CONNECT` to a real TLS origin (self-signed, `--insecure` recorded in the
   output). Unlike the P1.5 stand-in it does not replicate the real listener's
   loopback-target refusal — no leg here sends a loopback target *through* the proxy.
2. **A live leg against the shipped listener** — `#[ignore]`d
   `net::mxc::live::p18_managed_clients_consult_or_miss_the_real_proxy` in
   `src/net/mxc.rs` runs the **real** `net::proxy::spawn` listener with its own
   `LaunchProofCounters` and asserts on `outcome.proxy_proof`, i.e. on the listener's
   count, never on the client's claim.

Every leg's verdict below is the counter delta: `consulted` means the listener saw the
request (absolute-form or `CONNECT`), `407` means it refused an unauthenticated attempt,
`origin` means my own origin logged the request. A client saying "200 OK" is not
evidence on its own.

Targets: **E** = the host's LAN address (not in `NO_PROXY`, denied egress, only
reachable through the proxy); **ETS** = the same host over TLS; **L** = a loopback
origin; **P** = the proxy's own loopback port.

### Results

Scratch harness, 15 legs, one container each. `Δ` is the proxy's counter delta for the
leg. Errors are quoted verbatim; this host is a German locale, so the authoritative part
is the code (`NativeError=10013` = `WSAEACCES`), not the sentence.

| # | Client and configuration | Proxy source | Consulted | Form | Origin | Result | Δ counters |
|---|---|---|---|---|---|---|---|
| 1 | `new HttpClient()` — default handler (`SocketsHttpHandler`, `UseProxy=true`, `Proxy=null`) → E | **`HTTP_PROXY` env** (`HttpEnvironmentProxy`) | **yes, twice** | absolute-form | **yes** | **200** `P18ORIGINOK` | 2 consultations: `auth=false` → 407, then `auth=true` → forwarded |
| 2 | `SocketsHttpHandler{UseProxy=false}` → E | none (control) | **no** | — | no | `HttpRequestException` … `SocketException … [SocketError=AccessDenied, NativeError=10013]` | 0 |
| 3 | `Invoke-WebRequest`, Windows PowerShell 5.1 (.NET Framework 4.8) → E | **system proxy** (`WebProxyWrapper`; `GetProxy` returns the URL itself, `IsBypassed=True`) | **no** | — | no | `WebException: Die Verbindung mit dem Remoteserver kann nicht hergestellt werden.` inner `SocketException … 10013` | 0 |
| 4 | `Invoke-WebRequest`, `pwsh` 7 (CoreCLR) → E | `HTTP_PROXY` env | **yes, twice** | absolute-form | **yes** | **200**, body `P18ORIGINOK` | `auth=false` → 407, `auth=true` → 200 |
| 5 | `WebProxy(new Uri("http://sandbox:<token>@127.0.0.1:P"))` → E | explicit, **credential in the URI userinfo** | yes **once** | absolute-form | no | **407 surfaced to the caller**, `proxy_credentials_set=false` | 1 unauthenticated, 0 authenticated |
| 6 | `WebProxy(addr){ Credentials = NetworkCredential("sandbox", token) }` → E | explicit, credential via API | **yes, twice** | absolute-form | **yes** | **200** | `auth=false` → 407, `auth=true` → 200 |
| 7 | `new HttpClient()` → E with `NO_PROXY=<LAN ip>` in the child | `HTTP_PROXY` env, `NO_PROXY` honoured (`IsBypassed=True`) | **no** | — | no | `… 10013` — refused direct dial, not a silent success | 0 |
| 8 | `new HttpClient()` → L (loopback origin, wrapper's own `NO_PROXY=localhost,127.0.0.1,::1`) | env, bypassed | **no** | — | no | `… 10013` | 0 |
| 9 | `new HttpClient()` → P (`http://127.0.0.1:<proxy port>/sandbox/intent`) | env, bypassed | **yes, origin-form** | `GET /sandbox/intent` | n/a | **407** (no credential, no absolute-form) | 1 unauthenticated |
| 10 | `new HttpClient()` → ETS over TLS | `HTTP_PROXY` env | **yes, twice** | **`CONNECT`** | **yes** (`TLSORIGIN GET /p18`) | **200** `P18TLSOK`, tunnel established | `auth=false` → 407, `auth=true` → 200, `tunnels=1` |
| C1 | `curl --proxy http://sandbox:<token>@P` → E | explicit, pre-emptive | yes once, `auth=true` | absolute-form | yes | 200 | 1 authenticated |
| C2 | `curl --proxy …` → ETS | explicit, pre-emptive | yes once, `auth=true` | `CONNECT` | yes | 200 | 1 authenticated, 1 tunnel |
| C3 | child environment (`cmd /c set`) | — | — | — | — | `HTTP_PROXY`/`HTTPS_PROXY` with the token, `NO_PROXY=localhost,127.0.0.1,::1` | 0 |

Two further legs corroborate rather than add a row: `net-env` (reports
`HttpClient.DefaultProxy` resolution without sending anything) and `net-sockets-E`
(`SocketsHttpHandler` used explicitly instead of via `HttpClientHandler`) both agree
with row 1, and `net-sockets-E` reaches the origin with the same 407-then-auth pair.
That is 15 legs in total.

The same legs re-run against the **real** supervisor listener (7 legs, all green):

| Leg | Client | `ProxyProof` | Client-visible result |
|---|---|---|---|
| 1 | `HttpClient` default → E | `accepted: 1, tunnels: 1`, expectation `Required` | 200, body from my origin |
| 2 | `UseProxy=false` → E | `accepted: 0, tunnels: 0`, `MustBeAbsent` | 10013 |
| 6 | `WebProxy` + `Credentials` → E | `accepted: 1, tunnels: 1`, `Required` | 200 |
| 5 | `WebProxy(uri)` with userinfo → E | `accepted: 0, tunnels: 0`, `MustBeAbsent` | 407 |
| 7 | `NO_PROXY=<LAN ip>` → E | `accepted: 0, tunnels: 0`, `MustBeAbsent` | 10013 |
| 3 | `powershell.exe` 5.1 → E | `accepted: 0, tunnels: 0`, `MustBeAbsent` | `WebException` / 10013 |
| 4 | `pwsh` 7 → E | `accepted: 1, tunnels: 1`, `Required` | 200 |

`accepted` is **1**, not 2, for legs 1/6/4: the listener's unauthenticated attempt is a
refusal it deliberately does not count (`proxy.rs`, `AuthVerdict::Absent` → `AUTH_REQUIRED`
→ `return`), so the 407 round-trip does not inflate guardrail 1's counter.

### The mechanism, client by client

**1. .NET 8+ / CoreCLR reads the env, and authenticates only after a 407.**
`HttpClient.DefaultProxy` is `System.Net.Http.HttpEnvironmentProxy` built from
`HTTP_PROXY`/`HTTPS_PROXY`; it parses the URL userinfo into a `NetworkCredential`, and
`IsBypassed` reflects `NO_PROXY`. Consent is *not* pre-emptive: the first request on a
connection carries no `Proxy-Authorization`, the listener answers
`407 Proxy Authentication Required` + `Proxy-Authenticate: Basic realm="sandbox"`, and
the handler re-sends with the credential and gets 200. Both plain HTTP (absolute-form)
and HTTPS (`CONNECT`) work this way — the TLS leg completed a real handshake through
the tunnel and read `P18TLSOK`.

That the real listener's `AUTH_REQUIRED` carries a `Proxy-Authenticate: Basic` challenge
is what makes the whole thing work; a 407 without a challenge would leave .NET with
nothing to answer. Verified on the shipped listener (leg 1 above: `accepted: 1` can only
happen after a successful `classify_auth`).

**2. `UseProxy = false` is a clean refusal.** No consultation, `WSAEACCES 10013` at
connect. Nothing downgrades to a direct connection, and nothing leaks.

**3. Windows PowerShell 5.1 does not read the env at all.** Its
`[System.Net.WebRequest]::DefaultWebProxy` is `WebProxyWrapper` (the WinINet/IE view),
which in this container reports **direct** (`GetProxy` → the URL itself,
`IsBypassed=True`). So `Invoke-WebRequest` dials the origin itself and gets
`10013` — it does not even reach the proxy to be refused with a 407. This is *worse*
than the P1.5 WinINet row: `InternetOpen(PRECONFIG)` at least reached the proxy. The
reason is that .NET Framework's `HttpWebRequest` takes only its *configuration* from
WinINet and then does its own WinSock connect — so a "direct" system config becomes a
denied raw dial, with no proxy in the path at all.

**4. `pwsh` 7 is the same code path as .NET 8** (`HttpEnvironmentProxy`, 407 then auth)
and works for `Invoke-WebRequest` unchanged.

**5. The explicit-`WebProxy` forms differ, and the difference matters.**
`new WebProxy(new Uri("http://user:pass@host:port"))` **does not** lift the userinfo into
`Credentials` (`proxy_credentials_set=false`), so the caller sees the 407 itself — the
URL-userinfo convenience is a property of `HttpEnvironmentProxy`, not of `WebProxy`.
`new WebProxy(addr){ Credentials = new NetworkCredential(...) }` works. So "the managed
stack can carry the credential" is true, but only when it is handed over through the
API, not when it is embedded in a proxy URL.

**6. `NO_PROXY` is honoured by .NET, and that has a sharp edge.** Because the wrapper
injects `NO_PROXY=localhost,127.0.0.1,::1`, every .NET client bypasses the proxy for
loopback: a loopback origin is a refused direct dial (10013, leg 8) and a loopback URL on
the proxy's **own port** lands on the listener in **origin-form without a credential** and
gets 407 (leg 9). So a managed workload cannot reach a loopback HTTP endpoint — including
the supervisor's own intent endpoint — by URL today: the wrapper's `NO_PROXY` turns that
URL into a direct dial, and the listener reads it as an unauthenticated proxy
consultation. `NO_PROXY` under .NET is therefore honoured (it does what it says), but it
is currently pointed at the one loopback endpoint we publish.

### Decision: which managed clients get usable egress today

**Usable egress through the supervisor proxy today:**

* **.NET 8+ `HttpClient` / `SocketsHttpHandler` with the default handler** — HTTP and
  HTTPS, provided the listener keeps answering `407` **with a `Proxy-Authenticate: Basic`
  challenge**. Cost: one extra round-trip per new proxy connection, and one
  `no_token` deny leaf per connection in the audit chain (see below).
* **`pwsh` 7** and anything built on CoreCLR's `HttpClient` default proxy
  (`Invoke-WebRequest`, `Invoke-RestMethod`, most .NET CLI tools).
* **Clients that set `WebProxy` + `Credentials` explicitly** (a workload that reads
  `HTTP_PROXY` and splits the userinfo itself can work; if it just passes the URI to
  `WebProxy`, it must also set `Credentials`).

**No usable egress:**

* **Windows PowerShell 5.1 and everything on .NET Framework's
  `HttpWebRequest`/`WebClient`/`HttpClient`** — they use the system (WinINet) proxy
  config, which is "direct" inside the container, so they never consult the proxy and die
  on `WSAEACCES 10013`.
* **`new WebProxy(uri-with-userinfo)`** — the 407 reaches the application.

**What would have to change for the others:**

1. **Nothing client-side can fix PowerShell 5.1.** The system proxy it reads cannot be
   written from inside the container (`HKCU\...\Internet Settings` is
   `ERROR_ACCESS_DENIED`, measured in P1.5), the WinHTTP machine store needs elevation and
   is machine-wide, and even a configured WinINet proxy could not carry the token
   pre-emptively (P1.5 measured that WinINet has no working pre-emptive credential API).
   The realistic options are (a) require `pwsh` 7 / .NET 8 for managed workloads — a
   workload requirement, not a platform change — or (b) the P1.5 admission change below.
2. **The admission change is the only one that helps everyone.** Accept an
   unauthenticated consultation that provably comes from this run's container (peer SID /
   WFP attribution) instead of a bearer token. That removes the 407 round-trip, the
   `no_token` audit leaves, and the credential-delivery problem in one move — but it is a
   P1.4-level change (trading a per-run token for an OS-attested local-peer check) and
   needs its own spike, not a patch.
3. **`NO_PROXY` needs a loopback story.** If the intent endpoint is meant to be reachable
   from managed workloads, the wrapper's `NO_PROXY` cannot contain `127.0.0.1` for them
   (they bypass the proxy and get 407 in origin-form, or 10013 for any other port), or the
   endpoint needs to accept origin-form unauthenticated requests from the run's own
   identity. Today a .NET workload cannot use it.

### Consequence for the audit chain (new, and easy to miss)

Every .NET proxy connection costs one `407` first. On the shipped listener that path
writes an audit leaf with `"deny"` and `no_token` (`proxy.rs`, the `AuthVerdict::Absent`
arm) and is **not** counted as a consultation. So a healthy .NET workload produces a
steady trickle of `deny/no_token` leaves that are entirely benign — which hollows out
`no_token` as a signal. Either the leaf needs a distinguishing field (e.g. "challenge
issued, credential retried and accepted on this run"), or the audit doc must say that
`no_token` alone is not evidence of an attack when a managed client is in use.

### Reproduce (P1.8)

```text
cargo build --features mxc-backend --bin mxc-launch
# scratch harness (not in the repo):
#   p18/probe   -> p18probe.exe  : containers, both listeners, all legs
#   p18/client  -> p18client.dll : .NET 8 probe (default | noproxy | explicit-uri |
#                                  explicit-cred | sockets | env)
#   p18/tls     -> serve.py      : real TLS origin (self-signed) + `TLSORIGIN` log
P18_TLS_URL=https://<lan>:<port>/p18 p18probe.exe    # no filter = all legs
P18_ONLY=net-default p18probe.exe                    # one leg
P18_CMD='<command>' p18probe.exe                     # ad-hoc, raw stdout

# the real-listener leg (asserts on LaunchProofCounters):
P18_CLIENT_DLL=...\p18client.dll P18_PS_PROBE=...\psprobe.ps1 \
  cargo test --features mxc-backend -- --ignored --nocapture p18_managed
```

Measurement concessions, stated rather than buried: `TEMP`/`TMP` point at the granted
workspace (a framework-dependent .NET app needs a writable temp), the TLS origin's
certificate is self-signed and the leg sets `insecure_tls`, and the `net-default-L` /
`net-default-P` legs use ports the two listeners chose at runtime rather than fixed
values.
