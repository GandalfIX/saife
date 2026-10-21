# WinHTTP / WinINet proxy path inside a ProcessContainer (P1.5)

Status: **measured 2026-10-21**, unelevated, Windows 11 26300.9711, `mxc-sdk 1.0.1`.
Decision input for P2/P3: **env-only proxying is sufficient only for stacks that read
`HTTP_PROXY`; the Windows system stacks (WinHTTP, WinINet, therefore browsers and
services) reach the proxy but arrive unauthenticated and get 407. They have no usable
egress.** .NET workloads do not start at all in this container (below).

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
| .NET 8 (CoreCLR) "hello" | — | — | — | **does not start**: `Failed to load ... coreclr.dll, HRESULT 0x8007045A`, exit `0xC0000409` |
| .NET Framework 4.8 (`powershell.exe` 5.1) | — | — | — | **does not start**: exit `0xC0000142` `STATUS_DLL_INIT_FAILED` |
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

* **.NET `HttpClient` / `SocketsHttpHandler` (default and `UseProxy=$false`)** — the
  CLR cannot start in this container (codes above); the AppContainer contrast shows it
  is the container, not the binary.
* **A `NETWORK SERVICE`/system-context child** — creating a process with another
  account's token needs `SeAssignPrimaryToken`/`SeImpersonate` (elevation) or stored
  credentials; unavailable unelevated, and the SDK launches with the caller's token
  only.
* **A real browser or system service** — not launched; the browser consequence is
  inferred from the measured WinINet/WinHTTP path (proxy forced, no credentials -> 407),
  not from a browser run.
