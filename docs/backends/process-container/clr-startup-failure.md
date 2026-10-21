# Why every CLR process dies at load in an unelevated ProcessContainer (P1.7)

Status: **root cause determined and fix verified 2026-10-21**, unelevated, Windows 11
26300.9711, `mxc-sdk 1.0.1`.

**Verdict.** The CLR is not involved. The container runs every child with the kernel
mitigation **"disallow Win32k system calls"**, which is what `mxc-sdk` derives from
`ui.disable`, and `ui.disable` **defaults to `true`** whenever a caller does not set
`ContainerRequest::ui`. Any DLL whose `DllMain` touches Win32k — `user32.dll`,
`gdi32.dll`, `ole32.dll`, and `coreclr.dll` itself (it statically imports `USER32` and
`ole32`) as well as `powershell.exe`'s .NET Framework chain — therefore fails to
initialise, and the process dies before `main`:

* `LoadLibrary` returns `ERROR_DLL_INIT_FAILED` (`1114` / `0x8007045A`),
* the native loader aborts the image with `STATUS_DLL_INIT_FAILED` (`0xC0000142`), or
* the .NET host reports `0x8007045A` and fail-fasts with `0xC0000409`.

Setting the single request field `ui = Some(UiPolicy { disable: false, .. })` makes
`powershell.exe` print **`FXOK`** and `dotnet hello.dll` print **`HELLO-OK`** inside the
same unelevated ProcessContainer. Nothing else changed. **This is fixable by request
configuration we control — it is not an SDK limitation.**

## The question

P1.5 recorded that both CLR flavours die at load inside a ProcessContainer while the
same `powershell.exe` runs under this repo's old AppContainer backend, and left the
cause open. Is it the token (LPAC / missing `ALL APPLICATION PACKAGES`), the filesystem,
the registry, the environment, a job object, the working directory, or the SDK?

## Method

Scratch harness `%LOCALAPPDATA%\hermes\cache\scratch\clr\`:

* `probe/` (Rust, `mxc-sdk =1.0.1`) launches one real ProcessContainer per leg through
  `mxc_sdk::v1::run`, with the P1 production request shape: `mxc-launch` as the
  container command, workspace readwrite, `C:\Windows` + `C:\Program Files\dotnet`
  readonly, explicit `TEMP`/`TMP`, `inherit_default_environment = true`.
  `CLR_UI=both` runs every leg twice, differing **only** in `request.ui.disable`.
* `diag/` (`clrdiag.exe`) is a **native** probe — raw Win32 FFI, no CLR, and it
  deliberately resolves `user32.dll` at runtime rather than importing it, so that a
  static import cannot make the probe itself unloadable in the case being measured. It
  reports token SIDs, `GetProcessMitigationPolicy` for all 19 policy classes,
  job-object membership, single-DLL `LoadLibrary` results, `RegOpenKeyExW` reachability,
  file access, environment, window station, child creation, and clipboard access.
* `CLR_ONLY=<substr>` filters legs; `CLR_CWD`, `CLR_TEMP`, `CLR_EXTRA_RO/RW`,
  `CLR_NOLAUNCH=1` (skip the wrapper), `CLR_NET=proxy` (production network policy)
  vary one factor at a time. Raw log: `clr/run-main.log`.

## Measured results

Baseline, identical request except one field (exit codes as reported by
`WaitResult::Exited`):

| leg | `ui.disable` | exit | stdout / stderr |
|-----|--------------|------|-----------------|
| `cmd /c echo NATIVEOK` | true | `0` | `NATIVEOK` |
| `cmd /c echo NATIVEOK` | false | `0` | `NATIVEOK` |
| `powershell.exe -NoProfile -Command "Write-Output FXOK"` | true | `-1073741502` (`0xC0000142`) | *empty* |
| `powershell.exe -NoProfile -Command "Write-Output FXOK"` | **false** | **`0`** | **`FXOK`** |
| `dotnet hello.dll` (.NET 8) | true | `-1073740791` (`0xC0000409`) | `Failed to load the dll from [...\8.0.32\coreclr.dll], HRESULT: 0x8007045A` |
| `dotnet hello.dll` (.NET 8) | **false** | **`0`** | **`HELLO-OK`** |

The single-DLL loader matrix, measured in a **native** process inside the same
container (`clrdiag load <dll>`, one load per process, `GetLastError` after a failed
`LoadLibraryExW`):

| DLL | `ui.disable=true` | `ui.disable=false` |
|-----|-------------------|--------------------|
| `kernel32.dll` | loads | loads |
| `user32.dll` | **fails, `1114` `ERROR_DLL_INIT_FAILED`** | loads (`14007` = already loaded) |
| `gdi32.dll` | **fails, `1114`** | loads |
| `ole32.dll` | **fails, `1114`** | loads |
| `C:\Program Files\dotnet\shared\...\coreclr.dll` | **fails, `1114`** | loads |

`coreclr.dll` 8.0.32 imports `KERNEL32`, `ADVAPI32`, **`ole32`**, `OLEAUT32`,
**`USER32`** and the UCRT (`dumpbin /dependents`), so the loader cannot bring it in
without initialising a Win32k client.

So `coreclr.dll` does not need the CLR to fail — it needs only `LoadLibrary`.

`GetProcessMitigationPolicy` from the same native probe, both arms:

```
ui.disable=true   ASLR 0x0000000f  StrictHandleCheck 0x00000003  SystemCallDisable(win32k) 0x00000001
                  UserShadowStack 0x00000100  SEHOP 0x00000001
ui.disable=false  ASLR 0x0000000f  StrictHandleCheck 0x00000003  SystemCallDisable(win32k) 0x00000000
                  UserShadowStack 0x00000100  SEHOP 0x00000001
```

**`ProcessSystemCallDisablePolicy` is the only differing bit.** ACG (`0x0`), CIG
(`0x0`), ExtensionPointDisable, ImageLoad, ChildProcess and SystemCallFilter are zero in
both arms — so the P1.5 "dynamic code works" control and this measurement agree, and no
code-integrity policy is involved.

Token, both arms (identical shape):

```
is_app_container = 1        is_less_privileged_app_container = (query unsupported on this build)
integrity = S-1-16-4096 (Low)    session = 1    restricted_sids = []    token_elevation = 0
appcontainer_sid = S-1-15-2-<per-run derived>
capabilities = [ S-1-15-3-1024-530591407-... ]
groups = Low IL, Everyone, Users, INTERACTIVE, Authenticated Users, ... (no S-1-15-2-1 ALL APPLICATION PACKAGES)
```

Everything else that the candidate hypotheses name is **identical in both arms**, and the
arms differ in exactly one request field:

| Probe | `ui.disable=true` | `ui.disable=false` |
|-------|-------------------|--------------------|
| `coreclr.dll`, `mscorlib.dll`, `user32.dll`, `dotnet.exe` open for read/execute | ok | ok |
| write into the container's `TEMP` | ok | ok |
| `TEMP`/`TMP` | `%LOCALAPPDATA%\Packages\sandbox.{guid}\AC\Temp` (container-remapped) | same |
| `reg query HKLM\SOFTWARE\Microsoft\.NETFramework /v InstallRoot` | `C:\Windows\Microsoft.NET\Framework64\` | same |
| `CreateProcessW("cmd.exe /c echo CHILDOK")` from inside | ok, `err 0` | ok, `err 0` |
| `IsProcessInJob` / job `ui_restrictions` | `1` / `0x0` | `1` / `0x0` |
| window station | unreadable (`user32` cannot load) | `WinSta0` |
| `OpenClipboard(NULL)` | n/a (`user32` cannot load) | **fails, `5 ERROR_ACCESS_DENIED`** |

## Hypotheses, one at a time

Numbers are exit codes; `1114` is `ERROR_DLL_INIT_FAILED`, `0xC0000142` is
`STATUS_DLL_INIT_FAILED`.

| # | Hypothesis | Verdict | Evidence |
|---|------------|---------|----------|
| 1 | LPAC token / missing `ALL APPLICATION PACKAGES` ACEs on CLR files | **eliminated** | Both arms carry the *same* AppContainer-shaped, Low-IL token with empty restricted SIDs, no `S-1-15-2-1` group and one capability — and one arm works. `coreclr.dll`, `mscorlib.dll`, `user32.dll` and `dotnet.exe` all open for `GENERIC_READ|GENERIC_EXECUTE` **in the failing arm**. A missing ACE would give `ACCESS_DENIED (5)`, never `1114`. |
| 2 | Filesystem: a path we do not grant (`%WINDIR%\Microsoft.NET`, `%ProgramFiles%\dotnet`, `%LOCALAPPDATA%`, writable `%TEMP%`) | **eliminated** | Every CLR path is already readable (table above). Widening the policy to `readonly` = `C:\Program Files`, `%LOCALAPPDATA%`, `C:\ProgramData`, `C:\Windows\Microsoft.NET`, `C:\Windows\assembly` and running `powershell` → still `-1073741502`, unchanged. `TEMP` set to an *ungranted* directory and `TEMP` set to a granted one → both `-1073741502`, unchanged. |
| 3 | Registry virtualised/blocked (`HKLM\SOFTWARE\Microsoft\.NETFramework`, `.NETCore`) | **eliminated** | `reg.exe` reads `InstallRoot` from `HKLM\SOFTWARE\Microsoft\.NETFramework` inside the container in **both** arms, and the two arms differ only in `ui.disable`. The failure also happens in a native probe that never opens a registry key. (Instrument note: `clrdiag`'s own `RegOpenKeyExW` returned `2 ERROR_FILE_NOT_FOUND` for four *existing* keys **in the host control run as well**, so that instrument is unreliable on this host; the registry leg was measured with `reg.exe` instead.) |
| 4 | Environment: `TEMP` unwritable / `COMPLUS_*` / `DOTNET_*` | **eliminated** | `TEMP`/`TMP` are remapped by the container into its own `...\AC\Temp` and are writable in both arms; no `COMPLUS_*`/`DOTNET_*` variables are present in either; overriding `CLR_TEMP` changes nothing (row 2). |
| 5 | Job object / process mitigation | **partially confirmed, and this is the cause** | The container *does* put the child in a job (`IsProcessInJob = 1`) and *does* apply a mitigation — `ProcessSystemCallDisablePolicy = 0x1` — and that mitigation is the only thing separating working from failing. The job's `ui_restrictions` mask reads `0x0` in both arms, so the job's UI limits are not the difference. |
| 6 | Working directory | **eliminated** | `working_directory = C:\Windows\System32` → `-1073741502`, unchanged. The two arms share the same cwd. |
| 7 | Loader/`mscoree` path only, e.g. something specific to `corflags`/`csc` | **not applicable** | Unnecessary: a native `LoadLibrary` of `coreclr.dll` (`1114`) reproduces the .NET host's exact failure, and `user32`/`gdi32`/`ole32` fail the same way. No CLR component is implicated. |

Two further controls, because "the harness did it" is a real possibility:

* `CLR_NOLAUNCH=1` (no `mxc-launch` wrapper, the binary as the container command):
  `-1073741502` with `ui.disable=true`, **`FXOK`** with `ui.disable=false`.
* `CLR_NET=proxy` (the production network policy: `egress.default=deny`,
  `ingress.hostLoopback=allow`, token-bearing `networkProxy`): `-1073741502` /
  **`FXOK`**. So the fix holds in the request shape P1/P3 actually ship.

## The mechanism, with the code that enforces it

1. `src/net/mxc.rs::build_request` never sets `ContainerRequest::ui`; it only fills
   `ProcessContainerConfig` (which is the *job-object* UI-restriction knob:
   `isolation`, `desktopSystemControl`, `systemSettings`, `ime`). `ContainerRequest::ui`
   defaults to `None`.
2. `None` is not "no opinion": `ContainerPolicy::default()` uses
   `UiPolicy::default()`, and that is full lockdown —
   `mxc-sdk-1.0.1/src/core/mxc_common/models.rs:583`
   (`disable: true`, `clipboard: None`, `injection: false`). The wire default agrees:
   `src/core/mxc_common/config_parser.rs:1597` `disable: raw_ui.disable.unwrap_or(true)`.
3. The ProcessContainer backend turns that field into the PSEC spec flag —
   `src/backends/process_container/common/base_container_helpers.rs:57`:
   `disallow_win32k_system_calls: request.policy.ui.disable`
   (flatbuffer field at
   `src/core/process_security_environment_spec/process_security_environment_layout/process_security_environment_generated.rs:144`).
4. The OS applies it as the kernel mitigation
   `PROCESS_CREATION_MITIGATION_POLICY_WIN32K_SYSTEM_CALL_DISABLE` — observed as
   `GetProcessMitigationPolicy(ProcessSystemCallDisablePolicy) = 0x1`.
5. Every Win32k syscall from the child then fails. `user32.dll`'s loader-time
   initialisation is a Win32k client connect, so its `DllMain` returns `FALSE`,
   `LoadLibrary` fails with `ERROR_DLL_INIT_FAILED`, and the loader either kills the
   process (`0xC0000142`) or lets the .NET host report the error and fail fast
   (`0x8007045A` → `0xC0000409`).

Why the old AppContainer backend printed `FXOK`: this repo's own AppContainer
implementation (`src/sandbox/`) contains **no** mitigation-policy code at all (grep for
`MITIGATION` across `src/sandbox/` and `src/net/` returns nothing), so it never banned
Win32k. Note that the SDK's *own* AppContainer tier does ban it —
`src/backends/process_container/common/appcontainer_runner.rs:858` and `:917` apply
`PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY` with `process_mitigation::win32k_disable_value()`
when `request.policy.ui.disable` — so P4.3's AppContainer fallback would **not** rescue a
managed workload while this field keeps its default.

## The fix, and what it costs

Exactly one request field, in `build_request` next to `request.network`:

```rust
request.ui = Some(UiPolicy {
    disable: false,                       // was: absent -> UiPolicy::default() -> true
    clipboard: ClipboardPolicy::None,      // keep default-deny
    allow_input_injection: false,          // keep default-deny
});
```

Proof: `powershell.exe ... "Write-Output FXOK"` → exit `0`, stdout `FXOK`;
`dotnet hello.dll` → exit `0`, stdout `HELLO-OK`; same result with and without the
`mxc-launch` wrapper and with the production proxy policy.

What is given up, measured rather than assumed:

* **Kept** — all ten `JOB_OBJECT_UILIMIT_*` restrictions that
  `resolve_ui_restrictions` derives from `base_process_ui` are still emitted
  (`ui_policy.rs:53-120`): clipboard read/write, input injection, external UI objects,
  global UI namespace, desktop switching, logoff/shutdown, system parameters, display
  settings. `OpenClipboard(NULL)` inside the container returns `FALSE` with
  `ERROR_ACCESS_DENIED (5)` while `user32` loads fine — the clipboard half is verified
  behaviourally, not just on paper.
* **Lost** — the child may enter Win32k at all: it can create windows and reach a very
  large kernel attack surface that `disallow_win32k_system_calls` was there to remove.
  This is a real, non-cosmetic reduction in the container's hardening, and it is the
  price of running *any* GUI-loading or managed binary.

There is no middle setting: `coreclr.dll` **statically imports `USER32.dll` and
`ole32.dll`** (`dumpbin /dependents`, 8.0.32 — alongside `KERNEL32`, `ADVAPI32`,
`OLEAUT32` and the UCRT), so it is "Win32k syscalls" or "no CLR", never both.

## Upstream note (not a blocker, but worth reporting)

`mxc-sdk` is behaving as documented; the trap is that the *absence* of a UI policy means
full lockdown, and that the ProcessContainer-specific config cannot express it:

* `ProcessContainerConfig` (`src/configs/process_container.rs:42`) has **no** field for
  `ui.disable`. A caller that carefully pins every field of `processContainer.ui`
  (`isolation`, `desktopSystemControl`, `systemSettings`, `ime`) — as D6 in this repo
  does — has still said nothing about the Win32k ban, which lives in the separate,
  optional, cross-cutting `ui` section with a `true` default.
* The SDK is aware of the neighbouring LPAC interaction and refuses it explicitly
  (`base_container_runner.rs:1202`: "the process-security-environment path cannot be
  combined with `processContainer.leastPrivilege` because it does not support LPAC
  tokens"), but there is no equivalent signal for "this request implies a mitigation that
  no managed runtime survives".

Suggested upstream fix: either default `disable` to `false` when the `ui` section is
absent, or reject/annotate a ProcessContainer request whose PSEC spec sets
`disallow_win32k_system_calls` while the command needs user32-class DLLs. Until then the
field must be set explicitly by every caller.

## Consequence for P3

P3 cannot ship with the current `build_request`: with `request.ui` unset, **every**
managed workload — and in fact every binary that loads `user32`/`gdi32`/`ole32`, which
includes most of the GUI tooling the sandbox is meant to host — dies at load with
`0xC0000142`/`0x8007045A` in ~80-180 ms, which the suite will see as a launch failure
rather than a policy verdict. The remedy is one field, `request.ui.disable = false`, and
it restores the CLR (verified: `FXOK`, `HELLO-OK`) while leaving the ten UI restrictions,
the filesystem policy, the proxy-only egress and the AppContainer-shaped token untouched.
That means P1.5's two conclusions have to be revised: the .NET/`SocketsHttpHandler` proxy
legs are **runnable** (they were skipped only because of this defect), and the decision
"GUI/system-proxy workloads are out of scope for MXC, keep AppContainer for them" was
made on a symptom of a default rather than on a property of the primitive. What P3 must
add is honesty in the other direction: the shipped posture no longer bans Win32k, so no
doc, audit leaf or CLI text may claim that mitigation, and the loss of Win32k-attack-surface
containment should be a recorded, deliberate trade in the ADR rather than a side effect of
a default. P3.1's "full suite on both images" also needs a leg that asserts the managed
path *starts* — a green suite that never runs a CLR process would not have caught this.

## Reproduction

```
CLR_UI=both                  # every leg under ui.disable=true and false
CLR_ONLY=ps51                # or diag-info | diag-load | diag-files | diag-env | ...
CLR_NOLAUNCH=1 CLR_UI=both   # without the mxc-launch wrapper
CLR_NET=proxy CLR_UI=both    # production-shaped network policy
CLR_CWD='C:\Windows\System32' CLR_TEMP='C:\Windows\Temp'
CLR_EXTRA_RO='C:\Program Files;C:\Users\marku\AppData\Local;C:\ProgramData;C:\Windows\Microsoft.NET'
```

```
%LOCALAPPDATA%\hermes\cache\scratch\clr\probe\target\debug\clrprobe.exe
%LOCALAPPDATA%\hermes\cache\scratch\clr\diag\target\release\clrdiag.exe info|load|files|env|child|clipboard|win32k|reg
```

Expected: `ui.disable=true` → `ps51` `-1073741502`, `coreclr-hello` `-1073740791`,
`diag-load-user32` `1114`; `ui.disable=false` → `FXOK`, `HELLO-OK`, user32 loads.
