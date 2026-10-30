# opencode desktop inside saife — profile plan and verified architecture (Research + Plan)

> **Status:** Research complete, verified against the opencode source
> (`github.com/anomalyco/opencode`, `main`, read 2026-10-29). **Nothing has been
> implemented** — no profile file, no code. **Nothing has been run inside a real
> sandbox yet**, and the developer host is macOS while `saife` targets Windows, so
> *every Windows-specific fact below is unverified behaviorally* and must be
> confirmed on a Windows machine (§6). The plan is written so that the Windows
> session is a checklist, not a rediscovery.
>
> **Primary recommendation (§3):** do **not** sandbox the Electron app. Run the
> **server** (`opencode-cli serve --service`) under saife and let the desktop
> connect to it from outside; the untrusted work is server-side. The all-in-one
> variant (`saife run … OpenCode.exe`) is kept only as a fallback (§4).
>
> **Sibling plan:** `docs/plans/2026-10-28-gradle-daemon-loopback.md` — the same
> `WSAEACCES 10013` loopback wall, and the in-flight mechanism (address- and
> port-scoped loopback egress) that would make the `mxc` path viable for this
> workload too. This document leans on it and does **not** duplicate it.

**Goal:** a profile (and a documented run recipe) that lets a user do opencode
work under `saife`, on Windows, without hand-granting more than the workload
needs — and an honest statement of which process is sandboxed, which backend can
work today, and which parts are proven vs. merely reasoned.

**Non-goals:** implementing the profile, implementing loopback egress (owned by
the sibling plan), credential injection, updating opencode itself.

---

## 1. Verified architecture (from source)

All references are paths inside the opencode repository at `main`.

### 1.1 Install location, identity, and the "central directory"

| fact | value | source |
|---|---|---|
| Windows installer | NSIS, `oneClick: true`, **`perMachine: false`** → per-user install | `packages/desktop/electron-builder.config.ts:172-176` |
| default install dir (Windows) | `%LOCALAPPDATA%\Programs\OpenCode` (electron-builder per-user default; **confirm on the target machine**) | ibid. |
| app name | productName `OpenCode`; appId `ai.opencode.desktop` | `electron-builder.config.ts:246`, `src/main/constants.ts:17-25` |
| Electron userData | `%APPDATA%\OpenCode` (= `app.getPath("userData")`; **verify**, Electron derives it from the product name) | `background-service.ts:46`, `desktop-cli.ts:144` |
| main process CWD | `homedir()` (chdir at startup) | `src/main/lifecycle/configure.ts` |
| desktop ↔ server | renderer talks plain HTTP to a **local server**; the desktop is a thin client | `src/main/service/background-service.ts` |

The "central directory" the app runs from is therefore *two* directories:
`%LOCALAPPDATA%\Programs\OpenCode` (the Electron app) and — the part that matters
for sandboxing — `%APPDATA%\OpenCode\cli\<version>-<arch>\`, where the app
**copies the server binary and executes the copy**:

```
%APPDATA%\OpenCode\cli\2.2.0-x64\opencode-cli.exe      (staged at startup)
```

Source: `src/main/service/desktop-cli.ts:139-164` (`installCli`, `stageName`
`<version>-<arch>`), `src/main/service/cli-version.ts:33-35`. A packaged build
always stages (`resolveBundledCli` → `installCli` when `app.isPackaged`), so the
sandbox must allow **read-write and execute** on `%APPDATA%\OpenCode`, not only
read on the install directory. This is also why the running server is *not* the
file under `Programs\OpenCode`.

### 1.2 The server

| fact | value | source |
|---|---|---|
| spawn | `[opencode-cli, "serve", "--service"]`, **detached**, stdio ignored | `background-service.ts:64-69` |
| bind | hostname `127.0.0.1` (default; `0.0.0.0` only in isolated/dev or remote-access mode) | `background-service.ts:64-69,91` |
| default port | channel `latest`/`dev`/`beta`/`next` → `0xC0DE` (49374); `local` → `0xC0DF` (49375) | `packages/cli/src/services/service-config.ts:56-60` |
| **Windows port** | `port >= 0x8000` → `0x7000 \| (port & 0xFFF)` = **28894** for `0xC0DE` | `service-config.ts:46-53` |
| auth | HTTP **Basic** `opencode:<password>`; password = 32 random bytes base64url, persisted | `service-config.ts:183-192` |
| registration file | `$XDG_STATE_HOME/opencode/service.json`, i.e. `%USERPROFILE%\.local\state\opencode\service.json` on Windows | `service-config.ts:41-44,116-132`; `packages/util/src/global-roots.ts` |
| password/config file | `%USERPROFILE%\.config\opencode\service.json` (mode 0600) | `service-config.ts:130,175-181` |
| fixed port on purpose | "a fixed port makes a second contender fail to bind and back off" | `background-service.ts:62-63` |
| remote access (off by default) | `--hostname 0.0.0.0 --port 3084` + an E2E tunnel with a random subdomain route | `background-service.ts:66-68`, `service-config.ts:14-22,170-212` |

**The renderer's connection is plain loopback HTTP with Basic auth** — no unix
socket, no named pipe, no configurable alternative. That single fact decides the
backend question (§2).

### 1.3 Files the app reads and writes (Windows spellings)

opencode uses the XDG layout on every platform, rooted at the home directory
(`packages/util/src/global-roots.ts:4-18`):

| path | use |
|---|---|
| `%USERPROFILE%\.config\opencode` | config (`opencode.json`), `plugins/`, `skills/`, `package.json` + `node_modules` (plugins install as npm packages), `service.json` |
| `%USERPROFILE%\.local\share\opencode` | **`auth.json` (provider API keys)**, `opencode.db` (SQLite, sessions/messages), `storage/`, `log/` |
| `%USERPROFILE%\.local\state\opencode` | `service.json` (registration: url, pid, password), `kv.json`, `model.json`, `locks/` |
| `%USERPROFILE%\.cache\opencode` | `bin/` (downloaded LSP servers) |
| `%APPDATA%\OpenCode` | Electron userData: staged CLI, Local Storage, updater metadata/cache |
| `%LOCALAPPDATA%\Programs\OpenCode` | the app itself (read + execute only) |
| `$CWD` / project directory | the workspace opencode operates on (resolved by walking up to `.git`/`.opencode`) |

`auth.json` is inside a directory the existing `profiles/opencode.json` already
grants read-write. That profile grants `$USERPROFILE/AppData/Roaming/opencode`,
which on NTFS is **the same directory** as Electron's `%APPDATA%\OpenCode`
(case-insensitive). So the staged-CLI directory may already be covered — verify,
but expect the grant to be redundant rather than missing.

### 1.4 Network endpoints

| endpoint | when | source |
|---|---|---|
| `https://models.opencode.ai/experimental/v2.0/api.json` | startup model catalogue; bundled snapshot fallback + 5-min cache, so denial degrades | `packages/core/src/models-dev.ts:493,496,547-586` |
| provider APIs from `auth.json` (here `*.trustedtokens.eu`) | every agent turn | machine config, not source |
| `https://opencode.ai/…` (`config.json`, `theme.json`, desktop update feed) | shell UI, updater | `packages/core/src`, `electron-updater` `app-update.yml` |
| `http://localhost:8000/mcp` (example) | MCP servers of type `remote` — **loopback** | machine config |
| `127.0.0.1:19876` MCP OAuth callback, editor SSE port | only when those features are used | `packages/cli` |

The AI traffic that matters is the **Bun-compiled server's** traffic, and it is
proxy-env-aware (`HTTP_PROXY`/`HTTPS_PROXY`/`NO_PROXY`). The Electron shell's own
fetches use the OS/Chromium stack, not the env.

---

## 2. The collision with saife's backends

This section analyses the **all-in-one placement** (the whole app, Electron
included, inside one session). §3 shows that moving the shell outside removes the
UI-link half of the problem; the server's own loopback needs remain.

### 2.1 The loopback wall is measured, not hypothetical

Under the default `mxc` backend, a raw `connect()` from inside the container to
`127.0.0.1:<any port but the proxy's>` fails with **`WSAEACCES 10013`**;
`ingress.host_loopback = allow` is *not* general loopback (the D-4 endpoint works
only because it shares the proxy's own port). This is recorded in
`docs/tasks/mxc-migration/PROGRESS.md` (P1.5) and is the exact failure already
documented for the Gradle daemon in `profiles/README.md`.

opencode desktop has the same shape by construction: **renderer → 127.0.0.1:28894
(local server), and the server → `localhost:8000` (MCP)**. A loopback connect is
the app's core IPC. Consequences per backend:

| backend | renderer ↔ server | server → provider | shell → `opencode.ai` | verdict |
|---|---|---|---|---|
| `mxc` (default, today) | **denied (`10013`)** | proxy (env-aware, authenticates) | denied (Chromium/OS stack ignores env proxy) | **does not work** |
| `mxc` + loopback egress (sibling plan, in flight) | works if **28894** (and any MCP port) is allowed | proxy | denied (cosmetic) | **the intended answer** |
| `appcontainer` (documented escape hatch) | works via the per-SID loopback exemption (needs **admin**) | proxy | fails (system-proxy class, no env-aware client) | **works today**, elevated |

Because opencode's server port is **fixed** (28894 on Windows), the `mxc` path is
*simpler* than the Gradle one: no port pinning or `"auto"` allocation is needed —
one `127.0.0.1/32 : 28894` rule covers the client/server link. Additional ports
are needed only for features the user enables (MCP at `:8000`, MCP OAuth callback
at `:19876`); each must be an explicit line. **The sibling plan's `network.loopback`
schema does not exist yet**, so today this is a dependency, not an option.

In the **split** (§3), the renderer is outside and *connects into* the container
(ingress, which MXC allows). Only the server→`localhost` direction above still
needs `network.loopback` — and only for features that dial loopback.

### 2.2 The escape hatch that works today

`--backend appcontainer` is precisely the path AGENTS.md documents for
"WinINet / PowerShell 5.1 / system-proxy apps"; its all-or-nothing per-SID
loopback exemption lifts the `10013` wall for the renderer → server connection.
Two constraints it brings:

1. **Elevation** is required for networked AppContainer sessions (loopback
   exemption).
2. **DACL propagation stops at 20,000 objects** (`profiles/README.md`). The
   opencode state tree is large (the SQLite `opencode.db` plus `storage/`;
   the TUI state tree was measured in the tens of thousands of objects on the
   reference machine). Expect `grant propagation ... truncated` and verify what
   is actually granted before trusting a long agent session.

---

## 3. Recommended topology: server inside, desktop outside

**Claim under test:** the Electron app is "just" a frontend; the real work happens
in the server, so only the server has to be sandboxed.

**Verdict: confirmed in substance, but "just a frontend" is imprecise.** The
agent's work — file edits, shell tools, git, LSP, provider calls — runs in the
Bun server (`opencode-cli serve`). The Electron *main* process, which would stay
outside the sandbox, still holds user-driven OS powers:

| work | process | sandboxed in this topology |
|---|---|---|
| agent tools, file edits, shell, git, LSP, provider traffic | server (`opencode-cli serve`) | **yes** |
| UI, session rendering, SSE consumption | renderer | no |
| file pickers/attachments, Save-as, reveal/open-in-editor, clipboard, staged CLI, own settings DB, auto-update | Electron main | no |

The Electron-main powers are all user-initiated (a human picks a file, clicks
Save, opens a folder), so they are outside the agent's blast radius even though
they are not "nothing". Sources: `packages/desktop/src/main/files/index.ts`
(`openFilePicker`, `saveFile`, `openPath`, `revealPath`, `readClipboardImage`),
`src/main/service/desktop-cli.ts` (stages and executes the CLI),
`src/main/storage/` (its own database).

### 3.1 Why the split is easier than sandboxing the app

- No Electron-under-ProcessContainer / AppContainer question (GPU, shared
  memory, `oc://`, nested Chromium sandbox) — untested territory avoided
  entirely.
- The process boundary flips to the direction MXC *does* allow: the unsandboxed
  desktop **connects into** the container. `mxc.rs:2129-2152` sets
  `ingress.default = allow` + `ingress.host_loopback = allow` whenever a proxy
  session exists. (Unmeasured for a long-lived SSE stream — a spike, §6 B.)
- `auth.json` and every agent action stay inside the sandbox; the desktop's own
  network (theme, updater) is unrestricted but irrelevant.

### 3.2 The mechanism is service registration, not "Add server"

The desktop **always** ensures a local service at startup
(`background-service.ts:59`) and adopts a running, **version-compatible** one
before spawning (`:81-86`, `sidecar-probe.ts` → `Service.discover`).
`Service.ensure` **reuses** on version match, **replaces** on mismatch
(`packages/client/src/effect/service.ts`). Therefore:

1. Run `opencode-cli serve --service` **inside** saife, with the **same XDG state
   directory** as the desktop. The server writes
   `%USERPROFILE%\.local\state\opencode\service.json` (url, pid, version,
   password, 0600).
2. Start the desktop normally. It finds and adopts the sandboxed server; the
   renderer connects to it with the Basic credential from that file.
3. Use the **same CLI build** as the desktop's bundled one (the desktop compares
   versions and will otherwise stop or replace it).

The UI also offers "Add server" (URL + password,
`packages/app/src/servers/connect/dialog.tsx`), but that does **not** suppress
the startup `ensure`, so it is the manual fallback, not the reliable route.

### 3.3 The containment trap this topology must not fall into

`ensure`'s "missing/version-mismatch" branch spawns the desktop's **own** CLI —
**outside** the sandbox. Two ways that happens silently:

- the sandboxed server is not registered (no `--service`), unhealthy, or a
  different version;
- a **host-side** opencode server is registered, and the desktop adopts *that*
  (containment bypass that looks like success).

So a correct session has two hard conditions: **the sandboxed server is the one
registered**, and **no host server is running**. Both are operational checks in
§6 B, not assumptions.

### 3.4 What is still needed from the sibling plan

Only **server-originated** loopback: a `remote` MCP server on `localhost:8000`
(or the MCP OAuth callback on `:19876`), and anything else the *server* dials on
loopback. The UI link no longer needs loopback egress — it needs ingress, which
MXC already allows. Core agent work needs no loopback at all.

### 3.5 Run recipe (primary)

```powershell
# 1. ensure no host-side opencode server is running (it would be adopted instead)
# 2. sandbox the server only; the CLI runs from the install tree (no staging)
saife run --profile opencode-desktop --allow-cwd -- `
  "$env:LOCALAPPDATA\Programs\OpenCode\resources\opencode-cli.exe" serve --service
# 3. launch OpenCode.exe normally, outside the sandbox
```

`--backend mxc` (unelevated) is the goal and hinges on the ingress spike (§6 B);
`--backend appcontainer` is the fallback (and still needs elevation). The server
must be able to write the XDG state dir so `service.json` reaches the desktop.

---

## 4. Proposed profile (sketch — not implemented)

One profile serves both topologies. In the **primary split** (§3) it is the
server's policy: XDG state dirs, the project, and execute on the bundled CLI. In
the **all-in-one fallback** it also covers the Electron app. It extends the
shipped TUI profile so the state dirs, network baseline and 4 h session limit are
inherited:

```json
{
  "meta": {
    "name": "opencode-desktop",
    "version": "0.1.0",
    "schema_version": 1
  },
  "extends": ["opencode"],
  "filesystem": {
    "allow": [
      "$APPDATA/OpenCode"
    ],
    "read_only": [
      "$LOCALAPPDATA/Programs/OpenCode"
    ]
  },
  "network": {
    "allow_domain": [
      "models.opencode.ai",
      "opencode.ai"
    ]
  },
  "limits": {
    "workloadTimeoutSecs": 14400
  }
}
```

Notes on the schema (all verified in `src/profile.rs`):

- `extends` merges arrays and requires parents to agree on scalars; `opencode`
  already brings `$CWD`, the four XDG dirs, `AppData\Roaming\opencode`,
  `AppData\Local\opencode`, `profile: "developer"`, `*.trustedtokens.eu` and
  `workloadTimeoutSecs: 14400`.
- `read_only` on the install directory is what **both** topologies need: the
  split executes `resources\opencode-cli.exe` from it (no staging, so no write
  grant), and the fallback needs the app itself. It also deliberately
  **breaks auto-update** (electron-updater cannot write), the desired posture in
  a sandbox. Do not grant `%LOCALAPPDATA%\…-updater` unless updates inside the
  sandbox are wanted.
- `$APPDATA/OpenCode` is needed **only by the all-in-one fallback** (Electron
  userData and the staged CLI). The split's server never writes it, so a
  split-only profile can drop the grant. It is expected to **dedupe against** the
  parent's `$USERPROFILE/AppData/Roaming/opencode` anyway (dedupe is
  case-insensitive, and on NTFS these are one directory).
- Auto-update traffic (`opencode.ai/update/...`) and the shell's theme/config
  fetch will still fail in the fallback because the Electron stack cannot use the
  env proxy. Cosmetic; do not add hosts to "fix" it. In the split the shell is
  outside the sandbox and has ordinary network access.
- Built-in denies (`.ssh`, `.aws`, `.azure`, `.gnupg`, `.saife`) still apply. The
  built-in denies protect credential stores; note the deliberate consequence:
  `auth.json` **must remain readable** (it is the app's own credential store) and
  is inside a granted tree. The network allow-list is the only exfiltration
  bound. Accepted risk, to be stated in the profile README.

**Primary run recipe:** see §3.5 — sandbox `opencode-cli.exe serve --service`,
launch the desktop outside. No `--backend` requirement beyond the ingress spike
in §6 B; prefer `mxc` (unelevated) if it passes, else `appcontainer`.

**Fallback run recipe (all-in-one; `appcontainer`, elevated):** the whole app in
one session, kept only because it is the one single-process option that works
today:

```powershell
saife run --profile opencode-desktop --backend appcontainer --allow-cwd -- `
  "$env:LOCALAPPDATA\Programs\OpenCode\OpenCode.exe"
```

`--allow-cwd` grants the directory `saife` is launched from as the workspace; the
desktop itself chdirs to `$HOME`, and projects opened outside that launch CWD need
their own `--allow`.
Do **not** run the host desktop and a sandboxed server at the same time: the
server port is fixed and the registration file `service.json` is shared, so the
second instance backs off (see `background-service.ts:62-63`) — or, worse, the
desktop adopts the host server (§3.3).

**Loopback ports:** only for **server-originated** loopback (§3.4), e.g.
`"network": { "loopback": { "mode": "ports", "ports": [8000] } }` for a local MCP
server (schema from the sibling plan; not implemented). The UI link needs none.

---

## 5. Risks / open decisions

1. **Containment bypass via service adoption (primary topology's top risk).**
   If the sandboxed server is missing, unhealthy, or a different version, the
   desktop's `ensure` spawns its **own** server *outside* the sandbox; if a host
   server is registered, it is adopted instead. Correctness depends on two
   operational conditions: the sandboxed server is the registered one, and no
   host server runs. Verify, do not assume (§6 B).
2. **Which backend for the server?** Split: `mxc` if the ingress spike passes
   (unelevated, the goal), `appcontainer` as the fallback (elevated). The
   all-in-one fallback requires `appcontainer` and inherits the 20k-object DACL
   cap on a large state tree.
3. **Host→container ingress is unmeasured.** MXC sets `ingress.* = allow` with a
   proxy session, but a long-lived SSE stream from an unsandboxed client into the
   container has not been exercised; a spike, not a design unknown.
4. **The desktop is outside by design.** Its file/OS powers (pickers,
   attachments, Save-as, reveal/open, clipboard, updater, launching external
   apps) are outside the sandbox and are trusted-user actions, not agent actions.
   The one cross-boundary write worth naming: `saveFile` writes
   **renderer-supplied content** to a **user-chosen path**, i.e. server-influenced
   bytes land wherever the human confirms — the same class as any download dialog.
5. **Fixed port / shared registration.** `service.json` and port 28894 are
   user-global. A host server blocks or is adopted by the sandboxed one; the
   sandboxed one blocks the host. Operational, and partly the point (adoption).
6. **`auth.json` exposure.** Provider keys are readable inside the sandbox and
   reachable by any allow-listed host. Accepted for now; credential injection is
   a project non-goal.
7. **All-in-one fallback only:** the app stages a **writable executable** into
   `%APPDATA%\OpenCode\cli\…` (RW+exec, replaceable inside the grant — no
   privilege boundary, but worth stating) and runs Electron inside the container
   (GPU/shared-memory/`oc://`/single-instance lock unproven there).

---

## 6. Verification on a Windows machine (required — none of this is measured)

Run inside the disposable VM per AGENTS.md ("VM-first rule"); VM deletion is the
rollback. If any step is run on the physical host, write the rollback script
first (ACE cleanup: `tests/cleanup-acls.ps1`, and check the ancestor ACE count
before/after).

> **Measured 2026-10-30** (Windows 11, `mxc` GA, unelevated) - see
> `docs/research/backends/process-container/opencode-desktop-windows.md`.
>
> - **A1-A5 are wrong about the paths**: the install is `…\Programs\ai.opencode.desktop` and
>   userData is `%APPDATA%\ai.opencode.desktop` (appId, not product name). The profile now carries
>   the measured paths.
> - **B3 passed**: the sandboxed server binds 28894 and writes `service.json` with its own pid.
> - **B4/B5 failed, and the failure is the finding**: the desktop spawns its own unsandboxed server
>   (which cannot bind and exits), and the host's `connect()` to the container's port **times out** -
>   host -> container ingress is not usable under `mxc`, whatever the request asks for.
> - **C is not viable for this app**: the DACL propagation cap (20 000 objects) is below opencode's
>   state tree, so `appcontainer` cannot grant what the session needs.
>
> **Consequence for §3: the split topology does not work today.** The all-in-one shape becomes the
> intended answer *once loopback egress exists* (the sibling plan), because both processes then live
> in one container and use container loopback - no ingress involved. Electron-under-ProcessContainer
> stays the open risk (§5.7).

**A. Confirm the source-derived facts**

- [ ] **A1** Install opencode desktop on the VM; record the actual install
      directory (`Get-Process OpenCode | Select-Object Path`, and the NSIS
      uninstall key). Confirm `%LOCALAPPDATA%\Programs\OpenCode`.
- [ ] **A2** Start it once **outside** the sandbox. Confirm it stages the server:
      `%APPDATA%\OpenCode\cli\<version>-<arch>\opencode-cli.exe` exists.
- [ ] **A3** Read `%USERPROFILE%\.local\state\opencode\service.json`; confirm
      `url` is `http://127.0.0.1:28894` and that `port` is 28894 (the win32
      remap). Confirm `%USERPROFILE%\.config\opencode\service.json` exists (0600).
- [ ] **A4** `Get-NetTCPConnection -LocalPort 28894 -State Listen` → owning PID
      is `opencode-cli.exe` under `%APPDATA%\OpenCode\cli\…`.
- [ ] **A5** Confirm the bundled CLI is what the split will run:
      `%LOCALAPPDATA%\Programs\OpenCode\resources\opencode-cli.exe` and
      `opencode-cli.version` exist, and record the version. It must equal the
      staged CLI's version the desktop adopts against (§3.2).
- [ ] **A6** Record which provider hosts the user's `auth.json` actually targets
      (do not print the keys) so the allow-list is right for this machine.

**B. Split topology — server sandboxed, desktop outside (primary)**

- [ ] **B1** Put the profile at `%USERPROFILE%\.saife\profiles\opencode-desktop.json`;
      `saife profile show opencode-desktop --expanded` → variables expanded, no
      refusal (deny-covers-grant, unknown key).
- [ ] **B2** Stop every host-side opencode server (desktop quit, no `opencode
      serve`, no stale `service.json` owner). This is a precondition, not a
      nicety — see §3.3.
- [ ] **B3** Run the §3.5 recipe under `--backend mxc` (unelevated) first:
      `opencode-cli.exe serve --service` inside saife. Confirm it wrote
      `service.json` (same XDG dir), that `saife audit show <sid>` names the
      session, and record the guardrail line (`probes=… accepted=… tunnels=…`).
- [ ] **B4** Launch `OpenCode.exe` outside the sandbox. Confirm it **adopts** the
      sandboxed service, not spawn its own: `service.json`'s `pid` is the
      sandboxed CLI, `Get-NetTCPConnection -LocalPort 28894` is owned by that PID,
      and **no second `opencode-cli.exe`** exists outside the session.
- [ ] **B5** Send a prompt from the UI. Confirm: model catalogue, provider call
      through the proxy, a file edit, and that the UI stays connected to the
      sandboxed server across a long session (host→container ingress / SSE). This
      is the ingress risk in §5.
- [ ] **B6** If B5 fails on ingress under `mxc`, repeat B3–B5 with
      `--backend appcontainer` (elevated). Record which leg needed which backend.
- [ ] **B7** Containment negatives: `%USERPROFILE%\.ssh` is not readable by the
      sandboxed server; a non-allow-listed provider host is denied; and a
      deliberately **version-mismatched** or absent sandboxed server makes the
      desktop spawn its own (unsandboxed) one — confirm that failure mode exists
      so it can be documented as the thing to avoid (§3.3).
- [ ] **B8** Once `network.loopback` exists (sibling plan): let the server reach a
      `remote` MCP server on `localhost:8000` under `mxc` with
      `{"mode":"ports","ports":[8000]}`; a second, unallowed loopback port must
      still be refused with `10013`. The UI link needs no loopback port.
- [ ] **B9** Kill the session; confirm `service.json` is left in a state the next
      host launch can recover from. Clean up ACEs and re-run the ancestor-count
      check.

**C. All-in-one fallback — the whole app sandboxed (`appcontainer`, elevated)**

- [ ] **C1** Run the §4 fallback recipe elevated. Watch for `grant propagation …
      truncated` (20k cap on the state tree) and for Electron/AppContainer
      startup failures.
- [ ] **C2** Open a project, send a prompt, confirm the provider call through the
      proxy and that the UI stays connected to its own server (the loopback
      exemption working); confirm the server process belongs to the session.
- [ ] **C3** Kill the session; check the staged CLI and `service.json` are
      consistent and that the next host launch is not wedged. Clean up ACEs.

**D. `mxc` single-process (expected to fail today — capture the evidence)**

- [ ] **D1** Run the same profile with the **app** under `--backend mxc`
      (unelevated). Expect the renderer to be disconnected: confirm the failure
      is a `connect` to `127.0.0.1:28894` with `WSAEACCES 10013` (Procmon or an
      in-session probe), **not** a proxy/credential failure — the record that the
      all-in-one path depends on the sibling plan.

**E. Record the outcome**

- [ ] Write measured results into `docs/research/backends/` (same shape as
      `winhttp-proxy-path.md`: method, legs, table, mechanism) and link it from
      this plan. A negative result is a result, not a failed spike.
- [ ] Promote the ingress and adoption legs to `#[ignore]` live tests if the
      topology is adopted, so an SDK/opencode bump cannot silently change the
      answer.
- [ ] Update `profiles/README.md` with the verified row and the honest limits
      (which process is sandboxed, updates, `auth.json`, fixed port, version
      match).

---

## 7. Out of scope

- Implementing the profile or the loopback schema (this document is research +
  plan; the sibling plan owns enforcement).
- Sandboxing the Electron shell itself. In the primary topology it is outside by
  design (trusted UI); the all-in-one variant is only a fallback.
- Making the Electron shell's own network stack work behind the proxy in the
  fallback — the shell's non-loopback fetches are cosmetic and deliberately left
  failing.
- Updating opencode from inside the sandbox.
- Guessing opencode's server version: the split requires the same CLI build the
  desktop bundles; version negotiation is not solved here.
