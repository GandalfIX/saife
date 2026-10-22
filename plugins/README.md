# Plugins (host-side sidecars)

A **plugin** gives a sandboxed workload one narrow capability it cannot get any
other way: a small HTTP service that runs *outside* the container, on the
supervisor's side, and is reachable from inside only through the session proxy
at `http://<mount>.sandbox.invalid/`.

This directory holds **samples**. The copy that actually runs is the installed
one — `%USERPROFILE%\.sandbox\plugins\<name>\` — or a directory the operator
names explicitly with `--plugin-dir <PATH>`.

## Layout

```
<plugin root>/<name>/plugin.json      the manifest
<plugin root>/<name>/<anything else>  the sidecar and what it needs
```

`python` (or any program) is started with the plugin directory as its working
directory, so `"command": ["python", "sidecar.py"]` is self-contained.

## Where plugins come from (and the trust rule)

Discovery order for a name:

1. every `--plugin-dir <PATH>` on the command line, in the order given;
2. `%USERPROFILE%\.sandbox\plugins\`.

The **first** root that holds `<name>/plugin.json` wins. A later root that also
defines that name is *shadowed*, never merged. There is no deduplication by
content and no fallback: a broken manifest in the winning root is a refusal, not
an invitation to try the next one.

**A workspace `.sandbox/plugins` directory is NOT discovered automatically.**
That is deliberate: cloning a repository and running `sandbox run` in it must
never execute host-side code the repository shipped. Repo-local plugins are
usable only when the operator explicitly names the directory:

```
sandbox run --plugin-dir .\.sandbox\plugins --plugin tngtech -- <workload>
```

## Manifest fields

| field | type | meaning |
|---|---|---|
| `schema_version` | integer, required | must be `1`. A missing or unknown version is refused. |
| `name` | string, required | must equal the directory name; one DNS label. |
| `version`, `description` | string, optional | documentation only. |
| `mount` | string, required | one lowercase DNS label, `^[a-z0-9][a-z0-9-]{0,30}$`. No dots: a dot in a mount would forge a second label in the facade host. |
| `command` | array of strings, required | `command[0]` is resolved through `PATH`/`PATHEXT` and must be a real executable (`.cmd`/`.bat` are refused: the POC spawns no shell). The rest are arguments. |
| `health.path` | string, required | must start with `/`. Polled with `GET <path> HTTP/1.0` until it answers 2xx. |
| `health.timeout_ms` | integer, required | total budget for the health gate. Non-zero. |
| `health.interval_ms` | integer, required | pause between probes. Non-zero. |
| `operations` | array of `{method, path}`, default `[]` | what the plugin exposes. The POC relays `GET` only; the list is the declaration a later allowlist enforcement will read. |
| `secrets` | array of `{name, required, description, pattern}`, default `[]` | secret **names** the plugin needs. The POC parses and validates these but does not resolve them: no value is read, stored or passed. |
| `config` | object of string values, default `{}` | non-secret configuration. Each entry reaches the sidecar as `SIDECAR_CFG_<UPPER_SNAKE_KEY>`; `upstream` additionally arrives as `SIDECAR_UPSTREAM`, which is what the sample reads. |

Unknown fields are refused (`deny_unknown_fields`), so a typo in a key is a
refusal rather than a silently ignored setting.

## Transport (what the workload sees)

* Inside the container: `http://<mount>.sandbox.invalid/<path>`. Plain HTTP only.
  The name is never resolved and never dialled — the proxy recognises the
  reserved suffix and relays the request to the sidecar's loopback port.
* `GET` only in the POC. Any other method answers `501 facade_method_unsupported`.
* An undeclared mount answers `404 facade_unknown_mount`.
* `CONNECT <mount>.sandbox.invalid:443` answers `403 facade_requires_http`: TLS
  cannot be tunnelled past the facade, so nothing gets to pin or bypass the
  check.
* The workload still authenticates to the proxy with the session token, exactly
  like any other request. The façade hop then carries a **separate** per-session
  **facade token** (`X-Facade-Token`) that only the supervisor and the sidecar
  know; it never enters the container.
* Every facade request writes one audit leaf: `op: "FACADE"` with `mount`,
  `path`, `disposition` and, on a refusal, `reason`.

## The sidecar runs OUTSIDE the sandbox — the deputy boundary

The sidecar inherits the supervisor's token and its network access: it can reach
the internet, which is the entire point (the container cannot). It is therefore a
**deputy**, and the confused-deputy rule applies:

* A plugin must expose **narrow operations** (`GET /jira/issue/:key`), never a
  transparent proxy (`GET /?url=…`). Anything the sidecar exposes, the untrusted
  workload can call with the sidecar's authority.
* Its upstream is fixed by the manifest and carried in `config`, not by the
  request. A later allowlist enforcement reads `operations`; today the sample
  sidecar enforces its own path list.
* A plugin's stdout/stderr go to
  `%LOCALAPPDATA%\sandbox\sidecar-logs\<sid>-<mount>.log`. No secret value may
  be written there (the POC passes none).

## Lifecycle

1. the session proxy binds;
2. each requested plugin is loaded, its sidecar spawned with a free loopback
   port and a fresh 32-hex facade token, then health-gated;
3. the mount is registered in the session's facade registry — a duplicate mount
   in the same session is refused, so two plugins cannot answer for one name;
4. the workload starts.

A plugin that cannot be loaded, spawned or made healthy **refuses the session**
(exit code 5, one line naming the plugin and the reason). There is no "run
without it" fallback: asking for a capability and silently not getting it is the
failure this project exists to prevent. Sidecars are killed on every exit path,
including early returns, before the proxy that routes to them goes away.

## The sample: `tngtech`

`plugins/tngtech/` is a stdlib-only Python sidecar that fetches
`https://www.tngtech.com/` and serves it at `GET /`; `GET /status` is the health
probe; every other path, and every request without the facade token, is refused.
It exists to prove the transport before any secret handling does.

```
mkdir -p "$USERPROFILE/.sandbox/plugins"
cp -r plugins/tngtech "$USERPROFILE/.sandbox/plugins/"
cargo build --bin sandbox --bin mxc-launch
target/debug/sandbox.exe run --no-prompt --plugin tngtech -- cmd /c \
  "curl.exe -s -o NUL -w facade=%{http_code} http://tngtech.sandbox.invalid/ & curl.exe -s -o NUL -w direct=%{http_connect} https://www.tngtech.com/"
```

Expected: `facade=200` (the homepage came through the façade) and
`direct=403` (the container's own egress is still denied — no `--allow-domain`
was granted). `--no-prompt` keeps the deny half deterministic: an unattended run
has no dialog, and an answered "allow and remember" prompt would write a learned
entry that admits the host.

## What the POC does not do

No secret resolution (`secrets` is parsed, never read), no non-GET methods, no
per-operation enforcement by the supervisor, no AppContainer wiring (plugins are
`--backend mxc` only), no SSE size/keep-alive policy, no `sandbox plugin list`,
and no redaction of sidecar log output (there is nothing to redact yet).
