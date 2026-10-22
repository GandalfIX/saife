# Secret injection via sidecars — progress

Plan: [2026-10-23-secret-injection-and-sidecars.md](../../plans/2026-10-23-secret-injection-and-sidecars.md)
ADR (to be written in P6.2): `docs/adr/0005-sidecar-secret-injection.md`

Status legend: `[ ]` not started · `[~]` in progress · `[x]` done and gated · `[!]` blocked

## Rows

| # | Task | Status | Evidence |
|---|---|---|---|
| P1.1 | Skill manifest parse + validation matrix | [x] | Shipped as **plugin**: `src/plugin/mod.rs` (`PluginManifest`, `deny_unknown_fields`, mount label rule, health/command checks). Tests: `plugin::tests::*` (14) — missing `schema_version`, unknown field, mount matrix, empty mount, empty command, relative health path. |
| P1.2 | Skill registry, duplicate-mount refusal | [x] | `FacadeRegistry` + `facade_mount` in `src/plugin/mod.rs` (`the_registry_refuses_a_duplicate_mount`, `lookup_returns_none_for_an_unregistered_mount`). Two roots (`--plugin-dir` then global, first hit wins, shadowing pinned by `the_first_root_holding_a_name_shadows_later_ones`); loaded on demand per `--plugin`, not by scanning `*.json`. |
| P1.3 | `sandbox skill list/show`, `run --skill` (repeatable) | [~] | `run --plugin <NAME> --plugin-dir <PATH>`, both repeatable (`cli::tests::run_accepts_repeatable_plugin_and_plugin_dir`). NOT delivered: `plugin list` / `plugin show` — the source of a loaded plugin is visible in the refusal text instead. |
| P1.4 | Profile opt-in (`network.facade.enabled`, implied by `--skill`) | [ ] | |
| P2.1 | Credential-store backend (CredMan) behind a trait | [ ] | |
| P2.2 | `SecretValue`: redacting Debug/Display, no Serialize, zeroize | [ ] | |
| P2.3 | `sandbox secret set/list/delete` (fingerprint, never the value) | [ ] | |
| P2.4 | Launch-time resolution, `secret_missing` refusal | [ ] | |
| P3.1 | Sidecar spawn: job object, env, redacted log | [~] | `src/plugin/sidecar.rs`: free loopback port (TOCTOU documented), `SIDECAR_PORT/_FACADE_TOKEN/_MOUNT`, `SIDECAR_CFG_*` + `SIDECAR_UPSTREAM`, cwd = plugin dir, no shell, PATHEXT resolution with `.cmd`/`.bat` refused, stdout+stderr to `%LOCALAPPDATA%\sandbox\sidecar-logs\<sid>-<mount>.log`. NOT delivered: job object, log redaction (nothing secret exists to redact). |
| P3.2 | Health gate + `SIDECAR` audit leaf | [~] | Health gate polls `health.path` every `interval_ms` until `timeout_ms`, accepts any `2xx`, kills the child and refuses `sidecar_unhealthy{<mount>}` (live leg). NOT delivered: the `SIDECAR` leaf — facade traffic is audited as `op=FACADE` only. |
| P3.3 | Teardown kills the port (asserted by connecting) | [x] | `Drop for Sidecar` kills + reaps; the live leg connects to the port after Drop and requires the connect to FAIL. Sidecars are declared after the proxy in `run_mxc_session`, so they die first on every path. |
| P3.4 | In-tree fake sidecar fixture | [x] | `plugins/tngtech/` (stdlib Python, `plugins/README.md`) plus a Rust one-shot fake in `net::proxy::tests::fake_sidecar` for the routing/relay tests — no network needed there. |
| P4.1 | Facade routing (`<mount>.sandbox.invalid`), CONNECT refusal | [x] | `facade_action` table (7 rows) + host parsing table in `src/plugin/mod.rs` (bare suffix, lookalike, two labels refused). CONNECT to any `*.sandbox.invalid` → 403 `facade_requires_http`, audited, not counted as a consultation. |
| P4.2 | Relay + facade token + header rules + streaming | [~] | Supervisor-built request line (no client header is forwarded at all), `Host: <mount>`, `X-Facade-Token`, `tokio::io::copy` streaming, one request per connection. GET only. NOT delivered: SSE leg, explicit hop-by-hop stripping (nothing is forwarded), per-operation enforcement. |
| P4.3 | Per-request audit leaf, secrets unrepresentable | [x] | One `op: FACADE` leaf per request with `mount`, `path`, `disposition`, `reason`; `mount` added to `audit::filter::KNOWN_KEYS` (`mount=tngtech` parses). Secret values do not exist in this POC, so unrepresentable-by-construction is vacuously true — the real proof is P2.2 and is NOT done. |
| P4.4 | Live legs (round-trip, SSE, 404, 407) | [~] | Round-trip live leg `plugin::sidecar::tests::the_tngtech_sidecar_answers_through_the_facade_and_dies_on_drop` (needs internet + the installed plugin). 404/501/502/CONNECT are deterministic socket tests. NOT delivered: SSE leg; 407 is the existing token gate, untouched. |
| P5.1 | Jira sidecar with per-operation allowlist | [ ] | |
| P5.2 | Confluence sidecar | [ ] | |
| P5.3 | User-guide chapter with a worked example | [ ] | |
| P5.4 | Fake-upstream acceptance, then real instance checkpoint | [ ] | |
| P6.1 | Independent hardening review | [ ] | |
| P6.2 | ADR-0005 + amend ADR-0001's sidecar clause | [ ] | |
| P6.3 | Stale-claim grep sweep | [ ] | |

## Checkpoints (halt for user approval)

- **C1 — after P2**: a secret can be stored, listed by fingerprint, resolved at launch, and is provably absent from `Debug`/JSON. No process is started yet.
- **C2 — after P3**: a sidecar spawns, becomes healthy, is killed on every exit path, and the echo fixture proves it. Still no workload-visible route.
- **C3 — after P4**: the workload can reach a sidecar only through the façade; the CONNECT refusal and the token checks are pinned by tests. This is the security-relevant gate.
- **C4 — after P5**: Jira/Confluence work against a fake upstream and once against the real instance (user-run).
- **C5 — after P6**: ADR accepted, docs consistent, review findings closed or recorded.

## Open decisions (needed before P5.1)

1. **Jira scope**: read-only, and are project keys pinned in the manifest (recommended), or does the sidecar allow arbitrary JQL?
2. **Sidecar shape**: one binary per skill, or a single `sandbox-sidecar --skill <name>` (recommended: single binary, smaller surface).
3. **Mount TLD**: `.sandbox.invalid` (RFC 2606 reserved, recommended) vs a name under the workspace's own domain.
4. **Env-var injection** (`--env-credential`): ship in P7, or leave it out entirely?

## Event log

- 2026-10-23 — plan written. Nothing implemented. Repository state: `feature/windows-sandbox` at `5b30b5b` (== `master`), tree clean.
- 2026-10-23 — **POC landed** (the transport proof, not the plan's full scope). Shipped vocabulary is
  **plugin** (`plugin.json`, `--plugin`, `--plugin-dir`), not `skill` as the rows above say. Files:
  `src/plugin/{mod,sidecar}.rs` (manifest + validation, two-root discovery, `FacadeRegistry`, sidecar
  spawn + health gate + `Drop`), `src/net/proxy.rs` (`facade_action`, relay, CONNECT refusal,
  `op=FACADE` leaf, `mount` in `audit::filter::KNOWN_KEYS`), `src/main.rs` (wiring order: proxy binds
  → plugins spawn/health → registry → child; exit 5 on any plugin refusal), `src/cli.rs`
  (`--plugin`, `--plugin-dir`), `plugins/tngtech/` + `plugins/README.md`, `docs/USER-GUIDE.md` §6.
  Proof: in one `mxc` session `curl.exe http://tngtech.sandbox.invalid/` returns the homepage while
  `curl.exe https://www.tngtech.com/` is still denied. NOT delivered: secrets, non-GET methods,
  per-operation enforcement by the supervisor, AppContainer wiring, job object, `SIDECAR` leaf,
  `plugin list/show`.
