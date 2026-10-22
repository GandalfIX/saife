//! One plugin sidecar's lifecycle: spawn, health gate, teardown.
//!
//! The sidecar is the supervisor's child and runs **outside** the container. It
//! gets a free loopback port, a fresh 32-hex facade token, the mount name and the
//! manifest's non-secret `config` entries in its environment, and nothing else —
//! no secret value exists in the POC. Its stdout/stderr go to
//! `%LOCALAPPDATA%\sandbox\sidecar-logs\<sid>-<mount>.log` instead of the
//! session's console, so a chatty sidecar cannot corrupt the workload's output.
//!
//! No shell is involved: `command` is spawned directly, `command[0]` is resolved
//! through `PATH` and `PATHEXT`, and a `.cmd`/`.bat` entry point is **refused**
//! rather than handed to `cmd /c`. That is the POC's honest limit — a batch file
//! is a shell script, and running one would put a parser between the manifest and
//! the process.
//!
//! `Drop` kills and reaps the child, so a sidecar cannot outlive the supervisor
//! that routes to it — including on every early return between spawn and the
//! workload's exit.

use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use windows::Win32::Security::Cryptography::{BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom};

use super::{FacadeTarget, HealthSpec, PluginManifest};

/// Bytes behind a facade token: 128 bits, hex-encoded to 32 characters.
const FACADE_TOKEN_BYTES: usize = 16;

/// A spawned plugin sidecar.
pub struct Sidecar {
    mount: String,
    port: u16,
    token: String,
    /// `Some` until `Drop`: the child is killed and reaped exactly once.
    child: Option<Child>,
    log_path: PathBuf,
}

impl Sidecar {
    /// Spawn `manifest`'s sidecar from `plugin_dir` and wait for its health probe.
    ///
    /// Every failure is a named refusal that the session path prints as-is and
    /// turns into exit code 5: `sidecar_port_unavailable`,
    /// `sidecar_log_unavailable`, `sidecar_command_not_found`,
    /// `sidecar_command_not_exe`, `sidecar_spawn_failed`, `sidecar_unhealthy{mount}`.
    pub fn start(plugin_dir: &Path, manifest: &PluginManifest, sid: &str) -> Result<Self> {
        let port = free_loopback_port()?;
        let token = facade_token()?;
        let log_path = sidecar_log_path(sid, &manifest.mount)?;
        let stdout = open_log(&log_path)?;
        let stderr = stdout
            .try_clone()
            .with_context(|| format!("sidecar_log_unavailable: {}", log_path.display()))?;
        let program = resolve_program(&manifest.command[0])?;

        let mut cmd = Command::new(&program);
        // No shell: argv is passed through, `current_dir` is the plugin's own
        // directory, and every setting below is an explicit name/value pair.
        cmd.args(&manifest.command[1..])
            .current_dir(plugin_dir)
            .env("SIDECAR_PORT", port.to_string())
            .env("SIDECAR_FACADE_TOKEN", &token)
            .env("SIDECAR_MOUNT", &manifest.mount)
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr));
        for (key, value) in &manifest.config {
            cmd.env(format!("SIDECAR_CFG_{}", env_key(key)), value);
        }
        // The sample reads this one by its unprefixed name; `upstream` also
        // arrives as `SIDECAR_CFG_UPSTREAM` above, which is harmless and keeps
        // "every config entry is an env var" true.
        if let Some(upstream) = manifest.config.get("upstream") {
            cmd.env("SIDECAR_UPSTREAM", upstream);
        }

        let child = cmd.spawn().map_err(|e| {
            anyhow::anyhow!(
                "sidecar_spawn_failed{{{}}}: {}: {e} (log: {})",
                manifest.mount,
                program.display(),
                log_path.display()
            )
        })?;
        let sidecar = Self {
            mount: manifest.mount.clone(),
            port,
            token,
            child: Some(child),
            log_path,
        };
        // A gate that fails drops `sidecar`, whose `Drop` kills the child: a
        // sidecar never survives a refused session.
        if let Err(e) = wait_healthy(port, &manifest.health) {
            bail!("sidecar_unhealthy{{{}}}: {e}", manifest.mount);
        }
        Ok(sidecar)
    }

    /// This sidecar's registry entry: mount, loopback port, facade token.
    pub fn facade_target(&self) -> FacadeTarget {
        FacadeTarget {
            mount: self.mount.clone(),
            port: self.port,
            token: self.token.clone(),
        }
    }

    pub fn mount(&self) -> &str {
        &self.mount
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn log_path(&self) -> &Path {
        &self.log_path
    }

    pub fn pid(&self) -> Option<u32> {
        self.child.as_ref().map(Child::id)
    }
}

impl Drop for Sidecar {
    /// Kill and reap. `wait` is what makes "no orphan" true rather than likely:
    /// `kill` only requests termination, and a sidecar that outlived its session
    /// would still be holding a facade token nobody can revoke.
    fn drop(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        let _ = child.kill();
        let _ = child.wait();
    }
}

/// `config` key to its env suffix: uppercase, every non-alphanumeric byte `_`.
fn env_key(key: &str) -> String {
    key.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect()
}

/// A per-session facade token: 32 lowercase hex characters from CNG.
///
/// Deliberately NOT the session's `RunToken`: the workload holds that one, and
/// the whole point of this value is that the workload cannot present it.
fn facade_token() -> Result<String> {
    let mut buf = [0u8; FACADE_TOKEN_BYTES];
    // SAFETY: same call shape as `net::token::random_hex` — the system-preferred
    // RNG with no algorithm handle, filling a valid `&mut [u8]`. Thread-safe.
    unsafe {
        BCryptGenRandom(None, &mut buf, BCRYPT_USE_SYSTEM_PREFERRED_RNG)
            .ok()
            .context("facade_token_unavailable: BCryptGenRandom failed")?;
    }
    let mut out = String::with_capacity(FACADE_TOKEN_BYTES * 2);
    for b in buf {
        out.push_str(&format!("{b:02x}"));
    }
    Ok(out)
}

/// A free loopback port for one sidecar.
///
/// **Accepted TOCTOU, and why it is acceptable:** the listener is dropped before
/// the sidecar binds, so another process on this host could take the port in
/// between. The failure mode is a sidecar that cannot bind, which fails its
/// health gate and refuses the session *by name* (exit 5) — never a session that
/// silently routes nowhere. Closing the window would mean handing the child a
/// pre-bound socket over an inheritable handle, which `python sidecar.py` cannot
/// accept, so the POC takes the window and reports it here rather than pretending
/// the port is reserved.
fn free_loopback_port() -> Result<u16> {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .context("sidecar_port_unavailable: cannot bind a loopback port")?;
    let port = listener
        .local_addr()
        .context("sidecar_port_unavailable: bound socket has no address")?
        .port();
    drop(listener);
    Ok(port)
}

/// Resolve `command[0]` the way a shell would name it, without using a shell.
///
/// Bare names get `PATHEXT`'s executable extensions (`.exe` first, then the batch
/// ones), searched through `PATH`. A candidate that IS a batch file is refused:
/// running it needs `cmd /c`, which is a parser, and this POC has none.
fn resolve_program(program: &str) -> Result<PathBuf> {
    let name = program.trim();
    if name.is_empty() {
        bail!("sidecar_command_not_found: `command[0]` is empty");
    }
    let looks_like_path = name.contains('\\') || name.contains('/');
    let attempts: Vec<String> = if looks_like_path || Path::new(name).extension().is_some() {
        vec![name.to_string()]
    } else {
        vec![
            format!("{name}.exe"),
            format!("{name}.cmd"),
            format!("{name}.bat"),
            name.to_string(),
        ]
    };
    let dirs: Vec<PathBuf> = if looks_like_path {
        vec![PathBuf::new()]
    } else {
        std::env::var_os("PATH")
            .map(|p| std::env::split_paths(&p).collect())
            .unwrap_or_default()
    };
    for dir in &dirs {
        for attempt in &attempts {
            let candidate = dir.join(attempt);
            if !candidate.is_file() {
                continue;
            }
            if is_batch(&candidate) {
                bail!(
                    "sidecar_command_not_exe: {} is a batch entry point; the POC spawns no \
                     shell — point `command[0]` at a real executable",
                    candidate.display()
                );
            }
            return Ok(candidate);
        }
    }
    bail!(
        "sidecar_command_not_found: `{program}` is not on PATH as an executable \
         (PATHEXT `.exe` is applied; `.cmd`/`.bat` are refused)"
    )
}

fn is_batch(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("cmd") || e.eq_ignore_ascii_case("bat"))
}

/// The sidecar's log, under `%LOCALAPPDATA%\sandbox\sidecar-logs`.
///
/// Both halves of the file name are sanitised: `--sid` is operator input and a
/// mount is a validated label, but a log path is a filesystem write and neither
/// should be able to address a different directory.
fn sidecar_log_path(sid: &str, mount: &str) -> Result<PathBuf> {
    let local = std::env::var_os("LOCALAPPDATA")
        .context("sidecar_log_unavailable: LOCALAPPDATA is not set")?;
    let dir = PathBuf::from(local).join("sandbox").join("sidecar-logs");
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("sidecar_log_unavailable: create {}", dir.display()))?;
    let stem = format!("{}-{}", sanitize(sid), sanitize(mount));
    Ok(dir.join(format!("{stem}.log")))
}

fn sanitize(part: &str) -> String {
    part.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn open_log(path: &Path) -> Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("sidecar_log_unavailable: {}", path.display()))
}

/// Poll the health probe until it answers 2xx or the budget runs out.
fn wait_healthy(port: u16, health: &HealthSpec) -> Result<()> {
    let deadline = Instant::now() + Duration::from_millis(health.timeout_ms);
    loop {
        // The LAST failure is the one worth reporting: a sidecar that was not
        // listening yet fails with a connect error, one that listens but is not
        // ready fails with its status line.
        let err = match probe_health(port, &health.path) {
            Ok(()) => return Ok(()),
            Err(e) => format!("{e:#}"),
        };
        if Instant::now() >= deadline {
            bail!(
                "no 2xx from GET {} within {} ms (last: {err})",
                health.path,
                health.timeout_ms
            );
        }
        std::thread::sleep(Duration::from_millis(health.interval_ms.max(1)));
    }
}

/// One `GET <path> HTTP/1.0` and its status line. Any `2xx` is healthy; the body
/// is never read, because the gate is about readiness, not content.
fn probe_health(port: u16, path: &str) -> Result<()> {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let mut sock = TcpStream::connect_timeout(&addr, Duration::from_millis(500))
        .with_context(|| format!("connect 127.0.0.1:{port}"))?;
    sock.set_read_timeout(Some(Duration::from_secs(2)))?;
    sock.set_write_timeout(Some(Duration::from_secs(2)))?;
    sock.write_all(format!("GET {path} HTTP/1.0\r\nHost: localhost\r\n\r\n").as_bytes())
        .context("write health probe")?;
    let mut line = String::new();
    BufReader::new(sock)
        .read_line(&mut line)
        .context("read health status line")?;
    let status = line.split_whitespace().nth(1).unwrap_or("");
    if status.len() == 3 && status.starts_with('2') {
        return Ok(());
    }
    bail!("status line `{}`", line.trim_end())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn nanos() -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    }

    /// One blocking request/response round-trip; the responder closes, so
    /// `read_to_end` ends at the close. The timeout bounds a hung handler.
    fn exchange(port: u16, request: &str) -> String {
        use std::io::Read;
        let mut s = TcpStream::connect(("127.0.0.1", port)).expect("connect the session proxy");
        s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        s.set_write_timeout(Some(Duration::from_secs(10))).unwrap();
        s.write_all(request.as_bytes()).expect("write request");
        let mut out = Vec::new();
        let _ = s.read_to_end(&mut out);
        String::from_utf8_lossy(&out).into_owned()
    }

    #[test]
    fn config_keys_become_upper_snake_env_names() {
        assert_eq!(env_key("upstream"), "UPSTREAM");
        assert_eq!(env_key("api-base"), "API_BASE");
        assert_eq!(env_key("a.b"), "A_B");
    }

    #[test]
    fn log_file_names_cannot_address_another_directory() {
        assert_eq!(sanitize("../../x"), "______x");
        assert_eq!(sanitize("20261023-011500-00042"), "20261023-011500-00042");
    }

    #[test]
    fn a_bare_program_is_resolved_through_pathext() {
        let exe = resolve_program("cmd").expect("cmd.exe is on PATH on every Windows host");
        assert!(
            exe.to_string_lossy()
                .to_ascii_lowercase()
                .ends_with("cmd.exe"),
            "got {}",
            exe.display()
        );
    }

    #[test]
    fn a_batch_entry_point_is_refused_rather_than_run_through_a_shell() {
        let dir =
            std::env::temp_dir().join(format!("sandbox-sidecar-batch-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let bat = dir.join("run.cmd");
        std::fs::write(&bat, "@echo off\r\n").unwrap();
        let err = resolve_program(&bat.display().to_string())
            .expect_err("a .cmd entry point must be refused");
        assert!(
            err.to_string().contains("sidecar_command_not_exe"),
            "got: {err}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// LIVE (`-- --ignored`): the real `tngtech` plugin, the real proxy, the real
    /// relay, and a real kill.
    ///
    /// Requires (a) the plugin installed at
    /// `%USERPROFILE%\.sandbox\plugins\tngtech\` (copy `plugins/tngtech/` from
    /// this repo there) and (b) **working internet**, because the sidecar fetches
    /// `https://www.tngtech.com/`. Both are LOUD failures on purpose: this leg
    /// never skips, because a leg that silently skips measures nothing.
    ///
    /// Run: `cargo test --bin sandbox plugin:: -- --ignored`
    #[ignore = "starts a real python sidecar; needs the tngtech plugin installed and internet"]
    #[test]
    fn the_tngtech_sidecar_answers_through_the_facade_and_dies_on_drop() {
        use crate::net::intent::{DEFAULT_TTL, IntentRegistry};
        use crate::net::learned::LearnedStore;
        use crate::net::prompt::{
            DialogFn, DialogRequest, DialogUnavailable, PromptConfig, PromptCoordinator,
            PromptPolicy,
        };
        use crate::net::proxy::{self, PromptGate, ProxyConfig};
        use crate::net::token::RunToken;
        use std::sync::Mutex as StdMutex;

        let sid = format!("plugin-live-{}-{}", std::process::id(), nanos());
        let loaded = crate::plugin::load_plugin("tngtech", &[]).expect(
            "the tngtech plugin must be installed under %USERPROFILE%\\.sandbox\\plugins\\tngtech",
        );
        assert_eq!(loaded.manifest.mount, "tngtech");

        // (a) the health gate: `start` returns only after /status answered 2xx.
        let sidecar = Sidecar::start(&loaded.dir, &loaded.manifest, &sid)
            .expect("the sidecar must become healthy");
        let sidecar_port = sidecar.port();
        let log_path = sidecar.log_path().to_path_buf();
        let log = std::fs::read_to_string(&log_path).unwrap_or_default();
        assert!(
            log.contains("listening on 127.0.0.1:"),
            "the sidecar's log must show it started: {log}"
        );

        let registry = Arc::new(crate::plugin::FacadeRegistry::new());
        registry
            .insert(sidecar.facade_target())
            .expect("register the mount");

        let base = std::env::temp_dir().join(format!("sandbox-plugin-live-{sid}"));
        std::fs::create_dir_all(&base).unwrap();
        let learned = Arc::new(StdMutex::new(
            LearnedStore::load_in(&base, Some("plugin-live")).expect("empty learned store"),
        ));
        let dialog: DialogFn = Arc::new(|_: &DialogRequest| Err(DialogUnavailable));
        let prompt = PromptGate {
            enabled: false,
            config: PromptConfig {
                timeout: Duration::ZERO,
                on_unavailable: PromptPolicy::Deny,
            },
            coordinator: Arc::new(PromptCoordinator::with_dialog(dialog)),
            intent: Arc::new(IntentRegistry::new(DEFAULT_TTL)),
            learned,
        };
        let token = RunToken::for_tests(&format!("plugin-live-{}", nanos()));
        let writer = Arc::new(crate::audit::AuditWriter::open(&sid, false).unwrap());
        let handle = proxy::spawn(ProxyConfig {
            session_id: sid.clone(),
            token: token.clone(),
            allow_domain: Vec::new(),
            deny_domain: Vec::new(),
            upstream: None,
            writer,
            prompt,
            facade: Arc::clone(&registry),
        })
        .expect("spawn the session proxy");

        let auth = {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.encode(format!("sandbox:{}", token.value()))
        };

        // (b) and (c): the homepage arrives through the facade.
        let get = format!(
            "GET http://tngtech.sandbox.invalid/ HTTP/1.1\r\nHost: tngtech.sandbox.invalid\r\n\
             Proxy-Authorization: Basic {auth}\r\n\r\n"
        );
        let resp = exchange(handle.port, &get);
        let (head, body) = resp.split_once("\r\n\r\n").expect("a full HTTP response");
        assert!(
            head.starts_with("HTTP/1.0 200 OK"),
            "the sidecar's status line is relayed verbatim: {head}"
        );
        assert!(
            head.to_ascii_lowercase()
                .contains("content-type: text/html"),
            "headers: {head}"
        );
        assert!(
            body.len() > 1000,
            "the whole homepage must arrive, got {} bytes",
            body.len()
        );
        assert!(
            body.contains("<title>"),
            "the relayed body must be the page, not an error: {}",
            &body[..body.len().min(200)]
        );

        // (e) a CONNECT to the facade is refused, and says why.
        let connect = format!(
            "CONNECT tngtech.sandbox.invalid:443 HTTP/1.1\r\nProxy-Authorization: Basic {auth}\r\n\r\n"
        );
        let resp = exchange(handle.port, &connect);
        assert!(resp.starts_with("HTTP/1.1 403"), "got: {resp}");
        assert!(
            resp.contains("facade_requires_http"),
            "the refusal must name the reason: {resp}"
        );

        // The chain records both halves under op=FACADE, and never the token.
        let leaves = std::fs::read_to_string(crate::audit::audit_log_path(&sid))
            .unwrap_or_default()
            .lines()
            .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
            .filter(|v| v["op"] == "FACADE")
            .collect::<Vec<_>>();
        assert!(
            leaves
                .iter()
                .any(|l| l["disposition"] == "allow" && l["mount"] == "tngtech"),
            "expected the allow leaf: {leaves:?}"
        );
        assert!(
            leaves.iter().any(|l| l["reason"] == "facade_requires_http"),
            "expected the CONNECT refusal leaf: {leaves:?}"
        );

        // (d) after Drop the sidecar's port is CLOSED — proven by connecting, not
        // inferred from the drop. The proxy is dropped second, as in a session
        // (sidecars die before the route that points at them).
        drop(sidecar);
        drop(handle);
        let addr = SocketAddr::from(([127, 0, 0, 1], sidecar_port));
        let attempt = TcpStream::connect_timeout(&addr, Duration::from_millis(500));
        assert!(
            attempt.is_err(),
            "the sidecar's port {sidecar_port} must be CLOSED after Drop, but a connect succeeded"
        );

        let _ = std::fs::remove_file(crate::audit::audit_log_path(&sid));
        let _ = std::fs::remove_dir_all(&base);
        let _ = std::fs::remove_file(&log_path);
    }
}
