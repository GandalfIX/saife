//! Where the runner meets a live session: one listener, one mount, one token.
//!
//! Nothing else in `src/runner` knows a session exists. This module is the join: it
//! mints the runner's own facade token, starts the listener `server.rs` serves, and
//! registers `build.sandbox.invalid` in the session's [`FacadeRegistry`] with exactly
//! the operations `server.rs` declares. From then on the workload reaches the runner
//! the way it reaches a plugin — an ordinary proxied `POST http://build.sandbox.invalid/build`
//! — and the proxy's declaration check is the control.
//!
//! Two properties are the reason this is a module rather than twenty lines in `main.rs`:
//!
//! * **The token is not the proxy's.** The workload holds the proxy credential (it rides
//!   the proxy URL), so a runner token that equalled it would let the workload's own
//!   network credential start builds — the one thing T1.4 exists to prevent.
//! * **The teardown is not optional.** A listener with no session is a port nobody
//!   serves; a slot with no session is a container that outlives the sandbox. Both go
//!   away with the [`RunnerWiring`] value, on the clean path *and* on a `?` unwind.

use crate::plugin::{FacadeRegistry, FacadeTarget, Operation};
use crate::runner::server::{self, BuildEngine, RunnerServer, RunnerState};
use anyhow::{Result, bail};
use std::path::Path;
use std::sync::Arc;

/// The facade label the workload names: `http://build.sandbox.invalid/build`.
///
/// One lowercase DNS label under the reserved suffix, which is what
/// [`crate::plugin::facade_mount`] accepts. A plugin that declared the same mount cannot
/// shadow it: the registry refuses the second insert (`facade_mount_taken`) and the
/// session is refused rather than a winner being picked.
pub const MOUNT: &str = "build";

/// Bytes behind the runner token: 128 bits, hex-encoded to 32 characters.
///
/// The same strength as a plugin's facade token, and for the same reason: this value
/// authorises a capability the workload can spend, so it must not be guessable and must
/// not appear in a log ([`FacadeTarget`]'s `Debug` redacts it).
const TOKEN_BYTES: usize = 16;

/// A running runner listener plus the engine behind it, owned by one session.
///
/// Dropping it stops the listener (the accept loop ends when its stop half is dropped)
/// and shuts the engine down (the slot is a container, and invariant 4 says it does not
/// outlive its session).
pub struct RunnerWiring {
    server: RunnerServer,
    engine: Arc<dyn BuildEngine>,
}

impl RunnerWiring {
    /// Start the runner for one session and publish its mount.
    ///
    /// Order matters and is the same one the plugin path uses: the listener binds, then
    /// the mount goes live. A request that lands in between answers `404` (an empty
    /// registry is a fully-closed facade), never a stale allow.
    pub fn start(
        facade: &FacadeRegistry,
        workspace: &Path,
        default_paths: &[String],
        engine: Arc<dyn BuildEngine>,
        proxy_token: Option<&str>,
    ) -> Result<Self> {
        let token = runner_token()?;
        ensure_distinct_token(&token, proxy_token)?;
        let state = Arc::new(RunnerState {
            token: token.clone(),
            workspace: workspace.to_path_buf(),
            // The session profile's `runner.sync.paths`, threaded here the same way the
            // workspace is: the listener is the one place a request meets session policy.
            default_paths: default_paths.to_vec(),
            engine: Arc::clone(&engine),
        });
        let server = server::spawn(state)?;
        let target = FacadeTarget {
            mount: MOUNT.to_string(),
            port: server.port,
            token: server.token.clone(),
            operations: operations(),
        };
        // `?` here drops `server` — the listener stops — and returns before this value
        // exists, so the caller's unwind leaves no thread and no mount behind. A
        // duplicate mount (a plugin already answering for `build`) is the case.
        facade.insert(target)?;
        Ok(RunnerWiring { server, engine })
    }

    /// The loopback port the mount points at. Exposed for the diagnostics line and the
    /// tests; the workload never sees it, because it reaches the mount instead.
    pub fn port(&self) -> u16 {
        self.server.port
    }
}

impl Drop for RunnerWiring {
    fn drop(&mut self) {
        // The listener stops on its own (`RunnerServer`'s stop half goes with it) and
        // the engine is told, because only the engine knows a slot exists. Both run on
        // a `?` unwind exactly as on a clean return.
        self.engine.shutdown();
    }
}

/// The declared surface as facade operations.
///
/// Derived from [`server::OPERATIONS`] rather than written twice: the registry entry is
/// what the proxy checks a request against, and a second hand-written list is how the
/// declaration and the listener drift apart.
fn operations() -> Vec<Operation> {
    server::OPERATIONS
        .iter()
        .map(|(method, path)| Operation {
            method: (*method).to_string(),
            path: (*path).to_string(),
        })
        .collect()
}

/// The runner's own facade credential: 128 random bits, hex.
fn runner_token() -> Result<String> {
    crate::net::token::random_hex(TOKEN_BYTES)
        .map_err(|e| anyhow::anyhow!("runner_token_unavailable: the system RNG refused: {e}"))
}

/// Refuse a runner token that is the session's proxy token (T1.4).
///
/// The workload holds the proxy credential — it rides the proxy URL — so a shared value
/// would let the workload's *network* credential start builds, which is precisely the
/// capability separation the two tokens exist for. A 128-bit random value makes the
/// collision unreachable; the check is here so the invariant is a line of code rather
/// than an assumption about the RNG.
fn ensure_distinct_token(runner: &str, proxy: Option<&str>) -> Result<()> {
    if proxy == Some(runner) {
        bail!(
            "runner_token_shared: the runner's facade token is this session's proxy token - \
             the workload holds that value, so it could start builds with its network credential"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::server::BuildState;
    use std::io::{Read, Write};
    use std::net::TcpStream as StdTcpStream;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    /// An engine that answers the protocol and records its teardown: this module is
    /// about the mount and the lifecycle, so a container would only add failures.
    #[derive(Default)]
    struct Silent {
        shut_down: AtomicBool,
    }

    impl BuildEngine for Silent {
        fn start(&self, _req: crate::runner::BuildRequest) -> Result<String> {
            Ok("b1".to_string())
        }
        fn state(&self, _id: &str) -> Result<BuildState> {
            Ok(BuildState::Running)
        }
        fn lines(&self, _id: &str, _from: usize) -> Result<Vec<String>> {
            Ok(Vec::new())
        }
        fn shutdown(&self) {
            self.shut_down.store(true, Ordering::SeqCst);
        }
    }

    /// Each leg binds a listener and dials it; run in parallel they contend for the same
    /// thread slots and ephemeral ports, which is the flake `server.rs` already
    /// serialises for the same reason.
    static WIRING_TESTS: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn workspace(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "saife-runner-wiring-{label}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("app")).unwrap();
        dir
    }

    fn start(
        label: &str,
        proxy_token: Option<&str>,
    ) -> (RunnerWiring, Arc<Silent>, Arc<FacadeRegistry>, PathBuf) {
        let engine = Arc::new(Silent::default());
        let facade = Arc::new(FacadeRegistry::new());
        let ws = workspace(label);
        let wiring = RunnerWiring::start(
            &facade,
            &ws,
            &[],
            engine.clone() as Arc<dyn BuildEngine>,
            proxy_token,
        )
        .expect("the runner starts");
        (wiring, engine, facade, ws)
    }

    fn send(port: u16, request: &str) -> String {
        let mut stream = None;
        for _ in 0..60 {
            if let Ok(s) = StdTcpStream::connect(("127.0.0.1", port)) {
                stream = Some(s);
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let mut s = stream.unwrap_or_else(|| panic!("connect the runner on port {port}"));
        s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        s.write_all(request.as_bytes()).unwrap();
        let mut out = Vec::new();
        let _ = s.read_to_end(&mut out);
        String::from_utf8_lossy(&out).into_owned()
    }

    /// The wiring's whole output: a mount the proxy can route, pointing at the listener
    /// that was actually bound, with the declaration `server.rs` serves — no more.
    #[test]
    fn the_mount_points_at_the_listener_and_declares_only_the_build_operations() {
        let _serial = WIRING_TESTS.lock().unwrap_or_else(|e| e.into_inner());
        let (wiring, _engine, facade, _ws) = start("mount", Some("proxy-token-0001"));

        assert_eq!(
            crate::plugin::facade_mount("build.sandbox.invalid"),
            Some(MOUNT),
            "the host the workload types must resolve to this mount"
        );

        let target = facade.lookup(MOUNT).expect("the mount is registered");
        assert_eq!(
            target.port,
            wiring.port(),
            "the mount must point at the listener that was bound"
        );
        let declared: Vec<(&str, &str)> = target
            .operations
            .iter()
            .map(|o| (o.method.as_str(), o.path.as_str()))
            .collect();
        assert_eq!(
            declared,
            vec![("POST", "/build"), ("GET", "/build")],
            "the runner's surface is exactly the two declared operations"
        );
    }

    /// T1.4: the runner token is its own credential. The workload holds the proxy token,
    /// so a shared value would let the workload's network credential start builds; and
    /// the listener must refuse the proxy token outright, which is what makes the values
    /// non-interchangeable rather than merely different.
    #[test]
    fn the_runner_token_is_not_the_proxy_token() {
        let _serial = WIRING_TESTS.lock().unwrap_or_else(|e| e.into_inner());
        let proxy = "proxy-token-0123456789abcdef";
        let (wiring, _engine, facade, _ws) = start("token", Some(proxy));

        let target = facade.lookup(MOUNT).expect("registered");
        assert_ne!(
            target.token, proxy,
            "the runner token must not be the session's proxy token"
        );
        assert_eq!(
            target.token.len(),
            TOKEN_BYTES * 2,
            "128 bits, hex: {}",
            target.token.len()
        );

        // The one property that matters at runtime: the credential the workload DOES
        // hold cannot start a build. No body: the listener decides from the head, and an
        // unread body would make Windows reset the connection past the response.
        let refused = send(
            wiring.port(),
            &format!(
                "POST /build HTTP/1.0\r\nX-Facade-Token: {proxy}\r\nContent-Length: 0\r\n\r\n"
            ),
        );
        assert!(
            refused.starts_with("HTTP/1.0 401"),
            "the proxy token must not authenticate at the runner: {refused}"
        );
        assert!(
            refused.contains("runner_token_invalid"),
            "the refusal names what was wrong: {refused}"
        );

        // ... and the runner's own token does work, so the 401 above was about the
        // credential and not about the request.
        let body = r#"{"project":"app","task":"build","profile":"gradle"}"#;
        let accepted = send(
            wiring.port(),
            &format!(
                "POST /build HTTP/1.0\r\nX-Facade-Token: {}\r\nContent-Length: {}\r\n\r\n{body}",
                target.token,
                body.len()
            ),
        );
        assert!(
            accepted.starts_with("HTTP/1.0 202"),
            "the runner's own token starts a build: {accepted}"
        );
    }

    /// Two mechanisms, one contract: the listener stops and the engine is told the
    /// session is over — the second is what removes the slot, and it must happen on
    /// every path, which is why it is `Drop` and not an explicit call in `main`.
    #[test]
    fn ending_the_session_stops_the_listener_and_the_engine() {
        let _serial = WIRING_TESTS.lock().unwrap_or_else(|e| e.into_inner());
        let (wiring, engine, _facade, _ws) = start("teardown", None);
        let port = wiring.port();
        assert!(
            StdTcpStream::connect(("127.0.0.1", port)).is_ok(),
            "the listener answers while the session runs"
        );

        drop(wiring);

        assert!(
            engine.shut_down.load(Ordering::SeqCst),
            "the engine must be shut down when the session ends"
        );
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while std::time::Instant::now() < deadline {
            if StdTcpStream::connect(("127.0.0.1", port)).is_err() {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        panic!("the listener must stop with the session (port {port} still accepts)");
    }

    /// The guard itself, tested where it can be: a 128-bit random value makes a real
    /// collision unreachable, so the refusal is exercised directly rather than through
    /// a session that could never produce one.
    #[test]
    fn a_runner_token_equal_to_the_proxy_token_is_refused_by_name() {
        let err = ensure_distinct_token("same", Some("same"))
            .expect_err("a shared credential must be refused");
        assert!(
            format!("{err:#}").contains("proxy token"),
            "the refusal says which credential it collided with: {err:#}"
        );
        ensure_distinct_token("runner", Some("proxy")).expect("different values are fine");
        ensure_distinct_token("runner", None).expect("a blocked session has no proxy token");
    }
}
