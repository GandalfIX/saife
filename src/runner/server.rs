//! The runner's control surface, as the workload sees it *through the facade*.
//!
//! The workload never dials this listener directly (it cannot: loopback is closed
//! inside a session). The supervisor's proxy relays `http://<mount>.sandbox.invalid/...`
//! to it, so the transport, the token and the audit are the ones the facade already
//! enforces. Two operations, both exact paths — the declaration grammar has no wildcard,
//! which is why the build id travels as a query parameter:

//! ```
//! POST /build                      {"project":"app","task":"build","profile":"gradle"}
//!                                  optional: "paths":["apps/payments","settings.gradle.kts"]
//! GET  /build?id=<build>[&follow=1]   status JSON, or the log stream
//! ```

use crate::runner::{BuildRequest, Result};
use anyhow::Context;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// The declared surface. Both entries are exact `(method, path)` pairs, which is all the
/// facade's declaration check can express today.
pub const OPERATIONS: &[(&str, &str)] = &[("POST", "/build"), ("GET", "/build")];

/// One build's state, as the engine reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuildState {
    Running,
    Succeeded(i32),
    Failed(i32),
    /// The runner stopped the build at its deadline (`limits.workloadTimeoutSecs`).
    ///
    /// Not an exit code: the build did not decide to end, the supervisor did. It is
    /// spelled as its own state so a caller polling `GET /build` can tell a stop
    /// from a compiler's failure without knowing that 124 is `timeout(1)`'s number.
    TimedOut,
    Refused(String),
}

impl BuildState {
    pub fn is_terminal(&self) -> bool {
        !matches!(self, BuildState::Running)
    }

    fn as_json(&self) -> String {
        match self {
            BuildState::Running => "\"running\"".to_string(),
            BuildState::Succeeded(code) => format!("{{\"exited\":{code}}}"),
            BuildState::Failed(code) => format!("{{\"failed\":{code}}}"),
            BuildState::TimedOut => "{\"timed_out\":true}".to_string(),
            BuildState::Refused(why) => format!("{{\"refused\":{}}}", json_str(why)),
        }
    }
}

/// What an engine (Docker today, something else tomorrow) has to provide. The transport
/// and the request validation live above this line, so a fake engine can prove the
/// protocol without a container.
pub trait BuildEngine: Send + Sync {
    /// Start a build; the id is opaque to the workload.
    fn start(&self, req: BuildRequest) -> Result<String>;
    /// Current state of one build.
    fn state(&self, id: &str) -> Result<BuildState>;
    /// Log lines produced after the first `from` lines already delivered.
    fn lines(&self, id: &str, from: usize) -> Result<Vec<String>>;
    /// Release this engine's resources because its session is ending.
    ///
    /// Part of the contract rather than the wiring's business: "a slot dies with its
    /// session" (invariant 4) is something only the engine can keep, and the caller
    /// gets it for free on every path — the wiring's `Drop` runs on a `?` unwind just
    /// as it does on a clean exit. A no-op default, because an engine with nothing to
    /// release should not have to say so.
    fn shutdown(&self) {}
}

pub struct RunnerState {
    /// The facade token this listener requires. Never the session proxy's token: a
    /// build request must not be able to speak HTTP-proxy, and a proxy token must not
    /// be able to start a build.
    pub token: String,
    /// The session workspace every request's `project` is resolved against.
    pub workspace: std::path::PathBuf,
    /// The session profile's `runner.sync.paths`: the copy allow-list a request inherits when
    /// it names none. Empty means the whole project, which is what every caller that never
    /// heard of the field gets.
    pub default_paths: Vec<String>,
    pub engine: Arc<dyn BuildEngine>,
}

/// A running runner listener.
pub struct RunnerServer {
    pub port: u16,
    pub token: String,
    _stop: tokio::sync::oneshot::Sender<()>,
}

/// Bind, serve, and return the port the facade mount should point at.
pub fn spawn(state: Arc<RunnerState>) -> Result<RunnerServer> {
    let (port_tx, port_rx) = std::sync::mpsc::channel();
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let token = state.token.clone();
    std::thread::Builder::new()
        .name("saife-runner".into())
        .spawn(move || {
            let rt = match tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    let _ = port_tx.send(Err(e.to_string()));
                    return;
                }
            };
            rt.block_on(async move {
                let listener = match tokio::net::TcpListener::bind(("127.0.0.1", 0)).await {
                    Ok(l) => l,
                    Err(e) => {
                        let _ = port_tx.send(Err(e.to_string()));
                        return;
                    }
                };
                let port = match listener.local_addr() {
                    Ok(a) => a.port(),
                    Err(e) => {
                        let _ = port_tx.send(Err(e.to_string()));
                        return;
                    }
                };
                let _ = port_tx.send(Ok(port));
                let mut stop_rx = stop_rx;
                loop {
                    tokio::select! {
                        _ = &mut stop_rx => break,
                        accepted = listener.accept() => {
                            let Ok((sock, _)) = accepted else { continue };
                            let state = Arc::clone(&state);
                            tokio::spawn(async move {
                                let _ = handle(sock, state).await;
                            });
                        }
                    }
                }
            });
        })
        .context("runner: spawn the listener thread")?;

    let port = port_rx
        .recv()
        .context("runner: the listener thread died before binding")?
        .map_err(|e| anyhow::anyhow!("runner: bind 127.0.0.1: {e}"))?;
    Ok(RunnerServer {
        port,
        token,
        _stop: stop_tx,
    })
}

async fn handle(mut sock: TcpStream, state: Arc<RunnerState>) -> Result<()> {
    // Head, bounded: this listener is reachable only through the facade, but a bound is
    // still cheaper than trusting the relay.
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() > 16 * 1024 {
            return respond(&mut sock, "431 Request Header Fields Too Large", "", "").await;
        }
        match sock.read(&mut byte).await {
            Ok(0) | Err(_) => return Ok(()),
            Ok(_) => head.push(byte[0]),
        }
    }
    let head = String::from_utf8_lossy(&head).into_owned();
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");

    let mut token = None;
    for line in lines {
        if let Some((k, v)) = line.split_once(':')
            && k.trim().eq_ignore_ascii_case("x-facade-token")
        {
            token = Some(v.trim().to_string());
        }
    }
    if token.as_deref() != Some(state.token.as_str()) {
        return respond(
            &mut sock,
            "401 Unauthorized",
            "WWW-Authenticate: Facade\r\n",
            "runner_token_invalid\n",
        )
        .await;
    }

    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    match (method, path) {
        ("POST", "/build") => {
            let body = read_body(&mut sock, &head).await;
            let mut req = match BuildRequest::parse(&body, &state.workspace) {
                Ok(req) => req,
                Err(e) => {
                    return respond(&mut sock, "400 Bad Request", "", &format!("{e:#}\n")).await;
                }
            };
            // Precedence, decided once, here: the request's list wins entirely; an empty one
            // is "not named", so the profile's `runner.sync.paths` applies; with neither, the
            // whole project travels. Substituting before validation means the profile's
            // entries get the same disk checks as a caller's, not a quieter version.
            if req.paths.is_empty() {
                req.paths = state.default_paths.clone();
            }
            if let Err(e) = req.validate_on_disk(&state.workspace) {
                return respond(&mut sock, "400 Bad Request", "", &format!("{e:#}\n")).await;
            }
            match state.engine.start(req) {
                Ok(id) => {
                    let body = format!("{{\"id\":{}}}\n", json_str(&id));
                    respond(
                        &mut sock,
                        "202 Accepted",
                        "Content-Type: application/json\r\n",
                        &body,
                    )
                    .await
                }
                Err(e) => {
                    respond(
                        &mut sock,
                        "503 Service Unavailable",
                        "",
                        &format!("{e:#}\n"),
                    )
                    .await
                }
            }
        }
        ("GET", "/build") => {
            let id = query
                .split('&')
                .find_map(|p| p.strip_prefix("id="))
                .unwrap_or("")
                .to_string();
            if id.is_empty() {
                return respond(
                    &mut sock,
                    "400 Bad Request",
                    "",
                    "runner_build_id_missing\n",
                )
                .await;
            }
            let follow = query.split('&').any(|p| p == "follow=1");
            match state.engine.state(&id) {
                Ok(state_now) => {
                    if follow {
                        stream_log(&mut sock, &state, &id, state_now).await
                    } else {
                        let body = format!(
                            "{{\"id\":{},\"state\":{}}}\n",
                            json_str(&id),
                            state_now.as_json()
                        );
                        respond(
                            &mut sock,
                            "200 OK",
                            "Content-Type: application/json\r\n",
                            &body,
                        )
                        .await
                    }
                }
                Err(e) => respond(&mut sock, "404 Not Found", "", &format!("{e:#}\n")).await,
            }
        }
        _ => respond(&mut sock, "404 Not Found", "", "runner_operation_unknown\n").await,
    }
}

/// Stream a build's log until it reaches a terminal state. Close-delimited on purpose:
/// the facade relay copies bytes as they arrive, so the workload sees each line when it
/// is produced (measured in S0.1: first byte at 1 ms, last at 20 s).
async fn stream_log(
    sock: &mut TcpStream,
    state: &RunnerState,
    id: &str,
    mut now: BuildState,
) -> Result<()> {
    sock.write_all(b"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\n")
        .await
        .context("runner: write the log head")?;
    let mut from = 0usize;
    loop {
        if let Ok(lines) = state.engine.lines(id, from) {
            for line in lines {
                from += 1;
                if sock.write_all(line.as_bytes()).await.is_err() {
                    return Ok(());
                }
                if !line.ends_with('\n') && sock.write_all(b"\n").await.is_err() {
                    return Ok(());
                }
            }
        }
        if now.is_terminal() {
            let _ = sock
                .write_all(format!("[saife] build {}\n", now.as_json()).as_bytes())
                .await;
            return Ok(());
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        now = match state.engine.state(id) {
            Ok(s) => s,
            Err(_) => return Ok(()),
        };
    }
}

async fn read_body(sock: &mut TcpStream, head: &str) -> Vec<u8> {
    const CAP: usize = 4096;
    let want = head
        .lines()
        .find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.trim()
                .eq_ignore_ascii_case("content-length")
                .then(|| v.trim().parse::<usize>().ok())
                .flatten()
        })
        .unwrap_or(0)
        .min(CAP);
    let mut body = vec![0u8; want];
    let mut got = 0;
    while got < want {
        match sock.read(&mut body[got..]).await {
            Ok(0) | Err(_) => break,
            Ok(n) => got += n,
        }
    }
    body.truncate(got);
    body
}

async fn respond(sock: &mut TcpStream, status: &str, headers: &str, body: &str) -> Result<()> {
    let r = format!(
        "HTTP/1.0 {status}\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = sock.write_all(r.as_bytes()).await;
    Ok(())
}

fn json_str(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_else(|_| "\"\"".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::io::{Read, Write};
    use std::net::TcpStream as StdTcpStream;
    use std::sync::Mutex as StdMutex;
    use std::time::Duration;

    const TOKEN: &str = "runner-token-0123456789abcdef";

    /// CRLF, spelled as escapes: rustc normalises a real line break inside a string
    /// literal to a bare LF, so a head written across source lines reaches the listener
    /// as `\\n\\n` and never terminates - a 20 s hang instead of a
    /// failure. The escapes cannot be mangled by an editor or a formatter.
    const CRLF: &str = "\u{000d}\u{000a}";

    /// An engine that does exactly what a test asks it to: no container, no Docker.
    #[derive(Default)]
    struct FakeEngine {
        builds: StdMutex<HashMap<String, (Vec<String>, BuildState)>>,
        next: StdMutex<usize>,
        /// The last request the listener handed to the engine. The copy list is decided
        /// above the engine, so this is how precedence is asserted without a container.
        last: StdMutex<Option<BuildRequest>>,
    }

    impl FakeEngine {
        fn last_paths(&self) -> Vec<String> {
            self.last
                .lock()
                .unwrap()
                .as_ref()
                .map(|r| r.paths.clone())
                .unwrap_or_default()
        }

        fn push_line(&self, id: &str, line: &str) {
            self.builds
                .lock()
                .unwrap()
                .get_mut(id)
                .expect("known build")
                .0
                .push(line.to_string());
        }
        fn finish(&self, id: &str, state: BuildState) {
            self.builds
                .lock()
                .unwrap()
                .get_mut(id)
                .expect("known build")
                .1 = state;
        }
    }

    impl BuildEngine for FakeEngine {
        fn start(&self, req: BuildRequest) -> Result<String> {
            let mut n = self.next.lock().unwrap();
            *n += 1;
            let id = format!("b{}", *n);
            self.builds
                .lock()
                .unwrap()
                .insert(id.clone(), (vec![], BuildState::Running));
            *self.last.lock().unwrap() = Some(req);
            Ok(id)
        }
        fn state(&self, id: &str) -> Result<BuildState> {
            self.builds
                .lock()
                .unwrap()
                .get(id)
                .map(|(_, s)| s.clone())
                .ok_or_else(|| anyhow::anyhow!("runner: unknown build `{id}`"))
        }
        fn lines(&self, id: &str, from: usize) -> Result<Vec<String>> {
            let map = self.builds.lock().unwrap();
            let (lines, _) = map
                .get(id)
                .ok_or_else(|| anyhow::anyhow!("runner: unknown build `{id}`"))?;
            Ok(lines.iter().skip(from).cloned().collect())
        }
    }

    /// These legs each bind a listener, spawn a thread and dial it; run in parallel they
    /// contend for the same ephemeral ports and thread slots, which showed up as a flaky
    /// one-in-two failure. Serialising them costs well under a second and removes the class.
    static SERVER_TESTS: std::sync::Mutex<()> = std::sync::Mutex::new(());

    struct Harness {
        server: RunnerServer,
        engine: Arc<FakeEngine>,
        dir: std::path::PathBuf,
        _serialised: std::sync::MutexGuard<'static, ()>,
    }

    fn harness() -> Harness {
        harness_with(&[])
    }

    /// The same listener, with the session profile's `runner.sync.paths` as its default.
    fn harness_with(default_paths: &[&str]) -> Harness {
        let guard = SERVER_TESTS.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("saife-runner-{}", std::process::id()));
        // The workspace needs a real project directory: the listener refuses a request whose
        // project does not exist (that is T3.1's disk half).
        std::fs::create_dir_all(dir.join("app")).unwrap();
        let engine = Arc::new(FakeEngine::default());
        let state = Arc::new(RunnerState {
            token: TOKEN.to_string(),
            workspace: dir.clone(),
            default_paths: default_paths.iter().map(|p| p.to_string()).collect(),
            engine: engine.clone(),
        });
        let server = spawn(state).expect("runner listener");
        // Readiness: one round trip that must be answered before any test uses the port.
        // Without it a test can connect in the window between `bind` and the accept loop's
        // first poll, which surfaced as a one-in-ten failure under load.
        for _ in 0..50 {
            if std::net::TcpStream::connect(("127.0.0.1", server.port)).is_ok() {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        Harness {
            server,
            engine,
            dir,
            _serialised: guard,
        }
    }

    /// Connect with a retry: under load (a suite compiles in parallel with its own tests) a
    /// single connect can lose the race with the listener thread. A flake, not a defect.
    fn connect(port: u16) -> StdTcpStream {
        for _ in 0..60 {
            if let Ok(stream) = StdTcpStream::connect(("127.0.0.1", port)) {
                return stream;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("connect runner on port {port}");
    }

    fn send(port: u16, request: &str) -> String {
        let mut s = connect(port);
        s.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
        s.write_all(request.as_bytes()).unwrap();
        let mut out = Vec::new();
        let _ = s.read_to_end(&mut out);
        String::from_utf8_lossy(&out).into_owned()
    }

    fn post_build(port: u16, token: Option<&str>, body: &str) -> String {
        let auth = token
            .map(|t| format!("X-Facade-Token: {t}\r\n"))
            .unwrap_or_default();
        send(
            port,
            &format!(
                "POST /build HTTP/1.0\r\n{auth}Content-Length: {}\r\n\r\n{body}",
                body.len()
            ),
        )
    }

    const GOOD: &str = r#"{"project":"app","task":"build","profile":"gradle"}"#;

    #[test]
    fn a_request_without_the_runner_token_is_refused() {
        let h = harness();
        let resp = post_build(h.server.port, None, GOOD);
        assert!(resp.starts_with("HTTP/1.0 401"), "got: {resp}");
        assert!(resp.contains("runner_token_invalid"), "got: {resp}");

        // ... and a wrong token is refused the same way, including the session proxy's
        // own token shape: the two credentials are not interchangeable.
        let resp = post_build(h.server.port, Some("not-the-token"), GOOD);
        assert!(resp.starts_with("HTTP/1.0 401"), "got: {resp}");
    }

    /// A build the runner stopped at its deadline is not a build that failed: the
    /// verdict is the supervisor's, so it gets its own terminal shape instead of a
    /// magic exit code a caller would have to know (`timeout(1)`'s 124). The log
    /// stream says the same thing in words, but a poller only sees this.
    #[test]
    fn a_timed_out_build_is_terminal_and_says_so() {
        let timed_out = BuildState::TimedOut;
        assert!(timed_out.is_terminal(), "a deadline verdict ends the build");
        assert_eq!(timed_out.as_json(), "{\"timed_out\":true}");
        assert_ne!(
            BuildState::Failed(124).as_json(),
            timed_out.as_json(),
            "a deadline must not be indistinguishable from an exit code"
        );
    }

    #[test]
    fn only_the_declared_operations_exist() {
        let h = harness();
        for (method, path) in [("DELETE", "/build"), ("GET", "/builds"), ("PUT", "/build")] {
            let resp = send(
                h.server.port,
                &format!("{method} {path} HTTP/1.0\r\nX-Facade-Token: {TOKEN}\r\n\r\n"),
            );
            assert!(
                resp.starts_with("HTTP/1.0 404"),
                "{method} {path} got: {resp}"
            );
        }
    }

    /// The exit code reaches the caller through the wire, in the shape the workload
    /// reads: a build that failed says WHICH code failed, and a build the runner stopped
    /// says so instead of borrowing one. Both are the poller's whole view of the outcome.
    #[test]
    fn a_finished_build_reports_its_verdict() {
        let h = harness();
        let resp = post_build(h.server.port, Some(TOKEN), GOOD);
        assert!(resp.contains(r#""b1""#), "got: {resp}");

        h.engine.finish("b1", BuildState::Failed(3));
        let status = send(
            h.server.port,
            &format!("GET /build?id=b1 HTTP/1.0{CRLF}X-Facade-Token: {TOKEN}{CRLF}{CRLF}"),
        );
        assert!(status.starts_with("HTTP/1.0 200"), "got: {status}");
        assert!(
            status.contains(r#""state":{"failed":3}"#),
            "the exit code must survive the protocol: {status}"
        );

        h.engine.finish("b1", BuildState::TimedOut);
        let stopped = send(
            h.server.port,
            &format!("GET /build?id=b1 HTTP/1.0{CRLF}X-Facade-Token: {TOKEN}{CRLF}{CRLF}"),
        );
        assert!(
            stopped.contains(r#""state":{"timed_out":true}"#),
            "a deadline is its own verdict: {stopped}"
        );
    }

    #[test]
    fn a_valid_request_is_accepted_and_answers_with_its_id() {
        let h = harness();
        let resp = post_build(h.server.port, Some(TOKEN), GOOD);
        assert!(resp.starts_with("HTTP/1.0 202"), "got: {resp}");
        assert!(resp.contains(r#"{"id":"b1"}"#), "got: {resp}");

        let status = send(
            h.server.port,
            &format!("GET /build?id=b1 HTTP/1.0\r\nX-Facade-Token: {TOKEN}\r\n\r\n"),
        );
        assert!(status.starts_with("HTTP/1.0 200"), "got: {status}");
        assert!(status.contains("\"state\":\"running\""), "got: {status}");
    }

    #[test]
    fn a_body_that_names_an_image_is_refused_with_the_field() {
        let h = harness();
        let body = r#"{"project":"app","task":"build","profile":"gradle","image":"alpine"}"#;
        let resp = post_build(h.server.port, Some(TOKEN), body);
        assert!(resp.starts_with("HTTP/1.0 400"), "got: {resp}");
        assert!(
            resp.contains("image"),
            "the refusal names the field: {resp}"
        );
    }

    /// Precedence, as the workload sees it: a request's list wins ENTIRELY; one that names
    /// none falls back to the session profile's `runner.sync.paths`; with neither, the
    /// engine gets the empty list that means "the whole project".
    #[test]
    fn the_profile_default_applies_only_when_the_request_names_no_paths() {
        let h = harness_with(&["apps/payments", "settings.gradle.kts"]);
        // The profile's default has to exist on disk, exactly like a request's entry: the
        // listener validates whichever list ended up applying.
        std::fs::create_dir_all(h.dir.join("app").join("apps").join("payments")).unwrap();
        std::fs::create_dir_all(h.dir.join("app").join("apps").join("checkout")).unwrap();
        std::fs::write(
            h.dir.join("app").join("settings.gradle.kts"),
            b"rootProject.name",
        )
        .unwrap();

        let resp = post_build(h.server.port, Some(TOKEN), GOOD);
        assert!(resp.starts_with("HTTP/1.0 202"), "got: {resp}");
        assert_eq!(
            h.engine.last_paths(),
            vec!["apps/payments", "settings.gradle.kts"],
            "a request with no list inherits the profile's"
        );

        let body =
            r#"{"project":"app","task":"build","profile":"gradle","paths":["apps/checkout"]}"#;
        let resp = post_build(h.server.port, Some(TOKEN), body);
        assert!(resp.starts_with("HTTP/1.0 202"), "got: {resp}");
        assert_eq!(
            h.engine.last_paths(),
            vec!["apps/checkout"],
            "the request's list wins entirely - it is not merged with the profile's"
        );
    }

    /// A profile default is validated like a request entry: a session whose `paths` names
    /// something that is not there refuses the build by name instead of quietly copying a
    /// smaller tree than the profile promised.
    #[test]
    fn a_profile_default_that_names_nothing_is_refused_by_name() {
        let h = harness_with(&["apps/nope"]);
        let resp = post_build(h.server.port, Some(TOKEN), GOOD);
        assert!(resp.starts_with("HTTP/1.0 400"), "got: {resp}");
        assert!(
            resp.contains("apps/nope"),
            "the refusal names the entry: {resp}"
        );
    }

    /// The listener is where a bad entry becomes a 400: the lexical half of the policy has
    /// to be reachable from the wire, not only from a unit test on the parser.
    #[test]
    fn a_path_entry_outside_the_project_is_a_400_naming_it() {
        let h = harness();
        let body = r#"{"project":"app","task":"build","profile":"gradle","paths":["../outside"]}"#;
        let resp = post_build(h.server.port, Some(TOKEN), body);
        assert!(resp.starts_with("HTTP/1.0 400"), "got: {resp}");
        assert!(
            resp.contains("../outside"),
            "the refusal names the entry: {resp}"
        );
    }

    /// The point of `follow=1`: lines reach the caller while the build is still running,
    /// not in one lump at the end.
    #[test]
    fn the_log_stream_arrives_while_the_build_runs() {
        let h = harness();
        let resp = post_build(h.server.port, Some(TOKEN), GOOD);
        assert!(resp.contains(r#""b1""#), "got: {resp}");

        let port = h.server.port;
        let (tx, rx) = std::sync::mpsc::channel::<String>();
        std::thread::spawn(move || {
            let mut s = connect(port);
            s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
            s.write_all(
                format!("GET /build?id=b1&follow=1 HTTP/1.0\r\nX-Facade-Token: {TOKEN}\r\n\r\n")
                    .as_bytes(),
            )
            .unwrap();
            let mut buf = [0u8; 512];
            loop {
                match s.read(&mut buf) {
                    Ok(0) | Err(_) => return,
                    Ok(n) => {
                        let text = String::from_utf8_lossy(&buf[..n]).into_owned();
                        if tx.send(text).is_err() {
                            return;
                        }
                    }
                }
            }
        });

        // The build stays running until the test says otherwise, so a line arriving now can
        // only have been streamed. No sleeps: waiting for the event is the assertion.
        h.engine.push_line("b1", "line 1\n");
        // The first read is the response head, so accumulate until the line shows up. The
        // build is still `Running`, which is what makes "arrived now" mean "streamed".
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let mut all = String::new();
        while std::time::Instant::now() < deadline && !all.contains("line 1") {
            match rx.recv_timeout(Duration::from_millis(200)) {
                Ok(text) => all.push_str(&text),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
        assert!(
            all.contains("line 1"),
            "the first line must arrive while the build runs, got: {all:?}"
        );
        let state = h.engine.state("b1").unwrap();
        assert!(
            !state.is_terminal(),
            "the build must still be running when the line arrives"
        );

        h.engine.push_line("b1", "line 2\n");
        let mut more = String::new();
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while std::time::Instant::now() < deadline && !more.contains("line 2") {
            match rx.recv_timeout(Duration::from_millis(200)) {
                Ok(text) => more.push_str(&text),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
        assert!(more.contains("line 2"), "got: {more:?}");
    }
}
