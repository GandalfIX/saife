//! The runner's control surface, as the workload sees it *through the facade*.
//!
//! The workload never dials this listener directly (it cannot: loopback is closed
//! inside a session). The supervisor's proxy relays `http://<mount>.sandbox.invalid/...`
//! to it, so the transport, the token and the audit are the ones the facade already
//! enforces. Two operations, both exact paths — the declaration grammar has no wildcard,
//! which is why the build id travels as a query parameter:

//! ```
//! POST /build                      {"project":"app","task":"build","profile":"gradle"}
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
}

pub struct RunnerState {
    /// The facade token this listener requires. Never the session proxy's token: a
    /// build request must not be able to speak HTTP-proxy, and a proxy token must not
    /// be able to start a build.
    pub token: String,
    /// The session workspace every request's `project` is resolved against.
    pub workspace: std::path::PathBuf,
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
            let req = match BuildRequest::parse(&body, &state.workspace) {
                Ok(req) => req,
                Err(e) => {
                    return respond(&mut sock, "400 Bad Request", "", &format!("{e:#}\n")).await;
                }
            };
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
    use std::time::{Duration, Instant};

    const TOKEN: &str = "runner-token-0123456789abcdef";

    /// An engine that does exactly what a test asks it to: no container, no Docker.
    #[derive(Default)]
    struct FakeEngine {
        builds: StdMutex<HashMap<String, (Vec<String>, BuildState)>>,
        next: StdMutex<usize>,
    }

    impl FakeEngine {
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
            let _ = req;
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

    struct Harness {
        server: RunnerServer,
        engine: Arc<FakeEngine>,
        _dir: std::path::PathBuf,
    }

    fn harness() -> Harness {
        let dir = std::env::temp_dir().join(format!("saife-runner-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let engine = Arc::new(FakeEngine::default());
        let state = Arc::new(RunnerState {
            token: TOKEN.to_string(),
            workspace: dir.clone(),
            engine: engine.clone(),
        });
        let server = spawn(state).expect("runner listener");
        Harness {
            server,
            engine,
            _dir: dir,
        }
    }

    fn send(port: u16, request: &str) -> String {
        // Connect with a retry: on a loaded machine (the first run of a suite is a
        // compile in parallel with the tests) a single connect can lose the race with
        // the listener thread, which is a flake and not a defect.
        let mut s = None;
        for _ in 0..40 {
            match StdTcpStream::connect(("127.0.0.1", port)) {
                Ok(stream) => {
                    s = Some(stream);
                    break;
                }
                Err(_) => std::thread::sleep(Duration::from_millis(50)),
            }
        }
        let mut s = s.expect("connect runner");
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

    /// The point of `follow=1`: lines reach the caller while the build is still running,
    /// not in one lump at the end.
    #[test]
    fn the_log_stream_arrives_while_the_build_runs() {
        let h = harness();
        let resp = post_build(h.server.port, Some(TOKEN), GOOD);
        assert!(resp.contains(r#""b1""#), "got: {resp}");

        h.engine.push_line("b1", "line 1\n");
        let port = h.server.port;
        let started = Instant::now();
        let reader = std::thread::spawn(move || {
            let mut s = StdTcpStream::connect(("127.0.0.1", port)).unwrap();
            s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
            s.write_all(
                format!("GET /build?id=b1&follow=1 HTTP/1.0\r\nX-Facade-Token: {TOKEN}\r\n\r\n")
                    .as_bytes(),
            )
            .unwrap();
            let mut out = Vec::new();
            let mut buf = [0u8; 512];
            while let Ok(n) = s.read(&mut buf) {
                if n == 0 {
                    break;
                }
                out.extend_from_slice(&buf[..n]);
                if String::from_utf8_lossy(&out).contains("line 1") {
                    break;
                }
            }
            out
        });

        // The first line must arrive while the build is still running.
        std::thread::sleep(Duration::from_millis(300));
        let first = reader.join().unwrap();
        assert!(
            String::from_utf8_lossy(&first).contains("line 1"),
            "the first line must be delivered before the build ends: {first:?}"
        );
        assert!(started.elapsed() < Duration::from_secs(5));
    }
}
