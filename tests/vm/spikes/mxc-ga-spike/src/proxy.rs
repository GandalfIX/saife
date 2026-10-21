//! Minimal HTTP `CONNECT` proxy with **real forwarding** (spike-grade).
//!
//! Differences from the original dummy listener:
//!   * parses `CONNECT host:port`, resolves and dials the target **on this side**,
//!   * answers `200 Connection Established` only after the origin TCP connect
//!     succeeded, then splices bytes in both directions,
//!   * every accepted connection is recorded as a `Session` tagged with the
//!     launch *epoch* it arrived in, so a run's traffic can be attributed to that
//!     run (guardrail 1 structurally cannot be satisfied by an earlier run),
//!   * binds 127.0.0.1 only, and refuses `CONNECT` to loopback targets so the
//!     proxy cannot be used as a tunnel back into host services (D-1 [G-44]).
//!
//! Deliberately NOT here: allow/deny pipeline, DNS pinning/Happy Eyeballs,
//! prompt, learned store, proxy auth. Those stay in our product proxy (D-1..D-4).

use std::io::{ErrorKind, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const HEAD_LIMIT: usize = 8 * 1024;
const HEAD_TIMEOUT: Duration = Duration::from_secs(5);
const DIAL_BUDGET: Duration = Duration::from_secs(10);
const PER_ADDR_TIMEOUT: Duration = Duration::from_secs(5);
const TUNNEL_IO_TIMEOUT: Duration = Duration::from_secs(20);
const TUNNEL_BUDGET: Duration = Duration::from_secs(40);
const MAX_CONCURRENT: usize = 16;
const MAX_TUNNEL_BYTES: u64 = 8 * 1024 * 1024;
const ACCEPT_DEADLINE: Duration = Duration::from_secs(600);

#[derive(Clone, Debug)]
pub struct Session {
    pub id: u64,
    pub epoch: u64,
    pub peer: String,
    pub request_line: String,
    pub target: String,
    pub resolved: String,
    pub established: bool,
    pub status: String,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub elapsed_ms: u128,
}

impl Session {
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "id": self.id,
            "epoch": self.epoch,
            "peer": self.peer,
            "requestLine": self.request_line,
            "target": self.target,
            "resolved": self.resolved,
            "established": self.established,
            "status": self.status,
            "bytesUp": self.bytes_up,
            "bytesDown": self.bytes_down,
            "elapsedMs": self.elapsed_ms,
        })
    }
}

struct Inner {
    sessions: Vec<Session>,
    accepts: u64,
}

struct Ctx {
    inner: Mutex<Inner>,
    epoch: AtomicU64,
    active: AtomicU64,
    stop: AtomicBool,
    allowed: Vec<String>,
}

pub struct Proxy {
    pub port: u16,
    ctx: Arc<Ctx>,
    join: Option<std::thread::JoinHandle<()>>,
}

impl Proxy {
    pub fn endpoint(&self) -> String {
        format!("127.0.0.1:{}", self.port)
    }

    /// Open a new attribution epoch. Every session accepted after this call is
    /// tagged with the returned value; guardrail 1 only counts sessions of the
    /// epoch it opened for the launch it is gating.
    pub fn begin_run(&self) -> u64 {
        self.ctx.epoch.fetch_add(1, Ordering::SeqCst) + 1
    }

    pub fn sessions(&self, epoch: u64) -> Vec<Session> {
        self.ctx
            .inner
            .lock()
            .unwrap()
            .sessions
            .iter()
            .filter(|s| s.epoch == epoch)
            .cloned()
            .collect()
    }

    pub fn accepts_total(&self) -> u64 {
        self.ctx.inner.lock().unwrap().accepts
    }

    pub fn stop(&mut self) {
        self.ctx.stop.store(true, Ordering::SeqCst);
        // Wake the blocking accept() with one throwaway connection instead of
        // polling on a sleep. The accept loop sees `stop` and exits.
        let _ = TcpStream::connect_timeout(
            &SocketAddr::from(([127, 0, 0, 1], self.port)),
            Duration::from_secs(2),
        );
        if let Some(h) = self.join.take() {
            let _ = h.join();
        }
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        self.stop();
    }
}

fn now_ms(start: Instant) -> u128 {
    start.elapsed().as_millis()
}

pub fn start(allowed: Vec<String>) -> std::io::Result<Proxy> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    listener.set_nonblocking(false)?;

    let ctx = Arc::new(Ctx {
        inner: Mutex::new(Inner {
            sessions: Vec::new(),
            accepts: 0,
        }),
        epoch: AtomicU64::new(0),
        active: AtomicU64::new(0),
        stop: AtomicBool::new(false),
        allowed,
    });

    let ctx_t = Arc::clone(&ctx);
    let join = std::thread::spawn(move || {
        let deadline = Instant::now() + ACCEPT_DEADLINE;
        let mut next_id: u64 = 0;
        while Instant::now() < deadline {
            let (stream, peer) = match listener.accept() {
                Ok(v) => v,
                Err(_) => break,
            };
            if ctx_t.stop.load(Ordering::SeqCst) {
                break;
            }
            next_id += 1;
            let id = next_id;
            let epoch = ctx_t.epoch.load(Ordering::SeqCst);
            if ctx_t.active.load(Ordering::SeqCst) as usize >= MAX_CONCURRENT {
                let mut s = stream;
                let _ = s.write_all(
                    b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                );
                continue;
            }
            {
                let mut inner = ctx_t.inner.lock().unwrap();
                inner.accepts += 1;
                inner.sessions.push(Session {
                    id,
                    epoch,
                    peer: peer.to_string(),
                    request_line: String::new(),
                    target: String::new(),
                    resolved: String::new(),
                    established: false,
                    status: "accepted".to_string(),
                    bytes_up: 0,
                    bytes_down: 0,
                    elapsed_ms: 0,
                });
            }
            ctx_t.active.fetch_add(1, Ordering::SeqCst);
            let ctx_h = Arc::clone(&ctx_t);
            std::thread::spawn(move || {
                handle(stream, peer, ctx_h, id);
            });
        }
    });

    Ok(Proxy {
        port,
        ctx,
        join: Some(join),
    })
}

fn update<F: FnOnce(&mut Session)>(ctx: &Ctx, id: u64, f: F) {
    let mut inner = ctx.inner.lock().unwrap();
    if let Some(s) = inner.sessions.iter_mut().find(|s| s.id == id) {
        f(s);
    }
}

fn read_head(stream: &mut TcpStream) -> std::io::Result<(String, Vec<u8>)> {
    let deadline = Instant::now() + HEAD_TIMEOUT;
    let mut buf: Vec<u8> = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    loop {
        if let Some(pos) = find_double_crlf(&buf) {
            let head = String::from_utf8_lossy(&buf[..pos + 4]).to_string();
            let rest = buf[pos + 4..].to_vec();
            return Ok((head, rest));
        }
        if buf.len() >= HEAD_LIMIT {
            return Err(std::io::Error::new(ErrorKind::InvalidData, "head too large"));
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(std::io::Error::new(ErrorKind::TimedOut, "head timeout"));
        }
        stream.set_read_timeout(Some(remaining.min(HEAD_TIMEOUT)))?;
        match stream.read(&mut chunk) {
            Ok(0) => return Err(std::io::Error::new(ErrorKind::UnexpectedEof, "eof in head")),
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {
                return Err(std::io::Error::new(ErrorKind::TimedOut, "head timeout"))
            }
            Err(e) => return Err(e),
        }
    }
}

fn find_double_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn respond(stream: &mut TcpStream, code: u16, reason: &str, body: &str) {
    let head = format!(
        "HTTP/1.1 {code} {reason}\r\nX-Sandbox: {}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        if code == 200 { "allowed" } else { "denied" },
        body.len()
    );
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(body.as_bytes());
    let _ = stream.flush();
}

fn is_loopback_host(host: &str) -> bool {
    let h = host.trim_matches(['[', ']']).to_ascii_lowercase();
    if h == "localhost" || h.ends_with(".localhost") || h == "::1" || h == "0.0.0.0" {
        return true;
    }
    if let Ok(ip) = h.parse::<std::net::IpAddr>() {
        return match ip {
            std::net::IpAddr::V4(v4) => v4.is_loopback() || v4.is_unspecified(),
            std::net::IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified(),
        };
    }
    false
}

fn split_host_port(target: &str) -> Option<(String, u16)> {
    if let Some(rest) = target.strip_prefix('[') {
        // [::1]:443
        let (host, tail) = rest.split_once(']')?;
        let port = tail.strip_prefix(':')?.parse().ok()?;
        return Some((host.to_string(), port));
    }
    let (host, port) = target.rsplit_once(':')?;
    if host.contains(':') {
        // bare IPv6 without brackets: ambiguous, refuse
        return None;
    }
    Some((host.to_string(), port.parse().ok()?))
}

fn dial(host: &str, port: u16) -> Result<(TcpStream, String), (String, String)> {
    let deadline = Instant::now() + DIAL_BUDGET;
    let addrs: Vec<SocketAddr> = match (host, port).to_socket_addrs() {
        Ok(it) => it.take(4).collect(),
        Err(e) => return Err((format!("resolve_failed: {e}"), String::new())),
    };
    if addrs.is_empty() {
        return Err(("no_addresses".to_string(), String::new()));
    }
    let mut last = String::new();
    for addr in &addrs {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            last = "dial_budget_exhausted".to_string();
            break;
        }
        match TcpStream::connect_timeout(addr, remaining.min(PER_ADDR_TIMEOUT)) {
            Ok(s) => return Ok((s, addr.to_string())),
            Err(e) => last = format!("{addr}: {e}"),
        }
    }
    Err((format!("dial_failed: {last}"), addrs[0].to_string()))
}

fn splice(mut from: TcpStream, mut to: TcpStream, counter: Arc<AtomicU64>, done: mpsc::Sender<()>) {
    let mut buf = [0u8; 16 * 1024];
    loop {
        match from.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if counter.load(Ordering::Relaxed) + n as u64 > MAX_TUNNEL_BYTES {
                    break;
                }
                if to.write_all(&buf[..n]).is_err() {
                    break;
                }
                let _ = to.flush();
                counter.fetch_add(n as u64, Ordering::Relaxed);
            }
            Err(_) => break,
        }
    }
    let _ = done.send(());
}

fn handle(mut client: TcpStream, peer: SocketAddr, ctx: Arc<Ctx>, id: u64) {
    let started = Instant::now();
    let _ = client.set_write_timeout(Some(TUNNEL_IO_TIMEOUT));

    let (head, leftover) = match read_head(&mut client) {
        Ok(v) => v,
        Err(e) => {
            update(&ctx, id, |s| {
                s.status = format!("head_error: {e}");
                s.elapsed_ms = now_ms(started);
            });
            ctx.active.fetch_sub(1, Ordering::SeqCst);
            return;
        }
    };
    let first_line = head.lines().next().unwrap_or("").trim().to_string();
    update(&ctx, id, |s| s.request_line = first_line.clone());

    let mut parts = first_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_ascii_uppercase();
    let target = parts.next().unwrap_or("").to_string();
    if method != "CONNECT" || target.is_empty() {
        respond(&mut client, 405, "Method Not Allowed", "only CONNECT is supported\n");
        update(&ctx, id, |s| {
            s.status = "rejected_method".to_string();
            s.elapsed_ms = now_ms(started);
        });
        ctx.active.fetch_sub(1, Ordering::SeqCst);
        return;
    }
    update(&ctx, id, |s| s.target = target.clone());

    let (host, port) = match split_host_port(&target) {
        Some(v) => v,
        None => {
            respond(&mut client, 400, "Bad Request", "CONNECT target must be host:port\n");
            update(&ctx, id, |s| {
                s.status = "rejected_target".to_string();
                s.elapsed_ms = now_ms(started);
            });
            ctx.active.fetch_sub(1, Ordering::SeqCst);
            return;
        }
    };

    if is_loopback_host(&host) {
        respond(
            &mut client,
            403,
            "Forbidden",
            &format!("CONNECT to loopback target {target} refused by proxy policy\n"),
        );
        update(&ctx, id, |s| {
            s.status = "denied_loopback_target".to_string();
            s.elapsed_ms = now_ms(started);
        });
        ctx.active.fetch_sub(1, Ordering::SeqCst);
        return;
    }

    let key = format!("{}:{}", host.to_ascii_lowercase(), port);
    if !ctx.allowed.iter().any(|a| a.eq_ignore_ascii_case(&key)) {
        respond(
            &mut client,
            403,
            "Forbidden",
            &format!("target {key} not in this spike proxy's allow list\n"),
        );
        update(&ctx, id, |s| {
            s.status = "denied_not_allowed".to_string();
            s.elapsed_ms = now_ms(started);
        });
        ctx.active.fetch_sub(1, Ordering::SeqCst);
        return;
    }

    let (mut origin, resolved) = match dial(&host, port) {
        Ok(v) => v,
        Err((why, first)) => {
            respond(
                &mut client,
                502,
                "Bad Gateway",
                &format!("proxy could not dial {key}: {why}\n"),
            );
            update(&ctx, id, |s| {
                s.status = why;
                s.resolved = first;
                s.elapsed_ms = now_ms(started);
            });
            ctx.active.fetch_sub(1, Ordering::SeqCst);
            return;
        }
    };
    update(&ctx, id, |s| s.resolved = resolved.clone());

    // 200 only after the origin TCP handshake actually succeeded.
    let _ = client.write_all(b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: mxc-ga-spike\r\n\r\n");
    let _ = client.flush();
    if !leftover.is_empty() {
        let _ = origin.write_all(&leftover);
        let _ = origin.flush();
    }
    update(&ctx, id, |s| s.established = true);
    eprintln!(
        "PROXY: session={id} established peer={peer} target={key} resolved={resolved}"
    );

    let _ = client.set_read_timeout(Some(TUNNEL_IO_TIMEOUT));
    let _ = origin.set_read_timeout(Some(TUNNEL_IO_TIMEOUT));
    let _ = origin.set_write_timeout(Some(TUNNEL_IO_TIMEOUT));

    let up = Arc::new(AtomicU64::new(0));
    let down = Arc::new(AtomicU64::new(0));
    let (tx, rx) = mpsc::channel::<()>();

    let (c_in, o_out) = match (client.try_clone(), origin.try_clone()) {
        (Ok(a), Ok(b)) => (a, b),
        _ => {
            update(&ctx, id, |s| {
                s.status = "clone_failed".to_string();
                s.elapsed_ms = now_ms(started);
            });
            ctx.active.fetch_sub(1, Ordering::SeqCst);
            return;
        }
    };
    let up_t = Arc::clone(&up);
    let down_t = Arc::clone(&down);
    let kill_c = client.try_clone();
    let kill_o = origin.try_clone();
    let tx1 = tx.clone();
    let tx2 = tx;
    let t1 = std::thread::spawn(move || splice(c_in, origin, up_t, tx1));
    let t2 = std::thread::spawn(move || splice(o_out, client, down_t, tx2));

    // First direction to finish (EOF, error, or timeout) tears the tunnel down;
    // this is what bounds the splice instead of relying on sleeps.
    let _ = rx.recv_timeout(TUNNEL_BUDGET);
    if let Ok(k) = kill_c {
        let _ = k.shutdown(Shutdown::Both);
    }
    if let Ok(k) = kill_o {
        let _ = k.shutdown(Shutdown::Both);
    }
    let _ = t1.join();
    let _ = t2.join();

    update(&ctx, id, |s| {
        s.status = "tunnel_closed".to_string();
        s.bytes_up = up.load(Ordering::Relaxed);
        s.bytes_down = down.load(Ordering::Relaxed);
        s.elapsed_ms = now_ms(started);
    });
    eprintln!(
        "PROXY: session={id} closed up={} down={}",
        up.load(Ordering::Relaxed),
        down.load(Ordering::Relaxed)
    );
    ctx.active.fetch_sub(1, Ordering::SeqCst);
}
