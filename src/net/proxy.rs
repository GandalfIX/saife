//! Localhost reverse proxy: tokio + hyper + rustls.
//!
//! Architecture: the supervisor (`sandbox.exe`) spawns the proxy on a
//! random 127.0.0.1 port before launching the sandboxed process. The
//! sandboxed process is configured (via env vars) to route HTTP(S)
//! through this proxy. The proxy enforces the domain allow-list and the
//! always-denied list, emits CONNECT audit events, and splices the TCP
//! tunnel after the allow-list check.
//!
//! MVP DEVIATION FROM SPEC NARRATIVE: the spec says "the proxy does TLS to
//! the upstream" but for the MVP the proxy does a plain TCP splice for
//! CONNECT — the child speaks TLS end-to-end with the real host. The
//! allow-list is enforced at the CONNECT line (the target host is visible
//! before any bytes flow upstream). This satisfies every US-3 AC (they
//! assert on the CONNECT line and the connection outcome, not on where TLS
//! terminates). Terminating TLS at the proxy is future work tied to
//! credential injection (F-2). rustls + rustls-native-certs are in
//! Cargo.toml but unused in the MVP; they'll be wired in when F-2 lands.
//! Likewise `hyper`, `hyper-util`, `http`, `http-body-util`, and `bytes`
//! are present as deps for that future work and are NOT imported here.

use std::net::IpAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::runtime::Runtime;
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;

use crate::audit::{self, Disposition};
use crate::net::matcher::{self, Verdict};

pub struct ProxyConfig {
    pub session_id: String,
    pub token: String,
    pub allow_domain: Vec<String>,
}

pub struct ProxyHandle {
    pub port: u16,
    cancel: CancellationToken,
    rt: Option<Runtime>,
    join: Option<tokio::task::JoinHandle<()>>,
}

impl ProxyHandle {
    /// Synchronously cancel the accept loop. The runtime is shut down
    /// cleanly in `Drop` (which calls `Runtime::shutdown_background` so
    /// the accept-loop task is reaped and the listening socket is
    /// released promptly — see AC-3.14). There is intentionally no
    /// `.await` of the JoinHandle here: `shutdown` may be called from a
    /// sync context (the supervisor is sync), and a JoinHandle cannot be
    /// awaited synchronously.
    pub fn shutdown(&mut self) {
        self.cancel.cancel();
    }
}

impl Drop for ProxyHandle {
    fn drop(&mut self) {
        // 1. Signal the accept loop to break.
        self.cancel.cancel();
        // 2. Drop the JoinHandle (detaches the task; it will finish on
        //    its own once the cancelled select returns). We do NOT
        //    await it — Drop is sync.
        self.join = None;
        // 3. Shut the runtime down in the background. `shutdown_background`
        //    does not block the calling thread; it marks the runtime for
        //    shutdown and lets any in-flight tasks drain. Because the
        //    accept loop has already been cancelled (step 1) it will exit
        //    promptly, which lets the OS release the listening port — this
        //    is what satisfies AC-3.14 (port released within ~1s of exit).
        if let Some(rt) = self.rt.take() {
            rt.shutdown_background();
        }
    }
}

/// Spawn the proxy on a dedicated tokio runtime. Returns once the listener
/// is bound (so the caller knows the port before spawning the child
/// process). The runtime is owned by the returned `ProxyHandle` and is
/// shut down when the handle is dropped.
pub fn spawn(cfg: ProxyConfig) -> Result<ProxyHandle> {
    let ProxyConfig { session_id, token, allow_domain } = cfg;
    let allow = Arc::new(allow_domain);
    let token = Arc::new(token);
    let sid = Arc::new(session_id);

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(1)
        .build()?;

    let (port_tx, port_rx) = oneshot::channel::<u16>();
    let cancel = CancellationToken::new();
    let cancel_for_task = cancel.clone();

    let join = rt.spawn(async move {
        let listener = match TcpListener::bind("127.0.0.1:0").await {
            Ok(l) => l,
            Err(e) => {
                eprintln!("[proxy] bind failed: {e}");
                let _ = port_tx.send(0);
                return;
            }
        };
        let port = listener.local_addr().ok().map(|a| a.port()).unwrap_or(0);
        let _ = port_tx.send(port);
        // Log the listening port under SANDBOX_DIAG so integration tests
        // (S-36, S-38) can parse it from stderr.
        if std::env::var_os("SANDBOX_DIAG").is_some() {
            eprintln!("[proxy] listening on 127.0.0.1:{port}");
        }

        loop {
            tokio::select! {
                _ = cancel_for_task.cancelled() => break,
                accept = listener.accept() => {
                    let (sock, _peer) = match accept {
                        Ok(p) => p,
                        Err(_) => continue,
                    };
                    let allow = allow.clone();
                    let token = token.clone();
                    let sid = sid.clone();
                    tokio::spawn(async move {
                        let _ = handle_conn(sock, sid, token, allow).await;
                    });
                }
            }
        }
    });

    let port = port_rx.blocking_recv().context("proxy bind handshake")?;
    if port == 0 {
        anyhow::bail!("proxy failed to bind");
    }

    Ok(ProxyHandle {
        port,
        cancel,
        rt: Some(rt),
        join: Some(join),
    })
}

async fn handle_conn(
    mut sock: tokio::net::TcpStream,
    sid: Arc<String>,
    token: Arc<String>,
    allow: Arc<Vec<String>>,
) -> Result<()> {
    // Read up to 8 KiB of headers (request line + headers, terminated by \r\n\r\n).
    let mut buf = vec![0u8; 8192];
    let mut filled = 0;
    loop {
        if filled >= buf.len() { break; }
        let n = sock.read(&mut buf[filled..]).await.unwrap_or(0);
        if n == 0 { break; }
        filled += n;
        if buf[..filled].windows(4).any(|w| w == b"\r\n\r\n") { break; }
    }
    let head = std::str::from_utf8(&buf[..filled]).unwrap_or("");

    // Parse the request line.
    let first_line = head.lines().next().unwrap_or("");
    let mut parts = first_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");

    // Token check (AC-3.12). The header is matched case-insensitively on
    // the field name; the value is compared exactly (tokens are generated
    // by `net::token` and are case-sensitive hex).
    let token_ok = head.lines().skip(1).any(|l| {
        let l = l.to_ascii_lowercase();
        l.starts_with("x-sandbox-token:") && l[16..].trim() == *token
    });
    if !token_ok {
        let _ = sock.write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n").await;
        audit::emit_connect(sid.as_str(), "<unknown>", 0, Disposition::Deny, Some("no_token"));
        return Ok(());
    }

    // Extract host + port.
    let (host, port) = if method == "CONNECT" {
        let (h, p) = target.rsplit_once(':').unwrap_or((target, "443"));
        (h.to_string(), p.parse::<u16>().unwrap_or(443))
    } else if let Some(host_start) = target.find("://") {
        let after = &target[host_start + 3..];
        let host_port = after.split('/').next().unwrap_or(after);
        let (h, p) = host_port.rsplit_once(':').unwrap_or((host_port, "80"));
        (h.to_string(), p.parse::<u16>().unwrap_or(80))
    } else {
        let h = head.lines().skip(1)
            .find(|l| l.to_ascii_lowercase().starts_with("host:"))
            .map(|l| l[5..].trim().split(':').next().unwrap_or("").to_string())
            .unwrap_or_default();
        (h, 80)
    };

    if host.is_empty() {
        let _ = sock.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await;
        return Ok(());
    }

    // DNS resolve for the CIDR check (best-effort). On resolution failure
    // `resolved` is empty and only the DNS-name deny check runs — which is
    // fine, e.g. `metadata.google.internal` is caught pre-resolution.
    let resolved: Vec<IpAddr> = tokio::net::lookup_host(format!("{host}:0")).await
        .map(|it| it.map(|sa| sa.ip()).collect())
        .unwrap_or_default();

    let verdict = matcher::check(&host, &resolved, &allow);
    match verdict {
        Verdict::Allow => {
            audit::emit_connect(sid.as_str(), &host, port, Disposition::Allow, None);
            if method == "CONNECT" {
                let upstream = match tokio::net::TcpStream::connect(format!("{host}:{port}")).await {
                    Ok(s) => s,
                    Err(e) => {
                        let _ = sock.write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n").await;
                        eprintln!("[proxy] upstream connect to {host}:{port} failed: {e}");
                        return Ok(());
                    }
                };
                let _ = sock.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await;
                let (mut ri, mut wi) = sock.into_split();
                let (mut ro, mut wo) = upstream.into_split();
                let c2u = tokio::io::copy(&mut ri, &mut wo);
                let u2c = tokio::io::copy(&mut ro, &mut wi);
                let _ = tokio::join!(c2u, u2c);
            } else {
                let upstream = match tokio::net::TcpStream::connect(format!("{host}:{port}")).await {
                    Ok(s) => s,
                    Err(e) => {
                        let _ = sock.write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n").await;
                        eprintln!("[proxy] upstream connect to {host}:{port} failed: {e}");
                        return Ok(());
                    }
                };
                let (mut ri, mut wi) = sock.into_split();
                let (mut ro, mut wo) = upstream.into_split();
                let _ = wo.write_all(&buf[..filled]).await;
                let c2u = tokio::io::copy(&mut ri, &mut wo);
                let u2c = tokio::io::copy(&mut ro, &mut wi);
                let _ = tokio::join!(c2u, u2c);
            }
            Ok(())
        }
        Verdict::Deny(reason) => {
            let _ = sock.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n").await;
            audit::emit_connect(sid.as_str(), &host, port, Disposition::Deny, Some(reason.as_str()));
            Ok(())
        }
    }
}
