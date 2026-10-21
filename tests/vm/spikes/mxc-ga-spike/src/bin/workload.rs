//! The workload that runs INSIDE the MXC ProcessContainer.
//!
//! It performs a **real HTTPS request through the caller's CONNECT proxy**:
//!   1. TCP to 127.0.0.1:<proxy> (the only endpoint it ever dials),
//!   2. `CONNECT <host>:443`, expects `200 Connection Established`,
//!   3. TLS handshake (rustls, SNI = host) over that same socket,
//!   4. `GET <path>` and parse the origin status line.
//!
//! The host name is never resolved locally; DNS + TCP to the real origin happen
//! in the proxy (parent) process, outside the container.
//!
//! argv[1] = proxy endpoint as host:port (no scheme).
//! env MXC_SPIKE_TARGET = host:port of the origin (default api.anthropic.com:443)
//! env MXC_SPIKE_PATH   = request path (default "/")

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::{Duration, Instant};

fn env_report(name: &str) -> String {
    match std::env::var(name) {
        Ok(v) => format!("CHILD: env {name}={v}"),
        Err(_) => format!("CHILD: env {name}=<unset>"),
    }
}

fn print_status(status: u16, reason: &str, body_prefix: &str, bytes: usize) {
    println!("CHILD: https_status={status}");
    println!("CHILD: https_reason={reason}");
    println!("CHILD: https_received_bytes={bytes}");
    println!("CHILD: https_body_prefix={body_prefix:?}");
}

/// Send `CONNECT host:port`, verify a 2xx response, return the socket.
fn open_tunnel(mut s: TcpStream, host: &str, port: u16) -> Result<TcpStream, String> {
    let req = format!(
        "CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\nProxy-Connection: keep-alive\r\n\r\n"
    );
    s.set_read_timeout(Some(Duration::from_secs(15)))
        .map_err(|e| format!("set_read_timeout: {e}"))?;
    s.set_write_timeout(Some(Duration::from_secs(10)))
        .map_err(|e| format!("set_write_timeout: {e}"))?;
    s.write_all(req.as_bytes())
        .map_err(|e| format!("connect_write: {e}"))?;
    s.flush().map_err(|e| format!("connect_flush: {e}"))?;

    // Byte-at-a-time so no TLS bytes that follow the head can be swallowed.
    let mut head: Vec<u8> = Vec::with_capacity(256);
    let mut b = [0u8; 1];
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if head.len() >= 8192 {
            return Err("connect_response_head_too_large".into());
        }
        if Instant::now() > deadline {
            return Err("connect_response_timeout".into());
        }
        match s.read(&mut b) {
            Ok(0) => return Err("connect_response_eof".into()),
            Ok(_) => {
                head.push(b[0]);
                if head.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            Err(e) => return Err(format!("connect_response_read: {e}")),
        }
    }
    let text = String::from_utf8_lossy(&head).to_string();
    let first = text.lines().next().unwrap_or("").trim().to_string();
    println!("CHILD: connect_response={first:?}");
    let code = first
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse::<u16>().ok())
        .ok_or_else(|| format!("connect_response_unparsable: {first}"))?;
    if !(200..300).contains(&code) {
        return Err(format!("connect_status={code}"));
    }
    println!("CHILD: connect_tunnel=established");
    Ok(s)
}

fn tls_config() -> Result<Arc<rustls::ClientConfig>, String> {
    let loaded = rustls_native_certs::load_native_certs();
    let mut roots = rustls::RootCertStore::empty();
    let mut added = 0usize;
    for cert in loaded.certs {
        if roots.add(cert).is_ok() {
            added += 1;
        }
    }
    println!(
        "CHILD: tls_roots_loaded={} store_size={} store_errors={}",
        added,
        roots.len(),
        loaded.errors.len()
    );
    if roots.is_empty() {
        return Err("no_usable_root_certificates".into());
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("tls_versions: {e}"))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(cfg))
}

fn https_via_proxy(proxy: SocketAddr, host: &str, port: u16, path: &str) {
    let started = Instant::now();
    let sock = match TcpStream::connect_timeout(&proxy, Duration::from_secs(5)) {
        Ok(s) => s,
        Err(e) => {
            println!(
                "CHILD: proxy_connect=fail peer={proxy} err={e} os_code={:?} kind={:?}",
                e.raw_os_error(),
                e.kind()
            );
            println!("CHILD: proxy_reachable=false");
            println!("CHILD: https_status=none");
            return;
        }
    };
    println!("CHILD: proxy_connect=ok peer={proxy}");
    println!("CHILD: proxy_reachable=true");
    println!(
        "CHILD: proxy_connect_elapsed_ms={}",
        started.elapsed().as_millis()
    );

    let sock = match open_tunnel(sock, host, port) {
        Ok(s) => s,
        Err(e) => {
            println!("CHILD: https_status=none");
            println!("CHILD: https_error=tunnel: {e}");
            return;
        }
    };

    let cfg = match tls_config() {
        Ok(c) => c,
        Err(e) => {
            println!("CHILD: https_status=none");
            println!("CHILD: https_error=tls_config: {e}");
            return;
        }
    };
    let name = match rustls::pki_types::ServerName::try_from(host.to_string()) {
        Ok(n) => n,
        Err(e) => {
            println!("CHILD: https_status=none");
            println!("CHILD: https_error=server_name: {e}");
            return;
        }
    };
    let conn = match rustls::ClientConnection::new(cfg, name) {
        Ok(c) => c,
        Err(e) => {
            println!("CHILD: https_status=none");
            println!("CHILD: https_error=client_connection: {e}");
            return;
        }
    };
    let mut tls = rustls::StreamOwned::new(conn, sock);

    // Handshake + request. Any handshake failure surfaces on the first read/write.
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: mxc-ga-spike/0.0.0\r\nAccept: */*\r\nConnection: close\r\n\r\n"
    );
    if let Err(e) = tls.write_all(req.as_bytes()) {
        println!("CHILD: https_status=none");
        println!("CHILD: https_error=tls_write: {e}");
        println!("CHILD: tls_failure_kind={:?}", e.kind());
        return;
    }
    let _ = tls.flush();

    match (tls.conn.protocol_version(), tls.conn.negotiated_cipher_suite()) {
        (Some(v), Some(cs)) => {
            println!("CHILD: https_tls=ok version={v:?} cipher={:?}", cs.suite());
        }
        _ => println!("CHILD: https_tls=ok version=<unknown>"),
    }
    println!("CHILD: https_sni={host}");

    let mut resp: Vec<u8> = Vec::new();
    let mut buf = [0u8; 8192];
    let deadline = Instant::now() + Duration::from_secs(25);
    loop {
        if resp.len() > 256 * 1024 {
            break;
        }
        if Instant::now() > deadline {
            println!("CHILD: https_read=timeout");
            break;
        }
        match tls.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => resp.extend_from_slice(&buf[..n]),
            Err(e) => {
                println!("CHILD: https_read_err={e} kind={:?}", e.kind());
                break;
            }
        }
    }

    if resp.is_empty() {
        println!("CHILD: https_status=none");
        println!("CHILD: https_error=empty_response");
        return;
    }
    let text = String::from_utf8_lossy(&resp).to_string();
    let first = text.lines().next().unwrap_or("").trim().to_string();
    let mut it = first.split_whitespace();
    let _version = it.next();
    let status = it.next().and_then(|c| c.parse::<u16>().ok());
    let reason = it.collect::<Vec<_>>().join(" ");
    let body_start = text.find("\r\n\r\n").map(|p| p + 4).unwrap_or(0);
    let body: String = text[body_start..]
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(120)
        .collect();
    match status {
        Some(s) => print_status(s, &reason, body.trim(), resp.len()),
        None => {
            println!("CHILD: https_status=none");
            println!("CHILD: https_error=unparsable_status {first:?}");
        }
    }
    println!(
        "CHILD: https_elapsed_ms={}",
        started.elapsed().as_millis()
    );
}

fn main() {
    println!("CHILD: pid={}", std::process::id());
    println!(
        "CHILD: exe={}",
        std::env::current_exe().unwrap_or_default().display()
    );
    println!(
        "CHILD: cwd={}",
        std::env::current_dir().unwrap_or_default().display()
    );

    for name in [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "http_proxy",
        "https_proxy",
        "NO_PROXY",
        "no_proxy",
    ] {
        println!("{}", env_report(name));
    }
    println!(
        "CHILD: env NO_PROXY_BYPASSES_PROXY={:?}",
        std::env::var("NO_PROXY")
            .map(|v| v.contains("127.0.0.1"))
            .unwrap_or(false)
    );

    let proxy_arg = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:1".to_string());
    let target = std::env::var("MXC_SPIKE_TARGET")
        .unwrap_or_else(|_| "api.anthropic.com:443".to_string());
    let path = std::env::var("MXC_SPIKE_PATH").unwrap_or_else(|_| "/".to_string());

    match proxy_arg.parse::<SocketAddr>() {
        Ok(proxy) => {
            let (host, port) = target
                .rsplit_once(':')
                .map(|(h, p)| (h.to_string(), p.parse::<u16>().unwrap_or(443)))
                .unwrap_or_else(|| (target.clone(), 443));
            println!("CHILD: target={host}:{port} path={path}");
            println!(
                "CHILD: target_resolved_locally=false (hostname passed to the proxy verbatim)"
            );
            https_via_proxy(proxy, &host, port, &path);
        }
        Err(e) => {
            println!("CHILD: proxy_addr_parse=fail arg={proxy_arg} err={e}");
            println!("CHILD: https_status=none");
        }
    }

    // ---- Direct egress, raw IP (no DNS dependency): must be denied ----
    let direct: SocketAddr = "1.1.1.1:443".parse().unwrap();
    match TcpStream::connect_timeout(&direct, Duration::from_secs(6)) {
        Ok(_) => println!("CHILD: direct_egress=CONNECTED(!!) peer={direct}"),
        Err(e) => println!(
            "CHILD: direct_egress=blocked peer={direct} err={e} os_code={:?} kind={:?}",
            e.raw_os_error(),
            e.kind()
        ),
    }

    // ---- Direct egress to a public hostname (DNS + connect posture) ----
    match ("example.com", 443u16).to_socket_addrs() {
        Ok(mut addrs) => match addrs.next() {
            Some(addr) => match TcpStream::connect_timeout(&addr, Duration::from_secs(6)) {
                Ok(_) => println!("CHILD: direct_egress_dns=CONNECTED(!!) peer={addr}"),
                Err(e) => println!(
                    "CHILD: direct_egress_dns=blocked peer={addr} err={e} os_code={:?}",
                    e.raw_os_error()
                ),
            },
            None => println!("CHILD: direct_egress_dns=no_addresses"),
        },
        Err(e) => println!(
            "CHILD: dns_resolve=blocked err={e} os_code={:?}",
            e.raw_os_error()
        ),
    }

    // ---- Filesystem probes: granted dir vs ungranted host paths ----
    let scratch = std::env::var("MXC_SPIKE_SCRATCH").unwrap_or_default();
    if !scratch.is_empty() {
        let marker = format!("{scratch}\\child-wrote.txt");
        match std::fs::write(&marker, b"written by the sandboxed child\n") {
            Ok(()) => println!("CHILD: fs_write_granted_path=ok path={marker}"),
            Err(e) => println!("CHILD: fs_write_granted_path=fail path={marker} err={e}"),
        }
        match std::fs::read_to_string(&marker) {
            Ok(_) => println!("CHILD: fs_readback_granted_path=ok"),
            Err(e) => println!("CHILD: fs_readback_granted_path=fail err={e}"),
        }
    }
    if let Ok(canary) = std::env::var("MXC_SPIKE_CANARY") {
        match std::fs::read_to_string(&canary) {
            Ok(_) => println!("CHILD: fs_read_outside_policy=READABLE(!!) path={canary}"),
            Err(e) => println!(
                "CHILD: fs_read_outside_policy=denied path={canary} err={e} kind={:?}",
                e.kind()
            ),
        }
    }
    if let Ok(deny_write) = std::env::var("MXC_SPIKE_DENY_WRITE") {
        let target = format!("{deny_write}\\child-should-not-write.txt");
        match std::fs::write(&target, b"escaped\n") {
            Ok(()) => println!("CHILD: fs_write_outside_policy=WROTE(!!) path={target}"),
            Err(e) => println!(
                "CHILD: fs_write_outside_policy=denied path={target} err={e} kind={:?}",
                e.kind()
            ),
        }
    }
    match std::fs::read_to_string("C:\\Windows\\win.ini") {
        Ok(_) => println!("CHILD: fs_read_windir=READABLE(!)"),
        Err(e) => println!("CHILD: fs_read_windir=denied err={e} kind={:?}", e.kind()),
    }
    println!("CHILD: env USERNAME={:?}", std::env::var("USERNAME").ok());
    println!(
        "CHILD: env USERPROFILE={:?}",
        std::env::var("USERPROFILE").ok()
    );

    println!("CHILD: done");
}
