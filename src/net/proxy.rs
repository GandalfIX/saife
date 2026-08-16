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
use base64::Engine;
use subtle::ConstantTimeEq;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::runtime::Runtime;
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;

use crate::audit::AuditWriter;
use crate::net::matcher::{self, DenyReason, Verdict};

/// The complete set of valid `source` values for a CONNECT audit event
/// (D-5 taxonomy). Kept as a const so future validation logic and tests
/// share a single source of truth; no production call site consumes it yet
/// (only tests reference it), so it is `#[allow(dead_code)]` until the D-5
/// validator lands.
#[allow(dead_code)]
pub const SOURCES: &[&str] = &[
    "hard-deny",
    "learned",
    "blocklist",
    "allowlist",
    "prompt",
    "unavailable",
    "dns",
    "default",
    "prompt_overload",
];

pub struct ProxyConfig {
    pub session_id: String,
    pub token: String,
    pub allow_domain: Vec<String>,
    /// Domains always denied, checked after hard-deny and before the
    /// allow-list ([G-32, G-33]). Wired in D-3.2; the full prompt/learned-deny
    /// pipeline lands in D-3.6.
    pub deny_domain: Vec<String>,
    pub writer: Arc<AuditWriter>,
}

/// Emit a CONNECT audit leaf directly through the threaded `AuditWriter`
/// (replaces the per-call `audit::emit_connect` wrapper, which opened the
/// writer fresh on each event).
//
// The 8-arg signature is mandated by D-5.1 Step 1 (host, port, disposition,
// reason, source, scope, persisted + writer); folding into a struct would
// diverge from the spec, so the clippy lint is suppressed here only.
#[allow(clippy::too_many_arguments)]
fn emit_connect(
    writer: &AuditWriter,
    host: &str,
    port: u16,
    disposition: &str,
    reason: Option<&str>,
    source: &str,
    scope: Option<&str>,
    persisted: bool,
) -> Result<()> {
    use serde_json::{json, Map};
    let mut e = Map::new();
    e.insert("op".into(), json!("CONNECT"));
    e.insert("host".into(), json!(host));
    e.insert("port".into(), json!(port));
    e.insert("disposition".into(), json!(disposition));
    e.insert("reason".into(), json!(reason));
    e.insert("source".into(), json!(source));
    e.insert("scope".into(), json!(scope));
    e.insert("persisted".into(), json!(persisted));
    writer.append(e)?;
    Ok(())
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
    ///
    /// Not invoked today: `main.rs` drops `ProxyHandle` directly (the
    /// `Drop` impl already cancels the accept loop). Kept for the
    /// graceful-shutdown path that lands with the proxy follow-up.
    #[allow(dead_code)]
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
    // `session_id` is retained in ProxyConfig for diagnostics/future use but
    // is not threaded into handle_conn: the AuditWriter holds the log path.
    let ProxyConfig { session_id: _session_id, token, allow_domain, deny_domain, writer } = cfg;
    let allow = Arc::new(allow_domain);
    let deny = Arc::new(deny_domain);
    let token = Arc::new(token);

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
                    let deny = deny.clone();
                    let token = token.clone();
                    let writer = writer.clone();
                    tokio::spawn(async move {
                        let _ = handle_conn(sock, token, deny, allow, writer).await;
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

/// Check `Proxy-Authorization: Basic <base64(sandbox:token)>` against the
/// session token. Constant-time comparison via `subtle::ConstantTimeEq`.
/// Returns false if the header is missing, malformed, or the token doesn't match.
fn check_proxy_auth(head: &str, expected_token: &str) -> bool {
    // Find the Proxy-Authorization header (case-insensitive).
    let auth_value = head.lines().skip(1).find_map(|l| {
        // Match the header name case-insensitively, but slice the *original*
        // line — base64 payload is case-sensitive.
        if l.to_ascii_lowercase().starts_with("proxy-authorization:") {
            Some(l["proxy-authorization:".len()..].trim().to_string())
        } else {
            None
        }
    });

    let Some(auth_value) = auth_value else { return false; };

    // Expect "Basic <base64>" — accept any whitespace (RFC 7230 allows 1*SP).
    let mut parts = auth_value.split_whitespace();
    let scheme = parts.next().unwrap_or("");
    let b64 = parts.next().unwrap_or("");
    if !scheme.eq_ignore_ascii_case("Basic") || b64.is_empty() {
        return false;
    }

    // Decode base64 -> "sandbox:<token>".
    let decoded = match base64::engine::general_purpose::STANDARD.decode(b64) {
        Ok(d) => d,
        Err(_) => return false,
    };
    let decoded_str = match std::str::from_utf8(&decoded) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let (_, password) = decoded_str.split_once(':').unwrap_or(("", ""));

    // Constant-time compare.
    // NOTE: ct_eq leaks length on unequal-length slices; acceptable for a
    // localhost proxy with a fixed-length session token.
    password.as_bytes().ct_eq(expected_token.as_bytes()).into()
}

/// Map a deny reason to the `source` field of the D-5 audit taxonomy.
/// Metadata DNS names and CIDR/literal-IP denies are hard-denies
/// (non-negotiable, built into the binary); a `deny_domain` blocklist match
/// is the `blocklist` source ([G-32]); a host merely absent from the
/// allow-list is the `default` deny (will become `prompt` once the prompt
/// layer in D-3.5 intercepts unlisted hosts).
fn deny_source(reason: DenyReason) -> &'static str {
    match reason {
        DenyReason::DeniedDns | DenyReason::DeniedCidr => "hard-deny",
        DenyReason::DeniedDomain => "blocklist",
        DenyReason::DomainNotAllowed => "default",
    }
}

async fn handle_conn(
    mut sock: tokio::net::TcpStream,
    token: Arc<String>,
    deny: Arc<Vec<String>>,
    allow: Arc<Vec<String>>,
    writer: Arc<AuditWriter>,
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

    // Parse Proxy-Authorization: Basic <base64(sandbox:token)>
    // Standard HTTP clients auto-send this when HTTP_PROXY has userinfo.
    let token_ok = check_proxy_auth(head, &token);
    if !token_ok {
        let _ = sock.write_all(
            b"HTTP/1.1 407 Proxy Authentication Required\r\n\
              Proxy-Authenticate: Basic realm=\"sandbox\"\r\n\
              Content-Length: 0\r\n\r\n"
        ).await;
        let _ = emit_connect(&writer, "<unknown>", 0, "deny", Some("no_token"), "default", None, false);
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

    let verdict = matcher::check(&host, &resolved, &deny, &allow);
    match verdict {
        Verdict::Allow => {
            let _ = emit_connect(&writer, &host, port, "allow", None, "allowlist", None, false);
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
            let _ = emit_connect(
                &writer,
                &host,
                port,
                "deny",
                Some(reason.as_str()),
                deny_source(reason),
                None,
                false,
            );
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_head(auth: &str) -> String {
        format!("CONNECT api.example.com:443 HTTP/1.1\r\nProxy-Authorization: {auth}\r\n\r\n")
    }

    #[test]
    fn valid_basic_auth() {
        let token = "abc123";
        let creds = base64::engine::general_purpose::STANDARD.encode(format!("sandbox:{token}"));
        let head = make_head(&format!("Basic {creds}"));
        assert!(check_proxy_auth(&head, token));
    }

    #[test]
    fn missing_auth_header() {
        let head = "CONNECT api.example.com:443 HTTP/1.1\r\nHost: api.example.com\r\n\r\n";
        assert!(!check_proxy_auth(head, "abc123"));
    }

    #[test]
    fn wrong_token() {
        let creds = base64::engine::general_purpose::STANDARD.encode("sandbox:wrong");
        let head = make_head(&format!("Basic {creds}"));
        assert!(!check_proxy_auth(&head, "abc123"));
    }

    #[test]
    fn wrong_scheme() {
        let creds = base64::engine::general_purpose::STANDARD.encode("sandbox:abc123");
        let head = make_head(&format!("Bearer {creds}"));
        assert!(!check_proxy_auth(&head, "abc123"));
    }

    #[test]
    fn case_insensitive_header_name() {
        let token = "abc123";
        let creds = base64::engine::general_purpose::STANDARD.encode(format!("sandbox:{token}"));
        let head = format!("CONNECT x:443 HTTP/1.1\r\nproxy-AUTHORIZATION: Basic {creds}\r\n\r\n");
        assert!(check_proxy_auth(&head, token));
    }

    fn temp_sid(label: &str) -> String {
        format!(
            "test-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        )
    }

    #[test]
    fn emit_connect_writes_source_scope_persisted() {
        let sid = temp_sid("src-emit");
        let writer = crate::audit::AuditWriter::open(&sid, false).unwrap();
        emit_connect(
            &writer,
            "api.anthropic.com",
            443,
            "allow",
            None,
            "allowlist",
            None,
            false,
        )
        .unwrap();
        let path = crate::audit::audit_log_path(&sid);
        let content = std::fs::read_to_string(&path).unwrap();
        let _ = std::fs::remove_file(&path);

        let line = content.trim_end().lines().next().expect("one event line");
        let v: serde_json::Value = serde_json::from_str(line).unwrap();
        assert_eq!(v["op"], "CONNECT");
        assert_eq!(v["disposition"], "allow");
        assert_eq!(v["source"], "allowlist");
        assert_eq!(v["scope"], serde_json::Value::Null);
        assert_eq!(v["persisted"], false);
    }

    #[test]
    fn emit_connect_scope_null_when_none() {
        let sid = temp_sid("src-null");
        let writer = crate::audit::AuditWriter::open(&sid, false).unwrap();
        emit_connect(
            &writer,
            "evil.example.com",
            443,
            "deny",
            Some("domain_not_allowed"),
            "default",
            None,
            false,
        )
        .unwrap();
        let path = crate::audit::audit_log_path(&sid);
        let content = std::fs::read_to_string(&path).unwrap();
        let _ = std::fs::remove_file(&path);

        let line = content.trim_end().lines().next().unwrap();
        let v: serde_json::Value = serde_json::from_str(line).unwrap();
        // Option<&str>::None serializes to JSON null, not the string "null".
        assert!(v.get("scope").is_some(), "scope key present");
        assert_eq!(v["scope"], serde_json::Value::Null);
    }

    #[test]
    fn emit_connect_persisted_true_serializes_as_boolean() {
        let sid = temp_sid("src-persisted");
        let writer = crate::audit::AuditWriter::open(&sid, false).unwrap();
        emit_connect(
            &writer,
            "api.anthropic.com",
            443,
            "allow",
            None,
            "allowlist",
            Some("session-42"),
            true,
        )
        .unwrap();
        let path = crate::audit::audit_log_path(&sid);
        let content = std::fs::read_to_string(&path).unwrap();
        let _ = std::fs::remove_file(&path);

        let line = content.trim_end().lines().next().unwrap();
        let v: serde_json::Value = serde_json::from_str(line).unwrap();
        // persisted must be a JSON boolean true, not the string "true".
        assert!(v["persisted"].is_boolean());
        assert_eq!(v["persisted"], true);
        assert_eq!(v["scope"], "session-42");
    }

    #[test]
    fn sources_const_is_complete_and_contains_default() {
        // References SOURCES so it isn't flagged dead_code; also pins the
        // D-5 taxonomy so an accidental rename or drop is caught.
        assert!(SOURCES.contains(&"default"));
        assert!(SOURCES.contains(&"allowlist"));
        assert!(SOURCES.contains(&"hard-deny"));
        assert_eq!(
            SOURCES,
            &[
                "hard-deny",
                "learned",
                "blocklist",
                "allowlist",
                "prompt",
                "unavailable",
                "dns",
                "default",
                "prompt_overload",
            ]
        );
    }

    #[test]
    fn deny_source_maps_reasons_to_taxonomy() {
        assert_eq!(deny_source(DenyReason::DeniedDns), "hard-deny");
        assert_eq!(deny_source(DenyReason::DeniedCidr), "hard-deny");
        assert_eq!(deny_source(DenyReason::DeniedDomain), "blocklist");
        assert_eq!(deny_source(DenyReason::DomainNotAllowed), "default");
    }
}
