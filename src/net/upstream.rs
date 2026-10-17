//! Upstream corporate proxy dialer (ADR-0001 §D-2).
//!
//! `UpstreamDialer` chains admitted CONNECT requests through a corporate
//! egress proxy via HTTP `CONNECT` + optional Basic auth, and dials
//! `NO_PROXY`-matched hosts directly through `DirectDialer` (DNS-pinned
//! IPs, Happy Eyeballs — [G-11, G-49]). The two paths are mutually
//! exclusive per request:
//!
//! - `NO_PROXY` hit → direct dial of the admission-time pinned addresses.
//! - otherwise → `CONNECT host:port` to the upstream proxy; under chaining
//!   the hostname is the only thing we look at ([G-22]) — the upstream
//!   proxy resolves the name itself, so `pinned_addrs` is ignored there.
//!
//! CONNECT only, no plain-HTTP forwarding through the upstream proxy
//! ([G-24]): tunnels are opaque bytes after the 2xx head.
//!
//! Credentials come from the proxy URL userinfo
//! (`http://user:password@proxy:8080`) and are held for the dialer's
//! lifetime as a precomputed `Proxy-Authorization` header ([G-30]). They are
//! never logged and never appear in `Display`/`Debug`/error text: a proxy is
//! only ever named as `host:port`. Userinfo containing CR, LF or NUL is
//! refused at parse time, and a CONNECT target host with whitespace or a
//! control character is refused before any byte is written — both would
//! otherwise inject headers into the CONNECT request head.
//!
//! NTLM/Kerberos proxies are NOT supported ([G-14]). The workaround is a
//! local Basic-auth bridge in front of the corporate proxy: `cntlm` (Windows
//! build) or `px --proxy=...` listening on `127.0.0.1:<port>`, then point
//! `network.upstreamProxy` at that bridge (`http://user:pass@127.0.0.1:3128`).
//!
//! Wired into the proxy pipeline by Task 4.2: `proxy::dial_upstream` branches
//! on `chains_host` and maps `UpstreamError` to `502` +
//! `X-Sandbox: upstream-error`, while `main.rs` builds the dialer once from
//! `network.upstreamProxy` / `HTTPS_PROXY` ([G-10]). The module-level
//! `#![allow(dead_code)]` is gone; the few items no production path consumes
//! yet carry a per-item allow saying so.

use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use super::proxy::happy_eyeballs_dial;

/// Port used when the proxy URL omits one. 8080 is the conventional
/// explicit-proxy port (3128 is Squid's); there is no way to auto-detect,
/// so the common default wins and an explicit `:3128` is one keystroke.
const DEFAULT_PROXY_PORT: u16 = 8080;

/// Bound on the TCP connect to the upstream proxy itself. A blackholed
/// corporate proxy must fail fast (502) instead of pinning a request, and
/// the timeout is per request rather than per session.
const PROXY_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Bound on the CONNECT request/response exchange after the proxy TCP
/// connection is up. Separate from [`PROXY_CONNECT_TIMEOUT`] so a slow
/// CONNECT through an authenticating proxy is not charged to the connect.
const CONNECT_RESPONSE_TIMEOUT: Duration = Duration::from_secs(10);

/// Cap on the CONNECT response head (status line + headers). Real heads are
/// a few hundred bytes; anything past this is a broken or hostile proxy.
const MAX_RESPONSE_HEAD: usize = 8 * 1024;

// =====================================================================
// Errors
// =====================================================================

/// Failure of an upstream dial.
///
/// `Display` never contains credentials and never contains the proxy URL:
/// callers that want to name the proxy use [`UpstreamDialer::proxy_endpoint`]
/// (`host:port` only, [G-30]).
///
/// `BadResponse` doubles as the config-error arm: `ProxyUrl::parse` failures
/// are reported here too, with a static reason (never the raw URL text, which
/// may carry a password).
#[derive(Debug)]
pub enum UpstreamError {
    /// Could not reach the peer: the proxy, or — on the `NO_PROXY` path —
    /// one of the pinned addresses. It closed the connection or never
    /// answered in time.
    Unreachable(io::Error),
    /// The proxy answered with something that is not an HTTP CONNECT
    /// response head, or the proxy URL/config was malformed.
    BadResponse(&'static str),
    /// The proxy answered the CONNECT with a non-2xx status.
    Non200(u16),
}

impl fmt::Display for UpstreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            // Path-neutral on purpose: this arm also reports a failed
            // *direct* dial, where no proxy was involved at all.
            UpstreamError::Unreachable(e) => write!(f, "upstream unreachable: {e}"),
            UpstreamError::BadResponse(why) => write!(f, "upstream proxy protocol error: {why}"),
            UpstreamError::Non200(code) => {
                write!(f, "upstream proxy refused CONNECT with status {code}")
            }
        }
    }
}

impl std::error::Error for UpstreamError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            UpstreamError::Unreachable(e) => Some(e),
            _ => None,
        }
    }
}

/// A malformed upstream proxy URL or endpoint. The reason is a static
/// string: the input may contain a password, so it is never echoed.
fn bad_url(why: &'static str) -> UpstreamError {
    UpstreamError::BadResponse(why)
}

/// Map a timeout expiry onto the `Unreachable` arm with `TimedOut`, so the
/// caller's error handling does not need a fourth variant.
fn timed_out(what: &'static str) -> UpstreamError {
    UpstreamError::Unreachable(io::Error::new(io::ErrorKind::TimedOut, what))
}

// =====================================================================
// Proxy URL
// =====================================================================

/// A parsed upstream proxy endpoint (`http://[user[:pass]@]host[:port]`).
///
/// Hand-rolled instead of pulling in the `url` crate: we need exactly one
/// shape (scheme-less, path-less proxy authorities appear in the wild via
/// `HTTPS_PROXY`), and the `url` crate's normalization is the wrong tool for
/// a value that must never be logged verbatim.
///
/// `Display`/`Debug` render `host:port` only — the userinfo never leaves
/// this struct ([G-30]).
#[derive(Clone)]
pub struct ProxyUrl {
    host: String,
    port: u16,
    user: Option<String>,
    password: Option<String>,
}

impl ProxyUrl {
    /// Parse `http://[user[:pass]@]host[:port]`.
    ///
    /// Tolerated: a missing scheme, a bare trailing `/`, surrounding
    /// whitespace, a bracketed IPv6 literal, a password containing `@`.
    /// Rejected: any scheme other than `http` (TLS to the proxy is not
    /// implemented — refusing beats silently downgrading to plaintext),
    /// paths/queries, unbracketed IPv6 (ambiguous with the port separator),
    /// port `0` or an unparsable port, and CR/LF/NUL anywhere in the
    /// userinfo (those would inject headers into the CONNECT request — see
    /// [`check_userinfo`]).
    ///
    /// Userinfo is taken literally — no percent-decoding; use an encoded
    /// bridge (cntlm/px) or URL-safe credentials if the proxy needs escapes.
    /// Spaces and non-ASCII stay legal: base64 encodes them.
    pub fn parse(raw: &str) -> Result<ProxyUrl, UpstreamError> {
        let s = raw.trim();
        if s.is_empty() {
            return Err(bad_url("empty upstream proxy URL"));
        }

        let rest = match s.split_once("://") {
            Some((scheme, rest)) => {
                if !scheme.eq_ignore_ascii_case("http") {
                    return Err(bad_url("unsupported upstream proxy scheme"));
                }
                rest
            }
            None => s,
        };

        // `http://proxy:8080/` is common; anything longer is a path, which
        // a proxy endpoint is not.
        let rest = rest.strip_suffix('/').unwrap_or(rest);
        if rest.is_empty() {
            return Err(bad_url("upstream proxy URL has no host"));
        }
        if rest.contains('/') {
            return Err(bad_url("upstream proxy URL has a path"));
        }

        // The userinfo separator is the *last* `@` — passwords may contain
        // `@` unencoded, and the host never does.
        let (userinfo, hostport) = match rest.rsplit_once('@') {
            Some((u, hp)) => (Some(u), hp),
            None => (None, rest),
        };

        let (user, password) = match userinfo {
            Some(ui) => {
                if ui.is_empty() {
                    return Err(bad_url("empty upstream proxy userinfo"));
                }
                check_userinfo(ui)?;
                match ui.split_once(':') {
                    Some((u, p)) => {
                        if u.is_empty() {
                            return Err(bad_url("empty upstream proxy user"));
                        }
                        (Some(u.to_string()), Some(p.to_string()))
                    }
                    None => (Some(ui.to_string()), None),
                }
            }
            None => (None, None),
        };

        let (host, port) = split_host_port(hostport)?;
        if host.is_empty() || host.chars().any(|c| c.is_whitespace() || c.is_control()) {
            return Err(bad_url("invalid upstream proxy host"));
        }
        Ok(ProxyUrl {
            host,
            port,
            user,
            password,
        })
    }

    /// Proxy host without IPv6 brackets. Test-only today: production names a
    /// proxy through [`Self::endpoint`] ([G-30]).
    #[allow(dead_code)]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Test-only, same reason as [`Self::host`].
    #[allow(dead_code)]
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Userinfo username, if the URL carried one (`None` = no auth).
    /// Crate-private with [`Self::password`] ([G-30]): userinfo is half of a
    /// credential, so it does not leave the crate where a caller could log
    /// it.
    #[allow(dead_code)]
    pub(crate) fn user(&self) -> Option<&str> {
        self.user.as_deref()
    }

    /// Userinfo password, if present. Crate-private on purpose ([G-30]):
    /// only [`Self::auth_header`] and tests may touch it, so a future
    /// caller cannot accidentally log it.
    #[allow(dead_code)]
    pub(crate) fn password(&self) -> Option<&str> {
        self.password.as_deref()
    }

    /// `host:port` — the only form of the proxy that may be logged or put
    /// into an error body ([G-30]). IPv6 literals are re-bracketed.
    pub fn endpoint(&self) -> String {
        host_port(&self.host, self.port)
    }

    /// `Proxy-Authorization` value (`Basic <base64(user:pass)>`), or `None`
    /// when the URL has no userinfo ([G-30]).
    ///
    /// The cleartext `user:pass` buffer exists only for the duration of the
    /// base64 call and is dropped immediately; the dialer keeps just the
    /// encoded header.
    pub fn auth_header(&self) -> Option<String> {
        use base64::Engine;
        let user = self.user.as_deref()?;
        let password = self.password.as_deref().unwrap_or("");
        let raw = format!("{user}:{password}");
        let b64 = base64::engine::general_purpose::STANDARD.encode(raw.as_bytes());
        Some(format!("Basic {b64}"))
    }
}

impl fmt::Display for ProxyUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.endpoint())
    }
}

impl fmt::Debug for ProxyUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ProxyUrl({})", self.endpoint())
    }
}

/// `host:port`, bracketing IPv6 literals.
fn host_port(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// Split an authority into `(host, port)`, applying [`DEFAULT_PROXY_PORT`].
fn split_host_port(s: &str) -> Result<(String, u16), UpstreamError> {
    if let Some(inner) = s.strip_prefix('[') {
        let (host, rest) = inner
            .split_once(']')
            .ok_or_else(|| bad_url("unterminated IPv6 literal"))?;
        let port = match rest.strip_prefix(':') {
            Some(p) => parse_port(p)?,
            None if rest.is_empty() => DEFAULT_PROXY_PORT,
            None => return Err(bad_url("malformed upstream proxy host:port")),
        };
        return Ok((host.to_string(), port));
    }
    if s.is_empty() {
        return Err(bad_url("upstream proxy URL has no host"));
    }
    // A second colon means an unbracketed IPv6 literal; guessing where the
    // port starts would silently produce a wrong endpoint.
    if s.matches(':').count() > 1 {
        return Err(bad_url("IPv6 literals must be bracketed"));
    }
    match s.split_once(':') {
        Some((host, p)) => {
            if host.is_empty() {
                return Err(bad_url("upstream proxy URL has no host"));
            }
            Ok((host.to_string(), parse_port(p)?))
        }
        None => Ok((s.to_string(), DEFAULT_PROXY_PORT)),
    }
}

fn parse_port(p: &str) -> Result<u16, UpstreamError> {
    if p.is_empty() {
        return Err(bad_url("empty upstream proxy port"));
    }
    match p.parse::<u16>() {
        Ok(n) if n != 0 => Ok(n),
        _ => Err(bad_url("invalid upstream proxy port")),
    }
}

/// Reject CR, LF and NUL in the whole userinfo.
///
/// The userinfo is written verbatim into the CONNECT request head (base64
/// for the header, but the raw text decides where the head ends), so a CR or
/// LF here would smuggle an extra header — or an entire request — into the
/// proxy connection; NUL is never legal in a header either. Rejecting at
/// parse time means such a URL can never produce a dialer.
///
/// Everything else stays legal on purpose: spaces and non-ASCII bytes are
/// base64-encoded and real bridges hand them out, so refusing them would
/// break working credentials. The reason is static because the input may be
/// a password and must never be echoed.
fn check_userinfo(ui: &str) -> Result<(), UpstreamError> {
    if ui.chars().any(|c| matches!(c, '\r' | '\n' | '\0')) {
        return Err(bad_url("upstream proxy credentials contain CR, LF or NUL"));
    }
    Ok(())
}

/// Reject a CONNECT target host that cannot be written into a request line.
///
/// `host` is interpolated verbatim into both `CONNECT {host}:{port}` and
/// `Host: {host}:{port}`, so whitespace (which would split the request line,
/// changing the request) and control characters (CR/LF header injection,
/// NUL) must be refused before a single byte goes out. The hostname charset
/// is otherwise unconstrained — see the advisory about bracketed IPv6
/// literals, which belongs to the caller contract.
fn check_dial_host(host: &str) -> Result<(), UpstreamError> {
    if host.is_empty() || host.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(UpstreamError::BadResponse("invalid CONNECT target host"));
    }
    Ok(())
}

// =====================================================================
// NO_PROXY matching ([G-11])
// =====================================================================

/// Does `host` match any `NO_PROXY` entry?
///
/// Semantics ([G-11]): `host == entry || host ends with "." + entry`, ASCII
/// case-insensitive. Entries are trimmed and empty entries are skipped.
///
/// Deliberately *not* supported, matching the ADR's "consistent with
/// `allow_domain`" note:
/// - leading-dot entries — `.example.com` is a literal hostname here, so it
///   never matches (`example.com` and `api.example.com` both miss);
/// - CIDR blocks (`10.0.0.0/8` is literal);
/// - `*` wildcards (`*.example.com` is literal);
/// - ports in entries (`example.com:8080` is literal).
///
/// A trailing root dot on either side is ignored (`example.com.` matches
/// `example.com`); empty/whitespace hosts match nothing.
pub fn host_matches_no_proxy(host: &str, entries: &[String]) -> bool {
    let host = normalize_host(host);
    if host.is_empty() {
        return false;
    }
    entries.iter().any(|entry| {
        let entry = normalize_host(entry);
        !entry.is_empty() && (host == entry || host.ends_with(&format!(".{entry}")))
    })
}

fn normalize_host(h: &str) -> String {
    h.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// `[v6]` → `v6`; any other entry unchanged.
///
/// `NO_PROXY` entries are matched against the *bare* host: the dial path
/// normalizes a bracketed CONNECT target once before the decision, so a
/// bracketed entry has to be stored bare too or the two spellings would
/// disagree ([G-11]).
fn strip_bracket_entry(entry: &str) -> String {
    let e = entry.trim();
    e.strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(e)
        .to_string()
}

// =====================================================================
// Direct dialer
// =====================================================================

/// Dials admission-time pinned addresses with Happy Eyeballs ([G-12]).
///
/// The race itself lives in `proxy::happy_eyeballs_dial` (8 concurrent
/// dials per batch, first winner wins, losers aborted) — this type exists so
/// the `NO_PROXY` leg has a clean direct seam. Task 4.2 does *not* branch on
/// dialer identity: `proxy::dial_upstream` branches on `chains_host(host)`
/// and only reaches this type through `UpstreamDialer::dial`'s bypass arm.
#[derive(Debug, Clone, Copy, Default)]
pub struct DirectDialer;

impl DirectDialer {
    pub fn new() -> Self {
        DirectDialer
    }

    /// Dial the pinned addresses. An empty list fails closed.
    pub async fn dial(&self, pinned_addrs: &[SocketAddr]) -> Result<TcpStream, UpstreamError> {
        happy_eyeballs_dial(pinned_addrs.to_vec())
            .await
            .map_err(UpstreamError::Unreachable)
    }
}

// =====================================================================
// Upstream dialer
// =====================================================================

/// Upstream chaining dialer ([G-10, G-30, G-49]).
///
/// Holds the proxy endpoint, the precomputed Basic auth header, the
/// `NO_PROXY` bypass list, and the direct dialer used for bypassed hosts.
/// One instance lives for the proxy's lifetime; each CONNECT reuses the
/// cached auth header.
pub struct UpstreamDialer {
    proxy_url: ProxyUrl,
    proxy_auth: Option<String>,
    no_proxy: Vec<String>,
    direct: DirectDialer,
}

impl UpstreamDialer {
    pub fn new(proxy_url: ProxyUrl, no_proxy: Vec<String>) -> UpstreamDialer {
        let proxy_auth = proxy_url.auth_header();
        UpstreamDialer {
            proxy_url,
            proxy_auth,
            // Both `chains_host` and `dial`'s own re-check see the *bare*
            // host, so `[2606:4700::1111]` and `2606:4700::1111` must land on
            // the same entry ([G-11]).
            no_proxy: no_proxy.iter().map(|e| strip_bracket_entry(e)).collect(),
            direct: DirectDialer::new(),
        }
    }

    /// Parse the proxy URL and build a dialer in one step (what Task 4.2 /
    /// `main.rs` will use).
    pub fn from_url(raw: &str, no_proxy: Vec<String>) -> Result<UpstreamDialer, UpstreamError> {
        Ok(UpstreamDialer::new(ProxyUrl::parse(raw)?, no_proxy))
    }

    /// True when this host must go through the upstream proxy, i.e. it is
    /// *not* in `NO_PROXY` ([G-11, G-49]).
    pub fn chains_host(&self, host: &str) -> bool {
        !host_matches_no_proxy(host, &self.no_proxy)
    }

    /// Cached `Proxy-Authorization` value, `None` when the URL has no
    /// userinfo. Crate-private ([G-30]) like the userinfo it encodes: tests
    /// only, never log the value.
    #[allow(dead_code)]
    pub(crate) fn proxy_auth_header(&self) -> Option<String> {
        self.proxy_auth.clone()
    }

    /// Redacted proxy identity (`host:port`) for error bodies and logs.
    pub fn proxy_endpoint(&self) -> String {
        self.proxy_url.endpoint()
    }

    /// Dial `host:port`.
    ///
    /// `pinned_addrs` is used **only** on the `NO_PROXY` (direct) path.
    /// Under chaining it is ignored: the upstream proxy does its own DNS,
    /// so a local resolution would be both redundant and wrong ([G-22]).
    /// Callers may therefore pass the pinned set unconditionally.
    pub async fn dial(
        &self,
        host: &str,
        port: u16,
        pinned_addrs: &[SocketAddr],
    ) -> Result<TcpStream, UpstreamError> {
        // Refuse an unrepresentable host up front, on both paths: it would
        // otherwise be interpolated straight into the CONNECT request line.
        check_dial_host(host)?;
        if host_matches_no_proxy(host, &self.no_proxy) {
            return self.direct.dial(pinned_addrs).await;
        }
        self.dial_via_proxy(host, port).await
    }

    /// Connect to the proxy, issue `CONNECT host:port`, return the tunnel.
    async fn dial_via_proxy(&self, host: &str, port: u16) -> Result<TcpStream, UpstreamError> {
        let endpoint = self.proxy_url.endpoint();
        let mut stream = timeout(PROXY_CONNECT_TIMEOUT, TcpStream::connect(endpoint.as_str()))
            .await
            .map_err(|_| timed_out("upstream proxy connect timed out"))?
            .map_err(UpstreamError::Unreachable)?;

        let target = host_port(host, port);
        let mut req = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n");
        if let Some(auth) = &self.proxy_auth {
            req.push_str("Proxy-Authorization: ");
            req.push_str(auth);
            req.push_str("\r\n");
        }
        req.push_str("\r\n");

        // One bound over the whole exchange, request write included: a
        // proxy that accepts the connection and then stops reading must not
        // pin the request just because the stall happened before the read.
        let status = timeout(CONNECT_RESPONSE_TIMEOUT, async {
            stream
                .write_all(req.as_bytes())
                .await
                .map_err(UpstreamError::Unreachable)?;
            read_connect_status(&mut stream).await
        })
        .await
        .map_err(|_| timed_out("upstream proxy CONNECT exchange timed out"))??;
        if !(200..300).contains(&status) {
            return Err(UpstreamError::Non200(status));
        }
        Ok(stream)
    }
}

impl fmt::Debug for UpstreamDialer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UpstreamDialer")
            .field("proxy", &self.proxy_url)
            .field("auth", &self.proxy_auth.is_some())
            .field("no_proxy", &self.no_proxy)
            .finish()
    }
}

/// Read the CONNECT response head and return its status code.
///
/// Reads one byte at a time so the returned stream is positioned exactly
/// after `\r\n\r\n` — a proxy that pipelines bytes behind the head must not
/// lose them. Heads are tiny, so the syscall cost is irrelevant.
async fn read_connect_status(stream: &mut TcpStream) -> Result<u16, UpstreamError> {
    let mut head = Vec::with_capacity(128);
    let mut byte = [0u8; 1];
    loop {
        if let Some(end) = find_head_end(&head) {
            return parse_status_line(&head[..end]);
        }
        if head.len() >= MAX_RESPONSE_HEAD {
            return Err(UpstreamError::BadResponse(
                "CONNECT response head exceeds 8 KiB",
            ));
        }
        let n = stream
            .read(&mut byte)
            .await
            .map_err(UpstreamError::Unreachable)?;
        if n == 0 {
            return Err(UpstreamError::BadResponse(
                "connection closed before CONNECT response head completed",
            ));
        }
        head.push(byte[0]);
    }
}

/// Offset just past the first `\r\n\r\n`, if the head is complete.
fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

/// Status code from an HTTP/1.x response head.
///
/// Only the status line is decoded, and lossily: real proxies put Latin-1 or
/// Windows-1252 bytes in reason phrases and header values (`caf<e9>`), so
/// requiring the whole head to be UTF-8 turned a CONNECT that had actually
/// succeeded into a protocol error. Nothing past the first line feed is
/// inspected.
///
/// The shape is strict where it matters: the version token is exactly
/// `HTTP/1.0` or `HTTP/1.1` and the code is exactly three ASCII digits, so
/// `20`, `0200`, `2OO`, `HTTP/1.9` and `HTTP/1.Xjunk` are all protocol
/// errors. Any 2xx still opens the tunnel — the code is not pinned to 200.
fn parse_status_line(head: &[u8]) -> Result<u16, UpstreamError> {
    let line_end = head.iter().position(|&b| b == b'\n').unwrap_or(head.len());
    let line = &head[..line_end];
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    let text = String::from_utf8_lossy(line);
    let mut parts = text.split_whitespace();
    let version = parts.next().unwrap_or("");
    if !is_http1_version(version) {
        return Err(UpstreamError::BadResponse("malformed CONNECT status line"));
    }
    let code = parts
        .next()
        .ok_or(UpstreamError::BadResponse("missing CONNECT status code"))?;
    if code.len() != 3 || !code.bytes().all(|b| b.is_ascii_digit()) {
        return Err(UpstreamError::BadResponse("malformed CONNECT status code"));
    }
    code.parse::<u16>()
        .map_err(|_| UpstreamError::BadResponse("malformed CONNECT status code"))
}

/// `HTTP/1.0` or `HTTP/1.1` and nothing else.
///
/// Only 1.x minors that exist as a text protocol are accepted: the point is
/// to refuse a token like `HTTP/1.9` or `HTTP/1.Xjunk` rather than to guess
/// what an unknown version means. CONNECT is a 1.1 method, but a 1.0
/// answering proxy is tolerated like before.
fn is_http1_version(v: &str) -> bool {
    let b = v.as_bytes();
    b.len() == 8 && b.starts_with(b"HTTP/1.") && matches!(b[7], b'0' | b'1')
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;
    use tokio::time::{Duration, timeout};

    /// Budget for a mock-side I/O step or a dialer step a test is watching.
    /// A mock that stops responding fails the test instead of hanging
    /// `cargo test` forever.
    const MOCK_IO: Duration = Duration::from_secs(3);

    /// Bounded receive from a mock: a silent mock fails the test.
    async fn recv_mock<T>(rx: oneshot::Receiver<T>) -> T {
        timeout(MOCK_IO, rx)
            .await
            .expect("mock never responded")
            .expect("mock dropped its sender")
    }

    // ------------------------------------------------------------------
    // NO_PROXY matching ([G-11]): hostname suffix, case-insensitive, no
    // leading-dot form, no CIDR, no wildcards.
    // ------------------------------------------------------------------

    fn entries(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn exact_host_matches() {
        assert!(host_matches_no_proxy(
            "example.com",
            &entries(&["example.com"])
        ));
    }

    #[test]
    fn subdomain_matches() {
        assert!(host_matches_no_proxy(
            "api.example.com",
            &entries(&["example.com"])
        ));
        assert!(host_matches_no_proxy(
            "deep.api.example.com",
            &entries(&["example.com"])
        ));
    }

    #[test]
    fn apex_does_not_match_lookalike_domain() {
        // "notexample.com" must not match the "example.com" suffix: the
        // match is on a "." boundary, not a raw string suffix.
        assert!(!host_matches_no_proxy(
            "notexample.com",
            &entries(&["example.com"])
        ));
        assert!(!host_matches_no_proxy(
            "badexample.com",
            &entries(&["example.com"])
        ));
    }

    #[test]
    fn matching_is_case_insensitive_both_ways() {
        assert!(host_matches_no_proxy(
            "API.Example.COM",
            &entries(&["example.com"])
        ));
        assert!(host_matches_no_proxy(
            "api.example.com",
            &entries(&["Example.Com"])
        ));
    }

    #[test]
    fn empty_entry_list_matches_nothing() {
        assert!(!host_matches_no_proxy("example.com", &[]));
    }

    #[test]
    fn whitespace_entries_are_trimmed_and_empties_skipped() {
        assert!(host_matches_no_proxy(
            "example.com",
            &entries(&["  example.com  "])
        ));
        assert!(!host_matches_no_proxy(
            "example.com",
            &entries(&["", "   "])
        ));
    }

    #[test]
    fn leading_dot_entry_never_matches() {
        // [G-11] has no leading-dot form: ".example.com" is not normalized,
        // it is simply a hostname that cannot match.
        assert!(!host_matches_no_proxy(
            "example.com",
            &entries(&[".example.com"])
        ));
        assert!(!host_matches_no_proxy(
            "api.example.com",
            &entries(&[".example.com"])
        ));
    }

    #[test]
    fn wildcard_and_cidr_forms_are_literal_not_special() {
        assert!(!host_matches_no_proxy(
            "api.example.com",
            &entries(&["*.example.com"])
        ));
        assert!(!host_matches_no_proxy(
            "10.0.0.5",
            &entries(&["10.0.0.0/8"])
        ));
    }

    #[test]
    fn any_entry_may_match() {
        let list = entries(&["localhost", "corp.example", "internal.test"]);
        assert!(host_matches_no_proxy("build.internal.test", &list));
        assert!(!host_matches_no_proxy("external.test", &list));
    }

    #[test]
    fn empty_host_matches_nothing() {
        assert!(!host_matches_no_proxy("", &entries(&["example.com"])));
        assert!(!host_matches_no_proxy("   ", &entries(&["example.com"])));
    }

    // ------------------------------------------------------------------
    // chains_host — inverted NO_PROXY predicate.
    // ------------------------------------------------------------------

    fn dialer(url: &str, no_proxy: Vec<String>) -> UpstreamDialer {
        UpstreamDialer::from_url(url, no_proxy).expect("proxy url parses")
    }

    #[test]
    fn chains_when_no_proxy_list_is_empty() {
        assert!(dialer("http://proxy.corp:3128", vec![]).chains_host("example.com"));
    }

    #[test]
    fn does_not_chain_on_no_proxy_hit() {
        let d = dialer("http://proxy.corp:3128", entries(&["example.com"]));
        assert!(!d.chains_host("example.com"));
        assert!(!d.chains_host("api.example.com"));
    }

    #[test]
    fn chains_for_lookalike_domain() {
        let d = dialer("http://proxy.corp:3128", entries(&["example.com"]));
        assert!(d.chains_host("notexample.com"));
    }

    #[test]
    fn no_proxy_hit_is_case_insensitive() {
        let d = dialer("http://proxy.corp:3128", entries(&["Example.COM"]));
        assert!(!d.chains_host("api.example.com"));
    }

    // ------------------------------------------------------------------
    // Proxy URL parsing + redaction ([G-30]).
    // ------------------------------------------------------------------

    #[test]
    fn parses_full_url_with_userinfo_and_port() {
        let u = ProxyUrl::parse("http://bob:s3cret@proxy.corp:3128").unwrap();
        assert_eq!(u.host(), "proxy.corp");
        assert_eq!(u.port(), 3128);
        assert_eq!(u.user(), Some("bob"));
        assert_eq!(u.password(), Some("s3cret"));
    }

    #[test]
    fn parses_user_only_userinfo() {
        let u = ProxyUrl::parse("http://bob@proxy.corp:8080").unwrap();
        assert_eq!(u.user(), Some("bob"));
        assert_eq!(u.password(), None);
        assert_eq!(u.port(), 8080);
    }

    #[test]
    fn missing_port_defaults_to_8080() {
        let u = ProxyUrl::parse("http://proxy.corp").unwrap();
        assert_eq!(u.port(), 8080);
        assert_eq!(u.endpoint(), "proxy.corp:8080");
    }

    #[test]
    fn missing_scheme_is_tolerated() {
        let u = ProxyUrl::parse("proxy.corp:3128").unwrap();
        assert_eq!(u.host(), "proxy.corp");
        assert_eq!(u.port(), 3128);
        let v = ProxyUrl::parse("  bob:pw@proxy.corp  ").unwrap();
        assert_eq!(v.host(), "proxy.corp");
        assert_eq!(v.user(), Some("bob"));
    }

    #[test]
    fn trailing_slash_is_tolerated() {
        let u = ProxyUrl::parse("http://proxy.corp:3128/").unwrap();
        assert_eq!(u.port(), 3128);
    }

    #[test]
    fn bracketed_ipv6_literal_is_supported() {
        let u = ProxyUrl::parse("http://[::1]:3128").unwrap();
        assert_eq!(u.host(), "::1");
        assert_eq!(u.port(), 3128);
        assert_eq!(u.endpoint(), "[::1]:3128");
    }

    #[test]
    fn password_may_contain_at_sign() {
        // The userinfo/host separator is the *last* '@'.
        let u = ProxyUrl::parse("http://bob:p@ss@proxy.corp:3128").unwrap();
        assert_eq!(u.host(), "proxy.corp");
        assert_eq!(u.password(), Some("p@ss"));
    }

    #[test]
    fn userinfo_with_cr_lf_or_nul_is_rejected() {
        // [G-30] posture: userinfo is written verbatim into the CONNECT
        // request head, so a CR or LF there would smuggle a header (or a
        // whole request) past the proxy. NUL is never legal in a header
        // either. Rejection happens at parse time, before any credential is
        // held, and the reason is static so the password is never echoed.
        for raw in [
            "http://bob:pa\r\nInjected: 1@proxy.corp:3128",
            "http://bob:pass\r@proxy.corp:3128",
            "http://bob:pass\n@proxy.corp:3128",
            "http://bo\r\nb:pass@proxy.corp:3128",
            "http://bob:pa\0ss@proxy.corp:3128",
            "http://bob\0:pass@proxy.corp:3128",
        ] {
            let err = ProxyUrl::parse(raw)
                .err()
                .unwrap_or_else(|| panic!("userinfo {raw:?} must be rejected"));
            match err {
                UpstreamError::BadResponse(why) => {
                    assert!(
                        !why.contains("Injected") && !why.contains("bob"),
                        "reason leaks input: {why}"
                    );
                }
                other => panic!("userinfo {raw:?}: unexpected error {other:?}"),
            }
        }
    }

    #[test]
    fn userinfo_keeps_spaces_and_non_ascii_legal() {
        // Not over-restricting: base64 encodes any byte sequence, so spaces
        // and non-ASCII passwords stay usable (corporate bridges hand these
        // out). Only CR/LF/NUL are lethal to the header framing.
        let u = ProxyUrl::parse("http://böb:pa ss wörd!@proxy.corp:3128").unwrap();
        assert_eq!(u.user(), Some("böb"));
        assert_eq!(u.password(), Some("pa ss wörd!"));
    }

    #[test]
    fn garbage_urls_are_rejected() {
        assert!(ProxyUrl::parse("").is_err());
        assert!(ProxyUrl::parse("   ").is_err());
        assert!(ProxyUrl::parse("http://").is_err());
        assert!(ProxyUrl::parse("http://:3128").is_err());
        assert!(ProxyUrl::parse("http://proxy.corp:notaport").is_err());
        assert!(ProxyUrl::parse("http://proxy.corp:99999999").is_err());
        // https to the proxy needs TLS-to-proxy, which we do not implement:
        // fail closed rather than silently downgrading to plaintext.
        assert!(ProxyUrl::parse("https://proxy.corp:3128").is_err());
        // A path/query is not part of a proxy endpoint.
        assert!(ProxyUrl::parse("http://proxy.corp:3128/path").is_err());
        // Unbracketed IPv6 is ambiguous with the port separator.
        assert!(ProxyUrl::parse("http://::1:3128").is_err());
    }

    #[test]
    fn display_and_debug_are_redacted() {
        let u = ProxyUrl::parse("http://bob:s3cret@proxy.corp:3128").unwrap();
        let shown = format!("{u} {u:?}");
        assert!(!shown.contains("s3cret"), "password leaked: {shown}");
        assert!(!shown.contains("bob"), "user leaked: {shown}");
        assert!(shown.contains("proxy.corp:3128"));

        let d = dialer(
            "http://bob:s3cret@proxy.corp:3128",
            entries(&["example.com"]),
        );
        let shown = format!("{d:?}");
        assert!(!shown.contains("s3cret"), "password leaked: {shown}");
        assert!(!shown.contains("bob"), "user leaked: {shown}");
    }

    // ------------------------------------------------------------------
    // Basic auth header ([G-30]).
    // ------------------------------------------------------------------

    #[test]
    fn no_auth_header_without_userinfo() {
        let d = dialer("http://proxy.corp:3128", vec![]);
        assert_eq!(d.proxy_auth_header(), None);
    }

    #[test]
    fn auth_header_is_basic_base64_of_user_colon_password() {
        let d = dialer("http://user:pass@proxy.corp:3128", vec![]);
        // base64("user:pass") == "dXNlcjpwYXNz"
        assert_eq!(d.proxy_auth_header().as_deref(), Some("Basic dXNlcjpwYXNz"));
    }

    #[test]
    fn user_only_auth_header_has_empty_password() {
        let d = dialer("http://user@proxy.corp:3128", vec![]);
        // base64("user:") == "dXNlcjo="
        assert_eq!(d.proxy_auth_header().as_deref(), Some("Basic dXNlcjo="));
    }

    // ------------------------------------------------------------------
    // Behavioral: mock upstream proxy on 127.0.0.1:0.
    // ------------------------------------------------------------------

    /// Read a request head (through `\r\n\r\n`) byte-by-byte.
    /// Mock upstream proxy: accept one connection, read the CONNECT head,
    /// write `response` verbatim, then echo tunnel bytes. Returns its addr.
    async fn mock_proxy(response: &'static [u8]) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = timeout(MOCK_IO, listener.accept())
                .await
                .expect("mock accept timed out")
                .expect("mock accept failed");
            let _ = read_head(&mut sock).await;
            sock.write_all(response).await.unwrap();
            let mut buf = [0u8; 1024];
            loop {
                let n = match timeout(MOCK_IO, sock.read(&mut buf)).await {
                    Ok(Ok(n)) => n,
                    _ => return,
                };
                if n == 0 {
                    return;
                }
                if timeout(MOCK_IO, sock.write_all(&buf[..n])).await.is_err() {
                    return;
                }
            }
        });
        addr
    }

    async fn read_head(sock: &mut tokio::net::TcpStream) -> Vec<u8> {
        let mut head = Vec::new();
        let mut b = [0u8; 1];
        loop {
            let n = match timeout(MOCK_IO, sock.read(&mut b)).await {
                Ok(Ok(n)) => n,
                _ => return head,
            };
            if n == 0 {
                return head;
            }
            head.push(b[0]);
            if head.ends_with(b"\r\n\r\n") {
                return head;
            }
        }
    }

    #[tokio::test]
    async fn chained_dial_sends_connect_with_auth_and_round_trips() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        let (tx, rx) = oneshot::channel();

        tokio::spawn(async move {
            let (mut sock, _) = timeout(MOCK_IO, listener.accept())
                .await
                .expect("mock accept timed out")
                .expect("mock accept failed");
            let head = read_head(&mut sock).await;
            let _ = tx.send(String::from_utf8_lossy(&head).to_string());
            sock.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .unwrap();
            let mut buf = [0u8; 1024];
            loop {
                let n = match timeout(MOCK_IO, sock.read(&mut buf)).await {
                    Ok(Ok(n)) => n,
                    _ => return,
                };
                if n == 0 {
                    return;
                }
                sock.write_all(&buf[..n]).await.unwrap();
            }
        });

        let d = dialer(&format!("http://user:pass@{proxy_addr}"), vec![]);
        let mut stream = d
            .dial("internal.corp.example", 443, &[])
            .await
            .expect("tunnel established");
        stream.write_all(b"ping").await.unwrap();
        let mut echoed = [0u8; 4];
        timeout(MOCK_IO, stream.read_exact(&mut echoed))
            .await
            .expect("echo timed out")
            .expect("echo read failed");
        assert_eq!(&echoed, b"ping");

        let head = recv_mock(rx).await;
        assert!(
            head.starts_with("CONNECT internal.corp.example:443 HTTP/1.1\r\n"),
            "head: {head:?}"
        );
        assert!(
            head.contains("\r\nHost: internal.corp.example:443\r\n"),
            "head: {head:?}"
        );
        assert!(
            head.contains("\r\nProxy-Authorization: Basic dXNlcjpwYXNz\r\n"),
            "head: {head:?}"
        );
        assert!(head.ends_with("\r\n\r\n"), "head: {head:?}");
    }

    #[tokio::test]
    async fn chained_dial_omits_auth_header_without_credentials() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        let (tx, rx) = oneshot::channel();

        tokio::spawn(async move {
            let (mut sock, _) = timeout(MOCK_IO, listener.accept())
                .await
                .expect("mock accept timed out")
                .expect("mock accept failed");
            let head = read_head(&mut sock).await;
            let _ = tx.send(String::from_utf8_lossy(&head).to_string());
            sock.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await.unwrap();
        });

        let d = dialer(&format!("http://{proxy_addr}"), vec![]);
        let _stream = d.dial("example.com", 80, &[]).await.unwrap();
        let head = recv_mock(rx).await;
        assert!(!head.to_ascii_lowercase().contains("proxy-authorization"));
    }

    #[tokio::test]
    async fn non_2xx_connect_response_is_non200() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut sock, _) = timeout(MOCK_IO, listener.accept())
                .await
                .expect("mock accept timed out")
                .expect("mock accept failed");
            let _ = read_head(&mut sock).await;
            sock.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
        });

        let d = dialer(&format!("http://{proxy_addr}"), vec![]);
        let err = d.dial("example.com", 443, &[]).await.unwrap_err();
        assert!(
            matches!(err, UpstreamError::Non200(403)),
            "unexpected error: {err} ({err:?})"
        );
    }

    #[tokio::test]
    async fn garbage_status_line_is_bad_response() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut sock, _) = timeout(MOCK_IO, listener.accept())
                .await
                .expect("mock accept timed out")
                .expect("mock accept failed");
            let _ = read_head(&mut sock).await;
            sock.write_all(b"NOPE\r\n\r\n").await.unwrap();
        });

        let d = dialer(&format!("http://{proxy_addr}"), vec![]);
        let err = d.dial("example.com", 443, &[]).await.unwrap_err();
        assert!(
            matches!(err, UpstreamError::BadResponse(_)),
            "unexpected error: {err} ({err:?})"
        );
    }

    #[tokio::test]
    async fn truncated_response_head_is_bad_response() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut sock, _) = timeout(MOCK_IO, listener.accept())
                .await
                .expect("mock accept timed out")
                .expect("mock accept failed");
            let _ = read_head(&mut sock).await;
            // Status line without the terminating blank line, then EOF.
            sock.write_all(b"HTTP/1.1 200 Connection Established\r\n")
                .await
                .unwrap();
            sock.shutdown().await.unwrap();
        });

        let d = dialer(&format!("http://{proxy_addr}"), vec![]);
        let err = d.dial("example.com", 443, &[]).await.unwrap_err();
        assert!(
            matches!(err, UpstreamError::BadResponse(_)),
            "unexpected error: {err} ({err:?})"
        );
    }

    #[tokio::test]
    async fn no_proxy_host_dials_direct_and_never_touches_proxy() {
        // Direct-side listener: the pinned address the dialer should use.
        let direct = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let direct_addr = direct.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = timeout(MOCK_IO, direct.accept())
                .await
                .expect("direct accept timed out")
                .expect("direct accept failed");
            let mut buf = [0u8; 4];
            timeout(MOCK_IO, sock.read_exact(&mut buf))
                .await
                .expect("direct read timed out")
                .expect("direct read failed");
            sock.write_all(&buf).await.unwrap();
        });

        // Proxy-side listener: must stay silent for a NO_PROXY host.
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let (tx, rx) = oneshot::channel::<()>();
        tokio::spawn(async move {
            if let Ok(Ok((_sock, _))) = timeout(MOCK_IO, proxy.accept()).await {
                let _ = tx.send(());
            }
        });

        let d = dialer(
            &format!("http://user:pass@{proxy_addr}"),
            entries(&["example.com"]),
        );
        assert!(!d.chains_host("api.example.com"));

        let mut stream = d
            .dial("api.example.com", 443, &[direct_addr])
            .await
            .expect("direct dial");
        stream.write_all(b"pong").await.unwrap();
        let mut echoed = [0u8; 4];
        timeout(MOCK_IO, stream.read_exact(&mut echoed))
            .await
            .expect("echo timed out")
            .expect("echo read failed");
        assert_eq!(&echoed, b"pong");

        // The upstream proxy must not have seen a connection.
        assert!(
            timeout(Duration::from_millis(300), rx).await.is_err(),
            "upstream proxy was contacted for a NO_PROXY host"
        );
    }

    #[tokio::test]
    async fn head_reader_does_not_consume_pipelined_tunnel_bytes() {
        // Regression guard for the load-bearing property of the head reader:
        // it must stop exactly after CRLF CRLF and leave anything the proxy
        // pipelined behind the head in the socket. One write_all, so the
        // banner is already buffered when the head is parsed; the mock then
        // holds the connection open, because an eager EOF would let an
        // over-reading implementation look correct.
        const BANNER: &[u8] = b"SSH-2.0-mock-banner\r\n";
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = timeout(MOCK_IO, listener.accept())
                .await
                .expect("mock accept timed out")
                .expect("mock accept failed");
            let _ = read_head(&mut sock).await;
            let mut out = Vec::new();
            out.extend_from_slice(b"HTTP/1.1 200 Connection Established\r\n\r\n");
            out.extend_from_slice(BANNER);
            sock.write_all(&out).await.unwrap();
            let mut sink = [0u8; 64];
            while let Ok(n) = sock.read(&mut sink).await {
                if n == 0 {
                    return;
                }
            }
        });

        let d = dialer(&format!("http://{addr}"), vec![]);
        let mut stream = d
            .dial("example.com", 22, &[])
            .await
            .expect("tunnel established");
        let mut got = [0u8; BANNER.len()];
        timeout(MOCK_IO, stream.read_exact(&mut got))
            .await
            .expect("banner arrived")
            .expect("banner readable");
        assert_eq!(
            &got, BANNER,
            "tunnel bytes pipelined behind the head were consumed by the reader"
        );
    }

    #[tokio::test]
    async fn chained_dial_ignores_pinned_addrs() {
        // [G-22]: under chaining the upstream proxy resolves the name, so a
        // pinned address must be ignored outright -- the dial goes to the
        // proxy and the pinned listener never sees a connection.
        let pinned = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let pinned_addr = pinned.local_addr().unwrap();
        let (tx, rx) = oneshot::channel::<()>();
        tokio::spawn(async move {
            if let Ok(Ok((_sock, _))) = timeout(MOCK_IO, pinned.accept()).await {
                let _ = tx.send(());
            }
        });

        let proxy_addr = mock_proxy(b"HTTP/1.1 200 Connection Established\r\n\r\n").await;
        let d = dialer(&format!("http://{proxy_addr}"), vec![]);
        assert!(d.chains_host("example.com"));

        let mut stream = d
            .dial("example.com", 443, &[pinned_addr])
            .await
            .expect("chained dial");
        stream.write_all(b"ping").await.unwrap();
        let mut echoed = [0u8; 4];
        timeout(MOCK_IO, stream.read_exact(&mut echoed))
            .await
            .expect("echo arrived")
            .expect("echo readable");
        assert_eq!(&echoed, b"ping", "the dial did not reach the mock proxy");
        assert!(
            timeout(Duration::from_millis(300), rx).await.is_err(),
            "chained dial dialed the pinned address instead of the proxy"
        );
    }

    #[tokio::test]
    async fn direct_dial_with_no_pinned_addresses_fails() {
        let err = timeout(MOCK_IO, DirectDialer::new().dial(&[]))
            .await
            .expect("direct dial returned")
            .unwrap_err();
        assert!(
            matches!(err, UpstreamError::Unreachable(_)),
            "unexpected error: {err}"
        );
    }

    // ------------------------------------------------------------------
    // Status-line parsing: Latin-1 tolerance + strict 3-digit code.
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn latin1_header_value_does_not_break_a_working_connect() {
        // Real proxies emit Latin-1 in reason phrases and header values
        // (caf<e9>, Windows-1252 vendor strings). Validating the whole head
        // as UTF-8 turned those into a spurious 502 on a CONNECT that had in
        // fact succeeded; only the status line needs decoding.
        let addr =
            mock_proxy(b"HTTP/1.1 200 Connection established\r\nX-Reason: caf\xe9\r\n\r\n").await;
        let d = dialer(&format!("http://{addr}"), vec![]);
        let mut stream = d
            .dial("internal.corp.example", 443, &[])
            .await
            .expect("CONNECT succeeds despite a Latin-1 header value");
        stream.write_all(b"ping").await.unwrap();
        let mut echoed = [0u8; 4];
        timeout(MOCK_IO, stream.read_exact(&mut echoed))
            .await
            .expect("echo arrived")
            .expect("echo readable");
        assert_eq!(&echoed, b"ping");
    }

    #[tokio::test]
    async fn status_code_must_be_exactly_three_ascii_digits() {
        // A loose `parse::<u16>()` accepted "20" (-> Non200(20)) and "0200"
        // (-> a bogus 2xx success). The code is exactly 3 ASCII digits and
        // the version token is exactly "HTTP/1.<digit>".
        for head in [
            &b"HTTP/1.1 20 Foo\r\n\r\n"[..],
            &b"HTTP/1.1 0200 Foo\r\n\r\n"[..],
            &b"HTTP/1.9 200 Foo\r\n\r\n"[..],
            &b"HTTP/1.Xjunk 200 Foo\r\n\r\n"[..],
            &b"HTTP/1.1 2OO Foo\r\n\r\n"[..],
        ] {
            let addr = mock_proxy(head).await;
            let d = dialer(&format!("http://{addr}"), vec![]);
            let err = d.dial("example.com", 443, &[]).await.unwrap_err();
            assert!(
                matches!(err, UpstreamError::BadResponse(_)),
                "head {:?} must be a protocol error, got {err}",
                String::from_utf8_lossy(head)
            );
        }
    }

    #[tokio::test]
    async fn any_2xx_status_opens_the_tunnel() {
        // Any 2xx, not just 200: proxies answer with assorted codes and
        // reason phrases, and a 2xx means the tunnel is up.
        let addr = mock_proxy(b"HTTP/1.0 204 No Content\r\n\r\n").await;
        let d = dialer(&format!("http://{addr}"), vec![]);
        assert!(d.dial("example.com", 443, &[]).await.is_ok());
    }

    // ------------------------------------------------------------------
    // CONNECT request shaping ([G-30] header injection).
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn dial_rejects_host_with_whitespace_or_control_chars() {
        // `host` reaches the CONNECT head unvalidated: a space splits the
        // request line and a CR/LF injects headers. Reject it before a
        // single byte is written; the proxy must never see a connection.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        let (tx, rx) = oneshot::channel::<()>();
        tokio::spawn(async move {
            if let Ok(Ok((_sock, _))) = timeout(MOCK_IO, listener.accept()).await {
                let _ = tx.send(());
            }
        });

        let d = dialer(&format!("http://{proxy_addr}"), vec![]);
        for host in [
            "spaced host.example",
            "tab\thost.example",
            "crlf.example\r\nX-Injected: 1",
            "nul\0host.example",
        ] {
            let err = d
                .dial(host, 443, &[])
                .await
                .err()
                .unwrap_or_else(|| panic!("host {host:?} must be rejected"));
            assert!(
                matches!(err, UpstreamError::BadResponse(_)),
                "host {host:?}: unexpected error {err}"
            );
        }
        assert!(
            timeout(Duration::from_millis(300), rx).await.is_err(),
            "a malformed host still opened a proxy connection"
        );
    }

    // ------------------------------------------------------------------
    // Error attribution.
    // ------------------------------------------------------------------

    #[test]
    fn unreachable_display_does_not_blame_the_proxy() {
        // DirectDialer reports through the same variant, so the wording must
        // stay path-neutral.
        let err = UpstreamError::Unreachable(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            "connection refused",
        ));
        let shown = err.to_string();
        assert!(
            shown.starts_with("upstream unreachable"),
            "message: {shown}"
        );
        assert!(!shown.contains("proxy"), "message blames a proxy: {shown}");
    }
}
