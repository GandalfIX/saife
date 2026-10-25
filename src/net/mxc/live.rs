// Extracted from src/net/mxc.rs `#[cfg(test)] mod live` (2026-10-25), verbatim.
// Same note as tests.rs: keep the indentation, a blind dedent edits raw strings.

    use super::*;
    use std::collections::HashMap;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use crate::net::intent::{DEFAULT_TTL, IntentRegistry};
    use crate::net::learned::LearnedStore;
    use crate::net::prompt::{
        DialogFn, DialogRequest, DialogUnavailable, PromptConfig, PromptCoordinator, PromptPolicy,
        PromptResult,
    };
    use crate::net::proxy::LaunchCounters;
    use crate::net::proxy::LaunchProofCounters;
    use crate::net::token::RunToken;
    use base64::Engine as _;

    /// What the fake endpoint and the proof source share.
    #[derive(Default)]
    struct Shared {
        epoch: AtomicU64,
        /// The window that is open, if any: the fake proof source enforces the
        /// same no-overlap contract the real counters do (P1.4).
        active: Mutex<Option<u64>>,
        counters: Mutex<HashMap<u64, ProxyProof>>,
        closes: Mutex<Vec<u64>>,
        /// `(epoch, request line)` for origin-form requests: a client dialled the
        /// endpoint directly, which is what NO_PROXY is supposed to cause.
        origin: Mutex<Vec<(u64, String)>>,
        /// `(epoch, request line)` for proxy consultations (`CONNECT` or an
        /// absolute-form request).
        proxied: Mutex<Vec<(u64, String)>>,
    }

    struct LiveProof {
        shared: Arc<Shared>,
    }

    impl LiveProof {
        fn last_epoch(&self) -> u64 {
            self.shared.epoch.load(Ordering::SeqCst)
        }
    }

    impl ProxyProofSource for LiveProof {
        fn begin_launch(&self) -> Result<u64, EpochAlreadyOpen> {
            let mut active = self.shared.active.lock().unwrap();
            if let Some(open) = *active {
                return Err(EpochAlreadyOpen { active: open });
            }
            let epoch = self.shared.epoch.fetch_add(1, Ordering::SeqCst) + 1;
            *active = Some(epoch);
            self.shared
                .counters
                .lock()
                .unwrap()
                .insert(epoch, ProxyProof::default());
            Ok(epoch)
        }

        fn proof(&self, epoch: u64) -> ProxyProof {
            self.shared
                .counters
                .lock()
                .unwrap()
                .get(&epoch)
                .copied()
                .unwrap_or_default()
        }

        fn close_launch(&self, epoch: u64) {
            let mut active = self.shared.active.lock().unwrap();
            if *active == Some(epoch) {
                *active = None;
            }
            self.shared.closes.lock().unwrap().push(epoch);
        }
    }

    /// One loopback listener that is **both** the supervisor's proxy (it refuses
    /// loopback targets, as the real one does) and the intent endpoint. Serving
    /// both on one port is what lets the test tell the two apart.
    struct Endpoint {
        port: u16,
        shared: Arc<Shared>,
        stop: Arc<AtomicBool>,
        join: Option<std::thread::JoinHandle<()>>,
    }

    impl Endpoint {
        fn start(nonce: &str) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind endpoint");
            let port = listener.local_addr().expect("endpoint addr").port();
            listener
                .set_nonblocking(false)
                .expect("blocking listener for the accept loop");
            let shared = Arc::new(Shared::default());
            let stop = Arc::new(AtomicBool::new(false));
            let nonce = nonce.to_string();

            let ctx = Arc::clone(&shared);
            let stop_thread = Arc::clone(&stop);
            let join = std::thread::spawn(move || {
                for accepted in listener.incoming() {
                    if stop_thread.load(Ordering::SeqCst) {
                        break;
                    }
                    if let Ok(stream) = accepted {
                        let ctx = Arc::clone(&ctx);
                        let nonce = nonce.clone();
                        std::thread::spawn(move || handle(stream, &ctx, &nonce));
                    }
                }
            });

            Self {
                port,
                shared,
                stop,
                join: Some(join),
            }
        }

        fn url(&self) -> String {
            format!("http://127.0.0.1:{}/sandbox/intent", self.port)
        }

        fn proxy_consultations(&self, epoch: u64) -> Vec<String> {
            let proxied = self.shared.proxied.lock().unwrap();
            proxied
                .iter()
                .filter(|(e, _)| *e == epoch)
                .map(|(_, line)| line.clone())
                .collect()
        }

        fn origin_requests(&self, epoch: u64) -> Vec<String> {
            let origin = self.shared.origin.lock().unwrap();
            origin
                .iter()
                .filter(|(e, _)| *e == epoch)
                .map(|(_, line)| line.clone())
                .collect()
        }

        fn closed(&self, epoch: u64) -> bool {
            self.shared
                .closes
                .lock()
                .map(|closes| closes.contains(&epoch))
                .unwrap_or(false)
        }
    }

    impl Drop for Endpoint {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            // Wake the blocking accept() instead of polling on a sleep.
            let _ = TcpStream::connect(("127.0.0.1", self.port));
            if let Some(join) = self.join.take() {
                let _ = join.join();
            }
        }
    }

    fn bump(shared: &Shared, epoch: u64, f: impl FnOnce(&mut ProxyProof)) {
        let mut counters = shared.counters.lock().unwrap();
        f(counters.entry(epoch).or_default());
    }

    fn handle(mut stream: TcpStream, shared: &Shared, nonce: &str) {
        let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
        let mut buf: Vec<u8> = Vec::new();
        let mut chunk = [0u8; 1024];
        while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
            match stream.read(&mut chunk) {
                Ok(0) => return,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
                Err(_) => return,
            }
            if buf.len() > 16 * 1024 {
                return;
            }
        }

        let head = String::from_utf8_lossy(&buf).to_string();
        let line = head.lines().next().unwrap_or("").trim().to_string();
        let epoch = shared.epoch.load(Ordering::SeqCst);
        let target = line.split_whitespace().nth(1).unwrap_or("").to_string();

        // The control-plane probe, mirrored from the real listener: it is the
        // launch's evidence since the 2026-10-22 amendment, and a fake that did
        // not record it would make a `Required` launch fail for a reason the
        // product never produces.
        if target == "/sandbox/probe" {
            bump(shared, epoch, |proof| proof.probes += 1);
            let _ = stream.write_all(b"HTTP/1.1 204 No Content\r\n\r\n");
            return;
        }

        // A proxy consultation is anything a proxy must handle: a CONNECT or an
        // absolute-form request. Both are refused for loopback exactly as the
        // real proxy refuses them (invariant 4), so `tunnels` stays 0.
        if line.starts_with("CONNECT ")
            || target.starts_with("http://")
            || target.starts_with("https://")
        {
            shared.proxied.lock().unwrap().push((epoch, line));
            bump(shared, epoch, |proof| proof.accepted += 1);
            let body = format!("proxy refuses loopback target {target}\n");
            let _ = stream.write_all(&response(403, "Forbidden", &body));
            return;
        }

        // Origin-form: the client dialled us directly, so we are the endpoint.
        shared.origin.lock().unwrap().push((epoch, line));
        if target == "/sandbox/intent" {
            let body = format!("{{\"ok\":true,\"nonce\":\"{nonce}\"}}");
            let _ = stream.write_all(&response(200, "OK", &body));
        } else {
            let _ = stream.write_all(&response(404, "Not Found", "unknown endpoint\n"));
        }
    }

    fn response(code: u16, reason: &str, body: &str) -> Vec<u8> {
        format!(
            "HTTP/1.1 {code} {reason}\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .into_bytes()
    }

    /// The wrapper exe beside the test binary (`target/<profile>/`), built by
    /// `cargo build --features mxc-backend --bin saife-launch`.
    fn launcher_under_test() -> PathBuf {
        let exe = std::env::current_exe().expect("current test exe");
        let deps = exe.parent().expect("deps directory");
        let candidates = [
            deps.parent().map(|profile| profile.join(LAUNCHER_EXE_NAME)),
            Some(deps.join(LAUNCHER_EXE_NAME)),
        ];
        for candidate in candidates.into_iter().flatten() {
            if candidate.is_file() {
                return candidate;
            }
        }
        panic!(
            "{LAUNCHER_EXE_NAME} not found near {}: run `cargo build --features mxc-backend \
             --bin saife-launch` first",
            exe.display()
        );
    }

    /// A scratch directory that removes itself, so a failed assertion does not
    /// leave host state behind (the test grants nothing outside it).
    struct Scratch(PathBuf);

    impl Scratch {
        fn named(label: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "sandbox-mxc-{label}-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            // A previous run of the same test in the same process would collide
            // only on the thread id, which is stable per test thread — so start
            // from an empty directory.
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).expect("create scratch dir");
            Self(dir)
        }

        fn new() -> Self {
            Self::named("intent")
        }

        /// A scratch directory whose name carries nothing `cmd.exe` parses
        /// specially.
        ///
        /// P2.2 hands a `.bat` path to `cmd /c "<path>"`, and cmd's `/c`
        /// quote-stripping heuristic gives up on `(` or `)` — which the
        /// `ThreadId(n)` names in [`Scratch::named`] contain. Observed: the child
        /// exited 1 with `Zugriff verweigert` and no stdout, i.e. cmd refused the
        /// command line rather than the script.
        fn plain(label: &str) -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let dir = std::env::temp_dir().join(format!(
                "sandbox-mxc-{label}-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).expect("create scratch dir");
            Self(dir)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn live_input(port: u16, scratch: &Path, launcher: &Path, command: String) -> MxcSessionInput {
        MxcSessionInput {
            command,
            working_directory: Some(scratch.display().to_string()),
            environment: Vec::new(),
            filesystem: MxcFilesystemInput {
                readwrite_paths: vec![scratch.display().to_string()],
                readonly_paths: vec![
                    launcher_grant(launcher).expect("launcher directory"),
                    // The workloads below are System32-resident.
                    r"C:\Windows".to_string(),
                ],
                denied_paths: Vec::new(),
            },
            network: MxcNetworkInput {
                proxy_port: Some(port),
                proxy_token: None,
            },
            // The live legs read the child's output, so they capture it.
            stdio: StdioSelection::Capture,
            timeout_ms: None,
        }
    }

    fn stdout_of(outcome: &SessionOutcome) -> String {
        String::from_utf8_lossy(&outcome.stdout).to_string()
    }

    fn stderr_of(outcome: &SessionOutcome) -> String {
        String::from_utf8_lossy(&outcome.stderr).to_string()
    }

    const CURL: &str = r"C:\Windows\System32\curl.exe";

    /// `TokenElevation` for this process, so the evidence says whether anything
    /// ran elevated. Same signal as `IsInRole(Administrator)` and as
    /// `src/setup.rs::is_elevated` (private to that module).
    fn process_is_elevated() -> bool {
        use windows::Win32::Foundation::{CloseHandle, HANDLE};
        use windows::Win32::Security::{
            GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
        };
        use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
        // SAFETY: the token handle is closed on every path, and the information
        // buffer is exactly the size passed to the API.
        unsafe {
            let mut token = HANDLE::default();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
                return false;
            }
            let mut elevation = TOKEN_ELEVATION::default();
            let mut ret = 0u32;
            let ok = GetTokenInformation(
                token,
                TokenElevation,
                Some(&mut elevation as *mut _ as *mut _),
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut ret,
            );
            let _ = CloseHandle(token);
            ok.is_ok() && elevation.TokenIsElevated != 0
        }
    }

    fn proxy_lines(stdout: &str) -> Vec<String> {
        stdout
            .lines()
            .filter(|line| line.to_ascii_lowercase().contains("proxy"))
            .map(|line| line.trim().to_string())
            .collect()
    }

    // =====================================================================
    // P1 wave 2: proxied / plain-HTTP / blocked / filesystem legs
    // =====================================================================

    /// The body both legs look for, so a 200 from anything else cannot pass.
    const NONCE: &str = "nonce-p1-wave-2";

    /// The session token the live proxies require. URL-unreserved, the shape the
    /// real generator produces (hex).
    const LIVE_TOKEN: &str = "live-session-token-0123456789abcdef";

    fn stamp() -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    }

    /// The host's own LAN address — local, but **not** loopback.
    ///
    /// Invariant 4 forbids the proxy forwarding to a loopback target, and the
    /// live intent test relies on that refusal. A *proxied* round trip therefore
    /// needs an address that is local without being loopback: the container is
    /// told only `127.0.0.1:<proxy>`, the proxy dials this address, and the
    /// listener below is where the request provably arrives.
    fn non_loopback_ipv4() -> std::net::Ipv4Addr {
        let probe = std::net::UdpSocket::bind("0.0.0.0:0").expect("route probe socket");
        // No packet leaves: a connected UDP socket only fixes the route.
        probe.connect("1.1.1.1:80").expect("route probe");
        match probe.local_addr().expect("route probe address").ip() {
            std::net::IpAddr::V4(v4) if !v4.is_loopback() => v4,
            other => panic!(
                "this host has no non-loopback IPv4 (probe address {other}): a proxied round \
                 trip cannot be proven against a loopback target, because the proxy refuses those \
                 by design"
            ),
        }
    }

    /// A local origin server that records the request line it was asked for.
    ///
    /// Each origin answers with **its own** nonce, so "the body came from its own
    /// origin" is a testable claim: two origins answering with one shared string
    /// make a crossed body indistinguishable from a correct one (P1.6(f)).
    struct Origin {
        host: String,
        port: u16,
        nonce: String,
        seen: Arc<Mutex<Vec<String>>>,
        heads: Arc<Mutex<Vec<String>>>,
        stop: Arc<AtomicBool>,
        join: Option<std::thread::JoinHandle<()>>,
    }

    impl Origin {
        fn start() -> Self {
            Self::start_with_nonce(NONCE)
        }

        fn start_with_nonce(nonce: &str) -> Self {
            let nonce = nonce.to_string();
            let ip = non_loopback_ipv4();
            let listener =
                TcpListener::bind((ip, 0)).expect("bind origin on the host's LAN address");
            let port = listener.local_addr().expect("origin address").port();
            let seen = Arc::new(Mutex::new(Vec::new()));
            let heads = Arc::new(Mutex::new(Vec::new()));
            let stop = Arc::new(AtomicBool::new(false));
            let seen_thread = Arc::clone(&seen);
            let heads_thread = Arc::clone(&heads);
            let stop_thread = Arc::clone(&stop);
            let nonce_thread = nonce.clone();
            let join = std::thread::spawn(move || {
                for accepted in listener.incoming() {
                    if stop_thread.load(Ordering::SeqCst) {
                        break;
                    }
                    let Ok(stream) = accepted else { continue };
                    let seen = Arc::clone(&seen_thread);
                    let heads = Arc::clone(&heads_thread);
                    let nonce = nonce_thread.clone();
                    std::thread::spawn(move || serve_origin(stream, &seen, &heads, &nonce));
                }
            });
            Self {
                host: ip.to_string(),
                port,
                nonce,
                seen,
                heads,
                stop,
                join: Some(join),
            }
        }

        /// The body this origin answers with (P1.6(f)).
        fn nonce(&self) -> &str {
            &self.nonce
        }

        fn authority(&self) -> String {
            format!("{}:{}", self.host, self.port)
        }

        fn url(&self, path: &str) -> String {
            format!("http://{}{path}", self.authority())
        }

        fn requests(&self) -> Vec<String> {
            self.seen.lock().map(|s| s.clone()).unwrap_or_default()
        }

        /// Did the origin receive exactly this origin-form GET?
        fn saw(&self, path: &str) -> bool {
            let want = format!("GET {path} HTTP/1.1");
            self.requests().iter().any(|line| line == &want)
        }

        /// The full head the origin received for `path`, verbatim — the evidence
        /// for what the forward path rewrote (target form, `Host`, hop fields).
        fn head_for(&self, path: &str) -> Option<String> {
            let want = format!("GET {path} HTTP/1.1");
            self.heads
                .lock()
                .ok()?
                .iter()
                .find(|head| head.lines().next().map(str::trim) == Some(want.as_str()))
                .cloned()
        }
    }

    impl Drop for Origin {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            let _ = TcpStream::connect((self.host.as_str(), self.port));
            if let Some(join) = self.join.take() {
                let _ = join.join();
            }
        }
    }

    /// Answer one request with the nonce and close. Records the request line and
    /// the whole head verbatim, which is the evidence that the forwarded request
    /// was rewritten to origin-form with the admitted authority as `Host`.
    fn serve_origin(
        mut stream: TcpStream,
        seen: &Mutex<Vec<String>>,
        heads: &Mutex<Vec<String>>,
        nonce: &str,
    ) {
        let _ = stream.set_read_timeout(Some(Duration::from_secs(15)));
        let mut buf: Vec<u8> = Vec::new();
        let mut chunk = [0u8; 1024];
        while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
            match stream.read(&mut chunk) {
                Ok(0) | Err(_) => return,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
            }
            if buf.len() > 16 * 1024 {
                return;
            }
        }
        let head = String::from_utf8_lossy(&buf).to_string();
        let line = head.lines().next().unwrap_or("").trim().to_string();
        if let Ok(mut seen) = seen.lock() {
            seen.push(line);
        }
        if let Ok(mut heads) = heads.lock() {
            heads.push(head.clone());
        }
        let body = nonce;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\
             Connection: close\r\n\r\n{body}",
            body.len()
        );
        let _ = stream.write_all(response.as_bytes());
        let _ = stream.shutdown(std::net::Shutdown::Both);
    }

    // ---- ADR-0004 guardrail 1 (amended 2026-10-22): attributable evidence ----

    /// One `GET /sandbox/probe` carrying a CHOSEN credential (or none).
    ///
    /// A container can only present its own run's token (it rides its proxy URL),
    /// so "somebody else's credential" needs a raw socket — which is exactly the
    /// adversary this pins: any local process, or a session holding a stale token.
    fn probe_with(port: u16, token: Option<&str>) -> String {
        let mut sock = TcpStream::connect(("127.0.0.1", port)).expect("connect the listener");
        sock.set_read_timeout(Some(Duration::from_secs(5)))
            .expect("read timeout");
        let auth = match token {
            Some(token) => {
                let creds =
                    base64::engine::general_purpose::STANDARD.encode(format!("sandbox:{token}"));
                format!("Proxy-Authorization: Basic {creds}\r\n")
            }
            None => String::new(),
        };
        let req = format!("GET /sandbox/probe HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n{auth}\r\n");
        sock.write_all(req.as_bytes()).expect("write the probe");
        let mut out = Vec::new();
        let mut chunk = [0u8; 256];
        while !out.windows(4).any(|w| w == b"\r\n\r\n") {
            match sock.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(n) => out.extend_from_slice(&chunk[..n]),
            }
        }
        String::from_utf8_lossy(&out).into_owned()
    }

    /// **The property the gate exists for.** A session whose ONLY listener contact
    /// used a foreign credential is REFUSED.
    ///
    /// The listener answers the same `407` it gives a credential-less request, so
    /// the launch's epoch has `probes == 0` and guardrail 1 refuses with
    /// `proxy_probe_unmet`. The positive control (this listener's own credential,
    /// `204` and counted) is what makes the refusal mean something: without it a
    /// dead listener would look identical.
    ///
    /// The control runs in its OWN epoch (P3.2a): the refused attempt stays counted
    /// on the first launch's `unauthenticated`, so re-probing the same epoch with
    /// the right credential would prove the listener serves it - which the `204`
    /// below does - while the session would still (correctly) be refused.
    ///
    /// Not `#[ignore]`d: no container is involved — this is the real listener,
    /// the real counters and the real gate.
    #[test]
    fn a_session_whose_only_listener_contact_used_a_foreign_credential_is_refused() {
        let proxy = LiveProxy::start(&[]);
        let counters = proxy.counters();
        let epoch = counters.begin_launch().expect("the launch's epoch");

        // 1. Somebody else's token: refused like a missing one, and uncounted.
        let foreign = probe_with(proxy.port(), Some("a-different-runs-token"));
        println!(
            "EVIDENCE foreign_probe status={:?} proof={:?}",
            foreign.lines().next(),
            counters.proof(epoch)
        );
        assert!(
            foreign.starts_with("HTTP/1.1 407"),
            "a foreign credential must be refused exactly like a missing one: {foreign:?}"
        );
        assert_eq!(
            counters.proof(epoch).probes,
            0,
            "a refused probe must leave no observation, or any local process could satisfy \
             guardrail 1 for a session whose own path is broken: {:?}",
            counters.proof(epoch)
        );
        assert_eq!(
            verify_proxy_proof(counters.proof(epoch), ProofExpectation::Required)
                .expect_err("a foreign-credential probe must not satisfy the gate"),
            GuardError::ProbeUnmet
        );

        counters.close_launch(epoch);

        // 2. Positive control, fresh epoch: this listener's own credential is served
        //    and counted, and a launch whose only contact is that probe passes - so
        //    the refusal above is about the credential, not a dead listener.
        let control = counters.begin_launch().expect("the control's epoch");
        let own = probe_with(proxy.port(), Some(proxy.token().value()));
        println!(
            "EVIDENCE own_probe status={:?} proof={:?}",
            own.lines().next(),
            counters.proof(control)
        );
        assert!(
            own.starts_with("HTTP/1.1 204"),
            "the session's own credential must be served: {own:?}"
        );
        assert_eq!(counters.proof(control).probes, 1, "exactly one observation");
        assert_eq!(
            counters.proof(control).unauthenticated,
            0,
            "nothing but the probe touched this epoch"
        );
        verify_proxy_proof(counters.proof(control), ProofExpectation::Required)
            .expect("a launch probed with its own credential is proven");

        counters.close_launch(control);
    }

    /// One `CONNECT` carrying **no** credential at all, blocking on the status line.
    ///
    /// The WinINet / system-proxy shape (P1.5, P1.8): the container forces the
    /// request to this listener and the client sends no `Proxy-Authorization`
    /// header, so it is answered `407` for ever and the application has no egress
    /// while the proxy path itself is perfectly healthy.
    fn connect_no_auth(port: u16, target: &str) -> String {
        let mut sock = TcpStream::connect(("127.0.0.1", port)).expect("connect the listener");
        sock.set_read_timeout(Some(Duration::from_secs(5)))
            .expect("read timeout");
        let req = format!("CONNECT {target} HTTP/1.1\r\n\r\n");
        sock.write_all(req.as_bytes()).expect("write CONNECT");
        let mut out = Vec::new();
        let mut chunk = [0u8; 512];
        // The status line ends at the first blank line; never read to EOF (a
        // tunnel would keep the socket open).
        while !out.windows(4).any(|w| w == b"\r\n\r\n") {
            match sock.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(n) => out.extend_from_slice(&chunk[..n]),
            }
        }
        String::from_utf8_lossy(&out).into_owned()
    }

    /// **P3.2a, the class the probe amendment re-opened.** A launch whose probe
    /// arrived, whose ONLY other contact with the listener carried no credential,
    /// is REFUSED with `workload_cannot_authenticate`.
    ///
    /// Before this leg the session PASSED on `probes == 1`: the wrapper's probe
    /// proved the path, and nothing asked whether the workload could use it. A GUI
    /// / system-proxy client (WinINet, Windows PowerShell 5.1 - measured in P1.5 and
    /// P1.8) reaches this listener, gets `407` for ever, and the application
    /// silently has no egress: exactly the silent-misconfiguration class guardrail
    /// 1 exists for, so the evidence has to be two-part.
    #[test]
    fn a_probe_ok_session_whose_only_other_contact_was_credential_less_is_refused() {
        let proxy = LiveProxy::start(&[]);
        let counters = proxy.counters();
        let epoch = counters.begin_launch().expect("the launch's epoch");

        // 1. The wrapper's pre-flight probe: the PATH is proven.
        let probe = probe_with(proxy.port(), Some(proxy.token().value()));
        assert!(
            probe.starts_with("HTTP/1.1 204"),
            "the probe must be served: {probe:?}"
        );

        // 2. The workload: a client stack that cannot send the credential.
        let attempt = connect_no_auth(proxy.port(), "api.example.com:443");
        assert!(
            attempt.starts_with("HTTP/1.1 407"),
            "a credential-less CONNECT is refused, and identically every time: {attempt:?}"
        );

        let proof = counters.proof(epoch);
        println!("EVIDENCE credential_less_system_proxy proof={proof:?}");
        assert_eq!(proof.probes, 1, "the probe is the path evidence: {proof:?}");
        assert_eq!(
            (proof.accepted, proof.tunnels),
            (0, 0),
            "a refused attempt is not a consultation: it never reached the policy: {proof:?}"
        );
        assert_eq!(
            proof.unauthenticated, 1,
            "the attempt must be counted on this launch's epoch: {proof:?}"
        );

        let err = verify_proxy_proof(proof, ProofExpectation::Required)
            .expect_err("a session whose only listener contact was credential-less had no egress");
        println!("EVIDENCE refusal reason={err}");
        assert_eq!(err, GuardError::WorkloadCannotAuthenticate);
        assert!(
            err.to_string().contains("workload_cannot_authenticate"),
            "the operator must be told which cause it was: {err}"
        );
        assert!(
            !err.to_string().contains("proxy_probe_unmet"),
            "this is NOT a path failure - the probe arrived: {err}"
        );

        // 3. Positive control, fresh epoch on the SAME listener: probe and nothing
        //    else still passes, so the refusal above is the credential-less
        //    attempt and not the probe leg.
        counters.close_launch(epoch);
        let clean = counters.begin_launch().expect("the control's epoch");
        let probe = probe_with(proxy.port(), Some(proxy.token().value()));
        assert!(probe.starts_with("HTTP/1.1 204"), "{probe:?}");
        println!(
            "EVIDENCE control_probe_only proof={:?}",
            counters.proof(clean)
        );
        verify_proxy_proof(counters.proof(clean), ProofExpectation::Required)
            .expect("a probed session that made no other contact is unaffected");
        counters.close_launch(clean);
    }

    /// **P3.2a: a foreign credential is the same signal.** Lateral movement and a
    /// client stack that cannot authenticate both mean "reached the proxy and
    /// could not use this run's credential", so a probe-ok session whose only
    /// other contact presented somebody else's token is refused too.
    ///
    /// Distinguished from the existing foreign-credential leg (no probe, therefore
    /// `proxy_probe_unmet`): here the path IS proven, so the reason has to be the
    /// new one - the two refusals must not collapse into one string.
    #[test]
    fn a_probe_ok_session_whose_only_other_contact_used_a_foreign_credential_is_refused() {
        let proxy = LiveProxy::start(&[]);
        let counters = proxy.counters();
        let epoch = counters.begin_launch().expect("the launch's epoch");

        let probe = probe_with(proxy.port(), Some(proxy.token().value()));
        assert!(probe.starts_with("HTTP/1.1 204"), "{probe:?}");
        let attempt = cx(
            proxy.port(),
            "a-different-runs-token",
            "api.example.com:443",
        );
        assert!(
            attempt.starts_with("HTTP/1.1 407"),
            "a foreign credential is refused exactly like a missing one: {attempt:?}"
        );

        let proof = counters.proof(epoch);
        println!("EVIDENCE foreign_token_system_proxy proof={proof:?}");
        assert_eq!(proof.probes, 1, "{proof:?}");
        assert_eq!(
            (proof.accepted, proof.unauthenticated),
            (0, 1),
            "the foreign attempt is counted and never a consultation: {proof:?}"
        );
        let err = verify_proxy_proof(proof, ProofExpectation::Required)
            .expect_err("a session that only presented a foreign credential has no egress");
        println!("EVIDENCE refusal reason={err}");
        assert_eq!(err, GuardError::WorkloadCannotAuthenticate);

        counters.close_launch(epoch);
    }

    // ---- P3.4 (A): console passthrough -----------------------------------

    /// **P3.4 (A): an interactive session runs with inherited stdio.**
    ///
    /// The briefed shape: the child inherits this process's stdio, so there is
    /// nothing to capture, and the assertion is the EXIT CODE plus an empty
    /// `stdout` — with inherited stdio the workload's bytes went to the console, not
    /// into the supervisor's buffer. That is the mode's whole point, and for a TUI
    /// it is the same shape: the console is the display and the supervisor waits.
    ///
    /// The control arm is the same child with `Capture`: exit 0 AND the marker in
    /// `stdout`. Without it, "stdout is empty" would also hold for a launch that
    /// simply dropped the output.
    ///
    /// **Which SDK mode the request asks for is pinned by the UNIT test**
    /// (`the_stdio_selection_names_the_sdk_mode_it_asks_for`), not here: this
    /// harness's own stdout is a pipe (`cargo test` captures it), so the child of an
    /// `Inherit` launch legitimately sees a redirected stdout too — the mode is
    /// "a TTY exactly when WE have one", and `[Console]::IsOutputRedirected` reports
    /// the same value in both arms here. The probe is printed, not asserted, so a
    /// reader can see the harness condition rather than mistake it for a finding.
    #[test]
    #[ignore]
    fn an_interactive_session_inherits_the_console_and_still_reports_its_exit_code() {
        let launcher = launcher_under_test();
        let workspace = Scratch::plain("live-inherit");
        let marker = "HELLO-FROM-THE-CONTAINER";

        let run = |stdio: StdioSelection, label: &str| {
            let mut input = live_input(
                0,
                workspace.path(),
                &launcher,
                format!("cmd /c echo {marker}"),
            );
            input.stdio = stdio;
            input.network.proxy_port = None;
            let outcome = launch_session(
                LaunchCounters::new().as_ref(),
                None,
                None,
                &launcher,
                SessionBudget::default(),
                &input,
            )
            .expect("a proxy-less session needs no proof beyond `MustBeAbsent`");
            println!(
                "EVIDENCE {label} exit={:?} stdout={:?} stderr={:?} captured_stdout_is_empty={}",
                outcome.exit_code,
                stdout_of(&outcome).trim(),
                stderr_of(&outcome).trim(),
                outcome.stdout.is_empty()
            );
            outcome
        };

        // ---- the interactive arm ------------------------------------------
        let inherited = run(StdioSelection::Inherit, "stdio_inherit");
        assert_eq!(
            inherited.exit_code,
            Some(0),
            "the child must run to completion with inherited stdio: {inherited:?}"
        );
        assert!(
            inherited.stdout.is_empty(),
            "inherited stdio is NOT captured — that is the point of the mode: {:?}",
            stdout_of(&inherited)
        );

        // ---- the control arm: the same child, captured --------------------
        let captured = run(StdioSelection::Capture, "stdio_capture");
        assert_eq!(
            captured.exit_code,
            Some(0),
            "the captured mode is unchanged for every existing caller: {captured:?}"
        );
        assert!(
            stdout_of(&captured).contains(marker),
            "the captured mode still hands the supervisor the child's output: {:?}",
            stdout_of(&captured)
        );

        // ---- recorded, not asserted: the harness's own stdio ---------------
        //
        // `[Console]::IsOutputRedirected` inside the child, in the CAPTURED arm.
        // `True` here is `cargo test`'s own pipe, not the sandbox: the suite runs
        // with a redirected stdout, so an inherited child inherits a pipe too — the
        // rule is "a TTY exactly when we have one".
        let probe = workspace.path().join("console-probe.bat");
        std::fs::write(
            &probe,
            "@echo off\r\npowershell.exe -NoProfile -Command \"[Console]::IsOutputRedirected\"\r\n",
        )
        .expect("write the console probe");
        let mut input = live_input(
            0,
            workspace.path(),
            &launcher,
            format!("cmd /c \"{}\"", probe.display()),
        );
        input.stdio = StdioSelection::Capture;
        input.network.proxy_port = None;
        let observed = launch_session(
            LaunchCounters::new().as_ref(),
            None,
            None,
            &launcher,
            SessionBudget::default(),
            &input,
        )
        .expect("the probe session must run");
        println!(
            "EVIDENCE console_probe exit={:?} is_output_redirected={:?}",
            observed.exit_code,
            stdout_of(&observed).trim()
        );
    }

    /// **P3.4 (B): a writable grant outside the workspace is honoured.**
    ///
    /// Before P3.4 this session was refused by name (a second writable grant had
    /// "no honest mapping"), which made every tool that keeps state in the profile
    /// unrunnable. The control half matters as much as the positive one: a write
    /// to a directory that was NOT granted must still fail, or the leg would pass
    /// on a container whose filesystem policy does nothing.
    #[test]
    #[ignore]
    fn a_writable_grant_outside_the_workspace_is_honoured_on_a_real_launch() {
        let launcher = launcher_under_test();
        let workspace = Scratch::plain("live-grant-workspace");
        let state = Scratch::plain("live-grant-state");
        let ungranted = Scratch::plain("live-grant-ungranted");
        let written = state.path().join("written-by-the-child.txt");
        let refused = ungranted.path().join("must-not-exist.txt");

        let counters = LaunchCounters::new();
        let mut input = live_input(0, workspace.path(), &launcher, String::new());
        input.filesystem = filesystem_policy(
            workspace.path(),
            &[state.path().to_path_buf()],
            &[
                launcher_grant(&launcher).expect("launcher directory"),
                // The workload is System32-resident.
                r"C:\Windows".to_string(),
            ],
            &[],
            None,
            &launcher,
        )
        .expect("no deny in this session covers a grant");
        input.network.proxy_port = None;
        input.command = format!(
            "cmd /c echo GRANT-OK> \"{}\" & echo NO> \"{}\" & echo TAIL",
            written.display(),
            refused.display()
        );

        let outcome = launch_session(
            counters.as_ref(),
            None,
            None,
            &launcher,
            SessionBudget::default(),
            &input,
        )
        .expect("a proxy-less session needs no proof beyond `MustBeAbsent`");

        let body = std::fs::read_to_string(&written).unwrap_or_default();
        println!(
            "EVIDENCE writable_grant exit={:?} written={:?} ungranted_exists={} proof={:?}",
            outcome.exit_code,
            body.trim(),
            refused.exists(),
            outcome.proxy_proof
        );
        assert_eq!(
            outcome.exit_code,
            Some(0),
            "the session must run: {outcome:?} stderr={:?}",
            stderr_of(&outcome)
        );
        assert!(
            body.contains("GRANT-OK"),
            "the child must be able to WRITE inside the extra root: {body:?}"
        );
        assert!(
            !refused.exists(),
            "a directory that was not granted stays unwritable, or the policy is not doing anything: {}",
            refused.display()
        );
    }

    /// **P3.4 (B), the protection that had to survive: a credential directory.**
    ///
    /// The profile itself is granted read-write (that is what makes a tool with
    /// profile state work), and `~/.ssh` inside it is still denied by
    /// [`PROFILE_SECRET_DIRS`]. The synthetic profile keeps the test out of the
    /// real one; the mechanism is the same deny list, added by the same
    /// `profile_dir` argument.
    #[test]
    #[ignore]
    fn a_secret_directory_inside_a_writable_grant_is_still_denied() {
        let launcher = launcher_under_test();
        let workspace = Scratch::plain("live-secret-workspace");
        let profile = Scratch::plain("live-secret-profile");
        std::fs::create_dir_all(profile.path().join(".ssh")).expect("create .ssh");
        std::fs::create_dir_all(profile.path().join("state")).expect("create state");
        let allowed = profile.path().join("state").join("written.txt");
        let forbidden = profile.path().join(".ssh").join("must-not-exist.txt");

        let counters = LaunchCounters::new();
        let mut input = live_input(0, workspace.path(), &launcher, String::new());
        input.filesystem = filesystem_policy(
            workspace.path(),
            &[profile.path().to_path_buf()],
            &[
                launcher_grant(&launcher).expect("launcher directory"),
                r"C:\Windows".to_string(),
            ],
            &[],
            Some(profile.path()),
            &launcher,
        )
        .expect("a deny BESIDE the grant is expressible");
        input.network.proxy_port = None;
        input.command = format!(
            "cmd /c echo STATE-OK> \"{}\" & echo NO> \"{}\" & echo TAIL",
            allowed.display(),
            forbidden.display()
        );

        let outcome = launch_session(
            counters.as_ref(),
            None,
            None,
            &launcher,
            SessionBudget::default(),
            &input,
        )
        .expect("a proxy-less session needs no proof beyond `MustBeAbsent`");

        println!(
            "EVIDENCE secret_dir exit={:?} state_written={} ssh_written={} policy={:?}",
            outcome.exit_code,
            allowed.exists(),
            forbidden.exists(),
            input.filesystem.denied_paths
        );
        assert!(
            allowed.exists(),
            "the granted tree must be usable, or the deny is not the thing being measured"
        );
        assert!(
            !forbidden.exists(),
            "`~/.ssh` must stay denied even when its PARENT is granted writable: {}",
            forbidden.display()
        );
    }

    /// **P3.4 (C), MEASURED: a stat of an ANCESTOR of a grant is DENIED, and a
    /// read-only ancestor grant is the workaround that works.**
    ///
    /// opencode `lstat`s `C:\Users\<user>` at startup and only holds a grant
    /// deeper inside that tree. Two launches answer the question:
    ///
    /// 1. **Grant only** — a write inside the grant SUCCEEDS (traversal through the
    ///    ancestors is implicit in the policy model) while `if exist` on the
    ///    ancestor and on an intermediate directory is DENIED. `if exist` is
    ///    `GetFileAttributes`, i.e. exactly the `lstat` opencode performs.
    /// 2. **Grant + the ancestor read-only** — the ancestor and the intermediate
    ///    directory are statable, and the credential directories stay unreadable
    ///    because a deny that is a DESCENDANT of the grant is kept (`~/.ssh` etc.).
    ///
    /// **This is a blocker of the SDK's policy vocabulary, not of this mapping.**
    /// PSEC — and the contract above it — express four path classes: read-write,
    /// read-only, deny, and enumerate-without-read (`base_container_helpers.rs:59-63`,
    /// `fs_read_write`/`fs_read_only`/`fs_deny`/`fs_enumerate`). None of them means
    /// "traverse and read attributes, without listing or reading": a read-only
    /// ancestor is the NARROWEST expressible grant that makes the stat work, and it
    /// is still a widening (the ancestor becomes listable and readable). So the
    /// supervisor does not grant ancestors automatically; the operator's documented
    /// remedy is an explicit `--allow <path>:read`, and the built-in credential
    /// denies keep the credentials out of it.
    ///
    /// The probe is a `.bat` written into the granted workspace: one command per
    /// line, results appended to a file the test reads. Shell chaining was NOT
    /// trustworthy here — `%ERRORLEVEL%` inside a `( … & echo %ERRORLEVEL% )` block
    /// is expanded at parse time, and a `&&`/`||` chain after a redirect stopped
    /// reporting, both of which read as "denied" for the wrong reason.
    #[test]
    #[ignore]
    fn an_ancestor_of_a_writable_grant_cannot_be_statted_but_a_readonly_ancestor_works() {
        let launcher = launcher_under_test();
        let Some(profile) = std::env::var_os("USERPROFILE").map(PathBuf::from) else {
            panic!("this leg needs USERPROFILE: it is about the REAL profile chain");
        };
        let workspace = Scratch::plain("live-ancestor-workspace");
        let deep = profile.join(".local").join("share").join(format!(
            "sbox-ancestor-{}-{}",
            std::process::id(),
            {
                static NEXT: AtomicU64 = AtomicU64::new(0);
                NEXT.fetch_add(1, Ordering::Relaxed)
            }
        ));
        std::fs::create_dir_all(&deep).expect("create the deep grant");

        /// Remove the deep grant whatever the assertions do.
        struct Cleanup(PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let _cleanup = Cleanup(deep.clone());

        let script = workspace.path().join("probe.bat");
        let results = workspace.path().join("probe.out");
        let written = deep.join("written-by-the-child.txt");
        let script_body = format!(
            "@echo off\r\n\
             echo PROFILE-VAR=[%USERPROFILE%]\r\n\
             if exist \"{profile}\" (echo ANCESTOR-STAT-OK>>\"{results}\") else (echo ANCESTOR-STAT-DENIED>>\"{results}\")\r\n\
             if exist \"C:\\Windows\" (echo WINDIR-STAT-OK>>\"{results}\") else (echo WINDIR-STAT-DENIED>>\"{results}\")
\
             if exist \"{profile}\\.local\" (echo MID-STAT-OK>>\"{results}\") else (echo MID-STAT-DENIED>>\"{results}\")\r\n\
             attrib \"{profile}\" >nul 2>&1\r\n\
             if errorlevel 1 (echo ATTRIB-DENIED>>\"{results}\") else (echo ATTRIB-OK>>\"{results}\")\r\n\
             dir /b \"{profile}\" >nul 2>&1\r\n\
             if errorlevel 1 (echo ANCESTOR-LIST-DENIED>>\"{results}\") else (echo ANCESTOR-LIST-OK>>\"{results}\")\r\n\
             dir /b \"{profile}\\.ssh\" >nul 2>&1\r\n\
             if errorlevel 1 (echo SECRET-LIST-DENIED>>\"{results}\") else (echo SECRET-LIST-OK>>\"{results}\")\r\n\
             type \"{profile}\\.ssh\\config\" >nul 2>&1\r\n\
             if errorlevel 1 (echo SECRET-READ-DENIED>>\"{results}\") else (echo SECRET-READ-OK>>\"{results}\")\r\n\
             echo DEEP-OK>\"{written}\"\r\n",
            profile = profile.display(),
            results = results.display(),
            written = written.display()
        );
        std::fs::write(&script, script_body).expect("write the probe script");

        let base_readonly = vec![
            launcher_grant(&launcher).expect("launcher directory"),
            // The workload is System32-resident.
            r"C:\Windows".to_string(),
        ];

        let run =
            |readonly: Vec<String>, profile_dir: Option<&Path>, deep_grant: bool, label: &str| {
                let mut input = live_input(
                    0,
                    workspace.path(),
                    &launcher,
                    format!("cmd /c \"{}\"", script.display()),
                );
                let writable: Vec<PathBuf> = if deep_grant {
                    vec![deep.clone()]
                } else {
                    Vec::new()
                };
                input.filesystem = filesystem_policy(
                    workspace.path(),
                    &writable,
                    &readonly,
                    &[],
                    profile_dir,
                    &launcher,
                )
                .expect("no deny covers the deep grant");
                input.network.proxy_port = None;
                let _ = std::fs::remove_file(&results);
                let _ = std::fs::remove_file(&written);
                let outcome = launch_session(
                    LaunchCounters::new().as_ref(),
                    None,
                    None,
                    &launcher,
                    SessionBudget::default(),
                    &input,
                )
                .expect("a proxy-less session needs no proof beyond `MustBeAbsent`");
                let probe = std::fs::read_to_string(&results).unwrap_or_default();
                println!(
                    "EVIDENCE {label} exit={:?} deep_written={} results={:?} stdout={:?}",
                    outcome.exit_code,
                    written.exists(),
                    probe.trim(),
                    stdout_of(&outcome).trim()
                );
                (outcome.exit_code, probe, written.exists())
            };

        // ---- launch 1: the grant alone ------------------------------------
        let (code, probe, deep_written) = run(
            base_readonly.clone(),
            Some(&profile),
            true,
            "ancestor_grant_only",
        );
        assert_eq!(code, Some(0), "the session must run: {probe:?}");
        assert!(
            deep_written,
            "the deep grant must be writable, or nothing below measures the ancestor: {probe:?}"
        );
        assert!(
            probe.contains("ANCESTOR-STAT-DENIED"),
            "MEASURED BEHAVIOUR: mxc-sdk 1.0.1 does not grant read-attributes on an ancestor of a \
             grant, so the `lstat` opencode performs at startup fails. If this assertion starts \
             failing, the SDK gained ancestor traversal — promote it into ADR-0004 and delete the \
             workaround note. {probe:?}"
        );
        assert!(
            probe.contains("SECRET-LIST-DENIED"),
            "nothing was granted above the deep directory, so `.ssh` must be unreadable: {probe:?}"
        );

        // ---- launch 2: the ancestor read-only -----------------------------
        let mut readonly = base_readonly;
        readonly.push(profile.display().to_string());
        let (code, probe, deep_written) =
            run(readonly.clone(), Some(&profile), true, "ancestor_readonly");
        assert_eq!(code, Some(0), "the session must run: {probe:?}");
        assert!(deep_written, "the grant stays writable: {probe:?}");
        // MEASURED, and not what the first draft of this leg assumed: granting the
        // home root read-only makes its CHILDREN statable and the root listable,
        // but the root's OWN `if exist` is still refused — while `Windows` (also a
        // read-only grant, with no deny under it) answers OK in the same session.
        assert!(
            probe.contains("ANCESTOR-STAT-DENIED"),
            "MEASURED: a read-only grant of the home root does NOT make the root itself \
             statable while a credential deny sits under it: {probe:?}"
        );
        assert!(
            probe.contains("MID-STAT-OK"),
            "the children of a read-only grant ARE statable (`.local` answers OK in the same \
             session), which is what isolates the failure to the granted root itself: {probe:?}"
        );
        assert!(
            probe.contains("WINDIR-STAT-OK"),
            "a read-only grant with no deny under it IS statable (`C:\\Windows`), so `if exist` \
             on a directory is not the problem: {probe:?}"
        );
        assert!(
            probe.contains("SECRET-READ-DENIED"),
            "widening the ancestor to read-only must NOT make the credentials READABLE — the deny \
             that sits inside it still wins: {probe:?}"
        );
        assert!(
            probe.contains("SECRET-LIST-OK"),
            "and the LIST result is recorded as measured: a read-only grant of the profile makes \
             `.ssh` NAMES visible (content stays denied) — a widening worth stating: {probe:?}"
        );

        // ---- launch 3: the same grant without the credential denies ---------
        //
        // The arm that isolates the mechanism: with the profile granted read-only
        // and NO deny inside it, the home root becomes statable. That proves the
        // ancestor refusal is caused by a DENY SITTING UNDER THE GRANT (the
        // credentials), not by the grant being the ancestor of a readwrite path.
        let (code, probe, deep_written) =
            run(readonly.clone(), None, true, "ancestor_readonly_no_denies");
        assert_eq!(code, Some(0), "the session must run: {probe:?}");
        assert!(deep_written, "the grant stays writable: {probe:?}");
        assert!(
            probe.contains("ANCESTOR-STAT-DENIED"),
            "MEASURED: the refusal is not caused by the credential denies — it survives with none \
             of them in the policy: {probe:?}"
        );

        // ---- launch 4: the ancestor read-only, nothing granted beneath it ---
        //
        // The last arm isolates WHY the granted root itself is refused: with no
        // deeper grant under the profile, a read-only grant of it IS statable. That
        // makes the mechanism a GRANT BENEATH the granted root (the nested grant a
        // profile-state tool needs), not the root being special.
        let (code, probe, deep_written) =
            run(readonly, Some(&profile), false, "ancestor_readonly_flat");
        assert!(
            !deep_written,
            "this arm grants no deep directory, so nothing may be written there: {probe:?}"
        );
        assert_eq!(
            code,
            Some(1),
            "the probe script's last line writes into an ungranted directory, so the session \
             exits non-zero — that is the arm working, not failing: {probe:?}"
        );
        assert!(
            probe.contains("ANCESTOR-STAT-DENIED"),
            "MEASURED: the home root's own stat is still refused with a read-only grant and no deny \
             under it. The one grant that still sits beneath it is the LAUNCHER's directory (the \
             wrapper lives under `~\\tools`), so the standing hypothesis is 'a grant beneath the \
             granted root refuses the root's own stat' — NOT tested further here, because a \
             profile-state tool always has such a grant: {probe:?}"
        );
    }

    /// **P3.2a, the other direction: a policy denial is NOT a misconfiguration.**
    /// A launch whose workload authenticated and was then DENIED must still PASS -
    /// the credential path worked, the denial is the guardrail doing its job.
    ///
    /// Without this leg the new rule could drift into refusing every session that
    /// was denied anything, which would make `--allow-domain` unusable.
    #[test]
    fn a_probe_ok_session_whose_authenticated_connect_was_denied_still_passes() {
        let proxy = LiveProxy::start(&[]);
        let counters = proxy.counters();
        let epoch = counters.begin_launch().expect("the launch's epoch");

        let probe = probe_with(proxy.port(), Some(proxy.token().value()));
        assert!(probe.starts_with("HTTP/1.1 204"), "{probe:?}");
        let denied = cx(proxy.port(), proxy.token().value(), "api.example.com:443");
        assert!(
            denied.starts_with("HTTP/1.1 403"),
            "the workload authenticated and the POLICY denied it: {denied:?}"
        );

        let proof = counters.proof(epoch);
        println!("EVIDENCE authenticated_denied proof={proof:?}");
        assert_eq!(
            (proof.accepted, proof.tunnels),
            (1, 0),
            "a consultation that was denied is recorded, and no tunnel is claimed: {proof:?}"
        );
        assert_eq!(
            proof.unauthenticated, 0,
            "a client that authenticates is never counted here: {proof:?}"
        );
        verify_proxy_proof(proof, ProofExpectation::Required)
            .expect("an authenticated-but-denied workload used the proxy correctly");

        counters.close_launch(epoch);
    }

    /// **P3.2a: the 407-then-retry handshake is not a failure.** A .NET 8 /
    /// pwsh 7 managed client legitimately makes ONE credential-less attempt per
    /// connection and authenticates only after the `Proxy-Authenticate: Basic`
    /// challenge (P1.8), so this session must PASS.
    ///
    /// This is why the gate reads `unauthenticated` TOGETHER with `accepted`
    /// rather than demanding zero: `unauthenticated > 0` with an authenticated
    /// consultation is the handshake working, `> 0` with none is a client stack
    /// that can never use the proxy. Pin both, or the rule drifts into refusing the
    /// one managed shape the design supports.
    #[test]
    fn a_managed_client_that_authenticates_after_the_407_challenge_is_not_refused() {
        let proxy = LiveProxy::start(&[]);
        let counters = proxy.counters();
        let epoch = counters.begin_launch().expect("the launch's epoch");

        let probe = probe_with(proxy.port(), Some(proxy.token().value()));
        assert!(probe.starts_with("HTTP/1.1 204"), "{probe:?}");
        // 1. The unauthenticated first attempt: refused, but challenged.
        let first = connect_no_auth(proxy.port(), "api.example.com:443");
        assert!(first.starts_with("HTTP/1.1 407"), "{first:?}");
        assert!(
            first.contains("Proxy-Authenticate: Basic"),
            "the challenge is what makes the retry authenticate: {first:?}"
        );
        // 2. The retry, with the credential the URL carried all along: a real
        //    consultation, denied by policy (the gate's concern is the credential).
        let retry = cx(proxy.port(), proxy.token().value(), "api.example.com:443");
        assert!(retry.starts_with("HTTP/1.1 403"), "{retry:?}");

        let proof = counters.proof(epoch);
        println!("EVIDENCE managed_407_handshake proof={proof:?}");
        assert_eq!(
            (proof.probes, proof.unauthenticated, proof.accepted),
            (1, 1, 1),
            "one challenged attempt plus one authenticated consultation: {proof:?}"
        );
        verify_proxy_proof(proof, ProofExpectation::Required)
            .expect("the 407 handshake is how every supported managed client authenticates");

        counters.close_launch(epoch);
    }

    /// **P3.2a: the count is per EPOCH, not per listener.** Two sequential launches
    /// on one listener: the first makes credential-less attempts, the second is
    /// clean - and the second PASSES.
    ///
    /// Reusing the listener-lifetime `no_token`/`foreign_token` budgets would have
    /// refused launch N+1 on launch N's refusals, which is why the proof counter is
    /// its own epoch-scoped field.
    #[test]
    fn the_unauthenticated_count_is_per_epoch_so_a_second_launch_starts_clean() {
        let proxy = LiveProxy::start(&[]);
        let counters = proxy.counters();

        // Launch 1: two credential-less attempts, no probe.
        let first = counters.begin_launch().expect("the first launch's epoch");
        let attempt = connect_no_auth(proxy.port(), "api.example.com:443");
        assert!(attempt.starts_with("HTTP/1.1 407"), "{attempt:?}");
        let attempt = connect_no_auth(proxy.port(), "api.anthropic.com:443");
        assert!(attempt.starts_with("HTTP/1.1 407"), "{attempt:?}");
        assert_eq!(
            counters.proof(first).unauthenticated,
            2,
            "{:?}",
            counters.proof(first)
        );
        counters.close_launch(first);

        // Launch 2: probed, clean. It must inherit NOTHING.
        let second = counters.begin_launch().expect("the second launch's epoch");
        let probe = probe_with(proxy.port(), Some(proxy.token().value()));
        assert!(probe.starts_with("HTTP/1.1 204"), "{probe:?}");
        let proof = counters.proof(second);
        println!("EVIDENCE per_epoch first={first} second={second} proof={proof:?}");
        assert_eq!(
            proof.unauthenticated, 0,
            "a second launch must not inherit the first's refusals: {proof:?}"
        );
        verify_proxy_proof(proof, ProofExpectation::Required)
            .expect("the second launch is clean and must pass");

        // The first epoch's record is frozen, not reset: the evidence for launch 1
        // still reads what launch 1 did.
        assert_eq!(
            counters.counters(first).map(|c| c.unauthenticated),
            Some(2),
            "closing an epoch freezes it; it must never be zeroed by a later launch"
        );
        assert_eq!(
            counters.counters(second),
            Some(crate::net::proxy::LaunchProofCounters {
                consultations: 0,
                upstream_established: 0,
                probes: 1,
                unauthenticated: 0,
            }),
            "the second epoch counts only its own traffic"
        );

        counters.close_launch(second);
    }

    /// **P3.2a: `--block-net` is unaffected.** The new leg is scoped to the
    /// `Required` (proxy-configured) expectation.
    ///
    /// A proxy-less session has no listener to authenticate to, so its question -
    /// "did anything go out?" - is unchanged: `MustBeAbsent` still fails a
    /// consultation and still ignores the credential counters, which for a blocked
    /// session can only ever be zero.
    #[test]
    fn block_net_is_unaffected_by_the_unauthenticated_leg() {
        let refused = ProxyProof {
            accepted: 1,
            tunnels: 0,
            probes: 0,
            unauthenticated: 0,
        };
        assert_eq!(
            verify_proxy_proof(refused, ProofExpectation::MustBeAbsent)
                .expect_err("a blocked session that went out is still refused"),
            GuardError::ProxyConsultedUnexpectedly
        );
        let untouched = ProxyProof {
            accepted: 0,
            tunnels: 0,
            probes: 0,
            unauthenticated: 3,
        };
        verify_proxy_proof(untouched, ProofExpectation::MustBeAbsent).expect(
            "MustBeAbsent is the no-proxy leg: it neither probes nor authenticates, and the \
             new counter cannot make a blocked session refuse itself",
        );
    }

    /// A real session proxy (`127.0.0.1:0`, this process's own listener) plus the
    /// audit/learned scaffolding it needs.
    struct LiveProxy {
        handle: crate::net::proxy::ProxyHandle,
        sid: String,
        /// This listener's own run token: the only credential it accepts.
        token: RunToken,
        learned_base: PathBuf,
        /// The listener's audit writer, shared so a test can write the session's
        /// root into the same chain the listener appends CONNECT leaves to (P2.3).
        writer: Arc<crate::audit::AuditWriter>,
    }

    impl LiveProxy {
        /// A listener with a credential of its own.
        ///
        /// Minted, not a constant: `spawn` refuses a token that is already live
        /// (P1.6(b)) and the live tests share one process, so a fixed value would
        /// make them refuse each other as soon as two run in parallel.
        fn start(allow: &[&str]) -> Self {
            Self::start_with_token(allow, RunToken::issue().expect("mint a live token"))
        }

        /// The same listener with a run token of its own (P1.4's two-run test
        /// needs two sessions that must not be able to speak for each other).
        fn start_with_token(allow: &[&str], token: RunToken) -> Self {
            // Never called: a session that expects this listener's allow-list to
            // answer never prompts. A dialog that reports itself unavailable makes
            // an accidental prompt a denial rather than a hang.
            let dialog: DialogFn = Arc::new(|_request| Err(DialogUnavailable));
            Self::start_with(allow, token, false, dialog)
        }

        /// A listener whose D-3.5 prompt really fires (P2.2 leg 2), with the
        /// dialog seam supplied by the caller: the seam is the only place that
        /// sees what the user would be shown for a consultation.
        fn start_prompting(allow: &[&str], dialog: DialogFn) -> Self {
            Self::start_with(
                allow,
                RunToken::issue().expect("mint a live token"),
                true,
                dialog,
            )
        }

        /// The one constructor: credential, prompt posture, dialog seam.
        fn start_with(
            allow: &[&str],
            token: RunToken,
            prompt_enabled: bool,
            dialog: DialogFn,
        ) -> Self {
            let learned_base = std::env::temp_dir().join(format!(
                "sandbox-mxc-live-learned-{}-{}",
                std::process::id(),
                stamp()
            ));
            std::fs::create_dir_all(&learned_base).expect("learned base");
            let learned = Arc::new(Mutex::new(
                LearnedStore::load_in(&learned_base, Some("live")).expect("learned store"),
            ));
            let intent = Arc::new(IntentRegistry::new(DEFAULT_TTL));
            let prompt = crate::net::proxy::PromptGate {
                enabled: prompt_enabled,
                config: PromptConfig {
                    timeout: Duration::from_secs(1),
                    on_unavailable: PromptPolicy::Deny,
                },
                coordinator: Arc::new(PromptCoordinator::with_dialog(dialog)),
                intent,
                learned,
            };
            let sid = format!("test-mxc-live-{}-{}", std::process::id(), stamp());
            let writer =
                Arc::new(crate::audit::AuditWriter::open(&sid, false).expect("audit writer"));
            let handle = crate::net::proxy::spawn(crate::net::proxy::ProxyConfig {
                session_id: sid.clone(),
                token: token.clone(),
                allow_domain: allow.iter().map(|s| s.to_string()).collect(),
                deny_domain: Vec::new(),
                upstream: None,
                writer: writer.clone(),
                prompt,
                facade: std::sync::Arc::new(crate::plugin::FacadeRegistry::new()),
            })
            .expect("spawn the session proxy");
            Self {
                handle,
                sid,
                token,
                learned_base,
                writer,
            }
        }

        fn port(&self) -> u16 {
            self.handle.port
        }

        /// This listener's credential, for the child's proxy URL and for the
        /// cross-run refusal legs below.
        fn token(&self) -> &RunToken {
            &self.token
        }

        fn counters(&self) -> Arc<crate::net::proxy::LaunchCounters> {
            self.handle.counters()
        }
    }

    impl Drop for LiveProxy {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(crate::audit::audit_log_path(&self.sid));
            let _ = std::fs::remove_dir_all(&self.learned_base);
        }
    }

    /// A session input built through the **production** policy: workspace-only
    /// readwrite, `denied_paths` from [`filesystem_policy`], and the launcher's
    /// directory as a read-only grant — the policy adds it before filtering the
    /// deny list, so the grant set the request ships is the one the filter saw.
    fn session_input(
        scratch: &Path,
        launcher: &Path,
        denies: &[String],
        command: String,
        proxy_port: Option<u16>,
    ) -> MxcSessionInput {
        let profile = std::env::var_os("USERPROFILE").map(PathBuf::from);
        let filesystem = filesystem_policy(
            scratch,
            &[],
            // System32-resident workloads (cmd/curl) need the system directory.
            &[r"C:\Windows".to_string()],
            denies,
            profile.as_deref(),
            launcher,
        )
        .expect("no deny in this session's configuration contains a grant");
        MxcSessionInput {
            command,
            working_directory: Some(scratch.display().to_string()),
            environment: Vec::new(),
            filesystem,
            network: MxcNetworkInput {
                proxy_port,
                proxy_token: None,
            },
            // An explicit budget: `None` means no deadline at all (D5), which is
            // wrong for a test that could otherwise hang.
            timeout_ms: Some(180_000),
            // These sessions read the child's output, so they capture it.
            stdio: StdioSelection::Capture,
        }
    }

    fn trace_of(path: &Path) -> String {
        std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
    }

    #[test]
    #[ignore = "launches real ProcessContainers; run: cargo test --features mxc-backend -- --ignored"]
    fn intent_endpoint_is_reachable_from_a_container_and_no_proxy_arrives() {
        let launcher = launcher_under_test();
        let endpoint = Endpoint::start("nonce-p1-wave-1");
        let proof = LiveProof {
            shared: Arc::clone(&endpoint.shared),
        };
        let scratch = Scratch::new();
        let scratch_dir = scratch.path().to_path_buf();

        println!("EVIDENCE launcher={}", launcher.display());
        println!(
            "EVIDENCE elevated={} (TokenElevation of the driving process)",
            process_is_elevated()
        );
        println!(
            "EVIDENCE platform_support={}",
            serde_json::to_string(&v1::platform_support()).unwrap_or_else(|e| e.to_string())
        );
        println!(
            "EVIDENCE endpoint_port={} (proxy and intent endpoint share the listener)",
            endpoint.port
        );

        // An evidence run measures what dispatched; the product rule (`Exactly`) is
        // pinned by the unit tests and by the live refusal test.
        let backend = MxcBackend::new(
            &proof,
            Some(endpoint.port),
            &launcher,
            TierExpectation::Recorded,
        )
        .with_proxy_token(LIVE_TOKEN)
        .with_budget(SessionBudget::new(
            Duration::from_secs(30),
            Duration::from_secs(80),
            Duration::from_secs(10),
        ));

        // ---- 1. the child sees NO_PROXY and the SDK's own proxy variables ----
        let outcome = backend
            .launch(
                &live_input(
                    endpoint.port,
                    &scratch_dir,
                    &launcher,
                    "cmd /c set".to_string(),
                ),
                ProofExpectation::MustBeAbsent,
            )
            .expect("environment dump launch");
        let env_dump = stdout_of(&outcome);
        println!(
            "EVIDENCE env_probe exit={:?} success={} proof={:?} proxy_env_lines={:?}",
            outcome.exit_code,
            outcome.success(),
            outcome.proxy_proof,
            proxy_lines(&env_dump)
        );
        assert!(
            outcome.success(),
            "the environment probe must pass guardrail 1: {outcome:?}"
        );
        assert!(
            proxy_lines(&env_dump)
                .iter()
                .any(|line| line == "NO_PROXY=localhost,127.0.0.1,::1"),
            "the child must have NO_PROXY from the launcher: {:?}",
            proxy_lines(&env_dump)
        );
        assert!(
            proxy_lines(&env_dump)
                .iter()
                .any(|line| line.eq_ignore_ascii_case(&format!(
                    "HTTP_PROXY=http://sandbox:{LIVE_TOKEN}@127.0.0.1:{}",
                    endpoint.port
                ))),
            "the SDK's proxy variable must be present WITH the session token (our proxy \
             authenticates every consultation), otherwise NO_PROXY proves nothing: {:?}",
            proxy_lines(&env_dump)
        );

        // ---- 1b. a lowercase lookup resolves to the same value ----
        // Windows environment names are case-insensitive, so `NO_PROXY` and
        // `no_proxy` are one entry; this asserts the spelling a POSIX-emulation
        // client reads resolves, rather than claiming two blocks entries.
        let outcome = backend
            .launch(
                &live_input(
                    endpoint.port,
                    &scratch_dir,
                    &launcher,
                    "cmd /c echo lower=%no_proxy%".to_string(),
                ),
                ProofExpectation::MustBeAbsent,
            )
            .expect("lowercase no_proxy lookup launch");
        let lower = stdout_of(&outcome);
        println!(
            "EVIDENCE no_proxy_lookup exit={:?} stdout={:?}",
            outcome.exit_code,
            lower.trim()
        );
        assert!(
            lower.contains("lower=localhost,127.0.0.1,::1"),
            "a lowercase `no_proxy` lookup must resolve to the loopback list: {lower:?}"
        );

        // ---- 2. the intent endpoint is reachable, directly, from the container ----
        let command = format!("{CURL} -sS -f --max-time 20 {}", endpoint.url());
        let outcome = backend
            .launch(
                &live_input(endpoint.port, &scratch_dir, &launcher, command),
                ProofExpectation::MustBeAbsent,
            )
            .expect("intent endpoint launch");
        let epoch = proof.last_epoch();
        let out = stdout_of(&outcome);
        println!(
            "EVIDENCE intent_get epoch={epoch} exit={:?} stdout={:?} stderr={:?} \
             origin_requests={:?} proxy_consultations={:?}",
            outcome.exit_code,
            out.trim(),
            stderr_of(&outcome),
            endpoint.origin_requests(epoch),
            endpoint.proxy_consultations(epoch)
        );
        assert_eq!(outcome.exit_code, Some(0), "curl failed: {outcome:?}");
        assert!(
            out.contains("nonce-p1-wave-1"),
            "the child's response must come from our endpoint: {out:?}"
        );
        assert!(
            endpoint
                .origin_requests(epoch)
                .iter()
                .any(|line| line.contains("GET /sandbox/intent")),
            "the endpoint must have been called directly (origin form): {:?}",
            endpoint.origin_requests(epoch)
        );
        assert!(
            endpoint.proxy_consultations(epoch).is_empty(),
            "nothing may go through the proxy: {:?}",
            endpoint.proxy_consultations(epoch)
        );
        println!(
            "EVIDENCE guardrail1 epoch={epoch} proof={:?} expectation={:?} closed={} \
             tier={:?} needs_dacl_augmentation={:?}",
            outcome.proxy_proof,
            outcome.expectation,
            endpoint.closed(epoch),
            outcome.tier.tier,
            outcome.tier.needs_dacl_augmentation
        );
        assert!(endpoint.closed(epoch), "the launch epoch must be closed");

        // ---- 3. A/B control: ignore NO_PROXY and the request IS proxied ----
        // Without this leg the positive result above would not show that the
        // proxy is genuinely in the path (`--noproxy ""` empties the list).
        let command = format!(
            r#"{CURL} -sS -f --noproxy "" --max-time 20 {}"#,
            endpoint.url()
        );
        // Amended 2026-10-22: this launch now SUCCEEDS, and that is the point.
        // Its wrapper probed, so its path to the listener is proven; the refused
        // loopback CONNECT is recorded detail (`tunnels == 0`), no longer the
        // gate. What the leg still proves is the A/B it exists for: with
        // NO_PROXY ignored the child's request reached the PROXY (and was refused
        // there as a loopback target) instead of the endpoint.
        let outcome = backend
            .launch(
                &live_input(endpoint.port, &scratch_dir, &launcher, command),
                ProofExpectation::Required,
            )
            .expect("a session whose probe arrived passes, whatever its workload then did");
        let epoch = proof.last_epoch();
        println!(
            "EVIDENCE ab_control epoch={epoch} success={} proof={:?} proxy_consultations={:?} \
             origin_requests={:?}",
            outcome.success(),
            outcome.proxy_proof,
            endpoint.proxy_consultations(epoch),
            endpoint.origin_requests(epoch)
        );
        assert_eq!(
            outcome.proxy_proof.probes, 1,
            "the wrapper's own probe is the launch's evidence: {:?}",
            outcome.proxy_proof
        );
        assert!(
            !endpoint.proxy_consultations(epoch).is_empty(),
            "with NO_PROXY ignored, the request must reach the proxy"
        );
        assert_eq!(
            outcome.proxy_proof.tunnels, 0,
            "a loopback target is refused by the proxy, so nothing is established upstream: \
             {:?}",
            outcome.proxy_proof
        );
        assert!(
            !endpoint
                .origin_requests(epoch)
                .iter()
                .any(|line| line.contains("/sandbox/intent")),
            "with NO_PROXY ignored, no intent request may reach the endpoint directly: {:?}",
            endpoint.origin_requests(epoch)
        );
        // The GATE passed (this launch returned `Ok`), which is what the leg is
        // about. `success()` also demands exit 0 and must NOT: `curl -f` exits 22
        // because the proxy refused the request with 403 — the A/B's whole point.
        assert_eq!(
            outcome.exit_code,
            Some(22),
            "curl must report the proxy's 403 as its own failure: {outcome:?}"
        );
        assert!(
            verify_proxy_proof(outcome.proxy_proof, outcome.expectation).is_ok(),
            "guardrail 1 must pass on the probe, whatever the workload's request got: {:?}",
            outcome.proxy_proof
        );

        // ---- 4. the workload's own exit code is propagated unchanged ----
        let outcome = backend
            .launch(
                &live_input(
                    endpoint.port,
                    &scratch_dir,
                    &launcher,
                    "cmd /c exit 9".to_string(),
                ),
                ProofExpectation::MustBeAbsent,
            )
            .expect("exit-code launch");
        println!(
            "EVIDENCE exit_code_propagation exit={:?}",
            outcome.exit_code
        );
        assert_eq!(
            outcome.exit_code,
            Some(9),
            "the wrapper must propagate the workload's exit code: {outcome:?}"
        );

        // ---- 5. a failed spawn is a distinct exit code plus a stderr line ----
        let outcome = backend
            .launch(
                &live_input(
                    endpoint.port,
                    &scratch_dir,
                    &launcher,
                    "definitely-not-a-program-p1.exe --flag".to_string(),
                ),
                ProofExpectation::MustBeAbsent,
            )
            .expect("a spawn failure is a normal exit, not a launch error");
        let err_out = stderr_of(&outcome);
        println!(
            "EVIDENCE spawn_failure exit={:?} stderr={:?}",
            outcome.exit_code,
            err_out.trim()
        );
        assert_eq!(
            outcome.exit_code,
            Some(127),
            "a failed spawn must be its own non-zero code: {outcome:?}"
        );
        assert!(
            err_out.contains("saife-launch: failed to start"),
            "the failure must be named on stderr: {err_out:?}"
        );

        println!(
            "EVIDENCE done: intent endpoint reachable unelevated through the launcher, NO_PROXY delivered"
        );
    }
    /// The four wave-2 legs, unelevated, against the **real** supervisor proxy
    /// (a real `127.0.0.1:0` listener with its own counters) and a real local
    /// origin:
    ///
    /// 1. a CONNECT session reaches the origin and proves a tunnel;
    /// 2. a plain-HTTP (absolute-form, **no CONNECT**) session reaches the origin
    ///    and *also* proves upstream establishment — the counting fix in A;
    /// 3. a proxy-less session passes `MustBeAbsent` and cannot reach the origin;
    /// 4. the filesystem policy: the granted workspace is writable, a denied path
    ///    and an ungranted path are not, and `C:\Windows` stays readable (the
    ///    recorded additive-grants caveat).
    #[test]
    #[ignore = "launches real ProcessContainers and a real proxy; run: cargo test --features mxc-backend -- --ignored"]
    fn proxied_plain_http_blocked_and_filesystem_legs_are_proven() {
        let launcher = launcher_under_test();
        let origin = Origin::start();
        let proxy = LiveProxy::start(&[origin.host.as_str()]);
        let counters = proxy.counters();
        let scratch = Scratch::named("legs");
        let secret = Scratch::named("legs-secret");
        let scratch_dir = scratch.path().to_path_buf();
        let secret_dir = secret.path().to_path_buf();

        std::fs::write(secret_dir.join("secret.txt"), "top-secret").expect("write the secret");
        let denies = vec![secret_dir.display().to_string()];

        println!(
            "EVIDENCE elevated={} launcher={} proxy_port={} origin={}",
            process_is_elevated(),
            launcher.display(),
            proxy.port(),
            origin.authority()
        );
        println!(
            "EVIDENCE launcher_grant={:?} (filesystem_policy inserts it before filtering denies)",
            launcher_grant(&launcher)
        );
        let policy = filesystem_policy(
            &scratch_dir,
            &[],
            &[r"C:\Windows".to_string()],
            &denies,
            std::env::var_os("USERPROFILE")
                .map(PathBuf::from)
                .as_deref(),
            &launcher,
        )
        .expect("no deny in this session's configuration contains a grant");
        println!("EVIDENCE filesystem_policy={policy:?}");
        // Asserted, not merely printed: the grant without which the container
        // cannot execute the launcher, and the four built-in credential denies
        // (item (f): an operator whose workspace sits inside one of them gets a
        // refusal naming a path they never configured).
        let grant = launcher_grant(&launcher).expect("the launcher has a directory");
        assert!(
            policy
                .readonly_paths
                .iter()
                .any(|kept| path_key(kept) == path_key(&grant)),
            "the launcher grant must ship in the policy: {:?}",
            policy.readonly_paths
        );
        match std::env::var_os("USERPROFILE").map(PathBuf::from) {
            Some(profile) => {
                for dir in PROFILE_SECRET_DIRS {
                    let expected = profile.join(dir).display().to_string();
                    assert!(
                        policy
                            .denied_paths
                            .iter()
                            .any(|denied| path_key(denied) == path_key(&expected)),
                        "the built-in {dir} deny must survive the grant filter: {:?}",
                        policy.denied_paths
                    );
                }
            }
            None => println!("EVIDENCE credential_denies skipped: no USERPROFILE"),
        }

        // ---- leg 1: CONNECT through the proxy to the local origin ----------
        let trace = scratch_dir.join("leg-connect.trace");
        let command = format!(
            "{CURL} -sS -f --max-time 25 --proxytunnel --trace-ascii \"{}\" {}",
            trace.display(),
            origin.url("/proxied")
        );
        let outcome = launch_session(
            counters.as_ref(),
            Some(proxy.port()),
            Some(proxy.token().value()),
            &launcher,
            SessionBudget::default(),
            &session_input(
                &scratch_dir,
                &launcher,
                &denies,
                command,
                Some(proxy.port()),
            ),
        )
        .expect("the CONNECT leg must pass guardrail 1");
        println!(
            "EVIDENCE connect_leg exit={:?} success={} proof={:?} expectation={:?} tier={:?} \
             stdout={:?} stderr={:?}",
            outcome.exit_code,
            outcome.success(),
            outcome.proxy_proof,
            outcome.expectation,
            outcome.tier.tier,
            stdout_of(&outcome).trim(),
            stderr_of(&outcome).trim()
        );
        assert_eq!(outcome.exit_code, Some(0), "curl failed: {outcome:?}");
        assert!(
            stdout_of(&outcome).contains(NONCE),
            "the body must come from the origin: {:?}",
            stdout_of(&outcome)
        );
        assert!(
            origin.saw("/proxied"),
            "the origin must have served the tunnelled request: {:?}",
            origin.requests()
        );
        assert!(
            outcome.proxy_proof.accepted >= 1,
            "the proxy must have been consulted: {:?}",
            outcome.proxy_proof
        );
        assert!(
            outcome.proxy_proof.tunnels >= 1,
            "a live CONNECT must establish an upstream tunnel: {:?}",
            outcome.proxy_proof
        );
        assert_eq!(outcome.expectation, ProofExpectation::Required);
        assert!(outcome.success(), "a proven launch must report success");
        let connect_trace = trace_of(&trace);
        assert!(
            connect_trace.contains(&format!("CONNECT {}", origin.authority())),
            "the child's own bytes must show a CONNECT to the proxy: {connect_trace:?}"
        );
        println!(
            "EVIDENCE connect_leg_child_bytes={:?}",
            connect_trace
                .lines()
                .find(|line| line.contains("CONNECT "))
                .unwrap_or("")
                .trim()
        );

        // ---- leg 2: plain HTTP, absolute-form, NO CONNECT -------------------
        let trace = scratch_dir.join("leg-plain.trace");
        let command = format!(
            "{CURL} -sS -f --max-time 25 --trace-ascii \"{}\" {}",
            trace.display(),
            origin.url("/plain")
        );
        let outcome = launch_session(
            counters.as_ref(),
            Some(proxy.port()),
            Some(proxy.token().value()),
            &launcher,
            SessionBudget::default(),
            &session_input(
                &scratch_dir,
                &launcher,
                &denies,
                command,
                Some(proxy.port()),
            ),
        )
        .expect("the plain-HTTP leg must pass guardrail 1");
        println!(
            "EVIDENCE plain_http_leg exit={:?} success={} proof={:?} expectation={:?} \
             stdout={:?} stderr={:?}",
            outcome.exit_code,
            outcome.success(),
            outcome.proxy_proof,
            outcome.expectation,
            stdout_of(&outcome).trim(),
            stderr_of(&outcome).trim()
        );
        assert_eq!(outcome.exit_code, Some(0), "curl failed: {outcome:?}");
        assert!(stdout_of(&outcome).contains(NONCE));
        assert!(
            origin.saw("/plain"),
            "the origin must have served the forwarded request: {:?}",
            origin.requests()
        );
        // Origin-side evidence for the rewrite: what the *origin* saw, not what
        // the client sent. The Host must be the admitted authority and our proxy
        // credential must be absent.
        let plain_head = origin
            .head_for("/plain")
            .expect("the origin must record the head it was sent");
        println!("EVIDENCE plain_http_leg_origin_head={plain_head:?}");
        let want_host = format!("Host: {}", origin.authority());
        assert!(
            plain_head
                .lines()
                .any(|line| line.trim_end() == want_host.as_str()),
            "the origin must see the admitted authority as Host: {plain_head:?}"
        );
        assert!(
            !plain_head
                .to_ascii_lowercase()
                .contains("proxy-authorization"),
            "our proxy credential must never reach an origin: {plain_head:?}"
        );
        assert!(
            outcome.proxy_proof.accepted >= 1,
            "a plain-HTTP forward is a proxy consultation: {:?}",
            outcome.proxy_proof
        );
        assert!(
            outcome.proxy_proof.tunnels >= 1,
            "`tunnels` means 'upstream established': a completed plain-HTTP forward must satisfy \
             it, otherwise Required fails a working session: {:?}",
            outcome.proxy_proof
        );
        assert!(outcome.success());
        let plain_trace = trace_of(&trace);
        assert!(
            plain_trace.contains(&format!("GET {}", origin.url("/plain"))),
            "the child must have sent an ABSOLUTE-form request to the proxy: {plain_trace:?}"
        );
        println!(
            "EVIDENCE plain_http_leg_child_bytes={:?} contains_connect={}",
            plain_trace
                .lines()
                .find(|line| line.contains("GET "))
                .unwrap_or("")
                .trim(),
            plain_trace.contains("CONNECT ")
        );
        assert!(
            !plain_trace.contains("CONNECT "),
            "this leg must not involve CONNECT at all: {plain_trace:?}"
        );

        // ---- leg 3: blocked session (no proxy) -----------------------------
        let command = format!(
            "{CURL} -sS -f --max-time 8 --connect-timeout 5 {}",
            origin.url("/blocked")
        );
        let outcome = launch_session(
            counters.as_ref(),
            None,
            None,
            &launcher,
            SessionBudget::default(),
            &session_input(&scratch_dir, &launcher, &denies, command, None),
        )
        .expect("a blocked session that stayed offline passes MustBeAbsent");
        println!(
            "EVIDENCE blocked_leg exit={:?} proof={:?} expectation={:?} stderr={:?}",
            outcome.exit_code,
            outcome.proxy_proof,
            outcome.expectation,
            stderr_of(&outcome).trim()
        );
        assert_eq!(outcome.expectation, ProofExpectation::MustBeAbsent);
        assert_eq!(
            outcome.proxy_proof,
            ProxyProof::default(),
            "a blocked session must never consult the proxy"
        );
        assert_ne!(
            outcome.exit_code,
            Some(0),
            "without a proxy the workload cannot reach the origin: {outcome:?}"
        );
        assert!(
            !origin.saw("/blocked"),
            "the blocked workload reached the origin: {:?}",
            origin.requests()
        );
        assert!(
            !outcome.success(),
            "the guardrail leg passed, but a workload that failed is not a successful session"
        );

        // ---- leg 4: filesystem policy --------------------------------------
        // (a) the granted workspace is writable and readable.
        let probe = scratch_dir.join("probe.txt");
        let command = format!(
            "cmd /c echo granted>\"{}\" & type \"{}\"",
            probe.display(),
            probe.display()
        );
        let outcome = launch_session(
            counters.as_ref(),
            None,
            None,
            &launcher,
            SessionBudget::default(),
            &session_input(&scratch_dir, &launcher, &denies, command, None),
        )
        .expect("the workspace write leg must launch");
        println!(
            "EVIDENCE fs_granted exit={:?} stdout={:?} stderr={:?}",
            outcome.exit_code,
            stdout_of(&outcome).trim(),
            stderr_of(&outcome).trim()
        );
        assert_eq!(
            outcome.exit_code,
            Some(0),
            "the granted workspace must be writable: {outcome:?}"
        );
        assert!(stdout_of(&outcome).to_ascii_lowercase().contains("granted"));
        assert_eq!(
            std::fs::read_to_string(&probe).unwrap_or_default().trim(),
            "granted",
            "the write must have landed in the granted directory"
        );

        // (b) a denied path is not readable.
        let secret_file = secret_dir.join("secret.txt");
        let command = format!("cmd /c type \"{}\"", secret_file.display());
        let outcome = launch_session(
            counters.as_ref(),
            None,
            None,
            &launcher,
            SessionBudget::default(),
            &session_input(&scratch_dir, &launcher, &denies, command, None),
        )
        .expect("the denied-read leg must launch");
        println!(
            "EVIDENCE fs_denied_read exit={:?} stdout={:?} stderr={:?}",
            outcome.exit_code,
            stdout_of(&outcome).trim(),
            stderr_of(&outcome).trim()
        );
        assert!(
            secret_file.is_file(),
            "the file must exist outside the container, or 'unreadable' proves nothing"
        );
        assert_ne!(
            outcome.exit_code,
            Some(0),
            "a denied path must not be readable: {outcome:?}"
        );
        assert!(
            !stdout_of(&outcome).contains("top-secret"),
            "the secret's content must never reach the child: {:?}",
            stdout_of(&outcome)
        );

        // (c) a denied path is not writable.
        let planted = secret_dir.join("planted.txt");
        let command = format!("cmd /c echo leaked>\"{}\"", planted.display());
        let outcome = launch_session(
            counters.as_ref(),
            None,
            None,
            &launcher,
            SessionBudget::default(),
            &session_input(&scratch_dir, &launcher, &denies, command, None),
        )
        .expect("the denied-write leg must launch");
        println!(
            "EVIDENCE fs_denied_write exit={:?} stderr={:?}",
            outcome.exit_code,
            stderr_of(&outcome).trim()
        );
        assert_ne!(
            outcome.exit_code,
            Some(0),
            "a denied path must not be writable: {outcome:?}"
        );
        assert!(
            !planted.exists(),
            "the child wrote into a denied path: {}",
            planted.display()
        );

        // (d) an ungranted path (outside the workspace, not on the deny list) is
        //     not writable either: containment is grants, not only denies.
        let outside = std::env::temp_dir().join(format!("mxc-outside-{}.txt", std::process::id()));
        let _ = std::fs::remove_file(&outside);
        let command = format!("cmd /c echo escaped>\"{}\"", outside.display());
        let outcome = launch_session(
            counters.as_ref(),
            None,
            None,
            &launcher,
            SessionBudget::default(),
            &session_input(&scratch_dir, &launcher, &denies, command, None),
        )
        .expect("the ungranted-write leg must launch");
        println!(
            "EVIDENCE fs_ungranted_write exit={:?} stderr={:?}",
            outcome.exit_code,
            stderr_of(&outcome).trim()
        );
        assert_ne!(
            outcome.exit_code,
            Some(0),
            "an ungranted path must not be writable: {outcome:?}"
        );
        assert!(
            !outside.exists(),
            "the child escaped the workspace: {}",
            outside.display()
        );

        // (e) the recorded caveat: system directories stay readable, because the
        //     policy is additive grants (ADR-0004). Asserted as the caveat it is,
        //     so nobody "fixes" it by denying C:\Windows.
        let win_ini = Path::new(r"C:\Windows\win.ini");
        if win_ini.is_file() {
            let command = format!("cmd /c type \"{}\"", win_ini.display());
            let outcome = launch_session(
                counters.as_ref(),
                None,
                None,
                &launcher,
                SessionBudget::default(),
                &session_input(&scratch_dir, &launcher, &denies, command, None),
            )
            .expect("the system-dir caveat leg must launch");
            let first = stdout_of(&outcome).chars().take(48).collect::<String>();
            println!(
                "EVIDENCE caveat_system_dir_readable exit={:?} first_48={first:?}",
                outcome.exit_code
            );
            assert_eq!(
                outcome.exit_code,
                Some(0),
                "RECORDED CAVEAT: MXC filesystem policy is additive grants, so C:\\Windows stays \
                 readable inside the container (ADR-0004); this leg records that, it does not \
                 claim otherwise"
            );
        } else {
            println!("EVIDENCE caveat_system_dir_readable skipped: no C:\\Windows\\win.ini");
        }

        println!(
            "EVIDENCE done: proxied CONNECT, plain-HTTP forward, blocked and filesystem legs all \
             proven unelevated against the supervisor's own listener"
        );
    }

    // =====================================================================
    // P1.4: two concurrent sessions, two listeners, two run tokens
    // =====================================================================

    /// One `CONNECT` carrying a credential the test chose, blocking.
    ///
    /// A container can only present its own run's token (it rides its proxy
    /// URL), so the cross-run legs use a raw socket: presenting *another* run's
    /// token is exactly what must be refused.
    fn cx(port: u16, token: &str, target: &str) -> String {
        let mut sock = TcpStream::connect(("127.0.0.1", port)).expect("connect the listener");
        sock.set_read_timeout(Some(Duration::from_secs(5)))
            .expect("read timeout");
        let creds = base64::engine::general_purpose::STANDARD.encode(format!("sandbox:{token}"));
        let req =
            format!("CONNECT {target} HTTP/1.1\r\nProxy-Authorization: Basic {creds}\r\n\r\n");
        sock.write_all(req.as_bytes()).expect("write CONNECT");
        let mut out = Vec::new();
        let mut chunk = [0u8; 256];
        // Read until the status line is complete; a tunnel keeps the socket
        // open afterwards, so this must never read to EOF.
        while !out.windows(2).any(|w| w == b"\r\n") {
            match sock.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(n) => out.extend_from_slice(&chunk[..n]),
            }
        }
        String::from_utf8_lossy(&out).into_owned()
    }

    /// Did `port` stop accepting connections within `within`?
    ///
    /// Polled because dropping a [`crate::net::proxy::ProxyHandle`] cancels the
    /// accept loop and then shuts its runtime down in the background
    /// (`shutdown_background`, AC-3.14 promises the port inside ~1s). P1.6(f):
    /// "closed" has to be *observed*; asserting it by not asserting anything after
    /// `drop` is an inference about `Drop`, not evidence.
    fn port_is_closed(port: u16, within: Duration) -> bool {
        let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
        let deadline = std::time::Instant::now() + within;
        loop {
            match TcpStream::connect_timeout(&addr, Duration::from_millis(200)) {
                // Refused (or unroutable): nothing is listening any more.
                Err(_) => return true,
                Ok(_) => {
                    if std::time::Instant::now() >= deadline {
                        return false;
                    }
                    std::thread::sleep(Duration::from_millis(25));
                }
            }
        }
    }

    /// CONNECT leaves in a session's audit chain.
    fn connect_leaves(sid: &str) -> usize {
        std::fs::read_to_string(crate::audit::audit_log_path(sid))
            .unwrap_or_default()
            .lines()
            .filter(|line| line.contains("\"op\":\"CONNECT\""))
            .count()
    }

    /// A session's whole audit chain, parsed.
    fn audit_leaves(sid: &str) -> Vec<serde_json::Value> {
        std::fs::read_to_string(crate::audit::audit_log_path(sid))
            .unwrap_or_default()
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| serde_json::from_str(line).expect("each leaf is one JSON object"))
            .collect()
    }

    /// P2.3 acceptance 3: **a wrong tier is a refused session with NO CONNECT
    /// leaves.**
    ///
    /// Driven against a real listener with its real audit writer, so the assertion
    /// is about a `.ndjson` file a proxy could have appended to — not about a
    /// hypothetical chain. The ordering is the supervisor's: arm the session-start
    /// guard, probe, fail guardrail 2, then write the root (naming the tier that
    /// was *actually* dispatched) and the refusal. Nothing spawns, so the
    /// listener's own counters stay `{0,0}` — the positive evidence that no
    /// consultation happened, which is stronger than an empty file.
    #[test]
    fn a_wrong_tier_refuses_the_session_with_no_connect_leaves() {
        let proxy = LiveProxy::start(&["api.anthropic.com"]);

        // The tier record exactly as `probe_tier` produces it for a degraded
        // dispatch.
        let observed = tier_record(ProbeView {
            tier: Some("appcontainer-dacl"),
            needs_dacl_augmentation: Some(true),
        });
        let refusal = verify_tier(&observed, TierExpectation::Exactly(REQUIRED_TIER))
            .expect_err("a degraded tier must refuse a base-container session");

        // The supervisor's own ordering (P2.3): the root carries the observed
        // facts, the refusal follows it, and nothing else is written. The endpoint
        // is the listener's bare authority — `LoopbackEndpoint` takes a `u16`, so
        // the child's credential-bearing proxy URL cannot be passed here at all
        // (P2.3 review, item 3).
        let endpoint = crate::audit::session_start::LoopbackEndpoint::new(proxy.port());
        let facts = crate::audit::session_start::SessionStartFacts::measured(
            observed.audit_facts(),
            Some(true),
        );
        crate::audit::session_start::SessionStart::arm(
            proxy.writer.clone(),
            &proxy.sid,
            "cmd /c echo hi",
            facts,
        )
        .refuse(
            Some(endpoint),
            crate::audit::session_start::TierRefusal::tier_mismatch(refusal.expected),
        )
        .expect("the refusal is audited");

        // No CONNECT leaf — and none could exist: the listener never accepted a
        // connection because no child was ever started.
        assert_eq!(
            connect_leaves(&proxy.sid),
            0,
            "a refused session must have no CONNECT leaves"
        );
        let counters = proxy.counters();
        let epoch = ProxyProofSource::begin_launch(counters.as_ref()).expect("no epoch is open");
        let proof = ProxyProofSource::proof(counters.as_ref(), epoch);
        ProxyProofSource::close_launch(counters.as_ref(), epoch);
        assert_eq!(
            proof,
            ProxyProof::default(),
            "the listener must never have been consulted for a refused session"
        );

        let leaves = audit_leaves(&proxy.sid);
        assert_eq!(leaves.len(), 2, "root + refusal, nothing else: {leaves:?}");
        assert_eq!(leaves[0]["op"], "SESSION_START");
        assert_eq!(leaves[0]["parent"], serde_json::Value::Null);
        assert_eq!(
            leaves[0]["tier"], "appcontainer-dacl",
            "the refused session still records the tier it would have run on"
        );
        assert_eq!(leaves[0]["tier_source"], "probe");
        assert_eq!(
            leaves[0]["disposition"], "deny",
            "the refusal's root must already say deny, not `allow` (P2.3 review, item 2)"
        );
        assert_eq!(
            leaves[0]["proxy_endpoint"],
            endpoint.to_string(),
            "the bare loopback authority, never a URL"
        );
        assert_eq!(leaves[1]["op"], "SESSION_REFUSED");
        assert_eq!(leaves[1]["disposition"], "deny");
        assert_eq!(leaves[1]["reason"], "tier_mismatch");
        assert_eq!(leaves[1]["expected_tier"], REQUIRED_TIER);
        assert_eq!(leaves[1]["parent"], leaves[0]["hash"]);

        // The chain's own credential rule (P2.3 acceptance 5) survives the refusal
        // path: the listener's token is nowhere in the file.
        let raw = std::fs::read_to_string(crate::audit::audit_log_path(&proxy.sid))
            .expect("the chain exists");
        assert!(
            !raw.contains(proxy.token().value()),
            "token in the chain: {raw}"
        );
        assert!(!raw.contains('@'), "userinfo in the chain: {raw}");
    }

    /// One attempt of the concurrency test: when each launch was in flight, and
    /// what it returned.
    ///
    /// Extracted from the test body so the retry rule is testable without
    /// launching a container - and the retry rule is the part that was wrong: the
    /// loop used to discard ANY non-overlapping attempt, including one whose
    /// launch had failed, so a real failure could be retried into invisibility.
    struct ConcurrencyAttempt {
        a: (Duration, Duration),
        b: (Duration, Duration),
        out_a: Result<SessionOutcome, MxcError>,
        out_b: Result<SessionOutcome, MxcError>,
    }

    impl ConcurrencyAttempt {
        /// Both launch calls were executing at some common instant.
        fn overlaps(&self) -> bool {
            self.a.0 < self.b.1 && self.b.0 < self.a.1
        }

        /// How long the two windows were in flight together.
        fn overlap(&self) -> Duration {
            self.a
                .1
                .min(self.b.1)
                .checked_sub(self.a.0.max(self.b.0))
                .unwrap_or_default()
        }

        /// May this attempt be thrown away and tried again?
        ///
        /// Only when it is BOTH serialized (so it measured nothing about
        /// concurrency) AND clean on both sides. A serialized attempt whose launch
        /// failed is the finding, not noise: retrying it would replace a real
        /// failure with a later, luckier run - a test that passes over the defect
        /// it exists to catch. An overlapping attempt is never discarded either,
        /// because it *is* the measurement.
        fn discardable(&self) -> bool {
            !self.overlaps() && self.out_a.is_ok() && self.out_b.is_ok()
        }

        /// One line of evidence for this attempt, outcome included.
        ///
        /// Printed for every attempt, not only the chosen one, so a failure
        /// cannot hide behind a retry. Deliberately narrow: exit code, proof and
        /// the error - never the child's stderr (it can quote a URL) and never a
        /// credential.
        fn evidence(&self) -> String {
            format!(
                "run_a=[{}ms..{}ms] run_b=[{}ms..{}ms] overlap={}ms out_a={} out_b={}",
                self.a.0.as_millis(),
                self.a.1.as_millis(),
                self.b.0.as_millis(),
                self.b.1.as_millis(),
                self.overlap().as_millis(),
                describe_launch(&self.out_a),
                describe_launch(&self.out_b),
            )
        }
    }

    /// How one launch outcome reads in evidence.
    fn describe_launch(out: &Result<SessionOutcome, MxcError>) -> String {
        match out {
            Ok(o) => format!(
                "ok exit={:?} proof={:?} success={}",
                o.exit_code,
                o.proxy_proof,
                o.success()
            ),
            Err(e) => format!("ERR {e}"),
        }
    }

    /// The attempt the concurrency test settles on, if it may stop now.
    ///
    /// Stops on the latest attempt when it may not be discarded (an overlap to
    /// measure, or a failure to report) or when the attempt budget is spent.
    fn chosen_attempt(attempts: &[ConcurrencyAttempt], max: usize) -> Option<usize> {
        let last = attempts.len().checked_sub(1)?;
        (!attempts[last].discardable() || attempts.len() >= max).then_some(last)
    }

    /// P1.6 (blocking 3): a serialized attempt whose launch FAILED is reported,
    /// never retried.
    ///
    /// The live test retries a serialized pair because a scheduler can deschedule
    /// one thread for the whole of the other's launch. The first version retried
    /// on `!overlaps()` alone, so an attempt that serialized *and* failed was
    /// discarded - the failure replaced by a later run's luck, which is exactly
    /// how a test passes over the defect it was written to catch.
    #[test]
    fn a_serial_attempt_with_a_failed_launch_is_reported_not_retried() {
        let failed = ConcurrencyAttempt {
            a: (Duration::from_millis(0), Duration::from_millis(400)),
            b: (Duration::from_millis(500), Duration::from_millis(900)),
            out_a: Err(MxcError::Concurrency(EpochAlreadyOpen { active: 1 })),
            out_b: Ok(passing_outcome()),
        };
        assert!(
            !failed.overlaps(),
            "the fixture must be the serialized case"
        );
        assert!(
            !failed.discardable(),
            "a serialized attempt with a failed launch is the finding, not noise"
        );
        // The loop appends one attempt at a time: the failed one settles it at
        // once, even though a retry would still have budget left.
        let attempts = [failed, clean_serial(), clean_serial()];
        assert_eq!(
            chosen_attempt(&attempts[..1], 3),
            Some(0),
            "the loop must settle on the failed attempt immediately, not retry it"
        );
        assert_eq!(
            attempts.len(),
            3,
            "a failed attempt settles the loop, so the other two are never launched"
        );
        // The failure is visible in the per-attempt evidence, not only in the
        // panic at the end.
        let evidence = attempts[0].evidence();
        assert!(
            evidence.contains("out_a=ERR") && evidence.contains("overlap="),
            "every attempt must print its outcome: {evidence}"
        );

        // The scheduler case the retry exists for is unchanged: a clean serialized
        // attempt is discarded and retried...
        let clean = clean_serial();
        assert!(clean.discardable());
        assert_eq!(
            chosen_attempt(&[clean], 3),
            None,
            "one clean attempt: retry"
        );
        // The attempt budget is what bounds the retrying: at the limit, a clean
        // serialized attempt is settled on so the test can report the finding.
        assert_eq!(chosen_attempt(&[clean_serial()], 1), Some(0));
        // ... and an overlapping attempt is the measurement, so it is chosen even
        // when it is also a failure (the outcome is asserted separately).
        let overlapping = ConcurrencyAttempt {
            a: (Duration::from_millis(0), Duration::from_millis(400)),
            b: (Duration::from_millis(100), Duration::from_millis(500)),
            out_a: Err(MxcError::Concurrency(EpochAlreadyOpen { active: 1 })),
            out_b: Ok(passing_outcome()),
        };
        assert!(overlapping.overlaps());
        assert!(!overlapping.discardable());
        assert_eq!(chosen_attempt(&[overlapping], 3), Some(0));
    }

    /// A serialized attempt whose launches both came back clean.
    fn clean_serial() -> ConcurrencyAttempt {
        ConcurrencyAttempt {
            a: (Duration::from_millis(0), Duration::from_millis(400)),
            b: (Duration::from_millis(500), Duration::from_millis(900)),
            out_a: Ok(passing_outcome()),
            out_b: Ok(passing_outcome()),
        }
    }

    /// An outcome that passes guardrail 1 on the `Required` leg.
    fn passing_outcome() -> SessionOutcome {
        SessionOutcome {
            exit_code: Some(0),
            timeout: None,
            stdout: Vec::new(),
            stderr: Vec::new(),
            warnings: Vec::new(),
            tier: TierRecord {
                tier: Some("base-container".to_string()),
                tier_source: TIER_SOURCE_PROBE,
                needs_dacl_augmentation: Some(false),
            },
            proxy_proof: ProxyProof {
                accepted: 1,
                tunnels: 1,
                probes: 1,
                unauthenticated: 0,
            },
            expectation: ProofExpectation::Required,
            clock: SessionClock::default(),
        }
    }

    /// **P1.4 mandatory test: two containers, concurrently.**
    ///
    /// Each session gets its own listener, its own port and its own run token.
    /// The assertions are the four the review asked for: both sessions prove
    /// their own guardrail, each proof counts **only** its own traffic (`{1,1}`,
    /// never the `{2,2}` a shared listener would produce), a token from the other
    /// session is refused at the first listener with a `407` that is neither
    /// counted nor audited, and closing one session leaves the other's counters
    /// and service untouched.
    ///
    /// Run: `cargo test --features mxc-backend --bin saife -- --ignored --nocapture`
    #[test]
    #[ignore = "launches two real ProcessContainers; run: cargo test --features mxc-backend -- --ignored"]
    fn two_concurrent_sessions_prove_only_their_own_traffic_and_refuse_each_others_tokens() {
        let launcher = launcher_under_test();
        // Each origin answers with a body only it can produce (P1.6(f)): a shared
        // nonce would let a crossed body pass as a correct one.
        let origin_a = Origin::start_with_nonce("p14-origin-run-a");
        let origin_b = Origin::start_with_nonce("p14-origin-run-b");
        // Two runs, two credentials, minted the way the supervisor mints them.
        let token_a = RunToken::issue().expect("mint run A's token");
        let token_b = RunToken::issue().expect("mint run B's token");
        let a = LiveProxy::start_with_token(&[origin_a.host.as_str()], token_a.clone());
        let b = LiveProxy::start_with_token(&[origin_b.host.as_str()], token_b.clone());

        println!(
            "EVIDENCE elevated={} (TokenElevation of the driving process)",
            process_is_elevated()
        );
        println!(
            "EVIDENCE run_a port={} token_run={} origin={}",
            a.port(),
            a.token().run(),
            origin_a.authority()
        );
        println!(
            "EVIDENCE run_b port={} token_run={} origin={}",
            b.port(),
            b.token().run(),
            origin_b.authority()
        );
        assert_ne!(a.port(), b.port(), "each run gets its own listener");
        assert_ne!(
            token_a.value(),
            token_b.value(),
            "each run gets its own credential"
        );

        let scratch_a = Scratch::named("p14-run-a");
        let scratch_b = Scratch::named("p14-run-b");
        let dir_a = scratch_a.path().to_path_buf();
        let dir_b = scratch_b.path().to_path_buf();
        let no_denies: Vec<String> = Vec::new();

        // A: a real CONNECT tunnel. B: a real absolute-form plain-HTTP forward.
        // Different legs on purpose — each session proves itself with the leg it
        // uses, and neither proof can be borrowed from the other.
        let command_a = format!(
            "{CURL} -sS -f --max-time 40 --proxytunnel {}",
            origin_a.url("/run-a")
        );
        let command_b = format!("{CURL} -sS -f --max-time 40 {}", origin_b.url("/run-b"));
        let input_a = session_input(&dir_a, &launcher, &no_denies, command_a, Some(a.port()));
        let input_b = session_input(&dir_b, &launcher, &no_denies, command_b, Some(b.port()));

        let counters_a = a.counters();
        let counters_b = b.counters();

        // Genuinely concurrent, and **observed** to be (P1.6(f)): both threads
        // meet at a barrier before either launches, so neither launch can start
        // after the other *finished waiting*, and the measured windows then have to
        // overlap - which is printed as evidence, not asserted in prose.
        //
        // An attempt that comes out serialized is retried, and the retry is not
        // politeness: it happened once for real, with four live tests launching
        // containers at the same time, where one thread sat descheduled for the
        // whole 327 ms of the other's launch. That is a fact about the scheduler,
        // not about the proxy. If *no* attempt overlaps, the finding is real and
        // the test fails.
        //
        // Only an attempt that is BOTH serialized AND clean is discarded
        // ([`ConcurrencyAttempt::discardable`]): a launch that failed must fail
        // this test, never be retried into a luckier run.
        const CONCURRENCY_ATTEMPTS: usize = 3;
        let barrier = std::sync::Barrier::new(2);
        let mut attempts: Vec<ConcurrencyAttempt> = Vec::new();
        let chosen = loop {
            let launched_at = std::time::Instant::now();
            let run = std::thread::scope(|scope| {
                let barrier_a = &barrier;
                let barrier_b = &barrier;
                let handle_a = scope.spawn(|| {
                    barrier_a.wait();
                    let began = launched_at.elapsed();
                    let outcome = launch_session(
                        counters_a.as_ref(),
                        Some(a.port()),
                        Some(a.token().value()),
                        &launcher,
                        SessionBudget::default(),
                        &input_a,
                    );
                    (began, launched_at.elapsed(), outcome)
                });
                let handle_b = scope.spawn(|| {
                    barrier_b.wait();
                    let began = launched_at.elapsed();
                    let outcome = launch_session(
                        counters_b.as_ref(),
                        Some(b.port()),
                        Some(b.token().value()),
                        &launcher,
                        SessionBudget::default(),
                        &input_b,
                    );
                    (began, launched_at.elapsed(), outcome)
                });
                (
                    handle_a.join().expect("run A's launch thread"),
                    handle_b.join().expect("run B's launch thread"),
                )
            });
            attempts.push(ConcurrencyAttempt {
                a: (run.0.0, run.0.1),
                b: (run.1.0, run.1.1),
                out_a: run.0.2,
                out_b: run.1.2,
            });
            let last = attempts.len() - 1;
            // Every attempt, outcome included - not just the one that gets used.
            // A launch that failed once must be visible in the log even when a
            // later attempt succeeds.
            println!(
                "EVIDENCE concurrency attempt={}/{} {} (barrier of 2 released before either \
                 launch)",
                last + 1,
                CONCURRENCY_ATTEMPTS,
                attempts[last].evidence()
            );
            if let Some(settled) = chosen_attempt(&attempts, CONCURRENCY_ATTEMPTS) {
                break settled;
            }
        };
        let chosen = attempts.swap_remove(chosen);
        let overlapped = chosen.overlaps();
        let chosen_evidence = chosen.evidence();
        // Outcomes BEFORE the overlap verdict: when a launch failed, that error is
        // the finding, and it must be what the reader sees - not a note about the
        // scheduler that would bury it.
        let out_a = chosen
            .out_a
            .expect("run A's launch failed (a failed launch is never retried away)");
        let out_b = chosen
            .out_b
            .expect("run B's launch failed (a failed launch is never retried away)");
        assert!(
            overlapped,
            "no attempt put the two launches in flight at the same time, so this run proves \
             nothing about concurrent sessions: {}",
            attempts
                .iter()
                .map(ConcurrencyAttempt::evidence)
                .collect::<Vec<_>>()
                .join(" | ")
        );
        println!("EVIDENCE concurrency_chosen {chosen_evidence}");
        println!(
            "EVIDENCE run_a exit={:?} success={} proof={:?} stdout={:?} stderr={:?}",
            out_a.exit_code,
            out_a.success(),
            out_a.proxy_proof,
            stdout_of(&out_a).trim(),
            stderr_of(&out_a).trim()
        );
        println!(
            "EVIDENCE run_b exit={:?} success={} proof={:?} stdout={:?} stderr={:?}",
            out_b.exit_code,
            out_b.success(),
            out_b.proxy_proof,
            stdout_of(&out_b).trim(),
            stderr_of(&out_b).trim()
        );

        // (i) both sessions succeed.
        assert_eq!(out_a.exit_code, Some(0), "run A's curl failed: {out_a:?}");
        assert_eq!(out_b.exit_code, Some(0), "run B's curl failed: {out_b:?}");
        assert!(out_a.success() && out_b.success());

        // (ii) each proof is exactly its own traffic. `{2,2}` here would mean one
        // listener had served both sessions (the R3 masking failure).
        assert_eq!(
            out_a.proxy_proof,
            ProxyProof {
                accepted: 1,
                tunnels: 1,
                probes: 1,
                unauthenticated: 0,
            },
            "run A's proof must count only run A's consultation and its own probe"
        );
        assert_eq!(
            out_b.proxy_proof,
            ProxyProof {
                accepted: 1,
                tunnels: 1,
                probes: 1,
                unauthenticated: 0,
            },
            "run B's proof must count only run B's consultation and its own probe"
        );
        // The body each session printed must be the nonce of the origin that
        // session was allowed to reach - and not the other one's (P1.6(f)).
        println!(
            "EVIDENCE bodies run_a={:?} (own nonce {}) run_b={:?} (own nonce {})",
            stdout_of(&out_a).trim(),
            origin_a.nonce(),
            stdout_of(&out_b).trim(),
            origin_b.nonce()
        );
        assert!(
            stdout_of(&out_a).contains(origin_a.nonce()),
            "run A's body must be its own origin's nonce {}: {:?}",
            origin_a.nonce(),
            stdout_of(&out_a)
        );
        assert!(
            stdout_of(&out_b).contains(origin_b.nonce()),
            "run B's body must be its own origin's nonce {}: {:?}",
            origin_b.nonce(),
            stdout_of(&out_b)
        );
        assert!(
            !stdout_of(&out_a).contains(origin_b.nonce())
                && !stdout_of(&out_b).contains(origin_a.nonce()),
            "neither session may print the other's origin nonce: A={:?} B={:?}",
            stdout_of(&out_a),
            stdout_of(&out_b)
        );
        assert!(
            origin_a.saw("/run-a") && !origin_a.saw("/run-b"),
            "origin A served another session's request: {:?}",
            origin_a.requests()
        );
        assert!(
            origin_b.saw("/run-b") && !origin_b.saw("/run-a"),
            "origin B served another session's request: {:?}",
            origin_b.requests()
        );

        // (iii) a token from the other session is refused at the first: 407, not
        // counted, and no leaf in that run's audit chain.
        let epoch_a = counters_a.begin_epoch().expect("a fresh window for A");
        let leaves_before = connect_leaves(&a.sid);
        let resp = cx(a.port(), token_b.value(), &origin_a.authority());
        println!(
            "EVIDENCE foreign_token_at_run_a status={:?} counters={:?} leaves_before={} leaves_after={}",
            resp.lines().next().unwrap_or(""),
            counters_a.counters(epoch_a),
            leaves_before,
            connect_leaves(&a.sid)
        );
        assert!(
            resp.starts_with("HTTP/1.1 407"),
            "run A must refuse run B's token: {resp:?}"
        );
        assert_eq!(
            counters_a.counters(epoch_a).map(|c| (
                c.consultations,
                c.upstream_established,
                c.probes
            )),
            Some((0, 0, 0)),
            "a foreign token must not count as a consultation, a tunnel or a probe"
        );
        assert_eq!(
            counters_a.counters(epoch_a).map(|c| c.unauthenticated),
            Some(1),
            "it IS counted as an unauthenticated attempt (P3.2a): run A must be able to see \
             that something reached its listener without its credential"
        );
        assert_eq!(
            connect_leaves(&a.sid),
            leaves_before + 1,
            "a foreign token must be recorded once in run A's chain"
        );

        let epoch_b = counters_b.begin_epoch().expect("a fresh window for B");
        let leaves_before = connect_leaves(&b.sid);
        let resp = cx(b.port(), token_a.value(), &origin_b.authority());
        println!(
            "EVIDENCE foreign_token_at_run_b status={:?} counters={:?} leaves_before={} leaves_after={}",
            resp.lines().next().unwrap_or(""),
            counters_b.counters(epoch_b),
            leaves_before,
            connect_leaves(&b.sid)
        );
        assert!(
            resp.starts_with("HTTP/1.1 407"),
            "run B must refuse run A's token: {resp:?}"
        );
        assert_eq!(
            counters_b.counters(epoch_b).map(|c| (
                c.consultations,
                c.upstream_established,
                c.probes
            )),
            Some((0, 0, 0)),
            "a foreign token must not count at run B as traffic either"
        );
        assert_eq!(
            counters_b.counters(epoch_b).map(|c| c.unauthenticated),
            Some(1),
            "and it is counted once as an unauthenticated attempt at B, symmetrically to A"
        );
        assert_eq!(
            connect_leaves(&b.sid),
            leaves_before + 1,
            "a foreign token must be recorded once in run B's chain"
        );

        // Each listener still serves its own token, so the refusals above are
        // about ownership and not a broken listener.
        let resp = cx(a.port(), token_a.value(), &origin_a.authority());
        assert!(
            resp.starts_with("HTTP/1.1 200"),
            "run A must accept its own token: {resp:?}"
        );
        let resp = cx(b.port(), token_b.value(), &origin_b.authority());
        assert!(
            resp.starts_with("HTTP/1.1 200"),
            "run B must accept its own token: {resp:?}"
        );

        // (iv) closing one session does not disturb the other's counters or its
        // ability to serve.
        let frozen_b = counters_b.counters(epoch_b);
        let port_b = b.port();
        drop(b);
        // Observed, not inferred: B's listener must actually stop accepting, and
        // A's must still be serving (checked below) - the pair is what makes
        // "closing B left A alone" mean something (P1.6(f)).
        let closed = port_is_closed(port_b, Duration::from_secs(5));
        println!(
            "EVIDENCE after_closing_run_b port_b={port_b} refuses_connections={closed} \
             run_a_counters={:?} run_b_counters_frozen={:?}",
            counters_a.counters(epoch_a),
            frozen_b
        );
        assert!(
            closed,
            "run B's listener on port {port_b} must stop accepting connections once its handle is \
             dropped; a live socket would mean `drop` did not close its peer"
        );
        // ...and A is still *serving*, which the authenticated CONNECT below
        // asserts directly (an accept-and-407 would prove less, and would spend
        // A's `no_token` leaf budget doing it).
        assert_eq!(
            counters_b.counters(epoch_b),
            frozen_b,
            "closing run B must not change run B's frozen counters"
        );
        let resp = cx(a.port(), token_a.value(), &origin_a.authority());
        assert!(
            resp.starts_with("HTTP/1.1 200"),
            "run A must keep serving after run B closes: {resp:?}"
        );
        let leaves_before = connect_leaves(&a.sid);
        let resp = cx(a.port(), token_b.value(), &origin_a.authority());
        assert!(
            resp.starts_with("HTTP/1.1 407"),
            "run A must still refuse B's token after B closed: {resp:?}"
        );
        assert_eq!(
            connect_leaves(&a.sid),
            leaves_before + 1,
            "the refusal after B closed is recorded as one event in A's chain"
        );
        assert!(
            counters_a.close_epoch(epoch_a),
            "run A's window is still the open one"
        );
        assert!(counters_b.close_epoch(epoch_b));

        println!(
            "EVIDENCE done: two concurrent sessions, each proofed by its own listener and its \
             own run token, with the cross-run token refused as traffic (counted only as an \
             unauthenticated attempt) and kept out of the other run's proof"
        );
    }

    /// PowerShell 5.1 lives here (System32), and the container's policy grants
    /// `C:\Windows` read-only.
    const POWERSHELL: &str = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";

    /// **The managed-workload leg (P3).**
    ///
    /// Every other leg in this module runs a native executable (`curl.exe`,
    /// `cmd.exe`), and a native child starts even when the container bans Win32k
    /// system calls — so this suite could have been fully green while **every**
    /// managed workload died at load. It was: with `ContainerRequest::ui` unset,
    /// the SDK's `UiPolicy::default()` (`disable: true`) becomes
    /// `PROCESS_CREATION_MITIGATION_POLICY_WIN32K_SYSTEM_CALL_DISABLE`, `user32`,
    /// `gdi32` and `ole32` then fail `DllMain` with `ERROR_DLL_INIT_FAILED`
    /// (1114), and `powershell.exe` exits `0xC0000142`
    /// (`STATUS_DLL_INIT_FAILED`) with empty output.
    ///
    /// So this leg asserts only that a CLR-hosted workload *starts* inside the
    /// container, through the same wrapper, the same filesystem policy and the
    /// same proxy-only network posture as the other legs. The command is pure
    /// PowerShell on purpose: 5.1 cannot invoke native commands as an
    /// AppContainer child (`DriveNotFoundException:
    /// Microsoft.PowerShell.Core\FileSystem`), and `Write-Output` needs no
    /// subprocess. `FXOK` is the proof the child reached managed code — an exit
    /// code alone would also pass a silently swallowed error.
    ///
    /// Red without the fix: remove the `request.ui` assignment in
    /// [`build_request`] and this leg reports `exit=Some(-1073741502)`
    /// (`0xC0000142`) with empty stdout.
    /// P2.1, live: a session whose **workload term** is exceeded is killed by the
    /// container, and the outcome says so with the workload's own reason — not with
    /// `timed_out: true` and no more, and not with the prompt's reason.
    ///
    /// The budget is deliberately small (2 s prompt + 1 s workload + 1 s slack = 4 s
    /// session) and the workload sleeps for 8 s, so the kill happens at the session
    /// deadline with the workload term spent and no prompt time at all: that is the
    /// `workload_budget_exceeded` case by construction, and it also pins the fact
    /// that `timeout_ms` really reaches the SDK (a `None` — or a value that wrapped
    /// small — would either run to completion or die at once).
    #[test]
    #[ignore = "launches a real ProcessContainer; run: cargo test --features mxc-backend -- --ignored"]
    fn a_workload_that_overruns_its_term_is_killed_and_reported_as_such() {
        let launcher = launcher_under_test();
        let proxy = LiveProxy::start(&[]);
        let counters = proxy.counters();
        let scratch = Scratch::named("budget-kill");
        let dir = scratch.path().to_path_buf();
        let no_denies: Vec<String> = Vec::new();

        // `cmd /c timeout` needs a console; a native sleep is what the container
        // runs, and 8 s is comfortably past the 4 s session deadline.
        let command =
            format!(r#"{POWERSHELL} -NoProfile -NonInteractive -Command "Start-Sleep -Seconds 8""#);
        let input = session_input(
            &dir,
            &launcher,
            &no_denies,
            command.clone(),
            Some(proxy.port()),
        );
        // prompt 1 s + workload 1 s + slack 2 s: the deadline still lands at 4 s
        // (so an 8 s workload is killed), while the slack leaves the container's own
        // create/prove two seconds — the allowance it exists to provide (P2.1 review,
        // item 2). With a 1 s slack a slow Defender scan of the launcher could push
        // the handshake past its allowance and correctly re-label this kill.
        let budget = SessionBudget::new(
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(2),
        );
        println!(
            "EVIDENCE budget_kill command={:?} budget={:?} session_ms={}",
            command,
            budget,
            budget.timeout_ms()
        );

        let started = std::time::Instant::now();
        // Evidence runs measure what dispatched; enforcement is the product path's
        // (`supervisor_backend` -> `Exactly(REQUIRED_TIER)`).
        let backend = MxcBackend::new(
            counters.as_ref(),
            Some(proxy.port()),
            &launcher,
            TierExpectation::Recorded,
        )
        .with_proxy_token(proxy.token().value())
        .with_budget(budget);
        let outcome = backend
            .launch(&input, ProofExpectation::MustBeAbsent)
            .expect("a workload with no network use must leave the proxy unconsulted");
        let elapsed = started.elapsed();
        println!(
            "EVIDENCE budget_kill exit={:?} timeout={:?} success={} elapsed={:?} proof={:?}",
            outcome.exit_code,
            outcome.timeout,
            outcome.success(),
            elapsed,
            outcome.proxy_proof
        );

        // Item 2's live half: the measurements the label came from are on the
        // outcome, and the handshake really did finish inside its allowance — the
        // workload, not a stalled container, is what ran out of time.
        println!("EVIDENCE budget_kill clock={:?}", outcome.clock);
        assert!(
            outcome.clock.handshake_elapsed < budget.slack,
            "the container must be ready inside the slack that exists for it: {:?}",
            outcome.clock
        );
        assert!(
            outcome.clock.handshake_elapsed < elapsed,
            "the handshake is a part of the session, not the whole of it: {:?}",
            outcome.clock
        );
        assert_eq!(
            outcome.clock.prompt_wait,
            Duration::ZERO,
            "a workload that never used the proxy spent no prompt time: {:?}",
            outcome.clock
        );
        assert!(
            outcome.clock.elapsed >= budget.session(),
            "the kill landed at the deadline: {:?}",
            outcome.clock
        );
        // Item 7's live half: the teardown is MEASURED (a real container was reclaimed
        // after the kill), and it is a part of the session rather than the whole of it
        // — so the supervisor-side term now has a number instead of being folded into
        // `elapsed`.
        println!(
            "EVIDENCE budget_kill phases handshake={:?} run+teardown={:?} teardown={:?}",
            outcome.clock.handshake_elapsed,
            outcome
                .clock
                .elapsed
                .saturating_sub(outcome.clock.handshake_elapsed),
            outcome.clock.teardown_elapsed
        );
        assert!(
            outcome.clock.teardown_elapsed > Duration::ZERO,
            "reclaiming the container must be measured, not assumed zero: {:?}",
            outcome.clock
        );
        assert!(
            outcome.clock.teardown_elapsed <= budget.slack,
            "an ordinary teardown fits inside the slack that exists for it — a larger one \
             would (correctly) make this kill a `SessionTeardown`: {:?}",
            outcome.clock
        );
        assert!(
            outcome.clock.handshake_elapsed + outcome.clock.teardown_elapsed
                < outcome.clock.elapsed,
            "the two supervisor phases are parts of the session, not the whole of it: {:?}",
            outcome.clock
        );

        assert!(
            outcome.timed_out(),
            "the container must kill a workload that overruns its term: {outcome:?}"
        );
        assert_eq!(
            outcome.exit_code, None,
            "a killed session has no exit code: {outcome:?}"
        );
        // The distinct reason: the workload term, not the prompt's and not the
        // handshake's.
        assert_eq!(
            outcome.timeout,
            Some(TimeoutReason::WorkloadBudgetExceeded),
            "a kill with the workload term spent must be reported as a workload overrun, \
             not as a prompt or handshake timeout"
        );
        assert!(
            elapsed >= Duration::from_secs(3),
            "the kill can only happen at the session deadline (4 s), not at once: {elapsed:?}"
        );
        assert!(
            elapsed < Duration::from_secs(20),
            "the kill must be the deadline, not the workload's own 8 s run: {elapsed:?}"
        );
        assert!(!outcome.success(), "a killed session is never a success");
    }

    #[test]
    #[ignore = "launches a real ProcessContainer; run: cargo test --features mxc-backend -- --ignored"]
    fn managed_powershell_workload_starts_and_prints_fxok_inside_the_container() {
        let launcher = launcher_under_test();
        // No allowed origin: this workload makes no network request, and an
        // empty allow-list keeps that honest if it ever tried to.
        let proxy = LiveProxy::start(&[]);
        let counters = proxy.counters();
        let scratch = Scratch::named("managed");
        let dir = scratch.path().to_path_buf();
        let no_denies: Vec<String> = Vec::new();

        let command =
            format!(r#"{POWERSHELL} -NoProfile -NonInteractive -Command "Write-Output FXOK""#);
        let input = session_input(
            &dir,
            &launcher,
            &no_denies,
            command.clone(),
            Some(proxy.port()),
        );
        println!(
            "EVIDENCE elevated={} managed_command={:?} launcher={} proxy_port={}",
            process_is_elevated(),
            command,
            launcher.display(),
            proxy.port()
        );

        // The normal launch path, with the proof expectation stated rather than
        // derived: `launch_session` demands `Required` whenever the request
        // carries a proxy port, and this command cannot consult a proxy.
        // Evidence runs measure what dispatched; enforcement is the product path's
        // (`supervisor_backend` -> `Exactly(REQUIRED_TIER)`).
        let backend = MxcBackend::new(
            counters.as_ref(),
            Some(proxy.port()),
            &launcher,
            TierExpectation::Recorded,
        )
        .with_proxy_token(proxy.token().value())
        .with_budget(SessionBudget::new(
            Duration::from_secs(30),
            Duration::from_secs(80),
            Duration::from_secs(10),
        ));
        let outcome = backend
            .launch(&input, ProofExpectation::MustBeAbsent)
            .expect("a workload with no network use must leave the proxy unconsulted");
        let out = stdout_of(&outcome);
        println!(
            "EVIDENCE managed_workload exit={:?} timed_out={} success={} proof={:?} tier={:?}",
            outcome.exit_code,
            outcome.timed_out(),
            outcome.success(),
            outcome.proxy_proof,
            outcome.tier.tier
        );
        println!(
            "EVIDENCE managed_workload_stdout={:?} stderr={:?} readonly_grants={:?}",
            out.trim(),
            stderr_of(&outcome).trim(),
            input.filesystem.readonly_paths
        );

        assert_eq!(
            outcome.exit_code,
            Some(0),
            "a CLR workload must start inside the container; exit -1073741502 (0xC0000142) is \
             STATUS_DLL_INIT_FAILED, i.e. the Win32k ban is back: {outcome:?}"
        );
        assert!(
            out.contains("FXOK"),
            "the managed child must have reached managed code and printed FXOK: {out:?}"
        );
        println!(
            "EVIDENCE done: powershell started inside the container and printed FXOK (ui.disable = false)"
        );
    }

    // =====================================================================
    // P2.2: the D-4 control plane, proven from INSIDE a container
    // =====================================================================
    //
    // ADR-0001 §D-4 puts three endpoints on the proxy's loopback listener:
    // `POST /sandbox/intent` (204 / 400), `GET /sandbox/intent?host=` (200 with
    // `{host, reason, ts}` / 404) and `POST /sandbox/intent/explain` (204,
    // one-shot). The child reaches them DIRECTLY — `NO_PROXY` bypasses the proxy
    // for loopback — and identifies itself with `Proxy-Authorization: Basic
    // <sandbox:token>`.
    //
    // The two legs below are the MXC half of that contract. They are in-process
    // on purpose: `main.rs` refuses `--backend mxc` and the VM harness never
    // passes it, so no VM scenario can exercise this backend until the wiring
    // lands in P3 (the plan's standing coverage note). VM scenario S-77 is the
    // AppContainer baseline, and it checks strictly less than leg 1.

    /// The host the container declares intent for. `.example` is reserved, so a
    /// stray lookup could never leave this machine even if one were attempted.
    const P22_HOST: &str = "p22-declared.example";

    /// The reason the agent inside the container declares. Spelled once, so the
    /// GET must return *this* string rather than merely a non-empty one.
    const P22_REASON: &str = "reason-declared-from-inside-the-container";

    /// A host the container consults and that nothing allow-lists, so the D-3.5
    /// prompt is the only layer that can answer (leg 2).
    const P22_PROMPT_HOST: &str = "p22-prompt.example";

    /// What every P2.2 script starts with: derive the control-plane endpoint from
    /// the session's **own** proxy variable, and derive the
    /// `Proxy-Authorization: Basic` credential from that same token.
    ///
    /// This is done the way a real workload has to do it, because it is part of
    /// what the leg proves. The MXC launcher injects
    /// `HTTP_PROXY=http://sandbox:<token>@127.0.0.1:<port>`,
    /// `NO_PROXY=localhost,127.0.0.1,::1` and — since P2.4 —
    /// `SAIFE_PROXY_PORT=<port>`, the D-0.3 discovery variable the
    /// AppContainer path has always injected. The script below deliberately keeps
    /// deriving the endpoint from `HTTP_PROXY` rather than reading the discovery
    /// variable: the env leg asserts that the two agree (`SAIFE_PROXY_PORT` ==
    /// this listener's port), and a second, independent derivation is what makes
    /// that agreement evidence instead of a tautology. `cmd.exe` cannot
    /// base64, so the credential comes from `certutil`: one PEM block whose
    /// payload lines are concatenated (a 64-hex run token makes the payload wrap
    /// at 64 columns, and using only the first line produced a truncated
    /// credential — every call answered 407 until this joined them).
    const P22_PRELUDE: &str = r#"@echo off
rem Delayed expansion: the payload below can span more than one 64-column line.
setlocal enabledelayedexpansion
rem The endpoint, from the child's own environment: no argument from the test.
for /f "tokens=3,5 delims=:@" %%a in ("%HTTP_PROXY%") do (
  set "TOK=%%a"
  set "PORT=%%b"
)
if not defined TOK ( echo MARK parse=no_token & exit 4 )
if not defined PORT ( echo MARK parse=no_port & exit 4 )
echo MARK parsed_port=%PORT%
rem `set /p` with '=...' writes NO trailing newline: `echo` would add CRLF to the
rem file, certutil would encode it, and the credential would carry a stray CRLF
rem (observed: every call answered 407 because the password did not match).
<nul > creds.txt set /p "=sandbox:%TOK%"
certutil -encode -f creds.txt creds.b64 >nul 2>&1
set "B64="
for /f "skip=1 delims=" %%L in (creds.b64) do if not "%%L"=="-----END CERTIFICATE-----" set "B64=!B64!%%L"
del creds.txt creds.b64 >nul 2>&1
if not defined B64 ( echo MARK base64=failed & exit 4 )
echo MARK auth=derived
set "H=Proxy-Authorization: Basic %B64%"
set "AURL=http://127.0.0.1:%PORT%/sandbox/intent"
"#;

    /// The eight calls of leg 1: the roundtrip, the one-shot, and the three
    /// negative cases. Each status is a `MARK` line on stdout *and* an artifact
    /// in the workspace, so a failure can be diagnosed from the file rather than
    /// inferred from curl's exit code.
    ///
    /// The credential-dependent calls are the proof that the child identified
    /// itself: the listener answers 407 to every credential that is not its
    /// run's (P1.4), before it routes anything.
    const P22_ROUNDTRIP_BODY: &str = r#"> body-declare.json echo {"target":"__HOST__","reason":"__REASON__"}
> body-explain.json echo {"host":"__HOST__"}
> body-malformed.json echo this-is-not-json
curl -sS -o out-post.txt -w "MARK post_intent=%%{http_code}\n" -H "%H%" -H "Content-Type: application/json" --data-binary @body-declare.json "%AURL%"
curl -sS -o out-get-declared.json -w "MARK get_declared=%%{http_code}\n" -H "%H%" "%AURL%?host=__HOST__"
curl -sS -o out-explain.txt -w "MARK post_explain=%%{http_code}\n" -H "%H%" -H "Content-Type: application/json" --data-binary @body-explain.json "%AURL%/explain"
curl -sS -o out-get-flagged.json -w "MARK get_after_explain=%%{http_code}\n" -H "%H%" "%AURL%?host=__HOST__"
curl -sS -o out-get-consumed.json -w "MARK get_after_consume=%%{http_code}\n" -H "%H%" "%AURL%?host=__HOST__"
curl -sS -o out-get404.json -w "MARK get_undeclared=%%{http_code}\n" -H "%H%" "%AURL%?host=never-declared-p22.example"
curl -sS -o out-post400.txt -w "MARK post_malformed=%%{http_code}\n" -H "%H%" -H "Content-Type: application/json" --data-binary @body-malformed.json "%AURL%"
curl -sS -o out-get407.txt -w "MARK get_wrong_credential=%%{http_code}\n" -H "Proxy-Authorization: Basic c2FuZGJveDp3cm9uZw==" "%AURL%?host=__HOST__"
echo MARK done
"#;

    /// Leg 2's two calls: declare the intent, then consult the host. Both marker
    /// lines also go to files, because the launch is *expected* to fail guardrail
    /// 1 (a consultation), so the launch's stdout is not available to assert on.
    ///
    /// `exit /b 0` is deliberate: the CONNECT is meant to be refused, and the
    /// evidence is the marker files plus the dialog, not the child's exit code.
    const P22_PROMPT_BODY: &str = r#"> body-prompt.json echo {"target":"__HOST__","reason":"__REASON__"}
curl -sS -o out-prompt-post.txt -w "MARK prompt_intent=%%{http_code}\n" -H "%H%" -H "Content-Type: application/json" --data-binary @body-prompt.json "%AURL%" > markers-prompt.txt
type markers-prompt.txt
curl -sS -o out-prompt-connect.txt -w "MARK prompt_connect=%%{http_code}\n" --max-time 10 "https://__HOST__/" > markers-connect.txt
type markers-connect.txt
echo MARK done
exit /b 0
"#;

    /// Write one CRLF batch file (shared prelude + `body`) into the container's
    /// workspace and return the command line that runs it.
    fn p22_script(dir: &Path, name: &str, host: &str, reason: &str, body: &str) -> String {
        let path = dir.join(format!("{name}.bat"));
        let script = format!("{P22_PRELUDE}{body}")
            .replace("__HOST__", host)
            .replace("__REASON__", reason);
        // CRLF before it reaches cmd.exe, and independently of the source file's
        // own line endings (a batch file with bare LF loses `for /f` lines).
        let script = script.replace("\r\n", "\n").replace('\n', "\r\n");
        std::fs::write(&path, script.as_bytes())
            .unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
        format!("cmd /c \"{}\"", path.display())
    }

    /// One `MARK key=value` line from a P2.2 script's stdout.
    fn mark(stdout: &str, key: &str) -> Option<String> {
        let prefix = format!("MARK {key}=");
        stdout
            .lines()
            .find_map(|line| line.trim().strip_prefix(&prefix))
            .map(|value| value.trim().to_string())
    }

    /// One `MARK key=<http status>` line, as a number.
    fn mark_code(stdout: &str, key: &str) -> Option<u16> {
        mark(stdout, key).and_then(|value| value.parse().ok())
    }

    /// What the dialog seam saw, one `(host, agent reason)` per consultation.
    ///
    /// An alias rather than the literal type: the seam is what P2.2 leg 2
    /// asserts on, and `clippy::type_complexity` asks for exactly this.
    type DialogCalls = Arc<Mutex<Vec<(String, Option<String>)>>>;

    /// The eight statuses leg 1 asserts, printed in one line.
    fn p22_statuses(stdout: &str) -> String {
        [
            "post_intent",
            "get_declared",
            "post_explain",
            "get_after_explain",
            "get_after_consume",
            "get_undeclared",
            "post_malformed",
            "get_wrong_credential",
        ]
        .iter()
        .map(|key| format!("{key}={:?}", mark_code(stdout, key)))
        .collect::<Vec<_>>()
        .join(" ")
    }

    /// P2.2 leg 1 of 2: **the whole D-4 roundtrip, end to end, from inside an MXC
    /// container**, against the supervisor's real listener.
    ///
    /// Proven in this leg (all unelevated, on this host):
    ///
    /// 1. the child carries `NO_PROXY` with all three loopback spellings, and the
    ///    proxy variable that carries the session token;
    /// 2. it derives the endpoint and its `Basic` credential from that token
    ///    itself (no argument is handed to it by the test);
    /// 3. `POST /sandbox/intent` → 204, then `GET …?host=` → 200 with the
    ///    declared reason, the normalized host and an RFC3339 `ts`;
    /// 4. `POST /sandbox/intent/explain` → 204 sets the flag, the first GET
    ///    reports `"hint":"explain-more"`, and the *next* GET reports
    ///    `"hint":"declared"` — the flag is one-shot;
    /// 5. an undeclared host is 404, a malformed body is 400, and a wrong
    ///    credential is 407 (`the control plane is not an unauthenticated
    ///    oracle`);
    /// 6. none of the eight calls is a proxy consultation: the listener's own
    ///    counters stay `{accepted: 0, tunnels: 0}` plus the wrapper's one
    ///    probe, which is what
    ///    `ProofExpectation::MustBeAbsent` refuses the launch over;
    /// 7. the only audit leaf the launch writes is the wrong credential's
    ///    `foreign_token` refusal (`host: "<unknown>"`), and nothing names a host
    ///    or allows anything — an intent call is not a decision.
    #[test]
    #[ignore = "launches a real ProcessContainer; run: cargo test --features mxc-backend --bin saife -- --ignored"]
    fn d4_intent_roundtrip_from_inside_the_container_is_proven() {
        let launcher = launcher_under_test();
        let proxy = LiveProxy::start(&[]);
        let counters = proxy.counters();
        let scratch = Scratch::plain("p22-intent");
        let dir = scratch.path().to_path_buf();
        let backend = supervisor_backend(
            counters.as_ref(),
            Some(proxy.port()),
            Some(proxy.token().value()),
            &launcher,
            SessionBudget::default(),
        )
        .with_budget(SessionBudget::new(
            Duration::from_secs(30),
            Duration::from_secs(80),
            Duration::from_secs(10),
        ));

        println!(
            "EVIDENCE elevated={} launcher={} proxy_port={} sid={}",
            process_is_elevated(),
            launcher.display(),
            proxy.port(),
            proxy.sid
        );

        // ---- 1. the child's environment: NO_PROXY and the session token -----
        let outcome = backend
            .launch(
                &live_input(proxy.port(), &dir, &launcher, "cmd /c set".to_string()),
                ProofExpectation::MustBeAbsent,
            )
            .expect("environment dump launch");
        let env_dump = stdout_of(&outcome);
        let no_proxy = env_dump
            .lines()
            .find(|line| line.to_ascii_lowercase().starts_with("no_proxy="))
            .map(|line| line.trim().to_string())
            .unwrap_or_default();
        let http_proxy = env_dump
            .lines()
            .find(|line| line.to_ascii_uppercase().starts_with("HTTP_PROXY="))
            .map(|line| line.trim().to_string())
            .unwrap_or_default();
        // P2.4: the D-0.3 **discovery** contract, not just the proxy URL. The
        // AppContainer path injects `SAIFE_PROXY_PORT`
        // (`src/sandbox/appcontainer.rs:1007`); until P2.4 the MXC launcher did
        // not, so a workload written to D-0.3 (`GET
        // http://127.0.0.1:$SAIFE_PROXY_PORT/sandbox/intent`) could not find
        // the endpoint at all under this backend. The value must be THIS
        // listener's port: an inherited or stale number would point the
        // workload at a socket the supervisor does not own.
        let proxy_port_var = env_dump
            .lines()
            .find(|line| line.starts_with("SAIFE_PROXY_PORT="))
            .map(|line| line.trim().to_string())
            .unwrap_or_default();
        println!(
            "EVIDENCE child_env {no_proxy:?} {http_proxy:?} {proxy_port_var:?} proof={:?}",
            outcome.proxy_proof
        );
        let no_proxy_value = no_proxy
            .split_once('=')
            .map(|(_, value)| value.trim())
            .unwrap_or_default();
        assert_eq!(
            no_proxy_value, "localhost,127.0.0.1,::1",
            "the child must carry NO_PROXY from the launcher: {no_proxy:?}"
        );
        for spelling in ["localhost", "127.0.0.1", "::1"] {
            assert!(
                no_proxy_value.split(',').any(|host| host == spelling),
                "NO_PROXY must name the loopback spelling {spelling}: {no_proxy_value:?}"
            );
        }
        // Without the token in the proxy variable a real workload has no
        // credential for the control plane, so the endpoints would be
        // unreachable while NO_PROXY still looked correct.
        assert!(
            http_proxy.to_ascii_lowercase().contains(&format!(
                "sandbox:{}@127.0.0.1:{}",
                proxy.token().value(),
                proxy.port()
            )),
            "the child's proxy variable must carry the session token: {http_proxy:?}"
        );
        // The D-0.3 contract: a workload discovers the control plane from this
        // variable, so it must exist AND name this listener.
        let port_var_value = proxy_port_var
            .split_once('=')
            .map(|(_, value)| value.trim())
            .unwrap_or_default();
        assert_eq!(
            port_var_value,
            proxy.port().to_string(),
            "the child must carry SAIFE_PROXY_PORT naming this listener's port \
             (D-0.3 discovery); absent or a different port makes the D-4 endpoint \
             undiscoverable by a workload that only knows that contract: {proxy_port_var:?}"
        );

        // ---- 2. the roundtrip, the one-shot and the negative cases ----------
        let command = p22_script(
            &dir,
            "p22-roundtrip",
            P22_HOST,
            P22_REASON,
            P22_ROUNDTRIP_BODY,
        );
        println!("EVIDENCE roundtrip_command={command:?}");
        let outcome = backend
            .launch(
                &live_input(proxy.port(), &dir, &launcher, command),
                ProofExpectation::MustBeAbsent,
            )
            .expect("intent calls are not proxy consultations, so guardrail 1 must see {0,0}");
        let out = stdout_of(&outcome);
        println!(
            "EVIDENCE roundtrip exit={:?} success={} proof={:?} expectation={:?} tier={:?}",
            outcome.exit_code,
            outcome.success(),
            outcome.proxy_proof,
            outcome.expectation,
            outcome.tier.tier
        );
        println!("EVIDENCE roundtrip_stdout={:?}", out.trim());
        println!("EVIDENCE roundtrip_stderr={:?}", stderr_of(&outcome).trim());
        assert_eq!(
            outcome.exit_code,
            Some(0),
            "the control-plane script must exit 0: {outcome:?}"
        );
        assert!(
            out.contains("MARK done"),
            "the script must have run every call: {out:?}"
        );
        // The endpoint came from the child's own environment, not from the test:
        // if the test had supplied it, this line could not exist.
        assert_eq!(
            mark(&out, "parsed_port"),
            Some(proxy.port().to_string()),
            "the child must derive the port from its own HTTP_PROXY: {out:?}"
        );
        assert_eq!(
            mark(&out, "auth"),
            Some("derived".to_string()),
            "the child must derive its own Basic credential from the session token: {out:?}"
        );

        println!("EVIDENCE statuses {}", p22_statuses(&out));
        assert_eq!(
            mark_code(&out, "post_intent"),
            Some(204),
            "POST /sandbox/intent must answer 204: {out:?}"
        );
        assert_eq!(
            mark_code(&out, "get_declared"),
            Some(200),
            "GET /sandbox/intent must answer 200 for a declared host: {out:?}"
        );
        assert_eq!(
            mark_code(&out, "post_explain"),
            Some(204),
            "POST /sandbox/intent/explain must answer 204: {out:?}"
        );
        assert_eq!(
            mark_code(&out, "get_after_explain"),
            Some(200),
            "the GET after an explain POST must still answer 200: {out:?}"
        );
        assert_eq!(
            mark_code(&out, "get_after_consume"),
            Some(200),
            "the second GET after an explain POST must still answer 200: {out:?}"
        );
        assert_eq!(
            mark_code(&out, "get_undeclared"),
            Some(404),
            "an undeclared host must be 404, never a fabricated entry: {out:?}"
        );
        assert_eq!(
            mark_code(&out, "post_malformed"),
            Some(400),
            "a malformed body must be 400, never a 204 that swallows it: {out:?}"
        );
        assert_eq!(
            mark_code(&out, "get_wrong_credential"),
            Some(407),
            "a wrong credential must be refused before routing, or the control plane is an \
             unauthenticated oracle: {out:?}"
        );

        // ---- 3. the bodies: the declared reason, the ts, the one-shot -------
        let body = |name: &str| std::fs::read_to_string(dir.join(name)).unwrap_or_default();
        let parsed = |name: &str| -> serde_json::Value {
            serde_json::from_str(&body(name))
                .unwrap_or_else(|e| panic!("{name} is not JSON ({e}): {:?}", body(name)))
        };

        let declared = parsed("out-get-declared.json");
        println!("EVIDENCE get_declared_body={declared}");
        assert_eq!(
            declared["host"], P22_HOST,
            "GET must echo the normalized host it looked up: {declared}"
        );
        assert_eq!(
            declared["reason"], P22_REASON,
            "GET must return the reason the container declared, verbatim: {declared}"
        );
        assert_eq!(
            declared["hint"], "declared",
            "a declared entry with no explain request reports `declared`: {declared}"
        );
        let ts = declared["ts"]
            .as_str()
            .unwrap_or_else(|| panic!("a 200 must carry a ts: {declared}"));
        assert!(
            ts.len() == 20
                && ts.ends_with('Z')
                && ts.as_bytes()[4] == b'-'
                && ts.as_bytes()[10] == b'T',
            "ts must be RFC3339 UTC whole seconds (YYYY-MM-DDTHH:MM:SSZ): {ts:?}"
        );
        let year: u32 = ts[..4].parse().expect("a four-digit year");
        assert!(
            year >= 2026,
            "ts must be this run's wall clock, not the epoch: {ts:?}"
        );

        // D-4's one-shot: the explain POST sets the flag, ONE read consumes it.
        let flagged = parsed("out-get-flagged.json");
        println!("EVIDENCE get_after_explain_body={flagged}");
        assert_eq!(
            flagged["hint"], "explain-more",
            "POST /sandbox/intent/explain must take effect: the next GET reports the hint \
             (the 204 alone would not prove it): {flagged}"
        );
        let consumed = parsed("out-get-consumed.json");
        println!("EVIDENCE get_after_consume_body={consumed}");
        assert_eq!(
            consumed["hint"], "declared",
            "the explain-more flag is ONE-SHOT: the read above consumed it, so the next GET must \
             not report it again: {consumed}"
        );
        assert_eq!(
            consumed["reason"], P22_REASON,
            "consuming the hint must not disturb the entry: {consumed}"
        );

        let undeclared = parsed("out-get404.json");
        println!("EVIDENCE get_undeclared_body={undeclared}");
        assert_eq!(
            undeclared["hint"], "undeclared",
            "a 404 reports the undeclared hint: {undeclared}"
        );
        assert_eq!(
            undeclared["reason"], "",
            "a 404 must not invent a reason: {undeclared}"
        );
        assert_eq!(
            body("out-post400.txt"),
            "",
            "a 400 carries no body: {:?}",
            body("out-post400.txt")
        );
        assert_eq!(
            body("out-get407.txt"),
            "",
            "a 407 carries no body: {:?}",
            body("out-get407.txt")
        );

        // ---- 4. no proxy consultation, and no decision leaf ----------------
        assert_eq!(
            outcome.expectation,
            ProofExpectation::MustBeAbsent,
            "the intent calls can only be proven direct if the session expected no consultation"
        );
        assert_eq!(
            outcome.proxy_proof,
            ProxyProof {
                accepted: 0,
                tunnels: 0,
                // The wrapper's pre-flight probe, and nothing else: an intent call
                // served on the listener is NOT a proxy consultation.
                probes: 1,
                // Exactly one: the workload's OWN `407` leg sends a wrong credential
                // on purpose (`get_wrong_credential=407`). It is a control-plane
                // refusal, so it counts as an unauthenticated attempt (P3.2a) and
                // still never as traffic - and the session's expectation here is
                // `MustBeAbsent`, which this counter cannot affect.
                unauthenticated: 1,
            },
            "the roundtrip must record the probe, zero proxy traffic and the one \
             407 the workload asked for: {outcome:?}"
        );

        let leaves = audit_leaves(&proxy.sid);
        for leaf in &leaves {
            println!("EVIDENCE audit_leaf={leaf}");
        }
        assert_eq!(
            connect_leaves(&proxy.sid),
            leaves.len(),
            "every leaf this launch wrote is a CONNECT-shaped leaf: {leaves:?}"
        );
        assert!(
            leaves.iter().all(|leaf| leaf["host"] == "<unknown>"),
            "no intent call may write a decision leaf naming a host: {leaves:?}"
        );
        assert!(
            leaves.iter().all(|leaf| leaf["disposition"] != "allow"),
            "no intent call may write an allow leaf: {leaves:?}"
        );
        assert_eq!(
            leaves.len(),
            1,
            "exactly one leaf is expected: the wrong credential's own refusal (P1.4 records a \
             foreign token, which is not a decision): {leaves:?}"
        );
        assert_eq!(
            leaves[0]["reason"], "foreign_token",
            "the 407 must be recorded as a refused credential, not as a decision: {leaves:?}"
        );

        println!(
            "EVIDENCE done: D-4 roundtrip (204/200/204, one-shot consumed), 404/400/407, zero \
             proxy consultations, only the credential refusal in the chain"
        );
    }

    /// P2.2 leg 2 of 2: **D-4's actual point** — a reason declared by a process
    /// *inside the container* is what the user's dialog sees when that host is
    /// consulted.
    ///
    /// `prompt_default` (`src/net/proxy.rs`) reads the registry through
    /// `ctx.prompt.intent.lookup_host(host)` before it calls the coordinator, and
    /// the unit test `prompt_receives_declared_intent_reason` pins that wiring
    /// in-process. This leg proves the same thing **across the container
    /// boundary**: the child POSTs the intent, then the child itself issues a
    /// CONNECT, and the dialog seam — the only thing that sees the request —
    /// receives the child's own string.
    ///
    /// The launch is *expected* to fail guardrail 1 with
    /// `ProxyConsultedUnexpectedly`: that failure is the proof that the CONNECT
    /// really reached the decision pipeline, i.e. that the reason was not observed
    /// by some shortcut the product does not take.
    #[test]
    #[ignore = "launches a real ProcessContainer; run: cargo test --features mxc-backend --bin saife -- --ignored"]
    fn a_declared_intent_is_the_prompt_reason_from_inside_the_container() {
        let launcher = launcher_under_test();
        let seen: DialogCalls = Arc::new(Mutex::new(Vec::new()));
        let recorder = Arc::clone(&seen);
        let dialog: DialogFn = Arc::new(move |request: &DialogRequest| {
            recorder
                .lock()
                .unwrap()
                .push((request.host.clone(), request.reason.clone()));
            Ok(PromptResult::Deny {
                persist: false,
                scope: "host".to_string(),
                suffix: None,
            })
        });
        let proxy = LiveProxy::start_prompting(&[], dialog);
        let counters = proxy.counters();
        let scratch = Scratch::plain("p22-prompt");
        let dir = scratch.path().to_path_buf();
        let backend = supervisor_backend(
            counters.as_ref(),
            Some(proxy.port()),
            Some(proxy.token().value()),
            &launcher,
            SessionBudget::default(),
        )
        .with_budget(SessionBudget::new(
            Duration::from_secs(30),
            Duration::from_secs(80),
            Duration::from_secs(10),
        ));

        println!(
            "EVIDENCE elevated={} launcher={} proxy_port={} prompt_enabled=true consult_host={}",
            process_is_elevated(),
            launcher.display(),
            proxy.port(),
            P22_PROMPT_HOST
        );
        let command = p22_script(
            &dir,
            "p22-prompt",
            P22_PROMPT_HOST,
            P22_REASON,
            P22_PROMPT_BODY,
        );
        let err = backend
            .launch(
                &live_input(proxy.port(), &dir, &launcher, command),
                // The expectation a session with no network use states: the
                // failure below is the positive evidence of a consultation.
                ProofExpectation::MustBeAbsent,
            )
            .expect_err("the CONNECT must reach the proxy, so guardrail 1 must refuse the launch");
        println!("EVIDENCE consult_guard={err}");
        // P3.0 shape: a refusal raised AFTER the child ran is `Unproven` and
        // carries the outcome; the refused LEG is what this asserts. (Written
        // for the pre-P3.0 `Guard` shape, so this line was red until the
        // 2026-10-22 pass — the gate itself never changed.)
        assert!(
            matches!(
                err,
                MxcError::Unproven(ref refused)
                    if refused.error == GuardError::ProxyConsultedUnexpectedly
            ),
            "the CONNECT must have been counted as a real consultation, not skipped: {err:?}"
        );

        let read = |name: &str| std::fs::read_to_string(dir.join(name)).unwrap_or_default();
        let intent_marker = read("markers-prompt.txt");
        let connect_marker = read("markers-connect.txt");
        println!("EVIDENCE prompt_intent_marker={:?}", intent_marker.trim());
        println!("EVIDENCE prompt_connect_marker={:?}", connect_marker.trim());
        assert_eq!(
            mark_code(&intent_marker, "prompt_intent"),
            Some(204),
            "the container must declare its intent before consulting: {intent_marker:?}"
        );

        let calls = seen.lock().unwrap().clone();
        println!("EVIDENCE dialog_calls={calls:?}");
        let for_host: Vec<&(String, Option<String>)> = calls
            .iter()
            .filter(|(host, _)| host == P22_PROMPT_HOST)
            .collect();
        assert!(
            !for_host.is_empty(),
            "the dialog must have been asked about the consulted host: {calls:?}"
        );
        assert!(
            for_host
                .iter()
                .all(|(_, reason)| reason.as_deref() == Some(P22_REASON)),
            "the dialog must receive the reason the container declared — D-4's point — not \
             `None` and not some other string: {calls:?}"
        );

        let leaves = audit_leaves(&proxy.sid);
        for leaf in &leaves {
            println!("EVIDENCE audit_leaf={leaf}");
        }
        assert!(
            leaves
                .iter()
                .any(|leaf| leaf["host"] == P22_PROMPT_HOST && leaf["disposition"] == "deny"),
            "the refused consultation must be audited for the consulted host: {leaves:?}"
        );
        assert!(
            leaves.iter().any(|leaf| leaf["source"] == "prompt"),
            "the leaf must name the dialog as the decision's source: {leaves:?}"
        );

        println!(
            "EVIDENCE done: the container's declared reason reached the prompt, and the \
             consultation was counted"
        );
    }

    // =====================================================================
    // P2.4 / ADR-0004 guardrail 1 (amended 2026-10-22): the pre-flight probe
    // =====================================================================
    //
    // ADR-0004: "`warnings: []` is NOT evidence; a session MUST NOT be reported
    // as successful unless the supervisor can prove the child reached the
    // proxy." The evidence is now the WRAPPER's own probe of this listener,
    // issued before the payload starts and counted on the listener's side, in
    // the launch's epoch — because the old `>= 1 tunnel` rule demanded a
    // WORKLOAD event, so every network session whose workload made no request
    // was refused while its proxy path was fine (S-55, S-77, S-86, S-91).
    //
    // What a live leg adds that a unit test cannot: `verify_proxy_proof` is
    // tested pure, but these two show the PRODUCT path running it around a real
    // ProcessContainer — the wrapper really probed, or really could not.

    /// The live leg's workload: prove it RAN (a marker file in the granted
    /// workspace), touch no network at all, exit 0.
    ///
    /// A refusal for a child that failed to start would prove nothing about the
    /// gate, so the marker is each leg's positive control.
    const P24_SILENT_BODY: &str =
        "> p24-ran.txt echo MARK workload=completed-no-network\r\nexit /b 0\r\n";

    /// Write one CRLF batch file into the container's workspace and return the
    /// command line that runs it.
    ///
    /// The P2.2 helper's D-4 prelude is deliberately not reused: this workload
    /// must do *nothing* except print its marker, so it cannot consult the proxy
    /// by accident and turn a gate test into a networking test.
    fn p24_script(dir: &Path, name: &str, body: &str) -> String {
        let path = dir.join(format!("{name}.bat"));
        // CRLF before it reaches cmd.exe, independently of the source file's own
        // line endings (a batch file with bare LF loses its lines).
        let script = body.replace("\r\n", "\n").replace('\n', "\r\n");
        std::fs::write(&path, script.as_bytes())
            .unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
        format!("cmd /c \"{}\"", path.display())
    }

    /// **The S-77/S-86/S-91 shape, live.** A network session whose workload
    /// makes NO request succeeds, because the wrapper's probe reached the
    /// listener: `probes == 1` with `accepted == 0, tunnels == 0`.
    ///
    /// This is the leg that was refused before the amendment, and refusing it is
    /// a product cliff: `saife run --allow-domain api.anthropic.com -- echo hi`
    /// failed a user who did nothing wrong.
    #[test]
    #[ignore = "launches a real ProcessContainer; run: cargo test --features mxc-backend --bin saife -- --ignored"]
    fn a_launch_whose_workload_makes_no_request_passes_on_the_wrapper_probe() {
        let launcher = launcher_under_test();
        let proxy = LiveProxy::start(&[]);
        let counters = proxy.counters();
        let scratch = Scratch::plain("p24-probe-ok");
        let dir = scratch.path().to_path_buf();
        let backend = supervisor_backend(
            counters.as_ref(),
            Some(proxy.port()),
            Some(proxy.token().value()),
            &launcher,
            SessionBudget::default(),
        )
        .with_budget(SessionBudget::new(
            Duration::from_secs(30),
            Duration::from_secs(80),
            Duration::from_secs(10),
        ));

        println!(
            "EVIDENCE elevated={} launcher={} proxy_port={} expectation=Required sid={}",
            process_is_elevated(),
            launcher.display(),
            proxy.port(),
            proxy.sid
        );
        assert_eq!(
            counters.active_epoch(),
            None,
            "no launch epoch may be open before this one starts"
        );

        let command = p24_script(&dir, "p24-silent", P24_SILENT_BODY);
        println!("EVIDENCE silent_command={command:?}");
        let outcome = backend
            .launch(
                &live_input(proxy.port(), &dir, &launcher, command),
                ProofExpectation::Required,
            )
            .expect(
                "a network session whose wrapper probed MUST pass guardrail 1, even though its \
                 workload never opened a socket",
            );
        println!(
            "EVIDENCE silent_workload exit={:?} success={} proof={:?} tier={:?}",
            outcome.exit_code,
            outcome.success(),
            outcome.proxy_proof,
            outcome.tier.tier
        );

        // ---- 1. the session really ran -------------------------------------
        assert_eq!(outcome.exit_code, Some(0), "{outcome:?}");
        assert!(outcome.success(), "a probed launch is a successful session");
        let ran = std::fs::read_to_string(dir.join("p24-ran.txt")).unwrap_or_default();
        println!("EVIDENCE silent_workload marker={ran:?}");
        assert!(
            ran.contains("MARK workload=completed-no-network"),
            "the workload must have run to completion: {ran:?}"
        );

        // ---- 2. the probe is the evidence, read from the LISTENER ----------
        assert_eq!(
            outcome.proxy_proof.probes, 1,
            "the wrapper's probe must be counted exactly once: {:?}",
            outcome.proxy_proof
        );
        assert_eq!(
            (outcome.proxy_proof.accepted, outcome.proxy_proof.tunnels),
            (0, 0),
            "this workload made no request, so there is no traffic to record: {:?}",
            outcome.proxy_proof
        );
        let epoch1 = counters.counters(1).expect(
            "this launch must have opened epoch 1: an absent epoch reports the same \
                     numbers, so `Some` is the part that means anything",
        );
        println!(
            "EVIDENCE silent_proof epoch=1 counters={epoch1:?} proof={:?} active={:?}",
            counters.proof(1),
            counters.active_epoch()
        );
        assert_eq!(
            epoch1,
            LaunchProofCounters {
                consultations: 0,
                upstream_established: 0,
                probes: 1,
                unauthenticated: 0,
            },
            "a probe is neither a consultation nor an upstream connection"
        );
        assert_eq!(
            counters.active_epoch(),
            None,
            "the launch path must close the epoch it opened"
        );

        // ---- 3. nothing claims a proxy event that never happened -----------
        let leaves = audit_leaves(&proxy.sid);
        println!(
            "EVIDENCE silent_audit leaves={} connect_leaves={}",
            leaves.len(),
            connect_leaves(&proxy.sid)
        );
        assert_eq!(
            connect_leaves(&proxy.sid),
            0,
            "a workload that made no request must leave no CONNECT leaf: {leaves:?}"
        );

        println!(
            "EVIDENCE done: a network session whose workload made no request passed on the \
             wrapper's probe (probes=1, accepted=0, tunnels=0)"
        );
    }

    /// **The refusal, live, with the real mechanism.** The wrapper is pointed at
    /// a port nothing listens on, so its probe never arrives: the session is
    /// refused with `proxy_probe_unmet`, even though the workload exited 0.
    ///
    /// The proof source is a REAL listener (a `LiveProxy`), so the zeros below
    /// are that listener's own epoch, opened for this launch and never probed —
    /// not a fake that cannot count.
    #[test]
    #[ignore = "launches a real ProcessContainer; run: cargo test --features mxc-backend --bin saife -- --ignored"]
    fn a_launch_whose_probe_never_arrives_is_refused_with_proxy_probe_unmet() {
        let launcher = launcher_under_test();
        let proxy = LiveProxy::start(&[]);
        let counters = proxy.counters();
        // A port that is nobody's listener: bound, then closed. The wrapper's
        // probe gets a refused connection, which it swallows — the gate, not the
        // wrapper, is what refuses the session.
        let dead_port = {
            let probe_listener = TcpListener::bind("127.0.0.1:0").expect("bind a port to abandon");
            let port = probe_listener
                .local_addr()
                .expect("abandoned address")
                .port();
            drop(probe_listener);
            port
        };
        let scratch = Scratch::plain("p24-probe-dead");
        let dir = scratch.path().to_path_buf();
        let backend = supervisor_backend(
            counters.as_ref(),
            Some(dead_port),
            Some(proxy.token().value()),
            &launcher,
            SessionBudget::default(),
        )
        .with_budget(SessionBudget::new(
            Duration::from_secs(30),
            Duration::from_secs(80),
            Duration::from_secs(10),
        ));

        println!(
            "EVIDENCE elevated={} launcher={} dead_proxy_port={dead_port} live_listener_port={} \
             expectation=Required sid={}",
            process_is_elevated(),
            launcher.display(),
            proxy.port(),
            proxy.sid
        );

        let command = p24_script(&dir, "p24-silent", P24_SILENT_BODY);
        println!("EVIDENCE silent_command={command:?}");
        let err = backend
            .launch(
                &live_input(dead_port, &dir, &launcher, command),
                ProofExpectation::Required,
            )
            .expect_err(
                "a session whose probe never arrived must be REFUSED, never reported successful \
                 on `warnings: []` or on the child's exit code",
            );
        println!("EVIDENCE silent_guard={err}");

        // ---- 1. the refusal names the missing evidence ---------------------
        assert!(
            matches!(err, MxcError::Unproven(ref refused) if refused.error == GuardError::ProbeUnmet),
            "the missing probe must be reported as ProbeUnmet — not as a generic failure, and \
             certainly not as a success: {err:?}"
        );
        assert!(
            err.to_string().contains("proxy_probe_unmet"),
            "the operator-facing refusal must carry the reason token: {err}"
        );
        assert!(
            err.to_string().contains("probe"),
            "the refusal must name the evidence that was missing: {err}"
        );
        assert!(
            matches!(
                std::error::Error::source(&err),
                Some(source) if source.to_string() == err.to_string()
            ),
            "the typed error must be reachable through `source`, so a caller can match on it: \
             {err:?}"
        );

        // ---- 2. the child really ran ---------------------------------------
        let ran = std::fs::read_to_string(dir.join("p24-ran.txt")).unwrap_or_default();
        println!("EVIDENCE silent_workload marker={ran:?}");
        assert!(
            ran.contains("MARK workload=completed-no-network"),
            "the workload must have run to completion, so the refusal is about the missing probe \
             rather than about a child that never started: {ran:?}"
        );

        // ---- 3. the listener's own epoch: opened, empty, closed -------------
        let epoch1 = counters
            .counters(1)
            .expect("this launch must have opened epoch 1 on the live listener");
        println!(
            "EVIDENCE silent_proof epoch=1 counters={epoch1:?} proof={:?} active={:?}",
            counters.proof(1),
            counters.active_epoch()
        );
        assert_eq!(
            epoch1,
            LaunchProofCounters::default(),
            "nothing may have probed or consulted this listener: the wrapper was pointed at a \
             dead port"
        );
        assert_eq!(
            counters.active_epoch(),
            None,
            "the refusal path must close the epoch too (no window left open on an error)"
        );

        // ---- 4. no leaf claims a decision -----------------------------------
        let leaves = audit_leaves(&proxy.sid);
        assert_eq!(
            connect_leaves(&proxy.sid),
            0,
            "the refused launch must leave no CONNECT-shaped leaf: {leaves:?}"
        );

        println!(
            "EVIDENCE done: a launch whose probe never arrived was refused with \
             proxy_probe_unmet, its workload had already exited 0, and nothing claimed a decision"
        );
    }

    /// The tool's own control plane is a deny for every launch, whether or not the
    /// profile names one: `.saife` holds plugin manifests whose command runs
    /// host-side, and `%LOCALAPPDATA%\saife` holds the audit log and signing key.
    #[test]
    fn the_tool_control_plane_is_always_denied() {
        let home = std::env::var("USERPROFILE").expect("USERPROFILE");
        let policy = filesystem_policy(
            std::path::Path::new(r"C:\work"),
            &[],
            &[],
            &[],
            Some(Path::new(&home)),
            std::path::Path::new(r"C:\launcher.exe"),
        )
        .expect("no deny covers a grant");
        let want = Path::new(&home).join(".saife").display().to_string();
        assert!(
            policy.denied_paths.iter().any(|d| d.eq_ignore_ascii_case(&want)),
            ".saife must be denied: {:?}",
            policy.denied_paths
        );
        if let Some(lad) = std::env::var_os("LOCALAPPDATA") {
            let audit = Path::new(&lad).join("saife").display().to_string();
            assert!(
                policy.denied_paths.iter().any(|d| d.eq_ignore_ascii_case(&audit)),
                "%LOCALAPPDATA%\\saife must be denied: {:?}",
                policy.denied_paths
            );
        }
    }

    /// Granting the control plane is refused, not silently narrowed: a workload
    /// that can write `.saife/plugins` can have a sidecar executed host-side.
    #[test]
    fn granting_the_control_plane_is_refused() {
        let home = std::path::PathBuf::from(std::env::var("USERPROFILE").expect("USERPROFILE"));
        let err = filesystem_policy(
            std::path::Path::new(r"C:\work"),
            &[home.join(".saife").join("plugins")],
            &[],
            &[],
            None,
            std::path::Path::new(r"C:\launcher.exe"),
        )
        .expect_err("a grant inside .saife must be refused");
        assert!(
            matches!(err, RequestError::DenyCoversGrant { .. }),
            "expected DenyCoversGrant, got {err:?}"
        );
    }

    /// F-11: the launcher runs on the HOST at the next launch. A writable grant that
    /// contains it lets this workload replace the binary that the next session
    /// executes with the supervisor's rights.
    #[test]
    fn a_writable_grant_that_contains_the_launcher_is_refused() {
        let launcher_dir = std::path::PathBuf::from(r"C:\tools\saife");
        let launcher = launcher_dir.join("saife-launch.exe");
        let err = filesystem_policy(
            std::path::Path::new(r"C:\work"),
            std::slice::from_ref(&launcher_dir),
            &[],
            &[],
            None,
            &launcher,
        )
        .expect_err("a grant containing the launcher must be refused");
        match err {
            RequestError::GrantCoversLauncher { grant, .. } => {
                assert_eq!(grant, launcher_dir.display().to_string());
            }
            other => panic!("expected GrantCoversLauncher, got {other:?}"),
        }
    }
