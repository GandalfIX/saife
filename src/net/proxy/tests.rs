// Extracted from src/net/proxy.rs `#[cfg(test)] mod tests` (2026-10-25), verbatim.
// Keep the indentation: a blind dedent rewrites multi-line raw-string contents.

    use super::*;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

    thread_local! {
        /// The credential of the listener this test thread spawned last.
        ///
        /// The suite runs dozens of listeners in one process, and `spawn` now
        /// refuses a token that is already live (P1.6(b)), so the fixture can no
        /// longer hand every listener one constant value. The request builders
        /// (`auth_header`, `connect_req`, `http_req`) read the value from here
        /// instead, which keeps them matching the listener the test just started.
        /// A test that needs a *different* credential presents it explicitly with
        /// `connect_req_with`.
        static LISTENER_TOKEN: std::cell::RefCell<String> =
            std::cell::RefCell::new(TEST_TOKEN.to_string());
    }

    /// A credential no other live listener in this process can already hold.
    ///
    /// `TEST_TOKEN`-prefixed so a leaked value in a log line is recognisably a
    /// fixture, and serialised so the value is deterministic per process.
    fn unique_test_token() -> RunToken {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let serial = NEXT.fetch_add(1, Ordering::Relaxed);
        RunToken::for_tests(&format!("{TEST_TOKEN}-{serial}"))
    }

    /// The credential `auth_header` presents: the last one spawned on this thread.
    fn listener_token() -> String {
        LISTENER_TOKEN.with(|token| token.borrow().clone())
    }

    fn make_head(auth: &str) -> String {
        format!("CONNECT api.example.com:443 HTTP/1.1\r\nProxy-Authorization: {auth}\r\n\r\n")
    }

    fn basic(token: &str) -> String {
        let creds = base64::engine::general_purpose::STANDARD.encode(format!("sandbox:{token}"));
        format!("Basic {creds}")
    }

    fn own_run() -> RunToken {
        RunToken::for_tests("abc123")
    }

    #[test]
    fn valid_basic_auth_is_the_own_run() {
        assert_eq!(
            classify_auth(&make_head(&basic("abc123")), &own_run()),
            AuthVerdict::OwnRun
        );
    }

    #[test]
    fn missing_auth_header_is_absent() {
        let head = "CONNECT api.example.com:443 HTTP/1.1\r\nHost: api.example.com\r\n\r\n";
        assert_eq!(classify_auth(head, &own_run()), AuthVerdict::Absent);
    }

    /// The distinction P1.4 turns on: another run's token is not "no
    /// credential", it is a credential this listener does not own.
    #[test]
    fn another_runs_token_is_foreign_not_absent() {
        assert_eq!(
            classify_auth(&make_head(&basic("another-runs-token")), &own_run()),
            AuthVerdict::Foreign
        );
    }

    #[test]
    fn wrong_scheme_is_absent() {
        let creds = base64::engine::general_purpose::STANDARD.encode("sandbox:abc123");
        let head = make_head(&format!("Bearer {creds}"));
        assert_eq!(classify_auth(&head, &own_run()), AuthVerdict::Absent);
    }

    #[test]
    fn case_insensitive_header_name_is_the_own_run() {
        let creds = base64::engine::general_purpose::STANDARD.encode("sandbox:abc123");
        let head = format!("CONNECT x:443 HTTP/1.1\r\nproxy-AUTHORIZATION: Basic {creds}\r\n\r\n");
        assert_eq!(classify_auth(&head, &own_run()), AuthVerdict::OwnRun);
    }

    #[test]
    fn undecodable_and_colonless_credentials_are_absent() {
        let colonless =
            base64::engine::general_purpose::STANDARD.encode("sandbox-token-without-a-colon");
        for raw in [
            "Basic".to_string(),
            "Basic ".to_string(),
            "Basic !!!not-base64!!!".to_string(),
            format!("Basic {colonless}"),
        ] {
            assert_eq!(
                classify_auth(&make_head(&raw), &own_run()),
                AuthVerdict::Absent,
                "{raw} is not a credential"
            );
        }
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
            None,
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
        assert!(
            v.get("suppressed").is_some(),
            "every leaf carries the key, so a consumer never has to distinguish \
             'absent' from 'nothing suppressed'"
        );
        assert_eq!(v["suppressed"], serde_json::Value::Null);
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
            None,
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
            None,
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

    /// P1.6 (blocking 1): the suppressed count is a first-class integer field.
    ///
    /// It used to be written as `scope: "suppressed=1"`, which put a number into
    /// a key whose documented domain is rule scope (`once` | `host` | `suffix` |
    /// null) and made the count a constant, because it was computed as
    /// `n - BUDGET` with `n` always one past the budget. Here the field itself is
    /// pinned: a JSON number when a leaf stands in for several refusals, `null`
    /// when it describes exactly one, and `scope` untouched either way.
    #[test]
    fn emit_connect_writes_suppressed_as_an_integer_or_null() {
        let sid = temp_sid("src-suppressed");
        let writer = crate::audit::AuditWriter::open(&sid, false).unwrap();
        emit_connect(
            &writer,
            "<unknown>",
            0,
            "deny",
            Some("no_token_suppressed"),
            "default",
            None,
            false,
            Some(12),
        )
        .unwrap();
        emit_connect(
            &writer,
            "<unknown>",
            0,
            "deny",
            Some("no_token"),
            "default",
            None,
            false,
            None,
        )
        .unwrap();
        let path = crate::audit::audit_log_path(&sid);
        let content = std::fs::read_to_string(&path).unwrap();
        let _ = std::fs::remove_file(&path);

        let mut lines = content.trim_end().lines();
        let aggregate: serde_json::Value = serde_json::from_str(lines.next().unwrap()).unwrap();
        let single: serde_json::Value = serde_json::from_str(lines.next().unwrap()).unwrap();
        assert!(
            aggregate["suppressed"].is_u64(),
            "a count must be a JSON number, not a string: {aggregate:?}"
        );
        assert_eq!(aggregate["suppressed"], 12);
        assert_eq!(
            aggregate["scope"],
            serde_json::Value::Null,
            "scope's domain is rule scope, never a count: {aggregate:?}"
        );
        assert_eq!(
            single["suppressed"],
            serde_json::Value::Null,
            "one request suppresses nothing: {single:?}"
        );
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

    // ====================================================================
    // Task 3.6 — prompt + intent + learned wiring. Strict TDD: each new
    // behavior below was watched RED before its implementation landed.
    // ====================================================================

    use crate::net::intent::{DEFAULT_TTL, IntentRegistry};
    use crate::net::learned::LearnedStore;
    use crate::net::prompt::{
        DialogFn, DialogRequest, DialogUnavailable, PromptConfig, PromptOutcome, PromptPolicy,
        PromptResult,
    };
    use std::path::PathBuf;
    use std::sync::Mutex as StdMutex;
    use std::time::Duration;

    /// Session token used by every 3.6 listener test.
    const TEST_TOKEN: &str = "t36-test-token";

    /// One `Deny once` decision, as the dialog backend would return it.
    fn deny_once_result() -> PromptResult {
        PromptResult::Deny {
            persist: false,
            scope: "host".into(),
            suffix: None,
        }
    }

    /// Run one future to completion on a throwaway runtime — the listener
    /// tests are sync (they block on the proxy's own runtime handshake),
    /// so registry/coordinator probes use this instead of `#[tokio::test]`.
    fn block_on<F: std::future::Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(f)
    }

    // ---- RFC3339 formatter (D-4 `ts` field) ------------------------------

    #[test]
    fn rfc3339_utc_known_values() {
        use std::time::{Duration as StdDuration, UNIX_EPOCH};
        assert_eq!(super::rfc3339_utc(UNIX_EPOCH), "1970-01-01T00:00:00Z");
        // 2024-01-01 00:00:00 UTC == 1704067200.
        assert_eq!(
            super::rfc3339_utc(UNIX_EPOCH + StdDuration::from_secs(1_704_067_200)),
            "2024-01-01T00:00:00Z"
        );
        // Hour/minute/second rendering.
        assert_eq!(
            super::rfc3339_utc(UNIX_EPOCH + StdDuration::from_secs(1_704_067_200 + 3661)),
            "2024-01-01T01:01:01Z"
        );
        // Pre-epoch clamps to the epoch — never panics, never negative.
        assert_eq!(
            super::rfc3339_utc(UNIX_EPOCH - StdDuration::from_secs(5)),
            "1970-01-01T00:00:00Z"
        );
    }

    // ---- Happy Eyeballs dial (D-1, [G-12]) -------------------------------

    async fn local_listener() -> (tokio::net::TcpListener, std::net::SocketAddr) {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let a = l.local_addr().unwrap();
        (l, a)
    }

    #[tokio::test]
    async fn happy_eyeballs_first_wins_over_unreachable_first_addr() {
        let (_l, live) = local_listener().await;
        // Nothing listens on 127.0.0.1:1 — loopback connect fails fast.
        let dead = "127.0.0.1:1".parse().unwrap();
        let s = super::happy_eyeballs_dial(vec![dead, live])
            .await
            .expect("must reach the live addr");
        assert_eq!(s.peer_addr().unwrap().port(), live.port());
    }

    #[tokio::test]
    async fn happy_eyeballs_all_dead_is_an_error() {
        let dead = "127.0.0.1:1".parse().unwrap();
        assert!(super::happy_eyeballs_dial(vec![dead, dead]).await.is_err());
    }

    #[tokio::test]
    async fn happy_eyeballs_reaches_addresses_beyond_the_first_batch() {
        let (_l, live) = local_listener().await;
        let mut addrs = Vec::new();
        for _ in 0..super::MAX_PARALLEL_DIALS {
            addrs.push("127.0.0.1:1".parse().unwrap());
        }
        addrs.push(live); // 9th address — only reachable via the 2nd batch.
        let s = super::happy_eyeballs_dial(addrs)
            .await
            .expect("second batch must dial");
        assert_eq!(s.peer_addr().unwrap().port(), live.port());
    }

    // ---- Task 5.2: pinned (admission-time) resolution --------------------

    /// The resolved-IP hard-deny leg is a pure predicate over the pinned set,
    /// so it is testable with any address list and the production dial path
    /// calls exactly this. RFC 3927 link-local, unrelated to the two named
    /// metadata literals — this is the CIDR leg.
    ///
    /// Table-driven over the /16 edges (Task 5.2 spec advisory 6): the first
    /// and last host in 169.254.0.0/16 must deny, the neighbours just outside
    /// must not — an off-by-one in the prefix or a `<=`/`<` slip shows here.
    #[test]
    fn pinned_addrs_hard_denied_catches_link_local_v4() {
        let public: SocketAddr = "203.0.113.9:443".parse().unwrap();
        let cases = [
            ("169.254.0.1:443", true),      // first host of the /16
            ("169.254.31.7:443", true),     // interior
            ("169.254.255.254:443", true),  // last host of the /16
            ("169.255.0.1:443", false),     // one past the /16
            ("169.253.255.254:443", false), // one before it
        ];
        for (addr, denied) in cases {
            let addrs = [public, addr.parse::<SocketAddr>().unwrap()];
            let verdict = super::pinned_addrs_hard_denied(&addrs, false);
            assert_eq!(
                verdict.is_some(),
                denied,
                "{addr} must {}be hard-denied",
                if denied { "" } else { "NOT " }
            );
            if let Some(d) = verdict {
                assert!(!d.allowed);
                assert_eq!(d.source, "hard-deny");
                assert_eq!(d.reason.as_deref(), Some("denied_cidr"));
            }
        }
    }

    /// fe80::/10 ([G-45]) — the v6 link-local CIDR. Same edge discipline: the
    /// last address of the /10 (`febf:ffff:…:ffff`) denies and `fec0::1`, the
    /// first address outside it, does not.
    #[test]
    fn pinned_addrs_hard_denied_catches_link_local_v6() {
        let public: SocketAddr = "[2001:db8::9]:443".parse().unwrap();
        let cases = [
            ("[fe80::1]:443", true),            // first host of the /10
            ("[fe80:abcd:1234::ff]:443", true), // interior
            ("[febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:443", true), // last address of the /10
            ("[fec0::1]:443", false),           // one past the /10
            ("[fe70::1]:443", false),           // one before it
        ];
        for (addr, denied) in cases {
            let addrs = [public, addr.parse::<SocketAddr>().unwrap()];
            let verdict = super::pinned_addrs_hard_denied(&addrs, false);
            assert_eq!(
                verdict.is_some(),
                denied,
                "{addr} must {}be hard-denied",
                if denied { "" } else { "NOT " }
            );
            if let Some(d) = verdict {
                assert_eq!(d.reason.as_deref(), Some("denied_cidr"));
            }
        }
    }

    /// No false positives: a public pinned set (and the empty set, which the
    /// DNS-failure path handles) is not a CIDR denial.
    #[test]
    fn pinned_addrs_hard_denied_allows_public_and_empty_sets() {
        let addrs = [
            "203.0.113.9:443".parse::<SocketAddr>().unwrap(),
            "[2001:db8::9]:443".parse::<SocketAddr>().unwrap(),
        ];
        assert!(super::pinned_addrs_hard_denied(&addrs, false).is_none());
        assert!(super::pinned_addrs_hard_denied(&[], false).is_none());
    }

    /// The gap Task 5.1 recorded: the pinned-IP hard-deny leg had no test.
    /// `dial_upstream` is the production call site — a literal keeps the test
    /// DNS-free, and the leg sees the same `Vec<SocketAddr>` a hostname's
    /// resolver answer produces, so this pins the leg a resolving hostname
    /// would hit too.
    ///
    /// The 2s bound (Task 5.2 spec advisory 5) keeps the test FAST-RED: with
    /// the hard-deny removed it reaches a real connect to 169.254.31.7:80 and
    /// would otherwise fail only after the OS SYN timeout (~20s). The bound
    /// does not weaken it — a dial attempt that is actually attempted cannot
    /// be mistaken for a denial.
    #[tokio::test]
    async fn dial_upstream_denies_a_pinned_link_local_v4_literal() {
        match tokio::time::timeout(
            Duration::from_secs(2),
            super::dial_upstream(None, "169.254.31.7", 80, false, super::system_lookup),
        )
        .await
        {
            Ok(Err(super::DialFailure::Denied(d))) => {
                assert_eq!(d.source, "hard-deny");
                assert_eq!(d.reason.as_deref(), Some("denied_cidr"));
            }
            Ok(Err(_)) => panic!("expected a Denied dial failure, not a dial attempt"),
            Ok(Ok(_)) => panic!("a link-local pinned address must never be dialed"),
            Err(_) => panic!("the deny must be decided before any dial is awaited"),
        }
    }

    #[tokio::test]
    async fn dial_upstream_denies_a_pinned_link_local_v6_literal() {
        match tokio::time::timeout(
            Duration::from_secs(2),
            super::dial_upstream(None, "[fe80::1]", 80, false, super::system_lookup),
        )
        .await
        {
            Ok(Err(super::DialFailure::Denied(d))) => {
                assert_eq!(d.reason.as_deref(), Some("denied_cidr"));
            }
            Ok(Err(_)) => panic!("expected a Denied dial failure, not a dial attempt"),
            Ok(Ok(_)) => panic!("a link-local pinned address must never be dialed"),
            Err(_) => panic!("the deny must be decided before any dial is awaited"),
        }
    }

    /// The gap Task 5.1 recorded, in its REAL shape: a hostname whose
    /// admission-time answer is link-local. Same production leg as the literal
    /// tests, but the address list arrives from the resolver exactly as a
    /// poisoned DNS answer would.
    #[tokio::test]
    async fn dial_upstream_denies_a_hostname_that_resolves_to_link_local() {
        let calls = AtomicUsize::new(0);
        let result = tokio::time::timeout(
            Duration::from_secs(2),
            super::dial_upstream(None, "metadata.evil.example", 80, false, |host, port| {
                calls.fetch_add(1, Ordering::SeqCst);
                assert_eq!((host.as_str(), port), ("metadata.evil.example", 80));
                async { Ok(vec!["169.254.31.7:80".parse::<SocketAddr>().unwrap()]) }
            }),
        )
        .await
        .expect("the deny must be decided before any dial is awaited");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        match result {
            Err(super::DialFailure::Denied(d)) => {
                assert_eq!(d.source, "hard-deny");
                assert_eq!(d.reason.as_deref(), Some("denied_cidr"));
            }
            Err(_) => panic!("expected a Denied dial failure, not a dial attempt"),
            Ok(_) => panic!("a hostname resolving into link-local must never be dialed"),
        }
    }

    /// [G-12] at the real call site: ONE resolution per admitted host, and the
    /// dial is seeded with exactly its answer (the winning peer proves which
    /// address was dialed). A second resolution would either bump `calls` or
    /// dial a different address.
    #[tokio::test]
    async fn dial_upstream_resolves_once_and_dials_only_that_answer() {
        let (_l, live) = local_listener().await;
        let calls = AtomicUsize::new(0);
        let s = match super::dial_upstream(None, "pinned.example", live.port(), true, |host, port| {
            // `true`: dial mechanics, not policy - the stand-in upstream is a local listener
            calls.fetch_add(1, Ordering::SeqCst);
            assert_eq!((host.as_str(), port), ("pinned.example", live.port()));
            async move { Ok(vec![live]) }
        })
        .await
        {
            Ok(s) => s,
            Err(_) => panic!("the pinned answer must be dialed"),
        };
        assert_eq!(s.peer_addr().unwrap(), live);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "exactly one resolution per admitted host"
        );
    }

    /// Step 1 / requirement 4: a literal IP is its own answer — the resolver
    /// seam is never consulted (counted, not merely "returns the same thing",
    /// which `lookup_host` would also do for a literal).
    #[tokio::test]
    async fn resolve_pinned_literal_ip_never_calls_the_resolver() {
        let calls = AtomicUsize::new(0);
        let addrs = super::resolve_pinned_with("192.0.2.7", 8443, |_host, _port| {
            calls.fetch_add(1, Ordering::SeqCst);
            async { Ok(Vec::new()) }
        })
        .await
        .unwrap();
        assert_eq!(addrs, vec!["192.0.2.7:8443".parse::<SocketAddr>().unwrap()]);
        let addrs = super::resolve_pinned_with("[2001:db8::9]", 443, |_host, _port| {
            calls.fetch_add(1, Ordering::SeqCst);
            async { Ok(Vec::new()) }
        })
        .await
        .unwrap();
        assert_eq!(
            addrs,
            vec!["[2001:db8::9]:443".parse::<SocketAddr>().unwrap()]
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "a literal IP must not touch the resolver"
        );
    }

    /// Step 1: exactly ONE resolution per admission, and its answer is used
    /// verbatim (brackets stripped, trailing dot and case preserved — the
    /// resolver owns normalization, this seam must not silently rewrite the
    /// name it pins).
    #[tokio::test]
    async fn resolve_pinned_hostname_resolves_exactly_once() {
        let expected = vec![
            "203.0.113.9:443".parse::<SocketAddr>().unwrap(),
            "203.0.113.10:443".parse::<SocketAddr>().unwrap(),
        ];
        let calls = AtomicUsize::new(0);
        let got = super::resolve_pinned_with("Pinned.Example.", 443, |host, port| {
            calls.fetch_add(1, Ordering::SeqCst);
            assert_eq!((host.as_str(), port), ("Pinned.Example.", 443));
            let answer = expected.clone();
            async move { Ok(answer) }
        })
        .await
        .unwrap();
        assert_eq!(got, expected);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "one resolution per admission"
        );
    }

    /// Step 3 / requirement 3 — anti-rebinding. The audit event carries no
    /// `resolved_ips` field (the D-5 taxonomy has no such key), so the pin is
    /// structural: the address list produced at admission is the ONLY list the
    /// dial seam is handed, no second resolution happens, and the socket that
    /// wins belongs to that set.
    #[tokio::test]
    async fn anti_rebinding_dials_exactly_the_admission_resolved_set() {
        let (_l, live) = local_listener().await;
        let dead = "203.0.113.1:443".parse::<SocketAddr>().unwrap();
        let expected = vec![dead, live];
        let answer = expected.clone();
        let resolve_calls = AtomicUsize::new(0);

        // (1) admission: one resolution, answer recorded.
        let admitted = super::resolve_pinned_with("rebind.example", live.port(), |host, port| {
            resolve_calls.fetch_add(1, Ordering::SeqCst);
            assert_eq!((host.as_str(), port), ("rebind.example", live.port()));
            let answer = answer.clone();
            async move { Ok(answer) }
        })
        .await
        .unwrap();
        assert_eq!(resolve_calls.load(Ordering::SeqCst), 1);

        // (2) the dial: every attempted address is recorded. The barrier makes
        // the recording complete before the winner can return.
        let seen = Arc::new(StdMutex::new(Vec::new()));
        let seen_seam = Arc::clone(&seen);
        let barrier = Arc::new(tokio::sync::Barrier::new(admitted.len()));
        // Timeout-bounded (Task 5.2 quality advisory 1): a regression to fewer
        // concurrent dials would leave the barrier unfulfilled forever, and an
        // unbounded barrier HANGS the suite instead of failing it.
        let s = tokio::time::timeout(
            Duration::from_secs(2),
            super::happy_eyeballs_dial_with(admitted.clone(), move |addr| {
                seen_seam.lock().unwrap().push(addr);
                let barrier = Arc::clone(&barrier);
                let fut: std::pin::Pin<Box<dyn Future<Output = io::Result<TcpStream>> + Send>> =
                    Box::pin(async move {
                        barrier.wait().await;
                        if addr == live {
                            TcpStream::connect(live).await
                        } else {
                            Err(io::Error::from(io::ErrorKind::ConnectionRefused))
                        }
                    });
                fut
            }),
        )
        .await
        .expect("every admitted address must be dialed concurrently")
        .unwrap();
        assert_eq!(s.peer_addr().unwrap(), live);
        assert!(
            expected.contains(&s.peer_addr().unwrap()),
            "the winning socket must be one of the admission-resolved addresses"
        );

        let mut dialed = seen.lock().unwrap().clone();
        let mut want = admitted.clone();
        dialed.sort();
        want.sort();
        assert_eq!(
            dialed, want,
            "the dial set must equal the admission-resolved set"
        );
    }

    // ---- Task 5.2: Happy Eyeballs race shape -----------------------------

    /// Step 2: 8 dials in flight at once ([G-12] maxParallelDials). The
    /// barrier of 8 only releases if all eight are awaited concurrently — a
    /// sequential (or 4-wide) implementation times out here.
    #[tokio::test]
    async fn happy_eyeballs_races_eight_addresses_concurrently() {
        assert_eq!(super::MAX_PARALLEL_DIALS, 8, "[G-12] maxParallelDials");
        let (_l, live) = local_listener().await;
        let mut addrs = vec![live];
        for i in 0..7u8 {
            addrs.push(format!("203.0.113.{}:443", i + 1).parse().unwrap());
        }
        let barrier = Arc::new(tokio::sync::Barrier::new(super::MAX_PARALLEL_DIALS));
        let s = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            super::happy_eyeballs_dial_with(addrs, move |addr| {
                let barrier = Arc::clone(&barrier);
                let fut: std::pin::Pin<Box<dyn Future<Output = io::Result<TcpStream>> + Send>> =
                    Box::pin(async move {
                        barrier.wait().await;
                        if addr == live {
                            TcpStream::connect(live).await
                        } else {
                            Err(io::Error::from(io::ErrorKind::ConnectionRefused))
                        }
                    });
                fut
            }),
        )
        .await
        .expect("8 dials must run concurrently")
        .expect("the live address must win");
        assert_eq!(s.peer_addr().unwrap(), live);
    }

    /// The race is capped at 8 IN FLIGHT — not merely "8 per batch step". Every
    /// dial bumps a high-water mark, yields once so its peers can start, then
    /// fails; a 16-address list must still peak at exactly
    /// [`MAX_PARALLEL_DIALS`]. A wider cap peaks at the batch length, a narrower
    /// one below 8.
    ///
    /// `current_thread` is pinned deliberately (Task 5.2 quality advisory 2):
    /// the exact-equality assert is sound only when `yield_now` hands control
    /// to the other spawned dials before any of them decrements the counter.
    /// On a multi-thread flavor the dials can run on separate workers and
    /// finish before their peers start, giving a lower peak — a flake, not a
    /// regression. Pinning the flavor makes the assumption part of the test.
    #[tokio::test(flavor = "current_thread")]
    async fn happy_eyeballs_caps_concurrency_at_eight() {
        let mut addrs = Vec::new();
        for i in 0..16u8 {
            addrs.push(format!("203.0.113.{}:443", i + 1).parse().unwrap());
        }
        let live = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let out = super::happy_eyeballs_dial_with(addrs, {
            let live = Arc::clone(&live);
            let peak = Arc::clone(&peak);
            move |_addr| {
                let live = Arc::clone(&live);
                let peak = Arc::clone(&peak);
                let fut: std::pin::Pin<Box<dyn Future<Output = io::Result<TcpStream>> + Send>> =
                    Box::pin(async move {
                        let now = live.fetch_add(1, Ordering::SeqCst) + 1;
                        peak.fetch_max(now, Ordering::SeqCst);
                        tokio::task::yield_now().await;
                        live.fetch_sub(1, Ordering::SeqCst);
                        Err(io::Error::from(io::ErrorKind::ConnectionRefused))
                    });
                fut
            }
        })
        .await;
        assert!(out.is_err(), "sixteen dead addresses must all fail");
        assert_eq!(
            peak.load(Ordering::SeqCst),
            super::MAX_PARALLEL_DIALS,
            "the race must peak at MAX_PARALLEL_DIALS in flight"
        );
    }

    /// The interleave CALL SITE (not just the pure function): a resolver
    /// answer with every IPv4 first must still put 4+4 into the first batch.
    /// The first eight addresses to reach the barrier ARE that batch — batch
    /// two is not even spawned until batch one has finished.
    #[tokio::test]
    async fn happy_eyeballs_first_batch_interleaves_both_families() {
        let mut addrs: Vec<SocketAddr> = (1..=8)
            .map(|i| format!("203.0.113.{i}:443").parse().unwrap())
            .collect();
        addrs.extend((1..=8).map(|i| {
            format!("[2001:db8::{i}]:443")
                .parse::<SocketAddr>()
                .unwrap()
        }));
        let seen = Arc::new(StdMutex::new(Vec::new()));
        let seen_seam = Arc::clone(&seen);
        let barrier = Arc::new(tokio::sync::Barrier::new(super::MAX_PARALLEL_DIALS));
        // Timeout-bounded (Task 5.2 quality advisory 1): if the first batch
        // ever stopped holding eight concurrent dials the barrier would never
        // release and this would HANG the suite instead of failing it.
        let _ = tokio::time::timeout(
            Duration::from_secs(2),
            super::happy_eyeballs_dial_with(addrs, move |addr| {
                seen_seam.lock().unwrap().push(addr);
                let barrier = Arc::clone(&barrier);
                let fut: std::pin::Pin<Box<dyn Future<Output = io::Result<TcpStream>> + Send>> =
                    Box::pin(async move {
                        barrier.wait().await;
                        Err(io::Error::from(io::ErrorKind::ConnectionRefused))
                    });
                fut
            }),
        )
        .await
        .expect("the first batch must hold 8 concurrent dials");
        let first_batch: Vec<SocketAddr> = seen
            .lock()
            .unwrap()
            .iter()
            .take(super::MAX_PARALLEL_DIALS)
            .cloned()
            .collect();
        assert_eq!(first_batch.len(), super::MAX_PARALLEL_DIALS);
        assert_eq!(
            first_batch.iter().filter(|a| a.is_ipv6()).count(),
            4,
            "the first batch must be 4 IPv6 + 4 IPv4: {first_batch:?}"
        );
    }

    /// Step 2: the race is capped at 8 in flight — a 9th address is spawned
    /// only after the first batch has finished. With a 16-wide cap the 9th
    /// dial would start alongside the first eight and this goes red.
    #[tokio::test]
    async fn happy_eyeballs_ninth_dial_waits_for_the_first_batch() {
        let (_l, live) = local_listener().await;
        let mut addrs = Vec::new();
        for i in 0..8u8 {
            addrs.push(format!("203.0.113.{}:443", i + 1).parse().unwrap());
        }
        addrs.push(live); // 9th — second batch only
        let order = Arc::new(addrs.clone());
        let log = Arc::new(StdMutex::new(Vec::<(usize, &'static str)>::new()));
        let log_seam = Arc::clone(&log);
        let order_seam = Arc::clone(&order);
        let s = super::happy_eyeballs_dial_with(addrs, move |addr| {
            let idx = order_seam.iter().position(|a| *a == addr).unwrap();
            log_seam.lock().unwrap().push((idx, "start"));
            let log = Arc::clone(&log_seam);
            let fut: std::pin::Pin<Box<dyn Future<Output = io::Result<TcpStream>> + Send>> =
                Box::pin(async move {
                    if addr == live {
                        TcpStream::connect(live).await
                    } else {
                        log.lock().unwrap().push((idx, "done"));
                        Err(io::Error::from(io::ErrorKind::ConnectionRefused))
                    }
                });
            fut
        })
        .await
        .expect("the second batch must dial");
        assert_eq!(s.peer_addr().unwrap(), live);

        let events = log.lock().unwrap().clone();
        let ninth_start = events
            .iter()
            .position(|e| e.0 == 8 && e.1 == "start")
            .expect("the 9th dial must have started");
        let last_first_batch = events
            .iter()
            .rposition(|e| e.0 < 8)
            .expect("the first batch must have run");
        assert!(
            last_first_batch < ninth_start,
            "the 9th dial must not start before the first batch ends: {events:?}"
        );
        assert_eq!(events.iter().filter(|e| e.1 == "start").count(), 9);
    }

    /// Step 2: the losers are CANCELLED, not abandoned. Each loser's dial
    /// future holds a drop probe and never resolves; after the winner returns,
    /// both probes must have been dropped — the production path aborts each
    /// loser task and awaits its handle, so cancellation has completed before
    /// `happy_eyeballs_dial` returns.
    #[tokio::test]
    async fn happy_eyeballs_cancels_the_losing_dials() {
        struct CancelProbe(Arc<AtomicUsize>);
        impl Drop for CancelProbe {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        let (_l, live) = local_listener().await;
        let addrs = vec![
            "203.0.113.1:443".parse::<SocketAddr>().unwrap(),
            live,
            "203.0.113.2:443".parse::<SocketAddr>().unwrap(),
        ];
        let cancelled = Arc::new(AtomicUsize::new(0));
        let started = Arc::new(AtomicUsize::new(0));
        let barrier = Arc::new(tokio::sync::Barrier::new(addrs.len()));
        let outcome = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            super::happy_eyeballs_dial_with(addrs, {
                let cancelled = Arc::clone(&cancelled);
                let started = Arc::clone(&started);
                let barrier = Arc::clone(&barrier);
                move |addr| {
                    started.fetch_add(1, Ordering::SeqCst);
                    let probe = if addr == live {
                        None
                    } else {
                        Some(CancelProbe(Arc::clone(&cancelled)))
                    };
                    let barrier = Arc::clone(&barrier);
                    let fut: std::pin::Pin<Box<dyn Future<Output = io::Result<TcpStream>> + Send>> =
                        Box::pin(async move {
                            let _probe = probe;
                            barrier.wait().await;
                            if addr == live {
                                TcpStream::connect(live).await
                            } else {
                                std::future::pending::<io::Result<TcpStream>>().await
                            }
                        });
                    fut
                }
            }),
        )
        .await
        .expect("the race must not hang");
        let s = outcome.expect("the live address must win");
        assert_eq!(s.peer_addr().unwrap(), live);
        assert_eq!(started.load(Ordering::SeqCst), 3, "all three dials start");
        assert_eq!(
            cancelled.load(Ordering::SeqCst),
            2,
            "both losers must be cancelled, not abandoned"
        );
    }

    /// A loser that already CONNECTED is CLOSED, not leaked: the sockets this
    /// race opens must never escape it. Two live local listeners, and a
    /// barrier AFTER the connect, so both dials reach ESTABLISHED before
    /// either can win — the loser in this race is guaranteed to be holding an
    /// open socket. When the race returns, the winner's tunnel still carries
    /// bytes and the loser's peer has seen EOF. Deterministic: no sleeps, and
    /// no assumption about which listener wins.
    #[tokio::test]
    async fn happy_eyeballs_closes_a_loser_that_already_connected() {
        let (la, a) = local_listener().await;
        let (lb, b) = local_listener().await;
        // Accept up front: each connection is witnessed as ESTABLISHED, so the
        // loser's close is observed on a socket that really exists rather than
        // on a half-open backlog entry.
        let acc_a = tokio::spawn(async move { la.accept().await.map(|(s, _)| s) });
        let acc_b = tokio::spawn(async move { lb.accept().await.map(|(s, _)| s) });

        let barrier = Arc::new(tokio::sync::Barrier::new(2));
        let mut s = tokio::time::timeout(
            Duration::from_secs(2),
            super::happy_eyeballs_dial_with(vec![a, b], move |addr| {
                let barrier = Arc::clone(&barrier);
                let fut: std::pin::Pin<Box<dyn Future<Output = io::Result<TcpStream>> + Send>> =
                    Box::pin(async move {
                        let s = TcpStream::connect(addr).await?;
                        // Both dials have CONNECTED before either reports.
                        barrier.wait().await;
                        if addr == a {
                            Ok(s)
                        } else {
                            // The loser holds its ESTABLISHED socket and never
                            // reports: only cancellation (abort AND await, so
                            // the drop has happened by the time the race
                            // returns) can close it.
                            std::future::pending::<()>().await;
                            unreachable!("the pending dial cannot complete")
                        }
                    });
                fut
            }),
        )
        .await
        .expect("the race must not hang")
        .expect("one of two live listeners must win");

        let winner = s.peer_addr().unwrap();
        assert!(
            winner == a || winner == b,
            "the winner must be one of the dialed addresses"
        );
        let (mut winner_peer, mut loser_peer) = if winner == a {
            (acc_a.await.unwrap().unwrap(), acc_b.await.unwrap().unwrap())
        } else {
            (acc_b.await.unwrap().unwrap(), acc_a.await.unwrap().unwrap())
        };

        // The winner's tunnel is alive in both directions ...
        winner_peer.write_all(b"ping").await.unwrap();
        let mut echo = [0u8; 4];
        s.read_exact(&mut echo).await.unwrap();
        assert_eq!(&echo, b"ping");

        // ... while the loser's socket is closed. `read` returning 0 is EOF,
        // i.e. the client side dropped its TcpStream and sent a FIN. Had the
        // loser been abandoned instead of aborted-and-awaited, its socket
        // would still be open and this read would block until the timeout.
        let mut buf = [0u8; 8];
        let n = tokio::time::timeout(Duration::from_secs(2), loser_peer.read(&mut buf))
            .await
            .expect("a connected loser must be closed when the race returns")
            .expect("the close must be graceful, not a reset");
        assert_eq!(n, 0, "the loser's peer must see EOF");
    }

    /// Step 2 as specced: 8 concurrent is 4 IPv6 + 4 IPv4, so the first batch
    /// must alternate families instead of draining the resolver's IPv4 block
    /// before any IPv6 dial starts (RFC 8305 §4 ordering, IPv6 first).
    #[test]
    fn interleave_families_alternates_v6_and_v4() {
        let v6: Vec<SocketAddr> = (1..=4)
            .map(|i| format!("[2001:db8::{i}]:443").parse().unwrap())
            .collect();
        let v4: Vec<SocketAddr> = (1..=4)
            .map(|i| format!("203.0.113.{i}:443").parse().unwrap())
            .collect();
        let mut input = v4.clone();
        input.extend(v6.clone()); // resolver order: every IPv4 first
        let out = super::interleave_families(input);
        assert_eq!(
            out,
            vec![v6[0], v4[0], v6[1], v4[1], v6[2], v4[2], v6[3], v4[3]]
        );
        let first_batch = &out[..super::MAX_PARALLEL_DIALS];
        assert_eq!(
            first_batch.iter().filter(|a| a.is_ipv6()).count(),
            4,
            "the first batch must carry 4 IPv6 + 4 IPv4"
        );
    }

    #[test]
    fn interleave_families_keeps_a_single_family_order() {
        let v4: Vec<SocketAddr> = (1..=3)
            .map(|i| format!("203.0.113.{i}:443").parse().unwrap())
            .collect();
        assert_eq!(super::interleave_families(v4.clone()), v4);
        // Unequal counts: alternation first, then the remainder in place.
        let mixed = vec![
            v4[0],
            "[2001:db8::1]:443".parse::<SocketAddr>().unwrap(),
            v4[1],
            v4[2],
        ];
        assert_eq!(
            super::interleave_families(mixed),
            vec![
                "[2001:db8::1]:443".parse::<SocketAddr>().unwrap(),
                v4[0],
                v4[1],
                v4[2]
            ]
        );
    }

    // ---- PromptOutcome → D-5 audit mapping (pure) -------------------------

    #[test]
    fn outcome_audit_allow_once() {
        let a = super::outcome_audit(&PromptOutcome::Decided(PromptResult::Allow {
            persist: false,
            scope: "host".into(),
            suffix: None,
        }));
        assert!(a.allowed);
        assert_eq!(a.source, "prompt");
        assert_eq!(a.scope.as_deref(), Some("once"));
        assert!(!a.wants_persist);
    }

    #[test]
    fn outcome_audit_allow_persist_host() {
        let a = super::outcome_audit(&PromptOutcome::Decided(PromptResult::Allow {
            persist: true,
            scope: "host".into(),
            suffix: None,
        }));
        assert!(a.allowed);
        assert_eq!(a.source, "prompt");
        assert_eq!(a.scope.as_deref(), Some("host"));
        assert!(a.wants_persist);
    }

    #[test]
    fn outcome_audit_deny_persist_suffix() {
        let a = super::outcome_audit(&PromptOutcome::Decided(PromptResult::Deny {
            persist: true,
            scope: "suffix".into(),
            suffix: Some("example.com".into()),
        }));
        assert!(!a.allowed);
        assert_eq!(a.source, "prompt");
        assert_eq!(a.scope.as_deref(), Some("suffix"));
        assert!(a.wants_persist);
    }

    #[test]
    fn outcome_audit_deny_once() {
        let a = super::outcome_audit(&PromptOutcome::Decided(PromptResult::Deny {
            persist: false,
            scope: "host".into(),
            suffix: None,
        }));
        assert!(!a.allowed);
        assert_eq!(a.source, "prompt");
        assert_eq!(a.scope.as_deref(), Some("once"));
        assert!(!a.wants_persist);
    }

    #[test]
    fn outcome_audit_needs_intent() {
        let a = super::outcome_audit(&PromptOutcome::Decided(PromptResult::NeedsIntent));
        assert!(!a.allowed);
        assert_eq!(a.source, "prompt");
        assert_eq!(a.scope, None);
        assert!(!a.wants_persist);
    }

    #[test]
    fn outcome_audit_overloaded() {
        let a = super::outcome_audit(&PromptOutcome::Overloaded {
            cause: OverloadCause::ConsultationsHeld,
        });
        assert!(!a.allowed);
        assert_eq!(a.source, "prompt_overload");
        assert_eq!(a.scope, None);
        assert!(!a.wants_persist);
    }

    #[test]
    fn outcome_audit_unavailable_respects_policy() {
        let deny = super::outcome_audit(&PromptOutcome::Unavailable {
            allowed: false,
            cause: UnavailableCause::BudgetElapsed,
        });
        assert!(!deny.allowed);
        assert_eq!(deny.source, "unavailable");
        assert_eq!(deny.scope, None);

        let allow = super::outcome_audit(&PromptOutcome::Unavailable {
            allowed: true,
            cause: UnavailableCause::BudgetElapsed,
        });
        assert!(allow.allowed);
        assert_eq!(allow.source, "unavailable");
    }

    #[test]
    fn outcome_audit_disabled() {
        let a = super::outcome_audit(&PromptOutcome::Disabled);
        assert!(!a.allowed);
        assert_eq!(a.source, "default");
        assert_eq!(a.scope, None);
        assert!(!a.wants_persist);
    }

    // ---- Task 3.6 listener scaffolding ------------------------------------
    //
    // Every pipeline test below drives the REAL spawned proxy (real
    // listener, real audit writer, real tokio runtime) with a scripted
    // fake dialog injected through `PromptCoordinator::with_dialog`. The
    // real `show_dialog` must never run here: no desktop is needed and
    // the suite must stay fast.

    /// A fake dialog that records every request it receives and replies
    /// with the scripted result.
    fn recording_dialog(
        reply: Result<PromptResult, DialogUnavailable>,
    ) -> (DialogFn, Arc<StdMutex<Vec<DialogRequest>>>) {
        let calls: Arc<StdMutex<Vec<DialogRequest>>> = Arc::new(StdMutex::new(Vec::new()));
        let seen = Arc::clone(&calls);
        let f: DialogFn = Arc::new(move |req: &DialogRequest| {
            seen.lock().unwrap().push(req.clone());
            reply.clone()
        });
        (f, calls)
    }

    fn allow_once() -> PromptResult {
        PromptResult::Allow {
            persist: false,
            scope: "host".into(),
            suffix: None,
        }
    }

    fn allow_host_persist() -> PromptResult {
        PromptResult::Allow {
            persist: true,
            scope: "host".into(),
            suffix: None,
        }
    }

    fn allow_suffix_persist(suffix: &str) -> PromptResult {
        PromptResult::Allow {
            persist: true,
            scope: "suffix".into(),
            suffix: Some(suffix.to_string()),
        }
    }

    fn deny_host_persist() -> PromptResult {
        PromptResult::Deny {
            persist: true,
            scope: "host".into(),
            suffix: None,
        }
    }

    /// Everything one pipeline test needs: the live proxy plus the shared
    /// intent registry / learned store it was constructed with.
    struct T36 {
        /// Keep-alive: dropping the handle stops the proxy. Never read.
        #[allow(dead_code)]
        handle: super::ProxyHandle,
        port: u16,
        sid: String,
        intent: Arc<IntentRegistry>,
        learned: Arc<StdMutex<LearnedStore>>,
        learned_base: PathBuf,
    }

    impl Drop for T36 {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(crate::audit::audit_log_path(&self.sid));
            let _ = std::fs::remove_dir_all(&self.learned_base);
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn t36_setup_cfg(
        label: &str,
        allow: &[&str],
        deny: &[&str],
        dialog: DialogFn,
        enabled: bool,
        timeout: Duration,
        policy: PromptPolicy,
        upstream: Option<Arc<UpstreamDialer>>,
    ) -> T36 {
        t36_setup_token_cfg(
            label,
            allow,
            deny,
            dialog,
            enabled,
            timeout,
            policy,
            upstream,
            unique_test_token(),
        )
    }

    /// The same listener, with a run token of its own: what P1.4's two-run tests
    /// need to show that a listener refuses every credential but its own.
    #[allow(clippy::too_many_arguments)]
    fn t36_setup_token_cfg(
        label: &str,
        allow: &[&str],
        deny: &[&str],
        dialog: DialogFn,
        enabled: bool,
        timeout: Duration,
        policy: PromptPolicy,
        upstream: Option<Arc<UpstreamDialer>>,
        token: RunToken,
    ) -> T36 {
        try_t36_token_cfg(
            label, allow, deny, dialog, enabled, timeout, policy, upstream, token,
        )
        .expect("spawn test proxy")
    }

    /// [`t36_setup_token_cfg`], with the spawn result kept: the one test that
    /// asserts a *refused* spawn (a duplicate live credential, P1.6(b)) needs the
    /// error, and every other caller wants it unwrapped. A failed attempt leaves
    /// nothing behind: the scratch state it created is removed here.
    #[allow(clippy::too_many_arguments)]
    fn try_t36_token_cfg(
        label: &str,
        allow: &[&str],
        deny: &[&str],
        dialog: DialogFn,
        enabled: bool,
        timeout: Duration,
        policy: PromptPolicy,
        upstream: Option<Arc<UpstreamDialer>>,
        token: RunToken,
    ) -> Result<T36> {
        let token_value = token.value().to_string();
        let learned_base = std::env::temp_dir().join(format!(
            "sandbox-t36-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&learned_base).unwrap();
        let learned = Arc::new(StdMutex::new(
            LearnedStore::load_in(&learned_base, Some("t36")).expect("empty learned store"),
        ));
        let intent = Arc::new(IntentRegistry::new(DEFAULT_TTL));
        let gate = super::PromptGate {
            enabled,
            config: PromptConfig {
                timeout,
                on_unavailable: policy,
            },
            coordinator: Arc::new(PromptCoordinator::with_dialog(dialog)),
            intent: Arc::clone(&intent),
            learned: Arc::clone(&learned),
        };
        let sid = temp_sid(label);
        let writer = Arc::new(crate::audit::AuditWriter::open(&sid, false).unwrap());
        // One registry per listener, shared with the handle's ctx: a facade test
        // registers its mount on `t.handle.ctx.facade` after spawn, which is the
        // order the supervisor uses (bind, then plugins).
        let facade = Arc::new(FacadeRegistry::new());
        let handle = match super::spawn(super::ProxyConfig {
            session_id: sid.clone(),
            token,
            allow_domain: allow.iter().map(|s| s.to_string()).collect(),
            deny_domain: deny.iter().map(|s| s.to_string()).collect(),
            upstream,
            writer,
            prompt: gate,
            facade,
        }) {
            Ok(handle) => handle,
            Err(e) => {
                let _ = std::fs::remove_file(crate::audit::audit_log_path(&sid));
                let _ = std::fs::remove_dir_all(&learned_base);
                return Err(e);
            }
        };
        let port = handle.port;
        // The helpers below build requests for *this* listener's credential.
        LISTENER_TOKEN.with(|current| *current.borrow_mut() = token_value);
        Ok(T36 {
            handle,
            port,
            sid,
            intent,
            learned,
            learned_base,
        })
    }

    /// Default-config test proxy: prompting enabled, 60 s timeout,
    /// deny-on-unavailable.
    fn t36_setup(label: &str, allow: &[&str], deny: &[&str], dialog: DialogFn) -> T36 {
        t36_setup_cfg(
            label,
            allow,
            deny,
            dialog,
            true,
            Duration::from_secs(60),
            PromptPolicy::Deny,
            None,
        )
    }

    /// One blocking request/response round-trip against the test proxy.
    /// The handler closes the socket after answering, so `read_to_end`
    /// ends at EOF; the 5 s timeout bounds a hung handler.
    fn exchange(port: u16, request: &str) -> String {
        use std::io::{Read, Write};
        let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).expect("connect test proxy");
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        s.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
        s.write_all(request.as_bytes()).expect("write request");
        let mut out = Vec::new();
        let _ = s.read_to_end(&mut out);
        String::from_utf8_lossy(&out).into_owned()
    }

    fn auth_header() -> String {
        let creds = base64::engine::general_purpose::STANDARD
            .encode(format!("sandbox:{}", listener_token()));
        format!("Proxy-Authorization: Basic {creds}\r\n")
    }

    fn connect_req(target: &str) -> String {
        format!("CONNECT {target} HTTP/1.1\r\n{}\r\n", auth_header())
    }

    fn connect_req_no_auth(target: &str) -> String {
        format!("CONNECT {target} HTTP/1.1\r\n\r\n")
    }

    fn connect_events(sid: &str) -> Vec<serde_json::Value> {
        std::fs::read_to_string(crate::audit::audit_log_path(sid))
            .unwrap_or_default()
            .lines()
            .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
            .filter(|v| v["op"] == "CONNECT")
            .collect()
    }

    fn last_connect_event(sid: &str) -> serde_json::Value {
        let mut evs = connect_events(sid);
        assert!(!evs.is_empty(), "expected a CONNECT audit event");
        evs.pop().unwrap()
    }

    // ---- (1)-(2): loopback refused before anything else --------------------

    #[test]
    fn connect_loopback_refused_without_prompting() {
        let (dialog, calls) = recording_dialog(Ok(deny_once_result()));
        let t = t36_setup("loopback-ip", &[], &[], dialog);
        let resp = exchange(t.port, &connect_req("127.0.0.1:5432"));
        assert!(resp.starts_with("HTTP/1.1 403"), "got: {resp}");
        assert!(resp.contains("X-Sandbox: denied"), "got: {resp}");
        assert!(
            calls.lock().unwrap().is_empty(),
            "loopback must never prompt"
        );
        let ev = last_connect_event(&t.sid);
        assert_eq!(ev["disposition"], "deny");
        assert_eq!(ev["source"], "hard-deny");
        assert_eq!(ev["reason"], "loopback_refused");
    }

    #[test]
    fn connect_localhost_name_refused() {
        let (dialog, calls) = recording_dialog(Ok(deny_once_result()));
        let t = t36_setup("loopback-name", &[], &[], dialog);
        let resp = exchange(t.port, &connect_req("localhost:8080"));
        assert!(resp.starts_with("HTTP/1.1 403"), "got: {resp}");
        assert!(calls.lock().unwrap().is_empty());
        let ev = last_connect_event(&t.sid);
        assert_eq!(ev["source"], "hard-deny");
        assert_eq!(ev["reason"], "loopback_refused");
    }

    #[test]
    fn loopback_refused_even_when_allowlisted() {
        // [G-44] the loopback refusal is a pre-stage of the hard-deny: an
        // allow_domain entry for `localhost` must not reopen a tunnel to host
        // services. Pins the loopback stage against the allow-list stage.
        let (dialog, calls) = recording_dialog(Ok(allow_once()));
        let t = t36_setup("loopback-allow", &["localhost", "127.0.0.1"], &[], dialog);
        let resp = exchange(t.port, &connect_req("localhost:8080"));
        assert!(resp.starts_with("HTTP/1.1 403"), "got: {resp}");
        assert!(resp.contains("X-Sandbox: denied"), "got: {resp}");
        assert!(calls.lock().unwrap().is_empty());
        let ev = last_connect_event(&t.sid);
        assert_eq!(ev["source"], "hard-deny");
        assert_eq!(ev["reason"], "loopback_refused");
    }

    // ---- (3): hard-deny beats blocklist, allowlist, learned and prompt -----

    #[test]
    fn hard_deny_beats_blocklist_and_prompt() {
        // The host is ALSO on the deny_domain blocklist — hard-deny must
        // still win, because the audit reason distinguishes them.
        let (dialog, calls) = recording_dialog(Ok(deny_once_result()));
        let t = t36_setup("hard-deny-dns", &[], &["metadata.google.internal"], dialog);
        let resp = exchange(t.port, &connect_req("metadata.google.internal:80"));
        assert!(resp.starts_with("HTTP/1.1 403"), "got: {resp}");
        assert!(resp.contains("X-Sandbox: denied"), "got: {resp}");
        assert!(calls.lock().unwrap().is_empty());
        let ev = last_connect_event(&t.sid);
        assert_eq!(ev["source"], "hard-deny");
        assert_eq!(ev["reason"], "denied_dns");
    }

    #[test]
    fn hard_deny_ip_literal_refused() {
        let (dialog, calls) = recording_dialog(Ok(deny_once_result()));
        let t = t36_setup("hard-deny-ip", &[], &[], dialog);
        let resp = exchange(t.port, &connect_req("169.254.169.253:80"));
        assert!(resp.starts_with("HTTP/1.1 403"), "got: {resp}");
        assert!(calls.lock().unwrap().is_empty());
        let ev = last_connect_event(&t.sid);
        assert_eq!(ev["source"], "hard-deny");
        assert_eq!(ev["reason"], "denied_cidr");
    }

    #[test]
    fn hard_deny_bracketed_ipv6_literal_refused() {
        let (dialog, calls) = recording_dialog(Ok(deny_once_result()));
        let t = t36_setup("hard-deny-v6", &[], &[], dialog);
        let resp = exchange(t.port, &connect_req("[fe80::1]:443"));
        assert!(resp.starts_with("HTTP/1.1 403"), "got: {resp}");
        assert!(calls.lock().unwrap().is_empty());
        let ev = last_connect_event(&t.sid);
        assert_eq!(ev["source"], "hard-deny");
        assert_eq!(ev["reason"], "denied_cidr");
    }

    #[test]
    fn hard_deny_beats_learned_deny() {
        let (dialog, _calls) = recording_dialog(Ok(deny_once_result()));
        let t = t36_setup("hard-deny-learned", &[], &[], dialog);
        t.learned
            .lock()
            .unwrap()
            .record("metadata.google.internal", "host", false)
            .unwrap();
        let resp = exchange(t.port, &connect_req("metadata.google.internal:80"));
        assert!(resp.starts_with("HTTP/1.1 403"), "got: {resp}");
        let ev = last_connect_event(&t.sid);
        assert_eq!(ev["source"], "hard-deny", "hard-deny must outrank learned");
        assert_eq!(ev["persisted"], false);
    }

    #[test]
    fn hard_deny_beats_allowlist() {
        // [G-18, G-33] step 1 outranks step 4: an operator who allow-lists a
        // metadata name still cannot reach it, and the audit source names the
        // stage that answered (`allowlist` here would be the bug).
        let (dialog, calls) = recording_dialog(Ok(deny_once_result()));
        let t = t36_setup(
            "hard-deny-allow",
            &["metadata.google.internal", "*.google.internal"],
            &[],
            dialog,
        );
        let resp = exchange(t.port, &connect_req("metadata.google.internal:80"));
        assert!(resp.starts_with("HTTP/1.1 403"), "got: {resp}");
        assert!(resp.contains("X-Sandbox: denied"), "got: {resp}");
        assert!(
            calls.lock().unwrap().is_empty(),
            "hard-deny must not prompt"
        );
        let ev = last_connect_event(&t.sid);
        assert_eq!(ev["source"], "hard-deny");
        assert_eq!(ev["reason"], "denied_dns");
    }

    // ---- (4): learned-deny beats blocklist and allowlist -------------------

    #[test]
    fn learned_deny_beats_blocklist_and_allowlist() {
        let (dialog, calls) = recording_dialog(Ok(allow_once()));
        let t = t36_setup(
            "learned-deny",
            &["*.example.com"],
            &["*.example.com"],
            dialog,
        );
        t.learned
            .lock()
            .unwrap()
            .record("evil.example.com", "host", false)
            .unwrap();
        let resp = exchange(t.port, &connect_req("evil.example.com:443"));
        assert!(resp.starts_with("HTTP/1.1 403"), "got: {resp}");
        assert!(
            calls.lock().unwrap().is_empty(),
            "learned deny must not prompt"
        );
        let ev = last_connect_event(&t.sid);
        assert_eq!(ev["source"], "learned");
        assert_eq!(ev["scope"], "host");
        assert_eq!(ev["persisted"], true);
    }

    // ---- (5): deny_domain blocklist beats allow_domain ---------------------

    #[test]
    fn blocklist_beats_allowlist() {
        let (dialog, _calls) = recording_dialog(Ok(allow_once()));
        let t = t36_setup(
            "blocklist",
            &["evil.example.com"],
            &["*.example.com"],
            dialog,
        );
        let resp = exchange(t.port, &connect_req("evil.example.com:443"));
        assert!(resp.starts_with("HTTP/1.1 403"), "got: {resp}");
        let ev = last_connect_event(&t.sid);
        assert_eq!(ev["source"], "blocklist");
        assert_eq!(ev["reason"], "denied_domain");
    }

    #[test]
    fn blocklist_beats_learned_allow() {
        // [G-33] step 3 outranks step 4's learned-allow half: a deny_domain
        // entry added after the user once allowed the host still wins. The
        // mirror of `learned_deny_beats_blocklist_and_allowlist`, which pins
        // the opposite direction (learned deny is step 2).
        let (dialog, calls) = recording_dialog(Ok(allow_once()));
        let t = t36_setup("blocklist-learned-allow", &[], &["*.example.com"], dialog);
        t.learned
            .lock()
            .unwrap()
            .record("evil.example.com", "host", true)
            .unwrap();
        let resp = exchange(t.port, &connect_req("evil.example.com:443"));
        assert!(resp.starts_with("HTTP/1.1 403"), "got: {resp}");
        assert!(
            calls.lock().unwrap().is_empty(),
            "blocklist must not prompt"
        );
        let ev = last_connect_event(&t.sid);
        assert_eq!(ev["source"], "blocklist");
        assert_eq!(ev["reason"], "denied_domain");
    }

    // ---- (6): allow_domain / learned-allow admit without prompting --------

    #[test]
    fn allowlist_allows_without_prompt() {
        let (dialog, calls) = recording_dialog(Ok(deny_once_result()));
        let t = t36_setup("allowlist", &["nx-allowlist.invalid"], &[], dialog);
        let resp = exchange(t.port, &connect_req("nx-allowlist.invalid:443"));
        assert!(
            resp.starts_with("HTTP/1.1 403") || resp.starts_with("HTTP/1.1 502"),
            "got: {resp}"
        );
        assert!(
            calls.lock().unwrap().is_empty(),
            "allow-listed host must not prompt"
        );
        let ev = last_connect_event(&t.sid);
        let src = ev["source"].as_str().unwrap();
        assert!(
            src == "allowlist" || src == "dns",
            "allow-listed host may only fail at DNS, got {src}"
        );
    }

    #[test]
    fn learned_allow_allows_without_prompt() {
        let (dialog, calls) = recording_dialog(Ok(deny_once_result()));
        let t = t36_setup("learned-allow", &[], &[], dialog);
        t.learned
            .lock()
            .unwrap()
            .record("nx-learned-allow.invalid", "host", true)
            .unwrap();
        let resp = exchange(t.port, &connect_req("nx-learned-allow.invalid:443"));
        assert!(
            resp.starts_with("HTTP/1.1 403") || resp.starts_with("HTTP/1.1 502"),
            "got: {resp}"
        );
        assert!(calls.lock().unwrap().is_empty());
        let ev = last_connect_event(&t.sid);
        let src = ev["source"].as_str().unwrap();
        assert!(
            src == "learned" || src == "dns",
            "learned-allowed host may only fail at DNS, got {src}"
        );
    }

    #[test]
    fn learned_allow_admits_in_allowlist_mode() {
        // [G-33] step 4 is "allow_domain OR learned allow", so a learned allow
        // must still admit when the allow-list is non-empty and lacks the
        // host — i.e. ahead of the step-5 allowlist-mode default, which would
        // prompt here. `learned_allow_allows_without_prompt` covers the same
        // stage with an EMPTY allow-list (pure blocklist mode), so it cannot
        // pin this pair.
        let (dialog, calls) = recording_dialog(Ok(deny_once_result()));
        let t = t36_setup("learned-allow-mode", &["api.allowed.invalid"], &[], dialog);
        t.learned
            .lock()
            .unwrap()
            .record("nx-learned-mode.invalid", "host", true)
            .unwrap();
        exchange(t.port, &connect_req("nx-learned-mode.invalid:443"));
        assert!(
            calls.lock().unwrap().is_empty(),
            "learned allow must not prompt"
        );
        let evs = connect_events(&t.sid);
        assert!(
            evs.iter()
                .any(|e| e["source"] == "learned" && e["disposition"] == "allow"),
            "admission leaf must be a learned allow: {evs:?}"
        );
    }

    // ---- (7): prompt outcomes ----------------------------------------------

    #[test]
    fn prompt_deny_once_is_not_persisted() {
        let (dialog, calls) = recording_dialog(Ok(deny_once_result()));
        let t = t36_setup("prompt-deny-once", &[], &[], dialog);
        let resp = exchange(t.port, &connect_req("prompted-deny.invalid:443"));
        assert!(resp.starts_with("HTTP/1.1 403"), "got: {resp}");
        assert_eq!(
            calls.lock().unwrap().len(),
            1,
            "exactly one dialog expected"
        );
        let ev = last_connect_event(&t.sid);
        assert_eq!(ev["disposition"], "deny");
        assert_eq!(ev["source"], "prompt");
        assert_eq!(ev["scope"], "once");
        assert_eq!(ev["persisted"], false);
        assert!(
            t.learned.lock().unwrap().entries().is_empty(),
            "no persistence expected"
        );
    }

    #[test]
    fn prompt_deny_persist_records_learned_deny() {
        let (dialog, _calls) = recording_dialog(Ok(deny_host_persist()));
        let t = t36_setup("prompt-deny-persist", &[], &[], dialog);
        let resp = exchange(t.port, &connect_req("persist-deny.invalid:443"));
        assert!(resp.starts_with("HTTP/1.1 403"), "got: {resp}");
        let ev = last_connect_event(&t.sid);
        assert_eq!(ev["source"], "prompt");
        assert_eq!(ev["scope"], "host");
        assert_eq!(ev["persisted"], true);
        let learned = t.learned.lock().unwrap().lookup("persist-deny.invalid");
        assert_eq!(
            learned,
            Some(crate::net::learned::LearnedDecision {
                allow: false,
                scope: "host".into()
            })
        );
    }

    #[test]
    fn prompt_allow_persist_host_records_learned_allow() {
        let (dialog, calls) = recording_dialog(Ok(allow_host_persist()));
        let t = t36_setup("prompt-allow-host", &[], &[], dialog);
        let resp = exchange(t.port, &connect_req("persist-allow.invalid:443"));
        assert!(
            resp.starts_with("HTTP/1.1 403") || resp.starts_with("HTTP/1.1 502"),
            "admitted request may only fail at DNS/dial, got: {resp}"
        );
        assert_eq!(calls.lock().unwrap().len(), 1);
        let learned = t.learned.lock().unwrap().lookup("persist-allow.invalid");
        assert_eq!(
            learned,
            Some(crate::net::learned::LearnedDecision {
                allow: true,
                scope: "host".into()
            })
        );
        let ev = last_connect_event(&t.sid);
        if ev["disposition"] == "allow" {
            assert_eq!(ev["source"], "prompt");
            assert_eq!(ev["scope"], "host");
            assert_eq!(ev["persisted"], true);
        } else {
            // Hermetic default: NXDOMAIN for .invalid → denied at DNS.
            assert_eq!(ev["source"], "dns");
        }
    }

    #[test]
    fn prompt_allow_persist_suffix_records_suffix_entry() {
        let (dialog, _calls) = recording_dialog(Ok(allow_suffix_persist("persist-suffix.invalid")));
        let t = t36_setup("prompt-allow-suffix", &[], &[], dialog);
        let resp = exchange(t.port, &connect_req("cdn.persist-suffix.invalid:443"));
        assert!(
            resp.starts_with("HTTP/1.1 403") || resp.starts_with("HTTP/1.1 502"),
            "got: {resp}"
        );
        // The suffix entry must cover both the apex and subdomains.
        let learned = t
            .learned
            .lock()
            .unwrap()
            .lookup("api.persist-suffix.invalid");
        assert_eq!(
            learned,
            Some(crate::net::learned::LearnedDecision {
                allow: true,
                scope: "suffix".into()
            })
        );
        assert!(
            t.learned
                .lock()
                .unwrap()
                .lookup("persist-suffix.invalid")
                .is_some()
        );
    }

    #[test]
    fn prompt_needs_intent_sets_flag_and_hint_header() {
        let (dialog, _calls) = recording_dialog(Ok(PromptResult::NeedsIntent));
        let t = t36_setup("prompt-explain", &[], &[], dialog);
        let resp = exchange(t.port, &connect_req("explain.invalid:443"));
        assert!(resp.starts_with("HTTP/1.1 403"), "got: {resp}");
        assert!(
            resp.contains("X-Sandbox-Intent-Hint: explain-more"),
            "deny for NeedsIntent must carry the intent hint, got: {resp}"
        );
        // The one-shot flag must now be set for the agent to consume.
        let flagged = block_on(t.intent.consume_explain_more("explain.invalid"));
        assert!(flagged, "explain-more flag expected after NeedsIntent");
        let ev = last_connect_event(&t.sid);
        assert_eq!(ev["disposition"], "deny");
        assert_eq!(ev["source"], "prompt");
    }

    #[test]
    fn prompt_unavailable_deny_maps_to_unavailable_source() {
        let (dialog, _calls) = recording_dialog(Err(DialogUnavailable));
        let t = t36_setup("prompt-unavail", &[], &[], dialog);
        let resp = exchange(t.port, &connect_req("unavailable.invalid:443"));
        assert!(resp.starts_with("HTTP/1.1 403"), "got: {resp}");
        assert!(resp.contains("X-Sandbox: denied"), "got: {resp}");
        let ev = last_connect_event(&t.sid);
        assert_eq!(ev["source"], "unavailable");
        assert_eq!(ev["persisted"], false);
    }

    #[test]
    fn prompt_zero_timeout_is_disabled_and_never_shows_a_dialog() {
        let (dialog, calls) = recording_dialog(Ok(allow_host_persist()));
        let t = t36_setup_cfg(
            "prompt-disabled",
            &[],
            &[],
            dialog,
            true, // prompt_enabled, but timeout 0 → coordinator returns Disabled
            Duration::ZERO,
            PromptPolicy::Deny,
            None,
        );
        let resp = exchange(t.port, &connect_req("zero-timeout.invalid:443"));
        assert!(resp.starts_with("HTTP/1.1 403"), "got: {resp}");
        assert!(
            calls.lock().unwrap().is_empty(),
            "zero timeout must never show a dialog"
        );
        let ev = last_connect_event(&t.sid);
        assert_eq!(ev["source"], "default");
    }

    // ---- P2.1: the prompt budget on BOTH legs (D3 addendum) ----------------

    /// A dialog that is still up when the budget elapses: the coordinator
    /// abandons it after `budget` and its late answer is discarded ([G-4]).
    fn slow_dialog(up: Duration) -> DialogFn {
        Arc::new(move |_req: &DialogRequest| {
            std::thread::sleep(up);
            Err(DialogUnavailable)
        })
    }

    /// A dialog that never returns on its own: it blocks until the test drops the
    /// gate, so the coordinator's orphans are *still up* while the test asserts —
    /// the headless case, where nobody can answer the dialog at all.
    fn gated_dialog() -> (DialogFn, std::sync::mpsc::Sender<()>) {
        let (gate, wait) = std::sync::mpsc::channel::<()>();
        let wait = Arc::new(StdMutex::new(wait));
        let dialog: DialogFn = Arc::new(move |_req: &DialogRequest| {
            let rx = wait.lock().unwrap_or_else(|poison| poison.into_inner());
            let _ = rx.recv();
            Err(DialogUnavailable)
        });
        (dialog, gate)
    }

    /// D3 addendum, first half: a **plain-HTTP absolute-form** request to a host
    /// that reaches the prompt policy is bounded by the prompt budget exactly like
    /// CONNECT, gets the deny on the wire, leaves exactly one leaf, and never
    /// dials an origin.
    ///
    /// Before P2.1 the same request in a headless run stalled for the whole
    /// budget with no answer available (measured as curl exit 28 at `-m 15`) and
    /// the audit said "timeout or no dialog backend" — one string for two
    /// different failures, and nothing that named the budget as the cause.
    #[test]
    fn forward_prompt_timeout_is_bounded_by_the_budget_and_never_dials() {
        let fake = FakeUpstream::start(200);
        let t = t36_setup_cfg(
            "fwd-prompt-budget",
            &[],
            &[],
            slow_dialog(Duration::from_millis(800)),
            true,
            Duration::from_millis(200),
            PromptPolicy::Deny,
            Some(dialer(&fake.url(), &[])),
        );
        let counters = t.handle.counters();
        let epoch = counters.begin_epoch().expect("the launch's window");

        let started = std::time::Instant::now();
        let resp = exchange(t.port, &get_req("http://unlisted-forward.invalid/x"));
        let elapsed = started.elapsed();

        // The wire answer: the deny, promptly (bounded by the budget, not by the
        // dialog's own 800 ms), and it names the spent budget as the reason.
        assert!(resp.starts_with("HTTP/1.1 403"), "got: {resp}");
        assert!(resp.contains("X-Sandbox: denied"), "got: {resp}");
        assert!(
            resp.contains(PROMPT_TIMEOUT_REASON),
            "the deny must name the spent budget ({PROMPT_TIMEOUT_REASON}), got: {resp}"
        );
        assert!(
            elapsed < Duration::from_millis(700),
            "the forward leg must be bounded by the prompt budget, not by the dialog: {elapsed:?}"
        );

        // Exactly one leaf for the one timed-out request, with the reason a
        // CONNECT timeout produces.
        let leaves = connect_events(&t.sid);
        assert_eq!(
            leaves.len(),
            1,
            "one leaf per timed-out request: {leaves:?}"
        );
        assert_eq!(leaves[0]["host"], "unlisted-forward.invalid");
        assert_eq!(leaves[0]["port"], 80);
        assert_eq!(leaves[0]["disposition"], "deny");
        assert_eq!(leaves[0]["reason"], PROMPT_TIMEOUT_REASON);
        assert_eq!(leaves[0]["source"], "unavailable");

        // Counters: it WAS a consultation (accepted), and nothing was
        // tunnelled — the deny happened before any dial.
        assert_eq!(
            counters.counters(epoch),
            Some(LaunchProofCounters {
                consultations: 1,
                upstream_established: 0,
                probes: 0,
                unauthenticated: 0,
            }),
            "a denied forward is an accepted consultation with no upstream"
        );
        // The observable proof that no origin was involved: the chaining dialer
        // is the only outbound hop a forward can take, and it saw nothing.
        assert!(
            fake.heads().is_empty(),
            "a denied forward must not reach an origin: {:?}",
            fake.heads()
        );
        assert!(counters.close_epoch(epoch));
    }

    /// D3 addendum, second half: both legs produce the **same leaf shape** for the
    /// same timeout outcome — same keys, same `reason`, same `source` — and one
    /// leaf each. A forward deny must not be a second-class leaf: a consumer
    /// filtering on `reason` cannot be asked to know which leg produced it.
    #[test]
    fn connect_and_forward_prompt_timeouts_emit_the_same_deny_leaf() {
        let t = t36_setup_cfg(
            "prompt-parity",
            &[],
            &[],
            slow_dialog(Duration::from_millis(700)),
            true,
            Duration::from_millis(150),
            PromptPolicy::Deny,
            None,
        );

        let connect = exchange(t.port, &connect_req("parity-connect.invalid:443"));
        let forward = exchange(t.port, &get_req("http://parity-forward.invalid/x"));
        assert!(connect.starts_with("HTTP/1.1 403"), "got: {connect}");
        assert!(forward.starts_with("HTTP/1.1 403"), "got: {forward}");
        assert!(connect.contains(PROMPT_TIMEOUT_REASON), "got: {connect}");
        assert!(forward.contains(PROMPT_TIMEOUT_REASON), "got: {forward}");

        let leaves = connect_events(&t.sid);
        assert_eq!(
            leaves.len(),
            2,
            "one leaf per timed-out request, no doubles: {leaves:?}"
        );
        let keys = |v: &serde_json::Value| {
            let mut k: Vec<String> = v
                .as_object()
                .expect("leaf is an object")
                .keys()
                .cloned()
                .collect();
            k.sort();
            k
        };
        assert_eq!(
            keys(&leaves[0]),
            keys(&leaves[1]),
            "both legs must write the same leaf shape"
        );
        for field in [
            "reason",
            "source",
            "disposition",
            "scope",
            "persisted",
            "op",
        ] {
            assert_eq!(
                leaves[0][field], leaves[1][field],
                "`{field}` must be identical on both legs"
            );
        }
        assert_eq!(leaves[0]["reason"], PROMPT_TIMEOUT_REASON);
        // Not vacuous: the two leaves really are different requests.
        assert_ne!(leaves[0]["host"], leaves[1]["host"]);
        assert_eq!(leaves[0]["port"], 443);
        assert_eq!(leaves[1]["port"], 80);
    }

    /// The measurement the session budget is attributed with (P2.1): the listener
    /// times its own prompt consultations, so a session killed at its deadline can
    /// say *which* term spent the time. The control is the important half — a
    /// decision that never consulted a dialog must add nothing, or every session
    /// would look prompt-bound.
    #[test]
    fn prompt_consultation_time_is_measured_and_a_static_decision_adds_none() {
        let t = t36_setup(
            "prompt-clock",
            &["pre-approved.invalid"],
            &[],
            slow_dialog(Duration::from_millis(120)),
        );
        let counters = t.handle.counters();
        assert_eq!(
            counters.prompt_wait(),
            Duration::ZERO,
            "a fresh listener has spent no prompt time"
        );

        let resp = exchange(t.port, &connect_req("measured.invalid:443"));
        assert!(resp.starts_with("HTTP/1.1 403"), "got: {resp}");
        let waited = counters.prompt_wait();
        assert!(
            waited >= Duration::from_millis(100),
            "a dialog that took 120 ms must be measured, got {waited:?}"
        );
        assert!(waited < Duration::from_secs(5), "got {waited:?}");

        // A static answer (allow-list) consults no dialog: the measure must not move.
        // (An allow-listed host is admitted and then fails at the dial — there is no
        // such name on this network — but it is a `dns` decision, not a prompt.)
        let resp = exchange(t.port, &get_req("http://pre-approved.invalid/x"));
        assert!(resp.starts_with("HTTP/1.1 403"), "got: {resp}");
        assert!(
            resp.contains("dns policy"),
            "an allow-listed forward must be answered by the static layer: {resp}"
        );
        assert_eq!(
            counters.prompt_wait(),
            waited,
            "a decision that never prompted must add no prompt time"
        );
    }

    /// The resource-exhaustion half (P2.1) **and** the fast-fail that now
    /// supersedes it (item 3): a timed-out consultation must not keep its
    /// coordinator slot — eight of them used to consume all
    /// `MAX_CONCURRENT_PROMPTS` permits for the life of the process, so the ninth
    /// request was answered `prompt_overload` without its budget ever being
    /// consulted — and after `NO_BACKEND_STICKY_AFTER` of them the session stops
    /// paying the budget at all.
    ///
    /// Round 2, item 8: the skipped requests are answered on the cause that ARMED
    /// the latch, not on the nearest-looking one. These dialogs were shown and
    /// nobody answered them, so the reason is `prompt_suppressed_after_budget` —
    /// `no_dialog_backend` would tell the operator to run interactively when the
    /// interactive path demonstrably worked.
    ///
    /// Nine sequential requests, each with its dialog still up when the budget
    /// elapses (the routine headless state). The first two are denied on budget,
    /// the rest are denied immediately on `no_dialog_backend`, and *none* of them
    /// is ever an overload denial: the path neither wedges nor keeps stalling.
    #[test]
    fn nine_unanswered_prompts_never_wedge_into_overload_and_stop_paying_the_budget() {
        let budget = Duration::from_millis(80);
        let (dialog, gate) = gated_dialog();
        let t = t36_setup_cfg(
            "prompt-slots",
            &[],
            &[],
            dialog,
            true,
            budget,
            PromptPolicy::Deny,
            None,
        );

        let mut elapsed = Vec::new();
        for i in 0..=crate::net::prompt::MAX_CONCURRENT_PROMPTS {
            let host = format!("slot-{i}.invalid");
            let started = std::time::Instant::now();
            let resp = exchange(t.port, &get_req(&format!("http://{host}/x")));
            elapsed.push(started.elapsed());
            assert!(resp.starts_with("HTTP/1.1 403"), "host {i}: got {resp}");
            assert!(
                !resp.contains(PROMPT_OVERLOAD_REASON)
                    && !resp.contains(PROMPT_ABANDONED_CAPACITY_REASON),
                "host {i} must not be refused for capacity, no dialog is at fault: {resp}"
            );
            let ev = last_connect_event(&t.sid);
            assert_eq!(
                ev["source"], "unavailable",
                "host {i} must reach the prompt layer, got {ev}"
            );
            let expected = if i < crate::net::prompt::NO_BACKEND_STICKY_AFTER {
                PROMPT_TIMEOUT_REASON
            } else {
                PROMPT_SUPPRESSED_REASON
            };
            assert_eq!(
                ev["reason"],
                expected,
                "host {i} must be denied on {}, got {ev}",
                if i < crate::net::prompt::NO_BACKEND_STICKY_AFTER {
                    "the budget"
                } else {
                    "the budget that armed the latch"
                }
            );
            assert_eq!(ev["host"], host);
        }
        assert_eq!(
            connect_events(&t.sid).len(),
            crate::net::prompt::MAX_CONCURRENT_PROMPTS + 1,
            "one leaf per request"
        );
        // The measured cost: the first `NO_BACKEND_STICKY_AFTER` pay the budget,
        // the rest do not.
        for (i, e) in elapsed.iter().enumerate() {
            if i < crate::net::prompt::NO_BACKEND_STICKY_AFTER {
                assert!(
                    *e >= budget / 2,
                    "request {i} must wait for its budget: {e:?}"
                );
            } else {
                assert!(
                    *e < budget / 2,
                    "request {i} must be denied without waiting for the budget: {e:?}"
                );
            }
        }
        println!("EVIDENCE nine-headless budget={budget:?} elapsed={elapsed:?}");
        // Release the orphans so no blocking thread outlives the test.
        drop(gate);
    }

    /// A dialog that takes `up` and then answers: the ordinary interactive case,
    /// where the consultation's cost is the user's own thinking time.
    fn slow_deciding_dialog(up: Duration) -> (DialogFn, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&calls);
        let dialog: DialogFn = Arc::new(move |_req: &DialogRequest| {
            counter.fetch_add(1, Ordering::SeqCst);
            std::thread::sleep(up);
            Ok(deny_once_result())
        });
        (dialog, calls)
    }

    /// **Item 1, sequential half: the counter is a per-listener total, so a session's
    /// own prompt time is the DELTA across it.** Two consultations on one listener
    /// must each be attributed their own wait; a session that inherited the total
    /// would report twice its own budget (and, in the supervisor's arithmetic, claim
    /// a prompt overrun that never happened).
    #[test]
    fn two_sequential_consultations_are_attributed_their_own_prompt_time() {
        let (dialog, calls) = slow_deciding_dialog(Duration::from_millis(150));
        let t = t36_setup("prompt-clock-sequential", &[], &[], dialog);
        let counters = t.handle.counters();
        assert_eq!(counters.prompt_wait(), Duration::ZERO);

        let baseline = counters.prompt_wait();
        let first = exchange(t.port, &connect_req("sequential-a.invalid:443"));
        assert!(first.starts_with("HTTP/1.1 403"), "got: {first}");
        let after_first = counters.prompt_wait();
        let first_delta = after_first.saturating_sub(baseline);

        let second = exchange(t.port, &connect_req("sequential-b.invalid:443"));
        assert!(second.starts_with("HTTP/1.1 403"), "got: {second}");
        let after_second = counters.prompt_wait();
        let second_delta = after_second.saturating_sub(after_first);

        assert_eq!(calls.load(Ordering::SeqCst), 2, "two hosts, two dialogs");
        for (label, delta) in [("first", first_delta), ("second", second_delta)] {
            assert!(
                delta >= Duration::from_millis(120),
                "the {label} consultation's own wait must be measured, got {delta:?}"
            );
            assert!(
                delta < Duration::from_millis(700),
                "the {label} consultation must not inherit the listener's total: {label} \
                 delta {delta:?} of a total {after_second:?}"
            );
        }
        println!(
            "EVIDENCE sequential-prompt-time first={first_delta:?} second={second_delta:?} \
             total={after_second:?}"
        );
    }

    /// **Round 2, item 1: a coalesced follower set is credited ONE dialog.**
    ///
    /// `note_prompt_wait` ran per REQUEST, so K followers of one dialog each added
    /// its wall clock: six followers of one 150 ms dialog measured 5.90x the
    /// session, and with shipped defaults four concurrent requests to one unlisted
    /// host credited 240 s for 60 s of blocking — which labelled a workload that
    /// genuinely overran `prompt_budget_exhausted`. The coordinator credits the
    /// consultation's LEADER only, so the aggregate is the time this listener spent
    /// BLOCKED ON DIALOGS, not a share of the wall clock multiplied by whoever was
    /// parked behind one.
    #[test]
    fn a_coalesced_follower_set_is_credited_its_one_dialog() {
        // FOUR is the review's own scenario (four concurrent requests to one unlisted
        // host credited 240 s for 60 s of blocking with shipped defaults); six is the
        // round-1 measurement's worst case (5.90x). Each count gets its own listener,
        // because the counter it reads is cumulative.
        for followers in [4usize, 6] {
            let (dialog, calls) = slow_deciding_dialog(Duration::from_millis(150));
            let t = t36_setup(
                &format!("prompt-clock-coalesced-{followers}"),
                &[],
                &[],
                dialog,
            );
            let counters = t.handle.counters();

            // One host, K concurrent requests: one dialog, one wait on it.
            let request = connect_req("coalesced-one-host.invalid:443");
            let started = std::time::Instant::now();
            let leaders: Vec<_> = (0..followers)
                .map(|_| {
                    let req = request.clone();
                    let port = t.port;
                    std::thread::spawn(move || exchange(port, &req))
                })
                .collect();
            for l in leaders {
                let resp = l.join().expect("exchange thread");
                assert!(resp.starts_with("HTTP/1.1 403"), "got: {resp}");
            }
            let wall = started.elapsed();
            let aggregate = counters.prompt_wait();

            assert_eq!(calls.load(Ordering::SeqCst), 1, "one host means one dialog");
            assert!(
                aggregate >= Duration::from_millis(120),
                "the one dialog that ran must be credited its own wall clock, got {aggregate:?}"
            );
            assert!(
                aggregate <= wall * 2,
                "{followers} followers of ONE dialog must not multiply it: aggregate \
                 {aggregate:?} against a wall clock of {wall:?}"
            );
            println!(
                "EVIDENCE coalesced-credit followers={followers} wall={wall:?} \
                 aggregate={aggregate:?} ratio={:.2}",
                aggregate.as_secs_f64() / wall.as_secs_f64()
            );
        }
    }

    /// **Round 2, item 2: the fast-fail latch is LAUNCH-scoped, not listener-scoped.**
    ///
    /// The latch lives on the coordinator, which is per LISTENER and outlives a
    /// launch, and nothing reset it: one launch per process hid that, but the P1.4
    /// epoch machinery exists precisely so a listener can serve sequential launches,
    /// and then launch N's stalled prompts denied every prompt of launch N+1. The
    /// listener now registers `PromptCoordinator::begin_launch` as its launch reset
    /// and `begin_epoch` runs it as the attribution window opens.
    #[test]
    fn a_new_launch_on_the_same_listener_starts_with_an_unarmed_prompt_latch() {
        let budget = Duration::from_millis(80);
        let (dialog, gate) = gated_dialog();
        let t = t36_setup_cfg(
            "prompt-launch-scope",
            &[],
            &[],
            dialog,
            true,
            budget,
            PromptPolicy::Deny,
            None,
        );

        // Launch 1 arms the latch: three unanswered consultations (the dialog stays
        // up, which is the routine headless state).
        for i in 0..crate::net::prompt::NO_BACKEND_STICKY_AFTER {
            let resp = exchange(t.port, &get_req(&format!("http://launch-{i}.invalid/x")));
            assert!(resp.starts_with("HTTP/1.1 403"), "host {i}: got {resp}");
            assert_eq!(
                last_connect_event(&t.sid)["reason"],
                PROMPT_TIMEOUT_REASON,
                "host {i} must still pay its budget before the latch arms"
            );
        }
        let armed_started = std::time::Instant::now();
        let resp = exchange(t.port, &get_req("http://launch-armed.invalid/x"));
        assert!(resp.starts_with("HTTP/1.1 403"), "got {resp}");
        assert_eq!(
            last_connect_event(&t.sid)["reason"],
            PROMPT_SUPPRESSED_REASON,
            "the latch is armed, and by elapsed budgets"
        );
        assert!(
            armed_started.elapsed() < budget / 2,
            "an armed latch answers without paying: {:?}",
            armed_started.elapsed()
        );

        // A SECOND launch on the same listener: the epoch machinery's own case.
        let epoch = t
            .handle
            .counters()
            .begin_epoch()
            .expect("a second launch's window");
        assert!(t.handle.counters().close_epoch(epoch));

        // Launch 2's first unlisted host is consulted again: it pays its own budget
        // instead of inheriting launch 1's verdict.
        let second_started = std::time::Instant::now();
        let resp = exchange(t.port, &get_req("http://launch2.invalid/x"));
        assert!(resp.starts_with("HTTP/1.1 403"), "got {resp}");
        assert_eq!(
            last_connect_event(&t.sid)["reason"],
            PROMPT_TIMEOUT_REASON,
            "launch 2 must consult a dialog: it must not inherit launch 1's latch"
        );
        assert!(
            second_started.elapsed() >= budget / 2,
            "launch 2's consultation pays its own budget: {:?}",
            second_started.elapsed()
        );
        // Release the orphans so no blocking thread outlives the test.
        drop(gate);
    }

    /// A backend that reports "no decision" only after doing work of its own:
    /// the headless shape the D3 addendum measured (a dialog nobody answers, and
    /// a client that pays the budget for it). Every call is counted, because the
    /// count is how the test sees that later consultations stopped calling it.
    fn counting_slow_failing_dialog(up: Duration) -> (DialogFn, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&calls);
        let dialog: DialogFn = Arc::new(move |_req: &DialogRequest| {
            counter.fetch_add(1, Ordering::SeqCst);
            std::thread::sleep(up);
            Err(DialogUnavailable)
        });
        (dialog, calls)
    }

    /// **The D3 addendum's symptom, closed.** A headless session has no dialog to
    /// answer, so before the fast-fail every unlisted host cost the client the
    /// whole prompt budget (measured as `curl -m 15` exit 28). Every consultation up
    /// to `NO_BACKEND_STICKY_AFTER` still pays it — enough evidence that no decision
    /// is obtainable, and three rather than two since round 2 item 5 — and from then on
    /// the deny is immediate, audited with `no_dialog_backend` instead of
    /// `prompt_budget_exhausted` (this latch was armed by a backend that failed, so
    /// that is the arming cause — item 8), one leaf per request, and no further dialog
    /// is spawned.
    #[test]
    fn headless_requests_stop_paying_the_budget_for_an_absent_backend() {
        let budget = Duration::from_millis(400);
        let (dialog, calls) = counting_slow_failing_dialog(Duration::from_millis(200));
        let t = t36_setup_cfg(
            "headless-fast-fail",
            &[],
            &[],
            dialog,
            true,
            budget,
            PromptPolicy::Deny,
            None,
        );

        let mut elapsed = Vec::new();
        for i in 0..5 {
            let host = format!("unlisted-headless-{i}.invalid");
            let started = std::time::Instant::now();
            let resp = exchange(t.port, &connect_req(&format!("{host}:443")));
            elapsed.push(started.elapsed());
            assert!(resp.starts_with("HTTP/1.1 403"), "host {i}: got {resp}");
            assert!(
                resp.contains(NO_DIALOG_BACKEND_REASON),
                "host {i} must name the missing backend, not the budget: {resp}"
            );
            let ev = last_connect_event(&t.sid);
            assert_eq!(ev["host"], host);
            assert_eq!(ev["source"], "unavailable");
            assert_eq!(ev["reason"], NO_DIALOG_BACKEND_REASON);
            assert_eq!(ev["disposition"], "deny");
        }

        // The measured claim: the consultations before the threshold pay the
        // backend's own latency, the rest do not pay anything like it.
        for (i, e) in elapsed
            .iter()
            .enumerate()
            .take(crate::net::prompt::NO_BACKEND_STICKY_AFTER)
        {
            assert!(
                *e >= Duration::from_millis(150),
                "request {i} must wait on the backend: {e:?}"
            );
        }
        for (i, e) in elapsed
            .iter()
            .enumerate()
            .skip(crate::net::prompt::NO_BACKEND_STICKY_AFTER)
        {
            assert!(
                *e < budget / 4,
                "request {i} must be denied well inside the budget ({budget:?}), got {e:?}"
            );
        }
        assert_eq!(
            calls.load(Ordering::SeqCst),
            crate::net::prompt::NO_BACKEND_STICKY_AFTER,
            "a known-absent backend must not be consulted again"
        );
        assert_eq!(
            connect_events(&t.sid).len(),
            5,
            "every request is audited, skipped dialog or not"
        );

        println!(
            "EVIDENCE headless-fast-fail budget={budget:?} elapsed={:?} dialog_calls={}",
            elapsed,
            calls.load(Ordering::SeqCst)
        );
    }

    /// Item 4's reason half: the two capacity pools deny with **different**
    /// reasons, and both are greppable tokens a filter can select on.
    #[test]
    fn the_two_overload_pools_deny_with_different_reasons() {
        let consultations = super::overload_reason(OverloadCause::ConsultationsHeld);
        let abandoned = super::overload_reason(OverloadCause::AbandonedCapacity);
        assert_eq!(consultations, PROMPT_OVERLOAD_REASON);
        assert_eq!(abandoned, PROMPT_ABANDONED_CAPACITY_REASON);
        assert_eq!(abandoned, "prompt_abandoned_capacity");
        assert_ne!(
            consultations, abandoned,
            "a full abandoned pool must not read as a concurrency limit"
        );
        // The three prompt-side reasons are three distinct facts: a spent budget,
        // no backend, and which pool ran out.
        let mut all = vec![PROMPT_TIMEOUT_REASON, NO_DIALOG_BACKEND_REASON, abandoned];
        all.sort_unstable();
        all.dedup();
        assert_eq!(all.len(), 3, "reason tokens must be distinct: {all:?}");
        assert!(
            !all.contains(&consultations),
            "the consultation-cap prose is not one of the tokenised reasons"
        );
    }

    /// A dialog that parks every call until the gate drops, counting them: the
    /// 8-leader state the consultation cap exists for.
    fn counting_gated_dialog() -> (DialogFn, Arc<AtomicUsize>, std::sync::mpsc::Sender<()>) {
        let (gate, wait) = std::sync::mpsc::channel::<()>();
        let wait = Arc::new(StdMutex::new(wait));
        let calls = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&calls);
        let dialog: DialogFn = Arc::new(move |_req: &DialogRequest| {
            counter.fetch_add(1, Ordering::SeqCst);
            let rx = wait.lock().unwrap_or_else(|poison| poison.into_inner());
            let _ = rx.recv();
            Err(DialogUnavailable)
        });
        (dialog, calls, gate)
    }

    /// Arm 1 at the wire: with every consultation slot held, a NEW host is
    /// refused as `prompt_overload` whose reason names the consultation cap —
    /// and, unlike the abandoned arm, nothing about abandoned dialogs.
    #[test]
    fn a_full_consultation_pool_denies_with_its_own_reason() {
        let (dialog, calls, gate) = counting_gated_dialog();
        let t = t36_setup_cfg(
            "overload-consultations",
            &[],
            &[],
            dialog,
            true,
            Duration::from_secs(30),
            PromptPolicy::Deny,
            None,
        );
        let port = t.port;

        // Eight leaders, one per distinct host, all parked inside their dialogs.
        // The request strings are built HERE: this listener's credential lives in
        // a test thread-local, so a spawned thread must be handed a finished
        // request rather than building one without it.
        let requests: Vec<String> = (0..crate::net::prompt::MAX_CONCURRENT_PROMPTS)
            .map(|i| connect_req(&format!("held-{i}.invalid:443")))
            .collect();
        let leaders: Vec<_> = requests
            .into_iter()
            .map(|req| std::thread::spawn(move || exchange(port, &req)))
            .collect();
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while calls.load(Ordering::SeqCst) < crate::net::prompt::MAX_CONCURRENT_PROMPTS {
            assert!(
                std::time::Instant::now() < deadline,
                "the eight leaders must reach their dialogs, saw {}",
                calls.load(Ordering::SeqCst)
            );
            std::thread::sleep(Duration::from_millis(2));
        }

        let ninth = exchange(port, &connect_req("one-too-many.invalid:443"));
        assert!(ninth.starts_with("HTTP/1.1 403"), "got: {ninth}");
        assert!(
            ninth.contains(PROMPT_OVERLOAD_REASON),
            "the deny must name the consultation cap: {ninth}"
        );
        assert!(
            !ninth.contains(PROMPT_ABANDONED_CAPACITY_REASON),
            "no dialog was abandoned here: {ninth}"
        );
        let ev = last_connect_event(&t.sid);
        assert_eq!(ev["host"], "one-too-many.invalid");
        assert_eq!(ev["source"], "prompt_overload");
        assert_eq!(ev["reason"], PROMPT_OVERLOAD_REASON);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            crate::net::prompt::MAX_CONCURRENT_PROMPTS,
            "the refused consultation must not have shown a dialog"
        );

        // Release the leaders so no blocking thread outlives the test.
        drop(gate);
        for l in leaders {
            let _ = l.join();
        }
    }

    #[test]
    fn prompt_not_enabled_deny_policy() {
        let (dialog, calls) = recording_dialog(Ok(allow_host_persist()));
        let t = t36_setup_cfg(
            "no-prompt-deny",
            &[],
            &[],
            dialog,
            false,
            Duration::from_secs(60),
            PromptPolicy::Deny,
            None,
        );
        let resp = exchange(t.port, &connect_req("noprompt-deny.invalid:443"));
        assert!(resp.starts_with("HTTP/1.1 403"), "got: {resp}");
        assert!(
            calls.lock().unwrap().is_empty(),
            "--no-prompt must never show a dialog"
        );
        let ev = last_connect_event(&t.sid);
        assert_eq!(ev["source"], "default");
    }

    #[test]
    fn prompt_not_enabled_allow_policy_admits() {
        let (dialog, calls) = recording_dialog(Ok(deny_once_result()));
        let t = t36_setup_cfg(
            "no-prompt-allow",
            &[],
            &[],
            dialog,
            false,
            Duration::from_secs(60),
            PromptPolicy::Allow,
            None,
        );
        let resp = exchange(t.port, &connect_req("noprompt-allow.invalid:443"));
        assert!(
            resp.starts_with("HTTP/1.1 403") || resp.starts_with("HTTP/1.1 502"),
            "on_unavailable=allow must admit, got: {resp}"
        );
        assert!(calls.lock().unwrap().is_empty());
        let ev = last_connect_event(&t.sid);
        if ev["disposition"] == "allow" {
            assert_eq!(ev["source"], "default");
        } else {
            assert_eq!(ev["source"], "dns");
        }
    }

    // ---- [G-17]: the dialog is enriched with the declared intent ----------

    #[test]
    fn prompt_receives_declared_intent_reason() {
        let (dialog, calls) = recording_dialog(Ok(deny_once_result()));
        let t = t36_setup("prompt-reason", &[], &[], dialog);
        block_on(t.intent.record("reasoned.invalid", "fetching model list"));
        let resp = exchange(t.port, &connect_req("reasoned.invalid:443"));
        assert!(resp.starts_with("HTTP/1.1 403"), "got: {resp}");
        let calls = calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(
            calls[0].reason.as_deref(),
            Some("fetching model list"),
            "dialog must receive the declared intent reason"
        );
    }

    // ---- token gate on CONNECT (existing behavior, now listener-level) -----

    // ---- Step 4: /sandbox/intent endpoints (D-4) ---------------------------

    #[test]
    fn connect_without_token_gets_407_and_default_audit() {
        let (dialog, calls) = recording_dialog(Ok(allow_once()));
        let t = t36_setup("auth-407", &["*"], &[], dialog);
        let resp = exchange(t.port, &connect_req_no_auth("api.example.com:443"));
        assert!(resp.starts_with("HTTP/1.1 407"), "got: {resp}");
        assert!(calls.lock().unwrap().is_empty());
        let ev = last_connect_event(&t.sid);
        assert_eq!(ev["host"], "<unknown>");
        assert_eq!(ev["reason"], "no_token");
        assert_eq!(ev["source"], "default");
    }

    // ---- Step 4: /sandbox/intent endpoints (D-4) ---------------------------

    /// CRLF as a runtime value: the request builders below carry no escape
    /// sequences in their literals.
    fn crlf() -> String {
        let mut s = String::new();
        s.push(13u8 as char);
        s.push(10u8 as char);
        s
    }

    /// One authenticated HTTP request: CRLF head, Content-Length, body.
    fn http_req(method: &str, path: &str, json: bool, body: &str) -> String {
        let c = crlf();
        let auth = auth_header();
        let ct = if json {
            format!("Content-Type: application/json{c}")
        } else {
            String::new()
        };
        format!(
            "{method} {path} HTTP/1.1{c}{auth}{ct}Content-Length: {}{c}{c}{body}",
            body.len()
        )
    }

    fn get_req(path: &str) -> String {
        http_req("GET", path, false, "")
    }

    fn post_json(path: &str, body: &str) -> String {
        http_req("POST", path, true, body)
    }

    /// One UNauthenticated request, for the token-gate tests.
    fn http_req_no_auth(method: &str, path: &str, body: &str) -> String {
        let c = crlf();
        format!(
            "{method} {path} HTTP/1.1{c}Content-Length: {}{c}{c}{body}",
            body.len()
        )
    }

    /// The JSON document of a response (after the CRLF CRLF terminator).
    fn json_body(resp: &str) -> serde_json::Value {
        let sep = format!("{}{}", crlf(), crlf());
        let body = resp.split(sep.as_str()).nth(1).unwrap_or("");
        serde_json::from_str(body).unwrap_or_else(|_| panic!("bad JSON body in response: {resp}"))
    }

    #[test]
    fn intent_post_then_get_roundtrip() {
        let (dialog, _c) = recording_dialog(Ok(deny_once_result()));
        let t = t36_setup("intent-rt", &[], &[], dialog);
        let resp = exchange(
            t.port,
            &post_json(
                "/sandbox/intent",
                r#"{"target":"api.example.com","reason":"fetching the model list"}"#,
            ),
        );
        assert!(resp.starts_with("HTTP/1.1 204"), "got: {resp}");
        let resp = exchange(t.port, &get_req("/sandbox/intent?host=api.example.com"));
        assert!(resp.starts_with("HTTP/1.1 200"), "got: {resp}");
        let v = json_body(&resp);
        assert_eq!(v["host"], "api.example.com");
        assert_eq!(v["reason"], "fetching the model list");
        // RFC3339 UTC, whole seconds: YYYY-MM-DDTHH:MM:SSZ.
        let ts = v["ts"].as_str().unwrap();
        assert!(
            ts.len() == 20 && ts.ends_with('Z') && ts.as_bytes()[10] == b'T',
            "ts must be RFC3339, got {ts}"
        );
        assert_eq!(v["hint"], "declared");
    }

    #[test]
    fn intent_get_unknown_host_is_404() {
        let (dialog, _c) = recording_dialog(Ok(deny_once_result()));
        let t = t36_setup("intent-404", &[], &[], dialog);
        let resp = exchange(
            t.port,
            &get_req("/sandbox/intent?host=never-declared.invalid"),
        );
        assert!(resp.starts_with("HTTP/1.1 404"), "got: {resp}");
        let v = json_body(&resp);
        assert_eq!(v["host"], "never-declared.invalid");
        assert_eq!(v["reason"], "");
        assert_eq!(v["hint"], "undeclared");
    }

    #[test]
    fn intent_get_missing_host_param_is_400() {
        let (dialog, _c) = recording_dialog(Ok(deny_once_result()));
        let t = t36_setup("intent-nohost", &[], &[], dialog);
        let resp = exchange(t.port, &get_req("/sandbox/intent"));
        assert!(resp.starts_with("HTTP/1.1 400"), "got: {resp}");
        let resp = exchange(t.port, &get_req("/sandbox/intent?host="));
        assert!(resp.starts_with("HTTP/1.1 400"), "got: {resp}");
    }

    #[test]
    fn intent_post_malformed_body_is_400() {
        let (dialog, _c) = recording_dialog(Ok(deny_once_result()));
        let t = t36_setup("intent-badjson", &[], &[], dialog);
        let resp = exchange(t.port, &post_json("/sandbox/intent", "this is not json"));
        assert!(resp.starts_with("HTTP/1.1 400"), "got: {resp}");
    }

    #[test]
    fn intent_post_blank_fields_are_400() {
        let (dialog, _c) = recording_dialog(Ok(deny_once_result()));
        let t = t36_setup("intent-blank", &[], &[], dialog);
        let resp = exchange(
            t.port,
            &post_json("/sandbox/intent", r#"{"target":"","reason":"x"}"#),
        );
        assert!(resp.starts_with("HTTP/1.1 400"), "got: {resp}");
        let resp = exchange(t.port, &post_json("/sandbox/intent", r#"{"target":"x"}"#));
        assert!(
            resp.starts_with("HTTP/1.1 400"),
            "missing reason must 400, got: {resp}"
        );
    }

    #[test]
    fn intent_post_truncates_long_reason_not_rejects() {
        let (dialog, _c) = recording_dialog(Ok(deny_once_result()));
        let t = t36_setup("intent-trunc", &[], &[], dialog);
        let long = "a".repeat(600);
        let resp = exchange(
            t.port,
            &post_json(
                "/sandbox/intent",
                &format!(r#"{{"target":"api.example.com","reason":"{long}"}}"#),
            ),
        );
        assert!(
            resp.starts_with("HTTP/1.1 204"),
            "oversized reason is truncated, not rejected: {resp}"
        );
        let resp = exchange(t.port, &get_req("/sandbox/intent?host=api.example.com"));
        let v = json_body(&resp);
        assert_eq!(v["reason"].as_str().unwrap().len(), 500);
    }

    #[test]
    fn intent_explain_flag_is_set_by_post_and_consumed_by_get() {
        let (dialog, _c) = recording_dialog(Ok(deny_once_result()));
        let t = t36_setup("intent-explain", &[], &[], dialog);
        block_on(
            t.intent
                .record("api.example.com", "fetching the model list"),
        );
        let resp = exchange(
            t.port,
            &post_json("/sandbox/intent/explain", r#"{"host":"api.example.com"}"#),
        );
        assert!(resp.starts_with("HTTP/1.1 204"), "got: {resp}");
        // First GET observes the one-shot flag AND the declared entry.
        let resp = exchange(t.port, &get_req("/sandbox/intent?host=api.example.com"));
        assert!(resp.starts_with("HTTP/1.1 200"), "got: {resp}");
        let v = json_body(&resp);
        assert_eq!(v["hint"], "explain-more");
        assert_eq!(v["reason"], "fetching the model list");
        // The flag is one-shot: the second GET shows the plain entry.
        let resp = exchange(t.port, &get_req("/sandbox/intent?host=api.example.com"));
        let v = json_body(&resp);
        assert_eq!(v["hint"], "declared");
    }

    #[test]
    fn intent_get_404_still_carries_explain_flag() {
        let (dialog, _c) = recording_dialog(Ok(deny_once_result()));
        let t = t36_setup("intent-explain-404", &[], &[], dialog);
        let resp = exchange(
            t.port,
            &post_json(
                "/sandbox/intent/explain",
                r#"{"host":"undeclared.invalid"}"#,
            ),
        );
        assert!(resp.starts_with("HTTP/1.1 204"), "got: {resp}");
        let resp = exchange(t.port, &get_req("/sandbox/intent?host=undeclared.invalid"));
        assert!(resp.starts_with("HTTP/1.1 404"), "got: {resp}");
        let v = json_body(&resp);
        assert_eq!(v["hint"], "explain-more");
    }

    #[test]
    fn intent_post_retires_explain_flag() {
        let (dialog, _c) = recording_dialog(Ok(deny_once_result()));
        let t = t36_setup("intent-retire", &[], &[], dialog);
        // NeedsIntent clicked, the deny path set the flag...
        block_on(t.intent.mark_explain_more("redeclared.invalid"));
        // ...the agent re-declares via POST /sandbox/intent...
        let resp = exchange(
            t.port,
            &post_json(
                "/sandbox/intent",
                r#"{"target":"redeclared.invalid","reason":"better reason now"}"#,
            ),
        );
        assert!(resp.starts_with("HTTP/1.1 204"), "got: {resp}");
        // ...and the next GET shows the plain declared entry, no hint.
        let resp = exchange(t.port, &get_req("/sandbox/intent?host=redeclared.invalid"));
        let v = json_body(&resp);
        assert_eq!(v["hint"], "declared");
        assert_eq!(v["reason"], "better reason now");
    }

    #[test]
    fn intent_endpoints_require_the_session_token() {
        let (dialog, _c) = recording_dialog(Ok(deny_once_result()));
        let t = t36_setup("intent-auth", &[], &[], dialog);
        // No auth header at all.
        let resp = exchange(
            t.port,
            &http_req_no_auth("GET", "/sandbox/intent?host=x.invalid", ""),
        );
        assert!(resp.starts_with("HTTP/1.1 407"), "got: {resp}");
        // Wrong token.
        let bad = base64::engine::general_purpose::STANDARD.encode("sandbox:wrong");
        let c = crlf();
        let wrong = format!(
            "POST /sandbox/intent HTTP/1.1{c}Proxy-Authorization: Basic {bad}{c}Content-Length: 2{c}{c}{{}}"
        );
        let resp = exchange(t.port, &wrong);
        assert!(resp.starts_with("HTTP/1.1 407"), "got: {resp}");
    }

    /// Absolute-form is a **proxy consultation**: it runs the D-1 pipeline and is
    /// refused when the pipeline denies (403) — never silently forwarded, and no
    /// longer a 400. Origin-form outside `/sandbox/` stays a 400: this listener is
    /// not a reverse proxy for anyone.
    #[test]
    fn absolute_form_is_admitted_and_origin_form_outside_sandbox_is_400() {
        let (dialog, _c) = recording_dialog(Ok(deny_once_result()));
        let t = t36_setup("plain-http-400", &[], &[], dialog);
        let resp = exchange(t.port, &get_req("http://evil.example.com/"));
        assert!(resp.starts_with("HTTP/1.1 403"), "got: {resp}");
        assert!(resp.contains("X-Sandbox: denied"), "got: {resp}");
        // The deny went through the admission pipeline, so it is audited.
        assert_eq!(last_connect_event(&t.sid)["host"], "evil.example.com");
        // Origin-form request to a non-/sandbox path.
        let resp = exchange(t.port, &get_req("/some/path"));
        assert!(resp.starts_with("HTTP/1.1 400"), "got: {resp}");
    }

    /// Guardrail 1's counting rules on a real listener (plan P1 wave 2, item A):
    /// a *denied* consultation is accepted-and-no-tunnel, a *refused* CONNECT is
    /// the same shape, serving our own origin-form endpoint is not counted at
    /// all, and every epoch starts empty.
    #[test]
    fn counters_record_consultations_and_upstream_establishment_per_epoch() {
        let (dialog, _c) = recording_dialog(Ok(deny_once_result()));
        let t = t36_setup("counters", &[], &[], dialog);
        let counters = t.handle.counters();
        let epoch = counters.begin_epoch().expect("the first launch's window");

        // Origin-form to our own endpoint: served, but NOT a proxy consultation.
        let resp = exchange(t.port, &get_req("/sandbox/intent?host=x.invalid"));
        assert!(resp.starts_with("HTTP/1.1 404"), "got: {resp}");
        assert_eq!(
            counters.counters(epoch),
            Some(LaunchProofCounters::default()),
            "serving our own endpoint must never look like a proxy consultation"
        );

        // Absolute-form for another origin, denied by the pipeline.
        let resp = exchange(t.port, &get_req("http://evil.example.com/x"));
        assert!(resp.starts_with("HTTP/1.1 403"), "got: {resp}");
        // CONNECT to loopback, refused before any dial.
        let resp = exchange(t.port, &connect_req("127.0.0.1:9"));
        assert!(resp.starts_with("HTTP/1.1 403"), "got: {resp}");
        assert_eq!(
            counters.counters(epoch),
            Some(LaunchProofCounters {
                consultations: 2,
                upstream_established: 0,
                probes: 0,
                unauthenticated: 0,
            }),
            "both reached us as a proxy; neither established anything upstream"
        );

        // A 407 is not a consultation and not a probe. Since P3.2a it IS counted,
        // in its own field - which is why the frozen epoch below reads
        // `unauthenticated: 1` rather than zero.
        let resp = exchange(t.port, &connect_req_no_auth("api.example.com:443"));
        assert!(resp.starts_with("HTTP/1.1 407"), "got: {resp}");

        // A new epoch starts empty; the closed one keeps its numbers.
        assert!(counters.close_epoch(epoch));
        let next = counters.begin_epoch().expect("a window after the close");
        assert_eq!(
            counters.counters(next),
            Some(LaunchProofCounters::default())
        );
        exchange(t.port, &connect_req("127.0.0.1:9"));
        assert_eq!(
            counters.counters(next),
            Some(LaunchProofCounters {
                consultations: 1,
                upstream_established: 0,
                probes: 0,
                unauthenticated: 0,
            }),
            "the second epoch must not inherit the first one's traffic"
        );
        assert_eq!(
            counters.counters(epoch),
            Some(LaunchProofCounters {
                consultations: 2,
                upstream_established: 0,
                probes: 0,
                unauthenticated: 1,
            }),
            "a closed epoch keeps its frozen counters: two consultations and the one \
             credential-less attempt it answered"
        );
        assert_eq!(
            counters.counters(9_999),
            None,
            "an unknown epoch has no proof"
        );
        assert!(
            !counters.close_epoch(9_999),
            "closing an unknown epoch is a no-op"
        );
    }

    // ---- ADR-0004 guardrail 1, amended 2026-10-22: the pre-flight probe ----

    /// `GET /sandbox/probe` records ONE probe observation and answers `204`.
    ///
    /// A probe is neither a policy consultation nor an upstream connection: it
    /// is the wrapper's own report that the child's path to THIS listener
    /// works, which is what guardrail 1 gates on now. Counting it as a
    /// consultation would make `MustBeAbsent` unsatisfiable for the sessions
    /// it exists for (the same reason serving an intent endpoint is not one);
    /// counting it as an upstream connection would claim a dial nobody made.
    #[test]
    fn a_probe_is_recorded_as_a_probe_and_answers_204() {
        let (dialog, calls) = recording_dialog(Ok(deny_once_result()));
        let t = t36_setup("probe", &[], &[], dialog);
        let counters = t.handle.counters();
        let epoch = counters.begin_epoch().expect("the launch's window");

        let resp = exchange(t.port, &get_req(PROBE_PATH));
        assert!(resp.starts_with("HTTP/1.1 204"), "got: {resp}");
        assert_eq!(
            counters.counters(epoch),
            Some(LaunchProofCounters {
                consultations: 0,
                upstream_established: 0,
                probes: 1,
                unauthenticated: 0,
            }),
            "the probe must be its own observation - not a consultation, and not an \
             upstream connection"
        );
        assert!(
            calls.lock().unwrap().is_empty(),
            "a probe is not a policy question: it must never reach the dialog"
        );
    }

    /// The property the gate exists for: evidence must be ATTRIBUTABLE.
    ///
    /// A probe under a credential this listener does not own is refused with the
    /// same `407` as every other control-plane request and never counts as a
    /// probe, so it can never satisfy guardrail 1 for a session whose own proxy
    /// path is broken (dead listener, blocked loopback, wrong credential).
    ///
    /// Since P3.2a the refusal IS counted in its own field: something reached this
    /// listener without the run's credential, which is exactly the fact the gate's
    /// second leg reads. What must stay at zero is `probes` - the observation that
    /// stands in for a working path.
    #[test]
    fn a_probe_without_the_run_credential_is_407_and_never_counts_as_a_probe() {
        let (dialog, _c) = recording_dialog(Ok(deny_once_result()));
        let t = t36_setup("probe-cred", &[], &[], dialog);
        let counters = t.handle.counters();
        let epoch = counters.begin_epoch().expect("the launch's window");

        let c = crlf();
        let absent = format!("GET {PROBE_PATH} HTTP/1.1{c}{c}");
        let foreign = probe_req_with("not-this-runs-token");
        for (label, req) in [("absent", absent), ("foreign", foreign)] {
            let resp = exchange(t.port, &req);
            assert!(
                resp.starts_with("HTTP/1.1 407"),
                "{label}: the probe must be gated like every other control-plane \
                 request: {resp}"
            );
            assert!(
                resp.contains("Proxy-Authenticate: Basic"),
                "{label}: the refusal must carry the challenge: {resp}"
            );
        }
        let proof = counters.counters(epoch).expect("the open epoch");
        assert_eq!(
            (
                proof.consultations,
                proof.upstream_established,
                proof.probes
            ),
            (0, 0, 0),
            "a refused probe must leave no consultation, no tunnel and NO PROBE: it \
             cannot stand in for the session's own proxy path"
        );
        assert_eq!(
            proof.unauthenticated, 2,
            "both refusals are counted in their own field (P3.2a): the gate has to see \
             that something reached the listener without this run's credential"
        );
    }

    /// One probe under a CHOSEN credential (this listener must refuse it).
    fn probe_req_with(token: &str) -> String {
        let creds = base64::engine::general_purpose::STANDARD.encode(format!("sandbox:{token}"));
        let c = crlf();
        format!("GET {PROBE_PATH} HTTP/1.1{c}Proxy-Authorization: Basic {creds}{c}{c}")
    }

    /// A handler that panicked while holding the counter lock must not make the
    /// launch path panic: a poisoned mutex is recovered, not propagated.
    #[test]
    fn counters_survive_a_poisoned_lock() {
        let counters = LaunchCounters::new();
        let epoch = counters.begin_epoch().expect("the first launch's window");
        let poisoner = Arc::clone(&counters);
        let poisoned = std::thread::spawn(move || {
            let _guard = poisoner.state.lock().expect("first lock");
            panic!("handler blew up mid-count");
        });
        assert!(poisoned.join().is_err(), "the handler thread panicked");

        // Every accessor must still work on the same registry.
        assert_eq!(
            counters.counters(epoch),
            Some(LaunchProofCounters::default())
        );
        counters.note_consultation();
        assert_eq!(
            counters.counters(epoch),
            Some(LaunchProofCounters {
                consultations: 1,
                upstream_established: 0,
                probes: 0,
                unauthenticated: 0,
            })
        );
        assert!(counters.close_epoch(epoch));
        assert_eq!(
            counters.begin_epoch().expect("a window after the close"),
            epoch + 1
        );
    }

    // ---- P1.4: concurrency and per-run token attribution ------------------

    /// One CONNECT carrying a chosen credential (the tests below need to present
    /// a token that is *not* this listener's).
    fn connect_req_with(target: &str, token: &str) -> String {
        let creds = base64::engine::general_purpose::STANDARD.encode(format!("sandbox:{token}"));
        let c = crlf();
        format!("CONNECT {target} HTTP/1.1{c}Proxy-Authorization: Basic {creds}{c}{c}")
    }

    /// P1.8: managed clients do **not** send `Proxy-Authorization` pre-emptively.
    ///
    /// Measured inside a real container: .NET 8 (`SocketsHttpHandler`) and pwsh 7
    /// read the credential out of the `HTTP_PROXY` userinfo, try once WITHOUT it,
    /// and authenticate only after a `407` carrying a `Proxy-Authenticate: Basic`
    /// challenge (the first attempt is a deliberate, uncounted refusal, so the run
    /// still reports `accepted: 1`). If this listener ever answered 407 without a
    /// challenge, every managed workload would silently lose egress - so the
    /// header, not just the status, is pinned here.
    #[test]
    fn an_unauthenticated_consultation_gets_the_basic_challenge_managed_clients_need() {
        let token = RunToken::issue().expect("mint a token");
        let (dialog, _keep) = recording_dialog(Ok(allow_once()));
        let cfg = t36_setup_token_cfg(
            "p18-challenge",
            &["*"],
            &[],
            dialog,
            true,
            Duration::from_secs(60),
            PromptPolicy::Deny,
            None,
            token.clone(),
        );
        let c = crlf();
        let unauth = format!("CONNECT 127.0.0.1:9 HTTP/1.1{c}Host: 127.0.0.1:9{c}{c}");
        let resp = exchange(cfg.port, &unauth);
        assert!(resp.starts_with("HTTP/1.1 407"), "{resp}");
        assert!(
            resp.contains("Proxy-Authenticate: Basic"),
            "no challenge means every managed client loses egress: {resp}"
        );
        assert!(resp.contains("realm=\"sandbox\""), "{resp}");

        // The retry the client performs after that challenge is accepted, which
        // proves the challenge is actionable rather than decorative.
        let resp = exchange(cfg.port, &connect_req_with("127.0.0.1:9", token.value()));
        assert!(
            resp.starts_with("HTTP/1.1 403"),
            "an admitted request is loopback-refused, not challenged: {resp}"
        );
    }

    /// P1.4: a listener accepts exactly one credential - its own run's token.
    ///
    /// Two live listeners, each with its own token and port. Each refuses the
    /// other's token with a `407` that is **not** a consultation and leaves **no**
    /// audit leaf, while still serving its own token. Before the P1.4 rule the
    /// foreign token took the same `no_token` path as a missing credential: it
    /// wrote a leaf into an audit chain it does not belong to.
    #[test]
    fn a_listener_refuses_a_foreign_run_token_without_counting_it_and_records_it_once() {
        let (dialog_a, _keep_a) = recording_dialog(Ok(allow_once()));
        let (dialog_b, _keep_b) = recording_dialog(Ok(allow_once()));
        let token_a = RunToken::issue().expect("mint run A's token");
        let token_b = RunToken::issue().expect("mint run B's token");
        assert_ne!(token_a.value(), token_b.value());

        let a = t36_setup_token_cfg(
            "p14-run-a",
            &["*"],
            &[],
            dialog_a,
            true,
            Duration::from_secs(60),
            PromptPolicy::Deny,
            None,
            token_a.clone(),
        );
        let b = t36_setup_token_cfg(
            "p14-run-b",
            &["*"],
            &[],
            dialog_b,
            true,
            Duration::from_secs(60),
            PromptPolicy::Deny,
            None,
            token_b.clone(),
        );
        assert_ne!(
            a.port, b.port,
            "one listener per run means one port per run"
        );

        let epoch_a = a.handle.counters().begin_epoch().expect("A's window");
        let epoch_b = b.handle.counters().begin_epoch().expect("B's window");
        let one_consultation = Some(LaunchProofCounters {
            consultations: 1,
            upstream_established: 0,
            probes: 0,
            unauthenticated: 0,
        });

        // (i) A's own token at A's listener is served and counted.
        let resp = exchange(a.port, &connect_req_with("127.0.0.1:9", token_a.value()));
        assert!(
            resp.starts_with("HTTP/1.1 403"),
            "A must accept its own token: {resp}"
        );
        assert_eq!(a.handle.counters().counters(epoch_a), one_consultation);

        // (ii) B's token at A's listener: refused, uncounted, recorded once
        // as `foreign_token`.
        let leaves_before = connect_events(&a.sid).len();
        let resp = exchange(a.port, &connect_req_with("127.0.0.1:9", token_b.value()));
        assert!(
            resp.starts_with("HTTP/1.1 407"),
            "A must refuse B's token: {resp}"
        );
        let after_foreign = a
            .handle
            .counters()
            .counters(epoch_a)
            .expect("A's open window");
        assert_eq!(
            (
                after_foreign.consultations,
                after_foreign.upstream_established,
                after_foreign.probes
            ),
            (1, 0, 0),
            "a foreign token is not a consultation, a tunnel or a probe"
        );
        assert_eq!(
            after_foreign.unauthenticated, 1,
            "it IS counted as an unauthenticated attempt (P3.2a): the gate must see that \
             something reached A without A's credential"
        );
        assert_eq!(
            connect_events(&a.sid).len(),
            leaves_before + 1,
            "a foreign token must leave exactly one leaf in A's chain"
        );
        assert_eq!(
            last_connect_event(&a.sid)["reason"],
            "foreign_token",
            "the leaf must name the event, and never the credential"
        );
        assert_eq!(
            last_connect_event(&a.sid)["host"],
            "<unknown>",
            "a foreign attempt names no host, because none was admitted"
        );

        // (iii) the other direction: A's token at B's listener.
        let leaves_before = connect_events(&b.sid).len();
        let resp = exchange(b.port, &connect_req_with("127.0.0.1:9", token_a.value()));
        assert!(
            resp.starts_with("HTTP/1.1 407"),
            "B must refuse A's token: {resp}"
        );
        assert_eq!(
            b.handle.counters().counters(epoch_b),
            Some(LaunchProofCounters {
                consultations: 0,
                upstream_established: 0,
                probes: 0,
                unauthenticated: 1,
            }),
            "a foreign token must not count at B as traffic - only as the unauthenticated \
             attempt it was"
        );
        assert_eq!(
            connect_events(&b.sid).len(),
            leaves_before + 1,
            "a foreign token must leave exactly one leaf in B's chain"
        );
        assert_eq!(last_connect_event(&b.sid)["reason"], "foreign_token");

        // B still serves its own token, so the refusal is about ownership and
        // not a broken listener.
        let resp = exchange(b.port, &connect_req_with("127.0.0.1:9", token_b.value()));
        assert!(resp.starts_with("HTTP/1.1 403"), "{resp}");
        assert_eq!(
            b.handle.counters().counters(epoch_b),
            Some(LaunchProofCounters {
                consultations: 1,
                upstream_established: 0,
                probes: 0,
                unauthenticated: 1,
            }),
            "B's own credential is a consultation; the foreign attempt it refused earlier \
             stays counted on the same epoch"
        );

        // (iv) non-vacuity: a request with NO credential still gets its leaf, so
        // the silence above is the foreign-token rule and not a dead writer.
        let leaves_before = connect_events(&a.sid).len();
        let resp = exchange(a.port, &connect_req_no_auth("127.0.0.1:9"));
        assert!(resp.starts_with("HTTP/1.1 407"), "{resp}");
        assert_eq!(
            connect_events(&a.sid).len(),
            leaves_before + 1,
            "a missing credential is worth a leaf; a foreign one is not"
        );
    }

    // ---- P3.2a: unauthenticated attempts at the proxy (guardrail 1, leg 2) --

    /// **P3.2a: both refusal arms are counted on the launch's epoch, and the count
    /// is per epoch.** The counter is what lets the gate see a client stack that
    /// reaches the listener and can never authenticate (WinINet / Windows
    /// PowerShell 5.1), instead of reading `probes == 1` as a working session.
    ///
    /// Deliberately a NEW epoch-scoped field rather than the listener-lifetime
    /// `no_token`/`foreign_token` budgets that drive the leaf volume: those must
    /// survive launches (the flood cap is per listener), so reusing them would
    /// refuse launch N+1 on launch N's refusals.
    #[test]
    fn unauthenticated_attempts_are_counted_per_epoch_on_both_refusal_arms() {
        let token = RunToken::issue().expect("mint a token");
        let (dialog, _keep) = recording_dialog(Ok(deny_once_result()));
        let t = t36_setup_token_cfg(
            "p32a-unauthenticated",
            &["*"],
            &[],
            dialog,
            true,
            Duration::from_secs(60),
            PromptPolicy::Deny,
            None,
            token.clone(),
        );
        let counters = t.handle.counters();
        let epoch = counters.begin_epoch().expect("the launch's epoch");

        // 1. A client that sends no credential at all.
        let resp = exchange(t.port, &connect_req_no_auth("api.example.com:443"));
        assert!(resp.starts_with("HTTP/1.1 407"), "{resp}");
        // 2. A client holding somebody else's credential.
        let resp = exchange(
            t.port,
            &connect_req_with("api.example.com:443", "a-different-runs-token"),
        );
        assert!(resp.starts_with("HTTP/1.1 407"), "{resp}");

        let after_refusals = counters.counters(epoch).expect("the open epoch");
        println!("EVIDENCE refusals counters={after_refusals:?}");
        assert_eq!(
            after_refusals.unauthenticated, 2,
            "one per refusal, on BOTH arms: {after_refusals:?}"
        );
        assert_eq!(
            (
                after_refusals.consultations,
                after_refusals.upstream_established,
                after_refusals.probes
            ),
            (0, 0, 0),
            "a refusal is not a consultation, a tunnel or a probe: {after_refusals:?}"
        );

        // 3. Control: this listener's own credential is never counted here, and the
        //    request IS a consultation even though policy denies it (the gate must
        //    not confuse a denial with a client that cannot authenticate).
        let resp = exchange(t.port, &connect_req_with("127.0.0.1:9", token.value()));
        assert!(resp.starts_with("HTTP/1.1 403"), "{resp}");
        let proven = counters.counters(epoch).expect("the open epoch");
        println!("EVIDENCE control counters={proven:?}");
        assert_eq!(
            proven,
            LaunchProofCounters {
                consultations: 1,
                upstream_established: 0,
                probes: 0,
                unauthenticated: 2,
            },
            "an authenticated request counts as a consultation and NOT as unauthenticated"
        );

        // 4. Per epoch: the next launch inherits nothing, and closing an epoch
        //    FREEZES its record instead of zeroing it.
        assert!(counters.close_epoch(epoch));
        let second = counters.begin_epoch().expect("the second launch's epoch");
        assert_eq!(
            counters.counters(second),
            Some(LaunchProofCounters::default()),
            "a second launch on one listener must start at zero"
        );
        assert_eq!(
            counters.counters(epoch).map(|c| c.unauthenticated),
            Some(2),
            "a closed epoch keeps its own count; a later launch must not reset it"
        );
        assert!(counters.close_epoch(second));
    }

    // ---- P1.6: hardening ------------------------------------------------

    /// P1.6(a): a credential-less flood is capped per listener, and what it
    /// suppresses is counted exactly.
    ///
    /// Measured before the cap: 400 credential-less CONNECTs wrote 400 `no_token`
    /// leaves (129 KB) with nothing bounding a loop of any size, and P1.8 made it
    /// the *normal* case - every managed client's first request on a connection
    /// carries no credential, so `no_token` had stopped being a signal. The budget
    /// is eight individual leaves, then one aggregate leaf per window of
    /// suppressed refusals; the wire answer is unchanged and a refusal is still
    /// not a consultation.
    ///
    /// 20 refusals are 8 leaves of their own plus 12 suppressed - exactly one
    /// window - which pins all three review findings at once: a real `suppressed`
    /// integer (never text in `scope`), a count that is the true one (12, not a
    /// constant `1`), and a leaf volume that no longer tracks the flood.
    #[test]
    fn credential_less_refusals_are_capped_and_what_they_suppress_is_counted() {
        let (dialog, _keep) = recording_dialog(Ok(deny_once_result()));
        let t = t36_setup("p16-no-token-flood", &["*"], &[], dialog);
        let epoch = t
            .handle
            .counters()
            .begin_epoch()
            .expect("a window to watch");

        let mut statuses = Vec::new();
        for _ in 0..20 {
            let resp = exchange(t.port, &connect_req_no_auth("api.example.com:443"));
            statuses.push(resp.lines().next().unwrap_or("").to_string());
        }
        assert!(
            statuses
                .iter()
                .all(|line| line == "HTTP/1.1 407 Proxy Authentication Required"),
            "every credential-less CONNECT must still get the same 407: {statuses:?}"
        );

        let leaves = connect_events(&t.sid);
        let individual = leaves.iter().filter(|e| e["reason"] == "no_token").count();
        let aggregate: Vec<&serde_json::Value> = leaves
            .iter()
            .filter(|e| e["reason"] == "no_token_suppressed")
            .collect();
        assert_eq!(
            individual, 8,
            "the first eight refusals keep a leaf each: {leaves:?}"
        );
        assert_eq!(
            aggregate.len(),
            1,
            "twelve suppressed refusals are exactly one window: {leaves:?}"
        );
        assert_eq!(
            leaves.len(),
            9,
            "20 refusals must leave 8 + 1 leaves, not 20: {leaves:?}"
        );
        let aggregate = aggregate[0];
        assert_eq!(aggregate["disposition"], "deny");
        assert_eq!(aggregate["source"], "default");
        assert_eq!(aggregate["host"], "<unknown>");
        assert_eq!(aggregate["reason"], "no_token_suppressed");
        assert_eq!(
            aggregate["suppressed"], 12,
            "the aggregate stands in for exactly 20 - 8 refusals: {aggregate:?}"
        );
        assert_eq!(
            aggregate["scope"],
            serde_json::Value::Null,
            "scope means rule scope; a count in it makes a scope filter read a number: \
             {aggregate:?}"
        );

        // The CONTRACT is each field's domain, not a shared key set: `scope` is a
        // rule scope or null, `suppressed` a count or null, `persisted` a boolean,
        // `disposition` one of two words. Asserting "all leaves have the same
        // keys" tested the encoding of the fix (a count squeezed into an existing
        // field) instead of what a consumer is allowed to rely on.
        for leaf in &leaves {
            assert!(
                leaf["scope"].is_null() || leaf["scope"].is_string(),
                "scope must be a rule scope or null: {leaf:?}"
            );
            assert!(
                leaf["suppressed"].is_null() || leaf["suppressed"].is_u64(),
                "suppressed must be a count or null: {leaf:?}"
            );
            assert!(
                leaf["persisted"].is_boolean(),
                "persisted must be a boolean: {leaf:?}"
            );
            assert!(
                leaf["disposition"] == "allow" || leaf["disposition"] == "deny",
                "disposition is a closed vocabulary: {leaf:?}"
            );
            assert!(
                leaf["reason"].is_string() || leaf["reason"].is_null(),
                "reason is text or null: {leaf:?}"
            );
        }
        assert!(
            leaves
                .iter()
                .filter(|e| e["reason"] == "no_token")
                .all(|e| e["suppressed"].is_null()),
            "a leaf that describes one refusal suppresses nothing: {leaves:?}"
        );

        assert_eq!(
            t.handle.counters().counters(epoch),
            Some(LaunchProofCounters {
                consultations: 0,
                upstream_established: 0,
                probes: 0,
                unauthenticated: 20,
            }),
            "a credential-less refusal is not a consultation - and all twenty are \
             counted as unauthenticated attempts (P3.2a), suppression or not"
        );
        assert!(t.handle.counters().close_epoch(epoch));
    }

    /// P1.6(a): a listener that closes mid-window still writes what it suppressed.
    ///
    /// A partial window cannot be written when it is filled (it never is), so the
    /// chain would be short by up to eleven refusals forever if closing dropped
    /// it. 13 refusals are 8 leaves + a 5-refusal partial window; the aggregate
    /// for those 5 must appear once the handle is dropped, and only once.
    #[test]
    fn the_trailing_suppressed_window_is_written_once_when_the_listener_closes() {
        let (dialog, _keep) = recording_dialog(Ok(deny_once_result()));
        // `T36::drop` unlinks the chain before its fields drop, so the fixture is
        // held undropped and only the handle is dropped in place - the flush is
        // what this test is about, and it must land in the file the listener
        // wrote. The fixture's scratch state is removed by hand below.
        let mut t =
            std::mem::ManuallyDrop::new(t36_setup("p16-no-token-trailing", &["*"], &[], dialog));
        let sid = t.sid.clone();
        for _ in 0..13 {
            let resp = exchange(t.port, &connect_req_no_auth("api.example.com:443"));
            assert!(resp.starts_with("HTTP/1.1 407"), "{resp}");
        }
        assert_eq!(
            connect_events(&sid).len(),
            8,
            "a partial window writes no leaf while the listener runs"
        );

        // SAFETY: the handle is dropped exactly once, and no reference to it is
        // used afterwards.
        unsafe { std::ptr::drop_in_place(&mut t.handle) };

        let leaves = connect_events(&sid);
        let aggregates: Vec<&serde_json::Value> = leaves
            .iter()
            .filter(|e| e["reason"] == "no_token_suppressed")
            .collect();
        assert_eq!(
            aggregates.len(),
            1,
            "closing the listener must write the partial window exactly once: {leaves:?}"
        );
        assert_eq!(
            aggregates[0]["suppressed"], 5,
            "the remainder is the refusals no other leaf accounts for: {aggregates:?}"
        );
        assert_eq!(aggregates[0]["scope"], serde_json::Value::Null);
        assert_eq!(
            leaves.len(),
            9,
            "8 individual leaves + the one flushed aggregate: {leaves:?}"
        );

        // The fixture's own cleanup, since its `Drop` is what we bypassed.
        let _ = std::fs::remove_file(crate::audit::audit_log_path(&sid));
        let _ = std::fs::remove_dir_all(&t.learned_base);
    }

    /// P1.6(a): the leaf volume is bounded, and the chain still sums to the total.
    ///
    /// 44 refusals are 8 leaves of their own plus 36 suppressed - three full
    /// windows - so the chain must hold 8 + 3 leaves, each aggregate carrying
    /// exactly 12. A count that reset per window without being written, or a
    /// window that fired once and then went silent, fails here: the sum of the
    /// aggregates is the number of refusals no other leaf accounts for.
    #[test]
    fn a_long_flood_writes_one_aggregate_per_window_and_they_sum_to_the_total() {
        let (dialog, _keep) = recording_dialog(Ok(deny_once_result()));
        let t = t36_setup("p16-no-token-windows", &["*"], &[], dialog);
        let epoch = t
            .handle
            .counters()
            .begin_epoch()
            .expect("a window to watch");

        for _ in 0..44 {
            let resp = exchange(t.port, &connect_req_no_auth("api.example.com:443"));
            assert!(resp.starts_with("HTTP/1.1 407"), "{resp}");
        }

        let leaves = connect_events(&t.sid);
        let individual = leaves.iter().filter(|e| e["reason"] == "no_token").count();
        let aggregates: Vec<&serde_json::Value> = leaves
            .iter()
            .filter(|e| e["reason"] == "no_token_suppressed")
            .collect();
        assert_eq!(individual, 8, "the budget is eight leaves: {leaves:?}");
        assert_eq!(
            aggregates.len(),
            3,
            "36 suppressed refusals are three windows: {aggregates:?}"
        );
        let suppressed: u64 = aggregates
            .iter()
            .map(|e| e["suppressed"].as_u64().expect("an integer count"))
            .sum();
        assert_eq!(
            suppressed,
            44 - 8,
            "the aggregates must account for every refusal no other leaf does: {aggregates:?}"
        );
        assert_eq!(
            leaves.len(),
            11,
            "44 refusals must cost 8 + 3 leaves, never 44: {leaves:?}"
        );
        assert_eq!(
            t.handle.counters().counters(epoch),
            Some(LaunchProofCounters {
                consultations: 0,
                upstream_established: 0,
                probes: 0,
                unauthenticated: 44,
            }),
            "none of it is a consultation, and every refusal is counted (P3.2a) - the \
             count is exact even where the LEAVES are windowed"
        );
        assert!(t.handle.counters().close_epoch(epoch));
    }

    /// P1.6 (blocking 2): the FOREIGN arm is budgeted too, with its own counter.
    ///
    /// `Proxy-Authorization: Basic <anything base64>` reaches the `Foreign` arm,
    /// so capping only the credential-less arm left the flood one header away.
    /// The budgets are separate on purpose: a foreign flood must not spend the
    /// missing-credential budget (that is the P1.8 steady state), and neither arm
    /// may silence the other's evidence.
    ///
    /// 20 refusals are 8 `foreign_token` leaves plus 12 suppressed - one window.
    /// A foreign credential is still not a consultation and never a probe, so it
    /// can never satisfy guardrail 1; since P3.2a it IS counted as an
    /// unauthenticated attempt, which is the signal the gate's second leg reads.
    #[test]
    fn foreign_token_refusals_are_capped_by_their_own_budget() {
        let token = RunToken::issue().expect("mint the listener's token");
        let intruder = RunToken::issue().expect("mint another run's token");
        let (dialog, _keep) = recording_dialog(Ok(deny_once_result()));
        let t = t36_setup_token_cfg(
            "p16-foreign-flood",
            &["*"],
            &[],
            dialog,
            true,
            Duration::from_secs(60),
            PromptPolicy::Deny,
            None,
            token.clone(),
        );
        let epoch = t
            .handle
            .counters()
            .begin_epoch()
            .expect("a window to watch");

        for _ in 0..20 {
            let resp = exchange(
                t.port,
                &connect_req_with("api.example.com:443", intruder.value()),
            );
            assert!(resp.starts_with("HTTP/1.1 407"), "{resp}");
        }

        let leaves = connect_events(&t.sid);
        let individual = leaves
            .iter()
            .filter(|e| e["reason"] == "foreign_token")
            .count();
        let aggregates: Vec<&serde_json::Value> = leaves
            .iter()
            .filter(|e| e["reason"] == "foreign_token_suppressed")
            .collect();
        assert_eq!(
            individual, 8,
            "the first eight foreign refusals keep a leaf each: {leaves:?}"
        );
        assert_eq!(
            aggregates.len(),
            1,
            "twelve suppressed foreign refusals are one window: {leaves:?}"
        );
        assert_eq!(leaves.len(), 9, "20 refusals must not cost 20 leaves");
        assert_eq!(
            aggregates[0]["suppressed"], 12,
            "20 - 8, exactly: {aggregates:?}"
        );
        assert_eq!(
            aggregates[0]["scope"],
            serde_json::Value::Null,
            "scope means rule scope: {aggregates:?}"
        );
        assert_eq!(aggregates[0]["host"], "<unknown>");
        assert_eq!(
            t.handle.counters().counters(epoch),
            Some(LaunchProofCounters {
                consultations: 0,
                upstream_established: 0,
                probes: 0,
                unauthenticated: 20,
            }),
            "a foreign token is not a consultation, capped or not - and all twenty are \
             counted as unauthenticated attempts"
        );

        // Independence: the missing-credential arm still owns its own budget, so
        // the foreign flood cannot have spent it.
        let before = connect_events(&t.sid).len();
        let resp = exchange(t.port, &connect_req_no_auth("api.example.com:443"));
        assert!(resp.starts_with("HTTP/1.1 407"), "{resp}");
        assert_eq!(
            connect_events(&t.sid).len(),
            before + 1,
            "the no_token budget was untouched by the foreign flood"
        );
        assert_eq!(last_connect_event(&t.sid)["reason"], "no_token");
        assert_eq!(
            t.handle
                .counters()
                .counters(epoch)
                .map(|c| c.unauthenticated),
            Some(21),
            "the control's own credential-less refusal is counted too, on the same \
             epoch - the two arms are separate BUDGETS, not separate counters"
        );
        assert!(t.handle.counters().close_epoch(epoch));
    }

    /// P1.6(a)/(blocking 1c): windows are exact, and the remainder is claimable.
    ///
    /// Drives the budget directly - no sockets - so the arithmetic is pinned
    /// where it lives: eight individual leaves, one aggregate per full window of
    /// twelve, and whatever the last partial window holds is carried out exactly
    /// once when the listener closes (never twice, never silently dropped).
    #[test]
    fn a_refusal_budget_yields_exact_windows_and_one_flushable_remainder() {
        let budget = super::RefusalBudget::new();
        for i in 1..=8 {
            assert_eq!(
                budget.spend(),
                super::RefusalLeaf::Individual,
                "refusal {i} is still inside the budget"
            );
        }
        let mut aggregates = Vec::new();
        for _ in 0..30 {
            match budget.spend() {
                super::RefusalLeaf::Aggregate { suppressed } => aggregates.push(suppressed),
                super::RefusalLeaf::Nothing => {}
                super::RefusalLeaf::Individual => panic!("the individual budget is spent"),
            }
        }
        assert_eq!(
            aggregates,
            vec![12, 12],
            "30 suppressed refusals are two windows, each carrying exactly its own count"
        );
        assert_eq!(
            budget.claim_trailing(),
            Some(6),
            "the partial window is what the chain still owes"
        );
        assert_eq!(
            budget.claim_trailing(),
            None,
            "a remainder is written exactly once"
        );
        // And a later refusal cannot resurrect a window that was already paid.
        assert_eq!(budget.spend(), super::RefusalLeaf::Nothing);
        assert_eq!(budget.claim_trailing(), Some(1));
    }

    /// P1.6(b): one credential may be live on exactly one listener.
    ///
    /// `RunToken: Clone` meant two `ProxyConfig`s *could* carry the same value and
    /// both listeners would accept it - the P1.4 ambiguity (whose traffic was
    /// that?) reintroduced through a clone. `spawn` now refuses the second one by
    /// name, and the handle's `Drop` releases the credential.
    #[test]
    fn a_run_token_can_be_live_on_only_one_listener() {
        let token = RunToken::issue().expect("mint a token");
        let (dialog, _keep) = recording_dialog(Ok(deny_once_result()));
        let first = t36_setup_token_cfg(
            "p16-dup-first",
            &["*"],
            &[],
            dialog,
            true,
            Duration::from_secs(60),
            PromptPolicy::Deny,
            None,
            token.clone(),
        );

        // A second listener with a CLONE of the live credential: refused, by name,
        // before it binds a socket or builds a runtime.
        let (dialog, _keep) = recording_dialog(Ok(deny_once_result()));
        let err = try_t36_token_cfg(
            "p16-dup-second",
            &["*"],
            &[],
            dialog,
            true,
            Duration::from_secs(60),
            PromptPolicy::Deny,
            None,
            token.clone(),
        )
        .err()
        .expect("a duplicate live credential must be refused");
        assert!(
            err.downcast_ref::<super::TokenAlreadyLive>().is_some(),
            "the refusal must be the named error, not a free-form string: {err:?}"
        );
        let shown = format!("{err}");
        assert!(
            shown.contains("already live"),
            "the error must say what happened: {shown}"
        );
        assert!(
            !shown.contains(token.value()),
            "the refusal must never print the credential: {shown}"
        );

        // The refused spawn did not disturb the listener that holds the token.
        let resp = exchange(first.port, &connect_req_with("127.0.0.1:9", token.value()));
        assert!(
            resp.starts_with("HTTP/1.1 403"),
            "the holder must still serve its own credential (admitted, then loopback-refused): {resp}"
        );

        // Dropping the handle releases the credential.
        let port = first.port;
        drop(first);
        let again = t36_setup_token_cfg(
            "p16-dup-again",
            &["*"],
            &[],
            {
                let (dialog, _keep) = recording_dialog(Ok(deny_once_result()));
                dialog
            },
            true,
            Duration::from_secs(60),
            PromptPolicy::Deny,
            None,
            token.clone(),
        );
        let resp = exchange(again.port, &connect_req_with("127.0.0.1:9", token.value()));
        assert!(
            resp.starts_with("HTTP/1.1 403"),
            "the re-spawned listener must serve the same credential at its own port {port}: {resp}"
        );

        // Two distinct credentials coexist: the rule is one *live* token per
        // listener, not one listener per process.
        let other_token = RunToken::issue().expect("mint another token");
        let other = t36_setup_token_cfg(
            "p16-dup-other",
            &["*"],
            &[],
            {
                let (dialog, _keep) = recording_dialog(Ok(deny_once_result()));
                dialog
            },
            true,
            Duration::from_secs(60),
            PromptPolicy::Deny,
            None,
            other_token.clone(),
        );
        let resp = exchange(
            other.port,
            &connect_req_with("127.0.0.1:9", other_token.value()),
        );
        assert!(
            resp.starts_with("HTTP/1.1 403"),
            "a distinct credential must spawn alongside the first: {resp}"
        );
    }

    /// P1.6 (registry): the live-token set holds run serials, never credentials.
    ///
    /// The registry exists to make "one credential, one listener" true for the
    /// process, and it used to do that by keeping the credential itself in a
    /// process-global `HashSet<String>` - a second plaintext copy of the secret
    /// for the lifetime of the run. Keying on the run serial keeps the property
    /// (a clone carries the serial it was cloned from, so a clone still collides)
    /// and holds no copy at all. The key type is the assertion: `Vec<u64>` below
    /// does not compile against a string-keyed set.
    #[test]
    fn the_live_token_registry_holds_run_serials_and_no_credential() {
        let token = RunToken::issue().expect("mint a token");
        let (dialog, _keep) = recording_dialog(Ok(deny_once_result()));
        let handle = t36_setup_token_cfg(
            "p16-registry-keys",
            &["*"],
            &[],
            dialog,
            true,
            Duration::from_secs(60),
            PromptPolicy::Deny,
            None,
            token.clone(),
        );

        let keys: Vec<u64> = super::live_tokens().iter().copied().collect();
        assert!(
            keys.contains(&token.run()),
            "this listener's run serial must be registered: {keys:?}"
        );
        let dump = format!("{keys:?}");
        assert!(
            !dump.contains(token.value()),
            "the registry must not retain the credential: {dump}"
        );
        assert!(
            !dump.contains(&token.value()[8..]),
            "nor the secret half of it: {dump}"
        );

        // The same credential twice is still refused (a clone is one identity),
        // which is the property the value-keyed registry used to provide.
        let (dialog, _keep) = recording_dialog(Ok(deny_once_result()));
        let err = try_t36_token_cfg(
            "p16-registry-clone",
            &["*"],
            &[],
            dialog,
            true,
            Duration::from_secs(60),
            PromptPolicy::Deny,
            None,
            token.clone(),
        )
        .err()
        .expect("a clone of a live token must still be refused");
        assert!(
            err.downcast_ref::<super::TokenAlreadyLive>().is_some(),
            "{err:?}"
        );

        // The handle's `Drop` releases the serial, so the set does not grow with
        // the number of listeners a process has ever served.
        let run = token.run();
        drop(handle);
        assert!(
            !super::live_tokens().iter().any(|key| *key == run),
            "drop must release the run serial"
        );
    }

    /// P1.4: an epoch that is still open refuses a second launch by name.
    ///
    /// Before the rule, the second `begin_epoch` simply moved `active`: both
    /// launches' traffic landed in the newer window and the older launch's proof
    /// silently went to zero - a split attribution with no error anywhere.
    #[test]
    fn begin_epoch_refuses_a_second_launch_while_one_is_open() {
        let counters = LaunchCounters::new();
        let first = counters.begin_epoch().expect("the first launch's window");
        counters.note_consultation();

        let err = counters
            .begin_epoch()
            .expect_err("a second concurrent launch must be refused");
        assert_eq!(
            err,
            EpochAlreadyOpen { active: first },
            "the refusal must name the open epoch"
        );
        assert_eq!(
            counters.active_epoch(),
            Some(first),
            "a refused launch must not move the attribution window"
        );
        assert_eq!(
            counters.counters(first),
            Some(LaunchProofCounters {
                consultations: 1,
                upstream_established: 0,
                probes: 0,
                unauthenticated: 0,
            }),
            "a refused launch must not steal or reset the open window"
        );
        assert!(
            err.to_string().contains("still open"),
            "the error must say what is wrong: {err}"
        );

        // Non-vacuity: once the window is closed, the next launch is allowed and
        // starts empty, while the closed window keeps its numbers.
        assert!(counters.close_epoch(first));
        let second = counters.begin_epoch().expect("a window after the close");
        assert_eq!(second, first + 1);
        assert_eq!(
            counters.counters(second),
            Some(LaunchProofCounters::default())
        );
        assert_eq!(
            counters.counters(first),
            Some(LaunchProofCounters {
                consultations: 1,
                upstream_established: 0,
                probes: 0,
                unauthenticated: 0,
            })
        );
    }

    /// P1.4: the pruner evicts **only closed** epochs, so the window a live
    /// launch is about to read can never be dropped.
    ///
    /// Before the rule, `prune` skipped the active epoch alone; once the map hit
    /// `MAX_REMEMBERED_EPOCHS` it evicted the oldest entry regardless of whether
    /// a launch was still proving against it, and that launch then read zeros and
    /// failed `SessionNotAccepted` after doing real work.
    #[test]
    fn an_open_epoch_is_never_evicted_by_pruning() {
        let counters = LaunchCounters::new();
        let live = counters.begin_epoch().expect("the launch in flight");
        counters.note_consultation();

        {
            let mut state = counters.lock();
            // The open epochs get the LOWEST ids on purpose: a pruner that
            // evicts oldest-first without looking at `closed` removes exactly
            // these first, which is the defect this test exists for.
            for id in 100..110 {
                state.epochs.insert(
                    id,
                    EpochEntry {
                        counters: LaunchProofCounters::default(),
                        closed: false,
                    },
                );
            }
            for id in 900..(900 + MAX_REMEMBERED_EPOCHS as u64 + 8) {
                state.epochs.insert(
                    id,
                    EpochEntry {
                        counters: LaunchProofCounters::default(),
                        closed: true,
                    },
                );
            }
            state.prune();

            assert!(
                state.epochs.contains_key(&live),
                "the live launch's window must survive pruning"
            );
            for id in 100..110 {
                assert!(
                    state.epochs.contains_key(&id),
                    "open epoch {id} must survive pruning even though it is the oldest: only \
                     closed epochs are evictable"
                );
            }
            assert_eq!(
                state.epochs.len(),
                MAX_REMEMBERED_EPOCHS,
                "closed epochs are still trimmed to the bound"
            );
            assert_eq!(
                state.epochs.values().filter(|entry| entry.closed).count(),
                MAX_REMEMBERED_EPOCHS - 11,
                "the eleven open epochs are kept on top of the closed bound, and every                  over-bound entry removed was a closed one"
            );
        }

        assert_eq!(
            counters.counters(live),
            Some(LaunchProofCounters {
                consultations: 1,
                upstream_established: 0,
                probes: 0,
                unauthenticated: 0,
            }),
            "the surviving window still holds the live launch's traffic"
        );
    }

    /// The bound holds through ordinary open/close cycles: closed epochs are
    /// pruned oldest-first, so a long-lived listener cannot grow without limit.
    #[test]
    fn the_epoch_registry_stays_bounded_as_launches_close() {
        let counters = LaunchCounters::new();
        let mut last = 0;
        for _ in 0..(MAX_REMEMBERED_EPOCHS * 3) {
            last = counters
                .begin_epoch()
                .expect("sequential launches never overlap");
            counters.note_consultation();
            assert!(counters.close_epoch(last));
        }
        assert_eq!(
            counters.remembered_epochs(),
            MAX_REMEMBERED_EPOCHS,
            "the map must not grow with the number of launches"
        );
        assert_eq!(
            counters.counters(last),
            Some(LaunchProofCounters {
                consultations: 1,
                upstream_established: 0,
                probes: 0,
                unauthenticated: 0,
            }),
            "the newest window is still readable"
        );
        assert_eq!(
            counters.counters(1),
            None,
            "the oldest closed window was evicted"
        );
    }

    // ---- P1 wave 2: absolute-form parsing and head rewriting --------------

    #[test]
    fn absolute_targets_split_into_host_port_and_origin_form() {
        let http = |target: &str| match parse_absolute_target(target) {
            AbsoluteTarget::Forward(f) => f,
            other => panic!("{target} should forward, got {other:?}"),
        };
        assert_eq!(
            http("http://origin.example/a?b=1"),
            ForwardTarget {
                host: "origin.example".into(),
                port: 80,
                origin_form: "/a?b=1".into(),
            }
        );
        assert_eq!(
            http("HTTP://Origin.Example:8080"),
            ForwardTarget {
                host: "Origin.Example".into(),
                port: 8080,
                origin_form: "/".into(),
            },
            "no path means /, and the scheme is case-insensitive"
        );
        assert_eq!(
            http("http://[::1]:9000/x").origin_form,
            "/x",
            "a bracketed IPv6 authority is split without its brackets"
        );
        assert_eq!(
            http("http://user:secret@origin.example:81/p"),
            ForwardTarget {
                host: "origin.example".into(),
                port: 81,
                origin_form: "/p".into(),
            },
            "userinfo is dropped, never forwarded"
        );
        assert_eq!(http("http://origin.example?q=1").origin_form, "/?q=1");

        assert_eq!(
            parse_absolute_target("https://origin.example/"),
            AbsoluteTarget::HttpsNeedsConnect,
            "absolute-form https needs CONNECT and must be refused, not downgraded"
        );
        for bad in [
            "ftp://origin.example/",
            "http://",
            "http://:80/",
            "http://origin.example:0/",
            "http://origin.example:notaport/",
            "http://[::1/",
            "http://::1/",
            "/origin-form",
        ] {
            assert_eq!(
                parse_absolute_target(bad),
                AbsoluteTarget::Malformed,
                "{bad} must not be forwardable"
            );
        }
    }

    /// One authenticated absolute-form request: request line, our credential,
    /// `extra` fields (CRLF-terminated), the empty line, then `body`.
    fn fwd_req(method: &str, target: &str, extra: &str, body: &str) -> String {
        let c = crlf();
        let auth = auth_header();
        format!("{method} {target} HTTP/1.1{c}{auth}{extra}{c}{body}")
    }

    #[test]
    fn rewrite_head_makes_it_origin_form_and_drops_connection_scoped_headers() {
        let head = concat!(
            "GET http://origin.example:8080/a?b=1 HTTP/1.1\r\n",
            "Host: origin.example:8080\r\n",
            "Proxy-Authorization: Basic \"***\"\r\n",
            "Proxy-Connection: keep-alive\r\n",
            "Connection: keep-alive\r\n",
            "X-Keep: yes\r\n",
            "\r\n",
        );
        let rewritten = rewrite_head_for_upstream(head, "/a?b=1", "origin.example:8080");
        assert_eq!(
            rewritten,
            concat!(
                "GET /a?b=1 HTTP/1.1\r\n",
                "Host: origin.example:8080\r\n",
                "X-Keep: yes\r\n",
                "Connection: close\r\n\r\n",
            ),
            "origin-form target, no proxy credential, no client connection headers"
        );
        // The method and version survive; only the target changes.
        let post = "POST http://o/x HTTP/1.1\r\nHost: o\r\n\r\n";
        assert!(
            rewrite_head_for_upstream(post, "/x", "o").starts_with("POST /x HTTP/1.1\r\n"),
            "method and version must be preserved"
        );
    }

    /// Admission decides on the request-target authority, so that authority — and
    /// nothing the client put in a header — is the `Host` the origin sees.
    #[test]
    fn rewrite_head_rebuilds_the_host_from_the_admitted_authority() {
        let head = concat!(
            "GET http://allowlisted.example/ HTTP/1.1\r\n",
            "Host: victim.internal\r\n",
            "\r\n",
        );
        let rewritten = rewrite_head_for_upstream(head, "/", "allowlisted.example");
        assert!(
            rewritten.contains("\r\nHost: allowlisted.example\r\n"),
            "the admitted authority must be the Host: {rewritten:?}"
        );
        assert!(
            !rewritten.contains("victim.internal"),
            "the client's Host must never reach the origin: {rewritten:?}"
        );
        assert_eq!(
            rewritten.matches("Host:").count(),
            1,
            "exactly one Host line: {rewritten:?}"
        );
    }

    #[test]
    fn rewrite_head_supplies_a_host_when_the_client_sent_none() {
        let head = "GET http://origin.example/a HTTP/1.1\r\nX-Keep: yes\r\n\r\n";
        let rewritten = rewrite_head_for_upstream(head, "/a", "origin.example");
        assert!(
            rewritten.contains("\r\nHost: origin.example\r\n"),
            "HTTP/1.1 requires a Host, so an absent one is supplied: {rewritten:?}"
        );
    }

    #[test]
    fn host_value_normalises_the_port_and_brackets_ipv6_literals() {
        let value = |target: &str| match parse_absolute_target(target) {
            AbsoluteTarget::Forward(fwd) => upstream_host_value(&fwd),
            other => panic!("{target} should forward, got {other:?}"),
        };
        assert_eq!(value("http://origin.example/"), "origin.example");
        assert_eq!(
            value("http://origin.example:80/"),
            "origin.example",
            "the default port is omitted"
        );
        assert_eq!(
            value("http://origin.example:8080/"),
            "origin.example:8080",
            "a non-default port is included"
        );
        assert_eq!(
            value("http://[2001:db8::1]/p"),
            "[2001:db8::1]",
            "an IPv6 literal keeps its brackets"
        );
        assert_eq!(
            value("http://[2001:db8::1]:8080/p"),
            "[2001:db8::1]:8080",
            "an IPv6 literal with a port stays bracketed"
        );
    }

    #[test]
    fn rewrite_head_drops_fields_named_in_the_clients_connection_list() {
        // RFC 9110 7.6.1: whatever the client's `Connection:` names is
        // connection-scoped for this hop, even if it is not on our fixed list.
        let head = concat!(
            "GET http://origin.example/x HTTP/1.1\r\n",
            "Host: origin.example\r\n",
            "Connection: keep-alive, X-Secret-Hop\r\n",
            "X-Secret-Hop: leak\r\n",
            "X-Keep: yes\r\n",
            "\r\n",
        );
        let rewritten = rewrite_head_for_upstream(head, "/x", "origin.example");
        assert!(
            !rewritten.to_ascii_lowercase().contains("x-secret-hop"),
            "a Connection-listed field must not be forwarded: {rewritten:?}"
        );
        assert!(
            rewritten.contains("X-Keep: yes\r\n"),
            "an unrelated field survives: {rewritten:?}"
        );
        assert!(
            rewritten.ends_with("Connection: close\r\n\r\n"),
            "the hop is closed explicitly: {rewritten:?}"
        );
    }

    #[test]
    fn rewrite_head_drops_te_trailer_and_proxy_authenticate() {
        // The explicit decisions: `TE` (a client's acceptable codings), `Trailer`
        // (meaningless without chunked, which this path refuses) and
        // `Proxy-Authenticate` (a response field; forwarding it invites a 407)
        // are all dropped, while `Content-Length` — the one framing signal — is
        // forwarded untouched.
        let head = concat!(
            "POST http://origin.example/x HTTP/1.1\r\n",
            "Host: origin.example\r\n",
            "TE: trailers\r\n",
            "Trailer: X-Checksum\r\n",
            "Proxy-Authenticate: Basic realm=\"x\"\r\n",
            "Content-Length: 2\r\n",
            "\r\n",
        );
        let rewritten = rewrite_head_for_upstream(head, "/x", "origin.example");
        let lower = rewritten.to_ascii_lowercase();
        for gone in ["te:", "trailer:", "proxy-authenticate"] {
            assert!(
                !lower.contains(gone),
                "{gone} survived the rewrite: {rewritten:?}"
            );
        }
        assert!(
            rewritten.contains("Content-Length: 2\r\n"),
            "the framing signal is forwarded: {rewritten:?}"
        );
    }

    /// The target is chosen by the sandboxed child, so a byte offset inside a
    /// multi-byte character must be a verdict, never a panic.
    #[test]
    fn parse_absolute_target_is_utf8_safe_at_the_scheme_boundary() {
        for target in ["abcd😀://x", "http:/😀x"] {
            assert_eq!(
                parse_absolute_target(target),
                AbsoluteTarget::Malformed,
                "{target:?} must be refused, not panic"
            );
        }
    }

    #[test]
    fn bare_lf_and_obs_fold_are_framing_errors() {
        assert_eq!(
            head_framing_error("GET http://o/x HTTP/1.1\r\n\r\n"),
            None,
            "a plain CRLF head is fine"
        );
        assert_eq!(
            head_framing_error("GET http://o/x HTTP/1.1\nX: y\r\n\r\n"),
            Some("bare LF in the request head")
        );
        assert_eq!(
            head_framing_error("GET http://o/x HTTP/1.1\r\nX: y\r\n z\r\n\r\n"),
            Some("obs-fold line in the request head")
        );
        assert_eq!(
            head_framing_error("GET http://o/x HTTP/1.1\r\nX: y"),
            Some("request head is not CRLF-terminated")
        );
    }

    /// The exact split the framing rule closes: one CRLF field to the rewriter,
    /// three to the LF-aware auth gate and request-line parse.
    #[test]
    fn bare_lf_in_the_head_is_a_400_and_never_reaches_admission() {
        let (dialog, calls) = recording_dialog(Ok(allow_once()));
        let t = t36_setup("bare-lf", &["origin.example"], &[], dialog);
        let smuggled = "X-Hop: a\nConnection: upgrade\nUpgrade: h2c\r\n";
        let resp = exchange(
            t.port,
            &fwd_req("GET", "http://origin.example/x", smuggled, ""),
        );
        assert!(resp.starts_with("HTTP/1.1 400"), "got: {resp}");
        assert!(
            resp.contains("bare LF"),
            "the reason must name the framing fault: {resp}"
        );
        assert!(
            calls.lock().unwrap().is_empty(),
            "a framing refusal is not a policy question"
        );
        assert!(
            connect_events(&t.sid).is_empty(),
            "and it is not a consultation either: {:?}",
            connect_events(&t.sid)
        );
    }

    #[test]
    fn forward_body_framing_accepts_exactly_one_content_length() {
        let head = |fields: &str| format!("POST http://o/x HTTP/1.1{c}{fields}{c}{c}", c = crlf());
        assert_eq!(forward_body_framing(&head("")), Ok(ForwardBody::None));
        assert_eq!(
            forward_body_framing(&head("Content-Length: 7\r\n")),
            Ok(ForwardBody::Length(7))
        );
        assert_eq!(
            forward_body_framing(&head("Content-Length: 7\r\nContent-Length: 7\r\n")),
            Ok(ForwardBody::Length(7)),
            "repeated but identical values are one signal"
        );
        assert_eq!(
            forward_body_framing(&head("Content-Length: 7, 7\r\n")),
            Ok(ForwardBody::Length(7)),
            "a repeated list of identical values is one signal"
        );
        assert_eq!(
            forward_body_framing(&head("content-length: 7\r\nContent-Length: 8\r\n")),
            Err(BodyReject::ConflictingContentLength),
            "two different body lengths must never be resolved by preference"
        );
        assert_eq!(
            forward_body_framing(&head("Content-Length: seven\r\n")),
            Err(BodyReject::BadContentLength)
        );
        assert_eq!(
            forward_body_framing(&head("Content-Length: +5\r\n")),
            Err(BodyReject::BadContentLength),
            "a leading '+' is accepted by Rust's usize parser but is not a decimal number to every origin (RFC 9110 8.6: 1*DIGIT)"
        );
        assert_eq!(
            forward_body_framing(&head("Content-Length: \r\n")),
            Err(BodyReject::BadContentLength),
            "an empty value frames nothing and must not be read as zero"
        );
        assert_eq!(
            forward_body_framing(&head("Content-Length: 0x5\r\n")),
            Err(BodyReject::BadContentLength)
        );
        assert_eq!(
            forward_body_framing(&head("Content-Length:  5 \r\n")),
            Ok(ForwardBody::Length(5)),
            "surrounding OWS is legal and keeps the field decimal"
        );
        assert_eq!(
            forward_body_framing(&head("Transfer-Encoding: chunked\r\n")),
            Err(BodyReject::TransferEncoding)
        );
        assert_eq!(
            forward_body_framing(&head("Transfer-Encoding: identity\r\n")),
            Err(BodyReject::TransferEncoding),
            "any Transfer-Encoding, not only chunked"
        );
    }

    #[test]
    fn transfer_encoding_is_a_400_and_reaches_no_origin() {
        let origin = FakeOrigin::start("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
        let (dialog, _c) = recording_dialog(Ok(allow_once()));
        let t = t36_setup("fwd-te", &[origin.host.as_str()], &[], dialog);
        let extra = "Transfer-Encoding: chunked\r\n";
        let resp = exchange(
            t.port,
            &fwd_req(
                "POST",
                &format!("http://{}/x", origin.authority()),
                extra,
                "0\r\n\r\n",
            ),
        );
        assert!(resp.starts_with("HTTP/1.1 400"), "got: {resp}");
        assert!(
            resp.contains("Transfer-Encoding is not accepted on this path"),
            "Transfer-Encoding cannot be re-framed safely, so it is refused: {resp}"
        );
        assert!(
            origin.requests().is_empty(),
            "nothing may be forwarded: {:?}",
            origin.requests()
        );
    }

    #[test]
    fn conflicting_content_length_is_a_400_and_reaches_no_origin() {
        let origin = FakeOrigin::start("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
        let (dialog, _c) = recording_dialog(Ok(allow_once()));
        let t = t36_setup("fwd-cl", &[origin.host.as_str()], &[], dialog);
        let extra = "Content-Length: 5\r\nContent-Length: 6\r\n";
        let resp = exchange(
            t.port,
            &fwd_req(
                "POST",
                &format!("http://{}/x", origin.authority()),
                extra,
                "hello",
            ),
        );
        assert!(resp.starts_with("HTTP/1.1 400"), "got: {resp}");
        assert!(
            resp.contains("conflicting Content-Length"),
            "the reason must name the conflict: {resp}"
        );
        assert!(
            origin.requests().is_empty(),
            "nothing may be forwarded: {:?}",
            origin.requests()
        );
    }

    /// Exactly one request per client connection: a body followed by a second,
    /// unadmitted request is a 400 and the trailing bytes are never relayed.
    #[test]
    fn body_followed_by_trailing_bytes_is_a_400_and_nothing_is_forwarded() {
        let origin = FakeOrigin::start("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
        let (dialog, _c) = recording_dialog(Ok(allow_once()));
        let t = t36_setup("fwd-trailing", &[origin.host.as_str()], &[], dialog);
        let smuggled = "GET http://origin.example/second HTTP/1.1\r\nHost: origin.example\r\n\r\n";
        let resp = exchange(
            t.port,
            &fwd_req(
                "POST",
                &format!("http://{}/upload", origin.authority()),
                "Content-Length: 5\r\n",
                &format!("hello{smuggled}"),
            ),
        );
        assert!(resp.starts_with("HTTP/1.1 400"), "got: {resp}");
        assert!(
            resp.contains("one request per connection"),
            "the reason must name the rule: {resp}"
        );
        assert!(
            origin.requests().is_empty(),
            "neither the request nor the smuggled second one may be forwarded: {:?}",
            origin.requests()
        );
    }

    #[test]
    fn post_body_is_forwarded_byte_exact_with_the_admitted_host() {
        let origin = FakeOrigin::start("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
        let (dialog, _c) = recording_dialog(Ok(allow_once()));
        let t = t36_setup("fwd-post", &[origin.host.as_str()], &[], dialog);
        let body = "{\"hello\":\"world\"}";
        let authority = origin.authority();
        let extra = format!(
            "Host: victim.internal\r\nContent-Length: {}\r\nContent-Type: application/json\r\n",
            body.len()
        );
        let resp = exchange(
            t.port,
            &fwd_req(
                "POST",
                &format!("http://{authority}/upload?x=1"),
                &extra,
                body,
            ),
        );
        assert!(resp.starts_with("HTTP/1.1 200"), "got: {resp}");
        assert!(
            resp.ends_with("ok"),
            "the origin's body must be relayed: {resp}"
        );

        let seen = origin.requests();
        assert_eq!(seen.len(), 1, "exactly one request: {seen:?}");
        let raw = &seen[0];
        assert!(
            raw.starts_with("POST /upload?x=1 HTTP/1.1\r\n"),
            "the origin sees an origin-form target: {raw:?}"
        );
        assert!(
            raw.contains(&format!("\r\nHost: {authority}\r\n")),
            "the Host is the admitted authority, not the client's: {raw:?}"
        );
        assert!(
            !raw.contains("victim.internal"),
            "the client's Host never reaches the origin: {raw:?}"
        );
        assert!(
            raw.ends_with(&format!("\r\n\r\n{body}")),
            "the body must arrive byte-exact: {raw:?}"
        );
    }

    /// An origin must not be able to answer a *proxy* challenge: an honest client
    /// would replay our session token to it.
    #[test]
    fn origin_407_is_rewritten_to_502_and_the_challenge_is_withheld() {
        let origin = FakeOrigin::start(concat!(
            "HTTP/1.1 407 Proxy Authentication Required\r\n",
            "Proxy-Authenticate: Basic realm=\"origin\"\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        ));
        let (dialog, _c) = recording_dialog(Ok(allow_once()));
        let t = t36_setup("fwd-407", &[origin.host.as_str()], &[], dialog);
        let resp = exchange(
            t.port,
            &fwd_req("GET", &format!("http://{}/x", origin.authority()), "", ""),
        );
        assert!(
            resp.starts_with("HTTP/1.1 502"),
            "an origin 407 must be a 502 to the client: {resp}"
        );
        assert!(
            !resp.contains("Proxy-Authenticate"),
            "the challenge must never reach the client: {resp}"
        );
        assert!(
            !resp.contains("407"),
            "not even the status may be echoed: {resp}"
        );
        assert!(
            resp.contains("X-Sandbox: origin-challenge"),
            "the rewrite is marked for the operator: {resp}"
        );
    }

    // =================================================================
    // Round 3 — the forward path accepts only boring requests and responses
    // =================================================================

    #[test]
    fn field_names_must_be_rfc9110_tokens() {
        assert_eq!(
            head_field_syntax_error("GET http://o/x HTTP/1.1\r\n\r\n"),
            None
        );
        assert_eq!(
            head_field_syntax_error("POST http://o/x HTTP/1.1\r\nContent-Length: 5\r\n\r\n"),
            None,
            "a well-formed framing field is accepted"
        );
        assert_eq!(
            head_field_syntax_error("POST http://o/x HTTP/1.1\r\nContent-Length : 5\r\n\r\n"),
            Some("whitespace in a field name"),
            "a space before the colon is a different name to a strict origin"
        );
        assert_eq!(
            head_field_syntax_error("POST http://o/x HTTP/1.1\r\nX Y: z\r\n\r\n"),
            Some("whitespace in a field name")
        );
        assert_eq!(
            head_field_syntax_error("POST http://o/x HTTP/1.1\r\n: v\r\n\r\n"),
            Some("empty field name in the request head")
        );
        assert_eq!(
            head_field_syntax_error("POST http://o/x HTTP/1.1\r\nnot-a-field\r\n\r\n"),
            Some("header line without a field name"),
            "a line with no colon is not a field this proxy may forward"
        );
    }

    #[test]
    fn connection_may_not_name_a_framing_field() {
        let head = |value: &str| format!("POST http://o/x HTTP/1.1\r\nConnection: {value}\r\n\r\n");
        assert_eq!(connection_listed_framing_field(&head("close")), None);
        assert_eq!(
            connection_listed_framing_field(&head("keep-alive, X-Secret-Hop")),
            None,
            "an ordinary hop-by-hop list is still dropped, not refused"
        );
        assert_eq!(
            connection_listed_framing_field(&head("Content-Length")),
            Some("content-length"),
            "naming the framing field would strip it"
        );
        assert_eq!(connection_listed_framing_field(&head("Host")), Some("host"));
        assert_eq!(
            connection_listed_framing_field(&head("keep-alive, Transfer-Encoding")),
            Some("transfer-encoding")
        );
        assert_eq!(
            connection_listed_framing_field(&head("connection")),
            Some("connection")
        );
    }

    #[test]
    fn expect_is_detected_whatever_its_value() {
        let head = |fields: &str| format!("POST http://o/x HTTP/1.1\r\n{fields}\r\n");
        assert!(
            !has_expect_field(&head("X-Expect-Thing: 1\r\n")),
            "only the field named Expect counts"
        );
        assert!(has_expect_field(&head("Expect: 100-continue\r\n")));
        assert!(
            has_expect_field(&head("expect:\r\n")),
            "presence decides, not the value"
        );
    }

    #[test]
    fn upstream_status_line_must_be_a_strict_http1_status() {
        assert_eq!(parse_upstream_status_line("HTTP/1.1 200 OK"), Some(200));
        assert_eq!(parse_upstream_status_line("HTTP/1.1 404"), Some(404));
        assert_eq!(
            parse_upstream_status_line("HTTP/1.1 103 Early Hints"),
            Some(103),
            "an interim status parses — the caller is what refuses it"
        );
        assert_eq!(
            parse_upstream_status_line("HTTP/1.0 500 Internal Server Error"),
            Some(500)
        );
        for bad in [
            "",
            " 200 OK",
            "HTTP/1.1  200 OK",
            "HTTP/2 200 OK",
            "http/1.1 200 OK",
            "HTTP/1.1 20 OK",
            "HTTP/1.1 2000 OK",
            "HTTP/1.1",
            "HTTP/1.1 abc OK",
            "ICY 200 OK",
        ] {
            assert_eq!(
                parse_upstream_status_line(bad),
                None,
                "{bad:?} must not yield a status"
            );
        }
    }

    #[test]
    fn relayed_response_head_carries_exactly_one_connection_close() {
        // No `Connection` from the origin: exactly one is added, and the rest of
        // the head — framing fields included — is relayed byte for byte.
        let relayed = relayed_response_head(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
        assert_eq!(
            String::from_utf8(relayed).unwrap(),
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
        );

        // `keep-alive` is replaced, not appended to.
        let relayed = relayed_response_head(
            b"HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Length: 2\r\n\r\nok",
        );
        let head = String::from_utf8(relayed).unwrap();
        let lower = head.to_ascii_lowercase();
        assert_eq!(lower.matches("connection:").count(), 1, "{head:?}");
        assert!(head.contains("Connection: close"), "{head:?}");
        assert!(!lower.contains("keep-alive"), "{head:?}");
        assert!(
            head.ends_with("\r\n\r\nok"),
            "the body prefix survives: {head:?}"
        );

        // Two origin fields, in any spelling, collapse to one.
        let relayed = relayed_response_head(
            b"HTTP/1.1 204 No Content\r\nconnection: close\r\nCONNECTION: keep-alive\r\n\r\n",
        );
        let head = String::from_utf8(relayed).unwrap();
        assert_eq!(lower_count(&head), 1, "{head:?}");
        assert!(head.starts_with("HTTP/1.1 204 No Content\r\n"), "{head:?}");
    }

    fn lower_count(head: &str) -> usize {
        head.to_ascii_lowercase().matches("connection:").count()
    }

    async fn classify_upstream(raw: &[u8]) -> UpstreamHead {
        let (mut client, mut feed) = tokio::io::duplex(256);
        let raw = raw.to_vec();
        let writer = tokio::spawn(async move {
            feed.write_all(&raw).await.unwrap();
        });
        let head = read_upstream_head(&mut client)
            .await
            .expect("a non-empty reply is classified");
        writer.await.unwrap();
        head
    }

    /// The classification the relay depends on, independent of the wire tests:
    /// only a final `HTTP/1.x` response with a defined status is relayed.
    #[tokio::test]
    async fn read_upstream_head_only_accepts_a_final_http1_response() {
        assert!(matches!(
            classify_upstream(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").await,
            UpstreamHead::Final { status: 200, .. }
        ));
        assert_eq!(
            classify_upstream(b"HTTP/1.1 103 Early Hints\r\nLink: </x>\r\n\r\n").await,
            UpstreamHead::Interim,
            "an interim head is never an answer"
        );
        assert_eq!(
            classify_upstream(b"\r\nHTTP/1.1 407 Proxy Authentication Required\r\n\r\n").await,
            UpstreamHead::StatusUnparsable,
            "a leading CRLF leaves no first line to read a status from"
        );
        assert_eq!(
            classify_upstream(b"HTTP/2 200 OK\r\n\r\n").await,
            UpstreamHead::StatusUnparsable,
            "only HTTP/1.x is spoken here"
        );
        assert_eq!(
            classify_upstream(b"HTTP/1.1 200").await,
            UpstreamHead::StatusUnparsable,
            "an incomplete head is not vouched for"
        );
    }

    /// BLOCKER 1: an interim head is not an answer. `103` followed by `407` used
    /// to be relayed verbatim — an interim header block standing in for a status
    /// the client never received, with the challenge in it.
    #[test]
    fn interim_103_then_407_never_reaches_the_client() {
        let origin = FakeOrigin::start(concat!(
            "HTTP/1.1 103 Early Hints\r\n",
            "Link: </style.css>; rel=preload\r\n",
            "\r\n",
            "HTTP/1.1 407 Proxy Authentication Required\r\n",
            "Proxy-Authenticate: Basic realm=\"origin\"\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        ));
        let (dialog, _c) = recording_dialog(Ok(allow_once()));
        let t = t36_setup("fwd-103", &[origin.host.as_str()], &[], dialog);
        let resp = exchange(
            t.port,
            &fwd_req("GET", &format!("http://{}/x", origin.authority()), "", ""),
        );
        assert!(
            resp.starts_with("HTTP/1.1 502"),
            "an interim head must not be relayed: {resp}"
        );
        assert!(
            resp.contains("X-Sandbox: interim-response-unsupported"),
            "the refusal is named: {resp}"
        );
        assert!(!resp.contains("Proxy-Authenticate"), "no challenge: {resp}");
        assert!(!resp.contains("407"), "not even the status: {resp}");
        assert!(
            !resp.contains("Early Hints") && !resp.contains("rel=preload"),
            "not one byte of the interim head: {resp}"
        );
        assert_eq!(
            origin.requests().len(),
            1,
            "the request itself was admitted and sent"
        );
    }

    /// BLOCKER 2: a leading CRLF makes the status line empty, so the status check
    /// read `0` and the 407 behind it reached the client.
    #[test]
    fn response_starting_with_crlf_is_refused_and_the_challenge_withheld() {
        let origin = FakeOrigin::start(concat!(
            "\r\n",
            "HTTP/1.1 407 Proxy Authentication Required\r\n",
            "Proxy-Authenticate: Basic realm=\"origin\"\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        ));
        let (dialog, _c) = recording_dialog(Ok(allow_once()));
        let t = t36_setup("fwd-crlf", &[origin.host.as_str()], &[], dialog);
        let resp = exchange(
            t.port,
            &fwd_req("GET", &format!("http://{}/x", origin.authority()), "", ""),
        );
        assert!(
            resp.starts_with("HTTP/1.1 502"),
            "an unparsable head must be refused: {resp}"
        );
        assert!(
            resp.contains("X-Sandbox: origin-status-unparsable"),
            "the refusal is named: {resp}"
        );
        assert!(!resp.contains("Proxy-Authenticate"), "no challenge: {resp}");
        assert!(!resp.contains("407"), "not even the status: {resp}");
    }

    /// BLOCKER 3: `Connection` naming a framing field asks the rewrite to strip
    /// it, which relays the body to the origin as a second, unadmitted request
    /// carrying the client's own `Host`.
    #[test]
    fn connection_naming_a_framing_field_is_a_400_and_reaches_no_origin() {
        let origin = FakeOrigin::start("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
        let (dialog, calls) = recording_dialog(Ok(allow_once()));
        let t = t36_setup("fwd-conn-framing", &[origin.host.as_str()], &[], dialog);
        let smuggled =
            "GET http://victim.internal/second HTTP/1.1\r\nHost: victim.internal\r\n\r\n";
        for (listed, token) in [
            ("Content-Length", "content-length"),
            ("Host", "host"),
            ("Transfer-Encoding", "transfer-encoding"),
            ("connection", "connection"),
        ] {
            let extra = format!(
                "Connection: {listed}\r\nContent-Length: {}\r\n",
                smuggled.len()
            );
            let resp = exchange(
                t.port,
                &fwd_req(
                    "POST",
                    &format!("http://{}/x", origin.authority()),
                    &extra,
                    smuggled,
                ),
            );
            assert!(resp.starts_with("HTTP/1.1 400"), "{listed} -> {resp}");
            assert!(
                resp.contains(&format!("Connection names the framing field `{token}`")),
                "{listed} -> {resp}"
            );
        }
        assert!(
            origin.requests().is_empty(),
            "nothing may be dialled: {:?}",
            origin.requests()
        );
        assert!(
            calls.lock().unwrap().is_empty(),
            "a framing refusal is not a policy question"
        );
        assert!(
            connect_events(&t.sid).is_empty(),
            "and not a consultation either: {:?}",
            connect_events(&t.sid)
        );
    }

    /// DEFECT 4: `Content-Length : 5` is not a field name this proxy may frame
    /// on, while `Content-Length: 5` still is.
    #[test]
    fn whitespace_in_a_field_name_is_a_400_and_a_valid_one_still_forwards() {
        let origin = FakeOrigin::start("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
        let (dialog, calls) = recording_dialog(Ok(allow_once()));
        let t = t36_setup("fwd-field-name", &[origin.host.as_str()], &[], dialog);
        let resp = exchange(
            t.port,
            &fwd_req(
                "POST",
                &format!("http://{}/x", origin.authority()),
                "Content-Length : 5\r\n",
                "hello",
            ),
        );
        assert!(resp.starts_with("HTTP/1.1 400"), "{resp}");
        assert!(
            resp.contains("whitespace in a field name"),
            "the fault is named: {resp}"
        );
        assert!(
            origin.requests().is_empty(),
            "nothing may be dialled: {:?}",
            origin.requests()
        );
        assert!(
            calls.lock().unwrap().is_empty(),
            "a syntax refusal is not a policy question"
        );

        let resp = exchange(
            t.port,
            &fwd_req(
                "POST",
                &format!("http://{}/x", origin.authority()),
                "Content-Length: 5\r\n",
                "hello",
            ),
        );
        assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
        let seen = origin.requests();
        assert_eq!(seen.len(), 1, "exactly one request: {seen:?}");
        assert!(
            seen[0].ends_with("\r\n\r\nhello"),
            "the body arrives byte-exact: {:?}",
            seen[0]
        );
    }

    /// REGRESSION 5: `Expect` is refused before admission — the behaviour chosen
    /// over stripping it and answering `100 Continue` ourselves.
    #[test]
    fn expect_header_is_refused_before_admission() {
        let origin = FakeOrigin::start("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
        let (dialog, calls) = recording_dialog(Ok(allow_once()));
        let t = t36_setup("fwd-expect", &[origin.host.as_str()], &[], dialog);
        let resp = exchange(
            t.port,
            &fwd_req(
                "POST",
                &format!("http://{}/x", origin.authority()),
                "Expect: 100-continue\r\nContent-Length: 5\r\n",
                "hello",
            ),
        );
        assert!(resp.starts_with("HTTP/1.1 400"), "{resp}");
        assert!(
            resp.contains("X-Sandbox: expect-unsupported"),
            "the refusal is named: {resp}"
        );
        assert!(
            origin.requests().is_empty(),
            "nothing may be dialled: {:?}",
            origin.requests()
        );
        assert!(calls.lock().unwrap().is_empty(), "refused before admission");
        assert!(
            connect_events(&t.sid).is_empty(),
            "and not counted: {:?}",
            connect_events(&t.sid)
        );
    }

    /// REGRESSION 6: the listener closes the client socket after every forward, so
    /// the relayed head must say `Connection: close` exactly once — a client that
    /// honoured the origin's `keep-alive` would reuse a dead connection.
    #[test]
    fn relayed_response_tells_the_client_the_connection_closes() {
        let origin = FakeOrigin::start(concat!(
            "HTTP/1.1 200 OK\r\n",
            "Connection: keep-alive\r\n",
            "Content-Length: 2\r\n",
            "\r\n",
            "ok",
        ));
        let (dialog, _c) = recording_dialog(Ok(allow_once()));
        let t = t36_setup("fwd-close", &[origin.host.as_str()], &[], dialog);
        let resp = exchange(
            t.port,
            &fwd_req("GET", &format!("http://{}/x", origin.authority()), "", ""),
        );
        assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
        assert_eq!(
            lower_count(&resp),
            1,
            "exactly one Connection field: {resp}"
        );
        assert!(resp.contains("Connection: close"), "{resp}");
        assert!(
            !resp.to_ascii_lowercase().contains("keep-alive"),
            "the origin's keep-alive must not survive: {resp}"
        );
        assert!(resp.ends_with("ok"), "the body is relayed: {resp}");
    }

    #[tokio::test]
    async fn relay_forwards_exactly_the_framed_body() {
        let (mut client, mut client_feed) = tokio::io::duplex(64);
        let (mut upstream_sink, mut upstream_check) = tokio::io::duplex(64);
        let feed = tokio::spawn(async move {
            client_feed.write_all(b"llo world").await.unwrap();
        });
        relay_framed_body(&mut client, &mut upstream_sink, b"he", 11)
            .await
            .expect("the framed body must be forwarded");
        drop(upstream_sink);
        let mut got = Vec::new();
        upstream_check.read_to_end(&mut got).await.unwrap();
        feed.await.unwrap();
        assert_eq!(got, b"hello world");
    }

    #[tokio::test]
    async fn relay_rejects_leftover_beyond_the_framed_body() {
        let (mut client, _feed) = tokio::io::duplex(64);
        let (mut upstream_sink, _check) = tokio::io::duplex(64);
        assert_eq!(
            relay_framed_body(&mut client, &mut upstream_sink, b"helloGET /x HTTP/1.1", 5).await,
            Err(BodyRelayError::Trailing),
            "bytes past the framed body are a second request, never relayed"
        );
    }

    /// The host's non-loopback IPv4: the forward path refuses loopback targets by
    /// design, so a forwardable origin has to live on a real interface.
    fn route_ipv4() -> std::net::Ipv4Addr {
        let probe = std::net::UdpSocket::bind("0.0.0.0:0").expect("route probe socket");
        probe.connect("1.1.1.1:80").expect("route probe");
        match probe.local_addr().expect("route probe address").ip() {
            std::net::IpAddr::V4(v4) if !v4.is_loopback() => v4,
            other => panic!("this host has no non-loopback IPv4 (probe {other})"),
        }
    }

    /// A local origin the forward path can actually reach, recording the exact
    /// bytes of every request it is sent and answering with a canned response.
    struct FakeOrigin {
        host: String,
        port: u16,
        seen: Arc<StdMutex<Vec<Vec<u8>>>>,
        stop: Arc<std::sync::atomic::AtomicBool>,
        join: Option<std::thread::JoinHandle<()>>,
    }

    impl FakeOrigin {
        fn start(response: &str) -> FakeOrigin {
            use std::io::Write;
            use std::sync::atomic::Ordering;
            let ip = route_ipv4();
            let listener = std::net::TcpListener::bind((ip, 0)).expect("bind fake origin");
            let port = listener.local_addr().unwrap().port();
            listener.set_nonblocking(true).unwrap();
            let seen = Arc::new(StdMutex::new(Vec::new()));
            let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let seen_t = Arc::clone(&seen);
            let stop_t = Arc::clone(&stop);
            let response = response.to_string();
            let join = std::thread::spawn(move || {
                while !stop_t.load(Ordering::SeqCst) {
                    let Ok((mut s, _)) = listener.accept() else {
                        std::thread::sleep(Duration::from_millis(5));
                        continue;
                    };
                    s.set_nonblocking(false).ok();
                    s.set_read_timeout(Some(Duration::from_secs(5))).ok();
                    if let Some(raw) = read_one_request(&mut s) {
                        seen_t.lock().unwrap().push(raw);
                        let _ = s.write_all(response.as_bytes());
                    }
                    let _ = s.shutdown(std::net::Shutdown::Both);
                }
            });
            FakeOrigin {
                host: ip.to_string(),
                port,
                seen,
                stop,
                join: Some(join),
            }
        }

        fn authority(&self) -> String {
            format!("{}:{}", self.host, self.port)
        }

        /// Every request the origin received, verbatim (head plus framed body).
        fn requests(&self) -> Vec<String> {
            self.seen
                .lock()
                .unwrap()
                .iter()
                .map(|raw| String::from_utf8_lossy(raw).into_owned())
                .collect()
        }
    }

    impl Drop for FakeOrigin {
        fn drop(&mut self) {
            self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
            if let Some(join) = self.join.take() {
                let _ = join.join();
            }
        }
    }

    /// One request (head plus its Content-Length body) as it arrived, or `None`
    /// if the peer closed first. Anything past the head that the client pipelined
    /// is kept, so a smuggled second request would show up here.
    fn read_one_request(s: &mut std::net::TcpStream) -> Option<Vec<u8>> {
        use std::io::Read;
        let mut raw = Vec::new();
        let mut chunk = [0u8; 512];
        while find_head_end(&raw).is_none() {
            match s.read(&mut chunk) {
                Ok(0) | Err(_) => return None,
                Ok(n) => raw.extend_from_slice(&chunk[..n]),
            }
            if raw.len() > 64 * 1024 {
                return None;
            }
        }
        let head_end = find_head_end(&raw).unwrap();
        let head = String::from_utf8_lossy(&raw[..head_end]).into_owned();
        let want = content_length(&head).unwrap_or(0);
        while raw.len() < head_end + want {
            match s.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(n) => raw.extend_from_slice(&chunk[..n]),
            }
        }
        Some(raw)
    }

    #[test]
    fn sandbox_unknown_path_is_404() {
        let (dialog, _c) = recording_dialog(Ok(deny_once_result()));
        let t = t36_setup("sandbox-404", &[], &[], dialog);
        let resp = exchange(t.port, &get_req("/sandbox/other"));
        assert!(resp.starts_with("HTTP/1.1 404"), "got: {resp}");
    }

    #[test]
    fn connect_dns_failure_after_admission_is_fail_closed() {
        let (dialog, calls) = recording_dialog(Ok(allow_once()));
        // `*.invalid` can never resolve (RFC 6761): admission passes via
        // the allow-list, then the pinned resolution fails → fail-closed
        // 403 with an audit event sourced "dns" ([G-12]).
        let t = t36_setup("dns-fail", &["*.invalid"], &[], dialog);
        let resp = exchange(t.port, &connect_req("nx.invalid:443"));
        assert!(resp.starts_with("HTTP/1.1 403"), "got: {resp}");
        assert!(resp.contains("X-Sandbox: denied"), "got: {resp}");
        assert!(calls.lock().unwrap().is_empty());
        let ev = last_connect_event(&t.sid);
        assert_eq!(ev["source"], "dns");
    }

    #[test]
    fn intent_wrong_method_gets_405_with_allow() {
        let (dialog, _c) = recording_dialog(Ok(deny_once_result()));
        let t = t36_setup("intent-405", &[], &[], dialog);
        let resp = exchange(t.port, &http_req("PUT", "/sandbox/intent", false, "{}"));
        assert!(resp.starts_with("HTTP/1.1 405"), "got: {resp}");
        assert!(resp.contains("Allow: GET, POST"), "got: {resp}");
        let resp = exchange(t.port, &get_req("/sandbox/intent/explain"));
        assert!(resp.starts_with("HTTP/1.1 405"), "got: {resp}");
        assert!(resp.contains("Allow: POST"), "got: {resp}");
    }

    // =================================================================
    // Task 4.2 — upstream chaining (D-2): [G-10, G-22, G-30, G-49]
    // =================================================================

    /// Read one HTTP head (through CRLFCRLF) a byte at a time, so no byte
    /// of a following tunnel is consumed.
    fn read_head(s: &mut std::net::TcpStream) -> String {
        use std::io::Read;
        let mut out: Vec<u8> = Vec::new();
        let mut b = [0u8; 1];
        loop {
            match s.read(&mut b) {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    out.push(b[0]);
                    if out.ends_with(b"\r\n\r\n") || out.len() >= 8192 {
                        break;
                    }
                }
            }
        }
        String::from_utf8_lossy(&out).into_owned()
    }

    /// A fake upstream proxy: answers each CONNECT head with `status` (200 =
    /// established + echoing tunnel; anything else = refused CONNECT) and
    /// records every head it saw. The accept loop is non-blocking behind a
    /// stop flag so the thread never outlives the test.
    struct FakeUpstream {
        port: u16,
        seen: Arc<StdMutex<Vec<String>>>,
        stop: Arc<std::sync::atomic::AtomicBool>,
        join: Option<std::thread::JoinHandle<()>>,
    }

    impl FakeUpstream {
        fn start(status: u16) -> FakeUpstream {
            use std::io::{Read, Write};
            use std::sync::atomic::Ordering;
            let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind fake upstream");
            let port = l.local_addr().unwrap().port();
            l.set_nonblocking(true).unwrap();
            let seen = Arc::new(StdMutex::new(Vec::new()));
            let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let seen_t = Arc::clone(&seen);
            let stop_t = Arc::clone(&stop);
            let join = std::thread::spawn(move || {
                while !stop_t.load(Ordering::SeqCst) {
                    let Ok((mut s, _)) = l.accept() else {
                        std::thread::sleep(Duration::from_millis(5));
                        continue;
                    };
                    // Windows hands back an accepted socket in the
                    // listener's non-blocking mode; the echo loop needs
                    // blocking reads.
                    s.set_nonblocking(false).ok();
                    s.set_read_timeout(Some(Duration::from_secs(10))).ok();
                    let head = read_head(&mut s);
                    if head.is_empty() {
                        continue;
                    }
                    seen_t.lock().unwrap().push(head);
                    let resp = if status == 200 {
                        "HTTP/1.1 200 Connection Established\r\n\r\n"
                    } else {
                        "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"
                    };
                    if s.write_all(resp.as_bytes()).is_err() || status != 200 {
                        continue;
                    }
                    // Echo the tunnel until the peer closes it.
                    let mut buf = [0u8; 4096];
                    loop {
                        match s.read(&mut buf) {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if s.write_all(&buf[..n]).is_err() {
                                    break;
                                }
                            }
                        }
                    }
                }
            });
            FakeUpstream {
                port,
                seen,
                stop,
                join: Some(join),
            }
        }

        /// `http://127.0.0.1:<port>` — no credentials.
        fn url(&self) -> String {
            format!("http://127.0.0.1:{}", self.port)
        }

        /// The same endpoint with userinfo, for the [G-30] redaction tests.
        fn cred_url(&self) -> String {
            format!("http://alice:s3cret@127.0.0.1:{}", self.port)
        }

        fn heads(&self) -> Vec<String> {
            self.seen.lock().unwrap().clone()
        }
    }

    impl Drop for FakeUpstream {
        fn drop(&mut self) {
            self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
            if let Some(j) = self.join.take() {
                let _ = j.join();
            }
        }
    }

    /// CONNECT through the test proxy; on a 2xx head send `payload` through
    /// the tunnel and read the echo back. Returns `(head, echo)` — `echo` is
    /// empty when the proxy did not establish a tunnel.
    fn tunnel(port: u16, target: &str, payload: &[u8]) -> (String, String) {
        use std::io::{Read, Write};
        let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).expect("connect test proxy");
        s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        s.set_write_timeout(Some(Duration::from_secs(10))).unwrap();
        s.write_all(connect_req(target).as_bytes()).unwrap();
        let head = read_head(&mut s);
        if !head.starts_with("HTTP/1.1 2") {
            return (head, String::new());
        }
        s.write_all(payload).unwrap();
        let mut echo = vec![0u8; payload.len()];
        s.read_exact(&mut echo).expect("tunnel echo");
        (head, String::from_utf8_lossy(&echo).into_owned())
    }

    /// A chaining dialer over `url` with the given `NO_PROXY` entries.
    fn dialer(url: &str, no_proxy: &[&str]) -> Arc<UpstreamDialer> {
        Arc::new(
            UpstreamDialer::from_url(url, no_proxy.iter().map(|s| s.to_string()).collect())
                .expect("test upstream url parses"),
        )
    }

    /// A loopback port nothing listens on: 1 is reserved for tcpmux and never
    /// bound by the toolchain, so `connect` is refused at once — no
    /// bind-then-drop TOCTOU window (a race that could hand the port to
    /// something else between `drop` and the dial).
    const DEAD_PORT: u16 = 1;

    /// The 3.6 fixture with an optional upstream dialer.
    fn t42_setup(label: &str, allow: &[&str], upstream: Option<Arc<UpstreamDialer>>) -> T36 {
        let (dialog, _calls) = recording_dialog(Ok(deny_once_result()));
        t36_setup_cfg(
            label,
            allow,
            &[],
            dialog,
            true,
            Duration::from_secs(60),
            PromptPolicy::Deny,
            upstream,
        )
    }

    // (a) admission → chained CONNECT → the tunnel round-trips.
    #[test]
    fn chained_connect_tunnels_through_upstream_proxy() {
        let fake = FakeUpstream::start(200);
        let t = t42_setup(
            "chain-ok",
            &["api.example.com"],
            Some(dialer(&fake.cred_url(), &[])),
        );
        let (head, echo) = tunnel(t.port, "api.example.com:443", b"hello through the tunnel");
        assert!(head.starts_with("HTTP/1.1 200"), "got: {head}");
        assert_eq!(echo, "hello through the tunnel");

        let heads = fake.heads();
        assert_eq!(heads.len(), 1, "exactly one upstream CONNECT");
        assert!(
            heads[0].starts_with("CONNECT api.example.com:443 HTTP/1.1"),
            "request line: {:?}",
            heads[0]
        );
        assert!(
            heads[0]
                .to_ascii_lowercase()
                .contains("host: api.example.com:443"),
            "Host header: {:?}",
            heads[0]
        );
        // Exact value, not a prefix: the header is `Basic base64(user:pass)`,
        // and a prefix-only check would still pass if the userinfo were
        // dropped on the floor.
        let expected = base64::engine::general_purpose::STANDARD.encode("alice:s3cret");
        assert!(
            heads[0].contains(&format!("Proxy-Authorization: Basic {expected}")),
            "auth header: {:?}",
            heads[0]
        );
        // [G-30] the cleartext userinfo never reaches the wire.
        assert!(
            !heads[0].contains("s3cret"),
            "leaked password: {:?}",
            heads[0]
        );

        let ev = last_connect_event(&t.sid);
        assert_eq!(ev["disposition"], "allow");
        assert_eq!(ev["source"], "allowlist");
    }

    // (b) [G-11, G-49] a NO_PROXY match dials direct: the upstream proxy is
    // never contacted. De-flaked per 3.6: the target is unresolvable here, so
    // the direct leg normally ends in the fail-closed 403, but a resolver that
    // hijacks `.invalid` (some captive/ISP resolvers do) turns it into a
    // direct 502. Both are direct-path outcomes; the security property is
    // "nothing chained", so neither may look like an upstream failure.
    #[test]
    fn no_proxy_match_dials_direct_and_never_contacts_upstream() {
        let fake = FakeUpstream::start(200);
        let t = t42_setup(
            "chain-bypass",
            &["bypass.invalid"],
            Some(dialer(&fake.url(), &["bypass.invalid"])),
        );
        let resp = exchange(t.port, &connect_req("bypass.invalid:443"));
        assert!(
            !resp.contains("X-Sandbox: upstream-error"),
            "a NO_PROXY host must never chain: {resp}"
        );
        assert!(
            fake.heads().is_empty(),
            "NO_PROXY host must never reach the upstream proxy"
        );
        let ev = last_connect_event(&t.sid);
        if resp.starts_with("HTTP/1.1 403") {
            // The un-hijacked case: fail-closed DNS denial.
            assert_eq!(ev["source"], "dns");
        } else {
            assert!(
                resp.starts_with("HTTP/1.1 502"),
                "direct leg expected (403 dns-deny or 502 dial failure): {resp}"
            );
            // The bare 502 adds no leaf, so the admission allow is last.
            assert_eq!(ev["source"], "allowlist");
            assert_eq!(ev["disposition"], "allow");
        }
    }

    // (c) [G-30] upstream unreachable → 502 + X-Sandbox: upstream-error.
    #[test]
    fn upstream_unreachable_returns_502_with_upstream_error_header() {
        let port = DEAD_PORT;
        let t = t42_setup(
            "chain-dead",
            &["api.example.com"],
            Some(dialer(
                &format!("http://alice:s3cret@127.0.0.1:{port}"),
                &[],
            )),
        );
        let resp = exchange(t.port, &connect_req("api.example.com:443"));
        assert!(resp.starts_with("HTTP/1.1 502 Bad Gateway"), "got: {resp}");
        assert!(resp.contains("X-Sandbox: upstream-error"), "got: {resp}");
        assert!(
            resp.contains(&format!("127.0.0.1:{port}")),
            "body must name the proxy host:port: {resp}"
        );
        for (i, secret) in ["alice", "s3cret", "@"].into_iter().enumerate() {
            // The body is the thing under test: a failure that echoes it re-leaks
            // whatever the assertion just found.
            assert!(
                !resp.contains(secret),
                "body leaked credential #{} (values withheld)",
                i + 1
            );
        }
        let ev = last_connect_event(&t.sid);
        assert_eq!(ev["disposition"], "deny");
        assert_eq!(ev["source"], "default");
        assert_eq!(ev["reason"], "upstream_error");
        // Two leaves: the admission `allow` (emitted before the dial) and then
        // the `upstream_error` denial. The direct 502 path emits only the
        // admission leaf — chained failures are the two-event shape.
        let evs = connect_events(&t.sid);
        assert_eq!(evs.len(), 2, "expected admission + upstream_error: {evs:?}");
        assert_eq!(evs[0]["disposition"], "allow");
        assert_eq!(evs[0]["source"], "allowlist");
    }

    // (d) a non-2xx answer to the chained CONNECT maps to the same 502.
    #[test]
    fn upstream_non_200_returns_502_with_upstream_error_header() {
        let fake = FakeUpstream::start(403);
        let t = t42_setup(
            "chain-403",
            &["api.example.com"],
            Some(dialer(&fake.cred_url(), &[])),
        );
        let resp = exchange(t.port, &connect_req("api.example.com:443"));
        assert!(resp.starts_with("HTTP/1.1 502 Bad Gateway"), "got: {resp}");
        assert!(resp.contains("X-Sandbox: upstream-error"), "got: {resp}");
        assert!(
            resp.contains(&format!("127.0.0.1:{}", fake.port)),
            "body must name the proxy host:port: {resp}"
        );
        assert!(resp.contains("403"), "body should carry the status: {resp}");
        assert!(!resp.contains("s3cret"), "leaked password: {resp}");
        assert_eq!(fake.heads().len(), 1);
        let ev = last_connect_event(&t.sid);
        assert_eq!(ev["source"], "default");
        assert_eq!(ev["reason"], "upstream_error");
    }

    // (e) [G-22] chaining is hostname-only: a name that cannot resolve
    // locally still tunnels, because the upstream proxy does the DNS.
    #[test]
    fn chained_path_skips_local_dns_resolution() {
        let fake = FakeUpstream::start(200);
        let t = t42_setup(
            "chain-no-dns",
            &["*.invalid"],
            Some(dialer(&fake.url(), &[])),
        );
        let (head, echo) = tunnel(t.port, "nx-4-2.invalid:443", b"hostname-only");
        assert!(head.starts_with("HTTP/1.1 200"), "got: {head}");
        assert_eq!(echo, "hostname-only");
        let heads = fake.heads();
        assert_eq!(heads.len(), 1);
        assert!(
            heads[0].starts_with("CONNECT nx-4-2.invalid:443 HTTP/1.1"),
            "the hostname (not an IP) is what chains: {:?}",
            heads[0]
        );
    }

    // (e') the same hostname with no upstream configured dials directly — the
    // contrast that proves (e) skipped local DNS. De-flaked like (b): a
    // resolver that hijacks `.invalid` makes the direct dial succeed, so the
    // pinned property is "never chained", not a single status code.
    #[test]
    fn direct_path_dns_failure_fails_closed() {
        let t = t42_setup("direct-no-dns", &["*.invalid"], None);
        let resp = exchange(t.port, &connect_req("nx-4-2.invalid:443"));
        assert!(
            !resp.contains("X-Sandbox: upstream-error"),
            "no upstream is configured, so nothing may chain: {resp}"
        );
        match resp.split_whitespace().nth(1) {
            Some("403") => {
                assert!(resp.contains("X-Sandbox: denied"), "got: {resp}");
                assert_eq!(last_connect_event(&t.sid)["source"], "dns");
            }
            // Hijacked resolver: the direct leg completed (200) or failed to
            // connect (502). Neither is a chained request.
            Some("200") | Some("502") => {}
            other => panic!("unexpected CONNECT answer {other:?} in: {resp}"),
        }
    }

    // (f) [G-22] the hostname hard-deny still runs before chaining.
    #[test]
    fn hard_deny_hostname_wins_on_chained_path() {
        let fake = FakeUpstream::start(200);
        let t = t42_setup("chain-hard-deny-name", &[], Some(dialer(&fake.url(), &[])));
        let resp = exchange(t.port, &connect_req("metadata.google.internal:80"));
        assert!(resp.starts_with("HTTP/1.1 403"), "got: {resp}");
        assert!(fake.heads().is_empty(), "hard-deny must not chain");
        let ev = last_connect_event(&t.sid);
        assert_eq!(ev["source"], "hard-deny");
        assert_eq!(ev["reason"], "denied_dns");
    }

    // (g) [G-22] the IP-literal hard-deny still runs before chaining.
    #[test]
    fn hard_deny_ip_literal_wins_on_chained_path() {
        let fake = FakeUpstream::start(200);
        let t = t42_setup("chain-hard-deny-ip", &[], Some(dialer(&fake.url(), &[])));
        let resp = exchange(t.port, &connect_req("169.254.169.253:80"));
        assert!(resp.starts_with("HTTP/1.1 403"), "got: {resp}");
        assert!(fake.heads().is_empty(), "hard-deny must not chain");
        let ev = last_connect_event(&t.sid);
        assert_eq!(ev["source"], "hard-deny");
        assert_eq!(ev["reason"], "denied_cidr");
    }

    // (h) bracketed IPv6 target: `parse_connect_target` keeps the brackets,
    // the chained dial must strip them (else `host_port` emits `[[::1]]`).
    #[test]
    fn chained_bracketed_ipv6_target_is_unbracketed_for_the_dial() {
        let fake = FakeUpstream::start(200);
        let t = t42_setup(
            "chain-ipv6",
            &["[2606:4700::1111]"],
            Some(dialer(&fake.url(), &[])),
        );
        let (head, _echo) = tunnel(t.port, "[2606:4700::1111]:443", b"v6");
        assert!(head.starts_with("HTTP/1.1 200"), "got: {head}");
        let heads = fake.heads();
        assert_eq!(heads.len(), 1);
        assert!(
            heads[0].starts_with("CONNECT [2606:4700::1111]:443 HTTP/1.1"),
            "exactly one bracket pair: {:?}",
            heads[0]
        );
    }

    // (i) [G-11, B1] a conventional *bare* IPv6 `NO_PROXY` entry must bypass
    // the upstream for a bracketed CONNECT target. `parse_connect_target`
    // keeps the brackets, so the decision point has to normalize the host
    // once: otherwise `chains_host` misses, the bypass only fires inside
    // `UpstreamDialer::dial`'s own re-check, and that call dials the direct
    // path with no pinned addresses — reporting a proxy that was never
    // contacted as unreachable (502 + a spurious `upstream_error` leaf).
    #[test]
    fn bare_ipv6_no_proxy_entry_never_chains_and_unspecified_is_refused() {
        let fake = FakeUpstream::start(200);
        let t = t42_setup(
            "chain-v6-bare-noproxy",
            &["[::]"],
            Some(dialer(&fake.url(), &["::"])),
        );
        // `::` is the unspecified address: nothing can route to it, so the
        // direct leg fails at once and the test needs no external network.
        let resp = exchange(t.port, &connect_req("[::]:443"));
        assert!(
            !resp.contains("X-Sandbox: upstream-error"),
            "the NO_PROXY bypass must win before any chaining: {resp}"
        );
        assert!(
            fake.heads().is_empty(),
            "the upstream proxy must never be contacted: {:?}",
            fake.heads()
        );
        // The target is the unspecified address, which is now refused at the
        // pinned-address leg ([G-44]); the point this test protects is unchanged -
        // the NO_PROXY bypass must never chain to the upstream proxy.
        let evs = connect_events(&t.sid);
        let last = evs.last().expect("at least the admission leaf");
        assert_eq!(last["disposition"], "deny", "unspecified target must be refused: {evs:?}");
        assert_eq!(last["source"], "hard-deny");
        assert_eq!(last["reason"], "loopback_refused");
    }

    // (i') the bracket form of the same entry keeps working: entries are
    // normalized to the bare host when the dialer is built, so both spellings
    // of an IPv6 bypass agree with the single normalized host.
    #[test]
    fn bracketed_ipv6_no_proxy_entry_never_chains_and_unspecified_is_refused() {
        let fake = FakeUpstream::start(200);
        let t = t42_setup(
            "chain-v6-bracketed-noproxy",
            &["[::]"],
            Some(dialer(&fake.url(), &["[::]"])),
        );
        let resp = exchange(t.port, &connect_req("[::]:443"));
        assert!(
            !resp.contains("X-Sandbox: upstream-error"),
            "a bracketed NO_PROXY entry must bypass as well: {resp}"
        );
        assert!(
            fake.heads().is_empty(),
            "the upstream proxy must never be contacted: {:?}",
            fake.heads()
        );
        let evs = connect_events(&t.sid);
        assert_eq!(
            evs.last().unwrap()["reason"], "loopback_refused",
            "a bracketed NO_PROXY entry changes nothing about the refusal: {evs:?}"
        );
    }

    // =================================================================
    // Task 4.4 — tunnel half-close: the client's EOF must reach the
    // upstream as a FIN.
    //
    // Regression for the 4.2 review's live hang (S-83): the split +
    // `join!(copy, copy)` tunnel never shut down the other side's write
    // half, so a client that closed left `copy(upstream → client)` parked
    // forever against a keep-alive upstream — one leaked task and two leaked
    // fds per request. With `copy_bidirectional` the FIN propagates, the
    // upstream answers with its own EOF, and the handler returns.
    // =================================================================

    /// Async fake upstream proxy for the half-close test: answers the
    /// CONNECT with `200`, echoes until it reads EOF, then closes and
    /// resolves with the number of bytes it echoed. The head is read one
    /// byte at a time so no tunnel byte is swallowed by the CONNECT parse.
    async fn echoing_upstream_until_eof() -> (u16, tokio::task::JoinHandle<usize>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake upstream");
        let port = listener.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.expect("accept fake upstream");
            let mut head = Vec::new();
            let mut one = [0u8; 1];
            loop {
                if s.read(&mut one).await.unwrap_or(0) == 0 {
                    return 0;
                }
                head.push(one[0]);
                if head.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            s.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .expect("write fake 200");
            let mut echoed = 0usize;
            let mut buf = [0u8; 4096];
            loop {
                match s.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        echoed += n;
                        if s.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                }
            }
            echoed
        });
        (port, task)
    }

    /// Minimal `ConnCtx` for a chained tunnel test: `api.example.com` is
    /// allow-listed (so the prompt is never consulted), and the upstream
    /// dialer points at the fake proxy above. Returns the scratch dir too
    /// so the caller can drop it with the context.
    fn tunnel_ctx(label: &str, upstream_port: u16) -> (Arc<ConnCtx>, std::path::PathBuf) {
        let base = std::env::temp_dir().join(format!("sandbox-t44-{}", temp_sid(label)));
        std::fs::create_dir_all(&base).unwrap();
        let (dialog, _calls) = recording_dialog(Ok(deny_once_result()));
        let prompt = PromptGate {
            enabled: false,
            config: PromptConfig {
                timeout: Duration::from_secs(1),
                on_unavailable: PromptPolicy::Deny,
            },
            coordinator: Arc::new(PromptCoordinator::with_dialog(dialog)),
            intent: Arc::new(IntentRegistry::new(DEFAULT_TTL)),
            learned: Arc::new(StdMutex::new(
                LearnedStore::load_in(&base, Some("t44")).expect("empty learned store"),
            )),
        };
        let sid = temp_sid(label);
        let writer = Arc::new(crate::audit::AuditWriter::open(&sid, false).unwrap());
        let ctx = Arc::new(ConnCtx {
            token: RunToken::for_tests(TEST_TOKEN),
            deny: Vec::new(),
            allow: vec!["api.example.com".to_string()],
            writer,
            upstream: Some(dialer(&format!("http://127.0.0.1:{upstream_port}"), &[])),
            prompt,
            counters: LaunchCounters::new(),
            no_token: super::RefusalBudget::new(),
            foreign_token: super::RefusalBudget::new(),
            facade: Arc::new(super::FacadeRegistry::new()),
        });
        (ctx, base)
    }

    /// The 4.4 regression: after the client closes its socket the handler
    /// must finish promptly, and only if the EOF crossed the tunnel does the
    /// upstream's read-EOF-terminated loop end.
    #[tokio::test]
    async fn client_eof_reaches_the_upstream_and_the_handler_finishes() {
        let (upstream_port, upstream_task) = echoing_upstream_until_eof().await;
        let (ctx, _base) = tunnel_ctx("half-close", upstream_port);

        // The production accept loop hands `handle_conn` one end of a
        // loopback socket; this listener provides exactly that pair.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_port = listener.local_addr().unwrap().port();

        let client = tokio::spawn(async move {
            let mut s = TcpStream::connect(("127.0.0.1", proxy_port))
                .await
                .expect("connect handler socket");
            s.write_all(connect_req("api.example.com:443").as_bytes())
                .await
                .unwrap();
            let mut head = Vec::new();
            let mut one = [0u8; 1];
            loop {
                if s.read(&mut one).await.unwrap_or(0) == 0 {
                    break;
                }
                head.push(one[0]);
                if head.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            let payload = b"half-close payload";
            s.write_all(payload).await.unwrap();
            let mut echoed = vec![0u8; payload.len()];
            s.read_exact(&mut echoed).await.unwrap();
            // Close the client socket outright — no explicit shutdown, no
            // lingering write half. The handler has to forward this EOF.
            drop(s);
            (String::from_utf8_lossy(&head).into_owned(), echoed)
        });

        let (server, _peer) = listener.accept().await.unwrap();
        let handled = tokio::time::timeout(Duration::from_secs(2), handle_conn(server, ctx)).await;
        assert!(
            handled.is_ok(),
            "handle_conn was still running 2s after the client closed: the client EOF \
             never reached the upstream write half, so a keep-alive upstream parks the \
             handler (and two fds) forever"
        );

        let (head, echoed) = client.await.expect("client task");
        assert!(head.starts_with("HTTP/1.1 200"), "got: {head}");
        assert_eq!(
            echoed,
            b"half-close payload".to_vec(),
            "payload must round-trip before the close"
        );

        // The fake upstream's loop ends only on read-EOF, so a task that
        // resolves proves the FIN crossed the tunnel (and echoes the count).
        let echoed_upstream = tokio::time::timeout(Duration::from_secs(2), upstream_task)
            .await
            .expect("fake upstream never observed the tunnel's EOF")
            .expect("fake upstream task panicked");
        assert_eq!(echoed_upstream, b"half-close payload".len());
    }

    // ---- plugin facade: `<mount>.sandbox.invalid` -------------------------

    fn facade_target(mount: &str, port: u16, token: &str) -> FacadeTarget {
        FacadeTarget {
            mount: mount.to_string(),
            port,
            token: token.to_string(),
            operations: vec![
                crate::plugin::Operation { method: "GET".into(), path: "/".into() },
                crate::plugin::Operation { method: "GET".into(), path: "/page".into() },
            ],
        }
    }

    /// The manifest's `operations` are the operator's reviewed surface. They were
    /// parsed, documented as the plugin's exposed API, and never consulted, so the
    /// workload could reach any path the sidecar happens to serve.
    #[test]
    fn an_undeclared_facade_path_is_refused_before_the_sidecar() {
        const BODY: &str = "should not be reached";
        let (sidecar_port, seen) = fake_sidecar(BODY);
        let (dialog, _calls) = recording_dialog(Ok(deny_once_result()));
        let t = t36_setup("facade-undeclared", &[], &[], dialog);
        t.handle
            .ctx
            .facade
            .insert(facade_target("fake", sidecar_port, "facadetoken"))
            .unwrap();

        let resp = exchange(
            t.port,
            &format!(
                "GET http://fake.sandbox.invalid/admin HTTP/1.1\r\n{}\r\n",
                auth_header()
            ),
        );
        assert!(
            resp.starts_with("HTTP/1.1 403"),
            "an undeclared path must be refused: {resp}"
        );
        assert!(
            resp.contains("facade_operation_not_declared"),
            "the refusal must name the rule: {resp}"
        );
        assert!(
            seen.lock().unwrap().is_empty(),
            "the sidecar must never see an undeclared request"
        );
        let path = crate::audit::audit_log_path(&t.sid);
        let text = std::fs::read_to_string(&path).unwrap();
        let mut leaf: Option<serde_json::Value> = None;
        for line in text.lines() {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(line)
                && v["op"] == "FACADE"
            {
                leaf = Some(v);
            }
        }
        let leaf = leaf.expect("the refusal is recorded as a FACADE leaf");
        assert_eq!(leaf["disposition"], "deny");
        assert_eq!(leaf["reason"], "facade_operation_not_declared");
    }

    /// A one-shot HTTP/1.0 sidecar stand-in: records the request head it received
    /// and answers a fixed body. Blocking, on a std thread — the proxy connects to
    /// it from a tokio task, exactly as it reaches the real sidecar.
    /// Like [`fake_sidecar`], but reads the declared body too, so a relayed POST can
    /// be checked for what actually arrived.
    fn fake_sidecar_with_body(body: &'static str) -> (u16, Arc<StdMutex<Vec<String>>>) {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen: Arc<StdMutex<Vec<String>>> = Arc::new(StdMutex::new(Vec::new()));
        let seen_in_thread = Arc::clone(&seen);
        std::thread::spawn(move || {
            if let Ok((mut s, _)) = listener.accept() {
                s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                let mut raw = Vec::new();
                let mut one = [0u8; 1];
                while !raw.ends_with(b"\r\n\r\n") {
                    match s.read(&mut one) {
                        Ok(0) | Err(_) => break,
                        Ok(_) => raw.push(one[0]),
                    }
                }
                // The supervisor frames the body it forwards, so Content-Length is the
                // only thing to trust here.
                let head = String::from_utf8_lossy(&raw).into_owned();
                let want = content_length(&head).unwrap_or(0);
                let mut body_bytes = vec![0u8; want];
                let mut got = 0;
                while got < want {
                    match s.read(&mut body_bytes[got..]) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => got += n,
                    }
                }
                seen_in_thread.lock().unwrap().push(format!(
                    "{head}{}",
                    String::from_utf8_lossy(&body_bytes[..got])
                ));
                let resp = format!(
                    "HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{body}",
                    body.len()
                );
                let _ = s.write_all(resp.as_bytes());
            }
        });
        (port, seen)
    }

    fn fake_sidecar(body: &'static str) -> (u16, Arc<StdMutex<Vec<String>>>) {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen: Arc<StdMutex<Vec<String>>> = Arc::new(StdMutex::new(Vec::new()));
        let seen_in_thread = Arc::clone(&seen);
        std::thread::spawn(move || {
            if let Ok((mut s, _)) = listener.accept() {
                s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                let mut head = Vec::new();
                let mut one = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    match s.read(&mut one) {
                        Ok(0) | Err(_) => break,
                        Ok(_) => head.push(one[0]),
                    }
                }
                seen_in_thread
                    .lock()
                    .unwrap()
                    .push(String::from_utf8_lossy(&head).into_owned());
                let resp = format!(
                    "HTTP/1.0 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n\
                     Content-Length: {}\r\n\r\n{body}",
                    body.len()
                );
                let _ = s.write_all(resp.as_bytes());
            }
        });
        (port, seen)
    }

    fn facade_leaves(sid: &str) -> Vec<serde_json::Value> {
        std::fs::read_to_string(crate::audit::audit_log_path(sid))
            .unwrap_or_default()
            .lines()
            .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
            .filter(|v| v["op"] == "FACADE")
            .collect()
    }

    #[test]
    fn facade_routing_table() {
        let reg = FacadeRegistry::new();
        reg.insert(facade_target("tngtech", 4321, "tok")).unwrap();

        assert!(matches!(
            facade_action(&reg, "api.example.com", "GET", "/"),
            FacadeAction::NotFacade
        ));
        assert!(
            matches!(
                facade_action(&reg, "sandbox.invalid", "GET", "/"),
                FacadeAction::NotFacade
            ),
            "the bare suffix is not a mount"
        );
        assert!(
            matches!(
                facade_action(&reg, "tngtech.sandbox.invalid.evil.com", "GET", "/"),
                FacadeAction::NotFacade
            ),
            "a lookalike suffix must never be a facade host"
        );
        assert!(matches!(
            facade_action(&reg, "nope.sandbox.invalid", "GET", "/"),
            FacadeAction::UnknownMount
        ));
        assert!(
            matches!(
                facade_action(&reg, "nope.sandbox.invalid", "POST", "/"),
                FacadeAction::UnknownMount
            ),
            "an undeclared mount is 404 whatever the method"
        );
        assert!(
            matches!(
                facade_action(&reg, "tngtech.sandbox.invalid", "POST", "/"),
                FacadeAction::OperationNotDeclared
            ),
            "a method the manifest does not declare is a 403, not a 501: the declaration \
             is the control, and 'this transport only speaks GET' was never true"
        );
        assert!(
            matches!(
                facade_action(&reg, "tngtech.sandbox.invalid", "GE T", "/"),
                FacadeAction::MethodInvalid
            ),
            "a method that is not a token cannot be put on a request line"
        );
        match facade_action(&reg, "TNGTECH.sandbox.invalid", "GET", "/") {
            FacadeAction::Relay { mount, target } => {
                assert_eq!(mount, "tngtech", "the mount is the registry's spelling");
                assert_eq!(target.port, 4321);
            }
            other => panic!("expected a relay, got {other:?}"),
        }
    }

    /// T1.5: a declared POST reaches the sidecar **with its body**, and the request
    /// line names the method the manifest declared. Before this, the facade answered
    /// 501 for every method but GET and forwarded no body at all - a build request
    /// (task + profile) had nowhere to go.
    #[test]
    fn a_declared_post_reaches_the_sidecar_with_its_body() {
        const BODY: &str = "{\"task\":\"build\"}";
        let (sidecar_port, seen) = fake_sidecar_with_body("accepted");
        let (dialog, _calls) = recording_dialog(Ok(deny_once_result()));
        let t = t36_setup("facade-post", &[], &[], dialog);
        let mut target = facade_target("fake", sidecar_port, "facadetoken");
        target.operations.push(crate::plugin::Operation {
            method: "POST".into(),
            path: "/build".into(),
        });
        t.handle.ctx.facade.insert(target).unwrap();

        let request = format!(
            "POST http://fake.sandbox.invalid/build HTTP/1.1\r\n{}Content-Length: {}\r\n\r\n{BODY}",
            auth_header(),
            BODY.len()
        );
        let resp = exchange(t.port, &request);
        assert!(
            resp.starts_with("HTTP/1.0 200 OK"),
            "the sidecar's answer must be relayed: {resp}"
        );

        let seen = seen.lock().unwrap();
        let got = seen.first().expect("the sidecar must have been dialled");
        assert!(
            got.starts_with("POST /build HTTP/1.0"),
            "the declared method and path go on the request line: {got}"
        );
        assert!(
            got.ends_with(BODY),
            "the body must arrive verbatim, got: {got:?}"
        );
        assert!(
            got.contains("Content-Length: ") && got.contains("X-Facade-Token: facadetoken"),
            "the supervisor frames and authenticates the deputy: {got}"
        );
    }

    /// The declaration is the control: a method the manifest does not list is refused
    /// even though the transport now relays whatever *is* listed.
    #[test]
    fn an_undeclared_method_is_refused_with_403_not_501() {
        let (sidecar_port, _seen) = fake_sidecar("never");
        let (dialog, _calls) = recording_dialog(Ok(deny_once_result()));
        let t = t36_setup("facade-post-undeclared", &[], &[], dialog);
        t.handle
            .ctx
            .facade
            .insert(facade_target("fake", sidecar_port, "facadetoken"))
            .unwrap();

        let request = format!(
            "DELETE http://fake.sandbox.invalid/page HTTP/1.1\r\n{}\r\n",
            auth_header()
        );
        let resp = exchange(t.port, &request);
        assert!(resp.starts_with("HTTP/1.1 403"), "got: {resp}");
        assert!(
            resp.contains("facade_operation_not_declared"),
            "the refusal names the reason: {resp}"
        );
    }

    /// An oversized body is refused before a byte of it is read into memory.
    #[test]
    fn a_body_past_the_cap_is_413() {
        let (sidecar_port, _seen) = fake_sidecar("never");
        let (dialog, _calls) = recording_dialog(Ok(deny_once_result()));
        let t = t36_setup("facade-body-cap", &[], &[], dialog);
        let mut target = facade_target("fake", sidecar_port, "facadetoken");
        target.operations.push(crate::plugin::Operation {
            method: "POST".into(),
            path: "/page".into(),
        });
        t.handle.ctx.facade.insert(target).unwrap();

        let request = format!(
            "POST http://fake.sandbox.invalid/page HTTP/1.1\r\n{}Content-Length: {}\r\n\r\n",
            auth_header(),
            MAX_FACADE_BODY + 1
        );
        let resp = exchange(t.port, &request);
        assert!(resp.starts_with("HTTP/1.1 413"), "got: {resp}");
        assert!(resp.contains("facade_body_too_large"), "got: {resp}");
    }

    #[test]
    fn facade_relay_is_verbatim_and_carries_the_facade_token() {
        const BODY: &str = "<html><title>through the facade</title></html>";
        let (sidecar_port, seen) = fake_sidecar(BODY);
        let (dialog, _calls) = recording_dialog(Ok(deny_once_result()));
        let t = t36_setup("facade-relay", &[], &[], dialog);
        t.handle
            .ctx
            .facade
            .insert(facade_target("fake", sidecar_port, "facadetoken"))
            .unwrap();

        let resp = exchange(
            t.port,
            &format!(
                "GET http://fake.sandbox.invalid/page?q=1 HTTP/1.1\r\n{}\r\n",
                auth_header()
            ),
        );
        assert!(
            resp.starts_with("HTTP/1.0 200 OK"),
            "the sidecar's status line is relayed as-is: {resp}"
        );
        assert!(
            resp.to_ascii_lowercase()
                .contains("content-type: text/html"),
            "{resp}"
        );
        assert!(
            resp.ends_with(BODY),
            "the body must arrive verbatim: {resp}"
        );

        let head = seen
            .lock()
            .unwrap()
            .first()
            .cloned()
            .expect("the sidecar must have been called");
        assert!(
            head.starts_with("GET /page?q=1 HTTP/1.0\r\n"),
            "origin-form with the query: {head}"
        );
        assert!(head.contains("Host: fake\r\n"), "{head}");
        assert!(head.contains("X-Facade-Token: facadetoken\r\n"), "{head}");

        assert!(
            connect_events(&t.sid).is_empty(),
            "a facade request is not an origin consultation"
        );
        let leaves = facade_leaves(&t.sid);
        assert_eq!(leaves.len(), 1, "one request, one leaf: {leaves:?}");
        assert_eq!(leaves[0]["disposition"], "allow");
        assert_eq!(leaves[0]["mount"], "fake");
        assert_eq!(leaves[0]["path"], "/page?q=1");
        assert_eq!(leaves[0]["reason"], serde_json::Value::Null);
    }

    #[test]
    fn facade_unknown_mount_is_404_and_audited_as_a_deny() {
        let (dialog, _calls) = recording_dialog(Ok(deny_once_result()));
        let t = t36_setup("facade-unknown", &[], &[], dialog);
        let resp = exchange(
            t.port,
            &format!(
                "GET http://nope.sandbox.invalid/ HTTP/1.1\r\n{}\r\n",
                auth_header()
            ),
        );
        assert!(resp.starts_with("HTTP/1.1 404"), "got: {resp}");
        assert!(resp.contains("facade_unknown_mount"), "got: {resp}");
        let leaves = facade_leaves(&t.sid);
        assert_eq!(leaves.len(), 1);
        assert_eq!(leaves[0]["disposition"], "deny");
        assert_eq!(leaves[0]["reason"], "facade_unknown_mount");
        assert_eq!(leaves[0]["mount"], "nope");
    }

    #[test]
    fn facade_undeclared_method_is_403_and_audited_as_a_deny() {
        // T1.5 replaced the hard-coded GET gate: the transport relays whatever the
        // manifest declares, so the refusal for an undeclared method is the same 403
        // as for an undeclared path — one rule, one reason, one audit spelling.
        let (dialog, _calls) = recording_dialog(Ok(deny_once_result()));
        let t = t36_setup("facade-post", &[], &[], dialog);
        t.handle
            .ctx
            .facade
            .insert(facade_target("fake", 9, "tok"))
            .unwrap();
        let resp = exchange(
            t.port,
            &format!(
                "POST http://fake.sandbox.invalid/ HTTP/1.1\r\n{}Content-Length: 0\r\n\r\n",
                auth_header()
            ),
        );
        assert!(resp.starts_with("HTTP/1.1 403"), "got: {resp}");
        assert!(resp.contains("facade_operation_not_declared"), "got: {resp}");
        let leaves = facade_leaves(&t.sid);
        assert_eq!(leaves.len(), 1);
        assert_eq!(leaves[0]["reason"], "facade_operation_not_declared");
    }

    #[test]
    fn facade_with_a_dead_sidecar_is_502_and_audited() {
        // Bind and drop: the port is ours and nothing listens on it.
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let dead_port = listener.local_addr().unwrap().port();
        drop(listener);
        let (dialog, _calls) = recording_dialog(Ok(deny_once_result()));
        let t = t36_setup("facade-dead", &[], &[], dialog);
        t.handle
            .ctx
            .facade
            .insert(facade_target("fake", dead_port, "tok"))
            .unwrap();
        let resp = exchange(
            t.port,
            &format!(
                "GET http://fake.sandbox.invalid/ HTTP/1.1\r\n{}\r\n",
                auth_header()
            ),
        );
        assert!(resp.starts_with("HTTP/1.1 502"), "got: {resp}");
        assert!(resp.contains("facade_sidecar_unreachable"), "got: {resp}");
        let leaves = facade_leaves(&t.sid);
        assert_eq!(leaves.len(), 1);
        assert_eq!(leaves[0]["disposition"], "deny");
        assert_eq!(leaves[0]["reason"], "facade_sidecar_unreachable");
    }

    #[test]
    fn facade_connect_is_refused_with_facade_requires_http() {
        let (dialog, _calls) = recording_dialog(Ok(deny_once_result()));
        let t = t36_setup("facade-connect", &[], &[], dialog);
        let resp = exchange(t.port, &connect_req("tngtech.sandbox.invalid:443"));
        assert!(resp.starts_with("HTTP/1.1 403"), "got: {resp}");
        assert!(resp.contains("facade_requires_http"), "got: {resp}");
        let leaves = facade_leaves(&t.sid);
        assert_eq!(leaves.len(), 1, "the refusal is audited: {leaves:?}");
        assert_eq!(leaves[0]["disposition"], "deny");
        assert_eq!(leaves[0]["reason"], "facade_requires_http");
        assert_eq!(leaves[0]["mount"], "tngtech");
        assert!(
            connect_events(&t.sid).is_empty(),
            "a refused facade tunnel is not a consultation"
        );
    }

    /// [G-44] is about not becoming a tunnel to host services. A host STRING check
    /// cannot enforce that: `localtest.me` and `127.0.0.1.nip.io` are public names
    /// that resolve to loopback. The pinned address set is the only place the real
    /// destination is known, so loopback and the unspecified address must be
    /// refused there.
    #[test]
    fn pinned_loopback_addresses_are_hard_denied() {
        use std::net::SocketAddr;
        // `::ffff:127.0.0.1` is the form a resolver or a literal can produce for the
        // same destination; the check unmaps before deciding, so it is refused too.
        for s in [
            "127.0.0.1:443",
            "127.1.2.3:443",
            "[::1]:443",
            "0.0.0.0:443",
            "[::]:443",
            "[::ffff:127.0.0.1]:443",
            "[::ffff:7f00:1]:443",
        ] {
            let sa: SocketAddr = s.parse().unwrap();
            assert!(
                super::pinned_addrs_hard_denied(&[sa], false).is_some(),
                "{s} resolves to loopback/unspecified and must be refused before dialling"
            );
            // The bare address predicate stays loopback-agnostic on purpose (the
            // dialer's debug assertion and the dial-mechanics tests rely on that);
            // the REFUSAL is the policy leg above.
            assert!(!super::pinned_addrs_contain_hard_denied(&[sa]), "{s}");
        }
        // A public address is still allowed: the check must not swallow the world.
        let public: SocketAddr = "93.184.216.34:443".parse().unwrap();
        assert!(super::pinned_addrs_hard_denied(&[public], false).is_none());
    }

    /// A CONNECT target whose port is not a number used to be silently retried on
    /// 443 - a typo in the port became a different request. Refuse it instead, the
    /// way `split_authority` already refuses the same class in an absolute target.
    #[test]
    fn connect_target_with_an_invalid_port_is_refused_not_defaulted() {
        assert_eq!(super::parse_connect_target("example.com:8443"), Some(("example.com".into(), 8443)));
        assert_eq!(super::parse_connect_target("example.com"), Some(("example.com".into(), 443)));
        for bad in ["example.com:", "example.com:notaport", "example.com:70000", "example.com:0"] {
            assert_eq!(super::parse_connect_target(bad), None, "{bad} must be refused");
        }
    }

    /// The listener is reachable by any local process, including the child. A
    /// connection that arrives beyond the cap must be closed at once, not queued:
    /// otherwise "open sockets and say nothing" is a free denial of service inside
    /// the containment root.
    #[test]
    fn connections_beyond_the_cap_are_refused_instead_of_queued() {
        use std::io::Read;

        let (dialog, _calls) = recording_dialog(Ok(deny_once_result()));
        let t = t36_setup("admission-cap", &[], &[], dialog);

        let mut socks = Vec::new();
        for _ in 0..(super::MAX_INFLIGHT_CONNECTIONS + 3) {
            socks.push(std::net::TcpStream::connect(("127.0.0.1", t.port)).unwrap());
        }
        // Immediacy is the property: the head-read deadline also closes a silent
        // connection, but only after 15 s. A refusal at admission closes at once.
        let started = std::time::Instant::now();
        let mut closed = 0;
        for s in &socks {
            // Short: an admitted socket must time out here, a refused one returns 0
            // at once. 35 * 50 ms keeps the whole loop well inside the bound below.
            s.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
            let mut b = [0u8; 1];
            if matches!((&*s).read(&mut b), Ok(0)) {
                closed += 1;
            }
        }
        assert!(
            closed >= 3 && started.elapsed() < Duration::from_secs(3),
            "the overflow connections must be refused at admission (closed={closed} of {}, \
             elapsed={:?}); the head deadline is not a substitute",
            socks.len(),
            started.elapsed()
        );
    }
