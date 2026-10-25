// Extracted from src/main.rs `#[cfg(test)] mod tests` (2026-10-25), verbatim.
// Keep the indentation: a blind dedent rewrites multi-line raw-string contents.

    use super::*;

    #[test]
    fn session_id_format() {
        let id = new_session_id();
        // YYYYMMDD-HHMMSS-NNNNN  (8 + 1 + 6 + 1 + 5 = 21).
        assert_eq!(id.len(), 21);
        assert_eq!(id.as_bytes()[8], b'-');
        assert_eq!(id.as_bytes()[15], b'-');
    }

    #[test]
    fn chrono_basic() {
        // 1970-01-01 00:00:00 UTC == 0 seconds.
        assert_eq!(chrono_from_unix(0), "19700101-000000");
        // 1970-01-02 00:00:00 UTC.
        assert_eq!(chrono_from_unix(86_400), "19700102-000000");
        // A known date: 2024-01-01 00:00:00 UTC == 1704067200.
        assert_eq!(chrono_from_unix(1_704_067_200), "20240101-000000");
    }

    #[test]
    fn join_cmdline_quotes_spaces() {
        assert_eq!(
            join_cmdline(&["echo".into(), "hello world".into()]),
            "echo \"hello world\""
        );
        assert_eq!(join_cmdline(&["echo".into(), "".into()]), "echo \"\"");
        assert_eq!(join_cmdline(&["a".into()]), "a");
    }

    /// A finished MXC session, for the exit-code and refusal tests: what the two
    /// functions read, plus whatever `SessionOutcome` requires.
    #[cfg(feature = "mxc-backend")]
    fn finished_outcome(
        exit_code: Option<i32>,
        timeout: Option<net::mxc::TimeoutReason>,
    ) -> net::mxc::SessionOutcome {
        net::mxc::SessionOutcome {
            exit_code,
            timeout,
            stdout: b"out".to_vec(),
            stderr: b"err".to_vec(),
            warnings: Vec::new(),
            tier: base_container_record(),
            proxy_proof: net::mxc::ProxyProof::default(),
            expectation: net::mxc::ProofExpectation::MustBeAbsent,
            clock: net::mxc::SessionClock::measured(
                net::mxc::SessionBudget::default(),
                std::time::Duration::from_secs(5),
                std::time::Duration::from_secs(1),
                std::time::Duration::ZERO,
            ),
        }
    }

    #[cfg(feature = "mxc-backend")]
    fn base_container_record() -> net::mxc::TierRecord {
        net::mxc::tier_record(net::mxc::ProbeView {
            tier: Some(net::mxc::REQUIRED_TIER),
            needs_dacl_augmentation: Some(false),
        })
    }

    /// P3.0 decision 6: the AppContainer contract is mirrored for a child that
    /// exits `N` (return `N`), and a kill at the deadline is **not** that code — it
    /// gets its own, so "my command exited 124" and "the supervisor killed it at its
    /// budget" are distinguishable to a script. The `TimeoutReason` token beside the
    /// code says which term spent the clock.
    #[cfg(feature = "mxc-backend")]
    #[test]
    fn a_child_exit_code_is_mirrored_and_a_timeout_has_its_own() {
        assert_eq!(session_exit_code(&finished_outcome(Some(3), None)), 3);
        assert_eq!(session_exit_code(&finished_outcome(Some(0), None)), 0);
        let timed_out =
            finished_outcome(None, Some(net::mxc::TimeoutReason::WorkloadBudgetExceeded));
        assert_eq!(session_exit_code(&timed_out), EXIT_TIMEOUT);
        assert_eq!(
            timed_out.timeout.map(|reason| reason.as_str()),
            Some("workload_budget_exceeded"),
            "the operator is told which term ran the clock out"
        );
        assert_ne!(
            EXIT_TIMEOUT, EXIT_REFUSED,
            "a kill and a refusal must differ"
        );
    }

    /// A `TierRecord` for a session that dispatched to the **degraded** tier: the
    /// shape guardrail 2 refuses. The probe named it, so `tier_source` is `probe`
    /// and `needs_dacl_augmentation` is the probe's own `true` — not `None`.
    #[cfg(feature = "mxc-backend")]
    fn degraded_record() -> net::mxc::TierRecord {
        net::mxc::tier_record(net::mxc::ProbeView {
            tier: Some("appcontainer-dacl"),
            needs_dacl_augmentation: Some(true),
        })
    }

    /// A session id no other test can collide with.
    #[cfg(feature = "mxc-backend")]
    fn chain_sid(label: &str) -> String {
        format!(
            "test-p31-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        )
    }

    /// Every leaf of a session's chain, in file order.
    #[cfg(feature = "mxc-backend")]
    fn chain_leaves(sid: &str) -> Vec<serde_json::Value> {
        std::fs::read_to_string(audit::audit_log_path(sid))
            .unwrap_or_default()
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str(l).expect("each leaf is one JSON object"))
            .collect()
    }

    /// Remove a test session's chain, seal included.
    #[cfg(feature = "mxc-backend")]
    fn drop_chain(sid: &str) {
        let p = audit::audit_log_path(sid);
        let _ = std::fs::remove_file(&p);
        let _ = std::fs::remove_file(p.with_extension("root"));
        let _ = std::fs::remove_file(p.with_extension("sig"));
    }

    /// P3.0 decision 5, restated for P3.1 (S-55): only a **gate** refusal is
    /// written into the chain, and it is written as one leaf — the root is already
    /// on disk from before the launch.
    #[cfg(feature = "mxc-backend")]
    #[test]
    fn only_a_gate_refusal_reaches_the_chain() {
        use audit::session_start::{REASON_PROOF_UNMET, REASON_TIER_MISMATCH};
        use net::mxc::{GuardError, MxcError, REQUIRED_TIER, RequestError, TierMismatch};

        // Guardrail 1, pre-run shape. The reason is the guard's own cause, so the
        // five diagnoses stay distinguishable in the record.
        let guard = MxcError::Guard(GuardError::ProbeUnmet);
        let refusal = refusal_for(&guard).expect("guardrail 1 is recorded");
        assert_eq!(refusal.expected, REQUIRED_TIER);
        assert_eq!(refusal.reason, "proxy_probe_unmet");
        assert_eq!(launch_failure_exit(&guard), EXIT_REFUSED);

        // A different cause is a different token - this is what the collapse lost.
        let no_client = MxcError::Guard(GuardError::WorkloadCannotAuthenticate);
        assert_eq!(
            refusal_for(&no_client).expect("recorded").reason,
            "workload_cannot_authenticate"
        );
        let no_source = MxcError::Guard(GuardError::MissingProofSource);
        assert_eq!(
            refusal_for(&no_source).expect("recorded").reason,
            "proxy_proof_unavailable"
        );

        // Guardrail 1, post-run shape: same reason, and the one that carries the
        // workload's own output into the transcript.
        let unproven = MxcError::Unproven(Box::new(net::mxc::Unproven {
            error: GuardError::ProbeUnmet,
            outcome: finished_outcome(Some(0), None),
        }));
        let refusal = refusal_for(&unproven).expect("guardrail 1 is recorded");
        assert_eq!(refusal.reason, REASON_PROOF_UNMET);
        assert_eq!(launch_failure_exit(&unproven), EXIT_REFUSED);

        // Guardrail 2 after the root exists: the refusal names the requirement,
        // never the tier that was dispatched instead — the root already says that,
        // and it is not rewritten.
        let degraded = MxcError::Tier(TierMismatch {
            expected: REQUIRED_TIER,
            observed: Some("appcontainer-dacl".to_string()),
            source: "probe",
        });
        let refusal = refusal_for(&degraded).expect("guardrail 2 is recorded");
        assert_eq!(refusal.reason, REASON_TIER_MISMATCH);
        assert_eq!(refusal.expected, REQUIRED_TIER);
        assert_eq!(launch_failure_exit(&degraded), EXIT_REFUSED);

        // Nothing established: the root from before the launch is the whole
        // record, and a refusal leaf would claim a gate ran when none did.
        let unbuilt = MxcError::Request(RequestError::EmptyCommand);
        assert!(refusal_for(&unbuilt).is_none());
        assert_eq!(launch_failure_exit(&unbuilt), 1);
    }

    /// **S-55 on the MXC path**: the root is written before the launch, so a
    /// supervisor killed from that moment on leaves a readable chain — one root,
    /// the five facts, **no** `.root` seal — and `verify` says INCOMPLETE.
    ///
    /// The crash is expressed the only way a test can: the root is written and then
    /// nothing else happens — no launch, no `seal_audit`, no second leaf, and the
    /// writer is dropped without committing a root. `AuditWriter::append` opens,
    /// writes and closes per leaf ([`audit::AuditWriter::append`]), so the root is
    /// on disk the moment `complete` returns: there is no userspace buffer a
    /// `TerminateProcess` could lose, which is why the ordering alone is the fix.
    ///
    /// Both network postures: S-55 runs `--block-net`, where no listener exists and
    /// the endpoint must stay `null`; a networked session must record the port it
    /// bound, because that is a fact the root is now written early enough to carry.
    #[cfg(feature = "mxc-backend")]
    #[test]
    fn a_kill_after_the_root_leaves_one_root_five_facts_and_no_seal() {
        use audit::session_start::{LoopbackEndpoint, SessionStart, SessionStartFacts, TierFacts};
        use audit::verify::{VerifyOutcome, verify_inner};

        let elevated = setup::is_elevated();
        for (label, port) in [("block-net", None), ("networked", Some(49_152u16))] {
            let sid = chain_sid(label);
            // (4) writer + armed guard, (5) listener bound, (7b) the root — and then
            // the supervisor dies: the launch never happens.
            {
                let writer = std::sync::Arc::new(audit::AuditWriter::open(&sid, false).unwrap());
                SessionStart::arm(
                    writer,
                    &sid,
                    "cmd /c ping -n 30 127.0.0.1",
                    // Armed with what the supervisor knows before the probe — the
                    // probe's tier arrives through `with_tier`, as the session path
                    // does it.
                    SessionStartFacts::measured(TierFacts::default(), Some(elevated)),
                )
                .with_tier(base_container_record().audit_facts())
                .complete(port.map(LoopbackEndpoint::new))
                .unwrap();
            }

            let path = audit::audit_log_path(&sid);
            let leaves = chain_leaves(&sid);
            let sealed = path.with_extension("root").is_file();
            let signed = path.with_extension("sig").is_file();
            let verdict = verify_inner(&sid).unwrap();
            drop_chain(&sid);

            assert_eq!(
                leaves.len(),
                1,
                "{label}: the root is the whole chain: {leaves:?}"
            );
            let root = &leaves[0];
            assert_eq!(root["op"], audit::session_start::OP_SESSION_START);
            assert_eq!(root["seq"], 0, "{label}: the root is the genesis leaf");
            assert_eq!(root["parent"], serde_json::Value::Null);
            assert_eq!(root["disposition"], "allow", "{label}: it started");
            // The five facts, all of them, with no `.root` anywhere in sight.
            assert_eq!(root["tier"], net::mxc::REQUIRED_TIER);
            assert_eq!(root["tier_source"], net::mxc::TIER_SOURCE_PROBE);
            assert_eq!(root["tier_needs_dacl_augmentation"], false);
            assert_eq!(root["elevated"], elevated);
            match port {
                Some(p) => assert_eq!(root["proxy_endpoint"], format!("127.0.0.1:{p}")),
                None => assert_eq!(
                    root["proxy_endpoint"],
                    serde_json::Value::Null,
                    "{label}: --block-net binds nothing, so the endpoint is null"
                ),
            }
            assert!(!sealed, "{label}: a killed supervisor commits no root");
            assert!(!signed, "{label}: and signs nothing");
            match verdict {
                VerifyOutcome::Incomplete(reason) => assert!(
                    reason.contains("no committed root"),
                    "{label}: INCOMPLETE must name the missing seal: {reason}"
                ),
                other => {
                    panic!("{label}: a killed session must verify as INCOMPLETE, got {other:?}")
                }
            }
        }
    }

    /// Requirement (b): on the success path the leaf's facts **equal** the launch
    /// record's tier. Because the record now arrives after the root, the only thing
    /// it may do is confirm it — and a record that disagrees refuses the session
    /// instead of rewriting the root, still leaving exactly one root.
    #[cfg(feature = "mxc-backend")]
    #[test]
    fn the_launch_record_confirms_the_root_it_did_not_write() {
        use audit::session_start::{
            LoopbackEndpoint, OP_SESSION_REFUSED, OP_SESSION_START, SessionStart,
            SessionStartFacts, TierFacts, TierRefusal,
        };

        let sid = chain_sid("confirm");
        let probed = base_container_record();
        let writer = {
            let writer = std::sync::Arc::new(audit::AuditWriter::open(&sid, false).unwrap());
            SessionStart::arm(
                writer.clone(),
                &sid,
                "cmd /c echo MXC-WIRED",
                SessionStartFacts::measured(TierFacts::default(), Some(false)),
            )
            .with_tier(probed.audit_facts())
            .complete(Some(LoopbackEndpoint::new(49_154)))
            .unwrap();
            writer
        };

        // The record a successful launch hands back, for the same request.
        let recorded = base_container_record();
        let leaves = chain_leaves(&sid);
        let root = &leaves[0];
        assert_eq!(leaves.len(), 1, "one root: {leaves:?}");
        assert_eq!(root["op"], OP_SESSION_START);
        // The leaf's facts ARE the record's, field for field.
        assert_eq!(root["tier"], recorded.tier.clone().unwrap_or_default());
        assert_eq!(root["tier_source"], recorded.tier_source);
        assert_eq!(
            root["tier_needs_dacl_augmentation"],
            recorded.needs_dacl_augmentation.unwrap_or(false)
        );
        assert!(
            launch_confirms_root(&probed.audit_facts(), &recorded),
            "the launch record must confirm the facts the root claims"
        );

        // A record from a different tier is NOT confirmed, and step (9) refuses
        // rather than rewriting the root: the refusal leaf is the only write.
        let degraded = degraded_record();
        assert!(
            !launch_confirms_root(&probed.audit_facts(), &degraded),
            "a degraded record must not pass as confirmation"
        );
        audit::session_start::append_refusal(
            &writer,
            &sid,
            TierRefusal::tier_mismatch(net::mxc::REQUIRED_TIER),
        )
        .unwrap();
        drop(writer);

        let leaves = chain_leaves(&sid);
        drop_chain(&sid);
        let roots = leaves
            .iter()
            .filter(|l| l["op"] == OP_SESSION_START)
            .count();
        assert_eq!(roots, 1, "one root per run, even when refused: {leaves:?}");
        assert_eq!(
            leaves[0]["disposition"], "allow",
            "the root is not rewritten to deny after the fact"
        );
        assert_eq!(leaves[0]["tier"], net::mxc::REQUIRED_TIER);
        assert_eq!(leaves[1]["op"], OP_SESSION_REFUSED);
        assert_eq!(
            leaves[1]["reason"],
            audit::session_start::REASON_TIER_MISMATCH
        );
        assert_eq!(
            leaves[1]["parent"], leaves[0]["hash"],
            "the refusal links to the root"
        );
    }

    /// Requirement 2: a tier mismatch is still decided **before** the root is
    /// written, so a refused session's root can still say `deny` and still be the
    /// first leaf — the shape a refused AppContainer session has.
    #[cfg(feature = "mxc-backend")]
    #[test]
    fn a_tier_mismatch_is_decided_before_the_root_so_the_root_can_say_deny() {
        use audit::session_start::{
            LoopbackEndpoint, OP_SESSION_REFUSED, OP_SESSION_START, SessionStart,
            SessionStartFacts, TierFacts, TierRefusal,
        };

        assert!(
            pre_launch_tier_refusal(&base_container_record()).is_none(),
            "the required tier is not a refusal"
        );
        let degraded = degraded_record();
        let mismatch = pre_launch_tier_refusal(&degraded)
            .expect("a degraded tier is refused before anything is launched");
        assert_eq!(mismatch.expected, net::mxc::REQUIRED_TIER);
        assert_eq!(mismatch.observed.as_deref(), Some("appcontainer-dacl"));

        let sid = chain_sid("pre-launch-deny");
        {
            let writer = std::sync::Arc::new(audit::AuditWriter::open(&sid, false).unwrap());
            SessionStart::arm(
                writer,
                &sid,
                "cmd /c echo MXC-WIRED",
                SessionStartFacts::measured(TierFacts::default(), Some(false)),
            )
            .with_tier(degraded.audit_facts())
            .refuse(
                Some(LoopbackEndpoint::new(41_000)),
                TierRefusal::tier_mismatch(mismatch.expected),
            )
            .unwrap();
        }
        let leaves = chain_leaves(&sid);
        drop_chain(&sid);

        assert_eq!(leaves.len(), 2, "root + refusal: {leaves:?}");
        assert_eq!(leaves[0]["op"], OP_SESSION_START);
        assert_eq!(leaves[0]["parent"], serde_json::Value::Null);
        assert_eq!(
            leaves[0]["disposition"], "deny",
            "the root must not claim a start when the next leaf says refused"
        );
        assert_eq!(leaves[0]["tier"], "appcontainer-dacl");
        assert_eq!(
            leaves[0]["tier_needs_dacl_augmentation"], true,
            "the probe's own value, verbatim: the deny root is as complete as the allow one"
        );
        assert_eq!(leaves[1]["op"], OP_SESSION_REFUSED);
        assert_eq!(leaves[1]["expected_tier"], net::mxc::REQUIRED_TIER);
        assert!(
            leaves.iter().all(|l| l["op"] != "CONNECT"),
            "nothing ran, so nothing could reach the proxy: {leaves:?}"
        );
    }

    /// The newest `mtime` under `src/`, so a spawned supervisor can be shown to be
    /// newer than the code this run is testing.
    #[cfg(feature = "mxc-backend")]
    fn newest_source_mtime() -> Option<std::time::SystemTime> {
        fn walk(dir: &std::path::Path, newest: &mut Option<std::time::SystemTime>) {
            let Ok(entries) = std::fs::read_dir(dir) else {
                return;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    walk(&path, newest);
                } else if path.extension().is_some_and(|e| e == "rs")
                    && let Ok(mtime) = entry.metadata().and_then(|m| m.modified())
                    && newest.map(|n| mtime > n).unwrap_or(true)
                {
                    *newest = Some(mtime);
                }
            }
        }
        let mut newest = None;
        walk(std::path::Path::new("src"), &mut newest);
        newest
    }

    /// **S-55, the shape the harness runs** (P3.1): spawn the real supervisor on a
    /// real container, wait for its root, `TerminateProcess` it mid-session, then
    /// read the chain the way `audit verify` does.
    ///
    /// This is the *ordering* test. It asserts the root is on disk **while the child
    /// is still running**, which is exactly what P3.0's post-launch write could not
    /// do: with that ordering the log never appeared at all — `audit show` failed
    /// and `verify` had nothing to call INCOMPLETE. Reproduced against the old
    /// ordering, this test fails on "the root must be on disk while the child is
    /// still running"; with the root moved ahead of the launch it passes.
    #[cfg(feature = "mxc-backend")]
    #[test]
    #[ignore = "launches a real ProcessContainer and hard-kills a real supervisor; run: cargo test --features mxc-backend --bin saife -- --ignored"]
    fn a_supervisor_killed_mid_session_leaves_a_chain_verify_can_read() {
        use audit::verify::{VerifyOutcome, verify_inner};
        use std::time::Duration;

        let exe = std::env::current_exe().expect("current test exe");
        let supervisor = exe
            .parent()
            .and_then(std::path::Path::parent)
            .map(|profile| profile.join("saife.exe"))
            .expect("a profile directory above deps/");
        assert!(
            supervisor.is_file(),
            "build it first: cargo build --features mxc-backend --bin saife ({})",
            supervisor.display()
        );
        assert!(
            net::mxc::launcher_beside(&supervisor).is_some(),
            "saife-launch.exe must sit beside the supervisor: \
             cargo build --features mxc-backend --bin saife-launch"
        );
        // A spawned supervisor is evidence only if it was built from the sources
        // under test: `cargo test --bin saife` builds the TEST harness and leaves
        // `target/debug/saife.exe` alone, so a stale binary would answer for code
        // that has since changed — it inverted this very test's own RED probe.
        if let (Some(built), Some(source)) = (
            std::fs::metadata(&supervisor)
                .and_then(|m| m.modified())
                .ok(),
            newest_source_mtime(),
        ) {
            assert!(
                built >= source,
                "{} is older than src/: rebuild it first \
                 (`cargo build --features mxc-backend --bin saife`), or this run is \
                 measuring a binary that does not contain the code under test",
                supervisor.display()
            );
        }

        let scratch = std::env::temp_dir().join(format!("sandbox-s55-live-{}", std::process::id()));
        std::fs::create_dir_all(&scratch).expect("create the session working directory");
        let sid = chain_sid("s55-live");
        // A reused id would continue an existing chain and land a second root.
        drop_chain(&sid);

        let mut child = std::process::Command::new(&supervisor)
            .args([
                "run",
                "--backend",
                "mxc",
                // The posture S-55 runs: no listener, so no CONNECT leaf and no
                // endpoint to record — the root alone has to carry the session.
                "--block-net",
                "--allow-cwd",
                "--sid",
                &sid,
                "--",
                "cmd",
                "/c",
                // A workload that stays alive without a console, a network or an
                // interpreter the container may not have: S-55's own sleeper
                // (`python`) is not on the container's PATH, and `ping` cannot reach
                // the IP driver inside a `--block-net` container (both observed). A
                // counting loop runs for several seconds and exits on its own if the
                // kill somehow misses it.
                "for /l %i in (1,1,20000000) do @rem",
            ])
            .current_dir(&scratch)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn the supervisor");

        // Wait for the root the way a reader would — the file exists and carries a
        // SESSION_START. A minute is a container launch, not the assertion.
        let deadline = std::time::Instant::now() + Duration::from_secs(60);
        let mut root = None;
        while std::time::Instant::now() < deadline {
            root = chain_leaves(&sid)
                .into_iter()
                .find(|l| l["op"] == audit::session_start::OP_SESSION_START);
            if root.is_some() {
                break;
            }
            if let Ok(Some(status)) = child.try_wait() {
                panic!("the supervisor exited before writing a root: {status}");
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let root = root.expect("the root must be on disk while the child is still running");

        // The property, stated once: the root is on disk **because it was written
        // before the launch**, so the supervisor is still running when the kill
        // arrives. A supervisor that writes the root only after the launch returns
        // has nothing to show a kill — by the time the file exists the session is
        // over, which is what this assertion catches.
        std::thread::sleep(Duration::from_millis(500));
        assert!(
            child.try_wait().expect("poll the supervisor").is_none(),
            "the supervisor must still be running when it is killed; a root that only \
             appears once the launch returns is a root written after the session ended"
        );
        // Stop-Process -Force, as the harness does it.
        let killed = std::process::Command::new("taskkill")
            .args(["/F", "/PID", &child.id().to_string()])
            .output()
            .expect("run taskkill");
        assert!(killed.status.success(), "taskkill failed: {killed:?}");
        let _ = child.wait();

        let path = audit::audit_log_path(&sid);
        let leaves = chain_leaves(&sid);
        let sealed = path.with_extension("root").is_file();
        let verdict = verify_inner(&sid).unwrap();
        drop_chain(&sid);
        let _ = std::fs::remove_dir_all(&scratch);

        // The root the supervisor wrote before the child, with all five facts.
        assert_eq!(root["seq"], 0, "the root is the genesis leaf: {leaves:?}");
        assert_eq!(root["tier"], net::mxc::REQUIRED_TIER);
        assert_eq!(root["tier_source"], net::mxc::TIER_SOURCE_PROBE);
        assert_eq!(root["tier_needs_dacl_augmentation"], false);
        assert_eq!(root["elevated"], setup::is_elevated());
        assert_eq!(
            root["proxy_endpoint"],
            serde_json::Value::Null,
            "--block-net binds nothing, so the endpoint is null"
        );
        let roots = leaves
            .iter()
            .filter(|l| l["op"] == audit::session_start::OP_SESSION_START)
            .count();
        assert_eq!(roots, 1, "one root per run: {leaves:?}");
        assert!(!sealed, "a killed supervisor commits no root");
        match verdict {
            VerifyOutcome::Incomplete(reason) => assert!(
                reason.contains("no committed root"),
                "INCOMPLETE must name the missing seal: {reason}"
            ),
            other => panic!("a killed session must verify as INCOMPLETE, got {other:?}"),
        }
    }

    /// Unique temp dir per test (learned.rs's pattern) so the learned-CLI
    /// tests run in parallel without racing on a shared directory.
    fn learned_temp_dir(test_name: &str) -> std::path::PathBuf {
        let name = format!("sb-cli-learned-{}-{test_name}", std::process::id());
        let d = std::env::temp_dir().join(name);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn learned_list_missing_file_is_empty() {
        let tmp = learned_temp_dir("list-missing");
        let (rc, out, err) = learned_cmd_in(cli::LearnedSub::List, None, &tmp);
        assert_eq!(rc, 0);
        assert_eq!(out, "(no learned entries)\n");
        assert!(err.is_empty());

        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn learned_list_shows_host_scope_disposition_table() {
        let tmp = learned_temp_dir("list-table");
        {
            let mut store = net::learned::LearnedStore::load_in(&tmp, Some("t37")).unwrap();
            store.record("api.example.com", "host", true).unwrap();
            store.record("*.npmjs.org", "suffix", true).unwrap();
            store.record("evil.com", "host", false).unwrap();
        }
        let (rc, out, err) = learned_cmd_in(cli::LearnedSub::List, Some("t37"), &tmp);
        assert_eq!(rc, 0, "stderr: {err}");
        assert!(out.contains("HOST"), "header: {out}");
        assert!(out.contains("SCOPE"), "header: {out}");
        assert!(out.contains("DISPOSITION"), "header: {out}");
        // Stored representation: suffix entries keep their `*.` prefix.
        assert!(out.contains("api.example.com"), "allow host: {out}");
        assert!(out.contains("*.npmjs.org"), "suffix host: {out}");
        assert!(out.contains("suffix"), "scope: {out}");
        assert!(out.contains("evil.com"), "deny host: {out}");
        assert!(out.matches("allow").count() >= 2, "dispositions: {out}");
        assert!(out.matches("deny").count() >= 1, "dispositions: {out}");

        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn learned_revoke_removes_entry_and_persists() {
        let tmp = learned_temp_dir("revoke");
        {
            let mut store = net::learned::LearnedStore::load_in(&tmp, None).unwrap();
            store.record("api.example.com", "host", true).unwrap();
            store.record("evil.com", "host", false).unwrap();
        }
        let (rc, out, err) = learned_cmd_in(
            cli::LearnedSub::Revoke {
                host: "api.example.com".into(),
            },
            None,
            &tmp,
        );
        assert_eq!(rc, 0, "stderr: {err}");
        assert!(out.contains("revoked api.example.com"), "{out}");
        // The unrelated deny entry is untouched.
        let reloaded = net::learned::LearnedStore::load_in(&tmp, None).unwrap();
        assert!(reloaded.lookup("api.example.com").is_none());
        assert!(reloaded.lookup("evil.com").is_some_and(|d| !d.allow));

        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn learned_revoke_normalizes_input_like_the_store() {
        let tmp = learned_temp_dir("revoke-norm");
        {
            let mut store = net::learned::LearnedStore::load_in(&tmp, None).unwrap();
            store.record("api.example.com", "host", true).unwrap();
        }
        // Case + trailing dot are normalized the same way `record` does.
        let (rc, _out, err) = learned_cmd_in(
            cli::LearnedSub::Revoke {
                host: "API.Example.COM.".into(),
            },
            None,
            &tmp,
        );
        assert_eq!(rc, 0, "stderr: {err}");
        let reloaded = net::learned::LearnedStore::load_in(&tmp, None).unwrap();
        assert!(reloaded.lookup("api.example.com").is_none());

        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn learned_revoke_unknown_host_fails_loudly() {
        let tmp = learned_temp_dir("revoke-unknown");
        let (rc, out, err) = learned_cmd_in(
            cli::LearnedSub::Revoke {
                host: "nope.example.com".into(),
            },
            None,
            &tmp,
        );
        assert_eq!(rc, 1);
        assert!(out.is_empty());
        assert!(
            err.contains("no learned entry for nope.example.com"),
            "{err}"
        );

        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn learned_clear_empties_file() {
        let tmp = learned_temp_dir("clear");
        {
            let mut store = net::learned::LearnedStore::load_in(&tmp, None).unwrap();
            store.record("a.example.com", "host", true).unwrap();
            store.record("b.example.com", "host", false).unwrap();
        }
        let (rc, out, err) = learned_cmd_in(cli::LearnedSub::Clear, None, &tmp);
        assert_eq!(rc, 0, "stderr: {err}");
        assert!(out.is_empty());
        assert!(err.is_empty());
        let reloaded = net::learned::LearnedStore::load_in(&tmp, None).unwrap();
        assert!(reloaded.entries().is_empty());

        std::fs::remove_dir_all(&tmp).ok();
    }

    /// [G-5] corrupt-file recovery: a corrupt learned file hard-aborts
    /// `saife run`, and `clear` is the only non-editorial way out — so
    /// it must succeed even though the file cannot be loaded.
    #[test]
    fn learned_clear_resets_corrupt_file() {
        let tmp = learned_temp_dir("clear-corrupt");
        let path = net::learned::learned_file_path_in(&tmp, None);
        std::fs::create_dir_all(path.parent().unwrap()).ok();
        std::fs::write(&path, "}}} not json {{{").ok();
        // List proves the file is unreadable and the error points at the
        // recovery path.
        let (rc, _out, err) = learned_cmd_in(cli::LearnedSub::List, None, &tmp);
        assert_eq!(rc, 1);
        assert!(err.contains("saife learned clear"), "hint: {err}");
        // Clear is the recovery path and must succeed despite the corrupt file.
        let (rc, out, err) = learned_cmd_in(cli::LearnedSub::Clear, None, &tmp);
        assert_eq!(rc, 0, "stderr: {err}");
        assert!(out.is_empty() && err.is_empty());
        let reloaded = net::learned::LearnedStore::load_in(&tmp, None).unwrap();
        assert!(reloaded.entries().is_empty());

        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn learned_clear_missing_file_is_ok() {
        let tmp = learned_temp_dir("clear-missing");
        let (rc, out, err) = learned_cmd_in(cli::LearnedSub::Clear, None, &tmp);
        assert_eq!(rc, 0, "stderr: {err}");
        assert!(out.is_empty() && err.is_empty());

        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn learned_profile_selects_learned_file() {
        let tmp = learned_temp_dir("profile");
        {
            let mut store = net::learned::LearnedStore::load_in(&tmp, None).unwrap();
            store.record("api.example.com", "host", true).unwrap();
        }
        // default.json has one entry; the `dev` learned file does not exist.
        let (rc, out, err) = learned_cmd_in(cli::LearnedSub::List, Some("dev"), &tmp);
        assert_eq!(rc, 0, "stderr: {err}");
        assert_eq!(out, "(no learned entries)\n");
        let (rc, out, _err) = learned_cmd_in(cli::LearnedSub::List, None, &tmp);
        assert_eq!(rc, 0);
        assert!(out.contains("api.example.com"), "{out}");
        // Clearing the `dev` file must not touch default.json.
        let (rc, _out, err) = learned_cmd_in(cli::LearnedSub::Clear, Some("dev"), &tmp);
        assert_eq!(rc, 0, "stderr: {err}");
        let (rc, out, _err) = learned_cmd_in(cli::LearnedSub::List, None, &tmp);
        assert_eq!(rc, 0);
        assert!(out.contains("api.example.com"), "{out}");

        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn learned_invalid_profile_name_fails() {
        let tmp = learned_temp_dir("invalid-profile");
        let (rc, _out, err) = learned_cmd_in(cli::LearnedSub::List, Some("a/b"), &tmp);
        assert_eq!(rc, 1);
        assert!(!err.is_empty());
        let (rc, _out, err) = learned_cmd_in(cli::LearnedSub::Clear, Some("../escape"), &tmp);
        assert_eq!(rc, 1);
        assert!(!err.is_empty());

        std::fs::remove_dir_all(&tmp).ok();
    }

    // ---- Task 4.2: [G-10] upstream-proxy selection + [G-11] NO_PROXY ------

    /// A `select_upstream` / `host_no_proxy` env lookup over fixed pairs.
    /// Matching is case-insensitive on purpose: Windows reads the environment
    /// with `GetEnvironmentVariableW`, so one `HTTPS_PROXY` lookup also covers
    /// a `https_proxy` entry. The fake mirrors that.
    fn env_of<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |k| {
            pairs
                .iter()
                .find(|(kk, _)| kk.eq_ignore_ascii_case(k))
                .map(|(_, v)| (*v).to_string())
        }
    }

    #[test]
    fn select_upstream_profile_only() {
        let (chosen, warn, src) = select_upstream(
            Some("http://corp-proxy:8080"),
            env_of(&[("HTTPS_PROXY", "http://corp-proxy:8080")]),
        );
        assert_eq!(chosen.as_deref(), Some("http://corp-proxy:8080"));
        assert!(warn.is_none(), "equal values must not warn: {warn:?}");
        assert_eq!(src, Some(UpstreamSource::Profile));
    }

    #[test]
    fn select_upstream_env_only_prefers_https_proxy() {
        let (chosen, warn, src) = select_upstream(
            None,
            env_of(&[
                ("HTTPS_PROXY", "http://https-proxy:8080"),
                ("HTTP_PROXY", "http://http-proxy:8080"),
            ]),
        );
        assert_eq!(chosen.as_deref(), Some("http://https-proxy:8080"));
        assert!(
            warn.is_none(),
            "host-env-only detection is silent [G-42]: {warn:?}"
        );
        assert_eq!(src, Some(UpstreamSource::HostEnv));
    }

    #[test]
    fn select_upstream_env_only_falls_back_to_http_proxy() {
        let (chosen, warn, _src) =
            select_upstream(None, env_of(&[("HTTP_PROXY", "http://http-proxy:8080")]));
        assert_eq!(chosen.as_deref(), Some("http://http-proxy:8080"));
        assert!(warn.is_none());
    }

    #[test]
    fn select_upstream_none_when_nothing_is_set() {
        let (chosen, warn, _src) = select_upstream(None, env_of(&[]));
        assert!(chosen.is_none());
        assert!(warn.is_none());
    }

    #[test]
    fn select_upstream_blank_values_count_as_unset() {
        let (chosen, warn, _src) =
            select_upstream(None, env_of(&[("HTTPS_PROXY", "   "), ("HTTP_PROXY", "")]));
        assert!(chosen.is_none(), "blank proxy values must not be used");
        assert!(warn.is_none());
    }

    #[test]
    fn select_upstream_profile_over_env_warns_and_redacts() {
        let (chosen, warn, _src) = select_upstream(
            Some("http://alice:s3cret@profile-proxy:8080"),
            env_of(&[("HTTPS_PROXY", "http://bob:hunter2@env-proxy:3128")]),
        );
        // [G-10] the profile wins, and the caller gets the URL verbatim so it
        // can parse it (only diagnostics are redacted).
        assert_eq!(
            chosen.as_deref(),
            Some("http://alice:s3cret@profile-proxy:8080")
        );
        let warn = warn.expect("differing values must warn [G-42]");
        assert!(warn.contains("profile-proxy:8080"), "{warn}");
        assert!(warn.contains("env-proxy:3128"), "{warn}");
        for secret in ["s3cret", "hunter2", "alice", "bob"] {
            assert!(!warn.contains(secret), "warning leaked {secret:?}: {warn}");
        }
    }

    #[test]
    fn select_upstream_unparsable_values_still_warn_without_echoing_them() {
        let (chosen, warn, _src) = select_upstream(
            Some("https://profile-proxy:8443"),
            env_of(&[("HTTPS_PROXY", "http://env-proxy:3128")]),
        );
        assert_eq!(chosen.as_deref(), Some("https://profile-proxy:8443"));
        let warn = warn.expect("differing values must warn [G-42]");
        // No TLS-to-proxy: `https://` is unparsable here, so it is named by a
        // placeholder rather than echoed.
        assert!(warn.contains("(unparsable)"), "{warn}");
        assert!(!warn.contains("profile-proxy:8443"), "{warn}");
    }

    #[test]
    fn upstream_parse_failure_warning_names_the_profile_source_without_credentials() {
        let raw = "https://alice:s3cret@profile-proxy:8443";
        let e = net::upstream::ProxyUrl::parse(raw).expect_err("https is not a proxy scheme");
        let w = upstream_parse_failure_warning(UpstreamSource::Profile, raw, &e);
        assert!(w.contains("profile network.upstreamProxy"), "{w}");
        assert!(w.contains("(unparsable)"), "{w}");
        assert!(w.contains("unsupported upstream proxy scheme"), "{w}");
        assert!(w.contains("direct"), "{w}");
        for secret in ["alice", "s3cret", "profile-proxy:8443"] {
            assert!(!w.contains(secret), "warning leaked {secret:?}: {w}");
        }
    }

    #[test]
    fn upstream_parse_failure_warning_names_the_host_env_source() {
        let raw = "http://proxy.corp:notaport";
        let e = net::upstream::ProxyUrl::parse(raw).expect_err("port does not parse");
        let w = upstream_parse_failure_warning(UpstreamSource::HostEnv, raw, &e);
        assert!(w.contains("host HTTPS_PROXY/HTTP_PROXY"), "{w}");
        assert!(w.contains("(unparsable)"), "{w}");
        assert!(!w.contains("proxy.corp"), "{w}");
    }

    #[test]
    fn select_upstream_trailing_slash_is_not_a_difference() {
        // `http://p:8080` and `http://p:8080/` name the same endpoint, so the
        // [G-42] override notice must not fire for an "override" that changes
        // nothing.
        let (chosen, warn, _src) = select_upstream(
            Some("http://p:8080"),
            env_of(&[("HTTPS_PROXY", "http://p:8080/")]),
        );
        assert_eq!(chosen.as_deref(), Some("http://p:8080"));
        assert!(
            warn.is_none(),
            "equivalent endpoints must not warn: {warn:?}"
        );
    }

    #[test]
    fn host_no_proxy_blank_no_proxy_falls_through_to_the_lowercase_name() {
        // A *blank* `NO_PROXY` counts as unset, like every other env read
        // here (Windows routinely carries `NO_PROXY=`), so the lowercase
        // lookup must still be tried. Case-sensitive fake on purpose: the
        // real Windows lookup is case-insensitive, but the fallback logic is
        // what is under test.
        let env = |k: &str| match k {
            "NO_PROXY" => Some("   ".to_string()),
            "no_proxy" => Some("a.test, b.test".to_string()),
            _ => None,
        };
        assert_eq!(host_no_proxy(env), vec!["a.test", "b.test"]);
    }

    #[test]
    fn host_no_proxy_parses_comma_separated_entries() {
        let entries = host_no_proxy(env_of(&[("NO_PROXY", "a.test, b.test,,c.test ")]));
        assert_eq!(entries, vec!["a.test", "b.test", "c.test"]);
    }

    #[test]
    fn host_no_proxy_missing_is_empty() {
        assert!(host_no_proxy(env_of(&[])).is_empty());
        assert!(host_no_proxy(env_of(&[("NO_PROXY", "  ")])).is_empty());
    }

    /// P2.3 acceptance 1, at the production seam: the AppContainer backend's leaf
    /// facts are its identity (`appcontainer-dacl` / `structural`), never a probe
    /// result, and `elevated` is always known — the one fact a reader uses to tell
    /// an admin run from an unelevated one. Both survive an early death, because
    /// they are the facts the guard is armed with (review item 5).
    #[test]
    fn appcontainer_session_facts_name_the_dacl_tier_by_construction() {
        let facts = appcontainer_session_facts();
        assert_eq!(
            facts.tier().tier.as_deref(),
            Some(audit::session_start::TIER_APPCONTAINER_DACL)
        );
        assert_eq!(
            facts.tier().tier_source,
            Some(audit::session_start::TIER_SOURCE_STRUCTURAL),
            "this backend IS the tier; `probe` would claim a dispatch decision nobody made"
        );
        assert_eq!(
            facts.tier().needs_dacl_augmentation,
            Some(true),
            "the AC backend grants host DACLs by definition"
        );
        assert_eq!(
            facts.elevated(),
            Some(setup::is_elevated()),
            "`elevated` is this process's token, never guessed or defaulted"
        );
        assert!(
            facts.tier().tier.is_some() && facts.tier().tier_source.is_some(),
            "`tier` and `tier_source` travel together or not at all"
        );
    }

    /// P2.3 acceptance 4/5, at the production seam: the endpoint is the bare
    /// loopback authority of the listener this run bound, and `None` when
    /// `--block-net` bound nothing.
    ///
    /// The child's proxy URL (`http://sandbox:<token>@127.0.0.1:<port>`) is
    /// deliberately not what goes on the leaf: `LoopbackEndpoint` takes a `u16`
    /// and nothing else, so a credential cannot be passed at all (review item 3).
    #[test]
    fn the_session_endpoint_is_the_bare_loopback_authority_or_null() {
        let endpoint = audit::session_start::LoopbackEndpoint::new(63_123);
        assert_eq!(endpoint.to_string(), "127.0.0.1:63123");

        // What `complete` writes: the port the listener bound, or nothing.
        assert_eq!(
            appcontainer_session_facts()
                .with_endpoint(endpoint)
                .proxy_endpoint(),
            Some(endpoint)
        );
        assert_eq!(
            appcontainer_session_facts().proxy_endpoint(),
            None,
            "--block-net binds no listener, so there is no endpoint to record"
        );
        // The tier facts are recorded either way: a blocked session is still a
        // session with a containment posture, and an early death still names it.
        assert_eq!(
            appcontainer_session_facts().tier().tier.as_deref(),
            Some(audit::session_start::TIER_APPCONTAINER_DACL)
        );
    }
