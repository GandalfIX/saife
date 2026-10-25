// Extracted from src/net/mxc.rs `#[cfg(test)] mod tests` (2026-10-25), verbatim.
//
// The body keeps the one-level indentation it had inside the module - leading
// whitespace is legal at file scope, and a mechanical dedent would rewrite the
// contents of every multi-line raw string in here. Formatting, if wanted, is a
// separate change that must be reviewed as one.

    use super::*;
    use mxc_sdk::mxc_common::models::{ClipboardPolicy, NetworkAction};
    use std::collections::HashMap;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Stand-in launcher path: the mapping is pure, so it never has to exist.
    const TEST_LAUNCHER: &str = r"C:\tools\sandbox\saife-launch.exe";

    fn build(input: &MxcSessionInput) -> ExecutionRequest {
        build_request(input, Path::new(TEST_LAUNCHER)).expect("launchable request")
    }

    fn input() -> MxcSessionInput {
        MxcSessionInput {
            command: "cmd /c echo hi".to_string(),
            working_directory: Some(r"C:\work".to_string()),
            environment: vec![
                ("PATH".to_string(), r"C:\Windows".to_string()),
                ("TEMP".to_string(), r"C:\Temp".to_string()),
            ],
            filesystem: MxcFilesystemInput {
                readwrite_paths: vec![r"C:\work".to_string()],
                readonly_paths: vec![r"C:\ref".to_string()],
                denied_paths: vec![r"C:\Users\marku\.ssh".to_string()],
            },
            network: MxcNetworkInput {
                proxy_port: Some(54_321),
                proxy_token: None,
            },
            timeout_ms: Some(60_000),
            stdio: StdioSelection::Capture,
        }
    }

    fn tier() -> TierRecord {
        TierRecord {
            tier: Some("base-container".to_string()),
            tier_source: "probe",
            needs_dacl_augmentation: Some(false),
        }
    }

    /// A session clock for tests that are about the gate, not the budget: the
    /// default budget, no elapsed time, no prompt time. A kill under it classifies
    /// as a handshake timeout, which is what "no time was spent anywhere" means.
    fn clock() -> SessionClock {
        SessionClock::default()
    }

    fn child(wait: WaitResult) -> ChildRun {
        ChildRun {
            wait,
            stdout: b"hi\n".to_vec(),
            stderr: Vec::new(),
            warnings: Vec::new(),
        }
    }

    /// A launch whose wrapper probed and whose workload then did real work.
    fn proven() -> ProxyProof {
        ProxyProof {
            accepted: 1,
            tunnels: 1,
            probes: 1,
            unauthenticated: 0,
        }
    }

    fn untouched() -> ProxyProof {
        ProxyProof {
            accepted: 0,
            tunnels: 0,
            probes: 0,
            unauthenticated: 0,
        }
    }

    // ---- D1: launcher command construction -------------------------------

    #[test]
    fn launcher_command_puts_the_real_command_line_behind_the_wrapper() {
        let command = launcher_command(Path::new(TEST_LAUNCHER), "cmd /c echo hi", None);
        assert_eq!(
            command,
            format!(r#"{TEST_LAUNCHER} -- "cmd /c echo hi""#),
            "the real command line must travel as ONE quoted argument"
        );
    }

    /// P2.4: the discovery port rides the command line, before the `--`, so it is
    /// never part of the workload's single command-line argument.
    ///
    /// A proxy-less session omits the flag entirely (the wrapper then writes the
    /// variable empty rather than leaving an inherited value in place), which is
    /// the only shape that differs — the workload argument is unchanged.
    #[test]
    fn launcher_command_publishes_the_proxy_port_only_when_there_is_one() {
        assert_eq!(
            launcher_command(Path::new(TEST_LAUNCHER), "cmd /c echo hi", Some(49_152)),
            format!(r#"{TEST_LAUNCHER} --proxy-port 49152 -- "cmd /c echo hi""#),
        );
        assert_eq!(
            launcher_command(Path::new(TEST_LAUNCHER), "cmd /c echo hi", None),
            format!(r#"{TEST_LAUNCHER} -- "cmd /c echo hi""#),
            "no flag means the wrapper writes SAIFE_PROXY_PORT empty"
        );
        // The request's own command carries the port it will also put in
        // `networkProxy`: `input()` configures 54321 for both.
        let req = build(&input());
        assert!(
            req.script_code.contains("--proxy-port 54321"),
            "the port the proxy URL names must be the port the workload discovers: {}",
            req.script_code
        );
    }

    #[test]
    fn launcher_command_quotes_a_launcher_path_with_spaces() {
        let command = launcher_command(
            Path::new(r"C:\Program Files\sb\saife-launch.exe"),
            "x.exe",
            None,
        );
        assert_eq!(command, r#""C:\Program Files\sb\saife-launch.exe" -- x.exe"#);
    }

    #[test]
    fn launcher_command_survives_a_command_line_that_contains_quotes() {
        let real = r#"powershell.exe -Command "Start-Sleep -Seconds 1""#;
        let command = launcher_command(Path::new(TEST_LAUNCHER), real, None);
        assert_eq!(
            command,
            format!(r#"{TEST_LAUNCHER} -- "powershell.exe -Command \"Start-Sleep -Seconds 1\"""#)
        );
    }

    /// A golden-string test, **not** a round trip: it pins the exact text the
    /// quoting algorithm emits for each shape. A round-trip claim needs a parser
    /// (`shell32!CommandLineToArgvW`) this test does not call. The algorithm was
    /// fuzz-verified against that real parser at review time — 200k generated
    /// inputs, argv compared element by element, zero differences — so this test
    /// exists to catch an *edit* to the algorithm, not to re-prove its
    /// correctness.
    #[test]
    fn quoting_matches_the_documented_argv_rules() {
        assert_eq!(quote_windows_arg("simple"), "simple");
        assert_eq!(quote_windows_arg("a b"), "\"a b\"");
        assert_eq!(quote_windows_arg(""), "\"\"");
        // A quote inside the element is escaped, not dropped.
        assert_eq!(quote_windows_arg("a\"b"), "\"a\\\"b\"");
        // Backslashes before a quote are doubled; trailing ones before the
        // closing quote are doubled as well.
        assert_eq!(quote_windows_arg("a\\\"b"), "\"a\\\\\\\"b\"");
        assert_eq!(quote_windows_arg("a b\\"), "\"a b\\\\\"");
        assert_eq!(quote_windows_arg("a\\"), "a\\");
    }

    #[test]
    fn an_empty_command_is_refused_before_a_request_exists() {
        for blank in ["", "   ", "\t\n"] {
            let mut i = input();
            i.command = blank.to_string();
            assert_eq!(
                build_request(&i, Path::new(TEST_LAUNCHER)).expect_err("empty command"),
                RequestError::EmptyCommand,
                "{blank:?} must not become a container command"
            );
        }
    }

    #[test]
    fn a_nul_in_the_command_is_refused_before_a_request_exists() {
        let mut i = input();
        // This is what would silently become `cmd /c echo hi` for the child:
        // CreateProcessW stops at the NUL.
        i.command = "cmd /c echo hi\0 --injected".to_string();
        assert_eq!(
            build_request(&i, Path::new(TEST_LAUNCHER)).expect_err("NUL command"),
            RequestError::NulInCommand,
            "a NUL would truncate the command line at the OS boundary"
        );
    }

    #[test]
    fn request_for_reports_a_refused_command_as_a_typed_error() {
        let source = RecordingSource::default();
        let backend = MxcBackend::new(
            &source,
            Some(49_152),
            TEST_LAUNCHER,
            TierExpectation::Recorded,
        );
        let mut i = input();
        i.command = "  ".to_string();

        let err = backend.request_for(&i).expect_err("empty command");
        assert!(
            matches!(err, MxcError::Request(RequestError::EmptyCommand)),
            "got {err:?}"
        );
        // `launch` surfaces this text, so it must name the cause.
        assert!(err.to_string().contains("empty"), "got {err}");
    }

    #[test]
    fn the_launcher_directory_is_the_grant_a_caller_must_declare() {
        assert_eq!(
            launcher_grant(Path::new(TEST_LAUNCHER)).as_deref(),
            Some(r"C:\tools\sandbox")
        );
        assert_eq!(
            launcher_grant(Path::new("saife-launch.exe")),
            None,
            "a bare file name has no directory to grant"
        );
    }

    // ---- P0.2: request mapping -------------------------------------------

    #[test]
    fn request_carries_working_directory_and_timeout() {
        let req = build(&input());
        assert_eq!(req.working_directory, r"C:\work");
        assert_eq!(req.script_timeout, 60_000);
    }

    #[test]
    fn request_command_is_the_wrapper_not_the_workload() {
        let req = build(&input());
        assert_eq!(
            req.script_code,
            launcher_command(Path::new(TEST_LAUNCHER), "cmd /c echo hi", Some(54_321))
        );
        assert_ne!(req.script_code, "cmd /c echo hi");
        assert!(req.script_code.starts_with(TEST_LAUNCHER));
        assert!(
            req.script_code.ends_with(r#"-- "cmd /c echo hi""#),
            "the workload command line is the wrapper's single argument: {}",
            req.script_code
        );
    }

    #[test]
    fn request_selects_process_container_without_a_proxy_peer() {
        let req = build(&input());
        assert_eq!(
            req.containment,
            mxc_sdk::mxc_common::models::ContainmentBackend::ProcessContainer,
            "the session must be contained by the Windows process container"
        );
        // Identity-less deployment: allowedProxyPeer must stay unset, otherwise
        // the request is refused with `malformed_request`.
        assert!(
            req.policy.allowed_proxy_peer.is_none(),
            "allowedProxyPeer must never be set for an unpackaged proxy"
        );
    }

    #[test]
    fn request_denies_egress_by_default_and_routes_through_loopback_proxy() {
        let req = build(&input());
        let egress = req.policy.network_egress.as_ref().expect("egress");
        assert_eq!(egress.default, NetworkAction::Deny);
        let ingress = req.policy.network_ingress.as_ref().expect("ingress");
        assert_eq!(ingress.default, NetworkAction::Allow);
        assert_eq!(ingress.host_loopback, NetworkAction::Allow);
        assert_eq!(
            req.policy
                .network_proxy
                .address
                .as_ref()
                .map(|address| address.to_url())
                .as_deref(),
            Some("http://127.0.0.1:54321")
        );
    }

    #[test]
    fn request_without_a_proxy_keeps_loopback_closed() {
        let mut i = input();
        i.network.proxy_port = None;
        let req = build(&i);
        assert_eq!(
            req.policy
                .network_egress
                .as_ref()
                .map(|egress| egress.default),
            Some(NetworkAction::Deny)
        );
        let ingress = req.policy.network_ingress.as_ref().expect("ingress");
        assert_eq!(ingress.host_loopback, NetworkAction::Deny);
        assert!(
            req.policy.network_proxy.address.is_none(),
            "no proxy port => no networkProxy"
        );
    }

    /// Invariant 5 / ADR-0004: the host's proxy environment must never cross
    /// into the container. MXC injects its own proxy env; a host value would
    /// point the child at a proxy we do not control.
    #[test]
    fn host_proxy_env_is_never_copied_into_the_request() {
        let mut i = input();
        i.environment = vec![
            ("PATH".to_string(), r"C:\Windows".to_string()),
            (
                "HTTP_PROXY".to_string(),
                "http://host-proxy:3128".to_string(),
            ),
            (
                "HTTPS_PROXY".to_string(),
                "http://host-proxy:3128".to_string(),
            ),
            (
                "ALL_PROXY".to_string(),
                "socks5://host-proxy:1080".to_string(),
            ),
            ("NO_PROXY".to_string(), "example.com".to_string()),
            (
                "http_proxy".to_string(),
                "http://lower-host-proxy:3128".to_string(),
            ),
            (
                "https_proxy".to_string(),
                "http://lower-host-proxy:3128".to_string(),
            ),
            (
                "all_proxy".to_string(),
                "socks5://lower-host-proxy:1080".to_string(),
            ),
            ("no_proxy".to_string(), "localhost".to_string()),
            (
                "Http_Proxy".to_string(),
                "http://mixed-host-proxy:3128".to_string(),
            ),
        ];
        let req = build(&i);
        let env = req.env.as_ref().expect("explicit environment list");
        // Explicit set equality, not a re-run of the production predicate: this
        // fails for a leaked key *and* for a key the filter wrongly drops.
        let mut surviving: Vec<&str> = env
            .iter()
            .map(|entry| entry.split('=').next().unwrap_or(entry))
            .collect();
        surviving.sort_unstable();
        assert_eq!(surviving, ["PATH"], "exact surviving key set: {env:?}");
        // The allow-list still carries the legitimate entry, value included.
        assert!(
            env.iter().any(|entry| entry == r"PATH=C:\Windows"),
            "the allowed entry keeps its value: {env:?}"
        );
        assert_eq!(env.len(), 1, "only PATH should survive: {env:?}");
    }

    #[test]
    fn environment_is_always_an_explicit_list_never_none() {
        let mut i = input();
        i.environment.clear();
        let req = build(&i);
        assert_eq!(
            req.env.as_deref(),
            Some(&[][..]),
            "an empty allow-list must be explicit, not `None` (backend default)"
        );
        // D2: the profile default block is kept deliberately — the SDK strips
        // every proxy name from it before injecting ours.
        assert!(req.inherit_default_env);
    }

    #[test]
    fn declared_grants_are_carried_and_the_launcher_is_granted_automatically() {
        let req = build(&input());
        assert_eq!(req.policy.readwrite_paths, vec![r"C:\work".to_string()]);
        assert_eq!(
            req.policy.readonly_paths,
            vec![r"C:\ref".to_string(), r"C:\tools\sandbox".to_string()],
            "the caller's grants keep their order; the launcher's directory is appended"
        );
        assert_eq!(
            req.policy.denied_paths,
            vec![r"C:\Users\marku\.ssh".to_string()]
        );
    }

    // ---- D6: the config posture is pinned, not defaulted ------------------

    #[test]
    fn process_container_config_pins_every_field_explicitly() {
        let cfg = process_container_contract();
        assert_eq!(cfg.least_privilege.as_ref(), Some(&false));
        assert!(
            cfg.learning_mode.as_ref().is_none(),
            "learning mode is a discovery tool, not a containment posture"
        );
        assert_eq!(cfg.capabilities.as_ref(), Some(&Vec::new()));
        assert!(cfg.capture_denials.as_ref().is_none());
        assert!(cfg.filesystem.as_ref().is_none());
        assert!(cfg.network.as_ref().is_none());

        let ui = cfg.ui.as_ref().expect("the ui posture is always stated");
        assert_eq!(
            format!("{:?}", ui.isolation.as_ref()),
            "Some(Container)",
            "the desktop is isolated at the container level"
        );
        assert_eq!(ui.desktop_system_control.as_ref(), Some(&false));
        assert_eq!(ui.system_settings.as_ref(), Some(&"none".to_string()));
        assert_eq!(ui.ime.as_ref(), Some(&false));
    }

    /// Drift alarm, not a tautology: the pinned posture is asserted against the
    /// request that actually ships, so a parser change that silently substituted
    /// one of these values fails here.
    #[test]
    fn the_shipped_request_carries_the_pinned_process_container_posture() {
        let request = build(&input());
        let ui = &request.policy.base_process_ui;
        assert_eq!(ui.isolation, "container");
        assert!(!ui.desktop_system_control);
        assert_eq!(ui.system_settings, "none");
        assert!(!ui.ime);
        assert!(!request.policy.least_privilege_mode);
        assert!(request.policy.capabilities.is_empty());
        assert!(request.policy.capture_denials.is_none());
        assert!(request.policy.enumerate_paths.is_empty());
    }

    // ---- P3: the Win32k ban is a UI field, and its default is the trap -----

    /// The `processContainer.ui` block pinned above is the **job-object** knob
    /// (`isolation`, `desktopSystemControl`, `systemSettings`, `ime`). The
    /// Win32k ban is a different field — the cross-cutting `ContainerRequest::ui`
    /// — and leaving it unset is not "no opinion": the SDK resolves absence to
    /// `UiPolicy::default()`, which is `disable: true`, and the PSEC path turns
    /// that into `PROCESS_CREATION_MITIGATION_POLICY_WIN32K_SYSTEM_CALL_DISABLE`.
    /// A request that states nothing therefore ships the harshest posture.
    #[test]
    fn build_request_permits_win32k_but_keeps_clipboard_and_injection_closed() {
        let request = build(&input());
        let ui = &request.policy.ui;
        assert!(
            !ui.disable,
            "a Win32k ban makes every child that loads user32/gdi32/ole32 die at load"
        );
        assert_eq!(
            ui.clipboard,
            ClipboardPolicy::None,
            "clipboard stays default-deny"
        );
        assert!(!ui.injection, "input injection stays default-deny");
        assert!(
            request.policy.ui_specified,
            "the section must be SUPPLIED, not merely equal to the default: an absent ui is the \
             Win32k ban"
        );
    }

    /// Canary on the SDK default the explicit set above exists to escape.
    ///
    /// If this ever fails, `mxc-sdk` changed the trap: `UiPolicy::default()`
    /// stopped meaning "ban Win32k". Delete this canary and the explicit
    /// `request.ui` assignment in [`build_request`], then re-read the comment
    /// there and `docs/research/backends/process-container/clr-startup-failure.md` — the
    /// explicit set would then be pinning a posture the default already gives,
    /// and the "lost containment" note would be describing a default, not a
    /// choice.
    #[test]
    fn sdk_ui_policy_default_is_still_the_win32k_ban_we_explicitly_escape() {
        assert!(
            mxc_sdk::v1::UiPolicy::default().disable,
            "mxc-sdk changed UiPolicy::default() to disable = false: delete this canary and the \
             explicit request.ui in build_request"
        );
    }

    // ---- P3.4 (A): the stdio selection is data, and it maps 1:1 ----------

    /// The selection is a closed two-value decision, and each value names exactly
    /// one SDK mode. Pinned because the failure mode is silent: a session that
    /// asks for `Inherit` and gets pipes runs, exits 0, and cannot show a TUI.
    #[test]
    fn the_stdio_selection_names_the_sdk_mode_it_asks_for() {
        assert_eq!(StdioSelection::Capture.mode(), StdioMode::Pipes);
        assert_eq!(StdioSelection::Inherit.mode(), StdioMode::Inherit);
        assert!(StdioSelection::Capture.captures_output());
        assert!(
            !StdioSelection::Inherit.captures_output(),
            "inherited stdio has no streams to read: the launch must not build a capture path"
        );
    }

    /// The default is the CAPTURED mode, not the interactive one.
    ///
    /// Every pre-P3.4 caller (and every test fixture) leaves the field out, and a
    /// default of `Inherit` would silently move the child's output to a console
    /// nobody reads — the failure would be a missing `stdout`, not an error.
    #[test]
    fn a_session_input_defaults_to_captured_stdio() {
        assert_eq!(MxcSessionInput::default().stdio, StdioSelection::Capture);
        assert_eq!(
            build(&input()).script_code,
            build(&input()).script_code,
            "the request is stdio-independent: the mode is a launch decision"
        );
    }

    // ---- P0.3 / D3: guardrail 1, both legs -------------------------------

    /// `Required` passes on the wrapper's probe ALONE.
    ///
    /// This is the S-77/S-86/S-91 shape (2026-10-22): a network-enabled session
    /// whose workload makes no request at all — an intent roundtrip, a
    /// `cmd /c echo`, a raw 407 probe. `accepted == 0` and `tunnels == 0` there
    /// are not a missing path, they are a workload that never opened a socket,
    /// and refusing it refused a user who did nothing wrong.
    #[test]
    fn required_passes_on_the_wrapper_probe_alone() {
        verify_proxy_proof(
            ProxyProof {
                accepted: 0,
                tunnels: 0,
                probes: 1,
                unauthenticated: 0,
            },
            ProofExpectation::Required,
        )
        .expect("a probe of the listener's own control plane IS the evidence");
        // Traffic is recorded detail, never the gate: it does not replace the
        // probe, and it does not have to be there.
        verify_proxy_proof(proven(), ProofExpectation::Required)
            .expect("probe + traffic is the same proof plus coverage");
    }

    /// `Required` fails when the probe never arrived — however much traffic the
    /// epoch saw.
    ///
    /// A tunnel is a workload event: it can only exist if the child made a
    /// request, so it cannot answer "is the path broken?" for a child that made
    /// none. The probe is issued by the wrapper before the payload, so its
    /// absence means the path itself is broken (listener dead, loopback blocked,
    /// credential refused).
    #[test]
    fn required_fails_when_the_probe_never_arrived() {
        assert_eq!(
            verify_proxy_proof(untouched(), ProofExpectation::Required).expect_err("probes=0"),
            GuardError::ProbeUnmet
        );
        assert_eq!(
            verify_proxy_proof(
                ProxyProof {
                    accepted: 5,
                    tunnels: 2,
                    probes: 0,
                    unauthenticated: 0,
                },
                ProofExpectation::Required
            )
            .expect_err("probes=0"),
            GuardError::ProbeUnmet,
            "recorded traffic must not stand in for the probe"
        );
        assert!(
            GuardError::ProbeUnmet
                .to_string()
                .contains("proxy_probe_unmet"),
            "the refusal must name its own reason: {}",
            GuardError::ProbeUnmet
        );
    }

    /// `MustBeAbsent` + pass.
    #[test]
    fn must_be_absent_passes_only_when_the_proxy_was_never_consulted() {
        verify_proxy_proof(untouched(), ProofExpectation::MustBeAbsent)
            .expect("a blocked session that never reached the proxy is the proven case");
    }

    /// `MustBeAbsent` + fail.
    #[test]
    fn must_be_absent_fails_as_soon_as_the_proxy_is_consulted() {
        for proof in [
            ProxyProof {
                accepted: 1,
                tunnels: 0,
                probes: 0,
                unauthenticated: 0,
            },
            ProxyProof {
                accepted: 1,
                tunnels: 1,
                probes: 0,
                unauthenticated: 0,
            },
        ] {
            assert_eq!(
                verify_proxy_proof(proof, ProofExpectation::MustBeAbsent)
                    .expect_err("a consulted proxy must fail an offline session"),
                GuardError::ProxyConsultedUnexpectedly,
                "accepted={} tunnels={}",
                proof.accepted,
                proof.tunnels
            );
        }
    }

    #[test]
    fn the_expectation_follows_the_network_posture() {
        assert_eq!(
            ProofExpectation::for_network(Some(8080)),
            ProofExpectation::Required
        );
        assert_eq!(
            ProofExpectation::for_network(None),
            ProofExpectation::MustBeAbsent
        );
    }

    #[test]
    fn all_four_expectation_combinations_are_decided_by_the_gate() {
        // required+pass, required+fail, absent+pass, absent+fail.
        let cases = [
            (ProofExpectation::Required, proven(), true),
            // The S-77 shape: probed, and the workload made no request.
            (
                ProofExpectation::Required,
                ProxyProof {
                    accepted: 0,
                    tunnels: 0,
                    probes: 1,
                    unauthenticated: 0,
                },
                true,
            ),
            (
                ProofExpectation::Required,
                ProxyProof {
                    accepted: 1,
                    tunnels: 1,
                    probes: 0,
                    unauthenticated: 0,
                },
                false,
            ),
            (ProofExpectation::MustBeAbsent, untouched(), true),
            (
                ProofExpectation::MustBeAbsent,
                ProxyProof {
                    accepted: 0,
                    tunnels: 1,
                    probes: 0,
                    unauthenticated: 0,
                },
                false,
            ),
        ];
        for (expectation, proof, should_pass) in cases {
            assert_eq!(
                verify_proxy_proof(proof, expectation).is_ok(),
                should_pass,
                "{expectation:?} with accepted={} tunnels={}",
                proof.accepted,
                proof.tunnels
            );
        }
    }

    /// The silent-misconfiguration case: the SDK reported exit 0 with no
    /// warnings, yet the probe never arrived. Success must be impossible —
    /// and so is `accepted` traffic standing in for the probe.
    #[test]
    fn exited_zero_without_a_probe_is_an_error() {
        let err = gate_outcome(
            tier(),
            child(WaitResult::Exited(0)),
            ProxyProof {
                accepted: 1,
                tunnels: 1,
                probes: 0,
                unauthenticated: 0,
            },
            ProofExpectation::Required,
            clock(),
        )
        .expect_err("exit 0 must not mask a failed proof");
        assert!(matches!(
            err,
            MxcError::Unproven(ref refused) if refused.error == GuardError::ProbeUnmet
        ));
        // P3.0: the refusal still carries what the child did, so a refused session
        // is not a silent one.
        let MxcError::Unproven(refused) = err else {
            unreachable!("matched above")
        };
        assert_eq!(refused.outcome.exit_code, Some(0));
        assert!(
            !refused.outcome.success(),
            "an unproven outcome is not a success"
        );
    }

    #[test]
    fn exited_zero_with_a_proven_tunnel_is_a_success() {
        let outcome = gate_outcome(
            tier(),
            child(WaitResult::Exited(0)),
            proven(),
            ProofExpectation::Required,
            clock(),
        )
        .expect("proven launch");
        assert!(outcome.success());
        assert_eq!(outcome.exit_code, Some(0));
        assert!(!outcome.timed_out());
        assert_eq!(outcome.stdout, b"hi\n");
        assert!(outcome.stderr.is_empty());
        // Container warnings are carried for the audit trail, never as evidence
        // of reachability (ADR-0004): the proof below is what gates the launch.
        assert!(outcome.warnings.is_empty());
        assert_eq!(outcome.proxy_proof, proven());
        assert_eq!(outcome.expectation, ProofExpectation::Required);
        assert_eq!(outcome.tier.tier.as_deref(), Some("base-container"));
    }

    #[test]
    fn an_offline_session_that_stayed_offline_is_a_success() {
        let outcome = gate_outcome(
            tier(),
            child(WaitResult::Exited(0)),
            untouched(),
            ProofExpectation::MustBeAbsent,
            clock(),
        )
        .expect("a blocked session that never reached the proxy");
        assert!(outcome.success());
        assert_eq!(outcome.expectation, ProofExpectation::MustBeAbsent);
    }

    /// Hand-built success shape (exit 0, no timeout) with an unproven launch:
    /// `success()` must consult the proof, for either leg.
    #[test]
    fn success_shaped_outcome_without_a_proof_is_not_a_success() {
        let cases = [
            (ProofExpectation::Required, untouched()),
            (
                ProofExpectation::Required,
                ProxyProof {
                    accepted: 1,
                    tunnels: 0,
                    probes: 0,
                    unauthenticated: 0,
                },
            ),
            (
                ProofExpectation::MustBeAbsent,
                ProxyProof {
                    accepted: 1,
                    tunnels: 0,
                    probes: 0,
                    unauthenticated: 0,
                },
            ),
        ];
        for (expectation, proof) in cases {
            let outcome = SessionOutcome {
                exit_code: Some(0),
                timeout: None,
                stdout: Vec::new(),
                stderr: Vec::new(),
                warnings: Vec::new(),
                tier: tier(),
                proxy_proof: proof,
                expectation,
                clock: clock(),
            };
            assert!(
                !outcome.success(),
                "an unproven outcome ({expectation:?}, accepted={}, tunnels={}) must never \
                 report success",
                proof.accepted,
                proof.tunnels
            );
        }
    }

    #[test]
    fn non_zero_exit_is_carried_through_and_is_not_a_success() {
        let outcome = gate_outcome(
            tier(),
            child(WaitResult::Exited(3)),
            proven(),
            ProofExpectation::Required,
            clock(),
        )
        .expect("proven launch");
        assert_eq!(outcome.exit_code, Some(3));
        assert!(!outcome.success());
    }

    #[test]
    fn timed_out_child_maps_to_no_exit_code() {
        let outcome = gate_outcome(
            tier(),
            child(WaitResult::TimedOut),
            proven(),
            ProofExpectation::Required,
            clock(),
        )
        .expect("proven launch");
        assert!(outcome.timed_out());
        assert_eq!(
            outcome.timeout,
            Some(TimeoutReason::SessionHandshake),
            "a kill with no time spent in the workload or the prompt is a handshake timeout"
        );
        assert_eq!(outcome.exit_code, None);
        assert!(!outcome.success());
    }

    #[test]
    fn a_failed_proof_fails_even_a_timed_out_child() {
        let err = gate_outcome(
            tier(),
            child(WaitResult::TimedOut),
            untouched(),
            ProofExpectation::Required,
            clock(),
        )
        .expect_err("proof gate applies to every outcome");
        assert!(matches!(
            err,
            MxcError::Unproven(ref refused) if refused.error == GuardError::ProbeUnmet
        ));
        // The timeout label survives the refusal: a killed child is still labelled.
        let MxcError::Unproven(refused) = err else {
            unreachable!("matched above")
        };
        assert!(
            refused.outcome.timed_out(),
            "the carried outcome keeps its label"
        );
    }

    #[test]
    fn launch_without_a_proof_source_is_an_error_before_the_child_starts() {
        let err = MxcBackend::without_proof_source(
            Some(54_321),
            TEST_LAUNCHER,
            TierExpectation::Recorded,
        )
        .launch(&input(), ProofExpectation::Required)
        .expect_err("no proof source must refuse the launch");
        assert!(
            matches!(err, MxcError::Guard(GuardError::MissingProofSource)),
            "got {err:?}"
        );
    }

    // ---- D4: backend state + epoch lifecycle ----------------------------

    #[derive(Default)]
    struct RecordingSource {
        next: AtomicU64,
        /// The window that is open, if any: this fake enforces the same
        /// no-overlap contract the real `LaunchCounters` does (P1.4).
        active: Mutex<Option<u64>>,
        epochs: Mutex<Vec<u64>>,
        /// `(epoch, proof reads at close time)` — the read-then-close order is
        /// part of the contract, so it is recorded rather than assumed.
        closes: Mutex<Vec<(u64, u64)>>,
        reads: AtomicU64,
        proofs: Mutex<HashMap<u64, ProxyProof>>,
    }

    impl RecordingSource {
        fn set_proof(&self, epoch: u64, proof: ProxyProof) {
            self.proofs.lock().unwrap().insert(epoch, proof);
        }

        fn epochs(&self) -> Vec<u64> {
            self.epochs.lock().unwrap().clone()
        }

        fn closes(&self) -> Vec<(u64, u64)> {
            self.closes.lock().unwrap().clone()
        }
    }

    impl ProxyProofSource for RecordingSource {
        fn begin_launch(&self) -> Result<u64, EpochAlreadyOpen> {
            let mut active = self.active.lock().unwrap();
            if let Some(open) = *active {
                return Err(EpochAlreadyOpen { active: open });
            }
            let epoch = self.next.fetch_add(1, Ordering::SeqCst) + 1;
            *active = Some(epoch);
            self.epochs.lock().unwrap().push(epoch);
            Ok(epoch)
        }

        fn proof(&self, epoch: u64) -> ProxyProof {
            self.reads.fetch_add(1, Ordering::SeqCst);
            self.proofs
                .lock()
                .unwrap()
                .get(&epoch)
                .copied()
                .unwrap_or_default()
        }

        fn close_launch(&self, epoch: u64) {
            // Read-then-close ordering is part of the contract, so the read
            // count is captured before the window is released.
            let reads = self.reads.load(Ordering::SeqCst);
            let mut active = self.active.lock().unwrap();
            if *active == Some(epoch) {
                *active = None;
            }
            self.closes.lock().unwrap().push((epoch, reads));
        }
    }

    #[test]
    fn a_successful_run_opens_one_epoch_and_closes_it_after_reading_the_proof() {
        let source = RecordingSource::default();
        let (value, proof) = run_in_epoch(&source, || Ok::<_, MxcError>(7)).expect("body ran");
        assert_eq!(value, 7);
        assert_eq!(proof, untouched());
        assert_eq!(source.epochs(), vec![1]);
        // Closed exactly once, and only after the counters were read.
        assert_eq!(source.closes(), vec![(1, 1)]);
    }

    /// The defect D4 names: a `run` error must not abandon an open epoch.
    #[test]
    fn a_failed_run_still_closes_the_epoch() {
        let source = RecordingSource::default();
        let err = run_in_epoch(&source, || {
            Err::<(), _>(MxcError::Guard(GuardError::ProbeUnmet))
        })
        .expect_err("body failed");
        assert!(matches!(err, MxcError::Guard(GuardError::ProbeUnmet)));
        assert_eq!(source.epochs(), vec![1], "the epoch was opened");
        assert_eq!(
            source.closes().len(),
            1,
            "the epoch must be closed on the error path too: {:?}",
            source.closes()
        );
        assert_eq!(source.closes()[0].0, 1);
    }

    #[test]
    fn the_body_runs_while_the_epoch_is_open() {
        let source = RecordingSource::default();
        run_in_epoch(&source, || {
            assert_eq!(source.epochs(), vec![1], "opened before the child starts");
            assert!(
                source.closes().is_empty(),
                "not closed before the child ends"
            );
            Ok::<_, MxcError>(())
        })
        .expect("body ran");
    }

    #[test]
    fn a_panic_in_the_body_still_closes_the_epoch() {
        let source = RecordingSource::default();
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            run_in_epoch(&source, || -> Result<(), MxcError> { panic!("sdk bug") })
        }));
        assert!(outcome.is_err(), "the panic propagates");
        assert_eq!(
            source.closes().len(),
            1,
            "the guard closes the epoch while unwinding: {:?}",
            source.closes()
        );
    }

    /// `close_launch` is caller-supplied. A panic out of `EpochGuard::drop`
    /// while the body is already unwinding would abort the process; the guard
    /// catches it and lets the body's panic continue.
    #[test]
    fn a_panicking_close_does_not_abort_the_unwind() {
        struct PanickyClose;

        impl ProxyProofSource for PanickyClose {
            fn begin_launch(&self) -> Result<u64, EpochAlreadyOpen> {
                Ok(1)
            }

            fn proof(&self, _epoch: u64) -> ProxyProof {
                untouched()
            }

            fn close_launch(&self, _epoch: u64) {
                panic!("close_launch blew up");
            }
        }

        let source = PanickyClose;
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            run_in_epoch(&source, || -> Result<(), MxcError> { panic!("sdk bug") })
        }));
        assert!(
            outcome.is_err(),
            "the body's panic still propagates; the close's panic was swallowed"
        );
    }

    /// Each launch opens its own epoch, and a new epoch starts empty: the fake's
    /// proof for epoch 1 must not leak into the launch that opens epoch 2.
    ///
    /// The old form of this test opened an epoch by hand and then ran a launch:
    /// that sequence is exactly the overlap P1.4 now refuses, so the property is
    /// restated against the ids the fake assigns instead.
    #[test]
    fn a_new_epoch_does_not_inherit_an_earlier_launch_traffic() {
        let source = RecordingSource::default();
        source.set_proof(1, proven());
        let (_, first) = run_in_epoch(&source, || Ok::<_, MxcError>(())).expect("body ran");
        assert_eq!(first, proven(), "epoch 1 is the seeded one");
        let (_, second) = run_in_epoch(&source, || Ok::<_, MxcError>(())).expect("body ran");
        assert_eq!(
            second,
            untouched(),
            "epoch 2 starts empty even though epoch 1 saw a tunnel"
        );
        assert_eq!(source.epochs(), vec![1, 2]);
    }

    /// P1.4: a launch that would overlap an open epoch is refused by name,
    /// before the body runs, and leaves the open window alone.
    ///
    /// Without the refusal the second launch opened epoch 2 and the first
    /// launch's traffic was split silently between two windows.
    #[test]
    fn an_overlapping_launch_is_refused_and_leaves_the_open_window_alone() {
        let source = RecordingSource::default();
        let open = source.begin_launch().expect("the launch in flight");
        let err = run_in_epoch(&source, || Ok::<_, MxcError>(1))
            .expect_err("a second concurrent launch must be refused");
        match err {
            MxcError::Concurrency(e) => assert_eq!(
                e,
                EpochAlreadyOpen { active: open },
                "the refusal must name the open epoch"
            ),
            other => panic!("expected the named concurrency error, got {other:?}"),
        }
        assert!(
            err.to_string().contains("still open"),
            "the message must name the condition: {err}"
        );
        assert_eq!(
            source.epochs(),
            vec![open],
            "no epoch was opened for the refusal"
        );
        assert!(source.closes().is_empty(), "the open window was not closed");
        assert_eq!(
            source.active.lock().unwrap().as_ref(),
            Some(&open),
            "the launch in flight still owns the window"
        );
    }

    #[test]
    fn nothing_is_opened_when_the_launch_is_refused_up_front() {
        // No proof source at all.
        let _ = MxcBackend::without_proof_source(
            Some(54_321),
            TEST_LAUNCHER,
            TierExpectation::Recorded,
        )
        .launch(&input(), ProofExpectation::Required);

        // Unsatisfiable expectation: `Required` with no proxy port.
        let source = RecordingSource::default();
        let err = MxcBackend::new(&source, None, TEST_LAUNCHER, TierExpectation::Recorded)
            .launch(&input(), ProofExpectation::Required)
            .expect_err("Required without a proxy can never pass");
        assert!(
            matches!(err, MxcError::Guard(GuardError::RequiredWithoutProxy)),
            "got {err:?}"
        );
        assert!(
            source.epochs().is_empty(),
            "an unsatisfiable expectation must be refused before the child starts"
        );
        assert!(source.closes().is_empty());
    }

    #[test]
    fn the_backend_owns_the_proxy_port_and_the_budget() {
        let source = RecordingSource::default();
        // 300 + 650 + 50 = 1000 ms of session.
        let budget = SessionBudget::new(
            Duration::from_millis(300),
            Duration::from_millis(650),
            Duration::from_millis(50),
        );
        let backend = MxcBackend::new(
            &source,
            Some(49_152),
            TEST_LAUNCHER,
            TierExpectation::Recorded,
        )
        .with_budget(budget);
        let mut i = input();
        i.network.proxy_port = Some(1); // a caller-supplied lookalike
        i.timeout_ms = Some(999_999);

        let req = backend.request_for(&i).expect("launchable request");
        assert_eq!(
            network_proxy(&req).as_deref(),
            Some("http://127.0.0.1:49152"),
            "the request must point at the proxy this backend proves"
        );
        assert_eq!(req.script_timeout, 1_000, "the backend's budget wins");
        assert_eq!(backend.budget(), budget);
        assert_eq!(backend.proxy_port(), Some(49_152));
        assert_eq!(backend.launcher(), Path::new(TEST_LAUNCHER));
    }

    /// P2.1, item 4: **the supervisor path cannot ship an unbounded session.**
    ///
    /// `timeout_ms: None` (and `Some(0)`) is INFINITE in the SDK, and the old
    /// backend passed a caller's value through unchanged — so a supervisor that
    /// left the field unset launched a container with no deadline at all. The
    /// backend now owns the arithmetic and always writes `Some(..)`, and the value
    /// has to cover the whole session: prompt + workload + slack, never one term.
    #[test]
    fn the_supervisor_session_always_carries_a_deadline() {
        let source = RecordingSource::default();
        let backend = MxcBackend::new(
            &source,
            Some(49_152),
            TEST_LAUNCHER,
            TierExpectation::Recorded,
        );
        let mut i = input();
        i.timeout_ms = None; // the shape that used to ship an infinite session

        let req = backend.request_for(&i).expect("launchable request");
        let whole = PROMPT_BUDGET + WORKLOAD_BUDGET + SESSION_SLACK;
        let whole_ms = u32::try_from(whole.as_millis()).expect("budget fits u32 ms");
        assert_eq!(
            req.script_timeout, whole_ms,
            "an unbounded session must be impossible from the supervisor path"
        );
        // Not vacuous: the value is the SUM, so no single term can be mistaken for
        // the session's deadline (a 60 s prompt term would kill a working workload,
        // a 30 min workload term would kill an unanswered dialog's session).
        assert!(whole_ms > u32::try_from(PROMPT_BUDGET.as_millis()).unwrap());
        assert!(whole_ms > u32::try_from(WORKLOAD_BUDGET.as_millis()).unwrap());
        assert!(
            whole_ms > u32::try_from((PROMPT_BUDGET + WORKLOAD_BUDGET).as_millis()).unwrap(),
            "the slack must be strictly on top of both terms"
        );
    }

    /// The short-budget arithmetic of the same rule, and the reason the defaults are
    /// what they are: **a dialog may legitimately take 30 s**, so a session sized on
    /// a test-sized prompt term would kill a real workload. The deadline is the sum,
    /// which is strictly greater than prompt + workload.
    #[test]
    fn a_dialog_that_uses_its_whole_budget_does_not_kill_the_container() {
        // The short budget the test asks for: 300 ms of dialog, 200 ms of work,
        // 50 ms of slack.
        let budget = SessionBudget::new(
            Duration::from_millis(300),
            Duration::from_millis(200),
            Duration::from_millis(50),
        );
        assert_eq!(budget.session(), Duration::from_millis(550));
        assert_eq!(budget.timeout_ms(), 550);
        assert!(
            budget.session() > budget.prompt + budget.workload,
            "a session that spends BOTH terms in full must still be inside its deadline"
        );
        // A dialog that takes its whole 300 ms and a workload that then takes its
        // whole 200 ms = 500 ms, inside the 550 ms deadline: no kill.
        assert!(budget.session() >= Duration::from_millis(500));
        // Nothing was killed: when both terms were spent to the last millisecond the
        // session still had the slack left.
        assert!(budget.prompt + budget.workload < budget.session());
    }

    /// P2.1: the prompt time a session is judged on is its OWN — a listener that
    /// already served a launch must not hand its predecessor's spent dialog time to
    /// the next session, which would report a kill as `prompt_budget_exhausted` for a
    /// session that never prompted.
    #[test]
    fn the_session_prompt_time_is_the_delta_across_the_launch() {
        let before = Duration::from_secs(45);
        assert_eq!(
            prompt_wait_during(before, Duration::from_secs(50)),
            Duration::from_secs(5),
            "an earlier session's 45 s must not be attributed to this one"
        );
        assert_eq!(
            prompt_wait_during(before, before),
            Duration::ZERO,
            "a launch that never prompted has spent no prompt time"
        );
        assert_eq!(
            prompt_wait_during(Duration::from_secs(50), Duration::from_secs(45)),
            Duration::ZERO,
            "a clock that went backwards must credit zero, never an underflow"
        );
    }

    /// P2.1: a workload that exceeds its budget is killed and reported with a reason
    /// **distinct** from a spent prompt budget and from a session-handshake timeout.
    #[test]
    fn a_workload_overrun_is_reported_distinctly_from_a_prompt_or_handshake_timeout() {
        let budget = fixture_budget();

        // The workload ran the clock out with no prompt in the way.
        let workload = budget.classify(&SessionClock::measured(
            budget,
            Duration::from_secs(720),
            Duration::from_millis(200),
            Duration::ZERO,
        ));
        // Dialogs ate their 60 s term plus the slack, so the workload never got the
        // 600 s it was entitled to.
        let prompt = budget.classify(&SessionClock::measured(
            budget,
            Duration::from_secs(720),
            Duration::from_millis(200),
            Duration::from_secs(180),
        ));
        // The session ended long before either term could have been spent.
        let handshake = budget.classify(&SessionClock::measured(
            budget,
            Duration::from_secs(120),
            Duration::from_millis(200),
            Duration::ZERO,
        ));

        assert_eq!(workload, TimeoutReason::WorkloadBudgetExceeded);
        assert_eq!(prompt, TimeoutReason::PromptBudgetExhausted);
        assert_eq!(handshake, TimeoutReason::SessionHandshake);

        let mut reasons = vec![workload.as_str(), prompt.as_str(), handshake.as_str()];
        reasons.sort_unstable();
        reasons.dedup();
        assert_eq!(
            reasons.len(),
            3,
            "the three deadline causes must be three distinct reasons: {reasons:?}"
        );
        assert_eq!(workload.as_str(), "workload_budget_exceeded");
        assert_eq!(handshake.as_str(), "session_handshake_timeout");
        // The prompt cause shares its vocabulary with the proxy's deny reason for the
        // same term: a consumer reading either side names the budget, not the layer.
        assert_eq!(prompt.as_str(), crate::net::proxy::PROMPT_TIMEOUT_REASON);

        // And a session that is killed with time left on the workload term is not
        // reported as a workload overrun — the distinction is not vacuous.
        assert_ne!(workload, handshake);
    }

    /// The 60 s / 600 s / 60 s budget the attribution tests are written against: a
    /// deadline of 720 s, where "the workload was starved" and "the prompt term ate
    /// the slack" are the same statement.
    fn fixture_budget() -> SessionBudget {
        SessionBudget::new(
            Duration::from_secs(60),
            Duration::from_secs(600),
            Duration::from_secs(60),
        )
    }

    /// **Item 1b: the label requires deprivation.** A prompt label is a claim that
    /// the workload did not get the time it was entitled to — not that some dialog
    /// spent "more than its term". Two sessions with the SAME prompt aggregate are
    /// labelled differently depending on whether the workload was starved, which is
    /// the property that makes the prompt branch subordinate to the workload's.
    #[test]
    fn the_prompt_term_is_named_only_when_the_workload_was_starved() {
        let budget = fixture_budget();

        // One 720 s session, two prompt aggregates, and the label follows the
        // starvation rather than the aggregate's size relative to the term:
        // 100 s of prompt time leaves the workload 620 s of its 600 s term, so the
        // deadline it hit was its own.
        let had_its_time = SessionClock::measured(
            budget,
            Duration::from_secs(720),
            Duration::from_millis(200),
            Duration::from_secs(100),
        );
        assert_eq!(
            had_its_time.timeout_reason(),
            TimeoutReason::WorkloadBudgetExceeded,
            "the workload got its full 600 s: the prompt term is not to blame"
        );

        // 200 s of prompt time leaves it 520 s — 80 s short of its term — so the
        // session ended because of the dialogs, even though the prompt term is six
        // times what such a dialog is allowed to take (P2.1's point: the aggregate
        // is not a share, and the workload's deprivation is what decides).
        let starved = SessionClock::measured(
            budget,
            Duration::from_secs(720),
            Duration::from_millis(200),
            Duration::from_secs(200),
        );
        assert_eq!(
            starved.timeout_reason(),
            TimeoutReason::PromptBudgetExhausted,
            "520 s of workload time against a 600 s term: dialogs are why it ended"
        );
        assert_ne!(
            had_its_time.timeout_reason(),
            starved.timeout_reason(),
            "the two differ only in the prompt aggregate"
        );
    }

    /// **Item 1a + 1c: the aggregate is a sum over requests, so it is clamped and a
    /// saturated value is not evidence.** The measured over-count was 5.90x (six
    /// connections, one host) and 7.87x (eight hosts): `prompt_wait` said 4700 s in a
    /// 600 s session. That number must not become a prompt verdict.
    #[test]
    fn a_prompt_measurement_larger_than_the_session_is_clamped_and_blames_no_prompt() {
        let budget = fixture_budget();
        let raw = Duration::from_secs(4700); // 7.83x the session it happened in
        let clock = SessionClock::measured(
            budget,
            Duration::from_secs(720),
            Duration::from_millis(200),
            raw,
        );

        assert_eq!(
            clock.prompt_wait,
            Duration::from_secs(720),
            "the carried measurement is clamped to the session: a reader must not see \
             more prompt time than wall clock"
        );
        let reason = clock.timeout_reason();
        assert_ne!(
            reason,
            TimeoutReason::PromptBudgetExhausted,
            "a saturated aggregate is the fingerprint of the over-count, not a verdict"
        );
        assert_eq!(reason, TimeoutReason::WorkloadBudgetExceeded);

        // The clamp is not vacuous: a plausible aggregate on a session whose
        // workload was starved DOES produce a prompt verdict.
        let plausible = SessionBudget::new(
            Duration::from_secs(60),
            Duration::from_secs(300),
            Duration::from_secs(60),
        );
        assert_eq!(
            SessionClock::measured(
                plausible,
                Duration::from_secs(420),
                Duration::from_millis(200),
                Duration::from_secs(200)
            )
            .timeout_reason(),
            TimeoutReason::PromptBudgetExhausted
        );
    }

    /// **Item 2: the handshake is observable and decides first — when it deprived the
    /// workload.** A container that hangs at create/prove used to be recorded as the
    /// operator's workload overrunning, because `elapsed` was measured around the whole
    /// run and therefore always exceeded `prompt + workload`. With the handshake
    /// measured separately (launch start → container ready) a create that outlived the
    /// allowance `slack` exists to provide for it AND left less than the workload's
    /// term is the handshake's failure (round 2, item 6 tightened that second half;
    /// `the_handshake_term_is_named_only_when_it_starved_the_workload` is the pair).
    ///
    /// The clock is the session's own deadline: this fixture's budget is 60 + 600 + 60,
    /// so 720 s is the longest a session under it can run, and a clock claiming more
    /// would be a measurement bug rather than a case to classify.
    #[test]
    fn a_stalled_handshake_is_reported_as_a_handshake_timeout() {
        let budget = fixture_budget();
        let stalled = SessionClock::measured(
            budget,
            Duration::from_secs(720),
            Duration::from_secs(300), // > the 60 s slack, i.e. the create ate the session
            Duration::ZERO,
        );
        assert_eq!(
            stalled.timeout_reason(),
            TimeoutReason::SessionHandshake,
            "the container never became ready in time: the workload never got a chance"
        );
        assert_ne!(
            stalled.timeout_reason(),
            TimeoutReason::WorkloadBudgetExceeded,
            "a supervisor/container failure must not be recorded as the command's"
        );
        assert_eq!(
            stalled.timeout_reason().as_str(),
            "session_handshake_timeout"
        );

        // And the label is not vacuous: the same session with a handshake that
        // finished inside its allowance is the workload's overrun.
        let ready = SessionClock::measured(
            budget,
            Duration::from_secs(720),
            Duration::from_millis(180),
            Duration::ZERO,
        );
        assert_eq!(
            ready.timeout_reason(),
            TimeoutReason::WorkloadBudgetExceeded
        );
    }

    /// **Round 2, item 6: the handshake arm is DEPRIVATION-based, like the prompt
    /// one.** `handshake_elapsed > slack` alone misdirects the remedy when both are
    /// true: a 130 s create followed by a workload that then used its whole 600 s
    /// term is the operator's command overrunning, and calling it
    /// `session_handshake_timeout` sends the reader after a container that started
    /// perfectly well.
    #[test]
    fn the_handshake_term_is_named_only_when_it_starved_the_workload() {
        let budget = fixture_budget(); // prompt 60 + workload 600 + slack 60

        // Slow create (130 s, over the slack) AND the workload spent its whole term
        // on top of it: 730 - 130 = 600, i.e. nothing was taken from the command.
        let overran = SessionClock::measured(
            budget,
            Duration::from_secs(730),
            Duration::from_secs(130),
            Duration::ZERO,
        );
        assert_eq!(
            overran.timeout_reason(),
            TimeoutReason::WorkloadBudgetExceeded,
            "the command got its full 600 s after the create: the handshake ate nothing"
        );

        // Same slow create, but the workload never got its entitlement.
        let starved = SessionClock::measured(
            budget,
            Duration::from_secs(730),
            Duration::from_secs(300),
            Duration::ZERO,
        );
        assert_eq!(
            starved.timeout_reason(),
            TimeoutReason::SessionHandshake,
            "430 s of workload time against a 600 s term, and the create is why"
        );
        assert_ne!(overran.timeout_reason(), starved.timeout_reason());
    }

    /// **Round 2, item 7: teardown is measured, and a deadline that went on cleanup
    /// is a SUPERVISOR fault.** `elapsed` spans create + run + teardown, but only
    /// create was measured, so a teardown that ate the deadline was reported as the
    /// operator's command overrunning - the one label the operator cannot act on.
    #[test]
    fn a_deadline_spent_on_teardown_is_its_own_supervisor_side_reason() {
        let budget = fixture_budget();

        // 1 s create, the command ran 500 s and exited, then 190 s of teardown:
        // 691 s elapsed, of which 190 s is cleanup (over the 60 s slack) and the
        // command never approached its 600 s term.
        let cleanup = SessionClock::measured(
            budget,
            Duration::from_secs(691),
            Duration::from_secs(1),
            Duration::ZERO,
        )
        .with_teardown(Duration::from_secs(190));
        assert_eq!(cleanup.teardown_elapsed, Duration::from_secs(190));
        assert_eq!(
            cleanup.timeout_reason(),
            TimeoutReason::SessionTeardown,
            "the command finished at 501 s: cleanup is what ran the clock out"
        );
        assert_eq!(
            cleanup.timeout_reason().as_str(),
            "session_teardown_timeout"
        );

        // The same 691 s with an ordinary teardown IS the command's overrun: the
        // label follows the measurement, not the total.
        let ordinary = SessionClock::measured(
            budget,
            Duration::from_secs(691),
            Duration::from_secs(1),
            Duration::ZERO,
        )
        .with_teardown(Duration::from_secs(2));
        assert_ne!(
            ordinary.timeout_reason(),
            TimeoutReason::SessionTeardown,
            "a 2 s teardown is not why a 691 s session ended"
        );

        // And the four arms stay four distinct labels.
        let mut arms: Vec<&str> = [
            TimeoutReason::WorkloadBudgetExceeded,
            TimeoutReason::PromptBudgetExhausted,
            TimeoutReason::SessionHandshake,
            TimeoutReason::SessionTeardown,
        ]
        .iter()
        .map(|reason| reason.as_str())
        .collect();
        arms.sort_unstable();
        arms.dedup();
        assert_eq!(
            arms.len(),
            4,
            "each deadline cause keeps its own reason: {arms:?}"
        );
    }

    /// **Item 2: the measurements ride on the outcome**, so the label can be checked
    /// against its own inputs — and both cases above are reachable through the real
    /// mapping (`gate_outcome`), not only through `classify`.
    #[test]
    fn a_killed_session_carries_the_measurements_its_label_came_from() {
        let budget = fixture_budget();
        let stalled = SessionClock::measured(
            budget,
            Duration::from_secs(720),
            Duration::from_secs(300),
            Duration::from_secs(10),
        );
        let outcome = gate_outcome(
            tier(),
            child(WaitResult::TimedOut),
            proven(),
            ProofExpectation::Required,
            stalled,
        )
        .expect("a timed-out launch still has to pass guardrail 1");
        assert_eq!(outcome.timeout, Some(TimeoutReason::SessionHandshake));
        assert_eq!(outcome.clock.elapsed, Duration::from_secs(720));
        assert_eq!(outcome.clock.handshake_elapsed, Duration::from_secs(300));
        assert_eq!(outcome.clock.prompt_wait, Duration::from_secs(10));
        assert_eq!(
            outcome.clock.timeout_reason(),
            outcome.timeout.unwrap(),
            "the carried label must be exactly what the carried measurements produce"
        );

        // The long-workload half: same shape, a handshake that finished promptly.
        let ready = SessionClock::measured(
            budget,
            Duration::from_secs(720),
            Duration::from_millis(180),
            Duration::from_secs(5),
        );
        let outcome = gate_outcome(
            tier(),
            child(WaitResult::TimedOut),
            proven(),
            ProofExpectation::Required,
            ready,
        )
        .expect("proven launch");
        assert_eq!(outcome.timeout, Some(TimeoutReason::WorkloadBudgetExceeded));
        assert_eq!(outcome.clock.handshake_elapsed, Duration::from_millis(180));
        assert_eq!(outcome.clock.prompt_wait, Duration::from_secs(5));
        assert_eq!(outcome.clock.elapsed, Duration::from_secs(720));
    }

    /// **Item 6: the defaults agree by construction.** The production budget is
    /// `from_config` of the same constants the resolver applies as defaults, so a
    /// wiring mistake cannot silently reserve the DEFAULT prompt term while the
    /// dialog gets a resolved one.
    #[test]
    fn the_default_budget_is_the_config_defaults_through_from_config() {
        assert_eq!(
            PROMPT_BUDGET,
            Duration::from_secs(u64::from(crate::net::prompt::DEFAULT_PROMPT_TIMEOUT_SECS)),
            "the prompt term must be the profile default, in seconds"
        );
        assert_eq!(
            WORKLOAD_BUDGET,
            Duration::from_secs(u64::from(crate::net::DEFAULT_WORKLOAD_TIMEOUT_SECS)),
            "the workload term must be the profile default, in seconds"
        );
        assert_eq!(
            SessionBudget::default(),
            SessionBudget::from_config(
                crate::net::prompt::DEFAULT_PROMPT_TIMEOUT_SECS,
                crate::net::DEFAULT_WORKLOAD_TIMEOUT_SECS,
                SESSION_SLACK
            ),
            "Default and the resolved-config constructor must be the same budget"
        );
        // The terms a default profile resolves to, spelled out: 60 s + 30 min + 2 min.
        assert_eq!(
            SessionBudget::default().session(),
            Duration::from_secs(60 + 1800 + 120)
        );
        assert_eq!(SessionBudget::default().timeout_ms(), 1_980_000);
        // A raised profile is bigger in both terms, and still a finite u32 deadline.
        let raised = SessionBudget::from_config(300, 5400, SESSION_SLACK);
        assert_eq!(raised.prompt, Duration::from_secs(300));
        assert_eq!(raised.workload, Duration::from_secs(5400));
        assert_eq!(raised.session(), Duration::from_secs(300 + 5400 + 120));
        assert_eq!(raised.timeout_ms(), 5_820_000);
        assert!(raised.session() > SessionBudget::default().session());
        assert!(
            raised.timeout_ms() > 0,
            "a raised budget must still be expressible as timeout_ms"
        );
    }

    #[test]
    fn the_backend_and_its_proof_source_are_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>(_: &T) {}
        fn assert_trait_object(_: &(dyn ProxyProofSource + Send + Sync)) {}

        let source = RecordingSource::default();
        let backend = MxcBackend::new(&source, Some(1), TEST_LAUNCHER, TierExpectation::Recorded);
        assert_send_sync(&backend);
        assert_send_sync(&source);
        assert_trait_object(&source);
    }

    // ---- P0.4: guardrail 2 ----------------------------------------------

    #[test]
    fn a_probed_tier_is_recorded_with_source_probe() {
        let record = tier_record(ProbeView {
            tier: Some("base-container"),
            needs_dacl_augmentation: Some(false),
        });
        assert_eq!(record.tier.as_deref(), Some("base-container"));
        assert_eq!(record.tier_source, "probe");
        assert_eq!(record.needs_dacl_augmentation, Some(false));
    }

    #[test]
    fn dacl_augmentation_is_recorded_when_the_probe_reports_it() {
        let record = tier_record(ProbeView {
            tier: Some("appcontainer-dacl"),
            needs_dacl_augmentation: Some(true),
        });
        assert_eq!(record.tier.as_deref(), Some("appcontainer-dacl"));
        assert_eq!(record.needs_dacl_augmentation, Some(true));
    }

    #[test]
    fn an_unnameable_tier_is_recorded_as_unavailable_not_as_a_ceiling() {
        let record = tier_record(ProbeView {
            tier: None,
            needs_dacl_augmentation: None,
        });
        assert_eq!(record.tier, None);
        assert_eq!(record.tier_source, "unavailable");
        // A probe that declined to state it must not be recorded as `false`.
        assert_eq!(record.needs_dacl_augmentation, None);
    }

    // ---- P2.3: guardrail 2's hard half (tier requirement) -----------------

    #[test]
    fn a_dispatched_tier_that_matches_the_requirement_passes_the_gate() {
        let record = tier_record(ProbeView {
            tier: Some("base-container"),
            needs_dacl_augmentation: Some(false),
        });
        assert_eq!(
            verify_tier(&record, TierExpectation::Exactly(REQUIRED_TIER)),
            Ok(())
        );
        // `Recorded` never refuses: measurements have no requirement to make.
        assert_eq!(
            verify_tier(&record, TierExpectation::Recorded).map_err(|e| e.observed),
            Ok(())
        );
    }

    /// The ADR's product rule: a wrong tier is a REFUSED session. The refusal
    /// names both tiers and its source, because "refused" without "instead of
    /// what" is not actionable.
    #[test]
    fn a_degraded_tier_is_refused_and_the_refusal_names_both_tiers() {
        let record = tier_record(ProbeView {
            tier: Some("appcontainer-dacl"),
            needs_dacl_augmentation: Some(true),
        });
        let refusal = verify_tier(&record, TierExpectation::Exactly(REQUIRED_TIER))
            .expect_err("a degraded tier must be refused when base-container is required");
        assert_eq!(refusal.expected, "base-container");
        assert_eq!(refusal.observed.as_deref(), Some("appcontainer-dacl"));
        assert_eq!(refusal.source, "probe");
        let text = refusal.to_string();
        assert!(text.contains("guardrail 2"), "{text}");
        assert!(text.contains("`base-container`"), "{text}");
        assert!(text.contains("`appcontainer-dacl`"), "{text}");
        // The MxcError wrapper keeps the detail reachable.
        let err: MxcError = refusal.clone().into();
        assert!(matches!(err, MxcError::Tier(_)), "{err:?}");
    }

    /// A requirement that cannot be shown to be met is not met. A literal
    /// `observed != expected` check would let a silent probe through, which is the
    /// one case a degraded dispatch is most likely to produce.
    #[test]
    fn a_probe_that_names_no_tier_is_refused_by_a_requirement() {
        let record = tier_record(ProbeView {
            tier: None,
            needs_dacl_augmentation: None,
        });
        let refusal = verify_tier(&record, TierExpectation::Exactly(REQUIRED_TIER))
            .expect_err("an unnamed tier cannot satisfy a requirement");
        assert_eq!(refusal.observed, None);
        assert_eq!(refusal.source, "unavailable");
        assert!(refusal.to_string().contains("no tier"), "{refusal}");
    }

    /// The backend's requirement is what decides, not a global constant: a backend
    /// constructed with `Exactly(REQUIRED_TIER)` refuses, and `Recorded` is a
    /// **deliberate, named** opt-out for a measurement (P2.3 review, item 1).
    ///
    /// The opt-out is legitimate and narrow: a probe or a spike wants to record
    /// what dispatched. What was not legitimate is that `Recorded` was the
    /// *default* — see [`the_supervisor_seam_refuses_a_degraded_tier`].
    #[test]
    fn the_backends_declared_tier_expectation_is_what_the_gate_applies() {
        let source = RecordingSource::default();
        let degraded = tier_record(ProbeView {
            tier: Some("appcontainer-dacl"),
            needs_dacl_augmentation: Some(true),
        });

        let requiring = MxcBackend::new(
            &source,
            Some(49_152),
            TEST_LAUNCHER,
            TierExpectation::Exactly(REQUIRED_TIER),
        );
        assert_eq!(
            requiring.tier_expectation(),
            TierExpectation::Exactly(REQUIRED_TIER),
            "the constructor's argument is what the gate applies"
        );
        let refusal = requiring
            .tier_gate(&degraded)
            .expect_err("a base-container session must not accept a degraded dispatch");
        assert_eq!(refusal.observed.as_deref(), Some("appcontainer-dacl"));

        let recording = MxcBackend::new(
            &source,
            Some(49_152),
            TEST_LAUNCHER,
            TierExpectation::Recorded,
        );
        assert_eq!(
            recording.tier_expectation(),
            TierExpectation::Recorded,
            "the deliberate measurement opt-out, named at the call site"
        );
        assert_eq!(
            recording.tier_gate(&degraded),
            Ok(()),
            "a measurement states `Recorded` on purpose and is not refused"
        );
    }

    /// P3.0 decision 3: the seam the supervisor calls carries the **resolved**
    /// budget, not [`SessionBudget::default`].
    ///
    /// Red before the fix: a `launch_session` that built its backend without a
    /// budget shipped the config DEFAULTS, so a profile with longer `limits`
    /// terms got a container deadline that under-reserved it — the very kill P2.1 exists to prevent, reported against
    /// the wrong term. The assertion is equality against a budget that differs
    /// from the default in every field, so "the default happened to match" cannot
    /// pass it.
    #[test]
    fn the_supervisor_seam_carries_the_resolved_budget() {
        let source = RecordingSource::default();
        let budget = SessionBudget::new(
            Duration::from_secs(7),
            Duration::from_secs(11),
            Duration::from_secs(3),
        );
        assert_ne!(
            budget,
            SessionBudget::default(),
            "the fixture must differ from the default or this test cannot fail"
        );
        let seam = supervisor_backend(
            &source,
            Some(49_152),
            Some("token"),
            Path::new(TEST_LAUNCHER),
            budget,
        );
        assert_eq!(seam.budget(), budget);
        let request = seam.request_for(&input()).expect("request");
        assert_eq!(
            request.script_timeout,
            budget.timeout_ms(),
            "the container's deadline is the resolved budget, never a default"
        );
    }

    /// P3.0 decision 3 (the other half): [`request_for_session`] describes the
    /// request the launch will dispatch, so the tier the leaf is armed with is the
    /// tier of the request that runs.
    ///
    /// A lookalike request would still *pass* guardrail 2 locally while the leaf
    /// named a tier the launched request never dispatched to — which is why the
    /// probe must come from this function and not from a hand-built request.
    #[test]
    fn request_for_session_is_the_request_the_launch_will_dispatch() {
        let source = RecordingSource::default();
        let budget = SessionBudget::new(
            Duration::from_secs(5),
            Duration::from_secs(9),
            Duration::from_secs(1),
        );
        let input = input();
        let request = request_for_session(
            &source,
            Some(49_001),
            Some("run-token"),
            Path::new(TEST_LAUNCHER),
            budget,
            &input,
        )
        .expect("the session's request");

        assert_eq!(request.script_timeout, budget.timeout_ms());
        let network = format!("{:?}", request.policy.network_proxy);
        assert!(
            network.contains("49001"),
            "the request must name the port the proof counts: {network}"
        );
        assert!(
            network.contains("run-token"),
            "the request must carry the run's credential: {network}"
        );
        let seam = supervisor_backend(
            &source,
            Some(49_001),
            Some("run-token"),
            Path::new(TEST_LAUNCHER),
            budget,
        );
        assert_eq!(
            request.script_code,
            seam.request_for(&input)
                .expect("the same request")
                .script_code,
            "the same launcher command line, byte for byte"
        );
    }

    /// **P3.4 replaced P3.0 decision 9.** A writable grant outside the workspace
    /// is now ACCEPTED (it is the operator's explicit grant, and a tool that keeps
    /// state in the profile cannot run without it), and the workspace itself is not
    /// granted twice however it is spelled.
    #[test]
    fn a_writable_grant_outside_the_workspace_is_accepted_and_not_refused() {
        let cwd = Path::new(r"C:\work\repo");
        for spelling in [r"c:\WORK\repo\", r"C:\work\.\repo", r"C:\work\sub\..\repo"] {
            let fs = filesystem_policy(
                cwd,
                &[PathBuf::from(spelling), PathBuf::from(r"C:\data\datasets")],
                &[],
                &[],
                None,
                Path::new(TEST_LAUNCHER),
            )
            .expect("a writable grant outside the workspace is honoured");
            assert_eq!(
                fs.readwrite_paths,
                vec![r"C:\work\repo".to_string(), r"C:\data\datasets".to_string()],
                "{spelling} names the workspace and must not be granted twice"
            );
        }
    }

    /// The profile-shaped case this item exists for: opencode's own state
    /// directories, granted writable, on top of the workspace.
    #[test]
    fn profile_state_directories_become_writable_grants() {
        let fs = filesystem_policy(
            Path::new(r"C:\work\repo"),
            &[
                PathBuf::from(r"C:\Users\marku\.local\share\opencode"),
                PathBuf::from(r"C:\Users\marku\.cache\opencode"),
                PathBuf::from(r"C:\Users\marku\.config\opencode"),
                PathBuf::from(r"C:\Users\marku\.local\state\opencode"),
            ],
            &[],
            &[],
            Some(Path::new(PROFILE)),
            Path::new(TEST_LAUNCHER),
        )
        .expect("none of these grants is covered by a deny");
        assert_eq!(
            fs.readwrite_paths,
            vec![
                r"C:\work\repo".to_string(),
                r"C:\Users\marku\.local\share\opencode".to_string(),
                r"C:\Users\marku\.cache\opencode".to_string(),
                r"C:\Users\marku\.config\opencode".to_string(),
                r"C:\Users\marku\.local\state\opencode".to_string(),
            ],
            "the workspace plus every explicit grant, in the order the operator named them"
        );
        assert!(
            fs.denied_paths
                .iter()
                .any(|deny| deny == &format!(r"{PROFILE}\.ssh")),
            "the credential denies stay in force beside the grants: {:?}",
            fs.denied_paths
        );
    }

    /// A grant the operator made is still SUBORDINATE to a deny that covers it:
    /// the session is refused, and the message says which grant to narrow.
    #[test]
    fn a_deny_that_covers_a_writable_grant_refuses_the_session() {
        let err = filesystem_policy(
            Path::new(r"C:\work\repo"),
            &[PathBuf::from(r"C:\Users\marku\.local\share\opencode")],
            &[],
            &[r"C:\Users\marku\.local".to_string()],
            None,
            Path::new(TEST_LAUNCHER),
        )
        .expect_err("a deny above a writable grant cannot be honoured");
        let message = err.to_string();
        assert!(
            message.contains(r"C:\Users\marku\.local\share\opencode"),
            "the refusal must name the GRANT to narrow: {message}"
        );
        assert!(
            message.contains("Deny the specific subdirectory"),
            "the refusal must say how to resolve it: {message}"
        );
    }

    /// P3.0: the wrapper must be found *beside the supervisor*, and its absence
    /// must be observable rather than assumed — Docker-style PATH lookups are not
    /// something this binary does.
    #[test]
    fn launcher_beside_requires_the_wrapper_next_to_the_supervisor() {
        let dir = std::env::temp_dir().join(format!(
            "sb-p30-launcher-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let supervisor = dir.join("saife.exe");
        assert_eq!(launcher_beside(&supervisor), None, "nothing is written yet");
        let launcher = dir.join(LAUNCHER_EXE_NAME);
        std::fs::write(&launcher, b"stub").expect("stub launcher");
        assert_eq!(launcher_beside(&supervisor), Some(launcher));
        std::fs::remove_dir_all(&dir).ok();
    }

    /// P2.3 review (item 1) — **the finding itself**: the supervisor seam must not
    /// run un-gated.
    ///
    /// `launch_session` is what `main` will call, and it built its backend with the
    /// fail-open default while its doc comment claimed `Exactly(REQUIRED_TIER)`.
    /// This drives a degraded tier through *that* construction — the same function
    /// `launch_session` calls, not a lookalike — and requires the refusal.
    ///
    /// Red before the fix: `Ok(())` (the backend was built with `Recorded`), i.e.
    /// a degraded dispatch would have launched with the migration's whole UAC gain
    /// silently gone.
    #[test]
    fn the_supervisor_seam_refuses_a_degraded_tier() {
        let source = RecordingSource::default();
        let degraded = tier_record(ProbeView {
            tier: Some("appcontainer-dacl"),
            needs_dacl_augmentation: Some(true),
        });

        let seam = supervisor_backend(
            &source,
            Some(49_152),
            Some("token"),
            Path::new(TEST_LAUNCHER),
            SessionBudget::default(),
        );
        let refusal = seam.tier_gate(&degraded).expect_err(
            "the seam launch_session builds must require `base-container`, \
             not merely record what dispatched",
        );
        assert_eq!(refusal.expected, REQUIRED_TIER);
        assert_eq!(refusal.observed.as_deref(), Some("appcontainer-dacl"));
        assert_eq!(refusal.source, "probe");

        // A silent probe is refused too: a requirement that cannot be shown to be
        // met is not met, and that is the case a degraded dispatch produces.
        let silent = tier_record(ProbeView {
            tier: None,
            needs_dacl_augmentation: None,
        });
        assert!(
            seam.tier_gate(&silent).is_err(),
            "the seam must not accept a tier nobody could name"
        );

        // And the exact tier it requires still passes: the gate refuses the wrong
        // tier, not every tier.
        let required = tier_record(ProbeView {
            tier: Some(REQUIRED_TIER),
            needs_dacl_augmentation: Some(false),
        });
        assert_eq!(seam.tier_gate(&required), Ok(()));
    }

    /// P2.3 review (item 1), the compile-level half: **no constructor yields an
    /// un-gated backend.**
    ///
    /// Both constructors are coerced to `fn` pointers whose signatures include the
    /// [`TierExpectation`]. That pins the arity *and* the parameter type at compile
    /// time: an expression of `MxcBackend` that omits the expectation — the shape
    /// that produced the fail-open seam — cannot be written, because there is no
    /// constructor with that signature and the fields are private. This test does
    /// not build if one is ever added back.
    #[test]
    fn no_constructor_yields_an_un_gated_backend() {
        let _with_proof: fn(
            &'static dyn ProxyProofSource,
            Option<u16>,
            &'static str,
            TierExpectation,
        ) -> MxcBackend<'static> = MxcBackend::new;
        let _without_proof: fn(Option<u16>, &'static str, TierExpectation) -> MxcBackend<'static> =
            MxcBackend::without_proof_source;

        // …and the argument is not merely present but honoured by every
        // constructor: the gate applies whatever was passed.
        let degraded = tier_record(ProbeView {
            tier: Some("appcontainer-dacl"),
            needs_dacl_augmentation: Some(true),
        });
        assert!(
            MxcBackend::without_proof_source(Some(1), TEST_LAUNCHER, TierExpectation::Recorded)
                .tier_gate(&degraded)
                .is_ok()
        );
    }

    /// The audit adapter carries the record verbatim — including `None`, which
    /// must stay "unknown" rather than become `false` on the leaf.
    #[test]
    fn the_tier_record_maps_into_the_leaf_vocabulary_without_inventing_a_value() {
        let named = tier_record(ProbeView {
            tier: Some("base-container"),
            needs_dacl_augmentation: Some(false),
        });
        let facts = named.audit_facts();
        assert_eq!(facts.tier.as_deref(), Some("base-container"));
        assert_eq!(facts.tier_source, Some("probe"));
        assert_eq!(facts.needs_dacl_augmentation, Some(false));
        assert!(
            facts.tier.is_some() && facts.tier_source.is_some(),
            "the tier pair travels together"
        );

        let silent = tier_record(ProbeView {
            tier: None,
            needs_dacl_augmentation: None,
        });
        let facts = silent.audit_facts();
        assert_eq!(facts.tier, None);
        assert_eq!(facts.tier_source, Some("unavailable"));
        assert_eq!(facts.needs_dacl_augmentation, None);
        assert!(
            facts.tier.is_none() && facts.tier_source.is_some(),
            "a silent probe leaves the tier unknown but still names its source"
        );
    }

    // ---- P1 wave 2 B: the launcher grant is never the caller's job -------

    #[test]
    fn a_caller_that_omits_the_launcher_grant_still_gets_a_launchable_request() {
        let source = RecordingSource::default();
        let backend = MxcBackend::new(
            &source,
            Some(49_152),
            TEST_LAUNCHER,
            TierExpectation::Recorded,
        );
        let mut i = input();
        i.filesystem.readonly_paths.clear();

        let req = backend.request_for(&i).expect("launchable request");
        assert_eq!(
            req.policy.readonly_paths,
            vec![r"C:\tools\sandbox".to_string()],
            "without this grant the container cannot execute the launcher and the launch fails \
             with an opaque policy denial"
        );
    }

    #[test]
    fn a_declared_launcher_grant_is_not_duplicated() {
        let mut fs = MxcFilesystemInput {
            readonly_paths: vec![r"c:/TOOLS/sandbox/".to_string()],
            ..Default::default()
        };
        assert!(
            !ensure_launcher_grant(&mut fs, Path::new(TEST_LAUNCHER)),
            "case and separator variants are the same grant"
        );
        assert_eq!(fs.readonly_paths.len(), 1);
    }

    /// The protection P3.4 had to keep: with the whole profile granted writable,
    /// `.ssh` is a *descendant* deny and still ships — the grant must not swallow
    /// the credential directories.
    #[test]
    fn granting_the_profile_writable_keeps_the_secret_directories_denied() {
        let fs = filesystem_policy(
            Path::new(TEST_WORKSPACE),
            &[PathBuf::from(PROFILE)],
            &[],
            &[],
            Some(Path::new(PROFILE)),
            Path::new(TEST_LAUNCHER),
        )
        .expect("a descendant deny is expressible");
        assert!(
            fs.readwrite_paths.contains(&PROFILE.to_string()),
            "the profile is granted as asked: {:?}",
            fs.readwrite_paths
        );
        for dir in PROFILE_SECRET_DIRS {
            assert!(
                fs.denied_paths.contains(&format!(r"{PROFILE}\{dir}")),
                "{dir} must stay denied even inside a writable grant: {:?}",
                fs.denied_paths
            );
        }
    }

    #[test]
    fn a_bare_launcher_file_name_adds_no_grant() {
        let mut fs = MxcFilesystemInput::default();
        assert!(!ensure_launcher_grant(&mut fs, Path::new("saife-launch.exe")));
        assert!(
            fs.readonly_paths.is_empty(),
            "there is no directory to grant, and an empty path in the request would be worse"
        );
    }

    // ---- P1 wave 2 C: filesystem policy (workspace + operator grants) ----

    const TEST_WORKSPACE: &str = r"C:\work";
    const PROFILE: &str = r"C:\Users\marku";
    /// What [`ensure_launcher_grant`] derives from `TEST_LAUNCHER`.
    const TEST_LAUNCHER_DIR: &str = r"C:\tools\sandbox";

    fn policy() -> MxcFilesystemInput {
        filesystem_policy(
            Path::new(TEST_WORKSPACE),
            &[],
            &[r"C:\ref".to_string()],
            &[r"C:\secrets".to_string()],
            Some(Path::new(PROFILE)),
            Path::new(TEST_LAUNCHER),
        )
        .expect("no deny in this policy contains a grant")
    }

    #[test]
    fn the_workspace_is_the_only_writable_grant_and_declared_reads_are_kept() {
        let fs = policy();
        assert_eq!(fs.readwrite_paths, vec![TEST_WORKSPACE.to_string()]);
        assert_eq!(
            fs.readonly_paths,
            vec![r"C:\ref".to_string(), TEST_LAUNCHER_DIR.to_string()],
            "declared read-only grants are carried as declared, and the launcher's directory is \
             a grant from policy time on — the deny filter below runs against it"
        );
    }

    #[test]
    fn profile_credential_directories_are_denied() {
        let denied = policy().denied_paths;
        for dir in PROFILE_SECRET_DIRS {
            let expected = format!(r"C:\Users\marku\{dir}");
            assert!(
                denied.contains(&expected),
                "{dir} holds credentials and must be denied: {denied:?}"
            );
        }
        assert!(
            denied.contains(&r"C:\secrets".to_string()),
            "the configured deny list is not optional: {denied:?}"
        );
    }

    #[test]
    fn configured_denies_are_deduplicated_case_insensitively() {
        let fs = filesystem_policy(
            Path::new(TEST_WORKSPACE),
            &[],
            &[],
            &[
                r"C:\secrets".to_string(),
                r"c:\SECRETS\".to_string(),
                r"\\?\C:\secrets.".to_string(),
            ],
            None,
            Path::new(TEST_LAUNCHER),
        )
        .expect("a deny that contains no grant is kept");
        let secrets: Vec<_> = fs
            .denied_paths
            .iter()
            .filter(|d| d.eq_ignore_ascii_case(r"C:\secrets"))
            .collect();
        assert_eq!(
            secrets.len(),
            1,
            "case, a trailing separator, a verbatim prefix and a trailing dot are one deny: {:?}",
            fs.denied_paths
        );
        assert!(
            fs.denied_paths.len() > 1,
            "the tool's own control plane is always denied as well: {:?}",
            fs.denied_paths
        );
        assert!(
            !fs.denied_paths.iter().any(|d| d.contains(".ssh")),
            "no profile means no profile denies: {:?}",
            fs.denied_paths
        );
    }

    /// A deny that *is* a grant sits on the boundary of "contains a grant": it can
    /// be neither honoured nor dropped, so it is refused by name.
    #[test]
    fn a_deny_equal_to_a_grant_is_refused() {
        let err = filesystem_policy(
            Path::new(TEST_WORKSPACE),
            &[],
            &[],
            &[r"c:/WORK/".to_string()],
            None,
            Path::new(TEST_LAUNCHER),
        )
        .expect_err("`C:\\work` denies the workspace it grants");
        assert_eq!(
            err,
            RequestError::DenyCoversGrant {
                deny: r"c:/WORK/".to_string(),
                grant: TEST_WORKSPACE.to_string(),
            }
        );
    }

    /// BLOCKING 2, the reported case: `%USERPROFILE%` denied with the workspace
    /// inside it. This used to be dropped silently, which left `Documents`,
    /// `Downloads`, `AppData` and every browser profile readable.
    #[test]
    fn a_deny_that_is_an_ancestor_of_a_grant_is_refused_and_names_both_paths() {
        let workspace = format!(r"{PROFILE}\work");
        let err = filesystem_policy(
            Path::new(&workspace),
            &[],
            &[],
            &[PROFILE.to_string()],
            Some(Path::new(PROFILE)),
            Path::new(TEST_LAUNCHER),
        )
        .expect_err("a profile deny with the workspace inside it cannot be honoured");
        assert_eq!(
            err,
            RequestError::DenyCoversGrant {
                deny: PROFILE.to_string(),
                grant: workspace.clone(),
            },
            "the refusal must name the granted path the deny contains"
        );
        let message = err.to_string();
        assert!(
            message.contains(PROFILE) && message.contains(&workspace),
            "both paths must be in the message: {message}"
        );
        assert!(
            message.contains("Deny the specific subdirectory"),
            "the operator needs the fix, not just the failure: {message}"
        );
    }

    /// The intended, expressible case — and the one that must keep working.
    #[test]
    fn a_deny_that_is_a_descendant_of_a_grant_is_kept() {
        let fs = filesystem_policy(
            Path::new(PROFILE),
            &[],
            &[],
            &[format!(r"{PROFILE}\.ssh"), format!(r"{PROFILE}\Documents")],
            Some(Path::new(PROFILE)),
            Path::new(TEST_LAUNCHER),
        )
        .expect("denies below the granted workspace are exactly what a deny list is for");
        assert!(fs.denied_paths.contains(&format!(r"{PROFILE}\.ssh")));
        assert!(fs.denied_paths.contains(&format!(r"{PROFILE}\Documents")));
        assert_eq!(
            fs.denied_paths
                .iter()
                .filter(|deny| deny.eq_ignore_ascii_case(&format!(r"{PROFILE}\.ssh")))
                .count(),
            1,
            "the built-in `.ssh` deny and the configured one are the same path: {:?}",
            fs.denied_paths
        );
    }

    #[test]
    fn a_deny_unrelated_to_every_grant_is_kept() {
        let fs = filesystem_policy(
            Path::new(TEST_WORKSPACE),
            &[],
            &[],
            &[r"D:\secrets".to_string(), r"C:\work2".to_string()],
            None,
            Path::new(TEST_LAUNCHER),
        )
        .expect("neither deny contains a grant");
        for expected in [r"D:\secrets", r"C:\work2"] {
            assert!(
                fs.denied_paths
                    .iter()
                    .any(|d| d.eq_ignore_ascii_case(expected)),
                "{expected} must survive: {:?}",
                fs.denied_paths
            );
        }
    }

    /// BLOCKING 1, the ordering defect: the launcher lives under the user profile
    /// in practice, so an operator deny of the profile root contains the launcher
    /// grant. It must be refused at policy time — the grant is inserted there, so
    /// the deny set is filtered against it instead of against a grant set that is
    /// completed later in `build_request`.
    #[test]
    fn a_profile_deny_that_contains_the_launcher_grant_is_refused() {
        let launcher = format!(r"{PROFILE}\tools\sandbox\{LAUNCHER_EXE_NAME}");
        let err = filesystem_policy(
            Path::new(TEST_WORKSPACE),
            &[],
            &[],
            &[PROFILE.to_string()],
            Some(Path::new(PROFILE)),
            Path::new(&launcher),
        )
        .expect_err("the launcher's directory is under the denied profile");
        assert_eq!(
            err,
            RequestError::DenyCoversGrant {
                deny: PROFILE.to_string(),
                grant: format!(r"{PROFILE}\tools\sandbox"),
            },
            "the refusal must name the launcher directory — the grant the deny contains"
        );
    }

    /// The control for the test above: with no such deny, the profile credential
    /// denies survive alongside a launcher grant that sits under the profile. The
    /// grant must not swallow them, and their presence proves the deny list was
    /// filtered against a grant set that already contained the launcher.
    #[test]
    fn a_launcher_under_the_profile_keeps_the_profile_credential_denies() {
        let launcher = format!(r"{PROFILE}\tools\sandbox\{LAUNCHER_EXE_NAME}");
        let fs = filesystem_policy(
            Path::new(TEST_WORKSPACE),
            &[],
            &[],
            &[],
            Some(Path::new(PROFILE)),
            Path::new(&launcher),
        )
        .expect("no deny contains a grant");
        assert!(
            fs.readonly_paths
                .contains(&format!(r"{PROFILE}\tools\sandbox")),
            "the launcher grant is part of the policy: {:?}",
            fs.readonly_paths
        );
        let saife = std::path::Path::new(PROFILE).join(".saife");
        assert!(
            fs.denied_paths.iter().any(|d| d.eq_ignore_ascii_case(&saife.display().to_string())),
            "the tool's own plugin/policy root must stay denied even when the launcher sits \
             under the profile: {:?}",
            fs.denied_paths
        );
        assert!(
            fs.denied_paths.len() >= PROFILE_SECRET_DIRS.len(),
            "the credential denies must survive: {:?}",
            fs.denied_paths
        );
    }

    /// (b) The launcher used to defeat the guard: a relative spelling keys as
    /// `tools\sandbox`, which never matches an absolute deny, so a deny covering
    /// the real directory shipped and the container was then denied the launcher
    /// it needed. It is resolved before the comparison now.
    #[test]
    fn a_relative_launcher_is_resolved_before_the_deny_comparison() {
        let here = std::env::current_dir().expect("current directory");
        let launcher_dir = std::path::absolute(Path::new(r"tools\sandbox"))
            .expect("the relative launcher directory resolves")
            .display()
            .to_string();
        let err = filesystem_policy(
            Path::new(TEST_WORKSPACE),
            &[],
            &[],
            &[here.display().to_string()],
            None,
            Path::new(r"tools\sandbox\saife-launch.exe"),
        )
        .expect_err("the current directory is an ancestor of the resolved launcher directory");
        assert_eq!(
            err,
            RequestError::DenyCoversGrant {
                deny: here.display().to_string(),
                grant: launcher_dir,
            },
            "the grant must be the resolved directory, not the relative spelling"
        );
    }

    /// (b) The other input: a relative `cwd` keyed as `.` (empty), so a deny of the
    /// real directory matched nothing and shipped. `.` now behaves like its
    /// absolute form — same grant, same refusal.
    #[test]
    fn a_relative_cwd_behaves_like_its_absolute_form() {
        let here = std::env::current_dir().expect("current directory");
        let relative = filesystem_policy(
            Path::new("."),
            &[],
            &[],
            &[],
            None,
            Path::new(TEST_LAUNCHER),
        )
        .expect("`.` resolves to the current directory");
        assert_eq!(
            relative.readwrite_paths,
            vec![here.display().to_string()],
            "the grant must be the resolved directory, not `.`"
        );
        let absolute = filesystem_policy(&here, &[], &[], &[], None, Path::new(TEST_LAUNCHER))
            .expect("the absolute spelling of the same workspace");
        assert_eq!(
            relative.readwrite_paths, absolute.readwrite_paths,
            "`.` and the absolute form must produce the same policy"
        );

        let err = filesystem_policy(
            Path::new("."),
            &[],
            &[],
            &[here.display().to_string()],
            None,
            Path::new(TEST_LAUNCHER),
        )
        .expect_err("the current directory is the workspace it would grant");
        assert_eq!(
            err,
            RequestError::DenyCoversGrant {
                deny: here.display().to_string(),
                grant: here.display().to_string(),
            }
        );
    }

    /// A path the boundary cannot make absolute has no comparison key, so it is a
    /// named refusal rather than a guess that voids the guard.
    #[test]
    fn a_path_that_cannot_be_made_absolute_is_a_named_refusal() {
        let err = filesystem_policy(Path::new(""), &[], &[], &[], None, Path::new(TEST_LAUNCHER))
            .expect_err("an empty cwd has no key to compare");
        assert_eq!(
            err,
            RequestError::PathNotAbsolute {
                what: "workspace directory",
                path: String::new(),
            }
        );
        assert!(
            err.to_string().contains("is empty"),
            "the message must say what is wrong: {err}"
        );

        let err = build_request(&input(), Path::new("")).expect_err("an empty launcher has no key");
        assert_eq!(
            err,
            RequestError::PathNotAbsolute {
                what: "launcher",
                path: String::new(),
            }
        );
        assert!(
            err.to_string().contains("launcher"),
            "the message must name the input: {err}"
        );
    }

    /// (b) The command line names the resolved launcher too, so the container
    /// executes exactly the binary the policy granted.
    #[test]
    fn build_request_resolves_a_relative_launcher_in_the_command_line() {
        let here = std::env::current_dir().expect("current directory");
        let request = build_request(&input(), Path::new(r"bin\saife-launch.exe"))
            .expect("a relative launcher resolves");
        let resolved_dir = here.join("bin").display().to_string();
        assert!(
            request.script_code.contains(&resolved_dir),
            "the command line must name the absolute launcher directory: {:?}",
            request.script_code
        );
        assert!(
            request
                .policy
                .readonly_paths
                .iter()
                .any(|g| path_key(g) == path_key(&resolved_dir)),
            "the grant must be the resolved directory: {:?}",
            request.policy.readonly_paths
        );
    }

    /// (f) The built-in credential denies are not configuration: a workspace inside
    /// one is unlaunchable with no override, and the operator has to be told that
    /// rather than left hunting for a setting they never wrote.
    #[test]
    fn a_workspace_inside_a_built_in_credential_deny_names_the_trap() {
        for dir in PROFILE_SECRET_DIRS {
            let workspace = format!(r"{PROFILE}\{dir}\work");
            let err = filesystem_policy(
                Path::new(&workspace),
                &[],
                &[],
                &[],
                Some(Path::new(PROFILE)),
                Path::new(TEST_LAUNCHER),
            )
            .expect_err("the built-in credential deny contains the workspace");
            assert_eq!(
                err,
                RequestError::DenyCoversGrant {
                    deny: format!(r"{PROFILE}\{dir}"),
                    grant: workspace,
                },
                "{dir}"
            );
            let message = err.to_string();
            assert!(
                message.contains("built-in") && message.contains("move the workspace"),
                "the operator must be told this is not their configuration: {message}"
            );
        }
    }

    /// A caller may hand-build an [`MxcFilesystemInput`], so `build_request` runs
    /// the same coverage check again **after** inserting the launcher grant.
    #[test]
    fn build_request_refuses_a_hand_built_policy_that_denies_the_launcher_directory() {
        let source = RecordingSource::default();
        let backend = MxcBackend::new(
            &source,
            Some(49_152),
            TEST_LAUNCHER,
            TierExpectation::Recorded,
        );
        let mut i = input();
        i.filesystem.denied_paths = vec![TEST_LAUNCHER_DIR.to_string()];

        match backend.request_for(&i) {
            Err(MxcError::Request(RequestError::DenyCoversGrant { deny, grant })) => {
                assert_eq!(deny, TEST_LAUNCHER_DIR);
                assert_eq!(grant, TEST_LAUNCHER_DIR);
            }
            other => panic!(
                "a deny of the launcher's own directory must refuse the request, got {other:?}"
            ),
        }
    }

    /// (e) The *ancestor* branch of the second filter — a deny that covers the
    /// launcher's directory without naming it. The `deny == grant` test above
    /// reaches only the equality arm, so without this the ancestor arm of
    /// `covers` would be untested on the post-insertion re-check.
    #[test]
    fn build_request_refuses_a_hand_built_policy_whose_deny_is_an_ancestor_of_the_launcher() {
        let source = RecordingSource::default();
        let backend = MxcBackend::new(
            &source,
            Some(49_152),
            TEST_LAUNCHER,
            TierExpectation::Recorded,
        );
        let mut i = input();
        i.filesystem.readonly_paths.clear();
        i.filesystem.denied_paths = vec![r"C:\tools".to_string()];

        match backend.request_for(&i) {
            Err(MxcError::Request(RequestError::DenyCoversGrant { deny, grant })) => {
                assert_eq!(deny, r"C:\tools");
                assert_eq!(
                    grant, TEST_LAUNCHER_DIR,
                    "the grant is the launcher directory build_request itself inserted"
                );
            }
            other => panic!(
                "a deny that is an ancestor of the launcher's directory must refuse the \
                 request, got {other:?}"
            ),
        }
    }

    /// `covers` is the whole deny/grant decision, so its boundary cases are
    /// asserted directly rather than only through `filesystem_policy`.
    #[test]
    fn covers_is_segment_aware_and_prefix_safe() {
        // Siblings that share a prefix are not covered; children are.
        assert!(!covers(r"C:\work", r"C:\work2"));
        assert!(covers(r"C:\work", r"C:\work\sub"));
        assert!(!covers(r"C:\work", r"C:\work2\sub"));
        assert!(covers(r"C:\work", r"C:\work"));
        // Separator style and a trailing separator are not identity.
        assert!(covers(r"C:\work\", r"C:/work/sub"));

        // Win32 ignores a component's trailing dots and spaces.
        assert!(covers(r"C:\Users\x\.ssh.", r"C:\Users\x\.ssh"));
        assert!(covers(r"C:\Users\x\.ssh", r"C:\Users\x\.ssh."));
        assert!(covers(r"C:\work ", r"C:\work\sub"));

        // `.`/`..` collapse before comparison.
        assert!(covers(r"C:\work\.\sub\..", r"C:\work"));
        assert!(covers(r"C:\work\sub\..\sub", r"C:\work\sub"));

        // The verbatim/device prefix and its UNC spelling name the same tree.
        assert!(covers(r"\\?\C:\work", r"C:\work\sub"));
        assert!(covers(r"C:\work", r"\\?\C:\work\sub"));
        assert!(covers(r"\\.\C:\work", r"C:\work"));
        assert!(covers(r"\\?\UNC\server\share", r"\\server\share\sub"));
        assert!(covers(r"\\server\share", r"\\?\UNC\server\share\sub"));
        assert!(!covers(r"\\server\share", r"\\server\share2"));

        // An empty path covers nothing — an empty deny is a mistake, not a
        // wildcard — and nothing covers a drive root.
        assert!(!covers("", r"C:\work"));
        assert!(!covers("", ""));
        assert!(!covers(r"C:\work", ""));

        // A drive root covers its whole drive, and is covered by nothing else.
        assert!(covers(r"C:\", r"C:\work"));
        assert!(covers(r"C:\", r"C:\Windows\win.ini"));
        assert!(!covers(r"C:\work", r"C:\"));
    }

    /// Windows compares path components case-insensitively over the whole
    /// Unicode range; `to_ascii_lowercase` only folded ASCII, so `C:\Users\Ä` and
    /// `C:\Users\ä` were different keys and a covering deny escaped the guard.
    /// Both directions, because a fold that only worked one way would still let
    /// one operator's spelling through.
    #[test]
    fn unicode_case_folds_to_one_key_in_both_directions() {
        assert_eq!(path_key(r"C:\Users\Ä"), path_key(r"C:\Users\ä"));
        assert_eq!(path_key(r"C:\Users\ä"), path_key(r"C:\Users\Ä"));
        assert!(covers(r"C:\Users\Ä\work", r"C:\Users\ä\work\sub"));
        assert!(covers(r"C:\Users\ä\work", r"C:\Users\Ä\work\.ssh"));
        // Not Latin-1 only: the fold is Unicode, as Windows' ordinal compare is.
        assert_eq!(path_key(r"C:\Δ\Σ"), path_key(r"C:\δ\σ"));
        assert_eq!(path_key(r"C:\ДОМ"), path_key(r"C:\дом"));
        // ...and it stays case-*insensitive*, not case-blind: different letters
        // still differ, so the guard does not start refusing everything.
        assert_ne!(path_key(r"C:\Users\Ä"), path_key(r"C:\Users\Ö"));
    }

    /// The fold is only worth having if it reaches the guard: a Unicode-cased deny
    /// that covers the workspace must refuse the launch, in both directions.
    #[test]
    fn a_unicode_cased_deny_that_covers_the_workspace_is_refused() {
        for (deny, workspace) in [
            (r"C:\Users\Ä", r"C:\Users\ä\work"),
            (r"C:\Users\ä", r"C:\Users\Ä\work"),
        ] {
            let err = filesystem_policy(
                Path::new(workspace),
                &[],
                &[],
                &[deny.to_string()],
                None,
                Path::new(TEST_LAUNCHER),
            )
            .expect_err("these are one directory to Windows, so the deny covers the grant");
            assert_eq!(
                err,
                RequestError::DenyCoversGrant {
                    deny: deny.to_string(),
                    grant: workspace.to_string(),
                },
                "{deny} vs {workspace}"
            );
        }
    }

    /// (c) `..` is tested *after* the trailing-dot/space trim: `.. ` trimmed to
    /// nothing and was dropped, so `C:\work\sub\.. \x` keyed as
    /// `c:\work\sub\x` instead of collapsing to `c:\work\x`.
    #[test]
    fn a_dotdot_with_a_trailing_space_still_collapses_to_the_parent() {
        assert_eq!(path_key(r"C:\work\sub\.. \x"), path_key(r"C:\work\x"));
        assert_eq!(path_key(r"C:\work\sub\..  \x"), path_key(r"C:\work\x"));
        assert_eq!(path_key(r"C:\work\sub\..\x"), path_key(r"C:\work\x"));
        assert_eq!(path_key(r"C:\work\sub\.. "), path_key(r"C:\work"));
        assert!(covers(r"C:\work\sub\.. .", r"C:\work\sub"));
        // A dot-only segment with padding is still just `.`, dropped.
        assert_eq!(path_key(r"C:\work\. \x"), path_key(r"C:\work\x"));
        // `..` still clamps at the root.
        assert_eq!(path_key(r"C:\..\work"), path_key(r"C:\work"));
    }

    /// (d) The docblock promises *every* component loses its trailing dots and
    /// spaces; the UNC root's server and share were exempt, so `\\srv\share.\x`
    /// and `\\srv\share\x` were different keys.
    #[test]
    fn unc_root_components_lose_their_trailing_dots_and_spaces() {
        assert_eq!(path_key(r"\\srv\share.\x"), path_key(r"\\srv\share\x"));
        assert_eq!(path_key(r"\\srv\share \x"), path_key(r"\\srv\share\x"));
        assert_eq!(path_key(r"\\srv.\share\x"), path_key(r"\\srv\share\x"));
        assert!(covers(r"\\srv\share.", r"\\srv\share\sub"));
        assert!(covers(r"\\srv\share", r"\\srv\share.\sub"));
        // The trimmed root still prefixes its own children, and no sibling.
        assert!(!covers(r"\\srv\share.", r"\\srv\share2"));
        assert!(!covers(r"\\srv\share.", r"\\srv2\share"));
    }

    /// The normalisation `covers` relies on, asserted where it is observable: every
    /// spelling of one directory must reach one key, without touching the disk.
    #[test]
    fn equivalent_spellings_reach_the_same_path_key() {
        let expected = path_key(r"C:\Users\x\.ssh");
        for spelling in [
            r"C:\Users\x\.ssh.",
            r"C:\Users\x\.ssh   ",
            r"C:/Users/x/.ssh",
            r"\\?\C:\Users\x\.ssh",
            r"\\.\C:\Users\x\.ssh",
            r"C:\Users\.\x\ssh\..\.ssh",
            r"C:\Users\x\.ssh\",
        ] {
            assert_eq!(path_key(spelling), expected, "{spelling}");
        }
        assert_eq!(path_key(r"\\?\UNC\srv\share\x"), path_key(r"\\srv\share\x"));
    }

    /// The documented caveat, asserted as a caveat: MXC filesystem policy is
    /// additive grants, so system directories stay readable even when every
    /// secret we can name is denied. This test exists so nobody "fixes" the
    /// caveat by denying `C:\Windows` — that would break every workload that
    /// needs System32 while the policy still cannot express "nothing else".
    #[test]
    fn system_directories_are_not_denied_the_additive_caveat_is_recorded() {
        let fs = policy();
        assert!(
            !fs.denied_paths
                .iter()
                .any(|denied| covers(denied, r"C:\Windows")),
            "`C:\\Windows` readable inside the container is the known caveat: {:?}",
            fs.denied_paths
        );
        assert!(
            !fs.denied_paths
                .iter()
                .any(|denied| denied.eq_ignore_ascii_case(r"C:\Windows")),
            "denying C:\\Windows would break every System32-resident workload"
        );
    }

    // ---- P1 wave 2 D8: the token rides the proxy URL ---------------------

    fn network_proxy(request: &ExecutionRequest) -> Option<String> {
        request
            .policy
            .network_proxy
            .address
            .as_ref()
            .map(|address| address.to_url())
    }

    #[test]
    fn the_request_hands_the_child_a_proxy_url_with_the_session_token() {
        let source = RecordingSource::default();
        let backend = MxcBackend::new(
            &source,
            Some(49_152),
            TEST_LAUNCHER,
            TierExpectation::Recorded,
        )
        .with_proxy_token("abc-123");
        let request = backend.request_for(&input()).expect("launchable request");
        assert_eq!(
            network_proxy(&request).as_deref(),
            Some("http://sandbox:abc-123@127.0.0.1:49152"),
            "the SDK copies this URL verbatim into HTTP_PROXY/HTTPS_PROXY, and the proxy's \
             token gate is what it has to satisfy"
        );
    }

    #[test]
    fn a_callers_token_cannot_stand_in_for_the_backends() {
        let source = RecordingSource::default();
        let backend = MxcBackend::new(
            &source,
            Some(49_152),
            TEST_LAUNCHER,
            TierExpectation::Recorded,
        );
        let mut i = input();
        i.network.proxy_token = Some("caller-lookalike".to_string());

        let request = backend.request_for(&i).expect("launchable request");
        assert_eq!(
            network_proxy(&request).as_deref(),
            Some("http://127.0.0.1:49152"),
            "a token this backend's listener cannot honour must not ship: it would produce a \
             407 that reads like a broken proxy"
        );
    }

    /// The token is a credential: `{:?}` on either input must not print it, or
    /// every log line, panic message and error chain that formats an input hands
    /// out the session token the proxy's gate expects.
    #[test]
    fn debug_output_redacts_the_proxy_token() {
        const TOKEN: &str = "tok-must-not-appear-4821";
        let mut i = input();
        i.network.proxy_port = Some(49_152);
        i.network.proxy_token = Some(TOKEN.to_string());

        let network = format!("{:?}", i.network);
        assert!(
            network.contains(REDACTED_TOKEN),
            "the redaction must be visible: {network}"
        );
        assert!(
            !network.contains(TOKEN),
            "`MxcNetworkInput`'s Debug leaked the token: {network}"
        );

        let session = format!("{i:?}");
        assert!(
            session.contains(REDACTED_TOKEN),
            "the redaction must be visible: {session}"
        );
        assert!(
            !session.contains(TOKEN),
            "`MxcSessionInput`'s Debug leaked the token: {session}"
        );
    }

    #[test]
    fn an_unsafe_token_is_refused_before_a_request_exists() {
        for bad in ["a@b", "a/b", "a b", "a?b", "a#b"] {
            let mut i = input();
            i.network.proxy_token = Some(bad.to_string());
            assert_eq!(
                build_request(&i, Path::new(TEST_LAUNCHER)).expect_err("unsafe token"),
                RequestError::UnsafeProxyToken,
                "{bad:?} would move the URL's authority"
            );
        }
        assert_eq!(
            proxy_url(8080, Some("Hex-0123._~")).expect("unreserved characters are fine"),
            "http://sandbox:Hex-0123._~@127.0.0.1:8080"
        );
        assert_eq!(
            proxy_url(8080, None).expect("no token"),
            "http://127.0.0.1:8080",
            "no token means the credential-less form, unchanged"
        );
        assert_eq!(
            proxy_url(8080, Some("")).expect("an empty token is no token"),
            "http://127.0.0.1:8080"
        );
    }

    // ---- P1 wave 2 A: the real proof source is the listener ---------------

    #[test]
    fn the_proxy_counters_are_a_proxy_proof_source() {
        let counters = crate::net::proxy::LaunchCounters::new();
        let source: &dyn ProxyProofSource = counters.as_ref();
        assert_eq!(source.proof(1), untouched());
    }

    #[test]
    fn listener_counters_map_to_the_proof_and_never_leak_between_epochs() {
        let counters = crate::net::proxy::LaunchCounters::new();

        let first = counters.begin_launch().expect("the first launch's window");
        counters.note_probe();
        counters.note_consultation();
        counters.note_upstream_established();
        assert_eq!(
            counters.proof(first),
            ProxyProof {
                accepted: 1,
                tunnels: 1,
                probes: 1,
                unauthenticated: 0,
            }
        );
        counters.close_launch(first);

        // A second launch starts from zero, even though the first one saw
        // traffic — this is the whole point of the epoch.
        let second = counters.begin_launch().expect("a window after the close");
        assert_eq!(counters.proof(second), untouched());
        // A plain-HTTP forward: consulted and upstream established, with no
        // CONNECT anywhere. `tunnels >= 1` must hold or `Required` would fail a
        // working session.
        counters.note_probe();
        counters.note_consultation();
        counters.note_upstream_established();
        assert_eq!(
            counters.proof(second),
            ProxyProof {
                accepted: 1,
                tunnels: 1,
                probes: 1,
                unauthenticated: 0,
            },
            "a plain-HTTP-only session carries both the probe and its coverage"
        );
        // The closed epoch keeps its frozen numbers.
        assert_eq!(
            counters.proof(first),
            ProxyProof {
                accepted: 1,
                tunnels: 1,
                probes: 1,
                unauthenticated: 0,
            }
        );
        // An epoch nobody opened proves nothing.
        assert_eq!(counters.proof(4_242), untouched());
    }

    // ---- environment filter ---------------------------------------------

    #[test]
    fn blocked_env_keys_match_case_insensitively_and_only_proxy_vars() {
        for key in [
            "HTTP_PROXY",
            "https_proxy",
            "All_Proxy",
            "no_proxy",
            " HTTP_PROXY ",
        ] {
            assert!(is_blocked_env_key(key), "{key} must be blocked");
        }
        for key in ["PATH", "HTTP_PROXYX", "PROXY", "APPDATA"] {
            assert!(!is_blocked_env_key(key), "{key} must not be blocked");
        }
    }
