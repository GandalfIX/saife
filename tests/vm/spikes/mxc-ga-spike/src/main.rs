//! Unelevated MXC `mxc-sdk 1.0.1` GA spike: ProcessContainer, proxy-only egress,
//! real forwarding, and the two ADR-0004 guardrails.
//!
//! One run emits `SPIKE:`-prefixed machine-readable lines. See SPIKE-REPORT.md.
//!
//! Guardrails implemented here (both are mandatory for ADR-0004 Option A):
//!   1. **post-launch proxy proof** — the driver opens an attribution *epoch*
//!      before launching, counts the proxy sessions accepted in that epoch, and
//!      will not report success unless >= 1 session arrived *and* at least one
//!      CONNECT tunnel was established (origin TCP dial succeeded on our side).
//!      `warnings=[]` is never treated as evidence.
//!   2. **per-session tier logging** — `v1::probe()` on the *actual* request
//!      gives the selected tier; it is printed and persisted per run.

mod proxy;

use std::collections::BTreeMap;
use std::net::TcpStream;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use mxc_sdk::v1;
use mxc_sdk::v1::configs::{ProcessContainerConfig, ProcessContainerNetwork};
use mxc_sdk::v1::{
    ContainerRequest, Containment, FilesystemPolicy, NetworkAction, NetworkEgressPolicy,
    NetworkIngressPolicy, NetworkPolicy, NetworkRuntimeConfig, RunOptions, WaitResult,
};
use proxy::{Proxy, Session};

// ---------------------------------------------------------------------------
// Elevation state (TokenElevation), the same signal as IsInRole(Administrator)
// ---------------------------------------------------------------------------

#[repr(C)]
struct TokenElevation {
    token_is_elevated: u32,
}

const TOKEN_QUERY: u32 = 0x0008;
const TOKEN_ELEVATION_CLASS: u32 = 20; // TOKEN_INFORMATION_CLASS::TokenElevation

#[link(name = "advapi32")]
extern "system" {
    fn OpenProcessToken(process: isize, desired_access: u32, token: *mut isize) -> i32;
    fn GetTokenInformation(
        token: isize,
        class: u32,
        info: *mut core::ffi::c_void,
        len: u32,
        ret_len: *mut u32,
    ) -> i32;
    fn CloseHandle(handle: isize) -> i32;
}
#[link(name = "kernel32")]
extern "system" {
    fn GetCurrentProcess() -> isize;
}

fn is_elevated() -> Option<bool> {
    unsafe {
        let mut token: isize = 0;
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return None;
        }
        let mut info = TokenElevation {
            token_is_elevated: 0,
        };
        let mut ret: u32 = 0;
        let ok = GetTokenInformation(
            token,
            TOKEN_ELEVATION_CLASS,
            &mut info as *mut TokenElevation as *mut core::ffi::c_void,
            std::mem::size_of::<TokenElevation>() as u32,
            &mut ret,
        );
        CloseHandle(token);
        if ok == 0 {
            None
        } else {
            Some(info.token_is_elevated != 0)
        }
    }
}

// ---------------------------------------------------------------------------
// Time (no chrono dependency): UTC stamp for run records
// ---------------------------------------------------------------------------

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// (iso-with-colons, filename-safe, unix-secs)
fn utc_now() -> (String, String, u64) {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (y, mo, d) = civil_from_days(days);
    let (h, mi, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let iso = format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z");
    let file = format!("{y:04}-{mo:02}-{d:02}T{h:02}-{mi:02}-{s:02}Z");
    (iso, file, secs)
}

// ---------------------------------------------------------------------------
// Request construction
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq)]
enum Expect {
    /// The gate is armed: no proof => hard failure (non-zero exit).
    Required,
    /// Negative test: a FAIL here is the expected, correct outcome.
    ExpectFail,
}

fn process_container_cfg(peer: Option<String>) -> ProcessContainerConfig {
    let mut cfg = ProcessContainerConfig::default();
    if let Some(peer) = peer {
        // ProcessContainerNetwork is #[non_exhaustive]: build via Default then set.
        let mut network = ProcessContainerNetwork::default();
        network.allowed_proxy_peer = Some(peer);
        cfg.network = Some(network);
    }
    cfg
}

/// Model 2 (proxy-only egress).
///
/// `host_loopback_allow` selects the identity-less deployment: an unpackaged,
/// non-AppContainer proxy (this spike process) has no package family name or
/// AppContainer profile, so `allowedProxyPeer` must be OMITTED and host loopback
/// allowed -- networking.md, "Unpackaged non-AppContainer proxy".
fn model2_request(
    command: String,
    working_directory: String,
    scratch: String,
    proxy_port: u16,
    host_loopback_allow: bool,
    peer: Option<String>,
    env: Vec<(String, String)>,
) -> ContainerRequest {
    ContainerRequest {
        command,
        filesystem: Some(FilesystemPolicy {
            readwrite_paths: vec![scratch],
            readonly_paths: Vec::new(),
            denied_paths: Vec::new(),
            clear_policy_on_exit: Some(true),
        }),
        network: Some(NetworkPolicy {
            egress: Some(NetworkEgressPolicy {
                default: Some(NetworkAction::Deny),
                allow: None,
                deny: None,
            }),
            ingress: Some(NetworkIngressPolicy {
                default: Some(NetworkAction::Allow),
                host_loopback: Some(if host_loopback_allow {
                    NetworkAction::Allow
                } else {
                    NetworkAction::Deny
                }),
            }),
            runtime_config: Some(NetworkRuntimeConfig {
                network_proxy: Some(format!("http://127.0.0.1:{proxy_port}")),
            }),
        }),
        timeout_ms: Some(60_000),
        containment: Containment::ProcessContainer(process_container_cfg(peer)),
        working_directory: Some(working_directory),
        environment: Some(env),
        inherit_default_environment: Some(true),
        ..ContainerRequest::new(String::new())
    }
}

fn print_error(label: &str, e: &v1::Error) {
    println!(
        "SPIKE: {label}_error code={} message={:?} operation={:?} native={:?} remediation={:?}",
        e.code.as_str(),
        e.message,
        e.operation,
        e.native_code,
        e.remediation
    );
}

// ---------------------------------------------------------------------------
// Guardrail 2: tier observation for the request that is actually launched
// ---------------------------------------------------------------------------

struct Tier {
    tier: String,
    source: &'static str,
    needs_dacl: Option<bool>,
    probe_warnings: Vec<String>,
    probe_error: Option<String>,
    ceiling: String,
}

fn backend_ceiling(backends: &[v1::AvailableBackend]) -> String {
    backends
        .iter()
        .find(|b| b.backend == "processcontainer")
        .and_then(|b| b.tier.clone())
        .unwrap_or_else(|| "backend-absent".to_string())
}

/// `v1::probe(Some(req))` is the only public way to learn which tier this exact
/// request will dispatch to; `available_backends()[..].tier` is a host ceiling
/// and is used only as a fallback when the probe cannot name a tier.
fn select_tier(req: &ContainerRequest, backends: &[v1::AvailableBackend]) -> Tier {
    let ceiling = backend_ceiling(backends);
    match v1::probe(Some(req)) {
        Ok(p) => {
            let (tier, source) = match p.tier {
                Some(t) => (t.to_string(), "probe"),
                None => (ceiling.clone(), "backend"),
            };
            Tier {
                tier,
                source,
                needs_dacl: p.needs_dacl_augmentation,
                probe_warnings: p.warnings,
                probe_error: p.error,
                ceiling,
            }
        }
        Err(e) => {
            print_error("tier_probe", &e);
            Tier {
                tier: ceiling.clone(),
                source: "backend",
                needs_dacl: None,
                probe_warnings: Vec::new(),
                probe_error: Some(e.message.clone()),
                ceiling,
            }
        }
    }
}

fn report_tier(t: &Tier) {
    println!("SPIKE: tier={}", t.tier);
    println!("SPIKE: tier_source={}", t.source);
    println!(
        "SPIKE: tier_needs_dacl_augmentation={}",
        t.needs_dacl
            .map(|b| b.to_string())
            .unwrap_or_else(|| "unknown".into())
    );
    println!(
        "SPIKE: tier_probe_warnings={}",
        serde_json::to_string(&t.probe_warnings).unwrap_or_else(|_| "[]".into())
    );
    println!(
        "SPIKE: tier_probe_error={}",
        t.probe_error.clone().unwrap_or_else(|| "none".into())
    );
    println!("SPIKE: tier_backend_ceiling={}", t.ceiling);
    let ok = t.tier == "base-container";
    println!(
        "SPIKE: guardrail_tier={} tier={} tier_source={} expected=base-container",
        if ok { "PASS" } else { "FAIL" },
        t.tier,
        t.source
    );
}

// ---------------------------------------------------------------------------
// Guardrail 1: post-launch proxy proof
// ---------------------------------------------------------------------------

struct Proof {
    pass: bool,
    accepted: usize,
    tunnels: usize,
    bytes_down: u64,
}

fn guardrail_proxy_proof(label: &str, sessions: &[Session], expect: Expect) -> Proof {
    let accepted = sessions.len();
    let tunnels = sessions.iter().filter(|s| s.established).count();
    let bytes_down: u64 = sessions.iter().map(|s| s.bytes_down).sum();
    // >= 1 accepted connection proves the child reached us; >= 1 established
    // tunnel proves the proxy then reached the origin on the child's behalf.
    let pass = accepted >= 1 && tunnels >= 1;
    println!(
        "SPIKE: guardrail_proxy_proof={}",
        if pass { "PASS" } else { "FAIL" }
    );
    println!(
        "SPIKE: guardrail_proxy_proof_detail label={label} accepted={accepted} tunnels_established={tunnels} bytes_down={bytes_down} expected={}",
        match expect {
            Expect::Required => "PASS",
            Expect::ExpectFail => "FAIL",
        }
    );
    if !pass {
        println!(
            "SPIKE: guardrail_proxy_proof_reason=\"{}\"",
            if accepted == 0 {
                "no proxy session was accepted in this run's epoch: the child never reached the proxy"
            } else {
                "proxy session accepted, but no CONNECT tunnel was established"
            }
        );
    }
    Proof {
        pass,
        accepted,
        tunnels,
        bytes_down,
    }
}

// ---------------------------------------------------------------------------
// One launch: probe tier -> run -> proxy proof -> real-HTTPS check -> record
// ---------------------------------------------------------------------------

struct Outcome {
    hard_fail: bool,
}

#[allow(clippy::too_many_arguments)]
fn launch(
    label: &str,
    req: ContainerRequest,
    proxy: &Proxy,
    backends: &[v1::AvailableBackend],
    elevated: Option<bool>,
    expect: Expect,
    proxy_port: u16,
    target: &str,
) -> Outcome {
    println!("SPIKE: --- run {label} ---");
    let tier = select_tier(&req, backends);
    report_tier(&tier);

    let epoch = proxy.begin_run();
    println!("SPIKE: run_epoch={epoch}");

    let started = Instant::now();
    let result = v1::run(req, RunOptions::default());
    let elapsed_ms = started.elapsed().as_millis();
    println!("SPIKE: {label}_elapsed_ms={elapsed_ms}");

    let mut outcome = "error".to_string();
    let mut warnings: Vec<String> = Vec::new();
    let mut child: BTreeMap<String, String> = BTreeMap::new();

    match result {
        Ok(exec) => {
            outcome = match exec.outcome {
                WaitResult::Exited(code) => format!("exited:{code}"),
                WaitResult::TimedOut => "timed_out".to_string(),
            };
            warnings = exec.warnings.clone();
            println!("SPIKE: {label}=ok outcome={outcome}");
            println!(
                "SPIKE: {label}_warnings={}",
                serde_json::to_string(&exec.warnings).unwrap()
            );
            for line in String::from_utf8_lossy(&exec.stdout).lines() {
                println!("SPIKE: {label}_stdout={line}");
                if let Some(rest) = line.strip_prefix("CHILD: ") {
                    if let Some((k, v)) = rest.split_once('=') {
                        child
                            .entry(k.trim().to_string())
                            .or_insert_with(|| v.trim().to_string());
                    }
                }
            }
            for line in String::from_utf8_lossy(&exec.stderr).lines() {
                println!("SPIKE: {label}_stderr={line}");
            }
        }
        Err(e) => print_error(label, &e),
    }

    let sessions = proxy.sessions(epoch);
    for s in &sessions {
        println!("SPIKE: proxy_session_{label}={}", s.to_json());
    }
    println!(
        "SPIKE: proxy_accepted_{label}={} proxy_tunnels_{label}={} proxy_accepts_total={}",
        sessions.len(),
        sessions.iter().filter(|s| s.established).count(),
        proxy.accepts_total()
    );
    if let Some(s) = sessions.iter().find(|s| s.established) {
        println!(
            "SPIKE: dns_locus=proxy target={} resolved={} (child resolved nothing)",
            s.target, s.resolved
        );
    }

    let proof = guardrail_proxy_proof(label, &sessions, expect);

    let origin_status: Option<u16> = child
        .get("https_status")
        .and_then(|v| v.parse::<u16>().ok())
        .filter(|s| (100..=599).contains(s));

    // Real forwarding is only claimed when a tunnel was established AND the
    // child parsed a real origin status line through its own TLS session.
    let https_ok = origin_status.is_some() && proof.tunnels >= 1;
    match origin_status {
        Some(s) => println!(
            "SPIKE: real_https=PASS origin_status={s} target={target} tunneled_bytes_down={} tls={}",
            proof.bytes_down,
            child
                .get("https_tls")
                .cloned()
                .unwrap_or_else(|| "unknown".into())
        ),
        None => println!(
            "SPIKE: real_https=FAIL origin_status=none target={target} child_https_error={}",
            child
                .get("https_error")
                .cloned()
                .unwrap_or_else(|| "none".into())
        ),
    }

    let reasons: Vec<&str> = {
        let mut r: Vec<&str> = Vec::new();
        match expect {
            Expect::Required => {
                if !proof.pass {
                    r.push("guardrail_proxy_proof");
                }
                if !https_ok {
                    r.push("real_https");
                }
            }
            Expect::ExpectFail => {
                if proof.pass {
                    r.push("negative_test_not_caught");
                    println!(
                        "SPIKE: guardrail_negative_test=MISSED (the misconfigured run DID reach the proxy)"
                    );
                } else {
                    println!("SPIKE: guardrail_negative_test=caught");
                }
            }
        }
        r
    };
    let hard_fail = !reasons.is_empty();

    // ---- persist the per-run session record ----
    let (iso, file_stamp, secs) = utc_now();
    let record = serde_json::json!({
        "schema": 1,
        "spike": "mxc-ga-spike",
        "label": label,
        "startedUtc": iso,
        "unixSecs": secs,
        "elevated": elevated,
        "tier": tier.tier,
        "tierSource": tier.source,
        "tierExpected": "base-container",
        "tierOk": tier.tier == "base-container",
        "needsDaclAugmentation": tier.needs_dacl,
        "tierProbeWarnings": tier.probe_warnings,
        "tierProbeError": tier.probe_error,
        "proxy": {
            "bind": "127.0.0.1",
            "port": proxy_port,
            "endpoint": format!("127.0.0.1:{proxy_port}"),
            "epoch": epoch,
            "acceptedSessions": proof.accepted,
            "tunnelsEstablished": proof.tunnels,
            "sessions": sessions.iter().map(|s| s.to_json()).collect::<Vec<_>>(),
        },
        "guardrails": {
            "proxyProof": if proof.pass { "PASS" } else { "FAIL" },
            "proxyProofExpected": match expect { Expect::Required => "PASS", Expect::ExpectFail => "FAIL" },
            "tier": if tier.tier == "base-container" { "PASS" } else { "FAIL" },
            "negativeTest": match expect {
                Expect::Required => serde_json::Value::Null,
                Expect::ExpectFail => serde_json::json!(if proof.pass { "MISSED" } else { "caught" }),
            },
        },
        "realHttps": {
            "result": if https_ok { "PASS" } else { "FAIL" },
            "originStatus": origin_status,
            "target": target,
            "dnsResolvedBy": if proof.tunnels >= 1 { "proxy" } else { "none" },
        },
        "run": {
            "outcome": outcome,
            "warnings": warnings,
            "elapsedMs": elapsed_ms,
        },
        "child": child,
        "hardFail": hard_fail,
        "hardFailReasons": reasons,
    });

    let runs_dir = std::env::current_dir()
        .unwrap_or_default()
        .join("runs");
    let _ = std::fs::create_dir_all(&runs_dir);
    let path = runs_dir.join(format!("{file_stamp}-{label}.json"));
    match std::fs::write(
        &path,
        serde_json::to_string_pretty(&record).unwrap_or_default(),
    ) {
        Ok(()) => println!("SPIKE: run_record={}", path.display()),
        Err(e) => println!("SPIKE: run_record=FAIL path={} err={e}", path.display()),
    }

    Outcome { hard_fail }
}

fn print_attestation_note() {
    println!(
        "SPIKE: attestation=absent \
         searched=[v1::*, v1::container::*, ProvisionRequest, ExecutionRequest, ContainerRequest, \
         ProcessContainerConfig, options::*] \
         terms=[attest*, pre_resume, preResume, created_not_running, createdNotRunning, \
         require_tier, required_tier, requireTier, requiredTier, resume] \
         note=\"only private/internal: process_container_common::appcontainer_runner::AppContainerScriptRunner::spawn_suspended (private fn) + SpawnedChild (private struct, resume())\""
    );
}

fn main() {
    let suite = std::env::args()
        .find_map(|a| a.strip_prefix("--suite=").map(|s| s.to_string()))
        .unwrap_or_else(|| "all".to_string());
    println!("SPIKE: suite={suite}");

    let elevated = is_elevated();
    println!(
        "SPIKE: elevated={}",
        elevated
            .map(|e| e.to_string())
            .unwrap_or_else(|| "unknown".into())
    );
    println!(
        "SPIKE: process=pid:{} user={:?} host={:?}",
        std::process::id(),
        std::env::var("USERNAME").ok(),
        std::env::var("USERDOMAIN").ok()
    );

    // Control: prove THIS host has working direct egress, so a blocked child is
    // a containment result and not a broken network.
    match TcpStream::connect_timeout(&"1.1.1.1:443".parse().unwrap(), Duration::from_secs(5)) {
        Ok(_) => println!("SPIKE: parent_direct_egress=connected host_has_internet=true"),
        Err(e) => println!("SPIKE: parent_direct_egress=failed err={e}"),
    }

    let support = v1::platform_support();
    println!(
        "SPIKE: platform_support={}",
        serde_json::to_string(&support).unwrap_or_else(|e| format!("\"serialize error: {e}\""))
    );
    let backends = v1::available_backends();
    println!(
        "SPIKE: available_backends={}",
        serde_json::to_string(&backends).unwrap_or_else(|e| format!("\"serialize error: {e}\""))
    );

    // ---- origin target + proxy ----
    let target = std::env::var("MXC_SPIKE_TARGET")
        .unwrap_or_else(|_| "api.anthropic.com:443".to_string());
    let path = std::env::var("MXC_SPIKE_PATH").unwrap_or_else(|_| "/".to_string());
    let mut proxy = match proxy::start(vec![target.clone()]) {
        Ok(p) => p,
        Err(e) => {
            println!("SPIKE: proxy_start=FAIL err={e}");
            std::process::exit(9);
        }
    };
    println!("SPIKE: proxy_bind=127.0.0.1");
    println!("SPIKE: proxy_port={}", proxy.port);
    println!("SPIKE: proxy_endpoint={}", proxy.endpoint());
    println!(
        "SPIKE: proxy_allowlist={}",
        serde_json::json!([target.clone()])
    );

    // Scratch dirs (left in place for inspection).
    let spike_dir = std::env::current_dir().unwrap_or_default();
    let scratch = spike_dir.join("scratch");
    let outside = spike_dir.join("outside-policy");
    let _ = std::fs::create_dir_all(&scratch);
    let _ = std::fs::create_dir_all(&outside);
    let scratch_s = scratch.display().to_string();
    let outside_s = outside.display().to_string();
    let canary = outside.join("canary.txt");
    let _ = std::fs::write(&canary, b"secret outside the granted filesystem policy\n");
    let canary_s = canary.display().to_string();

    // The workload binary lives beside this exe; copy it into the granted dir.
    let self_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.to_path_buf()))
        .unwrap_or_default();
    let workload_src = self_dir.join("mxc-workload.exe");
    let workload_dst = scratch.join("mxc-workload.exe");
    match std::fs::copy(&workload_src, &workload_dst) {
        Ok(_) => println!("SPIKE: workload_staged={}", workload_dst.display()),
        Err(e) => println!(
            "SPIKE: workload_staged=FAIL src={} err={e}",
            workload_src.display()
        ),
    }
    let command = format!("{} 127.0.0.1:{}", workload_dst.display(), proxy.port);
    println!("SPIKE: target={target} path={path}");

    let env = vec![
        ("MXC_SPIKE_SCRATCH".to_string(), scratch_s.clone()),
        ("MXC_SPIKE_CANARY".to_string(), canary_s.clone()),
        ("MXC_SPIKE_DENY_WRITE".to_string(), outside_s.clone()),
        ("MXC_SPIKE_TARGET".to_string(), target.clone()),
        ("MXC_SPIKE_PATH".to_string(), path.clone()),
    ];

    // ---- 1. Validation evidence: allowedProxyPeer is an identity, not host:port ----
    let req_b = model2_request(
        command.clone(),
        scratch_s.clone(),
        scratch_s.clone(),
        proxy.port,
        true,
        Some(target.clone()),
        env.clone(),
    );
    match v1::probe(Some(&req_b)) {
        Ok(p) => println!(
            "SPIKE: request_probe_conflicting_peer={}",
            serde_json::to_string(&p).unwrap_or_else(|e| format!("\"serialize error: {e}\""))
        ),
        Err(e) => print_error("run_conflicting_peer", &e),
    }

    let (iso, _, _) = utc_now();
    println!("SPIKE: started_utc={iso}");
    let mut hard: Option<(i32, &'static str)> = None;

    // ---- 2. Canonical run: identity-less proxy deployment, REAL forwarding ----
    if suite != "negative" {
        let req_a = model2_request(
            command.clone(),
            scratch_s.clone(),
            scratch_s.clone(),
            proxy.port,
            true, // host loopback allow (identity-less proxy)
            None,
            env.clone(),
        );
        let out = launch(
            "canonical",
            req_a,
            &proxy,
            &backends,
            elevated,
            Expect::Required,
            proxy.port,
            &target,
        );
        if out.hard_fail {
            hard = Some((3, "canonical: guardrail_proxy_proof or real_https failed"));
        }
    }

    // ---- 3. Negative test: deliberately wrong identity-scoped form ----
    // The spike showed this combination launches, exits 0, and reports
    // warnings=[] while the proxy is unreachable. Guardrail 1 must catch it.
    if hard.is_none() && suite != "canonical" {
        let req_c = model2_request(
            command.clone(),
            scratch_s.clone(),
            scratch_s.clone(),
            proxy.port,
            false, // hostLoopback deny
            Some("MXC-SpikeUnpackagedProxy".to_string()),
            env.clone(),
        );
        let expect = if suite == "negative" {
            // `--suite=negative` arms the gate so the expected failure produces
            // the non-zero exit the guardrail contract requires.
            Expect::Required
        } else {
            Expect::ExpectFail
        };
        println!(
            "SPIKE: negative_case=identity_scoped_wrong_peer peer=MXC-SpikeUnpackagedProxy hostLoopback=deny gate_armed={}",
            expect == Expect::Required
        );
        let out = launch(
            "negative",
            req_c,
            &proxy,
            &backends,
            elevated,
            expect,
            proxy.port,
            &target,
        );
        if out.hard_fail && expect == Expect::Required {
            hard = Some((3, "negative-only: guardrail_proxy_proof FAIL (expected)"));
        } else if out.hard_fail {
            hard = Some((5, "negative test was NOT caught by the guardrail"));
        }
    }

    print_attestation_note();

    let accepts = proxy.accepts_total();
    proxy.stop();
    println!("SPIKE: proxy_accepts_total_after_stop={accepts}");
    println!(
        "SPIKE: scratch_dirs={}",
        serde_json::json!([scratch_s, outside_s])
    );

    match hard {
        Some((code, why)) => {
            println!("SPIKE: exit=nonzero code={code} reason=\"{why}\"");
            std::process::exit(code);
        }
        None => {
            println!("SPIKE: exit=0 all_expected_outcomes_observed");
            println!("SPIKE: done");
        }
    }
}
