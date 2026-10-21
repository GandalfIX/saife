//! Unelevated MXC `mxc-sdk 1.0.1` GA spike: ProcessContainer with proxy-only egress.
//!
//! One run emits `SPIKE:`-prefixed machine-readable lines. See SPIKE-REPORT.md.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use mxc_sdk::v1;
use mxc_sdk::v1::configs::{ProcessContainerConfig, ProcessContainerNetwork};
use mxc_sdk::v1::{
    ContainerRequest, Containment, FilesystemPolicy, NetworkAction, NetworkEgressPolicy,
    NetworkIngressPolicy, NetworkPolicy, NetworkRuntimeConfig, RunOptions, WaitResult,
};

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
        let mut info = TokenElevation { token_is_elevated: 0 };
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
// Minimal loopback TCP proxy: accept, read a request head, answer 200.
// ---------------------------------------------------------------------------

struct Proxy {
    port: u16,
    hits: Arc<AtomicUsize>,
    peers: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
}

impl Proxy {
    fn report(&self, label: &str) {
        println!(
            "SPIKE: proxy_hits_{label}={} proxy_peers_{label}={}",
            self.hits.load(Ordering::SeqCst),
            serde_json::to_string(&*self.peers.lock().unwrap()).unwrap()
        );
    }
}

fn start_proxy() -> Proxy {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback proxy");
    let port = listener.local_addr().unwrap().port();
    listener.set_nonblocking(true).expect("nonblocking listener");

    let hits = Arc::new(AtomicUsize::new(0));
    let peers = Arc::new(Mutex::new(Vec::new()));
    let stop = Arc::new(AtomicBool::new(false));

    let hits_t = Arc::clone(&hits);
    let peers_t = Arc::clone(&peers);
    let stop_t = Arc::clone(&stop);

    std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(180);
        while !stop_t.load(Ordering::Relaxed) && Instant::now() < deadline {
            match listener.accept() {
                Ok((mut stream, addr)) => {
                    hits_t.fetch_add(1, Ordering::SeqCst);
                    peers_t.lock().unwrap().push(addr.to_string());
                    let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
                    let _ = stream.set_write_timeout(Some(Duration::from_secs(3)));
                    let mut buf = [0u8; 512];
                    let n = stream.read(&mut buf).unwrap_or(0);
                    let head = String::from_utf8_lossy(&buf[..n]).to_string();
                    let is_connect = head.to_ascii_uppercase().starts_with("CONNECT");
                    // Log the observed request head on stderr so the parent can
                    // show it (the parent's stdout is the SPIKE stream).
                    eprintln!(
                        "PROXY: accept peer={addr} bytes={n} request={:?}",
                        head.lines().next().unwrap_or("")
                    );
                    let reply: &[u8] = if is_connect {
                        b"HTTP/1.1 200 Connection Established\r\n\r\n"
                    } else {
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
                    };
                    let _ = stream.write_all(reply);
                    let _ = stream.flush();
                    let _ = stream.shutdown(std::net::Shutdown::Both);
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(25));
                }
                Err(_) => break,
            }
        }
    });

    Proxy {
        port,
        hits,
        peers,
        stop,
    }
}

// ---------------------------------------------------------------------------
// Request construction
// ---------------------------------------------------------------------------

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
/// non-AppContainer proxy (our own spike process) has no package family name or
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

fn report_run(label: &str, result: Result<v1::ExecutionResult, v1::Error>) {
    match result {
        Ok(exec) => {
            let outcome = match exec.outcome {
                WaitResult::Exited(code) => format!("exited:{code}"),
                WaitResult::TimedOut => "timed_out".to_string(),
            };
            println!("SPIKE: {label}=ok outcome={outcome}");
            println!(
                "SPIKE: {label}_warnings={}",
                serde_json::to_string(&exec.warnings).unwrap()
            );
            for line in String::from_utf8_lossy(&exec.stdout).lines() {
                println!("SPIKE: {label}_stdout={line}");
            }
            for line in String::from_utf8_lossy(&exec.stderr).lines() {
                println!("SPIKE: {label}_stderr={line}");
            }
        }
        Err(e) => print_error(label, &e),
    }
}

fn main() {
    // ---- 1. Elevation ----
    let elevated = is_elevated();
    println!(
        "SPIKE: elevated={}",
        elevated.map(|e| e.to_string()).unwrap_or_else(|| "unknown".into())
    );
    println!(
        "SPIKE: process=pid:{} user={:?} admin_group_present={:?}",
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

    // ---- 2. Support probes ----
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

    // ---- 3. Local proxy ----
    let proxy = start_proxy();
    println!("SPIKE: proxy_port={}", proxy.port);
    println!("SPIKE: proxy_endpoint=127.0.0.1:{}", proxy.port);

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
        Err(e) => println!("SPIKE: workload_staged=FAIL src={} err={e}", workload_src.display()),
    }
    let command = format!("{} 127.0.0.1:{}", workload_dst.display(), proxy.port);

    let env = vec![
        ("MXC_SPIKE_SCRATCH".to_string(), scratch_s.clone()),
        ("MXC_SPIKE_CANARY".to_string(), canary_s.clone()),
        ("MXC_SPIKE_DENY_WRITE".to_string(), outside_s.clone()),
    ];

    // ---- 4a. Probe the canonical Model 2 request without launching ----
    let req_a = model2_request(
        command.clone(),
        scratch_s.clone(),
        scratch_s.clone(),
        proxy.port,
        true, // host loopback allow (identity-less proxy)
        None,
        env.clone(),
    );
    match v1::probe(Some(&req_a)) {
        Ok(p) => println!(
            "SPIKE: request_probe={}",
            serde_json::to_string(&p).unwrap_or_else(|e| format!("\"serialize error: {e}\""))
        ),
        Err(e) => print_error("request_probe", &e),
    }
    println!(
        "SPIKE: request_config_A={}",
        serde_json::json!({
            "command": command,
            "workingDirectory": scratch_s,
            "filesystem": {"readwritePaths": [scratch_s], "readonlyPaths": [], "deniedPaths": []},
            "network": {
                "egress": {"default": "deny"},
                "ingress": {"default": "allow", "hostLoopback": "allow"},
                "runtimeConfig": {"networkProxy": format!("http://127.0.0.1:{}", proxy.port)}
            },
            "processContainer": {"network": {"allowedProxyPeer": null}},
            "containment": "processcontainer",
            "environment": {"inheritDefault": true, "entries": env.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>()},
            "timeoutMs": 60000u32
        })
    );

    // ---- 4b. Launch the canonical run ----
    let started = Instant::now();
    let result = v1::run(req_a, RunOptions::default());
    println!("SPIKE: run_elapsed_ms={}", started.elapsed().as_millis());
    report_run("run", result);
    proxy.report("A");

    // ---- 4c. The literal brief: allowedProxyPeer = host:port ----
    // networking.md defines allowedProxyPeer as a Package Family Name / AppContainer
    // profile, NOT an endpoint. Record what the SDK does with a host:port.
    let req_b = model2_request(
        command.clone(),
        scratch_s.clone(),
        scratch_s.clone(),
        proxy.port,
        true, // keep host loopback allow -> deliberately conflicting identity
        Some(format!("127.0.0.1:{}", proxy.port)),
        env.clone(),
    );
    match v1::probe(Some(&req_b)) {
        Ok(p) => println!(
            "SPIKE: request_probe_conflicting_peer={}",
            serde_json::to_string(&p).unwrap_or_else(|e| format!("\"serialize error: {e}\""))
        ),
        Err(e) => print_error("request_probe_conflicting_peer", &e),
    }
    report_run("run_conflicting_peer", v1::run(req_b, RunOptions::default()));

    // ---- 4d. Identity-scoped shape: peer set, host loopback denied ----
    let req_c = model2_request(
        command.clone(),
        scratch_s.clone(),
        scratch_s.clone(),
        proxy.port,
        false,
        Some("MXC-SpikeUnpackagedProxy".to_string()),
        env.clone(),
    );
    match v1::probe(Some(&req_c)) {
        Ok(p) => println!(
            "SPIKE: request_probe_identity_scoped={}",
            serde_json::to_string(&p).unwrap_or_else(|e| format!("\"serialize error: {e}\""))
        ),
        Err(e) => print_error("request_probe_identity_scoped", &e),
    }
    report_run(
        "run_identity_scoped",
        v1::run(req_c, RunOptions::default()),
    );
    proxy.report("C");

    // ---- 5. Attestation surface ----
    println!(
        "SPIKE: attestation=absent \
         searched=[v1::*, v1::container::*, ProvisionRequest, ExecutionRequest, ContainerRequest, \
         ProcessContainerConfig, options::*] \
         terms=[attest*, pre_resume, preResume, created_not_running, createdNotRunning, \
         require_tier, required_tier, requireTier, requiredTier, resume] \
         note=\"only private/internal: process_container_common::appcontainer_runner::AppContainerScriptRunner::spawn_suspended (private fn) + SpawnedChild (private struct, resume())\""
    );
    println!("SPIKE: tier_source=available_backends[processcontainer].tier");
    let pc_tier = backends
        .iter()
        .find(|b| b.backend == "processcontainer")
        .map(|b| b.tier.clone().unwrap_or_else(|| "none".into()))
        .unwrap_or_else(|| "backend-absent".into());
    println!("SPIKE: tier={pc_tier}");

    proxy.stop.store(true, Ordering::SeqCst);
    println!(
        "SPIKE: scratch_dirs={}",
        serde_json::json!([scratch_s, outside_s])
    );
    println!("SPIKE: done");
}
