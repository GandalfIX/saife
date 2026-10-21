//! The workload that runs INSIDE the MXC ProcessContainer.
//!
//! It prints machine-readable `CHILD:` lines so the parent spike can prove:
//!   1. MXC injected HTTP_PROXY / HTTPS_PROXY into the child environment,
//!   2. the child can reach the caller's loopback proxy,
//!   3. a direct (non-proxy) outbound connection is refused/blocked.
//!
//! argv[1] = proxy endpoint as host:port (no scheme).

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

fn env_report(name: &str) -> String {
    match std::env::var(name) {
        Ok(v) => format!("CHILD: env {name}={v}"),
        Err(_) => format!("CHILD: env {name}=<unset>"),
    }
}

fn main() {
    println!("CHILD: pid={}", std::process::id());
    println!("CHILD: exe={}", std::env::current_exe().unwrap_or_default().display());
    println!("CHILD: cwd={}", std::env::current_dir().unwrap_or_default().display());

    for name in ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "NO_PROXY", "no_proxy"] {
        println!("{}", env_report(name));
    }
    println!(
        "CHILD: env NO_PROXY_BYPASSES_PROXY={:?}",
        std::env::var("NO_PROXY").map(|v| v.contains("127.0.0.1")).unwrap_or(false)
    );

    let proxy_arg = std::env::args().nth(1).unwrap_or_else(|| "127.0.0.1:1".to_string());

    // ---- 1. Reach the caller's loopback proxy over raw TCP ----
    match proxy_arg.parse::<SocketAddr>() {
        Ok(addr) => match TcpStream::connect_timeout(&addr, Duration::from_secs(5)) {
            Ok(mut stream) => {
                println!("CHILD: proxy_connect=ok peer={addr}");
                let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
                let req = "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n";
                let sent = stream.write_all(req.as_bytes());
                println!("CHILD: proxy_request_sent={:?}", sent.is_ok());
                let mut buf = [0u8; 128];
                match stream.read(&mut buf) {
                    Ok(n) if n > 0 => {
                        let head = String::from_utf8_lossy(&buf[..n]).replace("\r\n", " | ");
                        println!("CHILD: proxy_response=\"{head}\"");
                        println!("CHILD: proxy_reachable=true");
                    }
                    Ok(_) => println!("CHILD: proxy_response=<eof> proxy_reachable=false"),
                    Err(e) => println!("CHILD: proxy_response_err={e} proxy_reachable=false"),
                }
            }
            Err(e) => {
                println!("CHILD: proxy_connect=fail peer={addr} err={e} kind={:?}", e.kind());
                println!("CHILD: proxy_reachable=false");
            }
        },
        Err(e) => println!("CHILD: proxy_addr_parse=fail arg={proxy_arg} err={e}"),
    }

    // ---- 2. Direct egress, raw IP (no DNS dependency) ----
    let direct: SocketAddr = "1.1.1.1:443".parse().unwrap();
    match TcpStream::connect_timeout(&direct, Duration::from_secs(6)) {
        Ok(_) => println!("CHILD: direct_egress=CONNECTED(!!) peer={direct}"),
        Err(e) => println!(
            "CHILD: direct_egress=blocked peer={direct} err={e} os_code={:?} kind={:?}",
            e.raw_os_error(),
            e.kind()
        ),
    }

    // ---- 3. Direct egress to a public hostname (proves DNS + connect posture) ----
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
        Err(e) => println!("CHILD: dns_resolve=blocked err={e} os_code={:?}", e.raw_os_error()),
    }

    // ---- 4. Filesystem probes: granted dir vs ungranted host paths ----
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
    // Identity evidence: the container SID/token differs from the interactive user.
    println!(
        "CHILD: env USERNAME={:?} USERPROFILE={:?}",
        std::env::var("USERNAME").ok(),
        std::env::var("USERPROFILE").ok()
    );

    println!("CHILD: done");
}
