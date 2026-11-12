//! Which process owns a proxied connection (S-3, evidence only).
//!
//! The proxy authenticates the SESSION by run token, so today every process
//! inside the session can use every allow-listed host. Measuring which binary
//! actually holds the proxied TCP connection is the prerequisite for
//! binary-scoped rules (S-4) without changing any enforcement decision yet:
//! this module only OBSERVES, and `Unknown` never fails a request.
//!
//! Mechanism (port of OpenShell `openshell-mxc-boundary/src/socket_owner.rs`,
//! adapted to SAIFE's shape): the kernel TCP table
//! (`GetExtendedTcpTable(TCP_TABLE_OWNER_PID_ALL)`) is matched on the EXACT
//! four-tuple of the proxied connection, the owning PID is resolved to its
//! process image path (`QueryFullProcessImageNameW`) and hashed (SHA256).
//! The row's state is ignored on purpose - a half-closed connection is still
//! owned by the process that opened it, and filtering on state would turn a
//! working lookup into a race with the client.
//!
//! A lookup that resolves to THIS supervisor process is recorded as `self`,
//! never as a workload identity: `saife` itself holds sockets on this listener
//! (facade probes, intent endpoints, health checks), and a future S-4 rule
//! must never mistake supervisor traffic for the workload's.
//!
//! Everything here is evidence, not enforcement: an unresolvable owner (row
//! gone because the connection closed first, zero-PID system row, ambiguous
//! rows, OS call failure) is `Unknown`, and the audit leaf carries that gap
//! rather than a guess.

use std::net::SocketAddr;
use std::path::PathBuf;

/// The measured owner of one proxied connection.
///
/// Serialized into CONNECT-family audit leaves under `socket_owner`
/// (`audit_value`); the shapes are part of the chain's data and must stay
/// stable for readers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SocketOwner {
    /// The owning process was measured from the kernel TCP table.
    Identified(OwnerIdentity),
    /// The owning process is this supervisor itself (facade probes, intent
    /// endpoints, health checks). Not a workload identity.
    SaifeSelf,
    /// No measurement: connection gone before the lookup, a zero-PID system
    /// row, ambiguous rows, or an OS call failure.
    Unknown,
}

/// One identified process, with whatever evidence the OS handed over.
///
/// `real_path` / `sha256` are `None` when the OS refused the query (an
/// elevated or protected process answers `OpenProcess` with access denied) or
/// the binary could not be read/hashed. The PID is still first-class evidence:
/// it is the same number the kernel table named for this connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerIdentity {
    pub pid: u32,
    pub real_path: Option<String>,
    pub sha256: Option<String>,
}

impl SocketOwner {
    /// Measure the owner of the proxied connection the supervisor accepted.
    ///
    /// `client` is the accepted socket's PEER address (the workload's loopback
    /// endpoint) and `proxy` its LOCAL address (this listener). The kernel
    /// table names the row from the CLIENT's side: its local address is our
    /// peer, its remote address is our local, so the pair is swapped here -
    /// get this backwards and the lookup matches nothing, which an audit-only
    /// wire-in would hide as a field of `unknown` forever.
    pub fn measure(client: Option<SocketAddr>, proxy: Option<SocketAddr>) -> Self {
        let (Some(client), Some(proxy)) = (client, proxy) else {
            return SocketOwner::Unknown;
        };
        let rows = match client {
            SocketAddr::V4(_) => tcp_rows(AF_INET, read_v4_rows),
            SocketAddr::V6(_) => tcp_rows(AF_INET6, read_v6_rows),
        };
        classify(&rows, client, proxy)
    }

    /// The audit-leaf value for this measurement. `status` is the one field a
    /// reader may switch on; `pid`/`real_path`/`sha256` exist only on
    /// `identified` and are `null` individually when the OS did not hand them
    /// over.
    pub fn audit_value(&self) -> serde_json::Value {
        match self {
            SocketOwner::Unknown => serde_json::json!({"status": "unknown"}),
            SocketOwner::SaifeSelf => serde_json::json!({"status": "self"}),
            SocketOwner::Identified(i) => serde_json::json!({
                "status": "identified",
                "pid": i.pid,
                "real_path": i.real_path,
                "sha256": i.sha256,
            }),
        }
    }
}

/// One row of the kernel TCP owner table, reduced to what the four-tuple
/// match needs. The row's state is deliberately not carried (module doc).
#[derive(Debug, Clone, PartialEq, Eq)]
struct TcpRow {
    local: SocketAddr,
    remote: SocketAddr,
    pid: u32,
}

/// Classify the rows against the connection's client-side four-tuple.
///
/// Distinct owners on the same tuple (the table can carry a dying row beside
/// a live one across address reuse) are ambiguous and read as `Unknown`: the
/// field answers "which binary made this request", and two answers are no
/// answer. A zero PID is the system's row, not a workload's.
fn classify(rows: &[TcpRow], client: SocketAddr, proxy: SocketAddr) -> SocketOwner {
    let mut pids: Vec<u32> = rows
        .iter()
        .filter(|r| r.local == client && r.remote == proxy)
        .map(|r| r.pid)
        .collect();
    pids.sort_unstable();
    pids.dedup();
    match pids.as_slice() {
        [pid] if *pid == 0 => SocketOwner::Unknown,
        [pid] if *pid == std::process::id() => SocketOwner::SaifeSelf,
        [pid] => SocketOwner::Identified(identify(*pid)),
        _ => SocketOwner::Unknown,
    }
}

/// Resolve a PID to its process image path and hash the binary on disk.
fn identify(pid: u32) -> OwnerIdentity {
    let real_path = process_image_path(pid);
    let sha256 = real_path.as_deref().and_then(hash_file_hex);
    OwnerIdentity {
        pid,
        real_path,
        sha256,
    }
}

/// The process's Win32 image path, best effort. `None` on any refusal (an
/// elevated or protected process denies `OpenProcess` to us) - the PID stays
/// first-class evidence either way.
fn process_image_path(pid: u32) -> Option<String> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
        QueryFullProcessImageNameW,
    };
    use windows::core::PWSTR;

    // SAFETY: plain Win32 handle lifecycle; `handle` is valid from OpenProcess
    // to CloseHandle, and the path buffer outlives the query below.
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
        let mut buf = [0u16; 1024];
        let mut len = buf.len() as u32;
        let res = QueryFullProcessImageNameW(
            handle,
            PROCESS_NAME_WIN32,
            PWSTR(buf.as_mut_ptr()),
            &mut len,
        );
        let path = res
            .ok()
            .map(|()| String::from_utf16_lossy(&buf[..len as usize]));
        let _ = CloseHandle(handle);
        path.filter(|p| !p.is_empty())
    }
}

/// SHA256 of a file, lowercase hex, or `None` when the file cannot be read
/// (deleted between the table lookup and the read, locked, unreadable).
fn hash_file_hex(path: &str) -> Option<String> {
    use sha2::{Digest, Sha256};

    let mut file = std::fs::File::open(PathBuf::from(path)).ok()?;
    let mut hasher = Sha256::new();
    std::io::copy(&mut file, &mut hasher).ok()?;
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(digest.len() * 2);
    for b in digest {
        hex.push_str(&format!("{b:02x}"));
    }
    Some(hex)
}

// --- kernel TCP table -------------------------------------------------------
//
// `iphlpapi.dll`'s `GetExtendedTcpTable` with `TCP_TABLE_OWNER_PID_ALL` (5).
// Declared directly here, like `net/loopback.rs` declares its API-set import:
// the `windows` crate feature that ships these types is not enabled, and the
// three structs are fixed ABI - wiring a whole crate feature in for one call
// would buy nothing the struct definitions below do not.

const AF_INET: u32 = 2;
const AF_INET6: u32 = 23;
const TCP_TABLE_OWNER_PID_ALL: u32 = 5;
const ERROR_INSUFFICIENT_BUFFER: u32 = 122;

windows::core::link!(
    "iphlpapi.dll"
    "system"
    fn GetExtendedTcpTable(
        ptcptable: *mut core::ffi::c_void,
        pdwsize: *mut u32,
        border: windows::core::BOOL,
        ulaf: u32,
        tableclass: u32,
        reserved: u32,
    ) -> u32
);

/// `MIB_TCPROW_OWNER_PID`. Addresses and ports arrive in NETWORK byte order
/// (the API hands them over exactly as they sit on the wire); the readers
/// convert, so this struct is never inspected directly.
#[repr(C)]
struct MibTcpRowOwnerPid {
    state: u32,
    local_addr: u32,
    local_port: u32,
    remote_addr: u32,
    remote_port: u32,
    owning_pid: u32,
}

#[repr(C)]
struct MibTcpTableOwnerPid {
    num_entries: u32,
    first_row: MibTcpRowOwnerPid,
}

/// `MIB_TCP6ROW_OWNER_PID`. Layout note: unlike the v4 row, `state` sits AFTER
/// the address pair here, not first - get this wrong and every field silently
/// reads as a different field.
#[repr(C)]
struct MibTcp6RowOwnerPid {
    local_addr: [u8; 16],
    local_scope_id: u32,
    local_port: u32,
    remote_addr: [u8; 16],
    remote_scope_id: u32,
    remote_port: u32,
    state: u32,
    owning_pid: u32,
}

#[repr(C)]
struct MibTcp6TableOwnerPid {
    num_entries: u32,
    first_row: MibTcp6RowOwnerPid,
}

/// Read every owner row of one address family. Rows are converted to host
/// form here (`TcpRow`), so the classifier never sees wire byte order.
fn tcp_rows(af: u32, read: fn(&[u8]) -> Vec<TcpRow>) -> Vec<TcpRow> {
    // First call with no buffer returns the required size in
    // ERROR_INSUFFICIENT_BUFFER. The table can grow between calls (every
    // connection on the host is a row), so the retry re-reads the size each
    // round instead of trusting the first number.
    let mut size = 0u32;
    for _ in 0..4 {
        let rc = unsafe {
            GetExtendedTcpTable(
                core::ptr::null_mut(),
                &mut size,
                windows::core::BOOL::from(false),
                af,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            )
        };
        if rc != ERROR_INSUFFICIENT_BUFFER || size == 0 {
            return Vec::new();
        }
        let mut buf = vec![0u8; size as usize];
        let rc = unsafe {
            GetExtendedTcpTable(
                buf.as_mut_ptr().cast(),
                &mut size,
                windows::core::BOOL::from(false),
                af,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            )
        };
        if rc == 0 {
            return read(&buf);
        }
        if rc != ERROR_INSUFFICIENT_BUFFER {
            return Vec::new();
        }
    }
    Vec::new()
}

fn ntohs(wire: u32) -> u16 {
    // The table stores a port as a DWORD whose low half is the port in
    // NETWORK byte order; the high half is zero (msdn documents the port
    // "in network byte order", the field is 32 bits wide).
    u16::from_be((wire & 0xFFFF) as u16)
}

fn read_v4_rows(buf: &[u8]) -> Vec<TcpRow> {
    // SAFETY: the buffer is the table the API just filled; the header's entry
    // count bounds the walk below, so a truncated or lying buffer reads at
    // most the rows its own count claims. `first_row` is a real struct field
    // (the table header carries the count at offset 0), so `addr_of!` points
    // at the actual first row - pointer arithmetic from the buffer start
    // would be wrong by the header's own size.
    let table = unsafe { &*(buf.as_ptr().cast::<MibTcpTableOwnerPid>()) };
    if buf.len() < 4 + table.num_entries as usize * std::mem::size_of::<MibTcpRowOwnerPid>() {
        // A truncated table would let the walk read past the buffer. Treat
        // the whole family as unreadable rather than trusting some rows.
        return Vec::new();
    }
    (0..table.num_entries as usize)
        .map(|i| {
            // SAFETY: row i is inside the buffer as long as the count is
            // honest; the count is bounded again here.
            let row = unsafe { &*std::ptr::addr_of!(table.first_row).add(i) };
            TcpRow {
                local: SocketAddr::from((
                    std::net::Ipv4Addr::from(u32::from_be(row.local_addr)),
                    ntohs(row.local_port),
                )),
                remote: SocketAddr::from((
                    std::net::Ipv4Addr::from(u32::from_be(row.remote_addr)),
                    ntohs(row.remote_port),
                )),
                pid: row.owning_pid,
            }
        })
        .collect()
}

fn read_v6_rows(buf: &[u8]) -> Vec<TcpRow> {
    // SAFETY: same contract as `read_v4_rows`; the v6 row is larger, so the
    // walk is written against ITS stride, not the v4 one.
    let table = unsafe { &*(buf.as_ptr().cast::<MibTcp6TableOwnerPid>()) };
    if buf.len() < 4 + table.num_entries as usize * std::mem::size_of::<MibTcp6RowOwnerPid>() {
        return Vec::new();
    }
    (0..table.num_entries as usize)
        .map(|i| {
            let row = unsafe { &*std::ptr::addr_of!(table.first_row).add(i) };
            TcpRow {
                local: SocketAddr::from((
                    std::net::Ipv6Addr::from(row.local_addr),
                    ntohs(row.local_port),
                )),
                remote: SocketAddr::from((
                    std::net::Ipv6Addr::from(row.remote_addr),
                    ntohs(row.remote_port),
                )),
                pid: row.owning_pid,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream};

    /// A live loopback connection resolves to its true owner. Both endpoints
    /// are measured the way the proxy sees them (peer + local of the accepted
    /// socket) and the way the client socket sees them - the swapped-pair
    /// contract has to hold in both directions or the wire-in is blind.
    #[test]
    fn resolves_the_supervisor_its_own_loopback_connection() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let server = listener.accept().unwrap().0;

        let client_side = SocketOwner::measure(client.local_addr().ok(), client.peer_addr().ok());
        let server_side = SocketOwner::measure(server.peer_addr().ok(), server.local_addr().ok());

        for m in [client_side, server_side] {
            let SocketOwner::SaifeSelf = m else {
                panic!("expected SaifeSelf for a self-connection, got {m:?}");
            };
            assert_eq!(
                m.audit_value()["status"],
                serde_json::json!("self"),
                "audit shape for the self case"
            );
        }
    }

    /// An address pair with no matching table row is `Unknown`, not a guess.
    #[test]
    fn a_pair_with_no_row_is_unknown() {
        // 127.0.0.1:9 (discard) is not connected from here; if some other
        // process on the host happens to hold exactly that four-tuple, the
        // assertion would read `identified` - port 9 is chosen because a
        // client that CONNECTS to the discard port closes immediately, so no
        // stable row can match this pair during the test.
        let m = SocketOwner::measure(
            Some("127.0.0.1:9".parse().unwrap()),
            Some("127.0.0.1:10".parse().unwrap()),
        );
        assert_eq!(m, SocketOwner::Unknown);
        assert_eq!(
            m.audit_value(),
            serde_json::json!({"status": "unknown"}),
            "audit shape for the unknown case"
        );
    }

    /// Classification rules on synthetic rows: a zero-PID row and an
    /// ambiguous tuple are `Unknown`, and this process's own PID is
    /// `SaifeSelf`. Kept off `measure` so no OS state is needed.
    #[test]
    fn classification_rules() {
        let own = std::process::id();
        let client: SocketAddr = "127.0.0.1:40000".parse().unwrap();
        let proxy: SocketAddr = "127.0.0.1:40001".parse().unwrap();
        let row = |pid: u32| TcpRow {
            local: client,
            remote: proxy,
            pid,
        };
        let rows = |pids: &[u32]| -> Vec<TcpRow> { pids.iter().map(|p| row(*p)).collect() };

        assert_eq!(classify(&rows(&[0]), client, proxy), SocketOwner::Unknown);
        assert_eq!(
            classify(&rows(&[own]), client, proxy),
            SocketOwner::SaifeSelf
        );
        assert_eq!(classify(&rows(&[7]), client, proxy).audit_value()["pid"], 7);
        assert_eq!(
            classify(&rows(&[7, 8]), client, proxy),
            SocketOwner::Unknown,
            "two owners on one tuple are no answer"
        );
        assert_eq!(classify(&[], client, proxy), SocketOwner::Unknown);
        // A row for a DIFFERENT tuple must not match this one.
        let other = TcpRow {
            local: proxy,
            remote: client,
            pid: 7,
        };
        assert_eq!(classify(&[other], client, proxy), SocketOwner::Unknown);
    }

    /// A foreign process's connection resolves to `identified` with the
    /// process image path and a 64-hex SHA256. Spawns a short-lived
    /// PowerShell that connects and idles; the connection must stay open for
    /// the row to name its PID.
    #[test]
    fn identifies_a_foreign_connecting_process() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let mut child = std::process::Command::new("powershell.exe")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                &format!(
                    "$c = New-Object System.Net.Sockets.TcpClient('127.0.0.1', {port}); \
                     if (-not $c.Connected) {{ exit 1 }}; Start-Sleep -Seconds 60"
                ),
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn the connecting child");

        let server = listener.accept().unwrap().0;
        let measured = SocketOwner::measure(server.peer_addr().ok(), server.local_addr().ok());
        child.kill().ok();
        child.wait().ok();

        let SocketOwner::Identified(ref identity) = measured else {
            panic!("expected an identified foreign owner, got {measured:?}");
        };
        assert_ne!(identity.pid, std::process::id());
        assert_eq!(identity.pid, child.id(), "the row must name the child");
        let path = identity
            .real_path
            .as_ref()
            .expect("foreign process image path");
        assert!(
            path.to_ascii_lowercase().contains("powershell"),
            "real path names the actual binary: {path}"
        );
        let hash = identity
            .sha256
            .as_ref()
            .expect("sha256 of the readable binary");
        assert_eq!(hash.len(), 64, "lowercase sha256 hex: {hash}");
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(
            measured.audit_value()["status"],
            serde_json::json!("identified"),
            "audit shape for the identified case"
        );
    }
}
