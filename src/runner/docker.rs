//! The container engine, spoken to directly.
//!
//! Two decisions, both from measurement (`docs/research/build-runner/measurements.md`):
//!
//! * **The Engine API over the named pipe, never the `docker` CLI.** Rancher Desktop and
//!   Docker Desktop are the same dockerd behind a different endpoint, so one client covers
//!   both; a CLI shell-out would turn every flag difference into a bug report.
//! * **One request per connection.** The engine closes the pipe after a response when asked
//!   to (`Connection: close`), and a second write on the same handle fails with "broken
//!   pipe" - measured, not assumed.
//!
//! Only the slot lifecycle lives here so far: create, start, inspect, remove, and the
//! `/_ping` probe that tells the operator *which* engine answered.

use anyhow::{Context, Result, bail};
use std::io::{Read, Write};
use std::path::PathBuf;

/// The API version to speak. The engine on this machine reports min 1.41 / max 1.54; a
/// pinned floor inside that range stays valid across engine upgrades.
pub const API: &str = "v1.41";

/// Where the engine listens. `tcp://` is refused on purpose: a config value that moves
/// where builds run is a containment decision, not a convenience.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Endpoint {
    /// `npipe:////./pipe/docker_engine` or a bare `\\.\pipe\name`.
    Pipe(PathBuf),
    /// `unix:///var/run/docker.sock` (Linux hosts, WSL).
    Unix(PathBuf),
}

impl Endpoint {
    /// `DOCKER_HOST` if set, else the platform default. A `tcp://` or `ssh://` value is
    /// refused by name rather than silently ignored.
    pub fn resolve() -> Result<Self> {
        match std::env::var("DOCKER_HOST") {
            Ok(raw) if !raw.trim().is_empty() => Self::parse(&raw),
            _ => {
                #[cfg(windows)]
                {
                    Ok(Endpoint::Pipe(PathBuf::from(r"\\.\\pipe\\docker_engine")))
                }
                #[cfg(not(windows))]
                {
                    Ok(Endpoint::Unix(PathBuf::from("/var/run/docker.sock")))
                }
            }
        }
    }

    pub fn parse(raw: &str) -> Result<Self> {
        let raw = raw.trim();
        if let Some(rest) = raw.strip_prefix("npipe://") {
            // `npipe:////./pipe/x` carries a URL-style `//./pipe/x`; the engine wants a
            // Windows device path, so the leading `./` goes and `/` becomes `\`.
            let path = rest.trim_start_matches("//");
            let path = path.strip_prefix("./").unwrap_or(path);
            return Ok(Endpoint::Pipe(PathBuf::from(format!(
                r"\\.\{}",
                path.replace('/', "\\")
            ))));
        }
        if let Some(rest) = raw.strip_prefix("unix://") {
            return Ok(Endpoint::Unix(PathBuf::from(rest)));
        }
        if raw.starts_with(r"\\.\pipe\") {
            return Ok(Endpoint::Pipe(PathBuf::from(raw)));
        }
        if ["tcp://", "http://", "https://", "ssh://"]
            .iter()
            .any(|p| raw.starts_with(p))
        {
            bail!(
                "runner: refusing engine endpoint `{raw}` - a remote engine moves where builds \
                 run, outside the workspace and the audit; use a local pipe"
            );
        }
        bail!("runner: unsupported engine endpoint `{raw}`")
    }

    fn open(&self) -> Result<std::fs::File> {
        match self {
            Endpoint::Pipe(path) => std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(path)
                .with_context(|| format!("runner: open the engine pipe {}", path.display())),
            Endpoint::Unix(path) => {
                // A unix socket is not a file on Windows; this arm exists for Linux hosts.
                #[cfg(windows)]
                {
                    bail!(
                        "runner: unix socket {} is not available on Windows",
                        path.display()
                    )
                }
                #[cfg(not(windows))]
                {
                    use std::os::unix::net::UnixStream;
                    let stream = UnixStream::connect(path)
                        .with_context(|| format!("runner: connect {}", path.display()))?;
                    Ok(std::fs::File::from(stream))
                }
            }
        }
    }
}

/// One HTTP exchange with the engine.
pub struct Engine {
    endpoint: Endpoint,
}

/// A response, reduced to what the runner needs: status, headers lowercased, body.
#[derive(Debug)]
pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    pub fn json(&self) -> Result<serde_json::Value> {
        serde_json::from_slice(&self.body)
            .with_context(|| format!("runner: engine answered non-JSON ({})", self.status))
    }
}

impl Engine {
    pub fn connect(endpoint: Endpoint) -> Self {
        Engine { endpoint }
    }

    /// `GET /_ping` - the only honest way to learn whether an engine is there. A
    /// `Test-Path` on the pipe returns False while the API answers fine (measured).
    pub fn ping(&self) -> Result<String> {
        let r = self.request("GET", "/_ping", &[])?;
        if r.status != 200 {
            bail!("runner: engine /_ping answered {}", r.status);
        }
        Ok(String::from_utf8_lossy(&r.body).trim().to_string())
    }

    /// The engine version block, for the support line and for the API negotiation.
    pub fn version(&self) -> Result<serde_json::Value> {
        self.request("GET", "/version", &[])?.json()
    }

    pub fn request(&self, method: &str, path: &str, body: &[u8]) -> Result<Response> {
        let mut file = self.endpoint.open()?;
        // One request per connection: `Connection: close` makes the response
        // end-delimited, which is what the engine supports on a pipe.
        let mut head = format!(
            "{method} {path} HTTP/1.1\r\nHost: docker\r\nConnection: close\r\nAccept: application/json\r\n"
        );
        if !body.is_empty() {
            head.push_str("Content-Type: application/json\r\n");
            head.push_str(&format!("Content-Length: {}\r\n", body.len()));
        }
        head.push_str("\r\n");
        file.write_all(head.as_bytes())
            .context("runner: write the request head to the engine")?;
        if !body.is_empty() {
            file.write_all(body)
                .context("runner: write the request body to the engine")?;
        }
        let mut raw = Vec::new();
        file.read_to_end(&mut raw)
            .context("runner: read the engine's response")?;
        parse_response(&raw)
    }
}

/// Parse one HTTP/1.x response: status line, headers, then a body that is `Content-Length`
/// framed, chunked, or (with `Connection: close`) simply the rest of the stream.
fn parse_response(raw: &[u8]) -> Result<Response> {
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .context("runner: the engine's response has no header terminator")?;
    let head = String::from_utf8_lossy(&raw[..split]).into_owned();
    let rest = &raw[split + 4..];

    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .with_context(|| format!("runner: unparsable engine status line {status_line:?}"))?;

    let mut headers = Vec::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_ascii_lowercase(), v.trim().to_string()));
        }
    }
    let header = |name: &str| {
        headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    };

    let body = if header("transfer-encoding")
        .map(|v| v.to_ascii_lowercase().contains("chunked"))
        .unwrap_or(false)
    {
        dechunk(rest)?
    } else if let Some(len) = header("content-length").and_then(|v| v.parse::<usize>().ok()) {
        rest[..rest.len().min(len)].to_vec()
    } else {
        rest.to_vec()
    };

    Ok(Response {
        status,
        headers,
        body,
    })
}

/// Chunked transfer decoding: the engine uses it for JSON answers that are not
/// length-framed.
fn dechunk(mut rest: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let line_end = rest
            .windows(2)
            .position(|w| w == b"\r\n")
            .context("runner: truncated chunk header")?;
        let size_line = String::from_utf8_lossy(&rest[..line_end]).into_owned();
        let size_hex = size_line.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_hex, 16)
            .with_context(|| format!("runner: bad chunk size {size_hex:?}"))?;
        rest = &rest[line_end + 2..];
        if size == 0 {
            return Ok(out);
        }
        if rest.len() < size {
            bail!("runner: truncated chunk body");
        }
        out.extend_from_slice(&rest[..size]);
        rest = &rest[size..];
        if rest.starts_with(b"\r\n") {
            rest = &rest[2..];
        }
    }
}

// ---------------------------------------------------------------------------
// Slots: the long-lived container a session builds in
// ---------------------------------------------------------------------------

/// The image a slot runs. Pinned by digest, because a floating tag is a silent upgrade of
/// the toolchain inside a boundary the operator audited: `eclipse-temurin:25-jdk` resolved
/// here on 2026-10-30, and the sample project's conventions require Java 25.
pub const RUNNER_IMAGE: &str =
    "eclipse-temurin@sha256:83f4a7fc27df94dcc7b8de04d14cbbba8da14406f921e966969c3b09000aa507";

/// Refuse a reference that is not digest-pinned. A tag can move; a digest cannot.
fn require_digest(image: &str) -> Result<()> {
    if !image.contains("@sha256:") {
        bail!(
            "runner: image `{image}` is not digest-pinned - a tag can move under the boundary, \
             so the image must be named as `name@sha256:...`"
        );
    }
    Ok(())
}

/// How a slot is created. Everything the workload cannot influence lives here; the only
/// field it contributes to a build is the project path and the task.
#[derive(Debug, Clone)]
pub struct SlotSpec {
    pub image: String,
    pub name: String,
    pub session: String,
}

impl SlotSpec {
    pub fn new(session: &str) -> Self {
        SlotSpec {
            image: RUNNER_IMAGE.to_string(),
            name: format!("saife-runner-{session}"),
            session: session.to_string(),
        }
    }
}

/// A created slot container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Slot {
    pub id: String,
    pub name: String,
}

impl Engine {
    /// Create (not start) a slot. `--network none`, no auto-remove, and a session label the
    /// sweep can find: a container that outlives a crashed supervisor is a stale build
    /// environment, and the label is what makes it findable.
    pub fn create_slot(&self, spec: &SlotSpec) -> Result<Slot> {
        require_digest(&spec.image)?;
        let body = serde_json::json!({
            "Image": spec.image,
            "Cmd": ["sleep", "infinity"],
            "Labels": { "saife.runner": "1", "saife.session": spec.session },
            "HostConfig": {
                "NetworkMode": "none",
                "AutoRemove": false,
            },
        });
        let path = format!("/{API}/containers/create?name={}", urlencode(&spec.name));
        let r = self.request("POST", &path, body.to_string().as_bytes())?;
        if r.status != 201 {
            bail!(
                "runner: engine refused the slot container ({}) {}",
                r.status,
                String::from_utf8_lossy(&r.body)
            );
        }
        let v = r.json()?;
        let id = v["Id"].as_str().unwrap_or_default().to_string();
        if id.is_empty() {
            bail!("runner: the engine created a container without an id");
        }
        Ok(Slot {
            id,
            name: spec.name.clone(),
        })
    }

    pub fn start_slot(&self, slot: &Slot) -> Result<()> {
        let r = self.request("POST", &format!("/{API}/containers/{}/start", slot.id), &[])?;
        if r.status != 204 && r.status != 304 {
            bail!(
                "runner: could not start slot {} ({}) {}",
                slot.name,
                r.status,
                String::from_utf8_lossy(&r.body)
            );
        }
        Ok(())
    }

    /// Is the slot running? The readiness gate for anything that talks into it.
    pub fn slot_running(&self, slot: &Slot) -> Result<bool> {
        let r = self.request("GET", &format!("/{API}/containers/{}/json", slot.id), &[])?;
        if r.status == 404 {
            return Ok(false);
        }
        if r.status != 200 {
            bail!("runner: inspect {} answered {}", slot.name, r.status);
        }
        let v = r.json()?;
        Ok(v["State"]["Running"].as_bool().unwrap_or(false))
    }

    pub fn remove_slot(&self, slot: &Slot) -> Result<()> {
        let r = self.request(
            "DELETE",
            &format!("/{API}/containers/{}?force=1", slot.id),
            &[],
        )?;
        if r.status != 204 && r.status != 404 {
            bail!(
                "runner: could not remove slot {} ({}) {}",
                slot.name,
                r.status,
                String::from_utf8_lossy(&r.body)
            );
        }
        Ok(())
    }

    /// Every slot container on the engine, running or not: the start-up sweep (T2.4) uses
    /// this to clean up after a supervisor that died without removing its slot.
    pub fn list_slots(&self) -> Result<Vec<Slot>> {
        let filters = r#"{"label":["saife.runner=1"]}"#;
        let r = self.request(
            "GET",
            &format!(
                "/{API}/containers/json?all=1&filters={}",
                urlencode(filters)
            ),
            &[],
        )?;
        if r.status != 200 {
            bail!("runner: list containers answered {}", r.status);
        }
        let v = r.json()?;
        let mut out = Vec::new();
        for c in v.as_array().cloned().unwrap_or_default() {
            let id = c["Id"].as_str().unwrap_or_default().to_string();
            let name = c["Names"]
                .as_array()
                .and_then(|n| n.first())
                .and_then(|n| n.as_str())
                .unwrap_or("")
                .trim_start_matches('/')
                .to_string();
            if !id.is_empty() {
                out.push(Slot { id, name });
            }
        }
        Ok(out)
    }
}

/// Percent-encode a query value. The runner only ever passes container names, labels and
/// filters, but a name is caller-adjacent enough to encode rather than trust.
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn docker_host_parsing_covers_the_schemes_and_refuses_remote_engines() {
        assert_eq!(
            Endpoint::parse("npipe:////./pipe/docker_engine").unwrap(),
            Endpoint::Pipe(PathBuf::from(r"\\.\pipe\docker_engine"))
        );
        assert_eq!(
            Endpoint::parse(r"\\.\pipe\rancher_docker").unwrap(),
            Endpoint::Pipe(PathBuf::from(r"\\.\pipe\rancher_docker"))
        );
        assert_eq!(
            Endpoint::parse("unix:///var/run/docker.sock").unwrap(),
            Endpoint::Unix(PathBuf::from("/var/run/docker.sock"))
        );
        for remote in ["tcp://buildbox:2376", "https://buildbox:2376", "ssh://box"] {
            let err = Endpoint::parse(remote).expect_err("a remote engine must be refused");
            assert!(
                format!("{err:#}").contains("remote engine"),
                "the refusal says why: {err:#}"
            );
        }
    }

    #[test]
    fn a_content_length_response_is_framed_exactly() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhelloEXTRA";
        let r = parse_response(raw).unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(r.body, b"hello");
    }

    #[test]
    fn a_chunked_response_is_decoded() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        let r = parse_response(raw).unwrap();
        assert_eq!(String::from_utf8_lossy(&r.body), "hello world");
    }

    /// LIVE (`-- --ignored`): a real slot container comes up with no network, is visible to
    /// the sweep, and is removed cleanly. This is T2.1 - the lifecycle the rest of S-2
    /// builds on.
    #[test]
    #[ignore = "needs a running container engine and the pinned runner image"]
    fn live_a_slot_starts_with_no_network_and_can_be_removed() {
        let engine = Engine::connect(Endpoint::resolve().expect("endpoint"));
        let session = format!("probe{}", std::process::id());
        let spec = SlotSpec::new(&session);

        // A previous crashed run must not confuse this one.
        for old in engine.list_slots().unwrap_or_default() {
            if old.name == spec.name {
                let _ = engine.remove_slot(&old);
            }
        }

        let slot = engine.create_slot(&spec).expect("create the slot");
        engine.start_slot(&slot).expect("start the slot");
        assert!(
            engine.slot_running(&slot).expect("inspect"),
            "slot must be running"
        );

        let listed = engine.list_slots().expect("list slots");
        assert!(
            listed.iter().any(|s| s.id == slot.id),
            "the sweep must see the slot by label: {listed:?}"
        );

        engine.remove_slot(&slot).expect("remove the slot");
        assert!(
            !engine.slot_running(&slot).expect("inspect after remove"),
            "a removed slot is not running"
        );
    }

    /// LIVE (`-- --ignored`): the real engine on this machine, spoken to over the pipe.
    /// Proves the client can open the pipe, ping, and negotiate a version without the
    /// `docker` CLI being involved at all.
    #[test]
    #[ignore = "needs a running container engine"]
    fn live_the_engine_answers_over_the_pipe() {
        let engine = Engine::connect(Endpoint::resolve().expect("endpoint"));
        let pong = engine.ping().expect("engine answers /_ping");
        assert_eq!(pong, "OK");

        let v = engine.version().expect("engine answers /version");
        let api = v["ApiVersion"].as_str().unwrap_or_default();
        assert!(
            api.starts_with("1."),
            "the engine reports an API version: {v}"
        );
        eprintln!(
            "live: ping OK, api={api}, engine={}, os={}/{}",
            v["Version"].as_str().unwrap_or("?"),
            v["Os"].as_str().unwrap_or("?"),
            v["Arch"].as_str().unwrap_or("?")
        );
    }

    #[test]
    fn a_close_delimited_response_is_the_rest_of_the_stream() {
        let raw = b"HTTP/1.1 200 OK\r\n\r\nOK";
        assert_eq!(parse_response(raw).unwrap().body, b"OK");
    }
}
