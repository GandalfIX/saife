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
            Endpoint::Pipe(path) => {
                // A named pipe has a limited number of instances, and the engine is busy
                // when they are all taken (`ERROR_PIPE_BUSY`, os error 231). That is a
                // retry, not a failure - concurrent requests (a build log plus a status
                // poll) hit it routinely, and reporting it as "engine unreachable" would
                // turn normal concurrency into a broken session.
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
                loop {
                    match std::fs::OpenOptions::new()
                        .read(true)
                        .write(true)
                        .open(path)
                    {
                        Ok(file) => return Ok(file),
                        Err(e)
                            if e.raw_os_error() == Some(231)
                                && std::time::Instant::now() < deadline =>
                        {
                            std::thread::sleep(std::time::Duration::from_millis(10));
                        }
                        Err(e) => {
                            return Err(e).with_context(|| {
                                format!("runner: open the engine pipe {}", path.display())
                            });
                        }
                    }
                }
            }
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

// ---------------------------------------------------------------------------
// Exec: running a command inside a slot, with its log as it is produced
// ---------------------------------------------------------------------------

impl Engine {
    /// Create an exec and return its id. `Tty: false` on purpose: the multiplexed stream carries
    /// stdout and stderr separately, and no terminal escapes end up in the build log.
    pub fn exec_create(
        &self,
        container: &str,
        cmd: &[String],
        workdir: &str,
        env: &[String],
    ) -> Result<String> {
        let body = serde_json::json!({
            "AttachStdout": true,
            "AttachStderr": true,
            "Tty": false,
            "WorkingDir": workdir,
            "Env": env,
            "Cmd": cmd,
        });
        let r = self.request(
            "POST",
            &format!("/{API}/containers/{container}/exec"),
            body.to_string().as_bytes(),
        )?;
        if r.status != 201 {
            bail!(
                "runner: engine refused the exec ({}) {}",
                r.status,
                String::from_utf8_lossy(&r.body)
            );
        }
        let v = r.json()?;
        let id = v["Id"].as_str().unwrap_or_default().to_string();
        if id.is_empty() {
            bail!("runner: the engine created an exec without an id");
        }
        Ok(id)
    }

    /// Start an exec and hand every output chunk to `on_chunk` **as it arrives**.
    ///
    /// The engine answers with a multiplexed stream when `Tty` is false: an 8-byte header
    /// (stream id, three zero bytes, a big-endian length) followed by that many payload bytes,
    /// repeated until the process ends. Reading it incrementally is the whole point - a build
    /// log that only appears when the build finishes is useless.
    pub fn exec_stream(&self, exec_id: &str, mut on_chunk: impl FnMut(&[u8])) -> Result<()> {
        let mut file = self.endpoint.open()?;
        let body = serde_json::json!({ "Detach": false, "Tty": false }).to_string();
        let head = format!(
            "POST /{API}/exec/{exec_id}/start HTTP/1.1\r\nHost: docker\r\nConnection: close\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        file.write_all(head.as_bytes())
            .context("runner: write the exec start head")?;
        file.write_all(body.as_bytes())
            .context("runner: write the exec start body")?;

        // Response head, byte by byte: the body follows with no length framing of its own.
        let mut resp_head = Vec::new();
        let mut byte = [0u8; 1];
        while !resp_head.ends_with(b"\r\n\r\n") {
            match file.read(&mut byte) {
                Ok(0) | Err(_) => bail!("runner: the engine closed before the exec answered"),
                Ok(_) => resp_head.push(byte[0]),
            }
            if resp_head.len() > 16 * 1024 {
                bail!("runner: exec response head too large");
            }
        }
        let head_text = String::from_utf8_lossy(&resp_head).into_owned();
        let status: u16 = head_text
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        if status != 200 && status != 101 {
            bail!("runner: exec start answered {status}");
        }
        // The engine answers `Transfer-Encoding: chunked`, and inside those HTTP chunks is the
        // multiplexed frame stream. Both layers have to be unwrapped, and a frame may span
        // chunks - so bytes are buffered until a whole frame is present.
        let chunked = head_text
            .to_ascii_lowercase()
            .contains("transfer-encoding: chunked");
        let mut reader = std::io::BufReader::new(file);
        let mut pending: Vec<u8> = Vec::new();
        loop {
            if pending.len() >= 8 {
                let size =
                    u32::from_be_bytes([pending[4], pending[5], pending[6], pending[7]]) as usize;
                if pending.len() >= 8 + size {
                    if size > 0 {
                        on_chunk(&pending[8..8 + size]);
                    }
                    pending.drain(..8 + size);
                    continue;
                }
            }
            let more = if chunked {
                Self::read_http_chunk(&mut reader)?
            } else {
                let mut buf = [0u8; 8192];
                match reader.read(&mut buf) {
                    Ok(0) | Err(_) => None,
                    Ok(n) => Some(buf[..n].to_vec()),
                }
            };
            match more {
                Some(bytes) if !bytes.is_empty() => pending.extend_from_slice(&bytes),
                _ => return Ok(()),
            }
        }
    }

    /// Read one HTTP chunk (the engine sends `Transfer-Encoding: chunked` on the exec stream).
    fn read_http_chunk(reader: &mut impl std::io::BufRead) -> Result<Option<Vec<u8>>> {
        let mut size_line = String::new();
        if reader.read_line(&mut size_line)? == 0 {
            return Ok(None);
        }
        let size_hex = size_line.trim_end().split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_hex, 16)
            .with_context(|| format!("runner: bad HTTP chunk size {size_hex:?}"))?;
        if size == 0 {
            // Trailer: consume the terminating empty line.
            let mut trailer = String::new();
            let _ = reader.read_line(&mut trailer);
            return Ok(None);
        }
        let mut buf = vec![0u8; size];
        reader
            .read_exact(&mut buf)
            .context("runner: truncated HTTP chunk")?;
        let mut crlf = String::new();
        let _ = reader.read_line(&mut crlf);
        Ok(Some(buf))
    }

    /// The exit code of a finished exec. `Running: true` means the caller polled too early.
    pub fn exec_exit(&self, exec_id: &str) -> Result<Option<i32>> {
        let r = self.request("GET", &format!("/{API}/exec/{exec_id}/json"), &[])?;
        if r.status != 200 {
            bail!("runner: exec inspect answered {}", r.status);
        }
        let v = r.json()?;
        if v["Running"].as_bool().unwrap_or(true) {
            return Ok(None);
        }
        Ok(v["ExitCode"].as_i64().map(|c| c as i32))
    }
}

/// `Ok(true)` when the buffer was filled; `Ok(false)` on a clean EOF at the first byte.
fn read_exact_or_eof(file: &mut std::fs::File, buf: &mut [u8]) -> Result<bool> {
    let mut got = 0;
    while got < buf.len() {
        match file.read(&mut buf[got..]) {
            Ok(0) => {
                if got == 0 {
                    return Ok(false);
                }
                bail!("runner: truncated stream");
            }
            Ok(n) => got += n,
            Err(e) => return Err(e).context("runner: read the exec stream"),
        }
    }
    Ok(true)
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

    /// LIVE (`-- --ignored`): a command runs inside the slot, its output arrives as it is
    /// produced, and the exit code comes back. This is the mechanism every build uses.
    #[test]
    #[ignore = "needs a running container engine and the pinned runner image"]
    fn live_a_command_runs_in_the_slot_and_streams_its_output() {
        let g = SlotGuard::start(&format!("exec{}", std::process::id()));
        // stdout, stderr, a delayed line and a non-zero exit.
        let cmd = vec![
            "sh".to_string(),
            "-c".to_string(),
            "echo first; echo oops >&2; sleep 1; echo second; exit 3".to_string(),
        ];
        let exec_id = g
            .engine
            .exec_create(&g.slot.id, &cmd, "/", &[])
            .expect("create exec");

        let mut chunks: Vec<(u128, String)> = Vec::new();
        let started = std::time::Instant::now();
        g.engine
            .exec_stream(&exec_id, |chunk| {
                chunks.push((
                    started.elapsed().as_millis(),
                    String::from_utf8_lossy(chunk).into_owned(),
                ));
            })
            .expect("stream the exec");
        let all: String = chunks.iter().map(|(_, c)| c.as_str()).collect();

        assert!(all.contains("first"), "stdout arrives: {all:?}");
        assert!(all.contains("oops"), "stderr arrives: {all:?}");
        assert!(all.contains("second"), "the delayed line arrives: {all:?}");
        assert!(
            chunks.first().map(|(ms, _)| *ms < 800).unwrap_or(false),
            "the first chunk must arrive before the sleeps finish, not at the end: {chunks:?}"
        );
        assert_eq!(
            g.engine.exec_exit(&exec_id).expect("exit code"),
            Some(3),
            "the exit code is reported, not inferred"
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
    /// A slot that removes itself even when the test panics: the first failing runs of these
    /// legs left containers behind, which is exactly the leak the start-up sweep exists to
    /// clean up - the tests should not be the thing that creates the mess.
    struct SlotGuard {
        engine: Engine,
        slot: Slot,
    }

    impl SlotGuard {
        fn start(session: &str) -> Self {
            let engine = Engine::connect(Endpoint::resolve().expect("endpoint"));
            let spec = SlotSpec::new(session);
            for old in engine.list_slots().unwrap_or_default() {
                if old.name == spec.name {
                    let _ = engine.remove_slot(&old);
                }
            }
            let slot = engine.create_slot(&spec).expect("create the slot");
            engine.start_slot(&slot).expect("start the slot");
            SlotGuard { engine, slot }
        }
    }

    impl Drop for SlotGuard {
        fn drop(&mut self) {
            let _ = self.engine.remove_slot(&self.slot);
        }
    }

    /// LIVE (`-- --ignored`): a real slot container comes up with no network and is visible
    /// to the sweep. T2.1's lifecycle, on the real engine.
    #[test]
    #[ignore = "needs a running container engine and the pinned runner image"]
    fn live_a_slot_starts_with_no_network_and_can_be_removed() {
        let g = SlotGuard::start(&format!("slot{}", std::process::id()));
        assert!(
            g.engine.slot_running(&g.slot).expect("inspect"),
            "slot must be running"
        );
        let listed = g.engine.list_slots().expect("list slots");
        assert!(
            listed.iter().any(|s| s.id == g.slot.id),
            "the sweep must see the slot by label: {listed:?}"
        );
        // A container reaches the whole host loopback otherwise, so `none` is asserted rather
        // than trusted.
        let inspect = g
            .engine
            .request("GET", &format!("/{API}/containers/{}/json", g.slot.id), &[])
            .expect("inspect json")
            .json()
            .expect("json body");
        assert_eq!(
            inspect["HostConfig"]["NetworkMode"].as_str(),
            Some("none"),
            "a slot is created with no network: {inspect}"
        );
    }
}
