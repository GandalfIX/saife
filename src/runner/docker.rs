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
///
/// `Clone` because a slot outlives the call that made it: the idle watchdog and the session's
/// teardown both need their own handle, and the endpoint is immutable anyway.
#[derive(Clone)]
pub struct Engine {
    endpoint: Endpoint,
}

/// A response, reduced to what the runner needs: status, headers lowercased, body.
#[derive(Debug)]
pub struct Response {
    pub status: u16,
    /// Kept parsed, not dropped: the engine's capability probe (T2.6) reads answers
    /// like `X-Docker-Experiment` off them, and a response that threw its headers away
    /// would have to re-dial to see them.
    #[allow(dead_code)]
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    /// Look a header up by its **lowercased** name (the parser stores keys that way).
    /// No caller in the slot lifecycle yet: the headers exist for the probe, so the
    /// accessor that reads them exists with them.
    #[allow(dead_code)]
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
    ///
    /// No caller in the session path yet: `ping` is what a build needs, and the version
    /// block belongs to the capability probe (T2.6) that reports *which* engine answered.
    /// The live leg in this module is what exercises it today.
    #[allow(dead_code)]
    pub fn version(&self) -> Result<serde_json::Value> {
        self.request("GET", "/version", &[])?.json()
    }

    pub fn request(&self, method: &str, path: &str, body: &[u8]) -> Result<Response> {
        self.request_typed(method, path, body, "application/json")
    }

    /// The same exchange with an explicit content type: `/archive` takes a tar, and the
    /// engine is entitled to reject a body labelled as JSON.
    pub fn request_typed(
        &self,
        method: &str,
        path: &str,
        body: &[u8],
        content_type: &str,
    ) -> Result<Response> {
        self.request_typed_within(method, path, body, content_type, ENGINE_DEADLINE)
    }

    /// [`request_typed`] with an explicit deadline. Callers that know how long their request
    /// *should* take use this: a copy of a 300 KB tree that has not answered in seconds is not
    /// slow, it is stuck (`PUT /archive` was measured never answering at all).
    pub fn request_typed_within(
        &self,
        method: &str,
        path: &str,
        body: &[u8],
        content_type: &str,
        deadline: std::time::Duration,
    ) -> Result<Response> {
        // The named pipe supports no read timeout, so the bound is a thread and a channel:
        // measured, a stalled `PUT /archive` hung the CLI indefinitely with the container left
        // up and `/src` empty (T6.2). An engine that does not answer in two minutes is an error
        // the user can read, not a command that never returns.
        let (tx, rx) = std::sync::mpsc::channel();
        let endpoint = self.endpoint.clone();
        let (m, p, b, ct) = (
            method.to_string(),
            path.to_string(),
            body.to_vec(),
            content_type.to_string(),
        );
        std::thread::Builder::new()
            .name("saife-engine-request".into())
            .spawn(move || {
                let _ = tx.send(one_request(&endpoint, &m, &p, &b, &ct));
            })
            .context("runner: spawn the engine request")?;
        match rx.recv_timeout(deadline) {
            Ok(r) => r,
            Err(_) => bail!(
                "runner: the engine did not answer {method} {path} within {}s - it is up, but this \
                 request produced no response",
                deadline.as_secs()
            ),
        }
    }
}

/// One request on its own connection, extracted so it can run under a timeout.
fn one_request(
    endpoint: &Endpoint,
    method: &str,
    path: &str,
    body: &[u8],
    content_type: &str,
) -> Result<Response> {
    let mut file = endpoint.open()?;
    // One request per connection: `Connection: close` makes the response
    // end-delimited, which is what the engine supports on a pipe.
    let mut head = format!(
        "{method} {path} HTTP/1.1\r\nHost: docker\r\nConnection: close\r\nAccept: application/json\r\n"
    );
    if !body.is_empty() {
        head.push_str(&format!("Content-Type: {content_type}\r\n"));
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
/// The cache volume every slot mounts at `/cache`.
///
/// Global and shared on purpose: one warm Gradle cache is what makes an offline build
/// possible at all (904 MB for one Spring Boot project, measured), and a per-session volume
/// would pay the download again every session. The cost is that sessions share state -
/// acceptable while saife is single-user on one machine, and written down as a limit
/// rather than discovered later (see `docs/USER-GUIDE.md`, "Building in the sandbox").
///
/// **M11: what "shared state" actually means is CODE EXECUTION.** A write under
/// `/cache/init.d` is a Gradle init script that session B's build RUNS; a substituted
/// distribution or plugin jar is loaded by B's compiler. See [`slot_create_body`] for
/// the mount site and why the read-only fix is refused.
///
/// How long any engine request may take before it is treated as stuck.
pub const ENGINE_DEADLINE: std::time::Duration = std::time::Duration::from_secs(120);

pub const CACHE_VOLUME: &str = "saife-runner-cache";

// ---------------------------------------------------------------------------
// Resource limits for a build slot (M12)
// ---------------------------------------------------------------------------

/// Ceiling on tasks (threads *and* processes - the kernel's `pids` cgroup counts
/// both) inside a slot. A build that forks without bound is a host-wide DoS, and the
/// ceiling is high enough for Gradle's worker pool plus the Kotlin daemon.
pub const SLOT_PIDS_LIMIT: i64 = 1_024;

/// Four CPUs, in the engine's `NanoCpus` unit (1e-9 of a CPU). A build is CPU-hungry
/// but must not be able to starve the supervisor it is supposed to be isolated from.
pub const SLOT_NANO_CPUS: i64 = 4_000_000_000;

/// The **floor** for a slot's memory, in bytes: 4 GiB.
///
/// Not a tight default on purpose - a Kotlin/Gradle build needs 2-4 GiB for the daemons
/// alone, and a limit that fails a legitimate build is worse than no limit (operators
/// would raise it once, by hand, and never lower it again). This is the number the
/// code and the docs agree on; [`slot_memory_bytes`] can be raised without a rebuild.
pub const SLOT_MEMORY_FLOOR_BYTES: u64 = 4 * 1024 * 1024 * 1024;

/// A positive integer from the environment, or `None` when unset/invalid.
///
/// The override exists because the right ceiling depends on the machine: a 64 GiB
/// workstation can afford more than a 16 GiB laptop, and rebuilding saife to change a
/// number would push operators to remove the limit instead.
fn limit_override(name: &str) -> Option<u64> {
    std::env::var(name)
        .ok()?
        .trim()
        .parse::<u64>()
        .ok()
        .filter(|v| *v > 0)
}

/// Bytes of memory a slot may use: [`SLOT_MEMORY_FLOOR_BYTES`], or
/// `SAIFE_RUNNER_MEMORY_BYTES`.
pub fn slot_memory_bytes() -> u64 {
    limit_override("SAIFE_RUNNER_MEMORY_BYTES").unwrap_or(SLOT_MEMORY_FLOOR_BYTES)
}

/// CPU ceiling in `NanoCpus` units: [`SLOT_NANO_CPUS`], or `SAIFE_RUNNER_NANOCPUS`.
pub fn slot_nano_cpus() -> i64 {
    limit_override("SAIFE_RUNNER_NANOCPUS")
        .map(|v| v.min(i64::MAX as u64) as i64)
        .unwrap_or(SLOT_NANO_CPUS)
}

/// Task ceiling: [`SLOT_PIDS_LIMIT`], or `SAIFE_RUNNER_PIDS`.
pub fn slot_pids_limit() -> i64 {
    limit_override("SAIFE_RUNNER_PIDS")
        .map(|v| v.min(i64::MAX as u64) as i64)
        .unwrap_or(SLOT_PIDS_LIMIT)
}

pub const RUNNER_IMAGE: &str =
    "eclipse-temurin@sha256:83f4a7fc27df94dcc7b8de04d14cbbba8da14406f921e966969c3b09000aa507";

/// The JDK the pinned image carries, as a slot records it.
///
/// It travels as a label of its own even though the digest already pins the toolchain: the
/// sample project requires Java 25 (measured 2026-10-30), and a pin that moves the toolchain
/// must be visible as a *stale slot*, not as a build that fails with a toolchain error
/// half-way through. A slot whose `saife.jdk` is not this value is replaced.
pub const RUNNER_JDK: &str = "25";

/// Where a slot records when it was last used, **inside** the container.
///
/// The engine cannot say when a slot last ran a build (it knows when the container started,
/// not when it was used), so the fact is written by the runner and read back by whoever asks -
/// `saife runner status` in one process, the idle watchdog in another. Inside the container
/// rather than on the host on purpose: the marker dies with the container, so it can never
/// describe a slot that no longer exists.
pub const LAST_USE_DIR: &str = "/run/saife";
pub const LAST_USE_PATH: &str = "/run/saife/last-use";

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
    /// Slots are created with **no** network. The single exception is the explicit
    /// `saife runner prewarm`, which downloads the toolchain into the cache and must be a
    /// deliberate, visible step rather than something a build does on its own.
    pub allow_network: bool,
    /// The JDK the pin carries, recorded on the container so a toolchain change is a stale
    /// slot rather than a failed build (see [`RUNNER_JDK`]).
    pub jdk: String,
    /// The process that created the slot, and that process's creation time.
    ///
    /// A label pair, not a name: the sweep has to decide "is the session that owns this slot
    /// still running" from the container alone, and a pid on its own is not an answer because
    /// Windows reuses pids. The creation time makes the answer exact.
    pub owner_pid: u32,
    pub owner_created: i64,
}

impl SlotSpec {
    pub fn new(session: &str) -> Self {
        SlotSpec {
            image: RUNNER_IMAGE.to_string(),
            name: format!("saife-runner-{session}"),
            session: session.to_string(),
            allow_network: false,
            jdk: RUNNER_JDK.to_string(),
            owner_pid: std::process::id(),
            owner_created: crate::sandbox::dacl_journal::current_process_creation_time(),
        }
    }
}

/// A created slot container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Slot {
    pub id: String,
    pub name: String,
}

/// Everything the lifecycle and `saife runner status` need to know about a slot, read from the
/// engine's list answer plus the slot's own last-use marker.
///
/// One struct rather than an inspect per question: the sweep, the cap, the staleness check and
/// the status line all ask about the same slot, and four round trips to answer four questions
/// about one container is how the answers start disagreeing with each other.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SlotFacts {
    pub slot_id: String,
    pub name: String,
    /// The session label the slot was created with. Empty for a container made before the
    /// label existed, which is what makes it unowned.
    pub session: String,
    /// The digest-pinned reference the container was created from (`saife.image`), so a moved
    /// pin is visible as a fact rather than inferred from an image id.
    pub image: String,
    /// The JDK the pin carried at create time (`saife.jdk`).
    pub jdk: String,
    /// Unix seconds, the engine's own `Created`.
    pub created_at: i64,
    pub owner_pid: u32,
    pub owner_created: i64,
    pub running: bool,
    /// Unix seconds of the last build that used the slot, from [`LAST_USE_PATH`]. `None` when
    /// the marker cannot be read - which never makes a slot look idle (see
    /// `runner::lifecycle::idle_expired`).
    pub last_use: Option<i64>,
}

impl SlotFacts {
    pub fn slot(&self) -> Slot {
        Slot {
            id: self.slot_id.clone(),
            name: self.name.clone(),
        }
    }

    /// The creation time for a report: a wall clock a human can read, in the one format the
    /// rest of the repo prints (`2026-11-01T10:02:00Z`).
    pub fn created_iso(&self) -> String {
        iso8601(self.created_at)
    }

    /// "Idle since" for a report, or `None` when the slot cannot be dated.
    pub fn idle_since_iso(&self) -> Option<String> {
        self.last_use.map(iso8601)
    }
}

fn iso8601(unix_secs: i64) -> String {
    let ts = if unix_secs >= 0 {
        std::time::UNIX_EPOCH + std::time::Duration::from_secs(unix_secs as u64)
    } else {
        std::time::UNIX_EPOCH
    };
    crate::net::proxy::rfc3339_utc(ts)
}

impl Engine {
    /// Create (not start) a slot. `--network none`, no auto-remove, and a session label the
    /// sweep can find: a container that outlives a crashed supervisor is a stale build
    /// environment, and the label is what makes it findable.
    pub fn create_slot(&self, spec: &SlotSpec) -> Result<Slot> {
        require_digest(&spec.image)?;
        let body = slot_create_body(spec);
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

    /// Remove the slot, running or not.
    ///
    /// `force=1` and **no stop first**, which is measured rather than assumed: the slot's pid 1
    /// is `sleep`, pid 1 ignores a default-action SIGTERM, so `stop` waits out its whole timeout
    /// (5.13 s measured with `t=5`) while `remove --force` finishes in 0.16 s. A graceful stop is
    /// therefore not graceful here, just five seconds per slot on every teardown.
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

    /// Record "this slot was used now" inside the container.
    ///
    /// The engine has no notion of when a container was last *used*, and the idle kill has to
    /// be a fact rather than a guess - so the slot keeps it. One exec per acquisition (measured
    /// 73 ms against a 1.67 s warm build); a slot that cannot be dated is simply never
    /// idle-killed, which is why a failure here must not fail a build.
    pub fn touch_slot(&self, slot: &Slot) -> Result<()> {
        let cmd = vec![
            "sh".to_string(),
            "-c".to_string(),
            format!("mkdir -p {LAST_USE_DIR} && date +%s > {LAST_USE_PATH}"),
        ];
        let exec_id = self.exec_create(&slot.id, &cmd, "/", &[])?;
        self.exec_stream(&exec_id, |_| {})?;
        Ok(())
    }

    /// When this slot was last used, as recorded by [`Engine::touch_slot`].
    ///
    /// `None` covers every honest reason the marker is not there (never touched, an older slot,
    /// a stopped container that cannot be exec'd into): the caller must treat that as "not
    /// idle", never as "idle".
    pub fn slot_last_use(&self, slot: &Slot) -> Result<Option<i64>> {
        let cmd = vec![
            "sh".to_string(),
            "-c".to_string(),
            format!("cat {LAST_USE_PATH} 2>/dev/null"),
        ];
        let exec_id = self.exec_create(&slot.id, &cmd, "/", &[])?;
        let mut out = Vec::new();
        self.exec_stream(&exec_id, |chunk| out.extend_from_slice(chunk))?;
        Ok(String::from_utf8_lossy(&out).trim().parse::<i64>().ok())
    }

    /// Every slot container on the engine, running or not: the start-up sweep (T2.4) uses
    /// this to clean up after a supervisor that died without removing its slot.
    pub fn list_slots(&self) -> Result<Vec<Slot>> {
        Ok(self
            .list_slot_facts()?
            .into_iter()
            .map(|f| f.slot())
            .collect())
    }

    /// The same list with the facts attached (labels, creation time, owner, running state).
    ///
    /// Deliberately *without* the last-use marker: that costs an exec per slot, so it is read
    /// where it is needed (`lifecycle::facts_for_status`) instead of on every sweep.
    pub fn list_slot_facts(&self) -> Result<Vec<SlotFacts>> {
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
        Ok(slot_facts_from_json(&r.json()?))
    }
}

/// The engine's `/containers/json` answer, reduced to slot facts.
///
/// Every field comes from the container itself: the pin and the owner are labels the create
/// body wrote, so a slot cannot describe itself as something it is not.
fn slot_facts_from_json(list: &serde_json::Value) -> Vec<SlotFacts> {
    let mut out = Vec::new();
    for c in list.as_array().cloned().unwrap_or_default() {
        let slot_id = c["Id"].as_str().unwrap_or_default().to_string();
        if slot_id.is_empty() {
            continue;
        }
        let name = c["Names"]
            .as_array()
            .and_then(|n| n.first())
            .and_then(|n| n.as_str())
            .unwrap_or("")
            .trim_start_matches('/')
            .to_string();
        let labels = &c["Labels"];
        let label = |key: &str| labels[key].as_str().unwrap_or_default().to_string();
        let image = {
            let labelled = label("saife.image");
            if labelled.is_empty() {
                // A container from before the label existed: the engine only knows the image
                // *id*, which is a fact too - and it will not match a pinned digest, which is
                // exactly the right answer (the slot is stale).
                c["Image"].as_str().unwrap_or_default().to_string()
            } else {
                labelled
            }
        };
        out.push(SlotFacts {
            slot_id,
            name,
            session: label("saife.session"),
            image,
            jdk: label("saife.jdk"),
            created_at: c["Created"].as_i64().unwrap_or(0),
            owner_pid: label("saife.owner_pid").parse().unwrap_or(0),
            owner_created: label("saife.owner_created").parse().unwrap_or(0),
            running: c["State"].as_str() == Some("running"),
            last_use: None,
        });
    }
    out
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

// ---------------------------------------------------------------------------
// The volume: a project in, declared outputs out
// ---------------------------------------------------------------------------

impl Engine {
    /// Replace `path` inside the container with the archive's contents.
    ///
    /// `PUT /containers/{id}/archive` unpacks the tar into the directory named by `path`
    /// (which must exist), so the runner creates `/src` when the slot is made.
    /// Create the directories a slot needs before anything is copied into it.
    ///
    /// The slot's own command does `mkdir -p /src /cache` before `sleep infinity`, but nothing
    /// synchronises with it: `PUT /archive` requires the target directory to EXIST and answers
    /// `404 Could not find the file /src` when it loses that race. Measured - this was T6.2,
    /// which looked like a stalled request because the caller waited on a failure that had
    /// already happened. One exec costs ~70 ms and removes the race deterministically.
    pub fn ensure_dirs(&self, container: &str, dirs: &[&str]) -> Result<()> {
        let mut argv = vec!["mkdir".to_string(), "-p".to_string()];
        argv.extend(dirs.iter().map(|d| d.to_string()));
        let exec = self.exec_create(container, &argv, "/", &[])?;
        let mut sink = std::io::sink();
        self.exec_stream(&exec, |chunk| {
            let _ = std::io::Write::write_all(&mut sink, chunk);
        })?;
        match self.exec_exit(&exec)? {
            Some(0) => Ok(()),
            other => bail!("runner: could not prepare {dirs:?} in the slot (exit {other:?})"),
        }
    }

    pub fn put_archive(&self, container: &str, path: &str, tar: &[u8]) -> Result<()> {
        // Measured: this is the one call that sometimes never answers - the engine is up, the
        // container is running, and the PUT returns nothing at all until a deadline fires. A
        // copy this size takes milliseconds when it works, so waiting is pointless: retry on a
        // short deadline. Overwriting a partially extracted tree is harmless (same bytes), and
        // the alternative is a session that dies before its first build.
        const ATTEMPTS: u32 = 3;
        let mut last = String::new();
        for attempt in 1..=ATTEMPTS {
            match self.request_typed_within(
                "PUT",
                &format!(
                    "/{API}/containers/{container}/archive?path={}",
                    urlencode(path)
                ),
                tar,
                "application/x-tar",
                std::time::Duration::from_secs(20),
            ) {
                Ok(r) if r.status == 200 => return Ok(()),
                Ok(r) => {
                    last = format!("status {}: {}", r.status, String::from_utf8_lossy(&r.body));
                }
                Err(e) => last = format!("{e:#}"),
            }
            if attempt < ATTEMPTS {
                eprintln!("[saife] runner: the project copy did not take ({last}); retrying");
            }
        }
        bail!("runner: put archive to {path} failed {ATTEMPTS} times - last: {last}")
    }

    /// Read `path` back as a tar. Missing path is an empty result, not an error: a build
    /// that produced no outputs is a build that failed, and the caller reports that.
    pub fn get_archive(&self, container: &str, path: &str) -> Result<Vec<u8>> {
        let r = self.request(
            "GET",
            &format!(
                "/{API}/containers/{container}/archive?path={}",
                urlencode(path)
            ),
            &[],
        )?;
        if r.status == 404 {
            return Ok(Vec::new());
        }
        if r.status != 200 {
            bail!("runner: get archive answered {}", r.status);
        }
        Ok(r.body)
    }
}

// ---------------------------------------------------------------------------
// The cache volume
// ---------------------------------------------------------------------------

impl Engine {
    /// Create the cache volume if it is not there. Idempotent: the engine answers 201 on
    /// create and the same body on an existing name, so both are success.
    pub fn ensure_cache_volume(&self) -> Result<()> {
        let body = serde_json::json!({
            "Name": CACHE_VOLUME,
            "Labels": { "saife.runner": "1" },
        });
        let r = self.request(
            "POST",
            &format!("/{API}/volumes/create"),
            body.to_string().as_bytes(),
        )?;
        if r.status != 201 && r.status != 200 {
            bail!(
                "runner: could not create the cache volume ({}) {}",
                r.status,
                String::from_utf8_lossy(&r.body)
            );
        }
        Ok(())
    }

    /// Bytes the cache volume holds, from the engine's own accounting. `None` when the
    /// engine does not report usage for it (Podman's compat layer does not, reliably).
    pub fn cache_volume_bytes(&self) -> Result<Option<u64>> {
        let r = self.request("GET", &format!("/{API}/system/df"), &[])?;
        if r.status != 200 {
            return Ok(None);
        }
        let Ok(v) = r.json() else {
            return Ok(None);
        };
        for vol in v["Volumes"].as_array().cloned().unwrap_or_default() {
            if vol["Name"].as_str() == Some(CACHE_VOLUME) {
                let size = vol["UsageData"]["Size"].as_u64().unwrap_or(0);
                return Ok(Some(size));
            }
        }
        Ok(None)
    }
}

/// The create body for a slot, as JSON. Extracted so the properties that matter - no
/// network, the cache volume, the session label, the resource limits - are asserted
/// without an engine.
///
/// # The cache mount is a code-execution boundary (M11 residual)
///
/// Every slot mounts the same [`CACHE_VOLUME`] read-write, because an `--offline`
/// build needs one warm Gradle home. Session A can therefore write under
/// `/cache/init.d` (a Gradle **init script**, which B's build executes),
/// `/cache/caches/modules-2` (a substituted dependency jar, which B's compiler
/// loads), or the distribution itself. That is cross-session **code execution**,
/// not merely "B reads wrong bytes" - the plan's §4.1/§10.5 wording was corrected
/// to say so.
///
/// Read-only at `/cache` is NOT the fix: Gradle writes to its home (daemon logs,
/// `.lock`, caches) and the build fails. The honest fix is a per-session volume
/// seeded from this one, which is not a one-liner here: seeding ~900 MB needs a
/// helper container mounting both volumes and a copy per session, and `prewarm`,
/// the idle sweep and `status` all key on ONE volume name. Until that lands the
/// gap is documented here rather than papered over.
///
/// # Non-root `User`: out of scope (M12)
///
/// `HostConfig.User` is deliberately unset, so the build runs as root *inside the
/// container*. Setting it would need an ownership plan for `/src` and `/cache`
/// first: the tree arrives as an archive PUT (root-owned), the cache volume is
/// shared with a root-written prewarm, and a non-root user cannot read either
/// without a chown step per build. The container is unprivileged on the host and
/// `NetworkMode: none` by default; this is the remaining half of M12.
fn slot_create_body(spec: &SlotSpec) -> serde_json::Value {
    serde_json::json!({
        "Image": spec.image,
        // The marker's directory has to exist before the first `touch_slot`, and this command
        // is the only thing that runs before then.
        "Cmd": ["sh", "-c", format!("mkdir -p /src /cache {LAST_USE_DIR} && exec sleep infinity")],
        // The pin, the JDK and the owner travel as labels: the sweep and `status` read them
        // from the list answer, without an inspect and without a host-side table that could
        // disagree with the container it describes.
        "Labels": {
            "saife.runner": "1",
            "saife.session": spec.session,
            "saife.image": spec.image,
            "saife.jdk": spec.jdk,
            "saife.owner_pid": spec.owner_pid.to_string(),
            "saife.owner_created": spec.owner_created.to_string(),
        },
        "HostConfig": {
            "NetworkMode": if spec.allow_network { "bridge" } else { "none" },
            "AutoRemove": false,
            // M12 (verdict: confirmed): a build is untrusted code by construction, so it
            // gets a PID, CPU and memory ceiling of its own. Without them a runaway build
            // (or a fork bomb in a Gradle plugin) takes the host down with it - the
            // supervisor included. Memory is a floor, not a tight default; see
            // `SLOT_MEMORY_FLOOR_BYTES` and the `SAIFE_RUNNER_*` overrides.
            "PidsLimit": slot_pids_limit(),
            "NanoCpus": slot_nano_cpus(),
            "Memory": slot_memory_bytes(),
            "Mounts": [{
                "Type": "volume",
                "Source": CACHE_VOLUME,
                "Target": "/cache",
            }],
        },
    })
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
    /// The properties that matter are in the create body, so they can be asserted without
    /// an engine: no network, the cache volume, and the session label the sweep looks for.
    #[test]
    fn a_slot_is_created_without_network_and_with_the_cache_volume() {
        let spec = SlotSpec::new("s1");
        let body = slot_create_body(&spec);
        assert_eq!(body["HostConfig"]["NetworkMode"], "none");
        assert_eq!(body["HostConfig"]["Mounts"][0]["Source"], CACHE_VOLUME);
        assert_eq!(body["HostConfig"]["Mounts"][0]["Target"], "/cache");
        assert_eq!(body["Labels"]["saife.session"], "s1");
        assert!(
            body["Image"].as_str().unwrap().contains("@sha256:"),
            "the image is digest-pinned"
        );

        // ... and the prewarm container is the one exception, by explicit flag only.
        let mut warm = SlotSpec::new("p1");
        warm.allow_network = true;
        assert_eq!(
            slot_create_body(&warm)["HostConfig"]["NetworkMode"],
            "bridge"
        );
    }

    /// M12 (verdict: confirmed): a slot carries a PID, CPU and memory ceiling.
    /// Memory is at least the documented floor - Gradle/Kotlin daemons need
    /// GiBs, and a limit that fails a legitimate build would be raised once, by
    /// hand, and never lowered again. Generous by default, configurable without
    /// a rebuild through the `SAIFE_RUNNER_*` variables.
    #[test]
    fn a_slot_is_created_with_cpu_memory_and_pid_limits() {
        let _guard = crate::env_lock();
        // SAFETY: serialised by `env_lock`, and every variable is restored before
        // this test returns - the defaults below must not depend on the suite.
        let saved: Vec<(&str, Option<std::ffi::OsString>)> = [
            "SAIFE_RUNNER_MEMORY_BYTES",
            "SAIFE_RUNNER_NANOCPUS",
            "SAIFE_RUNNER_PIDS",
        ]
        .iter()
        .map(|k| (*k, std::env::var_os(k)))
        .collect();
        for (k, _) in &saved {
            unsafe { std::env::remove_var(k) };
        }

        let body = slot_create_body(&SlotSpec::new("limits"));
        let hc = &body["HostConfig"];
        let pids = hc["PidsLimit"].as_i64().expect("PidsLimit");
        let nanos = hc["NanoCpus"].as_i64().expect("NanoCpus");
        let memory = hc["Memory"].as_u64().expect("Memory is a byte count");
        assert!(
            (512..=1024).contains(&pids),
            "a fork bomb must hit a ceiling in the documented range: {pids}"
        );
        assert!(
            nanos > 0 && nanos <= 8 * 1_000_000_000,
            "a build must not take the whole host by default: {nanos}"
        );
        assert!(
            memory >= SLOT_MEMORY_FLOOR_BYTES,
            "the floor is the documented one (Gradle needs GiBs): {memory}"
        );

        // ... and the override changes the emitted body, not a copy of it.
        // SAFETY: as above.
        unsafe { std::env::set_var("SAIFE_RUNNER_MEMORY_BYTES", "8589934592") };
        unsafe { std::env::set_var("SAIFE_RUNNER_NANOCPUS", "2000000000") };
        unsafe { std::env::set_var("SAIFE_RUNNER_PIDS", "512") };
        let hc = &slot_create_body(&SlotSpec::new("limits"))["HostConfig"];
        assert_eq!(hc["Memory"], 8_589_934_592u64);
        assert_eq!(hc["NanoCpus"], 2_000_000_000i64);
        assert_eq!(hc["PidsLimit"], 512i64);

        // SAFETY: as above; the saved values go back so a parallel test's
        // view of the environment is what it saved.
        for (k, v) in saved {
            match v {
                Some(v) => unsafe { std::env::set_var(k, v) },
                None => unsafe { std::env::remove_var(k) },
            }
        }
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
        // M12, proved against the engine rather than the body we sent: the
        // limits are on the RUNNING container, not only in the create request.
        assert!(
            inspect["HostConfig"]["Memory"].as_u64().unwrap_or(0) >= SLOT_MEMORY_FLOOR_BYTES,
            "the engine must report the memory ceiling: {inspect}"
        );
        assert!(
            inspect["HostConfig"]["NanoCpus"].as_i64().unwrap_or(0) > 0,
            "the engine must report the CPU ceiling: {inspect}"
        );
        assert!(
            inspect["HostConfig"]["PidsLimit"].as_i64().unwrap_or(0) > 0,
            "the engine must report the PID ceiling: {inspect}"
        );
    }
    /// LIVE (`-- --ignored`): a project goes in through the archive API, a command sees it,
    /// and its output comes back out. The two directions the runner needs before it can
    /// build anything.
    #[test]
    #[ignore = "needs a running container engine and the pinned runner image"]
    fn live_a_tree_round_trips_through_the_slot() {
        let g = SlotGuard::start(&format!("sync{}", std::process::id()));
        let src = std::env::temp_dir().join(format!("saife-sync-live-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&src);
        std::fs::create_dir_all(src.join("nested")).unwrap();
        std::fs::write(src.join("hello.txt"), b"packed").unwrap();
        std::fs::write(src.join("nested/deep.txt"), b"deep").unwrap();
        let tar = crate::runner::sync::pack_dir(&src, &[]).expect("pack");

        g.engine
            .put_archive(&g.slot.id, "/src", &tar)
            .expect("put the tree");

        let exec_id = g
            .engine
            .exec_create(
                &g.slot.id,
                &[
                    "sh".to_string(),
                    "-c".to_string(),
                    "cat /src/hello.txt; mkdir -p /src/out; echo built > /src/out/art.txt"
                        .to_string(),
                ],
                "/src",
                &[],
            )
            .expect("create exec");
        let mut seen = String::new();
        g.engine
            .exec_stream(&exec_id, |c| seen.push_str(&String::from_utf8_lossy(c)))
            .expect("stream");
        assert_eq!(seen.trim(), "packed", "the file arrived inside the slot");
        assert_eq!(g.engine.exec_exit(&exec_id).unwrap(), Some(0));

        let out_tar = g
            .engine
            .get_archive(&g.slot.id, "/src/out")
            .expect("get archive");
        assert!(!out_tar.is_empty(), "the output directory came back");
        let dest = std::env::temp_dir().join(format!("saife-sync-out-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dest);
        std::fs::create_dir_all(&dest).unwrap();
        let n =
            crate::runner::sync::unpack_into_at(&out_tar, &dest, true, &|_| true).expect("unpack");
        assert!(n >= 1, "at least the artifact: {n}");
        assert_eq!(
            std::fs::read(dest.join("art.txt")).expect("artifact on the host"),
            b"built\n"
        );

        let _ = std::fs::remove_dir_all(&src);
        let _ = std::fs::remove_dir_all(&dest);
    }

    /// The facts a sweep and `saife runner status` need, parsed from the engine's own list
    /// answer: the pin and the owner travel as labels, so neither reader needs an inspect per
    /// container and neither can drift from the container it describes.
    #[test]
    fn slot_facts_come_from_the_engine_list_and_the_labels_on_the_container() {
        let body = serde_json::json!([
            {
                "Id": "abc123",
                "Names": ["/saife-runner-s1"],
                "Image": "sha256:deadbeef",
                "Created": 1_700_000_000_i64,
                "State": "running",
                "Labels": {
                    "saife.runner": "1",
                    "saife.session": "s1",
                    "saife.image": RUNNER_IMAGE,
                    "saife.jdk": RUNNER_JDK,
                    "saife.owner_pid": "8120",
                    "saife.owner_created": "133000000000000000"
                }
            },
            {
                "Id": "def456",
                "Names": ["/saife-runner-s2"],
                "Image": "sha256:cafe",
                "Created": 1_700_000_100_i64,
                "State": "exited",
                "Labels": { "saife.runner": "1" }
            }
        ]);

        let facts = slot_facts_from_json(&body);
        assert_eq!(facts.len(), 2, "both containers are slots");

        let mine = &facts[0];
        assert_eq!(mine.slot_id, "abc123");
        assert_eq!(mine.name, "saife-runner-s1", "the leading slash is dropped");
        assert_eq!(mine.session, "s1");
        assert_eq!(
            mine.image, RUNNER_IMAGE,
            "the report carries the pinned digest"
        );
        assert_eq!(mine.jdk, RUNNER_JDK);
        assert_eq!(mine.owner_pid, 8120);
        assert_eq!(mine.owner_created, 133_000_000_000_000_000);
        assert_eq!(mine.created_at, 1_700_000_000);
        assert!(mine.running);
        assert_eq!(mine.last_use, None, "the marker needs a call of its own");

        // A container from before the labels existed: unowned (so the sweep may take it) and
        // dated by the engine alone.
        let old = &facts[1];
        assert_eq!(old.session, "");
        assert_eq!(old.owner_pid, 0);
        assert_eq!(old.image, "sha256:cafe");
        assert!(!old.running);
    }

    /// The pin and the owner are labels so that the sweep and `status` read them from the
    /// list answer instead of inspecting every container, and so a *host-side* table never
    /// becomes a second source of truth for who owns what.
    #[test]
    fn the_pin_the_jdk_and_the_owner_are_labels_on_the_container() {
        let spec = SlotSpec::new("s1");
        let body = slot_create_body(&spec);
        assert_eq!(body["Labels"]["saife.image"], RUNNER_IMAGE);
        assert_eq!(body["Labels"]["saife.jdk"], RUNNER_JDK);
        assert_eq!(
            body["Labels"]["saife.owner_pid"],
            std::process::id().to_string()
        );
        assert_eq!(
            body["Labels"]["saife.owner_created"],
            spec.owner_created.to_string(),
            "the PID-reuse guard travels with the slot"
        );
        // The marker's directory has to exist before the first build touches it, and the
        // slot's own command is the only thing that runs before then.
        assert!(
            body["Cmd"][2]
                .as_str()
                .unwrap_or_default()
                .contains(LAST_USE_DIR),
            "the slot prepares the last-use marker's directory: {}",
            body["Cmd"][2]
        );
    }

    /// The owner is this process, captured at create time: a slot cannot be handed a pid it
    /// did not have.
    #[test]
    fn a_spec_records_the_pin_the_jdk_and_its_owning_process() {
        let spec = SlotSpec::new("s1");
        assert_eq!(spec.name, "saife-runner-s1");
        assert_eq!(spec.owner_pid, std::process::id());
        assert_eq!(spec.jdk, RUNNER_JDK);
        assert!(spec.image.contains("@sha256:"));
        assert!(
            spec.owner_created > 0,
            "the creation time is the PID-reuse guard, and the OS reports it"
        );
    }

    /// `status` prints times, not epoch integers: one formatter, shared with the rest of the
    /// repo (`net::proxy::rfc3339_utc`), so the report reads like every other timestamp.
    #[test]
    fn the_facts_format_their_times_for_the_status_line() {
        let facts = SlotFacts {
            slot_id: "abc123".to_string(),
            name: "saife-runner-s1".to_string(),
            session: "s1".to_string(),
            image: RUNNER_IMAGE.to_string(),
            jdk: RUNNER_JDK.to_string(),
            created_at: 1_700_000_000,
            owner_pid: 1,
            owner_created: 2,
            running: true,
            last_use: Some(1_700_000_060),
        };
        assert_eq!(facts.created_iso(), "2023-11-14T22:13:20Z");
        assert_eq!(
            facts.idle_since_iso().as_deref(),
            Some("2023-11-14T22:14:20Z")
        );
        assert_eq!(
            SlotFacts {
                last_use: None,
                ..facts.clone()
            }
            .idle_since_iso(),
            None,
            "an undatable slot says so instead of inventing a time"
        );
        assert_eq!(
            facts.slot(),
            Slot {
                id: "abc123".to_string(),
                name: "saife-runner-s1".to_string()
            }
        );
    }
}
