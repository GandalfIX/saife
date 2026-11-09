//! The glue: a build is slot -> sync in -> exec -> sync out.
//!
//! Everything it uses already exists and is measured: `docker.rs` speaks the Engine API,
//! `sync.rs` moves the tree, `server.rs` owns the protocol the workload sees. This module is
//! the state machine that joins them, and deliberately nothing else.

use crate::runner::BuildRequest;
use crate::runner::docker::{Engine, Slot, SlotSpec};
use crate::runner::lifecycle;
use crate::runner::server::{BuildEngine, BuildState, LogWindow};
use crate::runner::sync;
use anyhow::{Context, Result, bail};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// Directories that never go into the runner: they are outputs or caches, and a build that
/// starts from a stale one is not the build the user asked for.
const SKIP_IN_PROJECT: &[&str] = &["build", ".gradle", ".git"];

/// What the copy's header line says about the allow-list, or nothing when the whole project
/// travels. A closed list is only reviewable if the log that shows the failure also shows
/// the list that caused it.
fn copy_scope(paths: &[String]) -> String {
    if paths.is_empty() {
        String::new()
    } else {
        format!(" (paths: {})", paths.join(", "))
    }
}

/// The JDK inside the slot, as the pinned image publishes it (`eclipse-temurin`'s
/// `JAVA_HOME`). `gradlew` consults `JAVA_HOME` before `PATH`, so naming it makes the
/// toolchain the DIGEST's choice even for an image that stops setting the variable.
///
/// The supervisor's own `JAVA_HOME` is deliberately **not** passed through: it names a
/// Windows directory, i.e. a path that cannot exist in the slot, and honouring it would
/// let a host setting pick a JDK the pinned image is there to fix.
pub const IMAGE_JAVA_HOME: &str = "/opt/java/openjdk";

/// The cache volume's mount point: Gradle's home, so `--offline` resolves against the
/// one warm cache every slot shares (the 88 s first build is paid once per machine).
const CACHE_IN_SLOT: &str = "/cache";

/// M10 (verdict: confirmed): how much of a build's log the supervisor retains.
///
/// A build that prints gigabytes must not fill the supervisor's heap, and the
/// build deadline is not a bound on bytes (a build can print faster than it
/// builds). Two budgets, whichever trips first: [`LOG_LINE_CAP`] lines, or
/// [`LOG_BYTE_BUDGET`] bytes of line text. [`LOG_PARTIAL_CAP`] bounds the line
/// still being assembled, because a stream with no newline at all is unbounded
/// output too.
pub(crate) const LOG_LINE_CAP: usize = 8_192;
pub(crate) const LOG_BYTE_BUDGET: usize = 4 * 1024 * 1024;
pub(crate) const LOG_PARTIAL_CAP: usize = 64 * 1024;

/// What a reader sees when lines were dropped before its place (M10). Spelled
/// as a line so a `follow=1` reader can tell a gap from a build that was simply
/// quiet: one marker, emitted where the reader notices, never renumbered.
pub(crate) const LOG_TRUNCATED_MARKER: &str = "[saife] log truncated\n";

/// One build's retained log, addressed by ABSOLUTE line number.
///
/// `total` counts every line ever appended, evicted ones included. A reader's
/// `from` index is an absolute line number, so eviction can never shift a line
/// under a follower or hand it one twice (M10). Both budgets apply, whichever
/// trips first: [`LOG_LINE_CAP`] lines, or [`LOG_BYTE_BUDGET`] bytes.
struct BoundedLog {
    lines: std::collections::VecDeque<String>,
    bytes: usize,
    total: usize,
}

impl BoundedLog {
    fn new() -> Self {
        BoundedLog {
            lines: std::collections::VecDeque::new(),
            bytes: 0,
            total: 0,
        }
    }

    /// Append one line, then evict the OLDEST lines while the window is over
    /// either budget. Eviction is from the front only: the absolute numbering
    /// (`total - len` is the first retained index) stays stable no matter how
    /// many lines a burst drops.
    fn push(&mut self, line: String) {
        self.bytes += line.len();
        self.total += 1;
        self.lines.push_back(line);
        // Never evict below one line: the splitter caps every line at
        // [`LOG_PARTIAL_CAP`], far under the byte budget, so this only guards a
        // direct push of a monster line - and then ONE line is retained even
        // though it alone busts the budget.
        while (self.lines.len() > LOG_LINE_CAP || self.bytes > LOG_BYTE_BUDGET)
            && self.lines.len() > 1
        {
            match self.lines.pop_front() {
                Some(dropped) => self.bytes -= dropped.len(),
                None => break,
            }
        }
    }

    /// The lines from absolute index `from` onwards.
    ///
    /// `first` is the ABSOLUTE index of the first line returned: a follower
    /// whose place was evicted learns it here (`gap == true`) instead of being
    /// handed a window that silently repeats or skips lines.
    fn window(&self, from: usize) -> LogWindow {
        let base = self.total - self.lines.len();
        let skip = from.saturating_sub(base);
        LogWindow {
            first: base + skip,
            gap: from < base,
            lines: self.lines.iter().skip(skip).cloned().collect(),
        }
    }
}

/// Turns the exec stream's arbitrary chunks into lines, bounding the line that
/// is still being assembled.
///
/// The supervisor splits the stream itself because the engine hands it chunks
/// that end wherever the container flushed: the partial line between chunks is
/// the one buffer nothing else here bounds (M10). A line longer than
/// [`LOG_PARTIAL_CAP`] is cut there and marked, so the log never looks like the
/// build simply printed a short line.
struct LineSplitter {
    partial: String,
    capped: bool,
}

impl LineSplitter {
    fn new() -> Self {
        LineSplitter {
            partial: String::new(),
            capped: false,
        }
    }

    /// Feed one chunk; `sink` receives every complete line (and the marker
    /// ahead of any line that had to be cut).
    fn feed(&mut self, chunk: &[u8], sink: &mut dyn FnMut(String)) {
        self.partial.push_str(&String::from_utf8_lossy(chunk));
        loop {
            if let Some(pos) = self.partial.find('\n') {
                let mut line: String = self.partial.drain(..=pos).collect();
                if line.len() > LOG_PARTIAL_CAP {
                    truncate_on_char_boundary(&mut line, LOG_PARTIAL_CAP);
                    self.capped = true;
                }
                if self.capped {
                    self.capped = false;
                    sink(LOG_TRUNCATED_MARKER.to_string());
                }
                sink(line);
                continue;
            }
            if self.partial.len() > LOG_PARTIAL_CAP {
                // Keep the head, drop the tail, and mark it: the cut becomes
                // visible when the line finally ends (or the stream does).
                self.capped = true;
                truncate_on_char_boundary(&mut self.partial, LOG_PARTIAL_CAP);
            }
            break;
        }
    }

    /// End of stream: a cut is marked, whatever is left is the last line.
    fn finish(&mut self, sink: &mut dyn FnMut(String)) {
        if self.capped {
            self.capped = false;
            sink(LOG_TRUNCATED_MARKER.to_string());
        }
        if !self.partial.is_empty() {
            let tail = std::mem::take(&mut self.partial);
            sink(tail);
        }
    }
}

/// Truncate a `String` to at most `cap` bytes, on a char boundary - `String::truncate`
/// panics on a boundary split, and a multi-byte character at the cut is the tail we
/// are dropping anyway.
fn truncate_on_char_boundary(s: &mut String, cap: usize) {
    if s.len() <= cap {
        return;
    }
    let mut end = cap;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s.truncate(end);
}

struct BuildRecord {
    state: BuildState,
    lines: BoundedLog,
}

struct Inner {
    engine: Engine,
    /// The session workspace: every request's project resolves inside it.
    workspace: PathBuf,
    session: String,
    /// How long one build may run, from the profile's `limits.workloadTimeoutSecs`. A
    /// build is work the workload asked for, so it shares the workload's clock rather
    /// than inventing a second deadline an operator would have to discover.
    timeout: std::time::Duration,
    /// One slot per runner instance, created on the first build (measured: a warm daemon is
    /// 1.67 s against 4.95-13.6 s when it starts per build).
    slot: Mutex<Option<Slot>>,
    builds: Mutex<HashMap<String, BuildRecord>>,
    next: AtomicU64,
}

/// A `BuildEngine` backed by a real container engine.
pub struct DockerBuilds {
    inner: Arc<Inner>,
}

impl DockerBuilds {
    pub fn new(
        engine: Engine,
        workspace: PathBuf,
        session: String,
        timeout: std::time::Duration,
    ) -> Self {
        DockerBuilds {
            inner: Arc::new(Inner {
                engine,
                workspace,
                session,
                timeout,
                slot: Mutex::new(None),
                builds: Mutex::new(HashMap::new()),
                next: AtomicU64::new(1),
            }),
        }
    }

    /// The command a task turns into. A fixed argv, never a shell string built from the
    /// request: the task is already validated against the allow-list, and `sh -c` here would
    /// re-open the quoting question the allow-list exists to close.
    fn command_for(task: &str) -> Vec<String> {
        vec![
            "./gradlew".to_string(),
            "--offline".to_string(),
            "--console=plain".to_string(),
            task.to_string(),
        ]
    }

    /// The exec's environment: two constants, and nothing else.
    ///
    /// Not `std::env`: the request has no env field (T1.1), and inheriting the
    /// supervisor's would put Windows paths inside a Linux slot.
    pub fn exec_env() -> Vec<String> {
        vec![
            format!("JAVA_HOME={IMAGE_JAVA_HOME}"),
            format!("GRADLE_USER_HOME={CACHE_IN_SLOT}"),
        ]
    }
}

/// Append one log line to a build's record. Silent for an unknown id: a build a session
/// has torn down must not resurrect itself through a late write.
fn append_line(inner: &Inner, id: &str, line: String) {
    if let Some(rec) = inner
        .builds
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get_mut(id)
    {
        rec.lines.push(line);
    }
}

/// How a build's log stream ended.
#[derive(Debug)]
enum StreamEnd {
    /// The stream thread reported: the exec's output ended, or reading it failed.
    Finished(Result<()>),
    /// Nothing arrived within the deadline.
    TimedOut,
    /// The stream thread ended without reporting — it panicked, or could not start.
    /// Deliberately not `TimedOut`: blaming the clock for a defect would hide it.
    Lost,
}

/// Wait for a build's log stream, bounded by the deadline.
///
/// The stream itself blocks until the process ends, which is exactly the case a deadline
/// exists for, so the wait — not the read — is what holds the clock.
fn wait_for_stream(
    done: &std::sync::mpsc::Receiver<Result<()>>,
    deadline: std::time::Duration,
) -> StreamEnd {
    use std::sync::mpsc::RecvTimeoutError;
    match done.recv_timeout(deadline) {
        Ok(r) => StreamEnd::Finished(r),
        Err(RecvTimeoutError::Timeout) => StreamEnd::TimedOut,
        Err(RecvTimeoutError::Disconnected) => StreamEnd::Lost,
    }
}

/// The exec's exit code, as the state the workload polls. One place, so "the exit code is
/// propagated" is a property rather than a habit: `0` succeeded, anything else is that
/// exact code (1 = the build failed, 127 = the command does not exist), and no code at all
/// is not success.
fn state_for_exit(code: Option<i32>) -> BuildState {
    match code {
        Some(0) => BuildState::Succeeded(0),
        Some(code) => BuildState::Failed(code),
        None => BuildState::Failed(-1),
    }
}

impl BuildEngine for DockerBuilds {
    fn start(&self, req: BuildRequest) -> Result<String> {
        let inner = Arc::clone(&self.inner);
        let slot = self.ensure_slot()?;

        // Sync in: the measured-cheap direction (2.8 s for 20 000 files against 53 s for a
        // bind mount read of the same tree).
        //
        // A request that named its paths copies exactly those; one that named none copies the
        // whole project, minus the skip list. The listener has already substituted the session
        // profile's `runner.sync.paths` into an empty list, so there is no third case here.
        let tar = if req.paths.is_empty() {
            sync::pack_dir(&req.project, SKIP_IN_PROJECT)
        } else {
            sync::pack_paths(&req.project, &req.paths, SKIP_IN_PROJECT)
        }
        .with_context(|| format!("runner: pack {}", req.project.display()))?;
        inner
            .engine
            .put_archive(&slot.id, "/src", &tar)
            .context("runner: sync the project into the slot")?;

        let cmd = Self::command_for(&req.task);
        let exec_id = inner
            .engine
            .exec_create(&slot.id, &cmd, "/src", &Self::exec_env())
            .context("runner: start the build")?;

        let id = format!("b{}", inner.next.fetch_add(1, Ordering::SeqCst));
        // The project as the session knows it: the absolute host path the runner
        // received is noise in a build log whose reader is the workload.
        let shown = req
            .project
            .strip_prefix(&inner.workspace)
            .unwrap_or(&req.project)
            .display()
            .to_string();
        inner.builds.lock().unwrap().insert(
            id.clone(),
            BuildRecord {
                state: BuildState::Running,
                lines: {
                    let mut log = BoundedLog::new();
                    log.push(format!(
                        "[saife] {} {}{}\n",
                        req.task,
                        shown,
                        copy_scope(&req.paths)
                    ));
                    log
                },
            },
        );

        // The build runs in its own thread: the supervisor must answer status and log
        // requests while it is going, and the workload polls.
        let project = req.project.clone();
        let id_thread = id.clone();
        std::thread::Builder::new()
            .name(format!("saife-build-{id}"))
            .spawn(move || {
                // The log stream is read on a THIRD thread on purpose: `exec_stream`
                // blocks until the process ends, and a build that never ends would hold
                // the deadline below hostage. This thread owns the clock, that one owns
                // the socket.
                let (done_tx, done_rx) = std::sync::mpsc::channel::<Result<()>>();
                let streamer = {
                    let inner = Arc::clone(&inner);
                    let exec_id = exec_id.clone();
                    let id_stream = id_thread.clone();
                    std::thread::Builder::new()
                        .name(format!("saife-build-log-{id_stream}"))
                        .spawn(move || {
                            let mut splitter = LineSplitter::new();
                            let streamed = inner.engine.exec_stream(&exec_id, |chunk| {
                                splitter
                                    .feed(chunk, &mut |line| append_line(&inner, &id_stream, line));
                            });
                            splitter.finish(&mut |line| append_line(&inner, &id_stream, line));
                            let _ = done_tx.send(streamed);
                        })
                };
                if streamer.is_err() {
                    // No reader: the build cannot be watched, so it is refused rather
                    // than left running with nobody able to see it end.
                    if let Some(rec) = inner.builds.lock().unwrap().get_mut(&id_thread) {
                        rec.state = BuildState::Refused(
                            "runner_build_unwatchable: the log reader thread could not start"
                                .to_string(),
                        );
                    }
                    let _ = inner.stop_slot();
                    return;
                }

                let state = match wait_for_stream(&done_rx, inner.timeout) {
                    StreamEnd::Finished(Err(e)) => BuildState::Refused(format!("{e:#}")),
                    StreamEnd::Lost => {
                        append_line(
                            &inner,
                            &id_thread,
                            "[saife] the build's log stream ended without reporting; \
                             its exit code was lost\n"
                                .to_string(),
                        );
                        BuildState::Refused(
                            "runner_build_stream_lost: the engine stopped reporting before \
                             the build's exit code was known"
                                .to_string(),
                        )
                    }
                    StreamEnd::TimedOut => {
                        // Named for the profile key the operator can change, because a
                        // deadline that does not say which setting it came from is a
                        // message nobody can act on.
                        append_line(
                            &inner,
                            &id_thread,
                            format!(
                                "[saife] cancelled after {} s: this build exceeded \
                                 limits.workloadTimeoutSecs\n",
                                inner.timeout.as_secs()
                            ),
                        );
                        if let Err(e) = inner.stop_slot() {
                            append_line(&inner, &id_thread, format!("[saife] cancel: {e:#}\n"));
                        }
                        BuildState::TimedOut
                    }
                    StreamEnd::Finished(Ok(())) => match inner.engine.exec_exit(&exec_id) {
                        Ok(Some(0)) => {
                            sync_out(&inner, &project, &id_thread);
                            BuildState::Succeeded(0)
                        }
                        Ok(code) => state_for_exit(code),
                        Err(e) => BuildState::Refused(format!("{e:#}")),
                    },
                };
                if let Some(rec) = inner.builds.lock().unwrap().get_mut(&id_thread) {
                    rec.state = state;
                }
            })
            .context("runner: spawn the build thread")?;

        Ok(id)
    }

    fn state(&self, id: &str) -> Result<BuildState> {
        self.inner
            .builds
            .lock()
            .unwrap()
            .get(id)
            .map(|r| r.state.clone())
            .ok_or_else(|| anyhow::anyhow!("runner: unknown build `{id}`"))
    }

    fn lines(&self, id: &str, from: usize) -> Result<LogWindow> {
        let builds = self.inner.builds.lock().unwrap();
        let rec = builds
            .get(id)
            .ok_or_else(|| anyhow::anyhow!("runner: unknown build `{id}`"))?;
        Ok(rec.lines.window(from))
    }

    /// Stop this runner's slot when the session ends (invariant 4: a slot is a container,
    /// and a container that outlives its session is a stale build environment). The wiring
    /// calls this from its `Drop`, so an error path unwinds through it exactly as the
    /// success path does.
    fn shutdown(&self) {
        let _ = self.inner.stop_slot();
    }
}

/// Copy the declared outputs back into the project directory.
///
/// Best-effort on purpose: a build that succeeded but cannot copy its jar back has still
/// succeeded (and the log says what failed). Only `build/libs` travels - a copy-out of the
/// whole tree would overwrite the agent's edits with the snapshot the build started from.
fn sync_out(inner: &Inner, project: &std::path::Path, id: &str) {
    match inner
        .engine
        .get_archive(&inner.current_slot_id(), "/src/build/libs")
    {
        Ok(tar) if !tar.is_empty() => {
            let dest = project.join("build").join("libs");
            if let Err(e) = sync_out_unpack(&tar, project, &dest) {
                append_line(inner, id, format!("[saife] sync out failed: {e:#}\n"));
            } else {
                append_line(
                    inner,
                    id,
                    format!("[saife] artifacts -> {}\n", dest.display()),
                );
            }
        }
        Ok(_) => append_line(
            inner,
            id,
            "[saife] no artifacts in build/libs\n".to_string(),
        ),
        Err(e) => append_line(inner, id, format!("[saife] sync out failed: {e:#}\n")),
    }
}

/// Validate and unpack the sync-out tar into `dest` under `project`.
///
/// Split from [`sync_out`] so the C2 guards are testable without a container
/// engine. The guards live HERE, not at build start, because the workload can
/// plant a junction under `build/` while the build runs. C2 (verdict: confirmed,
/// Critical): the tar crate's `validate_inside_dst` canonicalizes THROUGH a
/// junction, so without them a `build/libs` junction would land the artifacts in
/// the junction's target with supervisor rights. Three layers:
///
/// 1. entry kinds: only Regular/Directory entries may travel - a link entry is
///    a named refusal, not a silent drop;
/// 2. reparse points: every existing component of `project -> dest` must be a
///    real path, checked before AND after `create_dir_all` so a pre-existing
///    junction is never written through even to create the destination;
/// 3. containment: `dest` must canonicalize under the canonical project, which
///    a junction does not.
fn sync_out_unpack(tar: &[u8], project: &std::path::Path, dest: &std::path::Path) -> Result<()> {
    // (1) Entry kinds first, before anything is created: the archive is untrusted
    // input, and a link entry is the in-container half of the C2 escape.
    let mut archive = tar::Archive::new(std::io::Cursor::new(tar));
    for entry in archive.entries().context("runner: read the sync-out tar")? {
        let entry = entry.context("runner: read a sync-out tar entry")?;
        let kind = entry.header().entry_type();
        if !(kind.is_file() || kind.is_dir()) {
            bail!(
                "runner: sync-out refuses a {} tar entry ({}); \
                 only regular files and directories travel",
                kind_name(kind),
                entry.path().unwrap_or_default().display()
            );
        }
    }
    // (2) Reparse points on the project -> dest chain, BEFORE `create_dir_all`:
    // creating `build/libs` through a junction at `build` would already be a
    // write into the target.
    refuse_reparse_in_descendant_chain(project, dest, "the sync-out destination")?;
    std::fs::create_dir_all(dest).with_context(|| format!("runner: create {}", dest.display()))?;
    // And again after: the check the verdict doc asks for, and a second window
    // a junction could appear in.
    refuse_reparse_in_descendant_chain(project, dest, "the sync-out destination")?;
    // (3) Containment on canonical paths: a junction canonicalizes to its
    // target, so the lexical `dest` alone proves nothing.
    let canonical_project = std::fs::canonicalize(project)
        .with_context(|| format!("runner: canonicalize {}", project.display()))?;
    let canonical_dest = std::fs::canonicalize(dest)
        .with_context(|| format!("runner: canonicalize {}", dest.display()))?;
    if !canonical_dest.starts_with(&canonical_project) {
        bail!(
            "runner: sync-out destination {} resolves to {}, which is outside \
             the project {}",
            dest.display(),
            canonical_dest.display(),
            canonical_project.display()
        );
    }
    // Defense-in-depth: the keeper is type-aware too, so a path that bypasses
    // the pre-scan above still cannot unpack a link entry.
    sync::unpack_into_at_typed(tar, dest, true, &|_, kind| kind.is_file() || kind.is_dir())
        .context("runner: unpack sync-out artifacts")?;
    Ok(())
}

/// Every EXISTING component of `dest` below `base` must be a real path, not a
/// link or junction.
///
/// The ancestor walker `refuse_reparse_in_chain` (runner/mod.rs) stops at the
/// first missing component, which is right for its caller but wrong here: this
/// walks the DESCENDANT chain from `base` toward `dest` so a junction planted at
/// any intermediate level (`build/`, `build/libs`) is caught even when deeper
/// levels do not exist yet. Missing components are skipped, not fatal - they are
/// about to be created as real directories.
fn refuse_reparse_in_descendant_chain(
    base: &std::path::Path,
    dest: &std::path::Path,
    what: &str,
) -> Result<()> {
    let Ok(rel) = dest.strip_prefix(base) else {
        return Ok(());
    };
    let mut cursor = base.to_path_buf();
    for component in rel.components() {
        cursor.push(component);
        if let Ok(meta) = std::fs::symlink_metadata(&cursor)
            && super::is_reparse_point(&meta)
        {
            bail!(
                "runner: {} is a link or junction; {what} must be a real path",
                cursor.display()
            );
        }
    }
    Ok(())
}

/// The name a refused entry kind gets in the refusal: `symlink` tells an operator
/// what to look for in the tar; `non-regular` covers the kinds this runner never
/// expects to see and cannot usefully name.
fn kind_name(kind: tar::EntryType) -> &'static str {
    match kind {
        tar::EntryType::Symlink => "symlink",
        tar::EntryType::Link => "hardlink",
        tar::EntryType::Char => "character-device",
        tar::EntryType::Block => "block-device",
        tar::EntryType::Fifo => "fifo",
        _ => "non-regular",
    }
}

impl Inner {
    /// The live slot's id, or an empty one (an engine answers 404, and the caller reports
    /// it). The slot is always present at this point in a build; this is the accessor that
    /// keeps the field private to the module.
    fn current_slot_id(&self) -> String {
        self.slot
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .map(|s| s.id.clone())
            .unwrap_or_default()
    }

    /// Take and remove this runner's slot. Idempotent: the slot is *taken*, so a
    /// session-end teardown after a cancelled build's own stop finds nothing.
    fn stop_slot(&self) -> Result<()> {
        let slot = self.slot.lock().unwrap_or_else(|e| e.into_inner()).take();
        match slot {
            Some(slot) => self.engine.remove_slot(&slot),
            None => Ok(()),
        }
    }
}

impl Drop for Inner {
    /// The backstop for a runner no session ever took: whoever drops the last handle
    /// stops the slot. Reported nowhere because `Drop` cannot fail, and the explicit
    /// [`BuildEngine::shutdown`] is what the session path uses.
    fn drop(&mut self) {
        let taken = self
            .slot
            .get_mut()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        if let Some(slot) = taken {
            let _ = self.engine.remove_slot(&slot);
        }
    }
}

impl DockerBuilds {
    /// Whether a build is running in this session's slot.
    ///
    /// The idle watchdog asks this before reaping: a build that takes longer than the idle
    /// window (a cold Gradle run on a big project can) must not lose its container because
    /// nothing has *asked* for ten minutes.
    pub fn busy(&self) -> bool {
        self.inner
            .builds
            .lock()
            .unwrap()
            .values()
            .any(|r| matches!(r.state, BuildState::Running))
    }

    /// Create and start the slot if this runner does not have a live one.
    fn ensure_slot(&self) -> Result<Slot> {
        let mut guard = self.inner.slot.lock().unwrap();
        if let Some(slot) = guard.as_ref()
            && self.inner.engine.slot_running(slot).unwrap_or(false)
        {
            return Ok(slot.clone());
        }
        self.inner.engine.ensure_cache_volume()?;
        let spec = SlotSpec::new(&self.inner.session);
        // Admission, not a name sweep: this code used to remove any container whose name
        // matched, which is how a session steals another live session's slot. `admit` checks
        // ownership (pid + creation time), the image digest, the JDK, idleness and the cap,
        // and refuses by name rather than guessing.
        let admission =
            lifecycle::admit(&self.inner.engine, &lifecycle::SlotPolicy::default(), &spec)?;
        self.inner.engine.start_slot(&admission.slot)?;
        // Same race as prewarm: the archive PUT needs `/src` to exist (T6.2).
        self.inner
            .engine
            .ensure_dirs(&admission.slot.id, &["/src", "/cache"])?;
        if let Some(reason) = &admission.recycle_reason {
            // Say it once on the runner's own stream: a recycled slot means a cold daemon,
            // which is the difference between a 2 s and a 90 s build.
            eprintln!("[saife] runner: slot recycled: {reason}");
        }
        *guard = Some(admission.slot.clone());
        Ok(admission.slot)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_task_becomes_a_fixed_argv_not_a_shell_string() {
        assert_eq!(
            DockerBuilds::command_for("build"),
            vec!["./gradlew", "--offline", "--console=plain", "build"]
        );
        // Nothing from the request is interpolated into a shell: the argv is the argv.
        assert!(
            DockerBuilds::command_for("test")
                .iter()
                .all(|a| !a.contains(';'))
        );
    }

    /// The toolchain is the **image's**, and the supervisor's `JAVA_HOME` never
    /// reaches the slot. It names a Windows directory that cannot exist inside a
    /// Linux container, so passing it through is either ignored (a silent lie about
    /// which JDK ran) or a build that dies at its first `java` call. The digest pin
    /// is what makes the image's JDK the answer, and this makes that explicit.
    #[test]
    fn a_host_java_home_is_never_passed_into_the_runner() {
        let _guard = crate::env_lock();
        let saved = std::env::var_os("JAVA_HOME");
        // SAFETY: serialised by `env_lock`, and restored before this test returns.
        unsafe { std::env::set_var("JAVA_HOME", r"C:\Program Files\Java\jdk-21") };
        let env = DockerBuilds::exec_env();
        // SAFETY: as above.
        match saved {
            Some(v) => unsafe { std::env::set_var("JAVA_HOME", v) },
            None => unsafe { std::env::remove_var("JAVA_HOME") },
        }

        let java_home: Vec<&String> = env.iter().filter(|e| e.starts_with("JAVA_HOME=")).collect();
        assert_eq!(
            java_home.len(),
            1,
            "exactly one JAVA_HOME: the image's, never a host value beside it: {env:?}"
        );
        assert_eq!(java_home[0], &format!("JAVA_HOME={IMAGE_JAVA_HOME}"));
        assert!(
            !java_home[0].contains('\\'),
            "a Windows path in the slot's environment is a lie: {java_home:?}"
        );
        assert!(
            env.iter().any(|e| e == "GRADLE_USER_HOME=/cache"),
            "the offline build needs the cache volume as Gradle's home: {env:?}"
        );
    }

    /// The build's own exit code is what the workload sees. Squashing every non-zero
    /// exit into `Failed(1)` would erase the difference between "the tests failed"
    /// and "gradlew is not executable" (126/127), and a caller acts on those
    /// differently.
    #[test]
    fn an_exit_code_is_propagated_not_squashed() {
        assert_eq!(state_for_exit(Some(0)), BuildState::Succeeded(0));
        assert_eq!(state_for_exit(Some(1)), BuildState::Failed(1));
        assert_eq!(state_for_exit(Some(126)), BuildState::Failed(126));
        assert_eq!(state_for_exit(Some(127)), BuildState::Failed(127));
        assert_eq!(
            state_for_exit(None),
            BuildState::Failed(-1),
            "a stream that ended without an exit code is not success"
        );
    }

    /// The deadline is enforced by the thread that owns the clock, not by the stream
    /// (which blocks until the process ends). A build that never ends must end at the
    /// deadline; this is the branch that decides it, without a container.
    #[test]
    fn waiting_past_the_deadline_gives_up_instead_of_blocking() {
        let (_tx, rx) = std::sync::mpsc::channel::<Result<()>>();
        let started = std::time::Instant::now();
        assert!(
            matches!(
                wait_for_stream(&rx, std::time::Duration::from_millis(50)),
                StreamEnd::TimedOut
            ),
            "a silent stream past the deadline is a timeout"
        );
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "the wait must be bounded by the deadline, took {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn a_finished_stream_ends_the_wait_before_the_deadline() {
        let (tx, rx) = std::sync::mpsc::channel::<Result<()>>();
        tx.send(Ok(())).unwrap();
        assert!(
            matches!(
                wait_for_stream(&rx, std::time::Duration::from_secs(30)),
                StreamEnd::Finished(Ok(()))
            ),
            "a completed stream ends the wait immediately"
        );
    }

    /// A stream thread that died without reporting is not a timeout: calling it one
    /// would blame the clock for a defect. It still ends the build (there is no other
    /// verdict), with a refusal that says the exit code was lost.
    #[test]
    fn a_stream_thread_that_died_is_not_a_timeout() {
        let (tx, rx) = std::sync::mpsc::channel::<Result<()>>();
        drop(tx);
        assert!(
            matches!(
                wait_for_stream(&rx, std::time::Duration::from_secs(30)),
                StreamEnd::Lost
            ),
            "a disconnected stream thread is a lost build, not a deadline"
        );
    }

    /// A closed allow-list is only reviewable if the log says which one was applied: a build
    /// that fails at configuration time because `settings.gradle.kts` was not named has to
    /// show the list that caused it, in the same log the failure appears in.
    #[test]
    fn the_log_names_the_allow_list_it_copied() {
        assert_eq!(
            copy_scope(&[]),
            "",
            "the whole project needs no note: that is the default case"
        );
        assert_eq!(
            copy_scope(&[
                "apps/payments".to_string(),
                "settings.gradle.kts".to_string()
            ]),
            " (paths: apps/payments, settings.gradle.kts)"
        );
    }

    /// The skip list is a boundary, not a preference: a build that starts from the previous
    /// `build/` or `.gradle/` is not the build the user asked for.
    #[test]
    fn outputs_and_caches_never_go_into_the_runner() {
        assert!(SKIP_IN_PROJECT.contains(&"build"));
        assert!(SKIP_IN_PROJECT.contains(&".gradle"));
        assert!(SKIP_IN_PROJECT.contains(&".git"));
    }

    // ---- M10: bounded log retention -----------------------------------------

    /// M10 (verdict: confirmed): a build printing ten times the budget must leave a
    /// bounded record. The deadline does not bound bytes - a build prints faster than
    /// it builds - so a `Vec<String>` that only the clock stops is a heap exhaustion
    /// vector that looks like a normal build.
    #[test]
    fn log_retention_is_bounded_by_a_line_cap_and_a_byte_budget() {
        let mut log = BoundedLog::new();
        let attempts = LOG_LINE_CAP * 10;
        for i in 0..attempts {
            log.push(format!("line {i}\n"));
        }
        assert!(
            log.lines.len() <= LOG_LINE_CAP,
            "retained {} lines, cap is {LOG_LINE_CAP}",
            log.lines.len()
        );
        assert!(
            log.bytes <= LOG_BYTE_BUDGET,
            "retained {} bytes, budget is {LOG_BYTE_BUDGET}",
            log.bytes
        );
        assert_eq!(
            log.total, attempts,
            "every line is still counted: the absolute numbering is what a follower tracks"
        );
        assert!(
            log.window(attempts).lines.is_empty(),
            "a reader at the end has nothing left to read"
        );
    }

    /// ... and the byte budget is its own trip: many large lines must bound bytes
    /// before the line count reaches its cap, or a 64 KiB-per-line build fills 4 MiB
    /// in 64 lines and the line cap never fires.
    #[test]
    fn the_byte_budget_trips_before_the_line_cap() {
        let mut log = BoundedLog::new();
        let line = format!("{}\n", "x".repeat(8 * 1024));
        for _ in 0..(LOG_BYTE_BUDGET / line.len() * 3) {
            log.push(line.clone());
        }
        assert!(
            log.lines.len() < LOG_LINE_CAP,
            "the byte budget must trip first: {} lines retained",
            log.lines.len()
        );
        assert!(log.bytes <= LOG_BYTE_BUDGET, "{} bytes", log.bytes);
    }

    /// The reader contract M10 is really about: `follow=1` reads with an absolute
    /// `from` index, so eviction must not renumber a line. A follower that keeps up
    /// receives every line exactly once; one that fell behind is TOLD (gap), instead
    /// of being handed a shifted window that silently repeats or skips lines.
    #[test]
    fn a_following_reader_neither_skips_nor_duplicates_lines() {
        let mut log = BoundedLog::new();
        let mut from = 0usize;
        let mut seen: Vec<String> = Vec::new();
        for i in 0..(LOG_LINE_CAP * 2) {
            log.push(format!("line {i}\n"));
            let w = log.window(from);
            assert!(
                !w.gap,
                "a poller that keeps up never sees a gap (at line {i})"
            );
            assert_eq!(w.first, from, "the window starts where the reader asked");
            from += w.lines.len();
            seen.extend(w.lines);
        }
        assert_eq!(seen.len(), LOG_LINE_CAP * 2, "no skip and no duplicate");
        assert_eq!(seen.first().map(String::as_str), Some("line 0\n"));
        assert_eq!(
            seen.last().map(String::as_str),
            Some(format!("line {}\n", LOG_LINE_CAP * 2 - 1).as_str())
        );

        // Now poll late enough that the reader's place is gone: the window must say
        // so, and the index it reports must be the real first retained line.
        let late = log.window(0);
        assert!(
            late.gap,
            "a reader whose place was evicted must be told, not silently shifted"
        );
        assert_eq!(late.first, log.total - log.lines.len());
        assert!(!late.lines.is_empty());

        // Continuing from the window's own end delivers the next line and nothing else.
        let next_from = late.first + late.lines.len();
        log.push("late\n".to_string());
        let w = log.window(next_from);
        assert!(!w.gap, "the follower caught up");
        assert_eq!(
            w.lines,
            vec!["late\n".to_string()],
            "neither a repeat nor a skip after the gap"
        );
    }

    /// A chunk boundary is not a line boundary, and a stream that never emits a
    /// newline is unbounded output: the partial line has its own cap, and the cut is
    /// marked so the log does not look like the build simply printed a short line.
    #[test]
    fn a_partial_line_is_capped_and_marked() {
        let mut splitter = LineSplitter::new();
        let mut out: Vec<String> = Vec::new();
        splitter.feed(&vec![b'x'; LOG_PARTIAL_CAP * 10], &mut |l| out.push(l));
        splitter.finish(&mut |l| out.push(l));

        assert!(
            out.iter().all(|l| l.len() <= LOG_PARTIAL_CAP + 1),
            "no emitted line may exceed the partial cap: {:?}",
            out.iter().map(String::len).collect::<Vec<_>>()
        );
        assert!(
            out.iter().any(|l| l == LOG_TRUNCATED_MARKER),
            "the cut must be marked: {:?}",
            out.iter().map(|l| l.len()).collect::<Vec<_>>()
        );
        assert!(
            out.iter().map(String::len).sum::<usize>() <= LOG_PARTIAL_CAP * 2,
            "ten times the cap must not be retained: {} bytes",
            out.iter().map(String::len).sum::<usize>()
        );
    }

    /// The ordinary case still works: chunk boundaries do not split lines, and the
    /// tail without a newline is flushed when the stream ends.
    #[test]
    fn chunk_boundaries_do_not_split_lines_and_the_tail_is_flushed() {
        let mut splitter = LineSplitter::new();
        let mut out: Vec<String> = Vec::new();
        splitter.feed(b"one\ntw", &mut |l| out.push(l));
        splitter.feed(b"o\nthr", &mut |l| out.push(l));
        splitter.finish(&mut |l| out.push(l));
        assert_eq!(out, vec!["one\n", "two\n", "thr"]);
    }

    /// LIVE (`-- --ignored`): a real project, a real container, a real Gradle build.
    ///
    /// Needs a prewarmed cache (`saife runner prewarm <project>`) - the slot has no network
    /// by design, so a cold cache can only fail, and that failure is what the offline
    /// message exists for.
    #[test]
    #[ignore = "needs a running engine, the pinned image, and a prewarmed cache"]
    fn live_a_real_project_builds_through_the_runner() {
        let workspace = std::path::PathBuf::from(r"C:\Users\marku\projekte\temp");
        let project = workspace.join("sample-gradle");
        assert!(
            project.join("gradlew").exists(),
            "the sample project is there"
        );

        let engine = Engine::connect(crate::runner::docker::Endpoint::resolve().expect("endpoint"));
        let builds = DockerBuilds::new(
            engine,
            workspace.clone(),
            format!("livebuild{}", std::process::id()),
            std::time::Duration::from_secs(600),
        );
        let req = BuildRequest::parse(
            br#"{"project":"sample-gradle","task":"build","profile":"gradle"}"#,
            &workspace,
        )
        .expect("a valid request");
        let id = builds.start(req).expect("start the build");

        // The leg removes its own slot: a failing run that leaves a container behind is the
        // leak the start-up sweep exists for, and the tests should not create it.
        struct Cleanup {
            engine: Engine,
            session: String,
        }
        impl Drop for Cleanup {
            fn drop(&mut self) {
                if let Ok(slots) = self.engine.list_slots() {
                    for s in slots {
                        if s.name == format!("saife-runner-{}", self.session) {
                            let _ = self.engine.remove_slot(&s);
                        }
                    }
                }
            }
        }
        let _cleanup = Cleanup {
            engine: Engine::connect(crate::runner::docker::Endpoint::resolve().expect("endpoint")),
            session: format!("livebuild{}", std::process::id()),
        };

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(600);
        loop {
            let state = builds.state(&id).expect("state");
            if !matches!(state, BuildState::Running) {
                let lines = builds.lines(&id, 0).expect("lines").lines;
                eprintln!("live: {} lines, final state {state:?}", lines.len());
                for l in lines.iter().rev().take(12).rev() {
                    eprint!("  {l}");
                }
                assert_eq!(
                    state,
                    BuildState::Succeeded(0),
                    "the build must succeed: {state:?}"
                );
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the build did not finish in 10 minutes"
            );
            std::thread::sleep(std::time::Duration::from_millis(500));
        }

        let libs = project.join("build").join("libs");
        let jar = std::fs::read_dir(&libs)
            .expect("the artifacts came back")
            .filter_map(|e| e.ok())
            .find(|e| e.path().extension().map(|x| x == "jar").unwrap_or(false))
            .map(|e| e.path());
        assert!(
            jar.is_some(),
            "a jar must be synced back into {}",
            libs.display()
        );
        eprintln!("live: artifact {}", jar.unwrap().display());

        // Invariant 4, proved rather than assumed: the session ending stops the slot.
        // The label sweep is the same one the start-up sweep uses, so a leftover
        // container here is exactly what an operator would find tomorrow.
        builds.shutdown();
        let engine = Engine::connect(crate::runner::docker::Endpoint::resolve().expect("endpoint"));
        let leftover: Vec<String> = engine
            .list_slots()
            .expect("the engine answers")
            .into_iter()
            .filter(|s| s.name == format!("saife-runner-livebuild{}", std::process::id()))
            .map(|s| s.name)
            .collect();
        assert!(
            leftover.is_empty(),
            "the session's slot must not outlive it: {leftover:?}"
        );
    }

    /// LIVE (`-- --ignored`): the deadline stops a REAL build, and takes its slot with it.
    ///
    /// The sample project takes seconds, so a one-second deadline must end it with
    /// `TimedOut` rather than 9 s of Gradle: that is the difference between "the runner
    /// says it enforces a deadline" and "the container a runaway build was using is gone".
    #[test]
    #[ignore = "needs a running engine, the pinned image, and a prewarmed cache"]
    fn live_a_build_past_its_deadline_is_cancelled() {
        let workspace = std::path::PathBuf::from(r"C:\Users\marku\projekte\temp");
        let project = workspace.join("sample-gradle");
        assert!(
            project.join("gradlew").exists(),
            "the sample project is there"
        );
        let session = format!("livetimeout{}", std::process::id());
        let engine = Engine::connect(crate::runner::docker::Endpoint::resolve().expect("endpoint"));
        let builds = DockerBuilds::new(
            engine,
            workspace.clone(),
            session.clone(),
            std::time::Duration::from_secs(1),
        );
        let req = BuildRequest::parse(
            br#"{"project":"sample-gradle","task":"build","profile":"gradle"}"#,
            &workspace,
        )
        .expect("a valid request");
        let id = builds.start(req).expect("start the build");

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(180);
        let state = loop {
            let now = builds.state(&id).expect("state");
            if !matches!(now, BuildState::Running) {
                break now;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the deadline never fired: the build was still running after 180 s"
            );
            std::thread::sleep(std::time::Duration::from_millis(200));
        };
        assert_eq!(
            state,
            BuildState::TimedOut,
            "a build past its deadline must be stopped, not reported as a build failure"
        );
        let lines = builds.lines(&id, 0).expect("lines").lines;
        assert!(
            lines
                .iter()
                .any(|l| l.contains("limits.workloadTimeoutSecs")),
            "the log must name the setting the deadline came from: {lines:?}"
        );

        // Invariant 4, one step earlier: a cancelled build's container is gone, so the
        // next session cannot inherit a half-built environment.
        let sweep = Engine::connect(crate::runner::docker::Endpoint::resolve().expect("endpoint"));
        let leftover: Vec<String> = sweep
            .list_slots()
            .expect("the engine answers")
            .into_iter()
            .filter(|s| s.name == format!("saife-runner-{session}"))
            .map(|s| s.name)
            .collect();
        assert!(
            leftover.is_empty(),
            "a cancelled build must not leave its slot behind: {leftover:?}"
        );
    }

    // ---- C2: sync-out reparse-point / entry-kind guards ---------------------

    /// Removes every scratch tree on the way out, including when an assertion
    /// fails: a test that creates junctions must not leave them behind.
    struct Cleanup(Vec<std::path::PathBuf>);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            for p in &self.0 {
                // `remove_dir_all` removes a junction without recursing into its
                // target on Windows (it detects the reparse point), so this is
                // safe against the junction tests below.
                let _ = std::fs::remove_dir_all(p);
            }
        }
    }

    fn scratch_builds_dir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("saife-builds-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// Create a junction (`mklink /J`): no privilege required, and it is the
    /// exact reparse-point shape C2 is about.
    #[cfg(windows)]
    fn make_junction(link: &std::path::Path, target: &std::path::Path) {
        let status = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(link)
            .arg(target)
            .status()
            .expect("mklink runs");
        assert!(
            status.success(),
            "the junction {link:?} -> {target:?} must be created for this test"
        );
    }

    fn regular_tar(name: &str, contents: &[u8]) -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        let mut hdr = tar::Header::new_gnu();
        hdr.set_size(contents.len() as u64);
        hdr.set_mode(0o755);
        hdr.set_entry_type(tar::EntryType::Regular);
        hdr.set_cksum();
        b.append_data(&mut hdr, name, &mut &contents[..]).unwrap();
        b.into_inner().unwrap()
    }

    fn symlink_tar(name: &str, target: &str) -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        let mut hdr = tar::Header::new_gnu();
        hdr.set_entry_type(tar::EntryType::Symlink);
        hdr.set_link_name(target).unwrap();
        hdr.set_mode(0o777);
        hdr.set_size(0);
        hdr.set_cksum();
        b.append_data(&mut hdr, name, &mut std::io::empty())
            .unwrap();
        b.into_inner().unwrap()
    }

    /// C2 (verdict: confirmed, Critical): a workload can plant a junction at
    /// `build/libs` while the build runs; sync-out must refuse it and write
    /// nothing through it into the junction's target.
    #[cfg(windows)]
    #[test]
    fn sync_out_refuses_a_junction_at_build_libs() {
        let ws = scratch_builds_dir("c2-junction");
        let target = ws.join("target");
        let project = ws.join("proj");
        std::fs::create_dir_all(project.join("build")).unwrap();
        std::fs::create_dir_all(&target).unwrap();
        let libs = project.join("build").join("libs");
        make_junction(&libs, &target);
        let _cleanup = Cleanup(vec![ws.clone()]);

        let tar = regular_tar("libs/payload.bat", b"pwned");
        let err = sync_out_unpack(&tar, &project, &libs)
            .expect_err("a junction at build/libs must be refused");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("link") || msg.contains("junction") || msg.contains("reparse"),
            "the refusal must name a reparse point: {msg}"
        );
        assert!(
            !target.join("payload.bat").exists(),
            "nothing may be written through the junction into {}",
            target.display()
        );
    }

    /// C2: a tar carrying a non-Regular/Directory entry (here a symlink) is
    /// refused for sync-out, not silently unpacked.
    #[test]
    fn sync_out_refuses_a_symlink_tar_entry() {
        let ws = scratch_builds_dir("c2-symlink");
        let project = ws.join("proj");
        let libs = project.join("build").join("libs");
        std::fs::create_dir_all(&libs).unwrap();
        let _cleanup = Cleanup(vec![ws.clone()]);

        let tar = symlink_tar("libs/evil", "../secret");
        let err = sync_out_unpack(&tar, &project, &libs)
            .expect_err("a symlink tar entry must be refused for sync-out");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("only regular files and directories"),
            "the refusal must name the entry-kind policy, not an OS symlink error: {msg}"
        );
        assert!(!libs.join("evil").exists(), "no link may be created");
    }

    /// C2 negative control: a normal project (real `build/libs`) syncs out
    /// unchanged. Must stay green in both the red and green states.
    #[test]
    fn sync_out_unpacks_into_a_real_build_libs() {
        let ws = scratch_builds_dir("c2-real");
        let project = ws.join("proj");
        let libs = project.join("build").join("libs");
        std::fs::create_dir_all(&libs).unwrap();
        let _cleanup = Cleanup(vec![ws.clone()]);

        let tar = regular_tar("libs/app.jar", b"jar");
        sync_out_unpack(&tar, &project, &libs).expect("a real dir syncs out");
        assert!(
            libs.join("app.jar").exists(),
            "the artifact must land in build/libs"
        );
    }
}
