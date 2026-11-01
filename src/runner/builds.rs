//! The glue: a build is slot -> sync in -> exec -> sync out.
//!
//! Everything it uses already exists and is measured: `docker.rs` speaks the Engine API,
//! `sync.rs` moves the tree, `server.rs` owns the protocol the workload sees. This module is
//! the state machine that joins them, and deliberately nothing else.

use crate::runner::BuildRequest;
use crate::runner::docker::{Engine, Slot, SlotSpec};
use crate::runner::server::{BuildEngine, BuildState};
use crate::runner::sync;
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// Directories that never go into the runner: they are outputs or caches, and a build that
/// starts from a stale one is not the build the user asked for.
const SKIP_IN_PROJECT: &[&str] = &["build", ".gradle", ".git"];

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

struct BuildRecord {
    state: BuildState,
    lines: Vec<String>,
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
        let tar = sync::pack_dir(&req.project, SKIP_IN_PROJECT)
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
                lines: vec![format!("[saife] {} {}\n", req.task, shown)],
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
                            let mut partial = String::new();
                            let streamed = inner.engine.exec_stream(&exec_id, |chunk| {
                                partial.push_str(&String::from_utf8_lossy(chunk));
                                while let Some(pos) = partial.find('\n') {
                                    let line = partial[..=pos].to_string();
                                    partial.drain(..=pos);
                                    append_line(&inner, &id_stream, line);
                                }
                            });
                            if !partial.is_empty() {
                                append_line(&inner, &id_stream, partial);
                            }
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

    fn lines(&self, id: &str, from: usize) -> Result<Vec<String>> {
        let builds = self.inner.builds.lock().unwrap();
        let rec = builds
            .get(id)
            .ok_or_else(|| anyhow::anyhow!("runner: unknown build `{id}`"))?;
        Ok(rec.lines.iter().skip(from).cloned().collect())
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
            if let Err(e) = std::fs::create_dir_all(&dest) {
                append_line(
                    inner,
                    id,
                    format!("[saife] could not create {}: {e}\n", dest.display()),
                );
            } else if let Err(e) = sync::unpack_into_at(&tar, &dest, true, &|_| true) {
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
        // A previous run of this session may have left the container behind.
        for old in self.inner.engine.list_slots().unwrap_or_default() {
            if old.name == spec.name {
                let _ = self.inner.engine.remove_slot(&old);
            }
        }
        let slot = self.inner.engine.create_slot(&spec)?;
        self.inner.engine.start_slot(&slot)?;
        *guard = Some(slot.clone());
        Ok(slot)
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

    /// The skip list is a boundary, not a preference: a build that starts from the previous
    /// `build/` or `.gradle/` is not the build the user asked for.
    #[test]
    fn outputs_and_caches_never_go_into_the_runner() {
        assert!(SKIP_IN_PROJECT.contains(&"build"));
        assert!(SKIP_IN_PROJECT.contains(&".gradle"));
        assert!(SKIP_IN_PROJECT.contains(&".git"));
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
                let lines = builds.lines(&id, 0).expect("lines");
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
        let lines = builds.lines(&id, 0).expect("lines");
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
}
