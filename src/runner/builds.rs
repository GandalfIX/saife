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

struct BuildRecord {
    state: BuildState,
    lines: Vec<String>,
}

struct Inner {
    engine: Engine,
    /// The session workspace: every request's project resolves inside it.
    workspace: PathBuf,
    session: String,
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
    pub fn new(engine: Engine, workspace: PathBuf, session: String) -> Self {
        DockerBuilds {
            inner: Arc::new(Inner {
                engine,
                workspace,
                session,
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
            .exec_create(
                &slot.id,
                &cmd,
                "/src",
                &["GRADLE_USER_HOME=/cache".to_string()],
            )
            .context("runner: start the build")?;

        let id = format!("b{}", inner.next.fetch_add(1, Ordering::SeqCst));
        inner.builds.lock().unwrap().insert(
            id.clone(),
            BuildRecord {
                state: BuildState::Running,
                lines: vec![format!(
                    "[saife] {} {} in the session's slot\n",
                    req.task,
                    req.project.display()
                )],
            },
        );

        // The build runs in its own thread: the supervisor must answer status and log
        // requests while it is going, and the workload polls.
        let project = req.project.clone();
        let id_thread = id.clone();
        std::thread::Builder::new()
            .name(format!("saife-build-{id}"))
            .spawn(move || {
                let push = |line: String| {
                    if let Some(rec) = inner.builds.lock().unwrap().get_mut(&id_thread) {
                        rec.lines.push(line);
                    }
                };
                let mut partial = String::new();
                let streamed = inner.engine.exec_stream(&exec_id, |chunk| {
                    partial.push_str(&String::from_utf8_lossy(chunk));
                    while let Some(pos) = partial.find('\n') {
                        let line = partial[..=pos].to_string();
                        partial.drain(..=pos);
                        push(line);
                    }
                });
                if !partial.is_empty() {
                    push(partial);
                }

                let state = match streamed {
                    Err(e) => BuildState::Refused(format!("{e:#}")),
                    Ok(()) => match inner.engine.exec_exit(&exec_id) {
                        Ok(Some(0)) => {
                            // Sync out is best-effort: a build that succeeded but cannot copy
                            // its jar back has still succeeded, and the log says so.
                            match inner.engine.get_archive(&slot.id, "/src/build/libs") {
                                Ok(tar) if !tar.is_empty() => {
                                    let dest = project.join("build").join("libs");
                                    if let Err(e) = std::fs::create_dir_all(&dest) {
                                        push(format!(
                                            "[saife] could not create {}: {e}\n",
                                            dest.display()
                                        ));
                                    } else if let Err(e) =
                                        sync::unpack_into_at(&tar, &dest, true, &|_| true)
                                    {
                                        push(format!("[saife] sync out failed: {e:#}\n"));
                                    } else {
                                        push(format!("[saife] artifacts -> {}\n", dest.display()));
                                    }
                                }
                                Ok(_) => push("[saife] no artifacts in build/libs\n".to_string()),
                                Err(e) => push(format!("[saife] sync out failed: {e:#}\n")),
                            }
                            BuildState::Succeeded(0)
                        }
                        Ok(Some(code)) => BuildState::Failed(code),
                        Ok(None) => BuildState::Failed(-1),
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
    }
}
