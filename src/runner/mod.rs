//! The build runner: what a workload may ask for, and nothing more.
//!
//! The runner is a federated capability, not an executor. A request names a project
//! directory, a task and a profile; the image, the mounts, the environment, the
//! command line and every flag are constants on the supervisor's side. That is the
//! whole security story: a workload that could name an image or a mount could run
//! `-v C:\:/host` through the deputy, so the request type has no field for either and
//! the JSON parser refuses unknown keys by name.

// The session wiring (`wiring.rs`) is reached only from the MXC session path, which a
// `--no-default-features` build does not have: there, the runner is compiled but
// unreachable, and the chain below is how that is said once instead of as a dozen
// per-item gates that would also drop these tests from that lane. In the default build
// nothing is exempt: an item with no caller is a finding, not background noise.
#![cfg_attr(not(feature = "mxc-backend"), allow(dead_code))]

use anyhow::{Context, Result, bail};

pub mod builds;
pub mod docker;
pub mod lifecycle;
pub mod server;
pub mod sync;
pub mod wiring;
use std::path::{Path, PathBuf};

/// Streams a build's log to a writer without letting the writer end the build.
///
/// Measured symptom this exists for (T6.2): `prewarm … > out 2> err` works, `prewarm … | tee log`
/// goes silent and may never return. `print!` per chunk neither flushes - so a file shows nothing
/// until the process exits - nor survives a closed pipe: the macro panics on a write error, and a
/// panic while streaming kills a build that has already done its work.
///
/// So: write, flush, and treat "the reader is gone" as "stop writing". The caller keeps draining
/// the stream, because abandoning it would stall the process producing it.
pub struct StreamSink<W: std::io::Write> {
    out: W,
    broken: bool,
}

impl<W: std::io::Write> StreamSink<W> {
    pub fn new(out: W) -> Self {
        StreamSink { out, broken: false }
    }

    /// Write one chunk. `false` means the writer is gone and further writes are pointless -
    /// but not fatal: the build continues, only its log is lost.
    pub fn write(&mut self, bytes: &[u8]) -> bool {
        if self.broken {
            return false;
        }
        match self.out.write_all(bytes).and_then(|()| self.out.flush()) {
            Ok(()) => true,
            Err(e) => {
                self.broken = true;
                eprintln!(
                    "[saife] the log's destination closed ({e}); the build continues without it"
                );
                false
            }
        }
    }

    /// Test-only: production code has nothing to do with the answer.
    #[cfg(test)]
    pub fn is_broken(&self) -> bool {
        self.broken
    }

    /// Take the writer back. Test-only: production code has no reason to unplug a log.
    #[cfg(test)]
    fn into_inner_for_test(self) -> W {
        self.out
    }
}

/// Tasks the runner will execute. An allow-list, not a pattern: a task string reaches
/// a process's argv, and everything not listed here is refused rather than escaped.
pub const TASKS: &[&str] = &["assemble", "build", "check", "clean", "test"];

/// Runner profiles: the image + toolchain pair the supervisor will use. A profile is
/// a name, never a reference: the digest lives in the binary.
pub const PROFILES: &[&str] = &["gradle"];

/// One build request, as the workload sends it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildRequest {
    /// The project directory, relative to the session workspace.
    pub project: PathBuf,
    /// A task from [`TASKS`].
    pub task: String,
    /// A profile from [`PROFILES`].
    pub profile: String,
    /// The copy allow-list, relative to `project`. Empty means the whole project: the
    /// listener substitutes the session profile's `runner.sync.paths` before this type is
    /// validated, so by the time a build starts, `paths` is the list that governs the copy.
    pub paths: Vec<String>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RawBuildRequest {
    project: String,
    task: String,
    profile: String,
    /// Absent and empty are the same thing here, deliberately: `paths: []` cannot mean
    /// "copy nothing", because a build on an empty tree is not a build anyone asks for. An
    /// empty list falls back to the profile's list, or to the whole project.
    #[serde(default)]
    paths: Vec<String>,
}

/// The runner's one lexical path policy: a value that names something inside `container`,
/// spelled relatively, with no way out of it.
///
/// Shared by `project` and every allow-list entry so the two cannot drift into different
/// rules, and re-run by [`BuildRequest::validate_on_disk`] because a profile default never
/// passes through [`BuildRequest::parse`].
fn refuse_unsafe_relative(label: &str, value: &str, container: &str) -> Result<()> {
    if value.trim().is_empty() {
        bail!("runner: {label} is empty");
    }
    let path = Path::new(value);
    // A UNC path, a device path or any rooted path names something the container cannot be
    // said to be inside, so it is refused before it is joined.
    if value.starts_with("\\\\")
        || value.starts_with("//")
        || value.starts_with('/')
        || path.is_absolute()
    {
        bail!(
            "runner: {label} `{value}` must be a path inside {container}, not a rooted or network path"
        );
    }
    if path.components().any(|c| {
        matches!(
            c,
            std::path::Component::ParentDir
                // `C:foo` is *drive-relative*: `is_absolute()` says no, it does not start with
                // a separator, and it resolves against the drive's own working directory - the
                // one shape that slipped through both checks above. Any prefix or root is a
                // refusal, whatever spelling produced it.
                | std::path::Component::Prefix(_)
                | std::path::Component::RootDir
        )
    }) {
        bail!(
            "runner: {label} `{value}` must be a plain relative path inside {container} \
             (no `..`, no drive, no root)"
        );
    }
    Ok(())
}

/// Whether this directory entry is a link, a junction or another reparse point.
///
/// Windows gives a junction a real path and a real directory attribute, so only the
/// attribute tells it apart from the directory it names.
fn is_reparse_point(meta: &std::fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
    #[cfg(not(windows))]
    {
        meta.file_type().is_symlink()
    }
}

/// `target` and every ancestor below `stop` must be a real path, not a link.
///
/// A reparse point inside the tree is refused even when it happens to point inside: the
/// mount step's promise is "what you see is what gets copied".
fn refuse_reparse_in_chain(target: &Path, stop: &Path, what: &str) -> Result<()> {
    for ancestor in target.ancestors() {
        if ancestor == stop {
            break;
        }
        let meta = match std::fs::symlink_metadata(ancestor) {
            Ok(m) => m,
            Err(_) => break,
        };
        if is_reparse_point(&meta) {
            bail!(
                "runner: {} is a link or junction; {what} must be a real path",
                ancestor.display()
            );
        }
    }
    Ok(())
}

/// Nothing inside a listed directory may be a link either: an entry names a tree, and a
/// junction inside it would copy a tree the caller never named.
fn refuse_reparse_below(dir: &Path, what: &str) -> Result<()> {
    for entry in
        std::fs::read_dir(dir).with_context(|| format!("runner: read {}", dir.display()))?
    {
        let path = entry?.path();
        let meta = std::fs::symlink_metadata(&path)
            .with_context(|| format!("runner: inspect {}", path.display()))?;
        if is_reparse_point(&meta) {
            bail!(
                "runner: {} is a link or junction; {what} must be a real path",
                path.display()
            );
        }
        if meta.is_dir() {
            refuse_reparse_below(&path, what)?;
        }
    }
    Ok(())
}

impl BuildRequest {
    /// Parse and validate a request body against the session's workspace root.
    ///
    /// Lexical only: the filesystem checks (reparse points, a junction out of the
    /// tree, the install directory) belong to the mount step, which is the first
    /// place a path is touched.
    pub fn parse(body: &[u8], workspace: &Path) -> Result<Self> {
        let raw: RawBuildRequest = serde_json::from_slice(body)
            .with_context(|| "runner: the request body is not a valid build request")?;

        if !TASKS.contains(&raw.task.as_str()) {
            bail!(
                "runner: task `{}` is not one this runner executes (known: {})",
                raw.task,
                TASKS.join(", ")
            );
        }
        if !PROFILES.contains(&raw.profile.as_str()) {
            bail!(
                "runner: profile `{}` is not one this build defines (known: {})",
                raw.profile,
                PROFILES.join(", ")
            );
        }

        let project = Path::new(&raw.project);
        refuse_unsafe_relative("project", &raw.project, "the session workspace")?;
        // Each entry, not just the list: a caller with ten entries has to be able to find
        // the one that was wrong.
        for entry in &raw.paths {
            refuse_unsafe_relative("paths entry", entry, "the project")?;
        }

        let resolved = workspace.join(project);
        Ok(BuildRequest {
            project: resolved,
            task: raw.task,
            profile: raw.profile,
            paths: raw.paths,
        })
    }
    /// The filesystem half of the validation: the lexical checks above can be satisfied by a
    /// path that a junction redirects somewhere else entirely (a link inside the workspace
    /// pointing at `%USERPROFILE%` would copy `.ssh` into the runner). Called by the listener
    /// before a build starts, because this is the first place the path is touched.
    pub fn validate_on_disk(&self, workspace: &Path) -> Result<()> {
        let canonical_ws = std::fs::canonicalize(workspace).with_context(|| {
            format!(
                "runner: the session workspace {} is not readable",
                workspace.display()
            )
        })?;
        let canonical = std::fs::canonicalize(&self.project).with_context(|| {
            format!(
                "runner: project `{}` does not exist",
                self.project.display()
            )
        })?;
        if !canonical.starts_with(&canonical_ws) {
            bail!(
                "runner: project `{}` resolves to {}, which is outside the session workspace - \
                 a link or junction is not a way out of it",
                self.project.display(),
                canonical.display()
            );
        }
        refuse_reparse_in_chain(&canonical, &canonical_ws, "the project")?;
        for entry in &self.paths {
            self.validate_path_entry(&canonical, entry)?;
        }
        Ok(())
    }

    /// One allow-list entry, checked the way `project` is - plus the two things an entry
    /// adds: it must exist, and it must not be (or contain) a link.
    ///
    /// The lexical half is repeated here because the session profile's `runner.sync.paths`
    /// never passes through [`BuildRequest::parse`]: the listener substitutes it afterwards.
    fn validate_path_entry(&self, canonical_project: &Path, entry: &str) -> Result<()> {
        refuse_unsafe_relative("paths entry", entry, "the project")?;
        let joined = self.project.join(entry);
        let canonical = std::fs::canonicalize(&joined).with_context(|| {
            format!(
                "runner: paths entry `{entry}` does not exist under {}",
                self.project.display()
            )
        })?;
        if !canonical.starts_with(canonical_project) {
            bail!(
                "runner: paths entry `{entry}` resolves to {}, which is outside the project",
                canonical.display()
            );
        }
        refuse_reparse_in_chain(&joined, &self.project, "the listed path")?;
        if canonical.is_dir() {
            // Metadata only, so this is cheap next to the pack: the pack reads every file,
            // and this only asks the directory whether any entry is a link.
            refuse_reparse_below(&canonical, "the listed tree")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ws() -> PathBuf {
        std::env::temp_dir().join("saife-runner-unit")
    }

    #[test]
    fn a_known_request_parses() {
        let r = BuildRequest::parse(
            br#"{"project":"app","task":"build","profile":"gradle"}"#,
            &ws(),
        )
        .expect("a well-formed request");
        assert_eq!(
            r.project,
            ws().join("app"),
            "the request carries the resolved project path, not the raw string"
        );
        assert_eq!(r.task, "build");
        assert_eq!(r.profile, "gradle");
    }

    /// The type is the control: a workload cannot name the image, the mounts, the
    /// command or any flag, so the parser must refuse those keys **by name** rather
    /// than ignoring them (an ignored key is a silent no-op that looks applied).
    #[test]
    fn a_request_cannot_name_an_image_a_mount_or_a_command() {
        for (key, value) in [
            ("image", "\"alpine:3.20\""),
            ("mounts", "[\"C:/:/host\"]"),
            ("command", "\"rm -rf /\""),
            ("env", "{}"),
            ("privileged", "true"),
        ] {
            let body =
                format!(r#"{{"project":"app","task":"build","profile":"gradle","{key}":{value}}}"#);
            let err = BuildRequest::parse(body.as_bytes(), &ws())
                .expect_err("an extra field must be refused");
            let msg = format!("{err:#}");
            assert!(
                msg.contains(key),
                "the refusal must name the offending field `{key}`: {msg}"
            );
        }
    }

    #[test]
    fn a_task_outside_the_allow_list_is_refused() {
        for task in ["build; rm -rf /", "--init-script", "build -x test", ""] {
            let body = format!(r#"{{"project":"app","task":"{task}","profile":"gradle"}}"#);
            let err = BuildRequest::parse(body.as_bytes(), &ws())
                .expect_err(&format!("task {task:?} must be refused"));
            assert!(
                format!("{err:#}").contains("task"),
                "the refusal names the field: {err:#}"
            );
        }
    }

    #[test]
    fn an_unknown_profile_is_refused() {
        let err = BuildRequest::parse(
            br#"{"project":"app","task":"build","profile":"whatever"}"#,
            &ws(),
        )
        .expect_err("an unknown profile must be refused");
        assert!(format!("{err:#}").contains("profile"));
    }

    /// A project that leaves the workspace is the escape this type exists to prevent:
    /// `..` traversal, an absolute path outside, a UNC path, or a device path.
    #[test]
    fn a_project_outside_the_workspace_is_refused() {
        for project in [
            "../other",
            "C:/Windows",
            "//server/share",
            r"\\?\C:\Windows",
            "/etc",
        ] {
            // JSON-escaped, or the device path's backslashes fail to parse and the test
            // would pass for the wrong reason.
            let body = format!(
                r#"{{"project":{},"task":"build","profile":"gradle"}}"#,
                serde_json::to_string(project).unwrap()
            );
            let err = BuildRequest::parse(body.as_bytes(), &ws())
                .expect_err(&format!("project {project:?} must be refused"));
            assert!(
                format!("{err:#}").contains("project"),
                "the refusal names the field: {err:#}"
            );
        }
    }
    /// The lexical checks cannot see a junction: it is a real directory with a real path
    /// inside the workspace, and its target is somewhere else. This is the check that makes
    /// "the project directory" mean what it says.
    #[cfg(windows)]
    #[test]
    fn a_junction_out_of_the_workspace_is_refused() {
        let ws = std::env::temp_dir().join(format!("saife-runner-junction-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&ws);
        std::fs::create_dir_all(ws.join("real")).unwrap();
        let outside =
            std::env::temp_dir().join(format!("saife-runner-outside-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&outside);
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("secret.txt"), b"x").unwrap();

        let link = ws.join("linked");
        let status = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&link)
            .arg(&outside)
            .status()
            .expect("mklink runs");
        assert!(
            status.success(),
            "the junction must be created for this test"
        );

        let req = BuildRequest::parse(
            br#"{"project":"linked","task":"build","profile":"gradle"}"#,
            &ws,
        )
        .expect("lexically fine");
        let err = req
            .validate_on_disk(&ws)
            .expect_err("a junction out of the workspace must be refused");
        let msg = format!("{err:#}");
        assert!(msg.contains("outside the session workspace"), "got: {msg}");

        let _ = std::fs::remove_dir_all(&ws);
        let _ = std::fs::remove_dir_all(&outside);
    }

    #[test]
    fn a_real_project_directory_passes_the_disk_check() {
        let ws = std::env::temp_dir().join(format!("saife-runner-real-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&ws);
        std::fs::create_dir_all(ws.join("app")).unwrap();
        let req = BuildRequest::parse(
            br#"{"project":"app","task":"build","profile":"gradle"}"#,
            &ws,
        )
        .expect("valid");
        req.validate_on_disk(&ws)
            .expect("a plain directory is fine");
        let _ = std::fs::remove_dir_all(&ws);
    }

    #[test]
    fn a_missing_project_directory_is_refused() {
        let ws = std::env::temp_dir().join(format!("saife-runner-missing-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&ws);
        let req = BuildRequest::parse(
            br#"{"project":"nope","task":"build","profile":"gradle"}"#,
            &ws,
        )
        .expect("lexically fine");
        let err = req
            .validate_on_disk(&ws)
            .expect_err("a missing project is refused");
        assert!(format!("{err:#}").contains("does not exist"), "{err:#}");
        let _ = std::fs::remove_dir_all(&ws);
    }

    /// Absent and empty are the same thing: an allow-list is either a list or it is not
    /// there. `paths: []` meaning "copy nothing" would turn a caller's empty default into a
    /// build on an empty tree, which is never what was meant.
    #[test]
    fn a_request_without_paths_is_the_whole_project() {
        for body in [
            r#"{"project":"app","task":"build","profile":"gradle"}"#,
            r#"{"project":"app","task":"build","profile":"gradle","paths":[]}"#,
        ] {
            let r = BuildRequest::parse(body.as_bytes(), &ws()).expect("a well-formed request");
            assert!(r.paths.is_empty(), "`{body}` must copy the whole project");
        }
    }

    #[test]
    fn a_request_with_paths_carries_them_verbatim() {
        let r = BuildRequest::parse(
            br#"{"project":"app","task":"build","profile":"gradle","paths":["apps/payments","settings.gradle.kts"]}"#,
            &ws(),
        )
        .expect("a well-formed request");
        assert_eq!(
            r.paths,
            vec!["apps/payments", "settings.gradle.kts"],
            "the caller's spelling is what the log and the copy both use"
        );
    }

    /// The same lexical policy as `project`, applied to each entry - and the refusal names
    /// the ENTRY, because a caller with ten entries has to find the one that was wrong.
    #[test]
    fn a_path_entry_that_leaves_the_project_is_refused_by_name() {
        for entry in [
            "../other",
            "C:/Windows",
            "//server/share",
            r"\\?\C:\Windows",
            "/etc",
            "",
        ] {
            let body = format!(
                r#"{{"project":"app","task":"build","profile":"gradle","paths":[{}]}}"#,
                serde_json::to_string(entry).unwrap()
            );
            let err = BuildRequest::parse(body.as_bytes(), &ws())
                .expect_err(&format!("paths entry {entry:?} must be refused"));
            let msg = format!("{err:#}");
            assert!(
                msg.contains("paths entry"),
                "the refusal says which field: {msg}"
            );
            if !entry.is_empty() {
                assert!(msg.contains(entry), "the refusal names the entry: {msg}");
            }
        }
    }

    /// A named entry that is not there is a 400, never a partial copy: a build that silently
    /// misses one of its modules fails later, at configuration time, naming a symbol instead
    /// of the path the caller typed.
    #[test]
    fn a_missing_path_entry_is_refused_by_name() {
        let ws =
            std::env::temp_dir().join(format!("saife-runner-paths-missing-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&ws);
        std::fs::create_dir_all(ws.join("app")).unwrap();
        std::fs::write(ws.join("app/settings.gradle.kts"), b"rootProject.name").unwrap();
        let req = BuildRequest::parse(
            br#"{"project":"app","task":"build","profile":"gradle","paths":["settings.gradle.kts","apps/nope"]}"#,
            &ws,
        )
        .expect("lexically fine");
        let err = req
            .validate_on_disk(&ws)
            .expect_err("a missing entry must be refused, not skipped");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("apps/nope"),
            "the refusal names the entry: {msg}"
        );
        assert!(msg.contains("does not exist"), "{msg}");
        let _ = std::fs::remove_dir_all(&ws);
    }

    /// Removes a scratch tree on the way out, including when an assertion fails: a test that
    /// creates junctions must not leave them behind for the next run to trip over.
    struct Scratch(PathBuf);
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// A junction is a real directory with a real path, so only the attribute check sees it;
    /// inside a listed directory it would put files into the container that the list never
    /// named - which is the whole promise of naming paths.
    #[cfg(windows)]
    #[test]
    fn a_path_entry_that_contains_a_junction_is_refused() {
        let ws = std::env::temp_dir().join(format!(
            "saife-runner-paths-junction-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&ws);
        let _ws_guard = Scratch(ws.clone());
        std::fs::create_dir_all(ws.join("app/tree/src")).unwrap();
        std::fs::write(ws.join("app/tree/src/A.java"), b"class A {}").unwrap();
        let outside =
            std::env::temp_dir().join(format!("saife-runner-paths-outside-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&outside);
        let _outside_guard = Scratch(outside.clone());
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("secret.txt"), b"x").unwrap();

        let link = ws.join("app").join("tree").join("linked");
        let status = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&link)
            .arg(&outside)
            .status()
            .expect("mklink runs");
        assert!(
            status.success(),
            "the junction must be created for this test"
        );

        let req = BuildRequest::parse(
            br#"{"project":"app","task":"build","profile":"gradle","paths":["tree"]}"#,
            &ws,
        )
        .expect("lexically fine");
        let err = req
            .validate_on_disk(&ws)
            .expect_err("a junction inside a listed directory must be refused");
        assert!(format!("{err:#}").contains("link or junction"), "{err:#}");
    }

    /// A writer that fails the way a closed pipe does, after the first chunk.
    struct Closing {
        writes: usize,
        flushed: usize,
    }
    impl std::io::Write for Closing {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.writes += 1;
            if self.writes > 1 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "pipe closed",
                ));
            }
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            self.flushed += 1;
            Ok(())
        }
    }

    /// The second chunk hits a closed pipe: it must report "stop writing", not panic, and the
    /// third must not touch the writer again.
    #[test]
    fn a_closed_pipe_stops_writing_instead_of_killing_the_build() {
        let mut sink = StreamSink::new(Closing {
            writes: 0,
            flushed: 0,
        });
        assert!(sink.write(b"first\n"), "the first chunk lands");
        assert!(
            !sink.write(b"second\n"),
            "the closed pipe is reported, not panicked on"
        );
        assert!(sink.is_broken());
        assert!(
            !sink.write(b"third\n"),
            "and nothing is attempted afterwards"
        );
    }

    /// A writer that never fails, so the flush count can be asserted directly.
    struct Recording {
        bytes: Vec<u8>,
        flushes: usize,
    }
    impl std::io::Write for Recording {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.bytes.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            self.flushes += 1;
            Ok(())
        }
    }

    /// Every chunk is flushed as it arrives: a file must show the log while the build runs, which
    /// is the half of T6.2 that made `> out` look empty until exit.
    #[test]
    fn every_chunk_is_flushed_not_buffered_until_the_end() {
        let mut sink = StreamSink::new(Recording {
            bytes: Vec::new(),
            flushes: 0,
        });
        assert!(sink.write(b"one\n"));
        assert!(sink.write(b"two\n"));
        let out = sink.into_inner_for_test();
        assert_eq!(out.bytes, b"one\ntwo\n");
        assert_eq!(out.flushes, 2, "one flush per chunk, not one at the end");
    }
    /// L-N (verdict: partial; fix NOT approved): a `paths` entry carrying a
    /// control character must be refused so build output / log lines cannot be
    /// forged through it. red until L-N lands.
    #[test]
    #[ignore = "red until L-N lands"]
    fn a_paths_entry_with_a_control_character_is_refused() {
        let err = refuse_unsafe_relative("paths entry", "a\nb", "the project")
            .expect_err("a control character in a paths entry must be refused");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("control") || msg.contains("a\nb"),
            "the refusal must name the control character: {msg}"
        );
    }

    /// `C:foo` is drive-relative: not absolute, no leading separator, and it resolves against
    /// the drive's working directory - so it passed both earlier checks. Refused now.
    #[test]
    fn a_drive_relative_path_is_refused() {
        let ws = std::env::temp_dir().join(format!("saife-runner-drive-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&ws);
        std::fs::create_dir_all(ws.join("app")).unwrap();
        // Refused at parse (the lexical policy is shared by `project` and every `paths`
        // entry), or at the disk check - either is a refusal, and the message must say why.
        let refusal = match BuildRequest::parse(
            br#"{"project":"app","task":"build","profile":"gradle","paths":["C:secret"]}"#,
            &ws,
        ) {
            Err(e) => format!("{e:#}"),
            Ok(req) => match req.validate_on_disk(&ws) {
                Err(e) => format!("{e:#}"),
                Ok(()) => panic!("a drive-relative entry must not be accepted"),
            },
        };
        assert!(refusal.contains("no drive"), "got: {refusal}");
        let _ = std::fs::remove_dir_all(&ws);
    }
}
