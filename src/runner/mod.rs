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
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RawBuildRequest {
    project: String,
    task: String,
    profile: String,
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
        if raw.project.trim().is_empty() {
            bail!("runner: project is empty");
        }
        // A UNC path, a device path or any rooted path names something the workspace
        // boundary cannot contain, so it is refused before it is joined.
        if raw.project.starts_with("\\\\")
            || raw.project.starts_with("//")
            || raw.project.starts_with('/')
            || project.is_absolute()
        {
            bail!(
                "runner: project `{}` must be a path inside the session workspace, not a rooted or network path",
                raw.project
            );
        }
        if project
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            bail!(
                "runner: project `{}` must not climb out of the session workspace (`..`)",
                raw.project
            );
        }

        let resolved = workspace.join(project);
        Ok(BuildRequest {
            project: resolved,
            task: raw.task,
            profile: raw.profile,
        })
    }
    /// The filesystem half of the validation: the lexical checks above can be satisfied by a
    /// path that a junction redirects somewhere else entirely (a link inside the workspace
    /// pointing at `%USERPROFILE%` would copy `.ssh` into the runner). Called by the listener
    /// before a build starts, because this is the first place the path is touched.
    pub fn validate_on_disk(&self, workspace: &Path) -> Result<()> {
        let canonical_ws = std::fs::canonicalize(workspace).with_context(|| {
            format!("runner: the session workspace {} is not readable", workspace.display())
        })?;
        let canonical = std::fs::canonicalize(&self.project).with_context(|| {
            format!("runner: project `{}` does not exist", self.project.display())
        })?;
        if !canonical.starts_with(&canonical_ws) {
            bail!(
                "runner: project `{}` resolves to {}, which is outside the session workspace - \
                 a link or junction is not a way out of it",
                self.project.display(),
                canonical.display()
            );
        }
        // A reparse point inside the tree is refused even when it happens to point inside:
        // the mount step's promise is "what you see is what gets copied".
        for ancestor in canonical.ancestors() {
            if ancestor == canonical_ws.as_path() {
                break;
            }
            let meta = match std::fs::symlink_metadata(ancestor) {
                Ok(m) => m,
                Err(_) => break,
            };
            #[cfg(windows)]
            {
                use std::os::windows::fs::MetadataExt;
                const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
                if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                    bail!(
                        "runner: {} is a link or junction; the project must be a real directory",
                        ancestor.display()
                    );
                }
            }
            #[cfg(not(windows))]
            if meta.file_type().is_symlink() {
                bail!(
                    "runner: {} is a symlink; the project must be a real directory",
                    ancestor.display()
                );
            }
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
        let outside = std::env::temp_dir().join(format!("saife-runner-outside-{}", std::process::id()));
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
        assert!(status.success(), "the junction must be created for this test");

        let req = BuildRequest::parse(br#"{"project":"linked","task":"build","profile":"gradle"}"#, &ws)
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
        let req = BuildRequest::parse(br#"{"project":"app","task":"build","profile":"gradle"}"#, &ws)
            .expect("valid");
        req.validate_on_disk(&ws).expect("a plain directory is fine");
        let _ = std::fs::remove_dir_all(&ws);
    }

    #[test]
    fn a_missing_project_directory_is_refused() {
        let ws = std::env::temp_dir().join(format!("saife-runner-missing-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&ws);
        let req = BuildRequest::parse(br#"{"project":"nope","task":"build","profile":"gradle"}"#, &ws)
            .expect("lexically fine");
        let err = req.validate_on_disk(&ws).expect_err("a missing project is refused");
        assert!(format!("{err:#}").contains("does not exist"), "{err:#}");
        let _ = std::fs::remove_dir_all(&ws);
    }

}
