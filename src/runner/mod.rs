//! The build runner: what a workload may ask for, and nothing more.
//!
//! The runner is a federated capability, not an executor. A request names a project
//! directory, a task and a profile; the image, the mounts, the environment, the
//! command line and every flag are constants on the supervisor's side. That is the
//! whole security story: a workload that could name an image or a mount could run
//! `-v C:\:/host` through the deputy, so the request type has no field for either and
//! the JSON parser refuses unknown keys by name.

// Exercised only by its own tests until T1.2 wires the declared `POST /build` facade
// operation into it; in a binary crate `pub` does not silence dead-code, and a blanket
// allow here would hide a genuine regression later - so it goes away with T1.2.
#![allow(dead_code)]

use anyhow::{Context, Result, bail};

pub mod server;
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
}
