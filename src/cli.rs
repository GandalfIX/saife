use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "sandbox",
    version,
    about = "Native Windows process sandbox for AI agents"
)]
pub struct Cli {
    #[command(subcommand)]
    pub cmd: Cmd,
}

#[derive(Subcommand)]
pub enum Cmd {
    /// Run a command in the sandbox.
    Run {
        /// Profile name (resolves to %USERPROFILE%\.sandbox\profiles\<name>.json)
        /// or a path to a profile JSON file.
        #[arg(long, value_name = "NAME|PATH")]
        profile: Option<String>,

        /// Grant read+write+execute on the current working directory.
        #[arg(long)]
        allow_cwd: bool,

        /// Grant access on an additional path (repeatable).
        /// Format: <path>[:<mode>] where mode is read|write|readwrite|execute.
        #[arg(long, value_name = "PATH[:MODE]")]
        allow: Vec<String>,

        /// Grant read-only access on a path (repeatable).
        #[arg(long, value_name = "PATH")]
        read_only: Vec<String>,

        /// Block all outbound network (stub for this slice: accepted, logged, ignored).
        #[arg(long)]
        block_net: bool,

        /// Allow a domain (repeatable) (stub for this slice: accepted, logged, ignored).
        #[arg(long, value_name = "DOMAIN")]
        allow_domain: Vec<String>,

        /// Network profile name: none | minimal | developer.
        #[arg(long, value_name = "NAME")]
        network_profile: Option<String>,

        /// Print only the session id and exit 0 without spawning.
        #[arg(long, hide = true)]
        print_sid: bool,

        /// Reuse an existing session id (re-derive its profile + ACLs).
        #[arg(long, value_name = "SID", hide = true)]
        sid: Option<String>,

        /// The command + args, after `--`.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        cmd: Vec<String>,
    },

    /// List sandbox sessions (MVP: returns the single running session or empty).
    Ps {
        /// Show all sessions (not just running).
        #[arg(long)]
        all: bool,
        /// Emit JSON.
        #[arg(long)]
        json: bool,
    },

    /// Inspect or verify the audit trail for a session.
    Audit {
        #[command(subcommand)]
        action: AuditAction,
    },

    /// Manage profiles.
    Profile {
        #[command(subcommand)]
        action: ProfileAction,
    },

    /// Check host compatibility and feature availability.
    Setup {
        /// Only check and report; do not make changes.
        #[arg(long)]
        check_only: bool,

        /// Grant FILE_READ_ATTRIBUTES on every fixed drive root (C:\, D:\, …)
        /// to S-1-15-2-2 (All RESTRICTED APPLICATION PACKAGES). One-time,
        /// idempotent, requires elevation. Fixes KI-1.1: `cmd /c dir` and
        /// PowerShell filesystem-provider init read drive-root volume metadata
        /// via GetVolumeInformationW, which the AppContainer can't reach
        /// without this ACE (the drive root is TrustedInstaller-owned and
        /// cannot be granted per-session unprivileged).
        #[arg(long)]
        grant_drive_root: bool,
    },
}

#[derive(Subcommand)]
pub enum AuditAction {
    /// Show the audit log for a session.
    Show {
        session_id: String,
        #[arg(long)]
        json: bool,
        #[arg(long, value_name = "EXPR")]
        filter: Option<String>,
    },
    /// Recompute the Merkle root and verify the signed audit log.
    Verify {
        session_id: String,
    },
}

#[derive(Subcommand)]
pub enum ProfileAction {
    /// List available profiles.
    List,
    /// Show a profile's resolved contents.
    Show {
        name: String,
    },
}

/// Resolved CLI inputs for `run`, after parsing flags into a single struct.
pub struct RunArgs {
    pub profile: Option<String>,
    pub allow_cwd: bool,
    pub allow: Vec<String>,
    pub read_only: Vec<String>,
    pub block_net: bool,
    pub allow_domain: Vec<String>,
    pub network_profile: Option<String>,
    pub print_sid: bool,
    pub sid: Option<String>,
    pub cmd: Vec<String>,
}

impl RunArgs {
    pub fn from_cli(
        profile: Option<String>,
        allow_cwd: bool,
        allow: Vec<String>,
        read_only: Vec<String>,
        block_net: bool,
        allow_domain: Vec<String>,
        network_profile: Option<String>,
        print_sid: bool,
        sid: Option<String>,
        cmd: Vec<String>,
    ) -> Self {
        Self {
            profile,
            allow_cwd,
            allow,
            read_only,
            block_net,
            allow_domain,
            network_profile,
            print_sid,
            sid,
            cmd,
        }
    }
}

/// Where profile files live.
pub fn profiles_dir() -> PathBuf {
    let userprofile = std::env::var_os("USERPROFILE")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    userprofile.join(".sandbox").join("profiles")
}
