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

        /// Block all outbound network (no proxy, no network capability SIDs, all connect() kernel-denied).
        #[arg(long)]
        block_net: bool,

        /// Allow a domain (repeatable). Requires network capability (privateNetworkClientServer SID).
        #[arg(long, value_name = "DOMAIN")]
        allow_domain: Vec<String>,

        /// Deny a domain (repeatable). Checked before the allow-list; deny
        /// always wins. Complements the profile `network.denyDomain` field.
        #[arg(long, value_name = "DOMAIN")]
        deny_domain: Vec<String>,

        /// Disable the interactive network prompt entirely. Unlisted hosts are
        /// denied (or allowed, per `onUnavailable`). Distinct from
        /// `onUnavailable=deny`, which only governs the prompt-unavailable case.
        #[arg(long)]
        no_prompt: bool,

        /// Network profile name: none | minimal | developer.
        #[arg(long, value_name = "NAME")]
        network_profile: Option<String>,

        /// Strict audit mode: abort the run if the audit log can't be opened or
        /// the session-start event can't be written. CONNECT audit events remain
        /// best-effort (a mid-stream write failure does not kill active connections).
        #[arg(long)]
        audit_strict: bool,

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

    /// Manage the learned allow/deny store (permanent prompt decisions).
    Learned {
        /// Learned-file profile name (selects
        /// %USERPROFILE%\.sandbox\learned\<name>.json; defaults to
        /// default.json). Must be given before the subcommand.
        #[arg(long, value_name = "NAME")]
        profile: Option<String>,

        #[command(subcommand)]
        subcommand: LearnedSub,
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

        /// Diagnostic: list the current Windows Firewall loopback exempt list.
        /// --allow-domain / --network-profile require loopback access to reach
        /// the proxy. Loopback is registered automatically at runtime when
        /// `sandbox run` is elevated; unprivileged runs degrade to block-net.
        /// Use this command to check the current exempt state.
        #[arg(long)]
        enable_loopback: bool,
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
        /// Show the fully-resolved profile (extends flattened, security
        /// groups expanded to concrete paths, variables expanded).
        #[arg(long)]
        expanded: bool,
    },
}

#[derive(Subcommand)]
pub enum LearnedSub {
    /// List learned entries (host, scope, disposition).
    List,
    /// Remove the learned entry for a host.
    Revoke {
        /// Host whose entry to remove (as shown by `sandbox learned list`).
        host: String,
    },
    /// Remove all learned entries. The designated recovery path for a
    /// corrupt learned file ([G-5]).
    Clear,
}

/// Resolved CLI inputs for `run`, after parsing flags into a single struct.
///
/// Not yet wired into the supervisor: `main.rs` currently threads the parsed
/// clap fields directly into `run_cmd` / `run_inner`. This struct exists so
/// the US-3 plan's "Update `RunArgs` + `from_cli`" step can land without
/// touching the clap layer. See `docs/specs/us-3-network-exfiltration-blocked/spec.md`.
#[allow(dead_code)]
pub struct RunArgs {
    pub profile: Option<String>,
    pub allow_cwd: bool,
    pub allow: Vec<String>,
    pub read_only: Vec<String>,
    pub block_net: bool,
    pub allow_domain: Vec<String>,
    pub deny_domain: Vec<String>,
    pub no_prompt: bool,
    pub network_profile: Option<String>,
    pub print_sid: bool,
    pub sid: Option<String>,
    pub cmd: Vec<String>,
}

impl RunArgs {
    #[allow(clippy::too_many_arguments)]
    #[allow(dead_code)]
    pub fn from_cli(
        profile: Option<String>,
        allow_cwd: bool,
        allow: Vec<String>,
        read_only: Vec<String>,
        block_net: bool,
        allow_domain: Vec<String>,
        deny_domain: Vec<String>,
        no_prompt: bool,
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
            deny_domain,
            no_prompt,
            network_profile,
            print_sid,
            sid,
            cmd,
        }
    }
}

/// Where profile files live (`%USERPROFILE%\.sandbox\profiles`).
pub fn profiles_dir() -> PathBuf {
    let userprofile = std::env::var_os("USERPROFILE")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    userprofile.join(".sandbox").join("profiles")
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn parse_learned_list() {
        let cli = Cli::parse_from(["sandbox", "learned", "list"]);
        let Cmd::Learned {
            subcommand,
            profile,
        } = cli.cmd
        else {
            panic!("expected Cmd::Learned");
        };
        assert!(matches!(subcommand, LearnedSub::List));
        assert_eq!(profile, None);
    }

    #[test]
    fn parse_learned_revoke_host() {
        let cli = Cli::parse_from(["sandbox", "learned", "revoke", "evil.example.com"]);
        let Cmd::Learned {
            subcommand,
            profile,
        } = cli.cmd
        else {
            panic!("expected Cmd::Learned");
        };
        let LearnedSub::Revoke { host } = subcommand else {
            panic!("expected LearnedSub::Revoke");
        };
        assert_eq!(host, "evil.example.com");
        assert_eq!(profile, None);
    }

    #[test]
    fn parse_learned_clear() {
        let cli = Cli::parse_from(["sandbox", "learned", "clear"]);
        let Cmd::Learned {
            subcommand,
            profile,
        } = cli.cmd
        else {
            panic!("expected Cmd::Learned");
        };
        assert!(matches!(subcommand, LearnedSub::Clear));
        assert_eq!(profile, None);
    }

    #[test]
    fn parse_learned_profile_flag_before_subcommand() {
        let cli = Cli::parse_from(["sandbox", "learned", "--profile", "dev", "revoke", "a.com"]);
        let Cmd::Learned {
            subcommand,
            profile,
        } = cli.cmd
        else {
            panic!("expected Cmd::Learned");
        };
        assert!(matches!(subcommand, LearnedSub::Revoke { .. }));
        assert_eq!(profile.as_deref(), Some("dev"));
    }

    #[test]
    fn parse_learned_revoke_requires_host() {
        assert!(Cli::try_parse_from(["sandbox", "learned", "revoke"]).is_err());
    }

    #[test]
    fn parse_learned_unknown_subcommand_rejected() {
        assert!(Cli::try_parse_from(["sandbox", "learned", "bogus"]).is_err());
    }

    /// The `--profile` flag lives on the `learned` level (plan Step 1), so
    /// it must be given before the subcommand — clap rejects it after.
    #[test]
    fn parse_learned_profile_after_subcommand_rejected() {
        assert!(Cli::try_parse_from(["sandbox", "learned", "list", "--profile", "dev"]).is_err());
    }
}
