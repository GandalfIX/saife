use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

/// Containment backend for `saife run`.
///
/// The default is the in-repo AppContainer supervisor: P0 adds the MXC backend
/// behind a flag without changing any existing behaviour (P3 flips the default).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum)]
pub enum Backend {
    /// In-repo AppContainer supervisor (network sessions need elevation).
    #[default]
    #[value(name = "appcontainer")]
    AppContainer,
    /// `mxc-sdk` ProcessContainer (ADR-0004 Option A). Requires a binary built
    /// with `--features mxc-backend`.
    #[value(name = "mxc")]
    Mxc,
}

/// Refusal when `--backend mxc` is selected in a binary without the feature.
pub const MXC_FEATURE_MISSING: &str = "`--backend mxc` requires a binary built with the \
`mxc-backend` feature: rebuild with `cargo build --release --features mxc-backend`";

/// Refusal when more than one MXC run is requested concurrently: ADR-0004
/// guardrail 1 cannot yet attribute proxy traffic to a single run.
pub const MXC_CONCURRENCY_REFUSED: &str = "`--backend mxc` refuses more than one concurrent run: \
run one session per supervisor process (per-run proxy attribution and one listener per run \
landed in P1.4)";

/// Refusal when `--backend mxc` is requested but the session path does not route
/// through the MXC backend yet. Refusing beats a silent fallback to
/// `appcontainer`, which would misreport the containment the child got.
pub const MXC_NOT_WIRED: &str = "`--backend mxc` is not wired into the session path yet (plan P1); \
refusing rather than falling back to `appcontainer`";

/// Whether this session may hand the child OUR console (P3.4).
///
/// The MXC backend launches the child with `StdioMode::Inherit` when this is
/// true: the child then sees a TTY exactly when the supervisor does, which is
/// what an interactive workload (opencode's TUI) needs and what a captured-pipes
/// launch can never provide. It is chosen AUTOMATICALLY — both of this process's
/// standard streams must be terminals — so the common case (`saife run --
/// opencode`) needs no flag.
///
/// `--no-interactive` forces the captured mode, which is the shape a script
/// wants: it reads the session's output, and an inherited child would have
/// written it straight to the console instead. There is deliberately no
/// *required* flag in either direction: a required one would break every existing
/// caller, and a prompt about a stream is worse than a rule.
///
/// Both streams, not just stdout: a task scheduler or a CI runner can give a
/// child a console-ish stdout while stdin is NUL, and a TUI started that way
/// renders and then cannot read a keystroke.
#[cfg_attr(not(feature = "mxc-backend"), allow(dead_code))]
pub fn inherit_console(no_interactive: bool, stdin_is_tty: bool, stdout_is_tty: bool) -> bool {
    !no_interactive && stdin_is_tty && stdout_is_tty
}

/// Refusal when `saife-launch.exe` does not sit beside the supervisor binary.
///
/// `#[cfg_attr(not(feature = "mxc-backend"), allow(dead_code))]`: the only caller
/// is the MXC session path.
///
/// The wrapper is not optional: mxc-sdk 1.0.1 strips `NO_PROXY` from
/// `request.environment` and re-injects only the proxy URL, so without the
/// launcher the child cannot reach the D-4 control plane on loopback — the
/// reason D1 exists at all.
#[cfg_attr(not(feature = "mxc-backend"), allow(dead_code))]
pub const MXC_LAUNCHER_MISSING: &str = "`--backend mxc` needs `saife-launch.exe` beside the \
saife binary: rebuild with `cargo build --release --features mxc-backend` (the wrapper is a \
required bin of that feature)";

/// Decide whether a run may use the selected backend, or explain the refusal.
///
/// Pure on purpose: `feature_enabled` is a parameter rather than a `cfg!` read,
/// so the refusal is testable in both feature states.
///
/// `concurrency` is the requested number of concurrent runs. There is **no**
/// `--concurrency` flag yet (P0.5 found none), so callers pass `None` and the
/// MXC concurrency refusal is currently unreachable; it exists so P1.4 only has
/// to thread the value through once the flag lands.
/// The backend used when `--backend` is not given (P3.2's flip).
///
/// Deliberately a function of the BUILD, not a constant: a binary compiled
/// without `mxc-backend` has no MXC session path at all, and a hard default of
/// `mxc` would make every `run` on such a build refuse with "feature missing".
/// So the flip is feature-conditional and the fallback is loud
/// ([`MXC_FEATURE_FALLBACK`]), never silent.
pub fn default_backend(feature_enabled: bool) -> Backend {
    if feature_enabled {
        Backend::Mxc
    } else {
        Backend::AppContainer
    }
}

/// Printed once when a build without `mxc-backend` falls back to the
/// AppContainer backend, so "why is this still asking for admin?" has an answer.
pub const MXC_FEATURE_FALLBACK: &str = "this build was made with \
--no-default-features (`mxc-backend` off): falling back to --backend appcontainer, \
which needs administrator rights for network sessions. Rebuild without \
--no-default-features for the unelevated default backend.";

pub fn resolve_backend(
    backend: Backend,
    concurrency: Option<usize>,
    feature_enabled: bool,
) -> Result<Backend, String> {
    match backend {
        // The shipped path: never gated, so P0 changes no existing behaviour.
        Backend::AppContainer => Ok(Backend::AppContainer),
        Backend::Mxc => {
            if !feature_enabled {
                return Err(MXC_FEATURE_MISSING.to_string());
            }
            if concurrency.is_some_and(|n| n > 1) {
                return Err(MXC_CONCURRENCY_REFUSED.to_string());
            }
            Ok(Backend::Mxc)
        }
    }
}

/// Why a run may not use the selected backend.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackendRefusal {
    /// The binary was built without the `mxc-backend` feature.
    FeatureMissing,
    /// The feature is present, but the session path does not route through it.
    NotWiredYet,
}

impl BackendRefusal {
    /// The user-facing text for this refusal. The enum carries the decision; the
    /// wording lives here, at the CLI boundary.
    pub fn message(self) -> &'static str {
        match self {
            Self::FeatureMissing => MXC_FEATURE_MISSING,
            Self::NotWiredYet => MXC_NOT_WIRED,
        }
    }
}

/// Route a `saife run` to a backend, or refuse it — fail-closed, before
/// anything is spawned or created.
///
/// Pure and table-testable: `feature_enabled` and `wired` are parameters rather
/// than `cfg!`/runtime reads, so every cell of the matrix is exercised in both
/// feature states. `appcontainer` is never gated, so P0 changes no existing
/// behaviour.
///
/// Order is the contract. Without the feature, `mxc` cannot route at all; with
/// the feature it still refuses until the session path is wired, because
/// ADR-0004 guardrail 1 makes an unproven launch non-conformant.
pub fn route_backend(
    backend: Backend,
    feature_enabled: bool,
    wired: bool,
) -> Result<Backend, BackendRefusal> {
    // The feature gate is expressed once, in `resolve_backend`; with no
    // concurrency hint its only possible refusal is the missing feature.
    match resolve_backend(backend, None, feature_enabled) {
        Err(_) => Err(BackendRefusal::FeatureMissing),
        Ok(Backend::AppContainer) => Ok(Backend::AppContainer),
        Ok(Backend::Mxc) if wired => Ok(Backend::Mxc),
        Ok(Backend::Mxc) => Err(BackendRefusal::NotWiredYet),
    }
}

#[derive(Parser)]
#[command(
    name = "SAIFE Sandbox",
    version,
    about = "Isolate and audit AI agents with production-grade Windows containment policies.",
    // The default clap template never prints the command name, so `--help`
    // would show only the description. The product name belongs in the header:
    // `saife --help` must say who it is, exactly as `--version` does.
    help_template = "{name} {version}\n{about-with-newline}\n{usage-heading} {usage}\n\n{all-args}{after-help}"
)]
pub struct Cli {
    #[command(subcommand)]
    pub cmd: Cmd,
}

#[derive(Subcommand)]
pub enum Cmd {
    /// Run a command in the sandbox.
    Run {
        /// Profile name (resolves to %USERPROFILE%\.saife\profiles\<name>.json)
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

        /// Force captured output instead of handing the child this console.
        /// By default a session whose stdin and stdout are both terminals runs
        /// the workload with inherited stdio (so a TUI works); this flag is for
        /// scripts that read the session's output. No effect on the
        /// `appcontainer` backend, which has no passthrough mode.
        #[arg(long)]
        no_interactive: bool,

        /// Network profile name: none | minimal | developer.
        #[arg(long, value_name = "NAME")]
        network_profile: Option<String>,

        /// Strict audit mode: abort the run if the audit log can't be opened or
        /// the session-start event can't be written. CONNECT audit events remain
        /// best-effort (a mid-stream write failure does not kill active connections).
        #[arg(long)]
        audit_strict: bool,

        /// Containment backend. When omitted the default is `mxc` in a build
        /// with `--features mxc-backend` (P3.2) and `appcontainer` otherwise -
        /// see [`default_backend`]. `mxc` runs unelevated and needs one session
        /// per supervisor process; `appcontainer` remains the escape hatch for
        /// workloads whose client stack cannot use a proxy (WinINet, PowerShell
        /// 5.1: they reach the proxy and cannot authenticate, which guardrail 1
        /// refuses by name).
        #[arg(long, value_enum)]
        backend: Option<Backend>,

        /// Print only the session id and exit 0 without spawning.
        #[arg(long, hide = true)]
        print_sid: bool,

        /// Reuse an existing session id (re-derive its profile + ACLs).
        #[arg(long, value_name = "SID", hide = true)]
        sid: Option<String>,

        /// Load a plugin sidecar for this session (repeatable). Plugins are looked
        /// up as `<root>/<name>/plugin.json`, searching each `--plugin-dir` in the
        /// order given and then `%USERPROFILE%\.saife\plugins`; the first hit
        /// for a name wins. A plugin that cannot be loaded, spawned or made
        /// healthy refuses the session (exit 5).
        #[arg(long, value_name = "NAME")]
        plugin: Vec<String>,

        /// An extra plugin root, consulted BEFORE the global one (repeatable). The
        /// path directly holds `<name>/plugin.json`. A name found here shadows the
        /// global copy; it is never merged with it. Nothing inside the workspace
        /// is discovered implicitly: a cloned repository must never gain host-side
        /// code execution from the act of running `saife run` in it, so
        /// repo-local plugins are usable only when the operator names the directory
        /// here.
        #[arg(long, value_name = "PATH")]
        plugin_dir: Vec<String>,

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
        /// %USERPROFILE%\.saife\learned\<name>.json; defaults to
        /// default.json). Must be given before the subcommand.
        #[arg(long, value_name = "NAME")]
        profile: Option<String>,

        #[command(subcommand)]
        subcommand: LearnedSub,
    },

    /// Manage the build runner: its cache volume and its warm-up.
    Runner {
        #[command(subcommand)]
        subcommand: RunnerSub,
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
        /// `saife run` is elevated; unprivileged runs degrade to block-net.
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
    Verify { session_id: String },
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
pub enum RunnerSub {
    /// Show the cache volume's size, the image and the slots on this machine.
    Status,
    /// Download the toolchain into the cache so builds can run offline.
    Prewarm {
        /// Project whose Gradle wrapper and dependencies to fetch (default: cwd).
        #[arg(default_value = ".")]
        project: String,
    },
}

#[derive(Subcommand)]
pub enum LearnedSub {
    /// List learned entries (host, scope, disposition).
    List,
    /// Remove the learned entry for a host.
    Revoke {
        /// Host whose entry to remove (as shown by `saife learned list`).
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
/// touching the clap layer. See `docs/design/specs/us-3-network-exfiltration-blocked/spec.md`.
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

/// Where profile files live (`%USERPROFILE%\.saife\profiles`).
pub fn profiles_dir() -> PathBuf {
    let userprofile = std::env::var_os("USERPROFILE")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    userprofile.join(".saife").join("profiles")
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn run_accepts_repeatable_plugin_and_plugin_dir() {
        let cli = Cli::parse_from([
            "saife",
            "run",
            "--plugin",
            "tngtech",
            "--plugin",
            "jira",
            "--plugin-dir",
            r"C:\repo\.saife\plugins",
            "--plugin-dir",
            "rel",
            "--",
            "cmd",
        ]);
        let Cmd::Run {
            plugin,
            plugin_dir,
            cmd,
            ..
        } = cli.cmd
        else {
            panic!("expected Cmd::Run");
        };
        assert_eq!(plugin, vec!["tngtech".to_string(), "jira".to_string()]);
        assert_eq!(
            plugin_dir,
            vec![r"C:\repo\.saife\plugins".to_string(), "rel".to_string()],
            "the order the operator gave is the discovery order"
        );
        assert_eq!(cmd, vec!["cmd".to_string()]);
    }

    #[test]
    fn parse_runner_status() {
        let cli = Cli::parse_from(["saife", "runner", "status"]);
        match cli.cmd {
            Cmd::Runner {
                subcommand: RunnerSub::Status,
            } => {}
            _ => panic!("expected runner status"),
        }
    }

    #[test]
    fn parse_runner_prewarm_defaults_to_the_cwd() {
        let cli = Cli::parse_from(["saife", "runner", "prewarm"]);
        match cli.cmd {
            Cmd::Runner {
                subcommand: RunnerSub::Prewarm { project },
            } => assert_eq!(project, "."),
            _ => panic!("expected runner prewarm"),
        }
        let cli = Cli::parse_from(["saife", "runner", "prewarm", "C:/work/app"]);
        match cli.cmd {
            Cmd::Runner {
                subcommand: RunnerSub::Prewarm { project },
            } => assert_eq!(project, "C:/work/app"),
            _ => panic!("expected runner prewarm with a project"),
        }
    }

    #[test]
    fn parse_learned_list() {
        let cli = Cli::parse_from(["saife", "learned", "list"]);
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
        let cli = Cli::parse_from(["saife", "learned", "revoke", "evil.example.com"]);
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
        let cli = Cli::parse_from(["saife", "learned", "clear"]);
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
        let cli = Cli::parse_from(["saife", "learned", "--profile", "dev", "revoke", "a.com"]);
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
        assert!(Cli::try_parse_from(["saife", "learned", "revoke"]).is_err());
    }

    #[test]
    fn parse_learned_unknown_subcommand_rejected() {
        assert!(Cli::try_parse_from(["saife", "learned", "bogus"]).is_err());
    }

    /// The `--profile` flag lives on the `learned` level (plan Step 1), so
    /// it must be given before the subcommand — clap rejects it after.
    #[test]
    fn parse_learned_profile_after_subcommand_rejected() {
        assert!(Cli::try_parse_from(["saife", "learned", "list", "--profile", "dev"]).is_err());
    }

    fn run_backend(args: &[&str]) -> Option<Backend> {
        let mut argv = vec!["saife", "run"];
        argv.extend_from_slice(args);
        argv.extend(["--", "cmd", "/c", "exit", "0"]);
        let cli = Cli::parse_from(argv);
        let Cmd::Run { backend, .. } = cli.cmd else {
            panic!("expected Cmd::Run");
        };
        backend
    }

    /// P3.2: the default is `mxc` in a feature build and `appcontainer`
    /// otherwise — never a refusal. The helper returns None when the flag is
    /// absent, and `default_backend` decides.
    #[test]
    fn the_default_backend_follows_the_build_and_never_refuses() {
        assert_eq!(run_backend(&[]), None);
        assert_eq!(default_backend(true), Backend::Mxc);
        assert_eq!(default_backend(false), Backend::AppContainer);
        // The fallback message names the flag a user would pass, not the feature.
        assert!(MXC_FEATURE_FALLBACK.contains("--backend appcontainer"));
        assert!(MXC_FEATURE_FALLBACK.contains("--no-default-features"));
    }

    #[test]
    fn run_accepts_backend_mxc() {
        assert_eq!(run_backend(&["--backend", "mxc"]), Some(Backend::Mxc));
    }

    #[test]
    fn run_accepts_backend_appcontainer_explicitly() {
        assert_eq!(
            run_backend(&["--backend", "appcontainer"]),
            Some(Backend::AppContainer)
        );
    }

    /// An unknown value must fail as an invalid *value* (naming the valid ones),
    /// not as some other parse error that would also satisfy `is_err()`.
    #[test]
    fn run_rejects_an_unknown_backend() {
        let argv = ["saife", "run", "--backend", "sandboxie", "--", "cmd"];
        let err = match Cli::try_parse_from(argv) {
            Ok(_) => panic!("an unknown backend must be rejected"),
            Err(err) => err,
        };
        assert_eq!(err.kind(), clap::error::ErrorKind::InvalidValue);
        let rendered = err.to_string();
        assert!(
            rendered.contains("appcontainer") && rendered.contains("mxc"),
            "the error must name the valid backends: {rendered}"
        );
    }

    #[test]
    fn appcontainer_is_allowed_in_every_feature_state() {
        for feature_enabled in [false, true] {
            for concurrency in [None, Some(1), Some(8)] {
                assert_eq!(
                    resolve_backend(Backend::AppContainer, concurrency, feature_enabled),
                    Ok(Backend::AppContainer)
                );
            }
        }
    }

    #[test]
    fn mxc_without_the_feature_names_the_feature_in_the_error() {
        let err = resolve_backend(Backend::Mxc, None, false)
            .expect_err("mxc must be refused without the feature");
        assert!(
            err.contains("--features mxc-backend"),
            "the message must name the feature flag: {err}"
        );
        assert_eq!(err, MXC_FEATURE_MISSING);
    }

    #[test]
    fn mxc_refuses_concurrency_above_one() {
        let err = resolve_backend(Backend::Mxc, Some(2), true)
            .expect_err("concurrency > 1 must be refused");
        assert!(
            err.contains("run one session per supervisor process"),
            "the message must say what to do instead: {err}"
        );
        assert!(
            !err.contains("plan P1"),
            "user-facing text must not cite an internal plan: {err}"
        );
        assert_eq!(err, MXC_CONCURRENCY_REFUSED);
    }

    /// The routing decision, exhaustively: 2 backends x 2 feature states x 2
    /// wiring states. The cells that must never soften are feature-off + `mxc`
    /// (refuse) and feature-on + `mxc` + not wired (still refuse, never a silent
    /// fallback to `appcontainer`).
    #[test]
    fn route_backend_matrix_is_fail_closed() {
        for (backend, feature_enabled, wired, expected) in [
            (
                Backend::AppContainer,
                false,
                false,
                Ok(Backend::AppContainer),
            ),
            (
                Backend::AppContainer,
                false,
                true,
                Ok(Backend::AppContainer),
            ),
            (
                Backend::AppContainer,
                true,
                false,
                Ok(Backend::AppContainer),
            ),
            (Backend::AppContainer, true, true, Ok(Backend::AppContainer)),
            (
                Backend::Mxc,
                false,
                false,
                Err(BackendRefusal::FeatureMissing),
            ),
            (
                Backend::Mxc,
                false,
                true,
                Err(BackendRefusal::FeatureMissing),
            ),
            (Backend::Mxc, true, false, Err(BackendRefusal::NotWiredYet)),
            (Backend::Mxc, true, true, Ok(Backend::Mxc)),
        ] {
            assert_eq!(
                route_backend(backend, feature_enabled, wired),
                expected,
                "backend={backend:?} feature_enabled={feature_enabled} wired={wired}"
            );
        }
    }

    /// Each refusal keeps its existing user-facing text, so moving the decision
    /// into an enum cannot silently reword what the CLI prints.
    #[test]
    fn refusal_text_is_the_existing_message() {
        assert_eq!(
            BackendRefusal::FeatureMissing.message(),
            MXC_FEATURE_MISSING
        );
        assert_eq!(BackendRefusal::NotWiredYet.message(), MXC_NOT_WIRED);
        assert!(
            MXC_FEATURE_MISSING.contains("--features mxc-backend"),
            "the feature refusal must name the flag: {MXC_FEATURE_MISSING}"
        );
        assert!(
            !MXC_CONCURRENCY_REFUSED.contains("plan P"),
            "the concurrency refusal must not cite an internal plan: {MXC_CONCURRENCY_REFUSED}"
        );
    }

    /// P3.0: the session path routes through the MXC backend, so the *shipped*
    /// wiring constant must let `--backend mxc` through. Asserted through
    /// [`route_backend`] rather than on the constant itself: the constant is an
    /// input to the decision, and it is the decision that has to change.
    ///
    /// Feature-gated because without the feature the cell is `FeatureMissing`
    /// forever — that refusal is pinned by the matrix test above.
    #[cfg(feature = "mxc-backend")]
    #[test]
    fn the_mxc_backend_is_wired_into_the_session_path() {
        assert_eq!(
            route_backend(Backend::Mxc, true, crate::MXC_SESSION_WIRED),
            Ok(Backend::Mxc),
            "MXC_SESSION_WIRED must be true now that run_inner routes --backend mxc"
        );
    }

    /// P3.4: the console decision is a PURE function of two observed facts and one
    /// flag, so it can be table-tested — no terminal required, and no path where a
    /// caller has to guess what the product does on a CI runner.
    ///
    /// Both streams are load-bearing: stdout-only is the task-scheduler shape
    /// (a console-ish handle with stdin at NUL) in which a TUI renders and cannot
    /// read a key, and stdin-only is a redirect that would swallow the child's
    /// output into a terminal nobody is reading.
    #[test]
    fn the_console_is_inherited_only_when_both_streams_are_terminals_and_nothing_forbids_it() {
        let cases = [
            (
                false,
                true,
                true,
                true,
                "an interactive shell: the CLI/TUI case",
            ),
            (true, true, true, false, "--no-interactive forces capture"),
            (
                false,
                true,
                false,
                false,
                "stdout redirected: a script reads the output",
            ),
            (
                false,
                false,
                true,
                false,
                "stdin redirected: no way to type at a TUI",
            ),
            (false, false, false, false, "both redirected"),
            (
                true,
                false,
                false,
                false,
                "a pipe with the flag: still capture",
            ),
        ];
        for (no_interactive, stdin_is_tty, stdout_is_tty, expected, why) in cases {
            assert_eq!(
                inherit_console(no_interactive, stdin_is_tty, stdout_is_tty),
                expected,
                "no_interactive={no_interactive} stdin_tty={stdin_is_tty} \
                 stdout_tty={stdout_is_tty}: {why}"
            );
        }
    }

    /// The refusal is vacuous today (no `--concurrency` flag exists), so a
    /// serial run must pass — and `Some(1)` must behave like `None`.
    #[test]
    fn mxc_allows_serial_runs() {
        for concurrency in [None, Some(1)] {
            assert_eq!(
                resolve_backend(Backend::Mxc, concurrency, true),
                Ok(Backend::Mxc)
            );
        }
    }

    /// The CLI identity is product surface: `--version` must print
    /// `SAIFE Sandbox 0.2.0` and `--help` must name the product and its
    /// one-line purpose. Asserted on the clap command itself (the same tree
    /// `--version`/`--help` render from), so a rename that misses either the
    /// name or the version fails here instead of at a shell prompt.
    #[test]
    fn cli_identity_is_saife_sandbox_with_the_release_version() {
        use clap::CommandFactory;
        let mut cmd = Cli::command();
        // Derived, never typed: the version lives in Cargo.toml alone (R0.1).
        assert_eq!(
            cmd.render_version().to_string().trim_end(),
            format!("SAIFE Sandbox {}", env!("CARGO_PKG_VERSION"))
        );
        let help = cmd.render_help().to_string();
        assert!(
            help.contains("SAIFE Sandbox"),
            "help must name the product: {help}"
        );
        assert!(
            help.contains(
                "Isolate and audit AI agents with production-grade Windows containment policies."
            ),
            "help must carry the one-line description: {help}"
        );
    }
}
