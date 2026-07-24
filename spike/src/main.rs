mod allowlist;
mod appcontainer;
mod job;
mod spawn;

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "spike", about = "AppContainer + RuleSet Option E spike")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run a command in the sandbox.
    Run {
        /// Reuse an existing session id (re-derive its profile + ACLs).
        #[arg(long)]
        sid: Option<String>,
        /// Print only the session id and exit 0 without spawning.
        #[arg(long)]
        print_sid: bool,
        /// Alias the per-session bin dir to a persisted store (STUBBED).
        #[arg(long)]
        reuse: Option<String>,
        /// The command + args, after `--`.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        cmd: Vec<String>,
    },
    /// Persist a session's bin dir to a named store (STUBBED).
    Persist {
        sid: String,
        #[arg(long)]
        as_name: String,
    },
    /// Run the PowerShell test harness.
    Test,
}

fn main() {
    let cli = Cli::parse();
    let rc = match cli.cmd {
        Cmd::Run {
            sid,
            print_sid,
            reuse,
            cmd,
        } => run(sid, print_sid, reuse, cmd),
        Cmd::Persist { sid, as_name } => persist(&sid, &as_name),
        Cmd::Test => test_harness(),
    };
    std::process::exit(rc);
}

fn new_session_id() -> String {
    // 8 hex chars from the nanosecond clock + pid — unique enough for a spike.
    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0) as u64;
    let pid = std::process::id() as u64;
    format!("{:08x}", n ^ (pid.rotate_left(16)))
}

fn cwd() -> PathBuf {
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

fn run(sid: Option<String>, print_sid: bool, reuse: Option<String>, cmd: Vec<String>) -> i32 {
    if reuse.is_some() {
        eprintln!("[spike:diag] --reuse is not implemented in this spike (S-14 optional)");
        return 1;
    }

    let sid = sid.unwrap_or_else(new_session_id);
    let cwd = cwd();

    // Ensure the per-session install dirs exist.
    if let Err(e) = allowlist::ensure_session_dirs(&cwd, &sid) {
        eprintln!("[spike:diag] failed to create session dirs: {e}");
        return 1;
    }

    // Create/derive the AppContainer profile + token.
    let session = match appcontainer::create_session(&sid) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[spike:diag] AppContainer setup failed: {e}");
            return 1;
        }
    };

    // Build the allow-list and grant ACLs.
    let entries = allowlist::build(&sid, &cwd);
    if let Err(e) = appcontainer::grant_access(&session.ac_sid, &entries) {
        if std::env::var_os("SPIKE_DIAG").is_some() {
            eprintln!("[spike:diag] grant_access failed: {e}");
        }
    }

    if print_sid {
        // Print only the sid and exit 0. Do not spawn.
        println!("{}", sid);
        return 0;
    }

    // The first line of stdout is exactly `SESSION <sid>` (the test harness
    // captures it). Then the child's output flows through unchanged.
    println!("SESSION {}", sid);
    // Flush so the harness reliably sees SESSION before child output.
    use std::io::Write;
    let _ = std::io::stdout().flush();

    if cmd.is_empty() {
        return 0;
    }

    // Join the command tokens into a single command line for CreateProcessW.
    // Re-quote any token containing spaces (or empty) so the child's CRT
    // argv parsing reconstructs the original tokens faithfully. The test
    // harness (and the real product) may pass a single argument like
    // `print('hello from python')` which must stay one token.
    fn quote_arg(a: &str) -> String {
        if a.is_empty() {
            "\"\"".to_string()
        } else if a.contains(' ') || a.contains('\t') {
            // Escape embedded backslashes preceding a quote, then escape quotes.
            let escaped = a.replace('\\', "\\\\").replace('"', "\\\"");
            format!("\"{}\"", escaped)
        } else {
            a.to_string()
        }
    }
    let cmdline = cmd.iter().map(|c| quote_arg(c)).collect::<Vec<_>>().join(" ");

    let job = match job::Job::create() {
        Ok(j) => j,
        Err(e) => {
            eprintln!("[spike:diag] Job Object creation failed: {e}");
            return 1;
        }
    };

    let env_block = appcontainer::build_env_block(&sid, &cwd);

    match spawn::spawn(&session, &job, &cwd, env_block, &cmdline) {
        Ok(code) => code as i32,
        Err(e) => {
            eprintln!("[spike:diag] spawn failed: {e}");
            1
        }
    }
}

fn persist(_sid: &str, _name: &str) -> i32 {
    eprintln!("[spike:diag] persist is not implemented in this spike (S-14 optional)");
    1
}

fn test_harness() -> i32 {
    let script = std::path::Path::new("tests/run-tests.ps1");
    if !script.exists() {
        println!("tests/run-tests.ps1 not found — the test harness is written by another agent.");
        println!("Nothing to run.");
        return 0;
    }
    let status = std::process::Command::new("powershell")
        .args(["-ExecutionPolicy", "Bypass", "-File", "tests/run-tests.ps1"])
        .status();
    match status {
        Ok(s) => s.code().unwrap_or(1),
        Err(e) => {
            eprintln!("[spike] failed to invoke powershell: {e}");
            1
        }
    }
}
