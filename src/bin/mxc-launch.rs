//! `mxc-launch` — the supervisor-owned wrapper launcher for the MXC backend.
//!
//! ## Why this exists (plan D1)
//!
//! `mxc-sdk 1.0.1` builds the container's environment block and, whenever a
//! proxy is configured, **strips** `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY` and
//! `ALL_PROXY` in any case and re-injects only uppercase `HTTP_PROXY` /
//! `HTTPS_PROXY` (`process_container_common/appcontainer_runner.rs`,
//! `inject_proxy_vars`). `NO_PROXY` therefore cannot be delivered through
//! `ContainerRequest::environment` — and without it a proxy-honouring client
//! that is asked to call a loopback intent endpoint
//! (`http://127.0.0.1:<proxy-port>/sandbox/intent`) sends that request to the
//! supervisor's proxy, which refuses loopback targets by policy. The endpoint
//! becomes unreachable.
//!
//! The supervisor's own process cannot set it either: `request.environment` is
//! the only env channel the launch path has. So the container command becomes
//! *this* wrapper, which sets the environment the SDK scrubs and then starts the
//! real workload.
//!
//! ## Protocol (the documented interface; built by
//! `src/net/mxc.rs::launcher_command`)
//!
//! ```text
//! mxc-launch.exe [--proxy-port <port>] [--env NAME=VALUE]... -- <real command line>
//! ```
//!
//! * `--proxy-port <port>` is the loopback port the supervisor's proxy (and,
//!   on the same listener, its D-4 intent endpoints) listens on for this
//!   session. The wrapper writes it to the child as `SANDBOX_PROXY_PORT`, the
//!   D-0.3 discovery variable (`src/sandbox/appcontainer.rs:1007` is the
//!   AppContainer injector of the same name). Omitting the flag — a session
//!   with no proxy — still writes the name, EMPTY, so a value inherited from
//!   the container's profile environment cannot point the workload at a socket
//!   nobody is listening on.
//! * `--env NAME=VALUE` (repeatable) sets or overrides one variable in the
//!   environment the workload starts with. Reserve it for names the SDK
//!   scrubs — every other variable belongs in `ContainerRequest::environment`.
//!   A later `--env` for the same name wins. The proxy-variable family
//!   (`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `NO_PROXY`,
//!   `SANDBOX_PROXY_PORT`, any case) is refused with [`EXIT_USAGE`]: see
//!   [`RESERVED_ENV_NAMES`].
//! * Everything after `--` is **one** argument: the workload's command line.
//!   It is handed verbatim to `CreateProcessW`, so it means exactly what it
//!   would have meant as the container command itself (same argument parsing,
//!   same PATH search, no shell).
//!
//! The wrapper always sets `NO_PROXY` and `no_proxy` to
//! [`LOOPBACK_NO_PROXY`], and `SANDBOX_PROXY_PORT` to the port named by
//! `--proxy-port` (empty when it names none), before starting the workload. This
//! does not widen egress containment: every non-loopback destination still goes
//! to the supervisor's proxy, and loopback reachability comes from the request's
//! `network.ingress.hostLoopback = allow` (which proxy-only egress requires
//! anyway), not from `NO_PROXY`.
//!
//! ## Exit codes
//!
//! * the workload's own exit code, propagated unchanged;
//! * [`EXIT_CANT_START`] (`127`) **plus** a `mxc-launch: failed to start ...`
//!   line on stderr when the workload could not be started (or its wait
//!   failed). The stderr line is the signature, not the number: a workload that
//!   itself exits 127 propagates identically and writes no such line, so the
//!   code alone cannot distinguish the two;
//! * [`EXIT_USAGE`] (`126`) for a malformed wrapper command line.
//!
//! ## What the caller must guarantee
//!
//! * **Absolute paths in the workload command line.** `CreateProcessW` is called
//!   with `lpApplicationName = NULL`, so the executable is resolved by
//!   `CreateProcessW`'s own search order — which tries the **current
//!   directory** first, ahead of `PATH` and System32. A workload named `curl`,
//!   `git` or `python` can therefore run a planted executable from the session
//!   CWD; review executed a `curl.exe` dropped into the session directory. The
//!   wrapper cannot close this without changing what the command line means, so
//!   the caller (`src/net/mxc.rs::build_request`) must pass absolute paths.
//! * **Nothing may depend on post-exit proxy traffic.** This launch's proof is
//!   frozen when the child exits: the supervisor reads the epoch's counters and
//!   closes the window at that point, so traffic arriving concurrently with —
//!   or after — the exit cannot retroactively fail the launch, and equally
//!   cannot retroactively satisfy it. That is the epoch-read race, and it is
//!   accepted rather than fixed.

use std::ffi::OsString;

use windows::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, WAIT_FAILED, WAIT_OBJECT_0};
use windows::Win32::System::Console::{
    GetStdHandle, STD_ERROR_HANDLE, STD_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
};
use windows::Win32::System::Threading::{
    CreateProcessW, GetExitCodeProcess, INFINITE, PROCESS_CREATION_FLAGS, PROCESS_INFORMATION,
    STARTF_USESTDHANDLES, STARTUPINFOW, WaitForSingleObject,
};
use windows::core::{PCWSTR, PWSTR};

/// Loopback names a proxy-honouring client must dial directly: the supervisor's
/// proxy refuses loopback targets, and the D-4 intent endpoints are served on
/// the supervisor's own loopback listener.
pub const LOOPBACK_NO_PROXY: &str = "localhost,127.0.0.1,::1";

/// Proxy variables `--env` must never set.
///
/// The wrapper exists (plan decision **D1**) precisely because *it* owns
/// `NO_PROXY`: `--env NO_PROXY=evil` would overwrite the loopback value it
/// installs moments later, so a proxy-honouring client would send the loopback
/// intent request into the supervisor's proxy and lose the endpoint. The next
/// three are the SDK's — `HTTP_PROXY`/`HTTPS_PROXY` point at the supervisor's
/// proxy and `ALL_PROXY` is scrubbed for the same reason (plan invariant 5) — so
/// a caller-set value would either bypass the proxy guardrail 1 proves or
/// silently disable it. `SANDBOX_PROXY_PORT` is the wrapper's too (P2.4): it is
/// the D-0.3 discovery variable, so a caller-set value would point a workload's
/// intent POST at a port the supervisor does not own while everything else
/// looked correct. The endpoint comes from `--proxy-port`, which only the
/// supervisor's own `build_request` writes.
///
/// Matching is ASCII case-insensitive because Windows environment names are.
pub const RESERVED_ENV_NAMES: [&str; 5] = [
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "SANDBOX_PROXY_PORT",
];

/// Whether `name` belongs to the proxy-variable family that `--env` may not set.
pub fn is_reserved_env_name(name: &str) -> bool {
    let name = name.trim();
    RESERVED_ENV_NAMES
        .iter()
        .any(|reserved| reserved.eq_ignore_ascii_case(name))
}

/// The workload could not be started, or waiting for it failed. Always
/// accompanied by a `mxc-launch: failed to start ...` line on stderr.
///
/// Deliberately not 1, so it cannot be mistaken for a workload that ran and
/// failed — but the **number alone is not a spawn-failure verdict**. A workload
/// that exits 127 propagates as 127 with no `failed to start` line, and nothing
/// in the exit status distinguishes it. Callers must key on the stderr line and
/// must not treat 127 as proof that no child ever ran.
pub const EXIT_CANT_START: i32 = 127;

/// The wrapper's own command line was malformed.
pub const EXIT_USAGE: i32 = 126;

/// One parsed wrapper invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchPlan {
    /// Variables to set in the wrapper's own environment before spawning, in
    /// command-line order (later entries win).
    pub env: Vec<(String, String)>,
    /// The supervisor's proxy port for this session (`--proxy-port`), written to
    /// the workload as `SANDBOX_PROXY_PORT`. `None` for a session with no proxy.
    pub proxy_port: Option<u16>,
    /// The workload's command line, verbatim.
    pub command: String,
}

/// The process's arguments as `String`s, without `std::env::args()`.
///
/// `args()` **panics** on an argument that is not valid Unicode, and that panic
/// would abort with the runtime's abort code rather than the documented
/// 126/127 — so the raw `args_os()` is read instead and a malformed element
/// becomes an ordinary usage error. (Windows argv is UTF-16, so a lone surrogate
/// has no `String` form; the same applies to arbitrary bytes from a non-Windows
/// launcher.)
fn unicode_args<I: IntoIterator<Item = OsString>>(args: I) -> Result<Vec<String>, String> {
    args.into_iter()
        .enumerate()
        .map(|(index, arg)| {
            arg.into_string().map_err(|bad| {
                format!(
                    "argument {} is not valid Unicode ({:?})",
                    index + 1,
                    bad.to_string_lossy()
                )
            })
        })
        .collect()
}

/// Parse the wrapper's arguments (i.e. `std::env::args().skip(1)`).
pub fn parse_args<I: IntoIterator<Item = String>>(args: I) -> Result<LaunchPlan, String> {
    let mut env: Vec<(String, String)> = Vec::new();
    let mut proxy_port: Option<u16> = None;
    let mut iter = args.into_iter();
    loop {
        match iter.next() {
            // Everything after `--` is one argument: the workload command line.
            Some(flag) if flag == "--" => {
                let command = iter.next().ok_or_else(|| {
                    "nothing after `--`: expected the workload command line".to_string()
                })?;
                if iter.next().is_some() {
                    return Err(
                        "exactly one argument is expected after `--` (the workload command \
                         line must be quoted as a single argument)"
                            .to_string(),
                    );
                }
                if command.trim().is_empty() {
                    return Err("the workload command line after `--` is empty".to_string());
                }
                return Ok(LaunchPlan {
                    env,
                    proxy_port,
                    command,
                });
            }
            Some(flag) if flag == "--proxy-port" => {
                // A second value would be a silent coin toss, and the two values
                // name different listeners.
                if proxy_port.is_some() {
                    return Err("`--proxy-port` was given more than once".to_string());
                }
                let value = iter
                    .next()
                    .ok_or_else(|| "`--proxy-port` requires a port number".to_string())?;
                // Refuse anything that is not a dialable port. `--` here would
                // otherwise be swallowed as the value and the workload's command
                // line would silently become the next token; 0 names no listener.
                let port = value
                    .parse::<u16>()
                    .ok()
                    .filter(|port| *port != 0)
                    .ok_or_else(|| {
                        format!("`--proxy-port {value}` is not a port number (1..=65535)")
                    })?;
                proxy_port = Some(port);
            }
            Some(flag) if flag == "--env" => {
                let entry = iter
                    .next()
                    .ok_or_else(|| "`--env` requires NAME=VALUE".to_string())?;
                let (name, value) = entry
                    .split_once('=')
                    .ok_or_else(|| format!("`--env {entry}` is not NAME=VALUE"))?;
                if name.is_empty() {
                    return Err("`--env` requires a non-empty variable name".to_string());
                }
                if name.contains('\0') || value.contains('\0') {
                    return Err("environment entries must not contain NUL".to_string());
                }
                // D1: the wrapper's own NO_PROXY must not be overridable, and the
                // proxy endpoints are the backend's business, not the caller's.
                if is_reserved_env_name(name) {
                    return Err(format!(
                        "`--env {name}=...` is reserved: the wrapper and the container \
                         backend own HTTP_PROXY/HTTPS_PROXY/ALL_PROXY/NO_PROXY/\
                         SANDBOX_PROXY_PORT, and an override would defeat the loopback \
                         NO_PROXY that keeps the intent endpoint reachable (the port comes \
                         from `--proxy-port`)"
                    ));
                }
                env.push((name.to_string(), value.to_string()));
            }
            Some(other) => {
                return Err(format!(
                    "unrecognised argument `{other}`: expected `--env NAME=VALUE` or `--`"
                ));
            }
            None => {
                return Err("missing `--` and the workload command line".to_string());
            }
        }
    }
}

/// The environment the wrapper adds on top of the container's own block:
/// `NO_PROXY` in both spellings (Windows variable names are case-insensitive,
/// so both names reach the same slot; a case-sensitive POSIX-emulation client
/// inside the container reads the lowercase spelling literally) and
/// `SANDBOX_PROXY_PORT`, the D-0.3 discovery variable for the D-4 intent
/// endpoints (P2.4).
///
/// The port is passed in from the command line rather than parsed out of
/// `HTTP_PROXY`: the supervisor knows which port it bound, and a launcher that
/// re-derived it from the SDK's injected URL would break the moment that URL's
/// shape changed — silently, and only for workloads that use the discovery
/// contract.
///
/// `None` (no proxy for this session) still writes the name, empty. The
/// AppContainer path's `None` arm does the same for all four of its proxy
/// variables, and for the same reason: the child inherits the container's
/// profile environment, so a stale value there would otherwise survive into a
/// session that has no listener at all.
pub fn added_env(proxy_port: Option<u16>) -> Vec<(String, String)> {
    vec![
        ("NO_PROXY".to_string(), LOOPBACK_NO_PROXY.to_string()),
        ("no_proxy".to_string(), LOOPBACK_NO_PROXY.to_string()),
        (
            "SANDBOX_PROXY_PORT".to_string(),
            proxy_port.map(|port| port.to_string()).unwrap_or_default(),
        ),
    ]
}

fn main() {
    let plan = match unicode_args(std::env::args_os())
        .and_then(|argv| parse_args(argv.into_iter().skip(1)))
    {
        Ok(plan) => plan,
        Err(message) => {
            eprintln!("mxc-launch: {message}");
            eprintln!(
                "mxc-launch: usage: mxc-launch.exe [--env NAME=VALUE]... -- \
                 \"<workload command line>\""
            );
            std::process::exit(EXIT_USAGE);
        }
    };

    let mut env = added_env(plan.proxy_port);
    env.extend(plan.env.iter().cloned());
    for (name, value) in &env {
        // SAFETY: single-threaded here — this runs before any worker thread is
        // created, so no other thread can be reading the environment.
        unsafe { std::env::set_var(name, value) };
    }

    match spawn_and_wait(&plan.command) {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!(
                "mxc-launch: failed to start `{}`: {e}",
                first_token(&plan.command)
            );
            std::process::exit(EXIT_CANT_START);
        }
    }
}

/// The part of a command line a reader needs to identify the program, without
/// echoing the whole (possibly sensitive) argument list to stderr.
fn first_token(command: &str) -> &str {
    let trimmed = command.trim_start();
    if let Some(rest) = trimmed.strip_prefix('"') {
        return rest.split('"').next().unwrap_or(rest);
    }
    trimmed.split_whitespace().next().unwrap_or(trimmed)
}

/// Start `command_line` with this process's std handles and wait for it.
///
/// `lpApplicationName` is null, so the OS parses the command line exactly as it
/// would have parsed it as the container command — including its search order,
/// which tries the current directory **first**, so the caller must pass an
/// absolute path (see the module doc). The environment block is inherited from
/// this process, which is how the variables [`added_env`] sets reach the
/// workload.
fn spawn_and_wait(command_line: &str) -> Result<i32, String> {
    let mut wide: Vec<u16> = command_line
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    let mut si = STARTUPINFOW {
        cb: std::mem::size_of::<STARTUPINFOW>() as u32,
        ..Default::default()
    };
    let mut pi = PROCESS_INFORMATION::default();

    // SAFETY: `GetStdHandle` takes no pointers and only reads this process's own
    // std-handle table.
    let std_handles = unsafe {
        (
            std_handle(STD_INPUT_HANDLE),
            std_handle(STD_OUTPUT_HANDLE),
            std_handle(STD_ERROR_HANDLE),
        )
    };

    // All three or none. Under STARTF_USESTDHANDLES a handle we do not have is
    // passed as NULL, so the child's writes vanish into a NULL sink and its reads
    // can never complete — silent output loss, worse than inheriting. With the
    // flag off the child inherits this process's console, which is what an
    // ordinary child gets.
    if let (Some(input), Some(output), Some(error)) = std_handles {
        si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdInput = input;
        si.hStdOutput = output;
        si.hStdError = error;
    }

    // SAFETY: `wide` is writable and NUL-terminated for the duration of the
    // call; the handles are borrowed by value from this process's own std handle
    // table (and are inheritable, because the SDK passed them to us through an
    // inheriting CreateProcessW); `pi` is a valid out-parameter.
    unsafe {
        CreateProcessW(
            PCWSTR::null(),
            Some(PWSTR(wide.as_mut_ptr())),
            None,
            None,
            true,
            // No CREATE_SUSPENDED: the workload starts immediately.
            PROCESS_CREATION_FLAGS(0),
            None,
            PCWSTR::null(),
            &si,
            &mut pi,
        )
        .map_err(|e| format!("{e}"))?;

        let _ = CloseHandle(pi.hThread);

        // A discarded wait result used to mean exit code 0 for a child that may
        // still be running. A wait that did not return WAIT_OBJECT_0 leaves the
        // child's state unknown, so it is reported as a failed spawn (127 plus
        // the `failed to start` line), never as a result.
        let waited = WaitForSingleObject(pi.hProcess, INFINITE);
        if waited != WAIT_OBJECT_0 {
            let detail = if waited == WAIT_FAILED {
                format!("WAIT_FAILED, GetLastError={}", GetLastError().0)
            } else {
                format!("unexpected wait result {}", waited.0)
            };
            let _ = CloseHandle(pi.hProcess);
            return Err(format!(
                "WaitForSingleObject: {detail} (the child's state is unknown)"
            ));
        }

        let mut code: u32 = 0;
        let read = GetExitCodeProcess(pi.hProcess, &mut code);
        let _ = CloseHandle(pi.hProcess);
        read.map_err(|e| format!("GetExitCodeProcess: {e}"))?;
        Ok(code as i32)
    }
}

/// `GetStdHandle` for one of the three standard handles, or `None` when this
/// process has no such handle (a detached console, a closed stream).
///
/// A missing handle is not an error: a closed stdout must not make the wrapper
/// refuse to run the workload. The caller drops `STARTF_USESTDHANDLES` when any
/// of the three is `None`, so the child inherits the console instead of being
/// handed a NULL handle.
///
/// # Safety
/// Calls a Win32 accessor that takes no pointers.
unsafe fn std_handle(which: STD_HANDLE) -> Option<HANDLE> {
    match unsafe { GetStdHandle(which) } {
        // `is_invalid` covers both NULL and INVALID_HANDLE_VALUE: either would
        // be a silent sink under STARTF_USESTDHANDLES.
        Ok(handle) if !handle.is_invalid() => Some(handle),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parses_one_command_line_after_the_separator() {
        let plan = parse_args(args(&["--", "cmd /c echo hi"])).expect("valid");
        assert_eq!(plan.command, "cmd /c echo hi");
        assert!(plan.env.is_empty());
    }

    #[test]
    fn takes_the_command_verbatim_even_when_it_looks_like_a_flag() {
        let plan = parse_args(args(&["--", "--env NOPE=1"])).expect("valid");
        assert_eq!(plan.command, "--env NOPE=1");
        assert!(plan.env.is_empty());
    }

    #[test]
    fn collects_repeated_env_entries_in_order() {
        let plan = parse_args(args(&[
            "--env",
            "A=1",
            "--env",
            "B=two=three",
            "--",
            "run.exe",
        ]))
        .expect("valid");
        assert_eq!(
            plan.env,
            vec![
                ("A".to_string(), "1".to_string()),
                ("B".to_string(), "two=three".to_string()),
            ]
        );
        assert_eq!(plan.command, "run.exe");
    }

    #[test]
    fn rejects_a_missing_separator() {
        let err = parse_args(args(&["run.exe"])).expect_err("no `--`");
        assert!(err.contains("unrecognised argument"), "got {err}");
        assert!(parse_args(args(&[])).is_err());
    }

    #[test]
    fn rejects_a_missing_env_value_or_bad_pair() {
        assert!(parse_args(args(&["--env"])).is_err());
        let err = parse_args(args(&["--env", "NOEQUALS", "--", "x.exe"])).expect_err("bad pair");
        assert!(err.contains("NAME=VALUE"), "got {err}");
        assert!(parse_args(args(&["--env", "=v", "--", "x.exe"])).is_err());
    }

    #[test]
    fn rejects_env_entries_in_the_proxy_family() {
        // D1: the wrapper's own NO_PROXY must not be overridable, and the other
        // three names belong to the backend. `--env NO_PROXY=evil` was verified
        // to win over `added_env()` before this check existed.
        for entry in [
            "NO_PROXY=evil",
            "no_proxy=evil",
            "No_Proxy=",
            "HTTP_PROXY=http://evil:8080",
            "https_proxy=http://evil:8080",
            "ALL_PROXY=socks5://evil:1080",
            "all_proxy=socks5://evil:1080",
            // P2.4: the discovery variable is the wrapper's own fact. A caller
            // value would name a port the supervisor does not own, so the
            // workload would send its intent to somebody else's socket.
            "SANDBOX_PROXY_PORT=1",
            "sandbox_proxy_port=1",
        ] {
            let err = parse_args(args(&["--env", entry, "--", "run.exe"]))
                .expect_err("a proxy variable must be refused");
            assert!(err.contains("reserved"), "{entry}: got {err}");
        }

        // Every other name still works, including ones that merely look like
        // the family.
        for entry in ["PATH=C:\\Windows", "MY_NO_PROXY=1", "NO_PROXY_EXTRA=1"] {
            let plan = parse_args(args(&["--env", entry, "--", "run.exe"])).expect("allowed");
            assert_eq!(plan.env.len(), 1, "{entry}");
        }
    }

    #[test]
    fn a_non_unicode_argument_is_a_usage_error_not_a_panic() {
        use std::ffi::OsString;
        use std::os::windows::ffi::OsStringExt;

        // An unpaired surrogate is exactly what `std::env::args()` panics on.
        let bad = OsString::from_wide(&[0xD800, 0x0041]);
        let err = unicode_args(vec![
            OsString::from("mxc-launch.exe"),
            OsString::from("--"),
            bad,
        ])
        .expect_err("a lone surrogate has no String form");
        assert!(err.contains("not valid Unicode"), "got {err}");
        assert!(err.contains("argument 3"), "the position is named: {err}");

        // Well-formed argv passes through unchanged, program name included
        // (`main` is what skips it).
        let ok = unicode_args(vec![
            OsString::from("mxc-launch.exe"),
            OsString::from("--env"),
        ])
        .expect("unicode argv is accepted");
        assert_eq!(ok, vec!["mxc-launch.exe".to_string(), "--env".to_string()]);
    }

    #[test]
    fn rejects_an_empty_command_or_a_split_command_line() {
        assert!(parse_args(args(&["--"])).is_err());
        assert!(parse_args(args(&["--", "   "])).is_err());
        // Two tokens after `--` would silently drop the second one: refuse.
        let err = parse_args(args(&["--", "cmd", "/c echo hi"])).expect_err("split command");
        assert!(err.contains("exactly one argument"), "got {err}");
    }

    #[test]
    fn sets_both_no_proxy_spellings() {
        let env = added_env(None);
        assert_eq!(
            env,
            vec![
                ("NO_PROXY".to_string(), LOOPBACK_NO_PROXY.to_string()),
                ("no_proxy".to_string(), LOOPBACK_NO_PROXY.to_string()),
                // P2.4: present even when the session has no proxy, and empty —
                // see `added_env`'s note on inherited values.
                ("SANDBOX_PROXY_PORT".to_string(), String::new()),
            ]
        );
        assert_eq!(LOOPBACK_NO_PROXY, "localhost,127.0.0.1,::1");
    }

    /// P2.4: the D-0.3 **discovery** contract.
    ///
    /// A workload written to D-0.3 finds the D-4 control plane from
    /// `SANDBOX_PROXY_PORT` and nowhere else; the AppContainer path has injected
    /// it since Task 1.3 (`src/sandbox/appcontainer.rs:1007`), while this
    /// launcher did not, so under MXC the endpoint existed and was
    /// undiscoverable. The value is the supervisor's own bound port, so it must
    /// come from the command line — never be derived here from `HTTP_PROXY`,
    /// which would make the discovery contract depend on the SDK's URL shape.
    #[test]
    fn injects_the_sandbox_proxy_port_the_workload_discovers() {
        let env = added_env(Some(49_152));
        assert!(
            env.contains(&("SANDBOX_PROXY_PORT".to_string(), "49152".to_string())),
            "the workload must be able to discover the listener: {env:?}"
        );
        // Exactly three entries: the SDK owns HTTP_PROXY/HTTPS_PROXY (it strips
        // and re-injects them from the request's proxy URL) and this wrapper
        // must not invent a second, contradictory copy.
        assert_eq!(env.len(), 3, "{env:?}");
        assert!(env.contains(&("NO_PROXY".to_string(), LOOPBACK_NO_PROXY.to_string())));
        assert!(env.contains(&("no_proxy".to_string(), LOOPBACK_NO_PROXY.to_string())));
    }

    /// The proxy-less arm, matching the AppContainer path's `None` branch: the
    /// name is still written, EMPTY, so a value inherited from the container's
    /// profile environment cannot point a workload at a port nobody listens on.
    #[test]
    fn clears_the_port_when_the_session_has_no_proxy() {
        let env = added_env(None);
        assert!(
            env.contains(&("SANDBOX_PROXY_PORT".to_string(), String::new())),
            "{env:?}"
        );
    }

    #[test]
    fn takes_the_proxy_port_from_its_own_flag() {
        let plan = parse_args(args(&["--proxy-port", "49152", "--", "run.exe"])).expect("valid");
        assert_eq!(plan.proxy_port, Some(49_152));
        assert!(plan.env.is_empty(), "the flag is not an --env entry");

        // Absent means no proxy: the workload gets an empty discovery variable.
        let plan = parse_args(args(&["--env", "A=1", "--", "run.exe"])).expect("valid");
        assert_eq!(plan.proxy_port, None);
        assert_eq!(plan.env.len(), 1);
    }

    #[test]
    fn rejects_a_malformed_or_duplicated_proxy_port() {
        for argv in [
            // A separator consumed as the value would silently drop the
            // workload's command line.
            vec!["--proxy-port", "--", "x.exe"],
            vec!["--proxy-port", "0", "--", "x.exe"],
            vec!["--proxy-port", "65536", "--", "x.exe"],
            vec!["--proxy-port", "http", "--", "x.exe"],
            vec!["--proxy-port", "", "--", "x.exe"],
            // Two values: one of them would win silently.
            vec!["--proxy-port", "1", "--proxy-port", "2", "--", "x.exe"],
        ] {
            let err = match parse_args(args(&argv)) {
                Ok(plan) => panic!("a bad --proxy-port must be refused: {argv:?} -> {plan:?}"),
                Err(err) => err,
            };
            assert!(err.contains("proxy-port"), "{argv:?}: got {err}");
        }
    }

    #[test]
    fn first_token_strips_quotes_and_arguments() {
        assert_eq!(
            first_token(r#""C:\Program Files\x.exe" --flag"#),
            r"C:\Program Files\x.exe"
        );
        assert_eq!(first_token("cmd /c echo hi"), "cmd");
        assert_eq!(first_token(""), "");
    }
}
