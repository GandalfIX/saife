//! MXC `processcontainer` containment backend — ADR-0004 Option A.
//!
//! This module is the *only* place the supervisor talks to `mxc-sdk`. It is
//! compiled only with the `mxc-backend` Cargo feature; the AppContainer
//! supervisor is untouched and remains the default backend (P3 flips it).
//!
//! What is here:
//!
//! * [`build_request`] is a **pure** mapping from our resolved session data to a
//!   `ContainerRequest`. No I/O, no SDK calls, so it is fully unit-testable.
//! * The container command is always the wrapper launcher, never the workload
//!   itself: `mxc-sdk 1.0.1` scrubs `NO_PROXY` from `request.environment`, and
//!   without it a proxy-honouring client that is asked to call the D-4 intent
//!   endpoint would send that request into the proxy (plan decision **D1**).
//!   [`launcher_command`] builds `saife-launch.exe -- "<real command line>"`;
//!   `src/bin/saife-launch.rs` sets `NO_PROXY`, starts the workload with inherited
//!   stdio and propagates its exit code.
//! * [`MxcBackend`] is a **state-carrying** launch context — proof source, proxy
//!   port, wrapper launcher and run budget — so a request can never describe a
//!   proxy the backend does not own (plan decision **D4**).
//! * Guardrail 1 ([`ProofExpectation`] + [`verify_proxy_proof`]) is a hard gate
//!   with **two** legs: a network session must prove the child reached the proxy
//!   (`Required`), and a blocked/proxy-less session must prove the proxy was
//!   never consulted (`MustBeAbsent`). Both are errors, never warnings (plan
//!   decision **D3**).
//! * Every launch owns an attribution **epoch**: opened before the child starts,
//!   closed on the success *and* the error path ([`EpochGuard`]).
//! * Guardrail 2 ([`probe_tier`]) records the tier of the *exact* request about
//!   to be launched, and P2.3 gives that record a destination: the session-start
//!   audit leaf (`crate::audit::session_start`), via [`TierRecord::audit_facts`].
//!   Its hard half is [`TierExpectation`] + [`verify_tier`] — a session that
//!   dispatches to a tier other than the one it requires is refused *before* the
//!   launch epoch opens, so it can have no CONNECT leaf.
//! * The **real** proof source is this listener's own counters:
//!   [`LaunchCounters`](crate::net::proxy::LaunchCounters) in `src/net/proxy.rs`
//!   implements [`ProxyProofSource`] (see the impl below), and [`launch_session`]
//!   is the seam that binds one to the other — the port the supervisor bound is
//!   the port the request configures, and the same port decides which guardrail
//!   leg applies.
//! * P1.3's filesystem policy is [`filesystem_policy`] (amended by P3.4): the
//!   writable grants are the workspace **plus every explicit operator grant**
//!   (the profile's `filesystem.allow` and each `--allow <path>` that is not
//!   `:read`) — refusing a second writable root made every tool that keeps state
//!   in the profile unrunnable, so it is wired now — and the launcher's directory
//!   is added automatically
//!   ([`ensure_launcher_grant`]) **before** the deny list is filtered against the
//!   grant set, and the profile's four credential directories plus the configured
//!   deny list become `denied_paths`. A deny that contains a grant (equal to it,
//!   or an ancestor of it) is a hard [`RequestError::DenyCoversGrant`], never a
//!   silent drop — dropping it would leave the rest of the denied tree readable.
//!
//! Not here, by design: the session-start audit leaf itself (`crate::audit::
//! session_start`, P2.3 — this module only hands it a [`TierRecord`]) and the
//! WinHTTP measurement (P1.5). The per-run token
//! that makes concurrent sessions safe landed in P1.4 and lives where it is
//! enforced: `net::token::RunToken` mints one credential per run and the listener
//! accepts only its own (`net::proxy::classify_auth`). What this module owns is
//! the other half — an overlapping launch epoch is refused with
//! [`MxcError::Concurrency`] rather than splitting one window between two runs.
//! **The session deadline is supervisor-owned (P2.1).** [`build_request`] passes
//! the caller's `timeout_ms` through unchanged — `None` means *no deadline*,
//! because the SDK turns a zero timeout into `INFINITE`
//! (`mxc_common::script_runner::get_timeout_milliseconds`) — so the arithmetic
//! lives one layer up, in [`MxcBackend`]: it always writes
//! `Some(SessionBudget::timeout_ms())`, i.e. the prompt term plus the workload term
//! plus the slack ([`PROMPT_BUDGET`], [`WORKLOAD_BUDGET`], [`SESSION_SLACK`]).
//! There is no representation of "no budget" on that path, so a caller cannot ship
//! an unbounded session by leaving a field unset, and a kill at the deadline is
//! attributed to the term that spent the time ([`TimeoutReason`]) instead of being
//! reported as a bare timeout.
//!
//! There is no attestation at `mxc-sdk 1.0.1` (ADR-0004): the tier is observed
//! after the fact, and `warnings: []` is never treated as evidence.

// P1 wires the launch path behind `MxcBackend`, but `main.rs` still refuses
// `--backend mxc` (`MXC_SESSION_WIRED = false`), so nothing in the binary
// constructs a backend and *every* item in this module is unreachable from a
// non-test build: `pub` inside a binary crate is not a reachable entry point.
// The allow is scoped to non-test builds so genuine rot still surfaces under
// `cargo test`. Removing it requires a real call site in `main.rs` (the P2/P3
// session wiring), not merely this seam. Unreachable set: the whole public
// surface — `BLOCKED_ENV_KEYS`, `is_blocked_env_key`, `LAUNCHER_EXE_NAME`,
// `launcher_grant`, `launcher_command`, `ensure_launcher_grant`,
// `PROFILE_SECRET_DIRS`, `filesystem_policy`, `launch_session`,
// `MxcFilesystemInput`, `MxcNetworkInput`, `MxcSessionInput`, `ProxyProof`,
// `ProofExpectation`, `verify_proxy_proof`, `GuardError`, `ProxyProofSource`,
// `TierRecord`, `ProbeView`, `tier_record`, `probe_tier`, `TIER_SOURCE_PROBE`,
// `TIER_SOURCE_UNAVAILABLE`, `TierExpectation`, `REQUIRED_TIER`, `verify_tier`,
// `TierMismatch`, `RequestError`, `MxcError`, `SessionOutcome`, `build_request`,
// `process_container_config`, `MxcBackend`.
#![cfg_attr(not(test), allow(dead_code))]

use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::net::proxy::EpochAlreadyOpen;

use mxc_sdk::mxc_common::config_parser::{
    ExactOneShotContract, load_one_shot_request_from_contract,
};
use mxc_sdk::mxc_common::logger::{Logger, Mode};
use mxc_sdk::mxc_common::models::ExecutionRequest;
use mxc_sdk::mxc_common::sandbox_process::{SandboxProcess, StdioMode};
use mxc_sdk::mxc_contract::published::v1_0_0 as contract;
use mxc_sdk::process_container_common::dispatcher::{DispatchedProcess, spawn_with_fallback};
use mxc_sdk::v1;
use mxc_sdk::v1::WaitResult;

// ---------------------------------------------------------------------------
// Environment allow-list
// ---------------------------------------------------------------------------

/// Environment keys that must never be copied from the host into the container.
///
/// This is invariant 5 of the migration plan and a direct consequence of
/// ADR-0004: MXC injects its own `HTTP_PROXY`/`HTTPS_PROXY` pointing at the
/// supervisor's proxy and leaves `NO_PROXY` unset. A host value that crossed
/// into the request would either point the child at a proxy we do not control —
/// which makes guardrail 1 unprovable — or disable proxying for a host we
/// intended to route.
///
/// `NO_PROXY` is on this list even though the child *does* need one: the value
/// it needs is the loopback-only one, delivered by the wrapper launcher
/// ([`launcher_command`]) after the SDK has finished sanitising the request
/// environment. A caller-supplied value would still be wrong.
///
/// Matching is ASCII case-insensitive because Windows environment names are.
pub const BLOCKED_ENV_KEYS: [&str; 4] = ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"];

/// Whether `key` is a host proxy variable that must be stripped.
pub fn is_blocked_env_key(key: &str) -> bool {
    let key = key.trim();
    BLOCKED_ENV_KEYS
        .iter()
        .any(|blocked| blocked.eq_ignore_ascii_case(key))
}

// ---------------------------------------------------------------------------
// Wrapper launcher (D1: the only way NO_PROXY reaches the child)
// ---------------------------------------------------------------------------

/// File name of the wrapper launcher, deployed beside the supervisor's own
/// executable (`src/bin/saife-launch.rs`).
pub const LAUNCHER_EXE_NAME: &str = "saife-launch.exe";

/// The directory the container must be granted to execute the launcher.
///
/// Filesystem policy in MXC is additive grants, so the container cannot execute
/// the launcher unless its directory is granted; without this the launch fails
/// with a policy denial that names nothing. Callers therefore never supply it:
/// [`build_request`] inserts it through [`ensure_launcher_grant`]. The function
/// stays public so the grant can be named in diagnostics and reused by the
/// launch-path tooling without duplicating the parent-directory rule.
pub fn launcher_grant(launcher: &Path) -> Option<String> {
    let dir = launcher.parent()?.display().to_string();
    // A bare file name has no directory to grant; returning `Some("")` would
    // turn into an empty filesystem path in the request.
    (!dir.is_empty()).then_some(dir)
}

/// Insert the launcher's directory into the request's read-only grants.
///
/// A missing launcher grant fails with an opaque policy denial at launch, so
/// the mapping adds it rather than trusting every caller to remember (plan P1.3).
/// Returns whether the grant was added — a caller that already declared it keeps
/// its declared order and is not duplicated.
///
/// **Exposure, recorded not hidden:** MXC grants *directories*, not files, so
/// this is the launcher's whole **parent** directory — not just
/// `saife-launch.exe`. The launcher is deployed beside the supervisor
/// (`target\debug\saife-launch.exe` in this repo), which means every container
/// gets a read-only view of the directory the binary was built into: the build
/// directory, and for this repository that is `<repo>\target\debug` plus every
/// sibling of the executable. When the supervisor itself is installed under
/// `C:\Program Files\<app>\`, the granted directory is that installation
/// directory instead. The narrowing options — copying the launcher into a
/// directory of its own, or granting a dedicated one-entry directory beside it —
/// are deferred; the plan's P1.3 row records both this exposure and why it was
/// accepted (nothing writable is added, and the alternative is a launcher the
/// container cannot execute).
///
/// This grant is also a grant for deny-coverage purposes: see
/// [`filesystem_policy`], which adds it **before** filtering the deny list for
/// exactly that reason.
pub fn ensure_launcher_grant(filesystem: &mut MxcFilesystemInput, launcher: &Path) -> bool {
    let Some(grant) = launcher_grant(launcher) else {
        return false;
    };
    if filesystem
        .readonly_paths
        .iter()
        .any(|declared| path_key(declared) == path_key(&grant))
    {
        return false;
    }
    filesystem.readonly_paths.push(grant);
    true
}

/// Normalized comparison key for a Windows path.
///
/// Two spellings that name the same object must compare equal, and none of these
/// paths has to exist — a deny list is configuration, not a directory scan — so
/// nothing here touches the filesystem:
///
/// * separators become `\` and runs of them collapse;
/// * a verbatim/device prefix is dropped: `\\?\C:\x` and `\\.\C:\x` are
///   `C:\x`, and `\\?\UNC\server\share` is `\\server\share`;
/// * each component loses its **trailing** dots and spaces, which Win32 ignores,
///   **before** the `.`/`..` tests — so `.. ` (trailing space) is still the
///   parent directory rather than a segment that trims to nothing;
/// * `.` segments are dropped and `..` segments collapse against their parent,
///   clamping at the root as Windows does;
/// * the UNC root's server and share components lose their trailing dots and
///   spaces too, like every other component: `\\srv\share.\x` is
///   `\\srv\share\x`;
/// * a trailing separator is dropped (a drive root keeps the bare `c:` form, so
///   that it still prefixes its own children) and the whole key is case-folded
///   by [`fold_case`].
///
/// **Spellings this deliberately does *not* unify.** Each of these still compares
/// *different*, so a deny spelled one way does not cover a grant spelled the
/// other — recorded here so the gap is a known caveat rather than a surprise:
///
/// * **8.3 short names**: `C:\PROGRA~1` and `C:\Program Files` are distinct keys
///   (expanding them needs the filesystem);
/// * **junctions and symlinks**: an alias and its target are distinct keys, for
///   the same reason — nothing here touches the disk;
/// * **drive-relative (`C:work`) and root-relative (`\Windows`) spellings**: they
///   resolve against a per-drive or per-process current directory this function
///   cannot know, so they are distinct from the absolute forms. That is why
///   [`filesystem_policy`] and [`build_request`] make their cwd and launcher
///   absolute first ([`absolute_path`]) instead of trusting the caller's
///   spelling;
/// * **alternate data streams**: `C:\x\file:stream` keeps its `:stream` suffix,
///   which is not stripped, so it never matches the base file.
fn path_key(path: &str) -> String {
    let unified = unify_path_prefix(path);
    let (root, rest) = split_path_root(&unified);

    let mut segments: Vec<&str> = Vec::new();
    for segment in rest.split('\\') {
        // Trailing spaces first, then the `.`/`..` tests, then the dots: Windows
        // ignores a component's trailing dots and spaces *before* deciding what
        // the component means, so `.. ` is the parent directory. Doing it in any
        // other order dropped `.. ` (it trimmed to nothing), keying
        // `C:\work\sub\.. \x` as `c:\work\sub\x`. Dots cannot be trimmed before
        // the `..` test for the same reason in reverse: `..` would lose its own
        // dots.
        let segment = segment.trim_end_matches(' ');
        if segment.is_empty() || segment == "." {
            continue;
        }
        if segment == ".." {
            segments.pop();
            continue;
        }
        let segment = trim_component(segment);
        if !segment.is_empty() {
            segments.push(segment);
        }
    }

    let mut key = fold_case(&root);
    for segment in segments {
        if !key.is_empty() && !key.ends_with('\\') {
            key.push('\\');
        }
        key.push_str(&fold_case(segment));
    }
    key
}

/// One path component as Win32 compares it: trailing dots and spaces are not part
/// of the name.
fn trim_component(component: &str) -> &str {
    component.trim_end_matches(['.', ' '])
}

/// Win32's case fold, as closely as `std` approximates it: Unicode **uppercase**
/// (`str::to_uppercase`).
///
/// Windows' ordinal case-insensitive compare (`CompareStringOrdinal` with
/// `bIgnoreCase`) uppercases each character from its invariant table, so folding
/// both sides with Unicode uppercase agrees with it across the scripts a Windows
/// path practically contains (ASCII, Latin-1, Greek, Cyrillic) where the previous
/// `to_ascii_lowercase` did not: `C:\Users\Ä` and `C:\Users\ä` name one directory
/// and now produce one key, so a deny of either covers a grant under the other.
/// Folding to uppercase rather than lowercase matters for the same reason:
/// uppercase is what Windows compares.
///
/// **Approximation, recorded not hidden:** `std` performs *full* case mapping,
/// which may expand one character into several (`ß` → `SS`), while Windows maps
/// character for character. Where the two disagree the difference is an
/// *over*-match — two spellings compare equal here that Windows would distinguish
/// — which fails closed: the over-covering deny is refused
/// ([`RequestError::DenyCoversGrant`]) rather than shipped or dropped. It is not
/// an under-match that would let a covering deny through.
fn fold_case(text: &str) -> String {
    text.to_uppercase()
}

/// Separator unification plus verbatim/device-prefix removal, so
/// [`path_key`]'s segment pass sees one spelling per path.
fn unify_path_prefix(path: &str) -> String {
    let raw = path.trim().replace('/', "\\");
    let bytes = raw.as_bytes();
    if bytes.len() < 4
        || !(bytes[..4].eq_ignore_ascii_case(br"\\?\") || bytes[..4].eq_ignore_ascii_case(br"\\.\"))
    {
        return raw;
    }
    // Byte 4 is a char boundary: the prefix that matched is ASCII.
    let rest = &raw[4..];
    let rest_bytes = rest.as_bytes();
    if rest_bytes.len() >= 4 && rest_bytes[..4].eq_ignore_ascii_case(br"UNC\") {
        // `\\?\UNC\server\share` is the plain UNC path `\\server\share`.
        return format!("\\\\{}", &rest[4..]);
    }
    rest.to_string()
}

/// Split a unified path into its root (`C:`, `\\server\share`, `\`, or `""`)
/// and the part below it.
///
/// A drive root is returned **without** its separator so the joined key still
/// prefixes its children (`c:` covers `c:\work`); the join in [`path_key`]
/// re-adds exactly one separator. The UNC root's server and share components are
/// trimmed like every other component ([`trim_component`]), which is why the root
/// is owned: `\\srv\share.` and `\\srv\share` must be one root.
fn split_path_root(path: &str) -> (String, &str) {
    let bytes = path.as_bytes();
    if bytes.len() >= 2 && bytes[0] == b'\\' && bytes[1] == b'\\' {
        // UNC root: `\\server\share`; everything after it is segments.
        let mut parts = path[2..].splitn(3, '\\');
        let server = parts.next().unwrap_or_default();
        let share = parts.next().unwrap_or_default();
        let end = 2 + server.len() + usize::from(!share.is_empty()) + share.len();
        let root = if share.is_empty() {
            format!("\\\\{}", trim_component(server))
        } else {
            format!("\\\\{}\\{}", trim_component(server), trim_component(share))
        };
        return (root, &path[end..]);
    }
    if bytes.len() >= 2 && bytes[1] == b':' {
        return (path[..2].to_string(), &path[2..]);
    }
    if bytes.first() == Some(&b'\\') {
        return ("\\".to_string(), &path[1..]);
    }
    (String::new(), path)
}

/// Is `parent` the same path as `child`, or an ancestor of it?
///
/// Segment-aware, so `C:\work2` is *not* covered by `C:\work`, and comparison
/// happens on [`path_key`], so case, separator style, `.`/`..` segments, a
/// verbatim prefix and a trailing dot all compare equal. An empty `parent`
/// covers nothing: an empty deny is a mistake, not a wildcard.
fn covers(parent: &str, child: &str) -> bool {
    let (parent, child) = (path_key(parent), path_key(child));
    !parent.is_empty()
        && (child == parent
            || child
                .strip_prefix(&parent)
                .is_some_and(|rest| rest.starts_with('\\')))
}

/// Resolve a caller-supplied path that takes part in the deny-vs-grant
/// comparison, naming the input it was.
///
/// The comparison is between [`path_key`]s, and a relative spelling keys as
/// itself (`tools\sandbox`, or empty for `.`) — which never matches an absolute
/// deny, so the guard would pass a deny that covers the real directory and the
/// container would then be denied its own workspace or launcher. Every path in
/// that comparison is therefore made absolute at the boundary:
/// `std::path::absolute` joins a relative path onto the current directory (and a
/// drive-relative `C:work` onto that drive's current directory) without touching
/// the filesystem, while an already-absolute path — a verbatim `\\?\C:\x`
/// included — is returned unchanged.
///
/// A spelling that cannot be resolved (empty, or rejected by the OS) is
/// [`RequestError::PathNotAbsolute`]: guessing what it meant is how the guard gets
/// voided, and the operator can name a real path.
fn absolute_path(what: &'static str, path: &Path) -> Result<PathBuf, RequestError> {
    if path.as_os_str().is_empty() {
        return Err(RequestError::PathNotAbsolute {
            what,
            path: String::new(),
        });
    }
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }
    std::path::absolute(path).map_err(|_| RequestError::PathNotAbsolute {
        what,
        path: path.display().to_string(),
    })
}

/// Quote one argv element so that a `CommandLineToArgvW`-compatible parser
/// (what `CreateProcessW`'s target and Rust's `std::env::args` both use)
/// returns it unchanged.
///
/// This mirrors the algorithm Rust's own `Command` uses on Windows: backslashes
/// are literal unless they precede a quote, where they are doubled, and a
/// backslash run before the closing quote is doubled as well.
///
/// A NUL is **not** rejected here — the function is byte-transparent — but an
/// embedded NUL would truncate the command line at the OS boundary, so
/// [`build_request`] refuses such a command before a request exists
/// ([`RequestError::NulInCommand`]).
fn quote_windows_arg(arg: &str) -> String {
    let needs_quotes = arg.is_empty()
        || arg
            .chars()
            .any(|c| matches!(c, ' ' | '\t' | '"' | '\n' | '\u{b}'));
    if !needs_quotes {
        return arg.to_string();
    }

    let mut out = String::with_capacity(arg.len() + 2);
    out.push('"');
    let mut backslashes = 0usize;
    for c in arg.chars() {
        match c {
            '\\' => backslashes += 1,
            '"' => {
                // 2n+1 backslashes then the quote: n literal backslashes plus
                // the escaping one.
                for _ in 0..(backslashes * 2 + 1) {
                    out.push('\\');
                }
                out.push('"');
                backslashes = 0;
            }
            other => {
                for _ in 0..backslashes {
                    out.push('\\');
                }
                backslashes = 0;
                out.push(other);
            }
        }
    }
    // Trailing backslashes would otherwise escape the closing quote.
    for _ in 0..(backslashes * 2) {
        out.push('\\');
    }
    out.push('"');
    out
}

/// The proxy URL the child is given, with the session token as `userinfo` when
/// there is one.
///
/// No token → the credential-less form (a proxy that authenticates nobody).
///
/// Refuses a token containing anything outside the RFC 3986 *unreserved* set: in
/// `userinfo`, `@` ends the userinfo early and `/` ends the authority, so either
/// could point the child at a different host or port than the one the supervisor
/// bound and proves.
fn proxy_url(port: u16, token: Option<&str>) -> Result<String, RequestError> {
    let Some(token) = token.filter(|token| !token.is_empty()) else {
        return Ok(format!("http://127.0.0.1:{port}"));
    };
    if !token
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | '~'))
    {
        return Err(RequestError::UnsafeProxyToken);
    }
    Ok(format!("http://sandbox:{token}@127.0.0.1:{port}"))
}

/// The container command: the wrapper launcher, the port it must publish, and the
/// real workload command line as its single argument.
///
/// The workload's command line travels as **one** argument and the wrapper hands
/// it to `CreateProcessW` verbatim, so it keeps exactly the meaning it would
/// have had as the container command itself.
///
/// `--proxy-port` (P2.4) is the supervisor's bound port, which the wrapper writes
/// to the child as `SAIFE_PROXY_PORT` — the D-0.3 discovery variable the
/// AppContainer path has always injected (`src/sandbox/appcontainer.rs:1007`).
/// Without it a workload written to D-0.3 could not find the D-4 intent endpoint
/// under this backend at all. The port is the value from the same
/// `input.network.proxy_port` that becomes the request's `networkProxy`, so the
/// variable and the proxy URL cannot disagree; `None` (proxy-less session) omits
/// the flag and the wrapper writes the name empty.
pub fn launcher_command(launcher: &Path, real_command: &str, proxy_port: Option<u16>) -> String {
    let port_flag = match proxy_port {
        Some(port) => format!(" --proxy-port {port}"),
        None => String::new(),
    };
    format!(
        "{}{port_flag} -- {}",
        quote_windows_arg(&launcher.to_string_lossy()),
        quote_windows_arg(real_command)
    )
}

/// The wrapper launcher that must ship beside the supervisor binary (P3.0).
///
/// D1 makes `saife-launch.exe` the command the container actually runs, and the
/// release build puts every bin in the same directory, so "beside this exe" is
/// where it is. `None` when it is not there: the caller refuses by name
/// ([`crate::cli::MXC_LAUNCHER_MISSING`]) rather than launching a session whose
/// wrapper — and therefore whose `NO_PROXY` and D-0.3 discovery variable — would
/// be missing.
pub fn launcher_beside(supervisor_exe: &Path) -> Option<PathBuf> {
    let candidate = supervisor_exe.parent()?.join(LAUNCHER_EXE_NAME);
    candidate.is_file().then_some(candidate)
}

// ---------------------------------------------------------------------------
// Input: our resolved session data (plain, no SDK types)
// ---------------------------------------------------------------------------

/// Filesystem grants as the supervisor resolved them (P1.3 maps policy onto
/// this; for now only explicit grants are passed through).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MxcFilesystemInput {
    pub readwrite_paths: Vec<String>,
    pub readonly_paths: Vec<String>,
    /// Paths the child must not see. Filesystem policy is *additive* in MXC, so
    /// a "workspace only" posture needs explicit denies (ADR-0004).
    pub denied_paths: Vec<String>,
}

/// Network posture for the launch.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct MxcNetworkInput {
    /// Loopback port the supervisor's proxy listens on (P1.4 binds it). `None`
    /// means no proxy: the request stays egress-denied and host loopback stays
    /// closed.
    ///
    /// [`MxcBackend`] overrides this with its own port; the field stays so the
    /// pure mapping can be exercised on its own.
    pub proxy_port: Option<u16>,
    /// The session token the proxy's `Proxy-Authorization` gate expects.
    ///
    /// It is embedded in the proxy URL's `userinfo`
    /// (`http://sandbox:<token>@127.0.0.1:<port>`) because that URL is the
    /// **only** channel that reaches the child's `HTTP_PROXY`/`HTTPS_PROXY`:
    /// mxc-sdk 1.0.1 strips every proxy variable from `request.environment` and
    /// re-injects the URL from `runtimeConfig.networkProxy` verbatim
    /// (`ProxyAddress::original_url` → `to_url`). Without it every child request
    /// is a `407` and guardrail 1 could never pass — the ADR-0004 spike's
    /// listener had no auth, so the gap only appears against the real proxy.
    ///
    /// Only URL-unreserved characters are accepted
    /// ([`RequestError::UnsafeProxyToken`]): anything else would change which
    /// host or port the child is told to use.
    pub proxy_token: Option<String>,
}

/// What `{:?}` prints in place of the token.
///
/// [`MxcNetworkInput::proxy_token`] is a credential — the session token the
/// proxy's `Proxy-Authorization` gate expects — so a derived `Debug` would print
/// it into every log line, panic message and error chain that formats an input,
/// which is exactly the leak audit logging exists to prevent.
pub const REDACTED_TOKEN: &str = "<redacted>";

impl fmt::Debug for MxcNetworkInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MxcNetworkInput")
            .field("proxy_port", &self.proxy_port)
            .field(
                "proxy_token",
                &self.proxy_token.as_ref().map(|_| REDACTED_TOKEN),
            )
            .finish()
    }
}

/// How the sandboxed child's standard streams are wired (P3.4).
///
/// `mxc-sdk 1.0.1` exposes the choice as
/// `mxc_common::sandbox_process::StdioMode`, and it decides more than where bytes
/// go: with `StdioMode::Pipes` the backend hands the child capture pipes and no
/// console, so a TUI cannot start; with `StdioMode::Inherit` the child inherits
/// *this* process's std handles and sees a TTY exactly when we do. Until P3.4 the
/// supervisor requested no mode at all, which meant the capture path — and
/// therefore no interactive workload could run under `mxc`.
///
/// This type is ours (not the SDK's) for the same reason the rest of a session
/// input is: the decision is data the caller states, and whether it is
/// satisfiable is checked where the process is spawned.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum StdioSelection {
    /// Capture the child's output through pipes (the SDK's `StdioMode::Pipes`).
    /// Every pre-P3.4 session ran this way, and it is the only shape where the
    /// supervisor has the child's bytes to print, audit or re-emit.
    #[default]
    Capture,
    /// The child inherits this process's stdin/stdout/stderr
    /// (`StdioMode::Inherit`): a TTY exactly when we have one, no streams to tee,
    /// and the wait-only launch path.
    Inherit,
}

impl StdioSelection {
    /// The SDK mode this selection asks the backend to wire.
    pub fn mode(self) -> StdioMode {
        match self {
            Self::Capture => StdioMode::Pipes,
            Self::Inherit => StdioMode::Inherit,
        }
    }

    /// Whether the launch captures the child's output itself.
    ///
    /// The load-bearing half of the choice: with inherited stdio `take_stdout`
    /// returns `None` and there is nothing to read, so the launch must not build
    /// a capture path over it (a reader thread over a stream that never exists).
    pub fn captures_output(self) -> bool {
        matches!(self, Self::Capture)
    }
}

/// One session, as the supervisor resolved it. Plain data — deliberately free
/// of SDK types so the mapping can be tested without the runtime.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct MxcSessionInput {
    /// The workload's command line, verbatim. [`build_request`] does not hand it
    /// to the container directly: it becomes the argument of the wrapper
    /// launcher ([`launcher_command`]).
    pub command: String,
    /// Initial working directory; `None` leaves the backend default.
    pub working_directory: Option<String>,
    /// Environment entries the caller wants propagated. Host proxy variables
    /// are removed by [`build_request`] — see [`BLOCKED_ENV_KEYS`].
    pub environment: Vec<(String, String)>,
    pub filesystem: MxcFilesystemInput,
    pub network: MxcNetworkInput,
    /// Wall-clock bound for the whole session, in milliseconds. `None` — and
    /// `Some(0)` — means **no deadline**: the SDK maps a zero timeout to
    /// `INFINITE` (`mxc_common::script_runner::get_timeout_milliseconds`).
    ///
    /// Since P2.1 the supervisor never ships this value as-is: [`MxcBackend`]
    /// always writes `Some(budget.timeout_ms())` from its own [`SessionBudget`],
    /// because a caller-supplied `None` here is how an unbounded session gets
    /// shipped by accident. [`build_request`] still passes the field through
    /// unchanged (it is a pure mapping), so the guarantee lives where the launch
    /// is decided — see [`MxcBackend::request_for`].
    pub timeout_ms: Option<u32>,
    /// How the child's standard streams are wired (P3.4). `Capture` by default,
    /// which is what every pre-P3.4 session had; `Inherit` is what an interactive
    /// workload needs and what the CLI's stdio decision selects when this process
    /// has a terminal.
    pub stdio: StdioSelection,
}

impl fmt::Debug for MxcSessionInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Hand-written for the same reason as [`MxcNetworkInput`]'s: whoever
        // formats a session input must see `<redacted>` where the proxy token
        // would be, and that guarantee should not rest on a derived impl
        // delegating to the field's.
        f.debug_struct("MxcSessionInput")
            .field("command", &self.command)
            .field("working_directory", &self.working_directory)
            .field("environment", &self.environment)
            .field("filesystem", &self.filesystem)
            .field("network", &self.network)
            .field("timeout_ms", &self.timeout_ms)
            .field("stdio", &self.stdio)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// P1.3 + P3.4: filesystem policy (the workspace and the operator's grants)
// ---------------------------------------------------------------------------

/// Profile subdirectories that hold credentials, denied for every MXC launch.
///
/// `.ssh` (keys and known_hosts), `.aws`/`.azure` (credential files) and
/// `.gnupg` (secret keyrings) are the four a compromised workload would read
/// first. They are denied as a path list; the rest of the profile stays
/// readable, because a workload that cannot read `%APPDATA%` at all is not a
/// workload anyone can run.
pub const PROFILE_SECRET_DIRS: [&str; 4] = [".ssh", ".aws", ".azure", ".gnupg"];

/// Build the launch's filesystem grants from policy (plan P1.3).
///
/// * `readwrite_paths` is the session's working directory **plus** the caller's
///   explicit `writable_extra` grants (P3.4: the profile's `filesystem.allow`
///   and every `--allow <path>` that is not `:read`). The grant set stays closed
///   — the workspace, what the operator named, and the launcher's directory —
///   and nothing is derived from a convention or from the environment.
/// * `cwd` and `launcher` are made absolute first ([`absolute_path`]). A relative
///   spelling keys as itself (`tools\sandbox`, or empty for `.`), which no
///   absolute deny can cover, so resolving here is what keeps the guard below
///   meaningful; a spelling that cannot be resolved is
///   [`RequestError::PathNotAbsolute`], not a guess.
/// * `readonly_paths` is the caller's declared read-only grants, as declared,
///   **plus** the launcher's directory ([`ensure_launcher_grant`]). It is added
///   here and not only in [`build_request`] because the deny filter below needs
///   the complete grant set: a deny that covers the launcher's directory is as
///   self-contradictory as one that covers the workspace, and in practice the
///   launcher lives under the user profile — so an operator deny of
///   `%USERPROFILE%` or `C:\Users\<user>\tools` hits it.
/// * `denied_paths` is [`PROFILE_SECRET_DIRS`] under `profile_dir` plus the
///   configured deny list, deduplicated case-insensitively.
///
/// **A deny that contains a grant fails the launch.** MXC filesystem policy is
/// additive grants, so a deny that is an ancestor of a grant (or the same path)
/// cannot be honoured: shipping it produces a launch that denies its own
/// workspace or launcher, and *dropping* it — the previous behaviour — silently
/// un-denied everything else under it. Denying `%USERPROFILE%` with the
/// workspace at `%USERPROFILE%\work` discarded the whole profile deny, leaving
/// `Documents`, `Downloads`, `AppData` and every browser profile readable inside
/// the container with no warning, no error and no audit trace. This returns
/// [`RequestError::DenyCoversGrant`] naming **both** paths and telling the
/// operator to deny the specific subdirectories instead — no silent narrowing,
/// no drop.
///
/// A deny that is a *descendant* of a grant (workspace `%USERPROFILE%` with
/// `%USERPROFILE%\.ssh` denied) is the intended, expressible case and is kept.
///
/// **The one deny no configuration can remove:** the four
/// [`PROFILE_SECRET_DIRS`] are added for every launch and are *not* the
/// operator's configuration. A workspace that lives inside one of them
/// (`%USERPROFILE%\.ssh\work`, say) is therefore unlaunchable with no
/// override at all, and the refusal names `.ssh` — a path the operator never
/// wrote. It is not their configuration to fix: the workspace has to live
/// elsewhere.
///
/// **Known caveat, recorded rather than "fixed":** MXC filesystem policy is
/// *additive grants*, so system directories stay readable (`C:\Windows\win.ini`
/// was readable inside the container in the ADR-0004 spike). Denying them would
/// break every workload that needs System32, so the caveat is documented and
/// measured (see the live filesystem leg) instead of being papered over with a
/// deny list that cannot work.
pub fn filesystem_policy(
    cwd: &Path,
    writable_extra: &[PathBuf],
    readonly: &[String],
    configured_denies: &[String],
    profile_dir: Option<&Path>,
    launcher: &Path,
) -> Result<MxcFilesystemInput, RequestError> {
    // Both paths enter the deny-versus-grant comparison, and a relative spelling
    // (`tools\sandbox`, or empty for `.`) has no key an absolute deny could
    // cover: resolve them here, at the boundary, before anything is compared.
    let cwd = absolute_path("workspace directory", cwd)?;
    let launcher = absolute_path("launcher", launcher)?;
    let mut filesystem = MxcFilesystemInput {
        readwrite_paths: vec![cwd.display().to_string()],
        readonly_paths: readonly.to_vec(),
        denied_paths: Vec::new(),
    };
    // P3.4: the operator's EXPLICIT writable grants join the workspace. Before
    // P3.4 any second writable grant was refused by name (P3.0 decision 9),
    // which made every tool that keeps state in the profile — opencode's
    // `~/.local/share/opencode`, `~/.cache/opencode`, `~/.config/opencode` —
    // unrunnable under this backend. The posture therefore becomes "the
    // workspace plus what the operator named", not "the workspace alone": the
    // grants are still a closed set, still reviewed, and still subject to every
    // deny below (the four credential directories are denies for every launch,
    // and a deny that covers one of these grants REFUSES the session rather than
    // being dropped).
    //
    // Resolved here for the same reason `cwd` is: a relative spelling keys as
    // itself, and an absolute deny could not cover it.
    let workspace = path_key(&filesystem.readwrite_paths[0]);
    for grant in writable_extra {
        let resolved = absolute_path("writable grant", grant)?;
        let text = resolved.display().to_string();
        let key = path_key(&text);
        // The workspace is already granted; duplicating it would make the
        // request say the same thing twice.
        if key == workspace
            || filesystem
                .readwrite_paths
                .iter()
                .any(|kept| path_key(kept) == key)
        {
            continue;
        }
        filesystem.readwrite_paths.push(text);
    }
    // Before any deny is filtered, never after: the launcher grant is a grant
    // like any other, and `build_request` would otherwise insert it into a
    // request whose deny list was filtered against a grant set missing it.
    ensure_launcher_grant(&mut filesystem, &launcher);

    // F-11: the launcher is executed by the NEXT session, on the host. A writable
    // grant that contains it therefore hands the workload a way to run code with the
    // supervisor's rights - the escalation the wrapper exists to avoid.
    for grant in &filesystem.readwrite_paths {
        let g = path_key(grant);
        let l = path_key(&launcher.display().to_string());
        if l == g || l.starts_with(&format!("{g}\\")) {
            return Err(RequestError::GrantCoversLauncher {
                grant: grant.clone(),
                launcher: launcher.display().to_string(),
            });
        }
    }

    let grants = granted_paths(&filesystem);
    if let Some(profile) = profile_dir {
        for dir in PROFILE_SECRET_DIRS {
            push_deny(
                &mut filesystem.denied_paths,
                &profile.join(dir).display().to_string(),
                &grants,
            )?;
        }
    }

    // The tool's own control plane, denied for every launch. `.saife` holds the
    // plugin manifests whose `command` runs host-side and the learned policy; the
    // sibling `%LOCALAPPDATA%\saife` holds the audit log and the signing key. A
    // profile that grants `$HOME` would otherwise let the workload rewrite a plugin
    // that executes outside the sandbox on the next run.
    for dir in crate::profile::builtin_deny_dirs() {
        let name = dir.file_name().and_then(|s| s.to_str()).unwrap_or_default();
        if PROFILE_SECRET_DIRS.contains(&name) {
            continue; // already denied above
        }
        push_deny(
            &mut filesystem.denied_paths,
            &dir.display().to_string(),
            &grants,
        )?;
    }
    for candidate in configured_denies {
        push_deny(&mut filesystem.denied_paths, candidate, &grants)?;
    }
    Ok(filesystem)
}

/// Every path the request grants, writable grants first.
fn granted_paths(filesystem: &MxcFilesystemInput) -> Vec<String> {
    let mut grants = filesystem.readwrite_paths.clone();
    grants.extend(filesystem.readonly_paths.iter().cloned());
    grants
}

/// The first grant that `deny` is equal to, or an ancestor of.
fn grant_contained_by_deny<'a>(deny: &str, grants: &'a [String]) -> Option<&'a String> {
    grants.iter().find(|grant| covers(deny, grant))
}

/// Append one denied path, refusing one that contains a grant.
///
/// Empty entries and case-folded duplicates are ignored. A deny that is an
/// ancestor of (or equal to) a grant is [`RequestError::DenyCoversGrant`] — a
/// named refusal, never the silent drop that used to un-deny a whole tree.
fn push_deny(
    denied: &mut Vec<String>,
    candidate: &str,
    grants: &[String],
) -> Result<(), RequestError> {
    let candidate = candidate.trim();
    if candidate.is_empty() {
        return Ok(());
    }
    if let Some(grant) = grant_contained_by_deny(candidate, grants) {
        return Err(RequestError::DenyCoversGrant {
            deny: candidate.to_string(),
            grant: grant.clone(),
        });
    }
    if denied
        .iter()
        .any(|kept| path_key(kept) == path_key(candidate))
    {
        return Ok(());
    }
    denied.push(candidate.to_string());
    Ok(())
}

// ---------------------------------------------------------------------------
// Guardrail 1: post-launch proxy proof (hard gate, two legs)
// ---------------------------------------------------------------------------

/// The supervisor's own count of what its proxy saw for one launch epoch.
///
/// **`probes` is the evidence** (ADR-0004 guardrail 1, amended 2026-10-22): the
/// wrapper's own `GET /sandbox/probe` to this listener, sent before the payload
/// starts. The two counters below it are **recorded detail** — what the session
/// actually did over the proxy — and no longer decide the gate.
///
/// * `accepted` counts **proxy consultations** — connections the proxy handled
///   as a proxy (`CONNECT`, or an absolute-form request naming another origin).
/// * `tunnels` counts those whose origin dial succeeded (a real `200 Connection
///   Established`, or a plain-HTTP forward whose upstream came up). The spike
///   proved that a proxy 502/403 gives `accepted >= 1, tunnels == 0`, and that a
///   container that never reached the proxy gives `accepted == 0` while still
///   exiting 0 with `warnings: []`.
///
/// Why they cannot be the gate (2026-10-22): both are **workload** events. A
/// session whose workload makes no request at all — an intent roundtrip, a
/// `cmd /c echo`, a raw 407 probe — produces `{accepted: 0, tunnels: 0}` while
/// its proxy path is perfectly healthy, so a `tunnels >= 1` rule refused
/// sessions that did nothing wrong (four P3.1 scenarios: S-55, S-77, S-86,
/// S-91). A gate must prove the PATH, never the workload's use of it.
///
/// Deliberately *not* counted as either: a direct, origin-form request to one of
/// our own loopback endpoints (the D-4 intent endpoints, and the probe itself).
/// Serving an endpoint is not a proxy consultation, and counting it would make
/// [`ProofExpectation::MustBeAbsent`] unsatisfiable for exactly the sessions it
/// exists for.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ProxyProof {
    pub accepted: u64,
    pub tunnels: u64,
    /// Pre-flight probes the WRAPPER reported to this listener's own control
    /// plane in the epoch (`GET /sandbox/probe`).
    ///
    /// This is guardrail 1's evidence (amended 2026-10-22): the supervisor asks
    /// the child's side to prove its path to *this* listener BEFORE the payload
    /// starts, and records the answer where the workload cannot reach it. A
    /// workload-derived count can never distinguish "made no request" from
    /// "could not make any"; a probe can, because it runs whether or not the
    /// workload ever opens a socket.
    ///
    /// `accepted` and `tunnels` stay recorded as coverage — they say what the
    /// session actually did over the proxy — but they no longer decide.
    pub probes: u64,
    /// Refusals this listener answered **without this run's credential** in the
    /// epoch (`no_token` + `foreign_token`).
    ///
    /// The second half of guardrail 1's evidence (P3.2a, amended 2026-10-22): the
    /// probe proves the child's PATH works, and this counter proves that nothing
    /// in the container was left *trying without* the credential. A GUI /
    /// system-proxy client (WinINet, Windows PowerShell 5.1 — measured in P1.5 and
    /// P1.8) reaches the proxy, never sends a `Proxy-Authorization`, and gets `407`
    /// for ever: `probes == 1, tunnels == 0` used to PASS such a session while the
    /// application had no egress at all.
    ///
    /// Read together with `accepted`, never alone: a .NET 8 / pwsh 7 managed
    /// client legitimately makes ONE credential-less attempt per connection and
    /// authenticates after the `407` challenge (`Proxy-Authenticate: Basic` is
    /// load-bearing), so `unauthenticated > 0` with an authenticated consultation
    /// is the handshake working, not a client that cannot use the proxy.
    pub unauthenticated: u64,
}

/// What guardrail 1 must observe for this launch (plan decision D3).
///
/// Both legs are hard gates, and the caller **must** supply the right one:
///
/// * [`ProofExpectation::Required`] for a network session (a proxy port is
///   configured): the wrapper's pre-flight probe must have reached THIS
///   listener in the launch's epoch. Derive it with
///   [`ProofExpectation::for_network`].
/// * [`ProofExpectation::MustBeAbsent`] for a blocked / proxy-less session: the
///   proxy must never have been consulted, which is the only positive evidence
///   that a no-network session really did not go out.
///
/// Choosing the wrong leg is itself a hard failure — never a skipped check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofExpectation {
    /// `probes >= 1`: the child's path to the listener works (ADR-0004
    /// guardrail 1, amended 2026-10-22). `accepted`/`tunnels` are recorded, not
    /// required — they are workload events.
    Required,
    /// `accepted == 0 && tunnels == 0`.
    MustBeAbsent,
}

impl ProofExpectation {
    /// The leg a session with this network posture must supply: `Required` when
    /// a proxy port is configured, `MustBeAbsent` when it is not.
    pub fn for_network(proxy_port: Option<u16>) -> Self {
        match proxy_port {
            Some(_) => Self::Required,
            None => Self::MustBeAbsent,
        }
    }
}

/// Why guardrail 1 refused a launch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardError {
    /// No proof source was supplied, so the launch cannot be proven at all.
    MissingProofSource,
    /// `Required` was requested for a session with no proxy port: no launch can
    /// ever satisfy it, so it is refused before the child starts.
    RequiredWithoutProxy,
    /// `MustBeAbsent` was requested but the proxy *was* consulted for this
    /// launch — a session that was supposed to stay offline went out.
    ProxyConsultedUnexpectedly,
    /// The wrapper's pre-flight probe never reached this listener in this
    /// launch's epoch: the child's path to the proxy — a live loopback
    /// listener that accepts the session's own credential — was never proven.
    ProbeUnmet,
    /// The probe proved the path, but **nothing in this epoch ever
    /// authenticated** and the listener answered credential-less (or
    /// foreign-credential) attempts instead (P3.2a).
    ///
    /// This is the silent-misconfiguration the probe amendment re-opened: a
    /// GUI / system-proxy client (WinINet, Windows PowerShell 5.1 — P1.5, P1.8)
    /// reaches the listener and gets `407` for ever without ever sending a
    /// credential, so the session has no egress while every other signal in the
    /// launch says it worked. Distinct from [`GuardError::ProbeUnmet`]: there the
    /// path is unproven, here the path is proven and the *workload's client stack*
    /// cannot use it.
    WorkloadCannotAuthenticate,
}

impl GuardError {
    /// The token written to the audit as `reason`. The five causes exist because
    /// they mean different things to whoever reads the log afterwards - a missing
    /// proof source is an operator error, `WorkloadCannotAuthenticate` is a client
    /// stack that cannot use a proxy at all - and collapsing them into
    /// `proxy_proof_unmet` threw that away in the one artifact that outlives the
    /// process.
    pub fn audit_reason(&self) -> &'static str {
        match self {
            GuardError::MissingProofSource => "proxy_proof_unavailable",
            GuardError::RequiredWithoutProxy => "proxy_required_without_proxy",
            GuardError::ProxyConsultedUnexpectedly => "proxy_consulted_unexpectedly",
            GuardError::ProbeUnmet => "proxy_probe_unmet",
            GuardError::WorkloadCannotAuthenticate => "workload_cannot_authenticate",
        }
    }
}

impl fmt::Display for GuardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Self::MissingProofSource => {
                "no proxy proof source: ADR-0004 guardrail 1 requires a post-launch proxy proof \
                 for every MXC launch"
            }
            Self::RequiredWithoutProxy => {
                "guardrail 1: a network session was expected but the request configures no proxy, \
                 so no launch could ever prove the child reached one"
            }
            Self::ProxyConsultedUnexpectedly => {
                "guardrail 1: the proxy was consulted for a session that must never reach it — \
                 the workload is expected to be blocked"
            }
            Self::ProbeUnmet => {
                "guardrail 1: proxy_probe_unmet — the wrapper's pre-flight probe never reached \
                 this listener, so the child's path to the proxy is unproven (dead listener, \
                 blocked loopback, or a credential it does not accept)"
            }
            Self::WorkloadCannotAuthenticate => {
                "guardrail 1: workload_cannot_authenticate — something in the container reached \
                 the proxy without this run credential and nothing in the session ever \
                 authenticated: a client stack that cannot use the proxy (WinINet / system \
                 proxy) or a misconfigured proxy setting, so the workload had no egress; use \
                 --backend appcontainer for those workloads"
            }
        };
        f.write_str(msg)
    }
}

impl std::error::Error for GuardError {}

/// The hard gate, in both legs.
///
/// `Required` demands **two things**: `probes >= 1` — the wrapper's pre-flight
/// probe reached this listener in the epoch — and that no credential-less attempt
/// was left unanswered by an authenticated one (`!(unauthenticated > 0 &&
/// accepted == 0)`). `MustBeAbsent` demands `accepted == 0 && tunnels == 0` (a
/// proxy-less session cannot probe at all: the wrapper only probes when
/// `--proxy-port` names a listener). Anything else fails the launch.
///
/// **Why `Required` no longer looks at `accepted`/`tunnels` (2026-10-22).**
/// Both are produced by the workload, so a gate keyed on them answers "did the
/// workload use the proxy?" and reads a no-op workload as a broken path — S-55,
/// S-77, S-86 and S-91 were refused for exactly that. The probe is produced by
/// the wrapper before the payload, so its absence means the path itself is
/// broken: dead listener, blocked loopback, or a credential this listener does
/// not accept. The property the old rule was reaching for — *this* listener,
/// *this* run, *this* launch's window — is preserved: the probe is token-gated
/// like every control-plane request and counted per epoch.
///
/// **Why the credential leg exists (P3.2a, 2026-10-22).** The probe alone proved
/// the child *could* reach the listener, not that the workload *used* it with the
/// credential. A GUI / system-proxy client (WinINet, Windows PowerShell 5.1 —
/// P1.5/P1.8) is forced to this listener by the container's egress rules, never
/// sends a `Proxy-Authorization`, and gets `407` for ever: `probes == 1` passed
/// such a session while the application silently had no egress. The listener
/// already counts those refusals (`unauthenticated`), so the gate reads them with
/// `accepted`: an epoch where something authenticated is fine (that is the
/// `407`-then-retry handshake every supported managed client uses), an epoch where
/// the only contact was refusals is `workload_cannot_authenticate`.
///
/// **What remains OUTSIDE this gate.** (1) A workload that never attempts
/// anything is unproven either way — the gate detects "tried and could not
/// authenticate", never "chose not to use the network". (2) A MIXED session (one
/// client that authenticates plus a GUI stack that cannot) is not caught by this
/// leg, because one authenticated consultation satisfies it; catching that needs a
/// per-client signal the listener does not have (peer SID / WFP attestation).
pub fn verify_proxy_proof(
    proof: ProxyProof,
    expectation: ProofExpectation,
) -> Result<(), GuardError> {
    match expectation {
        ProofExpectation::Required => {
            // Leg 1: the probe. `accepted`/`tunnels` are carried in the same struct
            // as coverage and printed in every `EVIDENCE` line, but a workload that
            // made no request must not be able to fail this gate.
            if proof.probes == 0 {
                return Err(GuardError::ProbeUnmet);
            }
            // Second half of the evidence (P3.2a): the probe proves the PATH, this
            // proves nothing in the container was left trying WITHOUT the
            // credential. A GUI / system-proxy client (WinINet, Windows PowerShell
            // 5.1) reaches the listener, gets `407` for ever and never
            // authenticates - `probes == 1, tunnels == 0` used to PASS it while the
            // application had no egress at all.
            //
            // Deliberately NOT `unauthenticated == 0`: a .NET 8 / pwsh 7 managed
            // client makes one credential-less attempt per connection and
            // authenticates after the `407` challenge (P1.8 - the challenge is
            // load-bearing), so that shape has `unauthenticated > 0` AND
            // `accepted > 0` and must pass. `accepted == 0` is the discriminator:
            // nothing in this epoch ever used the credential, so the only contact
            // was a refusal.
            if proof.unauthenticated > 0 && proof.accepted == 0 {
                return Err(GuardError::WorkloadCannotAuthenticate);
            }
            Ok(())
        }
        ProofExpectation::MustBeAbsent => {
            if proof.accepted != 0 || proof.tunnels != 0 {
                return Err(GuardError::ProxyConsultedUnexpectedly);
            }
            Ok(())
        }
    }
}

/// Where the launch path gets its proof from.
///
/// Implemented by the per-session proxy: [`begin_launch`] opens an attribution
/// epoch *before* the child starts, [`proof`] reports the counters for that
/// epoch, and [`close_launch`] closes the window. The launch path calls
/// `close_launch` exactly once per `begin_launch`, on the success and the error
/// path alike (see [`EpochGuard`]), so a `v1::run` error cannot leave an epoch
/// open.
///
/// `Send + Sync`: the epoch is opened on the session's thread while the counters
/// are written from the proxy's I/O threads, and the supervisor's proxy runtime
/// will hold this across `await` points.
///
/// # Counting rules (normative — guardrail 1 is only as honest as these)
///
/// `probes` counts **pre-flight probes**: an authenticated, origin-form
/// `GET /sandbox/probe` this listener served inside the epoch. It is the gate's
/// evidence (see [`verify_proxy_proof`]); a foreign or absent credential answers
/// `407` before routing and counts nowhere.
///
/// `accepted` counts **proxy consultations** only: a `CONNECT` whose target
/// parsed, or an absolute-form request naming another origin, that reached this
/// listener *and authenticated with the session token*. Not counted: a 407 or a
/// malformed request line (no proof the session's proxy path works), and — the
/// case that matters — an **origin-form** request to one of our own loopback
/// endpoints (the D-4 intent API). Serving an endpoint is not a proxy
/// consultation, and counting it would make [`ProofExpectation::MustBeAbsent`]
/// unsatisfiable for exactly the sessions it exists for.
///
/// `tunnels` means **upstream established**, never "a 200 was written": the
/// `200 Connection Established` is sent only after the upstream dial succeeded,
/// and a **plain-HTTP forward** counts as soon as its own upstream connection
/// comes up. This is why the definition is not "CONNECT answered 200": a session
/// that only ever makes plain-HTTP requests would otherwise report
/// `accepted >= 1, tunnels == 0` and fail [`ProofExpectation::Required`]
/// spuriously, i.e. the gate would reject a working session — the worst possible
/// false negative for a hard gate.
///
/// Both counters are per epoch, so a launch cannot borrow another launch's
/// traffic; attribution is by the epoch that was active when the connection was
/// classified.
///
/// [`LaunchCounters`](crate::net::proxy::LaunchCounters) in `src/net/proxy.rs`
/// is the real implementation: the supervisor's own listener, counting what it
/// served.
///
/// One listener per run, one token per run (P1.4): the run's own
/// [`RunToken`](crate::net::token::RunToken) is the only credential its listener
/// accepts, and the epoch it opens while the child runs is the only window its
/// traffic can be counted in. A second launch on the same listener is refused by
/// [`begin_launch`](ProxyProofSource::begin_launch), never merged into the first.
///
/// [`begin_launch`]: ProxyProofSource::begin_launch
/// [`proof`]: ProxyProofSource::proof
/// [`close_launch`]: ProxyProofSource::close_launch
pub trait ProxyProofSource: Send + Sync {
    /// Open an attribution epoch and return its id.
    ///
    /// Refuses with [`EpochAlreadyOpen`] when an epoch is already open. One
    /// listener serves one run's token (P1.4), so a second open window means two
    /// launches sharing one attribution epoch: the older launch's traffic would
    /// land in the newer window and either launch could satisfy its guardrail
    /// with the other's consultation. An implementation must refuse — not merge,
    /// not reset, not silently move `active`.
    fn begin_launch(&self) -> Result<u64, EpochAlreadyOpen>;
    /// Counters for the sessions accepted in `epoch`.
    fn proof(&self, epoch: u64) -> ProxyProof;
    /// Close `epoch`'s attribution window. Called exactly once per
    /// [`begin_launch`](ProxyProofSource::begin_launch).
    fn close_launch(&self, epoch: u64);

    /// Time this source's dialogs cost since the current launch began (P2.1): one
    /// credit per LEADER, and reset when a launch opens its epoch — so a listener
    /// that serves several sequential launches attributes to each one only its own
    /// prompt time. The launch path also takes a **delta** around the run, so the
    /// reset and the delta agree instead of depending on each other.
    ///
    /// Default zero: a proof source that is not a proxy listener has no prompt
    /// path, and zero is the honest answer — it makes a kill attribute to the
    /// workload or handshake term only, never to a prompt that did not happen. The
    /// real implementation is the listener's own measurement, so a session that
    /// died waiting for a dialog says so.
    fn prompt_wait(&self) -> Duration {
        Duration::ZERO
    }
}

/// The real proof source: the supervisor's proxy listener, in
/// `src/net/proxy.rs`.
///
/// The counters are the listener's own, shared with its handler tasks, so a
/// launch is proofed by the very socket the child was told to use
/// (`runtimeConfig.networkProxy`) — never by a lookalike listener or a second
/// count ("two sources of truth" is how a guardrail starts lying).
impl ProxyProofSource for crate::net::proxy::LaunchCounters {
    fn begin_launch(&self) -> Result<u64, EpochAlreadyOpen> {
        self.begin_epoch()
    }

    fn prompt_wait(&self) -> Duration {
        crate::net::proxy::LaunchCounters::prompt_wait(self)
    }

    fn proof(&self, epoch: u64) -> ProxyProof {
        match self.counters(epoch) {
            Some(counters) => ProxyProof {
                accepted: counters.consultations,
                tunnels: counters.upstream_established,
                probes: counters.probes,
                unauthenticated: counters.unauthenticated,
            },
            // An unknown epoch has no counters. Zeros make the gate fail closed
            // instead of reporting traffic that belongs to someone else.
            None => ProxyProof::default(),
        }
    }

    fn close_launch(&self, epoch: u64) {
        // A close for an epoch that is not the active one is a no-op: the
        // listener must not stop counting for a launch that is still running.
        let _ = self.close_epoch(epoch);
    }
}

/// Owns one epoch's lifetime: whichever way the launch leaves, the epoch is
/// closed.
///
/// The guard is the structural part of D4 — the alternative (a bare
/// `begin_launch` followed by a `?` on `v1::run`) abandons the window on every
/// error path.
struct EpochGuard<'a> {
    source: &'a dyn ProxyProofSource,
    epoch: u64,
    closed: bool,
}

impl<'a> EpochGuard<'a> {
    /// Open this launch's epoch, or refuse the launch.
    ///
    /// The refusal happens before the body runs, so an overlapping launch never
    /// spawns a container and never touches the open window.
    fn open(source: &'a dyn ProxyProofSource) -> Result<Self, EpochAlreadyOpen> {
        Ok(Self {
            source,
            epoch: source.begin_launch()?,
            closed: false,
        })
    }

    /// Read the epoch's counters and close the window. The counters are frozen
    /// at this point, so traffic that arrives later cannot satisfy this launch.
    fn finish(&mut self) -> ProxyProof {
        let proof = self.source.proof(self.epoch);
        self.close();
        proof
    }

    fn close(&mut self) {
        if !self.closed {
            self.closed = true;
            self.source.close_launch(self.epoch);
        }
    }
}

impl Drop for EpochGuard<'_> {
    fn drop(&mut self) {
        // `drop` also runs while a panic unwinds, and a panic that escapes a
        // `Drop` *during* an unwind aborts the whole process. `close_launch` is
        // caller-supplied, so a panicking close must not turn a recoverable
        // launch failure into an abort. Nothing can be reported from here: the
        // `closed` flag is already set when the call panics, so the worst case is
        // an epoch window the source never released — a leak, never a false
        // proof, because the proof is read before `close()` is called.
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.close()));
    }
}

/// Run `body` under a fresh launch epoch and return its value with the epoch's
/// proof. The epoch is opened before `body` runs and closed afterwards whether
/// `body` succeeded or failed.
fn run_in_epoch<T>(
    source: &dyn ProxyProofSource,
    body: impl FnOnce() -> Result<T, MxcError>,
) -> Result<(T, ProxyProof), MxcError> {
    let mut guard = EpochGuard::open(source).map_err(MxcError::Concurrency)?;
    // No `?` here: the epoch must be closed and its proof read before the error
    // is propagated.
    let result = body();
    let proof = guard.finish();
    result.map(|value| (value, proof))
}

// ---------------------------------------------------------------------------
// Guardrail 2: per-session tier record
// ---------------------------------------------------------------------------

/// The isolation tier that was actually dispatched, plus its provenance.
///
/// `tier_source` is `"probe"` when `v1::probe` named a tier and `"unavailable"`
/// when it could not (probe error or no tier). It is never the backend ceiling:
/// ADR-0004 forbids recording a ceiling as if it were the dispatched tier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TierRecord {
    pub tier: Option<String>,
    pub tier_source: &'static str,
    /// Verbatim from the probe: `None` when the probe did not state it. Never
    /// narrowed to `false`, which would assert something the probe declined to
    /// assert.
    pub needs_dacl_augmentation: Option<bool>,
}

/// `tier_source` when `v1::probe` named the dispatched tier.
pub const TIER_SOURCE_PROBE: &str = "probe";
/// `tier_source` when the probe could not name a tier.
pub const TIER_SOURCE_UNAVAILABLE: &str = "unavailable";

/// The subset of `v1::ProbeOutput` guardrail 2 consumes.
///
/// Splitting it out keeps the mapping unit-testable without fabricating the
/// SDK's full probe-fact set.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ProbeView {
    pub tier: Option<&'static str>,
    pub needs_dacl_augmentation: Option<bool>,
}

impl ProbeView {
    pub fn from_probe(probe: &v1::ProbeOutput) -> Self {
        Self {
            tier: probe.tier,
            needs_dacl_augmentation: probe.needs_dacl_augmentation,
        }
    }
}

/// Map a probe result to a [`TierRecord`] (pure).
pub fn tier_record(view: ProbeView) -> TierRecord {
    TierRecord {
        tier: view.tier.map(str::to_string),
        // Never a backend ceiling: a probe that names no tier is recorded as
        // unknown, so the record cannot overstate what was dispatched.
        tier_source: if view.tier.is_some() {
            TIER_SOURCE_PROBE
        } else {
            TIER_SOURCE_UNAVAILABLE
        },
        // Carried through as-is: a probe that says nothing is recorded as
        // "unknown", not as "no augmentation needed".
        needs_dacl_augmentation: view.needs_dacl_augmentation,
    }
}

/// Probe the **exact** request that is about to be launched.
///
/// Never called with a lookalike or a copy: `v1::probe` is the only way to learn
/// which tier *this* request dispatches to, and a tier is observable after
/// dispatch only (there is no `require_tier` at 1.0.1).
pub fn probe_tier(request: &ExecutionRequest) -> Result<TierRecord, MxcError> {
    // `v1::probe` is `prepare_request` followed by exactly this call, so probing
    // the already-normalized request is the same adjudication — and it is the only
    // way to probe a request that is not a `ContainerRequest`. The P3.4 stdio
    // change forced the normalized model: `StdioMode` exists only on its spawn
    // path, and the SDK exposes no `ContainerRequest` → `ExecutionRequest`
    // conversion.
    let probe = mxc_sdk::mxc_engine::probe_execution_request(Some(request)).map_err(|error| {
        MxcError::Sdk(v1::Error::new(
            v1::ErrorCode::BackendError,
            format!("probing the sandbox tier failed: {error}"),
        ))
    })?;
    Ok(tier_record(ProbeView::from_probe(&probe)))
}

impl TierRecord {
    /// This record in the **audit leaf's** vocabulary (P2.3).
    ///
    /// The adapter exists so the leaf cannot invent a tier or a source: every
    /// value here comes from [`tier_record`], which never reports a backend
    /// ceiling as the dispatched tier.
    pub fn audit_facts(&self) -> crate::audit::session_start::TierFacts {
        crate::audit::session_start::TierFacts {
            tier: self.tier.clone(),
            tier_source: Some(self.tier_source),
            needs_dacl_augmentation: self.needs_dacl_augmentation,
        }
    }
}

/// Which tier a session **requires** (ADR-0004 guardrail 2's hard half).
///
/// Recording the tier is the soft half: it makes a degraded tier visible after
/// the fact. This is the hard half, and the ADR's prototype evidence states the
/// product rule — *a wrong tier is a refused session with no CONNECT leaves*.
/// The check therefore runs before the launch epoch opens, so a refused session
/// cannot have a child that reaches the proxy, and therefore cannot have a
/// CONNECT leaf.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TierExpectation {
    /// No requirement stated: record whatever dispatches. Used by probes,
    /// measurements and tests — never by the product session path.
    Recorded,
    /// Require exactly this tier. A different tier, or a probe that named none,
    /// refuses the session.
    Exactly(&'static str),
}

/// The tier a networked MXC session requires.
///
/// `base-container` is the PSEC tier the migration exists for. The alternative,
/// `appcontainer-dacl`, is the degraded tier: the SDK's AppContainer runner, which
/// applies the same Win32k mitigation and needs the host DACLs augmented — i.e.
/// the AppContainer backend's own posture, not a better one. Silently running a
/// session on it would ship the migration's whole UAC gain away without saying so.
pub const REQUIRED_TIER: &str = "base-container";

/// Guardrail 2 refused a launch: the dispatched tier is not the required one.
///
/// Carries the observed tier and its source because the refusal is only
/// actionable if it says what was dispatched instead — and `None`/`unavailable`
/// must read as "the probe could not say", never as "no tier".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TierMismatch {
    /// The tier this session required.
    pub expected: &'static str,
    /// What the probe of the exact request reported (`None`: it named none).
    pub observed: Option<String>,
    /// [`TIER_SOURCE_PROBE`] or [`TIER_SOURCE_UNAVAILABLE`].
    pub source: &'static str,
}

impl fmt::Display for TierMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let observed = match &self.observed {
            Some(tier) => format!("`{tier}`"),
            None => "no tier".to_string(),
        };
        write!(
            f,
            "guardrail 2: this session requires tier `{}`, but the probe of the exact request \
             reported {observed} (tier_source `{}`) — refused before launch, so the workload \
             never ran\n  \
             What to do: this host's MXC probe named no dispatcheable tier, so the `mxc` \
             backend cannot run a session here. Use `--backend appcontainer`, or run \
             `saife setup --check-only` for the host report and the exact probe verdict.",
            self.expected, self.source
        )
    }
}

impl std::error::Error for TierMismatch {}

/// Apply guardrail 2's hard half to a probed tier. Pure.
pub fn verify_tier(tier: &TierRecord, expectation: TierExpectation) -> Result<(), TierMismatch> {
    let TierExpectation::Exactly(expected) = expectation else {
        return Ok(());
    };
    // `None` is refused rather than waved through: a requirement that cannot be
    // shown to have been met is not met, and "the probe was silent" is exactly
    // the case where a degraded tier would slip past a literal `!=` check.
    if tier.tier.as_deref() == Some(expected) {
        return Ok(());
    }
    Err(TierMismatch {
        expected,
        observed: tier.tier.clone(),
        source: tier.tier_source,
    })
}

// ---------------------------------------------------------------------------
// Errors and outcome
// ---------------------------------------------------------------------------

/// A request the mapping refuses to build.
///
/// Every case is checked **before** anything is spawned, because each only
/// surfaces later and misleadingly: an empty command reaches the container as a
/// wrapper launch with nothing to start (a bare `126` that looks like a usage
/// error), a command line containing NUL is truncated by `CreateProcessW` at the
/// NUL — the child would run a different command from the one the request is
/// recorded as launching — and a deny that contains a grant cannot be honoured
/// by an additive-grant policy at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestError {
    /// The workload command line is empty (or only whitespace).
    EmptyCommand,
    /// The command line contains a NUL, which the OS treats as its end.
    NulInCommand,
    /// A path that takes part in the deny-versus-grant comparison is empty, or
    /// cannot be made absolute, so it has no key an absolute deny could cover —
    /// the guard would compare nothing and a deny covering the real directory
    /// would ship. Refused rather than guessed: a relative or empty spelling is
    /// exactly how that guard gets voided.
    PathNotAbsolute {
        /// Which input it was: `"workspace directory"` or `"launcher"`.
        what: &'static str,
        /// The spelling that could not be resolved (empty when it was empty).
        path: String,
    },
    /// The session token contains a character that is not URL-safe, so it cannot
    /// be embedded in the proxy URL's `userinfo` without changing which host or
    /// port the child is told to use.
    UnsafeProxyToken,
    /// A `denied_paths` entry is the same path as a grant, or an ancestor of one.
    ///
    /// Filesystem policy is additive grants, so such a deny cannot be expressed:
    /// shipping it denies the request its own workspace or launcher, and
    /// quietly dropping it leaves everything else under the deny readable. The
    /// launch is refused instead, naming both paths.
    ///
    /// **A workspace inside a built-in credential deny cannot be saved by
    /// configuration.** [`filesystem_policy`] also denies the four
    /// [`PROFILE_SECRET_DIRS`] for every launch, and those denies are built in:
    /// no setting removes them. If `deny` is one of them
    /// (`%USERPROFILE%\\.ssh`, `.aws`, `.azure`, `.gnupg`), there is no
    /// override to grant and nothing the operator misconfigured — the workspace
    /// has to live outside it.
    DenyCoversGrant {
        /// The operator-supplied denied path.
        deny: String,
        /// The grant it contains: the workspace, a declared writable grant, a
        /// declared read-only grant, or the launcher's directory.
        grant: String,
    },
    /// The SDK's own contract adapter rejected the assembled request.
    ///
    /// The mapping is a pure function that no longer constructs the normalized
    /// model by hand: it builds the published `1.0.0` one-shot contract and lets
    /// the SDK parse, validate and normalize it. That adapter is the authority on
    /// what a well-formed request is, so its refusal is carried here verbatim
    /// rather than paraphrased — and it is a *request* error, not a launch
    /// failure, because nothing has been spawned.
    InvalidRequest {
        /// The SDK's message, unedited.
        reason: String,
    },
    /// A writable grant contains the launcher binary. The launcher runs in the HOST
    /// session on the NEXT launch (that is the whole wrapper design), so a workload
    /// that can rewrite it is scheduling code to run with the supervisor's rights.
    GrantCoversLauncher { grant: String, launcher: String },
}

impl fmt::Display for RequestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyCommand => f.write_str(
                "the workload command line is empty: there is nothing to start in the container",
            ),
            Self::NulInCommand => f.write_str(
                "the workload command line contains a NUL, which would truncate it at the OS \
                 boundary — the child would run something other than the command named here",
            ),
            Self::UnsafeProxyToken => f.write_str(
                "the session token contains a character outside the URL-unreserved set \
                 (A-Z a-z 0-9 - . _ ~): in the proxy URL's userinfo any other character would \
                 change which host or port the child is told to use",
            ),
            Self::PathNotAbsolute { what, path } if path.is_empty() => write!(
                f,
                "the {what} path is empty: the deny-versus-grant check compares absolute paths, \
                 and an empty spelling matches nothing — any deny that covers the real path \
                 would ship, so name the path explicitly"
            ),
            Self::PathNotAbsolute { what, path } => write!(
                f,
                "the {what} path `{path}` could not be made absolute: the deny-versus-grant \
                 check compares absolute paths, and a relative spelling matches nothing — a \
                 deny that covers the real path would ship, so name an absolute path"
            ),
            Self::DenyCoversGrant { deny, grant } => write!(
                f,
                "denied path `{deny}` contains the granted path `{grant}`: filesystem policy is \
                 additive grants, so this deny cannot be honoured — the container would either \
                 be denied its own grant or, if the deny were dropped, keep everything else \
                 under `{deny}` readable. Deny the specific subdirectory instead of a tree that \
                 contains a grant (for example `{deny}\\Documents` rather than `{deny}`). \
                 If `{deny}` is one of the built-in profile credential denies (`.ssh`, `.aws`, \
                 `.azure`, `.gnupg` under the user profile), no configuration can remove it — \
                 move the workspace outside it"
            ),
            Self::InvalidRequest { reason } => write!(
                f,
                "the sandbox SDK rejected this session's request: {reason}"
            ),
            RequestError::GrantCoversLauncher { grant, launcher } => write!(
                f,
                "writable grant {grant:?} contains the launcher {launcher:?}: the launcher runs \
                 on the host at the next launch, so a workload that can replace it is scheduling \
                 code to run with the supervisor's rights. Narrow the grant."
            ),
        }
    }
}

impl std::error::Error for RequestError {}

/// An MXC launch failure.
#[derive(Debug)]
pub enum MxcError {
    /// Guardrail 1 refused the launch **before the child existed**: no proof
    /// source was supplied, or a `Required` leg was demanded of a session with no
    /// proxy, which no launch could ever satisfy.
    Guard(GuardError),
    /// Guardrail 1 refused a launch that **ran** (P3.0): the child finished and the
    /// listener never proved it reached the proxy. Boxed because the carried
    /// outcome is large, and separate from [`MxcError::Guard`] so the supervisor can
    /// tell "refused, nothing happened" from "refused, and here is what the workload
    /// printed" without inspecting a side channel.
    Unproven(Box<Unproven>),
    /// Guardrail 2 refused the launch: the tier the request dispatched to is not
    /// the tier the session requires (P2.3). Refused before the child started, so
    /// no CONNECT leaf can exist for this session.
    Tier(TierMismatch),
    /// The request could not be built at all: refused before any spawn, with no
    /// container and no epoch.
    Request(RequestError),
    /// The SDK refused the request or the wait failed.
    Sdk(v1::Error),
    /// A launch was refused because the listener already had an open epoch:
    /// two launches would share one attribution window (P1.4). Nothing was
    /// spawned and the open window was not touched.
    Concurrency(EpochAlreadyOpen),
}

impl fmt::Display for MxcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Guard(e) => write!(f, "{e}"),
            // Same text as the pre-run refusal: the leg that failed is what the
            // operator needs to read, and the message must not change shape
            // because the refusal happened later.
            Self::Unproven(e) => write!(f, "{}", e.error),
            Self::Tier(e) => write!(f, "{e}"),
            Self::Request(e) => write!(f, "{e}"),
            Self::Sdk(e) => write!(f, "mxc-sdk: {e}"),
            Self::Concurrency(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for MxcError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Guard(e) => Some(e),
            Self::Unproven(e) => Some(&e.error),
            Self::Tier(e) => Some(e),
            Self::Request(e) => Some(e),
            Self::Sdk(e) => Some(e),
            Self::Concurrency(e) => Some(e),
        }
    }
}

impl From<GuardError> for MxcError {
    fn from(e: GuardError) -> Self {
        Self::Guard(e)
    }
}

impl From<TierMismatch> for MxcError {
    fn from(e: TierMismatch) -> Self {
        Self::Tier(e)
    }
}

impl From<RequestError> for MxcError {
    fn from(e: RequestError) -> Self {
        Self::Request(e)
    }
}

impl From<v1::Error> for MxcError {
    fn from(e: v1::Error) -> Self {
        Self::Sdk(e)
    }
}

/// What a launch produced, in the shape P1 feeds into the existing session
/// result path.
///
/// A `SessionOutcome` exists only for launches that passed guardrail 1, so its
/// presence is the proof-carrying success signal.
#[derive(Debug, Clone)]
pub struct SessionOutcome {
    /// `None` when the workload was killed by `timeout_ms`.
    pub exit_code: Option<i32>,
    /// Why the session was killed, when it was (P2.1). One field instead of a
    /// boolean because "timed out" was three different failures with three
    /// different remediations — see [`TimeoutReason`].
    pub timeout: Option<TimeoutReason>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    /// Policy/operational warnings from the container. Never evidence of
    /// network reachability (ADR-0004).
    pub warnings: Vec<String>,
    pub tier: TierRecord,
    pub proxy_proof: ProxyProof,
    /// The leg this launch was gated on, carried so [`success`] cannot re-check
    /// against a different leg than the launch used.
    ///
    /// [`success`]: SessionOutcome::success
    pub expectation: ProofExpectation,
    /// What the supervisor measured of this launch (P2.1 review, item 2; round 2,
    /// item 7 added the teardown): `elapsed`, `handshake_elapsed`, `prompt_wait` and
    /// `teardown_elapsed`. Carried so the
    /// [`timeout`](SessionOutcome::timeout) label can be checked against its own
    /// inputs — "workload overran" is falsifiable only if the reader can see that
    /// the container was ready in 200 ms, and "prompt budget spent" only if the
    /// prompt time is visible next to the wall clock.
    pub clock: SessionClock,
}

impl SessionOutcome {
    /// True only for a clean exit 0 whose proxy proof passes guardrail 1 for the
    /// leg the launch was gated on.
    ///
    /// The proof is re-checked here rather than assumed: a hand-built or
    /// deserialised outcome cannot report success on an unproven launch just by
    /// carrying a zero exit code.
    pub fn success(&self) -> bool {
        self.exit_code == Some(0)
            && !self.timed_out()
            && verify_proxy_proof(self.proxy_proof, self.expectation).is_ok()
    }

    /// `true` when the container killed the session at its deadline.
    pub fn timed_out(&self) -> bool {
        self.timeout.is_some()
    }
}

/// A launch that **ran** and failed guardrail 1 (P3.0).
///
/// Distinct from [`MxcError::Guard`], which refuses a launch *before* the child
/// exists (no proof source, or a `Required` leg with no proxy). This one is the
/// post-run refusal, and it carries the finished [`SessionOutcome`] for one
/// reason: guardrail 1 refuses the SESSION, not the operator's right to see what
/// their command did.
///
/// Losing that output was a real defect, not a cosmetic one. A workload that
/// printed `curl: (2) no URL specified`, or its own error, and never touched the
/// network produced **no output at all** — the supervisor showed one line about a
/// proxy and left the operator with nothing to act on, while the same command
/// under `--block-net` printed everything. The session is still refused (a
/// `proxy_probe_unmet` launch is not a contained session) and `success()` on the
/// carried outcome is still `false`; what changes is that the transcript keeps the
/// workload's own evidence.
#[derive(Debug, Clone)]
pub struct Unproven {
    /// Which leg of guardrail 1 refused the session.
    pub error: GuardError,
    /// What the child did before the session was refused. `success()` on this is
    /// `false` by construction — the proof it re-checks is the failed one.
    pub outcome: SessionOutcome,
}

/// The child's result, before the guardrail is applied.
#[derive(Debug, Clone)]
struct ChildRun {
    wait: WaitResult,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    warnings: Vec<String>,
}

/// One finished child, plus the supervisor's own time after it exited
/// (P2.1 review round 2, item 7).
struct TimedChild {
    child: ChildRun,
    /// Time from the child's exit to the container being gone: the tree kill, the
    /// proxy stop, the release. Carried onto [`SessionClock`] so a deadline that went
    /// on cleanup is not reported as the operator's command overrunning.
    teardown_elapsed: Duration,
}

/// Run `process` to its exit, measuring the workload's run and the supervisor's
/// teardown **separately** (P2.1 review round 2, item 7).
///
/// `wait_with_output` reports the two as one call — it waits, samples warnings and
/// tears the container down — so `elapsed` spanned a teardown whose share was
/// invisible, and a supervisor fault was recorded as the operator's command. This
/// does what `wait_with_output` does, in the same order, with the child's exit (which
/// the SDK exposes as `try_wait`) as the boundary between the two.
///
/// The session deadline is enforced here rather than left to the SDK's own
/// `timeout_ms`: the exit poll is what measures the boundary, so at `deadline` the
/// run is over, and [`v1::MxcProcess::kill_for_timeout`] is the SDK's own timeout
/// arm. `wait` then reports `TimedOut` and the teardown it performs is measured on
/// its own. A run that ends earlier never reaches that arm.
fn run_timed(
    mut process: Box<dyn SandboxProcess>,
    deadline: std::time::Instant,
    capture: bool,
) -> std::io::Result<TimedChild> {
    // How often the child's exit is sampled: the cost of noticing it, paid once per
    // launch. Small against the `slack` a session budgets for startup and teardown,
    // large against the syscall's own cost.
    const EXIT_POLL: Duration = Duration::from_millis(20);

    // Take both streams before waiting so `wait` cannot discard them, and read each
    // on its own thread so an output-heavy child cannot deadlock on a full pipe.
    // Same shape as the SDK's `wait_with_output`, whose closers are what let a
    // timed-out descendant's readers finish.
    //
    // **Not in inherit mode (P3.4).** With `StdioMode::Inherit` the child writes to
    // this process's own console: `take_stdout`/`take_stderr` return `None` and the
    // `*_closer`s return `None`, so there is nothing to tee — building reader
    // threads over inherited stdio would pretend to capture output that already
    // went to the console. The wait path is identical either way: deadline, kill,
    // exit code.
    let (stdout_closer, stderr_closer, stdout, stderr) = if capture {
        let stdout_closer = process.stdout_closer();
        let stderr_closer = process.stderr_closer();
        let stdout = capture_stream(process.take_stdout());
        let stderr = capture_stream(process.take_stderr());
        (stdout_closer, stderr_closer, Some(stdout), Some(stderr))
    } else {
        (None, None, None, None)
    };

    // (1) The workload's own time: from the handshake to the child being gone.
    loop {
        match process.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {}
            // The SDK's own deadline fired, or the wait itself failed: `wait` owns
            // the report, and it cannot take long now.
            Err(_) => break,
        }
        if std::time::Instant::now() >= deadline {
            let _ = process.kill_for_timeout();
            break;
        }
        std::thread::sleep(EXIT_POLL);
    }

    // (2) The supervisor's own time: tree kill, teardown, release.
    let teardown_started = std::time::Instant::now();
    let wait = map_wait(process.wait());
    let teardown_elapsed = teardown_started.elapsed();
    // Sampled after the wait: a backend whose teardown runs there reports its
    // failures here.
    let warnings = process.warnings();
    // Some backends keep their original pipe ends until the process object is
    // released. Drop it before joining the readers so they observe EOF.
    drop(process);
    // A timed-out descendant may retain a write end even after the foreground
    // process is gone: stop capture rather than wait for it.
    if !matches!(wait, Ok(WaitResult::Exited(_))) {
        if let Some(closer) = stdout_closer {
            closer.close();
        }
        if let Some(closer) = stderr_closer {
            closer.close();
        }
    }
    let stdout = match stdout {
        Some(handle) => join_capture(handle)?,
        None => Vec::new(),
    };
    let stderr = match stderr {
        Some(handle) => join_capture(handle)?,
        None => Vec::new(),
    };
    Ok(TimedChild {
        child: ChildRun {
            wait: wait?,
            stdout,
            stderr,
            warnings,
        },
        teardown_elapsed,
    })
}

/// Flatten the dispatcher's two-shaped error into a launch failure.
///
/// `SpawnDispatchError` implements neither `Display` nor `Debug`, so the message
/// is built from its parts instead of being formatted with `{:?}`: a dispatch
/// failure carries the dispatcher's own (debug-formatted, and stable for
/// diagnosis) error, and a backend spawn failure carries the SDK's
/// `ScriptResponse` — whose `error_message` names what the backend refused — plus
/// the tier it was refused at and the tier-selection warnings, which would
/// otherwise be lost on exactly the path an operator needs them.
fn spawn_failed(
    error: mxc_sdk::process_container_common::dispatcher::SpawnDispatchError,
) -> MxcError {
    use mxc_sdk::process_container_common::dispatcher::SpawnDispatchError;
    let detail = match error {
        SpawnDispatchError::Dispatch(inner) => format!("tier selection failed: {inner:?}"),
        SpawnDispatchError::Spawn {
            response,
            tier,
            warnings,
        } => {
            let mut detail = format!(
                "the {} tier refused the launch: {}",
                tier.as_str(),
                response.error_message
            );
            for warning in warnings {
                detail.push_str(&format!("; {warning}"));
            }
            detail
        }
    };
    MxcError::Sdk(v1::Error::new(
        v1::ErrorCode::BackendError,
        format!("spawning the sandboxed process failed: {detail}"),
    ))
}

/// The handle's exit code, in the vocabulary the gate reads.
///
/// `SandboxProcess::wait` reports a deadline kill as `ErrorKind::TimedOut` and a
/// real exit as the code; [`WaitResult`] is the SDK's typed form of the same two
/// answers, and the gate must keep seeing it (`SessionOutcome::timeout` is derived
/// from it, and a timeout attributed to a budget term depends on that label).
fn map_wait(result: std::io::Result<i32>) -> std::io::Result<WaitResult> {
    match result {
        Ok(code) => Ok(WaitResult::Exited(code)),
        Err(error) if error.kind() == std::io::ErrorKind::TimedOut => Ok(WaitResult::TimedOut),
        Err(error) => Err(error),
    }
}

/// Read one of the child's pipes to EOF on its own thread (see [`run_timed`]).
fn capture_stream(
    stream: Option<Box<dyn std::io::Read + Send>>,
) -> std::thread::JoinHandle<std::io::Result<Vec<u8>>> {
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(mut stream) = stream {
            std::io::Read::read_to_end(&mut stream, &mut buf)?;
        }
        Ok(buf)
    })
}

/// The bytes a capture thread read, or the failure it hit — the same two answers
/// `wait_with_output` gives.
fn join_capture(
    handle: std::thread::JoinHandle<std::io::Result<Vec<u8>>>,
) -> std::io::Result<Vec<u8>> {
    handle
        .join()
        .unwrap_or_else(|_| Err(std::io::Error::other("output capture thread panicked")))
}

// ---------------------------------------------------------------------------
// Request mapping (pure)
// ---------------------------------------------------------------------------

/// The unnormalized launch mode for the SDK's own logger.
///
/// `Mode::Buffer` collects the backend's log lines in memory instead of writing
/// them to our stdout: with inherited stdio the child owns that console (a log
/// line interleaved into a TUI's frames would corrupt the display), and with
/// captured stdio the supervisor prints the child's output itself. The buffer is
/// dropped with the launch, exactly as `v1::spawn`/`v1::run` do internally.
fn launch_log_mode() -> Mode {
    Mode::Buffer
}

/// The `ProcessContainer` posture, pinned field by field.
///
/// The SDK's contract types state every field explicitly instead of inheriting a
/// patchable default (plan decision D6): a bump that changed one of them would
/// otherwise change containment silently. The values are today's SDK defaults and
/// must stay so — `process_container_contract_pins_every_field_explicitly` is the
/// drift alarm.
fn process_container_contract() -> contract::ProcessContainer {
    contract::ProcessContainer {
        // Stated, not inherited: absent and "explicitly false" are different
        // requests, and `false` is today's default.
        least_privilege: contract::OptionalField::present(false),
        // No deny-and-record ETL capture: learning mode is a discovery tool, not
        // a containment posture, and it writes a trace.
        learning_mode: Default::default(),
        // No additional capability SIDs beyond what proxy-only egress implies.
        capabilities: contract::OptionalField::present(Vec::new()),
        capture_denials: Default::default(),
        ui: contract::OptionalField::present(contract::ProcessContainerUi {
            isolation: contract::OptionalField::present(
                contract::ProcessContainerUiIsolation::Container,
            ),
            desktop_system_control: contract::OptionalField::present(false),
            system_settings: contract::OptionalField::present("none".to_string()),
            ime: contract::OptionalField::present(false),
        }),
        // No enumerate-without-read grants.
        filesystem: Default::default(),
        // Identity-less deployment: `allowedProxyPeer` stays unset (a
        // `host:port` peer fails the request build with `malformed_request`).
        network: Default::default(),
    }
}
/// Map resolved session data to a `ContainerRequest` (pure: no I/O, no SDK
/// calls).
///
/// Posture, all of it forced by the ADR-0004 prototype:
///
/// * `egress.default = deny` — the child reaches nothing except our proxy.
/// * `ingress.default = allow` **and** `ingress.host_loopback = allow` are
///   mandatory for proxy-only egress, and `processContainer.network
///   .allowedProxyPeer` stays unset: an unpackaged caller-owned proxy has no
///   package identity, and the identity-scoped form fails the request build.
///   This is the deployment upstream labels development/testing compatibility
///   (ADR-0004 risk 2) — the one that actually works unelevated.
/// * `environment` is always an explicit, filtered allow-list — never `None`
///   (which would mean "backend default").
/// * `ui` is stated explicitly with `disable: false`, because an **absent** UI
///   policy is not neutral: the SDK resolves it to `UiPolicy::default()`, which
///   bans Win32k system calls, and every child that loads `user32`/`gdi32`/
///   `ole32` then dies at load (`0xC0000142`). The assignment carries the
///   mechanism, the measured codes and the containment that is given up.
/// * The command is the **wrapper launcher**, not the workload (D1).
///
/// Fails with [`RequestError`] for a workload command that cannot be launched.
/// Those refusals happen here, at map time, rather than once the container
/// exists: an empty command and an embedded NUL only show up as a failed spawn.
///
/// Also fails with [`RequestError::DenyCoversGrant`] when a `denied_paths` entry
/// contains a grant **after** the launcher grant is inserted. That check is
/// repeated here, not only in [`filesystem_policy`], because a caller may build
/// an [`MxcFilesystemInput`] by hand: the launcher grant is added below, and a
/// deny list filtered before it existed can still ship a deny that covers it.
///
/// Also fails with [`RequestError::PathNotAbsolute`] for a launcher that is empty
/// or cannot be made absolute: both the grant derived here and the check above
/// compare absolute keys, so a relative launcher would defeat them.
pub fn build_request(
    input: &MxcSessionInput,
    launcher: &Path,
) -> Result<ExecutionRequest, RequestError> {
    if input.command.trim().is_empty() {
        return Err(RequestError::EmptyCommand);
    }
    // A NUL would end the command line at `CreateProcessW`, so the argv the
    // child sees would stop there — silently, and not what was recorded here.
    if input.command.contains('\0') {
        return Err(RequestError::NulInCommand);
    }

    // The launcher takes part in the deny comparison below, so a relative
    // spelling would key as itself and no absolute deny could cover it: resolve
    // it at this boundary, before the grant is derived from it. The command line
    // below names the resolved path as well, so the container executes exactly
    // the binary the policy granted.
    let launcher = absolute_path("launcher", launcher)?;
    // P1.3: the launcher's directory is a grant the request cannot do without,
    // so the mapping adds it here instead of relying on the caller.
    let mut filesystem = input.filesystem.clone();
    ensure_launcher_grant(&mut filesystem, &launcher);
    // ...and then re-check the deny list against the grant set that now
    // includes it (BLOCKING 1: the filter must never run before this grant).
    // Fail closed: a deny that contains any grant is a refusal, not a drop.
    let grants = granted_paths(&filesystem);
    for deny in &filesystem.denied_paths {
        let deny = deny.trim();
        if deny.is_empty() {
            continue;
        }
        if let Some(grant) = grant_contained_by_deny(deny, &grants) {
            return Err(RequestError::DenyCoversGrant {
                deny: deny.to_string(),
                grant: grant.clone(),
            });
        }
    }

    // Invariant 5: the host's proxy configuration never crosses. Always an
    // explicit list, even when empty — `None` would mean "backend default".
    let environment: Vec<String> = input
        .environment
        .iter()
        .filter(|(key, _)| !is_blocked_env_key(key))
        .map(|(key, value)| format!("{key}={value}"))
        .collect();

    // The proxy URL is the ONLY channel that reaches the child's
    // `HTTP_PROXY`/`HTTPS_PROXY` (mxc-sdk 1.0.1 strips every proxy variable from
    // the environment and re-injects this one verbatim), and its presence is also
    // what decides the ingress posture below.
    let network_proxy = match input.network.proxy_port {
        Some(port) => Some(proxy_url(port, input.network.proxy_token.as_deref())?),
        None => None,
    };
    // Proxy-only egress: everything outbound is denied at the container level and
    // the only path out is the supervisor's loopback proxy. Both ingress fields
    // are mandatory for it (ADR-0004 constraint); with no proxy, no network at
    // all and no host loopback.
    // Both ingress fields carry the SAME answer, so they are built from one
    // expression rather than a cloned value (`NetworkAction` is not `Clone`, and a
    // copy that drifted between the two fields would be an unenforced policy).
    let ingress_action = || {
        if network_proxy.is_some() {
            contract::NetworkAction::Allow
        } else {
            contract::NetworkAction::Deny
        }
    };
    let network = contract::Network {
        egress: contract::OptionalField::present(contract::NetworkEgress {
            default: contract::OptionalField::present(contract::NetworkAction::Deny),
            allow: Default::default(),
            deny: Default::default(),
        }),
        ingress: contract::OptionalField::present(contract::NetworkIngress {
            default: contract::OptionalField::present(ingress_action()),
            host_loopback: contract::OptionalField::present(ingress_action()),
        }),
    };

    // The command is the wrapper launcher, not the workload (D1).
    let command = launcher_command(&launcher, &input.command, input.network.proxy_port);
    let request = contract::OneShotRequest {
        schema: Default::default(),
        comment: Default::default(),
        version: contract::Version::V1_0_0,
        // Left to the SDK: it mints an identifier when the caller names none, and
        // this request is per-session by construction (one listener, one epoch,
        // one container).
        container_id: Default::default(),
        containment: contract::OptionalField::present(
            contract::OneShotContainment::ProcessContainer,
        ),
        // `clearPolicyOnExit: true`, as the pre-P3.4 request stated it: the
        // container's policy is not preserved after the run.
        lifecycle: contract::OptionalField::present(contract::Lifecycle {
            destroy_on_exit: contract::OptionalField::present(true),
            preserve_policy: contract::OptionalField::present(false),
        }),
        process: contract::Process {
            command_line: contract::NonEmptyString::new(command)
                .map_err(|reason| RequestError::InvalidRequest { reason })?,
            cwd: match &input.working_directory {
                Some(directory) => contract::OptionalField::present(directory.clone()),
                None => Default::default(),
            },
            env: contract::OptionalField::present(environment),
            // D2 — deliberately `true`. At `mxc-sdk 1.0.1` this block is the
            // user's **profile** environment (`create_default_env_entries` →
            // `CreateEnvironmentBlock(.., bInherit = FALSE)`), never this
            // process's environment, and it is what makes an ordinary workload
            // work at all (PATH/TEMP/USERPROFILE/PSModulePath); `false` would
            // hand the child a bare allow-list, and the SDK's
            // `validate_required_child_env` exists precisely because that breaks
            // CreateProcessW.
            //
            // It is safe *because* `build_inherited_entries` lays our filtered
            // list on top and then `inject_proxy_vars` strips HTTP_PROXY /
            // HTTPS_PROXY / NO_PROXY / ALL_PROXY (case-insensitive) from the
            // merged block before injecting the configured proxy: no host proxy
            // value can survive into a proxied session. In the proxy-less branch
            // a persisted proxy value does survive, and is inert —
            // `egress.default = deny` and `host_loopback = deny`. Residual risk,
            // accepted: other profile-persisted variables (e.g. a CA-bundle
            // override) do reach the child; filesystem and network policy, not
            // env, are the containment boundary. `NO_PROXY` needs no exception
            // here — the wrapper supplies it (D1).
            inherit_default_env: contract::OptionalField::present(true),
            // `None` keeps the SDK's "no deadline" spelling (`0` → INFINITE); the
            // supervisor never ships it as-is — [`MxcBackend`] always writes its
            // own budget.
            timeout: contract::OptionalField::present(input.timeout_ms.unwrap_or(0)),
        },
        filesystem: contract::OptionalField::present(contract::Filesystem {
            readwrite_paths: contract::OptionalField::present(filesystem.readwrite_paths.clone()),
            readonly_paths: contract::OptionalField::present(filesystem.readonly_paths.clone()),
            denied_paths: contract::OptionalField::present(filesystem.denied_paths.clone()),
        }),
        fallback: Default::default(),
        network: contract::OptionalField::present(network),
        // P3 — the Win32k ban is *this* section, and its default is the trap.
        //
        // An ABSENT `ui` section is not "no opinion": it resolves to
        // `UiPolicy::default()`, whose `disable: true` the PSEC path maps to
        // `PROCESS_CREATION_MITIGATION_POLICY_WIN32K_SYSTEM_CALL_DISABLE`, and
        // every child that loads `user32`/`gdi32`/`ole32` then dies at load
        // (`0xC0000142`). Measured A/B on this exact request, one field
        // different: `powershell.exe -Command "Write-Output FXOK"` exits
        // `0xC0000142` with the default and `0` with `disable: false`, and
        // `dotnet hello.dll` fails to load `coreclr.dll` with `HRESULT
        // 0x8007045A` (0xC0000409) versus printing `HELLO-OK`. `coreclr.dll`
        // statically imports USER32 *and* ole32, so there is no middle setting —
        // it is Win32k syscalls or no CLR, never both.
        //
        // The cost, accepted deliberately and not hidden: the child may now enter
        // Win32k at all — create windows and reach that large kernel attack
        // surface — which is precisely what the mitigation existed to remove.
        // Everything else stays closed: clipboard and input injection are pinned
        // default-deny here, and the ten `JOB_OBJECT_UILIMIT_*` restrictions
        // `resolve_ui_restrictions` derives from `processContainer.ui` are still
        // emitted. Do not "tidy" this back to the default;
        // `sdk_ui_policy_default_is_still_the_win32k_ban_we_explicitly_escape`
        // is what tells us if a bump ever moves the default out from under it.
        // Evidence: `docs/research/backends/process-container/clr-startup-failure.md`.
        ui: contract::OptionalField::present(contract::Ui {
            disable: contract::OptionalField::present(false),
            // Default-deny: the child keeps no clipboard and cannot inject input.
            clipboard: contract::OptionalField::present(contract::UiClipboard::None),
            injection: contract::OptionalField::present(false),
        }),
        // Identity-less deployment: `allowedProxyPeer` is left unset because an
        // unpackaged caller-owned proxy has no package family name, and the
        // identity-scoped form fails the request build with `malformed_request`.
        process_container: contract::OptionalField::present(process_container_contract()),
        lxc: Default::default(),
        seatbelt: Default::default(),
        runtime_config: match network_proxy {
            Some(url) => contract::OptionalField::present(contract::RuntimeConfig {
                network_proxy: contract::OptionalField::present(url),
            }),
            None => Default::default(),
        },
        telemetry: Default::default(),
        wslc: Default::default(),
    };

    // Through the SDK's OWN one-shot contract adapter, not a struct literal: the
    // parser is what sets the parse-derived facts a backend reads
    // (`ui_specified`, `network_specified`, `runtime_network_proxy_specified`) and
    // what rejects a request the SDK cannot honour. Building the model by hand
    // would ship those flags at their defaults — and an absent UI policy is the
    // Win32k ban this request exists to escape.
    let mut logger = Logger::new(Mode::Buffer);
    load_one_shot_request_from_contract(ExactOneShotContract::V1_0(Box::new(request)), &mut logger)
        .map_err(|error| RequestError::InvalidRequest {
            reason: error.to_string(),
        })
}

// ---------------------------------------------------------------------------
// P2.1: the session budget (timeout_ms = prompt + workload + slack)
// ---------------------------------------------------------------------------

/// The **prompt term**: how long ONE prompt consultation may legitimately take.
///
/// The same value the coordinator uses ([`crate::net::prompt::
/// DEFAULT_PROMPT_TIMEOUT`], 60 s — the ADR's `limits.promptTimeoutSecs`
/// default), and deliberately the same constant rather than a second number that
/// can drift: the container's deadline is computed from this, and if a dialog were
/// allowed to take longer than the term this budget reserves for it, a
/// legitimate dialog would kill the session.
pub const PROMPT_BUDGET: Duration = crate::net::prompt::DEFAULT_PROMPT_TIMEOUT;

/// The **workload term**: how long the sandboxed workload itself may run.
///
/// [`crate::net::DEFAULT_WORKLOAD_TIMEOUT_SECS`] (30 min) — the `limits.
/// workloadTimeoutSecs` default: long enough for the workloads this tool actually
/// runs (a build, a test suite, a model download over the proxy) and short enough
/// that a wedged child cannot hold a container for a day. It is *not* the
/// container's deadline — that is this plus the prompt term plus the slack — so a
/// session that spends its whole prompt budget still gets this much time to work.
///
/// **This is a bound the tool never had.** Before P2.1 the session had no bound at
/// all (`timeout_ms: None`, i.e. `INFINITE`), so a profile that legitimately needs
/// longer — a cold Rust build with a large dependency graph, a multi-gigabyte model
/// download — must RAISE it with `limits.workloadTimeoutSecs`. The failure mode
/// of leaving it at the default is a killed session whose audit reason says
/// `workload_budget_exceeded`, which is exactly what that reason is for.
pub const WORKLOAD_BUDGET: Duration =
    Duration::from_secs(crate::net::DEFAULT_WORKLOAD_TIMEOUT_SECS as u64);

/// The **slack term**: container create, proxy proof, teardown, and the scheduling
/// jitter between the container's own clock and ours.
///
/// Two minutes, because everything this term covers is either process creation
/// (hundreds of milliseconds, but it includes Defender scanning the launcher) or
/// process teardown (the SDK killing the tree and draining the pipes). Its job is
/// to make the deadline *strictly larger* than prompt + workload, so a session that
/// uses both terms to the last millisecond is not killed for arithmetic reasons.
pub const SESSION_SLACK: Duration = Duration::from_secs(2 * 60);

/// The three terms a session's `timeout_ms` is made of (P2.1).
///
/// **Why three terms.** `timeout_ms` bounds the whole session, and the prompt and
/// the workload are two independent things that can each take a long time. Sizing
/// the container's deadline as the prompt term alone (or as the workload term
/// alone) makes one of them kill the other: a 60 s dialog would kill a workload
/// that was still working, and a workload that legitimately waits 3 minutes on a
/// slow origin would starve the dialog that has to be answered to unblock it. So
/// the deadline is the *sum*, and neither term can be spent by the other.
///
/// **Why not `None`.** `timeout_ms: None` is mapped to `INFINITE` by the SDK, so a
/// session with no budget is a container that outlives its supervisor's attention.
/// This type has no way to express that, and the backend always writes
/// `Some(..)` — see [`MxcBackend::request_for`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionBudget {
    /// How long one prompt consultation may take.
    pub prompt: Duration,
    /// How long the workload itself may run.
    pub workload: Duration,
    /// Create/prove/teardown allowance on top of both.
    pub slack: Duration,
}

impl Default for SessionBudget {
    /// The configuration defaults, through the same constructor a resolved profile
    /// uses ([`SessionBudget::from_config`]) — not three literals that could drift
    /// from the profile's top-level `limits` section.
    fn default() -> Self {
        Self::from_config(
            crate::net::prompt::DEFAULT_PROMPT_TIMEOUT_SECS,
            crate::net::DEFAULT_WORKLOAD_TIMEOUT_SECS,
            SESSION_SLACK,
        )
    }
}

impl SessionBudget {
    /// A budget with explicit terms (tests, and any future profile knob).
    pub const fn new(prompt: Duration, workload: Duration, slack: Duration) -> Self {
        Self {
            prompt,
            workload,
            slack,
        }
    }

    /// The budget a **resolved profile** asks for (P2.1 review, item 6).
    ///
    /// Takes the RESOLVED values in seconds — `limits.promptTimeoutSecs` and
    /// `limits.workloadTimeoutSecs` after defaults and validation — never the
    /// constants, and never a `Duration` built at the call site: the failure this
    /// replaces was a budget sized from [`PROMPT_BUDGET`] (the 60 s DEFAULT) while
    /// the dialog actually got the profile's `limits.promptTimeoutSecs`. A 300 s profile
    /// then reserved 60 s + slack of prompt time and killed a legitimate dialog
    /// plus a full workload — the exact kill P2.1 exists to prevent — and blamed
    /// the wrong term for it. [`SessionBudget::default`] is defined as
    /// `from_config` of the config defaults, so the two cannot disagree.
    pub fn from_config(prompt_secs: u32, workload_secs: u32, slack: Duration) -> Self {
        Self {
            prompt: Duration::from_secs(u64::from(prompt_secs)),
            workload: Duration::from_secs(u64::from(workload_secs)),
            slack,
        }
    }

    /// The whole session: every term added.
    pub fn session(&self) -> Duration {
        self.prompt + self.workload + self.slack
    }

    /// The value the container gets as `timeout_ms`.
    ///
    /// Saturating rather than wrapping: `u32::MAX` milliseconds is 49 days and the
    /// SDK reads it as a finite (absurdly long) deadline, which is the safe side of
    /// a bug here — the alternative, a wrapped small number, would kill every
    /// session immediately.
    pub fn timeout_ms(&self) -> u32 {
        u32::try_from(self.session().as_millis()).unwrap_or(u32::MAX)
    }

    /// Attribute a kill at this budget's deadline to the term that spent the time
    /// (P2.1), from the measurements the session carries ([`SessionClock`]).
    ///
    /// **The handshake decides first** (P2.1 review, item 2). Whether the container
    /// ever became ready is a question about the supervisor and the platform, and it
    /// is asked before any question about the operator's command: a create/prove
    /// that never finished means the deadline was spent before the workload could
    /// run. Reporting that as `WorkloadBudgetExceeded` blamed the command for a
    /// container that never started. This branch used to be unreachable: `elapsed`
    /// was measured around the whole run, so it was always at least
    /// `prompt + workload` and the check could never fire. It is measured separately
    /// now (`SessionClock::handshake_elapsed`) and this is the first branch that reads
    /// it. Round 2 (item 6) added the other half of the rule: an over-`slack`
    /// handshake is only to blame when it also **deprived** the workload, because a
    /// 130 s create plus a command that then used its whole term is the command's
    /// overrun and nothing about the container is wrong.
    ///
    /// **Teardown is a supervisor term too** (round 2, item 7), on the same
    /// deprivation rule and after the handshake: the command finished and cleanup ran
    /// the clock out is [`TimeoutReason::SessionTeardown`], never the operator's
    /// command.
    ///
    /// **Prompt time is a sum, not a share of the wall clock** (item 1c). The
    /// listener credits each dialog once, to its LEADER (round 2, item 1), so what the
    /// session carries is the total time it was blocked on dialogs — still not a
    /// share of the wall clock, because dialogs on different hosts run concurrently.
    /// What it can answer is whether the workload was **starved**: the workload is
    /// entitled to `workload` of unblocked wall clock, so a prompt term is to blame
    /// only when `elapsed - prompt_wait - teardown < workload` (item 1b) — otherwise
    /// the workload had its full entitlement and overran it, which is the operator's
    /// command and nobody else's. The rule is stated as deprivation rather than as
    /// "`prompt_wait > prompt + slack`" because those two are equal only when the
    /// kill lands exactly on the deadline; the deprivation form also holds for a
    /// kill that arrives late.
    ///
    /// **Saturation is not evidence** (item 1a). The aggregate is clamped to the
    /// session it happened in — `prompt_wait.min(elapsed)` — and a value that needed
    /// the clamp is the fingerprint of the over-count, not a measurement that the
    /// workload was blocked for the whole session. Such a value cannot support a
    /// positive claim about the prompt term, so it falls back to the term the
    /// supervisor measures with its own clock.
    pub fn classify(&self, clock: &SessionClock) -> TimeoutReason {
        let elapsed = clock.elapsed;
        // (2a) A session that ended before either term could have been spent did not
        // lose the deadline to either of them: nothing but the supervisor explains it.
        if elapsed < self.prompt + self.workload {
            return TimeoutReason::SessionHandshake;
        }
        // (2b) The handshake, from its own measurement — and only when it DEPRIVED
        // the workload (round 2, item 6). `handshake_elapsed > slack` alone made a
        // 130 s create plus a workload that then used its full term read as
        // "container never started", which sends the reader after the wrong
        // subsystem: the rule is the prompt rule, applied to the supervisor's own
        // term.
        if clock.handshake_elapsed > self.slack
            && elapsed.saturating_sub(clock.handshake_elapsed) < self.workload
        {
            return TimeoutReason::SessionHandshake;
        }
        // (2c) The teardown, on the same rule (round 2, item 7). Nothing about the
        // command's own time is in question when the command had already finished and
        // cleanup is what ran the clock out.
        if clock.teardown_elapsed > self.slack
            && elapsed.saturating_sub(clock.teardown_elapsed) < self.workload
        {
            return TimeoutReason::SessionTeardown;
        }
        // (1a) The clamp, repeated defensively so a hand-built clock cannot claim
        // more prompt time than session.
        let prompt_wait = clock.prompt_wait.min(elapsed);
        if prompt_wait >= elapsed {
            // Saturated: the aggregate over-counted (see above), or the workload
            // genuinely never ran — either way a prompt overrun is not the claim
            // this measurement can support.
            return TimeoutReason::WorkloadBudgetExceeded;
        }
        // (1b) Deprivation: prompt-bound only if the workload did not get its term.
        // Net of the supervisor's own teardown, which is time the workload could not
        // have used either way — without that subtraction a real workload overrun
        // next to a pathological teardown is blamed on the dialog.
        let workload_available = elapsed
            .saturating_sub(prompt_wait)
            .saturating_sub(clock.teardown_elapsed);
        if workload_available < self.workload {
            TimeoutReason::PromptBudgetExhausted
        } else {
            TimeoutReason::WorkloadBudgetExceeded
        }
    }
}

/// Why a session hit its deadline (P2.1).
///
/// Four variants because the four have different remediations and must not share a
/// reason string: a workload overrun is the operator's command, a spent prompt budget
/// is an unanswered dialog, a handshake timeout is a container that never started, and
/// a teardown timeout is a container that will not go away (round 2, item 7). Before
/// this the only fact an outcome carried was `timed_out: true`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeoutReason {
    /// The workload ran past [`SessionBudget::workload`].
    WorkloadBudgetExceeded,
    /// Prompt consultations consumed the whole [`SessionBudget::prompt`] term.
    PromptBudgetExhausted,
    /// Neither term was spent: create/prove/teardown is what the deadline covered.
    SessionHandshake,
    /// The command finished, and the supervisor's teardown is what ran the deadline
    /// out (round 2, item 7). Supervisor-side, like [`Self::SessionHandshake`], and
    /// separate from it because the remedies differ: a container that never started
    /// versus a container that will not go away.
    SessionTeardown,
}

impl TimeoutReason {
    /// The stable, greppable reason string (audit/log vocabulary, same shape as the
    /// proxy's `prompt_budget_exhausted`).
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::WorkloadBudgetExceeded => "workload_budget_exceeded",
            Self::PromptBudgetExhausted => "prompt_budget_exhausted",
            Self::SessionHandshake => "session_handshake_timeout",
            Self::SessionTeardown => "session_teardown_timeout",
        }
    }
}

impl fmt::Display for TimeoutReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Prompt time one launch spent: the listener's counter restarts at every launch
/// (`LaunchCounters::begin_epoch`) and the delta across the run is this session's own
/// contribution to it (P2.1). The delta is kept as well as the reset, so the two
/// cannot silently disagree.
///
/// A SUM of dialog wall clocks, not a share of the session's wall clock: the listener
/// credits each dialog once, to the consultation that LED it (round 2, item 1), and
/// dialogs on different hosts run concurrently. Nothing here may be read as "the
/// session spent this long in a dialog" — [`SessionClock::measured`] is what turns it
/// into a measurement a label can be based on (clamped, and
/// saturated-means-over-counted).
///
/// Saturating on purpose: the clock cannot go backwards, and if it ever did (a
/// counter reset), the session must be credited with zero prompt time rather than
/// with an underflowed giant, which would report every later kill as a prompt
/// timeout.
fn prompt_wait_during(before: Duration, after: Duration) -> Duration {
    after.saturating_sub(before)
}

/// What the supervisor observed of one launch, for attributing a kill (P2.1).
///
/// Measurements, never policy: [`SessionBudget::classify`] is the only consumer, and
/// every field is carried onto [`SessionOutcome`] so a reader can check the label
/// against its own inputs instead of trusting it. Round 2 added the teardown, because
/// `elapsed` spans it and an unmeasured phase can only be blamed on the workload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SessionClock {
    /// The budget the session was launched with.
    pub budget: SessionBudget,
    /// Wall-clock time from launch to the child's exit (or kill): create, run and
    /// teardown.
    pub elapsed: Duration,
    /// Time from launch until the container was **ready** — the SDK's `spawn`
    /// returned, i.e. the container exists and the workload was launched (P2.1
    /// review, item 2). Measured separately because `elapsed` alone cannot say
    /// whether the workload ever ran: a create that hangs is a supervisor/platform
    /// failure and must not be reported as the operator's command overrunning.
    pub handshake_elapsed: Duration,
    /// Time inside prompt consultations, measured by the proxy listener: the wall
    /// clock of each dialog it LED, summed (a coalesced follower adds nothing) and
    /// clamped to [`SessionClock::elapsed`].
    pub prompt_wait: Duration,
    /// Time the supervisor spent tearing the container down after the child's exit
    /// (round 2, item 7): the tree kill, the proxy stop and the container release.
    /// Measured separately for the same reason as the handshake — `elapsed` spans it,
    /// and a deadline that went on cleanup is a supervisor fault, not the operator's
    /// command.
    pub teardown_elapsed: Duration,
}

impl SessionClock {
    /// Record one launch's measurements, clamping the prompt aggregate to the
    /// session it happened in (P2.1 review, item 1a).
    ///
    /// The clamp belongs here, at the reader: the counter is a sum over the dialogs
    /// this session LED, and dialogs on different hosts run concurrently, so it can
    /// exceed the session's wall clock even with each dialog credited exactly once.
    /// Crediting the session with more prompt time than it ran for is not a
    /// measurement — and `min` keeps the carried value
    /// (`SessionOutcome::clock.prompt_wait`) a number a reader can reason about,
    /// with saturation as the visible sign that the aggregate over-counted.
    pub fn measured(
        budget: SessionBudget,
        elapsed: Duration,
        handshake_elapsed: Duration,
        prompt_wait: Duration,
    ) -> Self {
        Self {
            budget,
            elapsed,
            handshake_elapsed,
            prompt_wait: prompt_wait.min(elapsed),
            teardown_elapsed: Duration::ZERO,
        }
    }

    /// Record the teardown this session measured (round 2, item 7).
    ///
    /// A builder rather than a fifth parameter of [`SessionClock::measured`]: the
    /// teardown is only measurable where a container is really torn down, and a
    /// caller that has no such measurement must not be able to leave a fifth `0`
    /// standing in for it.
    pub fn with_teardown(self, teardown: Duration) -> Self {
        Self {
            teardown_elapsed: teardown,
            ..self
        }
    }

    /// The reason this session's deadline produced, if it produced one.
    pub fn timeout_reason(&self) -> TimeoutReason {
        self.budget.classify(self)
    }
}

// ---------------------------------------------------------------------------
// Launch
// ---------------------------------------------------------------------------

/// The `processcontainer` backend for one launch.
///
/// It carries the launch context — the proof source, the proxy port it listens
/// on, the wrapper launcher and the run budget — so a request cannot be built
/// against a proxy this backend does not own (D4).
pub struct MxcBackend<'a> {
    proof: Option<&'a dyn ProxyProofSource>,
    proxy_port: Option<u16>,
    /// The token the backend's own listener expects, if that listener
    /// authenticates. Always overrides whatever the caller's input carried: only
    /// this backend's token can satisfy this backend's proxy, so a caller value
    /// is a lookalike by definition.
    proxy_token: Option<String>,
    /// The session's budget (P2.1). **Not** optional: a backend with no budget
    /// ships the caller's `timeout_ms`, and a caller that passed `None` used to
    /// produce a container with an infinite deadline. There is no representation
    /// of "no budget" here, so that cannot be reintroduced by forgetting to call
    /// a setter.
    budget: SessionBudget,
    /// Guardrail 2's hard half (P2.3): which tier this session requires.
    ///
    /// **A required constructor argument**, never a default (P2.3 review, item 1):
    /// the field used to default to `Recorded` — the value that means "don't
    /// enforce" — so a caller that forgot the requirement silently ran un-gated.
    /// `Recorded` is still expressible, but only by naming it at the call site,
    /// which makes "we are measuring, not enforcing" a decision rather than an
    /// omission.
    tier: TierExpectation,
    launcher: PathBuf,
}

impl<'a> MxcBackend<'a> {
    /// A backend for one launch on `proxy_port`, proofed by `proof`, enforcing
    /// `tier`.
    ///
    /// `tier` has no default on purpose. The product session path passes
    /// `TierExpectation::Exactly(REQUIRED_TIER)`; a launch that dispatches to any
    /// other tier — or to a tier the probe cannot name — is refused before the
    /// child starts, so the refused session has no CONNECT leaf. A measurement
    /// (probe, spike, evidence test) passes `TierExpectation::Recorded` and says so.
    pub fn new(
        proof: &'a dyn ProxyProofSource,
        proxy_port: Option<u16>,
        launcher: impl Into<PathBuf>,
        tier: TierExpectation,
    ) -> Self {
        Self {
            proof: Some(proof),
            proxy_port,
            proxy_token: None,
            budget: SessionBudget::default(),
            tier,
            launcher: launcher.into(),
        }
    }

    /// A backend with no proof source: every launch is refused by guardrail 1
    /// with [`GuardError::MissingProofSource`]. Exists so that refusal is
    /// expressible rather than accidental.
    ///
    /// Takes the tier requirement for the same reason [`MxcBackend::new`] does:
    /// no constructor may leave the gate unstated.
    pub fn without_proof_source(
        proxy_port: Option<u16>,
        launcher: impl Into<PathBuf>,
        tier: TierExpectation,
    ) -> Self {
        Self {
            proof: None,
            proxy_port,
            proxy_token: None,
            budget: SessionBudget::default(),
            tier,
            launcher: launcher.into(),
        }
    }

    /// The tier requirement this backend applies (guardrail 2's hard half).
    ///
    /// Read-only: there is no setter, so the requirement is fixed at construction
    /// and cannot be relaxed halfway through a session's life.
    pub fn tier_expectation(&self) -> TierExpectation {
        self.tier
    }

    /// Guardrail 2's decision for a probed tier, using this backend's requirement.
    ///
    /// The seam exists so the requirement is testable without a container: a
    /// backend that was told it requires `base-container` must refuse a record
    /// naming anything else, and the launch path below is the only other caller.
    fn tier_gate(&self, tier: &TierRecord) -> Result<(), TierMismatch> {
        verify_tier(tier, self.tier)
    }

    /// The session token the backend's proxy expects, embedded in the proxy URL
    /// the child receives (see [`MxcNetworkInput::proxy_token`]).
    pub fn with_proxy_token(mut self, token: impl Into<String>) -> Self {
        self.proxy_token = Some(token.into());
        self
    }

    /// Replace the session budget (P2.1).
    ///
    /// Takes the three-term [`SessionBudget`], never a bare `Option<u32>`: a bare
    /// `None` is the unbounded session this item removed, and a bare number hides
    /// which term it is meant to cover. The default is
    /// [`SessionBudget::default`] — prompt + workload + slack — and this setter
    /// exists for a caller that knows better (a profile knob, or a test with a
    /// 300 ms prompt term).
    pub fn with_budget(mut self, budget: SessionBudget) -> Self {
        self.budget = budget;
        self
    }

    /// This backend's session budget.
    pub fn budget(&self) -> SessionBudget {
        self.budget
    }

    /// The port this backend's proxy listens on.
    pub fn proxy_port(&self) -> Option<u16> {
        self.proxy_port
    }

    /// The wrapper launcher this backend launches.
    pub fn launcher(&self) -> &Path {
        &self.launcher
    }

    /// The request this backend would launch for `input`.
    ///
    /// The backend's own proxy port, launcher and budget replace whatever the
    /// caller's input carried: the request must describe the launch that is
    /// actually about to happen, or guardrail 1 would attribute traffic to the
    /// wrong place.
    ///
    /// The budget is **always** written, unconditionally, from this backend's
    /// [`SessionBudget`] (P2.1). Passing the caller's value through was the
    /// unbounded-session bug: `timeout_ms: None` means no deadline at all in the
    /// SDK, so a supervisor that forgot to set one launched a container that could
    /// outlive everything. The caller's field is still honoured where it belongs —
    /// as the *default* a caller can set — but only a value covering prompt +
    /// workload + slack can survive this function.
    ///
    /// Returns [`RequestError`] (wrapped in [`MxcError`]) for a command line that
    /// cannot be launched; see [`build_request`].
    pub fn request_for(&self, input: &MxcSessionInput) -> Result<ExecutionRequest, MxcError> {
        let mut effective = input.clone();
        effective.network.proxy_port = self.proxy_port;
        // Overriding unconditionally (not `unwrap_or`): a caller-supplied token
        // cannot authenticate against this backend's listener, and shipping it
        // would produce a 407 that reads like a broken proxy.
        effective.network.proxy_token = self.proxy_token.clone();
        // Never `None`, never the caller's number: the session deadline is this
        // backend's own arithmetic.
        effective.timeout_ms = Some(self.budget.timeout_ms());
        Ok(build_request(&effective, &self.launcher)?)
    }

    /// Run a short-lived command to completion inside a ProcessContainer.
    ///
    /// Order is the contract: resolve the proof source (refuse early if there is
    /// none), build the request, refuse an unsatisfiable expectation, probe the
    /// tier of the exact request, run inside a launch epoch, then apply
    /// guardrail 1 to that epoch's counters. There is no path from `v1::run`
    /// returning `Ok` to a success without the gate passing.
    ///
    /// `expectation` is the caller's declaration of what the session's network
    /// posture demands — see [`ProofExpectation`].
    pub fn launch(
        &self,
        input: &MxcSessionInput,
        expectation: ProofExpectation,
    ) -> Result<SessionOutcome, MxcError> {
        let source = self
            .proof
            .ok_or(MxcError::Guard(GuardError::MissingProofSource))?;

        // P3.4: inherited stdio (a real console for the child) or captured pipes.
        // Read once, here, so the spawn and the wait path cannot disagree about
        // which one this session is.
        let stdio = input.stdio;

        let request = self.request_for(input)?;

        // D3: a network expectation without a proxy cannot be satisfied by any
        // run, so refuse before the child starts instead of failing a launch
        // that could never have proven anything.
        if expectation == ProofExpectation::Required && self.proxy_port.is_none() {
            return Err(MxcError::Guard(GuardError::RequiredWithoutProxy));
        }

        // Guardrail 2 on the exact request that is about to be launched: not a
        // lookalike, and not the backend ceiling (which policy can lower).
        let tier = probe_tier(&request)?;

        // Guardrail 2's HARD half, and it belongs here rather than in
        // `gate_outcome`: a session that dispatches to the wrong tier is refused
        // before the epoch opens and before the child exists, so it cannot have
        // reached the proxy and therefore cannot have a CONNECT leaf. Checking it
        // after the run would make "no CONNECT leaves" a hope instead of a fact.
        self.tier_gate(&tier)?;

        // P2.1: the same measurement starts before the child does, so a kill at the
        // deadline can be attributed to a term instead of reported as a bare
        // timeout. `prompt_wait` comes from the listener, i.e. from the code that
        // actually waited on the dialog.
        let started = std::time::Instant::now();
        // The listener's prompt clock is a per-listener total, so the session's own
        // prompt time is a DELTA between two reads: one listener can serve several
        // sequential launches, and a later session must not inherit an earlier one's
        // spent budget (it would be reported as `prompt_budget_exhausted` having
        // never prompted). Concurrent launches are impossible here ([`MxcError::
        // Concurrency`] refuses an overlapping epoch), so the window is exactly this
        // launch.
        let prompt_baseline = source.prompt_wait();
        // The epoch is opened before the child starts, so guardrail 1 cannot be
        // satisfied by traffic from an earlier launch, and it is closed on every
        // path out of the run (success, SDK error, panic unwind).
        //
        // P2.1 review (item 2): `v1::run` is `spawn` + `wait_with_output` with no
        // seam between them, so the one moment that says whether the container ever
        // became ready was invisible — and a container that hung at create was
        // recorded as the operator's workload overrunning. The two calls are made
        // here instead: identical to what `run` does internally (spawn, then capture
        // both streams while waiting, then sample warnings and tear down), with the
        // handshake measured in between and the teardown measured on the way out
        // ([`run_timed`], round 2 item 7).
        // The session deadline, handed to the run so the exit poll and the SDK's own
        // `timeout_ms` agree on when the workload is over (round 2, item 7).
        let deadline = started + self.budget.session();
        let ((exec, handshake_elapsed), proof) = run_in_epoch(source, || {
            // P3.4: the mode is a LAUNCH decision, not a request field — the
            // normalized request has no stdio field, and the engine's own
            // run-to-completion bridge hardcodes pipes. `spawn_with_fallback` is
            // the public seam that takes one, and it is the same three-tier
            // dispatcher `v1::spawn` reaches (T1 BaseContainer, T2 AppContainer +
            // BFS, T3 AppContainer + DACL); the differences are the stdio wiring
            // and that no denial-capture factory is attached (this request never
            // sets `captureDenials`).
            let mut logger = Logger::new(launch_log_mode());
            let dispatched = spawn_with_fallback(&request, &mut logger, stdio.mode(), None)
                .map_err(spawn_failed)?;
            // The container exists and the workload was launched: the handshake is
            // over. Everything after this point is the workload's own time.
            let handshake_elapsed = started.elapsed();
            let DispatchedProcess {
                process, warnings, ..
            } = dispatched;
            let mut exec = run_timed(process, deadline, stdio.captures_output()).map_err(|e| {
                MxcError::Sdk(v1::Error::new(
                    v1::ErrorCode::BackendError,
                    format!("waiting for the sandbox to complete failed: {e}"),
                ))
            })?;
            // Tier-selection warnings belong in the same record as the handle's own
            // teardown warnings.
            exec.child.warnings.extend(warnings);
            Ok((exec, handshake_elapsed))
        })?;
        let clock = SessionClock::measured(
            self.budget,
            started.elapsed(),
            handshake_elapsed,
            prompt_wait_during(prompt_baseline, source.prompt_wait()),
        )
        // The supervisor's own time after the child exited (round 2, item 7).
        .with_teardown(exec.teardown_elapsed);

        gate_outcome(tier, exec.child, proof, expectation, clock)
    }
}

/// Launch one session against the listener that owns `proxy_port`.
///
/// This is the seam the supervisor calls, and it is deliberately the only place
/// the two halves meet:
///
/// * the **port** the proxy bound (`127.0.0.1:0`, so the session's own random
///   port) becomes `runtimeConfig.networkProxy`, with `proxy_token` as its
///   `userinfo` so the child can satisfy the proxy's token gate, and
/// * the **same port** decides the guardrail leg — `Required` when a proxy
///   exists, `MustBeAbsent` when it does not ([`ProofExpectation::for_network`]).
///
/// Deriving the leg here rather than taking it from the caller is the point: a
/// hand-picked leg can only make a blocked session prove nothing or a networked
/// session fail a test it could never pass. The proof source is the listener
/// itself — `proxy_handle.counters()` — so the proof cannot come from a
/// different socket than the child was pointed at.
pub fn launch_session(
    source: &dyn ProxyProofSource,
    proxy_port: Option<u16>,
    proxy_token: Option<&str>,
    launcher: &Path,
    budget: SessionBudget,
    input: &MxcSessionInput,
) -> Result<SessionOutcome, MxcError> {
    let backend = supervisor_backend(source, proxy_port, proxy_token, launcher, budget);
    backend.launch(input, ProofExpectation::for_network(proxy_port))
}

/// The request [`launch_session`] would dispatch for this session (P3.0).
///
/// The session-start leaf has to name the tier of the **exact** request before the
/// launch, because a refused launch carries no [`SessionOutcome`] to read it from —
/// and a leaf armed with `tier: null` for a session that dispatched to
/// `base-container` is the omission ADR-0004 guardrail 2 exists to prevent. Both
/// this function and [`launch_session`] build their backend through
/// [`supervisor_backend`], so the request probed here and the request launched
/// there cannot differ: same port, same token, same budget, same launcher.
///
/// Probing is a second `v1::probe` of the same request (the launch probes again,
/// for its own gate). That cost is deliberate: the alternative is either a leaf
/// with no tier on every refusal, or teaching the launch to hand its tier back
/// through the error, which would make the gate's record optional at the call
/// site — the shape [`TierExpectation`] was made a required argument to remove.
pub fn request_for_session(
    source: &dyn ProxyProofSource,
    proxy_port: Option<u16>,
    proxy_token: Option<&str>,
    launcher: &Path,
    budget: SessionBudget,
    input: &MxcSessionInput,
) -> Result<ExecutionRequest, MxcError> {
    supervisor_backend(source, proxy_port, proxy_token, launcher, budget).request_for(input)
}

/// The backend [`launch_session`] builds — the supervisor's own construction, as a
/// named function so guardrail 2's requirement is testable without a container.
///
/// P2.3 review (item 1): `launch_session` used to call `MxcBackend::new`, whose
/// `tier` defaulted to [`TierExpectation::Recorded`] — the fail-open value — so
/// the documented supervisor seam silently ran un-gated while the doc comment
/// claimed it passed `Exactly(REQUIRED_TIER)`. The requirement is now a *required
/// constructor argument*, so no caller can forget it, and this function states
/// the product rule in the one place the product enters the module.
fn supervisor_backend<'a>(
    source: &'a dyn ProxyProofSource,
    proxy_port: Option<u16>,
    proxy_token: Option<&str>,
    launcher: &Path,
    budget: SessionBudget,
) -> MxcBackend<'a> {
    let mut backend = MxcBackend::new(
        source,
        proxy_port,
        launcher,
        // The product rule, stated once, at the one place the product enters this
        // module (P2.3 review, item 1).
        TierExpectation::Exactly(REQUIRED_TIER),
    );
    if let Some(token) = proxy_token {
        backend = backend.with_proxy_token(token);
    }
    // P3.0 decision 3: the deadline comes from the **resolved** configuration
    // (`crate::profile::Limits::session_budget`, which resolves the top-level
    // `limits` terms). Leaving it at
    // `SessionBudget::default()` here would size the container's deadline from the
    // config DEFAULTS while the dialog gate gets the profile's value — the
    // under-reservation that killed a legitimate dialog plus a full workload, and
    // reported the wrong term for it (P2.1 review, item 6).
    backend.with_budget(budget)
}

/// Apply guardrail 1 to a finished child and map it into a [`SessionOutcome`].
///
/// Pure on purpose: this is the one place a proof can turn into a success or an
/// error, so it can be tested with the spike's observed outcomes without
/// spawning a container.
fn gate_outcome(
    tier: TierRecord,
    child: ChildRun,
    proof: ProxyProof,
    expectation: ProofExpectation,
    clock: SessionClock,
) -> Result<SessionOutcome, MxcError> {
    // P2.1: a kill at the deadline is attributed to the term that spent the time,
    // from measurements the supervisor and the listener took — never guessed from
    // the fact that a timeout happened.
    let (exit_code, timeout) = match child.wait {
        WaitResult::Exited(code) => (Some(code), None),
        WaitResult::TimedOut => (None, Some(clock.timeout_reason())),
    };

    let outcome = SessionOutcome {
        exit_code,
        timeout,
        stdout: child.stdout,
        stderr: child.stderr,
        warnings: child.warnings,
        tier,
        proxy_proof: proof,
        expectation,
        // The label above is derived from exactly these numbers (P2.1 review).
        clock,
    };

    // Guardrail 1 first and unconditionally: `warnings: []` and exit 0 are not
    // evidence, so a failed proof poisons every outcome, timeout included. The
    // outcome is built first only so the refusal can CARRY it (P3.0): the session
    // is refused either way, and the workload's own output stays visible.
    if let Err(error) = verify_proxy_proof(proof, expectation) {
        return Err(MxcError::Unproven(Box::new(Unproven { error, outcome })));
    }
    Ok(outcome)
}

#[cfg(test)]
mod tests;

// ---------------------------------------------------------------------------
// Live evidence: a real, unelevated ProcessContainer (ignored by default)
// ---------------------------------------------------------------------------

/// The intent-endpoint proof lives here rather than under `tests/` because this
/// crate has no library target: an integration test cannot import
/// [`MxcBackend`], so the only place a real container can be launched from is a
/// test module inside the crate. It is `#[ignore]`d so the normal suite stays
/// fast:
///
/// ```text
/// cargo build --features mxc-backend --bin saife-launch
/// cargo test  --features mxc-backend -- --ignored
/// ```
///
/// Nothing here needs elevation, and nothing here mutates host state: the
/// container's filesystem policy is a grant *inside* the container, and the
/// scratch directory removes itself.
#[cfg(test)]
mod live;
