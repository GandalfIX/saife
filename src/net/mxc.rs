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
//!   [`launcher_command`] builds `mxc-launch.exe -- "<real command line>"`;
//!   `src/bin/mxc-launch.rs` sets `NO_PROXY`, starts the workload with inherited
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
//!   to be launched. The audit leaf that persists it lands in P2.3.
//! * The **real** proof source is this listener's own counters:
//!   [`LaunchCounters`](crate::net::proxy::LaunchCounters) in `src/net/proxy.rs`
//!   implements [`ProxyProofSource`] (see the impl below), and [`launch_session`]
//!   is the seam that binds one to the other — the port the supervisor bound is
//!   the port the request configures, and the same port decides which guardrail
//!   leg applies.
//! * P1.3's filesystem policy is [`filesystem_policy`]: the workspace is the only
//!   writable grant, the launcher's directory is added automatically
//!   ([`ensure_launcher_grant`]) **before** the deny list is filtered against the
//!   grant set, and the profile's four credential directories plus the configured
//!   deny list become `denied_paths`. A deny that contains a grant (equal to it,
//!   or an ancestor of it) is a hard [`RequestError::DenyCoversGrant`], never a
//!   silent drop — dropping it would leave the rest of the denied tree readable.
//!
//! Not here, by design: the session-start audit leaf (P2.3), the prompt/timeout
//! budget arithmetic (P2.1) and the WinHTTP measurement (P1.5). The per-run token
//! that makes concurrent sessions safe landed in P1.4 and lives where it is
//! enforced: `net::token::RunToken` mints one credential per run and the listener
//! accepts only its own (`net::proxy::classify_auth`). What this module owns is
//! the other half — an overlapping launch epoch is refused with
//! [`MxcError::Concurrency`] rather than splitting one window between two runs.
//! [`build_request`] passes the caller's `timeout_ms` through unchanged —
//! `None` means *no deadline*, because the SDK turns a zero timeout into
//! `INFINITE` (`mxc_common::script_runner::get_timeout_milliseconds`) — and
//! [`MxcBackend`] overrides it only when a budget was set explicitly with
//! [`with_budget`](MxcBackend::with_budget). A backend that was never given a
//! budget therefore never discards the caller's deadline.
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
// `TIER_SOURCE_UNAVAILABLE`, `RequestError`, `MxcError`, `SessionOutcome`,
// `build_request`,
// `process_container_config`, `MxcBackend`.
#![cfg_attr(not(test), allow(dead_code))]

use std::fmt;
use std::path::{Path, PathBuf};

use crate::net::proxy::EpochAlreadyOpen;

use mxc_sdk::v1;
use mxc_sdk::v1::configs::{
    ProcessContainerConfig, ProcessContainerSystemSettings, ProcessContainerUi,
    ProcessContainerUiIsolation,
};
use mxc_sdk::v1::{
    ClipboardPolicy, ContainerRequest, Containment, FilesystemPolicy, NetworkAction,
    NetworkEgressPolicy, NetworkIngressPolicy, NetworkPolicy, NetworkRuntimeConfig, RunOptions,
    UiPolicy, WaitResult,
};

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
/// executable (`src/bin/mxc-launch.rs`).
pub const LAUNCHER_EXE_NAME: &str = "mxc-launch.exe";

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
/// `mxc-launch.exe`. The launcher is deployed beside the supervisor
/// (`target\debug\mxc-launch.exe` in this repo), which means every container
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

/// The container command: the wrapper launcher, with the real workload command
/// line as its single argument.
///
/// The workload's command line travels as **one** argument and the wrapper hands
/// it to `CreateProcessW` verbatim, so it keeps exactly the meaning it would
/// have had as the container command itself.
pub fn launcher_command(launcher: &Path, real_command: &str) -> String {
    format!(
        "{} -- {}",
        quote_windows_arg(&launcher.to_string_lossy()),
        quote_windows_arg(real_command)
    )
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
    /// Wall-clock bound for the whole workload, in milliseconds. `None` — and
    /// `Some(0)` — means **no deadline**: the SDK maps a zero timeout to
    /// `INFINITE` (`mxc_common::script_runner::get_timeout_milliseconds`). P2.1
    /// owns the budget arithmetic; [`build_request`] passes the value through
    /// unchanged, and [`MxcBackend`] overrides it only when it carries an
    /// explicit budget ([`with_budget`](MxcBackend::with_budget)).
    pub timeout_ms: Option<u32>,
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
            .finish()
    }
}

// ---------------------------------------------------------------------------
// P1.3: filesystem policy (workspace-only posture)
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
/// * `readwrite_paths` is exactly the session's working directory — the
///   workspace, and nothing else. Extra writable grants are not derived from
///   the profile: the workspace-only posture is the point of the mapping.
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
    // Before any deny is filtered, never after: the launcher grant is a grant
    // like any other, and `build_request` would otherwise insert it into a
    // request whose deny list was filtered against a grant set missing it.
    ensure_launcher_grant(&mut filesystem, &launcher);

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
/// `accepted` counts **proxy consultations** — connections the proxy handled as
/// a proxy (`CONNECT`, or an absolute-form request) — in the epoch; `tunnels`
/// counts those whose origin dial succeeded (i.e. a real `200 Connection
/// Established` was sent). Both are needed: the spike proved that a proxy
/// 502/403 (unresolvable target, loopback target) and a silently misconfigured
/// container both give `accepted >= 1, tunnels == 0`, and that a container that
/// never reached the proxy gives `accepted == 0` while still exiting 0 with
/// `warnings: []`.
///
/// Deliberately *not* counted: a direct, origin-form request to one of our own
/// loopback endpoints (the D-4 intent endpoints). Serving an endpoint is not a
/// proxy consultation, and counting it would make
/// [`ProofExpectation::MustBeAbsent`] unsatisfiable for exactly the sessions it
/// exists for.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ProxyProof {
    pub accepted: u64,
    pub tunnels: u64,
}

/// What guardrail 1 must observe for this launch (plan decision D3).
///
/// Both legs are hard gates, and the caller **must** supply the right one:
///
/// * [`ProofExpectation::Required`] for a network session (a proxy port is
///   configured): the child must have reached the proxy *and* the proxy must
///   have established at least one tunnel. Derive it with
///   [`ProofExpectation::for_network`].
/// * [`ProofExpectation::MustBeAbsent`] for a blocked / proxy-less session: the
///   proxy must never have been consulted, which is the only positive evidence
///   that a no-network session really did not go out.
///
/// Choosing the wrong leg is itself a hard failure — never a skipped check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofExpectation {
    /// `accepted >= 1 && tunnels >= 1`.
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
    /// The child never reached the proxy in this launch's epoch.
    SessionNotAccepted,
    /// The proxy accepted a connection but never established a tunnel (502/403
    /// or a loopback/HostLoopback misconfiguration).
    TunnelNotEstablished,
    /// `MustBeAbsent` was requested but the proxy *was* consulted for this
    /// launch — a session that was supposed to stay offline went out.
    ProxyConsultedUnexpectedly,
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
            Self::SessionNotAccepted => {
                "guardrail 1: no proxy session was accepted in this launch's epoch — the child \
                 never reached the proxy"
            }
            Self::TunnelNotEstablished => {
                "guardrail 1: the proxy accepted a session but established no CONNECT tunnel"
            }
            Self::ProxyConsultedUnexpectedly => {
                "guardrail 1: the proxy was consulted for a session that must never reach it — \
                 the workload is expected to be blocked"
            }
        };
        f.write_str(msg)
    }
}

impl std::error::Error for GuardError {}

/// The hard gate, in both legs.
///
/// `Required` demands `accepted >= 1 && tunnels >= 1`; `MustBeAbsent` demands
/// `accepted == 0 && tunnels == 0`. Anything else fails the launch.
pub fn verify_proxy_proof(
    proof: ProxyProof,
    expectation: ProofExpectation,
) -> Result<(), GuardError> {
    match expectation {
        ProofExpectation::Required => {
            if proof.accepted == 0 {
                return Err(GuardError::SessionNotAccepted);
            }
            if proof.tunnels == 0 {
                return Err(GuardError::TunnelNotEstablished);
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

    fn proof(&self, epoch: u64) -> ProxyProof {
        match self.counters(epoch) {
            Some(counters) => ProxyProof {
                accepted: counters.consultations,
                tunnels: counters.upstream_established,
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
pub fn probe_tier(request: &ContainerRequest) -> Result<TierRecord, MxcError> {
    let probe = v1::probe(Some(request))?;
    Ok(tier_record(ProbeView::from_probe(&probe)))
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
        /// The grant it contains: the workspace, a declared read-only grant, or
        /// the launcher's directory.
        grant: String,
    },
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
        }
    }
}

impl std::error::Error for RequestError {}

/// An MXC launch failure.
#[derive(Debug)]
pub enum MxcError {
    /// Guardrail 1 refused the launch.
    Guard(GuardError),
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
    pub timed_out: bool,
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
            && !self.timed_out
            && verify_proxy_proof(self.proxy_proof, self.expectation).is_ok()
    }
}

/// The child's result, before the guardrail is applied.
#[derive(Debug, Clone)]
struct ChildRun {
    wait: WaitResult,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    warnings: Vec<String>,
}

// ---------------------------------------------------------------------------
// Request mapping (pure)
// ---------------------------------------------------------------------------

/// The `ProcessContainerConfig` posture, pinned field by field.
///
/// The SDK types are `#[non_exhaustive]` and their `Default` is a *patchable*
/// value, so every field we care about is set here explicitly (plan decision
/// D6) instead of inherited: a bump that changed one of them would otherwise
/// change containment silently. The values are today's SDK defaults and must
/// stay so — `pinned_ui_fields_match_the_sdk_default` is the drift alarm.
fn process_container_config() -> ProcessContainerConfig {
    let mut ui = ProcessContainerUi::default();
    ui.isolation = ProcessContainerUiIsolation::Container;
    ui.desktop_system_control = false;
    ui.system_settings = ProcessContainerSystemSettings::None;
    ui.ime = false;

    let mut config = ProcessContainerConfig::default();
    // No deny-and-record ETL capture: learning mode is a discovery tool, not a
    // containment posture, and it writes a trace.
    config.learning_mode = false;
    // No additional capability SIDs beyond what proxy-only egress implies.
    config.capabilities = Vec::new();
    config.capture_denials = None;
    config.ui = Some(ui);
    // No enumerate-without-read grants.
    config.filesystem = None;
    // Identity-less deployment: `allowedProxyPeer` stays unset (a `host:port`
    // peer fails the request build with `malformed_request`).
    config.network = None;
    config
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
) -> Result<ContainerRequest, RequestError> {
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
    let environment: Vec<(String, String)> = input
        .environment
        .iter()
        .filter(|(key, _)| !is_blocked_env_key(key))
        .cloned()
        .collect();

    let network = match input.network.proxy_port {
        // Proxy-only egress: everything outbound is denied at the container
        // level and the only path out is the supervisor's loopback proxy.
        Some(port) => NetworkPolicy {
            egress: Some(NetworkEgressPolicy {
                default: Some(NetworkAction::Deny),
                allow: None,
                deny: None,
            }),
            // Both are mandatory for proxy-only egress (ADR-0004 constraint).
            ingress: Some(NetworkIngressPolicy {
                default: Some(NetworkAction::Allow),
                host_loopback: Some(NetworkAction::Allow),
            }),
            runtime_config: Some(NetworkRuntimeConfig {
                // With the session token as userinfo: the SDK copies this URL
                // verbatim into the child's HTTP_PROXY/HTTPS_PROXY, and our
                // proxy's token gate ([G-7]) is what it has to satisfy.
                network_proxy: Some(proxy_url(port, input.network.proxy_token.as_deref())?),
            }),
        },
        // No proxy: no network at all, and no host loopback.
        None => NetworkPolicy {
            egress: Some(NetworkEgressPolicy {
                default: Some(NetworkAction::Deny),
                allow: None,
                deny: None,
            }),
            ingress: Some(NetworkIngressPolicy {
                default: Some(NetworkAction::Deny),
                host_loopback: Some(NetworkAction::Deny),
            }),
            runtime_config: None,
        },
    };

    let mut request = ContainerRequest::new(launcher_command(&launcher, &input.command));
    request.filesystem = Some(FilesystemPolicy {
        readwrite_paths: filesystem.readwrite_paths,
        readonly_paths: filesystem.readonly_paths,
        denied_paths: filesystem.denied_paths,
        clear_policy_on_exit: Some(true),
    });
    request.network = Some(network);
    // P3 — the Win32k ban is *this* field, and its default is the trap.
    //
    // `ContainerRequest::ui` is not `processContainer.ui` above: that one is the
    // job-object UI-restriction knob (`isolation`, `desktopSystemControl`,
    // `systemSettings`, `ime`).  This one is the cross-cutting `UiPolicy` whose
    // `disable` flag the backend copies into the process-security-environment
    // spec as `disallow_win32k_system_calls` (mxc-sdk 1.0.1,
    // `backends/process_container/common/base_container_helpers.rs:57`), which
    // the OS applies as `PROCESS_CREATION_MITIGATION_POLICY_WIN32K_SYSTEM_CALL_DISABLE`
    // before the child runs any user-mode code.
    //
    // Leaving the field unset is NOT "no opinion": absence resolves to
    // `UiPolicy::default()`, and that default is `disable: true`
    // (`mxc_common/models.rs:583` for the internal twin, `policy.rs:564` for the
    // public type, and the wire default agrees —
    // `mxc_common/config_parser.rs:1597` `disable: raw_ui.disable.unwrap_or(true)`).
    // So every launch so far shipped the harshest posture, and with Win32k
    // syscalls banned `user32.dll`, `gdi32.dll` and `ole32.dll` fail their
    // `DllMain` with `ERROR_DLL_INIT_FAILED` (1114) and the loader kills the
    // process before `main`. Measured A/B on this exact request, one field
    // different: `powershell.exe -Command "Write-Output FXOK"` exits
    // `0xC0000142` with the default and `0` with `disable: false`, and
    // `dotnet hello.dll` fails to load `coreclr.dll` with `HRESULT 0x8007045A`
    // (0xC0000409) versus printing `HELLO-OK`. `coreclr.dll` statically imports
    // USER32 *and* ole32, so there is no middle setting — it is Win32k syscalls
    // or no CLR, never both.
    //
    // The cost, accepted deliberately and not hidden: the child may now enter
    // Win32k at all — create windows and reach that large kernel attack surface
    // — which is precisely what the mitigation existed to remove. Everything
    // else stays closed: clipboard and input injection are pinned default-deny
    // right here, and the ten `JOB_OBJECT_UILIMIT_*` restrictions
    // `resolve_ui_restrictions` derives from `processContainer.ui` are still
    // emitted. Do not "tidy" this back to the default; the canary test
    // `sdk_ui_policy_default_is_still_the_win32k_ban_we_explicitly_escape` is
    // what tells us if a bump ever moves the default out from under it.
    // Evidence: `docs/backends/process-container/clr-startup-failure.md`.
    request.ui = Some(UiPolicy {
        disable: false,
        // Default-deny: the child keeps no clipboard and cannot inject input.
        clipboard: ClipboardPolicy::None,
        allow_input_injection: false,
    });
    request.timeout_ms = input.timeout_ms;
    // Identity-less deployment: `allowedProxyPeer` is left unset because an
    // unpackaged caller-owned proxy has no package family name, and the
    // identity-scoped form fails the request build with `malformed_request`.
    request.containment = Containment::ProcessContainer(process_container_config());
    request.working_directory = input.working_directory.clone();
    request.environment = Some(environment);
    // D2 — deliberately `Some(true)`. At `mxc-sdk 1.0.1` this block is the
    // user's **profile** environment (`create_default_env_entries` →
    // `CreateEnvironmentBlock(.., bInherit = FALSE)`), never this process's
    // environment, and it is what makes an ordinary workload work at all
    // (PATH/TEMP/USERPROFILE/PSModulePath); `Some(false)` would hand the child a
    // bare allow-list, and the SDK's `validate_required_child_env` exists
    // precisely because that breaks CreateProcessW.
    //
    // It is safe *because* `build_inherited_entries` lays our filtered list on
    // top and then `inject_proxy_vars` strips HTTP_PROXY/HTTPS_PROXY/NO_PROXY/
    // ALL_PROXY (case-insensitive) from the merged block before injecting the
    // configured proxy: no host proxy value can survive into a proxied session.
    // In the proxy-less branch a persisted proxy value does survive, and is
    // inert — `egress.default = deny` and `host_loopback = deny`. Residual risk,
    // accepted: other profile-persisted variables (e.g. a CA-bundle override) do
    // reach the child; filesystem and network policy, not env, are the
    // containment boundary. `NO_PROXY` needs no exception here — the wrapper
    // supplies it (D1).
    request.inherit_default_environment = Some(true);
    Ok(request)
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
    /// `None` when this backend has no budget of its own, so the caller's
    /// [`MxcSessionInput::timeout_ms`] ships untouched. `Some(budget)` is an
    /// explicit decision — including `Some(None)`, which means "no deadline" —
    /// and wins over the caller's value.
    budget: Option<Option<u32>>,
    launcher: PathBuf,
}

impl<'a> MxcBackend<'a> {
    /// A backend for one launch on `proxy_port`, proofed by `proof`.
    pub fn new(
        proof: &'a dyn ProxyProofSource,
        proxy_port: Option<u16>,
        launcher: impl Into<PathBuf>,
    ) -> Self {
        Self {
            proof: Some(proof),
            proxy_port,
            proxy_token: None,
            budget: None,
            launcher: launcher.into(),
        }
    }

    /// A backend with no proof source: every launch is refused by guardrail 1
    /// with [`GuardError::MissingProofSource`]. Exists so that refusal is
    /// expressible rather than accidental.
    pub fn without_proof_source(proxy_port: Option<u16>, launcher: impl Into<PathBuf>) -> Self {
        Self {
            proof: None,
            proxy_port,
            proxy_token: None,
            budget: None,
            launcher: launcher.into(),
        }
    }

    /// Set the wall-clock budget for the whole workload, in milliseconds.
    ///
    /// `Some(ms)` is a deadline and `None` explicitly asks for **no** deadline;
    /// either way the budget wins over the caller's
    /// [`MxcSessionInput::timeout_ms`]. A backend that never calls this leaves
    /// the caller's deadline in force. P2.1 owns the real arithmetic.
    /// The session token the backend's proxy expects, embedded in the proxy URL
    /// the child receives (see [`MxcNetworkInput::proxy_token`]).
    pub fn with_proxy_token(mut self, token: impl Into<String>) -> Self {
        self.proxy_token = Some(token.into());
        self
    }

    pub fn with_budget(mut self, timeout_ms: Option<u32>) -> Self {
        self.budget = Some(timeout_ms);
        self
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
    /// The budget is replaced only when this backend was given one explicitly
    /// ([`with_budget`](MxcBackend::with_budget)). Overwriting it
    /// unconditionally would discard every caller-supplied deadline — and since
    /// `None` means "no deadline", the workload would then run unbounded.
    ///
    /// Returns [`RequestError`] (wrapped in [`MxcError`]) for a command line that
    /// cannot be launched; see [`build_request`].
    pub fn request_for(&self, input: &MxcSessionInput) -> Result<ContainerRequest, MxcError> {
        let mut effective = input.clone();
        effective.network.proxy_port = self.proxy_port;
        // Overriding unconditionally (not `unwrap_or`): a caller-supplied token
        // cannot authenticate against this backend's listener, and shipping it
        // would produce a 407 that reads like a broken proxy.
        effective.network.proxy_token = self.proxy_token.clone();
        if let Some(budget) = self.budget {
            effective.timeout_ms = budget;
        }
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

        // The epoch is opened before the child starts, so guardrail 1 cannot be
        // satisfied by traffic from an earlier launch, and it is closed on every
        // path out of the run (success, SDK error, panic unwind).
        let (exec, proof) = run_in_epoch(source, || {
            v1::run(request, RunOptions::default()).map_err(MxcError::from)
        })?;

        gate_outcome(
            tier,
            ChildRun {
                wait: exec.outcome,
                stdout: exec.stdout,
                stderr: exec.stderr,
                warnings: exec.warnings,
            },
            proof,
            expectation,
        )
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
    input: &MxcSessionInput,
) -> Result<SessionOutcome, MxcError> {
    let mut backend = MxcBackend::new(source, proxy_port, launcher);
    if let Some(token) = proxy_token {
        backend = backend.with_proxy_token(token);
    }
    backend.launch(input, ProofExpectation::for_network(proxy_port))
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
) -> Result<SessionOutcome, MxcError> {
    // Guardrail 1 first and unconditionally: `warnings: []` and exit 0 are not
    // evidence, so a failed proof poisons every outcome, timeout included.
    verify_proxy_proof(proof, expectation)?;

    let (exit_code, timed_out) = match child.wait {
        WaitResult::Exited(code) => (Some(code), false),
        WaitResult::TimedOut => (None, true),
    };

    Ok(SessionOutcome {
        exit_code,
        timed_out,
        stdout: child.stdout,
        stderr: child.stderr,
        warnings: child.warnings,
        tier,
        proxy_proof: proof,
        expectation,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Stand-in launcher path: the mapping is pure, so it never has to exist.
    const TEST_LAUNCHER: &str = r"C:\tools\sandbox\mxc-launch.exe";

    fn build(input: &MxcSessionInput) -> ContainerRequest {
        build_request(input, Path::new(TEST_LAUNCHER)).expect("launchable request")
    }

    fn input() -> MxcSessionInput {
        MxcSessionInput {
            command: "cmd /c echo hi".to_string(),
            working_directory: Some(r"C:\work".to_string()),
            environment: vec![
                ("PATH".to_string(), r"C:\Windows".to_string()),
                ("TEMP".to_string(), r"C:\Temp".to_string()),
            ],
            filesystem: MxcFilesystemInput {
                readwrite_paths: vec![r"C:\work".to_string()],
                readonly_paths: vec![r"C:\ref".to_string()],
                denied_paths: vec![r"C:\Users\marku\.ssh".to_string()],
            },
            network: MxcNetworkInput {
                proxy_port: Some(54_321),
                proxy_token: None,
            },
            timeout_ms: Some(60_000),
        }
    }

    fn tier() -> TierRecord {
        TierRecord {
            tier: Some("base-container".to_string()),
            tier_source: "probe",
            needs_dacl_augmentation: Some(false),
        }
    }

    fn child(wait: WaitResult) -> ChildRun {
        ChildRun {
            wait,
            stdout: b"hi\n".to_vec(),
            stderr: Vec::new(),
            warnings: Vec::new(),
        }
    }

    fn proven() -> ProxyProof {
        ProxyProof {
            accepted: 1,
            tunnels: 1,
        }
    }

    fn untouched() -> ProxyProof {
        ProxyProof {
            accepted: 0,
            tunnels: 0,
        }
    }

    // ---- D1: launcher command construction -------------------------------

    #[test]
    fn launcher_command_puts_the_real_command_line_behind_the_wrapper() {
        let command = launcher_command(Path::new(TEST_LAUNCHER), "cmd /c echo hi");
        assert_eq!(
            command,
            format!(r#"{TEST_LAUNCHER} -- "cmd /c echo hi""#),
            "the real command line must travel as ONE quoted argument"
        );
    }

    #[test]
    fn launcher_command_quotes_a_launcher_path_with_spaces() {
        let command = launcher_command(Path::new(r"C:\Program Files\sb\mxc-launch.exe"), "x.exe");
        assert_eq!(command, r#""C:\Program Files\sb\mxc-launch.exe" -- x.exe"#);
    }

    #[test]
    fn launcher_command_survives_a_command_line_that_contains_quotes() {
        let real = r#"powershell.exe -Command "Start-Sleep -Seconds 1""#;
        let command = launcher_command(Path::new(TEST_LAUNCHER), real);
        assert_eq!(
            command,
            format!(r#"{TEST_LAUNCHER} -- "powershell.exe -Command \"Start-Sleep -Seconds 1\"""#)
        );
    }

    /// A golden-string test, **not** a round trip: it pins the exact text the
    /// quoting algorithm emits for each shape. A round-trip claim needs a parser
    /// (`shell32!CommandLineToArgvW`) this test does not call. The algorithm was
    /// fuzz-verified against that real parser at review time — 200k generated
    /// inputs, argv compared element by element, zero differences — so this test
    /// exists to catch an *edit* to the algorithm, not to re-prove its
    /// correctness.
    #[test]
    fn quoting_matches_the_documented_argv_rules() {
        assert_eq!(quote_windows_arg("simple"), "simple");
        assert_eq!(quote_windows_arg("a b"), "\"a b\"");
        assert_eq!(quote_windows_arg(""), "\"\"");
        // A quote inside the element is escaped, not dropped.
        assert_eq!(quote_windows_arg("a\"b"), "\"a\\\"b\"");
        // Backslashes before a quote are doubled; trailing ones before the
        // closing quote are doubled as well.
        assert_eq!(quote_windows_arg("a\\\"b"), "\"a\\\\\\\"b\"");
        assert_eq!(quote_windows_arg("a b\\"), "\"a b\\\\\"");
        assert_eq!(quote_windows_arg("a\\"), "a\\");
    }

    #[test]
    fn an_empty_command_is_refused_before_a_request_exists() {
        for blank in ["", "   ", "\t\n"] {
            let mut i = input();
            i.command = blank.to_string();
            assert_eq!(
                build_request(&i, Path::new(TEST_LAUNCHER)).expect_err("empty command"),
                RequestError::EmptyCommand,
                "{blank:?} must not become a container command"
            );
        }
    }

    #[test]
    fn a_nul_in_the_command_is_refused_before_a_request_exists() {
        let mut i = input();
        // This is what would silently become `cmd /c echo hi` for the child:
        // CreateProcessW stops at the NUL.
        i.command = "cmd /c echo hi\0 --injected".to_string();
        assert_eq!(
            build_request(&i, Path::new(TEST_LAUNCHER)).expect_err("NUL command"),
            RequestError::NulInCommand,
            "a NUL would truncate the command line at the OS boundary"
        );
    }

    #[test]
    fn request_for_reports_a_refused_command_as_a_typed_error() {
        let source = RecordingSource::default();
        let backend = MxcBackend::new(&source, Some(49_152), TEST_LAUNCHER);
        let mut i = input();
        i.command = "  ".to_string();

        let err = backend.request_for(&i).expect_err("empty command");
        assert!(
            matches!(err, MxcError::Request(RequestError::EmptyCommand)),
            "got {err:?}"
        );
        // `launch` surfaces this text, so it must name the cause.
        assert!(err.to_string().contains("empty"), "got {err}");
    }

    #[test]
    fn the_launcher_directory_is_the_grant_a_caller_must_declare() {
        assert_eq!(
            launcher_grant(Path::new(TEST_LAUNCHER)).as_deref(),
            Some(r"C:\tools\sandbox")
        );
        assert_eq!(
            launcher_grant(Path::new("mxc-launch.exe")),
            None,
            "a bare file name has no directory to grant"
        );
    }

    // ---- P0.2: request mapping -------------------------------------------

    #[test]
    fn request_carries_working_directory_and_timeout() {
        let req = build(&input());
        assert_eq!(req.working_directory.as_deref(), Some(r"C:\work"));
        assert_eq!(req.timeout_ms, Some(60_000));
    }

    #[test]
    fn request_command_is_the_wrapper_not_the_workload() {
        let req = build(&input());
        assert_eq!(
            req.command,
            launcher_command(Path::new(TEST_LAUNCHER), "cmd /c echo hi")
        );
        assert_ne!(req.command, "cmd /c echo hi");
        assert!(req.command.starts_with(TEST_LAUNCHER));
        assert!(
            req.command.ends_with(r#"-- "cmd /c echo hi""#),
            "the workload command line is the wrapper's single argument: {}",
            req.command
        );
    }

    #[test]
    fn request_selects_process_container_without_a_proxy_peer() {
        let req = build(&input());
        let Containment::ProcessContainer(cfg) = &req.containment else {
            panic!(
                "expected Containment::ProcessContainer, got {:?}",
                req.containment
            );
        };
        // Identity-less deployment: allowedProxyPeer must stay unset, otherwise
        // the request is refused with `malformed_request`.
        assert!(
            cfg.network
                .as_ref()
                .and_then(|n| n.allowed_proxy_peer.as_ref())
                .is_none(),
            "allowedProxyPeer must never be set for an unpackaged proxy"
        );
    }

    #[test]
    fn request_denies_egress_by_default_and_routes_through_loopback_proxy() {
        let req = build(&input());
        let net = req.network.as_ref().expect("network policy");
        let egress = net.egress.as_ref().expect("egress");
        assert_eq!(egress.default, Some(NetworkAction::Deny));
        let ingress = net.ingress.as_ref().expect("ingress");
        assert_eq!(ingress.default, Some(NetworkAction::Allow));
        assert_eq!(ingress.host_loopback, Some(NetworkAction::Allow));
        let runtime = net.runtime_config.as_ref().expect("runtime config");
        assert_eq!(
            runtime.network_proxy.as_deref(),
            Some("http://127.0.0.1:54321")
        );
    }

    #[test]
    fn request_without_a_proxy_keeps_loopback_closed() {
        let mut i = input();
        i.network.proxy_port = None;
        let req = build(&i);
        let net = req.network.as_ref().expect("network policy");
        assert_eq!(
            net.egress.as_ref().and_then(|e| e.default),
            Some(NetworkAction::Deny)
        );
        let ingress = net.ingress.as_ref().expect("ingress");
        assert_eq!(ingress.host_loopback, Some(NetworkAction::Deny));
        assert!(
            net.runtime_config
                .as_ref()
                .and_then(|r| r.network_proxy.as_deref())
                .is_none(),
            "no proxy port => no networkProxy"
        );
    }

    /// Invariant 5 / ADR-0004: the host's proxy environment must never cross
    /// into the container. MXC injects its own proxy env; a host value would
    /// point the child at a proxy we do not control.
    #[test]
    fn host_proxy_env_is_never_copied_into_the_request() {
        let mut i = input();
        i.environment = vec![
            ("PATH".to_string(), r"C:\Windows".to_string()),
            (
                "HTTP_PROXY".to_string(),
                "http://host-proxy:3128".to_string(),
            ),
            (
                "HTTPS_PROXY".to_string(),
                "http://host-proxy:3128".to_string(),
            ),
            (
                "ALL_PROXY".to_string(),
                "socks5://host-proxy:1080".to_string(),
            ),
            ("NO_PROXY".to_string(), "example.com".to_string()),
            (
                "http_proxy".to_string(),
                "http://lower-host-proxy:3128".to_string(),
            ),
            (
                "https_proxy".to_string(),
                "http://lower-host-proxy:3128".to_string(),
            ),
            (
                "all_proxy".to_string(),
                "socks5://lower-host-proxy:1080".to_string(),
            ),
            ("no_proxy".to_string(), "localhost".to_string()),
            (
                "Http_Proxy".to_string(),
                "http://mixed-host-proxy:3128".to_string(),
            ),
        ];
        let req = build(&i);
        let env = req.environment.as_ref().expect("explicit environment list");
        // Explicit set equality, not a re-run of the production predicate: this
        // fails for a leaked key *and* for a key the filter wrongly drops.
        let mut surviving: Vec<&str> = env.iter().map(|(key, _)| key.as_str()).collect();
        surviving.sort_unstable();
        assert_eq!(surviving, ["PATH"], "exact surviving key set: {env:?}");
        // The allow-list still carries the legitimate entry, value included.
        assert!(env.iter().any(|(k, v)| k == "PATH" && v == r"C:\Windows"));
        assert_eq!(env.len(), 1, "only PATH should survive: {env:?}");
    }

    #[test]
    fn environment_is_always_an_explicit_list_never_none() {
        let mut i = input();
        i.environment.clear();
        let req = build(&i);
        assert_eq!(
            req.environment,
            Some(Vec::new()),
            "an empty allow-list must be explicit, not `None` (backend default)"
        );
        // D2: the profile default block is kept deliberately — the SDK strips
        // every proxy name from it before injecting ours.
        assert_eq!(req.inherit_default_environment, Some(true));
    }

    #[test]
    fn declared_grants_are_carried_and_the_launcher_is_granted_automatically() {
        let req = build(&input());
        let fs = req.filesystem.as_ref().expect("filesystem policy");
        assert_eq!(fs.readwrite_paths, vec![r"C:\work".to_string()]);
        assert_eq!(
            fs.readonly_paths,
            vec![r"C:\ref".to_string(), r"C:\tools\sandbox".to_string()],
            "the caller's grants keep their order; the launcher's directory is appended"
        );
        assert_eq!(fs.denied_paths, vec![r"C:\Users\marku\.ssh".to_string()]);
    }

    // ---- D6: the config posture is pinned, not defaulted ------------------

    #[test]
    fn process_container_config_pins_every_field_explicitly() {
        let cfg = process_container_config();
        assert!(!cfg.learning_mode);
        assert!(cfg.capabilities.is_empty());
        assert!(cfg.capture_denials.is_none());
        assert!(cfg.filesystem.is_none());
        assert!(cfg.network.is_none());

        let ui = cfg.ui.expect("the ui posture is always stated");
        assert_eq!(ui.isolation, ProcessContainerUiIsolation::Container);
        assert!(!ui.desktop_system_control);
        assert_eq!(ui.system_settings, ProcessContainerSystemSettings::None);
        assert!(!ui.ime);
    }

    /// Drift alarm, not a tautology: it fails when a patch bump changes a
    /// `#[non_exhaustive]` default we pinned, which is the moment to re-decide
    /// the posture instead of silently inheriting the new one.
    #[test]
    fn pinned_ui_fields_match_the_sdk_default_they_were_taken_from() {
        let sdk = ProcessContainerConfig::default();
        let pinned = process_container_config();
        assert_eq!(pinned.ui, sdk.ui);
        assert_eq!(pinned.capabilities, sdk.capabilities);
        assert_eq!(pinned.capture_denials, sdk.capture_denials);
    }

    // ---- P3: the Win32k ban is a UI field, and its default is the trap -----

    /// The `processContainer.ui` block pinned above is the **job-object** knob
    /// (`isolation`, `desktopSystemControl`, `systemSettings`, `ime`). The
    /// Win32k ban is a different field — the cross-cutting `ContainerRequest::ui`
    /// — and leaving it unset is not "no opinion": the SDK resolves absence to
    /// `UiPolicy::default()`, which is `disable: true`, and the PSEC path turns
    /// that into `PROCESS_CREATION_MITIGATION_POLICY_WIN32K_SYSTEM_CALL_DISABLE`.
    /// A request that states nothing therefore ships the harshest posture.
    #[test]
    fn build_request_permits_win32k_but_keeps_clipboard_and_injection_closed() {
        let request = build(&input());
        let ui = request
            .ui
            .expect("the UI policy is stated on the request, not inherited");
        assert!(
            !ui.disable,
            "a Win32k ban makes every child that loads user32/gdi32/ole32 die at load"
        );
        assert_eq!(
            ui.clipboard,
            ClipboardPolicy::None,
            "clipboard stays default-deny"
        );
        assert!(
            !ui.allow_input_injection,
            "input injection stays default-deny"
        );
    }

    /// Canary on the SDK default the explicit set above exists to escape.
    ///
    /// If this ever fails, `mxc-sdk` changed the trap: `UiPolicy::default()`
    /// stopped meaning "ban Win32k". Delete this canary and the explicit
    /// `request.ui` assignment in [`build_request`], then re-read the comment
    /// there and `docs/backends/process-container/clr-startup-failure.md` — the
    /// explicit set would then be pinning a posture the default already gives,
    /// and the "lost containment" note would be describing a default, not a
    /// choice.
    #[test]
    fn sdk_ui_policy_default_is_still_the_win32k_ban_we_explicitly_escape() {
        assert!(
            UiPolicy::default().disable,
            "mxc-sdk changed UiPolicy::default() to disable = false: delete this canary and the \
             explicit request.ui in build_request"
        );
    }

    // ---- P0.3 / D3: guardrail 1, both legs -------------------------------

    /// `Required` + pass.
    #[test]
    fn required_passes_when_the_child_reached_the_proxy_and_a_tunnel_was_established() {
        verify_proxy_proof(proven(), ProofExpectation::Required).expect("accepted=1 tunnels=1");
        verify_proxy_proof(
            ProxyProof {
                accepted: 3,
                tunnels: 2,
            },
            ProofExpectation::Required,
        )
        .expect("more traffic than the minimum is fine");
    }

    /// `Required` + fail (two distinct shapes, two distinct errors).
    #[test]
    fn required_fails_without_an_accepted_session_or_without_a_tunnel() {
        assert_eq!(
            verify_proxy_proof(untouched(), ProofExpectation::Required).expect_err("accepted=0"),
            GuardError::SessionNotAccepted
        );
        // The structural case the spike proved matters: proxy 502 (unresolvable
        // target) and loopback-denied both give accepted=1, tunnels=0.
        assert_eq!(
            verify_proxy_proof(
                ProxyProof {
                    accepted: 1,
                    tunnels: 0,
                },
                ProofExpectation::Required
            )
            .expect_err("tunnels=0"),
            GuardError::TunnelNotEstablished
        );
    }

    /// `MustBeAbsent` + pass.
    #[test]
    fn must_be_absent_passes_only_when_the_proxy_was_never_consulted() {
        verify_proxy_proof(untouched(), ProofExpectation::MustBeAbsent)
            .expect("a blocked session that never reached the proxy is the proven case");
    }

    /// `MustBeAbsent` + fail.
    #[test]
    fn must_be_absent_fails_as_soon_as_the_proxy_is_consulted() {
        for proof in [
            ProxyProof {
                accepted: 1,
                tunnels: 0,
            },
            ProxyProof {
                accepted: 1,
                tunnels: 1,
            },
        ] {
            assert_eq!(
                verify_proxy_proof(proof, ProofExpectation::MustBeAbsent)
                    .expect_err("a consulted proxy must fail an offline session"),
                GuardError::ProxyConsultedUnexpectedly,
                "accepted={} tunnels={}",
                proof.accepted,
                proof.tunnels
            );
        }
    }

    #[test]
    fn the_expectation_follows_the_network_posture() {
        assert_eq!(
            ProofExpectation::for_network(Some(8080)),
            ProofExpectation::Required
        );
        assert_eq!(
            ProofExpectation::for_network(None),
            ProofExpectation::MustBeAbsent
        );
    }

    #[test]
    fn all_four_expectation_combinations_are_decided_by_the_gate() {
        // required+pass, required+fail, absent+pass, absent+fail.
        let cases = [
            (ProofExpectation::Required, proven(), true),
            (
                ProofExpectation::Required,
                ProxyProof {
                    accepted: 1,
                    tunnels: 0,
                },
                false,
            ),
            (ProofExpectation::MustBeAbsent, untouched(), true),
            (
                ProofExpectation::MustBeAbsent,
                ProxyProof {
                    accepted: 0,
                    tunnels: 1,
                },
                false,
            ),
        ];
        for (expectation, proof, should_pass) in cases {
            assert_eq!(
                verify_proxy_proof(proof, expectation).is_ok(),
                should_pass,
                "{expectation:?} with accepted={} tunnels={}",
                proof.accepted,
                proof.tunnels
            );
        }
    }

    /// The silent-misconfiguration case: the SDK reported exit 0 with no
    /// warnings, yet no tunnel was established. Success must be impossible.
    #[test]
    fn exited_zero_without_a_tunnel_is_an_error() {
        let err = gate_outcome(
            tier(),
            child(WaitResult::Exited(0)),
            ProxyProof {
                accepted: 1,
                tunnels: 0,
            },
            ProofExpectation::Required,
        )
        .expect_err("exit 0 must not mask a failed proof");
        assert!(matches!(
            err,
            MxcError::Guard(GuardError::TunnelNotEstablished)
        ));
    }

    #[test]
    fn exited_zero_with_a_proven_tunnel_is_a_success() {
        let outcome = gate_outcome(
            tier(),
            child(WaitResult::Exited(0)),
            proven(),
            ProofExpectation::Required,
        )
        .expect("proven launch");
        assert!(outcome.success());
        assert_eq!(outcome.exit_code, Some(0));
        assert!(!outcome.timed_out);
        assert_eq!(outcome.stdout, b"hi\n");
        assert!(outcome.stderr.is_empty());
        // Container warnings are carried for the audit trail, never as evidence
        // of reachability (ADR-0004): the proof below is what gates the launch.
        assert!(outcome.warnings.is_empty());
        assert_eq!(outcome.proxy_proof, proven());
        assert_eq!(outcome.expectation, ProofExpectation::Required);
        assert_eq!(outcome.tier.tier.as_deref(), Some("base-container"));
    }

    #[test]
    fn an_offline_session_that_stayed_offline_is_a_success() {
        let outcome = gate_outcome(
            tier(),
            child(WaitResult::Exited(0)),
            untouched(),
            ProofExpectation::MustBeAbsent,
        )
        .expect("a blocked session that never reached the proxy");
        assert!(outcome.success());
        assert_eq!(outcome.expectation, ProofExpectation::MustBeAbsent);
    }

    /// Hand-built success shape (exit 0, no timeout) with an unproven launch:
    /// `success()` must consult the proof, for either leg.
    #[test]
    fn success_shaped_outcome_without_a_proof_is_not_a_success() {
        let cases = [
            (ProofExpectation::Required, untouched()),
            (
                ProofExpectation::Required,
                ProxyProof {
                    accepted: 1,
                    tunnels: 0,
                },
            ),
            (
                ProofExpectation::MustBeAbsent,
                ProxyProof {
                    accepted: 1,
                    tunnels: 0,
                },
            ),
        ];
        for (expectation, proof) in cases {
            let outcome = SessionOutcome {
                exit_code: Some(0),
                timed_out: false,
                stdout: Vec::new(),
                stderr: Vec::new(),
                warnings: Vec::new(),
                tier: tier(),
                proxy_proof: proof,
                expectation,
            };
            assert!(
                !outcome.success(),
                "an unproven outcome ({expectation:?}, accepted={}, tunnels={}) must never \
                 report success",
                proof.accepted,
                proof.tunnels
            );
        }
    }

    #[test]
    fn non_zero_exit_is_carried_through_and_is_not_a_success() {
        let outcome = gate_outcome(
            tier(),
            child(WaitResult::Exited(3)),
            proven(),
            ProofExpectation::Required,
        )
        .expect("proven launch");
        assert_eq!(outcome.exit_code, Some(3));
        assert!(!outcome.success());
    }

    #[test]
    fn timed_out_child_maps_to_no_exit_code() {
        let outcome = gate_outcome(
            tier(),
            child(WaitResult::TimedOut),
            proven(),
            ProofExpectation::Required,
        )
        .expect("proven launch");
        assert!(outcome.timed_out);
        assert_eq!(outcome.exit_code, None);
        assert!(!outcome.success());
    }

    #[test]
    fn a_failed_proof_fails_even_a_timed_out_child() {
        let err = gate_outcome(
            tier(),
            child(WaitResult::TimedOut),
            untouched(),
            ProofExpectation::Required,
        )
        .expect_err("proof gate applies to every outcome");
        assert!(matches!(
            err,
            MxcError::Guard(GuardError::SessionNotAccepted)
        ));
    }

    #[test]
    fn launch_without_a_proof_source_is_an_error_before_the_child_starts() {
        let err = MxcBackend::without_proof_source(Some(54_321), TEST_LAUNCHER)
            .launch(&input(), ProofExpectation::Required)
            .expect_err("no proof source must refuse the launch");
        assert!(
            matches!(err, MxcError::Guard(GuardError::MissingProofSource)),
            "got {err:?}"
        );
    }

    // ---- D4: backend state + epoch lifecycle ----------------------------

    #[derive(Default)]
    struct RecordingSource {
        next: AtomicU64,
        /// The window that is open, if any: this fake enforces the same
        /// no-overlap contract the real `LaunchCounters` does (P1.4).
        active: Mutex<Option<u64>>,
        epochs: Mutex<Vec<u64>>,
        /// `(epoch, proof reads at close time)` — the read-then-close order is
        /// part of the contract, so it is recorded rather than assumed.
        closes: Mutex<Vec<(u64, u64)>>,
        reads: AtomicU64,
        proofs: Mutex<HashMap<u64, ProxyProof>>,
    }

    impl RecordingSource {
        fn set_proof(&self, epoch: u64, proof: ProxyProof) {
            self.proofs.lock().unwrap().insert(epoch, proof);
        }

        fn epochs(&self) -> Vec<u64> {
            self.epochs.lock().unwrap().clone()
        }

        fn closes(&self) -> Vec<(u64, u64)> {
            self.closes.lock().unwrap().clone()
        }
    }

    impl ProxyProofSource for RecordingSource {
        fn begin_launch(&self) -> Result<u64, EpochAlreadyOpen> {
            let mut active = self.active.lock().unwrap();
            if let Some(open) = *active {
                return Err(EpochAlreadyOpen { active: open });
            }
            let epoch = self.next.fetch_add(1, Ordering::SeqCst) + 1;
            *active = Some(epoch);
            self.epochs.lock().unwrap().push(epoch);
            Ok(epoch)
        }

        fn proof(&self, epoch: u64) -> ProxyProof {
            self.reads.fetch_add(1, Ordering::SeqCst);
            self.proofs
                .lock()
                .unwrap()
                .get(&epoch)
                .copied()
                .unwrap_or_default()
        }

        fn close_launch(&self, epoch: u64) {
            // Read-then-close ordering is part of the contract, so the read
            // count is captured before the window is released.
            let reads = self.reads.load(Ordering::SeqCst);
            let mut active = self.active.lock().unwrap();
            if *active == Some(epoch) {
                *active = None;
            }
            self.closes.lock().unwrap().push((epoch, reads));
        }
    }

    #[test]
    fn a_successful_run_opens_one_epoch_and_closes_it_after_reading_the_proof() {
        let source = RecordingSource::default();
        let (value, proof) = run_in_epoch(&source, || Ok::<_, MxcError>(7)).expect("body ran");
        assert_eq!(value, 7);
        assert_eq!(proof, untouched());
        assert_eq!(source.epochs(), vec![1]);
        // Closed exactly once, and only after the counters were read.
        assert_eq!(source.closes(), vec![(1, 1)]);
    }

    /// The defect D4 names: a `run` error must not abandon an open epoch.
    #[test]
    fn a_failed_run_still_closes_the_epoch() {
        let source = RecordingSource::default();
        let err = run_in_epoch(&source, || {
            Err::<(), _>(MxcError::Guard(GuardError::SessionNotAccepted))
        })
        .expect_err("body failed");
        assert!(matches!(
            err,
            MxcError::Guard(GuardError::SessionNotAccepted)
        ));
        assert_eq!(source.epochs(), vec![1], "the epoch was opened");
        assert_eq!(
            source.closes().len(),
            1,
            "the epoch must be closed on the error path too: {:?}",
            source.closes()
        );
        assert_eq!(source.closes()[0].0, 1);
    }

    #[test]
    fn the_body_runs_while_the_epoch_is_open() {
        let source = RecordingSource::default();
        run_in_epoch(&source, || {
            assert_eq!(source.epochs(), vec![1], "opened before the child starts");
            assert!(
                source.closes().is_empty(),
                "not closed before the child ends"
            );
            Ok::<_, MxcError>(())
        })
        .expect("body ran");
    }

    #[test]
    fn a_panic_in_the_body_still_closes_the_epoch() {
        let source = RecordingSource::default();
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            run_in_epoch(&source, || -> Result<(), MxcError> { panic!("sdk bug") })
        }));
        assert!(outcome.is_err(), "the panic propagates");
        assert_eq!(
            source.closes().len(),
            1,
            "the guard closes the epoch while unwinding: {:?}",
            source.closes()
        );
    }

    /// `close_launch` is caller-supplied. A panic out of `EpochGuard::drop`
    /// while the body is already unwinding would abort the process; the guard
    /// catches it and lets the body's panic continue.
    #[test]
    fn a_panicking_close_does_not_abort_the_unwind() {
        struct PanickyClose;

        impl ProxyProofSource for PanickyClose {
            fn begin_launch(&self) -> Result<u64, EpochAlreadyOpen> {
                Ok(1)
            }

            fn proof(&self, _epoch: u64) -> ProxyProof {
                untouched()
            }

            fn close_launch(&self, _epoch: u64) {
                panic!("close_launch blew up");
            }
        }

        let source = PanickyClose;
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            run_in_epoch(&source, || -> Result<(), MxcError> { panic!("sdk bug") })
        }));
        assert!(
            outcome.is_err(),
            "the body's panic still propagates; the close's panic was swallowed"
        );
    }

    /// Each launch opens its own epoch, and a new epoch starts empty: the fake's
    /// proof for epoch 1 must not leak into the launch that opens epoch 2.
    ///
    /// The old form of this test opened an epoch by hand and then ran a launch:
    /// that sequence is exactly the overlap P1.4 now refuses, so the property is
    /// restated against the ids the fake assigns instead.
    #[test]
    fn a_new_epoch_does_not_inherit_an_earlier_launch_traffic() {
        let source = RecordingSource::default();
        source.set_proof(1, proven());
        let (_, first) = run_in_epoch(&source, || Ok::<_, MxcError>(())).expect("body ran");
        assert_eq!(first, proven(), "epoch 1 is the seeded one");
        let (_, second) = run_in_epoch(&source, || Ok::<_, MxcError>(())).expect("body ran");
        assert_eq!(
            second,
            untouched(),
            "epoch 2 starts empty even though epoch 1 saw a tunnel"
        );
        assert_eq!(source.epochs(), vec![1, 2]);
    }

    /// P1.4: a launch that would overlap an open epoch is refused by name,
    /// before the body runs, and leaves the open window alone.
    ///
    /// Without the refusal the second launch opened epoch 2 and the first
    /// launch's traffic was split silently between two windows.
    #[test]
    fn an_overlapping_launch_is_refused_and_leaves_the_open_window_alone() {
        let source = RecordingSource::default();
        let open = source.begin_launch().expect("the launch in flight");
        let err = run_in_epoch(&source, || Ok::<_, MxcError>(1))
            .expect_err("a second concurrent launch must be refused");
        match err {
            MxcError::Concurrency(e) => assert_eq!(
                e,
                EpochAlreadyOpen { active: open },
                "the refusal must name the open epoch"
            ),
            other => panic!("expected the named concurrency error, got {other:?}"),
        }
        assert!(
            err.to_string().contains("still open"),
            "the message must name the condition: {err}"
        );
        assert_eq!(
            source.epochs(),
            vec![open],
            "no epoch was opened for the refusal"
        );
        assert!(source.closes().is_empty(), "the open window was not closed");
        assert_eq!(
            source.active.lock().unwrap().as_ref(),
            Some(&open),
            "the launch in flight still owns the window"
        );
    }

    #[test]
    fn nothing_is_opened_when_the_launch_is_refused_up_front() {
        // No proof source at all.
        let _ = MxcBackend::without_proof_source(Some(54_321), TEST_LAUNCHER)
            .launch(&input(), ProofExpectation::Required);

        // Unsatisfiable expectation: `Required` with no proxy port.
        let source = RecordingSource::default();
        let err = MxcBackend::new(&source, None, TEST_LAUNCHER)
            .launch(&input(), ProofExpectation::Required)
            .expect_err("Required without a proxy can never pass");
        assert!(
            matches!(err, MxcError::Guard(GuardError::RequiredWithoutProxy)),
            "got {err:?}"
        );
        assert!(
            source.epochs().is_empty(),
            "an unsatisfiable expectation must be refused before the child starts"
        );
        assert!(source.closes().is_empty());
    }

    #[test]
    fn the_backend_owns_the_proxy_port_and_the_budget() {
        let source = RecordingSource::default();
        let backend =
            MxcBackend::new(&source, Some(49_152), TEST_LAUNCHER).with_budget(Some(1_000));
        let mut i = input();
        i.network.proxy_port = Some(1); // a caller-supplied lookalike
        i.timeout_ms = Some(999_999);

        let req = backend.request_for(&i).expect("launchable request");
        assert_eq!(
            req.network
                .as_ref()
                .and_then(|n| n.runtime_config.as_ref())
                .and_then(|r| r.network_proxy.as_deref()),
            Some("http://127.0.0.1:49152"),
            "the request must point at the proxy this backend proves"
        );
        assert_eq!(req.timeout_ms, Some(1_000), "the backend's budget wins");
        assert_eq!(backend.proxy_port(), Some(49_152));
        assert_eq!(backend.launcher(), Path::new(TEST_LAUNCHER));
    }

    #[test]
    fn a_caller_supplied_timeout_survives_a_backend_with_no_budget() {
        let source = RecordingSource::default();
        // No `with_budget`: this backend has no opinion, so the caller's
        // deadline is the one that must ship. Overwriting it with `None` would
        // have discarded it *and* removed the deadline (None = no deadline).
        let backend = MxcBackend::new(&source, Some(49_152), TEST_LAUNCHER);
        let mut i = input();
        i.timeout_ms = Some(1_500);

        let req = backend.request_for(&i).expect("launchable request");
        assert_eq!(
            req.timeout_ms,
            Some(1_500),
            "an unset backend budget must not discard the caller's deadline"
        );
    }

    #[test]
    fn an_explicit_budget_wins_over_the_caller_timeout_in_both_directions() {
        let source = RecordingSource::default();
        let mut i = input();
        i.timeout_ms = Some(999_999);

        let capped = MxcBackend::new(&source, Some(49_152), TEST_LAUNCHER).with_budget(Some(250));
        assert_eq!(
            capped
                .request_for(&i)
                .expect("launchable request")
                .timeout_ms,
            Some(250),
            "an explicit budget narrows the caller's deadline"
        );

        // `with_budget(None)` is a decision ("no deadline"), not a missing value.
        let unbounded = MxcBackend::new(&source, Some(49_152), TEST_LAUNCHER).with_budget(None);
        assert_eq!(
            unbounded
                .request_for(&i)
                .expect("launchable request")
                .timeout_ms,
            None,
            "an explicit `None` budget must win over a caller-supplied timeout"
        );
    }

    #[test]
    fn the_backend_and_its_proof_source_are_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>(_: &T) {}
        fn assert_trait_object(_: &(dyn ProxyProofSource + Send + Sync)) {}

        let source = RecordingSource::default();
        let backend = MxcBackend::new(&source, Some(1), TEST_LAUNCHER);
        assert_send_sync(&backend);
        assert_send_sync(&source);
        assert_trait_object(&source);
    }

    // ---- P0.4: guardrail 2 ----------------------------------------------

    #[test]
    fn a_probed_tier_is_recorded_with_source_probe() {
        let record = tier_record(ProbeView {
            tier: Some("base-container"),
            needs_dacl_augmentation: Some(false),
        });
        assert_eq!(record.tier.as_deref(), Some("base-container"));
        assert_eq!(record.tier_source, "probe");
        assert_eq!(record.needs_dacl_augmentation, Some(false));
    }

    #[test]
    fn dacl_augmentation_is_recorded_when_the_probe_reports_it() {
        let record = tier_record(ProbeView {
            tier: Some("appcontainer-dacl"),
            needs_dacl_augmentation: Some(true),
        });
        assert_eq!(record.tier.as_deref(), Some("appcontainer-dacl"));
        assert_eq!(record.needs_dacl_augmentation, Some(true));
    }

    #[test]
    fn an_unnameable_tier_is_recorded_as_unavailable_not_as_a_ceiling() {
        let record = tier_record(ProbeView {
            tier: None,
            needs_dacl_augmentation: None,
        });
        assert_eq!(record.tier, None);
        assert_eq!(record.tier_source, "unavailable");
        // A probe that declined to state it must not be recorded as `false`.
        assert_eq!(record.needs_dacl_augmentation, None);
    }

    // ---- P1 wave 2 B: the launcher grant is never the caller's job -------

    #[test]
    fn a_caller_that_omits_the_launcher_grant_still_gets_a_launchable_request() {
        let source = RecordingSource::default();
        let backend = MxcBackend::new(&source, Some(49_152), TEST_LAUNCHER);
        let mut i = input();
        i.filesystem.readonly_paths.clear();

        let req = backend.request_for(&i).expect("launchable request");
        let fs = req.filesystem.as_ref().expect("filesystem policy");
        assert_eq!(
            fs.readonly_paths,
            vec![r"C:\tools\sandbox".to_string()],
            "without this grant the container cannot execute the launcher and the launch fails \
             with an opaque policy denial"
        );
    }

    #[test]
    fn a_declared_launcher_grant_is_not_duplicated() {
        let mut fs = MxcFilesystemInput {
            readonly_paths: vec![r"c:/TOOLS/sandbox/".to_string()],
            ..Default::default()
        };
        assert!(
            !ensure_launcher_grant(&mut fs, Path::new(TEST_LAUNCHER)),
            "case and separator variants are the same grant"
        );
        assert_eq!(fs.readonly_paths.len(), 1);
    }

    #[test]
    fn a_bare_launcher_file_name_adds_no_grant() {
        let mut fs = MxcFilesystemInput::default();
        assert!(!ensure_launcher_grant(&mut fs, Path::new("mxc-launch.exe")));
        assert!(
            fs.readonly_paths.is_empty(),
            "there is no directory to grant, and an empty path in the request would be worse"
        );
    }

    // ---- P1 wave 2 C: filesystem policy (workspace-only posture) ---------

    const TEST_WORKSPACE: &str = r"C:\work";
    const PROFILE: &str = r"C:\Users\marku";
    /// What [`ensure_launcher_grant`] derives from `TEST_LAUNCHER`.
    const TEST_LAUNCHER_DIR: &str = r"C:\tools\sandbox";

    fn policy() -> MxcFilesystemInput {
        filesystem_policy(
            Path::new(TEST_WORKSPACE),
            &[r"C:\ref".to_string()],
            &[r"C:\secrets".to_string()],
            Some(Path::new(PROFILE)),
            Path::new(TEST_LAUNCHER),
        )
        .expect("no deny in this policy contains a grant")
    }

    #[test]
    fn the_workspace_is_the_only_writable_grant_and_declared_reads_are_kept() {
        let fs = policy();
        assert_eq!(fs.readwrite_paths, vec![TEST_WORKSPACE.to_string()]);
        assert_eq!(
            fs.readonly_paths,
            vec![r"C:\ref".to_string(), TEST_LAUNCHER_DIR.to_string()],
            "declared read-only grants are carried as declared, and the launcher's directory is \
             a grant from policy time on — the deny filter below runs against it"
        );
    }

    #[test]
    fn profile_credential_directories_are_denied() {
        let denied = policy().denied_paths;
        for dir in PROFILE_SECRET_DIRS {
            let expected = format!(r"C:\Users\marku\{dir}");
            assert!(
                denied.contains(&expected),
                "{dir} holds credentials and must be denied: {denied:?}"
            );
        }
        assert!(
            denied.contains(&r"C:\secrets".to_string()),
            "the configured deny list is not optional: {denied:?}"
        );
    }

    #[test]
    fn configured_denies_are_deduplicated_case_insensitively() {
        let fs = filesystem_policy(
            Path::new(TEST_WORKSPACE),
            &[],
            &[
                r"C:\secrets".to_string(),
                r"c:\SECRETS\".to_string(),
                r"\\?\C:\secrets.".to_string(),
            ],
            None,
            Path::new(TEST_LAUNCHER),
        )
        .expect("a deny that contains no grant is kept");
        assert_eq!(
            fs.denied_paths,
            vec![r"C:\secrets".to_string()],
            "case, a trailing separator, a verbatim prefix and a trailing dot are one deny"
        );
        assert!(
            !fs.denied_paths.iter().any(|d| d.contains(".ssh")),
            "no profile means no profile denies: {:?}",
            fs.denied_paths
        );
    }

    /// A deny that *is* a grant sits on the boundary of "contains a grant": it can
    /// be neither honoured nor dropped, so it is refused by name.
    #[test]
    fn a_deny_equal_to_a_grant_is_refused() {
        let err = filesystem_policy(
            Path::new(TEST_WORKSPACE),
            &[],
            &[r"c:/WORK/".to_string()],
            None,
            Path::new(TEST_LAUNCHER),
        )
        .expect_err("`C:\\work` denies the workspace it grants");
        assert_eq!(
            err,
            RequestError::DenyCoversGrant {
                deny: r"c:/WORK/".to_string(),
                grant: TEST_WORKSPACE.to_string(),
            }
        );
    }

    /// BLOCKING 2, the reported case: `%USERPROFILE%` denied with the workspace
    /// inside it. This used to be dropped silently, which left `Documents`,
    /// `Downloads`, `AppData` and every browser profile readable.
    #[test]
    fn a_deny_that_is_an_ancestor_of_a_grant_is_refused_and_names_both_paths() {
        let workspace = format!(r"{PROFILE}\work");
        let err = filesystem_policy(
            Path::new(&workspace),
            &[],
            &[PROFILE.to_string()],
            Some(Path::new(PROFILE)),
            Path::new(TEST_LAUNCHER),
        )
        .expect_err("a profile deny with the workspace inside it cannot be honoured");
        assert_eq!(
            err,
            RequestError::DenyCoversGrant {
                deny: PROFILE.to_string(),
                grant: workspace.clone(),
            },
            "the refusal must name the granted path the deny contains"
        );
        let message = err.to_string();
        assert!(
            message.contains(PROFILE) && message.contains(&workspace),
            "both paths must be in the message: {message}"
        );
        assert!(
            message.contains("Deny the specific subdirectory"),
            "the operator needs the fix, not just the failure: {message}"
        );
    }

    /// The intended, expressible case — and the one that must keep working.
    #[test]
    fn a_deny_that_is_a_descendant_of_a_grant_is_kept() {
        let fs = filesystem_policy(
            Path::new(PROFILE),
            &[],
            &[format!(r"{PROFILE}\.ssh"), format!(r"{PROFILE}\Documents")],
            Some(Path::new(PROFILE)),
            Path::new(TEST_LAUNCHER),
        )
        .expect("denies below the granted workspace are exactly what a deny list is for");
        assert!(fs.denied_paths.contains(&format!(r"{PROFILE}\.ssh")));
        assert!(fs.denied_paths.contains(&format!(r"{PROFILE}\Documents")));
        assert_eq!(
            fs.denied_paths
                .iter()
                .filter(|deny| deny.eq_ignore_ascii_case(&format!(r"{PROFILE}\.ssh")))
                .count(),
            1,
            "the built-in `.ssh` deny and the configured one are the same path: {:?}",
            fs.denied_paths
        );
    }

    #[test]
    fn a_deny_unrelated_to_every_grant_is_kept() {
        let fs = filesystem_policy(
            Path::new(TEST_WORKSPACE),
            &[],
            &[r"D:\secrets".to_string(), r"C:\work2".to_string()],
            None,
            Path::new(TEST_LAUNCHER),
        )
        .expect("neither deny contains a grant");
        assert_eq!(
            fs.denied_paths,
            vec![r"D:\secrets".to_string(), r"C:\work2".to_string()],
            "`C:\\work2` shares a prefix with the grant but is a sibling: the check stays \
             segment-aware"
        );
    }

    /// BLOCKING 1, the ordering defect: the launcher lives under the user profile
    /// in practice, so an operator deny of the profile root contains the launcher
    /// grant. It must be refused at policy time — the grant is inserted there, so
    /// the deny set is filtered against it instead of against a grant set that is
    /// completed later in `build_request`.
    #[test]
    fn a_profile_deny_that_contains_the_launcher_grant_is_refused() {
        let launcher = format!(r"{PROFILE}\tools\sandbox\{LAUNCHER_EXE_NAME}");
        let err = filesystem_policy(
            Path::new(TEST_WORKSPACE),
            &[],
            &[PROFILE.to_string()],
            Some(Path::new(PROFILE)),
            Path::new(&launcher),
        )
        .expect_err("the launcher's directory is under the denied profile");
        assert_eq!(
            err,
            RequestError::DenyCoversGrant {
                deny: PROFILE.to_string(),
                grant: format!(r"{PROFILE}\tools\sandbox"),
            },
            "the refusal must name the launcher directory — the grant the deny contains"
        );
    }

    /// The control for the test above: with no such deny, the profile credential
    /// denies survive alongside a launcher grant that sits under the profile. The
    /// grant must not swallow them, and their presence proves the deny list was
    /// filtered against a grant set that already contained the launcher.
    #[test]
    fn a_launcher_under_the_profile_keeps_the_profile_credential_denies() {
        let launcher = format!(r"{PROFILE}\tools\sandbox\{LAUNCHER_EXE_NAME}");
        let fs = filesystem_policy(
            Path::new(TEST_WORKSPACE),
            &[],
            &[],
            Some(Path::new(PROFILE)),
            Path::new(&launcher),
        )
        .expect("no deny contains a grant");
        assert!(
            fs.readonly_paths
                .contains(&format!(r"{PROFILE}\tools\sandbox")),
            "the launcher grant is part of the policy: {:?}",
            fs.readonly_paths
        );
        assert_eq!(
            fs.denied_paths.len(),
            PROFILE_SECRET_DIRS.len(),
            "all four credential denies must survive: {:?}",
            fs.denied_paths
        );
    }

    /// (b) The launcher used to defeat the guard: a relative spelling keys as
    /// `tools\sandbox`, which never matches an absolute deny, so a deny covering
    /// the real directory shipped and the container was then denied the launcher
    /// it needed. It is resolved before the comparison now.
    #[test]
    fn a_relative_launcher_is_resolved_before_the_deny_comparison() {
        let here = std::env::current_dir().expect("current directory");
        let launcher_dir = std::path::absolute(Path::new(r"tools\sandbox"))
            .expect("the relative launcher directory resolves")
            .display()
            .to_string();
        let err = filesystem_policy(
            Path::new(TEST_WORKSPACE),
            &[],
            &[here.display().to_string()],
            None,
            Path::new(r"tools\sandbox\mxc-launch.exe"),
        )
        .expect_err("the current directory is an ancestor of the resolved launcher directory");
        assert_eq!(
            err,
            RequestError::DenyCoversGrant {
                deny: here.display().to_string(),
                grant: launcher_dir,
            },
            "the grant must be the resolved directory, not the relative spelling"
        );
    }

    /// (b) The other input: a relative `cwd` keyed as `.` (empty), so a deny of the
    /// real directory matched nothing and shipped. `.` now behaves like its
    /// absolute form — same grant, same refusal.
    #[test]
    fn a_relative_cwd_behaves_like_its_absolute_form() {
        let here = std::env::current_dir().expect("current directory");
        let relative = filesystem_policy(Path::new("."), &[], &[], None, Path::new(TEST_LAUNCHER))
            .expect("`.` resolves to the current directory");
        assert_eq!(
            relative.readwrite_paths,
            vec![here.display().to_string()],
            "the grant must be the resolved directory, not `.`"
        );
        let absolute = filesystem_policy(&here, &[], &[], None, Path::new(TEST_LAUNCHER))
            .expect("the absolute spelling of the same workspace");
        assert_eq!(
            relative.readwrite_paths, absolute.readwrite_paths,
            "`.` and the absolute form must produce the same policy"
        );

        let err = filesystem_policy(
            Path::new("."),
            &[],
            &[here.display().to_string()],
            None,
            Path::new(TEST_LAUNCHER),
        )
        .expect_err("the current directory is the workspace it would grant");
        assert_eq!(
            err,
            RequestError::DenyCoversGrant {
                deny: here.display().to_string(),
                grant: here.display().to_string(),
            }
        );
    }

    /// A path the boundary cannot make absolute has no comparison key, so it is a
    /// named refusal rather than a guess that voids the guard.
    #[test]
    fn a_path_that_cannot_be_made_absolute_is_a_named_refusal() {
        let err = filesystem_policy(Path::new(""), &[], &[], None, Path::new(TEST_LAUNCHER))
            .expect_err("an empty cwd has no key to compare");
        assert_eq!(
            err,
            RequestError::PathNotAbsolute {
                what: "workspace directory",
                path: String::new(),
            }
        );
        assert!(
            err.to_string().contains("is empty"),
            "the message must say what is wrong: {err}"
        );

        let err = build_request(&input(), Path::new("")).expect_err("an empty launcher has no key");
        assert_eq!(
            err,
            RequestError::PathNotAbsolute {
                what: "launcher",
                path: String::new(),
            }
        );
        assert!(
            err.to_string().contains("launcher"),
            "the message must name the input: {err}"
        );
    }

    /// (b) The command line names the resolved launcher too, so the container
    /// executes exactly the binary the policy granted.
    #[test]
    fn build_request_resolves_a_relative_launcher_in_the_command_line() {
        let here = std::env::current_dir().expect("current directory");
        let request = build_request(&input(), Path::new(r"bin\mxc-launch.exe"))
            .expect("a relative launcher resolves");
        let resolved_dir = here.join("bin").display().to_string();
        assert!(
            request.command.contains(&resolved_dir),
            "the command line must name the absolute launcher directory: {:?}",
            request.command
        );
        let fs = request.filesystem.as_ref().expect("filesystem policy");
        assert!(
            fs.readonly_paths
                .iter()
                .any(|g| path_key(g) == path_key(&resolved_dir)),
            "the grant must be the resolved directory: {:?}",
            fs.readonly_paths
        );
    }

    /// (f) The built-in credential denies are not configuration: a workspace inside
    /// one is unlaunchable with no override, and the operator has to be told that
    /// rather than left hunting for a setting they never wrote.
    #[test]
    fn a_workspace_inside_a_built_in_credential_deny_names_the_trap() {
        for dir in PROFILE_SECRET_DIRS {
            let workspace = format!(r"{PROFILE}\{dir}\work");
            let err = filesystem_policy(
                Path::new(&workspace),
                &[],
                &[],
                Some(Path::new(PROFILE)),
                Path::new(TEST_LAUNCHER),
            )
            .expect_err("the built-in credential deny contains the workspace");
            assert_eq!(
                err,
                RequestError::DenyCoversGrant {
                    deny: format!(r"{PROFILE}\{dir}"),
                    grant: workspace,
                },
                "{dir}"
            );
            let message = err.to_string();
            assert!(
                message.contains("built-in") && message.contains("move the workspace"),
                "the operator must be told this is not their configuration: {message}"
            );
        }
    }

    /// A caller may hand-build an [`MxcFilesystemInput`], so `build_request` runs
    /// the same coverage check again **after** inserting the launcher grant.
    #[test]
    fn build_request_refuses_a_hand_built_policy_that_denies_the_launcher_directory() {
        let source = RecordingSource::default();
        let backend = MxcBackend::new(&source, Some(49_152), TEST_LAUNCHER);
        let mut i = input();
        i.filesystem.denied_paths = vec![TEST_LAUNCHER_DIR.to_string()];

        match backend.request_for(&i) {
            Err(MxcError::Request(RequestError::DenyCoversGrant { deny, grant })) => {
                assert_eq!(deny, TEST_LAUNCHER_DIR);
                assert_eq!(grant, TEST_LAUNCHER_DIR);
            }
            other => panic!(
                "a deny of the launcher's own directory must refuse the request, got {other:?}"
            ),
        }
    }

    /// (e) The *ancestor* branch of the second filter — a deny that covers the
    /// launcher's directory without naming it. The `deny == grant` test above
    /// reaches only the equality arm, so without this the ancestor arm of
    /// `covers` would be untested on the post-insertion re-check.
    #[test]
    fn build_request_refuses_a_hand_built_policy_whose_deny_is_an_ancestor_of_the_launcher() {
        let source = RecordingSource::default();
        let backend = MxcBackend::new(&source, Some(49_152), TEST_LAUNCHER);
        let mut i = input();
        i.filesystem.readonly_paths.clear();
        i.filesystem.denied_paths = vec![r"C:\tools".to_string()];

        match backend.request_for(&i) {
            Err(MxcError::Request(RequestError::DenyCoversGrant { deny, grant })) => {
                assert_eq!(deny, r"C:\tools");
                assert_eq!(
                    grant, TEST_LAUNCHER_DIR,
                    "the grant is the launcher directory build_request itself inserted"
                );
            }
            other => panic!(
                "a deny that is an ancestor of the launcher's directory must refuse the \
                 request, got {other:?}"
            ),
        }
    }

    /// `covers` is the whole deny/grant decision, so its boundary cases are
    /// asserted directly rather than only through `filesystem_policy`.
    #[test]
    fn covers_is_segment_aware_and_prefix_safe() {
        // Siblings that share a prefix are not covered; children are.
        assert!(!covers(r"C:\work", r"C:\work2"));
        assert!(covers(r"C:\work", r"C:\work\sub"));
        assert!(!covers(r"C:\work", r"C:\work2\sub"));
        assert!(covers(r"C:\work", r"C:\work"));
        // Separator style and a trailing separator are not identity.
        assert!(covers(r"C:\work\", r"C:/work/sub"));

        // Win32 ignores a component's trailing dots and spaces.
        assert!(covers(r"C:\Users\x\.ssh.", r"C:\Users\x\.ssh"));
        assert!(covers(r"C:\Users\x\.ssh", r"C:\Users\x\.ssh."));
        assert!(covers(r"C:\work ", r"C:\work\sub"));

        // `.`/`..` collapse before comparison.
        assert!(covers(r"C:\work\.\sub\..", r"C:\work"));
        assert!(covers(r"C:\work\sub\..\sub", r"C:\work\sub"));

        // The verbatim/device prefix and its UNC spelling name the same tree.
        assert!(covers(r"\\?\C:\work", r"C:\work\sub"));
        assert!(covers(r"C:\work", r"\\?\C:\work\sub"));
        assert!(covers(r"\\.\C:\work", r"C:\work"));
        assert!(covers(r"\\?\UNC\server\share", r"\\server\share\sub"));
        assert!(covers(r"\\server\share", r"\\?\UNC\server\share\sub"));
        assert!(!covers(r"\\server\share", r"\\server\share2"));

        // An empty path covers nothing — an empty deny is a mistake, not a
        // wildcard — and nothing covers a drive root.
        assert!(!covers("", r"C:\work"));
        assert!(!covers("", ""));
        assert!(!covers(r"C:\work", ""));

        // A drive root covers its whole drive, and is covered by nothing else.
        assert!(covers(r"C:\", r"C:\work"));
        assert!(covers(r"C:\", r"C:\Windows\win.ini"));
        assert!(!covers(r"C:\work", r"C:\"));
    }

    /// Windows compares path components case-insensitively over the whole
    /// Unicode range; `to_ascii_lowercase` only folded ASCII, so `C:\Users\Ä` and
    /// `C:\Users\ä` were different keys and a covering deny escaped the guard.
    /// Both directions, because a fold that only worked one way would still let
    /// one operator's spelling through.
    #[test]
    fn unicode_case_folds_to_one_key_in_both_directions() {
        assert_eq!(path_key(r"C:\Users\Ä"), path_key(r"C:\Users\ä"));
        assert_eq!(path_key(r"C:\Users\ä"), path_key(r"C:\Users\Ä"));
        assert!(covers(r"C:\Users\Ä\work", r"C:\Users\ä\work\sub"));
        assert!(covers(r"C:\Users\ä\work", r"C:\Users\Ä\work\.ssh"));
        // Not Latin-1 only: the fold is Unicode, as Windows' ordinal compare is.
        assert_eq!(path_key(r"C:\Δ\Σ"), path_key(r"C:\δ\σ"));
        assert_eq!(path_key(r"C:\ДОМ"), path_key(r"C:\дом"));
        // ...and it stays case-*insensitive*, not case-blind: different letters
        // still differ, so the guard does not start refusing everything.
        assert_ne!(path_key(r"C:\Users\Ä"), path_key(r"C:\Users\Ö"));
    }

    /// The fold is only worth having if it reaches the guard: a Unicode-cased deny
    /// that covers the workspace must refuse the launch, in both directions.
    #[test]
    fn a_unicode_cased_deny_that_covers_the_workspace_is_refused() {
        for (deny, workspace) in [
            (r"C:\Users\Ä", r"C:\Users\ä\work"),
            (r"C:\Users\ä", r"C:\Users\Ä\work"),
        ] {
            let err = filesystem_policy(
                Path::new(workspace),
                &[],
                &[deny.to_string()],
                None,
                Path::new(TEST_LAUNCHER),
            )
            .expect_err("these are one directory to Windows, so the deny covers the grant");
            assert_eq!(
                err,
                RequestError::DenyCoversGrant {
                    deny: deny.to_string(),
                    grant: workspace.to_string(),
                },
                "{deny} vs {workspace}"
            );
        }
    }

    /// (c) `..` is tested *after* the trailing-dot/space trim: `.. ` trimmed to
    /// nothing and was dropped, so `C:\work\sub\.. \x` keyed as
    /// `c:\work\sub\x` instead of collapsing to `c:\work\x`.
    #[test]
    fn a_dotdot_with_a_trailing_space_still_collapses_to_the_parent() {
        assert_eq!(path_key(r"C:\work\sub\.. \x"), path_key(r"C:\work\x"));
        assert_eq!(path_key(r"C:\work\sub\..  \x"), path_key(r"C:\work\x"));
        assert_eq!(path_key(r"C:\work\sub\..\x"), path_key(r"C:\work\x"));
        assert_eq!(path_key(r"C:\work\sub\.. "), path_key(r"C:\work"));
        assert!(covers(r"C:\work\sub\.. .", r"C:\work\sub"));
        // A dot-only segment with padding is still just `.`, dropped.
        assert_eq!(path_key(r"C:\work\. \x"), path_key(r"C:\work\x"));
        // `..` still clamps at the root.
        assert_eq!(path_key(r"C:\..\work"), path_key(r"C:\work"));
    }

    /// (d) The docblock promises *every* component loses its trailing dots and
    /// spaces; the UNC root's server and share were exempt, so `\\srv\share.\x`
    /// and `\\srv\share\x` were different keys.
    #[test]
    fn unc_root_components_lose_their_trailing_dots_and_spaces() {
        assert_eq!(path_key(r"\\srv\share.\x"), path_key(r"\\srv\share\x"));
        assert_eq!(path_key(r"\\srv\share \x"), path_key(r"\\srv\share\x"));
        assert_eq!(path_key(r"\\srv.\share\x"), path_key(r"\\srv\share\x"));
        assert!(covers(r"\\srv\share.", r"\\srv\share\sub"));
        assert!(covers(r"\\srv\share", r"\\srv\share.\sub"));
        // The trimmed root still prefixes its own children, and no sibling.
        assert!(!covers(r"\\srv\share.", r"\\srv\share2"));
        assert!(!covers(r"\\srv\share.", r"\\srv2\share"));
    }

    /// The normalisation `covers` relies on, asserted where it is observable: every
    /// spelling of one directory must reach one key, without touching the disk.
    #[test]
    fn equivalent_spellings_reach_the_same_path_key() {
        let expected = path_key(r"C:\Users\x\.ssh");
        for spelling in [
            r"C:\Users\x\.ssh.",
            r"C:\Users\x\.ssh   ",
            r"C:/Users/x/.ssh",
            r"\\?\C:\Users\x\.ssh",
            r"\\.\C:\Users\x\.ssh",
            r"C:\Users\.\x\ssh\..\.ssh",
            r"C:\Users\x\.ssh\",
        ] {
            assert_eq!(path_key(spelling), expected, "{spelling}");
        }
        assert_eq!(path_key(r"\\?\UNC\srv\share\x"), path_key(r"\\srv\share\x"));
    }

    /// The documented caveat, asserted as a caveat: MXC filesystem policy is
    /// additive grants, so system directories stay readable even when every
    /// secret we can name is denied. This test exists so nobody "fixes" the
    /// caveat by denying `C:\Windows` — that would break every workload that
    /// needs System32 while the policy still cannot express "nothing else".
    #[test]
    fn system_directories_are_not_denied_the_additive_caveat_is_recorded() {
        let fs = policy();
        assert!(
            !fs.denied_paths
                .iter()
                .any(|denied| covers(denied, r"C:\Windows")),
            "`C:\\Windows` readable inside the container is the known caveat: {:?}",
            fs.denied_paths
        );
        assert!(
            !fs.denied_paths
                .iter()
                .any(|denied| denied.eq_ignore_ascii_case(r"C:\Windows")),
            "denying C:\\Windows would break every System32-resident workload"
        );
    }

    // ---- P1 wave 2 D8: the token rides the proxy URL ---------------------

    fn network_proxy(request: &ContainerRequest) -> Option<String> {
        request
            .network
            .as_ref()?
            .runtime_config
            .as_ref()?
            .network_proxy
            .clone()
    }

    #[test]
    fn the_request_hands_the_child_a_proxy_url_with_the_session_token() {
        let source = RecordingSource::default();
        let backend =
            MxcBackend::new(&source, Some(49_152), TEST_LAUNCHER).with_proxy_token("abc-123");
        let request = backend.request_for(&input()).expect("launchable request");
        assert_eq!(
            network_proxy(&request).as_deref(),
            Some("http://sandbox:abc-123@127.0.0.1:49152"),
            "the SDK copies this URL verbatim into HTTP_PROXY/HTTPS_PROXY, and the proxy's \
             token gate is what it has to satisfy"
        );
    }

    #[test]
    fn a_callers_token_cannot_stand_in_for_the_backends() {
        let source = RecordingSource::default();
        let backend = MxcBackend::new(&source, Some(49_152), TEST_LAUNCHER);
        let mut i = input();
        i.network.proxy_token = Some("caller-lookalike".to_string());

        let request = backend.request_for(&i).expect("launchable request");
        assert_eq!(
            network_proxy(&request).as_deref(),
            Some("http://127.0.0.1:49152"),
            "a token this backend's listener cannot honour must not ship: it would produce a \
             407 that reads like a broken proxy"
        );
    }

    /// The token is a credential: `{:?}` on either input must not print it, or
    /// every log line, panic message and error chain that formats an input hands
    /// out the session token the proxy's gate expects.
    #[test]
    fn debug_output_redacts_the_proxy_token() {
        const TOKEN: &str = "tok-must-not-appear-4821";
        let mut i = input();
        i.network.proxy_port = Some(49_152);
        i.network.proxy_token = Some(TOKEN.to_string());

        let network = format!("{:?}", i.network);
        assert!(
            network.contains(REDACTED_TOKEN),
            "the redaction must be visible: {network}"
        );
        assert!(
            !network.contains(TOKEN),
            "`MxcNetworkInput`'s Debug leaked the token: {network}"
        );

        let session = format!("{i:?}");
        assert!(
            session.contains(REDACTED_TOKEN),
            "the redaction must be visible: {session}"
        );
        assert!(
            !session.contains(TOKEN),
            "`MxcSessionInput`'s Debug leaked the token: {session}"
        );
    }

    #[test]
    fn an_unsafe_token_is_refused_before_a_request_exists() {
        for bad in ["a@b", "a/b", "a b", "a?b", "a#b"] {
            let mut i = input();
            i.network.proxy_token = Some(bad.to_string());
            assert_eq!(
                build_request(&i, Path::new(TEST_LAUNCHER)).expect_err("unsafe token"),
                RequestError::UnsafeProxyToken,
                "{bad:?} would move the URL's authority"
            );
        }
        assert_eq!(
            proxy_url(8080, Some("Hex-0123._~")).expect("unreserved characters are fine"),
            "http://sandbox:Hex-0123._~@127.0.0.1:8080"
        );
        assert_eq!(
            proxy_url(8080, None).expect("no token"),
            "http://127.0.0.1:8080",
            "no token means the credential-less form, unchanged"
        );
        assert_eq!(
            proxy_url(8080, Some("")).expect("an empty token is no token"),
            "http://127.0.0.1:8080"
        );
    }

    // ---- P1 wave 2 A: the real proof source is the listener ---------------

    #[test]
    fn the_proxy_counters_are_a_proxy_proof_source() {
        let counters = crate::net::proxy::LaunchCounters::new();
        let source: &dyn ProxyProofSource = counters.as_ref();
        assert_eq!(source.proof(1), untouched());
    }

    #[test]
    fn listener_counters_map_to_the_proof_and_never_leak_between_epochs() {
        let counters = crate::net::proxy::LaunchCounters::new();

        let first = counters.begin_launch().expect("the first launch's window");
        counters.note_consultation();
        counters.note_upstream_established();
        assert_eq!(
            counters.proof(first),
            ProxyProof {
                accepted: 1,
                tunnels: 1,
            }
        );
        counters.close_launch(first);

        // A second launch starts from zero, even though the first one saw
        // traffic — this is the whole point of the epoch.
        let second = counters.begin_launch().expect("a window after the close");
        assert_eq!(counters.proof(second), untouched());
        // A plain-HTTP forward: consulted and upstream established, with no
        // CONNECT anywhere. `tunnels >= 1` must hold or `Required` would fail a
        // working session.
        counters.note_consultation();
        counters.note_upstream_established();
        assert_eq!(
            counters.proof(second),
            ProxyProof {
                accepted: 1,
                tunnels: 1,
            },
            "a plain-HTTP-only session must satisfy Required"
        );
        // The closed epoch keeps its frozen numbers.
        assert_eq!(
            counters.proof(first),
            ProxyProof {
                accepted: 1,
                tunnels: 1,
            }
        );
        // An epoch nobody opened proves nothing.
        assert_eq!(counters.proof(4_242), untouched());
    }

    // ---- environment filter ---------------------------------------------

    #[test]
    fn blocked_env_keys_match_case_insensitively_and_only_proxy_vars() {
        for key in [
            "HTTP_PROXY",
            "https_proxy",
            "All_Proxy",
            "no_proxy",
            " HTTP_PROXY ",
        ] {
            assert!(is_blocked_env_key(key), "{key} must be blocked");
        }
        for key in ["PATH", "HTTP_PROXYX", "PROXY", "APPDATA"] {
            assert!(!is_blocked_env_key(key), "{key} must not be blocked");
        }
    }
}

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
/// cargo build --features mxc-backend --bin mxc-launch
/// cargo test  --features mxc-backend -- --ignored
/// ```
///
/// Nothing here needs elevation, and nothing here mutates host state: the
/// container's filesystem policy is a grant *inside* the container, and the
/// scratch directory removes itself.
#[cfg(test)]
mod live {
    use super::*;
    use std::collections::HashMap;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use crate::net::intent::{DEFAULT_TTL, IntentRegistry};
    use crate::net::learned::LearnedStore;
    use crate::net::prompt::{
        DialogFn, DialogUnavailable, PromptConfig, PromptCoordinator, PromptPolicy,
    };
    use crate::net::proxy::LaunchProofCounters;
    use crate::net::token::RunToken;
    use base64::Engine as _;

    /// What the fake endpoint and the proof source share.
    #[derive(Default)]
    struct Shared {
        epoch: AtomicU64,
        /// The window that is open, if any: the fake proof source enforces the
        /// same no-overlap contract the real counters do (P1.4).
        active: Mutex<Option<u64>>,
        counters: Mutex<HashMap<u64, ProxyProof>>,
        closes: Mutex<Vec<u64>>,
        /// `(epoch, request line)` for origin-form requests: a client dialled the
        /// endpoint directly, which is what NO_PROXY is supposed to cause.
        origin: Mutex<Vec<(u64, String)>>,
        /// `(epoch, request line)` for proxy consultations (`CONNECT` or an
        /// absolute-form request).
        proxied: Mutex<Vec<(u64, String)>>,
    }

    struct LiveProof {
        shared: Arc<Shared>,
    }

    impl LiveProof {
        fn last_epoch(&self) -> u64 {
            self.shared.epoch.load(Ordering::SeqCst)
        }
    }

    impl ProxyProofSource for LiveProof {
        fn begin_launch(&self) -> Result<u64, EpochAlreadyOpen> {
            let mut active = self.shared.active.lock().unwrap();
            if let Some(open) = *active {
                return Err(EpochAlreadyOpen { active: open });
            }
            let epoch = self.shared.epoch.fetch_add(1, Ordering::SeqCst) + 1;
            *active = Some(epoch);
            self.shared
                .counters
                .lock()
                .unwrap()
                .insert(epoch, ProxyProof::default());
            Ok(epoch)
        }

        fn proof(&self, epoch: u64) -> ProxyProof {
            self.shared
                .counters
                .lock()
                .unwrap()
                .get(&epoch)
                .copied()
                .unwrap_or_default()
        }

        fn close_launch(&self, epoch: u64) {
            let mut active = self.shared.active.lock().unwrap();
            if *active == Some(epoch) {
                *active = None;
            }
            self.shared.closes.lock().unwrap().push(epoch);
        }
    }

    /// One loopback listener that is **both** the supervisor's proxy (it refuses
    /// loopback targets, as the real one does) and the intent endpoint. Serving
    /// both on one port is what lets the test tell the two apart.
    struct Endpoint {
        port: u16,
        shared: Arc<Shared>,
        stop: Arc<AtomicBool>,
        join: Option<std::thread::JoinHandle<()>>,
    }

    impl Endpoint {
        fn start(nonce: &str) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind endpoint");
            let port = listener.local_addr().expect("endpoint addr").port();
            listener
                .set_nonblocking(false)
                .expect("blocking listener for the accept loop");
            let shared = Arc::new(Shared::default());
            let stop = Arc::new(AtomicBool::new(false));
            let nonce = nonce.to_string();

            let ctx = Arc::clone(&shared);
            let stop_thread = Arc::clone(&stop);
            let join = std::thread::spawn(move || {
                for accepted in listener.incoming() {
                    if stop_thread.load(Ordering::SeqCst) {
                        break;
                    }
                    if let Ok(stream) = accepted {
                        let ctx = Arc::clone(&ctx);
                        let nonce = nonce.clone();
                        std::thread::spawn(move || handle(stream, &ctx, &nonce));
                    }
                }
            });

            Self {
                port,
                shared,
                stop,
                join: Some(join),
            }
        }

        fn url(&self) -> String {
            format!("http://127.0.0.1:{}/sandbox/intent", self.port)
        }

        fn proxy_consultations(&self, epoch: u64) -> Vec<String> {
            let proxied = self.shared.proxied.lock().unwrap();
            proxied
                .iter()
                .filter(|(e, _)| *e == epoch)
                .map(|(_, line)| line.clone())
                .collect()
        }

        fn origin_requests(&self, epoch: u64) -> Vec<String> {
            let origin = self.shared.origin.lock().unwrap();
            origin
                .iter()
                .filter(|(e, _)| *e == epoch)
                .map(|(_, line)| line.clone())
                .collect()
        }

        fn closed(&self, epoch: u64) -> bool {
            self.shared
                .closes
                .lock()
                .map(|closes| closes.contains(&epoch))
                .unwrap_or(false)
        }
    }

    impl Drop for Endpoint {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            // Wake the blocking accept() instead of polling on a sleep.
            let _ = TcpStream::connect(("127.0.0.1", self.port));
            if let Some(join) = self.join.take() {
                let _ = join.join();
            }
        }
    }

    fn bump(shared: &Shared, epoch: u64, f: impl FnOnce(&mut ProxyProof)) {
        let mut counters = shared.counters.lock().unwrap();
        f(counters.entry(epoch).or_default());
    }

    fn handle(mut stream: TcpStream, shared: &Shared, nonce: &str) {
        let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
        let mut buf: Vec<u8> = Vec::new();
        let mut chunk = [0u8; 1024];
        while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
            match stream.read(&mut chunk) {
                Ok(0) => return,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
                Err(_) => return,
            }
            if buf.len() > 16 * 1024 {
                return;
            }
        }

        let head = String::from_utf8_lossy(&buf).to_string();
        let line = head.lines().next().unwrap_or("").trim().to_string();
        let epoch = shared.epoch.load(Ordering::SeqCst);
        let target = line.split_whitespace().nth(1).unwrap_or("").to_string();

        // A proxy consultation is anything a proxy must handle: a CONNECT or an
        // absolute-form request. Both are refused for loopback exactly as the
        // real proxy refuses them (invariant 4), so `tunnels` stays 0.
        if line.starts_with("CONNECT ")
            || target.starts_with("http://")
            || target.starts_with("https://")
        {
            shared.proxied.lock().unwrap().push((epoch, line));
            bump(shared, epoch, |proof| proof.accepted += 1);
            let body = format!("proxy refuses loopback target {target}\n");
            let _ = stream.write_all(&response(403, "Forbidden", &body));
            return;
        }

        // Origin-form: the client dialled us directly, so we are the endpoint.
        shared.origin.lock().unwrap().push((epoch, line));
        if target == "/sandbox/intent" {
            let body = format!("{{\"ok\":true,\"nonce\":\"{nonce}\"}}");
            let _ = stream.write_all(&response(200, "OK", &body));
        } else {
            let _ = stream.write_all(&response(404, "Not Found", "unknown endpoint\n"));
        }
    }

    fn response(code: u16, reason: &str, body: &str) -> Vec<u8> {
        format!(
            "HTTP/1.1 {code} {reason}\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .into_bytes()
    }

    /// The wrapper exe beside the test binary (`target/<profile>/`), built by
    /// `cargo build --features mxc-backend --bin mxc-launch`.
    fn launcher_under_test() -> PathBuf {
        let exe = std::env::current_exe().expect("current test exe");
        let deps = exe.parent().expect("deps directory");
        let candidates = [
            deps.parent().map(|profile| profile.join(LAUNCHER_EXE_NAME)),
            Some(deps.join(LAUNCHER_EXE_NAME)),
        ];
        for candidate in candidates.into_iter().flatten() {
            if candidate.is_file() {
                return candidate;
            }
        }
        panic!(
            "{LAUNCHER_EXE_NAME} not found near {}: run `cargo build --features mxc-backend \
             --bin mxc-launch` first",
            exe.display()
        );
    }

    /// A scratch directory that removes itself, so a failed assertion does not
    /// leave host state behind (the test grants nothing outside it).
    struct Scratch(PathBuf);

    impl Scratch {
        fn named(label: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "sandbox-mxc-{label}-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            // A previous run of the same test in the same process would collide
            // only on the thread id, which is stable per test thread — so start
            // from an empty directory.
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).expect("create scratch dir");
            Self(dir)
        }

        fn new() -> Self {
            Self::named("intent")
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn live_input(port: u16, scratch: &Path, launcher: &Path, command: String) -> MxcSessionInput {
        MxcSessionInput {
            command,
            working_directory: Some(scratch.display().to_string()),
            environment: Vec::new(),
            filesystem: MxcFilesystemInput {
                readwrite_paths: vec![scratch.display().to_string()],
                readonly_paths: vec![
                    launcher_grant(launcher).expect("launcher directory"),
                    // The workloads below are System32-resident.
                    r"C:\Windows".to_string(),
                ],
                denied_paths: Vec::new(),
            },
            network: MxcNetworkInput {
                proxy_port: Some(port),
                proxy_token: None,
            },
            timeout_ms: None,
        }
    }

    fn stdout_of(outcome: &SessionOutcome) -> String {
        String::from_utf8_lossy(&outcome.stdout).to_string()
    }

    fn stderr_of(outcome: &SessionOutcome) -> String {
        String::from_utf8_lossy(&outcome.stderr).to_string()
    }

    const CURL: &str = r"C:\Windows\System32\curl.exe";

    /// `TokenElevation` for this process, so the evidence says whether anything
    /// ran elevated. Same signal as `IsInRole(Administrator)` and as
    /// `src/setup.rs::is_elevated` (private to that module).
    fn process_is_elevated() -> bool {
        use windows::Win32::Foundation::{CloseHandle, HANDLE};
        use windows::Win32::Security::{
            GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
        };
        use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
        // SAFETY: the token handle is closed on every path, and the information
        // buffer is exactly the size passed to the API.
        unsafe {
            let mut token = HANDLE::default();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
                return false;
            }
            let mut elevation = TOKEN_ELEVATION::default();
            let mut ret = 0u32;
            let ok = GetTokenInformation(
                token,
                TokenElevation,
                Some(&mut elevation as *mut _ as *mut _),
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut ret,
            );
            let _ = CloseHandle(token);
            ok.is_ok() && elevation.TokenIsElevated != 0
        }
    }

    fn proxy_lines(stdout: &str) -> Vec<String> {
        stdout
            .lines()
            .filter(|line| line.to_ascii_lowercase().contains("proxy"))
            .map(|line| line.trim().to_string())
            .collect()
    }

    // =====================================================================
    // P1 wave 2: proxied / plain-HTTP / blocked / filesystem legs
    // =====================================================================

    /// The body both legs look for, so a 200 from anything else cannot pass.
    const NONCE: &str = "nonce-p1-wave-2";

    /// The session token the live proxies require. URL-unreserved, the shape the
    /// real generator produces (hex).
    const LIVE_TOKEN: &str = "live-session-token-0123456789abcdef";

    fn stamp() -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    }

    /// The host's own LAN address — local, but **not** loopback.
    ///
    /// Invariant 4 forbids the proxy forwarding to a loopback target, and the
    /// live intent test relies on that refusal. A *proxied* round trip therefore
    /// needs an address that is local without being loopback: the container is
    /// told only `127.0.0.1:<proxy>`, the proxy dials this address, and the
    /// listener below is where the request provably arrives.
    fn non_loopback_ipv4() -> std::net::Ipv4Addr {
        let probe = std::net::UdpSocket::bind("0.0.0.0:0").expect("route probe socket");
        // No packet leaves: a connected UDP socket only fixes the route.
        probe.connect("1.1.1.1:80").expect("route probe");
        match probe.local_addr().expect("route probe address").ip() {
            std::net::IpAddr::V4(v4) if !v4.is_loopback() => v4,
            other => panic!(
                "this host has no non-loopback IPv4 (probe address {other}): a proxied round \
                 trip cannot be proven against a loopback target, because the proxy refuses those \
                 by design"
            ),
        }
    }

    /// A local origin server that records the request line it was asked for.
    struct Origin {
        host: String,
        port: u16,
        seen: Arc<Mutex<Vec<String>>>,
        heads: Arc<Mutex<Vec<String>>>,
        stop: Arc<AtomicBool>,
        join: Option<std::thread::JoinHandle<()>>,
    }

    impl Origin {
        fn start() -> Self {
            let ip = non_loopback_ipv4();
            let listener =
                TcpListener::bind((ip, 0)).expect("bind origin on the host's LAN address");
            let port = listener.local_addr().expect("origin address").port();
            let seen = Arc::new(Mutex::new(Vec::new()));
            let heads = Arc::new(Mutex::new(Vec::new()));
            let stop = Arc::new(AtomicBool::new(false));
            let seen_thread = Arc::clone(&seen);
            let heads_thread = Arc::clone(&heads);
            let stop_thread = Arc::clone(&stop);
            let join = std::thread::spawn(move || {
                for accepted in listener.incoming() {
                    if stop_thread.load(Ordering::SeqCst) {
                        break;
                    }
                    let Ok(stream) = accepted else { continue };
                    let seen = Arc::clone(&seen_thread);
                    let heads = Arc::clone(&heads_thread);
                    std::thread::spawn(move || serve_origin(stream, &seen, &heads));
                }
            });
            Self {
                host: ip.to_string(),
                port,
                seen,
                heads,
                stop,
                join: Some(join),
            }
        }

        fn authority(&self) -> String {
            format!("{}:{}", self.host, self.port)
        }

        fn url(&self, path: &str) -> String {
            format!("http://{}{path}", self.authority())
        }

        fn requests(&self) -> Vec<String> {
            self.seen.lock().map(|s| s.clone()).unwrap_or_default()
        }

        /// Did the origin receive exactly this origin-form GET?
        fn saw(&self, path: &str) -> bool {
            let want = format!("GET {path} HTTP/1.1");
            self.requests().iter().any(|line| line == &want)
        }

        /// The full head the origin received for `path`, verbatim — the evidence
        /// for what the forward path rewrote (target form, `Host`, hop fields).
        fn head_for(&self, path: &str) -> Option<String> {
            let want = format!("GET {path} HTTP/1.1");
            self.heads
                .lock()
                .ok()?
                .iter()
                .find(|head| head.lines().next().map(str::trim) == Some(want.as_str()))
                .cloned()
        }
    }

    impl Drop for Origin {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            let _ = TcpStream::connect((self.host.as_str(), self.port));
            if let Some(join) = self.join.take() {
                let _ = join.join();
            }
        }
    }

    /// Answer one request with the nonce and close. Records the request line and
    /// the whole head verbatim, which is the evidence that the forwarded request
    /// was rewritten to origin-form with the admitted authority as `Host`.
    fn serve_origin(mut stream: TcpStream, seen: &Mutex<Vec<String>>, heads: &Mutex<Vec<String>>) {
        let _ = stream.set_read_timeout(Some(Duration::from_secs(15)));
        let mut buf: Vec<u8> = Vec::new();
        let mut chunk = [0u8; 1024];
        while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
            match stream.read(&mut chunk) {
                Ok(0) | Err(_) => return,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
            }
            if buf.len() > 16 * 1024 {
                return;
            }
        }
        let head = String::from_utf8_lossy(&buf).to_string();
        let line = head.lines().next().unwrap_or("").trim().to_string();
        if let Ok(mut seen) = seen.lock() {
            seen.push(line);
        }
        if let Ok(mut heads) = heads.lock() {
            heads.push(head.clone());
        }
        let body = NONCE;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\
             Connection: close\r\n\r\n{body}",
            body.len()
        );
        let _ = stream.write_all(response.as_bytes());
        let _ = stream.shutdown(std::net::Shutdown::Both);
    }

    /// A real session proxy (`127.0.0.1:0`, this process's own listener) plus the
    /// audit/learned scaffolding it needs.
    struct LiveProxy {
        handle: crate::net::proxy::ProxyHandle,
        sid: String,
        /// This listener's own run token: the only credential it accepts.
        token: RunToken,
        learned_base: PathBuf,
    }

    impl LiveProxy {
        fn start(allow: &[&str]) -> Self {
            Self::start_with_token(allow, RunToken::for_tests(LIVE_TOKEN))
        }

        /// The same listener with a run token of its own (P1.4's two-run test
        /// needs two sessions that must not be able to speak for each other).
        fn start_with_token(allow: &[&str], token: RunToken) -> Self {
            let learned_base = std::env::temp_dir().join(format!(
                "sandbox-mxc-live-learned-{}-{}",
                std::process::id(),
                stamp()
            ));
            std::fs::create_dir_all(&learned_base).expect("learned base");
            let learned = Arc::new(Mutex::new(
                LearnedStore::load_in(&learned_base, Some("live")).expect("learned store"),
            ));
            let intent = Arc::new(IntentRegistry::new(DEFAULT_TTL));
            // Never called: the origin is allow-listed, so the pipeline answers
            // from the allow-list. A dialog that reports itself unavailable makes
            // an accidental prompt a denial rather than a hang.
            let dialog: DialogFn = Arc::new(|_request| Err(DialogUnavailable));
            let prompt = crate::net::proxy::PromptGate {
                enabled: false,
                config: PromptConfig {
                    timeout: Duration::from_secs(1),
                    on_unavailable: PromptPolicy::Deny,
                },
                coordinator: Arc::new(PromptCoordinator::with_dialog(dialog)),
                intent,
                learned,
            };
            let sid = format!("test-mxc-live-{}-{}", std::process::id(), stamp());
            let writer =
                Arc::new(crate::audit::AuditWriter::open(&sid, false).expect("audit writer"));
            let handle = crate::net::proxy::spawn(crate::net::proxy::ProxyConfig {
                session_id: sid.clone(),
                token: token.clone(),
                allow_domain: allow.iter().map(|s| s.to_string()).collect(),
                deny_domain: Vec::new(),
                upstream: None,
                writer,
                prompt,
            })
            .expect("spawn the session proxy");
            Self {
                handle,
                sid,
                token,
                learned_base,
            }
        }

        fn port(&self) -> u16 {
            self.handle.port
        }

        /// This listener's credential, for the child's proxy URL and for the
        /// cross-run refusal legs below.
        fn token(&self) -> &RunToken {
            &self.token
        }

        fn counters(&self) -> Arc<crate::net::proxy::LaunchCounters> {
            self.handle.counters()
        }
    }

    impl Drop for LiveProxy {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(crate::audit::audit_log_path(&self.sid));
            let _ = std::fs::remove_dir_all(&self.learned_base);
        }
    }

    /// A session input built through the **production** policy: workspace-only
    /// readwrite, `denied_paths` from [`filesystem_policy`], and the launcher's
    /// directory as a read-only grant — the policy adds it before filtering the
    /// deny list, so the grant set the request ships is the one the filter saw.
    fn session_input(
        scratch: &Path,
        launcher: &Path,
        denies: &[String],
        command: String,
        proxy_port: Option<u16>,
    ) -> MxcSessionInput {
        let profile = std::env::var_os("USERPROFILE").map(PathBuf::from);
        let filesystem = filesystem_policy(
            scratch,
            // System32-resident workloads (cmd/curl) need the system directory.
            &[r"C:\Windows".to_string()],
            denies,
            profile.as_deref(),
            launcher,
        )
        .expect("no deny in this session's configuration contains a grant");
        MxcSessionInput {
            command,
            working_directory: Some(scratch.display().to_string()),
            environment: Vec::new(),
            filesystem,
            network: MxcNetworkInput {
                proxy_port,
                proxy_token: None,
            },
            // An explicit budget: `None` means no deadline at all (D5), which is
            // wrong for a test that could otherwise hang.
            timeout_ms: Some(180_000),
        }
    }

    fn trace_of(path: &Path) -> String {
        std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
    }

    #[test]
    #[ignore = "launches real ProcessContainers; run: cargo test --features mxc-backend -- --ignored"]
    fn intent_endpoint_is_reachable_from_a_container_and_no_proxy_arrives() {
        let launcher = launcher_under_test();
        let endpoint = Endpoint::start("nonce-p1-wave-1");
        let proof = LiveProof {
            shared: Arc::clone(&endpoint.shared),
        };
        let scratch = Scratch::new();
        let scratch_dir = scratch.path().to_path_buf();

        println!("EVIDENCE launcher={}", launcher.display());
        println!(
            "EVIDENCE elevated={} (TokenElevation of the driving process)",
            process_is_elevated()
        );
        println!(
            "EVIDENCE platform_support={}",
            serde_json::to_string(&v1::platform_support()).unwrap_or_else(|e| e.to_string())
        );
        println!(
            "EVIDENCE endpoint_port={} (proxy and intent endpoint share the listener)",
            endpoint.port
        );

        let backend = MxcBackend::new(&proof, Some(endpoint.port), &launcher)
            .with_proxy_token(LIVE_TOKEN)
            .with_budget(Some(120_000));

        // ---- 1. the child sees NO_PROXY and the SDK's own proxy variables ----
        let outcome = backend
            .launch(
                &live_input(
                    endpoint.port,
                    &scratch_dir,
                    &launcher,
                    "cmd /c set".to_string(),
                ),
                ProofExpectation::MustBeAbsent,
            )
            .expect("environment dump launch");
        let env_dump = stdout_of(&outcome);
        println!(
            "EVIDENCE env_probe exit={:?} success={} proof={:?} proxy_env_lines={:?}",
            outcome.exit_code,
            outcome.success(),
            outcome.proxy_proof,
            proxy_lines(&env_dump)
        );
        assert!(
            outcome.success(),
            "the environment probe must pass guardrail 1: {outcome:?}"
        );
        assert!(
            proxy_lines(&env_dump)
                .iter()
                .any(|line| line == "NO_PROXY=localhost,127.0.0.1,::1"),
            "the child must have NO_PROXY from the launcher: {:?}",
            proxy_lines(&env_dump)
        );
        assert!(
            proxy_lines(&env_dump)
                .iter()
                .any(|line| line.eq_ignore_ascii_case(&format!(
                    "HTTP_PROXY=http://sandbox:{LIVE_TOKEN}@127.0.0.1:{}",
                    endpoint.port
                ))),
            "the SDK's proxy variable must be present WITH the session token (our proxy \
             authenticates every consultation), otherwise NO_PROXY proves nothing: {:?}",
            proxy_lines(&env_dump)
        );

        // ---- 1b. a lowercase lookup resolves to the same value ----
        // Windows environment names are case-insensitive, so `NO_PROXY` and
        // `no_proxy` are one entry; this asserts the spelling a POSIX-emulation
        // client reads resolves, rather than claiming two blocks entries.
        let outcome = backend
            .launch(
                &live_input(
                    endpoint.port,
                    &scratch_dir,
                    &launcher,
                    "cmd /c echo lower=%no_proxy%".to_string(),
                ),
                ProofExpectation::MustBeAbsent,
            )
            .expect("lowercase no_proxy lookup launch");
        let lower = stdout_of(&outcome);
        println!(
            "EVIDENCE no_proxy_lookup exit={:?} stdout={:?}",
            outcome.exit_code,
            lower.trim()
        );
        assert!(
            lower.contains("lower=localhost,127.0.0.1,::1"),
            "a lowercase `no_proxy` lookup must resolve to the loopback list: {lower:?}"
        );

        // ---- 2. the intent endpoint is reachable, directly, from the container ----
        let command = format!("{CURL} -sS -f --max-time 20 {}", endpoint.url());
        let outcome = backend
            .launch(
                &live_input(endpoint.port, &scratch_dir, &launcher, command),
                ProofExpectation::MustBeAbsent,
            )
            .expect("intent endpoint launch");
        let epoch = proof.last_epoch();
        let out = stdout_of(&outcome);
        println!(
            "EVIDENCE intent_get epoch={epoch} exit={:?} stdout={:?} stderr={:?} \
             origin_requests={:?} proxy_consultations={:?}",
            outcome.exit_code,
            out.trim(),
            stderr_of(&outcome),
            endpoint.origin_requests(epoch),
            endpoint.proxy_consultations(epoch)
        );
        assert_eq!(outcome.exit_code, Some(0), "curl failed: {outcome:?}");
        assert!(
            out.contains("nonce-p1-wave-1"),
            "the child's response must come from our endpoint: {out:?}"
        );
        assert!(
            endpoint
                .origin_requests(epoch)
                .iter()
                .any(|line| line.contains("GET /sandbox/intent")),
            "the endpoint must have been called directly (origin form): {:?}",
            endpoint.origin_requests(epoch)
        );
        assert!(
            endpoint.proxy_consultations(epoch).is_empty(),
            "nothing may go through the proxy: {:?}",
            endpoint.proxy_consultations(epoch)
        );
        println!(
            "EVIDENCE guardrail1 epoch={epoch} proof={:?} expectation={:?} closed={} \
             tier={:?} needs_dacl_augmentation={:?}",
            outcome.proxy_proof,
            outcome.expectation,
            endpoint.closed(epoch),
            outcome.tier.tier,
            outcome.tier.needs_dacl_augmentation
        );
        assert!(endpoint.closed(epoch), "the launch epoch must be closed");

        // ---- 3. A/B control: ignore NO_PROXY and the request IS proxied ----
        // Without this leg the positive result above would not show that the
        // proxy is genuinely in the path (`--noproxy ""` empties the list).
        let command = format!(
            r#"{CURL} -sS -f --noproxy "" --max-time 20 {}"#,
            endpoint.url()
        );
        let err = backend
            .launch(
                &live_input(endpoint.port, &scratch_dir, &launcher, command),
                ProofExpectation::Required,
            )
            .expect_err("a proxied loopback request must fail guardrail 1");
        let epoch = proof.last_epoch();
        println!(
            "EVIDENCE ab_control epoch={epoch} err={err} proxy_consultations={:?} \
             origin_requests={:?}",
            endpoint.proxy_consultations(epoch),
            endpoint.origin_requests(epoch)
        );
        assert!(
            matches!(err, MxcError::Guard(GuardError::TunnelNotEstablished)),
            "expected a proxy consultation without a tunnel, got {err:?}"
        );
        assert!(
            !endpoint.proxy_consultations(epoch).is_empty(),
            "with NO_PROXY ignored, the request must reach the proxy"
        );
        assert!(
            endpoint.origin_requests(epoch).is_empty(),
            "with NO_PROXY ignored, nothing may reach the endpoint directly"
        );

        // ---- 4. the workload's own exit code is propagated unchanged ----
        let outcome = backend
            .launch(
                &live_input(
                    endpoint.port,
                    &scratch_dir,
                    &launcher,
                    "cmd /c exit 9".to_string(),
                ),
                ProofExpectation::MustBeAbsent,
            )
            .expect("exit-code launch");
        println!(
            "EVIDENCE exit_code_propagation exit={:?}",
            outcome.exit_code
        );
        assert_eq!(
            outcome.exit_code,
            Some(9),
            "the wrapper must propagate the workload's exit code: {outcome:?}"
        );

        // ---- 5. a failed spawn is a distinct exit code plus a stderr line ----
        let outcome = backend
            .launch(
                &live_input(
                    endpoint.port,
                    &scratch_dir,
                    &launcher,
                    "definitely-not-a-program-p1.exe --flag".to_string(),
                ),
                ProofExpectation::MustBeAbsent,
            )
            .expect("a spawn failure is a normal exit, not a launch error");
        let err_out = stderr_of(&outcome);
        println!(
            "EVIDENCE spawn_failure exit={:?} stderr={:?}",
            outcome.exit_code,
            err_out.trim()
        );
        assert_eq!(
            outcome.exit_code,
            Some(127),
            "a failed spawn must be its own non-zero code: {outcome:?}"
        );
        assert!(
            err_out.contains("mxc-launch: failed to start"),
            "the failure must be named on stderr: {err_out:?}"
        );

        println!(
            "EVIDENCE done: intent endpoint reachable unelevated through the launcher, NO_PROXY delivered"
        );
    }
    /// The four wave-2 legs, unelevated, against the **real** supervisor proxy
    /// (a real `127.0.0.1:0` listener with its own counters) and a real local
    /// origin:
    ///
    /// 1. a CONNECT session reaches the origin and proves a tunnel;
    /// 2. a plain-HTTP (absolute-form, **no CONNECT**) session reaches the origin
    ///    and *also* proves upstream establishment — the counting fix in A;
    /// 3. a proxy-less session passes `MustBeAbsent` and cannot reach the origin;
    /// 4. the filesystem policy: the granted workspace is writable, a denied path
    ///    and an ungranted path are not, and `C:\Windows` stays readable (the
    ///    recorded additive-grants caveat).
    #[test]
    #[ignore = "launches real ProcessContainers and a real proxy; run: cargo test --features mxc-backend -- --ignored"]
    fn proxied_plain_http_blocked_and_filesystem_legs_are_proven() {
        let launcher = launcher_under_test();
        let origin = Origin::start();
        let proxy = LiveProxy::start(&[origin.host.as_str()]);
        let counters = proxy.counters();
        let scratch = Scratch::named("legs");
        let secret = Scratch::named("legs-secret");
        let scratch_dir = scratch.path().to_path_buf();
        let secret_dir = secret.path().to_path_buf();

        std::fs::write(secret_dir.join("secret.txt"), "top-secret").expect("write the secret");
        let denies = vec![secret_dir.display().to_string()];

        println!(
            "EVIDENCE elevated={} launcher={} proxy_port={} origin={}",
            process_is_elevated(),
            launcher.display(),
            proxy.port(),
            origin.authority()
        );
        println!(
            "EVIDENCE launcher_grant={:?} (filesystem_policy inserts it before filtering denies)",
            launcher_grant(&launcher)
        );
        let policy = filesystem_policy(
            &scratch_dir,
            &[r"C:\Windows".to_string()],
            &denies,
            std::env::var_os("USERPROFILE")
                .map(PathBuf::from)
                .as_deref(),
            &launcher,
        )
        .expect("no deny in this session's configuration contains a grant");
        println!("EVIDENCE filesystem_policy={policy:?}");
        // Asserted, not merely printed: the grant without which the container
        // cannot execute the launcher, and the four built-in credential denies
        // (item (f): an operator whose workspace sits inside one of them gets a
        // refusal naming a path they never configured).
        let grant = launcher_grant(&launcher).expect("the launcher has a directory");
        assert!(
            policy
                .readonly_paths
                .iter()
                .any(|kept| path_key(kept) == path_key(&grant)),
            "the launcher grant must ship in the policy: {:?}",
            policy.readonly_paths
        );
        match std::env::var_os("USERPROFILE").map(PathBuf::from) {
            Some(profile) => {
                for dir in PROFILE_SECRET_DIRS {
                    let expected = profile.join(dir).display().to_string();
                    assert!(
                        policy
                            .denied_paths
                            .iter()
                            .any(|denied| path_key(denied) == path_key(&expected)),
                        "the built-in {dir} deny must survive the grant filter: {:?}",
                        policy.denied_paths
                    );
                }
            }
            None => println!("EVIDENCE credential_denies skipped: no USERPROFILE"),
        }

        // ---- leg 1: CONNECT through the proxy to the local origin ----------
        let trace = scratch_dir.join("leg-connect.trace");
        let command = format!(
            "{CURL} -sS -f --max-time 25 --proxytunnel --trace-ascii \"{}\" {}",
            trace.display(),
            origin.url("/proxied")
        );
        let outcome = launch_session(
            counters.as_ref(),
            Some(proxy.port()),
            Some(LIVE_TOKEN),
            &launcher,
            &session_input(
                &scratch_dir,
                &launcher,
                &denies,
                command,
                Some(proxy.port()),
            ),
        )
        .expect("the CONNECT leg must pass guardrail 1");
        println!(
            "EVIDENCE connect_leg exit={:?} success={} proof={:?} expectation={:?} tier={:?} \
             stdout={:?} stderr={:?}",
            outcome.exit_code,
            outcome.success(),
            outcome.proxy_proof,
            outcome.expectation,
            outcome.tier.tier,
            stdout_of(&outcome).trim(),
            stderr_of(&outcome).trim()
        );
        assert_eq!(outcome.exit_code, Some(0), "curl failed: {outcome:?}");
        assert!(
            stdout_of(&outcome).contains(NONCE),
            "the body must come from the origin: {:?}",
            stdout_of(&outcome)
        );
        assert!(
            origin.saw("/proxied"),
            "the origin must have served the tunnelled request: {:?}",
            origin.requests()
        );
        assert!(
            outcome.proxy_proof.accepted >= 1,
            "the proxy must have been consulted: {:?}",
            outcome.proxy_proof
        );
        assert!(
            outcome.proxy_proof.tunnels >= 1,
            "a live CONNECT must establish an upstream tunnel: {:?}",
            outcome.proxy_proof
        );
        assert_eq!(outcome.expectation, ProofExpectation::Required);
        assert!(outcome.success(), "a proven launch must report success");
        let connect_trace = trace_of(&trace);
        assert!(
            connect_trace.contains(&format!("CONNECT {}", origin.authority())),
            "the child's own bytes must show a CONNECT to the proxy: {connect_trace:?}"
        );
        println!(
            "EVIDENCE connect_leg_child_bytes={:?}",
            connect_trace
                .lines()
                .find(|line| line.contains("CONNECT "))
                .unwrap_or("")
                .trim()
        );

        // ---- leg 2: plain HTTP, absolute-form, NO CONNECT -------------------
        let trace = scratch_dir.join("leg-plain.trace");
        let command = format!(
            "{CURL} -sS -f --max-time 25 --trace-ascii \"{}\" {}",
            trace.display(),
            origin.url("/plain")
        );
        let outcome = launch_session(
            counters.as_ref(),
            Some(proxy.port()),
            Some(LIVE_TOKEN),
            &launcher,
            &session_input(
                &scratch_dir,
                &launcher,
                &denies,
                command,
                Some(proxy.port()),
            ),
        )
        .expect("the plain-HTTP leg must pass guardrail 1");
        println!(
            "EVIDENCE plain_http_leg exit={:?} success={} proof={:?} expectation={:?} \
             stdout={:?} stderr={:?}",
            outcome.exit_code,
            outcome.success(),
            outcome.proxy_proof,
            outcome.expectation,
            stdout_of(&outcome).trim(),
            stderr_of(&outcome).trim()
        );
        assert_eq!(outcome.exit_code, Some(0), "curl failed: {outcome:?}");
        assert!(stdout_of(&outcome).contains(NONCE));
        assert!(
            origin.saw("/plain"),
            "the origin must have served the forwarded request: {:?}",
            origin.requests()
        );
        // Origin-side evidence for the rewrite: what the *origin* saw, not what
        // the client sent. The Host must be the admitted authority and our proxy
        // credential must be absent.
        let plain_head = origin
            .head_for("/plain")
            .expect("the origin must record the head it was sent");
        println!("EVIDENCE plain_http_leg_origin_head={plain_head:?}");
        let want_host = format!("Host: {}", origin.authority());
        assert!(
            plain_head
                .lines()
                .any(|line| line.trim_end() == want_host.as_str()),
            "the origin must see the admitted authority as Host: {plain_head:?}"
        );
        assert!(
            !plain_head
                .to_ascii_lowercase()
                .contains("proxy-authorization"),
            "our proxy credential must never reach an origin: {plain_head:?}"
        );
        assert!(
            outcome.proxy_proof.accepted >= 1,
            "a plain-HTTP forward is a proxy consultation: {:?}",
            outcome.proxy_proof
        );
        assert!(
            outcome.proxy_proof.tunnels >= 1,
            "`tunnels` means 'upstream established': a completed plain-HTTP forward must satisfy \
             it, otherwise Required fails a working session: {:?}",
            outcome.proxy_proof
        );
        assert!(outcome.success());
        let plain_trace = trace_of(&trace);
        assert!(
            plain_trace.contains(&format!("GET {}", origin.url("/plain"))),
            "the child must have sent an ABSOLUTE-form request to the proxy: {plain_trace:?}"
        );
        println!(
            "EVIDENCE plain_http_leg_child_bytes={:?} contains_connect={}",
            plain_trace
                .lines()
                .find(|line| line.contains("GET "))
                .unwrap_or("")
                .trim(),
            plain_trace.contains("CONNECT ")
        );
        assert!(
            !plain_trace.contains("CONNECT "),
            "this leg must not involve CONNECT at all: {plain_trace:?}"
        );

        // ---- leg 3: blocked session (no proxy) -----------------------------
        let command = format!(
            "{CURL} -sS -f --max-time 8 --connect-timeout 5 {}",
            origin.url("/blocked")
        );
        let outcome = launch_session(
            counters.as_ref(),
            None,
            None,
            &launcher,
            &session_input(&scratch_dir, &launcher, &denies, command, None),
        )
        .expect("a blocked session that stayed offline passes MustBeAbsent");
        println!(
            "EVIDENCE blocked_leg exit={:?} proof={:?} expectation={:?} stderr={:?}",
            outcome.exit_code,
            outcome.proxy_proof,
            outcome.expectation,
            stderr_of(&outcome).trim()
        );
        assert_eq!(outcome.expectation, ProofExpectation::MustBeAbsent);
        assert_eq!(
            outcome.proxy_proof,
            ProxyProof::default(),
            "a blocked session must never consult the proxy"
        );
        assert_ne!(
            outcome.exit_code,
            Some(0),
            "without a proxy the workload cannot reach the origin: {outcome:?}"
        );
        assert!(
            !origin.saw("/blocked"),
            "the blocked workload reached the origin: {:?}",
            origin.requests()
        );
        assert!(
            !outcome.success(),
            "the guardrail leg passed, but a workload that failed is not a successful session"
        );

        // ---- leg 4: filesystem policy --------------------------------------
        // (a) the granted workspace is writable and readable.
        let probe = scratch_dir.join("probe.txt");
        let command = format!(
            "cmd /c echo granted>\"{}\" & type \"{}\"",
            probe.display(),
            probe.display()
        );
        let outcome = launch_session(
            counters.as_ref(),
            None,
            None,
            &launcher,
            &session_input(&scratch_dir, &launcher, &denies, command, None),
        )
        .expect("the workspace write leg must launch");
        println!(
            "EVIDENCE fs_granted exit={:?} stdout={:?} stderr={:?}",
            outcome.exit_code,
            stdout_of(&outcome).trim(),
            stderr_of(&outcome).trim()
        );
        assert_eq!(
            outcome.exit_code,
            Some(0),
            "the granted workspace must be writable: {outcome:?}"
        );
        assert!(stdout_of(&outcome).to_ascii_lowercase().contains("granted"));
        assert_eq!(
            std::fs::read_to_string(&probe).unwrap_or_default().trim(),
            "granted",
            "the write must have landed in the granted directory"
        );

        // (b) a denied path is not readable.
        let secret_file = secret_dir.join("secret.txt");
        let command = format!("cmd /c type \"{}\"", secret_file.display());
        let outcome = launch_session(
            counters.as_ref(),
            None,
            None,
            &launcher,
            &session_input(&scratch_dir, &launcher, &denies, command, None),
        )
        .expect("the denied-read leg must launch");
        println!(
            "EVIDENCE fs_denied_read exit={:?} stdout={:?} stderr={:?}",
            outcome.exit_code,
            stdout_of(&outcome).trim(),
            stderr_of(&outcome).trim()
        );
        assert!(
            secret_file.is_file(),
            "the file must exist outside the container, or 'unreadable' proves nothing"
        );
        assert_ne!(
            outcome.exit_code,
            Some(0),
            "a denied path must not be readable: {outcome:?}"
        );
        assert!(
            !stdout_of(&outcome).contains("top-secret"),
            "the secret's content must never reach the child: {:?}",
            stdout_of(&outcome)
        );

        // (c) a denied path is not writable.
        let planted = secret_dir.join("planted.txt");
        let command = format!("cmd /c echo leaked>\"{}\"", planted.display());
        let outcome = launch_session(
            counters.as_ref(),
            None,
            None,
            &launcher,
            &session_input(&scratch_dir, &launcher, &denies, command, None),
        )
        .expect("the denied-write leg must launch");
        println!(
            "EVIDENCE fs_denied_write exit={:?} stderr={:?}",
            outcome.exit_code,
            stderr_of(&outcome).trim()
        );
        assert_ne!(
            outcome.exit_code,
            Some(0),
            "a denied path must not be writable: {outcome:?}"
        );
        assert!(
            !planted.exists(),
            "the child wrote into a denied path: {}",
            planted.display()
        );

        // (d) an ungranted path (outside the workspace, not on the deny list) is
        //     not writable either: containment is grants, not only denies.
        let outside = std::env::temp_dir().join(format!("mxc-outside-{}.txt", std::process::id()));
        let _ = std::fs::remove_file(&outside);
        let command = format!("cmd /c echo escaped>\"{}\"", outside.display());
        let outcome = launch_session(
            counters.as_ref(),
            None,
            None,
            &launcher,
            &session_input(&scratch_dir, &launcher, &denies, command, None),
        )
        .expect("the ungranted-write leg must launch");
        println!(
            "EVIDENCE fs_ungranted_write exit={:?} stderr={:?}",
            outcome.exit_code,
            stderr_of(&outcome).trim()
        );
        assert_ne!(
            outcome.exit_code,
            Some(0),
            "an ungranted path must not be writable: {outcome:?}"
        );
        assert!(
            !outside.exists(),
            "the child escaped the workspace: {}",
            outside.display()
        );

        // (e) the recorded caveat: system directories stay readable, because the
        //     policy is additive grants (ADR-0004). Asserted as the caveat it is,
        //     so nobody "fixes" it by denying C:\Windows.
        let win_ini = Path::new(r"C:\Windows\win.ini");
        if win_ini.is_file() {
            let command = format!("cmd /c type \"{}\"", win_ini.display());
            let outcome = launch_session(
                counters.as_ref(),
                None,
                None,
                &launcher,
                &session_input(&scratch_dir, &launcher, &denies, command, None),
            )
            .expect("the system-dir caveat leg must launch");
            let first = stdout_of(&outcome).chars().take(48).collect::<String>();
            println!(
                "EVIDENCE caveat_system_dir_readable exit={:?} first_48={first:?}",
                outcome.exit_code
            );
            assert_eq!(
                outcome.exit_code,
                Some(0),
                "RECORDED CAVEAT: MXC filesystem policy is additive grants, so C:\\Windows stays \
                 readable inside the container (ADR-0004); this leg records that, it does not \
                 claim otherwise"
            );
        } else {
            println!("EVIDENCE caveat_system_dir_readable skipped: no C:\\Windows\\win.ini");
        }

        println!(
            "EVIDENCE done: proxied CONNECT, plain-HTTP forward, blocked and filesystem legs all \
             proven unelevated against the supervisor's own listener"
        );
    }

    // =====================================================================
    // P1.4: two concurrent sessions, two listeners, two run tokens
    // =====================================================================

    /// One `CONNECT` carrying a credential the test chose, blocking.
    ///
    /// A container can only present its own run's token (it rides its proxy
    /// URL), so the cross-run legs use a raw socket: presenting *another* run's
    /// token is exactly what must be refused.
    fn cx(port: u16, token: &str, target: &str) -> String {
        let mut sock = TcpStream::connect(("127.0.0.1", port)).expect("connect the listener");
        sock.set_read_timeout(Some(Duration::from_secs(5)))
            .expect("read timeout");
        let creds = base64::engine::general_purpose::STANDARD.encode(format!("sandbox:{token}"));
        let req =
            format!("CONNECT {target} HTTP/1.1\r\nProxy-Authorization: Basic {creds}\r\n\r\n");
        sock.write_all(req.as_bytes()).expect("write CONNECT");
        let mut out = Vec::new();
        let mut chunk = [0u8; 256];
        // Read until the status line is complete; a tunnel keeps the socket
        // open afterwards, so this must never read to EOF.
        while !out.windows(2).any(|w| w == b"\r\n") {
            match sock.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(n) => out.extend_from_slice(&chunk[..n]),
            }
        }
        String::from_utf8_lossy(&out).into_owned()
    }

    /// CONNECT leaves in a session's audit chain.
    fn connect_leaves(sid: &str) -> usize {
        std::fs::read_to_string(crate::audit::audit_log_path(sid))
            .unwrap_or_default()
            .lines()
            .filter(|line| line.contains("\"op\":\"CONNECT\""))
            .count()
    }

    /// **P1.4 mandatory test: two containers, concurrently.**
    ///
    /// Each session gets its own listener, its own port and its own run token.
    /// The assertions are the four the review asked for: both sessions prove
    /// their own guardrail, each proof counts **only** its own traffic (`{1,1}`,
    /// never the `{2,2}` a shared listener would produce), a token from the other
    /// session is refused at the first listener with a `407` that is neither
    /// counted nor audited, and closing one session leaves the other's counters
    /// and service untouched.
    ///
    /// Run: `cargo test --features mxc-backend --bin sandbox -- --ignored --nocapture`
    #[test]
    #[ignore = "launches two real ProcessContainers; run: cargo test --features mxc-backend -- --ignored"]
    fn two_concurrent_sessions_prove_only_their_own_traffic_and_refuse_each_others_tokens() {
        let launcher = launcher_under_test();
        let origin_a = Origin::start();
        let origin_b = Origin::start();
        // Two runs, two credentials, minted the way the supervisor mints them.
        let token_a = RunToken::issue().expect("mint run A's token");
        let token_b = RunToken::issue().expect("mint run B's token");
        let a = LiveProxy::start_with_token(&[origin_a.host.as_str()], token_a.clone());
        let b = LiveProxy::start_with_token(&[origin_b.host.as_str()], token_b.clone());

        println!(
            "EVIDENCE elevated={} (TokenElevation of the driving process)",
            process_is_elevated()
        );
        println!(
            "EVIDENCE run_a port={} token_run={} origin={}",
            a.port(),
            a.token().run(),
            origin_a.authority()
        );
        println!(
            "EVIDENCE run_b port={} token_run={} origin={}",
            b.port(),
            b.token().run(),
            origin_b.authority()
        );
        assert_ne!(a.port(), b.port(), "each run gets its own listener");
        assert_ne!(
            token_a.value(),
            token_b.value(),
            "each run gets its own credential"
        );

        let scratch_a = Scratch::named("p14-run-a");
        let scratch_b = Scratch::named("p14-run-b");
        let dir_a = scratch_a.path().to_path_buf();
        let dir_b = scratch_b.path().to_path_buf();
        let no_denies: Vec<String> = Vec::new();

        // A: a real CONNECT tunnel. B: a real absolute-form plain-HTTP forward.
        // Different legs on purpose — each session proves itself with the leg it
        // uses, and neither proof can be borrowed from the other.
        let command_a = format!(
            "{CURL} -sS -f --max-time 40 --proxytunnel {}",
            origin_a.url("/run-a")
        );
        let command_b = format!("{CURL} -sS -f --max-time 40 {}", origin_b.url("/run-b"));
        let input_a = session_input(&dir_a, &launcher, &no_denies, command_a, Some(a.port()));
        let input_b = session_input(&dir_b, &launcher, &no_denies, command_b, Some(b.port()));

        let counters_a = a.counters();
        let counters_b = b.counters();

        // Genuinely concurrent: both containers are in flight at once, each
        // pointed at its own listener by its own proxy URL.
        let (out_a, out_b) = std::thread::scope(|scope| {
            let handle_a = scope.spawn(|| {
                launch_session(
                    counters_a.as_ref(),
                    Some(a.port()),
                    Some(a.token().value()),
                    &launcher,
                    &input_a,
                )
            });
            let handle_b = scope.spawn(|| {
                launch_session(
                    counters_b.as_ref(),
                    Some(b.port()),
                    Some(b.token().value()),
                    &launcher,
                    &input_b,
                )
            });
            (
                handle_a.join().expect("run A's launch thread"),
                handle_b.join().expect("run B's launch thread"),
            )
        });

        let out_a = out_a.expect("run A must pass guardrail 1");
        let out_b = out_b.expect("run B must pass guardrail 1");
        println!(
            "EVIDENCE run_a exit={:?} success={} proof={:?} stdout={:?} stderr={:?}",
            out_a.exit_code,
            out_a.success(),
            out_a.proxy_proof,
            stdout_of(&out_a).trim(),
            stderr_of(&out_a).trim()
        );
        println!(
            "EVIDENCE run_b exit={:?} success={} proof={:?} stdout={:?} stderr={:?}",
            out_b.exit_code,
            out_b.success(),
            out_b.proxy_proof,
            stdout_of(&out_b).trim(),
            stderr_of(&out_b).trim()
        );

        // (i) both sessions succeed.
        assert_eq!(out_a.exit_code, Some(0), "run A's curl failed: {out_a:?}");
        assert_eq!(out_b.exit_code, Some(0), "run B's curl failed: {out_b:?}");
        assert!(out_a.success() && out_b.success());

        // (ii) each proof is exactly its own traffic. `{2,2}` here would mean one
        // listener had served both sessions (the R3 masking failure).
        assert_eq!(
            out_a.proxy_proof,
            ProxyProof {
                accepted: 1,
                tunnels: 1,
            },
            "run A's proof must count only run A's consultation"
        );
        assert_eq!(
            out_b.proxy_proof,
            ProxyProof {
                accepted: 1,
                tunnels: 1,
            },
            "run B's proof must count only run B's consultation"
        );
        assert!(
            stdout_of(&out_a).contains(NONCE) && stdout_of(&out_b).contains(NONCE),
            "each session's body must come from its own origin"
        );
        assert!(
            origin_a.saw("/run-a") && !origin_a.saw("/run-b"),
            "origin A served another session's request: {:?}",
            origin_a.requests()
        );
        assert!(
            origin_b.saw("/run-b") && !origin_b.saw("/run-a"),
            "origin B served another session's request: {:?}",
            origin_b.requests()
        );

        // (iii) a token from the other session is refused at the first: 407, not
        // counted, and no leaf in that run's audit chain.
        let epoch_a = counters_a.begin_epoch().expect("a fresh window for A");
        let leaves_before = connect_leaves(&a.sid);
        let resp = cx(a.port(), token_b.value(), &origin_a.authority());
        println!(
            "EVIDENCE foreign_token_at_run_a status={:?} counters={:?} leaves_before={} leaves_after={}",
            resp.lines().next().unwrap_or(""),
            counters_a.counters(epoch_a),
            leaves_before,
            connect_leaves(&a.sid)
        );
        assert!(
            resp.starts_with("HTTP/1.1 407"),
            "run A must refuse run B's token: {resp:?}"
        );
        assert_eq!(
            counters_a.counters(epoch_a),
            Some(LaunchProofCounters::default()),
            "a foreign token must not count as a consultation"
        );
        assert_eq!(
            connect_leaves(&a.sid),
            leaves_before + 1,
            "a foreign token must be recorded once in run A's chain"
        );

        let epoch_b = counters_b.begin_epoch().expect("a fresh window for B");
        let leaves_before = connect_leaves(&b.sid);
        let resp = cx(b.port(), token_a.value(), &origin_b.authority());
        println!(
            "EVIDENCE foreign_token_at_run_b status={:?} counters={:?} leaves_before={} leaves_after={}",
            resp.lines().next().unwrap_or(""),
            counters_b.counters(epoch_b),
            leaves_before,
            connect_leaves(&b.sid)
        );
        assert!(
            resp.starts_with("HTTP/1.1 407"),
            "run B must refuse run A's token: {resp:?}"
        );
        assert_eq!(
            counters_b.counters(epoch_b),
            Some(LaunchProofCounters::default()),
            "a foreign token must not count at run B either"
        );
        assert_eq!(
            connect_leaves(&b.sid),
            leaves_before + 1,
            "a foreign token must be recorded once in run B's chain"
        );

        // Each listener still serves its own token, so the refusals above are
        // about ownership and not a broken listener.
        let resp = cx(a.port(), token_a.value(), &origin_a.authority());
        assert!(
            resp.starts_with("HTTP/1.1 200"),
            "run A must accept its own token: {resp:?}"
        );
        let resp = cx(b.port(), token_b.value(), &origin_b.authority());
        assert!(
            resp.starts_with("HTTP/1.1 200"),
            "run B must accept its own token: {resp:?}"
        );

        // (iv) closing one session does not disturb the other's counters or its
        // ability to serve.
        let frozen_b = counters_b.counters(epoch_b);
        drop(b);
        println!(
            "EVIDENCE after_closing_run_b run_a_counters={:?} run_b_counters_frozen={:?}",
            counters_a.counters(epoch_a),
            frozen_b
        );
        assert_eq!(
            counters_b.counters(epoch_b),
            frozen_b,
            "closing run B must not change run B's frozen counters"
        );
        let resp = cx(a.port(), token_a.value(), &origin_a.authority());
        assert!(
            resp.starts_with("HTTP/1.1 200"),
            "run A must keep serving after run B closes: {resp:?}"
        );
        let leaves_before = connect_leaves(&a.sid);
        let resp = cx(a.port(), token_b.value(), &origin_a.authority());
        assert!(
            resp.starts_with("HTTP/1.1 407"),
            "run A must still refuse B's token after B closed: {resp:?}"
        );
        assert_eq!(
            connect_leaves(&a.sid),
            leaves_before + 1,
            "the refusal after B closed is recorded as one event in A's chain"
        );
        assert!(
            counters_a.close_epoch(epoch_a),
            "run A's window is still the open one"
        );
        assert!(counters_b.close_epoch(epoch_b));

        println!(
            "EVIDENCE done: two concurrent sessions, each proofed by its own listener and its \
             own run token, with the cross-run token refused uncounted and unaudited"
        );
    }

    /// PowerShell 5.1 lives here (System32), and the container's policy grants
    /// `C:\Windows` read-only.
    const POWERSHELL: &str = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";

    /// **The managed-workload leg (P3).**
    ///
    /// Every other leg in this module runs a native executable (`curl.exe`,
    /// `cmd.exe`), and a native child starts even when the container bans Win32k
    /// system calls — so this suite could have been fully green while **every**
    /// managed workload died at load. It was: with `ContainerRequest::ui` unset,
    /// the SDK's `UiPolicy::default()` (`disable: true`) becomes
    /// `PROCESS_CREATION_MITIGATION_POLICY_WIN32K_SYSTEM_CALL_DISABLE`, `user32`,
    /// `gdi32` and `ole32` then fail `DllMain` with `ERROR_DLL_INIT_FAILED`
    /// (1114), and `powershell.exe` exits `0xC0000142`
    /// (`STATUS_DLL_INIT_FAILED`) with empty output.
    ///
    /// So this leg asserts only that a CLR-hosted workload *starts* inside the
    /// container, through the same wrapper, the same filesystem policy and the
    /// same proxy-only network posture as the other legs. The command is pure
    /// PowerShell on purpose: 5.1 cannot invoke native commands as an
    /// AppContainer child (`DriveNotFoundException:
    /// Microsoft.PowerShell.Core\FileSystem`), and `Write-Output` needs no
    /// subprocess. `FXOK` is the proof the child reached managed code — an exit
    /// code alone would also pass a silently swallowed error.
    ///
    /// Red without the fix: remove the `request.ui` assignment in
    /// [`build_request`] and this leg reports `exit=Some(-1073741502)`
    /// (`0xC0000142`) with empty stdout.
    #[test]
    #[ignore = "launches a real ProcessContainer; run: cargo test --features mxc-backend -- --ignored"]
    fn managed_powershell_workload_starts_and_prints_fxok_inside_the_container() {
        let launcher = launcher_under_test();
        // No allowed origin: this workload makes no network request, and an
        // empty allow-list keeps that honest if it ever tried to.
        let proxy = LiveProxy::start(&[]);
        let counters = proxy.counters();
        let scratch = Scratch::named("managed");
        let dir = scratch.path().to_path_buf();
        let no_denies: Vec<String> = Vec::new();

        let command =
            format!(r#"{POWERSHELL} -NoProfile -NonInteractive -Command "Write-Output FXOK""#);
        let input = session_input(
            &dir,
            &launcher,
            &no_denies,
            command.clone(),
            Some(proxy.port()),
        );
        println!(
            "EVIDENCE elevated={} managed_command={:?} launcher={} proxy_port={}",
            process_is_elevated(),
            command,
            launcher.display(),
            proxy.port()
        );

        // The normal launch path, with the proof expectation stated rather than
        // derived: `launch_session` demands `Required` whenever the request
        // carries a proxy port, and this command cannot consult a proxy.
        let backend = MxcBackend::new(counters.as_ref(), Some(proxy.port()), &launcher)
            .with_proxy_token(proxy.token().value())
            .with_budget(Some(120_000));
        let outcome = backend
            .launch(&input, ProofExpectation::MustBeAbsent)
            .expect("a workload with no network use must leave the proxy unconsulted");
        let out = stdout_of(&outcome);
        println!(
            "EVIDENCE managed_workload exit={:?} timed_out={} success={} proof={:?} tier={:?}",
            outcome.exit_code,
            outcome.timed_out,
            outcome.success(),
            outcome.proxy_proof,
            outcome.tier.tier
        );
        println!(
            "EVIDENCE managed_workload_stdout={:?} stderr={:?} readonly_grants={:?}",
            out.trim(),
            stderr_of(&outcome).trim(),
            input.filesystem.readonly_paths
        );

        assert_eq!(
            outcome.exit_code,
            Some(0),
            "a CLR workload must start inside the container; exit -1073741502 (0xC0000142) is \
             STATUS_DLL_INIT_FAILED, i.e. the Win32k ban is back: {outcome:?}"
        );
        assert!(
            out.contains("FXOK"),
            "the managed child must have reached managed code and printed FXOK: {out:?}"
        );
        println!(
            "EVIDENCE done: powershell started inside the container and printed FXOK (ui.disable = false)"
        );
    }
}
