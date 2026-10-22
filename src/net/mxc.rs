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
//! Not here, by design: the session-start audit leaf (P2.3) and the WinHTTP
//! measurement (P1.5). The per-run token
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
// `TIER_SOURCE_UNAVAILABLE`, `RequestError`, `MxcError`, `SessionOutcome`,
// `build_request`,
// `process_container_config`, `MxcBackend`.
#![cfg_attr(not(test), allow(dead_code))]

use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::net::proxy::EpochAlreadyOpen;

use mxc_sdk::v1;
use mxc_sdk::v1::configs::{
    ProcessContainerConfig, ProcessContainerSystemSettings, ProcessContainerUi,
    ProcessContainerUiIsolation,
};
use mxc_sdk::v1::{
    ClipboardPolicy, ContainerRequest, Containment, FilesystemPolicy, NetworkAction,
    NetworkEgressPolicy, NetworkIngressPolicy, NetworkPolicy, NetworkRuntimeConfig, SpawnOptions,
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
fn run_timed(process: v1::MxcProcess, deadline: std::time::Instant) -> std::io::Result<TimedChild> {
    // How often the child's exit is sampled: the cost of noticing it, paid once per
    // launch. Small against the `slack` a session budgets for startup and teardown,
    // large against the syscall's own cost.
    const EXIT_POLL: Duration = Duration::from_millis(20);

    let mut process = process;
    // Take both streams before waiting so `wait` cannot discard them, and read each on
    // its own thread so an output-heavy child cannot deadlock on a full pipe. Same
    // shape as the SDK's `wait_with_output`, whose closers are what let a timed-out
    // descendant's readers finish.
    let stdout_closer = process.stdout_closer();
    let stderr_closer = process.stderr_closer();
    let stdout = capture_stream(process.take_stdout());
    let stderr = capture_stream(process.take_stderr());

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
    let wait = process.wait();
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
    let stdout = join_capture(stdout)?;
    let stderr = join_capture(stderr)?;
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
// P2.1: the session budget (timeout_ms = prompt + workload + slack)
// ---------------------------------------------------------------------------

/// The **prompt term**: how long ONE prompt consultation may legitimately take.
///
/// The same value the coordinator uses ([`crate::net::prompt::
/// DEFAULT_PROMPT_TIMEOUT`], 60 s — the ADR's `network.promptTimeoutSecs`
/// default), and deliberately the same constant rather than a second number that
/// can drift: the container's deadline is computed from this, and if a dialog were
/// allowed to take longer than the term this budget reserves for it, a
/// legitimate dialog would kill the session.
pub const PROMPT_BUDGET: Duration = crate::net::prompt::DEFAULT_PROMPT_TIMEOUT;

/// The **workload term**: how long the sandboxed workload itself may run.
///
/// [`crate::net::DEFAULT_WORKLOAD_TIMEOUT_SECS`] (30 min) — the `network.
/// workloadTimeoutSecs` default: long enough for the workloads this tool actually
/// runs (a build, a test suite, a model download over the proxy) and short enough
/// that a wedged child cannot hold a container for a day. It is *not* the
/// container's deadline — that is this plus the prompt term plus the slack — so a
/// session that spends its whole prompt budget still gets this much time to work.
///
/// **This is a bound the tool never had.** Before P2.1 the session had no bound at
/// all (`timeout_ms: None`, i.e. `INFINITE`), so a profile that legitimately needs
/// longer — a cold Rust build with a large dependency graph, a multi-gigabyte model
/// download — must RAISE it with `network.workloadTimeoutSecs`. The failure mode
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
    /// from `network.promptTimeoutSecs` / `network.workloadTimeoutSecs`.
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
    /// Takes the RESOLVED values in seconds — `network.promptTimeoutSecs` and
    /// `network.workloadTimeoutSecs` after defaults and validation — never the
    /// constants, and never a `Duration` built at the call site: the failure this
    /// replaces was a budget sized from [`PROMPT_BUDGET`] (the 60 s DEFAULT) while
    /// the dialog actually got the profile's `promptTimeoutSecs`. A 300 s profile
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
            budget: SessionBudget::default(),
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
            budget: SessionBudget::default(),
            launcher: launcher.into(),
        }
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
    pub fn request_for(&self, input: &MxcSessionInput) -> Result<ContainerRequest, MxcError> {
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
            let process = v1::spawn(request, SpawnOptions::default()).map_err(MxcError::from)?;
            // The container exists and the workload was launched: the handshake is
            // over. Everything after this point is the workload's own time.
            let handshake_elapsed = started.elapsed();
            let exec = run_timed(process, deadline).map_err(|e| {
                MxcError::Sdk(v1::Error::new(
                    v1::ErrorCode::BackendError,
                    format!("waiting for the sandbox to complete failed: {e}"),
                ))
            })?;
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
    clock: SessionClock,
) -> Result<SessionOutcome, MxcError> {
    // Guardrail 1 first and unconditionally: `warnings: []` and exit 0 are not
    // evidence, so a failed proof poisons every outcome, timeout included.
    verify_proxy_proof(proof, expectation)?;

    // P2.1: a kill at the deadline is attributed to the term that spent the time,
    // from measurements the supervisor and the listener took — never guessed from
    // the fact that a timeout happened.
    let (exit_code, timeout) = match child.wait {
        WaitResult::Exited(code) => (Some(code), None),
        WaitResult::TimedOut => (None, Some(clock.timeout_reason())),
    };

    Ok(SessionOutcome {
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

    /// A session clock for tests that are about the gate, not the budget: the
    /// default budget, no elapsed time, no prompt time. A kill under it classifies
    /// as a handshake timeout, which is what "no time was spent anywhere" means.
    fn clock() -> SessionClock {
        SessionClock::default()
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
            clock(),
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
            clock(),
        )
        .expect("proven launch");
        assert!(outcome.success());
        assert_eq!(outcome.exit_code, Some(0));
        assert!(!outcome.timed_out());
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
            clock(),
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
                timeout: None,
                stdout: Vec::new(),
                stderr: Vec::new(),
                warnings: Vec::new(),
                tier: tier(),
                proxy_proof: proof,
                expectation,
                clock: clock(),
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
            clock(),
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
            clock(),
        )
        .expect("proven launch");
        assert!(outcome.timed_out());
        assert_eq!(
            outcome.timeout,
            Some(TimeoutReason::SessionHandshake),
            "a kill with no time spent in the workload or the prompt is a handshake timeout"
        );
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
            clock(),
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
        // 300 + 650 + 50 = 1000 ms of session.
        let budget = SessionBudget::new(
            Duration::from_millis(300),
            Duration::from_millis(650),
            Duration::from_millis(50),
        );
        let backend = MxcBackend::new(&source, Some(49_152), TEST_LAUNCHER).with_budget(budget);
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
        assert_eq!(backend.budget(), budget);
        assert_eq!(backend.proxy_port(), Some(49_152));
        assert_eq!(backend.launcher(), Path::new(TEST_LAUNCHER));
    }

    /// P2.1, item 4: **the supervisor path cannot ship an unbounded session.**
    ///
    /// `timeout_ms: None` (and `Some(0)`) is INFINITE in the SDK, and the old
    /// backend passed a caller's value through unchanged — so a supervisor that
    /// left the field unset launched a container with no deadline at all. The
    /// backend now owns the arithmetic and always writes `Some(..)`, and the value
    /// has to cover the whole session: prompt + workload + slack, never one term.
    #[test]
    fn the_supervisor_session_always_carries_a_deadline() {
        let source = RecordingSource::default();
        let backend = MxcBackend::new(&source, Some(49_152), TEST_LAUNCHER);
        let mut i = input();
        i.timeout_ms = None; // the shape that used to ship an infinite session

        let req = backend.request_for(&i).expect("launchable request");
        let whole = PROMPT_BUDGET + WORKLOAD_BUDGET + SESSION_SLACK;
        let whole_ms = u32::try_from(whole.as_millis()).expect("budget fits u32 ms");
        assert_eq!(
            req.timeout_ms,
            Some(whole_ms),
            "an unbounded session must be impossible from the supervisor path"
        );
        // Not vacuous: the value is the SUM, so no single term can be mistaken for
        // the session's deadline (a 60 s prompt term would kill a working workload,
        // a 30 min workload term would kill an unanswered dialog's session).
        assert!(whole_ms > u32::try_from(PROMPT_BUDGET.as_millis()).unwrap());
        assert!(whole_ms > u32::try_from(WORKLOAD_BUDGET.as_millis()).unwrap());
        assert!(
            whole_ms > u32::try_from((PROMPT_BUDGET + WORKLOAD_BUDGET).as_millis()).unwrap(),
            "the slack must be strictly on top of both terms"
        );
    }

    /// The short-budget arithmetic of the same rule, and the reason the defaults are
    /// what they are: **a dialog may legitimately take 30 s**, so a session sized on
    /// a test-sized prompt term would kill a real workload. The deadline is the sum,
    /// which is strictly greater than prompt + workload.
    #[test]
    fn a_dialog_that_uses_its_whole_budget_does_not_kill_the_container() {
        // The short budget the test asks for: 300 ms of dialog, 200 ms of work,
        // 50 ms of slack.
        let budget = SessionBudget::new(
            Duration::from_millis(300),
            Duration::from_millis(200),
            Duration::from_millis(50),
        );
        assert_eq!(budget.session(), Duration::from_millis(550));
        assert_eq!(budget.timeout_ms(), 550);
        assert!(
            budget.session() > budget.prompt + budget.workload,
            "a session that spends BOTH terms in full must still be inside its deadline"
        );
        // A dialog that takes its whole 300 ms and a workload that then takes its
        // whole 200 ms = 500 ms, inside the 550 ms deadline: no kill.
        assert!(budget.session() >= Duration::from_millis(500));
        // Nothing was killed: when both terms were spent to the last millisecond the
        // session still had the slack left.
        assert!(budget.prompt + budget.workload < budget.session());
    }

    /// P2.1: the prompt time a session is judged on is its OWN — a listener that
    /// already served a launch must not hand its predecessor's spent dialog time to
    /// the next session, which would report a kill as `prompt_budget_exhausted` for a
    /// session that never prompted.
    #[test]
    fn the_session_prompt_time_is_the_delta_across_the_launch() {
        let before = Duration::from_secs(45);
        assert_eq!(
            prompt_wait_during(before, Duration::from_secs(50)),
            Duration::from_secs(5),
            "an earlier session's 45 s must not be attributed to this one"
        );
        assert_eq!(
            prompt_wait_during(before, before),
            Duration::ZERO,
            "a launch that never prompted has spent no prompt time"
        );
        assert_eq!(
            prompt_wait_during(Duration::from_secs(50), Duration::from_secs(45)),
            Duration::ZERO,
            "a clock that went backwards must credit zero, never an underflow"
        );
    }

    /// P2.1: a workload that exceeds its budget is killed and reported with a reason
    /// **distinct** from a spent prompt budget and from a session-handshake timeout.
    #[test]
    fn a_workload_overrun_is_reported_distinctly_from_a_prompt_or_handshake_timeout() {
        let budget = fixture_budget();

        // The workload ran the clock out with no prompt in the way.
        let workload = budget.classify(&SessionClock::measured(
            budget,
            Duration::from_secs(720),
            Duration::from_millis(200),
            Duration::ZERO,
        ));
        // Dialogs ate their 60 s term plus the slack, so the workload never got the
        // 600 s it was entitled to.
        let prompt = budget.classify(&SessionClock::measured(
            budget,
            Duration::from_secs(720),
            Duration::from_millis(200),
            Duration::from_secs(180),
        ));
        // The session ended long before either term could have been spent.
        let handshake = budget.classify(&SessionClock::measured(
            budget,
            Duration::from_secs(120),
            Duration::from_millis(200),
            Duration::ZERO,
        ));

        assert_eq!(workload, TimeoutReason::WorkloadBudgetExceeded);
        assert_eq!(prompt, TimeoutReason::PromptBudgetExhausted);
        assert_eq!(handshake, TimeoutReason::SessionHandshake);

        let mut reasons = vec![workload.as_str(), prompt.as_str(), handshake.as_str()];
        reasons.sort_unstable();
        reasons.dedup();
        assert_eq!(
            reasons.len(),
            3,
            "the three deadline causes must be three distinct reasons: {reasons:?}"
        );
        assert_eq!(workload.as_str(), "workload_budget_exceeded");
        assert_eq!(handshake.as_str(), "session_handshake_timeout");
        // The prompt cause shares its vocabulary with the proxy's deny reason for the
        // same term: a consumer reading either side names the budget, not the layer.
        assert_eq!(prompt.as_str(), crate::net::proxy::PROMPT_TIMEOUT_REASON);

        // And a session that is killed with time left on the workload term is not
        // reported as a workload overrun — the distinction is not vacuous.
        assert_ne!(workload, handshake);
    }

    /// The 60 s / 600 s / 60 s budget the attribution tests are written against: a
    /// deadline of 720 s, where "the workload was starved" and "the prompt term ate
    /// the slack" are the same statement.
    fn fixture_budget() -> SessionBudget {
        SessionBudget::new(
            Duration::from_secs(60),
            Duration::from_secs(600),
            Duration::from_secs(60),
        )
    }

    /// **Item 1b: the label requires deprivation.** A prompt label is a claim that
    /// the workload did not get the time it was entitled to — not that some dialog
    /// spent "more than its term". Two sessions with the SAME prompt aggregate are
    /// labelled differently depending on whether the workload was starved, which is
    /// the property that makes the prompt branch subordinate to the workload's.
    #[test]
    fn the_prompt_term_is_named_only_when_the_workload_was_starved() {
        let budget = fixture_budget();

        // One 720 s session, two prompt aggregates, and the label follows the
        // starvation rather than the aggregate's size relative to the term:
        // 100 s of prompt time leaves the workload 620 s of its 600 s term, so the
        // deadline it hit was its own.
        let had_its_time = SessionClock::measured(
            budget,
            Duration::from_secs(720),
            Duration::from_millis(200),
            Duration::from_secs(100),
        );
        assert_eq!(
            had_its_time.timeout_reason(),
            TimeoutReason::WorkloadBudgetExceeded,
            "the workload got its full 600 s: the prompt term is not to blame"
        );

        // 200 s of prompt time leaves it 520 s — 80 s short of its term — so the
        // session ended because of the dialogs, even though the prompt term is six
        // times what such a dialog is allowed to take (P2.1's point: the aggregate
        // is not a share, and the workload's deprivation is what decides).
        let starved = SessionClock::measured(
            budget,
            Duration::from_secs(720),
            Duration::from_millis(200),
            Duration::from_secs(200),
        );
        assert_eq!(
            starved.timeout_reason(),
            TimeoutReason::PromptBudgetExhausted,
            "520 s of workload time against a 600 s term: dialogs are why it ended"
        );
        assert_ne!(
            had_its_time.timeout_reason(),
            starved.timeout_reason(),
            "the two differ only in the prompt aggregate"
        );
    }

    /// **Item 1a + 1c: the aggregate is a sum over requests, so it is clamped and a
    /// saturated value is not evidence.** The measured over-count was 5.90x (six
    /// connections, one host) and 7.87x (eight hosts): `prompt_wait` said 4700 s in a
    /// 600 s session. That number must not become a prompt verdict.
    #[test]
    fn a_prompt_measurement_larger_than_the_session_is_clamped_and_blames_no_prompt() {
        let budget = fixture_budget();
        let raw = Duration::from_secs(4700); // 7.83x the session it happened in
        let clock = SessionClock::measured(
            budget,
            Duration::from_secs(720),
            Duration::from_millis(200),
            raw,
        );

        assert_eq!(
            clock.prompt_wait,
            Duration::from_secs(720),
            "the carried measurement is clamped to the session: a reader must not see \
             more prompt time than wall clock"
        );
        let reason = clock.timeout_reason();
        assert_ne!(
            reason,
            TimeoutReason::PromptBudgetExhausted,
            "a saturated aggregate is the fingerprint of the over-count, not a verdict"
        );
        assert_eq!(reason, TimeoutReason::WorkloadBudgetExceeded);

        // The clamp is not vacuous: a plausible aggregate on a session whose
        // workload was starved DOES produce a prompt verdict.
        let plausible = SessionBudget::new(
            Duration::from_secs(60),
            Duration::from_secs(300),
            Duration::from_secs(60),
        );
        assert_eq!(
            SessionClock::measured(
                plausible,
                Duration::from_secs(420),
                Duration::from_millis(200),
                Duration::from_secs(200)
            )
            .timeout_reason(),
            TimeoutReason::PromptBudgetExhausted
        );
    }

    /// **Item 2: the handshake is observable and decides first — when it deprived the
    /// workload.** A container that hangs at create/prove used to be recorded as the
    /// operator's workload overrunning, because `elapsed` was measured around the whole
    /// run and therefore always exceeded `prompt + workload`. With the handshake
    /// measured separately (launch start → container ready) a create that outlived the
    /// allowance `slack` exists to provide for it AND left less than the workload's
    /// term is the handshake's failure (round 2, item 6 tightened that second half;
    /// `the_handshake_term_is_named_only_when_it_starved_the_workload` is the pair).
    ///
    /// The clock is the session's own deadline: this fixture's budget is 60 + 600 + 60,
    /// so 720 s is the longest a session under it can run, and a clock claiming more
    /// would be a measurement bug rather than a case to classify.
    #[test]
    fn a_stalled_handshake_is_reported_as_a_handshake_timeout() {
        let budget = fixture_budget();
        let stalled = SessionClock::measured(
            budget,
            Duration::from_secs(720),
            Duration::from_secs(300), // > the 60 s slack, i.e. the create ate the session
            Duration::ZERO,
        );
        assert_eq!(
            stalled.timeout_reason(),
            TimeoutReason::SessionHandshake,
            "the container never became ready in time: the workload never got a chance"
        );
        assert_ne!(
            stalled.timeout_reason(),
            TimeoutReason::WorkloadBudgetExceeded,
            "a supervisor/container failure must not be recorded as the command's"
        );
        assert_eq!(
            stalled.timeout_reason().as_str(),
            "session_handshake_timeout"
        );

        // And the label is not vacuous: the same session with a handshake that
        // finished inside its allowance is the workload's overrun.
        let ready = SessionClock::measured(
            budget,
            Duration::from_secs(720),
            Duration::from_millis(180),
            Duration::ZERO,
        );
        assert_eq!(
            ready.timeout_reason(),
            TimeoutReason::WorkloadBudgetExceeded
        );
    }

    /// **Round 2, item 6: the handshake arm is DEPRIVATION-based, like the prompt
    /// one.** `handshake_elapsed > slack` alone misdirects the remedy when both are
    /// true: a 130 s create followed by a workload that then used its whole 600 s
    /// term is the operator's command overrunning, and calling it
    /// `session_handshake_timeout` sends the reader after a container that started
    /// perfectly well.
    #[test]
    fn the_handshake_term_is_named_only_when_it_starved_the_workload() {
        let budget = fixture_budget(); // prompt 60 + workload 600 + slack 60

        // Slow create (130 s, over the slack) AND the workload spent its whole term
        // on top of it: 730 - 130 = 600, i.e. nothing was taken from the command.
        let overran = SessionClock::measured(
            budget,
            Duration::from_secs(730),
            Duration::from_secs(130),
            Duration::ZERO,
        );
        assert_eq!(
            overran.timeout_reason(),
            TimeoutReason::WorkloadBudgetExceeded,
            "the command got its full 600 s after the create: the handshake ate nothing"
        );

        // Same slow create, but the workload never got its entitlement.
        let starved = SessionClock::measured(
            budget,
            Duration::from_secs(730),
            Duration::from_secs(300),
            Duration::ZERO,
        );
        assert_eq!(
            starved.timeout_reason(),
            TimeoutReason::SessionHandshake,
            "430 s of workload time against a 600 s term, and the create is why"
        );
        assert_ne!(overran.timeout_reason(), starved.timeout_reason());
    }

    /// **Round 2, item 7: teardown is measured, and a deadline that went on cleanup
    /// is a SUPERVISOR fault.** `elapsed` spans create + run + teardown, but only
    /// create was measured, so a teardown that ate the deadline was reported as the
    /// operator's command overrunning - the one label the operator cannot act on.
    #[test]
    fn a_deadline_spent_on_teardown_is_its_own_supervisor_side_reason() {
        let budget = fixture_budget();

        // 1 s create, the command ran 500 s and exited, then 190 s of teardown:
        // 691 s elapsed, of which 190 s is cleanup (over the 60 s slack) and the
        // command never approached its 600 s term.
        let cleanup = SessionClock::measured(
            budget,
            Duration::from_secs(691),
            Duration::from_secs(1),
            Duration::ZERO,
        )
        .with_teardown(Duration::from_secs(190));
        assert_eq!(cleanup.teardown_elapsed, Duration::from_secs(190));
        assert_eq!(
            cleanup.timeout_reason(),
            TimeoutReason::SessionTeardown,
            "the command finished at 501 s: cleanup is what ran the clock out"
        );
        assert_eq!(
            cleanup.timeout_reason().as_str(),
            "session_teardown_timeout"
        );

        // The same 691 s with an ordinary teardown IS the command's overrun: the
        // label follows the measurement, not the total.
        let ordinary = SessionClock::measured(
            budget,
            Duration::from_secs(691),
            Duration::from_secs(1),
            Duration::ZERO,
        )
        .with_teardown(Duration::from_secs(2));
        assert_ne!(
            ordinary.timeout_reason(),
            TimeoutReason::SessionTeardown,
            "a 2 s teardown is not why a 691 s session ended"
        );

        // And the four arms stay four distinct labels.
        let mut arms: Vec<&str> = [
            TimeoutReason::WorkloadBudgetExceeded,
            TimeoutReason::PromptBudgetExhausted,
            TimeoutReason::SessionHandshake,
            TimeoutReason::SessionTeardown,
        ]
        .iter()
        .map(|reason| reason.as_str())
        .collect();
        arms.sort_unstable();
        arms.dedup();
        assert_eq!(
            arms.len(),
            4,
            "each deadline cause keeps its own reason: {arms:?}"
        );
    }

    /// **Item 2: the measurements ride on the outcome**, so the label can be checked
    /// against its own inputs — and both cases above are reachable through the real
    /// mapping (`gate_outcome`), not only through `classify`.
    #[test]
    fn a_killed_session_carries_the_measurements_its_label_came_from() {
        let budget = fixture_budget();
        let stalled = SessionClock::measured(
            budget,
            Duration::from_secs(720),
            Duration::from_secs(300),
            Duration::from_secs(10),
        );
        let outcome = gate_outcome(
            tier(),
            child(WaitResult::TimedOut),
            proven(),
            ProofExpectation::Required,
            stalled,
        )
        .expect("a timed-out launch still has to pass guardrail 1");
        assert_eq!(outcome.timeout, Some(TimeoutReason::SessionHandshake));
        assert_eq!(outcome.clock.elapsed, Duration::from_secs(720));
        assert_eq!(outcome.clock.handshake_elapsed, Duration::from_secs(300));
        assert_eq!(outcome.clock.prompt_wait, Duration::from_secs(10));
        assert_eq!(
            outcome.clock.timeout_reason(),
            outcome.timeout.unwrap(),
            "the carried label must be exactly what the carried measurements produce"
        );

        // The long-workload half: same shape, a handshake that finished promptly.
        let ready = SessionClock::measured(
            budget,
            Duration::from_secs(720),
            Duration::from_millis(180),
            Duration::from_secs(5),
        );
        let outcome = gate_outcome(
            tier(),
            child(WaitResult::TimedOut),
            proven(),
            ProofExpectation::Required,
            ready,
        )
        .expect("proven launch");
        assert_eq!(outcome.timeout, Some(TimeoutReason::WorkloadBudgetExceeded));
        assert_eq!(outcome.clock.handshake_elapsed, Duration::from_millis(180));
        assert_eq!(outcome.clock.prompt_wait, Duration::from_secs(5));
        assert_eq!(outcome.clock.elapsed, Duration::from_secs(720));
    }

    /// **Item 6: the defaults agree by construction.** The production budget is
    /// `from_config` of the same constants the resolver applies as defaults, so a
    /// wiring mistake cannot silently reserve the DEFAULT prompt term while the
    /// dialog gets a resolved one.
    #[test]
    fn the_default_budget_is_the_config_defaults_through_from_config() {
        assert_eq!(
            PROMPT_BUDGET,
            Duration::from_secs(u64::from(crate::net::prompt::DEFAULT_PROMPT_TIMEOUT_SECS)),
            "the prompt term must be the profile default, in seconds"
        );
        assert_eq!(
            WORKLOAD_BUDGET,
            Duration::from_secs(u64::from(crate::net::DEFAULT_WORKLOAD_TIMEOUT_SECS)),
            "the workload term must be the profile default, in seconds"
        );
        assert_eq!(
            SessionBudget::default(),
            SessionBudget::from_config(
                crate::net::prompt::DEFAULT_PROMPT_TIMEOUT_SECS,
                crate::net::DEFAULT_WORKLOAD_TIMEOUT_SECS,
                SESSION_SLACK
            ),
            "Default and the resolved-config constructor must be the same budget"
        );
        // The terms a default profile resolves to, spelled out: 60 s + 30 min + 2 min.
        assert_eq!(
            SessionBudget::default().session(),
            Duration::from_secs(60 + 1800 + 120)
        );
        assert_eq!(SessionBudget::default().timeout_ms(), 1_980_000);
        // A raised profile is bigger in both terms, and still a finite u32 deadline.
        let raised = SessionBudget::from_config(300, 5400, SESSION_SLACK);
        assert_eq!(raised.prompt, Duration::from_secs(300));
        assert_eq!(raised.workload, Duration::from_secs(5400));
        assert_eq!(raised.session(), Duration::from_secs(300 + 5400 + 120));
        assert_eq!(raised.timeout_ms(), 5_820_000);
        assert!(raised.session() > SessionBudget::default().session());
        assert!(
            raised.timeout_ms() > 0,
            "a raised budget must still be expressible as timeout_ms"
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
    ///
    /// Each origin answers with **its own** nonce, so "the body came from its own
    /// origin" is a testable claim: two origins answering with one shared string
    /// make a crossed body indistinguishable from a correct one (P1.6(f)).
    struct Origin {
        host: String,
        port: u16,
        nonce: String,
        seen: Arc<Mutex<Vec<String>>>,
        heads: Arc<Mutex<Vec<String>>>,
        stop: Arc<AtomicBool>,
        join: Option<std::thread::JoinHandle<()>>,
    }

    impl Origin {
        fn start() -> Self {
            Self::start_with_nonce(NONCE)
        }

        fn start_with_nonce(nonce: &str) -> Self {
            let nonce = nonce.to_string();
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
            let nonce_thread = nonce.clone();
            let join = std::thread::spawn(move || {
                for accepted in listener.incoming() {
                    if stop_thread.load(Ordering::SeqCst) {
                        break;
                    }
                    let Ok(stream) = accepted else { continue };
                    let seen = Arc::clone(&seen_thread);
                    let heads = Arc::clone(&heads_thread);
                    let nonce = nonce_thread.clone();
                    std::thread::spawn(move || serve_origin(stream, &seen, &heads, &nonce));
                }
            });
            Self {
                host: ip.to_string(),
                port,
                nonce,
                seen,
                heads,
                stop,
                join: Some(join),
            }
        }

        /// The body this origin answers with (P1.6(f)).
        fn nonce(&self) -> &str {
            &self.nonce
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
    fn serve_origin(
        mut stream: TcpStream,
        seen: &Mutex<Vec<String>>,
        heads: &Mutex<Vec<String>>,
        nonce: &str,
    ) {
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
        let body = nonce;
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
        /// A listener with a credential of its own.
        ///
        /// Minted, not a constant: `spawn` refuses a token that is already live
        /// (P1.6(b)) and the live tests share one process, so a fixed value would
        /// make them refuse each other as soon as two run in parallel.
        fn start(allow: &[&str]) -> Self {
            Self::start_with_token(allow, RunToken::issue().expect("mint a live token"))
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
            .with_budget(SessionBudget::new(
                Duration::from_secs(30),
                Duration::from_secs(80),
                Duration::from_secs(10),
            ));

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
            Some(proxy.token().value()),
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
            Some(proxy.token().value()),
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

    /// Did `port` stop accepting connections within `within`?
    ///
    /// Polled because dropping a [`crate::net::proxy::ProxyHandle`] cancels the
    /// accept loop and then shuts its runtime down in the background
    /// (`shutdown_background`, AC-3.14 promises the port inside ~1s). P1.6(f):
    /// "closed" has to be *observed*; asserting it by not asserting anything after
    /// `drop` is an inference about `Drop`, not evidence.
    fn port_is_closed(port: u16, within: Duration) -> bool {
        let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
        let deadline = std::time::Instant::now() + within;
        loop {
            match TcpStream::connect_timeout(&addr, Duration::from_millis(200)) {
                // Refused (or unroutable): nothing is listening any more.
                Err(_) => return true,
                Ok(_) => {
                    if std::time::Instant::now() >= deadline {
                        return false;
                    }
                    std::thread::sleep(Duration::from_millis(25));
                }
            }
        }
    }

    /// CONNECT leaves in a session's audit chain.
    fn connect_leaves(sid: &str) -> usize {
        std::fs::read_to_string(crate::audit::audit_log_path(sid))
            .unwrap_or_default()
            .lines()
            .filter(|line| line.contains("\"op\":\"CONNECT\""))
            .count()
    }

    /// One attempt of the concurrency test: when each launch was in flight, and
    /// what it returned.
    ///
    /// Extracted from the test body so the retry rule is testable without
    /// launching a container - and the retry rule is the part that was wrong: the
    /// loop used to discard ANY non-overlapping attempt, including one whose
    /// launch had failed, so a real failure could be retried into invisibility.
    struct ConcurrencyAttempt {
        a: (Duration, Duration),
        b: (Duration, Duration),
        out_a: Result<SessionOutcome, MxcError>,
        out_b: Result<SessionOutcome, MxcError>,
    }

    impl ConcurrencyAttempt {
        /// Both launch calls were executing at some common instant.
        fn overlaps(&self) -> bool {
            self.a.0 < self.b.1 && self.b.0 < self.a.1
        }

        /// How long the two windows were in flight together.
        fn overlap(&self) -> Duration {
            self.a
                .1
                .min(self.b.1)
                .checked_sub(self.a.0.max(self.b.0))
                .unwrap_or_default()
        }

        /// May this attempt be thrown away and tried again?
        ///
        /// Only when it is BOTH serialized (so it measured nothing about
        /// concurrency) AND clean on both sides. A serialized attempt whose launch
        /// failed is the finding, not noise: retrying it would replace a real
        /// failure with a later, luckier run - a test that passes over the defect
        /// it exists to catch. An overlapping attempt is never discarded either,
        /// because it *is* the measurement.
        fn discardable(&self) -> bool {
            !self.overlaps() && self.out_a.is_ok() && self.out_b.is_ok()
        }

        /// One line of evidence for this attempt, outcome included.
        ///
        /// Printed for every attempt, not only the chosen one, so a failure
        /// cannot hide behind a retry. Deliberately narrow: exit code, proof and
        /// the error - never the child's stderr (it can quote a URL) and never a
        /// credential.
        fn evidence(&self) -> String {
            format!(
                "run_a=[{}ms..{}ms] run_b=[{}ms..{}ms] overlap={}ms out_a={} out_b={}",
                self.a.0.as_millis(),
                self.a.1.as_millis(),
                self.b.0.as_millis(),
                self.b.1.as_millis(),
                self.overlap().as_millis(),
                describe_launch(&self.out_a),
                describe_launch(&self.out_b),
            )
        }
    }

    /// How one launch outcome reads in evidence.
    fn describe_launch(out: &Result<SessionOutcome, MxcError>) -> String {
        match out {
            Ok(o) => format!(
                "ok exit={:?} proof={:?} success={}",
                o.exit_code,
                o.proxy_proof,
                o.success()
            ),
            Err(e) => format!("ERR {e}"),
        }
    }

    /// The attempt the concurrency test settles on, if it may stop now.
    ///
    /// Stops on the latest attempt when it may not be discarded (an overlap to
    /// measure, or a failure to report) or when the attempt budget is spent.
    fn chosen_attempt(attempts: &[ConcurrencyAttempt], max: usize) -> Option<usize> {
        let last = attempts.len().checked_sub(1)?;
        (!attempts[last].discardable() || attempts.len() >= max).then_some(last)
    }

    /// P1.6 (blocking 3): a serialized attempt whose launch FAILED is reported,
    /// never retried.
    ///
    /// The live test retries a serialized pair because a scheduler can deschedule
    /// one thread for the whole of the other's launch. The first version retried
    /// on `!overlaps()` alone, so an attempt that serialized *and* failed was
    /// discarded - the failure replaced by a later run's luck, which is exactly
    /// how a test passes over the defect it was written to catch.
    #[test]
    fn a_serial_attempt_with_a_failed_launch_is_reported_not_retried() {
        let failed = ConcurrencyAttempt {
            a: (Duration::from_millis(0), Duration::from_millis(400)),
            b: (Duration::from_millis(500), Duration::from_millis(900)),
            out_a: Err(MxcError::Concurrency(EpochAlreadyOpen { active: 1 })),
            out_b: Ok(passing_outcome()),
        };
        assert!(
            !failed.overlaps(),
            "the fixture must be the serialized case"
        );
        assert!(
            !failed.discardable(),
            "a serialized attempt with a failed launch is the finding, not noise"
        );
        // The loop appends one attempt at a time: the failed one settles it at
        // once, even though a retry would still have budget left.
        let attempts = [failed, clean_serial(), clean_serial()];
        assert_eq!(
            chosen_attempt(&attempts[..1], 3),
            Some(0),
            "the loop must settle on the failed attempt immediately, not retry it"
        );
        assert_eq!(
            attempts.len(),
            3,
            "a failed attempt settles the loop, so the other two are never launched"
        );
        // The failure is visible in the per-attempt evidence, not only in the
        // panic at the end.
        let evidence = attempts[0].evidence();
        assert!(
            evidence.contains("out_a=ERR") && evidence.contains("overlap="),
            "every attempt must print its outcome: {evidence}"
        );

        // The scheduler case the retry exists for is unchanged: a clean serialized
        // attempt is discarded and retried...
        let clean = clean_serial();
        assert!(clean.discardable());
        assert_eq!(
            chosen_attempt(&[clean], 3),
            None,
            "one clean attempt: retry"
        );
        // The attempt budget is what bounds the retrying: at the limit, a clean
        // serialized attempt is settled on so the test can report the finding.
        assert_eq!(chosen_attempt(&[clean_serial()], 1), Some(0));
        // ... and an overlapping attempt is the measurement, so it is chosen even
        // when it is also a failure (the outcome is asserted separately).
        let overlapping = ConcurrencyAttempt {
            a: (Duration::from_millis(0), Duration::from_millis(400)),
            b: (Duration::from_millis(100), Duration::from_millis(500)),
            out_a: Err(MxcError::Concurrency(EpochAlreadyOpen { active: 1 })),
            out_b: Ok(passing_outcome()),
        };
        assert!(overlapping.overlaps());
        assert!(!overlapping.discardable());
        assert_eq!(chosen_attempt(&[overlapping], 3), Some(0));
    }

    /// A serialized attempt whose launches both came back clean.
    fn clean_serial() -> ConcurrencyAttempt {
        ConcurrencyAttempt {
            a: (Duration::from_millis(0), Duration::from_millis(400)),
            b: (Duration::from_millis(500), Duration::from_millis(900)),
            out_a: Ok(passing_outcome()),
            out_b: Ok(passing_outcome()),
        }
    }

    /// An outcome that passes guardrail 1 on the `Required` leg.
    fn passing_outcome() -> SessionOutcome {
        SessionOutcome {
            exit_code: Some(0),
            timeout: None,
            stdout: Vec::new(),
            stderr: Vec::new(),
            warnings: Vec::new(),
            tier: TierRecord {
                tier: Some("base-container".to_string()),
                tier_source: TIER_SOURCE_PROBE,
                needs_dacl_augmentation: Some(false),
            },
            proxy_proof: ProxyProof {
                accepted: 1,
                tunnels: 1,
            },
            expectation: ProofExpectation::Required,
            clock: SessionClock::default(),
        }
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
        // Each origin answers with a body only it can produce (P1.6(f)): a shared
        // nonce would let a crossed body pass as a correct one.
        let origin_a = Origin::start_with_nonce("p14-origin-run-a");
        let origin_b = Origin::start_with_nonce("p14-origin-run-b");
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

        // Genuinely concurrent, and **observed** to be (P1.6(f)): both threads
        // meet at a barrier before either launches, so neither launch can start
        // after the other *finished waiting*, and the measured windows then have to
        // overlap - which is printed as evidence, not asserted in prose.
        //
        // An attempt that comes out serialized is retried, and the retry is not
        // politeness: it happened once for real, with four live tests launching
        // containers at the same time, where one thread sat descheduled for the
        // whole 327 ms of the other's launch. That is a fact about the scheduler,
        // not about the proxy. If *no* attempt overlaps, the finding is real and
        // the test fails.
        //
        // Only an attempt that is BOTH serialized AND clean is discarded
        // ([`ConcurrencyAttempt::discardable`]): a launch that failed must fail
        // this test, never be retried into a luckier run.
        const CONCURRENCY_ATTEMPTS: usize = 3;
        let barrier = std::sync::Barrier::new(2);
        let mut attempts: Vec<ConcurrencyAttempt> = Vec::new();
        let chosen = loop {
            let launched_at = std::time::Instant::now();
            let run = std::thread::scope(|scope| {
                let barrier_a = &barrier;
                let barrier_b = &barrier;
                let handle_a = scope.spawn(|| {
                    barrier_a.wait();
                    let began = launched_at.elapsed();
                    let outcome = launch_session(
                        counters_a.as_ref(),
                        Some(a.port()),
                        Some(a.token().value()),
                        &launcher,
                        &input_a,
                    );
                    (began, launched_at.elapsed(), outcome)
                });
                let handle_b = scope.spawn(|| {
                    barrier_b.wait();
                    let began = launched_at.elapsed();
                    let outcome = launch_session(
                        counters_b.as_ref(),
                        Some(b.port()),
                        Some(b.token().value()),
                        &launcher,
                        &input_b,
                    );
                    (began, launched_at.elapsed(), outcome)
                });
                (
                    handle_a.join().expect("run A's launch thread"),
                    handle_b.join().expect("run B's launch thread"),
                )
            });
            attempts.push(ConcurrencyAttempt {
                a: (run.0.0, run.0.1),
                b: (run.1.0, run.1.1),
                out_a: run.0.2,
                out_b: run.1.2,
            });
            let last = attempts.len() - 1;
            // Every attempt, outcome included - not just the one that gets used.
            // A launch that failed once must be visible in the log even when a
            // later attempt succeeds.
            println!(
                "EVIDENCE concurrency attempt={}/{} {} (barrier of 2 released before either \
                 launch)",
                last + 1,
                CONCURRENCY_ATTEMPTS,
                attempts[last].evidence()
            );
            if let Some(settled) = chosen_attempt(&attempts, CONCURRENCY_ATTEMPTS) {
                break settled;
            }
        };
        let chosen = attempts.swap_remove(chosen);
        let overlapped = chosen.overlaps();
        let chosen_evidence = chosen.evidence();
        // Outcomes BEFORE the overlap verdict: when a launch failed, that error is
        // the finding, and it must be what the reader sees - not a note about the
        // scheduler that would bury it.
        let out_a = chosen
            .out_a
            .expect("run A's launch failed (a failed launch is never retried away)");
        let out_b = chosen
            .out_b
            .expect("run B's launch failed (a failed launch is never retried away)");
        assert!(
            overlapped,
            "no attempt put the two launches in flight at the same time, so this run proves \
             nothing about concurrent sessions: {}",
            attempts
                .iter()
                .map(ConcurrencyAttempt::evidence)
                .collect::<Vec<_>>()
                .join(" | ")
        );
        println!("EVIDENCE concurrency_chosen {chosen_evidence}");
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
        // The body each session printed must be the nonce of the origin that
        // session was allowed to reach - and not the other one's (P1.6(f)).
        println!(
            "EVIDENCE bodies run_a={:?} (own nonce {}) run_b={:?} (own nonce {})",
            stdout_of(&out_a).trim(),
            origin_a.nonce(),
            stdout_of(&out_b).trim(),
            origin_b.nonce()
        );
        assert!(
            stdout_of(&out_a).contains(origin_a.nonce()),
            "run A's body must be its own origin's nonce {}: {:?}",
            origin_a.nonce(),
            stdout_of(&out_a)
        );
        assert!(
            stdout_of(&out_b).contains(origin_b.nonce()),
            "run B's body must be its own origin's nonce {}: {:?}",
            origin_b.nonce(),
            stdout_of(&out_b)
        );
        assert!(
            !stdout_of(&out_a).contains(origin_b.nonce())
                && !stdout_of(&out_b).contains(origin_a.nonce()),
            "neither session may print the other's origin nonce: A={:?} B={:?}",
            stdout_of(&out_a),
            stdout_of(&out_b)
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
        let port_b = b.port();
        drop(b);
        // Observed, not inferred: B's listener must actually stop accepting, and
        // A's must still be serving (checked below) - the pair is what makes
        // "closing B left A alone" mean something (P1.6(f)).
        let closed = port_is_closed(port_b, Duration::from_secs(5));
        println!(
            "EVIDENCE after_closing_run_b port_b={port_b} refuses_connections={closed} \
             run_a_counters={:?} run_b_counters_frozen={:?}",
            counters_a.counters(epoch_a),
            frozen_b
        );
        assert!(
            closed,
            "run B's listener on port {port_b} must stop accepting connections once its handle is \
             dropped; a live socket would mean `drop` did not close its peer"
        );
        // ...and A is still *serving*, which the authenticated CONNECT below
        // asserts directly (an accept-and-407 would prove less, and would spend
        // A's `no_token` leaf budget doing it).
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
    /// P2.1, live: a session whose **workload term** is exceeded is killed by the
    /// container, and the outcome says so with the workload's own reason — not with
    /// `timed_out: true` and no more, and not with the prompt's reason.
    ///
    /// The budget is deliberately small (2 s prompt + 1 s workload + 1 s slack = 4 s
    /// session) and the workload sleeps for 8 s, so the kill happens at the session
    /// deadline with the workload term spent and no prompt time at all: that is the
    /// `workload_budget_exceeded` case by construction, and it also pins the fact
    /// that `timeout_ms` really reaches the SDK (a `None` — or a value that wrapped
    /// small — would either run to completion or die at once).
    #[test]
    #[ignore = "launches a real ProcessContainer; run: cargo test --features mxc-backend -- --ignored"]
    fn a_workload_that_overruns_its_term_is_killed_and_reported_as_such() {
        let launcher = launcher_under_test();
        let proxy = LiveProxy::start(&[]);
        let counters = proxy.counters();
        let scratch = Scratch::named("budget-kill");
        let dir = scratch.path().to_path_buf();
        let no_denies: Vec<String> = Vec::new();

        // `cmd /c timeout` needs a console; a native sleep is what the container
        // runs, and 8 s is comfortably past the 4 s session deadline.
        let command =
            format!(r#"{POWERSHELL} -NoProfile -NonInteractive -Command "Start-Sleep -Seconds 8""#);
        let input = session_input(
            &dir,
            &launcher,
            &no_denies,
            command.clone(),
            Some(proxy.port()),
        );
        // prompt 1 s + workload 1 s + slack 2 s: the deadline still lands at 4 s
        // (so an 8 s workload is killed), while the slack leaves the container's own
        // create/prove two seconds — the allowance it exists to provide (P2.1 review,
        // item 2). With a 1 s slack a slow Defender scan of the launcher could push
        // the handshake past its allowance and correctly re-label this kill.
        let budget = SessionBudget::new(
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(2),
        );
        println!(
            "EVIDENCE budget_kill command={:?} budget={:?} session_ms={}",
            command,
            budget,
            budget.timeout_ms()
        );

        let started = std::time::Instant::now();
        let backend = MxcBackend::new(counters.as_ref(), Some(proxy.port()), &launcher)
            .with_proxy_token(proxy.token().value())
            .with_budget(budget);
        let outcome = backend
            .launch(&input, ProofExpectation::MustBeAbsent)
            .expect("a workload with no network use must leave the proxy unconsulted");
        let elapsed = started.elapsed();
        println!(
            "EVIDENCE budget_kill exit={:?} timeout={:?} success={} elapsed={:?} proof={:?}",
            outcome.exit_code,
            outcome.timeout,
            outcome.success(),
            elapsed,
            outcome.proxy_proof
        );

        // Item 2's live half: the measurements the label came from are on the
        // outcome, and the handshake really did finish inside its allowance — the
        // workload, not a stalled container, is what ran out of time.
        println!("EVIDENCE budget_kill clock={:?}", outcome.clock);
        assert!(
            outcome.clock.handshake_elapsed < budget.slack,
            "the container must be ready inside the slack that exists for it: {:?}",
            outcome.clock
        );
        assert!(
            outcome.clock.handshake_elapsed < elapsed,
            "the handshake is a part of the session, not the whole of it: {:?}",
            outcome.clock
        );
        assert_eq!(
            outcome.clock.prompt_wait,
            Duration::ZERO,
            "a workload that never used the proxy spent no prompt time: {:?}",
            outcome.clock
        );
        assert!(
            outcome.clock.elapsed >= budget.session(),
            "the kill landed at the deadline: {:?}",
            outcome.clock
        );
        // Item 7's live half: the teardown is MEASURED (a real container was reclaimed
        // after the kill), and it is a part of the session rather than the whole of it
        // — so the supervisor-side term now has a number instead of being folded into
        // `elapsed`.
        println!(
            "EVIDENCE budget_kill phases handshake={:?} run+teardown={:?} teardown={:?}",
            outcome.clock.handshake_elapsed,
            outcome
                .clock
                .elapsed
                .saturating_sub(outcome.clock.handshake_elapsed),
            outcome.clock.teardown_elapsed
        );
        assert!(
            outcome.clock.teardown_elapsed > Duration::ZERO,
            "reclaiming the container must be measured, not assumed zero: {:?}",
            outcome.clock
        );
        assert!(
            outcome.clock.teardown_elapsed <= budget.slack,
            "an ordinary teardown fits inside the slack that exists for it — a larger one \
             would (correctly) make this kill a `SessionTeardown`: {:?}",
            outcome.clock
        );
        assert!(
            outcome.clock.handshake_elapsed + outcome.clock.teardown_elapsed
                < outcome.clock.elapsed,
            "the two supervisor phases are parts of the session, not the whole of it: {:?}",
            outcome.clock
        );

        assert!(
            outcome.timed_out(),
            "the container must kill a workload that overruns its term: {outcome:?}"
        );
        assert_eq!(
            outcome.exit_code, None,
            "a killed session has no exit code: {outcome:?}"
        );
        // The distinct reason: the workload term, not the prompt's and not the
        // handshake's.
        assert_eq!(
            outcome.timeout,
            Some(TimeoutReason::WorkloadBudgetExceeded),
            "a kill with the workload term spent must be reported as a workload overrun, \
             not as a prompt or handshake timeout"
        );
        assert!(
            elapsed >= Duration::from_secs(3),
            "the kill can only happen at the session deadline (4 s), not at once: {elapsed:?}"
        );
        assert!(
            elapsed < Duration::from_secs(20),
            "the kill must be the deadline, not the workload's own 8 s run: {elapsed:?}"
        );
        assert!(!outcome.success(), "a killed session is never a success");
    }

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
            .with_budget(SessionBudget::new(
                Duration::from_secs(30),
                Duration::from_secs(80),
                Duration::from_secs(10),
            ));
        let outcome = backend
            .launch(&input, ProofExpectation::MustBeAbsent)
            .expect("a workload with no network use must leave the proxy unconsulted");
        let out = stdout_of(&outcome);
        println!(
            "EVIDENCE managed_workload exit={:?} timed_out={} success={} proof={:?} tier={:?}",
            outcome.exit_code,
            outcome.timed_out(),
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
