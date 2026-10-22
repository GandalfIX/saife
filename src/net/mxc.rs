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
//! * P1.3's filesystem policy is [`filesystem_policy`]: the workspace is the only
//!   writable grant, the launcher's directory is added automatically
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

/// The container command: the wrapper launcher, the port it must publish, and the
/// real workload command line as its single argument.
///
/// The workload's command line travels as **one** argument and the wrapper hands
/// it to `CreateProcessW` verbatim, so it keeps exactly the meaning it would
/// have had as the container command itself.
///
/// `--proxy-port` (P2.4) is the supervisor's bound port, which the wrapper writes
/// to the child as `SANDBOX_PROXY_PORT` — the D-0.3 discovery variable the
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
/// D1 makes `mxc-launch.exe` the command the container actually runs, and the
/// release build puts every bin in the same directory, so "beside this exe" is
/// where it is. `None` when it is not there: the caller refuses by name
/// ([`crate::cli::MXC_LAUNCHER_MISSING`]) rather than launching a session whose
/// wrapper — and therefore whose `NO_PROXY` and D-0.3 discovery variable — would
/// be missing.
pub fn launcher_beside(supervisor_exe: &Path) -> Option<PathBuf> {
    let candidate = supervisor_exe.parent()?.join(LAUNCHER_EXE_NAME);
    candidate.is_file().then_some(candidate)
}

/// The writable grants [`filesystem_policy`] cannot honour (P3.0 decision 9).
///
/// [`filesystem_policy`] grants read-write **exactly the workspace** and takes only
/// *read-only* extras: the workspace-only posture is ADR-0004 P1.3's decision, not
/// an omission, and a launch that widened it would be a second filesystem policy
/// nobody reviewed. So any other writable path a resolved profile asks for — a
/// profile's `filesystem.allow`, or a `--allow <path>` without `:read` — has no
/// launch it could describe.
///
/// Returned rather than dropped. Dropping is what this function exists to prevent:
/// the workload would run with a narrower filesystem than the operator asked for,
/// and nothing in the transcript, the audit chain or the exit code would say so.
/// The caller refuses by name, naming the path and the read-only alternative
/// ([`crate::cli::mxc_writable_grant_unsupported`]).
///
/// Compared on [`path_key`]s, so the workspace matches however it is spelled (a
/// trailing separator, a case difference, a `.` segment). A workspace that cannot
/// be made absolute is reported as *no* offending grant here: [`filesystem_policy`]
/// names that condition itself, and refusing every grant because the comparison
/// failed would blame the wrong input.
pub fn writable_grants_outside_workspace(cwd: &Path, writable: &[PathBuf]) -> Vec<String> {
    let workspace = match absolute_path("workspace directory", cwd) {
        Ok(path) => path_key(&path.display().to_string()),
        Err(_) => return Vec::new(),
    };
    writable
        .iter()
        .filter(|grant| path_key(&grant.display().to_string()) != workspace)
        .map(|grant| grant.display().to_string())
        .collect()
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
pub fn probe_tier(request: &ContainerRequest) -> Result<TierRecord, MxcError> {
    let probe = v1::probe(Some(request))?;
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
             never ran",
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

    // Same `proxy_port` that became `networkProxy` above, so the workload's
    // discovery variable and the proxy URL cannot name different listeners.
    let mut request = ContainerRequest::new(launcher_command(
        &launcher,
        &input.command,
        input.network.proxy_port,
    ));
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
) -> Result<ContainerRequest, MxcError> {
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
    // (`NetworkConfig::session_budget`, which resolves `promptTimeoutSecs` and
    // `workloadTimeoutSecs` from the profile). Leaving it at
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

    /// A launch whose wrapper probed and whose workload then did real work.
    fn proven() -> ProxyProof {
        ProxyProof {
            accepted: 1,
            tunnels: 1,
            probes: 1,
            unauthenticated: 0,
        }
    }

    fn untouched() -> ProxyProof {
        ProxyProof {
            accepted: 0,
            tunnels: 0,
            probes: 0,
            unauthenticated: 0,
        }
    }

    // ---- D1: launcher command construction -------------------------------

    #[test]
    fn launcher_command_puts_the_real_command_line_behind_the_wrapper() {
        let command = launcher_command(Path::new(TEST_LAUNCHER), "cmd /c echo hi", None);
        assert_eq!(
            command,
            format!(r#"{TEST_LAUNCHER} -- "cmd /c echo hi""#),
            "the real command line must travel as ONE quoted argument"
        );
    }

    /// P2.4: the discovery port rides the command line, before the `--`, so it is
    /// never part of the workload's single command-line argument.
    ///
    /// A proxy-less session omits the flag entirely (the wrapper then writes the
    /// variable empty rather than leaving an inherited value in place), which is
    /// the only shape that differs — the workload argument is unchanged.
    #[test]
    fn launcher_command_publishes_the_proxy_port_only_when_there_is_one() {
        assert_eq!(
            launcher_command(Path::new(TEST_LAUNCHER), "cmd /c echo hi", Some(49_152)),
            format!(r#"{TEST_LAUNCHER} --proxy-port 49152 -- "cmd /c echo hi""#),
        );
        assert_eq!(
            launcher_command(Path::new(TEST_LAUNCHER), "cmd /c echo hi", None),
            format!(r#"{TEST_LAUNCHER} -- "cmd /c echo hi""#),
            "no flag means the wrapper writes SANDBOX_PROXY_PORT empty"
        );
        // The request's own command carries the port it will also put in
        // `networkProxy`: `input()` configures 54321 for both.
        let req = build(&input());
        assert!(
            req.command.contains("--proxy-port 54321"),
            "the port the proxy URL names must be the port the workload discovers: {}",
            req.command
        );
    }

    #[test]
    fn launcher_command_quotes_a_launcher_path_with_spaces() {
        let command = launcher_command(
            Path::new(r"C:\Program Files\sb\mxc-launch.exe"),
            "x.exe",
            None,
        );
        assert_eq!(command, r#""C:\Program Files\sb\mxc-launch.exe" -- x.exe"#);
    }

    #[test]
    fn launcher_command_survives_a_command_line_that_contains_quotes() {
        let real = r#"powershell.exe -Command "Start-Sleep -Seconds 1""#;
        let command = launcher_command(Path::new(TEST_LAUNCHER), real, None);
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
        let backend = MxcBackend::new(
            &source,
            Some(49_152),
            TEST_LAUNCHER,
            TierExpectation::Recorded,
        );
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
            launcher_command(Path::new(TEST_LAUNCHER), "cmd /c echo hi", Some(54_321))
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

    /// `Required` passes on the wrapper's probe ALONE.
    ///
    /// This is the S-77/S-86/S-91 shape (2026-10-22): a network-enabled session
    /// whose workload makes no request at all — an intent roundtrip, a
    /// `cmd /c echo`, a raw 407 probe. `accepted == 0` and `tunnels == 0` there
    /// are not a missing path, they are a workload that never opened a socket,
    /// and refusing it refused a user who did nothing wrong.
    #[test]
    fn required_passes_on_the_wrapper_probe_alone() {
        verify_proxy_proof(
            ProxyProof {
                accepted: 0,
                tunnels: 0,
                probes: 1,
                unauthenticated: 0,
            },
            ProofExpectation::Required,
        )
        .expect("a probe of the listener's own control plane IS the evidence");
        // Traffic is recorded detail, never the gate: it does not replace the
        // probe, and it does not have to be there.
        verify_proxy_proof(proven(), ProofExpectation::Required)
            .expect("probe + traffic is the same proof plus coverage");
    }

    /// `Required` fails when the probe never arrived — however much traffic the
    /// epoch saw.
    ///
    /// A tunnel is a workload event: it can only exist if the child made a
    /// request, so it cannot answer "is the path broken?" for a child that made
    /// none. The probe is issued by the wrapper before the payload, so its
    /// absence means the path itself is broken (listener dead, loopback blocked,
    /// credential refused).
    #[test]
    fn required_fails_when_the_probe_never_arrived() {
        assert_eq!(
            verify_proxy_proof(untouched(), ProofExpectation::Required).expect_err("probes=0"),
            GuardError::ProbeUnmet
        );
        assert_eq!(
            verify_proxy_proof(
                ProxyProof {
                    accepted: 5,
                    tunnels: 2,
                    probes: 0,
                    unauthenticated: 0,
                },
                ProofExpectation::Required
            )
            .expect_err("probes=0"),
            GuardError::ProbeUnmet,
            "recorded traffic must not stand in for the probe"
        );
        assert!(
            GuardError::ProbeUnmet
                .to_string()
                .contains("proxy_probe_unmet"),
            "the refusal must name its own reason: {}",
            GuardError::ProbeUnmet
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
                probes: 0,
                unauthenticated: 0,
            },
            ProxyProof {
                accepted: 1,
                tunnels: 1,
                probes: 0,
                unauthenticated: 0,
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
            // The S-77 shape: probed, and the workload made no request.
            (
                ProofExpectation::Required,
                ProxyProof {
                    accepted: 0,
                    tunnels: 0,
                    probes: 1,
                    unauthenticated: 0,
                },
                true,
            ),
            (
                ProofExpectation::Required,
                ProxyProof {
                    accepted: 1,
                    tunnels: 1,
                    probes: 0,
                    unauthenticated: 0,
                },
                false,
            ),
            (ProofExpectation::MustBeAbsent, untouched(), true),
            (
                ProofExpectation::MustBeAbsent,
                ProxyProof {
                    accepted: 0,
                    tunnels: 1,
                    probes: 0,
                    unauthenticated: 0,
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
    /// warnings, yet the probe never arrived. Success must be impossible —
    /// and so is `accepted` traffic standing in for the probe.
    #[test]
    fn exited_zero_without_a_probe_is_an_error() {
        let err = gate_outcome(
            tier(),
            child(WaitResult::Exited(0)),
            ProxyProof {
                accepted: 1,
                tunnels: 1,
                probes: 0,
                unauthenticated: 0,
            },
            ProofExpectation::Required,
            clock(),
        )
        .expect_err("exit 0 must not mask a failed proof");
        assert!(matches!(
            err,
            MxcError::Unproven(ref refused) if refused.error == GuardError::ProbeUnmet
        ));
        // P3.0: the refusal still carries what the child did, so a refused session
        // is not a silent one.
        let MxcError::Unproven(refused) = err else {
            unreachable!("matched above")
        };
        assert_eq!(refused.outcome.exit_code, Some(0));
        assert!(
            !refused.outcome.success(),
            "an unproven outcome is not a success"
        );
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
                    probes: 0,
                    unauthenticated: 0,
                },
            ),
            (
                ProofExpectation::MustBeAbsent,
                ProxyProof {
                    accepted: 1,
                    tunnels: 0,
                    probes: 0,
                    unauthenticated: 0,
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
            MxcError::Unproven(ref refused) if refused.error == GuardError::ProbeUnmet
        ));
        // The timeout label survives the refusal: a killed child is still labelled.
        let MxcError::Unproven(refused) = err else {
            unreachable!("matched above")
        };
        assert!(
            refused.outcome.timed_out(),
            "the carried outcome keeps its label"
        );
    }

    #[test]
    fn launch_without_a_proof_source_is_an_error_before_the_child_starts() {
        let err = MxcBackend::without_proof_source(
            Some(54_321),
            TEST_LAUNCHER,
            TierExpectation::Recorded,
        )
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
            Err::<(), _>(MxcError::Guard(GuardError::ProbeUnmet))
        })
        .expect_err("body failed");
        assert!(matches!(err, MxcError::Guard(GuardError::ProbeUnmet)));
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
        let _ = MxcBackend::without_proof_source(
            Some(54_321),
            TEST_LAUNCHER,
            TierExpectation::Recorded,
        )
        .launch(&input(), ProofExpectation::Required);

        // Unsatisfiable expectation: `Required` with no proxy port.
        let source = RecordingSource::default();
        let err = MxcBackend::new(&source, None, TEST_LAUNCHER, TierExpectation::Recorded)
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
        let backend = MxcBackend::new(
            &source,
            Some(49_152),
            TEST_LAUNCHER,
            TierExpectation::Recorded,
        )
        .with_budget(budget);
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
        let backend = MxcBackend::new(
            &source,
            Some(49_152),
            TEST_LAUNCHER,
            TierExpectation::Recorded,
        );
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
        let backend = MxcBackend::new(&source, Some(1), TEST_LAUNCHER, TierExpectation::Recorded);
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

    // ---- P2.3: guardrail 2's hard half (tier requirement) -----------------

    #[test]
    fn a_dispatched_tier_that_matches_the_requirement_passes_the_gate() {
        let record = tier_record(ProbeView {
            tier: Some("base-container"),
            needs_dacl_augmentation: Some(false),
        });
        assert_eq!(
            verify_tier(&record, TierExpectation::Exactly(REQUIRED_TIER)),
            Ok(())
        );
        // `Recorded` never refuses: measurements have no requirement to make.
        assert_eq!(
            verify_tier(&record, TierExpectation::Recorded).map_err(|e| e.observed),
            Ok(())
        );
    }

    /// The ADR's product rule: a wrong tier is a REFUSED session. The refusal
    /// names both tiers and its source, because "refused" without "instead of
    /// what" is not actionable.
    #[test]
    fn a_degraded_tier_is_refused_and_the_refusal_names_both_tiers() {
        let record = tier_record(ProbeView {
            tier: Some("appcontainer-dacl"),
            needs_dacl_augmentation: Some(true),
        });
        let refusal = verify_tier(&record, TierExpectation::Exactly(REQUIRED_TIER))
            .expect_err("a degraded tier must be refused when base-container is required");
        assert_eq!(refusal.expected, "base-container");
        assert_eq!(refusal.observed.as_deref(), Some("appcontainer-dacl"));
        assert_eq!(refusal.source, "probe");
        let text = refusal.to_string();
        assert!(text.contains("guardrail 2"), "{text}");
        assert!(text.contains("`base-container`"), "{text}");
        assert!(text.contains("`appcontainer-dacl`"), "{text}");
        // The MxcError wrapper keeps the detail reachable.
        let err: MxcError = refusal.clone().into();
        assert!(matches!(err, MxcError::Tier(_)), "{err:?}");
    }

    /// A requirement that cannot be shown to be met is not met. A literal
    /// `observed != expected` check would let a silent probe through, which is the
    /// one case a degraded dispatch is most likely to produce.
    #[test]
    fn a_probe_that_names_no_tier_is_refused_by_a_requirement() {
        let record = tier_record(ProbeView {
            tier: None,
            needs_dacl_augmentation: None,
        });
        let refusal = verify_tier(&record, TierExpectation::Exactly(REQUIRED_TIER))
            .expect_err("an unnamed tier cannot satisfy a requirement");
        assert_eq!(refusal.observed, None);
        assert_eq!(refusal.source, "unavailable");
        assert!(refusal.to_string().contains("no tier"), "{refusal}");
    }

    /// The backend's requirement is what decides, not a global constant: a backend
    /// constructed with `Exactly(REQUIRED_TIER)` refuses, and `Recorded` is a
    /// **deliberate, named** opt-out for a measurement (P2.3 review, item 1).
    ///
    /// The opt-out is legitimate and narrow: a probe or a spike wants to record
    /// what dispatched. What was not legitimate is that `Recorded` was the
    /// *default* — see [`the_supervisor_seam_refuses_a_degraded_tier`].
    #[test]
    fn the_backends_declared_tier_expectation_is_what_the_gate_applies() {
        let source = RecordingSource::default();
        let degraded = tier_record(ProbeView {
            tier: Some("appcontainer-dacl"),
            needs_dacl_augmentation: Some(true),
        });

        let requiring = MxcBackend::new(
            &source,
            Some(49_152),
            TEST_LAUNCHER,
            TierExpectation::Exactly(REQUIRED_TIER),
        );
        assert_eq!(
            requiring.tier_expectation(),
            TierExpectation::Exactly(REQUIRED_TIER),
            "the constructor's argument is what the gate applies"
        );
        let refusal = requiring
            .tier_gate(&degraded)
            .expect_err("a base-container session must not accept a degraded dispatch");
        assert_eq!(refusal.observed.as_deref(), Some("appcontainer-dacl"));

        let recording = MxcBackend::new(
            &source,
            Some(49_152),
            TEST_LAUNCHER,
            TierExpectation::Recorded,
        );
        assert_eq!(
            recording.tier_expectation(),
            TierExpectation::Recorded,
            "the deliberate measurement opt-out, named at the call site"
        );
        assert_eq!(
            recording.tier_gate(&degraded),
            Ok(()),
            "a measurement states `Recorded` on purpose and is not refused"
        );
    }

    /// P3.0 decision 3: the seam the supervisor calls carries the **resolved**
    /// budget, not [`SessionBudget::default`].
    ///
    /// Red before the fix: a `launch_session` that built its backend without a
    /// budget shipped the config DEFAULTS, so a profile with a longer
    /// `promptTimeoutSecs`/`workloadTimeoutSecs` got a container deadline that
    /// under-reserved it — the very kill P2.1 exists to prevent, reported against
    /// the wrong term. The assertion is equality against a budget that differs
    /// from the default in every field, so "the default happened to match" cannot
    /// pass it.
    #[test]
    fn the_supervisor_seam_carries_the_resolved_budget() {
        let source = RecordingSource::default();
        let budget = SessionBudget::new(
            Duration::from_secs(7),
            Duration::from_secs(11),
            Duration::from_secs(3),
        );
        assert_ne!(
            budget,
            SessionBudget::default(),
            "the fixture must differ from the default or this test cannot fail"
        );
        let seam = supervisor_backend(
            &source,
            Some(49_152),
            Some("token"),
            Path::new(TEST_LAUNCHER),
            budget,
        );
        assert_eq!(seam.budget(), budget);
        let request = seam.request_for(&input()).expect("request");
        assert_eq!(
            request.timeout_ms,
            Some(budget.timeout_ms()),
            "the container's deadline is the resolved budget, never a default"
        );
    }

    /// P3.0 decision 3 (the other half): [`request_for_session`] describes the
    /// request the launch will dispatch, so the tier the leaf is armed with is the
    /// tier of the request that runs.
    ///
    /// A lookalike request would still *pass* guardrail 2 locally while the leaf
    /// named a tier the launched request never dispatched to — which is why the
    /// probe must come from this function and not from a hand-built request.
    #[test]
    fn request_for_session_is_the_request_the_launch_will_dispatch() {
        let source = RecordingSource::default();
        let budget = SessionBudget::new(
            Duration::from_secs(5),
            Duration::from_secs(9),
            Duration::from_secs(1),
        );
        let input = input();
        let request = request_for_session(
            &source,
            Some(49_001),
            Some("run-token"),
            Path::new(TEST_LAUNCHER),
            budget,
            &input,
        )
        .expect("the session's request");

        assert_eq!(request.timeout_ms, Some(budget.timeout_ms()));
        let network = format!("{:?}", request.network.expect("a network policy"));
        assert!(
            network.contains("49001"),
            "the request must name the port the proof counts: {network}"
        );
        assert!(
            network.contains("run-token"),
            "the request must carry the run's credential: {network}"
        );
        let seam = supervisor_backend(
            &source,
            Some(49_001),
            Some("run-token"),
            Path::new(TEST_LAUNCHER),
            budget,
        );
        assert_eq!(
            request.command,
            seam.request_for(&input).expect("the same request").command,
            "the same launcher command line, byte for byte"
        );
    }

    /// P3.0 decision 9: a writable grant the workspace-only posture cannot honour
    /// is NAMED, never dropped.
    ///
    /// Dropping it is the silent narrowing: the workload would run with a subset of
    /// the filesystem the operator asked for, and nothing would say so.
    #[test]
    fn a_writable_grant_outside_the_workspace_is_reported_not_dropped() {
        let cwd = Path::new(r"C:\work\repo");
        let writable = [
            PathBuf::from(r"C:\work\repo"),
            PathBuf::from(r"C:\data\datasets"),
        ];
        assert_eq!(
            writable_grants_outside_workspace(cwd, &writable),
            vec![r"C:\data\datasets".to_string()]
        );
        assert!(
            writable_grants_outside_workspace(cwd, &writable[..1]).is_empty(),
            "the workspace itself is the grant the posture allows"
        );
    }

    /// The workspace match has to survive the spellings a profile can produce:
    /// trailing separator, different case, a `.` segment.
    #[test]
    fn the_workspace_grant_is_recognised_however_it_is_spelled() {
        let cwd = Path::new(r"C:\work\repo");
        for spelling in [r"c:\WORK\repo\", r"C:\work\.\repo", r"C:\work\sub\..\repo"] {
            assert!(
                writable_grants_outside_workspace(cwd, &[PathBuf::from(spelling)]).is_empty(),
                "{spelling} names the workspace"
            );
        }
    }

    /// P3.0: the wrapper must be found *beside the supervisor*, and its absence
    /// must be observable rather than assumed — Docker-style PATH lookups are not
    /// something this binary does.
    #[test]
    fn launcher_beside_requires_the_wrapper_next_to_the_supervisor() {
        let dir = std::env::temp_dir().join(format!(
            "sb-p30-launcher-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let supervisor = dir.join("sandbox.exe");
        assert_eq!(launcher_beside(&supervisor), None, "nothing is written yet");
        let launcher = dir.join(LAUNCHER_EXE_NAME);
        std::fs::write(&launcher, b"stub").expect("stub launcher");
        assert_eq!(launcher_beside(&supervisor), Some(launcher));
        std::fs::remove_dir_all(&dir).ok();
    }

    /// P2.3 review (item 1) — **the finding itself**: the supervisor seam must not
    /// run un-gated.
    ///
    /// `launch_session` is what `main` will call, and it built its backend with the
    /// fail-open default while its doc comment claimed `Exactly(REQUIRED_TIER)`.
    /// This drives a degraded tier through *that* construction — the same function
    /// `launch_session` calls, not a lookalike — and requires the refusal.
    ///
    /// Red before the fix: `Ok(())` (the backend was built with `Recorded`), i.e.
    /// a degraded dispatch would have launched with the migration's whole UAC gain
    /// silently gone.
    #[test]
    fn the_supervisor_seam_refuses_a_degraded_tier() {
        let source = RecordingSource::default();
        let degraded = tier_record(ProbeView {
            tier: Some("appcontainer-dacl"),
            needs_dacl_augmentation: Some(true),
        });

        let seam = supervisor_backend(
            &source,
            Some(49_152),
            Some("token"),
            Path::new(TEST_LAUNCHER),
            SessionBudget::default(),
        );
        let refusal = seam.tier_gate(&degraded).expect_err(
            "the seam launch_session builds must require `base-container`, \
             not merely record what dispatched",
        );
        assert_eq!(refusal.expected, REQUIRED_TIER);
        assert_eq!(refusal.observed.as_deref(), Some("appcontainer-dacl"));
        assert_eq!(refusal.source, "probe");

        // A silent probe is refused too: a requirement that cannot be shown to be
        // met is not met, and that is the case a degraded dispatch produces.
        let silent = tier_record(ProbeView {
            tier: None,
            needs_dacl_augmentation: None,
        });
        assert!(
            seam.tier_gate(&silent).is_err(),
            "the seam must not accept a tier nobody could name"
        );

        // And the exact tier it requires still passes: the gate refuses the wrong
        // tier, not every tier.
        let required = tier_record(ProbeView {
            tier: Some(REQUIRED_TIER),
            needs_dacl_augmentation: Some(false),
        });
        assert_eq!(seam.tier_gate(&required), Ok(()));
    }

    /// P2.3 review (item 1), the compile-level half: **no constructor yields an
    /// un-gated backend.**
    ///
    /// Both constructors are coerced to `fn` pointers whose signatures include the
    /// [`TierExpectation`]. That pins the arity *and* the parameter type at compile
    /// time: an expression of `MxcBackend` that omits the expectation — the shape
    /// that produced the fail-open seam — cannot be written, because there is no
    /// constructor with that signature and the fields are private. This test does
    /// not build if one is ever added back.
    #[test]
    fn no_constructor_yields_an_un_gated_backend() {
        let _with_proof: fn(
            &'static dyn ProxyProofSource,
            Option<u16>,
            &'static str,
            TierExpectation,
        ) -> MxcBackend<'static> = MxcBackend::new;
        let _without_proof: fn(Option<u16>, &'static str, TierExpectation) -> MxcBackend<'static> =
            MxcBackend::without_proof_source;

        // …and the argument is not merely present but honoured by every
        // constructor: the gate applies whatever was passed.
        let degraded = tier_record(ProbeView {
            tier: Some("appcontainer-dacl"),
            needs_dacl_augmentation: Some(true),
        });
        assert!(
            MxcBackend::without_proof_source(Some(1), TEST_LAUNCHER, TierExpectation::Recorded)
                .tier_gate(&degraded)
                .is_ok()
        );
    }

    /// The audit adapter carries the record verbatim — including `None`, which
    /// must stay "unknown" rather than become `false` on the leaf.
    #[test]
    fn the_tier_record_maps_into_the_leaf_vocabulary_without_inventing_a_value() {
        let named = tier_record(ProbeView {
            tier: Some("base-container"),
            needs_dacl_augmentation: Some(false),
        });
        let facts = named.audit_facts();
        assert_eq!(facts.tier.as_deref(), Some("base-container"));
        assert_eq!(facts.tier_source, Some("probe"));
        assert_eq!(facts.needs_dacl_augmentation, Some(false));
        assert!(
            facts.tier.is_some() && facts.tier_source.is_some(),
            "the tier pair travels together"
        );

        let silent = tier_record(ProbeView {
            tier: None,
            needs_dacl_augmentation: None,
        });
        let facts = silent.audit_facts();
        assert_eq!(facts.tier, None);
        assert_eq!(facts.tier_source, Some("unavailable"));
        assert_eq!(facts.needs_dacl_augmentation, None);
        assert!(
            facts.tier.is_none() && facts.tier_source.is_some(),
            "a silent probe leaves the tier unknown but still names its source"
        );
    }

    // ---- P1 wave 2 B: the launcher grant is never the caller's job -------

    #[test]
    fn a_caller_that_omits_the_launcher_grant_still_gets_a_launchable_request() {
        let source = RecordingSource::default();
        let backend = MxcBackend::new(
            &source,
            Some(49_152),
            TEST_LAUNCHER,
            TierExpectation::Recorded,
        );
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
        let backend = MxcBackend::new(
            &source,
            Some(49_152),
            TEST_LAUNCHER,
            TierExpectation::Recorded,
        );
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
        let backend = MxcBackend::new(
            &source,
            Some(49_152),
            TEST_LAUNCHER,
            TierExpectation::Recorded,
        );
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
        let backend = MxcBackend::new(
            &source,
            Some(49_152),
            TEST_LAUNCHER,
            TierExpectation::Recorded,
        )
        .with_proxy_token("abc-123");
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
        let backend = MxcBackend::new(
            &source,
            Some(49_152),
            TEST_LAUNCHER,
            TierExpectation::Recorded,
        );
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
        counters.note_probe();
        counters.note_consultation();
        counters.note_upstream_established();
        assert_eq!(
            counters.proof(first),
            ProxyProof {
                accepted: 1,
                tunnels: 1,
                probes: 1,
                unauthenticated: 0,
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
        counters.note_probe();
        counters.note_consultation();
        counters.note_upstream_established();
        assert_eq!(
            counters.proof(second),
            ProxyProof {
                accepted: 1,
                tunnels: 1,
                probes: 1,
                unauthenticated: 0,
            },
            "a plain-HTTP-only session carries both the probe and its coverage"
        );
        // The closed epoch keeps its frozen numbers.
        assert_eq!(
            counters.proof(first),
            ProxyProof {
                accepted: 1,
                tunnels: 1,
                probes: 1,
                unauthenticated: 0,
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
        DialogFn, DialogRequest, DialogUnavailable, PromptConfig, PromptCoordinator, PromptPolicy,
        PromptResult,
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

        // The control-plane probe, mirrored from the real listener: it is the
        // launch's evidence since the 2026-10-22 amendment, and a fake that did
        // not record it would make a `Required` launch fail for a reason the
        // product never produces.
        if target == "/sandbox/probe" {
            bump(shared, epoch, |proof| proof.probes += 1);
            let _ = stream.write_all(b"HTTP/1.1 204 No Content\r\n\r\n");
            return;
        }

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

        /// A scratch directory whose name carries nothing `cmd.exe` parses
        /// specially.
        ///
        /// P2.2 hands a `.bat` path to `cmd /c "<path>"`, and cmd's `/c`
        /// quote-stripping heuristic gives up on `(` or `)` — which the
        /// `ThreadId(n)` names in [`Scratch::named`] contain. Observed: the child
        /// exited 1 with `Zugriff verweigert` and no stdout, i.e. cmd refused the
        /// command line rather than the script.
        fn plain(label: &str) -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let dir = std::env::temp_dir().join(format!(
                "sandbox-mxc-{label}-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).expect("create scratch dir");
            Self(dir)
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

    // ---- ADR-0004 guardrail 1 (amended 2026-10-22): attributable evidence ----

    /// One `GET /sandbox/probe` carrying a CHOSEN credential (or none).
    ///
    /// A container can only present its own run's token (it rides its proxy URL),
    /// so "somebody else's credential" needs a raw socket — which is exactly the
    /// adversary this pins: any local process, or a session holding a stale token.
    fn probe_with(port: u16, token: Option<&str>) -> String {
        let mut sock = TcpStream::connect(("127.0.0.1", port)).expect("connect the listener");
        sock.set_read_timeout(Some(Duration::from_secs(5)))
            .expect("read timeout");
        let auth = match token {
            Some(token) => {
                let creds =
                    base64::engine::general_purpose::STANDARD.encode(format!("sandbox:{token}"));
                format!("Proxy-Authorization: Basic {creds}\r\n")
            }
            None => String::new(),
        };
        let req = format!("GET /sandbox/probe HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n{auth}\r\n");
        sock.write_all(req.as_bytes()).expect("write the probe");
        let mut out = Vec::new();
        let mut chunk = [0u8; 256];
        while !out.windows(4).any(|w| w == b"\r\n\r\n") {
            match sock.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(n) => out.extend_from_slice(&chunk[..n]),
            }
        }
        String::from_utf8_lossy(&out).into_owned()
    }

    /// **The property the gate exists for.** A session whose ONLY listener contact
    /// used a foreign credential is REFUSED.
    ///
    /// The listener answers the same `407` it gives a credential-less request, so
    /// the launch's epoch has `probes == 0` and guardrail 1 refuses with
    /// `proxy_probe_unmet`. The positive control (this listener's own credential,
    /// `204` and counted) is what makes the refusal mean something: without it a
    /// dead listener would look identical.
    ///
    /// The control runs in its OWN epoch (P3.2a): the refused attempt stays counted
    /// on the first launch's `unauthenticated`, so re-probing the same epoch with
    /// the right credential would prove the listener serves it - which the `204`
    /// below does - while the session would still (correctly) be refused.
    ///
    /// Not `#[ignore]`d: no container is involved — this is the real listener,
    /// the real counters and the real gate.
    #[test]
    fn a_session_whose_only_listener_contact_used_a_foreign_credential_is_refused() {
        let proxy = LiveProxy::start(&[]);
        let counters = proxy.counters();
        let epoch = counters.begin_launch().expect("the launch's epoch");

        // 1. Somebody else's token: refused like a missing one, and uncounted.
        let foreign = probe_with(proxy.port(), Some("a-different-runs-token"));
        println!(
            "EVIDENCE foreign_probe status={:?} proof={:?}",
            foreign.lines().next(),
            counters.proof(epoch)
        );
        assert!(
            foreign.starts_with("HTTP/1.1 407"),
            "a foreign credential must be refused exactly like a missing one: {foreign:?}"
        );
        assert_eq!(
            counters.proof(epoch).probes,
            0,
            "a refused probe must leave no observation, or any local process could satisfy \
             guardrail 1 for a session whose own path is broken: {:?}",
            counters.proof(epoch)
        );
        assert_eq!(
            verify_proxy_proof(counters.proof(epoch), ProofExpectation::Required)
                .expect_err("a foreign-credential probe must not satisfy the gate"),
            GuardError::ProbeUnmet
        );

        counters.close_launch(epoch);

        // 2. Positive control, fresh epoch: this listener's own credential is served
        //    and counted, and a launch whose only contact is that probe passes - so
        //    the refusal above is about the credential, not a dead listener.
        let control = counters.begin_launch().expect("the control's epoch");
        let own = probe_with(proxy.port(), Some(proxy.token().value()));
        println!(
            "EVIDENCE own_probe status={:?} proof={:?}",
            own.lines().next(),
            counters.proof(control)
        );
        assert!(
            own.starts_with("HTTP/1.1 204"),
            "the session's own credential must be served: {own:?}"
        );
        assert_eq!(counters.proof(control).probes, 1, "exactly one observation");
        assert_eq!(
            counters.proof(control).unauthenticated,
            0,
            "nothing but the probe touched this epoch"
        );
        verify_proxy_proof(counters.proof(control), ProofExpectation::Required)
            .expect("a launch probed with its own credential is proven");

        counters.close_launch(control);
    }

    /// One `CONNECT` carrying **no** credential at all, blocking on the status line.
    ///
    /// The WinINet / system-proxy shape (P1.5, P1.8): the container forces the
    /// request to this listener and the client sends no `Proxy-Authorization`
    /// header, so it is answered `407` for ever and the application has no egress
    /// while the proxy path itself is perfectly healthy.
    fn connect_no_auth(port: u16, target: &str) -> String {
        let mut sock = TcpStream::connect(("127.0.0.1", port)).expect("connect the listener");
        sock.set_read_timeout(Some(Duration::from_secs(5)))
            .expect("read timeout");
        let req = format!("CONNECT {target} HTTP/1.1\r\n\r\n");
        sock.write_all(req.as_bytes()).expect("write CONNECT");
        let mut out = Vec::new();
        let mut chunk = [0u8; 512];
        // The status line ends at the first blank line; never read to EOF (a
        // tunnel would keep the socket open).
        while !out.windows(4).any(|w| w == b"\r\n\r\n") {
            match sock.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(n) => out.extend_from_slice(&chunk[..n]),
            }
        }
        String::from_utf8_lossy(&out).into_owned()
    }

    /// **P3.2a, the class the probe amendment re-opened.** A launch whose probe
    /// arrived, whose ONLY other contact with the listener carried no credential,
    /// is REFUSED with `workload_cannot_authenticate`.
    ///
    /// Before this leg the session PASSED on `probes == 1`: the wrapper's probe
    /// proved the path, and nothing asked whether the workload could use it. A GUI
    /// / system-proxy client (WinINet, Windows PowerShell 5.1 - measured in P1.5 and
    /// P1.8) reaches this listener, gets `407` for ever, and the application
    /// silently has no egress: exactly the silent-misconfiguration class guardrail
    /// 1 exists for, so the evidence has to be two-part.
    #[test]
    fn a_probe_ok_session_whose_only_other_contact_was_credential_less_is_refused() {
        let proxy = LiveProxy::start(&[]);
        let counters = proxy.counters();
        let epoch = counters.begin_launch().expect("the launch's epoch");

        // 1. The wrapper's pre-flight probe: the PATH is proven.
        let probe = probe_with(proxy.port(), Some(proxy.token().value()));
        assert!(
            probe.starts_with("HTTP/1.1 204"),
            "the probe must be served: {probe:?}"
        );

        // 2. The workload: a client stack that cannot send the credential.
        let attempt = connect_no_auth(proxy.port(), "api.example.com:443");
        assert!(
            attempt.starts_with("HTTP/1.1 407"),
            "a credential-less CONNECT is refused, and identically every time: {attempt:?}"
        );

        let proof = counters.proof(epoch);
        println!("EVIDENCE credential_less_system_proxy proof={proof:?}");
        assert_eq!(proof.probes, 1, "the probe is the path evidence: {proof:?}");
        assert_eq!(
            (proof.accepted, proof.tunnels),
            (0, 0),
            "a refused attempt is not a consultation: it never reached the policy: {proof:?}"
        );
        assert_eq!(
            proof.unauthenticated, 1,
            "the attempt must be counted on this launch's epoch: {proof:?}"
        );

        let err = verify_proxy_proof(proof, ProofExpectation::Required)
            .expect_err("a session whose only listener contact was credential-less had no egress");
        println!("EVIDENCE refusal reason={err}");
        assert_eq!(err, GuardError::WorkloadCannotAuthenticate);
        assert!(
            err.to_string().contains("workload_cannot_authenticate"),
            "the operator must be told which cause it was: {err}"
        );
        assert!(
            !err.to_string().contains("proxy_probe_unmet"),
            "this is NOT a path failure - the probe arrived: {err}"
        );

        // 3. Positive control, fresh epoch on the SAME listener: probe and nothing
        //    else still passes, so the refusal above is the credential-less
        //    attempt and not the probe leg.
        counters.close_launch(epoch);
        let clean = counters.begin_launch().expect("the control's epoch");
        let probe = probe_with(proxy.port(), Some(proxy.token().value()));
        assert!(probe.starts_with("HTTP/1.1 204"), "{probe:?}");
        println!(
            "EVIDENCE control_probe_only proof={:?}",
            counters.proof(clean)
        );
        verify_proxy_proof(counters.proof(clean), ProofExpectation::Required)
            .expect("a probed session that made no other contact is unaffected");
        counters.close_launch(clean);
    }

    /// **P3.2a: a foreign credential is the same signal.** Lateral movement and a
    /// client stack that cannot authenticate both mean "reached the proxy and
    /// could not use this run's credential", so a probe-ok session whose only
    /// other contact presented somebody else's token is refused too.
    ///
    /// Distinguished from the existing foreign-credential leg (no probe, therefore
    /// `proxy_probe_unmet`): here the path IS proven, so the reason has to be the
    /// new one - the two refusals must not collapse into one string.
    #[test]
    fn a_probe_ok_session_whose_only_other_contact_used_a_foreign_credential_is_refused() {
        let proxy = LiveProxy::start(&[]);
        let counters = proxy.counters();
        let epoch = counters.begin_launch().expect("the launch's epoch");

        let probe = probe_with(proxy.port(), Some(proxy.token().value()));
        assert!(probe.starts_with("HTTP/1.1 204"), "{probe:?}");
        let attempt = cx(
            proxy.port(),
            "a-different-runs-token",
            "api.example.com:443",
        );
        assert!(
            attempt.starts_with("HTTP/1.1 407"),
            "a foreign credential is refused exactly like a missing one: {attempt:?}"
        );

        let proof = counters.proof(epoch);
        println!("EVIDENCE foreign_token_system_proxy proof={proof:?}");
        assert_eq!(proof.probes, 1, "{proof:?}");
        assert_eq!(
            (proof.accepted, proof.unauthenticated),
            (0, 1),
            "the foreign attempt is counted and never a consultation: {proof:?}"
        );
        let err = verify_proxy_proof(proof, ProofExpectation::Required)
            .expect_err("a session that only presented a foreign credential has no egress");
        println!("EVIDENCE refusal reason={err}");
        assert_eq!(err, GuardError::WorkloadCannotAuthenticate);

        counters.close_launch(epoch);
    }

    /// **P3.2a, the other direction: a policy denial is NOT a misconfiguration.**
    /// A launch whose workload authenticated and was then DENIED must still PASS -
    /// the credential path worked, the denial is the guardrail doing its job.
    ///
    /// Without this leg the new rule could drift into refusing every session that
    /// was denied anything, which would make `--allow-domain` unusable.
    #[test]
    fn a_probe_ok_session_whose_authenticated_connect_was_denied_still_passes() {
        let proxy = LiveProxy::start(&[]);
        let counters = proxy.counters();
        let epoch = counters.begin_launch().expect("the launch's epoch");

        let probe = probe_with(proxy.port(), Some(proxy.token().value()));
        assert!(probe.starts_with("HTTP/1.1 204"), "{probe:?}");
        let denied = cx(proxy.port(), proxy.token().value(), "api.example.com:443");
        assert!(
            denied.starts_with("HTTP/1.1 403"),
            "the workload authenticated and the POLICY denied it: {denied:?}"
        );

        let proof = counters.proof(epoch);
        println!("EVIDENCE authenticated_denied proof={proof:?}");
        assert_eq!(
            (proof.accepted, proof.tunnels),
            (1, 0),
            "a consultation that was denied is recorded, and no tunnel is claimed: {proof:?}"
        );
        assert_eq!(
            proof.unauthenticated, 0,
            "a client that authenticates is never counted here: {proof:?}"
        );
        verify_proxy_proof(proof, ProofExpectation::Required)
            .expect("an authenticated-but-denied workload used the proxy correctly");

        counters.close_launch(epoch);
    }

    /// **P3.2a: the 407-then-retry handshake is not a failure.** A .NET 8 /
    /// pwsh 7 managed client legitimately makes ONE credential-less attempt per
    /// connection and authenticates only after the `Proxy-Authenticate: Basic`
    /// challenge (P1.8), so this session must PASS.
    ///
    /// This is why the gate reads `unauthenticated` TOGETHER with `accepted`
    /// rather than demanding zero: `unauthenticated > 0` with an authenticated
    /// consultation is the handshake working, `> 0` with none is a client stack
    /// that can never use the proxy. Pin both, or the rule drifts into refusing the
    /// one managed shape the design supports.
    #[test]
    fn a_managed_client_that_authenticates_after_the_407_challenge_is_not_refused() {
        let proxy = LiveProxy::start(&[]);
        let counters = proxy.counters();
        let epoch = counters.begin_launch().expect("the launch's epoch");

        let probe = probe_with(proxy.port(), Some(proxy.token().value()));
        assert!(probe.starts_with("HTTP/1.1 204"), "{probe:?}");
        // 1. The unauthenticated first attempt: refused, but challenged.
        let first = connect_no_auth(proxy.port(), "api.example.com:443");
        assert!(first.starts_with("HTTP/1.1 407"), "{first:?}");
        assert!(
            first.contains("Proxy-Authenticate: Basic"),
            "the challenge is what makes the retry authenticate: {first:?}"
        );
        // 2. The retry, with the credential the URL carried all along: a real
        //    consultation, denied by policy (the gate's concern is the credential).
        let retry = cx(proxy.port(), proxy.token().value(), "api.example.com:443");
        assert!(retry.starts_with("HTTP/1.1 403"), "{retry:?}");

        let proof = counters.proof(epoch);
        println!("EVIDENCE managed_407_handshake proof={proof:?}");
        assert_eq!(
            (proof.probes, proof.unauthenticated, proof.accepted),
            (1, 1, 1),
            "one challenged attempt plus one authenticated consultation: {proof:?}"
        );
        verify_proxy_proof(proof, ProofExpectation::Required)
            .expect("the 407 handshake is how every supported managed client authenticates");

        counters.close_launch(epoch);
    }

    /// **P3.2a: the count is per EPOCH, not per listener.** Two sequential launches
    /// on one listener: the first makes credential-less attempts, the second is
    /// clean - and the second PASSES.
    ///
    /// Reusing the listener-lifetime `no_token`/`foreign_token` budgets would have
    /// refused launch N+1 on launch N's refusals, which is why the proof counter is
    /// its own epoch-scoped field.
    #[test]
    fn the_unauthenticated_count_is_per_epoch_so_a_second_launch_starts_clean() {
        let proxy = LiveProxy::start(&[]);
        let counters = proxy.counters();

        // Launch 1: two credential-less attempts, no probe.
        let first = counters.begin_launch().expect("the first launch's epoch");
        let attempt = connect_no_auth(proxy.port(), "api.example.com:443");
        assert!(attempt.starts_with("HTTP/1.1 407"), "{attempt:?}");
        let attempt = connect_no_auth(proxy.port(), "api.anthropic.com:443");
        assert!(attempt.starts_with("HTTP/1.1 407"), "{attempt:?}");
        assert_eq!(
            counters.proof(first).unauthenticated,
            2,
            "{:?}",
            counters.proof(first)
        );
        counters.close_launch(first);

        // Launch 2: probed, clean. It must inherit NOTHING.
        let second = counters.begin_launch().expect("the second launch's epoch");
        let probe = probe_with(proxy.port(), Some(proxy.token().value()));
        assert!(probe.starts_with("HTTP/1.1 204"), "{probe:?}");
        let proof = counters.proof(second);
        println!("EVIDENCE per_epoch first={first} second={second} proof={proof:?}");
        assert_eq!(
            proof.unauthenticated, 0,
            "a second launch must not inherit the first's refusals: {proof:?}"
        );
        verify_proxy_proof(proof, ProofExpectation::Required)
            .expect("the second launch is clean and must pass");

        // The first epoch's record is frozen, not reset: the evidence for launch 1
        // still reads what launch 1 did.
        assert_eq!(
            counters.counters(first).map(|c| c.unauthenticated),
            Some(2),
            "closing an epoch freezes it; it must never be zeroed by a later launch"
        );
        assert_eq!(
            counters.counters(second),
            Some(crate::net::proxy::LaunchProofCounters {
                consultations: 0,
                upstream_established: 0,
                probes: 1,
                unauthenticated: 0,
            }),
            "the second epoch counts only its own traffic"
        );

        counters.close_launch(second);
    }

    /// **P3.2a: `--block-net` is unaffected.** The new leg is scoped to the
    /// `Required` (proxy-configured) expectation.
    ///
    /// A proxy-less session has no listener to authenticate to, so its question -
    /// "did anything go out?" - is unchanged: `MustBeAbsent` still fails a
    /// consultation and still ignores the credential counters, which for a blocked
    /// session can only ever be zero.
    #[test]
    fn block_net_is_unaffected_by_the_unauthenticated_leg() {
        let refused = ProxyProof {
            accepted: 1,
            tunnels: 0,
            probes: 0,
            unauthenticated: 0,
        };
        assert_eq!(
            verify_proxy_proof(refused, ProofExpectation::MustBeAbsent)
                .expect_err("a blocked session that went out is still refused"),
            GuardError::ProxyConsultedUnexpectedly
        );
        let untouched = ProxyProof {
            accepted: 0,
            tunnels: 0,
            probes: 0,
            unauthenticated: 3,
        };
        verify_proxy_proof(untouched, ProofExpectation::MustBeAbsent).expect(
            "MustBeAbsent is the no-proxy leg: it neither probes nor authenticates, and the \
             new counter cannot make a blocked session refuse itself",
        );
    }

    /// A real session proxy (`127.0.0.1:0`, this process's own listener) plus the
    /// audit/learned scaffolding it needs.
    struct LiveProxy {
        handle: crate::net::proxy::ProxyHandle,
        sid: String,
        /// This listener's own run token: the only credential it accepts.
        token: RunToken,
        learned_base: PathBuf,
        /// The listener's audit writer, shared so a test can write the session's
        /// root into the same chain the listener appends CONNECT leaves to (P2.3).
        writer: Arc<crate::audit::AuditWriter>,
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
            // Never called: a session that expects this listener's allow-list to
            // answer never prompts. A dialog that reports itself unavailable makes
            // an accidental prompt a denial rather than a hang.
            let dialog: DialogFn = Arc::new(|_request| Err(DialogUnavailable));
            Self::start_with(allow, token, false, dialog)
        }

        /// A listener whose D-3.5 prompt really fires (P2.2 leg 2), with the
        /// dialog seam supplied by the caller: the seam is the only place that
        /// sees what the user would be shown for a consultation.
        fn start_prompting(allow: &[&str], dialog: DialogFn) -> Self {
            Self::start_with(
                allow,
                RunToken::issue().expect("mint a live token"),
                true,
                dialog,
            )
        }

        /// The one constructor: credential, prompt posture, dialog seam.
        fn start_with(
            allow: &[&str],
            token: RunToken,
            prompt_enabled: bool,
            dialog: DialogFn,
        ) -> Self {
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
            let prompt = crate::net::proxy::PromptGate {
                enabled: prompt_enabled,
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
                writer: writer.clone(),
                prompt,
            })
            .expect("spawn the session proxy");
            Self {
                handle,
                sid,
                token,
                learned_base,
                writer,
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

        // An evidence run measures what dispatched; the product rule (`Exactly`) is
        // pinned by the unit tests and by the live refusal test.
        let backend = MxcBackend::new(
            &proof,
            Some(endpoint.port),
            &launcher,
            TierExpectation::Recorded,
        )
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
        // Amended 2026-10-22: this launch now SUCCEEDS, and that is the point.
        // Its wrapper probed, so its path to the listener is proven; the refused
        // loopback CONNECT is recorded detail (`tunnels == 0`), no longer the
        // gate. What the leg still proves is the A/B it exists for: with
        // NO_PROXY ignored the child's request reached the PROXY (and was refused
        // there as a loopback target) instead of the endpoint.
        let outcome = backend
            .launch(
                &live_input(endpoint.port, &scratch_dir, &launcher, command),
                ProofExpectation::Required,
            )
            .expect("a session whose probe arrived passes, whatever its workload then did");
        let epoch = proof.last_epoch();
        println!(
            "EVIDENCE ab_control epoch={epoch} success={} proof={:?} proxy_consultations={:?} \
             origin_requests={:?}",
            outcome.success(),
            outcome.proxy_proof,
            endpoint.proxy_consultations(epoch),
            endpoint.origin_requests(epoch)
        );
        assert_eq!(
            outcome.proxy_proof.probes, 1,
            "the wrapper's own probe is the launch's evidence: {:?}",
            outcome.proxy_proof
        );
        assert!(
            !endpoint.proxy_consultations(epoch).is_empty(),
            "with NO_PROXY ignored, the request must reach the proxy"
        );
        assert_eq!(
            outcome.proxy_proof.tunnels, 0,
            "a loopback target is refused by the proxy, so nothing is established upstream: \
             {:?}",
            outcome.proxy_proof
        );
        assert!(
            !endpoint
                .origin_requests(epoch)
                .iter()
                .any(|line| line.contains("/sandbox/intent")),
            "with NO_PROXY ignored, no intent request may reach the endpoint directly: {:?}",
            endpoint.origin_requests(epoch)
        );
        // The GATE passed (this launch returned `Ok`), which is what the leg is
        // about. `success()` also demands exit 0 and must NOT: `curl -f` exits 22
        // because the proxy refused the request with 403 — the A/B's whole point.
        assert_eq!(
            outcome.exit_code,
            Some(22),
            "curl must report the proxy's 403 as its own failure: {outcome:?}"
        );
        assert!(
            verify_proxy_proof(outcome.proxy_proof, outcome.expectation).is_ok(),
            "guardrail 1 must pass on the probe, whatever the workload's request got: {:?}",
            outcome.proxy_proof
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
            SessionBudget::default(),
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
            SessionBudget::default(),
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
            SessionBudget::default(),
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
            SessionBudget::default(),
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
            SessionBudget::default(),
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
            SessionBudget::default(),
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
            SessionBudget::default(),
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
                SessionBudget::default(),
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

    /// A session's whole audit chain, parsed.
    fn audit_leaves(sid: &str) -> Vec<serde_json::Value> {
        std::fs::read_to_string(crate::audit::audit_log_path(sid))
            .unwrap_or_default()
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| serde_json::from_str(line).expect("each leaf is one JSON object"))
            .collect()
    }

    /// P2.3 acceptance 3: **a wrong tier is a refused session with NO CONNECT
    /// leaves.**
    ///
    /// Driven against a real listener with its real audit writer, so the assertion
    /// is about a `.ndjson` file a proxy could have appended to — not about a
    /// hypothetical chain. The ordering is the supervisor's: arm the session-start
    /// guard, probe, fail guardrail 2, then write the root (naming the tier that
    /// was *actually* dispatched) and the refusal. Nothing spawns, so the
    /// listener's own counters stay `{0,0}` — the positive evidence that no
    /// consultation happened, which is stronger than an empty file.
    #[test]
    fn a_wrong_tier_refuses_the_session_with_no_connect_leaves() {
        let proxy = LiveProxy::start(&["api.anthropic.com"]);

        // The tier record exactly as `probe_tier` produces it for a degraded
        // dispatch.
        let observed = tier_record(ProbeView {
            tier: Some("appcontainer-dacl"),
            needs_dacl_augmentation: Some(true),
        });
        let refusal = verify_tier(&observed, TierExpectation::Exactly(REQUIRED_TIER))
            .expect_err("a degraded tier must refuse a base-container session");

        // The supervisor's own ordering (P2.3): the root carries the observed
        // facts, the refusal follows it, and nothing else is written. The endpoint
        // is the listener's bare authority — `LoopbackEndpoint` takes a `u16`, so
        // the child's credential-bearing proxy URL cannot be passed here at all
        // (P2.3 review, item 3).
        let endpoint = crate::audit::session_start::LoopbackEndpoint::new(proxy.port());
        let facts = crate::audit::session_start::SessionStartFacts::measured(
            observed.audit_facts(),
            Some(true),
        );
        crate::audit::session_start::SessionStart::arm(
            proxy.writer.clone(),
            &proxy.sid,
            "cmd /c echo hi",
            facts,
        )
        .refuse(
            Some(endpoint),
            crate::audit::session_start::TierRefusal::tier_mismatch(refusal.expected),
        )
        .expect("the refusal is audited");

        // No CONNECT leaf — and none could exist: the listener never accepted a
        // connection because no child was ever started.
        assert_eq!(
            connect_leaves(&proxy.sid),
            0,
            "a refused session must have no CONNECT leaves"
        );
        let counters = proxy.counters();
        let epoch = ProxyProofSource::begin_launch(counters.as_ref()).expect("no epoch is open");
        let proof = ProxyProofSource::proof(counters.as_ref(), epoch);
        ProxyProofSource::close_launch(counters.as_ref(), epoch);
        assert_eq!(
            proof,
            ProxyProof::default(),
            "the listener must never have been consulted for a refused session"
        );

        let leaves = audit_leaves(&proxy.sid);
        assert_eq!(leaves.len(), 2, "root + refusal, nothing else: {leaves:?}");
        assert_eq!(leaves[0]["op"], "SESSION_START");
        assert_eq!(leaves[0]["parent"], serde_json::Value::Null);
        assert_eq!(
            leaves[0]["tier"], "appcontainer-dacl",
            "the refused session still records the tier it would have run on"
        );
        assert_eq!(leaves[0]["tier_source"], "probe");
        assert_eq!(
            leaves[0]["disposition"], "deny",
            "the refusal's root must already say deny, not `allow` (P2.3 review, item 2)"
        );
        assert_eq!(
            leaves[0]["proxy_endpoint"],
            endpoint.to_string(),
            "the bare loopback authority, never a URL"
        );
        assert_eq!(leaves[1]["op"], "SESSION_REFUSED");
        assert_eq!(leaves[1]["disposition"], "deny");
        assert_eq!(leaves[1]["reason"], "tier_mismatch");
        assert_eq!(leaves[1]["expected_tier"], REQUIRED_TIER);
        assert_eq!(leaves[1]["parent"], leaves[0]["hash"]);

        // The chain's own credential rule (P2.3 acceptance 5) survives the refusal
        // path: the listener's token is nowhere in the file.
        let raw = std::fs::read_to_string(crate::audit::audit_log_path(&proxy.sid))
            .expect("the chain exists");
        assert!(
            !raw.contains(proxy.token().value()),
            "token in the chain: {raw}"
        );
        assert!(!raw.contains('@'), "userinfo in the chain: {raw}");
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
                probes: 1,
                unauthenticated: 0,
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
                        SessionBudget::default(),
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
                        SessionBudget::default(),
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
                probes: 1,
                unauthenticated: 0,
            },
            "run A's proof must count only run A's consultation and its own probe"
        );
        assert_eq!(
            out_b.proxy_proof,
            ProxyProof {
                accepted: 1,
                tunnels: 1,
                probes: 1,
                unauthenticated: 0,
            },
            "run B's proof must count only run B's consultation and its own probe"
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
            counters_a.counters(epoch_a).map(|c| (
                c.consultations,
                c.upstream_established,
                c.probes
            )),
            Some((0, 0, 0)),
            "a foreign token must not count as a consultation, a tunnel or a probe"
        );
        assert_eq!(
            counters_a.counters(epoch_a).map(|c| c.unauthenticated),
            Some(1),
            "it IS counted as an unauthenticated attempt (P3.2a): run A must be able to see \
             that something reached its listener without its credential"
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
            counters_b.counters(epoch_b).map(|c| (
                c.consultations,
                c.upstream_established,
                c.probes
            )),
            Some((0, 0, 0)),
            "a foreign token must not count at run B as traffic either"
        );
        assert_eq!(
            counters_b.counters(epoch_b).map(|c| c.unauthenticated),
            Some(1),
            "and it is counted once as an unauthenticated attempt at B, symmetrically to A"
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
             own run token, with the cross-run token refused as traffic (counted only as an \
             unauthenticated attempt) and kept out of the other run's proof"
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
        // Evidence runs measure what dispatched; enforcement is the product path's
        // (`supervisor_backend` -> `Exactly(REQUIRED_TIER)`).
        let backend = MxcBackend::new(
            counters.as_ref(),
            Some(proxy.port()),
            &launcher,
            TierExpectation::Recorded,
        )
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
        // Evidence runs measure what dispatched; enforcement is the product path's
        // (`supervisor_backend` -> `Exactly(REQUIRED_TIER)`).
        let backend = MxcBackend::new(
            counters.as_ref(),
            Some(proxy.port()),
            &launcher,
            TierExpectation::Recorded,
        )
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

    // =====================================================================
    // P2.2: the D-4 control plane, proven from INSIDE a container
    // =====================================================================
    //
    // ADR-0001 §D-4 puts three endpoints on the proxy's loopback listener:
    // `POST /sandbox/intent` (204 / 400), `GET /sandbox/intent?host=` (200 with
    // `{host, reason, ts}` / 404) and `POST /sandbox/intent/explain` (204,
    // one-shot). The child reaches them DIRECTLY — `NO_PROXY` bypasses the proxy
    // for loopback — and identifies itself with `Proxy-Authorization: Basic
    // <sandbox:token>`.
    //
    // The two legs below are the MXC half of that contract. They are in-process
    // on purpose: `main.rs` refuses `--backend mxc` and the VM harness never
    // passes it, so no VM scenario can exercise this backend until the wiring
    // lands in P3 (the plan's standing coverage note). VM scenario S-77 is the
    // AppContainer baseline, and it checks strictly less than leg 1.

    /// The host the container declares intent for. `.example` is reserved, so a
    /// stray lookup could never leave this machine even if one were attempted.
    const P22_HOST: &str = "p22-declared.example";

    /// The reason the agent inside the container declares. Spelled once, so the
    /// GET must return *this* string rather than merely a non-empty one.
    const P22_REASON: &str = "reason-declared-from-inside-the-container";

    /// A host the container consults and that nothing allow-lists, so the D-3.5
    /// prompt is the only layer that can answer (leg 2).
    const P22_PROMPT_HOST: &str = "p22-prompt.example";

    /// What every P2.2 script starts with: derive the control-plane endpoint from
    /// the session's **own** proxy variable, and derive the
    /// `Proxy-Authorization: Basic` credential from that same token.
    ///
    /// This is done the way a real workload has to do it, because it is part of
    /// what the leg proves. The MXC launcher injects
    /// `HTTP_PROXY=http://sandbox:<token>@127.0.0.1:<port>`,
    /// `NO_PROXY=localhost,127.0.0.1,::1` and — since P2.4 —
    /// `SANDBOX_PROXY_PORT=<port>`, the D-0.3 discovery variable the
    /// AppContainer path has always injected. The script below deliberately keeps
    /// deriving the endpoint from `HTTP_PROXY` rather than reading the discovery
    /// variable: the env leg asserts that the two agree (`SANDBOX_PROXY_PORT` ==
    /// this listener's port), and a second, independent derivation is what makes
    /// that agreement evidence instead of a tautology. `cmd.exe` cannot
    /// base64, so the credential comes from `certutil`: one PEM block whose
    /// payload lines are concatenated (a 64-hex run token makes the payload wrap
    /// at 64 columns, and using only the first line produced a truncated
    /// credential — every call answered 407 until this joined them).
    const P22_PRELUDE: &str = r#"@echo off
rem Delayed expansion: the payload below can span more than one 64-column line.
setlocal enabledelayedexpansion
rem The endpoint, from the child's own environment: no argument from the test.
for /f "tokens=3,5 delims=:@" %%a in ("%HTTP_PROXY%") do (
  set "TOK=%%a"
  set "PORT=%%b"
)
if not defined TOK ( echo MARK parse=no_token & exit 4 )
if not defined PORT ( echo MARK parse=no_port & exit 4 )
echo MARK parsed_port=%PORT%
rem `set /p` with '=...' writes NO trailing newline: `echo` would add CRLF to the
rem file, certutil would encode it, and the credential would carry a stray CRLF
rem (observed: every call answered 407 because the password did not match).
<nul > creds.txt set /p "=sandbox:%TOK%"
certutil -encode -f creds.txt creds.b64 >nul 2>&1
set "B64="
for /f "skip=1 delims=" %%L in (creds.b64) do if not "%%L"=="-----END CERTIFICATE-----" set "B64=!B64!%%L"
del creds.txt creds.b64 >nul 2>&1
if not defined B64 ( echo MARK base64=failed & exit 4 )
echo MARK auth=derived
set "H=Proxy-Authorization: Basic %B64%"
set "AURL=http://127.0.0.1:%PORT%/sandbox/intent"
"#;

    /// The eight calls of leg 1: the roundtrip, the one-shot, and the three
    /// negative cases. Each status is a `MARK` line on stdout *and* an artifact
    /// in the workspace, so a failure can be diagnosed from the file rather than
    /// inferred from curl's exit code.
    ///
    /// The credential-dependent calls are the proof that the child identified
    /// itself: the listener answers 407 to every credential that is not its
    /// run's (P1.4), before it routes anything.
    const P22_ROUNDTRIP_BODY: &str = r#"> body-declare.json echo {"target":"__HOST__","reason":"__REASON__"}
> body-explain.json echo {"host":"__HOST__"}
> body-malformed.json echo this-is-not-json
curl -sS -o out-post.txt -w "MARK post_intent=%%{http_code}\n" -H "%H%" -H "Content-Type: application/json" --data-binary @body-declare.json "%AURL%"
curl -sS -o out-get-declared.json -w "MARK get_declared=%%{http_code}\n" -H "%H%" "%AURL%?host=__HOST__"
curl -sS -o out-explain.txt -w "MARK post_explain=%%{http_code}\n" -H "%H%" -H "Content-Type: application/json" --data-binary @body-explain.json "%AURL%/explain"
curl -sS -o out-get-flagged.json -w "MARK get_after_explain=%%{http_code}\n" -H "%H%" "%AURL%?host=__HOST__"
curl -sS -o out-get-consumed.json -w "MARK get_after_consume=%%{http_code}\n" -H "%H%" "%AURL%?host=__HOST__"
curl -sS -o out-get404.json -w "MARK get_undeclared=%%{http_code}\n" -H "%H%" "%AURL%?host=never-declared-p22.example"
curl -sS -o out-post400.txt -w "MARK post_malformed=%%{http_code}\n" -H "%H%" -H "Content-Type: application/json" --data-binary @body-malformed.json "%AURL%"
curl -sS -o out-get407.txt -w "MARK get_wrong_credential=%%{http_code}\n" -H "Proxy-Authorization: Basic c2FuZGJveDp3cm9uZw==" "%AURL%?host=__HOST__"
echo MARK done
"#;

    /// Leg 2's two calls: declare the intent, then consult the host. Both marker
    /// lines also go to files, because the launch is *expected* to fail guardrail
    /// 1 (a consultation), so the launch's stdout is not available to assert on.
    ///
    /// `exit /b 0` is deliberate: the CONNECT is meant to be refused, and the
    /// evidence is the marker files plus the dialog, not the child's exit code.
    const P22_PROMPT_BODY: &str = r#"> body-prompt.json echo {"target":"__HOST__","reason":"__REASON__"}
curl -sS -o out-prompt-post.txt -w "MARK prompt_intent=%%{http_code}\n" -H "%H%" -H "Content-Type: application/json" --data-binary @body-prompt.json "%AURL%" > markers-prompt.txt
type markers-prompt.txt
curl -sS -o out-prompt-connect.txt -w "MARK prompt_connect=%%{http_code}\n" --max-time 10 "https://__HOST__/" > markers-connect.txt
type markers-connect.txt
echo MARK done
exit /b 0
"#;

    /// Write one CRLF batch file (shared prelude + `body`) into the container's
    /// workspace and return the command line that runs it.
    fn p22_script(dir: &Path, name: &str, host: &str, reason: &str, body: &str) -> String {
        let path = dir.join(format!("{name}.bat"));
        let script = format!("{P22_PRELUDE}{body}")
            .replace("__HOST__", host)
            .replace("__REASON__", reason);
        // CRLF before it reaches cmd.exe, and independently of the source file's
        // own line endings (a batch file with bare LF loses `for /f` lines).
        let script = script.replace("\r\n", "\n").replace('\n', "\r\n");
        std::fs::write(&path, script.as_bytes())
            .unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
        format!("cmd /c \"{}\"", path.display())
    }

    /// One `MARK key=value` line from a P2.2 script's stdout.
    fn mark(stdout: &str, key: &str) -> Option<String> {
        let prefix = format!("MARK {key}=");
        stdout
            .lines()
            .find_map(|line| line.trim().strip_prefix(&prefix))
            .map(|value| value.trim().to_string())
    }

    /// One `MARK key=<http status>` line, as a number.
    fn mark_code(stdout: &str, key: &str) -> Option<u16> {
        mark(stdout, key).and_then(|value| value.parse().ok())
    }

    /// What the dialog seam saw, one `(host, agent reason)` per consultation.
    ///
    /// An alias rather than the literal type: the seam is what P2.2 leg 2
    /// asserts on, and `clippy::type_complexity` asks for exactly this.
    type DialogCalls = Arc<Mutex<Vec<(String, Option<String>)>>>;

    /// The eight statuses leg 1 asserts, printed in one line.
    fn p22_statuses(stdout: &str) -> String {
        [
            "post_intent",
            "get_declared",
            "post_explain",
            "get_after_explain",
            "get_after_consume",
            "get_undeclared",
            "post_malformed",
            "get_wrong_credential",
        ]
        .iter()
        .map(|key| format!("{key}={:?}", mark_code(stdout, key)))
        .collect::<Vec<_>>()
        .join(" ")
    }

    /// P2.2 leg 1 of 2: **the whole D-4 roundtrip, end to end, from inside an MXC
    /// container**, against the supervisor's real listener.
    ///
    /// Proven in this leg (all unelevated, on this host):
    ///
    /// 1. the child carries `NO_PROXY` with all three loopback spellings, and the
    ///    proxy variable that carries the session token;
    /// 2. it derives the endpoint and its `Basic` credential from that token
    ///    itself (no argument is handed to it by the test);
    /// 3. `POST /sandbox/intent` → 204, then `GET …?host=` → 200 with the
    ///    declared reason, the normalized host and an RFC3339 `ts`;
    /// 4. `POST /sandbox/intent/explain` → 204 sets the flag, the first GET
    ///    reports `"hint":"explain-more"`, and the *next* GET reports
    ///    `"hint":"declared"` — the flag is one-shot;
    /// 5. an undeclared host is 404, a malformed body is 400, and a wrong
    ///    credential is 407 (`the control plane is not an unauthenticated
    ///    oracle`);
    /// 6. none of the eight calls is a proxy consultation: the listener's own
    ///    counters stay `{accepted: 0, tunnels: 0}` plus the wrapper's one
    ///    probe, which is what
    ///    `ProofExpectation::MustBeAbsent` refuses the launch over;
    /// 7. the only audit leaf the launch writes is the wrong credential's
    ///    `foreign_token` refusal (`host: "<unknown>"`), and nothing names a host
    ///    or allows anything — an intent call is not a decision.
    #[test]
    #[ignore = "launches a real ProcessContainer; run: cargo test --features mxc-backend --bin sandbox -- --ignored"]
    fn d4_intent_roundtrip_from_inside_the_container_is_proven() {
        let launcher = launcher_under_test();
        let proxy = LiveProxy::start(&[]);
        let counters = proxy.counters();
        let scratch = Scratch::plain("p22-intent");
        let dir = scratch.path().to_path_buf();
        let backend = supervisor_backend(
            counters.as_ref(),
            Some(proxy.port()),
            Some(proxy.token().value()),
            &launcher,
            SessionBudget::default(),
        )
        .with_budget(SessionBudget::new(
            Duration::from_secs(30),
            Duration::from_secs(80),
            Duration::from_secs(10),
        ));

        println!(
            "EVIDENCE elevated={} launcher={} proxy_port={} sid={}",
            process_is_elevated(),
            launcher.display(),
            proxy.port(),
            proxy.sid
        );

        // ---- 1. the child's environment: NO_PROXY and the session token -----
        let outcome = backend
            .launch(
                &live_input(proxy.port(), &dir, &launcher, "cmd /c set".to_string()),
                ProofExpectation::MustBeAbsent,
            )
            .expect("environment dump launch");
        let env_dump = stdout_of(&outcome);
        let no_proxy = env_dump
            .lines()
            .find(|line| line.to_ascii_lowercase().starts_with("no_proxy="))
            .map(|line| line.trim().to_string())
            .unwrap_or_default();
        let http_proxy = env_dump
            .lines()
            .find(|line| line.to_ascii_uppercase().starts_with("HTTP_PROXY="))
            .map(|line| line.trim().to_string())
            .unwrap_or_default();
        // P2.4: the D-0.3 **discovery** contract, not just the proxy URL. The
        // AppContainer path injects `SANDBOX_PROXY_PORT`
        // (`src/sandbox/appcontainer.rs:1007`); until P2.4 the MXC launcher did
        // not, so a workload written to D-0.3 (`GET
        // http://127.0.0.1:$SANDBOX_PROXY_PORT/sandbox/intent`) could not find
        // the endpoint at all under this backend. The value must be THIS
        // listener's port: an inherited or stale number would point the
        // workload at a socket the supervisor does not own.
        let proxy_port_var = env_dump
            .lines()
            .find(|line| line.starts_with("SANDBOX_PROXY_PORT="))
            .map(|line| line.trim().to_string())
            .unwrap_or_default();
        println!(
            "EVIDENCE child_env {no_proxy:?} {http_proxy:?} {proxy_port_var:?} proof={:?}",
            outcome.proxy_proof
        );
        let no_proxy_value = no_proxy
            .split_once('=')
            .map(|(_, value)| value.trim())
            .unwrap_or_default();
        assert_eq!(
            no_proxy_value, "localhost,127.0.0.1,::1",
            "the child must carry NO_PROXY from the launcher: {no_proxy:?}"
        );
        for spelling in ["localhost", "127.0.0.1", "::1"] {
            assert!(
                no_proxy_value.split(',').any(|host| host == spelling),
                "NO_PROXY must name the loopback spelling {spelling}: {no_proxy_value:?}"
            );
        }
        // Without the token in the proxy variable a real workload has no
        // credential for the control plane, so the endpoints would be
        // unreachable while NO_PROXY still looked correct.
        assert!(
            http_proxy.to_ascii_lowercase().contains(&format!(
                "sandbox:{}@127.0.0.1:{}",
                proxy.token().value(),
                proxy.port()
            )),
            "the child's proxy variable must carry the session token: {http_proxy:?}"
        );
        // The D-0.3 contract: a workload discovers the control plane from this
        // variable, so it must exist AND name this listener.
        let port_var_value = proxy_port_var
            .split_once('=')
            .map(|(_, value)| value.trim())
            .unwrap_or_default();
        assert_eq!(
            port_var_value,
            proxy.port().to_string(),
            "the child must carry SANDBOX_PROXY_PORT naming this listener's port \
             (D-0.3 discovery); absent or a different port makes the D-4 endpoint \
             undiscoverable by a workload that only knows that contract: {proxy_port_var:?}"
        );

        // ---- 2. the roundtrip, the one-shot and the negative cases ----------
        let command = p22_script(
            &dir,
            "p22-roundtrip",
            P22_HOST,
            P22_REASON,
            P22_ROUNDTRIP_BODY,
        );
        println!("EVIDENCE roundtrip_command={command:?}");
        let outcome = backend
            .launch(
                &live_input(proxy.port(), &dir, &launcher, command),
                ProofExpectation::MustBeAbsent,
            )
            .expect("intent calls are not proxy consultations, so guardrail 1 must see {0,0}");
        let out = stdout_of(&outcome);
        println!(
            "EVIDENCE roundtrip exit={:?} success={} proof={:?} expectation={:?} tier={:?}",
            outcome.exit_code,
            outcome.success(),
            outcome.proxy_proof,
            outcome.expectation,
            outcome.tier.tier
        );
        println!("EVIDENCE roundtrip_stdout={:?}", out.trim());
        println!("EVIDENCE roundtrip_stderr={:?}", stderr_of(&outcome).trim());
        assert_eq!(
            outcome.exit_code,
            Some(0),
            "the control-plane script must exit 0: {outcome:?}"
        );
        assert!(
            out.contains("MARK done"),
            "the script must have run every call: {out:?}"
        );
        // The endpoint came from the child's own environment, not from the test:
        // if the test had supplied it, this line could not exist.
        assert_eq!(
            mark(&out, "parsed_port"),
            Some(proxy.port().to_string()),
            "the child must derive the port from its own HTTP_PROXY: {out:?}"
        );
        assert_eq!(
            mark(&out, "auth"),
            Some("derived".to_string()),
            "the child must derive its own Basic credential from the session token: {out:?}"
        );

        println!("EVIDENCE statuses {}", p22_statuses(&out));
        assert_eq!(
            mark_code(&out, "post_intent"),
            Some(204),
            "POST /sandbox/intent must answer 204: {out:?}"
        );
        assert_eq!(
            mark_code(&out, "get_declared"),
            Some(200),
            "GET /sandbox/intent must answer 200 for a declared host: {out:?}"
        );
        assert_eq!(
            mark_code(&out, "post_explain"),
            Some(204),
            "POST /sandbox/intent/explain must answer 204: {out:?}"
        );
        assert_eq!(
            mark_code(&out, "get_after_explain"),
            Some(200),
            "the GET after an explain POST must still answer 200: {out:?}"
        );
        assert_eq!(
            mark_code(&out, "get_after_consume"),
            Some(200),
            "the second GET after an explain POST must still answer 200: {out:?}"
        );
        assert_eq!(
            mark_code(&out, "get_undeclared"),
            Some(404),
            "an undeclared host must be 404, never a fabricated entry: {out:?}"
        );
        assert_eq!(
            mark_code(&out, "post_malformed"),
            Some(400),
            "a malformed body must be 400, never a 204 that swallows it: {out:?}"
        );
        assert_eq!(
            mark_code(&out, "get_wrong_credential"),
            Some(407),
            "a wrong credential must be refused before routing, or the control plane is an \
             unauthenticated oracle: {out:?}"
        );

        // ---- 3. the bodies: the declared reason, the ts, the one-shot -------
        let body = |name: &str| std::fs::read_to_string(dir.join(name)).unwrap_or_default();
        let parsed = |name: &str| -> serde_json::Value {
            serde_json::from_str(&body(name))
                .unwrap_or_else(|e| panic!("{name} is not JSON ({e}): {:?}", body(name)))
        };

        let declared = parsed("out-get-declared.json");
        println!("EVIDENCE get_declared_body={declared}");
        assert_eq!(
            declared["host"], P22_HOST,
            "GET must echo the normalized host it looked up: {declared}"
        );
        assert_eq!(
            declared["reason"], P22_REASON,
            "GET must return the reason the container declared, verbatim: {declared}"
        );
        assert_eq!(
            declared["hint"], "declared",
            "a declared entry with no explain request reports `declared`: {declared}"
        );
        let ts = declared["ts"]
            .as_str()
            .unwrap_or_else(|| panic!("a 200 must carry a ts: {declared}"));
        assert!(
            ts.len() == 20
                && ts.ends_with('Z')
                && ts.as_bytes()[4] == b'-'
                && ts.as_bytes()[10] == b'T',
            "ts must be RFC3339 UTC whole seconds (YYYY-MM-DDTHH:MM:SSZ): {ts:?}"
        );
        let year: u32 = ts[..4].parse().expect("a four-digit year");
        assert!(
            year >= 2026,
            "ts must be this run's wall clock, not the epoch: {ts:?}"
        );

        // D-4's one-shot: the explain POST sets the flag, ONE read consumes it.
        let flagged = parsed("out-get-flagged.json");
        println!("EVIDENCE get_after_explain_body={flagged}");
        assert_eq!(
            flagged["hint"], "explain-more",
            "POST /sandbox/intent/explain must take effect: the next GET reports the hint \
             (the 204 alone would not prove it): {flagged}"
        );
        let consumed = parsed("out-get-consumed.json");
        println!("EVIDENCE get_after_consume_body={consumed}");
        assert_eq!(
            consumed["hint"], "declared",
            "the explain-more flag is ONE-SHOT: the read above consumed it, so the next GET must \
             not report it again: {consumed}"
        );
        assert_eq!(
            consumed["reason"], P22_REASON,
            "consuming the hint must not disturb the entry: {consumed}"
        );

        let undeclared = parsed("out-get404.json");
        println!("EVIDENCE get_undeclared_body={undeclared}");
        assert_eq!(
            undeclared["hint"], "undeclared",
            "a 404 reports the undeclared hint: {undeclared}"
        );
        assert_eq!(
            undeclared["reason"], "",
            "a 404 must not invent a reason: {undeclared}"
        );
        assert_eq!(
            body("out-post400.txt"),
            "",
            "a 400 carries no body: {:?}",
            body("out-post400.txt")
        );
        assert_eq!(
            body("out-get407.txt"),
            "",
            "a 407 carries no body: {:?}",
            body("out-get407.txt")
        );

        // ---- 4. no proxy consultation, and no decision leaf ----------------
        assert_eq!(
            outcome.expectation,
            ProofExpectation::MustBeAbsent,
            "the intent calls can only be proven direct if the session expected no consultation"
        );
        assert_eq!(
            outcome.proxy_proof,
            ProxyProof {
                accepted: 0,
                tunnels: 0,
                // The wrapper's pre-flight probe, and nothing else: an intent call
                // served on the listener is NOT a proxy consultation.
                probes: 1,
                // Exactly one: the workload's OWN `407` leg sends a wrong credential
                // on purpose (`get_wrong_credential=407`). It is a control-plane
                // refusal, so it counts as an unauthenticated attempt (P3.2a) and
                // still never as traffic - and the session's expectation here is
                // `MustBeAbsent`, which this counter cannot affect.
                unauthenticated: 1,
            },
            "the roundtrip must record the probe, zero proxy traffic and the one \
             407 the workload asked for: {outcome:?}"
        );

        let leaves = audit_leaves(&proxy.sid);
        for leaf in &leaves {
            println!("EVIDENCE audit_leaf={leaf}");
        }
        assert_eq!(
            connect_leaves(&proxy.sid),
            leaves.len(),
            "every leaf this launch wrote is a CONNECT-shaped leaf: {leaves:?}"
        );
        assert!(
            leaves.iter().all(|leaf| leaf["host"] == "<unknown>"),
            "no intent call may write a decision leaf naming a host: {leaves:?}"
        );
        assert!(
            leaves.iter().all(|leaf| leaf["disposition"] != "allow"),
            "no intent call may write an allow leaf: {leaves:?}"
        );
        assert_eq!(
            leaves.len(),
            1,
            "exactly one leaf is expected: the wrong credential's own refusal (P1.4 records a \
             foreign token, which is not a decision): {leaves:?}"
        );
        assert_eq!(
            leaves[0]["reason"], "foreign_token",
            "the 407 must be recorded as a refused credential, not as a decision: {leaves:?}"
        );

        println!(
            "EVIDENCE done: D-4 roundtrip (204/200/204, one-shot consumed), 404/400/407, zero \
             proxy consultations, only the credential refusal in the chain"
        );
    }

    /// P2.2 leg 2 of 2: **D-4's actual point** — a reason declared by a process
    /// *inside the container* is what the user's dialog sees when that host is
    /// consulted.
    ///
    /// `prompt_default` (`src/net/proxy.rs`) reads the registry through
    /// `ctx.prompt.intent.lookup_host(host)` before it calls the coordinator, and
    /// the unit test `prompt_receives_declared_intent_reason` pins that wiring
    /// in-process. This leg proves the same thing **across the container
    /// boundary**: the child POSTs the intent, then the child itself issues a
    /// CONNECT, and the dialog seam — the only thing that sees the request —
    /// receives the child's own string.
    ///
    /// The launch is *expected* to fail guardrail 1 with
    /// `ProxyConsultedUnexpectedly`: that failure is the proof that the CONNECT
    /// really reached the decision pipeline, i.e. that the reason was not observed
    /// by some shortcut the product does not take.
    #[test]
    #[ignore = "launches a real ProcessContainer; run: cargo test --features mxc-backend --bin sandbox -- --ignored"]
    fn a_declared_intent_is_the_prompt_reason_from_inside_the_container() {
        let launcher = launcher_under_test();
        let seen: DialogCalls = Arc::new(Mutex::new(Vec::new()));
        let recorder = Arc::clone(&seen);
        let dialog: DialogFn = Arc::new(move |request: &DialogRequest| {
            recorder
                .lock()
                .unwrap()
                .push((request.host.clone(), request.reason.clone()));
            Ok(PromptResult::Deny {
                persist: false,
                scope: "host".to_string(),
                suffix: None,
            })
        });
        let proxy = LiveProxy::start_prompting(&[], dialog);
        let counters = proxy.counters();
        let scratch = Scratch::plain("p22-prompt");
        let dir = scratch.path().to_path_buf();
        let backend = supervisor_backend(
            counters.as_ref(),
            Some(proxy.port()),
            Some(proxy.token().value()),
            &launcher,
            SessionBudget::default(),
        )
        .with_budget(SessionBudget::new(
            Duration::from_secs(30),
            Duration::from_secs(80),
            Duration::from_secs(10),
        ));

        println!(
            "EVIDENCE elevated={} launcher={} proxy_port={} prompt_enabled=true consult_host={}",
            process_is_elevated(),
            launcher.display(),
            proxy.port(),
            P22_PROMPT_HOST
        );
        let command = p22_script(
            &dir,
            "p22-prompt",
            P22_PROMPT_HOST,
            P22_REASON,
            P22_PROMPT_BODY,
        );
        let err = backend
            .launch(
                &live_input(proxy.port(), &dir, &launcher, command),
                // The expectation a session with no network use states: the
                // failure below is the positive evidence of a consultation.
                ProofExpectation::MustBeAbsent,
            )
            .expect_err("the CONNECT must reach the proxy, so guardrail 1 must refuse the launch");
        println!("EVIDENCE consult_guard={err}");
        // P3.0 shape: a refusal raised AFTER the child ran is `Unproven` and
        // carries the outcome; the refused LEG is what this asserts. (Written
        // for the pre-P3.0 `Guard` shape, so this line was red until the
        // 2026-10-22 pass — the gate itself never changed.)
        assert!(
            matches!(
                err,
                MxcError::Unproven(ref refused)
                    if refused.error == GuardError::ProxyConsultedUnexpectedly
            ),
            "the CONNECT must have been counted as a real consultation, not skipped: {err:?}"
        );

        let read = |name: &str| std::fs::read_to_string(dir.join(name)).unwrap_or_default();
        let intent_marker = read("markers-prompt.txt");
        let connect_marker = read("markers-connect.txt");
        println!("EVIDENCE prompt_intent_marker={:?}", intent_marker.trim());
        println!("EVIDENCE prompt_connect_marker={:?}", connect_marker.trim());
        assert_eq!(
            mark_code(&intent_marker, "prompt_intent"),
            Some(204),
            "the container must declare its intent before consulting: {intent_marker:?}"
        );

        let calls = seen.lock().unwrap().clone();
        println!("EVIDENCE dialog_calls={calls:?}");
        let for_host: Vec<&(String, Option<String>)> = calls
            .iter()
            .filter(|(host, _)| host == P22_PROMPT_HOST)
            .collect();
        assert!(
            !for_host.is_empty(),
            "the dialog must have been asked about the consulted host: {calls:?}"
        );
        assert!(
            for_host
                .iter()
                .all(|(_, reason)| reason.as_deref() == Some(P22_REASON)),
            "the dialog must receive the reason the container declared — D-4's point — not \
             `None` and not some other string: {calls:?}"
        );

        let leaves = audit_leaves(&proxy.sid);
        for leaf in &leaves {
            println!("EVIDENCE audit_leaf={leaf}");
        }
        assert!(
            leaves
                .iter()
                .any(|leaf| leaf["host"] == P22_PROMPT_HOST && leaf["disposition"] == "deny"),
            "the refused consultation must be audited for the consulted host: {leaves:?}"
        );
        assert!(
            leaves.iter().any(|leaf| leaf["source"] == "prompt"),
            "the leaf must name the dialog as the decision's source: {leaves:?}"
        );

        println!(
            "EVIDENCE done: the container's declared reason reached the prompt, and the \
             consultation was counted"
        );
    }

    // =====================================================================
    // P2.4 / ADR-0004 guardrail 1 (amended 2026-10-22): the pre-flight probe
    // =====================================================================
    //
    // ADR-0004: "`warnings: []` is NOT evidence; a session MUST NOT be reported
    // as successful unless the supervisor can prove the child reached the
    // proxy." The evidence is now the WRAPPER's own probe of this listener,
    // issued before the payload starts and counted on the listener's side, in
    // the launch's epoch — because the old `>= 1 tunnel` rule demanded a
    // WORKLOAD event, so every network session whose workload made no request
    // was refused while its proxy path was fine (S-55, S-77, S-86, S-91).
    //
    // What a live leg adds that a unit test cannot: `verify_proxy_proof` is
    // tested pure, but these two show the PRODUCT path running it around a real
    // ProcessContainer — the wrapper really probed, or really could not.

    /// The live leg's workload: prove it RAN (a marker file in the granted
    /// workspace), touch no network at all, exit 0.
    ///
    /// A refusal for a child that failed to start would prove nothing about the
    /// gate, so the marker is each leg's positive control.
    const P24_SILENT_BODY: &str =
        "> p24-ran.txt echo MARK workload=completed-no-network\r\nexit /b 0\r\n";

    /// Write one CRLF batch file into the container's workspace and return the
    /// command line that runs it.
    ///
    /// The P2.2 helper's D-4 prelude is deliberately not reused: this workload
    /// must do *nothing* except print its marker, so it cannot consult the proxy
    /// by accident and turn a gate test into a networking test.
    fn p24_script(dir: &Path, name: &str, body: &str) -> String {
        let path = dir.join(format!("{name}.bat"));
        // CRLF before it reaches cmd.exe, independently of the source file's own
        // line endings (a batch file with bare LF loses its lines).
        let script = body.replace("\r\n", "\n").replace('\n', "\r\n");
        std::fs::write(&path, script.as_bytes())
            .unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
        format!("cmd /c \"{}\"", path.display())
    }

    /// **The S-77/S-86/S-91 shape, live.** A network session whose workload
    /// makes NO request succeeds, because the wrapper's probe reached the
    /// listener: `probes == 1` with `accepted == 0, tunnels == 0`.
    ///
    /// This is the leg that was refused before the amendment, and refusing it is
    /// a product cliff: `sandbox run --allow-domain api.anthropic.com -- echo hi`
    /// failed a user who did nothing wrong.
    #[test]
    #[ignore = "launches a real ProcessContainer; run: cargo test --features mxc-backend --bin sandbox -- --ignored"]
    fn a_launch_whose_workload_makes_no_request_passes_on_the_wrapper_probe() {
        let launcher = launcher_under_test();
        let proxy = LiveProxy::start(&[]);
        let counters = proxy.counters();
        let scratch = Scratch::plain("p24-probe-ok");
        let dir = scratch.path().to_path_buf();
        let backend = supervisor_backend(
            counters.as_ref(),
            Some(proxy.port()),
            Some(proxy.token().value()),
            &launcher,
            SessionBudget::default(),
        )
        .with_budget(SessionBudget::new(
            Duration::from_secs(30),
            Duration::from_secs(80),
            Duration::from_secs(10),
        ));

        println!(
            "EVIDENCE elevated={} launcher={} proxy_port={} expectation=Required sid={}",
            process_is_elevated(),
            launcher.display(),
            proxy.port(),
            proxy.sid
        );
        assert_eq!(
            counters.active_epoch(),
            None,
            "no launch epoch may be open before this one starts"
        );

        let command = p24_script(&dir, "p24-silent", P24_SILENT_BODY);
        println!("EVIDENCE silent_command={command:?}");
        let outcome = backend
            .launch(
                &live_input(proxy.port(), &dir, &launcher, command),
                ProofExpectation::Required,
            )
            .expect(
                "a network session whose wrapper probed MUST pass guardrail 1, even though its \
                 workload never opened a socket",
            );
        println!(
            "EVIDENCE silent_workload exit={:?} success={} proof={:?} tier={:?}",
            outcome.exit_code,
            outcome.success(),
            outcome.proxy_proof,
            outcome.tier.tier
        );

        // ---- 1. the session really ran -------------------------------------
        assert_eq!(outcome.exit_code, Some(0), "{outcome:?}");
        assert!(outcome.success(), "a probed launch is a successful session");
        let ran = std::fs::read_to_string(dir.join("p24-ran.txt")).unwrap_or_default();
        println!("EVIDENCE silent_workload marker={ran:?}");
        assert!(
            ran.contains("MARK workload=completed-no-network"),
            "the workload must have run to completion: {ran:?}"
        );

        // ---- 2. the probe is the evidence, read from the LISTENER ----------
        assert_eq!(
            outcome.proxy_proof.probes, 1,
            "the wrapper's probe must be counted exactly once: {:?}",
            outcome.proxy_proof
        );
        assert_eq!(
            (outcome.proxy_proof.accepted, outcome.proxy_proof.tunnels),
            (0, 0),
            "this workload made no request, so there is no traffic to record: {:?}",
            outcome.proxy_proof
        );
        let epoch1 = counters.counters(1).expect(
            "this launch must have opened epoch 1: an absent epoch reports the same \
                     numbers, so `Some` is the part that means anything",
        );
        println!(
            "EVIDENCE silent_proof epoch=1 counters={epoch1:?} proof={:?} active={:?}",
            counters.proof(1),
            counters.active_epoch()
        );
        assert_eq!(
            epoch1,
            LaunchProofCounters {
                consultations: 0,
                upstream_established: 0,
                probes: 1,
                unauthenticated: 0,
            },
            "a probe is neither a consultation nor an upstream connection"
        );
        assert_eq!(
            counters.active_epoch(),
            None,
            "the launch path must close the epoch it opened"
        );

        // ---- 3. nothing claims a proxy event that never happened -----------
        let leaves = audit_leaves(&proxy.sid);
        println!(
            "EVIDENCE silent_audit leaves={} connect_leaves={}",
            leaves.len(),
            connect_leaves(&proxy.sid)
        );
        assert_eq!(
            connect_leaves(&proxy.sid),
            0,
            "a workload that made no request must leave no CONNECT leaf: {leaves:?}"
        );

        println!(
            "EVIDENCE done: a network session whose workload made no request passed on the \
             wrapper's probe (probes=1, accepted=0, tunnels=0)"
        );
    }

    /// **The refusal, live, with the real mechanism.** The wrapper is pointed at
    /// a port nothing listens on, so its probe never arrives: the session is
    /// refused with `proxy_probe_unmet`, even though the workload exited 0.
    ///
    /// The proof source is a REAL listener (a `LiveProxy`), so the zeros below
    /// are that listener's own epoch, opened for this launch and never probed —
    /// not a fake that cannot count.
    #[test]
    #[ignore = "launches a real ProcessContainer; run: cargo test --features mxc-backend --bin sandbox -- --ignored"]
    fn a_launch_whose_probe_never_arrives_is_refused_with_proxy_probe_unmet() {
        let launcher = launcher_under_test();
        let proxy = LiveProxy::start(&[]);
        let counters = proxy.counters();
        // A port that is nobody's listener: bound, then closed. The wrapper's
        // probe gets a refused connection, which it swallows — the gate, not the
        // wrapper, is what refuses the session.
        let dead_port = {
            let probe_listener = TcpListener::bind("127.0.0.1:0").expect("bind a port to abandon");
            let port = probe_listener
                .local_addr()
                .expect("abandoned address")
                .port();
            drop(probe_listener);
            port
        };
        let scratch = Scratch::plain("p24-probe-dead");
        let dir = scratch.path().to_path_buf();
        let backend = supervisor_backend(
            counters.as_ref(),
            Some(dead_port),
            Some(proxy.token().value()),
            &launcher,
            SessionBudget::default(),
        )
        .with_budget(SessionBudget::new(
            Duration::from_secs(30),
            Duration::from_secs(80),
            Duration::from_secs(10),
        ));

        println!(
            "EVIDENCE elevated={} launcher={} dead_proxy_port={dead_port} live_listener_port={} \
             expectation=Required sid={}",
            process_is_elevated(),
            launcher.display(),
            proxy.port(),
            proxy.sid
        );

        let command = p24_script(&dir, "p24-silent", P24_SILENT_BODY);
        println!("EVIDENCE silent_command={command:?}");
        let err = backend
            .launch(
                &live_input(dead_port, &dir, &launcher, command),
                ProofExpectation::Required,
            )
            .expect_err(
                "a session whose probe never arrived must be REFUSED, never reported successful \
                 on `warnings: []` or on the child's exit code",
            );
        println!("EVIDENCE silent_guard={err}");

        // ---- 1. the refusal names the missing evidence ---------------------
        assert!(
            matches!(err, MxcError::Unproven(ref refused) if refused.error == GuardError::ProbeUnmet),
            "the missing probe must be reported as ProbeUnmet — not as a generic failure, and \
             certainly not as a success: {err:?}"
        );
        assert!(
            err.to_string().contains("proxy_probe_unmet"),
            "the operator-facing refusal must carry the reason token: {err}"
        );
        assert!(
            err.to_string().contains("probe"),
            "the refusal must name the evidence that was missing: {err}"
        );
        assert!(
            matches!(
                std::error::Error::source(&err),
                Some(source) if source.to_string() == err.to_string()
            ),
            "the typed error must be reachable through `source`, so a caller can match on it: \
             {err:?}"
        );

        // ---- 2. the child really ran ---------------------------------------
        let ran = std::fs::read_to_string(dir.join("p24-ran.txt")).unwrap_or_default();
        println!("EVIDENCE silent_workload marker={ran:?}");
        assert!(
            ran.contains("MARK workload=completed-no-network"),
            "the workload must have run to completion, so the refusal is about the missing probe \
             rather than about a child that never started: {ran:?}"
        );

        // ---- 3. the listener's own epoch: opened, empty, closed -------------
        let epoch1 = counters
            .counters(1)
            .expect("this launch must have opened epoch 1 on the live listener");
        println!(
            "EVIDENCE silent_proof epoch=1 counters={epoch1:?} proof={:?} active={:?}",
            counters.proof(1),
            counters.active_epoch()
        );
        assert_eq!(
            epoch1,
            LaunchProofCounters::default(),
            "nothing may have probed or consulted this listener: the wrapper was pointed at a \
             dead port"
        );
        assert_eq!(
            counters.active_epoch(),
            None,
            "the refusal path must close the epoch too (no window left open on an error)"
        );

        // ---- 4. no leaf claims a decision -----------------------------------
        let leaves = audit_leaves(&proxy.sid);
        assert_eq!(
            connect_leaves(&proxy.sid),
            0,
            "the refused launch must leave no CONNECT-shaped leaf: {leaves:?}"
        );

        println!(
            "EVIDENCE done: a launch whose probe never arrived was refused with \
             proxy_probe_unmet, its workload had already exited 0, and nothing claimed a decision"
        );
    }
}
