//! The session-start leaf — the chain root **every run** writes.
//!
//! ## Why this exists in its own module
//!
//! `audit verify` recomputes a Merkle root from the `.ndjson` file and compares
//! it to the committed `.root`, so a session that writes **no** leaf cannot be
//! verified at all. Until P2.3 that was guaranteed by emitting `SESSION_START`
//! first thing in `run_inner` (before the session existed) — which is also the
//! only moment at which the tier/proxy facts ADR-0004 guardrail 2 requires do
//! **not** exist yet. This module resolves the conflict with a guard:
//!
//! * [`SessionStart::arm`] is called as soon as the writer exists, carrying the
//!   facts that are already known then (the backend's tier identity and whether
//!   this supervisor runs elevated). It writes nothing.
//! * [`SessionStart::complete`] adds the one fact only the listener can supply
//!   (`proxy_endpoint`) and writes the leaf, disarming the guard.
//! * [`SessionStart::drop`] writes the **armed** leaf — the tier and elevation it
//!   was armed with, `proxy_endpoint` null — if the run unwound first, so `?` on
//!   `create_session`, the token mint, the learned store or the proxy bind still
//!   leaves exactly one root, and a session that dies early is still selectable by
//!   `tier=…` / `elevated=…`.
//!
//! ## One root per run — and why that is the honest scope
//!
//! The guarantee is **one root per run**, and it is guaranteed *against the
//! child*: the root is written before the child is spawned (`src/main.rs:674`
//! versus `:689`, and on the MXC path `:912` versus its launch at `:916`), so no
//! leaf the child causes can precede it, and every early return between `arm` and
//! `complete` writes it from `Drop`.
//!
//! It is **not** true that the root is always the genesis leaf (`seq: 0`,
//! `parent: null`) of the file. Two cases the earlier wording of this comment
//! missed, both reproduced by the P2.3 reviewers:
//!
//! * The listener is bound *before* the root is written — `src/main.rs:661`
//!   starts the proxy, `:674` writes the leaf — so a local connection that
//!   reaches that listener inside the window is audited by the proxy thread
//!   first, and the run's root then lands at `seq > 0`.
//! * A reused `--sid` opens the *existing* chain (`AuditWriter::open` continues
//!   from `scan_existing`), so a second run legitimately appends a second
//!   `SESSION_START` root at `seq > 0`. `verify` accepts it: the chain still
//!   links, it just carries one root per run.
//!
//! ## The MXC session path writes the root **before** the launch (P3.1, S-55)
//!
//! P3.0 wrote it *after* `launch_session` returned, taking the tier from the
//! launch record. That made S-55 fail on the MXC path: a supervisor
//! `TerminateProcess`ed two seconds into a session left **no log at all**, so
//! `audit show` failed and `verify` had nothing to report INCOMPLETE on — a
//! regression of the guarantee the backend MXC replaces provides. The ordering is
//! now the AppContainer path's, because every one of the five facts is knowable
//! before the child exists:
//!
//! * `tier` / `tier_source` / `tier_needs_dacl_augmentation` — from `probe_tier`
//!   of the **exact** request `launch_session` dispatches
//!   (`request_for_session` builds it through the same `supervisor_backend`);
//! * `proxy_endpoint` — the port `start_session_proxy` has already bound;
//! * `elevated` — this supervisor process's token.
//!
//! So the root is written before the launch, and the launch record is only a
//! **confirmation**: a record that disagrees with what the root already claims is
//! a guardrail-2 violation and refuses the session — the root is never rewritten,
//! and there is still exactly one root per run.
//!
//! What cannot be known before the child runs is guardrail 1's verdict. A
//! `proxy_proof_unmet` refusal therefore appends its `SESSION_REFUSED` leaf to a
//! root that already says `allow`: the session *was* started and then refused,
//! which is what happened, and the refusal leaf says so. The tier-mismatch
//! refusal needs no such concession — it is decided from the same probe that fills
//! the root, before anything is launched, so it is still written as
//! root(`deny`) + `SESSION_REFUSED` and the root is still the first leaf.
//!
//! Two smaller limits, stated rather than papered over:
//!
//! * A run killed with `TerminateProcess`/abort before the root is written —
//!   between `arm` and `complete`, i.e. during the listener bind, the request
//!   build or the probe — skips `Drop` and lands no root at all. That window is
//!   the supervisor's own setup, and keeping the leaf as early as the facts allow
//!   is the whole of what closes it.
//! * A **non-strict** writer swallows a failed write: `AuditWriter::append`
//!   returns `Ok(())` when the file cannot be opened or written, so "one root"
//!   holds *except* when the sink refuses, and then the run proceeds with no root
//!   at all. `--audit-strict` is the fail-closed mode, and choosing it is the
//!   operator's call.
//!
//! ## `tier_source` — three values (d-5.1, ADR-0004)
//!
//! * `probe` / `unavailable` describe the **MXC probe** (`v1::probe` on the exact
//!   request named a tier, or did not).
//! * `structural` (P2.3) says the backend **is** that tier by construction, so
//!   there was nothing to probe. The AppContainer backend is the DACL-appcontainer
//!   tier: it creates the profile and grants the host DACLs itself.
//!
//! A `null` `tier`/`tier_source` is **absence, not a fourth case**: nothing
//! established it. Consumers compare `tier` and read `tier_source` as the
//! explanation of how it is known — never as *no tier*.

use std::fmt;
use std::sync::Arc;

use anyhow::Result;
use serde_json::{json, Map};

use super::AuditWriter;

/// `op` of the leaf every session writes exactly once, as its chain root.
pub const OP_SESSION_START: &str = "SESSION_START";

/// `op` of the leaf that records a guardrail refusal which ended the session.
///
/// Written by [`SessionStart::refuse`], which the MXC session path calls when the
/// launch was refused (P3.0): guardrail 2's tier mismatch refuses *before* the
/// child exists, guardrail 1's unproven launch *after* it ran — both end the
/// session, so both leave the chain readable as root(deny) + this leaf.
///
/// `#[cfg_attr(not(feature = "mxc-backend"), allow(dead_code))]`: the refusal
/// surface is reachable only from that path, so it is genuinely unreachable in a
/// build without the feature — and enumerated as such rather than hidden behind a
/// module-level allow.
#[cfg_attr(not(feature = "mxc-backend"), allow(dead_code))]
pub const OP_SESSION_REFUSED: &str = "SESSION_REFUSED";

/// Tier name of the DACL-appcontainer tier (ADR-0004). The same value the MXC
/// probe reports when policy lowers the request to the AppContainer tier.
pub const TIER_APPCONTAINER_DACL: &str = "appcontainer-dacl";

/// `tier_source` when the backend **is** that tier by construction, so there was
/// nothing to probe. The third value beside `probe` and `unavailable`.
pub const TIER_SOURCE_STRUCTURAL: &str = "structural";

/// Stable `reason` token for a session refused because the tier it dispatched to
/// was not the one it requires (ADR-0004 guardrail 2's hard half).
#[cfg_attr(not(feature = "mxc-backend"), allow(dead_code))]
pub const REASON_TIER_MISMATCH: &str = "tier_mismatch";

/// Stable `reason` token for a session refused because guardrail 1 could not be
/// satisfied (P3.0): the launch ran, but the supervisor's own proxy never proved
/// the child reached it — or, under `--block-net`, reached anything at all.
///
/// Deliberately distinct from [`REASON_TIER_MISMATCH`]: the two refusals have
/// different causes and different remedies (a broken proxy path versus a
/// degraded containment tier), and one filterable token for both would make the
/// chain unusable for exactly the question it is read for.
#[cfg_attr(not(feature = "mxc-backend"), allow(dead_code))]
pub const REASON_PROOF_UNMET: &str = "proxy_proof_unmet";

/// The tier facts of a session, each independently optional.
///
/// `tier` and `tier_source` travel together: naming a tier without saying how it
/// is known is what ADR-0004 forbids (it is how a backend *ceiling* gets recorded
/// as if it were the dispatched tier).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TierFacts {
    /// `base-container` | `appcontainer-dacl` | `None` (unknown).
    pub tier: Option<String>,
    /// `probe` | `unavailable` | `structural` | `None` (unknown).
    pub tier_source: Option<&'static str>,
    /// Verbatim from the probe: `None` when nothing stated it. Never narrowed to
    /// `false`, which would assert something no measurement did.
    pub needs_dacl_augmentation: Option<bool>,
}

impl TierFacts {
    /// The AppContainer backend's tier, **by construction**: this backend creates
    /// the AppContainer profile and grants the host DACLs, so it needs DACL
    /// augmentation by definition and there is no dispatch decision to probe.
    pub fn appcontainer_dacl() -> Self {
        Self {
            tier: Some(TIER_APPCONTAINER_DACL.to_string()),
            tier_source: Some(TIER_SOURCE_STRUCTURAL),
            needs_dacl_augmentation: Some(true),
        }
    }
}

/// A loopback listener authority, `127.0.0.1:<port>` — everything this leaf may
/// say about the proxy.
///
/// A newtype, not a `String` (P2.3 review). `SessionStartFacts`' fields are
/// private and this type's only constructor takes a `u16`, so `proxy_endpoint`
/// cannot be given a URL — and therefore cannot be given the child's
/// `http://sandbox:<token>@127.0.0.1:<port>`, whose userinfo is this run's
/// credential. The earlier claim ("a URL cannot be passed at all") was true only
/// of the helper function: a caller could still write
/// `proxy_endpoint: Some("http://...@...".into())` into a struct whose fields were
/// all public. That literal is now a compile error, and the rendered value for
/// port 49152 is exactly `127.0.0.1:49152`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LoopbackEndpoint(u16);

impl LoopbackEndpoint {
    /// The only way to build one: a port. No scheme, no userinfo, no path.
    pub fn new(port: u16) -> Self {
        Self(port)
    }

    /// The port the listener bound.
    ///
    /// `#[allow(dead_code)]`: the leaf writes the value through `Display`, so only
    /// the tests and a future consumer (P2.2/P3) read it back.
    #[allow(dead_code)]
    pub fn port(self) -> u16 {
        self.0
    }
}

impl fmt::Display for LoopbackEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "127.0.0.1:{}", self.0)
    }
}

/// The leaf carries the bare authority as a JSON string, not a number or object.
impl serde::Serialize for LoopbackEndpoint {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

/// Everything the session-start leaf records beyond `op`/`sid`/`command`.
///
/// The filesystem policy a session was launched with.
///
/// Recorded because the audit could say exactly which *hosts* a session was
/// allowed to reach and nothing about which *paths* it was allowed to touch: a
/// reader asking "did this session really deny `.ssh`?" had no record to consult,
/// and the only answer available was the profile on disk, which is not what the
/// launch used. Under `mxc` these are the very lists the kernel policy was built
/// from (PSEC `fs_read_write`/`fs_read_only`/`fs_deny`), so the leaf states the
/// enforced posture rather than a request.
///
/// What this cannot say is what was *attempted*: the backend reports no denial
/// events, so a refused `CreateFile` leaves no trace anywhere. Grants are
/// auditable; accesses are not.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FilesystemFacts {
    /// The session's working directory, i.e. the root the work happens under.
    pub workspace: Option<String>,
    /// Paths the child may write (`fs_readwrite`).
    pub readwrite: Vec<String>,
    /// Paths the child may read (`fs_read_only`).
    pub readonly: Vec<String>,
    /// Paths explicitly denied; these win over any grant.
    pub deny: Vec<String>,
}

/// Built through a named constructor ([`SessionStartFacts::appcontainer_dacl`],
/// [`SessionStartFacts::measured`]) plus [`SessionStartFacts::with_endpoint`] and
/// [`SessionStartFacts::with_filesystem`] —
/// never field-by-field at the call site, because the fields are private and there
/// is deliberately **no `Default`**: a caller cannot half-fill it, and cannot
/// leave the tier or the elevation unsaid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionStartFacts {
    /// Guardrail 2's per-session tier record.
    tier: TierFacts,
    /// Whether **this supervisor process** ran elevated.
    elevated: Option<bool>,
    /// The listener this run bound, when it bound one: `None` under `--block-net`,
    /// and on the `Drop` path, which never reached the bind.
    proxy_endpoint: Option<LoopbackEndpoint>,
    /// The filesystem policy, when the caller resolved one before arming. `None`
    /// on the AppContainer path, whose DACL grants are computed later in the run
    /// (and on the `Drop` path, which never got that far) — an absent section is
    /// distinguishable from an empty policy, which is a session allowed nothing.
    filesystem: Option<FilesystemFacts>,
}

impl SessionStartFacts {
    /// Facts for the AppContainer backend: the DACL tier by construction, and the
    /// one elevation fact this process can measure.
    pub fn appcontainer_dacl(elevated: bool) -> Self {
        Self::measured(TierFacts::appcontainer_dacl(), Some(elevated))
    }

    /// Facts for a tier that was **measured** rather than known by construction
    /// (the MXC probe), through [`TierFacts`].
    pub fn measured(tier: TierFacts, elevated: Option<bool>) -> Self {
        Self {
            tier,
            elevated,
            proxy_endpoint: None,
            filesystem: None,
        }
    }

    /// Record the resolved filesystem policy (P3.5).
    ///
    /// Called before arming, from the same value the launch uses, so the leaf
    /// cannot describe a policy different from the enforced one. `allow` like the
    /// rest of this builder surface: only the `mxc` path resolves a policy before
    /// arming, and a build without that feature would otherwise warn.
    #[cfg_attr(not(feature = "mxc-backend"), allow(dead_code))]
    pub fn with_filesystem(mut self, filesystem: FilesystemFacts) -> Self {
        self.filesystem = Some(filesystem);
        self
    }

    /// Record the listener this session bound.
    ///
    /// `#[allow(dead_code)]`: production sets the endpoint through
    /// [`SessionStart::complete`], which is the only caller that knows a port; the
    /// builder stays for a caller that has the endpoint before arming (P2.2/P3),
    /// and for the tests.
    #[allow(dead_code)]
    pub fn with_endpoint(mut self, endpoint: LoopbackEndpoint) -> Self {
        self.proxy_endpoint = Some(endpoint);
        self
    }

    /// Guardrail 2's record.
    ///
    /// Read-only accessors below: `write_leaf` reads the fields directly, so these
    /// exist for the tests that pin the leaf and for the wiring that will read a
    /// session's facts back (P2.2/P3) — hence the allow, which enumerates them
    /// rather than hiding a genuinely unused surface.
    #[allow(dead_code)]
    pub fn tier(&self) -> &TierFacts {
        &self.tier
    }

    /// Whether this supervisor ran elevated; `None` when nothing measured it.
    #[allow(dead_code)]
    pub fn elevated(&self) -> Option<bool> {
        self.elevated
    }

    /// The listener this run bound, if any.
    #[allow(dead_code)]
    pub fn proxy_endpoint(&self) -> Option<LoopbackEndpoint> {
        self.proxy_endpoint
    }
}

/// Why a guardrail refused a session.
#[cfg_attr(not(feature = "mxc-backend"), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TierRefusal<'a> {
    /// The tier the session required (e.g. `base-container`).
    pub expected: &'a str,
    /// Stable token for the leaf's `reason` field (filterable).
    pub reason: &'static str,
}

#[cfg_attr(not(feature = "mxc-backend"), allow(dead_code))]
impl<'a> TierRefusal<'a> {
    /// Guardrail 2: the dispatched tier is not the tier this session requires.
    pub fn tier_mismatch(expected: &'a str) -> Self {
        Self {
            expected,
            reason: REASON_TIER_MISMATCH,
        }
    }

    /// Guardrail 1: the launch could not be proven to have reached the proxy.
    ///
    /// `expected` is the tier the session required, not the one observed: this
    /// refusal does not question the tier, and the root it is written beside
    /// already carries the tier the launch dispatched.
    pub fn proof_unmet(expected: &'a str) -> Self {
        Self {
            expected,
            reason: REASON_PROOF_UNMET,
        }
    }

    /// A refusal whose reason is the guard's own cause, not a generic token.
    pub fn refused(reason: &'static str, expected: &'a str) -> Self {
        Self { expected, reason }
    }
}

/// What the root's `disposition` says this run was.
///
/// A type, not a `&str` (P2.3 review): `write_leaf` used to hardcode `allow`, so a
/// refusal's root claimed the session started while the very next leaf said it was
/// refused. A crash between the two writes left exactly that chain and `verify`
/// still passed it — the root is the leaf a reader sees first, and it was lying.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Disposition {
    Allow,
    // Only [`SessionStart::refuse`] produces a deny root, and that is the MXC
    // session path's refusal (P3.0).
    #[cfg_attr(not(feature = "mxc-backend"), allow(dead_code))]
    Deny,
}

impl Disposition {
    fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
        }
    }
}

/// The armed session-start leaf. See the module docs for the state machine.
pub struct SessionStart {
    writer: Arc<AuditWriter>,
    sid: String,
    command: String,
    /// The facts known when the guard was armed. `complete` adds the endpoint and
    /// writes them; `Drop` writes them as armed (endpoint null), so a session that
    /// dies before the listener binds still answers `tier=...` and `elevated=...`.
    facts: SessionStartFacts,
    /// Armed until [`SessionStart::complete`] or [`SessionStart::refuse`] writes
    /// a leaf; `Drop` writes the armed leaf only while this is true.
    armed: bool,
}

impl SessionStart {
    /// Arm the guard with the facts already known. Writes nothing yet.
    ///
    /// `facts` is what the supervisor knows *before* the launch — for the
    /// AppContainer path, the backend's tier identity and this process's token —
    /// and it is the whole of what `Drop` will write.
    pub fn arm(
        writer: Arc<AuditWriter>,
        sid: impl Into<String>,
        command: impl Into<String>,
        facts: SessionStartFacts,
    ) -> Self {
        Self {
            writer,
            sid: sid.into(),
            command: command.into(),
            facts,
            armed: true,
        }
    }

    /// Add the listener fact, write the leaf and disarm.
    ///
    /// Called once the listener is bound and always before the child is spawned —
    /// that ordering is what makes the root a root *for the child*, on both
    /// session paths: the AppContainer path calls it after the proxy bind, and the
    /// MXC path calls it after the proxy bind **and** the tier probe of the exact
    /// request, with the launch still ahead of it (P3.1, S-55).
    ///
    /// Disarms **before** writing: a failed write must not be followed by a
    /// second leaf from `Drop` — in strict mode the error propagates and ends the
    /// session, which is also what the pre-P2.3 code did.
    pub fn complete(mut self, endpoint: Option<LoopbackEndpoint>) -> Result<()> {
        self.armed = false;
        self.facts.proxy_endpoint = endpoint;
        write_leaf(
            &self.writer,
            &self.sid,
            &self.command,
            &self.facts,
            Disposition::Allow,
        )
    }

    /// Record the tier the **probe of the exact request** named, before
    /// [`Self::complete`] or [`Self::refuse`] writes it.
    ///
    /// The MXC path cannot know its tier when it arms: `v1::probe` runs against
    /// the exact request, which does not exist until the listener is bound and the
    /// request is built. So it arms with what it does know (this process's
    /// elevation) and supplies the tier here, from that probe, **before the
    /// launch** (P3.1, S-55) — not from the launch record, which would put the
    /// root after the child.
    ///
    /// A builder rather than a field setter: the facts stay private, so no caller
    /// can half-fill a leaf, and the one value that must never be invented — the
    /// dispatched tier — enters through exactly this door.
    ///
    /// `#[cfg_attr(not(feature = "mxc-backend"), allow(dead_code))]`: the caller
    /// is the MXC session path, which only exists with that feature. Scoping the
    /// allow to the feature-off build keeps rot in the feature-on build visible.
    #[cfg_attr(not(feature = "mxc-backend"), allow(dead_code))]
    pub fn with_tier(mut self, tier: TierFacts) -> Self {
        self.facts.tier = tier;
        self
    }

    /// Write the root, then the refusal leaf that ends the session.
    ///
    /// The root names the tier that was **actually** dispatched, so a degraded
    /// tier stays visible after the fact even though the session was refused
    /// (ADR-0004 guardrail 2), and its `disposition` is already `deny`: the root
    /// is the leaf read first, and it must not say the session started when the
    /// next leaf says it was refused.
    ///
    /// **This is the pre-launch shape only** (P3.1, S-55): the caller refuses
    /// before anything runs — guardrail 2's tier mismatch, decided from the same
    /// probe that fills this root. A refusal decided *after* the launch (guardrail
    /// 1, whose verdict needs the finished child) has a root on disk already and
    /// calls [`append_refusal`] instead; writing the root here would be a second
    /// root for one run.
    #[cfg_attr(not(feature = "mxc-backend"), allow(dead_code))]
    pub fn refuse(
        mut self,
        endpoint: Option<LoopbackEndpoint>,
        refusal: TierRefusal<'_>,
    ) -> Result<()> {
        self.armed = false;
        self.facts.proxy_endpoint = endpoint;
        write_leaf(
            &self.writer,
            &self.sid,
            &self.command,
            &self.facts,
            Disposition::Deny,
        )?;
        append_refusal(&self.writer, &self.sid, refusal)
    }
}

/// Append the leaf that records a guardrail refusal **after** the root exists.
///
/// Split out of [`SessionStart::refuse`] in P3.1 (S-55), when the MXC root moved
/// ahead of the launch. A guardrail-1 refusal is the one verdict only the finished
/// child can produce, so its root is necessarily already on disk — and the
/// guarantee is one root per run, so the refusal records itself without writing a
/// second one. The chain then reads root(allow: the session started) →
/// `SESSION_REFUSED`(deny, with the reason), which is exactly what happened.
///
/// Takes `&AuditWriter` rather than a [`SessionStart`] because the guard is
/// consumed by the root write: after `complete` there is no value left to hold
/// the fallback, which is the point.
#[cfg_attr(not(feature = "mxc-backend"), allow(dead_code))]
pub fn append_refusal(writer: &AuditWriter, sid: &str, refusal: TierRefusal<'_>) -> Result<()> {
    let mut e = Map::new();
    e.insert("op".into(), json!(OP_SESSION_REFUSED));
    e.insert("sid".into(), json!(sid));
    e.insert("disposition".into(), json!("deny"));
    e.insert("reason".into(), json!(refusal.reason));
    e.insert("expected_tier".into(), json!(refusal.expected));
    writer.append(e)
}

impl Drop for SessionStart {
    /// The fallback: the run unwound before the listener bound, so leave the root
    /// rather than none.
    ///
    /// Best-effort by construction (a `Drop` cannot report an error), and honest
    /// by construction: it writes the facts the guard was **armed** with — the
    /// tier the backend was about to dispatch to, and this process's elevation —
    /// with `proxy_endpoint` null, because no endpoint was established. Nothing is
    /// guessed. An early-death session is therefore still selectable by
    /// `tier=appcontainer-dacl` / `elevated=false`, which is exactly the session a
    /// reader wants when a run died in setup.
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let _ = write_leaf(
            &self.writer,
            &self.sid,
            &self.command,
            &self.facts,
            Disposition::Allow,
        );
    }
}

/// The one place the leaf's shape is written, so the four pre-P2.3 keys cannot
/// drift between the full, the fallback and the refused paths.
///
/// `disposition` is a parameter because the three callers do not agree: the
/// success and fallback paths allow, the refusal path denies.
fn write_leaf(
    writer: &AuditWriter,
    sid: &str,
    command: &str,
    facts: &SessionStartFacts,
    disposition: Disposition,
) -> Result<()> {
    let mut e = Map::new();
    // Unchanged since US-4a.
    e.insert("op".into(), json!(OP_SESSION_START));
    e.insert("sid".into(), json!(sid));
    e.insert("command".into(), json!(command));
    e.insert("disposition".into(), json!(disposition.as_str()));
    // P2.3.
    e.insert("tier".into(), json!(facts.tier.tier));
    e.insert("tier_source".into(), json!(facts.tier.tier_source));
    e.insert(
        "tier_needs_dacl_augmentation".into(),
        json!(facts.tier.needs_dacl_augmentation),
    );
    e.insert("elevated".into(), json!(facts.elevated));
    e.insert("proxy_endpoint".into(), json!(facts.proxy_endpoint));
    // P3.5: the enforced filesystem posture, omitted when the caller had none to
    // state. Omitted keys (rather than empty arrays) keep "not recorded" and
    // "allowed nothing" distinguishable in `audit show`.
    if let Some(fs) = &facts.filesystem {
        e.insert("fs_workspace".into(), json!(fs.workspace));
        e.insert("fs_readwrite".into(), json!(fs.readwrite));
        e.insert("fs_readonly".into(), json!(fs.readonly));
        e.insert("fs_deny".into(), json!(fs.deny));
    }
    writer.append(e)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::filter::Filter;
    use serde_json::Value;

    fn fresh_sid(label: &str) -> String {
        format!(
            "test-p23-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        )
    }

    fn log_path(sid: &str) -> std::path::PathBuf {
        crate::audit::audit_log_path(sid)
    }

    fn leaves(sid: &str) -> Vec<Value> {
        std::fs::read_to_string(log_path(sid))
            .unwrap_or_default()
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str(l).expect("each leaf is one JSON object"))
            .collect()
    }

    fn cleanup(sid: &str) {
        let _ = std::fs::remove_file(log_path(sid));
    }

    fn fs_facts() -> FilesystemFacts {
        FilesystemFacts {
            workspace: Some(r"C:\work\repo".to_string()),
            readwrite: vec![r"C:\work\repo".to_string(), r"C:\Users\u\.cache\tool".to_string()],
            readonly: vec![r"C:\Users\u\.gitconfig".to_string()],
            deny: vec![r"C:\Users\u\.ssh".to_string()],
        }
    }

    /// P3.5: the leaf states the filesystem posture that was ENFORCED, so an
    /// operator can answer "was `.ssh` denied in that session?" from the record
    /// instead of from the profile on disk.
    #[test]
    fn the_leaf_records_the_enforced_filesystem_policy() {
        let sid = fresh_sid("fs-facts");
        {
            let writer = Arc::new(AuditWriter::open(&sid, false).unwrap());
            let guard = SessionStart::arm(
                writer,
                &sid,
                "cmd /c echo hi",
                SessionStartFacts::measured(TierFacts::default(), Some(false))
                    .with_filesystem(fs_facts()),
            );
            guard.complete(Some(LoopbackEndpoint::new(41_235))).unwrap();
        }
        let leaves = leaves(&sid);
        cleanup(&sid);

        assert_eq!(leaves.len(), 1, "one leaf: {leaves:?}");
        let leaf = &leaves[0];
        assert_eq!(leaf["fs_workspace"], r"C:\work\repo");
        assert_eq!(
            leaf["fs_readwrite"],
            json!([r"C:\work\repo", r"C:\Users\u\.cache\tool"])
        );
        assert_eq!(leaf["fs_readonly"], json!([r"C:\Users\u\.gitconfig"]));
        assert_eq!(leaf["fs_deny"], json!([r"C:\Users\u\.ssh"]));
        // The pre-existing keys are untouched.
        assert_eq!(leaf["op"], OP_SESSION_START);
        assert_eq!(leaf["tier"], Value::Null);
        assert_eq!(leaf["elevated"], false);
    }

    /// A session that recorded no policy must not claim one: absent keys, not
    /// empty arrays, because "not recorded" and "allowed nothing" differ.
    #[test]
    fn a_session_without_a_filesystem_policy_omits_the_keys() {
        let sid = fresh_sid("fs-none");
        {
            let writer = Arc::new(AuditWriter::open(&sid, false).unwrap());
            let guard = SessionStart::arm(
                writer,
                &sid,
                "cmd /c echo hi",
                SessionStartFacts::appcontainer_dacl(true),
            );
            guard.complete(None).unwrap();
        }
        let leaves = leaves(&sid);
        cleanup(&sid);

        let leaf = &leaves[0];
        for key in ["fs_workspace", "fs_readwrite", "fs_readonly", "fs_deny"] {
            assert!(leaf.get(key).is_none(), "{key} must be absent: {leaf:?}");
        }
    }

    /// Acceptance 1 (P2.3): the AppContainer backend IS the DACL tier, so its
    /// leaf must say so, with all five facts present and the four existing keys
    /// untouched.
    #[test]
    fn the_leaf_carries_the_five_tier_facts_on_the_appcontainer_path() {
        let sid = fresh_sid("ac-facts");
        {
            let writer = Arc::new(AuditWriter::open(&sid, false).unwrap());
            let guard = SessionStart::arm(
                writer,
                &sid,
                "cmd /c echo hi",
                SessionStartFacts::appcontainer_dacl(true),
            );
            guard.complete(Some(LoopbackEndpoint::new(41_234))).unwrap();
        }
        let leaves = leaves(&sid);
        cleanup(&sid);

        assert_eq!(leaves.len(), 1, "one leaf, no fallback: {leaves:?}");
        let leaf = &leaves[0];
        assert_eq!(leaf["op"], OP_SESSION_START);
        assert_eq!(
            leaf["parent"],
            Value::Null,
            "the session-start leaf is the chain root"
        );
        // Unchanged since US-4a.
        assert_eq!(leaf["sid"], sid.as_str());
        assert_eq!(leaf["command"], "cmd /c echo hi");
        assert_eq!(leaf["disposition"], "allow");
        // The five tier facts.
        assert_eq!(leaf["tier"], TIER_APPCONTAINER_DACL);
        assert_eq!(leaf["tier_source"], TIER_SOURCE_STRUCTURAL);
        assert_eq!(leaf["tier_needs_dacl_augmentation"], true);
        assert_eq!(leaf["elevated"], true);
        assert_eq!(leaf["proxy_endpoint"], "127.0.0.1:41234");
    }

    /// P3.0: the MXC path arms **before** it knows the tier (`v1::probe` runs
    /// against the exact request, which the launch decides) and records the
    /// launch's tier before writing. The leaf must carry THAT tier — not the
    /// `null` it was armed with — or a real MXC session loses the
    /// `tier=base-container, tier_source=probe` fact ADR-0004 guardrail 2 is
    /// read for.
    #[test]
    fn the_mxc_leaf_takes_the_tier_the_launch_recorded() {
        let sid = fresh_sid("mxc-tier");
        {
            let writer = Arc::new(AuditWriter::open(&sid, false).unwrap());
            // Armed with what the supervisor knows before the launch: this
            // process's elevation, and no tier (the probe has not run).
            let armed = SessionStart::arm(
                writer,
                &sid,
                "cmd /c echo MXC-WIRED",
                SessionStartFacts::measured(TierFacts::default(), Some(false)),
            );
            assert_eq!(armed.facts.tier.tier, None, "armed before the probe");
            armed
                .with_tier(TierFacts {
                    tier: Some("base-container".to_string()),
                    tier_source: Some("probe"),
                    needs_dacl_augmentation: Some(false),
                })
                .complete(Some(LoopbackEndpoint::new(49_152)))
                .unwrap();
        }
        let leaves = leaves(&sid);
        cleanup(&sid);

        assert_eq!(leaves.len(), 1, "one leaf, no fallback: {leaves:?}");
        let leaf = &leaves[0];
        assert_eq!(leaf["tier"], "base-container");
        assert_eq!(leaf["tier_source"], "probe");
        assert_eq!(leaf["tier_needs_dacl_augmentation"], false);
        assert_eq!(leaf["elevated"], false);
        assert_eq!(leaf["proxy_endpoint"], "127.0.0.1:49152");
        assert_eq!(leaf["disposition"], "allow", "a launched session allowed");
    }

    /// P3.0 decision 5: a session refused by a guardrail is refused **in the
    /// chain** — root(deny) naming the tier that was actually dispatched, then a
    /// `SESSION_REFUSED` leaf carrying the reason. Two leaves, one root.
    #[test]
    fn a_guardrail_refusal_writes_a_deny_root_then_the_refused_leaf() {
        let sid = fresh_sid("mxc-refused");
        {
            let writer = Arc::new(AuditWriter::open(&sid, false).unwrap());
            SessionStart::arm(
                writer,
                &sid,
                "cmd /c echo MXC-WIRED",
                SessionStartFacts::measured(TierFacts::default(), Some(false)),
            )
            .with_tier(TierFacts {
                tier: Some("base-container".to_string()),
                tier_source: Some("probe"),
                needs_dacl_augmentation: Some(false),
            })
            .refuse(
                Some(LoopbackEndpoint::new(49_153)),
                TierRefusal::proof_unmet("base-container"),
            )
            .unwrap();
        }
        let leaves = leaves(&sid);
        cleanup(&sid);

        assert_eq!(leaves.len(), 2, "root + refusal: {leaves:?}");
        let root = &leaves[0];
        assert_eq!(root["op"], OP_SESSION_START);
        assert_eq!(
            root["disposition"], "deny",
            "the root must not claim a start"
        );
        assert_eq!(root["tier"], "base-container");
        assert_eq!(root["tier_source"], "probe");
        assert_eq!(root["proxy_endpoint"], "127.0.0.1:49153");
        let refused = &leaves[1];
        assert_eq!(refused["op"], OP_SESSION_REFUSED);
        assert_eq!(refused["disposition"], "deny");
        assert_eq!(refused["reason"], REASON_PROOF_UNMET);
        assert_eq!(refused["expected_tier"], "base-container");
    }

    /// Acceptance 4 (P2.3) **as amended by its review (item 5)**: a run that dies
    /// in setup — `create_session` failing is the shape of it: the writer is open,
    /// the guard is armed, and `?` unwinds before `complete` — still leaves exactly
    /// one root, and that root still answers the two questions a reader asks of it.
    ///
    /// The tier and the elevation are knowable at arm time (the backend *is* the
    /// tier; elevation is one token query), so writing `null` for both made an
    /// early-death session invisible to `tier=appcontainer-dacl` and
    /// `elevated=false`. Only `proxy_endpoint` is genuinely unknown here.
    #[test]
    fn a_run_that_ends_before_the_listener_binds_still_answers_tier_and_elevated() {
        let sid = fresh_sid("early-error");
        {
            let writer = Arc::new(AuditWriter::open(&sid, false).unwrap());
            let guard = SessionStart::arm(
                writer,
                &sid,
                "cmd /c echo hi",
                SessionStartFacts::appcontainer_dacl(false),
            );
            // The early return: `complete` is never reached.
            drop(guard);
        }
        let leaves = leaves(&sid);
        cleanup(&sid);

        assert_eq!(
            leaves.len(),
            1,
            "the guard must leave exactly one leaf: {leaves:?}"
        );
        let leaf = &leaves[0];
        assert_eq!(leaf["op"], OP_SESSION_START);
        assert_eq!(leaf["parent"], Value::Null);
        // The armed facts survive the early death.
        assert_eq!(leaf["tier"], TIER_APPCONTAINER_DACL);
        assert_eq!(leaf["tier_source"], TIER_SOURCE_STRUCTURAL);
        assert_eq!(leaf["tier_needs_dacl_augmentation"], true);
        assert_eq!(
            leaf["elevated"], false,
            "the measured elevation, not a guess and not null"
        );
        // Only the fact nobody established is null.
        assert_eq!(
            leaf["proxy_endpoint"],
            Value::Null,
            "no listener was bound before the unwind"
        );

        // The reader's queries work on it — this is the leaf item 4 exists for.
        assert!(
            Filter::parse("tier=appcontainer-dacl")
                .unwrap()
                .matches(leaf),
            "an early-death session must answer the degraded-tier query"
        );
        assert!(
            Filter::parse("elevated=false").unwrap().matches(leaf),
            "and the unelevated query"
        );
        assert!(Filter::parse("proxy_endpoint=null").unwrap().matches(leaf));
    }

    /// Acceptance 4 (P2.3): the full leaf disarms the guard, so the success path
    /// cannot end up with two roots.
    #[test]
    fn completing_the_leaf_disarms_the_fallback() {
        let sid = fresh_sid("disarm");
        {
            let writer = Arc::new(AuditWriter::open(&sid, false).unwrap());
            SessionStart::arm(
                writer.clone(),
                &sid,
                "cmd /c echo hi",
                SessionStartFacts::appcontainer_dacl(false),
            )
            .complete(None)
            .unwrap();
            // The writer outlives the guard in `run_inner` (the proxy shares it).
            drop(writer);
        }
        let leaves = leaves(&sid);
        cleanup(&sid);

        let roots = leaves
            .iter()
            .filter(|l| l["op"] == OP_SESSION_START)
            .count();
        assert_eq!(roots, 1, "one root per run: {leaves:?}");
        assert_eq!(leaves[0]["seq"], 0, "the root is seq 0");
        assert_eq!(leaves[0]["parent"], Value::Null);
    }

    /// Acceptance 4/5 (P2.3): `--block-net` starts no listener, so the endpoint is
    /// null — never a placeholder port, never a credential — while the tier facts
    /// are still recorded.
    #[test]
    fn a_blocked_session_records_no_proxy_endpoint() {
        let sid = fresh_sid("block-net");
        {
            let writer = Arc::new(AuditWriter::open(&sid, false).unwrap());
            SessionStart::arm(
                writer,
                &sid,
                "cmd /c echo hi",
                SessionStartFacts::appcontainer_dacl(true),
            )
            .complete(None)
            .unwrap();
        }
        let leaves = leaves(&sid);
        cleanup(&sid);

        assert_eq!(leaves.len(), 1, "{leaves:?}");
        assert_eq!(leaves[0]["proxy_endpoint"], Value::Null);
        assert_eq!(leaves[0]["tier"], TIER_APPCONTAINER_DACL);
        assert_eq!(leaves[0]["tier_source"], TIER_SOURCE_STRUCTURAL);
        assert_eq!(leaves[0]["tier_needs_dacl_augmentation"], true);
    }

    /// Acceptance 5 (P2.3) **as amended by its review (item 3)**: `proxy_endpoint`
    /// is `127.0.0.1:<port>` and nothing else.
    ///
    /// The child's proxy URL carries this run's token as userinfo
    /// (`http://sandbox:<token>@127.0.0.1:<port>`) and that URL must never reach
    /// the chain. The claim is now structural: [`LoopbackEndpoint`] has a private
    /// port and a `u16`-only constructor, and `SessionStartFacts`' fields are
    /// private — so the URL is not merely omitted here, it cannot be written into
    /// the field at all.
    #[test]
    fn the_leaf_carries_no_credential() {
        let token = crate::net::token::RunToken::issue().expect("mint a run token");
        let sid = fresh_sid("no-credential");
        {
            let writer = Arc::new(AuditWriter::open(&sid, false).unwrap());
            SessionStart::arm(
                writer,
                &sid,
                "cmd /c echo hi",
                SessionStartFacts::appcontainer_dacl(true),
            )
            .complete(Some(LoopbackEndpoint::new(49_152)))
            .unwrap();
        }
        let raw = std::fs::read_to_string(log_path(&sid)).unwrap();
        cleanup(&sid);

        assert!(
            !raw.contains('@'),
            "no userinfo separator anywhere in the leaf: {raw}"
        );
        assert!(!raw.contains("sandbox:"), "no proxy userinfo prefix: {raw}");
        assert!(
            !raw.contains(token.value()),
            "this run's token must not be in the chain: {raw}"
        );
        assert!(
            raw.contains(r#""proxy_endpoint":"127.0.0.1:49152""#),
            "the endpoint is the bare loopback authority: {raw}"
        );
    }

    /// P2.3 review (item 3): the endpoint renders as exactly the bare loopback
    /// authority, and it travels to the leaf as a JSON string (not a number, not
    /// an object).
    #[test]
    fn the_endpoint_renders_as_the_bare_loopback_authority() {
        let endpoint = LoopbackEndpoint::new(49_152);
        assert_eq!(endpoint.to_string(), "127.0.0.1:49152");
        assert_eq!(endpoint.port(), 49_152);
        assert_eq!(json!(endpoint), json!("127.0.0.1:49152"));
        assert_eq!(json!(Some(endpoint)), json!("127.0.0.1:49152"));
        assert_eq!(json!(Option::<LoopbackEndpoint>::None), Value::Null);

        let facts = SessionStartFacts::appcontainer_dacl(true).with_endpoint(endpoint);
        assert_eq!(facts.proxy_endpoint(), Some(endpoint));
        assert_eq!(
            SessionStartFacts::appcontainer_dacl(true).proxy_endpoint(),
            None,
            "no listener stated means no endpoint, not a placeholder"
        );
    }

    /// Acceptance 3 (P2.3), audit half: a session refused by guardrail 2 is a root
    /// naming the tier it actually got **and already saying `deny`**, followed by
    /// one refusal leaf — and no CONNECT leaf. That no CONNECT can follow is proven
    /// against a live listener in `net::mxc`'s
    /// `a_wrong_tier_refuses_the_session_with_no_connect_leaves`.
    #[test]
    fn a_refused_session_is_audited_after_its_root() {
        let sid = fresh_sid("refused");
        let observed = TierFacts {
            tier: Some(TIER_APPCONTAINER_DACL.to_string()),
            tier_source: Some("probe"),
            needs_dacl_augmentation: Some(true),
        };
        {
            let writer = Arc::new(AuditWriter::open(&sid, false).unwrap());
            let facts = SessionStartFacts::measured(observed, Some(true));
            SessionStart::arm(writer, &sid, "cmd /c echo hi", facts)
                .refuse(
                    Some(LoopbackEndpoint::new(41_000)),
                    TierRefusal::tier_mismatch("base-container"),
                )
                .unwrap();
        }
        let leaves = leaves(&sid);
        cleanup(&sid);

        assert_eq!(leaves.len(), 2, "root + refusal: {leaves:?}");
        assert_eq!(leaves[0]["op"], OP_SESSION_START);
        assert_eq!(leaves[0]["parent"], Value::Null);
        // P2.3 review (item 2): the root cannot claim the session started when the
        // next leaf says it was refused — a crash between the two writes would
        // leave exactly that, and `verify` would still pass.
        assert_eq!(
            leaves[0]["disposition"], "deny",
            "the refusal's root must already say deny: {leaves:?}"
        );
        assert_eq!(
            leaves[0]["tier"], TIER_APPCONTAINER_DACL,
            "the degraded tier must stay visible after the fact"
        );
        assert_eq!(leaves[1]["op"], OP_SESSION_REFUSED);
        assert_eq!(leaves[1]["disposition"], "deny");
        assert_eq!(leaves[1]["reason"], REASON_TIER_MISMATCH);
        assert_eq!(leaves[1]["expected_tier"], "base-container");
        assert_eq!(
            leaves[1]["parent"], leaves[0]["hash"],
            "the refusal links to the root"
        );
        assert!(
            leaves.iter().all(|l| l["op"] != "CONNECT"),
            "a refused session has no CONNECT leaf: {leaves:?}"
        );
    }
}
