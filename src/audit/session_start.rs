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
//! child*: the root is written before the child is spawned (`src/main.rs:748`
//! versus `:767`), so no leaf the child causes can precede it, and every early
//! return between `arm` and `complete` writes it from `Drop`.
//!
//! It is **not** true that the root is always the genesis leaf (`seq: 0`,
//! `parent: null`) of the file. Two cases the earlier wording of this comment
//! missed, both reproduced by the P2.3 reviewers:
//!
//! * The listener is bound *before* the root is written — `src/main.rs:717`
//!   starts the proxy, `:748` writes the leaf — so a local connection that
//!   reaches that listener inside the window is audited by the proxy thread
//!   first, and the run's root then lands at `seq > 0`.
//! * A reused `--sid` opens the *existing* chain (`AuditWriter::open` continues
//!   from `scan_existing`), so a second run legitimately appends a second
//!   `SESSION_START` root at `seq > 0`. `verify` accepts it: the chain still
//!   links, it just carries one root per run.
//!
//! Two smaller limits, stated rather than papered over:
//!
//! * A run killed with `TerminateProcess`/abort skips `Drop` and lands no root at
//!   all — the one path the guard cannot cover, and the reason the window between
//!   `arm` and `complete` is kept to the supervisor's own setup.
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

/// `op` of the leaf that records a guardrail refusal which ended the session
/// before any child existed.
///
/// `#[allow(dead_code)]` until the MXC session path is wired
/// (`MXC_SESSION_WIRED = false`, P2.2/P3): [`SessionStart::refuse`] is the only
/// writer and nothing in the binary calls it yet. A wiring gap, not rot — the
/// tests and the future caller exercise the same code, and the precedent is
/// `net::mxc`, whose module-level allow enumerates its own unreachable surface.
#[allow(dead_code)]
pub const OP_SESSION_REFUSED: &str = "SESSION_REFUSED";

/// Tier name of the DACL-appcontainer tier (ADR-0004). The same value the MXC
/// probe reports when policy lowers the request to the AppContainer tier.
pub const TIER_APPCONTAINER_DACL: &str = "appcontainer-dacl";

/// `tier_source` when the backend **is** that tier by construction, so there was
/// nothing to probe. The third value beside `probe` and `unavailable`.
pub const TIER_SOURCE_STRUCTURAL: &str = "structural";

/// Stable `reason` token for a session refused because the tier it dispatched to
/// was not the one it requires (ADR-0004 guardrail 2's hard half).
///
/// `#[allow(dead_code)]`: see [`OP_SESSION_REFUSED`].
#[allow(dead_code)]
pub const REASON_TIER_MISMATCH: &str = "tier_mismatch";

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
/// Built through a named constructor ([`SessionStartFacts::appcontainer_dacl`],
/// [`SessionStartFacts::measured`]) plus [`SessionStartFacts::with_endpoint`] —
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
        }
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

/// Why a guardrail refused a session before any child ran.
///
/// `#[allow(dead_code)]`: see [`OP_SESSION_REFUSED`].
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TierRefusal<'a> {
    /// The tier the session required (e.g. `base-container`).
    pub expected: &'a str,
    /// Stable token for the leaf's `reason` field (filterable).
    pub reason: &'static str,
}

#[allow(dead_code)]
impl<'a> TierRefusal<'a> {
    /// Guardrail 2: the dispatched tier is not the tier this session requires.
    pub fn tier_mismatch(expected: &'a str) -> Self {
        Self {
            expected,
            reason: REASON_TIER_MISMATCH,
        }
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
    /// that ordering is what makes the root a root *for the child*.
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

    /// Write the root, then the refusal leaf that ends the session.
    ///
    /// The root names the tier that was **actually** dispatched, so a degraded
    /// tier stays visible after the fact even though the session was refused
    /// (ADR-0004 guardrail 2), and its `disposition` is already `deny`: the root
    /// is the leaf read first, and it must not say the session started when the
    /// next leaf says it was refused.
    ///
    /// `#[allow(dead_code)]`: see [`OP_SESSION_REFUSED`].
    #[allow(dead_code)]
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
        let mut e = Map::new();
        e.insert("op".into(), json!(OP_SESSION_REFUSED));
        e.insert("sid".into(), json!(&self.sid));
        e.insert("disposition".into(), json!("deny"));
        e.insert("reason".into(), json!(refusal.reason));
        e.insert("expected_tier".into(), json!(refusal.expected));
        self.writer.append(e)
    }
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
