//! `saife audit verify <sid>`
//!
//! Recompute the Merkle root from the .ndjson file, compare to the committed
//! .root, check the Ed25519 signature on .sig. Prints OK / TAMPERED /
//! BAD_SIGNATURE / INCOMPLETE and exits 0/1 accordingly.

use anyhow::Result;
use serde_json::Value;

use super::{audit_log_path, canonicalize, normalize_session_id, sha256_hex};
use crate::signing;

pub fn run_verify(session_id: &str) -> i32 {
    match verify_inner(session_id) {
        Ok(VerifyOutcome::Ok) => {
            println!("OK");
            0
        }
        Ok(VerifyOutcome::Incomplete(reason)) => {
            println!("INCOMPLETE: {reason}");
            1
        }
        Ok(VerifyOutcome::Tampered(reason)) => {
            println!("TAMPERED: {reason}");
            1
        }
        Ok(VerifyOutcome::BadSignature(reason)) => {
            println!("BAD_SIGNATURE: {reason}");
            1
        }
        Ok(VerifyOutcome::KeyMissing(reason)) => {
            println!("KEY_MISSING: {reason}");
            1
        }
        Ok(VerifyOutcome::KeyChanged(reason)) => {
            println!("KEY_CHANGED: {reason}");
            1
        }
        Err(e) => {
            eprintln!("[saife] audit verify: {e:#}");
            1
        }
    }
}

/// `pub(crate)`, not private (P3.1, S-55): the crash test lives beside the
/// mechanism it protects (the root that is written before the launch) and has to
/// assert the *verdict* `verify` reaches, not a copy of it. The CLI entry point
/// stays [`run_verify`].
///
/// `KeyMissing` is its own verdict (M6): verifying must never mint a key, so a
/// missing key is reported distinctly rather than collapsed into `BadSignature`
/// - and must not be reported as `Tampered`, which would blame the operator.
///
/// `KeyChanged` (M7) is the rotation-vs-tamper verdict: the committed root
/// records the fingerprint of the key that signed it, and a mismatch with the
/// current key cannot be checked with the current key. Without a trust store
/// a per-session fingerprint cannot distinguish a legitimate rotation from a
/// substituted signature, so the verdict says so rather than inventing a weak
/// signal or calling a different key a forgery.
#[derive(Debug)]
pub(crate) enum VerifyOutcome {
    Ok,
    Incomplete(String),
    Tampered(String),
    BadSignature(String),
    KeyMissing(String),
    KeyChanged(String),
}

pub(crate) fn verify_inner(session_id: &str) -> Result<VerifyOutcome> {
    // H4: validate before any file is opened. `audit_log_path` joins the raw id,
    // so a traversal/absolute/UNC sid reached an attacker-chosen file. The UNC
    // case has no file to find, so without this guard it reported a missing-file
    // error instead of the session-id refusal - which is why the test asserts the
    // word "session".
    let session_id = normalize_session_id(session_id)?;
    verify_with_key_source(&session_id, signing::KeyMaterial::load_existing)
}

/// Verify with an injected key loader (M6). The production path loads the
/// existing key (never minting); tests inject a temp path so the "missing key"
/// verdict and the "no file created" guarantee are provable without touching the
/// user's real key.
fn verify_with_key_source(
    session_id: &str,
    load_key: impl FnOnce() -> Result<signing::KeyMaterial>,
) -> Result<VerifyOutcome> {
    let log_path = audit_log_path(session_id);
    if !log_path.exists() {
        return Ok(VerifyOutcome::Incomplete(format!("no audit log at {}", log_path.display())));
    }
    let content = std::fs::read_to_string(&log_path)?;

    let mut prev_hash: Option<String> = None;
    let mut computed_root: Option<String> = None;
    let mut leaf_count: usize = 0;
    let total_lines = content.lines().count();
    // A crash mid-append leaves a partial last line with no terminator. That is
    // INCOMPLETE evidence, not tampering: calling it tampered teaches the operator
    // to ignore the verdict that matters.
    let torn_tail = !content.ends_with('\n');

    for (i, line) in content.lines().enumerate() {
        if line.trim().is_empty() { continue; }
        leaf_count += 1;
        let leaf: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(e) if torn_tail && i + 1 == total_lines => {
                return Ok(VerifyOutcome::Incomplete(format!(
                    "leaf {i}: last line is truncated ({e}) - the session was killed mid-write"
                )));
            }
            Err(e) => return Ok(VerifyOutcome::Tampered(
                format!("leaf {i}: invalid JSON ({e})")
            )),
        };
        let obj = match leaf.as_object() {
            Some(o) => o,
            None => return Ok(VerifyOutcome::Tampered(
                format!("leaf {i}: not a JSON object")
            )),
        };

        // The log must belong to the session it is filed under, and its sequence
        // numbers must be the line order. Both were unchecked, so copying a clean
        // session's .ndjson/.root/.sig over another session's names verified OK -
        // a substitution that needs no key at all.
        //
        // L-H: `sid` and `seq` are required on every leaf, not checked only when
        // present. Stripping them (and recomputing the hash) used to verify OK.
        // L-F: the compare is case-insensitive, so a legacy log whose leaf carries
        // a mixed-case id still verifies after intake lowercased the lookup.
        let leaf_sid = match obj.get("sid").and_then(|x| x.as_str()) {
            Some(s) => s,
            None => {
                return Ok(VerifyOutcome::Tampered(format!(
                    "leaf {i}: missing or non-string `sid` field"
                )));
            }
        };
        if !leaf_sid.eq_ignore_ascii_case(session_id) {
            return Ok(VerifyOutcome::Tampered(format!(
                "leaf {i}: belongs to session {leaf_sid}, not {session_id}"
            )));
        }
        let seq = match obj.get("seq").and_then(|x| x.as_u64()) {
            Some(s) => s,
            None => {
                return Ok(VerifyOutcome::Tampered(format!(
                    "leaf {i}: missing or non-numeric `seq` field"
                )));
            }
        };
        if seq != leaf_count as u64 - 1 {
            return Ok(VerifyOutcome::Tampered(format!(
                "leaf {i}: seq {seq} does not match its position in the log"
            )));
        }

        let stored_hash = match obj.get("hash").and_then(|x| x.as_str()) {
            Some(h) => h.to_string(),
            None => return Ok(VerifyOutcome::Tampered(
                format!("leaf {i}: missing `hash` field")
            )),
        };

        // Recompute the hash from the canonical body (minus hash+parent).
        let canonical = canonicalize(obj);
        let recomputed = sha256_hex(&canonical);
        if recomputed != stored_hash {
            return Ok(VerifyOutcome::Tampered(format!(
                "leaf {i}: hash mismatch (expected {stored_hash}, computed {recomputed})"
            )));
        }

        // Check parent linkage.
        let stored_parent = obj.get("parent");
        match (&prev_hash, stored_parent) {
            (None, Some(Value::Null)) | (None, None) => {} // genesis: parent null/absent
            (Some(p), Some(Value::String(sp))) if p == sp => {} // link ok
            (Some(_), Some(other)) => return Ok(VerifyOutcome::Tampered(format!(
                "leaf {i}: parent mismatch (expected {prev_hash:?}, got {other})"
            ))),
            (Some(p), None) => return Ok(VerifyOutcome::Tampered(format!(
                "leaf {i}: parent missing (expected {p})"
            ))),
            (None, Some(_)) => return Ok(VerifyOutcome::Tampered(format!(
                "leaf {i}: first leaf has non-null parent"
            ))),
        }

        prev_hash = Some(stored_hash.clone());
        computed_root = Some(stored_hash);
    }

    if leaf_count == 0 {
        return Ok(VerifyOutcome::Incomplete("no events in log".to_string()));
    }

    // Compare to committed root.
    let root_path = log_path.with_extension("root");
    let sig_path = log_path.with_extension("sig");
    let committed_root = match std::fs::read_to_string(&root_path) {
        Ok(s) => s,
        Err(_) => return Ok(VerifyOutcome::Incomplete(
            format!("no committed root (session did not end cleanly); {} events present", leaf_count)
        )),
    };
    let committed_root = committed_root.trim().to_string();
    let computed = computed_root.unwrap();

    // H5b: a root that is not a well-formed 32-byte hex value is not an edit -
    // it is a half-written `fs::write` the kill interrupted (the commit now
    // writes atomically, but an old run or an external actor can still leave a
    // torn file). Calling it TAMPERED blames the operator for a crash; an
    // interrupted commit is honest INCOMPLETE.
    //
    // Checked by character class, not `decode_hex`: `decode_hex` byte-slices a
    // `&str` (the L-G shape), so a 64-*byte* non-ASCII root would panic instead
    // of reporting a verdict.
    if committed_root.len() != 64 || !committed_root.chars().all(|c| c.is_ascii_hexdigit()) {
        return Ok(VerifyOutcome::Incomplete(format!(
            "committed root is not a complete 32-byte hash (got {} chars); \
             the commit was interrupted - {} events present",
            committed_root.len(),
            leaf_count
        )));
    }
    if committed_root != computed {
        return Ok(VerifyOutcome::Tampered(format!(
            "root mismatch (committed {committed_root}, computed {computed})"
        )));
    }

    // Verify the signature.
    //
    // H5b: a missing signature alongside a present root is the other half of an
    // interrupted commit. The new writer publishes the signature first, so this
    // state cannot be produced by it, but the ordering's job is exactly to make
    // every half-committed pair read as INCOMPLETE rather than BAD_SIGNATURE - so
    // the operator is never told a crash was a forgery.
    let sig_hex = match std::fs::read_to_string(&sig_path) {
        Ok(s) => s.trim().to_string(),
        Err(_) => {
            return Ok(VerifyOutcome::Incomplete(format!(
                "committed root has no signature - the commit was interrupted, or the \
                 signature was removed; {} events present",
                leaf_count
            )));
        }
    };

    // M6: load, never mint. `ensure()` here meant a missing key both reported
    // `BAD_SIGNATURE` for every old session (indistinguishable from tampering)
    // and installed a fresh trust anchor as a side effect of verifying.
    let key = match load_key() {
        Ok(k) => k,
        Err(e) => return Ok(VerifyOutcome::KeyMissing(format!("{e:#}"))),
    };

    // M7: the commit records the fingerprint of the key that signed this
    // session (`<sid>.keyfp`). A mismatch means the current key cannot check
    // this signature - rotation, another host, or a substitution - and saying
    // BAD_SIGNATURE would call the operator's own history a forgery. A
    // per-session fingerprint without a trust store cannot tell rotation from
    // tampering, so the verdict names both possibilities; re-verify on the
    // signing host to settle it. Absent file = a session committed before
    // fingerprints existed: no signal, check the signature as before.
    let current_fp = key.fingerprint();
    if let Ok(recorded) = std::fs::read_to_string(log_path.with_extension("keyfp")) {
        let recorded = recorded.trim();
        if !recorded.is_empty() && !recorded.eq_ignore_ascii_case(&current_fp) {
            return Ok(VerifyOutcome::KeyChanged(format!(
                "recorded signing key {recorded} differs from the current key {current_fp}; \
                 the signature cannot be checked with the current key. This is either key \
                 rotation (or a session signed on another machine/user) or a substituted \
                 signature - a per-session fingerprint cannot tell them apart without a \
                 trust store; re-verify on the host that signed this session"
            )));
        }
    }

    let sig_bytes = match decode_hex(&sig_hex) {
        Some(b) => b,
        None => return Ok(VerifyOutcome::BadSignature("signature is not valid hex".to_string())),
    };
    let root_bytes = match decode_hex(&computed) {
        Some(b) => b,
        None => return Ok(VerifyOutcome::BadSignature("computed root is not valid hex".to_string())),
    };

    if !signing::verify_with_secret(&key.signing, &root_bytes, &sig_bytes) {
        return Ok(VerifyOutcome::BadSignature("signature does not verify".to_string()));
    }

    Ok(VerifyOutcome::Ok)
}

/// Hex-decode by bytes (L-G). The previous version byte-sliced a `&str`, so an
/// even-length non-ASCII input ("a€": 4 bytes) sliced inside a char boundary
/// and panicked (exit 101) instead of producing a verdict. Byte-wise nibble
/// parsing returns `None` for any non-hex byte, ASCII or not.
fn decode_hex(s: &str) -> Option<Vec<u8>> {
    let bytes = s.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    bytes
        .chunks(2)
        .map(|pair| {
            let hi = (pair[0] as char).to_digit(16)?;
            let lo = (pair[1] as char).to_digit(16)?;
            Some((hi * 16 + lo) as u8)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use serde_json::{json, Map};
    use crate::audit::{AuditWriter, audit_log_path};

    fn fresh_sid(label: &str) -> String {
        format!("test-verify-{label}-{}-{}", std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos())
    }

    fn cleanup(sid: &str) {
        let p = audit_log_path(sid);
        let _ = std::fs::remove_file(&p);
        let _ = std::fs::remove_file(p.with_extension("root"));
        let _ = std::fs::remove_file(p.with_extension("sig"));
        let _ = std::fs::remove_file(p.with_extension("keyfp"));
    }

    #[test]
    fn verify_missing_log_is_incomplete() {
        let sid = fresh_sid("missing");
        let outcome = verify_inner(&sid).unwrap();
        assert!(matches!(outcome, VerifyOutcome::Incomplete(_)));
    }

    #[test]
    fn verify_log_without_root_is_incomplete() {
        let sid = fresh_sid("no-root");
        {
            let w = AuditWriter::open(&sid, false).unwrap();
            let mut e = Map::new();
            e.insert("op".into(), json!("CONNECT"));
            e.insert("host".into(), json!("a.com"));
            w.append(e).unwrap();
        }
        let outcome = verify_inner(&sid).unwrap();
        cleanup(&sid);
        assert!(matches!(outcome, VerifyOutcome::Incomplete(_)));
    }

    #[test]
    fn verify_clean_session_is_ok() {
        let sid = fresh_sid("clean");
        let root;
        {
            let w = AuditWriter::open(&sid, false).unwrap();
            for host in ["a.com", "b.com", "c.com"] {
                let mut e = Map::new();
                e.insert("op".into(), json!("CONNECT"));
                e.insert("host".into(), json!(host));
                w.append(e).unwrap();
            }
            root = w.current_root().unwrap();
        }
        // Sign + write root + sig, mimicking what run_inner does on clean exit.
        let key = signing::KeyMaterial::ensure().unwrap();
        let root_bytes = decode_hex(&root).unwrap();
        let sig = key.sign_root(&root_bytes);
        std::fs::write(audit_log_path(&sid).with_extension("root"), &root).unwrap();
        let sig_hex: String = sig.iter().map(|b| format!("{:02x}", b)).collect();
        std::fs::write(audit_log_path(&sid).with_extension("sig"), &sig_hex).unwrap();

        let outcome = verify_inner(&sid).unwrap();
        cleanup(&sid);
        assert!(matches!(outcome, VerifyOutcome::Ok), "got {:?}", outcome);
    }

    /// P2.3 acceptance 2: the extended session-start leaf is the chain root and
    /// `verify` still validates the whole chain around it — root, leaves, parent
    /// links and the signed root.
    ///
    /// This is the regression that matters for the D-5 extension: the five new
    /// keys go through the same `canonicalize`/`sha256` path as every other field
    /// (field-agnostic since US-4, [G-31]), so adding them must not need a hash or
    /// ordering change — and must not break the root that a session which never
    /// reaches the proxy depends on.
    #[test]
    fn verify_accepts_an_extended_session_start_root() {
        use crate::audit::session_start::{
            LoopbackEndpoint, SessionStart, SessionStartFacts, TIER_APPCONTAINER_DACL,
            TIER_SOURCE_STRUCTURAL,
        };

        let sid = fresh_sid("p23-root");
        let root;
        {
            let writer = std::sync::Arc::new(AuditWriter::open(&sid, false).unwrap());
            SessionStart::arm(
                writer.clone(),
                &sid,
                "cmd /c echo hi",
                SessionStartFacts::appcontainer_dacl(true),
            )
            .complete(Some(LoopbackEndpoint::new(41_234)))
            .unwrap();
            // A networked session appends CONNECT leaves behind that root.
            for host in ["api.anthropic.com", "evil.example.com"] {
                let mut e = Map::new();
                e.insert("op".into(), json!("CONNECT"));
                e.insert("host".into(), json!(host));
                writer.append(e).unwrap();
            }
            root = writer.current_root().unwrap();
        }

        // The root itself carries the facts (a chain that verifies without them
        // would be a leaf that silently lost ADR-0004 guardrail 2's record).
        let content = std::fs::read_to_string(audit_log_path(&sid)).unwrap();
        let first: serde_json::Value =
            serde_json::from_str(content.lines().next().unwrap()).unwrap();
        assert_eq!(first["op"], "SESSION_START");
        assert_eq!(first["seq"], 0);
        assert_eq!(first["parent"], serde_json::Value::Null);
        assert_eq!(first["tier"], TIER_APPCONTAINER_DACL);
        assert_eq!(first["tier_source"], TIER_SOURCE_STRUCTURAL);
        assert_eq!(first["tier_needs_dacl_augmentation"], true);
        assert_eq!(first["elevated"], true);
        assert_eq!(first["proxy_endpoint"], "127.0.0.1:41234");

        // Sign + write root + sig, mimicking what run_inner does on clean exit.
        let key = signing::KeyMaterial::ensure().unwrap();
        let root_bytes = decode_hex(&root).unwrap();
        let sig = key.sign_root(&root_bytes);
        std::fs::write(audit_log_path(&sid).with_extension("root"), &root).unwrap();
        let sig_hex: String = sig.iter().map(|b| format!("{:02x}", b)).collect();
        std::fs::write(audit_log_path(&sid).with_extension("sig"), &sig_hex).unwrap();

        let outcome = verify_inner(&sid).unwrap();
        cleanup(&sid);
        assert!(matches!(outcome, VerifyOutcome::Ok), "got {:?}", outcome);
    }

    #[test]
    fn verify_tampered_leaf_is_tampered() {
        let sid = fresh_sid("tampered");
        let root;
        {
            let w = AuditWriter::open(&sid, false).unwrap();
            let mut e = Map::new();
            e.insert("op".into(), json!("CONNECT"));
            e.insert("host".into(), json!("a.com"));
            w.append(e).unwrap();
            let mut e2 = Map::new();
            e2.insert("op".into(), json!("CONNECT"));
            e2.insert("host".into(), json!("b.com"));
            w.append(e2).unwrap();
            root = w.current_root().unwrap();
        }
        let key = signing::KeyMaterial::ensure().unwrap();
        let root_bytes = decode_hex(&root).unwrap();
        let sig = key.sign_root(&root_bytes);
        std::fs::write(audit_log_path(&sid).with_extension("root"), &root).unwrap();
        let sig_hex: String = sig.iter().map(|b| format!("{:02x}", b)).collect();
        std::fs::write(audit_log_path(&sid).with_extension("sig"), &sig_hex).unwrap();

        // Tamper: flip a byte in the second leaf's host field.
        let path = audit_log_path(&sid);
        let mut content = std::fs::read_to_string(&path).unwrap();
        content = content.replace("b.com", "B.com"); // case-flip
        std::fs::write(&path, &content).unwrap();

        let outcome = verify_inner(&sid).unwrap();
        cleanup(&sid);
        assert!(matches!(outcome, VerifyOutcome::Tampered(_)), "got {:?}", outcome);
    }

    #[test]
    fn verify_forged_root_is_bad_signature() {
        let sid = fresh_sid("forged");
        let root;
        {
            let w = AuditWriter::open(&sid, false).unwrap();
            let mut e = Map::new();
            e.insert("op".into(), json!("CONNECT"));
            e.insert("host".into(), json!("a.com"));
            w.append(e).unwrap();
            root = w.current_root().unwrap();
        }
        // Write the real root + a corrupted signature (flip a byte).
        let key = signing::KeyMaterial::ensure().unwrap();
        let root_bytes = decode_hex(&root).unwrap();
        let mut sig = key.sign_root(&root_bytes);
        sig[0] ^= 0xff;
        std::fs::write(audit_log_path(&sid).with_extension("root"), &root).unwrap();
        let sig_hex: String = sig.iter().map(|b| format!("{:02x}", b)).collect();
        std::fs::write(audit_log_path(&sid).with_extension("sig"), &sig_hex).unwrap();

        let outcome = verify_inner(&sid).unwrap();
        cleanup(&sid);
        assert!(matches!(outcome, VerifyOutcome::BadSignature(_)), "got {:?}", outcome);
    }

    /// Substitution, the attack that needs no key: copy a clean session's log over
    /// another session's file name. Leaves now carry the session id, so the copy is
    /// reported as tampered instead of verified.
    #[test]
    fn a_log_copied_from_another_session_is_tampered() {
        let a = fresh_sid("copy-from");
        let b = fresh_sid("copy-to");
        {
            let w = AuditWriter::open(&a, false).unwrap();
            let mut e = Map::new();
            e.insert("op".into(), json!("CONNECT"));
            e.insert("host".into(), json!("example.com"));
            w.append(e).unwrap();
        }
        std::fs::copy(audit_log_path(&a), audit_log_path(&b)).unwrap();

        match verify_inner(&b).unwrap() {
            VerifyOutcome::Tampered(m) => assert!(
                m.contains("belongs to session"),
                "the verdict must name the mismatch: {m}"
            ),
            other => panic!("a copied log must not verify: {other:?}"),
        }
        cleanup(&a);
        cleanup(&b);
    }

    /// Sequence numbers are the line order. Deleting a middle leaf used to be caught
    /// by the parent link; this pins the other half, so a log that has been rewritten
    /// with consistent parents but wrong ordering is still refused.
    #[test]
    fn a_leaf_with_the_wrong_seq_is_tampered() {
        let sid = fresh_sid("seq");
        {
            let w = AuditWriter::open(&sid, false).unwrap();
            for host in ["a.example", "b.example", "c.example"] {
                let mut e = Map::new();
                e.insert("op".into(), json!("CONNECT"));
                e.insert("host".into(), json!(host));
                w.append(e).unwrap();
            }
        }
        let path = audit_log_path(&sid);
        let text = std::fs::read_to_string(&path).unwrap();
        let mut lines: Vec<&str> = text.lines().collect();
        lines.remove(1); // drop the middle leaf, leaving a seq gap
        std::fs::write(&path, format!("{}\n", lines.join("\n"))).unwrap();

        match verify_inner(&sid).unwrap() {
            VerifyOutcome::Tampered(m) => assert!(
                m.contains("seq") || m.contains("parent"),
                "a gap must be reported as tampering: {m}"
            ),
            other => panic!("a log missing a leaf must not verify: {other:?}"),
        }
        cleanup(&sid);
    }

    /// A kill mid-write leaves a partial last line. That is an incomplete session,
    /// not an edited one - the distinction the operator acts on.
    #[test]
    fn a_torn_last_line_is_incomplete_not_tampered() {
        let sid = fresh_sid("torn");
        {
            let w = AuditWriter::open(&sid, false).unwrap();
            let mut e = Map::new();
            e.insert("op".into(), json!("CONNECT"));
            e.insert("host".into(), json!("example.com"));
            w.append(e).unwrap();
        }
        let path = audit_log_path(&sid);
        let mut text = std::fs::read_to_string(&path).unwrap();
        text.push_str("{\"op\":\"CONNE"); // no trailing newline
        std::fs::write(&path, text).unwrap();

        match verify_inner(&sid).unwrap() {
            VerifyOutcome::Incomplete(m) => assert!(
                m.contains("truncated"),
                "the verdict must say what it found: {m}"
            ),
            other => panic!("a torn tail is incomplete, not {other:?}"),
        }
        cleanup(&sid);
    }

    /// H5b (verdict doc: confirmed). `commit_audit_root` used to write `.root`
    /// then `.sig` as two separate `fs::write`s; a kill between them left a
    /// committed root whose signature was missing (or stale), and `verify`
    /// reported `BAD_SIGNATURE`/`TAMPERED` instead of an honest "the commit was
    /// interrupted". Every half-committed pair is now `INCOMPLETE`-class, never
    /// tampering - so the operator never mistakes a crash for an edit.
    ///
    /// Root without its signature: an interrupted commit (sig-first ordering means
    /// this cannot be produced by the new writer, but an external actor or an old
    /// run can leave it). Today this is `BAD_SIGNATURE`; it must be `Incomplete`.
    #[test]
    fn a_root_without_its_signature_is_incomplete() {
        let sid = fresh_sid("h5b-root-only");
        plant_signed_chain(&sid, chain_leaf(&sid, true, true));
        // Remove the signature, leaving the committed root alone.
        std::fs::remove_file(audit_log_path(&sid).with_extension("sig")).unwrap();
        match verify_inner(&sid).unwrap() {
            VerifyOutcome::Incomplete(m) => assert!(
                m.to_ascii_lowercase().contains("sig")
                    || m.to_ascii_lowercase().contains("signature"),
                "the verdict must name the missing half: {m}"
            ),
            VerifyOutcome::Tampered(m) => {
                panic!("a root without a signature is a crash, not an edit: {m}")
            }
            VerifyOutcome::BadSignature(m) => {
                panic!("a missing signature is incomplete, not bad-signature: {m}")
            }
            other => panic!("a root without a signature must be incomplete, got {other:?}"),
        }
        cleanup(&sid);
    }

    /// Signature without its root: the only half the new sig-first writer can leave
    /// behind if it is killed before the root lands. `verify` already reported
    /// `Incomplete` here, but the case is pinned so the ordering stays load-bearing.
    #[test]
    fn a_signature_without_its_root_is_incomplete() {
        let sid = fresh_sid("h5b-sig-only");
        plant_signed_chain(&sid, chain_leaf(&sid, true, true));
        std::fs::remove_file(audit_log_path(&sid).with_extension("root")).unwrap();
        match verify_inner(&sid).unwrap() {
            VerifyOutcome::Incomplete(_) => {}
            other => panic!("a signature without a root must be incomplete, got {other:?}"),
        }
        cleanup(&sid);
    }

    /// A truncated committed root (a half-written `fs::write` that the kill
    /// interrupted) used to fail the hex comparison and read as `TAMPERED` - the
    /// tool calling an interrupted commit an edit. It must be `Incomplete`.
    #[test]
    fn a_truncated_committed_root_is_incomplete_not_tampered() {
        let sid = fresh_sid("h5b-trunc-root");
        plant_signed_chain(&sid, chain_leaf(&sid, true, true));
        // Half the 64-hex-char root: exactly the kind of torn file a kill produces.
        let root_path = audit_log_path(&sid).with_extension("root");
        let root = std::fs::read_to_string(&root_path).unwrap();
        let half = &root[..root.len() / 2];
        std::fs::write(&root_path, half).unwrap();

        match verify_inner(&sid).unwrap() {
            VerifyOutcome::Incomplete(m) => assert!(
                m.to_ascii_lowercase().contains("root")
                    || m.to_ascii_lowercase().contains("commit"),
                "the verdict must name the interrupted commit: {m}"
            ),
            VerifyOutcome::Tampered(m) => {
                panic!("a truncated root is a crash, not an edit: {m}")
            }
            other => panic!("a truncated root must be incomplete, got {other:?}"),
        }
        cleanup(&sid);
    }

    /// M6 (verdict doc: confirmed). `audit verify` used to call
    /// `signing::KeyMaterial::ensure()`, which MINTS a fresh key when the file is
    /// missing. So losing the key made every old session report `BAD_SIGNATURE`
    /// (indistinguishable from tampering) AND installed a brand-new trust anchor as
    /// a side effect of merely verifying. Verify must load-or-fail, report a
    /// distinct `KeyMissing` verdict, and create no key file.
    #[test]
    fn a_missing_signing_key_is_its_own_verdict_and_mints_nothing() {
        let sid = fresh_sid("m6-no-key");
        // A fully committed chain (root + sig), exactly as a clean session left it.
        plant_signed_chain(&sid, chain_leaf(&sid, true, true));

        // The verifier's key does not exist: the loader is pointed at a path that
        // was never created (and never will be, because verify must not mint).
        let missing_key = std::env::temp_dir().join(format!(
            "saife-m6-verify-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        assert!(!missing_key.exists());

        match verify_with_key_source(&sid, || {
            signing::KeyMaterial::load_existing_at(&missing_key)
        })
        .unwrap()
        {
            VerifyOutcome::KeyMissing(m) => assert!(
                m.to_ascii_lowercase().contains("key"),
                "the verdict must name what is missing: {m}"
            ),
            VerifyOutcome::BadSignature(m) => {
                panic!("a missing key is not a bad signature: {m}")
            }
            other => panic!("a missing key must be KeyMissing, got {other:?}"),
        }

        assert!(
            !missing_key.exists(),
            "verifying a session must never mint a signing key"
        );
        cleanup(&sid);
    }

    /// A `.root` that is not hex at all (or is 64 *bytes* of non-ASCII) must still
    /// produce a verdict. `decode_hex` byte-slices a `&str`, so routing the root
    /// through it would panic here instead of answering — the H5b check runs on the
    /// character class for exactly that reason.
    #[test]
    fn a_non_hex_committed_root_is_incomplete_without_panicking() {
        let sid = fresh_sid("h5b-nonhex-root");
        plant_signed_chain(&sid, chain_leaf(&sid, true, true));
        // 32 non-ASCII chars == 64 bytes: the length check alone would let this
        // through to a byte-slicing hex decoder.
        let not_hex: String = "é".repeat(32);
        assert_eq!(not_hex.len(), 64);
        std::fs::write(audit_log_path(&sid).with_extension("root"), &not_hex).unwrap();

        match verify_inner(&sid).unwrap() {
            VerifyOutcome::Incomplete(_) => {}
            other => panic!("a non-hex root is an interrupted commit, got {other:?}"),
        }
        cleanup(&sid);
    }

    /// L-F (verdict doc: confirmed, Low). NTFS is case-insensitive, so a log
    /// created with `--sid ABC` is found by `audit verify abc` — but the leaf
    /// carries `ABC` and the comparison was exact, so the tool called its own
    /// untouched log TAMPERED. Intake must lowercase the id so the on-disk name
    /// and the leaf value always agree.
    #[test]
    fn a_session_created_in_upper_case_verifies_in_lower_case() {
        let upper = format!("TEST-CASE-INTAKE-{}", std::process::id());
        let lower = upper.to_ascii_lowercase();
        let root;
        {
            let w = AuditWriter::open(&upper, false).unwrap();
            let mut e = Map::new();
            e.insert("op".into(), json!("CONNECT"));
            e.insert("host".into(), json!("case.example"));
            w.append(e).unwrap();
            root = w.current_root().unwrap();
        }
        // Commit exactly as a clean session would.
        let key = signing::KeyMaterial::ensure().unwrap();
        let root_bytes = decode_hex(&root).unwrap();
        let sig = key.sign_root(&root_bytes);
        std::fs::write(audit_log_path(&upper).with_extension("root"), &root).unwrap();
        let sig_hex: String = sig.iter().map(|b| format!("{b:02x}")).collect();
        std::fs::write(audit_log_path(&upper).with_extension("sig"), &sig_hex).unwrap();

        let outcome = verify_inner(&lower).unwrap();
        cleanup(&upper);
        assert!(
            matches!(outcome, VerifyOutcome::Ok),
            "`--sid ABC` then `verify abc` must verify, got {outcome:?}"
        );
    }

    /// L-F, the legacy half: a log written before intake lowercased ids has a
    /// mixed-case leaf `sid` on disk (and NTFS finds the file regardless).
    /// Verify must accept a case-insensitive match of the stored value rather
    /// than turning a pre-existing mixed-case log into TAMPERED.
    #[test]
    fn a_legacy_mixed_case_leaf_still_verifies() {
        let upper = format!("TEST-CASE-LEGACY-{}", std::process::id());
        plant_signed_chain(&upper, chain_leaf(&upper, true, true));
        let outcome = verify_inner(&upper.to_ascii_lowercase()).unwrap();
        cleanup(&upper);
        assert!(
            matches!(outcome, VerifyOutcome::Ok),
            "a legacy mixed-case sid must still verify, got {outcome:?}"
        );
    }

    /// L-G (verdict doc: confirmed, Low). `decode_hex` byte-sliced a `&str`, so
    /// a valid-UTF-8 non-ASCII `.sig` (here `"a€"`: 4 bytes, 2 chars — even
    /// length, so the length check let it through) hit a slice off a char
    /// boundary and `audit verify` panicked with exit 101 instead of printing
    /// a verdict. A non-hex `.sig` is a bad signature, never a crash.
    #[test]
    fn a_non_ascii_signature_is_a_verdict_not_a_panic() {
        let sid = fresh_sid("lg-nonascii-sig");
        plant_signed_chain(&sid, chain_leaf(&sid, true, true));
        std::fs::write(audit_log_path(&sid).with_extension("sig"), "a\u{20ac}").unwrap();

        let outcome = verify_inner(&sid).unwrap();
        cleanup(&sid);
        assert!(
            matches!(outcome, VerifyOutcome::BadSignature(_)),
            "a non-hex .sig must be BAD_SIGNATURE, got {outcome:?}"
        );
    }

    /// M7 (verdict doc: confirmed). The committed root did not record which key
    /// signed it, so after a rotation every older session verified under the new
    /// key, failed, and was reported BAD_SIGNATURE - the tool calling its own
    /// history a forgery. The commit now records the signer's fingerprint, and
    /// a mismatch is its own verdict.
    #[test]
    fn a_session_signed_with_a_different_key_is_key_changed() {
        let older = fresh_sid("m7-older");
        let newer = fresh_sid("m7-newer");
        // Deterministic test keys: the point is that they differ, not that they
        // came from the RNG.
        let old_key = SigningKey::from_bytes(&[0x11; 32]);
        let new_key = SigningKey::from_bytes(&[0x22; 32]);

        plant_signed_chain_with_key(&older, chain_leaf(&older, true, true), &old_key);
        plant_signed_chain_with_key(&newer, chain_leaf(&newer, true, true), &new_key);

        // A rotation happened: the current key is `new_key`.
        let older_outcome =
            verify_with_key_source(&older, || Ok(signing::KeyMaterial { signing: new_key.clone() }))
                .unwrap();
        let newer_outcome =
            verify_with_key_source(&newer, || Ok(signing::KeyMaterial { signing: new_key.clone() }))
                .unwrap();

        cleanup(&older);
        cleanup(&newer);

        match older_outcome {
            VerifyOutcome::KeyChanged(m) => assert!(
                m.to_ascii_lowercase().contains("key"),
                "the verdict must say which key changed: {m}"
            ),
            VerifyOutcome::BadSignature(m) => panic!(
                "a key rotation must not be reported as a forgery (BAD_SIGNATURE): {m}"
            ),
            other => panic!("a different signing key must be KeyChanged, got {other:?}"),
        }
        assert!(
            matches!(newer_outcome, VerifyOutcome::Ok),
            "the session signed with the current key must still verify, got {newer_outcome:?}"
        );
    }

    /// M7, the guard against over-claiming: a matching fingerprint must not
    /// short-circuit the signature check. A forged signature under the same key
    /// is still BAD_SIGNATURE.
    #[test]
    fn a_matching_fingerprint_does_not_excuse_a_forged_signature() {
        let sid = fresh_sid("m7-same-key-bad-sig");
        let key = signing::KeyMaterial::ensure().unwrap();
        plant_signed_chain_with_key(&sid, chain_leaf(&sid, true, true), &key.signing);
        // Corrupt the signature; the fingerprint still matches the key.
        let sig_path = audit_log_path(&sid).with_extension("sig");
        let sig = std::fs::read_to_string(&sig_path).unwrap();
        let flipped = if sig.starts_with("00") { "ff" } else { "00" };
        let corrupt = format!("{flipped}{}", &sig[2..]);
        std::fs::write(&sig_path, corrupt).unwrap();

        let outcome = verify_inner(&sid).unwrap();
        cleanup(&sid);
        assert!(
            matches!(outcome, VerifyOutcome::BadSignature(_)),
            "a forged signature must stay BAD_SIGNATURE, got {outcome:?}"
        );
    }

    /// Write a fully valid, signed one-leaf chain at `sid`'s path. `leaf` must
    /// already carry whatever fields the test wants to pin; `hash`/`parent`
    /// are recomputed here and the root is signed with the real key, so the
    /// only thing under test is the field set.
    fn plant_signed_chain(sid: &str, leaf: Map<String, Value>) {
        let key = signing::KeyMaterial::ensure().unwrap();
        plant_signed_chain_with_key(sid, leaf, &key.signing);
    }

    /// M7 variant: sign with an explicit key and record its fingerprint with the
    /// commit, exactly as `commit_audit_root` now does. Lets a test model a key
    /// rotation without touching the user's real key.
    fn plant_signed_chain_with_key(sid: &str, mut leaf: Map<String, Value>, key: &SigningKey) {
        leaf.insert("ts".into(), json!("2026-11-09T00:00:00Z"));
        let hash = sha256_hex(&canonicalize(&leaf));
        leaf.insert("hash".into(), json!(hash));
        leaf.insert("parent".into(), json!(Value::Null));
        let path = audit_log_path(sid);
        std::fs::write(&path, serde_json::to_string(&leaf).unwrap() + "\n").unwrap();
        std::fs::write(path.with_extension("root"), &hash).unwrap();
        let hash_bytes = decode_hex(&hash).unwrap();
        let sig = {
            use ed25519_dalek::Signer;
            key.sign(&hash_bytes).to_bytes()
        };
        let sig_hex: String = sig.iter().map(|b| format!("{b:02x}")).collect();
        std::fs::write(path.with_extension("sig"), &sig_hex).unwrap();
        std::fs::write(path.with_extension("keyfp"), signing::fingerprint_of(key)).unwrap();
    }

    /// One CONNECT leaf, carrying `sid`/`seq` only when asked: the missing-key
    /// tests need a leaf that never had the key at all.
    fn chain_leaf(sid: &str, with_sid: bool, with_seq: bool) -> Map<String, Value> {
        let mut e = Map::new();
        e.insert("op".into(), json!("CONNECT"));
        e.insert("host".into(), json!("planted.example"));
        if with_sid {
            e.insert("sid".into(), json!(sid));
        }
        if with_seq {
            e.insert("seq".into(), json!(0));
        }
        e
    }

    /// H4 (verdict doc: partial, Medium — real but deferred). `verify` joins
    /// the raw `--sid` into the audit directory exactly like `show`, so a
    /// traversal sid names a file outside it — and the chain planted below is
    /// fully valid, so today `verify` reports **OK** for it.
    ///
    /// RED until H4 lands (verdict doc): sid validation at this reader entry
    /// point must make every case return `Err` before any file is opened.
    #[test]
    fn verify_refuses_a_traversal_session_id_before_reading_any_file() {
        let pid = std::process::id();
        let relative = format!("..\\..\\h4-verify-{pid}");
        let absolute = std::env::temp_dir()
            .join(format!("h4-verify-abs-{pid}"))
            .to_string_lossy()
            .into_owned();
        let unc = format!("\\\\h4-nonexistent\\share\\h4-verify-{pid}");

        // The planted chain carries the traversal sid itself, so today every
        // check inside `verify_inner` passes and the verdict is OK.
        plant_signed_chain(&relative, chain_leaf(&relative, true, true));
        plant_signed_chain(&absolute, chain_leaf(&absolute, true, true));

        let results = [
            verify_inner(&relative).map_err(|e| format!("{e:#}")),
            verify_inner(&absolute).map_err(|e| format!("{e:#}")),
            verify_inner(&unc).map_err(|e| format!("{e:#}")),
        ];
        cleanup(&relative);
        cleanup(&absolute);

        assert!(
            results[0].is_err(),
            "a relative traversal sid must be refused, got {results:?}"
        );
        assert!(
            results[1].is_err(),
            "an absolute-path sid must be refused, got {results:?}"
        );
        match &results[2] {
            Err(message) => assert!(
                message.to_ascii_lowercase().contains("session"),
                "a UNC sid must be refused by sid validation before any path lookup: {message}"
            ),
            Ok(outcome) => panic!("a UNC sid must be refused, got {outcome:?}"),
        }
    }

    /// L-H (verdict doc: partial, Low — deferred defense-in-depth). A leaf
    /// that STRIPPED its `sid` key must verify as Tampered, not be silently
    /// accepted: `verify` checks the session binding only when the key is
    /// present, so a rewritten leaf that drops it (hash recomputed, chain
    /// re-signed — the honest forgery below) verifies OK today.
    ///
    /// RED until L-H lands (verdict doc): requiring `sid` on every leaf turns
    /// this into Tampered.
    #[test]
    fn a_leaf_without_the_sid_key_is_tampered() {
        let sid = fresh_sid("lh-no-sid");
        plant_signed_chain(&sid, chain_leaf(&sid, false, true));
        let outcome = verify_inner(&sid).unwrap();
        cleanup(&sid);
        assert!(
            matches!(outcome, VerifyOutcome::Tampered(_)),
            "a leaf without `sid` must be Tampered, got {outcome:?}"
        );
    }

    /// L-H, the `seq` half: a leaf with its sequence number stripped must be
    /// Tampered for the same reason — the check is conditional on presence.
    ///
    /// RED until L-H lands (verdict doc).
    #[test]
    fn a_leaf_without_the_seq_key_is_tampered() {
        let sid = fresh_sid("lh-no-seq");
        plant_signed_chain(&sid, chain_leaf(&sid, true, false));
        let outcome = verify_inner(&sid).unwrap();
        cleanup(&sid);
        assert!(
            matches!(outcome, VerifyOutcome::Tampered(_)),
            "a leaf without `seq` must be Tampered, got {outcome:?}"
        );
    }

    /// A two-leaf chain, committed the way `commit_audit_root` does: `.root` and
    /// `.sig` pin the LAST leaf's hash. `tamper_parent` corrupts leaf 1's
    /// `parent` link while leaving its (self-consistent) `hash` intact, so only
    /// the LINKAGE check can catch it.
    fn plant_two_leaf_chain(sid: &str, tamper_parent: bool) {
        let key = signing::KeyMaterial::ensure().unwrap();
        let path = audit_log_path(sid);

        let mut first = chain_leaf(sid, true, true);
        first.insert("ts".into(), json!("2026-11-12T00:00:00Z"));
        let h0 = sha256_hex(&canonicalize(&first));
        first.insert("hash".into(), json!(h0.clone()));
        first.insert("parent".into(), json!(Value::Null));

        let mut second = chain_leaf(sid, true, true);
        second.insert("seq".into(), json!(1));
        second.insert("ts".into(), json!("2026-11-12T00:00:01Z"));
        let h1 = sha256_hex(&canonicalize(&second));
        second.insert("hash".into(), json!(h1.clone()));
        second.insert("parent".into(), json!(if tamper_parent { "0".repeat(64) } else { h0 }));

        std::fs::write(
            &path,
            serde_json::to_string(&first).unwrap() + "\n" + &serde_json::to_string(&second).unwrap() + "\n",
        )
        .unwrap();
        std::fs::write(path.with_extension("root"), &h1).unwrap();
        let sig = {
            use ed25519_dalek::Signer;
            key.signing.sign(&decode_hex(&h1).unwrap()).to_bytes()
        };
        let sig_hex: String = sig.iter().map(|b| format!("{b:02x}")).collect();
        std::fs::write(path.with_extension("sig"), &sig_hex).unwrap();
        std::fs::write(
            path.with_extension("keyfp"),
            signing::fingerprint_of(&key.signing),
        )
        .unwrap();
    }

    /// The `p == sp` linkage guard says "this leaf chains to the one before".
    /// Forcing it true makes a re-parented middle leaf verify OK - the same
    /// substitution attack the linkage check exists to refuse.
    #[test]
    fn a_tampered_parent_link_in_a_middle_leaf_is_tampered() {
        let sid = fresh_sid("parent-link");
        plant_two_leaf_chain(&sid, true);
        let outcome = verify_inner(&sid).unwrap();
        cleanup(&sid);
        match outcome {
            VerifyOutcome::Tampered(r) => {
                assert!(r.contains("parent mismatch"), "expected the parent verdict, got: {r}");
            }
            other => panic!("a re-parented middle leaf is Tampered, not {other:?}"),
        }
    }

    #[test]
    fn an_honest_two_leaf_chain_verifies_ok() {
        let sid = fresh_sid("parent-ok");
        plant_two_leaf_chain(&sid, false);
        let outcome = verify_inner(&sid).unwrap();
        cleanup(&sid);
        assert!(
            matches!(outcome, VerifyOutcome::Ok),
            "an honest two-leaf chain must be Ok, got {outcome:?}"
        );
    }

    /// The torn-tail guard protects ONLY the last line: a truncated write can
    /// only land at the end of the file. A parse error anywhere EARLIER is a
    /// manipulated log, torn tail or not - and the guard mutants would call
    /// it INCOMPLETE (guard => true) or, with `&&` widened to `||`, hide a
    /// corrupted middle line behind a torn tail.
    #[test]
    fn a_parse_error_before_the_last_line_is_tampered_even_with_a_torn_tail() {
        let sid = fresh_sid("mid-garbage");
        plant_two_leaf_chain(&sid, false);
        let path = audit_log_path(&sid);
        let original = std::fs::read_to_string(&path).unwrap();
        let first = original.lines().next().expect("one planted leaf").to_string();
        // Two honest leaves become: one honest leaf, a corrupted MIDDLE line, and
        // a torn fragment with no terminator - the shape the widened guard
        // misreads as an interrupted write.
        std::fs::write(
            &path,
            format!("{first}\nnot json at all\n{{\"op\": \"CONNECT\""),
        )
        .unwrap();
        let outcome = verify_inner(&sid).unwrap();
        cleanup(&sid);
        match outcome {
            VerifyOutcome::Tampered(r) => {
                assert!(r.contains("invalid JSON"), "expected the parse verdict, got: {r}");
            }
            other => panic!(
                "a corrupted middle line is Tampered even when the tail is torn, not {other:?}"
            ),
        }
    }

    /// `run_verify` is the CLI contract: OK exits 0, every verdict carries 1.
    /// A constant-return mutant either mints 0 on a tampered chain or throws a
    /// valid chain's exit code away.
    #[test]
    fn run_verify_exit_codes_convey_the_verdict() {
        let good = fresh_sid("exit-ok");
        plant_two_leaf_chain(&good, false);
        assert_eq!(run_verify(&good), 0, "an honest chain exits 0");
        cleanup(&good);

        let bad = fresh_sid("exit-tampered");
        plant_two_leaf_chain(&bad, true);
        assert_eq!(run_verify(&bad), 1, "a tampered chain exits 1");
        cleanup(&bad);

        assert_eq!(
            run_verify(&fresh_sid("exit-missing")),
            1,
            "a missing log is INCOMPLETE evidence, which exits 1"
        );
    }
}
