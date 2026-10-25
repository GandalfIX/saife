//! `saife audit verify <sid>`
//!
//! Recompute the Merkle root from the .ndjson file, compare to the committed
//! .root, check the Ed25519 signature on .sig. Prints OK / TAMPERED /
//! BAD_SIGNATURE / INCOMPLETE and exits 0/1 accordingly.

use anyhow::Result;
use serde_json::Value;

use super::{canonicalize, sha256_hex, audit_log_path};
use crate::signing;

pub fn run_verify(session_id: &str) -> i32 {
    match verify_inner(session_id) {
        Ok(VerifyOutcome::Ok) => { println!("OK"); 0 }
        Ok(VerifyOutcome::Incomplete(reason)) => { println!("INCOMPLETE: {reason}"); 1 }
        Ok(VerifyOutcome::Tampered(reason)) => { println!("TAMPERED: {reason}"); 1 }
        Ok(VerifyOutcome::BadSignature(reason)) => { println!("BAD_SIGNATURE: {reason}"); 1 }
        Err(e) => { eprintln!("[saife] audit verify: {e:#}"); 1 }
    }
}

/// `pub(crate)`, not private (P3.1, S-55): the crash test lives beside the
/// mechanism it protects (the root that is written before the launch) and has to
/// assert the *verdict* `verify` reaches, not a copy of it. The CLI entry point
/// stays [`run_verify`].
#[derive(Debug)]
pub(crate) enum VerifyOutcome {
    Ok,
    Incomplete(String),
    Tampered(String),
    BadSignature(String),
}

pub(crate) fn verify_inner(session_id: &str) -> Result<VerifyOutcome> {
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
        if let Some(leaf_sid) = obj.get("sid").and_then(|x| x.as_str())
            && leaf_sid != session_id
        {
            return Ok(VerifyOutcome::Tampered(format!(
                "leaf {i}: belongs to session {leaf_sid}, not {session_id}"
            )));
        }
        if let Some(seq) = obj.get("seq").and_then(|x| x.as_u64())
            && seq != leaf_count as u64 - 1
        {
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
        Ok(s) => s.trim().to_string(),
        Err(_) => return Ok(VerifyOutcome::Incomplete(
            format!("no committed root (session did not end cleanly); {} events present", leaf_count)
        )),
    };
    let computed = computed_root.unwrap();
    if committed_root != computed {
        return Ok(VerifyOutcome::Tampered(format!(
            "root mismatch (committed {committed_root}, computed {computed})"
        )));
    }

    // Verify the signature.
    let sig_hex = match std::fs::read_to_string(&sig_path) {
        Ok(s) => s.trim().to_string(),
        Err(_) => return Ok(VerifyOutcome::BadSignature("no .sig file".to_string())),
    };
    let sig_bytes = match decode_hex(&sig_hex) {
        Some(b) => b,
        None => return Ok(VerifyOutcome::BadSignature("signature is not valid hex".to_string())),
    };
    let root_bytes = match decode_hex(&computed) {
        Some(b) => b,
        None => return Ok(VerifyOutcome::BadSignature("computed root is not valid hex".to_string())),
    };

    let key = signing::KeyMaterial::ensure()?;
    if !signing::verify_with_secret(&key.signing, &root_bytes, &sig_bytes) {
        return Ok(VerifyOutcome::BadSignature("signature does not verify".to_string()));
    }

    Ok(VerifyOutcome::Ok)
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) { return None; }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i+2], 16).ok()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
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
}
