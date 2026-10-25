//! US-4a audit core: hash-chain NDJSON leaves, canonicalization, hashing.
//! This module grows across tasks; for now it holds the pure canonicalization
//! logic. The existing writer code from US-3 is folded in by Task 5.
//!
//! ## Reserved event: `secret.inject` (D-5.2, not yet emitted)
//!
//! Schema (a complete leaf; `seq`/`ts`/`hash`/`parent` are added by
//! [`AuditWriter::append`], the caller supplies only `op` + `name`):
//!
//! ```json
//! {"op": "secret.inject", "name": "<secret-name>", "seq": <u64>, "ts": "<iso8601>", "hash": "<hex>", "parent": "<hex|null>"}
//! ```
//!
//! The `name` field identifies the secret being injected (e.g. an env var
//! name or a file path identifier). This schema is reserved for F-2
//! (credential injection), which is out of scope for ADR-0001. No emission
//! code exists yet; see [`SECRET_INJECT_SCHEMA`] for the machine-checked
//! contract.

pub mod filter;
pub mod session_start;
pub mod show;
pub mod verify;

use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

use anyhow::{Context, Result};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

/// Reserved schema template for the `secret.inject` audit event (D-5.2).
/// Kept as a const so future F-2 emission code and tests share a single
/// source of truth; no production call site consumes it yet (only tests
/// reference it), so it is `#[allow(dead_code)]` until F-2 lands. See the
/// module-level doc comment for the full schema description.
#[allow(dead_code)]
pub const SECRET_INJECT_SCHEMA: &str =
    r#"{"op": "secret.inject", "name": "<secret-name>", "seq": <u64>, "ts": "<iso8601>", "hash": "<hex>", "parent": "<hex|null>"}"#;

pub fn audit_log_path(session_id: &str) -> PathBuf {
    let local = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    let dir = local.join("saife").join("audit");
    let _ = std::fs::create_dir_all(&dir);
    dir.join(format!("{session_id}.ndjson"))
}

#[derive(Debug, Clone, Copy)]
#[cfg(test)]
pub enum Disposition { Allow, Deny }

#[cfg(test)]
impl Disposition {
    fn as_str(&self) -> &'static str { match self { Self::Allow => "allow", Self::Deny => "deny" } }
}

#[cfg(test)]
pub fn emit_connect(
    session_id: &str,
    host: &str,
    port: u16,
    disposition: Disposition,
    reason: Option<&str>,
) {
    let writer = AuditWriter::open(session_id, false).unwrap();
    let mut event = Map::new();
    event.insert("op".into(), serde_json::json!("CONNECT"));
    event.insert("host".into(), serde_json::json!(host));
    event.insert("port".into(), serde_json::json!(port));
    event.insert("disposition".into(), serde_json::json!(disposition.as_str()));
    event.insert("reason".into(), serde_json::json!(reason));
    writer.append(event).unwrap();
}

pub struct AuditWriter {
    path: PathBuf,
    /// Parent hash AND next sequence number behind one lock. They are one
    /// invariant: seq must increase in file order, and the parent link must name
    /// the leaf written immediately before. Splitting them (a mutex for the hash,
    /// an atomic for seq) let two appends observe the same `None` parent and
    /// produced leaves that `verify` reported as TAMPERED - the tool accusing its
    /// own untouched log. Hold this guard across compute -> write -> commit.
    chain: Mutex<ChainState>,
    strict: bool,
    /// Stamped into every leaf. It is what makes a log belong to a session: without
    /// it, a clean session's three files can be copied over another's names and
    /// `audit verify` reports OK for the substitute.
    session_id: Option<String>,
}

/// The chain's commit point. Only `append` mutates this, and only under the lock.
#[derive(Default)]
struct ChainState {
    last: Option<String>,
    seq: u64,
}

impl AuditWriter {
    /// Open the writer for a session. If the log file already exists (e.g.
    /// `--reuse <sid>` or crash recovery), scan existing lines to recover
    /// `last_hash` and `seq`. If it doesn't exist, start fresh.
    ///
    /// When `strict` is true, returns `Err` if the audit directory can't be
    /// created or the log file can't be opened for writing. When `strict`
    /// is false, degrades gracefully (best-effort logging, never returns
    /// `Err`).
    pub fn open(session_id: &str, strict: bool) -> Result<Self> {
        let path = audit_log_path(session_id);
        Self::open_at(path, strict)
    }

    /// Internal: open at an explicit path (for testing strict mode without
    /// env var manipulation).
    fn open_at(path: PathBuf, strict: bool) -> Result<Self> {
        if strict {
            // Verify the parent directory exists / can be created and the
            // log file is writable before claiming the writer is usable.
            if let Some(parent) = path.parent()
                && !parent.as_os_str().is_empty()
                && let Err(e) = std::fs::create_dir_all(parent)
            {
                return Err(anyhow::anyhow!("create audit dir {:?}: {e}", parent.display()))
                    .with_context(|| "strict audit: directory not writable");
            }
            // Touch the file to confirm it can be opened for appending. This
            // also surfaces permission errors eagerly instead of at the first
            // `append`.
            if let Err(e) = std::fs::OpenOptions::new()
                .append(true)
                .create(true)
                .open(&path)
            {
                return Err(anyhow::anyhow!("open audit log {:?}: {e}", path.display()))
                    .with_context(|| "strict audit: log file not writable");
            }
        }

        // An existing log that cannot be scanned must NOT be extended: appending
        // with a `null` parent to a chain that already has leaves is exactly the
        // shape `verify` reports as tampering, so it would manufacture the verdict
        // it is supposed to detect. Refusing keeps the evidence honest and the
        // operator moves the file aside deliberately.
        let chain = if path.exists() {
            let (last, seq) = scan_existing(&path).with_context(|| {
                format!(
                    "existing audit chain {:?} is unreadable or corrupt; refusing to extend it \
                     (move it aside to start a new session)",
                    path.display()
                )
            })?;
            ChainState { last, seq }
        } else {
            ChainState::default()
        };
        let session_id = path
            .file_stem()
            .and_then(|s| s.to_str())
            .map(str::to_string);
        Ok(Self {
            path,
            chain: Mutex::new(chain),
            strict,
            session_id,
        })
    }

    /// Append a leaf. `event` is the op-specific payload (op, host, path,
    /// etc.) WITHOUT seq/ts/hash/parent — those are computed here.
    ///
    /// When `strict` is true, returns `Err` if the file can't be opened for
    /// appending or the write fails. When `strict` is false, silently
    /// swallows errors (best-effort) and always returns `Ok(())`.
    pub fn append(&self, mut event: Map<String, Value>) -> Result<()> {
        let mut chain = self.chain.lock().unwrap_or_else(|p| p.into_inner());
        let seq = chain.seq;
        let ts = iso8601_utc();
        event.insert("seq".into(), serde_json::json!(seq));
        event.insert("ts".into(), serde_json::json!(ts));
        if let Some(sid) = &self.session_id {
            event.insert("sid".into(), serde_json::json!(sid));
        }
        let canonical = canonicalize(&event);
        let hash = sha256_hex(&canonical);
        let parent = chain.last.clone();
        event.insert("hash".into(), serde_json::json!(hash));
        event.insert("parent".into(), serde_json::json!(parent));
        let mut line = serde_json::to_string(&event)
            .expect("a Map<String, Value> is always serializable; see canonicalize");
        line.push('\n');

        if std::env::var_os("SAIFE_DIAG").is_some() {
            eprint!("[proxy] {line}");
        }

        let file_result = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(&self.path);
        if self.strict {
            let mut f = file_result
                .with_context(|| format!("strict audit: open {:?} for append", self.path.display()))?;
            f.write_all(line.as_bytes())
                .with_context(|| format!("strict audit: write {:?} failed", self.path.display()))?;
        } else if let Ok(mut f) = file_result {
            let _ = f.write_all(line.as_bytes());
        }
        // Commit last: a failed write must not advance the chain, or the next
        // leaf would name a parent that is not in the file.
        chain.seq = seq + 1;
        chain.last = Some(hash);
        Ok(())
    }

    /// The current chain root (last leaf's hash). None if no leaves yet.
    pub fn current_root(&self) -> Option<String> {
        self.chain
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .last
            .clone()
    }
}

/// Scan an existing .ndjson file to recover the last hash + next seq for
/// crash recovery / --reuse.
fn scan_existing(path: &std::path::Path) -> Result<(Option<String>, u64)> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("read existing chain {:?}", path.display()))?;
    let mut last_hash: Option<String> = None;
    let mut max_seq: Option<u64> = None;
    for (line_no, line) in content.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let v: Value = serde_json::from_str(line)
            .with_context(|| format!("parse existing chain {:?} (line {line_no})", path.display()))?;
        if let Some(h) = v.get("hash").and_then(|x| x.as_str()) {
            last_hash = Some(h.to_string());
        }
        if let Some(s) = v.get("seq").and_then(|x| x.as_u64()) {
            max_seq = Some(max_seq.map_or(s, |m| m.max(s)));
        }
    }
    let next_seq = max_seq.map_or(0, |m| m + 1);
    Ok((last_hash, next_seq))
}

fn iso8601_utc() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let h = rem / 3600;
    let m = (rem % 3600) / 60;
    let s = rem % 60;
    let (y, mo, d) = civil_from_days(days);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}

fn civil_from_days(z_off: i64) -> (i64, u32, u32) {
    let z = z_off + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m as u32, d as u32)
}

/// Canonicalize a leaf for hashing: remove `hash` and `parent` keys, sort the
/// remaining keys alphabetically (via BTreeMap), serialize compactly (no
/// whitespace). Deterministic across implementations regardless of insertion
/// order.
pub fn canonicalize(leaf: &Map<String, Value>) -> String {
    let mut copy = leaf.clone();
    copy.remove("hash");
    copy.remove("parent");
    // serde_json::Map with the "preserve_order" feature off defaults to
    // BTreeMap-backed, producing alphabetical keys. But to be explicit and
    // safe across feature flags, route through a BTreeMap:
    let btree: std::collections::BTreeMap<String, Value> = copy.into_iter().collect();
    // Infallible by construction: the value is a map with string keys of
    // `serde_json::Value`, which has no failing representation. The previous
    // `unwrap_or_else(|_| "{}")` was worse than a panic - it committed
    // sha256("{}") as the leaf hash while `verify` recomputed the same string, so
    // the chain "verified" while no longer committing to the event body.
    serde_json::to_string(&btree).expect("Map<String, Value> is always serializable")
}

/// SHA-256 of the canonical bytes, returned as lowercase hex.
pub fn sha256_hex(s: &str) -> String {
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    let digest = h.finalize();
    digest.iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_from_days_known() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(1), (1970, 1, 2));
    }

    #[test]
    fn emit_connect_produces_valid_json() {
        // Use a temp session id so we don't collide with real sessions.
        let sid = format!("test-{}-{}", std::process::id(), std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos());
        emit_connect(&sid, "api.anthropic.com", 443, Disposition::Allow, None);
        emit_connect(&sid, "evil.example.com", 443, Disposition::Deny, Some("domain_not_allowed"));
        let path = audit_log_path(&sid);
        let content = std::fs::read_to_string(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        let lines: Vec<&str> = content.trim().lines().collect();
        assert_eq!(lines.len(), 2);
        for line in &lines {
            let v: serde_json::Value = serde_json::from_str(line).expect("line is valid JSON");
            assert_eq!(v["op"], "CONNECT");
            assert!(v["host"].as_str().unwrap().contains("anthropic.com") || v["host"].as_str().unwrap().contains("evil.example.com"));
            assert_eq!(v["port"], 443);
        }
        // The deny line must have a reason field.
        let deny_line: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(deny_line["disposition"], "deny");
        assert_eq!(deny_line["reason"], "domain_not_allowed");
    }

    #[test]
    fn emit_connect_escapes_malicious_host() {
        let sid = format!("test-escape-{}-{}", std::process::id(), std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos());
        emit_connect(&sid, "evil\\\nhost", 443, Disposition::Deny, Some("a\"b"));
        let path = audit_log_path(&sid);
        let content = std::fs::read_to_string(&path).unwrap();
        let _ = std::fs::remove_file(&path);

        // The event must occupy exactly one line in the file (no newline injection).
        let trimmed = content.strip_suffix('\n').unwrap_or(&content);
        let lines: Vec<&str> = trimmed.lines().collect();
        assert_eq!(lines.len(), 1, "event must occupy exactly one line");

        // The single line must parse as valid JSON.
        let v: serde_json::Value = serde_json::from_str(lines[0]).expect("line is valid JSON");
        assert_eq!(v["host"], "evil\\\nhost", "host backslash + newline preserved literally");
        assert_eq!(v["reason"], "a\"b", "reason quote preserved literally");
        assert_eq!(v["port"], 443);
        assert_eq!(v["disposition"], "deny");
    }

    #[test]
    fn canonicalize_strips_hash_and_parent() {
        let m: Map<String, Value> = [
            ("op", Value::String("CONNECT".into())),
            ("host", Value::String("a.com".into())),
            ("hash", Value::String("deadbeef".into())),
            ("parent", Value::Null),
        ].iter().map(|(k, v)| (k.to_string(), v.clone())).collect();
        let c = canonicalize(&m);
        let v: Value = serde_json::from_str(&c).unwrap();
        assert!(v.get("hash").is_none());
        assert!(v.get("parent").is_none());
        assert_eq!(v["op"], "CONNECT");
    }

    #[test]
    fn canonicalize_is_alphabetical() {
        let m: Map<String, Value> = [
            ("op", Value::String("X".into())),
            ("host", Value::String("a".into())),
        ].iter().map(|(k, v)| (k.to_string(), v.clone())).collect();
        let c = canonicalize(&m);
        // "host" sorts before "op"
        let host_pos = c.find("\"host\"").unwrap();
        let op_pos = c.find("\"op\"").unwrap();
        assert!(host_pos < op_pos);
    }

    #[test]
    fn canonicalize_is_compact() {
        let m: Map<String, Value> = [("op", Value::String("X".into()))]
            .iter().map(|(k, v)| (k.to_string(), v.clone())).collect();
        let c = canonicalize(&m);
        assert!(!c.contains(' '), "no whitespace: got {c:?}");
        assert_eq!(c, "{\"op\":\"X\"}");
    }

    #[test]
    fn canonicalize_is_insertion_order_independent() {
        let mut m1: Map<String, Value> = Map::new();
        m1.insert("a".to_string(), Value::String("1".into()));
        m1.insert("b".to_string(), Value::String("2".into()));
        let mut m2: Map<String, Value> = Map::new();
        m2.insert("b".to_string(), Value::String("2".into()));
        m2.insert("a".to_string(), Value::String("1".into()));
        assert_eq!(canonicalize(&m1), canonicalize(&m2));
    }

    #[test]
    fn sha256_hex_known_vector() {
        // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        assert_eq!(
            sha256_hex(""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        // SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        assert_eq!(
            sha256_hex("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn hash_chain_links_correctly() {
        let sid = format!("test-chain-{}-{}", std::process::id(), std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos());
        let writer = AuditWriter::open(&sid, false).unwrap();
        let mut e1 = Map::new();
        e1.insert("op".into(), serde_json::json!("CONNECT"));
        e1.insert("host".into(), serde_json::json!("a.com"));
        writer.append(e1).unwrap();
        let mut e2 = Map::new();
        e2.insert("op".into(), serde_json::json!("CONNECT"));
        e2.insert("host".into(), serde_json::json!("b.com"));
        writer.append(e2).unwrap();

        let path = audit_log_path(&sid);
        let content = std::fs::read_to_string(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        let lines: Vec<&str> = content.trim().lines().collect();
        assert_eq!(lines.len(), 2);

        let l1: Value = serde_json::from_str(lines[0]).unwrap();
        let l2: Value = serde_json::from_str(lines[1]).unwrap();

        // First leaf: parent is null.
        assert_eq!(l1["parent"], Value::Null);
        let h1 = l1["hash"].as_str().unwrap();

        // Second leaf: parent == hash of first.
        assert_eq!(l2["parent"], h1);

        // seq monotonic from 0.
        assert_eq!(l1["seq"], 0);
        assert_eq!(l2["seq"], 1);

        // Recompute hash of leaf 1 from its canonical body.
        let m1 = l1.as_object().unwrap().clone();
        let c1 = canonicalize(&m1);
        let recomputed1 = sha256_hex(&c1);
        assert_eq!(recomputed1, h1);
    }

    #[test]
    fn scan_existing_recovers_state() {
        let sid = format!("test-scan-{}-{}", std::process::id(), std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos());
        {
            let w = AuditWriter::open(&sid, false).unwrap();
            for host in ["a", "b", "c"] {
                let mut e = Map::new();
                e.insert("op".into(), serde_json::json!("CONNECT"));
                e.insert("host".into(), serde_json::json!(host));
                w.append(e).unwrap();
            }
        }
        let path = audit_log_path(&sid);
        let (last_hash, next_seq) = scan_existing(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        assert!(last_hash.is_some());
        assert_eq!(next_seq, 3);
    }

    #[test]
    fn secret_inject_schema_is_reserved() {
        // References SECRET_INJECT_SCHEMA so it isn't flagged dead_code; also
        // pins the reserved `secret.inject` event contract (D-5.2) so an
        // accidental rename or drop is caught. See the module doc comment for
        // the full schema.
        assert!(SECRET_INJECT_SCHEMA.contains("\"op\""), "schema must name the op field");
        assert!(SECRET_INJECT_SCHEMA.contains("\"secret.inject\""), "schema must reserve the secret.inject op");
        assert!(SECRET_INJECT_SCHEMA.contains("\"name\""), "schema must include the name field");
        // Hash-chain fields are added by AuditWriter::append; the schema
        // template should enumerate them so the contract is explicit.
        for key in ["\"seq\"", "\"ts\"", "\"hash\"", "\"parent\""] {
            assert!(
                SECRET_INJECT_SCHEMA.contains(key),
                "schema must enumerate the {key} hash-chain field"
            );
        }
    }

    #[test]
    fn strict_open_fails_on_unwritable_path() {
        // Block `create_dir_all` by placing a regular file where a directory
        // is required: a file at `blocker`, then a log path of
        // `blocker/subdir/test.ndjson`. `create_dir_all` can't make a
        // directory inside a file, so strict open must fail. Reliable on
        // every platform (no env-var or drive-letter assumptions).
        let mut blocker_parent = std::env::temp_dir();
        blocker_parent.push(format!(
            "sandbox-audit-blocker-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let blocker_file = blocker_parent.join("blocker");
        std::fs::create_dir_all(&blocker_parent).unwrap();
        std::fs::write(&blocker_file, b"x").unwrap();

        let log_path = blocker_file.join("subdir").join("test.ndjson");

        // Strict mode MUST refuse: create_dir_all fails because `blocker`
        // is a file, not a directory.
        let strict_res = AuditWriter::open_at(log_path.clone(), true);
        assert!(strict_res.is_err(), "strict open must fail on unwritable path");

        // Non-strict mode degrades gracefully (never returns Err).
        let lenient_res = AuditWriter::open_at(log_path, false);
        assert!(lenient_res.is_ok(), "non-strict open must degrade gracefully");

        // Clean up the blocker file + parent dir.
        let _ = std::fs::remove_file(&blocker_file);
        let _ = std::fs::remove_dir_all(&blocker_parent);
    }

    #[test]
    fn strict_append_fails_on_write_error() {
        // Open strict on a writable path inside a dedicated subdir we own,
        // then delete the whole subdir so the next `append` can't reopen the
        // file. Strict mode must surface that as `Err`; non-strict mode must
        // swallow it and return `Ok(())`.
        let mut own_dir = std::env::temp_dir();
        own_dir.push(format!(
            "sandbox-audit-strict-append-dir-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&own_dir).unwrap();
        let own_log = own_dir.join("test.ndjson");

        let strict_writer = AuditWriter::open_at(own_log.clone(), true)
            .expect("strict open in own dir succeeds");
        let lenient_writer = AuditWriter::open_at(own_log.clone(), false)
            .expect("non-strict open in own dir succeeds");

        // Delete the dedicated dir + its file. Now append can't open the
        // file (parent dir is gone).
        let _ = std::fs::remove_dir_all(&own_dir);

        let mut e = Map::new();
        e.insert("op".into(), serde_json::json!("CONNECT"));
        e.insert("host".into(), serde_json::json!("a.com"));

        let strict_res = strict_writer.append(e.clone());
        assert!(strict_res.is_err(), "strict append must fail when file can't be opened");

        let lenient_res = lenient_writer.append(e);
        assert!(lenient_res.is_ok(), "non-strict append must swallow the write error");

        // No cleanup needed: own_dir was already removed.
    }

    /// The chain is the product's evidence. Two appends that interleave must still
    /// produce ONE chain: seq in file order, every parent naming the previous leaf.
    /// This failed before the writer kept `last` and `seq` behind one lock - both
    /// threads read `None` and `verify` called the result tampered.
    #[test]
    fn concurrent_appends_produce_one_verifiable_chain() {
        use crate::audit::verify::{VerifyOutcome, verify_inner};
        use std::sync::Arc;

        let sid = format!(
            "test-concurrent-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        {
            let writer = Arc::new(AuditWriter::open(&sid, false).unwrap());
            let mut threads = Vec::new();
            for t in 0..4 {
                let w = Arc::clone(&writer);
                threads.push(std::thread::spawn(move || {
                    for i in 0..25 {
                        let mut e = Map::new();
                        e.insert("op".into(), serde_json::json!("CONNECT"));
                        e.insert("host".into(), serde_json::json!(format!("t{t}-{i}.example")));
                        w.append(e).unwrap();
                    }
                }));
            }
            for h in threads {
                h.join().unwrap();
            }
        }

        let path = audit_log_path(&sid);
        let content = std::fs::read_to_string(&path).unwrap();
        let (mut expected_seq, mut prev, mut leaves) = (0u64, None::<String>, 0);
        for line in content.lines() {
            let v: Value = serde_json::from_str(line).unwrap();
            assert_eq!(
                v["seq"].as_u64().unwrap(),
                expected_seq,
                "seq must follow file order even under concurrency"
            );
            assert_eq!(
                v["parent"].as_str().map(str::to_string),
                prev,
                "every leaf's parent must name the leaf written before it"
            );
            prev = v["hash"].as_str().map(str::to_string);
            expected_seq += 1;
            leaves += 1;
        }
        assert_eq!(leaves, 100, "no leaf may be lost");
        assert!(
            !matches!(verify_inner(&sid).unwrap(), VerifyOutcome::Tampered(_)),
            "an untampered log must never verify as tampered"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// A corrupt existing log is evidence, not a starting point. Extending it would
    /// emit a null parent after real leaves - the exact shape `verify` reports as
    /// tampering - so the writer refuses and leaves the bytes alone.
    #[test]
    fn an_unreadable_existing_chain_is_refused_not_extended() {
        let mut dir = std::env::temp_dir();
        dir.push(format!(
            "sandbox-audit-corrupt-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("session.ndjson");
        let original = "{\"op\":\"CONNECT\"}\nnot json at all\n";
        std::fs::write(&path, original).unwrap();

        let err = match AuditWriter::open_at(path.clone(), false) {
            Ok(_) => panic!("a corrupt chain must not be reopened for appending"),
            Err(e) => e,
        };
        assert!(
            format!("{err:#}").contains("refusing to extend"),
            "the refusal must say what to do: {err:#}"
        );
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            original,
            "refusing must not touch the evidence"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
