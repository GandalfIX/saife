//! US-4a audit core: hash-chain NDJSON leaves, canonicalization, hashing.
//! This module grows across tasks; for now it holds the pure canonicalization
//! logic. The existing writer code from US-3 is folded in by Task 5.

pub mod filter;
pub mod show;
pub mod verify;

use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

static SEQ: AtomicU64 = AtomicU64::new(0);

pub fn audit_log_path(session_id: &str) -> PathBuf {
    let local = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    let dir = local.join("sandbox").join("audit");
    let _ = std::fs::create_dir_all(&dir);
    dir.join(format!("{session_id}.ndjson"))
}

#[derive(Debug, Clone, Copy)]
pub enum Disposition { Allow, Deny }

impl Disposition {
    fn as_str(&self) -> &'static str { match self { Self::Allow => "allow", Self::Deny => "deny" } }
}

pub fn emit_connect(
    session_id: &str,
    host: &str,
    port: u16,
    disposition: Disposition,
    reason: Option<&str>,
) {
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let ts = iso8601_utc();
    let event = serde_json::json!({
        "ts": ts,
        "seq": seq,
        "op": "CONNECT",
        "host": host,
        "port": port,
        "disposition": disposition.as_str(),
        "reason": reason,
    });
    let mut line = serde_json::to_string(&event).unwrap_or_else(|_| "{}".into());
    line.push('\n');

    if std::env::var_os("SANDBOX_DIAG").is_some() {
        eprint!("[proxy] {line}");
    }
    let path = audit_log_path(session_id);
    if let Ok(mut f) = std::fs::OpenOptions::new().append(true).create(true).open(&path) {
        let _ = f.write_all(line.as_bytes());
    }
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
    serde_json::to_string(&btree).unwrap_or_else(|_| "{}".to_string())
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
}
