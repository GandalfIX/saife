//! Filter grammar for `sandbox audit show --filter "expr"`.
//!
//! Grammar (AC-4.13):
//!   filter  := clause ( "&" clause )*
//!   clause  := key ( "=" | "~=" | ">=" | "<=" ) value
//!   key     := "op" | "disposition" | "host" | "path" | "ts" | "pid" | "seq" | "source" | "scope" | "persisted"
//!   value   := bare-string (no & or = chars)
//!
//! Semantics:
//!   `=`  — exact string match (case-sensitive for op/disposition/source/scope,
//!          which are enum-like taxonomy values; case-insensitive otherwise).
//!          `persisted` is a boolean (`true`/`false`).
//!   `~=` — substring match (case-insensitive).
//!   `>=` / `<=` — for ts: ISO-8601 lexicographic; for seq/pid: integer.
//! Multiple clauses AND together.

use anyhow::{bail, Result};
use serde_json::Value;
use std::cmp::Ordering;

#[derive(Debug, Clone, PartialEq)]
enum Op { Eq, Sub, Gte, Lte }

#[derive(Debug, Clone)]
struct Clause {
    key: String,
    op: Op,
    value: String,
}

#[derive(Debug, Clone, Default)]
pub struct Filter {
    clauses: Vec<Clause>,
}

const KNOWN_KEYS: &[&str] = &[
    "op", "disposition", "host", "path", "ts", "pid", "seq", "source", "scope", "persisted",
];

impl Filter {
    /// Parse a filter expression. Empty string returns a Filter that matches
    /// everything.
    pub fn parse(expr: &str) -> Result<Self> {
        let expr = expr.trim();
        if expr.is_empty() {
            return Ok(Self::default());
        }
        let mut clauses = Vec::new();
        for (i, raw) in expr.split('&').enumerate() {
            let raw = raw.trim();
            if raw.is_empty() {
                bail!("empty clause at position {i}");
            }
            // Find the operator. Two-char operators must be checked before
            // one-char so `>=` is not parsed as `>`. The key is everything
            // before the operator; the value is everything after.
            let (key, op, value) = if let Some(idx) = raw.find("~=") {
                (raw[..idx].trim(), Op::Sub, raw[idx + 2..].trim())
            } else if let Some(idx) = raw.find(">=") {
                (raw[..idx].trim(), Op::Gte, raw[idx + 2..].trim())
            } else if let Some(idx) = raw.find("<=") {
                (raw[..idx].trim(), Op::Lte, raw[idx + 2..].trim())
            } else if let Some(idx) = raw.find('=') {
                (raw[..idx].trim(), Op::Eq, raw[idx + 1..].trim())
            } else {
                bail!("missing operator in clause `{raw}`");
            };
            if key.is_empty() {
                bail!("missing operator in clause `{raw}`");
            }
            if !KNOWN_KEYS.contains(&key) {
                bail!("unknown key `{key}`");
            }
            if value.is_empty() {
                bail!("value is empty in clause `{raw}`");
            }
            clauses.push(Clause { key: key.to_string(), op, value: value.to_string() });
        }
        Ok(Self { clauses })
    }

    /// Does this leaf match the filter?
    pub fn matches(&self, leaf: &Value) -> bool {
        if self.clauses.is_empty() {
            return true;
        }
        self.clauses.iter().all(|c| clause_matches(c, leaf))
    }
}

fn clause_matches(c: &Clause, leaf: &Value) -> bool {
    let obj = match leaf.as_object() {
        Some(o) => o,
        None => return false,
    };
    let actual = match obj.get(&c.key) {
        Some(v) => v,
        None => return false,
    };
    match c.op {
        Op::Eq => eq_match(&c.key, actual, &c.value),
        Op::Sub => sub_match(actual, &c.value),
        Op::Gte | Op::Lte => ordered_match(&c.key, c.op.clone(), actual, &c.value),
    }
}

fn eq_match(key: &str, actual: &Value, expected: &str) -> bool {
    if key == "persisted" {
        // boolean field; expected is "true"/"false" string
        let expected_bool = expected.eq_ignore_ascii_case("true");
        actual.as_bool().map(|b| b == expected_bool).unwrap_or(false)
    } else if key == "op" || key == "disposition" || key == "source" || key == "scope" {
        // case-sensitive for these enums
        actual.as_str().map(|s| s == expected).unwrap_or(false)
    } else {
        // case-insensitive for hosts/paths
        actual.as_str().map(|s| s.eq_ignore_ascii_case(expected)).unwrap_or(false)
    }
}

fn sub_match(actual: &Value, needle: &str) -> bool {
    actual.as_str()
        .map(|s| s.to_ascii_lowercase().contains(&needle.to_ascii_lowercase()))
        .unwrap_or(false)
}

fn ordered_match(key: &str, op: Op, actual: &Value, expected: &str) -> bool {
    if key == "ts" {
        // ISO-8601 lexicographic compare works for UTC Z-suffixed timestamps.
        let a = match actual.as_str() { Some(s) => s, None => return false };
        let ord = a.cmp(expected);
        match op {
            Op::Gte => ord != Ordering::Less,
            Op::Lte => ord != Ordering::Greater,
            _ => unreachable!(),
        }
    } else {
        // integer compare (seq, pid)
        let a = match actual.as_i64() { Some(n) => n, None => return false };
        let e: i64 = match expected.parse() { Ok(n) => n, Err(_) => return false };
        let ord = a.cmp(&e);
        match op {
            Op::Gte => ord != Ordering::Less,
            Op::Lte => ord != Ordering::Greater,
            _ => unreachable!(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn leaf(pairs: &[(&str, Value)]) -> Value {
        let m: serde_json::Map<String, Value> = pairs.iter().map(|(k, v)| (k.to_string(), v.clone())).collect();
        Value::Object(m)
    }

    #[test]
    fn empty_filter_matches_all() {
        let f = Filter::parse("").unwrap();
        assert!(f.matches(&leaf(&[("op", json!("CONNECT"))])));
        assert!(f.matches(&leaf(&[("op", json!("FILE_READ"))])));
    }

    #[test]
    fn op_exact_match() {
        let f = Filter::parse("op=CONNECT").unwrap();
        assert!(f.matches(&leaf(&[("op", json!("CONNECT"))])));
        assert!(!f.matches(&leaf(&[("op", json!("FILE_READ"))])));
    }

    #[test]
    fn disposition_exact_match_case_sensitive() {
        let f = Filter::parse("disposition=denied").unwrap();
        assert!(f.matches(&leaf(&[("disposition", json!("denied"))])));
        assert!(!f.matches(&leaf(&[("disposition", json!("DENIED"))])));
    }

    #[test]
    fn host_substring_case_insensitive() {
        let f = Filter::parse("host~=anthropic").unwrap();
        assert!(f.matches(&leaf(&[("host", json!("api.anthropic.com"))])));
        assert!(f.matches(&leaf(&[("host", json!("ANTHROPIC.com"))])));
        assert!(!f.matches(&leaf(&[("host", json!("example.com"))])));
    }

    #[test]
    fn two_clauses_and() {
        let f = Filter::parse("op=CONNECT&disposition=denied").unwrap();
        assert!(f.matches(&leaf(&[("op", json!("CONNECT")), ("disposition", json!("denied"))])));
        assert!(!f.matches(&leaf(&[("op", json!("CONNECT")), ("disposition", json!("allow"))])));
        assert!(!f.matches(&leaf(&[("op", json!("FILE_READ")), ("disposition", json!("denied"))])));
    }

    #[test]
    fn ts_gte_lexicographic() {
        let f = Filter::parse("ts>=2026-07-23T14:00:00Z").unwrap();
        assert!(f.matches(&leaf(&[("ts", json!("2026-07-23T14:30:00Z"))])));
        assert!(f.matches(&leaf(&[("ts", json!("2026-07-23T14:00:00Z"))])));
        assert!(!f.matches(&leaf(&[("ts", json!("2026-07-23T13:59:59Z"))])));
    }

    #[test]
    fn seq_integer_compare() {
        let f = Filter::parse("seq>=10").unwrap();
        assert!(f.matches(&leaf(&[("seq", json!(10))])));
        assert!(f.matches(&leaf(&[("seq", json!(100))])));
        assert!(!f.matches(&leaf(&[("seq", json!(9))])));
    }

    #[test]
    fn missing_key_does_not_match() {
        let f = Filter::parse("op=CONNECT").unwrap();
        assert!(!f.matches(&leaf(&[("host", json!("x"))])));
    }

    #[test]
    fn malformed_filter_errors() {
        assert!(Filter::parse("op").is_err());           // no operator
        assert!(Filter::parse("op=").is_err());          // no value
        assert!(Filter::parse("boguskey=x").is_err());   // unknown key
        assert!(Filter::parse("op=CONNECT&").is_err());  // trailing empty clause
    }

    #[test]
    fn source_eq_hard_deny_matches() {
        let f = Filter::parse("source=hard-deny").unwrap();
        assert!(f.matches(&leaf(&[("source", json!("hard-deny"))])));
        assert!(!f.matches(&leaf(&[("source", json!("allowlist"))])));
    }

    #[test]
    fn source_eq_allowlist_excludes_other_sources() {
        let f = Filter::parse("source=allowlist").unwrap();
        assert!(f.matches(&leaf(&[("source", json!("allowlist"))])));
        assert!(!f.matches(&leaf(&[("source", json!("hard-deny"))])));
        assert!(!f.matches(&leaf(&[("source", json!("default"))])));
    }

    #[test]
    fn source_eq_is_case_sensitive() {
        let f = Filter::parse("source=hard-deny").unwrap();
        assert!(f.matches(&leaf(&[("source", json!("hard-deny"))])));
        assert!(!f.matches(&leaf(&[("source", json!("HARD-DENY"))])));
    }

    #[test]
    fn scope_eq_matches() {
        let f = Filter::parse("scope=host").unwrap();
        assert!(f.matches(&leaf(&[("scope", json!("host"))])));
        assert!(!f.matches(&leaf(&[("scope", json!("suffix"))])));
    }

    #[test]
    fn persisted_eq_true_matches_only_persisted() {
        let f = Filter::parse("persisted=true").unwrap();
        assert!(f.matches(&leaf(&[("persisted", json!(true))])));
        assert!(!f.matches(&leaf(&[("persisted", json!(false))])));
    }

    #[test]
    fn persisted_eq_false_matches_only_unpersisted() {
        let f = Filter::parse("persisted=false").unwrap();
        assert!(f.matches(&leaf(&[("persisted", json!(false))])));
        assert!(!f.matches(&leaf(&[("persisted", json!(true))])));
    }
}
