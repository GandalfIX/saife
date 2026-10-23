//! Filter grammar for `saife audit show --filter "expr"`.
//!
//! Grammar (AC-4.13):
//!   filter  := clause ( "&" clause )*
//!   clause  := key ( "=" | "~=" | ">=" | "<=" ) value
//!   key     := "op" | "disposition" | "host" | "path" | "ts" | "pid" | "seq" | "source" | "scope" | "persisted" | "reason" | "suppressed" | "tier" | "tier_source" | "tier_needs_dacl_augmentation" | "elevated" | "proxy_endpoint" | "expected_tier" | "fs_workspace" | "fs_readwrite" | "fs_readonly" | "fs_deny"
//!   value   := bare-string (no & or = chars)
//!
//! Semantics:
//!   `=`  — exact string match (case-sensitive for op/disposition/source/scope,
//!          which are enum-like taxonomy values; case-insensitive otherwise).
//!          `persisted`/`elevated`/`tier_needs_dacl_augmentation` are booleans:
//!          `=true` / `=false`, and any other value is a parse error.
//!   `=` with the literal `null` (any key): the leaf's value for this key is JSON
//!          null, i.e. "nothing was established here" — for a boolean key that is
//!          NOT a synonym for `false`.
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

/// Every filterable leaf key.
///
/// `reason` (P2.1) and `suppressed` (P1.6) were added to the leaf without being
/// added here, so the two fields that name *why* a request was refused and *how
/// many* refusals a window stands for were unqueryable — the one place an operator
/// would look after an incident. `scope` keeps its own meaning (rule scope) and is
/// never a count.
const KNOWN_KEYS: &[&str] = &[
    "op",
    "disposition",
    "host",
    // Plugin facade (P4.1): the mount a FACADE leaf names. Filterable so an
    // operator can ask "did this session use the tngtech capability" without
    // reading the whole chain, and so a refusal is as findable as a relay.
    "mount",
    "path",
    "ts",
    "pid",
    "seq",
    "source",
    "scope",
    "persisted",
    "reason",
    "suppressed",
    // P2.3, the session-start leaf (ADR-0004 guardrail 2). `tier`/`tier_source`
    // are the enum-like taxonomy values, so they match case-sensitively like
    // `source`; the two booleans are real booleans in the leaf, and comparing
    // them as strings matches nothing — see `BOOL_KEYS`.
    "tier",
    "tier_source",
    "tier_needs_dacl_augmentation",
    "elevated",
    "proxy_endpoint",
    // The refusal leaf's counterpart to `tier`: what the session required.
    "expected_tier",
    // P3.5, the filesystem posture in the session-start leaf. The three lists are
    // JSON arrays; `=` matches any element and `~=` any element containing the
    // needle (see `ARRAY_KEYS`), so `fs_deny~=.ssh` asks the question an operator
    // actually asks.
    "fs_workspace",
    "fs_readwrite",
    "fs_readonly",
    "fs_deny",
];

/// Leaf keys whose value is a JSON **array of strings**.
///
/// Comparing them as scalars would match nothing, which is indistinguishable from
/// "no such leaf" — the same failure `BOOL_KEYS` exists to prevent.
const ARRAY_KEYS: &[&str] = &["fs_readwrite", "fs_readonly", "fs_deny"];

/// Leaf keys whose value is a JSON boolean, so `=true` / `=false` compare against
/// the boolean rather than a string.
///
/// `persisted` (P1.6) was the first; P2.3's `elevated` and
/// `tier_needs_dacl_augmentation` are the same shape. A bool compared as a string
/// silently matches nothing, which is indistinguishable from "no such leaf".
const BOOL_KEYS: &[&str] = &["persisted", "elevated", "tier_needs_dacl_augmentation"];

/// The value that means *this leaf established nothing* — JSON `null`.
///
/// It is a value for `=` on **every** key (P2.3 review), not a string to compare
/// and not a synonym for `false`. `null` is how the session-start leaf says "no
/// fact here", so a reader must be able to ask for it: without the literal,
/// `tier=null` (the Drop fallback root) matched nothing while
/// `tier_needs_dacl_augmentation=null` matched the leaves asserting `false`.
const NULL_LITERAL: &str = "null";

/// A boolean key's only legal `=` values. Anything else is refused at parse time
/// rather than coerced, because the coercion has no "unknown" input: every value
/// that is not `true` used to mean `false`.
const BOOL_VALUES: &[&str] = &["true", "false", NULL_LITERAL];

/// Enum-like taxonomy values: matched case-sensitively, because `Tier=Base`
/// is a different token from the one the leaf wrote, not a lenient spelling.
const ENUM_KEYS: &[&str] = &[
    "op",
    "disposition",
    "source",
    "scope",
    "tier",
    "tier_source",
    "expected_tier",
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
            // P2.3 review (item 4): a boolean key's `=` value is `true`, `false`
            // or `null`. The comparison used to read any other spelling as
            // `false`, so `elevated=yes` answered with every *unelevated* run — a
            // confidently wrong result for a typo the grammar can refuse.
            if op == Op::Eq && BOOL_KEYS.contains(&key) && !is_bool_value(value) {
                bail!(
                    "`{key}` is a boolean: compare it with `true`, `false` or `null`, not `{value}`"
                );
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
        Op::Sub => sub_match(&c.key, actual, &c.value),
        Op::Gte | Op::Lte => ordered_match(&c.key, c.op.clone(), actual, &c.value),
    }
}

/// Is `value` one of a boolean key's legal `=` spellings?
fn is_bool_value(value: &str) -> bool {
    BOOL_VALUES
        .iter()
        .any(|legal| value.eq_ignore_ascii_case(legal))
}

fn eq_match(key: &str, actual: &Value, expected: &str) -> bool {
    // `=null` asks "did this leaf establish nothing?" for ANY key, and the answer
    // is the leaf's own JSON null. It has to come first: the boolean branch below
    // used to read `null` as the string it is not, and coerce it to `false`.
    if expected == NULL_LITERAL {
        return actual.is_null();
    }
    if ARRAY_KEYS.contains(&key) {
        return array_any(actual, &|s| s.eq_ignore_ascii_case(expected));
    }
    if BOOL_KEYS.contains(&key) {
        // A boolean field. The value was already refused at parse time unless it
        // is `true`/`false` (or `null`, handled above), so this cannot silently
        // answer a typo with `false`.
        let Some(want) = parse_bool(expected) else {
            return false;
        };
        actual.as_bool() == Some(want)
    } else if ENUM_KEYS.contains(&key) {
        // case-sensitive for these enums
        actual.as_str().map(|s| s == expected).unwrap_or(false)
    } else {
        // case-insensitive for hosts/paths
        actual.as_str().map(|s| s.eq_ignore_ascii_case(expected)).unwrap_or(false)
    }
}

/// `true`/`false` in any case; `None` for anything else (including `null`, which
/// [`eq_match`] answers before it gets here).
fn parse_bool(value: &str) -> Option<bool> {
    if value.eq_ignore_ascii_case("true") {
        Some(true)
    } else if value.eq_ignore_ascii_case("false") {
        Some(false)
    } else {
        None
    }
}

fn sub_match(key: &str, actual: &Value, needle: &str) -> bool {
    let contains = |s: &str| s.to_ascii_lowercase().contains(&needle.to_ascii_lowercase());
    if ARRAY_KEYS.contains(&key) {
        return array_any(actual, &contains);
    }
    actual.as_str().map(contains).unwrap_or(false)
}

/// Does any string element of `actual` satisfy `pred`? A non-array (or an array
/// with no string elements) satisfies nothing.
fn array_any(actual: &Value, pred: &dyn Fn(&str) -> bool) -> bool {
    actual
        .as_array()
        .map(|items| items.iter().filter_map(Value::as_str).any(pred))
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

    /// P2.1 review (item d): `reason` and `suppressed` are in the leaf but were not
    /// filterable, so the two fields an incident reader actually needs to select on
    /// (`reason=prompt_budget_exhausted`, `suppressed>=1`) were a parse error.
    #[test]
    fn reason_and_suppressed_are_filterable_keys() {
        let by_reason = Filter::parse("reason=prompt_abandoned_capacity").unwrap();
        assert!(by_reason.matches(&leaf(&[("reason", json!("prompt_abandoned_capacity"))])));
        assert!(!by_reason.matches(&leaf(&[("reason", json!("prompt_budget_exhausted"))])));

        let by_reason_substring = Filter::parse("reason~=no_dialog").unwrap();
        assert!(by_reason_substring.matches(&leaf(&[("reason", json!("no_dialog_backend"))])));

        let by_suppressed = Filter::parse("suppressed>=12").unwrap();
        assert!(by_suppressed.matches(&leaf(&[("suppressed", json!(12))])));
        assert!(!by_suppressed.matches(&leaf(&[("suppressed", json!(11))])));

        // Combined with a taxonomy key, as a reader would write it.
        let combined = Filter::parse("op=CONNECT&reason=no_dialog_backend").unwrap();
        assert!(combined.matches(&leaf(&[
            ("op", json!("CONNECT")),
            ("reason", json!("no_dialog_backend")),
        ])));
        // A leaf that carries neither (every leaf written before P1.6/P2.1 has a
        // null `reason` or `suppressed`) must not MATCH an equality clause, and must
        // not blow up.
        assert!(!by_reason.matches(&leaf(&[("reason", json!(null))])));
    }

    /// P2.3: the session-start leaf's tier facts are exactly what an incident
    /// reader selects on ("which sessions ran degraded?"), so they must be
    /// filterable keys — `tier`/`tier_source` as the enum-like taxonomy values
    /// they are, the two booleans as booleans (a bool leaf field compared as a
    /// string never matches anything), and the endpoint like a host.
    ///
    /// A `null` fact (the fallback leaf, or a probe that stated nothing) must match
    /// no equality clause and must not panic.
    #[test]
    fn session_start_tier_facts_are_filterable() {
        let by_tier = Filter::parse("tier=appcontainer-dacl").unwrap();
        assert!(by_tier.matches(&leaf(&[("tier", json!("appcontainer-dacl"))])));
        assert!(!by_tier.matches(&leaf(&[("tier", json!("base-container"))])));
        // Enum-like: a taxonomy value is not case-folded for the reader's comfort.
        assert!(!by_tier.matches(&leaf(&[("tier", json!("AppContainer-DACL"))])));

        let by_source = Filter::parse("tier_source=structural").unwrap();
        assert!(by_source.matches(&leaf(&[("tier_source", json!("structural"))])));
        assert!(!by_source.matches(&leaf(&[("tier_source", json!("probe"))])));

        let needs_dacl = Filter::parse("tier_needs_dacl_augmentation=true").unwrap();
        assert!(needs_dacl.matches(&leaf(&[("tier_needs_dacl_augmentation", json!(true))])));
        assert!(!needs_dacl.matches(&leaf(&[("tier_needs_dacl_augmentation", json!(false))])));
        assert!(
            !needs_dacl.matches(&leaf(&[("tier_needs_dacl_augmentation", json!(null))])),
            "`null` is unknown, not `true`"
        );

        let unelevated = Filter::parse("elevated=false").unwrap();
        assert!(unelevated.matches(&leaf(&[("elevated", json!(false))])));
        assert!(!unelevated.matches(&leaf(&[("elevated", json!(true))])));

        let by_endpoint = Filter::parse("proxy_endpoint=127.0.0.1:41234").unwrap();
        assert!(by_endpoint.matches(&leaf(&[("proxy_endpoint", json!("127.0.0.1:41234"))])));
        assert!(!by_endpoint.matches(&leaf(&[("proxy_endpoint", json!(null))])));

        // As a reader would actually write it: the root leaf of a degraded session.
        let combined = Filter::parse("op=SESSION_START&tier=appcontainer-dacl").unwrap();
        assert!(combined.matches(&leaf(&[
            ("op", json!("SESSION_START")),
            ("tier", json!("appcontainer-dacl")),
        ])));
    }

    /// P2.3 review (item 4): `=null` is the only query for a fact nobody
    /// established, and it has to mean *the leaf's value is JSON null* for every
    /// key — not "the string `null`", and certainly not `false`.
    ///
    /// Before the fix `eq_match` coerced every value except `true` to `false` for
    /// the boolean keys, so `elevated=null` returned the *unelevated* runs and
    /// `tier_needs_dacl_augmentation=null` returned the leaves asserting `false`;
    /// `tier=null` (an enum key) matched nothing at all. The Drop fallback leaf —
    /// the one leaf that says "this run established nothing" — was unqueryable.
    #[test]
    fn null_matches_only_a_leaf_that_established_nothing() {
        let fallback = leaf(&[
            ("op", json!("SESSION_START")),
            ("tier", json!(null)),
            ("tier_source", json!(null)),
            ("tier_needs_dacl_augmentation", json!(null)),
            ("elevated", json!(null)),
            ("proxy_endpoint", json!(null)),
        ]);

        let by_tier = Filter::parse("tier=null").unwrap();
        assert!(
            by_tier.matches(&fallback),
            "`tier=null` must select the fallback root"
        );
        assert!(!by_tier.matches(&leaf(&[("tier", json!("appcontainer-dacl"))])));

        let by_source = Filter::parse("tier_source=null").unwrap();
        assert!(by_source.matches(&fallback));
        assert!(!by_source.matches(&leaf(&[("tier_source", json!("structural"))])));

        let by_dacl = Filter::parse("tier_needs_dacl_augmentation=null").unwrap();
        assert!(by_dacl.matches(&fallback));
        assert!(
            !by_dacl.matches(&leaf(&[("tier_needs_dacl_augmentation", json!(false))])),
            "`false` is a measurement; unknown is the absence of one"
        );

        let by_elevated = Filter::parse("elevated=null").unwrap();
        assert!(by_elevated.matches(&leaf(&[("elevated", json!(null))])));
        assert!(
            !by_elevated.matches(&leaf(&[("elevated", json!(false))])),
            "`elevated=false` is an unelevated run, not an unknown one"
        );
        assert!(!by_elevated.matches(&leaf(&[("elevated", json!(true))])));
        // A leaf that does not carry the key at all is not a null-valued leaf.
        assert!(!by_elevated.matches(&leaf(&[("op", json!("CONNECT"))])));

        // `null` works for a non-tier key too: it is a value, not a taxonomy term.
        assert!(Filter::parse("proxy_endpoint=null")
            .unwrap()
            .matches(&fallback));
    }

    /// P2.3 review (item 4), parse half: a boolean key takes `true`, `false` or
    /// `null`. Anything else used to be silently coerced to `false`, so
    /// `elevated=yes` returned every *unelevated* run — a wrong answer to a
    /// question the grammar could have rejected outright.
    #[test]
    fn a_bool_key_rejects_a_value_that_is_not_true_false_or_null() {
        for bad in [
            "elevated=yes",
            "persisted=1",
            "tier_needs_dacl_augmentation=unknown",
            "elevated=TRUE!", // close to `true`, still not a boolean
        ] {
            let err = Filter::parse(bad).expect_err(&format!("`{bad}` must be a parse error"));
            assert!(
                err.to_string().contains("true"),
                "the error should name the legal spellings: {err}"
            );
        }
        for good in [
            "elevated=true",
            "elevated=false",
            "elevated=null",
            "persisted=true",
            "tier_needs_dacl_augmentation=null",
        ] {
            assert!(Filter::parse(good).is_ok(), "`{good}` must parse");
        }
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
        // P4.1: the facade leaf's key is part of the filter grammar.
        assert!(Filter::parse("mount=tngtech").is_ok());
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

    /// P3.5: `fs_*` values are arrays. `~=` asks "did any granted/denied path
    /// contain this?" — the question an operator asks after an incident.
    #[test]
    fn array_keys_match_any_element() {
        let deny = leaf(&[("fs_deny", json!([r"C:\Users\u\.ssh", r"C:\Users\u\.aws"]))]);

        let sub = Filter::parse("fs_deny~=.SSH").unwrap();
        assert!(sub.matches(&deny), "substring, case-insensitive, any element");

        let eq = Filter::parse(r"fs_deny=C:\Users\u\.aws").unwrap();
        assert!(eq.matches(&deny), "exact match on a non-first element");

        let miss = Filter::parse("fs_deny~=.gnupg").unwrap();
        assert!(!miss.matches(&deny), "no element contains it");

        // A scalar where an array is expected, and a missing key, both match
        // nothing — never a silent `true`.
        let scalar = leaf(&[("fs_deny", json!("not-an-array"))]);
        assert!(!sub.matches(&scalar));
        assert!(!sub.matches(&leaf(&[("host", json!("x"))])));
    }

    #[test]
    fn persisted_eq_false_matches_only_unpersisted() {
        let f = Filter::parse("persisted=false").unwrap();
        assert!(f.matches(&leaf(&[("persisted", json!(false))])));
        assert!(!f.matches(&leaf(&[("persisted", json!(true))])));
    }
}
