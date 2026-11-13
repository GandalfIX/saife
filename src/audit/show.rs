//! `saife audit show <sid> [--json] [--filter "expr"]`

use std::fmt::Write as _;
use std::io::Write;
use anyhow::{bail, Result};

use super::filter::Filter;

pub fn run_show(session_id: &str, json: bool, filter_expr: Option<&str>) -> i32 {
    match run_show_inner(session_id, json, filter_expr) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("[saife] audit show: {e:#}");
            1
        }
    }
}

fn run_show_inner(session_id: &str, json: bool, filter_expr: Option<&str>) -> Result<i32> {
    // H4: validate before `audit_log_path` joins the id (same shape as `verify`).
    let session_id = super::normalize_session_id(session_id)?;
    let path = super::audit_log_path(&session_id);
    if !path.exists() {
        bail!("no audit log for session `{session_id}` at {}", path.display());
    }
    let content = std::fs::read_to_string(&path)?;

    let filter = match filter_expr {
        Some(expr) => Some(Filter::parse(expr)?),
        None => None,
    };

    if json {
        // Raw NDJSON dump (filtered). Pipes directly to jq -c.
        let stdout = std::io::stdout();
        let mut out = stdout.lock();
        for line in content.lines() {
            if line.trim().is_empty() { continue; }
            let v: serde_json::Value = serde_json::from_str(line)
                .map_err(|e| anyhow::anyhow!(
                    "invalid JSON in log at line `{}`: {e}",
                    truncate_for_error(line)
                ))?;
            if filter.as_ref().is_none_or(|f| f.matches(&v)) {
                writeln!(out, "{line}")?;
            }
        }
        return Ok(0);
    }

    // Human-readable summary.
    let mut events: Vec<serde_json::Value> = Vec::new();
    for line in content.lines() {
        if line.trim().is_empty() { continue; }
        let v: serde_json::Value = serde_json::from_str(line)
            .map_err(|e| anyhow::anyhow!("invalid JSON in log: {e}"))?;
        events.push(v);
    }
    let filtered: Vec<&serde_json::Value> = events.iter()
        .filter(|v| filter.as_ref().is_none_or(|f| f.matches(v)))
        .collect();

    print!("{}", render_summary(&session_id, &filtered));
    Ok(0)
}

/// H4 (verdict doc). A malformed log line was embedded into the error message
/// verbatim, so a CI-injected payload could pour an unbounded line into
/// same-user stderr. Bounded to a character count; the `... (truncated)` marker
/// keeps it diagnosable.
fn truncate_for_error(line: &str) -> String {
    const MAX: usize = 160;
    let taken: Vec<char> = line.chars().take(MAX + 1).collect();
    if taken.len() <= MAX {
        line.to_string()
    } else {
        let mut s: String = taken[..MAX].iter().collect();
        s.push_str("... (truncated)");
        s
    }
}

pub(crate) fn render_summary(session_id: &str, events: &[&serde_json::Value]) -> String {
    let mut out = String::new();
    writeln!(out, "Session {session_id}").unwrap();
    if let Some(first) = events.first()
        && let Some(ts) = first.get("ts").and_then(|t| t.as_str()) {
            writeln!(out, "Started  {ts}").unwrap();
        }

    // Events by type.
    let mut by_op: std::collections::BTreeMap<String, (usize, usize)> = std::collections::BTreeMap::new();
    for e in events {
        let op = e.get("op").and_then(|x| x.as_str()).unwrap_or("?").to_string();
        let entry = by_op.entry(op).or_insert((0, 0));
        entry.0 += 1;
        let denied = e.get("disposition").and_then(|x| x.as_str()) == Some("deny");
        if denied { entry.1 += 1; }
    }
    writeln!(out).unwrap();
    writeln!(out, "Events by type:").unwrap();
    if by_op.is_empty() {
        writeln!(out, "  (none)").unwrap();
    } else {
        for (op, (total, denied)) in &by_op {
            let allowed = total - denied;
            writeln!(out, "  {op:<10} {total:>4}  ({allowed} allowed, {denied} denied)").unwrap();
        }
    }

    // Denied operations.
    let denies: Vec<&serde_json::Value> = events.iter()
        .filter(|v| v.get("disposition").and_then(|x| x.as_str()) == Some("deny"))
        .copied()
        .collect();
    if !denies.is_empty() {
        writeln!(out).unwrap();
        writeln!(out, "Denied operations:").unwrap();
        for d in &denies {
            let op = d.get("op").and_then(|x| x.as_str()).unwrap_or("?");
            let reason = d.get("reason").and_then(|x| x.as_str()).unwrap_or("");
            match op {
                "CONNECT" => {
                    let host = d.get("host").and_then(|x| x.as_str()).unwrap_or("?");
                    let port = d.get("port").and_then(|x| x.as_u64()).unwrap_or(0);
                    writeln!(out, "  {op} {host}:{port}  reason={reason}").unwrap();
                }
                _ => {
                    let target = d.get("path").and_then(|x| x.as_str())
                        .or_else(|| d.get("target").and_then(|x| x.as_str()))
                        .unwrap_or("?");
                    writeln!(out, "  {op} {target}  reason={reason}").unwrap();
                }
            }
        }
    }

    // Hosts contacted (allowed).
    //
    // M8 (security review 2026-11-09): a host counts only when its request's
    // TERMINAL leaf is `allow`. An allow leaf is written before the dial that
    // can still deny the same request (a name resolving to loopback or a
    // LAN range), so counting every allow leaf claimed a contact that never
    // happened. Leaves are grouped by `req_id`; the last leaf for an id is its
    // terminal disposition. Leaves without a `req_id` (older logs, or the
    // credential-less refusal leaves whose host is `<unknown>`) keep the legacy
    // shape: counted when their disposition is allow.
    let mut by_request: std::collections::BTreeMap<u64, (String, bool)> =
        std::collections::BTreeMap::new();
    let mut legacy: Vec<(String, bool)> = Vec::new();
    for e in events {
        if e.get("op").and_then(|x| x.as_str()) != Some("CONNECT") {
            continue;
        }
        let host = e.get("host").and_then(|x| x.as_str()).unwrap_or("?");
        let port = e.get("port").and_then(|x| x.as_u64()).unwrap_or(0);
        let key = format!("{host}:{port}");
        let allow = e.get("disposition").and_then(|x| x.as_str()) == Some("allow");
        match e.get("req_id").and_then(|x| x.as_u64()) {
            // `insert` overwrites, so the final leaf for an id wins — that is
            // the terminal disposition the reader needs.
            Some(id) => {
                by_request.insert(id, (key, allow));
            }
            None => legacy.push((key, allow)),
        }
    }
    let mut hosts: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    for (key, allow) in by_request.values().chain(legacy.iter()) {
        if *allow {
            *hosts.entry(key.clone()).or_insert(0) += 1;
        }
    }
    if !hosts.is_empty() {
        writeln!(out).unwrap();
        writeln!(out, "Hosts contacted (allowed):").unwrap();
        for (h, n) in &hosts {
            writeln!(out, "  {h}  x{n}").unwrap();
        }
    }

    // Root + signature status (best-effort: check for .root and .sig files).
    // L-I: never print "OK" from file existence alone - `show` does not verify
    // the signature. A reader of the summary must be told to run `verify`.
    writeln!(out).unwrap();
    let root_path = super::audit_log_path(session_id).with_extension("root");
    let sig_path = super::audit_log_path(session_id).with_extension("sig");
    if let Some(root) = events.last().and_then(|e| e.get("hash").and_then(|x| x.as_str())) {
        let short: String = root.chars().take(8).collect();
        if root_path.exists() && sig_path.exists() {
            writeln!(out, "Root    {short}...").unwrap();
            writeln!(
                out,
                "Sig     PRESENT (not verified; run `saife audit verify`)"
            ).unwrap();
        } else {
            writeln!(out, "Root    {short}... (NOT COMMITTED — session did not end cleanly?)").unwrap();
            writeln!(out, "Sig     ABSENT").unwrap();
        }
    } else {
        writeln!(out, "Root    (no events)").unwrap();
    }

    writeln!(out).unwrap();
    writeln!(out, "Total events: {}", events.len()).unwrap();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn show_missing_session_errors() {
        let rc = run_show("nonexistent-sid-12345678", false, None);
        assert_ne!(rc, 0);
    }

    /// H4 (verdict doc: partial, Medium — real but deferred). The reader joins
    /// the raw `--sid` into the audit directory (`audit_log_path`), so
    /// `audit show` reads an attacker-chosen `*.ndjson` outside it.
    ///
    /// RED until H4 lands (verdict doc): validation at this reader entry point
    /// must make every case below return `Err` BEFORE any file is opened.
    /// Each traversal case plants a readable log where the path resolves to,
    /// so today the read SUCCEEDS (`Ok(0)`) and this test is red; after the
    /// fix the planted file is never read.
    ///
    /// `run_show_inner`, not `run_show`: it is the reader entry point the CLI
    /// wrapper only maps to an exit code, and it returns the `Err` the fix
    /// will produce.
    #[test]
    fn show_refuses_a_traversal_session_id_before_reading_any_file() {
        let pid = std::process::id();
        // (1) Relative traversal: `..\..\x` resolves, via the OS, to a sibling
        // of (above) the audit directory.
        let relative = format!("..\\..\\h4-show-{pid}");
        // (2) Absolute path: `Path::join` REPLACES the audit directory.
        let absolute = std::env::temp_dir()
            .join(format!("h4-show-abs-{pid}"))
            .to_string_lossy()
            .into_owned();
        // (3) UNC path: no share is created, so today's answer is "no audit
        // log". The assertion is that the refusal names the SESSION ID — i.e.
        // it happened before any path lookup — not that a file went missing.
        let unc = format!("\\\\h4-nonexistent\\share\\h4-show-{pid}");

        let planted: Vec<(&str, std::path::PathBuf)> = vec![
            (relative.as_str(), crate::audit::audit_log_path(&relative)),
            (absolute.as_str(), crate::audit::audit_log_path(&absolute)),
        ];
        for (_, path) in &planted {
            std::fs::write(path, "{\"op\":\"CONNECT\",\"host\":\"planted.example\"}\n")
                .expect("plant a readable log at the traversal target");
        }

        let results = [
            run_show_inner(&relative, false, None).map_err(|e| format!("{e:#}")),
            run_show_inner(&absolute, false, None).map_err(|e| format!("{e:#}")),
            run_show_inner(&unc, false, None).map_err(|e| format!("{e:#}")),
        ];
        for (_, path) in &planted {
            let _ = std::fs::remove_file(path);
        }

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
            Ok(_) => panic!("a UNC sid must be refused, got {results:?}"),
        }
    }

    /// L-I (verdict doc: confirmed, Low). `audit show` printed `Sig OK` from
    /// the mere existence of a `.sig` file and never checked it. The label must
    /// not claim a verification that did not happen.
    #[test]
    fn show_reports_a_signature_as_present_not_ok() {
        let sid = format!(
            "li-sig-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let log = crate::audit::audit_log_path(&sid);
        std::fs::write(
            &log,
            "{\"op\":\"CONNECT\",\"host\":\"a.example\",\"hash\":\"abcdef0123456789\",\
             \"ts\":\"2026-11-09T00:00:00Z\",\"seq\":0}\n",
        )
        .unwrap();
        std::fs::write(log.with_extension("root"), "abcdef0123456789").unwrap();
        // Present, but patently not a signature: show must not look at it and
        // must not call it OK either way.
        std::fs::write(log.with_extension("sig"), "not a signature at all").unwrap();

        let content = std::fs::read_to_string(&log).unwrap();
        let events: Vec<serde_json::Value> = vec![
            serde_json::from_str(content.lines().next().unwrap()).unwrap(),
        ];
        let refs: Vec<&serde_json::Value> = events.iter().collect();
        let out = render_summary(&sid, &refs);

        let _ = std::fs::remove_file(&log);
        let _ = std::fs::remove_file(log.with_extension("root"));
        let _ = std::fs::remove_file(log.with_extension("sig"));

        assert!(
            !out.contains("OK"),
            "show must not claim a verification it never did: {out}"
        );
        assert!(
            out.contains("PRESENT"),
            "the existing signature must still be reported: {out}"
        );
        assert!(
            out.contains("audit verify"),
            "the summary must point at the command that actually verifies: {out}"
        );
    }

    /// H4 (verdict doc). The `--json` error path embedded the whole malformed
    /// line, so an untrusted sid/content could pour an unbounded payload into
    /// the operator's stderr. The message stays diagnostic but bounded.
    #[test]
    fn show_truncates_a_malformed_line_in_its_error() {
        let sid = format!(
            "h4-trunc-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let log = crate::audit::audit_log_path(&sid);
        std::fs::write(&log, format!("{{\"op\":{}{}\n", "\"broken", "x".repeat(4000)))
            .unwrap();

        let err = run_show_inner(&sid, true, None).expect_err("invalid JSON must be an error");
        let msg = format!("{err:#}");
        let _ = std::fs::remove_file(&log);

        assert!(
            msg.len() < 500,
            "the raw line must be bounded in the error, got {} chars",
            msg.len()
        );
        assert!(
            !msg.contains(&"x".repeat(200)),
            "the raw line must be truncated, not echoed whole"
        );
    }

    /// M8 follow-up (2026-11-09 verdict doc): `req_id` is now a filter key,
    /// so `audit show --filter 'req_id=17'` selects exactly the two leaves of
    /// request 17 (the admission allow and the post-dial deny) and neither
    /// leaf of request 18. This is `run_show_inner`'s pipeline — parse the
    /// filter, apply it to every leaf, render — exercised on the same leaf
    /// chain the M8 counting test uses, so the filter and the terminal-
    /// disposition counting are proven to compose: request 17's terminal leaf
    /// is `deny`, so it still counts as no contact under the filter.
    #[test]
    fn show_filter_req_id_selects_one_requests_leaves() {
        let events: Vec<serde_json::Value> = vec![
            // Request 17: admitted, then refused at the dial.
            serde_json::json!({"op":"CONNECT","host":"10.0.0.1","port":443,
                               "disposition":"allow","req_id":17,"seq":0}),
            serde_json::json!({"op":"CONNECT","host":"10.0.0.1","port":443,
                               "disposition":"deny","reason":"lan_refused",
                               "req_id":17,"seq":1}),
            // Request 18: served, and filtered out.
            serde_json::json!({"op":"CONNECT","host":"api.example.com","port":443,
                               "disposition":"allow","req_id":18,"seq":2}),
        ];
        let filter = super::super::filter::Filter::parse("req_id=17").unwrap();
        let filtered: Vec<&serde_json::Value> =
            events.iter().filter(|v| filter.matches(v)).collect();
        assert_eq!(filtered.len(), 2, "exactly request 17's two leaves");
        let out = render_summary("reqid-filter", &filtered);

        assert!(
            !out.contains("api.example.com"),
            "request 18 is filtered out: {out}"
        );
        assert!(
            out.contains("lan_refused"),
            "request 17's post-dial deny is shown: {out}"
        );
        assert!(
            !out.contains("10.0.0.1:443  x"),
            "request 17's terminal leaf is deny, so it is no contact: {out}"
        );
    }
}

    /// M8 (verdict: confirmed, Medium). `show` counted every `allow` leaf as a
    /// contacted host, so a request whose admission was allowed and whose dial
    /// was then denied read as a contact. Counting is now per request: the
    /// terminal leaf (last for a `req_id`) decides. A leaf without an id keeps
    /// the legacy shape so an older log still reads the way it was written.
    #[test]
    fn show_counts_only_a_terminal_allow_as_a_contacted_host() {
        let sid = "m8-show-counting";
        let events: Vec<serde_json::Value> = vec![
            // Request 1: admitted, then refused at the dial. NOT a contact.
            serde_json::json!({"op":"CONNECT","host":"10.0.0.1","port":443,
                               "disposition":"allow","req_id":1,"seq":0}),
            serde_json::json!({"op":"CONNECT","host":"10.0.0.1","port":443,
                               "disposition":"deny","reason":"lan_refused",
                               "req_id":1,"seq":1}),
            // Request 2: served. Counted once.
            serde_json::json!({"op":"CONNECT","host":"api.example.com","port":443,
                               "disposition":"allow","req_id":2,"seq":2}),
            // Request 3: same host, also served. Counted once more.
            serde_json::json!({"op":"CONNECT","host":"api.example.com","port":443,
                               "disposition":"allow","req_id":3,"seq":3}),
            // A pre-M8 leaf (no req_id): legacy shape, still counted.
            serde_json::json!({"op":"CONNECT","host":"legacy.example","port":8443,
                               "disposition":"allow","seq":4}),
            // A refusal leaf with no id and no contact.
            serde_json::json!({"op":"CONNECT","host":"<unknown>","port":0,
                               "disposition":"deny","reason":"no_token","seq":5}),
        ];
        let refs: Vec<&serde_json::Value> = events.iter().collect();
        let out = render_summary(sid, &refs);

        assert!(
            !out.contains("10.0.0.1:443  x"),
            "a request whose terminal leaf is deny is not a contact: {out}"
        );
        assert!(
            out.contains("api.example.com:443  x2"),
            "two served requests to one host count twice: {out}"
        );
        assert!(
            out.contains("legacy.example:8443  x1"),
            "a leaf without a req_id keeps the legacy shape: {out}"
        );
        assert!(
            !out.contains("<unknown>:0  x"),
            "a credential-less refusal is never a contacted host: {out}"
        );
    }

    /// `show` exits 0 on a readable log and 1 without one, and the error names
    /// the session. The constant-return mutants claim success for a missing log
    /// (or throw a good one's code away); the `!` mutant replaces the helpful
    /// error with a bare io failure.
    #[test]
    fn show_exit_codes_and_errors_follow_the_session_state() {
        let sid = "mutant-gaps-show-exit";
        let path = crate::audit::audit_log_path(sid);
        std::fs::create_dir_all(path.parent().unwrap()).ok();
        std::fs::write(
            &path,
            "{\"op\":\"CONNECT\",\"host\":\"a.example\",\"port\":443,\"disposition\":\"allow\",\"ts\":\"2026-11-12T00:00:00Z\",\"seq\":0}\n",
        )
        .unwrap();
        let ok = run_show(sid, false, None);
        let _ = std::fs::remove_file(&path);
        assert_eq!(ok, 0, "a readable log exits 0");

        let missing = "mutant-gaps-show-missing";
        assert_eq!(run_show(missing, false, None), 1, "no log is an error exit");
        let err = run_show_inner(missing, false, None)
            .expect_err("a missing log is an error")
            .to_string();
        assert!(
            err.contains("no audit log for session"),
            "the error names the missing session: {err}"
        );
    }

    /// The bound is a CHARACTER count and the marker is part of the contract: a
    /// CI-injected payload must not pour an unbounded line into stderr, and a
    /// multibyte line must not be cut mid-character.
    #[test]
    fn truncate_for_error_bounds_the_line_and_marks_it() {
        let at_limit = "x".repeat(160);
        assert_eq!(
            truncate_for_error(&at_limit),
            at_limit,
            "a line at the limit is returned unchanged"
        );

        let over = "y".repeat(161);
        let cut = truncate_for_error(&over);
        assert!(
            cut.ends_with("... (truncated)"),
            "a cut line carries the marker: {cut}"
        );
        assert_eq!(
            cut.chars().filter(|c| *c == 'y').count(),
            160,
            "exactly MAX characters survive"
        );

        let wide = "ä".repeat(200);
        let cut_wide = truncate_for_error(&wide);
        assert_eq!(
            cut_wide.chars().filter(|c| *c == 'ä').count(),
            160,
            "chars, not bytes: multibyte lines are cut on a character boundary"
        );
    }

    /// The summary's counts are the incident reader's first number: flipping the
    /// `deny` comparison moves a denial into the allowed column. The denial list
    /// must also keep its two shapes - a CONNECT denial names host:port, an fs
    /// denial names the path.
    #[test]
    fn render_summary_counts_and_renders_both_denial_shapes() {
        let allow = serde_json::json!({
            "op": "CONNECT", "host": "ok.example", "port": 443, "disposition": "allow"
        });
        let deny_connect = serde_json::json!({
            "op": "CONNECT", "host": "evil.example", "port": 8443,
            "disposition": "deny", "reason": "domain_not_allowed"
        });
        let deny_fs = serde_json::json!({
            "op": "fs.write", "path": "C:\\secret", "disposition": "deny",
            "reason": "deny_rule"
        });
        let events: Vec<&serde_json::Value> = vec![&allow, &deny_connect, &deny_fs];
        let out = render_summary("sid-render", &events);
        assert!(out.contains("CONNECT"), "the summary lists the op: {out}");
        assert!(
            out.contains("2  (1 allowed, 1 denied)"),
            "one allow and one deny for CONNECT: {out}"
        );
        assert!(
            out.contains("evil.example:8443  reason=domain_not_allowed"),
            "a CONNECT denial names host:port: {out}"
        );
        assert!(
            out.contains("C:\\secret  reason=deny_rule"),
            "a filesystem denial names the path: {out}"
        );
    }

    /// A root without its signature is NOT a commit. Widening the two
    /// `exists()` checks into `||` prints "PRESENT" for a half-committed pair -
    /// a claim of integrity the files do not support.
    #[test]
    fn a_root_without_a_signature_is_reported_as_not_committed() {
        let sid = "mutant-gaps-show-sig";
        let path = crate::audit::audit_log_path(sid);
        std::fs::create_dir_all(path.parent().unwrap()).ok();
        std::fs::write(
            &path,
            "{\"op\":\"CONNECT\",\"host\":\"a.example\",\"hash\":\"abcdef0123456789\",\"seq\":0}\n",
        )
        .unwrap();
        // Root present, signature absent.
        std::fs::write(path.with_extension("root"), "root-hex").unwrap();
        let event: serde_json::Value =
            serde_json::json!({"op": "CONNECT", "host": "a.example", "hash": "abcdef0123456789"});
        let out = render_summary(sid, &[&event]);
        assert!(
            out.contains("Sig     ABSENT"),
            "a root without a signature must not claim PRESENT: {out}"
        );
        assert!(
            out.contains("NOT COMMITTED"),
            "the root line says the session did not end cleanly: {out}"
        );

        // With both files the pair is present - and still not verified by `show`.
        std::fs::write(path.with_extension("sig"), "sig-hex").unwrap();
        let out_both = render_summary(sid, &[&event]);
        assert!(
            out_both.contains("PRESENT (not verified"),
            "a half-check never claims verification: {out_both}"
        );

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("root"));
        let _ = std::fs::remove_file(path.with_extension("sig"));
    }
