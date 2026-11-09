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

fn render_summary(session_id: &str, events: &[&serde_json::Value]) -> String {
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
    let mut hosts: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    for e in events {
        if e.get("op").and_then(|x| x.as_str()) == Some("CONNECT")
            && e.get("disposition").and_then(|x| x.as_str()) == Some("allow")
        {
            let host = e.get("host").and_then(|x| x.as_str()).unwrap_or("?");
            let port = e.get("port").and_then(|x| x.as_u64()).unwrap_or(0);
            let key = format!("{host}:{port}");
            *hosts.entry(key).or_insert(0) += 1;
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
}
