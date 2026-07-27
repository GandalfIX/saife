//! `sandbox audit show <sid> [--json] [--filter "expr"]`

use std::io::Write;
use anyhow::{bail, Result};

use super::filter::Filter;

pub fn run_show(session_id: &str, json: bool, filter_expr: Option<&str>) -> i32 {
    match run_show_inner(session_id, json, filter_expr) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("[sandbox] audit show: {e:#}");
            1
        }
    }
}

fn run_show_inner(session_id: &str, json: bool, filter_expr: Option<&str>) -> Result<i32> {
    let path = super::audit_log_path(session_id);
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
                .map_err(|e| anyhow::anyhow!("invalid JSON in log at line `{line}`: {e}"))?;
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

    print_summary(session_id, &filtered);
    Ok(0)
}

fn print_summary(session_id: &str, events: &[&serde_json::Value]) {
    println!("Session {session_id}");
    if let Some(first) = events.first()
        && let Some(ts) = first.get("ts").and_then(|t| t.as_str()) {
            println!("Started  {ts}");
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
    println!();
    println!("Events by type:");
    if by_op.is_empty() {
        println!("  (none)");
    } else {
        for (op, (total, denied)) in &by_op {
            let allowed = total - denied;
            println!("  {op:<10} {total:>4}  ({allowed} allowed, {denied} denied)");
        }
    }

    // Denied operations.
    let denies: Vec<&serde_json::Value> = events.iter()
        .filter(|v| v.get("disposition").and_then(|x| x.as_str()) == Some("deny"))
        .copied()
        .collect();
    if !denies.is_empty() {
        println!();
        println!("Denied operations:");
        for d in &denies {
            let op = d.get("op").and_then(|x| x.as_str()).unwrap_or("?");
            let reason = d.get("reason").and_then(|x| x.as_str()).unwrap_or("");
            match op {
                "CONNECT" => {
                    let host = d.get("host").and_then(|x| x.as_str()).unwrap_or("?");
                    let port = d.get("port").and_then(|x| x.as_u64()).unwrap_or(0);
                    println!("  {op} {host}:{port}  reason={reason}");
                }
                _ => {
                    let target = d.get("path").and_then(|x| x.as_str())
                        .or_else(|| d.get("target").and_then(|x| x.as_str()))
                        .unwrap_or("?");
                    println!("  {op} {target}  reason={reason}");
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
        println!();
        println!("Hosts contacted (allowed):");
        for (h, n) in &hosts {
            println!("  {h}  x{n}");
        }
    }

    // Root + signature status (best-effort: check for .root and .sig files).
    println!();
    let root_path = super::audit_log_path(session_id).with_extension("root");
    let sig_path = super::audit_log_path(session_id).with_extension("sig");
    if let Some(root) = events.last().and_then(|e| e.get("hash").and_then(|x| x.as_str())) {
        let short: String = root.chars().take(8).collect();
        if root_path.exists() && sig_path.exists() {
            println!("Root    {short}...");
            println!("Sig     OK (files present; run `audit verify` to check)");
        } else {
            println!("Root    {short}... (NOT COMMITTED — session did not end cleanly?)");
            println!("Sig     ABSENT");
        }
    } else {
        println!("Root    (no events)");
    }

    println!();
    println!("Total events: {}", events.len());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn show_missing_session_errors() {
        let rc = run_show("nonexistent-sid-12345678", false, None);
        assert_ne!(rc, 0);
    }
}
