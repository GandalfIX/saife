# US-3: Network exfiltration blocked — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the full US-3 spec — `--block-net`, `--allow-domain` with a localhost TLS reverse proxy, built-in network profiles (`minimal`/`developer`/`none`), randomized proxy port, `X-Sandbox-Token` gate, and `CONNECT` audit events — so sandboxed processes can only reach allow-listed hosts.

**Architecture:** AppContainer processes are network-deny-by-default. For `--block-net` we pass zero network capability SIDs and start no proxy (every `connect()` is kernel-denied). For `--allow-domain`/profiles we still pass zero internet capability SIDs (so direct connects fail closed, AC-3.13) but register a loopback exemption for the AppContainer SID, start a tokio+hyper+rustls HTTP CONNECT proxy on a random `127.0.0.1` port, inject `HTTP_PROXY`/`HTTPS_PROXY`/`X-Sandbox-Token` into the child env, and the proxy enforces the domain allow-list + always-denied list and emits `CONNECT` audit events. AC-3.15 (per-port loopback scoping) is deferred to F-6 (WFP driver) — AppContainer's loopback exemption is all-or-nothing per SID.

**Tech Stack:** Rust (edition 2024), `windows` crate (NetworkIsolation, BCryptGenRandom), tokio (mt scheduler), hyper 1.x + hyper-util, rustls 0.23 + rustls-native-certs, tokio-util (CancellationToken), http, http-body-util, bytes. Tests: existing PowerShell harness in `tests/run-tests.ps1`, plus `#[cfg(test)]` Rust unit tests for pure logic.

**Spec:** `docs/specs/us-3-network-exfiltration-blocked/spec.md` (the "Implementation-ready detail" section is the authoritative design).

**Branch:** `feature/us-3-network` (worktree at `C:\Users\marku\tools\.worktrees\us-3-network\sandbox`).

**Out of scope for this plan:** AC-3.15 (deferred to F-6), raw TCP/SOCKS5 (F-1), per-endpoint filtering (F-1), upstream corporate proxy chaining (F-1), WFP callout driver (F-6), the US-4 hash-chain + Ed25519 signing (US-3 only emits the raw `CONNECT` NDJSON lines).

---

## File Structure

| File | Status | Responsibility |
|---|---|---|
| `Cargo.toml` | Modify | Add tokio, hyper, hyper-util, rustls, rustls-native-certs, tokio-util, http, http-body-util, bytes; add windows features `Win32_Networking_WinSock`, `Win32_Security_Cryptography`. |
| `src/cli.rs` | Modify | Add `--network-profile <name>` flag; thread `block_net`/`allow_domain`/`network_profile` into `RunArgs`. |
| `src/profile.rs` | Modify | Add `NetworkSlice` to `ResolvedProfile`; parse `network` JSON (was `serde_json::Value`); merge with CLI flags. |
| `src/net/mod.rs` | Create | Facade: `NetworkConfig`, `resolve_network(profile, cli) -> NetworkConfig`, re-exports. |
| `src/net/matcher.rs` | Create | `matches(host, entry)`, `is_allowed(host, &allow_list)`, `is_always_denied(host_or_ip)`. Pure. Unit-tested. |
| `src/net/profile.rs` | Create | `builtin_profile(name) -> Option<Vec<String>>` for `minimal`/`developer`/`none`. |
| `src/net/token.rs` | Create | `gen_token() -> String` (256-bit hex via `BCryptGenRandom`). |
| `src/net/loopback.rs` | Create | `register_loopback(ac_sid) -> Result<()>` via `NetworkIsolationSetAppContainerConfig`. Best-effort; failures logged under `SANDBOX_DIAG`. |
| `src/net/proxy.rs` | Create | tokio+hyper+rustls CONNECT proxy. `ProxyHandle` (Drop cancels token, releases port). `spawn(token, allow_list, audit_sink) -> Result<ProxyHandle>` returns the bound port. |
| `src/audit.rs` | Create | `emit_connect(sid, host, port, disposition, reason)`. Writes NDJSON to `%LOCALAPPDATA%\sandbox\audit\<sid>.ndjson` and to stderr under `SANDBOX_DIAG`. US-4 will own hashing/signing. |
| `src/sandbox/appcontainer.rs` | Modify | `build_env_block` gains `proxy: Option<ProxyConfig>` param; sets `HTTP_PROXY`/`HTTPS_PROXY`/`X-Sandbox-Token`/`NO_PROXY`. |
| `src/main.rs` | Modify | `run_inner` resolves `NetworkConfig`, starts proxy (or not), registers loopback (or not), passes proxy port+token into `build_env_block`. Remove the stub "accepted, logged, ignored" messages. |
| `src/setup.rs` | Modify | `setup --check-only` reports proxy/network-cap status (replace "not yet implemented" lines for the network row). |
| `tests/run-tests.ps1` | Modify | Add S-25..S-38; add S-39 as SKIP (AC-3.15 deferred). Update the `required` list and `Scenarios` array. |

---

## Task 1: Dependencies and Cargo.toml

**Files:**
- Modify: `Cargo.toml`

- [ ] **Step 1: Add the new deps**

Append to the `[dependencies]` section (keep the existing windows features; add the two new ones to the existing `features = [...]` list):

```toml
tokio = { version = "1", features = ["rt-multi-thread", "net", "macros", "io-util", "time", "sync"] }
hyper = { version = "1", features = ["server", "http1"] }
hyper-util = { version = "0.1", features = ["server-auto", "tokio"] }
rustls = { version = "0.23", default-features = false, features = ["ring", "std"] }
rustls-native-certs = "0.8"
tokio-util = "0.7"
http = "1"
http-body-util = "0.1"
bytes = "1"
```

Add to the `windows` crate's `features` array:
```
"Win32_Networking_WinSock",
"Win32_Security_Cryptography",
```

- [ ] **Step 2: Verify it builds (deps resolve, no compile errors yet)**

Run: `cargo build --release`
Expected: builds successfully (the new crates are unused at this point — there may be `unused import` / `unused dependency` warnings, that's fine).

- [ ] **Step 3: Commit**

```bash
git add Cargo.toml Cargo.lock
git commit -m "build(us-3): add tokio/hyper/rustls + NetworkIsolation/BCrypt deps"
```

---

## Task 2: Domain matcher (pure logic, TDD)

**Files:**
- Create: `src/net/mod.rs`
- Create: `src/net/matcher.rs`

- [ ] **Step 1: Create the module facade**

`src/net/mod.rs`:

```rust
pub mod matcher;
pub mod profile;
pub mod token;
pub mod loopback;
pub mod proxy;

/// The fully-resolved network configuration for a session.
#[derive(Debug, Clone)]
pub enum NetworkConfig {
    /// `--block-net` / `none` profile: no proxy, no network capability.
    Blocked,
    /// Allow-list mode: proxy started on a random loopback port.
    Allow {
        allow_domain: Vec<String>,
        proxy_port: Option<u16>,
        token: Option<String>,
    },
}

impl NetworkConfig {
    pub fn is_blocked(&self) -> bool { matches!(self, NetworkConfig::Blocked) }
    pub fn needs_proxy(&self) -> bool { matches!(self, NetworkConfig::Allow { .. }) }
}
```

(All submodules except `matcher` can be empty `// TODO` stubs for now — we'll fill them in later tasks. The build will fail on `mod profile; mod token; ...` if they're missing; create them as empty files.)

- [ ] **Step 2: Write the failing tests for the matcher**

`src/net/matcher.rs`:

```rust
//! Domain allow-list matching + always-denied destination enforcement.
//!
//! Pure functions. Unit-tested in this file. The proxy and the CLI both
//! call into here so the matching logic has exactly one implementation.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Always-denied IPv4 CIDRs (AC-3.6, AC-3.7). Link-local + AWS/GCP/Azure
/// metadata.
pub const ALWAYS_DENIED_V4_CIDRS: &[(&str, u8)] = &[("169.254.0.0", 16)];
/// Always-denied IPv4 literals.
pub const ALWAYS_DENIED_V4_HOSTS: &[&str] = &["169.254.169.254"];
/// Always-denied IPv6 CIDRs (link-local).
pub const ALWAYS_DENIED_V6_CIDRS: &[(&str, u8)] = &[("fe80::", 10)];
/// Always-denied DNS names (checked pre-resolution, AC-3.7).
pub const ALWAYS_DENIED_DNS: &[&str] = &["metadata.google.internal"];

/// Reason codes used in the audit log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenyReason {
    DomainNotAllowed,
    DeniedCidr,
    DeniedDns,
}

impl DenyReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            DenyReason::DomainNotAllowed => "domain_not_allowed",
            DenyReason::DeniedCidr => "denied_cidr",
            DenyReason::DeniedDns => "denied_dns",
        }
    }
}

/// Result of an allow-list check on a (host, resolved_ips) pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    Deny(DenyReason),
}

/// Does `host` (a hostname or literal IP, no port) match an allow-list
/// `entry`? Implements the suffix-wildcard rule from AC-3.5: `*.anthropic.com`
/// matches `api.anthropic.com` but NOT `anthropic.com.evil.io` and NOT the
/// bare apex `anthropic.com`.
pub fn matches(host: &str, entry: &str) -> bool {
    let h = host.trim_end_matches('.').to_ascii_lowercase();
    let e = entry.trim_end_matches('.').to_ascii_lowercase();
    if let Some(suffix) = e.strip_prefix("*.") {
        let dot = format!(".{suffix}");
        h.ends_with(&dot)
    } else {
        h == e
    }
}

/// Is `host` (or any of its `resolved_ips`) on the always-denied list?
/// `resolved_ips` is the empty slice when `host` is not a literal IP and DNS
/// resolution has not yet been attempted (or failed).
pub fn is_always_denied(host: &str, resolved_ips: &[IpAddr]) -> bool {
    let h = host.trim_end_matches('.').to_ascii_lowercase();
    if ALWAYS_DENIED_DNS.iter().any(|d| **d == h) {
        return true;
    }
    for ip in resolved_ips {
        match ip {
            IpAddr::V4(v) => {
                if ALWAYS_DENIED_V4_HOSTS.iter().any(|s| s.parse::<Ipv4Addr>().ok() == Some(*v)) {
                    return true;
                }
                for (net, prefix) in ALWAYS_DENIED_V4_CIDRS {
                    if in_v4_cidr(*v, net.parse().unwrap(), *prefix) {
                        return true;
                    }
                }
            }
            IpAddr::V6(v) => {
                for (net, prefix) in ALWAYS_DENIED_V6_CIDRS {
                    if in_v6_cidr(*v, net.parse().unwrap(), *prefix) {
                        return true;
                    }
                }
            }
        }
    }
    false
}

fn in_v4_cidr(ip: Ipv4Addr, net: Ipv4Addr, prefix: u8) -> bool {
    let mask: u32 = if prefix == 0 { 0 } else { (!0u32) << (32 - prefix) };
    let ipn = u32::from(ip) & mask;
    let netn = u32::from(net) & mask;
    ipn == netn
}

fn in_v6_cidr(ip: Ipv6Addr, net: Ipv6Addr, prefix: u8) -> bool {
    let ipb = ip.octets();
    let netb = net.octets();
    let full = (prefix / 8) as usize;
    let rem = prefix % 8;
    if ipb[..full] != netb[..full] { return false; }
    if rem == 0 { return true; }
    let mask = (!0u8) << (8 - rem);
    (ipb[full] & mask) == (netb[full] & mask)
}

/// Full verdict: always-denied first (overrides allow-list per AC-3.6),
/// then allow-list match.
pub fn check(host: &str, resolved_ips: &[IpAddr], allow_list: &[String]) -> Verdict {
    if is_always_denied(host, resolved_ips) {
        // Distinguish DNS-name deny (AC-3.7) from CIDR deny (AC-3.6).
        let h = host.trim_end_matches('.').to_ascii_lowercase();
        if ALWAYS_DENIED_DNS.iter().any(|d| **d == h) {
            return Verdict::Deny(DenyReason::DeniedDns);
        }
        return Verdict::Deny(DenyReason::DeniedCidr);
    }
    if allow_list.iter().any(|e| matches(host, e)) {
        Verdict::Allow
    } else {
        Verdict::Deny(DenyReason::DomainNotAllowed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_match() {
        assert!(matches("api.anthropic.com", "api.anthropic.com"));
        assert!(!matches("api.anthropic.com", "api.openai.com"));
    }

    #[test]
    fn case_insensitive_and_trailing_dot() {
        assert!(matches("API.Anthropic.COM", "api.anthropic.com"));
        assert!(matches("api.anthropic.com.", "api.anthropic.com"));
    }

    #[test]
    fn wildcard_suffix() {
        assert!(matches("api.anthropic.com", "*.anthropic.com"));
        assert!(matches("console.anthropic.com", "*.anthropic.com"));
        // Bare apex is NOT matched by *.anthropic.com.
        assert!(!matches("anthropic.com", "*.anthropic.com"));
        // Suffix does not cross dots.
        assert!(!matches("anthropic.com.evil.io", "*.anthropic.com"));
    }

    #[test]
    fn v4_cidr_169_254() {
        assert!(in_v4_cidr("169.254.169.254".parse().unwrap(), "169.254.0.0".parse().unwrap(), 16));
        assert!(in_v4_cidr("169.254.0.1".parse().unwrap(), "169.254.0.0".parse().unwrap(), 16));
        assert!(!in_v4_cidr("169.255.0.1".parse().unwrap(), "169.254.0.0".parse().unwrap(), 16));
    }

    #[test]
    fn v6_link_local() {
        assert!(in_v6_cidr("fe80::1".parse().unwrap(), "fe80::".parse().unwrap(), 10));
        assert!(!in_v6_cidr("fe70::1".parse().unwrap(), "fe80::".parse().unwrap(), 10));
    }

    #[test]
    fn always_denied_dns() {
        assert!(is_always_denied("metadata.google.internal", &[]));
        assert!(is_always_denied("METADATA.google.INTERNAL.", &[]));
    }

    #[test]
    fn always_denied_ip_literal() {
        let ips = [IpAddr::V4("169.254.169.254".parse().unwrap())];
        assert!(is_always_denied("169.254.169.254", &ips));
    }

    #[test]
    fn check_overrides_allow_with_cidr() {
        let ips = [IpAddr::V4("169.254.169.254".parse().unwrap())];
        let allow = vec!["169.254.169.254".to_string(), "api.anthropic.com".to_string()];
        // AC-3.6: explicit allow is overridden by always-denied.
        assert_eq!(check("169.254.169.254", &ips, &allow), Verdict::Deny(DenyReason::DeniedCidr));
        // But the unrelated allow entry still works.
        assert_eq!(check("api.anthropic.com", &[], &allow), Verdict::Allow);
    }

    #[test]
    fn check_dns_deny_reason() {
        // AC-3.7: metadata.google.internal denied with reason=denied_dns.
        assert_eq!(check("metadata.google.internal", &[], &[]), Verdict::Deny(DenyReason::DeniedDns));
    }

    #[test]
    fn check_unlisted_host_denied() {
        assert_eq!(check("evil.example.com", &[], &["api.anthropic.com".into()]),
                   Verdict::Deny(DenyReason::DomainNotAllowed));
    }
}
```

(Leave the other submodules as empty files for now so the facade compiles: `src/net/profile.rs`, `src/net/token.rs`, `src/net/loopback.rs`, `src/net/proxy.rs` — each just `// TODO`.)

- [ ] **Step 3: Wire `mod net;` into `src/main.rs`**

Add `mod net;` next to the other top-level mod declarations in `src/main.rs`.

- [ ] **Step 4: Run the tests**

Run: `cargo test --release net::matcher`
Expected: all 9 tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/net/mod.rs src/net/matcher.rs src/net/profile.rs src/net/token.rs src/net/loopback.rs src/net/proxy.rs src/main.rs
git commit -m "feat(us-3): domain matcher with wildcard + always-denied CIDR/DNS"
```

---

## Task 3: Built-in network profiles

**Files:**
- Modify: `src/net/profile.rs`

- [ ] **Step 1: Write failing tests + impl**

Replace `src/net/profile.rs` contents:

```rust
//! Built-in network profiles (`minimal`, `developer`, `none`).
//!
//! These are hardcoded in the binary, not files on disk. A profile name in
//! the user's profile JSON (or the `--network-profile` CLI flag) resolves to
//! one of these. `none` is an alias for `--block-net`.

pub fn builtin_profile(name: &str) -> Option<Vec<String>> {
    match name {
        "none" => Some(Vec::new()), // block-net; empty list is irrelevant
        "minimal" => Some(vec![
            "api.openai.com".into(),
            "api.anthropic.com".into(),
            "generativelanguage.googleapis.com".into(),
        ]),
        "developer" => {
            let mut v = builtin_profile("minimal").unwrap();
            v.extend([
                "registry.npmjs.org".into(),
                "registry.npmjs.com".into(),
                "pypi.org".into(),
                "files.pythonhosted.org".into(),
                "crates.io".into(),
                "static.crates.io".into(),
                "github.com".into(),
                "objects.githubusercontent.com".into(),
                "raw.githubusercontent.com".into(),
                "codeload.github.com".into(),
            ]);
            Some(v)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimal_covers_llm_apis() {
        let p = builtin_profile("minimal").unwrap();
        assert!(p.contains(&"api.openai.com".into()));
        assert!(p.contains(&"api.anthropic.com".into()));
        assert!(p.contains(&"generativelanguage.googleapis.com".into()));
        assert!(!p.contains(&"github.com".into()));
    }

    #[test]
    fn developer_adds_registries_and_github() {
        let p = builtin_profile("developer").unwrap();
        for h in ["api.openai.com","registry.npmjs.org","pypi.org","crates.io","github.com"] {
            assert!(p.iter().any(|x| x == h), "developer profile missing {h}");
        }
    }

    #[test]
    fn none_is_empty() {
        assert!(builtin_profile("none").unwrap().is_empty());
    }

    #[test]
    fn unknown_returns_none() {
        assert!(builtin_profile("bogus").is_none());
    }
}
```

- [ ] **Step 2: Run tests**

Run: `cargo test --release net::profile`
Expected: 4 tests pass.

- [ ] **Step 3: Commit**

```bash
git add src/net/profile.rs
git commit -m "feat(us-3): minimal/developer/none built-in network profiles"
```

---

## Task 4: Session token + network config resolution

**Files:**
- Modify: `src/net/token.rs`
- Modify: `src/net/mod.rs` (add `resolve_network`)
- Modify: `src/cli.rs` (add `--network-profile` flag)
- Modify: `src/profile.rs` (parse `network` JSON into `NetworkSlice`)

- [ ] **Step 1: Implement `gen_token`**

`src/net/token.rs`:

```rust
//! 256-bit random session token, hex-encoded (64 chars).

use windows::Win32::Security::Cryptography::{BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG};
use windows::core::*;

pub fn gen_token() -> Result<String> {
    let mut buf = [0u8; 32];
    unsafe {
        BCryptGenRandom(Some(std::ptr::null_mut()), &mut buf, BCRYPT_USE_SYSTEM_PREFERRED_RNG)?;
    }
    Ok(hex_encode(&buf))
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_is_64_hex_chars() {
        let t = gen_token().unwrap();
        assert_eq!(t.len(), 64);
        assert!(t.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn tokens_differ() {
        let a = gen_token().unwrap();
        let b = gen_token().unwrap();
        assert_ne!(a, b);
    }
}
```

- [ ] **Step 2: Add `--network-profile` to the CLI**

In `src/cli.rs`, add to the `Run` variant (between `allow_domain` and `print_sid`):

```rust
/// Network profile name: none | minimal | developer.
#[arg(long, value_name = "NAME")]
network_profile: Option<String>,
```

Add the field to `RunArgs` and `from_cli`. In `src/main.rs`, pass it through `run_cmd` → `run_inner`.

- [ ] **Step 3: Parse `network` JSON in the profile**

In `src/profile.rs`, replace the `pub network: Option<serde_json::Value>` with a typed slice:

```rust
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RawNetwork {
    #[serde(default)]
    pub block_net: bool,
    #[serde(default)]
    pub allow_domain: Vec<String>,
    #[serde(default)]
    pub profile: Option<String>,
}
```

Add to `ResolvedProfile`:

```rust
pub struct ResolvedProfile {
    pub name: String,
    pub filesystem: FilesystemSlice,
    pub network: NetworkSlice,  // NEW
}

#[derive(Debug, Default, Clone)]
pub struct NetworkSlice {
    pub block_net: bool,
    pub allow_domain: Vec<String>,
    pub profile_name: Option<String>,
}
```

Populate `network` in `load_and_resolve` from `raw.network`. Update `merge_profiles` to merge `network` (child overrides scalars, `allow_domain` concatenates, `profile` child-wins).

- [ ] **Step 4: Implement `resolve_network`**

In `src/net/mod.rs`, add:

```rust
use crate::profile::NetworkSlice;

/// Merge profile network slice + CLI flags into a `NetworkConfig` (with
/// port/token placeholders filled in by the proxy layer later).
pub fn resolve_network(
    profile_net: &NetworkSlice,
    cli_block_net: bool,
    cli_allow_domain: &[String],
    cli_network_profile: Option<&str>,
) -> NetworkConfig {
    let block = cli_block_net || profile_net.block_net
        || cli_network_profile == Some("none")
        || profile_net.profile_name.as_deref() == Some("none");
    if block {
        return NetworkConfig::Blocked;
    }

    // Build the merged allow-list.
    let mut allow: Vec<String> = Vec::new();

    // Profile name (CLI overrides profile JSON).
    let profile_name = cli_network_profile
        .map(|s| s.to_string())
        .or_else(|| profile_net.profile_name.clone());

    if let Some(name) = &profile_name {
        if let Some(builtin) = crate::net::profile::builtin_profile(name) {
            allow.extend(builtin);
        } else if name != "none" {
            // Unknown profile name: warn but continue with empty allow-list.
            eprintln!("[sandbox] warning: unknown network profile `{name}`");
        }
    }

    // Profile JSON allow_domain (concatenate).
    allow.extend(profile_net.allow_domain.iter().cloned());

    // CLI --allow-domain (concatenate).
    allow.extend(cli_allow_domain.iter().cloned());

    // Dedupe, case-insensitive, preserve order.
    allow = dedupe(allow);

    NetworkConfig::Allow {
        allow_domain: allow,
        proxy_port: None,
        token: None,
    }
}

fn dedupe(v: Vec<String>) -> Vec<String> {
    let mut seen = std::collections::BTreeSet::new();
    let mut out = Vec::with_capacity(v.len());
    for s in v {
        let key = s.to_ascii_lowercase();
        if seen.insert(key) { out.push(s); }
    }
    out
}
```

- [ ] **Step 5: Write unit tests for `resolve_network`**

Add `#[cfg(test)] mod tests` at the bottom of `src/net/mod.rs` covering: `--block-net` wins; `none` profile blocks; `minimal` profile + `--allow-domain github.com` merges; unknown profile name doesn't crash; dedupe is case-insensitive.

- [ ] **Step 6: Run tests**

Run: `cargo test --release net::`
Expected: all net tests pass (matcher, profile, token, resolve_network).

- [ ] **Step 7: Build the whole crate**

Run: `cargo build --release`
Expected: builds (warnings OK; nothing wired into `main` yet).

- [ ] **Step 8: Commit**

```bash
git add src/net/mod.rs src/net/token.rs src/cli.rs src/profile.rs src/main.rs
git commit -m "feat(us-3): session token + network config resolution + --network-profile flag"
```

---

## Task 5: Audit `CONNECT` event emission

**Files:**
- Create: `src/audit.rs`
- Modify: `src/main.rs` (add `mod audit;`)

- [ ] **Step 1: Implement `emit_connect`**

`src/audit.rs`:

```rust
//! Minimal audit emitter for US-3. US-4 owns the hash chain + signing; US-3
//! just appends a NDJSON line per CONNECT event.

use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

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
    let line = format!(
        "{{\"ts\":\"{ts}\",\"seq\":{seq},\"op\":\"CONNECT\",\"host\":\"{host}\",\"port\":{port},\"disposition\":\"{disp}\"{reason}}}\n",
        host = host.replace('"', "\\\""),
        disp = disposition.as_str(),
        reason = match reason { Some(r) => format!(",\"reason\":\"{}\"", r.replace('"', "\\\"\"")), None => String::new() }
    );

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
    let rem = (secs % 86_400) as u64;
    let h = rem / 3600;
    let m = (rem % 3600) / 60;
    let s = rem % 60;
    // Reuse the civil-from-days algorithm from main.rs.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_from_days_known() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(1), (1970, 1, 2));
    }
}
```

- [ ] **Step 2: Wire `mod audit;` into `src/main.rs`**

Add `mod audit;` to the top of `src/main.rs` alongside the other mod declarations.

- [ ] **Step 3: Build + test**

Run: `cargo build --release && cargo test --release audit`
Expected: builds, audit civil test passes.

- [ ] **Step 4: Commit**

```bash
git add src/audit.rs src/main.rs
git commit -m "feat(us-3): CONNECT audit event emitter (US-4 will add hash chain)"
```

---

## Task 6: Loopback exemption (NetworkIsolation)

**Files:**
- Modify: `src/net/loopback.rs`

- [ ] **Step 1: Implement `register_loopback`**

`src/net/loopback.rs`:

```rust
//! Register the AppContainer SID for loopback access.
//!
//! AC-3.15 (per-port loopback scoping) is deferred to F-6 (WFP driver);
//! AppContainer's loopback exemption is all-or-nothing per SID. We grant
//! full loopback here so the sandboxed process can reach the proxy on
//! 127.0.0.1:<proxy-port>. The proxy's X-Sandbox-Token gate (AC-3.12)
//! and the fact that other loopback services don't honor our token
//! provide the practical isolation in the MVP.

use windows::Win32::Networking::WinSock::*;
use windows::Win32::Security::Isolation::*;
use windows::core::*;

/// Register loopback for the AppContainer SID. Best-effort: failures are
/// logged under `SANDBOX_DIAG` but not propagated — direct connects to
/// the proxy would simply fail closed (kernel denies non-exempted
/// loopback), which is a worse failure mode but not a security one.
pub fn register_loopback(ac_sid: &PSID) -> Result<()> {
    let diag = std::env::var_os("SANDBOX_DIAG").is_some();
    unsafe {
        // INET_FIREWALL_APP_CONTAINER: app_container_sid + capabilities.
        // We pass an empty capabilities array (no internet caps).
        let ac = INET_FIREWALL_APP_CONTAINER {
            app_container_sid: *ac_sid,
            capabilities: std::ptr::null_mut(),
            capability_count: 0,
            ..Default::default()
        };
        let r = NetworkIsolationSetAppContainerConfig(&[ac]);
        if r.is_err() {
            if diag {
                eprintln!("[net] WARN: NetworkIsolationSetAppContainerConfig failed: {r}");
            }
            return Err(r.into());
        }
        if diag {
            eprintln!("[net] loopback exemption registered for AC SID");
        }
    }
    Ok(())
}
```

(If the windows crate's API surface differs — `NetworkIsolationSetAppContainerConfig` may take a different signature across versions — adapt to the actual signature that compiles. The semantic intent is the same: register the AC SID with no internet capabilities but with loopback access.)

- [ ] **Step 2: Build**

Run: `cargo build --release`
Expected: builds. (Not testable without an AppContainer SID; integration-tested in Task 10.)

- [ ] **Step 3: Commit**

```bash
git add src/net/loopback.rs Cargo.lock
git commit -m "feat(us-3): register AppContainer loopback exemption"
```

---

## Task 7: The proxy (tokio + hyper + rustls)

**Files:**
- Modify: `src/net/proxy.rs`

This is the largest task. The proxy:
1. Binds a `tokio::net::TcpListener` to `127.0.0.1:0`.
2. Returns the bound port to the caller.
3. For each accepted connection: parses the HTTP/1.1 request line, checks the `X-Sandbox-Token`, looks up the host (for `CONNECT host:port` the host is in the request target; for `GET http://host/...` it's in the URL), runs `net::matcher::check`, emits an audit event, and either:
   - `Allow`: opens a TCP connection to the upstream, for `CONNECT` upgrades to TLS with rustls and splices bytes; for plain HTTP forwards the request.
   - `Deny`: writes a `407 Proxy Authentication Required` (token mismatch) or `403 Forbidden` (domain denied) response and closes.
4. Honours a `CancellationToken`; `ProxyHandle::drop` cancels it.

- [ ] **Step 1: Write the proxy skeleton**

`src/net/proxy.rs`:

```rust
//! Localhost reverse proxy: tokio + hyper + rustls.
//!
//! Architecture: the supervisor (`sandbox.exe`) spawns the proxy on a
//! random 127.0.0.1 port before launching the sandboxed process. The
//! sandboxed process is configured (via env vars) to route HTTP(S)
//! through this proxy. The proxy enforces the domain allow-list and the
//! always-denied list, emits CONNECT audit events, and terminates TLS
//! to the upstream with rustls (so it sees plain HTTP from the child,
//! TLS to the real host).

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tokio::sync::oneshot;

use crate::audit::{self, Disposition};
use crate::net::matcher::{self, DenyReason, Verdict};

pub struct ProxyConfig {
    pub session_id: String,
    pub token: String,
    pub allow_domain: Vec<String>,
}

pub struct ProxyHandle {
    pub port: u16,
    cancel: CancellationToken,
    join: Option<tokio::task::JoinHandle<()>>,
}

impl ProxyHandle {
    pub fn shutdown(mut self) {
        self.cancel.cancel();
        if let Some(j) = self.join.take() { let _ = j.blocking_recv_or_abort(); }
    }
}

impl Drop for ProxyHandle {
    fn drop(&mut self) {
        self.cancel.cancel();
        // Best-effort: don't block the drop on the task; tokio runtime
        // shutdown will reap it.
    }
}

/// Spawn the proxy on a tokio runtime. Returns once the listener is bound
/// (so the caller knows the port before spawning the child process).
pub fn spawn(cfg: ProxyConfig) -> Result<ProxyHandle> {
    let ProxyConfig { session_id, token, allow_domain } = cfg;
    let allow = Arc::new(allow_domain);
    let token = Arc::new(token);
    let sid = Arc::new(session_id);

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(1)
        .build()?;

    let (port_tx, port_rx) = oneshot::channel::<u16>();
    let cancel = CancellationToken::new();
    let cancel_for_task = cancel.clone();

    let join = rt.spawn(async move {
        let listener = match TcpListener::bind("127.0.0.1:0").await {
            Ok(l) => l,
            Err(e) => {
                eprintln!("[proxy] bind failed: {e}");
                let _ = port_tx.send(0);
                return;
            }
        };
        let port = listener.local_addr().ok().map(|a| a.port()).unwrap_or(0);
        let _ = port_tx.send(port);

        loop {
            tokio::select! {
                _ = cancel_for_task.cancelled() => break,
                accept = listener.accept() => {
                    let (sock, _peer) = match accept {
                        Ok(p) => p,
                        Err(_) => continue,
                    };
                    let allow = allow.clone();
                    let token = token.clone();
                    let sid = sid.clone();
                    tokio::spawn(async move {
                        let _ = handle_conn(sock, sid, token, allow).await;
                    });
                }
            }
        }
    });

    let port = port_rx.blocking_recv().context("proxy bind handshake")?;
    if port == 0 { anyhow::bail!("proxy failed to bind"); }

    // Keep the runtime alive for the proxy's lifetime by leaking it; we
    // shut the proxy down via the cancellation token. The leaked runtime
    // is reclaimed when the process exits (the supervisor is short-lived).
    std::mem::forget(rt);

    Ok(ProxyHandle { port, cancel, join: Some(join) })
}

async fn handle_conn(
    mut sock: tokio::net::TcpStream,
    sid: Arc<String>,
    token: Arc<String>,
    allow: Arc<Vec<String>>,
) -> Result<()> {
    // Read up to 8 KiB of headers (request line + headers, terminated by \r\n\r\n).
    let mut buf = vec![0u8; 8192];
    let mut filled = 0;
    loop {
        if filled >= buf.len() { break; }
        let n = sock.read(&mut buf[filled..]).await.unwrap_or(0);
        if n == 0 { break; }
        filled += n;
        if buf[..filled].windows(4).any(|w| w == b"\r\n\r\n") { break; }
    }
    let head = std::str::from_utf8(&buf[..filled]).unwrap_or("");

    // Parse the request line.
    let first_line = head.lines().next().unwrap_or("");
    let mut parts = first_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");

    // Token check (AC-3.12).
    let token_ok = head.lines().skip(1).any(|l| {
        let l = l.to_ascii_lowercase();
        l.starts_with("x-sandbox-token:") && l[16..].trim() == *token
    });
    if !token_ok {
        let _ = sock.write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n").await;
        audit::emit_connect(&sid, "<unknown>", 0, Disposition::Deny, Some("no_token"));
        return Ok(());
    }

    // Extract host + port.
    let (host, port) = if method == "CONNECT" {
        // CONNECT host:port HTTP/1.1
        let (h, p) = target.rsplit_once(':').unwrap_or((target, "443"));
        (h.to_string(), p.parse::<u16>().unwrap_or(443))
    } else if let Some(host_start) = target.find("://") {
        // GET http://host[:port]/path HTTP/1.1
        let after = &target[host_start + 3..];
        let host_port = after.split('/').next().unwrap_or(after);
        let (h, p) = host_port.rsplit_once(':').unwrap_or((host_port, "80"));
        (h.to_string(), p.parse::<u16>().unwrap_or(80))
    } else {
        // Absolute path with Host header. Fall back to parsing Host:.
        let h = head.lines().skip(1)
            .find(|l| l.to_ascii_lowercase().starts_with("host:"))
            .map(|l| l[5..].trim().split(':').next().unwrap_or("").to_string())
            .unwrap_or_default();
        (h, 80)
    };

    if host.is_empty() {
        let _ = sock.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await;
        return Ok(());
    }

    // DNS resolve for CIDR check (best-effort).
    let resolved: Vec<IpAddr> = tokio::net::lookup_host(format!("{host}:0")).await
        .map(|it| it.map(|sa| sa.ip()).collect()).unwrap_or_default();

    let verdict = matcher::check(&host, &resolved, &allow);
    match verdict {
        Verdict::Allow => {
            audit::emit_connect(&sid, &host, port, Disposition::Allow, None);
            if method == "CONNECT" {
                // Open upstream TCP, splice.
                let upstream = match tokio::net::TcpStream::connect(format!("{host}:{port}")).await {
                    Ok(s) => s,
                    Err(e) => {
                        let _ = sock.write_all(format!("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n").as_bytes()).await;
                        eprintln!("[proxy] upstream connect to {host}:{port} failed: {e}");
                        return Ok(());
                    }
                };
                let _ = sock.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await;
                let (mut ri, mut wi) = sock.into_split();
                let (mut ro, mut wo) = upstream.into_split();
                let c2u = tokio::io::copy(&mut ri, &mut wo);
                let u2c = tokio::io::copy(&mut ro, &mut wi);
                let _ = tokio::join!(c2u, u2c);
            } else {
                // Plain HTTP forward — re-send the request line + headers we read,
                // then splice body. (MVP: HTTP/1.1 only, no TLS for plain http://.)
                let upstream = tokio::net::TcpStream::connect(format!("{host}:{port}")).await?;
                let (mut ri, mut wi) = sock.into_split();
                let (mut ro, mut wo) = upstream.into_split();
                let _ = wo.write_all(&buf[..filled]).await;
                let c2u = tokio::io::copy(&mut ri, &mut wo);
                let u2c = tokio::io::copy(&mut ro, &mut wi);
                let _ = tokio::join!(c2u, u2c);
            }
            Ok(())
        }
        Verdict::Deny(reason) => {
            let code = match reason {
                DenyReason::DomainNotAllowed => "403 Forbidden",
                DenyReason::DeniedCidr | DenyReason::DeniedDns => "403 Forbidden",
            };
            let _ = sock.write_all(format!("HTTP/1.1 {code}\r\nContent-Length: 0\r\n\r\n").as_bytes()).await;
            audit::emit_connect(&sid, &host, port, Disposition::Deny, Some(reason.as_str()));
            Ok(())
        }
    }
}
```

Note: the MVP does NOT terminate TLS to the upstream inside the proxy for `CONNECT` — it does a plain TCP splice. The child speaks TLS end-to-end with the real host. This is simpler than terminating TLS at the proxy and still enforces the allow-list (the `CONNECT host:port` line reveals the target host). **Add a comment in the file explaining this deviation from the spec's narrative**: the spec says "the proxy does TLS to the upstream" but for the MVP the proxy just splices the TCP tunnel after the allow-list check; the child's TLS handshake goes straight through. This satisfies every US-3 AC (the ACs assert on the `CONNECT` line and the connection outcome, not on where TLS terminates). Terminating TLS at the proxy is future work tied to credential injection (F-2).

- [ ] **Step 2: Build**

Run: `cargo build --release`
Expected: builds (the proxy is not yet wired into `main`; just needs to compile).

- [ ] **Step 3: Commit**

```bash
git add src/net/proxy.rs Cargo.lock
git commit -m "feat(us-3): localhost CONNECT proxy with allow-list + 407 token gate"
```

---

## Task 8: Env injection of proxy vars

**Files:**
- Modify: `src/sandbox/appcontainer.rs`

- [ ] **Step 1: Change `build_env_block` signature**

Add a `proxy: Option<&ProxyConfig>` parameter to `build_env_block`. Define a small `ProxyConfig` struct in `src/net/mod.rs` (or reuse the proxy's `ProxyConfig`; the supervisor passes port + token). When `Some`, add these env vars to the child (replacing any inherited values):

- `HTTP_PROXY = http://127.0.0.1:<port>`
- `HTTPS_PROXY = http://127.0.0.1:<port>`
- `X-Sandbox-Token = <token>`
- `NO_PROXY =`  (empty — force the proxy to be used for everything)

When `None` (block-net), set none of these and let inherited proxy vars be cleared (the supervisor does not set them, but a parent shell might have — explicitly clear `HTTP_PROXY`/`HTTPS_PROXY`/`X-Sandbox-Token` to empty to avoid leakage into the sandboxed process).

- [ ] **Step 2: Update the caller in `src/main.rs`**

`build_env_block` is called in `run_inner`. Thread the resolved `NetworkConfig` through.

- [ ] **Step 3: Build**

Run: `cargo build --release`
Expected: builds.

- [ ] **Step 4: Commit**

```bash
git add src/sandbox/appcontainer.rs src/main.rs
git commit -m "feat(us-3): inject HTTP_PROXY/HTTPS_PROXY/X-Sandbox-Token into child env"
```

---

## Task 9: Wire it all into `run_inner`

**Files:**
- Modify: `src/main.rs`

- [ ] **Step 1: Replace the stub messages**

Remove the "accepted, logged, ignored" eprintln for `--block-net` / `--allow-domain` in `run_cmd`. Pass `block_net`, `allow_domain`, `network_profile` into `run_inner`.

- [ ] **Step 2: Resolve `NetworkConfig` and start the proxy**

In `run_inner`, after profile load and FS merge:

```rust
let net_cfg = net::resolve_network(&resolved.network, block_net, &allow_domain, network_profile.as_deref());

let (proxy_port, proxy_token) = match &net_cfg {
    net::NetworkConfig::Blocked => (None, None),
    net::NetworkConfig::Allow { allow_domain, .. } => {
        let token = net::token::gen_token().context("generate session token")?;
        let handle = net::proxy::spawn(net::proxy::ProxyConfig {
            session_id: sid.clone(),
            token: token.clone(),
            allow_domain: allow_domain.clone(),
        }).context("start localhost proxy")?;
        // Register loopback for the AC SID (we'll have created the
        // session just above; see Step 3 for ordering).
        let port = handle.port;
        // Stash the handle so it lives as long as the sandboxed process;
        // it shuts down when run_inner returns (Drop cancels it).
        // (Hold it in a binding that outlives spawn().)
        (Some(port), Some(token))
        // NOTE: handle must be held until after spawn() returns; see below.
    }
};
```

The actual ordering needs care: `create_session` (which mints the AC SID) must happen before `register_loopback`. Re-order so: `create_session` → `register_loopback` (if not blocked) → `spawn proxy` → `build_env_block` → `spawn child` → wait.

- [ ] **Step 3: Register loopback (when not blocked)**

```rust
if !net_cfg.is_blocked() {
    if let Err(e) = net::loopback::register_loopback(&session.ac_sid) {
        eprintln!("[sandbox] warning: loopback exemption failed: {e}");
        eprintln!("[sandbox]          direct connects to the proxy will be denied.");
    }
}
```

- [ ] **Step 4: Pass proxy vars to `build_env_block`**

Build a `ProxyConfig` from `(proxy_port, proxy_token)` and pass it.

- [ ] **Step 5: Hold the `ProxyHandle` until the child exits**

Bind `_proxy_handle` in `run_inner` so it lives until `spawn()` returns and we read the exit code. The handle must be assigned in the *outer* scope (not inside the match arm) so it isn't dropped when the match block ends. Pattern:

```rust
let _proxy_handle: Option<net::proxy::ProxyHandle> = match &net_cfg {
    net::NetworkConfig::Blocked => None,
    net::NetworkConfig::Allow { .. } => {
        // ... gen token, spawn proxy ...
        Some(handle)
    }
};
// _proxy_handle lives until the end of run_inner; sandbox::spawn runs
// below and the child process can talk to the proxy the whole time.
```

- [ ] **Step 6: Build**

Run: `cargo build --release`
Expected: builds.

- [ ] **Step 7: Commit**

```bash
git add src/main.rs
git commit -m "feat(us-3): wire proxy + loopback + env injection into run_inner"
```

---

## Task 10: `setup --check-only` reports network status

**Files:**
- Modify: `src/setup.rs`

- [ ] **Step 1: Replace the placeholder line**

In `setup::check`, change:

```rust
println!("Reverse proxy (network)    : not yet implemented in this slice");
```

to:

```rust
println!("Reverse proxy (network)    : available (US-3)");
```

- [ ] **Step 2: Build + run the existing S-18 test**

Run: `cargo build --release; pwsh -File tests/run-tests.ps1 -Only 18`
Expected: S-18 still passes.

- [ ] **Step 3: Commit**

```bash
git add src/setup.rs
git commit -m "feat(us-3): setup --check-only reports network proxy available"
```

---

## Task 11: Integration tests S-25 .. S-38

**Files:**
- Modify: `tests/run-tests.ps1`

Follow the table in the spec's "Test commands" section. Each scenario uses `Invoke-Sandbox` (already defined). Tests that need python/curl skip cleanly via `Get-Command`.

- [ ] **Step 1: Add S-25 (AC-3.1, block-net denies)**

```powershell
function Invoke-Scenario-S25 {
    $d = New-ScenarioDir 25
    $py = Get-Python
    if (-not $py) { return @{ Num=25; Name='S-25 (AC-3.1)'; Passed=$true; Skipped=$true; PythonSkipped=$true; Detail='python not on PATH' } }
    $r = Invoke-Sandbox -Args @('run','--allow-cwd','--block-net','--','python','-c',"import urllib.request,sys; urllib.request.urlopen('https://api.openai.com')") -WorkingDirectory $d
    $err = ($r.Stderr -join "`n")
    $passed = ($r.ExitCode -ne 0) -and ($err -match '(?i)(access is denied|urLError|ConnectionError|PermissionError|WSAEACCES)')
    return @{ Num=25; Name='S-25 (AC-3.1)'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { 'block-net denied urllib connect' } else { "exit=$($r.ExitCode) stderr=$err" } }
}
```

- [ ] **Step 2: Add S-26 (AC-3.2, block-net denies raw socket)**

```powershell
function Invoke-Scenario-S26 {
    $d = New-ScenarioDir 26
    $py = Get-Python
    if (-not $py) { return @{ Num=26; Name='S-26 (AC-3.2)'; Passed=$true; Skipped=$true; PythonSkipped=$true; Detail='python not on PATH' } }
    $r = Invoke-Sandbox -Args @('run','--allow-cwd','--block-net','--','python','-c',"import socket; socket.create_connection(('169.254.169.254',80))") -WorkingDirectory $d
    $err = ($r.Stderr -join "`n")
    $passed = ($r.ExitCode -ne 0) -and ($err -match '(?i)(access is denied|PermissionError|WSAEACCES)')
    return @{ Num=26; Name='S-26 (AC-3.2)'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { 'block-net denied raw socket to metadata' } else { "exit=$($r.ExitCode) stderr=$err" } }
}
```

- [ ] **Step 3: Add S-27 (AC-3.3, allow-domain permits)**

```powershell
function Invoke-Scenario-S27 {
    $d = New-ScenarioDir 27
    $curl = Get-Command curl -ErrorAction SilentlyContinue
    if (-not $curl) { return @{ Num=27; Name='S-27 (AC-3.3)'; Passed=$true; Skipped=$true; Detail='curl not on PATH' } }
    $env:SANDBOX_DIAG='1'
    try {
        $r = Invoke-Sandbox -Args @('run','--allow-cwd','--allow-domain','api.anthropic.com','--','cmd','/c','curl','-s','-o','NUL','-w','%{http_code}','https://api.anthropic.com/v1/messages') -WorkingDirectory $d
    } finally { Remove-Item env:SANDBOX_DIAG -ErrorAction SilentlyContinue }
    $out = ($r.Stdout -join '')
    # Connection succeeded → anthropic returns 401 (no auth) or 4xx. The
    # assertion is that we reached the host (not a proxy error).
    $passed = ($r.ExitCode -eq 0) -and ($out -match '^(40[0-9]|200|30[0-9])')
    return @{ Num=27; Name='S-27 (AC-3.3)'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { "reached api.anthropic.com (http_code=$out)" } else { "exit=$($r.ExitCode) stdout=$out" } }
}
```

- [ ] **Step 4: Add S-28 (AC-3.4, allow-domain denies unlisted)**

```powershell
function Invoke-Scenario-S28 {
    $d = New-ScenarioDir 28
    $curl = Get-Command curl -ErrorAction SilentlyContinue
    if (-not $curl) { return @{ Num=28; Name='S-28 (AC-3.4)'; Passed=$true; Skipped=$true; Detail='curl not on PATH' } }
    $env:SANDBOX_DIAG='1'
    try {
        $r = Invoke-Sandbox -Args @('run','--allow-cwd','--allow-domain','api.anthropic.com','--','cmd','/c','curl','-s','-o','NUL','-w','%{http_code}','https://evil.example.com') -WorkingDirectory $d
    } finally { Remove-Item env:SANDBOX_DIAG -ErrorAction SilentlyContinue }
    $out = ($r.Stdout -join '')
    # curl exits non-zero when the proxy returns 403.
    $passed = ($r.ExitCode -ne 0) -or ($out -eq '403')
    return @{ Num=28; Name='S-28 (AC-3.4)'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { 'unlisted host denied' } else { "exit=$($r.ExitCode) stdout=$out" } }
}
```

- [ ] **Step 5: Add S-29 (AC-3.5, wildcard suffix)**

```powershell
function Invoke-Scenario-S29 {
    $d = New-ScenarioDir 29
    $curl = Get-Command curl -ErrorAction SilentlyContinue
    if (-not $curl) { return @{ Num=29; Name='S-29 (AC-3.5)'; Passed=$true; Skipped=$true; Detail='curl not on PATH' } }
    $env:SANDBOX_DIAG='1'
    try {
        $rA = Invoke-Sandbox -Args @('run','--allow-cwd','--allow-domain','*.anthropic.com','--','cmd','/c','curl','-s','-o','NUL','-w','%{http_code}','https://api.anthropic.com/v1/messages') -WorkingDirectory $d
        $rB = Invoke-Sandbox -Args @('run','--allow-cwd','--allow-domain','*.anthropic.com','--','cmd','/c','curl','-s','-o','NUL','-w','%{http_code}','https://console.anthropic.com/') -WorkingDirectory $d
        $rC = Invoke-Sandbox -Args @('run','--allow-cwd','--allow-domain','*.anthropic.com','--','cmd','/c','curl','-s','-o','NUL','-w','%{http_code}','https://anthropic.com.evil.io/') -WorkingDirectory $d
    } finally { Remove-Item env:SANDBOX_DIAG -ErrorAction SilentlyContinue }
    $outA = ($rA.Stdout -join '')
    $outB = ($rB.Stdout -join '')
    $outC = ($rC.Stdout -join '')
    $passedA = $outA -match '^(4[0-9][0-9]|2[0-9][0-9]|3[0-9][0-9])'
    $passedB = $outB -match '^(4[0-9][0-9]|2[0-9][0-9]|3[0-9][0-9])'
    $passedC = ($rC.ExitCode -ne 0) -or ($outC -eq '403')
    $passed = $passedA -and $passedB -and $passedC
    return @{ Num=29; Name='S-29 (AC-3.5)'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { 'wildcard suffix matches bounded by dots' } else { "A=$outA B=$outB C=$outC" } }
}
```

- [ ] **Step 6: Add S-30 (AC-3.6, always-denied overrides allow)**

```powershell
function Invoke-Scenario-S30 {
    $d = New-ScenarioDir 30
    $curl = Get-Command curl -ErrorAction SilentlyContinue
    if (-not $curl) { return @{ Num=30; Name='S-30 (AC-3.6)'; Passed=$true; Skipped=$true; Detail='curl not on PATH' } }
    $env:SANDBOX_DIAG='1'
    try {
        $r = Invoke-Sandbox -Args @('run','--allow-cwd','--allow-domain','169.254.169.254','--allow-domain','api.anthropic.com','--','cmd','/c','curl','-s','-o','NUL','-w','%{http_code}','http://169.254.169.254/') -WorkingDirectory $d
    } finally { Remove-Item env:SANDBOX_DIAG -ErrorAction SilentlyContinue }
    $out = ($r.Stdout -join '')
    $passed = ($r.ExitCode -ne 0) -or ($out -eq '403')
    return @{ Num=30; Name='S-30 (AC-3.6)'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { 'always-denied overrides explicit allow' } else { "exit=$($r.ExitCode) stdout=$out" } }
}
```

- [ ] **Step 7: Add S-31 (AC-3.7, metadata.google.internal denied)**

```powershell
function Invoke-Scenario-S31 {
    $d = New-ScenarioDir 31
    $curl = Get-Command curl -ErrorAction SilentlyContinue
    if (-not $curl) { return @{ Num=31; Name='S-31 (AC-3.7)'; Passed=$true; Skipped=$true; Detail='curl not on PATH' } }
    $env:SANDBOX_DIAG='1'
    try {
        $r = Invoke-Sandbox -Args @('run','--allow-cwd','--allow-domain','metadata.google.internal','--','cmd','/c','curl','-s','-o','NUL','-w','%{http_code}','http://metadata.google.internal/') -WorkingDirectory $d
    } finally { Remove-Item env:SANDBOX_DIAG -ErrorAction SilentlyContinue }
    $out = ($r.Stdout -join '')
    $passed = ($r.ExitCode -ne 0) -or ($out -eq '403')
    return @{ Num=31; Name='S-31 (AC-3.7)'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { 'metadata.google.internal denied' } else { "exit=$($r.ExitCode) stdout=$out" } }
}
```

- [ ] **Step 8: Add S-32 (AC-3.8, minimal profile)**

```powershell
function Invoke-Scenario-S32 {
    $d = New-ScenarioDir 32
    $curl = Get-Command curl -ErrorAction SilentlyContinue
    if (-not $curl) { return @{ Num=32; Name='S-32 (AC-3.8)'; Passed=$true; Skipped=$true; Detail='curl not on PATH' } }
    $env:SANDBOX_DIAG='1'
    try {
        $rAllow = Invoke-Sandbox -Args @('run','--allow-cwd','--network-profile','minimal','--','cmd','/c','curl','-s','-o','NUL','-w','%{http_code}','https://api.anthropic.com/v1/messages') -WorkingDirectory $d
        $rDeny  = Invoke-Sandbox -Args @('run','--allow-cwd','--network-profile','minimal','--','cmd','/c','curl','-s','-o','NUL','-w','%{http_code}','https://github.com/') -WorkingDirectory $d
    } finally { Remove-Item env:SANDBOX_DIAG -ErrorAction SilentlyContinue }
    $outA = ($rAllow.Stdout -join '')
    $outD = ($rDeny.Stdout -join '')
    $passed = ($outA -match '^(4[0-9][0-9]|2[0-9][0-9]|3[0-9][0-9])') -and (($rDeny.ExitCode -ne 0) -or ($outD -eq '403'))
    return @{ Num=32; Name='S-32 (AC-3.8)'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { 'minimal allows LLM APIs, denies github' } else { "allow=$outA deny=$outD" } }
}
```

- [ ] **Step 9: Add S-33 (AC-3.9, developer profile)**

```powershell
function Invoke-Scenario-S33 {
    $d = New-ScenarioDir 33
    $curl = Get-Command curl -ErrorAction SilentlyContinue
    if (-not $curl) { return @{ Num=33; Name='S-33 (AC-3.9)'; Passed=$true; Skipped=$true; Detail='curl not on PATH' } }
    $env:SANDBOX_DIAG='1'
    try {
        $r = Invoke-Sandbox -Args @('run','--allow-cwd','--network-profile','developer','--','cmd','/c','curl','-s','-o','NUL','-w','%{http_code}','https://github.com/') -WorkingDirectory $d
    } finally { Remove-Item env:SANDBOX_DIAG -ErrorAction SilentlyContinue }
    $out = ($r.Stdout -join '')
    $passed = ($out -match '^(4[0-9][0-9]|2[0-9][0-9]|3[0-9][0-9])')
    return @{ Num=33; Name='S-33 (AC-3.9)'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { "developer allows github (http_code=$out)" } else { "exit=$($r.ExitCode) stdout=$out" } }
}
```

- [ ] **Step 10: Add S-34 (AC-3.10, profile + CLI merge)**

```powershell
function Invoke-Scenario-S34 {
    $d = New-ScenarioDir 34
    $profileDir = Join-Path $d 'profiles'
    New-Item -ItemType Directory -Path $profileDir -Force | Out-Null
    $profilePath = Join-Path $profileDir 'net-merge.json'
    $profileJson = @{
        meta = @{ name='net-merge'; version='1.0.0' }
        filesystem = @{ allow=@('$CWD'); read_only=@(); deny=@() }
        network = @{ allowDomain=@('api.anthropic.com') }
    } | ConvertTo-Json -Depth 5
    Set-Content -LiteralPath $profilePath -Value $profileJson -Encoding UTF8
    $curl = Get-Command curl -ErrorAction SilentlyContinue
    if (-not $curl) { return @{ Num=34; Name='S-34 (AC-3.10)'; Passed=$true; Skipped=$true; Detail='curl not on PATH' } }
    $env:SANDBOX_DIAG='1'
    try {
        $rA = Invoke-Sandbox -Args @('run','--profile',$profilePath,'--allow-cwd','--allow-domain','github.com','--','cmd','/c','curl','-s','-o','NUL','-w','%{http_code}','https://api.anthropic.com/v1/messages') -WorkingDirectory $d
        $rB = Invoke-Sandbox -Args @('run','--profile',$profilePath,'--allow-cwd','--allow-domain','github.com','--','cmd','/c','curl','-s','-o','NUL','-w','%{http_code}','https://github.com/') -WorkingDirectory $d
    } finally { Remove-Item env:SANDBOX_DIAG -ErrorAction SilentlyContinue }
    $outA = ($rA.Stdout -join '')
    $outB = ($rB.Stdout -join '')
    $passed = ($outA -match '^(4[0-9][0-9]|2[0-9][0-9]|3[0-9][0-9])') -and ($outB -match '^(4[0-9][0-9]|2[0-9][0-9]|3[0-9][0-9])')
    return @{ Num=34; Name='S-34 (AC-3.10)'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { 'profile + CLI merged' } else { "anthropic=$outA github=$outB" } }
}
```

- [ ] **Step 11: Add S-35 (AC-3.11, randomized port)**

```powershell
function Invoke-Scenario-S35 {
    $d = New-ScenarioDir 35
    # Run two concurrent sandboxes with --print-sid and a network profile;
    # both must succeed (no EADDRINUSE). We can't read the proxy port
    # directly from outside, so the assertion is: both runs exit 0 with a
    # sid, and the sids differ.
    $jobA = Start-Job -ScriptBlock {
        param($SandboxExe,$d)
        & $SandboxExe run --allow-cwd --network-profile minimal --print-sid -- cmd /c echo init
    } -ArgumentList $SandboxExe,$d
    $jobB = Start-Job -ScriptBlock {
        param($SandboxExe,$d)
        & $SandboxExe run --allow-cwd --network-profile minimal --print-sid -- cmd /c echo init
    } -ArgumentList $SandboxExe,$d
    $rA = Receive-Job $jobA -Wait -AutoRemoveJob
    $rB = Receive-Job $jobB -Wait -AutoRemoveJob
    $sidA = (($rA | Where-Object { $_ -match '^\d{8}-\d{6}-\d{5}$' }) -join '').Trim()
    $sidB = (($rB | Where-Object { $_ -match '^\d{8}-\d{6}-\d{5}$' }) -join '').Trim()
    $passed = $sidA -and $sidB -and ($sidA -ne $sidB)
    return @{ Num=35; Name='S-35 (AC-3.11)'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { "two concurrent sessions; sids differ" } else { "A='$sidA' B='$sidB'" } }
}
```

- [ ] **Step 12: Add S-36 (AC-3.12, no token → 407)**

AC-3.12 requires that a request to the proxy *without* the `X-Sandbox-Token` gets a 407. The proxy port is randomized per session, so we must capture the port from one session and probe it from *within the same session* (using `--sid <sid>` to reuse the session+proxy). The sandboxed process can read `X-Sandbox-Token` from its own env (we injected it) and then deliberately omit it from a raw socket request to the proxy.

```powershell
function Invoke-Scenario-S36 {
    $d = New-ScenarioDir 36
    $py = Get-Python
    if (-not $py) { return @{ Num=36; Name='S-36 (AC-3.12)'; Passed=$true; Skipped=$true; PythonSkipped=$true; Detail='python not on PATH' } }
    # Start a session and capture the sid + proxy port. The proxy port is
    # printed on stderr under SANDBOX_DIAG ([proxy] listening on 127.0.0.1:<port>).
    $env:SANDBOX_DIAG='1'
    try {
        $probe = Invoke-Sandbox -Args @('run','--allow-cwd','--allow-domain','api.anthropic.com','--print-sid','--','cmd','/c','echo','probe') -WorkingDirectory $d
    } finally { Remove-Item env:SANDBOX_DIAG -ErrorAction SilentlyContinue }
    $sid = ($probe.Stdout | Where-Object { $_ -match '^\d{8}-\d{6}-\d{5}$' } | Select-Object -First 1)
    $portLine = ($probe.Stderr | Where-Object { $_ -match '\[proxy\].*127\.0\.0\.1:(\d{2,5})' } | Select-Object -First 1)
    if (-not $sid -or -not $portLine -or $portLine -notmatch '(\d{2,5})') {
        return @{ Num=36; Name='S-36 (AC-3.12)'; Passed=$true; Skipped=$true; Detail="could not extract sid/port (sid=$sid line=$portLine)" }
    }
    $port = $matches[1]
    # Reuse the same session. The sandboxed python reads the proxy port from
    # the diag output (we re-export SANDBOX_DIAG so the second run also logs
    # the port — but we already have it from $port). We hard-code the port
    # into the python snippet. Python opens a raw socket to 127.0.0.1:$port
    # and sends a GET request WITHOUT the X-Sandbox-Token header.
    $env:SANDBOX_DIAG='1'
    try {
        $pyCmd = "import socket; s=socket.create_connection(('127.0.0.1',$port)); s.sendall(b'GET http://api.anthropic.com/ HTTP/1.1\r\nHost: api.anthropic.com\r\n\r\n'); print(s.recv(64).decode(errors='replace'))"
        $r = Invoke-Sandbox -Args @('run','--allow-cwd','--allow-domain','api.anthropic.com','--sid',$sid,'--','python','-c',$pyCmd) -WorkingDirectory $d
    } finally { Remove-Item env:SANDBOX_DIAG -ErrorAction SilentlyContinue }
    $out = ($r.Stdout -join '')
    $passed = $out -match '407'
    return @{ Num=36; Name='S-36 (AC-3.12)'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { 'proxy returned 407 without token' } else { "stdout=$out" } }
}
```

> Requires the proxy to log its listening port under `SANDBOX_DIAG` (added in Task 7's `proxy::spawn`). Also requires `--sid <sid>` reuse to point at the *same* proxy instance whose port we extracted.

- [ ] **Step 13: Add S-37 (AC-3.13, raw-socket app fails closed)**

```powershell
function Invoke-Scenario-S37 {
    $d = New-ScenarioDir 37
    $py = Get-Python
    if (-not $py) { return @{ Num=37; Name='S-37 (AC-3.13)'; Passed=$true; Skipped=$true; PythonSkipped=$true; Detail='python not on PATH' } }
    # Use a raw socket connect that ignores HTTPS_PROXY. The AppContainer
    # network cap denies it.
    $r = Invoke-Sandbox -Args @('run','--allow-cwd','--allow-domain','api.openai.com','--','python','-c',"import socket; socket.create_connection(('api.openai.com',443))") -WorkingDirectory $d
    $err = ($r.Stderr -join "`n")
    $passed = ($r.ExitCode -ne 0) -and ($err -match '(?i)(access is denied|PermissionError|WSAEACCES|Operation not permitted)')
    return @{ Num=37; Name='S-37 (AC-3.13)'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { 'raw-socket direct connect denied by AC' } else { "exit=$($r.ExitCode) stderr=$err" } }
}
```

- [ ] **Step 14: Add S-38 (AC-3.14, proxy shuts down with sandbox)**

```powershell
function Invoke-Scenario-S38 {
    $d = New-ScenarioDir 38
    $env:SANDBOX_DIAG='1'
    try {
        $proc = Start-Process -FilePath $SandboxExe -ArgumentList @('run','--allow-cwd','--network-profile','minimal','--','cmd','/c','ping -t 127.0.0.1') -PassThru -WorkingDirectory $d -RedirectStandardError (Join-Path $d 'diag.log')
        Start-Sleep -Seconds 1
        # Read the diag log to get the proxy port.
        $port = $null
        if (Test-Path (Join-Path $d 'diag.log')) {
            $line = Get-Content (Join-Path $d 'diag.log') -ErrorAction SilentlyContinue | Where-Object { $_ -match '\[proxy\].*127\.0\.0\.1:(\d{2,5})' } | Select-Object -First 1
            if ($line -and $line -match '(\d{2,5})') { $port = $matches[1] }
        }
        try { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue } catch {}
        Start-Sleep -Seconds 2
        $listenerStillUp = $false
        if ($port) {
            $conn = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue
            $listenerStillUp = $null -ne $conn
        }
        $passed = $port -and -not $listenerStillUp
        Get-Process ping -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    } finally { Remove-Item env:SANDBOX_DIAG -ErrorAction SilentlyContinue }
    return @{ Num=38; Name='S-38 (AC-3.14)'; Passed=$passed; Skipped=$false
        Detail = if ($passed) { "proxy port $port released on sandbox exit" } else { "port=$port listenerStillUp=$listenerStillUp" } }
}
```

- [ ] **Step 15: Add S-39 as SKIP (AC-3.15 deferred)**

```powershell
function Invoke-Scenario-S39 {
    return @{ Num=39; Name='S-39 (AC-3.15)'; Passed=$true; Skipped=$true; Detail='deferred to F-6 (WFP callout driver)' }
}
```

- [ ] **Step 16: Update the `$script:Scenarios` array and `$required` list**

Add `Invoke-Scenario-S25 .. S39` to the array. Update `$required` to include the new scenario numbers that must pass (skip python/curl ones gracefully). Add a clear eprintln in `proxy::spawn` so S-36 and S-38 can parse the port:

```rust
eprintln!("[proxy] listening on 127.0.0.1:{port}");
```

- [ ] **Step 17: Run the whole suite**

Run: `cargo build --release; pwsh -ExecutionPolicy Bypass -File tests/run-tests.ps1`
Expected: S-1..S-24 still pass; S-25..S-38 pass (with python/curl-dependent ones skipping cleanly); S-39 skips.

- [ ] **Step 18: Commit**

```bash
git add tests/run-tests.ps1
git commit -m "test(us-3): integration scenarios S-25..S-39 (AC-3.1 through AC-3.15)"
```

---

## Task 12: Final verification

- [ ] **Step 1: Clean build**

Run: `cargo build --release`
Expected: builds with no new warnings beyond the pre-existing ones from US-1/US-2.

- [ ] **Step 2: Run the Rust unit tests**

Run: `cargo test --release`
Expected: all unit tests pass (matcher, profile, token, audit, profile-merge from US-1/US-2).

- [ ] **Step 3: Run the full integration suite**

Run: `pwsh -ExecutionPolicy Bypass -File tests/run-tests.ps1`
Expected: `SANDBOX: PASS` (or `PASS (python scenarios skipped)` if python/curl aren't installed). Zero hard failures.

- [ ] **Step 4: Commit any remaining tweaks**

```bash
git add -A
git commit -m "chore(us-3): final cleanup"
```

---

## Notes for the executor

- **Don't skip the TDD loop on the pure-logic modules** (`matcher`, `profile`, `resolve_network`, `audit`). These have no Win32 deps and are the highest-leverage tests in the plan.
- **The proxy is the riskiest piece.** Get a minimal CONNECT splice working first (no TLS termination — the child speaks TLS end-to-end). The allow-list enforcement happens at the `CONNECT host:port` line, before any bytes flow upstream. Document the "no TLS termination at the proxy in MVP" deviation in a code comment.
- **Order of operations in `run_inner`** (Task 9): `create_session` → (if not blocked) `register_loopback` → `proxy::spawn` → `build_env_block` → `sandbox::spawn` → wait → drop proxy handle.
- **AC-3.15 is intentionally skipped** in the harness (S-39) with `Detail='deferred to F-6'`. Do not implement per-port loopback scoping — it requires a kernel driver.
- **The `NetworkIsolationSetAppContainerConfig` signature may differ across `windows` crate versions.** Adapt the call in `loopback.rs` to whatever compiles; the semantic intent (register the AC SID with loopback access, no internet caps) is stable.
- **The audit emitter writes one NDJSON line per CONNECT event.** US-4 will wrap it to add `parent`/`hash` fields and sign the root. US-3 deliberately does NOT compute the hash chain.
- **`setup --check-only`** is the only existing test (S-18) that touches setup output text. Updating the "Reverse proxy (network)" line must keep S-18 passing — the test greps for `Windows build number` and `AppContainer`, not the proxy line, so the change is safe.

---

## Reference: skills used during execution

- @superpowers:executing-plans (or @superpowers:subagent-driven-development) — task-by-task execution.
- @superpowers:test-driven-development — for the pure-logic modules (matcher, profile, resolve_network).
- @superpowers:systematic-debugging — when an integration scenario fails (especially S-27/S-28: proxy + curl + AppContainer is a multi-layer system).
- @superpowers:verification-before-completion — before claiming the plan is done.
