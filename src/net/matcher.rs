//! Domain allow-list matching + always-denied destination enforcement.
//!
//! Pure functions. Unit-tested in this file. The proxy and the CLI both
//! call into here so the matching logic has exactly one implementation.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Always-denied IPv4 CIDRs (AC-3.6, AC-3.7). Link-local + AWS/GCP/Azure
/// metadata.
pub const ALWAYS_DENIED_V4_CIDRS: &[(Ipv4Addr, u8)] = &[(Ipv4Addr::new(169, 254, 0, 0), 16)];
/// Always-denied IPv4 literals.
pub const ALWAYS_DENIED_V4_HOSTS: &[&str] = &["169.254.169.254"];
/// Always-denied IPv6 CIDRs (link-local).
pub const ALWAYS_DENIED_V6_CIDRS: &[(Ipv6Addr, u8)] = &[(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0xfe80, 0), 10)];
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
                    if in_v4_cidr(*v, *net, *prefix) {
                        return true;
                    }
                }
            }
            IpAddr::V6(v) => {
                for (net, prefix) in ALWAYS_DENIED_V6_CIDRS {
                    if in_v6_cidr(*v, *net, *prefix) {
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
