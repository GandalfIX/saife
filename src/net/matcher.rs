//! Domain allow-list matching + always-denied destination enforcement.
//!
//! Pure functions. Unit-tested in this file. The proxy and the CLI both
//! call into here so the matching logic has exactly one implementation.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Always-denied IPv4 CIDRs (AC-3.6, AC-3.7). Link-local + AWS/GCP/Azure
/// metadata.
pub const ALWAYS_DENIED_V4_CIDRS: &[(Ipv4Addr, u8)] = &[(Ipv4Addr::new(169, 254, 0, 0), 16)];
/// Canonical always-denied IPv4 host-strings (retained for reference; IP-path
/// uses `ALWAYS_DENIED_V4_LITERALS`/CIDRs post-split per [G-45]). Not consulted
/// by `is_hard_denied_host`/`is_hard_denied_ip`; the pre-resolution host-string
/// deny check that will consume this lands in D-3.6.
#[allow(dead_code)]
pub const ALWAYS_DENIED_V4_HOSTS: &[&str] = &["169.254.169.254", "169.254.169.253"];
/// Always-denied IPv6 CIDRs (link-local).
pub const ALWAYS_DENIED_V6_CIDRS: &[(Ipv6Addr, u8)] =
    // Link-local fe80::/10 ([G-45]). The network must be `fe80::` —
    // `Ipv6Addr::new(0xfe80, 0, ..)` (first segment). An earlier encoding
    // passed `0xfe80` as the 7th segment, silently encoding `::fe80:0/10`
    // instead; caught by the Task 3.6 pipeline tests.
    &[(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0), 10)];
/// Always-denied DNS names (checked pre-resolution, AC-3.7).
pub const ALWAYS_DENIED_DNS: &[&str] = &[
    "metadata.google.internal",
    "metadata.azure.internal",
    "metadata.tencentyun.com",
];
/// Always-denied IPv4 literals (the IP set from [G-45]). Precomputed as
/// `Ipv4Addr` (const-constructible) so `is_hard_denied_ip` compares directly
/// without reparsing the `&str` form per request. Distinct from the
/// hostname-string set so audit attribution is precise (`source: "hard-deny"`
/// with the right sub-reason).
const ALWAYS_DENIED_V4_LITERALS: &[Ipv4Addr] = &[
    Ipv4Addr::new(169, 254, 169, 254),
    Ipv4Addr::new(169, 254, 169, 253),
    Ipv4Addr::new(100, 100, 100, 200),
];

/// Reason codes used in the audit log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenyReason {
    DomainNotAllowed,
    DeniedCidr,
    DeniedDns,
    DeniedDomain,
}

impl DenyReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            DenyReason::DomainNotAllowed => "domain_not_allowed",
            DenyReason::DeniedCidr => "denied_cidr",
            DenyReason::DeniedDns => "denied_dns",
            DenyReason::DeniedDomain => "denied_domain",
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
/// `entry`? Implements the wildcard rule from [G-55]: `*.suffix` matches
/// `suffix` (the apex) and any subdomain (`foo.suffix`), but NOT
/// `suffix.evil.io` (suffix doesn't cross dots).
pub fn matches(host: &str, entry: &str) -> bool {
    let h = host.trim_end_matches('.').to_ascii_lowercase();
    let e = entry.trim_end_matches('.').to_ascii_lowercase();
    if let Some(suffix) = e.strip_prefix("*.") {
        // [G-55] apex + subdomain, not cross-dot. Allocation-free:
        // `h == suffix` is the apex; otherwise `h` must end with `.suffix`
        // (strip `suffix`, the remainder must end with '.').
        h == suffix || h.strip_suffix(suffix).is_some_and(|p| p.ends_with('.'))
    } else {
        h == e
    }
}

/// Is `host` (a hostname, no port) on the hard-deny DNS-name list?
/// Case-insensitive, trailing dot stripped. Does NOT check IPs — see
/// [`is_hard_denied_ip`]. The two are separate so audit `source: "hard-deny"`
/// attribution distinguishes a hostname deny from an IP deny.
pub fn is_hard_denied_host(host: &str) -> bool {
    let h = host.trim_end_matches('.').to_ascii_lowercase();
    ALWAYS_DENIED_DNS.iter().any(|d| **d == h)
}

/// Is `ip` on the hard-deny IP list (literal match or link-local CIDR)?
/// Covers `ALWAYS_DENIED_V4_LITERALS` + `ALWAYS_DENIED_V4_CIDRS` +
/// `ALWAYS_DENIED_V6_CIDRS`. IPv4-mapped IPv6 forms are unmapped first.
/// Loopback (`127.0.0.0/8`, `::1`) or the unspecified address (`0.0.0.0`, `::`).
/// IPv4-mapped IPv6 is unmapped first so `::ffff:127.0.0.1` cannot slip through.
pub fn is_loopback_or_unspecified(ip: IpAddr) -> bool {
    match unmap_ipv4_mapped(ip) {
        IpAddr::V4(v) => v.is_loopback() || v.is_unspecified(),
        IpAddr::V6(v) => v.is_loopback() || v.is_unspecified(),
    }
}

pub fn is_hard_denied_ip(ip: IpAddr) -> bool {
    let ip = unmap_ipv4_mapped(ip);
    // NOTE: loopback is deliberately NOT part of this predicate. It is a POLICY
    // refusal ([G-44]), applied by the proxy's decision leg, not a property of the
    // address: this predicate also feeds the direct-dialer's debug assertion and
    // the tests that use a local server as an upstream. See
    // `proxy::pinned_addrs_hard_denied`.
    match ip {
        IpAddr::V4(v) => {
            if ALWAYS_DENIED_V4_LITERALS.contains(&v) {
                return true;
            }
            for (net, prefix) in ALWAYS_DENIED_V4_CIDRS {
                if in_v4_cidr(v, *net, *prefix) {
                    return true;
                }
            }
            false
        }
        IpAddr::V6(v) => {
            for (net, prefix) in ALWAYS_DENIED_V6_CIDRS {
                if in_v6_cidr(v, *net, *prefix) {
                    return true;
                }
            }
            false
        }
    }
}

/// Unmap IPv4-mapped IPv6 (::ffff:a.b.c.d) to the IPv4 form, so the
/// hard-deny IP check works on mapped addresses returned by dual-stack
/// resolvers.
fn unmap_ipv4_mapped(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v) if is_ipv4_mapped(&v) => {
            let octets = v.octets();
            IpAddr::V4(Ipv4Addr::new(
                octets[12], octets[13], octets[14], octets[15],
            ))
        }
        other => other,
    }
}

/// Is `v` an IPv4-mapped IPv6 address (::ffff:a.b.c.d)? Manual check —
/// `Ipv6Addr::is_ipv4_mapped` is unstable on stable Rust.
fn is_ipv4_mapped(v: &Ipv6Addr) -> bool {
    let o = v.octets();
    o[0] == 0
        && o[1] == 0
        && o[2] == 0
        && o[3] == 0
        && o[4] == 0
        && o[5] == 0
        && o[6] == 0
        && o[7] == 0
        && o[8] == 0
        && o[9] == 0
        && o[10] == 0xff
        && o[11] == 0xff
}

/// Legacy combined check. Prefer [`is_hard_denied_host`] + [`is_hard_denied_ip`]
/// for precise audit attribution.
//
// Kept as the transitional API the spec (D-3.2 Step 2) mandates for call sites
// that have not yet migrated to the split functions. No production call site
// consumes it after D-3.2 (the sole caller, `check`, was rewritten to use the
// split functions); `dead_code` is allowed here so the wrapper remains
// available for D-3.6 wiring and any external consumers. The `deprecated`
// attribute surfaces a warning at any future use site.
#[allow(dead_code)]
#[deprecated(note = "use is_hard_denied_host + is_hard_denied_ip")]
pub fn is_always_denied(host: &str, resolved_ips: &[IpAddr]) -> bool {
    is_hard_denied_host(host) || resolved_ips.iter().any(|ip| is_hard_denied_ip(*ip))
}

fn in_v4_cidr(ip: Ipv4Addr, net: Ipv4Addr, prefix: u8) -> bool {
    let mask: u32 = if prefix == 0 {
        0
    } else {
        (!0u32) << (32 - prefix)
    };
    let ipn = u32::from(ip) & mask;
    let netn = u32::from(net) & mask;
    ipn == netn
}

fn in_v6_cidr(ip: Ipv6Addr, net: Ipv6Addr, prefix: u8) -> bool {
    let ipb = ip.octets();
    let netb = net.octets();
    let full = (prefix / 8) as usize;
    let rem = prefix % 8;
    if ipb[..full] != netb[..full] {
        return false;
    }
    if rem == 0 {
        return true;
    }
    let mask = (!0u8) << (8 - rem);
    (ipb[full] & mask) == (netb[full] & mask)
}

/// Full verdict pipeline: hard-deny → deny_domain → allow-list.
/// `deny_list` is the `deny_domain` blocklist ([G-32]); `allow_list` is the
/// allow-list. Pipeline ordering is load-bearing for audit `source`
/// attribution ([G-33]).
pub fn check(
    host: &str,
    resolved_ips: &[IpAddr],
    deny_list: &[String],
    allow_list: &[String],
) -> Verdict {
    // 1. Hard-deny (hostname set + IP set + CIDR).
    if is_hard_denied_host(host) {
        return Verdict::Deny(DenyReason::DeniedDns);
    }
    for ip in resolved_ips {
        if is_hard_denied_ip(*ip) {
            return Verdict::Deny(DenyReason::DeniedCidr);
        }
    }
    // 2. deny_domain blocklist ([G-32, G-33]).
    if deny_list.iter().any(|e| matches(host, e)) {
        return Verdict::Deny(DenyReason::DeniedDomain);
    }
    // 3. Allow-list.
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
        // [G-55] Bare apex IS matched by *.anthropic.com now.
        assert!(matches("anthropic.com", "*.anthropic.com"));
        // Suffix does not cross dots.
        assert!(!matches("anthropic.com.evil.io", "*.anthropic.com"));
    }

    #[test]
    fn wildcard_apex_matches_now() {
        // [G-55] regression: *.anthropic.com now matches the apex.
        assert!(matches("anthropic.com", "*.anthropic.com"));
        assert!(matches("api.anthropic.com", "*.anthropic.com"));
        assert!(!matches("anthropic.com.evil.io", "*.anthropic.com"));
    }

    #[test]
    fn v4_cidr_169_254() {
        assert!(in_v4_cidr(
            "169.254.169.254".parse().unwrap(),
            "169.254.0.0".parse().unwrap(),
            16
        ));
        assert!(in_v4_cidr(
            "169.254.0.1".parse().unwrap(),
            "169.254.0.0".parse().unwrap(),
            16
        ));
        assert!(!in_v4_cidr(
            "169.255.0.1".parse().unwrap(),
            "169.254.0.0".parse().unwrap(),
            16
        ));
    }

    #[test]
    fn v6_link_local() {
        assert!(in_v6_cidr(
            "fe80::1".parse().unwrap(),
            "fe80::".parse().unwrap(),
            10
        ));
        assert!(!in_v6_cidr(
            "fe70::1".parse().unwrap(),
            "fe80::".parse().unwrap(),
            10
        ));
    }

    #[test]
    fn hard_denied_dns() {
        assert!(is_hard_denied_host("metadata.google.internal"));
        assert!(is_hard_denied_host("METADATA.google.INTERNAL."));
        assert!(is_hard_denied_host("metadata.azure.internal"));
        assert!(is_hard_denied_host("metadata.tencentyun.com"));
        assert!(!is_hard_denied_host("api.anthropic.com"));
    }

    #[test]
    fn hard_denied_ip_literal() {
        let ip: IpAddr = "169.254.169.254".parse().unwrap();
        assert!(is_hard_denied_ip(ip));
        let ip: IpAddr = "169.254.169.253".parse().unwrap();
        assert!(is_hard_denied_ip(ip));
        let ip: IpAddr = "100.100.100.200".parse().unwrap();
        assert!(is_hard_denied_ip(ip));
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        assert!(!is_hard_denied_ip(ip));
    }

    #[test]
    fn hard_denied_ip_v6_link_local_literal() {
        // fe80::/10 is hard-denied ([G-45]). Regression guard for the
        // CIDR constant encoding: the network must be `fe80::` (first
        // segment), never `::fe80:0` (seventh segment).
        let ip: IpAddr = "fe80::1".parse().unwrap();
        assert!(is_hard_denied_ip(ip));
        let ip: IpAddr = "fe80:abcd:1234::ff".parse().unwrap();
        assert!(is_hard_denied_ip(ip));
        let ip: IpAddr = "fe70::1".parse().unwrap();
        assert!(!is_hard_denied_ip(ip));
        let ip: IpAddr = "2001:db8::1".parse().unwrap();
        assert!(!is_hard_denied_ip(ip));
    }

    #[test]
    fn ipv4_mapped_ipv6_unmapped_for_hard_deny() {
        // ::ffff:169.254.169.254 unmapped → 169.254.169.254 → hard-denied.
        let mapped: IpAddr = "::ffff:169.254.169.254".parse().unwrap();
        assert!(is_hard_denied_ip(mapped));
    }

    #[test]
    fn check_overrides_allow_with_cidr() {
        let ips = [IpAddr::V4("169.254.169.254".parse().unwrap())];
        let allow = vec![
            "169.254.169.254".to_string(),
            "api.anthropic.com".to_string(),
        ];
        assert_eq!(
            check("169.254.169.254", &ips, &[], &allow),
            Verdict::Deny(DenyReason::DeniedCidr)
        );
        assert_eq!(check("api.anthropic.com", &[], &[], &allow), Verdict::Allow);
    }

    #[test]
    fn check_dns_deny_reason() {
        // AC-3.7: metadata.google.internal denied with reason=denied_dns.
        assert_eq!(
            check("metadata.google.internal", &[], &[], &[]),
            Verdict::Deny(DenyReason::DeniedDns)
        );
    }

    #[test]
    fn check_unlisted_host_denied() {
        assert_eq!(
            check("evil.example.com", &[], &[], &["api.anthropic.com".into()]),
            Verdict::Deny(DenyReason::DomainNotAllowed)
        );
    }

    #[test]
    fn deny_domain_wins_over_allow() {
        // [G-32, G-33] deny_domain checked before allow-list.
        //
        // Note: the deny entry must actually match the host under the Step 3
        // wildcard rule (`*.suffix` matches `suffix` + its subdomains, not
        // cross-dot). `*.example.com` matches `evil.example.com`, which is
        // also in the allow-list — so a Deny(DeniedDomain) outcome proves the
        // deny_domain stage runs before the allow-list stage.
        let deny = vec!["*.example.com".to_string()];
        let allow = vec!["evil.example.com".to_string()];
        assert_eq!(
            check("evil.example.com", &[], &deny, &allow),
            Verdict::Deny(DenyReason::DeniedDomain)
        );
    }

    #[test]
    fn deny_domain_exact_match() {
        let deny = vec!["api.evil.com".to_string()];
        assert_eq!(
            check("api.evil.com", &[], &deny, &[]),
            Verdict::Deny(DenyReason::DeniedDomain)
        );
    }

    #[test]
    fn deny_domain_wildcard_matches_apex() {
        // [G-55] apex match applies to deny_domain too.
        let deny = vec!["*.evil.com".to_string()];
        assert_eq!(
            check("evil.com", &[], &deny, &[]),
            Verdict::Deny(DenyReason::DeniedDomain)
        );
        assert_eq!(
            check("api.evil.com", &[], &deny, &[]),
            Verdict::Deny(DenyReason::DeniedDomain)
        );
        assert_eq!(
            check("not-evil.com", &[], &deny, &[]),
            Verdict::Deny(DenyReason::DomainNotAllowed)
        );
    }

    #[test]
    fn hard_deny_precedes_deny_domain() {
        // [G-33] hard-deny (hostname set) is step 1, before deny_domain (step 2).
        // metadata.google.internal is in the hard-deny DNS list; even if it's also
        // in deny_domain, the hard-deny reason wins.
        assert_eq!(
            check(
                "metadata.google.internal",
                &[],
                &["metadata.google.internal".into()],
                &[]
            ),
            Verdict::Deny(DenyReason::DeniedDns),
        );
    }
}
