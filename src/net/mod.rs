pub mod loopback;
pub mod matcher;
pub mod profile;
pub mod proxy;
pub mod token;

use crate::profile::NetworkSlice;

/// The fully-resolved network configuration for a session.
#[derive(Debug, Clone)]
pub enum NetworkConfig {
    /// `--block-net` / `none` profile: no proxy, no network capability.
    Blocked,
    /// Allow-list mode: proxy started on a random loopback port.
    ///
    /// `proxy_port` and `token` are placeholders filled in by the proxy
    /// layer when the proxy-bootstrap path lands (currently deferred —
    /// see `main.rs`). Held in the config so the resolved form stays
    /// self-describing for diagnostics and the US-3 follow-up.
    #[allow(dead_code)]
    Allow {
        allow_domain: Vec<String>,
        proxy_port: Option<u16>,
        token: Option<String>,
    },
}

impl NetworkConfig {
    pub fn is_blocked(&self) -> bool { matches!(self, NetworkConfig::Blocked) }
    /// Reserved for the proxy-bootstrap path (currently the supervisor
    /// dispatches on `is_blocked` alone). Tracked by the US-3 follow-up.
    #[allow(dead_code)]
    pub fn needs_proxy(&self) -> bool { matches!(self, NetworkConfig::Allow { .. }) }
}

/// Proxy configuration injected into the sandboxed child's environment.
/// Carries only what the env block needs; `ProxyConfig` (used by
/// `net::proxy::spawn`) additionally holds the session id and allow-list
/// which the child process does not see.
pub struct ProxyEnv {
    pub port: u16,
    pub token: String,
}

/// Merge profile network slice + CLI flags into a `NetworkConfig` (with
/// port/token placeholders filled in by the proxy layer later).
pub fn resolve_network(
    profile_net: &NetworkSlice,
    cli_block_net: bool,
    cli_allow_domain: &[String],
    cli_network_profile: Option<&str>,
) -> NetworkConfig {
    let block = cli_block_net
        || profile_net.block_net
        || cli_network_profile == Some("none")
        || profile_net.profile_name.as_deref() == Some("none");
    if block {
        return NetworkConfig::Blocked;
    }

    let mut allow: Vec<String> = Vec::new();

    let profile_name = cli_network_profile
        .map(|s| s.to_string())
        .or_else(|| profile_net.profile_name.clone());

    if let Some(name) = &profile_name {
        if let Some(builtin) = crate::net::profile::builtin_profile(name) {
            allow.extend(builtin);
        } else if name != "none" {
            eprintln!("[sandbox] warning: unknown network profile `{name}`");
        }
    }

    allow.extend(profile_net.allow_domain.iter().cloned());
    allow.extend(cli_allow_domain.iter().cloned());
    allow = dedupe(allow);

    // Deny-by-default: an empty allow-list is semantically identical to
    // Blocked (the proxy would deny every host), so skip the proxy entirely.
    // This also avoids spurious "deferred" warnings when the user passes no
    // network flags at all (the common case).
    if allow.is_empty() {
        return NetworkConfig::Blocked;
    }

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
        if seen.insert(key) {
            out.push(s);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_slice() -> NetworkSlice {
        NetworkSlice::default()
    }

    #[test]
    fn block_net_flag_wins_even_with_profile() {
        let cfg = resolve_network(&empty_slice(), true, &[], Some("minimal"));
        assert!(cfg.is_blocked());
    }

    #[test]
    fn none_profile_via_profile_name_blocks() {
        let slice = NetworkSlice {
            profile_name: Some("none".into()),
            ..Default::default()
        };
        let cfg = resolve_network(&slice, false, &[], None);
        assert!(cfg.is_blocked());
    }

    #[test]
    fn none_profile_via_cli_blocks() {
        let cfg = resolve_network(&empty_slice(), false, &[], Some("none"));
        assert!(cfg.is_blocked());
    }

    #[test]
    fn minimal_profile_plus_cli_allow_domain_merges() {
        let cfg = resolve_network(&empty_slice(), false, &["github.com".into()], Some("minimal"));
        match cfg {
            NetworkConfig::Allow { allow_domain, .. } => {
                // minimal includes api.openai.com etc. but not github.com
                assert!(allow_domain.iter().any(|d| d == "api.openai.com"));
                assert!(allow_domain.iter().any(|d| d == "github.com"));
            }
            NetworkConfig::Blocked => panic!("expected Allow"),
        }
    }

    #[test]
    fn unknown_profile_does_not_crash() {
        // Returns Allow with just CLI/domain entries; warning printed to stderr.
        let cfg = resolve_network(&empty_slice(), false, &["example.com".into()], Some("bogus"));
        match cfg {
            NetworkConfig::Allow { allow_domain, .. } => {
                assert_eq!(allow_domain, vec!["example.com".to_string()]);
            }
            NetworkConfig::Blocked => panic!("expected Allow"),
        }
    }

    #[test]
    fn dedupe_is_case_insensitive() {
        let slice = NetworkSlice {
            allow_domain: vec!["api.anthropic.com".into(), "API.ANTHROPIC.COM".into()],
            ..Default::default()
        };
        let cfg = resolve_network(&slice, false, &[], None);
        match cfg {
            NetworkConfig::Allow { allow_domain, .. } => {
                assert_eq!(allow_domain.len(), 1);
            }
            NetworkConfig::Blocked => panic!("expected Allow"),
        }
    }

    #[test]
    fn empty_everything_yields_blocked() {
        // Deny-by-default: no flags + no profile + no allow-list → Blocked
        // (not Allow-with-empty-list, which would spuriously trigger the
        // proxy + deferred-warning path).
        let cfg = resolve_network(&empty_slice(), false, &[], None);
        assert!(matches!(cfg, NetworkConfig::Blocked));
    }

    #[test]
    fn block_net_in_profile_slice_blocks() {
        let slice = NetworkSlice {
            block_net: true,
            ..Default::default()
        };
        let cfg = resolve_network(&slice, false, &[], None);
        assert!(cfg.is_blocked());
    }

    #[test]
    fn json_allow_domain_only_propagates() {
        let slice = NetworkSlice {
            allow_domain: vec!["api.anthropic.com".into()],
            ..Default::default()
        };
        let cfg = resolve_network(&slice, false, &[], None);
        match cfg {
            NetworkConfig::Allow { allow_domain, .. } => {
                assert_eq!(allow_domain, vec!["api.anthropic.com".to_string()]);
            }
            NetworkConfig::Blocked => panic!("expected Allow"),
        }
    }

    #[test]
    fn cli_profile_name_overrides_slice_profile_name() {
        let slice = NetworkSlice {
            profile_name: Some("minimal".into()),
            ..Default::default()
        };
        let cfg = resolve_network(&slice, false, &[], Some("developer"));
        match cfg {
            NetworkConfig::Allow { allow_domain, .. } => {
                // developer includes github.com, minimal does not.
                assert!(allow_domain.iter().any(|d| d == "github.com"));
                assert_eq!(
                    allow_domain.len(),
                    crate::net::profile::builtin_profile("developer").unwrap().len()
                );
            }
            NetworkConfig::Blocked => panic!("expected Allow"),
        }
    }
}
