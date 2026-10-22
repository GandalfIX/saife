pub mod intent;
pub mod learned;
pub mod loopback;
pub mod matcher;
/// MXC `processcontainer` containment backend (ADR-0004 Option A). Compiled
/// only with the `mxc-backend` feature; the AppContainer supervisor stays the
/// default backend (P3 flips it).
#[cfg(feature = "mxc-backend")]
pub mod mxc;
pub mod profile;
pub mod prompt;
pub mod proxy;
pub mod token;
pub mod upstream;

use crate::net::token::RunToken;
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
        /// Domains always denied, checked before `allow_domain` (deny wins).
        /// Merged from the profile `network.denyDomain` and the CLI `--deny-domain`.
        deny_domain: Vec<String>,
        /// Whether the interactive prompt is shown for unlisted hosts ([G-47]).
        /// Defaults to `true` unless the profile sets `promptEnabled: false` or
        /// the CLI passes `--no-prompt`.
        prompt_enabled: bool,
        /// Action when a host is unavailable / the prompt times out: `"deny"`
        /// (default) or `"allow"`. Profile-only ([G-48]).
        on_unavailable: String,
        /// Seconds before the prompt auto-denies. Default 60; `0` = instant
        /// deny (handled by the prompt layer in D-3.5). Profile-only ([G-46]).
        prompt_timeout_secs: u32,
        /// Upstream proxy URL. Parsed now, consumed in Phase 4.
        upstream_proxy: Option<String>,
        profile_name: Option<String>,
        proxy_port: Option<u16>,
        token: Option<String>,
    },
}

impl NetworkConfig {
    pub fn is_blocked(&self) -> bool {
        matches!(self, NetworkConfig::Blocked)
    }
    /// Reserved for the proxy-bootstrap path (currently the supervisor
    /// dispatches on `is_blocked` alone). Tracked by the US-3 follow-up.
    #[allow(dead_code)]
    pub fn needs_proxy(&self) -> bool {
        matches!(self, NetworkConfig::Allow { .. })
    }
}

/// Proxy configuration injected into the sandboxed child's environment.
/// Carries only what the env block needs; `ProxyConfig` (used by
/// `net::proxy::spawn`) additionally holds the session id and allow-list
/// which the child process does not see.
///
/// `token` is a [`RunToken`], not a `String` (P1.6(c)). The env block
/// interpolates it into `HTTP_PROXY`/`HTTPS_PROXY` as `userinfo`
/// (`http://sandbox:<token>@127.0.0.1:<port>`), where `@` would end the userinfo
/// early and `/` would end the authority - i.e. an unsafe value there changes
/// *which host or port the child is told to use*, while the supervisor goes on
/// proving the port it actually bound. `mxc::proxy_url` has always rejected such
/// a value; this edge had no check at all, only a `String` that anybody could
/// build. Typing the field is the check: the only values that can reach the
/// interpolation are ones a `RunToken` produced.
pub struct ProxyEnv {
    pub port: u16,
    pub token: RunToken,
}

/// Merge profile network slice + CLI flags into a `NetworkConfig` (with
/// port/token placeholders filled in by the proxy layer later).
pub fn resolve_network(
    profile_net: &NetworkSlice,
    cli_block_net: bool,
    cli_allow_domain: &[String],
    cli_deny_domain: &[String],
    cli_no_prompt: bool,
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

    // Merge deny-list from profile + CLI (deny wins over allow; checked first
    // by the proxy/prompt layer).
    let mut deny: Vec<String> = Vec::new();
    deny.extend(profile_net.deny_domain.iter().cloned());
    deny.extend(cli_deny_domain.iter().cloned());
    deny = dedupe(deny);

    // [G-47] prompt defaults to ON when the network is active, unless the
    // profile explicitly sets `promptEnabled: false` or the CLI passes
    // `--no-prompt`.
    let prompt_enabled = !cli_no_prompt && profile_net.prompt_enabled.unwrap_or(true);

    // [G-48] `onUnavailable` defaults to "deny". Profile-only field.
    // Validated against {"deny", "allow"}: an invalid value (e.g. a typo like
    // "denie") falls back to "deny" with a warning, so the resolved
    // `NetworkConfig::Allow.on_unavailable` is always either "deny" or
    // "allow" — the prompt layer (D-3.5) can then match it deterministically.
    let on_unavailable = match profile_net.on_unavailable.as_deref() {
        Some(v) if v == "deny" || v == "allow" => v.to_string(),
        Some(invalid) => {
            eprintln!(
                "[sandbox] invalid onUnavailable value \"{invalid}\", defaulting to \"deny\""
            );
            "deny".to_string()
        }
        None => "deny".to_string(),
    };

    // [G-46] `promptTimeoutSecs` defaults to 60. Profile-only field.
    // `0` means "instant deny" (handled by the prompt layer in D-3.5).
    let prompt_timeout_secs = profile_net.prompt_timeout_secs.unwrap_or(60);

    // Deny-by-default: when neither an allow-list nor a deny-list is present,
    // there is nothing to enforce — skip the proxy entirely. This also avoids
    // spurious "deferred" warnings when the user passes no network flags at
    // all (the common case).
    if allow.is_empty() && deny.is_empty() {
        return NetworkConfig::Blocked;
    }
    // Allow-list mode: an empty allow-list is Blocked only when the prompt is
    // off. When the prompt is on, an empty allow-list means "prompt for
    // everything" (the deny-list still hard-denies its entries).
    if allow.is_empty() && !prompt_enabled {
        return NetworkConfig::Blocked;
    }

    NetworkConfig::Allow {
        allow_domain: allow,
        deny_domain: deny,
        prompt_enabled,
        on_unavailable,
        prompt_timeout_secs,
        upstream_proxy: profile_net.upstream_proxy.clone(),
        profile_name,
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
        let cfg = resolve_network(&empty_slice(), true, &[], &[], false, Some("minimal"));
        assert!(cfg.is_blocked());
    }

    #[test]
    fn none_profile_via_profile_name_blocks() {
        let slice = NetworkSlice {
            profile_name: Some("none".into()),
            ..Default::default()
        };
        let cfg = resolve_network(&slice, false, &[], &[], false, None);
        assert!(cfg.is_blocked());
    }

    #[test]
    fn none_profile_via_cli_blocks() {
        let cfg = resolve_network(&empty_slice(), false, &[], &[], false, Some("none"));
        assert!(cfg.is_blocked());
    }

    #[test]
    fn minimal_profile_plus_cli_allow_domain_merges() {
        let cfg = resolve_network(
            &empty_slice(),
            false,
            &["github.com".into()],
            &[],
            false,
            Some("minimal"),
        );
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
        let cfg = resolve_network(
            &empty_slice(),
            false,
            &["example.com".into()],
            &[],
            false,
            Some("bogus"),
        );
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
        let cfg = resolve_network(&slice, false, &[], &[], false, None);
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
        let cfg = resolve_network(&empty_slice(), false, &[], &[], false, None);
        assert!(matches!(cfg, NetworkConfig::Blocked));
    }

    #[test]
    fn block_net_in_profile_slice_blocks() {
        let slice = NetworkSlice {
            block_net: true,
            ..Default::default()
        };
        let cfg = resolve_network(&slice, false, &[], &[], false, None);
        assert!(cfg.is_blocked());
    }

    #[test]
    fn json_allow_domain_only_propagates() {
        let slice = NetworkSlice {
            allow_domain: vec!["api.anthropic.com".into()],
            ..Default::default()
        };
        let cfg = resolve_network(&slice, false, &[], &[], false, None);
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
        let cfg = resolve_network(&slice, false, &[], &[], false, Some("developer"));
        match cfg {
            NetworkConfig::Allow { allow_domain, .. } => {
                // developer includes github.com, minimal does not.
                assert!(allow_domain.iter().any(|d| d == "github.com"));
                assert_eq!(
                    allow_domain.len(),
                    crate::net::profile::builtin_profile("developer")
                        .unwrap()
                        .len()
                );
            }
            NetworkConfig::Blocked => panic!("expected Allow"),
        }
    }

    #[test]
    fn no_prompt_flag_disables_prompt() {
        let slice = NetworkSlice {
            allow_domain: vec!["a.com".into()],
            ..Default::default()
        };
        let cfg = resolve_network(&slice, false, &["a.com".into()], &[], true, None);
        match cfg {
            NetworkConfig::Allow { prompt_enabled, .. } => assert!(!prompt_enabled),
            _ => panic!("expected Allow"),
        }
    }

    #[test]
    fn prompt_defaults_on_when_network_active() {
        let slice = NetworkSlice {
            allow_domain: vec!["a.com".into()],
            ..Default::default()
        };
        let cfg = resolve_network(&slice, false, &["a.com".into()], &[], false, None);
        match cfg {
            NetworkConfig::Allow { prompt_enabled, .. } => assert!(prompt_enabled),
            _ => panic!("expected Allow"),
        }
    }

    #[test]
    fn deny_domain_merged_from_profile_and_cli() {
        let slice = NetworkSlice {
            allow_domain: vec!["a.com".into()],
            deny_domain: vec!["*.profile-evil.com".into()],
            ..Default::default()
        };
        let cfg = resolve_network(
            &slice,
            false,
            &["a.com".into()],
            &["*.cli-evil.com".into()],
            false,
            None,
        );
        match cfg {
            NetworkConfig::Allow { deny_domain, .. } => {
                assert!(deny_domain.iter().any(|d| d == "*.profile-evil.com"));
                assert!(deny_domain.iter().any(|d| d == "*.cli-evil.com"));
            }
            _ => panic!("expected Allow"),
        }
    }

    #[test]
    fn on_unavailable_defaults_to_deny() {
        let slice = NetworkSlice {
            allow_domain: vec!["a.com".into()],
            ..Default::default()
        };
        let cfg = resolve_network(&slice, false, &["a.com".into()], &[], false, None);
        match cfg {
            NetworkConfig::Allow { on_unavailable, .. } => assert_eq!(on_unavailable, "deny"),
            _ => panic!("expected Allow"),
        }
    }

    #[test]
    fn prompt_timeout_secs_defaults_to_60() {
        let slice = NetworkSlice {
            allow_domain: vec!["a.com".into()],
            ..Default::default()
        };
        let cfg = resolve_network(&slice, false, &["a.com".into()], &[], false, None);
        match cfg {
            NetworkConfig::Allow {
                prompt_timeout_secs,
                ..
            } => assert_eq!(prompt_timeout_secs, 60),
            _ => panic!("expected Allow"),
        }
    }

    #[test]
    fn profile_prompt_enabled_false_overrides_default() {
        let slice = NetworkSlice {
            allow_domain: vec!["a.com".into()],
            prompt_enabled: Some(false),
            ..Default::default()
        };
        let cfg = resolve_network(&slice, false, &["a.com".into()], &[], false, None);
        match cfg {
            NetworkConfig::Allow { prompt_enabled, .. } => assert!(!prompt_enabled),
            _ => panic!("expected Allow"),
        }
    }

    #[test]
    fn on_unavailable_invalid_value_falls_back_to_deny() {
        // A typo like "denie" must not silently pass through; the resolved
        // on_unavailable is always either "deny" or "allow" so the prompt
        // layer (D-3.5) can match it deterministically.
        let slice = NetworkSlice {
            allow_domain: vec!["a.com".into()],
            on_unavailable: Some("denie".into()),
            ..Default::default()
        };
        let cfg = resolve_network(&slice, false, &["a.com".into()], &[], false, None);
        match cfg {
            NetworkConfig::Allow { on_unavailable, .. } => {
                assert_eq!(
                    on_unavailable, "deny",
                    "invalid onUnavailable must fall back to \"deny\""
                );
            }
            _ => panic!("expected Allow"),
        }
    }

    #[test]
    fn deny_only_mode_prompts_for_everything_not_denied() {
        // allow empty + deny non-empty + prompt on → Allow (prompt for
        // everything not in the deny-list). Exercises the branch where
        // allow.is_empty() && !deny.is_empty() skips the first Blocked
        // check and prompt_enabled keeps it off the second.
        let slice = NetworkSlice {
            deny_domain: vec!["*.evil.com".into()],
            ..Default::default()
        };
        let cfg = resolve_network(&slice, false, &[], &["*.evil.com".into()], false, None);
        match cfg {
            NetworkConfig::Allow {
                allow_domain,
                deny_domain,
                prompt_enabled,
                ..
            } => {
                assert!(
                    allow_domain.is_empty(),
                    "allow-list should be empty in deny-only mode"
                );
                assert_eq!(deny_domain, vec!["*.evil.com".to_string()]);
                assert!(
                    prompt_enabled,
                    "prompt must be on so empty allow means prompt-for-all"
                );
            }
            _ => panic!("expected Allow in deny-only mode"),
        }
    }

    #[test]
    fn no_prompt_with_deny_only_yields_blocked() {
        // allow empty + deny non-empty + prompt off → Blocked. The deny-list
        // alone can't form a usable Allow config when there is nothing to
        // allow and no prompt to ask the user. Exercises the
        // `allow.is_empty() && !prompt_enabled → Blocked` branch (deny
        // non-empty is required to reach it; otherwise the earlier
        // `allow.is_empty() && deny.is_empty()` check intercepts).
        let slice = NetworkSlice {
            deny_domain: vec!["*.evil.com".into()],
            ..Default::default()
        };
        let cfg = resolve_network(&slice, false, &[], &["*.evil.com".into()], true, None);
        assert!(
            matches!(cfg, NetworkConfig::Blocked),
            "no-prompt + deny-only must be Blocked"
        );
    }
}
