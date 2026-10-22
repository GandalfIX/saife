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

/// Default workload term in seconds: the `network.workloadTimeoutSecs` default
/// (30 min), and the number [`crate::net::mxc::WORKLOAD_BUDGET`] is built from
/// (P2.1 review, item 6).
///
/// The session bound is new in P2.1 (the container used to have no deadline at
/// all), so a profile whose workload legitimately runs longer — a cold build, a
/// large download — must raise it. The default exists to bound a wedged child,
/// not to size a normal run.
pub const DEFAULT_WORKLOAD_TIMEOUT_SECS: u32 = 30 * 60;

/// Ceiling for `network.workloadTimeoutSecs`: 24 hours.
///
/// Validation, not policy: the container's `timeout_ms` is a `u32` of
/// milliseconds (49 days), so an absurd value survives the arithmetic and becomes
/// a session nothing will ever reclaim. A day is already far past any workload this
/// tool runs; beyond it the honest reading is "a wedged session", and refusing the
/// value (with a warning and the default) is the fail-closed answer.
pub const MAX_WORKLOAD_TIMEOUT_SECS: u32 = 24 * 60 * 60;

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
        /// Seconds the workload itself may run before the container kills it.
        /// Default [`DEFAULT_WORKLOAD_TIMEOUT_SECS`] (30 min), validated
        /// `> 0` and `<=` [`MAX_WORKLOAD_TIMEOUT_SECS`] (P2.1 review, item 6).
        /// This is the term the session budget reserves for the workload; a
        /// profile that needs longer must raise it.
        workload_timeout_secs: u32,
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

    /// The session budget this configuration resolves to (P2.1 review, item 6).
    ///
    /// The launch path must size the container's deadline from THIS, never from
    /// [`crate::net::mxc::SessionBudget::default`]: the dialogs get the resolved
    /// `promptTimeoutSecs` (see `main.rs`), so a budget built from the constant
    /// would reserve 60 s for a dialog a 300 s profile lets run — and kill a
    /// legitimate dialog plus a full workload. One resolved config, one budget.
    ///
    /// A blocked session still gets a budget: it runs a container too, and the
    /// defaults are what bound it.
    #[cfg(feature = "mxc-backend")]
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn session_budget(&self) -> crate::net::mxc::SessionBudget {
        match self {
            Self::Allow {
                prompt_timeout_secs,
                workload_timeout_secs,
                ..
            } => crate::net::mxc::SessionBudget::from_config(
                *prompt_timeout_secs,
                *workload_timeout_secs,
                crate::net::mxc::SESSION_SLACK,
            ),
            Self::Blocked => crate::net::mxc::SessionBudget::default(),
        }
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

/// [`resolve_network_with`] with the facade flag off.
///
/// Kept for the resolution table tests, which read better without a trailing
/// `false`; the supervisor always goes through `resolve_network_with`, because it
/// is the one caller that knows whether plugins were requested.
#[cfg(test)]
pub fn resolve_network(
    profile_net: &NetworkSlice,
    cli_block_net: bool,
    cli_allow_domain: &[String],
    cli_deny_domain: &[String],
    cli_no_prompt: bool,
    cli_network_profile: Option<&str>,
) -> NetworkConfig {
    resolve_network_with(
        profile_net,
        cli_block_net,
        cli_allow_domain,
        cli_deny_domain,
        cli_no_prompt,
        cli_network_profile,
        false,
    )
}

/// [`resolve_network`] with the plugin-facade flag.
///
/// A session that requested a plugin needs the LISTENER, because the facade route
/// exists only in the proxy — but it must not gain an ORIGIN. With
/// `facade_requested` the two "nothing to enforce, skip the proxy" short-circuits
/// are skipped and the resolved `Allow` keeps exactly the allow-list the operator
/// declared (usually empty, i.e. every non-facade host is denied or prompted as
/// before). An explicit block still wins: `--block-net` and the `none` network
/// profile name no listener at all, so `--plugin` is refused there by the caller.
#[allow(clippy::too_many_arguments)]
pub fn resolve_network_with(
    profile_net: &NetworkSlice,
    cli_block_net: bool,
    cli_allow_domain: &[String],
    cli_deny_domain: &[String],
    cli_no_prompt: bool,
    cli_network_profile: Option<&str>,
    facade_requested: bool,
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
    // `0` means "instant deny" (handled by the prompt layer in D-3.5). The
    // default comes from the SAME constant the prompt layer and the session
    // budget use, so `SessionBudget::default()` and a default profile agree by
    // construction (P2.1 review, item 6).
    let prompt_timeout_secs = profile_net
        .prompt_timeout_secs
        .unwrap_or(crate::net::prompt::DEFAULT_PROMPT_TIMEOUT_SECS);

    // P2.1 review (item 6): `workloadTimeoutSecs` is the workload term the session
    // budget reserves. Validated here (like `onUnavailable`) because an absurd
    // value would become a container deadline nothing reclaims: `0` would end every
    // session before the workload started, and beyond the cap the value can only be
    // a wedged session. A rejected value falls back to the default with a warning,
    // so the resolved field is always in range.
    let workload_timeout_secs = match profile_net.workload_timeout_secs {
        Some(v) if v > 0 && v <= MAX_WORKLOAD_TIMEOUT_SECS => v,
        Some(invalid) => {
            eprintln!(
                "[sandbox] invalid workloadTimeoutSecs value {invalid} (must be 1..=\
                 {MAX_WORKLOAD_TIMEOUT_SECS}), defaulting to {DEFAULT_WORKLOAD_TIMEOUT_SECS}"
            );
            DEFAULT_WORKLOAD_TIMEOUT_SECS
        }
        None => DEFAULT_WORKLOAD_TIMEOUT_SECS,
    };

    // Deny-by-default: when neither an allow-list nor a deny-list is present,
    // there is nothing to enforce — skip the proxy entirely. This also avoids
    // spurious "deferred" warnings when the user passes no network flags at
    // all (the common case).
    if allow.is_empty() && deny.is_empty() && !facade_requested {
        return NetworkConfig::Blocked;
    }
    // Allow-list mode: an empty allow-list is Blocked only when the prompt is
    // off. When the prompt is on, an empty allow-list means "prompt for
    // everything" (the deny-list still hard-denies its entries).
    if allow.is_empty() && !prompt_enabled && !facade_requested {
        return NetworkConfig::Blocked;
    }

    NetworkConfig::Allow {
        allow_domain: allow,
        deny_domain: deny,
        prompt_enabled,
        on_unavailable,
        prompt_timeout_secs,
        workload_timeout_secs,
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
    fn a_facade_only_session_gets_a_listener_and_no_origin() {
        // `--plugin` needs the proxy (that is where the facade route lives), but
        // it must not grant an origin: the allow-list stays empty and prompting
        // stays off, so every non-facade host is denied exactly as before.
        let cfg = resolve_network_with(&empty_slice(), false, &[], &[], true, None, true);
        match cfg {
            NetworkConfig::Allow {
                allow_domain,
                prompt_enabled,
                ..
            } => {
                assert!(
                    allow_domain.is_empty(),
                    "the facade must not add an allowed domain"
                );
                assert!(!prompt_enabled, "no-prompt still means no prompting");
            }
            other => panic!("expected a listener for a facade-only session, got {other:?}"),
        }
    }

    #[test]
    fn a_facade_does_not_survive_block_net() {
        // `--block-net` names no listener, so asking for a plugin cannot open one.
        let cfg = resolve_network_with(&empty_slice(), true, &[], &[], false, None, true);
        assert!(cfg.is_blocked(), "--block-net must still win over --plugin");
    }

    #[test]
    fn without_a_facade_an_empty_network_is_still_blocked() {
        assert!(
            resolve_network_with(&empty_slice(), false, &[], &[], false, None, false).is_blocked(),
            "the facade flag is the only thing that keeps an empty network alive"
        );
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

    /// P2.1 review (item 6): the workload term is a profile knob, defaulting to the
    /// same 30 minutes the budget constant is built from, and validated into range.
    #[test]
    fn workload_timeout_defaults_and_is_validated_into_range() {
        let slice = NetworkSlice {
            allow_domain: vec!["a.com".into()],
            ..Default::default()
        };
        match resolve_network(&slice, false, &["a.com".into()], &[], false, None) {
            NetworkConfig::Allow {
                workload_timeout_secs,
                ..
            } => assert_eq!(
                workload_timeout_secs, DEFAULT_WORKLOAD_TIMEOUT_SECS,
                "an unset workloadTimeoutSecs must resolve to the documented default"
            ),
            _ => panic!("expected Allow"),
        }

        // In range: kept verbatim.
        for accepted in [1, 600, MAX_WORKLOAD_TIMEOUT_SECS] {
            let slice = NetworkSlice {
                allow_domain: vec!["a.com".into()],
                workload_timeout_secs: Some(accepted),
                ..Default::default()
            };
            match resolve_network(&slice, false, &["a.com".into()], &[], false, None) {
                NetworkConfig::Allow {
                    workload_timeout_secs,
                    ..
                } => assert_eq!(workload_timeout_secs, accepted),
                _ => panic!("expected Allow"),
            }
        }

        // Out of range (zero would end every session before the workload started;
        // past the cap the deadline could only be a wedged session): the default,
        // so the resolved field is always usable.
        for rejected in [0, MAX_WORKLOAD_TIMEOUT_SECS + 1, u32::MAX] {
            let slice = NetworkSlice {
                allow_domain: vec!["a.com".into()],
                workload_timeout_secs: Some(rejected),
                ..Default::default()
            };
            match resolve_network(&slice, false, &["a.com".into()], &[], false, None) {
                NetworkConfig::Allow {
                    workload_timeout_secs,
                    ..
                } => assert_eq!(
                    workload_timeout_secs, DEFAULT_WORKLOAD_TIMEOUT_SECS,
                    "{rejected} is out of range and must not reach the budget"
                ),
                _ => panic!("expected Allow"),
            }
        }
    }

    /// **Item 6, the whole point: the budget is built from the RESOLVED profile.**
    /// A profile with a 300 s prompt timeout and a 90 min workload must reserve both,
    /// because that is what the dialog and the workload actually get — a budget sized
    /// from the 60 s default would kill a legitimate dialog plus a full workload and
    /// label the kill as a prompt overrun.
    #[cfg(feature = "mxc-backend")]
    #[test]
    fn a_raised_profile_prompt_timeout_and_workload_both_fit_the_session_deadline() {
        use crate::net::mxc::{SESSION_SLACK, SessionBudget, SessionClock, TimeoutReason};

        let slice = NetworkSlice {
            allow_domain: vec!["build.example.com".into()],
            prompt_timeout_secs: Some(300),
            workload_timeout_secs: Some(5400),
            ..Default::default()
        };
        let cfg = resolve_network(
            &slice,
            false,
            &["build.example.com".into()],
            &[],
            false,
            None,
        );
        match &cfg {
            NetworkConfig::Allow {
                prompt_timeout_secs,
                workload_timeout_secs,
                ..
            } => {
                assert_eq!(*prompt_timeout_secs, 300);
                assert_eq!(*workload_timeout_secs, 5400);
            }
            _ => panic!("expected Allow"),
        }

        let budget = cfg.session_budget();
        assert_eq!(
            budget.prompt,
            std::time::Duration::from_secs(300),
            "the prompt term must be the resolved profile value, not the default"
        );
        assert_eq!(budget.workload, std::time::Duration::from_secs(5400));
        assert_eq!(
            budget.session(),
            std::time::Duration::from_secs(300 + 5400 + SESSION_SLACK.as_secs())
        );
        assert_eq!(budget.timeout_ms(), 5_820_000);
        assert!(
            budget.session() > SessionBudget::default().session(),
            "a raised profile must widen the deadline, not narrow it"
        );

        // A dialog that uses its whole raised term AND a workload that then overruns
        // are both inside the deadline: the prompt term is not blamed, and the
        // workload kill is what the audit names.
        let clock = SessionClock::measured(
            budget,
            std::time::Duration::from_secs(300 + 5400 + SESSION_SLACK.as_secs()),
            std::time::Duration::from_millis(150),
            std::time::Duration::from_secs(300),
        );
        assert_eq!(
            clock.timeout_reason(),
            TimeoutReason::WorkloadBudgetExceeded
        );
        assert!(
            clock.elapsed <= budget.session(),
            "the session deadline must cover the dialog it allowed"
        );
    }

    /// The default profile and `SessionBudget::default()` are the same budget — so a
    /// wiring mistake cannot reserve the constants' terms while the dialogs get the
    /// resolved ones.
    #[cfg(feature = "mxc-backend")]
    #[test]
    fn a_default_profile_resolves_to_the_default_session_budget() {
        let slice = NetworkSlice {
            allow_domain: vec!["a.com".into()],
            ..Default::default()
        };
        let cfg = resolve_network(&slice, false, &["a.com".into()], &[], false, None);
        assert_eq!(
            cfg.session_budget(),
            crate::net::mxc::SessionBudget::default()
        );
        // And a blocked session still has one: it runs a container too.
        assert_eq!(
            resolve_network(&empty_slice(), true, &[], &[], false, None).session_budget(),
            crate::net::mxc::SessionBudget::default()
        );
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
