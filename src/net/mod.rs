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
