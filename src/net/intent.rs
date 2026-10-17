//! Agent-declared intent registry (ADR-0001 §D-4).
//!
//! The agent POSTs "I want to reach host X because Y" *before* the network
//! request; the interactive prompt dialog (D-3.5) displays that reason when
//! the host is not otherwise allowed ([G-7, G-25, G-57]). Port of omac's
//! `internal/intent/registry.go`: a TTL-evicted in-memory store — no disk
//! persistence, lost on supervisor restart, which is the correct recovery
//! path ([G-16]).
//!
//! Bounds ([G-16, G-57]):
//! - 10-minute default TTL, background sweeper at TTL/2 removes expired
//!   entries; lookups also check expiry lazily.
//! - Max 500 entries; on overflow the oldest record is evicted.
//! - Reasons > 500 chars are truncated, not rejected.
//! - "Explain more" is a one-shot flag per host (consumed on read; the set
//!   of pending flags is capped at 500 like the entries — an
//!   implementation bound, not ADR-mandated).
//!
//! The registry's public API is not yet called from the release binary —
//! the `/sandbox/intent*` endpoints are mounted by D-3.6 (pipeline wire-in).
//! Until then the whole module is `#[allow(dead_code)]` to keep
//! `cargo build --release` clean (same posture as `learned.rs`). Tests
//! exercise the full API, so the code is verified even though the
//! non-test binary does not yet link it in.
//!
//! Concurrency: all operations go through a `tokio::sync::Mutex` ([G-25]
//! eventually-consistent). `new()` may be called from synchronous code (the
//! supervisor in D-3.6 creates the registry before the proxy runtime
//! starts), so the background sweeper is a plain `std::thread` parked on a
//! condvar; it uses `blocking_lock()` (legal outside a runtime) and
//! `close()` wakes + joins it promptly.

#![allow(dead_code)]

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Condvar, Mutex as StdMutex};
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime};

use tokio::sync::Mutex;

/// Default entry TTL: 10 minutes ([G-16]).
pub const DEFAULT_TTL: Duration = Duration::from_secs(10 * 60);

/// Maximum number of tracked hosts; on overflow the oldest record is
/// evicted ([G-16]).
pub const MAX_ENTRIES: usize = 500;

/// Reasons longer than this are truncated, never rejected ([G-57]).
pub const MAX_REASON_CHARS: usize = 500;

/// One recorded intent, as returned by [`IntentRegistry::lookup_host`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Normalized host the intent was recorded for.
    pub host: String,
    /// Truncated reason (≤ [`MAX_REASON_CHARS`] chars).
    pub reason: String,
    /// Wall-clock record time; also drives TTL expiry.
    pub ts: SystemTime,
}

/// Shared state guarded by the tokio Mutex.
#[derive(Debug, Default)]
struct State {
    /// Normalized host → (record sequence, entry). The sequence number
    /// gives a deterministic eviction order (oldest record out) even when
    /// several entries share a timestamp; re-recording refreshes it.
    entries: HashMap<String, (u64, Entry)>,
    /// Hosts carrying a live one-shot "explain more" flag.
    explain_more: HashSet<String>,
    /// Monotonic record counter for eviction ordering.
    next_seq: u64,
}

impl State {
    /// Record (or refresh) an intent. Empty normalized targets are ignored.
    fn record(&mut self, target: &str, reason: &str) {
        let host = normalize_host(target);
        if host.is_empty() {
            return;
        }
        let reason: String = reason.chars().take(MAX_REASON_CHARS).collect();
        let seq = self.next_seq;
        self.next_seq += 1;
        self.entries.insert(
            host.clone(),
            (
                seq,
                Entry {
                    host,
                    reason,
                    ts: SystemTime::now(),
                },
            ),
        );
        if self.entries.len() > MAX_ENTRIES {
            self.evict_oldest();
        }
    }

    /// Evict the entry with the smallest record sequence (the oldest
    /// record; a refreshed entry has a newer sequence and survives).
    fn evict_oldest(&mut self) {
        if let Some(oldest) = self
            .entries
            .iter()
            .min_by_key(|(_, (seq, _))| *seq)
            .map(|(host, _)| host.clone())
        {
            self.entries.remove(&oldest);
        }
    }

    /// Look up the intent for `host`, lazily purging it when expired.
    fn lookup_purge(&mut self, host: &str, ttl: Duration) -> Option<Entry> {
        let h = normalize_host(host);
        let expired = matches!(
            self.entries.get(&h),
            Some((_, entry)) if is_expired_at(entry, ttl, SystemTime::now())
        );
        if expired {
            self.entries.remove(&h);
            return None;
        }
        self.entries.get(&h).map(|(_, entry)| entry.clone())
    }

    /// Remove all expired entries (background sweeper).
    fn sweep(&mut self, ttl: Duration) {
        let now = SystemTime::now();
        self.entries
            .retain(|_, (_, entry)| !is_expired_at(entry, ttl, now));
    }

    /// Set the one-shot "explain more" flag for a host ([G-26]). The set of
    /// *pending* (unconsumed) flags is capped at [`MAX_ENTRIES`] like the
    /// entry map, so a looping agent cannot grow it without limit; a mark
    /// beyond the cap is dropped (500 pending flags is already pathological
    /// — the one-shot flow consumes each on read).
    fn mark_explain_more(&mut self, host: &str) {
        let h = normalize_host(host);
        if h.is_empty() || self.explain_more.len() >= MAX_ENTRIES {
            return;
        }
        self.explain_more.insert(h);
    }

    /// Read + clear the one-shot flag.
    fn consume_explain_more(&mut self, host: &str) -> bool {
        self.explain_more.remove(&normalize_host(host))
    }

    /// Clear the one-shot flag without reading it.
    fn clear_explain_more(&mut self, host: &str) {
        self.explain_more.remove(&normalize_host(host));
    }
}

/// Normalize a declared target to a bare lowercase hostname ([G-8]).
///
/// Accepts a full URL, `host:port`, `[v6]:port`, or a bare host (with an
/// optional trailing dot). Port, path, query, fragment and userinfo are
/// stripped. Input that normalizes to nothing yields an empty string,
/// which callers must treat as "no host".
pub(crate) fn normalize_host(input: &str) -> String {
    let mut s = input.trim().to_ascii_lowercase();
    // Strip the scheme, e.g. "https://".
    if let Some(pos) = s.find("://") {
        s.drain(..pos + 3);
    }
    // Cut at the first path/query/fragment separator.
    if let Some(pos) = s.find(['/', '?', '#']) {
        s.truncate(pos);
    }
    // Strip userinfo, e.g. "user:pass@".
    if let Some(pos) = s.rfind('@') {
        s.drain(..pos + 1);
    }
    // Bracketed IPv6 literal: keep the address inside the brackets.
    if let Some(rest) = s.strip_prefix('[')
        && let Some(close) = rest.find(']')
    {
        return rest[..close].to_string();
    }
    // `host:port` → host. Only when there is exactly one colon and the
    // remainder is all digits — or empty (RFC 3986: an empty port is
    // equivalent to no port) — so bare IPv6 literals ("::1") are left alone.
    if s.matches(':').count() == 1
        && let Some((host, port)) = s.rsplit_once(':')
        && (port.is_empty() || port.bytes().all(|b| b.is_ascii_digit()))
    {
        s = host.to_string();
    }
    s.trim_end_matches('.').to_string()
}

/// Expiry predicate, pure for testability: an entry is expired once its age
/// (measured from `ts` to `now`) reaches `ttl`. A `ts` in the future
/// (clock set backwards) counts as age 0 — the entry stays live until the
/// clock catches up, which is fail-open for an advisory UX layer.
fn is_expired_at(entry: &Entry, ttl: Duration, now: SystemTime) -> bool {
    now.duration_since(entry.ts)
        .map(|age| age >= ttl)
        .unwrap_or(false)
}

/// The sweeper runs at TTL/2, floored at 1ms so a tiny (or zero) TTL
/// cannot degenerate into a busy loop.
fn sweeper_interval(ttl: Duration) -> Duration {
    let half = ttl / 2;
    if half < Duration::from_millis(1) {
        Duration::from_millis(1)
    } else {
        half
    }
}

/// TTL-evicted in-memory intent registry (ADR-0001 §D-4).
///
/// Created by the supervisor (sync context) before the proxy starts and
/// shared with the proxy's async request handlers. All operations go
/// through an internal `tokio::sync::Mutex` ([G-25]); the background
/// sweeper is a plain `std::thread` so `new()` works outside a runtime.
pub struct IntentRegistry {
    state: Arc<Mutex<State>>,
    ttl: Duration,
    sweeper: Option<JoinHandle<()>>,
    shutdown: Arc<(StdMutex<bool>, Condvar)>,
}

impl IntentRegistry {
    /// Create a registry with the given entry TTL and start the background
    /// sweeper at TTL/2.
    pub fn new(ttl: Duration) -> Self {
        let state = Arc::new(Mutex::new(State::default()));
        let shutdown: Arc<(StdMutex<bool>, Condvar)> =
            Arc::new((StdMutex::new(false), Condvar::new()));
        let sweeper = std::thread::Builder::new()
            .name("intent-sweeper".to_string())
            .spawn({
                let state = Arc::clone(&state);
                let shutdown = Arc::clone(&shutdown);
                move || sweeper_loop(state, shutdown, ttl)
            })
            .expect("failed to spawn intent sweeper thread");
        IntentRegistry {
            state,
            ttl,
            sweeper: Some(sweeper),
            shutdown,
        }
    }

    /// Record (or refresh) the agent's declared intent for a target.
    /// `target` is normalized to a bare lowercase hostname; the reason is
    /// truncated to [`MAX_REASON_CHARS`] chars ([G-57]).
    pub async fn record(&self, target: &str, reason: &str) {
        self.state.lock().await.record(target, reason);
    }

    /// Look up the live intent for a host, or `None` if missing/expired
    /// ([G-57]). Expired entries are purged lazily here as well as by the
    /// background sweeper.
    pub async fn lookup_host(&self, host: &str) -> Option<Entry> {
        self.state.lock().await.lookup_purge(host, self.ttl)
    }

    /// Set the one-shot "explain more" flag for a host ([G-26]).
    pub async fn mark_explain_more(&self, host: &str) {
        self.state.lock().await.mark_explain_more(host);
    }

    /// Read + clear the one-shot "explain more" flag for a host.
    pub async fn consume_explain_more(&self, host: &str) -> bool {
        self.state.lock().await.consume_explain_more(host)
    }

    /// Clear the "explain more" flag without reading it.
    pub async fn clear_explain_more(&self, host: &str) {
        self.state.lock().await.clear_explain_more(host);
    }

    /// Stop the background sweeper (wakes + joins it). The registry itself
    /// stays usable. Idempotent.
    pub fn close(&mut self) {
        {
            let (lock, cv) = &*self.shutdown;
            let mut flag = lock.lock().expect("intent sweeper shutdown lock poisoned");
            *flag = true;
            cv.notify_all();
        }
        if let Some(handle) = self.sweeper.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for IntentRegistry {
    fn drop(&mut self) {
        self.close();
    }
}

/// Sweeper thread body: sleep for the sweep interval (interruptible by the
/// shutdown signal), then remove expired entries. Uses `blocking_lock`
/// because this is a plain thread, never a tokio worker.
fn sweeper_loop(state: Arc<Mutex<State>>, shutdown: Arc<(StdMutex<bool>, Condvar)>, ttl: Duration) {
    let interval = sweeper_interval(ttl);
    loop {
        // Sleep for `interval`, waking early on the shutdown signal.
        {
            let (lock, cv) = &*shutdown;
            let mut flag = lock.lock().expect("intent sweeper shutdown lock poisoned");
            let deadline = std::time::Instant::now() + interval;
            loop {
                if *flag {
                    return;
                }
                let now = std::time::Instant::now();
                if now >= deadline {
                    break;
                }
                let (guard, _t) = cv
                    .wait_timeout(flag, deadline - now)
                    .expect("intent sweeper shutdown lock poisoned");
                flag = guard;
            }
        }
        state.blocking_lock().sweep(ttl);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    // ---- record + lookup --------------------------------------------------

    #[tokio::test]
    async fn record_then_lookup_returns_entry() {
        let reg = IntentRegistry::new(Duration::from_secs(600));
        reg.record("api.example.com", "fetching the latest model list")
            .await;
        let entry = reg
            .lookup_host("api.example.com")
            .await
            .expect("intent recorded");
        assert_eq!(entry.host, "api.example.com");
        assert_eq!(entry.reason, "fetching the latest model list");
    }

    #[tokio::test]
    async fn lookup_normalizes_case_and_trailing_dot() {
        let reg = IntentRegistry::new(Duration::from_secs(600));
        reg.record("API.Example.COM.", "r").await;
        assert!(reg.lookup_host("api.example.com").await.is_some());
    }

    #[tokio::test]
    async fn lookup_missing_host_returns_none() {
        let reg = IntentRegistry::new(Duration::from_secs(600));
        assert!(
            reg.lookup_host("never-recorded.example.com")
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn re_record_replaces_reason() {
        let reg = IntentRegistry::new(Duration::from_secs(600));
        reg.record("api.example.com", "first").await;
        reg.record("api.example.com", "second").await;
        assert_eq!(
            reg.lookup_host("api.example.com").await.unwrap().reason,
            "second"
        );
    }

    #[tokio::test]
    async fn record_empty_target_is_ignored() {
        let reg = IntentRegistry::new(Duration::from_secs(600));
        reg.record("", "reason").await;
        reg.record("://", "reason").await;
        assert!(reg.lookup_host("").await.is_none());
    }

    // ---- TTL expiry ---------------------------------------------------------

    #[tokio::test]
    async fn ttl_expiry_removes_entry() {
        let reg = IntentRegistry::new(Duration::from_millis(50));
        reg.record("api.example.com", "r").await;
        assert!(
            reg.lookup_host("api.example.com").await.is_some(),
            "fresh entry must be live"
        );
        tokio::time::sleep(Duration::from_millis(120)).await;
        assert!(
            reg.lookup_host("api.example.com").await.is_none(),
            "expired entry must be gone"
        );
    }

    #[test]
    fn is_expired_at_boundaries() {
        let ts = SystemTime::now();
        let entry = Entry {
            host: "h".into(),
            reason: "r".into(),
            ts,
        };
        let ttl = Duration::from_millis(100);
        assert!(!is_expired_at(&entry, ttl, ts + Duration::from_millis(99)));
        assert!(
            is_expired_at(&entry, ttl, ts + Duration::from_millis(100)),
            "age >= ttl is expired"
        );
        assert!(!is_expired_at(&entry, ttl, ts), "age 0 is live");
    }

    // ---- normalization -------------------------------------------------------

    #[tokio::test]
    async fn normalize_url_to_host() {
        let reg = IntentRegistry::new(DEFAULT_TTL);
        reg.record(
            "https://API.Example.com:443/v1/models?q=1",
            "fetch model list",
        )
        .await;
        assert!(reg.lookup_host("api.example.com").await.is_some());
    }

    #[tokio::test]
    async fn normalize_host_port_to_host() {
        let reg = IntentRegistry::new(DEFAULT_TTL);
        reg.record("api.example.com:8443", "r").await;
        assert!(reg.lookup_host("api.example.com").await.is_some());
    }

    #[tokio::test]
    async fn normalize_strips_userinfo_and_trailing_dot() {
        let reg = IntentRegistry::new(DEFAULT_TTL);
        reg.record("user:secret@Host.Example.COM:8080/x", "r").await;
        assert!(reg.lookup_host("host.example.com").await.is_some());
    }

    #[tokio::test]
    async fn normalize_bracketed_ipv6_literal() {
        let reg = IntentRegistry::new(DEFAULT_TTL);
        reg.record("[::1]:9000", "local debug endpoint").await;
        assert!(reg.lookup_host("::1").await.is_some());
    }

    #[test]
    fn normalize_host_pure_cases() {
        assert_eq!(
            normalize_host("https://Api.Example.COM/a?b#c"),
            "api.example.com"
        );
        assert_eq!(normalize_host("api.example.com:443"), "api.example.com");
        assert_eq!(normalize_host("API.Example.com."), "api.example.com");
        assert_eq!(normalize_host("[2001:db8::1]:443"), "2001:db8::1");
        assert_eq!(normalize_host("::1"), "::1");
        assert_eq!(normalize_host("host:"), "host", "empty port means no port");
        assert_eq!(normalize_host(":"), "");
        assert_eq!(normalize_host(""), "");
    }

    // ---- explain-more one-shot -------------------------------------------------

    #[tokio::test]
    async fn explain_more_is_one_shot() {
        let reg = IntentRegistry::new(DEFAULT_TTL);
        reg.mark_explain_more("Api.Example.COM").await;
        assert!(
            reg.consume_explain_more("api.example.com").await,
            "first consume reads the flag"
        );
        assert!(
            !reg.consume_explain_more("api.example.com").await,
            "second consume: flag was one-shot"
        );
    }

    #[tokio::test]
    async fn explain_more_clear_prevents_consume() {
        let reg = IntentRegistry::new(DEFAULT_TTL);
        reg.mark_explain_more("api.example.com").await;
        reg.clear_explain_more("api.example.com").await;
        assert!(!reg.consume_explain_more("api.example.com").await);
    }

    #[tokio::test]
    async fn explain_more_without_mark_is_false() {
        let reg = IntentRegistry::new(DEFAULT_TTL);
        assert!(!reg.consume_explain_more("api.example.com").await);
    }

    #[tokio::test]
    async fn explain_more_works_without_intent_entry() {
        // The explain flag is independent of recorded intents: the dialog
        // can show an "explain more" request even if no intent was POSTed.
        let reg = IntentRegistry::new(DEFAULT_TTL);
        reg.mark_explain_more("api.example.com").await;
        assert!(reg.lookup_host("api.example.com").await.is_none());
        assert!(reg.consume_explain_more("api.example.com").await);
    }

    #[tokio::test]
    async fn explain_more_is_bounded() {
        // Pending flags are capped like entries: a looping agent must not
        // be able to grow the set without limit.
        let reg = IntentRegistry::new(DEFAULT_TTL);
        for i in 0..=500u32 {
            reg.mark_explain_more(&format!("h{i:03}.example.com")).await;
        }
        let st = reg.state.lock().await;
        assert!(
            st.explain_more.len() <= MAX_ENTRIES,
            "pending explain flags must stay bounded"
        );
    }

    // ---- overflow eviction --------------------------------------------------------

    #[tokio::test]
    async fn overflow_evicts_oldest_record() {
        let reg = IntentRegistry::new(DEFAULT_TTL);
        for i in 0..=500u32 {
            reg.record(&format!("h{i:03}.example.com"), "r").await;
        }
        // h000 was recorded first → evicted when h500 (the 501st distinct
        // host) overflowed the 500-entry cap.
        assert!(
            reg.lookup_host("h000.example.com").await.is_none(),
            "oldest must be evicted"
        );
        assert!(
            reg.lookup_host("h500.example.com").await.is_some(),
            "newest must survive"
        );
    }

    #[tokio::test]
    async fn re_record_refreshes_eviction_order() {
        let reg = IntentRegistry::new(DEFAULT_TTL);
        for i in 0..=250u32 {
            reg.record(&format!("h{i:03}.example.com"), "r").await;
        }
        // Re-declare h000: it becomes the *newest* record.
        reg.record("h000.example.com", "refreshed").await;
        for i in 251..=500u32 {
            reg.record(&format!("h{i:03}.example.com"), "r").await;
        }
        // 501 distinct hosts → one eviction, and it must be h001 (the
        // oldest record that was never refreshed), not h000.
        assert!(
            reg.lookup_host("h001.example.com").await.is_none(),
            "h001 is the stale oldest"
        );
        assert!(
            reg.lookup_host("h000.example.com").await.is_some(),
            "refreshed record survives"
        );
    }

    // ---- reason truncation ---------------------------------------------------------

    #[tokio::test]
    async fn reason_truncated_to_500_chars() {
        let reg = IntentRegistry::new(DEFAULT_TTL);
        let long = "x".repeat(600);
        reg.record("api.example.com", &long).await;
        let entry = reg.lookup_host("api.example.com").await.unwrap();
        assert_eq!(entry.reason.chars().count(), MAX_REASON_CHARS);

        let exact = "y".repeat(MAX_REASON_CHARS);
        reg.record("exact.example.com", &exact).await;
        let entry = reg.lookup_host("exact.example.com").await.unwrap();
        assert_eq!(
            entry.reason.chars().count(),
            MAX_REASON_CHARS,
            "exactly-500 reason is kept whole"
        );

        let short = "z".repeat(499);
        reg.record("short.example.com", &short).await;
        let entry = reg.lookup_host("short.example.com").await.unwrap();
        assert_eq!(entry.reason.chars().count(), 499);
    }

    #[tokio::test]
    async fn reason_truncation_counts_chars_not_bytes() {
        let reg = IntentRegistry::new(DEFAULT_TTL);
        let multibyte = "ä".repeat(600); // 2 bytes per char
        reg.record("api.example.com", &multibyte).await;
        let entry = reg.lookup_host("api.example.com").await.unwrap();
        assert_eq!(entry.reason.chars().count(), MAX_REASON_CHARS);
        assert!(
            entry.reason.len() > MAX_REASON_CHARS,
            "multibyte truncation is char-based"
        );
    }

    // ---- sweeper ----------------------------------------------------------------------

    #[tokio::test]
    async fn sweeper_removes_expired_entries_in_background() {
        let reg = IntentRegistry::new(Duration::from_millis(40)); // sweep every 20ms
        reg.record("api.example.com", "r").await;
        tokio::time::sleep(Duration::from_millis(150)).await;
        // No lookup was issued — only the background sweeper can have
        // removed the expired entry from the raw map.
        let st = reg.state.lock().await;
        assert!(st.entries.is_empty(), "sweeper must purge expired entries");
    }

    #[tokio::test]
    async fn close_stops_the_sweeper_promptly() {
        let mut reg = IntentRegistry::new(Duration::from_secs(5)); // sweep every 2.5s
        reg.record("api.example.com", "r").await;
        let start = Instant::now();
        reg.close();
        // close() wakes + joins the sweeper: without the condvar wake it
        // would block for the full 2.5s interval.
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "close must interrupt the sweeper sleep"
        );
        // close() only stops the sweeper — the registry itself stays usable.
        assert!(reg.lookup_host("api.example.com").await.is_some());
    }

    #[test]
    fn sweeper_interval_is_half_ttl_with_1ms_floor() {
        assert_eq!(
            sweeper_interval(Duration::from_secs(600)),
            Duration::from_secs(300)
        );
        assert_eq!(
            sweeper_interval(Duration::from_millis(1)),
            Duration::from_millis(1)
        );
        assert_eq!(sweeper_interval(Duration::ZERO), Duration::from_millis(1));
    }

    #[test]
    fn default_bounds_match_adr() {
        assert_eq!(DEFAULT_TTL, Duration::from_secs(10 * 60));
        assert_eq!(MAX_ENTRIES, 500);
        assert_eq!(MAX_REASON_CHARS, 500);
    }
}
