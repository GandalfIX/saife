//! Per-run proxy credential.
//!
//! The supervisor mints exactly **one** [`RunToken`] per run. That value is the
//! only credential the run's listener accepts (`ProxyConfig::token`), and the
//! only one the run's child is given (it rides the proxy URL's `userinfo`, plan
//! D8). One listener per run plus one token per run is what makes concurrent
//! sessions attributable: a container that presents another run's token gets a
//! `407`, and nothing about that attempt enters *this* run's counters or audit
//! chain (P1.4).
//!
//! # Uniqueness is structural, not incidental
//!
//! A token is 64 lowercase hex characters: an 8-character **run serial** prefix
//! followed by 224 bits from the system-preferred CNG RNG. Two runs therefore
//! never share a credential even if the RNG repeated itself, and the serial is
//! readable at a glance in a log line without revealing anything secret. The
//! 256-bit form and the URL-unreserved charset are unchanged (the value has to
//! survive `url::Url::parse` as `userinfo`, see `RequestError::UnsafeProxyToken`).

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

use subtle::ConstantTimeEq;
use windows::Win32::Security::Cryptography::{BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom};
use windows::core::Result;

/// Hex characters of run serial that prefix every token.
const RUN_SERIAL_HEX: usize = 8;

/// Random bytes behind the serial: 224 bits, i.e. the 256-bit strength of the
/// pre-P1 token minus the serial's 32 bits.
const RANDOM_BYTES: usize = 28;

/// The next run serial for this process. Per process, monotonic, starting at 1
/// (0 is reserved for tokens built by tests).
static NEXT_RUN: AtomicU64 = AtomicU64::new(1);

/// One run's proxy credential.
///
/// Not `Copy` and not `Default`: a token only comes from [`issue`](RunToken::issue)
/// (one per run) or from a test fixture, so "every launch gets its own token" is
/// a property of the type rather than of the caller's discipline.
///
/// `Debug` is redacted: the value is a credential, and a `{:?}` of a config
/// struct must not put it in a log ([G-7]/[G-30]).
#[derive(Clone)]
pub struct RunToken {
    value: String,
    run: u64,
}

impl RunToken {
    /// Mint this process's next run token.
    ///
    /// The serial is taken from a process-global counter, so consecutive calls
    /// differ in the prefix; the RNG fills the remaining 56 characters.
    pub fn issue() -> Result<Self> {
        let run = NEXT_RUN.fetch_add(1, Ordering::Relaxed);
        let value = format!("{}{}", serial_hex(run), random_hex(RANDOM_BYTES)?);
        debug_assert_eq!(value.len(), RUN_SERIAL_HEX + RANDOM_BYTES * 2);
        Ok(Self { value, run })
    }

    /// A token with a fixed value, for tests that must know the credential the
    /// listener expects (the live tests build the child's proxy URL themselves).
    ///
    /// The serial still comes from the process counter: it is the live-token
    /// registry's key (P1.6), so two fixtures — distinct listeners — must not
    /// collide merely because a test chose the same value twice. `Clone` is the
    /// only way to get one identity twice, which is exactly the case the registry
    /// exists to refuse.
    #[cfg(test)]
    pub(crate) fn for_tests(value: &str) -> Self {
        Self {
            value: value.to_string(),
            run: NEXT_RUN.fetch_add(1, Ordering::Relaxed),
        }
    }

    /// The credential itself, for the proxy URL the child receives.
    pub fn value(&self) -> &str {
        &self.value
    }

    /// This token's run serial (the numeric form of the value's prefix).
    ///
    /// Two callers, both about identity rather than secrecy: `Debug` prints it
    /// (never the value), and the live-token registry keys on it (P1.6) so a
    /// process-global set can enforce "one credential, one listener" without
    /// keeping a second copy of the credential. Unique per process by
    /// construction — the counter starts at 1 and only `issue` (and, in tests,
    /// `for_tests`) mints.
    pub fn run(&self) -> u64 {
        self.run
    }

    /// Constant-time comparison against a client-presented password.
    ///
    /// The `ct_eq` on unequal lengths returns "not equal" but leaks the length;
    /// that is acceptable for a fixed-length token on a loopback listener, and
    /// is the pre-existing behaviour ([G-7]).
    ///
    /// # This property is unpinned by the suite, and that is deliberate
    ///
    /// **A plain `==` here would pass every test in this suite.** Every assertion
    /// in the crate compares outcomes - the run's own credential is admitted,
    /// every other string is a `407` - and `==` answers all of them identically.
    /// The only observable difference is timing, and a timing assertion is noise
    /// on a shared machine: a test loose enough to be stable would also pass
    /// against a leaky comparison, and a test tight enough to catch the swap would
    /// be flaky enough to get deleted. So the honest position is that this
    /// property rests on **review**, not on a test, and a fake test here would be
    /// worse than none - it would look like coverage.
    ///
    /// What review gets to lean on is the shape of the code, so keep it this
    /// small: **the comparison must remain a single whole-value `ct_eq` over the
    /// two byte slices.** No early return on a length mismatch, no per-character
    /// loop, no `str == str`, no pre-hashing of the presented value (hashing
    /// changes the timing *shape* without making the comparison constant-time).
    /// Written this way, removing the defence is a visible one-line diff instead
    /// of a subtle re-slice nobody notices.
    ///
    /// The one caller is the password arm of `classify_auth` in
    /// [`net::proxy`](crate::net::proxy).
    pub fn matches(&self, presented: &str) -> bool {
        presented.as_bytes().ct_eq(self.value.as_bytes()).into()
    }
}

impl fmt::Debug for RunToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RunToken(run {}, <redacted>)", self.run)
    }
}

/// The 8-character serial prefix. The serial is truncated to 32 bits because the
/// prefix is fixed-width; a process that served 4 billion runs would reuse
/// prefixes, and the RNG half still keeps the values apart.
fn serial_hex(run: u64) -> String {
    format!("{:08x}", (run & 0xffff_ffff) as u32)
}

/// `bytes` random bytes, hex-encoded.
fn random_hex(bytes: usize) -> Result<String> {
    let mut buf = vec![0u8; bytes];
    // SAFETY: `BCryptGenRandom` with `BCRYPT_USE_SYSTEM_PREFERRED_RNG` and a
    // `None` algorithm handle fills `buf` from the system-preferred RNG. The
    // buffer is a valid `&mut [u8]` of arbitrary length. This is a thread-safe
    // CNG API.
    unsafe {
        BCryptGenRandom(None, &mut buf, BCRYPT_USE_SYSTEM_PREFERRED_RNG).ok()?;
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
    use std::collections::HashSet;

    #[test]
    fn token_is_64_lowercase_hex_chars() {
        let t = RunToken::issue().unwrap();
        assert_eq!(t.value().len(), 64);
        assert!(
            t.value().chars().all(|c| c.is_ascii_hexdigit()),
            "a token must stay URL-unreserved: {}",
            t.value()
        );
        assert_eq!(
            t.value().to_ascii_lowercase(),
            t.value(),
            "lowercase keeps the value canonical"
        );
    }

    /// Uniqueness per run is structural: the serial prefix alone makes two runs'
    /// tokens different, so the assertion does not depend on the RNG.
    #[test]
    fn every_run_gets_its_own_token_and_its_own_serial() {
        let mut values = HashSet::new();
        let mut prefixes = HashSet::new();
        for _ in 0..64 {
            let t = RunToken::issue().unwrap();
            assert!(
                prefixes.insert(t.value()[..RUN_SERIAL_HEX].to_string()),
                "two runs shared a serial prefix: {}",
                t.value()
            );
            assert!(
                values.insert(t.value().to_string()),
                "two runs shared a token: {}",
                t.value()
            );
            assert_eq!(
                &t.value()[..RUN_SERIAL_HEX],
                serial_hex(t.run()),
                "the prefix must be this run's serial"
            );
        }
    }

    #[test]
    fn matches_accepts_only_the_exact_value() {
        let a = RunToken::issue().unwrap();
        let b = RunToken::issue().unwrap();
        assert!(a.matches(a.value()));
        assert!(!a.matches(b.value()), "another run's token must not match");
        assert!(!a.matches(""), "an empty credential must not match");
        assert!(
            !a.matches(&a.value().to_ascii_uppercase()),
            "the comparison is byte-exact, not case-folded"
        );
    }

    #[test]
    fn debug_redacts_the_credential() {
        let t = RunToken::issue().unwrap();
        let shown = format!("{t:?}");
        assert!(
            !shown.contains(t.value()),
            "Debug leaked the token: {shown}"
        );
        assert!(shown.contains(&format!("run {}", t.run())));
    }
}
