//! 256-bit random session token, hex-encoded (64 chars).

use windows::Win32::Security::Cryptography::{BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG};
use windows::core::Result;

pub fn gen_token() -> Result<String> {
    let mut buf = [0u8; 32];
    // SAFETY: `BCryptGenRandom` with `BCRYPT_USE_SYSTEM_PREFERRED_RNG` and a
    // `None` algorithm handle fills `buf` from the system-preferred RNG. The
    // buffer is a valid `&mut [u8]` of length 32. This is a thread-safe CNG API.
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
