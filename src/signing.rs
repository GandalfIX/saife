//! Ed25519 signing key for the audit trail root.
//!
//! The secret key is stored at `%LOCALAPPDATA%\saife\signing\ed25519-key`,
//! DPAPI-encrypted (`CryptProtectData`, user scope — not LOCAL_MACHINE, so only
//! the same user on the same machine can decrypt). The file inherits the
//! user's `%LOCALAPPDATA%` ACL; there is deliberately **no** extra restrictive
//! DACL on it (M7): a previous doc comment claimed owner+SYSTEM-only and the
//! code never applied one. User-scope DPAPI is the primary and sufficient
//! protection for the threat this key faces — another process running as the
//! same user cannot decrypt the blob even though it can read the file, and
//! anything running as another user or SYSTEM is already outside the model.
//! No DPAPI entropy is used: a constant embedded in the binary is not a
//! secret, and machine-unique entropy would break moving a key between
//! installs. Which key signed a session is recorded as a fingerprint
//! (`fingerprint_of`, M7) so `audit verify` can report KEY_CHANGED.
//!
//! Public key is derived from the secret on demand; we don't store it.

use anyhow::{bail, Context, Result};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use zeroize::Zeroizing;
use windows::Win32::Foundation::LocalFree;
use windows::Win32::Foundation::HLOCAL;
use windows::Win32::Security::Cryptography::{
    CryptProtectData, CryptUnprotectData, CRYPT_INTEGER_BLOB,
};
use windows::Win32::Storage::FileSystem::{MoveFileExW, MOVE_FILE_FLAGS};
use windows::core::{HRESULT, HSTRING};

/// Serializes first-time key creation within this process. The cross-process
/// race is handled by the non-replacing atomic publish in `ensure()`. Without
/// both, concurrent first-runs (two `saife run` processes on a fresh
/// machine, or parallel unit tests in a fresh guest) each mint a key and
/// overwrite the file; the losers' signatures then fail `audit verify` with
/// BadSignature even though nothing was tampered.
static ENSURE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// The 32-byte Ed25519 secret key, decrypted in memory.
pub struct KeyMaterial {
    pub signing: SigningKey,
}

impl KeyMaterial {
    /// Load the secret key from disk (DPAPI-decrypting it). If the file does
    /// not exist, generate a new keypair, encrypt, and publish it atomically:
    /// write to a temp sibling, then `MoveFileExW` WITHOUT
    /// MOVEFILE_REPLACE_EXISTING — the first process to rename wins, losers
    /// fall through and read the winner's key. (`std::fs::rename` replaces
    /// the destination on Windows and would reintroduce the race.)
    pub fn ensure() -> Result<Self> {
        let _guard = ENSURE_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let path = key_path()?;
        if !path.exists() {
            let signing = generate_signing_key()?;
            // L-L: the raw 32-byte secret exists exactly once in memory, in
            // this buffer, before it is DPAPI-encrypted - wipe it on drop.
            let secret = Zeroizing::new(signing.to_bytes());
            let encrypted = dpapi_protect(&secret[..])?;
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).ok();
            }
            let tmp = path.with_extension(format!("tmp-{}", std::process::id()));
            std::fs::write(&tmp, &encrypted)
                .with_context(|| format!("write {}", tmp.display()))?;
            let publish = unsafe {
                // flags = 0: no MOVEFILE_REPLACE_EXISTING — fail instead
                // of overwriting, so the first publisher wins the race.
                MoveFileExW(
                    &HSTRING::from(tmp.as_os_str()),
                    &HSTRING::from(path.as_os_str()),
                    MOVE_FILE_FLAGS(0),
                )
            };
            let lost_race = match publish {
                Ok(()) => false,
                // ERROR_ALREADY_EXISTS (183): another process published
                // first — read its key below instead.
                Err(e) if e.code() == HRESULT::from_win32(183) => true,
                Err(e) => {
                    let _ = std::fs::remove_file(&tmp);
                    return Err(e).with_context(|| format!("publish {}", path.display()));
                }
            };
            if lost_race {
                let _ = std::fs::remove_file(&tmp);
            }
        }
        // One decrypt path for minting and for reading: `load_existing_at` (M6)
        // holds the read + DPAPI-decrypt + length check.
        Self::load_existing_at(&path)
    }

    /// Load the current key, never creating one (M6).
    ///
    /// This is the **verify** path: losing the key must be a verdict of its own,
    /// not a silent trust-anchor rotation. [`Self::ensure`] (create-if-missing)
    /// stays reserved for the signing path.
    pub fn load_existing() -> Result<Self> {
        let path = key_path()?;
        Self::load_existing_at(&path)
    }

    /// Path-injected form of [`Self::load_existing`], so the "never mint, never
    /// mutate" contract is testable against a temp path instead of the user's
    /// real key. Reading fails loudly (missing, undecryptable, wrong length) and
    /// touches nothing.
    pub fn load_existing_at(path: &std::path::Path) -> Result<Self> {
        let bytes = std::fs::read(path).map_err(|e| {
            anyhow::anyhow!(
                "no signing key at {}: {e} (verifying cannot create one; \
                 run `saife setup` on the machine that signed this session)",
                path.display()
            )
        })?;
        // L-L: the decrypted plaintext only lives in zeroized wrappers from
        // here to the SigningKey.
        let secret = Zeroizing::new(
            dpapi_unprotect(&bytes)
                .with_context(|| format!("signing key at {} cannot be decrypted", path.display()))?,
        );
        if secret.len() != 32 {
            bail!(
                "signing key at {} is {} bytes, expected 32 (decrypted)",
                path.display(),
                secret.len()
            );
        }
        let mut arr = Zeroizing::new([0u8; 32]);
        arr.copy_from_slice(&secret);
        Ok(Self {
            signing: SigningKey::from_bytes(&arr),
        })
    }

    /// Sign the 32-byte root (chain root = SHA-256 of last leaf's canonical
    /// body, already computed by the caller). Returns the 64-byte signature.
    pub fn sign_root(&self, root_bytes: &[u8]) -> [u8; 64] {
        use ed25519_dalek::Signer;
        self.signing.sign(root_bytes).to_bytes()
    }

    /// Fingerprint of this key's public half (M7). Recorded with a committed
    /// root; see [`fingerprint_of`].
    pub fn fingerprint(&self) -> String {
        fingerprint_of(&self.signing)
    }
}

/// Fingerprint of the verifying key (M7): SHA-256 over the 32-byte public key,
/// lowercase hex.
///
/// This is an identifier, not a trust anchor. Recording it beside the root lets
/// `audit verify` say `KEY_CHANGED` ("the current key cannot check this
/// signature") instead of `BAD_SIGNATURE` ("this is a forgery") after a
/// rotation. Without a pinned/stored trust root it cannot prove which key
/// *should* have signed, so it cannot distinguish rotation from substitution;
/// the verdict text says exactly that.
pub fn fingerprint_of(secret: &SigningKey) -> String {
    let public = VerifyingKey::from(secret);
    let mut h = Sha256::new();
    h.update(public.as_bytes());
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// Verify a root signature against the public key derived from a secret key.
pub fn verify_root(public: &VerifyingKey, root_bytes: &[u8], sig: &[u8]) -> bool {
    if sig.len() != 64 {
        return false;
    }
    let mut arr = [0u8; 64];
    arr.copy_from_slice(sig);
    let signature = Signature::from_bytes(&arr);
    use ed25519_dalek::Verifier;
    public.verify(root_bytes, &signature).is_ok()
}

/// Convenience: verify a root signature given a secret key (derive the public
/// key, then verify). Used by `audit verify` since we only have the secret
/// key on the verifying host.
pub fn verify_with_secret(secret: &SigningKey, root_bytes: &[u8], sig: &[u8]) -> bool {
    let public = VerifyingKey::from(secret);
    verify_root(&public, root_bytes, sig)
}

/// Path of the on-disk DPAPI-encrypted Ed25519 secret key.
pub fn key_path() -> Result<PathBuf> {
    let local = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .context("LOCALAPPDATA not set")?;
    Ok(local.join("saife").join("signing").join("ed25519-key"))
}

/// Does the key file exist? Used by `setup --check-only`.
pub fn key_exists() -> bool {
    key_path().map(|p| p.exists()).unwrap_or(false)
}

/// Generate a fresh Ed25519 signing key using BCryptGenRandom (consistent with
/// `src/net/token.rs`). No `rand` crate dependency.
fn generate_signing_key() -> Result<SigningKey> {
    use windows::Win32::Security::Cryptography::BCRYPT_USE_SYSTEM_PREFERRED_RNG;
    use windows::Win32::Security::Cryptography::BCryptGenRandom;
    // L-L: wiped on drop.
    let mut secret = Zeroizing::new([0u8; 32]);
    // SAFETY: see `src/net/token.rs:12`. Same pattern: system-preferred RNG,
    // no algorithm handle, valid `&mut [u8]` of length 32.
    unsafe {
        BCryptGenRandom(None, &mut *secret, BCRYPT_USE_SYSTEM_PREFERRED_RNG)
            .ok()
            .context("BCryptGenRandom failed")?;
    }
    Ok(SigningKey::from_bytes(&secret))
}

fn dpapi_protect(plaintext: &[u8]) -> Result<Vec<u8>> {
    unsafe {
        let in_blob = CRYPT_INTEGER_BLOB {
            cbData: plaintext.len() as u32,
            pbData: plaintext.as_ptr() as *mut u8,
        };
        let mut out_blob = CRYPT_INTEGER_BLOB::default();
        // Optional entropy (NULL = none) — we rely on user-scope DPAPI.
        let r = CryptProtectData(
            &in_blob,
            windows::core::PCWSTR::null(),
            None,
            None,
            None,
            0, // no flags: user scope (not LOCAL_MACHINE)
            &mut out_blob,
        );
        if r.is_err() {
            bail!("CryptProtectData failed: {:?}", r);
        }
        let out = std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize).to_vec();
        // Free the DPAPI-allocated buffer.
        let _ = LocalFree(Some(HLOCAL(out_blob.pbData as *mut _)));
        Ok(out)
    }
}

fn dpapi_unprotect(ciphertext: &[u8]) -> Result<Vec<u8>> {
    unsafe {
        let in_blob = CRYPT_INTEGER_BLOB {
            cbData: ciphertext.len() as u32,
            pbData: ciphertext.as_ptr() as *mut u8,
        };
        let mut out_blob = CRYPT_INTEGER_BLOB::default();
        let r = CryptUnprotectData(&in_blob, None, None, None, None, 0, &mut out_blob);
        if r.is_err() {
            bail!("CryptUnprotectData failed: {:?}", r);
        }
        // L-L: zero the plaintext in the DPAPI-allocated buffer before it is
        // freed. `LocalFree` does not scrub, and the buffer held the decrypted
        // secret. Safe: `out_blob` came from a successful CryptUnprotectData and
        // names `cbData` valid bytes at `pbData`.
        let out = std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize).to_vec();
        std::ptr::write_bytes(out_blob.pbData, 0, out_blob.cbData as usize);
        let _ = LocalFree(Some(HLOCAL(out_blob.pbData as *mut _)));
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// L-L (verdict doc: confirmed, understated). `Cargo.toml` built
    /// ed25519-dalek with `default-features = false`, which switched the
    /// crate's `zeroize` feature off - so even its own `Drop` did not scrub
    /// the key. This bound is the compile-time guard: if the feature is ever
    /// dropped again, the crate stops compiling. (The wipe of the
    /// DPAPI-unprotected plaintext buffer is a `write_bytes` before `LocalFree`
    /// - not observable from a unit test, so this bound is the guard.)
    #[test]
    fn the_signing_key_zeroizes_on_drop() {
        fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<SigningKey>();
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let key = generate_signing_key().unwrap();
        let msg = b"hello world";
        let sig = {
            use ed25519_dalek::Signer;
            key.sign(msg).to_bytes()
        };
        assert!(verify_with_secret(&key, msg, &sig));
        assert!(!verify_with_secret(&key, b"tampered", &sig));
        assert!(!verify_with_secret(&key, msg, &[0u8; 63])); // wrong-length sig
    }

    #[test]
    fn dpapi_roundtrip() {
        let plaintext = b"secret bytes 32 bytes long here!!".to_vec(); // 32 bytes
        let ct = dpapi_protect(&plaintext).unwrap();
        // Ciphertext must not contain plaintext.
        assert!(!ct.windows(8).any(|w| w == &plaintext[..8]));
        let pt = dpapi_unprotect(&ct).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn key_path_is_under_localappdata() {
        let p = key_path().unwrap();
        assert!(p.to_string_lossy().contains("saife"));
        assert!(p.to_string_lossy().contains("signing"));
        assert!(p.to_string_lossy().contains("ed25519-key"));
    }

    fn missing_key_path(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "saife-m6-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    /// M6 (verdict doc: confirmed). `audit verify` used to call `ensure()`, which
    /// MINTS a key when the file is missing - so losing the key turned every old
    /// session's verdict into `BAD_SIGNATURE` and installed a new trust anchor as a
    /// side effect of *verifying*. `load_existing` must read-or-fail, and a missing
    /// key must stay missing.
    #[test]
    fn load_existing_on_a_missing_key_errors_and_mints_nothing() {
        let path = missing_key_path("absent");
        // `KeyMaterial` deliberately has no `Debug` (it wraps a secret), so match
        // rather than `expect_err`.
        let err = match KeyMaterial::load_existing_at(&path) {
            Ok(_) => panic!("a missing key must be an error, not a mint"),
            Err(e) => e,
        };
        let text = format!("{err:#}");
        assert!(
            text.to_ascii_lowercase().contains("signing key"),
            "the error must say what is missing: {text}"
        );
        assert!(
            text.contains(&path.display().to_string()),
            "the error must name where it looked: {text}"
        );
        assert!(
            !path.exists(),
            "loading a missing key must not create the file"
        );
    }

    /// An unreadable key file (wrong DPAPI scope, corruption) is an error too: it
    /// proves nothing either way, and silently treating it as absent would send the
    /// verifier off to `BAD_SIGNATURE` for the same wrong reason.
    #[test]
    fn load_existing_refuses_a_key_it_cannot_decrypt() {
        let path = missing_key_path("garbage");
        std::fs::write(&path, b"this is not a DPAPI blob").unwrap();
        let err = match KeyMaterial::load_existing_at(&path) {
            Ok(_) => panic!("an undecryptable key must be an error, not a mint"),
            Err(e) => e,
        };
        let text = format!("{err:#}");
        assert!(
            text.to_ascii_lowercase().contains("decrypt"),
            "the error must say what failed: {text}"
        );
        assert!(
            std::fs::read(&path).unwrap() == b"this is not a DPAPI blob",
            "a failed load must not touch the file"
        );
        let _ = std::fs::remove_file(&path);
    }
}
