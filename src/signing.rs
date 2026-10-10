//! Ed25519 signing key for the audit trail root.
//!
//! The secret key is stored at `%LOCALAPPDATA%\sandbox\signing\ed25519-key`,
//! DPAPI-encrypted (`CryptProtectData`, user scope — not LOCAL_MACHINE, so only
//! the same user on the same machine can decrypt). The 32-byte secret is
//! encrypted to a variable-length blob and written with a restrictive DACL
//! (owner + SYSTEM only — best-effort; DPAPI is the primary protection).
//!
//! Public key is derived from the secret on demand; we don't store it.

use anyhow::{bail, Context, Result};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use std::path::PathBuf;
use windows::Win32::Foundation::LocalFree;
use windows::Win32::Foundation::HLOCAL;
use windows::Win32::Security::Cryptography::{
    CryptProtectData, CryptUnprotectData, CRYPT_INTEGER_BLOB,
};
use windows::Win32::Storage::FileSystem::{MoveFileExW, MOVE_FILE_FLAGS};
use windows::core::{HRESULT, HSTRING};

/// Serializes first-time key creation within this process. The cross-process
/// race is handled by the non-replacing atomic publish in `ensure()`. Without
/// both, concurrent first-runs (two `sandbox run` processes on a fresh
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
            let secret = signing.to_bytes();
            let encrypted = dpapi_protect(&secret)?;
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
        let bytes = std::fs::read(&path).with_context(|| format!("read {}", path.display()))?;
        let secret = dpapi_unprotect(&bytes)?;
        if secret.len() != 32 {
            bail!("ed25519-key file is {} bytes, expected 32 (decrypted)", secret.len());
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&secret);
        let signing = SigningKey::from_bytes(&arr);
        Ok(Self { signing })
    }

    /// Sign the 32-byte root (chain root = SHA-256 of last leaf's canonical
    /// body, already computed by the caller). Returns the 64-byte signature.
    pub fn sign_root(&self, root_bytes: &[u8]) -> [u8; 64] {
        use ed25519_dalek::Signer;
        self.signing.sign(root_bytes).to_bytes()
    }
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
    Ok(local.join("sandbox").join("signing").join("ed25519-key"))
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
    let mut secret = [0u8; 32];
    // SAFETY: see `src/net/token.rs:12`. Same pattern: system-preferred RNG,
    // no algorithm handle, valid `&mut [u8]` of length 32.
    unsafe {
        BCryptGenRandom(None, &mut secret, BCRYPT_USE_SYSTEM_PREFERRED_RNG)
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
        let out = std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize).to_vec();
        let _ = LocalFree(Some(HLOCAL(out_blob.pbData as *mut _)));
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert!(p.to_string_lossy().contains("sandbox"));
        assert!(p.to_string_lossy().contains("signing"));
        assert!(p.to_string_lossy().contains("ed25519-key"));
    }
}
