// Copyright 2026 Alexander Orlov <alexander.orlov@loxal.net>

//! Phase 1b crypto layer: KDF + HKDF stretch + EncString decrypt.
//!
//! **Decrypt-only.** This binary never generates IVs, never encrypts,
//! never PUTs back. The recoverability story is:
//!  1. Read the user's master password (interactive prompt, in
//!     `secrecy::SecretString`, zeroized on drop).
//!  2. Derive `master_key` via the account's KDF parameters.
//!  3. Stretch via two HKDF-SHA256 expand calls (info `"enc"` and
//!     `"mac"`, NOT one 64-byte expand split — the classic
//!     third-party-tool bug, locked in by byte-locked vector tests).
//!  4. Decrypt the user key (`profile.key`) with the stretched key.
//!  5. For each cipher, decrypt the per-cipher key (when present) or
//!     use the user key directly (when absent — older ciphers).
//!  6. Decrypt each encrypted field under the resolved per-cipher key.
//!
//! All algorithms come from `bitwarden/sdk-internal`'s
//! `bitwarden-crypto` crate; the byte-exact vectors live in
//! `tests/crypto_vectors.rs` and MUST pass before any decrypt code
//! touches a real vault.
//!
//! # Invariants (locked by tests/crypto_vectors.rs)
//!
//! 1. **HMAC verify is constant-time, before AES.** `subtle::ConstantTimeEq`
//!    only; never `==` on `[u8; 32]`.
//! 2. **HKDF stretch is two `hkdf_expand` calls** with literal info
//!    bytes `b"enc"` and `b"mac"`, each producing 32 bytes.
//! 3. **Argon2id salt = SHA256(email)**, PBKDF2 salt = raw email bytes.
//!    Email is `trim().to_lowercase()` before either.
//! 4. **EncString type is locked at parse.** We accept ONLY type 2
//!    (AES-256-CBC + HMAC-SHA256); types 0, 1, 3-7 abort with a clear
//!    error. The MAC has no domain separator, so allowing fallback
//!    to type 0 (no MAC) would be a downgrade attack vector.

use std::num::NonZeroU32;

use aes::Aes256;
use aes::cipher::{BlockDecryptMut, KeyIvInit, block_padding::Pkcs7};
use cbc::Decryptor;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use secrecy::{ExposeSecret, SecretString};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

type HmacSha256 = Hmac<Sha256>;

// -----------------------------------------------------------------
// KDF — derive a 32-byte master_key from (master_password, email, kdf_params)
// -----------------------------------------------------------------

/// KDF parameters returned by `/accounts/prelogin`. Wire format
/// matches the JSON Bitwarden's identity server emits.
#[derive(Debug, Clone, Copy)]
pub enum KdfParams {
    /// PBKDF2-SHA256 with `iterations` rounds. Server min 600,000
    /// since Bitwarden 2026.2.1; the audit recommended refusing
    /// anything below the current default.
    Pbkdf2 { iterations: NonZeroU32 },
    /// Argon2id with `t=iterations`, `m=memory_mib` MiB, `p=parallelism`.
    /// Bitwarden's defaults are t=3, m=64, p=4.
    Argon2id {
        iterations: NonZeroU32,
        memory_mib: NonZeroU32,
        parallelism: NonZeroU32,
    },
}

#[derive(Debug)]
pub enum CryptoError {
    /// KDF iteration count or memory below the documented minimum.
    /// Refusing acts as defense against a network adversary serving
    /// a forged `/accounts/prelogin` response.
    KdfDowngrade(&'static str),
    /// Argon2id parameter combination produced an internal error
    /// (memory-allocation failure, etc.).
    Argon2(argon2::Error),
    /// EncString string didn't parse — wrong shape, bad base64, or
    /// disallowed type code.
    EncString(&'static str),
    /// HMAC verification failed; ciphertext rejected before AES.
    /// The most security-critical failure path.
    HmacMismatch,
    /// AES-CBC unpadding failed. Usually means a wrong key or a
    /// truncated ciphertext.
    AesUnpad,
    /// User key (profile.key) didn't decrypt to the expected 64-byte
    /// (32 enc + 32 mac) shape.
    UserKeyShape,
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoError::KdfDowngrade(msg) => write!(f, "KDF downgrade refused: {msg}"),
            CryptoError::Argon2(e) => write!(f, "Argon2id error: {e}"),
            CryptoError::EncString(msg) => write!(f, "EncString parse/format error: {msg}"),
            CryptoError::HmacMismatch => write!(
                f,
                "HMAC verification failed — ciphertext rejected. Wrong key or tampered data."
            ),
            CryptoError::AesUnpad => write!(
                f,
                "AES-CBC unpad failed — wrong key, truncated ciphertext, or non-PKCS7 padding."
            ),
            CryptoError::UserKeyShape => write!(
                f,
                "decrypted user key is not 64 bytes (expected 32 enc || 32 mac)"
            ),
        }
    }
}

impl std::error::Error for CryptoError {}

/// 32-byte master key derived from the master password. Never
/// printed; zeroized on drop.
#[derive(ZeroizeOnDrop)]
pub struct MasterKey([u8; 32]);

impl MasterKey {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Test-vector-only constructor. `#[doc(hidden)]` so it doesn't
    /// show up in published rustdoc; only used by
    /// `tests/crypto_vectors.rs` to load byte-locked sdk-internal
    /// vectors. Production code paths construct `MasterKey` only
    /// via [`derive_master_key`].
    #[doc(hidden)]
    pub fn from_bytes_for_test_vectors(bytes: [u8; 32]) -> Self {
        MasterKey(bytes)
    }
}

impl std::fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("MasterKey").field(&"<redacted>").finish()
    }
}

/// Derive the master key from the user's master password and email.
///
/// Email is normalized (`trim().to_lowercase()`) before salting.
/// For PBKDF2 the salt is the normalized email bytes; for
/// Argon2id the salt is `SHA256(normalized_email)`. **This split
/// is the third-most-common third-party-tool bug** — locked in
/// by `tests/crypto_vectors.rs::pbkdf2_master_key` and
/// `argon2id_master_key`.
pub fn derive_master_key(
    password: &SecretString,
    email: &str,
    params: KdfParams,
) -> Result<MasterKey, CryptoError> {
    let normalized_email = email.trim().to_lowercase();

    match params {
        KdfParams::Pbkdf2 { iterations } => {
            // Audit defense: Bitwarden raised the server min to
            // 600,000 in v2026.2.1. Refuse anything weaker.
            if iterations.get() < 600_000 {
                return Err(CryptoError::KdfDowngrade(
                    "PBKDF2 iterations < 600,000 — refusing as downgrade-attack defense",
                ));
            }
            let mut out = [0u8; 32];
            pbkdf2::pbkdf2::<HmacSha256>(
                password.expose_secret().as_bytes(),
                normalized_email.as_bytes(),
                iterations.get(),
                &mut out,
            )
            .expect("HMAC-SHA256 accepts any key length, so pbkdf2 cannot fail here");
            Ok(MasterKey(out))
        }
        KdfParams::Argon2id {
            iterations,
            memory_mib,
            parallelism,
        } => {
            if iterations.get() < 2 {
                return Err(CryptoError::KdfDowngrade(
                    "Argon2id iterations < 2 — refusing",
                ));
            }
            if memory_mib.get() < 16 {
                return Err(CryptoError::KdfDowngrade(
                    "Argon2id memory < 16 MiB — refusing",
                ));
            }
            // Argon2id-specific: the salt is SHA256(normalized email),
            // NOT the raw email bytes. Easy to miss; locked in by
            // crypto_vectors::argon2id_master_key.
            let salt_sha = Sha256::new_with_prefix(normalized_email.as_bytes()).finalize();
            // sdk-internal converts MiB → KiB before passing to argon2.
            let memory_kib = memory_mib.get().saturating_mul(1024);
            let argon_params =
                argon2::Params::new(memory_kib, iterations.get(), parallelism.get(), Some(32))
                    .map_err(CryptoError::Argon2)?;
            let argon = argon2::Argon2::new(
                argon2::Algorithm::Argon2id,
                argon2::Version::V0x13,
                argon_params,
            );
            let mut out = [0u8; 32];
            argon
                .hash_password_into(password.expose_secret().as_bytes(), &salt_sha, &mut out)
                .map_err(CryptoError::Argon2)?;
            Ok(MasterKey(out))
        }
    }
}

// -----------------------------------------------------------------
// HKDF — stretch master_key (32 B) → enc_key (32 B) + mac_key (32 B)
// -----------------------------------------------------------------

/// 64-byte symmetric key: 32-byte AES enc key followed by 32-byte
/// HMAC-SHA256 mac key. The shape Bitwarden uses for the user key
/// AND for every per-cipher key.
#[derive(Clone, ZeroizeOnDrop)]
pub struct SymmetricKey {
    enc: [u8; 32],
    mac: [u8; 32],
}

impl SymmetricKey {
    pub fn enc(&self) -> &[u8; 32] {
        &self.enc
    }
    pub fn mac(&self) -> &[u8; 32] {
        &self.mac
    }

    /// Construct from a 64-byte buffer (e.g. a decrypted per-cipher
    /// key payload). Returns an error if `bytes.len() != 64`. Source
    /// bytes are zeroized after copy.
    pub fn from_bytes_zeroizing(bytes: &mut [u8]) -> Result<Self, CryptoError> {
        if bytes.len() != 64 {
            bytes.zeroize();
            return Err(CryptoError::UserKeyShape);
        }
        let mut enc = [0u8; 32];
        let mut mac = [0u8; 32];
        enc.copy_from_slice(&bytes[..32]);
        mac.copy_from_slice(&bytes[32..]);
        bytes.zeroize();
        Ok(SymmetricKey { enc, mac })
    }
}

impl std::fmt::Debug for SymmetricKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SymmetricKey")
            .field("enc", &"<redacted>")
            .field("mac", &"<redacted>")
            .finish()
    }
}

/// Stretch a 32-byte master key into a 64-byte (enc || mac)
/// symmetric key via TWO separate HKDF-SHA256 expand calls.
///
/// The PRK is the master key itself (HKDF-Extract is skipped).
/// The two info strings are the ASCII bytes `b"enc"` and `b"mac"`.
///
/// **DO NOT** combine this into a single 64-byte expand and split.
/// That produces different bytes; sdk-internal uses two calls, and
/// the byte-locked test in `tests/crypto_vectors.rs` rejects the
/// single-call mistake.
pub fn stretch_master_key(master_key: &MasterKey) -> SymmetricKey {
    let hk = Hkdf::<Sha256>::from_prk(master_key.as_bytes())
        .expect("PRK length matches Sha256 output (32 bytes); cannot fail");
    let mut enc = [0u8; 32];
    let mut mac = [0u8; 32];
    hk.expand(b"enc", &mut enc)
        .expect("32 byte expand within HKDF length budget");
    hk.expand(b"mac", &mut mac)
        .expect("32 byte expand within HKDF length budget");
    SymmetricKey { enc, mac }
}

// -----------------------------------------------------------------
// EncString — `<type>.<base64-iv>|<base64-data>|<base64-mac>`
// -----------------------------------------------------------------

/// Parsed EncString. We accept ONLY type 2 — see the module-level
/// invariant on type-locking. Other types abort at parse time.
#[derive(Clone)]
pub struct EncString {
    iv: Vec<u8>,
    data: Vec<u8>,
    mac: Vec<u8>,
}

impl std::fmt::Debug for EncString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncString")
            .field("iv_len", &self.iv.len())
            .field("data_len", &self.data.len())
            .field("mac_len", &self.mac.len())
            .finish()
    }
}

impl EncString {
    /// Parse a Bitwarden EncString. Refuses anything but type 2.
    pub fn parse(s: &str) -> Result<Self, CryptoError> {
        use base64::Engine;
        use base64::engine::general_purpose::STANDARD as B64;

        let (type_part, rest) = s
            .split_once('.')
            .ok_or(CryptoError::EncString("missing `.` separator"))?;
        let type_id: u8 = type_part
            .parse()
            .map_err(|_| CryptoError::EncString("type prefix is not an integer"))?;
        if type_id != 2 {
            return Err(CryptoError::EncString(
                "only EncString type 2 (AES-256-CBC + HMAC-SHA256) is supported. \
                 Type 0 (no MAC) is refused as a downgrade-attack defense; type 7 \
                 (XChaCha20-Poly1305 v2) is not yet supported.",
            ));
        }
        let mut parts = rest.split('|');
        let iv_b64 = parts
            .next()
            .ok_or(CryptoError::EncString("missing iv part"))?;
        let data_b64 = parts
            .next()
            .ok_or(CryptoError::EncString("missing data part"))?;
        let mac_b64 = parts
            .next()
            .ok_or(CryptoError::EncString("missing mac part"))?;
        if parts.next().is_some() {
            return Err(CryptoError::EncString("too many `|` parts"));
        }
        let iv = B64
            .decode(iv_b64)
            .map_err(|_| CryptoError::EncString("iv base64 decode failed"))?;
        let data = B64
            .decode(data_b64)
            .map_err(|_| CryptoError::EncString("data base64 decode failed"))?;
        let mac = B64
            .decode(mac_b64)
            .map_err(|_| CryptoError::EncString("mac base64 decode failed"))?;
        if iv.len() != 16 {
            return Err(CryptoError::EncString("iv must be 16 bytes"));
        }
        if mac.len() != 32 {
            return Err(CryptoError::EncString("mac must be 32 bytes (SHA-256)"));
        }
        if data.is_empty() || data.len() % 16 != 0 {
            return Err(CryptoError::EncString(
                "data must be a non-empty multiple of 16 bytes (CBC block size)",
            ));
        }
        Ok(EncString { iv, data, mac })
    }
}

/// AES-256-CBC + HMAC-SHA256 decrypt with **constant-time MAC verify**.
///
/// Order of operations (mandatory):
///   1. Compute `expected_mac = HMAC-SHA256(mac_key, iv || data)`.
///   2. **Constant-time** compare `expected_mac` against `enc.mac`.
///   3. ONLY if MAC verifies, run AES-256-CBC decrypt with PKCS7 unpad.
///
/// Skipping step 1 or doing step 2 with `==` is the #1 historical
/// implementation bug. `subtle::ConstantTimeEq` is mandatory.
pub fn decrypt(enc: &EncString, key: &SymmetricKey) -> Result<Vec<u8>, CryptoError> {
    let mut hmac =
        HmacSha256::new_from_slice(&key.mac).expect("HMAC-SHA256 accepts any key length");
    hmac.update(&enc.iv);
    hmac.update(&enc.data);
    let expected_mac = hmac.finalize().into_bytes();
    // Constant-time compare — never `==`.
    if !bool::from(expected_mac.ct_eq(&enc.mac)) {
        return Err(CryptoError::HmacMismatch);
    }

    let mut buf = enc.data.clone();
    let pt_len = Decryptor::<Aes256>::new(&key.enc.into(), enc.iv.as_slice().into())
        .decrypt_padded_mut::<Pkcs7>(&mut buf)
        .map_err(|_| CryptoError::AesUnpad)?
        .len();
    buf.truncate(pt_len);
    Ok(buf)
}

/// Decrypt an EncString and interpret the plaintext as UTF-8. Most
/// of Bitwarden's encrypted fields are strings (cipher names,
/// passwords, notes, URIs) — this saves the caller a `from_utf8`
/// every time.
pub fn decrypt_to_string(enc: &EncString, key: &SymmetricKey) -> Result<String, CryptoError> {
    let pt = decrypt(enc, key)?;
    String::from_utf8(pt).map_err(|_| CryptoError::EncString("plaintext is not UTF-8"))
}

#[cfg(test)]
mod tests {
    //! Unit tests living next to the impl. The byte-locked
    //! regression vectors against `sdk-internal` live in
    //! `tests/crypto_vectors.rs` so they run as integration tests
    //! and can't be silently `#[ignore]`d.

    use super::*;

    #[test]
    fn enc_string_parse_rejects_type_0() {
        let s = "0.AAECAwQFBgcICQoLDA0ODw==|AAECAwQFBgcICQoLDA0ODw==";
        let err = EncString::parse(s).unwrap_err();
        assert!(matches!(err, CryptoError::EncString(_)));
    }

    #[test]
    fn enc_string_parse_rejects_type_7() {
        // Type 7 (COSE_Encrypt0 / XChaCha20-Poly1305) is the v2
        // marker. Refusing it is invariant L.0 #5/6.
        let s = "7.somecoseblob";
        let err = EncString::parse(s).unwrap_err();
        match err {
            CryptoError::EncString(msg) => assert!(msg.contains("type")),
            _ => panic!("expected EncString error"),
        }
    }

    #[test]
    fn enc_string_parse_rejects_missing_mac_part() {
        // 2 parts (iv|data, no mac). Could be a pre-MAC type 0 in
        // disguise. Refuse.
        let s = "2.AAECAwQFBgcICQoLDA0ODw==|AAECAwQFBgcICQoLDA0ODw==";
        let err = EncString::parse(s).unwrap_err();
        assert!(matches!(err, CryptoError::EncString(_)));
    }

    #[test]
    fn enc_string_parse_rejects_iv_wrong_length() {
        let s = "2.AAEC|AAECAwQFBgcICQoLDA0ODw==|AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
        let err = EncString::parse(s).unwrap_err();
        match err {
            CryptoError::EncString(msg) => assert!(msg.contains("iv")),
            _ => panic!("expected EncString error"),
        }
    }

    #[test]
    fn enc_string_parse_accepts_valid_type_2() {
        // 16-byte iv, 16-byte data (one CBC block), 32-byte mac.
        let s = "2.AAECAwQFBgcICQoLDA0ODw==|AAECAwQFBgcICQoLDA0ODw==|AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
        let parsed = EncString::parse(s).unwrap();
        assert_eq!(parsed.iv.len(), 16);
        assert_eq!(parsed.data.len(), 16);
        assert_eq!(parsed.mac.len(), 32);
    }

    #[test]
    fn pbkdf2_refuses_iterations_below_600k() {
        let pw = SecretString::new("anything".to_string().into());
        let params = KdfParams::Pbkdf2 {
            iterations: NonZeroU32::new(599_999).unwrap(),
        };
        let err = derive_master_key(&pw, "u@example.test", params).unwrap_err();
        assert!(matches!(err, CryptoError::KdfDowngrade(_)));
    }

    #[test]
    fn argon2id_refuses_low_memory() {
        let pw = SecretString::new("anything".to_string().into());
        let params = KdfParams::Argon2id {
            iterations: NonZeroU32::new(3).unwrap(),
            memory_mib: NonZeroU32::new(15).unwrap(),
            parallelism: NonZeroU32::new(4).unwrap(),
        };
        let err = derive_master_key(&pw, "u@example.test", params).unwrap_err();
        assert!(matches!(err, CryptoError::KdfDowngrade(_)));
    }

    #[test]
    fn debug_redacts_master_key() {
        let mk = MasterKey([0xaa; 32]);
        let s = format!("{mk:?}");
        assert!(!s.contains("aa"), "master key bytes leaked in Debug: {s}");
        assert!(s.contains("redacted"));
    }

    #[test]
    fn debug_redacts_symmetric_key() {
        let sk = SymmetricKey {
            enc: [0xaa; 32],
            mac: [0xbb; 32],
        };
        let s = format!("{sk:?}");
        assert!(!s.contains("aa"));
        assert!(!s.contains("bb"));
        assert!(s.contains("redacted"));
    }
}
