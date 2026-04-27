// Copyright 2026 Alexander Orlov <alexander.orlov@loxal.net>

//! Live-vault transport for the REST-API snapshot code.
//!
//! Used by:
//!   - `bitwarden-backup-vault-encrypted` — auth + sync only
//!   - `bitwarden-backup-vault-decrypted` — auth + sync + local decrypt
//!   - crypto/vector tests that keep the direct `/api/sync` decoder honest
//!
//! This module owns: OAuth2 `client_credentials` authentication
//! against `/identity/connect/token`, the `/api/sync` fetch,
//! `/accounts/prelogin` for KDF parameters, the AES-CBC-HMAC crypto
//! stack (KDF + HKDF + EncString parser + decrypt), and the
//! cipher-codec that translates `/api/sync` into a Bitwarden
//! JSON-export-shaped value.
//!
//! Vault mutations are NOT implemented — the binaries are
//! read-only by design. Crypto correctness is gated on
//! `tests/crypto_vectors.rs`, which locks every primitive byte-exact
//! against `bitwarden/sdk-internal`.
//!
//! # Module map
//!
//! - [`auth`] — OAuth client_credentials, device-id persistence,
//!   redacted-error display
//! - [`rest`]    — `/api/sync`, `/accounts/prelogin`
//! - [`crypto`] — KDF (PBKDF2 + Argon2id), HKDF stretch, EncString
//!   type-2 parse + AES-CBC-HMAC decrypt
//! - [`cipher_codec`] — `/api/sync` → JSON-export shape (with all
//!   field-level decryption)
//! - [`snapshot`] — atomic-no-clobber writers for the encrypted and
//!   decrypted backup files

pub mod auth;
pub mod cipher_codec;
pub mod crypto;
pub mod rest;
pub mod snapshot;

use std::fmt;

/// Bitwarden cloud region. Selects the `identity.*` and `api.*`
/// hostnames. There is no automatic region-discovery endpoint
/// (confirmed in `RESEARCH_BITWARDEN_CRYPTO.md` § L.8) — the user
/// must declare their region via `BW_REGION=us|eu` in
/// `vault/bitwarden_api_key.env`.
///
/// Self-hosted (Vaultwarden, on-prem) is intentionally NOT
/// supported in v1; supporting it would require a `BW_BASE_URL`
/// override that we don't want to expose until the cloud path
/// has burned in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Region {
    Us,
    Eu,
}

impl Region {
    /// `https://identity.bitwarden.com` or `.eu` — the OAuth2 host.
    pub fn identity_base_url(self) -> &'static str {
        match self {
            Region::Us => "https://identity.bitwarden.com",
            Region::Eu => "https://identity.bitwarden.eu",
        }
    }

    /// `https://api.bitwarden.com` or `.eu` — the vault API host.
    pub fn api_base_url(self) -> &'static str {
        match self {
            Region::Us => "https://api.bitwarden.com",
            Region::Eu => "https://api.bitwarden.eu",
        }
    }

    /// Parse `us` or `eu` (case-insensitive) from the env var.
    pub fn parse(s: &str) -> Result<Self, RegionParseError> {
        match s.trim().to_ascii_lowercase().as_str() {
            "us" => Ok(Region::Us),
            "eu" => Ok(Region::Eu),
            other => Err(RegionParseError(other.to_string())),
        }
    }
}

#[derive(Debug)]
pub struct RegionParseError(String);

impl fmt::Display for RegionParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "unrecognized BW_REGION {:?}: expected `us` or `eu`",
            self.0
        )
    }
}

impl std::error::Error for RegionParseError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn region_us_endpoints() {
        assert_eq!(
            Region::Us.identity_base_url(),
            "https://identity.bitwarden.com"
        );
        assert_eq!(Region::Us.api_base_url(), "https://api.bitwarden.com");
    }

    #[test]
    fn region_eu_endpoints() {
        assert_eq!(
            Region::Eu.identity_base_url(),
            "https://identity.bitwarden.eu"
        );
        assert_eq!(Region::Eu.api_base_url(), "https://api.bitwarden.eu");
    }

    #[test]
    fn region_parse_accepts_us_and_eu_case_insensitive() {
        assert_eq!(Region::parse("us").unwrap(), Region::Us);
        assert_eq!(Region::parse("US").unwrap(), Region::Us);
        assert_eq!(Region::parse("eu").unwrap(), Region::Eu);
        assert_eq!(Region::parse("  EU  ").unwrap(), Region::Eu);
    }

    #[test]
    fn region_parse_rejects_self_hosted_alias() {
        // We deliberately don't accept `self-hosted` / `selfhosted`
        // / `vaultwarden` / `custom` — Phase 1 is cloud-only.
        assert!(Region::parse("self-hosted").is_err());
        assert!(Region::parse("vaultwarden").is_err());
        assert!(Region::parse("").is_err());
    }
}
