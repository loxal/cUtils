// Copyright 2026 Alexander Orlov <alexander.orlov@loxal.net>

//! `/api/sync` fetch — pulls the full encrypted vault from
//! Bitwarden's cloud API.
//!
//! In Phase 1a this is the ONLY authenticated endpoint we hit. The
//! response body is captured byte-for-byte and written to the
//! forensic snapshot in [`super::snapshot::write_forensic`]; no
//! parsing or decryption happens at this layer. Phase 1b adds a
//! parsed-shape decode in `cipher_codec.rs` that consumes the same
//! bytes.
//!
//! Why bytes-not-Value: a `serde_json::Value` round-trip is lossy
//! for floating-point numbers and re-orders object keys, both of
//! which would break the forensic-snapshot promise that the file
//! is *exactly* what Bitwarden served. Storing the raw text keeps
//! the file replayable.

use std::num::NonZeroU32;

use serde::Deserialize;

use super::Region;
use super::auth::{AccessToken, redact_secrets_from_body};
use super::crypto::KdfParams;

/// Maximum acceptable `/api/sync` response body size in bytes.
///
/// 256 MiB. The user's 8519-cipher vault is ~22 MB, so this gives
/// 11x headroom — easily covers any plausible personal-vault size.
/// Defends against a buggy-server or malicious-network scenario
/// where the body is large enough to cause OOM. Both
/// `Content-Length` (pre-fetch) and the actual decoded body length
/// (post-fetch) are checked; either tripping aborts the run.
pub const MAX_SYNC_BODY_BYTES: u64 = 256 * 1024 * 1024;

/// Errors specific to the `/api/sync` fetch. Distinct from
/// `AuthError` because retry policy differs: a `401` here means
/// "token expired, refresh and retry once," whereas a `401` from
/// auth itself means "credentials are wrong, abort."
#[derive(Debug)]
pub enum SyncError {
    Network(reqwest::Error),
    Unauthorized {
        body: String,
    },
    HttpStatus {
        status: u16,
        body: String,
    },
    /// Server response is too large to safely buffer. Either the
    /// `Content-Length` header exceeded [`MAX_SYNC_BODY_BYTES`]
    /// (pre-fetch reject) or the decoded body did (post-fetch).
    /// Defensive cap; never observed in practice.
    ResponseTooLarge {
        reported_bytes: u64,
    },
}

impl std::fmt::Display for SyncError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SyncError::Network(e) => write!(f, "network error contacting Bitwarden /api/sync: {e}"),
            // Sync error bodies shouldn't carry tokens, but apply
            // the same secret-scrubbing the auth path uses for
            // consistency (audit 2026-04-25).
            SyncError::Unauthorized { body } => write!(
                f,
                "Bitwarden /api/sync returned 401 (token expired or revoked): {}",
                redact_secrets_from_body(body)
            ),
            SyncError::HttpStatus { status, body } => write!(
                f,
                "Bitwarden /api/sync returned HTTP {status}: {}",
                redact_secrets_from_body(body)
            ),
            SyncError::ResponseTooLarge { reported_bytes } => write!(
                f,
                "Bitwarden /api/sync response is {reported_bytes} bytes — refusing to \
                 buffer more than {} bytes ({} MiB). If your vault legitimately exceeds \
                 this, raise the cap in live_vault::rest::MAX_SYNC_BODY_BYTES.",
                MAX_SYNC_BODY_BYTES,
                MAX_SYNC_BODY_BYTES / (1024 * 1024)
            ),
        }
    }
}

impl std::error::Error for SyncError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let SyncError::Network(e) = self {
            Some(e)
        } else {
            None
        }
    }
}

/// Fetch `/api/sync?excludeDomains=true` and return the response
/// body as raw bytes (UTF-8 JSON, but unparsed).
///
/// `excludeDomains=true` skips the equivalent-domains lookup table
/// from the response. We don't use it for dedup and skipping it
/// keeps the snapshot file slimmer.
///
/// The response **always includes**:
/// - `profile.key` — the user-symmetric-key envelope (EncString
///   type 2 on Argon2id accounts today)
/// - `profile.privateKey` — RSA private key envelope (we don't
///   touch this in v1; org collections are skipped)
/// - `ciphers[]` — every personal cipher, encrypted
/// - `folders[]` — folder definitions
/// - `collections[]`, `policies[]`, `domains` (when not excluded)
pub async fn fetch_sync(
    client: &reqwest::Client,
    region: Region,
    token: &AccessToken,
) -> Result<String, SyncError> {
    fetch_sync_at_url(client, region.api_base_url(), token).await
}

// -----------------------------------------------------------------
// /accounts/prelogin — fetches the account's KDF parameters
// -----------------------------------------------------------------

/// Wire shape of `/accounts/prelogin`. Bitwarden's identity server
/// returns these as a flat object even on the legacy endpoint.
#[derive(Deserialize, Debug)]
struct PreloginResponse {
    /// 0 = PBKDF2_SHA256, 1 = Argon2id (server `KdfType` enum).
    #[serde(rename = "Kdf", alias = "kdf")]
    kdf: i64,
    #[serde(rename = "KdfIterations", alias = "kdfIterations")]
    kdf_iterations: u32,
    #[serde(default, rename = "KdfMemory", alias = "kdfMemory")]
    kdf_memory: Option<u32>,
    #[serde(default, rename = "KdfParallelism", alias = "kdfParallelism")]
    kdf_parallelism: Option<u32>,
}

#[derive(Debug)]
pub enum PreloginError {
    Network(reqwest::Error),
    HttpStatus {
        status: u16,
        body: String,
    },
    MalformedResponse {
        body: String,
    },
    /// `kdf` field was neither 0 (PBKDF2) nor 1 (Argon2id).
    UnknownKdfType(i64),
    /// Argon2id account was missing `kdfMemory` or `kdfParallelism`.
    MissingArgonParams,
    /// KDF parameter was zero (NonZeroU32 conversion failed).
    ZeroKdfParam,
}

impl std::fmt::Display for PreloginError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PreloginError::Network(e) => write!(f, "network error contacting prelogin: {e}"),
            PreloginError::HttpStatus { status, body } => write!(
                f,
                "Bitwarden /accounts/prelogin returned HTTP {status}: {}",
                redact_secrets_from_body(body)
            ),
            PreloginError::MalformedResponse { body } => write!(
                f,
                "Bitwarden /accounts/prelogin returned an unparseable response: {}",
                redact_secrets_from_body(body)
            ),
            PreloginError::UnknownKdfType(t) => write!(
                f,
                "/accounts/prelogin returned unknown KDF type {t} (expected 0=PBKDF2 or 1=Argon2id)"
            ),
            PreloginError::MissingArgonParams => write!(
                f,
                "/accounts/prelogin reported Argon2id but omitted kdfMemory or kdfParallelism"
            ),
            PreloginError::ZeroKdfParam => write!(
                f,
                "/accounts/prelogin returned a zero KDF parameter (iterations/memory/parallelism)"
            ),
        }
    }
}

impl std::error::Error for PreloginError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let PreloginError::Network(e) = self {
            Some(e)
        } else {
            None
        }
    }
}

/// Hit `/accounts/prelogin` to learn the account's KDF parameters.
///
/// The legacy endpoint takes an unauthenticated POST with
/// `{"email": "..."}` and returns the KDF settings flat. We use the
/// legacy endpoint (not `/accounts/prelogin/password`) per the audit
/// L.1.4 recommendation: the legacy shape is broadly compatible and
/// what every existing reference implementation uses.
pub async fn fetch_prelogin(
    client: &reqwest::Client,
    region: Region,
    email: &str,
) -> Result<KdfParams, PreloginError> {
    fetch_prelogin_at_url(client, region.identity_base_url(), email).await
}

/// Variant of [`fetch_prelogin`] taking an explicit base URL for
/// wiremock tests.
pub async fn fetch_prelogin_at_url(
    client: &reqwest::Client,
    identity_base: &str,
    email: &str,
) -> Result<KdfParams, PreloginError> {
    let url = format!("{identity_base}/accounts/prelogin");
    let body_json = serde_json::to_string(&serde_json::json!({ "email": email }))
        .expect("serializing a known-shape JSON object cannot fail");
    let response = client
        .post(&url)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .header("Bitwarden-Client-Name", super::auth::CLIENT_NAME_VALUE)
        .header(
            "Bitwarden-Client-Version",
            super::auth::CLIENT_VERSION_VALUE,
        )
        .body(body_json)
        .send()
        .await
        .map_err(PreloginError::Network)?;

    let status = response.status();
    let response_body = response.text().await.map_err(PreloginError::Network)?;

    if !status.is_success() {
        return Err(PreloginError::HttpStatus {
            status: status.as_u16(),
            body: response_body,
        });
    }

    let parsed: PreloginResponse =
        serde_json::from_str(&response_body).map_err(|_| PreloginError::MalformedResponse {
            body: response_body.clone(),
        })?;

    let iterations = NonZeroU32::new(parsed.kdf_iterations).ok_or(PreloginError::ZeroKdfParam)?;
    match parsed.kdf {
        0 => Ok(KdfParams::Pbkdf2 { iterations }),
        1 => {
            let memory_mib = parsed
                .kdf_memory
                .and_then(NonZeroU32::new)
                .ok_or(PreloginError::MissingArgonParams)?;
            let parallelism = parsed
                .kdf_parallelism
                .and_then(NonZeroU32::new)
                .ok_or(PreloginError::MissingArgonParams)?;
            Ok(KdfParams::Argon2id {
                iterations,
                memory_mib,
                parallelism,
            })
        }
        other => Err(PreloginError::UnknownKdfType(other)),
    }
}

// -----------------------------------------------------------------
// /api/sync helpers (declared earlier in the file)
// -----------------------------------------------------------------

/// Variant of [`fetch_sync`] that takes an explicit base URL — used
/// by the wiremock tests in this module.
pub async fn fetch_sync_at_url(
    client: &reqwest::Client,
    api_base: &str,
    token: &AccessToken,
) -> Result<String, SyncError> {
    let url = format!("{api_base}/sync?excludeDomains=true");
    let response = client
        .get(&url)
        .header(reqwest::header::AUTHORIZATION, token.header_value())
        .header(reqwest::header::ACCEPT, "application/json")
        // Same client headers Identity demands on /connect/token.
        // Sourced from auth.rs so the two endpoints can never drift.
        .header(
            super::auth::CLIENT_NAME_HEADER,
            super::auth::CLIENT_NAME_VALUE,
        )
        .header(
            super::auth::CLIENT_VERSION_HEADER,
            super::auth::CLIENT_VERSION_VALUE,
        )
        .send()
        .await
        .map_err(SyncError::Network)?;

    // Pre-fetch size cap: if the server advertises a Content-Length
    // beyond the documented limit, refuse before allocating the
    // body buffer. Defends against OOM on a runaway response.
    if let Some(cl) = response.content_length()
        && cl > MAX_SYNC_BODY_BYTES
    {
        return Err(SyncError::ResponseTooLarge { reported_bytes: cl });
    }

    let status = response.status();
    let body = response.text().await.map_err(SyncError::Network)?;

    // Post-fetch size cap: belt-and-braces in case the server uses
    // chunked encoding (no Content-Length) or under-reports.
    if body.len() as u64 > MAX_SYNC_BODY_BYTES {
        return Err(SyncError::ResponseTooLarge {
            reported_bytes: body.len() as u64,
        });
    }

    if status.as_u16() == 401 {
        return Err(SyncError::Unauthorized { body });
    }
    if !status.is_success() {
        return Err(SyncError::HttpStatus {
            status: status.as_u16(),
            body,
        });
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{header, header_exists, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn fetch_sync_happy_path_returns_raw_body() {
        let server = MockServer::start().await;
        let token = AccessToken::for_testing("good-token");

        let body = r#"{"profile":{"key":"2.iv|data|mac"},"ciphers":[],"folders":[]}"#;
        Mock::given(method("GET"))
            .and(path("/sync"))
            .and(query_param("excludeDomains", "true"))
            .and(header("authorization", "Bearer good-token"))
            .and(header_exists("Bitwarden-Client-Name"))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .mount(&server)
            .await;

        let result = fetch_sync_at_url(&reqwest::Client::new(), &server.uri(), &token)
            .await
            .unwrap();
        assert_eq!(result, body);
    }

    #[tokio::test]
    async fn fetch_sync_401_maps_to_unauthorized() {
        let server = MockServer::start().await;
        let token = AccessToken::for_testing("expired");

        Mock::given(method("GET"))
            .and(path("/sync"))
            .respond_with(ResponseTemplate::new(401).set_body_string("token expired"))
            .mount(&server)
            .await;

        let err = fetch_sync_at_url(&reqwest::Client::new(), &server.uri(), &token)
            .await
            .unwrap_err();
        match err {
            SyncError::Unauthorized { body } => assert!(body.contains("token expired")),
            other => panic!("expected Unauthorized, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn fetch_sync_5xx_maps_to_http_status() {
        let server = MockServer::start().await;
        let token = AccessToken::for_testing("x");

        Mock::given(method("GET"))
            .and(path("/sync"))
            .respond_with(ResponseTemplate::new(503).set_body_string("upstream down"))
            .mount(&server)
            .await;

        let err = fetch_sync_at_url(&reqwest::Client::new(), &server.uri(), &token)
            .await
            .unwrap_err();
        match err {
            SyncError::HttpStatus { status, body } => {
                assert_eq!(status, 503);
                assert!(body.contains("upstream down"));
            }
            other => panic!("expected HttpStatus, got {other:?}"),
        }
    }

    #[test]
    fn sync_error_display_redacts_secrets_in_body() {
        // /api/sync error bodies shouldn't normally carry bearer
        // tokens, but we still scrub for consistency with the auth
        // error path (audit 2026-04-25). This regression catches
        // the case where a server returns a debug-info error blob
        // that happens to echo the inbound Authorization header.
        let leaky_body = r#"{"error":"x","access_token":"LEAKED-FROM-SYNC"}"#;
        let unauthorized = SyncError::Unauthorized {
            body: leaky_body.to_string(),
        };
        let http_status = SyncError::HttpStatus {
            status: 500,
            body: leaky_body.to_string(),
        };
        for err in [&unauthorized, &http_status] {
            let rendered = err.to_string();
            assert!(
                !rendered.contains("LEAKED-FROM-SYNC"),
                "SyncError leaked bearer in body: {rendered}"
            );
            assert!(rendered.contains("redacted"));
        }
    }

    #[test]
    fn max_sync_body_bytes_cap_is_documented_value() {
        // Lock in the cap. Bumping it requires editing this test,
        // which forces a code-review look at why we'd accept a
        // larger response.
        assert_eq!(MAX_SYNC_BODY_BYTES, 256 * 1024 * 1024);
    }

    #[test]
    fn response_too_large_display_includes_size_info() {
        // Operator-visible error message must name the offending
        // size and the current cap so the user knows how to react.
        let err = SyncError::ResponseTooLarge {
            reported_bytes: 999_999_999,
        };
        let msg = err.to_string();
        assert!(msg.contains("999999999"), "got: {msg}");
        assert!(msg.contains("256"), "got: {msg}"); // 256 MiB
        assert!(msg.contains("MAX_SYNC_BODY_BYTES"), "got: {msg}");
    }

    #[tokio::test]
    async fn fetch_sync_accepts_response_under_cap() {
        // Sanity: a normal-sized body succeeds — make sure the cap
        // isn't accidentally rejecting valid responses.
        let server = MockServer::start().await;
        let token = AccessToken::for_testing("x");
        let body = r#"{"profile":{"key":"x"},"ciphers":[{"id":"a"}]}"#;
        Mock::given(method("GET"))
            .and(path("/sync"))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .mount(&server)
            .await;
        let out = fetch_sync_at_url(&reqwest::Client::new(), &server.uri(), &token)
            .await
            .unwrap();
        assert_eq!(out, body);
    }

    #[tokio::test]
    async fn fetch_sync_preserves_response_bytes_verbatim() {
        // Forensic-snapshot guarantee: whatever the server sent, we
        // hand back unmodified. Test with whitespace + key ordering
        // that a Value round-trip would scramble.
        let server = MockServer::start().await;
        let token = AccessToken::for_testing("x");
        let weird = "{\n  \"profile\":  { \"key\": \"x\" },\n  \"ciphers\": []\n}";
        Mock::given(method("GET"))
            .and(path("/sync"))
            .respond_with(ResponseTemplate::new(200).set_body_string(weird))
            .mount(&server)
            .await;
        let result = fetch_sync_at_url(&reqwest::Client::new(), &server.uri(), &token)
            .await
            .unwrap();
        assert_eq!(
            result, weird,
            "fetch_sync must preserve response bytes verbatim"
        );
    }
}
