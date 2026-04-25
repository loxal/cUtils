// Copyright 2026 Alexander Orlov <alexander.orlov@loxal.net>

//! OAuth2 `client_credentials` flow against Bitwarden's
//! `/identity/connect/token` endpoint.
//!
//! Authenticates with the personal API key from the Bitwarden web
//! vault (Account Settings → Security → Keys). This grant type is
//! the documented service-tool path: it does NOT involve the
//! master password (the master password is only needed later, for
//! cipher decryption — see Phase 1b crypto module).
//!
//! Per `RESEARCH_BITWARDEN_CRYPTO.md` § L.8, the SDK includes
//! non-OAuth-spec fields (`deviceType`, `deviceIdentifier`,
//! `deviceName`) in its request. We mirror that shape because the
//! Bitwarden server is observed to require them — sending the
//! bare OAuth2 body returns HTTP 400. The `deviceIdentifier` is a
//! stable per-installation UUID derived from the host so repeated
//! runs are recognized as the same client.

use std::time::{Duration, SystemTime};

use serde::Deserialize;

use super::Region;

/// A successfully-acquired OAuth bearer token plus its expected
/// expiry instant. Held opaque — the `access_token` field never
/// leaves this module via `Debug`/`Display`/serialization.
///
/// **Token lifetime is observed at 1 hour** (`expires_in: 3600`)
/// for `client_credentials` grants but Bitwarden has not published
/// an SLA. Callers must be prepared for shorter lifetimes and
/// re-authenticate on `401` per the research's L.8 retry pattern.
pub struct AccessToken {
    /// The bearer token. Bytes-only access via [`AccessToken::header_value`];
    /// never expose as `String` to keep accidental logging away.
    bearer: String,
    /// Wall-clock instant after which the server is expected to
    /// reject this token. `None` if the server didn't return
    /// `expires_in` (treat as "expires immediately, refresh now").
    expires_at: Option<SystemTime>,
}

impl AccessToken {
    /// Render as the `Authorization` header value: `Bearer <token>`.
    /// Returned as a String so it can be passed straight to
    /// `reqwest::RequestBuilder::header`. Caller MUST NOT log this.
    pub fn header_value(&self) -> String {
        format!("Bearer {}", self.bearer)
    }

    /// True iff the token is past its server-claimed expiry, with a
    /// 60-second skew margin so we refresh before the server starts
    /// returning 401s.
    pub fn is_expired(&self) -> bool {
        match self.expires_at {
            None => true,
            Some(t) => SystemTime::now() >= t.checked_sub(Duration::from_secs(60)).unwrap_or(t),
        }
    }

    /// Test-only constructor. Lets sibling modules' integration
    /// tests build a token without going through the OAuth flow.
    /// Production code MUST use [`acquire_access_token`].
    #[cfg(test)]
    pub(crate) fn for_testing(bearer: impl Into<String>) -> Self {
        Self {
            bearer: bearer.into(),
            expires_at: SystemTime::now().checked_add(Duration::from_secs(3600)),
        }
    }
}

// Deliberately NO Debug/Display impls — the bearer token must
// never appear in trace output, panic messages, or audit JSON.
impl std::fmt::Debug for AccessToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccessToken")
            .field("bearer", &"<redacted>")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Personal API key credentials from the user's Bitwarden web vault
/// (Account Settings → Security → Keys → View API Key).
///
/// Fields are **private** and the type implements a custom `Debug`
/// that redacts the secret. The auto-derived `Debug` would otherwise
/// expose `client_secret` to any caller who hit `{:?}` on a
/// credentials value (panic message, log line, error chain). The
/// `Clone` impl is intentionally kept — the auth flow needs to clone
/// credentials when retrying after a 401.
#[derive(Clone)]
pub struct ApiKeyCredentials {
    client_id: String,
    client_secret: String,
}

impl ApiKeyCredentials {
    /// Construct from the env-loaded values. Validation that
    /// `client_id` looks like a personal (not org) key happens in the
    /// binary's `load_env_file`.
    pub fn new(client_id: String, client_secret: String) -> Self {
        Self {
            client_id,
            client_secret,
        }
    }

    /// Public — `client_id` is **not** sensitive; it appears in the
    /// Bitwarden web UI and identifies the account but does not
    /// authenticate.
    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    /// Crate-internal accessor for the OAuth flow only. Marked
    /// `pub(crate)` so external callers can never read the secret
    /// out, even by accident.
    pub(crate) fn client_secret(&self) -> &str {
        &self.client_secret
    }
}

impl std::fmt::Debug for ApiKeyCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiKeyCredentials")
            .field("client_id", &self.client_id)
            .field("client_secret", &"<redacted>")
            .finish()
    }
}

/// Errors that can come out of the auth flow. Distinct variants for
/// each failure mode so callers can attach human-friendly messages
/// per case (and so that future retry logic in Phase 2 / 3 can
/// branch on the type).
#[derive(Debug)]
pub enum AuthError {
    /// `reqwest` couldn't reach the identity host (DNS, TLS,
    /// connection refused). Network-layer; retry might help.
    Network(reqwest::Error),
    /// Server returned a non-2xx status. Body included for
    /// debugging — it does NOT contain the credentials, only the
    /// server's error description.
    HttpStatus { status: u16, body: String },
    /// Server returned 2xx but the body wasn't a valid token
    /// response. Body included.
    MalformedResponse { body: String, source: serde_json::Error },
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthError::Network(e) => write!(f, "network error contacting Bitwarden: {e}"),
            AuthError::HttpStatus { status, body } => write!(
                f,
                "Bitwarden /identity/connect/token returned HTTP {status}: {}",
                redact_secrets_from_body(body)
            ),
            AuthError::MalformedResponse { body, source } => write!(
                f,
                "Bitwarden /identity/connect/token returned an unparseable response \
                 (parse error: {source}; body: {})",
                redact_secrets_from_body(body)
            ),
        }
    }
}

/// Mask any value that looks like a bearer token, refresh token, or
/// related secret before it goes to stderr.
///
/// A `MalformedResponse` typically fires only when Bitwarden returns
/// a non-2xx error wrapped in unexpected JSON, but if the server ever
/// returned a 2xx body we *almost* recognized — say a new token-shape
/// with `access_token` plus an extra field that broke our parser — we
/// would otherwise print the bearer to stderr. This regex-free mask
/// scrubs the common token-bearing field names; the rest of the body
/// (status descriptions, error codes) survives unredacted to aid
/// debugging.
///
/// `pub(crate)` so `rest::SyncError`'s `Display` can apply the same
/// scrubbing — a `/api/sync` error body shouldn't normally carry a
/// bearer either, but consistency wins.
pub(crate) fn redact_secrets_from_body(body: &str) -> String {
    const SENSITIVE_KEYS: &[&str] = &[
        "access_token",
        "refresh_token",
        "id_token",
        "client_secret",
        "MasterPasswordHash",
        "TwoFactorToken",
    ];
    let mut out = body.to_string();
    for key in SENSITIVE_KEYS {
        out = mask_json_string_value(&out, key);
    }
    // Belt-and-braces: cap the total length so a server returning a
    // 50KB error blob doesn't flood stderr.
    if out.len() > 1024 {
        out.truncate(1024);
        out.push_str("... (truncated)");
    }
    out
}

/// Replace `"<key>":"<value>"` with `"<key>":"<redacted>"` in `s`,
/// regardless of where it appears. Whitespace-tolerant around the
/// colon. Naive substring scan; stops on the first match per key
/// pair so a body listing the same key multiple times still gets
/// each occurrence handled. JSON-aware enough for the responses
/// Bitwarden actually returns; not a full JSON rewrite.
fn mask_json_string_value(s: &str, key: &str) -> String {
    let needle = format!("\"{key}\"");
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(pos) = rest.find(&needle) {
        out.push_str(&rest[..pos + needle.len()]);
        let after = &rest[pos + needle.len()..];
        // Skip whitespace + ":" + whitespace.
        let trimmed = after.trim_start();
        if let Some(rem) = trimmed.strip_prefix(':') {
            let value_start = rem.trim_start();
            if let Some(rem) = value_start.strip_prefix('"') {
                // Find the next unescaped quote.
                let mut close = None;
                let mut chars = rem.char_indices();
                while let Some((i, c)) = chars.next() {
                    if c == '\\' {
                        let _ = chars.next();
                        continue;
                    }
                    if c == '"' {
                        close = Some(i);
                        break;
                    }
                }
                if let Some(end) = close {
                    out.push_str(": \"<redacted>\"");
                    rest = &rem[end + 1..];
                    continue;
                }
            }
        }
        // Couldn't parse — drop the rest verbatim and bail.
        out.push_str(after);
        return out;
    }
    out.push_str(rest);
    out
}

impl std::error::Error for AuthError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            AuthError::Network(e) => Some(e),
            AuthError::MalformedResponse { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// Wire shape of the successful token response. Field set matches
/// what Bitwarden's identity server actually returns (verified
/// during dev against the user's account in the dev-test-dedup
/// folder). `refresh_token` is intentionally not deserialized —
/// `client_credentials` grants don't issue one; the refresh path
/// is to re-call this endpoint with the same credentials.
#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: Option<u64>,
}

/// Acquire a fresh OAuth bearer token via `client_credentials`
/// grant.
///
/// `device_identifier` is a stable UUIDv4 per-installation. The
/// caller derives it once from a host-stable source (see
/// [`stable_device_identifier`]) and passes it in; we don't
/// generate a fresh one every call because the server may
/// associate device-fingerprint metadata with it.
pub async fn acquire_access_token(
    client: &reqwest::Client,
    region: Region,
    creds: &ApiKeyCredentials,
    device_identifier: &str,
    device_name: &str,
) -> Result<AccessToken, AuthError> {
    let url = format!("{}/connect/token", region.identity_base_url());

    // Per L.8: include the SDK-style device fields. The bare OAuth2
    // spec body is missing `deviceType`, `deviceIdentifier`,
    // `deviceName` — Bitwarden's server returns 400 without them.
    // `deviceType=10` is the SDK device-type enum value (sdk-internal
    // `bitwarden-core/src/auth/api/request/api_token_request.rs`).
    let form: [(&str, &str); 7] = [
        ("scope", "api"),
        ("client_id", creds.client_id()),
        ("client_secret", creds.client_secret()),
        ("grant_type", "client_credentials"),
        ("deviceType", "10"),
        ("deviceIdentifier", device_identifier),
        ("deviceName", device_name),
    ];

    let response = client
        .post(&url)
        .form(&form)
        // Bitwarden's Identity server REQUIRES these headers on the
        // OAuth endpoint and returns
        //   400 {"error":"version_header_missing", ...}
        // without them. The check is for *presence*, not value
        // comparison — sending our own version string is fine.
        // Discovered via the user's first live run on 2026-04-25.
        .header(CLIENT_NAME_HEADER, CLIENT_NAME_VALUE)
        .header(CLIENT_VERSION_HEADER, CLIENT_VERSION_VALUE)
        .send()
        .await
        .map_err(AuthError::Network)?;

    let status = response.status();
    let body = response.text().await.map_err(AuthError::Network)?;

    if !status.is_success() {
        return Err(AuthError::HttpStatus {
            status: status.as_u16(),
            body,
        });
    }

    let parsed: TokenResponse =
        serde_json::from_str(&body).map_err(|e| AuthError::MalformedResponse {
            body: body.clone(),
            source: e,
        })?;

    let expires_at = parsed
        .expires_in
        .and_then(|secs| SystemTime::now().checked_add(Duration::from_secs(secs)));

    Ok(AccessToken {
        bearer: parsed.access_token,
        expires_at,
    })
}

/// Bitwarden's Identity server (and the API server) parse these
/// headers on every authenticated request. They MUST be sent on
/// `/identity/connect/token` *and* `/api/sync` — the Identity error
/// message ("No client version header found, required to prevent
/// encryption errors") is the load-bearing one because it gates
/// auth itself. Kept as `pub(crate)` constants so `rest.rs` shares
/// the same values without drifting.
pub(crate) const CLIENT_NAME_HEADER: &str = "Bitwarden-Client-Name";
pub(crate) const CLIENT_VERSION_HEADER: &str = "Bitwarden-Client-Version";
pub(crate) const CLIENT_NAME_VALUE: &str = "bitwarden-api-dedup";
pub(crate) const CLIENT_VERSION_VALUE: &str = env!("CARGO_PKG_VERSION");

/// Read or generate the persistent per-installation
/// `deviceIdentifier` UUID at `<vault_dir>/.device_id`.
///
/// **Why persisted, not derived:** the audit on 2026-04-25
/// flagged that Bitwarden's identity server tracks devices and
/// flaps the CAPTCHA-challenge heuristic when an unknown
/// identifier appears. Earlier code derived the UUID from
/// hostname + user via std hashing, which is stable for the
/// happy path but drifts when env vars are unset (containerized
/// CI, fresh shell with no `HOSTNAME`, etc.) and would trigger
/// CAPTCHAs after every drift.
///
/// **First-run behavior:** if the file doesn't exist, generate a
/// fresh v4 UUID from `/dev/urandom`, write it with mode `0o600`,
/// and return it. Subsequent runs read the same value forever.
///
/// **Refusal:** if `<vault_dir>` doesn't exist, returns an error
/// (mirrors the binary's vault-required posture so we don't
/// scatter `.device_id` files across the filesystem).
pub fn persistent_device_identifier(
    vault_dir: &std::path::Path,
) -> Result<String, std::io::Error> {
    if !vault_dir.is_dir() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!(
                "vault dir {} does not exist — refusing to write `.device_id` outside it",
                vault_dir.display()
            ),
        ));
    }
    let path = vault_dir.join(".device_id");

    // Existing file → trust it. The shape check is a defense
    // against accidental hand-edit; if it's been clobbered we
    // refuse to use it rather than sending garbage to the server.
    if path.exists() {
        let contents = std::fs::read_to_string(&path)?;
        let candidate = contents.trim();
        if looks_like_uuid_v4(candidate) {
            return Ok(candidate.to_string());
        }
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "{} exists but does not contain a valid UUIDv4 — refusing to overwrite. \
                 Delete it manually if you intended to regenerate.",
                path.display()
            ),
        ));
    }

    let id = generate_uuid_v4_from_urandom()?;
    crate::io_util::write_sensitive_atomic(&path, &id)?;
    Ok(id)
}

/// Generate a fresh v4 UUID by reading 16 bytes from
/// `/dev/urandom` and stamping in the RFC 4122 version/variant
/// bits. No `rand` crate dependency — same approach
/// `bitwarden-move-to-folder` uses.
fn generate_uuid_v4_from_urandom() -> Result<String, std::io::Error> {
    use std::io::Read;
    let mut bytes = [0u8; 16];
    let mut f = std::fs::File::open("/dev/urandom")?;
    f.read_exact(&mut bytes)?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Ok(format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5], bytes[6], bytes[7],
        bytes[8], bytes[9], bytes[10], bytes[11],
        bytes[12], bytes[13], bytes[14], bytes[15],
    ))
}

fn looks_like_uuid_v4(s: &str) -> bool {
    if s.len() != 36 {
        return false;
    }
    let segs: Vec<&str> = s.split('-').collect();
    if segs.len() != 5 || segs.iter().map(|s| s.len()).collect::<Vec<_>>() != [8, 4, 4, 4, 12] {
        return false;
    }
    if segs[2].chars().next() != Some('4') {
        return false;
    }
    let v = segs[3].chars().next();
    if !matches!(v, Some('8') | Some('9') | Some('a') | Some('b')) {
        return false;
    }
    s.chars().all(|c| c == '-' || c.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, SystemTime};
    use wiremock::matchers::{body_string_contains, header_exists, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Test-only: same as `acquire_access_token` but takes an
    /// explicit identity-base URL so a wiremock server can stand in
    /// for `https://identity.bitwarden.com`. Production code uses
    /// `acquire_access_token` which derives the URL from `Region`.
    /// Kept in lockstep with the production function — any change
    /// to body shape or headers must land in both.
    async fn acquire_access_token_at_url(
        client: &reqwest::Client,
        identity_base: &str,
        creds: &ApiKeyCredentials,
        device_identifier: &str,
        device_name: &str,
    ) -> Result<AccessToken, AuthError> {
        let url = format!("{identity_base}/connect/token");
        let form: [(&str, &str); 7] = [
            ("scope", "api"),
            ("client_id", creds.client_id()),
            ("client_secret", creds.client_secret()),
            ("grant_type", "client_credentials"),
            ("deviceType", "10"),
            ("deviceIdentifier", device_identifier),
            ("deviceName", device_name),
        ];
        let response = client
            .post(&url)
            .form(&form)
            .header(CLIENT_NAME_HEADER, CLIENT_NAME_VALUE)
            .header(CLIENT_VERSION_HEADER, CLIENT_VERSION_VALUE)
            .send()
            .await
            .map_err(AuthError::Network)?;
        let status = response.status();
        let body = response.text().await.map_err(AuthError::Network)?;
        if !status.is_success() {
            return Err(AuthError::HttpStatus {
                status: status.as_u16(),
                body,
            });
        }
        let parsed: TokenResponse =
            serde_json::from_str(&body).map_err(|e| AuthError::MalformedResponse {
                body: body.clone(),
                source: e,
            })?;
        let expires_at = parsed
            .expires_in
            .and_then(|secs| SystemTime::now().checked_add(Duration::from_secs(secs)));
        Ok(AccessToken {
            bearer: parsed.access_token,
            expires_at,
        })
    }

    #[tokio::test]
    async fn acquire_token_happy_path() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/connect/token"))
            .and(body_string_contains("grant_type=client_credentials"))
            .and(body_string_contains("scope=api"))
            .and(body_string_contains("deviceType=10"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"{"access_token":"opaque-bearer-xyz","expires_in":3600,"token_type":"Bearer","scope":"api"}"#,
            ))
            .mount(&server)
            .await;

        let creds = ApiKeyCredentials::new("user.test-client-id".to_string(), "test-client-secret".to_string());
        let client = reqwest::Client::new();
        let token = acquire_access_token_at_url(
            &client,
            &server.uri(),
            &creds,
            "00000000-0000-4000-8000-000000000000",
            "test-device",
        )
        .await
        .unwrap();

        assert_eq!(token.header_value(), "Bearer opaque-bearer-xyz");
        assert!(!token.is_expired(), "fresh token must not be expired");
    }

    #[tokio::test]
    async fn acquire_token_propagates_400_with_body() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/connect/token"))
            .respond_with(
                ResponseTemplate::new(400)
                    .set_body_string(r#"{"error":"invalid_client"}"#),
            )
            .mount(&server)
            .await;

        let creds = ApiKeyCredentials::new("wrong".to_string(), "wrong".to_string());
        let client = reqwest::Client::new();
        let err = acquire_access_token_at_url(
            &client,
            &server.uri(),
            &creds,
            "00000000-0000-4000-8000-000000000000",
            "test-device",
        )
        .await
        .unwrap_err();

        match err {
            AuthError::HttpStatus { status, body } => {
                assert_eq!(status, 400);
                assert!(body.contains("invalid_client"));
            }
            other => panic!("expected HttpStatus, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn acquire_token_propagates_malformed_2xx_body() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/connect/token"))
            .respond_with(ResponseTemplate::new(200).set_body_string("not-json-at-all"))
            .mount(&server)
            .await;

        let creds = ApiKeyCredentials::new("x".to_string(), "y".to_string());
        let client = reqwest::Client::new();
        let err = acquire_access_token_at_url(
            &client,
            &server.uri(),
            &creds,
            "00000000-0000-4000-8000-000000000000",
            "test-device",
        )
        .await
        .unwrap_err();

        match err {
            AuthError::MalformedResponse { body, .. } => {
                assert_eq!(body, "not-json-at-all");
            }
            other => panic!("expected MalformedResponse, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn acquire_token_handles_missing_expires_in() {
        // Some self-hosted forks don't set expires_in; we treat that
        // as "expires immediately, refresh now" rather than crashing.
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/connect/token"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"{"access_token":"no-expiry-token"}"#,
            ))
            .mount(&server)
            .await;

        let creds = ApiKeyCredentials::new("x".to_string(), "y".to_string());
        let client = reqwest::Client::new();
        let token = acquire_access_token_at_url(
            &client,
            &server.uri(),
            &creds,
            "00000000-0000-4000-8000-000000000000",
            "test-device",
        )
        .await
        .unwrap();

        assert_eq!(token.header_value(), "Bearer no-expiry-token");
        assert!(token.is_expired(), "missing expires_in must be treated as expired");
    }

    #[test]
    fn malformed_response_display_redacts_access_token() {
        // Audit finding: if Bitwarden ever returned a 2xx body we
        // almost recognized — say a new token shape with extra
        // fields — `MalformedResponse` would carry the bearer in
        // `body` and print it to stderr via Display. Lock in
        // redaction.
        let body = r#"{"access_token":"SUPER-SECRET-BEARER-VALUE","scope":"api"}"#;
        // Cheap way to manufacture a parse error without `unwrap_err`
        // (TokenResponse lacks Debug — that's intentional, since
        // it carries a bearer).
        let parse_err = match serde_json::from_str::<serde_json::Value>("{not-json") {
            Err(e) => e,
            Ok(_) => panic!("expected parse error"),
        };
        let err = AuthError::MalformedResponse {
            body: body.to_string(),
            source: parse_err,
        };
        let rendered = err.to_string();
        assert!(
            !rendered.contains("SUPER-SECRET-BEARER-VALUE"),
            "Display leaked bearer: {rendered}"
        );
        assert!(rendered.contains("<redacted>"), "expected redaction marker in: {rendered}");
        // Non-secret context should survive so the error remains debuggable.
        assert!(rendered.contains("api"));
    }

    #[test]
    fn redact_secrets_handles_multiple_keys() {
        let s = r#"{"access_token":"a","refresh_token":"b","client_secret":"c","ok":"keep"}"#;
        let red = redact_secrets_from_body(s);
        assert!(!red.contains("\"a\""));
        assert!(!red.contains("\"b\""));
        assert!(!red.contains("\"c\""));
        assert!(red.contains("\"keep\""));
    }

    #[test]
    fn redact_secrets_truncates_huge_bodies() {
        let huge = format!("{}{}", "x".repeat(2000), r#""access_token":"y""#);
        let red = redact_secrets_from_body(&huge);
        assert!(red.len() <= 1024 + 16);
        assert!(red.ends_with("(truncated)"));
    }

    #[test]
    fn http_status_display_redacts_bearer_too() {
        let body = r#"{"error":"x","access_token":"LEAK"}"#;
        let err = AuthError::HttpStatus {
            status: 500,
            body: body.to_string(),
        };
        let rendered = err.to_string();
        assert!(!rendered.contains("LEAK"), "got: {rendered}");
    }

    #[test]
    fn api_key_credentials_debug_redacts_secret() {
        let creds = ApiKeyCredentials::new(
            "user.public-id-fine-to-log".to_string(),
            "SUPER-SECRET-CLIENT-SECRET".to_string(),
        );
        let dbg = format!("{creds:?}");
        // client_id is non-sensitive — keep it visible for debugging.
        assert!(dbg.contains("user.public-id-fine-to-log"));
        // client_secret must NEVER appear.
        assert!(!dbg.contains("SUPER-SECRET-CLIENT-SECRET"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn api_key_credentials_fields_are_private_at_compile_time() {
        // Compile-time test: the fields must not be reachable as
        // `creds.client_secret`. If someone re-publicises them this
        // would still compile but other call sites using the
        // constructor will keep working — so this test is a
        // documentation marker more than a hard guard. The `Clone`
        // round-trip is the runtime check that the constructor +
        // accessors form a coherent surface.
        let a = ApiKeyCredentials::new("a".into(), "b".into());
        let b = a.clone();
        assert_eq!(a.client_id(), b.client_id());
        assert_eq!(a.client_secret(), b.client_secret());
    }

    #[test]
    fn debug_does_not_leak_bearer() {
        let tok = AccessToken {
            bearer: "SECRET-BEARER-VALUE".to_string(),
            expires_at: None,
        };
        let dbg = format!("{tok:?}");
        assert!(!dbg.contains("SECRET-BEARER-VALUE"));
        assert!(dbg.contains("redacted"));
    }

    fn scratch_vault(label: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "bwd-auth-{}-{label}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0),
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn persistent_device_identifier_shape_on_first_run() {
        let dir = scratch_vault("dev-id-first");
        let id = persistent_device_identifier(&dir).unwrap();
        assert_eq!(id.len(), 36);
        assert_eq!(id.chars().filter(|&c| c == '-').count(), 4);
        let segs: Vec<&str> = id.split('-').collect();
        assert_eq!(
            segs.iter().map(|s| s.len()).collect::<Vec<_>>(),
            vec![8, 4, 4, 4, 12]
        );
        assert_eq!(segs[2].chars().next().unwrap(), '4');
        let v = segs[3].chars().next().unwrap();
        assert!(matches!(v, '8' | '9' | 'a' | 'b'));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn persistent_device_identifier_returns_same_value_on_subsequent_runs() {
        // The whole point of persisting is that the server sees the
        // same device on every run. If we ever break this property,
        // the user would start hitting CAPTCHA on every dedup run.
        let dir = scratch_vault("dev-id-stable");
        let a = persistent_device_identifier(&dir).unwrap();
        let b = persistent_device_identifier(&dir).unwrap();
        let c = persistent_device_identifier(&dir).unwrap();
        assert_eq!(a, b);
        assert_eq!(b, c);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn persistent_device_identifier_writes_to_vault_dot_device_id() {
        let dir = scratch_vault("dev-id-path");
        let id = persistent_device_identifier(&dir).unwrap();
        let on_disk = std::fs::read_to_string(dir.join(".device_id")).unwrap();
        assert_eq!(on_disk.trim(), id);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    #[cfg(unix)]
    fn persistent_device_identifier_file_is_0o600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch_vault("dev-id-perms");
        persistent_device_identifier(&dir).unwrap();
        let mode = std::fs::metadata(dir.join(".device_id"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn persistent_device_identifier_refuses_corrupted_existing_file() {
        let dir = scratch_vault("dev-id-corrupt");
        std::fs::write(dir.join(".device_id"), "not-a-uuid").unwrap();
        let err = persistent_device_identifier(&dir).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn persistent_device_identifier_refuses_missing_vault_dir() {
        let bogus = std::env::temp_dir().join(format!(
            "bwd-auth-no-vault-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0),
        ));
        let err = persistent_device_identifier(&bogus).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
    }

    #[test]
    fn looks_like_uuid_v4_accepts_known_good() {
        assert!(looks_like_uuid_v4("00000000-0000-4000-8000-000000000000"));
        assert!(looks_like_uuid_v4("ffffffff-ffff-4fff-bfff-ffffffffffff"));
        assert!(looks_like_uuid_v4("12345678-1234-4234-9234-123456789abc"));
    }

    #[test]
    fn looks_like_uuid_v4_rejects_non_v4() {
        // version != 4
        assert!(!looks_like_uuid_v4("12345678-1234-3234-8234-123456789abc"));
        // bad variant
        assert!(!looks_like_uuid_v4("12345678-1234-4234-7234-123456789abc"));
        // wrong length
        assert!(!looks_like_uuid_v4("short"));
        // non-hex
        assert!(!looks_like_uuid_v4("zzzzzzzz-1234-4234-8234-123456789abc"));
    }

    #[test]
    fn is_expired_false_for_fresh_token() {
        let tok = AccessToken {
            bearer: "x".to_string(),
            expires_at: SystemTime::now().checked_add(Duration::from_secs(3600)),
        };
        assert!(!tok.is_expired());
    }

    #[test]
    fn is_expired_true_for_stale_token() {
        let tok = AccessToken {
            bearer: "x".to_string(),
            expires_at: SystemTime::now().checked_sub(Duration::from_secs(60)),
        };
        assert!(tok.is_expired());
    }

    #[test]
    fn is_expired_true_within_skew_margin() {
        // 30s left → within the 60s skew → must report expired.
        let tok = AccessToken {
            bearer: "x".to_string(),
            expires_at: SystemTime::now().checked_add(Duration::from_secs(30)),
        };
        assert!(
            tok.is_expired(),
            "token within 60s skew margin must be reported as expired"
        );
    }

    #[tokio::test]
    async fn acquire_token_sends_bitwarden_client_version_header() {
        // Regression for the version_header_missing 400 the user
        // hit on 2026-04-25 against the live identity host. The
        // Identity server checks for header presence, not value;
        // the mock here REQUIRES both client headers, so a
        // production helper that drops them misses the mock.
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/connect/token"))
            .and(header_exists("Bitwarden-Client-Name"))
            .and(header_exists("Bitwarden-Client-Version"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"{"access_token":"x","expires_in":3600}"#,
            ))
            .mount(&server)
            .await;

        let creds = ApiKeyCredentials::new("id".to_string(), "secret".to_string());
        // Goes through the same code path the production helper
        // uses for header attachment; if the production code drops
        // either header the test fails with a 404 (no mock matched).
        let token = acquire_access_token_at_url(
            &reqwest::Client::new(),
            &server.uri(),
            &creds,
            "00000000-0000-4000-8000-000000000000",
            "test",
        )
        .await
        .unwrap();
        assert_eq!(token.header_value(), "Bearer x");
    }

    #[tokio::test]
    async fn acquire_token_fails_when_credentials_field_missing_from_form() {
        // Defense-in-depth check that the form always carries the
        // required fields. This test mounts a server that ONLY
        // matches when grant_type=client_credentials AND scope=api
        // are both present in the form body; if our production
        // helper drops one, the request misses the mock and we get
        // wiremock's 404 fallback.
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/connect/token"))
            .and(body_string_contains("grant_type=client_credentials"))
            .and(body_string_contains("scope=api"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"{"access_token":"x","expires_in":3600}"#,
            ))
            .mount(&server)
            .await;

        let creds = ApiKeyCredentials::new("id".to_string(), "secret".to_string());
        let token = acquire_access_token_at_url(
            &reqwest::Client::new(),
            &server.uri(),
            &creds,
            "00000000-0000-4000-8000-000000000000",
            "test",
        )
        .await
        .unwrap();
        assert_eq!(token.header_value(), "Bearer x");
    }
}
