// Copyright 2026 Alexander Orlov <alexander.orlov@loxal.net>

//! Decrypt the `/api/sync` response into the Bitwarden JSON-export
//! shape that `bitwarden-dedup` (the JSON path) already consumes.
//!
//! Inputs:
//!   - The raw `/api/sync` JSON body (UTF-8 string)
//!   - The KDF parameters from `/accounts/prelogin`
//!   - The user's master password (from an interactive prompt; held
//!     in `secrecy::SecretString`)
//!
//! Output:
//!   - A `serde_json::Value` in the same shape `bw export --format json`
//!     emits — directly drop-in for `just dedup`.
//!
//! # Per-cipher key resolution
//!
//! Some ciphers carry their own `key` field (a wrapped per-cipher
//! 64-byte symmetric key). When present, every encrypted field on
//! that cipher is decrypted under the per-cipher key. When **None**
//! (older ciphers, every cipher on a fresh account during initial
//! provisioning), fields are encrypted directly under the account
//! user key. Audit pitfall #4 — must handle both shapes; this
//! module's `resolve_cipher_key` does so.
//!
//! # Encryption-v2 detection
//!
//! Personal accounts today emit EncString type 2 only. If we
//! encounter type 7 (XChaCha20-Poly1305 v2), the `crypto` layer
//! refuses at parse time. We propagate that failure with a
//! migration-aware message instead of aborting silently.

use serde::Deserialize;
use serde_json::Value;
use serde_json::json;

use super::crypto::{
    CryptoError, EncString, KdfParams, SymmetricKey, decrypt, decrypt_to_string, derive_master_key,
    stretch_master_key,
};
use secrecy::SecretString;

#[derive(Debug)]
pub enum CodecError {
    /// `/api/sync` body didn't deserialize into the expected shape.
    Shape(serde_json::Error),
    /// A cipher's encrypted field could not be decrypted (HMAC
    /// mismatch, wrong key, malformed EncString). Carries the
    /// cipher id and field name for diagnostic.
    Decrypt {
        cipher_id: String,
        field: &'static str,
        source: CryptoError,
    },
    /// Encryption-v2 (type 7) marker found. The user's account has
    /// migrated to XChaCha20-Poly1305; this tool doesn't yet support
    /// that envelope. Refuses cleanly per audit invariant L.0 #5.
    EncryptionV2 {
        cipher_id: String,
        field: &'static str,
    },
    /// Master key derivation or user-key unwrap failed (typically
    /// "wrong master password" — HMAC mismatch on profile.key).
    MasterUnwrap(CryptoError),
}

impl std::fmt::Display for CodecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CodecError::Shape(e) => write!(f, "/api/sync response shape error: {e}"),
            CodecError::Decrypt {
                cipher_id,
                field,
                source,
            } => write!(
                f,
                "decrypt failed on cipher {cipher_id} field `{field}`: {source}"
            ),
            CodecError::EncryptionV2 { cipher_id, field } => write!(
                f,
                "cipher {cipher_id} field `{field}` is EncString type 7 (encryption v2 / \
                 XChaCha20-Poly1305). This tool only supports v1 (type 2). Your account has \
                 migrated; upgrade to a v2-capable build before re-running. No file was written."
            ),
            CodecError::MasterUnwrap(source) => write!(
                f,
                "master key derivation or user-key unwrap failed: {source}. \
                 Most likely: wrong master password."
            ),
        }
    }
}

impl std::error::Error for CodecError {}

// -----------------------------------------------------------------
// /api/sync wire shape
// -----------------------------------------------------------------

#[derive(Deserialize)]
struct SyncResponse {
    profile: Profile,
    #[serde(default)]
    folders: Vec<Folder>,
    #[serde(default)]
    ciphers: Vec<Cipher>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Profile {
    /// Account email — used as KDF salt input. Required.
    email: Option<String>,
    /// Wrapped user key (EncString type 2).
    key: String,
    // KDF parameters are NOT on the profile in /api/sync — observed
    // 2026-04-25 against the live US production server; the audit's
    // L.2 recommendation to use `/accounts/prelogin` was correct.
    // The binary obtains kdf params from prelogin and passes them in.
    // privateKey, organizations, etc. are present here but unused.
}

#[derive(Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct Folder {
    /// Some folders (e.g. the implicit "no folder") may have null id.
    /// We pass through as-is.
    id: Option<String>,
    /// Encrypted folder name.
    name: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Cipher {
    id: String,
    organization_id: Option<String>,
    folder_id: Option<String>,
    /// 1 = login, 2 = secureNote, 3 = card, 4 = identity, 5 = sshKey
    #[serde(rename = "type")]
    cipher_type: i64,
    reprompt: Option<i64>,
    favorite: Option<bool>,
    /// Optional per-cipher key (EncString type 2 wrapping a 64-byte
    /// symmetric key). When None, fields are decrypted directly
    /// under the user key.
    #[serde(default)]
    key: Option<String>,

    name: Option<String>,
    notes: Option<String>,

    creation_date: Option<String>,
    revision_date: Option<String>,
    deleted_date: Option<String>,
    archived_date: Option<String>,
    #[serde(default)]
    collection_ids: Option<Vec<String>>,

    #[serde(default)]
    fields: Option<Vec<CipherField>>,
    #[serde(default)]
    password_history: Option<Vec<PasswordHistoryEntry>>,

    #[serde(default)]
    login: Option<Login>,
    #[serde(default)]
    secure_note: Option<SecureNote>,
    #[serde(default)]
    card: Option<Card>,
    #[serde(default)]
    identity: Option<Identity>,
    #[serde(default)]
    ssh_key: Option<SshKey>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CipherField {
    name: Option<String>,
    value: Option<String>,
    #[serde(rename = "type")]
    field_type: Option<i64>,
    linked_id: Option<i64>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PasswordHistoryEntry {
    password: Option<String>,
    last_used_date: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Login {
    username: Option<String>,
    password: Option<String>,
    totp: Option<String>,
    password_revision_date: Option<String>,
    #[serde(default)]
    uris: Option<Vec<LoginUri>>,
    #[serde(default)]
    fido2_credentials: Option<Vec<Fido2Credential>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LoginUri {
    uri: Option<String>,
    /// Match mode is unencrypted; pass through as-is.
    #[serde(rename = "match")]
    match_mode: Option<i64>,
}

/// FIDO2 credential — every field is encrypted *except* the
/// canonical-form indicator. We decrypt each individually.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Fido2Credential {
    credential_id: Option<String>,
    key_type: Option<String>,
    key_algorithm: Option<String>,
    key_curve: Option<String>,
    key_value: Option<String>,
    rp_id: Option<String>,
    rp_name: Option<String>,
    user_handle: Option<String>,
    user_name: Option<String>,
    user_display_name: Option<String>,
    counter: Option<String>,
    discoverable: Option<String>,
    creation_date: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SecureNote {
    /// Numeric type (always 0 today). NOT encrypted.
    #[serde(rename = "type")]
    note_type: Option<i64>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Card {
    cardholder_name: Option<String>,
    brand: Option<String>,
    number: Option<String>,
    exp_month: Option<String>,
    exp_year: Option<String>,
    code: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Identity {
    title: Option<String>,
    first_name: Option<String>,
    middle_name: Option<String>,
    last_name: Option<String>,
    address1: Option<String>,
    address2: Option<String>,
    address3: Option<String>,
    city: Option<String>,
    state: Option<String>,
    postal_code: Option<String>,
    country: Option<String>,
    company: Option<String>,
    email: Option<String>,
    phone: Option<String>,
    ssn: Option<String>,
    username: Option<String>,
    passport_number: Option<String>,
    license_number: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SshKey {
    private_key: Option<String>,
    public_key: Option<String>,
    key_fingerprint: Option<String>,
}

// -----------------------------------------------------------------
// Top-level entrypoint
// -----------------------------------------------------------------

/// Extract just the account email from a `/api/sync` response.
///
/// The binary needs the email *before* it can call
/// `/accounts/prelogin` to learn the KDF parameters. This is a
/// minimal early parse over the same body the full decrypt
/// pipeline will later re-parse — fine because parsing 22 MB of
/// already-in-memory JSON is cheap.
pub fn extract_account_email(sync_body: &str) -> Result<String, CodecError> {
    let sync: SyncResponse = serde_json::from_str(sync_body).map_err(CodecError::Shape)?;
    sync.profile.email.ok_or_else(|| {
        CodecError::Shape(serde::de::Error::custom(
            "profile.email missing from /api/sync response — cannot determine account",
        ))
    })
}

/// Decrypt a `/api/sync` response into the JSON-export shape.
///
/// `kdf` comes from `/accounts/prelogin` — Bitwarden does NOT
/// include KDF params on `/api/sync.profile` (verified 2026-04-25).
/// The audit's L.2 recommendation was correct.
///
/// Returns a `serde_json::Value` shaped like `bw export --format json`
/// — directly importable by `just dedup`.
pub fn decrypt_sync_to_export_shape(
    sync_body: &str,
    kdf: KdfParams,
    master_password: &SecretString,
) -> Result<Value, CodecError> {
    let sync: SyncResponse = serde_json::from_str(sync_body).map_err(CodecError::Shape)?;

    let email = sync.profile.email.as_deref().ok_or_else(|| {
        CodecError::Shape(serde::de::Error::custom(
            "profile.email missing from /api/sync response",
        ))
    })?;

    // Derive master key → stretched key → user key.
    let master_key =
        derive_master_key(master_password, email, kdf).map_err(CodecError::MasterUnwrap)?;
    let stretched = stretch_master_key(&master_key);
    let user_key = unwrap_user_key(&sync.profile.key, &stretched)?;

    // Decrypt folders.
    let mut export_folders = Vec::with_capacity(sync.folders.len());
    for folder in &sync.folders {
        let name = match folder.name.as_deref() {
            Some(s) => decrypt_field(s, &user_key, &folder.id.clone().unwrap_or_default(), "name")?,
            None => Value::Null,
        };
        export_folders.push(json!({
            "id": folder.id,
            "name": name,
        }));
    }

    // Decrypt ciphers.
    let mut export_items = Vec::with_capacity(sync.ciphers.len());
    for cipher in sync.ciphers {
        export_items.push(decrypt_cipher(cipher, &user_key)?);
    }

    Ok(json!({
        "encrypted": false,
        "folders": export_folders,
        "items": export_items,
    }))
}

/// Counts returned by [`filter_export_to_bw_export_items`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ExportItemFilterStats {
    pub kept: usize,
    pub trashed_omitted: usize,
    pub archived_kept: usize,
}

/// Mutate a decrypted `/api/sync` export so its `items` match
/// `bw export --format json` item-state semantics.
///
/// Official Bitwarden exports omit Trash (`deletedDate != null`) but
/// preserve Archive (`archivedDate != null`) so archive state can
/// round-trip through JSON import. Raw `/api/sync` includes Trash too,
/// so the direct REST backup applies this export filter before
/// handing the JSON to `just dedup`.
pub fn filter_export_to_bw_export_items(
    export: &mut Value,
    include_trash: bool,
) -> ExportItemFilterStats {
    let Some(items) = export.get_mut("items").and_then(Value::as_array_mut) else {
        return ExportItemFilterStats::default();
    };

    let mut stats = ExportItemFilterStats::default();
    let mut kept = Vec::with_capacity(items.len());

    for item in std::mem::take(items) {
        let trashed = item
            .get("deletedDate")
            .map(|value| !value.is_null())
            .unwrap_or(false);
        let archived = item
            .get("archivedDate")
            .map(|value| !value.is_null())
            .unwrap_or(false);

        if trashed && !include_trash {
            stats.trashed_omitted += 1;
            continue;
        }

        stats.kept += 1;
        if archived {
            stats.archived_kept += 1;
        }
        kept.push(item);
    }

    *items = kept;
    stats
}

/// Unwrap `profile.key` (EncString type 2 wrapping a 64-byte
/// `enc || mac` user-symmetric-key) using the stretched master key.
fn unwrap_user_key(
    profile_key_str: &str,
    stretched: &SymmetricKey,
) -> Result<SymmetricKey, CodecError> {
    let enc = EncString::parse(profile_key_str).map_err(|e| match e {
        CryptoError::EncString(_) if profile_key_str.starts_with("7.") => {
            CodecError::EncryptionV2 {
                cipher_id: "<account profile>".to_string(),
                field: "profile.key",
            }
        }
        other => CodecError::MasterUnwrap(other),
    })?;
    let mut bytes = decrypt(&enc, stretched).map_err(CodecError::MasterUnwrap)?;
    SymmetricKey::from_bytes_zeroizing(&mut bytes).map_err(CodecError::MasterUnwrap)
}

// -----------------------------------------------------------------
// Per-cipher decryption
// -----------------------------------------------------------------

/// Resolve the key to use for decrypting a cipher's encrypted fields.
///
/// - If `cipher.key` is `Some(EncString)`, decrypt it with the
///   user key to get the per-cipher `enc || mac` 64-byte key.
/// - If `cipher.key` is `None`, use the user key directly. (Common
///   on older ciphers; per the audit, must handle both shapes.)
fn resolve_cipher_key<'a>(
    cipher_id: &str,
    cipher_key_str: Option<&str>,
    user_key: &'a SymmetricKey,
    cipher_key_holder: &'a mut Option<SymmetricKey>,
) -> Result<&'a SymmetricKey, CodecError> {
    match cipher_key_str {
        None => Ok(user_key),
        Some(s) => {
            let enc = EncString::parse(s).map_err(|e| match e {
                CryptoError::EncString(_) if s.starts_with("7.") => CodecError::EncryptionV2 {
                    cipher_id: cipher_id.to_string(),
                    field: "key",
                },
                other => CodecError::Decrypt {
                    cipher_id: cipher_id.to_string(),
                    field: "key",
                    source: other,
                },
            })?;
            let mut bytes = decrypt(&enc, user_key).map_err(|source| CodecError::Decrypt {
                cipher_id: cipher_id.to_string(),
                field: "key",
                source,
            })?;
            let per_cipher = SymmetricKey::from_bytes_zeroizing(&mut bytes).map_err(|source| {
                CodecError::Decrypt {
                    cipher_id: cipher_id.to_string(),
                    field: "key",
                    source,
                }
            })?;
            *cipher_key_holder = Some(per_cipher);
            Ok(cipher_key_holder.as_ref().unwrap())
        }
    }
}

fn decrypt_cipher(cipher: Cipher, user_key: &SymmetricKey) -> Result<Value, CodecError> {
    let mut per_cipher_holder: Option<SymmetricKey> = None;
    let key = resolve_cipher_key(
        &cipher.id,
        cipher.key.as_deref(),
        user_key,
        &mut per_cipher_holder,
    )?;

    let name = optional_field_string(&cipher.id, "name", cipher.name.as_deref(), key)?;
    let notes = optional_field_string(&cipher.id, "notes", cipher.notes.as_deref(), key)?;

    let mut item = serde_json::Map::new();
    item.insert("id".into(), json!(cipher.id));
    item.insert("organizationId".into(), json!(cipher.organization_id));
    item.insert("folderId".into(), json!(cipher.folder_id));
    item.insert("type".into(), json!(cipher.cipher_type));
    item.insert("reprompt".into(), json!(cipher.reprompt.unwrap_or(0)));
    item.insert("favorite".into(), json!(cipher.favorite.unwrap_or(false)));
    item.insert("name".into(), name);
    item.insert("notes".into(), notes);
    item.insert("creationDate".into(), json!(cipher.creation_date));
    item.insert("revisionDate".into(), json!(cipher.revision_date));
    item.insert("deletedDate".into(), json!(cipher.deleted_date));
    item.insert("archivedDate".into(), json!(cipher.archived_date));
    item.insert("collectionIds".into(), json!(cipher.collection_ids));

    if let Some(fields) = cipher.fields {
        let mut out_fields = Vec::with_capacity(fields.len());
        for (i, f) in fields.into_iter().enumerate() {
            out_fields.push(json!({
                "name": optional_field_string(
                    &cipher.id,
                    "fields[].name",
                    f.name.as_deref(),
                    key,
                )?,
                "value": optional_field_string(
                    &cipher.id,
                    "fields[].value",
                    f.value.as_deref(),
                    key,
                )?,
                "type": f.field_type.unwrap_or(0),
                "linkedId": f.linked_id,
                "_field_index": i, // suppress `i` unused warnings
            }));
            // Strip the helper-only key from the emitted JSON.
            if let Some(obj) = out_fields.last_mut().and_then(Value::as_object_mut) {
                obj.remove("_field_index");
            }
        }
        item.insert("fields".into(), Value::Array(out_fields));
    } else {
        item.insert("fields".into(), Value::Null);
    }

    if let Some(history) = cipher.password_history {
        let mut out_history = Vec::with_capacity(history.len());
        for h in history {
            out_history.push(json!({
                "password": optional_field_string(
                    &cipher.id,
                    "passwordHistory[].password",
                    h.password.as_deref(),
                    key,
                )?,
                "lastUsedDate": h.last_used_date,
            }));
        }
        item.insert("passwordHistory".into(), Value::Array(out_history));
    } else {
        item.insert("passwordHistory".into(), Value::Null);
    }

    // Cipher-type-specific blocks. The export shape includes the
    // sub-object only for the matching type.
    match cipher.cipher_type {
        1 => {
            if let Some(login) = cipher.login {
                item.insert("login".into(), decrypt_login(&cipher.id, login, key)?);
            } else {
                item.insert("login".into(), Value::Null);
            }
        }
        2 => {
            if let Some(sn) = cipher.secure_note {
                item.insert(
                    "secureNote".into(),
                    json!({"type": sn.note_type.unwrap_or(0)}),
                );
            } else {
                item.insert("secureNote".into(), json!({"type": 0}));
            }
        }
        3 => {
            if let Some(c) = cipher.card {
                item.insert("card".into(), decrypt_card(&cipher.id, c, key)?);
            } else {
                item.insert("card".into(), Value::Null);
            }
        }
        4 => {
            if let Some(i) = cipher.identity {
                item.insert("identity".into(), decrypt_identity(&cipher.id, i, key)?);
            } else {
                item.insert("identity".into(), Value::Null);
            }
        }
        5 => {
            if let Some(s) = cipher.ssh_key {
                item.insert("sshKey".into(), decrypt_ssh_key(&cipher.id, s, key)?);
            } else {
                item.insert("sshKey".into(), Value::Null);
            }
        }
        _ => {}
    }

    Ok(Value::Object(item))
}

fn decrypt_login(cipher_id: &str, login: Login, key: &SymmetricKey) -> Result<Value, CodecError> {
    let username =
        optional_field_string(cipher_id, "login.username", login.username.as_deref(), key)?;
    let password =
        optional_field_string(cipher_id, "login.password", login.password.as_deref(), key)?;
    let totp = optional_field_string(cipher_id, "login.totp", login.totp.as_deref(), key)?;

    let uris = match login.uris {
        Some(arr) => {
            let mut out = Vec::with_capacity(arr.len());
            for u in arr {
                out.push(json!({
                    "uri": optional_field_string(
                        cipher_id,
                        "login.uris[].uri",
                        u.uri.as_deref(),
                        key,
                    )?,
                    "match": u.match_mode,
                }));
            }
            Value::Array(out)
        }
        None => Value::Null,
    };

    let fido2_credentials = match login.fido2_credentials {
        Some(arr) => {
            let mut out = Vec::with_capacity(arr.len());
            for c in arr {
                out.push(decrypt_fido2(cipher_id, c, key)?);
            }
            Value::Array(out)
        }
        None => Value::Null,
    };

    Ok(json!({
        "username": username,
        "password": password,
        "totp": totp,
        "passwordRevisionDate": login.password_revision_date,
        "uris": uris,
        "fido2Credentials": fido2_credentials,
    }))
}

fn decrypt_fido2(
    cipher_id: &str,
    cred: Fido2Credential,
    key: &SymmetricKey,
) -> Result<Value, CodecError> {
    Ok(json!({
        "credentialId": optional_field_string(cipher_id, "fido2.credentialId", cred.credential_id.as_deref(), key)?,
        "keyType": optional_field_string(cipher_id, "fido2.keyType", cred.key_type.as_deref(), key)?,
        "keyAlgorithm": optional_field_string(cipher_id, "fido2.keyAlgorithm", cred.key_algorithm.as_deref(), key)?,
        "keyCurve": optional_field_string(cipher_id, "fido2.keyCurve", cred.key_curve.as_deref(), key)?,
        "keyValue": optional_field_string(cipher_id, "fido2.keyValue", cred.key_value.as_deref(), key)?,
        "rpId": optional_field_string(cipher_id, "fido2.rpId", cred.rp_id.as_deref(), key)?,
        "rpName": optional_field_string(cipher_id, "fido2.rpName", cred.rp_name.as_deref(), key)?,
        "userHandle": optional_field_string(cipher_id, "fido2.userHandle", cred.user_handle.as_deref(), key)?,
        "userName": optional_field_string(cipher_id, "fido2.userName", cred.user_name.as_deref(), key)?,
        "userDisplayName": optional_field_string(cipher_id, "fido2.userDisplayName", cred.user_display_name.as_deref(), key)?,
        "counter": optional_field_string(cipher_id, "fido2.counter", cred.counter.as_deref(), key)?,
        "discoverable": optional_field_string(cipher_id, "fido2.discoverable", cred.discoverable.as_deref(), key)?,
        "creationDate": cred.creation_date,
    }))
}

fn decrypt_card(cipher_id: &str, card: Card, key: &SymmetricKey) -> Result<Value, CodecError> {
    Ok(json!({
        "cardholderName": optional_field_string(cipher_id, "card.cardholderName", card.cardholder_name.as_deref(), key)?,
        "brand": optional_field_string(cipher_id, "card.brand", card.brand.as_deref(), key)?,
        "number": optional_field_string(cipher_id, "card.number", card.number.as_deref(), key)?,
        "expMonth": optional_field_string(cipher_id, "card.expMonth", card.exp_month.as_deref(), key)?,
        "expYear": optional_field_string(cipher_id, "card.expYear", card.exp_year.as_deref(), key)?,
        "code": optional_field_string(cipher_id, "card.code", card.code.as_deref(), key)?,
    }))
}

fn decrypt_identity(
    cipher_id: &str,
    id: Identity,
    key: &SymmetricKey,
) -> Result<Value, CodecError> {
    Ok(json!({
        "title": optional_field_string(cipher_id, "identity.title", id.title.as_deref(), key)?,
        "firstName": optional_field_string(cipher_id, "identity.firstName", id.first_name.as_deref(), key)?,
        "middleName": optional_field_string(cipher_id, "identity.middleName", id.middle_name.as_deref(), key)?,
        "lastName": optional_field_string(cipher_id, "identity.lastName", id.last_name.as_deref(), key)?,
        "address1": optional_field_string(cipher_id, "identity.address1", id.address1.as_deref(), key)?,
        "address2": optional_field_string(cipher_id, "identity.address2", id.address2.as_deref(), key)?,
        "address3": optional_field_string(cipher_id, "identity.address3", id.address3.as_deref(), key)?,
        "city": optional_field_string(cipher_id, "identity.city", id.city.as_deref(), key)?,
        "state": optional_field_string(cipher_id, "identity.state", id.state.as_deref(), key)?,
        "postalCode": optional_field_string(cipher_id, "identity.postalCode", id.postal_code.as_deref(), key)?,
        "country": optional_field_string(cipher_id, "identity.country", id.country.as_deref(), key)?,
        "company": optional_field_string(cipher_id, "identity.company", id.company.as_deref(), key)?,
        "email": optional_field_string(cipher_id, "identity.email", id.email.as_deref(), key)?,
        "phone": optional_field_string(cipher_id, "identity.phone", id.phone.as_deref(), key)?,
        "ssn": optional_field_string(cipher_id, "identity.ssn", id.ssn.as_deref(), key)?,
        "username": optional_field_string(cipher_id, "identity.username", id.username.as_deref(), key)?,
        "passportNumber": optional_field_string(cipher_id, "identity.passportNumber", id.passport_number.as_deref(), key)?,
        "licenseNumber": optional_field_string(cipher_id, "identity.licenseNumber", id.license_number.as_deref(), key)?,
    }))
}

fn decrypt_ssh_key(cipher_id: &str, s: SshKey, key: &SymmetricKey) -> Result<Value, CodecError> {
    Ok(json!({
        "privateKey": optional_field_string(cipher_id, "sshKey.privateKey", s.private_key.as_deref(), key)?,
        "publicKey": optional_field_string(cipher_id, "sshKey.publicKey", s.public_key.as_deref(), key)?,
        "keyFingerprint": optional_field_string(cipher_id, "sshKey.keyFingerprint", s.key_fingerprint.as_deref(), key)?,
    }))
}

// -----------------------------------------------------------------
// Field-level decrypt helpers
// -----------------------------------------------------------------

fn optional_field_string(
    cipher_id: &str,
    field_name: &'static str,
    enc_str: Option<&str>,
    key: &SymmetricKey,
) -> Result<Value, CodecError> {
    match enc_str {
        None => Ok(Value::Null),
        Some("") => Ok(Value::String(String::new())),
        Some(s) => Ok(Value::String(
            decrypt_field(s, key, cipher_id, field_name)?
                .as_str()
                .unwrap_or("")
                .to_string(),
        )),
    }
}

fn decrypt_field(
    enc_str: &str,
    key: &SymmetricKey,
    cipher_id: &str,
    field: &'static str,
) -> Result<Value, CodecError> {
    let enc = EncString::parse(enc_str).map_err(|e| match e {
        CryptoError::EncString(_) if enc_str.starts_with("7.") => CodecError::EncryptionV2 {
            cipher_id: cipher_id.to_string(),
            field,
        },
        other => CodecError::Decrypt {
            cipher_id: cipher_id.to_string(),
            field,
            source: other,
        },
    })?;
    let s = decrypt_to_string(&enc, key).map_err(|source| CodecError::Decrypt {
        cipher_id: cipher_id.to_string(),
        field,
        source,
    })?;
    Ok(Value::String(s))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::num::NonZeroU32;

    /// End-to-end test: PBKDF2 master_key (audit vector) →
    /// stretched key → encrypt some fixture data → decrypt back
    /// through `decrypt_sync_to_export_shape`. Uses Argon2id as
    /// the KDF since the public derive_master_key path enforces
    /// a 600k floor on PBKDF2 that the audit vector predates.
    #[test]
    fn end_to_end_pipeline_through_argon2_account() {
        // Build an `/api/sync` body where `profile.key` is a known
        // user-key wrapped under the stretched master key for the
        // audit's argon2 vector.
        let pw = SecretString::new("67t9b5g67$%Dh89n".to_string().into());
        let kdf = KdfParams::Argon2id {
            iterations: NonZeroU32::new(4).unwrap(),
            memory_mib: NonZeroU32::new(32).unwrap(),
            parallelism: NonZeroU32::new(2).unwrap(),
        };
        let mk = derive_master_key(&pw, "test_key", kdf).unwrap();
        let stretched = stretch_master_key(&mk);

        // Manufacture a known 64-byte user key.
        let mut uk_bytes = vec![0xa5u8; 64];
        let user_key = SymmetricKey::from_bytes_zeroizing(&mut uk_bytes).unwrap();

        // Encrypt the user key under the stretched master key so
        // the codec can unwrap it.
        let user_key_str = encrypt_for_test(
            &stretched,
            b"hardcoded-test-iv",
            &[
                0xa5u8, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5,
                0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5,
                0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5,
                0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5,
                0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5,
            ],
        );

        // Encrypt one cipher's `name` field under the user key.
        let cipher_name_str = encrypt_for_test(&user_key, b"hardcoded-test-iv", b"My Login");

        let sync_body = format!(
            r#"{{
                "profile": {{
                    "email": "test_key",
                    "key": "{}"
                }},
                "folders": [],
                "ciphers": [{{
                    "id": "cipher-1",
                    "type": 1,
                    "name": "{}",
                    "archivedDate": "2026-04-27T02:00:00Z",
                    "login": {{"username": null, "password": null, "uris": null}}
                }}]
            }}"#,
            user_key_str, cipher_name_str
        );

        // Caller obtains kdf from /accounts/prelogin in production;
        // here we hand it in directly.
        let result = decrypt_sync_to_export_shape(&sync_body, kdf, &pw).unwrap();
        let items = result["items"].as_array().unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["name"], json!("My Login"));
        assert_eq!(items[0]["archivedDate"], json!("2026-04-27T02:00:00Z"));
        // Type 1 → login subobject present.
        assert!(items[0]["login"].is_object());
        // Top-level shape matches a Bitwarden export.
        assert_eq!(result["encrypted"], json!(false));
        assert!(result["folders"].is_array());
    }

    #[test]
    fn export_item_filter_matches_bw_export_semantics_by_default() {
        let mut export = json!({
            "encrypted": false,
            "folders": [],
            "items": [
                {"id": "active", "deletedDate": null, "archivedDate": null},
                {"id": "trashed", "deletedDate": "2026-04-27T01:00:00Z", "archivedDate": null},
                {"id": "archived", "deletedDate": null, "archivedDate": "2026-04-27T02:00:00Z"},
                {"id": "both", "deletedDate": "2026-04-27T03:00:00Z", "archivedDate": "2026-04-27T04:00:00Z"}
            ]
        });

        let stats = filter_export_to_bw_export_items(&mut export, false);

        assert_eq!(
            stats,
            ExportItemFilterStats {
                kept: 2,
                trashed_omitted: 2,
                archived_kept: 1,
            }
        );
        assert_eq!(export["items"].as_array().unwrap().len(), 2);
        assert_eq!(export["items"][0]["id"], "active");
        assert_eq!(export["items"][1]["id"], "archived");
    }

    #[test]
    fn export_item_filter_can_include_trash_for_forensics() {
        let mut export = json!({
            "items": [
                {"id": "active", "deletedDate": null, "archivedDate": null},
                {"id": "trashed", "deletedDate": "2026-04-27T01:00:00Z", "archivedDate": null},
                {"id": "archived", "deletedDate": null, "archivedDate": "2026-04-27T02:00:00Z"}
            ]
        });

        let stats = filter_export_to_bw_export_items(&mut export, true);

        assert_eq!(
            stats,
            ExportItemFilterStats {
                kept: 3,
                trashed_omitted: 0,
                archived_kept: 1,
            }
        );
        assert_eq!(export["items"].as_array().unwrap().len(), 3);
    }

    /// Test-only encrypt helper, mirrored from
    /// tests/crypto_vectors.rs (we can't share it cleanly across
    /// integration tests and unit tests).
    fn encrypt_for_test(key: &SymmetricKey, iv_seed: &[u8], plaintext: &[u8]) -> String {
        use aes::Aes256;
        use aes::cipher::{BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};
        use base64::Engine;
        use base64::engine::general_purpose::STANDARD as B64;
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        type HmacSha256 = Hmac<Sha256>;

        // Pad/truncate iv_seed to 16 bytes deterministically.
        let mut iv = [0u8; 16];
        for (i, b) in iv_seed.iter().take(16).enumerate() {
            iv[i] = *b;
        }

        let cipher = cbc::Encryptor::<Aes256>::new(key.enc().into(), &iv.into());
        let pt_len = plaintext.len();
        let mut buf = vec![0u8; pt_len + 16];
        buf[..pt_len].copy_from_slice(plaintext);
        let ct_len = cipher
            .encrypt_padded_mut::<Pkcs7>(&mut buf, pt_len)
            .unwrap()
            .len();
        buf.truncate(ct_len);

        let mut hmac = HmacSha256::new_from_slice(key.mac()).unwrap();
        hmac.update(&iv);
        hmac.update(&buf);
        let mac = hmac.finalize().into_bytes();

        format!(
            "2.{}|{}|{}",
            B64.encode(iv),
            B64.encode(&buf),
            B64.encode(mac.as_slice())
        )
    }
}
