// Copyright 2026 Alexander Orlov <alexander.orlov@loxal.net>

//! Merge an Apple Passwords CSV export into a Bitwarden JSON vault.
//!
//! Apple's Passwords app exports to a 6-column CSV:
//! `Title, URL, Username, Password, Notes, OTPAuth`.
//!
//! This module:
//!
//! 1. Parses the CSV (RFC 4180-ish, quoted fields with embedded commas and
//!    newlines, `""` = literal quote).
//! 2. Maps each row to a synthetic Bitwarden item:
//!    - rows with a URL, username, password, or OTPAuth → `type: 1` (login)
//!    - rows with only Title + Notes → `type: 2` (secure note)
//! 3. Appends the synthetic items to the Bitwarden export's `items` array.
//! 4. Runs the standard dedup pipeline ([`crate::dedup_export`]) so any
//!    overlap with existing Bitwarden items collapses cleanly:
//!    URIs union, notes merge, TOTP keeps newest, passkeys/fields/
//!    passwordHistory are preserved on whichever item has them.
//!
//! ## What Apple's CSV export does *not* contain
//!
//! These fields do not appear in the CSV at all, so they cannot be merged
//! from it — they stay in iCloud Keychain:
//!
//! - **Passkeys / FIDO2** credentials — not exported; no CSV column exists.
//! - **Wi-Fi passwords** — stored in a separate vault section, not exported.
//! - **Sign-in-with-Apple** tokens — same.
//! - **Deleted (recently-removed) items** — the CSV is an active-only
//!   snapshot. See the README for the dedicated note on this.
//!
//! Any passkeys / FIDO2 credentials that already live on the **Bitwarden**
//! side are preserved unchanged: they're in the dedup key, so the CSV
//! merge can never overwrite them.

use std::collections::HashMap;

use serde_json::{Value, json};

use crate::pipeline::{DedupConfig, DedupStats, dedup_export_with_config};
use crate::time_util::iso8601_from_epoch_secs;

/// Summary of an iCloud-CSV merge run.
#[derive(Debug, Clone)]
pub struct MergeStats {
    /// Data rows in the CSV (excludes header).
    pub csv_rows: usize,
    /// CSV rows mapped to synthetic Bitwarden items and appended.
    pub csv_items_appended: usize,
    /// Rows discarded as empty.
    pub csv_rows_skipped: usize,
    /// Dedup stats on the combined (Bitwarden + CSV) item set.
    pub dedup_stats: DedupStats,
}

/// Parse an Apple Passwords CSV, map each row to a Bitwarden item, append
/// the items to the existing `items` array, and run the dedup pipeline
/// with the default [`DedupConfig`].
///
/// The combined vault is written back into `export` in place; the caller
/// serializes the result.
pub fn merge_icloud_csv_into_export(
    export: &mut Value,
    csv_text: &str,
) -> Result<MergeStats, String> {
    merge_icloud_csv_into_export_with_config(export, csv_text, &DedupConfig::default())
}

/// Same as [`merge_icloud_csv_into_export`] but with an explicit
/// [`DedupConfig`]. Use this entry point to thread CLI flags like
/// `--split-divergent-totps` into the shared pipeline.
pub fn merge_icloud_csv_into_export_with_config(
    export: &mut Value,
    csv_text: &str,
    config: &DedupConfig,
) -> Result<MergeStats, String> {
    let rows = parse_apple_passwords_csv(csv_text)?;
    let csv_rows_total = rows.len();

    let epoch_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let ts = iso8601_from_epoch_secs(epoch_secs);

    let mut new_items: Vec<Value> = Vec::new();
    let mut skipped = 0usize;
    for (idx, row) in rows.iter().enumerate() {
        if row.is_effectively_empty() {
            skipped += 1;
            continue;
        }
        new_items.push(row_to_bitwarden_item(row, idx as u64, epoch_secs, &ts));
    }

    // Append to existing items. Fail fast if the export has an `items`
    // field that is NOT an array — silently overwriting it with a fresh
    // array would discard whatever the file actually held (a damaged
    // export, a wrong file entirely) and produce an output that looks
    // valid but isn't a faithful transformation of the input.
    let Some(obj) = export.as_object_mut() else {
        return Err("Bitwarden export is not a top-level JSON object".into());
    };
    match obj.get_mut("items") {
        Some(Value::Array(items)) => {
            items.extend(new_items.iter().cloned());
        }
        Some(other) => {
            return Err(format!(
                "Bitwarden export `items` field is not an array (found {}). \
                 Refusing to overwrite it — is this the right file?",
                describe_value(other)
            ));
        }
        None => {
            // Allow bootstrap of an empty export that only carries
            // `{folders: [...]}` or similar.
            obj.insert("items".to_string(), Value::Array(new_items.clone()));
        }
    }

    let csv_items_appended = new_items.len();

    // Run dedup over the combined set — overlap with existing Bitwarden
    // items collapses, new items pass through untouched.
    let dedup_stats = dedup_export_with_config(export, config);

    Ok(MergeStats {
        csv_rows: csv_rows_total,
        csv_items_appended,
        csv_rows_skipped: skipped,
        dedup_stats,
    })
}

// --- CSV row → Bitwarden item -------------------------------------------

#[derive(Debug, Clone, Default)]
pub(crate) struct AppleRow {
    pub title: String,
    pub url: String,
    pub username: String,
    pub password: String,
    pub notes: String,
    pub otpauth: String,
}

impl AppleRow {
    fn is_effectively_empty(&self) -> bool {
        self.title.trim().is_empty()
            && self.url.trim().is_empty()
            && self.username.trim().is_empty()
            && self.password.trim().is_empty()
            && self.notes.trim().is_empty()
            && self.otpauth.trim().is_empty()
    }

    fn looks_like_login(&self) -> bool {
        !self.url.trim().is_empty()
            || !self.username.trim().is_empty()
            || !self.password.trim().is_empty()
            || !self.otpauth.trim().is_empty()
    }
}

fn row_to_bitwarden_item(row: &AppleRow, seq: u64, epoch_secs: u64, ts: &str) -> Value {
    // Generated ids prefixed with `apple-csv-` so they're easy to grep in the
    // audit file. Bitwarden regenerates all ids on import; the shape doesn't
    // matter beyond uniqueness during the dedup pass.
    let id = format!("apple-csv-{epoch_secs:010}-{seq:06}");

    let name = if row.title.trim().is_empty() {
        // Fall back to URL or username so the item has *some* visible label.
        if !row.url.trim().is_empty() {
            row.url.trim().to_string()
        } else if !row.username.trim().is_empty() {
            row.username.trim().to_string()
        } else {
            "(unnamed)".to_string()
        }
    } else {
        row.title.clone()
    };

    let notes = if row.notes.trim().is_empty() {
        Value::Null
    } else {
        Value::String(row.notes.clone())
    };

    let mut item = json!({
        "id": id,
        "organizationId": null,
        "folderId": null,
        "reprompt": 0,
        "name": name,
        "notes": notes,
        "favorite": false,
        "creationDate": ts,
        "revisionDate": ts,
        "deletedDate": null,
        "collectionIds": null,
    });

    if row.looks_like_login() {
        item["type"] = json!(1);
        let mut uris: Vec<Value> = Vec::new();
        let url = row.url.trim();
        if !url.is_empty() {
            uris.push(json!({ "match": null, "uri": url }));
        }
        item["login"] = json!({
            "fido2Credentials": [],
            "uris": uris,
            "username": empty_to_null(&row.username),
            "password": empty_to_null(&row.password),
            "totp": empty_to_null(&row.otpauth),
        });
    } else {
        // Notes-only → secure note.
        item["type"] = json!(2);
        item["secureNote"] = json!({ "type": 0 });
    }

    item
}

fn empty_to_null(s: &str) -> Value {
    if s.is_empty() {
        Value::Null
    } else {
        Value::String(s.to_string())
    }
}

fn describe_value(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

// --- CSV parser (RFC 4180-ish) ------------------------------------------

/// The six header names Apple's Passwords app emits on every CSV export
/// we've seen (`Title`, `URL`, `Username`, `Password`, `Notes`, `OTPAuth`).
/// Matched case-insensitively after trim, so minor capitalization drift
/// in a future Apple release still parses.
const APPLE_REQUIRED_HEADERS: &[&str] =
    &["title", "url", "username", "password", "notes", "otpauth"];

/// Parse an Apple Passwords CSV. Handles double-quoted fields, escaped
/// quotes (`""` → `"`), and embedded newlines inside quoted fields.
///
/// **Fail-fast validation** (the tool's output feeds straight into a
/// purge-and-reimport flow, so silent best-effort parsing of a
/// wrong-shaped file is unsafe):
///
/// - The CSV must have at least a header row.
/// - Every one of [`APPLE_REQUIRED_HEADERS`] must be present. Extra
///   columns beyond those six are allowed (forward-compat for future
///   Apple additions) but missing any required one is a hard error —
///   that is how we reject non-Apple CSVs pointed at this tool by
///   mistake.
/// - The CSV must not end with an unterminated quoted field. That is a
///   syntax error no well-formed Apple export would produce.
pub(crate) fn parse_apple_passwords_csv(text: &str) -> Result<Vec<AppleRow>, String> {
    let mut rows = raw_parse_csv(text)?;
    if rows.is_empty() {
        return Err(
            "iCloud CSV is empty — expected an Apple Passwords header row plus data."
                .to_string(),
        );
    }
    let header = rows.remove(0);
    let col_index: HashMap<String, usize> = header
        .iter()
        .enumerate()
        .map(|(i, h)| (h.trim().to_ascii_lowercase(), i))
        .collect();

    let mut missing: Vec<&str> = Vec::new();
    for want in APPLE_REQUIRED_HEADERS {
        if !col_index.contains_key(*want) {
            missing.push(*want);
        }
    }
    if !missing.is_empty() {
        return Err(format!(
            "iCloud CSV header does not look like an Apple Passwords export — \
             missing required column(s): {}. Found: {:?}. Expected (case-insensitive): {:?}.",
            missing.join(", "),
            header,
            APPLE_REQUIRED_HEADERS,
        ));
    }

    // Apple header names, case-insensitive. `pick` is total here because
    // every required column was confirmed above.
    let pick = |row: &[String], key: &str| -> String {
        col_index
            .get(key)
            .and_then(|&i| row.get(i))
            .cloned()
            .unwrap_or_default()
    };

    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        out.push(AppleRow {
            title: pick(&r, "title"),
            url: pick(&r, "url"),
            username: pick(&r, "username"),
            password: pick(&r, "password"),
            notes: pick(&r, "notes"),
            otpauth: pick(&r, "otpauth"),
        });
    }
    Ok(out)
}

fn raw_parse_csv(text: &str) -> Result<Vec<Vec<String>>, String> {
    let mut rows: Vec<Vec<String>> = Vec::new();
    let mut field = String::new();
    let mut row: Vec<String> = Vec::new();
    let mut in_quotes = false;
    let bytes: Vec<char> = text.chars().collect();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if in_quotes {
            if c == '"' {
                if i + 1 < bytes.len() && bytes[i + 1] == '"' {
                    field.push('"');
                    i += 2;
                    continue;
                }
                in_quotes = false;
            } else {
                field.push(c);
            }
        } else {
            match c {
                '"' => in_quotes = true,
                ',' => {
                    row.push(std::mem::take(&mut field));
                }
                '\r' => {
                    // Consume a following \n for \r\n terminators.
                    if i + 1 < bytes.len() && bytes[i + 1] == '\n' {
                        i += 1;
                    }
                    row.push(std::mem::take(&mut field));
                    rows.push(std::mem::take(&mut row));
                }
                '\n' => {
                    row.push(std::mem::take(&mut field));
                    rows.push(std::mem::take(&mut row));
                }
                _ => field.push(c),
            }
        }
        i += 1;
    }
    // If the file ended mid-quote the CSV is malformed — refuse it
    // rather than silently accept a field that was never closed.
    if in_quotes {
        return Err(
            "iCloud CSV ends inside a quoted field — malformed export (unterminated quote).".to_string(),
        );
    }
    // Flush any unterminated final line.
    if !field.is_empty() || !row.is_empty() {
        row.push(field);
        rows.push(row);
    }
    Ok(rows)
}

// --- Tests --------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_csv() {
        let csv = "Title,URL,Username,Password,Notes,OTPAuth\n\
                   GitHub,https://github.com,alex,pw,some notes,\n\
                   Gmail,https://gmail.com,alex@example.com,pw2,,otpauth://totp/G?secret=X\n";
        let rows = parse_apple_passwords_csv(csv).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].title, "GitHub");
        assert_eq!(rows[0].password, "pw");
        assert_eq!(rows[0].notes, "some notes");
        assert_eq!(rows[1].otpauth, "otpauth://totp/G?secret=X");
    }

    #[test]
    fn parse_quoted_fields_with_embedded_commas() {
        let csv = "Title,URL,Username,Password,Notes,OTPAuth\n\
                   \"Acme, Inc.\",https://acme.test,,pw,\"note, comma, included\",\n";
        let rows = parse_apple_passwords_csv(csv).unwrap();
        assert_eq!(rows[0].title, "Acme, Inc.");
        assert_eq!(rows[0].notes, "note, comma, included");
    }

    #[test]
    fn parse_escaped_quotes() {
        let csv = "Title,URL,Username,Password,Notes,OTPAuth\n\
                   X,,,,\"she said \"\"hi\"\" loudly\",\n";
        let rows = parse_apple_passwords_csv(csv).unwrap();
        assert_eq!(rows[0].notes, "she said \"hi\" loudly");
    }

    #[test]
    fn parse_embedded_newlines_in_notes() {
        let csv = "Title,URL,Username,Password,Notes,OTPAuth\n\
                   X,,,,\"line1\nline2\nline3\",\n";
        let rows = parse_apple_passwords_csv(csv).unwrap();
        assert_eq!(rows[0].notes, "line1\nline2\nline3");
    }

    #[test]
    fn parse_rejects_non_apple_header() {
        // A non-Apple CSV (e.g. someone points the tool at a 1Password
        // export or a wrong file entirely) must fail loud rather than
        // silently return empty synthetic items.
        let csv = "Name,Website,Login,Secret\n\
                   GitHub,https://github.com,alex,pw\n";
        let err = parse_apple_passwords_csv(csv).unwrap_err();
        assert!(
            err.contains("missing required column"),
            "error must name the missing columns; got {err:?}"
        );
    }

    #[test]
    fn parse_rejects_header_missing_single_required_column() {
        // Even a single missing column (e.g. no OTPAuth) is a hard fail —
        // the tool's contract is "six Apple columns", not "some subset".
        let csv = "Title,URL,Username,Password,Notes\n\
                   GitHub,https://github.com,alex,pw,a note\n";
        let err = parse_apple_passwords_csv(csv).unwrap_err();
        assert!(err.contains("otpauth"), "error must name the missing column; got {err:?}");
    }

    #[test]
    fn parse_accepts_extra_unknown_columns() {
        // Forward compat: Apple may add columns in a future release. Extra
        // unknown columns beyond the six required ones are accepted.
        let csv = "Title,URL,Username,Password,Notes,OTPAuth,FutureField\n\
                   X,https://x.test,u,p,,,ignore-me\n";
        let rows = parse_apple_passwords_csv(csv).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].url, "https://x.test");
    }

    #[test]
    fn parse_rejects_unterminated_quote() {
        // A truncated CSV that leaves a quote open is almost certainly
        // corrupted — refuse rather than silently flushing the field.
        let csv = "Title,URL,Username,Password,Notes,OTPAuth\n\
                   GitHub,,alex,pw,\"unterminated note without closing quote,\n";
        let err = parse_apple_passwords_csv(csv).unwrap_err();
        assert!(
            err.contains("quote") || err.contains("malformed"),
            "error must mention malformed quoting; got {err:?}"
        );
    }

    #[test]
    fn parse_rejects_empty_file() {
        let err = parse_apple_passwords_csv("").unwrap_err();
        assert!(
            err.to_lowercase().contains("empty"),
            "error must mention empty CSV; got {err:?}"
        );
    }

    #[test]
    fn parse_crlf_line_endings() {
        let csv = "Title,URL,Username,Password,Notes,OTPAuth\r\nX,,,p,,\r\n";
        let rows = parse_apple_passwords_csv(csv).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].password, "p");
    }

    #[test]
    fn row_mapping_login_has_login_block() {
        let row = AppleRow {
            title: "GitHub".into(),
            url: "https://github.com".into(),
            username: "alex".into(),
            password: "pw".into(),
            notes: "note".into(),
            otpauth: "otpauth://totp/X?secret=Y".into(),
        };
        let item = row_to_bitwarden_item(&row, 0, 1000, "2026-04-23T00:00:00Z");
        assert_eq!(item["type"], 1);
        assert_eq!(item["name"], "GitHub");
        assert_eq!(item["login"]["username"], "alex");
        assert_eq!(item["login"]["password"], "pw");
        assert_eq!(item["login"]["totp"], "otpauth://totp/X?secret=Y");
        assert_eq!(item["login"]["uris"][0]["uri"], "https://github.com");
        assert_eq!(item["notes"], "note");
    }

    #[test]
    fn row_mapping_notes_only_becomes_secure_note() {
        let row = AppleRow {
            title: "Recovery codes".into(),
            notes: "some secret notes".into(),
            ..Default::default()
        };
        let item = row_to_bitwarden_item(&row, 0, 1000, "2026-04-23T00:00:00Z");
        assert_eq!(item["type"], 2);
        assert_eq!(item["secureNote"]["type"], 0);
        assert_eq!(item["notes"], "some secret notes");
        assert!(item.get("login").is_none());
    }

    #[test]
    fn row_mapping_empty_fields_become_null() {
        let row = AppleRow {
            title: "X".into(),
            url: "https://x.test".into(),
            ..Default::default()
        };
        let item = row_to_bitwarden_item(&row, 0, 1000, "2026-04-23T00:00:00Z");
        assert_eq!(item["login"]["username"], Value::Null);
        assert_eq!(item["login"]["password"], Value::Null);
        assert_eq!(item["login"]["totp"], Value::Null);
        assert_eq!(item["notes"], Value::Null);
    }

    #[test]
    fn row_mapping_passkey_only_row_without_password_still_imported() {
        // CSV rows where Apple's login is passkey-only have no password.
        // They are not notes (no Notes content) — we still want them in
        // Bitwarden so the user can attach a passkey later.
        let row = AppleRow {
            title: "x.ai".into(),
            url: "https://accounts.x.ai/".into(),
            username: "alex@example.test".into(),
            ..Default::default()
        };
        let item = row_to_bitwarden_item(&row, 0, 1000, "2026-04-23T00:00:00Z");
        assert_eq!(item["type"], 1);
        assert_eq!(item["login"]["username"], "alex@example.test");
        assert_eq!(item["login"]["password"], Value::Null);
    }

    #[test]
    fn merge_appends_and_dedups_overlap() {
        // Existing Bitwarden item has no passkey, matching the empty fido2
        // signature the CSV produces — so the dedup key matches and the
        // CSV-imported GitHub row collapses with the existing one.
        let mut export = json!({
            "folders": [],
            "items": [
                {
                    "id": "existing-1",
                    "type": 1,
                    "name": "GitHub",
                    "revisionDate": "2025-01-01T00:00:00Z",
                    "creationDate": "2024-01-01T00:00:00Z",
                    "login": {
                        "username": "alex",
                        "password": "pw",
                        "uris": [{"match": null, "uri": "https://github.com"}],
                        "fido2Credentials": []
                    }
                }
            ]
        });
        let csv = "Title,URL,Username,Password,Notes,OTPAuth\n\
                   GitHub,https://github.com/login,alex,pw,,otpauth://totp/G?secret=NEW\n\
                   NewSite,https://new.test,alex,freshpw,a note,\n";
        let stats = merge_icloud_csv_into_export(&mut export, csv).unwrap();
        assert_eq!(stats.csv_rows, 2);
        assert_eq!(stats.csv_items_appended, 2);
        let items = export["items"].as_array().unwrap();
        // 1 existing + 2 CSV = 3 items; GitHub duplicate routed to Trash.
        assert_eq!(items.len(), 3, "all items preserved (trashed stay in output)");
        let living: Vec<&Value> = items
            .iter()
            .filter(|i| i["deletedDate"].is_null())
            .collect();
        assert_eq!(living.len(), 2, "one GitHub duplicate routed to Trash");
        // Living GitHub survivor carries merged URIs + CSV TOTP.
        let github = living
            .iter()
            .find(|i| i["name"].as_str() == Some("GitHub"))
            .expect("GitHub item must remain living");
        let uris: Vec<&str> = github["login"]["uris"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|u| u["uri"].as_str())
            .collect();
        assert!(uris.contains(&"https://github.com"));
        assert!(uris.contains(&"https://github.com/login"));
        // CSV item revisioned "now" (newer than 2025-01-01), so its TOTP lands.
        assert_eq!(
            github["login"]["totp"].as_str(),
            Some("otpauth://totp/G?secret=NEW")
        );
        // NewSite is a fresh living item.
        assert!(
            living.iter().any(|i| i["name"].as_str() == Some("NewSite")),
            "NewSite must appear as a living item"
        );
        // And a trashed GitHub copy is retained in the array.
        assert!(
            items.iter().any(|i| {
                i["name"].as_str() == Some("GitHub")
                    && i["deletedDate"].as_str().is_some_and(|s| !s.is_empty())
            }),
            "the GitHub duplicate must be trashed, not removed"
        );
    }

    #[test]
    fn merge_preserves_bitwarden_passkey_when_csv_has_none() {
        // Bitwarden has a passkey; CSV row carries the same credentials but
        // no passkey (Apple doesn't export them). Their fido2 signatures
        // differ so they don't group — both remain as separate living
        // items, and the Bitwarden passkey is preserved intact.
        let mut export = json!({
            "folders": [],
            "items": [
                {
                    "id": "has-passkey",
                    "type": 1,
                    "name": "GitHub",
                    "revisionDate": "2025-01-01T00:00:00Z",
                    "login": {
                        "username": "alex",
                        "password": "pw",
                        "uris": [{"match": null, "uri": "https://github.com"}],
                        "fido2Credentials": [{"credentialId": "existing-passkey"}]
                    }
                }
            ]
        });
        let csv = "Title,URL,Username,Password,Notes,OTPAuth\n\
                   GitHub,https://github.com,alex,pw,,\n";
        merge_icloud_csv_into_export(&mut export, csv).unwrap();
        let items = export["items"].as_array().unwrap();
        let living: Vec<&Value> = items
            .iter()
            .filter(|i| i["deletedDate"].is_null())
            .collect();
        assert_eq!(living.len(), 2, "distinct fido2 signatures must not merge");
        let passkey_holder = items
            .iter()
            .find(|i| i["id"].as_str() == Some("has-passkey"))
            .unwrap();
        let creds = passkey_holder["login"]["fido2Credentials"]
            .as_array()
            .unwrap();
        assert_eq!(
            creds[0]["credentialId"], "existing-passkey",
            "Bitwarden passkey must survive untouched"
        );
    }

    #[test]
    fn merge_preserves_existing_bitwarden_only_items() {
        // An item only in Bitwarden (not in CSV) must never be touched
        // or moved to Trash — the CSV is additive, never authoritative.
        let mut export = json!({
            "folders": [],
            "items": [
                {
                    "id": "keep-me",
                    "type": 1,
                    "name": "WorkOnlyAccount",
                    "revisionDate": "2025-01-01T00:00:00Z",
                    "login": {"username": "u", "password": "p"}
                }
            ]
        });
        let csv = "Title,URL,Username,Password,Notes,OTPAuth\n\
                   OtherSite,,u2,p2,,\n";
        merge_icloud_csv_into_export(&mut export, csv).unwrap();
        let items = export["items"].as_array().unwrap();
        let keep = items
            .iter()
            .find(|i| i["id"].as_str() == Some("keep-me"))
            .expect("Bitwarden-only item must survive the merge");
        assert!(
            keep["deletedDate"].is_null(),
            "Bitwarden-only item must stay living — never auto-trashed on merge"
        );
        assert!(
            items.iter().any(|i| i["name"].as_str() == Some("OtherSite")
                && i["deletedDate"].is_null()),
            "CSV-only item must be added as living"
        );
    }

    #[test]
    fn merge_empty_csv_is_noop() {
        let mut export = json!({
            "folders": [],
            "items": [
                {"id": "a", "type": 1, "name": "X",
                 "revisionDate": "2026-01-01T00:00:00Z",
                 "login": {"username": "u", "password": "p"}}
            ]
        });
        let csv = "Title,URL,Username,Password,Notes,OTPAuth\n";
        let stats = merge_icloud_csv_into_export(&mut export, csv).unwrap();
        assert_eq!(stats.csv_rows, 0);
        assert_eq!(stats.csv_items_appended, 0);
        assert_eq!(export["items"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn merge_refuses_to_overwrite_non_array_items() {
        // If `items` exists but is not an array, the file is almost
        // certainly damaged or not actually a Bitwarden export. Silently
        // replacing its `items` with a fresh array would mask the real
        // problem — refuse instead.
        let mut export = json!({
            "folders": [],
            "items": "oops-not-an-array"
        });
        let csv = "Title,URL,Username,Password,Notes,OTPAuth\n\
                   GitHub,https://github.com,u,p,,\n";
        let err = merge_icloud_csv_into_export(&mut export, csv).unwrap_err();
        assert!(
            err.contains("not an array"),
            "error must explain why we refused; got {err:?}"
        );
        // Original structure must be untouched on error.
        assert_eq!(export["items"].as_str(), Some("oops-not-an-array"));
    }

    #[test]
    fn merge_bootstraps_items_when_absent() {
        // An export that carries only `folders` (no `items` field at all)
        // is a valid scaffold — the merge path inserts a fresh array.
        let mut export = json!({"folders": []});
        let csv = "Title,URL,Username,Password,Notes,OTPAuth\n\
                   X,https://x.test,u,p,,\n";
        let stats = merge_icloud_csv_into_export(&mut export, csv).unwrap();
        assert_eq!(stats.csv_items_appended, 1);
        assert_eq!(export["items"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn merge_surfaces_csv_parse_errors() {
        // When the CSV parser rejects the file, the merge entry point
        // must propagate the error — no silent best-effort pass-through.
        let mut export = json!({"folders": [], "items": []});
        // Wrong headers entirely.
        let err = merge_icloud_csv_into_export(&mut export, "A,B,C\n1,2,3\n").unwrap_err();
        assert!(
            err.contains("missing required column"),
            "CSV validation error must bubble up; got {err:?}"
        );
    }
}
