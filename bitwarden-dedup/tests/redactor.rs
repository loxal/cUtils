// Copyright 2026 Alexander Orlov <alexander.orlov@loxal.net>

//! Integration tests for the `bitwarden-redact` binary.
//!
//! These tests invoke the compiled binary as a subprocess (via the
//! `CARGO_BIN_EXE_bitwarden-redact` env var Cargo sets for integration
//! tests) and feed it a small hand-crafted synthetic "source" export that
//! contains strings a real vault export would have: full-shape UUIDs,
//! organization ids, collection ids, folder ids with non-zero bytes, a
//! populated `passwordHistory`, `fido2Credentials`, notes, custom fields,
//! an `androidapp://` URI, and a bare opaque identifier without a URL
//! scheme.
//!
//! The assertions enforce two contracts:
//!
//! 1. Every field the redactor promises to scrub or nullify is actually
//!    scrubbed or nullified, and none of the source strings appear in the
//!    output JSON (verified both by parsing and by substring scan).
//! 2. Running the redactor twice on the same input produces byte-for-byte
//!    identical output — a regression here would mean the redactor
//!    started depending on HashMap iteration order, process clock, or
//!    another non-deterministic source.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{Value, json};

const REDACTOR_BIN: &str = env!("CARGO_BIN_EXE_bitwarden-redact");

fn scratch_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "bwd-redactor-{label}-{}-{}",
        std::process::id(),
        nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

fn cleanup(dir: &Path) {
    let _ = std::fs::remove_dir_all(dir);
}

fn run_redactor(input: &Path, output: &Path) {
    let result = Command::new(REDACTOR_BIN)
        .arg("--input")
        .arg(input)
        .arg("--output")
        .arg(output)
        .output()
        .expect("spawn bitwarden-redact");
    assert!(
        result.status.success(),
        "bitwarden-redact failed: stdout={} stderr={}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr),
    );
}

/// A minimal but high-coverage synthetic source export. Every string
/// here is intentionally "real-looking" so the leak-substring scan can
/// catch the redactor accidentally copying it through.
fn synthetic_source() -> Value {
    json!({
        "encrypted": false,
        "folders": [
            {"id": "11111111-2222-3333-4444-555555555555", "name": "Secret Folder"},
            {"id": "66666666-7777-8888-9999-aaaaaaaaaaaa", "name": "Work Folder"}
        ],
        "items": [
            {
                "id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                "organizationId": "99999999-8888-7777-6666-555555555555",
                "collectionIds": ["cccccccc-dddd-eeee-ffff-000011112222"],
                "folderId": "11111111-2222-3333-4444-555555555555",
                "type": 1,
                "reprompt": 0,
                "favorite": true,
                "name": "Corp Example Portal",
                "notes": "this is a sensitive note",
                "creationDate": "2020-05-15T12:34:56Z",
                "revisionDate": "2024-11-30T08:15:00Z",
                "deletedDate": null,
                "fields": [
                    {"name": "recovery email", "value": "alice@corp.example", "type": 1, "linkedId": null}
                ],
                "passwordHistory": [
                    {"lastUsedDate": "2020-05-15T12:34:56Z", "password": "old-password-1"}
                ],
                "login": {
                    "username": "alice@corp.example",
                    "password": "hunter2-real",
                    "totp": "otpauth://totp/Corp:alice?secret=JBSWY3DPEHPK3PXP&issuer=Corp",
                    "uris": [
                        {"uri": "https://portal.corp.example", "match": null},
                        {"uri": "com.corp.iosapp", "match": null},
                        {"uri": "androidapp://com.corp.android", "match": null}
                    ],
                    "fido2Credentials": [
                        {"credentialId": "realcred", "keyValue": "private-key-material"}
                    ]
                }
            },
            {
                "id": "22222222-2222-2222-2222-222222222222",
                "organizationId": null,
                "collectionIds": null,
                "folderId": "66666666-7777-8888-9999-aaaaaaaaaaaa",
                "type": 1,
                "reprompt": 0,
                "favorite": false,
                "name": "Dup Pair",
                "notes": null,
                "creationDate": "2023-01-01T00:00:00Z",
                "revisionDate": "2024-01-01T00:00:00Z",
                "deletedDate": null,
                "fields": null,
                "passwordHistory": null,
                "login": {
                    "username": "bob@corp.example",
                    "password": "dup-shared",
                    "totp": null,
                    "uris": [{"uri": "https://duplicated.example.com", "match": null}],
                    "fido2Credentials": []
                }
            },
            {
                "id": "33333333-3333-3333-3333-333333333333",
                "organizationId": null,
                "collectionIds": null,
                "folderId": "66666666-7777-8888-9999-aaaaaaaaaaaa",
                "type": 1,
                "reprompt": 0,
                "favorite": false,
                "name": "Dup Pair",
                "notes": null,
                "creationDate": "2023-06-01T00:00:00Z",
                "revisionDate": "2025-06-01T00:00:00Z",
                "deletedDate": null,
                "fields": null,
                "passwordHistory": null,
                "login": {
                    "username": "bob@corp.example",
                    "password": "dup-shared",
                    "totp": null,
                    "uris": [{"uri": "https://duplicated.example.com", "match": null}],
                    "fido2Credentials": []
                }
            }
        ]
    })
}

fn write_source(dir: &Path) -> PathBuf {
    let input = dir.join("source.json");
    std::fs::write(
        &input,
        serde_json::to_string_pretty(&synthetic_source()).unwrap(),
    )
    .unwrap();
    input
}

#[test]
fn redactor_strips_all_source_metadata() {
    let dir = scratch_dir("strip-metadata");
    let input = write_source(&dir);
    let output = dir.join("redacted.json");
    run_redactor(&input, &output);

    let text = std::fs::read_to_string(&output).expect("read output");

    // Substring scan: every source string must be absent from the output.
    let forbidden = [
        // item ids
        "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        "22222222-2222-2222-2222-222222222222",
        "33333333-3333-3333-3333-333333333333",
        // folder ids
        "11111111-2222-3333-4444-555555555555",
        "66666666-7777-8888-9999-aaaaaaaaaaaa",
        // org and collection ids
        "99999999-8888-7777-6666-555555555555",
        "cccccccc-dddd-eeee-ffff-000011112222",
        // names, notes, PII
        "Corp Example Portal",
        "Dup Pair",
        "Secret Folder",
        "Work Folder",
        "sensitive note",
        "alice@corp.example",
        "bob@corp.example",
        "hunter2-real",
        "dup-shared",
        "old-password-1",
        "recovery email",
        "JBSWY3DPEHPK3PXP",
        "realcred",
        "private-key-material",
        // real URIs
        "portal.corp.example",
        "com.corp.iosapp",
        "com.corp.android",
        "duplicated.example.com",
        // real timestamps
        "2020-05-15T12:34:56Z",
        "2024-11-30T08:15:00Z",
        "2023-01-01T00:00:00Z",
        "2024-01-01T00:00:00Z",
        "2023-06-01T00:00:00Z",
        "2025-06-01T00:00:00Z",
    ];
    for needle in forbidden {
        assert!(
            !text.contains(needle),
            "source string leaked into redacted output: {needle:?}"
        );
    }

    // Structural checks on the parsed JSON.
    let out: Value = serde_json::from_str(&text).unwrap();
    let items = out["items"].as_array().expect("items array");
    assert_eq!(items.len(), 3, "all source items should still be present");

    for item in items {
        assert!(
            item["organizationId"].is_null(),
            "organizationId must be null"
        );
        assert!(
            item["collectionIds"].is_null(),
            "collectionIds must be null"
        );
        assert!(item["notes"].is_null(), "notes must be null");
        assert!(
            item["passwordHistory"].is_null(),
            "passwordHistory must be null"
        );

        // Synthetic item id shape.
        let id = item["id"].as_str().expect("id is string");
        assert!(
            id.starts_with("00000000-0000-0000-0000-"),
            "item id not synthesized: {id}"
        );

        // Synthetic folder id shape (or null if original was null).
        if let Some(fid) = item.get("folderId").and_then(Value::as_str) {
            assert!(
                fid.starts_with("00000000-0000-0000-0001-"),
                "folderId not mapped to synthetic: {fid}"
            );
        }

        // Synthetic dates — baseline 2026 for revision, 2025 for creation.
        let rev = item["revisionDate"].as_str().unwrap();
        let cre = item["creationDate"].as_str().unwrap();
        assert!(
            rev.starts_with("2026-"),
            "revisionDate not synthesized: {rev}"
        );
        assert!(
            cre.starts_with("2025-"),
            "creationDate not synthesized: {cre}"
        );

        if item["type"].as_u64() == Some(1) {
            let login = &item["login"];
            // FIDO2 credentials must be an empty array — passkey private
            // key material is NEVER copied through.
            let fido = login
                .get("fido2Credentials")
                .and_then(Value::as_array)
                .expect("fido2Credentials array");
            assert!(fido.is_empty(), "fido2Credentials not emptied");
        }
    }

    cleanup(&dir);
}

#[test]
fn redactor_preserves_dedup_equivalence() {
    // The source has 1 unique item plus a duplicate pair. The redactor
    // must preserve that structure: running bitwarden-dedup on the
    // redacted output should still report 3 total, 1 group, 1 removed.
    let dir = scratch_dir("equivalence");
    let input = write_source(&dir);
    let output = dir.join("redacted.json");
    run_redactor(&input, &output);

    let mut data: Value = serde_json::from_str(&std::fs::read_to_string(&output).unwrap()).unwrap();
    let items_owned: Vec<Value> = match data.as_object_mut().and_then(|o| o.get_mut("items")) {
        Some(Value::Array(arr)) => std::mem::take(arr),
        _ => panic!("redacted output missing items"),
    };
    let mut items = items_owned;
    let stats = bitwarden_dedup::dedup_items(&mut items);

    assert_eq!(stats.total, 3);
    assert_eq!(stats.groups, 1);
    assert_eq!(stats.trashed, 1);
    // Output keeps every input item; losers are trashed, not removed.
    assert_eq!(stats.output, 3);
    assert_eq!(stats.living, 2);

    cleanup(&dir);
}

/// Equivalence preservation must hold for non-login passes too: cards,
/// secure notes, identities, SSH keys, and the empty-password login
/// pass each have their own (predicate, key) pair in the dedup
/// pipeline, and the redactor must group items the same way the live
/// pipeline does. This test feeds the redactor a source with a
/// duplicate **card** pair (no logins involved) and asserts that
/// dedup-on-redacted reports the same one-group, one-loser result the
/// live pipeline would produce on the original.
#[test]
fn redactor_preserves_card_dedup_equivalence() {
    let dir = scratch_dir("card-equivalence");
    let source = json!({
        "encrypted": false,
        "folders": [],
        "items": [
            {
                "id": "11111111-1111-1111-1111-111111111111",
                "organizationId": null,
                "collectionIds": null,
                "folderId": null,
                "type": 3,
                "reprompt": 0,
                "favorite": false,
                "name": "Visa Personal",
                "notes": null,
                "creationDate": "2023-01-01T00:00:00Z",
                "revisionDate": "2024-01-01T00:00:00Z",
                "deletedDate": null,
                "fields": null,
                "passwordHistory": null,
                "card": {
                    "cardholderName": "Alice Example",
                    "brand": "Visa",
                    "number": "4111111111111111",
                    "expMonth": "12",
                    "expYear": "2030",
                    "code": "123"
                }
            },
            {
                "id": "22222222-2222-2222-2222-222222222222",
                "organizationId": null,
                "collectionIds": null,
                "folderId": null,
                "type": 3,
                "reprompt": 0,
                "favorite": false,
                "name": "Visa Personal",
                "notes": null,
                "creationDate": "2023-06-01T00:00:00Z",
                "revisionDate": "2025-06-01T00:00:00Z",
                "deletedDate": null,
                "fields": null,
                "passwordHistory": null,
                "card": {
                    "cardholderName": "Alice Example",
                    "brand": "Visa",
                    "number": "4111111111111111",
                    "expMonth": "12",
                    "expYear": "2030",
                    "code": "123"
                }
            }
        ]
    });
    let input = dir.join("source.json");
    std::fs::write(&input, serde_json::to_string_pretty(&source).unwrap()).unwrap();
    let output = dir.join("redacted.json");
    run_redactor(&input, &output);

    let mut data: Value = serde_json::from_str(&std::fs::read_to_string(&output).unwrap()).unwrap();
    let items_owned: Vec<Value> = match data.as_object_mut().and_then(|o| o.get_mut("items")) {
        Some(Value::Array(arr)) => std::mem::take(arr),
        _ => panic!("redacted output missing items"),
    };
    let mut items = items_owned;
    let stats = bitwarden_dedup::dedup_items(&mut items);

    // Two duplicate cards → one group, one loser.
    assert_eq!(stats.total, 2);
    assert_eq!(stats.groups, 1);
    assert_eq!(stats.trashed, 1);
    assert_eq!(stats.living, 1);

    cleanup(&dir);
}

#[test]
fn redactor_is_byte_for_byte_deterministic() {
    // Same input → same output, twice. Protects against a regression
    // where the redactor starts depending on HashMap iteration order,
    // a random seed, or a wall-clock timestamp.
    let dir = scratch_dir("determinism");
    let input = write_source(&dir);
    let out_a = dir.join("a.json");
    let out_b = dir.join("b.json");
    run_redactor(&input, &out_a);
    run_redactor(&input, &out_b);

    let a = std::fs::read(&out_a).unwrap();
    let b = std::fs::read(&out_b).unwrap();
    assert_eq!(
        a, b,
        "redactor output is not byte-for-byte deterministic across runs"
    );

    cleanup(&dir);
}

#[test]
fn redactor_preserves_androidapp_and_bare_identifier_shapes() {
    // The source has three URIs on the first item: one https://, one
    // bare identifier (`com.corp.iosapp`, no scheme), and one
    // `androidapp://`. The redactor must keep each in its own shape
    // category so the committed fixture (and the dedup library's
    // opaque-URI path) stay covered.
    let dir = scratch_dir("uri-shapes");
    let input = write_source(&dir);
    let output = dir.join("redacted.json");
    run_redactor(&input, &output);

    let text = std::fs::read_to_string(&output).unwrap();
    assert!(
        text.contains("androidapp://com.example.service"),
        "androidapp:// scheme did not survive redaction"
    );
    assert!(
        text.contains("com.example.opaque.service"),
        "bare-identifier URI was silently upgraded to https://"
    );

    cleanup(&dir);
}

#[test]
fn redactor_matches_output_item_count_to_source() {
    let dir = scratch_dir("count");
    let input = write_source(&dir);
    let output = dir.join("redacted.json");
    run_redactor(&input, &output);

    let out: Value = serde_json::from_str(&std::fs::read_to_string(&output).unwrap()).unwrap();
    let items = out["items"].as_array().unwrap();
    let src_items = synthetic_source()["items"].as_array().unwrap().len();
    assert_eq!(items.len(), src_items);

    cleanup(&dir);
}

// ---------------------------------------------------------------------------
// Adversarial shape check: walk every string in the redactor's output and
// require each one to match a known synthetic shape the redactor is allowed
// to emit. Catches the class of leak where a specific real string was
// missed by the substring-scan allowlist above — this test doesn't care
// WHAT the source strings were, only that the OUTPUT contains nothing that
// looks structurally like a real email, hostname, password, UUID, or note.
// ---------------------------------------------------------------------------

#[test]
fn redactor_output_strings_all_match_synthetic_shapes() {
    let dir = scratch_dir("shape-check");
    let input = write_source(&dir);
    let output = dir.join("redacted.json");
    run_redactor(&input, &output);

    let out: Value = serde_json::from_str(&std::fs::read_to_string(&output).unwrap()).unwrap();

    let mut path_trail = String::new();
    walk_strings(&out, &mut path_trail, &mut |s, p| {
        assert!(
            is_redactor_output_shape_safe(s),
            "redactor output contains a string that doesn't match any \
             synthetic shape\n  path:   {p}\n  string: {s:?}"
        );
    });

    cleanup(&dir);
}

fn walk_strings(value: &Value, path: &mut String, visit: &mut impl FnMut(&str, &str)) {
    match value {
        Value::String(s) => visit(s, path),
        Value::Array(arr) => {
            for (i, v) in arr.iter().enumerate() {
                let saved = path.len();
                use std::fmt::Write;
                let _ = write!(path, "[{i}]");
                walk_strings(v, path, visit);
                path.truncate(saved);
            }
        }
        Value::Object(obj) => {
            for (k, v) in obj {
                let saved = path.len();
                use std::fmt::Write;
                let _ = write!(path, ".{k}");
                walk_strings(v, path, visit);
                path.truncate(saved);
            }
        }
        _ => {}
    }
}

fn is_redactor_output_shape_safe(s: &str) -> bool {
    if s.is_empty() {
        return true;
    }

    // Literals the redactor emits in fixed positions (REDACTED for
    // card/identity placeholder strings, folder labels, etc.).
    const EXACT: &[&str] = &["REDACTED"];
    if EXACT.contains(&s) {
        return true;
    }

    is_example_service_name(s)
        || is_example_user_4digits(s)
        || is_redacted_password_4digits(s)
        || is_redacted_totp_4digits(s)
        || is_example_https_url(s)
        || is_example_http_url(s)
        || is_example_androidapp_url(s)
        || is_example_opaque_bare(s)
        || is_synthetic_uuid_item_or_folder(s)
        || is_synthetic_folder_name(s)
        || is_synthetic_rank_date(s)
        || is_example_field_name(s)
}

// Custom-field labels emitted by scrub_item: `field_0`, `field_1`, …
fn is_example_field_name(s: &str) -> bool {
    s.strip_prefix("field_")
        .is_some_and(|d| !d.is_empty() && d.chars().all(|c| c.is_ascii_digit()))
}

fn is_example_service_name(s: &str) -> bool {
    // "Example Service NNNN" — 4 digits, matches scrub_item()'s emitter.
    s.strip_prefix("Example Service ")
        .is_some_and(|rest| rest.len() == 4 && rest.chars().all(|c| c.is_ascii_digit()))
}

fn is_example_user_4digits(s: &str) -> bool {
    s.strip_prefix("user")
        .and_then(|r| r.strip_suffix("@example.test"))
        .is_some_and(|d| d.len() == 4 && d.chars().all(|c| c.is_ascii_digit()))
}

fn is_redacted_password_4digits(s: &str) -> bool {
    s.strip_prefix("redacted-password-")
        .is_some_and(|d| d.len() == 4 && d.chars().all(|c| c.is_ascii_digit()))
}

fn is_redacted_totp_4digits(s: &str) -> bool {
    s.strip_prefix("redacted-totp-seed-")
        .is_some_and(|d| d.len() == 4 && d.chars().all(|c| c.is_ascii_digit()))
}

// https://service\d{4}\.example\.test(/\d+)?
fn is_example_https_url(s: &str) -> bool {
    is_example_url_with_scheme(s, "https://")
}

fn is_example_http_url(s: &str) -> bool {
    is_example_url_with_scheme(s, "http://")
}

fn is_example_url_with_scheme(s: &str, scheme: &str) -> bool {
    let Some(rest) = s.strip_prefix(scheme) else {
        return false;
    };
    let Some(rest) = rest.strip_prefix("service") else {
        return false;
    };
    let Some((num, tail)) = rest.split_once('.') else {
        return false;
    };
    if num.len() != 4 || !num.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }
    if tail == "example.test" {
        return true;
    }
    if let Some(path) = tail.strip_prefix("example.test/") {
        return !path.is_empty() && path.chars().all(|c| c.is_ascii_digit());
    }
    false
}

// androidapp://com.example.service\d{4}
fn is_example_androidapp_url(s: &str) -> bool {
    s.strip_prefix("androidapp://com.example.service")
        .is_some_and(|d| d.len() == 4 && d.chars().all(|c| c.is_ascii_digit()))
}

// com.example.opaque.service\d{4}\.\d+
fn is_example_opaque_bare(s: &str) -> bool {
    let Some(rest) = s.strip_prefix("com.example.opaque.service") else {
        return false;
    };
    let Some((num, idx)) = rest.split_once('.') else {
        return false;
    };
    num.len() == 4
        && num.chars().all(|c| c.is_ascii_digit())
        && !idx.is_empty()
        && idx.chars().all(|c| c.is_ascii_digit())
}

// 00000000-0000-0000-000[01]-[hex]{12}
fn is_synthetic_uuid_item_or_folder(s: &str) -> bool {
    if s.len() != 36 {
        return false;
    }
    if !s.starts_with("00000000-0000-0000-0000-") && !s.starts_with("00000000-0000-0000-0001-") {
        return false;
    }
    if s.chars().filter(|&c| c == '-').count() != 4 {
        return false;
    }
    s.chars().all(|c| c == '-' || c.is_ascii_hexdigit())
}

// "Folder NN" — builder uses 2-digit zero-padded, but allow any run of digits.
fn is_synthetic_folder_name(s: &str) -> bool {
    s.strip_prefix("Folder ")
        .is_some_and(|rest| !rest.is_empty() && rest.chars().all(|c| c.is_ascii_digit()))
}

// Rank-based synthetic date: (2024|2025|2026)-12-31THH:MM:SSZ
fn is_synthetic_rank_date(s: &str) -> bool {
    if s.len() != 20 {
        return false;
    }
    let bytes = s.as_bytes();
    if bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes[19] != b'Z'
    {
        return false;
    }
    let year = &s[..4];
    if !matches!(year, "2024" | "2025" | "2026") {
        return false;
    }
    if &s[5..10] != "12-31" {
        return false;
    }
    s[11..13].chars().all(|c| c.is_ascii_digit())
        && s[14..16].chars().all(|c| c.is_ascii_digit())
        && s[17..19].chars().all(|c| c.is_ascii_digit())
}

// Smoke tests for the shape matchers themselves.
#[cfg(test)]
mod shape_unit_tests {
    use super::*;

    #[test]
    fn accepts_every_shape_the_redactor_emits() {
        assert!(is_redactor_output_shape_safe("Example Service 0042"));
        assert!(is_redactor_output_shape_safe("user0042@example.test"));
        assert!(is_redactor_output_shape_safe("redacted-password-0042"));
        assert!(is_redactor_output_shape_safe("redacted-totp-seed-0042"));
        assert!(is_redactor_output_shape_safe(
            "https://service0042.example.test"
        ));
        assert!(is_redactor_output_shape_safe(
            "https://service0042.example.test/0"
        ));
        assert!(is_redactor_output_shape_safe(
            "http://service0042.example.test/3"
        ));
        assert!(is_redactor_output_shape_safe(
            "androidapp://com.example.service0042"
        ));
        assert!(is_redactor_output_shape_safe(
            "com.example.opaque.service0042.0"
        ));
        assert!(is_redactor_output_shape_safe(
            "00000000-0000-0000-0000-000000000017"
        ));
        assert!(is_redactor_output_shape_safe(
            "00000000-0000-0000-0001-000000000000"
        ));
        assert!(is_redactor_output_shape_safe("Folder 01"));
        assert!(is_redactor_output_shape_safe("2026-12-31T23:59:59Z"));
        assert!(is_redactor_output_shape_safe("REDACTED"));
        assert!(is_redactor_output_shape_safe("field_0"));
        assert!(is_redactor_output_shape_safe("field_12"));
    }

    #[test]
    fn rejects_real_looking_strings() {
        assert!(!is_redactor_output_shape_safe("alice@example.com"));
        assert!(!is_redactor_output_shape_safe("https://github.com"));
        assert!(!is_redactor_output_shape_safe(
            "https://service0042.example.test/github"
        ));
        assert!(!is_redactor_output_shape_safe(
            "androidapp://com.github.android"
        ));
        assert!(!is_redactor_output_shape_safe("hunter2"));
        assert!(!is_redactor_output_shape_safe("real note text"));
        assert!(!is_redactor_output_shape_safe(
            "aabbccdd-1111-2222-3333-444444444444"
        ));
        assert!(!is_redactor_output_shape_safe("Secret Folder"));
        assert!(!is_redactor_output_shape_safe("2024-01-15T09:30:00Z")); // not 12-31
    }
}
