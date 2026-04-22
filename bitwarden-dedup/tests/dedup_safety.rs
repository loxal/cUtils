// Copyright 2026 Alexander Orlov <alexander.orlov@loxal.net>

//! Safety guards: every distinct credential must survive dedup.
//!
//! The invariants a reviewer should be able to verify at a glance before
//! trusting the tool on a real vault:
//!
//! - different passwords never merge
//! - different `(username, password)` pairs never merge
//! - passkeys are never overwritten — distinct FIDO2 credentials keep items
//!   separate even when every other field matches
//! - when items differ only by TOTP, the group collapses to one survivor
//!   that carries the NEWEST TOTP secret (older rotations are intentionally
//!   dropped because they no longer authenticate against the backend)
//!
//! All tests exercise the public `dedup_items` API — the behaviour they
//! assert is part of the contract, not an implementation detail.

use bitwarden_dedup::dedup_items;
use serde_json::{Value, json};

#[test]
fn distinct_passwords_stay_separate() {
    let mut items = vec![
        json!({
            "type": 1, "name": "Gmail",
            "revisionDate": "2026-01-01T00:00:00Z",
            "login": {"username": "a", "password": "pw1"}
        }),
        json!({
            "type": 1, "name": "Gmail",
            "revisionDate": "2026-01-01T00:00:00Z",
            "login": {"username": "a", "password": "pw2"}
        }),
    ];
    let stats = dedup_items(&mut items);
    assert_eq!(stats.groups, 0);
    assert_eq!(stats.removed, 0);
    assert_eq!(items.len(), 2);
}

#[test]
fn every_distinct_username_password_pair_survives() {
    // Same name, same notes, same everything — only (username, password)
    // differs. Every pair must survive.
    let mut items = vec![
        json!({"type": 1, "name": "Site", "notes": "n",
            "revisionDate": "2026-01-01T00:00:00Z",
            "login": {"username": "u1", "password": "p1"}}),
        json!({"type": 1, "name": "Site", "notes": "n",
            "revisionDate": "2026-01-01T00:00:00Z",
            "login": {"username": "u1", "password": "p2"}}),
        json!({"type": 1, "name": "Site", "notes": "n",
            "revisionDate": "2026-01-01T00:00:00Z",
            "login": {"username": "u2", "password": "p1"}}),
        json!({"type": 1, "name": "Site", "notes": "n",
            "revisionDate": "2026-01-01T00:00:00Z",
            "login": {"username": "u2", "password": "p2"}}),
    ];
    let stats = dedup_items(&mut items);
    assert_eq!(stats.removed, 0, "all four distinct (u, p) pairs must survive");
    assert_eq!(items.len(), 4);
}

#[test]
fn divergent_totps_collapse_keeping_newest_secret() {
    // Two items identical on name/username/password but with distinct TOTP
    // secrets — the older TOTP is a rotation of the same slot on the same
    // backend, so the group collapses to one survivor carrying the newer
    // secret. This is the ONE field where dedup can displace a value.
    let mut items = vec![
        json!({"type": 1, "name": "Acme",
            "revisionDate": "2025-01-01T00:00:00Z",
            "login": {"username": "u", "password": "p",
                "totp": "otpauth://totp/Acme?secret=OLD"}}),
        json!({"type": 1, "name": "Acme",
            "revisionDate": "2026-06-01T00:00:00Z",
            "login": {"username": "u", "password": "p",
                "totp": "otpauth://totp/Acme?secret=NEW"}}),
    ];
    let stats = dedup_items(&mut items);
    assert_eq!(stats.removed, 1);
    assert_eq!(items.len(), 1);
    let secret = items[0]
        .get("login")
        .and_then(|l| l.get("totp"))
        .and_then(Value::as_str)
        .unwrap_or("");
    assert!(
        secret.contains("NEW"),
        "newest TOTP must win; got {secret:?}"
    );
}

#[test]
fn totp_presence_beats_absence_in_merge() {
    // One item carries a TOTP, the other doesn't. After merge, the survivor
    // must carry the TOTP — absence must never overwrite presence.
    let mut items = vec![
        json!({"type": 1, "name": "Acme",
            "revisionDate": "2026-02-01T00:00:00Z",
            "login": {"username": "u", "password": "p"}}),
        json!({"type": 1, "name": "Acme",
            "revisionDate": "2026-01-01T00:00:00Z",
            "login": {"username": "u", "password": "p",
                "totp": "otpauth://totp/Acme?secret=REAL"}}),
    ];
    dedup_items(&mut items);
    assert_eq!(items.len(), 1, "TOTP-presence asymmetry still collapses");
    let secret = items[0]
        .get("login")
        .and_then(|l| l.get("totp"))
        .and_then(Value::as_str)
        .unwrap_or("");
    assert!(
        secret.contains("REAL"),
        "the only TOTP in the group must move onto the survivor; got {secret:?}"
    );
}

#[test]
fn distinct_passkeys_prevent_merge_even_when_credentials_match() {
    // FIDO2 / passkey is strict-match. Two items sharing name/user/password
    // but with distinct passkeys must stay separate so neither passkey is
    // overwritten by the survivor selection.
    let mut items = vec![
        json!({
            "type": 1, "name": "GitHub",
            "revisionDate": "2026-01-01T00:00:00Z",
            "login": {
                "username": "u", "password": "p",
                "fido2Credentials": [{
                    "credentialId": "pk-alice", "counter": "1", "userHandle": "ua"
                }]
            }
        }),
        json!({
            "type": 1, "name": "GitHub",
            "revisionDate": "2026-06-01T00:00:00Z",
            "login": {
                "username": "u", "password": "p",
                "fido2Credentials": [{
                    "credentialId": "pk-bob", "counter": "7", "userHandle": "ub"
                }]
            }
        }),
    ];
    let stats = dedup_items(&mut items);
    assert_eq!(stats.removed, 0, "distinct passkeys must never merge");
    assert_eq!(items.len(), 2);
    // Both passkeys still visible, on their own items.
    let credential_ids: Vec<&str> = items
        .iter()
        .flat_map(|i| {
            i.get("login")
                .and_then(|l| l.get("fido2Credentials"))
                .and_then(Value::as_array)
                .map(|arr| {
                    arr.iter()
                        .filter_map(|c| c.get("credentialId").and_then(Value::as_str))
                        .collect::<Vec<&str>>()
                })
                .unwrap_or_default()
        })
        .collect();
    assert!(credential_ids.contains(&"pk-alice"));
    assert!(credential_ids.contains(&"pk-bob"));
}

#[test]
fn passkey_preserved_when_totp_merge_happens() {
    // TOTP-only-differs → merge; both items carry the SAME passkey.
    // Survivor must retain the passkey (it's the same anyway, but the
    // merge step must not drop it).
    let passkey = json!({"credentialId": "pk-1", "counter": "1", "userHandle": "u"});
    let mut items = vec![
        json!({
            "type": 1, "name": "Service",
            "revisionDate": "2025-01-01T00:00:00Z",
            "login": {
                "username": "u", "password": "p",
                "totp": "otpauth://totp/S?secret=OLD",
                "fido2Credentials": [passkey.clone()]
            }
        }),
        json!({
            "type": 1, "name": "Service",
            "revisionDate": "2026-06-01T00:00:00Z",
            "login": {
                "username": "u", "password": "p",
                "totp": "otpauth://totp/S?secret=NEW",
                "fido2Credentials": [passkey.clone()]
            }
        }),
    ];
    dedup_items(&mut items);
    assert_eq!(items.len(), 1, "TOTP-only divergence should merge");
    let passkeys = items[0]
        .get("login")
        .and_then(|l| l.get("fido2Credentials"))
        .and_then(Value::as_array)
        .map(Vec::len)
        .unwrap_or(0);
    assert_eq!(passkeys, 1, "passkey must survive the merge");
}
