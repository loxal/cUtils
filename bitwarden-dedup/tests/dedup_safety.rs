// Copyright 2026 Alexander Orlov <alexander.orlov@loxal.net>

//! Safety guards: every distinct credential must survive dedup.
//!
//! These are the invariants a reviewer should be able to verify at a glance
//! before trusting the tool on a real vault:
//!
//! - different passwords never merge
//! - different `(username, password)` pairs never merge
//! - different TOTP secrets never merge
//! - a TOTP presence asymmetry never loses the real secret
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
fn distinct_totp_secrets_stay_separate() {
    // Two items identical on name/username/password but with distinct TOTP
    // secrets must stay separate — a single Bitwarden item has only one
    // TOTP slot, so merging would overwrite one secret.
    let mut items = vec![
        json!({"type": 1, "name": "Acme",
            "revisionDate": "2026-01-01T00:00:00Z",
            "login": {"username": "u", "password": "p",
                "totp": "otpauth://totp/Acme?secret=ABC"}}),
        json!({"type": 1, "name": "Acme",
            "revisionDate": "2026-01-01T00:00:00Z",
            "login": {"username": "u", "password": "p",
                "totp": "otpauth://totp/Acme?secret=XYZ"}}),
    ];
    let stats = dedup_items(&mut items);
    assert_eq!(stats.removed, 0, "distinct TOTP secrets must never be lost");
    assert_eq!(items.len(), 2);
    let secrets: Vec<&str> = items
        .iter()
        .filter_map(|i| {
            i.get("login")
                .and_then(|l| l.get("totp"))
                .and_then(Value::as_str)
        })
        .collect();
    assert!(secrets.iter().any(|s| s.contains("ABC")));
    assert!(secrets.iter().any(|s| s.contains("XYZ")));
}

#[test]
fn totp_presence_asymmetry_preserves_the_real_secret() {
    // Edge case: one item has a TOTP secret and an otherwise-identical
    // item does not. They must stay separate — otherwise the no-TOTP
    // item could win as survivor and silently drop the real secret.
    let mut items = vec![
        json!({"type": 1, "name": "Acme",
            "revisionDate": "2026-02-01T00:00:00Z",
            "login": {"username": "u", "password": "p"}}),
        json!({"type": 1, "name": "Acme",
            "revisionDate": "2026-01-01T00:00:00Z",
            "login": {"username": "u", "password": "p",
                "totp": "otpauth://totp/Acme?secret=ABC"}}),
    ];
    dedup_items(&mut items);
    assert_eq!(items.len(), 2, "TOTP presence must not be merged away");
    assert!(items.iter().any(|i| i
        .get("login")
        .and_then(|l| l.get("totp"))
        .and_then(Value::as_str)
        .is_some_and(|s| s.contains("ABC"))));
}
