// Copyright 2026 Alexander Orlov <alexander.orlov@loxal.net>

//! Integration coverage for `--collapse-empty-passwords` flowing
//! through both the `bitwarden-dedup` library API and the
//! `bitwarden-merge-icloud` library API. The two binaries each build
//! their own audit JSON literal and stdout summary, so the spec
//! asked for tests that exercise the full configured-merge path
//! (not just the strict-pass library entry points).

use bitwarden_dedup::{
    DedupConfig, dedup_export_with_config, merge_icloud_csv_into_export_with_config,
};
use serde_json::{Value, json};

fn empty_pw_login(id: &str, name: &str, user: &str, uri: Option<&str>) -> Value {
    let uris = match uri {
        Some(u) => json!([{"uri": u, "match": null}]),
        None => json!([]),
    };
    json!({
        "id": id,
        "type": 1,
        "name": name,
        "revisionDate": "2026-01-01T00:00:00Z",
        "creationDate": "2026-01-01T00:00:00Z",
        "login": {
            "username": user,
            "password": "",
            "uris": uris,
        },
    })
}

#[test]
fn dedup_export_collapse_empty_passwords_trashes_loser() {
    // End-to-end: the public dedup_export entry point honors
    // `collapse_empty_passwords` and routes the loser to trash.
    let mut export = json!({
        "folders": [],
        "items": [
            empty_pw_login("a", "Acme", "u", Some("https://acme.com/")),
            empty_pw_login("b", "Acme", "u", Some("https://acme.com/")),
        ]
    });
    let stats = dedup_export_with_config(
        &mut export,
        &DedupConfig {
            collapse_empty_passwords: true,
            ..Default::default()
        },
    )
    .expect("export shape valid");
    assert_eq!(stats.empty_password_groups, 1);
    assert_eq!(stats.empty_password_trashed, 1);
    assert_eq!(stats.living, 1);

    // Trash routing: loser carries deletedDate, survivor doesn't.
    let items = export["items"].as_array().unwrap();
    let trashed: Vec<&Value> = items
        .iter()
        .filter(|i| !i["deletedDate"].is_null())
        .collect();
    let living: Vec<&Value> = items
        .iter()
        .filter(|i| i["deletedDate"].is_null())
        .collect();
    assert_eq!(trashed.len(), 1);
    assert_eq!(living.len(), 1);
}

#[test]
fn dedup_export_collapse_empty_passwords_off_by_default() {
    // Regression guard at the public entry point: omitting the flag
    // (default config) preserves the prior behavior — empty-pw items
    // pass through.
    let mut export = json!({
        "folders": [],
        "items": [
            empty_pw_login("a", "Acme", "u", Some("https://acme.com/")),
            empty_pw_login("b", "Acme", "u", Some("https://acme.com/")),
        ]
    });
    let stats = dedup_export_with_config(&mut export, &DedupConfig::default())
        .expect("export shape valid");
    assert_eq!(stats.empty_password_groups, 0);
    assert_eq!(stats.empty_password_trashed, 0);
    assert_eq!(stats.living, 2);
}

#[test]
fn icloud_merge_collapse_empty_passwords_collapses_csv_overlap() {
    // The flag must flow all the way through
    // `merge_icloud_csv_into_export_with_config` to the shared dedup
    // pipeline — earlier code paths run unmodified, so this test is
    // the contract that breaks if someone forgets to thread the
    // config through a future refactor.
    //
    // Setup: existing Bitwarden side has one empty-pw stub for
    // `acme.com`; CSV has another row that materializes as an
    // empty-pw stub on the same domain (Apple's Passwords CSV emits
    // empty passwords on iCloud Keychain entries that have a saved
    // username but no password yet).
    let mut export = json!({
        "folders": [],
        "items": [
            empty_pw_login("bw-1", "Acme", "u@example.test",
                Some("https://acme.com/"))
        ]
    });
    // CSV row with no password — bitwarden-merge-icloud maps this to
    // a `type: 1` login with empty `login.password` (it never invents
    // a placeholder password; absence stays absence).
    let csv = "Title,URL,Username,Password,Notes,OTPAuth\n\
               Acme,https://acme.com/,u@example.test,,,\n";

    let stats = merge_icloud_csv_into_export_with_config(
        &mut export,
        csv,
        &DedupConfig {
            collapse_empty_passwords: true,
            ..Default::default()
        },
    )
    .expect("merge succeeds");

    assert_eq!(stats.csv_rows, 1);
    assert_eq!(stats.csv_items_appended, 1);
    assert_eq!(
        stats.dedup_stats.empty_password_groups, 1,
        "the CSV-origin empty-pw stub must collapse with the existing Bitwarden stub"
    );
    assert_eq!(stats.dedup_stats.empty_password_trashed, 1);
    assert_eq!(
        stats.dedup_stats.living, 1,
        "exactly one survivor remains living"
    );

    // Audit-entry contract: the new pass labels its drops with the
    // expected `item_kind` / `signal_kind` so downstream tooling can
    // grep them.
    let entries = &stats.dedup_stats.audit_entries;
    let epw_entries: Vec<&Value> = entries
        .iter()
        .filter(|e| e["item_kind"] == "empty_password_login")
        .collect();
    assert_eq!(epw_entries.len(), 1);
    assert!(
        epw_entries[0]["signal_kind"].is_string(),
        "signal_kind must be present on every empty-pw audit entry"
    );
}

#[test]
fn icloud_merge_off_by_default_preserves_csv_overlap() {
    // Without the flag, the same setup keeps both items as living —
    // the strict pass would skip them (empty pw) and there is no
    // second pass to catch them. Confirms the default is conservative.
    let mut export = json!({
        "folders": [],
        "items": [
            empty_pw_login("bw-1", "Acme", "u@example.test",
                Some("https://acme.com/"))
        ]
    });
    let csv = "Title,URL,Username,Password,Notes,OTPAuth\n\
               Acme,https://acme.com/,u@example.test,,,\n";

    let stats = merge_icloud_csv_into_export_with_config(
        &mut export,
        csv,
        &DedupConfig::default(),
    )
    .expect("merge succeeds");

    assert_eq!(stats.dedup_stats.empty_password_groups, 0);
    assert_eq!(
        stats.dedup_stats.living, 2,
        "default config must NOT collapse empty-pw stubs across BW + CSV"
    );
}

#[test]
fn dedup_stats_carries_per_pass_breakdown_for_audit_consumers() {
    // The two binaries serialize stats fields directly into their
    // audit JSON literals. This test pins the contract: every field
    // an audit consumer depends on must be reachable from
    // `DedupStats` after a real run, and the per-pass counts must
    // sum to `groups`.
    let mut export = json!({
        "folders": [],
        "items": [
            // Strict-pass duplicate
            json!({"id": "s1", "type": 1, "name": "S",
                "revisionDate": "2026-01-01T00:00:00Z",
                "login": {"username": "u", "password": "p"}}),
            json!({"id": "s2", "type": 1, "name": "S",
                "revisionDate": "2026-01-02T00:00:00Z",
                "login": {"username": "u", "password": "p"}}),
            // Empty-pw duplicate
            empty_pw_login("e1", "E", "v", Some("https://e.com/")),
            empty_pw_login("e2", "E", "v", Some("https://e.com/")),
            // Secure-note duplicate
            json!({"id": "n1", "type": 2, "name": "Note", "notes": "body"}),
            json!({"id": "n2", "type": 2, "name": "Note", "notes": "body"}),
        ]
    });
    let stats = dedup_export_with_config(
        &mut export,
        &DedupConfig {
            collapse_empty_passwords: true,
            ..Default::default()
        },
    )
    .expect("export valid");

    // Per-pass counts are what the binaries publish as audit fields.
    assert_eq!(stats.strict_login_groups, 1);
    assert_eq!(stats.empty_password_groups, 1);
    assert_eq!(stats.secure_note_groups, 1);
    assert_eq!(stats.ssh_key_groups, 0);

    // Sum invariant — the back-compat `groups` field must equal the
    // sum of the four per-pass counters so audit consumers reading
    // either form get consistent numbers.
    assert_eq!(
        stats.groups,
        stats.strict_login_groups
            + stats.empty_password_groups
            + stats.secure_note_groups
            + stats.ssh_key_groups
    );

    // Signal-kind breakdown sums to empty_password_groups.
    let signal_sum: usize = stats.empty_password_groups_by_signal.values().sum();
    assert_eq!(signal_sum, stats.empty_password_groups);
}
