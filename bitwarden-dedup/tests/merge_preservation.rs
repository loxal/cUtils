// Copyright 2026 Alexander Orlov <alexander.orlov@loxal.net>

//! Merge-preservation guards: every field that is NOT in the dedup key
//! must survive as merged data on the survivor.
//!
//! These are the invariants that give the "no user-entered data is lost"
//! guarantee real teeth:
//!
//! - distinct notes are preserved (including folder-disambiguation prefix)
//! - URIs are unioned across drops
//! - collectionIds are unioned
//! - custom fields are unioned (including Linked-Username vs Linked-Password)
//! - passwordHistory entries are unioned and sorted newest-first
//! - favorite is a logical OR across the group
//! - longer raw name wins on the merged record
//!
//! Tests drive the public `dedup_items` / `dedup_export` entry points so the
//! contract stays honest — no peeking at private helpers.

use bitwarden_dedup::{dedup_export, dedup_items};
use serde_json::{Value, json};

#[test]
fn merges_pair_with_uri_union() {
    let mut items = vec![
        json!({
            "id": "aaaaaaaa-0000-0000-0000-000000000000",
            "type": 1, "name": "GitHub",
            "revisionDate": "2026-01-01T00:00:00Z",
            "creationDate": "2025-01-01T00:00:00Z",
            "login": {
                "username": "alex", "password": "pw",
                "uris": [{"uri": "https://github.com"}],
            },
        }),
        json!({
            "id": "bbbbbbbb-0000-0000-0000-000000000000",
            "type": 1, "name": "GitHub",
            "revisionDate": "2026-02-01T00:00:00Z",
            "creationDate": "2025-06-01T00:00:00Z",
            "login": {
                "username": "alex", "password": "pw",
                "uris": [{"uri": "androidapp://com.github.android"}],
            },
        }),
    ];
    let stats = dedup_items(&mut items);
    assert_eq!(stats.total, 2);
    assert_eq!(stats.groups, 1);
    assert_eq!(stats.removed, 1);
    assert_eq!(stats.merged, 1);
    assert_eq!(stats.output, 1);
    assert_eq!(items.len(), 1);
    assert_eq!(
        items[0].get("id").and_then(Value::as_str),
        Some("bbbbbbbb-0000-0000-0000-000000000000"),
    );
    let kept_uris: Vec<&str> = items[0]
        .get("login")
        .and_then(|l| l.get("uris"))
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|u| u.get("uri").and_then(Value::as_str))
                .collect()
        })
        .unwrap();
    assert_eq!(kept_uris.len(), 2);
    assert!(kept_uris.contains(&"androidapp://com.github.android"));
    assert!(kept_uris.contains(&"https://github.com"));
}

#[test]
fn merges_notes_and_picks_longest_name() {
    let mut items = vec![
        json!({
            "id": "aaaaaaaa-0000-0000-0000-000000000000",
            "type": 1, "name": "fastly-eng.okta.com",
            "notes": "Autosaved on fastly-eng.okta.com",
            "revisionDate": "2026-04-12T02:11:29Z",
            "creationDate": "2024-10-31T14:36:43Z",
            "login": {"username": "a@b.com", "password": "pw", "uris": []},
        }),
        json!({
            "id": "bbbbbbbb-0000-0000-0000-000000000000",
            "type": 1, "name": "fastly-eng.okta.com (a@b.com)",
            "notes": "Manually labelled",
            "revisionDate": "2026-04-21T02:05:21Z",
            "creationDate": "2026-04-21T02:05:21Z",
            "login": {"username": "a@b.com", "password": "pw", "uris": []},
        }),
    ];
    let stats = dedup_items(&mut items);
    assert_eq!(stats.groups, 1);
    assert_eq!(stats.removed, 1);
    assert_eq!(items.len(), 1);
    let survivor = &items[0];
    // Longer raw name wins on the merged record.
    assert_eq!(
        survivor.get("name").and_then(Value::as_str),
        Some("fastly-eng.okta.com (a@b.com)"),
        "longest raw name should be preserved"
    );
    // Distinct notes merged with a separator so nothing is lost.
    let merged_notes = survivor.get("notes").and_then(Value::as_str).unwrap_or("");
    assert!(merged_notes.contains("Autosaved on fastly-eng.okta.com"));
    assert!(merged_notes.contains("Manually labelled"));
}

#[test]
fn merges_identical_notes_without_duplication() {
    let mut items = vec![
        json!({
            "type": 1, "name": "X",
            "notes": "same",
            "revisionDate": "2026-01-01T00:00:00Z",
            "login": {"username": "u", "password": "p"},
        }),
        json!({
            "type": 1, "name": "X",
            "notes": "same",
            "revisionDate": "2026-02-01T00:00:00Z",
            "login": {"username": "u", "password": "p"},
        }),
    ];
    dedup_items(&mut items);
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].get("notes").and_then(Value::as_str), Some("same"));
}

#[test]
fn merges_password_history_across_duplicates() {
    let mut items = vec![
        json!({
            "type": 1, "name": "X",
            "revisionDate": "2026-01-01T00:00:00Z",
            "passwordHistory": [
                {"lastUsedDate": "2025-06-01T00:00:00Z", "password": "old_a"},
            ],
            "login": {"username": "u", "password": "p"},
        }),
        json!({
            "type": 1, "name": "X",
            "revisionDate": "2026-02-01T00:00:00Z",
            "passwordHistory": [
                {"lastUsedDate": "2024-06-01T00:00:00Z", "password": "old_b"},
            ],
            "login": {"username": "u", "password": "p"},
        }),
    ];
    dedup_items(&mut items);
    assert_eq!(items.len(), 1);
    let hist = items[0].get("passwordHistory").and_then(Value::as_array).unwrap();
    assert_eq!(hist.len(), 2, "both historical passwords should be preserved");
    // Newest-first ordering.
    assert_eq!(
        hist[0].get("password").and_then(Value::as_str),
        Some("old_a")
    );
}

#[test]
fn favorite_is_logical_or_across_group() {
    let mut items = vec![
        json!({
            "type": 1, "name": "X", "favorite": false,
            "revisionDate": "2026-01-01T00:00:00Z",
            "login": {"username": "u", "password": "p"},
        }),
        json!({
            "type": 1, "name": "X", "favorite": true,
            "revisionDate": "2026-02-01T00:00:00Z",
            "login": {"username": "u", "password": "p"},
        }),
    ];
    dedup_items(&mut items);
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].get("favorite").and_then(Value::as_bool), Some(true));
}

#[test]
fn merges_custom_fields_preserving_linked_id() {
    // Two Linked custom fields sharing the same label but pointing at
    // different targets (Username=100, Password=101) must both survive
    // the merge. Previously this was enforced by keeping fields in the
    // dedup key; with fields moved out of the key, the merge step has
    // to keep the distinction.
    let mut items = vec![
        json!({
            "type": 1, "name": "X",
            "revisionDate": "2026-01-01T00:00:00Z",
            "fields": [
                {"name": "lu", "value": null, "type": 3, "linkedId": 100},
            ],
            "login": {"username": "u", "password": "p"},
        }),
        json!({
            "type": 1, "name": "X",
            "revisionDate": "2026-02-01T00:00:00Z",
            "fields": [
                {"name": "lu", "value": null, "type": 3, "linkedId": 101},
            ],
            "login": {"username": "u", "password": "p"},
        }),
    ];
    dedup_items(&mut items);
    assert_eq!(items.len(), 1);
    let fields = items[0].get("fields").and_then(Value::as_array).unwrap();
    let linked_ids: Vec<i64> = fields
        .iter()
        .filter_map(|f| f.get("linkedId").and_then(Value::as_i64))
        .collect();
    assert!(linked_ids.contains(&100));
    assert!(linked_ids.contains(&101));
}

#[test]
fn preserves_every_distinct_note_in_merged_survivor() {
    let mut items = vec![
        json!({"type": 1, "name": "Site", "notes": "first",
            "revisionDate": "2026-01-01T00:00:00Z",
            "login": {"username": "u", "password": "p"}}),
        json!({"type": 1, "name": "Site", "notes": "second",
            "revisionDate": "2026-02-01T00:00:00Z",
            "login": {"username": "u", "password": "p"}}),
        json!({"type": 1, "name": "Site", "notes": "third",
            "revisionDate": "2026-03-01T00:00:00Z",
            "login": {"username": "u", "password": "p"}}),
    ];
    dedup_items(&mut items);
    assert_eq!(items.len(), 1);
    let notes = items[0].get("notes").and_then(Value::as_str).unwrap_or("");
    assert!(notes.contains("first"), "distinct note 'first' must be merged");
    assert!(notes.contains("second"), "distinct note 'second' must be merged");
    assert!(notes.contains("third"), "distinct note 'third' must be merged");
}

#[test]
fn unions_collection_ids_across_duplicates() {
    // Two otherwise-identical org items in different collection sets
    // must collapse into one survivor whose `collectionIds` contains
    // both sets — Bitwarden supports multiple collection memberships.
    let mut items = vec![
        json!({
            "type": 1, "name": "Site",
            "organizationId": "org-1",
            "collectionIds": ["c-A"],
            "revisionDate": "2026-01-01T00:00:00Z",
            "login": {"username": "u", "password": "p"}
        }),
        json!({
            "type": 1, "name": "Site",
            "organizationId": "org-1",
            "collectionIds": ["c-B"],
            "revisionDate": "2026-02-01T00:00:00Z",
            "login": {"username": "u", "password": "p"}
        }),
    ];
    dedup_items(&mut items);
    assert_eq!(items.len(), 1, "duplicates should collapse");
    let cols: Vec<&str> = items[0]
        .get("collectionIds")
        .and_then(Value::as_array)
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(cols.contains(&"c-A"), "keep's collection must stay");
    assert!(cols.contains(&"c-B"), "drop's collection must be merged");
}

#[test]
fn appends_folder_note_when_drops_differ() {
    // End-to-end via `dedup_export`: drops with a different folder must
    // leave a disambiguation line on the survivor so placement isn't
    // silently lost at import time.
    let mut export = json!({
        "folders": [
            {"id": "folder-keep", "name": "Work"},
            {"id": "folder-drop", "name": "Personal"}
        ],
        "items": [
            {
                "type": 1, "name": "Site",
                "folderId": "folder-keep",
                "revisionDate": "2026-02-01T00:00:00Z",
                "login": {"username": "u", "password": "p"}
            },
            {
                "type": 1, "name": "Site",
                "folderId": "folder-drop",
                "revisionDate": "2026-01-01T00:00:00Z",
                "login": {"username": "u", "password": "p"}
            }
        ]
    });
    let stats = dedup_export(&mut export);
    assert_eq!(stats.output, 1);
    let items = export.get("items").and_then(Value::as_array).unwrap();
    let notes = items[0].get("notes").and_then(Value::as_str).unwrap_or("");
    assert!(
        notes.contains("Personal"),
        "dropped folder name must be captured; got {notes:?}"
    );
    assert!(
        !notes.contains("Work"),
        "survivor's own folder should not appear in the note; got {notes:?}"
    );
}

#[test]
fn omits_folder_note_when_folders_match() {
    let mut items = vec![
        json!({
            "type": 1, "name": "Site",
            "folderId": "same-folder",
            "revisionDate": "2026-02-01T00:00:00Z",
            "login": {"username": "u", "password": "p"}
        }),
        json!({
            "type": 1, "name": "Site",
            "folderId": "same-folder",
            "revisionDate": "2026-01-01T00:00:00Z",
            "login": {"username": "u", "password": "p"}
        }),
    ];
    dedup_items(&mut items);
    assert_eq!(items.len(), 1);
    let notes = items[0]
        .get("notes")
        .and_then(Value::as_str)
        .unwrap_or("");
    assert!(
        !notes.contains("originally also in folder"),
        "no folder-note line when folders match; got {notes:?}"
    );
}

#[test]
fn folder_note_falls_back_to_uuid_without_lookup() {
    // When the caller has no folders map (direct `dedup_items`), the
    // folder UUID itself must still appear in the note so the info
    // isn't lost silently.
    let mut items = vec![
        json!({
            "type": 1, "name": "Site",
            "folderId": "00000000-0000-0000-0000-000000000001",
            "revisionDate": "2026-02-01T00:00:00Z",
            "login": {"username": "u", "password": "p"}
        }),
        json!({
            "type": 1, "name": "Site",
            "folderId": "00000000-0000-0000-0000-000000000002",
            "revisionDate": "2026-01-01T00:00:00Z",
            "login": {"username": "u", "password": "p"}
        }),
    ];
    dedup_items(&mut items);
    let notes = items[0].get("notes").and_then(Value::as_str).unwrap_or("");
    assert!(
        notes.contains("00000000-0000-0000-0000-000000000002"),
        "dropped folder UUID must survive in notes; got {notes:?}"
    );
}

#[test]
fn dedup_export_reads_top_level_folders_and_dedups_items() {
    let mut export = json!({
        "folders": [
            {"id": "f-1", "name": "Work"},
            {"id": "f-2", "name": "Personal"}
        ],
        "items": [
            {
                "type": 1, "name": "Site",
                "folderId": "f-1",
                "revisionDate": "2026-02-01T00:00:00Z",
                "login": {"username": "u", "password": "p"}
            },
            {
                "type": 1, "name": "Site",
                "folderId": "f-2",
                "revisionDate": "2026-01-01T00:00:00Z",
                "login": {"username": "u", "password": "p"}
            }
        ]
    });
    let stats = dedup_export(&mut export);
    assert_eq!(stats.output, 1);
    assert_eq!(stats.removed, 1);
    let items = export.get("items").and_then(Value::as_array).unwrap();
    let notes = items[0].get("notes").and_then(Value::as_str).unwrap_or("");
    assert!(
        notes.contains("Personal"),
        "dedup_export must resolve folder UUIDs via top-level folders array; got {notes:?}"
    );
}
