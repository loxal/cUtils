// Copyright 2026 Alexander Orlov <alexander.orlov@loxal.net>

//! **"Which item survives, and what's the audit trail?"** — pipeline
//! orchestration.
//!
//! The dedup pipeline runs in four passes:
//!
//! 1. Group items by [`crate::key::dedup_key`]; skip items that fail
//!    [`crate::key::skip_from_dedup`].
//! 2. For each group of size > 1, pick a survivor and compute the merged
//!    survivor patch via [`crate::merge::build_survivor_patch`].
//! 3. Apply patches via [`crate::merge::apply_survivor_patch`].
//! 4. Drop the losers and assemble a [`DedupStats`] summary.
//!
//! **Survivor selection** is deterministic: longer `passwordHistory` wins
//! (captures more rotation history), then newer `revisionDate`, then newer
//! `creationDate`. That ordering is what keeps the agent-merge safe — older
//! items with richer history aren't discarded in favour of a freshly-updated
//! stub.

use std::collections::{HashMap, HashSet};

use serde_json::{Value, json};

use crate::json_util::get_str;
use crate::key::{dedup_key, skip_from_dedup};
use crate::merge::{SurvivorPatch, apply_survivor_patch, build_survivor_patch};

/// Summary of a [`dedup_items`] run.
///
/// Field meanings:
/// - `total`    — input item count before dedup
/// - `skipped`  — items passed through without being grouped (non-logins,
///                reprompt-gated, empty password, already tagged `[duplicate]`,
///                deleted items)
/// - `groups`   — number of strict duplicate groups found
/// - `removed`  — number of items dropped (always `total - output`)
/// - `merged`   — total URIs merged from dropped items into kept items
/// - `output`   — surviving item count after dedup
/// - `audit_entries` — one JSON record per removed item, suitable for
///                     writing alongside the deduplicated output
#[derive(Debug, Clone)]
pub struct DedupStats {
    pub total: usize,
    pub skipped: usize,
    pub groups: usize,
    pub removed: usize,
    pub merged: usize,
    pub output: usize,
    pub audit_entries: Vec<Value>,
}

/// Run the full dedup pipeline on a `Vec<Value>` of Bitwarden items in place.
///
/// The input vector is mutated:
/// - items that are removed drop out of the vec
/// - the surviving item in each duplicate group absorbs data from the dropped
///   items: URIs, notes, custom fields, passwordHistory, favorite flag,
///   collection memberships, and the longest name in the group. Drops whose
///   `folderId` differs from the survivor's are recorded as a note line so
///   the placement hint survives import.
///
/// **Survivor selection** (within a duplicate group):
/// 1. Longer `passwordHistory` array wins (captures more rotation records)
/// 2. Then newer `revisionDate`
/// 3. Then newer `creationDate`
///
/// The returned [`DedupStats`] describes what happened and includes
/// per-removal audit records.
///
/// For top-level exports that carry a `folders: [{id, name}, …]` array,
/// prefer [`dedup_export`] — it resolves folder UUIDs to names in the
/// disambiguation note. This entry point passes an empty lookup, so
/// divergent folders fall back to bare UUIDs in the merged notes.
pub fn dedup_items(items: &mut Vec<Value>) -> DedupStats {
    dedup_items_with_folders(items, &HashMap::new())
}

/// Run the full dedup pipeline on a complete Bitwarden export JSON value.
///
/// Accepts the parsed top-level object (the structure `{folders, items, …}`
/// that `bw export --format json` writes). Extracts the `folders` lookup,
/// dedups `items` in place, and returns the same [`DedupStats`] as
/// [`dedup_items`]. When the export has no `folders` array, behaves
/// identically to [`dedup_items`].
pub fn dedup_export(export: &mut Value) -> DedupStats {
    let folders = extract_folder_names(export);
    let Some(items_value) = export.get_mut("items") else {
        return empty_stats();
    };
    let Some(arr) = items_value.as_array_mut() else {
        return empty_stats();
    };
    let mut items = std::mem::take(arr);
    let stats = dedup_items_with_folders(&mut items, &folders);
    *arr = items;
    stats
}

fn empty_stats() -> DedupStats {
    DedupStats {
        total: 0,
        skipped: 0,
        groups: 0,
        removed: 0,
        merged: 0,
        output: 0,
        audit_entries: Vec::new(),
    }
}

fn extract_folder_names(export: &Value) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let Some(folders) = export.get("folders").and_then(Value::as_array) else {
        return out;
    };
    for entry in folders {
        let Some(id) = entry.get("id").and_then(Value::as_str) else {
            continue;
        };
        let name = entry
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        out.insert(id.to_string(), name);
    }
    out
}

/// Core of the pipeline. Exposed `pub(crate)` so inline tests here can drive
/// it with an explicit folders map; the public API is [`dedup_items`] /
/// [`dedup_export`].
pub(crate) fn dedup_items_with_folders(
    items: &mut Vec<Value>,
    folders: &HashMap<String, String>,
) -> DedupStats {
    let total = items.len();

    // Pass 1: group by dedup key.
    let mut groups: HashMap<String, Vec<usize>> = HashMap::new();
    let mut skipped = 0usize;
    for (idx, item) in items.iter().enumerate() {
        if skip_from_dedup(item) {
            skipped += 1;
            continue;
        }
        groups.entry(dedup_key(item)).or_default().push(idx);
    }

    let mut dupe_groups: Vec<Vec<usize>> = groups
        .into_values()
        .filter(|v| v.len() > 1)
        .collect();
    dupe_groups.sort_by_key(|g| *g.first().unwrap_or(&0));

    // Pass 2: plan removals and build the merged-survivor value for each group.
    let mut to_drop: HashSet<usize> = HashSet::new();
    let mut audit_entries: Vec<Value> = Vec::new();
    let mut survivor_patches: Vec<(usize, SurvivorPatch)> = Vec::new();
    let mut total_merged = 0usize;

    for group in &dupe_groups {
        let mut ordered = group.clone();
        // Sort to pick survivor: longer passwordHistory > newer revisionDate
        // > newer creationDate. Using DESC ordering, so the winner sits at
        // index 0.
        ordered.sort_by(|a, b| {
            let a_hist = password_history_len(&items[*a]);
            let b_hist = password_history_len(&items[*b]);
            let a_rev = get_str(&items[*a], "revisionDate");
            let b_rev = get_str(&items[*b], "revisionDate");
            let a_cre = get_str(&items[*a], "creationDate");
            let b_cre = get_str(&items[*b], "creationDate");
            (b_hist, b_rev, b_cre).cmp(&(a_hist, a_rev, a_cre))
        });
        let keep_idx = ordered[0];
        let drop_idxs = &ordered[1..];

        let keep = &items[keep_idx];
        let drops: Vec<&Value> = drop_idxs.iter().map(|i| &items[*i]).collect();

        let patch = build_survivor_patch(keep, &drops, folders);
        let merged_here = patch.uri_additions.len();
        total_merged += merged_here;

        let keep_id = keep.get("id").cloned().unwrap_or(Value::Null);
        let keep_rev = keep.get("revisionDate").cloned().unwrap_or(Value::Null);
        let keep_folder = keep.get("folderId").cloned().unwrap_or(Value::Null);
        let keep_name_for_audit = Value::String(patch.longest_name.clone());

        for &di in drop_idxs {
            to_drop.insert(di);
            let dropped = &items[di];
            audit_entries.push(json!({
                "removed_id": dropped.get("id").cloned().unwrap_or(Value::Null),
                "removed_name": dropped.get("name").cloned().unwrap_or(Value::Null),
                "removed_username": dropped
                    .get("login").and_then(|l| l.get("username"))
                    .cloned().unwrap_or(Value::Null),
                "removed_revisionDate": dropped.get("revisionDate").cloned().unwrap_or(Value::Null),
                "removed_creationDate": dropped.get("creationDate").cloned().unwrap_or(Value::Null),
                "removed_folderId": dropped.get("folderId").cloned().unwrap_or(Value::Null),
                "kept_id": keep_id.clone(),
                "kept_name": keep_name_for_audit.clone(),
                "kept_revisionDate": keep_rev.clone(),
                "kept_folderId": keep_folder.clone(),
                "uris_merged_into_kept": merged_here,
            }));
        }

        survivor_patches.push((keep_idx, patch));
    }

    // Pass 3: apply merged fields to the surviving items.
    for (keep_idx, patch) in survivor_patches {
        apply_survivor_patch(&mut items[keep_idx], patch);
    }

    // Pass 4: filter out dropped items.
    let new_items: Vec<Value> = std::mem::take(items)
        .into_iter()
        .enumerate()
        .filter_map(|(i, v)| (!to_drop.contains(&i)).then_some(v))
        .collect();
    let output = new_items.len();
    let removed = total - output;
    *items = new_items;

    DedupStats {
        total,
        skipped,
        groups: dupe_groups.len(),
        removed,
        merged: total_merged,
        output,
        audit_entries,
    }
}

fn password_history_len(item: &Value) -> usize {
    item.get("passwordHistory")
        .and_then(Value::as_array)
        .map(Vec::len)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn empty_export_returns_zeroed_stats() {
        // `dedup_export` on a document missing `items` or with an empty
        // array must return zeroed stats without panicking.
        let mut no_items = json!({"folders": []});
        let s = dedup_export(&mut no_items);
        assert_eq!(s.total, 0);
        assert_eq!(s.removed, 0);
        assert_eq!(s.output, 0);

        let mut empty_items = json!({"folders": [], "items": []});
        let s = dedup_export(&mut empty_items);
        assert_eq!(s.total, 0);
    }

    #[test]
    fn extract_folder_names_handles_missing_or_malformed() {
        assert!(extract_folder_names(&json!({})).is_empty());
        assert!(extract_folder_names(&json!({"folders": null})).is_empty());
        let map = extract_folder_names(&json!({
            "folders": [
                {"id": "a", "name": "Alpha"},
                {"id": "b"},                 // missing name → stored as ""
                {"name": "no-id-dropped"},   // missing id → skipped
            ]
        }));
        assert_eq!(map.get("a"), Some(&"Alpha".to_string()));
        assert_eq!(map.get("b"), Some(&"".to_string()));
        assert!(map.get("no-id-dropped").is_none());
    }

    #[test]
    fn survivor_selection_longer_history_beats_newer_revision() {
        // `a` has richer passwordHistory but is older; `b` is newer but empty.
        // Longer history must win (primary tiebreaker).
        let mut items = vec![
            json!({
                "id": "aaaaaaaa",
                "type": 1, "name": "X",
                "revisionDate": "2025-01-01T00:00:00Z",
                "creationDate": "2024-01-01T00:00:00Z",
                "passwordHistory": [
                    {"lastUsedDate": "2024-06-01T00:00:00Z", "password": "old1"},
                    {"lastUsedDate": "2023-06-01T00:00:00Z", "password": "old2"},
                ],
                "login": {"username": "u", "password": "p"},
            }),
            json!({
                "id": "bbbbbbbb",
                "type": 1, "name": "X",
                "revisionDate": "2026-01-01T00:00:00Z",
                "creationDate": "2026-01-01T00:00:00Z",
                "login": {"username": "u", "password": "p"},
            }),
        ];
        dedup_items(&mut items);
        assert_eq!(items.len(), 1);
        assert_eq!(
            items[0].get("id").and_then(Value::as_str),
            Some("aaaaaaaa"),
            "item with longer passwordHistory must be the survivor"
        );
    }

    #[test]
    fn audit_entries_one_per_removed_item() {
        let mut items = vec![
            json!({
                "id": "a", "type": 1, "name": "X",
                "revisionDate": "2026-01-01T00:00:00Z",
                "login": {"username": "u", "password": "p"}
            }),
            json!({
                "id": "b", "type": 1, "name": "X",
                "revisionDate": "2026-02-01T00:00:00Z",
                "login": {"username": "u", "password": "p"}
            }),
            json!({
                "id": "c", "type": 1, "name": "X",
                "revisionDate": "2026-03-01T00:00:00Z",
                "login": {"username": "u", "password": "p"}
            }),
        ];
        let stats = dedup_items(&mut items);
        assert_eq!(stats.removed, 2);
        assert_eq!(stats.audit_entries.len(), 2);
    }
}
