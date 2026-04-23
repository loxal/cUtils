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
//! 4. Mark the losers with `deletedDate = now`. They **stay in the output
//!    array** — this is what makes them visible in Bitwarden's **Trash**
//!    folder after import so the user can audit every merge manually and
//!    recover anything they disagree with. No item is ever removed.
//!
//! **Survivor selection** is deterministic: longer `passwordHistory` wins
//! (captures more rotation history), then newer `revisionDate`, then newer
//! `creationDate`. That ordering is what keeps the merge safe — older
//! items with richer history aren't discarded in favour of a freshly-updated
//! stub.

use std::collections::{HashMap, HashSet};

use serde_json::{Value, json};

use crate::json_util::get_str;
use crate::key::{dedup_key, skip_from_dedup};
use crate::merge::{SurvivorPatch, apply_survivor_patch, build_survivor_patch};
use crate::time_util::iso8601_now;

/// Configuration knobs for a dedup run. Defaults match the documented
/// merge semantics; callers only set fields they want to diverge from.
#[derive(Debug, Clone, Default)]
pub struct DedupConfig {
    /// When `true`, items that differ only in `login.totp` stay as
    /// separate living items instead of collapsing with the
    /// newest-by-`revisionDate` pick.
    ///
    /// `revisionDate` is an item-level timestamp (touched by edits to
    /// notes, favorite flag, etc.), so it is an imperfect proxy for
    /// "which TOTP is currently valid on the backend". The default
    /// behavior (`false`) collapses the group and keeps the newest
    /// secret — the non-chosen TOTPs still reach the output inside
    /// their items' Trash entries, so they are recoverable. Set this
    /// to `true` if you would rather keep the duplicates than risk
    /// having the wrong live secret on the living survivor.
    pub split_divergent_totps: bool,
}

/// Summary of a [`dedup_items`] run.
///
/// Field meanings:
/// - `total`    — input item count
/// - `skipped`  — items passed through without being grouped (non-logins,
///                reprompt-gated, empty password, already tagged `[duplicate]`,
///                already-deleted items in the input)
/// - `groups`   — number of strict duplicate groups found
/// - `trashed`  — number of items freshly moved to Trash by this run
///                (dedup losers — they stay in the output array with
///                `deletedDate = now` so Bitwarden shows them in the Trash
///                folder after import; no item is ever removed)
/// - `merged`   — total URIs merged from dropped items into kept items
/// - `totp_conflict_groups` — groups that contained more than one distinct
///                non-empty TOTP (the sensitive case reviewers should
///                spot-check; every per-entry audit record carries a
///                `totp_conflict` flag for the same groups)
/// - `output`   — total items in the output array (always equals `total`,
///                because dedup no longer removes anything — it only trashes)
/// - `living`   — items in the output whose `deletedDate` is null, i.e.
///                items the user will see in the main Bitwarden view
/// - `audit_entries` — one JSON record per trashed item, suitable for
///                     writing alongside the deduplicated output
#[derive(Debug, Clone)]
pub struct DedupStats {
    pub total: usize,
    pub skipped: usize,
    pub groups: usize,
    pub trashed: usize,
    pub merged: usize,
    pub totp_conflict_groups: usize,
    pub output: usize,
    pub living: usize,
    pub audit_entries: Vec<Value>,
}

impl DedupStats {
    /// Backwards-compatible alias for [`Self::trashed`].  Earlier versions
    /// called this field `removed`, meaning "items dropped from the array";
    /// the semantics now are "items moved to Trash", but the count is the
    /// same so callers relying on the old name keep working.
    pub fn removed(&self) -> usize {
        self.trashed
    }
}

fn empty_stats_full() -> DedupStats {
    DedupStats {
        total: 0,
        skipped: 0,
        groups: 0,
        trashed: 0,
        merged: 0,
        totp_conflict_groups: 0,
        output: 0,
        living: 0,
        audit_entries: Vec::new(),
    }
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
    dedup_items_with_folders(items, &HashMap::new(), &DedupConfig::default())
}

/// Same as [`dedup_items`] but with an explicit [`DedupConfig`].
pub fn dedup_items_with_config(items: &mut Vec<Value>, config: &DedupConfig) -> DedupStats {
    dedup_items_with_folders(items, &HashMap::new(), config)
}

/// Run the full dedup pipeline on a complete Bitwarden export JSON value.
///
/// Accepts the parsed top-level object (the structure `{folders, items, …}`
/// that `bw export --format json` writes). Extracts the `folders` lookup,
/// dedups `items` in place, and returns the same [`DedupStats`] as
/// [`dedup_items`]. When the export has no `folders` array, behaves
/// identically to [`dedup_items`].
pub fn dedup_export(export: &mut Value) -> DedupStats {
    dedup_export_with_config(export, &DedupConfig::default())
}

/// Same as [`dedup_export`] but with an explicit [`DedupConfig`].
pub fn dedup_export_with_config(export: &mut Value, config: &DedupConfig) -> DedupStats {
    let folders = extract_folder_names(export);
    let Some(items_value) = export.get_mut("items") else {
        return empty_stats_full();
    };
    let Some(arr) = items_value.as_array_mut() else {
        return empty_stats_full();
    };
    let mut items = std::mem::take(arr);
    let stats = dedup_items_with_folders(&mut items, &folders, config);
    *arr = items;
    stats
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
/// [`dedup_export`] / [`dedup_items_with_config`] / [`dedup_export_with_config`].
pub(crate) fn dedup_items_with_folders(
    items: &mut Vec<Value>,
    folders: &HashMap<String, String>,
    config: &DedupConfig,
) -> DedupStats {
    let total = items.len();

    // Pass 1: group by dedup key. When `split_divergent_totps` is set,
    // append the item's TOTP to the group key so items with different
    // TOTPs never share a group — they stay as separate living items.
    let mut groups: HashMap<String, Vec<usize>> = HashMap::new();
    let mut skipped = 0usize;
    for (idx, item) in items.iter().enumerate() {
        if skip_from_dedup(item) {
            skipped += 1;
            continue;
        }
        let base_key = dedup_key(item);
        let key = if config.split_divergent_totps {
            let totp = item
                .get("login")
                .and_then(|l| l.get("totp"))
                .and_then(Value::as_str)
                .unwrap_or("");
            format!("{base_key}\0totp={totp}")
        } else {
            base_key
        };
        groups.entry(key).or_default().push(idx);
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
    let mut totp_conflict_groups = 0usize;

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
        if patch.totp.conflict {
            totp_conflict_groups += 1;
        }

        let keep_id = keep.get("id").cloned().unwrap_or(Value::Null);
        let keep_rev = keep.get("revisionDate").cloned().unwrap_or(Value::Null);
        let keep_folder = keep.get("folderId").cloned().unwrap_or(Value::Null);
        let keep_name_for_audit = Value::String(patch.longest_name.clone());
        let totp_conflict = patch.totp.conflict;
        let totp_kept_from_id = patch
            .totp
            .chosen_from_id
            .as_ref()
            .map(|s| Value::String(s.clone()))
            .unwrap_or(Value::Null);
        let fields_merged_count = patch.field_additions.len();
        let collections_merged_count = patch.collection_additions.len();
        let folder_note_added = patch.folder_note_line.is_some();
        let notes_merged_flag = patch.notes_merged;

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
                "removed_totp_present": dropped
                    .get("login").and_then(|l| l.get("totp"))
                    .and_then(Value::as_str)
                    .map(|s| !s.is_empty()).unwrap_or(false),
                "kept_id": keep_id.clone(),
                "kept_name": keep_name_for_audit.clone(),
                "kept_revisionDate": keep_rev.clone(),
                "kept_folderId": keep_folder.clone(),
                "uris_merged_into_kept": merged_here,
                // Merge-sensitivity flags — let reviewers grep risky cases.
                "totp_conflict": totp_conflict,
                "totp_kept_from_id": totp_kept_from_id.clone(),
                "notes_merged": notes_merged_flag,
                "fields_merged": fields_merged_count,
                "collections_merged": collections_merged_count,
                "folder_note_added": folder_note_added,
            }));
        }

        survivor_patches.push((keep_idx, patch));
    }

    // Pass 3: apply merged fields to the surviving items.
    for (keep_idx, patch) in survivor_patches {
        apply_survivor_patch(&mut items[keep_idx], patch);
    }

    // Pass 4: mark losers with `deletedDate = now`. They stay in the array
    // so Bitwarden surfaces them in the Trash folder after import. Nothing
    // is ever removed — the user can manually recover any false positive.
    let now = iso8601_now();
    for (i, item) in items.iter_mut().enumerate() {
        if to_drop.contains(&i)
            && let Some(obj) = item.as_object_mut()
        {
            obj.insert("deletedDate".to_string(), Value::String(now.clone()));
        }
    }
    let trashed = to_drop.len();
    let output = items.len();
    let living = items
        .iter()
        .filter(|v| {
            v.get("deletedDate")
                .map(Value::is_null)
                .unwrap_or(true)
        })
        .count();

    DedupStats {
        total,
        skipped,
        groups: dupe_groups.len(),
        trashed,
        merged: total_merged,
        totp_conflict_groups,
        output,
        living,
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
        assert_eq!(s.trashed, 0);
        assert_eq!(s.output, 0);
        assert_eq!(s.living, 0);

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
        // Both items still in array; loser is trashed, survivor is living.
        assert_eq!(items.len(), 2);
        let living: Vec<&Value> = items.iter().filter(|i| i["deletedDate"].is_null()).collect();
        assert_eq!(living.len(), 1);
        assert_eq!(
            living[0].get("id").and_then(Value::as_str),
            Some("aaaaaaaa"),
            "item with longer passwordHistory must be the living survivor"
        );
        let trashed: Vec<&Value> = items.iter().filter(|i| !i["deletedDate"].is_null()).collect();
        assert_eq!(trashed.len(), 1);
        assert_eq!(
            trashed[0].get("id").and_then(Value::as_str),
            Some("bbbbbbbb"),
            "loser must stay in the array with deletedDate set"
        );
    }

    #[test]
    fn audit_entries_one_per_trashed_item() {
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
        assert_eq!(stats.trashed, 2);
        assert_eq!(stats.audit_entries.len(), 2);
        assert_eq!(stats.living, 1, "one survivor, two trashed");
        assert_eq!(stats.output, 3, "array still holds all three");
    }

    #[test]
    fn split_divergent_totps_keeps_items_separate() {
        // With the opt-in flag set, two items identical on name/user/pw but
        // differing only in TOTP stay as separate living items instead of
        // collapsing. This protects against a bad revisionDate heuristic
        // picking the wrong secret for the survivor.
        let mut items = vec![
            json!({
                "id": "with-old", "type": 1, "name": "Acme",
                "revisionDate": "2026-02-01T00:00:00Z",
                "login": {"username": "u", "password": "p",
                    "totp": "otpauth://totp/A?secret=OLD"}
            }),
            json!({
                "id": "with-new", "type": 1, "name": "Acme",
                "revisionDate": "2026-01-01T00:00:00Z",
                "login": {"username": "u", "password": "p",
                    "totp": "otpauth://totp/A?secret=NEW"}
            }),
        ];
        let stats = dedup_items_with_config(
            &mut items,
            &DedupConfig {
                split_divergent_totps: true,
            },
        );
        assert_eq!(stats.trashed, 0, "divergent TOTPs must not collapse");
        assert_eq!(stats.groups, 0);
        assert_eq!(
            items.iter().filter(|i| i["deletedDate"].is_null()).count(),
            2,
            "both items stay living"
        );
    }

    #[test]
    fn divergent_totp_group_collapses_by_default_with_conflict_flag() {
        // Default config: the group collapses and the survivor gets the
        // newest TOTP by revisionDate. But `totp_conflict` is surfaced on
        // every audit entry for the group so reviewers can find it.
        let mut items = vec![
            json!({
                "id": "older", "type": 1, "name": "Acme",
                "revisionDate": "2025-01-01T00:00:00Z",
                "login": {"username": "u", "password": "p",
                    "totp": "otpauth://totp/A?secret=OLD"}
            }),
            json!({
                "id": "newer", "type": 1, "name": "Acme",
                "revisionDate": "2026-06-01T00:00:00Z",
                "login": {"username": "u", "password": "p",
                    "totp": "otpauth://totp/A?secret=NEW"}
            }),
        ];
        let stats = dedup_items(&mut items);
        assert_eq!(stats.groups, 1);
        assert_eq!(stats.trashed, 1);
        assert_eq!(stats.totp_conflict_groups, 1);
        assert_eq!(stats.audit_entries.len(), 1);
        let entry = &stats.audit_entries[0];
        assert_eq!(entry["totp_conflict"], true);
        assert_eq!(entry["totp_kept_from_id"], "newer");
        assert_eq!(entry["removed_totp_present"], true);
    }

    #[test]
    fn audit_entry_has_merge_sensitivity_flags() {
        // When a merge pulls in a distinct note / custom field / collection
        // from a drop, the audit entry for that drop records it so a reviewer
        // can spot which groups had non-trivial merges.
        let mut items = vec![
            json!({
                "id": "keep", "type": 1, "name": "X",
                "organizationId": "org-1",
                "collectionIds": ["c-A"],
                "notes": "note-from-keep",
                "revisionDate": "2026-02-01T00:00:00Z",
                "login": {"username": "u", "password": "p"}
            }),
            json!({
                "id": "drop", "type": 1, "name": "X",
                "organizationId": "org-1",
                "collectionIds": ["c-B"],
                "notes": "note-from-drop",
                "fields": [{"name": "q", "value": "r", "type": 0}],
                "revisionDate": "2026-01-01T00:00:00Z",
                "login": {"username": "u", "password": "p"}
            }),
        ];
        let stats = dedup_items(&mut items);
        assert_eq!(stats.audit_entries.len(), 1);
        let entry = &stats.audit_entries[0];
        assert_eq!(entry["removed_id"], "drop");
        assert_eq!(entry["notes_merged"], true);
        assert_eq!(entry["fields_merged"], 1);
        assert_eq!(entry["collections_merged"], 1);
        assert_eq!(entry["folder_note_added"], false);
        assert_eq!(entry["totp_conflict"], false);
    }

    #[test]
    fn already_trashed_items_pass_through_untouched() {
        // Items that arrive with `deletedDate` set must be preserved
        // as-is — they are the user's existing Trash.
        let mut items = vec![
            json!({
                "id": "already-trash", "type": 1, "name": "Old",
                "deletedDate": "2025-01-01T00:00:00Z",
                "revisionDate": "2024-12-01T00:00:00Z",
                "login": {"username": "u", "password": "p"}
            }),
            json!({
                "id": "live", "type": 1, "name": "Live",
                "revisionDate": "2026-02-01T00:00:00Z",
                "login": {"username": "u2", "password": "p2"}
            }),
        ];
        dedup_items(&mut items);
        assert_eq!(items.len(), 2);
        let trashed = items
            .iter()
            .find(|i| i["id"].as_str() == Some("already-trash"))
            .unwrap();
        assert_eq!(
            trashed["deletedDate"].as_str(),
            Some("2025-01-01T00:00:00Z"),
            "pre-existing deletedDate must not be overwritten"
        );
    }
}
