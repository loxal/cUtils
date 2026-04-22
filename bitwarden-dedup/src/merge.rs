// Copyright 2026 Alexander Orlov <alexander.orlov@loxal.net>

//! **"What data is merged into the survivor?"** — survivor patching.
//!
//! Once [`crate::pipeline`] has decided which item in a duplicate group
//! survives, this module computes the full set of mutations that need to be
//! applied to that survivor so nothing from the dropped items is silently
//! lost. Every multi-valued or concatenable field that is deliberately kept
//! out of the dedup key (see [`crate::key`]) has a merge rule here.
//!
//! Rules at a glance:
//!
//! - **notes** — union of distinct trimmed bodies; raw whitespace preserved
//! - **URIs** — union by `(uri, match_mode)` (see [`crate::uris`])
//! - **passwordHistory** — union by `(lastUsedDate, password)`, newest first
//! - **custom fields** — union by `(name, value, type, linkedId)` tuple
//! - **collectionIds** — set union (Bitwarden supports multi-collection)
//! - **folderId** — single-valued, so survivor's wins; differing drops
//!   contribute a `[bitwarden-dedup] originally also in folder: …` note line
//! - **favorite** — logical OR
//! - **name** — longest raw name in the group (ties keep survivor's)

use std::collections::{HashMap, HashSet};

use serde_json::Value;

use crate::json_util::get_str;
use crate::uris::uris_to_merge;

/// All mutations that need to be applied to a surviving item once its
/// duplicate group has been decided.
pub(crate) struct SurvivorPatch {
    pub(crate) longest_name: String,
    pub(crate) notes: Option<String>,
    pub(crate) uri_additions: Vec<Value>,
    pub(crate) password_history_additions: Vec<Value>,
    pub(crate) field_additions: Vec<Value>,
    pub(crate) collection_additions: Vec<String>,
    /// Folder labels from dropped items whose `folderId` differs from the
    /// survivor's. Prepended to notes on import so the placement hint is
    /// preserved even though Bitwarden allows only one folder per item.
    pub(crate) folder_note_line: Option<String>,
    pub(crate) favorite: bool,
}

pub(crate) fn build_survivor_patch(
    keep: &Value,
    drops: &[&Value],
    folders: &HashMap<String, String>,
) -> SurvivorPatch {
    // 1. Name: pick the longest original (raw, pre-normalization) name across
    //    the group. Ties are broken by keeping the survivor's own name so we
    //    do not churn the item for cosmetic reasons.
    let keep_name = get_str(keep, "name").to_string();
    let mut longest_name = keep_name.clone();
    for d in drops {
        let dn = get_str(d, "name");
        if dn.chars().count() > longest_name.chars().count() {
            longest_name = dn.to_string();
        }
    }

    // 2. Notes: union of distinct non-empty note bodies, joined by a visible
    //    separator so a reader can tell they came from separate items. The
    //    raw note body is preserved — dedup keys normalize via trim, but the
    //    stored text is left byte-identical to its source.
    let notes = merge_notes(keep, drops);

    // 3. URIs: adds (uri, match_mode) pairs missing on keep.
    let uri_additions = uris_to_merge(keep, drops);

    // 4. passwordHistory: union keyed by (lastUsedDate, password), sorted
    //    newest first. Bitwarden emits these item-level entries so each
    //    rotation is preserved across merges.
    let password_history_additions = password_history_to_merge(keep, drops);

    // 5. Custom fields: union by full field tuple (name, value, type,
    //    linkedId). Linked-Username and Linked-Password fields with the same
    //    label are preserved as separate entries because their `linkedId`
    //    differs.
    let field_additions = fields_to_merge(keep, drops);

    // 6. collectionIds: union across the group. Bitwarden natively supports
    //    multiple collection memberships, so unioning is lossless.
    let collection_additions = collections_to_merge(keep, drops);

    // 7. folderId: single-valued — the survivor's folder wins. When drops
    //    sat in a different folder, emit a note line so the user still knows
    //    after import.
    let folder_note_line = folder_disambiguation_note(keep, drops, folders);

    // 8. Favorite: any item favorited → merged item favorited.
    let favorite = item_is_favorite(keep) || drops.iter().any(|d| item_is_favorite(d));

    SurvivorPatch {
        longest_name,
        notes,
        uri_additions,
        password_history_additions,
        field_additions,
        collection_additions,
        folder_note_line,
        favorite,
    }
}

pub(crate) fn apply_survivor_patch(item: &mut Value, patch: SurvivorPatch) {
    // Assemble the final notes: folder disambiguation line (if any) prepended
    // to the merged note body so it reads top-to-bottom after import.
    let final_notes = match (patch.folder_note_line.as_deref(), patch.notes.as_deref()) {
        (Some(line), Some(body)) if !body.is_empty() => Some(format!("{line}\n{body}")),
        (Some(line), _) => Some(line.to_string()),
        (None, Some(body)) if !body.is_empty() => Some(body.to_string()),
        _ => None,
    };

    if let Some(obj) = item.as_object_mut() {
        // Name.
        obj.insert("name".to_string(), Value::String(patch.longest_name));

        // Notes.
        if let Some(merged) = final_notes {
            obj.insert("notes".to_string(), Value::String(merged));
        }

        // Favorite.
        obj.insert("favorite".to_string(), Value::Bool(patch.favorite));

        // passwordHistory: append additions to existing array.
        if !patch.password_history_additions.is_empty() {
            let mut hist = obj
                .get("passwordHistory")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            hist.extend(patch.password_history_additions);
            // Sort newest first by lastUsedDate (descending).
            hist.sort_by(|a, b| {
                let a_d = a.get("lastUsedDate").and_then(Value::as_str).unwrap_or("");
                let b_d = b.get("lastUsedDate").and_then(Value::as_str).unwrap_or("");
                b_d.cmp(a_d)
            });
            obj.insert("passwordHistory".to_string(), Value::Array(hist));
        }

        // Custom fields: append additions to existing array.
        if !patch.field_additions.is_empty() {
            let mut fields = obj
                .get("fields")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            fields.extend(patch.field_additions);
            obj.insert("fields".to_string(), Value::Array(fields));
        }

        // collectionIds: union of keep's set and dropped additions. The
        // Bitwarden schema uses `null` when an item is not in any collection,
        // but also accepts an array. Normalize to an array only when we have
        // something to add or keep already had an array.
        if !patch.collection_additions.is_empty() {
            let mut cols: Vec<Value> = obj
                .get("collectionIds")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            for id in patch.collection_additions {
                cols.push(Value::String(id));
            }
            obj.insert("collectionIds".to_string(), Value::Array(cols));
        }
    }

    // URIs: merged into login.uris.
    if let Some(login) = item.get_mut("login").and_then(Value::as_object_mut) {
        if !patch.uri_additions.is_empty() {
            let mut uris = login
                .get("uris")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            uris.extend(patch.uri_additions);
            login.insert("uris".to_string(), Value::Array(uris));
        }
    }
}

fn item_is_favorite(item: &Value) -> bool {
    item.get("favorite").and_then(Value::as_bool).unwrap_or(false)
}

/// Merge notes from `keep` and `drops` into a single string.
///
/// Uses the trimmed note body as the dedup key, but stores the **raw**
/// original body in the output so any meaningful leading/trailing whitespace
/// is preserved. When two items carry notes that differ only in surrounding
/// whitespace, the first one encountered (survivor's, then each drop in order)
/// wins and its raw formatting is kept.
///
/// Returns `None` when every note is empty/missing.
fn merge_notes(keep: &Value, drops: &[&Value]) -> Option<String> {
    let mut seen: HashSet<String> = HashSet::new();
    let mut ordered: Vec<String> = Vec::new();
    let push = |raw: &str, seen: &mut HashSet<String>, ordered: &mut Vec<String>| {
        let key = raw.trim();
        if !key.is_empty() && seen.insert(key.to_string()) {
            ordered.push(raw.to_string());
        }
    };
    push(get_str(keep, "notes"), &mut seen, &mut ordered);
    for d in drops {
        push(get_str(d, "notes"), &mut seen, &mut ordered);
    }
    if ordered.is_empty() {
        None
    } else {
        Some(ordered.join("\n---\n"))
    }
}

/// Return `collectionIds` from `drops` that are missing on `keep`.
///
/// Bitwarden items can belong to multiple collections, so the union is
/// lossless — whichever collections the group's items were visible in stays
/// visible on the survivor.
fn collections_to_merge(keep: &Value, drops: &[&Value]) -> Vec<String> {
    let mut seen: HashSet<String> = HashSet::new();
    if let Some(arr) = keep.get("collectionIds").and_then(Value::as_array) {
        for v in arr {
            if let Some(s) = v.as_str() {
                seen.insert(s.to_string());
            }
        }
    }
    let mut out: Vec<String> = Vec::new();
    for d in drops {
        let Some(arr) = d.get("collectionIds").and_then(Value::as_array) else {
            continue;
        };
        for v in arr {
            if let Some(s) = v.as_str()
                && seen.insert(s.to_string())
            {
                out.push(s.to_string());
            }
        }
    }
    out
}

/// Emit a single-line note listing folders from dropped items that differ
/// from the survivor's folder, or `None` when every drop shared the
/// survivor's folder (nothing to preserve).
///
/// When a folder-id lookup is available, human-readable folder names are
/// used. Otherwise the raw UUIDs appear so no information is silently lost.
fn folder_disambiguation_note(
    keep: &Value,
    drops: &[&Value],
    folders: &HashMap<String, String>,
) -> Option<String> {
    let keep_folder = keep.get("folderId").and_then(Value::as_str);
    let mut seen: HashSet<String> = HashSet::new();
    let mut extras: Vec<String> = Vec::new();
    for d in drops {
        let df = d.get("folderId").and_then(Value::as_str);
        if df == keep_folder {
            continue;
        }
        let Some(fid) = df else {
            continue;
        };
        if !seen.insert(fid.to_string()) {
            continue;
        }
        let display = folders
            .get(fid)
            .cloned()
            .unwrap_or_else(|| fid.to_string());
        extras.push(display);
    }
    if extras.is_empty() {
        None
    } else {
        let plural = if extras.len() == 1 { "" } else { "s" };
        Some(format!(
            "[bitwarden-dedup] originally also in folder{plural}: {}",
            extras.join(", ")
        ))
    }
}

/// Return passwordHistory entries from `drops` that are missing on `keep`.
/// Dedup key is `(lastUsedDate, password)`.
fn password_history_to_merge(keep: &Value, drops: &[&Value]) -> Vec<Value> {
    let mut seen: HashSet<(String, String)> = HashSet::new();
    for entry in keep
        .get("passwordHistory")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        seen.insert(password_history_key(entry));
    }
    let mut out: Vec<Value> = Vec::new();
    for d in drops {
        let Some(arr) = d.get("passwordHistory").and_then(Value::as_array) else {
            continue;
        };
        for entry in arr {
            if seen.insert(password_history_key(entry)) {
                out.push(entry.clone());
            }
        }
    }
    out
}

fn password_history_key(entry: &Value) -> (String, String) {
    let date = entry
        .get("lastUsedDate")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let pw = entry
        .get("password")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    (date, pw)
}

/// Return custom fields from `drops` that are missing on `keep`, keyed by the
/// full `(name, value, type, linkedId)` tuple so Linked-Username and
/// Linked-Password variants of the same label both survive.
fn fields_to_merge(keep: &Value, drops: &[&Value]) -> Vec<Value> {
    let mut seen: HashSet<(String, String, i64, i64)> = HashSet::new();
    for entry in keep
        .get("fields")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        seen.insert(field_key(entry));
    }
    let mut out: Vec<Value> = Vec::new();
    for d in drops {
        let Some(arr) = d.get("fields").and_then(Value::as_array) else {
            continue;
        };
        for entry in arr {
            if seen.insert(field_key(entry)) {
                out.push(entry.clone());
            }
        }
    }
    out
}

fn field_key(entry: &Value) -> (String, String, i64, i64) {
    (
        entry
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        entry
            .get("value")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        entry.get("type").and_then(Value::as_i64).unwrap_or(0),
        entry.get("linkedId").and_then(Value::as_i64).unwrap_or(-1),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn merge_notes_preserves_leading_trailing_whitespace_of_survivor() {
        let keep = json!({"notes": "  indented note  "});
        let drops = [&json!({"notes": "other"})];
        let merged = merge_notes(&keep, &drops).expect("merge yields Some");
        assert!(
            merged.starts_with("  indented note  "),
            "survivor's leading/trailing whitespace must be preserved; got {merged:?}"
        );
        assert!(merged.contains("other"), "drop's body must be merged too");
    }

    #[test]
    fn merge_notes_deduplicates_on_trimmed_body_but_keeps_first_raw() {
        let keep = json!({"notes": "Hello"});
        let drops = [&json!({"notes": "  Hello  "})];
        let merged = merge_notes(&keep, &drops).expect("merge yields Some");
        assert_eq!(merged, "Hello");
        let keep = json!({"notes": "  Hello  "});
        let drops = [&json!({"notes": "Hello"})];
        let merged = merge_notes(&keep, &drops).expect("merge yields Some");
        assert_eq!(merged, "  Hello  ");
    }

    #[test]
    fn password_history_key_distinguishes_date_and_password() {
        let a = json!({"lastUsedDate": "2025-01-01T00:00:00Z", "password": "pw1"});
        let b = json!({"lastUsedDate": "2025-01-01T00:00:00Z", "password": "pw2"});
        let c = json!({"lastUsedDate": "2024-01-01T00:00:00Z", "password": "pw1"});
        assert_eq!(password_history_key(&a), password_history_key(&a));
        assert_ne!(password_history_key(&a), password_history_key(&b));
        assert_ne!(password_history_key(&a), password_history_key(&c));
    }

    #[test]
    fn field_key_distinguishes_linked_targets() {
        // Two Linked fields with the same label must not collapse just
        // because their `value` is null — `linkedId` (100 vs 101) is what
        // separates Linked-Username from Linked-Password.
        let linked_user = json!({"name": "Autofill", "value": null, "type": 3, "linkedId": 100});
        let linked_pass = json!({"name": "Autofill", "value": null, "type": 3, "linkedId": 101});
        assert_ne!(field_key(&linked_user), field_key(&linked_pass));
    }
}
