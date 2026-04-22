// Copyright 2026 Alexander Orlov <alexander.orlov@loxal.net>

//! Shared helpers for the `bitwarden-dedup` binaries.
//!
//! Both the main `bitwarden-dedup` binary and the `bitwarden-redact` binary
//! need to agree on what constitutes a "duplicate" in a Bitwarden export.
//! This module is the single source of truth for that decision:
//!
//! - [`dedup_key`]         — the strict equality key used to group items
//! - [`skip_from_dedup`]   — items that are never grouped (non-logins,
//!                           reprompt-gated, empty passwords, already-tagged
//!                           duplicates, deleted items)
//! - [`uri_pairs`]         — `(uri, match_mode)` set for a login item
//! - [`uris_to_merge`]     — returns URI values from dropped items that are
//!                           missing from the kept item, keyed by
//!                           `(uri, match_mode)` so distinct match detection
//!                           modes are preserved
//! - [`dedup_items`]       — the end-to-end dedup pipeline. Mutates a
//!                           `Vec<Value>` in place (drops items, merges URIs
//!                           into kept items) and returns a [`DedupStats`]
//!                           summary including per-removal audit entries.
//!
//! URIs are treated as opaque strings with no case folding. That matters for
//! `androidapp://` URIs where the package-name segment is case-sensitive by
//! Android spec.

use std::collections::{HashMap, HashSet};

use serde_json::{Value, json};

/// Duplicate-equality key for a Bitwarden login item.
///
/// **Invariant**: the key contains every field that Bitwarden stores as a
/// single-valued slot. Items that disagree on any of these fields end up in
/// different groups, so no single-valued user data is ever overwritten or
/// silently discarded by dedup. In particular:
///
/// - Distinct `(username, password)` pairs are never collapsed.
/// - Distinct TOTP secrets are never collapsed (including empty-vs-non-empty).
/// - Distinct FIDO2 credential sets are never collapsed.
/// - Personal items never merge with org-owned items.
///
/// The key:
/// - name                  (case-insensitive, trimmed, with trailing
///                          ` (email@address)` disambiguation suffix stripped —
///                          see [`normalize_name`])
/// - username              (trimmed only — case is preserved, because some
///                          systems treat usernames as case-sensitive)
/// - password              (exact)
/// - TOTP secret           (exact)
/// - FIDO2 credentials     (canonicalized full objects, not just credentialIds —
///                          divergent metadata keeps items distinct)
/// - organizationId        (personal vs org)
///
/// Notes, custom fields, favorite flag, URIs, passwordHistory, and
/// `collectionIds` are NOT in the key — they are multi-valued or concatenable,
/// so [`dedup_items`] union-merges them into the surviving item.
///
/// `folderId` is NOT in the key either. Bitwarden items can only sit in one
/// folder, so a union is not possible; instead, when drops differ from the
/// survivor's folder, their folder ids are appended to the survivor's notes
/// as a disambiguation line. No user-entered data is lost.
pub fn dedup_key(item: &Value) -> String {
    let name = normalize_name(get_str(item, "name"));
    let login = item.get("login");
    let user = norm_user(
        login
            .and_then(|l| l.get("username"))
            .and_then(Value::as_str)
            .unwrap_or(""),
    );
    let pw = login
        .and_then(|l| l.get("password"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let totp = login
        .and_then(|l| l.get("totp"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let fido2 = fido2_signature(item);
    let org_id = item
        .get("organizationId")
        .and_then(Value::as_str)
        .unwrap_or("");
    format!("{name}\0{user}\0{pw}\0{totp}\0{fido2}\0{org_id}")
}

/// Strip a trailing ` (something@else)` disambiguation suffix from a name and
/// lowercase the result.
///
/// Some Bitwarden clients append `(username)` to the name when two items share
/// the base name — e.g. `fastly-eng.okta.com` and
/// `fastly-eng.okta.com (aorlov@fastly.com)` are the same login with the
/// second entry carrying a cosmetic suffix. Without this normalization the two
/// entries would never group as duplicates.
///
/// Only suffixes whose parenthesized body contains `@` are stripped — plain
/// suffixes like `(prod)` or `(staging)` are kept because they convey a real
/// distinction.
pub fn normalize_name(s: &str) -> String {
    let trimmed = s.trim();
    if trimmed.ends_with(')') {
        if let Some(open) = trimmed.rfind('(') {
            let inner = &trimmed[open + 1..trimmed.len() - 1];
            if inner.contains('@') {
                return trimmed[..open].trim_end().to_lowercase();
            }
        }
    }
    trimmed.to_lowercase()
}

/// Return `true` for items that must never be grouped for deduplication.
///
/// This is the safety floor: non-login types pass through unchanged,
/// master-password-gated items are left alone, empty-password items would
/// spuriously group on `""`, and anything already tagged `[duplicate]` or
/// sitting in the trash is skipped.
pub fn skip_from_dedup(item: &Value) -> bool {
    if item.get("type").and_then(Value::as_u64) != Some(1) {
        return true;
    }
    if item.get("deletedDate").is_some_and(|v| !v.is_null()) {
        return true;
    }
    if item.get("reprompt").and_then(Value::as_u64) == Some(1) {
        return true;
    }
    if get_str(item, "name").contains("[duplicate]") {
        return true;
    }
    let pw = item
        .get("login")
        .and_then(|l| l.get("password"))
        .and_then(Value::as_str)
        .unwrap_or("");
    pw.trim().is_empty()
}

/// Collect every `(uri, match_mode)` pair on a login item.
///
/// The match mode is carried as `Option<i64>` so `match: null` (inherit
/// default) is distinguished from `match: 0` (explicit Base domain). This
/// preserves user intent when merging URIs across duplicate items.
pub fn uri_pairs(item: &Value) -> HashSet<(String, Option<i64>)> {
    item.get("login")
        .and_then(|l| l.get("uris"))
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|u| {
                    let uri = u.get("uri").and_then(Value::as_str)?.to_string();
                    let match_mode = u.get("match").and_then(Value::as_i64);
                    Some((uri, match_mode))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Return the URI entries from `drops` that are missing from `keep`.
///
/// Keyed by `(uri, match_mode)` so the same URI string with different match
/// detection modes is preserved rather than collapsed. Pure function — it
/// clones the URI values it returns and never mutates its inputs.
pub fn uris_to_merge(keep: &Value, drops: &[&Value]) -> Vec<Value> {
    let mut seen: HashSet<(String, Option<i64>)> = uri_pairs(keep);
    let mut out: Vec<Value> = Vec::new();
    for d in drops {
        let Some(arr) = d
            .get("login")
            .and_then(|l| l.get("uris"))
            .and_then(Value::as_array)
        else {
            continue;
        };
        for u in arr {
            let Some(url) = u.get("uri").and_then(Value::as_str) else {
                continue;
            };
            let match_mode = u.get("match").and_then(Value::as_i64);
            let key = (url.to_string(), match_mode);
            if seen.insert(key) {
                out.push(u.clone());
            }
        }
    }
    out
}

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
        return DedupStats {
            total: 0,
            skipped: 0,
            groups: 0,
            removed: 0,
            merged: 0,
            output: 0,
            audit_entries: Vec::new(),
        };
    };
    let Some(arr) = items_value.as_array_mut() else {
        return DedupStats {
            total: 0,
            skipped: 0,
            groups: 0,
            removed: 0,
            merged: 0,
            output: 0,
            audit_entries: Vec::new(),
        };
    };
    let mut items = std::mem::take(arr);
    let stats = dedup_items_with_folders(&mut items, &folders);
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

fn dedup_items_with_folders(
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

/// All mutations that need to be applied to a surviving item once its
/// duplicate group has been decided.
struct SurvivorPatch {
    longest_name: String,
    notes: Option<String>,
    uri_additions: Vec<Value>,
    password_history_additions: Vec<Value>,
    field_additions: Vec<Value>,
    collection_additions: Vec<String>,
    /// Folder labels from dropped items whose `folderId` differs from the
    /// survivor's. Prepended to notes on import so the placement hint is
    /// preserved even though Bitwarden allows only one folder per item.
    folder_note_line: Option<String>,
    favorite: bool,
}

fn build_survivor_patch(
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

    // 3. URIs: existing merger — adds (uri, match_mode) pairs missing on keep.
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

fn apply_survivor_patch(item: &mut Value, patch: SurvivorPatch) {
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

    // URIs: unchanged — merged into login.uris.
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

fn password_history_len(item: &Value) -> usize {
    item.get("passwordHistory")
        .and_then(Value::as_array)
        .map(Vec::len)
        .unwrap_or(0)
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
    for entry in keep.get("passwordHistory").and_then(Value::as_array).into_iter().flatten() {
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
    for entry in keep.get("fields").and_then(Value::as_array).into_iter().flatten() {
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
        entry.get("name").and_then(Value::as_str).unwrap_or("").to_string(),
        entry.get("value").and_then(Value::as_str).unwrap_or("").to_string(),
        entry.get("type").and_then(Value::as_i64).unwrap_or(0),
        entry.get("linkedId").and_then(Value::as_i64).unwrap_or(-1),
    )
}

/// Shorthand for reading an item's string field with a default of `""`.
pub(crate) fn get_str<'a>(item: &'a Value, key: &str) -> &'a str {
    item.get(key).and_then(Value::as_str).unwrap_or("")
}

/// Trim-only normalization for usernames. Case is preserved so
/// `Alice` and `alice` — which some backends treat as distinct
/// login identities — never collapse into the same dedup group.
fn norm_user(s: &str) -> String {
    s.trim().to_string()
}

/// Canonical signature of an item's FIDO2 / passkey credentials.
///
/// Includes the **entire** credential object (not just `credentialId`) so that
/// two items carrying the same `credentialId` but divergent metadata
/// (`counter`, `userHandle`, `keyType`, etc.) end up in different groups.
/// That keeps their metadata from being silently overwritten by the survivor.
///
/// Objects are sorted by `credentialId` first, then serialized. Any
/// non-deterministic key ordering inside a credential object yields a
/// different signature — that is deliberately conservative: when in doubt,
/// don't merge.
fn fido2_signature(item: &Value) -> String {
    let mut creds: Vec<Value> = item
        .get("login")
        .and_then(|l| l.get("fido2Credentials"))
        .and_then(Value::as_array)
        .map(|arr| arr.to_vec())
        .unwrap_or_default();
    creds.sort_by(|a, b| {
        let a_id = a.get("credentialId").and_then(Value::as_str).unwrap_or("");
        let b_id = b.get("credentialId").and_then(Value::as_str).unwrap_or("");
        a_id.cmp(b_id)
    });
    serde_json::to_string(&Value::Array(creds)).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn login(name: &str, user: &str, pw: &str) -> Value {
        json!({
            "type": 1,
            "name": name,
            "login": { "username": user, "password": pw },
        })
    }

    #[test]
    fn norm_user_trims_but_preserves_case() {
        // Usernames: trim only. Case is identity-significant on some systems
        // (Unix logins, legacy POSIX accounts), so `Alice` must not fold into
        // `alice`.
        assert_eq!(norm_user("  Alice "), "Alice");
        assert_eq!(norm_user("alice"), "alice");
        assert_ne!(norm_user("Alice"), norm_user("alice"));
        assert_eq!(norm_user(""), "");
    }

    #[test]
    fn dedup_key_matches_identical_items() {
        // Name is case-insensitive (display label).  Username is trim-only
        // (identity), so test with matching case to exercise the positive
        // path — divergent username case is covered by a dedicated test.
        let a = login("GitHub", "a@b.com", "pw1");
        let b = login(" github ", "a@b.com", "pw1");
        assert_eq!(dedup_key(&a), dedup_key(&b));
    }

    #[test]
    fn dedup_key_differs_on_username_case() {
        // `Alice` and `alice` represent different logins on case-sensitive
        // backends. They must not collapse even when every other field matches.
        let a = login("Site", "Alice", "pw");
        let b = login("Site", "alice", "pw");
        assert_ne!(
            dedup_key(&a),
            dedup_key(&b),
            "usernames differing only in case must stay separate"
        );
    }

    #[test]
    fn dedup_key_differs_on_password() {
        let a = login("GitHub", "a@b.com", "pw1");
        let b = login("GitHub", "a@b.com", "pw2");
        assert_ne!(dedup_key(&a), dedup_key(&b));
    }

    #[test]
    fn dedup_key_differs_on_username() {
        // Distinct usernames must never group — different login identities.
        let a = login("Site", "alice@b.com", "pw");
        let b = login("Site", "bob@b.com", "pw");
        assert_ne!(
            dedup_key(&a),
            dedup_key(&b),
            "items with distinct usernames must stay separate"
        );
    }

    #[test]
    fn dedup_key_differs_on_totp() {
        let mut a = login("GitHub", "a@b.com", "pw");
        let mut b = login("GitHub", "a@b.com", "pw");
        a["login"]["totp"] = json!("otpauth://totp/A?secret=ABC");
        b["login"]["totp"] = json!("otpauth://totp/A?secret=XYZ");
        assert_ne!(dedup_key(&a), dedup_key(&b));
    }

    #[test]
    fn normalize_name_strips_email_suffix() {
        assert_eq!(
            normalize_name("fastly-eng.okta.com (aorlov@fastly.com)"),
            "fastly-eng.okta.com"
        );
        assert_eq!(normalize_name("Site (user@example.com)"), "site");
    }

    #[test]
    fn normalize_name_keeps_non_email_suffix() {
        // Parenthesized info without an `@` carries real distinction and
        // must not be stripped.
        assert_eq!(normalize_name("Acme (prod)"), "acme (prod)");
        assert_eq!(normalize_name("Service (staging)"), "service (staging)");
    }

    #[test]
    fn normalize_name_plain_name_unchanged_except_case() {
        assert_eq!(normalize_name("GitHub"), "github");
        assert_eq!(normalize_name(""), "");
    }

    #[test]
    fn dedup_key_matches_when_only_email_suffix_differs() {
        let a = login("fastly-eng.okta.com", "a@fastly.com", "pw");
        let b = login("fastly-eng.okta.com (a@fastly.com)", "a@fastly.com", "pw");
        assert_eq!(
            dedup_key(&a),
            dedup_key(&b),
            "name suffix ' (email)' must not prevent dedup"
        );
    }

    #[test]
    fn dedup_key_ignores_notes_fields_favorite() {
        let mut a = login("GitHub", "a@b.com", "pw");
        let mut b = login("GitHub", "a@b.com", "pw");
        a["notes"] = json!("note A");
        b["notes"] = json!("note B");
        a["favorite"] = json!(false);
        b["favorite"] = json!(true);
        a["fields"] = json!([{"name": "x", "value": "1", "type": 0}]);
        b["fields"] = json!([{"name": "y", "value": "2", "type": 0}]);
        assert_eq!(
            dedup_key(&a),
            dedup_key(&b),
            "notes/fields/favorite must no longer split the dedup key"
        );
    }

    #[test]
    fn dedup_key_differs_on_organization_id() {
        // Two items with identical credentials, one personal and one
        // organization-owned, must never cross-dedup — they live in
        // different vaults with different access control.
        let mut a = login("GitHub", "a@b.com", "pw");
        let mut b = login("GitHub", "a@b.com", "pw");
        a["organizationId"] = json!(null);
        b["organizationId"] = json!("11111111-1111-1111-1111-111111111111");
        assert_ne!(
            dedup_key(&a),
            dedup_key(&b),
            "personal and org items must not cross-dedup"
        );
    }

    #[test]
    fn dedup_key_matches_when_both_personal() {
        let mut a = login("GitHub", "a@b.com", "pw");
        let mut b = login("GitHub", "a@b.com", "pw");
        a["organizationId"] = json!(null);
        b["organizationId"] = json!(null);
        assert_eq!(dedup_key(&a), dedup_key(&b));
    }

    #[test]
    fn skip_non_login_types() {
        assert!(skip_from_dedup(&json!({"type": 2})));
        assert!(skip_from_dedup(&json!({"type": 3})));
        assert!(skip_from_dedup(&json!({"type": 4})));
    }

    #[test]
    fn skip_reprompt_items() {
        let mut item = login("GitHub", "a@b.com", "pw");
        item["reprompt"] = json!(1);
        assert!(skip_from_dedup(&item));
    }

    #[test]
    fn skip_empty_password() {
        assert!(skip_from_dedup(&login("GitHub", "a@b.com", "")));
        assert!(skip_from_dedup(&login("GitHub", "a@b.com", "   ")));
    }

    #[test]
    fn skip_already_marked_duplicate() {
        assert!(skip_from_dedup(&login("GitHub [duplicate]", "a@b.com", "pw")));
    }

    #[test]
    fn skip_deleted_items() {
        let mut item = login("GitHub", "a@b.com", "pw");
        item["deletedDate"] = json!("2026-01-01T00:00:00Z");
        assert!(skip_from_dedup(&item));
    }

    #[test]
    fn uri_pairs_collects_from_login() {
        let item = json!({
            "login": {
                "uris": [
                    {"uri": "https://github.com"},
                    {"uri": "https://github.com/login"},
                ]
            }
        });
        let pairs = uri_pairs(&item);
        assert_eq!(pairs.len(), 2);
        assert!(pairs.contains(&("https://github.com".to_string(), None)));
    }

    #[test]
    fn uri_pairs_distinguishes_null_and_zero_match_mode() {
        let item = json!({
            "login": {
                "uris": [
                    {"uri": "https://example.com", "match": null},
                    {"uri": "https://example.com", "match": 0},
                ]
            }
        });
        let pairs = uri_pairs(&item);
        assert_eq!(pairs.len(), 2, "null and 0 match modes must not collapse");
    }

    #[test]
    fn merge_preserves_android_uri_from_dropped_item() {
        let keep = json!({
            "login": { "uris": [{"uri": "https://github.com"}] }
        });
        let dropped = json!({
            "login": {
                "uris": [
                    {"uri": "https://github.com"},
                    {"uri": "androidapp://com.github.android"},
                ]
            }
        });
        let added = uris_to_merge(&keep, &[&dropped]);
        assert_eq!(added.len(), 1);
        assert_eq!(
            added[0].get("uri").and_then(Value::as_str),
            Some("androidapp://com.github.android"),
        );
    }

    #[test]
    fn merge_preserves_ios_style_universal_link() {
        let keep = json!({
            "login": { "uris": [{"uri": "https://apps.apple.com/app/id123456"}] }
        });
        let dropped = json!({
            "login": {
                "uris": [
                    {"uri": "com.example.iosapp"},
                    {"uri": "https://example.com/ios/callback"},
                ]
            }
        });
        let added = uris_to_merge(&keep, &[&dropped]);
        let uris: Vec<&str> = added
            .iter()
            .filter_map(|u| u.get("uri").and_then(Value::as_str))
            .collect();
        assert_eq!(added.len(), 2);
        assert!(uris.contains(&"com.example.iosapp"));
        assert!(uris.contains(&"https://example.com/ios/callback"));
    }

    #[test]
    fn merge_distinguishes_match_modes_for_same_uri() {
        let keep = json!({
            "login": {
                "uris": [{"uri": "https://github.com", "match": null}]
            }
        });
        let dropped = json!({
            "login": {
                "uris": [
                    {"uri": "https://github.com", "match": null},
                    {"uri": "https://github.com", "match": 3},
                ]
            }
        });
        let added = uris_to_merge(&keep, &[&dropped]);
        assert_eq!(added.len(), 1);
        assert_eq!(added[0].get("match").and_then(Value::as_i64), Some(3));
    }

    #[test]
    fn merge_android_uris_are_case_sensitive() {
        let keep = json!({
            "login": { "uris": [{"uri": "androidapp://com.Example"}] }
        });
        let dropped = json!({
            "login": { "uris": [{"uri": "androidapp://com.example"}] }
        });
        let added = uris_to_merge(&keep, &[&dropped]);
        assert_eq!(
            added.len(),
            1,
            "distinct Android package casings must both be preserved"
        );
    }

    #[test]
    fn merge_skips_identical_uri_and_match() {
        let keep = json!({
            "login": {
                "uris": [
                    {"uri": "https://x.com", "match": null},
                    {"uri": "androidapp://com.x"},
                ]
            }
        });
        let dropped = json!({
            "login": {
                "uris": [
                    {"uri": "https://x.com", "match": null},
                    {"uri": "androidapp://com.x"},
                ]
            }
        });
        let added = uris_to_merge(&keep, &[&dropped]);
        assert!(added.is_empty());
    }

    #[test]
    fn merge_handles_missing_uris_array() {
        let keep = json!({"login": {}});
        let dropped = json!({
            "login": {
                "uris": [{"uri": "androidapp://com.example"}]
            }
        });
        let added = uris_to_merge(&keep, &[&dropped]);
        assert_eq!(added.len(), 1);
    }

    #[test]
    fn dedup_items_merges_pair() {
        let mut items = vec![
            json!({
                "id": "aaaaaaaa-0000-0000-0000-000000000000",
                "type": 1,
                "name": "GitHub",
                "revisionDate": "2026-01-01T00:00:00Z",
                "creationDate": "2025-01-01T00:00:00Z",
                "login": {
                    "username": "alex",
                    "password": "pw",
                    "uris": [{"uri": "https://github.com"}],
                },
            }),
            json!({
                "id": "bbbbbbbb-0000-0000-0000-000000000000",
                "type": 1,
                "name": "GitHub",
                "revisionDate": "2026-02-01T00:00:00Z",
                "creationDate": "2025-06-01T00:00:00Z",
                "login": {
                    "username": "alex",
                    "password": "pw",
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
        // Newer item (Feb 2026) wins; the older item's URI was merged in.
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
    fn dedup_items_merges_notes_and_picks_longest_name() {
        let mut items = vec![
            json!({
                "id": "aaaaaaaa-0000-0000-0000-000000000000",
                "type": 1,
                "name": "fastly-eng.okta.com",
                "notes": "Autosaved on fastly-eng.okta.com",
                "revisionDate": "2026-04-12T02:11:29Z",
                "creationDate": "2024-10-31T14:36:43Z",
                "login": {"username": "a@b.com", "password": "pw", "uris": []},
            }),
            json!({
                "id": "bbbbbbbb-0000-0000-0000-000000000000",
                "type": 1,
                "name": "fastly-eng.okta.com (a@b.com)",
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
    fn dedup_items_merges_identical_notes_without_duplication() {
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
    fn dedup_items_picks_longer_history_as_survivor() {
        // Item `a` has richer passwordHistory but is older; item `b` is newer
        // but has no history. `a` must win — longer history is the primary
        // tiebreaker per the merge spec.
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
    fn dedup_items_merges_password_history_across_duplicates() {
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
    fn dedup_items_or_merges_favorite() {
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
    fn dedup_items_merges_custom_fields_preserving_linked_id() {
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
    fn dedup_items_distinct_passwords_stay_separate() {
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
    fn dedup_items_preserves_every_distinct_username_password_pair() {
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
    fn dedup_items_preserves_distinct_totps_as_separate_items() {
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
            .filter_map(|i| i.get("login").and_then(|l| l.get("totp")).and_then(Value::as_str))
            .collect();
        assert!(secrets.iter().any(|s| s.contains("ABC")));
        assert!(secrets.iter().any(|s| s.contains("XYZ")));
    }

    #[test]
    fn dedup_items_preserves_totp_when_only_one_item_has_one() {
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

    #[test]
    fn dedup_items_preserves_every_distinct_note_in_merged_survivor() {
        // Three items with identical (username, password) but distinct notes
        // must collapse into a single survivor whose notes contain every
        // distinct body.
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

    // --- Regression guards for the post-review hardening ---

    #[test]
    fn dedup_items_unions_collection_ids_across_duplicates() {
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
    fn dedup_items_appends_folder_note_when_drops_differ() {
        // Drops with a different folder must leave a disambiguation line on
        // the survivor so placement isn't silently lost at import time.
        let mut items = vec![
            json!({
                "type": 1, "name": "Site",
                "folderId": "folder-keep",
                "revisionDate": "2026-02-01T00:00:00Z",
                "login": {"username": "u", "password": "p"}
            }),
            json!({
                "type": 1, "name": "Site",
                "folderId": "folder-drop",
                "revisionDate": "2026-01-01T00:00:00Z",
                "login": {"username": "u", "password": "p"}
            }),
        ];
        let mut folders = HashMap::new();
        folders.insert("folder-keep".to_string(), "Work".to_string());
        folders.insert("folder-drop".to_string(), "Personal".to_string());
        dedup_items_with_folders(&mut items, &folders);
        assert_eq!(items.len(), 1);
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
    fn dedup_items_omits_folder_note_when_folders_match() {
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
    fn dedup_items_folder_note_falls_back_to_uuid_without_lookup() {
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
    fn fido2_metadata_divergence_keeps_items_distinct() {
        // Same credentialId but different counter/userHandle must not group.
        // Previously the key was credentialId-only, so divergent metadata was
        // silently dropped with the loser.
        let a = json!({
            "type": 1, "name": "Passkey",
            "login": {"username": "u", "password": "p", "fido2Credentials": [{
                "credentialId": "cid-1", "counter": "1", "userHandle": "ua"
            }]}
        });
        let b = json!({
            "type": 1, "name": "Passkey",
            "login": {"username": "u", "password": "p", "fido2Credentials": [{
                "credentialId": "cid-1", "counter": "42", "userHandle": "ub"
            }]}
        });
        assert_ne!(
            dedup_key(&a),
            dedup_key(&b),
            "divergent FIDO2 metadata must keep items distinct"
        );
    }

    #[test]
    fn fido2_same_full_objects_group_identically() {
        // Same credentialId AND same metadata should still group — otherwise
        // real duplicates (same passkey exported twice) would stop deduping.
        let cred = json!({"credentialId": "cid-1", "counter": "7", "userHandle": "u"});
        let a = json!({
            "type": 1, "name": "Passkey",
            "login": {"username": "u", "password": "p", "fido2Credentials": [cred.clone()]}
        });
        let b = json!({
            "type": 1, "name": "Passkey",
            "login": {"username": "u", "password": "p", "fido2Credentials": [cred]}
        });
        assert_eq!(dedup_key(&a), dedup_key(&b));
    }

    #[test]
    fn merge_notes_preserves_leading_trailing_whitespace_of_survivor() {
        // Notes that differ only in surrounding whitespace are treated as
        // the same body for dedup purposes, but the survivor's ORIGINAL
        // bytes are what lands in the output — no silent trim.
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
        // If survivor has `"Hello"` and drop has `"  Hello  "`, they're the
        // same note — survivor's raw bytes win and the drop version is not
        // appended as a second entry.
        let keep = json!({"notes": "Hello"});
        let drops = [&json!({"notes": "  Hello  "})];
        let merged = merge_notes(&keep, &drops).expect("merge yields Some");
        assert_eq!(merged, "Hello");
        // Conversely: survivor with whitespace, drop without — keep survivor's.
        let keep = json!({"notes": "  Hello  "});
        let drops = [&json!({"notes": "Hello"})];
        let merged = merge_notes(&keep, &drops).expect("merge yields Some");
        assert_eq!(merged, "  Hello  ");
    }

    #[test]
    fn dedup_export_reads_top_level_folders_and_dedups_items() {
        // End-to-end: `dedup_export` should pull folder names from the
        // top-level `folders` array, dedup `items`, and mutate in place.
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
}
