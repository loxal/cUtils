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

/// Strict duplicate-equality key for a Bitwarden login item.
///
/// Two items are considered duplicates only when every field in this tuple
/// matches exactly:
/// - name                  (case-insensitive, trimmed)
/// - username              (case-insensitive, trimmed)
/// - password              (exact)
/// - TOTP secret           (exact)
/// - FIDO2 credential ids  (exact set)
/// - notes                 (trimmed)
/// - custom fields         (`(name, value, type, linkedId)` tuples,
///                          order-insensitive — linkedId distinguishes
///                          Linked fields that point at Username vs Password)
/// - favorite flag
/// - organizationId        (personal items never merge with org items —
///                          they live in different vaults with different
///                          access control)
pub fn dedup_key(item: &Value) -> String {
    let name = norm(get_str(item, "name"));
    let login = item.get("login");
    let user = norm(
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
    let notes = get_str(item, "notes").trim();
    let fields = fields_signature(item);
    let favorite = item.get("favorite").and_then(Value::as_bool).unwrap_or(false);
    let org_id = item
        .get("organizationId")
        .and_then(Value::as_str)
        .unwrap_or("");
    format!("{name}\0{user}\0{pw}\0{totp}\0{fido2}\0{notes}\0{fields}\0{favorite}\0{org_id}")
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
/// The input vector is mutated: items that are removed drop out of the vec,
/// items that are kept may have URIs from dropped duplicates merged into
/// their `login.uris` array. The returned [`DedupStats`] describes what
/// happened and includes per-removal audit records.
pub fn dedup_items(items: &mut Vec<Value>) -> DedupStats {
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

    // Pass 2: plan removals and URI merges without mutating items.
    let mut to_drop: HashSet<usize> = HashSet::new();
    let mut audit_entries: Vec<Value> = Vec::new();
    let mut uri_additions: Vec<(usize, Vec<Value>)> = Vec::new();
    let mut total_merged = 0usize;

    for group in &dupe_groups {
        let mut ordered = group.clone();
        ordered.sort_by(|a, b| {
            let a_rev = get_str(&items[*a], "revisionDate");
            let b_rev = get_str(&items[*b], "revisionDate");
            let a_cre = get_str(&items[*a], "creationDate");
            let b_cre = get_str(&items[*b], "creationDate");
            (b_rev, b_cre).cmp(&(a_rev, a_cre))
        });
        let keep_idx = ordered[0];
        let drop_idxs = &ordered[1..];

        let keep = &items[keep_idx];
        let drops: Vec<&Value> = drop_idxs.iter().map(|i| &items[*i]).collect();
        let to_add = uris_to_merge(keep, &drops);
        let merged_here = to_add.len();
        total_merged += merged_here;
        if merged_here > 0 {
            uri_additions.push((keep_idx, to_add));
        }

        let keep_id = keep.get("id").cloned().unwrap_or(Value::Null);
        let keep_name = keep.get("name").cloned().unwrap_or(Value::Null);
        let keep_rev = keep.get("revisionDate").cloned().unwrap_or(Value::Null);
        let keep_folder = keep.get("folderId").cloned().unwrap_or(Value::Null);

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
                "kept_name": keep_name.clone(),
                "kept_revisionDate": keep_rev.clone(),
                "kept_folderId": keep_folder.clone(),
                "uris_merged_into_kept": merged_here,
            }));
        }
    }

    // Pass 3: apply URI additions to kept items.
    for (keep_idx, additions) in uri_additions {
        if let Some(login) = items[keep_idx]
            .get_mut("login")
            .and_then(Value::as_object_mut)
        {
            let mut uris = login
                .get("uris")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            uris.extend(additions);
            login.insert("uris".to_string(), Value::Array(uris));
        }
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

/// Shorthand for reading an item's string field with a default of `""`.
pub(crate) fn get_str<'a>(item: &'a Value, key: &str) -> &'a str {
    item.get(key).and_then(Value::as_str).unwrap_or("")
}

fn norm(s: &str) -> String {
    s.trim().to_lowercase()
}

/// Hash a login item's `fields[]` array into a stable, order-insensitive
/// signature.
///
/// The signature tuple is `(name, value, type, linkedId)`. The `linkedId`
/// member matters for type 3 ("Linked") custom fields: Bitwarden stores
/// these with a null `value` and the actual target (Username = 100,
/// Password = 101 — confirmed by reading a live vault's API response) in
/// `linkedId`. Without it, a Linked-to-Username field and a Linked-to-
/// Password field would share the same `(name, value, type)` tuple and
/// collide in the dedup key. We use `-1` as the sentinel for "not a
/// Linked field" since real `linkedId` values are non-negative.
fn fields_signature(item: &Value) -> String {
    let mut tuples: Vec<(String, String, i64, i64)> = item
        .get("fields")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .map(|f| {
                    (
                        f.get("name").and_then(Value::as_str).unwrap_or("").to_string(),
                        f.get("value").and_then(Value::as_str).unwrap_or("").to_string(),
                        f.get("type").and_then(Value::as_i64).unwrap_or(0),
                        f.get("linkedId").and_then(Value::as_i64).unwrap_or(-1),
                    )
                })
                .collect()
        })
        .unwrap_or_default();
    tuples.sort();
    serde_json::to_string(&tuples).unwrap_or_default()
}

fn fido2_signature(item: &Value) -> String {
    let mut ids: Vec<String> = item
        .get("login")
        .and_then(|l| l.get("fido2Credentials"))
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .map(|c| {
                    c.get("credentialId")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string()
                })
                .collect()
        })
        .unwrap_or_default();
    ids.sort();
    ids.join("|")
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
    fn norm_lowercases_and_trims() {
        assert_eq!(norm("  GitHub "), "github");
        assert_eq!(norm(""), "");
    }

    #[test]
    fn dedup_key_matches_identical_items() {
        let a = login("GitHub", "a@b.com", "pw1");
        let b = login(" github ", "A@B.com", "pw1");
        assert_eq!(dedup_key(&a), dedup_key(&b));
    }

    #[test]
    fn dedup_key_differs_on_password() {
        let a = login("GitHub", "a@b.com", "pw1");
        let b = login("GitHub", "a@b.com", "pw2");
        assert_ne!(dedup_key(&a), dedup_key(&b));
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
    fn fields_signature_is_order_insensitive() {
        let a = json!({
            "fields": [
                {"name": "A", "value": "1", "type": 0},
                {"name": "B", "value": "2", "type": 0},
            ]
        });
        let b = json!({
            "fields": [
                {"name": "B", "value": "2", "type": 0},
                {"name": "A", "value": "1", "type": 0},
            ]
        });
        assert_eq!(fields_signature(&a), fields_signature(&b));
    }

    #[test]
    fn fields_signature_differs_on_linked_id() {
        // Two Linked custom fields with the same label but pointing at
        // different targets (Username vs Password). Without linkedId in
        // the signature these would collide in the dedup key and items
        // would incorrectly merge.
        let a = json!({
            "fields": [
                {"name": "lu", "value": null, "type": 3, "linkedId": 100},
            ]
        });
        let b = json!({
            "fields": [
                {"name": "lu", "value": null, "type": 3, "linkedId": 101},
            ]
        });
        assert_ne!(
            fields_signature(&a),
            fields_signature(&b),
            "Linked(Username) vs Linked(Password) must not collide"
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
}
