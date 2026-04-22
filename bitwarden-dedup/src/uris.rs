// Copyright 2026 Alexander Orlov <alexander.orlov@loxal.net>

//! URI-set logic for Bitwarden login items.
//!
//! URIs are treated as opaque strings with **no case folding**. That matters
//! for `androidapp://` URIs where the package-name segment is case-sensitive
//! per Android spec, and for iOS universal-link-style identifiers that often
//! carry mixed case.
//!
//! The `(uri, match_mode)` pair — not just `uri` — is the identity key, so
//! `match: null` (inherit default) and `match: 0` (explicit Base domain) are
//! kept as distinct entries. The user chose those modes deliberately; we do
//! not second-guess them.

use std::collections::HashSet;

use serde_json::Value;

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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

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
}
