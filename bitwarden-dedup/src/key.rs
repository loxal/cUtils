// Copyright 2026 Alexander Orlov <alexander.orlov@loxal.net>

//! **"Is this a duplicate?"** — duplicate-identity rules.
//!
//! This module is the single source of truth for the dedup equality decision.
//! Every field that Bitwarden stores in a single-valued slot appears in the
//! key; items that disagree on any of them end up in different groups and
//! cannot be merged. Multi-valued or concatenable fields (notes, URIs,
//! passwordHistory, collectionIds, …) live in [`crate::merge`] instead.
//!
//! Key members:
//!
//! - name           (case-insensitive; trailing `(email@domain)` suffix is
//!                   stripped, because some Bitwarden clients append it to
//!                   disambiguate UI-level collisions)
//! - username       (trim-only — case is preserved)
//! - password       (exact)
//! - TOTP secret    (exact; empty and non-empty never collapse)
//! - FIDO2 creds    (canonical serialized full objects, not just credentialIds)
//! - organizationId (personal vs org; never cross-dedup)

use serde_json::Value;

use crate::json_util::get_str;

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
        assert_eq!(norm_user("  Alice "), "Alice");
        assert_eq!(norm_user("alice"), "alice");
        assert_ne!(norm_user("Alice"), norm_user("alice"));
        assert_eq!(norm_user(""), "");
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
        assert_eq!(normalize_name("Acme (prod)"), "acme (prod)");
        assert_eq!(normalize_name("Service (staging)"), "service (staging)");
    }

    #[test]
    fn normalize_name_plain_name_unchanged_except_case() {
        assert_eq!(normalize_name("GitHub"), "github");
        assert_eq!(normalize_name(""), "");
    }

    #[test]
    fn dedup_key_matches_identical_items() {
        let a = login("GitHub", "a@b.com", "pw1");
        let b = login(" github ", "a@b.com", "pw1");
        assert_eq!(dedup_key(&a), dedup_key(&b));
    }

    #[test]
    fn dedup_key_differs_on_username_case() {
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
    fn fido2_metadata_divergence_keeps_items_distinct() {
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
}
