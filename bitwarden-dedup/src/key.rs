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
//! - FIDO2 creds    (canonical serialized full objects, not just credentialIds —
//!                   different passkeys keep items distinct so no passkey is
//!                   ever overwritten)
//! - organizationId (personal vs org; never cross-dedup)
//!
//! **TOTP is deliberately not in the key.** A Bitwarden item has a single
//! `login.totp` slot, so two items sharing every credential field but
//! differing only in TOTP represent the same account with a rotated secret.
//! [`crate::merge`] picks the newest TOTP across the group; older rotations
//! are dropped (they no longer authenticate against the backend anyway).
//! This is the only field where dedup can displace user-entered data —
//! everything else is either in the key (distinct-preserving) or union-merged.

use serde_json::Value;

use crate::json_util::get_str;

/// Duplicate-equality key for a Bitwarden login item.
///
/// **Invariants**:
///
/// - Distinct `(username, password)` pairs are never collapsed.
/// - Distinct FIDO2 credential sets are never collapsed — passkeys are
///   never overwritten.
/// - Personal items never merge with org-owned items.
///
/// TOTP is **not** in the key; items that differ only in TOTP represent
/// the same account with a rotated secret, and [`crate::merge`] keeps the
/// newest TOTP on the survivor.
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
    let fido2 = fido2_signature(item);
    let org_id = item
        .get("organizationId")
        .and_then(Value::as_str)
        .unwrap_or("");
    format!("{name}\0{user}\0{pw}\0{fido2}\0{org_id}")
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

/// Return `true` for login (`type: 1`) items that must never be grouped
/// for deduplication.
///
/// This is the safety floor for the login-dedup pass: non-login types
/// skip this path (they have their own grouping rules — see
/// [`is_dedupable_secure_note`]), master-password-gated items are left
/// alone, empty-password items would spuriously group on `""`, and
/// anything already tagged `[duplicate]` or sitting in the trash is
/// skipped.
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

/// Return `true` when the item is a secure note (`type: 2`) that the
/// dedup pipeline should consider for grouping.
///
/// Secure notes dedup by [`secure_note_key`] — currently
/// `type=2 \0 normalize_name(name)`. Notes without a name cannot group
/// (we have nothing stable to hash on). Master-password-gated
/// (`reprompt == 1`) and already-trashed notes pass through untouched
/// for the same safety reasons as logins.
pub fn is_dedupable_secure_note(item: &Value) -> bool {
    if item.get("type").and_then(Value::as_u64) != Some(2) {
        return false;
    }
    if item.get("deletedDate").is_some_and(|v| !v.is_null()) {
        return false;
    }
    if item.get("reprompt").and_then(Value::as_u64) == Some(1) {
        return false;
    }
    if get_str(item, "name").contains("[duplicate]") {
        return false;
    }
    !get_str(item, "name").trim().is_empty()
}

/// Grouping key for secure notes.
///
/// **Strict-by-default**: two secure notes only collapse when they agree
/// on **note-name (normalized)**, **organizationId**, AND **canonicalized
/// notes body**. That narrows the dedup to literal duplicates — two
/// copies of the same note — and never merges semantically distinct
/// items that just happen to share a generic name like `Recovery`,
/// `Wallet`, or `credentials.txt`.
///
/// Fields and rationale:
///
/// - `type=2` prefix — secure notes never collide with login keys.
/// - [`normalize_note_name`] — case-fold + outer-trim, plus stripping
///   of zero-width / invisible format characters. Critically, **the
///   login-style `(email@…)` suffix stripping is NOT applied** here:
///   a title like `credentials (alice@example.com)` can be meaningful
///   content for a note, not cosmetic UI disambiguation.
/// - `organizationId` — personal (`""`/`null`) and org-owned notes
///   with the same name stay separate; different vaults, different
///   access control.
/// - [`canonicalize_note_body`] — outer-trim + zero-width strip on
///   the body. Different bodies mean different notes; visually
///   identical bodies that only differ in invisible Unicode noise
///   still collapse.
pub fn secure_note_key(item: &Value) -> String {
    let name = normalize_note_name(get_str(item, "name"));
    let org = item
        .get("organizationId")
        .and_then(Value::as_str)
        .unwrap_or("");
    let body = canonicalize_note_body(get_str(item, "notes"));
    format!("type=2\0name={name}\0org={org}\0body={body}")
}

/// Normalize a Secure Note title for the dedup key.
///
/// - Case-fold (ASCII-lowercase — conservative; full-Unicode casefold
///   would be semantically the same here for the scripts we care
///   about but brings a bigger dep surface).
/// - Trim Unicode whitespace (not just ASCII).
/// - Strip zero-width and default-ignorable characters (ZWSP, ZWNJ,
///   ZWJ, BOM, WJ, SHY, LRM, RLM, LRE, RLE, PDF). These are invisible
///   but byte-different — they cause "obvious duplicates" to survive
///   under pure `trim()` based keys.
///
/// Deliberately **does not** strip `(email@…)` suffixes — that rule
/// is login-specific and unsafe for secure-note titles where the
/// suffix may be meaningful content.
pub fn normalize_note_name(s: &str) -> String {
    scrub_invisible(s).trim().to_lowercase()
}

/// Canonicalize a Secure Note body for the dedup key.
///
/// Same invisible-character scrubbing as [`normalize_note_name`], plus
/// Unicode-aware outer-trim. Byte-identical stored body is preserved
/// elsewhere; this canonical form is used **only** for the key so
/// visually identical bodies that differ only in zero-width or NBSP
/// noise dedup cleanly.
pub fn canonicalize_note_body(s: &str) -> String {
    scrub_invisible(s).trim().to_string()
}

/// Return `true` when the item is an SSH key (`type: 5`) that the
/// dedup pipeline should consider for grouping.
///
/// SSH keys dedup by [`ssh_key_key`] — a canonicalized snapshot of the
/// `sshKey` object (public key + private key + fingerprint) plus the
/// organization id. Two items with the same SSH material collapse; any
/// byte-level difference in the key material keeps them separate. That
/// conservative bias is deliberate: private-key material is the most
/// sensitive field we touch, and "one of these two keys is subtly
/// different" is never a merge we want to guess at.
pub fn is_dedupable_ssh_key(item: &Value) -> bool {
    if item.get("type").and_then(Value::as_u64) != Some(5) {
        return false;
    }
    if item.get("deletedDate").is_some_and(|v| !v.is_null()) {
        return false;
    }
    if item.get("reprompt").and_then(Value::as_u64) == Some(1) {
        return false;
    }
    if get_str(item, "name").contains("[duplicate]") {
        return false;
    }
    // Refuse to group an SSH key without an sshKey block — the key
    // material is the only identity we trust here.
    let Some(ssh) = item.get("sshKey") else {
        return false;
    };
    let pub_key = ssh
        .get("publicKey")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim();
    !pub_key.is_empty()
}

/// Grouping key for SSH keys.
///
/// Combines:
/// - `type=5` prefix — never collides with login / secure-note keys.
/// - Canonicalized `sshKey` object — the full object (public key,
///   private key, fingerprint) serialized in alphabetical-key order,
///   so any byte-level mismatch in the key material keeps items
///   distinct. Private keys are part of the identity on purpose:
///   a public-key collision with different private halves would
///   almost certainly be vault corruption, and we refuse to guess.
/// - `organizationId` — personal and org-owned SSH keys stay separate.
pub fn ssh_key_key(item: &Value) -> String {
    let ssh_sig = ssh_canonical_signature(item);
    let org = item
        .get("organizationId")
        .and_then(Value::as_str)
        .unwrap_or("");
    format!("type=5\0ssh={ssh_sig}\0org={org}")
}

fn ssh_canonical_signature(item: &Value) -> String {
    let Some(ssh) = item.get("sshKey") else {
        return String::new();
    };
    // BTreeMap-backed Value serialization gives alphabetical keys,
    // which is the canonical form we need — matches the approach used
    // for `fido2_signature` above.
    serde_json::to_string(ssh).unwrap_or_default()
}

/// Strip invisible/default-ignorable characters that can make
/// byte-different strings render identically. Also folds non-ASCII
/// whitespace (NBSP, figure space, zero-width NBSP) to a regular
/// space so `trim()` handles edges correctly.
fn scrub_invisible(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            // Zero-width / default-ignorable code points.
            '\u{200B}' // ZERO WIDTH SPACE
            | '\u{200C}' // ZWNJ
            | '\u{200D}' // ZWJ
            | '\u{2060}' // WORD JOINER
            | '\u{FEFF}' // ZERO WIDTH NO-BREAK SPACE / BOM
            | '\u{00AD}' // SOFT HYPHEN
            | '\u{200E}' // LRM
            | '\u{200F}' // RLM
            | '\u{202A}' // LRE
            | '\u{202B}' // RLE
            | '\u{202C}' // PDF
            | '\u{202D}' // LRO
            | '\u{202E}' // RLO
            => { /* drop */ }
            // NBSP-like whitespace → fold to ASCII space so `trim`
            // handles the edges uniformly.
            '\u{00A0}' // NBSP
            | '\u{2007}' // FIGURE SPACE
            | '\u{202F}' // NARROW NBSP
            | '\u{205F}' // MEDIUM MATHEMATICAL SPACE
            | '\u{3000}' // IDEOGRAPHIC SPACE
            => out.push(' '),
            _ => out.push(c),
        }
    }
    out
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
    fn dedup_key_ignores_totp_differences() {
        // TOTP is intentionally out of the key — items differing only on TOTP
        // are the same account with a rotated secret. [`crate::merge`] picks
        // the newest TOTP for the survivor.
        let mut a = login("GitHub", "a@b.com", "pw");
        let mut b = login("GitHub", "a@b.com", "pw");
        a["login"]["totp"] = json!("otpauth://totp/A?secret=ABC");
        b["login"]["totp"] = json!("otpauth://totp/A?secret=XYZ");
        assert_eq!(
            dedup_key(&a),
            dedup_key(&b),
            "TOTP rotation must not prevent dedup"
        );
    }

    #[test]
    fn dedup_key_still_splits_on_passkey_even_when_totp_also_differs() {
        // Passkeys are strict-match. Even if TOTP-relaxation would otherwise
        // merge two items, a distinct FIDO2 credential on either side must
        // keep them separate so no passkey is overwritten.
        let mut a = login("GitHub", "a@b.com", "pw");
        let mut b = login("GitHub", "a@b.com", "pw");
        a["login"]["totp"] = json!("otpauth://totp/A?secret=ABC");
        b["login"]["totp"] = json!("otpauth://totp/A?secret=XYZ");
        a["login"]["fido2Credentials"] = json!([{"credentialId": "pk-alice"}]);
        b["login"]["fido2Credentials"] = json!([{"credentialId": "pk-bob"}]);
        assert_ne!(
            dedup_key(&a),
            dedup_key(&b),
            "distinct passkeys must keep items separate regardless of TOTP"
        );
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

    #[test]
    fn secure_note_key_matches_normalized_names_with_identical_bodies() {
        // Same name (modulo trim/case) AND same trimmed body AND same
        // org → literal duplicate, dedup.
        let a = json!({"type": 2, "name": "Recovery codes", "notes": "AAA BBB"});
        let b = json!({"type": 2, "name": "  recovery codes  ", "notes": "AAA BBB"});
        assert_eq!(secure_note_key(&a), secure_note_key(&b));
    }

    #[test]
    fn secure_note_key_differs_on_body() {
        // Same name, different bodies → different groups, both preserved.
        // This is the safety floor that prevents merging unrelated items
        // that share a generic title like "Recovery" or "credentials.txt".
        let a = json!({"type": 2, "name": "Recovery", "notes": "codes for GitHub"});
        let b = json!({"type": 2, "name": "Recovery", "notes": "codes for GitLab"});
        assert_ne!(
            secure_note_key(&a),
            secure_note_key(&b),
            "secure notes with distinct bodies must not share a key"
        );
    }

    #[test]
    fn secure_note_key_body_is_trimmed() {
        // Whitespace around the body should not cause false separation.
        let a = json!({"type": 2, "name": "n", "notes": "body"});
        let b = json!({"type": 2, "name": "n", "notes": "  body  \n"});
        assert_eq!(secure_note_key(&a), secure_note_key(&b));
    }

    #[test]
    fn secure_note_key_does_not_strip_email_suffix() {
        // Secure-note titles keep `(email@…)` content — unlike login
        // names, the suffix can be meaningful on a note (e.g. which
        // account the recovery codes belong to). Two notes with
        // different email suffixes must stay separate.
        let a = json!({"type": 2, "name": "credentials", "notes": "codes"});
        let b = json!({"type": 2, "name": "credentials (alice@example.com)", "notes": "codes"});
        let c = json!({"type": 2, "name": "credentials (bob@example.com)", "notes": "codes"});
        assert_ne!(
            secure_note_key(&a),
            secure_note_key(&b),
            "'(email)' suffix must NOT be stripped for secure notes"
        );
        assert_ne!(
            secure_note_key(&b),
            secure_note_key(&c),
            "distinct email suffixes must keep notes separate"
        );
    }

    #[test]
    fn secure_note_key_ignores_zero_width_noise_in_name() {
        // Visually identical titles that differ only by invisible
        // Unicode (zero-width space, ZWJ, BOM) must still collapse.
        let a = json!({"type": 2, "name": "Recovery", "notes": "body"});
        let b = json!({"type": 2, "name": "Re\u{200B}co\u{FEFF}very", "notes": "body"});
        assert_eq!(
            secure_note_key(&a),
            secure_note_key(&b),
            "zero-width chars must not split a secure-note group"
        );
    }

    #[test]
    fn secure_note_key_folds_nbsp_whitespace_at_edges() {
        // NBSP and friends at edges must trim the same way ASCII space
        // does, so copy/paste whitespace quirks don't split groups.
        let a = json!({"type": 2, "name": "Note", "notes": "body"});
        let b = json!({"type": 2, "name": "\u{00A0}Note\u{00A0}", "notes": " body "});
        let c = json!({"type": 2, "name": "\u{3000}Note", "notes": "\u{2007}body\u{202F}"});
        assert_eq!(secure_note_key(&a), secure_note_key(&b));
        assert_eq!(secure_note_key(&a), secure_note_key(&c));
    }

    #[test]
    fn secure_note_key_ignores_zero_width_noise_in_body() {
        let a = json!({"type": 2, "name": "X", "notes": "abc"});
        let b = json!({"type": 2, "name": "X", "notes": "a\u{200B}b\u{200D}c"});
        assert_eq!(secure_note_key(&a), secure_note_key(&b));
    }

    fn ssh_key_item(pub_key: &str, priv_key: &str, fp: &str) -> Value {
        json!({
            "type": 5,
            "name": "laptop-ed25519",
            "sshKey": {
                "publicKey": pub_key,
                "privateKey": priv_key,
                "keyFingerprint": fp
            }
        })
    }

    #[test]
    fn ssh_key_key_matches_when_material_identical() {
        let a = ssh_key_item(
            "ssh-ed25519 AAAAC...alex",
            "-----BEGIN OPENSSH PRIVATE KEY-----\nABC\n-----END-----",
            "SHA256:abc",
        );
        let b = ssh_key_item(
            "ssh-ed25519 AAAAC...alex",
            "-----BEGIN OPENSSH PRIVATE KEY-----\nABC\n-----END-----",
            "SHA256:abc",
        );
        assert_eq!(ssh_key_key(&a), ssh_key_key(&b));
    }

    #[test]
    fn ssh_key_key_differs_when_private_key_differs() {
        // Same public key + different private key is almost certainly
        // corrupt state — never merge these items; keep them separate.
        let a = ssh_key_item(
            "ssh-ed25519 AAAAC...alex",
            "-----BEGIN OPENSSH PRIVATE KEY-----\nONE\n-----END-----",
            "SHA256:abc",
        );
        let b = ssh_key_item(
            "ssh-ed25519 AAAAC...alex",
            "-----BEGIN OPENSSH PRIVATE KEY-----\nTWO\n-----END-----",
            "SHA256:abc",
        );
        assert_ne!(ssh_key_key(&a), ssh_key_key(&b));
    }

    #[test]
    fn ssh_key_key_differs_when_public_key_differs() {
        let a = ssh_key_item("ssh-ed25519 AAA.ONE", "priv1", "SHA256:a");
        let b = ssh_key_item("ssh-ed25519 AAA.TWO", "priv2", "SHA256:b");
        assert_ne!(ssh_key_key(&a), ssh_key_key(&b));
    }

    #[test]
    fn is_dedupable_ssh_key_filters_non_type_5() {
        let a = ssh_key_item("pk", "priv", "fp");
        assert!(is_dedupable_ssh_key(&a));
        let mut not_ssh = a.clone();
        not_ssh["type"] = json!(1);
        assert!(!is_dedupable_ssh_key(&not_ssh));
    }

    #[test]
    fn is_dedupable_ssh_key_refuses_items_without_public_key() {
        // Without a publicKey we have no identity — refuse to group.
        let item = json!({
            "type": 5,
            "name": "orphan",
            "sshKey": {"publicKey": "", "privateKey": "priv"}
        });
        assert!(!is_dedupable_ssh_key(&item));
    }

    #[test]
    fn is_dedupable_ssh_key_skips_trashed_and_reprompt() {
        let mut item = ssh_key_item("pk", "priv", "fp");
        item["deletedDate"] = json!("2025-01-01T00:00:00Z");
        assert!(!is_dedupable_ssh_key(&item));
        let mut item = ssh_key_item("pk", "priv", "fp");
        item["reprompt"] = json!(1);
        assert!(!is_dedupable_ssh_key(&item));
    }

    #[test]
    fn ssh_key_key_separates_personal_and_org() {
        let mut a = ssh_key_item("pk", "priv", "fp");
        let mut b = ssh_key_item("pk", "priv", "fp");
        a["organizationId"] = Value::Null;
        b["organizationId"] = json!("11111111-1111-1111-1111-111111111111");
        assert_ne!(ssh_key_key(&a), ssh_key_key(&b));
    }

    #[test]
    fn secure_note_key_separates_personal_and_org() {
        // Personal and organization-owned notes sharing a name + body
        // must NOT collapse — they live in different vaults with
        // different access control.
        let mut personal = json!({"type": 2, "name": "Shared Wiki", "notes": "internal URL"});
        let mut org = personal.clone();
        personal["organizationId"] = Value::Null;
        org["organizationId"] = json!("11111111-1111-1111-1111-111111111111");
        assert_ne!(
            secure_note_key(&personal),
            secure_note_key(&org),
            "personal and org-owned secure notes must never cross-dedup"
        );
    }

    #[test]
    fn secure_note_key_distinct_from_login_key() {
        // A login and a secure note that happen to share a name must
        // never collide — their keys live in separate namespaces.
        let login = json!({
            "type": 1, "name": "credentials.txt",
            "login": {"username": "u", "password": "p"}
        });
        let note = json!({"type": 2, "name": "credentials.txt", "notes": "n"});
        assert_ne!(dedup_key(&login), secure_note_key(&note));
    }

    #[test]
    fn is_dedupable_secure_note_filters_non_type_2() {
        assert!(is_dedupable_secure_note(&json!({"type": 2, "name": "n"})));
        assert!(!is_dedupable_secure_note(&json!({"type": 1, "name": "n"})));
        assert!(!is_dedupable_secure_note(&json!({"type": 3, "name": "n"})));
    }

    #[test]
    fn is_dedupable_secure_note_rejects_untagged_cases() {
        let mut base = json!({"type": 2, "name": "n"});
        assert!(is_dedupable_secure_note(&base));
        // trashed already → skip
        base["deletedDate"] = json!("2026-01-01T00:00:00Z");
        assert!(!is_dedupable_secure_note(&base));
        // reprompt-gated → skip
        base["deletedDate"] = Value::Null;
        base["reprompt"] = json!(1);
        assert!(!is_dedupable_secure_note(&base));
        // already tagged → skip
        base["reprompt"] = json!(0);
        base["name"] = json!("n [duplicate]");
        assert!(!is_dedupable_secure_note(&base));
        // empty name → skip (nothing stable to group on)
        base["name"] = json!("   ");
        assert!(!is_dedupable_secure_note(&base));
    }
}
