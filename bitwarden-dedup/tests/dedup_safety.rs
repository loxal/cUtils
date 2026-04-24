// Copyright 2026 Alexander Orlov <alexander.orlov@loxal.net>

//! Safety guards: every distinct credential must survive dedup.
//!
//! The invariants a reviewer should be able to verify at a glance before
//! trusting the tool on a real vault:
//!
//! - different passwords never merge
//! - different `(username, password)` pairs never merge
//! - passkeys are never overwritten — distinct FIDO2 credentials keep items
//!   separate even when every other field matches
//! - when items differ only by TOTP, the group collapses to one survivor
//!   that carries the NEWEST TOTP secret (older rotations are routed to
//!   Bitwarden's Trash; nothing is ever removed from the output)
//! - **nothing is ever removed** — dedup losers carry `deletedDate = now`
//!   and stay in the output so they appear in Bitwarden's Trash folder
//!
//! All tests exercise the public `dedup_items` API.

use bitwarden_dedup::{DedupConfig, dedup_export, dedup_items, dedup_items_with_config};
use serde_json::{Value, json};

fn living(items: &[Value]) -> Vec<&Value> {
    items.iter().filter(|i| i["deletedDate"].is_null()).collect()
}

fn trashed(items: &[Value]) -> Vec<&Value> {
    items.iter().filter(|i| !i["deletedDate"].is_null()).collect()
}

#[test]
fn distinct_passwords_stay_separate() {
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
    assert_eq!(stats.trashed, 0);
    assert_eq!(items.len(), 2);
    assert_eq!(living(&items).len(), 2);
}

#[test]
fn every_distinct_username_password_pair_survives() {
    // Same name, same notes, same everything — only (username, password)
    // differs. Every pair must survive as a living item.
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
    assert_eq!(stats.trashed, 0, "no pair must be trashed");
    assert_eq!(living(&items).len(), 4);
}

#[test]
fn divergent_totps_collapse_keeping_newest_secret() {
    // Two items identical on name/username/password but with distinct TOTP
    // secrets — the older TOTP is a rotation of the same slot on the same
    // backend, so the group collapses to one LIVING survivor carrying the
    // newer secret. The loser is preserved in Trash (deletedDate set).
    let mut items = vec![
        json!({"type": 1, "name": "Acme",
            "revisionDate": "2025-01-01T00:00:00Z",
            "login": {"username": "u", "password": "p",
                "totp": "otpauth://totp/Acme?secret=OLD"}}),
        json!({"type": 1, "name": "Acme",
            "revisionDate": "2026-06-01T00:00:00Z",
            "login": {"username": "u", "password": "p",
                "totp": "otpauth://totp/Acme?secret=NEW"}}),
    ];
    let stats = dedup_items(&mut items);
    assert_eq!(stats.trashed, 1);
    assert_eq!(items.len(), 2, "nothing removed from array");
    let alive = living(&items);
    assert_eq!(alive.len(), 1);
    let secret = alive[0]
        .get("login")
        .and_then(|l| l.get("totp"))
        .and_then(Value::as_str)
        .unwrap_or("");
    assert!(
        secret.contains("NEW"),
        "newest TOTP must win on the living survivor; got {secret:?}"
    );
    // The loser is preserved in the Trash.
    let gone = trashed(&items);
    assert_eq!(gone.len(), 1);
    let trashed_totp = gone[0]
        .get("login")
        .and_then(|l| l.get("totp"))
        .and_then(Value::as_str)
        .unwrap_or("");
    assert!(
        trashed_totp.contains("OLD"),
        "older TOTP is preserved in Trash (recoverable); got {trashed_totp:?}"
    );
}

#[test]
fn totp_presence_beats_absence_in_merge() {
    // One item carries a TOTP, the other doesn't. After merge, the living
    // survivor must carry the TOTP — absence must never overwrite presence.
    let mut items = vec![
        json!({"type": 1, "name": "Acme",
            "revisionDate": "2026-02-01T00:00:00Z",
            "login": {"username": "u", "password": "p"}}),
        json!({"type": 1, "name": "Acme",
            "revisionDate": "2026-01-01T00:00:00Z",
            "login": {"username": "u", "password": "p",
                "totp": "otpauth://totp/Acme?secret=REAL"}}),
    ];
    dedup_items(&mut items);
    let alive = living(&items);
    assert_eq!(alive.len(), 1, "one living survivor after collapse");
    let secret = alive[0]
        .get("login")
        .and_then(|l| l.get("totp"))
        .and_then(Value::as_str)
        .unwrap_or("");
    assert!(
        secret.contains("REAL"),
        "the only TOTP in the group must move onto the living survivor; got {secret:?}"
    );
}

#[test]
fn distinct_passkeys_prevent_merge_even_when_credentials_match() {
    // FIDO2 / passkey is strict-match. Two items sharing name/user/password
    // but with distinct passkeys must stay separate so neither passkey is
    // overwritten by the survivor selection.
    let mut items = vec![
        json!({
            "type": 1, "name": "GitHub",
            "revisionDate": "2026-01-01T00:00:00Z",
            "login": {
                "username": "u", "password": "p",
                "fido2Credentials": [{
                    "credentialId": "pk-alice", "counter": "1", "userHandle": "ua"
                }]
            }
        }),
        json!({
            "type": 1, "name": "GitHub",
            "revisionDate": "2026-06-01T00:00:00Z",
            "login": {
                "username": "u", "password": "p",
                "fido2Credentials": [{
                    "credentialId": "pk-bob", "counter": "7", "userHandle": "ub"
                }]
            }
        }),
    ];
    let stats = dedup_items(&mut items);
    assert_eq!(stats.trashed, 0, "distinct passkeys must never merge");
    assert_eq!(living(&items).len(), 2);
    // Both passkeys still visible, on their own living items.
    let credential_ids: Vec<&str> = living(&items)
        .iter()
        .flat_map(|i| {
            i.get("login")
                .and_then(|l| l.get("fido2Credentials"))
                .and_then(Value::as_array)
                .map(|arr| {
                    arr.iter()
                        .filter_map(|c| c.get("credentialId").and_then(Value::as_str))
                        .collect::<Vec<&str>>()
                })
                .unwrap_or_default()
        })
        .collect();
    assert!(credential_ids.contains(&"pk-alice"));
    assert!(credential_ids.contains(&"pk-bob"));
}

#[test]
fn passkey_preserved_when_totp_merge_happens() {
    // TOTP-only-differs → merge; both items carry the SAME passkey.
    // Living survivor must retain the passkey (it's the same anyway,
    // but the merge step must not drop it).
    let passkey = json!({"credentialId": "pk-1", "counter": "1", "userHandle": "u"});
    let mut items = vec![
        json!({
            "type": 1, "name": "Service",
            "revisionDate": "2025-01-01T00:00:00Z",
            "login": {
                "username": "u", "password": "p",
                "totp": "otpauth://totp/S?secret=OLD",
                "fido2Credentials": [passkey.clone()]
            }
        }),
        json!({
            "type": 1, "name": "Service",
            "revisionDate": "2026-06-01T00:00:00Z",
            "login": {
                "username": "u", "password": "p",
                "totp": "otpauth://totp/S?secret=NEW",
                "fido2Credentials": [passkey.clone()]
            }
        }),
    ];
    dedup_items(&mut items);
    let alive = living(&items);
    assert_eq!(alive.len(), 1, "TOTP-only divergence should collapse");
    let passkeys = alive[0]
        .get("login")
        .and_then(|l| l.get("fido2Credentials"))
        .and_then(Value::as_array)
        .map(Vec::len)
        .unwrap_or(0);
    assert_eq!(passkeys, 1, "passkey must survive on living item");
}

#[test]
fn split_divergent_totps_opt_in_keeps_items_separate() {
    // Opt-in safety net: when the caller sets `split_divergent_totps`, two
    // items identical on every key field except `login.totp` do not
    // collapse. This protects against a mis-aimed revisionDate heuristic
    // putting the wrong live secret on the survivor when the user knows
    // their vault has been edited unevenly.
    let mut items = vec![
        json!({"type": 1, "name": "Acme",
            "revisionDate": "2026-02-01T00:00:00Z",
            "login": {"username": "u", "password": "p",
                "totp": "otpauth://totp/A?secret=OLD-BUT-LOOKS-NEWER"}}),
        json!({"type": 1, "name": "Acme",
            "revisionDate": "2025-01-01T00:00:00Z",
            "login": {"username": "u", "password": "p",
                "totp": "otpauth://totp/A?secret=CURRENT"}}),
    ];
    let stats = dedup_items_with_config(
        &mut items,
        &DedupConfig {
            split_divergent_totps: true,
        },
    );
    assert_eq!(stats.trashed, 0, "divergent TOTPs must stay separate under opt-in");
    assert_eq!(living(&items).len(), 2);
    // Every TOTP is reachable on a living item — nothing is at risk of
    // being overwritten by a wrong survivor pick.
    let secrets: Vec<&str> = living(&items)
        .iter()
        .filter_map(|i| {
            i.get("login")
                .and_then(|l| l.get("totp"))
                .and_then(Value::as_str)
        })
        .collect();
    assert!(secrets.iter().any(|s| s.contains("OLD-BUT-LOOKS-NEWER")));
    assert!(secrets.iter().any(|s| s.contains("CURRENT")));
}

#[test]
fn lone_secure_note_passes_through_unchanged() {
    // A `type: 2` Secure Note with no same-name sibling has no dedup
    // group to collapse, so it must land in the output byte-identical
    // to the input — every field preserved, not trashed.
    let secure_note_input = json!({
        "id": "note-1",
        "type": 2,
        "name": "Recovery codes — GitHub",
        "notes": "  Line 1: backup code AAAA-BBBB\n  Line 2: backup code CCCC-DDDD  ",
        "folderId": "folder-security",
        "favorite": true,
        "fields": [
            {"name": "where", "value": "Generated 2026-01-01", "type": 0}
        ],
        "revisionDate": "2026-01-02T00:00:00Z",
        "creationDate": "2026-01-01T00:00:00Z",
        "secureNote": {"type": 0}
    });
    let mut items = vec![
        secure_note_input.clone(),
        // A normal login item in the same run so the pipeline actually
        // runs; the note must not be touched by anything the login path
        // does.
        json!({"type": 1, "name": "Gmail",
            "revisionDate": "2026-01-01T00:00:00Z",
            "login": {"username": "u", "password": "p"}}),
    ];
    let stats = dedup_items(&mut items);
    assert_eq!(stats.trashed, 0);
    let survivor = items
        .iter()
        .find(|i| i["id"].as_str() == Some("note-1"))
        .expect("secure note must still be in output");
    assert_eq!(*survivor, secure_note_input);
}

#[test]
fn same_name_secure_notes_collapse_with_identical_body_deduped() {
    // Two `type: 2` items sharing the same name AND the same notes body
    // collapse into one living survivor; the loser is trashed. The
    // surviving notes body is unchanged (no `=== Merged === ` header
    // because the drop's body was identical and therefore skipped).
    let mut items = vec![
        json!({
            "id": "n-a", "type": 2, "name": "Recovery",
            "notes": "codes",
            "revisionDate": "2026-02-01T00:00:00Z",
            "secureNote": {"type": 0}
        }),
        json!({
            "id": "n-b", "type": 2, "name": "Recovery",
            "notes": "codes",
            "revisionDate": "2026-01-01T00:00:00Z",
            "secureNote": {"type": 0}
        }),
    ];
    let stats = dedup_items(&mut items);
    assert_eq!(stats.trashed, 1);
    let alive = living(&items);
    assert_eq!(alive.len(), 1);
    assert_eq!(alive[0]["notes"].as_str(), Some("codes"),
        "identical bodies should not produce a merge banner");
    assert_eq!(trashed(&items).len(), 1, "loser preserved in Trash");
}

#[test]
fn same_name_secure_notes_with_different_bodies_stay_separate() {
    // Strict secure-note key: two notes sharing only a name but
    // carrying different trimmed bodies are NOT considered duplicates.
    // Both stay living — the operator reconciles by hand if they
    // actually represent the same concept. This is the safety floor
    // that protects generic names like "Recovery" or "credentials.txt".
    let mut items = vec![
        json!({
            "id": "bw-note", "type": 2, "name": "Abus Lock",
            "notes": "official share URL saved 2024",
            "revisionDate": "2026-01-01T00:00:00Z",
            "secureNote": {"type": 0}
        }),
        json!({
            "id": "apple-csv-1776000000-000042", "type": 2, "name": "Abus Lock",
            "notes": "completely different note body — not a duplicate",
            "revisionDate": "2026-04-23T00:00:00Z",
            "secureNote": {"type": 0}
        }),
    ];
    let stats = dedup_items(&mut items);
    assert_eq!(stats.trashed, 0, "distinct bodies must not auto-collapse");
    assert_eq!(living(&items).len(), 2, "both notes stay living");
}

#[test]
fn personal_and_org_secure_notes_never_cross_dedup() {
    // Personal (organizationId=null) and org-owned notes with the same
    // name AND body must never collapse — they live in different
    // vaults with different access control.
    let mut items = vec![
        json!({
            "id": "personal", "type": 2, "name": "Shared Wiki",
            "organizationId": null,
            "notes": "internal URL",
            "revisionDate": "2026-01-01T00:00:00Z",
            "secureNote": {"type": 0}
        }),
        json!({
            "id": "org", "type": 2, "name": "Shared Wiki",
            "organizationId": "11111111-1111-1111-1111-111111111111",
            "notes": "internal URL",
            "revisionDate": "2026-02-01T00:00:00Z",
            "secureNote": {"type": 0}
        }),
    ];
    let stats = dedup_items(&mut items);
    assert_eq!(stats.trashed, 0, "personal and org notes must not cross-dedup");
    assert_eq!(living(&items).len(), 2);
}

#[test]
fn secure_note_loser_preserved_in_trash_with_deleted_date() {
    // Consistent with login dedup: a trashed secure note still carries
    // its original body (byte-identical, including any surrounding
    // whitespace) so the operator can recover from Bitwarden's Trash.
    // Strict-body grouping: both items must share the same trimmed
    // body to land in the same group.
    let mut items = vec![
        json!({
            "id": "newer", "type": 2, "name": "Wallet",
            "notes": "seed",
            "revisionDate": "2026-06-01T00:00:00Z",
            "secureNote": {"type": 0}
        }),
        json!({
            "id": "older", "type": 2, "name": "Wallet",
            // Same trimmed body as the newer item → both group together.
            "notes": "  seed\n",
            "revisionDate": "2025-01-01T00:00:00Z",
            "secureNote": {"type": 0}
        }),
    ];
    dedup_items(&mut items);
    let dropped = items
        .iter()
        .find(|i| i["id"].as_str() == Some("older"))
        .unwrap();
    assert!(
        !dropped["deletedDate"].is_null(),
        "older (= loser) must carry deletedDate so Bitwarden shows it in Trash"
    );
    assert_eq!(
        dropped["notes"].as_str(),
        Some("  seed\n"),
        "trashed loser retains its original body byte-for-byte — recoverable"
    );
}

#[test]
fn secure_notes_and_logins_with_same_name_do_not_collide() {
    // A login and a secure note that happen to share a display name
    // must stay separate — different type namespaces.
    let mut items = vec![
        json!({
            "id": "note", "type": 2, "name": "credentials.txt",
            "notes": "private notes body",
            "revisionDate": "2026-01-01T00:00:00Z",
            "secureNote": {"type": 0}
        }),
        json!({
            "id": "login", "type": 1, "name": "credentials.txt",
            "revisionDate": "2026-01-01T00:00:00Z",
            "login": {"username": "u", "password": "p"}
        }),
    ];
    let stats = dedup_items(&mut items);
    assert_eq!(stats.trashed, 0, "login/note cross-type grouping must not happen");
    assert_eq!(living(&items).len(), 2);
}

#[test]
fn non_login_types_are_all_preserved() {
    // Cards (type 3), identities (type 4), SSH keys (type 5) — none
    // of these flow through the dedup grouping step. They pass through
    // regardless of what other items share their name.
    let mut items = vec![
        json!({"id": "card", "type": 3, "name": "Visa",
            "revisionDate": "2026-01-01T00:00:00Z"}),
        json!({"id": "ident", "type": 4, "name": "Personal",
            "revisionDate": "2026-01-01T00:00:00Z"}),
        json!({"id": "ssh",   "type": 5, "name": "laptop-key",
            "revisionDate": "2026-01-01T00:00:00Z"}),
        // A duplicate login group alongside — makes sure the non-login
        // pass-through is unaffected by dedup activity elsewhere.
        json!({"id": "login-a", "type": 1, "name": "Site",
            "revisionDate": "2026-01-01T00:00:00Z",
            "login": {"username": "u", "password": "p"}}),
        json!({"id": "login-b", "type": 1, "name": "Site",
            "revisionDate": "2026-02-01T00:00:00Z",
            "login": {"username": "u", "password": "p"}}),
    ];
    dedup_items(&mut items);
    for want_id in ["card", "ident", "ssh"] {
        let item = items
            .iter()
            .find(|i| i["id"].as_str() == Some(want_id))
            .unwrap_or_else(|| panic!("{want_id} missing from output"));
        assert!(
            item["deletedDate"].is_null(),
            "{want_id} must not be trashed by dedup"
        );
    }
}

#[test]
fn dedup_never_removes_items_from_output() {
    // Core invariant: no matter how aggressive the dedup, `items.len()`
    // after dedup must equal `items.len()` before. Losers are trashed
    // (deletedDate set), not removed.
    let mut items = vec![
        json!({"type": 1, "name": "X",
            "revisionDate": "2026-01-01T00:00:00Z",
            "login": {"username": "u", "password": "p"}}),
        json!({"type": 1, "name": "X",
            "revisionDate": "2026-02-01T00:00:00Z",
            "login": {"username": "u", "password": "p"}}),
        json!({"type": 1, "name": "X",
            "revisionDate": "2026-03-01T00:00:00Z",
            "login": {"username": "u", "password": "p"}}),
    ];
    let before = items.len();
    let stats = dedup_items(&mut items);
    assert_eq!(items.len(), before, "dedup must never shrink the array");
    assert_eq!(stats.output, before);
    assert_eq!(stats.trashed, 2);
    assert_eq!(stats.living, 1);
    // Every trashed item has a non-null `deletedDate`.
    for t in trashed(&items) {
        assert!(
            t["deletedDate"].as_str().is_some_and(|s| !s.is_empty()),
            "trashed items must have ISO 8601 deletedDate: {}",
            t
        );
    }
}

// --- SSH key dedup --------------------------------------------------

#[test]
fn ssh_keys_with_identical_material_collapse() {
    // Two `type: 5` items carrying the exact same SSH key material —
    // same public key, private key, fingerprint — dedup cleanly. The
    // loser is trashed, key material never touched.
    let ssh = json!({
        "publicKey": "ssh-ed25519 AAAAC... alex@laptop",
        "privateKey": "-----BEGIN OPENSSH PRIVATE KEY-----\nSECRET\n-----END-----",
        "keyFingerprint": "SHA256:abcd1234"
    });
    let mut items = vec![
        json!({
            "id": "newer", "type": 5, "name": "laptop-ed25519",
            "revisionDate": "2026-02-01T00:00:00Z",
            "sshKey": ssh
        }),
        json!({
            "id": "older", "type": 5, "name": "laptop key",
            "revisionDate": "2025-01-01T00:00:00Z",
            "sshKey": json!({
                "publicKey": "ssh-ed25519 AAAAC... alex@laptop",
                "privateKey": "-----BEGIN OPENSSH PRIVATE KEY-----\nSECRET\n-----END-----",
                "keyFingerprint": "SHA256:abcd1234"
            })
        }),
    ];
    let stats = dedup_items(&mut items);
    assert_eq!(stats.trashed, 1);
    let alive = living(&items);
    assert_eq!(alive.len(), 1);
    assert_eq!(alive[0]["id"].as_str(), Some("newer"));
    // Longest name wins on the merged record.
    assert_eq!(alive[0]["name"].as_str(), Some("laptop-ed25519"));
    // Key material untouched.
    assert_eq!(alive[0]["sshKey"]["keyFingerprint"].as_str(), Some("SHA256:abcd1234"));
}

#[test]
fn ssh_keys_with_different_private_keys_never_merge() {
    // Same public key + different private key material is almost
    // certainly corrupt state. Refuse to guess — keep both living.
    let mut items = vec![
        json!({
            "type": 5, "name": "id-ed25519",
            "revisionDate": "2026-01-01T00:00:00Z",
            "sshKey": {
                "publicKey": "ssh-ed25519 AAAA.SAME",
                "privateKey": "PRIV-ONE",
                "keyFingerprint": "fp-1"
            }
        }),
        json!({
            "type": 5, "name": "id-ed25519",
            "revisionDate": "2026-02-01T00:00:00Z",
            "sshKey": {
                "publicKey": "ssh-ed25519 AAAA.SAME",
                "privateKey": "PRIV-TWO",
                "keyFingerprint": "fp-2"
            }
        }),
    ];
    let stats = dedup_items(&mut items);
    assert_eq!(stats.trashed, 0, "divergent SSH private keys must never merge");
    assert_eq!(living(&items).len(), 2);
}

// --- Folder dedup ---------------------------------------------------

#[test]
fn duplicate_folders_collapse_and_folder_ids_remap() {
    // Two folders share the same normalized name ("main"). They
    // collapse to one and every item's `folderId` is remapped to the
    // survivor so references stay valid after import.
    let mut export = json!({
        "folders": [
            {"id": "folder-a", "name": "main"},
            {"id": "folder-b", "name": "main"},
            {"id": "folder-c", "name": "work"}
        ],
        "items": [
            {
                "id": "item-1", "type": 1, "name": "Site-A",
                "folderId": "folder-a",
                "revisionDate": "2026-01-01T00:00:00Z",
                "login": {"username": "u1", "password": "p1"}
            },
            {
                "id": "item-2", "type": 1, "name": "Site-B",
                "folderId": "folder-b",
                "revisionDate": "2026-01-01T00:00:00Z",
                "login": {"username": "u2", "password": "p2"}
            },
            {
                "id": "item-3", "type": 1, "name": "Site-C",
                "folderId": "folder-c",
                "revisionDate": "2026-01-01T00:00:00Z",
                "login": {"username": "u3", "password": "p3"}
            }
        ]
    });
    let stats = dedup_export(&mut export).unwrap();
    assert_eq!(stats.folders_deduplicated, 1);
    // Two unique folder names remain: `main` and `work`.
    let folders = export["folders"].as_array().unwrap();
    assert_eq!(folders.len(), 2);
    let names: Vec<&str> = folders
        .iter()
        .filter_map(|f| f["name"].as_str())
        .collect();
    assert!(names.contains(&"main"));
    assert!(names.contains(&"work"));
    // Items that used to live in folder-b now point at folder-a
    // (first-seen wins), item-3 still points at folder-c.
    let items = export["items"].as_array().unwrap();
    let by_id = |id: &str| {
        items
            .iter()
            .find(|i| i["id"].as_str() == Some(id))
            .expect(id)
    };
    assert_eq!(by_id("item-1")["folderId"].as_str(), Some("folder-a"));
    assert_eq!(
        by_id("item-2")["folderId"].as_str(),
        Some("folder-a"),
        "item originally in folder-b must be remapped to survivor folder-a"
    );
    assert_eq!(by_id("item-3")["folderId"].as_str(), Some("folder-c"));
}

#[test]
fn folder_dedup_ignores_invisible_noise_in_names() {
    // Folders with the same visible name but with ZWSP / NBSP noise
    // collapse just like secure notes.
    let mut export = json!({
        "folders": [
            {"id": "f-1", "name": "main"},
            {"id": "f-2", "name": "\u{00A0}ma\u{200B}in\u{00A0}"}
        ],
        "items": []
    });
    let stats = dedup_export(&mut export).unwrap();
    assert_eq!(stats.folders_deduplicated, 1);
    assert_eq!(export["folders"].as_array().unwrap().len(), 1);
}

#[test]
fn folder_dedup_tolerates_missing_or_null_folders_field() {
    // Exports that don't carry `folders` (or carry `folders: null`)
    // must not blow up — just report zero collapses.
    let mut no_folders = json!({"items": []});
    let s = dedup_export(&mut no_folders).unwrap();
    assert_eq!(s.folders_deduplicated, 0);
    let mut null_folders = json!({"folders": null, "items": []});
    let s = dedup_export(&mut null_folders).unwrap();
    assert_eq!(s.folders_deduplicated, 0);
}
