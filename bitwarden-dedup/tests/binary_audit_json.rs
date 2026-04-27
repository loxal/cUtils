// Copyright 2026 Alexander Orlov <alexander.orlov@loxal.net>

//! Subprocess tests for the audit JSON contracts of
//! `bitwarden-dedup` and `bitwarden-merge-icloud`.
//!
//! Library-level tests already cover [`bitwarden_dedup::DedupStats`]
//! field population, but neither binary's `json!` literal is
//! exercised — deleting a field from the audit doc would silently
//! pass library tests. These tests close that gap by invoking the
//! compiled binaries (via the `CARGO_BIN_EXE_*` env vars Cargo sets
//! for integration tests) on minimal synthetic inputs and asserting
//! field presence on the on-disk audit JSON.
//!
//! Mirrors the subprocess pattern in `tests/redactor.rs`.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{Value, json};

const DEDUP_BIN: &str = env!("CARGO_BIN_EXE_bitwarden-dedup");
const MERGE_BIN: &str = env!("CARGO_BIN_EXE_bitwarden-merge-icloud");

fn scratch_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "bwd-audit-{label}-{}-{}",
        std::process::id(),
        nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

fn cleanup(dir: &Path) {
    let _ = std::fs::remove_dir_all(dir);
}

/// One duplicate of every dedupable type so the resulting audit
/// JSON exercises every pass's counter in a single end-to-end run:
/// strict-login pair, empty-password pair, card pair, identity
/// pair. All four collapse by default; the empty-password pair
/// stays as separate items only when `--keep-empty-password-stubs`
/// is passed.
fn synthetic_export() -> Value {
    json!({
        "folders": [],
        "items": [
            // strict-pass login duplicate
            {
                "id": "s1", "type": 1, "name": "Strict",
                "revisionDate": "2026-01-01T00:00:00Z",
                "login": {"username": "u", "password": "p",
                    "uris": [{"uri": "https://strict.example.test/"}]}
            },
            {
                "id": "s2", "type": 1, "name": "Strict",
                "revisionDate": "2026-01-02T00:00:00Z",
                "login": {"username": "u", "password": "p",
                    "uris": [{"uri": "https://strict.example.test/"}]}
            },
            // empty-password login duplicate (host signal)
            {
                "id": "e1", "type": 1, "name": "Acme",
                "revisionDate": "2026-01-01T00:00:00Z",
                "login": {"username": "u@acme.example.test", "password": "",
                    "uris": [{"uri": "https://acme.example.test/"}]}
            },
            {
                "id": "e2", "type": 1, "name": "Acme",
                "revisionDate": "2026-01-02T00:00:00Z",
                "login": {"username": "u@acme.example.test", "password": "",
                    "uris": [{"uri": "https://acme.example.test/"}]}
            },
            // card duplicate (synthetic — never a real PAN)
            {
                "id": "c1", "type": 3, "name": "TestCard",
                "revisionDate": "2026-01-01T00:00:00Z",
                "card": {
                    "cardholderName": "Test User", "brand": "Visa",
                    "number": "0000000000000000", "expMonth": "12",
                    "expYear": "2099", "code": "000"
                }
            },
            {
                "id": "c2", "type": 3, "name": "TestCard",
                "revisionDate": "2026-01-02T00:00:00Z",
                "card": {
                    "cardholderName": "Test User", "brand": "Visa",
                    "number": "0000000000000000", "expMonth": "12",
                    "expYear": "2099", "code": "000"
                }
            },
            // identity duplicate
            {
                "id": "i1", "type": 4, "name": "TestIdentity",
                "revisionDate": "2026-01-01T00:00:00Z",
                "identity": {
                    "firstName": "Test", "lastName": "User",
                    "email": "user@example.test"
                }
            },
            {
                "id": "i2", "type": 4, "name": "TestIdentity",
                "revisionDate": "2026-01-02T00:00:00Z",
                "identity": {
                    "firstName": "Test", "lastName": "User",
                    "email": "user@example.test"
                }
            },
        ]
    })
}

fn run_bin(bin: &str, args: &[&Path]) -> std::process::Output {
    let mut cmd = Command::new(bin);
    for a in args {
        cmd.arg(a);
    }
    cmd.output().expect("spawn binary")
}

#[test]
fn bitwarden_dedup_audit_json_has_all_documented_fields() {
    let dir = scratch_dir("dedup-fields");
    let input = dir.join("vault.json");
    let output = dir.join("vault.dedup.json");
    let audit = dir.join("vault.audit.json");

    std::fs::write(&input, synthetic_export().to_string()).unwrap();

    // Default invocation — empty-password pass runs without any
    // explicit flag now. This test exercises the same end-to-end
    // path an operator hits when they run `just dedup`.
    let result = Command::new(DEDUP_BIN)
        .arg("--input")
        .arg(&input)
        .arg("--output")
        .arg(&output)
        .arg("--audit")
        .arg(&audit)
        .output()
        .expect("spawn bitwarden-dedup");
    assert!(
        result.status.success(),
        "bitwarden-dedup failed: stdout={} stderr={}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr),
    );

    let audit_text = std::fs::read_to_string(&audit).unwrap();
    let audit_doc: Value = serde_json::from_str(&audit_text).unwrap();

    // Every field the binary's json! literal promises must be
    // present. Deleting any of these from src/main.rs makes this
    // test fail loud — exactly the regression coverage the library
    // tests cannot provide.
    let required_top_level = [
        "input",
        "output",
        "trashed_sidecar",
        "trashed_sidecar_item_count",
        "split_divergent_totps",
        "keep_empty_password_stubs",
        "input_item_count",
        "output_item_count",
        "living_item_count",
        "trashed_count",
        "removed_count", // back-compat alias for trashed_count
        "duplicate_groups",
        "strict_login_groups",
        "empty_password_groups",
        "empty_password_trashed",
        "empty_password_groups_by_signal",
        "secure_note_groups",
        "ssh_key_groups",
        "card_groups",
        "identity_groups",
        "totp_conflict_groups",
        "folders_deduplicated",
        "strict_pass_skipped",
        "skipped_from_dedup", // back-compat alias for strict_pass_skipped
        "uris_merged_into_kept_total",
        "entries",
    ];
    for field in &required_top_level {
        assert!(
            audit_doc.get(field).is_some(),
            "audit JSON missing required field `{field}`. Full top-level keys: {:?}",
            audit_doc
                .as_object()
                .map(|o| o.keys().collect::<Vec<_>>())
                .unwrap_or_default()
        );
    }

    // Counts match expectations: 1 strict-pass + 1 empty-pw + 1 card
    // + 1 identity = 4 groups; secure-note and ssh-key groups stay 0
    // (no fixture items of those types). duplicate_groups is the sum.
    assert_eq!(audit_doc["strict_login_groups"], 1);
    assert_eq!(audit_doc["empty_password_groups"], 1);
    assert_eq!(audit_doc["secure_note_groups"], 0);
    assert_eq!(audit_doc["ssh_key_groups"], 0);
    assert_eq!(audit_doc["card_groups"], 1);
    assert_eq!(audit_doc["identity_groups"], 1);
    assert_eq!(audit_doc["duplicate_groups"], 4);
    assert_eq!(audit_doc["keep_empty_password_stubs"], false);
    assert_eq!(audit_doc["empty_password_trashed"], 1);
    // Each duplicate pair contributes one trashed loser → 4 total.
    assert_eq!(audit_doc["trashed_count"], 4);

    // Back-compat aliases hold the same values as their new keys.
    assert_eq!(audit_doc["skipped_from_dedup"], audit_doc["strict_pass_skipped"]);
    assert_eq!(audit_doc["removed_count"], audit_doc["trashed_count"]);

    // Per-entry shape: every empty-pw drop has both the item_kind
    // and signal_kind that downstream tooling relies on.
    let entries = audit_doc["entries"].as_array().unwrap();
    let epw_entries: Vec<&Value> = entries
        .iter()
        .filter(|e| e["item_kind"] == "empty_password_login")
        .collect();
    assert_eq!(
        epw_entries.len(),
        1,
        "exactly one empty-pw drop expected from this fixture"
    );
    let signal = epw_entries[0]["signal_kind"]
        .as_str()
        .expect("signal_kind must be a string on every empty-pw entry");
    assert!(
        ["fido2", "host", "username_only"].contains(&signal),
        "unexpected signal_kind {signal:?}"
    );

    // Card and identity audit entries — labeled with the right
    // item_kind so downstream tooling can grep them. Confirms the
    // card/identity passes actually fired through the binary, not
    // just that the audit-doc keys exist.
    let card_entries: Vec<&Value> = entries
        .iter()
        .filter(|e| e["item_kind"] == "card")
        .collect();
    assert_eq!(card_entries.len(), 1, "expected one trashed card from the fixture");
    assert_eq!(card_entries[0]["removed_id"], "c1");
    assert_eq!(card_entries[0]["kept_id"], "c2");

    let identity_entries: Vec<&Value> = entries
        .iter()
        .filter(|e| e["item_kind"] == "identity")
        .collect();
    assert_eq!(identity_entries.len(), 1);
    assert_eq!(identity_entries[0]["removed_id"], "i1");
    assert_eq!(identity_entries[0]["kept_id"], "i2");

    cleanup(&dir);
}

#[test]
fn bitwarden_dedup_audit_json_keep_empty_password_stubs_opts_out() {
    // With `--keep-empty-password-stubs`, the per-pass counters for
    // the empty-password pass must be zero AND the
    // `keep_empty_password_stubs` flag must serialize as `true`.
    // The other passes (strict-login, card, identity) still run.
    // Regression guard: a refactor that mis-wires the opt-out would
    // either suppress those passes too (over-correcting) or fail to
    // suppress the empty-pw pass (under-correcting).
    let dir = scratch_dir("dedup-keep-stubs");
    let input = dir.join("vault.json");
    let output = dir.join("vault.dedup.json");
    let audit = dir.join("vault.audit.json");

    std::fs::write(&input, synthetic_export().to_string()).unwrap();

    let result = run_bin(
        DEDUP_BIN,
        &[
            Path::new("--input"),
            &input,
            Path::new("--output"),
            &output,
            Path::new("--audit"),
            &audit,
            Path::new("--keep-empty-password-stubs"),
        ],
    );
    assert!(result.status.success());

    let audit_doc: Value = serde_json::from_str(&std::fs::read_to_string(&audit).unwrap()).unwrap();
    assert_eq!(audit_doc["keep_empty_password_stubs"], true);
    assert_eq!(audit_doc["empty_password_groups"], 0);
    assert_eq!(audit_doc["empty_password_trashed"], 0);
    // Card and identity passes still run regardless of this flag,
    // so they collapse their fixtures. The empty-pw pair stays as
    // 2 living items because the opt-out is set.
    assert_eq!(audit_doc["card_groups"], 1);
    assert_eq!(audit_doc["identity_groups"], 1);
    // Living item arithmetic with this fixture (8 input items):
    //   strict-login: 2 → 1, empty-pw: 2 → 2, card: 2 → 1, identity: 2 → 1.
    // Total living = 1 + 2 + 1 + 1 = 5.
    assert_eq!(audit_doc["living_item_count"], 5);

    cleanup(&dir);
}

#[test]
fn bitwarden_merge_icloud_audit_json_has_all_documented_fields() {
    let dir = scratch_dir("merge-fields");
    let bw_input = dir.join("bitwarden.json");
    let csv_input = dir.join("apple.csv");
    let output = dir.join("merged.json");
    let audit = dir.join("merged.audit.json");

    // Bitwarden side: an empty-pw stub for acme that the CSV row
    // collapses against, plus a card duplicate pair and an identity
    // duplicate pair. The card and identity passes always run by
    // default (no opt-in flag), so the merge binary must report
    // non-zero `card_groups` / `identity_groups` in its audit JSON.
    // Apple's Passwords CSV does not carry cards or identities, so
    // the duplicates live entirely on the Bitwarden side.
    let bw = json!({
        "folders": [],
        "items": [
            {
                "id": "bw-1", "type": 1, "name": "Acme",
                "revisionDate": "2026-01-01T00:00:00Z",
                "login": {"username": "u@acme.example.test", "password": "",
                    "uris": [{"uri": "https://acme.example.test/"}]}
            },
            // card duplicate (synthetic — never a real PAN)
            {
                "id": "c1", "type": 3, "name": "TestCard",
                "revisionDate": "2026-01-01T00:00:00Z",
                "card": {
                    "cardholderName": "Test User", "brand": "Visa",
                    "number": "0000000000000000", "expMonth": "12",
                    "expYear": "2099", "code": "000"
                }
            },
            {
                "id": "c2", "type": 3, "name": "TestCard",
                "revisionDate": "2026-01-02T00:00:00Z",
                "card": {
                    "cardholderName": "Test User", "brand": "Visa",
                    "number": "0000000000000000", "expMonth": "12",
                    "expYear": "2099", "code": "000"
                }
            },
            // identity duplicate
            {
                "id": "i1", "type": 4, "name": "TestIdentity",
                "revisionDate": "2026-01-01T00:00:00Z",
                "identity": {
                    "firstName": "Test", "lastName": "User",
                    "email": "user@example.test"
                }
            },
            {
                "id": "i2", "type": 4, "name": "TestIdentity",
                "revisionDate": "2026-01-02T00:00:00Z",
                "identity": {
                    "firstName": "Test", "lastName": "User",
                    "email": "user@example.test"
                }
            },
        ]
    });
    std::fs::write(&bw_input, bw.to_string()).unwrap();
    std::fs::write(
        &csv_input,
        "Title,URL,Username,Password,Notes,OTPAuth\n\
         Acme,https://acme.example.test/,u@acme.example.test,,,\n",
    )
    .unwrap();

    // Default invocation — empty-password pass runs without an
    // explicit flag.
    let result = Command::new(MERGE_BIN)
        .arg("--bitwarden")
        .arg(&bw_input)
        .arg("--icloud")
        .arg(&csv_input)
        .arg("--output")
        .arg(&output)
        .arg("--audit")
        .arg(&audit)
        .output()
        .expect("spawn bitwarden-merge-icloud");
    assert!(
        result.status.success(),
        "bitwarden-merge-icloud failed: stdout={} stderr={}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr),
    );

    let audit_text = std::fs::read_to_string(&audit).unwrap();
    let audit_doc: Value = serde_json::from_str(&audit_text).unwrap();

    let required_top_level = [
        "bitwarden_input",
        "icloud_csv_input",
        "output",
        "trashed_sidecar",
        "trashed_sidecar_item_count",
        "split_divergent_totps",
        "keep_empty_password_stubs",
        "csv_rows_total",
        "csv_rows_appended",
        "csv_rows_skipped_empty",
        "combined_input_item_count",
        "combined_output_item_count",
        "combined_living_count",
        "combined_trashed_count",
        "duplicate_groups",
        "strict_login_groups",
        "empty_password_groups",
        "empty_password_trashed",
        "empty_password_groups_by_signal",
        "secure_note_groups",
        "ssh_key_groups",
        "card_groups",
        "identity_groups",
        "totp_conflict_groups",
        "folders_deduplicated",
        "strict_pass_skipped",
        "skipped_from_dedup",
        "uris_merged_into_kept_total",
        "entries",
    ];
    for field in &required_top_level {
        assert!(
            audit_doc.get(field).is_some(),
            "merge audit JSON missing required field `{field}`. Full top-level keys: {:?}",
            audit_doc
                .as_object()
                .map(|o| o.keys().collect::<Vec<_>>())
                .unwrap_or_default()
        );
    }

    // CSV row collapsed against the existing Bitwarden stub by
    // default (the empty-password pass runs without the opt-out).
    assert_eq!(audit_doc["keep_empty_password_stubs"], false);
    assert_eq!(audit_doc["csv_rows_total"], 1);
    assert_eq!(audit_doc["csv_rows_appended"], 1);
    assert_eq!(audit_doc["empty_password_groups"], 1);
    assert_eq!(audit_doc["empty_password_trashed"], 1);
    assert_eq!(audit_doc["skipped_from_dedup"], audit_doc["strict_pass_skipped"]);

    // Card and identity passes ran on the merged set and collapsed
    // their respective Bitwarden-side duplicates. Regression guard:
    // a refactor that forgot to call `dedup_cards` / `dedup_identities`
    // through the merge code path would silently zero these out.
    assert_eq!(audit_doc["card_groups"], 1);
    assert_eq!(audit_doc["identity_groups"], 1);

    // Per-entry shape: the merge binary's audit must label its
    // card/identity drops with the expected `item_kind`.
    let entries = audit_doc["entries"].as_array().unwrap();
    let card_entries: Vec<&Value> = entries
        .iter()
        .filter(|e| e["item_kind"] == "card")
        .collect();
    assert_eq!(card_entries.len(), 1, "expected one trashed card from the merge fixture");
    let identity_entries: Vec<&Value> = entries
        .iter()
        .filter(|e| e["item_kind"] == "identity")
        .collect();
    assert_eq!(identity_entries.len(), 1);

    cleanup(&dir);
}
