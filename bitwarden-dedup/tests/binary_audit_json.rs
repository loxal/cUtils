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

/// Two empty-password stubs that should collapse under
/// `--collapse-empty-passwords`, plus one strict-pass duplicate pair
/// (so the resulting audit JSON exercises both passes' counters).
fn synthetic_export() -> Value {
    json!({
        "folders": [],
        "items": [
            // strict-pass duplicate
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
            // empty-pw duplicate (host signal)
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

    let result = Command::new(DEDUP_BIN)
        .arg("--input")
        .arg(&input)
        .arg("--output")
        .arg(&output)
        .arg("--audit")
        .arg(&audit)
        .arg("--collapse-empty-passwords")
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
        "collapse_empty_passwords",
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

    // Counts match expectations: 1 strict-pass group + 1 empty-pw
    // group + 0 secure-note + 0 ssh-key. duplicate_groups is the sum.
    assert_eq!(audit_doc["strict_login_groups"], 1);
    assert_eq!(audit_doc["empty_password_groups"], 1);
    assert_eq!(audit_doc["secure_note_groups"], 0);
    assert_eq!(audit_doc["ssh_key_groups"], 0);
    assert_eq!(audit_doc["duplicate_groups"], 2);
    assert_eq!(audit_doc["collapse_empty_passwords"], true);
    assert_eq!(audit_doc["empty_password_trashed"], 1);

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

    cleanup(&dir);
}

#[test]
fn bitwarden_dedup_audit_json_off_by_default_omits_empty_pw_collapse() {
    // Without `--collapse-empty-passwords`, the per-pass counters
    // for the empty-password pass must be zero AND the
    // `collapse_empty_passwords` flag must serialize as `false`.
    // Regression guard: the binary currently surfaces both, and a
    // future refactor that flips the default would silently change
    // this output.
    let dir = scratch_dir("dedup-default");
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
        ],
    );
    assert!(result.status.success());

    let audit_doc: Value = serde_json::from_str(&std::fs::read_to_string(&audit).unwrap()).unwrap();
    assert_eq!(audit_doc["collapse_empty_passwords"], false);
    assert_eq!(audit_doc["empty_password_groups"], 0);
    assert_eq!(audit_doc["empty_password_trashed"], 0);
    // The two empty-pw stubs stay as living items (strict pass
    // skipped them; no second pass ran).
    assert_eq!(audit_doc["living_item_count"], 3);

    cleanup(&dir);
}

#[test]
fn bitwarden_merge_icloud_audit_json_has_all_documented_fields() {
    let dir = scratch_dir("merge-fields");
    let bw_input = dir.join("bitwarden.json");
    let csv_input = dir.join("apple.csv");
    let output = dir.join("merged.json");
    let audit = dir.join("merged.audit.json");

    // Bitwarden side: one empty-pw stub for acme. CSV side: another
    // empty-pw row for the same domain. With the flag set, they
    // collapse via the empty-password pass.
    let bw = json!({
        "folders": [],
        "items": [
            {
                "id": "bw-1", "type": 1, "name": "Acme",
                "revisionDate": "2026-01-01T00:00:00Z",
                "login": {"username": "u@acme.example.test", "password": "",
                    "uris": [{"uri": "https://acme.example.test/"}]}
            }
        ]
    });
    std::fs::write(&bw_input, bw.to_string()).unwrap();
    std::fs::write(
        &csv_input,
        "Title,URL,Username,Password,Notes,OTPAuth\n\
         Acme,https://acme.example.test/,u@acme.example.test,,,\n",
    )
    .unwrap();

    let result = Command::new(MERGE_BIN)
        .arg("--bitwarden")
        .arg(&bw_input)
        .arg("--icloud")
        .arg(&csv_input)
        .arg("--output")
        .arg(&output)
        .arg("--audit")
        .arg(&audit)
        .arg("--collapse-empty-passwords")
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
        "collapse_empty_passwords",
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

    // CSV row collapsed against the existing Bitwarden stub.
    assert_eq!(audit_doc["collapse_empty_passwords"], true);
    assert_eq!(audit_doc["csv_rows_total"], 1);
    assert_eq!(audit_doc["csv_rows_appended"], 1);
    assert_eq!(audit_doc["empty_password_groups"], 1);
    assert_eq!(audit_doc["empty_password_trashed"], 1);
    assert_eq!(audit_doc["skipped_from_dedup"], audit_doc["strict_pass_skipped"]);

    cleanup(&dir);
}
