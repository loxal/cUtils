// Copyright 2026 Alexander Orlov <alexander.orlov@loxal.net>

//! Move every item in a Bitwarden vault export into a single folder.
//!
//! Replaces the export's `folders` array with one folder of the given
//! name and rewrites every item's `folderId` to point at it. The new
//! folder gets a fresh v4 UUID; Bitwarden's import re-resolves folders
//! by name on the way in, so the generated UUID only needs to satisfy
//! the export schema.
//!
//! Auto-discovers the latest `bitwarden_export_*.json` in `vault/` when
//! `--input` is omitted, excluding sidecar shapes the other binaries
//! produce (`*.dedup.json`, `*-with-icloud-credentials.json`,
//! `*.in-folder-*.json`, etc.) so re-runs never re-consume their own
//! output.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use bitwarden_dedup::io_util::write_sensitive_atomic;
use clap::Parser;
use serde_json::{Value, json};

#[derive(Parser, Debug)]
#[command(
    name = "bitwarden-move-to-folder",
    about = "Move every item in a Bitwarden export into a single folder. \
             Replaces the export's `folders` array with one folder of the \
             given name and rewrites every item's `folderId` to match."
)]
struct Cli {
    /// Name of the destination folder. Bitwarden's import re-resolves
    /// folder UUIDs by name, so this is the label an operator will see.
    #[arg(short, long, default_value = "main")]
    folder: String,

    /// Path to the Bitwarden export JSON. If omitted, the latest
    /// `vault/bitwarden_export_*.json` is auto-discovered.
    #[arg(short, long)]
    input: Option<PathBuf>,

    /// Output path (default: `<input_stem>.in-folder-<folder>.json` next
    /// to the input).
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Allow `--output` to resolve to the same path as `--input`.
    /// WITHOUT this flag, a collision is a hard error — the default
    /// protects the original export from being overwritten.
    #[arg(long)]
    force: bool,
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    let input_path = match cli.input {
        Some(p) => p,
        None => {
            let discovered = discover_latest_vault_export(Path::new("vault"))?;
            eprintln!("using latest export: {}", discovered.display());
            discovered
        }
    };

    let output_path = cli
        .output
        .unwrap_or_else(|| default_output_path(&input_path, &cli.folder));

    if !cli.force && paths_collide(&input_path, &output_path)? {
        return Err(format!(
            "path safety: --input and --output resolve to the same path ({}). \
             Pass --force to override (dangerous — overwrites the original export).",
            input_path.display()
        )
        .into());
    }

    let text = fs::read_to_string(&input_path)
        .map_err(|e| format!("reading {}: {e}", input_path.display()))?;
    let mut data: Value = serde_json::from_str(&text)
        .map_err(|e| format!("parsing {}: {e}", input_path.display()))?;

    let folder_id = generate_v4_uuid()?;
    let item_count = move_all_items_to_folder(&mut data, &cli.folder, &folder_id)?;

    write_sensitive_atomic(&output_path, &serde_json::to_string_pretty(&data)?)?;

    println!(
        "moved {item_count} items into folder \"{}\" (id {folder_id})",
        cli.folder
    );
    println!("wrote: {}", output_path.display());
    Ok(())
}

/// Replace `data.folders` with a single `{id, name}` folder and rewrite
/// every item's `folderId` to match. Returns the number of items
/// rewritten.
fn move_all_items_to_folder(
    data: &mut Value,
    folder_name: &str,
    folder_id: &str,
) -> Result<usize, String> {
    let obj = data
        .as_object_mut()
        .ok_or("export is not a top-level JSON object")?;

    obj.insert(
        "folders".into(),
        json!([{"id": folder_id, "name": folder_name}]),
    );

    let items = obj
        .get_mut("items")
        .and_then(Value::as_array_mut)
        .ok_or("export `items` field is missing or not an array")?;

    for item in items.iter_mut() {
        let item_obj = item
            .as_object_mut()
            .ok_or("items[] contains a non-object element")?;
        item_obj.insert("folderId".into(), json!(folder_id));
    }
    Ok(items.len())
}

fn default_output_path(input: &Path, folder: &str) -> PathBuf {
    let parent = input.parent().unwrap_or(Path::new("."));
    let stem = input.file_stem().unwrap_or_default().to_string_lossy();
    parent.join(format!("{stem}.in-folder-{folder}.json"))
}

/// Find the lexically-last `bitwarden_export_*.json` in `dir` that is
/// not one of the known generated sidecar shapes. Bitwarden's export
/// filenames use zero-padded `YYYYMMDDHHMMSS` timestamps, so a lexical
/// sort is also a chronological sort.
fn discover_latest_vault_export(dir: &Path) -> Result<PathBuf, String> {
    if !dir.is_dir() {
        return Err(format!(
            "no --input given and {} directory does not exist. \
             hint: mkdir -p vault && mv ~/Downloads/bitwarden_export_*.json vault/",
            dir.display()
        ));
    }

    let mut candidates: Vec<PathBuf> = fs::read_dir(dir)
        .map_err(|e| format!("reading {}: {e}", dir.display()))?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.is_file())
        .filter(|p| is_primary_vault_export(p))
        .collect();

    candidates.sort();
    candidates.pop().ok_or_else(|| {
        format!(
            "no bitwarden_export_*.json file in {}. \
             hint: mv ~/Downloads/bitwarden_export_*.json {}/",
            dir.display(),
            dir.display()
        )
    })
}

/// A file is a "primary" vault export if it matches one of the
/// recognized export prefixes and does NOT match any of the sidecar
/// shapes the other binaries (including this one) produce.
///
/// Recognized prefixes:
///   - `bitwarden_export_*.json`            — `bw export --format json`
///   - `bitwarden_decrypted-export_*.json`  — `just backup-vault-decrypted`
fn is_primary_vault_export(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    if !name.ends_with(".json") {
        return false;
    }
    let has_known_prefix =
        name.starts_with("bitwarden_export_") || name.starts_with("bitwarden_decrypted-export_");
    if !has_known_prefix {
        return false;
    }
    const EXCLUDED_SUFFIXES: &[&str] = &[
        ".dedup.json",
        ".dedup.audit.json",
        ".dedup.trashed.json",
        "-with-trash.json",
        "-with-icloud-credentials.json",
        "-with-icloud-credentials.audit.json",
        "-with-icloud-credentials.trashed.json",
    ];
    if EXCLUDED_SUFFIXES.iter().any(|s| name.ends_with(s)) {
        return false;
    }
    // `*.in-folder-*.json` — this binary's own output.
    if name.contains(".in-folder-") {
        return false;
    }
    true
}

/// Generate a random v4 UUID by reading 16 bytes from `/dev/urandom`
/// and stamping in the RFC 4122 version/variant bits. No crate
/// dependency: the rest of the project deliberately keeps a minimal
/// dependency list (`clap`, `serde_json` only).
fn generate_v4_uuid() -> Result<String, String> {
    let mut bytes = [0u8; 16];
    #[cfg(unix)]
    {
        let mut f =
            fs::File::open("/dev/urandom").map_err(|e| format!("opening /dev/urandom: {e}"))?;
        f.read_exact(&mut bytes)
            .map_err(|e| format!("reading /dev/urandom: {e}"))?;
    }
    #[cfg(not(unix))]
    {
        return Err("UUID generation is only implemented on Unix".into());
    }
    // Version 4 (random): top nibble of byte 6 = 0b0100.
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    // Variant RFC 4122: top two bits of byte 8 = 0b10.
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Ok(format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15],
    ))
}

/// Returns true iff both paths resolve to the same canonical location.
/// Uses the same canonicalize-parent fallback as `bitwarden-dedup` so
/// not-yet-existing output paths still collide with their inputs when
/// they're spelled differently (e.g. `./a.json` vs `a.json`).
fn paths_collide(a: &Path, b: &Path) -> Result<bool, String> {
    Ok(canonical_identity(a)? == canonical_identity(b)?)
}

fn canonical_identity(p: &Path) -> Result<PathBuf, String> {
    if let Ok(resolved) = fs::canonicalize(p) {
        return Ok(resolved);
    }
    if let (Some(parent), Some(name)) = (p.parent(), p.file_name())
        && let Ok(parent_canon) = fs::canonicalize(if parent.as_os_str().is_empty() {
            Path::new(".")
        } else {
            parent
        })
    {
        return Ok(parent_canon.join(name));
    }
    std::path::absolute(p).map_err(|e| format!("resolving {}: {e}", p.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ---- move_all_items_to_folder ----

    #[test]
    fn replaces_folders_array_with_single_entry() {
        let mut data = json!({
            "folders": [
                {"id": "old-1", "name": "Work"},
                {"id": "old-2", "name": "Personal"},
            ],
            "items": [],
        });
        let count = move_all_items_to_folder(&mut data, "archive", "new-uuid").unwrap();
        assert_eq!(count, 0);
        let folders = data.get("folders").unwrap().as_array().unwrap();
        assert_eq!(folders.len(), 1);
        assert_eq!(folders[0]["id"], json!("new-uuid"));
        assert_eq!(folders[0]["name"], json!("archive"));
    }

    #[test]
    fn rewrites_every_items_folder_id() {
        let mut data = json!({
            "folders": [{"id": "old", "name": "Old"}],
            "items": [
                {"id": "i1", "folderId": "old", "name": "a"},
                {"id": "i2", "folderId": null, "name": "b"},
                {"id": "i3", "name": "c"},
            ],
        });
        let count = move_all_items_to_folder(&mut data, "main", "new-uuid").unwrap();
        assert_eq!(count, 3);
        let items = data.get("items").unwrap().as_array().unwrap();
        for item in items {
            assert_eq!(item.get("folderId"), Some(&json!("new-uuid")));
        }
    }

    #[test]
    fn preserves_other_item_fields() {
        let mut data = json!({
            "folders": [],
            "items": [
                {"id": "i1", "folderId": "old", "name": "Login", "login": {"username": "u"}},
            ],
        });
        move_all_items_to_folder(&mut data, "main", "new").unwrap();
        let item = &data.get("items").unwrap().as_array().unwrap()[0];
        assert_eq!(item["name"], json!("Login"));
        assert_eq!(item["login"]["username"], json!("u"));
        assert_eq!(item["folderId"], json!("new"));
    }

    #[test]
    fn preserves_top_level_encrypted_flag() {
        let mut data = json!({
            "encrypted": false,
            "folders": [],
            "items": [],
        });
        move_all_items_to_folder(&mut data, "main", "new").unwrap();
        assert_eq!(data["encrypted"], json!(false));
    }

    #[test]
    fn creates_folders_key_when_absent() {
        let mut data = json!({"items": []});
        move_all_items_to_folder(&mut data, "main", "new").unwrap();
        let folders = data.get("folders").unwrap().as_array().unwrap();
        assert_eq!(folders.len(), 1);
    }

    #[test]
    fn errors_when_items_missing() {
        let mut data = json!({"folders": []});
        let err = move_all_items_to_folder(&mut data, "main", "new").unwrap_err();
        assert!(err.contains("items"));
    }

    #[test]
    fn errors_when_items_not_array() {
        let mut data = json!({"folders": [], "items": "oops"});
        let err = move_all_items_to_folder(&mut data, "main", "new").unwrap_err();
        assert!(err.contains("items"));
    }

    #[test]
    fn errors_when_top_level_not_object() {
        let mut data = json!([]);
        let err = move_all_items_to_folder(&mut data, "main", "new").unwrap_err();
        assert!(err.contains("top-level"));
    }

    #[test]
    fn errors_when_item_is_not_object() {
        let mut data = json!({"folders": [], "items": ["oops"]});
        let err = move_all_items_to_folder(&mut data, "main", "new").unwrap_err();
        assert!(err.contains("non-object"));
    }

    // ---- default_output_path ----

    #[test]
    fn default_output_appends_in_folder_suffix() {
        let out = default_output_path(
            Path::new("vault/bitwarden_export_20260101000000.json"),
            "archive",
        );
        assert_eq!(
            out,
            PathBuf::from("vault/bitwarden_export_20260101000000.in-folder-archive.json"),
        );
    }

    #[test]
    fn default_output_handles_no_parent() {
        // `Path::new("foo.json").parent()` returns an empty path, so
        // joining yields just the new name with no leading `./`.
        let out = default_output_path(Path::new("foo.json"), "main");
        assert_eq!(out, PathBuf::from("foo.in-folder-main.json"));
    }

    // ---- is_primary_vault_export ----

    #[test]
    fn primary_export_accepts_bare_timestamped_name() {
        assert!(is_primary_vault_export(Path::new(
            "vault/bitwarden_export_20260101000000.json"
        )));
    }

    #[test]
    fn primary_export_accepts_decrypted_export_prefix() {
        // `just backup-vault-decrypted` produces this shape — must be
        // recognized as a primary export.
        assert!(is_primary_vault_export(Path::new(
            "vault/bitwarden_decrypted-export_20260101000000.json"
        )));
        assert!(is_primary_vault_export(Path::new(
            "vault/bitwarden_decrypted-export_20260101000000123.json"
        )));
    }

    #[test]
    fn primary_export_rejects_encrypted_export_prefix() {
        // `just backup-vault-encrypted` writes the raw `/api/sync`
        // body — that's encrypted, not a dedup input.
        assert!(!is_primary_vault_export(Path::new(
            "vault/bitwarden_encrypted-export_20260101000000.json"
        )));
    }

    #[test]
    fn primary_export_rejects_decrypted_with_trash_snapshot() {
        assert!(!is_primary_vault_export(Path::new(
            "vault/bitwarden_decrypted-export_20260101000000-with-trash.json"
        )));
        assert!(!is_primary_vault_export(Path::new(
            "vault/bitwarden_decrypted-export_20260101000000123-with-trash.json"
        )));
    }

    #[test]
    fn primary_export_rejects_dedup_sidecars() {
        for name in [
            "bitwarden_export_20260101000000.dedup.json",
            "bitwarden_export_20260101000000.dedup.audit.json",
            "bitwarden_export_20260101000000.dedup.trashed.json",
        ] {
            assert!(
                !is_primary_vault_export(Path::new(name)),
                "expected rejection for {name}"
            );
        }
    }

    #[test]
    fn primary_export_rejects_icloud_merge_sidecars() {
        for name in [
            "bitwarden_export_20260101000000-with-icloud-credentials.json",
            "bitwarden_export_20260101000000-with-icloud-credentials.audit.json",
            "bitwarden_export_20260101000000-with-icloud-credentials.trashed.json",
        ] {
            assert!(
                !is_primary_vault_export(Path::new(name)),
                "expected rejection for {name}"
            );
        }
    }

    #[test]
    fn primary_export_rejects_in_folder_output() {
        assert!(!is_primary_vault_export(Path::new(
            "bitwarden_export_20260101000000.in-folder-main.json"
        )));
    }

    #[test]
    fn primary_export_rejects_unrelated_filenames() {
        assert!(!is_primary_vault_export(Path::new("notes.json")));
        assert!(!is_primary_vault_export(Path::new(
            "bitwarden_export_x.txt"
        )));
    }

    // ---- discover_latest_vault_export ----

    fn scratch_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "bwd-mv-{}-{label}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0),
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn discover_picks_lexically_last_primary_export() {
        let dir = scratch_dir("latest");
        for name in [
            "bitwarden_export_20260101000000.json",
            "bitwarden_export_20260301000000.json",
            "bitwarden_export_20260201000000.json",
        ] {
            fs::write(dir.join(name), "{}").unwrap();
        }
        let latest = discover_latest_vault_export(&dir).unwrap();
        assert_eq!(
            latest.file_name().unwrap().to_str().unwrap(),
            "bitwarden_export_20260301000000.json"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn discover_skips_sidecar_shapes() {
        let dir = scratch_dir("skip-sidecars");
        // Only the bare export should win; the ".dedup.json" sidecar
        // has a lexically later name but must be excluded.
        fs::write(dir.join("bitwarden_export_20260101000000.json"), "{}").unwrap();
        fs::write(dir.join("bitwarden_export_20260101000000.dedup.json"), "{}").unwrap();
        fs::write(
            dir.join("bitwarden_export_20260101000000.in-folder-main.json"),
            "{}",
        )
        .unwrap();
        let latest = discover_latest_vault_export(&dir).unwrap();
        assert_eq!(
            latest.file_name().unwrap().to_str().unwrap(),
            "bitwarden_export_20260101000000.json"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn discover_errors_when_dir_missing() {
        let missing = std::env::temp_dir().join(format!(
            "bwd-mv-missing-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0),
        ));
        let err = discover_latest_vault_export(&missing).unwrap_err();
        assert!(err.contains("does not exist"));
    }

    #[test]
    fn discover_errors_when_no_primary_exports() {
        let dir = scratch_dir("only-sidecars");
        fs::write(dir.join("bitwarden_export_20260101000000.dedup.json"), "{}").unwrap();
        let err = discover_latest_vault_export(&dir).unwrap_err();
        assert!(err.contains("no bitwarden_export_"));
        let _ = fs::remove_dir_all(&dir);
    }

    // ---- UUID shape ----

    #[test]
    fn uuid_v4_has_correct_shape_and_version() {
        let id = generate_v4_uuid().unwrap();
        assert_eq!(id.len(), 36);
        assert_eq!(id.chars().filter(|&c| c == '-').count(), 4);
        // Positions of dashes must be 8-4-4-4-12.
        let segs: Vec<&str> = id.split('-').collect();
        assert_eq!(
            segs.iter().map(|s| s.len()).collect::<Vec<_>>(),
            vec![8, 4, 4, 4, 12]
        );
        // Version nibble (first char of third group) must be '4'.
        assert_eq!(segs[2].chars().next().unwrap(), '4');
        // Variant: first char of fourth group must be one of 8/9/a/b.
        let v = segs[3].chars().next().unwrap();
        assert!(matches!(v, '8' | '9' | 'a' | 'b'), "variant nibble was {v}");
    }

    #[test]
    fn uuid_v4_is_lowercase_hex() {
        let id = generate_v4_uuid().unwrap();
        for c in id.chars() {
            assert!(
                c.is_ascii_hexdigit() && !c.is_ascii_uppercase() || c == '-',
                "unexpected char {c}"
            );
        }
    }

    #[test]
    fn uuid_v4_values_are_not_duplicated() {
        // Not a statistical guarantee, but a smoke check that we're
        // pulling fresh entropy each call rather than returning a
        // constant.
        let a = generate_v4_uuid().unwrap();
        let b = generate_v4_uuid().unwrap();
        assert_ne!(a, b);
    }

    // ---- paths_collide ----

    #[test]
    fn paths_collide_detects_same_path() {
        let dir = scratch_dir("collide");
        let p = dir.join("a.json");
        fs::write(&p, "{}").unwrap();
        assert!(paths_collide(&p, &p).unwrap());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn paths_collide_detects_dot_variants() {
        let dir = scratch_dir("collide-dot");
        let p = dir.join("a.json");
        fs::write(&p, "{}").unwrap();
        let spelled = dir.join(".").join("a.json");
        assert!(paths_collide(&p, &spelled).unwrap());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn paths_collide_distinguishes_different_paths() {
        let dir = scratch_dir("no-collide");
        let a = dir.join("a.json");
        let b = dir.join("b.json");
        fs::write(&a, "{}").unwrap();
        // b doesn't exist yet — simulates the --output case.
        assert!(!paths_collide(&a, &b).unwrap());
        let _ = fs::remove_dir_all(&dir);
    }
}
