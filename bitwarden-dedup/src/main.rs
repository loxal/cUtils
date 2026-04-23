// Copyright 2026 Alexander Orlov <alexander.orlov@loxal.net>

//! Deduplicate a Bitwarden JSON vault export.
//!
//! The dedup decision is defined in `bitwarden_dedup::{dedup_key,
//! skip_from_dedup, dedup_items}` so both this binary and `bitwarden-redact`
//! agree. This file only handles CLI parsing, path safety, file I/O with
//! owner-only permissions on Unix, and the stdout summary.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use bitwarden_dedup::io_util::write_sensitive_atomic;
use bitwarden_dedup::{DedupConfig, dedup_export_with_config};
use clap::Parser;
use serde_json::{Value, json};

#[derive(Parser, Debug)]
#[command(
    name = "bitwarden-dedup",
    about = "Deduplicate a Bitwarden JSON vault export into an import-ready file"
)]
struct Cli {
    /// Path to the Bitwarden export JSON file.
    #[arg(short, long)]
    input: PathBuf,

    /// Output path (default: <input_stem>.dedup.json next to the input).
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Audit path (default: <input_stem>.dedup.audit.json next to the input).
    #[arg(short, long)]
    audit: Option<PathBuf>,

    /// Allow `--output` or `--audit` to collide with `--input` or each other.
    /// WITHOUT this flag, any path collision is a hard error — the default
    /// protects the original export from being overwritten and prevents the
    /// audit JSON from clobbering the deduplicated output.
    #[arg(long)]
    force: bool,

    /// Keep items with divergent `login.totp` as separate living items
    /// instead of collapsing them and picking the newest secret for the
    /// survivor. `revisionDate` is an item-level timestamp — editing notes
    /// or favouriting an item with an old TOTP can make it "look newer"
    /// than an item carrying the current secret. Use this flag when you
    /// would rather keep the duplicates living than risk the wrong TOTP
    /// landing on the survivor. Losers stay in Trash regardless.
    #[arg(long)]
    split_divergent_totps: bool,
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
    let input_path = cli.input;
    let output_path = cli
        .output
        .unwrap_or_else(|| sibling(&input_path, ".dedup.json"));
    let audit_path = cli
        .audit
        .unwrap_or_else(|| sibling(&input_path, ".dedup.audit.json"));

    // Path safety: input, output, and audit must resolve to distinct
    // absolute paths unless --force is set. Without this check, an
    // unfortunate --output or --audit override could overwrite the only
    // backup of the export or clobber the dedup output with the audit file.
    check_paths_distinct(&input_path, &output_path, &audit_path, cli.force)?;

    let text = fs::read_to_string(&input_path)
        .map_err(|e| format!("reading {}: {e}", input_path.display()))?;
    let mut data: Value = serde_json::from_str(&text)
        .map_err(|e| format!("parsing {}: {e}", input_path.display()))?;

    if data.get("items").and_then(Value::as_array).is_none() {
        return Err("missing 'items' array in export".into());
    }

    // `dedup_export` reads the top-level `folders` array so the folder
    // disambiguation note on merged items uses human-readable folder names
    // instead of opaque UUIDs.
    let config = DedupConfig {
        split_divergent_totps: cli.split_divergent_totps,
    };
    let stats = dedup_export_with_config(&mut data, &config);

    write_sensitive_atomic(&output_path, &serde_json::to_string_pretty(&data)?)?;

    let audit_doc = json!({
        "input": input_path.to_string_lossy(),
        "output": output_path.to_string_lossy(),
        "split_divergent_totps": config.split_divergent_totps,
        "input_item_count": stats.total,
        "output_item_count": stats.output,
        "living_item_count": stats.living,
        "trashed_count": stats.trashed,
        // Back-compat alias — older consumers of the audit JSON look for this field.
        "removed_count": stats.trashed,
        "duplicate_groups": stats.groups,
        "totp_conflict_groups": stats.totp_conflict_groups,
        "skipped_from_dedup": stats.skipped,
        "uris_merged_into_kept_total": stats.merged,
        "entries": stats.audit_entries,
    });
    write_sensitive_atomic(&audit_path, &serde_json::to_string_pretty(&audit_doc)?)?;

    println!("Input:         {}", input_path.display());
    println!(
        "               {} items total, {} skipped from dedup",
        stats.total, stats.skipped
    );
    println!("Groups:        {} strict duplicate groups", stats.groups);
    if stats.totp_conflict_groups > 0 {
        println!(
            "TOTP conflicts:{} group(s) carried >1 distinct non-empty TOTP (audit entries: totp_conflict=true; rerun with --split-divergent-totps to keep them separate)",
            stats.totp_conflict_groups
        );
    }
    println!(
        "Trashed:       {} items routed to Bitwarden Trash (survivor picked by longer passwordHistory, then newer revisionDate)",
        stats.trashed
    );
    println!(
        "               (trashed items stay in the output with deletedDate set — you can recover any of them from Bitwarden's Trash folder after import)"
    );
    println!(
        "URIs merged:   {} unique URLs preserved from dropped items",
        stats.merged
    );
    println!(
        "               (notes, custom fields, TOTP, passwordHistory, collections, folders — all merged into survivors)"
    );
    println!("Output:        {}", output_path.display());
    let total_trashed_in_output = stats.output.saturating_sub(stats.living);
    println!(
        "               {} items ({} living, {} in Trash — includes any items that arrived pre-trashed)",
        stats.output, stats.living, total_trashed_in_output
    );
    println!("Audit:         {}", audit_path.display());
    println!();
    println!("Import workflow (Bitwarden web vault):");
    println!("  1. Back up your current vault (keep the original export file)");
    println!(
        "  2. Settings -> My Account -> Purge Vault (Bitwarden import never \
         dedupes — if you skip Purge, every item imports a second time)"
    );
    println!(
        "  3. Tools -> Import Data -> Bitwarden (json) -> select {}",
        output_path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
    );
    println!("  4. Verify TOTP codes generate correctly on a few critical items");

    Ok(())
}

fn sibling(input: &Path, suffix: &str) -> PathBuf {
    let parent = input.parent().unwrap_or(Path::new("."));
    let stem = input.file_stem().unwrap_or_default().to_string_lossy();
    parent.join(format!("{stem}{suffix}"))
}

/// Resolve a path to a canonical identity for collision detection.
///
/// - Existing paths are canonicalized via [`fs::canonicalize`] so symlinks,
///   `.`, and `..` components collapse to the real inode path.
/// - For paths that don't exist yet (typical for `--output` / `--audit`),
///   canonicalize the parent directory and append the file name — that
///   way a symlinked parent still trips the duplicate check.
/// - As a last resort (no parent either), fall back to
///   [`std::path::absolute`] so we still return a comparable value.
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

fn check_paths_distinct(
    input: &Path,
    output: &Path,
    audit: &Path,
    force: bool,
) -> Result<(), String> {
    let input_abs = canonical_identity(input)?;
    let output_abs = canonical_identity(output)?;
    let audit_abs = canonical_identity(audit)?;

    let mut collisions: Vec<String> = Vec::new();
    if output_abs == input_abs {
        collisions.push(format!(
            "--output ({}) would overwrite --input",
            output.display()
        ));
    }
    if audit_abs == input_abs {
        collisions.push(format!(
            "--audit ({}) would overwrite --input",
            audit.display()
        ));
    }
    if output_abs == audit_abs {
        collisions.push(format!(
            "--output and --audit resolve to the same path ({})",
            output.display()
        ));
    }

    if collisions.is_empty() {
        return Ok(());
    }

    if force {
        eprintln!(
            "warning: --force bypassed path safety ({} collision{} detected):",
            collisions.len(),
            if collisions.len() == 1 { "" } else { "s" }
        );
        for c in &collisions {
            eprintln!("  - {c}");
        }
        return Ok(());
    }

    let joined = collisions.join("; ");
    Err(format!(
        "path safety: {joined}. Pass --force to override (dangerous — may \
         destroy your only backup)."
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_safety_rejects_output_equals_input() {
        let r = check_paths_distinct(
            Path::new("/tmp/vault.json"),
            Path::new("/tmp/vault.json"),
            Path::new("/tmp/audit.json"),
            false,
        );
        assert!(r.is_err());
    }

    #[test]
    fn path_safety_rejects_audit_equals_input() {
        let r = check_paths_distinct(
            Path::new("/tmp/vault.json"),
            Path::new("/tmp/out.json"),
            Path::new("/tmp/vault.json"),
            false,
        );
        assert!(r.is_err());
    }

    #[test]
    fn path_safety_rejects_output_equals_audit() {
        let r = check_paths_distinct(
            Path::new("/tmp/vault.json"),
            Path::new("/tmp/same.json"),
            Path::new("/tmp/same.json"),
            false,
        );
        assert!(r.is_err());
    }

    #[test]
    fn path_safety_accepts_distinct() {
        let r = check_paths_distinct(
            Path::new("/tmp/vault.json"),
            Path::new("/tmp/out.json"),
            Path::new("/tmp/audit.json"),
            false,
        );
        assert!(r.is_ok());
    }

    #[test]
    fn path_safety_force_bypasses_collision() {
        let r = check_paths_distinct(
            Path::new("/tmp/vault.json"),
            Path::new("/tmp/vault.json"),
            Path::new("/tmp/audit.json"),
            true,
        );
        assert!(r.is_ok());
    }

    #[test]
    fn path_safety_canonicalizes_relative_paths() {
        // Different spellings of the same path should collide.
        let r = check_paths_distinct(
            Path::new("/tmp/./vault.json"),
            Path::new("/tmp/vault.json"),
            Path::new("/tmp/audit.json"),
            false,
        );
        assert!(r.is_err(), "path safety should collapse '.' segments");
    }

    // Low-level write_sensitive_atomic has its own unit tests in
    // `src/io_util.rs`; we don't re-prove 0o600 behavior from main.rs.

}
