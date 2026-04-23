// Copyright 2026 Alexander Orlov <alexander.orlov@loxal.net>

//! Merge an Apple Passwords CSV export into a Bitwarden JSON vault.
//!
//! Reads both files, appends each CSV row as a synthetic Bitwarden item,
//! runs the standard dedup pipeline so overlaps collapse (URIs union, notes
//! merge, TOTP keeps newest, passkeys/FIDO2 stay strict-match), and writes
//! the combined vault with a `-with-icloud-credentials` suffix.
//!
//! Nothing is ever removed: dedup losers get `deletedDate = now` so they
//! show up in Bitwarden's Trash folder after import and can be recovered
//! by hand.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use bitwarden_dedup::{DedupConfig, merge_icloud_csv_into_export_with_config};
use clap::Parser;
use serde_json::{Value, json};

#[derive(Parser, Debug)]
#[command(
    name = "bitwarden-merge-icloud",
    about = "Merge an Apple Passwords CSV export into a Bitwarden JSON vault. \
             Applies the dedup pipeline so overlaps collapse cleanly; dedup \
             losers are kept with `deletedDate` set so they surface in \
             Bitwarden's Trash folder after import."
)]
struct Cli {
    /// Path to the Bitwarden JSON vault export.
    #[arg(short, long)]
    bitwarden: PathBuf,

    /// Path to the Apple Passwords CSV export.
    #[arg(short, long)]
    icloud: PathBuf,

    /// Output path (default: `<bitwarden_stem>-with-icloud-credentials.json`
    /// next to the input).
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Audit path (default: `<bitwarden_stem>-with-icloud-credentials.audit.json`
    /// next to the input).
    #[arg(short, long)]
    audit: Option<PathBuf>,

    /// Allow path collisions (default: inputs must not match outputs).
    #[arg(long)]
    force: bool,

    /// Keep items with divergent `login.totp` as separate living items
    /// rather than collapsing them with a newest-by-`revisionDate` pick.
    /// See `bitwarden-dedup --help` for the full rationale — this flag is
    /// propagated to the shared dedup pipeline so it applies to both the
    /// Bitwarden side and the merged CSV rows.
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
    let bw_path = cli.bitwarden;
    let csv_path = cli.icloud;
    let output_path = cli
        .output
        .unwrap_or_else(|| suffix_sibling(&bw_path, "-with-icloud-credentials.json"));
    let audit_path = cli
        .audit
        .unwrap_or_else(|| suffix_sibling(&bw_path, "-with-icloud-credentials.audit.json"));

    check_paths_distinct(&[&bw_path, &csv_path, &output_path, &audit_path], cli.force)?;

    let bw_text = fs::read_to_string(&bw_path)
        .map_err(|e| format!("reading {}: {e}", bw_path.display()))?;
    let csv_text = fs::read_to_string(&csv_path)
        .map_err(|e| format!("reading {}: {e}", csv_path.display()))?;

    let mut export: Value = serde_json::from_str(&bw_text)
        .map_err(|e| format!("parsing {}: {e}", bw_path.display()))?;
    if !export.is_object() {
        return Err("Bitwarden export must be a top-level JSON object".into());
    }
    if export.get("items").and_then(Value::as_array).is_none()
        && !export
            .as_object_mut()
            .is_some_and(|o| o.contains_key("items"))
    {
        return Err("Bitwarden export missing `items` array".into());
    }

    let config = DedupConfig {
        split_divergent_totps: cli.split_divergent_totps,
    };
    let stats = merge_icloud_csv_into_export_with_config(&mut export, &csv_text, &config)?;

    write_sensitive(&output_path, &serde_json::to_string_pretty(&export)?)?;

    let dedup = &stats.dedup_stats;
    let audit_doc = json!({
        "bitwarden_input": bw_path.to_string_lossy(),
        "icloud_csv_input": csv_path.to_string_lossy(),
        "output": output_path.to_string_lossy(),
        "split_divergent_totps": config.split_divergent_totps,
        "csv_rows_total": stats.csv_rows,
        "csv_rows_appended": stats.csv_items_appended,
        "csv_rows_skipped_empty": stats.csv_rows_skipped,
        "combined_input_item_count": dedup.total,
        "combined_output_item_count": dedup.output,
        "combined_living_count": dedup.living,
        "combined_trashed_count": dedup.trashed,
        "duplicate_groups": dedup.groups,
        "totp_conflict_groups": dedup.totp_conflict_groups,
        "skipped_from_dedup": dedup.skipped,
        "uris_merged_into_kept_total": dedup.merged,
        "entries": dedup.audit_entries.clone(),
    });
    write_sensitive(&audit_path, &serde_json::to_string_pretty(&audit_doc)?)?;

    println!("Bitwarden input: {}", bw_path.display());
    println!("iCloud CSV:      {}", csv_path.display());
    println!(
        "                 {} CSV rows ({} appended, {} empty rows skipped)",
        stats.csv_rows, stats.csv_items_appended, stats.csv_rows_skipped
    );
    println!("Combined:        {} items total", dedup.total);
    println!(
        "Groups:          {} strict duplicate groups across Bitwarden + iCloud",
        dedup.groups
    );
    if dedup.totp_conflict_groups > 0 {
        println!(
            "TOTP conflicts:  {} group(s) carried >1 distinct non-empty TOTP (audit entries: totp_conflict=true; rerun with --split-divergent-totps to keep them separate)",
            dedup.totp_conflict_groups
        );
    }
    println!(
        "Trashed:         {} items routed to Bitwarden Trash by this run (CSV + Bitwarden duplicates; deletedDate set — recoverable after import)",
        dedup.trashed
    );
    println!(
        "URIs merged:     {} unique URLs preserved from dropped items",
        dedup.merged
    );
    println!(
        "                 (notes, custom fields, TOTP, passwordHistory, collections, folders merged into survivors)"
    );
    println!("Output:          {}", output_path.display());
    let total_trashed_in_output = dedup.output.saturating_sub(dedup.living);
    println!(
        "                 {} items ({} living, {} in Trash — includes any items that arrived pre-trashed)",
        dedup.output, dedup.living, total_trashed_in_output
    );
    println!("Audit:           {}", audit_path.display());
    println!();
    println!("What is NOT merged (Apple's CSV does not export these):");
    println!("  - Passkeys / FIDO2 credentials — kept in iCloud Keychain only");
    println!("  - Wi-Fi passwords — not in the CSV export");
    println!("  - Sign-in-with-Apple tokens — not in the CSV export");
    println!("  Any passkey / FIDO2 credential that already exists on the Bitwarden");
    println!("  side is preserved untouched.");
    println!();
    println!("Import workflow:");
    println!("  1. Back up your current vault (keep the original export file).");
    println!("  2. Bitwarden web vault → Settings → My Account → Purge Vault.");
    println!(
        "  3. Tools → Import Data → Bitwarden (json) → select {}.",
        output_path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
    );
    println!("  4. Review Bitwarden's Trash folder: any dedup loser or iCloud-dup");
    println!("     is there, and you can restore items you disagree with.");

    Ok(())
}

fn suffix_sibling(input: &Path, suffix: &str) -> PathBuf {
    let parent = input.parent().unwrap_or(Path::new("."));
    let stem = input
        .file_stem()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    parent.join(format!("{stem}{suffix}"))
}

/// Resolve a path to a canonical identity for collision detection.
/// Mirrors the helper in `src/main.rs`: canonicalize existing paths,
/// canonicalize parent + file name for non-existent outputs, and fall
/// back to `std::path::absolute` only if even the parent is missing.
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

fn check_paths_distinct(paths: &[&Path], force: bool) -> Result<(), String> {
    let resolved: Vec<PathBuf> = paths
        .iter()
        .map(|p| canonical_identity(p))
        .collect::<Result<_, _>>()?;
    let mut collisions: Vec<String> = Vec::new();
    for i in 0..resolved.len() {
        for j in i + 1..resolved.len() {
            if resolved[i] == resolved[j] {
                collisions.push(format!(
                    "{} and {} resolve to the same path",
                    paths[i].display(),
                    paths[j].display()
                ));
            }
        }
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
    Err(format!(
        "path safety: {}. Pass --force to override (dangerous).",
        collisions.join("; ")
    ))
}

/// Write sensitive content with owner-only permissions on Unix.
#[cfg(unix)]
fn write_sensitive(path: &Path, content: &str) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
    }
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(content.as_bytes())?;
    drop(file);
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn write_sensitive(path: &Path, content: &str) -> std::io::Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, content)
}
