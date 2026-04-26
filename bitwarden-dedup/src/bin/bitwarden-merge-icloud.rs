// Copyright 2026 Alexander Orlov <alexander.orlov@loxal.net>

//! Merge an Apple Passwords CSV export into a Bitwarden JSON vault.
//!
//! Reads both files, appends each CSV row as a synthetic Bitwarden item,
//! runs the standard dedup pipeline so overlaps collapse (URIs union,
//! notes merge, TOTP keeps newest, passkeys/FIDO2 stay strict-match),
//! and writes the living-only combined vault with a
//! `-with-icloud-credentials` suffix.
//!
//! Nothing is ever removed. Dedup losers get `deletedDate = now` and
//! are split into a separate sidecar file
//! (`*-with-icloud-credentials.trashed.json`) — same Bitwarden-JSON
//! shape, not auto-imported — so Bitwarden's active vault stays clean
//! after import regardless of how the target client handles
//! `deletedDate`. The sidecar is the operator's offline recovery
//! copy; importing it separately populates Bitwarden's Trash.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use bitwarden_dedup::io_util::write_sensitive_atomic;
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

    /// Run a second login-dedup pass over credential-less stubs (empty
    /// `login.password`). Same semantics as `bitwarden-dedup
    /// --collapse-empty-passwords`; applies to both Bitwarden and CSV
    /// rows after the merge appends them. Off by default.
    #[arg(long)]
    collapse_empty_passwords: bool,
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
    // Compute the trash sidecar path up front so it participates in
    // the path-safety check — a custom --output matching the default
    // sidecar path would otherwise race us at write time and clobber
    // the recovery copy.
    let trashed_path = suffix_sibling(&bw_path, "-with-icloud-credentials.trashed.json");

    check_paths_distinct(
        &[
            &bw_path,
            &csv_path,
            &output_path,
            &audit_path,
            &trashed_path,
        ],
        cli.force,
    )?;

    let bw_text =
        fs::read_to_string(&bw_path).map_err(|e| format!("reading {}: {e}", bw_path.display()))?;
    let csv_text = fs::read_to_string(&csv_path)
        .map_err(|e| format!("reading {}: {e}", csv_path.display()))?;

    let mut export: Value = serde_json::from_str(&bw_text)
        .map_err(|e| format!("parsing {}: {e}", bw_path.display()))?;
    if !export.is_object() {
        return Err("Bitwarden export must be a top-level JSON object".into());
    }
    // If `items` is present at all, it must be an array — otherwise
    // this is not a valid Bitwarden export and merging on top of it
    // would silently discard whatever the field contained. Missing
    // `items` is fine (the merge path will create one).
    match export.get("items") {
        Some(Value::Array(_)) | None => {}
        Some(_) => {
            return Err(
                "Bitwarden export `items` field exists but is not an array. Refusing to proceed."
                    .into(),
            );
        }
    }

    let config = DedupConfig {
        split_divergent_totps: cli.split_divergent_totps,
        collapse_empty_passwords: cli.collapse_empty_passwords,
    };
    let stats = merge_icloud_csv_into_export_with_config(&mut export, &csv_text, &config)?;

    // Partition dedup output into living vs trashed. The main output
    // file only contains living items — that way Bitwarden's import
    // cannot misplace dedup losers into the active vault view if its
    // `deletedDate` handling is lenient or version-dependent. Trashed
    // items are written to a sidecar file in the same Bitwarden-JSON
    // shape so the operator can inspect them or, if desired, import
    // them separately to populate Bitwarden's Trash folder. If this
    // run produces zero losers, a stale sidecar from a previous run
    // is deleted so an outdated recovery copy never sits next to
    // fresh output.
    let trashed_count = split_items_to_sidecar(&mut export, &trashed_path)?;

    write_sensitive_atomic(&output_path, &serde_json::to_string_pretty(&export)?)?;

    let dedup = &stats.dedup_stats;
    let trashed_sidecar = if trashed_count > 0 {
        Value::String(trashed_path.to_string_lossy().into_owned())
    } else {
        Value::Null
    };
    let audit_doc = json!({
        "bitwarden_input": bw_path.to_string_lossy(),
        "icloud_csv_input": csv_path.to_string_lossy(),
        "output": output_path.to_string_lossy(),
        "trashed_sidecar": trashed_sidecar,
        "trashed_sidecar_item_count": trashed_count,
        "split_divergent_totps": config.split_divergent_totps,
        "collapse_empty_passwords": config.collapse_empty_passwords,
        "csv_rows_total": stats.csv_rows,
        "csv_rows_appended": stats.csv_items_appended,
        "csv_rows_skipped_empty": stats.csv_rows_skipped,
        "combined_input_item_count": dedup.total,
        "combined_output_item_count": dedup.output,
        "combined_living_count": dedup.living,
        "combined_trashed_count": dedup.trashed,
        "duplicate_groups": dedup.groups,
        "strict_login_groups": dedup.strict_login_groups,
        "empty_password_groups": dedup.empty_password_groups,
        "empty_password_trashed": dedup.empty_password_trashed,
        "empty_password_groups_by_signal": dedup.empty_password_groups_by_signal,
        "secure_note_groups": dedup.secure_note_groups,
        "ssh_key_groups": dedup.ssh_key_groups,
        "totp_conflict_groups": dedup.totp_conflict_groups,
        "folders_deduplicated": dedup.folders_deduplicated,
        // Strict-pass-local skip count — see the same field in
        // `bitwarden-dedup --help` for the empty-password-pass
        // interaction.
        "strict_pass_skipped": dedup.skipped,
        "uris_merged_into_kept_total": dedup.merged,
        "entries": dedup.audit_entries.clone(),
    });
    write_sensitive_atomic(&audit_path, &serde_json::to_string_pretty(&audit_doc)?)?;

    println!("Bitwarden input: {}", bw_path.display());
    println!("iCloud CSV:      {}", csv_path.display());
    println!(
        "                 {} CSV rows ({} appended, {} empty rows skipped)",
        stats.csv_rows, stats.csv_items_appended, stats.csv_rows_skipped
    );
    println!("Combined:        {} items total", dedup.total);
    println!(
        "Groups:          {} total dedup groups across Bitwarden + iCloud",
        dedup.groups
    );
    if dedup.strict_login_groups > 0 {
        println!(
            "                   strict login: {}",
            dedup.strict_login_groups
        );
    }
    if dedup.empty_password_groups > 0 {
        let signals = &dedup.empty_password_groups_by_signal;
        let f = signals
            .get(&bitwarden_dedup::SignalKind::Fido2)
            .copied()
            .unwrap_or(0);
        let h = signals
            .get(&bitwarden_dedup::SignalKind::Host)
            .copied()
            .unwrap_or(0);
        let u = signals
            .get(&bitwarden_dedup::SignalKind::UsernameOnly)
            .copied()
            .unwrap_or(0);
        println!(
            "                   empty-password login: {} (signals — fido2: {}, host: {}, username-only: {})",
            dedup.empty_password_groups, f, h, u
        );
    }
    if dedup.secure_note_groups > 0 {
        println!(
            "                   secure note: {}",
            dedup.secure_note_groups
        );
    }
    if dedup.ssh_key_groups > 0 {
        println!("                   ssh key: {}", dedup.ssh_key_groups);
    }
    if dedup.folders_deduplicated > 0 {
        println!(
            "Folders:         {} duplicate folder(s) collapsed; every item's folderId was remapped to the surviving folder.",
            dedup.folders_deduplicated
        );
    }
    if dedup.totp_conflict_groups > 0 {
        println!();
        println!(
            "!! TOTP CONFLICT: {} group(s) had >1 distinct non-empty TOTP. The",
            dedup.totp_conflict_groups
        );
        println!("   newest-by-revisionDate secret is on the survivor; the older ones");
        println!("   are in Trash. If you do NOT trust that heuristic, rerun");
        println!("   `just merge-with-icloud-credentials-csv-split-totps` to keep");
        println!("   divergent-TOTP items as separate living entries. Audit records");
        println!("   for each group carry `totp_conflict: true`.");
        println!();
    }
    println!(
        "Trashed:         {} items routed to Bitwarden Trash by this run (CSV + Bitwarden duplicates; deletedDate set — recoverable after import)",
        dedup.trashed
    );
    if dedup.empty_password_groups > 0 {
        println!();
        println!(
            "Empty-pw pass:   {} groups, {} items routed to trash.",
            dedup.empty_password_groups, dedup.empty_password_trashed
        );
        println!("                 Grouped by name + organization + username + URI host");
        println!("                 set + fido2 set. Username-only groups (signal_kind");
        println!("                 == \"username_only\") are the weakest evidence class —");
        println!("                 review the audit JSON filtered on that field if you");
        println!("                 want to spot-check them. Items had no password set;");
        println!("                 full merge rules apply (URIs/notes/fields union onto");
        println!("                 survivor).");
        println!();
    }
    println!(
        "URIs merged:     {} unique URLs preserved from dropped items",
        dedup.merged
    );
    println!(
        "                 (notes, custom fields, TOTP, passwordHistory, collections, folders merged into survivors)"
    );
    println!("Output:          {}", output_path.display());
    println!(
        "                 {} items — all living (clean import into Bitwarden's active vault)",
        dedup.living
    );
    if trashed_count > 0 {
        println!("Trash sidecar:   {}", trashed_path.display());
        println!(
            "                 {} items carrying `deletedDate` (dedup losers plus anything that arrived pre-trashed in the inputs).",
            trashed_count
        );
        println!(
            "                 This file is NOT auto-imported; Bitwarden's JSON importer handles `deletedDate` inconsistently, and"
        );
        println!(
            "                 keeping trashed items out of the main `items` array is the only reliable way to prevent them from"
        );
        println!(
            "                 showing up as duplicates in the active view after import. Import this sidecar separately if you"
        );
        println!(
            "                 want to populate Bitwarden's Trash folder, or keep it locally as an offline recovery copy."
        );
    }
    println!("Audit:           {}", audit_path.display());
    println!();
    println!("What is NOT merged (Apple's CSV does not export these):");
    println!("  - Passkeys / FIDO2 credentials — kept in iCloud Keychain only");
    println!("  - Wi-Fi passwords — not in the CSV export");
    println!("  - Sign-in-with-Apple tokens — not in the CSV export");
    println!("  Any passkey / FIDO2 credential that already exists on the Bitwarden");
    println!("  side is preserved untouched.");
    println!();
    println!("!! IMPORT WORKFLOW — follow every step or you WILL see duplicates !!");
    println!("   Bitwarden's Import feature is purely ADDITIVE: it never dedupes");
    println!("   against your existing vault. Skipping the Purge step below means");
    println!("   the imported items land on top of what's already there, and every");
    println!("   item you already had will appear twice in the Bitwarden UI.");
    println!();
    println!("  1. Back up your current vault (keep the original export file).");
    println!("  2. Bitwarden web vault → Settings → My Account → Purge Vault.");
    println!("     (This empties your vault. It is load-bearing.)");
    println!(
        "  3. Tools → Import Data → Bitwarden (json) → select {}.",
        output_path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
    );
    println!("  4. Do NOT also import the .trashed.json sidecar unless you");
    println!("     specifically want to populate Bitwarden's Trash folder.");

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

/// Split the `items` array of `export` in place: non-trashed items stay
/// in `export.items`; items carrying a non-null `deletedDate` are moved
/// into a sibling JSON file that mirrors the export shape and can be
/// imported separately if the operator wants to populate Bitwarden's
/// Trash folder. Returns the count of trashed items written.
///
/// Bitwarden's JSON importer is inconsistent about the `deletedDate`
/// field — some client versions put such items in Trash, others ignore
/// it and import them as active. By stripping them from the main
/// `items` array we remove that risk entirely: whatever Bitwarden
/// does with `deletedDate`, the main import only ever sees living
/// items, so the active view stays clean.
fn split_items_to_sidecar(export: &mut Value, trashed_path: &Path) -> Result<usize, String> {
    let Some(obj) = export.as_object_mut() else {
        return Err("export is not a top-level JSON object".into());
    };
    let Some(Value::Array(arr)) = obj.get_mut("items") else {
        return Err("export `items` field is not an array after dedup".into());
    };
    let all = std::mem::take(arr);
    let mut living = Vec::with_capacity(all.len());
    let mut trashed = Vec::new();
    for item in all {
        let is_trashed = item
            .get("deletedDate")
            .and_then(Value::as_str)
            .is_some_and(|s| !s.is_empty());
        if is_trashed {
            trashed.push(item);
        } else {
            living.push(item);
        }
    }
    let trashed_count = trashed.len();
    *arr = living;

    // Only write the sidecar if we actually have something to put in
    // it — avoids cluttering vault/ with empty files after a run with
    // no dedup losers.
    if trashed_count > 0 {
        let mut trashed_export = export.clone();
        if let Some(obj) = trashed_export.as_object_mut() {
            obj.insert("items".to_string(), Value::Array(trashed));
        }
        let json = serde_json::to_string_pretty(&trashed_export)
            .map_err(|e| format!("serializing trashed sidecar: {e}"))?;
        write_sensitive_atomic(trashed_path, &json)
            .map_err(|e| format!("writing {}: {e}", trashed_path.display()))?;
    } else if trashed_path.exists() {
        // No losers this run — remove a stale sidecar from a previous
        // run so the operator never imports an outdated recovery
        // file by mistake.
        fs::remove_file(trashed_path).map_err(|e| {
            format!(
                "removing stale trash sidecar {}: {e}",
                trashed_path.display()
            )
        })?;
    }
    Ok(trashed_count)
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
