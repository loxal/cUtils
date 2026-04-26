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

    /// Run a second login-dedup pass over credential-less stubs (empty
    /// `login.password`) that the strict pass deliberately skips. Items
    /// only group when name + organization + username + URI host set +
    /// fido2 signature all match AND the group has at least one
    /// identifying signal beyond its name (non-empty username, non-empty
    /// URI host set, or a fido2 credential). Losers route to the trash
    /// sidecar like every other dedup loser. Off by default.
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
    let input_path = cli.input;
    let output_path = cli
        .output
        .unwrap_or_else(|| sibling(&input_path, ".dedup.json"));
    let audit_path = cli
        .audit
        .unwrap_or_else(|| sibling(&input_path, ".dedup.audit.json"));
    // Compute the trash-sidecar path up front so it participates in
    // the path-safety check — a custom --output or --audit equal to
    // the default sidecar path would otherwise race us at write time
    // and clobber the recovery copy.
    let trashed_path = sibling(&input_path, ".dedup.trashed.json");

    // Path safety: input, output, audit, and the derived trash
    // sidecar must all resolve to distinct absolute paths unless
    // --force is set. Without this check an unfortunate override
    // could overwrite the only backup of the export or clobber one
    // recovery artifact with another.
    check_paths_distinct(
        &input_path,
        &output_path,
        &audit_path,
        &trashed_path,
        cli.force,
    )?;

    let text = fs::read_to_string(&input_path)
        .map_err(|e| format!("reading {}: {e}", input_path.display()))?;
    let mut data: Value = serde_json::from_str(&text)
        .map_err(|e| format!("parsing {}: {e}", input_path.display()))?;

    // `dedup_export_with_config` fails loud when the top-level object is
    // malformed (missing `items`, or `items` present but not an array)
    // so an operator who points the tool at the wrong file sees a clear
    // error instead of a plausible-looking no-op output.
    let config = DedupConfig {
        split_divergent_totps: cli.split_divergent_totps,
        collapse_empty_passwords: cli.collapse_empty_passwords,
    };
    let stats = dedup_export_with_config(&mut data, &config)?;

    // Split dedup output into living vs trashed. Bitwarden's JSON
    // importer handles `deletedDate` inconsistently across client
    // versions, so the safest shape for a clean re-import is to move
    // all trashed items out of the main `items` array and write them
    // to a sidecar file (same Bitwarden-JSON shape, importable
    // separately if desired). If this run produces zero trashed
    // items, `split_items_to_sidecar` deletes any stale sidecar left
    // from a previous run so the operator never imports a misleading
    // outdated recovery file.
    let trashed_count = split_items_to_sidecar(&mut data, &trashed_path)?;

    write_sensitive_atomic(&output_path, &serde_json::to_string_pretty(&data)?)?;

    let trashed_sidecar = if trashed_count > 0 {
        Value::String(trashed_path.to_string_lossy().into_owned())
    } else {
        Value::Null
    };
    let audit_doc = json!({
        "input": input_path.to_string_lossy(),
        "output": output_path.to_string_lossy(),
        "trashed_sidecar": trashed_sidecar,
        "trashed_sidecar_item_count": trashed_count,
        "split_divergent_totps": config.split_divergent_totps,
        "collapse_empty_passwords": config.collapse_empty_passwords,
        "input_item_count": stats.total,
        "output_item_count": stats.output,
        "living_item_count": stats.living,
        "trashed_count": stats.trashed,
        // Back-compat alias — older consumers of the audit JSON look for this field.
        "removed_count": stats.trashed,
        "duplicate_groups": stats.groups,
        "strict_login_groups": stats.strict_login_groups,
        "empty_password_groups": stats.empty_password_groups,
        "empty_password_trashed": stats.empty_password_trashed,
        "empty_password_groups_by_signal": stats.empty_password_groups_by_signal,
        "secure_note_groups": stats.secure_note_groups,
        "ssh_key_groups": stats.ssh_key_groups,
        "card_groups": stats.card_groups,
        "identity_groups": stats.identity_groups,
        "totp_conflict_groups": stats.totp_conflict_groups,
        "folders_deduplicated": stats.folders_deduplicated,
        // Strict-pass-local skip count: items the strict login pass
        // declined to group (non-logins, reprompt-gated, empty
        // password, `[duplicate]`-tagged, or already trashed). When
        // `collapse_empty_passwords` is set, some items in this
        // bucket may still be grouped by Pass 2 — read alongside
        // `empty_password_groups` / `empty_password_trashed` for the
        // full picture.
        "strict_pass_skipped": stats.skipped,
        // Back-compat alias — same value under the old key name so
        // any audit-grep tooling written against earlier releases
        // keeps working. New consumers should read
        // `strict_pass_skipped` for the more accurate label.
        "skipped_from_dedup": stats.skipped,
        "uris_merged_into_kept_total": stats.merged,
        "entries": stats.audit_entries,
    });
    write_sensitive_atomic(&audit_path, &serde_json::to_string_pretty(&audit_doc)?)?;

    println!("Input:         {}", input_path.display());
    println!(
        "               {} items total, {} skipped by strict pass",
        stats.total, stats.skipped
    );
    println!("Groups:        {} total dedup groups", stats.groups);
    if stats.strict_login_groups > 0 {
        println!(
            "                 strict login: {}",
            stats.strict_login_groups
        );
    }
    if stats.empty_password_groups > 0 {
        let signals = &stats.empty_password_groups_by_signal;
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
            "                 empty-password login: {} (signals — fido2: {}, host: {}, username-only: {})",
            stats.empty_password_groups, f, h, u
        );
    }
    if stats.secure_note_groups > 0 {
        println!("                 secure note: {}", stats.secure_note_groups);
    }
    if stats.ssh_key_groups > 0 {
        println!("                 ssh key: {}", stats.ssh_key_groups);
    }
    if stats.card_groups > 0 {
        println!("                 card: {}", stats.card_groups);
    }
    if stats.identity_groups > 0 {
        println!("                 identity: {}", stats.identity_groups);
    }
    if stats.folders_deduplicated > 0 {
        println!(
            "Folders:       {} duplicate folder(s) collapsed; every item's folderId remapped to the surviving folder.",
            stats.folders_deduplicated
        );
    }
    if stats.totp_conflict_groups > 0 {
        println!();
        println!(
            "!! TOTP CONFLICT: {} group(s) had >1 distinct non-empty TOTP. The",
            stats.totp_conflict_groups
        );
        println!("   newest-by-revisionDate secret is on the survivor; the older ones");
        println!("   are in Trash. If you do NOT trust that heuristic for this vault,");
        println!("   rerun `just dedup-split-totps` (or pass --split-divergent-totps)");
        println!("   to keep divergent-TOTP items as separate living entries. Audit");
        println!("   records for each group carry `totp_conflict: true`.");
        println!();
    }
    println!(
        "Trashed:       {} items routed out of the active `items` array (survivor picked by longer passwordHistory, then newer revisionDate)",
        stats.trashed
    );
    if stats.empty_password_groups > 0 {
        println!();
        println!(
            "Empty-pw pass: {} groups, {} items routed to trash.",
            stats.empty_password_groups, stats.empty_password_trashed
        );
        println!("               Grouped by name + organization + username + URI host");
        println!("               set + fido2 set. Username-only groups (signal_kind");
        println!("               == \"username_only\") are the weakest evidence class —");
        println!("               review the audit JSON filtered on that field if you");
        println!("               want to spot-check them. Items had no password set;");
        println!("               full merge rules apply (URIs/notes/fields union onto");
        println!("               survivor).");
        println!();
    }
    println!(
        "URIs merged:   {} unique URLs preserved from dropped items",
        stats.merged
    );
    println!(
        "               (notes, custom fields, TOTP, passwordHistory, collections, folders — all merged into survivors)"
    );
    println!("Output:        {}", output_path.display());
    println!(
        "               {} items — all living (clean import into Bitwarden's active vault)",
        stats.living
    );
    if trashed_count > 0 {
        println!("Trash sidecar: {}", trashed_path.display());
        println!(
            "               {} items carrying `deletedDate` (dedup losers plus anything pre-trashed in the input).",
            trashed_count
        );
        println!(
            "               NOT auto-imported — kept out of the main `items` array so Bitwarden's active view stays clean."
        );
        println!(
            "               Import this sidecar separately if you want to populate Bitwarden's Trash folder."
        );
    }
    println!("Audit:         {}", audit_path.display());
    println!();
    println!("!! IMPORT WORKFLOW — follow every step or you WILL see duplicates !!");
    println!("   Bitwarden's Import is purely ADDITIVE: it never dedupes against");
    println!("   your existing vault. Skip the Purge step and every item already");
    println!("   in your vault appears twice.");
    println!();
    println!("  1. Back up your current vault (keep the original export file).");
    println!("  2. Settings -> My Account -> Purge Vault.");
    println!("     (This empties your vault. It is load-bearing.)");
    println!(
        "  3. Tools -> Import Data -> Bitwarden (json) -> select {}",
        output_path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
    );
    println!("  4. Verify TOTP codes generate correctly on a few critical items.");

    Ok(())
}

fn sibling(input: &Path, suffix: &str) -> PathBuf {
    let parent = input.parent().unwrap_or(Path::new("."));
    let stem = input.file_stem().unwrap_or_default().to_string_lossy();
    parent.join(format!("{stem}{suffix}"))
}

/// Move items carrying a non-null `deletedDate` out of `data.items`
/// into a sibling JSON file with the same top-level shape. Returns
/// the count written.
///
/// Keeping trashed items out of the main `items` array is the only
/// way to guarantee Bitwarden's active view is clean after import,
/// regardless of how the target Bitwarden client version handles
/// `deletedDate` on JSON import.
fn split_items_to_sidecar(data: &mut Value, trashed_path: &Path) -> Result<usize, String> {
    let Some(obj) = data.as_object_mut() else {
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

    if trashed_count > 0 {
        let mut trashed_export = data.clone();
        if let Some(obj) = trashed_export.as_object_mut() {
            obj.insert("items".to_string(), Value::Array(trashed));
        }
        let json = serde_json::to_string_pretty(&trashed_export)
            .map_err(|e| format!("serializing trashed sidecar: {e}"))?;
        write_sensitive_atomic(trashed_path, &json)
            .map_err(|e| format!("writing {}: {e}", trashed_path.display()))?;
    } else {
        // No losers this run — delete any stale sidecar from a previous
        // run at the same path. Keeping it would leave a misleading
        // recovery file next to a fresh clean output, which is exactly
        // the kind of thing an operator imports by mistake.
        if trashed_path.exists() {
            fs::remove_file(trashed_path).map_err(|e| {
                format!(
                    "removing stale trash sidecar {}: {e}",
                    trashed_path.display()
                )
            })?;
        }
    }
    Ok(trashed_count)
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
    trashed: &Path,
    force: bool,
) -> Result<(), String> {
    let labelled: [(&str, &Path); 4] = [
        ("--input", input),
        ("--output", output),
        ("--audit", audit),
        ("trash sidecar", trashed),
    ];
    let resolved: Vec<(String, PathBuf)> = labelled
        .iter()
        .map(|(label, p)| Ok(((*label).to_string(), canonical_identity(p)?)))
        .collect::<Result<_, String>>()?;

    let mut collisions: Vec<String> = Vec::new();
    for i in 0..resolved.len() {
        for j in i + 1..resolved.len() {
            if resolved[i].1 == resolved[j].1 {
                collisions.push(format!(
                    "{} and {} resolve to the same path ({})",
                    resolved[i].0,
                    resolved[j].0,
                    resolved[i].1.display()
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
            Path::new("/tmp/trashed.json"),
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
            Path::new("/tmp/trashed.json"),
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
            Path::new("/tmp/trashed.json"),
            false,
        );
        assert!(r.is_err());
    }

    #[test]
    fn path_safety_rejects_trashed_equals_output() {
        // Regression guard: a custom --output equal to the default
        // sidecar path (or vice versa) would race at write time and
        // clobber the recovery copy. The safety check must catch it.
        let r = check_paths_distinct(
            Path::new("/tmp/vault.json"),
            Path::new("/tmp/same.json"),
            Path::new("/tmp/audit.json"),
            Path::new("/tmp/same.json"),
            false,
        );
        assert!(
            r.is_err(),
            "trash-sidecar vs --output collision must be caught"
        );
    }

    #[test]
    fn path_safety_rejects_trashed_equals_input() {
        let r = check_paths_distinct(
            Path::new("/tmp/vault.json"),
            Path::new("/tmp/out.json"),
            Path::new("/tmp/audit.json"),
            Path::new("/tmp/vault.json"),
            false,
        );
        assert!(r.is_err(), "trash sidecar must not overwrite --input");
    }

    #[test]
    fn path_safety_rejects_trashed_equals_audit() {
        let r = check_paths_distinct(
            Path::new("/tmp/vault.json"),
            Path::new("/tmp/out.json"),
            Path::new("/tmp/same.json"),
            Path::new("/tmp/same.json"),
            false,
        );
        assert!(r.is_err(), "trash sidecar must not collide with --audit");
    }

    #[test]
    fn path_safety_accepts_distinct() {
        let r = check_paths_distinct(
            Path::new("/tmp/vault.json"),
            Path::new("/tmp/out.json"),
            Path::new("/tmp/audit.json"),
            Path::new("/tmp/trashed.json"),
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
            Path::new("/tmp/trashed.json"),
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
            Path::new("/tmp/trashed.json"),
            false,
        );
        assert!(r.is_err(), "path safety should collapse '.' segments");
    }

    // Low-level write_sensitive_atomic has its own unit tests in
    // `src/io_util.rs`; we don't re-prove 0o600 behavior from main.rs.
}
