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

use bitwarden_dedup::dedup_items;
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

    let mut items: Vec<Value> = match data.as_object_mut().and_then(|o| o.get_mut("items")) {
        Some(Value::Array(arr)) => std::mem::take(arr),
        _ => return Err("missing 'items' array in export".into()),
    };

    let stats = dedup_items(&mut items);

    if let Some(obj) = data.as_object_mut() {
        obj.insert("items".to_string(), Value::Array(items));
    }

    write_sensitive(&output_path, &serde_json::to_string_pretty(&data)?)?;

    let audit_doc = json!({
        "input": input_path.to_string_lossy(),
        "output": output_path.to_string_lossy(),
        "input_item_count": stats.total,
        "output_item_count": stats.output,
        "removed_count": stats.removed,
        "duplicate_groups": stats.groups,
        "skipped_from_dedup": stats.skipped,
        "uris_merged_into_kept_total": stats.merged,
        "entries": stats.audit_entries,
    });
    write_sensitive(&audit_path, &serde_json::to_string_pretty(&audit_doc)?)?;

    println!("Input:         {}", input_path.display());
    println!(
        "               {} items total, {} skipped from dedup",
        stats.total, stats.skipped
    );
    println!("Groups:        {} strict duplicate groups", stats.groups);
    println!(
        "Removed:       {} items (kept newest by revisionDate)",
        stats.removed
    );
    println!(
        "URIs merged:   {} unique URLs preserved from dropped items",
        stats.merged
    );
    println!("Output:        {}", output_path.display());
    println!("               {} items", stats.output);
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

fn check_paths_distinct(
    input: &Path,
    output: &Path,
    audit: &Path,
    force: bool,
) -> Result<(), String> {
    let abs = |p: &Path| -> Result<PathBuf, String> {
        std::path::absolute(p).map_err(|e| format!("resolving {}: {e}", p.display()))
    };
    let input_abs = abs(input)?;
    let output_abs = abs(output)?;
    let audit_abs = abs(audit)?;

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

/// Write sensitive content to `path` with owner-only permissions on Unix.
///
/// On macOS/Linux this creates the file with mode `0o600` and then re-applies
/// `0o600` after writing to cover the case where the file already existed
/// with looser permissions. On non-Unix platforms this falls back to
/// `fs::write`.
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

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("bwd-test-{}-{name}", std::process::id()))
    }

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

    #[cfg(unix)]
    #[test]
    fn write_sensitive_creates_file_with_0o600_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let path = tmp("sensitive.json");
        let _ = fs::remove_file(&path);
        write_sensitive(&path, "{}").expect("write");
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "new file must be owner-only");
        fs::remove_file(&path).ok();
    }

    #[cfg(unix)]
    #[test]
    fn write_sensitive_fixes_existing_loose_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let path = tmp("loose.json");
        fs::write(&path, "loose").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        write_sensitive(&path, "tight").expect("rewrite");
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "existing file must be chmod'd to owner-only");
        fs::remove_file(&path).ok();
    }

}
