// Copyright 2026 Alexander Orlov <alexander.orlov@loxal.net>

//! `bitwarden-backup-vault-decrypted-via-bw-cli` — decrypted active-vault
//! backup through the official Bitwarden CLI.
//!
//! This is the conservative fallback/source-of-truth path: shell out to
//! `bw sync --force`, `bw list folders`, and `bw list items`. It requires
//! an unlocked official CLI session (`BW_SESSION`) and therefore matches
//! the same default item state that `bw list items` exposes: not deleted,
//! not archived.

use std::path::Path;
use std::process::{Command, ExitCode, Stdio};

use bitwarden_dedup::live_vault::snapshot::{recoverable_snapshot_path, write_recoverable};
use clap::Parser;
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Parser, Debug)]
#[command(
    name = "bitwarden-backup-vault-decrypted-via-bw-cli",
    about = "Decrypted active-vault backup through the official Bitwarden CLI. \
             Requires an unlocked `bw` session and writes a `just dedup`-ready \
             JSON file to vault/bitwarden_decrypted-export_<UTC-ts>.json."
)]
struct Cli {
    /// Skip `bw sync --force` before listing items. Useful only when
    /// intentionally working from the current local CLI cache.
    #[arg(long)]
    no_sync: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BwStatus {
    server_url: Option<String>,
    last_sync: Option<String>,
    user_email: Option<String>,
    user_id: Option<String>,
    status: String,
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
    let vault_dir = Path::new("vault");
    require_real_vault_dir(vault_dir)?;

    eprintln!("Checking official Bitwarden CLI session ...");
    let status = bw_status()?;
    require_unlocked(&status)?;
    eprintln!(
        "OK — {} on {} ({})",
        status.user_email.as_deref().unwrap_or("<unknown email>"),
        status.server_url.as_deref().unwrap_or("<unknown server>"),
        status.user_id.as_deref().unwrap_or("<unknown user id>")
    );

    if cli.no_sync {
        eprintln!("Skipping `bw sync --force` because --no-sync was passed.");
    } else {
        eprintln!("Running `bw sync --force` ...");
        let sync_output = run_bw_text(&["sync", "--force"])?;
        if !sync_output.trim().is_empty() {
            eprintln!("{}", sync_output.trim());
        }
    }

    eprintln!("Reading folders from `bw list folders` ...");
    let mut folders = read_bw_array(&["list", "folders"], "folders")?;
    for folder in &mut folders {
        strip_cli_only_fields(folder);
    }

    eprintln!("Reading active items from `bw list items` ...");
    let mut items = read_bw_array(&["list", "items"], "items")?;
    for item in &mut items {
        strip_cli_only_fields(item);
    }

    let identity_count = items
        .iter()
        .filter(|item| item.get("type").and_then(Value::as_i64) == Some(4))
        .count();
    let non_null_deleted_date_count = items
        .iter()
        .filter(|item| {
            item.get("deletedDate")
                .map(|v| !v.is_null())
                .unwrap_or(false)
        })
        .count();

    let decrypted = json!({
        "encrypted": false,
        "folders": folders,
        "items": items,
    });

    let path = recoverable_snapshot_path(vault_dir);
    let snap = write_recoverable(&path, &decrypted)?;

    println!();
    println!("Decrypted backup complete");
    println!(
        "  account:   {}",
        status.user_email.as_deref().unwrap_or("<unknown email>")
    );
    println!(
        "  server:    {}",
        status.server_url.as_deref().unwrap_or("<unknown server>")
    );
    if let Some(last_sync) = status.last_sync.as_deref() {
        println!("  last sync: {last_sync} (before this run's forced sync)");
    }
    println!("  source:    official `bw` CLI (`bw list items`, active vault only)");
    println!("  snapshot:  {}", snap.path.display());
    println!("  bytes:     {}", snap.byte_count);
    println!("  items:     {}", snap.item_count);
    println!("  identities:{identity_count:>5}");
    println!("  folders:   {}", snap.folder_count);
    if non_null_deleted_date_count > 0 {
        println!("  warning:   {non_null_deleted_date_count} listed items carried deletedDate");
    }
    println!();
    println!("This file is **maximum-sensitivity plaintext** — passwords, TOTP seeds,");
    println!("FIDO2 material, secure-note bodies in the clear. Mode 0o600, gitignored,");
    println!("but treat as if you'd just run `bw export --format json`. Delete after use.");
    println!();
    println!("Next step: `just dedup` will auto-discover this file (newest by lexical sort)");
    println!("and run the dedup pipeline against it.");

    Ok(())
}

fn bw_status() -> Result<BwStatus, Box<dyn std::error::Error>> {
    let out = run_bw_text(&["status", "--raw"])?;
    serde_json::from_str(&out).map_err(|e| format!("parsing `bw status --raw`: {e}").into())
}

fn require_unlocked(status: &BwStatus) -> Result<(), Box<dyn std::error::Error>> {
    match status.status.as_str() {
        "unlocked" => Ok(()),
        "locked" => Err("Bitwarden CLI is logged in but locked. Run `export BW_SESSION=\"$(bw unlock --raw)\"` and retry.".into()),
        "unauthenticated" => Err("Bitwarden CLI is not logged in. Run `bw login <email>`, then `export BW_SESSION=\"$(bw unlock --raw)\"`, and retry.".into()),
        other => Err(format!(
            "Bitwarden CLI status is {other:?}; expected `unlocked`. Run `bw status --raw` to inspect."
        )
        .into()),
    }
}

fn read_bw_array(
    args: &[&str],
    label: &'static str,
) -> Result<Vec<Value>, Box<dyn std::error::Error>> {
    let out = run_bw_text(args)?;
    let value: Value =
        serde_json::from_str(&out).map_err(|e| format!("parsing `bw {}`: {e}", args.join(" ")))?;
    value.as_array().cloned().ok_or_else(|| {
        format!(
            "`bw {}` did not return a JSON array for {label}",
            args.join(" ")
        )
        .into()
    })
}

fn strip_cli_only_fields(value: &mut Value) {
    if let Some(obj) = value.as_object_mut() {
        obj.remove("object");
    }
}

fn run_bw_text(args: &[&str]) -> Result<String, Box<dyn std::error::Error>> {
    let output = Command::new("bw")
        .args(args)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| {
            format!(
                "failed to run `bw {}`: {e}. Is the Bitwarden CLI installed and on PATH?",
                args.join(" ")
            )
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let detail = if !stderr.trim().is_empty() {
            stderr.trim().to_string()
        } else {
            stdout.trim().to_string()
        };
        return Err(format!(
            "`bw {}` failed with status {}{}",
            args.join(" "),
            output.status,
            if detail.is_empty() {
                String::new()
            } else {
                format!(": {detail}")
            }
        )
        .into());
    }

    String::from_utf8(output.stdout)
        .map_err(|e| format!("`bw {}` returned non-UTF-8 output: {e}", args.join(" ")).into())
}

fn require_real_vault_dir(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    use std::fs;
    let lmeta = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(_) => {
            return Err(format!(
                "vault/ directory missing — run from the bitwarden-dedup project root \
                 (current dir: {})",
                std::env::current_dir()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|_| "?".to_string())
            )
            .into());
        }
    };
    if lmeta.file_type().is_symlink() {
        let target = fs::read_link(path).ok();
        return Err(format!(
            "refusing to use {} as the vault directory: it is a symlink{}. \
             The gitignore rule `vault/` is path-based.",
            path.display(),
            target
                .map(|t| format!(" pointing at {}", t.display()))
                .unwrap_or_default()
        )
        .into());
    }
    if !lmeta.file_type().is_dir() {
        return Err(format!("{} exists but is not a directory", path.display()).into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_cli_only_fields_removes_object_marker_only() {
        let mut value = json!({
            "object": "item",
            "id": "cipher-id",
            "name": "example",
            "deletedDate": null
        });

        strip_cli_only_fields(&mut value);

        assert_eq!(value.get("object"), None);
        assert_eq!(value["id"], "cipher-id");
        assert_eq!(value["name"], "example");
        assert!(value["deletedDate"].is_null());
    }

    #[test]
    fn require_unlocked_rejects_locked_cli_state_with_recovery_hint() {
        let status = BwStatus {
            server_url: Some("https://vault.bitwarden.com".to_string()),
            last_sync: None,
            user_email: Some("alexander.orlov@loxal.net".to_string()),
            user_id: Some("user-id".to_string()),
            status: "locked".to_string(),
        };

        let err = require_unlocked(&status).unwrap_err().to_string();

        assert!(err.contains("BW_SESSION"));
        assert!(err.contains("bw unlock --raw"));
    }
}
