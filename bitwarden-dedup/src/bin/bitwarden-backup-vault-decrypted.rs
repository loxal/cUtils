// Copyright 2026 Alexander Orlov <alexander.orlov@loxal.net>

//! `bitwarden-backup-vault-decrypted` — decrypted backup of a
//! Bitwarden personal vault via the REST API.
//!
//! Same network path as `bitwarden-backup-vault-encrypted`
//! (OAuth `client_credentials` → `/api/sync`), but additionally:
//!
//!   - Prompts for the master password at stdin (no echo,
//!     `secrecy::SecretString`, zeroized on drop).
//!   - Derives the master key via Argon2id or PBKDF2 per the
//!     account's KDF parameters.
//!   - Decrypts the user key, then every cipher field.
//!   - Writes the result as a JSON-export-shape file to
//!     `vault/bitwarden_decrypted-export_<UTC-ts>.json` (mode 0o600,
//!     gitignored). Directly consumable by `just dedup`.
//!
//! The output matches official `bw export --format json` **item-state**
//! semantics: deleted ciphers from `/api/sync` are omitted, archived
//! ciphers are preserved with `archivedDate`, and the encrypted
//! `/api/sync` snapshot remains the full forensic backup.
//!
//! **Scope limits** (where the output is narrower than official
//! `bw export --format json`):
//!
//!   - Organization-owned ciphers (`organizationId != null`) are
//!     **skipped before decryption**. Their payloads are encrypted
//!     under per-org keys, not the user key, and decrypting them
//!     correctly would require unwrapping each
//!     `profile.organizations[].key` with the user's RSA private key
//!     and selecting the right org key per cipher — substantial extra
//!     crypto not yet implemented. The skipped count is surfaced on
//!     stderr and in the final summary so the user is never
//!     surprised by missing items.
//!   - Restricted-item-types policy filtering (an enterprise feature)
//!     is not applied. Consumer-cloud and personal-vault paths don't
//!     use it, so this only matters for enterprise-policy users.
//!
//! **The decrypted output is maximum-sensitivity plaintext** —
//! passwords, TOTP seeds, FIDO2 material, secure-note bodies, all
//! in the clear. Same risk profile as `bw export --format json`.

use std::path::PathBuf;
use std::process::ExitCode;

use bitwarden_dedup::live_vault::{
    Region,
    auth::{ApiKeyCredentials, acquire_access_token, persistent_device_identifier},
    cipher_codec::{
        decrypt_sync_to_export_shape, extract_account_email, filter_export_to_bw_export_items,
    },
    rest::{SyncError, fetch_prelogin, fetch_sync},
    snapshot::{
        recoverable_snapshot_path, recoverable_with_trash_snapshot_path, write_recoverable,
    },
};
use clap::Parser;
use secrecy::SecretString;

#[derive(Parser, Debug)]
#[command(
    name = "bitwarden-backup-vault-decrypted",
    about = "Decrypted Bitwarden export backup via REST API. Prompts for \
             the master password, decrypts /api/sync, filters trash like \
             `bw export`, preserves archive state, and writes a `just dedup`-ready JSON."
)]
struct Cli {
    /// Path to the env file carrying `BW_CLIENT_ID`,
    /// `BW_CLIENT_SECRET`, and `BW_REGION`. Defaults to
    /// `vault/bitwarden_api_key.env`.
    #[arg(long, default_value = "vault/bitwarden_api_key.env")]
    env_file: PathBuf,

    /// Include ciphers currently in Bitwarden Trash. The default
    /// matches `bw export --format json` and omits them.
    #[arg(long)]
    include_trash: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: failed to start tokio runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(run(cli)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    let env = load_env_file(&cli.env_file)?;
    let creds = ApiKeyCredentials::new(env.client_id, env.client_secret);
    let region = env.region;

    let vault_dir = std::path::Path::new("vault");
    require_real_vault_dir(vault_dir)?;

    let master_password = prompt_master_password()?;

    let client = reqwest::Client::builder()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(60))
        .connect_timeout(std::time::Duration::from_secs(10))
        .build()?;

    let device_id = persistent_device_identifier(vault_dir)?;
    let device_name = format!(
        "bitwarden-backup-vault-decrypted ({})",
        std::env::consts::OS
    );

    eprintln!("Authenticating against {} ...", region.identity_base_url());
    let mut token = acquire_access_token(&client, region, &creds, &device_id, &device_name).await?;
    eprintln!("OK — bearer acquired (full token redacted)");

    eprintln!(
        "Fetching {}/sync?excludeDomains=true ...",
        region.api_base_url()
    );
    let sync_body = match fetch_sync(&client, region, &token).await {
        Ok(b) => b,
        Err(SyncError::Unauthorized { .. }) => {
            eprintln!("got 401 — refreshing bearer and retrying once ...");
            token = acquire_access_token(&client, region, &creds, &device_id, &device_name).await?;
            fetch_sync(&client, region, &token).await?
        }
        Err(other) => return Err(other.into()),
    };
    eprintln!("OK — received {} bytes", sync_body.len());

    let email = extract_account_email(&sync_body)?;
    eprintln!("Fetching KDF params from /accounts/prelogin for {email} ...");
    let kdf = fetch_prelogin(&client, region, &email).await?;
    eprintln!("OK — KDF params: {kdf:?}");

    eprintln!("Decrypting vault ...");
    let decrypt_result = decrypt_sync_to_export_shape(&sync_body, kdf, &master_password)?;
    let mut decrypted = decrypt_result.value;
    let org_omitted = decrypt_result.org_ciphers_omitted;
    let before_count = item_count(&decrypted);
    let filter_stats = filter_export_to_bw_export_items(&mut decrypted, cli.include_trash);
    let after_count = item_count(&decrypted);
    let folder_count = decrypted
        .get("folders")
        .and_then(serde_json::Value::as_array)
        .map(|a| a.len())
        .unwrap_or(0);
    eprintln!("OK — decrypted {before_count} items / {folder_count} folders");
    if org_omitted > 0 {
        eprintln!(
            "Note: skipped {org_omitted} organization-owned cipher(s) — \
             org-key decryption is not implemented in this tool. \
             Personal-vault items are decrypted normally; for an org-vault \
             export use `bw --raw export --format json --organizationid <id>`."
        );
    }
    if !cli.include_trash {
        eprintln!(
            "Filtered to {after_count} `bw export` items (omitted {} trashed, preserved {} archived).",
            filter_stats.trashed_omitted, filter_stats.archived_kept
        );
    }

    let path = if cli.include_trash {
        recoverable_with_trash_snapshot_path(vault_dir)
    } else {
        recoverable_snapshot_path(vault_dir)
    };
    let snap = write_recoverable(&path, &decrypted)?;

    println!();
    println!("Decrypted backup complete");
    println!("  region:    {:?}", region);
    println!("  endpoint:  {}/sync", region.api_base_url());
    println!("  source:    REST /api/sync, filtered to Bitwarden export semantics");
    println!("  snapshot:  {}", snap.path.display());
    println!("  bytes:     {}", snap.byte_count);
    println!("  items:     {}", snap.item_count);
    println!("  folders:   {}", snap.folder_count);
    if filter_stats.trashed_omitted > 0 || filter_stats.archived_kept > 0 {
        println!(
            "  state:     omitted {} trashed; preserved {} archived",
            filter_stats.trashed_omitted, filter_stats.archived_kept
        );
    }
    if org_omitted > 0 {
        println!(
            "  org-skip:  {org_omitted} cipher(s) skipped — \
             org-key decryption not implemented (personal-vault items only)"
        );
    }
    if cli.include_trash {
        println!("  warning:   includes Trash; skipped by `just dedup` auto-discovery");
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

fn item_count(export: &serde_json::Value) -> usize {
    export
        .get("items")
        .and_then(serde_json::Value::as_array)
        .map(|a| a.len())
        .unwrap_or(0)
}

struct LoadedEnv {
    client_id: String,
    client_secret: String,
    region: Region,
}

fn load_env_file(path: &std::path::Path) -> Result<LoadedEnv, Box<dyn std::error::Error>> {
    if !path.exists() {
        return Err(format!(
            "env file not found at {} — expected `BW_CLIENT_ID`, `BW_CLIENT_SECRET`, \
             and `BW_REGION`",
            path.display()
        )
        .into());
    }
    require_owner_only_perms(path)?;
    let entries: Vec<(String, String)> = dotenvy::from_path_iter(path)
        .map_err(|e| format!("reading {}: {e}", path.display()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("parsing {}: {e}", path.display()))?;

    let get = |key: &str| -> Option<String> {
        entries
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.clone())
    };

    let client_id = get("BW_CLIENT_ID").ok_or("BW_CLIENT_ID missing from env file")?;
    let client_secret = get("BW_CLIENT_SECRET").ok_or("BW_CLIENT_SECRET missing from env file")?;
    let region_raw = get("BW_REGION").ok_or(
        "BW_REGION missing from env file — set to `us` or `eu`. \
         No automatic region-discovery; the tool fails-fast.",
    )?;
    let region = Region::parse(&region_raw)?;

    if !client_id.starts_with("user.") {
        return Err(format!(
            "BW_CLIENT_ID {client_id:?} does not look like a personal API key (expected `user.<uuid>`)"
        )
        .into());
    }

    Ok(LoadedEnv {
        client_id,
        client_secret,
        region,
    })
}

fn require_real_vault_dir(path: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
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

fn require_owner_only_perms(path: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(path).map_err(|e| format!("stat {}: {e}", path.display()))?;
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(format!(
                "{} has permissions {:o} (group/world readable). \
                 Run `chmod 600 {}` and re-run.",
                path.display(),
                mode,
                path.display()
            )
            .into());
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

fn prompt_master_password() -> Result<SecretString, Box<dyn std::error::Error>> {
    eprintln!();
    eprintln!("This tool will decrypt your vault using your master password.");
    eprintln!("The password is only used locally to derive the user key — it is");
    eprintln!("NEVER sent to Bitwarden. (Auth uses the API key in vault/bitwarden_api_key.env.)");
    eprintln!();
    let raw = rpassword::prompt_password("Master password: ")
        .map_err(|e| format!("failed to read password from stdin: {e}"))?;
    if raw.is_empty() {
        return Err("master password was empty — aborting".into());
    }
    Ok(SecretString::new(raw.into()))
}
