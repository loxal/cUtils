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
//!     account's KDF parameters (read from the sync response's
//!     profile object).
//!   - Stretches via two HKDF-SHA256 expand calls (`b"enc"` /
//!     `b"mac"`).
//!   - Decrypts the user key, then every encrypted cipher field.
//!   - Writes the result as a JSON-export-shape file to
//!     `vault/bitwarden_export_<UTC-ts>.json` (mode 0o600,
//!     gitignored). Directly consumable by `just dedup`.
//!
//! **The decrypted output is maximum-sensitivity plaintext** —
//! passwords, TOTP seeds, FIDO2 material, secure-note bodies, all
//! in the clear. Same risk profile as `bw export --format json`.
//! Treat it accordingly: never share, delete after use, never
//! commit. The `vault/` directory's gitignore + 0o600 mode are the
//! only at-rest protection.
//!
//! Crypto correctness is gated on `tests/crypto_vectors.rs`, which
//! locks every primitive byte-exact against `bitwarden/sdk-internal`.
//! If those tests pass, this tool decrypts identically to the
//! official Bitwarden client. If they fail, this binary will refuse
//! to build.

use std::path::PathBuf;
use std::process::ExitCode;

use bitwarden_dedup::live_vault::{
    Region,
    auth::{ApiKeyCredentials, acquire_access_token, persistent_device_identifier},
    cipher_codec::{decrypt_sync_to_export_shape, extract_account_email},
    rest::{SyncError, fetch_prelogin, fetch_sync},
    snapshot::{recoverable_snapshot_path, write_recoverable},
};
use clap::Parser;
use secrecy::SecretString;

#[derive(Parser, Debug)]
#[command(
    name = "bitwarden-backup-vault-decrypted",
    about = "Decrypted backup of a Bitwarden personal vault via the REST API. \
             Prompts for the master password, decrypts /api/sync, and writes a \
             `just dedup`-ready JSON to vault/bitwarden_export_<UTC-ts>.json."
)]
struct Cli {
    /// Path to the env file carrying `BW_CLIENT_ID`,
    /// `BW_CLIENT_SECRET`, and `BW_REGION`. Defaults to
    /// `vault/bitwarden_api_key.env`.
    #[arg(long, default_value = "vault/bitwarden_api_key.env")]
    env_file: PathBuf,
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
    // 1. Env (credentials + region) and vault dir.
    let env = load_env_file(&cli.env_file)?;
    let creds = ApiKeyCredentials::new(env.client_id, env.client_secret);
    let region = env.region;

    let vault_dir = std::path::Path::new("vault");
    require_real_vault_dir(vault_dir)?;

    // 2. Master-password prompt — BEFORE the network call, so a
    //    typo doesn't waste a round trip + so the user can ^C
    //    without the bearer token in flight.
    let master_password = prompt_master_password()?;

    // 3. Build reqwest client — same shape as the encrypted variant.
    let client = reqwest::Client::builder()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(60))
        .connect_timeout(std::time::Duration::from_secs(10))
        .build()?;

    // 4. Resolve / persist deviceIdentifier.
    let device_id = persistent_device_identifier(vault_dir)?;
    let device_name = format!("bitwarden-backup-vault-decrypted ({})", std::env::consts::OS);

    // 5. OAuth bearer.
    eprintln!("Authenticating against {} ...", region.identity_base_url());
    let mut token =
        acquire_access_token(&client, region, &creds, &device_id, &device_name).await?;
    eprintln!("OK — bearer acquired (full token redacted)");

    // 6. /api/sync with one 401 refresh-and-retry.
    eprintln!("Fetching {}/sync?excludeDomains=true ...", region.api_base_url());
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

    // 7. Get the account email from /api/sync, then KDF params from
    //    /accounts/prelogin. KDF params are NOT on /api/sync.profile
    //    (verified empirically against live US production server on
    //    2026-04-25), so the audit's L.2 recommendation to use
    //    /accounts/prelogin is the right path.
    let email = extract_account_email(&sync_body)?;
    eprintln!("Fetching KDF params from /accounts/prelogin for {email} ...");
    let kdf = fetch_prelogin(&client, region, &email).await?;
    eprintln!("OK — KDF params: {kdf:?}");

    // 8. Decrypt. ALL the crypto correctness gates
    //    (HMAC-before-AES, two-call HKDF, Argon2id-SHA256-salt,
    //    EncString type 2 only) live in live_vault::crypto and
    //    are exercised by tests/crypto_vectors.rs.
    eprintln!("Decrypting vault ...");
    let decrypted = decrypt_sync_to_export_shape(&sync_body, kdf, &master_password)?;
    let item_count = decrypted
        .get("items")
        .and_then(serde_json::Value::as_array)
        .map(|a| a.len())
        .unwrap_or(0);
    let folder_count = decrypted
        .get("folders")
        .and_then(serde_json::Value::as_array)
        .map(|a| a.len())
        .unwrap_or(0);
    eprintln!("OK — decrypted {item_count} items / {folder_count} folders");

    // 8. Write the recoverable snapshot.
    let path = recoverable_snapshot_path(vault_dir);
    let snap = write_recoverable(&path, &decrypted)?;

    // 9. Summary.
    println!();
    println!("Decrypted backup complete");
    println!("  region:    {:?}", region);
    println!("  endpoint:  {}/sync", region.api_base_url());
    println!("  snapshot:  {}", snap.path.display());
    println!("  bytes:     {}", snap.byte_count);
    println!("  items:     {}", snap.item_count);
    println!("  folders:   {}", snap.folder_count);
    println!();
    println!("This file is **maximum-sensitivity plaintext** — passwords, TOTP seeds,");
    println!("FIDO2 material, secure-note bodies in the clear. Mode 0o600, gitignored,");
    println!("but treat as if you'd just run `bw export --format json`. Delete after use.");
    println!();
    println!("Next step: `just dedup` will auto-discover this file (newest by lexical sort)");
    println!("and run the dedup pipeline against it.");

    Ok(())
}

// -----------------------------------------------------------------
// env file + vault-dir helpers (same as the encrypted variant —
// duplicated rather than shared to keep the binaries decoupled)
// -----------------------------------------------------------------

struct LoadedEnv {
    client_id: String,
    client_secret: String,
    region: Region,
}

fn load_env_file(path: &std::path::Path) -> Result<LoadedEnv, Box<dyn std::error::Error>> {
    if !path.exists() {
        return Err(format!(
            "env file not found at {} — expected `BW_CLIENT_ID`, `BW_CLIENT_SECRET`, \
             `BW_REGION`",
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

    let client_id =
        get("BW_CLIENT_ID").ok_or("BW_CLIENT_ID missing from env file")?;
    let client_secret =
        get("BW_CLIENT_SECRET").ok_or("BW_CLIENT_SECRET missing from env file")?;
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

fn require_owner_only_perms(
    path: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(path)
            .map_err(|e| format!("stat {}: {e}", path.display()))?;
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

// -----------------------------------------------------------------
// Master password prompt
// -----------------------------------------------------------------

/// Prompt for the master password without echo, wrap in
/// `SecretString` immediately so it's zeroized on drop. Never
/// reaches `tracing`/`log`/stderr beyond the prompt itself.
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
