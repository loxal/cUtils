// Copyright 2026 Alexander Orlov <alexander.orlov@loxal.net>

//! `bitwarden-backup-vault-encrypted` — encrypted backup of a
//! Bitwarden personal vault via the REST API.
//!
//! Authenticates with the user's personal API key (OAuth
//! `client_credentials` against `/identity/connect/token`), fetches
//! `/api/sync`, and writes the raw response bytes to
//! `vault/bitwarden_encrypted-export_<UTC-ts>.json` with mode 0o600. The
//! response is **encrypted** end-to-end — this tool never sees,
//! requires, or stores the master password. For a `just dedup`-ready
//! JSON export, use `bitwarden-backup-vault-decrypted`; for an
//! independent official-client cross-check, use
//! `bitwarden-backup-vault-decrypted-via-bw-cli`.
//!
//! Use cases:
//!  - Independent backup of the live vault state, without depending
//!    on Bitwarden's Node.js CLI.
//!  - Pre-flight snapshot before any risky vault operation done
//!    elsewhere (web UI bulk edits, mobile-app reorganization).
//!  - Cron-friendly: no interactive prompt, exits non-zero on any
//!    failure, and refuses to overwrite an existing snapshot.

use std::path::PathBuf;
use std::process::ExitCode;

use bitwarden_dedup::live_vault::{
    Region,
    auth::{ApiKeyCredentials, acquire_access_token, persistent_device_identifier},
    rest::{SyncError, fetch_sync},
    snapshot::{forensic_snapshot_path, write_forensic},
};
use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    name = "bitwarden-backup-vault-encrypted",
    about = "Encrypted backup of a Bitwarden personal vault via the REST API. \
             Writes the raw /api/sync response (encrypted, no master password \
             needed) to vault/bitwarden_encrypted-export_<UTC-ts>.json with mode 0o600."
)]
struct Cli {
    /// Path to the env file carrying `BW_CLIENT_ID`,
    /// `BW_CLIENT_SECRET`, and `BW_REGION`. Defaults to
    /// `vault/bitwarden_api_key.env` relative to the current
    /// working directory (the Bitwarden-dedup project root).
    #[arg(long, default_value = "vault/bitwarden_api_key.env")]
    env_file: PathBuf,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    // current_thread runtime: this binary makes one auth call and
    // one GET, no concurrency. Multi-threaded runtime was overkill.
    // (Audit right-sizing recommendation 2026-04-25.)
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
    // 1. Load credentials + region from the env file.
    let env = load_env_file(&cli.env_file)?;
    let creds = ApiKeyCredentials::new(env.client_id, env.client_secret);
    let region = env.region;

    // 2. Build a single reqwest client.
    //
    //    - rustls-only TLS via webpki-roots (no system-trust ambiguity)
    //    - https_only refuses any plaintext URL even if a future code
    //      path constructs one
    //    - **redirects disabled**: bitwarden.com / bitwarden.eu never
    //      legitimately 30x our requests. Following a redirect would
    //      forward our `Authorization: Bearer ...` header to the
    //      target host, so a server-side misconfig that points to an
    //      unrelated domain would leak the bearer. Defense-in-depth
    //      per audit handoff 2026-04-25.
    //    - timeouts bound the worst case (a hung TLS handshake or a
    //      slow sync response).
    let client = reqwest::Client::builder()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(60))
        .connect_timeout(std::time::Duration::from_secs(10))
        .build()?;

    // 3. Resolve / persist deviceIdentifier under vault/.device_id
    //    (audit 2026-04-25: a stable per-installation UUID is what
    //    keeps the Identity server's CAPTCHA heuristic quiet across
    //    runs).
    let vault_dir = std::path::Path::new("vault");
    require_real_vault_dir(vault_dir)?;
    let device_id = persistent_device_identifier(vault_dir)?;
    let device_name = format!("bitwarden-api-dedup ({})", std::env::consts::OS);

    // 4. Acquire OAuth bearer.
    eprintln!("Authenticating against {} ...", region.identity_base_url());
    let mut token = acquire_access_token(&client, region, &creds, &device_id, &device_name).await?;
    eprintln!("OK — bearer acquired (expires_in honored, full token redacted)");

    // 5. Fetch /api/sync (raw bytes — no parsing, no crypto). One
    //    refresh-and-retry on 401 so a token that the server has
    //    invalidated mid-session doesn't take down a multi-minute
    //    sync. Read-only operation, idempotent — safe to retry.
    eprintln!(
        "Fetching {}/sync?excludeDomains=true ...",
        region.api_base_url()
    );
    let sync_body = match fetch_sync(&client, region, &token).await {
        Ok(b) => b,
        Err(SyncError::Unauthorized { .. }) => {
            eprintln!("got 401 — bearer token invalidated server-side; refreshing once ...");
            token = acquire_access_token(&client, region, &creds, &device_id, &device_name).await?;
            fetch_sync(&client, region, &token).await?
        }
        Err(other) => return Err(other.into()),
    };
    eprintln!("OK — received {} bytes", sync_body.len());

    // 6. Write forensic snapshot to vault/.
    let path = forensic_snapshot_path(vault_dir);
    let snap = write_forensic(&path, &sync_body)?;

    // 6. Summary.
    println!();
    println!("Backup complete");
    println!("  region:    {:?}", region);
    println!("  endpoint:  {}/sync", region.api_base_url());
    println!("  snapshot:  {}", snap.path.display());
    println!("  bytes:     {}", snap.byte_count);
    println!("  ciphers:   {}", snap.cipher_count);
    println!("  folders:   {}", snap.folder_count);
    println!();
    println!("The snapshot is the encrypted /api/sync response, byte-for-byte. Safe to keep,");
    println!("gitignored, mode 0o600. Decryption is out of scope for this tool — for the dedup");
    println!("workflow, run `bw export --format json` and feed the result to `just dedup`.");

    Ok(())
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
             `BW_REGION` per the plan's L.10 section",
            path.display()
        )
        .into());
    }

    // Refuse to read credentials out of a group- or world-readable
    // file on Unix. The vault/ rule chmods this to 0o600 on first
    // creation, so a permissive mode means someone has tampered or
    // a different user wrote the file — either way, we'd rather
    // bail than silently slurp the secrets.
    require_owner_only_perms(path)?;

    // Don't pollute the process environment globally — read into our
    // own map so concurrent runs / tests don't leak credentials.
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
            "BW_CLIENT_ID {:?} does not look like a personal API key (expected `user.<uuid>`). \
             Generate one in: Bitwarden web vault → Account Settings → Security → Keys.",
            client_id
        )
        .into());
    }

    Ok(LoadedEnv {
        client_id,
        client_secret,
        region,
    })
}

/// Verify `path` exists, is a directory, and is **not** a symlink.
/// The `vault/` gitignore rule is path-based — a symlinked
/// `vault/` would let an operator (or an attacker who could plant
/// a symlink) divert snapshot writes outside the gitignored area.
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
        // Resolve the target so the error can name where it points.
        let target = fs::read_link(path).ok();
        return Err(format!(
            "refusing to use {} as the vault directory: it is a symlink{}. \
             The gitignore rule `vault/` is path-based, so a symlink could \
             redirect snapshots outside the ignored area.",
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

/// On Unix: refuse if the file is group- or world-readable. The env
/// file holds the personal API key — if anyone but the user can
/// read it, the credential is already compromised.
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn scratch(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "bwd-bin-{}-{label}-{}",
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

    /// `unwrap_err()` requires `T: Debug`, but `LoadedEnv`
    /// deliberately doesn't implement Debug — its `client_secret`
    /// field must never end up in a panic message. Use this
    /// pattern-match helper instead.
    fn expect_err(result: Result<LoadedEnv, Box<dyn std::error::Error>>) -> String {
        match result {
            Ok(_) => panic!("expected error, got Ok"),
            Err(e) => e.to_string(),
        }
    }

    /// Helper: write an env file at owner-only perms so the
    /// permissions check in `load_env_file` doesn't reject it.
    fn write_env_file(path: &std::path::Path, content: &str) {
        fs::write(path, content).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
    }

    #[test]
    fn load_env_file_happy_path() {
        let dir = scratch("env-happy");
        let f = dir.join(".env");
        write_env_file(
            &f,
            "BW_CLIENT_ID=user.abc-1234\nBW_CLIENT_SECRET=hush\nBW_REGION=us\n",
        );
        let env = load_env_file(&f).unwrap();
        assert_eq!(env.client_id, "user.abc-1234");
        assert_eq!(env.client_secret, "hush");
        assert_eq!(env.region, Region::Us);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_env_file_rejects_missing_file() {
        let bogus = std::env::temp_dir().join(format!(
            "bwd-missing-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0),
        ));
        let msg = expect_err(load_env_file(&bogus));
        assert!(msg.contains("env file not found"));
    }

    #[test]
    fn load_env_file_rejects_missing_client_id() {
        let dir = scratch("env-no-id");
        let f = dir.join(".env");
        write_env_file(&f, "BW_CLIENT_SECRET=x\nBW_REGION=us\n");
        let msg = expect_err(load_env_file(&f));
        assert!(msg.contains("BW_CLIENT_ID"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_env_file_rejects_missing_region() {
        let dir = scratch("env-no-region");
        let f = dir.join(".env");
        write_env_file(&f, "BW_CLIENT_ID=user.x\nBW_CLIENT_SECRET=y\n");
        let msg = expect_err(load_env_file(&f));
        assert!(msg.contains("BW_REGION"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_env_file_rejects_bad_region_value() {
        let dir = scratch("env-bad-region");
        let f = dir.join(".env");
        write_env_file(
            &f,
            "BW_CLIENT_ID=user.x\nBW_CLIENT_SECRET=y\nBW_REGION=mars\n",
        );
        let msg = expect_err(load_env_file(&f));
        assert!(msg.contains("BW_REGION"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    #[cfg(unix)]
    fn load_env_file_refuses_group_readable_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch("env-perms");
        let f = dir.join(".env");
        fs::write(
            &f,
            "BW_CLIENT_ID=user.x\nBW_CLIENT_SECRET=y\nBW_REGION=us\n",
        )
        .unwrap();
        // 0o644 = owner rw, group r, world r — clearly too loose.
        fs::set_permissions(&f, fs::Permissions::from_mode(0o644)).unwrap();
        let msg = expect_err(load_env_file(&f));
        assert!(msg.contains("group/world readable"), "got: {msg}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    #[cfg(unix)]
    fn load_env_file_accepts_owner_only_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch("env-tight");
        let f = dir.join(".env");
        fs::write(
            &f,
            "BW_CLIENT_ID=user.x\nBW_CLIENT_SECRET=y\nBW_REGION=us\n",
        )
        .unwrap();
        fs::set_permissions(&f, fs::Permissions::from_mode(0o600)).unwrap();
        let env = load_env_file(&f).unwrap();
        assert_eq!(env.client_id, "user.x");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn require_real_vault_dir_accepts_real_dir() {
        let dir = scratch("real-vault");
        require_real_vault_dir(&dir).unwrap();
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn require_real_vault_dir_rejects_missing() {
        let bogus = std::env::temp_dir().join(format!(
            "bwd-bin-missing-vault-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0),
        ));
        let err = require_real_vault_dir(&bogus).unwrap_err();
        assert!(err.to_string().contains("vault/ directory missing"));
    }

    #[test]
    #[cfg(unix)]
    fn require_real_vault_dir_rejects_symlink() {
        let parent = std::env::temp_dir().join(format!(
            "bwd-bin-symvault-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0),
        ));
        fs::create_dir_all(&parent).unwrap();
        let real_target = parent.join("real_target");
        let symlink_path = parent.join("vault");
        fs::create_dir_all(&real_target).unwrap();
        std::os::unix::fs::symlink(&real_target, &symlink_path).unwrap();
        let err = require_real_vault_dir(&symlink_path).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("symlink"), "got: {msg}");
        // Error message should also reveal where the symlink resolves
        // so the user can investigate.
        assert!(msg.contains("real_target"), "got: {msg}");
        let _ = fs::remove_dir_all(&parent);
    }

    #[test]
    fn require_real_vault_dir_rejects_file_at_path() {
        let dir = scratch("file-not-dir");
        let masquerade = dir.join("vault");
        fs::write(&masquerade, "not a directory").unwrap();
        let err = require_real_vault_dir(&masquerade).unwrap_err();
        assert!(err.to_string().contains("not a directory"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_env_file_rejects_non_personal_api_key_id() {
        // Bitwarden organization API keys start with `organization.`;
        // we want to fail clearly if the user pasted one of those by
        // mistake — this tool is personal-vault only.
        let dir = scratch("env-org-id");
        let f = dir.join(".env");
        write_env_file(
            &f,
            "BW_CLIENT_ID=organization.abc\nBW_CLIENT_SECRET=y\nBW_REGION=us\n",
        );
        let msg = expect_err(load_env_file(&f));
        assert!(msg.contains("personal API key"));
        let _ = fs::remove_dir_all(&dir);
    }
}
