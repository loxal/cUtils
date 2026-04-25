// Copyright 2026 Alexander Orlov <alexander.orlov@loxal.net>

//! Snapshot writers for the forensic and (Phase 1b) recoverable
//! backups.
//!
//! Phase 1a implements the **forensic snapshot** only: the
//! `/api/sync` HTTP response body, written verbatim (UTF-8 bytes,
//! no parsing) to `vault/bitwarden_encrypted-export_<UTC-ts>.json`. This is the
//! trustless-of-our-code backup — even if our crypto is broken, an
//! official Bitwarden client could in principle replay the file.
//!
//! Invariants enforced before writing:
//!
//! 1. **Path is inside `vault/`.** Refuse anything else. The vault/
//!    directory is gitignored; writing snapshots elsewhere risks
//!    committing them.
//! 2. **Filename matches the timestamped pattern.** Auto-discovery
//!    in the existing JSON-export tools sorts by lexical filename;
//!    using the same `bitwarden_encrypted-export_YYYYMMDDHHMMSS.json` shape
//!    keeps that working.
//! 3. **Body parses as JSON and contains a non-zero `ciphers[]`
//!    array.** Catches "we wrote the wrong thing" before the
//!    snapshot is trusted.
//! 4. **Atomic write at mode `0o600`** via the existing
//!    [`crate::io_util::write_sensitive_atomic`] helper.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Deserialize;
use serde::de::IgnoredAny;

use crate::io_util::write_sensitive_atomic_no_clobber;

/// Errors specific to snapshot writing.
#[derive(Debug)]
pub enum SnapshotError {
    /// Output path is not inside a `vault/` directory, or contains
    /// `..` components, or has a filename that doesn't match the
    /// `bitwarden_encrypted-export_<digits>.json` pattern.
    InvalidPath { path: PathBuf, reason: &'static str },
    /// Sync body didn't parse as JSON.
    NotJson { source: serde_json::Error },
    /// Sync body parsed but is missing or has empty `ciphers[]`.
    /// Phase 1a treats an empty vault as a hard error so an
    /// operator pointing the tool at the wrong account sees a
    /// clear error rather than a plausible-looking empty backup.
    NoCiphers,
    /// Sync body parsed but is missing the `profile.key` envelope.
    /// Without it, Phase 1b cannot derive the user key and the
    /// snapshot is not actually recoverable. Catches "wrong
    /// account" / "truncated response" before we declare the
    /// backup complete. (Audit finding 2026-04-25.)
    MissingProfileKey,
    /// Refuse-if-exists guard: another snapshot already lives at
    /// the requested path. Higher-resolution timestamps usually
    /// prevent this, but defense-in-depth catches the rare case.
    DestinationExists(PathBuf),
    /// `vault/` directory creation or atomic write failed.
    Io(std::io::Error),
}

impl std::fmt::Display for SnapshotError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SnapshotError::InvalidPath { path, reason } => write!(
                f,
                "refusing to write snapshot to {}: {reason}",
                path.display()
            ),
            SnapshotError::NotJson { source } => write!(
                f,
                "refusing to write snapshot — /api/sync response did not parse as JSON: {source}"
            ),
            SnapshotError::NoCiphers => write!(
                f,
                "refusing to write snapshot — /api/sync response has no `ciphers` array (or it is empty). \
                 Pointing at the wrong account?"
            ),
            SnapshotError::MissingProfileKey => write!(
                f,
                "refusing to write snapshot — /api/sync response has no `profile.key`. \
                 Without that envelope the backup is not decryptable, so we'd be writing a useless file. \
                 Pointing at the wrong account, or a truncated response?"
            ),
            SnapshotError::DestinationExists(p) => write!(
                f,
                "refusing to overwrite existing snapshot at {} — \
                 a previous backup already lives at this path. Wait one millisecond and re-run, \
                 or delete the existing file if you intentionally want to clobber it.",
                p.display()
            ),
            SnapshotError::Io(e) => write!(f, "I/O error writing snapshot: {e}"),
        }
    }
}

impl std::error::Error for SnapshotError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SnapshotError::NotJson { source } => Some(source),
            SnapshotError::Io(e) => Some(e),
            _ => None,
        }
    }
}

/// Result of a successful forensic snapshot write.
#[derive(Debug, Clone)]
pub struct ForensicSnapshot {
    pub path: PathBuf,
    /// Number of items in the `ciphers[]` array (sanity-check
    /// surface; the user should compare to their Bitwarden UI).
    pub cipher_count: usize,
    /// Number of folders. May be zero on a fresh account.
    pub folder_count: usize,
    /// Bytes written.
    pub byte_count: usize,
}

/// Result of a successful recoverable snapshot write.
#[derive(Debug, Clone)]
pub struct RecoverableSnapshot {
    pub path: PathBuf,
    pub item_count: usize,
    pub folder_count: usize,
    pub byte_count: usize,
}

/// Build the canonical forensic-snapshot path for "now" inside a
/// given vault directory.
///
/// UTC timestamp at **millisecond precision** — `YYYYMMDDHHMMSSmmm`,
/// 17 digits. Earlier code used second precision and two snapshots
/// taken in the same second silently clobbered each other (audit
/// finding 2026-04-25). Lexical sort still works for chronological
/// ordering.
///
/// Filename: `bitwarden_encrypted-export_<ts>.json`. The
/// `encrypted-export` infix distinguishes our raw `/api/sync` snapshot
/// from `bw export`'s output (`bitwarden_export_*.json`) so the two
/// can coexist in `vault/` without ambiguity.
pub fn forensic_snapshot_path(vault_dir: &Path) -> PathBuf {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let ts = utc_yyyymmddhhmmss_ms(now.as_secs(), now.subsec_millis());
    vault_dir.join(format!("bitwarden_encrypted-export_{ts}.json"))
}

/// Build the canonical recoverable-snapshot path for "now" inside a
/// given vault directory. Same shape as `bw export --format json`
/// emits — directly drop-in for `just dedup`.
///
/// Filename: `bitwarden_decrypted-export_<ts>.json`. The
/// `decrypted-export` infix distinguishes files our tool decrypted
/// from files dropped here by `bw export` (`bitwarden_export_*.json`).
/// Both shapes are valid `just dedup` inputs.
pub fn recoverable_snapshot_path(vault_dir: &Path) -> PathBuf {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let ts = utc_yyyymmddhhmmss_ms(now.as_secs(), now.subsec_millis());
    vault_dir.join(format!("bitwarden_decrypted-export_{ts}.json"))
}

/// Write the forensic snapshot.
///
/// `sync_body` is the raw `/api/sync` response — UTF-8 JSON. We
/// validate that it parses and has at least one cipher, but we
/// then write the **original** bytes (not a re-serialized
/// representation), so byte-equality with the server's response is
/// preserved.
///
/// Path validation (per audit 2026-04-25):
/// - Must contain a `vault` directory component (gitignore alignment)
/// - No `..` components anywhere in the path (defeats vault-escape)
/// - Filename must match `bitwarden_encrypted-export_<14|17 digits>.json`
/// - Destination must not already exist (defense-in-depth on the
///   millisecond-precision timestamp)
pub fn write_forensic(path: &Path, sync_body: &str) -> Result<ForensicSnapshot, SnapshotError> {
    validate_snapshot_path(path)?;

    // IgnoredAny: deserializes ciphers and folders as opaque
    // arrays whose elements are dropped after parse. Counts the
    // length without building the full Value tree — much cheaper
    // on a 22 MB sync response. `profile.key` is the recoverability
    // marker: without it Phase 1b cannot decrypt from the snapshot,
    // so we capture just that one string here (small) and ignore
    // the rest of the profile object.
    #[derive(Deserialize)]
    struct CountOnly {
        profile: Option<Profile>,
        #[serde(default)]
        ciphers: Vec<IgnoredAny>,
        #[serde(default)]
        folders: Vec<IgnoredAny>,
    }
    #[derive(Deserialize)]
    struct Profile {
        #[serde(default)]
        key: Option<String>,
    }

    let counts: CountOnly = serde_json::from_str(sync_body)
        .map_err(|e| SnapshotError::NotJson { source: e })?;

    let key_present = counts
        .profile
        .as_ref()
        .and_then(|p| p.key.as_deref())
        .is_some_and(|s| !s.is_empty());
    if !key_present {
        return Err(SnapshotError::MissingProfileKey);
    }

    let cipher_count = counts.ciphers.len();
    if cipher_count == 0 {
        return Err(SnapshotError::NoCiphers);
    }
    let folder_count = counts.folders.len();

    // Atomic no-clobber: if `path` already exists, this returns an
    // `AlreadyExists` IO error. Map it to the more specific
    // `DestinationExists` variant so the operator sees a clear
    // message. The check-then-rename TOCTOU window the prior code
    // had is gone — POSIX `link(2)` either succeeds or returns
    // EEXIST, atomically.
    write_sensitive_atomic_no_clobber(path, sync_body).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            SnapshotError::DestinationExists(path.to_path_buf())
        } else {
            SnapshotError::Io(e)
        }
    })?;

    Ok(ForensicSnapshot {
        path: path.to_path_buf(),
        cipher_count,
        folder_count,
        byte_count: sync_body.len(),
    })
}

/// Write a **decrypted** JSON-export-shape snapshot.
///
/// `decrypted_export` is the `serde_json::Value` produced by
/// `cipher_codec::decrypt_sync_to_export_shape` — same shape `bw
/// export --format json` emits, directly consumable by `just dedup`.
///
/// **Warning: this file is maximum-sensitivity plaintext** —
/// passwords, TOTP seeds, FIDO2 material, secure-note bodies, all in
/// the clear. We still write at mode 0o600 inside `vault/` (gitignored),
/// but the risk profile is the same as `bw export --format json`.
/// Treat it accordingly: never share, delete after use, never commit.
pub fn write_recoverable(
    path: &Path,
    decrypted_export: &serde_json::Value,
) -> Result<RecoverableSnapshot, SnapshotError> {
    validate_recoverable_snapshot_path(path)?;

    let item_count = decrypted_export
        .get("items")
        .and_then(serde_json::Value::as_array)
        .map(|a| a.len())
        .unwrap_or(0);
    if item_count == 0 {
        return Err(SnapshotError::NoCiphers);
    }
    let folder_count = decrypted_export
        .get("folders")
        .and_then(serde_json::Value::as_array)
        .map(|a| a.len())
        .unwrap_or(0);

    let body = serde_json::to_string_pretty(decrypted_export)
        .map_err(|e| SnapshotError::NotJson { source: e })?;
    let byte_count = body.len();

    write_sensitive_atomic_no_clobber(path, &body).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            SnapshotError::DestinationExists(path.to_path_buf())
        } else {
            SnapshotError::Io(e)
        }
    })?;

    Ok(RecoverableSnapshot {
        path: path.to_path_buf(),
        item_count,
        folder_count,
        byte_count,
    })
}

/// Path validation for the recoverable snapshot. Same rules as the
/// forensic-snapshot validator (must be inside `vault/`, no `..`,
/// timestamped filename) but with the `bitwarden_decrypted-export_`
/// prefix.
fn validate_recoverable_snapshot_path(path: &Path) -> Result<(), SnapshotError> {
    use std::path::Component;
    let mut saw_vault = false;
    for comp in path.components() {
        match comp {
            Component::ParentDir => {
                return Err(SnapshotError::InvalidPath {
                    path: path.to_path_buf(),
                    reason: "path contains a `..` component — refusing to write outside the \
                            apparent target directory",
                });
            }
            Component::Normal(seg) if seg.to_str() == Some("vault") => {
                saw_vault = true;
            }
            _ => {}
        }
    }
    if !saw_vault {
        return Err(SnapshotError::InvalidPath {
            path: path.to_path_buf(),
            reason: "path must be inside a `vault/` directory",
        });
    }
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return Err(SnapshotError::InvalidPath {
            path: path.to_path_buf(),
            reason: "path has no file name component",
        });
    };
    if !recoverable_filename_matches_pattern(name) {
        return Err(SnapshotError::InvalidPath {
            path: path.to_path_buf(),
            reason: "filename must match `bitwarden_decrypted-export_<14|17 digits>.json`",
        });
    }
    Ok(())
}

fn recoverable_filename_matches_pattern(name: &str) -> bool {
    let Some(stem) = name
        .strip_prefix("bitwarden_decrypted-export_")
        .and_then(|s| s.strip_suffix(".json"))
    else {
        return false;
    };
    matches!(stem.len(), 14 | 17) && stem.chars().all(|c| c.is_ascii_digit())
}

/// Lexically validate the snapshot path. Lexical (not canonicalized)
/// because the destination doesn't exist yet, and we want clear
/// error messages naming the rule that fired rather than a vague
/// "canonicalize failed."
fn validate_snapshot_path(path: &Path) -> Result<(), SnapshotError> {
    use std::path::Component;
    let mut saw_vault = false;
    for comp in path.components() {
        match comp {
            Component::ParentDir => {
                return Err(SnapshotError::InvalidPath {
                    path: path.to_path_buf(),
                    reason: "path contains a `..` component — refusing to write outside the \
                            apparent target directory",
                });
            }
            Component::Normal(seg) if seg.to_str() == Some("vault") => {
                saw_vault = true;
            }
            _ => {}
        }
    }
    if !saw_vault {
        return Err(SnapshotError::InvalidPath {
            path: path.to_path_buf(),
            reason: "path must be inside a `vault/` directory (the only directory gitignored \
                    for vault contents)",
        });
    }

    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return Err(SnapshotError::InvalidPath {
            path: path.to_path_buf(),
            reason: "path has no file name component",
        });
    };
    if !filename_matches_pattern(name) {
        return Err(SnapshotError::InvalidPath {
            path: path.to_path_buf(),
            reason: "filename must match `bitwarden_encrypted-export_<14|17 digits>.json`",
        });
    }
    Ok(())
}

/// `bitwarden_encrypted-export_(14 or 17 digits).json` — both
/// 14-digit second-precision (legacy) and 17-digit millisecond-
/// precision shapes accepted. The `encrypted-export` infix
/// distinguishes our raw `/api/sync` snapshot from `bw export`'s
/// `bitwarden_export_*.json`.
fn filename_matches_pattern(name: &str) -> bool {
    let Some(stem) = name
        .strip_prefix("bitwarden_encrypted-export_")
        .and_then(|s| s.strip_suffix(".json"))
    else {
        return false;
    };
    matches!(stem.len(), 14 | 17) && stem.chars().all(|c| c.is_ascii_digit())
}

/// `(seconds_since_epoch, millis)` → `YYYYMMDDHHMMSSmmm` (UTC).
/// 17 digits, no separators. Lexical sort = chronological sort.
fn utc_yyyymmddhhmmss_ms(secs: u64, millis: u32) -> String {
    let total_secs = secs as i64;
    let days = total_secs.div_euclid(86_400);
    let secs_in_day = total_secs.rem_euclid(86_400) as u32;

    let h = secs_in_day / 3600;
    let m = (secs_in_day % 3600) / 60;
    let s = secs_in_day % 60;

    let (y, mo, d) = civil_from_days(days);
    format!("{y:04}{mo:02}{d:02}{h:02}{m:02}{s:02}{millis:03}")
}

/// Legacy second-precision formatter, retained because some
/// existing tools auto-discover by 14-digit timestamps. Unused by
/// production code; kept as a callable helper for tests and any
/// future code that prefers second precision.
#[cfg(test)]
fn utc_yyyymmddhhmmss(secs: u64) -> String {
    let s = utc_yyyymmddhhmmss_ms(secs, 0);
    s[..14].to_string()
}

/// Hinnant's civil-from-days. `days` is days since 1970-01-01,
/// can be negative (we won't see negatives — `SystemTime::now() >= UNIX_EPOCH`
/// in practice).
fn civil_from_days(days: i64) -> (i32, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = (z - era * 146_097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i32 + era as i32 * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn scratch_vault_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir()
            .join(format!(
                "bwd-snapshot-{}-{label}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or(0),
            ))
            .join("vault");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn forensic_path_uses_millisecond_precision() {
        let dir = PathBuf::from("/tmp/scratch/vault");
        let p = forensic_snapshot_path(&dir);
        let name = p.file_name().unwrap().to_str().unwrap();
        assert!(name.starts_with("bitwarden_encrypted-export_"), "got {name}");
        assert!(name.ends_with(".json"));
        let stem = name
            .trim_start_matches("bitwarden_encrypted-export_")
            .trim_end_matches(".json");
        // Audit fix: 17 digits = YYYYMMDDHHMMSSmmm (millisecond
        // precision). Two snapshots in the same second no longer
        // collide.
        assert_eq!(stem.len(), 17, "expected 17-digit ms-precision stem, got {stem}");
        assert!(stem.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn forensic_path_two_calls_differ_by_at_least_milliseconds() {
        // The whole point of ms precision is to never collide on
        // back-to-back invocations within the same second.
        let dir = PathBuf::from("/tmp/scratch/vault");
        let mut paths = Vec::new();
        for _ in 0..5 {
            paths.push(forensic_snapshot_path(&dir));
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        let unique: std::collections::HashSet<_> = paths.iter().collect();
        assert_eq!(
            unique.len(),
            paths.len(),
            "ms-precision paths must not collide on 2ms-spaced calls: {paths:?}"
        );
    }

    #[test]
    fn utc_yyyymmddhhmmss_known_values() {
        // 2024-01-01T00:00:00Z is unix 1704067200
        assert_eq!(utc_yyyymmddhhmmss(1_704_067_200), "20240101000000");
        // 1970-01-01T00:00:00Z
        assert_eq!(utc_yyyymmddhhmmss(0), "19700101000000");
        // 2026-04-28T12:54:56Z = unix 1777380896
        // (cross-check: 2026-01-01T00:00 = 1767225600; + 117 days
        // = 1777334400; + 12*3600+54*60+56 = 46496; sum 1777380896)
        assert_eq!(utc_yyyymmddhhmmss(1_777_380_896), "20260428125456");
        // Leap-day boundary (2024 is a leap year): 2024-02-29T00:00:00Z = 1709164800
        assert_eq!(utc_yyyymmddhhmmss(1_709_164_800), "20240229000000");
        // 2024-03-01T00:00:00Z = 1709251200
        assert_eq!(utc_yyyymmddhhmmss(1_709_251_200), "20240301000000");
    }

    /// Standard well-formed timestamped name for tests.
    const VALID_NAME: &str = "bitwarden_encrypted-export_20260425000000.json";
    const VALID_NAME_MS: &str = "bitwarden_encrypted-export_20260425000000123.json";

    /// Minimal sync body with `profile.key` present so the
    /// recoverability gate doesn't fire — used by every test that
    /// is not specifically about the gate itself.
    const MIN_VALID_BODY: &str = r#"{"profile":{"key":"2.iv|data|mac"},"ciphers":[{"id":"a"}]}"#;

    #[test]
    fn write_forensic_happy_path() {
        let dir = scratch_vault_dir("happy");
        let path = dir.join(VALID_NAME);
        let body = r#"{"profile":{"key":"x"},"ciphers":[{"id":"a"},{"id":"b"}],"folders":[]}"#;

        let snap = write_forensic(&path, body).unwrap();

        assert_eq!(snap.cipher_count, 2);
        assert_eq!(snap.folder_count, 0);
        assert_eq!(snap.byte_count, body.len());
        assert_eq!(fs::read_to_string(&path).unwrap(), body);
        let _ = fs::remove_dir_all(dir.parent().unwrap());
    }

    #[test]
    fn write_forensic_accepts_millisecond_precision_filename() {
        let dir = scratch_vault_dir("happy-ms");
        let path = dir.join(VALID_NAME_MS);
        write_forensic(&path, MIN_VALID_BODY).unwrap();
        let _ = fs::remove_dir_all(dir.parent().unwrap());
    }

    #[test]
    #[cfg(unix)]
    fn write_forensic_sets_0o600_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch_vault_dir("perms");
        let path = dir.join(VALID_NAME);
        write_forensic(&path, MIN_VALID_BODY).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "snapshot must be owner-only");
        let _ = fs::remove_dir_all(dir.parent().unwrap());
    }

    #[test]
    fn write_forensic_refuses_non_vault_path() {
        let dir = std::env::temp_dir().join(format!(
            "bwd-snapshot-novault-{}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join(VALID_NAME);
        let body = r#"{"ciphers":[{"id":"a"}]}"#;
        let err = write_forensic(&path, body).unwrap_err();
        match err {
            SnapshotError::InvalidPath { reason, .. } => {
                assert!(reason.contains("`vault/`"), "got reason: {reason}");
            }
            other => panic!("expected InvalidPath, got {other:?}"),
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_forensic_refuses_dotdot_escape() {
        // Audit finding: `vault/../examples/foo.json` would have
        // passed the bare "any-component-named-vault" check.
        let parent = std::env::temp_dir().join(format!(
            "bwd-snapshot-dotdot-{}-{}",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
        ));
        fs::create_dir_all(parent.join("vault")).unwrap();
        fs::create_dir_all(parent.join("examples")).unwrap();
        // path component sequence: parent / vault / .. / examples / VALID_NAME
        let bad = parent.join("vault").join("..").join("examples").join(VALID_NAME);
        let err = write_forensic(&bad, r#"{"ciphers":[{"id":"a"}]}"#).unwrap_err();
        match err {
            SnapshotError::InvalidPath { reason, .. } => {
                assert!(reason.contains("`..`"), "got reason: {reason}");
            }
            other => panic!("expected InvalidPath for dotdot, got {other:?}"),
        }
        let _ = fs::remove_dir_all(&parent);
    }

    #[test]
    fn write_forensic_refuses_bad_filename_pattern() {
        let dir = scratch_vault_dir("badname");
        let bad_names = [
            "anything.json",
            "bitwarden_encrypted-export_.json",
            "bitwarden_encrypted-export_abc.json",
            "bitwarden_encrypted-export_2026.json",            // 4 digits
            "bitwarden_encrypted-export_2026042500000012.json", // 16 digits
            "bitwarden_decrypted-export_20260425000000.json", // wrong prefix
            "bitwarden_encrypted-export_20260425000000.txt",   // wrong ext
        ];
        for n in bad_names {
            let p = dir.join(n);
            let err = write_forensic(&p, r#"{"ciphers":[{"id":"a"}]}"#).unwrap_err();
            match err {
                SnapshotError::InvalidPath { reason, .. } => {
                    assert!(
                        reason.contains("filename"),
                        "expected filename rejection for {n}, got: {reason}"
                    );
                }
                other => panic!("expected InvalidPath for {n}, got {other:?}"),
            }
        }
        let _ = fs::remove_dir_all(dir.parent().unwrap());
    }

    #[test]
    fn write_forensic_refuses_existing_destination() {
        // Defense-in-depth on the ms-precision path: even if two
        // calls somehow collide, the second one must fail loudly
        // rather than silently clobbering the first.
        let dir = scratch_vault_dir("clobber");
        let path = dir.join(VALID_NAME);
        let v1 = r#"{"profile":{"key":"k1"},"ciphers":[{"id":"a"}]}"#;
        let v2 = r#"{"profile":{"key":"k2"},"ciphers":[{"id":"b"}]}"#;
        write_forensic(&path, v1).unwrap();
        // Same path, second call must fail.
        let err = write_forensic(&path, v2).unwrap_err();
        assert!(matches!(err, SnapshotError::DestinationExists(_)));
        // First file's content survives.
        let preserved = fs::read_to_string(&path).unwrap();
        assert!(preserved.contains(r#""id":"a""#));
        let _ = fs::remove_dir_all(dir.parent().unwrap());
    }

    #[test]
    fn write_forensic_refuses_unparseable_body() {
        let dir = scratch_vault_dir("nonjson");
        let path = dir.join(VALID_NAME);
        let err = write_forensic(&path, "not-json-at-all").unwrap_err();
        assert!(matches!(err, SnapshotError::NotJson { .. }));
        assert!(!path.exists(), "snapshot must not be written when body is non-JSON");
        let _ = fs::remove_dir_all(dir.parent().unwrap());
    }

    #[test]
    fn write_forensic_refuses_empty_ciphers() {
        let dir = scratch_vault_dir("empty");
        let path = dir.join(VALID_NAME);
        let body = r#"{"profile":{"key":"x"},"ciphers":[]}"#;
        let err = write_forensic(&path, body).unwrap_err();
        assert!(matches!(err, SnapshotError::NoCiphers));
        assert!(!path.exists());
        let _ = fs::remove_dir_all(dir.parent().unwrap());
    }

    #[test]
    fn write_forensic_refuses_missing_ciphers_field() {
        let dir = scratch_vault_dir("noctx");
        let path = dir.join(VALID_NAME);
        let err = write_forensic(&path, r#"{"profile":{"key":"x"}}"#).unwrap_err();
        assert!(matches!(err, SnapshotError::NoCiphers));
        let _ = fs::remove_dir_all(dir.parent().unwrap());
    }

    #[test]
    fn write_forensic_refuses_missing_profile_key() {
        // Recoverability gate: a snapshot without `profile.key` is
        // not decryptable in Phase 1b, so refusing here is more
        // useful than letting "backup complete" report success on a
        // useless file. (Audit finding 2026-04-25.)
        let dir = scratch_vault_dir("no-profile-key");
        let path = dir.join(VALID_NAME);
        let cases: &[(&str, &str)] = &[
            ("missing profile field", r#"{"ciphers":[{"id":"a"}]}"#),
            ("empty profile object", r#"{"profile":{},"ciphers":[{"id":"a"}]}"#),
            ("null profile.key", r#"{"profile":{"key":null},"ciphers":[{"id":"a"}]}"#),
            ("empty string profile.key", r#"{"profile":{"key":""},"ciphers":[{"id":"a"}]}"#),
        ];
        for (label, body) in cases {
            let err = write_forensic(&path, body).unwrap_err();
            assert!(
                matches!(err, SnapshotError::MissingProfileKey),
                "case `{label}` did not report MissingProfileKey, got: {err:?}"
            );
            assert!(!path.exists(), "no snapshot must be written when profile.key is missing");
        }
        let _ = fs::remove_dir_all(dir.parent().unwrap());
    }

    #[test]
    fn write_forensic_accepts_realistic_profile_key_shape() {
        // The check is "non-empty string"; we don't validate the
        // EncString format here — that's Phase 1b's job. Confirm
        // the realistic shape (type-2 encstring) passes.
        let dir = scratch_vault_dir("real-profile");
        let path = dir.join(VALID_NAME);
        let body = r#"{"profile":{"key":"2.iv-base64==|data-base64==|mac-base64=="},"ciphers":[{"id":"a"}]}"#;
        let snap = write_forensic(&path, body).unwrap();
        assert_eq!(snap.cipher_count, 1);
        let _ = fs::remove_dir_all(dir.parent().unwrap());
    }

    #[test]
    fn write_forensic_preserves_byte_for_byte() {
        let dir = scratch_vault_dir("byteforbyte");
        let path = dir.join(VALID_NAME);
        let weird = "{\n  \"ciphers\": [{ \"id\": \"a\" }],\n  \"profile\": { \"key\": \"x\" }\n}";
        write_forensic(&path, weird).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), weird);
        let _ = fs::remove_dir_all(dir.parent().unwrap());
    }

    #[test]
    fn write_forensic_counts_via_ignored_any_not_value() {
        // The performance fix replaces `serde_json::Value` parse
        // with an IgnoredAny-based count-only path. Validate the
        // count is correct on a body whose cipher elements have
        // structure too rich to round-trip cheaply through Value.
        let dir = scratch_vault_dir("ignoredany");
        let path = dir.join(VALID_NAME);
        let body = r#"{"profile":{"key":"x"},"ciphers":[
            {"id":"a","name":"long","fields":[{"k":"v"},{"k2":"v2"}]},
            {"id":"b","login":{"username":"u","password":"p","uris":[{"uri":"https://example.test"}]}},
            {"id":"c","secureNote":{"type":0}}
        ],"folders":[{"id":"f1"},{"id":"f2"}]}"#;
        let snap = write_forensic(&path, body).unwrap();
        assert_eq!(snap.cipher_count, 3);
        assert_eq!(snap.folder_count, 2);
        let _ = fs::remove_dir_all(dir.parent().unwrap());
    }

    #[test]
    fn validate_snapshot_path_accepts_nested_vault() {
        // Direct unit test for the validator separate from full
        // write path.
        let p = PathBuf::from("/x/y/vault/").join(VALID_NAME);
        assert!(validate_snapshot_path(&p).is_ok());
        let p = PathBuf::from("project/vault/sub/").join(VALID_NAME);
        assert!(validate_snapshot_path(&p).is_ok());
    }

    #[test]
    fn validate_snapshot_path_rejects_lookalike_dir_names() {
        // `vaults/` (plural) doesn't qualify.
        let p = PathBuf::from("vaults/").join(VALID_NAME);
        assert!(matches!(
            validate_snapshot_path(&p),
            Err(SnapshotError::InvalidPath { .. })
        ));
    }

    #[test]
    fn write_recoverable_happy_path() {
        let dir = scratch_vault_dir("rec-happy");
        let path = dir.join("bitwarden_decrypted-export_20260425000000.json");
        let body = serde_json::json!({
            "encrypted": false,
            "folders": [{"id": "f1", "name": "Inbox"}],
            "items": [
                {"id": "a", "type": 1, "name": "Site A"},
                {"id": "b", "type": 2, "name": "Note"},
            ],
        });
        let snap = write_recoverable(&path, &body).unwrap();
        assert_eq!(snap.item_count, 2);
        assert_eq!(snap.folder_count, 1);
        let on_disk = fs::read_to_string(&path).unwrap();
        assert!(on_disk.contains(r#""Site A""#));
        let _ = fs::remove_dir_all(dir.parent().unwrap());
    }

    #[test]
    #[cfg(unix)]
    fn write_recoverable_sets_0o600_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch_vault_dir("rec-perms");
        let path = dir.join("bitwarden_decrypted-export_20260425000000.json");
        let body = serde_json::json!({"items": [{"id": "a"}]});
        write_recoverable(&path, &body).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "decrypted snapshot is plaintext-sensitive — must be 0o600");
        let _ = fs::remove_dir_all(dir.parent().unwrap());
    }

    #[test]
    fn write_recoverable_refuses_empty_items() {
        let dir = scratch_vault_dir("rec-empty");
        let path = dir.join("bitwarden_decrypted-export_20260425000000.json");
        let body = serde_json::json!({"items": []});
        let err = write_recoverable(&path, &body).unwrap_err();
        assert!(matches!(err, SnapshotError::NoCiphers));
        assert!(!path.exists());
        let _ = fs::remove_dir_all(dir.parent().unwrap());
    }

    #[test]
    fn write_recoverable_refuses_wrong_filename_prefix() {
        // Forensic prefix would land in the dedup auto-discover
        // path with the wrong shape — refuse.
        let dir = scratch_vault_dir("rec-wrong-prefix");
        let path = dir.join("bitwarden_encrypted-export_20260425000000.json");
        let body = serde_json::json!({"items": [{"id": "a"}]});
        let err = write_recoverable(&path, &body).unwrap_err();
        assert!(matches!(err, SnapshotError::InvalidPath { .. }));
        let _ = fs::remove_dir_all(dir.parent().unwrap());
    }

    #[test]
    fn write_recoverable_refuses_existing_destination() {
        let dir = scratch_vault_dir("rec-clobber");
        let path = dir.join("bitwarden_decrypted-export_20260425000000.json");
        let body1 = serde_json::json!({"items": [{"id": "a"}]});
        let body2 = serde_json::json!({"items": [{"id": "b"}]});
        write_recoverable(&path, &body1).unwrap();
        let err = write_recoverable(&path, &body2).unwrap_err();
        assert!(matches!(err, SnapshotError::DestinationExists(_)));
        // Original survives.
        let preserved = fs::read_to_string(&path).unwrap();
        assert!(preserved.contains(r#""id": "a""#));
        let _ = fs::remove_dir_all(dir.parent().unwrap());
    }

    #[test]
    fn recoverable_filename_pattern_accepts_both_precisions() {
        // 14-digit and 17-digit (ms) timestamps both accepted.
        assert!(recoverable_filename_matches_pattern(
            "bitwarden_decrypted-export_20260425000000.json"
        ));
        assert!(recoverable_filename_matches_pattern(
            "bitwarden_decrypted-export_20260425000000123.json"
        ));
        // Wrong prefix: encrypted-export is the forensic snapshot.
        assert!(!recoverable_filename_matches_pattern(
            "bitwarden_encrypted-export_20260425000000.json"
        ));
        // `bw export`'s prefix is also rejected — those files exist
        // as a separate category that `just dedup` finds via its own
        // pattern set; this validator only writes our tool's output.
        assert!(!recoverable_filename_matches_pattern(
            "bitwarden_export_20260425000000.json"
        ));
        // Non-digit timestamp.
        assert!(!recoverable_filename_matches_pattern(
            "bitwarden_decrypted-export_abc.json"
        ));
    }

    #[test]
    fn filename_matches_pattern_unit() {
        assert!(filename_matches_pattern("bitwarden_encrypted-export_20260425000000.json"));
        assert!(filename_matches_pattern("bitwarden_encrypted-export_20260425000000123.json"));
        assert!(!filename_matches_pattern("bitwarden_encrypted-export_2026.json"));
        assert!(!filename_matches_pattern("anything.json"));
        assert!(!filename_matches_pattern(
            "bitwarden_encrypted-export_a0260425000000.json" // non-digit
        ));
    }
}
