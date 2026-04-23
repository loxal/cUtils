// Copyright 2026 Alexander Orlov <alexander.orlov@loxal.net>

//! Small I/O helpers shared across the binaries.
//!
//! All vault-derived artifacts — dedup output, audit JSON, redacted
//! replica — are written via [`write_sensitive_atomic`] so:
//!
//! 1. **Permissions are owner-only** on Unix (mode `0o600`) even when a
//!    looser file already exists at the target path.
//! 2. **Writes are atomic**: content lands in a temp file first, then
//!    `rename()` swaps it over the destination. A crash, disk-full
//!    condition, or interrupted write cannot leave a partially-populated
//!    file visible at the destination path — at worst, a stray
//!    `.tmp-…` sidecar remains in the same directory for the operator
//!    to delete.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process;

/// Write `content` to `path` atomically with owner-only permissions on
/// Unix. Uses a temp file in the same directory + `rename()` so the
/// destination never exists in a partially-written state.
///
/// On non-Unix platforms the atomicity guarantee is the same; the
/// permission step reduces to whatever `fs::rename` / `fs::write`
/// provides (typically process umask).
pub fn write_sensitive_atomic(path: &Path, content: &str) -> io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    if !parent.as_os_str().is_empty() {
        fs::create_dir_all(parent)?;
    }
    let tmp = tmp_sibling(path);

    // Best-effort cleanup hook in case we bail before the rename.
    let cleanup = Cleanup {
        path: tmp.clone(),
        armed: true,
    };

    write_tmp_with_permissions(&tmp, content)?;
    fs::rename(&tmp, path)?;
    // Some filesystems clear the tightened mode on rename; re-apply.
    enforce_owner_only(path)?;
    cleanup.disarm();
    Ok(())
}

#[cfg(unix)]
fn write_tmp_with_permissions(tmp: &Path, content: &str) -> io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(tmp)?;
    file.write_all(content.as_bytes())?;
    file.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn write_tmp_with_permissions(tmp: &Path, content: &str) -> io::Result<()> {
    use std::io::Write;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(tmp)?;
    file.write_all(content.as_bytes())?;
    file.sync_all()?;
    Ok(())
}

#[cfg(unix)]
fn enforce_owner_only(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn enforce_owner_only(_path: &Path) -> io::Result<()> {
    Ok(())
}

fn tmp_sibling(path: &Path) -> PathBuf {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "out".to_string());
    let pid = process::id();
    // Nanosecond-since-epoch gives uniqueness across rapid-fire writes in
    // the same process without needing a random number generator.
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    parent.join(format!(".{name}.tmp-{pid}-{nanos}"))
}

/// Deletes `path` on drop unless disarmed. Used to clean up the temp
/// sidecar when [`write_sensitive_atomic`] bails before `rename`.
struct Cleanup {
    path: PathBuf,
    armed: bool,
}

impl Cleanup {
    fn disarm(mut self) {
        self.armed = false;
    }
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        if self.armed {
            let _ = fs::remove_file(&self.path);
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn tmp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("bwd-io-{}-{name}", process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn atomic_write_creates_file_with_0o600() {
        let dir = tmp_dir("basic");
        let path = dir.join("out.json");
        write_sensitive_atomic(&path, "{}").unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(fs::read_to_string(&path).unwrap(), "{}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn atomic_write_tightens_existing_loose_file() {
        let dir = tmp_dir("loose");
        let path = dir.join("preexisting.json");
        fs::write(&path, "old").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        write_sensitive_atomic(&path, "new").unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "mode must be tightened on rewrite");
        assert_eq!(fs::read_to_string(&path).unwrap(), "new");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn atomic_write_leaves_no_tmp_sidecar_after_success() {
        let dir = tmp_dir("notemp");
        let path = dir.join("result.json");
        write_sensitive_atomic(&path, "ok").unwrap();
        let leftovers: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp-"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "atomic write must remove its tmp sidecar after rename; leftovers: {leftovers:?}"
        );
        let _ = fs::remove_dir_all(&dir);
    }
}
