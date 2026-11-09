//! The one writer for private files (identity, TLS key, link state).
//!
//! A write creates a temp file in the destination directory with its final
//! permissions at creation time, writes and fsyncs it, renames it over the
//! destination, then fsyncs the directory. Readers see the old file or the
//! new file, never a truncated or partially written one, and the contents
//! are never visible with looser permissions than the final mode.

use anyhow::{Context, Result};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

/// Mode for private files.
pub const PRIVATE_FILE_MODE: u32 = 0o600;

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Atomically replace `path` with `contents`, created with mode `0600`.
pub fn write_private_file_atomic(path: &Path, contents: &[u8]) -> Result<()> {
    write_private_file_atomic_with(path, |file| file.write_all(contents))
}

/// Like [`write_private_file_atomic`], with the body supplied by `write`. If
/// `write` fails the destination is left untouched and the temp file removed.
pub fn write_private_file_atomic_with(
    path: &Path,
    write: impl FnOnce(&mut fs::File) -> std::io::Result<()>,
) -> Result<()> {
    let dir = parent_dir(path);
    let tmp = temp_path(dir, path);
    let result = (|| -> Result<()> {
        let mut file =
            create_private(&tmp).with_context(|| format!("failed to create {}", tmp.display()))?;
        write(&mut file).with_context(|| format!("failed to write {}", tmp.display()))?;
        file.sync_all()
            .with_context(|| format!("failed to sync {}", tmp.display()))?;
        drop(file);
        fs::rename(&tmp, path)
            .with_context(|| format!("failed to rename {} to {}", tmp.display(), path.display()))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
        return result;
    }
    sync_dir(dir)
}

/// fsync a directory so a rename or create inside it is durable.
#[cfg(unix)]
pub fn sync_dir(dir: &Path) -> Result<()> {
    fs::File::open(dir)
        .and_then(|d| d.sync_all())
        .with_context(|| format!("failed to sync directory {}", dir.display()))
}

#[cfg(not(unix))]
pub fn sync_dir(_dir: &Path) -> Result<()> {
    Ok(())
}

/// Unique sibling temp path (same directory, so the rename is atomic).
pub fn temp_path(dir: &Path, dest: &Path) -> PathBuf {
    let name = dest
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let n = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    dir.join(format!(".{name}.tmp-{}-{n}", std::process::id()))
}

fn parent_dir(path: &Path) -> &Path {
    match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    }
}

#[cfg(unix)]
fn create_private(path: &Path) -> std::io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(PRIVATE_FILE_MODE)
        .open(path)
}

#[cfg(not(unix))]
fn create_private(path: &Path) -> std::io::Result<fs::File> {
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::tempdir;

    fn mode(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    fn entries(dir: &Path) -> Vec<String> {
        let mut v: Vec<_> = fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        v.sort();
        v
    }

    #[test]
    fn new_file_is_0600_and_no_temp_remains() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("secret");
        write_private_file_atomic(&path, b"v1").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"v1");
        assert_eq!(mode(&path), 0o600);
        assert_eq!(entries(tmp.path()), vec!["secret"]);
    }

    #[test]
    fn replacing_a_loose_file_ends_0600() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("secret");
        fs::write(&path, b"old").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        write_private_file_atomic(&path, b"new").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"new");
        assert_eq!(mode(&path), 0o600);
    }

    #[test]
    fn temp_file_has_final_mode_while_being_written() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("secret");
        let dir = tmp.path().to_path_buf();
        write_private_file_atomic_with(&path, |file| {
            file.write_all(b"partial")?;
            let temps: Vec<_> = entries(&dir);
            assert_eq!(temps.len(), 1);
            assert_eq!(mode(&dir.join(&temps[0])), 0o600);
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn interrupted_write_keeps_previous_contents_and_leaves_no_temp() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("secret");
        write_private_file_atomic(&path, b"previous").unwrap();

        let err = write_private_file_atomic_with(&path, |file| {
            file.write_all(b"half of the new")?;
            Err(std::io::Error::other("interrupted"))
        });
        assert!(err.is_err());
        assert_eq!(fs::read(&path).unwrap(), b"previous");
        assert_eq!(entries(tmp.path()), vec!["secret"]);
    }

    #[test]
    fn interrupted_first_write_creates_no_destination() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("secret");
        let err =
            write_private_file_atomic_with(&path, |_| Err(std::io::Error::other("interrupted")));
        assert!(err.is_err());
        assert!(entries(tmp.path()).is_empty());
    }
}
