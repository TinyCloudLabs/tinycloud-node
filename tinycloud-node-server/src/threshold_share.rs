//! The startup guard for `encryption_network.threshold_share_dir` (TC-2224).
//!
//! A node configured with a threshold share directory is a threshold member.
//! Before serving, the member's process is made non-dumpable and the
//! directory must already exist with mode 0700, be owned by the process uid
//! and take an exclusive `std::fs::File::try_lock` on a probe file inside it.
//! Anything else refuses the start. With the setting unset the guard never
//! runs.

use std::{fs, path::Path, path::PathBuf};

/// One named case per refusal, so a start log can report `error_kind`.
#[derive(Debug, thiserror::Error)]
pub enum ThresholdShareDirError {
    #[error("threshold share directory {0} is missing or is not a directory")]
    Missing(PathBuf),
    #[error("threshold share directory {path} has mode {mode:o}; mode 700 is required")]
    Mode { path: PathBuf, mode: u32 },
    #[error(
        "threshold share directory {path} is owned by uid {owner}; the process uid is required"
    )]
    Owner { path: PathBuf, owner: u32 },
    #[error("threshold share directory {0} cannot be locked exclusively")]
    Lock(PathBuf),
    #[error("threshold share directory {path} could not be inspected: {error}")]
    Io {
        path: PathBuf,
        error: std::io::Error,
    },
    #[error("prctl(PR_SET_DUMPABLE, 0) failed: {0}")]
    Dumpable(std::io::Error),
    #[error("threshold share directories are only supported on unix")]
    Unsupported,
}

impl ThresholdShareDirError {
    /// A fixed name for logs and errors: it carries no path.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Missing(_) => "missing",
            Self::Mode { .. } => "mode",
            Self::Owner { .. } => "owner",
            Self::Lock(_) => "lock",
            Self::Io { .. } => "io",
            Self::Dumpable(_) => "dumpable",
            Self::Unsupported => "unsupported",
        }
    }
}

/// Applies the startup guard for a configured threshold share directory. It
/// marks the process non-dumpable first, then checks the directory.
#[cfg(unix)]
pub fn guard_threshold_share_dir(dir: &Path) -> Result<(), ThresholdShareDirError> {
    set_process_nondumpable()?;
    // SAFETY: `geteuid` reads a process attribute.
    guard_dir(dir, unsafe { libc::geteuid() })
}

#[cfg(not(unix))]
pub fn guard_threshold_share_dir(_dir: &Path) -> Result<(), ThresholdShareDirError> {
    Err(ThresholdShareDirError::Unsupported)
}

/// `PR_SET_DUMPABLE` exists only on Linux; the directory checks still apply
/// on other unix targets.
#[cfg(target_os = "linux")]
fn set_process_nondumpable() -> Result<(), ThresholdShareDirError> {
    // SAFETY: `prctl` with PR_SET_DUMPABLE writes no memory of ours.
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0) } != 0 {
        return Err(ThresholdShareDirError::Dumpable(
            std::io::Error::last_os_error(),
        ));
    }
    Ok(())
}

#[cfg(all(unix, not(target_os = "linux")))]
fn set_process_nondumpable() -> Result<(), ThresholdShareDirError> {
    Ok(())
}

/// The directory checks, with the expected owner passed so a test can
/// exercise the owner case without owning a foreign uid.
#[cfg(unix)]
fn guard_dir(dir: &Path, expected_owner: u32) -> Result<(), ThresholdShareDirError> {
    use std::os::unix::fs::MetadataExt;
    let missing = || ThresholdShareDirError::Missing(dir.to_path_buf());
    let metadata = match fs::metadata(dir) {
        Ok(metadata) => metadata,
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
            ) =>
        {
            return Err(missing());
        }
        Err(error) => {
            return Err(ThresholdShareDirError::Io {
                path: dir.to_path_buf(),
                error,
            });
        }
    };
    if !metadata.is_dir() {
        return Err(missing());
    }
    let mode = metadata.mode() & 0o7777;
    if mode != 0o700 {
        return Err(ThresholdShareDirError::Mode {
            path: dir.to_path_buf(),
            mode,
        });
    }
    let owner = metadata.uid();
    if owner != expected_owner {
        return Err(ThresholdShareDirError::Owner {
            path: dir.to_path_buf(),
            owner,
        });
    }
    let probe = dir.join(".tinycloud-threshold-probe");
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(false);
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = match options.open(&probe) {
        Ok(file) => file,
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
            ) =>
        {
            return Err(missing());
        }
        Err(error) => {
            return Err(ThresholdShareDirError::Io { path: probe, error });
        }
    };
    let locked = file.try_lock().is_ok();
    drop(file);
    let remove = fs::remove_file(&probe);
    if !locked {
        let _ = remove;
        return Err(ThresholdShareDirError::Lock(dir.to_path_buf()));
    }
    remove.map_err(|error| ThresholdShareDirError::Io { path: probe, error })
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::tempdir;

    fn share_dir() -> (tempfile::TempDir, PathBuf) {
        let tmp = tempdir().unwrap();
        let dir = tmp.path().join("threshold");
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        (tmp, dir)
    }

    fn process_uid() -> u32 {
        // SAFETY: `geteuid` reads a process attribute.
        unsafe { libc::geteuid() }
    }

    #[test]
    fn a_private_owned_lockable_dir_passes_and_the_probe_is_removed() {
        let (_tmp, dir) = share_dir();
        guard_dir(&dir, process_uid()).unwrap();
        assert!(fs::read_dir(&dir).unwrap().next().is_none());
    }

    #[test]
    fn a_missing_dir_is_refused() {
        let tmp = tempdir().unwrap();
        let error = guard_dir(&tmp.path().join("absent"), process_uid()).unwrap_err();
        assert_eq!(error.kind(), "missing");

        let file = tmp.path().join("a-file");
        fs::write(&file, b"x").unwrap();
        let error = guard_dir(&file, process_uid()).unwrap_err();
        assert_eq!(error.kind(), "missing");
    }

    #[test]
    fn a_dir_with_any_other_mode_is_refused() {
        let (_tmp, dir) = share_dir();
        for loose in [0o750, 0o770, 0o755, 0o777, 0o600] {
            fs::set_permissions(&dir, fs::Permissions::from_mode(loose)).unwrap();
            let error = guard_dir(&dir, process_uid()).unwrap_err();
            assert_eq!(error.kind(), "mode", "mode {loose:o}");
        }
    }

    #[test]
    fn a_foreign_owner_is_refused() {
        let (_tmp, dir) = share_dir();
        // A non-root process cannot chown the dir to a foreign uid, so the
        // expected owner is passed as a different value: the check itself is
        // exercised. As root the real foreign-owner case runs too.
        let error = guard_dir(&dir, process_uid() + 1).unwrap_err();
        assert_eq!(error.kind(), "owner");

        if process_uid() == 0 {
            let rc = unsafe {
                libc::chown(
                    std::ffi::CString::new(dir.to_str().unwrap())
                        .unwrap()
                        .as_ptr(),
                    12345,
                    12345,
                )
            };
            assert_eq!(rc, 0);
            let error = guard_dir(&dir, process_uid()).unwrap_err();
            assert_eq!(error.kind(), "owner");
        }
    }

    #[test]
    fn a_held_probe_lock_is_refused() {
        let (_tmp, dir) = share_dir();
        let probe = dir.join(".tinycloud-threshold-probe");
        let held = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(&probe)
            .unwrap();
        held.try_lock().unwrap();
        let error = guard_dir(&dir, process_uid()).unwrap_err();
        assert_eq!(error.kind(), "lock");
        drop(held);
    }

    /// `PR_SET_DUMPABLE` is process-wide, so the flag is read back in a child
    /// process that ran the whole guard, not in the shared test process.
    #[test]
    #[cfg(target_os = "linux")]
    fn the_guard_makes_the_process_nondumpable() {
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "threshold_share::tests::dumpable_child",
                "--nocapture",
            ])
            .env("THRESHOLD_SHARE_DUMPABLE_CHILD", "1")
            .status()
            .unwrap();
        assert!(status.success(), "child process check failed");
    }

    /// Body of the subprocess above; a no-op in the normal test run.
    #[test]
    #[cfg(target_os = "linux")]
    fn dumpable_child() {
        if std::env::var_os("THRESHOLD_SHARE_DUMPABLE_CHILD").is_none() {
            return;
        }
        let (_tmp, dir) = share_dir();
        guard_threshold_share_dir(&dir).unwrap();
        // SAFETY: `prctl` with PR_GET_DUMPABLE reads a process attribute.
        let dumpable = unsafe { libc::prctl(libc::PR_GET_DUMPABLE) };
        assert_eq!(dumpable, 0);
    }
}
