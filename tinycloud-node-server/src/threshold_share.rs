//! The startup guard for `encryption_network.threshold_share_dir` (TC-2224).
//!
//! A node configured with a threshold share directory is a threshold member.
//! Before serving, the member's process is made non-dumpable and the
//! directory must already exist with mode 0700, be owned by the process uid
//! and take an exclusive `std::fs::File::try_lock` on a lock probe inside it.
//! The probe is opened relative to an `O_DIRECTORY | O_NOFOLLOW` descriptor
//! of the directory, so a symlinked dir or probe is refused, and the lock is
//! held for the process lifetime so a second node on the same volume is
//! refused for as long as the first runs. With the setting unset the guard
//! never runs.

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
    #[error("threshold share directory {0} resolves through a symbolic link")]
    Symlink(PathBuf),
    #[error("threshold share directory {path} could not be inspected: {error}")]
    Io {
        path: PathBuf,
        error: std::io::Error,
    },
    #[error("prctl(PR_SET_DUMPABLE, 0) failed: {0}")]
    Dumpable(std::io::Error),
    #[error("threshold share directories are only supported on linux: refusing to start")]
    Unsupported,
    #[error("threshold share directory {0} is not an absolute path")]
    InvalidPath(PathBuf),
}

impl ThresholdShareDirError {
    /// A fixed name for logs and errors: it carries no path.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Missing(_) => "missing",
            Self::Mode { .. } => "mode",
            Self::Owner { .. } => "owner",
            Self::Lock(_) => "lock",
            Self::Symlink(_) => "symlink",
            Self::Io { .. } => "io",
            Self::Dumpable(_) => "dumpable",
            Self::Unsupported => "unsupported",
            Self::InvalidPath(_) => "invalid_path",
        }
    }
}

/// The share directory's exclusive lock, held while the node runs. Rocket
/// keeps it in managed state for the process lifetime; dropping it releases
/// the lock the same way process exit does.
#[derive(Debug)]
pub struct ThresholdShareGuard {
    _dir: fs::File,
    _lock: fs::File,
}

/// Marks the process non-dumpable so no core or ptrace read of memory can
/// carry a share out of it. This runs at the very top of startup, before the
/// database connects or migrates and long before routes exist; a member
/// spends its whole life non-dumpable. With `threshold_share_dir` unset it
/// is never called.
#[cfg(target_os = "linux")]
pub fn set_process_nondumpable() -> Result<(), ThresholdShareDirError> {
    // SAFETY: `prctl` with PR_SET_DUMPABLE writes no memory of ours.
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0) } != 0 {
        return Err(ThresholdShareDirError::Dumpable(
            std::io::Error::last_os_error(),
        ));
    }
    Ok(())
}

/// A member cannot start non-dumpable off Linux, so it refuses to start
/// there until an equivalent mandatory control exists.
#[cfg(not(target_os = "linux"))]
pub fn set_process_nondumpable() -> Result<(), ThresholdShareDirError> {
    Err(ThresholdShareDirError::Unsupported)
}

/// Checks and exclusively locks a configured threshold share directory; the
/// returned guard must outlive startup. `set_process_nondumpable` has
/// already run.
#[cfg(target_os = "linux")]
pub fn guard_threshold_share_dir(
    dir: &Path,
) -> Result<ThresholdShareGuard, ThresholdShareDirError> {
    // SAFETY: `geteuid` reads a process attribute.
    guard_dir(dir, unsafe { libc::geteuid() })
}

#[cfg(not(target_os = "linux"))]
pub fn guard_threshold_share_dir(
    _dir: &Path,
) -> Result<ThresholdShareGuard, ThresholdShareDirError> {
    Err(ThresholdShareDirError::Unsupported)
}

/// The lock probe, at the share dir root. The share store only reads and
/// writes `<dir>/<network-hash>/`, never the root, so it neither sweeps nor
/// refuses this dot-prefixed file.
#[cfg(target_os = "linux")]
const LOCK_PROBE_NAME: &str = ".tinycloud-threshold-lock";

/// Classify an open/stat error for `dir`. `O_NOFOLLOW` on a final symlink
/// fails as ELOOP for the probe but ENOTDIR for the `O_DIRECTORY` dir open,
/// which is also how a non-directory path fails: an `lstat` tells the two
/// apart. ENOENT means the directory is absent.
#[cfg(target_os = "linux")]
fn classify(dir: &Path, error: std::io::Error) -> ThresholdShareDirError {
    if error.raw_os_error() == Some(libc::ELOOP) {
        return ThresholdShareDirError::Symlink(dir.to_path_buf());
    }
    if error.kind() == std::io::ErrorKind::NotADirectory
        && fs::symlink_metadata(dir)
            .map(|meta| meta.file_type().is_symlink())
            .unwrap_or(false)
    {
        return ThresholdShareDirError::Symlink(dir.to_path_buf());
    }
    if matches!(
        error.kind(),
        std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
    ) {
        return ThresholdShareDirError::Missing(dir.to_path_buf());
    }
    ThresholdShareDirError::Io {
        path: dir.to_path_buf(),
        error,
    }
}

/// The directory checks, with the expected owner passed so a test can
/// exercise the owner case without owning a foreign uid. Everything is
/// resolved through the one `O_DIRECTORY | O_NOFOLLOW` descriptor opened
/// here, so a symlink swap of the dir or the probe cannot pass.
#[cfg(target_os = "linux")]
fn guard_dir(
    dir: &Path,
    expected_owner: u32,
) -> Result<ThresholdShareGuard, ThresholdShareDirError> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    if !dir.is_absolute() {
        return Err(ThresholdShareDirError::InvalidPath(dir.to_path_buf()));
    }
    let dir_file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(dir)
        .map_err(|error| classify(dir, error))?;
    let metadata = dir_file.metadata().map_err(|error| classify(dir, error))?;
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
    let lock = {
        use std::os::unix::io::{AsRawFd, FromRawFd};
        // SAFETY: the name is a static with no interior NUL.
        let name = std::ffi::CString::new(LOCK_PROBE_NAME).unwrap();
        // SAFETY: `dir_file` is a valid descriptor for the duration of the
        // call and the returned descriptor is owned by a File at once.
        let fd = unsafe {
            libc::openat(
                dir_file.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd < 0 {
            return Err(classify(dir, std::io::Error::last_os_error()));
        }
        unsafe { fs::File::from_raw_fd(fd) }
    };
    if lock.try_lock().is_err() {
        // Never unlink the probe here: it may belong to the holder. The
        // probe stays for the next start, which reuses it.
        return Err(ThresholdShareDirError::Lock(dir.to_path_buf()));
    }
    Ok(ThresholdShareGuard {
        _dir: dir_file,
        _lock: lock,
    })
}

#[cfg(all(test, target_os = "linux"))]
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
    fn a_private_owned_lockable_dir_passes_and_keeps_its_lock_probe() {
        let (_tmp, dir) = share_dir();
        let _guard = guard_dir(&dir, process_uid()).unwrap();
        assert!(dir.join(LOCK_PROBE_NAME).exists());
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
    fn a_relative_dir_is_refused() {
        let error = guard_dir(Path::new("relative/threshold"), process_uid()).unwrap_err();
        assert_eq!(error.kind(), "invalid_path");
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
    fn a_symlinked_dir_is_refused() {
        let (_tmp, dir) = share_dir();
        let tmp = tempdir().unwrap();
        let link = tmp.path().join("link");
        std::os::unix::fs::symlink(&dir, &link).unwrap();
        let error = guard_dir(&link, process_uid()).unwrap_err();
        assert_eq!(error.kind(), "symlink");
    }

    #[test]
    fn a_symlinked_lock_probe_is_refused() {
        let (_tmp, dir) = share_dir();
        let outside = tempdir().unwrap();
        let target = outside.path().join("elsewhere");
        fs::write(&target, b"x").unwrap();
        std::os::unix::fs::symlink(&target, dir.join(LOCK_PROBE_NAME)).unwrap();
        let error = guard_dir(&dir, process_uid()).unwrap_err();
        assert_eq!(error.kind(), "symlink");
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
    fn a_second_guard_is_refused_while_the_first_is_alive_and_the_probe_stays() {
        let (_tmp, dir) = share_dir();
        let first = guard_dir(&dir, process_uid()).unwrap();
        let error = guard_dir(&dir, process_uid()).unwrap_err();
        assert_eq!(error.kind(), "lock");
        // The probe was never unlinked: it belongs to the holder.
        assert!(dir.join(LOCK_PROBE_NAME).exists());
        drop(first);
        // With the first guard dropped its lock is released and a start
        // reuses the probe it left.
        let _second = guard_dir(&dir, process_uid()).unwrap();
        assert!(dir.join(LOCK_PROBE_NAME).exists());
    }

    /// `PR_SET_DUMPABLE` is process-wide, so the flag is read back in a
    /// child that ran the whole guard. The child prints a marker only after
    /// `PR_GET_DUMPABLE` reads 0; the parent asserts both, so the test cannot
    /// pass vacuously when the guard never ran.
    #[test]
    fn the_guard_makes_the_process_nondumpable() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "threshold_share::tests::dumpable_child",
                "--nocapture",
            ])
            .env("THRESHOLD_SHARE_DUMPABLE_CHILD", "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "child process check failed: {output:?}"
        );
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(
            stdout.contains("THRESHOLD_SHARE_NONDUMPABLE"),
            "child never reached the guard or the flag was nonzero: {stdout:?}"
        );
    }

    /// Body of the subprocess above; a no-op in the normal test run.
    #[test]
    fn dumpable_child() {
        if std::env::var_os("THRESHOLD_SHARE_DUMPABLE_CHILD").is_none() {
            return;
        }
        let (_tmp, dir) = share_dir();
        set_process_nondumpable().unwrap();
        let _guard = guard_threshold_share_dir(&dir).unwrap();
        // SAFETY: `prctl` with PR_GET_DUMPABLE reads a process attribute.
        if unsafe { libc::prctl(libc::PR_GET_DUMPABLE) } == 0 {
            println!("THRESHOLD_SHARE_NONDUMPABLE");
        }
    }
}

/// A configured member refuses to start on non-Linux targets: no mandatory
/// non-dumpable control exists there. This branch cannot compile on this
/// Linux host, so it is never run here; it compiles and runs where it
/// matters.
#[cfg(all(test, not(target_os = "linux")))]
mod tests {
    use super::*;

    #[test]
    fn a_member_is_refused_off_linux() {
        let dir = tempfile::tempdir().unwrap();
        let error = set_process_nondumpable().unwrap_err();
        assert_eq!(error.kind(), "unsupported");
        let error = guard_threshold_share_dir(dir.path()).unwrap_err();
        assert_eq!(error.kind(), "unsupported");
    }
}
