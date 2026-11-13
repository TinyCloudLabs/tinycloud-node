use super::*;
use crate::storage::purge_ledger::{validate_key, PurgeLedgerStore, PREFIX};

fn checked_parent(root: &Path, key: &str, create: bool) -> Result<PathBuf, IoError> {
    validate_key(key)?;
    let mut current = root.to_owned();
    let parts: Vec<_> = key.split('/').collect();
    for part in &parts[..parts.len() - 1] {
        current.push(part);
        if create {
            match std::fs::create_dir(&current) {
                Ok(()) => {
                    std::fs::File::open(current.parent().unwrap())?.sync_all()?;
                }
                Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error),
            }
        }
        let metadata = std::fs::symlink_metadata(&current)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(IoError::other("invalid ledger directory"));
        }
    }
    Ok(current)
}

#[rocket::async_trait]
impl PurgeLedgerStore for FileSystemStore {
    async fn append_purge_record(&self, key: &str, body: &[u8]) -> Result<(), IoError> {
        validate_key(key)?;
        let root = self.path.clone();
        let key = key.to_owned();
        let body = body.to_vec();
        tokio::task::spawn_blocking(move || {
            use std::io::Write;
            let parent = checked_parent(&root, &key, true)?;
            let destination = root.join(&key);
            let mut temporary = NamedTempFile::new_in(&parent)?;
            temporary.write_all(&body)?;
            temporary.as_file().sync_all()?;
            match temporary.persist_noclobber(&destination) {
                Ok(_) => {}
                Err(error) if error.error.kind() == ErrorKind::AlreadyExists => {
                    let metadata = std::fs::symlink_metadata(&destination)?;
                    if !metadata.is_file() || metadata.file_type().is_symlink() {
                        return Err(IoError::other("invalid ledger record"));
                    }
                    if std::fs::read(&destination)? != body {
                        return Err(IoError::new(
                            ErrorKind::AlreadyExists,
                            "ledger record already exists",
                        ));
                    }
                }
                Err(error) => return Err(error.error),
            }
            std::fs::File::open(parent)?.sync_all()?;
            Ok(())
        })
        .await
        .map_err(IoError::other)?
    }

    async fn read_purge_record(&self, key: &str) -> Result<Option<Vec<u8>>, IoError> {
        validate_key(key)?;
        let root = self.path.clone();
        let key = key.to_owned();
        tokio::task::spawn_blocking(move || {
            match checked_parent(&root, &key, false) {
                Ok(_) => {}
                Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
                Err(error) => return Err(error),
            }
            let path = root.join(&key);
            match std::fs::symlink_metadata(&path) {
                Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
                Err(error) => Err(error),
                Ok(metadata) if !metadata.is_file() || metadata.file_type().is_symlink() => {
                    Err(IoError::other("invalid ledger record"))
                }
                Ok(_) => Ok(Some(std::fs::read(path)?)),
            }
        })
        .await
        .map_err(IoError::other)?
    }

    async fn list_purge_records(&self) -> Result<Vec<String>, IoError> {
        let root = self.path.clone();
        tokio::task::spawn_blocking(move || {
            let mut pending = vec![root.join(PREFIX)];
            let mut entries = Vec::new();
            while let Some(directory) = pending.pop() {
                let metadata = match std::fs::symlink_metadata(&directory) {
                    Err(error)
                        if error.kind() == ErrorKind::NotFound
                            && directory == root.join(PREFIX) =>
                    {
                        return Ok(entries)
                    }
                    other => other?,
                };
                if !metadata.is_dir() || metadata.file_type().is_symlink() {
                    return Err(IoError::other("invalid ledger directory"));
                }
                for object in std::fs::read_dir(directory)? {
                    let object = object?;
                    if object.file_name().to_string_lossy().starts_with(".tmp") {
                        continue;
                    }
                    let path = object.path();
                    let key = path
                        .strip_prefix(&root)
                        .map_err(IoError::other)?
                        .to_str()
                        .ok_or_else(|| IoError::other("invalid ledger path"))?
                        .to_owned();
                    validate_key(&key)?;
                    let kind = object.file_type()?;
                    if kind.is_dir() {
                        pending.push(path);
                    } else if kind.is_file() {
                        entries.push(key);
                    } else {
                        return Err(IoError::other("invalid ledger entry"));
                    }
                }
            }
            Ok(entries)
        })
        .await
        .map_err(IoError::other)?
    }
}
