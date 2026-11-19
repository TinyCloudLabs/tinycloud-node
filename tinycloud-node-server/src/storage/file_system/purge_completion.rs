use super::*;

impl FileSystemStore {
    /// Caller holds the exclusive space drain. Completion requires the exact
    /// space path to be gone; an owner with other spaces is preserved.
    pub(super) async fn finish_empty_space(&self, space: &SpaceId) -> Result<bool, IoError> {
        if let Some(directory) = self.purge_directory(space).await? {
            match tokio::fs::remove_dir(&directory).await {
                Ok(()) => {}
                Err(error) if error.kind() == ErrorKind::NotFound => {}
                Err(error) if error.kind() == ErrorKind::DirectoryNotEmpty => return Ok(false),
                Err(error) => return Err(error),
            }
        }
        let owner = self.path.join(space.suffix());
        match tokio::fs::symlink_metadata(&owner).await {
            Ok(metadata) if !metadata.is_dir() || metadata.file_type().is_symlink() => {
                return Err(IoError::new(
                    ErrorKind::InvalidData,
                    "invalid owner directory",
                ));
            }
            Ok(_) => match tokio::fs::remove_dir(&owner).await {
                Ok(()) => {}
                Err(error)
                    if matches!(
                        error.kind(),
                        ErrorKind::NotFound | ErrorKind::DirectoryNotEmpty
                    ) => {}
                Err(error) => return Err(error),
            },
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let directory = owner.join(space.name().as_str());
        self.pending
            .lock()
            .await
            .retain(|(candidate, _, _), _| candidate != space);
        self.boot_stages
            .lock()
            .await
            .retain(|path, _| !path.starts_with(&directory));
        self.operations.forget_space(space).await;
        self.sizes.forget_space(space).await;
        Ok(true)
    }
}
