use std::{
    io,
    path::{Component, Path},
};

/// Remove the entire exact-space cache, including unregistered crash remnants.
/// The caller has closed every actor and holds the exclusive space lifetime guard.
pub(crate) async fn remove_directory(base: &str, space: &str) -> io::Result<()> {
    let mut components = Path::new(space).components();
    if space.contains('\\')
        || !matches!(components.next(), Some(Component::Normal(_)))
        || components.next().is_some()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid space cache component",
        ));
    }
    let path = Path::new(base).join(space);
    match tokio::fs::symlink_metadata(&path).await {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
        Ok(metadata) if !metadata.is_dir() || metadata.file_type().is_symlink() => {
            return Err(io::Error::other("invalid space cache directory"))
        }
        Ok(_) => {}
    }
    tokio::fs::remove_dir_all(path).await
}
