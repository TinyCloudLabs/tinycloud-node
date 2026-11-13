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

/// Inventory only canonical space directories, refusing ambiguous filesystem state.
pub(crate) async fn inventory(
    base: &str,
    targets: Vec<String>,
) -> io::Result<Vec<tinycloud_auth::resource::SpaceId>> {
    let mut names: std::collections::BTreeSet<String> = targets.into_iter().collect();
    // Reject symlink ancestors as well as a symlink cache root.
    let mut ancestor = std::path::PathBuf::new();
    for component in Path::new(base).components() {
        ancestor.push(component);
        match tokio::fs::symlink_metadata(&ancestor).await {
            Ok(meta) if meta.file_type().is_symlink() || !meta.is_dir() => {
                return Err(io::Error::other("invalid cache root"));
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => break,
            Err(error) => return Err(error),
        }
    }
    match tokio::fs::read_dir(base).await {
        Ok(mut entries) => {
            while let Some(entry) = entries.next_entry().await? {
                let meta = tokio::fs::symlink_metadata(entry.path()).await?;
                if meta.file_type().is_symlink() || !meta.is_dir() {
                    return Err(io::Error::other("invalid cache entry"));
                }
                names.insert(
                    entry
                        .file_name()
                        .into_string()
                        .map_err(|_| io::Error::other("invalid cache name"))?,
                );
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    names
        .into_iter()
        .map(|name| {
            let space: tinycloud_auth::resource::SpaceId = name
                .parse()
                .map_err(|_| io::Error::other("invalid cache space"))?;
            if space.to_string() != name || name.contains(['/', '\\']) {
                return Err(io::Error::other("noncanonical cache space"));
            }
            Ok(space)
        })
        .collect()
}

#[cfg(test)]
mod restore_inventory_tests {
    use super::*;

    #[tokio::test]
    async fn inventory_preserves_memory_only_targets_and_refuses_ambiguous_disk() {
        let root = tempfile::tempdir().unwrap();
        let disk = "tinycloud:key:test:disk";
        let detached = "tinycloud:key:test:detached";
        tokio::fs::create_dir(root.path().join(disk)).await.unwrap();
        let spaces = inventory(root.path().to_str().unwrap(), vec![detached.into()])
            .await
            .unwrap();
        assert_eq!(spaces.len(), 2);
        assert!(spaces.iter().any(|space| space.to_string() == detached));
        assert!(root.path().join(disk).exists());
        tokio::fs::create_dir(root.path().join("malformed"))
            .await
            .unwrap();
        assert!(inventory(root.path().to_str().unwrap(), vec![])
            .await
            .is_err());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn inventory_refuses_symlink_root_and_space() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let link = root.path().join("tinycloud:key:test:linked");
        std::os::unix::fs::symlink(outside.path(), &link).unwrap();
        assert!(inventory(root.path().to_str().unwrap(), vec![])
            .await
            .is_err());
        assert!(inventory(link.to_str().unwrap(), vec![]).await.is_err());
        assert!(outside.path().exists());
    }
}
