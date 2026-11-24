use super::*;

#[tokio::test]
async fn empty_probe_is_read_only_and_rejects_symlinked_owner() {
    let root = tempfile::tempdir().unwrap();
    let store = FileSystemStore::new(root.path().to_owned()).await.unwrap();
    let space: SpaceId = "tinycloud:key:test:probe".parse().unwrap();
    assert!(store.space_is_empty(&space).await.unwrap());
    assert!(!root.path().join(space.suffix()).exists());
    let directory = root.path().join(space.suffix()).join(space.name().as_str());
    tokio::fs::create_dir_all(&directory).await.unwrap();
    tokio::fs::write(directory.join("keep"), b"kept")
        .await
        .unwrap();
    assert!(!store.space_is_empty(&space).await.unwrap());
    assert_eq!(
        tokio::fs::read(directory.join("keep")).await.unwrap(),
        b"kept"
    );
    assert!(!store.purge_space_batch(&space).await.unwrap());
    assert!(store.space_is_empty(&space).await.unwrap());
    #[cfg(unix)]
    {
        let outside = tempfile::tempdir().unwrap();
        tokio::fs::remove_dir_all(root.path().join(space.suffix()))
            .await
            .unwrap();
        std::os::unix::fs::symlink(outside.path(), root.path().join(space.suffix())).unwrap();
        assert!(store.space_is_empty(&space).await.is_err());
    }
}
