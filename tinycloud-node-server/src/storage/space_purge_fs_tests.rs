use super::*;

#[tokio::test]
async fn purge_batches_restart_and_preserve_neighbour() {
    let root = tempfile::tempdir().unwrap();
    let space: SpaceId = "tinycloud:key:test:purge".parse().unwrap();
    let neighbour: SpaceId = "tinycloud:key:test:purge-other".parse().unwrap();
    let target = root.path().join(space.suffix()).join(space.name().as_str());
    let adjacent = root
        .path()
        .join(neighbour.suffix())
        .join(neighbour.name().as_str());
    tokio::fs::create_dir_all(&target).await.unwrap();
    tokio::fs::create_dir_all(&adjacent).await.unwrap();
    tokio::fs::write(adjacent.join("keep"), b"data")
        .await
        .unwrap();
    for index in 0..300 {
        tokio::fs::write(target.join(format!("object-{index}")), b"data")
            .await
            .unwrap();
    }
    let store = FileSystemStore::new(root.path().to_owned()).await.unwrap();
    assert!(!store.purge_space_batch(&space).await.unwrap());
    drop(store);
    // Restart reconstructs the store and resumes by listing remaining objects.
    let store = FileSystemStore::new(root.path().to_owned()).await.unwrap();
    assert!(!store.purge_space_batch(&space).await.unwrap());
    assert!(store.purge_space_batch(&space).await.unwrap());
    assert!(store.purge_space_batch(&space).await.unwrap());
    assert_eq!(
        tokio::fs::read(adjacent.join("keep")).await.unwrap(),
        b"data"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn purge_refuses_symlinked_owner_directory() {
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let space: SpaceId = "tinycloud:key:test:purge".parse().unwrap();
    let target = outside.path().join(space.name().as_str());
    tokio::fs::create_dir_all(&target).await.unwrap();
    tokio::fs::write(target.join("keep"), b"keep")
        .await
        .unwrap();
    let store = FileSystemStore::new(root.path().to_owned()).await.unwrap();
    std::os::unix::fs::symlink(outside.path(), root.path().join(space.suffix())).unwrap();
    assert!(store.purge_space_batch(&space).await.is_err());
    assert_eq!(tokio::fs::read(target.join("keep")).await.unwrap(), b"keep");
}

#[tokio::test]
async fn purge_retries_after_io_failure_and_relists_late_objects() {
    let root = tempfile::tempdir().unwrap();
    let space: SpaceId = "tinycloud:key:test:purge".parse().unwrap();
    let target = root.path().join(space.suffix()).join(space.name().as_str());
    tokio::fs::create_dir_all(target.join("unexpected-directory"))
        .await
        .unwrap();
    let store = FileSystemStore::new(root.path().to_owned()).await.unwrap();
    assert!(store.purge_space_batch(&space).await.is_err());
    tokio::fs::remove_dir(target.join("unexpected-directory"))
        .await
        .unwrap();
    tokio::fs::write(target.join("late"), b"data")
        .await
        .unwrap();
    assert!(!store.purge_space_batch(&space).await.unwrap());
    assert!(store.purge_space_batch(&space).await.unwrap());
}
