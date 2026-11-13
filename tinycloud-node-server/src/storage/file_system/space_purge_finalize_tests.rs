use super::*;

#[tokio::test]
async fn completion_removes_exact_directories_and_metering_after_empty_relist() {
    let root = tempfile::tempdir().unwrap();
    let store = FileSystemConfig::new(root.path()).open().await.unwrap();
    let a: SpaceId = "tinycloud:pkh:eip155:1:0x1111111111111111111111111111111111111111:files"
        .parse()
        .unwrap();
    let b: SpaceId =
        "tinycloud:pkh:eip155:1:0x1111111111111111111111111111111111111111:files-neighbor"
            .parse()
            .unwrap();
    let owner = root.path().join(a.suffix());
    let a_dir = owner.join(a.name().as_str());
    let b_dir = owner.join(b.name().as_str());
    for directory in [&a_dir, &b_dir] {
        tokio::fs::create_dir_all(directory).await.unwrap();
        tokio::fs::write(directory.join("value"), b"bytes")
            .await
            .unwrap();
    }
    store.sizes.init_size(a.clone()).await;
    store.sizes.init_size(b.clone()).await;
    store.sizes.increment_size(&a, 100).await;
    store.sizes.increment_size(&b, 200).await;
    let hash = tinycloud_core::hash::hash(b"reservation");
    store.pending.lock().await.insert((a.clone(), hash, 1), 10);
    store.pending.lock().await.insert((b.clone(), hash, 1), 20);
    store
        .boot_stages
        .lock()
        .await
        .insert(a_dir.join(".tc-stage-old"), 10);
    store
        .boot_stages
        .lock()
        .await
        .insert(b_dir.join(".tc-stage-old"), 20);
    drop(store.operations.lock((a.clone(), hash, 1)).await);
    drop(store.operations.lock((b.clone(), hash, 1)).await);
    assert!(!store.purge_space_batch(&a).await.unwrap());
    assert_eq!(store.sizes.get_size(&a).await, Some(100));
    assert!(store.purge_space_batch(&a).await.unwrap());
    assert!(!a_dir.exists());
    assert!(owner.exists());
    assert_eq!(
        tokio::fs::read(b_dir.join("value")).await.unwrap(),
        b"bytes"
    );
    assert_eq!(store.sizes.get_size(&a).await, None);
    assert_eq!(store.sizes.get_size(&b).await, Some(200));
    assert!(!store
        .pending
        .lock()
        .await
        .keys()
        .any(|(space, _, _)| space == &a));
    assert!(store
        .pending
        .lock()
        .await
        .keys()
        .any(|(space, _, _)| space == &b));
    assert!(!store
        .boot_stages
        .lock()
        .await
        .keys()
        .any(|path| path.starts_with(&a_dir)));
    assert!(store
        .boot_stages
        .lock()
        .await
        .keys()
        .any(|path| path.starts_with(&b_dir)));
    assert!(!store
        .operations
        .0
        .lock()
        .await
        .keys()
        .any(|(space, _, _)| space == &a));
    assert!(store.purge_space_batch(&a).await.unwrap());
    assert!(!store.purge_space_batch(&b).await.unwrap());
    assert!(store.purge_space_batch(&b).await.unwrap());
    assert!(!owner.exists());
    assert!(store.purge_space_batch(&b).await.unwrap());
}

#[cfg(unix)]
#[tokio::test]
async fn completion_refuses_symlink_space_and_keeps_metering() {
    use std::os::unix::fs::symlink;
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let store = FileSystemConfig::new(root.path()).open().await.unwrap();
    let space: SpaceId = "tinycloud:pkh:eip155:1:0x1111111111111111111111111111111111111111:files"
        .parse()
        .unwrap();
    let owner = root.path().join(space.suffix());
    tokio::fs::create_dir_all(&owner).await.unwrap();
    symlink(outside.path(), owner.join(space.name().as_str())).unwrap();
    tokio::fs::write(outside.path().join("keep"), b"outside")
        .await
        .unwrap();
    store.sizes.init_size(space.clone()).await;
    store.sizes.increment_size(&space, 10).await;
    assert!(store.purge_space_batch(&space).await.is_err());
    assert_eq!(store.sizes.get_size(&space).await, Some(10));
    assert_eq!(
        tokio::fs::read(outside.path().join("keep")).await.unwrap(),
        b"outside"
    );
}

#[tokio::test]
async fn sql_filesystem_completion_also_removes_exact_prefix_directory() {
    use crate::storage::sql_object::{purge::SqlPhysicalPrefix, FsSqlObjectStore};
    let root = tempfile::tempdir().unwrap();
    let blocks = root.path().join("blocks");
    tokio::fs::create_dir_all(&blocks).await.unwrap();
    let sql_root = root.path().join("sql-store");
    let store = FsSqlObjectStore::open(sql_root.clone(), &blocks).unwrap();
    let a: SpaceId = "tinycloud:pkh:eip155:1:0x1111111111111111111111111111111111111111:files"
        .parse()
        .unwrap();
    let b: SpaceId =
        "tinycloud:pkh:eip155:1:0x1111111111111111111111111111111111111111:files-neighbor"
            .parse()
            .unwrap();
    let target = SqlPhysicalPrefix::for_space(&a);
    let neighbor = SqlPhysicalPrefix::for_space(&b);
    let directory = sql_root.join(target.as_str());
    let adjacent = sql_root.join(neighbor.as_str());
    for path in [&directory, &adjacent] {
        tokio::fs::create_dir_all(path).await.unwrap();
        tokio::fs::write(path.join("checkpoint"), b"bytes")
            .await
            .unwrap();
    }
    assert!(!store.purge_prefix_batch(&target).await.unwrap());
    assert!(store.purge_prefix_batch(&target).await.unwrap());
    assert!(!directory.exists());
    assert_eq!(
        tokio::fs::read(adjacent.join("checkpoint")).await.unwrap(),
        b"bytes"
    );
    assert!(store.purge_prefix_batch(&target).await.unwrap());
}
