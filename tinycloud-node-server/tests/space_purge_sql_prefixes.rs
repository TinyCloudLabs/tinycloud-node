use std::path::Path;
use tinycloud::storage::{
    s3::S3BlockConfig,
    sql_object::{purge::SqlPhysicalPrefix, FsSqlObjectStore, S3SqlObjectStore, WriteMode},
};
use tinycloud_core::storage::StorageConfig;

fn prefix(byte: u8) -> SqlPhysicalPrefix {
    SqlPhysicalPrefix::parse(&format!("sql/v1/~{}/", format!("{byte:02x}").repeat(32))).unwrap()
}
fn directory(root: &Path, prefix: &SqlPhysicalPrefix) -> std::path::PathBuf {
    root.join(prefix.as_str().trim_end_matches('/'))
}

#[test]
fn exact_sql_prefix_rejects_broad_reserved_and_noncanonical_scope() {
    for invalid in [
        "sql/",
        "sql/v1/",
        "sql/v1/_probe/",
        "_purge-ledger/",
        "sql/v1/../",
        "sql/v1/~aa/",
        "sql/v1/~AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/",
        "sql/v1/a/b/",
    ] {
        assert!(SqlPhysicalPrefix::parse(invalid).is_err(), "{invalid}");
    }
    assert_eq!(
        SqlPhysicalPrefix::parse(prefix(1).as_str()).unwrap(),
        prefix(1)
    );
}

#[tokio::test]
async fn filesystem_hashed_prefix_resumes_and_preserves_neighbor_and_ledger() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("sql-store");
    let blocks = temp.path().join("blocks");
    std::fs::create_dir_all(&blocks).unwrap();
    let store = FsSqlObjectStore::open(root.clone(), &blocks).unwrap();
    let a = prefix(1);
    let b = prefix(2);
    let a_dir = directory(&root, &a).join("database/lineage/snap");
    std::fs::create_dir_all(&a_dir).unwrap();
    for n in 0..300 {
        std::fs::write(a_dir.join(format!("{n}")), b"bytes").unwrap();
    }
    let b_dir = directory(&root, &b);
    std::fs::create_dir_all(&b_dir).unwrap();
    std::fs::write(b_dir.join("keep"), b"neighbor").unwrap();
    std::fs::create_dir_all(root.join("_purge-ledger")).unwrap();
    std::fs::write(root.join("_purge-ledger/keep"), b"ledger").unwrap();
    let page = store.list_purge_prefixes(None).await.unwrap();
    assert_eq!(page.prefixes, vec![a.clone(), b.clone()]);
    assert!(!store.purge_prefix_batch(&a).await.unwrap());
    assert!(std::fs::read_dir(&a_dir).unwrap().next().is_some());
    drop(store);
    let resumed = FsSqlObjectStore::open(root.clone(), &blocks).unwrap();
    for pass in 0..10 {
        if resumed.purge_prefix_batch(&a).await.unwrap() {
            break;
        }
        assert!(pass < 9, "purge did not converge");
    }
    assert!(resumed.purge_prefix_batch(&a).await.unwrap());
    assert_eq!(std::fs::read(b_dir.join("keep")).unwrap(), b"neighbor");
    assert_eq!(
        std::fs::read(root.join("_purge-ledger/keep")).unwrap(),
        b"ledger"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn filesystem_prefix_refuses_symlink_ancestors_and_unlinks_leaf_links() {
    use std::os::unix::fs::symlink;
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("sql-store");
    let blocks = temp.path().join("blocks");
    std::fs::create_dir_all(&blocks).unwrap();
    let store = FsSqlObjectStore::open(root.clone(), &blocks).unwrap();
    let a = prefix(3);
    let target = directory(&root, &a);
    let outside = temp.path().join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(outside.join("keep"), b"outside").unwrap();
    std::fs::create_dir_all(target.parent().unwrap()).unwrap();
    symlink(&outside, &target).unwrap();
    assert!(store.purge_prefix_batch(&a).await.is_err());
    assert!(store.list_purge_prefixes(None).await.is_err());
    std::fs::remove_file(&target).unwrap();
    std::fs::create_dir_all(&target).unwrap();
    symlink(&outside, target.join("link")).unwrap();
    assert!(!store.purge_prefix_batch(&a).await.unwrap());
    assert!(store.purge_prefix_batch(&a).await.unwrap());
    assert_eq!(std::fs::read(outside.join("keep")).unwrap(), b"outside");
}

#[tokio::test]
async fn minio_hashed_prefix_relists_after_restart_and_preserves_neighbor() {
    let Ok(endpoint) = std::env::var("TC735_TEST_MINIO_ENDPOINT") else {
        return;
    };
    let bucket = std::env::var("TC735_TEST_MINIO_BUCKET").unwrap();
    let blocks = S3BlockConfig {
        bucket: bucket.clone(),
        endpoint: Some(endpoint.parse().unwrap()),
    }
    .open()
    .await
    .unwrap();
    let a = SqlPhysicalPrefix::parse(&format!(
        "sql/v1/~{}/",
        hex::encode(rand::random::<[u8; 32]>())
    ))
    .unwrap();
    let b = SqlPhysicalPrefix::parse(&format!(
        "sql/v1/~{}/",
        hex::encode(rand::random::<[u8; 32]>())
    ))
    .unwrap();
    let neighbor = format!("{}keep", b.as_str());
    blocks
        .client
        .put_object()
        .bucket(&bucket)
        .key(&neighbor)
        .body(b"neighbor".to_vec().into())
        .send()
        .await
        .unwrap();
    for n in 0..260 {
        blocks
            .client
            .put_object()
            .bucket(&bucket)
            .key(format!("{}{n}", a.as_str()))
            .body(b"bytes".to_vec().into())
            .send()
            .await
            .unwrap();
    }
    let store = S3SqlObjectStore::new(
        blocks.client.clone(),
        bucket.clone(),
        WriteMode::Conditional,
    );
    assert!(!store.purge_prefix_batch(&a).await.unwrap());
    drop(store);
    let resumed = S3SqlObjectStore::new(
        blocks.client.clone(),
        bucket.clone(),
        WriteMode::Conditional,
    );
    assert!(!resumed.purge_prefix_batch(&a).await.unwrap());
    assert!(resumed.purge_prefix_batch(&a).await.unwrap());
    assert!(resumed
        .list_purge_prefixes(None)
        .await
        .unwrap()
        .prefixes
        .contains(&b));
    assert_eq!(
        blocks
            .client
            .get_object()
            .bucket(&bucket)
            .key(&neighbor)
            .send()
            .await
            .unwrap()
            .body
            .collect()
            .await
            .unwrap()
            .into_bytes()
            .as_ref(),
        b"neighbor"
    );
    assert!(!resumed.purge_prefix_batch(&b).await.unwrap());
    assert!(resumed.purge_prefix_batch(&b).await.unwrap());
}

#[tokio::test]
async fn filesystem_prefix_inventory_pages_without_reversing_hashed_identity() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("sql-store");
    let blocks = temp.path().join("blocks");
    std::fs::create_dir_all(&blocks).unwrap();
    let store = FsSqlObjectStore::open(root.clone(), &blocks).unwrap();
    for n in 0..257 {
        std::fs::create_dir_all(root.join(format!("sql/v1/~{n:064x}"))).unwrap();
    }
    let first = store.list_purge_prefixes(None).await.unwrap();
    assert_eq!(first.prefixes.len(), 256);
    let cursor = first.next_cursor.unwrap();
    let second = store.list_purge_prefixes(Some(&cursor)).await.unwrap();
    assert_eq!(second.prefixes.len(), 1);
    assert!(second.next_cursor.is_none());
    assert!(first.prefixes.last().unwrap() < second.prefixes.first().unwrap());
}

#[tokio::test]
async fn filesystem_kv_inventory_returns_exact_relative_prefix_and_skips_reserved_ledger() {
    use tinycloud::storage::file_system::FileSystemConfig;
    let temp = tempfile::tempdir().unwrap();
    let store = FileSystemConfig::new(temp.path()).open().await.unwrap();
    let space = "tinycloud:pkh:eip155:1:0x1111111111111111111111111111111111111111:files"
        .parse::<tinycloud_auth::resource::SpaceId>()
        .unwrap();
    let relative = format!("{}/{}/", space.suffix(), space.name());
    std::fs::create_dir_all(temp.path().join(&relative)).unwrap();
    std::fs::create_dir_all(temp.path().join("_purge-ledger/owners/key")).unwrap();
    std::fs::write(
        temp.path().join("_purge-ledger/owners/key/opaque"),
        b"ledger",
    )
    .unwrap();
    let page = store.list_purge_prefixes(None).await.unwrap();
    assert_eq!(page.prefixes.len(), 1);
    assert_eq!(page.prefixes[0].space, space);
    assert_eq!(page.prefixes[0].prefix, relative);
    assert!(page.next_cursor.is_none());
    assert!(store
        .list_purge_prefixes(Some(&relative))
        .await
        .unwrap()
        .prefixes
        .is_empty());
}
