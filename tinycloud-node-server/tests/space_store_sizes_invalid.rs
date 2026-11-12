use tinycloud::storage::file_system::FileSystemConfig;
use tinycloud_core::storage::{StorageConfig, StoreSize};
#[tokio::test]
async fn invalid_space_directory_does_not_abort_other_space_size_reconstruction() {
    let dir = tempfile::tempdir().unwrap();
    let owner = "pkh:eip155:1:0x1111111111111111111111111111111111111111";
    for name in ["Uppercase", "valid"] {
        let path = dir.path().join(owner).join(name);
        std::fs::create_dir_all(&path).unwrap();
        std::fs::write(path.join("data"), b"123").unwrap();
    }
    let store = FileSystemConfig::new(dir.path()).open().await.unwrap();
    let valid = format!("tinycloud:{owner}:valid").parse().unwrap();
    assert_eq!(store.total_size(&valid).await.unwrap(), Some(3));
}
