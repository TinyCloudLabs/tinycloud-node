//! TC-887: KV writes through `SpaceDatabase` into a FileSystem block store in
//! `encrypt` mode, with a real at-rest keyring on SQLite (data keys in the
//! database, their copies in the key mirror). Covers what the app-level
//! tests in `at_rest_fs_node.rs` cover, without needing every seal path to
//! boot the app in `encrypt`.

use std::{
    path::{Path as FsPath, PathBuf},
    sync::{Arc, OnceLock},
    time::Duration,
};

use anyhow::{ensure, Context, Result};
use futures::io::{AsyncReadExt, AsyncWriteExt};
use tinycloud::storage::{
    at_rest_mirror::FsKeyMirror,
    file_system::{FileSystemConfig, FileSystemStore},
    sealed::AtRestHandle,
};
use tinycloud_at_rest_escrow::RecipientPolicy;
use tinycloud_auth::resource::{Path, SpaceId};
use tinycloud_core::{
    at_rest::{
        AtRestKeyring, AtRestMode, AtRestSource, AtRestStore, AtRestView, DataKeyProvider,
        KeyringConfig,
    },
    keys::StaticSecret,
    sea_orm::{ActiveModelTrait, ConnectionTrait, Database, DbBackend, Set, Statement},
    storage::{memory::MemoryStaging, ByteRangeSpec, HashBuffer, RangeRead, StorageConfig},
    types::{Metadata, SpaceIdWrap},
    RecoveringConnection, SpaceDatabase, TxError, TxStoreError,
};

const MARKER: &[u8] = b"TC887-FS-STORE-MARKER";
const ROOT: [u8; 32] = [77; 32];

type Db = SpaceDatabase<RecoveringConnection, FileSystemStore, StaticSecret>;

/// `encrypt` with the gate open, once the keyring is installed.
#[derive(Default)]
struct Encrypting(OnceLock<Arc<AtRestKeyring>>);

impl AtRestSource for Encrypting {
    fn view(&self) -> AtRestView {
        match self.0.get() {
            Some(keyring) => AtRestView {
                mode: AtRestMode::Encrypt,
                encrypting: true,
                provider: Some(keyring.clone() as Arc<dyn DataKeyProvider>),
            },
            None => AtRestView::off(),
        }
    }
}

struct Node {
    db: Db,
    conn: RecoveringConnection,
}

/// A node as the app wires one: block store attached to the at-rest state
/// before the database takes it, keyring installed after migrations.
async fn node(dir: &FsPath) -> Result<Node> {
    let url = format!("sqlite://{}?mode=rwc", dir.join("caps.db").display());
    let conn = RecoveringConnection::new(Database::connect(url).await?);
    tinycloud_core::db::migrate(&conn).await?;
    let mut store = FileSystemConfig::new(dir.join("blocks")).open().await?;
    let source = Arc::new(Encrypting::default());
    store.attach_at_rest(AtRestHandle::new(source.clone()));
    let secret = StaticSecret::new(vec![5; 32]).map_err(|_| anyhow::anyhow!("node secret"))?;
    let db = SpaceDatabase::new(conn.clone(), store, secret).await?;
    let keyring = AtRestKeyring::open(
        AtRestStore::new(conn.clone()).with_sqlite_writer_lock(db.sqlite_writer_lock()),
        Arc::new(FsKeyMirror::new(dir.join("at-rest"))),
        &ROOT,
        KeyringConfig {
            provision: true,
            holders: Vec::new(),
            recipient_policy: RecipientPolicy::HardwareOnly,
            pinned_efp: None,
            app_id: None,
            compose_hash: None,
            require_mirror: true,
            allow_resplit_before_verify: false,
        },
    )
    .await?;
    assert!(source.0.set(Arc::new(keyring)).is_ok());
    Ok(Node { db, conn })
}

fn space(name: &str) -> SpaceId {
    format!("tinycloud:key:atrestfs:{name}").parse().unwrap()
}

/// Hosts `space` and seeds its size entry, as hosting and boot do.
async fn host(node: &Node, space: &SpaceId) -> Result<()> {
    tinycloud_core::models::space::ActiveModel {
        id: Set(SpaceIdWrap(space.clone())),
    }
    .insert(&node.conn)
    .await?;
    node.db.seed_store_sizes().await?;
    Ok(())
}

async fn try_put(
    node: &Node,
    space: &SpaceId,
    path: &str,
    value: &[u8],
) -> Result<(), TxStoreError<FileSystemStore, MemoryStaging, StaticSecret>> {
    let mut stage = HashBuffer::new(Vec::new());
    stage.write_all(value).await.unwrap();
    // A first put in a new space creates its data key: before the SQLite
    // writer lock, or this would wait on the lock it holds.
    tokio::time::timeout(
        Duration::from_secs(30),
        node.db.invoke_internal_kv_put::<MemoryStaging>(
            space.clone(),
            path.parse().unwrap(),
            Metadata(Default::default()),
            stage,
            None,
        ),
    )
    .await
    .expect("a KV put must not hang on the writer lock")
    .map(|_| ())
}

async fn put(node: &Node, space: &SpaceId, path: &str, value: &[u8]) -> Result<()> {
    try_put(node, space, path, value)
        .await
        .map_err(|e| anyhow::anyhow!("put {path}: {e}"))
}

async fn get(node: &Node, space: &SpaceId, path: &str) -> Result<Option<Vec<u8>>> {
    let path: Path = path.parse()?;
    let Some((_, _, content)) = node.db.kv_get(space, &path).await? else {
        return Ok(None);
    };
    let mut out = Vec::new();
    Box::pin(content).read_to_end(&mut out).await?;
    Ok(Some(out))
}

async fn data_key_rows(node: &Node) -> Result<i64> {
    let row = node
        .conn
        .query_one(Statement::from_string(
            DbBackend::Sqlite,
            "SELECT COUNT(*) AS n FROM space_data_key",
        ))
        .await?
        .context("count row")?;
    Ok(row.try_get("", "n")?)
}

async fn forget_data_keys(node: &Node) -> Result<()> {
    node.conn
        .execute(Statement::from_string(
            DbBackend::Sqlite,
            "DELETE FROM space_data_key",
        ))
        .await?;
    Ok(())
}

fn files(root: &FsPath) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else {
                out.push(path);
            }
        }
    }
    out.sort();
    out
}

/// Three 64 KiB segments and a bit, with the marker at the start.
fn big_value() -> Vec<u8> {
    let mut v: Vec<u8> = (0..200_000).map(|i| (i % 251) as u8).collect();
    v[..MARKER.len()].copy_from_slice(MARKER);
    v
}

#[tokio::test]
async fn an_encrypting_store_holds_only_tce1_under_sealed_names() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let node = node(dir.path()).await?;
    let s = space("sealed");
    host(&node, &s).await?;
    let (short, big) = ([MARKER, b" short"].concat(), big_value());
    put(&node, &s, "notes/short", &short).await?;
    put(&node, &s, "notes/big", &big).await?;

    let blocks = dir.path().join("blocks");
    let stored = files(&blocks);
    ensure!(stored.len() == 2, "{stored:?}");
    for file in &stored {
        let rel = file.strip_prefix(&blocks)?.to_string_lossy().into_owned();
        ensure!(rel.starts_with("v1/") && !rel.contains('@'), "{rel}");
        ensure!(!rel.contains("atrestfs"), "the name leaks the space: {rel}");
        let raw = std::fs::read(file)?;
        ensure!(raw.starts_with(b"TCE1"), "{rel} is not TCE1");
        ensure!(
            !raw.windows(MARKER.len()).any(|w| w == MARKER),
            "plaintext in {rel}"
        );
    }
    ensure!(get(&node, &s, "notes/short").await? == Some(short.clone()));
    ensure!(get(&node, &s, "notes/big").await? == Some(big.clone()));
    let range = node
        .db
        .kv_get_range(
            &s,
            &"notes/big".parse()?,
            ByteRangeSpec::Inclusive {
                start: 65_530,
                end: 131_080,
            },
        )
        .await?
        .context("range")?;
    let RangeRead::Content {
        total_size,
        content,
        ..
    } = range.2
    else {
        anyhow::bail!("range unsatisfiable");
    };
    ensure!(total_size == big.len() as u64, "plaintext total");
    let mut out = Vec::new();
    Box::pin(content).read_to_end(&mut out).await?;
    ensure!(out == big[65_530..=131_080], "range bytes");
    ensure!(node.db.store_size(&s).await? == Some((short.len() + big.len()) as u64));
    ensure!(data_key_rows(&node).await? == 1);
    Ok(())
}

/// A put the node refuses (a space it does not host) is refused before any
/// key work: no data key row and no key mirror object.
#[tokio::test]
async fn a_refused_put_creates_no_data_key_or_mirror_object() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let node = node(dir.path()).await?;
    let mirror = dir.path().join("at-rest");
    let (rows, mirrored) = (data_key_rows(&node).await?, files(&mirror));
    for n in 0..3 {
        let refused = try_put(&node, &space(&format!("never-hosted-{n}")), "x", b"value").await;
        ensure!(
            matches!(refused, Err(TxStoreError::Tx(TxError::SpaceNotFound))),
            "{:?}",
            refused.map_err(|e| e.to_string())
        );
    }
    ensure!(
        data_key_rows(&node).await? == rows,
        "a refused put made a key"
    );
    ensure!(files(&mirror) == mirrored, "a refused put wrote the mirror");
    ensure!(files(&dir.path().join("blocks")).is_empty());
    Ok(())
}

/// The database lost the space's data-key row (restored from before it); the
/// mirror still has it. A read restores it on first use. A protected legacy
/// write, which uploads under the writer lock, finds it restored before the
/// lock instead of failing with "not prepared" (or waiting on its own lock).
#[tokio::test]
async fn a_lost_data_key_row_is_restored_before_the_writer_lock() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let s = space("restore");
    let value = big_value();
    {
        let node = node(dir.path()).await?;
        host(&node, &s).await?;
        put(&node, &s, "notes/big", &value).await?;
        forget_data_keys(&node).await?;
    }
    {
        let node = node(dir.path()).await?;
        ensure!(data_key_rows(&node).await? == 0);
        ensure!(get(&node, &s, "notes/big").await? == Some(value.clone()));
        ensure!(data_key_rows(&node).await? == 1, "a read restores the key");
        forget_data_keys(&node).await?;
    }
    let node = node(dir.path()).await?;
    put(
        &node,
        &s,
        "xyz.tinycloud.tinychat/connectors/fireflies/transcript/restored",
        b"protected",
    )
    .await?;
    ensure!(data_key_rows(&node).await? == 1, "the key is put back");
    ensure!(get(&node, &s, "notes/big").await? == Some(value));
    Ok(())
}
