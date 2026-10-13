//! TC-899: a write that commits on another SQLite connection while a graph
//! transaction sits between its first read and its first write must not
//! invalidate that transaction's snapshot (SQLITE_BUSY_SNAPSHOT, code 517,
//! which busy_timeout cannot retry and the node returns as HTTP 500).
//!
//! Every case opens the graph transaction through the production
//! `SpaceDatabase::begin_graph_transaction`, on the production pool
//! (`sqlite_connect_options`). The ungated competitors are built without the
//! writer gate on purpose: they prove the transaction defends itself whatever
//! else writes the file. The gated ones prove the in-process gate still
//! serializes.

use super::*;
use tinycloud_core::database_artifacts::{ArtifactExpectation, DatabaseArtifactRepository};
use tinycloud_core::models::{actor, epoch, signed_kv_ticket, space};
use tinycloud_core::sea_orm::{
    error::{DbErr, RuntimeErr, SqlxError},
    ActiveModelTrait, Database, DatabaseTransaction, PaginatorTrait, TransactionTrait,
};
use tinycloud_core::storage::{either::Either, StorageConfig};
use tinycloud_core::types::SpaceIdWrap;

const SPACE: &str = "tinycloud:pkh:eip155:1:0x00000000000000000000000000000000000c0899:default";

/// Long enough for an uncontended autocommit write to finish on a slow CI
/// host, well under the pool's 5 s busy_timeout.
const WINDOW: std::time::Duration = std::time::Duration::from_secs(1);

#[derive(Clone, Copy, Debug)]
enum Competitor {
    UngatedReplayInsert,
    UngatedReplayCleanup,
    UngatedArtifactSave,
    /// `SpaceDatabase::create_signed_kv_ticket`, ungated in production.
    SignedKvTicket,
    /// A second pool on the same file, standing in for another process.
    IndependentPool,
    GatedReplayInsert,
    GatedArtifactSave,
}

#[derive(Clone, Copy, Debug)]
enum Begin {
    /// Production: `begin_graph_transaction`.
    Graph,
    /// A plain deferred `BEGIN`; the control that shows the hazard is live.
    PlainDeferred,
}

fn sqlite_code(error: &DbErr) -> Option<String> {
    match error {
        DbErr::Exec(RuntimeErr::SqlxError(SqlxError::Database(e)))
        | DbErr::Query(RuntimeErr::SqlxError(SqlxError::Database(e))) => {
            e.code().map(|c| c.to_string())
        }
        _ => None,
    }
}

fn ticket(id: &str) -> signed_kv_ticket::Model {
    signed_kv_ticket::Model {
        id: id.to_owned(),
        issuer_did: "did:key:tc899".into(),
        subject_did: "did:key:tc899".into(),
        space_id: SPACE.into(),
        path: "seed".into(),
        service: "kv".into(),
        ability: "tinycloud.kv/get".into(),
        created_at: "2026-10-11T00:00:00Z".into(),
        expires_at: "2099-01-01T00:00:00Z".into(),
        invocation_expires_at: None,
        parent_expires_at: None,
        content_hash: None,
        etag: None,
        parent_cids_json: None,
    }
}

/// Opens a graph transaction, reads, lets `competitor` run, then writes the
/// epoch row. Returns the epoch insert result and whether the competitor
/// committed between the read and the write.
async fn race(competitor: Competitor, begin: Begin) -> (Result<(), DbErr>, bool) {
    let directory = tempfile::tempdir().unwrap();
    let url = format!(
        "sqlite:{}?mode=rwc",
        directory.path().join("caps.db").display()
    );
    let connection = Database::connect(crate::sqlite_connect_options(&url))
        .await
        .unwrap();
    let storage =
        crate::storage::file_system::FileSystemConfig::new(directory.path().join("blocks"))
            .open()
            .await
            .unwrap();
    let node = crate::TinyCloud::new(
        connection.into(),
        Either::B(storage),
        tinycloud_core::keys::StaticSecret::new(vec![7u8; 64]).unwrap(),
    )
    .await
    .unwrap();
    let (replay, artifacts): (InvocationReplayCache, Box<dyn DatabaseArtifactRepository>) =
        match competitor {
            Competitor::GatedReplayInsert | Competitor::GatedArtifactSave => (
                crate::node_replay_cache(&node),
                Box::new(crate::node_artifact_repository(&node)),
            ),
            _ => (
                InvocationReplayCache::new(node.connection().clone()),
                Box::new(
                    tinycloud_core::database_artifacts::SeaOrmDatabaseArtifactRepository::new(
                        node.connection().clone(),
                    ),
                ),
            ),
        };
    let other_pool = Database::connect(crate::sqlite_connect_options(&url))
        .await
        .unwrap();

    let space_id: tinycloud_auth::resource::SpaceId = SPACE.parse().unwrap();
    space::ActiveModel {
        id: Set(SpaceIdWrap(space_id.clone())),
    }
    .insert(node.connection())
    .await
    .unwrap();
    // One expired row so the cleanup really deletes something.
    replay
        .check_and_insert_key(
            hash(b"tc899-expired"),
            OffsetDateTime::now_utc() - Duration::seconds(1),
        )
        .await
        .unwrap();

    // As in `SpaceDatabase::transact`: writer gate, BEGIN, read, epoch INSERT.
    let gate = node.sqlite_writer_lock().unwrap();
    let writer = gate.lock().await;
    let tx: DatabaseTransaction = match begin {
        Begin::Graph => node.begin_graph_transaction().await.unwrap(),
        Begin::PlainDeferred => node.connection().begin().await.unwrap(),
    };
    let seen = epoch::Entity::find().count(&tx).await.unwrap() as i64;

    let competing_node = node.clone();
    let mut competing = tokio::spawn(async move {
        match competitor {
            Competitor::UngatedReplayInsert | Competitor::GatedReplayInsert => replay
                .check_and_insert_key(
                    hash(b"tc899-concurrent"),
                    OffsetDateTime::now_utc() + Duration::seconds(60),
                )
                .await
                .map(|()| 1u64)
                .map_err(|e| e.to_string()),
            Competitor::UngatedReplayCleanup => replay
                .cleanup(OffsetDateTime::now_utc(), 300)
                .await
                .map_err(|e| e.to_string()),
            Competitor::UngatedArtifactSave | Competitor::GatedArtifactSave => artifacts
                .save(
                    "sql",
                    SPACE,
                    "account",
                    b"tc899 artifact bytes".to_vec(),
                    ArtifactExpectation::Absent,
                )
                .await
                .map(|_| 1u64)
                .map_err(|e| e.to_string()),
            Competitor::SignedKvTicket => competing_node
                .create_signed_kv_ticket(ticket("tc899-ticket"))
                .await
                .map(|_| 1u64)
                .map_err(|e| e.to_string()),
            Competitor::IndependentPool => actor::ActiveModel {
                id: Set("did:key:tc899-other-process".to_owned()),
            }
            .insert(&other_pool)
            .await
            .map(|_| 1u64)
            .map_err(|e| e.to_string()),
        }
    });
    let early = tokio::time::timeout(WINDOW, &mut competing).await.ok();
    let committed_inside_window = early.is_some();

    let epoch_insert = epoch::Entity::insert(epoch::ActiveModel {
        seq: Set(seen),
        id: Set(hash(b"tc899-epoch")),
        space: Set(SpaceIdWrap(space_id)),
    })
    .exec(&tx)
    .await
    .map(|_| ());
    if epoch_insert.is_ok() {
        tx.commit().await.unwrap();
    } else {
        drop(tx);
    }
    drop(writer);
    let competed = match early {
        Some(result) => result,
        None => competing.await,
    };
    assert_eq!(competed.unwrap().unwrap(), 1, "{competitor:?}");
    (epoch_insert, committed_inside_window)
}

async fn graph_transaction_survives(competitor: Competitor) {
    let (epoch_insert, committed_inside_window) = race(competitor, Begin::Graph).await;
    if let Err(error) = &epoch_insert {
        panic!(
            "{competitor:?} invalidated the graph transaction's snapshot: sqlite code {:?}: {error}",
            sqlite_code(error)
        );
    }
    assert!(
        !committed_inside_window,
        "{competitor:?} must wait until the graph transaction commits"
    );
}

macro_rules! survives {
    ($name:ident, $competitor:expr) => {
        #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
        async fn $name() {
            graph_transaction_survives($competitor).await;
        }
    };
}

survives!(
    ungated_replay_insert_cannot_invalidate_graph_snapshot,
    Competitor::UngatedReplayInsert
);
survives!(
    ungated_replay_cleanup_cannot_invalidate_graph_snapshot,
    Competitor::UngatedReplayCleanup
);
survives!(
    ungated_artifact_save_cannot_invalidate_graph_snapshot,
    Competitor::UngatedArtifactSave
);
survives!(
    signed_kv_ticket_cannot_invalidate_graph_snapshot,
    Competitor::SignedKvTicket
);
survives!(
    independent_connection_pool_cannot_invalidate_graph_snapshot,
    Competitor::IndependentPool
);
survives!(
    gated_replay_insert_waits_for_writer_gate,
    Competitor::GatedReplayInsert
);
survives!(
    gated_artifact_save_waits_for_writer_gate,
    Competitor::GatedArtifactSave
);

/// Control: the harness still detects the hazard, so the cases above cannot
/// pass vacuously after a pool or journal-mode change.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn deferred_begin_is_still_exposed_to_snapshot_invalidation() {
    let (epoch_insert, committed_inside_window) =
        race(Competitor::SignedKvTicket, Begin::PlainDeferred).await;
    assert!(committed_inside_window);
    let error = epoch_insert.expect_err("a deferred transaction keeps its stale snapshot");
    assert_eq!(sqlite_code(&error).as_deref(), Some("517"), "{error}");
}
