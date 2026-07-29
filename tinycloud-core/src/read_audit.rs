//! Durable audit journal for successful authenticated reads.
//!
//! Read requests must not enter the mutation transaction merely to record that
//! they happened. They authorize and read on ordinary database connections,
//! then wait for this pipeline to commit their immutable invocation record
//! before the response is acknowledged. Concurrent records are drained into
//! one transaction. Mutations and audit batches share the same writer lock.

use crate::{
    encryption::{maybe_encrypt, ColumnEncryption},
    events::Invocation,
    hash::Hash,
    models::{actor, invocation},
    relationships::{invoked_abilities, parent_delegations},
    types::{Ability, Resource},
};
use sea_orm::{
    sea_query::OnConflict, ActiveValue::Set, ConnectionTrait, DatabaseConnection, DbErr,
    EntityTrait, TransactionTrait,
};
use std::collections::HashSet;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use time::OffsetDateTime;
use tokio::sync::{mpsc, oneshot, Mutex};

const CHANNEL_CAPACITY: usize = 1024;
const MAX_BATCH_SIZE: usize = 64;

#[derive(Debug)]
struct ReadAuditRecord {
    id: Hash,
    invoker: String,
    issued_at: OffsetDateTime,
    serialization: Vec<u8>,
    abilities: Vec<(Resource, Ability)>,
    parents: Vec<Hash>,
}

impl ReadAuditRecord {
    fn from_invocation(invocation: &Invocation, encryption: Option<&ColumnEncryption>) -> Self {
        Self {
            id: invocation.content_hash(),
            invoker: invocation.0.invoker.clone(),
            issued_at: OffsetDateTime::now_utc(),
            serialization: maybe_encrypt(encryption, invocation.serialized_bytes()),
            abilities: invocation
                .0
                .capabilities
                .iter()
                .map(|capability| (capability.resource.clone(), capability.ability.clone()))
                .collect(),
            parents: invocation
                .0
                .parents
                .iter()
                .copied()
                .map(Hash::from)
                .collect(),
        }
    }
}

struct Command {
    record: ReadAuditRecord,
    committed: oneshot::Sender<Result<(), String>>,
}

#[derive(Debug, Default)]
struct PipelineStats {
    records: AtomicU64,
    batches: AtomicU64,
}

#[derive(Clone, Debug)]
pub(crate) struct ReadAuditPipeline {
    sender: mpsc::Sender<Command>,
    stats: Arc<PipelineStats>,
}

impl ReadAuditPipeline {
    pub(crate) fn start(conn: DatabaseConnection, writer_lock: Option<Arc<Mutex<()>>>) -> Self {
        let (sender, receiver) = mpsc::channel(CHANNEL_CAPACITY);
        let stats = Arc::new(PipelineStats::default());
        tokio::spawn(run_pipeline(conn, writer_lock, receiver, stats.clone()));
        Self { sender, stats }
    }

    pub(crate) async fn record(
        &self,
        invocation: &Invocation,
        encryption: Option<&ColumnEncryption>,
    ) -> Result<(), DbErr> {
        self.enqueue(ReadAuditRecord::from_invocation(invocation, encryption))
            .await
    }

    async fn enqueue(&self, record: ReadAuditRecord) -> Result<(), DbErr> {
        let (committed, receipt) = oneshot::channel();
        self.sender
            .send(Command { record, committed })
            .await
            .map_err(|_| DbErr::Custom("read audit pipeline stopped".to_string()))?;
        receipt
            .await
            .map_err(|_| DbErr::Custom("read audit pipeline dropped commit receipt".to_string()))?
            .map_err(DbErr::Custom)
    }

    pub(crate) fn stats(&self) -> (u64, u64) {
        (
            self.stats.records.load(Ordering::Relaxed),
            self.stats.batches.load(Ordering::Relaxed),
        )
    }
}

async fn run_pipeline(
    conn: DatabaseConnection,
    writer_lock: Option<Arc<Mutex<()>>>,
    mut receiver: mpsc::Receiver<Command>,
    stats: Arc<PipelineStats>,
) {
    while let Some(first) = receiver.recv().await {
        let mut batch = vec![first];
        tokio::task::yield_now().await;
        while batch.len() < MAX_BATCH_SIZE {
            match receiver.try_recv() {
                Ok(command) => batch.push(command),
                Err(_) => break,
            }
        }

        let _writer = match &writer_lock {
            Some(lock) => Some(lock.lock().await),
            None => None,
        };
        let result = persist_batch(&conn, &batch)
            .await
            .map_err(|error| error.to_string());
        if result.is_ok() {
            stats
                .records
                .fetch_add(batch.len() as u64, Ordering::Relaxed);
            stats.batches.fetch_add(1, Ordering::Relaxed);
        }
        for command in batch {
            let _ = command.committed.send(result.clone());
        }
    }
}

async fn persist_batch(conn: &DatabaseConnection, batch: &[Command]) -> Result<(), DbErr> {
    let tx = conn.begin().await?;
    persist_records(&tx, batch).await?;
    tx.commit().await
}

/// Persist an entire drained batch with a constant number of statements — at
/// most one `insert_many` per table — instead of the previous ~4 statements
/// per record.
///
/// Every VALUES list is deduplicated by its `ON CONFLICT` target before it is
/// sent. This is mandatory once rows are batched: some backends (notably
/// Postgres) reject a single `INSERT ... ON CONFLICT` whose VALUES contain the
/// same conflict key twice, and a saturated batch can legitimately carry a
/// repeated invoker (many reads by one principal) or even a repeated
/// invocation (identical concurrent reads share a content hash). The old
/// per-record path never hit this because each row was its own statement.
///
/// Everything that the per-record path guaranteed is preserved: the same
/// `ON CONFLICT DO NOTHING` targets, the already-encrypted `serialization`
/// bytes carried verbatim from each record, and — because inserts stay
/// conflict-idempotent — identical final table contents and no-op re-persists.
async fn persist_records<C: ConnectionTrait>(db: &C, batch: &[Command]) -> Result<(), DbErr> {
    // Collapse repeated invocations (identical concurrent reads hash to the
    // same id) to their first occurrence so every downstream VALUES list is
    // duplicate-free at the invocation level.
    let mut seen_invocations = HashSet::new();
    let records: Vec<&ReadAuditRecord> = batch
        .iter()
        .map(|command| &command.record)
        .filter(|record| seen_invocations.insert(record.id))
        .collect();

    if records.is_empty() {
        return Ok(());
    }

    // 1. Actors — one row per distinct invoker.
    let mut seen_actors = HashSet::new();
    let actors: Vec<actor::ActiveModel> = records
        .iter()
        .filter(|record| seen_actors.insert(record.invoker.as_str()))
        .map(|record| actor::ActiveModel {
            id: Set(record.invoker.clone()),
        })
        .collect();
    if !actors.is_empty() {
        ignore_record_not_inserted(
            actor::Entity::insert_many(actors)
                .on_conflict(
                    OnConflict::column(actor::Column::Id)
                        .do_nothing()
                        .to_owned(),
                )
                .exec(db)
                .await,
        )?;
    }

    // 2. Invocations — one row per distinct invocation (records already deduped).
    let invocations: Vec<invocation::ActiveModel> = records
        .iter()
        .map(|record| invocation::ActiveModel {
            id: Set(record.id),
            invoker: Set(record.invoker.clone()),
            issued_at: Set(record.issued_at),
            facts: Set(None),
            serialization: Set(record.serialization.clone()),
        })
        .collect();
    ignore_record_not_inserted(
        invocation::Entity::insert_many(invocations)
            .on_conflict(
                OnConflict::column(invocation::Column::Id)
                    .do_nothing()
                    .to_owned(),
            )
            .exec(db)
            .await,
    )?;

    // 3. Invoked abilities — every (invocation, resource, ability) across the
    //    batch, deduplicated by the full primary key.
    let mut seen_abilities = HashSet::new();
    let abilities: Vec<invoked_abilities::ActiveModel> = records
        .iter()
        .flat_map(|record| {
            let invocation = record.id;
            record
                .abilities
                .iter()
                .map(move |(resource, ability)| (invocation, resource.clone(), ability.clone()))
        })
        .filter(|(invocation, resource, ability)| {
            seen_abilities.insert((*invocation, resource.clone(), ability.clone()))
        })
        .map(
            |(invocation, resource, ability)| invoked_abilities::ActiveModel {
                invocation: Set(invocation),
                resource: Set(resource),
                ability: Set(ability),
            },
        )
        .collect();
    if !abilities.is_empty() {
        ignore_record_not_inserted(
            invoked_abilities::Entity::insert_many(abilities)
                .on_conflict(
                    OnConflict::columns([
                        invoked_abilities::Column::Invocation,
                        invoked_abilities::Column::Resource,
                        invoked_abilities::Column::Ability,
                    ])
                    .do_nothing()
                    .to_owned(),
                )
                .exec(db)
                .await,
        )?;
    }

    // 4. Parent delegations — every (parent, child) across the batch,
    //    deduplicated by the full primary key.
    let mut seen_parents = HashSet::new();
    let parents: Vec<parent_delegations::ActiveModel> = records
        .iter()
        .flat_map(|record| {
            let child = record.id;
            record.parents.iter().map(move |parent| (*parent, child))
        })
        .filter(|(parent, child)| seen_parents.insert((*parent, *child)))
        .map(|(parent, child)| parent_delegations::ActiveModel {
            parent: Set(parent),
            child: Set(child),
        })
        .collect();
    if !parents.is_empty() {
        ignore_record_not_inserted(
            parent_delegations::Entity::insert_many(parents)
                .on_conflict(
                    OnConflict::columns([
                        parent_delegations::Column::Parent,
                        parent_delegations::Column::Child,
                    ])
                    .do_nothing()
                    .to_owned(),
                )
                .exec(db)
                .await,
        )?;
    }

    Ok(())
}

fn ignore_record_not_inserted<T>(result: Result<T, DbErr>) -> Result<(), DbErr> {
    match result {
        Ok(_) | Err(DbErr::RecordNotInserted) => Ok(()),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migrations::Migrator;
    use sea_orm::{ConnectOptions, Database, PaginatorTrait};
    use sea_orm_migration::MigratorTrait;

    fn record(index: usize) -> ReadAuditRecord {
        ReadAuditRecord {
            id: crate::hash::hash(format!("read-audit-{index}").as_bytes()),
            invoker: "did:key:read-audit-test".to_string(),
            issued_at: OffsetDateTime::now_utc(),
            serialization: format!("serialized-{index}").into_bytes(),
            abilities: Vec::new(),
            parents: Vec::new(),
        }
    }

    async fn database(url: String, max_connections: u32) -> DatabaseConnection {
        let mut options = ConnectOptions::new(url);
        options.max_connections(max_connections);
        let conn = Database::connect(options).await.unwrap();
        Migrator::up(&conn, None).await.unwrap();
        conn
    }

    #[tokio::test]
    async fn concurrent_records_group_commit_and_are_durable() {
        let directory = tempfile::tempdir().unwrap();
        let url = format!(
            "sqlite:{}?mode=rwc",
            directory.path().join("audit.db").display()
        );
        let conn = database(url.clone(), 8).await;
        let pipeline = ReadAuditPipeline::start(conn.clone(), Some(Arc::new(Mutex::new(()))));

        let requests = (0..32)
            .map(|index| {
                let pipeline = pipeline.clone();
                tokio::spawn(async move { pipeline.enqueue(record(index)).await })
            })
            .collect::<Vec<_>>();
        for request in requests {
            request.await.unwrap().unwrap();
        }

        let (records, batches) = pipeline.stats();
        println!("durable read audit: {records} records in {batches} commits");
        assert_eq!(records, 32);
        assert!(
            batches < records,
            "saturated reads should use fewer commits than records"
        );
        assert_eq!(invocation::Entity::find().count(&conn).await.unwrap(), 32);

        drop(pipeline);
        drop(conn);
        let reopened = database(url, 1).await;
        assert_eq!(
            invocation::Entity::find().count(&reopened).await.unwrap(),
            32
        );
    }

    #[tokio::test]
    async fn wal_reader_progresses_while_audit_waits_for_writer() {
        let directory = tempfile::tempdir().unwrap();
        let url = format!(
            "sqlite:{}?mode=rwc",
            directory.path().join("concurrent.db").display()
        );
        let mut options = ConnectOptions::new(url);
        options.max_connections(4).map_sqlx_sqlite_opts(|options| {
            options
                .create_if_missing(true)
                .pragma("journal_mode", "WAL")
        });
        let conn = Database::connect(options).await.unwrap();
        Migrator::up(&conn, None).await.unwrap();
        let writer_lock = Arc::new(Mutex::new(()));
        let pipeline = ReadAuditPipeline::start(conn.clone(), Some(writer_lock.clone()));
        let writer = writer_lock.lock().await;

        let audit = tokio::spawn(async move { pipeline.enqueue(record(0)).await });
        tokio::task::yield_now().await;
        assert!(!audit.is_finished());

        tokio::time::timeout(
            std::time::Duration::from_millis(100),
            invocation::Entity::find().count(&conn),
        )
        .await
        .expect("WAL read should not wait for the writer lock")
        .unwrap();

        drop(writer);
        audit.await.unwrap().unwrap();
    }

    fn resource(uri: &str) -> Resource {
        uri.parse().expect("valid resource uri")
    }

    fn ability(uri: &str) -> Ability {
        uri.to_string().try_into().expect("valid ability")
    }

    fn rich_record(
        seed: &str,
        invoker: &str,
        abilities: Vec<(Resource, Ability)>,
        parents: Vec<Hash>,
    ) -> ReadAuditRecord {
        ReadAuditRecord {
            id: crate::hash::hash(seed.as_bytes()),
            invoker: invoker.to_string(),
            issued_at: OffsetDateTime::now_utc(),
            serialization: format!("serialized-{seed}").into_bytes(),
            abilities,
            parents,
        }
    }

    fn command(record: ReadAuditRecord) -> Command {
        let (committed, _receipt) = oneshot::channel();
        Command { record, committed }
    }

    /// A `parent_delegation.parent` value must reference a real `delegation`
    /// row (enforced FK), so seed one before persisting audit records that cite
    /// it as a parent. Mirrors the delegation module's own test helper.
    async fn insert_parent_delegation(conn: &DatabaseConnection, id: Hash) {
        use crate::models::delegation;
        ignore_record_not_inserted(
            actor::Entity::insert(actor::ActiveModel {
                id: Set("did:key:parent-authority".to_string()),
            })
            .on_conflict(
                OnConflict::column(actor::Column::Id)
                    .do_nothing()
                    .to_owned(),
            )
            .exec(conn)
            .await,
        )
        .unwrap();
        delegation::Entity::insert(delegation::ActiveModel {
            id: Set(id),
            delegator: Set("did:key:parent-authority".to_string()),
            delegatee: Set("did:key:parent-authority".to_string()),
            expiry: Set(None),
            issued_at: Set(None),
            not_before: Set(None),
            facts: Set(None),
            serialization: Set(id.as_ref().to_vec()),
        })
        .exec(conn)
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn batched_persist_matches_per_record_contents_and_is_idempotent() {
        let conn = database("sqlite::memory:".to_string(), 1).await;

        let parent_one = crate::hash::hash(b"parent-one");
        let parent_two = crate::hash::hash(b"parent-two");
        insert_parent_delegation(&conn, parent_one).await;
        insert_parent_delegation(&conn, parent_two).await;

        let res_a = resource("tinycloud:did:key:ne-delegator:files/kv/a");
        let res_b = resource("tinycloud:did:key:ne-delegator:files/kv/b");
        let get = ability("tinycloud.kv/get");
        let put = ability("tinycloud.kv/put");
        let read = ability("tinycloud.capabilities/read");

        // alice1: multiple abilities on one resource, two parents.
        let alice1 = rich_record(
            "alice-1",
            "did:key:alice",
            vec![(res_a.clone(), get.clone()), (res_a.clone(), put.clone())],
            vec![parent_one, parent_two],
        );
        // alice2: DUPLICATE actor (did:key:alice), one ability, shares parent_one.
        let alice2 = rich_record(
            "alice-2",
            "did:key:alice",
            vec![(res_b.clone(), read.clone())],
            vec![parent_one],
        );
        // bob: distinct actor, no abilities, no parents.
        let bob = rich_record("bob-1", "did:key:bob", vec![], vec![]);

        let alice1_id = alice1.id;
        let alice2_id = alice2.id;
        let bob_id = bob.id;

        let batch = vec![command(alice1), command(alice2), command(bob)];
        persist_batch(&conn, &batch).await.unwrap();

        // Actors: the duplicate invoker collapses to one row.
        let actors: HashSet<String> = actor::Entity::find()
            .all(&conn)
            .await
            .unwrap()
            .into_iter()
            .map(|row| row.id)
            .collect();
        assert!(actors.contains("did:key:alice"));
        assert!(actors.contains("did:key:bob"));

        // Invocations: three rows; invoker + (already-encrypted) serialization
        // are carried verbatim.
        let invocations = invocation::Entity::find().all(&conn).await.unwrap();
        assert_eq!(invocations.len(), 3);
        let by_id: std::collections::HashMap<Hash, invocation::Model> =
            invocations.into_iter().map(|row| (row.id, row)).collect();
        assert_eq!(by_id[&alice1_id].invoker, "did:key:alice");
        assert_eq!(
            by_id[&alice1_id].serialization,
            b"serialized-alice-1".to_vec()
        );
        assert_eq!(by_id[&alice2_id].invoker, "did:key:alice");
        assert_eq!(by_id[&bob_id].invoker, "did:key:bob");

        // Invoked abilities: exact (invocation, resource, ability) set.
        let ability_rows: HashSet<(Hash, String, String)> = invoked_abilities::Entity::find()
            .all(&conn)
            .await
            .unwrap()
            .into_iter()
            .map(|row| {
                (
                    row.invocation,
                    row.resource.to_string(),
                    row.ability.to_string(),
                )
            })
            .collect();
        let expected_abilities: HashSet<(Hash, String, String)> = [
            (alice1_id, res_a.to_string(), get.to_string()),
            (alice1_id, res_a.to_string(), put.to_string()),
            (alice2_id, res_b.to_string(), read.to_string()),
        ]
        .into_iter()
        .collect();
        assert_eq!(ability_rows, expected_abilities);

        // Parent delegations: exact (parent, child) set.
        let parent_rows: HashSet<(Hash, Hash)> = parent_delegations::Entity::find()
            .all(&conn)
            .await
            .unwrap()
            .into_iter()
            .map(|row| (row.parent, row.child))
            .collect();
        let expected_parents: HashSet<(Hash, Hash)> = [
            (parent_one, alice1_id),
            (parent_two, alice1_id),
            (parent_one, alice2_id),
        ]
        .into_iter()
        .collect();
        assert_eq!(parent_rows, expected_parents);

        // Re-persisting the identical batch is a no-op (ON CONFLICT DO NOTHING).
        persist_batch(&conn, &batch).await.unwrap();
        assert_eq!(invocation::Entity::find().count(&conn).await.unwrap(), 3);
        assert_eq!(
            invoked_abilities::Entity::find()
                .count(&conn)
                .await
                .unwrap(),
            3
        );
        assert_eq!(
            parent_delegations::Entity::find()
                .count(&conn)
                .await
                .unwrap(),
            3
        );
    }
}
