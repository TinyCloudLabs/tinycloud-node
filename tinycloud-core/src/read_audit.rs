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
    sea_query::{Alias, CommonTableExpression, OnConflict, WithClause},
    ActiveValue::Set,
    ConnectionTrait, DatabaseConnection, DbBackend, DbErr, EntityTrait, Insert, QueryTrait,
    Statement, TransactionTrait,
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
    let inserts = audit_inserts(batch);
    if conn.get_database_backend() == DbBackend::Postgres {
        if let Some(statement) = inserts.as_ref().and_then(postgres_single_statement) {
            return conn.execute(statement).await.map(|_| ());
        }
    }
    let tx = conn.begin().await?;
    if let Some(inserts) = inserts {
        persist_inserts(&tx, inserts).await?;
    }
    tx.commit().await
}

/// PostgreSQL commits the batch's INSERTs as one statement instead of
/// `BEGIN`, one statement per table and `COMMIT` (6 sequential round-trips
/// for a typical read). The INSERTs are exactly those `persist_inserts` runs,
/// with the same rows and `ON CONFLICT DO NOTHING` targets, as data-modifying
/// CTEs of the invocation INSERT. One statement is atomic on its own, and
/// PostgreSQL checks the foreign keys between these tables (invocation to
/// actor, invoked ability to invocation, parent edge to delegation) at the end
/// of the statement, so rows inserted by a sibling CTE satisfy them.
/// PostgreSQL does not define the order in which the CTEs run, so their rows
/// may be locked in a different order than the old transaction's; only two
/// writers of the same invocation id could notice, and the invocation replay
/// guard admits an invocation once.
///
/// `None` when the combined statement would bind more than the 65,535
/// parameters PostgreSQL's protocol allows (each per-table statement had that
/// limit on its own); `persist_batch` then takes the transactional path.
fn postgres_single_statement(inserts: &AuditInserts) -> Option<Statement> {
    let mut ctes = WithClause::new();
    let mut any_cte = false;
    for (name, insert) in [
        (
            "read_audit_actor",
            inserts.actors.as_ref().map(|i| i.as_query().clone()),
        ),
        (
            "read_audit_invoked_abilities",
            inserts.abilities.as_ref().map(|i| i.as_query().clone()),
        ),
        (
            "read_audit_parent_delegation",
            inserts.parents.as_ref().map(|i| i.as_query().clone()),
        ),
    ] {
        if let Some(insert) = insert {
            ctes.cte(
                CommonTableExpression::new()
                    .table_name(Alias::new(name))
                    .query(insert)
                    .to_owned(),
            );
            any_cte = true;
        }
    }
    let mut statement = inserts.invocations.as_query().clone();
    if any_cte {
        statement.with_cte(ctes);
    }
    let statement = DbBackend::Postgres.build(&statement);
    let parameters = statement.values.as_ref().map_or(0, |values| values.0.len());
    (parameters <= usize::from(u16::MAX)).then_some(statement)
}

/// The INSERTs that persist one drained batch: at most one `insert_many` per
/// table, instead of the previous ~4 statements per record.
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
struct AuditInserts {
    actors: Option<Insert<actor::ActiveModel>>,
    invocations: Insert<invocation::ActiveModel>,
    abilities: Option<Insert<invoked_abilities::ActiveModel>>,
    parents: Option<Insert<parent_delegations::ActiveModel>>,
}

/// `None` for a batch with no records.
fn audit_inserts(batch: &[Command]) -> Option<AuditInserts> {
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
        return None;
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
    let actors = (!actors.is_empty()).then(|| {
        actor::Entity::insert_many(actors).on_conflict(
            OnConflict::column(actor::Column::Id)
                .do_nothing()
                .to_owned(),
        )
    });

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
    let invocations = invocation::Entity::insert_many(invocations).on_conflict(
        OnConflict::column(invocation::Column::Id)
            .do_nothing()
            .to_owned(),
    );

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
    let abilities = (!abilities.is_empty()).then(|| {
        invoked_abilities::Entity::insert_many(abilities).on_conflict(
            OnConflict::columns([
                invoked_abilities::Column::Invocation,
                invoked_abilities::Column::Resource,
                invoked_abilities::Column::Ability,
            ])
            .do_nothing()
            .to_owned(),
        )
    });

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
    let parents = (!parents.is_empty()).then(|| {
        parent_delegations::Entity::insert_many(parents).on_conflict(
            OnConflict::columns([
                parent_delegations::Column::Parent,
                parent_delegations::Column::Child,
            ])
            .do_nothing()
            .to_owned(),
        )
    });

    Some(AuditInserts {
        actors,
        invocations,
        abilities,
        parents,
    })
}

/// Persist a drained batch inside the caller's transaction with one statement
/// per table (SQLite, MySQL, and PostgreSQL past the parameter limit).
async fn persist_inserts<C: ConnectionTrait>(db: &C, inserts: AuditInserts) -> Result<(), DbErr> {
    let AuditInserts {
        actors,
        invocations,
        abilities,
        parents,
    } = inserts;
    if let Some(actors) = actors {
        ignore_record_not_inserted(actors.exec(db).await)?;
    }
    ignore_record_not_inserted(invocations.exec(db).await)?;
    if let Some(abilities) = abilities {
        ignore_record_not_inserted(abilities.exec(db).await)?;
    }
    if let Some(parents) = parents {
        ignore_record_not_inserted(parents.exec(db).await)?;
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
        assert_batched_persist_contents(&conn, persist_batch_boxed).await;
    }

    /// How a test persists a batch: `persist_batch` (one statement on
    /// PostgreSQL), or the transaction of per-table INSERTs it replaces there.
    type Persist = for<'a> fn(
        &'a DatabaseConnection,
        &'a [Command],
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<(), DbErr>> + Send + 'a>,
    >;

    fn persist_batch_boxed<'a>(
        conn: &'a DatabaseConnection,
        batch: &'a [Command],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), DbErr>> + Send + 'a>> {
        Box::pin(persist_batch(conn, batch))
    }

    fn persist_in_transaction<'a>(
        conn: &'a DatabaseConnection,
        batch: &'a [Command],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), DbErr>> + Send + 'a>> {
        Box::pin(async move {
            let tx = conn.begin().await?;
            if let Some(inserts) = audit_inserts(batch) {
                persist_inserts(&tx, inserts).await?;
            }
            tx.commit().await
        })
    }

    async fn assert_batched_persist_contents(conn: &DatabaseConnection, persist: Persist) {
        let conn = conn.clone();

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
        persist(&conn, &batch).await.unwrap();

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
        persist(&conn, &batch).await.unwrap();
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

    async fn audit_rows(
        conn: &DatabaseConnection,
    ) -> (
        Vec<String>,
        Vec<(Hash, String, Vec<u8>)>,
        Vec<(Hash, String, String)>,
        Vec<(Hash, Hash)>,
    ) {
        let mut actors: Vec<String> = actor::Entity::find()
            .all(conn)
            .await
            .unwrap()
            .into_iter()
            .map(|row| row.id)
            .filter(|id| id != "did:key:parent-authority")
            .collect();
        let mut invocations: Vec<(Hash, String, Vec<u8>)> = invocation::Entity::find()
            .all(conn)
            .await
            .unwrap()
            .into_iter()
            .map(|row| (row.id, row.invoker, row.serialization))
            .collect();
        let mut abilities: Vec<(Hash, String, String)> = invoked_abilities::Entity::find()
            .all(conn)
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
        let mut parents: Vec<(Hash, Hash)> = parent_delegations::Entity::find()
            .all(conn)
            .await
            .unwrap()
            .into_iter()
            .map(|row| (row.parent, row.child))
            .collect();
        actors.sort();
        invocations.sort_by(|left, right| left.0.as_ref().cmp(right.0.as_ref()));
        abilities.sort_by(|left, right| {
            (left.0.as_ref(), &left.1, &left.2).cmp(&(right.0.as_ref(), &right.1, &right.2))
        });
        parents.sort_by(|left, right| {
            (left.0.as_ref(), left.1.as_ref()).cmp(&(right.0.as_ref(), right.1.as_ref()))
        });
        (actors, invocations, abilities, parents)
    }

    /// PostgreSQL persists a batch as one statement. The same batch persisted
    /// by the transaction of per-table INSERTs it replaced (in a second,
    /// isolated schema) leaves exactly the same rows, a failing batch leaves
    /// none of its rows on either path, and concurrent reads still group
    /// commit and are durable.
    #[tokio::test]
    async fn postgres_read_audit_batch_is_one_atomic_statement_with_unchanged_rows() {
        use crate::test_support::PostgresTestSchema;
        use std::sync::atomic::AtomicUsize;

        const TEST: &str = "postgres_read_audit_batch_is_one_atomic_statement_with_unchanged_rows";
        let Some(transactional) = PostgresTestSchema::new(TEST).await else {
            return;
        };
        let Some(single) = PostgresTestSchema::new(TEST).await else {
            return;
        };
        // The new actors in this batch exercise invocation -> actor, and its
        // parents invoked_abilities -> invocation and parent -> delegation,
        // all within one statement.
        assert_batched_persist_contents(&transactional.conn, persist_in_transaction).await;
        assert_batched_persist_contents(&single.conn, persist_batch_boxed).await;
        assert_eq!(
            audit_rows(&single.conn).await,
            audit_rows(&transactional.conn).await
        );

        // One statement per batch on PostgreSQL; the transactional path ran
        // one per table (plus BEGIN and COMMIT on the wire).
        let parent = crate::hash::hash(b"parent-one");
        let batch = || {
            vec![
                command(rich_record(
                    "count-1",
                    "did:key:count",
                    vec![(
                        resource("tinycloud:did:key:ne-delegator:files/kv/count"),
                        ability("tinycloud.kv/get"),
                    )],
                    vec![parent],
                )),
                command(rich_record("count-2", "did:key:count", vec![], vec![])),
            ]
        };
        for (conn, persist, expected) in [
            (&single.conn, persist_batch_boxed as Persist, 1),
            (&transactional.conn, persist_in_transaction as Persist, 4),
        ] {
            let statements = Arc::new(AtomicUsize::new(0));
            let counter = statements.clone();
            let mut counted = conn.clone();
            counted.set_metric_callback(move |_| {
                counter.fetch_add(1, Ordering::SeqCst);
            });
            persist(&counted, &batch()).await.unwrap();
            assert_eq!(statements.load(Ordering::SeqCst), expected);
        }
        assert_eq!(
            audit_rows(&single.conn).await,
            audit_rows(&transactional.conn).await
        );

        // A record citing a delegation that does not exist violates the parent
        // edge's foreign key: the whole batch fails, including its new actor
        // and the other record's rows.
        let doomed = vec![
            command(rich_record("doomed-ok", "did:key:doomed", vec![], vec![])),
            command(rich_record(
                "doomed-bad",
                "did:key:doomed",
                vec![],
                vec![crate::hash::hash(b"no-such-delegation")],
            )),
        ];
        for (conn, persist) in [
            (&single.conn, persist_batch_boxed as Persist),
            (&transactional.conn, persist_in_transaction as Persist),
        ] {
            let before = audit_rows(conn).await;
            assert!(persist(conn, &doomed).await.is_err());
            assert_eq!(audit_rows(conn).await, before);
        }

        // The pipeline itself, without a writer lock as on PostgreSQL in
        // production: concurrent reads group commit and are durable.
        let pipeline = ReadAuditPipeline::start(single.conn.clone(), None);
        let before = invocation::Entity::find()
            .count(&single.conn)
            .await
            .unwrap();
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
        assert_eq!(records, 32);
        assert!(batches < records, "saturated reads share commits");
        assert_eq!(
            invocation::Entity::find()
                .count(&single.conn)
                .await
                .unwrap(),
            before + 32
        );
    }

    #[test]
    fn single_statement_audit_covers_every_table_and_falls_back_past_the_parameter_limit() {
        assert!(audit_inserts(&[]).is_none());
        let single_statement = |batch: &[Command]| {
            postgres_single_statement(&audit_inserts(batch).expect("a non-empty batch"))
        };

        let get = ability("tinycloud.kv/get");
        let batch = vec![command(rich_record(
            "shape",
            "did:key:shape",
            vec![(
                resource("tinycloud:did:key:ne-delegator:files/kv/a"),
                get.clone(),
            )],
            vec![crate::hash::hash(b"parent")],
        ))];
        let sql = single_statement(&batch)
            .expect("an ordinary batch is one statement")
            .sql;
        assert!(sql.starts_with("WITH "), "{sql}");
        for table in [
            r#"INSERT INTO "actor""#,
            r#"INSERT INTO "invoked_abilities""#,
            r#"INSERT INTO "parent_delegation""#,
            r#"INSERT INTO "invocation""#,
        ] {
            assert_eq!(sql.matches(table).count(), 1, "{table}: {sql}");
        }
        assert_eq!(sql.matches("ON CONFLICT").count(), 4, "{sql}");
        assert!(!sql.contains("RETURNING"), "{sql}");

        // 6 parameters for the actor and invocation, 3 per invoked ability:
        // past 65,535 the batch takes the transactional path instead.
        let fits = (65_535 - 6) / 3;
        let abilities = |count: usize| {
            (0..count)
                .map(|index| {
                    (
                        resource(&format!("tinycloud:did:key:ne-delegator:files/kv/{index}")),
                        get.clone(),
                    )
                })
                .collect::<Vec<_>>()
        };
        let at_limit = vec![command(rich_record(
            "at-limit",
            "did:key:limit",
            abilities(fits),
            vec![],
        ))];
        assert!(single_statement(&at_limit).is_some());
        let past_limit = vec![command(rich_record(
            "past-limit",
            "did:key:limit",
            abilities(fits + 1),
            vec![],
        ))];
        assert!(single_statement(&past_limit).is_none());
    }
}
