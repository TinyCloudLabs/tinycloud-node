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
    for command in batch {
        persist_record(&tx, &command.record).await?;
    }
    tx.commit().await
}

async fn persist_record<C: ConnectionTrait>(db: &C, record: &ReadAuditRecord) -> Result<(), DbErr> {
    ignore_record_not_inserted(
        actor::Entity::insert(actor::ActiveModel {
            id: Set(record.invoker.clone()),
        })
        .on_conflict(
            OnConflict::column(actor::Column::Id)
                .do_nothing()
                .to_owned(),
        )
        .exec(db)
        .await,
    )?;

    ignore_record_not_inserted(
        invocation::Entity::insert(invocation::ActiveModel {
            id: Set(record.id),
            invoker: Set(record.invoker.clone()),
            issued_at: Set(record.issued_at),
            facts: Set(None),
            serialization: Set(record.serialization.clone()),
        })
        .on_conflict(
            OnConflict::column(invocation::Column::Id)
                .do_nothing()
                .to_owned(),
        )
        .exec(db)
        .await,
    )?;

    if !record.abilities.is_empty() {
        ignore_record_not_inserted(
            invoked_abilities::Entity::insert_many(record.abilities.iter().cloned().map(
                |(resource, ability)| invoked_abilities::ActiveModel {
                    invocation: Set(record.id),
                    resource: Set(resource),
                    ability: Set(ability),
                },
            ))
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

    if !record.parents.is_empty() {
        ignore_record_not_inserted(
            parent_delegations::Entity::insert_many(record.parents.iter().map(|parent| {
                parent_delegations::ActiveModel {
                    parent: Set(*parent),
                    child: Set(record.id),
                }
            }))
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
}
