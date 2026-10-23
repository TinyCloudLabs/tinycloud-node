use sea_orm::{
    ConnectionTrait, DatabaseConnection, DatabaseTransaction, DbBackend, Statement,
    TransactionTrait,
};
use sea_orm_migration::prelude::*;
use sea_orm_migration::{IntoSchemaManagerConnection, SchemaManagerConnection};
pub mod m20230510_101010_init_tables;
pub mod m20260218_sql_database;
pub mod m20260409_000000_hook_tables;
pub mod m20260512_000000_signed_kv_tickets;
pub mod m20260516_000000_database_artifacts;
pub mod m20260601_000000_encryption_networks;
pub mod m20260602_000000_rename_encryption_owner_did;
pub mod m20260715_000000_policy_authority;
pub mod m20260715_000000_revocation_timestamp;
pub mod m20260719_000000_share_email_protocol;
pub mod m20260719_000001_share_policy_presentation_jti;
pub mod m20260719_000002_policy_status_freshness;
pub mod m20260724_000000_database_artifact_deltas;
pub mod m20260724_000000_invocation_replay;
pub mod m20260724_010000_current_kv;
pub mod m20260725_000000_request_path_indexes;
pub mod m20260726_000000_owner_share_policy;
pub mod m20260726_000001_owner_share_policy_proof;
pub mod m20260726_000002_owner_share_enforcement_bytes;
pub mod m20260731_000000_policy_v3;
pub mod m20260915_000000_meeting_legacy_write_guard;
pub mod m20261005_000000_current_kv_sync_order;
pub mod m20261005_000000_deactivate_hook_subscriptions;
pub mod m20261007_000000_database_alias;
pub mod m20261007_010000_database_identity_fence;
pub mod m20261014_000000_delegation_cid_alias;
pub mod m20261015_000000_delegation_cursor_index;
pub mod m20261017_000000_epoch_order_space_index;
pub mod m20261018_000000_epoch_head;
pub mod m20261020_000000_current_kv_key_c_index;
pub mod m20261021_000000_sql_store_manifest;
pub mod m20261022_000000_encryption_network_key;
pub mod m20261023_000000_current_kv_prefix_index;

pub struct Migrator;

/// One PostgreSQL migration batch: a transaction that lifts the pool's
/// `statement_timeout` (TC-1054) and bounds every lock wait (TC-1176). Both are
/// `SET LOCAL`, so they end with the transaction.
async fn begin_postgres_batch(db: &DatabaseConnection) -> Result<DatabaseTransaction, DbErr> {
    let open = db.begin().await?;
    open.execute_unprepared(crate::db_pool::EXEMPT_STATEMENT_TIMEOUT)
        .await?;
    open.execute_unprepared(&format!(
        "SET LOCAL lock_timeout = '{}'",
        crate::db::MIGRATION_LOCK_TIMEOUT
    ))
    .await?;
    Ok(open)
}

/// SeaORM wraps every PostgreSQL migration batch in a transaction. The
/// byte-ordered index cannot be built or dropped there: CONCURRENTLY must run
/// between committed batches. Keep ordinary migrations atomic on either side.
async fn postgres_migrate(
    db: &DatabaseConnection,
    steps: Option<u32>,
    rollback: bool,
) -> Result<(), DbErr> {
    let initial = begin_postgres_batch(db).await?;
    Migrator::install(&initial).await?;
    let mut selected = if rollback {
        Migrator::get_applied_migrations(&initial).await?
    } else {
        Migrator::get_pending_migrations(&initial).await?
    };
    if rollback {
        selected.reverse();
    }
    let selected = selected
        .into_iter()
        .take(steps.map(|steps| steps as usize).unwrap_or(usize::MAX))
        .map(|migration| migration.name().to_owned())
        .collect::<Vec<_>>();
    let mut migrations = Migrator::migrations();
    if rollback {
        migrations.reverse();
    }
    let mut transaction = Some(initial);
    for migration in migrations {
        if !selected.iter().any(|name| name == migration.name()) {
            continue;
        }
        let concurrent = migration.name() == m20261023_000000_current_kv_prefix_index::NAME;
        if concurrent {
            if let Some(open) = transaction.take() {
                open.commit().await?;
            }
            let manager = SchemaManager::new(db);
            if rollback {
                migration.down(&manager).await?;
            } else {
                migration.up(&manager).await?;
            }
        } else {
            if transaction.is_none() {
                transaction = Some(begin_postgres_batch(db).await?);
            }
            let open = transaction.as_ref().expect("transaction opened above");
            let manager = SchemaManager::new(open);
            if rollback {
                migration.down(&manager).await?;
            } else {
                migration.up(&manager).await?;
            }
        }
        if transaction.is_none() {
            transaction = Some(begin_postgres_batch(db).await?);
        }
        let connection: &dyn ConnectionTrait =
            transaction.as_ref().expect("transaction opened above");
        if rollback {
            connection
                .execute(Statement::from_sql_and_values(
                    DbBackend::Postgres,
                    "DELETE FROM seaql_migrations WHERE version = $1",
                    [migration.name().to_owned().into()],
                ))
                .await?;
        } else {
            // Another node can finish the same concurrent build between the
            // pending-migration read and this write.
            let sql = if concurrent {
                "INSERT INTO seaql_migrations (version, applied_at) VALUES ($1, $2) \
                 ON CONFLICT (version) DO NOTHING"
            } else {
                "INSERT INTO seaql_migrations (version, applied_at) VALUES ($1, $2)"
            };
            connection
                .execute(Statement::from_sql_and_values(
                    DbBackend::Postgres,
                    sql,
                    [
                        migration.name().to_owned().into(),
                        time::OffsetDateTime::now_utc().unix_timestamp().into(),
                    ],
                ))
                .await?;
        }
    }
    if let Some(open) = transaction {
        open.commit().await?;
    }
    Ok(())
}

/// Use SeaORM's standard runner on SQLite/MySQL; only PostgreSQL needs a
/// nontransactional break around the concurrent index.
struct StandardMigrator;

#[async_trait::async_trait]
impl MigratorTrait for StandardMigrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        Migrator::migrations()
    }
}

/// SeaORM's default maintenance methods bypass `up`/`down` and wrap their
/// PostgreSQL work in one transaction. Reject them before touching schema or
/// history rather than entering the nontransactional index migration.
fn standard_maintenance_only<'c>(
    db: SchemaManagerConnection<'c>,
    operation: &str,
) -> Result<SchemaManagerConnection<'c>, DbErr> {
    if db.get_database_backend() == DbBackend::Postgres {
        Err(DbErr::Custom(format!(
            "PostgreSQL migrations support up/down only; {operation} is unsupported"
        )))
    } else {
        Ok(db)
    }
}

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20230510_101010_init_tables::Migration),
            Box::new(m20260218_sql_database::Migration),
            Box::new(m20260409_000000_hook_tables::Migration),
            Box::new(m20260512_000000_signed_kv_tickets::Migration),
            Box::new(m20260516_000000_database_artifacts::Migration),
            Box::new(m20260601_000000_encryption_networks::Migration),
            Box::new(m20260602_000000_rename_encryption_owner_did::Migration),
            Box::new(m20260715_000000_revocation_timestamp::Migration),
            Box::new(m20260715_000000_policy_authority::Migration),
            Box::new(m20260719_000000_share_email_protocol::Migration),
            Box::new(m20260719_000001_share_policy_presentation_jti::Migration),
            Box::new(m20260719_000002_policy_status_freshness::Migration),
            Box::new(m20260724_000000_invocation_replay::Migration),
            Box::new(m20260724_010000_current_kv::Migration),
            Box::new(m20260724_000000_database_artifact_deltas::Migration),
            Box::new(m20260725_000000_request_path_indexes::Migration),
            Box::new(m20260726_000000_owner_share_policy::Migration),
            Box::new(m20260726_000001_owner_share_policy_proof::Migration),
            Box::new(m20260726_000002_owner_share_enforcement_bytes::Migration),
            Box::new(m20260731_000000_policy_v3::Migration),
            Box::new(m20260915_000000_meeting_legacy_write_guard::Migration),
            Box::new(m20261005_000000_current_kv_sync_order::Migration),
            Box::new(m20261005_000000_deactivate_hook_subscriptions::Migration),
            Box::new(m20261007_000000_database_alias::Migration),
            Box::new(m20261007_010000_database_identity_fence::Migration),
            Box::new(m20261014_000000_delegation_cid_alias::Migration),
            Box::new(m20261015_000000_delegation_cursor_index::Migration),
            Box::new(m20261017_000000_epoch_order_space_index::Migration),
            Box::new(m20261018_000000_epoch_head::Migration),
            Box::new(m20261020_000000_current_kv_key_c_index::Migration),
            Box::new(m20261021_000000_sql_store_manifest::Migration),
            Box::new(m20261022_000000_encryption_network_key::Migration),
            Box::new(m20261023_000000_current_kv_prefix_index::Migration),
        ]
    }

    async fn fresh<'c, C>(db: C) -> Result<(), DbErr>
    where
        C: IntoSchemaManagerConnection<'c>,
    {
        StandardMigrator::fresh(standard_maintenance_only(
            db.into_schema_manager_connection(),
            "fresh",
        )?)
        .await
    }

    async fn refresh<'c, C>(db: C) -> Result<(), DbErr>
    where
        C: IntoSchemaManagerConnection<'c>,
    {
        StandardMigrator::refresh(standard_maintenance_only(
            db.into_schema_manager_connection(),
            "refresh",
        )?)
        .await
    }

    async fn reset<'c, C>(db: C) -> Result<(), DbErr>
    where
        C: IntoSchemaManagerConnection<'c>,
    {
        StandardMigrator::reset(standard_maintenance_only(
            db.into_schema_manager_connection(),
            "reset",
        )?)
        .await
    }

    async fn up<'c, C>(db: C, steps: Option<u32>) -> Result<(), DbErr>
    where
        C: IntoSchemaManagerConnection<'c>,
    {
        match db.into_schema_manager_connection() {
            SchemaManagerConnection::Connection(conn)
                if conn.get_database_backend() == DbBackend::Postgres =>
            {
                postgres_migrate(conn, steps, false).await
            }
            SchemaManagerConnection::Transaction(conn)
                if conn.get_database_backend() == DbBackend::Postgres =>
            {
                Err(DbErr::Custom(
                    "PostgreSQL migrations require a connection outside a transaction".into(),
                ))
            }
            other => StandardMigrator::up(other, steps).await,
        }
    }

    async fn down<'c, C>(db: C, steps: Option<u32>) -> Result<(), DbErr>
    where
        C: IntoSchemaManagerConnection<'c>,
    {
        match db.into_schema_manager_connection() {
            SchemaManagerConnection::Connection(conn)
                if conn.get_database_backend() == DbBackend::Postgres =>
            {
                postgres_migrate(conn, steps, true).await
            }
            SchemaManagerConnection::Transaction(conn)
                if conn.get_database_backend() == DbBackend::Postgres =>
            {
                Err(DbErr::Custom(
                    "PostgreSQL migrations require a connection outside a transaction".into(),
                ))
            }
            other => StandardMigrator::down(other, steps).await,
        }
    }
}

#[cfg(test)]
mod release_line_tests {
    use super::*;
    use sea_orm::{ConnectOptions, ConnectionTrait, Database, DbBackend, Statement};

    #[tokio::test]
    async fn postgres_fresh_and_release_line_upgrade_apply_n3_last() {
        let Some(url) = crate::test_support::postgres_test_url(
            "postgres_fresh_and_release_line_upgrade_apply_n3_last",
        ) else {
            return;
        };
        let admin = Database::connect(url.clone()).await.unwrap();
        let base_count = (Migrator::migrations().len() - 3) as u32;
        for path in ["fresh", "release"] {
            let schema = format!(
                "tc780_{path}_{}_{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            );
            admin
                .execute(Statement::from_string(
                    DbBackend::Postgres,
                    format!("CREATE SCHEMA {schema}"),
                ))
                .await
                .unwrap();
            let mut options = ConnectOptions::new(url.clone());
            options.set_schema_search_path(schema.clone());
            let db = Database::connect(options).await.unwrap();
            if path == "release" {
                Migrator::up(&db, Some(base_count)).await.unwrap();
                let applied = db
                    .query_all(Statement::from_string(
                        DbBackend::Postgres,
                        "SELECT version FROM seaql_migrations".to_string(),
                    ))
                    .await
                    .unwrap();
                assert_eq!(applied.len(), base_count as usize);
                let versions: Vec<String> = applied
                    .iter()
                    .map(|row| row.try_get("", "version").unwrap())
                    .collect();
                for required in [
                    "m20260915_000000_meeting_legacy_write_guard",
                    "m20261005_000000_current_kv_sync_order",
                    "m20261005_000000_deactivate_hook_subscriptions",
                ] {
                    assert!(versions.iter().any(|version| version == required));
                }
            }
            Migrator::up(&db, None).await.unwrap();
            let applied = db
                .query_all(Statement::from_string(
                    DbBackend::Postgres,
                    "SELECT version FROM seaql_migrations".to_string(),
                ))
                .await
                .unwrap();
            assert_eq!(applied.len(), Migrator::migrations().len());
            let versions: Vec<String> = applied
                .iter()
                .map(|row| row.try_get("", "version").unwrap())
                .collect();
            assert!(versions.contains(&"m20261007_000000_database_alias".to_string()));
            assert!(versions.contains(&"m20261007_010000_database_identity_fence".to_string()));
            assert!(versions.contains(&"m20261014_000000_delegation_cid_alias".to_string()));
            drop(db);
            admin
                .execute(Statement::from_string(
                    DbBackend::Postgres,
                    format!("DROP SCHEMA {schema} CASCADE"),
                ))
                .await
                .unwrap();
        }
    }

    #[tokio::test]
    async fn postgres_ordinary_migration_rolls_back_all_ddl_on_failure() {
        let Some(url) = crate::test_support::postgres_test_url(
            "postgres_ordinary_migration_rolls_back_all_ddl_on_failure",
        ) else {
            return;
        };
        let admin = Database::connect(url.clone()).await.unwrap();
        let schema = format!(
            "tc737_atomic_{}_{}",
            std::process::id(),
            time::OffsetDateTime::now_utc().unix_timestamp_nanos()
        );
        admin
            .execute(Statement::from_string(
                DbBackend::Postgres,
                format!("CREATE SCHEMA {schema}"),
            ))
            .await
            .unwrap();
        let mut options = ConnectOptions::new(url);
        options.set_schema_search_path(schema.clone());
        let db = Database::connect(options).await.unwrap();
        db.execute_unprepared("CREATE TABLE actor (id text PRIMARY KEY)")
            .await
            .unwrap();
        // The first ordinary migration creates `space` before `actor`.
        // Conflict at actor must roll back space and the migration history.
        assert!(Migrator::up(&db, Some(1)).await.is_err());
        let rolled_back: bool = db
            .query_one(Statement::from_string(
                DbBackend::Postgres,
                "SELECT to_regclass('space') IS NULL AND \
                 to_regclass('seaql_migrations') IS NULL AS rolled_back",
            ))
            .await
            .unwrap()
            .unwrap()
            .try_get("", "rolled_back")
            .unwrap();
        assert!(rolled_back, "ordinary migration must remain atomic");
        db.execute_unprepared("DROP TABLE actor").await.unwrap();
        Migrator::up(&db, None).await.unwrap();
        drop(db);
        admin
            .execute(Statement::from_string(
                DbBackend::Postgres,
                format!("DROP SCHEMA {schema} CASCADE"),
            ))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn postgres_maintenance_methods_reject_without_mutation() {
        let Some(schema) = crate::test_support::PostgresTestSchema::new(
            "postgres_maintenance_methods_reject_without_mutation",
        )
        .await
        else {
            return;
        };
        let db = &schema.conn;
        db.execute_unprepared("CREATE TABLE tc737_stray (id integer)")
            .await
            .unwrap();
        let before: i64 = db
            .query_one(Statement::from_string(
                DbBackend::Postgres,
                "SELECT count(*) AS count FROM seaql_migrations",
            ))
            .await
            .unwrap()
            .unwrap()
            .try_get("", "count")
            .unwrap();
        for (name, result) in [
            ("fresh", Migrator::fresh(db).await),
            ("refresh", Migrator::refresh(db).await),
            ("reset", Migrator::reset(db).await),
        ] {
            assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .contains(&format!("{name} is unsupported")),
                "{name} must reject before DDL"
            );
        }
        let row = db
            .query_one(Statement::from_string(
                DbBackend::Postgres,
                "SELECT (SELECT count(*) FROM seaql_migrations) AS count, \
                 to_regclass('tc737_stray') IS NOT NULL AS stray, \
                 EXISTS(SELECT 1 FROM pg_index WHERE \
                 indexrelid = to_regclass('idx_current_kv_space_key_c') AND indisvalid) AS valid",
            ))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.try_get::<i64>("", "count").unwrap(), before);
        assert!(row.try_get::<bool>("", "stray").unwrap());
        assert!(row.try_get::<bool>("", "valid").unwrap());
    }

    #[tokio::test]
    async fn postgres_tc1195_and_tc737_fresh_and_from_1206() {
        let Some(url) =
            crate::test_support::postgres_test_url("postgres_tc1195_and_tc737_fresh_and_from_1206")
        else {
            return;
        };
        let admin = Database::connect(url.clone()).await.unwrap();
        let migrations = Migrator::migrations();
        let before_1195 = migrations
            .iter()
            .position(|migration| migration.name() == "m20261015_000000_delegation_cursor_index")
            .unwrap() as u32;
        // Migrations main added after TC-1195 sit between it and TC-737's.
        let after_737 = migrations
            .iter()
            .position(|migration| migration.name() == "m20261023_000000_current_kv_prefix_index")
            .unwrap() as u32
            + 1;
        // Older same-timestamp migrations have historical registration order;
        // the new release-line tail must never precede an already applied one.
        for pair in migrations[before_1195 as usize..].windows(2) {
            assert!(
                pair[0].name() < pair[1].name(),
                "new migration must follow its predecessor: {} before {}",
                pair[0].name(),
                pair[1].name()
            );
        }
        // v1.20.6 ends immediately before TC-1195 in the migration list.
        for (prior, with_737) in [
            ("fresh", false),
            ("fresh", true),
            ("v1.20.6", false),
            ("v1.20.6", true),
        ] {
            let schema = format!(
                "tc737_{}_{}_{}",
                std::process::id(),
                if with_737 { "both" } else { "only1195" },
                time::OffsetDateTime::now_utc().unix_timestamp_nanos()
            );
            admin
                .execute(Statement::from_string(
                    DbBackend::Postgres,
                    format!("CREATE SCHEMA {schema}"),
                ))
                .await
                .unwrap();
            let mut options = ConnectOptions::new(url.clone());
            options.set_schema_search_path(schema.clone());
            let db = Database::connect(options).await.unwrap();
            if prior == "v1.20.6" {
                Migrator::up(&db, Some(before_1195)).await.unwrap();
            }
            Migrator::up(
                &db,
                Some(match (prior, with_737) {
                    ("fresh", false) => before_1195 + 1,
                    ("fresh", true) => after_737,
                    (_, false) => 1,
                    (_, true) => after_737 - before_1195,
                }),
            )
            .await
            .unwrap();
            let ddl: String = db
                .query_one(Statement::from_string(
                    DbBackend::Postgres,
                    "SELECT pg_get_indexdef(to_regclass('idx_delegation_delegator')) AS ddl",
                ))
                .await
                .unwrap()
                .unwrap()
                .try_get("", "ddl")
                .unwrap();
            assert!(ddl.contains("(delegator, id)"), "{prior}: {ddl}");
            let prefix_index: Option<bool> = db
                .query_one(Statement::from_string(
                    DbBackend::Postgres,
                    "SELECT indisvalid AS valid FROM pg_index \
                     WHERE indexrelid = to_regclass('idx_current_kv_space_key_c')",
                ))
                .await
                .unwrap()
                .map(|row| row.try_get("", "valid").unwrap());
            assert_eq!(prefix_index, with_737.then_some(true), "{prior}");
            drop(db);
            admin
                .execute(Statement::from_string(
                    DbBackend::Postgres,
                    format!("DROP SCHEMA {schema} CASCADE"),
                ))
                .await
                .unwrap();
        }
    }
}
