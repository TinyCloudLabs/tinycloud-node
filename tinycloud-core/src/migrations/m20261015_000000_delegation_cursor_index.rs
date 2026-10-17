use sea_orm_migration::prelude::*;

use crate::models::delegation;

#[derive(DeriveMigrationName)]
pub struct Migration;

async fn drop_index_if_exists(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    if manager
        .has_index("delegation", "idx_delegation_delegator")
        .await?
    {
        manager
            .drop_index(
                Index::drop()
                    .name("idx_delegation_delegator")
                    .table(delegation::Entity)
                    .to_owned(),
            )
            .await?;
    }
    Ok(())
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        drop_index_if_exists(manager).await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_delegation_delegator")
                    .table(delegation::Entity)
                    .col(delegation::Column::Delegator)
                    .col(delegation::Column::Id)
                    .if_not_exists()
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        drop_index_if_exists(manager).await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_delegation_delegator")
                    .table(delegation::Entity)
                    .col(delegation::Column::Delegator)
                    .if_not_exists()
                    .to_owned(),
            )
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{db::migrate, db_pool::RecoveringConnection, test_support::PostgresTestSchema};
    use sea_orm::{ConnectionTrait, DatabaseConnection, DbBackend, Statement, TransactionTrait};
    use std::time::{Duration, Instant};

    /// `(name, definition, valid)` for every index on `delegation`.
    async fn delegation_indexes(db: &DatabaseConnection) -> Vec<(String, String, bool)> {
        db.query_all(Statement::from_string(
            DbBackend::Postgres,
            "SELECT c.relname, pg_get_indexdef(i.indexrelid) AS def, i.indisvalid \
             FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid \
             WHERE i.indrelid = 'delegation'::regclass ORDER BY c.relname"
                .to_string(),
        ))
        .await
        .unwrap()
        .iter()
        .map(|row| {
            (
                row.try_get("", "relname").unwrap(),
                row.try_get("", "def").unwrap(),
                row.try_get("", "indisvalid").unwrap(),
            )
        })
        .collect()
    }

    async fn recorded(db: &DatabaseConnection) -> bool {
        db.query_one(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT 1 FROM seaql_migrations WHERE version = $1",
            [Migration.name().into()],
        ))
        .await
        .unwrap()
        .is_some()
    }

    /// A session holding any lock on `delegation` must make the boot
    /// migration fail within its lock timeout, not hang, and leave the
    /// database exactly as before so a later boot can apply it.
    #[tokio::test]
    async fn postgres_cursor_index_fails_fast_while_delegation_is_locked() {
        let Some(fixture) =
            PostgresTestSchema::new("postgres_cursor_index_fails_fast_while_delegation_is_locked")
                .await
        else {
            return;
        };
        let db = &fixture.conn;
        // Back to the state a node upgrading to this migration boots with:
        // roll back this migration and every later one, located by name.
        let migrations = crate::migrations::Migrator::migrations();
        let index = migrations
            .iter()
            .position(|m| m.name() == Migration.name())
            .unwrap();
        crate::migrations::Migrator::down(db, Some((migrations.len() - index) as u32))
            .await
            .unwrap();
        assert!(!recorded(db).await);
        let before = delegation_indexes(db).await;

        let reader = db.begin().await.unwrap();
        reader
            .execute_unprepared("LOCK TABLE delegation IN ACCESS SHARE MODE")
            .await
            .unwrap();
        let pool = RecoveringConnection::new(db.clone());
        let started = Instant::now();
        let outcome = tokio::time::timeout(Duration::from_secs(45), migrate(&pool)).await;
        let waited = started.elapsed();
        reader.rollback().await.unwrap();

        let error = outcome
            .expect("boot migration still waiting for the delegation lock after 45s")
            .expect_err("boot migration must fail while delegation is locked");
        let message = error.to_string();
        assert!(
            matches!(error, DbErr::Migration(_))
                && message.contains("30s")
                && message.contains("55P03"),
            "error must name the lock wait: {message}"
        );
        eprintln!("boot migration failed after {waited:?}: {message}");
        assert_eq!(delegation_indexes(db).await, before);
        assert!(!recorded(db).await);

        migrate(&pool).await.unwrap();
        assert!(recorded(db).await);
        let after = delegation_indexes(db).await;
        let cursor = after
            .iter()
            .find(|(name, _, _)| name == "idx_delegation_delegator")
            .unwrap();
        assert!(
            cursor.1.ends_with("(delegator, id)") && cursor.2,
            "{cursor:?}"
        );
    }
}
