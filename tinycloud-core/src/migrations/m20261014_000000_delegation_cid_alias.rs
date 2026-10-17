use sea_orm_migration::prelude::*;

use crate::models::{delegation, delegation_cid_alias};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let mut id = ColumnDef::new(delegation_cid_alias::Column::Id);
        let mut canonical = ColumnDef::new(delegation_cid_alias::Column::Canonical);
        if manager.get_database_backend() == sea_orm::DbBackend::MySql {
            // Encoded multihashes have variable length; MySQL's bare BINARY
            // defaults to one byte, and fixed-width BINARY would pad the ID.
            id.var_binary(255);
            canonical.var_binary(255);
        } else {
            id.binary();
            canonical.binary();
        }
        manager
            .create_table(
                Table::create()
                    .table(delegation_cid_alias::Entity)
                    .if_not_exists()
                    .col(id.not_null().primary_key())
                    .col(canonical.not_null())
                    .col(
                        ColumnDef::new(delegation_cid_alias::Column::Encrypted)
                            .boolean()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(
                                delegation_cid_alias::Entity,
                                delegation_cid_alias::Column::Id,
                            )
                            .to(delegation::Entity, delegation::Column::Id),
                    )
                    // Canonical identities may have no separately persisted
                    // serialization, so only the exact ID has a foreign key.
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_delegation_cid_alias_canonical")
                    .table(delegation_cid_alias::Entity)
                    .col(delegation_cid_alias::Column::Canonical)
                    .col(delegation_cid_alias::Column::Id)
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_delegation_cid_alias_encrypted")
                    .table(delegation_cid_alias::Entity)
                    .col(delegation_cid_alias::Column::Encrypted)
                    .col(delegation_cid_alias::Column::Id)
                    .if_not_exists()
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_index(
                Index::drop()
                    .name("idx_delegation_cid_alias_canonical")
                    .table(delegation_cid_alias::Entity)
                    .to_owned(),
            )
            .await?;
        manager
            .drop_index(
                Index::drop()
                    .name("idx_delegation_cid_alias_encrypted")
                    .table(delegation_cid_alias::Entity)
                    .to_owned(),
            )
            .await?;
        manager
            .drop_table(Table::drop().table(delegation_cid_alias::Entity).to_owned())
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        db::migrate, db_pool::RecoveringConnection, migrations::Migrator,
        test_support::PostgresTestSchema,
    };
    use sea_orm::{ConnectionTrait, DatabaseConnection, DbBackend, Statement, TransactionTrait};
    use sea_orm_migration::MigratorTrait;
    use std::time::{Duration, Instant};

    async fn scalar(db: &DatabaseConnection, sql: &str) -> String {
        db.query_one(Statement::from_string(DbBackend::Postgres, sql.to_string()))
            .await
            .unwrap()
            .unwrap()
            .try_get_by_index(0)
            .unwrap()
    }

    async fn applied(db: &DatabaseConnection) -> String {
        scalar(db, "SELECT count(*)::text FROM seaql_migrations").await
    }

    async fn alias_table(db: &DatabaseConnection) -> String {
        scalar(
            db,
            "SELECT coalesce(to_regclass('delegation_cid_alias')::text, 'absent')",
        )
        .await
    }

    /// The first boot after 1.20.6 runs this migration first. Its foreign key
    /// to `delegation` needs SHARE ROW EXCLUSIVE, which waits for any open
    /// write on `delegation`; the boot must fail within its lock timeout,
    /// apply nothing, and leave no `lock_timeout` on the pooled session.
    #[tokio::test]
    async fn postgres_boot_from_1_20_6_fails_fast_behind_an_open_delegation_write() {
        let test = "postgres_boot_from_1_20_6_fails_fast_behind_an_open_delegation_write";
        let release_1_20_6 = Migrator::migrations()
            .iter()
            .position(|migration| migration.name() == Migration.name())
            .unwrap() as u32;
        let Some(fixture) = PostgresTestSchema::migrated_through(test, Some(release_1_20_6)).await
        else {
            return;
        };
        let db = &fixture.conn;
        assert_eq!(applied(db).await, release_1_20_6.to_string());
        assert_eq!(alias_table(db).await, "absent");

        let writer = db.begin().await.unwrap();
        writer
            .execute_unprepared("UPDATE delegation SET id = id WHERE false")
            .await
            .unwrap();
        // One connection, so every check below runs on the session that
        // applied the migrations.
        let boot = fixture.connect(1).await;
        let pool = RecoveringConnection::new(boot.clone());
        let started = Instant::now();
        let outcome = tokio::time::timeout(Duration::from_secs(45), migrate(&pool)).await;
        let waited = started.elapsed();
        writer.rollback().await.unwrap();

        let error = outcome
            .expect("boot still waiting behind the open delegation write after 45s")
            .expect_err("boot must fail while delegation has an open write");
        let message = error.to_string();
        assert!(
            matches!(error, DbErr::Migration(_))
                && message.contains("30s")
                && message.contains("55P03"),
            "error must name the lock wait: {message}"
        );
        eprintln!("boot failed after {waited:?}: {message}");
        assert_eq!(applied(db).await, release_1_20_6.to_string());
        assert_eq!(alias_table(db).await, "absent");
        assert_eq!(scalar(&boot, "SHOW lock_timeout").await, "0");

        migrate(&pool).await.unwrap();
        assert_eq!(applied(db).await, Migrator::migrations().len().to_string());
        assert_eq!(alias_table(db).await, "delegation_cid_alias");
        assert_eq!(scalar(&boot, "SHOW lock_timeout").await, "0");
    }
}
