//! Threshold network authorization set (TC-2225): the per-network object set,
//! the members' key rows, the network-revocation marker and fault records.
//!
//! Four new, empty tables: no foreign key, no change to an existing table and
//! no backfill. Re-run is a no-op (IF NOT EXISTS). Nothing writes them unless
//! `threshold_v1` is on. `down` drops them; a rollback past this migration is
//! a restore of the database, not a `down`.

use sea_orm_migration::prelude::*;

use crate::models::{
    threshold_fault as fault, threshold_key_row as key_row,
    threshold_network_revocation as network_revocation, threshold_set_object as object,
};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for table in tables() {
            manager.create_table(table).await?;
        }
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for table in [
            fault::Entity.into_table_ref(),
            network_revocation::Entity.into_table_ref(),
            key_row::Entity.into_table_ref(),
            object::Entity.into_table_ref(),
        ] {
            manager
                .drop_table(Table::drop().table(table).if_exists().to_owned())
                .await?;
        }
        Ok(())
    }
}

fn text(column: impl IntoIden) -> ColumnDef {
    ColumnDef::new(column).string().not_null().to_owned()
}

fn tables() -> [TableCreateStatement; 4] {
    [
        Table::create()
            .table(object::Entity)
            .if_not_exists()
            .col(text(object::Column::NetworkId))
            .col(text(object::Column::Cid))
            .col(text(object::Column::Kind))
            .col(text(object::Column::Subject))
            .col(ColumnDef::new(object::Column::Bytes).blob().not_null())
            .col(text(object::Column::RecordedAt))
            .primary_key(
                Index::create()
                    .col(object::Column::NetworkId)
                    .col(object::Column::Cid),
            )
            .to_owned(),
        Table::create()
            .table(key_row::Entity)
            .if_not_exists()
            .col(text(key_row::Column::NetworkId))
            .col(text(key_row::Column::KeyPath))
            .col(text(key_row::Column::State))
            .col(
                ColumnDef::new(key_row::Column::KeyVersion)
                    .big_integer()
                    .not_null(),
            )
            .col(
                ColumnDef::new(key_row::Column::StateSeq)
                    .big_integer()
                    .not_null(),
            )
            .col(text(key_row::Column::StatementCid))
            .col(
                ColumnDef::new(key_row::Column::Conflict)
                    .boolean()
                    .not_null(),
            )
            .col(text(key_row::Column::UpdatedAt))
            .primary_key(
                Index::create()
                    .col(key_row::Column::NetworkId)
                    .col(key_row::Column::KeyPath),
            )
            .to_owned(),
        Table::create()
            .table(network_revocation::Entity)
            .if_not_exists()
            .col(text(network_revocation::Column::NetworkId).primary_key())
            .col(text(network_revocation::Column::StatementCid))
            .col(text(network_revocation::Column::RecordedAt))
            .to_owned(),
        Table::create()
            .table(fault::Entity)
            .if_not_exists()
            .col(
                ColumnDef::new(fault::Column::Id)
                    .big_integer()
                    .not_null()
                    .auto_increment()
                    .primary_key(),
            )
            .col(text(fault::Column::NetworkId))
            .col(text(fault::Column::SourceDid))
            .col(text(fault::Column::ObjectCid))
            .col(text(fault::Column::Reason))
            .col(text(fault::Column::RecordedAt))
            .to_owned(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migrations::Migrator;
    use sea_orm::{ConnectOptions, ConnectionTrait, Database, DbBackend, Statement};
    use sea_orm_migration::MigratorTrait;

    const TABLES: [&str; 4] = [
        "threshold_set_object",
        "threshold_key_row",
        "threshold_network_revocation",
        "threshold_fault",
    ];

    async fn present(conn: &sea_orm::DatabaseConnection) -> Vec<String> {
        let mut found = Vec::new();
        for table in TABLES {
            let rows = conn
                .query_all(Statement::from_string(
                    DbBackend::Sqlite,
                    format!("SELECT name FROM pragma_table_info('{table}')"),
                ))
                .await
                .unwrap();
            if !rows.is_empty() {
                found.push(table.to_string());
            }
        }
        found
    }

    #[tokio::test]
    async fn sqlite_up_is_idempotent_and_down_drops_the_tables() {
        let mut options = ConnectOptions::new("sqlite::memory:".to_string());
        options.max_connections(1).sqlx_logging(false);
        let conn = Database::connect(options).await.unwrap();
        Migrator::up(&conn, None).await.unwrap();
        assert_eq!(present(&conn).await, TABLES);
        Migration.up(&SchemaManager::new(&conn)).await.unwrap();
        Migration.down(&SchemaManager::new(&conn)).await.unwrap();
        assert!(present(&conn).await.is_empty());
        Migration.down(&SchemaManager::new(&conn)).await.unwrap();
        Migration.up(&SchemaManager::new(&conn)).await.unwrap();
        assert_eq!(present(&conn).await, TABLES);
    }

    #[tokio::test]
    async fn postgres_up_is_idempotent_and_down_drops_the_tables() {
        let Some(fixture) = crate::test_support::PostgresTestSchema::new(
            "postgres_up_is_idempotent_and_down_drops_the_tables",
        )
        .await
        else {
            return;
        };
        let conn = &fixture.conn;
        let count = || async {
            conn.query_one(Statement::from_string(
                DbBackend::Postgres,
                "SELECT count(*) AS n FROM information_schema.tables
                 WHERE table_schema = current_schema() AND table_name LIKE 'threshold\\_%'"
                    .to_string(),
            ))
            .await
            .unwrap()
            .unwrap()
            .try_get::<i64>("", "n")
            .unwrap()
        };
        assert_eq!(count().await, 4);
        Migration.up(&SchemaManager::new(conn)).await.unwrap();
        Migration.down(&SchemaManager::new(conn)).await.unwrap();
        assert_eq!(count().await, 0);
        Migration.up(&SchemaManager::new(conn)).await.unwrap();
        assert_eq!(count().await, 4);
    }
}
