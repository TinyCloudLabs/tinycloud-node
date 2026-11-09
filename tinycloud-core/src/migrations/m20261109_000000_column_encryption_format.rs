//! Record column storage formats without rewriting existing bytes.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

const COLUMNS: [(&str, &str); 5] = [
    ("delegation", "serialization_format"),
    ("invocation", "serialization_format"),
    ("hook_subscription", "encrypted_secret_format"),
    ("owner_share_policy", "policy_bytes_format"),
    ("owner_share_policy", "enforcement_delegation_bytes_format"),
];

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for (table, column) in COLUMNS {
            manager
                .alter_table(
                    Table::alter()
                        .table(Alias::new(table))
                        .add_column(
                            ColumnDef::new(Alias::new(column))
                                .small_integer()
                                .not_null()
                                .default(0),
                        )
                        .to_owned(),
                )
                .await?;
        }
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for (table, column) in COLUMNS.into_iter().rev() {
            manager
                .alter_table(
                    Table::alter()
                        .table(Alias::new(table))
                        .drop_column(Alias::new(column))
                        .to_owned(),
                )
                .await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sea_orm::{ConnectionTrait, Database, DbBackend, Statement};

    #[tokio::test]
    async fn existing_rows_keep_bytes_and_default_to_compatibility_format() {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        for table in [
            "delegation",
            "invocation",
            "hook_subscription",
            "owner_share_policy",
        ] {
            db.execute(Statement::from_string(
                DbBackend::Sqlite,
                format!("CREATE TABLE {table} (bytes BLOB NOT NULL)"),
            ))
            .await
            .unwrap();
            db.execute(Statement::from_string(
                DbBackend::Sqlite,
                format!("INSERT INTO {table} (bytes) VALUES (X'010203')"),
            ))
            .await
            .unwrap();
        }
        Migration.up(&SchemaManager::new(&db)).await.unwrap();
        for (table, column) in COLUMNS {
            let row = db
                .query_one(Statement::from_string(
                    DbBackend::Sqlite,
                    format!("SELECT bytes, {column} AS format FROM {table}"),
                ))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(row.try_get::<Vec<u8>>("", "bytes").unwrap(), [1, 2, 3]);
            assert_eq!(row.try_get::<i16>("", "format").unwrap(), 0);
        }
    }
}
