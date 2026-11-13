use sea_orm_migration::prelude::*;

/// TC-2492: record each KV write's stored value size. The column is nullable:
/// rows written before it exist have no recorded size.
#[derive(DeriveMigrationName)]
pub struct Migration;

const TABLES: [&str; 2] = ["kv_write", "current_kv"];

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    /// A fresh install builds both tables from today's entities, which
    /// already have the column, so it is added only where missing; applying
    /// the migration again changes nothing.
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for table in TABLES {
            if !manager.has_column(table, "size").await? {
                manager
                    .alter_table(
                        Table::alter()
                            .table(Alias::new(table))
                            .add_column(ColumnDef::new(Alias::new("size")).big_integer().null())
                            .to_owned(),
                    )
                    .await?;
            }
        }
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for table in TABLES {
            manager
                .alter_table(
                    Table::alter()
                        .table(Alias::new(table))
                        .drop_column(Alias::new("size"))
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
    use crate::migrations::Migrator;
    use sea_orm::{
        ConnectOptions, ConnectionTrait, Database, DatabaseConnection, DbBackend, Statement, Value,
    };
    use sea_orm_migration::MigratorTrait;

    fn placeholders(backend: DbBackend, n: usize) -> String {
        (1..=n)
            .map(|i| match backend {
                DbBackend::Postgres => format!("${i}"),
                _ => "?".to_owned(),
            })
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// An upgraded schema gains the column with every existing row's size
    /// unknown, and applying the migration again changes nothing.
    async fn assert_upgrade(db: &DatabaseConnection) {
        let backend = db.get_database_backend();
        let manager = SchemaManager::new(db);
        Migration.down(&manager).await.unwrap();
        let blob = |tag: &[u8]| Value::Bytes(Some(Box::new(tag.to_vec())));
        db.execute(Statement::from_sql_and_values(
            backend,
            format!(
                "INSERT INTO space (id) VALUES ({})",
                placeholders(backend, 1)
            ),
            ["legacy".into()],
        ))
        .await
        .unwrap();
        db.execute(Statement::from_sql_and_values(
            backend,
            format!(
                "INSERT INTO current_kv (space, key, invocation, seq, epoch, epoch_seq, value, \
                 metadata, deleted) VALUES ({})",
                placeholders(backend, 9)
            ),
            [
                "legacy".into(),
                "k".into(),
                blob(b"invocation"),
                1i64.into(),
                blob(b"epoch"),
                1i64.into(),
                blob(b"value"),
                Value::Json(Some(Box::new(serde_json::json!({})))),
                false.into(),
            ],
        ))
        .await
        .unwrap();

        for _ in 0..2 {
            Migration.up(&manager).await.unwrap();
            for table in TABLES {
                assert!(manager.has_column(table, "size").await.unwrap(), "{table}");
            }
        }
        let size = db
            .query_one(Statement::from_string(
                backend,
                "SELECT size FROM current_kv WHERE key = 'k'".to_owned(),
            ))
            .await
            .unwrap()
            .expect("the legacy row")
            .try_get::<Option<i64>>("", "size")
            .unwrap();
        assert_eq!(size, None);
    }

    #[tokio::test]
    async fn sqlite_kv_value_size_upgrades_existing_rows_as_unknown() {
        let db = Database::connect(ConnectOptions::new("sqlite::memory:".to_owned()))
            .await
            .unwrap();
        Migrator::up(&db, None).await.unwrap();
        assert_upgrade(&db).await;
    }

    #[tokio::test]
    async fn postgres_kv_value_size_upgrades_existing_rows_as_unknown() {
        let Some(fixture) = crate::test_support::PostgresTestSchema::new(
            "postgres_kv_value_size_upgrades_existing_rows_as_unknown",
        )
        .await
        else {
            return;
        };
        assert_upgrade(&fixture.conn).await;
    }
}
