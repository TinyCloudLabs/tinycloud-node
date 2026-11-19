//! TC-3123: optional write-only custom headers on webhook subscriptions.
//! Names are plaintext (they are returned on list); name/value pairs are
//! sealed like `encrypted_secret`. Existing rows carry no headers.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

const TABLE: &str = "hook_subscription";

fn columns() -> [ColumnDef; 3] {
    [
        ColumnDef::new(Alias::new("header_names_json"))
            .text()
            .null()
            .to_owned(),
        ColumnDef::new(Alias::new("encrypted_headers"))
            .blob()
            .null()
            .to_owned(),
        ColumnDef::new(Alias::new("encrypted_headers_format"))
            .small_integer()
            .not_null()
            .default(0)
            .to_owned(),
    ]
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // One column per ALTER: SQLite accepts a single ADD COLUMN per statement.
        for mut column in columns() {
            manager
                .alter_table(
                    Table::alter()
                        .table(Alias::new(TABLE))
                        .add_column(&mut column)
                        .to_owned(),
                )
                .await?;
        }
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for column in [
            "encrypted_headers_format",
            "encrypted_headers",
            "header_names_json",
        ] {
            manager
                .alter_table(
                    Table::alter()
                        .table(Alias::new(TABLE))
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
    use crate::migrations::Migrator;
    use sea_orm::{ConnectionTrait, Database, DbBackend, EntityTrait, Statement};
    use sea_orm_migration::{MigrationName, MigratorTrait};

    #[tokio::test]
    async fn existing_subscriptions_gain_empty_headers_and_down_drops_columns() {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        // Up to just before this migration, then this one alone: the
        // erase-30 purge migrations that follow it are irreversible by
        // design, so `down` can only ever roll back this single step.
        let migrations = Migrator::migrations();
        let before = migrations
            .iter()
            .position(|migration| migration.name() == super::Migration.name())
            .unwrap();
        Migrator::up(&db, Some(before as u32)).await.unwrap();
        db.execute(Statement::from_string(
            DbBackend::Sqlite,
            "INSERT INTO hook_subscription (id, subscriber_did, space_id, target_service, \
             callback_url, encrypted_secret, encrypted_secret_format, secret_key_id, active, \
             created_at) VALUES ('sub', 'did:key:x', 'space', 'sql', 'https://a.example/h', \
             X'0102', 2, 'primary', 1, '2026-11-17T00:00:00Z')"
                .to_string(),
        ))
        .await
        .unwrap();

        Migrator::up(&db, Some(1)).await.unwrap();
        let row = crate::models::hook_subscription::Entity::find_by_id("sub")
            .one(&db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.header_names_json, None);
        assert_eq!(row.encrypted_headers, None);
        assert_eq!(row.encrypted_headers_format, 0);
        assert_eq!(row.encrypted_secret, [1, 2]);

        Migrator::down(&db, Some(1)).await.unwrap();
        let row = db
            .query_one(Statement::from_string(
                DbBackend::Sqlite,
                "SELECT * FROM hook_subscription WHERE id = 'sub'".to_string(),
            ))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            row.try_get::<Vec<u8>>("", "encrypted_secret").unwrap(),
            [1, 2]
        );
        let columns = db
            .query_all(Statement::from_string(
                DbBackend::Sqlite,
                "SELECT name FROM pragma_table_info('hook_subscription')".to_string(),
            ))
            .await
            .unwrap()
            .into_iter()
            .map(|row| row.try_get::<String>("", "name").unwrap())
            .collect::<Vec<_>>();
        assert!(columns.contains(&"encrypted_secret".to_string()));
        for dropped in [
            "header_names_json",
            "encrypted_headers",
            "encrypted_headers_format",
        ] {
            assert!(!columns.contains(&dropped.to_string()), "{dropped}");
        }
    }
}
