use crate::models::meeting_legacy_write_guard;
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(meeting_legacy_write_guard::Entity)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(meeting_legacy_write_guard::Column::Space)
                            .string()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(meeting_legacy_write_guard::Column::Frozen)
                            .boolean()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(meeting_legacy_write_guard::Column::Generation)
                            .big_integer()
                            .not_null()
                            .default(0),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
        // Dropping the generation would permit stale releases after a rollback.
        Err(DbErr::Custom(
            "legacy meeting guard rollback requires an explicit recovery plan".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::meeting_legacy_guard::{status, transition, FreezeStatus};
    use sea_orm::{Database, TransactionTrait};
    use tinycloud_auth::{resolver::DID_METHODS, resource::SpaceId, ssi::jwk::JWK};

    #[tokio::test]
    async fn legacy_freeze_migration_rollback_preserves_frozen_and_released_generation() {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        let schema = SchemaManager::new(&db);
        Migration.up(&schema).await.unwrap();
        let space = SpaceId::new(
            DID_METHODS
                .generate(&JWK::generate_ed25519().unwrap(), "key")
                .unwrap(),
            "legacy-freeze-rollback".parse().unwrap(),
        );

        for (frozen, generation) in [(true, 1), (false, 2)] {
            let tx = db.begin().await.unwrap();
            transition(&tx, &space, frozen, generation - 1)
                .await
                .unwrap();
            tx.commit().await.unwrap();
            let expected = FreezeStatus { frozen, generation };
            assert_eq!(status(&db, &space).await.unwrap(), expected);

            let error = Migration.down(&schema).await.unwrap_err();
            assert!(matches!(error, DbErr::Custom(message) if message ==
                "legacy meeting guard rollback requires an explicit recovery plan"));
            assert!(schema
                .has_table("meeting_legacy_write_guard")
                .await
                .unwrap());
            assert_eq!(status(&db, &space).await.unwrap(), expected);

            Migration.up(&schema).await.unwrap();
            assert_eq!(status(&db, &space).await.unwrap(), expected);
        }
    }
}
