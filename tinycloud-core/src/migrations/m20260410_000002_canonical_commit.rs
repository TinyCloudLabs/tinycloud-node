use crate::models::canonical_commit;
use sea_orm::Schema;
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let schema = Schema::new(manager.get_database_backend());

        manager
            .create_table(schema.create_table_from_entity(canonical_commit::Entity))
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx-kv-canonical-commit-space-key-seq")
                    .table(canonical_commit::Entity)
                    .col(canonical_commit::Column::Space)
                    .col(canonical_commit::Column::Key)
                    .col(canonical_commit::Column::Seq)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx-kv-canonical-commit-space-invocation")
                    .table(canonical_commit::Entity)
                    .col(canonical_commit::Column::Space)
                    .col(canonical_commit::Column::InvocationId)
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(canonical_commit::Entity).to_owned())
            .await
    }
}
