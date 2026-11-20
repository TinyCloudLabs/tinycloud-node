use sea_orm_migration::prelude::*;

use crate::root_wrap::RootWrap;

#[derive(DeriveMigrationName)]
pub struct Migration;

/// TC-3554: the sealed node identity root (`crate::root_wrap`). A
/// `DstackKmsEpoch` node creates the table itself before its identity check,
/// ahead of every other migration, so this is a no-op there; it records the
/// table in the migration history and creates it for every other node.
#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager.create_table(crate::root_wrap::create_table()).await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(RootWrap::Table).to_owned())
            .await
    }
}
