use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(DeriveIden)]
enum RenewalIdentity {
    Table,
    Id,
    RenewerDid,
    Epoch,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(RenewalIdentity::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(RenewalIdentity::Id)
                            .integer()
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(RenewalIdentity::RenewerDid).string().null())
                    .col(
                        ColumnDef::new(RenewalIdentity::Epoch)
                            .big_integer()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(RenewalIdentity::Table).to_owned())
            .await
    }
}
