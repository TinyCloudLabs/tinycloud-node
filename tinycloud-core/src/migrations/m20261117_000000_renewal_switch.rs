use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(DeriveIden)]
enum RenewalSwitch {
    Table,
    Id,
    Paused,
    ChangedAt,
}

/// The node-wide renewal STOP-ALL switch: one row, seeded as running, so the
/// stamp transaction can always lock it and the deploy changes nothing.
#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(RenewalSwitch::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(RenewalSwitch::Id)
                            .integer()
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(RenewalSwitch::Paused).boolean().not_null())
                    .col(
                        ColumnDef::new(RenewalSwitch::ChangedAt)
                            .big_integer()
                            .null(),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .exec_stmt(
                Query::insert()
                    .into_table(RenewalSwitch::Table)
                    .columns([RenewalSwitch::Id, RenewalSwitch::Paused])
                    .values_panic([1.into(), false.into()])
                    .on_conflict(
                        OnConflict::column(RenewalSwitch::Id)
                            .do_nothing()
                            .to_owned(),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(RenewalSwitch::Table).to_owned())
            .await
    }
}
