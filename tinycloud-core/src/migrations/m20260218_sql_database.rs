use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(Iden)]
enum SqlDatabase {
    Table,
    Space,
    Name,
    CreatedAt,
    SizeBytes,
    StorageMode,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(SqlDatabase::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(SqlDatabase::Space).string().not_null())
                    .col(ColumnDef::new(SqlDatabase::Name).string().not_null())
                    .col(
                        ColumnDef::new(SqlDatabase::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(SqlDatabase::SizeBytes)
                            .big_integer()
                            .not_null()
                            .default(0),
                    )
                    .col(
                        ColumnDef::new(SqlDatabase::StorageMode)
                            .string()
                            .not_null()
                            .default("memory"),
                    )
                    .primary_key(
                        Index::create()
                            .col(SqlDatabase::Space)
                            .col(SqlDatabase::Name),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(SqlDatabase::Table).to_owned())
            .await
    }
}
