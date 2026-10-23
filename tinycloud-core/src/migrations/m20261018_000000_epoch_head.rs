//! TC-1274: `epoch_head`, the per-space head epochs `transact` maintains so a
//! write no longer runs the `epoch`/`epoch_order` anti-join over the space's
//! whole history.
//!
//! Only the empty table. No foreign keys: it is a derived cache that
//! validates itself (`crate::epoch_head`), and an FK to `epoch` or `space`
//! would make this `CREATE TABLE` lock those tables against writers during
//! boot. Existing spaces are filled lazily by their next write, and online by
//! the node's gentle backfill, never inside the migration transaction.

use sea_orm_migration::prelude::*;

use crate::models::epoch_head;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let mut id = ColumnDef::new(epoch_head::Column::Id);
        if manager.get_database_backend() == sea_orm::DbBackend::MySql {
            // As in m20261014: MySQL's bare BINARY is one byte and fixed-width
            // BINARY would pad the multihash.
            id.var_binary(255);
        } else {
            id.binary();
        }
        manager
            .create_table(
                Table::create()
                    .table(epoch_head::Entity)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(epoch_head::Column::Space)
                            .string()
                            .not_null(),
                    )
                    .col(id.not_null())
                    .col(
                        ColumnDef::new(epoch_head::Column::Seq)
                            .big_integer()
                            .not_null(),
                    )
                    .primary_key(
                        Index::create()
                            .col(epoch_head::Column::Space)
                            .col(epoch_head::Column::Id),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(epoch_head::Entity).to_owned())
            .await
    }
}
