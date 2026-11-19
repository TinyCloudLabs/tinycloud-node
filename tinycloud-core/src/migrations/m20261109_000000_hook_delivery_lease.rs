use sea_orm_migration::prelude::*;

/// Adds the lease columns a webhook dispatcher sets when it claims a delivery.
/// Re-runnable: each column is added only where missing.
#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for column in ["lease_token", "lease_expires_at"] {
            if !manager.has_column("hook_delivery", column).await? {
                manager
                    .alter_table(
                        Table::alter()
                            .table(Alias::new("hook_delivery"))
                            .add_column(ColumnDef::new(Alias::new(column)).string().null())
                            .to_owned(),
                    )
                    .await?;
            }
        }
        Ok(())
    }

    async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
        Ok(())
    }
}
