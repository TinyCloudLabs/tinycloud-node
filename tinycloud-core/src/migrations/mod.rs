use sea_orm_migration::prelude::*;
pub mod m20230510_101010_init_tables;
pub mod m20260218_sql_database;
pub mod m20260409_000000_hook_tables;
pub mod m20260512_000000_signed_kv_tickets;
pub mod m20260516_000000_database_artifacts;
pub mod m20260601_000000_encryption_networks;
pub mod m20260602_000000_rename_encryption_owner_did;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20230510_101010_init_tables::Migration),
            Box::new(m20260218_sql_database::Migration),
            Box::new(m20260409_000000_hook_tables::Migration),
            Box::new(m20260512_000000_signed_kv_tickets::Migration),
            Box::new(m20260516_000000_database_artifacts::Migration),
            Box::new(m20260601_000000_encryption_networks::Migration),
            Box::new(m20260602_000000_rename_encryption_owner_did::Migration),
        ]
    }
}
