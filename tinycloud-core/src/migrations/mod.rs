use sea_orm_migration::prelude::*;
pub mod m20230510_101010_init_tables;
pub mod m20260218_sql_database;
pub mod m20260410_000001_kv_quarantine;
pub mod m20260410_000002_canonical_commit;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20230510_101010_init_tables::Migration),
            Box::new(m20260410_000001_kv_quarantine::Migration),
            Box::new(m20260410_000002_canonical_commit::Migration),
            Box::new(m20260218_sql_database::Migration),
        ]
    }
}
