use sea_orm_migration::prelude::*;
pub mod m20230510_101010_init_tables;
pub mod m20260218_sql_database;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20230510_101010_init_tables::Migration),
            Box::new(m20260218_sql_database::Migration),
        ]
    }
}
