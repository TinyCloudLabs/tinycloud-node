use sea_orm_migration::prelude::*;
#[derive(DeriveMigrationName)]
pub struct Migration;
#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager.get_connection().execute_unprepared("CREATE TABLE storage_rekey (id INTEGER PRIMARY KEY, target INTEGER NOT NULL, column_index INTEGER NOT NULL, cursor TEXT NULL, rewritten BIGINT NOT NULL, complete BOOLEAN NOT NULL)").await?;
        manager
            .get_connection()
            .execute_unprepared("INSERT INTO storage_rekey VALUES (1,0,0,NULL,0,FALSE)")
            .await?;
        Ok(())
    }
    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();
        let state = db
            .query_one(sea_orm::Statement::from_string(
                db.get_database_backend(),
                "SELECT target FROM storage_rekey WHERE id=1",
            ))
            .await?
            .ok_or_else(|| DbErr::Custom("missing storage fence".into()))?;
        if state.try_get::<i32>("", "target")? != 0 {
            return Err(DbErr::Custom(
                "activated storage rekey fencing cannot be downgraded".into(),
            ));
        }
        db.execute_unprepared("DROP TABLE storage_rekey").await?;
        Ok(())
    }
}
