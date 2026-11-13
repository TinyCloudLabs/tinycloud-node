//! TC-2917: compressed TOAST makes repeated bytea slices decompress growing prefixes.
//! Catalog-only: existing values are deliberately left to the operator re-toast script.
//! Lock contention defers this optimisation without preventing service startup;
//! operators apply the catalog setting separately before running the rewrite.
use sea_orm::{ConnectionTrait, DbBackend};
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if manager.get_database_backend() != DbBackend::Postgres {
            return Ok(());
        }
        // Each exception block is a subtransaction: a lock timeout releases
        // its locks before retrying. Restore the caller's transaction setting.
        manager
            .get_connection()
            .execute_unprepared(
                r#"
DO $$
DECLARE previous_timeout text := current_setting('lock_timeout');
BEGIN
    PERFORM set_config('lock_timeout', '500ms', true);
    FOR attempt IN 1..3 LOOP
        BEGIN
            ALTER TABLE database_artifact
                ALTER COLUMN payload SET STORAGE EXTERNAL,
                ALTER COLUMN delta_payload SET STORAGE EXTERNAL;
            EXIT;
        EXCEPTION WHEN lock_not_available THEN
            IF attempt = 3 THEN
                RAISE WARNING 'TC-2917: artifact EXTERNAL storage deferred due to lock contention; migration recorded, operator must apply storage settings before re-toast (scripts/tc2917-README.md)';
                EXIT;
            END IF;
            PERFORM pg_sleep(0.1);
        END;
    END LOOP;
    PERFORM set_config('lock_timeout', previous_timeout, true);
END $$;
"#,
            )
            .await?;
        Ok(())
    }

    async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
        Err(DbErr::Migration(
            "TC-2917 storage migration is forward-only".into(),
        ))
    }
}
