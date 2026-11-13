use sea_orm::{ConnectionTrait, DbBackend, Statement};
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if manager.get_database_backend() != DbBackend::Postgres {
            return Ok(());
        }
        let conn = manager.get_connection();
        let previous: String = conn
            .query_one(Statement::from_string(
                DbBackend::Postgres,
                "SHOW lock_timeout".to_string(),
            ))
            .await?
            .ok_or_else(|| DbErr::Migration("missing lock timeout".into()))?
            .try_get("", "lock_timeout")?;
        conn.execute_unprepared("SET LOCAL lock_timeout = '500ms'")
            .await?;
        manager
            .get_connection()
            .execute_unprepared(
                r#"
CREATE TABLE artifact_account (
    owner text PRIMARY KEY,
    reserved_bytes bigint NOT NULL DEFAULT 0 CHECK(reserved_bytes >= 0)
);
CREATE TABLE artifact_part (
    service text NOT NULL, space text NOT NULL, name text NOT NULL,
    part_id text NOT NULL, owner text NOT NULL REFERENCES artifact_account(owner),
    size_bytes bigint NOT NULL CHECK(size_bytes >= 0),
    content_hash text, chunk_count integer NOT NULL CHECK(chunk_count >= 0),
    sealed boolean NOT NULL DEFAULT false,
    PRIMARY KEY(service, space, name, part_id)
);
CREATE TABLE artifact_chunk (
    service text NOT NULL, space text NOT NULL, name text NOT NULL,
    part_id text NOT NULL, ordinal integer NOT NULL CHECK(ordinal >= 0),
    payload bytea NOT NULL CHECK(octet_length(payload) BETWEEN 1 AND 1048576),
    PRIMARY KEY(service, space, name, part_id, ordinal),
    FOREIGN KEY(service, space, name, part_id)
      REFERENCES artifact_part(service, space, name, part_id)
);
ALTER TABLE artifact_chunk ALTER COLUMN payload SET STORAGE EXTERNAL;
ALTER TABLE database_artifact ADD COLUMN checkpoint_part_id text;
ALTER TABLE database_artifact ADD COLUMN delta_part_id text;
ALTER TABLE database_artifact ADD CONSTRAINT artifact_checkpoint_part_fk
    FOREIGN KEY(service, space, name, checkpoint_part_id)
    REFERENCES artifact_part(service, space, name, part_id);
ALTER TABLE database_artifact ADD CONSTRAINT artifact_delta_part_fk
    FOREIGN KEY(service, space, name, delta_part_id)
    REFERENCES artifact_part(service, space, name, part_id);
CREATE FUNCTION artifact_chunk_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP <> 'INSERT' THEN
        RAISE EXCEPTION 'artifact chunks are immutable';
    END IF;
    PERFORM 1 FROM artifact_part WHERE service=NEW.service AND space=NEW.space
      AND name=NEW.name AND part_id=NEW.part_id AND NOT sealed FOR SHARE;
    IF NOT FOUND THEN RAISE EXCEPTION 'artifact part is not uploading'; END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER artifact_chunk_guard BEFORE INSERT OR UPDATE OR DELETE ON artifact_chunk
    FOR EACH ROW EXECUTE FUNCTION artifact_chunk_guard();
"#,
            )
            .await?;
        conn.execute(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT set_config('lock_timeout', $1, true)",
            [previous.into()],
        ))
        .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if manager.get_database_backend() != DbBackend::Postgres {
            return Ok(());
        }
        Err(DbErr::Migration(
            "artifact chunk storage is forward-only".into(),
        ))
    }
}
