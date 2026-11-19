//! TC-2917: a DuckDB write that races another checkpoint replacement of the
//! same database is refused as retryable contention, with the body token
//! (`unavailable_retryable`) that gives it `Retry-After` on the node and
//! `NODE_BUSY` in the SDK, not a capacity or internal error.

use std::sync::Arc;

use sea_orm::{ConnectionTrait, DbBackend, Statement};
use tempfile::TempDir;
use tinycloud_auth::{
    resolver::DID_METHODS,
    resource::SpaceId,
    ssi::{dids::DIDBuf, jwk::JWK},
};

use crate::database_artifacts::{
    chunks::ChunkLimits, ArtifactExpectation, DatabaseArtifactRepository,
    SeaOrmDatabaseArtifactRepository,
};
use crate::duckdb::{DuckDbError, DuckDbRequest, DuckDbService};

fn space(name: &str) -> SpaceId {
    let jwk = JWK::generate_ed25519().unwrap();
    let did: DIDBuf = DID_METHODS.generate(&jwk, "key").unwrap();
    SpaceId::new(did, name.parse().unwrap()).unwrap()
}

fn write(sql: &str, schema: Option<Vec<String>>) -> DuckDbRequest {
    DuckDbRequest::Execute {
        schema,
        sql: sql.into(),
        params: vec![],
    }
}

async fn count(fixture: &crate::test_support::PostgresTestSchema, sql: &str) -> i64 {
    fixture
        .conn
        .query_one(Statement::from_string(DbBackend::Postgres, sql.to_string()))
        .await
        .unwrap()
        .unwrap()
        .try_get("", "n")
        .unwrap()
}

/// The mapping alone, so a run without PostgreSQL still checks the token.
#[test]
fn replacement_busy_maps_to_unavailable_retryable() {
    let error = super::artifact_error_to_duckdb(
        crate::database_artifacts::DatabaseArtifactError::ReplacementBusy,
    );
    assert!(matches!(error, DuckDbError::Unavailable), "{error:?}");
    assert!(
        error.to_string().starts_with("unavailable_retryable: "),
        "{error}"
    );
}

#[tokio::test]
async fn postgres_chunked_duckdb_replacement_busy_is_unavailable_retryable() {
    let Some(fixture) = crate::test_support::PostgresTestSchema::new(
        "postgres_chunked_duckdb_replacement_busy_is_unavailable_retryable",
    )
    .await
    else {
        return;
    };
    let repo = Arc::new(
        SeaOrmDatabaseArtifactRepository::new(fixture.conn.clone()).with_chunk_limits(Some(
            ChunkLimits {
                artifact_bytes: 16 * 1024 * 1024,
                account_bytes: 64 * 1024 * 1024,
            },
        )),
    );
    let cache = TempDir::new().unwrap();
    let space = space("duckdb-parts-busy");
    let service = DuckDbService::new(
        cache.path().to_string_lossy().into_owned(),
        0,
        300,
        "128MB".into(),
        repo.clone(),
    );
    let execute = |request: DuckDbRequest| {
        service.execute(
            &space,
            "main",
            request,
            None,
            "tinycloud.duckdb/admin".into(),
            false,
        )
    };
    execute(write(
        "INSERT INTO items VALUES (1)",
        Some(vec!["CREATE TABLE items(id INTEGER)".into()]),
    ))
    .await
    .unwrap();
    let base = repo
        .load_meta("duckdb", &space.to_string(), "main")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(base.storage_mode, "checkpoint-parts-v1");

    // Another replacement of the same database holds its reservation, sealed
    // but unpublished, at the publish barrier.
    let mut racing = (*repo).clone();
    racing.chunk_publish_barrier = Some(Arc::new(tokio::sync::Barrier::new(2)));
    let target = space.to_string();
    let upload = tokio::spawn(async move {
        let mut snapshot = tempfile::NamedTempFile::new().unwrap();
        std::io::Write::write_all(&mut snapshot, &[9; 1024]).unwrap();
        racing
            .save_snapshot(
                "duckdb",
                &target,
                "main",
                snapshot,
                ArtifactExpectation::Derived {
                    revision: base.revision,
                    checkpoint_content_hash: base.checkpoint_content_hash,
                },
            )
            .await
    });
    let until = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    while count(
        &fixture,
        "SELECT count(*)::bigint AS n FROM artifact_part WHERE state='sealed'",
    )
    .await
        == 0
    {
        assert!(
            tokio::time::Instant::now() < until,
            "racing part never sealed"
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }

    let refused = execute(write("INSERT INTO items VALUES (2)", None)).await;
    let Err(error) = refused else {
        panic!("a write racing a replacement must be refused: {refused:?}");
    };
    assert!(matches!(error, DuckDbError::Unavailable), "{error:?}");
    assert!(
        error.to_string().starts_with("unavailable_retryable: "),
        "{error}"
    );

    // Retryable means retryable: once the other replacement is gone the same
    // write succeeds.
    upload.abort();
    assert!(upload.await.unwrap_err().is_cancelled());
    let until = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    while count(
        &fixture,
        "SELECT count(*)::bigint AS n FROM artifact_part WHERE state<>'published'",
    )
    .await
        != 0
    {
        assert!(
            tokio::time::Instant::now() < until,
            "aborted part never reclaimed"
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    execute(write("INSERT INTO items VALUES (2)", None))
        .await
        .unwrap();
    service
        .discard_local_state(&(space.to_string(), "main".into()))
        .await
        .unwrap();
}
