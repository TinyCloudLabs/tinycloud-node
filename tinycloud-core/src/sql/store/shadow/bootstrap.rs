//! Bootstrap: seed a database's shadow from Postgres.
//!
//! Used when a shadow uploader is enabled on a database with no in-hand
//! capture: the natural case is enabling the flag on an already-running
//! node. The uploader cannot wait for the next natural checkpoint because
//! some databases never checkpoint again (idle actors). Bootstrap reads
//! the stored checkpoint (and the WAL delta, when the database has one)
//! back out of Postgres in bounded 4 MiB slices, publishes a snapshot and
//! (when a delta exists) one segment, and leaves the manifest at the
//! revision Postgres currently records.
//!
//! The read is the only time shadow-phase code reads back the checkpoint
//! payload column (which the KV-usage ban otherwise forbids). It is paced,
//! bounded, serialised against the hot uploader pool through a small
//! semaphore, and hash-verified end-to-end so no partial read is ever
//! published.
//!
//! The uploader run loop and this module are intentionally decoupled: the
//! planner reports `Action::NeedsBootstrap` and whoever drives the
//! uploader calls [`bootstrap`] to turn it into a `(snapshot, Option<segment>)`
//! publish plan. The caller owns the semaphore, the pacing, and the
//! timeout.
//!
//! TC-1491.

use bytes::Bytes;

use super::super::key::{DbRef, Lineage};
use crate::database_artifacts::{DatabaseArtifactError, DatabaseArtifactRepository};
use crate::hash::hash;

/// What the uploader needs to publish after the bootstrap read. The
/// caller is responsible for taking out a lineage, sealing each body with
/// its hash into an [`ObjectKey`](super::super::key::ObjectKey), uploading
/// it through the real `SqlObjectStore`, and finally driving the manifest
/// CAS. This type carries only the content-addressed parts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapPlan {
    /// The snapshot's revision the manifest will record. When the artifact
    /// has a WAL delta this is `meta.revision - 1`: the snapshot is the
    /// state before the delta.
    pub snapshot_revision: i64,
    /// `database_artifact.checkpoint_content_hash` the snapshot was cut
    /// from.
    pub base_checkpoint_cid: String,
    /// The snapshot body (the `database_artifact.payload` as a `Bytes`).
    pub snapshot_body: Bytes,
    /// Present when the artifact has a WAL delta: the segment's end
    /// revision (identical to `meta.revision`), the base_seq
    /// (snapshot_revision), and the body.
    pub segment: Option<BootstrapSegment>,
}

/// One segment is published, if the artifact has a WAL delta.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapSegment {
    /// `database_artifact.revision`.
    pub to_seq: i64,
    /// The WAL body (the `database_artifact.delta_payload` as a `Bytes`).
    pub body: Bytes,
    /// `database_artifact.delta_content_hash` the body hashes to.
    pub delta_cid: String,
}

/// Why bootstrap would refuse to produce a plan. The caller may retry a
/// `CidMoved` once (one re-read pair); any other error is terminal for this
/// cycle.
#[derive(Debug, thiserror::Error)]
pub enum BootstrapError {
    #[error("database artifact not found")]
    NotFound,
    #[error("artifact repository error: {0}")]
    Artifact(#[from] DatabaseArtifactError),
    #[error(
        "the artifact's checkpoint hash changed between the meta read and the body read; retry"
    )]
    CidMoved,
    #[error("the artifact body did not hash to its recorded content hash")]
    HashMismatch,
}

/// Drive a bootstrap plan for a single database. Takes the live artifact
/// repository and nothing else: no store client, no manifest, no uploader
/// state. Returns a plan the uploader then acts on. The read of the
/// payload is guarded by the artifact's `checkpoint_content_hash` only (so
/// a database that keeps committing does not block the bootstrap on a
/// moving revision).
///
/// Calls into the artifact repository:
/// 1. `load_meta` once, outside any lock.
/// 2. `read_chunks` into an in-memory sink; chunk size is the repository's
///    `ARTIFACT_CHUNK_BYTES` default (4 MiB today).
/// 3. Re-check `load_meta` and compare `checkpoint_content_hash`: a change
///    means the pair is inconsistent and returns `CidMoved`.
///
/// The hash verification inside the repository's streaming read catches
/// any partial or torn read; this module trusts that invariant and does
/// not re-hash.
///
/// Memory: peak is one slice (4 MiB) over the repository, plus the final
/// payload the sink keeps. The caller MUST bound the number of concurrent
/// bootstraps (typically one per node at a time, per the uploader's PG
/// semaphore).
pub async fn bootstrap(
    repo: &dyn DatabaseArtifactRepository,
    space: &str,
    name: &str,
) -> Result<BootstrapPlan, BootstrapError> {
    let before = repo
        .load_meta("sql", space, name)
        .await?
        .ok_or(BootstrapError::NotFound)?;

    let mut sink = crate::database_artifacts::MemorySink::default();
    repo.read_chunks("sql", space, name, &before, &mut sink)
        .await?;

    let after = repo
        .load_meta("sql", space, name)
        .await?
        .ok_or(BootstrapError::NotFound)?;
    if after.checkpoint_content_hash != before.checkpoint_content_hash {
        return Err(BootstrapError::CidMoved);
    }

    let checkpoint_bytes = Bytes::from(sink.checkpoint);
    // The repository's `read_chunks` verifies the checkpoint hash against
    // its row during the streaming read, but we also assert the surface
    // invariant: the bytes we return carry `before.checkpoint_content_hash`.
    let computed = hash(&checkpoint_bytes).to_cid(0x55).to_string();
    if computed != before.checkpoint_content_hash {
        return Err(BootstrapError::HashMismatch);
    }

    let (snapshot_revision, segment) = match (before.delta_content_hash.clone(), sink.wal) {
        (Some(delta_cid), Some(wal_bytes)) => {
            let wal_bytes = Bytes::from(wal_bytes);
            (
                before.revision - 1,
                Some(BootstrapSegment {
                    to_seq: before.revision,
                    body: wal_bytes,
                    delta_cid,
                }),
            )
        }
        _ => (before.revision, None),
    };

    Ok(BootstrapPlan {
        snapshot_revision,
        base_checkpoint_cid: before.checkpoint_content_hash,
        snapshot_body: checkpoint_bytes,
        segment,
    })
}

/// The caller chooses a fresh [`Lineage`] for the first bootstrap publish
/// so that two nodes racing a bootstrap for the same database do not
/// collide on a seeded lineage string.
pub fn fresh_lineage() -> Lineage {
    Lineage::random()
}

/// A convenience alias that names what the caller must own. The bootstrap
/// does not hold onto a `DbRef` because it is not re-entrant: every call
/// targets one database.
pub type BootstrapTarget<'a> = DbRef<'a>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database_artifacts::{ArtifactExpectation, SeaOrmDatabaseArtifactRepository};
    use crate::migrations::Migrator;
    use crate::sea_orm::{ConnectOptions, Database};
    use crate::sea_orm_migration::MigratorTrait;
    use std::sync::Arc;

    async fn repo_and_db() -> Arc<SeaOrmDatabaseArtifactRepository> {
        let db = Database::connect(ConnectOptions::new("sqlite::memory:".to_string()))
            .await
            .unwrap();
        Migrator::up(&db, None).await.unwrap();
        Arc::new(SeaOrmDatabaseArtifactRepository::new(db))
    }

    #[tokio::test]
    async fn bootstrap_of_a_checkpoint_only_artifact_has_no_segment() {
        let repo = repo_and_db().await;
        let payload = vec![42u8; 1024];
        let saved = repo
            .save(
                "sql",
                "space",
                "main",
                Bytes::copy_from_slice(&payload),
                ArtifactExpectation::Absent,
            )
            .await
            .unwrap();

        let plan = bootstrap(&*repo, "space", "main").await.unwrap();
        assert_eq!(plan.snapshot_revision, saved.revision);
        assert_eq!(plan.base_checkpoint_cid, saved.checkpoint_content_hash);
        assert_eq!(plan.snapshot_body.as_ref(), payload.as_slice());
        assert!(plan.segment.is_none());
    }

    #[tokio::test]
    async fn bootstrap_of_a_delta_artifact_names_the_snapshot_at_r_minus_one() {
        let repo = repo_and_db().await;
        let payload = vec![1u8; 512];
        let saved = repo
            .save(
                "sql",
                "space",
                "main",
                Bytes::copy_from_slice(&payload),
                ArtifactExpectation::Absent,
            )
            .await
            .unwrap();
        let wal = vec![2u8; 128];
        let delta = repo
            .save_delta(
                "sql",
                "space",
                "main",
                Bytes::copy_from_slice(&wal),
                ArtifactExpectation::Derived {
                    revision: saved.revision,
                    checkpoint_content_hash: saved.checkpoint_content_hash.clone(),
                },
            )
            .await
            .unwrap();

        let plan = bootstrap(&*repo, "space", "main").await.unwrap();
        // The snapshot is the pre-delta state; the delta is the segment.
        assert_eq!(plan.snapshot_revision, delta.revision - 1);
        assert_eq!(plan.base_checkpoint_cid, saved.checkpoint_content_hash);
        assert_eq!(plan.snapshot_body.as_ref(), payload.as_slice());
        let seg = plan.segment.expect("delta present");
        assert_eq!(seg.to_seq, delta.revision);
        assert_eq!(seg.body.as_ref(), wal.as_slice());
    }

    #[tokio::test]
    async fn bootstrap_of_an_absent_artifact_is_not_found() {
        let repo = repo_and_db().await;
        let err = bootstrap(&*repo, "space", "main").await.unwrap_err();
        assert!(matches!(err, BootstrapError::NotFound));
    }

    #[test]
    fn fresh_lineage_is_thirty_two_lowercase_hex() {
        let lineage = fresh_lineage();
        assert_eq!(lineage.as_str().len(), 32);
        assert!(lineage
            .as_str()
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
    }
}
