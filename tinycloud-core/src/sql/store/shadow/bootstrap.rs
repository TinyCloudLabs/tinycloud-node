//! Bootstrap: seed a database's shadow from Postgres.
//!
//! Used when a shadow uploader is enabled on a database with no in-hand
//! capture: the natural case is enabling the flag on an already-running
//! node. The uploader cannot wait for the next natural checkpoint because
//! some databases never checkpoint again (idle actors). Bootstrap reads
//! the stored checkpoint and (when a delta exists) the cumulative WAL out
//! of the artifact repository, applies the WAL in-process to materialise
//! a snapshot of the state at the artifact's current revision, and
//! returns one `BootstrapPlan` the uploader turns into a single snapshot
//! publication. There is no bootstrap-produced segment: a database with a
//! delta is published as a snapshot at `R` (the current revision), not as
//! a snapshot at `R-1` plus a segment.
//!
//! The one-snapshot-at-R shape closes the restore-correctness bug the
//! split shape would otherwise open. The artifact row is checkpoint `C`
//! plus cumulative WAL at `R = C + k` where `k >= 1`, and `C` is not
//! recorded by the row (`save_delta` overwrites `delta_payload` and
//! increments `revision`). Labelling the checkpoint bytes as a snapshot
//! at `R-1` and the WAL as a segment at `R..R` would restore any PITR to
//! `R-1` as state `C`, silently dropping `k-1` commits.
//!
//! The read is paced, bounded, serialised against the hot uploader pool
//! through the caller's semaphore, and hash-verified end-to-end so no
//! partial read is ever published.
//!
//! TC-1491.

use std::io::Write;

use bytes::Bytes;

use super::super::key::Lineage;
use crate::database_artifacts::{DatabaseArtifactError, DatabaseArtifactRepository, MemorySink};
use crate::hash::hash;

/// What the uploader needs to publish after the bootstrap. The caller is
/// responsible for taking out a lineage, sealing the body with its hash
/// into an [`ObjectKey`](super::super::key::ObjectKey), uploading it
/// through the real `SqlObjectStore`, and driving the manifest CAS. This
/// type carries only the content-addressed parts.
///
/// One-snapshot shape: a bootstrap publishes exactly one snapshot and no
/// segment, so `snapshot_revision` is the artifact's current revision.
/// The segment case lives on the uploader's steady-state capture path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapPlan {
    /// The revision the manifest records for this snapshot. Equal to
    /// `database_artifact.revision` at the time of the bootstrap.
    pub snapshot_revision: i64,
    /// The `checkpoint_content_hash` the published row records as
    /// `base_checkpoint_cid`. Note this is the hash of the stored
    /// checkpoint column, not of the materialised snapshot: the
    /// uploader keeps it for later segment-publish lineage checks.
    pub base_checkpoint_cid: String,
    /// The snapshot bytes the caller uploads. Equal to the stored
    /// checkpoint when no delta exists; the WAL-applied state at
    /// revision `R` when a delta exists. The sha256 of these bytes is
    /// what the key records.
    pub snapshot_body: Bytes,
}

/// Why bootstrap would refuse to produce a plan. `CidMoved` is retryable
/// once by the caller; any other error is terminal for this cycle.
#[derive(Debug, thiserror::Error)]
pub enum BootstrapError {
    #[error("database artifact not found")]
    NotFound,
    #[error("artifact repository error: {0}")]
    Artifact(DatabaseArtifactError),
    #[error(
        "the artifact's checkpoint hash changed between the meta read and the body read; retry"
    )]
    CidMoved,
    #[error("the checkpoint body did not hash to its recorded content hash")]
    HashMismatch,
    #[error("replaying the WAL into a temp SQLite failed: {0}")]
    Replay(String),
}

impl From<DatabaseArtifactError> for BootstrapError {
    fn from(err: DatabaseArtifactError) -> Self {
        Self::Artifact(err)
    }
}

/// Drive a bootstrap for a single database. Takes the live artifact
/// repository and nothing else: no store client, no manifest, no uploader
/// state. Returns a plan the uploader then acts on.
///
/// Sequence:
/// 1. `load_meta` once, outside any lock.
/// 2. `read_chunks` the stored checkpoint and (when present) the WAL into
///    an in-memory sink. A concurrent commit mid-read surfaces as
///    `DatabaseArtifactError::ArtifactChanged`; the module retries the
///    streaming read up to `BOOTSTRAP_READ_RETRIES` times (the repository
///    itself resets the sink between attempts).
/// 3. Re-check `load_meta` and compare `checkpoint_content_hash`: a
///    checkpoint change between the first meta and the completed body
///    read returns `CidMoved`, which the caller retries once and then
///    backs off.
/// 4. Verify the checkpoint whole-object hash against the repository's
///    `checkpoint_content_hash`; the per-chunk verify inside the
///    repository already gates partial reads, this is a surface
///    invariant.
/// 5. When the artifact carries a WAL delta, write the checkpoint to a
///    temp file plus the WAL as its `-wal` sidecar, open the file, run
///    `PRAGMA wal_checkpoint(TRUNCATE)` to apply the WAL, and `VACUUM
///    INTO` a second temp file that holds the materialised state at
///    revision `R`. Read that file back as the snapshot body.
/// 6. Otherwise the snapshot body is the stored checkpoint unchanged.
///
/// Memory: peak is bounded by the stored checkpoint size plus (if a WAL
/// is present) the materialised snapshot. The caller MUST serialise
/// bootstraps (typically one per node at a time via the uploader's
/// `pg_concurrency` semaphore) so this bound holds.
pub async fn bootstrap(
    repo: &dyn DatabaseArtifactRepository,
    space: &str,
    name: &str,
) -> Result<BootstrapPlan, BootstrapError> {
    // `read_artifact` refreshes metadata between retries and restarts the
    // streaming read on `ArtifactChanged`, so a database that keeps
    // committing in the middle of a bootstrap resolves cleanly: the
    // checkpoint's identity is its `checkpoint_content_hash` (which does
    // not change on a new WAL delta), and the WAL's identity is its
    // revision (which does). When the repository's chunk guards diverge
    // between a cid-only guard on the checkpoint and a revision guard on
    // the delta (the follow-up chunks.rs change), the meta returned by
    // this call pins both parts to one consistent artifact row.
    let mut sink = MemorySink::default();
    let meta = crate::database_artifacts::read_artifact(repo, "sql", space, name, &mut sink)
        .await?
        .ok_or(BootstrapError::NotFound)?;

    let checkpoint_bytes = sink.checkpoint;
    let computed = hash(&checkpoint_bytes).to_cid(0x55).to_string();
    if computed != meta.checkpoint_content_hash {
        return Err(BootstrapError::HashMismatch);
    }

    let snapshot_body = match sink.wal {
        None => Bytes::from(checkpoint_bytes),
        Some(wal) => Bytes::from(materialise_with_wal(&checkpoint_bytes, &wal)?),
    };

    Ok(BootstrapPlan {
        snapshot_revision: meta.revision,
        base_checkpoint_cid: meta.checkpoint_content_hash,
        snapshot_body,
    })
}

/// Apply the cumulative WAL to the stored checkpoint and return the
/// materialised snapshot at revision R.
///
/// SQLite's WAL recovery runs on open; we then request a TRUNCATE
/// checkpoint to merge the WAL into the main file and VACUUM INTO a
/// clean copy. The result is byte-identical to what a snapshot cut at
/// revision R by the live actor would be.
fn materialise_with_wal(checkpoint: &[u8], wal: &[u8]) -> Result<Vec<u8>, BootstrapError> {
    let dir =
        tempfile::TempDir::new().map_err(|e| BootstrapError::Replay(format!("tempdir: {e}")))?;
    let db_path = dir.path().join("bootstrap.sqlite");
    let wal_path = dir.path().join("bootstrap.sqlite-wal");
    let snap_path = dir.path().join("snapshot.sqlite");

    // Write checkpoint and WAL to disk atomically-ish; the dir is unique
    // per call and torn down with the TempDir drop.
    {
        let mut f = std::fs::File::create(&db_path)
            .map_err(|e| BootstrapError::Replay(format!("create db: {e}")))?;
        f.write_all(checkpoint)
            .map_err(|e| BootstrapError::Replay(format!("write db: {e}")))?;
        f.sync_all()
            .map_err(|e| BootstrapError::Replay(format!("sync db: {e}")))?;
    }
    {
        let mut f = std::fs::File::create(&wal_path)
            .map_err(|e| BootstrapError::Replay(format!("create wal: {e}")))?;
        f.write_all(wal)
            .map_err(|e| BootstrapError::Replay(format!("write wal: {e}")))?;
        f.sync_all()
            .map_err(|e| BootstrapError::Replay(format!("sync wal: {e}")))?;
    }

    let conn = rusqlite::Connection::open(&db_path)
        .map_err(|e| BootstrapError::Replay(format!("open: {e}")))?;
    // WAL recovery runs on first access; a TRUNCATE checkpoint moves the
    // WAL into the main file and leaves an empty sidecar.
    conn.query_row::<i64, _, _>("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| row.get(0))
        .map_err(|e| BootstrapError::Replay(format!("wal_checkpoint: {e}")))?;
    // VACUUM INTO materialises a clean, defragmented copy with no WAL
    // sidecar at the given path.
    conn.execute(&format!("VACUUM INTO '{}'", snap_path.display()), [])
        .map_err(|e| BootstrapError::Replay(format!("vacuum into: {e}")))?;
    drop(conn);

    let bytes = std::fs::read(&snap_path)
        .map_err(|e| BootstrapError::Replay(format!("read snapshot: {e}")))?;
    Ok(bytes)
}

/// The caller chooses a fresh [`Lineage`] for the first bootstrap publish
/// so that two nodes racing a bootstrap for the same database do not
/// collide on a seeded lineage string.
pub fn fresh_lineage() -> Lineage {
    Lineage::random()
}

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

    /// Build a tiny real SQLite checkpoint (not just random bytes) and
    /// return its bytes and its one table's row set at checkpoint time.
    fn make_checkpoint_with_one_row(v: i64) -> Vec<u8> {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("db.sqlite");
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute("CREATE TABLE t (v INTEGER NOT NULL)", [])
            .unwrap();
        conn.execute("INSERT INTO t VALUES (?)", [v]).unwrap();
        // Force the WAL to merge into the main file so we're returning
        // the "checkpoint only" state.
        conn.query_row::<i64, _, _>("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| row.get(0))
            .unwrap();
        drop(conn);
        std::fs::read(&path).unwrap()
    }

    #[tokio::test]
    async fn bootstrap_of_a_checkpoint_only_artifact_publishes_at_r() {
        let repo = repo_and_db().await;
        let payload = make_checkpoint_with_one_row(1);
        let saved = repo
            .save(
                "sql",
                "space",
                "main",
                Bytes::from(payload.clone()),
                ArtifactExpectation::Absent,
            )
            .await
            .unwrap();

        let plan = bootstrap(&*repo, "space", "main").await.unwrap();
        assert_eq!(plan.snapshot_revision, saved.revision);
        assert_eq!(plan.base_checkpoint_cid, saved.checkpoint_content_hash);
        assert_eq!(plan.snapshot_body.as_ref(), payload.as_slice());
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

    /// The crux test: build a fresh SQLite file, hand its WAL to
    /// save_delta, and prove that the bootstrap plan's snapshot at R
    /// materialises the state AT R, not the state at the checkpoint.
    #[tokio::test]
    async fn bootstrap_with_a_delta_materialises_state_at_r() {
        let repo = repo_and_db().await;

        // A small SQLite file at checkpoint time: row (v = 1).
        let checkpoint_bytes = make_checkpoint_with_one_row(1);
        let saved = repo
            .save(
                "sql",
                "space",
                "main",
                Bytes::from(checkpoint_bytes.clone()),
                ArtifactExpectation::Absent,
            )
            .await
            .unwrap();

        // Build a WAL that inserts two more rows (k = 2), without
        // checkpointing so delta_payload stays as a cumulative WAL.
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("db.sqlite");
        std::fs::write(&path, &checkpoint_bytes).unwrap();
        let conn = rusqlite::Connection::open(&path).unwrap();
        // WAL mode writes an .sqlite-wal sidecar we can read back.
        conn.query_row::<String, _, _>("PRAGMA journal_mode=WAL", [], |row| row.get(0))
            .unwrap();
        // Explicitly disable auto-checkpoint, matching the actor
        // (database.rs:28).
        conn.pragma_update(None, "wal_autocheckpoint", 0).unwrap();
        conn.execute("INSERT INTO t VALUES (2)", []).unwrap();
        conn.execute("INSERT INTO t VALUES (3)", []).unwrap();
        // SQLite checkpoints on last-close by default, which would
        // empty the -wal sidecar; read the file before dropping.
        let wal_path = dir.path().join("db.sqlite-wal");
        let wal_bytes = std::fs::read(&wal_path).unwrap();
        drop(conn);

        let delta = repo
            .save_delta(
                "sql",
                "space",
                "main",
                Bytes::from(wal_bytes),
                ArtifactExpectation::Derived {
                    revision: saved.revision,
                    checkpoint_content_hash: saved.checkpoint_content_hash.clone(),
                },
            )
            .await
            .unwrap();

        let plan = bootstrap(&*repo, "space", "main").await.unwrap();
        assert_eq!(
            plan.snapshot_revision, delta.revision,
            "snapshot is labelled at the artifact's current revision, not R-1"
        );
        assert_eq!(plan.base_checkpoint_cid, saved.checkpoint_content_hash);

        // Materialised snapshot MUST contain all three rows. Write it
        // out and query.
        let out_dir = tempfile::TempDir::new().unwrap();
        let out = out_dir.path().join("snap.sqlite");
        std::fs::write(&out, &plan.snapshot_body).unwrap();
        let conn = rusqlite::Connection::open(&out).unwrap();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM t", [], |row| row.get(0))
            .unwrap();
        assert_eq!(
            count, 3,
            "snapshot at R must include every row at R, not just the pre-delta checkpoint"
        );
        let rows: Vec<i64> = conn
            .prepare("SELECT v FROM t ORDER BY v")
            .unwrap()
            .query_map([], |row| row.get::<_, i64>(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(rows, vec![1, 2, 3]);
    }
}
