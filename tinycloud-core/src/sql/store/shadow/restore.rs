//! Restore a database from the published manifest frontier.
//!
//! The uploader publishes a snapshot (and, in later slices, segments) to
//! the block store. Restore is the reverse: given the manifest's current
//! frontier, fetch the snapshot and the highest segment, verify each
//! object against its key's SHA-256, write the materialised SQLite file,
//! and run `PRAGMA integrity_check` on it. A sampling of restores is
//! what the nightly `sql-store restore-check` CLI runs.
//!
//! Restore writes the materialised file under a caller-chosen scratch
//! directory that must live under the node's SQL data directory, so the
//! bytes count against the 1a `DiskBudget` and the configured minimum
//! free headroom.
//!
//! The byte path is:
//!
//! 1. Verify the snapshot bytes hash to its key's recorded SHA-256.
//! 2. Write the snapshot to `restored.sqlite`.
//! 3. If a segment is present, verify the WAL bytes hash to the
//!    segment's recorded SHA-256, write it as `restored.sqlite-wal`.
//! 4. Open the SQLite file. WAL recovery runs on first access and
//!    merges any segment into the main file.
//! 5. `PRAGMA integrity_check` returns `ok` when the materialised state
//!    at revision R is internally consistent.
//!
//! No manifest or object-store client is linked into this module: the
//! caller supplies the already-fetched bytes. That lets the module be
//! tested without the real network path and keeps the dependency graph
//! shallow.
//!
//! TC-1491.

use std::io::Write;

/// Byte-level inputs to a restore. The caller fetched these from the
/// object store and verified they correspond to the frontier the
/// manifest named.
#[derive(Debug, Clone)]
pub struct RestoreInput {
    pub snapshot_bytes: Vec<u8>,
    pub snapshot_sha256: [u8; 32],
    /// Present when the frontier includes a segment. For shadow-phase
    /// bootstrap-materialised snapshots this is `None` (the bootstrap
    /// materialises the WAL in-process and publishes a single snapshot
    /// at R; see `shadow::bootstrap`).
    pub segment: Option<RestoreSegment>,
}

/// The highest-`to_seq` segment the frontier names, if any.
#[derive(Debug, Clone)]
pub struct RestoreSegment {
    pub bytes: Vec<u8>,
    pub sha256: [u8; 32],
}

/// What the restore reports back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RestoreReport {
    /// The restore materialised a file and `PRAGMA integrity_check`
    /// returned `ok`.
    Ok,
    /// `PRAGMA integrity_check` returned something other than `ok`. The
    /// report carries the first error line.
    IntegrityFailure { first_error: String },
}

#[derive(Debug, thiserror::Error)]
pub enum RestoreError {
    #[error("snapshot bytes did not hash to the recorded sha256")]
    SnapshotHashMismatch,
    #[error("segment bytes did not hash to the recorded sha256")]
    SegmentHashMismatch,
    #[error("io: {0}")]
    Io(String),
    #[error("rusqlite: {0}")]
    Sqlite(String),
}

/// Materialise the database under `scratch_dir` and run the integrity
/// check. The caller passes its own tokio runtime; this function is
/// synchronous and expected to be called from `spawn_blocking` if that
/// matters to the caller.
pub fn restore(
    scratch_dir: &std::path::Path,
    input: &RestoreInput,
) -> Result<RestoreReport, RestoreError> {
    if sha256(&input.snapshot_bytes) != input.snapshot_sha256 {
        return Err(RestoreError::SnapshotHashMismatch);
    }
    if let Some(seg) = &input.segment {
        if sha256(&seg.bytes) != seg.sha256 {
            return Err(RestoreError::SegmentHashMismatch);
        }
    }

    let dir = tempfile::TempDir::new_in(scratch_dir)
        .map_err(|e| RestoreError::Io(format!("tempdir: {e}")))?;
    let db_path = dir.path().join("restored.sqlite");
    let wal_path = dir.path().join("restored.sqlite-wal");
    {
        let mut f = std::fs::File::create(&db_path)
            .map_err(|e| RestoreError::Io(format!("create db: {e}")))?;
        f.write_all(&input.snapshot_bytes)
            .map_err(|e| RestoreError::Io(format!("write db: {e}")))?;
        f.sync_all()
            .map_err(|e| RestoreError::Io(format!("sync db: {e}")))?;
    }
    if let Some(seg) = &input.segment {
        let mut f = std::fs::File::create(&wal_path)
            .map_err(|e| RestoreError::Io(format!("create wal: {e}")))?;
        f.write_all(&seg.bytes)
            .map_err(|e| RestoreError::Io(format!("write wal: {e}")))?;
        f.sync_all()
            .map_err(|e| RestoreError::Io(format!("sync wal: {e}")))?;
    }

    let conn = rusqlite::Connection::open(&db_path)
        .map_err(|e| RestoreError::Sqlite(format!("open: {e}")))?;
    // Force WAL recovery / merge into the main file before the integrity
    // check, so a corrupted segment surfaces here.
    let _ = conn.query_row::<i64, _, _>("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| row.get(0));
    let mut stmt = conn
        .prepare("PRAGMA integrity_check")
        .map_err(|e| RestoreError::Sqlite(format!("prepare: {e}")))?;
    let mut rows = stmt
        .query([])
        .map_err(|e| RestoreError::Sqlite(format!("query: {e}")))?;
    let Some(first) = rows
        .next()
        .map_err(|e| RestoreError::Sqlite(format!("next: {e}")))?
    else {
        return Err(RestoreError::Sqlite(
            "integrity_check returned no rows".into(),
        ));
    };
    let first_text: String = first
        .get(0)
        .map_err(|e| RestoreError::Sqlite(format!("get: {e}")))?;
    if first_text == "ok" {
        Ok(RestoreReport::Ok)
    } else {
        Ok(RestoreReport::IntegrityFailure {
            first_error: first_text,
        })
    }
}

fn sha256(body: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(body).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a tiny real SQLite file and return its bytes.
    fn make_simple_db() -> Vec<u8> {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("db.sqlite");
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute("CREATE TABLE t (v INTEGER NOT NULL)", [])
            .unwrap();
        conn.execute("INSERT INTO t VALUES (1)", []).unwrap();
        conn.query_row::<i64, _, _>("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| row.get(0))
            .unwrap();
        drop(conn);
        std::fs::read(&path).unwrap()
    }

    #[test]
    fn a_simple_snapshot_restores_and_integrity_checks_ok() {
        let bytes = make_simple_db();
        let input = RestoreInput {
            snapshot_sha256: sha256(&bytes),
            snapshot_bytes: bytes,
            segment: None,
        };
        let scratch = tempfile::TempDir::new().unwrap();
        let report = restore(scratch.path(), &input).unwrap();
        assert_eq!(report, RestoreReport::Ok);
    }

    #[test]
    fn a_mismatched_snapshot_hash_refuses_before_any_file_write() {
        let bytes = make_simple_db();
        let input = RestoreInput {
            snapshot_sha256: [0u8; 32],
            snapshot_bytes: bytes,
            segment: None,
        };
        let scratch = tempfile::TempDir::new().unwrap();
        let err = restore(scratch.path(), &input).unwrap_err();
        assert!(matches!(err, RestoreError::SnapshotHashMismatch));
    }

    #[test]
    fn a_mismatched_segment_hash_refuses_before_any_file_write() {
        let bytes = make_simple_db();
        let input = RestoreInput {
            snapshot_sha256: sha256(&bytes),
            snapshot_bytes: bytes,
            segment: Some(RestoreSegment {
                bytes: b"not a wal".to_vec(),
                sha256: [0u8; 32],
            }),
        };
        let scratch = tempfile::TempDir::new().unwrap();
        let err = restore(scratch.path(), &input).unwrap_err();
        assert!(matches!(err, RestoreError::SegmentHashMismatch));
    }

    #[test]
    fn a_corrupted_snapshot_surfaces_as_integrity_failure_or_sqlite_open_error() {
        // Mangle the SQLite header bytes so the file is not a valid db,
        // but is still a well-formed byte sequence that hashes.
        let mut bytes = make_simple_db();
        bytes[16..18].copy_from_slice(&[0xff, 0xff]);
        let input = RestoreInput {
            snapshot_sha256: sha256(&bytes),
            snapshot_bytes: bytes,
            segment: None,
        };
        let scratch = tempfile::TempDir::new().unwrap();
        match restore(scratch.path(), &input) {
            // Either SQLite refuses to open (a surface error) or the
            // integrity check reports a mismatch. Both are failures the
            // restore-check surfaces to the operator.
            Ok(RestoreReport::IntegrityFailure { .. }) => {}
            Err(RestoreError::Sqlite(_)) => {}
            other => panic!("expected an integrity or sqlite error, got {other:?}"),
        }
    }
}
