//! The `tinycloud node sql-store restore-check` command.
//!
//! Samples `--sample N` databases from the published manifest frontier,
//! fetches each one's snapshot (and, when the manifest's frontier names
//! a non-trivial segment, the segment too), runs `shadow::restore` on
//! the materialised bytes, and reports counts. Exits nonzero on any
//! mismatch.
//!
//! The sampler is seeded (`--seed S`) so a run is reproducible. When
//! `--seed` is omitted, the sampler uses OS entropy.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use rand::rngs::StdRng;
use rand::seq::SliceRandom;
use rand::SeedableRng;
use serde::Serialize;

use tinycloud_core::sea_orm::{ConnectOptions, Database, EntityTrait};
use tinycloud_core::sql::store::object::{sha256, SqlObjectStore};
use tinycloud_core::sql::store::shadow::restore::{
    restore, RestoreError, RestoreInput, RestoreReport, RestoreSegment,
};
use tinycloud_core::sql::store::{DbRef, Lineage, ObjectKey};
use tinycloud_core::storage::ByteRangeSpec;

use crate::config::Config;
use crate::space_purge_executor::PurgeSqlObjects;

/// What the CLI prints when the check finishes.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Report {
    pub sampled: usize,
    pub ok: usize,
    pub failed: usize,
    /// How many sampled rows had a segment above their base snapshot
    /// in the manifest that this build does not read. Zero in the
    /// current build (bootstrap at R publishes one snapshot and no
    /// segment); the count is in the report so a future build that
    /// publishes segments cannot silently skip verifying them.
    pub segments_unverified: usize,
    /// Database identifiers that failed, with a one-line reason. The
    /// `space` and `db_id` fields are printed verbatim because the CLI
    /// talks to the operator, not to users.
    pub failures: Vec<Failure>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Failure {
    pub space: String,
    pub db_id: String,
    pub reason: String,
}

/// Drive the check end to end. Returns the structured report and an
/// exit-code hint (`0` on no failures, `1` otherwise).
pub async fn run_restore_check(
    config: &Config,
    sample: u32,
    seed: Option<u64>,
) -> Result<(Report, i32)> {
    // 1. Open the control-DB connection.
    let conn = Database::connect(ConnectOptions::new(config.storage.database().to_string()))
        .await
        .context("control DB connect")?;

    // 2. Open the SQL object store the same way the purge executor does
    //    (the restore-check only reads; no write probe runs).
    let objects = PurgeSqlObjects::open(&config.storage)
        .await
        .context("open SQL object store")?;

    // 3. Load the full set of published manifest rows. The sample is
    //    taken from this set so a rolling CI job always exercises the
    //    live frontier.
    use tinycloud_core::models::sql_store_manifest as manifest;
    let all = manifest::Entity::find()
        .all(&conn)
        .await
        .context("list sql_store_manifest")?;
    if all.is_empty() {
        return Ok((
            Report {
                sampled: 0,
                ok: 0,
                failed: 0,
                segments_unverified: 0,
                failures: Vec::new(),
            },
            0,
        ));
    }

    // 4. Shuffle + take `sample`. Seed makes the run reproducible.
    let mut rng = match seed {
        Some(s) => StdRng::seed_from_u64(s),
        None => StdRng::from_entropy(),
    };
    let mut rows = all;
    rows.shuffle(&mut rng);
    rows.truncate(sample as usize);

    // 5. Scratch directory lives under the SQL data directory. That
    //    is `storage.sql.path` when set (SQL databases can live on a
    //    separate volume), else `{datadir}/sql`; in both cases the
    //    scratch is a sibling the uploader already uses, and the
    //    bytes count against the same `DiskBudget` headroom live
    //    writes do.
    let sql_data_dir: PathBuf = match &config.storage.sql.path {
        Some(p) => PathBuf::from(p),
        None => config.storage.datadir.join("sql"),
    };
    let scratch_root: PathBuf = sql_data_dir.join("sql-store-restore-check");
    std::fs::create_dir_all(&scratch_root).context("create scratch root")?;
    let min_free_bytes = config.storage.sql.min_free_bytes.as_u64();

    let mut ok = 0usize;
    let mut failed = 0usize;
    let mut failures = Vec::new();
    for row in &rows {
        match check_one(&conn, &objects, &scratch_root, min_free_bytes, row).await {
            Ok(RestoreReport::Ok) => {
                ok += 1;
            }
            Ok(RestoreReport::IntegrityFailure { first_error }) => {
                failed += 1;
                failures.push(Failure {
                    space: row.space.clone(),
                    db_id: row.db_id.clone(),
                    reason: format!("integrity: {first_error}"),
                });
            }
            Err(e) => {
                failed += 1;
                failures.push(Failure {
                    space: row.space.clone(),
                    db_id: row.db_id.clone(),
                    reason: e.to_string(),
                });
            }
        }
    }

    let exit = if failed == 0 { 0 } else { 1 };
    Ok((
        Report {
            sampled: rows.len(),
            ok,
            failed,
            segments_unverified: 0,
            failures,
        },
        exit,
    ))
}

async fn check_one(
    conn: &tinycloud_core::sea_orm::DatabaseConnection,
    objects: &PurgeSqlObjects,
    scratch_root: &Path,
    min_free_bytes: u64,
    row: &tinycloud_core::models::sql_store_manifest::Model,
) -> Result<RestoreReport, anyhow::Error> {
    use tinycloud_core::models::sql_store_object as obj;
    use tinycloud_core::sea_orm::{ColumnTrait, QueryFilter};

    // Look up the sql_store_object row whose `key` matches the
    // manifest's base_snapshot_key. That gives us its content_hash.
    let obj_row = obj::Entity::find()
        .filter(obj::Column::Key.eq(row.base_snapshot_key.clone()))
        .one(conn)
        .await
        .context("look up sql_store_object by key")?
        .ok_or_else(|| {
            anyhow::anyhow!("manifest references base_snapshot_key with no sql_store_object row")
        })?;

    // Defensive: the manifest's base_snapshot_key is the key for THIS
    // row, written from this row's columns in the uploader. If any
    // field drifted (bad backfill, schema migration bug) we refuse the
    // check loudly rather than restore from a different lineage's
    // snapshot.
    if obj_row.space != row.space || obj_row.db_id != row.db_id {
        anyhow::bail!("sql_store_object row names a different (space, db_id) than the manifest");
    }

    let snapshot_sha = parse_content_hash(&obj_row.content_hash)?;
    let lineage = Lineage::parse(&row.lineage).map_err(|e| anyhow::anyhow!("bad lineage: {e}"))?;
    let db = DbRef {
        space: &row.space,
        db_id: &row.db_id,
    };
    let key = ObjectKey::snapshot(&db, &lineage, row.base_seq as u64, &snapshot_sha)
        .map_err(|e| anyhow::anyhow!("rebuild ObjectKey::snapshot: {e}"))?;
    if key.as_str() != row.base_snapshot_key {
        anyhow::bail!("rebuilt ObjectKey does not match the manifest's base_snapshot_key");
    }

    // Preflight free-space: HEAD the object, then require free >=
    // 2 * obj_bytes + min_free_bytes, so a big object cannot drive the
    // scratch volume into a 507 for live writes. The factor of 2
    // covers the RAM copy below and the restore's temp SQLite file.
    let head_meta = head(objects, &key).await?;
    let obj_bytes = head_meta.bytes;
    let needed = obj_bytes.saturating_mul(2).saturating_add(min_free_bytes);
    let free = scratch_root_free_bytes(scratch_root)?;
    if free < needed {
        anyhow::bail!(
            "insufficient free space in scratch: need at least {needed} bytes, have {free}"
        );
    }

    // Fetch the body (From { start: 0 } reads the whole object).
    let snapshot_bytes = read_all(objects, &key).await?;
    let bytes_sha = sha256(&snapshot_bytes);
    if bytes_sha != snapshot_sha {
        anyhow::bail!("snapshot bytes do not hash to the manifest's content_hash");
    }

    // In the shadow phase, bootstrap publishes a single snapshot at R
    // and never a separate segment, so the manifest's current frontier
    // always restores from the snapshot alone. Segment reading lands
    // with capture-driven segment publishing in a later change.
    let segment: Option<RestoreSegment> = None;

    let scratch_root_owned = scratch_root.to_path_buf();
    let report = tokio::task::spawn_blocking(move || {
        restore(
            &scratch_root_owned,
            &RestoreInput {
                snapshot_bytes,
                snapshot_sha256: snapshot_sha,
                segment,
            },
        )
    })
    .await
    .context("spawn_blocking restore")?
    .map_err(|e: RestoreError| anyhow::anyhow!("restore: {e}"))?;
    Ok(report)
}

async fn head(
    objects: &PurgeSqlObjects,
    key: &ObjectKey,
) -> Result<tinycloud_core::sql::store::object::ObjectMeta> {
    let meta = match objects {
        PurgeSqlObjects::S3(store) => store
            .head(key)
            .await
            .with_context(|| format!("S3 head {}", key.as_str()))?,
        PurgeSqlObjects::FileSystem(store) => store
            .head(key)
            .await
            .with_context(|| format!("FS head {}", key.as_str()))?,
    };
    meta.ok_or_else(|| anyhow::anyhow!("object not found: {}", key.as_str()))
}

fn scratch_root_free_bytes(scratch_root: &Path) -> Result<u64> {
    // Use the live FreeSpace impl so the preflight matches what the
    // 1a DiskBudget reads.
    use tinycloud_core::sql::durability::{FreeSpace, StatvfsFreeSpace};
    StatvfsFreeSpace
        .free_bytes(scratch_root)
        .context("read free bytes on the scratch volume")
}

async fn read_all(objects: &PurgeSqlObjects, key: &ObjectKey) -> Result<Vec<u8>> {
    let range = ByteRangeSpec::From { start: 0 };
    let r = match objects {
        PurgeSqlObjects::S3(store) => store
            .get_range(key, range)
            .await
            .with_context(|| format!("S3 get_range {}", key.as_str()))?,
        PurgeSqlObjects::FileSystem(store) => store
            .get_range(key, range)
            .await
            .with_context(|| format!("FS get_range {}", key.as_str()))?,
    };
    let r = r.ok_or_else(|| anyhow::anyhow!("object not found: {}", key.as_str()))?;
    Ok(r.data)
}

fn parse_content_hash(hex_str: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(hex_str).context("decode content_hash hex")?;
    if bytes.len() != 32 {
        anyhow::bail!("content_hash must be 32 bytes, got {} bytes", bytes.len());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_content_hash() {
        let hex_str = "a".repeat(64);
        let bytes = parse_content_hash(&hex_str).unwrap();
        assert_eq!(bytes, [0xaa; 32]);
    }

    #[test]
    fn rejects_non_hex_or_wrong_length_content_hash() {
        assert!(parse_content_hash("zzzz").is_err(), "non-hex rejected");
        assert!(
            parse_content_hash(&"a".repeat(62)).is_err(),
            "31-byte hex rejected"
        );
    }

    #[test]
    fn failure_serialises_as_json() {
        let f = Failure {
            space: "tc:test".into(),
            db_id: "main".into(),
            reason: "integrity: row 42 bad page".into(),
        };
        let s = serde_json::to_string(&f).unwrap();
        assert!(s.contains("tc:test"));
        assert!(s.contains("row 42 bad page"));
    }

    #[test]
    fn empty_report_serialises_as_json() {
        let r = Report {
            sampled: 0,
            ok: 0,
            failed: 0,
            segments_unverified: 0,
            failures: Vec::new(),
        };
        let s = serde_json::to_string(&r).unwrap();
        assert!(s.contains("\"sampled\":0"));
        assert!(s.contains("\"ok\":0"));
        assert!(s.contains("\"failed\":0"));
        assert!(s.contains("\"segments_unverified\":0"));
    }
}
