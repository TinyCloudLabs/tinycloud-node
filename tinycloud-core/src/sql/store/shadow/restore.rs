//! The restore check (TC-1491 P2): rebuild a database from its published
//! frontier and compare it with Postgres's artifact at the same revision.
//! It gates turning the shadow copy on for any space.
//!
//! Per database ([`check_database`]):
//! 1. Read the frontier (the manifest's primary key) and resolve its chain in
//!    the inventory by primary-key columns: the base snapshot and, when
//!    `last_seq > base_seq`, the WAL segments that reach `last_seq`: the
//!    highest published `wal-cum-v1` segment `base_seq+1 ..= C`, then the
//!    published `wal-delta-v1` segments after it end to end (`C+1 ..= D`,
//!    `D+1 ..= E`, ...), the last ending at `last_seq`. A segment missing
//!    from that chain is the shortfall. Every key must sit under the
//!    database's own lineage prefix. A frontier at `at_seq = 0` is never a
//!    restore point (contract 4.2, 11.6).
//! 2. Read Postgres's head. Unless it is at the frontier's revision with the
//!    frontier's checkpoint, the database is `not_comparable` and nothing
//!    more is read: the check never compares across revisions.
//! 3. Stream the snapshot and the segments from the store into scratch files
//!    (capped at their recorded sizes, SHA-256 checked against their keys; a
//!    refused download is discarded and never opened), appending the
//!    segments in order into one WAL, check the headers ([`db_page_size`],
//!    [`check_wal`], which walks the whole WAL: its salts and checksum chain
//!    tie the deltas to one another) before SQLite opens anything, replay
//!    with `wal_checkpoint(TRUNCATE)` and run `PRAGMA integrity_check`.
//! 4. Stream Postgres's checkpoint and WAL through [`ShadowSource`] into
//!    scratch files and materialise them the same way.
//! 5. Compare the SHA-256 of the two materialised files.
//!
//! Scratch space is reserved from a [`DiskBudget`] before anything is
//! written; no body is held in memory whole. The report carries verdicts,
//! reasons and counts, never payload bytes.

use std::fs::File;
use std::io::{BufReader, ErrorKind, Read};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use rand::Rng;
use sea_orm::{
    ColumnTrait, ConnectionTrait, DatabaseConnection, DbErr, EntityTrait, QueryFilter, QueryOrder,
    QuerySelect,
};
use serde::Serialize;

use super::budget::DiskBudget;
use super::machine::ArtifactHead;
use super::metrics::{RestoreMetrics, RestoreResult};
use super::source::{ShadowSource, SourceError};
use crate::models::{sql_store_manifest as manifest_row, sql_store_object as object};
use crate::sql::store::key::{lineage_prefix, DbRef, ObjectKey, ObjectKind};
use crate::sql::store::manifest::{
    object_pk, DbSqlManifest, Frontier, ObjectState, SqlManifest, DELTA_FORMAT, SEGMENT_FORMAT,
    SNAPSHOT_FORMAT,
};
use crate::sql::store::object::{
    discard_download, private_file_options, sha256_file, ObjectMeta, SqlObjectStore, SqlStoreError,
};

/// The reason given for a key that does not belong to the database.
pub const KEY_OUTSIDE_DB_PREFIX: &str = "key outside db prefix";

/// Name of the materialised database in its scratch directory.
const DB_FILE: &str = "db";

/// Everything the check reads from.
pub struct RestoreDeps {
    /// The control database: the manifest and the inventory.
    pub control: DatabaseConnection,
    pub store: Arc<dyn SqlObjectStore>,
    pub source: Arc<dyn ShadowSource>,
    /// Scratch space for the restored and the Postgres copies.
    pub disk: Arc<DiskBudget>,
    pub metrics: Arc<dyn RestoreMetrics>,
}

/// The verdict on one database.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DbReport {
    pub space: String,
    pub db_id: String,
    pub result: RestoreResult,
    /// Why the result is not `ok`. Never carries payload bytes.
    pub reason: Option<String>,
    /// The frontier's `last_seq`, when there is a frontier.
    pub last_seq: Option<u64>,
    /// Postgres's revision, when it was read.
    pub pg_revision: Option<i64>,
    /// Segments the frontier needs for a restore at `last_seq`: none when
    /// `last_seq = base_seq`, else the highest `wal-cum-v1` segment and the
    /// `wal-delta-v1` segments after it. When the chain has a gap, the
    /// segments found plus the one missing.
    pub segments_required: u64,
    /// Segments streamed, checked against their key and the WAL rules, and
    /// replayed into a sound database.
    pub segments_verified: u64,
    /// `segments_required - segments_verified`.
    pub segments_unverified: u64,
}

/// The verdicts on a sample of databases.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct RunReport {
    pub sampled: usize,
    pub ok: usize,
    pub mismatch: usize,
    pub not_comparable: usize,
    pub unreadable: usize,
    pub segments_unverified: u64,
    pub databases: Vec<DbReport>,
}

impl RunReport {
    fn add(&mut self, db: DbReport) {
        self.sampled += 1;
        match db.result {
            RestoreResult::Ok => self.ok += 1,
            RestoreResult::Mismatch => self.mismatch += 1,
            RestoreResult::NotComparable => self.not_comparable += 1,
            RestoreResult::Unreadable => self.unreadable += 1,
        }
        self.segments_unverified += db.segments_unverified;
        self.databases.push(db);
    }

    /// No database restored wrongly or failed to restore. `not_comparable`
    /// databases are counted, not failed.
    pub fn passed(&self) -> bool {
        self.mismatch == 0 && self.unreadable == 0
    }
}

/// Up to `sample` databases with a published frontier in `spaces`, chosen
/// uniformly (reservoir sampling) and returned sorted. Each space is read in
/// keyset pages of `page` ids on the manifest's primary key
/// `(space, db_id)`, so memory stays at `sample` entries.
pub async fn sample_databases<C: ConnectionTrait>(
    conn: &C,
    spaces: &[String],
    sample: usize,
    page: u64,
    rng: &mut impl Rng,
) -> Result<Vec<(String, String)>, DbErr> {
    use manifest_row::Column as C;
    let page = page.max(1);
    let mut chosen: Vec<(String, String)> = Vec::with_capacity(sample);
    let mut seen = 0usize;
    for space in spaces {
        let mut after = String::new();
        loop {
            let ids: Vec<String> = manifest_row::Entity::find()
                .select_only()
                .column(C::DbId)
                .filter(C::Space.eq(space.as_str()))
                .filter(C::DbId.gt(after.as_str()))
                .order_by_asc(C::DbId)
                .limit(page)
                .into_tuple()
                .all(conn)
                .await?;
            let Some(last) = ids.last() else { break };
            after.clone_from(last);
            let more = ids.len() as u64 == page;
            for db_id in ids {
                seen += 1;
                if chosen.len() < sample {
                    chosen.push((space.clone(), db_id));
                } else {
                    let slot = rng.gen_range(0..seen);
                    if slot < sample {
                        chosen[slot] = (space.clone(), db_id);
                    }
                }
            }
            if !more {
                break;
            }
        }
    }
    chosen.sort();
    Ok(chosen)
}

/// Check every database of `databases` in turn.
pub async fn check_databases(deps: &RestoreDeps, databases: &[(String, String)]) -> RunReport {
    let mut report = RunReport::default();
    for (space, db_id) in databases {
        let db = DbRef {
            space: space.as_str(),
            db_id: db_id.as_str(),
        };
        report.add(check_database(deps, &db).await);
    }
    report
}

/// Restore `db` at its frontier and compare it with Postgres (module docs).
pub async fn check_database(deps: &RestoreDeps, db: &DbRef<'_>) -> DbReport {
    let started = Instant::now();
    let mut report = DbReport {
        space: db.space.to_owned(),
        db_id: db.db_id.to_owned(),
        result: RestoreResult::Ok,
        reason: None,
        last_seq: None,
        pg_revision: None,
        segments_required: 0,
        segments_verified: 0,
        segments_unverified: 0,
    };
    if let Err(verdict) = check(deps, db, &mut report).await {
        report.result = verdict.result;
        report.reason = Some(verdict.reason);
    }
    report.segments_unverified = report
        .segments_required
        .saturating_sub(report.segments_verified);
    deps.metrics.restore_check(
        report.result,
        report.segments_unverified,
        started.elapsed().as_secs_f64(),
    );
    report
}

/// A result other than `ok`, with its reason.
#[derive(Debug)]
struct Verdict {
    result: RestoreResult,
    reason: String,
}

fn unreadable(reason: impl Into<String>) -> Verdict {
    Verdict {
        result: RestoreResult::Unreadable,
        reason: reason.into(),
    }
}

fn not_comparable(reason: impl Into<String>) -> Verdict {
    Verdict {
        result: RestoreResult::NotComparable,
        reason: format!("not comparable at this revision: {}", reason.into()),
    }
}

/// One object of the chain and its recorded size.
struct Link {
    key: ObjectKey,
    bytes: u64,
}

/// What a restore at the frontier reads.
struct Chain {
    snapshot: Link,
    /// In WAL order: the cumulative segment, then the deltas after it.
    segments: Vec<Link>,
}

impl Chain {
    fn wal_bytes(&self) -> u64 {
        self.segments
            .iter()
            .fold(0, |total, s| u64::saturating_add(total, s.bytes))
    }
}

async fn check(deps: &RestoreDeps, db: &DbRef<'_>, report: &mut DbReport) -> Result<(), Verdict> {
    let frontier = DbSqlManifest::new(deps.control.clone())
        .current(db)
        .await
        .map_err(|e| unreadable(format!("manifest: {}", store_reason(&e))))?
        .ok_or_else(|| unreadable("no published frontier"))?;
    report.last_seq = Some(frontier.last_seq);
    let chain = resolve_chain(&deps.control, db, &frontier, report).await?;

    let head = deps
        .source
        .head(db)
        .await
        .map_err(source_verdict)?
        .ok_or_else(|| not_comparable("postgres holds no artifact"))?;
    report.pg_revision = Some(head.revision);
    if u64::try_from(head.revision).ok() != Some(frontier.last_seq) {
        return Err(not_comparable(format!(
            "postgres is at revision {}, the frontier at {}",
            head.revision, frontier.last_seq
        )));
    }
    if head.cid != frontier.base_checkpoint_cid {
        // Same revision, another checkpoint: Postgres was restored below the
        // frontier (contract 11.7); its history is not the chain's.
        return Err(not_comparable(
            "postgres holds another checkpoint at the frontier's revision",
        ));
    }

    let need = scratch_need(chain.snapshot.bytes, chain.wal_bytes()).max(scratch_need(
        head.checkpoint_bytes,
        if head.has_delta { head.delta_bytes } else { 0 },
    ));
    if need > deps.disk.capacity() {
        return Err(unreadable(format!(
            "needs {need} scratch bytes, the budget holds {}",
            deps.disk.capacity()
        )));
    }
    let reservation = deps
        .disk
        .try_reserve(need)
        .ok_or_else(|| unreadable("the scratch budget is in use"))?;

    // The store's copy. Each copy lives in its own scratch directory, removed
    // before the next one is written, so the reservation covers one at a time.
    let restored = {
        let dir = reservation.scratch_dir().map_err(scratch_verdict)?;
        let db_path = dir.path().join(DB_FILE);
        download(&*deps.store, &chain.snapshot, &db_path).await?;
        assemble_wal(&*deps.store, &chain.segments, &db_path).await?;
        let restored = materialise_file(db_path, !chain.segments.is_empty(), true)
            .await
            .map_err(|e| unreadable(format!("restored copy: {e}")))?;
        report.segments_verified = chain.segments.len() as u64;
        restored
    };

    // Postgres's copy at the same revision.
    let expected = {
        let dir = reservation.scratch_dir().map_err(scratch_verdict)?;
        let db_path = dir.path().join(DB_FILE);
        pg_copy(&*deps.source, db, &head, &db_path).await?;
        materialise_file(db_path, head.has_delta, false)
            .await
            .map_err(|e| unreadable(format!("postgres copy: {e}")))?
    };

    if restored != expected {
        return Err(Verdict {
            result: RestoreResult::Mismatch,
            reason: format!(
                "the restored file differs from postgres's at revision {}",
                head.revision
            ),
        });
    }
    Ok(())
}

/// Scratch bytes to materialise a `db`-byte file with a `wal`-byte WAL: both
/// files, the database growing by at most the WAL's pages while it is
/// checkpointed, and the `-shm` index (8 bytes per frame, under `wal / 64`,
/// plus its first 32 KiB block).
fn scratch_need(db: u64, wal: u64) -> u64 {
    db.saturating_add(wal.saturating_mul(2))
        .saturating_add(wal / 64)
        .saturating_add(64 * 1024)
}

fn seq(v: u64) -> i64 {
    i64::try_from(v).unwrap_or(i64::MAX)
}

/// The frontier's chain, looked up by the inventory's primary-key columns.
async fn resolve_chain<C: ConnectionTrait>(
    conn: &C,
    db: &DbRef<'_>,
    f: &Frontier,
    report: &mut DbReport,
) -> Result<Chain, Verdict> {
    if f.last_seq < f.base_seq {
        return Err(unreadable("the frontier's last_seq is below its base_seq"));
    }
    // The WAL is the highest wal-cum-v1 segment on the base and the
    // wal-delta-v1 segments after it; the earlier segments are history.
    // `segments_of` refines the count once it has walked the chain.
    report.segments_required = u64::from(f.last_seq > f.base_seq);
    // Restore is defined only at the recoverable frontier; a snapshot
    // labelled at_seq 0 names no revision (contract 4.2, 11.6).
    if f.last_seq == 0 {
        return Err(unreadable("at_seq 0 is not a restore point"));
    }
    let prefix =
        lineage_prefix(db, &f.lineage).map_err(|_| unreadable("the database cannot form a key"))?;
    let snapshot_key = snapshot_key_of(db, f, &prefix)?;
    let row = object::Entity::find()
        .filter(object_pk(db, &snapshot_key).map_err(|e| unreadable(store_reason(&e)))?)
        .one(conn)
        .await
        .map_err(db_verdict)?
        .ok_or_else(|| unreadable("the base snapshot is not in the inventory"))?;
    let snapshot = link(&prefix, &snapshot_key, &row, SNAPSHOT_FORMAT)?;
    let segments = if f.last_seq > f.base_seq {
        segments_of(conn, db, f, &prefix, report).await?
    } else {
        Vec::new()
    };
    let chain = Chain { snapshot, segments };
    if chain.snapshot.bytes.saturating_add(chain.wal_bytes()) != f.frontier_bytes {
        return Err(unreadable("frontier_bytes disagrees with the inventory"));
    }
    Ok(chain)
}

/// The base snapshot's key, rebuilt from the frontier's columns and the hash
/// its stored key ends in; it must be the stored key exactly.
fn snapshot_key_of(db: &DbRef<'_>, f: &Frontier, prefix: &str) -> Result<ObjectKey, Verdict> {
    if !f.base_snapshot_key.starts_with(prefix) {
        return Err(unreadable(KEY_OUTSIDE_DB_PREFIX));
    }
    let hash = f
        .base_snapshot_key
        .rsplit_once('-')
        .and_then(|(_, hex)| hex::decode(hex).ok())
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        .ok_or_else(|| unreadable("base_snapshot_key is not a snapshot key"))?;
    let key = ObjectKey::snapshot(db, &f.lineage, f.base_seq, &hash)
        .map_err(|_| unreadable("base_snapshot_key is not a snapshot key"))?;
    if key.as_str() != f.base_snapshot_key {
        return Err(unreadable(
            "base_snapshot_key does not match the frontier's columns",
        ));
    }
    Ok(key)
}

/// The published segments that restore `last_seq` on the frontier's base: the
/// highest `wal-cum-v1` segment `base_seq+1 ..= C`, then the `wal-delta-v1`
/// segment that starts at `C+1`, and so on until one ends at `last_seq`. Each
/// step is a primary-key prefix lookup `(space, db_id, lineage, kind,
/// base_seq, from_seq)`; a step without a row reports the shortfall.
async fn segments_of<C: ConnectionTrait>(
    conn: &C,
    db: &DbRef<'_>,
    f: &Frontier,
    prefix: &str,
    report: &mut DbReport,
) -> Result<Vec<Link>, Verdict> {
    use object::Column as C;
    let on_base = || {
        object::Entity::find()
            .filter(C::Space.eq(db.space))
            .filter(C::DbId.eq(db.db_id))
            .filter(C::Lineage.eq(f.lineage.as_str()))
            .filter(C::Kind.eq(ObjectKind::Segment.as_str()))
            .filter(C::BaseSeq.eq(seq(f.base_seq)))
            .filter(C::State.eq(ObjectState::Published.as_str()))
    };
    let mut chain: Vec<Link> = Vec::new();
    let mut covered = f.base_seq;
    while covered < f.last_seq {
        // The longest segment that starts where the chain ends; the first
        // step has the cumulative segments to choose from, the later ones a
        // single delta.
        let rows = on_base()
            .filter(C::FromSeq.eq(seq(covered + 1)))
            .filter(C::ToSeq.lte(seq(f.last_seq)))
            .order_by_desc(C::ToSeq)
            .limit(2)
            .all(conn)
            .await
            .map_err(db_verdict)?;
        let row = match rows.as_slice() {
            [] => {
                let published =
                    !chain.is_empty() || on_base().one(conn).await.map_err(db_verdict)?.is_some();
                return Err(unreadable(if published {
                    format!(
                        "the published chain reaches seq {covered}, the frontier claims {}",
                        f.last_seq
                    )
                } else {
                    format!(
                        "no published segment on the base, the frontier claims seq {}",
                        f.last_seq
                    )
                }));
            }
            [row] => row,
            [row, next] if row.to_seq != next.to_seq => row,
            _ => return Err(unreadable("two published segments claim the frontier")),
        };
        let hash = hex::decode(&row.content_hash)
            .ok()
            .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
            .ok_or_else(|| unreadable("a segment's content hash is malformed"))?;
        let to =
            u64::try_from(row.to_seq).map_err(|_| unreadable("a segment's range is malformed"))?;
        let key = ObjectKey::segment(db, &f.lineage, f.base_seq, covered + 1, to, &hash)
            .map_err(|_| unreadable("a segment cannot form a key"))?;
        let format = if covered == f.base_seq {
            SEGMENT_FORMAT
        } else {
            DELTA_FORMAT
        };
        chain.push(link(prefix, &key, row, format)?);
        covered = to;
        report.segments_required = chain.len() as u64 + u64::from(covered < f.last_seq);
    }
    Ok(chain)
}

/// One inventory row of the chain, checked against the key it was looked up by.
fn link(prefix: &str, key: &ObjectKey, row: &object::Model, format: &str) -> Result<Link, Verdict> {
    let kind = key.kind().as_str();
    if !row.key.starts_with(prefix) {
        return Err(unreadable(KEY_OUTSIDE_DB_PREFIX));
    }
    if row.key != key.as_str() {
        return Err(unreadable(format!(
            "the {kind}'s inventory key does not match its columns"
        )));
    }
    if row.state != ObjectState::Published.as_str() {
        return Err(unreadable(format!("the {kind} is not published")));
    }
    if row.format != format {
        return Err(unreadable(format!("the {kind}'s format is not {format}")));
    }
    let bytes = u64::try_from(row.bytes)
        .map_err(|_| unreadable(format!("the {kind}'s size is negative")))?;
    Ok(Link {
        key: key.clone(),
        bytes,
    })
}

/// Stream one object into `path`, capped at its recorded size. A refused
/// download is removed here (the backend already emptied it) and never opened.
async fn download(store: &dyn SqlObjectStore, link: &Link, path: &Path) -> Result<(), Verdict> {
    let refused = match store.get_to_file(&link.key, path, link.bytes).await {
        Ok(Some(meta)) if meta.bytes == link.bytes => return Ok(()),
        Ok(Some(_)) => "it is shorter than its recorded size".to_owned(),
        Ok(None) => "it is missing from the store".to_owned(),
        Err(e) => format!("the download was refused ({})", store_reason(&e)),
    };
    if std::fs::remove_file(path).is_err() {
        discard_download(path);
    }
    Err(unreadable(format!(
        "{}: {refused}",
        link.key.kind().as_str()
    )))
}

/// The chain's segments, in order, as the `-wal` file beside `db_path`. The
/// first goes straight there; each later one lands in a part file, is
/// appended and removed, so the scratch holds the WAL and one segment.
async fn assemble_wal(
    store: &dyn SqlObjectStore,
    segments: &[Link],
    db_path: &Path,
) -> Result<(), Verdict> {
    let Some((first, rest)) = segments.split_first() else {
        return Ok(());
    };
    let wal = wal_path(db_path);
    download(store, first, &wal).await?;
    let part = sibling(db_path, "-part");
    for segment in rest {
        download(store, segment, &part).await?;
        append(&part, &wal).await.map_err(scratch_verdict)?;
        tokio::fs::remove_file(&part)
            .await
            .map_err(scratch_verdict)?;
    }
    Ok(())
}

async fn append(part: &Path, wal: &Path) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;
    let mut from = tokio::fs::File::open(part).await?;
    let mut to = tokio::fs::OpenOptions::new().append(true).open(wal).await?;
    tokio::io::copy(&mut from, &mut to).await?;
    to.flush().await
}

/// Postgres's checkpoint (and WAL, when the head has one) into `db_path`.
async fn pg_copy(
    source: &dyn ShadowSource,
    db: &DbRef<'_>,
    head: &ArtifactHead,
    db_path: &Path,
) -> Result<(), Verdict> {
    let mut file = create(db_path).await?;
    source
        .checkpoint_to(db, &head.cid, &mut file)
        .await
        .map_err(source_verdict)?;
    if head.has_delta {
        let mut wal = create(&wal_path(db_path)).await?;
        source
            .wal_to(db, &head.head(), &mut wal)
            .await
            .map_err(source_verdict)?;
    }
    Ok(())
}

/// A new scratch file for Postgres's copy, owner-only (`0600` on unix).
async fn create(path: &Path) -> Result<tokio::fs::File, Verdict> {
    let mut options = private_file_options();
    options.read(true).create_new(true);
    tokio::fs::OpenOptions::from(options)
        .open(path)
        .await
        .map_err(scratch_verdict)
}

fn scratch_verdict(e: std::io::Error) -> Verdict {
    unreadable(format!("scratch file: {:?}", e.kind()))
}

fn db_verdict(_: DbErr) -> Verdict {
    unreadable("control database error")
}

fn source_verdict(error: SourceError) -> Verdict {
    match error {
        SourceError::MovedOn => not_comparable("postgres moved on during the check"),
        SourceError::Gone => not_comparable("postgres holds no artifact"),
        SourceError::TooLarge => unreadable("postgres: the artifact is over the read limit"),
        SourceError::Unreadable(_) => unreadable("postgres: the artifact failed its own checks"),
        SourceError::Transient(_) => unreadable("postgres: the read failed"),
    }
}

/// A store error as a fixed phrase (backend texts can carry keys).
fn store_reason(error: &SqlStoreError) -> &'static str {
    match error {
        SqlStoreError::Key(_) => "bad key",
        SqlStoreError::Conflict => "conflict",
        SqlStoreError::BodyMismatch => "the bytes do not hash to the key",
        SqlStoreError::Oversize => "more bytes than the recorded size",
        SqlStoreError::Backend(_) => "backend error",
        SqlStoreError::File(_) => "scratch file error",
        SqlStoreError::Manifest(_) => "control database error",
        SqlStoreError::ObjectNotUploaded => "object not uploaded",
        SqlStoreError::Invalid(why) => why,
    }
}

/// `{db_path}-wal`, where SQLite looks for the database's WAL.
pub fn wal_path(db_path: &Path) -> PathBuf {
    sibling(db_path, "-wal")
}

fn sibling(db_path: &Path, suffix: &str) -> PathBuf {
    let mut name = db_path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

/// [`materialise`] off the async runtime, then the result's length and SHA-256.
async fn materialise_file(
    db_path: PathBuf,
    with_wal: bool,
    integrity: bool,
) -> Result<ObjectMeta, MaterialiseError> {
    let path = db_path.clone();
    tokio::task::spawn_blocking(move || materialise(&path, with_wal, integrity))
        .await
        .map_err(|_| MaterialiseError::Io("the materialise task failed".into()))??;
    sha256_file(&db_path)
        .await
        .map_err(|_| MaterialiseError::Io("hashing the materialised file failed".into()))
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MaterialiseError {
    /// The files were refused before SQLite opened anything.
    #[error("refused before open: {0}")]
    Refused(String),
    /// The guard against RUSTSEC-2026-0459; also refused before open.
    #[error(
        "refused before open: the WAL page size {wal} differs from the database page size {db}"
    )]
    PageSizeMismatch { db: u32, wal: u32 },
    #[error("sqlite {op} failed ({code})")]
    Sqlite { op: &'static str, code: String },
    #[error("wal_checkpoint({mode}) returned busy={busy} log={log} checkpointed={checkpointed}")]
    Checkpoint {
        mode: &'static str,
        busy: i64,
        log: i64,
        checkpointed: i64,
    },
    /// SQLite replayed another number of WAL frames than the WAL holds.
    #[error("sqlite saw {sqlite} WAL frames, the WAL holds {walked}")]
    FrameCount { walked: u64, sqlite: i64 },
    #[error("wal_checkpoint(TRUNCATE) left the WAL non-empty")]
    WalLeft,
    #[error("integrity_check reported {0} problem(s)")]
    Integrity(usize),
    #[error("scratch file: {0}")]
    Io(String),
}

fn refused(reason: impl Into<String>) -> MaterialiseError {
    MaterialiseError::Refused(reason.into())
}

fn io_error(e: std::io::Error) -> MaterialiseError {
    MaterialiseError::Io(format!("{:?}", e.kind()))
}

fn sqlite(op: &'static str) -> impl FnOnce(rusqlite::Error) -> MaterialiseError {
    move |e| MaterialiseError::Sqlite {
        op,
        code: match e {
            rusqlite::Error::SqliteFailure(failure, _) => format!("{:?}", failure.code),
            _ => "client error".into(),
        },
    }
}

/// Replay the database at `db_path` (and `{db_path}-wal` when `with_wal`)
/// into a single file in place: header checks first, then open, then
/// `wal_checkpoint(TRUNCATE)` with its result checked, then (when
/// `integrity`) `PRAGMA integrity_check`. Returns the WAL frames replayed.
///
/// Nothing is opened unless [`db_page_size`] and [`check_wal`] accept the
/// files, and no `-shm`, `-journal` or unexpected `-wal` sits next to them.
pub fn materialise(
    db_path: &Path,
    with_wal: bool,
    integrity: bool,
) -> Result<u64, MaterialiseError> {
    let wal = wal_path(db_path);
    for leftover in [sibling(db_path, "-shm"), sibling(db_path, "-journal")] {
        if leftover.exists() {
            return Err(refused("a -shm or -journal file sits next to the database"));
        }
    }
    if !with_wal && wal.exists() {
        return Err(refused("an unexpected -wal file sits next to the database"));
    }
    let page_size = db_page_size(db_path)?;
    let frames = if with_wal {
        Some(check_wal(&wal, page_size)?)
    } else {
        None
    };

    // SQLITE_OPEN_CREATE is left out: a missing file is an error, not a new
    // empty database.
    let conn = rusqlite::Connection::open_with_flags(
        db_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(sqlite("open"))?;
    if let Some(frames) = frames {
        // PASSIVE first: its `log` is the number of frames SQLite's recovery
        // accepted, which must be every frame `check_wal` walked.
        let (busy, log, checkpointed) = checkpoint(&conn, "PASSIVE")?;
        if busy != 0 || log != checkpointed {
            return Err(MaterialiseError::Checkpoint {
                mode: "PASSIVE",
                busy,
                log,
                checkpointed,
            });
        }
        let seen_all = if frames == 0 {
            log <= 0
        } else {
            u64::try_from(log).ok() == Some(frames)
        };
        if !seen_all {
            return Err(MaterialiseError::FrameCount {
                walked: frames,
                sqlite: log,
            });
        }
    }
    let (busy, log, checkpointed) = checkpoint(&conn, "TRUNCATE")?;
    if busy != 0 || log != checkpointed {
        return Err(MaterialiseError::Checkpoint {
            mode: "TRUNCATE",
            busy,
            log,
            checkpointed,
        });
    }
    if frames.is_some_and(|f| f > 0) && std::fs::metadata(&wal).map_err(io_error)?.len() != 0 {
        return Err(MaterialiseError::WalLeft);
    }
    if integrity {
        let mut statement = conn
            .prepare("PRAGMA integrity_check")
            .map_err(sqlite("integrity_check"))?;
        let lines = statement
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(sqlite("integrity_check"))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(sqlite("integrity_check"))?;
        if lines != ["ok"] {
            return Err(MaterialiseError::Integrity(lines.len()));
        }
        drop(statement);
    }
    conn.close().map_err(|(_, e)| sqlite("close")(e))?;
    Ok(frames.unwrap_or(0))
}

fn checkpoint(
    conn: &rusqlite::Connection,
    mode: &'static str,
) -> Result<(i64, i64, i64), MaterialiseError> {
    conn.query_row(&format!("PRAGMA wal_checkpoint({mode})"), [], |row| {
        Ok((row.get(0)?, row.get(1)?, row.get(2)?))
    })
    .map_err(sqlite("wal_checkpoint"))
}

fn valid_page_size(size: u32) -> bool {
    size.is_power_of_two() && (512..=65536).contains(&size)
}

fn be32(bytes: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

/// The page size in the 100-byte header of the database file at `path`,
/// refusing a file that is not a SQLite database. (A file without pages is
/// refused too: SQLite deletes a `-wal` it finds next to an empty database.)
pub fn db_page_size(path: &Path) -> Result<u32, MaterialiseError> {
    let mut header = [0u8; 100];
    File::open(path)
        .and_then(|mut file| file.read_exact(&mut header))
        .map_err(|e| match e.kind() {
            ErrorKind::UnexpectedEof => refused("the database file is shorter than its header"),
            _ => io_error(e),
        })?;
    if &header[..16] != b"SQLite format 3\0" {
        return Err(refused("the database file has no SQLite header"));
    }
    // Offset 16, big-endian; the value 1 means 65536.
    let raw = u16::from_be_bytes([header[16], header[17]]);
    let size = if raw == 1 { 65536 } else { u32::from(raw) };
    if !valid_page_size(size) {
        return Err(refused("the database header's page size is invalid"));
    }
    Ok(size)
}

const WAL_HEADER: usize = 32;
const FRAME_HEADER: usize = 24;
/// Checksums over little-endian words.
const WAL_MAGIC_LE: u32 = 0x377f_0682;
/// Checksums over big-endian words.
const WAL_MAGIC_BE: u32 = 0x377f_0683;
const WAL_VERSION: u32 = 3_007_000;

/// SQLite's WAL checksum: `s1 += x[i] + s2; s2 += x[i+1] + s1` over 32-bit
/// words in the byte order the magic selects, continuing from `sum`.
fn wal_checksum(big_endian: bool, data: &[u8], (mut s1, mut s2): (u32, u32)) -> (u32, u32) {
    let word = |b: &[u8]| {
        let b = [b[0], b[1], b[2], b[3]];
        if big_endian {
            u32::from_be_bytes(b)
        } else {
            u32::from_le_bytes(b)
        }
    };
    for pair in data.chunks_exact(8) {
        s1 = s1.wrapping_add(word(&pair[..4])).wrapping_add(s2);
        s2 = s2.wrapping_add(word(&pair[4..])).wrapping_add(s1);
    }
    (s1, s2)
}

/// Check the WAL at `path` against a database of `db_page_size` before
/// SQLite may open the pair; returns the number of frames, all of which
/// SQLite will replay. A zero-length WAL is an empty WAL (0 frames).
///
/// SQLite's recovery never reports a WAL it rejects: a header it does not
/// accept makes it treat the whole WAL as empty, and replay silently stops at
/// the first frame that fails. Either way the restore would quietly be an
/// older state that can still pass `integrity_check`. So every condition
/// recovery checks is checked here first, and anything it would skip is
/// refused:
///
/// 1. Length: at least the 32-byte header.
/// 2. Magic `0x377f0682` or `0x377f0683` (bytes 0..4, big-endian); its low
///    bit selects the checksum byte order.
/// 3. Format version 3007000 (bytes 4..8).
/// 4. Page size (bytes 8..12) a power of two in 512..=65536, and **equal to
///    the database header's page size**. This is the guard against
///    RUSTSEC-2026-0459 (libsqlite3-sys < 0.39): this build's bundled SQLite
///    must never open a db+WAL pair whose page sizes differ.
/// 5. Header checksum (bytes 24..32) equal to the checksum of bytes 0..24.
///    Recovery ignores a WAL whose header checksum fails.
/// 6. Salts: every frame's salt-1/salt-2 (frame bytes 8..16) equal the
///    header's (bytes 16..24). Recovery stops at the first frame with other
///    salts, taking it for a leftover of an earlier WAL generation; a
///    `wal-cum-v1` segment is one generation (the node checkpoints with
///    TRUNCATE and autocheckpoint off), so another salt means corruption or
///    a spliced file, not a leftover.
/// 7. Every frame names a page (`pgno != 0`) and its cumulative checksum
///    (frame bytes 16..24, over frame bytes 0..8 and the page, continuing
///    from the previous frame) matches.
/// 8. The WAL is whole frames and ends with a commit frame: recovery drops a
///    torn last frame and frames after the last commit, and a cumulative WAL
///    of committed revisions has neither.
pub fn check_wal(path: &Path, db_page_size: u32) -> Result<u64, MaterialiseError> {
    let file = File::open(path).map_err(io_error)?;
    let len = file.metadata().map_err(io_error)?.len();
    if len == 0 {
        return Ok(0);
    }
    if len < WAL_HEADER as u64 {
        return Err(refused("the WAL is shorter than its 32-byte header"));
    }
    let mut reader = BufReader::with_capacity(1 << 16, file);
    let mut header = [0u8; WAL_HEADER];
    reader.read_exact(&mut header).map_err(io_error)?;
    let big_endian = match be32(&header, 0) {
        WAL_MAGIC_LE => false,
        WAL_MAGIC_BE => true,
        _ => return Err(refused("the WAL magic is wrong")),
    };
    if be32(&header, 4) != WAL_VERSION {
        return Err(refused("the WAL format version is not 3007000"));
    }
    let page_size = be32(&header, 8);
    if !valid_page_size(page_size) {
        return Err(refused("the WAL page size is invalid"));
    }
    if page_size != db_page_size {
        return Err(MaterialiseError::PageSizeMismatch {
            db: db_page_size,
            wal: page_size,
        });
    }
    let mut sum = wal_checksum(big_endian, &header[..24], (0, 0));
    if sum != (be32(&header, 24), be32(&header, 28)) {
        return Err(refused("the WAL header checksum does not match"));
    }
    let salts = (be32(&header, 16), be32(&header, 20));
    let frame_size = FRAME_HEADER as u64 + u64::from(page_size);
    let body = len - WAL_HEADER as u64;
    if !body.is_multiple_of(frame_size) {
        return Err(refused("the WAL ends inside a frame"));
    }
    let frames = body / frame_size;
    let mut frame = vec![0u8; FRAME_HEADER + page_size as usize];
    let mut last_commit = 0;
    for n in 1..=frames {
        reader.read_exact(&mut frame).map_err(io_error)?;
        if (be32(&frame, 8), be32(&frame, 12)) != salts {
            return Err(refused(format!("WAL frame {n} carries other salts")));
        }
        if be32(&frame, 0) == 0 {
            return Err(refused(format!("WAL frame {n} names page 0")));
        }
        sum = wal_checksum(big_endian, &frame[..8], sum);
        sum = wal_checksum(big_endian, &frame[FRAME_HEADER..], sum);
        if sum != (be32(&frame, 16), be32(&frame, 20)) {
            return Err(refused(format!("WAL frame {n} fails its checksum")));
        }
        if be32(&frame, 4) != 0 {
            last_commit = n;
        }
    }
    if last_commit != frames {
        return Err(refused(format!(
            "{} WAL frame(s) follow the last commit",
            frames - last_commit
        )));
    }
    Ok(frames)
}

/// The length of the WAL at `path` through its last commit frame (TC-1491
/// P4.2a), or 0 when it has none or does not exist.
///
/// A WAL file can be longer than what SQLite would replay. A write that
/// outgrows the page cache puts frames into the WAL before its COMMIT, and if
/// it rolls back, those frames stay in the file until a later write overwrites
/// them; whatever the later write does not reach is a tail that fails the
/// checksum chain. [`check_wal`] refuses such a file, so a store-master
/// upload must send only the committed prefix, never the file's length.
///
/// Reads the whole file once (the same conditions as [`check_wal`], but where
/// that refuses, this stops): header magic, page size and checksum, then
/// frames while salts and the cumulative checksum hold.
pub fn committed_wal_len(path: &Path) -> std::io::Result<u64> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(error),
    };
    let len = file.metadata()?.len();
    if len < WAL_HEADER as u64 {
        return Ok(0);
    }
    let mut reader = BufReader::with_capacity(1 << 16, file);
    let mut header = [0u8; WAL_HEADER];
    reader.read_exact(&mut header)?;
    let big_endian = match be32(&header, 0) {
        WAL_MAGIC_LE => false,
        WAL_MAGIC_BE => true,
        _ => return Ok(0),
    };
    let page_size = be32(&header, 8);
    if !valid_page_size(page_size) {
        return Ok(0);
    }
    let mut sum = wal_checksum(big_endian, &header[..24], (0, 0));
    if sum != (be32(&header, 24), be32(&header, 28)) {
        return Ok(0);
    }
    let salts = (be32(&header, 16), be32(&header, 20));
    let frame_size = FRAME_HEADER as u64 + u64::from(page_size);
    let frames = (len - WAL_HEADER as u64) / frame_size;
    let mut frame = vec![0u8; frame_size as usize];
    let mut last_commit = 0u64;
    for n in 1..=frames {
        reader.read_exact(&mut frame)?;
        if (be32(&frame, 8), be32(&frame, 12)) != salts || be32(&frame, 0) == 0 {
            break;
        }
        sum = wal_checksum(big_endian, &frame[..8], sum);
        sum = wal_checksum(big_endian, &frame[FRAME_HEADER..], sum);
        if sum != (be32(&frame, 16), be32(&frame, 20)) {
            break;
        }
        if be32(&frame, 4) != 0 {
            last_commit = n;
        }
    }
    Ok(match last_commit {
        0 => 0,
        n => WAL_HEADER as u64 + n * frame_size,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database_artifacts::{
        ArtifactExpectation, DatabaseArtifactRepository, SeaOrmDatabaseArtifactRepository,
    };
    use crate::models::sql_wal_mark;
    use crate::sql::store::key::{Lineage, PublishId};
    use crate::sql::store::manifest::{
        now_timestamp, ObjectRecord, Publish, PublishChain, PublishKind,
    };
    use crate::sql::store::memory::MemorySqlObjectStore;
    use crate::sql::store::object::sha256;
    use crate::sql::store::policy::SpaceAllowlist;
    use crate::sql::store::shadow::machine::Policy;
    use crate::sql::store::shadow::metrics::NoopMetrics;
    use crate::sql::store::shadow::scheduler::{self, SchedulerConfig, ShadowDeps};
    use crate::sql::store::shadow::source::tests::{repository, saved, SPACE};
    use crate::sql::store::shadow::source::PgArtifactSource;
    use crate::sql::store::shadow::NoticeBoard;
    use rand::SeedableRng;
    use sea_orm::{sea_query::Expr, ActiveValue::Set};
    use std::sync::Mutex;
    use std::time::Duration;

    const OTHER_SPACE: &str = "tinycloud:pkh:eip155:1:0xCd://default";

    /// A real SQLite database the way the node keeps one: WAL mode,
    /// autocheckpoint off, checkpoints with TRUNCATE.
    struct Live {
        _dir: tempfile::TempDir,
        path: PathBuf,
        conn: rusqlite::Connection,
        rows: usize,
    }

    impl Live {
        fn new(page_size: u32) -> Self {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("live.db");
            let conn = rusqlite::Connection::open(&path).unwrap();
            conn.execute_batch(&format!(
                "PRAGMA page_size = {page_size};
                 PRAGMA journal_mode = WAL;
                 PRAGMA wal_autocheckpoint = 0;
                 CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT NOT NULL);"
            ))
            .unwrap();
            Self {
                _dir: dir,
                path,
                conn,
                rows: 0,
            }
        }

        /// `n` commits of one row each.
        fn write(&mut self, n: usize) {
            for _ in 0..n {
                self.rows += 1;
                self.conn
                    .execute(
                        "INSERT INTO t (v) VALUES (?1)",
                        [format!("row-{}-{}", self.rows, "x".repeat(300))],
                    )
                    .unwrap();
            }
        }

        /// The checkpoint bytes, as the node saves them.
        fn checkpoint(&self) -> Vec<u8> {
            self.conn
                .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| {
                    r.get::<_, i64>(0)
                })
                .unwrap();
            std::fs::read(&self.path).unwrap()
        }

        /// The cumulative WAL since the last checkpoint.
        fn wal(&self) -> Vec<u8> {
            std::fs::read(wal_path(&self.path)).unwrap()
        }
    }

    #[derive(Default)]
    struct Counted(Mutex<Vec<(RestoreResult, u64)>>);

    impl RestoreMetrics for Counted {
        fn restore_check(&self, result: RestoreResult, segments_unverified: u64, _: f64) {
            self.0.lock().unwrap().push((result, segments_unverified));
        }
    }

    struct Rig {
        conn: DatabaseConnection,
        repo: Arc<SeaOrmDatabaseArtifactRepository>,
        store: Arc<MemorySqlObjectStore>,
        scratch: tempfile::TempDir,
        metrics: Arc<Counted>,
    }

    async fn rig() -> Rig {
        let (conn, repo) = repository().await;
        Rig {
            conn,
            repo,
            store: Arc::new(MemorySqlObjectStore::default()),
            scratch: tempfile::tempdir().unwrap(),
            metrics: Arc::default(),
        }
    }

    fn db(db_id: &str) -> DbRef<'_> {
        DbRef {
            space: SPACE,
            db_id,
        }
    }

    impl Rig {
        fn deps(&self) -> RestoreDeps {
            RestoreDeps {
                control: self.conn.clone(),
                store: self.store.clone(),
                source: Arc::new(PgArtifactSource::new(self.repo.clone())),
                disk: DiskBudget::new(self.scratch.path(), 1 << 26),
                metrics: self.metrics.clone(),
            }
        }

        fn manifest(&self) -> DbSqlManifest {
            DbSqlManifest::new(self.conn.clone())
        }

        /// Run the P1 uploader until `db_id`'s frontier reaches `revision`.
        async fn upload(&self, db_id: &str, revision: u64) -> Frontier {
            let upload_scratch = tempfile::tempdir().unwrap();
            let handle = scheduler::spawn(
                ShadowDeps {
                    control: self.conn.clone(),
                    manifest: Arc::new(self.manifest()),
                    store: self.store.clone(),
                    source: Arc::new(PgArtifactSource::new(self.repo.clone())),
                    disk: DiskBudget::new(upload_scratch.path(), 1 << 24),
                    board: Arc::new(NoticeBoard::new(
                        SpaceAllowlist::new([SPACE.to_string()]),
                        Arc::new(NoopMetrics),
                    )),
                    metrics: Arc::new(NoopMetrics),
                },
                SchedulerConfig {
                    policy: Policy {
                        interval: Duration::ZERO,
                        backoff_base: Duration::from_millis(10),
                        backoff_max: Duration::from_millis(50),
                    },
                    tick: Duration::from_millis(5),
                    ..SchedulerConfig::default()
                },
            );
            let manifest = self.manifest();
            let frontier = tokio::time::timeout(Duration::from_secs(10), async {
                loop {
                    if let Some(f) = manifest.current(&db(db_id)).await.unwrap() {
                        if f.last_seq >= revision {
                            return f;
                        }
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .expect("the uploader reaches the revision");
            handle.drain(Duration::from_secs(5)).await;
            frontier
        }

        async fn check(&self, db_id: &str) -> DbReport {
            check_database(&self.deps(), &db(db_id)).await
        }

        async fn save_delta(&self, db_id: &str, wal: &[u8], revision: i64, cid: &str) -> i64 {
            self.repo
                .save_delta(
                    "sql",
                    SPACE,
                    db_id,
                    bytes::Bytes::copy_from_slice(wal),
                    ArtifactExpectation::Derived {
                        revision,
                        checkpoint_content_hash: cid.into(),
                    },
                )
                .await
                .unwrap()
                .revision
        }

        /// The published segment the frontier ends in.
        async fn frontier_segment(&self, db_id: &str, f: &Frontier) -> ObjectKey {
            self.manifest()
                .list_objects(&db(db_id), Some(ObjectState::Published))
                .await
                .unwrap()
                .into_iter()
                .find(|r| r.key.kind() == ObjectKind::Segment && r.key.to_seq() == f.last_seq)
                .expect("the frontier's segment")
                .key
        }

        fn scratch_is_empty(&self) -> bool {
            std::fs::read_dir(self.scratch.path()).unwrap().count() == 0
        }
    }

    fn assert_result(report: &DbReport, result: RestoreResult) {
        assert_eq!(report.result, result, "{report:?}");
    }

    /// A Live database with a checkpoint at 3 rows and two cumulative WALs.
    fn bootstrap_fixture() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let mut live = Live::new(4096);
        live.write(3);
        let checkpoint = live.checkpoint();
        live.write(2);
        let wal1 = live.wal();
        live.write(2);
        let wal2 = live.wal();
        (checkpoint, wal1, wal2)
    }

    #[tokio::test]
    async fn a_matching_restore_is_ok() {
        let rig = rig().await;
        let mut live = Live::new(4096);
        live.write(3);
        let meta = saved(&rig.repo, "main", &live.checkpoint(), &[]).await;
        // A checkpoint without a WAL: a snapshot at its revision.
        let f = rig.upload("main", 1).await;
        assert_eq!((f.base_seq, f.last_seq), (1, 1));
        let report = rig.check("main").await;
        assert_result(&report, RestoreResult::Ok);
        assert_eq!(
            (report.segments_required, report.segments_unverified),
            (0, 0)
        );
        // WAL deltas on the same checkpoint: a segment appended on base 1.
        live.write(4);
        let revision = rig
            .save_delta(
                "main",
                &live.wal(),
                meta.revision,
                &meta.checkpoint_content_hash,
            )
            .await;
        let f = rig.upload("main", revision as u64).await;
        assert_eq!((f.base_seq, f.last_seq), (1, 2));
        let report = rig.check("main").await;
        assert_result(&report, RestoreResult::Ok);
        assert_eq!(report.reason, None);
        assert_eq!(
            (
                report.segments_required,
                report.segments_verified,
                report.segments_unverified
            ),
            (1, 1, 0)
        );
        assert_eq!((report.last_seq, report.pg_revision), (Some(2), Some(2)));
        assert!(rig.scratch_is_empty(), "scratch files are removed");
        assert_eq!(
            *rig.metrics.0.lock().unwrap(),
            vec![(RestoreResult::Ok, 0), (RestoreResult::Ok, 0)]
        );
    }

    #[tokio::test]
    async fn a_bootstrap_chain_at_seq_0_restores_at_its_frontier() {
        let rig = rig().await;
        let (checkpoint, wal1, wal2) = bootstrap_fixture();
        let meta = saved(&rig.repo, "main", &checkpoint, &[&wal1, &wal2]).await;
        assert_eq!(meta.revision, 3);
        let f = rig.upload("main", 3).await;
        // The P1 bootstrap: the checkpoint at at_seq 0, the WAL as 1..=3.
        assert_eq!((f.base_seq, f.last_seq), (0, 3));
        let report = rig.check("main").await;
        assert_result(&report, RestoreResult::Ok);
        assert_eq!(report.last_seq, Some(3));
        assert_eq!(
            (report.segments_verified, report.segments_unverified),
            (1, 0)
        );
    }

    #[tokio::test]
    async fn a_snapshot_at_seq_0_alone_is_not_a_restore_point() {
        let rig = rig().await;
        let lineage = Lineage::random();
        let key = ObjectKey::snapshot(&db("main"), &lineage, 0, &sha256(b"ck")).unwrap();
        let manifest = rig.manifest();
        manifest
            .record_object(
                &db("main"),
                &ObjectRecord {
                    key: key.clone(),
                    format: SNAPSHOT_FORMAT.into(),
                    bytes: 2,
                    created_at: now_timestamp(),
                },
            )
            .await
            .unwrap();
        manifest
            .publish_cas(
                &db("main"),
                None,
                Publish {
                    kind: PublishKind::Snapshot,
                    object: key,
                    base_checkpoint_cid: "ck".into(),
                    frontier_bytes: 2,
                    publish_id: PublishId::random(),
                    now: now_timestamp(),
                },
            )
            .await
            .unwrap();
        let report = rig.check("main").await;
        assert_result(&report, RestoreResult::Unreadable);
        assert_eq!(
            report.reason.as_deref(),
            Some("at_seq 0 is not a restore point")
        );
    }

    #[tokio::test]
    async fn a_corrupted_segment_byte_is_unreadable() {
        let rig = rig().await;
        let (checkpoint, wal1, wal2) = bootstrap_fixture();
        saved(&rig.repo, "main", &checkpoint, &[&wal1, &wal2]).await;
        let f = rig.upload("main", 3).await;
        // A byte flipped in the stored object: the download is refused.
        let key = rig.frontier_segment("main", &f).await;
        let mut bytes = rig.store.bytes(key.as_str()).unwrap();
        let at = bytes.len() / 2;
        bytes[at] ^= 0x40;
        rig.store.plant(key.as_str(), bytes);
        let report = rig.check("main").await;
        assert_result(&report, RestoreResult::Unreadable);
        assert!(
            report.reason.as_deref().unwrap().starts_with("segment: "),
            "{report:?}"
        );
        assert_eq!(
            (report.segments_verified, report.segments_unverified),
            (0, 1)
        );
        assert!(rig.scratch_is_empty(), "the refused download is gone");

        // A byte flipped before upload (so the key hashes it): the WAL walk
        // finds the frame whose checksum fails, before SQLite opens it.
        let mut torn = wal2.clone();
        let at = torn.len() - 10;
        torn[at] ^= 0x40;
        saved(&rig.repo, "other", &checkpoint, &[&wal1, &torn]).await;
        rig.upload("other", 3).await;
        let report = rig.check("other").await;
        assert_result(&report, RestoreResult::Unreadable);
        let reason = report.reason.unwrap();
        assert!(
            reason.starts_with("restored copy: refused before open: WAL frame")
                && reason.ends_with("fails its checksum"),
            "{reason}"
        );
    }

    /// Records, per download, the scratch directory and the modes of it and
    /// of the file written into it.
    #[cfg(unix)]
    struct Inspecting {
        inner: Arc<MemorySqlObjectStore>,
        seen: Mutex<Vec<(PathBuf, u32, u32)>>,
    }

    #[cfg(unix)]
    #[async_trait::async_trait]
    impl SqlObjectStore for Inspecting {
        async fn put_file(
            &self,
            key: &ObjectKey,
            path: &Path,
            size: u64,
        ) -> Result<crate::sql::store::object::PutOutcome, SqlStoreError> {
            self.inner.put_file(key, path, size).await
        }
        async fn get_to_file(
            &self,
            key: &ObjectKey,
            path: &Path,
            max_bytes: u64,
        ) -> Result<Option<ObjectMeta>, SqlStoreError> {
            use std::os::unix::fs::PermissionsExt;
            let result = self.inner.get_to_file(key, path, max_bytes).await;
            let dir = path.parent().unwrap().to_path_buf();
            let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
            let entry = (dir.clone(), mode(&dir), mode(path));
            self.seen.lock().unwrap().push(entry);
            result
        }
        async fn get_range(
            &self,
            key: &ObjectKey,
            range: crate::storage::ByteRangeSpec,
        ) -> Result<Option<crate::sql::store::object::ObjectRange>, SqlStoreError> {
            self.inner.get_range(key, range).await
        }
        async fn head(&self, key: &ObjectKey) -> Result<Option<ObjectMeta>, SqlStoreError> {
            self.inner.head(key).await
        }
    }

    /// Restore scratch holds tenant databases in plaintext: the directory is
    /// 0700, each file 0600, and both are gone once a check fails.
    #[cfg(unix)]
    #[tokio::test]
    async fn restore_scratch_is_owner_only_and_removed_when_the_check_fails() {
        let rig = rig().await;
        let (checkpoint, wal1, wal2) = bootstrap_fixture();
        // A byte flipped before upload: the downloads succeed, then the WAL
        // walk refuses the frame whose checksum fails.
        let mut torn = wal2.clone();
        let at = torn.len() - 10;
        torn[at] ^= 0x40;
        saved(&rig.repo, "main", &checkpoint, &[&wal1, &torn]).await;
        rig.upload("main", 3).await;
        let store = Arc::new(Inspecting {
            inner: rig.store.clone(),
            seen: Mutex::default(),
        });
        let deps = RestoreDeps {
            store: store.clone(),
            ..rig.deps()
        };
        let report = check_database(&deps, &db("main")).await;
        assert_result(&report, RestoreResult::Unreadable);
        assert!(
            report
                .reason
                .as_deref()
                .unwrap()
                .ends_with("fails its checksum"),
            "{report:?}"
        );
        let seen = store.seen.lock().unwrap();
        assert_eq!(seen.len(), 2, "the snapshot and the segment");
        for (dir, dir_mode, file_mode) in seen.iter() {
            assert_eq!((*dir_mode, *file_mode), (0o700, 0o600), "{dir:?}");
            assert!(!dir.exists(), "{dir:?} outlived the failed check");
        }
        assert!(rig.scratch_is_empty());
    }

    #[test]
    fn a_page_size_mismatched_wal_is_refused_before_open() {
        let mut db4k = Live::new(4096);
        db4k.write(2);
        let checkpoint = db4k.checkpoint();
        let mut db1k = Live::new(1024);
        db1k.write(2);
        let wal = db1k.wal();
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join(DB_FILE);
        std::fs::write(&db_path, &checkpoint).unwrap();
        std::fs::write(wal_path(&db_path), &wal).unwrap();
        assert_eq!(
            materialise(&db_path, true, true),
            Err(MaterialiseError::PageSizeMismatch {
                db: 4096,
                wal: 1024
            })
        );
        // SQLite never opened the pair: no -shm index, both files untouched.
        assert!(!sibling(&db_path, "-shm").exists());
        assert_eq!(std::fs::read(&db_path).unwrap(), checkpoint);
        assert_eq!(std::fs::read(wal_path(&db_path)).unwrap(), wal);
    }

    #[tokio::test]
    async fn a_published_page_size_mismatched_wal_is_unreadable() {
        let rig = rig().await;
        let mut db4k = Live::new(4096);
        db4k.write(2);
        let mut db1k = Live::new(1024);
        db1k.write(2);
        saved(&rig.repo, "main", &db4k.checkpoint(), &[&db1k.wal()]).await;
        rig.upload("main", 2).await;
        let report = rig.check("main").await;
        assert_result(&report, RestoreResult::Unreadable);
        assert_eq!(
            report.reason.as_deref(),
            Some(
                "restored copy: refused before open: the WAL page size 1024 differs from the \
                 database page size 4096"
            )
        );
    }

    #[tokio::test]
    async fn postgres_ahead_of_the_frontier_is_not_comparable() {
        let rig = rig().await;
        let mut live = Live::new(4096);
        live.write(3);
        let checkpoint = live.checkpoint();
        live.write(2);
        let meta = saved(&rig.repo, "main", &checkpoint, &[&live.wal()]).await;
        rig.upload("main", 2).await;
        live.write(1);
        let revision = rig
            .save_delta(
                "main",
                &live.wal(),
                meta.revision,
                &meta.checkpoint_content_hash,
            )
            .await;
        let report = rig.check("main").await;
        assert_result(&report, RestoreResult::NotComparable);
        assert_eq!(
            report.reason.as_deref(),
            Some("not comparable at this revision: postgres is at revision 3, the frontier at 2")
        );
        assert_eq!(
            (report.last_seq, report.pg_revision),
            (Some(2), Some(revision))
        );
        // Nothing was read, so the frontier's segment is unverified.
        assert_eq!(
            (report.segments_required, report.segments_unverified),
            (1, 1)
        );
        assert!(rig.scratch_is_empty());
        assert_eq!(
            *rig.metrics.0.lock().unwrap(),
            vec![(RestoreResult::NotComparable, 1)]
        );
    }

    /// Record and publish `objects` (bodies put into the store) by hand.
    async fn publish_by_hand(rig: &Rig, db_id: &str, cid: &str, objects: &[(ObjectKey, &[u8])]) {
        let dir = tempfile::tempdir().unwrap();
        let mut records = Vec::new();
        for (i, (key, body)) in objects.iter().enumerate() {
            let path = dir.path().join(i.to_string());
            std::fs::write(&path, body).unwrap();
            rig.store
                .put_file(key, &path, body.len() as u64)
                .await
                .unwrap();
            records.push(ObjectRecord {
                key: key.clone(),
                format: match key.kind() {
                    ObjectKind::Snapshot => SNAPSHOT_FORMAT,
                    ObjectKind::Segment => SEGMENT_FORMAT,
                }
                .into(),
                bytes: body.len() as u64,
                created_at: now_timestamp(),
            });
        }
        rig.manifest()
            .publish_chain(
                &db(db_id),
                None,
                PublishChain {
                    objects: records,
                    base_checkpoint_cid: cid.into(),
                    publish_id: PublishId::random(),
                    now: now_timestamp(),
                },
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn a_chain_that_restores_another_state_is_a_mismatch() {
        let rig = rig().await;
        let (checkpoint, wal1, wal2) = bootstrap_fixture();
        let meta = saved(&rig.repo, "main", &checkpoint, &[&wal1, &wal2]).await;
        // The store claims revision 3 but carries the WAL of revision 2.
        let lineage = Lineage::random();
        let snapshot = ObjectKey::snapshot(&db("main"), &lineage, 0, &sha256(&checkpoint)).unwrap();
        let segment = ObjectKey::segment(&db("main"), &lineage, 0, 1, 3, &sha256(&wal1)).unwrap();
        publish_by_hand(
            &rig,
            "main",
            &meta.checkpoint_content_hash,
            &[(snapshot, &checkpoint), (segment, &wal1)],
        )
        .await;
        let report = rig.check("main").await;
        assert_result(&report, RestoreResult::Mismatch);
        assert_eq!(
            report.reason.as_deref(),
            Some("the restored file differs from postgres's at revision 3")
        );
        // The restore itself was sound: its segment counts as verified.
        assert_eq!(report.segments_unverified, 0);
    }

    #[tokio::test]
    async fn a_key_outside_the_db_prefix_is_unreadable() {
        let rig = rig().await;
        let (checkpoint, wal1, _) = bootstrap_fixture();
        for db_id in ["main", "other"] {
            saved(&rig.repo, db_id, &checkpoint, &[&wal1]).await;
            rig.upload(db_id, 2).await;
        }
        let f = rig.manifest().current(&db("main")).await.unwrap().unwrap();
        let foreign = |key: &ObjectKey| {
            let other = DbRef {
                space: OTHER_SPACE,
                db_id: "main",
            };
            match key.kind() {
                ObjectKind::Snapshot => {
                    ObjectKey::snapshot(&other, key.lineage(), key.base_seq(), key.sha256())
                }
                ObjectKind::Segment => ObjectKey::segment(
                    &other,
                    key.lineage(),
                    key.base_seq(),
                    key.from_seq(),
                    key.to_seq(),
                    key.sha256(),
                ),
            }
            .unwrap()
        };

        // The manifest's base_snapshot_key points into another space.
        let snapshot = ObjectKey::snapshot(
            &db("main"),
            &f.lineage,
            f.base_seq,
            &<[u8; 32]>::try_from(
                hex::decode(f.base_snapshot_key.rsplit_once('-').unwrap().1).unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        manifest_row::Entity::update_many()
            .col_expr(
                manifest_row::Column::BaseSnapshotKey,
                Expr::value(foreign(&snapshot).as_str()),
            )
            .filter(manifest_row::Column::DbId.eq("main"))
            .exec(&rig.conn)
            .await
            .unwrap();
        let report = rig.check("main").await;
        assert_result(&report, RestoreResult::Unreadable);
        assert_eq!(report.reason.as_deref(), Some(KEY_OUTSIDE_DB_PREFIX));

        // An inventory row's key points into another space.
        let f = rig.manifest().current(&db("other")).await.unwrap().unwrap();
        let segment = rig.frontier_segment("other", &f).await;
        let moved = foreign(&segment);
        object::Entity::update_many()
            .col_expr(object::Column::Key, Expr::value(moved.as_str()))
            .filter(object::Column::DbId.eq("other"))
            .filter(object::Column::Kind.eq("segment"))
            .exec(&rig.conn)
            .await
            .unwrap();
        let report = rig.check("other").await;
        assert_result(&report, RestoreResult::Unreadable);
        assert_eq!(report.reason.as_deref(), Some(KEY_OUTSIDE_DB_PREFIX));
        assert!(rig.scratch_is_empty(), "nothing was downloaded");
    }

    #[tokio::test]
    async fn a_missing_segment_reports_the_shortfall() {
        let rig = rig().await;
        let (checkpoint, wal1, _) = bootstrap_fixture();
        saved(&rig.repo, "main", &checkpoint, &[&wal1]).await;
        let f = rig.upload("main", 2).await;
        // The segment row is no longer published: the chain stops at 0.
        object::Entity::update_many()
            .col_expr(object::Column::State, Expr::value("uploaded"))
            .filter(object::Column::Kind.eq("segment"))
            .exec(&rig.conn)
            .await
            .unwrap();
        let report = rig.check("main").await;
        assert_result(&report, RestoreResult::Unreadable);
        assert_eq!(
            report.reason,
            Some(format!(
                "no published segment on the base, the frontier claims seq {}",
                f.last_seq
            ))
        );
        assert_eq!(report.segments_unverified, 1);
    }

    #[test]
    fn the_wal_walk_refuses_what_sqlite_would_skip() {
        let mut live = Live::new(4096);
        live.write(2);
        let checkpoint = live.checkpoint();
        live.write(3);
        let wal = live.wal();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("w");
        let walk = |bytes: &[u8]| {
            std::fs::write(&path, bytes).unwrap();
            check_wal(&path, 4096)
        };
        let frames = walk(&wal).unwrap();
        assert!(frames >= 3, "{frames}");
        assert_eq!(walk(b""), Ok(0));
        assert!(matches!(
            walk(&wal[..20]),
            Err(MaterialiseError::Refused(_))
        ));
        // A header checksum that fails.
        let mut bad = wal.clone();
        bad[27] ^= 1;
        assert_eq!(
            walk(&bad),
            Err(refused("the WAL header checksum does not match"))
        );
        // A frame with other salts.
        let mut bad = wal.clone();
        bad[WAL_HEADER + 8] ^= 1;
        assert_eq!(walk(&bad), Err(refused("WAL frame 1 carries other salts")));
        // A torn last frame.
        assert_eq!(
            walk(&wal[..wal.len() - 1]),
            Err(refused("the WAL ends inside a frame"))
        );
        // A wrong magic.
        let mut bad = wal.clone();
        bad[0] = 0;
        assert_eq!(walk(&bad), Err(refused("the WAL magic is wrong")));

        // The accepted WAL replays every frame, and the result is sound.
        let db_path = dir.path().join(DB_FILE);
        std::fs::write(&db_path, &checkpoint).unwrap();
        std::fs::write(wal_path(&db_path), &wal).unwrap();
        assert_eq!(materialise(&db_path, true, true), Ok(frames));
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        let rows: i64 = conn
            .query_row("SELECT count(*) FROM t", [], |r| r.get(0))
            .unwrap();
        assert_eq!(rows, 5);
    }

    #[test]
    fn a_file_without_a_sqlite_header_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(DB_FILE);
        std::fs::write(&path, b"short").unwrap();
        assert_eq!(
            materialise(&path, false, true),
            Err(refused("the database file is shorter than its header"))
        );
        std::fs::write(&path, [7u8; 4096]).unwrap();
        assert_eq!(
            materialise(&path, false, true),
            Err(refused("the database file has no SQLite header"))
        );
    }

    #[tokio::test]
    async fn the_sample_is_bounded_and_allowlisted() {
        let rig = rig().await;
        let spaces = [SPACE, OTHER_SPACE, "tinycloud:pkh:eip155:1:0xEf://default"];
        for (space, count) in spaces.iter().zip([5, 3, 2]) {
            for i in 0..count {
                manifest_row::Entity::insert(manifest_row::ActiveModel {
                    space: Set(space.to_string()),
                    db_id: Set(format!("db{i}")),
                    lineage: Set(Lineage::random().to_string()),
                    epoch: Set(0),
                    revision: Set(1),
                    base_snapshot_key: Set("k".into()),
                    base_seq: Set(1),
                    base_checkpoint_cid: Set("c".into()),
                    last_seq: Set(1),
                    publish_id: Set(PublishId::random().to_string()),
                    published_at: Set(now_timestamp()),
                    frontier_bytes: Set(1),
                })
                .exec(&rig.conn)
                .await
                .unwrap();
            }
        }
        let allowed = [SPACE.to_string(), OTHER_SPACE.to_string()];
        let mut rng = rand::rngs::StdRng::seed_from_u64(7);
        let picked = sample_databases(&rig.conn, &allowed, 4, 2, &mut rng)
            .await
            .unwrap();
        assert_eq!(picked.len(), 4);
        assert!(
            picked.iter().all(|(s, _)| allowed.contains(s)),
            "{picked:?}"
        );
        let mut unique = picked.clone();
        unique.dedup();
        assert_eq!(unique, picked, "sorted and distinct");
        let all = sample_databases(&rig.conn, &allowed, 100, 2, &mut rng)
            .await
            .unwrap();
        assert_eq!(all.len(), 8);
        assert!(sample_databases(&rig.conn, &allowed, 0, 2, &mut rng)
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn a_run_report_counts_each_verdict() {
        let rig = rig().await;
        let (checkpoint, wal1, wal2) = bootstrap_fixture();
        saved(&rig.repo, "main", &checkpoint, &[&wal1, &wal2]).await;
        rig.upload("main", 3).await;
        let report = check_databases(
            &rig.deps(),
            &[
                (SPACE.to_string(), "main".to_string()),
                (SPACE.to_string(), "absent".to_string()),
            ],
        )
        .await;
        assert_eq!(
            (
                report.sampled,
                report.ok,
                report.unreadable,
                report.passed()
            ),
            (2, 1, 1, false)
        );
        assert_eq!(
            report.databases[1].reason.as_deref(),
            Some("no published frontier")
        );
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["databases"][0]["result"], "ok");
    }

    // ---- TC-1491 P3: wal-delta-v1 chains -----------------------------------

    impl Live {
        /// The node reopening the database from its Postgres artifact (the
        /// stored checkpoint and WAL) in a fresh directory, mid-generation.
        fn hydrate(&mut self, checkpoint: &[u8], wal: &[u8]) {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("live.db");
            std::fs::write(&path, checkpoint).unwrap();
            std::fs::write(wal_path(&path), wal).unwrap();
            let conn = rusqlite::Connection::open(&path).unwrap();
            conn.execute_batch("PRAGMA wal_autocheckpoint = 0;")
                .unwrap();
            let rows = self.rows;
            drop(std::mem::replace(
                self,
                Self {
                    _dir: dir,
                    path,
                    conn,
                    rows,
                },
            ));
        }
    }

    impl Rig {
        /// [`Rig::upload`] with deltas planned at any size.
        async fn upload_deltas(&self, db_id: &str, revision: u64) -> Frontier {
            let upload_scratch = tempfile::tempdir().unwrap();
            let handle = scheduler::spawn(
                ShadowDeps {
                    control: self.conn.clone(),
                    manifest: Arc::new(self.manifest()),
                    store: self.store.clone(),
                    source: Arc::new(PgArtifactSource::new(self.repo.clone())),
                    disk: DiskBudget::new(upload_scratch.path(), 1 << 24),
                    board: Arc::new(NoticeBoard::new(
                        SpaceAllowlist::new([SPACE.to_string()]),
                        Arc::new(NoopMetrics),
                    )),
                    metrics: Arc::new(NoopMetrics),
                },
                SchedulerConfig {
                    policy: Policy {
                        interval: Duration::ZERO,
                        backoff_base: Duration::from_millis(10),
                        backoff_max: Duration::from_millis(50),
                    },
                    tick: Duration::from_millis(5),
                    delta_min_wal_bytes: 0,
                    ..SchedulerConfig::default()
                },
            );
            let manifest = self.manifest();
            let frontier = tokio::time::timeout(Duration::from_secs(10), async {
                loop {
                    if let Some(f) = manifest.current(&db(db_id)).await.unwrap() {
                        if f.last_seq >= revision {
                            return f;
                        }
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .expect("the uploader reaches the revision");
            handle.drain(Duration::from_secs(5)).await;
            frontier
        }

        /// The published segments of `db_id`, in chain order, with their formats.
        async fn segments(&self, db_id: &str) -> Vec<(ObjectKey, String)> {
            let mut segments: Vec<_> = self
                .manifest()
                .list_objects(&db(db_id), Some(ObjectState::Published))
                .await
                .unwrap()
                .into_iter()
                .filter(|r| r.key.kind() == ObjectKind::Segment)
                .map(|r| (r.key, r.format))
                .collect();
            segments.sort_by_key(|(key, _)| (key.from_seq(), key.to_seq()));
            segments
        }

        /// The published segments as `(from, to, format)`.
        async fn ranges(&self, db_id: &str) -> Vec<(u64, u64, String)> {
            self.segments(db_id)
                .await
                .into_iter()
                .map(|(key, format)| (key.from_seq(), key.to_seq(), format))
                .collect()
        }

        /// The segment `from..=to` is no longer published.
        async fn unpublish(&self, db_id: &str, from: u64, to: u64) {
            object::Entity::update_many()
                .col_expr(object::Column::State, Expr::value("uploaded"))
                .filter(object::Column::DbId.eq(db_id))
                .filter(object::Column::Kind.eq("segment"))
                .filter(object::Column::FromSeq.eq(seq(from)))
                .filter(object::Column::ToSeq.eq(seq(to)))
                .exec(&self.conn)
                .await
                .unwrap();
        }

        async fn drop_mark(&self, db_id: &str, revision: i64) {
            sql_wal_mark::Entity::delete_many()
                .filter(sql_wal_mark::Column::Name.eq(db_id))
                .filter(sql_wal_mark::Column::Revision.eq(revision))
                .exec(&self.conn)
                .await
                .unwrap();
        }
    }

    /// One database on one checkpoint, saved and uploaded a revision at a
    /// time: the chain is the snapshot at the checkpoint's revision, a
    /// cumulative segment for the first save (the frontier is still at its
    /// snapshot) and a delta for each save after it.
    struct Generation {
        db_id: &'static str,
        live: Live,
        cid: String,
        revision: i64,
        checkpoint_bytes: u64,
    }

    impl Generation {
        async fn new(rig: &Rig, db_id: &'static str) -> Self {
            let mut live = Live::new(4096);
            live.write(3);
            let checkpoint = live.checkpoint();
            let meta = saved(&rig.repo, db_id, &checkpoint, &[]).await;
            let g = Self {
                db_id,
                live,
                cid: meta.checkpoint_content_hash,
                revision: meta.revision,
                checkpoint_bytes: checkpoint.len() as u64,
            };
            let f = rig.upload_deltas(db_id, 1).await;
            assert_eq!((f.base_seq, f.last_seq), (1, 1));
            g
        }

        /// Two more commits, stored as the next revision's WAL.
        async fn save(&mut self, rig: &Rig) {
            self.live.write(2);
            self.revision = rig
                .save_delta(self.db_id, &self.live.wal(), self.revision, &self.cid)
                .await;
        }

        async fn upload(&self, rig: &Rig) -> Frontier {
            rig.upload_deltas(self.db_id, self.revision as u64).await
        }

        async fn save_and_upload(&mut self, rig: &Rig) -> Frontier {
            self.save(rig).await;
            self.upload(rig).await
        }
    }

    /// A generation with a cumulative segment `2..=2` and deltas `3..=3` and
    /// `4..=4` published.
    async fn delta_chain(rig: &Rig, db_id: &'static str) -> (Generation, Frontier) {
        let mut g = Generation::new(rig, db_id).await;
        for _ in 0..2 {
            g.save_and_upload(rig).await;
        }
        let f = g.save_and_upload(rig).await;
        assert_eq!((f.base_seq, f.last_seq), (1, 4));
        assert_eq!(
            rig.ranges(db_id).await,
            vec![
                (2, 2, "wal-cum-v1".to_string()),
                (3, 3, "wal-delta-v1".to_string()),
                (4, 4, "wal-delta-v1".to_string()),
            ]
        );
        (g, f)
    }

    #[tokio::test]
    async fn a_delta_chain_restores_byte_exact() {
        let rig = rig().await;
        let (g, f) = delta_chain(&rig, "main").await;
        let report = rig.check("main").await;
        assert_result(&report, RestoreResult::Ok);
        assert_eq!(report.reason, None);
        assert_eq!(
            (
                report.segments_required,
                report.segments_verified,
                report.segments_unverified
            ),
            (3, 3, 0)
        );
        assert_eq!((report.last_seq, report.pg_revision), (Some(4), Some(4)));
        assert!(rig.scratch_is_empty(), "scratch files are removed");

        // The objects are the stored WAL cut at the revisions' boundaries:
        // appended in order they are PG's WAL, byte for byte.
        let wal = g.live.wal();
        let mut joined = Vec::new();
        let mut sizes = 0;
        for (key, _) in rig.segments("main").await {
            let bytes = rig.store.bytes(key.as_str()).unwrap();
            assert!(!bytes.is_empty());
            sizes += bytes.len() as u64;
            joined.extend(bytes);
        }
        assert_eq!(joined, wal);
        assert_eq!(f.frontier_bytes, g.checkpoint_bytes + sizes);
        // Each delta is smaller than the whole WAL it extends.
        let deltas = rig.segments("main").await;
        for (key, _) in &deltas[1..] {
            assert!((rig.store.bytes(key.as_str()).unwrap().len()) < wal.len());
        }
    }

    #[tokio::test]
    async fn a_gap_in_the_delta_chain_reports_the_shortfall() {
        let rig = rig().await;
        let (_g, f) = delta_chain(&rig, "main").await;
        rig.unpublish("main", 3, 3).await;
        let report = rig.check("main").await;
        assert_result(&report, RestoreResult::Unreadable);
        assert_eq!(
            report.reason,
            Some(format!(
                "the published chain reaches seq 2, the frontier claims {}",
                f.last_seq
            ))
        );
        // The cumulative segment found, and the delta missing after it.
        assert_eq!(
            (report.segments_required, report.segments_unverified),
            (2, 2)
        );

        // Without the cumulative segment the chain does not start at all.
        let (_g, f) = delta_chain(&rig, "other").await;
        rig.unpublish("other", 2, 2).await;
        let report = rig.check("other").await;
        assert_result(&report, RestoreResult::Unreadable);
        assert_eq!(
            report.reason,
            Some(format!(
                "the published chain reaches seq 1, the frontier claims {}",
                f.last_seq
            ))
        );
        assert_eq!(report.segments_unverified, 1);
    }

    #[tokio::test]
    async fn a_published_delta_beyond_the_frontier_is_not_part_of_its_chain() {
        let rig = rig().await;
        let (_g, f) = delta_chain(&rig, "main").await;
        let beyond = ObjectKey::segment(
            &db("main"),
            &f.lineage,
            f.base_seq,
            f.last_seq + 1,
            f.last_seq + 3,
            &sha256(b"beyond"),
        )
        .unwrap();
        object::Entity::insert(object::ActiveModel {
            space: Set(SPACE.into()),
            db_id: Set("main".into()),
            lineage: Set(f.lineage.to_string()),
            kind: Set("segment".into()),
            base_seq: Set(seq(f.base_seq)),
            from_seq: Set(seq(f.last_seq + 1)),
            to_seq: Set(seq(f.last_seq + 3)),
            content_hash: Set(beyond.content_hash()),
            format: Set("wal-delta-v1".into()),
            key: Set(beyond.as_str().into()),
            bytes: Set(7),
            state: Set("published".into()),
            created_at: Set(now_timestamp()),
        })
        .exec(&rig.conn)
        .await
        .unwrap();
        let report = rig.check("main").await;
        assert_result(&report, RestoreResult::Ok);
        assert_eq!(report.segments_verified, 3);
    }

    #[tokio::test]
    async fn a_corrupted_delta_byte_is_unreadable() {
        let rig = rig().await;
        let (_g, _f) = delta_chain(&rig, "main").await;
        // A byte flipped in a stored delta: the download is refused.
        let (key, format) = rig.segments("main").await.remove(1);
        assert_eq!(format, "wal-delta-v1");
        let mut bytes = rig.store.bytes(key.as_str()).unwrap();
        let at = bytes.len() / 2;
        bytes[at] ^= 0x40;
        rig.store.plant(key.as_str(), bytes);
        let report = rig.check("main").await;
        assert_result(&report, RestoreResult::Unreadable);
        assert!(
            report.reason.as_deref().unwrap().starts_with("segment: "),
            "{report:?}"
        );
        assert_eq!(
            (
                report.segments_required,
                report.segments_verified,
                report.segments_unverified
            ),
            (3, 0, 3)
        );
        assert!(rig.scratch_is_empty(), "the refused download is gone");

        // A byte flipped before the delta was stored (so its key hashes it):
        // the WAL walk over the whole chain finds the frame that fails its
        // checksum, before SQLite opens anything.
        let mut g = Generation::new(&rig, "torn").await;
        g.save_and_upload(&rig).await;
        g.live.write(2);
        let mut torn = g.live.wal();
        let at = torn.len() - 10;
        torn[at] ^= 0x40;
        g.revision = rig.save_delta("torn", &torn, g.revision, &g.cid).await;
        g.upload(&rig).await;
        assert_eq!(
            rig.ranges("torn").await.last().map(|r| r.2.clone()),
            Some("wal-delta-v1".to_string())
        );
        let report = rig.check("torn").await;
        assert_result(&report, RestoreResult::Unreadable);
        let reason = report.reason.unwrap();
        assert!(
            reason.starts_with("restored copy: refused before open: WAL frame")
                && reason.ends_with("fails its checksum"),
            "{reason}"
        );
    }

    #[tokio::test]
    async fn a_delta_from_another_wal_generation_is_refused_by_its_salts() {
        let rig = rig().await;
        let mut g = Generation::new(&rig, "main").await;
        g.save_and_upload(&rig).await;
        // Another WAL generation's frames appended to this one's: the stored
        // key hashes them, so only the walk over the whole chain can tell.
        let mut other = Live::new(4096);
        other.write(5);
        let foreign = other.wal();
        let mut wal = g.live.wal();
        wal.extend_from_slice(&foreign[WAL_HEADER..]);
        g.revision = rig.save_delta("main", &wal, g.revision, &g.cid).await;
        g.upload(&rig).await;
        assert_eq!(
            rig.ranges("main").await.last().map(|r| r.2.clone()),
            Some("wal-delta-v1".to_string())
        );
        let report = rig.check("main").await;
        assert_result(&report, RestoreResult::Unreadable);
        let reason = report.reason.unwrap();
        assert!(
            reason.starts_with("restored copy: refused before open: WAL frame")
                && reason.ends_with("carries other salts"),
            "{reason}"
        );
    }

    #[tokio::test]
    async fn a_cum_segment_heals_a_delta_gap() {
        let rig = rig().await;
        let (mut g, _) = delta_chain(&rig, "main").await;
        rig.unpublish("main", 3, 3).await;
        assert_result(&rig.check("main").await, RestoreResult::Unreadable);
        // The next upload finds no mark at the frontier's revision and
        // publishes the cumulative WAL: restore needs nothing before it.
        rig.drop_mark("main", 4).await;
        let f = g.save_and_upload(&rig).await;
        assert_eq!((f.base_seq, f.last_seq), (1, 5));
        assert_eq!(
            rig.ranges("main").await,
            vec![
                (2, 2, "wal-cum-v1".to_string()),
                (2, 5, "wal-cum-v1".to_string()),
                (4, 4, "wal-delta-v1".to_string()),
            ]
        );
        let report = rig.check("main").await;
        assert_result(&report, RestoreResult::Ok);
        assert_eq!(
            (
                report.segments_required,
                report.segments_verified,
                report.segments_unverified
            ),
            (1, 1, 0)
        );
        // The frontier counts the snapshot and the one cumulative segment.
        let cum = &rig.segments("main").await[1];
        let bytes = rig.store.bytes(cum.0.as_str()).unwrap().len() as u64;
        assert_eq!(f.frontier_bytes, g.checkpoint_bytes + bytes);
    }

    #[tokio::test]
    async fn a_mixed_cum_and_delta_chain_restores() {
        let rig = rig().await;
        let (mut g, _) = delta_chain(&rig, "main").await;
        // A cumulative segment in the middle of the chain (no mark at the
        // frontier's revision), then deltas after it.
        rig.drop_mark("main", 4).await;
        g.save_and_upload(&rig).await;
        g.save_and_upload(&rig).await;
        let f = g.save_and_upload(&rig).await;
        assert_eq!((f.base_seq, f.last_seq), (1, 7));
        assert_eq!(
            rig.ranges("main").await,
            vec![
                (2, 2, "wal-cum-v1".to_string()),
                (2, 5, "wal-cum-v1".to_string()),
                (3, 3, "wal-delta-v1".to_string()),
                (4, 4, "wal-delta-v1".to_string()),
                (6, 6, "wal-delta-v1".to_string()),
                (7, 7, "wal-delta-v1".to_string()),
            ]
        );
        let report = rig.check("main").await;
        assert_result(&report, RestoreResult::Ok);
        // The highest cumulative segment 2..=5, then 6 and 7; the deltas
        // before it are history.
        assert_eq!(
            (
                report.segments_required,
                report.segments_verified,
                report.segments_unverified
            ),
            (3, 3, 0)
        );
        assert!(rig.scratch_is_empty());
    }

    #[test]
    fn the_wal_only_grows_between_checkpoints_and_every_mark_is_a_commit_boundary() {
        let mut live = Live::new(4096);
        live.write(3);
        let checkpoint = live.checkpoint();
        let dir = tempfile::tempdir().unwrap();
        let probe = dir.path().join("probe");
        let mut stored: Vec<u8> = Vec::new();
        let mut marks = Vec::new();
        for round in 0..9 {
            // The node's actor reopens its database from Postgres's artifact:
            // the next WAL must continue the stored one, not restart it.
            if round == 3 || round == 6 {
                live.hydrate(&checkpoint, &stored);
            }
            live.write(1 + round % 3);
            let wal = live.wal();
            assert!(
                wal.starts_with(&stored),
                "round {round}: the WAL must extend what was stored"
            );
            assert!(wal.len() > stored.len(), "round {round}: it grew");
            marks.push(wal.len());
            stored = wal;
        }
        // Each mark is the end of a whole commit: the stored WAL cut there is
        // a WAL SQLite would replay in full.
        for end in marks {
            std::fs::write(&probe, &stored[..end]).unwrap();
            assert!(check_wal(&probe, 4096).is_ok(), "mark {end}");
        }
        // A checkpoint (TRUNCATE) starts a new generation: the old marks no
        // longer describe the WAL, and `save` dropped them.
        live.checkpoint();
        live.write(1);
        assert!(!live.wal().starts_with(&stored));
    }

    #[test]
    fn a_wal_of_another_format_version_has_no_committed_length_without_a_version_check() {
        // The version is inside the header checksum, which seeds the frame
        // chain: a header that names another version (with a checksum that
        // matches it) verifies no frame, so `committed_wal_len` says 0, as
        // `check_wal`'s explicit version check says "refused".
        let mut live = Live::new(4096);
        live.write(3);
        let mut wal = live.wal();
        let dir = tempfile::tempdir().unwrap();
        let probe = dir.path().join("probe-wal");
        std::fs::write(&probe, &wal).unwrap();
        assert_eq!(committed_wal_len(&probe).unwrap(), wal.len() as u64);

        wal[4..8].copy_from_slice(&(WAL_VERSION + 1).to_be_bytes());
        let big_endian = be32(&wal, 0) == WAL_MAGIC_BE;
        let (s1, s2) = wal_checksum(big_endian, &wal[..24], (0, 0));
        wal[24..28].copy_from_slice(&s1.to_be_bytes());
        wal[28..32].copy_from_slice(&s2.to_be_bytes());
        std::fs::write(&probe, &wal).unwrap();
        assert_eq!(committed_wal_len(&probe).unwrap(), 0);
        assert!(check_wal(&probe, 4096).is_err());
    }
}
