//! Request context travels with each actor message, not with the actor's idle
//! loop. Query metrics measure explicit native SQL calls (one attempt per
//! prepare/query lifecycle or execute/execute_batch call), including failures
//! and request-originated maintenance. Queueing, response serialization,
//! filesystem I/O, native backup and implicit connection-close work are not
//! SQL query time.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use dashmap::DashMap;
use rusqlite::hooks::{AuthContext, Authorization};
use tokio::sync::{mpsc, oneshot};

use crate::request_telemetry::{self, QueryTimer, RequestContext};

use super::{
    authority::{record_ddl_without_schema, SqlAuthority},
    authorizer::{PragmaTracker, StatementScope},
    caveats::SqlCaveats,
    durability::{cache_used_bytes, unspilled_wal_bound, DurabilityPolicy, ReservationRefused},
    parser,
    storage::{self, StorageMode},
    types::*,
};

const MAX_RESPONSE_SIZE: usize = 10 * 1024 * 1024; // 10MB
const MAX_BOUNDED_QUERY_ROWS: usize = 1_000;
const MAX_BOUNDED_QUERY_BYTES: usize = 4 * 1024 * 1024;
const IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300); // 5 min

enum DbMessage {
    Publication {
        command: serde_json::Value,
        response_tx: oneshot::Sender<Result<SqlExecutionResult, SqlError>>,
    },
    Execute {
        request: SqlRequest,
        caveats: Option<SqlCaveats>,
        authority: SqlAuthority,
        growth: GrowthPolicy,
        response_tx: oneshot::Sender<Result<SqlExecutionResult, SqlError>>,
    },
    Export {
        response_tx: oneshot::Sender<Result<Vec<u8>, SqlError>>,
    },
    Checkpoint {
        response_tx: oneshot::Sender<Result<Vec<u8>, SqlError>>,
    },
    Wal {
        response_tx: oneshot::Sender<Result<Option<Vec<u8>>, SqlError>>,
    },
    Shutdown {
        response_tx: oneshot::Sender<()>,
    },
}

/// Whether a write may grow the database file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrowthPolicy {
    Allow,
    /// The owner's storage budget has this many bytes left: the write may grow
    /// the database by at most that. SQLite enforces it (`max_page_count`), so
    /// a write that would pass it is rolled back before COMMIT with
    /// [`SqlError::StorageWouldGrow`] instead of overshooting by one write.
    Budget(u64),
    /// The space is full: run the request, but undo it and fail with
    /// [`SqlError::StorageWouldGrow`] if the database grew. No-op DDL,
    /// `DELETE` and `DROP` free pages instead of adding them, so they pass.
    Forbid,
}

/// Distinguishes one actor from its replacement for the same (space, db); see
/// the deregistration at the end of [`spawn_actor`].
static NEXT_ACTOR_ID: AtomicU64 = AtomicU64::new(0);

#[derive(Clone)]
pub struct DatabaseHandle {
    id: u64,
    tx: mpsc::Sender<(Option<Arc<RequestContext>>, DbMessage)>,
}

impl DatabaseHandle {
    /// Close the connection before acknowledging that its local files can be removed.
    pub async fn shutdown(&self) -> Result<(), SqlError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.tx
            .send((
                request_telemetry::current(),
                DbMessage::Shutdown { response_tx },
            ))
            .await
            .map_err(|_| SqlError::Internal("Database actor not available".into()))?;
        response_rx
            .await
            .map_err(|_| SqlError::Internal("Database actor dropped shutdown response".into()))
    }

    pub(crate) async fn publication(
        &self,
        command: serde_json::Value,
    ) -> Result<SqlExecutionResult, SqlError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.tx
            .send((
                request_telemetry::current(),
                DbMessage::Publication {
                    command,
                    response_tx,
                },
            ))
            .await
            .map_err(|_| SqlError::Internal("Database actor not available".into()))?;
        response_rx
            .await
            .map_err(|_| SqlError::Internal("Database actor dropped response".into()))?
    }
    pub async fn execute(
        &self,
        request: SqlRequest,
        caveats: Option<SqlCaveats>,
        ability: String,
        growth: GrowthPolicy,
    ) -> Result<SqlExecutionResult, SqlError> {
        self.execute_authorized(request, caveats, SqlAuthority::from(ability), growth)
            .await
    }

    /// As [`Self::execute`], judging each statement against every SQL ability
    /// the invocation holds (TC-1581).
    pub async fn execute_authorized(
        &self,
        request: SqlRequest,
        caveats: Option<SqlCaveats>,
        authority: SqlAuthority,
        growth: GrowthPolicy,
    ) -> Result<SqlExecutionResult, SqlError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.tx
            .send((
                request_telemetry::current(),
                DbMessage::Execute {
                    request,
                    caveats,
                    authority,
                    growth,
                    response_tx,
                },
            ))
            .await
            .map_err(|_| SqlError::Internal("Database actor not available".to_string()))?;
        response_rx
            .await
            .map_err(|_| SqlError::Internal("Database actor dropped response".to_string()))?
    }

    pub async fn export(&self) -> Result<Vec<u8>, SqlError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.tx
            .send((
                request_telemetry::current(),
                DbMessage::Export { response_tx },
            ))
            .await
            .map_err(|_| SqlError::Internal("Database actor not available".to_string()))?;
        response_rx
            .await
            .map_err(|_| SqlError::Internal("Database actor dropped response".to_string()))?
    }

    pub async fn checkpoint(&self) -> Result<Vec<u8>, SqlError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.tx
            .send((
                request_telemetry::current(),
                DbMessage::Checkpoint { response_tx },
            ))
            .await
            .map_err(|_| SqlError::Internal("Database actor not available".to_string()))?;
        response_rx
            .await
            .map_err(|_| SqlError::Internal("Database actor dropped response".to_string()))?
    }

    pub async fn wal(&self) -> Result<Option<Vec<u8>>, SqlError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.tx
            .send((request_telemetry::current(), DbMessage::Wal { response_tx }))
            .await
            .map_err(|_| SqlError::Internal("Database actor not available".to_string()))?;
        response_rx
            .await
            .map_err(|_| SqlError::Internal("Database actor dropped response".to_string()))?
    }
}

pub fn spawn_actor(
    space_id: String,
    db_name: String,
    base_path: String,
    memory_threshold: u64,
    databases: Arc<DashMap<(String, String), DatabaseHandle>>,
) -> DatabaseHandle {
    spawn_actor_with_policy(
        space_id,
        db_name,
        base_path,
        memory_threshold,
        databases,
        DurabilityPolicy::default(),
    )
}

/// [`spawn_actor`] with the node's durability policy (TC-1491): the
/// `synchronous` level, the size cap and the disk headroom.
pub fn spawn_actor_with_policy(
    space_id: String,
    db_name: String,
    base_path: String,
    memory_threshold: u64,
    databases: Arc<DashMap<(String, String), DatabaseHandle>>,
    policy: DurabilityPolicy,
) -> DatabaseHandle {
    let (tx, mut rx) = mpsc::channel::<(Option<Arc<RequestContext>>, DbMessage)>(32);
    let id = NEXT_ACTOR_ID.fetch_add(1, Ordering::Relaxed);
    let initial_context = request_telemetry::current();

    tokio::task::spawn_blocking(move || {
        let rt = tokio::runtime::Handle::current();
        let file_path = PathBuf::from(&base_path)
            .join(&space_id)
            .join(format!("{}.db", db_name));

        // Check if file already exists -- if so, open from file
        let mut mode = if file_path.exists() {
            StorageMode::File(file_path.clone())
        } else {
            StorageMode::InMemory
        };
        let mut conn = {
            let _context = request_telemetry::enter(initial_context);
            let Ok(connection) = storage::open_connection(&mode, policy.synchronous) else {
                tracing::error!("Failed to open database");
                databases.remove_if(&(space_id, db_name), |_, handle| handle.id == id);
                return;
            };
            connection
        };

        let shutdown_response = loop {
            // Block on receiving with timeout
            let (context, msg) =
                match rt.block_on(async { tokio::time::timeout(IDLE_TIMEOUT, rx.recv()).await }) {
                    Ok(Some(msg)) => msg,
                    Ok(None) => break None, // Channel closed
                    Err(_) => break None,   // Idle timeout
                };
            let _context = request_telemetry::enter(context);

            match msg {
                DbMessage::Shutdown { response_tx } => break Some(response_tx),
                DbMessage::Publication {
                    command,
                    response_tx,
                } => {
                    conn.authorizer(None::<fn(AuthContext<'_>) -> Authorization>);
                    let result =
                        super::publication::execute(&conn, &space_id, &command).map(|receipt| {
                            SqlExecutionResult {
                                response: SqlResponse::Query(QueryResponse {
                                    columns: vec!["receipt".into()],
                                    rows: vec![vec![SqlValue::Text(receipt.to_string())]],
                                    row_count: 1,
                                }),
                                write_targets: vec![],
                            }
                        });
                    let _ = response_tx.send(result);
                }
                DbMessage::Execute {
                    request,
                    caveats,
                    authority,
                    growth,
                    response_tx,
                } => {
                    let pragmas = PragmaTracker::default();
                    let key = format!("{space_id}/{db_name}");
                    let ctx = WriteContext {
                        policy: &policy,
                        key: &key,
                        dir: existing_ancestor(&file_path),
                        file_backed: matches!(mode, StorageMode::File(_)),
                        remaining: match growth {
                            GrowthPolicy::Budget(remaining) => Some(remaining),
                            _ => None,
                        },
                    };
                    let result = match growth {
                        GrowthPolicy::Allow | GrowthPolicy::Budget(_) => handle_message_ctx(
                            &conn, &request, &caveats, &authority, &pragmas, &ctx,
                        ),
                        GrowthPolicy::Forbid => handle_message_without_growth_ctx(
                            &conn, &request, &caveats, &authority, &pragmas, &ctx,
                        ),
                    };
                    conn.authorizer(None::<fn(AuthContext<'_>) -> Authorization>);
                    inject_open_transaction(&conn, &space_id, &db_name);

                    // A request ends its transaction, by commit or rollback.
                    // One still open here (a rollback that itself failed)
                    // would swallow the next request's writes, so serve no
                    // further request on this connection.
                    //
                    // TC-1586: the connection is shared by every request on
                    // this database. After any request in which the
                    // authorizer allowed a PRAGMA outside the plain schema
                    // reports, reset it; if that fails, serve no further
                    // request on this connection either (the next one
                    // rebuilds it).
                    let retire = if !conn.is_autocommit() {
                        Some("SQL connection transaction could not be ended")
                    } else if pragmas.load(Ordering::Relaxed)
                        && connection_reset_failed(&conn, &mode, &space_id, &db_name)
                    {
                        Some("SQL connection state could not be reset")
                    } else {
                        None
                    };
                    if let Some(reason) = retire {
                        tracing::error!("{reason}; retiring the database actor");
                        // Deregister first, so the request that follows the
                        // error builds a new actor instead of finding this one.
                        databases.remove_if(&(space_id.clone(), db_name.clone()), |_, handle| {
                            handle.id == id
                        });
                        let _ = response_tx.send(Err(SqlError::Internal(reason.into())));
                        break None;
                    }

                    // Post-write promotion check
                    if result.is_ok() && matches!(mode, StorageMode::InMemory) {
                        if let Ok(size) = storage::database_size(&conn) {
                            if size > memory_threshold {
                                // The copy needs the whole database on disk,
                                // next to what in-flight writes still need.
                                let room = if policy.min_free_bytes == 0 {
                                    Ok(())
                                } else {
                                    policy.budget.reserve(
                                        &key,
                                        size,
                                        policy.free_space.as_ref(),
                                        existing_ancestor(&file_path),
                                        policy.min_free_bytes,
                                    )
                                };
                                if room.is_err() {
                                    tracing::warn!(
                                        "Not enough free disk to promote a database; keeping it in memory"
                                    );
                                } else {
                                    let promoted = storage::promote_to_file(
                                        &conn,
                                        &file_path,
                                        policy.synchronous,
                                    );
                                    // The copy is on disk now.
                                    policy.budget.release(&key);
                                    match promoted {
                                        Ok(new_conn) => {
                                            conn = new_conn;
                                            mode = StorageMode::File(file_path.clone());
                                            tracing::info!("Promoted database to file storage");
                                        }
                                        Err(_) => {
                                            tracing::error!("Failed to promote database to file");
                                        }
                                    }
                                }
                            }
                        }
                    }

                    seam(&policy.seams.before_response);
                    let _ = response_tx.send(result);
                }
                DbMessage::Export { response_tx } => {
                    let result = handle_export(&conn, &mode, &file_path);
                    let _ = response_tx.send(result);
                }
                DbMessage::Checkpoint { response_tx } => {
                    let result = handle_checkpoint(&conn, &mode, &file_path);
                    let _ = response_tx.send(result);
                }
                DbMessage::Wal { response_tx } => {
                    let result = handle_wal(&mode, &file_path);
                    let _ = response_tx.send(result);
                }
            }
        };

        // SQLite can checkpoint its WAL on close. Finish that before removing
        // the registry entry or allowing a service to replace the local files.
        drop(conn);

        // Deregister only OUR OWN entry. A replacement actor may already have
        // been hydrated and registered for this key (the dead-actor respawn in
        // `SqlService::execute` does exactly that), and evicting it would send
        // the next request through hydration while it is live — deleting and
        // rewriting the files it holds open by path.
        databases.remove_if(&(space_id.clone(), db_name.clone()), |_, handle| {
            handle.id == id
        });
        tracing::debug!("Database actor shutting down");
        if let Some(response_tx) = shutdown_response {
            let _ = response_tx.send(());
        }
    });

    DatabaseHandle { id, tx }
}

/// The nearest existing ancestor of `path`: where `statvfs` can be asked how
/// much room the filesystem has before the file or its directory exists.
fn existing_ancestor(path: &Path) -> &Path {
    path.ancestors()
        .find(|ancestor| !ancestor.as_os_str().is_empty() && ancestor.exists())
        .unwrap_or_else(|| Path::new("."))
}

fn handle_wal(mode: &StorageMode, file_path: &Path) -> Result<Option<Vec<u8>>, SqlError> {
    if !matches!(mode, StorageMode::File(_)) {
        return Ok(None);
    }
    match std::fs::read(format!("{}-wal", file_path.display())) {
        Ok(wal) if !wal.is_empty() => Ok(Some(wal)),
        Ok(_) => Ok(None),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(SqlError::Internal(error.to_string())),
    }
}

fn handle_export(
    conn: &rusqlite::Connection,
    _mode: &StorageMode,
    _file_path: &PathBuf,
) -> Result<Vec<u8>, SqlError> {
    // Serialize through SQLite's backup API for both in-memory and WAL-backed
    // file databases so the exported artifact contains a complete checkpoint.
    let temp_dir = tempfile::tempdir().map_err(|e| SqlError::Internal(e.to_string()))?;
    let temp_path = temp_dir.path().join("export.db");

    let mut dest =
        rusqlite::Connection::open(&temp_path).map_err(|e| SqlError::Internal(e.to_string()))?;

    {
        let backup = rusqlite::backup::Backup::new(conn, &mut dest)
            .map_err(|e| SqlError::Internal(e.to_string()))?;
        // Copy all pages in one step with no pause (rusqlite rejects the
        // sqlite "-1 = all pages" sentinel, so use i32::MAX). The actor owns
        // `conn` exclusively and every SQL write blocks on this export, so
        // pacing (5 pages / 250ms) caps write throughput at ~80KB/s of
        // database size — a 45MB database makes every write take ~9 minutes
        // (tinycloud-node#112).
        backup
            .run_to_completion(i32::MAX, std::time::Duration::ZERO, None)
            .map_err(|e| SqlError::Internal(e.to_string()))?;
    }

    drop(dest);

    std::fs::read(&temp_path).map_err(|e| SqlError::Internal(e.to_string()))
}

fn handle_checkpoint(
    conn: &rusqlite::Connection,
    mode: &StorageMode,
    file_path: &PathBuf,
) -> Result<Vec<u8>, SqlError> {
    match mode {
        StorageMode::File(_) => {
            let busy: i64 = {
                let _timer = QueryTimer::new();
                conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| row.get(0))
                    .map_err(|e| SqlError::Internal(e.to_string()))?
            };
            if busy != 0 {
                return Err(SqlError::Internal("Database checkpoint is busy".into()));
            }
            std::fs::read(file_path).map_err(|e| SqlError::Internal(e.to_string()))
        }
        StorageMode::InMemory => handle_export(conn, mode, file_path),
    }
}

const GUARD_BEGIN: &str = "SAVEPOINT tinycloud_storage_guard";
const GUARD_KEEP: &str = "RELEASE tinycloud_storage_guard";
const GUARD_UNDO: &str = "ROLLBACK TO tinycloud_storage_guard; RELEASE tinycloud_storage_guard";

/// Run `request` inside a savepoint and keep its effects only if the
/// database did not grow (`PRAGMA page_count` reflects uncommitted pages on
/// this connection). Every failed guarded request is rolled back, including
/// schema entries and batch statements that ran before a later rejection.
fn handle_message_without_growth_ctx(
    conn: &rusqlite::Connection,
    request: &SqlRequest,
    caveats: &Option<SqlCaveats>,
    authority: &SqlAuthority,
    pragmas: &PragmaTracker,
    ctx: &WriteContext<'_>,
) -> Result<SqlExecutionResult, SqlError> {
    let before = page_count(conn)?;
    {
        let _timer = QueryTimer::new();
        conn.execute_batch(GUARD_BEGIN)
            .map_err(|e| SqlError::Internal(e.to_string()))?;
    }
    let result = handle_message_ctx(conn, request, caveats, authority, pragmas, ctx);
    // An early error return can leave the request's authorizer installed.
    conn.authorizer(None::<fn(AuthContext<'_>) -> Authorization>);
    // ROLLBACK conflict handling can already have undone the transaction.
    if result.is_err() && conn.is_autocommit() {
        return result;
    }
    let grew = page_count(conn).map(|after| after > before);
    // The disk check before COMMIT, for a request that is about to be kept.
    let gate = match (&result, &grew) {
        (Ok(_), Ok(false)) => baseline(conn).and_then(|base| {
            precommit_gate(
                conn,
                ctx,
                &Baseline {
                    pages: u64::try_from(before).unwrap_or(0),
                    page_size: base.page_size,
                },
            )
        }),
        _ => Ok(()),
    };
    let end = match grew {
        Ok(false) if result.is_ok() && gate.is_ok() => GUARD_KEEP,
        // Undo earlier statements on any error, even without page growth.
        _ => GUARD_UNDO,
    };
    if end == GUARD_KEEP {
        seam(&ctx.policy.seams.before_commit);
    }
    let end_result = {
        let _timer = QueryTimer::new();
        conn.execute_batch(end)
    };
    if let Err(error) = end_result {
        // RELEASE is also the commit for the outermost savepoint. Deferred
        // constraints can fail here and leave both the mutation and savepoint
        // active; undo them before the next request or checkpoint runs.
        if !conn.is_autocommit() {
            let _timer = QueryTimer::new();
            conn.execute_batch(GUARD_UNDO)
                .map_err(|e| SqlError::Internal(e.to_string()))?;
        }
        ctx.policy.budget.release(ctx.key);
        return Err(commit_error(&error));
    }
    if let Err(error) = gate {
        ctx.policy.budget.release(ctx.key);
        return Err(error);
    }
    match grew? {
        false => {
            seam(&ctx.policy.seams.after_commit);
            // Growth is zero here; the WAL bytes are on disk.
            ctx.policy.budget.hold(ctx.key, 0);
            result
        }
        true => Err(SqlError::StorageWouldGrow),
    }
}

fn page_count(conn: &rusqlite::Connection) -> Result<i64, SqlError> {
    let _timer = QueryTimer::new();
    conn.query_row("PRAGMA page_count", [], |row| row.get(0))
        .map_err(|e| SqlError::Internal(e.to_string()))
}

/// The unit tests drive a bare connection: no disk, no budget.
#[cfg(test)]
fn handle_message(
    conn: &rusqlite::Connection,
    request: &SqlRequest,
    caveats: &Option<SqlCaveats>,
    ability: &str,
) -> Result<SqlExecutionResult, SqlError> {
    let policy = DurabilityPolicy::default();
    let ctx = WriteContext {
        policy: &policy,
        key: "test/test",
        dir: Path::new("."),
        file_backed: false,
        remaining: None,
    };
    handle_message_ctx(
        conn,
        request,
        caveats,
        &SqlAuthority::from(ability),
        &PragmaTracker::default(),
        &ctx,
    )
}

#[cfg(test)]
fn handle_message_without_growth(
    conn: &rusqlite::Connection,
    request: &SqlRequest,
    caveats: &Option<SqlCaveats>,
    ability: &str,
) -> Result<SqlExecutionResult, SqlError> {
    let policy = DurabilityPolicy::default();
    let ctx = WriteContext {
        policy: &policy,
        key: "test/test",
        dir: Path::new("."),
        file_backed: false,
        remaining: None,
    };
    handle_message_without_growth_ctx(
        conn,
        request,
        caveats,
        &SqlAuthority::from(ability),
        &PragmaTracker::default(),
        &ctx,
    )
}

const REQUEST_BEGIN: &str = "SAVEPOINT tinycloud_request";
const REQUEST_KEEP: &str = "RELEASE tinycloud_request";
/// SQLite's default `max_page_count`.
const UNLIMITED_PAGES: u64 = 4_294_967_294;
/// Opcodes between the disk checks of a running statement.
const PROGRESS_INTERVAL_OPS: std::os::raw::c_int = 10_000;

/// What a write request needs to be bounded before it commits (TC-1491).
struct WriteContext<'a> {
    policy: &'a DurabilityPolicy,
    /// `space/db`, the key of this database's reservation.
    key: &'a str,
    /// An existing directory on the filesystem holding the database.
    dir: &'a Path,
    /// True once the database is a file (and so has a WAL and uses the disk).
    file_backed: bool,
    /// Bytes the owner's storage budget still allows this database to grow
    /// by, or `None` for no budget.
    remaining: Option<u64>,
}

/// The state a request starts from.
struct Baseline {
    pages: u64,
    page_size: u64,
}

fn pragma_u64(conn: &rusqlite::Connection, pragma: &str) -> Result<u64, SqlError> {
    conn.query_row(&format!("PRAGMA {pragma}"), [], |row| row.get::<_, i64>(0))
        .map(|value| u64::try_from(value).unwrap_or(0))
        .map_err(|e| SqlError::Internal(e.to_string()))
}

fn baseline(conn: &rusqlite::Connection) -> Result<Baseline, SqlError> {
    Ok(Baseline {
        pages: pragma_u64(conn, "page_count")?,
        page_size: pragma_u64(conn, "page_size")?,
    })
}

fn set_max_pages(conn: &rusqlite::Connection, pages: u64) -> Result<(), SqlError> {
    conn.query_row(&format!("PRAGMA max_page_count = {pages}"), [], |_| Ok(()))
        .map_err(|e| SqlError::Internal(e.to_string()))
}

/// The page limit SQLite enforces for this request, and whether the owner's
/// budget (rather than the per-database cap) is the tighter of the two. SQLite
/// never sets it below the current size, so a database already over the cap
/// can still run writes that do not grow it.
fn page_limit(ctx: &WriteContext<'_>, baseline: &Baseline) -> (u64, bool) {
    let page_size = baseline.page_size.max(1);
    let cap = match ctx.policy.max_database_bytes {
        0 => UNLIMITED_PAGES,
        bytes => (bytes / page_size).max(1),
    };
    match ctx.remaining {
        Some(remaining) => {
            let budget = baseline.pages.saturating_add(remaining / page_size);
            (budget.min(cap), budget < cap)
        }
        None => (cap, false),
    }
}

fn is_full_error(error: &SqlError) -> bool {
    matches!(error, SqlError::Sqlite(m) | SqlError::SchemaError(m) if m.contains("database or disk is full"))
}

/// What a `SQLITE_FULL` means: the size limit SQLite enforces (`max_page_count`)
/// or the disk itself (ENOSPC). The page count cannot tell them apart, since
/// SQLite has already undone the failed statement by the time it is read; the
/// free-space reading can: a disk below its floor is the disk.
fn classify_full(ctx: &WriteContext<'_>, budget_binding: bool) -> SqlError {
    if ctx.policy.max_database_bytes == 0 && !budget_binding {
        // No limit of ours can have fired, so the disk really is full.
        return SqlError::DiskHeadroom;
    }
    let disk_exhausted = ctx.file_backed
        && ctx.policy.min_free_bytes > 0
        && ctx
            .policy
            .free_space
            .free_bytes(ctx.dir)
            .map_or(true, |free| {
                free < ctx
                    .policy
                    .budget
                    .reserved_excluding(ctx.key)
                    .saturating_add(ctx.policy.min_free_bytes)
            });
    match (disk_exhausted, budget_binding) {
        (true, _) => SqlError::DiskHeadroom,
        (false, true) => SqlError::StorageWouldGrow,
        (false, false) => SqlError::DatabaseSizeLimit,
    }
}

/// The last check before COMMIT. Rolling back on an error is the caller's.
///
/// The disk bound: the pages COMMIT still writes to the WAL are the dirty
/// pages that have not spilled yet, and those are all in the connection's
/// page cache, so `cache_used` bounds them whatever the SQL payload was
/// (index, trigger and foreign-key writes, freelist and overflow pages are
/// all just pages). A later checkpoint grows the main file by the page growth
/// of the request. WAL bytes already spilled are on disk and already out of
/// the free space the check reads.
fn precommit_gate(
    conn: &rusqlite::Connection,
    ctx: &WriteContext<'_>,
    baseline: &Baseline,
) -> Result<(), SqlError> {
    let now = pragma_u64(conn, "page_count")?;
    let growth_pages = now.saturating_sub(baseline.pages);
    let growth_bytes = growth_pages.saturating_mul(baseline.page_size);
    if ctx
        .remaining
        .is_some_and(|remaining| growth_bytes > remaining)
    {
        return Err(SqlError::StorageWouldGrow);
    }
    if growth_pages > 0
        && ctx.policy.max_database_bytes > 0
        && now.saturating_mul(baseline.page_size) > ctx.policy.max_database_bytes
    {
        return Err(SqlError::DatabaseSizeLimit);
    }
    if !ctx.file_backed || ctx.policy.min_free_bytes == 0 {
        return Ok(());
    }
    let wal_bound = unspilled_wal_bound(cache_used_bytes(conn), baseline.page_size);
    match ctx.policy.budget.reserve(
        ctx.key,
        wal_bound.saturating_add(growth_bytes),
        ctx.policy.free_space.as_ref(),
        ctx.dir,
        ctx.policy.min_free_bytes,
    ) {
        Ok(()) => Ok(()),
        Err(ReservationRefused::Headroom) => Err(SqlError::DiskHeadroom),
        Err(ReservationRefused::Unknown) => Err(SqlError::Internal(
            "could not read the free disk space".into(),
        )),
    }
}

fn seam(hook: &Option<Arc<dyn Fn() + Send + Sync>>) {
    if let Some(hook) = hook {
        hook();
    }
}

/// Whether `request` runs in a transaction of its own (TC-1491).
///
/// Every request that can write does, so the checks before COMMIT have a
/// transaction to roll back, and the request is all-or-nothing whatever its
/// conflict clauses say: a statement that stops with `OR FAIL` or
/// `ON CONFLICT FAIL` keeps the rows it changed first when it runs on its
/// own, and a request with several statements keeps its earlier ones.
/// A request that carries a `PRAGMA` (admin only) is wrapped like any other,
/// and so is limited, gated and reserved like any write. Every pragma the
/// authorizer admits is transactional (`user_version` and `application_id`
/// are undone by the rollback; the rest are reports), and the authorizer's
/// allow-list is what keeps connection-level settings out of the
/// transaction. The actor's TC-1586 connection reset runs after the
/// transaction has ended. Not wrapped: a query that only reads.
///
/// Whether a query writes is `parser::classify_sql` (TC-1585), which sees
/// writes nested in a query tree: a `WITH … INSERT` is wrapped, gated and
/// reserved like any other write. It does not depend on the caller's
/// abilities (a read-tier grant is only a shortcut: its writes are refused
/// anyway), and a statement that does not parse is left to
/// `handle_request_authorized` to report. This is the one place that decides
/// it; `Execute`, `Batch` and `ExecuteStatement` are wrapped whatever they
/// contain, a read in a batch included.
fn needs_transaction(
    request: &SqlRequest,
    caveats: &Option<SqlCaveats>,
    authority: &SqlAuthority,
) -> bool {
    match request {
        SqlRequest::Query { sql, .. } => {
            !authority.is_read_tier_only()
                && (parser::is_pragma_sql(sql)
                    || parser::classify_sql(sql)
                        .map(|class| !class.is_read_only)
                        .unwrap_or(false))
        }
        SqlRequest::Execute { .. } | SqlRequest::Batch { .. } => true,
        SqlRequest::ExecuteStatement { name, .. } => caveats
            .as_ref()
            .is_some_and(|c| c.find_statement(name).is_some()),
        SqlRequest::Export => false,
    }
}

/// `DdlPolicy::Log` bookkeeping for one request: count every statement that
/// only `write` let through, and warn once. The message is constant and the
/// counter is labelled by statement kind alone, so neither carries SQL text,
/// space ids, DIDs or table names.
#[derive(Default)]
struct DdlLog {
    warned: bool,
}

impl DdlLog {
    fn note(&mut self, parsed: &parser::ParsedQuery) {
        let Some(kind) = parsed.ddl_without_schema else {
            return;
        };
        record_ddl_without_schema(kind);
        if !self.warned {
            self.warned = true;
            tracing::warn!("sql ddl allowed without schema ability (ddl_requires_schema = log)");
        }
    }
}

/// Run `request` as one transaction when it needs one: every statement is
/// kept or none is.
///
/// The transaction is a `SAVEPOINT`, which opens one when none is active;
/// users cannot issue transaction control themselves, the authorizer denies
/// it. A failure at any statement, or at the commit (a deferred constraint),
/// is a `ROLLBACK`: the local file is unchanged and matches the durable copy,
/// which is only written after a fully successful request. See
/// [`needs_transaction`] for what is wrapped. The wrap sits inside the request
/// and outside the actor's TC-1586 connection reset, which runs after the
/// transaction has ended.
///
/// When a transaction is already open, [`handle_message_without_growth_ctx`]'s
/// guard has it and already undoes the whole request on any error (reporting
/// growth ahead of the SQL error), so this adds nothing there.
///
/// Order, for a write: limits (SQLite's `max_page_count`: the per-database
/// cap and the owner's remaining budget), the statements, the pre-commit gate
/// ([`precommit_gate`]), COMMIT. Any failure before COMMIT is a ROLLBACK.
///
/// If the transaction is still open after the final `ROLLBACK`, the actor
/// retires the connection instead of serving another request on it.
fn handle_message_ctx(
    conn: &rusqlite::Connection,
    request: &SqlRequest,
    caveats: &Option<SqlCaveats>,
    authority: &SqlAuthority,
    pragmas: &PragmaTracker,
    ctx: &WriteContext<'_>,
) -> Result<SqlExecutionResult, SqlError> {
    if !conn.is_autocommit() || !needs_transaction(request, caveats, authority) {
        return handle_request_authorized(conn, request, caveats, authority, pragmas);
    }
    let base = baseline(conn)?;
    set_max_pages(conn, page_limit(ctx, &base).0)?;
    let tripped = Arc::new(AtomicBool::new(false));
    let disk_checked = ctx.file_backed && ctx.policy.min_free_bytes > 0;
    if disk_checked {
        let (budget, free_space) = (ctx.policy.budget.clone(), ctx.policy.free_space.clone());
        let (key, dir) = (ctx.key.to_string(), ctx.dir.to_path_buf());
        let (min_free, tripped) = (ctx.policy.min_free_bytes, tripped.clone());
        // Stops a statement early once the disk is already too full; the
        // authoritative check is `precommit_gate`.
        conn.progress_handler(
            PROGRESS_INTERVAL_OPS,
            Some(move || {
                let free = free_space.free_bytes(&dir).unwrap_or(0);
                let others = budget.reserved_excluding(&key);
                let exhausted = free < others.saturating_add(min_free);
                if exhausted {
                    tripped.store(true, Ordering::Relaxed);
                }
                exhausted
            }),
        );
    }
    let outcome = run_transaction(conn, request, caveats, authority, pragmas, ctx, &base);
    if disk_checked {
        conn.progress_handler(0, None::<fn() -> bool>);
    }
    let outcome = outcome.map_err(|error| {
        if tripped.load(Ordering::Relaxed) {
            SqlError::DiskHeadroom
        } else {
            error
        }
    });
    // A failed request keeps nothing, so nothing of it stays reserved.
    if outcome.is_err() {
        ctx.policy.budget.release(ctx.key);
    }
    let _ = set_max_pages(conn, UNLIMITED_PAGES);
    outcome.map(|(result, growth_bytes)| {
        // Committed: its WAL bytes are on disk now. What stays held, until the
        // request's outcome is known (the Postgres save), is the checkpoint
        // growth.
        ctx.policy
            .budget
            .hold(ctx.key, if disk_checked { growth_bytes } else { 0 });
        result
    })
}

/// The transaction itself; on `Err` it has been rolled back.
fn run_transaction(
    conn: &rusqlite::Connection,
    request: &SqlRequest,
    caveats: &Option<SqlCaveats>,
    authority: &SqlAuthority,
    pragmas: &PragmaTracker,
    ctx: &WriteContext<'_>,
    base: &Baseline,
) -> Result<(SqlExecutionResult, u64), SqlError> {
    {
        let _timer = QueryTimer::new();
        conn.execute_batch(REQUEST_BEGIN)
            .map_err(|e| SqlError::Internal(e.to_string()))?;
    }
    let result = handle_request_authorized(conn, request, caveats, authority, pragmas);
    // An early error return can leave the request's authorizer installed.
    conn.authorizer(None::<fn(AuthContext<'_>) -> Authorization>);
    // The error is surfaced before the rollback so the caller can still read
    // the uncommitted page count to tell a size limit from a full disk.
    let result = result.and_then(|ok| precommit_gate(conn, ctx, base).map(|()| ok));
    let result = match result {
        Ok(ok) => ok,
        Err(error) => {
            // SQLite can already have undone the transaction (ROLLBACK
            // conflict handling); there is then nothing left to undo.
            let full = is_full_error(&error);
            let classified = full.then(|| classify_full(ctx, page_limit(ctx, base).1));
            if !conn.is_autocommit() {
                // A failure rolls the whole transaction back. `ROLLBACK TO` +
                // `RELEASE` would instead commit an empty write transaction
                // and rewrite the header.
                let _timer = QueryTimer::new();
                let _ = conn.execute_batch("ROLLBACK");
            }
            return Err(classified.unwrap_or(error));
        }
    };
    let growth_bytes = pragma_u64(conn, "page_count")
        .unwrap_or(base.pages)
        .saturating_sub(base.pages)
        .saturating_mul(base.page_size);
    seam(&ctx.policy.seams.before_commit);
    // RELEASE of the outermost savepoint is the COMMIT.
    let commit = {
        let _timer = QueryTimer::new();
        conn.execute_batch(REQUEST_KEEP)
    };
    if let Err(error) = commit {
        if !conn.is_autocommit() {
            let _timer = QueryTimer::new();
            let _ = conn.execute_batch("ROLLBACK");
        }
        return Err(commit_error(&error));
    }
    seam(&ctx.policy.seams.after_commit);
    Ok((result, growth_bytes))
}

/// COMMIT failed. A deferred constraint is the request's own fault; anything
/// else is the disk.
///
/// If COMMIT's fsync fails after the WAL frames were written, SQLite reports
/// the error and rolls the transaction back in memory, but the frames are
/// already in the file and, if their commit mark reached it, the commit can
/// reappear when the database is next opened — although we reported the
/// request as rejected. That is harmless while Postgres is master: the caller
/// discards the local state and re-hydrates from Postgres, which never saw the
/// write. Under store-master (1b+) it is an outcome-unknown case: the local
/// WAL must be kept and the request answered `outcome_unknown`, not rejected.
fn commit_error(error: &rusqlite::Error) -> SqlError {
    match error.sqlite_error_code() {
        Some(rusqlite::ErrorCode::ConstraintViolation) => SqlError::Sqlite(error.to_string()),
        Some(rusqlite::ErrorCode::DiskFull) => SqlError::DiskHeadroom,
        code => {
            tracing::error!(?code, "Local SQL commit failed");
            SqlError::CommitFailed
        }
    }
}

fn handle_request_authorized(
    conn: &rusqlite::Connection,
    request: &SqlRequest,
    caveats: &Option<SqlCaveats>,
    authority: &SqlAuthority,
    pragmas: &PragmaTracker,
) -> Result<SqlExecutionResult, SqlError> {
    let mut ddl_log = DdlLog::default();
    let authorizer = |parsed: &parser::ParsedQuery| {
        super::authorizer::create_authorizer_tracked(
            caveats.clone(),
            authority,
            StatementScope::of(parsed),
            pragmas.clone(),
        )
    };

    match request {
        SqlRequest::Query {
            sql,
            params,
            max_rows,
            max_bytes,
        } => {
            let parsed = parser::validate_sql_authorized(sql, caveats, authority)?;
            ddl_log.note(&parsed);

            conn.authorizer(Some(authorizer(&parsed)));

            let result = execute_query(conn, sql, params, *max_rows, *max_bytes);

            conn.authorizer(None::<fn(AuthContext<'_>) -> Authorization>);

            result.map(|response| SqlExecutionResult {
                response: SqlResponse::Query(response),
                write_targets: parsed.write_targets,
            })
        }
        SqlRequest::Execute {
            sql,
            params,
            schema,
        } => {
            let mut write_targets = Vec::new();
            // Schema init. Each entry is judged like any other statement: a
            // schema-changing entry needs a schema-conferring ability.
            if let Some(schema_stmts) = schema {
                for stmt_sql in schema_stmts {
                    let parsed = parser::validate_sql_authorized(stmt_sql, caveats, authority)?;
                    ddl_log.note(&parsed);
                    write_targets.extend(parsed.write_targets.iter().cloned());
                    conn.authorizer(Some(authorizer(&parsed)));
                    {
                        let _timer = QueryTimer::new();
                        conn.execute_batch(stmt_sql)
                            .map_err(|e| SqlError::SchemaError(e.to_string()))?;
                    }
                    conn.authorizer(None::<fn(AuthContext<'_>) -> Authorization>);
                }
            }

            let parsed = parser::validate_sql_authorized(sql, caveats, authority)?;
            ddl_log.note(&parsed);
            conn.authorizer(Some(authorizer(&parsed)));

            let result = execute_statement(conn, sql, params, is_insert_statement(&parsed));

            conn.authorizer(None::<fn(AuthContext<'_>) -> Authorization>);

            let response = result.map(SqlResponse::Execute)?;
            write_targets.extend(parsed.write_targets);
            Ok(SqlExecutionResult {
                response,
                write_targets,
            })
        }
        SqlRequest::Batch { statements } => {
            let mut write_targets = Vec::new();
            let mut insert_statements = Vec::with_capacity(statements.len());
            let mut scopes = Vec::with_capacity(statements.len());
            // Hooks are emitted only after this branch returns Ok to the caller.
            // If a later statement fails after some earlier statements applied,
            // MVP intentionally under-emits rather than guessing partial success.
            for stmt in statements {
                let parsed = parser::validate_sql_authorized(&stmt.sql, caveats, authority)?;
                ddl_log.note(&parsed);
                insert_statements.push(is_insert_statement(&parsed));
                scopes.push(StatementScope::of(&parsed));
                write_targets.extend(parsed.write_targets);
            }

            let mut results = Vec::new();
            for ((stmt, is_insert), scope) in statements.iter().zip(insert_statements).zip(scopes) {
                let auth = super::authorizer::create_authorizer_tracked(
                    caveats.clone(),
                    authority,
                    scope,
                    pragmas.clone(),
                );
                conn.authorizer(Some(auth));
                let result = execute_statement(conn, &stmt.sql, &stmt.params, is_insert);
                conn.authorizer(None::<fn(AuthContext<'_>) -> Authorization>);
                results.push(result?);
            }

            Ok(SqlExecutionResult {
                response: SqlResponse::Batch(BatchResponse { results }),
                write_targets,
            })
        }
        SqlRequest::ExecuteStatement { name, params } => {
            let caveats_ref = caveats
                .as_ref()
                .ok_or_else(|| SqlError::InvalidStatement("No caveats found".to_string()))?;
            let prepared = caveats_ref.find_statement(name).ok_or_else(|| {
                SqlError::InvalidStatement(format!("Statement '{}' not found", name))
            })?;

            // A named statement is judged as the SQL it holds: one that
            // resolves to DDL needs a schema-conferring ability on the
            // invocation, like the same SQL sent directly.
            let parsed = parser::validate_sql_authorized(&prepared.sql, caveats, authority)?;
            ddl_log.note(&parsed);

            conn.authorizer(Some(authorizer(&parsed)));

            let result = if is_query_statement(&parsed) {
                execute_query(conn, &prepared.sql, params, None, None).map(SqlResponse::Query)
            } else {
                execute_statement(conn, &prepared.sql, params, is_insert_statement(&parsed))
                    .map(SqlResponse::Execute)
            };

            conn.authorizer(None::<fn(AuthContext<'_>) -> Authorization>);

            result.map(|response| SqlExecutionResult {
                response,
                write_targets: parsed.write_targets,
            })
        }
        SqlRequest::Export => Err(SqlError::Internal(
            "Export should be handled by service".to_string(),
        )),
    }
}

fn sql_value_to_rusqlite(v: &SqlValue) -> rusqlite::types::Value {
    rusqlite::types::Value::from(v)
}

fn row_to_sql_value(row: &rusqlite::Row, idx: usize) -> Result<SqlValue, SqlError> {
    let value: rusqlite::types::Value =
        row.get(idx).map_err(|e| SqlError::Sqlite(e.to_string()))?;
    Ok(SqlValue::from(value))
}

fn is_query_statement(parsed: &parser::ParsedQuery) -> bool {
    // A `WITH … INSERT/UPDATE` is a Query to the parser but runs as a write.
    parsed.is_read_only
        && matches!(
            parsed.statements.as_slice(),
            [sqlparser::ast::Statement::Query(_)]
        )
}

/// Return the connection to the state `storage::open_connection` leaves it in
/// (TC-1586).
///
/// The actor's connection is shared by every request on a database, so
/// connection-level state must not outlive the request that changed it. The
/// authorizer allows an admin only a short list of PRAGMAs, none of which
/// change connection state; this reset is the backstop for anything that
/// list misses. It covers in-memory and file-backed connections alike.
fn reset_connection_state(conn: &rusqlite::Connection, mode: &StorageMode) -> Result<(), SqlError> {
    let _timer = QueryTimer::new();
    conn.execute_batch(
        "PRAGMA writable_schema = OFF;
         PRAGMA query_only = OFF;
         PRAGMA ignore_check_constraints = OFF;
         PRAGMA recursive_triggers = OFF;
         PRAGMA case_sensitive_like = OFF;
         PRAGMA defer_foreign_keys = OFF;
         PRAGMA reverse_unordered_selects = OFF;
         PRAGMA automatic_index = ON;
         PRAGMA read_uncommitted = OFF;
         PRAGMA cell_size_check = OFF;
         PRAGMA legacy_alter_table = OFF;
         PRAGMA locking_mode = NORMAL;
         PRAGMA temp_store = DEFAULT;
         PRAGMA foreign_keys = ON;",
    )
    .map_err(|e| SqlError::Internal(e.to_string()))?;
    let (journal_mode, wal) = match mode {
        StorageMode::File(_) => ("wal", true),
        StorageMode::InMemory => ("memory", false),
    };
    conn.pragma_update(None, "journal_mode", journal_mode)
        .map_err(|e| SqlError::Internal(e.to_string()))?;
    if wal {
        conn.pragma_update(None, "wal_autocheckpoint", 0)
            .map_err(|e| SqlError::Internal(e.to_string()))?;
    }
    Ok(())
}

/// Reset after a request that was allowed a PRAGMA. `true` when it failed, in
/// which case the actor must not serve another request on this connection.
fn connection_reset_failed(
    conn: &rusqlite::Connection,
    mode: &StorageMode,
    space_id: &str,
    db_name: &str,
) -> bool {
    injected_reset_failure(space_id, db_name) || reset_connection_state(conn, mode).is_err()
}

#[cfg(test)]
pub(crate) static RESET_FAILURES: std::sync::Mutex<Vec<(String, String)>> =
    std::sync::Mutex::new(Vec::new());

#[cfg(test)]
fn injected_reset_failure(space_id: &str, db_name: &str) -> bool {
    RESET_FAILURES
        .lock()
        .unwrap()
        .iter()
        .any(|(space, db)| space == space_id && db == db_name)
}

#[cfg(not(test))]
fn injected_reset_failure(_space_id: &str, _db_name: &str) -> bool {
    false
}

/// Test seam: databases whose connection is left inside a transaction after
/// their next request, as a failed final `ROLLBACK` would leave it.
#[cfg(test)]
pub(crate) static OPEN_TRANSACTIONS: std::sync::Mutex<Vec<(String, String)>> =
    std::sync::Mutex::new(Vec::new());

#[cfg(test)]
fn inject_open_transaction(conn: &rusqlite::Connection, space_id: &str, db_name: &str) {
    let injected = OPEN_TRANSACTIONS
        .lock()
        .unwrap()
        .iter()
        .any(|(space, db)| space == space_id && db == db_name);
    if injected {
        conn.execute_batch("BEGIN").unwrap();
    }
}

#[cfg(not(test))]
fn inject_open_transaction(_conn: &rusqlite::Connection, _space_id: &str, _db_name: &str) {}

fn is_insert_statement(parsed: &parser::ParsedQuery) -> bool {
    matches!(
        parsed.statements.as_slice(),
        [sqlparser::ast::Statement::Insert { .. }]
    )
}

fn execute_query(
    conn: &rusqlite::Connection,
    sql: &str,
    params: &[SqlValue],
    max_rows: Option<usize>,
    max_bytes: Option<usize>,
) -> Result<QueryResponse, SqlError> {
    validate_query_limits(max_rows, max_bytes)?;
    let mut timer = QueryTimer::new();
    let mut stmt = conn
        .prepare(sql)
        .map_err(|e| SqlError::Sqlite(e.to_string()))?;
    timer.pause();

    let columns: Vec<String> = stmt.column_names().into_iter().map(String::from).collect();

    let rusqlite_params: Vec<rusqlite::types::Value> =
        params.iter().map(sql_value_to_rusqlite).collect();
    let param_refs: Vec<&dyn rusqlite::types::ToSql> = rusqlite_params
        .iter()
        .map(|p| p as &dyn rusqlite::types::ToSql)
        .collect();

    let mut rows = Vec::new();
    let response_limit = max_bytes.unwrap_or(MAX_RESPONSE_SIZE);
    let mut serialized_size = serde_json::to_vec(&QueryResponse {
        columns: columns.clone(),
        rows: Vec::new(),
        row_count: 0,
    })
    .map_err(|e| SqlError::Internal(format!("Failed to serialize query response: {e}")))?
    .len();
    if serialized_size > response_limit {
        return Err(SqlError::ResponseTooLarge(serialized_size as u64));
    }

    timer.resume();
    let mut query_rows = stmt
        .query(param_refs.as_slice())
        .map_err(|e| SqlError::Sqlite(e.to_string()))?;
    timer.pause();

    loop {
        timer.resume();
        let next = query_rows.next();
        timer.pause();
        let Some(row) = next.map_err(|e| SqlError::Sqlite(e.to_string()))? else {
            break;
        };
        if max_rows.is_some_and(|limit| rows.len() >= limit) {
            return Err(SqlError::ResponseTooLarge(serialized_size as u64));
        }
        let mut values = Vec::new();
        for i in 0..columns.len() {
            let val = row_to_sql_value(row, i)?;
            values.push(val);
        }

        let row_size = serde_json::to_vec(&values)
            .map_err(|e| SqlError::Internal(format!("Failed to serialize query row: {e}")))?
            .len();
        let old_row_count_digits = rows.len().to_string().len();
        let new_row_count_digits = (rows.len() + 1).to_string().len();
        serialized_size +=
            row_size + usize::from(!rows.is_empty()) + new_row_count_digits - old_row_count_digits;
        if serialized_size > response_limit {
            return Err(SqlError::ResponseTooLarge(serialized_size as u64));
        }
        rows.push(values);
    }

    let row_count = rows.len();
    let response = QueryResponse {
        columns,
        rows,
        row_count,
    };
    let serialized_size = serde_json::to_vec(&response)
        .map_err(|e| SqlError::Internal(format!("Failed to serialize query response: {e}")))?
        .len();
    if serialized_size > response_limit {
        return Err(SqlError::ResponseTooLarge(serialized_size as u64));
    }

    Ok(response)
}

fn validate_query_limits(
    max_rows: Option<usize>,
    max_bytes: Option<usize>,
) -> Result<(), SqlError> {
    if max_rows.is_some_and(|value| value == 0 || value > MAX_BOUNDED_QUERY_ROWS) {
        return Err(SqlError::InvalidStatement(format!(
            "maxRows must be between 1 and {MAX_BOUNDED_QUERY_ROWS}"
        )));
    }
    if max_bytes.is_some_and(|value| value == 0 || value > MAX_BOUNDED_QUERY_BYTES) {
        return Err(SqlError::InvalidStatement(format!(
            "maxBytes must be between 1 and {MAX_BOUNDED_QUERY_BYTES}"
        )));
    }
    Ok(())
}

fn execute_statement(
    conn: &rusqlite::Connection,
    sql: &str,
    params: &[SqlValue],
    is_insert: bool,
) -> Result<ExecuteResponse, SqlError> {
    let rusqlite_params: Vec<rusqlite::types::Value> =
        params.iter().map(sql_value_to_rusqlite).collect();
    let param_refs: Vec<&dyn rusqlite::types::ToSql> = rusqlite_params
        .iter()
        .map(|p| p as &dyn rusqlite::types::ToSql)
        .collect();

    {
        let _timer = QueryTimer::new();
        conn.execute(sql, param_refs.as_slice())
            .map_err(|e| SqlError::Sqlite(e.to_string()))?;
    }

    Ok(ExecuteResponse {
        changes: conn.changes(),
        last_insert_row_id: is_insert.then(|| conn.last_insert_rowid()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sql::durability::Synchronous;

    #[tokio::test]
    async fn tc626_review_release_escape_cannot_survive_checkpoint() {
        for memory_threshold in [u64::MAX, 0] {
            let dir = tempfile::tempdir().unwrap();
            let actor = spawn_actor(
                "space".into(),
                "guard".into(),
                dir.path().to_str().unwrap().into(),
                memory_threshold,
                Arc::new(DashMap::new()),
            );
            actor
                .execute(
                    SqlRequest::Execute {
                        schema: None,
                        sql: "CREATE TABLE data (value TEXT)".into(),
                        params: vec![],
                    },
                    None,
                    "tinycloud.sql/admin".into(),
                    GrowthPolicy::Allow,
                )
                .await
                .unwrap();
            actor
                .execute(
                    SqlRequest::Execute {
                        schema: Some(vec![
                            "PRAGMA user_version = 1; RELEASE tinycloud_storage_guard".into(),
                        ]),
                        sql: "INSERT INTO data VALUES (hex(zeroblob(65536)))".into(),
                        params: vec![],
                    },
                    None,
                    "tinycloud.sql/admin".into(),
                    GrowthPolicy::Forbid,
                )
                .await
                .expect_err("the caller must not release the storage guard");

            let result = actor
                .execute(
                    SqlRequest::Query {
                        sql: "SELECT count(*) FROM data".into(),
                        params: vec![],
                        max_rows: None,
                        max_bytes: None,
                    },
                    None,
                    "tinycloud.sql/read".into(),
                    GrowthPolicy::Allow,
                )
                .await
                .unwrap();
            let SqlResponse::Query(response) = result.response else {
                panic!("expected query response");
            };
            assert_eq!(response.rows, vec![vec![SqlValue::Integer(0)]]);

            let checkpoint = actor.checkpoint().await.unwrap();
            let restored_path = dir.path().join("restored.db");
            std::fs::write(&restored_path, checkpoint).unwrap();
            let restored = rusqlite::Connection::open(restored_path).unwrap();
            let count: i64 = restored
                .query_row("SELECT count(*) FROM data", [], |row| row.get(0))
                .unwrap();
            let version: i64 = restored
                .query_row("PRAGMA user_version", [], |row| row.get(0))
                .unwrap();
            assert_eq!(
                count, 0,
                "a later checkpoint must not persist rejected data"
            );
            assert_eq!(version, 0, "the rejected schema entry must also be undone");
        }
    }

    #[test]
    fn tc626_review_transaction_controls_undo_earlier_schema_entries() {
        for control in [
            "RELEASE tinycloud_storage_guard",
            "RELEASE SAVEPOINT tinycloud_storage_guard",
            "ROLLBACK",
            "ROLLBACK TO tinycloud_storage_guard",
            "COMMIT",
            "END",
            "SAVEPOINT caller_savepoint",
            "BEGIN",
        ] {
            for prefix in ["", "PRAGMA user_version = 1; /* boundary; */ "] {
                let conn =
                    storage::open_connection(&StorageMode::InMemory, Synchronous::Full).unwrap();
                conn.execute_batch(
                    "CREATE TABLE data (value TEXT); INSERT INTO data VALUES ('before')",
                )
                .unwrap();
                let sql = format!("{prefix}{control}");
                let result = handle_message_without_growth(
                    &conn,
                    &SqlRequest::Execute {
                        schema: Some(vec![
                            "UPDATE data SET value = 'rejected'".into(),
                            sql.clone(),
                        ]),
                        sql: "UPDATE data SET value = 'escaped'".into(),
                        params: vec![],
                    },
                    &None,
                    "tinycloud.sql/admin",
                );
                assert!(result.is_err(), "transaction control was accepted: {sql}");
                let value: String = conn
                    .query_row("SELECT value FROM data", [], |row| row.get(0))
                    .unwrap();
                let version: i64 = conn
                    .query_row("PRAGMA user_version", [], |row| row.get(0))
                    .unwrap();
                assert_eq!(value, "before", "earlier schema entry survived {sql}");
                assert_eq!(version, 0, "PRAGMA mutation survived {sql}");
                assert!(
                    conn.is_autocommit(),
                    "request left a transaction open: {sql}"
                );
            }
        }
    }

    #[test]
    fn tc626_review_single_pragma_preserves_quoted_semicolons_and_comments() {
        let conn = storage::open_connection(&StorageMode::InMemory, Synchronous::Full).unwrap();
        conn.execute_batch("CREATE TABLE \"quoted;name\" (value TEXT)")
            .unwrap();
        let result = handle_message_without_growth(
            &conn,
            &SqlRequest::Query {
                sql: "-- leading ;\nPRAGMA table_info('quoted;name'); /* trailing ; */".into(),
                params: vec![],
                max_rows: None,
                max_bytes: None,
            },
            &None,
            "tinycloud.sql/admin",
        )
        .unwrap();
        let SqlResponse::Query(response) = result.response else {
            panic!("expected query response");
        };
        assert_eq!(response.rows[0][1], SqlValue::Text("value".into()));

        handle_message_without_growth(
            &conn,
            &SqlRequest::Execute {
                schema: Some(vec!["PRAGMA user_version = 7; -- trailing ;".into()]),
                sql: "UPDATE \"quoted;name\" SET value = 'unused'".into(),
                params: vec![],
            },
            &None,
            "tinycloud.sql/admin",
        )
        .unwrap();
        let version: i64 = conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, 7);
        assert!(conn.is_autocommit());
    }

    #[test]
    fn growth_guard_rolls_back_failed_deferred_commit() {
        let conn = storage::open_connection(&StorageMode::InMemory, Synchronous::Full).unwrap();
        conn.execute_batch(
            "CREATE TABLE parents (id INTEGER PRIMARY KEY);
             CREATE TABLE children (
                 parent_id INTEGER REFERENCES parents(id) DEFERRABLE INITIALLY DEFERRED
             );
             INSERT INTO parents VALUES (1);
             INSERT INTO children VALUES (1);",
        )
        .unwrap();
        let error = handle_message_without_growth(
            &conn,
            &SqlRequest::Execute {
                schema: None,
                sql: "DELETE FROM parents".into(),
                params: vec![],
            },
            &None,
            "tinycloud.sql/write",
        )
        .unwrap_err();
        assert!(matches!(error, SqlError::Sqlite(_)));

        // The failed RELEASE must not leave a deleted parent or an open outer
        // transaction that swallows the next request's successful commit.
        handle_message_without_growth(
            &conn,
            &SqlRequest::Execute {
                schema: None,
                sql: "DELETE FROM children".into(),
                params: vec![],
            },
            &None,
            "tinycloud.sql/write",
        )
        .unwrap();
        assert!(conn.is_autocommit());
        let parents: i64 = conn
            .query_row("SELECT count(*) FROM parents", [], |row| row.get(0))
            .unwrap();
        let children: i64 = conn
            .query_row("SELECT count(*) FROM children", [], |row| row.get(0))
            .unwrap();
        assert_eq!((parents, children), (1, 0));
    }

    #[test]
    fn bounded_query_rejects_more_rows_than_requested() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        let err = execute_query(&conn, "SELECT 1 UNION ALL SELECT 2", &[], Some(1), None)
            .expect_err("the second row must exceed maxRows");

        assert!(matches!(err, SqlError::ResponseTooLarge(_)));
    }

    #[test]
    fn bounded_query_rejects_response_larger_than_requested() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        let err = execute_query(&conn, "SELECT 'payload'", &[], None, Some(1))
            .expect_err("the text value must exceed maxBytes");

        assert!(matches!(err, SqlError::ResponseTooLarge(_)));
    }

    #[test]
    fn bounded_query_uses_exact_serialized_response_size() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        let cases = [
            "SELECT 'quoted \\\"text\\\" and \\n newline' AS escaped",
            "SELECT 9223372036854775807 AS largest_integer",
            "SELECT X'0001FEFF' AS blob",
            "SELECT 1 AS one, 2 AS two, 3 AS three, 4 AS four, 5 AS five",
            "SELECT 1 UNION ALL SELECT 2 UNION ALL SELECT 3 UNION ALL SELECT 4 \
             UNION ALL SELECT 5 UNION ALL SELECT 6 UNION ALL SELECT 7 UNION ALL SELECT 8 \
             UNION ALL SELECT 9 UNION ALL SELECT 10",
        ];

        for sql in cases {
            let response = execute_query(&conn, sql, &[], None, None).unwrap();
            let exact_size = serde_json::to_vec(&response).unwrap().len();

            execute_query(&conn, sql, &[], None, Some(exact_size))
                .expect("the exact serialized response size must be accepted");
            let err = execute_query(&conn, sql, &[], None, Some(exact_size - 1))
                .expect_err("one byte below the serialized response size must fail");
            assert!(matches!(
                err,
                SqlError::ResponseTooLarge(actual) if actual == exact_size as u64
            ));
        }
    }

    #[test]
    fn only_insert_responses_include_last_insert_row_id() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE items (id INTEGER PRIMARY KEY, value TEXT)")
            .unwrap();

        let insert = handle_message(
            &conn,
            &SqlRequest::Execute {
                sql: "INSERT INTO items (value) VALUES ('before')".to_string(),
                params: vec![],
                schema: None,
            },
            &None,
            "tinycloud.sql/write",
        )
        .unwrap();
        let SqlResponse::Execute(insert) = insert.response else {
            panic!("expected execute response");
        };
        assert_eq!(insert.last_insert_row_id, Some(1));

        for sql in [
            "UPDATE items SET value = 'after' WHERE id = 1",
            "DELETE FROM items WHERE id = 1",
        ] {
            let result = handle_message(
                &conn,
                &SqlRequest::Execute {
                    sql: sql.to_string(),
                    params: vec![],
                    schema: None,
                },
                &None,
                "tinycloud.sql/write",
            )
            .unwrap();
            let SqlResponse::Execute(response) = result.response else {
                panic!("expected execute response");
            };
            assert_eq!(response.last_insert_row_id, None);
            assert_eq!(
                serde_json::to_value(response).unwrap()["lastInsertRowId"],
                serde_json::Value::Null
            );
        }
    }

    #[test]
    fn batch_and_prepared_updates_do_not_reuse_insert_row_id() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE items (id INTEGER PRIMARY KEY, value TEXT)")
            .unwrap();

        let batch = handle_message(
            &conn,
            &SqlRequest::Batch {
                statements: vec![
                    SqlStatement {
                        sql: "INSERT INTO items (value) VALUES ('before')".to_string(),
                        params: vec![],
                    },
                    SqlStatement {
                        sql: "UPDATE items SET value = 'during' WHERE id = 1".to_string(),
                        params: vec![],
                    },
                ],
            },
            &None,
            "tinycloud.sql/write",
        )
        .unwrap();
        let SqlResponse::Batch(batch) = batch.response else {
            panic!("expected batch response");
        };
        assert_eq!(batch.results[0].last_insert_row_id, Some(1));
        assert_eq!(batch.results[1].last_insert_row_id, None);

        let caveats = SqlCaveats {
            statements: Some(vec![crate::sql::caveats::PreparedStatement {
                name: "update_item".to_string(),
                sql: "UPDATE items SET value = 'after' WHERE id = 1".to_string(),
            }]),
            ..Default::default()
        };
        let prepared = handle_message(
            &conn,
            &SqlRequest::ExecuteStatement {
                name: "update_item".to_string(),
                params: vec![],
            },
            &Some(caveats),
            "tinycloud.sql/write",
        )
        .unwrap();
        let SqlResponse::Execute(prepared) = prepared.response else {
            panic!("expected execute response");
        };
        assert_eq!(prepared.last_insert_row_id, None);
    }

    #[test]
    fn batch_does_not_reuse_schema_authorizer_state_between_statements() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE source (id INTEGER); INSERT INTO source VALUES (1)")
            .unwrap();

        let error = handle_message(
            &conn,
            &SqlRequest::Batch {
                statements: vec![
                    SqlStatement {
                        sql: "CREATE INDEX source_idx ON source(id)".to_string(),
                        params: vec![],
                    },
                    SqlStatement {
                        sql: "CREATE TABLE copied AS SELECT id FROM source".to_string(),
                        params: vec![],
                    },
                ],
            },
            &None,
            "tinycloud.sql/schema",
        )
        .expect_err("a prior DDL statement must not authorize a later CTAS source read");
        assert!(
            error.to_string().contains("not authorized")
                || error.to_string().contains("is prohibited"),
            "expected an authorization error, got: {error}"
        );
        let copied_tables: i64 = conn
            .query_row(
                "SELECT count(*) FROM sqlite_schema WHERE type = 'table' AND name = 'copied'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(copied_tables, 0, "failed CTAS must not leave its table");
    }

    #[test]
    fn bounded_query_validates_public_limits() {
        assert!(matches!(
            validate_query_limits(Some(0), None),
            Err(SqlError::InvalidStatement(_))
        ));
        assert!(matches!(
            validate_query_limits(Some(MAX_BOUNDED_QUERY_ROWS + 1), None),
            Err(SqlError::InvalidStatement(_))
        ));
        assert!(matches!(
            validate_query_limits(None, Some(MAX_BOUNDED_QUERY_BYTES + 1)),
            Err(SqlError::InvalidStatement(_))
        ));
    }
}

#[cfg(test)]
mod publication_rollback_tests {
    use super::*;
    #[test]
    fn publication_rollback_restores_authorized_legacy_sql_and_bookkeeping() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE connector_meeting(id TEXT PRIMARY KEY,title TEXT,metadata TEXT,publication_state TEXT); INSERT INTO connector_meeting VALUES('old','Published','{}','published'); CREATE TABLE connector_publication_control(id INTEGER PRIMARY KEY,active INTEGER NOT NULL); INSERT INTO connector_publication_control VALUES(1,1);").unwrap();
        for sql in [
            "UPDATE connector_meeting SET title='Original',metadata='{ \"kept\": true }',publication_state=NULL WHERE id='old'",
            "UPDATE connector_publication_control SET active=0 WHERE id=1",
            "INSERT INTO connector_meeting(id,title) VALUES('new','Legacy sync')",
            "DELETE FROM connector_meeting WHERE id='new'",
        ] {
            handle_message(&conn, &SqlRequest::Execute { sql: sql.into(), params: vec![], schema: None }, &None, "tinycloud.sql/write").unwrap_or_else(|error| panic!("legacy recovery rejected: {error}"));
        }
        assert_eq!(
            conn.query_row(
                "SELECT title,metadata,publication_state FROM connector_meeting WHERE id='old'",
                [],
                |row| Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?
                ))
            )
            .unwrap(),
            ("Original".into(), "{ \"kept\": true }".into(), None)
        );
        assert_eq!(
            conn.query_row(
                "SELECT active FROM connector_publication_control",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
            0
        );
    }

    #[test]
    fn publication_rollback_keeps_normal_read_only_authority() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE connector_meeting(id TEXT PRIMARY KEY,title TEXT); INSERT INTO connector_meeting VALUES('old','Original'); CREATE TABLE connector_publication_control(id INTEGER PRIMARY KEY,active INTEGER NOT NULL); INSERT INTO connector_publication_control VALUES(1,1);").unwrap();
        let result = handle_message(
            &conn,
            &SqlRequest::Execute {
                sql: "UPDATE connector_meeting SET title='Unauthorized'".into(),
                params: vec![],
                schema: None,
            },
            &None,
            "tinycloud.sql/read",
        );
        assert!(result.is_err());
        assert_eq!(
            conn.query_row("SELECT title FROM connector_meeting", [], |row| row
                .get::<_, String>(0))
                .unwrap(),
            "Original"
        );
    }

    // TC-1491: a request with several statements is all-or-nothing.

    fn exec(sql: &str) -> SqlRequest {
        SqlRequest::Execute {
            schema: None,
            sql: sql.into(),
            params: vec![],
        }
    }

    fn batch(statements: &[&str]) -> SqlRequest {
        SqlRequest::Batch {
            statements: statements
                .iter()
                .map(|sql| SqlStatement {
                    sql: (*sql).into(),
                    params: vec![],
                })
                .collect(),
        }
    }

    async fn run(
        actor: &DatabaseHandle,
        request: SqlRequest,
        growth: GrowthPolicy,
    ) -> Result<SqlExecutionResult, SqlError> {
        actor
            .execute(request, None, "tinycloud.sql/admin".into(), growth)
            .await
    }

    async fn scalar(actor: &DatabaseHandle, sql: &str) -> String {
        let result = run(
            actor,
            SqlRequest::Query {
                sql: sql.into(),
                params: vec![],
                max_rows: None,
                max_bytes: None,
            },
            GrowthPolicy::Allow,
        )
        .await
        .unwrap();
        match result.response {
            SqlResponse::Query(query) => match &query.rows[0][0] {
                SqlValue::Integer(value) => value.to_string(),
                SqlValue::Text(value) => value.clone(),
                other => format!("{other:?}"),
            },
            other => panic!("expected a query response, got {other:?}"),
        }
    }

    fn spawn_test_actor(dir: &tempfile::TempDir, memory_threshold: u64) -> DatabaseHandle {
        spawn_actor(
            "space".into(),
            "atomic".into(),
            dir.path().to_str().unwrap().into(),
            memory_threshold,
            Arc::new(DashMap::new()),
        )
    }

    #[tokio::test]
    async fn tc1491_failed_batch_leaves_the_local_file_unchanged() {
        for memory_threshold in [u64::MAX, 0] {
            for growth in [GrowthPolicy::Allow, GrowthPolicy::Forbid] {
                let dir = tempfile::tempdir().unwrap();
                let actor = spawn_test_actor(&dir, memory_threshold);
                run(
                    &actor,
                    exec("CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT NOT NULL)"),
                    GrowthPolicy::Allow,
                )
                .await
                .unwrap();
                run(
                    &actor,
                    exec("INSERT INTO t (v) VALUES ('keep')"),
                    GrowthPolicy::Allow,
                )
                .await
                .unwrap();
                let before = actor.checkpoint().await.unwrap();

                // Two statements apply, the third violates NOT NULL.
                let failed = run(
                    &actor,
                    batch(&[
                        "UPDATE t SET v = 'changed'",
                        "INSERT INTO t (v) VALUES ('prefix')",
                        "INSERT INTO t (v) VALUES (NULL)",
                    ]),
                    growth,
                )
                .await;
                assert!(matches!(failed, Err(SqlError::Sqlite(_))), "{failed:?}");

                assert_eq!(scalar(&actor, "SELECT count(*) FROM t").await, "1");
                assert_eq!(scalar(&actor, "SELECT v FROM t").await, "keep");
                // The `Forbid` guard predates this change and ends a rejected
                // request with ROLLBACK TO + RELEASE, which commits an empty
                // transaction and bumps the header's change counter; its
                // content is checked above, its bytes only for `Allow`.
                if growth == GrowthPolicy::Allow {
                    assert!(
                        actor.checkpoint().await.unwrap() == before,
                        "a rejected batch must not change a single byte of the checkpoint"
                    );
                }
            }
        }
    }

    #[tokio::test]
    async fn tc1491_failed_schema_request_leaves_no_schema_behind() {
        for memory_threshold in [u64::MAX, 0] {
            let dir = tempfile::tempdir().unwrap();
            let actor = spawn_test_actor(&dir, memory_threshold);
            run(
                &actor,
                exec("CREATE TABLE base (id INTEGER)"),
                GrowthPolicy::Allow,
            )
            .await
            .unwrap();
            let failed = run(
                &actor,
                SqlRequest::Execute {
                    schema: Some(vec![
                        "CREATE TABLE extra (id INTEGER)".into(),
                        "CREATE INDEX extra_id ON extra (id)".into(),
                    ]),
                    sql: "INSERT INTO missing_table VALUES (1)".into(),
                    params: vec![],
                },
                GrowthPolicy::Allow,
            )
            .await;
            assert!(failed.is_err());
            assert_eq!(
                scalar(
                    &actor,
                    "SELECT count(*) FROM sqlite_master WHERE name IN ('extra', 'extra_id')"
                )
                .await,
                "0"
            );
        }
    }

    #[tokio::test]
    async fn tc1491_successful_batch_and_ddl_batch_apply_in_full() {
        let dir = tempfile::tempdir().unwrap();
        let actor = spawn_test_actor(&dir, 0);
        let result = run(
            &actor,
            batch(&[
                "CREATE TABLE a (id INTEGER PRIMARY KEY, v TEXT)",
                "CREATE INDEX a_v ON a (v)",
                "INSERT INTO a (v) VALUES ('x')",
                "INSERT INTO a (v) VALUES ('y')",
            ]),
            GrowthPolicy::Allow,
        )
        .await
        .unwrap();
        let SqlResponse::Batch(response) = result.response else {
            panic!("expected a batch response");
        };
        assert_eq!(response.results.len(), 4);
        assert_eq!(response.results[3].last_insert_row_id, Some(2));
        assert_eq!(scalar(&actor, "SELECT count(*) FROM a").await, "2");

        // A failing DDL batch undoes its DDL too.
        let failed = run(
            &actor,
            batch(&["CREATE TABLE b (id INTEGER)", "CREATE TABLE a (id INTEGER)"]),
            GrowthPolicy::Allow,
        )
        .await;
        assert!(failed.is_err());
        assert_eq!(
            scalar(
                &actor,
                "SELECT count(*) FROM sqlite_master WHERE name = 'b'"
            )
            .await,
            "0"
        );
    }

    #[tokio::test]
    async fn tc1491_user_transaction_control_is_still_denied() {
        let dir = tempfile::tempdir().unwrap();
        let actor = spawn_test_actor(&dir, 0);
        run(&actor, exec("CREATE TABLE t (v TEXT)"), GrowthPolicy::Allow)
            .await
            .unwrap();
        for control in [
            "BEGIN",
            "COMMIT",
            "ROLLBACK",
            "END",
            "SAVEPOINT mine",
            "RELEASE tinycloud_request",
            "ROLLBACK TO tinycloud_request",
        ] {
            for request in [
                batch(&["INSERT INTO t VALUES ('a')", control]),
                batch(&[control, "INSERT INTO t VALUES ('a')"]),
                SqlRequest::Execute {
                    schema: Some(vec![control.into()]),
                    sql: "INSERT INTO t VALUES ('a')".into(),
                    params: vec![],
                },
            ] {
                let result = run(&actor, request, GrowthPolicy::Allow).await;
                assert!(result.is_err(), "{control} must be refused: {result:?}");
                assert_eq!(
                    scalar(&actor, "SELECT count(*) FROM t").await,
                    "0",
                    "{control} must not let a prefix commit"
                );
            }
        }
    }

    /// A request that carries a `PRAGMA` is one transaction like any other:
    /// a failure leaves neither its statements nor the header value it set,
    /// and the connection is still served afterwards.
    #[tokio::test]
    async fn tc1491_pragma_requests_are_one_transaction() {
        for memory_threshold in [u64::MAX, 0] {
            let dir = tempfile::tempdir().unwrap();
            let actor = spawn_test_actor(&dir, memory_threshold);
            run(
                &actor,
                exec("CREATE TABLE t (v TEXT NOT NULL)"),
                GrowthPolicy::Allow,
            )
            .await
            .unwrap();
            let before = actor.checkpoint().await.unwrap();

            // `user_version` is on the admin PRAGMA allow-list (TC-1586);
            // `foreign_keys = OFF` is not.
            for failing in [
                batch(&[
                    "PRAGMA user_version = 7",
                    "INSERT INTO t VALUES ('prefix')",
                    "INSERT INTO t VALUES (NULL)",
                ]),
                batch(&[
                    "INSERT INTO t VALUES ('prefix')",
                    "PRAGMA application_id = 9",
                    "INSERT INTO t VALUES (NULL)",
                ]),
                SqlRequest::Execute {
                    schema: Some(vec![
                        "PRAGMA user_version = 7".into(),
                        "INSERT INTO t VALUES ('prefix')".into(),
                    ]),
                    sql: "INSERT INTO t VALUES (NULL)".into(),
                    params: vec![],
                },
            ] {
                let failed = run(&actor, failing, GrowthPolicy::Allow).await;
                assert!(failed.is_err());
                assert_eq!(scalar(&actor, "SELECT count(*) FROM t").await, "0");
                assert_eq!(scalar(&actor, "PRAGMA user_version").await, "0");
                assert_eq!(scalar(&actor, "PRAGMA application_id").await, "0");
                assert!(
                    actor.checkpoint().await.unwrap() == before,
                    "a rejected request with a PRAGMA must not change a single byte"
                );
            }

            // The reports an admin may run, in a request that writes: they
            // return normally inside the transaction and the write is kept.
            run(
                &actor,
                SqlRequest::Execute {
                    schema: Some(
                        [
                            "PRAGMA journal_mode",
                            "PRAGMA foreign_keys",
                            "PRAGMA page_count",
                            "PRAGMA schema_version",
                            "PRAGMA freelist_count",
                            "PRAGMA data_version",
                            "PRAGMA table_info(t)",
                            "PRAGMA integrity_check",
                            "PRAGMA quick_check",
                            "PRAGMA foreign_key_check",
                            "PRAGMA user_version = 3",
                        ]
                        .map(String::from)
                        .to_vec(),
                    ),
                    sql: "INSERT INTO t VALUES ('kept')".into(),
                    params: vec![],
                },
                GrowthPolicy::Allow,
            )
            .await
            .unwrap();
            assert_eq!(scalar(&actor, "SELECT count(*) FROM t").await, "1");
            assert_eq!(scalar(&actor, "PRAGMA user_version").await, "3");
            // A single PRAGMA request runs, and the connection keeps the
            // state it opened with (the TC-1586 reset ran after the request).
            assert_eq!(scalar(&actor, "PRAGMA foreign_keys").await, "1");
        }
    }

    /// A write that stops with `OR FAIL` or `ON CONFLICT FAIL` keeps the rows
    /// it changed first when it runs on its own; the request is one
    /// transaction, so it keeps none of them, in memory and on disk.
    #[test]
    fn tc1491_a_single_write_with_fail_conflict_resolution_leaves_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("fail.db");
        for mode in [StorageMode::InMemory, StorageMode::File(file.clone())] {
            let conn =
                storage::open_connection(&mode, crate::sql::durability::Synchronous::Full).unwrap();
            // `ON CONFLICT FAIL` on a column is outside what the SQL parser
            // accepts, so the schema is created on the connection directly.
            conn.execute_batch(
                "CREATE TABLE u (id INTEGER PRIMARY KEY, v TEXT UNIQUE ON CONFLICT FAIL);
                 CREATE TABLE n (id INTEGER PRIMARY KEY, v TEXT NOT NULL ON CONFLICT FAIL);
                 INSERT INTO u VALUES (10, 'x'), (11, 'y'), (12, 'z');",
            )
            .unwrap();
            let bytes = || -> Vec<u8> {
                match &mode {
                    StorageMode::File(path) => {
                        conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()))
                            .unwrap();
                        std::fs::read(path).unwrap()
                    }
                    // In memory there is no file; the rows are the check.
                    StorageMode::InMemory => Vec::new(),
                }
            };
            let before = bytes();
            for sql in [
                "INSERT OR FAIL INTO u VALUES (1, 'a'), (2, 'b'), (1, 'dup')",
                "UPDATE u SET v = 'same'",
                "UPDATE OR FAIL u SET v = 'same'",
                "INSERT INTO n VALUES (1, 'a'), (2, 'b'), (3, NULL)",
            ] {
                for request in [
                    exec(sql),
                    SqlRequest::Query {
                        sql: sql.into(),
                        params: vec![],
                        max_rows: None,
                        max_bytes: None,
                    },
                    batch(&[sql]),
                ] {
                    let failed = handle_message(&conn, &request, &None, "tinycloud.sql/write");
                    // `UPDATE OR FAIL` is outside what the SQL parser accepts:
                    // refused, and nothing changes either.
                    assert!(failed.is_err(), "{sql}: {failed:?}");
                    let rows = |sql: &str| -> String {
                        conn.query_row(sql, [], |row| row.get(0)).unwrap()
                    };
                    assert_eq!(
                        rows("SELECT count(*) || ':' || group_concat(v) FROM u"),
                        "3:x,y,z"
                    );
                    assert_eq!(rows("SELECT count(*) || '' FROM n"), "0");
                    assert!(conn.is_autocommit());
                    assert!(bytes() == before, "{sql}: the file must not change");
                }
            }
        }
    }

    /// A connection still inside a transaction after its request is retired:
    /// the next request would otherwise run inside it.
    #[tokio::test]
    async fn tc1491_a_connection_left_in_a_transaction_retires_the_actor() {
        let dir = tempfile::tempdir().unwrap();
        let key = ("space".to_string(), "leaks".to_string());
        for growth in [GrowthPolicy::Allow, GrowthPolicy::Forbid] {
            let databases = Arc::new(DashMap::new());
            let actor = spawn_actor(
                key.0.clone(),
                key.1.clone(),
                dir.path().to_str().unwrap().into(),
                u64::MAX,
                databases.clone(),
            );
            databases.insert(key.clone(), actor.clone());
            run(&actor, exec("CREATE TABLE t (v TEXT)"), GrowthPolicy::Allow)
                .await
                .unwrap();

            OPEN_TRANSACTIONS.lock().unwrap().push(key.clone());
            let result = run(&actor, exec("INSERT INTO t VALUES ('x')"), growth).await;
            OPEN_TRANSACTIONS.lock().unwrap().retain(|k| *k != key);
            assert!(matches!(result, Err(SqlError::Internal(_))), "{result:?}");
            assert!(
                !databases.contains_key(&key),
                "the retired actor must leave the registry"
            );
            assert!(
                run(&actor, exec("INSERT INTO t VALUES ('y')"), growth)
                    .await
                    .is_err(),
                "a retired actor serves no further request"
            );
        }
    }
}

/// TC-1581: schema-changing statements need `schema`; `write` is data only.
/// Every request variant is judged statement by statement against all the
/// abilities held, not against one preferred ability.
#[cfg(test)]
mod ddl_authority_tests {
    use super::*;
    use crate::sql::authority::{ddl_without_schema_count, DdlKind, DdlPolicy};
    use std::sync::{Arc, Mutex};

    const READ: &str = "tinycloud.sql/read";
    const WRITE: &str = "tinycloud.sql/write";
    const SCHEMA: &str = "tinycloud.sql/schema";
    const ADMIN: &str = "tinycloud.sql/admin";
    const STAR: &str = "tinycloud.sql/*";

    fn held(abilities: &[&str]) -> SqlAuthority {
        SqlAuthority::new(abilities.iter().copied())
    }

    fn execute(sql: &str, schema: Option<&[&str]>) -> SqlRequest {
        SqlRequest::Execute {
            sql: sql.to_string(),
            params: vec![],
            schema: schema.map(|s| s.iter().map(|s| s.to_string()).collect()),
        }
    }

    fn batch(statements: &[&str]) -> SqlRequest {
        SqlRequest::Batch {
            statements: statements
                .iter()
                .map(|sql| SqlStatement {
                    sql: sql.to_string(),
                    params: vec![],
                })
                .collect(),
        }
    }

    fn query(sql: &str) -> SqlRequest {
        SqlRequest::Query {
            sql: sql.to_string(),
            params: vec![],
            max_rows: None,
            max_bytes: None,
        }
    }

    fn caveats_with(statements: &[(&str, &str)]) -> Option<SqlCaveats> {
        Some(SqlCaveats {
            statements: Some(
                statements
                    .iter()
                    .map(|(name, sql)| crate::sql::caveats::PreparedStatement {
                        name: name.to_string(),
                        sql: sql.to_string(),
                    })
                    .collect(),
            ),
            ..SqlCaveats::default()
        })
    }

    fn run(
        conn: &rusqlite::Connection,
        request: &SqlRequest,
        caveats: &Option<SqlCaveats>,
        authority: &SqlAuthority,
    ) -> Result<SqlExecutionResult, SqlError> {
        let policy = DurabilityPolicy::default();
        let ctx = WriteContext {
            policy: &policy,
            key: "test/test",
            dir: Path::new("."),
            file_backed: false,
            remaining: None,
        };
        handle_message_ctx(
            conn,
            request,
            caveats,
            authority,
            &PragmaTracker::default(),
            &ctx,
        )
    }

    fn table_exists(conn: &rusqlite::Connection, name: &str) -> bool {
        conn.query_row(
            "SELECT count(*) FROM sqlite_schema WHERE name = ?",
            [name],
            |row| row.get::<_, i64>(0),
        )
        .unwrap()
            > 0
    }

    fn is_denied(result: &Result<SqlExecutionResult, SqlError>) -> bool {
        matches!(
            result,
            Err(SqlError::PermissionDenied(_)) | Err(SqlError::ReadOnlyViolation)
        )
    }

    #[test]
    fn write_alone_cannot_change_the_schema_on_any_request_path() {
        let ddl = [
            "CREATE TABLE made (id INTEGER)",
            "DROP TABLE data",
            "ALTER TABLE data ADD COLUMN extra TEXT",
            "CREATE INDEX data_value ON data (value)",
            "CREATE VIEW data_view AS SELECT value FROM data",
        ];
        for sql in ddl {
            for abilities in [&[WRITE][..], &[READ, WRITE][..], &[READ][..]] {
                let authority = held(abilities);
                let conn = rusqlite::Connection::open_in_memory().unwrap();
                conn.execute_batch(
                    "CREATE TABLE data (value TEXT); INSERT INTO data VALUES ('kept')",
                )
                .unwrap();
                let schema_before: i64 = conn
                    .query_row("SELECT count(*) FROM sqlite_schema", [], |row| row.get(0))
                    .unwrap();

                let named = caveats_with(&[("change", sql)]);
                let attempts = [
                    ("query", run(&conn, &query(sql), &None, &authority)),
                    (
                        "execute",
                        run(&conn, &execute(sql, None), &None, &authority),
                    ),
                    (
                        "execute schema[]",
                        run(&conn, &execute("SELECT 1", Some(&[sql])), &None, &authority),
                    ),
                    (
                        "batch",
                        run(
                            &conn,
                            &batch(&["INSERT INTO data VALUES ('second')", sql]),
                            &None,
                            &authority,
                        ),
                    ),
                    (
                        "named statement",
                        run(
                            &conn,
                            &SqlRequest::ExecuteStatement {
                                name: "change".into(),
                                params: vec![],
                            },
                            &named,
                            &authority,
                        ),
                    ),
                ];
                for (path, result) in attempts {
                    assert!(is_denied(&result), "{abilities:?} {path} {sql}: {result:?}");
                }

                let schema_after: i64 = conn
                    .query_row("SELECT count(*) FROM sqlite_schema", [], |row| row.get(0))
                    .unwrap();
                assert_eq!(
                    schema_before, schema_after,
                    "{abilities:?} changed the schema: {sql}"
                );
                let rows: i64 = conn
                    .query_row("SELECT count(*) FROM data", [], |row| row.get(0))
                    .unwrap();
                assert_eq!(
                    rows, 1,
                    "a refused batch must not run its earlier statements"
                );
            }
        }
    }

    #[test]
    fn schema_conferring_abilities_run_ddl_on_every_request_path() {
        for abilities in [
            &[SCHEMA][..],
            &[WRITE, SCHEMA][..],
            &[ADMIN][..],
            &[STAR][..],
        ] {
            let authority = held(abilities);
            let conn = rusqlite::Connection::open_in_memory().unwrap();
            let named = caveats_with(&[("mk", "CREATE TABLE IF NOT EXISTS named (id INTEGER)")]);
            run(
                &conn,
                &query("CREATE TABLE via_query (id INTEGER)"),
                &None,
                &authority,
            )
            .unwrap_or_else(|e| panic!("{abilities:?} query: {e:?}"));
            run(
                &conn,
                &execute("CREATE TABLE via_execute (id INTEGER)", None),
                &None,
                &authority,
            )
            .unwrap_or_else(|e| panic!("{abilities:?} execute: {e:?}"));
            run(
                &conn,
                &batch(&["CREATE TABLE via_batch (id INTEGER)"]),
                &None,
                &authority,
            )
            .unwrap_or_else(|e| panic!("{abilities:?} batch: {e:?}"));
            run(
                &conn,
                &SqlRequest::ExecuteStatement {
                    name: "mk".into(),
                    params: vec![],
                },
                &named,
                &authority,
            )
            .unwrap_or_else(|e| panic!("{abilities:?} named: {e:?}"));
            for table in ["via_query", "via_execute", "via_batch", "named"] {
                assert!(table_exists(&conn, table), "{abilities:?} {table}");
            }
            run(
                &conn,
                &execute("DROP TABLE via_query", None),
                &None,
                &authority,
            )
            .unwrap_or_else(|e| panic!("{abilities:?} drop: {e:?}"));
        }
    }

    #[test]
    fn mixed_requests_need_both_abilities_or_admin() {
        let create = "CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY, body TEXT)";
        let insert = "INSERT INTO notes (body) VALUES ('hello')";
        for (abilities, expected_ok) in [
            (&[WRITE, SCHEMA][..], true),
            (&[ADMIN][..], true),
            (&[STAR][..], true),
            (&[WRITE][..], false),
            (&[SCHEMA][..], false),
            (&[READ][..], false),
            (&[READ, SCHEMA][..], false),
        ] {
            let authority = held(abilities);

            // execute { schema: [DDL], sql: DML }: the SDK's migration shape.
            let conn = rusqlite::Connection::open_in_memory().unwrap();
            let result = run(&conn, &execute(insert, Some(&[create])), &None, &authority);
            assert_eq!(
                result.is_ok(),
                expected_ok,
                "{abilities:?} execute: {result:?}"
            );

            // batch [DDL, DML] is validated before anything runs.
            let conn = rusqlite::Connection::open_in_memory().unwrap();
            let result = run(&conn, &batch(&[create, insert]), &None, &authority);
            assert_eq!(
                result.is_ok(),
                expected_ok,
                "{abilities:?} batch: {result:?}"
            );
            if !expected_ok {
                assert!(
                    !table_exists(&conn, "notes"),
                    "{abilities:?}: a refused batch ran its DDL"
                );
            }
        }
    }

    #[test]
    fn data_statements_still_run_on_write_alone() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE data (id INTEGER PRIMARY KEY, value TEXT)")
            .unwrap();
        let authority = held(&[WRITE]);
        for sql in [
            "INSERT INTO data (value) VALUES ('a')",
            "INSERT OR REPLACE INTO data (id, value) VALUES (1, 'b')",
            "UPDATE data SET value = 'c' WHERE id = 1",
            "WITH x AS (SELECT 'd' AS value) INSERT INTO data (value) SELECT value FROM x",
            "DELETE FROM data WHERE id = 1",
        ] {
            run(&conn, &execute(sql, None), &None, &authority)
                .unwrap_or_else(|e| panic!("write must run {sql}: {e:?}"));
        }
        run(
            &conn,
            &batch(&["INSERT INTO data (value) VALUES ('e')"]),
            &None,
            &authority,
        )
        .unwrap();
        let read = run(
            &conn,
            &query("SELECT value FROM data ORDER BY id"),
            &None,
            &authority,
        )
        .unwrap();
        let SqlResponse::Query(rows) = read.response else {
            panic!("expected rows");
        };
        assert_eq!(rows.row_count, 2);

        // A named statement that is data runs on write alone as well.
        let named = caveats_with(&[("put", "INSERT INTO data (value) VALUES ('f')")]);
        run(
            &conn,
            &SqlRequest::ExecuteStatement {
                name: "put".into(),
                params: vec![],
            },
            &named,
            &authority,
        )
        .unwrap();
    }

    #[test]
    fn read_stays_read_only() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE data (value TEXT)")
            .unwrap();
        let authority = held(&[READ]);
        run(&conn, &query("SELECT value FROM data"), &None, &authority).unwrap();
        let result = run(
            &conn,
            &execute("INSERT INTO data VALUES ('x')", None),
            &None,
            &authority,
        );
        assert!(
            matches!(result, Err(SqlError::ReadOnlyViolation)),
            "{result:?}"
        );
    }

    #[test]
    fn pragma_is_unchanged_for_write_and_schema() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        for abilities in [&[WRITE][..], &[SCHEMA][..], &[WRITE, SCHEMA][..]] {
            let authority = held(abilities);
            for request in [
                query("PRAGMA user_version = 9"),
                execute("PRAGMA user_version = 9", None),
                execute("SELECT 1", Some(&["PRAGMA user_version = 9"])),
            ] {
                let result = run(&conn, &request, &None, &authority);
                assert!(is_denied(&result), "{abilities:?}: {result:?}");
            }
        }
        for abilities in [&[ADMIN][..], &[STAR][..]] {
            run(
                &conn,
                &execute("PRAGMA user_version = 3", None),
                &None,
                &held(abilities),
            )
            .unwrap();
        }
        let version: i64 = conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, 3);
    }

    #[test]
    fn ddl_policy_switch_off_log_enforce() {
        let _serial = crate::sql::authority::LOG_COUNTER_LOCK.blocking_lock();
        let create = "CREATE TABLE IF NOT EXISTS made (id INTEGER)";
        for (policy, write_only_may_ddl) in [
            (DdlPolicy::Off, true),
            (DdlPolicy::Log, true),
            (DdlPolicy::Enforce, false),
        ] {
            let conn = rusqlite::Connection::open_in_memory().unwrap();
            let write_only = held(&[WRITE]).with_ddl_policy(policy);
            let result = run(&conn, &execute(create, None), &None, &write_only);
            assert_eq!(result.is_ok(), write_only_may_ddl, "{policy:?}: {result:?}");
            assert_eq!(
                table_exists(&conn, "made"),
                write_only_may_ddl,
                "{policy:?}"
            );

            // Holders of schema and read are judged the same in every mode.
            let conn = rusqlite::Connection::open_in_memory().unwrap();
            let both = held(&[WRITE, SCHEMA]).with_ddl_policy(policy);
            run(&conn, &execute(create, None), &None, &both).unwrap();
            let read = held(&[READ]).with_ddl_policy(policy);
            assert!(is_denied(&run(
                &conn,
                &execute("DROP TABLE made", None),
                &None,
                &read
            )));
        }
    }

    #[derive(Clone, Default)]
    struct Captured(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for Captured {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Captured {
        type Writer = Captured;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    #[test]
    fn log_mode_counts_each_statement_and_warns_once_without_request_content() {
        let _serial = crate::sql::authority::LOG_COUNTER_LOCK.blocking_lock();
        let captured = Captured::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(captured.clone())
            .with_ansi(false)
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);

        let conn = rusqlite::Connection::open_in_memory().unwrap();
        let authority = held(&[WRITE]).with_ddl_policy(DdlPolicy::Log);
        let secret_table = "tc1581_secret_table_name";
        let create_before = ddl_without_schema_count(DdlKind::CreateTable);
        let drop_before = ddl_without_schema_count(DdlKind::Drop);

        run(
            &conn,
            &batch(&[
                &format!("CREATE TABLE {secret_table} (id INTEGER)"),
                &format!("CREATE TABLE {secret_table}_two (id INTEGER)"),
                &format!("DROP TABLE {secret_table}_two"),
                &format!("INSERT INTO {secret_table} (id) VALUES (1)"),
            ]),
            &None,
            &authority,
        )
        .unwrap();

        assert_eq!(
            ddl_without_schema_count(DdlKind::CreateTable) - create_before,
            2
        );
        assert_eq!(ddl_without_schema_count(DdlKind::Drop) - drop_before, 1);

        let logged = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
        assert_eq!(
            logged.matches("ddl_requires_schema = log").count(),
            1,
            "one warning per request: {logged}"
        );
        assert!(
            !logged.contains(secret_table),
            "log carried request content: {logged}"
        );
        assert!(!logged.to_lowercase().contains("create table"), "{logged}");

        // A holder of schema is not counted, and data statements never are.
        let before = ddl_without_schema_count(DdlKind::CreateTable);
        let both = held(&[WRITE, SCHEMA]).with_ddl_policy(DdlPolicy::Log);
        run(
            &conn,
            &execute("CREATE TABLE fine (id INTEGER)", None),
            &None,
            &both,
        )
        .unwrap();
        run(
            &conn,
            &execute("INSERT INTO fine VALUES (1)", None),
            &None,
            &authority,
        )
        .unwrap();
        assert_eq!(ddl_without_schema_count(DdlKind::CreateTable), before);
        let after_logged = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
        assert_eq!(after_logged.matches("ddl_requires_schema = log").count(), 1);
    }

    #[test]
    fn enforce_and_off_neither_count_nor_warn() {
        let _serial = crate::sql::authority::LOG_COUNTER_LOCK.blocking_lock();
        let captured = Captured::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(captured.clone())
            .with_ansi(false)
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);
        let before = ddl_without_schema_count(DdlKind::AlterTable);

        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE t (a)").unwrap();
        let off = held(&[WRITE]).with_ddl_policy(DdlPolicy::Off);
        run(
            &conn,
            &execute("ALTER TABLE t ADD COLUMN b", None),
            &None,
            &off,
        )
        .unwrap();
        let enforce = held(&[WRITE]).with_ddl_policy(DdlPolicy::Enforce);
        let denied = run(
            &conn,
            &execute("ALTER TABLE t ADD COLUMN c", None),
            &None,
            &enforce,
        );
        assert!(is_denied(&denied));

        assert_eq!(ddl_without_schema_count(DdlKind::AlterTable), before);
        assert!(captured.0.lock().unwrap().is_empty());
    }

    #[test]
    fn an_unregistered_ability_beside_schema_runs_no_data_statement() {
        const UNREGISTERED: &str = "tinycloud.sql/not-a-registered-ability";
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE data (value TEXT)")
            .unwrap();
        for abilities in [&[SCHEMA][..], &[SCHEMA, UNREGISTERED][..]] {
            let authority = held(abilities);
            for request in [
                query("SELECT value FROM data"),
                execute("INSERT INTO data VALUES ('x')", None),
                batch(&["DELETE FROM data"]),
                execute(
                    "SELECT 1",
                    Some(&["CREATE TABLE IF NOT EXISTS made (id INTEGER)"]),
                ),
            ] {
                let result = run(&conn, &request, &None, &authority);
                // The schema entry of the last request is the one statement
                // schema authority may run; its trailing SELECT is refused.
                assert!(is_denied(&result), "{abilities:?} {request:?}: {result:?}");
            }
        }
    }

    /// TC-1586: the reset returns a connection to the state `open_connection`
    /// leaves it in, for an in-memory connection (journal mode included) and a
    /// file-backed one.
    #[test]
    fn reset_restores_the_opening_state_for_memory_and_file_connections() {
        let dir = tempfile::TempDir::new().unwrap();
        for mode in [
            StorageMode::InMemory,
            StorageMode::File(dir.path().join("reset.db")),
        ] {
            let conn =
                storage::open_connection(&mode, crate::sql::durability::Synchronous::Full).unwrap();
            conn.execute_batch("CREATE TABLE t (a)").unwrap();
            let read = |pragma: &str| -> String {
                conn.query_row(&format!("PRAGMA {pragma}"), [], |row| {
                    row.get::<_, rusqlite::types::Value>(0)
                        .map(|value| match value {
                            rusqlite::types::Value::Integer(n) => n.to_string(),
                            rusqlite::types::Value::Text(s) => s,
                            other => format!("{other:?}"),
                        })
                })
                .unwrap()
            };
            let opening: Vec<String> = [
                "journal_mode",
                "foreign_keys",
                "writable_schema",
                "query_only",
                "ignore_check_constraints",
                "recursive_triggers",
                "reverse_unordered_selects",
            ]
            .iter()
            .map(|pragma| read(pragma))
            .collect();

            let other_journal_mode = if matches!(mode, StorageMode::InMemory) {
                "OFF"
            } else {
                "DELETE"
            };
            conn.execute_batch(&format!(
                "PRAGMA writable_schema = ON; PRAGMA query_only = ON;
                 PRAGMA foreign_keys = OFF; PRAGMA ignore_check_constraints = ON;
                 PRAGMA recursive_triggers = ON; PRAGMA reverse_unordered_selects = ON;
                 PRAGMA journal_mode = {other_journal_mode};"
            ))
            .unwrap();
            assert_ne!(read("journal_mode"), opening[0], "the test must change it");
            assert_eq!(read("foreign_keys"), "0");

            reset_connection_state(&conn, &mode).unwrap();
            let after: Vec<String> = [
                "journal_mode",
                "foreign_keys",
                "writable_schema",
                "query_only",
                "ignore_check_constraints",
                "recursive_triggers",
                "reverse_unordered_selects",
            ]
            .iter()
            .map(|pragma| read(pragma))
            .collect();
            assert_eq!(opening, after, "{mode:?}");
        }
    }

    #[test]
    fn nested_block_comments_hide_nothing_on_any_request_path() {
        let hidden =
            "CREATE TABLE IF NOT EXISTS made (id INTEGER) /* /* */ ; DELETE FROM data; /* */";
        for abilities in [&[SCHEMA][..], &[WRITE, SCHEMA][..], &[ADMIN][..]] {
            let authority = held(abilities);
            let conn = rusqlite::Connection::open_in_memory().unwrap();
            conn.execute_batch("CREATE TABLE data (value TEXT); INSERT INTO data VALUES ('kept')")
                .unwrap();
            let named = caveats_with(&[("change", hidden)]);
            for (label, result) in [
                ("query", run(&conn, &query(hidden), &None, &authority)),
                (
                    "schema entry",
                    run(
                        &conn,
                        &execute("SELECT 1", Some(&[hidden])),
                        &None,
                        &authority,
                    ),
                ),
                ("batch", run(&conn, &batch(&[hidden]), &None, &authority)),
                (
                    "named",
                    run(
                        &conn,
                        &SqlRequest::ExecuteStatement {
                            name: "change".into(),
                            params: vec![],
                        },
                        &named,
                        &authority,
                    ),
                ),
            ] {
                assert!(result.is_err(), "{abilities:?} {label}: {result:?}");
            }
            let rows: i64 = conn
                .query_row("SELECT count(*) FROM data", [], |row| row.get(0))
                .unwrap();
            assert_eq!(rows, 1, "{abilities:?}");
            assert!(!table_exists(&conn, "made"), "{abilities:?}");
        }
    }
}
