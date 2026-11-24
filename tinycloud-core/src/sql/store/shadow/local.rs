//! The local-file uploader source (TC-1491 P4.2a, design 5.3 and 12).
//!
//! [`LocalFileSource`] reads a store-master database's checkpoint and WAL from
//! the local working copy, where [`PgArtifactSource`] reads Postgres.
//!
//! - **Under the operation lock, after COMMIT.** Every method takes the
//!   database's operation lock (the same one every execute and export takes),
//!   so a write is either wholly in the files it reads or not started. It
//!   copies into the uploader's scratch file and **drops the lock before it
//!   returns**: the PUT and the manifest CAS that follow run with no lock held
//!   (contract 11.5 / R7), so a slow store never stalls a write.
//! - **Wakes on local commits.** The service calls
//!   [`ShadowSink::notify_local`](super::ShadowSink::notify_local) after each
//!   commit; the 8 MiB trigger is that notice's `ahead_bytes`.
//! - **`seq` is the in-file counter.** `head().revision` is the counter the
//!   actor wrote in the write's own transaction.
//! - **The WAL cannot be reset behind the uploader's back.** Auto-checkpoint
//!   is off and the working copy does not checkpoint on close. The only
//!   checkpoint is [`LocalFileSource::head`]'s rotation, which runs when the
//!   WAL reaches [`WINDOW_BYTES`]: it counts one revision, folds the WAL into
//!   the main file, and the new main file is published as a snapshot at that
//!   revision. If anything else did reset the WAL, the marks' prefix hashes no
//!   longer match, the upload falls back to a cumulative segment, and a
//!   checkpoint that changed is a [`SourceError::MovedOn`], never a wrong
//!   delta.
//! - **Pilot cap.** A checkpoint above [`PILOT_CAP_BYTES`] is
//!   [`SourceError::TooLarge`]: the database is blocked as `too_large` and
//!   nothing of it is published.
//!
//! [`RoutedSource`] picks this source for store-master databases and
//! [`PgArtifactSource`] for everything else, so a pg_master or shadow database
//! is read exactly as before.
//!
//! The head of a restarted node has no marks, so its first publish is a
//! cumulative segment (always correct); deltas resume from the next one.

use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;
use tinycloud_auth::resource::SpaceId;
use tokio::io::AsyncReadExt;

use super::machine::{ArtifactHead, DeltaPlan, Head};
use super::source::{Copied, FileSink, PgArtifactSource, RangeSink, ShadowSource, SourceError};
use super::DbKey;
use crate::database_artifacts::{ArtifactPart, ArtifactSink, DatabaseArtifactError, WalMark};
use crate::sql::database::DatabaseHandle;
use crate::sql::service::SqlService;
use crate::sql::store::key::DbRef;
use crate::sql::store::local::{
    hash_prefix, within_pilot_cap, LocalFiles, LocalState, StoreMasterGate, WINDOW_BYTES,
};
use crate::sql::store::Frontier;
use crate::sql::types::SqlError;

/// What one locked read of the working copy found.
struct View {
    state: LocalState,
    cid: String,
}

/// Whether [`LocalFileSource::view`] may rotate and record a WAL mark.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// The upload job's head: rotates a full WAL, records the head's mark.
    Publish,
    /// A recovery scan's head: changes nothing.
    Peek,
}

pub struct LocalFileSource {
    service: SqlService,
    files: Arc<LocalFiles>,
    gate: Arc<dyn StoreMasterGate>,
}

fn key_of(db: &DbRef<'_>) -> DbKey {
    (db.space.to_owned(), db.db_id.to_owned())
}

fn space_of(db: &DbRef<'_>) -> Result<SpaceId, SourceError> {
    db.space
        .parse()
        .map_err(|_| SourceError::Unreadable("the space id is not valid".into()))
}

fn sql_error(error: SqlError) -> SourceError {
    SourceError::Transient(error.to_string())
}

fn io_error(error: std::io::Error) -> SourceError {
    SourceError::Transient(format!("local file: {:?}", error.kind()))
}

fn join_error(error: tokio::task::JoinError) -> SourceError {
    SourceError::Transient(error.to_string())
}

fn sink_failure(error: DatabaseArtifactError) -> SourceError {
    SourceError::Transient(error.to_string())
}

/// Stream `path` into `sink` as the one part `part`.
async fn stream(
    path: &Path,
    part: ArtifactPart,
    sink: &mut dyn ArtifactSink,
) -> Result<(), SourceError> {
    let mut file = tokio::fs::File::open(path).await.map_err(io_error)?;
    sink.begin_part(part).await.map_err(sink_failure)?;
    let mut buffer = vec![0u8; 1 << 20];
    loop {
        let read = file.read(&mut buffer).await.map_err(io_error)?;
        if read == 0 {
            break;
        }
        sink.write(&buffer[..read]).await.map_err(sink_failure)?;
    }
    sink.finish_part().await.map_err(sink_failure)
}

impl LocalFileSource {
    /// `gate` must be the one the service was given.
    pub fn new(service: SqlService, gate: Arc<dyn StoreMasterGate>) -> Self {
        let files = service.local_files();
        Self {
            service,
            files,
            gate,
        }
    }

    /// Whether `db` is store-master. An unreadable mode is an error, never a
    /// guess.
    async fn is_local(&self, db: &DbRef<'_>) -> Result<bool, SourceError> {
        self.gate
            .is_store_master(db)
            .await
            .map_err(|error| SourceError::Transient(error.to_string()))
    }

    /// Read the working copy. The caller holds the operation lock.
    /// `Ok(None)`: no working copy (missing or never initialised): loss or
    /// damage, never created or re-hydrated from here.
    async fn view(
        &self,
        space: &SpaceId,
        db: &DbRef<'_>,
        mode: Mode,
    ) -> Result<Option<(DatabaseHandle, View)>, SourceError> {
        let handle = match self.service.local_handle(space, db.db_id).await {
            Ok(handle) => handle,
            Err(SqlError::Unavailable) => return Ok(None),
            Err(error) => return Err(sql_error(error)),
        };
        let (main, wal) = self.service.local_paths(space, db.db_id);
        let key = key_of(db);
        let mut state = handle.local_state().await.map_err(sql_error)?;
        if !within_pilot_cap(state.main_bytes) {
            return Err(SourceError::TooLarge);
        }
        if mode == Mode::Publish && state.wal_bytes >= WINDOW_BYTES {
            handle.rotate().await.map_err(sql_error)?;
            self.files.invalidate(&key);
            state = handle.local_state().await.map_err(sql_error)?;
            if !within_pilot_cap(state.main_bytes) {
                return Err(SourceError::TooLarge);
            }
        }
        let cid = {
            let (files, key, main) = (self.files.clone(), key.clone(), main);
            tokio::task::spawn_blocking(move || files.checkpoint_cid(&key, &main))
                .await
                .map_err(join_error)?
                .map_err(io_error)?
        };
        if mode == Mode::Publish && state.wal_bytes > 0 {
            let len = state.wal_bytes;
            let sha = tokio::task::spawn_blocking(move || hash_prefix(&wal, len))
                .await
                .map_err(join_error)?
                .map_err(io_error)?
                .ok_or_else(|| SourceError::Transient("the WAL is shorter than reported".into()))?;
            self.files.record_mark(
                &key,
                WalMark {
                    revision: i64::try_from(state.seq)
                        .map_err(|_| SourceError::Unreadable("seq out of range".into()))?,
                    checkpoint_content_hash: cid.clone(),
                    wal_end_bytes: len,
                    wal_prefix_sha256: sha,
                },
            );
        }
        Ok(Some((handle, View { state, cid })))
    }

    /// The working copy is still at `head`: same counter, same checkpoint,
    /// and a WAL to read.
    async fn at_head(
        &self,
        space: &SpaceId,
        db: &DbRef<'_>,
        head: &Head,
    ) -> Result<LocalState, SourceError> {
        let Some((_, view)) = self.view(space, db, Mode::Peek).await? else {
            return Err(SourceError::Gone);
        };
        if i64::try_from(view.state.seq) != Ok(head.revision)
            || view.cid != head.cid
            || view.state.wal_bytes == 0
        {
            return Err(SourceError::MovedOn);
        }
        Ok(view.state)
    }
}

#[async_trait]
impl ShadowSource for LocalFileSource {
    async fn head(&self, db: &DbRef<'_>) -> Result<Option<ArtifactHead>, SourceError> {
        let space = space_of(db)?;
        let _lock = self
            .service
            .lock_local(&space, db.db_id)
            .await
            .map_err(sql_error)?;
        let Some((_, view)) = self.view(&space, db, Mode::Publish).await? else {
            return Ok(None);
        };
        Ok(Some(ArtifactHead {
            revision: i64::try_from(view.state.seq)
                .map_err(|_| SourceError::Unreadable("seq out of range".into()))?,
            cid: view.cid,
            has_delta: view.state.wal_bytes > 0,
            checkpoint_bytes: view.state.main_bytes,
            delta_bytes: view.state.wal_bytes,
        }))
    }

    async fn checkpoint_to(
        &self,
        db: &DbRef<'_>,
        expected_cid: &str,
        file: &mut tokio::fs::File,
    ) -> Result<Copied, SourceError> {
        let space = space_of(db)?;
        let _lock = self
            .service
            .lock_local(&space, db.db_id)
            .await
            .map_err(sql_error)?;
        let Some((_, view)) = self.view(&space, db, Mode::Peek).await? else {
            return Err(SourceError::Gone);
        };
        if view.cid != expected_cid {
            return Err(SourceError::MovedOn);
        }
        let (main, _) = self.service.local_paths(&space, db.db_id);
        let mut sink = FileSink::new(file);
        sink.truncate().await.map_err(super::source::sink_error)?;
        stream(&main, ArtifactPart::Checkpoint, &mut sink).await?;
        let copied = sink.done().await?;
        // The cached hash may not describe these bytes (a file replaced
        // behind it): never publish a checkpoint under a hash it lacks.
        if hex::encode(copied.sha256) != expected_cid {
            self.files.invalidate(&key_of(db));
            return Err(SourceError::MovedOn);
        }
        Ok(copied)
    }

    async fn wal_to(
        &self,
        db: &DbRef<'_>,
        head: &Head,
        file: &mut tokio::fs::File,
    ) -> Result<Copied, SourceError> {
        let space = space_of(db)?;
        let _lock = self
            .service
            .lock_local(&space, db.db_id)
            .await
            .map_err(sql_error)?;
        self.at_head(&space, db, head).await?;
        let (_, wal) = self.service.local_paths(&space, db.db_id);
        let mut sink = FileSink::new(file);
        sink.truncate().await.map_err(super::source::sink_error)?;
        stream(&wal, ArtifactPart::Wal, &mut sink).await?;
        sink.done().await
    }

    async fn wal_marks(
        &self,
        db: &DbRef<'_>,
        revisions: &[i64],
    ) -> Result<Vec<WalMark>, SourceError> {
        Ok(self.files.marks(&key_of(db), revisions))
    }

    async fn wal_delta_to(
        &self,
        db: &DbRef<'_>,
        head: &Head,
        delta: &DeltaPlan,
        file: &mut tokio::fs::File,
    ) -> Result<Option<Copied>, SourceError> {
        let space = space_of(db)?;
        let _lock = self
            .service
            .lock_local(&space, db.db_id)
            .await
            .map_err(sql_error)?;
        self.at_head(&space, db, head).await?;
        let (_, wal) = self.service.local_paths(&space, db.db_id);
        let mut sink = RangeSink::new(file, delta);
        sink.truncate().await.map_err(super::source::sink_error)?;
        stream(&wal, ArtifactPart::Wal, &mut sink).await?;
        sink.done().await
    }

    fn published(&self, db: &DbRef<'_>, frontier: &Frontier) {
        self.files.set_published(
            &key_of(db),
            &frontier.base_checkpoint_cid,
            frontier.last_seq,
        );
    }

    async fn scan_applies(&self, db: &DbRef<'_>) -> bool {
        // An unreadable mode skips the scan: a store-master database read as
        // a Postgres one would be blocked as `regressed` for nothing.
        matches!(self.is_local(db).await, Ok(false))
    }

    async fn local_heads(&self) -> Vec<(DbKey, Head)> {
        let databases = match self.gate.store_master_databases().await {
            Ok(databases) => databases,
            Err(error) => {
                tracing::warn!(%error, "sql_store local source could not list store-master databases");
                return Vec::new();
            }
        };
        let mut heads = Vec::new();
        for key in databases {
            let db = DbRef {
                space: &key.0,
                db_id: &key.1,
            };
            let Ok(space) = space_of(&db) else { continue };
            let Ok(_lock) = self.service.lock_local(&space, db.db_id).await else {
                continue;
            };
            match self.view(&space, &db, Mode::Peek).await {
                Ok(Some((_, view))) => {
                    if let Ok(revision) = i64::try_from(view.state.seq) {
                        heads.push((
                            key.clone(),
                            Head {
                                revision,
                                cid: view.cid,
                            },
                        ));
                    }
                }
                Ok(None) => {
                    tracing::error!("sql_store: a store-master database has no working copy");
                }
                Err(error) => {
                    tracing::warn!(%error, "sql_store local source could not read a working copy");
                }
            }
        }
        heads
    }
}

/// Reads store-master databases from their local files and every other
/// database from Postgres, by the mode row.
pub struct RoutedSource {
    pg: PgArtifactSource,
    local: LocalFileSource,
}

impl RoutedSource {
    pub fn new(pg: PgArtifactSource, local: LocalFileSource) -> Self {
        Self { pg, local }
    }
}

#[async_trait]
impl ShadowSource for RoutedSource {
    async fn head(&self, db: &DbRef<'_>) -> Result<Option<ArtifactHead>, SourceError> {
        if self.local.is_local(db).await? {
            self.local.head(db).await
        } else {
            self.pg.head(db).await
        }
    }

    async fn checkpoint_to(
        &self,
        db: &DbRef<'_>,
        expected_cid: &str,
        file: &mut tokio::fs::File,
    ) -> Result<Copied, SourceError> {
        if self.local.is_local(db).await? {
            self.local.checkpoint_to(db, expected_cid, file).await
        } else {
            self.pg.checkpoint_to(db, expected_cid, file).await
        }
    }

    async fn wal_to(
        &self,
        db: &DbRef<'_>,
        head: &Head,
        file: &mut tokio::fs::File,
    ) -> Result<Copied, SourceError> {
        if self.local.is_local(db).await? {
            self.local.wal_to(db, head, file).await
        } else {
            self.pg.wal_to(db, head, file).await
        }
    }

    async fn wal_marks(
        &self,
        db: &DbRef<'_>,
        revisions: &[i64],
    ) -> Result<Vec<WalMark>, SourceError> {
        if self.local.is_local(db).await? {
            self.local.wal_marks(db, revisions).await
        } else {
            self.pg.wal_marks(db, revisions).await
        }
    }

    async fn wal_delta_to(
        &self,
        db: &DbRef<'_>,
        head: &Head,
        delta: &DeltaPlan,
        file: &mut tokio::fs::File,
    ) -> Result<Option<Copied>, SourceError> {
        if self.local.is_local(db).await? {
            self.local.wal_delta_to(db, head, delta, file).await
        } else {
            self.pg.wal_delta_to(db, head, delta, file).await
        }
    }

    fn published(&self, db: &DbRef<'_>, frontier: &Frontier) {
        self.local.published(db, frontier);
    }

    async fn scan_applies(&self, db: &DbRef<'_>) -> bool {
        self.local.scan_applies(db).await
    }

    async fn local_heads(&self) -> Vec<(DbKey, Head)> {
        self.local.local_heads().await
    }
}

#[cfg(test)]
mod tests;
