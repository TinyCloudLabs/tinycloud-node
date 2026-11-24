//! The store-master half of [`SqlService`] (TC-1491 P4.2a, design 5.3 and 12).
//!
//! Everything here runs only for a database whose mode the
//! [`StoreMasterGate`] reports as `store_master`. With no gate (the default,
//! and the only state the node runtime builds today) none of it is reached and
//! every database is served exactly as before.
//!
//! A store-master database is never hydrated from, saved to or seeded by
//! Postgres. Its working copy is the local file; a missing or uninitialised
//! file is `Unavailable` (loss or damage), never a reason to create or
//! re-hydrate one. A failed COMMIT never discards the local state either: the
//! frames may be in the WAL (see `commit_error`). The outcome-unknown handling
//! and `quick_check` of design 5.2 are P4.2's.

use std::path::PathBuf;
use std::sync::Arc;

use tinycloud_auth::resource::SpaceId;
use tokio::sync::OwnedMutexGuard;

use super::{begin_write, sql_wal_path, ReservationGuard, SqlService};
use crate::sql::database::{spawn_store_master_actor, DatabaseHandle, GrowthPolicy};
use crate::sql::store::key::DbRef;
use crate::sql::store::local::{
    validate_working_copy, LocalFiles, StoreMasterGate, WAL_BACKSTOP_BYTES,
};
use crate::sql::store::shadow::LocalNotice;
use crate::sql::types::{SqlError, SqlExecutionResult, SqlRequest};
use crate::sql::{authority::SqlAuthority, caveats::SqlCaveats};

impl SqlService {
    /// Tell the service which databases are store-master (TC-1491 P4.2a).
    /// Not called by the node runtime yet: cutover (P4.4) wires it.
    pub fn with_store_master_gate(mut self, gate: Arc<dyn StoreMasterGate>) -> Self {
        self.store_gate = Some(gate);
        self
    }

    /// What this service knows about its local working copies; shared with
    /// the local-file source.
    pub fn local_files(&self) -> Arc<LocalFiles> {
        self.local.clone()
    }

    /// Whether the mode row says `store_master`.
    ///
    /// A mode that cannot be read never makes the node guess. But the failure
    /// is scoped to the database asked about: one with a live actor is served
    /// in the mode its actor was opened in (a mode change replaces the actor
    /// under the operation lock), so a control-database blip does not stop
    /// every database that is already warm. Only a database with no actor,
    /// which would have to be hydrated or opened without knowing its mode, is
    /// refused (retryable).
    pub(super) async fn is_store_master(
        &self,
        space: &SpaceId,
        db_name: &str,
    ) -> Result<bool, SqlError> {
        let Some(gate) = &self.store_gate else {
            return Ok(false);
        };
        let space_text = space.to_string();
        match gate
            .is_store_master(&DbRef {
                space: &space_text,
                db_id: db_name,
            })
            .await
        {
            Ok(mode) => Ok(mode),
            Err(error) => {
                let key = (space_text, db_name.to_string());
                match self.databases.get(&key).map(|h| h.is_store_master()) {
                    Some(mode) => {
                        tracing::warn!(
                            %error,
                            "sql store mode unreadable; serving the live actor in its own mode"
                        );
                        Ok(mode)
                    }
                    None => {
                        tracing::warn!(%error, "sql store mode unreadable; refusing the request");
                        Err(SqlError::Unavailable)
                    }
                }
            }
        }
    }

    /// The main file and the WAL of a working copy.
    pub(crate) fn local_paths(&self, space: &SpaceId, db_name: &str) -> (PathBuf, PathBuf) {
        let main = self.cache_path(space, db_name);
        let wal = sql_wal_path(&main);
        (main, wal)
    }

    /// The per-database operation lock, for the local-file source. The source
    /// holds it while it reads the files and drops it before any store call.
    pub(crate) async fn lock_local(
        &self,
        space: &SpaceId,
        db_name: &str,
    ) -> Result<OwnedMutexGuard<()>, SqlError> {
        self.acquire_operation(space, db_name).await
    }

    /// The actor of a store-master working copy, started on the existing
    /// local file. Never creates, hydrates or seeds the file. The caller
    /// holds the operation lock.
    pub(crate) async fn local_handle(
        &self,
        space: &SpaceId,
        db_name: &str,
    ) -> Result<DatabaseHandle, SqlError> {
        let key = (space.to_string(), db_name.to_string());
        let mut replaced = false;
        if let Some(handle) = self.databases.get(&key).map(|h| h.clone()) {
            if handle.is_store_master() {
                return Ok(handle);
            }
            // An actor opened while Postgres was master. Its files stay; it
            // is replaced by one that does not checkpoint on close. Its own
            // close does checkpoint, folding the WAL into the main file with
            // no seq bump: the settle below makes the next store-master seq
            // account for that change.
            self.databases.remove(&key);
            self.lineage.remove(&key);
            handle.shutdown().await?;
            replaced = true;
        }
        let (main, _) = self.local_paths(space, db_name);
        // The counter must be there: a file without it was never cut over.
        tokio::task::spawn_blocking(move || validate_working_copy(&main))
            .await
            .map_err(|error| SqlError::Internal(error.to_string()))??;
        let handle = self
            .databases
            .entry(key.clone())
            .or_insert_with(|| {
                spawn_store_master_actor(
                    space.to_string(),
                    db_name.to_string(),
                    self.base_path.clone(),
                    self.databases.clone(),
                    self.durability.clone(),
                )
            })
            .clone();
        if replaced {
            // The previous actor's close changed the main file at an
            // unchanged seq, which the uploader would read as a foreign write
            // (cid_conflict). A rotation bumps the seq and truncates the WAL
            // in one step, so the file and the counter move together. If it
            // fails the request fails; the next write's bump gives the file a
            // new seq anyway, so this self-heals, loudly, rather than
            // publishing a wrong lineage.
            self.local.invalidate(&key);
            handle.rotate().await?;
            self.local.invalidate(&key);
        }
        Ok(handle)
    }

    /// An execute on a store-master working copy, under the operation lock.
    /// No Postgres: no hydration, no checkpoint back-off, no durable save.
    pub(super) async fn execute_store_master(
        &self,
        space: &SpaceId,
        db_name: &str,
        request: SqlRequest,
        caveats: Option<SqlCaveats>,
        authority: SqlAuthority,
        growth: GrowthPolicy,
    ) -> Result<SqlExecutionResult, SqlError> {
        let key = (space.to_string(), db_name.to_string());
        let _reservation = ReservationGuard::new(
            self.durability.budget.clone(),
            format!("{}/{}", key.0, key.1),
        );
        let mut handle = self.local_handle(space, db_name).await?;
        begin_write()?;
        let result = match handle
            .execute_authorized(request.clone(), caveats.clone(), authority.clone(), growth)
            .await
        {
            Err(SqlError::Internal(msg)) if msg.contains("Database actor not available") => {
                tracing::warn!("Dead SQL actor detected, respawning");
                self.databases.remove(&key);
                handle = self.local_handle(space, db_name).await?;
                handle
                    .execute_authorized(request, caveats, authority, growth)
                    .await
            }
            other => other,
        }?;
        if !result.write_targets.is_empty() {
            self.after_local_commit(space, db_name, &handle).await;
        }
        Ok(result)
    }

    /// Tell the uploader a write committed. Never fails the request: the
    /// write is durable locally, and a missed notice is found again by the
    /// uploader's recovery scan.
    async fn after_local_commit(&self, space: &SpaceId, db_name: &str, handle: &DatabaseHandle) {
        let mut state = match handle.local_state().await {
            Ok(state) => state,
            Err(error) => {
                tracing::warn!(%error, "store-master commit: local state unreadable");
                return;
            }
        };
        // The backstop for a database the uploader does not serve (not
        // allowlisted, over the cap): fold the WAL in and truncate it here,
        // under the operation lock this request still holds, before it grows
        // to the write refusal.
        if state.wal_bytes >= WAL_BACKSTOP_BYTES {
            let key = (space.to_string(), db_name.to_string());
            match handle.rotate().await {
                Ok(()) => {
                    self.local.invalidate(&key);
                    match handle.local_state().await {
                        Ok(after) => state = after,
                        Err(error) => {
                            tracing::warn!(%error, "store-master backstop: local state unreadable");
                            return;
                        }
                    }
                }
                Err(error) => {
                    tracing::warn!(%error, "store-master backstop rotation failed");
                }
            }
        }
        let key = (space.to_string(), db_name.to_string());
        let (main, _) = self.local_paths(space, db_name);
        let files = self.local.clone();
        let hash_key = key.clone();
        let cid = match tokio::task::spawn_blocking(move || files.checkpoint_cid(&hash_key, &main))
            .await
        {
            Ok(Ok(cid)) => cid,
            _ => {
                tracing::warn!("store-master commit: checkpoint hash unreadable");
                return;
            }
        };
        let Ok(seq) = i64::try_from(state.seq) else {
            return;
        };
        let ahead_bytes = self
            .local
            .ahead_bytes(&key, &cid, state.wal_bytes, state.main_bytes);
        self.shadow.notify_local(LocalNotice {
            space: key.0,
            db_id: key.1,
            seq,
            cid,
            ahead_bytes,
        });
    }
}

#[cfg(test)]
mod tests;
