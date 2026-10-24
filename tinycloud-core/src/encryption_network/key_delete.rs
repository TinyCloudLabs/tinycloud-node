//! `key.delete`: the effect of an owner-signed delete on key rows.
//!
//! One transaction, taken under the network row lock that `key.create`,
//! `key.block` and `key.unblock` also take. The delete's intent is appended
//! to the deletion ledger before the transaction commits and settled after it,
//! so the ledger always names every committed deletion.

use sea_orm::{
    sea_query::{Alias, Expr, Func, SimpleExpr},
    ActiveModelTrait,
    ActiveValue::Set,
    ColumnTrait, DatabaseTransaction, EntityTrait, QueryFilter, QueryOrder,
};

use crate::{
    db::begin_write_transaction,
    models::{encryption_audit, encryption_network, encryption_network_key},
};

use super::{
    canonical::hash_hex,
    delete_auth::{DeleteTarget, VerifiedOwnerDelete},
    deletion_ledger::{intent_committed, DeletionLedger, Intent, LedgerKey, Record},
    key_id::KeyKind,
    keys::{find_key_row, lock_network_row, KeyState},
    network_id::NetworkId,
    service::{now_rfc3339, EncryptionService, EncryptionServiceError},
};

/// Audit outcome of a deleted key.
pub const AUDIT_OUTCOME_DELETED: &str = "deleted";

/// The keys a delete touched, ordered by path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeleteOutcome {
    /// The body `keyPath` (a prefix keeps its trailing `/`).
    pub key_path: String,
    /// Keys this call moved to `deleted`.
    pub deleted: Vec<String>,
    /// Keys that were already `deleted` and hold no seed.
    pub already_deleted: Vec<String>,
}

impl EncryptionService {
    /// Deletes one key or every key under `apps/<app id>/`. The caller has
    /// verified the owner credential and consumed its nonce.
    ///
    /// All or nothing: a selected row that is not a deletable key aborts the
    /// call with no writes (`key_not_deletable`). A deleted row keeps its
    /// path; its seed is NULL and its state `deleted`. Zero matching rows is
    /// an empty outcome; a retry changes nothing.
    pub async fn delete_keys(
        &self,
        network: &NetworkId,
        target: &DeleteTarget,
        verified: &VerifiedOwnerDelete,
    ) -> Result<DeleteOutcome, EncryptionServiceError> {
        if !target.is_prefix() && target.location().kind() != KeyKind::Deletable {
            return Err(EncryptionServiceError::KeyNotDeletable);
        }
        let ledger = self.deletion_ledger.clone().ok_or_else(|| {
            EncryptionServiceError::DeletionLedger("no deletion ledger is configured".to_string())
        })?;
        let _writer = match &self.sqlite_writer_lock {
            Some(lock) => Some(lock.lock().await),
            None => None,
        };
        let tx = begin_write_transaction(&self.db, None).await?;
        // Every outcome ends the transaction here, so the network row lock is
        // released before this call returns.
        let result = self
            .delete_keys_in(&tx, network, target, verified, &ledger)
            .await;
        let (outcome, intent) = match result {
            Ok(done) => done,
            Err(err) => {
                let _ = tx.rollback().await;
                return Err(err);
            }
        };
        if let Err(err) = self.commit_delete(tx).await {
            // PostgreSQL can commit and then lose the reply, so the answer to
            // "did it commit" comes from the rows, not from this error.
            self.settle_after_commit_error(&ledger, intent.as_ref())
                .await;
            return Err(err.into());
        }
        if let Some(intent) = intent {
            // A missing `committed` line is settled from the database at the
            // next start, so a failure here does not undo the delete.
            if let Err(error) = ledger.append_async(Record::committed(&intent.op)).await {
                ::tracing::warn!(%error, "deletion ledger: committed line was not written");
            }
        }
        Ok(outcome)
    }

    /// Commits the delete's transaction. Tests can make it fail before the
    /// commit (rolled back) or after it (committed, reply lost).
    async fn commit_delete(&self, tx: DatabaseTransaction) -> Result<(), sea_orm::DbErr> {
        #[cfg(test)]
        {
            use std::sync::atomic::Ordering::SeqCst;
            if self.delete_faults.fail_before_commit.swap(false, SeqCst) {
                tx.rollback().await?;
                return Err(sea_orm::DbErr::Custom(
                    "injected failure before the commit".to_string(),
                ));
            }
            if self.delete_faults.lose_commit_reply.swap(false, SeqCst) {
                tx.commit().await?;
                return Err(sea_orm::DbErr::Custom(
                    "injected loss of the commit reply".to_string(),
                ));
            }
        }
        tx.commit().await
    }

    async fn delete_keys_in(
        &self,
        tx: &DatabaseTransaction,
        network: &NetworkId,
        target: &DeleteTarget,
        verified: &VerifiedOwnerDelete,
        ledger: &std::sync::Arc<DeletionLedger>,
    ) -> Result<(DeleteOutcome, Option<Intent>), EncryptionServiceError> {
        // Serializes this delete with create, block and unblock on the network.
        // The guarded updates (the key version must still match) keep each
        // row's write correct without it; the lock is defense in depth.
        lock_network_row(tx, network).await?;
        if encryption_network::Entity::find_by_id(network.to_string())
            .one(tx)
            .await?
            .is_none()
        {
            return Err(EncryptionServiceError::NetworkNotFound);
        }

        let mut rows = if target.is_prefix() {
            rows_under_prefix(tx, network, &target.key_path()).await?
        } else {
            vec![find_key_row(tx, network, target.location().path())
                .await?
                .ok_or(EncryptionServiceError::KeyNotFound)?]
        };
        rows.sort_by(|a, b| a.key_path.cmp(&b.key_path));

        // Every selected row is read before anything is written.
        let mut to_delete = Vec::new();
        let mut already_deleted = Vec::new();
        for row in rows {
            match KeyKind::parse(&row.kind) {
                Some(KeyKind::Deletable) => {}
                Some(KeyKind::Deterministic) => {
                    return Err(EncryptionServiceError::KeyNotDeletable)
                }
                None => return Err(EncryptionServiceError::CorruptKeyRow),
            }
            if KeyState::parse(&row.state)? == KeyState::Deleted && row.sealed_seed.is_none() {
                already_deleted.push(row.key_path);
            } else {
                to_delete.push(row);
            }
        }

        let now = now_rfc3339();
        let mut deleted = Vec::with_capacity(to_delete.len());
        let mut ledger_keys = Vec::with_capacity(to_delete.len());
        for row in to_delete {
            let updated = encryption_network_key::Entity::update_many()
                .col_expr(
                    encryption_network_key::Column::State,
                    Expr::value(KeyState::Deleted.as_str()),
                )
                .col_expr(
                    encryption_network_key::Column::SealedSeed,
                    Expr::value(Option::<Vec<u8>>::None),
                )
                .col_expr(
                    encryption_network_key::Column::UpdatedAt,
                    Expr::value(now.clone()),
                )
                .filter(encryption_network_key::Column::NetworkId.eq(network.to_string()))
                .filter(encryption_network_key::Column::KeyPath.eq(row.key_path.clone()))
                .filter(encryption_network_key::Column::KeyVersion.eq(row.key_version))
                .exec(tx)
                .await?;
            if updated.rows_affected != 1 {
                return Err(EncryptionServiceError::CorruptKeyRow);
            }
            encryption_audit::ActiveModel {
                request_hash: Set(audit_request_hash(&verified.auth_cid, &row.key_path)),
                requester: Set(verified.owner.clone()),
                network_id: Set(network.to_string()),
                node_id: Set(self.node_did.clone()),
                outcome: Set(AUDIT_OUTCOME_DELETED.to_string()),
                decided_at: Set(now.clone()),
                key_path: Set(Some(row.key_path.clone())),
            }
            .insert(tx)
            .await?;
            ledger_keys.push(LedgerKey {
                key_path: row.key_path.clone(),
                key_version: row.key_version,
            });
            deleted.push(row.key_path);
        }

        // The intent is durable before the commit: a crash after this point
        // leaves an open intent that the next start settles against the
        // database, so the ledger always names every committed deletion.
        let intent = if ledger_keys.is_empty() {
            None
        } else {
            let intent = Intent {
                op: verified.auth_cid.clone(),
                network_id: network.to_string(),
                keys: ledger_keys,
                deleted_at: now,
            };
            ledger.append_async(Record::Intent(intent.clone())).await?;
            Some(intent)
        };

        Ok((
            DeleteOutcome {
                key_path: target.key_path(),
                deleted,
                already_deleted,
            },
            intent,
        ))
    }

    /// After a failed commit: reads the rows again, through the pool and not
    /// the failed connection, and appends `committed` when every key is
    /// deleted at its version and `aborted` when the commit did not happen.
    /// When the rows cannot be read the intent stays open, and the next start
    /// settles it.
    async fn settle_after_commit_error(
        &self,
        ledger: &std::sync::Arc<DeletionLedger>,
        intent: Option<&Intent>,
    ) {
        let Some(intent) = intent else { return };
        let verdict = self.reread_committed(intent).await;
        let record = match verdict {
            Ok(true) => Record::committed(&intent.op),
            Ok(false) => Record::aborted(&intent.op),
            Err(error) => {
                ::tracing::warn!(%error, "deletion ledger: could not tell whether a delete committed; the operation stays open");
                return;
            }
        };
        if let Err(error) = ledger.append_async(record).await {
            ::tracing::warn!(%error, "deletion ledger: the settling line was not written");
        }
    }

    async fn reread_committed(&self, intent: &Intent) -> Result<bool, sea_orm::DbErr> {
        #[cfg(test)]
        if self
            .delete_faults
            .fail_reread
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            return Err(sea_orm::DbErr::Custom("injected read failure".to_string()));
        }
        intent_committed(&self.db, intent).await
    }
}

/// Switches for tests to make a delete fail around its commit.
#[cfg(test)]
#[derive(Default)]
pub(super) struct DeleteFaults {
    pub(super) fail_before_commit: std::sync::atomic::AtomicBool,
    pub(super) lose_commit_reply: std::sync::atomic::AtomicBool,
    pub(super) fail_reread: std::sync::atomic::AtomicBool,
}

/// `sha256(auth CID || 0x00 || key path)`, hex. The audit table's primary key.
pub fn audit_request_hash(auth_cid: &str, key_path: &str) -> String {
    let mut input = Vec::with_capacity(auth_cid.len() + 1 + key_path.len());
    input.extend_from_slice(auth_cid.as_bytes());
    input.push(0);
    input.extend_from_slice(key_path.as_bytes());
    hash_hex(&input)
}

/// The rows whose path starts with `prefix`, selected by a byte-exact
/// `substr` comparison. Never `LIKE` (it treats `_` and `%` as wildcards, and
/// SQLite's ignores case) and never a range (collation dependent). Each row
/// is checked again here in Rust.
async fn rows_under_prefix(
    tx: &DatabaseTransaction,
    network: &NetworkId,
    prefix: &str,
) -> Result<Vec<encryption_network_key::Model>, EncryptionServiceError> {
    let rows = encryption_network_key::Entity::find()
        .filter(encryption_network_key::Column::NetworkId.eq(network.to_string()))
        // `substr(key_path, 1, n) = prefix`: an exact comparison of the
        // first n characters, the same SQL on SQLite and PostgreSQL.
        .filter(
            Expr::expr(Func::cust(Alias::new("substr")).args([
                Expr::col(encryption_network_key::Column::KeyPath).into(),
                SimpleExpr::from(1i32),
                SimpleExpr::from(prefix.len() as i32),
            ]))
            .eq(prefix.to_string()),
        )
        .order_by_asc(encryption_network_key::Column::KeyPath)
        .all(tx)
        .await?;
    let network_id = network.to_string();
    if rows.iter().any(|row| {
        row.network_id != network_id
            || !row.key_path.starts_with(prefix)
            || row.key_path.len() <= prefix.len()
    }) {
        // Over-selection must never reach an update.
        return Err(EncryptionServiceError::CorruptKeyRow);
    }
    Ok(rows)
}
