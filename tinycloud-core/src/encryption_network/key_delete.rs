//! `key.delete`: the effect of an owner-signed delete on key rows.
//!
//! One transaction, taken under the network row lock that `key.create`,
//! `key.block` and `key.unblock` also take. The delete's intent is appended
//! to the deletion ledger before the transaction commits and settled after it,
//! so the ledger always names every committed deletion.

use sea_orm::{
    sea_query::Expr, ActiveModelTrait, ActiveValue::Set, ColumnTrait, DatabaseTransaction,
    EntityTrait, QueryFilter, QueryOrder, Value,
};

use crate::{
    db::begin_write_transaction,
    models::{encryption_audit, encryption_network, encryption_network_key},
};

use super::{
    canonical::hash_hex,
    delete_auth::{DeleteTarget, VerifiedOwnerDelete},
    deletion_ledger::{DeletionLedger, Intent, LedgerKey, Record},
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
        let (outcome, op) = match result {
            Ok(done) => done,
            Err(err) => {
                let _ = tx.rollback().await;
                return Err(err);
            }
        };
        #[cfg(test)]
        if self
            .fail_next_delete_commit
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            let _ = tx.rollback().await;
            self.settle_aborted(&ledger, op.as_deref()).await;
            return Err(EncryptionServiceError::Db(sea_orm::DbErr::Custom(
                "injected commit failure".to_string(),
            )));
        }
        if let Err(err) = tx.commit().await {
            // The commit did not happen: say so before answering.
            self.settle_aborted(&ledger, op.as_deref()).await;
            return Err(err.into());
        }
        if let Some(op) = op {
            // A missing `committed` line is settled from the database at the
            // next start, so a failure here does not undo the delete.
            if ledger.append_async(Record::committed(&op)).await.is_err() {
                ::tracing::warn!("deletion ledger: committed line was not written");
            }
        }
        Ok(outcome)
    }

    async fn delete_keys_in(
        &self,
        tx: &DatabaseTransaction,
        network: &NetworkId,
        target: &DeleteTarget,
        verified: &VerifiedOwnerDelete,
        ledger: &std::sync::Arc<DeletionLedger>,
    ) -> Result<(DeleteOutcome, Option<String>), EncryptionServiceError> {
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
        let op = if ledger_keys.is_empty() {
            None
        } else {
            ledger
                .append_async(Record::Intent(Intent {
                    op: verified.auth_cid.clone(),
                    network_id: network.to_string(),
                    keys: ledger_keys,
                    deleted_at: now,
                }))
                .await?;
            Some(verified.auth_cid.clone())
        };

        Ok((
            DeleteOutcome {
                key_path: target.key_path(),
                deleted,
                already_deleted,
            },
            op,
        ))
    }

    /// Appends `aborted` for an operation whose commit did not happen. A
    /// failure here is settled from the database at the next start.
    async fn settle_aborted(&self, ledger: &std::sync::Arc<DeletionLedger>, op: Option<&str>) {
        if let Some(op) = op {
            if ledger.append_async(Record::aborted(op)).await.is_err() {
                ::tracing::warn!("deletion ledger: aborted line was not written");
            }
        }
    }
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
        .filter(Expr::cust_with_values(
            "substr(key_path, 1, ?) = ?",
            [
                Value::Int(Some(prefix.len() as i32)),
                Value::String(Some(Box::new(prefix.to_string()))),
            ],
        ))
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
