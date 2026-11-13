//! Authenticated local retirement provenance. Raw bodies never enter the ledger.
//! This module grants no decrypt authority without the normal graph classifier.
use crate::{
    models::{
        resource_retirement_snapshot as stored, space_purge_fence as fence, space_retirement,
    },
    resource_purge_dependencies::ResourceDependencySnapshot,
    resource_purge_fence::ResourceTarget,
    space_purge_ledger::{LedgerKeys, LedgerRecord, RetirementSnapshotCommitment},
};
use sea_orm::{ActiveModelTrait, ActiveValue::Set, DatabaseTransaction, DbErr, EntityTrait};

fn refused() -> DbErr {
    DbErr::Custom("retirement snapshot unavailable or unverifiable".into())
}

pub struct AuthenticatedRetirementSnapshot {
    snapshot: ResourceDependencySnapshot,
    retirement_id: String,
    key_id: String,
    commitment: Vec<u8>,
}
impl AuthenticatedRetirementSnapshot {
    pub fn target(&self) -> &ResourceTarget {
        self.snapshot.target()
    }
    pub fn retirement_id(&self) -> &str {
        &self.retirement_id
    }
    pub fn hmac_key_id(&self) -> &str {
        &self.key_id
    }
    pub fn commitment(&self) -> &[u8] {
        &self.commitment
    }
    pub fn snapshot(&self) -> &ResourceDependencySnapshot {
        &self.snapshot
    }
}

/// Prepared only from the collector's canonical snapshot; persistence must be
/// in the same transaction as the retirement fence and its signed ledger copy.
pub struct PreparedSnapshot {
    row: stored::Model,
    manifest: RetirementSnapshotCommitment,
}
impl PreparedSnapshot {
    pub fn commitment(&self) -> &RetirementSnapshotCommitment {
        &self.manifest
    }
    pub async fn persist(
        self,
        tx: &DatabaseTransaction,
        keys: &LedgerKeys,
        record: &LedgerRecord,
    ) -> Result<(), DbErr> {
        let verified = keys
            .verify(
                &record.object_key().map_err(|_| refused())?,
                &record.to_bytes().map_err(|_| refused())?,
            )
            .map_err(|_| refused())?;
        if verified.version != 3
            || verified.kind != "owner"
            || verified.state != "retired"
            || verified.operation_id != self.row.retirement_id
            || verified.key_id != self.row.hmac_key_id
            || !verified.retirement_snapshots.contains(&self.manifest)
        {
            return Err(refused());
        }
        // Re-parse and authenticate at write time too, rather than trusting a
        // data wrapper merely because it was constructed earlier.
        let target = ResourceTarget::parse(
            &serde_json::from_slice::<serde_json::Value>(self.row.snapshot_body.as_bytes())
                .map_err(|_| refused())?[0]
                .as_str()
                .ok_or_else(refused)?
                .to_owned(),
        )
        .map_err(|_| refused())?;
        let snapshot =
            ResourceDependencySnapshot::from_db_bytes(&target, self.row.snapshot_body.as_bytes())
                .map_err(|_| refused())?;
        let rebuilt = prepare(keys, &verified.key_id, &verified.operation_id, &snapshot)?;
        if self.row != rebuilt.row
            || self.manifest != rebuilt.manifest
            || hex::encode(
                keys.target_hmac(&verified.key_id, "owner", target.owner_did())
                    .map_err(|_| refused())?,
            ) != verified.target_hmac
        {
            return Err(refused());
        }
        let id = (
            self.row.retirement_id.clone(),
            self.row.hmac_key_id.clone(),
            self.row.target_hmac.clone(),
        );
        if let Some(existing) = stored::Entity::find_by_id(id).one(tx).await? {
            if existing != self.row {
                return Err(refused());
            }
            return Ok(());
        }
        stored::ActiveModel {
            retirement_id: Set(self.row.retirement_id),
            hmac_key_id: Set(self.row.hmac_key_id),
            target_hmac: Set(self.row.target_hmac),
            network_hmac: Set(self.row.network_hmac),
            snapshot_body: Set(self.row.snapshot_body),
            snapshot_commitment: Set(self.row.snapshot_commitment),
        }
        .insert(tx)
        .await?;
        Ok(())
    }
}

pub fn prepare(
    keys: &LedgerKeys,
    key_id: &str,
    retirement_id: &str,
    snapshot: &ResourceDependencySnapshot,
) -> Result<PreparedSnapshot, DbErr> {
    let body = snapshot.to_db_bytes().map_err(|_| refused())?;
    let checked = ResourceDependencySnapshot::from_db_bytes(snapshot.target(), &body)
        .map_err(|_| refused())?;
    if checked.to_db_bytes().map_err(|_| refused())? != body {
        return Err(refused());
    }
    let target_hmac = keys
        .target_hmac(key_id, "resource", snapshot.target().as_str())
        .map_err(|_| refused())?;
    let network_hmac = keys
        .target_hmac(key_id, "resource", snapshot.target().network_id())
        .map_err(|_| refused())?;
    let snapshot_hmac = keys
        .retirement_snapshot_hmac(key_id, retirement_id, &body)
        .map_err(|_| refused())?;
    let manifest = RetirementSnapshotCommitment {
        target_hmac: hex::encode(&target_hmac),
        network_hmac: hex::encode(&network_hmac),
        snapshot_hmac: hex::encode(&snapshot_hmac),
    };
    Ok(PreparedSnapshot {
        row: stored::Model {
            retirement_id: retirement_id.into(),
            hmac_key_id: key_id.into(),
            target_hmac,
            network_hmac,
            snapshot_body: stored::SnapshotBody::new(body),
            snapshot_commitment: snapshot_hmac,
        },
        manifest,
    })
}

/// A ledger-authenticated manifest plus the matching original local retirement,
/// durable fence and canonical relationship row are all required. Missing local
/// provenance after restore cannot manufacture an outside-reader exception.
pub async fn load_authenticated(
    conn: &DatabaseTransaction,
    keys: &LedgerKeys,
    record: &LedgerRecord,
    target: &ResourceTarget,
) -> Result<AuthenticatedRetirementSnapshot, DbErr> {
    let verified = keys
        .verify(
            &record.object_key().map_err(|_| refused())?,
            &record.to_bytes().map_err(|_| refused())?,
        )
        .map_err(|_| refused())?;
    let owner_hmac = keys
        .target_hmac(&verified.key_id, "owner", target.owner_did())
        .map_err(|_| refused())?;
    if verified.version != 3
        || verified.kind != "owner"
        || verified.state != "retired"
        || verified.target_hmac != hex::encode(&owner_hmac)
    {
        return Err(refused());
    }
    let retirement =
        space_retirement::Entity::find_by_id((owner_hmac.clone(), verified.key_id.clone()))
            .one(conn)
            .await?
            .ok_or_else(refused)?;
    let state = fence::Entity::find_by_id(("owner".into(), owner_hmac, verified.key_id.clone()))
        .one(conn)
        .await?
        .ok_or_else(refused)?;
    if retirement.retirement_id != verified.operation_id
        || retirement.accepted_at.unix_timestamp() != verified.timestamp
        || !state.fenced
        || state.generation <= 0
    {
        return Err(refused());
    }
    let target_hmac = keys
        .target_hmac(&verified.key_id, "resource", target.as_str())
        .map_err(|_| refused())?;
    let row = stored::Entity::find_by_id((
        verified.operation_id.clone(),
        verified.key_id.clone(),
        target_hmac,
    ))
    .one(conn)
    .await?
    .ok_or_else(refused)?;
    let snapshot = ResourceDependencySnapshot::from_db_bytes(target, row.snapshot_body.as_bytes())
        .map_err(|_| refused())?;
    let expected = prepare(keys, &verified.key_id, &verified.operation_id, &snapshot)?;
    if row != expected.row || !verified.retirement_snapshots.contains(&expected.manifest) {
        return Err(refused());
    }
    Ok(AuthenticatedRetirementSnapshot {
        snapshot,
        retirement_id: verified.operation_id,
        key_id: verified.key_id,
        commitment: row.snapshot_commitment,
    })
}
