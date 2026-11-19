//! Exact-space database leaves. Signed-record roots are handled at completion.
use crate::space_purge_worker::{renew, ClaimedPurge};
use sea_orm::{ConnectionTrait, DatabaseBackend, DatabaseTransaction, DbErr, Statement};

/// Where a space purge erases a table's rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PurgePhase {
    /// [`delete_sql_and_hook_rows`], committed with the database→access advance.
    Database,
    /// Bounded [`reap_artifact_parts`] batches, then
    /// [`delete_verified_empty_inventory`] in the terminal transaction.
    Objects,
    /// Terminal transaction: `space_purge_records::complete_space` and the
    /// `space` row in `space_purge_worker::complete_with_encryption`.
    Completion,
}

// Every table with a column naming a space or an owner (see the
// `space_purge_table_inventory` test) is in exactly one of the three lists
// below. The test fails on an unlisted table, so a new table cannot silently
// outlive the purge of the space it names. Not listed because no column names
// a space: hook_delivery (deleted through its subscription), the HMAC-keyed
// lifecycle tables (space_purge_*, space_retirement, resource_*), policy and
// share projections without identity columns.

/// Rows deleted by the exact space identifier.
pub const PURGED_BY_SPACE: &[(&str, PurgePhase)] = &[
    ("hook_subscription", PurgePhase::Database),
    ("signed_kv_ticket", PurgePhase::Database),
    ("database_artifact", PurgePhase::Database),
    ("database_alias", PurgePhase::Database),
    ("database_legacy_artifact", PurgePhase::Database),
    ("meeting_legacy_write_guard", PurgePhase::Database),
    ("sql_database", PurgePhase::Database),
    ("kv_orphan_attempt", PurgePhase::Objects),
    ("kv_orphan_candidate", PurgePhase::Objects),
    ("kv_blob_generation", PurgePhase::Objects),
    ("sql_store_object", PurgePhase::Objects),
    ("sql_store_manifest", PurgePhase::Objects),
    ("artifact_chunk", PurgePhase::Objects),
    ("artifact_part", PurgePhase::Objects),
    ("artifact_space_owner", PurgePhase::Objects),
    ("current_kv", PurgePhase::Completion),
    ("kv_delete", PurgePhase::Completion),
    ("kv_write", PurgePhase::Completion),
    ("event_order", PurgePhase::Completion),
    ("epoch_order", PurgePhase::Completion),
    ("epoch_head", PurgePhase::Completion),
    ("epoch", PurgePhase::Completion),
    ("ability", PurgePhase::Completion),
    ("invoked_abilities", PurgePhase::Completion),
    ("space", PurgePhase::Completion),
];

/// Rows keyed by the owner, deleted only when the purge leaves that owner with
/// no live space on this node: `artifact_account` in
/// [`delete_verified_empty_inventory`], the encryption-network rows in
/// [`delete_owner_encryption_networks`].
pub const PURGED_BY_OWNER: &[&str] = &[
    "artifact_account",
    "encryption_network",
    "encryption_network_key",
    "encryption_network_member",
    "encryption_ceremony",
];

/// Tables a space purge does not delete by key, and why.
pub const RETAINED: &[(&str, &str)] = &[
    ("delegation", "signed-record root: records GC at completion, shared residue kept until its acknowledged cleanup"),
    ("invocation", "signed-record root: records GC at completion, shared residue kept until its acknowledged cleanup"),
    ("revocation", "signed-record root: records GC at completion, shared residue kept until its acknowledged cleanup"),
    ("actor", "signed-record principal: records GC removes it once no delegation, invocation or revocation names it"),
    ("owner_share_policy", "signed policy projection: removed with its proof closure by records GC, else shared residue"),
    ("policy_v3_registration", "signed policy projection: removed with its proof closure by records GC, else shared residue"),
    ("policy_v3_session", "signed policy projection: removed with its proof closure by records GC, else shared residue"),
    ("policy_v3_challenge", "policy challenge: removed with its registration by records GC; expires_at-bounded"),
    ("encryption_audit", "key-operation audit trail: key.delete keeps it as evidence; owner erase pending the deletion-ledger ruling"),
    ("encryption_nonce", "owner-delete replay nonce: expires_at-bounded, names no space"),
    ("renewal_identity", "this node's own renewer identity, not user data"),
    ("renewal_lease", "renewal state of a signed delegation, keyed by delegation CID, not by space"),
    ("space_purge_job", "the purge's own durable progress row: raw space is nulled in the terminal transaction"),
    ("resource_purge_job", "owner resource lifecycle job: its raw target belongs to the resource purge, not a space"),
];

/// Call after exclusive space drain and SQL/DuckDB actor eviction. This runs
/// within the caller's database-phase transaction, which must roll back on
/// failure. It deliberately preserves signed-record/event roots and SQL-store
/// object inventory until their separately acknowledged cleanup.
///
/// Deleting `database_artifact` fires `artifact_metadata_retire` when chunked
/// storage is enabled: the name's checkpoint parts become `deleting` and their
/// replacement credit is released. Their chunk bytes are erased by
/// [`reap_artifact_parts`] in the objects phase.
pub async fn delete_sql_and_hook_rows(
    tx: &DatabaseTransaction,
    job: &ClaimedPurge,
) -> Result<u64, DbErr> {
    if job.phase != "database" || !renew(tx, job).await? {
        return Err(DbErr::Custom("purge database lease unavailable".into()));
    }
    let bound = tx
        .query_one(Statement::from_sql_and_values(
            DatabaseBackend::Postgres,
            "SELECT purge_id FROM space_purge_job WHERE purge_id=$1 AND space=$2",
            [job.purge_id.clone().into(), job.space.clone().into()],
        ))
        .await?;
    if bound.is_none() {
        return Err(DbErr::Custom("purge space binding mismatch".into()));
    }
    let mut deleted = 0;
    // Deliveries reference subscriptions, so they must be removed first.
    for sql in [
        "DELETE FROM hook_delivery WHERE subscription_id IN (SELECT id FROM hook_subscription WHERE space_id=$1)",
        "DELETE FROM hook_subscription WHERE space_id=$1",
        "DELETE FROM signed_kv_ticket WHERE space_id=$1",
        // Payload and WAL-delta bytes are both in database_artifact.
        "DELETE FROM database_artifact WHERE space=$1",
        "DELETE FROM database_alias WHERE space=$1",
        "DELETE FROM database_legacy_artifact WHERE space=$1",
        "DELETE FROM meeting_legacy_write_guard WHERE space=$1",
        "DELETE FROM sql_database WHERE space=$1",
    ] {
        deleted+=tx.execute(Statement::from_sql_and_values(DatabaseBackend::Postgres,sql,
            [job.space.clone().into()])).await?.rows_affected();
    }
    deleted += delete_owner_encryption_networks(tx, job).await?;
    Ok(deleted)
}

/// Database phase: delete the owner's encryption networks with their keys,
/// members and ceremonies when this purge leaves the owner with no live space
/// on this node. Kept separate so it can be gated on its deletion-ledger
/// evidence. No foreign key references these rows.
///
/// Live means a `space` row with no accepted, uncompleted purge: the target
/// keeps its row until completion, and two concurrently purged last spaces
/// must not each wait for the other. Network owners are canonical DIDs
/// (`NetworkId::new`); a space DID may differ in EIP-55 case, so the SQL
/// filter is case-insensitive and the final match is
/// `did_principal_matches`. An unparseable candidate space counts as live.
pub async fn delete_owner_encryption_networks(
    tx: &DatabaseTransaction,
    job: &ClaimedPurge,
) -> Result<u64, DbErr> {
    use tinycloud_auth::{
        identity::{canonicalize_principal, did_principal_matches},
        resource::SpaceId,
    };
    let space: SpaceId = job
        .space
        .parse()
        .map_err(|_| DbErr::Custom("invalid purge space".into()))?;
    let Ok(owner) = canonicalize_principal(space.did().as_str()) else {
        // NetworkId::new rejects such an owner, so it cannot own a network.
        return Ok(0);
    };
    let candidates = tx
        .query_all(Statement::from_sql_and_values(
            DatabaseBackend::Postgres,
            "SELECT s.id FROM space s WHERE s.id<>$1
             AND lower(artifact_owner(s.id))=lower(artifact_owner($1))
             AND NOT EXISTS(SELECT 1 FROM space_purge_job j WHERE j.space=s.id AND j.phase<>'complete')",
            [job.space.clone().into()],
        ))
        .await?;
    for row in candidates {
        let live = match row.try_get::<String>("", "id")?.parse::<SpaceId>() {
            Ok(other) => did_principal_matches(other.did().as_str(), &owner),
            Err(_) => true,
        };
        if live {
            return Ok(0);
        }
    }
    let mut deleted = 0;
    for sql in [
        "DELETE FROM encryption_ceremony WHERE network_id IN (SELECT network_id FROM encryption_network WHERE owner_did=$1)",
        "DELETE FROM encryption_network_member WHERE network_id IN (SELECT network_id FROM encryption_network WHERE owner_did=$1)",
        "DELETE FROM encryption_network_key WHERE network_id IN (SELECT network_id FROM encryption_network WHERE owner_did=$1)",
        "DELETE FROM encryption_network WHERE owner_did=$1",
    ] {
        deleted += tx
            .execute(Statement::from_sql_and_values(
                DatabaseBackend::Postgres,
                sql,
                [owner.clone().into()],
            ))
            .await?
            .rows_affected();
    }
    Ok(deleted)
}

/// Objects phase: erase at most `max_steps` chunked-checkpoint chunks of the
/// purged space, one `artifact_reap_one` statement per chunk. Returns whether
/// no `artifact_part` row (hence no chunk) of the space remains.
///
/// Chunk bytes live in PostgreSQL, but they run here rather than in the
/// database phase: their volume is bounded only by the operator quota, and
/// that phase is one transaction which must commit with its advance before
/// the lease expires and would hold the owner's `artifact_account` lock,
/// blocking that owner's other spaces, for the whole erase. Here each chunk
/// is its own short statement, batches resume across leases, and completion
/// re-verifies emptiness in the terminal transaction.
///
/// `artifact_reap_one` keeps the owner counters exact: deleting a part
/// subtracts its `size_bytes` from `reserved_bytes` and its own and its
/// replacements' `replacement_credit` from `credit_bytes`, the same terms
/// `artifact_reserve` added. `abort_upload` reaps `uploading` and `sealed`
/// parts at once; after the drain and fence nothing can resume or publish them.
pub async fn reap_artifact_parts(
    conn: &impl ConnectionTrait,
    job: &ClaimedPurge,
    max_steps: usize,
) -> Result<bool, DbErr> {
    if job.phase != "objects" || !renew(conn, job).await? {
        return Err(DbErr::Custom("purge artifact lease unavailable".into()));
    }
    let space = || -> sea_orm::Value { job.space.clone().into() };
    for _ in 0..max_steps {
        let Some(part) = conn
            .query_one(Statement::from_sql_and_values(
                DatabaseBackend::Postgres,
                "SELECT service,name,part_id FROM artifact_part WHERE space=$1
                 ORDER BY service,name,part_id LIMIT 1",
                [space()],
            ))
            .await?
        else {
            return Ok(true);
        };
        let key = [
            part.try_get::<String>("", "service")?.into(),
            space(),
            part.try_get::<String>("", "name")?.into(),
            part.try_get::<String>("", "part_id")?.into(),
        ];
        let progress: bool = conn
            .query_one(Statement::from_sql_and_values(
                DatabaseBackend::Postgres,
                "SELECT artifact_reap_one($1,$2,$3,$4,true) AS progress",
                key.clone(),
            ))
            .await?
            .ok_or_else(|| DbErr::Custom("purge artifact reap unavailable".into()))?
            .try_get("", "progress")?;
        // False means a concurrent collector removed the part, or a
        // database_artifact row still points at it. Only the latter persists.
        if !progress
            && conn
                .query_one(Statement::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    "SELECT 1 FROM artifact_part WHERE service=$1 AND space=$2 AND name=$3 AND part_id=$4",
                    key,
                ))
                .await?
                .is_some()
        {
            return Err(DbErr::Custom("purge artifact part still referenced".into()));
        }
    }
    Ok(conn
        .query_one(Statement::from_sql_and_values(
            DatabaseBackend::Postgres,
            "SELECT 1 FROM artifact_part WHERE space=$1 LIMIT 1",
            [space()],
        ))
        .await?
        .is_none())
}

/// Remove physical-object inventory only after the object phase has verified
/// empty stores. Keeping it until terminal commit preserves restore candidates
/// and orphan-upload claims across crashes and provider retries.
///
/// Owner-keyed rows go in this same transaction, which also deletes the
/// `space` row: the owner's `artifact_account` is deleted only when no other
/// live `space` row and no artifact row of that owner remains. Spaces purged
/// earlier have no `space` row; spaces still being purged keep theirs, so the
/// owner's last completion removes the account.
pub(crate) async fn delete_verified_empty_inventory(
    tx: &DatabaseTransaction,
    job: &ClaimedPurge,
) -> Result<u64, DbErr> {
    if job.phase != "objects" || !renew(tx, job).await? {
        return Err(DbErr::Custom("purge inventory lease unavailable".into()));
    }
    // Chunks reference their part, so no part means no chunk bytes.
    if tx
        .query_one(Statement::from_sql_and_values(
            DatabaseBackend::Postgres,
            "SELECT 1 FROM artifact_part WHERE space=$1 LIMIT 1",
            [job.space.clone().into()],
        ))
        .await?
        .is_some()
    {
        return Err(DbErr::Custom("purge artifact parts remain".into()));
    }
    let mut deleted = 0;
    for sql in [
        "DELETE FROM kv_orphan_attempt WHERE space=$1",
        "DELETE FROM kv_orphan_candidate WHERE space=$1",
        "DELETE FROM kv_blob_generation WHERE space=$1",
        "DELETE FROM sql_store_object WHERE space=$1",
        "DELETE FROM sql_store_manifest WHERE space=$1",
        "DELETE FROM artifact_space_owner WHERE space=$1",
        // artifact_owner() is the owner key artifact_reserve enforces. The
        // foreign keys from artifact_space_owner and artifact_part make a
        // concurrently added reference fail this delete, never dangle.
        "DELETE FROM artifact_account a WHERE owner=artifact_owner($1)
         AND NOT EXISTS(SELECT 1 FROM space s WHERE s.id<>$1 AND artifact_owner(s.id)=a.owner)
         AND NOT EXISTS(SELECT 1 FROM artifact_space_owner o WHERE o.owner=a.owner)
         AND NOT EXISTS(SELECT 1 FROM artifact_part p WHERE p.owner=a.owner)",
    ] {
        deleted += tx
            .execute(Statement::from_sql_and_values(
                DatabaseBackend::Postgres,
                sql,
                [job.space.clone().into()],
            ))
            .await?
            .rows_affected();
    }
    Ok(deleted)
}
