//! Exact-space database leaves. Signed-record roots are handled at completion.
//! The owner-erasure step that follows a retired owner's last purge is here
//! too, so every owner-keyed table's deleter sits next to its classification.
use crate::{
    encryption_network::NetworkId,
    models::space_retirement,
    space_purge_ledger::LedgerKeys,
    space_purge_worker::{renew, ClaimedPurge},
};
use sea_orm::{
    ConnectionTrait, DatabaseBackend, DatabaseTransaction, DbErr, Statement, TransactionTrait,
};
use std::collections::BTreeSet;

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
    ("sql_wal_mark", PurgePhase::Database),
    ("database_alias", PurgePhase::Database),
    ("database_legacy_artifact", PurgePhase::Database),
    ("meeting_legacy_write_guard", PurgePhase::Database),
    ("sql_database", PurgePhase::Database),
    ("kv_orphan_attempt", PurgePhase::Objects),
    ("kv_orphan_candidate", PurgePhase::Objects),
    ("kv_blob_generation", PurgePhase::Objects),
    ("sql_store_object", PurgePhase::Objects),
    ("sql_store_manifest", PurgePhase::Objects),
    ("sql_store_mode", PurgePhase::Objects),
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

/// Rows keyed by the owner, and the condition under which they are deleted:
/// `artifact_account` in [`delete_verified_empty_inventory`], the
/// encryption-network rows by the owner-erasure step after a space purge
/// ([`erase_owner_encryption_rows`]).
pub const PURGED_BY_OWNER: &[(&str, &str)] = &[
    ("artifact_account", "quota counters only, all zero once no artifact row remains and re-created on demand: when the owner has no other live space"),
    ("encryption_network", "owner erasure: retired owner, no live space, every purge of the owner complete; after the signed `erased` record"),
    ("encryption_network_key", "owner erasure: retired owner, no live space, every purge of the owner complete; after the signed `erased` record"),
    ("encryption_network_member", "owner erasure: retired owner, no live space, every purge of the owner complete; after the signed `erased` record"),
    ("encryption_ceremony", "owner erasure: retired owner, no live space, every purge of the owner complete; after the signed `erased` record"),
    ("encryption_audit", "owner erasure: the key-operation trail of an erased owner's networks; the signed `erased` record is the evidence that replaces it"),
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
    ("encryption_nonce", "owner-delete replay nonce: expires_at-bounded, names no space"),
    ("renewal_identity", "this node's own renewer identity, not user data"),
    ("root_wrap", "this node's own sealed identity root, not user data; never purged (TC-3554)"),
    ("renewal_lease", "renewal state of a signed delegation, keyed by delegation CID, not by space; records GC deletes the row, and its stamps, when its lease or original delegation is deleted (TC-4092)"),
    ("session_retire", "sign-out marker keyed by a session did:key, names no space; expires_at-bounded and pruned (TC-3443)"),
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
        "DELETE FROM sql_wal_mark WHERE space=$1",
        "DELETE FROM database_alias WHERE space=$1",
        "DELETE FROM database_legacy_artifact WHERE space=$1",
        "DELETE FROM meeting_legacy_write_guard WHERE space=$1",
        "DELETE FROM sql_database WHERE space=$1",
    ] {
        deleted+=tx.execute(Statement::from_sql_and_values(DatabaseBackend::Postgres,sql,
            [job.space.clone().into()])).await?.rows_affected();
    }
    Ok(deleted)
}

// Owner erasure (TC-2871 S5, option A). Not a purge phase: it runs after a
// space purge completes, from the purge worker, and again from reconcile.
// The node publishes the signed `("owner","erased")` record first; only then
// does [`erase_owner_encryption_rows`] delete the rows, so a crash between the
// two leaves a record that reconcile acts on. Purging an owner's last space is
// not by itself account erasure: the owner must also be retired.

const NETWORK_PREFIX: &str = "urn:tinycloud:encryption:";

/// Tables holding an owner's encryption-network rows, children first.
const OWNER_ENCRYPTION_TABLES: [&str; 5] = [
    "encryption_ceremony",
    "encryption_network_member",
    "encryption_network_key",
    "encryption_audit",
    "encryption_network",
];

/// The canonical owner of a stored network id or owner DID, if it parses.
fn canonical_owner(value: &str) -> Option<String> {
    if value.starts_with(NETWORK_PREFIX) {
        value
            .parse::<NetworkId>()
            .ok()
            .map(|network| network.owner_did().to_owned())
    } else {
        tinycloud_auth::identity::canonicalize_principal(value).ok()
    }
}

/// Every canonical owner DID an encryption-network row names, by its
/// `owner_did` or its network id. Rows that do not parse name no owner.
pub async fn encryption_owners<C: ConnectionTrait>(conn: &C) -> Result<BTreeSet<String>, DbErr> {
    let rows = conn
        .query_all(Statement::from_string(
            DatabaseBackend::Postgres,
            "SELECT owner_did AS id FROM encryption_network
             UNION SELECT network_id FROM encryption_network
             UNION SELECT network_id FROM encryption_network_key
             UNION SELECT network_id FROM encryption_network_member
             UNION SELECT network_id FROM encryption_ceremony
             UNION SELECT network_id FROM encryption_audit",
        ))
        .await?;
    let mut owners = BTreeSet::new();
    for row in rows {
        if let Some(owner) = canonical_owner(&row.try_get::<String>("", "id")?) {
            owners.insert(owner);
        }
    }
    Ok(owners)
}

/// `LIKE` patterns, over lowercased values, that every stored spelling of
/// the canonical `owner` matches: (owner DID, network id). `NetworkId` and
/// `canonicalize_principal` accept a `did:pkh:eip155` owner with any chain id
/// `u64` parses (`1`, `01`, `+1`) and any address case, so for such an owner
/// the patterns pin only the address; any other DID is kept verbatim. Both
/// are supersets: callers keep a row only if it parses to `owner`.
fn owner_patterns(owner: &str) -> (String, String) {
    let escape = |value: &str| {
        value
            .to_lowercase()
            .replace('\\', "\\\\")
            .replace('%', "\\%")
            .replace('_', "\\_")
    };
    let did = match tinycloud_auth::identity::parse_pkh_did(owner) {
        Ok(Some(pkh)) => format!("did:pkh:eip155:%:{}", escape(&pkh.address)),
        _ => escape(owner),
    };
    let network = format!("{}{did}:%", escape(NETWORK_PREFIX));
    (did, network)
}

/// The network ids, exactly as stored, of `owner`'s rows in any encryption
/// table, including key rows whose network row is gone. Every spelling the
/// parsers accept counts (`owner_patterns`); the final match is on the
/// parsed canonical owner of the network id, or of the network row's
/// `owner_did`. Erasure and the prune gate share this one inventory.
async fn owner_network_ids<C: ConnectionTrait>(
    conn: &C,
    owner: &str,
) -> Result<BTreeSet<String>, DbErr> {
    let (did, network) = owner_patterns(owner);
    let mut ids = BTreeSet::new();
    for row in conn
        .query_all(Statement::from_sql_and_values(
            DatabaseBackend::Postgres,
            "SELECT network_id, owner_did FROM encryption_network WHERE lower(owner_did) LIKE $1",
            [did.into()],
        ))
        .await?
    {
        let owner_did: String = row.try_get("", "owner_did")?;
        if canonical_owner(&owner_did).as_deref() == Some(owner) {
            ids.insert(row.try_get("", "network_id")?);
        }
    }
    let rows = conn
        .query_all(Statement::from_sql_and_values(
            DatabaseBackend::Postgres,
            "SELECT network_id AS id FROM encryption_network WHERE lower(network_id) LIKE $1
             UNION SELECT network_id FROM encryption_network_key WHERE lower(network_id) LIKE $1
             UNION SELECT network_id FROM encryption_network_member WHERE lower(network_id) LIKE $1
             UNION SELECT network_id FROM encryption_ceremony WHERE lower(network_id) LIKE $1
             UNION SELECT network_id FROM encryption_audit WHERE lower(network_id) LIKE $1",
            [network.into()],
        ))
        .await?;
    for row in rows {
        let id: String = row.try_get("", "id")?;
        if canonical_owner(&id).as_deref() == Some(owner) {
            ids.insert(id);
        }
    }
    Ok(ids)
}

/// `encryption_network_key` rows that remain for `owner`'s networks. The
/// `deletions.jsonl` prune requires zero.
pub async fn owner_key_rows<C: ConnectionTrait>(conn: &C, owner: &str) -> Result<u64, DbErr> {
    let mut rows = 0;
    for id in owner_network_ids(conn, owner).await? {
        let row = conn
            .query_one(Statement::from_sql_and_values(
                DatabaseBackend::Postgres,
                "SELECT count(*) AS n FROM encryption_network_key WHERE network_id=$1",
                [id.into()],
            ))
            .await?
            .ok_or_else(|| DbErr::Custom("count returned no row".into()))?;
        rows += u64::try_from(row.try_get::<i64>("", "n")?).unwrap_or(0);
    }
    Ok(rows)
}

/// The gate before the `erased` record is published: `owner` (a canonical
/// DID) has a `space_retirement` row under some key id, every purge job of
/// that owner digest is complete, and no live space remains. An owner with
/// no purge job at all (encryption networks but never a space here) passes:
/// the signed retirement alone asks for erasure (Naomi 11-19, review N1).
/// Returns the retirement. Jobs and retirements are matched under every
/// configured key id, so a key rotation between them does not block erasure.
///
/// Live means any `space` row of the owner: completed purges have deleted
/// theirs. Network owners are canonical DIDs (`NetworkId::new`); a space DID
/// may differ in EIP-55 case, so the SQL filter is case-insensitive and the
/// final match is `did_principal_matches`. An unparseable candidate space
/// counts as live.
pub async fn owner_erasure_retirement<C: ConnectionTrait>(
    conn: &C,
    keys: &LedgerKeys,
    owner: &str,
) -> Result<Option<space_retirement::Model>, DbErr> {
    use sea_orm::EntityTrait;
    use tinycloud_auth::{identity::did_principal_matches, resource::SpaceId};
    let unavailable = |_| DbErr::Custom("owner digest unavailable".into());
    let mut retirement = None;
    let mut open = 0_i64;
    for key_id in keys.key_ids() {
        let digest = keys
            .target_hmac(key_id, "owner", owner)
            .map_err(unavailable)?;
        if retirement.is_none() {
            retirement = space_retirement::Entity::find_by_id((digest.clone(), key_id.to_owned()))
                .one(conn)
                .await?;
        }
        let row = conn
            .query_one(Statement::from_sql_and_values(
                DatabaseBackend::Postgres,
                "SELECT count(*) AS open FROM space_purge_job
                 WHERE owner_hmac=$1 AND hmac_key_id=$2 AND phase<>'complete'",
                [digest.into(), key_id.into()],
            ))
            .await?
            .ok_or_else(|| DbErr::Custom("count returned no row".into()))?;
        open += row.try_get::<i64>("", "open")?;
    }
    let Some(retirement) = retirement else {
        return Ok(None);
    };
    if open != 0 {
        return Ok(None);
    }
    let candidates = conn
        .query_all(Statement::from_sql_and_values(
            DatabaseBackend::Postgres,
            "SELECT id FROM space WHERE lower(artifact_owner(id))=lower($1)",
            [owner.into()],
        ))
        .await?;
    for row in candidates {
        let live = match row.try_get::<String>("", "id")?.parse::<SpaceId>() {
            Ok(space) => did_principal_matches(space.did().as_str(), owner),
            Err(_) => true,
        };
        if live {
            return Ok(None);
        }
    }
    Ok(Some(retirement))
}

/// Owner-erasure step (b): in one transaction, keep the database copy of the
/// verified `erased` record (`space_purge_ledger_copy::retain`) and delete
/// every `encryption_network*`, `encryption_ceremony` and `encryption_audit`
/// row of `owner`'s networks. The record must be `("owner","erased")` and its
/// digest must be `owner`'s under its key id, so the caller can only name the
/// owner the record names; an HMAC is never reversed. Idempotent: reconcile
/// runs it again for every verified `erased` record. No foreign key
/// references these rows. Returns the rows deleted.
pub async fn erase_owner_encryption_rows<C: TransactionTrait>(
    db: &C,
    keys: &LedgerKeys,
    path: &str,
    body: &[u8],
    owner: &str,
    now: time::OffsetDateTime,
) -> Result<u64, DbErr> {
    let invalid = || DbErr::Custom("owner erasure evidence mismatch".into());
    let record = keys.verify(path, body).map_err(|_| invalid())?;
    let digest = keys
        .target_hmac(&record.key_id, "owner", owner)
        .map_err(|_| invalid())?;
    if record.kind != "owner"
        || record.state != "erased"
        || record.target_hmac != hex::encode(digest)
    {
        return Err(invalid());
    }
    let tx = db.begin().await?;
    crate::space_purge_ledger_copy::retain(&tx, keys, path, body, now).await?;
    let mut deleted = 0;
    for id in owner_network_ids(&tx, owner).await? {
        for table in OWNER_ENCRYPTION_TABLES {
            deleted += tx
                .execute(Statement::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    format!("DELETE FROM {table} WHERE network_id=$1"),
                    [id.clone().into()],
                ))
                .await?
                .rows_affected();
        }
    }
    tx.commit().await?;
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
        "DELETE FROM sql_store_mode WHERE space=$1",
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
