//! TC-732: the ordered, prefix-scoped KV change feed behind `tinycloud.kv/sync`,
//! and the per-space sequence lock that makes `event_order.seq` commit-ordered.
//!
//! # Why `current_kv` is a complete feed
//!
//! `current_kv` keeps one row per key, including a permanent tombstone for
//! every deleted key, and `invocation::save` is its only writer. Each row
//! carries the position `(seq, epoch, epoch_seq)` of the key's last visible
//! change: a write's own position, or -- since TC-732 -- the position of the
//! delete that tombstoned it. Ordering rows by `(seq, epoch, epoch_seq, key)`
//! is therefore a replayable feed of each key's latest state.
//!
//! # Why `seq` must be commit-ordered
//!
//! `transact` assigns `MAX(seq) + 1` per space. Under READ COMMITTED two
//! same-space transactions could otherwise read the same maximum (sharing a
//! seq), or commit in the opposite order of their seqs, so a reader could pass
//! a position whose predecessor had not committed yet and skip it forever.
//! [`lock_space_sequences`] serializes every sequence producer per space and
//! holds the lock through commit, so a commit with seq `n + 1` can only start
//! computing its seq after the commit with seq `n` is visible.

use crate::auth_graph::AuthGraphSnapshot;
use crate::hash::Hash;
use crate::models::{current_kv, space};
use crate::relationships::event_order;
use crate::types::{Metadata, Resource, SpaceIdWrap};
use sea_orm::{
    entity::prelude::*,
    sea_query::{Expr, ExprTrait, Order, Query, SimpleExpr},
    Condition, ConnectionTrait, DbBackend, QueryOrder, QuerySelect, Statement,
};
use time::OffsetDateTime;
use tinycloud_auth::identity::did_principal_matches;
use tinycloud_auth::resource::{Path, SpaceId};

/// The only ability that may invoke the feed. Never implied by any wildcard.
pub const KV_SYNC_ACTION: &str = "tinycloud.kv/sync";
/// Never invoked: presented through `x-tinycloud-retention-grant` on a
/// `kv/sync` request to attest owner-approved offline retention.
pub const KV_RETAIN_ACTION: &str = "tinycloud.kv/retain";
/// Page size when the request names none.
pub const KV_SYNC_DEFAULT_LIMIT: usize = 500;
/// Largest page a request may ask for.
pub const KV_SYNC_MAX_LIMIT: usize = 1000;

/// Domain separator for the advisory-lock key derived from a space id.
const SPACE_SEQUENCE_LOCK_DOMAIN: &[u8] = b"tinycloud/kv-seq/v1\0";

/// Advisory-lock key for `space`: the first 8 bytes of
/// `blake3("tinycloud/kv-seq/v1\0" || space)`, big-endian.
fn space_sequence_lock_key(space: &SpaceId) -> i64 {
    let mut preimage = SPACE_SEQUENCE_LOCK_DOMAIN.to_vec();
    preimage.extend_from_slice(space.to_string().as_bytes());
    let digest = crate::hash::hash(&preimage);
    let mut key = [0u8; 8];
    key.copy_from_slice(&digest.as_ref()[..8]);
    i64::from_be_bytes(key)
}

/// Serialize every `event_order` sequence producer for `spaces` until the
/// enclosing transaction ends.
///
/// Call it right after `BEGIN`, before the transaction reads anything, so the
/// `MAX(seq)` it later computes (and any precondition it checks) observes
/// every earlier same-space commit.
///
/// - PostgreSQL: `pg_advisory_xact_lock` on each space's key, in ascending key
///   order (deadlock-free across spaces), released at commit or rollback.
///   Re-entrant within one transaction.
/// - SQLite: no-op; the node's single writer mutex already serializes writers.
/// - MySQL: `SELECT ... FOR UPDATE` on each `space` row. A space created by
///   the same transaction has no row to lock yet. MySQL is unsupported and
///   untested here.
pub async fn lock_space_sequences<'a, C: ConnectionTrait>(
    db: &C,
    spaces: impl IntoIterator<Item = &'a SpaceId>,
) -> Result<(), DbErr> {
    match db.get_database_backend() {
        DbBackend::Sqlite => Ok(()),
        DbBackend::Postgres => {
            let mut keys = spaces
                .into_iter()
                .map(space_sequence_lock_key)
                .collect::<Vec<_>>();
            keys.sort_unstable();
            keys.dedup();
            for key in keys {
                db.query_one(Statement::from_sql_and_values(
                    DbBackend::Postgres,
                    "SELECT pg_advisory_xact_lock($1)",
                    [key.into()],
                ))
                .await?;
            }
            Ok(())
        }
        DbBackend::MySql => {
            let mut ids = spaces.into_iter().cloned().collect::<Vec<_>>();
            ids.sort_by_key(|space| space.to_string());
            ids.dedup();
            for id in ids {
                space::Entity::find_by_id(SpaceIdWrap(id))
                    .lock_exclusive()
                    .one(db)
                    .await?;
            }
            Ok(())
        }
    }
}

/// A position in a space's event order: one `event_order` row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KvSyncAnchor {
    pub seq: i64,
    pub epoch: Hash,
    pub epoch_seq: i64,
}

/// The feed position just after the change to `key` at `anchor`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KvSyncPosition {
    pub anchor: KvSyncAnchor,
    pub key: String,
}

/// Decoded cursor state. `pos` is the last delivered change (none before the
/// first change). `floor` is the space's newest event when the client first
/// bootstrapped: tombstones at or below it predate the client and are skipped.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct KvSyncState {
    pub pos: Option<KvSyncPosition>,
    pub floor: Option<KvSyncAnchor>,
}

/// A `tinycloud.kv/sync` request's parameters, decoded by the route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KvSyncRequest {
    /// Page size, `1..=KV_SYNC_MAX_LIMIT`.
    pub limit: usize,
    /// `None` on the first page (no cursor).
    pub state: Option<KvSyncState>,
    /// CID of a `tinycloud.kv/retain` delegation presented for retention.
    pub retention_grant: Option<Hash>,
}

impl Default for KvSyncRequest {
    fn default() -> Self {
        Self {
            limit: KV_SYNC_DEFAULT_LIMIT,
            state: None,
            retention_grant: None,
        }
    }
}

/// One key's latest state. `value` is `None` for a tombstone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KvSyncChange {
    pub key: Path,
    pub value: Option<(Hash, Metadata)>,
}

impl KvSyncChange {
    pub fn deleted(&self) -> bool {
        self.value.is_none()
    }
}

/// Node-attested authority window for the response. `not_before` is the
/// latest `nbf` and `expires_at` the earliest `exp` across every delegation
/// the invocation's proofs rest on; `retain_until` is the earliest `exp` in
/// the presented retention grant's own proof closure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct KvSyncAuthority {
    pub not_before: Option<OffsetDateTime>,
    pub expires_at: Option<OffsetDateTime>,
    pub retain_until: Option<OffsetDateTime>,
}

/// One page of the feed.
#[derive(Debug, Clone)]
pub struct KvSyncPage {
    pub space: SpaceId,
    pub prefix: Path,
    pub changes: Vec<KvSyncChange>,
    /// More changes are available right now.
    pub more: bool,
    /// State to encode in the next cursor. Equal to the request state when
    /// `changes` is empty (the route then echoes the request cursor).
    pub state: KvSyncState,
    pub authority: KvSyncAuthority,
    /// The opaque cursor to return, filled in by the HTTP layer (which owns
    /// cursor encryption), like `InvocationOutcome::KvList`'s next cursor.
    pub cursor: Option<String>,
    /// The node identity `/info` advertises, filled in by the HTTP layer.
    pub node_did: Option<String>,
}

/// Why a cursor cannot be continued and the client must re-bootstrap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KvSyncResetReason {
    /// The cursor failed authentication or does not belong to this space and
    /// prefix.
    CursorInvalid,
    /// The cursor's position or floor names an event this space does not
    /// have (for example after a restore from backup).
    PositionUnknown,
}

impl KvSyncResetReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CursorInvalid => "cursor-invalid",
            Self::PositionUnknown => "position-unknown",
        }
    }
}

/// Why a presented `tinycloud.kv/retain` grant is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KvSyncRetentionError {
    NotFound,
    HolderMismatch,
    Revoked,
    AncestorRevoked,
    NotYetValid,
    Expired,
    NotCovering,
}

impl KvSyncRetentionError {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotFound => "retention-grant-not-found",
            Self::HolderMismatch => "retention-grant-holder-mismatch",
            Self::Revoked => "retention-grant-revoked",
            Self::AncestorRevoked => "retention-grant-ancestor-revoked",
            Self::NotYetValid => "retention-grant-not-yet-valid",
            Self::Expired => "retention-grant-expired",
            Self::NotCovering => "retention-grant-not-covering",
        }
    }
}

/// The node-attested authority window over every delegation `parents` rest
/// on. Returns `(not_before, expires_at)`; both are `None` for a root
/// authority invocation with no proofs.
///
/// Every cited parent's whole ancestor closure is folded, not just a single
/// chain: delegation registration keeps only the parents a capability needs,
/// but invocation authorization rejects the request when *any* ancestor of a
/// cited proof is outside its window, so the window is the intersection over
/// all of them.
pub(crate) fn authority_window(
    graph: &AuthGraphSnapshot,
    parents: &[Hash],
) -> (Option<OffsetDateTime>, Option<OffsetDateTime>) {
    let mut not_before = None;
    let mut expires_at = None;
    for parent in parents {
        for id in graph.chain_ids_from(parent) {
            let Some(row) = graph.delegation(&id) else {
                continue;
            };
            not_before = latest(not_before, row.not_before);
            expires_at = earliest(expires_at, row.expiry);
        }
    }
    (not_before, expires_at)
}

/// Validate a presented `tinycloud.kv/retain` grant for a `kv/sync` on
/// `sync_resource` by `invoker` at `now`, and return its `retainUntil`: the
/// earliest `exp` over the grant's own proof closure (`None` when nothing in
/// it expires, which grants no retention).
///
/// The grant must be held by the invoker, unrevoked along its whole chain,
/// inside every chain member's validity window, and carry `kv/retain` on a
/// resource the sync resource extends. Registration already enforced that a
/// delegated signer can only grant `kv/retain` if its own chain holds it.
pub(crate) fn retention_until(
    graph: &AuthGraphSnapshot,
    grant: &Hash,
    invoker: &str,
    sync_resource: &Resource,
    now: OffsetDateTime,
) -> Result<Option<OffsetDateTime>, KvSyncRetentionError> {
    let row = graph
        .delegation(grant)
        .ok_or(KvSyncRetentionError::NotFound)?;
    if !did_principal_matches(&row.delegatee, invoker) {
        return Err(KvSyncRetentionError::HolderMismatch);
    }
    if graph.is_revoked(grant) {
        return Err(KvSyncRetentionError::Revoked);
    }
    if graph.first_revoked_ancestor(grant).is_some() {
        return Err(KvSyncRetentionError::AncestorRevoked);
    }
    let mut retain_until = None;
    for id in graph.chain_ids_from(grant) {
        let ancestor = graph
            .delegation(&id)
            .ok_or(KvSyncRetentionError::NotFound)?;
        if ancestor.not_before.is_some_and(|nbf| now < nbf) {
            return Err(KvSyncRetentionError::NotYetValid);
        }
        if ancestor.expiry.is_some_and(|exp| now >= exp) {
            return Err(KvSyncRetentionError::Expired);
        }
        retain_until = earliest(retain_until, ancestor.expiry);
    }
    let covers = graph.abilities(grant).iter().any(|ability| {
        sync_resource.extends(&ability.resource)
            && crate::policy_capability::ability_matches(
                ability.ability.as_ref().as_ref(),
                KV_RETAIN_ACTION,
            )
    });
    if !covers {
        return Err(KvSyncRetentionError::NotCovering);
    }
    Ok(retain_until)
}

fn latest(left: Option<OffsetDateTime>, right: Option<OffsetDateTime>) -> Option<OffsetDateTime> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.max(right)),
        (left, right) => left.or(right),
    }
}

fn earliest(left: Option<OffsetDateTime>, right: Option<OffsetDateTime>) -> Option<OffsetDateTime> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.min(right)),
        (left, right) => left.or(right),
    }
}

/// Failure of a feed read.
#[derive(Debug, thiserror::Error)]
pub enum KvSyncError {
    #[error(transparent)]
    Db(#[from] DbErr),
    #[error("kv/sync cursor requires a reset: {}", .0.as_str())]
    ResetRequired(KvSyncResetReason),
}

/// The space's newest event: the bootstrap floor. `None` for a space with no
/// events yet.
async fn newest_event<C: ConnectionTrait>(
    db: &C,
    space: &SpaceId,
) -> Result<Option<KvSyncAnchor>, DbErr> {
    Ok(event_order::Entity::find()
        .filter(event_order::Column::Space.eq(SpaceIdWrap(space.clone())))
        .order_by_desc(event_order::Column::Seq)
        .order_by_desc(event_order::Column::Epoch)
        .order_by_desc(event_order::Column::EpochSeq)
        .one(db)
        .await?
        .map(|row| KvSyncAnchor {
            seq: row.seq,
            epoch: row.epoch,
            epoch_seq: row.epoch_seq,
        }))
}

/// Whether `anchor` is exactly one of this space's `event_order` rows.
async fn anchor_exists<C: ConnectionTrait>(
    db: &C,
    space: &SpaceId,
    anchor: &KvSyncAnchor,
) -> Result<bool, DbErr> {
    Ok(event_order::Entity::find_by_id((
        anchor.epoch,
        anchor.epoch_seq,
        SpaceIdWrap(space.clone()),
    ))
    .one(db)
    .await?
    .is_some_and(|row| row.seq == anchor.seq))
}

/// `current_kv.key` in byte order (see `db::byte_ordered`).
fn key_byte_ordered(backend: DbBackend) -> SimpleExpr {
    crate::db::byte_ordered(
        backend,
        Expr::col((current_kv::Entity, current_kv::Column::Key)),
    )
}

fn col(column: current_kv::Column) -> Expr {
    Expr::col((current_kv::Entity, column))
}

/// The feed query: rows in `prefix` strictly after `pos`, minus tombstones at
/// or below `floor.seq`, ordered by `(seq, epoch, epoch_seq, key)`. Comparison
/// and ordering both happen in SQL with the key in one byte-ordered
/// collation, so a page boundary cannot skip or repeat a row. One more row
/// than `limit` is fetched to detect `more`.
pub(crate) fn kv_sync_statement(
    backend: DbBackend,
    space: &SpaceId,
    prefix: &Path,
    limit: usize,
    pos: Option<&KvSyncPosition>,
    floor: Option<&KvSyncAnchor>,
) -> Statement {
    let mut condition =
        Condition::all().add(col(current_kv::Column::Space).eq(SpaceIdWrap(space.clone())));
    if let Some(prefix) = crate::db::kv_prefix_condition(backend, prefix.as_str()) {
        condition = condition.add(prefix);
    }
    if let Some(pos) = pos {
        let anchor = pos.anchor;
        let seq_eq = || col(current_kv::Column::Seq).eq(anchor.seq);
        let epoch_eq = || col(current_kv::Column::Epoch).eq(anchor.epoch);
        condition = condition.add(
            Condition::any()
                .add(col(current_kv::Column::Seq).gt(anchor.seq))
                .add(
                    Condition::all()
                        .add(seq_eq())
                        .add(col(current_kv::Column::Epoch).gt(anchor.epoch)),
                )
                .add(
                    Condition::all()
                        .add(seq_eq())
                        .add(epoch_eq())
                        .add(col(current_kv::Column::EpochSeq).gt(anchor.epoch_seq)),
                )
                .add(
                    Condition::all()
                        .add(seq_eq())
                        .add(epoch_eq())
                        .add(col(current_kv::Column::EpochSeq).eq(anchor.epoch_seq))
                        .add(key_byte_ordered(backend).gt(pos.key.as_str())),
                ),
        );
    }
    if let Some(floor) = floor {
        condition = condition.add(
            Condition::any()
                .add(col(current_kv::Column::Deleted).eq(false))
                .add(col(current_kv::Column::Seq).gt(floor.seq)),
        );
    }
    let mut query = Query::select();
    query
        .columns([
            (current_kv::Entity, current_kv::Column::Key),
            (current_kv::Entity, current_kv::Column::Seq),
            (current_kv::Entity, current_kv::Column::Epoch),
            (current_kv::Entity, current_kv::Column::EpochSeq),
            (current_kv::Entity, current_kv::Column::Value),
            (current_kv::Entity, current_kv::Column::Metadata),
            (current_kv::Entity, current_kv::Column::Deleted),
        ])
        .from(current_kv::Entity)
        .cond_where(condition)
        .order_by((current_kv::Entity, current_kv::Column::Seq), Order::Asc)
        .order_by((current_kv::Entity, current_kv::Column::Epoch), Order::Asc)
        .order_by(
            (current_kv::Entity, current_kv::Column::EpochSeq),
            Order::Asc,
        )
        .order_by_expr(key_byte_ordered(backend), Order::Asc)
        .limit(limit.saturating_add(1) as u64);
    backend.build(&query)
}

/// Read one page of the feed for `prefix` (non-empty) in `space`.
///
/// `state` is `None` on the first page, which anchors a fresh floor at the
/// space's newest event. Otherwise both the position and floor anchors must
/// name an existing `event_order` row of this space, or the cursor needs a
/// reset: a restore to before the cursor replaces those rows even when an old
/// `current_kv` position happens to survive.
pub(crate) async fn kv_sync_page<C: ConnectionTrait>(
    db: &C,
    space: &SpaceId,
    prefix: &Path,
    limit: usize,
    state: Option<&KvSyncState>,
) -> Result<(Vec<KvSyncChange>, bool, KvSyncState), KvSyncError> {
    let state = match state {
        None => KvSyncState {
            pos: None,
            floor: newest_event(db, space).await?,
        },
        Some(state) => {
            for anchor in state
                .pos
                .as_ref()
                .map(|pos| &pos.anchor)
                .into_iter()
                .chain(state.floor.as_ref())
            {
                if !anchor_exists(db, space, anchor).await? {
                    return Err(KvSyncError::ResetRequired(
                        KvSyncResetReason::PositionUnknown,
                    ));
                }
            }
            state.clone()
        }
    };
    let statement = kv_sync_statement(
        db.get_database_backend(),
        space,
        prefix,
        limit,
        state.pos.as_ref(),
        state.floor.as_ref(),
    );
    let rows = db.query_all(statement).await?;
    let more = rows.len() > limit;
    let mut changes = Vec::with_capacity(rows.len().min(limit));
    let mut last = None;
    for row in rows.into_iter().take(limit) {
        let key: String = row.try_get("", current_kv::Column::Key.as_str())?;
        let anchor = KvSyncAnchor {
            seq: row.try_get("", current_kv::Column::Seq.as_str())?,
            epoch: row.try_get("", current_kv::Column::Epoch.as_str())?,
            epoch_seq: row.try_get("", current_kv::Column::EpochSeq.as_str())?,
        };
        let deleted: bool = row.try_get("", current_kv::Column::Deleted.as_str())?;
        let value = if deleted {
            None
        } else {
            Some((
                row.try_get::<Hash>("", current_kv::Column::Value.as_str())?,
                row.try_get::<Metadata>("", current_kv::Column::Metadata.as_str())?,
            ))
        };
        changes.push(KvSyncChange {
            key: key
                .parse()
                .map_err(|error| DbErr::Custom(format!("invalid persisted KV path: {error}")))?,
            value,
        });
        last = Some(KvSyncPosition { anchor, key });
    }
    let next = match last {
        Some(pos) => KvSyncState {
            pos: Some(pos),
            floor: state.floor,
        },
        None => state,
    };
    Ok((changes, more, next))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::db::{KvInvokeOptions, KvPrecondition, SpaceDatabase};
    use crate::events::{Invocation, TinyCloudInvocation};
    use crate::keys::StaticSecret;
    use crate::storage::memory::{MemoryStaging, MemoryStore};
    use crate::storage::HashBuffer;
    use crate::InvocationOutcome;
    use futures::io::AsyncWriteExt;
    use sea_orm::{
        ActiveModelTrait, ActiveValue::Set, ConnectOptions, Database, DatabaseConnection,
        TransactionTrait,
    };
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicU64, Ordering};
    use tinycloud_auth::resolver::DID_METHODS;
    use tinycloud_auth::resource::Service;
    use tinycloud_auth::ssi::claims::jwt::NumericDate;
    use tinycloud_auth::ssi::dids::{DIDBuf, DIDURLBuf};
    use tinycloud_auth::ssi::jwk::JWK;
    use tinycloud_auth::ssi::ucan::Payload;
    use tinycloud_auth::ucan_capabilities_object::{Ability, Capabilities};

    pub(crate) type TestDb = SpaceDatabase<DatabaseConnection, MemoryStore, StaticSecret>;

    static NONCE: AtomicU64 = AtomicU64::new(0);

    /// A space owner that signs owner-root (proof-less) invocations.
    pub(crate) struct Owner {
        jwk: JWK,
        verification_method: String,
        did: String,
        pub(crate) space: SpaceId,
    }

    /// One KV operation in an owner-root invocation.
    pub(crate) enum Op<'a> {
        Put(&'a str, &'a [u8]),
        PutMeta(&'a str, &'a [u8], &'a [(&'a str, &'a str)]),
        Del(&'a str),
    }

    impl Owner {
        pub(crate) fn generate() -> Self {
            let jwk = JWK::generate_ed25519().unwrap();
            let did = DID_METHODS.generate(&jwk, "key").unwrap().to_string();
            let fragment = did.rsplit_once(':').unwrap().1.to_owned();
            let verification_method = format!("{did}#{fragment}");
            let space = SpaceId::new(did.parse::<DIDBuf>().unwrap(), "files".parse().unwrap());
            Self {
                jwk,
                verification_method,
                did,
                space,
            }
        }

        fn invocation(&self, ops: &[Op<'_>]) -> Invocation {
            let mut caps = Capabilities::new();
            for op in ops {
                let (key, ability) = match op {
                    Op::Put(key, _) | Op::PutMeta(key, _, _) => (key, "tinycloud.kv/put"),
                    Op::Del(key) => (key, "tinycloud.kv/del"),
                };
                let resource = self.space.clone().to_resource(
                    "kv".parse::<Service>().unwrap(),
                    Some(key.parse().unwrap()),
                    None,
                    None,
                );
                caps.with_action(
                    resource.as_uri(),
                    ability.parse::<Ability>().unwrap(),
                    [BTreeMap::<String, serde_json::Value>::new()],
                );
            }
            let expiration = NumericDate::try_from_seconds(
                OffsetDateTime::now_utc().unix_timestamp() as f64 + 1_800.0,
            )
            .unwrap();
            let nonce = format!("urn:tc732:{}", NONCE.fetch_add(1, Ordering::SeqCst));
            let header = Payload {
                issuer: self.verification_method.parse::<DIDURLBuf>().unwrap(),
                audience: self.did.parse::<DIDBuf>().unwrap(),
                not_before: None,
                expiration,
                nonce: Some(nonce),
                facts: Some(Vec::<serde_json::Value>::new()),
                proof: vec![],
                attenuation: caps,
            }
            .sign(self.jwk.get_algorithm().unwrap_or_default(), &self.jwk)
            .unwrap()
            .encode()
            .unwrap();
            Invocation::from_header_ser::<TinyCloudInvocation>(&header).unwrap()
        }
    }

    pub(crate) async fn sqlite_db() -> TestDb {
        SpaceDatabase::new(
            Database::connect(ConnectOptions::new("sqlite::memory:".to_string()))
                .await
                .unwrap(),
            MemoryStore::default(),
            StaticSecret::new([0u8; 32].to_vec()).unwrap(),
        )
        .await
        .unwrap()
    }

    pub(crate) async fn host(db: &TestDb, owner: &Owner) {
        space::ActiveModel {
            id: Set(SpaceIdWrap(owner.space.clone())),
        }
        .insert(db.connection())
        .await
        .unwrap();
    }

    /// Run `ops` as one owner-root invocation with `options`. Returns the
    /// content hashes of its puts; errors are rendered (the error type is
    /// deliberately not `Debug`).
    pub(crate) async fn invoke(
        db: &TestDb,
        owner: &Owner,
        ops: &[Op<'_>],
        options: KvInvokeOptions,
    ) -> Result<Vec<Hash>, String> {
        let mut inputs = std::collections::HashMap::new();
        for op in ops {
            let (key, value, metadata) = match op {
                Op::Put(key, value) => (key, value, &[][..]),
                Op::PutMeta(key, value, metadata) => (key, value, *metadata),
                Op::Del(_) => continue,
            };
            let mut stage = HashBuffer::new(Vec::new());
            stage.write_all(value).await.unwrap();
            let metadata = Metadata(
                metadata
                    .iter()
                    .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
                    .collect(),
            );
            inputs.insert(
                (owner.space.clone(), key.parse::<Path>().unwrap()),
                (metadata, stage),
            );
        }
        let (_, outcomes) = db
            .invoke_with_options::<MemoryStaging>(owner.invocation(ops), inputs, options)
            .await
            .map_err(|error| error.to_string())?;
        Ok(outcomes
            .into_iter()
            .filter_map(|outcome| match outcome {
                InvocationOutcome::KvWrite(hash) => Some(hash),
                _ => None,
            })
            .collect())
    }

    pub(crate) async fn run(db: &TestDb, owner: &Owner, ops: &[Op<'_>]) -> Vec<Hash> {
        invoke(db, owner, ops, KvInvokeOptions::default())
            .await
            .unwrap()
    }

    /// A delivered change: the key and its etag, `None` for a tombstone.
    pub(crate) type Delivered = (String, Option<Hash>);

    /// Read the feed from `state` until it reports no more changes.
    pub(crate) async fn drain<C: ConnectionTrait>(
        conn: &C,
        space: &SpaceId,
        prefix: &str,
        limit: usize,
        state: &mut Option<KvSyncState>,
    ) -> Vec<Delivered> {
        let prefix: Path = prefix.parse().unwrap();
        let mut delivered = Vec::new();
        loop {
            let (changes, more, next) = kv_sync_page(conn, space, &prefix, limit, state.as_ref())
                .await
                .unwrap();
            delivered.extend(
                changes
                    .into_iter()
                    .map(|change| (change.key.to_string(), change.value.map(|(hash, _)| hash))),
            );
            *state = Some(next);
            if !more {
                return delivered;
            }
        }
    }

    fn live(key: &str, value: &[u8]) -> Delivered {
        (key.to_string(), Some(crate::hash::hash(value)))
    }

    fn gone(key: &str) -> Delivered {
        (key.to_string(), None)
    }

    async fn current_row(db: &TestDb, owner: &Owner, key: &str) -> current_kv::Model {
        current_kv::Entity::find_by_id((
            SpaceIdWrap(owner.space.clone()),
            crate::types::Path(key.parse().unwrap()),
        ))
        .one(db.connection())
        .await
        .unwrap()
        .unwrap()
    }

    #[tokio::test]
    async fn kv_sync_orders_puts_overwrites_deletes_and_batches() {
        let db = sqlite_db().await;
        let owner = Owner::generate();
        host(&db, &owner).await;
        let mut state = None;
        assert!(drain(db.connection(), &owner.space, "notes", 2, &mut state)
            .await
            .is_empty());

        run(&db, &owner, &[Op::Put("notes/b", b"b1")]).await;
        run(&db, &owner, &[Op::Put("notes/a", b"a1")]).await;
        assert_eq!(
            drain(db.connection(), &owner.space, "notes", 2, &mut state).await,
            vec![live("notes/b", b"b1"), live("notes/a", b"a1")],
            "commit order, not key order"
        );

        run(&db, &owner, &[Op::Put("notes/b", b"b2")]).await;
        run(&db, &owner, &[Op::Del("notes/a")]).await;
        // One batch: both keys share the invocation's position and are
        // ordered by key within it.
        run(
            &db,
            &owner,
            &[Op::Put("notes/d", b"d1"), Op::Put("notes/c", b"c1")],
        )
        .await;
        for limit in [1, 2, 10] {
            let mut replay = state.clone();
            assert_eq!(
                drain(db.connection(), &owner.space, "notes", limit, &mut replay).await,
                vec![
                    live("notes/b", b"b2"),
                    gone("notes/a"),
                    live("notes/c", b"c1"),
                    live("notes/d", b"d1"),
                ],
                "limit {limit}"
            );
        }
    }

    #[tokio::test]
    async fn kv_delete_records_its_own_position() {
        let db = sqlite_db().await;
        let owner = Owner::generate();
        host(&db, &owner).await;
        run(&db, &owner, &[Op::Put("notes/a", b"a1")]).await;
        let written = current_row(&db, &owner, "notes/a").await;
        run(&db, &owner, &[Op::Del("notes/a")]).await;
        let deleted = current_row(&db, &owner, "notes/a").await;
        let newest = newest_event(db.connection(), &owner.space)
            .await
            .unwrap()
            .unwrap();

        assert!(deleted.deleted);
        assert_eq!(
            (deleted.seq, deleted.epoch, deleted.epoch_seq),
            (newest.seq, newest.epoch, newest.epoch_seq),
            "the tombstone carries the delete's own event position"
        );
        assert!(deleted.seq > written.seq);
        assert_eq!(
            deleted.invocation, written.invocation,
            "the matching-invocation predicate still names the deleted write"
        );
    }

    #[tokio::test]
    async fn same_invocation_delete_then_put_leaves_key_live() {
        let db = sqlite_db().await;
        let owner = Owner::generate();
        host(&db, &owner).await;
        run(&db, &owner, &[Op::Put("notes/a", b"a1")]).await;
        let mut state = None;
        drain(db.connection(), &owner.space, "notes", 10, &mut state).await;

        run(
            &db,
            &owner,
            &[Op::Del("notes/a"), Op::Put("notes/a", b"a2")],
        )
        .await;
        let row = current_row(&db, &owner, "notes/a").await;
        assert!(!row.deleted, "the put in the same invocation wins");
        assert_eq!(row.value, crate::hash::hash(b"a2"));
        assert_eq!(
            drain(db.connection(), &owner.space, "notes", 10, &mut state).await,
            vec![live("notes/a", b"a2")]
        );
    }

    #[tokio::test]
    async fn kv_sync_prefix_is_segment_and_case_exact() {
        let db = sqlite_db().await;
        let owner = Owner::generate();
        host(&db, &owner).await;
        for key in [
            "notes",
            "notes/a",
            "notes-secret/x",
            "notes-secret",
            "notesecret",
            "NOTES/x",
            "Notes/y",
            "notes/b/c",
        ] {
            run(&db, &owner, &[Op::Put(key, key.as_bytes())]).await;
        }
        let keys = |delivered: Vec<Delivered>| {
            delivered
                .into_iter()
                .map(|(key, _)| key)
                .collect::<Vec<_>>()
        };
        assert_eq!(
            keys(drain(db.connection(), &owner.space, "notes", 1, &mut None).await),
            vec!["notes", "notes/a", "notes/b/c"]
        );
        assert_eq!(
            keys(drain(db.connection(), &owner.space, "notes/", 1, &mut None).await),
            vec!["notes/a", "notes/b/c"]
        );
    }

    #[tokio::test]
    async fn kv_sync_bootstrap_skips_pre_floor_tombstones() {
        let db = sqlite_db().await;
        let owner = Owner::generate();
        host(&db, &owner).await;
        run(&db, &owner, &[Op::Put("notes/a", b"a1")]).await;
        run(&db, &owner, &[Op::Put("notes/b", b"b1")]).await;
        run(&db, &owner, &[Op::Del("notes/b")]).await;

        let mut state = None;
        assert_eq!(
            drain(db.connection(), &owner.space, "notes", 10, &mut state).await,
            vec![live("notes/a", b"a1")],
            "a tombstone older than the client's bootstrap is not news to it"
        );
        run(&db, &owner, &[Op::Del("notes/a")]).await;
        run(&db, &owner, &[Op::Put("notes/b", b"b2")]).await;
        assert_eq!(
            drain(db.connection(), &owner.space, "notes", 10, &mut state).await,
            vec![gone("notes/a"), live("notes/b", b"b2")],
            "deletes after the floor are delivered"
        );
    }

    #[tokio::test]
    async fn kv_sync_unknown_position_requires_reset() {
        let db = sqlite_db().await;
        let owner = Owner::generate();
        host(&db, &owner).await;
        run(&db, &owner, &[Op::Put("notes/a", b"a1")]).await;
        let mut state = None;
        drain(db.connection(), &owner.space, "notes", 10, &mut state).await;
        let state = state.unwrap();
        let prefix: Path = "notes".parse().unwrap();

        let foreign = KvSyncAnchor {
            seq: 0,
            epoch: crate::hash::hash(b"an epoch this space never had"),
            epoch_seq: 0,
        };
        let mut unknown_pos = state.clone();
        unknown_pos.pos.as_mut().unwrap().anchor = foreign;
        let mut unknown_floor = state.clone();
        unknown_floor.floor = Some(foreign);
        let other = Owner::generate();
        host(&db, &other).await;
        for (label, space, state) in [
            ("position", &owner.space, &unknown_pos),
            ("floor", &owner.space, &unknown_floor),
            ("another space's cursor", &other.space, &state),
        ] {
            assert!(
                matches!(
                    kv_sync_page(db.connection(), space, &prefix, 10, Some(state)).await,
                    Err(KvSyncError::ResetRequired(
                        KvSyncResetReason::PositionUnknown
                    ))
                ),
                "{label}"
            );
        }
    }

    /// A restore to a backup taken before the client bootstrapped removes the
    /// floor's event even though a later position may survive in
    /// `current_kv`: the cursor must reset rather than resume against a
    /// different history.
    #[tokio::test]
    async fn kv_sync_restored_floor_requires_reset() {
        let db = sqlite_db().await;
        let owner = Owner::generate();
        host(&db, &owner).await;
        run(&db, &owner, &[Op::Put("notes/a", b"a1")]).await;
        let mut state = None;
        drain(db.connection(), &owner.space, "notes", 10, &mut state).await;
        run(&db, &owner, &[Op::Put("notes/b", b"b1")]).await;
        drain(db.connection(), &owner.space, "notes", 10, &mut state).await;
        let state = state.unwrap();
        let floor = state.floor.unwrap();
        assert_ne!(Some(floor), state.pos.as_ref().map(|pos| pos.anchor));

        db.connection()
            .execute(Statement::from_string(
                DbBackend::Sqlite,
                "PRAGMA foreign_keys = OFF",
            ))
            .await
            .unwrap();
        event_order::Entity::delete_by_id((
            floor.epoch,
            floor.epoch_seq,
            SpaceIdWrap(owner.space.clone()),
        ))
        .exec(db.connection())
        .await
        .unwrap();

        assert!(matches!(
            kv_sync_page(
                db.connection(),
                &owner.space,
                &"notes".parse().unwrap(),
                10,
                Some(&state)
            )
            .await,
            Err(KvSyncError::ResetRequired(
                KvSyncResetReason::PositionUnknown
            ))
        ));
    }

    #[tokio::test]
    async fn kv_sync_metadata_only_change_is_delivered() {
        let db = sqlite_db().await;
        let owner = Owner::generate();
        host(&db, &owner).await;
        run(
            &db,
            &owner,
            &[Op::PutMeta(
                "notes/a",
                b"same",
                &[("content-type", "text/plain")],
            )],
        )
        .await;
        let mut state = None;
        drain(db.connection(), &owner.space, "notes", 10, &mut state).await;
        run(
            &db,
            &owner,
            &[Op::PutMeta(
                "notes/a",
                b"same",
                &[("content-type", "text/markdown")],
            )],
        )
        .await;

        let (changes, _, _) = kv_sync_page(
            db.connection(),
            &owner.space,
            &"notes".parse().unwrap(),
            10,
            state.as_ref(),
        )
        .await
        .unwrap();
        assert_eq!(
            changes.len(),
            1,
            "same content, new metadata: still a change"
        );
        let (hash, metadata) = changes[0].value.clone().unwrap();
        assert_eq!(hash, crate::hash::hash(b"same"));
        assert_eq!(
            metadata.0.get("content-type").map(String::as_str),
            Some("text/markdown")
        );
    }

    /// The feed query resolves through `idx_current_kv_space_order` on SQLite.
    #[tokio::test]
    async fn kv_sync_feed_query_uses_the_order_index_on_sqlite() {
        let db = sqlite_db().await;
        let owner = Owner::generate();
        host(&db, &owner).await;
        for index in 0..50 {
            let key = format!("notes/{index:03}");
            run(&db, &owner, &[Op::Put(&key, key.as_bytes())]).await;
        }
        let mut state = None;
        drain(db.connection(), &owner.space, "notes", 10, &mut state).await;
        let state = state.unwrap();
        let statement = kv_sync_statement(
            DbBackend::Sqlite,
            &owner.space,
            &"notes".parse().unwrap(),
            500,
            state.pos.as_ref(),
            state.floor.as_ref(),
        );
        let plan = db
            .connection()
            .query_all(Statement::from_sql_and_values(
                DbBackend::Sqlite,
                format!("EXPLAIN QUERY PLAN {}", statement.sql),
                statement.values.map(|values| values.0).unwrap_or_default(),
            ))
            .await
            .unwrap()
            .into_iter()
            .map(|row| row.try_get::<String>("", "detail").unwrap())
            .collect::<Vec<_>>();
        println!("TC-732 SQLite feed plan:\n  {}", plan.join("\n  "));
        assert!(
            plan.iter().any(|line| line
                .contains(crate::migrations::m20261005_000000_current_kv_sync_order::INDEX_NAME)),
            "{plan:?}"
        );
    }

    // ── PostgreSQL (run in CI's PG16 job; `TINYCLOUD_TEST_POSTGRES_URL`) ──

    /// An isolated schema with `instances` independent `SpaceDatabase`s over
    /// it, each with its own pool (15 connections, the production size) and
    /// its own in-process locks: separate node processes sharing a database.
    struct PostgresFixture {
        admin: DatabaseConnection,
        schema: String,
        dbs: Vec<TestDb>,
    }

    impl PostgresFixture {
        async fn new(test: &str, instances: usize) -> Option<Self> {
            let url = crate::test_support::postgres_test_url(test)?;
            let admin = Database::connect(ConnectOptions::new(url.clone()))
                .await
                .expect("connect to PostgreSQL test database");
            let schema = format!(
                "tc732_{}_{}",
                std::process::id(),
                OffsetDateTime::now_utc().unix_timestamp_nanos()
            );
            admin
                .execute(Statement::from_string(
                    DbBackend::Postgres,
                    format!("CREATE SCHEMA {schema}"),
                ))
                .await
                .expect("create isolated TC-732 schema");
            let mut dbs = Vec::with_capacity(instances);
            for _ in 0..instances {
                let mut options = ConnectOptions::new(url.clone());
                options
                    .max_connections(15)
                    .sqlx_logging(false)
                    .set_schema_search_path(schema.clone());
                dbs.push(
                    SpaceDatabase::new(
                        Database::connect(options)
                            .await
                            .expect("connect to isolated TC-732 schema"),
                        MemoryStore::default(),
                        StaticSecret::new([0u8; 32].to_vec()).unwrap(),
                    )
                    .await
                    .expect("migrate isolated TC-732 schema"),
                );
            }
            Some(Self { admin, schema, dbs })
        }

        async fn drop(self) {
            let Self { admin, schema, dbs } = self;
            drop(dbs);
            admin
                .execute(Statement::from_string(
                    DbBackend::Postgres,
                    format!("DROP SCHEMA {schema} CASCADE"),
                ))
                .await
                .expect("drop isolated TC-732 schema");
        }
    }

    /// `(seq, epoch bytes, epoch_seq, key bytes)`: the order the feed promises.
    fn order_key(pos: &KvSyncPosition) -> (i64, Vec<u8>, i64, Vec<u8>) {
        (
            pos.anchor.seq,
            Vec::<u8>::from(pos.anchor.epoch),
            pos.anchor.epoch_seq,
            pos.key.as_bytes().to_vec(),
        )
    }

    async fn print_postgres_plan(conn: &DatabaseConnection, label: &str, statement: Statement) {
        conn.execute(Statement::from_string(
            DbBackend::Postgres,
            "ANALYZE current_kv",
        ))
        .await
        .unwrap();
        let values = statement.values.map(|values| values.0).unwrap_or_default();
        let explain =
            |sql: String| Statement::from_sql_and_values(DbBackend::Postgres, sql, values.clone());
        let lines = |rows: Vec<sea_orm::QueryResult>| {
            rows.into_iter()
                .map(|row| row.try_get_by_index::<String>(0).unwrap())
                .collect::<Vec<_>>()
                .join("\n  ")
        };
        let plan = conn
            .query_all(explain(format!("EXPLAIN {}", statement.sql)))
            .await
            .unwrap();
        println!("TC-732 PostgreSQL feed plan ({label}):\n  {}", lines(plan));
        // The test tables are small enough that a sequential scan wins; show
        // the plan the index offers once a table is large enough to prefer it.
        let tx = conn.begin().await.unwrap();
        tx.execute(Statement::from_string(
            DbBackend::Postgres,
            "SET LOCAL enable_seqscan = off",
        ))
        .await
        .unwrap();
        let forced = tx
            .query_all(explain(format!("EXPLAIN {}", statement.sql)))
            .await
            .unwrap();
        tx.rollback().await.unwrap();
        println!(
            "TC-732 PostgreSQL feed plan ({label}, enable_seqscan=off):\n  {}",
            lines(forced)
        );
    }

    /// 32 concurrent put/delete writers in one space, spread over two
    /// `SpaceDatabase` instances (so only the database-side lock can order
    /// them), while a feed reader pages one change at a time. Every final
    /// `(key, etag)` reaches the reader exactly once, delivered positions
    /// strictly increase, and no `seq` is shared by two epochs.
    #[tokio::test]
    async fn postgres_same_space_commits_are_seq_ordered() {
        let Some(fixture) =
            PostgresFixture::new("postgres_same_space_commits_are_seq_ordered", 2).await
        else {
            return;
        };
        let owner = std::sync::Arc::new(Owner::generate());
        host(&fixture.dbs[0], &owner).await;

        let exercise = async {
            let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let reader = {
                let conn = fixture.dbs[0].connection().clone();
                let space = owner.space.clone();
                let done = done.clone();
                tokio::spawn(async move {
                    let prefix: Path = "notes".parse().unwrap();
                    let mut state: Option<KvSyncState> = None;
                    let mut log = Vec::new();
                    loop {
                        let finished = done.load(Ordering::SeqCst);
                        let (changes, _, next) =
                            kv_sync_page(&conn, &space, &prefix, 1, state.as_ref())
                                .await
                                .unwrap();
                        let empty = changes.is_empty();
                        if let (Some(change), Some(pos)) = (changes.into_iter().next(), &next.pos) {
                            log.push((
                                pos.clone(),
                                change.key.to_string(),
                                change.value.map(|(hash, _)| hash),
                            ));
                        }
                        state = Some(next);
                        if empty && finished {
                            return log;
                        }
                    }
                })
            };

            let writers = (0..32)
                .map(|writer| {
                    let db = fixture.dbs[writer % 2].clone();
                    let owner = owner.clone();
                    tokio::spawn(async move {
                        for step in 0..6 {
                            let key = format!("notes/w{writer:02}/k{}", step % 3);
                            if step == 4 {
                                let gone = format!("notes/w{writer:02}/k0");
                                run(&db, &owner, &[Op::Del(&gone)]).await;
                            } else {
                                let value = format!("w{writer}-s{step}");
                                run(&db, &owner, &[Op::Put(&key, value.as_bytes())]).await;
                            }
                        }
                    })
                })
                .collect::<Vec<_>>();
            for writer in writers {
                writer.await.unwrap();
            }
            done.store(true, Ordering::SeqCst);
            let log = reader.await.unwrap();

            for pair in log.windows(2) {
                assert!(
                    order_key(&pair[0].0) < order_key(&pair[1].0),
                    "positions must strictly increase: {:?} then {:?}",
                    pair[0].0,
                    pair[1].0
                );
            }
            let truth = current_kv::Entity::find()
                .filter(current_kv::Column::Space.eq(SpaceIdWrap(owner.space.clone())))
                .all(fixture.dbs[0].connection())
                .await
                .unwrap()
                .into_iter()
                .map(|row| (row.key.0.to_string(), (!row.deleted).then_some(row.value)))
                .collect::<BTreeMap<_, _>>();
            assert_eq!(truth.len(), 32 * 3);
            for (key, value) in &truth {
                let seen = log
                    .iter()
                    .filter(|(_, delivered, etag)| delivered == key && etag == value)
                    .count();
                assert_eq!(seen, 1, "{key}: final state delivered {seen} times");
            }
            let replica = log
                .iter()
                .map(|(_, key, etag)| (key.clone(), *etag))
                .collect::<BTreeMap<_, _>>();
            assert_eq!(replica, truth, "the replica converged on the space");

            let shared = fixture.dbs[0]
                .connection()
                .query_one(Statement::from_sql_and_values(
                    DbBackend::Postgres,
                    "SELECT COUNT(*) AS n FROM (SELECT seq FROM event_order WHERE space = $1 \
                     GROUP BY seq HAVING COUNT(DISTINCT epoch) > 1) shared",
                    [SpaceIdWrap(owner.space.clone()).into()],
                ))
                .await
                .unwrap()
                .unwrap()
                .try_get::<i64>("", "n")
                .unwrap();
            assert_eq!(shared, 0, "no seq may be shared across epochs");

            let state = log.last().map(|(pos, _, _)| pos.clone());
            print_postgres_plan(
                fixture.dbs[0].connection(),
                "C collation, mid-feed cursor",
                kv_sync_statement(
                    DbBackend::Postgres,
                    &owner.space,
                    &"notes".parse().unwrap(),
                    500,
                    state.as_ref(),
                    None,
                ),
            )
            .await;
        };
        let outcome = tokio::time::timeout(std::time::Duration::from_secs(120), exercise).await;
        fixture.drop().await;
        outcome.expect("concurrent writers and the feed reader finished");
    }

    /// The sequence lock is per space: a transaction holding space A's lock
    /// stalls a write to A but not a write to B.
    #[tokio::test]
    async fn postgres_cross_space_writes_do_not_wait() {
        let Some(fixture) =
            PostgresFixture::new("postgres_cross_space_writes_do_not_wait", 1).await
        else {
            return;
        };
        let db = fixture.dbs[0].clone();
        let (a, b) = (
            std::sync::Arc::new(Owner::generate()),
            std::sync::Arc::new(Owner::generate()),
        );
        host(&db, &a).await;
        host(&db, &b).await;

        let exercise = async {
            let holder = db.connection().begin().await.unwrap();
            lock_space_sequences(&holder, [&a.space]).await.unwrap();

            let other = {
                let (db, b) = (db.clone(), b.clone());
                tokio::spawn(async move { run(&db, &b, &[Op::Put("notes/x", b"b")]).await })
            };
            tokio::time::timeout(std::time::Duration::from_secs(10), other)
                .await
                .expect("a write to another space must not wait on space A's lock")
                .unwrap();

            let mut same = {
                let (db, a) = (db.clone(), a.clone());
                tokio::spawn(async move { run(&db, &a, &[Op::Put("notes/x", b"a")]).await })
            };
            assert!(
                tokio::time::timeout(std::time::Duration::from_millis(500), &mut same)
                    .await
                    .is_err(),
                "a write to space A must wait for A's sequence lock"
            );
            holder.commit().await.unwrap();
            tokio::time::timeout(std::time::Duration::from_secs(10), same)
                .await
                .expect("the write to A proceeds once the lock is released")
                .unwrap();
        };
        let outcome = tokio::time::timeout(std::time::Duration::from_secs(60), exercise).await;
        fixture.drop().await;
        outcome.expect("cross-space lock exercise finished");
    }

    /// Conditional writes run under READ COMMITTED behind the sequence lock.
    /// Concurrent creates (and concurrent replaces against one etag) on one
    /// key, across two node instances, admit exactly one winner; every loser
    /// is a precondition failure, never a false success.
    #[tokio::test]
    async fn postgres_conditional_put_is_atomic_under_concurrency() {
        let Some(fixture) =
            PostgresFixture::new("postgres_conditional_put_is_atomic_under_concurrency", 2).await
        else {
            return;
        };
        let owner = std::sync::Arc::new(Owner::generate());
        host(&fixture.dbs[0], &owner).await;
        let key: Path = "notes/x".parse().unwrap();

        let race = |precondition: KvPrecondition, round: &'static str| {
            let tasks = (0..16)
                .map(|contender| {
                    let db = fixture.dbs[contender % 2].clone();
                    let owner = owner.clone();
                    let key = key.clone();
                    tokio::spawn(async move {
                        let mut options = KvInvokeOptions::default();
                        options
                            .preconditions
                            .insert((owner.space.clone(), key), precondition);
                        let value = format!("{round}-{contender}");
                        invoke(
                            &db,
                            &owner,
                            &[Op::Put("notes/x", value.as_bytes())],
                            options,
                        )
                        .await
                        .map(|hashes| hashes[0])
                    })
                })
                .collect::<Vec<_>>();
            async move {
                let mut winners = Vec::new();
                for task in tasks {
                    match task.await.unwrap() {
                        Ok(hash) => winners.push(hash),
                        Err(error) => assert!(
                            error.contains("precondition"),
                            "{round}: a loser must fail its precondition, got {error}"
                        ),
                    }
                }
                winners
            }
        };

        let exercise = async {
            let created = race(KvPrecondition::DoesNotExist, "create").await;
            assert_eq!(created.len(), 1, "exactly one create wins: {created:?}");
            let replaced = race(
                KvPrecondition::Matches(created[0].as_ref().try_into().unwrap()),
                "replace",
            )
            .await;
            assert_eq!(replaced.len(), 1, "exactly one replace wins: {replaced:?}");
            let row = current_kv::Entity::find_by_id((
                SpaceIdWrap(owner.space.clone()),
                crate::types::Path(key.clone()),
            ))
            .one(fixture.dbs[0].connection())
            .await
            .unwrap()
            .unwrap();
            assert_eq!(row.value, replaced[0]);
        };
        let outcome = tokio::time::timeout(std::time::Duration::from_secs(120), exercise).await;
        fixture.drop().await;
        outcome.expect("conditional put races finished");
    }

    /// Feed paging compares and orders keys in byte order inside SQL, so a
    /// linguistic `current_kv.key` collation cannot skip or repeat a key that
    /// shares its position with others (one batch put).
    #[tokio::test]
    async fn postgres_kv_sync_paging_survives_hostile_collation() {
        let Some(fixture) =
            PostgresFixture::new("postgres_kv_sync_paging_survives_hostile_collation", 1).await
        else {
            return;
        };
        let db = fixture.dbs[0].clone();
        let owner = Owner::generate();
        host(&db, &owner).await;

        let exercise: Result<(), Box<dyn std::error::Error + Send + Sync>> = async {
            db.connection()
                .execute(Statement::from_string(
                    DbBackend::Postgres,
                    "CREATE COLLATION tc732_linguistic (provider = icu, locale = 'en')",
                ))
                .await?;
            db.connection()
                .execute(Statement::from_string(
                    DbBackend::Postgres,
                    "ALTER TABLE current_kv ALTER COLUMN key TYPE character varying \
                     COLLATE tc732_linguistic",
                ))
                .await?;
            let keys = [
                "docs/b",
                "docs/B",
                "docs",
                "docs/a",
                "docsecret/x",
                "DOCS/x",
                "docs-x",
            ];
            let ops = keys
                .iter()
                .map(|key| Op::Put(key, key.as_bytes()))
                .collect::<Vec<_>>();
            run(&db, &owner, &ops).await;
            let column_order = db
                .connection()
                .query_all(Statement::from_string(
                    DbBackend::Postgres,
                    "SELECT key FROM current_kv WHERE key IN ('docs/b', 'docs/B') ORDER BY key",
                ))
                .await?
                .into_iter()
                .map(|row| row.try_get::<String>("", "key"))
                .collect::<Result<Vec<_>, _>>()?;
            assert_eq!(
                column_order,
                vec!["docs/b", "docs/B"],
                "the linguistic collation must disagree with byte order"
            );

            for limit in [1, 2, 3] {
                let delivered = drain(db.connection(), &owner.space, "docs", limit, &mut None)
                    .await
                    .into_iter()
                    .map(|(key, _)| key)
                    .collect::<Vec<_>>();
                assert_eq!(
                    delivered,
                    vec!["docs", "docs/B", "docs/a", "docs/b"],
                    "limit {limit}: byte order within one position"
                );
            }
            let mut state = None;
            drain(db.connection(), &owner.space, "docs", 1, &mut state).await;
            let state = state.unwrap();
            print_postgres_plan(
                db.connection(),
                "linguistic key collation",
                kv_sync_statement(
                    DbBackend::Postgres,
                    &owner.space,
                    &"docs".parse().unwrap(),
                    500,
                    state.pos.as_ref(),
                    state.floor.as_ref(),
                ),
            )
            .await;
            Ok(())
        }
        .await;
        fixture.drop().await;
        exercise.expect("TC-732 PostgreSQL collation resilience");
    }
}
