//! TC-732: the ordered, prefix-scoped KV change feed behind `tinycloud.kv/sync`,
//! and the per-space sequence lock that makes `event_order.seq` commit-ordered.
//!
//! # Why `current_kv` is a complete feed
//!
//! `current_kv` keeps one row per key, including a permanent tombstone for
//! every deleted key, and `invocation::save` is its only writer. Each row
//! carries the position `(seq, epoch, epoch_seq)` of the key's last visible
//! change: a write's own position, or -- since TC-732 -- the position of the
//! delete that tombstoned it. Ordering rows by that position is therefore a
//! replayable feed of each key's latest state.
//!
//! # Pages never split an event
//!
//! Every row an invocation touches shares the invocation's position, so a
//! position names a *group* of rows. A page always ends on a whole group and
//! the cursor stores only the last group's position, never a key: its size is
//! constant however long the keys are. A page therefore holds at least
//! `limit` rows when more are available, and at most `limit - 1` plus the size
//! of its last group. A group is at most one invocation's KV operations, which
//! `db::KV_MAX_MUTATIONS_PER_INVOCATION` caps for every write since TC-732;
//! earlier groups were bounded only by the request size the transport
//! admitted. Within a page, rows of one group are ordered by key bytes.
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
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use rand::{rngs::OsRng, RngCore};
use sea_orm::{
    entity::prelude::*,
    sea_query::{Expr, Order, Query, SelectStatement},
    Condition, ConnectionTrait, DbBackend, QueryOrder, QueryResult, QuerySelect, Statement,
};
use serde::{Deserialize, Serialize};
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
#[doc(hidden)]
pub fn space_sequence_lock_key(space: &SpaceId) -> i64 {
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

/// `lock_space_sequences` on a transaction that has already taken the
/// sequence locks of `held` with `lock_space_sequences`.
///
/// PostgreSQL's transaction-level advisory locks are re-entrant and are held
/// until the transaction ends, so asking again for a key this transaction
/// holds returns at once and changes nothing: it is only a round-trip. Those
/// keys are skipped; every other key is taken exactly as `lock_space_sequences`
/// would, in the same ascending order. MySQL (row locks, which depend on the
/// space row existing when asked) and SQLite (no-op) are unchanged.
pub async fn lock_space_sequences_not_held<'a, C: ConnectionTrait>(
    db: &C,
    spaces: impl IntoIterator<Item = &'a SpaceId>,
    held: &[SpaceId],
) -> Result<(), DbErr> {
    match db.get_database_backend() {
        DbBackend::Postgres => {
            let held = held
                .iter()
                .map(space_sequence_lock_key)
                .collect::<std::collections::BTreeSet<_>>();
            let spaces = spaces
                .into_iter()
                .filter(|space| !held.contains(&space_sequence_lock_key(space)))
                .collect::<Vec<_>>();
            // Advisory locks are only deadlock-free when every transaction
            // takes them in one global ascending order. Keys taken here come
            // after the held ones, so they must all sort above them; today the
            // only non-empty caller holds every key it asks for.
            debug_assert!(
                spaces
                    .iter()
                    .map(|space| space_sequence_lock_key(space))
                    .min()
                    .zip(held.last())
                    .is_none_or(|(next, held)| next > *held),
                "sequence locks not held must sort above the held ones"
            );
            lock_space_sequences(db, spaces).await
        }
        DbBackend::Sqlite | DbBackend::MySql => lock_space_sequences(db, spaces).await,
    }
}

/// A position in a space's event order: one `event_order` row, i.e. one
/// event. Every row a KV invocation touches shares its event's position.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KvSyncAnchor {
    pub seq: i64,
    pub epoch: Hash,
    pub epoch_seq: i64,
}

/// Decoded cursor state. `pos` is the last event whose changes were all
/// delivered (none before the first change). `floor` is the space's newest
/// event when the client first bootstrapped: tombstones at or below it
/// predate the client and are skipped.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct KvSyncState {
    pub pos: Option<KvSyncAnchor>,
    pub floor: Option<KvSyncAnchor>,
}

/// A `tinycloud.kv/sync` request's parameters, as the route received them.
/// The cursor stays sealed until the invocation is authorized, so an
/// unauthorized caller learns nothing about it (401/403, never 410).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KvSyncRequest {
    /// Page size, `1..=KV_SYNC_MAX_LIMIT`; see the module docs for how a
    /// page's last event can extend it.
    pub limit: usize,
    /// The request's `x-tinycloud-cursor`, verbatim; `None` on the first
    /// page. The route has only checked that it is well formed.
    pub cursor: Option<String>,
    /// The node-local key cursors are sealed under.
    pub cursor_key: [u8; 32],
    /// CID of a `tinycloud.kv/retain` delegation presented for retention.
    pub retention_grant: Option<Hash>,
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
/// the invocation's proofs rest on (`None` when nothing in the closure sets
/// one, e.g. an owner invoking directly).
///
/// `retain_until` is the earliest `exp` in the presented retention grant's own
/// proof closure. `None` means no retention: either no grant was presented,
/// or the grant's chain sets no `exp` at all, which is deliberately treated as
/// granting none rather than unbounded retention.
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
    /// The opaque cursor to return: the request's own cursor, byte for byte,
    /// when `changes` is empty.
    pub cursor: String,
    pub authority: KvSyncAuthority,
    /// The node identity `/info` advertises, filled in by the HTTP layer.
    pub node_did: Option<String>,
}

/// Longest cursor header accepted, in characters. A cursor holds two fixed
/// size positions, so every cursor the node mints is far shorter.
pub const KV_SYNC_CURSOR_MAX_LEN: usize = 4096;
/// Cursor plaintext version. Version 1 carried the last key and is refused.
const KV_SYNC_CURSOR_VERSION: u8 = 2;
const CURSOR_NONCE_LEN: usize = 24;
const CURSOR_AAD_DOMAIN: &[u8] = b"tinycloud.kv/sync\0";

/// One position in the sealed cursor. `seq` and `epoch_seq` are 16 hex
/// digits (the `i64`'s bits, big-endian) and the epoch is always a 34-byte
/// multihash, so every cursor of one shape seals to the same length: its
/// size reveals nothing about how busy the space is.
#[derive(Serialize, Deserialize)]
struct WireAnchor {
    seq: String,
    /// Hex of the epoch's multihash bytes.
    epoch: String,
    epoch_seq: String,
}

#[derive(Serialize, Deserialize)]
struct WireCursor {
    v: u8,
    pos: Option<WireAnchor>,
    floor: Option<WireAnchor>,
}

fn fixed_width(value: i64) -> String {
    format!("{:016x}", value as u64)
}

fn from_fixed_width(value: &str) -> Option<i64> {
    (value.len() == 16)
        .then(|| u64::from_str_radix(value, 16).ok())
        .flatten()
        .map(|bits| bits as i64)
}

impl From<&KvSyncAnchor> for WireAnchor {
    fn from(anchor: &KvSyncAnchor) -> Self {
        Self {
            seq: fixed_width(anchor.seq),
            epoch: hex::encode(Vec::<u8>::from(anchor.epoch)),
            epoch_seq: fixed_width(anchor.epoch_seq),
        }
    }
}

impl WireAnchor {
    fn decode(self) -> Option<KvSyncAnchor> {
        Some(KvSyncAnchor {
            seq: from_fixed_width(&self.seq)?,
            epoch: Hash::try_from(hex::decode(self.epoch).ok()?).ok()?,
            epoch_seq: from_fixed_width(&self.epoch_seq)?,
        })
    }
}

/// Why a cursor header was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KvSyncCursorError {
    /// Not a cursor at all: empty, oversized, or not base64url. A 400.
    Malformed,
    /// Well formed but not minted by this node, for this space and prefix,
    /// at this cursor version. A 410 `RESET_REQUIRED`.
    Invalid,
}

/// Whether `value` has the shape of a cursor. Checking this needs no key and
/// reveals nothing, so the route rejects a malformed header (400) before
/// authorization; authenticating it waits until after authorization.
pub fn kv_sync_cursor_is_well_formed(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= KV_SYNC_CURSOR_MAX_LEN
        && URL_SAFE_NO_PAD
            .decode(value)
            .is_ok_and(|bytes| bytes.len() > CURSOR_NONCE_LEN)
}

/// `"tinycloud.kv/sync\0" || space || "\0" || prefix`: the cursor's AAD.
fn cursor_aad(space: &SpaceId, prefix: &Path) -> Vec<u8> {
    let mut aad = CURSOR_AAD_DOMAIN.to_vec();
    aad.extend_from_slice(space.to_string().as_bytes());
    aad.push(0);
    aad.extend_from_slice(prefix.as_str().as_bytes());
    aad
}

fn seal_cursor(
    key: &[u8; 32],
    space: &SpaceId,
    prefix: &Path,
    plaintext: &[u8],
) -> Result<String, DbErr> {
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| DbErr::Custom("kv/sync cursor key".to_string()))?;
    let mut nonce = [0u8; CURSOR_NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let aad = cursor_aad(space, prefix);
    let ciphertext = cipher
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| DbErr::Custom("kv/sync cursor sealing".to_string()))?;
    let mut bytes = nonce.to_vec();
    bytes.extend_from_slice(&ciphertext);
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

/// Seal `state` into an opaque cursor for `space`/`prefix`:
/// `base64url(nonce[24] || XChaCha20-Poly1305(plaintext))` with plaintext
/// `{v:2, pos:{seq,epoch,epoch_seq}|null, floor:{seq,epoch,epoch_seq}|null}`,
/// numbers fixed-width (see `WireAnchor`). Its length depends only on which
/// of `pos` and `floor` are present: not on any key, nor on any position.
pub fn encode_kv_sync_cursor(
    key: &[u8; 32],
    space: &SpaceId,
    prefix: &Path,
    state: &KvSyncState,
) -> Result<String, DbErr> {
    let wire = WireCursor {
        v: KV_SYNC_CURSOR_VERSION,
        pos: state.pos.as_ref().map(WireAnchor::from),
        floor: state.floor.as_ref().map(WireAnchor::from),
    };
    let plaintext = serde_json::to_vec(&wire)
        .map_err(|error| DbErr::Custom(format!("kv/sync cursor encoding: {error}")))?;
    seal_cursor(key, space, prefix, &plaintext)
}

/// Open a cursor minted for `space`/`prefix` under `key`.
pub fn decode_kv_sync_cursor(
    key: &[u8; 32],
    value: &str,
    space: &SpaceId,
    prefix: &Path,
) -> Result<KvSyncState, KvSyncCursorError> {
    if !kv_sync_cursor_is_well_formed(value) {
        return Err(KvSyncCursorError::Malformed);
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| KvSyncCursorError::Malformed)?;
    let (nonce, ciphertext) = bytes.split_at(CURSOR_NONCE_LEN);
    let nonce: [u8; CURSOR_NONCE_LEN] =
        nonce.try_into().map_err(|_| KvSyncCursorError::Malformed)?;
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| KvSyncCursorError::Invalid)?;
    let aad = cursor_aad(space, prefix);
    let plaintext = cipher
        .decrypt(
            &XNonce::from(nonce),
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| KvSyncCursorError::Invalid)?;
    let wire: WireCursor =
        serde_json::from_slice(&plaintext).map_err(|_| KvSyncCursorError::Invalid)?;
    if wire.v != KV_SYNC_CURSOR_VERSION {
        return Err(KvSyncCursorError::Invalid);
    }
    let decode = |anchor: Option<WireAnchor>| {
        anchor
            .map(|anchor| anchor.decode().ok_or(KvSyncCursorError::Invalid))
            .transpose()
    };
    Ok(KvSyncState {
        pos: decode(wire.pos)?,
        floor: decode(wire.floor)?,
    })
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

fn col(column: current_kv::Column) -> Expr {
    Expr::col((current_kv::Entity, column))
}

/// `(seq, epoch, epoch_seq)` as one row value.
fn position_columns() -> Expr {
    Expr::tuple([
        col(current_kv::Column::Seq).into(),
        col(current_kv::Column::Epoch).into(),
        col(current_kv::Column::EpochSeq).into(),
    ])
}

fn position_value(anchor: &KvSyncAnchor) -> Expr {
    Expr::tuple([
        Expr::val(anchor.seq).into(),
        Expr::val(anchor.epoch).into(),
        Expr::val(anchor.epoch_seq).into(),
    ])
}

/// The rows of `space` inside `prefix`, minus tombstones at or below
/// `floor.seq`, with the feed's columns.
fn feed_select(
    backend: DbBackend,
    space: &SpaceId,
    prefix: &Path,
    floor: Option<&KvSyncAnchor>,
) -> SelectStatement {
    let mut condition =
        Condition::all().add(col(current_kv::Column::Space).eq(SpaceIdWrap(space.clone())));
    if let Some(prefix) = crate::db::kv_prefix_condition(backend, prefix.as_str()) {
        condition = condition.add(prefix);
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
        .cond_where(condition);
    query
}

/// The feed query: rows in `prefix` at positions strictly after `pos`, in
/// position order, at most `limit + 1` of them.
///
/// `seq >= pos.seq` is redundant with the row comparison but gives every
/// planner a plain range on the second column of `idx_current_kv_space_order`
/// to seek on, so a caught-up poll touches only the rows after its cursor.
/// The order is exactly the index order after `space`, so no sort is needed;
/// keys are ordered within a group after the read (see `kv_sync_page`).
pub(crate) fn kv_sync_statement(
    backend: DbBackend,
    space: &SpaceId,
    prefix: &Path,
    limit: usize,
    pos: Option<&KvSyncAnchor>,
    floor: Option<&KvSyncAnchor>,
) -> Statement {
    let mut query = feed_select(backend, space, prefix, floor);
    if let Some(pos) = pos {
        query
            .and_where(col(current_kv::Column::Seq).gte(pos.seq))
            .and_where(position_columns().gt(position_value(pos)));
    }
    query
        .order_by((current_kv::Entity, current_kv::Column::Seq), Order::Asc)
        .order_by((current_kv::Entity, current_kv::Column::Epoch), Order::Asc)
        .order_by(
            (current_kv::Entity, current_kv::Column::EpochSeq),
            Order::Asc,
        )
        .limit(limit.saturating_add(1) as u64);
    backend.build(&query)
}

/// Every row of one event (`group`) inside `prefix`.
fn kv_sync_group_statement(
    backend: DbBackend,
    space: &SpaceId,
    prefix: &Path,
    group: &KvSyncAnchor,
    floor: Option<&KvSyncAnchor>,
) -> Statement {
    let mut query = feed_select(backend, space, prefix, floor);
    query.and_where(position_columns().eq(position_value(group)));
    backend.build(&query)
}

struct FeedRow {
    key: String,
    anchor: KvSyncAnchor,
    value: Option<(Hash, Metadata)>,
}

fn feed_row(row: QueryResult) -> Result<FeedRow, DbErr> {
    let deleted: bool = row.try_get("", current_kv::Column::Deleted.as_str())?;
    Ok(FeedRow {
        key: row.try_get("", current_kv::Column::Key.as_str())?,
        anchor: KvSyncAnchor {
            seq: row.try_get("", current_kv::Column::Seq.as_str())?,
            epoch: row.try_get("", current_kv::Column::Epoch.as_str())?,
            epoch_seq: row.try_get("", current_kv::Column::EpochSeq.as_str())?,
        },
        value: if deleted {
            None
        } else {
            Some((
                row.try_get("", current_kv::Column::Value.as_str())?,
                row.try_get("", current_kv::Column::Metadata.as_str())?,
            ))
        },
    })
}

async fn feed_rows<C: ConnectionTrait>(
    db: &C,
    statement: Statement,
) -> Result<Vec<FeedRow>, DbErr> {
    db.query_all(statement)
        .await?
        .into_iter()
        .map(feed_row)
        .collect()
}

/// Read one page of the feed for `prefix` (non-empty) in `space`.
///
/// `state` is `None` on the first page, which anchors a fresh floor at the
/// space's newest event. Otherwise both the position and floor anchors must
/// name an existing `event_order` row of this space, or the cursor needs a
/// reset: a restore to before the cursor replaces those rows even when an old
/// `current_kv` position happens to survive.
///
/// The page ends on a whole event: when the `limit`-th row's event continues
/// past it, the rest of that event joins the page (see the module docs). If
/// every row of that event moves to a newer position between the two reads,
/// the page can come back empty with `more` set; the next poll progresses.
pub(crate) async fn kv_sync_page<C: ConnectionTrait>(
    db: &C,
    space: &SpaceId,
    prefix: &Path,
    limit: usize,
    state: Option<&KvSyncState>,
) -> Result<(Vec<KvSyncChange>, bool, KvSyncState), KvSyncError> {
    let limit = limit.max(1);
    let state = match state {
        None => KvSyncState {
            pos: None,
            floor: newest_event(db, space).await?,
        },
        Some(state) => {
            for anchor in state.pos.iter().chain(state.floor.iter()) {
                if !anchor_exists(db, space, anchor).await? {
                    return Err(KvSyncError::ResetRequired(
                        KvSyncResetReason::PositionUnknown,
                    ));
                }
            }
            state.clone()
        }
    };
    let backend = db.get_database_backend();
    let floor = state.floor.as_ref();
    let mut rows = feed_rows(
        db,
        kv_sync_statement(backend, space, prefix, limit, state.pos.as_ref(), floor),
    )
    .await?;
    let more = if rows.len() <= limit {
        false
    } else {
        let last = rows[limit - 1].anchor;
        if rows[limit].anchor == last {
            // The page would split `last`: take the whole event instead.
            rows.retain(|row| row.anchor != last);
            rows.extend(
                feed_rows(
                    db,
                    kv_sync_group_statement(backend, space, prefix, &last, floor),
                )
                .await?,
            );
            !feed_rows(
                db,
                kv_sync_statement(backend, space, prefix, 1, Some(&last), floor),
            )
            .await?
            .is_empty()
        } else {
            rows.truncate(limit);
            true
        }
    };
    // Rows arrive in position order; order each event's rows by key bytes.
    let mut group = 0usize;
    let mut previous = None;
    let mut ordered = rows
        .into_iter()
        .map(|row| {
            if previous != Some(row.anchor) {
                group += 1;
                previous = Some(row.anchor);
            }
            (group, row)
        })
        .collect::<Vec<_>>();
    ordered.sort_by(|(left_group, left), (right_group, right)| {
        left_group
            .cmp(right_group)
            .then_with(|| left.key.as_bytes().cmp(right.key.as_bytes()))
    });
    let next = KvSyncState {
        pos: previous.or(state.pos),
        floor: state.floor,
    };
    let changes = ordered
        .into_iter()
        .map(|(_, row)| {
            Ok(KvSyncChange {
                key: row.key.parse().map_err(|error| {
                    DbErr::Custom(format!("invalid persisted KV path: {error}"))
                })?,
                value: row.value,
            })
        })
        .collect::<Result<Vec<_>, DbErr>>()?;
    Ok((changes, more, next))
}

/// Serve one `kv/sync` page for an already-authorized request: open its
/// cursor, read the page, and mint the next cursor (or echo the request's
/// own, byte for byte, when nothing changed).
pub(crate) async fn kv_sync_read<C: ConnectionTrait>(
    db: &C,
    space: &SpaceId,
    prefix: &Path,
    request: &KvSyncRequest,
) -> Result<(Vec<KvSyncChange>, bool, String), KvSyncError> {
    let state = request
        .cursor
        .as_deref()
        .map(|cursor| {
            decode_kv_sync_cursor(&request.cursor_key, cursor, space, prefix)
                .map_err(|_| KvSyncError::ResetRequired(KvSyncResetReason::CursorInvalid))
        })
        .transpose()?;
    let (changes, more, next) =
        kv_sync_page(db, space, prefix, request.limit, state.as_ref()).await?;
    let cursor = match (&request.cursor, changes.is_empty()) {
        (Some(cursor), true) => cursor.clone(),
        _ => encode_kv_sync_cursor(&request.cursor_key, space, prefix, &next)?,
    };
    Ok((changes, more, cursor))
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
        /// A read: it goes through the read-audit pipeline (TC-1317).
        Get(&'a str),
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

        /// Another space of this owner: it is the root authority there too.
        fn space_named(&self, name: &str) -> SpaceId {
            SpaceId::new(self.did.parse::<DIDBuf>().unwrap(), name.parse().unwrap())
        }

        /// One owner-root invocation of `ops`, each in the space it names.
        fn invocation_in(&self, ops: &[(&SpaceId, &Op<'_>)]) -> Invocation {
            let mut caps = Capabilities::new();
            for (space, op) in ops {
                let (key, ability) = match op {
                    Op::Put(key, _) | Op::PutMeta(key, _, _) => (key, "tinycloud.kv/put"),
                    Op::Del(key) => (key, "tinycloud.kv/del"),
                    Op::Get(key) => (key, "tinycloud.kv/get"),
                };
                let resource = (*space).clone().to_resource(
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
        host_space(db, &owner.space).await;
    }

    async fn host_space(db: &TestDb, space: &SpaceId) {
        space::ActiveModel {
            id: Set(SpaceIdWrap(space.clone())),
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
        let ops = ops.iter().map(|op| (&owner.space, op)).collect::<Vec<_>>();
        invoke_in(db, owner, &ops, options).await
    }

    /// `invoke` with each operation in the space it names, all of them
    /// spaces of `owner`.
    async fn invoke_in(
        db: &TestDb,
        owner: &Owner,
        ops: &[(&SpaceId, &Op<'_>)],
        options: KvInvokeOptions,
    ) -> Result<Vec<Hash>, String> {
        let mut inputs = std::collections::HashMap::new();
        for (space, op) in ops {
            let (key, value, metadata) = match op {
                Op::Put(key, value) => (key, value, &[][..]),
                Op::PutMeta(key, value, metadata) => (key, value, *metadata),
                Op::Del(_) | Op::Get(_) => continue,
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
                ((*space).clone(), key.parse::<Path>().unwrap()),
                (metadata, stage),
            );
        }
        let (_, outcomes) = db
            .invoke_with_options::<MemoryStaging>(owner.invocation_in(ops), inputs, options)
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

    /// TC-1317: with the read-audit drain held, a KV read answers busy at
    /// its bound without returning data, while KV writes, which are not
    /// audited reads, are unaffected.
    #[tokio::test]
    async fn tc1317_a_held_read_audit_bounds_reads_and_spares_writes() {
        let db = sqlite_db().await;
        db.set_read_audit_wait(std::time::Duration::from_millis(200));
        let owner = Owner::generate();
        host(&db, &owner).await;
        run(&db, &owner, &[Op::Put("notes/a", b"a")]).await;

        let held = db.read_audit_pipeline().hold_drain().await;
        let read = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            invoke(
                &db,
                &owner,
                &[Op::Get("notes/a")],
                KvInvokeOptions::default(),
            ),
        )
        .await
        .expect("a read must not wait past its bound");
        let error = read.expect_err("a read whose audit is not confirmed must fail");
        assert!(error.starts_with("read_audit_busy:"), "{error}");
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            invoke(
                &db,
                &owner,
                &[Op::Put("notes/b", b"b")],
                KvInvokeOptions::default(),
            ),
        )
        .await
        .expect("a write does not wait on the read audit")
        .unwrap();
        drop(held);
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
        unknown_pos.pos = Some(foreign);
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
        assert_ne!(Some(floor), state.pos);

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
        // A range seek on `seq` in the order index, not a scan of the space,
        // and the index order serves ORDER BY (no temp B-tree).
        let index = crate::migrations::m20261005_000000_current_kv_sync_order::INDEX_NAME;
        assert!(
            plan.iter()
                .any(|line| line.contains(&format!("USING INDEX {index} (space=? AND seq>"))),
            "{plan:?}"
        );
        assert!(
            !plan.iter().any(|line| line.contains("TEMP B-TREE")),
            "{plan:?}"
        );
    }

    /// A batch invocation with more operations than `limit` is delivered in
    /// one page, whole; the pages around it neither skip nor repeat a row.
    #[tokio::test]
    async fn kv_sync_page_never_splits_an_event() {
        let db = sqlite_db().await;
        let owner = Owner::generate();
        host(&db, &owner).await;
        run(&db, &owner, &[Op::Put("notes/before", b"0")]).await;
        let batch = ["notes/e", "notes/a", "notes/d", "notes/b", "notes/c"];
        run(&db, &owner, &batch.map(|key| Op::Put(key, key.as_bytes()))).await;
        run(&db, &owner, &[Op::Put("notes/after-1", b"1")]).await;
        run(&db, &owner, &[Op::Put("notes/after-2", b"2")]).await;

        let prefix: Path = "notes".parse().unwrap();
        let expected = [
            "notes/before",
            "notes/a",
            "notes/b",
            "notes/c",
            "notes/d",
            "notes/e",
            "notes/after-1",
            "notes/after-2",
        ];
        for limit in [1, 2, 3, 10] {
            let mut state = Some(KvSyncState::default());
            let mut pages = Vec::new();
            loop {
                let (changes, more, next) = kv_sync_page(
                    db.connection(),
                    &owner.space,
                    &prefix,
                    limit,
                    state.as_ref(),
                )
                .await
                .unwrap();
                pages.push(
                    changes
                        .into_iter()
                        .map(|change| change.key.to_string())
                        .collect::<Vec<_>>(),
                );
                state = Some(next);
                if !more {
                    break;
                }
                assert!(pages.len() < 10, "limit {limit}: no end: {pages:?}");
            }
            assert_eq!(
                pages.concat(),
                expected,
                "limit {limit}: every row once, in order: {pages:?}"
            );
            assert!(
                pages
                    .iter()
                    .any(|page| batch.iter().all(|key| page.iter().any(|k| k == key))),
                "limit {limit}: the batch is split across pages: {pages:?}"
            );
            if limit == 2 {
                assert_eq!(
                    pages,
                    vec![expected[..6].to_vec(), expected[6..].to_vec()],
                    "the batch joins the page its first row lands on"
                );
            }
        }
    }

    /// Core refuses an invocation over the mutation cap before any work, so
    /// every entry point (not just the route) bounds a feed event.
    #[tokio::test]
    async fn kv_invocation_over_the_mutation_cap_is_refused() {
        let db = sqlite_db().await;
        let owner = Owner::generate();
        host(&db, &owner).await;
        let keys = (0..=crate::db::KV_MAX_MUTATIONS_PER_INVOCATION)
            .map(|index| format!("notes/{index}"))
            .collect::<Vec<_>>();
        let ops = keys.iter().map(|key| Op::Del(key)).collect::<Vec<_>>();
        let error = invoke(&db, &owner, &ops, KvInvokeOptions::default())
            .await
            .unwrap_err();
        assert!(error.contains("at most 4096 mutations"), "{error}");
    }

    fn cursor_state() -> KvSyncState {
        let epoch = crate::hash::hash(b"epoch");
        KvSyncState {
            pos: Some(KvSyncAnchor {
                seq: 7,
                epoch,
                epoch_seq: 1,
            }),
            floor: Some(KvSyncAnchor {
                seq: 3,
                epoch,
                epoch_seq: 0,
            }),
        }
    }

    /// The cursor round-trips only for the space and prefix it was minted
    /// for, under the key that minted it; everything else is `Invalid` (410),
    /// and a header that is not a cursor at all is `Malformed` (400).
    #[test]
    fn kv_sync_cursor_is_bound_to_space_prefix_and_key() {
        let key = [7u8; 32];
        let space = Owner::generate().space;
        let prefix: Path = "notes".parse().unwrap();
        let cursor = encode_kv_sync_cursor(&key, &space, &prefix, &cursor_state()).unwrap();
        assert_eq!(
            decode_kv_sync_cursor(&key, &cursor, &space, &prefix),
            Ok(cursor_state())
        );
        let other_prefix: Path = "notes-secret".parse().unwrap();
        for (label, result) in [
            (
                "other prefix",
                decode_kv_sync_cursor(&key, &cursor, &space, &other_prefix),
            ),
            (
                "other space",
                decode_kv_sync_cursor(&key, &cursor, &Owner::generate().space, &prefix),
            ),
            (
                "other key",
                decode_kv_sync_cursor(&[8u8; 32], &cursor, &space, &prefix),
            ),
        ] {
            assert_eq!(result, Err(KvSyncCursorError::Invalid), "{label}");
        }
        for malformed in ["", "not base64!", &"A".repeat(KV_SYNC_CURSOR_MAX_LEN + 1)] {
            assert_eq!(
                decode_kv_sync_cursor(&key, malformed, &space, &prefix),
                Err(KvSyncCursorError::Malformed)
            );
        }
    }

    /// A cursor's length does not leak how far a space's sequence has run.
    #[test]
    fn kv_sync_cursor_length_is_independent_of_positions() {
        let key = [7u8; 32];
        let space = Owner::generate().space;
        let prefix: Path = "notes".parse().unwrap();
        let state = |seq: i64, epoch_seq: i64| KvSyncState {
            pos: Some(KvSyncAnchor {
                seq,
                epoch: crate::hash::hash(b"epoch"),
                epoch_seq,
            }),
            floor: Some(KvSyncAnchor {
                seq: seq / 2,
                epoch: crate::hash::hash(b"floor"),
                epoch_seq: 0,
            }),
        };
        let small = encode_kv_sync_cursor(&key, &space, &prefix, &state(1, 0)).unwrap();
        let large = encode_kv_sync_cursor(&key, &space, &prefix, &state(i64::MAX, 4095)).unwrap();
        assert_eq!(small.len(), large.len());
        assert_eq!(
            decode_kv_sync_cursor(&key, &large, &space, &prefix),
            Ok(state(i64::MAX, 4095))
        );
    }

    /// Version 1 cursors carried the last key; they are refused with a reset
    /// rather than misread.
    #[test]
    fn kv_sync_cursor_v1_is_refused() {
        let key = [7u8; 32];
        let space = Owner::generate().space;
        let prefix: Path = "notes".parse().unwrap();
        let epoch = hex::encode(Vec::<u8>::from(crate::hash::hash(b"epoch")));
        let v1 = serde_json::json!({
            "v": 1,
            "pos": {"seq": 7, "epoch": epoch, "epoch_seq": 1, "key": "notes/a"},
            "floor": null,
        });
        let sealed = seal_cursor(&key, &space, &prefix, &serde_json::to_vec(&v1).unwrap()).unwrap();
        assert_eq!(
            decode_kv_sync_cursor(&key, &sealed, &space, &prefix),
            Err(KvSyncCursorError::Invalid)
        );
    }

    // ── PostgreSQL (run in CI's PG16 job; `TINYCLOUD_TEST_POSTGRES_URL`) ──

    /// Drops its schema when it goes out of scope, including while a failed
    /// assertion unwinds. `Drop` cannot await, so the drop runs on its own
    /// thread and runtime and is joined before the test returns.
    struct SchemaGuard {
        url: String,
        schema: String,
    }

    impl Drop for SchemaGuard {
        fn drop(&mut self) {
            let (url, schema) = (self.url.clone(), self.schema.clone());
            let dropped = std::thread::spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("schema drop runtime");
                runtime.block_on(async move {
                    let admin = Database::connect(ConnectOptions::new(url)).await?;
                    admin
                        .execute(Statement::from_string(
                            DbBackend::Postgres,
                            format!("DROP SCHEMA IF EXISTS {schema} CASCADE"),
                        ))
                        .await
                        .map(|_| ())
                })
            })
            .join();
            if !matches!(dropped, Ok(Ok(()))) {
                eprintln!("failed to drop isolated TC-732 schema {}", self.schema);
            }
        }
    }

    /// An isolated schema with `instances` independent `SpaceDatabase`s over
    /// it, each with its own pool (15 connections, the production size) and
    /// its own in-process locks: separate node processes sharing a database.
    /// The schema is dropped when the fixture goes out of scope.
    ///
    /// Fixtures are serialized within the test process. Each one opens up to
    /// `instances × 15` connections, and several concurrency tests running
    /// in parallel can exhaust PostgreSQL's default `max_connections = 100`
    /// ("sorry, too many clients already" at `CREATE SCHEMA`).
    struct PostgresFixture {
        dbs: Vec<TestDb>,
        _schema: SchemaGuard,
        // Last, so the schema is dropped before the next fixture starts.
        _serial: tokio::sync::MutexGuard<'static, ()>,
    }

    static POSTGRES_FIXTURES: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    impl PostgresFixture {
        async fn new(test: &str, instances: usize) -> Option<Self> {
            let url = crate::test_support::postgres_test_url(test)?;
            let serial = POSTGRES_FIXTURES.lock().await;
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
            let guard = SchemaGuard {
                url: url.clone(),
                schema: schema.clone(),
            };
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
            Some(Self {
                dbs,
                _schema: guard,
                _serial: serial,
            })
        }
    }

    /// `(seq, epoch bytes, epoch_seq)`: the order the feed promises.
    fn order_key(pos: &KvSyncAnchor) -> (i64, Vec<u8>, i64) {
        (pos.seq, Vec::<u8>::from(pos.epoch), pos.epoch_seq)
    }

    /// TC-951: `space`'s committed history is one chain. The seqs `0..n` each
    /// name exactly one epoch; the epoch at seq 0 has no parent and the one at
    /// seq `k` has exactly one, the epoch at seq `k - 1`; and every
    /// `event_order` row carries its epoch's seq. An epoch's parents are the
    /// heads its transaction read, so each commit computed its seq after its
    /// predecessor was visible: seq order is commit order. Two writers that
    /// read the same head (no shared sequence lock) leave a repeated seq or a
    /// fork here. Returns `n`.
    async fn assert_linear_history(
        conn: &DatabaseConnection,
        space: &SpaceId,
        label: &str,
    ) -> usize {
        use crate::models::epoch;
        use crate::relationships::epoch_order;
        let space = SpaceIdWrap(space.clone());
        let mut epochs = epoch::Entity::find()
            .filter(epoch::Column::Space.eq(space.clone()))
            .all(conn)
            .await
            .unwrap();
        epochs.sort_by_key(|epoch| epoch.seq);
        assert_eq!(
            epochs.iter().map(|epoch| epoch.seq).collect::<Vec<_>>(),
            (0..epochs.len() as i64).collect::<Vec<_>>(),
            "{label}: every seq must name exactly one epoch"
        );
        let mut parents = std::collections::HashMap::<Hash, Vec<Hash>>::new();
        for edge in epoch_order::Entity::find()
            .filter(epoch_order::Column::Space.eq(space.clone()))
            .all(conn)
            .await
            .unwrap()
        {
            parents.entry(edge.child).or_default().push(edge.parent);
        }
        for (seq, epoch) in epochs.iter().enumerate() {
            let predecessor = seq.checked_sub(1).map(|previous| epochs[previous].id);
            assert_eq!(
                parents.remove(&epoch.id).unwrap_or_default(),
                Vec::from_iter(predecessor),
                "{label}: the epoch at seq {seq} must follow exactly the one before it"
            );
        }
        assert!(
            parents.is_empty(),
            "{label}: an ordering edge names an epoch outside the history"
        );
        let seq_of = epochs
            .iter()
            .map(|epoch| (epoch.id, epoch.seq))
            .collect::<std::collections::HashMap<_, _>>();
        for event in event_order::Entity::find()
            .filter(event_order::Column::Space.eq(space.clone()))
            .all(conn)
            .await
            .unwrap()
        {
            assert_eq!(
                seq_of.get(&event.epoch),
                Some(&event.seq),
                "{label}: an event must carry its epoch's seq"
            );
        }
        // TC-1274: the cached heads are exactly the chain's last epoch.
        let cached = crate::models::epoch_head::Entity::find()
            .filter(crate::models::epoch_head::Column::Space.eq(space))
            .all(conn)
            .await
            .unwrap()
            .into_iter()
            .map(|head| (head.id, head.seq))
            .collect::<Vec<_>>();
        assert_eq!(
            cached,
            Vec::from_iter(epochs.last().map(|epoch| (epoch.id, epoch.seq))),
            "{label}: the cached head must be the newest epoch"
        );
        epochs.len()
    }

    /// TC-951: no lost update. Every key's `current_kv` row is live and is
    /// the key's highest-positioned `kv_write`: same invocation, value and
    /// position. Returns the rows by key.
    async fn assert_current_kv_is_latest_write(
        conn: &DatabaseConnection,
        space: &SpaceId,
        label: &str,
    ) -> BTreeMap<String, current_kv::Model> {
        use crate::models::kv_write;
        let position =
            |write: &kv_write::Model| (write.seq, Vec::<u8>::from(write.epoch), write.epoch_seq);
        let space = SpaceIdWrap(space.clone());
        let mut latest = BTreeMap::<String, kv_write::Model>::new();
        for write in kv_write::Entity::find()
            .filter(kv_write::Column::Space.eq(space.clone()))
            .all(conn)
            .await
            .unwrap()
        {
            let key = write.key.0.to_string();
            if latest
                .get(&key)
                .is_none_or(|seen| position(seen) < position(&write))
            {
                latest.insert(key, write);
            }
        }
        let current = current_kv::Entity::find()
            .filter(current_kv::Column::Space.eq(space))
            .all(conn)
            .await
            .unwrap()
            .into_iter()
            .map(|row| (row.key.0.to_string(), row))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(
            current.keys().collect::<Vec<_>>(),
            latest.keys().collect::<Vec<_>>(),
            "{label}: one current row per written key"
        );
        for (key, write) in &latest {
            let row = &current[key];
            assert!(!row.deleted, "{label}: {key} must be live");
            assert_eq!(
                (row.invocation, row.value, row.seq, row.epoch, row.epoch_seq),
                (
                    write.invocation,
                    write.value,
                    write.seq,
                    write.epoch,
                    write.epoch_seq
                ),
                "{label}: {key} must hold its newest write"
            );
        }
        current
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
        let forced = lines(forced);
        println!("TC-732 PostgreSQL feed plan ({label}, enable_seqscan=off):\n  {forced}");
        // The poll seeks the order index at the cursor and reads it in order:
        // a range on `seq` in the index condition, and no sort of the rest.
        assert!(
            forced.contains("idx_current_kv_space_order"),
            "{label}: {forced}"
        );
        let index_cond = forced
            .lines()
            .find(|line| line.trim_start().starts_with("Index Cond:"))
            .unwrap_or_else(|| panic!("{label}: no Index Cond in {forced}"));
        assert!(index_cond.contains("seq"), "{label}: {index_cond}");
        assert!(!forced.contains("Sort"), "{label}: {forced}");
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
                                *pos,
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

            let state = log.last().map(|(pos, _, _)| *pos);
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
        drop(fixture);
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
        drop(fixture);
        outcome.expect("cross-space lock exercise finished");
    }

    /// Conditional writes run under READ COMMITTED behind the sequence lock.
    /// 32 contenders on four node instances race one key, round after round:
    /// a create (if-none-match), ten replaces in which half the contenders
    /// present the current etag and half the one it replaced, a re-create
    /// over a tombstone, and a create over a live value. Each round admits
    /// exactly one winner, always a contender whose precondition held when
    /// the round began (none in the last round); every loser is a
    /// precondition failure, never a false success, and leaves no write and
    /// no epoch behind (TC-951).
    #[tokio::test]
    async fn postgres_conditional_put_is_atomic_under_concurrency() {
        use crate::models::kv_write;
        const INSTANCES: usize = 4;
        const CONTENDERS: usize = 32;
        let Some(fixture) = PostgresFixture::new(
            "postgres_conditional_put_is_atomic_under_concurrency",
            INSTANCES,
        )
        .await
        else {
            return;
        };
        let owner = std::sync::Arc::new(Owner::generate());
        host(&fixture.dbs[0], &owner).await;
        let conn = fixture.dbs[0].connection();
        let key: Path = "notes/x".parse().unwrap();

        // Contender `i` presents `preconditions[i]`. Returns the winners as
        // `(contender, etag)`.
        let race = |round: String, preconditions: Vec<KvPrecondition>| {
            let tasks = preconditions
                .into_iter()
                .enumerate()
                .map(|(contender, precondition)| {
                    let db = fixture.dbs[contender % INSTANCES].clone();
                    let owner = owner.clone();
                    let key = key.clone();
                    let value = format!("{round}-{contender}");
                    tokio::spawn(async move {
                        let mut options = KvInvokeOptions::default();
                        options
                            .preconditions
                            .insert((owner.space.clone(), key), precondition);
                        let outcome = invoke(
                            &db,
                            &owner,
                            &[Op::Put("notes/x", value.as_bytes())],
                            options,
                        )
                        .await;
                        (contender, outcome)
                    })
                })
                .collect::<Vec<_>>();
            async move {
                // Every contender finishes before any verdict, so a failed
                // assertion never leaves a transaction in flight.
                let mut winners = Vec::new();
                for outcome in futures::future::join_all(tasks).await {
                    match outcome.unwrap() {
                        (contender, Ok(written)) => winners.push((contender, written[0])),
                        (_, Err(error)) => assert!(
                            error.contains("precondition"),
                            "{round}: a loser must fail its precondition, got {error}"
                        ),
                    }
                }
                winners
            }
        };
        let if_match = |etag: Hash| KvPrecondition::Matches(etag.as_ref().try_into().unwrap());
        let who = |winners: &[(usize, Hash)]| {
            winners
                .iter()
                .map(|(contender, _)| *contender)
                .collect::<Vec<_>>()
        };

        let exercise = async {
            let create = || vec![KvPrecondition::DoesNotExist; CONTENDERS];
            let created = race("create".into(), create()).await;
            assert_eq!(
                created.len(),
                1,
                "exactly one create wins: {:?}",
                who(&created)
            );
            let mut committed = vec![created[0].1];
            // Before the first replace no etag has been replaced yet: present
            // one that was never written.
            let mut stale = crate::hash::hash(b"never written");
            for round in 0..10 {
                let current = committed[committed.len() - 1];
                let preconditions = (0..CONTENDERS)
                    .map(|contender| if_match(if contender % 2 == 0 { current } else { stale }))
                    .collect();
                let replaced = race(format!("replace{round}"), preconditions).await;
                assert_eq!(
                    replaced.len(),
                    1,
                    "replace {round}: exactly one wins: {:?}",
                    who(&replaced)
                );
                assert_eq!(
                    replaced[0].0 % 2,
                    0,
                    "replace {round}: a stale etag must never win"
                );
                stale = current;
                committed.push(replaced[0].1);
            }
            run(&fixture.dbs[1], &owner, &[Op::Del("notes/x")]).await;
            let recreated = race("recreate".into(), create()).await;
            assert_eq!(
                recreated.len(),
                1,
                "exactly one create over the tombstone wins: {:?}",
                who(&recreated)
            );
            committed.push(recreated[0].1);
            let over_live = race("create-over-live".into(), create()).await;
            assert!(
                over_live.is_empty(),
                "a create over a live value never wins: {:?}",
                who(&over_live)
            );

            let row = current_kv::Entity::find_by_id((
                SpaceIdWrap(owner.space.clone()),
                crate::types::Path(key.clone()),
            ))
            .one(conn)
            .await
            .unwrap()
            .unwrap();
            assert!(!row.deleted);
            assert_eq!(row.value, committed[committed.len() - 1]);
            // Only winners wrote, in round order; the delete is the one other
            // commit.
            let mut writes = kv_write::Entity::find()
                .filter(kv_write::Column::Space.eq(SpaceIdWrap(owner.space.clone())))
                .all(conn)
                .await
                .unwrap();
            writes.sort_by_key(|write| write.seq);
            assert_eq!(
                writes.iter().map(|write| write.value).collect::<Vec<_>>(),
                committed
            );
            assert_eq!(
                assert_linear_history(conn, &owner.space, "conditional").await,
                committed.len() + 1
            );
        };
        let outcome = tokio::time::timeout(std::time::Duration::from_secs(300), exercise).await;
        drop(fixture);
        outcome.expect("conditional put races finished");
    }

    /// TC-951: 32 writers put distinct values to one key of one space at
    /// once, for 10 rounds, spread over four node instances (each with its
    /// own 15-connection pool and in-process locks, so only the
    /// database-side sequence lock orders them). Every put succeeds and
    /// commits once, at its own seq of one linear history; a put that
    /// returned before another began has the lower seq; and after every round
    /// `current_kv` holds the highest-seq write, one of that round's (no lost
    /// update).
    #[tokio::test]
    async fn postgres_same_key_puts_commit_in_one_seq_ordered_history() {
        use crate::models::kv_write;
        const INSTANCES: usize = 4;
        const WRITERS: usize = 32;
        const ROUNDS: usize = 10;
        const KEY: &str = "notes/hot";
        let Some(fixture) = PostgresFixture::new(
            "postgres_same_key_puts_commit_in_one_seq_ordered_history",
            INSTANCES,
        )
        .await
        else {
            return;
        };
        let owner = std::sync::Arc::new(Owner::generate());
        host(&fixture.dbs[0], &owner).await;
        let conn = fixture.dbs[0].connection();

        let exercise = async {
            // A logical clock: each put ticks it before it starts and after it
            // returns, which orders puts in real time without timing them.
            let clock = std::sync::Arc::new(AtomicU64::new(0));
            // `(etag, round, started, returned)` per put.
            let mut puts = Vec::new();
            for round in 0..ROUNDS {
                let tasks = (0..WRITERS)
                    .map(|writer| {
                        let db = fixture.dbs[writer % INSTANCES].clone();
                        let (owner, clock) = (owner.clone(), clock.clone());
                        tokio::spawn(async move {
                            let value = format!("round{round}-writer{writer}");
                            let started = clock.fetch_add(1, Ordering::SeqCst);
                            let outcome = invoke(
                                &db,
                                &owner,
                                &[Op::Put(KEY, value.as_bytes())],
                                KvInvokeOptions::default(),
                            )
                            .await;
                            let returned = clock.fetch_add(1, Ordering::SeqCst);
                            (value, outcome, started, returned)
                        })
                    })
                    .collect::<Vec<_>>();
                // Every put of the round finishes before any verdict, so a
                // failed assertion never leaves a transaction in flight.
                for outcome in futures::future::join_all(tasks).await {
                    let (value, outcome, started, returned) = outcome.unwrap();
                    let etag = crate::hash::hash(value.as_bytes());
                    match outcome {
                        Ok(written) => assert_eq!(written, vec![etag], "{value}"),
                        Err(error) => panic!("{value}: an unconditional put must succeed: {error}"),
                    }
                    puts.push((etag, round, started, returned));
                }
                let current =
                    assert_current_kv_is_latest_write(conn, &owner.space, "same key").await;
                assert!(
                    puts.iter()
                        .any(|&(etag, of, _, _)| of == round && etag == current[KEY].value),
                    "round {round}: the newest write must be one of this round's"
                );
            }

            assert_eq!(
                assert_linear_history(conn, &owner.space, "same key").await,
                WRITERS * ROUNDS,
                "one commit per put"
            );
            let writes = kv_write::Entity::find()
                .filter(kv_write::Column::Space.eq(SpaceIdWrap(owner.space.clone())))
                .all(conn)
                .await
                .unwrap();
            assert_eq!(writes.len(), WRITERS * ROUNDS, "one kv_write per put");
            let seq_of = writes
                .into_iter()
                .map(|write| (write.value, write.seq))
                .collect::<std::collections::HashMap<_, _>>();
            assert_eq!(seq_of.len(), WRITERS * ROUNDS);
            for &(before, _, _, returned) in &puts {
                for &(after, _, started, _) in &puts {
                    if returned < started {
                        assert!(
                            seq_of[&before] < seq_of[&after],
                            "a put that returned before another began must have the lower seq"
                        );
                    }
                }
            }
        };
        let outcome = tokio::time::timeout(std::time::Duration::from_secs(300), exercise).await;
        drop(fixture);
        outcome.expect("same-key writers finished");
    }

    /// TC-951: same-key, other-key and multi-space puts at once, for 10
    /// rounds across four node instances. Three spaces of one owner; each
    /// round 32 writers put a hot key in one space, their own key in one
    /// space, the hot key of each pair of spaces in one invocation, or their
    /// own key in all three. A multi-space put takes its spaces' sequence
    /// locks in one global order and holds them to commit, so: no put
    /// deadlocks or fails; every space keeps one linear history with one
    /// commit per put that touched it; a multi-space put lands in each of its
    /// spaces as one invocation; two multi-space puts are ordered the same
    /// way in every space they share; and every key holds its newest write.
    #[tokio::test]
    async fn postgres_mixed_and_multi_space_puts_stay_ordered() {
        use crate::models::kv_write;
        const INSTANCES: usize = 4;
        const WRITERS: usize = 32;
        const ROUNDS: usize = 10;
        // Per role (`writer % 8`): the spaces it puts to in one invocation,
        // and its key (`None`: the writer's own key).
        const ROLES: [(&[usize], Option<&str>); 8] = [
            (&[0], Some("shared/hot")),
            (&[1], Some("shared/hot")),
            (&[0], None),
            (&[2], None),
            (&[0, 1], Some("shared/hot")),
            (&[1, 2], Some("shared/hot")),
            (&[2, 0], Some("shared/hot")),
            (&[0, 1, 2], None),
        ];
        let Some(fixture) = PostgresFixture::new(
            "postgres_mixed_and_multi_space_puts_stay_ordered",
            INSTANCES,
        )
        .await
        else {
            return;
        };
        let owner = std::sync::Arc::new(Owner::generate());
        let spaces = std::sync::Arc::new([
            owner.space.clone(),
            owner.space_named("photos"),
            owner.space_named("music"),
        ]);
        for space in spaces.iter() {
            host_space(&fixture.dbs[0], space).await;
        }
        let conn = fixture.dbs[0].connection();

        let exercise = async {
            // Per put: `(space index, etag)` of each value it wrote.
            let mut puts = Vec::<Vec<(usize, Hash)>>::new();
            for round in 0..ROUNDS {
                let tasks = (0..WRITERS)
                    .map(|writer| {
                        let db = fixture.dbs[writer % INSTANCES].clone();
                        let (owner, spaces) = (owner.clone(), spaces.clone());
                        tokio::spawn(async move {
                            let (targets, key) = ROLES[writer % ROLES.len()];
                            let key =
                                key.map_or_else(|| format!("own/writer{writer}"), str::to_owned);
                            let values = targets
                                .iter()
                                .map(|&space| {
                                    (space, format!("round{round}-writer{writer}-space{space}"))
                                })
                                .collect::<Vec<_>>();
                            let ops = values
                                .iter()
                                .map(|(_, value)| Op::Put(&key, value.as_bytes()))
                                .collect::<Vec<_>>();
                            let ops = values
                                .iter()
                                .zip(&ops)
                                .map(|((space, _), op)| (&spaces[*space], op))
                                .collect::<Vec<_>>();
                            let outcome =
                                invoke_in(&db, &owner, &ops, KvInvokeOptions::default()).await;
                            let written = values
                                .iter()
                                .map(|(space, value)| (*space, crate::hash::hash(value.as_bytes())))
                                .collect::<Vec<_>>();
                            (format!("round {round} writer {writer}"), written, outcome)
                        })
                    })
                    .collect::<Vec<_>>();
                // Every put of the round finishes before any verdict.
                for outcome in futures::future::join_all(tasks).await {
                    let (label, written, outcome) = outcome.unwrap();
                    let etags = outcome
                        .unwrap_or_else(|error| panic!("{label}: every put must succeed: {error}"));
                    assert_eq!(etags.len(), written.len(), "{label}");
                    assert!(
                        written.iter().all(|(_, etag)| etags.contains(etag)),
                        "{label}"
                    );
                    puts.push(written);
                }
            }

            // etag -> (space index, invocation, seq)
            let mut write_of = std::collections::HashMap::new();
            for (index, space) in spaces.iter().enumerate() {
                let label = format!("space {index}");
                let touching = puts
                    .iter()
                    .filter(|put| put.iter().any(|&(of, _)| of == index))
                    .count();
                assert_eq!(
                    assert_linear_history(conn, space, &label).await,
                    touching,
                    "{label}: one commit per put that touched it"
                );
                assert_current_kv_is_latest_write(conn, space, &label).await;
                for write in kv_write::Entity::find()
                    .filter(kv_write::Column::Space.eq(SpaceIdWrap(space.clone())))
                    .all(conn)
                    .await
                    .unwrap()
                {
                    let seen = write_of.insert(write.value, (index, write.invocation, write.seq));
                    assert!(seen.is_none(), "{label}: every value is written once");
                }
            }
            assert_eq!(
                write_of.len(),
                puts.iter().map(Vec::len).sum::<usize>(),
                "one kv_write per value put"
            );
            for put in &puts {
                let invocations = put
                    .iter()
                    .map(|(space, etag)| {
                        let (landed, invocation, _) = write_of[etag];
                        assert_eq!(landed, *space, "a value lands in the space it was put to");
                        invocation
                    })
                    .collect::<Vec<_>>();
                assert!(
                    invocations.windows(2).all(|pair| pair[0] == pair[1]),
                    "a multi-space put is one invocation in all its spaces"
                );
            }
            // Two multi-space puts each held both of their shared spaces'
            // locks to commit, so one preceded the other in both.
            let multi = puts
                .iter()
                .filter(|put| put.len() > 1)
                .map(|put| {
                    put.iter()
                        .map(|(space, etag)| (*space, write_of[etag].2))
                        .collect::<BTreeMap<_, _>>()
                })
                .collect::<Vec<_>>();
            for (index, first) in multi.iter().enumerate() {
                for second in &multi[index + 1..] {
                    let orders = first
                        .iter()
                        .filter_map(|(space, seq)| second.get(space).map(|other| seq.cmp(other)))
                        .collect::<Vec<_>>();
                    assert!(
                        orders.windows(2).all(|pair| pair[0] == pair[1])
                            && !orders.contains(&std::cmp::Ordering::Equal),
                        "multi-space puts must be ordered alike in every shared space: \
                         {first:?} vs {second:?}"
                    );
                }
            }
        };
        let outcome = tokio::time::timeout(std::time::Duration::from_secs(300), exercise).await;
        drop(fixture);
        outcome.expect("mixed writers finished");
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
        drop(fixture);
        exercise.expect("TC-732 PostgreSQL collation resilience");
    }

    async fn sequence_lock_is_free(conn: &DatabaseConnection, space: &SpaceId) -> bool {
        conn.query_one(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT pg_try_advisory_xact_lock($1) AS free",
            [space_sequence_lock_key(space).into()],
        ))
        .await
        .unwrap()
        .unwrap()
        .try_get::<bool>("", "free")
        .unwrap()
    }

    /// A connection that counts the sequence-lock statements it runs.
    fn counting_sequence_locks(
        conn: &DatabaseConnection,
    ) -> (DatabaseConnection, std::sync::Arc<AtomicU64>) {
        let locks = std::sync::Arc::new(AtomicU64::new(0));
        let counter = locks.clone();
        let mut conn = conn.clone();
        conn.set_metric_callback(move |info| {
            if info.statement.sql.contains("pg_advisory_xact_lock") {
                counter.fetch_add(1, Ordering::SeqCst);
            }
        });
        (conn, locks)
    }

    /// Keys the transaction already holds are not asked for again; the
    /// others are, and every one stays held until the transaction ends.
    #[tokio::test]
    async fn postgres_held_sequence_locks_are_not_asked_for_again() {
        let Some(schema) = crate::test_support::PostgresTestSchema::new(
            "postgres_held_sequence_locks_are_not_asked_for_again",
        )
        .await
        else {
            return;
        };
        // `b` sorts above `a`, so taking it after the held `a` keeps the
        // global ascending lock order that `lock_space_sequences_not_held`
        // asserts.
        let (mut a, mut b) = (Owner::generate().space, Owner::generate().space);
        if space_sequence_lock_key(&a) > space_sequence_lock_key(&b) {
            std::mem::swap(&mut a, &mut b);
        }
        let (conn, locks) = counting_sequence_locks(&schema.conn);
        let tx = conn.begin().await.unwrap();
        lock_space_sequences(&tx, [&a]).await.unwrap();
        assert_eq!(locks.load(Ordering::SeqCst), 1);
        lock_space_sequences_not_held(&tx, [&a, &b], std::slice::from_ref(&a))
            .await
            .unwrap();
        assert_eq!(locks.load(Ordering::SeqCst), 2, "only b is asked for");
        lock_space_sequences_not_held(&tx, [&a, &b], &[a.clone(), b.clone()])
            .await
            .unwrap();
        assert_eq!(locks.load(Ordering::SeqCst), 2, "both held already");
        assert!(!sequence_lock_is_free(&schema.conn, &a).await);
        assert!(!sequence_lock_is_free(&schema.conn, &b).await);
        tx.commit().await.unwrap();
        assert!(sequence_lock_is_free(&schema.conn, &a).await);
        assert!(sequence_lock_is_free(&schema.conn, &b).await);
    }

    /// A KV write asks for its space's sequence lock once: right after BEGIN.
    /// `transact` runs on the same transaction and no longer asks again.
    #[tokio::test]
    async fn postgres_kv_write_takes_its_space_sequence_lock_once() {
        let Some(schema) = crate::test_support::PostgresTestSchema::new(
            "postgres_kv_write_takes_its_space_sequence_lock_once",
        )
        .await
        else {
            return;
        };
        let (conn, locks) = counting_sequence_locks(&schema.conn);
        let db: TestDb = SpaceDatabase::new(
            conn,
            MemoryStore::default(),
            StaticSecret::new([0u8; 32].to_vec()).unwrap(),
        )
        .await
        .unwrap();
        let owner = Owner::generate();
        host(&db, &owner).await;
        let cases: [(&str, &[Op<'_>]); 3] = [
            ("put", &[Op::Put("notes/a", b"one")]),
            (
                "two puts",
                &[Op::Put("notes/a", b"two"), Op::Put("notes/b", b"three")],
            ),
            ("delete", &[Op::Del("notes/a")]),
        ];
        for (label, ops) in cases {
            let before = locks.load(Ordering::SeqCst);
            run(&db, &owner, ops).await;
            assert_eq!(locks.load(Ordering::SeqCst) - before, 1, "{label}");
        }
    }
}
