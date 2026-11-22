//! The manifest: the published frontier of each database's store copy and the
//! inventory of its objects (TC-1491 contract, section 4).
//!
//! Publication is a compare-and-set on one `sql_store_manifest` row. The
//! publisher uploads and records its object first; the CAS and the object's
//! `uploaded -> published` flip commit in one transaction, and the flip must
//! change exactly one row or the CAS rolls back.

use async_trait::async_trait;
use sea_orm::{
    sea_query::{Expr, OnConflict},
    ActiveValue::Set,
    ColumnTrait, ConnectionTrait, DatabaseConnection, DatabaseTransaction, EntityTrait,
    QueryFilter, QueryOrder, TransactionTrait,
};
use time::{format_description::well_known::Rfc3339, OffsetDateTime, UtcOffset};

use super::key::{DbRef, Lineage, ObjectKey, ObjectKind, PublishId};
use super::object::SqlStoreError;
use crate::models::{sql_store_manifest as manifest, sql_store_object as object};

/// The only epoch in the shadow phase (contract 4.4).
pub const SHADOW_EPOCH: i64 = 0;
/// Longest `space` / `db_id` the `varchar(255)` columns hold.
const MAX_ID_CHARS: usize = 255;

/// The `format` each object kind must be recorded with.
const SNAPSHOT_FORMAT: &str = "sqlite-v1";
const SEGMENT_FORMAT: &str = "wal-cum-v1";

fn required_format(kind: ObjectKind) -> &'static str {
    match kind {
        ObjectKind::Snapshot => SNAPSHOT_FORMAT,
        ObjectKind::Segment => SEGMENT_FORMAT,
    }
}

/// Current time in the canonical `created_at` form.
pub fn now_timestamp() -> String {
    canonical_format(OffsetDateTime::now_utc())
}

/// Fixed-width UTC form `YYYY-MM-DDTHH:MM:SS.ffffffZ`, so text comparison
/// orders by time. `at` must already be in UTC.
fn canonical_format(at: OffsetDateTime) -> String {
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:06}Z",
        at.year(),
        u8::from(at.month()),
        at.day(),
        at.hour(),
        at.minute(),
        at.second(),
        at.microsecond(),
    )
}

/// Parses an RFC 3339 timestamp and returns its canonical UTC form.
fn canonical_timestamp(text: &str) -> Result<String, SqlStoreError> {
    let at = OffsetDateTime::parse(text, &Rfc3339)
        .map_err(|_| SqlStoreError::Invalid("created_at is not an RFC 3339 timestamp"))?;
    // Converting to UTC can leave the representable range, so it is checked.
    let utc = at
        .checked_to_offset(UtcOffset::UTC)
        .filter(|utc| (0..=9999).contains(&utc.year()))
        .ok_or(SqlStoreError::Invalid("created_at is out of range"))?;
    Ok(canonical_format(utc))
}

/// An inventory row's state. There is no `orphan` state: an `uploaded` row
/// that no frontier reaches is an orphan, and GC derives that by query
/// (contract 3.3, slice 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectState {
    Uploaded,
    Published,
}

impl ObjectState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Uploaded => "uploaded",
            Self::Published => "published",
        }
    }
    fn parse(text: &str) -> Result<Self, SqlStoreError> {
        match text {
            "uploaded" => Ok(Self::Uploaded),
            "published" => Ok(Self::Published),
            _ => Err(SqlStoreError::Invalid("unknown object state")),
        }
    }
}

/// An uploaded object to register. Its position fields come from the key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectRecord {
    pub key: ObjectKey,
    /// `sqlite-v1` for a snapshot, `wal-cum-v1` for a cumulative-WAL segment.
    pub format: String,
    pub bytes: u64,
    pub created_at: String,
}

/// The manifest row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frontier {
    pub lineage: Lineage,
    pub epoch: i64,
    pub revision: i64,
    pub base_snapshot_key: String,
    pub base_seq: u64,
    pub base_checkpoint_cid: String,
    pub last_seq: u64,
    pub publish_id: String,
    pub published_at: String,
    pub frontier_bytes: u64,
}

impl Frontier {
    /// What a publisher compares against.
    pub fn token(&self) -> CasToken {
        CasToken {
            epoch: self.epoch,
            lineage: self.lineage.clone(),
            revision: self.revision,
        }
    }

    pub(crate) fn from_model(m: manifest::Model) -> Result<Self, SqlStoreError> {
        let nonneg = |v: i64| u64::try_from(v).map_err(|_| SqlStoreError::Invalid("negative seq"));
        Ok(Self {
            lineage: Lineage::parse(&m.lineage)?,
            epoch: m.epoch,
            revision: m.revision,
            base_snapshot_key: m.base_snapshot_key,
            base_seq: nonneg(m.base_seq)?,
            base_checkpoint_cid: m.base_checkpoint_cid,
            last_seq: nonneg(m.last_seq)?,
            publish_id: m.publish_id,
            published_at: m.published_at,
            frontier_bytes: nonneg(m.frontier_bytes)?,
        })
    }
}

/// The state a publish expects to replace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CasToken {
    pub epoch: i64,
    pub lineage: Lineage,
    pub revision: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublishKind {
    /// A new chain in the current lineage (`object` is a snapshot).
    Snapshot,
    /// Append to the current chain. `base_snapshot_key` and the request's
    /// `base_checkpoint_cid` must still be the manifest's.
    Segment { base_snapshot_key: String },
    /// Start `object.lineage()` on top of a different `token.lineage`.
    LineageSwitch,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Publish {
    pub kind: PublishKind,
    /// The new object; it must already be recorded as `uploaded`.
    pub object: ObjectKey,
    /// The artifact's `checkpoint_content_hash` this publish is cut from.
    pub base_checkpoint_cid: String,
    /// Bytes of the snapshot and segment(s) needed to restore after this.
    pub frontier_bytes: u64,
    pub publish_id: PublishId,
    pub now: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublishOutcome {
    Published(Frontier),
    /// The CAS matched nothing (stale epoch, lineage or revision, a regressing
    /// `last_seq`, or a lost first-publish race). Not an error. Carries the
    /// current row, if any.
    Lost(Option<Frontier>),
}

/// Objects to record and publish in one control-database transaction
/// ([`SqlManifest::publish_chain`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishChain {
    /// Either a snapshot followed by zero or more segments on it, or one or
    /// more segments on the expected frontier's base snapshot.
    pub objects: Vec<ObjectRecord>,
    /// The artifact's `checkpoint_content_hash` the chain is cut from.
    pub base_checkpoint_cid: String,
    pub publish_id: PublishId,
    pub now: String,
}

#[async_trait]
pub trait SqlManifest: Send + Sync {
    async fn current(&self, db: &DbRef<'_>) -> Result<Option<Frontier>, SqlStoreError>;

    /// Compare-and-set (contract 4.1). `expected` is `None` only for the first
    /// publication, which must be a snapshot.
    async fn publish_cas(
        &self,
        db: &DbRef<'_>,
        expected: Option<&CasToken>,
        publish: Publish,
    ) -> Result<PublishOutcome, SqlStoreError>;

    /// Register an uploaded object as `uploaded`. Idempotent: an existing row
    /// with the same size returns its current state; a different size is a
    /// `Conflict`.
    async fn record_object(
        &self,
        db: &DbRef<'_>,
        record: &ObjectRecord,
    ) -> Result<ObjectState, SqlStoreError>;

    async fn list_objects(
        &self,
        db: &DbRef<'_>,
        state: Option<ObjectState>,
    ) -> Result<Vec<ObjectRecord>, SqlStoreError>;

    /// Record every object of `chain` as `uploaded` and CAS-publish them in
    /// order, in one transaction (contract 4.1). `expected` is the frontier
    /// the caller planned against (`None` for a first publication). A
    /// leading snapshot publishes as `Snapshot` in `expected`'s lineage,
    /// `LineageSwitch` in another, or as the first row; every segment chains
    /// on the previous step. The chain must end at or above
    /// `expected.last_seq`.
    ///
    /// A CAS lost on the first object commits the inventory rows (they stay
    /// `uploaded`) and returns `Lost` with the current row. A CAS lost on a
    /// later object rolls everything back and is an error: in one
    /// transaction the earlier steps fixed the row it checks against.
    async fn publish_chain(
        &self,
        db: &DbRef<'_>,
        expected: Option<&Frontier>,
        chain: PublishChain,
    ) -> Result<PublishOutcome, SqlStoreError>;
}

/// [`SqlManifest`] on the control database (Postgres, MySQL or SQLite).
#[derive(Clone)]
pub struct DbSqlManifest {
    db: DatabaseConnection,
}

impl DbSqlManifest {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }
}

fn check_db(db: &DbRef<'_>) -> Result<(), SqlStoreError> {
    ObjectKey::db_prefix(db)?;
    if db.space.chars().count() > MAX_ID_CHARS || db.db_id.chars().count() > MAX_ID_CHARS {
        return Err(SqlStoreError::Invalid("space or database id too long"));
    }
    Ok(())
}

fn to_i64(v: u64) -> Result<i64, SqlStoreError> {
    i64::try_from(v).map_err(|_| SqlStoreError::Invalid("value exceeds i64"))
}

/// The primary key filter of one object row.
fn object_pk(db: &DbRef<'_>, key: &ObjectKey) -> Result<sea_orm::Condition, SqlStoreError> {
    use object::Column as C;
    Ok(sea_orm::Condition::all()
        .add(C::Space.eq(db.space))
        .add(C::DbId.eq(db.db_id))
        .add(C::Lineage.eq(key.lineage().as_str()))
        .add(C::Kind.eq(key.kind().as_str()))
        .add(C::BaseSeq.eq(to_i64(key.base_seq())?))
        .add(C::FromSeq.eq(to_i64(key.from_seq())?))
        .add(C::ToSeq.eq(to_i64(key.to_seq())?))
        .add(C::ContentHash.eq(key.content_hash())))
}

fn manifest_row(
    db: &DbRef<'_>,
    p: &Publish,
    epoch: i64,
    revision: i64,
) -> Result<manifest::ActiveModel, SqlStoreError> {
    Ok(manifest::ActiveModel {
        space: Set(db.space.to_owned()),
        db_id: Set(db.db_id.to_owned()),
        lineage: Set(p.object.lineage().to_string()),
        epoch: Set(epoch),
        revision: Set(revision),
        base_snapshot_key: Set(p.object.as_str().to_owned()),
        base_seq: Set(to_i64(p.object.base_seq())?),
        base_checkpoint_cid: Set(p.base_checkpoint_cid.clone()),
        last_seq: Set(to_i64(p.object.to_seq())?),
        publish_id: Set(p.publish_id.to_string()),
        published_at: Set(p.now.clone()),
        frontier_bytes: Set(to_i64(p.frontier_bytes)?),
    })
}

/// What the transactional part of a publish decided.
enum PublishStep {
    /// The CAS and the object flip ran; carries the frontier read in the same transaction.
    Won(Option<Frontier>),
    /// The CAS lost; the caller rolls back and reads the winner.
    Lost,
}

impl DbSqlManifest {
    async fn read<C: ConnectionTrait>(
        conn: &C,
        db: &DbRef<'_>,
    ) -> Result<Option<Frontier>, SqlStoreError> {
        manifest::Entity::find_by_id((db.space.to_owned(), db.db_id.to_owned()))
            .one(conn)
            .await?
            .map(Frontier::from_model)
            .transpose()
    }

    /// The row-level CAS of one publish; returns rows affected (0 or 1).
    async fn cas<C: ConnectionTrait>(
        conn: &C,
        db: &DbRef<'_>,
        token: &CasToken,
        p: &Publish,
    ) -> Result<u64, SqlStoreError> {
        use manifest::Column as C_;
        let at = to_i64(p.object.to_seq())?;
        let mut update = manifest::Entity::update_many()
            .col_expr(C_::Revision, Expr::col(C_::Revision).add(1))
            .col_expr(C_::PublishId, Expr::value(p.publish_id.to_string()))
            .col_expr(C_::PublishedAt, Expr::value(p.now.clone()))
            .col_expr(C_::FrontierBytes, Expr::value(to_i64(p.frontier_bytes)?))
            .col_expr(C_::LastSeq, Expr::value(at))
            .filter(C_::Space.eq(db.space))
            .filter(C_::DbId.eq(db.db_id))
            .filter(C_::Epoch.eq(token.epoch))
            .filter(C_::Revision.eq(token.revision));
        match &p.kind {
            PublishKind::Snapshot => {
                update = update
                    .col_expr(
                        C_::BaseSnapshotKey,
                        Expr::value(p.object.as_str().to_owned()),
                    )
                    .col_expr(C_::BaseSeq, Expr::value(at))
                    .col_expr(
                        C_::BaseCheckpointCid,
                        Expr::value(p.base_checkpoint_cid.clone()),
                    )
                    .filter(C_::Lineage.eq(token.lineage.as_str()))
                    .filter(C_::LastSeq.lte(at));
            }
            PublishKind::LineageSwitch => {
                update = update
                    .col_expr(C_::Lineage, Expr::value(p.object.lineage().to_string()))
                    .col_expr(
                        C_::BaseSnapshotKey,
                        Expr::value(p.object.as_str().to_owned()),
                    )
                    .col_expr(C_::BaseSeq, Expr::value(at))
                    .col_expr(
                        C_::BaseCheckpointCid,
                        Expr::value(p.base_checkpoint_cid.clone()),
                    )
                    .filter(C_::Lineage.eq(token.lineage.as_str()));
            }
            PublishKind::Segment { base_snapshot_key } => {
                // wal-cum-v1 segments are cumulative from base_seq + 1; publish_cas
                // has already checked from_seq.
                // last_seq in [from_seq - 1, to_seq): no gap, and it strictly advances.
                let from_prev = to_i64(p.object.from_seq() - 1)?;
                update = update
                    .filter(C_::Lineage.eq(token.lineage.as_str()))
                    .filter(C_::BaseSnapshotKey.eq(base_snapshot_key.as_str()))
                    .filter(C_::BaseSeq.eq(to_i64(p.object.base_seq())?))
                    .filter(C_::BaseCheckpointCid.eq(p.base_checkpoint_cid.as_str()))
                    .filter(C_::LastSeq.gte(from_prev))
                    .filter(C_::LastSeq.lt(at));
            }
        }
        Ok(update.exec(conn).await?.rows_affected)
    }

    /// The transactional part of one publish. Returns with `txn` still open;
    /// the caller commits after `Won` and rolls back on every other outcome,
    /// including the errors returned here.
    async fn publish_in(
        txn: &DatabaseTransaction,
        db: &DbRef<'_>,
        expected: Option<&CasToken>,
        publish: &Publish,
    ) -> Result<PublishStep, SqlStoreError> {
        let obj = &publish.object;
        let won = match expected {
            // INSERT … ON CONFLICT DO NOTHING: a raw primary-key violation
            // would abort the whole Postgres transaction.
            None => {
                let inserted =
                    manifest::Entity::insert(manifest_row(db, publish, SHADOW_EPOCH, 0)?)
                        .on_conflict(
                            OnConflict::columns([manifest::Column::Space, manifest::Column::DbId])
                                .do_nothing()
                                .to_owned(),
                        )
                        .exec_without_returning(txn)
                        .await?;
                inserted == 1
            }
            Some(token) => Self::cas(txn, db, token, publish).await? == 1,
        };
        if !won {
            return Ok(PublishStep::Lost);
        }
        let flipped = object::Entity::update_many()
            .col_expr(
                object::Column::State,
                Expr::value(ObjectState::Published.as_str()),
            )
            .filter(object_pk(db, obj)?)
            .filter(object::Column::State.eq(ObjectState::Uploaded.as_str()))
            .filter(object::Column::Format.eq(required_format(obj.kind())))
            .exec(txn)
            .await?
            .rows_affected;
        if flipped != 1 {
            return Err(SqlStoreError::ObjectNotUploaded);
        }
        Ok(PublishStep::Won(Self::read(txn, db).await?))
    }

    /// Insert one inventory row as `uploaded`, or report the existing row's state.
    async fn record_in<C: ConnectionTrait>(
        conn: &C,
        db: &DbRef<'_>,
        record: &ObjectRecord,
    ) -> Result<ObjectState, SqlStoreError> {
        let key = &record.key;
        if record.format != required_format(key.kind()) {
            return Err(SqlStoreError::Invalid(
                "object format does not match its kind",
            ));
        }
        let created_at = canonical_timestamp(&record.created_at)?;
        let row = object::ActiveModel {
            space: Set(db.space.to_owned()),
            db_id: Set(db.db_id.to_owned()),
            lineage: Set(key.lineage().to_string()),
            kind: Set(key.kind().as_str().to_owned()),
            base_seq: Set(to_i64(key.base_seq())?),
            from_seq: Set(to_i64(key.from_seq())?),
            to_seq: Set(to_i64(key.to_seq())?),
            content_hash: Set(key.content_hash()),
            format: Set(record.format.clone()),
            key: Set(key.as_str().to_owned()),
            bytes: Set(to_i64(record.bytes)?),
            state: Set(ObjectState::Uploaded.as_str().to_owned()),
            created_at: Set(created_at),
        };
        use object::Column as C;
        let inserted = object::Entity::insert(row)
            .on_conflict(
                OnConflict::columns([
                    C::Space,
                    C::DbId,
                    C::Lineage,
                    C::Kind,
                    C::BaseSeq,
                    C::FromSeq,
                    C::ToSeq,
                    C::ContentHash,
                ])
                .do_nothing()
                .to_owned(),
            )
            .exec_without_returning(conn)
            .await?;
        if inserted == 1 {
            return Ok(ObjectState::Uploaded);
        }
        let existing = object::Entity::find()
            .filter(object_pk(db, key)?)
            .one(conn)
            .await?
            .ok_or(SqlStoreError::Invalid("object row vanished"))?;
        if existing.bytes != to_i64(record.bytes)? {
            return Err(SqlStoreError::Conflict);
        }
        ObjectState::parse(&existing.state)
    }

    /// The recorded size of the object stored under `key`.
    async fn object_bytes<C: ConnectionTrait>(
        conn: &C,
        db: &DbRef<'_>,
        key: &str,
    ) -> Result<u64, SqlStoreError> {
        let row = object::Entity::find()
            .filter(object::Column::Space.eq(db.space))
            .filter(object::Column::DbId.eq(db.db_id))
            .filter(object::Column::Key.eq(key))
            .one(conn)
            .await?
            .ok_or(SqlStoreError::Invalid("base snapshot is not recorded"))?;
        u64::try_from(row.bytes).map_err(|_| SqlStoreError::Invalid("negative size"))
    }

    /// The transactional part of [`SqlManifest::publish_chain`]. Returns with
    /// `txn` open; the caller commits after `Won` or `Lost` and rolls back on
    /// an error.
    async fn chain_in(
        txn: &DatabaseTransaction,
        db: &DbRef<'_>,
        expected: Option<&Frontier>,
        chain: &PublishChain,
    ) -> Result<ChainStep, SqlStoreError> {
        for record in &chain.objects {
            Self::record_in(txn, db, record).await?;
        }
        let mut current = expected.cloned();
        let mut base_bytes = None;
        for (i, record) in chain.objects.iter().enumerate() {
            let obj = &record.key;
            let kind = match (obj.kind(), &current) {
                (ObjectKind::Snapshot, _) if i > 0 => {
                    return Err(SqlStoreError::Invalid(
                        "only the first object of a chain can be a snapshot",
                    ))
                }
                (ObjectKind::Snapshot, Some(f)) if &f.lineage != obj.lineage() => {
                    PublishKind::LineageSwitch
                }
                (ObjectKind::Snapshot, _) => PublishKind::Snapshot,
                (ObjectKind::Segment, Some(f)) => PublishKind::Segment {
                    base_snapshot_key: f.base_snapshot_key.clone(),
                },
                (ObjectKind::Segment, None) => {
                    return Err(SqlStoreError::Invalid("a segment needs a published base"))
                }
            };
            let frontier_bytes = match (&kind, base_bytes) {
                (PublishKind::Segment { .. }, Some(base)) => base + record.bytes,
                (PublishKind::Segment { base_snapshot_key }, None) => {
                    let base = Self::object_bytes(txn, db, base_snapshot_key).await?;
                    base_bytes = Some(base);
                    base + record.bytes
                }
                _ => {
                    base_bytes = Some(record.bytes);
                    record.bytes
                }
            };
            let token = current.as_ref().map(Frontier::token);
            let publish = Publish {
                kind,
                object: obj.clone(),
                base_checkpoint_cid: chain.base_checkpoint_cid.clone(),
                frontier_bytes,
                publish_id: chain.publish_id.clone(),
                now: chain.now.clone(),
            };
            check_publish(&publish, token.as_ref())?;
            match Self::publish_in(txn, db, token.as_ref(), &publish).await? {
                PublishStep::Lost if i == 0 => return Ok(ChainStep::Lost),
                PublishStep::Lost => {
                    return Err(SqlStoreError::Invalid(
                        "publish chain lost its CAS after the first object",
                    ))
                }
                PublishStep::Won(Some(frontier)) => current = Some(frontier),
                PublishStep::Won(None) => {
                    return Err(SqlStoreError::Invalid(
                        "manifest row vanished after publish",
                    ))
                }
            }
        }
        current
            .map(ChainStep::Won)
            .ok_or(SqlStoreError::Invalid("empty publish chain"))
    }
}

/// What the transactional part of a chain publish decided.
enum ChainStep {
    Won(Frontier),
    /// The first CAS lost; the inventory rows are kept.
    Lost,
}

/// A publish's kind must match its object and the token it replaces.
fn check_publish(publish: &Publish, expected: Option<&CasToken>) -> Result<(), SqlStoreError> {
    let obj = &publish.object;
    match (&publish.kind, expected) {
        (PublishKind::Snapshot, None) if obj.kind() == ObjectKind::Snapshot => {}
        (PublishKind::Snapshot, Some(t))
            if obj.kind() == ObjectKind::Snapshot && obj.lineage() == &t.lineage => {}
        (PublishKind::LineageSwitch, Some(t))
            if obj.kind() == ObjectKind::Snapshot && obj.lineage() != &t.lineage => {}
        (PublishKind::Segment { .. }, Some(t))
            if obj.kind() == ObjectKind::Segment && obj.lineage() == &t.lineage => {}
        _ => {
            return Err(SqlStoreError::Invalid(
                "publish kind does not match its inputs",
            ))
        }
    }
    if matches!(publish.kind, PublishKind::Segment { .. })
        && obj.from_seq() != obj.base_seq() + 1
    {
        return Err(SqlStoreError::Invalid("segment must start at base_seq + 1"));
    }
    Ok(())
}

#[async_trait]
impl SqlManifest for DbSqlManifest {
    async fn current(&self, db: &DbRef<'_>) -> Result<Option<Frontier>, SqlStoreError> {
        check_db(db)?;
        Self::read(&self.db, db).await
    }

    async fn publish_cas(
        &self,
        db: &DbRef<'_>,
        expected: Option<&CasToken>,
        publish: Publish,
    ) -> Result<PublishOutcome, SqlStoreError> {
        check_db(db)?;
        check_publish(&publish, expected)?;
        let txn = self.db.begin().await?;
        let step = match Self::publish_in(&txn, db, expected, &publish).await {
            Ok(step) => step,
            Err(err) => {
                let _ = txn.rollback().await;
                return Err(err);
            }
        };
        match step {
            PublishStep::Lost => {
                txn.rollback().await?;
                Ok(PublishOutcome::Lost(Self::read(&self.db, db).await?))
            }
            PublishStep::Won(published) => {
                txn.commit().await?;
                match published {
                    Some(frontier) => Ok(PublishOutcome::Published(frontier)),
                    None => Err(SqlStoreError::Invalid(
                        "manifest row vanished after publish",
                    )),
                }
            }
        }
    }

    async fn record_object(
        &self,
        db: &DbRef<'_>,
        record: &ObjectRecord,
    ) -> Result<ObjectState, SqlStoreError> {
        check_db(db)?;
        Self::record_in(&self.db, db, record).await
    }

    async fn publish_chain(
        &self,
        db: &DbRef<'_>,
        expected: Option<&Frontier>,
        chain: PublishChain,
    ) -> Result<PublishOutcome, SqlStoreError> {
        check_db(db)?;
        let Some(last) = chain.objects.last() else {
            return Err(SqlStoreError::Invalid("empty publish chain"));
        };
        if expected.is_some_and(|f| last.key.to_seq() < f.last_seq) {
            return Err(SqlStoreError::Invalid("publish chain would regress last_seq"));
        }
        let txn = self.db.begin().await?;
        match Self::chain_in(&txn, db, expected, &chain).await {
            Ok(ChainStep::Won(frontier)) => {
                txn.commit().await?;
                Ok(PublishOutcome::Published(frontier))
            }
            Ok(ChainStep::Lost) => {
                txn.commit().await?;
                Ok(PublishOutcome::Lost(Self::read(&self.db, db).await?))
            }
            Err(err) => {
                let _ = txn.rollback().await;
                Err(err)
            }
        }
    }

    async fn list_objects(
        &self,
        db: &DbRef<'_>,
        state: Option<ObjectState>,
    ) -> Result<Vec<ObjectRecord>, SqlStoreError> {
        check_db(db)?;
        let mut query = object::Entity::find()
            .filter(object::Column::Space.eq(db.space))
            .filter(object::Column::DbId.eq(db.db_id));
        if let Some(state) = state {
            query = query.filter(object::Column::State.eq(state.as_str()));
        }
        let rows = query
            .order_by_asc(object::Column::Lineage)
            .order_by_asc(object::Column::BaseSeq)
            .order_by_asc(object::Column::FromSeq)
            .order_by_asc(object::Column::ToSeq)
            .all(&self.db)
            .await?;
        rows.into_iter()
            .map(|row| {
                let hash: [u8; 32] = hex::decode(&row.content_hash)
                    .ok()
                    .and_then(|b| b.try_into().ok())
                    .ok_or(SqlStoreError::Invalid("bad content hash"))?;
                let lineage = Lineage::parse(&row.lineage)?;
                let kind = ObjectKind::parse(&row.kind)
                    .ok_or(SqlStoreError::Invalid("unknown object kind"))?;
                let (base, from, to) = (
                    u64::try_from(row.base_seq),
                    u64::try_from(row.from_seq),
                    u64::try_from(row.to_seq),
                );
                let (Ok(base), Ok(from), Ok(to)) = (base, from, to) else {
                    return Err(SqlStoreError::Invalid("negative seq"));
                };
                let dbref = DbRef {
                    space: &row.space,
                    db_id: &row.db_id,
                };
                let key = match kind {
                    ObjectKind::Snapshot => ObjectKey::snapshot(&dbref, &lineage, base, &hash)?,
                    ObjectKind::Segment => {
                        ObjectKey::segment(&dbref, &lineage, base, from, to, &hash)?
                    }
                };
                Ok(ObjectRecord {
                    key,
                    format: row.format,
                    bytes: u64::try_from(row.bytes)
                        .map_err(|_| SqlStoreError::Invalid("negative size"))?,
                    created_at: row.created_at,
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migrations::Migrator;
    use crate::sql::store::object::sha256;
    use crate::test_support::PostgresTestSchema;
    use sea_orm::{ConnectOptions, Database};
    use sea_orm_migration::MigratorTrait;
    use std::sync::Arc;

    const DB: DbRef<'static> = DbRef {
        space: "tinycloud:pkh:eip155:1:0xAb://default",
        db_id: "v2dabc",
    };
    const CID: &str = "ckpt-1";

    async fn sqlite() -> DbSqlManifest {
        // One connection: `sqlite::memory:` is private to each connection.
        let mut options = ConnectOptions::new("sqlite::memory:".to_string());
        options.max_connections(1).sqlx_logging(false);
        let conn = Database::connect(options).await.unwrap();
        Migrator::up(&conn, None).await.unwrap();
        DbSqlManifest::new(conn)
    }

    fn snap(lineage: &Lineage, at: u64, tag: &str) -> ObjectKey {
        ObjectKey::snapshot(&DB, lineage, at, &sha256(tag.as_bytes())).unwrap()
    }

    fn seg(lineage: &Lineage, base: u64, from: u64, to: u64, tag: &str) -> ObjectKey {
        ObjectKey::segment(&DB, lineage, base, from, to, &sha256(tag.as_bytes())).unwrap()
    }

    async fn record(m: &DbSqlManifest, key: &ObjectKey) -> ObjectState {
        let format = match key.kind() {
            ObjectKind::Snapshot => "sqlite-v1",
            ObjectKind::Segment => "wal-cum-v1",
        };
        m.record_object(
            &DB,
            &ObjectRecord {
                key: key.clone(),
                format: format.into(),
                bytes: 10,
                created_at: "2026-10-21T00:00:00Z".into(),
            },
        )
        .await
        .unwrap()
    }

    fn publish(kind: PublishKind, object: &ObjectKey, cid: &str) -> Publish {
        Publish {
            kind,
            object: object.clone(),
            base_checkpoint_cid: cid.into(),
            frontier_bytes: 20,
            publish_id: PublishId::random(),
            now: "2026-10-21T00:01:00Z".into(),
        }
    }

    async fn first(m: &DbSqlManifest, lineage: &Lineage, at: u64) -> Frontier {
        let key = snap(lineage, at, "first");
        record(m, &key).await;
        match m
            .publish_cas(&DB, None, publish(PublishKind::Snapshot, &key, CID))
            .await
            .unwrap()
        {
            PublishOutcome::Published(f) => f,
            other => panic!("first publish lost: {other:?}"),
        }
    }

    async fn segment_outcome(
        m: &DbSqlManifest,
        f: &Frontier,
        from: u64,
        to: u64,
        tag: &str,
        cid: &str,
    ) -> Result<PublishOutcome, SqlStoreError> {
        let key = seg(&f.lineage, f.base_seq, from, to, tag);
        record(m, &key).await;
        m.publish_cas(
            &DB,
            Some(&f.token()),
            publish(
                PublishKind::Segment {
                    base_snapshot_key: f.base_snapshot_key.clone(),
                },
                &key,
                cid,
            ),
        )
        .await
    }

    async fn publish_segment(
        m: &DbSqlManifest,
        f: &Frontier,
        from: u64,
        to: u64,
        tag: &str,
        cid: &str,
    ) -> PublishOutcome {
        segment_outcome(m, f, from, to, tag, cid).await.unwrap()
    }

    fn lost(outcome: PublishOutcome) -> Option<Frontier> {
        match outcome {
            PublishOutcome::Lost(current) => current,
            other => panic!("expected the CAS to lose, got {other:?}"),
        }
    }

    async fn state_of(m: &DbSqlManifest, key: &ObjectKey) -> ObjectState {
        // Recording is idempotent and reports the current state.
        record(m, key).await
    }

    async fn first_publish_is_a_single_winner(m: DbSqlManifest) {
        let l1 = Lineage::random();
        let f = first(&m, &l1, 5).await;
        assert_eq!((f.revision, f.last_seq, f.base_seq, f.epoch), (0, 5, 5, 0));
        assert_eq!(f.base_checkpoint_cid, CID);
        // A second first-publish loses without aborting anything.
        let l2 = Lineage::random();
        let other = snap(&l2, 9, "other");
        record(&m, &other).await;
        let current = lost(
            m.publish_cas(&DB, None, publish(PublishKind::Snapshot, &other, CID))
                .await
                .unwrap(),
        );
        assert_eq!(current.unwrap(), f);
        assert_eq!(state_of(&m, &other).await, ObjectState::Uploaded);
        assert_eq!(
            state_of(&m, &snap(&l1, 5, "first")).await,
            ObjectState::Published
        );
    }

    async fn segments_are_contiguous_and_advance(m: DbSqlManifest) {
        let f = first(&m, &Lineage::random(), 5).await;
        // A gap (6 is missing) is an invalid request, not a lost CAS.
        assert!(matches!(
            segment_outcome(&m, &f, 8, 9, "gap", CID).await,
            Err(SqlStoreError::Invalid(_))
        ));
        // The refused segment is recorded but never applied.
        let gap = seg(&f.lineage, f.base_seq, 8, 9, "gap");
        assert_eq!(state_of(&m, &gap).await, ObjectState::Uploaded);
        assert_eq!(m.current(&DB).await.unwrap().unwrap(), f);
        // Cumulative WAL segments always start at base_seq + 1.
        let PublishOutcome::Published(f1) = publish_segment(&m, &f, 6, 8, "a", CID).await else {
            panic!("append lost");
        };
        assert_eq!((f1.revision, f1.last_seq, f1.base_seq), (1, 8, 5));
        let PublishOutcome::Published(f2) = publish_segment(&m, &f1, 6, 12, "b", CID).await else {
            panic!("second append lost");
        };
        assert_eq!((f2.revision, f2.last_seq), (2, 12));
        // A regression (to <= last_seq) loses even with the right token.
        assert!(lost(publish_segment(&m, &f2, 6, 11, "back", CID).await).is_some());
        assert!(lost(publish_segment(&m, &f2, 6, 12, "same", CID).await).is_some());
        assert_eq!(m.current(&DB).await.unwrap().unwrap(), f2);
    }

    async fn segment_from_must_follow_base_seq(m: DbSqlManifest) {
        let f = first(&m, &Lineage::random(), 5).await;
        // from_seq = base_seq + 2 skips one sequence number. No frontier accepts
        // this key, so it is refused as invalid rather than reported as a lost CAS.
        let skipped = seg(&f.lineage, 5, 7, 9, "skip");
        assert!(matches!(
            segment_outcome(&m, &f, 7, 9, "skip", CID).await,
            Err(SqlStoreError::Invalid(_))
        ));
        assert_eq!(state_of(&m, &skipped).await, ObjectState::Uploaded);
        assert_eq!(m.current(&DB).await.unwrap().unwrap(), f);
        // from_seq = base_seq + 1 is the only accepted start.
        let PublishOutcome::Published(f1) = publish_segment(&m, &f, 6, 8, "a", CID).await else {
            panic!("base_seq + 1 segment lost");
        };
        // The frontier is at 8. A segment from 9 passes the last_seq check
        // (8 >= 9 - 1), so only the from_seq rule refuses it.
        let gap = seg(&f.lineage, 5, 9, 12, "gap");
        assert!(matches!(
            segment_outcome(&m, &f1, 9, 12, "gap", CID).await,
            Err(SqlStoreError::Invalid(_))
        ));
        assert_eq!(state_of(&m, &gap).await, ObjectState::Uploaded);
        assert_eq!(m.current(&DB).await.unwrap().unwrap(), f1);
    }

    async fn object_state_flip_checks_the_format(m: DbSqlManifest) {
        let key = snap(&Lineage::random(), 5, "flip");
        record(&m, &key).await;
        // Corrupt the stored format behind the manifest's back.
        object::Entity::update_many()
            .col_expr(object::Column::Format, Expr::value("wal-cum-v1"))
            .filter(object::Column::Key.eq(key.as_str()))
            .exec(&m.db)
            .await
            .unwrap();
        assert!(matches!(
            m.publish_cas(&DB, None, publish(PublishKind::Snapshot, &key, CID))
                .await,
            Err(SqlStoreError::ObjectNotUploaded)
        ));
        assert!(m.current(&DB).await.unwrap().is_none());
    }

    async fn stale_epoch_lineage_and_revision_are_rejected(m: DbSqlManifest) {
        let l = Lineage::random();
        let f = first(&m, &l, 5).await;
        let key = seg(&l, 5, 6, 7, "s");
        record(&m, &key).await;
        let kind = PublishKind::Segment {
            base_snapshot_key: f.base_snapshot_key.clone(),
        };
        for token in [
            CasToken {
                epoch: 1,
                ..f.token()
            },
            CasToken {
                revision: 7,
                ..f.token()
            },
            CasToken {
                lineage: Lineage::random(),
                ..f.token()
            },
        ] {
            // A foreign-lineage token is a caller error (the key names its
            // lineage); the other two are CAS losses.
            let result = m
                .publish_cas(&DB, Some(&token), publish(kind.clone(), &key, CID))
                .await;
            if token.lineage != l {
                assert!(matches!(result, Err(SqlStoreError::Invalid(_))));
            } else {
                assert!(lost(result.unwrap()).is_some());
            }
        }
        // A snapshot publish on a stale lineage is lost the same way.
        let newer = snap(&l, 9, "newer");
        record(&m, &newer).await;
        let stale = CasToken {
            epoch: 3,
            ..f.token()
        };
        assert!(lost(
            m.publish_cas(
                &DB,
                Some(&stale),
                publish(PublishKind::Snapshot, &newer, "ckpt-2")
            )
            .await
            .unwrap()
        )
        .is_some());
        assert_eq!(m.current(&DB).await.unwrap().unwrap(), f);
    }

    async fn segments_need_the_matching_checkpoint(m: DbSqlManifest) {
        let f = first(&m, &Lineage::random(), 5).await;
        // The artifact's checkpoint changed: appending would apply the WAL to
        // the wrong base, so the CAS loses and a new snapshot is needed.
        assert!(lost(publish_segment(&m, &f, 6, 7, "x", "ckpt-OTHER").await).is_some());
        // A segment bound to another snapshot key loses too.
        let key = seg(&f.lineage, 5, 6, 7, "y");
        record(&m, &key).await;
        let wrong = PublishKind::Segment {
            base_snapshot_key: "sql/v1/elsewhere".into(),
        };
        assert!(lost(
            m.publish_cas(&DB, Some(&f.token()), publish(wrong, &key, CID))
                .await
                .unwrap()
        )
        .is_some());
        // A new snapshot in the same lineage re-bases the chain.
        let s2 = snap(&f.lineage, 9, "second");
        record(&m, &s2).await;
        let PublishOutcome::Published(f2) = m
            .publish_cas(
                &DB,
                Some(&f.token()),
                publish(PublishKind::Snapshot, &s2, "ckpt-2"),
            )
            .await
            .unwrap()
        else {
            panic!("snapshot lost");
        };
        assert_eq!((f2.revision, f2.base_seq, f2.last_seq), (1, 9, 9));
        assert_eq!(f2.base_checkpoint_cid, "ckpt-2");
        assert_eq!(f2.lineage, f.lineage);
        // Segments now follow the new base only.
        let old_base = seg(&f2.lineage, 5, 6, 12, "old-base");
        record(&m, &old_base).await;
        let kind = PublishKind::Segment {
            base_snapshot_key: f2.base_snapshot_key.clone(),
        };
        assert!(lost(
            m.publish_cas(&DB, Some(&f2.token()), publish(kind, &old_base, "ckpt-2"))
                .await
                .unwrap()
        )
        .is_some());
        // The snapshot's own `last_seq <= at_seq` guard: no regression.
        let behind = snap(&f.lineage, 3, "behind");
        record(&m, &behind).await;
        assert!(lost(
            m.publish_cas(
                &DB,
                Some(&f2.token()),
                publish(PublishKind::Snapshot, &behind, CID)
            )
            .await
            .unwrap()
        )
        .is_some());
    }

    async fn lineage_switch_keeps_revision_monotonic(m: DbSqlManifest) {
        let old = Lineage::random();
        let f = first(&m, &old, 20).await;
        let new = Lineage::random();
        let s = snap(&new, 4, "fresh");
        record(&m, &s).await;
        // Same lineage as the token is not a switch.
        assert!(matches!(
            m.publish_cas(
                &DB,
                Some(&f.token()),
                publish(PublishKind::Snapshot, &s, CID)
            )
            .await,
            Err(SqlStoreError::Invalid(_))
        ));
        let PublishOutcome::Published(f2) = m
            .publish_cas(
                &DB,
                Some(&f.token()),
                publish(PublishKind::LineageSwitch, &s, "ckpt-2"),
            )
            .await
            .unwrap()
        else {
            panic!("switch lost");
        };
        assert_eq!(f2.lineage, new);
        assert_eq!((f2.revision, f2.last_seq, f2.base_seq), (1, 4, 4));
        assert_eq!(f2.base_checkpoint_cid, "ckpt-2");
        // The writer that still holds the old lineage is stale now.
        let late = snap(&new, 8, "late");
        record(&m, &late).await;
        assert!(lost(
            m.publish_cas(
                &DB,
                Some(&f.token()),
                publish(PublishKind::LineageSwitch, &late, CID)
            )
            .await
            .unwrap()
        )
        .is_some());
    }

    async fn lost_response_is_reconciled_by_publish_id(m: DbSqlManifest) {
        let f = first(&m, &Lineage::random(), 5).await;
        let key = seg(&f.lineage, 5, 6, 9, "r");
        record(&m, &key).await;
        let attempt = publish(
            PublishKind::Segment {
                base_snapshot_key: f.base_snapshot_key.clone(),
            },
            &key,
            CID,
        );
        let pid = attempt.publish_id.to_string();
        // The response is lost; the caller re-reads instead of re-issuing.
        m.publish_cas(&DB, Some(&f.token()), attempt.clone())
            .await
            .unwrap();
        let current = m.current(&DB).await.unwrap().unwrap();
        assert_eq!(
            (current.revision, current.publish_id.as_str()),
            (1, pid.as_str())
        );
        // Re-issuing blindly is a loss (the token is stale), never a double publish.
        assert!(lost(m.publish_cas(&DB, Some(&f.token()), attempt).await.unwrap()).is_some());
        // Segment-CAS retry after another publisher won: re-derive the range
        // from current.last_seq + 1 on the new revision.
        let PublishOutcome::Published(f2) =
            publish_segment(&m, &current, 6, 14, "retry", CID).await
        else {
            panic!("retry lost");
        };
        assert_eq!((f2.revision, f2.last_seq), (2, 14));
    }

    async fn state_flips_are_conditional(m: DbSqlManifest) {
        let f = first(&m, &Lineage::random(), 5).await;
        let key = seg(&f.lineage, 5, 6, 7, "o");
        record(&m, &key).await;
        let kind = PublishKind::Segment {
            base_snapshot_key: f.base_snapshot_key.clone(),
        };
        let PublishOutcome::Published(f2) = m
            .publish_cas(&DB, Some(&f.token()), publish(kind, &key, CID))
            .await
            .unwrap()
        else {
            panic!("publish lost");
        };
        assert_eq!(f2.last_seq, 7);
        // Recording again is idempotent and reports the flipped state.
        assert_eq!(state_of(&m, &key).await, ObjectState::Published);
        // An object that was never recorded cannot be published.
        let ghost = seg(&f2.lineage, 5, 6, 20, "ghost");
        assert!(matches!(
            m.publish_cas(
                &DB,
                Some(&f2.token()),
                publish(
                    PublishKind::Segment {
                        base_snapshot_key: f2.base_snapshot_key.clone()
                    },
                    &ghost,
                    CID
                )
            )
            .await,
            Err(SqlStoreError::ObjectNotUploaded)
        ));
        assert_eq!(m.current(&DB).await.unwrap().unwrap(), f2, "CAS rolled back");
    }

    /// A publish whose read-back fails in Rust after the manifest row UPDATE
    /// ends its write transaction, so the row lock it took is released. The
    /// fault is a `BEFORE UPDATE` trigger storing a negative `frontier_bytes`,
    /// which `from_model` refuses as `negative seq`. A PostgreSQL statement
    /// error would abort the transaction and free the lock by itself, so the
    /// fault is Rust-side. PostgreSQL only; the probe runs in CI, not locally.
    #[tokio::test]
    async fn postgres_failed_readback_publish_releases_its_manifest_row_lock() {
        use sea_orm::ConnectionTrait;

        const FAIL_READBACK_SQL: &str = "
CREATE FUNCTION tc1836_fail_manifest_readback() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    NEW.frontier_bytes := -1;
    RETURN NEW;
END
$$;
CREATE TRIGGER tc1836_fail_manifest_readback BEFORE UPDATE ON sql_store_manifest
    FOR EACH ROW EXECUTE FUNCTION tc1836_fail_manifest_readback();
";
        let Some(fixture) =
            PostgresTestSchema::new("postgres_sql_store_failed_readback_row_lock").await
        else {
            return;
        };
        let m = DbSqlManifest::new(fixture.connect(10).await);
        let f = first(&m, &Lineage::random(), 5).await;
        let key = seg(&f.lineage, f.base_seq, 6, 7, "readback");
        record(&m, &key).await;
        m.db.execute_unprepared(FAIL_READBACK_SQL).await.unwrap();
        assert!(matches!(
            m.publish_cas(
                &DB,
                Some(&f.token()),
                publish(
                    PublishKind::Segment {
                        base_snapshot_key: f.base_snapshot_key.clone(),
                    },
                    &key,
                    CID,
                ),
            )
            .await,
            Err(SqlStoreError::Invalid("negative seq"))
        ));
        // The refused publish has returned, so its manifest row lock must be
        // released. Fresh session on its own thread, not the manifest's pool.
        fixture
            .execute_blocking(&format!(
                "SELECT space FROM sql_store_manifest WHERE space = '{}' AND db_id = '{}' FOR UPDATE NOWAIT",
                DB.space, DB.db_id
            ))
            .expect("manifest row lock released after the failed read-back");
        // The CAS rolled back: with the trigger gone, the row still holds `f`.
        m.db.execute_unprepared("DROP TRIGGER tc1836_fail_manifest_readback ON sql_store_manifest")
            .await
            .unwrap();
        assert_eq!(m.current(&DB).await.unwrap().unwrap(), f, "CAS rolled back");
    }

    async fn inventory_listing_and_conflicts(m: DbSqlManifest) {
        let l = Lineage::random();
        let a = snap(&l, 1, "a");
        assert_eq!(record(&m, &a).await, ObjectState::Uploaded);
        assert_eq!(record(&m, &a).await, ObjectState::Uploaded);
        let different_size = ObjectRecord {
            key: a.clone(),
            format: "sqlite-v1".into(),
            bytes: 11,
            created_at: "2026-10-21T00:00:00Z".into(),
        };
        assert!(matches!(
            m.record_object(&DB, &different_size).await,
            Err(SqlStoreError::Conflict)
        ));
        record(&m, &seg(&l, 1, 2, 3, "b")).await;
        let all = m.list_objects(&DB, None).await.unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].key, a);
        assert!(m
            .list_objects(&DB, Some(ObjectState::Published))
            .await
            .unwrap()
            .is_empty());
        // Another database in the same space is separate.
        let other = DbRef {
            db_id: "v2dother",
            ..DB
        };
        assert!(m.list_objects(&other, None).await.unwrap().is_empty());
        assert!(m.current(&other).await.unwrap().is_none());
        // Over-long or empty ids are refused before touching the database.
        let long = "x".repeat(256);
        assert!(m
            .current(&DbRef {
                space: &long,
                db_id: "d"
            })
            .await
            .is_err());
        assert!(m
            .current(&DbRef {
                space: "",
                db_id: "d"
            })
            .await
            .is_err());
    }

    async fn concurrent_publishers_have_one_winner(m: DbSqlManifest) {
        let m = Arc::new(m);
        // First publication: eight racers.
        let l = Lineage::random();
        let mut keys = Vec::new();
        for i in 0..8u64 {
            let key = snap(&l, 5, &format!("racer-{i}"));
            record(&m, &key).await;
            keys.push(key);
        }
        let mut tasks = Vec::new();
        for key in keys {
            let m = m.clone();
            tasks.push(tokio::spawn(async move {
                m.publish_cas(&DB, None, publish(PublishKind::Snapshot, &key, CID))
                    .await
            }));
        }
        let mut winners = 0;
        for task in tasks {
            if matches!(task.await.unwrap().unwrap(), PublishOutcome::Published(_)) {
                winners += 1;
            }
        }
        assert_eq!(winners, 1, "first publish");
        // Appends from one revision: eight racers, one winner.
        let f = m.current(&DB).await.unwrap().unwrap();
        let mut tasks = Vec::new();
        for i in 0..8u64 {
            let key = seg(&f.lineage, 5, 6, 7 + i, &format!("seg-{i}"));
            record(&m, &key).await;
            let (m, token, kind) = (
                m.clone(),
                f.token(),
                PublishKind::Segment {
                    base_snapshot_key: f.base_snapshot_key.clone(),
                },
            );
            tasks.push(tokio::spawn(async move {
                m.publish_cas(&DB, Some(&token), publish(kind, &key, CID))
                    .await
            }));
        }
        let mut winners = 0;
        for task in tasks {
            if matches!(task.await.unwrap().unwrap(), PublishOutcome::Published(_)) {
                winners += 1;
            }
        }
        assert_eq!(winners, 1, "append");
        let after = m.current(&DB).await.unwrap().unwrap();
        assert_eq!(after.revision, f.revision + 1);
        let published = m
            .list_objects(&DB, Some(ObjectState::Published))
            .await
            .unwrap();
        assert_eq!(published.len(), 2, "one snapshot and one segment");
    }

    async fn object_format_must_match_its_kind(m: DbSqlManifest) {
        let l = Lineage::random();
        let s = snap(&l, 1, "fmt-s");
        let g = seg(&l, 1, 2, 3, "fmt-g");
        for (key, format) in [(&s, "wal-cum-v1"), (&g, "sqlite-v1")] {
            let rec = ObjectRecord {
                key: key.clone(),
                format: format.into(),
                bytes: 10,
                created_at: "2026-10-21T00:00:00Z".into(),
            };
            assert!(matches!(
                m.record_object(&DB, &rec).await,
                Err(SqlStoreError::Invalid(_))
            ));
        }
        assert!(m.list_objects(&DB, None).await.unwrap().is_empty());
    }

    async fn created_at_is_stored_canonically(m: DbSqlManifest) {
        let l = Lineage::random();
        let rec = ObjectRecord {
            key: snap(&l, 1, "ts-a"),
            format: "sqlite-v1".into(),
            bytes: 10,
            created_at: "2026-10-21T02:00:00+02:00".into(),
        };
        assert_eq!(
            m.record_object(&DB, &rec).await.unwrap(),
            ObjectState::Uploaded
        );
        let listed = m.list_objects(&DB, None).await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].created_at, "2026-10-21T00:00:00.000000Z");
        let malformed = ObjectRecord {
            key: snap(&l, 2, "ts-b"),
            format: "sqlite-v1".into(),
            bytes: 10,
            created_at: "not a time".into(),
        };
        assert!(matches!(
            m.record_object(&DB, &malformed).await,
            Err(SqlStoreError::Invalid(_))
        ));
    }

    #[test]
    fn created_at_out_of_range_is_invalid_not_a_panic() {
        // Both inputs are valid RFC 3339, but UTC conversion leaves years 0..=9999.
        for text in ["9999-12-31T23:30:00-01:00", "0000-01-01T00:30:00+01:00"] {
            assert!(matches!(
                canonical_timestamp(text),
                Err(SqlStoreError::Invalid(_))
            ));
        }
    }

    fn rec(key: &ObjectKey) -> ObjectRecord {
        ObjectRecord {
            key: key.clone(),
            format: required_format(key.kind()).into(),
            bytes: 10,
            created_at: "2026-10-21T00:00:00Z".into(),
        }
    }

    fn chain(keys: &[&ObjectKey]) -> PublishChain {
        PublishChain {
            objects: keys.iter().map(|k| rec(k)).collect(),
            base_checkpoint_cid: CID.into(),
            publish_id: PublishId::random(),
            now: "2026-10-21T00:01:00Z".into(),
        }
    }

    async fn chain_bootstrap_publishes_snapshot_and_segment_atomically(m: DbSqlManifest) {
        let l = Lineage::random();
        let (s, g) = (snap(&l, 0, "boot"), seg(&l, 0, 1, 7, "wal"));
        let PublishOutcome::Published(f) = m
            .publish_chain(&DB, None, chain(&[&s, &g]))
            .await
            .unwrap()
        else {
            panic!("bootstrap chain lost");
        };
        assert_eq!(
            (f.base_seq, f.last_seq, f.frontier_bytes, f.base_snapshot_key.as_str()),
            (0, 7, 20, s.as_str())
        );
        assert_eq!(f.base_checkpoint_cid, CID);
        assert_eq!(state_of(&m, &s).await, ObjectState::Published);
        assert_eq!(state_of(&m, &g).await, ObjectState::Published);
    }

    async fn chain_lost_first_cas_keeps_the_inventory(m: DbSqlManifest) {
        let f = first(&m, &Lineage::random(), 5).await;
        let l = Lineage::random();
        let (s, g) = (snap(&l, 0, "late"), seg(&l, 0, 1, 9, "late-wal"));
        let current = lost(
            m.publish_chain(&DB, None, chain(&[&s, &g]))
                .await
                .unwrap(),
        );
        assert_eq!(current.unwrap(), f);
        assert_eq!(state_of(&m, &s).await, ObjectState::Uploaded);
        assert_eq!(state_of(&m, &g).await, ObjectState::Uploaded);
    }

    async fn chain_switches_lineage_then_appends_on_the_recorded_base(m: DbSqlManifest) {
        let f = first(&m, &Lineage::random(), 5).await;
        let l2 = Lineage::random();
        let (s, g) = (snap(&l2, 0, "switch"), seg(&l2, 0, 1, 9, "switch-wal"));
        let PublishOutcome::Published(f2) = m
            .publish_chain(&DB, Some(&f), chain(&[&s, &g]))
            .await
            .unwrap()
        else {
            panic!("switch chain lost");
        };
        assert_eq!((f2.lineage.clone(), f2.last_seq), (l2.clone(), 9));
        assert!(f2.revision > f.revision, "revision stays monotonic");
        // A segment-only chain sizes its frontier from the recorded base.
        let g2 = seg(&l2, 0, 1, 12, "more-wal");
        let PublishOutcome::Published(f3) = m
            .publish_chain(&DB, Some(&f2), chain(&[&g2]))
            .await
            .unwrap()
        else {
            panic!("segment chain lost");
        };
        assert_eq!((f3.last_seq, f3.frontier_bytes), (12, 20));
        assert_eq!(f3.base_snapshot_key, s.as_str());
    }

    async fn chain_loss_after_the_first_step_rolls_everything_back(m: DbSqlManifest) {
        let f = first(&m, &Lineage::random(), 5).await;
        let l = f.lineage.clone();
        // The segment names a base the snapshot step does not leave behind.
        let (s, g) = (snap(&l, 9, "mid"), seg(&l, 3, 4, 12, "mid-wal"));
        assert!(matches!(
            m.publish_chain(&DB, Some(&f), chain(&[&s, &g])).await,
            Err(SqlStoreError::Invalid(_))
        ));
        assert_eq!(m.current(&DB).await.unwrap().unwrap(), f);
        assert_eq!(m.list_objects(&DB, None).await.unwrap().len(), 1);
        // A chain ending below the frontier is refused before any write.
        assert!(matches!(
            m.publish_chain(&DB, Some(&f), chain(&[&snap(&l, 3, "old")]))
                .await,
            Err(SqlStoreError::Invalid(_))
        ));
        assert_eq!(m.list_objects(&DB, None).await.unwrap().len(), 1);
    }

    macro_rules! on_both {
        ($($name:ident),* $(,)?) => {$(
            mod $name {
                use super::*;
                #[tokio::test]
                async fn sqlite() {
                    super::$name(super::sqlite().await).await;
                }
                #[tokio::test]
                async fn postgres() {
                    let Some(fixture) = PostgresTestSchema::new(concat!(
                        "postgres_sql_store_",
                        stringify!($name)
                    ))
                    .await
                    else {
                        return;
                    };
                    super::$name(DbSqlManifest::new(fixture.connect(10).await)).await;
                }
            }
        )*};
    }

    on_both!(
        first_publish_is_a_single_winner,
        segments_are_contiguous_and_advance,
        stale_epoch_lineage_and_revision_are_rejected,
        segments_need_the_matching_checkpoint,
        lineage_switch_keeps_revision_monotonic,
        lost_response_is_reconciled_by_publish_id,
        state_flips_are_conditional,
        chain_bootstrap_publishes_snapshot_and_segment_atomically,
        chain_lost_first_cas_keeps_the_inventory,
        chain_switches_lineage_then_appends_on_the_recorded_base,
        chain_loss_after_the_first_step_rolls_everything_back,
        inventory_listing_and_conflicts,
        concurrent_publishers_have_one_winner,
        object_format_must_match_its_kind,
        created_at_is_stored_canonically,
        segment_from_must_follow_base_seq,
        object_state_flip_checks_the_format,
    );
}
