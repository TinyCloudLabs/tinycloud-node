//! Persistence for the at-rest keys: PG/SQLite rows plus a mirror of the
//! sealed ARK rows, escrow bundles and wrapped DEKs in the block store
//! (TC-887 plan §5).
//!
//! The mirror covers a database restored to a point before a key row was
//! written: sealed blobs in object storage outlive such a restore, and an
//! object sealed under a DEK must never meet a different DEK with its id.

use std::sync::Arc;

use base64::Engine;
use sea_orm::{
    sea_query::OnConflict, ActiveValue::Set, ColumnTrait, DbErr, EntityTrait, PaginatorTrait,
    QueryFilter, QueryOrder, QuerySelect, TransactionTrait,
};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::models::{at_rest_escrow, at_rest_key, space_data_key};
use crate::RecoveringConnection;

pub type MirrorError = Box<dyn std::error::Error + Send + Sync>;

/// The largest mirror object a [`KeyMirror`] reads. Key objects are a few
/// hundred bytes; a larger one is junk and is never read into memory.
pub const MAX_MIRROR_OBJECT: usize = 64 * 1024;

/// A mirror object over [`MAX_MIRROR_OBJECT`]. The keyring skips it like
/// any other unreadable object instead of failing.
#[derive(Debug, thiserror::Error)]
#[error("mirror object is larger than {MAX_MIRROR_OBJECT} bytes")]
pub struct MirrorObjectTooLarge;

/// Named control objects next to the node's blocks (`_tc/at-rest/…`). The S3
/// and filesystem block stores implement it in the server crate.
#[async_trait::async_trait]
pub trait KeyMirror: Send + Sync {
    async fn put(&self, name: &str, bytes: Vec<u8>) -> Result<(), MirrorError>;
    async fn get(&self, name: &str) -> Result<Option<Vec<u8>>, MirrorError>;
    /// Names under `prefix`, in any order.
    async fn list(&self, prefix: &str) -> Result<Vec<String>, MirrorError>;
}

pub const MIRROR_PREFIX: &str = "_tc/at-rest/";
pub(crate) const ARK_MIRROR_PREFIX: &str = "_tc/at-rest/ark-";

pub(crate) fn ark_mirror_name(generation: u32, ark_id_hex: &str) -> String {
    format!("{ARK_MIRROR_PREFIX}{generation:010}-{ark_id_hex}.json")
}

pub(crate) fn escrow_mirror_name(efp: &str) -> String {
    format!("{MIRROR_PREFIX}escrow-{efp}.json")
}

pub(crate) fn record_mirror_name(efp: &str) -> String {
    format!("{MIRROR_PREFIX}record-{efp}.json")
}

/// `tag` is a keyed hash of the space (see `hierarchy::dek_mirror_tag`), so
/// the bucket listing doesn't name spaces.
pub(crate) fn dek_mirror_name(tag: &str, dek_id: u32) -> String {
    format!("{MIRROR_PREFIX}dek-{tag}-{dek_id:010}.json")
}

/// Mirror object format version; a newer one is refused, never guessed at.
const MIRROR_VERSION: u32 = 1;

fn check_version(version: u32) -> Result<(), MirrorError> {
    if version == MIRROR_VERSION {
        Ok(())
    } else {
        Err(format!(
            "mirror object version {version} is not supported (this node reads {MIRROR_VERSION})"
        )
        .into())
    }
}

/// The mirrored form of an `at_rest_key` row.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MirroredArk {
    pub version: u32,
    pub generation: u32,
    pub ark_id: String,
    pub w_label: String,
    pub sealed: String,
    pub chain: Option<String>,
    pub created_at: String,
}

fn b64() -> base64::engine::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

impl MirroredArk {
    pub fn from_row(row: &at_rest_key::Model) -> Self {
        Self {
            version: MIRROR_VERSION,
            generation: row.generation as u32,
            ark_id: hex::encode(&row.ark_id),
            w_label: row.w_label.clone(),
            sealed: b64().encode(&row.sealed),
            chain: row.chain.as_ref().map(|c| b64().encode(c)),
            created_at: row.created_at.clone(),
        }
    }

    pub fn into_row(self) -> Result<at_rest_key::Model, MirrorError> {
        check_version(self.version)?;
        Ok(at_rest_key::Model {
            generation: i32::try_from(self.generation)?,
            ark_id: hex::decode(&self.ark_id)?,
            w_label: self.w_label,
            sealed: b64().decode(&self.sealed)?,
            chain: self.chain.map(|c| b64().decode(c)).transpose()?,
            created_at: self.created_at,
        })
    }
}

/// The mirrored form of a `space_data_key` row. The space is not stored:
/// whoever restores the row knows it, and the wrap's AAD binds it.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MirroredDek {
    pub version: u32,
    pub dek_id: u32,
    pub generation: u32,
    pub wrapped: String,
    pub created_at: String,
}

impl MirroredDek {
    pub fn from_row(row: &space_data_key::Model) -> Self {
        Self {
            version: MIRROR_VERSION,
            dek_id: row.dek_id as u32,
            generation: row.generation as u32,
            wrapped: b64().encode(&row.wrapped),
            created_at: row.created_at.clone(),
        }
    }

    pub fn into_row(self, space: &str) -> Result<space_data_key::Model, MirrorError> {
        check_version(self.version)?;
        Ok(space_data_key::Model {
            space: space.to_owned(),
            dek_id: i32::try_from(self.dek_id)?,
            generation: i32::try_from(self.generation)?,
            wrapped: b64().decode(&self.wrapped)?,
            created_at: self.created_at,
        })
    }
}

/// Row access. On SQLite, writes take the node's shared writer lock.
#[derive(Clone)]
pub struct AtRestStore {
    db: RecoveringConnection,
    sqlite_writer_lock: Option<Arc<Mutex<()>>>,
}

fn ignore_conflict<T>(r: Result<T, DbErr>) -> Result<(), DbErr> {
    match r {
        Ok(_) | Err(DbErr::RecordNotInserted) => Ok(()),
        Err(e) => Err(e),
    }
}

impl AtRestStore {
    pub fn new(db: impl Into<RecoveringConnection>) -> Self {
        Self {
            db: db.into(),
            sqlite_writer_lock: None,
        }
    }

    pub fn with_sqlite_writer_lock(mut self, lock: Option<Arc<Mutex<()>>>) -> Self {
        self.sqlite_writer_lock = lock;
        self
    }

    async fn writer(&self) -> Option<tokio::sync::MutexGuard<'_, ()>> {
        match &self.sqlite_writer_lock {
            Some(lock) => Some(lock.lock().await),
            None => None,
        }
    }

    pub async fn keys(&self) -> Result<Vec<at_rest_key::Model>, DbErr> {
        at_rest_key::Entity::find()
            .order_by_asc(at_rest_key::Column::Generation)
            .all(&self.db)
            .await
    }

    /// Insert unless the generation exists. The caller re-reads.
    pub async fn insert_key(&self, row: at_rest_key::Model) -> Result<(), DbErr> {
        let _w = self.writer().await;
        ignore_conflict(
            at_rest_key::Entity::insert(at_rest_key::ActiveModel {
                generation: Set(row.generation),
                ark_id: Set(row.ark_id),
                w_label: Set(row.w_label),
                sealed: Set(row.sealed),
                chain: Set(row.chain),
                created_at: Set(row.created_at),
            })
            .on_conflict(
                OnConflict::column(at_rest_key::Column::Generation)
                    .do_nothing()
                    .to_owned(),
            )
            .exec(&self.db)
            .await,
        )
    }

    /// Replace a generation's seal (after recovery under a new W).
    pub async fn reseal_key(
        &self,
        generation: i32,
        w_label: &str,
        sealed: Vec<u8>,
    ) -> Result<(), DbErr> {
        let _w = self.writer().await;
        at_rest_key::Entity::update_many()
            .col_expr(at_rest_key::Column::WLabel, w_label.into())
            .col_expr(at_rest_key::Column::Sealed, sealed.into())
            .filter(at_rest_key::Column::Generation.eq(generation))
            .exec(&self.db)
            .await
            .map(|_| ())
    }

    /// Write generation `row.generation` and the chain that lets it open
    /// generation `row.generation - 1`, in one transaction. Returns `false`,
    /// writing nothing, if that generation already exists or the older one
    /// is already chained: another node rotated first.
    pub async fn rotate(&self, row: at_rest_key::Model, chain: Vec<u8>) -> Result<bool, DbErr> {
        let older = row.generation - 1;
        let _w = self.writer().await;
        let tx = self.db.begin().await?;
        let inserted = at_rest_key::Entity::insert(at_rest_key::ActiveModel {
            generation: Set(row.generation),
            ark_id: Set(row.ark_id),
            w_label: Set(row.w_label),
            sealed: Set(row.sealed),
            chain: Set(row.chain),
            created_at: Set(row.created_at),
        })
        .on_conflict(
            OnConflict::column(at_rest_key::Column::Generation)
                .do_nothing()
                .to_owned(),
        )
        .exec(&tx)
        .await;
        match inserted {
            Ok(_) => {}
            Err(DbErr::RecordNotInserted) => return Ok(false),
            Err(e) => return Err(e),
        }
        let chained = at_rest_key::Entity::update_many()
            .col_expr(at_rest_key::Column::Chain, chain.into())
            .filter(at_rest_key::Column::Generation.eq(older))
            .filter(at_rest_key::Column::Chain.is_null())
            .exec(&tx)
            .await?;
        if chained.rows_affected != 1 {
            return Ok(false);
        }
        tx.commit().await?;
        Ok(true)
    }

    /// Replace a generation's chain. Only for repairing a chain that is
    /// missing or doesn't open, with the newer ARK in hand.
    pub async fn set_chain(&self, generation: i32, chain: Vec<u8>) -> Result<(), DbErr> {
        let _w = self.writer().await;
        at_rest_key::Entity::update_many()
            .col_expr(at_rest_key::Column::Chain, chain.into())
            .filter(at_rest_key::Column::Generation.eq(generation))
            .exec(&self.db)
            .await
            .map(|_| ())
    }

    /// Drop a generation's chain: the newest generation has no successor,
    /// so a chain there is stale (a restored or garbage row).
    pub async fn clear_chain(&self, generation: i32) -> Result<(), DbErr> {
        let _w = self.writer().await;
        at_rest_key::Entity::update_many()
            .col_expr(
                at_rest_key::Column::Chain,
                sea_orm::sea_query::Expr::value(Option::<Vec<u8>>::None),
            )
            .filter(at_rest_key::Column::Generation.eq(generation))
            .exec(&self.db)
            .await
            .map(|_| ())
    }

    /// Any escrow row at all (sealed material that must block provisioning).
    pub async fn has_escrow_rows(&self) -> Result<bool, DbErr> {
        Ok(at_rest_escrow::Entity::find().count(&self.db).await? > 0)
    }

    pub async fn has_space_keys(&self) -> Result<bool, DbErr> {
        Ok(space_data_key::Entity::find().count(&self.db).await? > 0)
    }

    /// The generation's active bundle. The partial unique index and
    /// `activate_escrow`'s lock keep it unique; the order makes the choice
    /// deterministic even if a database lacks the index.
    pub async fn active_escrow(
        &self,
        generation: i32,
    ) -> Result<Option<at_rest_escrow::Model>, DbErr> {
        at_rest_escrow::Entity::find()
            .filter(at_rest_escrow::Column::Generation.eq(generation))
            .filter(at_rest_escrow::Column::Active.eq(true))
            .order_by_desc(at_rest_escrow::Column::CreatedAt)
            .order_by_asc(at_rest_escrow::Column::Efp)
            .one(&self.db)
            .await
    }

    pub async fn escrow(&self, efp: &str) -> Result<Option<at_rest_escrow::Model>, DbErr> {
        at_rest_escrow::Entity::find_by_id(efp.to_owned())
            .one(&self.db)
            .await
    }

    /// Make `row` the generation's only active bundle. Older bundles stay.
    ///
    /// Concurrent activations serialize on the generation's `at_rest_key`
    /// row (`FOR UPDATE` on PG/MySQL; SQLite transactions are serializable
    /// and in-process writers share the writer lock), so the deactivate
    /// step always sees the other's committed bundle.
    pub async fn activate_escrow(&self, row: at_rest_escrow::Model) -> Result<(), DbErr> {
        let _w = self.writer().await;
        let tx = self.db.begin().await?;
        at_rest_key::Entity::find_by_id(row.generation)
            .lock_exclusive()
            .one(&tx)
            .await?
            .ok_or_else(|| DbErr::RecordNotFound("escrowed ARK generation".into()))?;
        at_rest_escrow::Entity::update_many()
            .col_expr(at_rest_escrow::Column::Active, false.into())
            .filter(at_rest_escrow::Column::Generation.eq(row.generation))
            .exec(&tx)
            .await?;
        ignore_conflict(
            at_rest_escrow::Entity::insert(at_rest_escrow::ActiveModel {
                efp: Set(row.efp.clone()),
                generation: Set(row.generation),
                bundle: Set(row.bundle),
                active: Set(true),
                record: Set(row.record),
                created_at: Set(row.created_at),
            })
            .on_conflict(
                OnConflict::column(at_rest_escrow::Column::Efp)
                    .do_nothing()
                    .to_owned(),
            )
            .exec(&tx)
            .await,
        )?;
        at_rest_escrow::Entity::update_many()
            .col_expr(at_rest_escrow::Column::Active, true.into())
            .filter(at_rest_escrow::Column::Efp.eq(row.efp))
            .exec(&tx)
            .await?;
        tx.commit().await
    }

    pub async fn save_record(&self, efp: &str, record_json: String) -> Result<(), DbErr> {
        let _w = self.writer().await;
        at_rest_escrow::Entity::update_many()
            .col_expr(at_rest_escrow::Column::Record, record_json.into())
            .filter(at_rest_escrow::Column::Efp.eq(efp))
            .exec(&self.db)
            .await
            .map(|_| ())
    }

    pub async fn newest_dek(&self, space: &str) -> Result<Option<space_data_key::Model>, DbErr> {
        space_data_key::Entity::find()
            .filter(space_data_key::Column::Space.eq(space))
            .order_by_desc(space_data_key::Column::DekId)
            .one(&self.db)
            .await
    }

    pub async fn dek(
        &self,
        space: &str,
        dek_id: i32,
    ) -> Result<Option<space_data_key::Model>, DbErr> {
        space_data_key::Entity::find_by_id((space.to_owned(), dek_id))
            .one(&self.db)
            .await
    }

    /// Insert unless `(space, dek_id)` exists. The caller re-reads, so
    /// concurrent creators converge on the first row written.
    pub async fn insert_dek(&self, row: space_data_key::Model) -> Result<(), DbErr> {
        let _w = self.writer().await;
        ignore_conflict(
            space_data_key::Entity::insert(space_data_key::ActiveModel {
                space: Set(row.space),
                dek_id: Set(row.dek_id),
                generation: Set(row.generation),
                wrapped: Set(row.wrapped),
                created_at: Set(row.created_at),
            })
            .on_conflict(
                OnConflict::columns([space_data_key::Column::Space, space_data_key::Column::DekId])
                    .do_nothing()
                    .to_owned(),
            )
            .exec(&self.db)
            .await,
        )
    }
}

/// In-memory mirror for tests.
#[cfg(any(test, feature = "test-util"))]
#[derive(Default)]
pub struct MemoryMirror {
    objects: parking_lot::Mutex<std::collections::BTreeMap<String, Vec<u8>>>,
    fail: std::sync::atomic::AtomicBool,
}

#[cfg(any(test, feature = "test-util"))]
impl MemoryMirror {
    /// Make every call fail, like an unreachable bucket.
    pub fn set_failing(&self, fail: bool) {
        self.fail.store(fail, std::sync::atomic::Ordering::SeqCst);
    }

    pub fn names(&self) -> Vec<String> {
        self.objects.lock().keys().cloned().collect()
    }

    pub fn clear(&self) {
        self.objects.lock().clear();
    }

    /// Drop every object under `prefix`, like a lost or rolled-back bucket.
    pub fn remove_prefix(&self, prefix: &str) {
        self.objects.lock().retain(|k, _| !k.starts_with(prefix));
    }

    fn check(&self) -> Result<(), MirrorError> {
        if self.fail.load(std::sync::atomic::Ordering::SeqCst) {
            Err("mirror unavailable".into())
        } else {
            Ok(())
        }
    }
}

#[cfg(any(test, feature = "test-util"))]
#[async_trait::async_trait]
impl KeyMirror for MemoryMirror {
    async fn put(&self, name: &str, bytes: Vec<u8>) -> Result<(), MirrorError> {
        self.check()?;
        self.objects.lock().insert(name.to_owned(), bytes);
        Ok(())
    }

    async fn get(&self, name: &str) -> Result<Option<Vec<u8>>, MirrorError> {
        self.check()?;
        match self.objects.lock().get(name) {
            Some(bytes) if bytes.len() > MAX_MIRROR_OBJECT => Err(Box::new(MirrorObjectTooLarge)),
            other => Ok(other.cloned()),
        }
    }

    async fn list(&self, prefix: &str) -> Result<Vec<String>, MirrorError> {
        self.check()?;
        Ok(self
            .objects
            .lock()
            .keys()
            .filter(|k| k.starts_with(prefix))
            .cloned()
            .collect())
    }
}
