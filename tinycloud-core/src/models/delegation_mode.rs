//! Side-table index of delegation mode (`attenuable`, `terminal`, `invalid`)
//! without rewriting historical `delegation` rows (TC-3810).

use std::collections::HashMap;

use sea_orm::{
    entity::prelude::*,
    sea_query::{OnConflict, Query},
    ActiveValue::Set,
    ConnectionTrait, DbBackend, QueryOrder, QuerySelect,
};
use tinycloud_auth::{
    authorization::TinyCloudDelegation,
    cacaos::siwe::Message,
    siwe_recap::{Capability as SiweCap, DelegationModeFact},
};

use crate::encryption::ColumnEncryption;
use crate::hash::Hash;
use crate::models::{delegation, delegation_cid_alias};
use crate::util::{self, DelegationMode};

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "delegation_mode")]
pub struct Model {
    /// Hash of the exact plaintext serialization persisted in `delegation`.
    #[sea_orm(primary_key, auto_increment = false)]
    pub delegation_id: Hash,
    /// Persisted mode marker: `"attenuable"`, `"terminal"`, or `"invalid"`.
    pub mode: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "delegation::Entity",
        from = "Column::DelegationId",
        to = "delegation::Column::Id"
    )]
    Delegation,
}

impl Related<delegation::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Delegation.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}

/// Normalized mode persisted in `delegation_mode` or derived on read from
/// stored signed bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoredDelegationMode {
    Attenuable,
    Terminal,
    Invalid,
}

impl StoredDelegationMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Attenuable => "attenuable",
            Self::Terminal => "terminal",
            Self::Invalid => "invalid",
        }
    }

    /// Parse a value read from `delegation_mode.mode`. Any unexpected value
    /// fails closed as [`Self::Invalid`].
    pub fn from_db_str(value: &str) -> Self {
        match value {
            "attenuable" => Self::Attenuable,
            "terminal" => Self::Terminal,
            _ => Self::Invalid,
        }
    }

    pub const fn from_live(mode: DelegationMode) -> Self {
        match mode {
            DelegationMode::Attenuable => Self::Attenuable,
            DelegationMode::Terminal => Self::Terminal,
            DelegationMode::Invalid => Self::Invalid,
        }
    }

    /// True if this delegation cannot parent children (both `terminal` and
    /// `invalid` refuse redelegation).
    pub const fn is_terminal_or_invalid(self) -> bool {
        matches!(self, Self::Terminal | Self::Invalid)
    }

    /// True if this delegation is quarantined (`invalid`) and cannot authorize
    /// direct invocation or status proof use either.
    pub const fn is_invalid(self) -> bool {
        matches!(self, Self::Invalid)
    }
}

/// Classify a decoded wallet-signed CACAO's `xyz.tinycloud.policy/delegationMode`.
/// Any decode/verification failure fails closed to [`StoredDelegationMode::Invalid`].
fn classify_cacao(cacao: &tinycloud_auth::cacaos::siwe_cacao::SiweCacao) -> StoredDelegationMode {
    let Ok(message) = TryInto::<Message>::try_into(cacao.payload().clone()) else {
        return StoredDelegationMode::Invalid;
    };
    match SiweCap::<serde_json::Value>::extract_and_verify(&message) {
        Ok(Some(cap)) => match cap.delegation_mode() {
            Some(DelegationModeFact::Terminal) => StoredDelegationMode::Terminal,
            Some(DelegationModeFact::Attenuable) | None => StoredDelegationMode::Attenuable,
        },
        Ok(None) => StoredDelegationMode::Attenuable,
        Err(_) => StoredDelegationMode::Invalid,
    }
}

/// Derive a stored delegation's mode directly from its persisted signed bytes
/// when its `delegation_mode` side-table row is absent (fail-closed default).
///
/// - Encrypted rows that fail decryption fail closed as [`StoredDelegationMode::Invalid`].
/// - Real CACAOs are parsed strictly; malformed, null, unknown, or duplicate
///   `xyz.tinycloud.policy/delegationMode` values (or invalid statements) fail
///   closed as [`StoredDelegationMode::Invalid`].
/// - Real UCANs read their signed `facts` array.
/// - Unparseable plaintext bytes fail closed as non-attenuable
///   ([`StoredDelegationMode::Terminal`]): they can never be used as a parent
///   for redelegation (including CACAO decrypt redelegation).
pub(crate) fn derive_when_unmarked(
    id: Hash,
    stored: &[u8],
    format: i16,
    encryption: Option<&ColumnEncryption>,
) -> StoredDelegationMode {
    let Ok(plaintext) = delegation_cid_alias::stored_plaintext(encryption, id, stored, format)
    else {
        return StoredDelegationMode::Invalid;
    };
    match TinyCloudDelegation::from_bytes(plaintext.as_ref()) {
        Ok(TinyCloudDelegation::Cacao(cacao)) => classify_cacao(&cacao),
        Ok(TinyCloudDelegation::Ucan(ucan)) => StoredDelegationMode::from_live(
            util::read_delegation_mode_from_ucan_facts(ucan.payload().facts.as_ref()),
        ),
        Err(_) => StoredDelegationMode::Terminal,
    }
}

/// Fail-closed fallback lookup for delegation IDs that had no row in
/// `delegation_mode`: reads their signed `serialization` and derives the mode
/// via [`derive_when_unmarked`]. Missing `delegation` rows are omitted from the
/// returned map so callers preserve `MissingParents`.
pub(crate) async fn resolve_unmarked_modes<C: ConnectionTrait>(
    db: &C,
    ids: &[Hash],
    encryption: Option<&ColumnEncryption>,
) -> Result<HashMap<Hash, StoredDelegationMode>, DbErr> {
    if ids.is_empty() {
        return Ok(HashMap::new());
    }
    let rows: Vec<(Hash, Vec<u8>, i16)> = delegation::Entity::find()
        .select_only()
        .column(delegation::Column::Id)
        .column(delegation::Column::Serialization)
        .column(delegation::Column::SerializationFormat)
        .filter(delegation::Column::Id.is_in(ids.iter().copied()))
        .into_tuple::<(Hash, Vec<u8>, i16)>()
        .all(db)
        .await?;
    let mut resolved = HashMap::with_capacity(rows.len());
    for (id, stored, format) in rows {
        resolved.insert(id, derive_when_unmarked(id, &stored, format, encryption));
    }
    Ok(resolved)
}

/// Outcome of boot-time delegation-mode side-table backfill (TC-3810).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BackfillStats {
    pub scanned: usize,
    pub reindexed_terminal: usize,
    pub marked_attenuable: usize,
    pub marked_invalid: usize,
    pub elapsed_ms: u64,
    pub completed: bool,
}

/// Populate `delegation_mode` for every stored delegation lacking a mode row
/// before serving traffic (TC-3810). Never updates or rewrites any column on
/// `delegation`.
pub(crate) async fn backfill<C>(
    pool: &C,
    encryption: Option<&ColumnEncryption>,
) -> Result<BackfillStats, DbErr>
where
    C: ConnectionTrait + sea_orm::TransactionTrait,
{
    backfill_bounded(pool, encryption, None).await
}

/// Bounded-page variant of [`backfill`] (used by interrupted-restart tests).
/// Runs each page's `SELECT` and `INSERT ... ON CONFLICT DO NOTHING` inside one
/// transaction with `EXEMPT_STATEMENT_TIMEOUT` on PostgreSQL.
pub(crate) async fn backfill_bounded<C>(
    pool: &C,
    encryption: Option<&ColumnEncryption>,
    max_pages: Option<usize>,
) -> Result<BackfillStats, DbErr>
where
    C: ConnectionTrait + sea_orm::TransactionTrait,
{
    const PAGE_SIZE: u64 = 128;
    let started = std::time::Instant::now();
    let backend = pool.get_database_backend();
    let mut after: Option<Hash> = None;
    let mut pages = 0usize;
    let mut stats = BackfillStats::default();

    loop {
        if max_pages.is_some_and(|limit| pages >= limit) {
            stats.elapsed_ms = started.elapsed().as_millis() as u64;
            return Ok(stats);
        }
        let tx = crate::db::begin_write_transaction(pool, None).await?;
        if backend == DbBackend::Postgres {
            tx.execute_unprepared(crate::db_pool::EXEMPT_STATEMENT_TIMEOUT)
                .await?;
        }
        let mut query = delegation::Entity::find()
            .select_only()
            .column(delegation::Column::Id)
            .column(delegation::Column::Serialization)
            .column(delegation::Column::SerializationFormat)
            .filter(
                Expr::exists(
                    Query::select()
                        .expr(Expr::value(1))
                        .from(Entity)
                        .and_where(
                            Expr::col((Entity, Column::DelegationId))
                                .equals((delegation::Entity, delegation::Column::Id)),
                        )
                        .to_owned(),
                )
                .not(),
            )
            .order_by_asc(delegation::Column::Id)
            .limit(PAGE_SIZE);
        if let Some(id) = after {
            query = query.filter(delegation::Column::Id.gt(id));
        }
        let rows = query.into_tuple::<(Hash, Vec<u8>, i16)>().all(&tx).await?;
        if rows.is_empty() {
            tx.commit().await?;
            stats.completed = true;
            stats.elapsed_ms = started.elapsed().as_millis() as u64;
            tracing::info!(
                scanned = stats.scanned,
                reindexed_terminal = stats.reindexed_terminal,
                marked_attenuable = stats.marked_attenuable,
                marked_invalid = stats.marked_invalid,
                elapsed_ms = stats.elapsed_ms,
                "delegation mode boot reindex complete"
            );
            return Ok(stats);
        }

        let mut inserts = Vec::with_capacity(rows.len());
        for (id, stored, format) in rows {
            after = Some(id);
            stats.scanned += 1;
            // Missing or wrong encryption key fails boot (same contract as
            // `delegation_cid_alias::backfill`); malformed/duplicate CACAO
            // delegation modes are marked `"invalid"` without failing boot.
            let plaintext =
                delegation_cid_alias::stored_plaintext(encryption, id, &stored, format)?;
            let mode = match TinyCloudDelegation::from_bytes(plaintext.as_ref()) {
                Ok(TinyCloudDelegation::Cacao(cacao)) => classify_cacao(&cacao),
                Ok(TinyCloudDelegation::Ucan(ucan)) => StoredDelegationMode::from_live(
                    util::read_delegation_mode_from_ucan_facts(ucan.payload().facts.as_ref()),
                ),
                Err(_) => StoredDelegationMode::Terminal,
            };
            match mode {
                StoredDelegationMode::Terminal => stats.reindexed_terminal += 1,
                StoredDelegationMode::Attenuable => stats.marked_attenuable += 1,
                StoredDelegationMode::Invalid => stats.marked_invalid += 1,
            }
            inserts.push(ActiveModel {
                delegation_id: Set(id),
                mode: Set(mode.as_str().to_string()),
            });
        }

        if !inserts.is_empty() {
            match Entity::insert_many(inserts)
                .on_conflict(
                    OnConflict::column(Column::DelegationId)
                        .do_nothing()
                        .to_owned(),
                )
                .exec(&tx)
                .await
            {
                Ok(_) | Err(DbErr::RecordNotInserted) => {}
                Err(error) => return Err(error),
            }
        }
        tx.commit().await?;
        pages += 1;
    }
}
