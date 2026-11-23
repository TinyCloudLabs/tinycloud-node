//! The per-database mode record and its state machine (TC-1491 P4.1, design
//! section 4, contract 4.6).
//!
//! One `sql_store_mode` row per SQL database says where it is mastered. An
//! absent row means [`StoreMode::PgMaster`]. [`rule`] is the transition
//! table as a pure function; [`transition_row`] applies one transition as a
//! single conditional statement on the control database. Nothing outside
//! tests calls either yet: every database stays `pg_master` or `shadow`, and
//! no request path reads the row.
//!
//! | From | To | Epoch | `owner_node` |
//! |---|---|---|---|
//! | (no row) / pg_master | shadow | keep | keep |
//! | shadow | pg_master | keep | keep |
//! | shadow | cutting_over | keep | keep |
//! | cutting_over | store_master | +1 | set to the claimant |
//! | cutting_over | shadow | keep | keep |
//! | store_master | copying_back | keep | keep |
//! | copying_back | pg_master | keep | cleared |
//! | copying_back | store_master | keep | keep |
//! | store_master | owner_lost | +1 | keep |
//! | owner_lost | store_master | +1 | set to the claimant |
//!
//! Every other pair, a mode to itself included, is refused with
//! [`ModeError::Illegal`]. The guards in the design's table (preconditions,
//! restore checks, size guard, lease expiry) belong to the callers that
//! arrive with P4.2-P4.4; this module enforces the pairs, the epoch and the
//! compare-and-set.

use sea_orm::{
    sea_query::{Expr, OnConflict},
    ActiveValue::Set,
    ColumnTrait, ConnectionTrait, DbBackend, EntityTrait, QueryFilter, SqlErr,
};

use super::key::DbRef;
use super::manifest::{check_db, now_timestamp};
use crate::models::sql_store_mode as row;

/// Longest `owner_node` the `varchar(255)` column holds.
const MAX_OWNER_CHARS: usize = 255;

/// Where one SQL database is mastered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StoreMode {
    /// Postgres is master; no store copy. Also what an absent row means.
    PgMaster,
    /// Postgres is master; the store holds an advisory copy.
    Shadow,
    /// A cutover is in flight; writes are fenced.
    CuttingOver,
    /// The store is the durable master; one node holds the working copy.
    StoreMaster,
    /// A copy back to Postgres is in flight.
    CopyingBack,
    /// The owner's lease expired; an operator has to decide who claims.
    OwnerLost,
}

impl StoreMode {
    pub const ALL: [Self; 6] = [
        Self::PgMaster,
        Self::Shadow,
        Self::CuttingOver,
        Self::StoreMaster,
        Self::CopyingBack,
        Self::OwnerLost,
    ];

    /// The value stored in `sql_store_mode.mode`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PgMaster => "pg_master",
            Self::Shadow => "shadow",
            Self::CuttingOver => "cutting_over",
            Self::StoreMaster => "store_master",
            Self::CopyingBack => "copying_back",
            Self::OwnerLost => "owner_lost",
        }
    }

    /// The mode a stored value names; `None` for anything else.
    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|mode| mode.as_str() == value)
    }
}

impl std::fmt::Display for StoreMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What a legal transition does to `owner_node`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerChange {
    Keep,
    /// Set to the claiming node, which the caller must name.
    Set,
    Clear,
}

/// What a legal transition does to the row besides changing its mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Effect {
    pub bumps_epoch: bool,
    pub owner: OwnerChange,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ModeError {
    /// The pair is not in the transition table.
    #[error("sql store mode transition {from} -> {to} is not allowed")]
    Illegal { from: StoreMode, to: StoreMode },
    /// The row is not in the expected mode and epoch (or, for a first
    /// transition, already exists). Nothing was changed.
    #[error("sql store mode row is not in the expected mode and epoch")]
    Stale,
    /// The stored mode is not one this binary knows. Refused, never guessed.
    #[error("sql store mode row holds an unknown mode")]
    Unknown,
    #[error("sql store mode request is invalid: {0}")]
    Invalid(&'static str),
    #[error("sql store mode database error: {0}")]
    Db(String),
}

impl From<sea_orm::DbErr> for ModeError {
    fn from(error: sea_orm::DbErr) -> Self {
        Self::Db(error.to_string())
    }
}

/// The transition table of design section 4.
pub fn rule(from: StoreMode, to: StoreMode) -> Result<Effect, ModeError> {
    use OwnerChange::{Clear, Keep, Set};
    use StoreMode::*;
    let (bumps_epoch, owner) = match (from, to) {
        (PgMaster, Shadow)
        | (Shadow, PgMaster)
        | (Shadow, CuttingOver)
        | (CuttingOver, Shadow)
        | (StoreMaster, CopyingBack)
        | (CopyingBack, StoreMaster) => (false, Keep),
        (CuttingOver, StoreMaster) | (OwnerLost, StoreMaster) => (true, Set),
        (StoreMaster, OwnerLost) => (true, Keep),
        (CopyingBack, PgMaster) => (false, Clear),
        _ => return Err(ModeError::Illegal { from, to }),
    };
    Ok(Effect { bumps_epoch, owner })
}

/// The row as the caller last read it: the compare half of the CAS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Expected {
    pub mode: StoreMode,
    pub epoch: i64,
}

/// One database's mode row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModeRow {
    pub mode: StoreMode,
    pub epoch: i64,
    pub owner_node: Option<String>,
    pub mode_changed_at: String,
}

impl ModeRow {
    pub fn expected(&self) -> Expected {
        Expected {
            mode: self.mode,
            epoch: self.epoch,
        }
    }
}

fn check(db: &DbRef<'_>) -> Result<(), ModeError> {
    check_db(db).map_err(|_| ModeError::Invalid("space or database id is invalid"))
}

/// The mode row of `db`; `None` means no row, which is `pg_master`. A row
/// whose mode this binary does not know is [`ModeError::Unknown`].
pub async fn read_mode<C: ConnectionTrait>(
    conn: &C,
    db: &DbRef<'_>,
) -> Result<Option<ModeRow>, ModeError> {
    check(db)?;
    let Some(model) = row::Entity::find_by_id((db.space.to_owned(), db.db_id.to_owned()))
        .one(conn)
        .await?
    else {
        return Ok(None);
    };
    Ok(Some(ModeRow {
        mode: StoreMode::parse(&model.mode).ok_or(ModeError::Unknown)?,
        epoch: model.epoch,
        owner_node: model.owner_node,
        mode_changed_at: model.mode_changed_at,
    }))
}

/// Moves `db` from `expected` to `to` and returns the row's new epoch.
///
/// `expected = None` means "no row": the only legal move is to `shadow`, an
/// insert at epoch 0 that changes nothing if any row exists
/// ([`insert_absent`]). Otherwise one `UPDATE … WHERE mode = :from AND
/// epoch = :e` that must change exactly one row. Either way a miss is
/// [`ModeError::Stale`] and nothing changed. `owner` names the claiming
/// node, required exactly when the transition sets `owner_node`.
pub async fn transition_row<C: ConnectionTrait>(
    conn: &C,
    db: &DbRef<'_>,
    expected: Option<Expected>,
    to: StoreMode,
    owner: Option<&str>,
) -> Result<i64, ModeError> {
    check(db)?;
    let from = expected.map_or(StoreMode::PgMaster, |e| e.mode);
    let effect = rule(from, to)?;
    match (effect.owner, owner) {
        (OwnerChange::Set, Some(node)) if !node.is_empty() => {
            if node.chars().count() > MAX_OWNER_CHARS {
                return Err(ModeError::Invalid("owner node id too long"));
            }
        }
        (OwnerChange::Set, _) => {
            return Err(ModeError::Invalid("entering store_master needs an owner"))
        }
        (_, Some(_)) => {
            return Err(ModeError::Invalid(
                "only entering store_master sets an owner",
            ))
        }
        (_, None) => {}
    }
    let now = now_timestamp();
    let Some(expected) = expected else {
        let first = row::ActiveModel {
            space: Set(db.space.to_owned()),
            db_id: Set(db.db_id.to_owned()),
            mode: Set(to.as_str().to_owned()),
            epoch: Set(0),
            owner_node: Set(None),
            lease_holder: Set(None),
            lease_expires_at: Set(None),
            mode_changed_at: Set(now),
            cutover_revision: Set(None),
        };
        let plain = conn.get_database_backend() == DbBackend::MySql;
        return if insert_absent(conn, first, plain).await? {
            Ok(0)
        } else {
            Err(ModeError::Stale)
        };
    };
    let epoch = if effect.bumps_epoch {
        expected
            .epoch
            .checked_add(1)
            .ok_or(ModeError::Invalid("epoch exhausted"))?
    } else {
        expected.epoch
    };
    use row::Column as C;
    let mut update = row::Entity::update_many()
        .col_expr(C::Mode, Expr::value(to.as_str()))
        .col_expr(C::Epoch, Expr::value(epoch))
        .col_expr(C::ModeChangedAt, Expr::value(now));
    update = match effect.owner {
        OwnerChange::Keep => update,
        OwnerChange::Set => update.col_expr(C::OwnerNode, Expr::value(owner.map(str::to_owned))),
        OwnerChange::Clear => update.col_expr(C::OwnerNode, Expr::value(Option::<String>::None)),
    };
    let changed = update
        .filter(C::Space.eq(db.space))
        .filter(C::DbId.eq(db.db_id))
        .filter(C::Mode.eq(from.as_str()))
        .filter(C::Epoch.eq(expected.epoch))
        .exec(conn)
        .await?
        .rows_affected;
    if changed == 1 {
        Ok(epoch)
    } else {
        Err(ModeError::Stale)
    }
}

/// Inserts `first` if the database has no row; `false` if one exists.
///
/// Postgres and SQLite: `INSERT … ON CONFLICT DO NOTHING`, decided by the row
/// count (a raw key violation would abort an enclosing Postgres
/// transaction). MySQL (`plain`): sea-query renders `DO NOTHING` as `ON
/// DUPLICATE KEY UPDATE`, and sqlx's `CLIENT_FOUND_ROWS` counts a duplicate
/// as one row, so the count cannot tell an insert from an existing row. There
/// a plain `INSERT` runs instead, and its key violation means the row exists
/// (as `database_artifacts` does for an absent artifact, TC-2214). A failed
/// statement does not abort a MySQL transaction.
async fn insert_absent<C: ConnectionTrait>(
    conn: &C,
    first: row::ActiveModel,
    plain: bool,
) -> Result<bool, ModeError> {
    let insert = row::Entity::insert(first);
    if plain {
        return match insert.exec_without_returning(conn).await {
            Ok(_) => Ok(true),
            Err(error) if matches!(error.sql_err(), Some(SqlErr::UniqueConstraintViolation(_))) => {
                Ok(false)
            }
            Err(error) => Err(error.into()),
        };
    }
    let inserted = insert
        .on_conflict(
            OnConflict::columns([row::Column::Space, row::Column::DbId])
                .do_nothing()
                .to_owned(),
        )
        .exec_without_returning(conn)
        .await?;
    Ok(inserted == 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migrations::Migrator;
    use proptest::prelude::*;
    use sea_orm::{ConnectOptions, Database, DatabaseConnection, DbBackend, Statement};
    use sea_orm_migration::MigratorTrait;
    use StoreMode::*;

    /// Design section 4's table, written out independently of [`rule`]:
    /// (from, to, epoch bumps, owner change).
    const SECTION_4: [(StoreMode, StoreMode, bool, OwnerChange); 10] = [
        (PgMaster, Shadow, false, OwnerChange::Keep),
        (Shadow, PgMaster, false, OwnerChange::Keep),
        (Shadow, CuttingOver, false, OwnerChange::Keep),
        (CuttingOver, StoreMaster, true, OwnerChange::Set),
        (CuttingOver, Shadow, false, OwnerChange::Keep),
        (StoreMaster, CopyingBack, false, OwnerChange::Keep),
        (CopyingBack, PgMaster, false, OwnerChange::Clear),
        (CopyingBack, StoreMaster, false, OwnerChange::Keep),
        (StoreMaster, OwnerLost, true, OwnerChange::Keep),
        (OwnerLost, StoreMaster, true, OwnerChange::Set),
    ];

    fn spec(from: StoreMode, to: StoreMode) -> Option<Effect> {
        SECTION_4
            .iter()
            .find(|(f, t, _, _)| (*f, *t) == (from, to))
            .map(|&(_, _, bumps_epoch, owner)| Effect { bumps_epoch, owner })
    }

    const DB: DbRef<'static> = DbRef {
        space: "tinycloud:pkh:eip155:1:0xabc:default",
        db_id: "main",
    };
    const NODE: &str = "node-a";

    async fn sqlite() -> DatabaseConnection {
        let mut options = ConnectOptions::new("sqlite::memory:".to_string());
        options.max_connections(1).sqlx_logging(false);
        let conn = Database::connect(options).await.unwrap();
        Migrator::up(&conn, None).await.unwrap();
        conn
    }

    fn owner_for(from: StoreMode, to: StoreMode) -> Option<&'static str> {
        matches!(spec(from, to), Some(e) if e.owner == OwnerChange::Set).then_some(NODE)
    }

    #[test]
    fn every_pair_matches_section_4() {
        let mut legal = 0;
        for from in StoreMode::ALL {
            for to in StoreMode::ALL {
                match spec(from, to) {
                    Some(effect) => {
                        legal += 1;
                        assert_eq!(rule(from, to), Ok(effect), "{from} -> {to}");
                    }
                    None => assert_eq!(
                        rule(from, to),
                        Err(ModeError::Illegal { from, to }),
                        "{from} -> {to}"
                    ),
                }
            }
        }
        assert_eq!(legal, SECTION_4.len());
    }

    #[test]
    fn stored_names_round_trip_and_fit_the_column() {
        for mode in StoreMode::ALL {
            assert_eq!(StoreMode::parse(mode.as_str()), Some(mode));
            assert!(mode.as_str().len() <= 16);
        }
        assert_eq!(StoreMode::parse("store-master"), None);
        assert_eq!(StoreMode::parse(""), None);
    }

    #[tokio::test]
    async fn absent_row_reads_as_none_and_only_shadow_creates_one() {
        let conn = sqlite().await;
        assert_eq!(read_mode(&conn, &DB).await, Ok(None));
        for to in [PgMaster, CuttingOver, StoreMaster, CopyingBack, OwnerLost] {
            assert_eq!(
                transition_row(&conn, &DB, None, to, owner_for(PgMaster, to)).await,
                Err(ModeError::Illegal { from: PgMaster, to })
            );
        }
        assert_eq!(read_mode(&conn, &DB).await, Ok(None));
        assert_eq!(transition_row(&conn, &DB, None, Shadow, None).await, Ok(0));
        // A second first transition (a concurrent allowlist) loses.
        assert_eq!(
            transition_row(&conn, &DB, None, Shadow, None).await,
            Err(ModeError::Stale)
        );
        let row = read_mode(&conn, &DB).await.unwrap().unwrap();
        assert_eq!((row.mode, row.epoch, row.owner_node), (Shadow, 0, None));
    }

    #[tokio::test]
    async fn owner_is_required_exactly_when_entering_store_master() {
        let conn = sqlite().await;
        let e = transition_row(&conn, &DB, None, Shadow, None)
            .await
            .unwrap();
        let shadow = Expected {
            mode: Shadow,
            epoch: e,
        };
        assert_eq!(
            transition_row(&conn, &DB, Some(shadow), CuttingOver, Some(NODE)).await,
            Err(ModeError::Invalid(
                "only entering store_master sets an owner"
            ))
        );
        let e = transition_row(&conn, &DB, Some(shadow), CuttingOver, None)
            .await
            .unwrap();
        let cutting = Expected {
            mode: CuttingOver,
            epoch: e,
        };
        for owner in [None, Some("")] {
            assert_eq!(
                transition_row(&conn, &DB, Some(cutting), StoreMaster, owner).await,
                Err(ModeError::Invalid("entering store_master needs an owner"))
            );
        }
        let long = "n".repeat(MAX_OWNER_CHARS + 1);
        assert_eq!(
            transition_row(&conn, &DB, Some(cutting), StoreMaster, Some(&long)).await,
            Err(ModeError::Invalid("owner node id too long"))
        );
        assert_eq!(
            read_mode(&conn, &DB).await.unwrap().unwrap().mode,
            CuttingOver
        );
    }

    #[tokio::test]
    async fn an_unknown_stored_mode_is_refused() {
        let conn = sqlite().await;
        transition_row(&conn, &DB, None, Shadow, None)
            .await
            .unwrap();
        conn.execute(Statement::from_string(
            DbBackend::Sqlite,
            "UPDATE sql_store_mode SET mode = 'evicted'".to_string(),
        ))
        .await
        .unwrap();
        assert_eq!(read_mode(&conn, &DB).await, Err(ModeError::Unknown));
    }

    /// Drives `DB` from no row to `store_master` at epoch 1.
    async fn to_store_master(conn: &DatabaseConnection) -> ModeRow {
        let e = transition_row(conn, &DB, None, Shadow, None).await.unwrap();
        let e = transition_row(
            conn,
            &DB,
            Some(Expected {
                mode: Shadow,
                epoch: e,
            }),
            CuttingOver,
            None,
        )
        .await
        .unwrap();
        let cutting = Expected {
            mode: CuttingOver,
            epoch: e,
        };
        transition_row(conn, &DB, Some(cutting), StoreMaster, Some(NODE))
            .await
            .unwrap();
        read_mode(conn, &DB).await.unwrap().unwrap()
    }

    fn first_row() -> row::ActiveModel {
        row::ActiveModel {
            space: Set(DB.space.to_owned()),
            db_id: Set(DB.db_id.to_owned()),
            mode: Set(Shadow.as_str().to_owned()),
            epoch: Set(0),
            owner_node: Set(None),
            lease_holder: Set(None),
            lease_expires_at: Set(None),
            mode_changed_at: Set(now_timestamp()),
            cutover_revision: Set(None),
        }
    }

    /// Both insert forms, the ON CONFLICT one and MySQL's plain one (run here
    /// on SQLite, whose key violation maps to the same `SqlErr`), insert into
    /// an empty table and report an existing `store_master` row as present
    /// without touching it. MySQL itself is not in this repo's test harness.
    #[tokio::test]
    async fn insert_absent_never_reports_an_existing_row_as_inserted() {
        for plain in [false, true] {
            let conn = sqlite().await;
            assert_eq!(insert_absent(&conn, first_row(), plain).await, Ok(true));
            conn.execute(Statement::from_string(
                DbBackend::Sqlite,
                "DELETE FROM sql_store_mode".to_string(),
            ))
            .await
            .unwrap();
            let before = to_store_master(&conn).await;
            assert_eq!(
                insert_absent(&conn, first_row(), plain).await,
                Ok(false),
                "plain={plain}"
            );
            assert_eq!(read_mode(&conn, &DB).await.unwrap(), Some(before));
        }
    }

    /// One attempted transition of the random walk.
    #[derive(Debug, Clone, Copy)]
    struct Attempt {
        to: StoreMode,
        /// Present a CAS token that does not match the row.
        stale: bool,
    }

    fn attempts() -> impl Strategy<Value = Vec<Attempt>> {
        prop::collection::vec(
            (
                prop::sample::select(StoreMode::ALL.to_vec()),
                prop::bool::weighted(0.2),
            )
                .prop_map(|(to, stale)| Attempt { to, stale }),
            1..40,
        )
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        /// A random walk of attempted transitions against SQLite matches
        /// the section 4 model: a legal pair with the current token applies
        /// with the table's epoch and owner effect, an illegal pair is
        /// `Illegal`, a stale token is refused, and a refusal never changes
        /// the row.
        #[test]
        fn random_walk_matches_the_section_4_model(walk in attempts()) {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async {
                let conn = sqlite().await;
                let mut model: Option<ModeRow> = None;
                for Attempt { to, stale } in walk {
                    let from = model.as_ref().map_or(PgMaster, |r| r.mode);
                    let expected = match (&model, stale) {
                        (Some(row), false) => Some(row.expected()),
                        (Some(row), true) => Some(Expected { mode: row.mode, epoch: row.epoch + 1 }),
                        (None, false) => None,
                        // Claims a pg_master row that does not exist.
                        (None, true) => Some(Expected { mode: PgMaster, epoch: 0 }),
                    };
                    let result =
                        transition_row(&conn, &DB, expected, to, owner_for(from, to)).await;
                    match spec(from, to) {
                        None => prop_assert_eq!(result, Err(ModeError::Illegal { from, to })),
                        Some(_) if stale => prop_assert_eq!(result, Err(ModeError::Stale)),
                        Some(effect) => {
                            let before = model.as_ref().map_or(0, |r| r.epoch);
                            let epoch = before + i64::from(effect.bumps_epoch);
                            prop_assert_eq!(result, Ok(epoch));
                            let owner_node = match effect.owner {
                                OwnerChange::Keep => model.as_ref().and_then(|r| r.owner_node.clone()),
                                OwnerChange::Set => Some(NODE.to_owned()),
                                OwnerChange::Clear => None,
                            };
                            model = Some(ModeRow {
                                mode: to,
                                epoch,
                                owner_node,
                                mode_changed_at: String::new(),
                            });
                        }
                    }
                    let stored = read_mode(&conn, &DB).await.unwrap();
                    prop_assert_eq!(
                        stored.map(|r| (r.mode, r.epoch, r.owner_node)),
                        model.as_ref().map(|r| (r.mode, r.epoch, r.owner_node.clone()))
                    );
                }
                Ok(())
            })?;
        }
    }
}
