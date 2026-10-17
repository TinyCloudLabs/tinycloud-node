//! TC-1274: per-space head epochs without scanning history.
//!
//! A new epoch's parents are all of its space's current heads: the epochs
//! with no child in `epoch_order`. Finding them with the `epoch` /
//! `epoch_order` anti-join costs O(history) on every write. `epoch_head`
//! caches them instead, and `transact` rewrites a space's rows, under the
//! space's sequence lock, to the one epoch it just appended.
//!
//! The cache is trusted only when it is provably current. Every epoch is
//! appended under the space's sequence lock with
//! `seq = MAX(event_order.seq) + 1` (TC-732), so it outranks every existing
//! epoch, including those appended by releases that never write
//! `epoch_head`. Rows written under the lock are exact at that moment, and
//! the newest epoch is always a head (its child would have a larger `seq`).
//! So the rows are still exact if and only if their largest `seq` is the
//! space's largest. Otherwise the space falls back to the anti-join once and
//! the caller rewrites its rows. Correctness never depends on a backfill
//! having run, or on every writer maintaining the table.
//!
//! Heads are returned in `id` (byte) order. The anti-join had no order, and
//! the parent order only feeds the hash of a new merge epoch; nothing
//! re-derives an epoch hash from its parents.

use std::collections::HashMap;

use sea_orm::{
    sea_query::Expr, ColumnTrait, ConnectionTrait, DbErr, EntityTrait, QueryFilter, QueryOrder,
    QuerySelect,
};

use crate::hash::Hash;
use crate::models::{epoch, epoch_head};
use crate::relationships::{epoch_order, event_order};
use crate::types::SpaceIdWrap;

/// The next `seq` of `space`: one past its largest `event_order.seq`, or
/// `None` for a space with no events yet. `transact` computes the same value.
async fn next_seq<C: ConnectionTrait>(db: &C, space: &SpaceIdWrap) -> Result<Option<i64>, DbErr> {
    let max = event_order::Entity::find()
        .filter(event_order::Column::Space.eq(space.clone()))
        .select_only()
        .column_as(event_order::Column::Seq.max(), "max_seq")
        .into_tuple::<Option<i64>>()
        .one(db)
        .await?
        .flatten();
    max.map(|seq| {
        seq.checked_add(1)
            .ok_or_else(|| DbErr::Custom(format!("event_order seq overflow in space {}", space.0)))
    })
    .transpose()
}

/// Whether cached heads with these seqs are exact for a space whose next seq
/// is `next` (see the module docs).
fn is_current(cached: &[(Hash, i64)], next: Option<i64>) -> bool {
    match (cached.iter().map(|(_, seq)| *seq).max(), next) {
        (None, None) => true,
        (Some(newest), Some(next)) => newest.checked_add(1) == Some(next),
        _ => false,
    }
}

/// The heads of `spaces` from history: the anti-join `transact` used to run
/// on every write. O(history); with `idx_epoch_order_space_parent_child` it
/// is two index-only range scans per space.
async fn heads_from_history<C: ConnectionTrait>(
    db: &C,
    spaces: &[SpaceIdWrap],
) -> Result<Vec<(SpaceIdWrap, Hash, i64)>, DbErr> {
    epoch::Entity::find()
        .select_only()
        .left_join(epoch_order::Entity)
        .filter(epoch::Column::Space.is_in(spaces.iter().cloned()))
        .filter(epoch_order::Column::Child.is_null())
        .column(epoch::Column::Space)
        .column(epoch::Column::Id)
        .column(epoch::Column::Seq)
        .order_by_asc(epoch::Column::Space)
        .order_by_asc(epoch::Column::Id)
        .into_tuple::<(SpaceIdWrap, Hash, i64)>()
        .all(db)
        .await
}

async fn cached_heads<C: ConnectionTrait>(
    db: &C,
    spaces: &[SpaceIdWrap],
) -> Result<HashMap<SpaceIdWrap, Vec<(Hash, i64)>>, DbErr> {
    let mut cached: HashMap<SpaceIdWrap, Vec<(Hash, i64)>> = HashMap::new();
    for row in epoch_head::Entity::find()
        .filter(epoch_head::Column::Space.is_in(spaces.iter().cloned()))
        .order_by_asc(epoch_head::Column::Space)
        .order_by_asc(epoch_head::Column::Id)
        .all(db)
        .await?
    {
        cached.entry(row.space).or_default().push((row.id, row.seq));
    }
    Ok(cached)
}

/// The heads `transact` builds on, read under the sequence locks of `spaces`.
pub(crate) struct Heads {
    /// The current heads of each space, in `id` order; a space without
    /// epochs is absent.
    pub(crate) parents: HashMap<SpaceIdWrap, Vec<Hash>>,
    /// How many cache rows each space has now (absent: none).
    cached_rows: HashMap<SpaceIdWrap, usize>,
}

/// The current heads of each of `spaces`. `next_seqs` holds each space's next
/// seq as `transact` computed it (absent for a space with no events). The
/// caller holds the sequence lock of every space and, after appending one
/// epoch per space, records them with [`advance`].
pub(crate) async fn current<C: ConnectionTrait>(
    db: &C,
    spaces: &[SpaceIdWrap],
    next_seqs: &HashMap<SpaceIdWrap, i64>,
) -> Result<Heads, DbErr> {
    let mut cached = cached_heads(db, spaces).await?;
    let mut parents = HashMap::new();
    let mut cached_rows = HashMap::new();
    let mut stale = Vec::new();
    for space in spaces {
        let rows = cached.remove(space).unwrap_or_default();
        if !rows.is_empty() {
            cached_rows.insert(space.clone(), rows.len());
        }
        if is_current(&rows, next_seqs.get(space).copied()) {
            if !rows.is_empty() {
                parents.insert(space.clone(), rows.into_iter().map(|(id, _)| id).collect());
            }
        } else {
            stale.push(space.clone());
        }
    }
    if !stale.is_empty() {
        for (space, id, _) in heads_from_history(db, &stale).await? {
            parents.entry(space).or_insert_with(Vec::new).push(id);
        }
    }
    Ok(Heads {
        parents,
        cached_rows,
    })
}

/// Record each `(space, id, seq)` as its space's only head: the epoch just
/// appended, whose parents were all of the space's heads. One statement per
/// space in the usual case of one cached row.
pub(crate) async fn advance<C: ConnectionTrait>(
    db: &C,
    heads: &Heads,
    appended: Vec<(SpaceIdWrap, Hash, i64)>,
) -> Result<(), DbErr> {
    for (space, id, seq) in appended {
        match heads.cached_rows.get(&space).copied().unwrap_or(0) {
            0 => insert(db, [(space, id, seq)]).await?,
            1 => {
                epoch_head::Entity::update_many()
                    .col_expr(epoch_head::Column::Id, Expr::value(id))
                    .col_expr(epoch_head::Column::Seq, Expr::value(seq))
                    .filter(epoch_head::Column::Space.eq(space))
                    .exec(db)
                    .await?;
            }
            _ => replace(db, std::slice::from_ref(&space), [(space.clone(), id, seq)]).await?,
        }
    }
    Ok(())
}

async fn insert<C: ConnectionTrait>(
    db: &C,
    heads: impl IntoIterator<Item = (SpaceIdWrap, Hash, i64)>,
) -> Result<(), DbErr> {
    let rows = heads
        .into_iter()
        .map(|(space, id, seq)| epoch_head::ActiveModel {
            space: sea_orm::Set(space),
            id: sea_orm::Set(id),
            seq: sea_orm::Set(seq),
        })
        .collect::<Vec<_>>();
    if !rows.is_empty() {
        epoch_head::Entity::insert_many(rows).exec(db).await?;
    }
    Ok(())
}

/// Make `heads` (`(space, id, seq)`) the only cached heads of `spaces`.
async fn replace<C: ConnectionTrait>(
    db: &C,
    spaces: &[SpaceIdWrap],
    heads: impl IntoIterator<Item = (SpaceIdWrap, Hash, i64)>,
) -> Result<(), DbErr> {
    epoch_head::Entity::delete_many()
        .filter(epoch_head::Column::Space.is_in(spaces.iter().cloned()))
        .exec(db)
        .await?;
    insert(db, heads).await
}

/// Backfill one space: if its cached heads are not provably current, rewrite
/// them from history. Returns whether it rewrote them. The caller holds the
/// space's sequence lock.
pub(crate) async fn repair<C: ConnectionTrait>(db: &C, space: &SpaceIdWrap) -> Result<bool, DbErr> {
    let spaces = std::slice::from_ref(space);
    let next = next_seq(db, space).await?;
    let cached = cached_heads(db, spaces)
        .await?
        .remove(space)
        .unwrap_or_default();
    if is_current(&cached, next) {
        return Ok(false);
    }
    let heads = heads_from_history(db, spaces).await?;
    replace(db, spaces, heads).await?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::migrate;
    use crate::hash::hash;
    use crate::keys::StaticSecret;
    use crate::kv_sync::tests::{host, run, sqlite_db, Op, Owner, TestDb};
    use crate::migrations::Migrator;
    use crate::models::space;
    use crate::storage::memory::MemoryStore;
    use crate::test_support::PostgresTestSchema;
    use crate::SpaceDatabase;
    use sea_orm::{DatabaseConnection, TransactionTrait};
    use sea_orm_migration::MigratorTrait;
    use tinycloud_auth::resource::SpaceId;

    async fn postgres_db(fixture: &PostgresTestSchema) -> TestDb {
        SpaceDatabase::new(
            fixture.connect(15).await,
            MemoryStore::default(),
            StaticSecret::new([0u8; 32].to_vec()).unwrap(),
        )
        .await
        .unwrap()
    }

    fn wrap(space: &SpaceId) -> SpaceIdWrap {
        SpaceIdWrap(space.clone())
    }

    /// The cached heads of `space`, in id order.
    async fn cached(db: &DatabaseConnection, space: &SpaceId) -> Vec<Hash> {
        cached_heads(db, &[wrap(space)])
            .await
            .unwrap()
            .remove(&wrap(space))
            .unwrap_or_default()
            .into_iter()
            .map(|(id, _)| id)
            .collect()
    }

    /// The true heads of `space`, from history, in id order.
    async fn truth(db: &DatabaseConnection, space: &SpaceId) -> Vec<Hash> {
        heads_from_history(db, &[wrap(space)])
            .await
            .unwrap()
            .into_iter()
            .map(|(_, id, _)| id)
            .collect()
    }

    /// The epoch with the largest seq in `space`.
    async fn newest(db: &DatabaseConnection, space: &SpaceId) -> epoch::Model {
        epoch::Entity::find()
            .filter(epoch::Column::Space.eq(wrap(space)))
            .order_by_desc(epoch::Column::Seq)
            .one(db)
            .await
            .unwrap()
            .unwrap()
    }

    /// The parents recorded for `child`, in id order.
    async fn parents_of(db: &DatabaseConnection, space: &SpaceId, child: Hash) -> Vec<Hash> {
        let mut parents: Vec<Hash> = epoch_order::Entity::find()
            .filter(epoch_order::Column::Space.eq(wrap(space)))
            .filter(epoch_order::Column::Child.eq(child))
            .all(db)
            .await
            .unwrap()
            .into_iter()
            .map(|edge| edge.parent)
            .collect();
        parents.sort();
        parents
    }

    /// Append an epoch the way a release without `epoch_head` (v1.20.x)
    /// does: `epoch`, `epoch_order` and `event_order` rows only.
    async fn old_writer_append(
        db: &DatabaseConnection,
        space: &SpaceId,
        parents: &[Hash],
        seq: i64,
        tag: &str,
    ) -> Hash {
        let id = hash(format!("tc1274-old-writer-epoch-{tag}").as_bytes());
        epoch::Entity::insert(epoch::ActiveModel {
            seq: sea_orm::Set(seq),
            id: sea_orm::Set(id),
            space: sea_orm::Set(wrap(space)),
        })
        .exec(db)
        .await
        .unwrap();
        for parent in parents {
            epoch_order::Entity::insert(epoch_order::ActiveModel {
                parent: sea_orm::Set(*parent),
                child: sea_orm::Set(id),
                space: sea_orm::Set(wrap(space)),
            })
            .exec(db)
            .await
            .unwrap();
        }
        event_order::Entity::insert(event_order::ActiveModel {
            seq: sea_orm::Set(seq),
            epoch: sea_orm::Set(id),
            epoch_seq: sea_orm::Set(0),
            event: sea_orm::Set(hash(format!("tc1274-old-writer-event-{tag}").as_bytes())),
            space: sea_orm::Set(wrap(space)),
        })
        .exec(db)
        .await
        .unwrap();
        id
    }

    /// After every write the cache holds exactly the epoch just appended,
    /// which is also the only head in history, and that epoch's parent is the
    /// previous head.
    async fn heads_follow_every_write(db: &TestDb) {
        let conn = db.connection();
        let owner = Owner::generate();
        host(db, &owner).await;
        let mut previous = Vec::new();
        for (round, key) in ["a", "b", "a", "c"].into_iter().enumerate() {
            run(db, &owner, &[Op::Put(key, b"value")]).await;
            let head = newest(conn, &owner.space).await;
            assert_eq!(head.seq, round as i64);
            assert_eq!(
                cached(conn, &owner.space).await,
                vec![head.id],
                "round {round}"
            );
            assert_eq!(
                truth(conn, &owner.space).await,
                vec![head.id],
                "round {round}"
            );
            assert_eq!(parents_of(conn, &owner.space, head.id).await, previous);
            previous = vec![head.id];
        }
    }

    #[tokio::test]
    async fn sqlite_heads_follow_every_write() {
        heads_follow_every_write(&sqlite_db().await).await;
    }

    #[tokio::test]
    async fn postgres_heads_follow_every_write() {
        let Some(fixture) = PostgresTestSchema::new("postgres_heads_follow_every_write").await
        else {
            return;
        };
        heads_follow_every_write(&postgres_db(&fixture).await).await;
    }

    /// A release that does not maintain `epoch_head` appends several epochs,
    /// ending in a fork (two epochs with the same parent and seq, as
    /// concurrent pre-TC-732 writers left). The next new-release write must
    /// take exactly the history's heads as parents, in id order, not the
    /// stale cached head, and leave only itself cached.
    async fn old_writer_history_with_a_fork_is_detected(db: &TestDb) {
        let conn = db.connection();
        let owner = Owner::generate();
        host(db, &owner).await;
        run(db, &owner, &[Op::Put("a", b"new release")]).await;
        let first = newest(conn, &owner.space).await;
        assert_eq!(cached(conn, &owner.space).await, vec![first.id]);

        let second = old_writer_append(conn, &owner.space, &[first.id], 1, "second").await;
        let third = old_writer_append(conn, &owner.space, &[second], 2, "third").await;
        let fork_a = old_writer_append(conn, &owner.space, &[third], 3, "fork-a").await;
        let fork_b = old_writer_append(conn, &owner.space, &[third], 3, "fork-b").await;
        let mut fork = vec![fork_a, fork_b];
        fork.sort();
        assert_eq!(truth(conn, &owner.space).await, fork);
        assert_eq!(
            cached(conn, &owner.space).await,
            vec![first.id],
            "cache is stale"
        );

        let tx = conn.begin().await.unwrap();
        let next = HashMap::from([(wrap(&owner.space), 4)]);
        let heads = current(&tx, &[wrap(&owner.space)], &next).await.unwrap();
        tx.rollback().await.unwrap();
        assert_eq!(
            heads.parents.get(&wrap(&owner.space)),
            Some(&fork),
            "id order"
        );

        run(db, &owner, &[Op::Put("b", b"new release again")]).await;
        let merge = newest(conn, &owner.space).await;
        assert_eq!(merge.seq, 4);
        assert_eq!(parents_of(conn, &owner.space, merge.id).await, fork);
        assert_eq!(cached(conn, &owner.space).await, vec![merge.id]);
        assert_eq!(truth(conn, &owner.space).await, vec![merge.id]);
    }

    #[tokio::test]
    async fn sqlite_old_writer_history_with_a_fork_is_detected() {
        old_writer_history_with_a_fork_is_detected(&sqlite_db().await).await;
    }

    #[tokio::test]
    async fn postgres_old_writer_history_with_a_fork_is_detected() {
        let Some(fixture) =
            PostgresTestSchema::new("postgres_old_writer_history_with_a_fork_is_detected").await
        else {
            return;
        };
        old_writer_history_with_a_fork_is_detected(&postgres_db(&fixture).await).await;
    }

    /// Writers in two node processes (separate pools and in-process locks)
    /// race on one space. The history stays one chain and the cache ends
    /// holding exactly its single head.
    #[tokio::test]
    async fn postgres_concurrent_writers_keep_exactly_one_head() {
        let Some(fixture) =
            PostgresTestSchema::new("postgres_concurrent_writers_keep_exactly_one_head").await
        else {
            return;
        };
        let nodes = [postgres_db(&fixture).await, postgres_db(&fixture).await];
        let owner = std::sync::Arc::new(Owner::generate());
        host(&nodes[0], &owner).await;
        const WRITES: usize = 24;
        let writes = (0..WRITES).map(|i| {
            let db = nodes[i % 2].clone();
            let owner = owner.clone();
            async move {
                let key = format!("k{i}");
                run(&db, &owner, &[Op::Put(&key, b"v")]).await;
            }
        });
        futures::future::join_all(writes).await;

        let conn = nodes[0].connection();
        let head = newest(conn, &owner.space).await;
        assert_eq!(head.seq, WRITES as i64 - 1);
        assert_eq!(truth(conn, &owner.space).await, vec![head.id]);
        assert_eq!(cached(conn, &owner.space).await, vec![head.id]);
        let edges = epoch_order::Entity::find()
            .filter(epoch_order::Column::Space.eq(wrap(&owner.space)))
            .all(conn)
            .await
            .unwrap();
        assert_eq!(edges.len(), WRITES - 1, "one chain, no fork");
    }

    /// A database upgraded from v1.20.6 has history but an empty cache.
    /// Repair makes every space's cache exact, including a forked space, and
    /// a second pass changes nothing.
    async fn repair_fills_upgraded_history_once(db: &TestDb) {
        let conn = db.connection();
        let (linear, forked) = (Owner::generate(), Owner::generate());
        for owner in [&linear, &forked] {
            host(db, owner).await;
            run(db, owner, &[Op::Put("a", b"1")]).await;
            run(db, owner, &[Op::Put("b", b"2")]).await;
        }
        let base = newest(conn, &forked.space).await;
        old_writer_append(conn, &forked.space, &[base.id], 2, "upgrade-fork-a").await;
        old_writer_append(conn, &forked.space, &[base.id], 2, "upgrade-fork-b").await;
        // As left by v1.20.6, which has no epoch_head.
        epoch_head::Entity::delete_many().exec(conn).await.unwrap();
        let empty = HostedNoHistory::new(db).await;

        for (owner, expected) in [(&linear.space, true), (&forked.space, true)] {
            assert!(cached(conn, owner).await.is_empty());
            assert_eq!(db.repair_epoch_heads(owner).await.unwrap(), expected);
            assert_eq!(cached(conn, owner).await, truth(conn, owner).await);
        }
        assert_eq!(cached(conn, &forked.space).await.len(), 2);
        assert!(
            !db.repair_epoch_heads(&empty.0).await.unwrap(),
            "nothing to do"
        );
        for owner in [&linear.space, &forked.space] {
            let before = cached(conn, owner).await;
            assert!(!db.repair_epoch_heads(owner).await.unwrap(), "idempotent");
            assert_eq!(cached(conn, owner).await, before);
        }
        // A write on the backfilled fork merges both heads and leaves one.
        let fork = cached(conn, &forked.space).await;
        run(db, &forked, &[Op::Put("merge", b"3")]).await;
        let merge = newest(conn, &forked.space).await;
        assert_eq!(parents_of(conn, &forked.space, merge.id).await, fork);
        assert_eq!(cached(conn, &forked.space).await, vec![merge.id]);
    }

    /// A hosted space with no writes yet.
    struct HostedNoHistory(SpaceId);

    impl HostedNoHistory {
        async fn new(db: &TestDb) -> Self {
            let owner = Owner::generate();
            host(db, &owner).await;
            Self(owner.space)
        }
    }

    #[tokio::test]
    async fn sqlite_repair_fills_upgraded_history_once() {
        repair_fills_upgraded_history_once(&sqlite_db().await).await;
    }

    #[tokio::test]
    async fn postgres_repair_fills_upgraded_history_once() {
        let Some(fixture) =
            PostgresTestSchema::new("postgres_repair_fills_upgraded_history_once").await
        else {
            return;
        };
        repair_fills_upgraded_history_once(&postgres_db(&fixture).await).await;
    }

    /// The backfill and writers on another node interleave on one space,
    /// starting from a stale cache. Every repair runs under the space's
    /// lock, so the cache ends exact.
    #[tokio::test]
    async fn postgres_repair_concurrent_with_writers_ends_exact() {
        let Some(fixture) =
            PostgresTestSchema::new("postgres_repair_concurrent_with_writers_ends_exact").await
        else {
            return;
        };
        let (writer, backfill) = (postgres_db(&fixture).await, postgres_db(&fixture).await);
        let owner = std::sync::Arc::new(Owner::generate());
        host(&writer, &owner).await;
        run(&writer, &owner, &[Op::Put("seed", b"v")]).await;
        epoch_head::Entity::delete_many()
            .exec(writer.connection())
            .await
            .unwrap();

        let writes = {
            let owner = owner.clone();
            async move {
                for i in 0..12 {
                    let key = format!("k{i}");
                    run(&writer, &owner, &[Op::Put(&key, b"v")]).await;
                }
                writer
            }
        };
        let repairs = async {
            let mut repaired = 0;
            for _ in 0..12 {
                repaired += backfill.repair_epoch_heads(&owner.space).await.unwrap() as usize;
                tokio::task::yield_now().await;
            }
            repaired
        };
        let (writer, _) = tokio::join!(writes, repairs);

        let conn = writer.connection();
        let head = newest(conn, &owner.space).await;
        assert_eq!(head.seq, 12);
        assert_eq!(truth(conn, &owner.space).await, vec![head.id]);
        assert_eq!(cached(conn, &owner.space).await, vec![head.id]);
    }

    /// Upgrading a v1.20.6 database, with history and with the operator's
    /// online `epoch_order (space, parent, child)` index (TC-1274 PR A)
    /// already built, adds the empty table at boot; the backfill and the next
    /// write then pick the history's exact heads.
    #[tokio::test]
    async fn postgres_v1_20_6_upgrade_with_operator_index() {
        let test = "postgres_v1_20_6_upgrade_with_operator_index";
        let v1_20_6 = Migrator::migrations()
            .iter()
            .position(|migration| migration.name() == "m20261007_010000_database_identity_fence")
            .unwrap() as u32
            + 1;
        let Some(fixture) = PostgresTestSchema::migrated_through(test, Some(v1_20_6)).await else {
            return;
        };
        let conn = &fixture.conn;
        let (linear, forked) = (Owner::generate(), Owner::generate());
        for owner in [&linear, &forked] {
            space::Entity::insert(space::ActiveModel {
                id: sea_orm::Set(wrap(&owner.space)),
            })
            .exec(conn)
            .await
            .unwrap();
            let root =
                old_writer_append(conn, &owner.space, &[], 0, &format!("{}-0", owner.space)).await;
            old_writer_append(
                conn,
                &owner.space,
                &[root],
                1,
                &format!("{}-1", owner.space),
            )
            .await;
        }
        let base = newest(conn, &forked.space).await;
        old_writer_append(conn, &forked.space, &[base.id], 2, "v1206-fork-a").await;
        old_writer_append(conn, &forked.space, &[base.id], 2, "v1206-fork-b").await;
        conn.execute_unprepared(
            "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_epoch_order_space_parent_child \
             ON epoch_order (space, parent, child)",
        )
        .await
        .unwrap();

        migrate(&conn.clone().into()).await.unwrap();

        let db = postgres_db(&fixture).await;
        assert!(db.repair_epoch_heads(&linear.space).await.unwrap());
        assert_eq!(
            cached(conn, &linear.space).await,
            truth(conn, &linear.space).await
        );
        let fork = truth(conn, &forked.space).await;
        assert_eq!(fork.len(), 2);
        // The forked space is left to its next write (no backfill yet).
        run(&db, &forked, &[Op::Put("after", b"upgrade")]).await;
        let merge = newest(conn, &forked.space).await;
        assert_eq!(parents_of(conn, &forked.space, merge.id).await, fork);
        assert_eq!(cached(conn, &forked.space).await, vec![merge.id]);
    }

    #[tokio::test]
    async fn backfill_pages_every_space_in_id_order() {
        let db = sqlite_db().await;
        let mut spaces = Vec::new();
        for _ in 0..5 {
            let owner = Owner::generate();
            host(&db, &owner).await;
            spaces.push(owner.space);
        }
        spaces.sort_by_key(|space| space.to_string());
        let mut seen = Vec::new();
        let mut after = None;
        loop {
            let page = db
                .epoch_head_backfill_page(after.as_ref(), 2)
                .await
                .unwrap();
            if page.is_empty() {
                break;
            }
            assert!(page.len() <= 2);
            after = page.last().cloned();
            seen.extend(page);
        }
        assert_eq!(seen, spaces);
    }

    #[test]
    fn cache_is_current_only_when_it_holds_the_newest_seq() {
        let id = hash(b"head");
        assert!(is_current(&[], None), "no history, nothing cached");
        assert!(!is_current(&[], Some(1)), "history, nothing cached");
        assert!(!is_current(&[(id, 0)], None), "cached heads, no history");
        assert!(is_current(&[(id, 4)], Some(5)));
        assert!(!is_current(&[(id, 3)], Some(5)), "another writer appended");
        assert!(is_current(&[(id, 2), (hash(b"fork"), 4)], Some(5)));
        assert!(!is_current(&[(id, i64::MAX)], Some(i64::MIN)));
    }
}
