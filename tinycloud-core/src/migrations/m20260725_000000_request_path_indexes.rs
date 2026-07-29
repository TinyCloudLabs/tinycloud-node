//! TC-282: request-path secondary indexes.
//!
//! TC-267..277 landed the architectural work (auth-graph snapshot, durable
//! replay, `current_kv` projection, batch reads, group-commit read audit,
//! incremental SQL persistence). This migration is the remaining
//! non-architectural tier: every table below is created with only a
//! composite primary key, so hot request-path queries that filter on a
//! non-leading PK column (or a column with no PK coverage at all) full-scan
//! tables that grow monotonically with node history.
//!
//! Column choices, order, and priority are documented in TC-282 and were
//! re-verified against the current schema (see the model/relationship
//! definitions imported below).

use sea_orm_migration::prelude::*;

use crate::models::{
    abilities, delegation, epoch, hook_delivery, hook_subscription, kv_write, revocation,
};
use crate::relationships::{event_order, parent_delegations};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // 1. ability(delegation, ability) -- `delegation` is the trailing PK
        //    column of (resource, ability, delegation). Filtered by every
        //    invocation's auth-graph load and both revocation control-proof
        //    checks.
        manager
            .create_index(
                Index::create()
                    .name("idx_ability_delegation_ability")
                    .table(abilities::Entity)
                    .col(abilities::Column::Delegation)
                    .col(abilities::Column::Ability)
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;

        // 2. parent_delegation(child) -- highest priority. `child` is the
        //    trailing PK column of (parent, child). Both arms of the
        //    recursive ancestor-closure CTE filter on it, and it now also
        //    grows with read volume via TC-273's read audit.
        manager
            .create_index(
                Index::create()
                    .name("idx_parent_delegation_child")
                    .table(parent_delegations::Entity)
                    .col(parent_delegations::Column::Child)
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;

        // 3. revocation(revoked) -- highest priority. PK is `id` alone, so
        //    `revoked` is entirely unindexed. Filtered by the auth-graph
        //    revocation-closure load, the per-ancestor COUNT(*) check, and
        //    three `delegation LEFT JOIN revocation` queries that otherwise
        //    join with no filter on `delegation` at all.
        manager
            .create_index(
                Index::create()
                    .name("idx_revocation_revoked")
                    .table(revocation::Entity)
                    .col(revocation::Column::Revoked)
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;

        // 4. event_order(space, seq) -- `space` is trailing PK column of
        //    (epoch, epoch_seq, space). Filtered (WHERE space IN (..) MAX(seq)
        //    GROUP BY space) once per transact.
        manager
            .create_index(
                Index::create()
                    .name("idx_event_order_space_seq")
                    .table(event_order::Entity)
                    .col(event_order::Column::Space)
                    .col(event_order::Column::Seq)
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;

        // 5. event_order(event) -- lower priority: real work only on
        //    /revoke, where `event_spaces`' IN list is populated by
        //    Event::Revocation.
        manager
            .create_index(
                Index::create()
                    .name("idx_event_order_event")
                    .table(event_order::Entity)
                    .col(event_order::Column::Event)
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;

        // 6. epoch(space, id) -- NOTE: (space, id), not (space, seq). `seq`
        //    is never filtered or ordered on for epoch anywhere, so
        //    (space, id) is covering for the epoch_order anti-join.
        manager
            .create_index(
                Index::create()
                    .name("idx_epoch_space_id")
                    .table(epoch::Entity)
                    .col(epoch::Column::Space)
                    .col(epoch::Column::Id)
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;

        // 7. kv_write(invocation) -- trailing PK column of
        //    (space, key, invocation). Filtered once per mutating invoke by
        //    emit_kv_hook_events.
        manager
            .create_index(
                Index::create()
                    .name("idx_kv_write_invocation")
                    .table(kv_write::Entity)
                    .col(kv_write::Column::Invocation)
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;

        // 8/9. delegation(delegatee) and delegation(delegator) -- PK is `id`
        //      alone, so both are entirely unindexed. Filtered per-hop in
        //      DID-PKH resolution, per-level in account-session-DID BFS, and
        //      by query_account_delegations (both columns, OR'd).
        manager
            .create_index(
                Index::create()
                    .name("idx_delegation_delegatee")
                    .table(delegation::Entity)
                    .col(delegation::Column::Delegatee)
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_delegation_delegator")
                    .table(delegation::Entity)
                    .col(delegation::Column::Delegator)
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;

        // 10. hook_delivery(status, created_at, attempts) -- NOTE this
        //     column order. `next_attempt_at` appears only in an
        //     IS NULL / range disjunction, so putting it before the ORDER BY
        //     columns would break the sort prefix. Polled every second with
        //     no prune path on the table.
        manager
            .create_index(
                Index::create()
                    .name("idx_hook_delivery_status_created_at_attempts")
                    .table(hook_delivery::Entity)
                    .col(hook_delivery::Column::Status)
                    .col(hook_delivery::Column::CreatedAt)
                    .col(hook_delivery::Column::Attempts)
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;

        // 11. hook_subscription(space_id, active, target_service) -- NOTE
        //     this column order, not (space_id, target_service, active).
        //     The real per-KV-op site filters all three; count_active_hook_
        //     subscriptions filters only (space_id, active), which this
        //     order also serves as a prefix.
        manager
            .create_index(
                Index::create()
                    .name("idx_hook_subscription_space_active_target")
                    .table(hook_subscription::Entity)
                    .col(hook_subscription::Column::SpaceId)
                    .col(hook_subscription::Column::Active)
                    .col(hook_subscription::Column::TargetService)
                    .if_not_exists()
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Reverse order. No `.if_exists()`: sea-query panics on MySQL for
        // `DROP INDEX ... IF EXISTS`, and `down()` only ever runs after a
        // successful `up()`, so the indexes are known to exist.
        manager
            .drop_index(
                Index::drop()
                    .name("idx_hook_subscription_space_active_target")
                    .table(hook_subscription::Entity)
                    .to_owned(),
            )
            .await?;
        manager
            .drop_index(
                Index::drop()
                    .name("idx_hook_delivery_status_created_at_attempts")
                    .table(hook_delivery::Entity)
                    .to_owned(),
            )
            .await?;
        manager
            .drop_index(
                Index::drop()
                    .name("idx_delegation_delegator")
                    .table(delegation::Entity)
                    .to_owned(),
            )
            .await?;
        manager
            .drop_index(
                Index::drop()
                    .name("idx_delegation_delegatee")
                    .table(delegation::Entity)
                    .to_owned(),
            )
            .await?;
        manager
            .drop_index(
                Index::drop()
                    .name("idx_kv_write_invocation")
                    .table(kv_write::Entity)
                    .to_owned(),
            )
            .await?;
        manager
            .drop_index(
                Index::drop()
                    .name("idx_epoch_space_id")
                    .table(epoch::Entity)
                    .to_owned(),
            )
            .await?;
        manager
            .drop_index(
                Index::drop()
                    .name("idx_event_order_event")
                    .table(event_order::Entity)
                    .to_owned(),
            )
            .await?;
        manager
            .drop_index(
                Index::drop()
                    .name("idx_event_order_space_seq")
                    .table(event_order::Entity)
                    .to_owned(),
            )
            .await?;
        manager
            .drop_index(
                Index::drop()
                    .name("idx_revocation_revoked")
                    .table(revocation::Entity)
                    .to_owned(),
            )
            .await?;
        manager
            .drop_index(
                Index::drop()
                    .name("idx_parent_delegation_child")
                    .table(parent_delegations::Entity)
                    .to_owned(),
            )
            .await?;
        manager
            .drop_index(
                Index::drop()
                    .name("idx_ability_delegation_ability")
                    .table(abilities::Entity)
                    .to_owned(),
            )
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::hash;
    use crate::migrations::Migrator;
    use crate::models::actor;
    use crate::types::{Ability, Caveats, Metadata, Resource, SpaceIdWrap};
    use sea_orm::{
        ActiveModelTrait, ActiveValue::Set, ConnectOptions, Database, DbBackend, DbConn, DbErr,
        EntityTrait, PaginatorTrait, QueryResult, Statement,
    };
    use sea_orm_migration::MigratorTrait;
    use std::collections::BTreeMap;
    use std::str::FromStr;
    use time::OffsetDateTime;
    use tinycloud_auth::{
        resolver::DID_METHODS,
        resource::{Path as LibPath, SpaceId as LibSpaceId},
        ssi::{dids::DIDBuf, jwk::JWK},
    };

    /// Mirrors `db.rs`'s own `test_space_id` helper: a real (but
    /// unregistered) DID-based `SpaceId`, since `SpaceId::from_str` requires
    /// well-formed `tinycloud:<method>:<id>:<name>` URIs.
    fn test_space_id(name: &str) -> LibSpaceId {
        let jwk = JWK::generate_ed25519().unwrap();
        let did: DIDBuf = DID_METHODS.generate(&jwk, "key").unwrap();
        LibSpaceId::new(did, name.parse().unwrap())
    }

    /// Ordered column list SQLite has physically recorded for `index_name`,
    /// via `PRAGMA index_info`. This is the piece a bare `has_index()` /
    /// `EXPLAIN QUERY PLAN` check cannot prove: that the index covers the
    /// exact columns, in the exact order, TC-282 asked for.
    async fn index_columns(conn: &DbConn, index_name: &str) -> Vec<String> {
        conn.query_all(Statement::from_string(
            DbBackend::Sqlite,
            format!("PRAGMA index_info('{index_name}')"),
        ))
        .await
        .unwrap()
        .into_iter()
        .map(|row: QueryResult| row.try_get::<String>("", "name").unwrap())
        .collect()
    }

    async fn index_names(conn: &DbConn, table: &str) -> Vec<String> {
        conn.query_all(Statement::from_string(
            DbBackend::Sqlite,
            format!("PRAGMA index_list('{table}')"),
        ))
        .await
        .unwrap()
        .into_iter()
        .map(|row: QueryResult| row.try_get::<String>("", "name").unwrap())
        .collect()
    }

    async fn explain(conn: &DbConn, sql: String) -> Vec<String> {
        conn.query_all(Statement::from_string(
            DbBackend::Sqlite,
            format!("EXPLAIN QUERY PLAN {sql}"),
        ))
        .await
        .unwrap()
        .into_iter()
        .map(|row| row.try_get::<String>("", "detail").unwrap())
        .collect()
    }

    const EXPECTED_INDEXES: &[(&str, &str, &[&str])] = &[
        (
            "idx_ability_delegation_ability",
            "ability",
            &["delegation", "ability"],
        ),
        (
            "idx_parent_delegation_child",
            "parent_delegation",
            &["child"],
        ),
        ("idx_revocation_revoked", "revocation", &["revoked"]),
        (
            "idx_event_order_space_seq",
            "event_order",
            &["space", "seq"],
        ),
        ("idx_event_order_event", "event_order", &["event"]),
        ("idx_epoch_space_id", "epoch", &["space", "id"]),
        ("idx_kv_write_invocation", "kv_write", &["invocation"]),
        ("idx_delegation_delegatee", "delegation", &["delegatee"]),
        ("idx_delegation_delegator", "delegation", &["delegator"]),
        (
            "idx_hook_delivery_status_created_at_attempts",
            "hook_delivery",
            &["status", "created_at", "attempts"],
        ),
        (
            "idx_hook_subscription_space_active_target",
            "hook_subscription",
            &["space_id", "active", "target_service"],
        ),
    ];

    async fn database() -> DbConn {
        let db = Database::connect(ConnectOptions::new("sqlite::memory:".to_string()))
            .await
            .unwrap();
        db.execute(Statement::from_string(
            DbBackend::Sqlite,
            "PRAGMA foreign_keys = OFF".to_string(),
        ))
        .await
        .unwrap();
        db
    }

    /// Everything a test needs to reproduce the exact literal values used
    /// while seeding, so `representative_plans` can filter on data that
    /// actually exists (space IDs are randomly-keyed DIDs, generated fresh
    /// per test run).
    struct SeedHandles {
        space_sql: String,
        other_space_sql: String,
    }

    /// Seed enough rows in every indexed table that the planner is choosing
    /// between a real table scan and a real index seek rather than reasoning
    /// about a handful of rows, matching the TC-271 precedent
    /// (`db.rs::current_reads_use_projection_indexes_with_large_history`).
    async fn seed_representative_data(db: &DbConn) -> Result<SeedHandles, DbErr> {
        let space = test_space_id("tc282-space");
        let other_space = test_space_id("tc282-other-space");
        let space_sql = space.to_string();
        let other_space_sql = other_space.to_string();

        actor::ActiveModel {
            id: Set("did:key:actor".to_string()),
        }
        .insert(db)
        .await
        .ok();

        // delegation + ability + parent_delegation + revocation
        let target_delegation = hash(b"tc282-target-delegation");
        for i in 0..300i64 {
            let id = hash(format!("tc282-delegation-{i}").as_bytes());
            delegation::ActiveModel {
                id: Set(id),
                delegator: Set(format!("did:key:delegator-{i}")),
                delegatee: Set(format!("did:key:delegatee-{i}")),
                expiry: Set(None),
                issued_at: Set(None),
                not_before: Set(None),
                facts: Set(None),
                serialization: Set(id.as_ref().to_vec()),
            }
            .insert(db)
            .await?;

            abilities::ActiveModel {
                resource: Set(Resource::from_str(&format!("urn:tc282:resource-{i}")).unwrap()),
                ability: Set(
                    <Ability as TryFrom<String>>::try_from("tc282/read".to_string()).unwrap(),
                ),
                delegation: Set(id),
                caveats: Set(Caveats(BTreeMap::new())),
            }
            .insert(db)
            .await?;

            let parent = hash(format!("tc282-parent-{i}").as_bytes());
            parent_delegations::ActiveModel {
                parent: Set(parent),
                child: Set(id),
            }
            .insert(db)
            .await?;

            revocation::ActiveModel {
                id: Set(hash(format!("tc282-revocation-{i}").as_bytes())),
                revoker: Set("did:key:actor".to_string()),
                revoked: Set(id),
                serialization: Set(format!("tc282-revocation-{i}").into_bytes()),
                revoked_at: Set(Some(OffsetDateTime::now_utc())),
            }
            .insert(db)
            .await?;
        }
        delegation::ActiveModel {
            id: Set(target_delegation),
            delegator: Set("did:key:target-delegator".to_string()),
            delegatee: Set("did:key:target-delegatee".to_string()),
            expiry: Set(None),
            issued_at: Set(None),
            not_before: Set(None),
            facts: Set(None),
            serialization: Set(target_delegation.as_ref().to_vec()),
        }
        .insert(db)
        .await?;
        abilities::ActiveModel {
            resource: Set(Resource::from_str("urn:tc282:target-resource").unwrap()),
            ability: Set(<Ability as TryFrom<String>>::try_from(
                "tc282/target-ability".to_string(),
            )
            .unwrap()),
            delegation: Set(target_delegation),
            caveats: Set(Caveats(BTreeMap::new())),
        }
        .insert(db)
        .await?;

        // event_order + epoch. `epoch` needs its own realistic row count
        // (not just one row) or the planner reasonably prefers a full scan
        // over an index seek regardless of which index exists.
        let epoch_id = hash(b"tc282-epoch-0");
        for i in 0..300i64 {
            epoch::ActiveModel {
                seq: Set(i),
                id: Set(hash(format!("tc282-epoch-{i}").as_bytes())),
                space: Set(SpaceIdWrap(if i % 2 == 0 {
                    space.clone()
                } else {
                    other_space.clone()
                })),
            }
            .insert(db)
            .await?;
        }
        for i in 0..300i64 {
            event_order::ActiveModel {
                seq: Set(i),
                epoch: Set(epoch_id),
                epoch_seq: Set(i),
                event: Set(hash(format!("tc282-event-{i}").as_bytes())),
                space: Set(SpaceIdWrap(if i % 2 == 0 {
                    space.clone()
                } else {
                    other_space.clone()
                })),
            }
            .insert(db)
            .await?;
        }

        // kv_write
        for i in 0..300i64 {
            kv_write::ActiveModel {
                space: Set(SpaceIdWrap(space.clone())),
                key: Set(format!("tc282-key-{i}").parse::<LibPath>().unwrap().into()),
                invocation: Set(hash(format!("tc282-invocation-{i}").as_bytes())),
                seq: Set(i),
                epoch: Set(epoch_id),
                epoch_seq: Set(i),
                value: Set(hash(format!("tc282-value-{i}").as_bytes())),
                metadata: Set(Metadata(BTreeMap::new())),
            }
            .insert(db)
            .await?;
        }

        // hook_delivery + hook_subscription
        for i in 0..300i64 {
            hook_subscription::ActiveModel {
                id: Set(format!("tc282-sub-{i}")),
                subscriber_did: Set("did:key:actor".to_string()),
                space_id: Set(if i % 2 == 0 {
                    space_sql.clone()
                } else {
                    other_space_sql.clone()
                }),
                target_service: Set(if i % 3 == 0 { "kv" } else { "sql" }.to_string()),
                path_prefix: Set(None),
                abilities_json: Set(None),
                callback_url: Set(format!("https://example.test/{i}")),
                encrypted_secret: Set(vec![0u8; 8]),
                secret_key_id: Set("key-1".to_string()),
                active: Set(i % 5 != 0),
                created_at: Set(OffsetDateTime::now_utc().to_string()),
            }
            .insert(db)
            .await?;

            hook_delivery::ActiveModel {
                id: Set(format!("tc282-delivery-{i}")),
                subscription_id: Set(format!("tc282-sub-{}", i % 50)),
                event_id: Set(format!("tc282-event-{i}")),
                payload_json: Set("{}".to_string()),
                status: Set(if i % 4 == 0 { "pending" } else { "delivered" }.to_string()),
                attempts: Set(i % 5),
                next_attempt_at: Set(None),
                last_error: Set(None),
                created_at: Set(OffsetDateTime::now_utc().to_string()),
                delivered_at: Set(None),
            }
            .insert(db)
            .await?;
        }

        Ok(SeedHandles {
            space_sql,
            other_space_sql,
        })
    }

    /// The 11 representative production query shapes from TC-282, run
    /// against the seeded data. Each returns the EXPLAIN QUERY PLAN lines.
    async fn representative_plans(
        db: &DbConn,
        seed: &SeedHandles,
    ) -> Vec<(&'static str, Vec<String>)> {
        let space_sql = seed.space_sql.replace('\'', "''");
        let other_space_sql = seed.other_space_sql.replace('\'', "''");
        vec![
            (
                "idx_ability_delegation_ability",
                explain(
                    db,
                    "SELECT * FROM ability WHERE delegation = x'00' AND ability = 'tc282/read'"
                        .to_string(),
                )
                .await,
            ),
            (
                "idx_parent_delegation_child",
                explain(
                    db,
                    "WITH RECURSIVE authorization_edges(child,parent) AS (\
                        SELECT child,parent FROM parent_delegation WHERE child = x'00' \
                        UNION \
                        SELECT parent_delegation.child, parent_delegation.parent \
                        FROM parent_delegation \
                        INNER JOIN authorization_edges ON parent_delegation.child = authorization_edges.parent\
                    ) SELECT child,parent FROM authorization_edges LIMIT 4097"
                        .to_string(),
                )
                .await,
            ),
            (
                "idx_revocation_revoked",
                explain(
                    db,
                    "SELECT delegation.* FROM delegation \
                     LEFT JOIN revocation ON revocation.revoked = delegation.id \
                     WHERE revocation.id IS NULL"
                        .to_string(),
                )
                .await,
            ),
            (
                "idx_event_order_space_seq",
                explain(
                    db,
                    format!(
                        "SELECT space, MAX(seq) FROM event_order WHERE space IN ('{space_sql}','{other_space_sql}') GROUP BY space"
                    ),
                )
                .await,
            ),
            (
                "idx_event_order_event",
                explain(db, "SELECT * FROM event_order WHERE event = x'00'".to_string()).await,
            ),
            (
                "idx_epoch_space_id",
                explain(
                    db,
                    format!(
                        "SELECT epoch.space, epoch.id FROM epoch \
                         LEFT JOIN epoch_order ON epoch_order.parent = epoch.id AND epoch_order.space = epoch.space \
                         WHERE epoch.space = '{space_sql}' AND epoch_order.child IS NULL"
                    ),
                )
                .await,
            ),
            (
                "idx_kv_write_invocation",
                explain(
                    db,
                    "SELECT * FROM kv_write WHERE invocation = x'00' ORDER BY seq, epoch, epoch_seq"
                        .to_string(),
                )
                .await,
            ),
            (
                "idx_delegation_delegatee",
                explain(
                    db,
                    "SELECT * FROM delegation WHERE delegatee = 'did:key:target-delegatee' LIMIT 1"
                        .to_string(),
                )
                .await,
            ),
            (
                "idx_delegation_delegator",
                explain(
                    db,
                    "SELECT * FROM delegation WHERE delegator = 'did:key:target-delegator' \
                     OR delegatee = 'did:key:target-delegatee'"
                        .to_string(),
                )
                .await,
            ),
            (
                "idx_hook_delivery_status_created_at_attempts",
                explain(
                    db,
                    "SELECT hd.*, hs.* FROM hook_delivery hd \
                     LEFT JOIN hook_subscription hs ON hs.id = hd.subscription_id \
                     WHERE hd.status IN ('pending','retrying') \
                       AND (hd.next_attempt_at IS NULL OR hd.next_attempt_at <= '2026-01-01T00:00:00Z') \
                     ORDER BY hd.created_at ASC, hd.attempts ASC LIMIT 32"
                        .to_string(),
                )
                .await,
            ),
            (
                "idx_hook_subscription_space_active_target",
                explain(
                    db,
                    format!(
                        "SELECT * FROM hook_subscription \
                         WHERE active = 1 AND space_id = '{space_sql}' AND target_service = 'kv'"
                    ),
                )
                .await,
            ),
        ]
    }

    #[tokio::test]
    async fn request_path_indexes_flip_scans_to_searches_and_round_trip_cleanly() {
        let db = database().await;

        // Apply every migration up to (but not including) TC-282, seed
        // realistic data volumes, then observe the BEFORE plans.
        let migrations = Migrator::migrations();
        let before_this = (migrations.len() - 1) as u32;
        Migrator::up(&db, Some(before_this)).await.unwrap();
        let seed = seed_representative_data(&db).await.unwrap();

        let before = representative_plans(&db, &seed).await;
        for (index_name, plan) in &before {
            println!("TC-282 BEFORE {index_name}: {plan:?}");
            assert!(
                plan.iter().any(|line| line.contains("SCAN")),
                "expected a SCAN before the index existed for {index_name}, got {plan:?}"
            );
            assert!(
                !plan.iter().any(|line| line.contains(index_name)),
                "index {index_name} must not be named in the BEFORE plan, got {plan:?}"
            );
        }
        for (table, index_name) in [
            ("ability", "idx_ability_delegation_ability"),
            ("parent_delegation", "idx_parent_delegation_child"),
            ("revocation", "idx_revocation_revoked"),
            ("event_order", "idx_event_order_space_seq"),
            ("event_order", "idx_event_order_event"),
            ("epoch", "idx_epoch_space_id"),
            ("kv_write", "idx_kv_write_invocation"),
            ("delegation", "idx_delegation_delegatee"),
            ("delegation", "idx_delegation_delegator"),
            (
                "hook_delivery",
                "idx_hook_delivery_status_created_at_attempts",
            ),
            (
                "hook_subscription",
                "idx_hook_subscription_space_active_target",
            ),
        ] {
            assert!(
                !index_names(&db, table)
                    .await
                    .contains(&ToString::to_string(&index_name)),
                "{index_name} must not exist before TC-282 runs"
            );
        }

        // Apply TC-282 itself and re-collect the ANALYZE'd table stats so
        // the planner sees realistic cardinalities, not empty-table
        // defaults.
        Migrator::up(&db, None).await.unwrap();
        db.execute(Statement::from_string(
            DbBackend::Sqlite,
            "ANALYZE".to_string(),
        ))
        .await
        .unwrap();

        // Schema readback: every index physically exists with the exact
        // ordered column list TC-282 specified.
        for (index_name, table, expected_cols) in EXPECTED_INDEXES {
            assert!(
                index_names(&db, table)
                    .await
                    .contains(&ToString::to_string(&index_name)),
                "{index_name} missing from {table} after up()"
            );
            let actual_cols = index_columns(&db, index_name).await;
            assert_eq!(
                &actual_cols, expected_cols,
                "{index_name} has the wrong ordered column list"
            );
        }

        let after = representative_plans(&db, &seed).await;
        for (index_name, plan) in &after {
            println!("TC-282 AFTER  {index_name}: {plan:?}");
            assert!(
                plan.iter()
                    .any(|line| line.contains("SEARCH") && line.contains(index_name)),
                "expected a SEARCH using {index_name} after the index existed, got {plan:?}"
            );
        }

        // down() drops all 11 and leaves the schema exactly as it was
        // before TC-282 ran.
        Migrator::down(&db, Some(1)).await.unwrap();
        for (_, table, index_name) in EXPECTED_INDEXES
            .iter()
            .map(|(name, table, _)| (*name, *table, *name))
        {
            assert!(
                !index_names(&db, table)
                    .await
                    .contains(&ToString::to_string(&index_name)),
                "{index_name} still present after down()"
            );
        }

        // up() is re-runnable thanks to `.if_not_exists()`.
        Migrator::up(&db, None).await.unwrap();
        for (index_name, table, _) in EXPECTED_INDEXES {
            assert!(
                index_names(&db, table)
                    .await
                    .contains(&ToString::to_string(&index_name)),
                "{index_name} missing from {table} after re-running up()"
            );
        }

        // Sanity check: seeding actually produced the volumes we assumed.
        assert_eq!(delegation::Entity::find().count(&db).await.unwrap(), 301);
    }

    /// TC-319: `transact` now computes the next per-space sequence with one
    /// ungrouped `SELECT MAX(seq) FROM event_order WHERE space = ?` per space
    /// (instead of a `GROUP BY space` aggregate). With `idx_event_order_space_seq`
    /// present that query must resolve via a backward index seek (SEARCH), not a
    /// table SCAN — the whole point of the rewrite.
    #[tokio::test]
    async fn ungrouped_per_space_max_seq_searches_event_order_index() {
        let db = database().await;
        Migrator::up(&db, None).await.unwrap();

        // Two spaces with enough rows that the planner prefers a seek over a
        // scan and the probed space's MAX(seq) genuinely skips the other's rows.
        let space = test_space_id("tc319-space");
        let other_space = test_space_id("tc319-other-space");
        let epoch_id = hash(b"tc319-epoch");
        for i in 0..300i64 {
            event_order::ActiveModel {
                seq: Set(i),
                epoch: Set(epoch_id),
                epoch_seq: Set(i),
                event: Set(hash(format!("tc319-event-{i}").as_bytes())),
                space: Set(SpaceIdWrap(if i % 2 == 0 {
                    space.clone()
                } else {
                    other_space.clone()
                })),
            }
            .insert(&db)
            .await
            .unwrap();
        }
        db.execute(Statement::from_string(
            DbBackend::Sqlite,
            "ANALYZE".to_string(),
        ))
        .await
        .unwrap();

        let plan = explain(
            &db,
            format!(
                "SELECT MAX(seq) FROM event_order WHERE space = '{}'",
                space.to_string().replace('\'', "''")
            ),
        )
        .await;
        println!("TC-319 ungrouped MAX(seq) plan: {plan:?}");
        assert!(
            plan.iter()
                .any(|line| line.contains("SEARCH") && line.contains("idx_event_order_space_seq")),
            "ungrouped per-space MAX(seq) must SEARCH idx_event_order_space_seq, got {plan:?}"
        );
        assert!(
            !plan.iter().any(|line| line.contains("SCAN")),
            "ungrouped per-space MAX(seq) must not SCAN event_order, got {plan:?}"
        );
    }
}
