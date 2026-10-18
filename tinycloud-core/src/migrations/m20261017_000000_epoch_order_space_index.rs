//! TC-1274: `epoch_order (space, parent, child)` for the head anti-join that
//! `transact` runs on every write. Without it the inner side of that join
//! cannot be limited to one space (the PK leads with `parent`).
//!
//! Operators build this exact index online first:
//! `CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_epoch_order_space_parent_child
//! ON epoch_order (space, parent, child)`. This migration must then do
//! nothing. On PostgreSQL a bare `CREATE INDEX IF NOT EXISTS` would still take
//! the SHARE lock on `epoch_order` before it checks the name, and the boot's
//! migration transaction would hold it, blocking writes, until every
//! migration had run. So `up` reads `pg_index` first and issues no DDL when a
//! valid index of that name and shape exists. `IF NOT EXISTS` also matches by
//! name only, so an INVALID (failed `CONCURRENTLY`) or differently shaped
//! index of that name fails the migration instead of being recorded as done.
//!
//! Without the operator-built index, `up` builds it inside the migration
//! transaction: instant on a fresh database, but on a large existing
//! `epoch_order` it blocks writes for the build.

use sea_orm::{ConnectionTrait, DbBackend, Statement};
use sea_orm_migration::prelude::*;

use crate::relationships::epoch_order;

#[derive(DeriveMigrationName)]
pub struct Migration;

const INDEX: &str = "idx_epoch_order_space_parent_child";

fn create_index() -> IndexCreateStatement {
    Index::create()
        .name(INDEX)
        .table(epoch_order::Entity)
        .col(epoch_order::Column::Space)
        .col(epoch_order::Column::Parent)
        .col(epoch_order::Column::Child)
        .if_not_exists()
        .to_owned()
}

/// On PostgreSQL: `Ok(true)` when a valid, ready and live plain btree index
/// named `INDEX` on `epoch_order (space, parent, child)` exists in the current
/// schema, `Ok(false)` when no relation has that name, and an error naming
/// the fix otherwise.
///
/// An index whose `CREATE INDEX CONCURRENTLY` is still running is not yet
/// valid either. It is recognised by its build's progress row: by
/// `index_relid` when this role may see it, and otherwise (PostgreSQL hides a
/// progress row's columns from roles without the builder's privileges) by a
/// hidden progress row whose backend holds the build's SHARE UPDATE EXCLUSIVE
/// lock on `epoch_order`.
async fn postgres_index_present(manager: &SchemaManager<'_>) -> Result<bool, DbErr> {
    let row = manager
        .get_connection()
        .query_one(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT c.relkind::text AS kind,
                    COALESCE(i.indrelid = 'epoch_order'::regclass, false) AS on_table,
                    COALESCE(i.indisvalid AND i.indisready AND i.indislive, false) AS usable,
                    am.amname::text AS method,
                    i.indpred IS NULL AND i.indexprs IS NULL AS plain,
                    array_to_string(ARRAY(
                        SELECT a.attname FROM unnest(i.indkey::int2[]) WITH ORDINALITY AS k(attnum, ord)
                        JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = k.attnum
                        ORDER BY k.ord), ',') AS columns,
                    EXISTS (
                        SELECT 1 FROM pg_stat_progress_create_index p
                        WHERE p.index_relid = c.oid
                           OR (p.relid IS NULL AND EXISTS (
                                   SELECT 1 FROM pg_locks l
                                   WHERE l.pid = p.pid AND l.granted
                                     AND l.database = (SELECT oid FROM pg_database
                                                       WHERE datname = current_database())
                                     AND l.relation = 'epoch_order'::regclass
                                     AND l.mode = 'ShareUpdateExclusiveLock'))
                    ) AS building
             FROM pg_class c
             LEFT JOIN pg_index i ON i.indexrelid = c.oid
             LEFT JOIN pg_am am ON am.oid = c.relam
             WHERE c.relname = $1
               AND c.relnamespace = (SELECT relnamespace FROM pg_class
                                     WHERE oid = 'epoch_order'::regclass)",
            [INDEX.into()],
        ))
        .await?;
    let Some(row) = row else {
        return Ok(false);
    };
    let kind: String = row.try_get("", "kind")?;
    let on_table: bool = row.try_get("", "on_table")?;
    let usable: bool = row.try_get("", "usable")?;
    let method: Option<String> = row.try_get("", "method")?;
    let plain: Option<bool> = row.try_get("", "plain")?;
    let columns: Option<String> = row.try_get("", "columns")?;
    let building: bool = row.try_get("", "building")?;
    let shaped = kind == "i"
        && on_table
        && method.as_deref() == Some("btree")
        && plain == Some(true)
        && columns.as_deref() == Some("space,parent,child");
    if shaped && usable {
        return Ok(true);
    }
    if shaped && building {
        return Err(DbErr::Migration(format!(
            "{INDEX} is still being built (a CREATE INDEX CONCURRENTLY is in progress). Nothing \
             was applied. Wait for the build to finish, check that pg_index.indisvalid is true, \
             and restart."
        )));
    }
    let problem = if shaped {
        "is not usable (indisvalid, indisready and indislive are not all true: a failed or \
         interrupted CREATE INDEX CONCURRENTLY)"
            .to_string()
    } else {
        format!(
            "is not a plain btree index on epoch_order (space, parent, child) \
             (relkind {kind}, on epoch_order: {on_table}, method {method:?}, \
             columns {columns:?}, no predicate or expressions: {plain:?})"
        )
    };
    Err(DbErr::Migration(format!(
        "{INDEX} {problem}. Nothing was applied. Run `DROP INDEX CONCURRENTLY {INDEX};` then \
         `CREATE INDEX CONCURRENTLY {INDEX} ON epoch_order (space, parent, child);`, check \
         pg_index.indisvalid, and restart."
    )))
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let present = match manager.get_database_backend() {
            DbBackend::Postgres => postgres_index_present(manager).await?,
            // MySQL has no CREATE INDEX IF NOT EXISTS (sea-query drops the
            // clause), so check the name first.
            DbBackend::MySql => manager.has_index("epoch_order", INDEX).await?,
            DbBackend::Sqlite => false,
        };
        if present {
            return Ok(());
        }
        manager.create_index(create_index()).await
    }

    /// Keeps the index. It may be operator-built, and older releases run the
    /// same anti-join, so they still need it. Drop it by hand with
    /// `DROP INDEX CONCURRENTLY` if it is ever unwanted.
    async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::{hash, Hash};
    use crate::migrations::Migrator;
    use crate::models::{epoch, space};
    use crate::test_support::PostgresTestSchema;
    use crate::types::SpaceIdWrap;
    use sea_orm::{
        ConnectionTrait, Database, DbBackend, DbConn, EntityTrait, PaginatorTrait, Statement,
        TransactionTrait,
    };
    use sea_orm_migration::MigratorTrait;
    use tinycloud_auth::{
        resolver::DID_METHODS,
        resource::SpaceId,
        ssi::{dids::DIDBuf, jwk::JWK},
    };

    fn test_space_id(name: &str) -> SpaceId {
        let jwk = JWK::generate_ed25519().unwrap();
        let did: DIDBuf = DID_METHODS.generate(&jwk, "key").unwrap();
        SpaceId::new(did, name.parse().unwrap())
    }

    fn position_of(name: &str) -> u32 {
        Migrator::migrations()
            .iter()
            .position(|migration| migration.name() == name)
            .unwrap() as u32
    }

    /// Migrations shipped in v1.20.6 and v1.20.7 (the production schema):
    /// everything through the database identity fence.
    fn v1_20_6_migrations() -> u32 {
        position_of("m20261007_010000_database_identity_fence") + 1
    }

    /// Number of migrations before this one.
    fn steps_before_this() -> u32 {
        position_of(Migration.name())
    }

    /// The DDL each backend runs when the index is absent. MySQL has no
    /// `CREATE INDEX IF NOT EXISTS` (sea-query drops the clause), so `up`
    /// checks for the name first. MySQL can't run the full migration chain
    /// (TC-1314), so this statement is its only coverage.
    #[test]
    fn generated_create_index_statements() {
        assert_eq!(
            create_index().to_string(PostgresQueryBuilder),
            r#"CREATE INDEX IF NOT EXISTS "idx_epoch_order_space_parent_child" ON "epoch_order" ("space", "parent", "child")"#
        );
        assert_eq!(
            create_index().to_string(SqliteQueryBuilder),
            r#"CREATE INDEX IF NOT EXISTS "idx_epoch_order_space_parent_child" ON "epoch_order" ("space", "parent", "child")"#
        );
        assert_eq!(
            create_index().to_string(MysqlQueryBuilder),
            "CREATE INDEX `idx_epoch_order_space_parent_child` ON `epoch_order` (`space`, `parent`, `child`)"
        );
    }

    /// A linear history of `epochs` epochs in one new space, as `transact`
    /// writes it: each epoch's parent is the previous one.
    async fn seed_history<C: ConnectionTrait>(db: &C, epochs: usize) -> Vec<Hash> {
        let space = SpaceIdWrap(test_space_id("tc1274"));
        space::Entity::insert(space::ActiveModel {
            id: sea_orm::Set(space.clone()),
        })
        .exec(db)
        .await
        .unwrap();
        let ids: Vec<Hash> = (0..epochs)
            .map(|i| hash(format!("tc1274-epoch-{i}").as_bytes()))
            .collect();
        epoch::Entity::insert_many(ids.iter().enumerate().map(|(seq, id)| epoch::ActiveModel {
            seq: sea_orm::Set(seq as i64),
            id: sea_orm::Set(*id),
            space: sea_orm::Set(space.clone()),
        }))
        .exec(db)
        .await
        .unwrap();
        epoch_order::Entity::insert_many(ids.windows(2).map(|pair| epoch_order::ActiveModel {
            parent: sea_orm::Set(pair[0]),
            child: sea_orm::Set(pair[1]),
            space: sea_orm::Set(space.clone()),
        }))
        .exec(db)
        .await
        .unwrap();
        ids
    }

    async fn sqlite() -> DbConn {
        Database::connect("sqlite::memory:").await.unwrap()
    }

    /// Ordered key columns of `INDEX` on `epoch_order`, or `None` if absent.
    async fn sqlite_index_columns(db: &DbConn) -> Option<Vec<String>> {
        let listed = db
            .query_all(Statement::from_string(
                DbBackend::Sqlite,
                "PRAGMA index_list('epoch_order')".to_string(),
            ))
            .await
            .unwrap()
            .into_iter()
            .any(|row| row.try_get::<String>("", "name").unwrap() == INDEX);
        if !listed {
            return None;
        }
        let columns = db
            .query_all(Statement::from_string(
                DbBackend::Sqlite,
                format!("PRAGMA index_info('{INDEX}')"),
            ))
            .await
            .unwrap()
            .into_iter()
            .map(|row| row.try_get::<String>("", "name").unwrap())
            .collect();
        Some(columns)
    }

    async fn sqlite_index_rootpage(db: &DbConn) -> i64 {
        db.query_one(Statement::from_string(
            DbBackend::Sqlite,
            format!("SELECT rootpage FROM sqlite_master WHERE type = 'index' AND name = '{INDEX}'"),
        ))
        .await
        .unwrap()
        .unwrap()
        .try_get("", "rootpage")
        .unwrap()
    }

    fn expected_columns() -> Option<Vec<String>> {
        Some(vec!["space".into(), "parent".into(), "child".into()])
    }

    #[tokio::test]
    async fn sqlite_fresh_database_gets_the_index() {
        let db = sqlite().await;
        Migrator::up(&db, None).await.unwrap();
        assert_eq!(sqlite_index_columns(&db).await, expected_columns());
    }

    #[tokio::test]
    async fn sqlite_v1_20_6_upgrade_indexes_existing_history() {
        let db = sqlite().await;
        Migrator::up(&db, Some(v1_20_6_migrations())).await.unwrap();
        seed_history(&db, 50).await;
        assert_eq!(sqlite_index_columns(&db).await, None);

        Migrator::up(&db, None).await.unwrap();

        assert_eq!(sqlite_index_columns(&db).await, expected_columns());
        assert_eq!(epoch_order::Entity::find().count(&db).await.unwrap(), 49);
    }

    #[tokio::test]
    async fn sqlite_existing_index_is_kept() {
        let db = sqlite().await;
        Migrator::up(&db, Some(steps_before_this())).await.unwrap();
        seed_history(&db, 50).await;
        db.execute_unprepared(&format!(
            "CREATE INDEX {INDEX} ON epoch_order (space, parent, child)"
        ))
        .await
        .unwrap();
        let rootpage = sqlite_index_rootpage(&db).await;

        Migrator::up(&db, None).await.unwrap();

        assert_eq!(sqlite_index_columns(&db).await, expected_columns());
        assert_eq!(
            sqlite_index_rootpage(&db).await,
            rootpage,
            "index was rebuilt"
        );
    }

    /// `(oid, indisvalid, key columns)` of `INDEX` in the schema on
    /// `search_path`, or `None` if absent.
    async fn postgres_index(db: &DbConn) -> Option<(u32, bool, String)> {
        let row = db
            .query_one(Statement::from_string(
                DbBackend::Postgres,
                format!(
                    "SELECT c.oid::int8 AS oid, i.indisvalid AS valid,
                            array_to_string(ARRAY(
                                SELECT a.attname FROM unnest(i.indkey::int2[]) WITH ORDINALITY AS k(attnum, ord)
                                JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = k.attnum
                                ORDER BY k.ord), ',') AS columns
                     FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid
                     WHERE i.indrelid = 'epoch_order'::regclass AND c.relname = '{INDEX}'"
                ),
            ))
            .await
            .unwrap()?;
        Some((
            row.try_get::<i64>("", "oid").unwrap() as u32,
            row.try_get("", "valid").unwrap(),
            row.try_get("", "columns").unwrap(),
        ))
    }

    /// The production entry point: one outer transaction (TC-1054).
    async fn migrate(db: &DbConn) -> Result<(), DbErr> {
        crate::db::migrate(&db.clone().into()).await
    }

    #[tokio::test]
    async fn postgres_fresh_database_gets_a_valid_index() {
        let Some(fixture) =
            PostgresTestSchema::new("postgres_fresh_database_gets_a_valid_index").await
        else {
            return;
        };
        let (_, valid, columns) = postgres_index(&fixture.conn).await.unwrap();
        assert!(valid);
        assert_eq!(columns, "space,parent,child");
    }

    #[tokio::test]
    async fn postgres_v1_20_6_upgrade_indexes_existing_history() {
        let Some(fixture) = PostgresTestSchema::migrated_through(
            "postgres_v1_20_6_upgrade_indexes_existing_history",
            Some(v1_20_6_migrations()),
        )
        .await
        else {
            return;
        };
        let db = &fixture.conn;
        seed_history(db, 200).await;
        assert_eq!(postgres_index(db).await, None);

        migrate(db).await.unwrap();

        let (_, valid, columns) = postgres_index(db).await.unwrap();
        assert!(valid);
        assert_eq!(columns, "space,parent,child");
        assert_eq!(epoch_order::Entity::find().count(db).await.unwrap(), 199);
    }

    /// The operator built the index online on v1.20.6. Upgrading must keep
    /// that index (same OID) and must not lock `epoch_order` against
    /// writers: PostgreSQL takes `CREATE INDEX`'s SHARE lock before it
    /// evaluates `IF NOT EXISTS`, and the migration transaction would hold it
    /// until every migration has run.
    #[tokio::test]
    async fn postgres_operator_built_index_is_kept_without_blocking_writers() {
        let Some(fixture) = PostgresTestSchema::migrated_through(
            "postgres_operator_built_index_is_kept_without_blocking_writers",
            Some(v1_20_6_migrations()),
        )
        .await
        else {
            return;
        };
        let db = &fixture.conn;
        seed_history(db, 200).await;
        db.execute_unprepared(&format!(
            "CREATE INDEX CONCURRENTLY IF NOT EXISTS {INDEX} ON epoch_order (space, parent, child)"
        ))
        .await
        .unwrap();
        let (oid, valid, _) = postgres_index(db).await.unwrap();
        assert!(valid);

        // A writer mid-transaction, as `transact` is when it inserts.
        let writer = db.begin().await.unwrap();
        writer
            .execute_unprepared("LOCK TABLE epoch_order IN ROW EXCLUSIVE MODE")
            .await
            .unwrap();
        let migrator = fixture.connect(1).await;
        let migrated =
            tokio::time::timeout(std::time::Duration::from_secs(5), migrate(&migrator)).await;
        writer.rollback().await.unwrap();
        migrated
            .expect("migration waited behind an open epoch_order write")
            .unwrap();

        let (after, valid, columns) = postgres_index(db).await.unwrap();
        assert_eq!(after, oid, "operator index was rebuilt");
        assert!(valid);
        assert_eq!(columns, "space,parent,child");
    }

    async fn recorded(db: &DbConn) -> i64 {
        db.query_one(Statement::from_string(
            DbBackend::Postgres,
            format!(
                "SELECT COUNT(*) AS n FROM seaql_migrations WHERE version = '{}'",
                Migration.name()
            ),
        ))
        .await
        .unwrap()
        .unwrap()
        .try_get::<i64>("", "n")
        .unwrap()
    }

    /// `IF NOT EXISTS` matches by name only. An index that is not valid,
    /// ready and live (a failed `CREATE INDEX CONCURRENTLY`), or one on
    /// other columns, must fail the migration rather than be recorded as
    /// done.
    #[tokio::test]
    async fn postgres_unusable_operator_index_fails_the_migration() {
        for (definition, unset) in [
            ("(space, parent, child)", Some("indisvalid")),
            ("(space, parent, child)", Some("indisready")),
            ("(space, parent, child)", Some("indislive")),
            ("(space, parent)", None),
        ] {
            let label = format!("{definition} {unset:?}");
            let Some(fixture) = PostgresTestSchema::migrated_through(
                "postgres_unusable_operator_index_fails_the_migration",
                Some(steps_before_this()),
            )
            .await
            else {
                return;
            };
            let db = &fixture.conn;
            db.execute_unprepared(&format!("CREATE INDEX {INDEX} ON epoch_order {definition}"))
                .await
                .unwrap();
            if let Some(flag) = unset {
                // What a failed CONCURRENTLY build leaves behind. Needs a
                // superuser, as the CI and local test roles are.
                db.execute_unprepared(&format!(
                    "UPDATE pg_index SET {flag} = false WHERE indexrelid = '{INDEX}'::regclass"
                ))
                .await
                .unwrap();
            }

            let error = migrate(db).await.unwrap_err().to_string();

            assert!(error.contains(INDEX), "{label}: {error}");
            assert!(
                error.contains("DROP INDEX CONCURRENTLY"),
                "{label}: {error}"
            );
            assert_eq!(recorded(db).await, 0, "{label}");
        }
    }

    /// A node that boots while the operator's `CREATE INDEX CONCURRENTLY` is
    /// still running sees the index as not yet valid. It must fail, say to
    /// wait for the build (not to drop it), and boot once the build is done.
    /// The build is held in its "waiting for writers" phase by an open
    /// `epoch_order` write. Checked as the building superuser, who sees the
    /// build's `index_relid`, and as another role, from whom PostgreSQL hides
    /// the progress row's columns.
    #[tokio::test]
    async fn postgres_index_build_in_progress_says_wait() {
        let test = "postgres_index_build_in_progress_says_wait";
        for restricted in [false, true] {
            let Some(fixture) =
                PostgresTestSchema::migrated_through(test, Some(steps_before_this())).await
            else {
                return;
            };
            let db = &fixture.conn;
            let schema: String = db
                .query_one(Statement::from_string(
                    DbBackend::Postgres,
                    "SELECT current_schema() AS s".to_string(),
                ))
                .await
                .unwrap()
                .unwrap()
                .try_get("", "s")
                .unwrap();
            let role = format!("{schema}_node");

            let writer = db.begin().await.unwrap();
            writer
                .execute_unprepared("LOCK TABLE epoch_order IN ROW EXCLUSIVE MODE")
                .await
                .unwrap();
            let builder = fixture.connect(1).await;
            let build = tokio::spawn(async move {
                builder
                    .execute_unprepared(&format!(
                        "CREATE INDEX CONCURRENTLY {INDEX} ON epoch_order (space, parent, child)"
                    ))
                    .await
            });
            let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
            while postgres_index(db).await.is_none() {
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "build never started"
                );
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
            assert!(
                !postgres_index(db).await.unwrap().1,
                "mid-build index is not valid"
            );

            let migrator = fixture.connect(1).await;
            if restricted {
                for statement in [
                    format!("CREATE ROLE {role} NOLOGIN"),
                    format!("GRANT USAGE, CREATE ON SCHEMA {schema} TO {role}"),
                    format!("GRANT SELECT ON seaql_migrations TO {role}"),
                    format!("SET ROLE {role}"),
                ] {
                    migrator.execute_unprepared(&statement).await.unwrap();
                }
            }
            let error = migrate(&migrator).await.unwrap_err().to_string();
            writer.rollback().await.unwrap();
            build.await.unwrap().unwrap();
            if restricted {
                drop(migrator);
                for statement in [format!("DROP OWNED BY {role}"), format!("DROP ROLE {role}")] {
                    db.execute_unprepared(&statement).await.unwrap();
                }
            }

            assert!(
                error.contains("still being built"),
                "restricted {restricted}: {error}"
            );
            assert!(
                !error.contains("DROP INDEX"),
                "restricted {restricted}: {error}"
            );
            assert_eq!(recorded(db).await, 0);
            migrate(db).await.unwrap();
            assert_eq!(recorded(db).await, 1);
            assert!(postgres_index(db).await.unwrap().1);
        }
    }

    /// A failed build is not mistaken for a running one just because some
    /// session that is not building an index (autovacuum, ANALYZE, a manual
    /// lock) holds SHARE UPDATE EXCLUSIVE on `epoch_order`: the advice stays
    /// to drop and rebuild.
    #[tokio::test]
    async fn postgres_failed_index_with_a_non_building_lock_holder_says_drop() {
        let Some(fixture) = PostgresTestSchema::migrated_through(
            "postgres_failed_index_with_a_non_building_lock_holder_says_drop",
            Some(steps_before_this()),
        )
        .await
        else {
            return;
        };
        let db = &fixture.conn;
        db.execute_unprepared(&format!(
            "CREATE INDEX {INDEX} ON epoch_order (space, parent, child)"
        ))
        .await
        .unwrap();
        db.execute_unprepared(&format!(
            "UPDATE pg_index SET indisvalid = false WHERE indexrelid = '{INDEX}'::regclass"
        ))
        .await
        .unwrap();
        let holder = db.begin().await.unwrap();
        holder
            .execute_unprepared("LOCK TABLE epoch_order IN SHARE UPDATE EXCLUSIVE MODE")
            .await
            .unwrap();

        let migrator = fixture.connect(1).await;
        let error = migrate(&migrator).await.unwrap_err().to_string();
        holder.rollback().await.unwrap();

        assert!(error.contains("DROP INDEX CONCURRENTLY"), "{error}");
        assert!(!error.contains("still being built"), "{error}");
        assert_eq!(recorded(db).await, 0);
    }
}
