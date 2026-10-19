//! TC-1274: `current_kv (space, deleted, (key COLLATE "C"))` for the KV list
//! range select. `kv_prefix_condition` compares `key COLLATE "C"` so prefix
//! membership is byte order whatever the column's collation is, and
//! `idx_current_kv_space_deleted_key` is built in the column's own collation.
//! On a database whose collation is not `C` (production's is `en_US.UTF-8`)
//! the key bounds therefore cannot be index conditions: the scan reads every
//! live key of the space and filters. This index matches the `COLLATE "C"`
//! expression, so the planner seeks on the bounds. The old index stays for
//! point lookups. No query changes: the planner matches the expression.
//!
//! Operators build this exact index online first, outside any transaction:
//! `CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_current_kv_space_deleted_key_c
//! ON current_kv (space, deleted, (key COLLATE "C"))`. This migration must then
//! do nothing. On PostgreSQL a bare `CREATE INDEX IF NOT EXISTS` would still
//! take the SHARE lock on `current_kv` before it checks the name, and the
//! boot's migration transaction would hold it, blocking every KV write, until
//! every migration had run. So `up` reads `pg_index` first and issues no DDL
//! when a valid index of that name and shape exists. `IF NOT EXISTS` also
//! matches by name only, so an INVALID (failed `CONCURRENTLY`) or differently
//! shaped index of that name fails the migration instead of being recorded as
//! done.
//!
//! Without the operator-built index, `up` builds it inside the migration
//! transaction: instant on a fresh database, but on a large `current_kv` it
//! blocks writes for the build. **Do not reach that path on production: the
//! operator step comes first** (`docs/releasing.md`).
//!
//! SQLite and MySQL: nothing to do. SQLite's `BINARY` collation is byte order,
//! so `idx_current_kv_space_deleted_key` already seeks on the bounds. MySQL has
//! no `COLLATE "C"` to match; the migration leaves it as it is.

use sea_orm::{ConnectionTrait, DbBackend, Statement};
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

const INDEX: &str = "idx_current_kv_space_deleted_key_c";
const DEFINITION: &str = r#"(space, deleted, (key COLLATE "C"))"#;

/// The DDL the migration runs when the index is absent (PostgreSQL only).
fn create_index_sql() -> String {
    format!("CREATE INDEX IF NOT EXISTS {INDEX} ON current_kv {DEFINITION}")
}

/// The statement an operator runs, in autocommit, before the node deploy.
#[cfg(test)]
fn operator_create_index_sql() -> String {
    format!("CREATE INDEX CONCURRENTLY IF NOT EXISTS {INDEX} ON current_kv {DEFINITION}")
}

/// On PostgreSQL: `Ok(true)` when a valid, ready and live plain btree index
/// named `INDEX` on `current_kv (space, deleted, (key COLLATE "C"))` exists in
/// the current schema, `Ok(false)` when no relation has that name, and an
/// error naming the fix otherwise.
///
/// PostgreSQL stores `(key COLLATE "C")` on a bare column not as an index
/// expression but as the column `key` with the `C` collation of `pg_catalog`
/// recorded in `indcollation`, so that is the shape checked: columns
/// `space, deleted, key`, the third in collation `pg_catalog.C`, default
/// operator classes, ascending, no expressions, predicate or included
/// columns. An index on `key` in the database collation (the existing
/// `idx_current_kv_space_deleted_key`), on `COLLATE "POSIX"`, on another
/// expression, with a predicate, or with extra columns is not this index, and
/// the planner cannot use it for the byte-order bounds.
///
/// An index whose `CREATE INDEX CONCURRENTLY` is still running is not yet
/// valid either. It is recognised by its build's progress row: by
/// `index_relid` when this role may see it, and otherwise (PostgreSQL hides a
/// progress row's columns from roles without the builder's privileges) by a
/// hidden progress row whose backend holds the build's SHARE UPDATE EXCLUSIVE
/// lock on `current_kv`.
async fn postgres_index_present(manager: &SchemaManager<'_>) -> Result<bool, DbErr> {
    let row = manager
        .get_connection()
        .query_one(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT c.relkind::text AS kind,
                    COALESCE(i.indrelid = 'current_kv'::regclass, false) AS on_table,
                    COALESCE(i.indisvalid AND i.indisready AND i.indislive, false) AS usable,
                    am.amname::text AS method,
                    i.indpred IS NULL AND i.indexprs IS NULL
                        AND i.indnatts = i.indnkeyatts AS plain,
                    array_to_string(ARRAY(
                        SELECT a.attname::text
                        FROM unnest(i.indkey::int2[]) WITH ORDINALITY AS k(attnum, ord)
                        LEFT JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = k.attnum
                        ORDER BY k.ord), ',') AS columns,
                    (SELECT n.nspname::text || '.' || co.collname::text
                     FROM unnest(i.indcollation::oid[]) WITH ORDINALITY AS k(coll, ord)
                     JOIN pg_collation co ON co.oid = k.coll
                     JOIN pg_namespace n ON n.oid = co.collnamespace
                     WHERE k.ord = 3) AS key_collation,
                    COALESCE((SELECT bool_and(oc.opcdefault)
                              FROM unnest(i.indclass::oid[]) AS k(opclass)
                              JOIN pg_opclass oc ON oc.oid = k.opclass), false) AS default_opclasses,
                    array_to_string(i.indoption::int2[], ',') AS options,
                    EXISTS (
                        SELECT 1 FROM pg_stat_progress_create_index p
                        WHERE p.index_relid = c.oid
                           OR (p.relid IS NULL AND EXISTS (
                                   SELECT 1 FROM pg_locks l
                                   WHERE l.pid = p.pid AND l.granted
                                     AND l.database = (SELECT oid FROM pg_database
                                                       WHERE datname = current_database())
                                     AND l.relation = 'current_kv'::regclass
                                     AND l.mode = 'ShareUpdateExclusiveLock'))
                    ) AS building
             FROM pg_class c
             LEFT JOIN pg_index i ON i.indexrelid = c.oid
             LEFT JOIN pg_am am ON am.oid = c.relam
             WHERE c.relname = $1
               AND c.relnamespace = (SELECT relnamespace FROM pg_class
                                     WHERE oid = 'current_kv'::regclass)",
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
    let key_collation: Option<String> = row.try_get("", "key_collation")?;
    let default_opclasses: bool = row.try_get("", "default_opclasses")?;
    let options: Option<String> = row.try_get("", "options")?;
    let building: bool = row.try_get("", "building")?;
    let shaped = kind == "i"
        && on_table
        && method.as_deref() == Some("btree")
        && plain == Some(true)
        && columns.as_deref() == Some("space,deleted,key")
        && key_collation.as_deref() == Some("pg_catalog.C")
        && default_opclasses
        && options.as_deref() == Some("0,0,0");
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
            "is not a plain btree index on current_kv {DEFINITION} \
             (relkind {kind}, on current_kv: {on_table}, method {method:?}, \
             columns {columns:?}, key collation {key_collation:?}, no predicate, expressions \
             or included columns: {plain:?}, default operator classes: {default_opclasses}, \
             options {options:?})"
        )
    };
    Err(DbErr::Migration(format!(
        "{INDEX} {problem}. Nothing was applied. Run `DROP INDEX CONCURRENTLY {INDEX};` then \
         `CREATE INDEX CONCURRENTLY {INDEX} ON current_kv {DEFINITION};`, check \
         pg_index.indisvalid, and restart."
    )))
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if manager.get_database_backend() != DbBackend::Postgres {
            return Ok(());
        }
        if postgres_index_present(manager).await? {
            return Ok(());
        }
        manager
            .get_connection()
            .execute_unprepared(&create_index_sql())
            .await?;
        Ok(())
    }

    /// Keeps the index. It may be operator-built, and the previous release
    /// runs the same range select, so it still benefits. Drop it by hand with
    /// `DROP INDEX CONCURRENTLY` if it is ever unwanted.
    async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migrations::Migrator;
    use crate::test_support::PostgresTestSchema;
    use sea_orm::{ConnectionTrait, Database, DbBackend, DbConn, Statement, TransactionTrait};
    use sea_orm_migration::MigratorTrait;

    fn position_of(name: &str) -> u32 {
        Migrator::migrations()
            .iter()
            .position(|migration| migration.name() == name)
            .unwrap() as u32
    }

    /// Number of migrations before this one.
    fn steps_before_this() -> u32 {
        position_of(Migration.name())
    }

    #[tokio::test]
    async fn sqlite_migration_is_a_no_op() {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        Migrator::up(&db, None).await.unwrap();
        let names: Vec<String> = db
            .query_all(Statement::from_string(
                DbBackend::Sqlite,
                "PRAGMA index_list('current_kv')".to_string(),
            ))
            .await
            .unwrap()
            .into_iter()
            .map(|row| row.try_get("", "name").unwrap())
            .collect();
        assert!(names.contains(&"idx_current_kv_space_deleted_key".to_string()));
        assert!(!names.iter().any(|name| name == INDEX), "{names:?}");
    }

    /// `(oid, indisvalid, key columns with the third's collation)` of `INDEX`
    /// on `current_kv` in the schema on `search_path`, or `None` if absent.
    async fn postgres_index(db: &DbConn) -> Option<(u32, bool, String)> {
        let row = db
            .query_one(Statement::from_string(
                DbBackend::Postgres,
                format!(
                    "SELECT c.oid::int8 AS oid, i.indisvalid AS valid,
                            array_to_string(ARRAY(
                                SELECT COALESCE(a.attname::text, '<expr>')
                                    || CASE WHEN k.ord = 3 THEN ' ' || co.collname::text ELSE '' END
                                FROM unnest(i.indkey::int2[]) WITH ORDINALITY AS k(attnum, ord)
                                LEFT JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = k.attnum
                                JOIN unnest(i.indcollation::oid[]) WITH ORDINALITY AS cl(coll, ord)
                                  ON cl.ord = k.ord
                                LEFT JOIN pg_collation co ON co.oid = cl.coll
                                ORDER BY k.ord), ',') AS columns
                     FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid
                     WHERE i.indrelid = 'current_kv'::regclass AND c.relname = '{INDEX}'"
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

    fn expected_columns() -> String {
        "space,deleted,key C".to_string()
    }

    /// A schema as of the previous release: this migration not yet applied.
    async fn before_this(test: &str) -> Option<PostgresTestSchema> {
        PostgresTestSchema::migrated_through(test, Some(steps_before_this())).await
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
        assert_eq!(columns, expected_columns());
    }

    /// An existing database without the index (the operator step skipped)
    /// gets it built by the migration, with its rows indexed.
    #[tokio::test]
    async fn postgres_missing_index_is_created_by_the_migration() {
        let Some(fixture) = before_this("postgres_missing_index_is_created_by_the_migration").await
        else {
            return;
        };
        let db = &fixture.conn;
        assert_eq!(postgres_index(db).await, None);

        migrate(db).await.unwrap();

        let (_, valid, columns) = postgres_index(db).await.unwrap();
        assert!(valid);
        assert_eq!(columns, expected_columns());
        assert_eq!(recorded(db).await, 1);
    }

    /// The operator built the index online with the documented statement.
    /// Booting must keep that index (same OID) and must not lock `current_kv`
    /// against writers: PostgreSQL takes `CREATE INDEX`'s SHARE lock before
    /// it evaluates `IF NOT EXISTS`, and the migration transaction would hold
    /// it until every migration has run.
    #[tokio::test]
    async fn postgres_operator_built_index_is_kept_without_blocking_writers() {
        let Some(fixture) =
            before_this("postgres_operator_built_index_is_kept_without_blocking_writers").await
        else {
            return;
        };
        let db = &fixture.conn;
        db.execute_unprepared(&operator_create_index_sql())
            .await
            .unwrap();
        let (oid, valid, columns) = postgres_index(db).await.unwrap();
        assert!(valid);
        assert_eq!(columns, expected_columns());

        // A writer mid-transaction, as `transact` is when it upserts.
        let writer = db.begin().await.unwrap();
        writer
            .execute_unprepared("LOCK TABLE current_kv IN ROW EXCLUSIVE MODE")
            .await
            .unwrap();
        let migrator = fixture.connect(1).await;
        let migrated =
            tokio::time::timeout(std::time::Duration::from_secs(5), migrate(&migrator)).await;
        writer.rollback().await.unwrap();
        migrated
            .expect("migration waited behind an open current_kv write")
            .unwrap();

        let (after, valid, _) = postgres_index(db).await.unwrap();
        assert_eq!(after, oid, "operator index was rebuilt");
        assert!(valid);
        assert_eq!(recorded(db).await, 1);
    }

    /// `IF NOT EXISTS` matches by name only. An index that is not valid,
    /// ready and live (a failed `CREATE INDEX CONCURRENTLY`), or one of another
    /// shape, must fail the migration rather than be recorded as done.
    #[tokio::test]
    async fn postgres_unusable_operator_index_fails_the_migration() {
        for (definition, unset) in [
            (DEFINITION, Some("indisvalid")),
            (DEFINITION, Some("indisready")),
            (DEFINITION, Some("indislive")),
            // The existing index's shape: the database collation, not "C".
            ("(space, deleted, key)", None),
            (r#"(space, deleted, (key COLLATE "POSIX"))"#, None),
            (r#"(space, deleted, (lower(key) COLLATE "C"))"#, None),
            (r#"(space, (key COLLATE "C"))"#, None),
            (r#"(space, (key COLLATE "C"), deleted)"#, None),
            (r#"(space, deleted, (key COLLATE "C") DESC)"#, None),
            (
                r#"(space, deleted, (key COLLATE "C") varchar_pattern_ops)"#,
                None,
            ),
            (r#"(space, deleted, (key COLLATE "C")) INCLUDE (seq)"#, None),
            (
                r#"(space, deleted, (key COLLATE "C")) WHERE deleted = false"#,
                None,
            ),
        ] {
            let label = format!("{definition} {unset:?}");
            let Some(fixture) =
                before_this("postgres_unusable_operator_index_fails_the_migration").await
            else {
                return;
            };
            let db = &fixture.conn;
            db.execute_unprepared(&format!("CREATE INDEX {INDEX} ON current_kv {definition}"))
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
            assert!(
                error.contains("CREATE INDEX CONCURRENTLY"),
                "{label}: {error}"
            );
            assert_eq!(recorded(db).await, 0, "{label}");
        }
    }

    /// A table of that name that is not an index at all is not this index.
    #[tokio::test]
    async fn postgres_other_relation_with_the_index_name_fails_the_migration() {
        let Some(fixture) =
            before_this("postgres_other_relation_with_the_index_name_fails_the_migration").await
        else {
            return;
        };
        let db = &fixture.conn;
        db.execute_unprepared(&format!("CREATE TABLE {INDEX} (id int)"))
            .await
            .unwrap();

        let error = migrate(db).await.unwrap_err().to_string();

        assert!(error.contains("DROP INDEX CONCURRENTLY"), "{error}");
        assert_eq!(recorded(db).await, 0);
    }

    /// A node that boots while the operator's `CREATE INDEX CONCURRENTLY` is
    /// still running sees the index as not yet valid. It must fail, say to
    /// wait for the build (not to drop it), and boot once the build is done.
    /// The build is held in its "waiting for writers" phase by an open
    /// `current_kv` write. Checked as the building superuser, who sees the
    /// build's `index_relid`, and as another role, from whom PostgreSQL hides
    /// the progress row's columns.
    #[tokio::test]
    async fn postgres_index_build_in_progress_says_wait() {
        let test = "postgres_index_build_in_progress_says_wait";
        for restricted in [false, true] {
            let Some(fixture) = before_this(test).await else {
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
                .execute_unprepared("LOCK TABLE current_kv IN ROW EXCLUSIVE MODE")
                .await
                .unwrap();
            let builder = fixture.connect(1).await;
            let build = tokio::spawn(async move {
                builder
                    .execute_unprepared(&format!(
                        "CREATE INDEX CONCURRENTLY {INDEX} ON current_kv {DEFINITION}"
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
    /// lock) holds SHARE UPDATE EXCLUSIVE on `current_kv`: the advice stays
    /// to drop and rebuild.
    #[tokio::test]
    async fn postgres_failed_index_with_a_non_building_lock_holder_says_drop() {
        let Some(fixture) =
            before_this("postgres_failed_index_with_a_non_building_lock_holder_says_drop").await
        else {
            return;
        };
        let db = &fixture.conn;
        db.execute_unprepared(&format!("CREATE INDEX {INDEX} ON current_kv {DEFINITION}"))
            .await
            .unwrap();
        db.execute_unprepared(&format!(
            "UPDATE pg_index SET indisvalid = false WHERE indexrelid = '{INDEX}'::regclass"
        ))
        .await
        .unwrap();
        let holder = db.begin().await.unwrap();
        holder
            .execute_unprepared("LOCK TABLE current_kv IN SHARE UPDATE EXCLUSIVE MODE")
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
