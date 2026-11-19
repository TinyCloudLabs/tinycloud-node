//! TC-3035: a `read_only` caveat admits only plain reads, for every DuckDB
//! tier. The admin tiers (`duckdb/admin`, `duckdb/*`) skip the statement
//! allowlist, so for them the caveat is the only check; each statement below
//! must be refused by the caveat itself, not by some other rule.

use super::super::caveats::DuckDbCaveats;
use super::super::types::DuckDbError;
use super::validate_sql;

const READ: &str = "tinycloud.duckdb/read";
const WRITE: &str = "tinycloud.duckdb/write";
const ADMIN: &str = "tinycloud.duckdb/admin";
const ALL: &str = "tinycloud.duckdb/*";

fn read_only() -> Option<DuckDbCaveats> {
    Some(DuckDbCaveats {
        tables: None,
        columns: None,
        statements: None,
        read_only: Some(true),
    })
}

/// Statements the node's parser accepts for the admin tiers that are not
/// plain reads: writes, files, other databases, settings, stored bodies,
/// and multi-statement requests that hide one of these behind a read.
const REFUSED: &[&str] = &[
    // Writes.
    "INSERT INTO t VALUES (1)",
    "UPDATE t SET a = 1",
    "DELETE FROM t",
    "TRUNCATE t",
    "CREATE TABLE u (a INTEGER)",
    "CREATE TABLE u AS SELECT * FROM t",
    "DROP TABLE t",
    "ALTER TABLE t ADD COLUMN b INTEGER",
    "CREATE INDEX i ON t (a)",
    "CREATE VIEW v AS SELECT * FROM t",
    "CREATE SCHEMA s",
    "CREATE SEQUENCE q",
    "CREATE MACRO m(a) AS a + 1",
    "WITH c AS (SELECT 1 AS a) INSERT INTO t SELECT a FROM c",
    // Stored bodies.
    "PREPARE p AS INSERT INTO t VALUES (1)",
    "PREPARE p AS SELECT 1",
    "EXECUTE p",
    "DEALLOCATE p",
    "EXPLAIN ANALYZE INSERT INTO t VALUES (1)",
    "EXPLAIN ANALYZE UPDATE t SET a = 1",
    "EXPLAIN ANALYZE DELETE FROM t",
    // Files and other databases.
    "COPY t TO 'out.csv'",
    "COPY t FROM 'in.csv'",
    "ATTACH 'other.duckdb' AS other",
    "ATTACH DATABASE ':memory:' AS other",
    "USE other",
    "INSTALL httpfs",
    "LOAD httpfs",
    // Settings and pragmas, including ones that only read.
    "SET threads = 1",
    "PRAGMA threads = 1",
    "PRAGMA force_checkpoint",
    "PRAGMA table_info('t')",
    "CALL checkpoint()",
    // Multi-statement: one non-read anywhere refuses the request.
    "SELECT 1; INSERT INTO t VALUES (1)",
    "INSERT INTO t VALUES (1); SELECT 1",
    "SELECT 1; EXECUTE p",
    "SELECT 1; COPY t TO 'out.csv'",
    "SELECT 1; ATTACH 'other.duckdb' AS other",
    "SELECT 1; PRAGMA threads = 1",
    "BEGIN; INSERT INTO t VALUES (1); COMMIT",
    "EXPLAIN SELECT 1; PREPARE p AS DELETE FROM t",
    // Transaction control changes the shared connection's state.
    "BEGIN",
    "COMMIT",
    "ROLLBACK",
    "BEGIN; SELECT 1; COMMIT",
];

/// Plain reads stay allowed under `read_only`.
const ALLOWED: &[&str] = &[
    "SELECT 1",
    "SELECT * FROM t",
    "WITH c AS (SELECT 1 AS a) SELECT a FROM c",
    "SELECT 1; SELECT 2",
    "EXPLAIN SELECT * FROM t",
    "EXPLAIN ANALYZE SELECT * FROM t",
];

#[test]
fn admin_tiers_parse_each_refused_statement_and_the_caveat_refuses_it() {
    for ability in [ADMIN, ALL] {
        for sql in REFUSED {
            // Without the caveat the admin tiers accept it, so the refusal
            // below comes from `read_only` and nothing else.
            if let Err(error) = validate_sql(sql, &None, ability) {
                panic!("{ability} {sql}: refused without the caveat: {error}");
            }
            let result = validate_sql(sql, &read_only(), ability);
            assert!(
                matches!(result, Err(DuckDbError::ReadOnlyViolation)),
                "{ability} {sql}: {:?}",
                result.map(|parsed| parsed.is_read_only)
            );
        }
    }
}

#[test]
fn no_tier_runs_a_refused_statement_under_the_caveat() {
    for ability in [READ, WRITE, ADMIN, ALL] {
        for sql in REFUSED {
            assert!(
                validate_sql(sql, &read_only(), ability).is_err(),
                "{ability} {sql}"
            );
        }
    }
}

#[test]
fn every_tier_still_reads_under_the_caveat() {
    for ability in [READ, WRITE, ADMIN, ALL] {
        for sql in ALLOWED {
            let parsed = validate_sql(sql, &read_only(), ability)
                .unwrap_or_else(|error| panic!("{ability} {sql}: {error}"));
            assert!(parsed.is_read_only, "{ability} {sql}");
        }
    }
}
