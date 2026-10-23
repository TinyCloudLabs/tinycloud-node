//! The delegated `tables` / `columns` / `readOnly` rules (TC-1791), run against
//! the real authorizer on the bundled SQLite: one table-driven test over every
//! statement of the case list (read from the arm tracker, never from SQLite's
//! error text), plus the rules that do not depend on a statement.

use rusqlite::Connection;

use super::authority::SqlAuthority;
use super::authorizer::{create_authorizer_scoped, StatementScope};
use super::caveats::SqlCaveats;
use super::parser;
use super::types::CaveatArm;

/// Created as the owner, with no caveat.
const FIXTURE: &str = "
PRAGMA foreign_keys = ON;
CREATE TABLE Notes(id INTEGER PRIMARY KEY, body TEXT, secret TEXT);
CREATE TABLE t2(id INTEGER PRIMARY KEY, nid INT REFERENCES Notes(id) ON DELETE CASCADE, x TEXT);
CREATE TABLE plain(a, b);
CREATE VIEW v AS SELECT id, body FROM Notes;
CREATE TABLE log(m TEXT);
CREATE TRIGGER tr AFTER INSERT ON Notes BEGIN INSERT INTO log VALUES(new.body); END;
INSERT INTO Notes VALUES (1,'a','s'),(2,'b','t');
INSERT INTO t2 VALUES (1,1,'q');
INSERT INTO plain VALUES (1,2);
";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Expect {
    Allow,
    Deny(CaveatArm),
}

use CaveatArm::{Column, Table, Write};
use Expect::{Allow, Deny};

struct Row {
    id: &'static str,
    sql: &'static str,
    tables: Option<&'static [&'static str]>,
    columns: Option<&'static [&'static str]>,
    read_only: bool,
    expect: Expect,
}

const fn row(
    id: &'static str,
    sql: &'static str,
    tables: Option<&'static [&'static str]>,
    columns: Option<&'static [&'static str]>,
    read_only: bool,
    expect: Expect,
) -> Row {
    Row {
        id,
        sql,
        tables,
        columns,
        read_only,
        expect,
    }
}

fn caveats(row: &Row) -> SqlCaveats {
    SqlCaveats {
        tables: row
            .tables
            .map(|t| t.iter().map(|n| n.to_string()).collect()),
        columns: row
            .columns
            .map(|c| c.iter().map(|n| n.to_string()).collect()),
        statements: None,
        read_only: row.read_only.then_some(true),
    }
}

/// Runs `sql` on a fresh fixture database through the authorizer built for
/// `caveats`; returns whether it ran and which arm the tracker recorded.
fn run(
    sql: &str,
    caveats: Option<SqlCaveats>,
    authority: &SqlAuthority,
) -> (Result<(), rusqlite::Error>, Option<CaveatArm>) {
    let conn = Connection::open_in_memory().expect("in-memory database");
    conn.execute_batch(FIXTURE).expect("fixture");
    // The scope classifies the statement; the abilities are judged by the
    // authorizer, so classify with an authority that is never the reason for a
    // refusal.
    let parsed =
        parser::validate_sql_authorized(sql, &None, &SqlAuthority::new(["tinycloud.sql/admin"]))
            .expect("statement parses");
    conn.authorizer(Some(create_authorizer_scoped(
        caveats,
        authority,
        StatementScope::of(&parsed),
    )));
    let result = conn.execute_batch(sql);
    conn.authorizer(None::<fn(rusqlite::hooks::AuthContext<'_>) -> rusqlite::hooks::Authorization>);
    (result, authority.denied_arm().get())
}

fn admin() -> SqlAuthority {
    SqlAuthority::new(["tinycloud.sql/admin"]).with_delegated_caveats(true)
}

const ROWS: &[Row] = &[
    // A. Reads and columns
    row("A1", "SELECT body FROM Notes", Some(&["Notes"]), Some(&["body"]), false, Allow),
    row("A2", "SELECT secret FROM Notes", Some(&["Notes"]), Some(&["body"]), false, Deny(Column)),
    row("A3", "SELECT count(*) FROM Notes", Some(&["Notes"]), Some(&["body"]), false, Allow),
    row("A4", "SELECT 1 FROM Notes", Some(&["Notes"]), Some(&["body"]), false, Allow),
    row("A5", "SELECT * FROM Notes", Some(&["Notes"]), Some(&["id", "body"]), false, Deny(Column)),
    row(
        "A6",
        "SELECT n.body FROM Notes n JOIN t2 ON t2.nid=n.id",
        Some(&["Notes", "t2"]),
        Some(&["body", "nid", "id"]),
        false,
        Allow,
    ),
    row(
        "A7",
        "SELECT n.body FROM Notes n JOIN t2 ON t2.nid=n.id",
        Some(&["Notes"]),
        None,
        false,
        Deny(Table),
    ),
    row("A8", "SELECT body FROM NOTES", Some(&["notes"]), None, false, Allow),
    row("A9", "SELECT body FROM Notes", Some(&["NOTES"]), Some(&["BODY"]), false, Allow),
    row(
        "A10",
        "WITH c AS (SELECT id FROM Notes) SELECT * FROM c",
        Some(&["Notes"]),
        Some(&["id"]),
        false,
        Allow,
    ),
    row(
        "A11",
        "SELECT id FROM Notes WHERE id IN (SELECT nid FROM t2)",
        Some(&["Notes"]),
        None,
        false,
        Deny(Table),
    ),
    row(
        "A12",
        "SELECT id FROM Notes UNION SELECT id FROM t2",
        Some(&["Notes"]),
        None,
        false,
        Deny(Table),
    ),
    row("A13", "SELECT a FROM plain", Some(&[]), None, false, Deny(Table)),
    row("A14", "SELECT rowid FROM plain", Some(&["plain"]), Some(&["a"]), false, Deny(Column)),
    row("A15", "SELECT a+b FROM plain", Some(&["plain"]), Some(&["a"]), false, Deny(Column)),
    row("A16", "SELECT name FROM sqlite_master", Some(&["Notes"]), None, false, Deny(Table)),
    row(
        "A17",
        "SELECT name FROM pragma_table_info('Notes')",
        Some(&["plain"]),
        None,
        false,
        Deny(Table),
    ),
    // A17b: listing the table-valued function is not enough, the PRAGMA it
    // reports for the table argument is refused under a table restriction.
    row(
        "A17b",
        "SELECT name FROM pragma_table_info('Notes')",
        Some(&["pragma_table_info"]),
        None,
        false,
        Deny(Table),
    ),
    // B. Views
    row("B1", "SELECT * FROM v", Some(&["v"]), None, false, Deny(Table)),
    row("B2", "SELECT * FROM v", Some(&["v", "Notes"]), None, false, Allow),
    // C. Writes
    row("C1", "INSERT INTO plain(a) VALUES (9)", Some(&["plain"]), None, false, Allow),
    row(
        "C2",
        "INSERT INTO plain(a) VALUES (9)",
        Some(&["plain"]),
        Some(&["a"]),
        false,
        Deny(Column),
    ),
    row("C3", "INSERT INTO plain(a) VALUES (9)", Some(&["Notes"]), None, false, Deny(Table)),
    row("C4", "INSERT INTO plain(a) VALUES (9)", None, None, true, Deny(Write)),
    row(
        "C5",
        "INSERT INTO plain(a) SELECT id FROM Notes",
        Some(&["plain"]),
        None,
        false,
        Deny(Table),
    ),
    row(
        "C6",
        "INSERT INTO plain(a) SELECT id FROM Notes",
        Some(&["plain", "Notes"]),
        None,
        false,
        Allow,
    ),
    row("C7", "DELETE FROM plain WHERE a=1", Some(&["plain"]), None, false, Allow),
    row(
        "C8",
        "DELETE FROM plain WHERE a=1",
        Some(&["plain"]),
        Some(&["a"]),
        false,
        Deny(Column),
    ),
    row(
        "C9",
        "UPDATE Notes SET body='x' WHERE id=1",
        Some(&["Notes"]),
        Some(&["body", "id"]),
        false,
        Allow,
    ),
    row(
        "C10",
        "UPDATE Notes SET body='x' WHERE id=1",
        Some(&["Notes"]),
        Some(&["body"]),
        false,
        Deny(Column),
    ),
    row(
        "C11",
        "UPDATE Notes SET secret='x' WHERE id=1",
        Some(&["Notes"]),
        Some(&["body", "id"]),
        false,
        Deny(Column),
    ),
    row("C12", "UPDATE Notes SET body='x' WHERE id=1", None, None, true, Deny(Write)),
    row(
        "C13",
        "INSERT INTO Notes(id,body) VALUES (1,'z') ON CONFLICT(id) DO UPDATE SET body=excluded.body",
        Some(&["Notes"]),
        None,
        false,
        Deny(Table),
    ),
    row(
        "C14",
        "INSERT INTO plain(a) VALUES (9) RETURNING b",
        Some(&["plain"]),
        Some(&["a"]),
        false,
        Deny(Column),
    ),
    row("C15", "REPLACE INTO plain(a,b) VALUES (1,2)", Some(&["plain"]), None, false, Allow),
    row("C15-readonly", "REPLACE INTO plain(a,b) VALUES (1,2)", None, None, true, Deny(Write)),
    // D. Side effects the authorizer sees (triggers, foreign keys)
    row("D1", "INSERT INTO Notes(id,body) VALUES (7,'t')", Some(&["Notes"]), None, false, Deny(Table)),
    row(
        "D2",
        "INSERT INTO Notes(id,body) VALUES (7,'t')",
        Some(&["Notes", "log"]),
        None,
        false,
        Deny(Table),
    ),
    row("D3", "DELETE FROM Notes WHERE id=1", Some(&["Notes"]), None, false, Deny(Table)),
    row("D4", "DELETE FROM Notes WHERE id=1", Some(&["Notes", "t2"]), None, false, Allow),
    // E. readOnly beyond DML
    row("E1", "CREATE TABLE z(a)", None, None, true, Deny(Write)),
    row("E2", "PRAGMA user_version = 5", None, None, true, Deny(Write)),
    row("E3", "PRAGMA user_version", None, None, true, Allow),
];

#[test]
fn every_case_of_the_list_is_decided_by_the_arm_the_tracker_records() {
    let mut mismatches = Vec::new();
    for row in ROWS {
        let authority = admin();
        let (result, arm) = run(row.sql, Some(caveats(row)), &authority);
        let observed = match (result.is_ok(), arm) {
            (true, None) => Allow,
            (false, Some(arm)) => Deny(arm),
            (ran, arm) => panic!(
                "{}: statement ran = {ran} but the recorded arm is {arm:?} (every refusal \
                 must record an arm, an allowed statement none)",
                row.id
            ),
        };
        if observed != row.expect {
            mismatches.push(format!(
                "{}: expected {:?}, observed {:?}",
                row.id, row.expect, observed
            ));
        }
    }
    assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
}

#[test]
fn a_refusal_records_only_the_highest_precedence_arm() {
    // readOnly and an unlisted table in one write: the write arm names it.
    let authority = admin();
    let caveats = SqlCaveats {
        tables: Some(vec!["Notes".to_string()]),
        read_only: Some(true),
        ..SqlCaveats::default()
    };
    let (result, arm) = run("INSERT INTO plain(a) VALUES (9)", Some(caveats), &authority);
    assert!(result.is_err());
    assert_eq!(arm, Some(Write));
}

#[test]
fn the_abilities_decide_before_the_caveats() {
    // A read-tier grant may not write whatever the caveat lists; the refusal
    // is the ability's and records no caveat arm.
    let authority = SqlAuthority::new(["tinycloud.sql/write"]).with_delegated_caveats(true);
    let caveats = SqlCaveats {
        tables: Some(vec!["plain".to_string()]),
        ..SqlCaveats::default()
    };
    // `write` may insert into a listed table.
    let (result, arm) = run(
        "INSERT INTO plain(a) VALUES (9)",
        Some(caveats.clone()),
        &authority,
    );
    assert!(result.is_ok());
    assert_eq!(arm, None);
    // DDL needs `schema`; `write` alone is refused by the ability, no arm.
    let (result, arm) = run("CREATE TABLE z(a)", Some(caveats), &authority);
    assert!(result.is_err());
    assert_eq!(arm, None);
}

#[test]
fn without_the_delegated_rules_the_caveats_keep_their_earlier_reading() {
    // Not delegated: table and column names compare exactly, and a read that
    // names no column is judged as the column "".
    let authority = SqlAuthority::new(["tinycloud.sql/admin"]);
    let columns_only = SqlCaveats {
        columns: Some(vec!["body".to_string()]),
        ..SqlCaveats::default()
    };
    let (result, arm) = run("SELECT count(*) FROM Notes", Some(columns_only), &authority);
    assert!(result.is_err());
    assert_eq!(arm, None, "no arm is recorded without the delegated rules");

    let lower = SqlCaveats {
        tables: Some(vec!["notes".to_string()]),
        ..SqlCaveats::default()
    };
    let (result, arm) = run("SELECT body FROM Notes", Some(lower), &authority);
    assert!(result.is_err());
    assert_eq!(arm, None);
}

#[test]
fn schema_reports_are_refused_under_a_table_or_column_restriction() {
    for (caveats, expected) in [
        (
            SqlCaveats {
                tables: Some(vec!["plain".to_string()]),
                ..SqlCaveats::default()
            },
            Deny(Table),
        ),
        (
            SqlCaveats {
                columns: Some(vec!["a".to_string()]),
                ..SqlCaveats::default()
            },
            Deny(Table),
        ),
        (
            SqlCaveats {
                read_only: Some(true),
                ..SqlCaveats::default()
            },
            Allow,
        ),
    ] {
        let authority = admin();
        let (result, arm) = run("PRAGMA table_info(Notes)", Some(caveats), &authority);
        let observed = match arm {
            Some(arm) => Deny(arm),
            None => {
                assert!(result.is_ok());
                Allow
            }
        };
        assert_eq!(observed, expected);
    }
}
