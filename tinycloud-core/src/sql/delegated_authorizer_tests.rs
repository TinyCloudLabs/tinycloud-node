//! The delegated `tables` / `columns` / `readOnly` rules (TC-1791), run against
//! the real authorizer on the bundled SQLite: one table-driven test over every
//! statement of the case list (read from the arm tracker, never from SQLite's
//! error text), plus the rules that do not depend on a statement.

use rusqlite::hooks::{AuthAction, AuthContext, TransactionOperation};
use rusqlite::Connection;

use super::authority::SqlAuthority;
use super::authorizer::{create_authorizer_scoped, delegated_denial, StatementScope};
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
CREATE INDEX t2x ON t2(x);
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
    run_with(sql, caveats, authority, "")
}

/// [`run`] on the fixture plus `setup`.
fn run_with(
    sql: &str,
    caveats: Option<SqlCaveats>,
    authority: &SqlAuthority,
    setup: &str,
) -> (Result<(), rusqlite::Error>, Option<CaveatArm>) {
    let conn = Connection::open_in_memory().expect("in-memory database");
    conn.execute_batch(FIXTURE).expect("fixture");
    conn.execute_batch(setup).expect("setup");
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
    // M. DDL judged against the table it names (`sqlite_master` listed so
    // that the bookkeeping of a schema change is not the reason).
    row("M1", "ALTER TABLE t2 ADD COLUMN z", Some(&["Notes", "sqlite_master"]), None, false, Deny(Table)),
    row("M1b", "ALTER TABLE t2 ADD COLUMN z", Some(&["t2", "sqlite_master"]), None, false, Allow),
    row("M2", "DROP INDEX t2x", Some(&["Notes", "sqlite_master"]), None, false, Deny(Table)),
    row("M2b", "DROP INDEX t2x", Some(&["t2", "sqlite_master"]), None, false, Allow),
    row("M3", "CREATE INDEX i2 ON plain(a)", Some(&["Notes", "sqlite_master"]), None, false, Deny(Table)),
    row("M3b", "CREATE INDEX i2 ON plain(a)", Some(&["plain", "sqlite_master"]), None, false, Allow),
    row("M4", "CREATE TABLE z(a)", Some(&["Notes", "sqlite_master"]), None, false, Deny(Table)),
    row("M4b", "CREATE TABLE z(a)", Some(&["z", "sqlite_master"]), None, false, Allow),
    row("M5", "CREATE VIEW v2 AS SELECT id FROM Notes", Some(&["Notes", "sqlite_master"]), None, false, Deny(Table)),
    row("M5b", "CREATE VIEW v2 AS SELECT id FROM Notes", Some(&["Notes", "v2", "sqlite_master"]), None, false, Allow),
    row("M6", "DROP VIEW v", Some(&["Notes", "sqlite_master"]), None, false, Deny(Table)),
    row("M6b", "DROP VIEW v", Some(&["v", "sqlite_master"]), None, false, Allow),
    row("M7", "DROP TABLE plain", Some(&["Notes", "sqlite_master"]), None, false, Deny(Table)),
    row("M7b", "DROP TABLE plain", Some(&["plain", "sqlite_master"]), None, false, Allow),
    row("M8", "CREATE TEMP TABLE tt(a)", Some(&["Notes", "sqlite_temp_master"]), None, false, Deny(Table)),
    row("M8b", "CREATE TEMP TABLE tt(a)", Some(&["tt", "sqlite_temp_master"]), None, false, Allow),
    row("M9", "ALTER TABLE t2 ADD COLUMN z", Some(&["Notes", "sqlite_master"]), None, true, Deny(Write)),
    // P. PRAGMAs under a table or column limit.
    row("P1", "PRAGMA foreign_key_check", Some(&["Notes"]), None, false, Deny(Table)),
    row("P2", "PRAGMA integrity_check", None, Some(&["a"]), false, Deny(Table)),
    row("P3", "PRAGMA quick_check", Some(&["plain"]), None, false, Deny(Table)),
    row("P4", "PRAGMA user_version = 5", Some(&["plain"]), None, false, Deny(Write)),
    row("P5", "PRAGMA application_id = 7", None, Some(&["a"]), false, Deny(Write)),
    row("P6", "PRAGMA user_version", Some(&["plain"]), None, false, Allow),
    row("P7", "PRAGMA integrity_check", None, None, true, Allow),
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
fn without_the_delegated_rules_names_compare_exactly() {
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

/// What `delegated_denial` answers for one rusqlite action, under a `tables`
/// limit that lists `listed` only (with a table that is not listed, and with
/// the listed one) and under `readOnly`.
struct Audit {
    variant: &'static str,
    action: for<'a> fn(&'a str) -> AuthAction<'a>,
    unlisted: Option<CaveatArm>,
    listed: Option<CaveatArm>,
    read_only: Option<CaveatArm>,
}

macro_rules! audit {
    ($variant:literal, $action:expr, $unlisted:expr, $listed:expr, $read_only:expr) => {
        Audit {
            variant: $variant,
            action: $action,
            unlisted: $unlisted,
            listed: $listed,
            read_only: $read_only,
        }
    };
}

/// One entry per variant of rusqlite 0.32's `AuthAction` (and per PRAGMA
/// form). Actions that name a table are judged against it; the others involve
/// no table and say so.
fn audit_table() -> Vec<Audit> {
    vec![
        // Actions that name a table: the table arm unless it is listed;
        // `readOnly` refuses every one that changes anything.
        audit!(
            "CreateIndex",
            |t| AuthAction::CreateIndex {
                index_name: "i",
                table_name: t
            },
            Some(Table),
            None,
            Some(Write)
        ),
        audit!(
            "CreateTable",
            |t| AuthAction::CreateTable { table_name: t },
            Some(Table),
            None,
            Some(Write)
        ),
        audit!(
            "CreateTempIndex",
            |t| AuthAction::CreateTempIndex {
                index_name: "i",
                table_name: t
            },
            Some(Table),
            None,
            Some(Write)
        ),
        audit!(
            "CreateTempTable",
            |t| AuthAction::CreateTempTable { table_name: t },
            Some(Table),
            None,
            Some(Write)
        ),
        audit!(
            "CreateTempTrigger",
            |t| AuthAction::CreateTempTrigger {
                trigger_name: "g",
                table_name: t
            },
            Some(Table),
            None,
            Some(Write)
        ),
        audit!(
            "CreateTempView",
            |t| AuthAction::CreateTempView { view_name: t },
            Some(Table),
            None,
            Some(Write)
        ),
        audit!(
            "CreateTrigger",
            |t| AuthAction::CreateTrigger {
                trigger_name: "g",
                table_name: t
            },
            Some(Table),
            None,
            Some(Write)
        ),
        audit!(
            "CreateView",
            |t| AuthAction::CreateView { view_name: t },
            Some(Table),
            None,
            Some(Write)
        ),
        audit!(
            "Delete",
            |t| AuthAction::Delete { table_name: t },
            Some(Table),
            None,
            Some(Write)
        ),
        audit!(
            "DropIndex",
            |t| AuthAction::DropIndex {
                index_name: "i",
                table_name: t
            },
            Some(Table),
            None,
            Some(Write)
        ),
        audit!(
            "DropTable",
            |t| AuthAction::DropTable { table_name: t },
            Some(Table),
            None,
            Some(Write)
        ),
        audit!(
            "DropTempIndex",
            |t| AuthAction::DropTempIndex {
                index_name: "i",
                table_name: t
            },
            Some(Table),
            None,
            Some(Write)
        ),
        audit!(
            "DropTempTable",
            |t| AuthAction::DropTempTable { table_name: t },
            Some(Table),
            None,
            Some(Write)
        ),
        audit!(
            "DropTempTrigger",
            |t| AuthAction::DropTempTrigger {
                trigger_name: "g",
                table_name: t
            },
            Some(Table),
            None,
            Some(Write)
        ),
        audit!(
            "DropTempView",
            |t| AuthAction::DropTempView { view_name: t },
            Some(Table),
            None,
            Some(Write)
        ),
        audit!(
            "DropTrigger",
            |t| AuthAction::DropTrigger {
                trigger_name: "g",
                table_name: t
            },
            Some(Table),
            None,
            Some(Write)
        ),
        audit!(
            "DropView",
            |t| AuthAction::DropView { view_name: t },
            Some(Table),
            None,
            Some(Write)
        ),
        audit!(
            "Insert",
            |t| AuthAction::Insert { table_name: t },
            Some(Table),
            None,
            Some(Write)
        ),
        audit!(
            "Read",
            |t| AuthAction::Read {
                table_name: t,
                column_name: "c"
            },
            Some(Table),
            None,
            None
        ),
        audit!(
            "Update",
            |t| AuthAction::Update {
                table_name: t,
                column_name: "c"
            },
            Some(Table),
            None,
            Some(Write)
        ),
        audit!(
            "AlterTable",
            |t| AuthAction::AlterTable {
                database_name: "main",
                table_name: t
            },
            Some(Table),
            None,
            Some(Write)
        ),
        audit!(
            "Analyze",
            |t| AuthAction::Analyze { table_name: t },
            Some(Table),
            None,
            Some(Write)
        ),
        audit!(
            "CreateVtable",
            |t| AuthAction::CreateVtable {
                table_name: t,
                module_name: "m"
            },
            Some(Table),
            None,
            Some(Write)
        ),
        audit!(
            "DropVtable",
            |t| AuthAction::DropVtable {
                table_name: t,
                module_name: "m"
            },
            Some(Table),
            None,
            Some(Write)
        ),
        // PRAGMA: a schema report or a check lists tables whichever table is
        // named; a PRAGMA that sets a header value is database-wide state.
        audit!(
            "Pragma table_info(t)",
            |t| AuthAction::Pragma {
                pragma_name: "table_info",
                pragma_value: Some(t)
            },
            Some(Table),
            Some(Table),
            None
        ),
        audit!(
            "Pragma foreign_key_check",
            |_| AuthAction::Pragma {
                pragma_name: "foreign_key_check",
                pragma_value: None
            },
            Some(Table),
            Some(Table),
            None
        ),
        audit!(
            "Pragma integrity_check",
            |_| AuthAction::Pragma {
                pragma_name: "integrity_check",
                pragma_value: None
            },
            Some(Table),
            Some(Table),
            None
        ),
        audit!(
            "Pragma quick_check",
            |_| AuthAction::Pragma {
                pragma_name: "quick_check",
                pragma_value: None
            },
            Some(Table),
            Some(Table),
            None
        ),
        audit!(
            "Pragma user_version = n",
            |_| AuthAction::Pragma {
                pragma_name: "user_version",
                pragma_value: Some("5")
            },
            Some(Write),
            Some(Write),
            Some(Write)
        ),
        audit!(
            "Pragma application_id = n",
            |_| AuthAction::Pragma {
                pragma_name: "application_id",
                pragma_value: Some("5")
            },
            Some(Write),
            Some(Write),
            Some(Write)
        ),
        audit!(
            "Pragma user_version",
            |_| AuthAction::Pragma {
                pragma_name: "user_version",
                pragma_value: None
            },
            None,
            None,
            None
        ),
        // REINDEX names an index; the table it belongs to is judged by the
        // actions that build the index.
        audit!(
            "Reindex",
            |t| AuthAction::Reindex { index_name: t },
            None,
            None,
            Some(Write)
        ),
        // No table is involved. The abilities refuse transaction control,
        // ATTACH and DETACH for every holder.
        audit!("Select", |_| AuthAction::Select, None, None, None),
        audit!(
            "Function",
            |_| AuthAction::Function {
                function_name: "count"
            },
            None,
            None,
            None
        ),
        audit!("Recursive", |_| AuthAction::Recursive, None, None, None),
        audit!(
            "Transaction",
            |_| AuthAction::Transaction {
                operation: TransactionOperation::Begin
            },
            None,
            None,
            None
        ),
        audit!(
            "Savepoint",
            |_| AuthAction::Savepoint {
                operation: TransactionOperation::Begin,
                savepoint_name: "s"
            },
            None,
            None,
            None
        ),
        audit!(
            "Attach",
            |_| AuthAction::Attach { filename: "f" },
            None,
            None,
            None
        ),
        audit!(
            "Detach",
            |_| AuthAction::Detach { database_name: "d" },
            None,
            None,
            None
        ),
        // An action this code does not know: refused under `tables`.
        audit!(
            "Unknown",
            |_| AuthAction::Unknown {
                code: -1,
                arg1: None,
                arg2: None
            },
            Some(Table),
            Some(Table),
            None
        ),
    ]
}

#[test]
fn every_authorizer_action_is_judged_against_the_table_it_names_or_involves_none() {
    let tables = SqlCaveats {
        tables: Some(vec!["listed".to_string()]),
        ..SqlCaveats::default()
    };
    let read_only = SqlCaveats {
        read_only: Some(true),
        ..SqlCaveats::default()
    };
    let mut mismatches = Vec::new();
    let audit = audit_table();
    assert_eq!(audit.len(), 40, "one entry per action and PRAGMA form");
    for entry in &audit {
        for (name, caveats, expected) in [
            ("unlisted", &tables, entry.unlisted),
            ("listed", &tables, entry.listed),
            ("readOnly", &read_only, entry.read_only),
        ] {
            let table = if name == "listed" { "listed" } else { "other" };
            let ctx = AuthContext {
                action: (entry.action)(table),
                database_name: Some("main"),
                accessor: None,
            };
            let observed = delegated_denial(caveats, true, &ctx);
            if observed != expected {
                mismatches.push(format!(
                    "{} ({name}): expected {expected:?}, observed {observed:?}",
                    entry.variant
                ));
            }
        }
        // A statement the parser classed as a write is refused under
        // `readOnly` at whatever callback comes first.
        let ctx = AuthContext {
            action: (entry.action)("other"),
            database_name: Some("main"),
            accessor: None,
        };
        if delegated_denial(&read_only, false, &ctx) != Some(Write) {
            mismatches.push(format!("{} (readOnly, write statement)", entry.variant));
        }
    }
    assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
}

/// Only the ASCII letters fold, as in SQLite: the Kelvin sign is not `k`.
#[test]
fn non_ascii_names_match_only_exactly() {
    const SETUP: &str = "CREATE TABLE Kelvin(a); CREATE TABLE \"\u{212A}x\"(a);";
    for (listed, sql, expected) in [
        ("\u{212A}elvin", "SELECT a FROM Kelvin", Deny(Table)),
        ("kx", "SELECT a FROM \"\u{212A}x\"", Deny(Table)),
        ("\u{212A}X", "SELECT a FROM \"\u{212A}x\"", Allow),
        ("kelvin", "SELECT a FROM Kelvin", Allow),
    ] {
        let authority = admin();
        let caveats = SqlCaveats {
            tables: Some(vec![listed.to_string()]),
            ..SqlCaveats::default()
        };
        let (result, arm) = run_with(sql, Some(caveats), &authority, SETUP);
        let observed = match arm {
            Some(arm) => Deny(arm),
            None => {
                assert!(result.is_ok(), "{listed:?} {sql}");
                Allow
            }
        };
        assert_eq!(observed, expected, "{listed:?} {sql}");
    }
}
