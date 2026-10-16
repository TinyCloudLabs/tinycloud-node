//! Exercise tenant policy against the real native service and process streams.
#![cfg(feature = "duckdb")]

use std::{process::Command, sync::Arc};

use dashmap::DashMap;
use tinycloud_core::duckdb::{
    caveats::{DuckDbCaveats, PreparedStatement},
    database::spawn_actor,
    types::{DuckDbRequest, DuckDbResponse, DuckDbValue},
};

const CHILD: &str = "TC1304_DIAGNOSTIC_POLICY_CHILD";
const LITERAL: &str = "tc1304_synthetic_sql_literal_canary";
const PARAMETER: &str = "tc1304_synthetic_bound_parameter_canary";

#[test]
fn tenant_diagnostics_cannot_escape_process_streams_and_normal_sql_still_works() {
    if std::env::var_os(CHILD).is_some() {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let directory = tempfile::tempdir().unwrap();
                let actor = spawn_actor(
                    "policy".into(),
                    "process".into(),
                    directory.path().to_str().unwrap().into(),
                    u64::MAX,
                    1,
                    "128MB".into(),
                    Arc::new(DashMap::new()),
                );
                for ability in [
                    "tinycloud.duckdb/read",
                    "tinycloud.duckdb/write",
                    "tinycloud.duckdb/admin",
                ] {
                    for sql in [
                        "SET enable_profiling = 'json'",
                        "PRAGMA enable_profile",
                        "PRAGMA enable_profiling",
                        "SET profiling_mode = 'detailed'",
                        "SELECT * FROM enable_logging(storage='stdout')",
                        "SELECT write_log('tc1304_synthetic_bound_parameter_canary')",
                    ] {
                        let caveats = DuckDbCaveats {
                            statements: Some(vec![PreparedStatement {
                                name: "untrusted-template".into(),
                                sql: sql.into(),
                            }]),
                            ..Default::default()
                        };
                        actor
                            .execute(
                                DuckDbRequest::Query {
                                    sql: sql.into(),
                                    params: vec![],
                                },
                                Some(caveats),
                                ability.into(),
                                false,
                                false,
                            )
                            .await
                            .expect_err("tenant diagnostic activation must be rejected");
                    }
                }
                for (sql, params, expected) in [
                    (format!("SELECT '{LITERAL}' AS value"), vec![], LITERAL),
                    (
                        "SELECT ? AS value".into(),
                        vec![DuckDbValue::Text(PARAMETER.into())],
                        PARAMETER,
                    ),
                    (
                        "SELECT 'enable_logging' AS value".into(),
                        vec![],
                        "enable_logging",
                    ),
                ] {
                    let result = actor
                        .execute(
                            DuckDbRequest::Query { sql, params },
                            None,
                            "tinycloud.duckdb/read".into(),
                            false,
                            false,
                        )
                        .await
                        .unwrap();
                    let DuckDbResponse::Query(result) = result.response else {
                        panic!("query response required");
                    };
                    assert_eq!(result.rows, vec![vec![DuckDbValue::Text(expected.into())]]);
                }
                drop(actor);
            });
        println!("tc1304_stdout_capture_control");
        eprintln!("tc1304_stderr_capture_control");
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "tenant_diagnostics_cannot_escape_process_streams_and_normal_sql_still_works",
            "--nocapture",
        ])
        .env_clear()
        .env("HOME", directory.path())
        .env(CHILD, "1")
        .output()
        .unwrap();
    assert!(output.status.success(), "native policy child failed");
    for stream in [&output.stdout, &output.stderr] {
        let text = String::from_utf8_lossy(stream);
        for forbidden in [LITERAL, PARAMETER, "SELECT ? AS value"] {
            assert!(
                !text.contains(forbidden),
                "native diagnostics disclosed tenant data"
            );
        }
    }
    assert!(String::from_utf8_lossy(&output.stdout).contains("tc1304_stdout_capture_control"));
    assert!(String::from_utf8_lossy(&output.stderr).contains("tc1304_stderr_capture_control"));
}

#[tokio::test]
async fn invocation_template_is_not_authority_to_execute_ddl_with_read_ability() {
    let directory = tempfile::tempdir().unwrap();
    let actor = spawn_actor(
        "policy".into(),
        "facts".into(),
        directory.path().to_str().unwrap().into(),
        u64::MAX,
        1,
        "128MB".into(),
        Arc::new(DashMap::new()),
    );
    let sql = "CREATE TABLE untrusted_template_created (value INTEGER)";
    let caveats = DuckDbCaveats {
        statements: Some(vec![PreparedStatement {
            name: "create".into(),
            sql: sql.into(),
        }]),
        ..Default::default()
    };
    actor
        .execute(
            DuckDbRequest::Execute {
                sql: sql.into(),
                params: vec![],
                schema: None,
            },
            Some(caveats),
            "tinycloud.duckdb/read".into(),
            false,
            false,
        )
        .await
        .expect_err("invocation facts cannot grant a stronger ability");
    let result = actor
        .execute(
            DuckDbRequest::Query {
                sql: "SELECT COUNT(*) FROM information_schema.tables WHERE table_name = 'untrusted_template_created'".into(),
                params: vec![],
            },
            None,
            "tinycloud.duckdb/read".into(),
            false,
            false,
        )
        .await
        .unwrap();
    let DuckDbResponse::Query(result) = result.response else {
        panic!("query response required");
    };
    assert_eq!(result.rows, vec![vec![DuckDbValue::Integer(0)]]);
}

fn assert_connection_policy(connection: &duckdb::Connection) {
    let settings: (bool, bool, bool, bool, Option<String>) = connection
        .query_row(
            "SELECT current_setting('enable_external_access'), \
             CAST(current_setting('enable_logging') AS BOOLEAN), current_setting('enable_http_logging'), \
             current_setting('lock_configuration'), current_setting('enable_profiling')",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
        )
        .unwrap();
    assert_eq!(settings, (false, false, false, true, None));
    assert!(connection
        .execute_batch("SET lock_configuration = false")
        .is_err());
    assert!(connection
        .execute_batch("SET enable_profiling = 'json'")
        .is_err());
    assert!(connection
        .execute_batch("SET enable_logging = true")
        .is_err());
}

#[test]
fn guarded_memory_file_and_promoted_connections_preserve_safe_data_and_definitions() {
    use tinycloud_core::duckdb::storage::{open_connection, promote_to_file};

    let directory = tempfile::tempdir().unwrap();
    let memory = open_connection(None, "128MB").unwrap();
    assert_connection_policy(&memory);
    memory
        .execute_batch(
            "CREATE TABLE safe_values (value INTEGER); INSERT INTO safe_values VALUES (41); \
             CREATE VIEW safe_view AS SELECT value + 1 AS value FROM safe_values;",
        )
        .unwrap();
    let path = directory.path().join("promoted.duckdb");
    let promoted = promote_to_file(&memory, &path, "128MB").unwrap();
    assert_connection_policy(&promoted);
    let value: i64 = promoted
        .query_row("SELECT value FROM safe_view", [], |row| row.get(0))
        .unwrap();
    assert_eq!(value, 42);
    promoted
        .execute_batch("CREATE MACRO safe_twice(x) AS x * 2")
        .unwrap();
    drop(promoted);

    let reopened = open_connection(Some(&path), "128MB").unwrap();
    assert_connection_policy(&reopened);
    let value: i64 = reopened
        .query_row("SELECT safe_twice(21)", [], |row| row.get(0))
        .unwrap();
    assert_eq!(value, 42);
}

#[test]
fn stored_code_is_audited_without_invocation_or_catalog_shadowing() {
    use tinycloud_core::duckdb::storage::open_connection;

    let definitions = [
        "CREATE VIEW hidden AS SELECT * FROM enable_logging(storage='stdout')",
        "CREATE MACRO hidden() AS write_log('tc1304_synthetic_bound_parameter_canary')",
        "CREATE MACRO hidden_sql(s) AS TABLE SELECT * FROM query(s)",
        "CREATE MACRO duckdb_views() AS TABLE SELECT * FROM enable_logging(storage='stdout')",
        "CREATE TABLE hidden (value VARCHAR DEFAULT write_log('tc1304_synthetic_bound_parameter_canary'))",
    ];
    for definition in definitions {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("untrusted.duckdb");
        // Author an untrusted snapshot, without executing any stored definition.
        let fixture = duckdb::Connection::open(&path).unwrap();
        fixture.execute_batch(definition).unwrap();
        drop(fixture);

        let error = open_connection(Some(&path), "128MB")
            .expect_err("stored code must pass the same structural policy as tenant statements");
        assert!(!error.to_string().contains(PARAMETER));
        assert!(!error.to_string().contains(definition));
    }
}

#[tokio::test]
async fn executing_explain_template_still_requires_the_wrapped_write_ability() {
    let directory = tempfile::tempdir().unwrap();
    let actor = spawn_actor(
        "policy".into(),
        "analyze".into(),
        directory.path().to_str().unwrap().into(),
        u64::MAX,
        1,
        "128MB".into(),
        Arc::new(DashMap::new()),
    );
    actor
        .execute(
            DuckDbRequest::Execute {
                sql: "INSERT INTO protected_values VALUES (1)".into(),
                params: vec![],
                schema: Some(vec!["CREATE TABLE protected_values (value INTEGER)".into()]),
            },
            None,
            "tinycloud.duckdb/admin".into(),
            false,
            false,
        )
        .await
        .unwrap();
    let sql = "EXPLAIN ANALYZE UPDATE protected_values SET value = 2";
    let caveats = DuckDbCaveats {
        statements: Some(vec![PreparedStatement {
            name: "analyze".into(),
            sql: sql.into(),
        }]),
        ..Default::default()
    };
    actor
        .execute(
            DuckDbRequest::Query {
                sql: sql.into(),
                params: vec![],
            },
            Some(caveats),
            "tinycloud.duckdb/read".into(),
            false,
            false,
        )
        .await
        .expect_err("executing wrappers must not convert a read ability into a write");
    let result = actor
        .execute(
            DuckDbRequest::Query {
                sql: "SELECT value FROM protected_values".into(),
                params: vec![],
            },
            None,
            "tinycloud.duckdb/read".into(),
            false,
            false,
        )
        .await
        .unwrap();
    let DuckDbResponse::Query(result) = result.response else {
        panic!("query response required");
    };
    assert_eq!(result.rows, vec![vec![DuckDbValue::Integer(1)]]);
    actor
        .execute(
            DuckDbRequest::Query {
                sql: sql.into(),
                params: vec![],
            },
            None,
            "tinycloud.duckdb/admin".into(),
            false,
            false,
        )
        .await
        .expect("authorized ANALYZE must preserve normal native execution");
    let result = actor
        .execute(
            DuckDbRequest::Query {
                sql: "SELECT value FROM protected_values".into(),
                params: vec![],
            },
            None,
            "tinycloud.duckdb/read".into(),
            false,
            false,
        )
        .await
        .unwrap();
    let DuckDbResponse::Query(result) = result.response else {
        panic!("query response required");
    };
    assert_eq!(result.rows, vec![vec![DuckDbValue::Integer(2)]]);
}
