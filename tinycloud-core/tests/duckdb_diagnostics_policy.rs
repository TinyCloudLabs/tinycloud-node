//! Exercise tenant policy against the real native service and process streams.
//! WITH-body writes also exercise the real service's touched-table persistence
//! consumer, including durable rehydration after authorized Query execution.
//! Restricted invocations fail closed on unsupported analysis shapes; these
//! controls do not claim HTTP delegation-chain caveat verification.
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

#[tokio::test]
async fn with_prefixed_writes_require_authority_and_persist_query_write_targets() {
    use tinycloud_auth::resource::SpaceId;
    use tinycloud_core::{
        database_artifacts::{DatabaseArtifactRepository, SeaOrmDatabaseArtifactRepository},
        duckdb::{service::DuckDbService, types::DuckDbError},
        migrations::Migrator,
        sea_orm::{ConnectOptions, Database},
        sea_orm_migration::MigratorTrait,
        write_hooks::TouchedTables,
    };

    async fn rows(service: &DuckDbService, space: &SpaceId, sql: &str) -> Vec<Vec<DuckDbValue>> {
        let result = service
            .execute(
                space,
                "nested",
                DuckDbRequest::Query {
                    sql: sql.into(),
                    params: vec![],
                },
                None,
                "tinycloud.duckdb/read".into(),
                false,
            )
            .await
            .unwrap();
        assert!(
            result.write_targets.is_empty(),
            "ordinary reads must not persist"
        );
        let DuckDbResponse::Query(result) = result.response else {
            panic!("query response required");
        };
        result.rows
    }

    fn statement(insert: bool, analyze: bool, id: i64, value: i64) -> String {
        let sql = if insert {
            format!(
                "WITH change AS (SELECT {id} AS id, {value} AS value) \
                 INSERT INTO policy_rows SELECT id, value FROM change"
            )
        } else {
            format!(
                "WITH change AS (SELECT {value} AS value) \
                 UPDATE policy_rows SET value = (SELECT value FROM change) WHERE id = 1"
            )
        };
        if analyze {
            format!("EXPLAIN ANALYZE {sql}")
        } else {
            sql
        }
    }

    let directory = tempfile::tempdir().unwrap();
    let database = Database::connect(ConnectOptions::new("sqlite::memory:".to_string()))
        .await
        .unwrap();
    Migrator::up(&database, None).await.unwrap();
    let repository = Arc::new(SeaOrmDatabaseArtifactRepository::new(database));
    let space = SpaceId::new(
        "did:pkh:eip155:1:0x6464646464646464646464646464646464646464"
            .parse()
            .unwrap(),
        "tc1304".parse().unwrap(),
    );
    let service = DuckDbService::new(
        directory.path().to_string_lossy().into_owned(),
        u64::MAX,
        300,
        "128MB".into(),
        repository.clone(),
    );
    for sql in [
        "CREATE TABLE policy_rows (id INTEGER, value INTEGER)",
        "INSERT INTO policy_rows VALUES (1, 7)",
    ] {
        service
            .execute(
                &space,
                "nested",
                DuckDbRequest::Execute {
                    sql: sql.into(),
                    params: vec![],
                    schema: None,
                },
                None,
                "tinycloud.duckdb/write".into(),
                false,
            )
            .await
            .unwrap();
    }
    let data_sql = "SELECT id, value FROM policy_rows ORDER BY id";
    let catalog_sql = "SELECT table_name, column_name, data_type FROM information_schema.columns \
                       WHERE table_schema = 'main' ORDER BY table_name, ordinal_position";
    let before_rows = rows(&service, &space, data_sql).await;
    let before_catalog = rows(&service, &space, catalog_sql).await;
    let before_artifact = repository
        .load("duckdb", &space.to_string(), "nested")
        .await
        .unwrap()
        .unwrap();
    let mut violations = Vec::new();
    for analyze in [false, true] {
        for insert in [false, true] {
            let sql = statement(insert, analyze, 2, 99);
            for (ability, read_only) in [
                ("tinycloud.duckdb/read", false),
                ("tinycloud.duckdb/write", true),
                ("tinycloud.duckdb/admin", true),
            ] {
                for mode in ["raw", "exact", "named"] {
                    let caveats = (read_only || mode != "raw").then(|| DuckDbCaveats {
                        read_only: read_only.then_some(true),
                        statements: (mode != "raw").then(|| {
                            vec![PreparedStatement {
                                name: "tenant".into(),
                                sql: sql.clone(),
                            }]
                        }),
                        ..Default::default()
                    });
                    // Query is intentional: EXPLAIN ANALYZE executes while
                    // returning a plan, so native execute() errors cannot
                    // masquerade as an authorization rejection.
                    let request = if mode == "named" {
                        DuckDbRequest::ExecuteStatement {
                            name: "tenant".into(),
                            params: vec![],
                        }
                    } else {
                        DuckDbRequest::Query {
                            sql: sql.clone(),
                            params: vec![],
                        }
                    };
                    let result = service
                        .execute(&space, "nested", request, caveats, ability.into(), false)
                        .await;
                    if !matches!(
                        &result,
                        Err(DuckDbError::PermissionDenied(_) | DuckDbError::ReadOnlyViolation)
                    ) {
                        violations.push(format!(
                            "{ability} readOnly={read_only} {mode} {sql}: {result:?}"
                        ));
                    }
                }
            }
        }
    }
    assert_eq!(rows(&service, &space, data_sql).await, before_rows);
    assert_eq!(rows(&service, &space, catalog_sql).await, before_catalog);
    let denied_artifact = repository
        .load("duckdb", &space.to_string(), "nested")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(denied_artifact.revision, before_artifact.revision);
    assert_eq!(denied_artifact.payload, before_artifact.payload);
    assert_eq!(denied_artifact.delta_payload, before_artifact.delta_payload);
    assert!(violations.is_empty(), "{}", violations.join("\n"));

    let mut expected = before_rows;
    let mut next_id = 2;
    let mut next_value = 10;
    for ability in ["tinycloud.duckdb/write", "tinycloud.duckdb/admin"] {
        for analyze in [false, true] {
            for insert in [false, true] {
                for mode in ["raw", "exact", "named"] {
                    // Named plans use the legacy execute response path; test
                    // executing plans through Query, not its native row error.
                    if analyze && mode == "named" {
                        continue;
                    }
                    let sql = statement(insert, analyze, next_id, next_value);
                    let caveats = (mode != "raw").then(|| DuckDbCaveats {
                        statements: Some(vec![PreparedStatement {
                            name: "tenant".into(),
                            sql: sql.clone(),
                        }]),
                        ..Default::default()
                    });
                    let request = if mode == "named" {
                        DuckDbRequest::ExecuteStatement {
                            name: "tenant".into(),
                            params: vec![],
                        }
                    } else {
                        DuckDbRequest::Query {
                            sql,
                            params: vec![],
                        }
                    };
                    let prior = repository
                        .load("duckdb", &space.to_string(), "nested")
                        .await
                        .unwrap()
                        .unwrap();
                    let result = service
                        .execute(&space, "nested", request, caveats, ability.into(), false)
                        .await
                        .unwrap();
                    assert_eq!(
                        result.write_targets,
                        vec![TouchedTables::supported(vec!["policy_rows".into()])],
                        "{ability} {mode} analyze={analyze} insert={insert}"
                    );
                    if mode != "named" {
                        let DuckDbResponse::Query(result) = result.response else {
                            panic!("query response required");
                        };
                        assert!(!result.columns.is_empty());
                        assert!(!result.rows.is_empty());
                        assert_eq!(result.row_count, result.rows.len());
                    }
                    if insert {
                        expected.push(vec![
                            DuckDbValue::Integer(next_id),
                            DuckDbValue::Integer(next_value),
                        ]);
                        next_id += 1;
                    } else {
                        expected[0][1] = DuckDbValue::Integer(next_value);
                    }
                    next_value += 1;
                    assert_eq!(rows(&service, &space, data_sql).await, expected);
                    let persisted = repository
                        .load("duckdb", &space.to_string(), "nested")
                        .await
                        .unwrap()
                        .unwrap();
                    assert!(
                        persisted.revision > prior.revision,
                        "Query-body writes must reach the persistence consumer"
                    );
                    // A fresh service/cache reads only durable state, not the
                    // writing actor's live connection or its local database.
                    let hydrated_directory = tempfile::tempdir().unwrap();
                    let hydrated = DuckDbService::new(
                        hydrated_directory.path().to_string_lossy().into_owned(),
                        u64::MAX,
                        300,
                        "128MB".into(),
                        repository.clone(),
                    );
                    assert_eq!(rows(&hydrated, &space, data_sql).await, expected);
                }
            }
        }
    }
    assert_eq!(rows(&service, &space, catalog_sql).await, before_catalog);
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

#[tokio::test]
async fn restricted_invocations_fail_closed_on_unsupported_sql_shapes_without_changing_data() {
    use tinycloud_auth::resource::SpaceId;
    use tinycloud_core::{
        database_artifacts::{DatabaseArtifactRepository, SeaOrmDatabaseArtifactRepository},
        duckdb::{
            service::DuckDbService,
            types::{DuckDbError, DuckDbExecutionResult},
        },
        migrations::Migrator,
        sea_orm::{ConnectOptions, Database},
        sea_orm_migration::MigratorTrait,
        write_hooks::TouchedTables,
    };

    async fn run(
        service: &DuckDbService,
        space: &SpaceId,
        sql: &str,
        caveats: Option<DuckDbCaveats>,
        ability: &str,
    ) -> DuckDbExecutionResult {
        service
            .execute(
                space,
                "restrictions",
                DuckDbRequest::Query {
                    sql: sql.into(),
                    params: vec![],
                },
                caveats,
                ability.into(),
                false,
            )
            .await
            .unwrap()
    }

    fn query_rows(result: DuckDbExecutionResult) -> Vec<Vec<DuckDbValue>> {
        let DuckDbResponse::Query(result) = result.response else {
            panic!("native Query response required");
        };
        assert_eq!(result.row_count, result.rows.len());
        result.rows
    }

    fn restrictions(scope: &str) -> DuckDbCaveats {
        DuckDbCaveats {
            tables: (scope != "columns").then(|| vec!["safe_rows".into(), "sink_rows".into()]),
            columns: (scope != "tables").then(|| vec!["id".into()]),
            ..Default::default()
        }
    }

    const READ: &str = "tinycloud.duckdb/read";
    const WRITE: &str = "tinycloud.duckdb/write";
    const ADMIN: &str = "tinycloud.duckdb/admin";
    const SECRET: &str = "tc1304_synthetic_excluded_service_value";
    let directory = tempfile::tempdir().unwrap();
    let database = Database::connect(ConnectOptions::new("sqlite::memory:".to_string()))
        .await
        .unwrap();
    Migrator::up(&database, None).await.unwrap();
    let repository = Arc::new(SeaOrmDatabaseArtifactRepository::new(database));
    let space = SpaceId::new(
        "did:pkh:eip155:1:0x6464646464646464646464646464646464646464"
            .parse()
            .unwrap(),
        "tc1304".parse().unwrap(),
    );
    let service = DuckDbService::new(
        directory.path().to_string_lossy().into_owned(),
        u64::MAX,
        300,
        "128MB".into(),
        repository.clone(),
    );
    for sql in [
        "CREATE TABLE safe_rows (id INTEGER, value TEXT)".to_string(),
        "CREATE TABLE private_rows (id INTEGER, secret TEXT)".into(),
        "CREATE TABLE sink_rows (id INTEGER, value TEXT)".into(),
        format!("INSERT INTO safe_rows VALUES (1, '{SECRET}')"),
        format!("INSERT INTO private_rows VALUES (1, '{SECRET}')"),
    ] {
        service
            .execute(
                &space,
                "restrictions",
                DuckDbRequest::Execute {
                    sql,
                    params: vec![],
                    schema: None,
                },
                None,
                WRITE.into(),
                false,
            )
            .await
            .unwrap();
    }
    for scope in ["tables", "columns", "both"] {
        assert_eq!(
            query_rows(
                run(
                    &service,
                    &space,
                    "SELECT id FROM safe_rows",
                    Some(restrictions(scope)),
                    READ,
                )
                .await
            ),
            vec![vec![DuckDbValue::Integer(1)]],
            "simple supported restricted SELECT must remain valid"
        );
        for sql in [
            "INSERT INTO sink_rows (id) VALUES (2)",
            "UPDATE sink_rows SET id = 3 WHERE id = 2",
            "DELETE FROM sink_rows WHERE id = 3",
        ] {
            run(&service, &space, sql, Some(restrictions(scope)), WRITE).await;
        }
        assert!(
            query_rows(run(&service, &space, "SELECT id FROM sink_rows", None, READ).await)
                .is_empty(),
            "supported restricted literal DML changed semantics"
        );
    }
    let snapshot_sql = "SELECT 'safe' AS source, id, value FROM safe_rows \
                        UNION ALL SELECT 'private', id, secret FROM private_rows \
                        UNION ALL SELECT 'sink', id, value FROM sink_rows ORDER BY source, id";
    let catalog_sql = "SELECT table_name, column_name, data_type FROM information_schema.columns \
                       WHERE table_schema = 'main' ORDER BY table_name, ordinal_position";
    let before_rows = query_rows(run(&service, &space, snapshot_sql, None, READ).await);
    let before_catalog = query_rows(run(&service, &space, catalog_sql, None, READ).await);
    let before_artifact = repository
        .load("duckdb", &space.to_string(), "restrictions")
        .await
        .unwrap()
        .unwrap();
    let cases = [
        (
            "derived SELECT",
            "SELECT id FROM (SELECT id FROM safe_rows) AS nested",
            false,
            false,
        ),
        (
            "scalar subquery",
            "SELECT (SELECT secret FROM private_rows WHERE id = 1) AS id",
            false,
            true,
        ),
        (
            "projection alias",
            "SELECT value AS id FROM safe_rows",
            false,
            true,
        ),
        (
            "table alias",
            "SELECT owned.id FROM safe_rows AS owned",
            false,
            false,
        ),
        (
            "INSERT SELECT",
            "INSERT INTO sink_rows SELECT id, secret FROM private_rows",
            true,
            false,
        ),
        (
            "CTE",
            "WITH owned AS (SELECT secret AS id FROM private_rows) SELECT id FROM owned",
            false,
            true,
        ),
    ];
    let mut violations = Vec::new();
    for scope in ["tables", "columns", "both"] {
        for (label, sql, writes, _) in cases {
            let abilities: &[&str] = if writes { &[WRITE, ADMIN] } else { &[READ] };
            for ability in abilities {
                for mode in ["raw", "exact", "named"] {
                    let mut caveats = restrictions(scope);
                    if mode != "raw" {
                        caveats.statements = Some(vec![PreparedStatement {
                            name: "tenant".into(),
                            sql: sql.into(),
                        }]);
                    }
                    let request = if mode == "named" {
                        DuckDbRequest::ExecuteStatement {
                            name: "tenant".into(),
                            params: vec![],
                        }
                    } else {
                        DuckDbRequest::Query {
                            sql: sql.into(),
                            params: vec![],
                        }
                    };
                    let result = service
                        .execute(
                            &space,
                            "restrictions",
                            request,
                            Some(caveats),
                            (*ability).into(),
                            false,
                        )
                        .await;
                    if !matches!(&result, Err(DuckDbError::PermissionDenied(_))) {
                        violations.push(format!("{scope} {label} {ability} {mode}: {result:?}"));
                    }
                    if let Ok(result) = result {
                        if let DuckDbResponse::Query(result) = result.response {
                            assert!(
                                !result
                                    .rows
                                    .iter()
                                    .flatten()
                                    .any(|value| value == &DuckDbValue::Text(SECRET.into())),
                                "excluded synthetic data returned by {scope} {label} {mode}"
                            );
                        }
                    }
                }
            }
        }
    }
    assert_eq!(
        query_rows(run(&service, &space, snapshot_sql, None, READ).await),
        before_rows,
        "denied shapes must not materialize excluded data"
    );
    assert_eq!(
        query_rows(run(&service, &space, catalog_sql, None, READ).await),
        before_catalog
    );
    let after_artifact = repository
        .load("duckdb", &space.to_string(), "restrictions")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(after_artifact.revision, before_artifact.revision);
    assert_eq!(after_artifact.payload, before_artifact.payload);
    assert_eq!(after_artifact.delta_payload, before_artifact.delta_payload);
    assert!(violations.is_empty(), "{}", violations.join("\n"));

    // These are restrictions on invocation-controlled facts, not a claim that
    // HTTP delegation-chain caveats were independently verified (TC-1307).
    // Without restrictions the same owned-data SQL and native results remain.
    for (label, sql, writes, returns_secret) in cases {
        let result = run(
            &service,
            &space,
            sql,
            None,
            if writes { WRITE } else { READ },
        )
        .await;
        if writes {
            assert_eq!(
                result.write_targets,
                vec![TouchedTables::supported(vec!["sink_rows".into()])]
            );
            assert_eq!(
                query_rows(
                    run(
                        &service,
                        &space,
                        "SELECT id, value FROM sink_rows",
                        None,
                        READ
                    )
                    .await
                ),
                vec![vec![
                    DuckDbValue::Integer(1),
                    DuckDbValue::Text(SECRET.into())
                ]],
                "unrestricted INSERT SELECT must preserve actual materialization"
            );
        } else {
            let expected = if returns_secret {
                DuckDbValue::Text(SECRET.into())
            } else {
                DuckDbValue::Integer(1)
            };
            assert_eq!(query_rows(result), vec![vec![expected]], "{label}");
        }
    }
}
