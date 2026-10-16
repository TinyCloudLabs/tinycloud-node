//! Offline identity tooling uses the same native admission policy as the node.
//! All fixtures are synthetic; the child and real CLI streams are captured whole.
#![cfg(feature = "duckdb")]

use std::{
    fs::File,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    sync::Arc,
};

use sha2::{Digest, Sha256};
use tinycloud_auth::resource::SpaceId;
use tinycloud_core::{
    database_artifacts::{
        ArtifactExpectation, DatabaseArtifactRepository, SeaOrmDatabaseArtifactRepository,
    },
    database_migration::{self as migration, ArtifactFingerprint, InventoryItem, TableFingerprint},
    duckdb::{
        storage::{copy_tables, open_connection, open_offline_connection},
        DuckDbService,
    },
    migrations::Migrator,
    sea_orm::{Database, DatabaseConnection},
    sea_orm_migration::MigratorTrait,
};

const CHILD: &str = "TC1304_OFFLINE_POLICY_CHILD";
const VALUE: &str = "tc1304_offline_synthetic_value_canary";
const DIAGNOSTIC: &str = "tc1304_offline_synthetic_diagnostic_canary";
const FILE_CANARY: &str = "tc1304_offline_synthetic_file_canary";
const UNSAFE_FIXTURE_COUNT: usize = 10;

#[test]
fn offline_opener_disables_diagnostics_and_locks_configuration() {
    let root = tempfile::tempdir().unwrap();
    let connection = open_offline_connection(&root.path().join("offline.duckdb")).unwrap();
    let settings: (bool, bool, bool, bool, Option<String>) = connection
        .query_row(
            "SELECT current_setting('enable_external_access'), \
             CAST(current_setting('enable_logging') AS BOOLEAN), \
             current_setting('enable_http_logging'), current_setting('lock_configuration'), \
             current_setting('enable_profiling')",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .unwrap();
    assert_eq!(settings, (false, false, false, true, None));
    for sql in [
        "SET lock_configuration = false",
        "SET enable_external_access = true",
        "SET enable_profiling = 'json'",
        "SET enable_logging = true",
    ] {
        assert!(connection.execute_batch(sql).is_err());
    }
}

#[test]
fn safe_default_generated_and_check_expressions_survive_guarded_reopen() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("safe_expressions.duckdb");
    let connection = open_connection(Some(&path), "128MB").unwrap();
    connection
        .execute_batch(
            "CREATE TABLE safe_expressions(\
                 source INTEGER DEFAULT 7,\
                 generated INTEGER GENERATED ALWAYS AS (source + 1),\
                 CHECK (source > 0));\
             INSERT INTO safe_expressions(source) VALUES (DEFAULT);",
        )
        .unwrap();
    drop(connection);
    let connection = open_offline_connection(&path).unwrap();
    let values: (i32, i32) = connection
        .query_row(
            "SELECT source, generated FROM safe_expressions",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(values, (7, 8));
    assert!(connection
        .execute_batch("INSERT INTO safe_expressions(source) VALUES (-1)")
        .is_err());
}

#[test]
fn fixed_size_array_defaults_survive_guarded_reopen() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("array_default.duckdb");
    let connection = open_connection(Some(&path), "128MB").unwrap();
    connection
        .execute_batch(
            "CREATE TABLE safe_array_defaults(v INTEGER[3] DEFAULT CAST([1,2,3] AS INTEGER[3]));\
             INSERT INTO safe_array_defaults VALUES (DEFAULT);",
        )
        .unwrap();
    drop(connection);
    let connection = open_offline_connection(&path).expect(
        "native array casts in defaults must be audited without rejecting harmless type syntax",
    );
    let value: String = connection
        .query_row(
            "SELECT CAST(v AS VARCHAR) FROM safe_array_defaults",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(value, "[1, 2, 3]");
}

#[test]
fn fixed_size_arrays_survive_guarded_reopen_and_copy() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("safe_arrays.duckdb");
    let source = open_connection(Some(&path), "128MB").unwrap();
    source
        .execute_batch(
            "CREATE TABLE safe_arrays(v INTEGER[3]); INSERT INTO safe_arrays VALUES ([1,2,3]);",
        )
        .unwrap();
    drop(source);

    let source = open_connection(Some(&path), "128MB")
        .expect("native fixed-size array type syntax is not executable diagnostic code");
    let value: String = source
        .query_row("SELECT CAST(v AS VARCHAR) FROM safe_arrays", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(value, "[1, 2, 3]");
    let imported_path = root.path().join("imported.duckdb");
    let imported = open_connection(Some(&imported_path), "128MB").unwrap();
    copy_tables(&source, &imported).expect("copy must preserve safe native array DDL");
    drop(imported);
    let imported = open_connection(Some(&imported_path), "128MB").unwrap();
    let value: String = imported
        .query_row("SELECT CAST(v AS VARCHAR) FROM safe_arrays", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(value, "[1, 2, 3]");
    drop(imported);
    drop(source);
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let repository = Arc::new(SeaOrmDatabaseArtifactRepository::new(
                metadata(&root.path().join("metadata")).await,
            ));
            let cache = root.path().join("service-import");
            let service = DuckDbService::new(
                cache.to_string_lossy().into_owned(),
                u64::MAX,
                300,
                "128MB".into(),
                repository,
            );
            let space = SpaceId::new(
                "did:pkh:eip155:1:0x1111111111111111111111111111111111111111"
                    .parse()
                    .unwrap(),
                "arrays".parse().unwrap(),
            );
            service
                .import_db(&space, "arrays", &std::fs::read(&path).unwrap())
                .await
                .expect("the real service import must admit safe fixed-size array tables");
            let imported = open_connection(
                Some(&cache.join(space.to_string()).join("arrays.duckdb")),
                "128MB",
            )
            .unwrap();
            let value: String = imported
                .query_row("SELECT CAST(v AS VARCHAR) FROM safe_arrays", [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(value, "[1, 2, 3]");
        });
}

fn cli(root: &Path, datadir: &Path, args: &[&str], capture: &str) -> Output {
    let output = Command::new(env!("CARGO_BIN_EXE_tinycloud-sql-identity"))
        .env_clear()
        .env("HOME", root.join("home"))
        .env("TMPDIR", root.join("tmp"))
        .current_dir(root)
        .arg("--datadir")
        .arg(datadir)
        .args(args)
        .output()
        .unwrap();
    std::fs::write(
        root.join(format!("capture/{capture}.stdout")),
        &output.stdout,
    )
    .unwrap();
    std::fs::write(
        root.join(format!("capture/{capture}.stderr")),
        &output.stderr,
    )
    .unwrap();
    output
}

fn success(output: &Output) {
    assert!(
        output.status.success(),
        "CLI failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

async fn metadata(datadir: &Path) -> DatabaseConnection {
    std::fs::create_dir_all(datadir).unwrap();
    let connection = Database::connect(format!(
        "sqlite:{}?mode=rwc",
        datadir.join("caps.db").display()
    ))
    .await
    .unwrap();
    Migrator::up(&connection, None).await.unwrap();
    migration::set_fence(&connection, true).await.unwrap();
    connection
}

fn cache_path(datadir: &Path) -> PathBuf {
    let directory = datadir.join("duckdb/synthetic-space");
    std::fs::create_dir_all(&directory).unwrap();
    directory.join("default.duckdb")
}

fn expected_fingerprint() -> ArtifactFingerprint {
    let columns = vec![("v".to_string(), "VARCHAR".to_string(), "YES".to_string())];
    let table_hash = hex::encode(Sha256::digest(format!("{columns:?}").as_bytes()));
    let schema = serde_json::to_string(&vec![("main.safe_values", &table_hash)]).unwrap();
    ArtifactFingerprint {
        schema_hash: hex::encode(Sha256::digest(schema.as_bytes())),
        tables: vec![TableFingerprint {
            name: "main.safe_values".into(),
            schema_hash: table_hash,
            row_count: 2,
        }],
    }
}

async fn persist_snapshot(metadata: &DatabaseConnection, path: &Path) {
    SeaOrmDatabaseArtifactRepository::new(metadata.clone())
        .save(
            "duckdb",
            "synthetic-space",
            "default",
            std::fs::read(path).unwrap(),
            ArtifactExpectation::Any,
        )
        .await
        .unwrap();
}

async fn safe_controls(root: &Path) {
    let datadir = root.join("data/safe");
    let metadata = metadata(&datadir).await;
    let path = cache_path(&datadir);
    let fixture = open_connection(Some(&path), "128MB").unwrap();
    fixture
        .execute_batch(&format!(
            "CREATE TABLE safe_values(v VARCHAR); \
             INSERT INTO safe_values VALUES ('{VALUE}'), ('enable_logging is inert data'); \
             CREATE MACRO safe_twice(v) AS v * 2; \
             CREATE VIEW safe_view AS SELECT safe_twice(21) AS answer;"
        ))
        .unwrap();
    drop(fixture);

    let items = migration::offline_inventory(&metadata, &datadir)
        .await
        .unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].offline_fingerprint, Some(expected_fingerprint()));
    assert_eq!(migration::checkpoint_cache(&datadir).unwrap(), (0, 1));
    let output = cli(
        root,
        &datadir,
        &["offline-fingerprint", "--local-snapshot"],
        "safe-fingerprint",
    );
    success(&output);
    let items: Vec<InventoryItem> = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].offline_fingerprint, Some(expected_fingerprint()));
    let output = cli(root, &datadir, &["checkpoint"], "safe-checkpoint");
    success(&output);
    assert_eq!(
        String::from_utf8(output.stdout).unwrap().trim(),
        "checkpointed 0 SQL and 1 DuckDB caches"
    );

    let reopened = open_connection(Some(&path), "128MB").unwrap();
    let value: String = reopened
        .query_row("SELECT v FROM safe_values WHERE v = ?", [VALUE], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(value, VALUE);
    let answer: i32 = reopened
        .query_row("SELECT answer FROM safe_view", [], |row| row.get(0))
        .unwrap();
    assert_eq!(answer, 42);
    drop(reopened);
    persist_snapshot(&metadata, &path).await;
    std::fs::remove_file(&path).unwrap();
    let items = migration::offline_inventory(&metadata, &datadir)
        .await
        .unwrap();
    assert_eq!(items.len(), 1);
    assert!(items[0].durable);
    assert!(!items[0].cached);
    assert_eq!(items[0].offline_fingerprint, Some(expected_fingerprint()));
    let output = cli(
        root,
        &datadir,
        &["offline-fingerprint", "--local-snapshot"],
        "safe-durable-fingerprint",
    );
    success(&output);
    let items: Vec<InventoryItem> = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(items[0].offline_fingerprint, Some(expected_fingerprint()));
}

async fn unsafe_controls(root: &Path) {
    let sink = root.join(format!("diagnostics/{FILE_CANARY}.json"));
    let sink = sink.to_string_lossy().replace('\'', "''");
    let definitions = [
        format!("CREATE VIEW hidden AS SELECT write_log('{DIAGNOSTIC}') AS value"),
        format!("CREATE MACRO hidden() AS write_log('{DIAGNOSTIC}')"),
        "CREATE MACRO hidden() AS TABLE SELECT * FROM enable_logging(storage='stdout')".into(),
        "CREATE MACRO hidden() AS TABLE SELECT * FROM enable_logging(storage='stderr')".into(),
        format!("CREATE MACRO hidden() AS TABLE SELECT * FROM query('SELECT ''{sink}''')"),
        format!("CREATE TABLE hidden(v VARCHAR DEFAULT write_log('{DIAGNOSTIC}'))"),
        format!("CREATE TABLE hidden(base INTEGER, generated VARCHAR GENERATED ALWAYS AS (write_log('{DIAGNOSTIC}')))"),
        format!("CREATE TABLE hidden(v INTEGER, CHECK(write_log('{DIAGNOSTIC}') IS NULL))"),
        format!("CREATE TABLE hidden(v INTEGER[3] DEFAULT CAST([CASE WHEN write_log('{DIAGNOSTIC}') IS NULL THEN 1 ELSE 0 END, 2, 3] AS INTEGER[3]))"),
        "CREATE MACRO duckdb_views() AS TABLE SELECT * FROM enable_logging(storage='stdout')".into(),
    ];
    for (index, definition) in definitions.iter().enumerate() {
        let datadir = root.join(format!("data/unsafe-{index}"));
        let metadata = metadata(&datadir).await;
        let path = cache_path(&datadir);
        // Author definitions only, never invoke them. Direct native execution is
        // deliberately used to model a persisted untrusted snapshot.
        let fixture = open_connection(Some(&path), "128MB").unwrap();
        fixture.execute_batch(definition).unwrap();
        let destination = open_connection(None, "128MB").unwrap();
        let error = copy_tables(&fixture, &destination).unwrap_err();
        assert!(matches!(
            error,
            tinycloud_core::duckdb::types::DuckDbError::PermissionDenied(_)
        ));
        let copied: i64 = destination
            .query_row(
                "SELECT count(*) FROM system.main.duckdb_tables() WHERE NOT internal",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(copied, 0, "source audit must finish before copying any DDL");
        drop(fixture);
        let error = migration::offline_inventory(&metadata, &datadir)
            .await
            .unwrap_err();
        assert!(!error.to_string().contains(definition));
        let error = migration::checkpoint_cache(&datadir).unwrap_err();
        assert!(!error.to_string().contains(definition));
        for (command, args) in [
            (
                "fingerprint",
                vec!["offline-fingerprint", "--local-snapshot"],
            ),
            ("checkpoint", vec!["checkpoint"]),
        ] {
            let output = cli(root, &datadir, &args, &format!("unsafe-{index}-{command}"));
            assert!(
                !output.status.success(),
                "unsafe stored definition was admitted"
            );
        }
        persist_snapshot(&metadata, &path).await;
        std::fs::remove_file(&path).unwrap();
        migration::offline_inventory(&metadata, &datadir)
            .await
            .expect_err("unsafe durable snapshot must be rejected");
        let output = cli(
            root,
            &datadir,
            &["offline-fingerprint", "--local-snapshot"],
            &format!("unsafe-{index}-durable-fingerprint"),
        );
        assert!(!output.status.success());
    }
}

fn scan_owned_files(directory: &Path, database_files: &[PathBuf]) {
    for entry in std::fs::read_dir(directory).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        let kind = entry.file_type().unwrap();
        if kind.is_dir() {
            scan_owned_files(&path, database_files);
        } else if kind.is_file() {
            // Only exact synthetic database/WAL paths may contain persisted
            // rows/definitions. Do not exclude the entire data or temp tree.
            if database_files.contains(&path) {
                continue;
            }
            let filename = entry.file_name();
            let filename = filename.to_str().unwrap();
            let bytes = std::fs::read(&path).unwrap();
            for canary in [VALUE, DIAGNOSTIC, FILE_CANARY] {
                assert!(
                    !bytes
                        .windows(canary.len())
                        .any(|window| window == canary.as_bytes()),
                    "canary escaped to {}",
                    path.display()
                );
                assert!(!filename.contains(canary), "diagnostic filename escaped");
            }
        }
    }
}

#[test]
fn offline_functions_and_cli_preserve_safe_results_without_diagnostic_escape() {
    if let Some(root) = std::env::var_os(CHILD) {
        let root = PathBuf::from(root);
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                safe_controls(&root).await;
                unsafe_controls(&root).await;
            });
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    for name in ["home", "tmp", "capture", "diagnostics", "data"] {
        std::fs::create_dir_all(root.join(name)).unwrap();
    }
    let mut database_files = Vec::new();
    for name in std::iter::once("safe".to_string())
        .chain((0..UNSAFE_FIXTURE_COUNT).map(|index| format!("unsafe-{index}")))
    {
        let datadir = root.join("data").join(name);
        for relative in [
            "caps.db",
            "caps.db-wal",
            "caps.db-shm",
            "duckdb/synthetic-space/default.duckdb",
            "duckdb/synthetic-space/default.duckdb.wal",
        ] {
            database_files.push(datadir.join(relative));
        }
    }
    let stdout = File::create(root.join("capture/functions.stdout")).unwrap();
    let stderr = File::create(root.join("capture/functions.stderr")).unwrap();
    let status = Command::new(std::env::current_exe().unwrap())
        .env_clear()
        .env(CHILD, root)
        .env("HOME", root.join("home"))
        .env("TMPDIR", root.join("tmp"))
        .current_dir(root)
        .args([
            "--exact",
            "offline_functions_and_cli_preserve_safe_results_without_diagnostic_escape",
            "--nocapture",
        ])
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .status()
        .unwrap();
    // Scan full unfiltered OS captures even if the child failed. Also scan all
    // non-database files, including native defaults in fresh HOME/TMPDIR/cwd.
    scan_owned_files(root, &database_files);
    assert!(!root
        .join(format!("diagnostics/{FILE_CANARY}.json"))
        .exists());
    let stdout = std::fs::read_to_string(root.join("capture/functions.stdout")).unwrap();
    let stderr = std::fs::read_to_string(root.join("capture/functions.stderr")).unwrap();
    assert!(
        status.success(),
        "offline child failed: stdout={stdout} stderr={stderr}"
    );
    assert!(
        stdout.contains("test result: ok"),
        "native child stdout capture must be connected"
    );
}
