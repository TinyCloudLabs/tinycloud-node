use std::{path::Path, process::Command};

use tinycloud_auth::{resolver::DID_METHODS, resource::SpaceId, ssi::jwk::JWK};
use tinycloud_core::{
    migrations::Migrator,
    models::database_artifact,
    sea_orm::{ActiveModelTrait, ActiveValue::Set, Database},
    sea_orm_migration::MigratorTrait,
};

fn run(datadir: &Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_tinycloud-sql-identity"))
        .arg("--datadir")
        .arg(datadir)
        .args(args)
        .output()
        .unwrap()
}

fn success(output: &std::process::Output) {
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[tokio::test]
async fn cli_fence_dry_run_apply_set_verify_clear() {
    let root = tempfile::tempdir().unwrap();
    let db_path = root.path().join("caps.db");
    let conn = Database::connect(format!("sqlite:{}?mode=rwc", db_path.display()))
        .await
        .unwrap();
    // A production snapshot predates N3's alias and fence migrations.
    let pre_n3_steps = (Migrator::migrations().len() - 2) as u32;
    Migrator::up(&conn, Some(pre_n3_steps)).await.unwrap();
    let jwk = JWK::generate_ed25519().unwrap();
    let did = DID_METHODS.generate(&jwk, "key").unwrap();
    let space = SpaceId::new(did, "cli".parse().unwrap()).to_string();
    let physical = root.path().join("legacy.db");
    let sqlite = rusqlite::Connection::open(&physical).unwrap();
    sqlite
        .execute_batch("CREATE TABLE t (v TEXT); INSERT INTO t VALUES ('existing-web-row');")
        .unwrap();
    drop(sqlite);
    database_artifact::ActiveModel {
        service: Set("sql".into()),
        space: Set(space.clone()),
        name: Set("threads".into()),
        revision: Set(1),
        content_hash: Set("fixture".into()),
        payload: Set(std::fs::read(physical).unwrap()),
        size_bytes: Set(8192),
        backend: Set("sqlite".into()),
        storage_mode: Set("database-blob".into()),
        created_at: Set("2026-01-01T00:00:00Z".into()),
        updated_at: Set("2026-01-01T00:00:00Z".into()),
        checkpoint_size_bytes: Set(8192),
        checkpoint_content_hash: Set("fixture".into()),
        delta_payload: Set(None),
        delta_content_hash: Set(None),
        delta_size_bytes: Set(0),
    }
    .insert(&conn)
    .await
    .unwrap();
    drop(conn);

    success(&run(root.path(), &["check-migrations"]));
    let ledger = rusqlite::Connection::open(&db_path).unwrap();
    ledger
        .execute(
            "INSERT INTO seaql_migrations (version, applied_at) VALUES ('m20990101_unknown_hotfix', 1)",
            [],
        )
        .unwrap();
    let missing = run(root.path(), &["check-migrations"]);
    assert!(!missing.status.success());
    assert!(String::from_utf8_lossy(&missing.stderr).contains("m20990101_unknown_hotfix"));
    ledger
        .execute(
            "DELETE FROM seaql_migrations WHERE version = 'm20990101_unknown_hotfix'",
            [],
        )
        .unwrap();
    drop(ledger);

    let dry_run = run(root.path(), &["dry-run"]);
    success(&dry_run);
    let report = run(root.path(), &["report"]);
    success(&report);
    let report_json: serde_json::Value = serde_json::from_slice(&report.stdout).unwrap();
    assert_eq!(report_json["inventory"].as_array().unwrap().len(), 1);
    assert!(report_json["aliases"].as_array().unwrap().is_empty());
    let inventory: serde_json::Value = serde_json::from_slice(&dry_run.stdout).unwrap();
    assert_eq!(inventory[0]["metadata"]["revision"], 1);
    assert!(inventory[0].get("offline_fingerprint").is_none());
    assert!(!run(root.path(), &["offline-fingerprint"]).status.success());
    let remote = run(
        root.path(),
        &[
            "--database",
            "postgres://example.invalid/tinycloud",
            "offline-fingerprint",
            "--local-snapshot",
        ],
    );
    assert!(!remote.status.success());
    assert!(String::from_utf8_lossy(&remote.stderr).contains("local database URL"));
    let remote_override = run(
        root.path(),
        &[
            "--database",
            "postgres://localhost/tinycloud?host=example.invalid",
            "offline-fingerprint",
            "--local-snapshot",
        ],
    );
    assert!(!remote_override.status.success());
    assert!(String::from_utf8_lossy(&remote_override.stderr).contains("local database URL"));
    let offline = run(root.path(), &["offline-fingerprint", "--local-snapshot"]);
    success(&offline);
    let offline_json: serde_json::Value = serde_json::from_slice(&offline.stdout).unwrap();
    assert_eq!(
        offline_json[0]["offline_fingerprint"]["tables"][0]["row_count"],
        1
    );
    let baseline = root.path().join("tc780-applied.json");
    let unfenced = run(root.path(), &["apply"]);
    assert!(!unfenced.status.success());
    success(&run(root.path(), &["fence", "on"]));
    let applied = run(root.path(), &["apply"]);
    success(&applied);
    std::fs::write(&baseline, &applied.stdout).unwrap();
    success(&run(
        root.path(),
        &[
            "set",
            "sql",
            &space,
            "threads",
            "--path",
            "web/threads",
            "--authorized",
        ],
    ));
    success(&run(
        root.path(),
        &["verify", "--baseline", baseline.to_str().unwrap()],
    ));
    let ledger = rusqlite::Connection::open(&db_path).unwrap();
    ledger
        .execute(
            "UPDATE database_artifact SET revision = 2 WHERE service = 'sql' AND name = 'threads'",
            [],
        )
        .unwrap();
    assert!(!run(
        root.path(),
        &["verify", "--baseline", baseline.to_str().unwrap()]
    )
    .status
    .success());
    ledger
        .execute(
            "UPDATE database_artifact SET revision = 1 WHERE service = 'sql' AND name = 'threads'",
            [],
        )
        .unwrap();
    drop(ledger);
    success(&run(
        root.path(),
        &["clear", "sql", &space, "--path", "web/threads"],
    ));
    success(&run(root.path(), &["fence", "off"]));
    assert!(!run(
        root.path(),
        &[
            "set",
            "sql",
            &space,
            "threads",
            "--path",
            "web/threads",
            "--authorized"
        ]
    )
    .status
    .success());
}
