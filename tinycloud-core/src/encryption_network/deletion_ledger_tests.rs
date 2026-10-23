//! Deletion ledger: durable append, tail repair, and replay onto a database.

use std::path::Path;

use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ConnectOptions, Database, DatabaseConnection, EntityTrait,
};
use sea_orm_migration::MigratorTrait;

use super::deletion_ledger::{
    read, replay, validate_path, DeletionLedger, LedgerEntry, ReplayReport,
};
use crate::{migrations::Migrator, models::encryption_network_key};

const NETWORK: &str = "did:key:z6MkOwner:default";

fn entry(path: &str, version: i64) -> LedgerEntry {
    LedgerEntry {
        network_id: NETWORK.to_string(),
        key_path: path.to_string(),
        key_version: version,
        deleted_at: "2026-10-23T12:00:00Z".to_string(),
    }
}

async fn fresh_db() -> DatabaseConnection {
    let db = Database::connect(ConnectOptions::new("sqlite::memory:".to_string()))
        .await
        .unwrap();
    Migrator::up(&db, None).await.unwrap();
    db
}

async fn insert_key(db: &DatabaseConnection, path: &str, state: &str, seed: bool, version: i64) {
    encryption_network_key::ActiveModel {
        network_id: Set(NETWORK.to_string()),
        key_path: Set(path.to_string()),
        kind: Set("deletable".to_string()),
        state: Set(state.to_string()),
        public_key: Set(vec![7; 32]),
        sealed_seed: Set(seed.then(|| vec![9; 60])),
        key_version: Set(version),
        created_at: Set("2026-10-22T00:00:00Z".to_string()),
        updated_at: Set("2026-10-22T00:00:00Z".to_string()),
    }
    .insert(db)
    .await
    .unwrap();
}

async fn row(db: &DatabaseConnection, path: &str) -> encryption_network_key::Model {
    encryption_network_key::Entity::find_by_id((NETWORK.to_string(), path.to_string()))
        .one(db)
        .await
        .unwrap()
        .unwrap()
}

#[test]
fn append_writes_one_json_line_per_entry_and_reopening_keeps_appending() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.jsonl");
    let ledger = DeletionLedger::open(&path).unwrap();
    ledger
        .append(&[entry("apps/a/x", 1), entry("apps/a/y", 3)])
        .unwrap();
    drop(ledger);
    let ledger = DeletionLedger::open(&path).unwrap();
    ledger.append(&[entry("apps/b/z", 1)]).unwrap();

    let text = std::fs::read_to_string(&path).unwrap();
    assert_eq!(text.lines().count(), 3);
    assert!(text.ends_with('\n'));
    let first: serde_json::Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
    assert_eq!(
        first,
        serde_json::json!({
            "networkId": NETWORK,
            "keyPath": "apps/a/x",
            "keyVersion": 1,
            "deletedAt": "2026-10-23T12:00:00Z",
        })
    );
    let contents = read(&path).unwrap();
    assert_eq!(
        contents.entries,
        vec![
            entry("apps/a/x", 1),
            entry("apps/a/y", 3),
            entry("apps/b/z", 1)
        ]
    );
    assert!(contents.malformed_lines.is_empty());
}

#[cfg(unix)]
#[test]
fn the_ledger_file_is_private_to_the_node_user() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.jsonl");
    DeletionLedger::open(&path).unwrap();
    let mode = std::fs::metadata(&path).unwrap().permissions().mode();
    assert_eq!(mode & 0o077, 0, "mode {mode:o}");
}

#[test]
fn an_unterminated_last_line_is_closed_before_the_next_append() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.jsonl");
    let mut torn = serde_json::to_string(&entry("apps/a/x", 1)).unwrap();
    torn.push('\n');
    torn.push_str("{\"networkId\":\"did:key:z6MkOw");
    std::fs::write(&path, torn).unwrap();

    let ledger = DeletionLedger::open(&path).unwrap();
    ledger.append(&[entry("apps/b/y", 1)]).unwrap();

    let contents = read(&path).unwrap();
    assert_eq!(
        contents.entries,
        vec![entry("apps/a/x", 1), entry("apps/b/y", 1)]
    );
    assert_eq!(contents.malformed_lines, vec![2]);
}

#[test]
fn appending_nothing_writes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.jsonl");
    let ledger = DeletionLedger::open(&path).unwrap();
    ledger.append(&[]).unwrap();
    assert_eq!(std::fs::metadata(&path).unwrap().len(), 0);
}

#[test]
fn the_path_is_validated_without_touching_the_filesystem() {
    for ok in ["/var/lib/tinycloud/deletion-ledger.jsonl", "/a"] {
        assert!(validate_path(Path::new(ok)).is_ok(), "{ok}");
    }
    for bad in [
        "",
        "relative/ledger.jsonl",
        "ledger.jsonl",
        "/var/lib/tinycloud/",
        "/",
        "/var/lib/../ledger.jsonl",
    ] {
        assert!(validate_path(Path::new(bad)).is_err(), "{bad:?}");
    }
}

#[tokio::test]
async fn replay_sets_named_keys_deleted_with_no_seed() {
    let db = fresh_db().await;
    insert_key(&db, "apps/a/active", "active", true, 1).await;
    insert_key(&db, "apps/a/blocked", "blocked", true, 1).await;
    insert_key(&db, "apps/a/untouched", "active", true, 1).await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.jsonl");
    let ledger = DeletionLedger::open(&path).unwrap();
    ledger
        .append(&[entry("apps/a/active", 1), entry("apps/a/blocked", 1)])
        .unwrap();

    let report = replay(&db, &path).await.unwrap();
    assert_eq!(
        report,
        ReplayReport {
            entries: 2,
            applied: 2,
            ..ReplayReport::default()
        }
    );
    for deleted in ["apps/a/active", "apps/a/blocked"] {
        let row = row(&db, deleted).await;
        assert_eq!(row.state, "deleted");
        assert_eq!(row.sealed_seed, None);
    }
    let untouched = row(&db, "apps/a/untouched").await;
    assert_eq!(untouched.state, "active");
    assert!(untouched.sealed_seed.is_some());
}

#[tokio::test]
async fn replay_is_idempotent() {
    let db = fresh_db().await;
    insert_key(&db, "apps/a/x", "active", true, 1).await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.jsonl");
    DeletionLedger::open(&path)
        .unwrap()
        .append(&[entry("apps/a/x", 1)])
        .unwrap();

    assert_eq!(replay(&db, &path).await.unwrap().applied, 1);
    let second = replay(&db, &path).await.unwrap();
    assert_eq!(second.applied, 0);
    assert_eq!(second.already_deleted, 1);
    assert_eq!(row(&db, "apps/a/x").await.sealed_seed, None);
}

#[tokio::test]
async fn replay_leaves_a_newer_key_version_and_counts_missing_rows() {
    let db = fresh_db().await;
    // A key deleted at version 1, then created again as version 2.
    insert_key(&db, "apps/a/x", "active", true, 2).await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.jsonl");
    DeletionLedger::open(&path)
        .unwrap()
        .append(&[entry("apps/a/x", 1), entry("apps/a/gone", 1)])
        .unwrap();

    let report = replay(&db, &path).await.unwrap();
    assert_eq!(report.newer_version, 1);
    assert_eq!(report.missing_row, 1);
    assert_eq!(report.applied, 0);
    let kept = row(&db, "apps/a/x").await;
    assert_eq!(kept.state, "active");
    assert!(kept.sealed_seed.is_some());

    // The ledger entry for the version that row holds does apply.
    DeletionLedger::open(&path)
        .unwrap()
        .append(&[entry("apps/a/x", 2)])
        .unwrap();
    assert_eq!(replay(&db, &path).await.unwrap().applied, 1);
    assert_eq!(row(&db, "apps/a/x").await.sealed_seed, None);
}

#[tokio::test]
async fn replay_applies_valid_entries_and_reports_malformed_lines() {
    let db = fresh_db().await;
    insert_key(&db, "apps/a/x", "active", true, 1).await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.jsonl");
    let mut text = String::from("not json\n");
    text.push_str(&serde_json::to_string(&entry("apps/a/x", 1)).unwrap());
    text.push_str("\n{\"networkId\":\"x\"}\n");
    std::fs::write(&path, text).unwrap();

    let report = replay(&db, &path).await.unwrap();
    assert_eq!(report.applied, 1);
    assert_eq!(report.malformed_lines, vec![1, 3]);
    assert_eq!(row(&db, "apps/a/x").await.state, "deleted");
}
