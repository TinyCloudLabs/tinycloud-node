//! Deletion ledger: durable append, tail repair, settling and replay.

use std::path::Path;

use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ConnectOptions, Database, DatabaseConnection, EntityTrait,
};
use sea_orm_migration::MigratorTrait;

use super::deletion_ledger::{
    read, replay, validate_path, DeletionLedger, DeletionLedgerError, Intent, LedgerKey, Record,
    ReplayReport,
};
use crate::{migrations::Migrator, models::encryption_network_key};

const OWNER: &str = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";

fn network() -> String {
    super::NetworkId::new(OWNER.to_string(), "default".to_string())
        .unwrap()
        .to_string()
}

fn intent(op: &str, keys: &[(&str, i64)]) -> Intent {
    Intent {
        op: op.to_string(),
        network_id: network(),
        keys: keys
            .iter()
            .map(|(key_path, key_version)| LedgerKey {
                key_path: key_path.to_string(),
                key_version: *key_version,
            })
            .collect(),
        deleted_at: "2026-10-23T12:00:00Z".to_string(),
    }
}

fn ledger_in(dir: &tempfile::TempDir) -> (std::path::PathBuf, DeletionLedger) {
    let path = dir.path().join("ledger.jsonl");
    let ledger = DeletionLedger::open(&path).unwrap();
    (path, ledger)
}

async fn fresh_db() -> DatabaseConnection {
    let db = Database::connect(ConnectOptions::new("sqlite::memory:".to_string()))
        .await
        .unwrap();
    Migrator::up(&db, None).await.unwrap();
    db
}

async fn insert_key(
    db: &DatabaseConnection,
    path: &str,
    kind: &str,
    state: &str,
    seed: bool,
    version: i64,
) {
    encryption_network_key::ActiveModel {
        network_id: Set(network()),
        key_path: Set(path.to_string()),
        kind: Set(kind.to_string()),
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

async fn active_key(db: &DatabaseConnection, path: &str) {
    insert_key(db, path, "deletable", "active", true, 1).await;
}

async fn row(db: &DatabaseConnection, path: &str) -> encryption_network_key::Model {
    encryption_network_key::Entity::find_by_id((network(), path.to_string()))
        .one(db)
        .await
        .unwrap()
        .unwrap()
}

#[test]
fn an_operation_is_one_line_and_is_settled_by_a_later_line() {
    let dir = tempfile::tempdir().unwrap();
    let (path, ledger) = ledger_in(&dir);
    ledger
        .append(&Record::Intent(intent(
            "op-1",
            &[("apps/a/x", 1), ("apps/a/y", 3)],
        )))
        .unwrap();
    ledger.append(&Record::committed("op-1")).unwrap();
    ledger
        .append(&Record::Intent(intent("op-2", &[("apps/b/z", 1)])))
        .unwrap();
    ledger.append(&Record::aborted("op-2")).unwrap();
    drop(ledger);
    let ledger = DeletionLedger::open(&path).unwrap();
    ledger
        .append(&Record::Intent(intent("op-3", &[("apps/c/z", 1)])))
        .unwrap();

    let text = std::fs::read_to_string(&path).unwrap();
    assert_eq!(text.lines().count(), 5);
    assert!(text.ends_with('\n'));
    let first: serde_json::Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
    assert_eq!(
        first,
        serde_json::json!({
            "op": "op-1",
            "networkId": network(),
            "keys": [
                { "keyPath": "apps/a/x", "keyVersion": 1 },
                { "keyPath": "apps/a/y", "keyVersion": 3 },
            ],
            "deletedAt": "2026-10-23T12:00:00Z",
        })
    );
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines[1], r#"{"committed":"op-1"}"#);
    assert_eq!(lines[3], r#"{"aborted":"op-2"}"#);

    let contents = read(&path).unwrap();
    assert!(!contents.torn_tail);
    let open: Vec<&str> = contents
        .open_intents()
        .into_iter()
        .map(|i| i.op.as_str())
        .collect();
    assert_eq!(open, vec!["op-3"]);
}

#[cfg(unix)]
#[test]
fn the_ledger_file_is_forced_to_mode_0600() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.jsonl");
    DeletionLedger::open(&path).unwrap();
    let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&path), 0o600);

    // A file that exists with a wider mode is narrowed, not trusted.
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    DeletionLedger::open(&path).unwrap();
    assert_eq!(mode(&path), 0o600);
}

#[test]
fn an_unfinished_final_line_is_dropped_and_a_whole_one_is_kept() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.jsonl");
    let whole = serde_json::to_string(&Record::Intent(intent("op-1", &[("apps/a/x", 1)]))).unwrap();
    let partial = r#"{"op":"op-2","networkId":"did:key:z6Mk"#;
    std::fs::write(&path, format!("{whole}\n{partial}")).unwrap();

    let ledger = DeletionLedger::open(&path).unwrap();
    assert_eq!(ledger.dropped_tail_bytes(), partial.len());
    ledger.append(&Record::committed("op-1")).unwrap();
    let contents = read(&path).unwrap();
    assert_eq!(contents.records.len(), 2);
    assert!(!contents.torn_tail);

    // The same file with a whole last record that lacks only its newline.
    let path = dir.path().join("whole.jsonl");
    std::fs::write(&path, &whole).unwrap();
    let ledger = DeletionLedger::open(&path).unwrap();
    assert_eq!(ledger.dropped_tail_bytes(), 0);
    ledger.append(&Record::committed("op-1")).unwrap();
    assert_eq!(read(&path).unwrap().records.len(), 2);
}

#[test]
fn a_torn_final_line_is_reported_and_a_malformed_middle_line_is_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.jsonl");
    let whole = serde_json::to_string(&Record::Intent(intent("op-1", &[("apps/a/x", 1)]))).unwrap();

    std::fs::write(&path, format!("{whole}\n{{\"op\":\"op-2\",\"netw")).unwrap();
    let contents = read(&path).unwrap();
    assert!(contents.torn_tail);
    assert_eq!(contents.records.len(), 1);

    std::fs::write(&path, format!("{whole}\nnot json\n{whole}\n")).unwrap();
    assert!(matches!(
        read(&path),
        Err(DeletionLedgerError::Malformed(2))
    ));
}

#[test]
fn an_append_fails_closed_once_the_file_was_renamed_or_removed() {
    let dir = tempfile::tempdir().unwrap();
    let (path, ledger) = ledger_in(&dir);
    ledger.append(&Record::committed("before")).unwrap();

    let moved = dir.path().join("moved.jsonl");
    std::fs::rename(&path, &moved).unwrap();
    assert!(matches!(
        ledger.append(&Record::committed("after-rename")),
        Err(DeletionLedgerError::Moved)
    ));
    assert!(!path.exists(), "nothing was created at the old path");
    assert_eq!(read(&moved).unwrap().records.len(), 1);

    // A different file at the path is not the open one either.
    std::fs::write(&path, "").unwrap();
    assert!(matches!(
        ledger.append(&Record::committed("after-replace")),
        Err(DeletionLedgerError::Moved)
    ));
    std::fs::remove_file(&path).unwrap();
    assert!(matches!(
        ledger.append(&Record::committed("after-remove")),
        Err(DeletionLedgerError::Moved)
    ));
}

/// A write that stores `written` bytes of the line and then fails, as a full
/// disk does.
fn fails_after(written: usize) -> impl FnOnce(&mut std::fs::File, &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    move |file, line| {
        file.write_all(&line[..written.min(line.len())])?;
        Err(std::io::Error::other("no space left on device"))
    }
}

#[tokio::test]
async fn a_failed_append_leaves_no_partial_line_and_later_appends_replay() {
    let dir = tempfile::tempdir().unwrap();
    let (path, ledger) = ledger_in(&dir);
    let db = fresh_db().await;
    active_key(&db, "apps/a/x").await;
    active_key(&db, "apps/a/y").await;
    ledger
        .append(&Record::Intent(intent("first", &[("apps/a/x", 1)])))
        .unwrap();
    ledger.append(&Record::committed("first")).unwrap();
    let before = std::fs::read(&path).unwrap();

    // A failure after some bytes, after none, and after all but the newline.
    let mut second =
        serde_json::to_vec(&Record::Intent(intent("second", &[("apps/a/y", 1)]))).unwrap();
    second.push(b'\n');
    for written in [0, 10, second.len() - 1] {
        let result = ledger.append_line(&second, fails_after(written));
        assert!(
            matches!(result, Err(DeletionLedgerError::Io(_))),
            "{written}: {result:?}"
        );
        assert_eq!(std::fs::read(&path).unwrap(), before, "{written}");
    }

    // The next append lands on a whole line and the file reads and replays.
    ledger
        .append(&Record::Intent(intent("second", &[("apps/a/y", 1)])))
        .unwrap();
    ledger.append(&Record::committed("second")).unwrap();
    let read = read(&path).unwrap();
    assert!(!read.torn_tail);
    assert_eq!(read.records.len(), 4);
    let report = replay(&db, &path).await.unwrap();
    assert_eq!(report.applied, 2);
    assert_eq!(row(&db, "apps/a/x").await.state, "deleted");
    assert_eq!(row(&db, "apps/a/y").await.state, "deleted");
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

// ------------------------------------------------------------------ replay

#[tokio::test]
async fn replay_applies_committed_and_open_operations_and_skips_aborted_ones() {
    let db = fresh_db().await;
    for path in [
        "apps/a/committed",
        "apps/a/open",
        "apps/a/aborted",
        "apps/a/untouched",
    ] {
        active_key(&db, path).await;
    }
    let dir = tempfile::tempdir().unwrap();
    let (path, ledger) = ledger_in(&dir);
    ledger
        .append(&Record::Intent(intent("c", &[("apps/a/committed", 1)])))
        .unwrap();
    ledger.append(&Record::committed("c")).unwrap();
    ledger
        .append(&Record::Intent(intent("o", &[("apps/a/open", 1)])))
        .unwrap();
    ledger
        .append(&Record::Intent(intent("a", &[("apps/a/aborted", 1)])))
        .unwrap();
    ledger.append(&Record::aborted("a")).unwrap();

    let report = replay(&db, &path).await.unwrap();
    assert_eq!(
        report,
        ReplayReport {
            operations: 3,
            aborted_operations: 1,
            applied: 2,
            ..ReplayReport::default()
        }
    );
    for deleted in ["apps/a/committed", "apps/a/open"] {
        let row = row(&db, deleted).await;
        assert_eq!(row.state, "deleted", "{deleted}");
        assert_eq!(row.sealed_seed, None, "{deleted}");
    }
    for kept in ["apps/a/aborted", "apps/a/untouched"] {
        let row = row(&db, kept).await;
        assert_eq!(row.state, "active", "{kept}");
        assert!(row.sealed_seed.is_some(), "{kept}");
    }
}

#[tokio::test]
async fn replay_is_idempotent() {
    let db = fresh_db().await;
    active_key(&db, "apps/a/x").await;
    let dir = tempfile::tempdir().unwrap();
    let (path, ledger) = ledger_in(&dir);
    ledger
        .append(&Record::Intent(intent("op", &[("apps/a/x", 1)])))
        .unwrap();

    assert_eq!(replay(&db, &path).await.unwrap().applied, 1);
    let second = replay(&db, &path).await.unwrap();
    assert_eq!(second.applied, 0);
    assert_eq!(second.already_deleted, 1);
    assert_eq!(row(&db, "apps/a/x").await.sealed_seed, None);
}

#[tokio::test]
async fn a_torn_batch_applies_nothing() {
    let db = fresh_db().await;
    for path in ["apps/a/x", "apps/a/y", "apps/a/z"] {
        active_key(&db, path).await;
    }
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.jsonl");
    // One operation, cut off after its first key.
    let whole = serde_json::to_string(&Record::Intent(intent(
        "op",
        &[("apps/a/x", 1), ("apps/a/y", 1), ("apps/a/z", 1)],
    )))
    .unwrap();
    let cut = whole.find("apps/a/y").unwrap();
    std::fs::write(&path, &whole[..cut]).unwrap();

    let report = replay(&db, &path).await.unwrap();
    assert!(report.torn_tail);
    assert_eq!(report.applied, 0);
    for key in ["apps/a/x", "apps/a/y", "apps/a/z"] {
        assert_eq!(row(&db, key).await.state, "active", "{key}");
    }
}

#[tokio::test]
async fn replay_leaves_a_key_that_is_not_a_deletable_key() {
    let db = fresh_db().await;
    insert_key(&db, "docs/a", "deterministic", "active", false, 1).await;
    insert_key(&db, "apps/a/stray", "deterministic", "active", false, 1).await;
    active_key(&db, "apps/a/x").await;
    let dir = tempfile::tempdir().unwrap();
    let (path, ledger) = ledger_in(&dir);
    ledger
        .append(&Record::Intent(intent(
            "op",
            &[("docs/a", 1), ("apps/a/stray", 1), ("apps/a/x", 1)],
        )))
        .unwrap();

    let report = replay(&db, &path).await.unwrap();
    assert_eq!(report.not_deletable, 2);
    assert_eq!(report.applied, 1);
    assert_eq!(row(&db, "docs/a").await.state, "active");
    assert_eq!(row(&db, "apps/a/stray").await.state, "active");
}

#[tokio::test]
async fn replay_refuses_keys_and_networks_the_grammar_refuses() {
    let db = fresh_db().await;
    active_key(&db, "apps/a").await;
    active_key(&db, "apps/a/x").await;
    let dir = tempfile::tempdir().unwrap();
    let (path, ledger) = ledger_in(&dir);
    ledger
        .append(&Record::Intent(intent(
            "op",
            // `apps/a` is not a key (R1); the rest of the operation applies.
            &[("apps/a", 1), ("apps/A/x", 1), ("apps/a/x", 1)],
        )))
        .unwrap();
    let mut other = intent("op-network", &[("apps/a/x", 1)]);
    other.network_id = "not a network".to_string();
    ledger.append(&Record::Intent(other)).unwrap();

    let report = replay(&db, &path).await.unwrap();
    assert_eq!(report.refused, 3);
    assert_eq!(report.applied, 1);
    assert_eq!(row(&db, "apps/a").await.state, "active");
}

#[tokio::test]
async fn replay_leaves_a_newer_key_version_and_counts_missing_rows() {
    let db = fresh_db().await;
    // A key deleted at version 1, then created again as version 2.
    insert_key(&db, "apps/a/x", "deletable", "active", true, 2).await;
    let dir = tempfile::tempdir().unwrap();
    let (path, ledger) = ledger_in(&dir);
    ledger
        .append(&Record::Intent(intent(
            "v1",
            &[("apps/a/x", 1), ("apps/a/gone", 1)],
        )))
        .unwrap();

    let report = replay(&db, &path).await.unwrap();
    assert_eq!(report.newer_version, 1);
    assert_eq!(report.missing_row, 1);
    assert_eq!(report.applied, 0);
    let kept = row(&db, "apps/a/x").await;
    assert_eq!(kept.state, "active");
    assert!(kept.sealed_seed.is_some());

    // The operation for the version that row holds does apply.
    ledger
        .append(&Record::Intent(intent("v2", &[("apps/a/x", 2)])))
        .unwrap();
    assert_eq!(replay(&db, &path).await.unwrap().applied, 1);
    assert_eq!(row(&db, "apps/a/x").await.sealed_seed, None);
}

// ------------------------------------------------------------ replay at start

#[tokio::test]
async fn replay_at_start_applies_open_operations_and_closes_them() {
    let db = fresh_db().await;
    // `done` committed. `lost` is open and its key is still active: the
    // owner authorized the delete, so it is applied. `again` is open and its
    // key was created again afterwards (a later version). `aborted` did not
    // commit.
    insert_key(&db, "apps/a/done", "deletable", "deleted", false, 1).await;
    active_key(&db, "apps/a/lost").await;
    insert_key(&db, "apps/a/again", "deletable", "active", true, 2).await;
    active_key(&db, "apps/a/aborted").await;
    let dir = tempfile::tempdir().unwrap();
    let (path, ledger) = ledger_in(&dir);
    for (op, key) in [
        ("done", ("apps/a/done", 1)),
        ("lost", ("apps/a/lost", 1)),
        ("again", ("apps/a/again", 1)),
        ("aborted", ("apps/a/aborted", 1)),
    ] {
        ledger.append(&Record::Intent(intent(op, &[key]))).unwrap();
    }
    ledger.append(&Record::committed("done")).unwrap();
    ledger.append(&Record::aborted("aborted")).unwrap();

    let report = ledger.replay_at_start(&db).await.unwrap();
    assert_eq!(
        report,
        ReplayReport {
            operations: 4,
            aborted_operations: 1,
            applied: 1,
            already_deleted: 1,
            newer_version: 1,
            ..ReplayReport::default()
        }
    );
    assert_eq!(row(&db, "apps/a/lost").await.state, "deleted");
    assert_eq!(row(&db, "apps/a/lost").await.sealed_seed, None);
    assert_eq!(row(&db, "apps/a/again").await.state, "active");
    assert_eq!(row(&db, "apps/a/aborted").await.state, "active");
    // Every open operation is closed, as committed, and none stays open.
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(text.contains(r#"{"committed":"lost"}"#));
    assert!(text.contains(r#"{"committed":"again"}"#));
    assert!(read(&path).unwrap().open_intents().is_empty());

    // A second start has nothing left to apply.
    let second = ledger.replay_at_start(&db).await.unwrap();
    assert_eq!(second.applied, 0);
}

#[tokio::test]
async fn replay_at_start_fails_and_closes_nothing_when_the_ledger_holds_a_refused_key() {
    let db = fresh_db().await;
    active_key(&db, "apps/a/x").await;
    let dir = tempfile::tempdir().unwrap();
    let (path, ledger) = ledger_in(&dir);
    ledger
        .append(&Record::Intent(intent(
            "op",
            &[("apps/a", 1), ("apps/a/x", 1)],
        )))
        .unwrap();

    let Err(error) = ledger.replay_at_start(&db).await else {
        panic!("a ledger with a refused key fails the start");
    };
    assert!(
        matches!(error, DeletionLedgerError::Refused(1)),
        "{error:?}"
    );
    assert_eq!(error.kind(), "refused");
    assert_eq!(read(&path).unwrap().open_intents().len(), 1);
}

#[tokio::test]
async fn replay_at_start_fails_on_a_malformed_middle_line() {
    let db = fresh_db().await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.jsonl");
    let whole = serde_json::to_string(&Record::Intent(intent("op", &[("apps/a/x", 1)]))).unwrap();
    std::fs::write(&path, format!("{whole}\nnot json\n{whole}\n")).unwrap();
    let ledger = DeletionLedger::open(&path).unwrap();
    let Err(error) = ledger.replay_at_start(&db).await else {
        panic!("a malformed middle line fails the start");
    };
    assert_eq!(error.kind(), "malformed");
}

#[tokio::test]
async fn an_operation_committed_means_every_key_is_deleted_at_its_version_or_later() {
    use super::deletion_ledger::intent_committed;
    let db = fresh_db().await;
    insert_key(&db, "apps/a/deleted", "deletable", "deleted", false, 1).await;
    active_key(&db, "apps/a/active").await;
    // Deleted at version 1 and created again as version 2.
    insert_key(&db, "apps/a/again", "deletable", "active", true, 2).await;

    let committed = |keys: &[(&str, i64)]| {
        let intent = intent("op", keys);
        let db = db.clone();
        async move { intent_committed(&db, &intent).await.unwrap() }
    };
    assert!(committed(&[("apps/a/deleted", 1)]).await);
    assert!(committed(&[("apps/a/deleted", 1), ("apps/a/again", 1)]).await);
    assert!(!committed(&[("apps/a/active", 1)]).await);
    assert!(!committed(&[("apps/a/deleted", 1), ("apps/a/active", 1)]).await);
    assert!(!committed(&[("apps/a/missing", 1)]).await);
    // A key that is only deleted at an older version than the operation's.
    assert!(!committed(&[("apps/a/deleted", 2)]).await);
}
