//! Deletion ledger: durable append, tail repair, settling and replay.

use std::{collections::BTreeSet, path::Path};

use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ConnectOptions, Database, DatabaseConnection, EntityTrait,
};
use sea_orm_migration::MigratorTrait;

use super::deletion_ledger::{
    read, replay, validate_path, DeletionLedger, DeletionLedgerError, Intent, LedgerKey,
    PrunePoint, PruneReport, Record, ReplayReport,
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

/// The whole line is written and the write step then reports an error, as a
/// failed fsync does: the line is cut back too.
#[test]
fn a_whole_line_followed_by_an_error_is_cut_back() {
    use std::io::Write;
    let dir = tempfile::tempdir().unwrap();
    let (path, ledger) = ledger_in(&dir);
    ledger.append(&Record::committed("before")).unwrap();
    let before = std::fs::read(&path).unwrap();

    let mut line = serde_json::to_vec(&Record::committed("after")).unwrap();
    line.push(b'\n');
    let result = ledger.append_line(&line, |file, bytes| {
        file.write_all(bytes)?;
        Err(std::io::Error::other("fsync failed"))
    });
    assert!(
        matches!(result, Err(DeletionLedgerError::Io(_))),
        "{result:?}"
    );
    assert_eq!(std::fs::read(&path).unwrap(), before);

    ledger.append(&Record::committed("later")).unwrap();
    assert_eq!(read(&path).unwrap().records.len(), 2);
}

const SHORT: std::time::Duration = std::time::Duration::from_millis(20);

#[test]
fn a_second_open_waits_for_the_first_to_close() {
    let dir = tempfile::tempdir().unwrap();
    let (path, first) = ledger_in(&dir);
    first.append(&Record::committed("one")).unwrap();

    let closer = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(200));
        drop(first);
    });
    let started = std::time::Instant::now();
    let second =
        DeletionLedger::open_waiting(&path, SHORT, std::time::Duration::from_secs(30)).unwrap();
    assert!(started.elapsed() >= std::time::Duration::from_millis(100));
    closer.join().unwrap();
    // The second holds the lock now, and sees the first's line.
    second.append(&Record::committed("two")).unwrap();
    assert_eq!(read(&path).unwrap().records.len(), 2);
    let lock = std::path::PathBuf::from(format!("{}.lock", path.display()));
    assert!(matches!(
        DeletionLedger::open_waiting(&path, SHORT, SHORT),
        Err(DeletionLedgerError::LockHeld)
    ));
    drop(second);
    // The lock file stays after the ledger closes and is free again.
    assert!(lock.exists());
    DeletionLedger::open_waiting(&path, SHORT, SHORT).unwrap();
}

#[test]
fn a_second_open_fails_as_lock_held_and_leaves_the_file_as_it_was() {
    use std::io::Write;
    let dir = tempfile::tempdir().unwrap();
    let (path, first) = ledger_in(&dir);
    first.append(&Record::committed("one")).unwrap();
    // An unfinished final line, as a crash would leave.
    std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap()
        .write_all(b"{\"committed\":\"tw")
        .unwrap();
    let before = std::fs::read(&path).unwrap();

    let error = DeletionLedger::open_waiting(&path, SHORT, std::time::Duration::from_millis(100))
        .unwrap_err();
    assert!(matches!(error, DeletionLedgerError::LockHeld), "{error:?}");
    assert_eq!(error.kind(), "lock_held");
    // The refused open did not trim the partial line.
    assert_eq!(std::fs::read(&path).unwrap(), before);

    drop(first);
    let reopened = DeletionLedger::open(&path).unwrap();
    assert!(reopened.dropped_tail_bytes() > 0);
}

#[cfg(unix)]
#[test]
fn the_lock_file_is_forced_to_mode_0600() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let lock = dir.path().join("ledger.jsonl.lock");
    std::fs::write(&lock, "").unwrap();
    std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(0o644)).unwrap();
    let (_path, _ledger) = ledger_in(&dir);
    assert_eq!(
        std::fs::metadata(&lock).unwrap().permissions().mode() & 0o777,
        0o600
    );
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

// ------------------------------------------------------------------- prune

const OTHER_OWNER: &str = "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH";

fn owners(list: &[&str]) -> BTreeSet<String> {
    list.iter().map(|owner| owner.to_string()).collect()
}

/// An intent on the `default` network of `owner`.
fn intent_of(owner: &str, op: &str, keys: &[(&str, i64)]) -> Intent {
    Intent {
        network_id: super::NetworkId::new(owner.to_string(), "default".to_string())
            .unwrap()
            .to_string(),
        ..intent(op, keys)
    }
}

/// The ledger's lines, each with its newline.
fn lines_of(path: &Path) -> Vec<String> {
    std::fs::read_to_string(path)
        .unwrap()
        .split_inclusive('\n')
        .map(str::to_string)
        .collect()
}

fn prune_temp_of(path: &Path) -> std::path::PathBuf {
    std::path::PathBuf::from(format!("{}.prune.tmp", path.display()))
}

/// OWNER: a committed and an aborted operation. OTHER_OWNER: a committed one
/// and an open one. The two owners' lines interleave.
fn two_owner_ledger(ledger: &DeletionLedger) {
    for record in [
        Record::Intent(intent_of(OWNER, "a1", &[("apps/a/x", 1)])),
        Record::Intent(intent_of(
            OTHER_OWNER,
            "b1",
            &[("apps/b/x", 1), ("apps/b/y", 2)],
        )),
        Record::committed("a1"),
        Record::Intent(intent_of(OWNER, "a2", &[("apps/a/y", 1)])),
        Record::committed("b1"),
        Record::aborted("a2"),
        Record::Intent(intent_of(OTHER_OWNER, "b2", &[("apps/b/z", 1)])),
    ] {
        ledger.append(&record).unwrap();
    }
}

#[test]
fn prune_removes_the_settled_operations_of_the_given_owners_and_keeps_every_other_line() {
    let dir = tempfile::tempdir().unwrap();
    let (path, ledger) = ledger_in(&dir);
    two_owner_ledger(&ledger);
    let before = lines_of(&path);

    let report = ledger.prune_owners(&owners(&[OWNER])).unwrap();
    assert_eq!(
        report,
        PruneReport {
            pruned_operations: 2,
            pruned_lines: 4,
            skipped_open: 0,
            kept_lines: 3,
        }
    );
    // The other owner's lines, byte for byte and in their order.
    assert_eq!(
        lines_of(&path),
        vec![before[1].clone(), before[4].clone(), before[6].clone()]
    );
    assert!(!prune_temp_of(&path).exists());
    // The report holds counts only.
    assert_eq!(
        serde_json::to_value(&report).unwrap(),
        serde_json::json!({
            "prunedOperations": 2,
            "prunedLines": 4,
            "skippedOpen": 0,
            "keptLines": 3,
        })
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}

#[test]
fn prune_keeps_an_open_operation_until_it_is_settled() {
    let dir = tempfile::tempdir().unwrap();
    let (path, ledger) = ledger_in(&dir);
    ledger
        .append(&Record::Intent(intent_of(
            OWNER,
            "done",
            &[("apps/a/x", 1)],
        )))
        .unwrap();
    ledger.append(&Record::committed("done")).unwrap();
    ledger
        .append(&Record::Intent(intent_of(
            OWNER,
            "open",
            &[("apps/a/y", 1)],
        )))
        .unwrap();
    let open_line = lines_of(&path)[2].clone();

    let report = ledger.prune_owners(&owners(&[OWNER])).unwrap();
    assert_eq!(
        report,
        PruneReport {
            pruned_operations: 1,
            pruned_lines: 2,
            skipped_open: 1,
            kept_lines: 1,
        }
    );
    assert_eq!(lines_of(&path), vec![open_line]);

    // Once settled, it goes with its settling line.
    ledger.append(&Record::committed("open")).unwrap();
    let report = ledger.prune_owners(&owners(&[OWNER])).unwrap();
    assert_eq!(
        report,
        PruneReport {
            pruned_operations: 1,
            pruned_lines: 2,
            skipped_open: 0,
            kept_lines: 0,
        }
    );
    assert!(std::fs::read(&path).unwrap().is_empty());
}

#[test]
fn prune_is_idempotent_and_rewrites_nothing_when_nothing_matches() {
    let dir = tempfile::tempdir().unwrap();
    let (path, ledger) = ledger_in(&dir);
    two_owner_ledger(&ledger);
    assert_eq!(
        ledger
            .prune_owners(&owners(&[OWNER]))
            .unwrap()
            .pruned_operations,
        2
    );
    let after = std::fs::read(&path).unwrap();
    #[cfg(unix)]
    let inode = {
        use std::os::unix::fs::MetadataExt;
        || std::fs::metadata(&path).unwrap().ino()
    };
    #[cfg(unix)]
    let pruned_inode = inode();

    let unchanged = PruneReport {
        kept_lines: 3,
        ..PruneReport::default()
    };
    let lists: [&[&str]; 3] = [&[OWNER], &[], &["did:key:z6MkNoLinesInThisLedger"]];
    for list in lists {
        assert_eq!(
            ledger.prune_owners(&owners(list)).unwrap(),
            unchanged,
            "{list:?}"
        );
        assert_eq!(std::fs::read(&path).unwrap(), after, "{list:?}");
        #[cfg(unix)]
        assert_eq!(inode(), pruned_inode, "not rewritten: {list:?}");
    }
    // The open operation of the other owner is reported, never removed.
    assert_eq!(
        ledger
            .prune_owners(&owners(&[OTHER_OWNER]))
            .unwrap()
            .skipped_open,
        1
    );
    assert_eq!(read(&path).unwrap().open_intents().len(), 1);
}

#[tokio::test]
async fn an_append_after_a_prune_lands_in_the_new_file_and_the_ledger_replays() {
    let db = fresh_db().await;
    active_key(&db, "apps/a/x").await;
    active_key(&db, "apps/a/y").await;
    let dir = tempfile::tempdir().unwrap();
    let (path, ledger) = ledger_in(&dir);
    ledger
        .append(&Record::Intent(intent_of(
            OTHER_OWNER,
            "gone",
            &[("apps/b/x", 1)],
        )))
        .unwrap();
    ledger.append(&Record::committed("gone")).unwrap();
    ledger
        .append(&Record::Intent(intent("kept", &[("apps/a/x", 1)])))
        .unwrap();
    ledger.append(&Record::committed("kept")).unwrap();
    assert_eq!(
        ledger
            .prune_owners(&owners(&[OTHER_OWNER]))
            .unwrap()
            .pruned_lines,
        2
    );

    // The handle follows the new file.
    ledger
        .append(&Record::Intent(intent("later", &[("apps/a/y", 1)])))
        .unwrap();
    let contents = read(&path).unwrap();
    assert!(!contents.torn_tail);
    assert_eq!(contents.records.len(), 3);
    let open: Vec<&str> = contents
        .open_intents()
        .into_iter()
        .map(|intent| intent.op.as_str())
        .collect();
    assert_eq!(open, vec!["later"]);

    let report = ledger.replay_at_start(&db).await.unwrap();
    assert_eq!(report.operations, 2);
    assert_eq!(report.applied, 2);
    for key in ["apps/a/x", "apps/a/y"] {
        let row = row(&db, key).await;
        assert_eq!(row.state, "deleted", "{key}");
        assert_eq!(row.sealed_seed, None, "{key}");
    }
    assert!(read(&path).unwrap().open_intents().is_empty());

    // A reopen reads and appends to the same file.
    drop(ledger);
    let ledger = DeletionLedger::open(&path).unwrap();
    ledger.append(&Record::committed("after-reopen")).unwrap();
    assert_eq!(read(&path).unwrap().records.len(), 5);
}

fn crash_at(at: PrunePoint) -> impl FnMut(PrunePoint) -> std::io::Result<()> {
    move |point| {
        if point == at {
            Err(std::io::Error::other("the process stops here"))
        } else {
            Ok(())
        }
    }
}

#[test]
fn a_prune_stopped_before_its_rename_leaves_the_old_ledger_and_open_removes_the_temp_file() {
    let dir = tempfile::tempdir().unwrap();
    let (path, ledger) = ledger_in(&dir);
    two_owner_ledger(&ledger);
    let before = std::fs::read(&path).unwrap();
    let temp = prune_temp_of(&path);

    let result = ledger.prune_owners_at(&owners(&[OWNER]), crash_at(PrunePoint::TempWritten));
    assert!(
        matches!(result, Err(DeletionLedgerError::Io(_))),
        "{result:?}"
    );
    assert!(temp.exists());
    assert_eq!(std::fs::read(&path).unwrap(), before);
    drop(ledger);

    let ledger = DeletionLedger::open(&path).unwrap();
    assert!(!temp.exists());
    assert_eq!(std::fs::read(&path).unwrap(), before);
    drop(ledger);

    // A temporary file cut off while it was written goes the same way.
    std::fs::write(&temp, br#"{"op":"b1","netw"#).unwrap();
    let ledger = DeletionLedger::open(&path).unwrap();
    assert!(!temp.exists());
    assert_eq!(std::fs::read(&path).unwrap(), before);
    assert_eq!(
        ledger
            .prune_owners(&owners(&[OWNER]))
            .unwrap()
            .pruned_operations,
        2
    );
}

#[test]
fn a_prune_stopped_after_its_rename_leaves_the_new_ledger_whole() {
    let dir = tempfile::tempdir().unwrap();
    let (path, ledger) = ledger_in(&dir);
    two_owner_ledger(&ledger);
    let before = lines_of(&path);
    let pruned = vec![before[1].clone(), before[4].clone(), before[6].clone()];

    let result = ledger.prune_owners_at(&owners(&[OWNER]), crash_at(PrunePoint::Renamed));
    assert!(
        matches!(result, Err(DeletionLedgerError::Io(_))),
        "{result:?}"
    );
    assert_eq!(lines_of(&path), pruned);
    assert!(!prune_temp_of(&path).exists());
    // The handle still names the replaced file: an append fails rather than
    // land there.
    assert!(matches!(
        ledger.append(&Record::committed("late")),
        Err(DeletionLedgerError::Moved)
    ));
    drop(ledger);

    let ledger = DeletionLedger::open(&path).unwrap();
    assert_eq!(lines_of(&path), pruned);
    ledger.append(&Record::committed("late")).unwrap();
    assert_eq!(read(&path).unwrap().records.len(), 4);
}

#[test]
fn prune_refuses_a_file_it_cannot_read_whole_and_changes_nothing() {
    use std::io::Write;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.jsonl");
    let whole =
        serde_json::to_string(&Record::Intent(intent_of(OWNER, "op", &[("apps/a/x", 1)]))).unwrap();
    std::fs::write(
        &path,
        format!("{whole}\nnot json\n{}\n", r#"{"committed":"op"}"#),
    )
    .unwrap();
    let ledger = DeletionLedger::open(&path).unwrap();
    let before = std::fs::read(&path).unwrap();
    assert!(matches!(
        ledger.prune_owners(&owners(&[OWNER])),
        Err(DeletionLedgerError::Malformed(2))
    ));
    assert_eq!(std::fs::read(&path).unwrap(), before);
    assert!(!prune_temp_of(&path).exists());

    // A final line without its newline, as only a failed append that could
    // not be cut back leaves.
    let path = dir.path().join("unterminated.jsonl");
    let ledger = DeletionLedger::open(&path).unwrap();
    ledger
        .append(&Record::Intent(intent_of(OWNER, "op", &[("apps/a/x", 1)])))
        .unwrap();
    ledger.append(&Record::committed("op")).unwrap();
    std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap()
        .write_all(br#"{"committed":"o"#)
        .unwrap();
    let before = std::fs::read(&path).unwrap();
    assert!(matches!(
        ledger.prune_owners(&owners(&[OWNER])),
        Err(DeletionLedgerError::Malformed(3))
    ));
    assert_eq!(std::fs::read(&path).unwrap(), before);
}
