//! The deletion ledger summary a node logs at start (TC-4177).

use super::deletion_ledger::{DeletionLedger, Intent, LedgerFileState, LedgerKey, Record};

const NETWORK: &str = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK:default";

fn intent(op: &str, keys: usize, deleted_at: &str) -> Record {
    Record::Intent(Intent {
        op: op.to_string(),
        network_id: NETWORK.to_string(),
        keys: (0..keys)
            .map(|index| LedgerKey {
                key_path: format!("apps/a/{op}/{index}"),
                key_version: 1,
            })
            .collect(),
        deleted_at: deleted_at.to_string(),
    })
}

#[test]
fn an_existing_empty_ledger_is_empty_with_no_newest_deletion() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("deletions.jsonl");
    std::fs::File::create(&path).unwrap();

    let ledger = DeletionLedger::open(&path).unwrap();
    let summary = ledger.start_summary().unwrap();

    assert!(!ledger.created());
    assert_eq!(summary.file, LedgerFileState::Empty);
    assert_eq!(summary.bytes, 0);
    assert_eq!(
        (
            summary.operations,
            summary.key_entries,
            summary.committed,
            summary.aborted
        ),
        (0, 0, 0, 0)
    );
    assert_eq!(summary.newest_deleted_at, None);
}

/// The open itself decides whether it created the file, under the lock and
/// before `open_ledger_file` creates it. A capture taken after that creation
/// answers `false` here, and the first assertion fails.
#[test]
fn a_missing_ledger_is_reported_missing_by_the_open_that_creates_it() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("deletions.jsonl");
    assert!(!path.exists());

    let ledger = DeletionLedger::open(&path).unwrap();
    assert!(
        ledger.created(),
        "open found no file and must say it created one"
    );
    let summary = ledger.start_summary().unwrap();
    assert_eq!(summary.file, LedgerFileState::Missing);
    assert_eq!(summary.bytes, 0);
    assert_eq!(summary.operations, 0);
    assert_eq!(summary.newest_deleted_at, None);
    drop(ledger);

    // The file is there now: the same content is an empty ledger, not a
    // missing one, for every later open (the node after a `purge-ledger
    // reconcile` that created it first).
    let again = DeletionLedger::open(&path).unwrap();
    assert!(!again.created());
    assert_eq!(again.start_summary().unwrap().file, LedgerFileState::Empty);
}

#[test]
fn a_populated_ledger_counts_by_line_kind_with_the_newest_deletion_and_its_size() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("deletions.jsonl");
    {
        let ledger = DeletionLedger::open(&path).unwrap();
        // The newest is the latest instant (op1, 2026-11-24T04:30Z), not the
        // last line (op3) nor the greatest string (op2, 2026-11-23T22:30Z).
        // Aborted intents count (op2).
        for record in [
            intent("op1", 2, "2026-11-23T23:30:00-05:00"),
            Record::committed("op1"),
            intent("op2", 1, "2026-11-24T00:30:00+02:00"),
            Record::aborted("op2"),
            intent("op3", 3, "2026-11-20T10:00:00Z"),
            Record::committed("op3"),
        ] {
            ledger.append(&record).unwrap();
        }
    }
    let size = std::fs::metadata(&path).unwrap().len();
    assert!(size > 0);

    let ledger = DeletionLedger::open(&path).unwrap();
    let summary = ledger.start_summary().unwrap();

    assert!(!ledger.created());
    assert_eq!(summary.file, LedgerFileState::Present);
    assert_eq!(summary.bytes, size);
    assert_eq!(summary.operations, 3);
    assert_eq!(summary.key_entries, 6);
    assert_eq!(summary.committed, 2);
    assert_eq!(summary.aborted, 1);
    assert_eq!(
        summary.newest_deleted_at.as_deref(),
        Some("2026-11-23T23:30:00-05:00")
    );
    assert!(!summary.torn_tail);
}

#[test]
fn an_aborted_intent_is_the_newest_deletion_when_it_is_the_latest() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("deletions.jsonl");
    let ledger = DeletionLedger::open(&path).unwrap();
    for record in [
        intent("old", 1, "2026-11-01T00:00:00Z"),
        Record::committed("old"),
        intent("late", 1, "2026-11-02T00:00:00Z"),
        Record::aborted("late"),
    ] {
        ledger.append(&record).unwrap();
    }

    let summary = ledger.start_summary().unwrap();

    assert_eq!(
        summary.newest_deleted_at.as_deref(),
        Some("2026-11-02T00:00:00Z")
    );
    assert_eq!((summary.committed, summary.aborted), (1, 1));
}
