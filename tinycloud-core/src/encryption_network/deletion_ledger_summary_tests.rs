//! The deletion ledger summary a node logs at start (TC-4177).

use super::deletion_ledger::{
    file_existed, summarize, DeletionLedger, Intent, LedgerFileState, LedgerKey, Record,
};

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

/// The sequence a node start follows: existence, open, summary.
fn summary_after_open(path: &std::path::Path) -> super::deletion_ledger::LedgerStartSummary {
    let existed = file_existed(path);
    let _ledger = DeletionLedger::open(path).unwrap();
    summarize(path, existed).unwrap()
}

#[test]
fn an_existing_empty_ledger_is_empty_with_no_newest_deletion() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("deletions.jsonl");
    std::fs::File::create(&path).unwrap();

    let summary = summary_after_open(&path);

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

#[test]
fn a_missing_ledger_is_reported_missing_not_empty() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("deletions.jsonl");
    assert!(!file_existed(&path));

    let summary = summary_after_open(&path);

    // The open created the file; without the answer taken before it, this
    // summary would be indistinguishable from the empty ledger above.
    assert!(path.exists());
    assert_eq!(summary.file, LedgerFileState::Missing);
    assert_eq!(summary.bytes, 0);
    assert_eq!(summary.operations, 0);
    assert_eq!(summary.newest_deleted_at, None);
    assert_eq!(
        summarize(&path, true).unwrap().file,
        LedgerFileState::Empty,
        "the same file, had it existed, is an empty ledger"
    );
}

#[test]
fn a_populated_ledger_counts_by_line_kind_with_the_newest_deletion_and_its_size() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("deletions.jsonl");
    {
        let ledger = DeletionLedger::open(&path).unwrap();
        // The newest is the latest instant (op1, 2026-11-24T04:30Z), not the
        // last line (op3) nor the greatest string (op2, 2026-11-23T22:30Z).
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

    let summary = summary_after_open(&path);

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
