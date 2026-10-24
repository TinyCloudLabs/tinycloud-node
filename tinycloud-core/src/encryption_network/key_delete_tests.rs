//! The effect of a verified owner delete on key rows, the audit table and the
//! deletion ledger.

use std::{collections::BTreeSet, sync::Arc};

use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, ConnectOptions, Database, DatabaseConnection,
    EntityTrait, QueryFilter,
};
use sea_orm_migration::MigratorTrait;

use super::{
    backend::wrap_to_public_key,
    delete_auth::{DeleteTarget, VerifiedOwnerDelete},
    deletion_ledger::{self, DeletionLedger, Intent, LedgerKey, Record},
    key_delete::{audit_request_hash, DeleteOutcome},
    key_id::KeyLocation,
    network_id::NetworkId,
    service::{CreateNetworkRequest, EncryptionService, EncryptionServiceError},
    types::Threshold,
    LocalOneOfOneBackend,
};
use crate::{
    encryption::ColumnEncryption,
    migrations::Migrator,
    models::{encryption_audit, encryption_network_key},
    test_support::PostgresTestSchema,
};

const NODE_DID: &str = "did:key:z6MkNodeTest";
const OWNER: &str = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";

fn network() -> NetworkId {
    NetworkId::new(OWNER.to_string(), "default".to_string()).unwrap()
}

fn loc(path: &str) -> KeyLocation {
    KeyLocation::new(&network(), path).unwrap()
}

fn verified(cid: &str) -> VerifiedOwnerDelete {
    VerifiedOwnerDelete {
        owner: OWNER.to_string(),
        nonce: "nonce-0001".to_string(),
        exp: 0,
        auth_cid: cid.to_string(),
    }
}

fn prefix(id: &str) -> DeleteTarget {
    DeleteTarget::parse(&network(), &format!("apps/{id}/")).unwrap()
}

fn key(path: &str) -> DeleteTarget {
    DeleteTarget::parse(&network(), path).unwrap()
}

struct Fixture {
    db: DatabaseConnection,
    service: EncryptionService,
    ledger_path: std::path::PathBuf,
    _dir: tempfile::TempDir,
}

fn service_over(db: DatabaseConnection, ledger: Option<Arc<DeletionLedger>>) -> EncryptionService {
    let backend = Arc::new(LocalOneOfOneBackend::new(ColumnEncryption::new(
        [0xABu8; 32],
    )));
    EncryptionService::new(db, NODE_DID.to_string(), backend).with_deletion_ledger(ledger)
}

async fn create_network(service: &EncryptionService) {
    service
        .create_one_of_one_network(CreateNetworkRequest {
            name: "default".to_string(),
            owner_did: OWNER.to_string(),
            threshold: Threshold::one_of_one(),
        })
        .await
        .unwrap();
}

async fn fixture() -> Fixture {
    let db = Database::connect(ConnectOptions::new("sqlite::memory:".to_string()))
        .await
        .unwrap();
    Migrator::up(&db, None).await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let ledger_path = dir.path().join("ledger.jsonl");
    let ledger = Arc::new(DeletionLedger::open(&ledger_path).unwrap());
    let service = service_over(db.clone(), Some(ledger));
    create_network(&service).await;
    Fixture {
        db,
        service,
        ledger_path,
        _dir: dir,
    }
}

impl Fixture {
    async fn create(&self, paths: &[&str]) {
        for path in paths {
            let deletable = path.starts_with("apps/");
            self.service
                .create_key(&loc(path), deletable)
                .await
                .unwrap_or_else(|e| panic!("create {path}: {e}"));
        }
    }

    async fn row(&self, path: &str) -> encryption_network_key::Model {
        encryption_network_key::Entity::find_by_id((network().to_string(), path.to_string()))
            .one(&self.db)
            .await
            .unwrap()
            .unwrap_or_else(|| panic!("no row at {path}"))
    }

    async fn insert_raw(&self, path: &str, kind: &str, seed: bool) {
        encryption_network_key::ActiveModel {
            network_id: Set(network().to_string()),
            key_path: Set(path.to_string()),
            kind: Set(kind.to_string()),
            state: Set("active".to_string()),
            public_key: Set(vec![7u8; 32]),
            sealed_seed: Set(seed.then(|| vec![9u8; 60])),
            key_version: Set(1),
            created_at: Set("2026-01-01T00:00:00Z".to_string()),
            updated_at: Set("2026-01-01T00:00:00Z".to_string()),
        }
        .insert(&self.db)
        .await
        .unwrap();
    }

    async fn audit_rows(&self) -> Vec<encryption_audit::Model> {
        encryption_audit::Entity::find()
            .filter(encryption_audit::Column::Outcome.eq("deleted"))
            .all(&self.db)
            .await
            .unwrap()
    }

    /// Key paths of every operation in the ledger, in order.
    fn ledger_paths(&self) -> Vec<String> {
        ledger_keys(&self.ledger_path)
            .into_iter()
            .map(|key| key.key_path)
            .collect()
    }

    async fn delete(
        &self,
        target: &DeleteTarget,
        cid: &str,
    ) -> Result<DeleteOutcome, EncryptionServiceError> {
        self.service
            .delete_keys(&network(), target, &verified(cid))
            .await
    }

    async fn assert_unchanged(&self, paths: &[&str]) {
        for path in paths {
            let row = self.row(path).await;
            assert_ne!(row.state, "deleted", "{path}");
            assert!(row.sealed_seed.is_some(), "{path} keeps its seed");
        }
    }
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|v| v.to_string()).collect()
}

/// The keys of every operation in a ledger, in order.
fn ledger_keys(path: &std::path::Path) -> Vec<LedgerKey> {
    deletion_ledger::read(path)
        .unwrap()
        .records
        .into_iter()
        .filter_map(|record| match record {
            Record::Intent(intent) => Some(intent.keys),
            _ => None,
        })
        .flatten()
        .collect()
}

#[tokio::test]
async fn a_prefix_delete_deletes_exactly_the_keys_under_it() {
    let f = fixture().await;
    f.create(&[
        "apps/foo/a",
        "apps/foo/b/c",
        "apps/foo/d",
        "apps/foobar/x",
        "apps/foo.bar/x",
        "apps/foo-bar/x",
        "apps/fo/x",
        "apps/other/x",
        "docs/a",
    ])
    .await;
    f.service.block_key(&loc("apps/foo/d")).await.unwrap();

    let outcome = f.delete(&prefix("foo"), "cid-1").await.unwrap();
    assert_eq!(
        outcome,
        DeleteOutcome {
            key_path: "apps/foo/".to_string(),
            deleted: strings(&["apps/foo/a", "apps/foo/b/c", "apps/foo/d"]),
            already_deleted: vec![],
        }
    );
    for path in ["apps/foo/a", "apps/foo/b/c", "apps/foo/d"] {
        let row = f.row(path).await;
        assert_eq!(row.state, "deleted", "{path}");
        assert_eq!(row.sealed_seed, None, "{path}: NULL, not zeros");
    }
    f.assert_unchanged(&[
        "apps/foobar/x",
        "apps/foo.bar/x",
        "apps/foo-bar/x",
        "apps/fo/x",
        "apps/other/x",
    ])
    .await;
    assert_eq!(f.row("docs/a").await.state, "active");
}

#[tokio::test]
async fn one_audit_row_and_one_ledger_line_per_deleted_key() {
    let f = fixture().await;
    f.create(&["apps/foo/a", "apps/foo/b", "apps/bar/a"]).await;
    f.delete(&prefix("foo"), "cid-audit").await.unwrap();

    let mut audits = f.audit_rows().await;
    audits.sort_by(|a, b| a.key_path.cmp(&b.key_path));
    assert_eq!(audits.len(), 2);
    for (audit, path) in audits.iter().zip(["apps/foo/a", "apps/foo/b"]) {
        assert_eq!(audit.request_hash, audit_request_hash("cid-audit", path));
        assert_eq!(audit.outcome, "deleted");
        assert_eq!(audit.key_path.as_deref(), Some(path));
        assert_eq!(audit.requester, OWNER);
        assert_eq!(audit.network_id, network().to_string());
        assert_eq!(audit.node_id, NODE_DID);
    }
    // The hash is sha256(CID || 0x00 || path).
    assert_eq!(
        audit_request_hash("a", "bc"),
        super::canonical::hash_hex(b"a\0bc")
    );
    assert_ne!(audit_request_hash("a", "bc"), audit_request_hash("ab", "c"));
    assert_eq!(f.ledger_paths(), strings(&["apps/foo/a", "apps/foo/b"]));
    // One operation line, then its committed line.
    let records = deletion_ledger::read(&f.ledger_path).unwrap().records;
    assert_eq!(records.len(), 2);
    let Record::Intent(intent) = &records[0] else {
        panic!("the first line is the operation");
    };
    assert_eq!(intent.op, "cid-audit");
    assert_eq!(intent.network_id, network().to_string());
    assert!(intent.keys.iter().all(|key| key.key_version == 1));
    assert_eq!(records[1], Record::committed("cid-audit"));
}

#[tokio::test]
async fn like_wildcard_and_case_never_widen_the_selection() {
    let f = fixture().await;
    f.create(&[
        "apps/foo_bar/x",
        "apps/fooxbar/y",
        "apps/foo-bar/y",
        "apps/foo.bar/y",
    ])
    .await;
    // A row the API cannot create: upper case in the app id. A LIKE pattern
    // ignores case on SQLite and would select it.
    f.insert_raw("apps/FOO_BAR/z", "deletable", true).await;

    let outcome = f.delete(&prefix("foo_bar"), "cid-like").await.unwrap();
    assert_eq!(outcome.deleted, strings(&["apps/foo_bar/x"]));
    assert!(outcome.already_deleted.is_empty());
    f.assert_unchanged(&[
        "apps/fooxbar/y",
        "apps/foo-bar/y",
        "apps/foo.bar/y",
        "apps/FOO_BAR/z",
    ])
    .await;
    assert_eq!(f.ledger_paths(), strings(&["apps/foo_bar/x"]));
}

#[tokio::test]
async fn a_second_delete_changes_nothing_and_lists_the_keys_as_already_deleted() {
    let f = fixture().await;
    f.create(&["apps/foo/a", "apps/foo/b"]).await;
    f.delete(&prefix("foo"), "cid-1").await.unwrap();
    let ledger_before = std::fs::read(&f.ledger_path).unwrap();

    let again = f.delete(&prefix("foo"), "cid-2").await.unwrap();
    assert_eq!(again.deleted, Vec::<String>::new());
    assert_eq!(
        again.already_deleted,
        strings(&["apps/foo/a", "apps/foo/b"])
    );
    assert_eq!(std::fs::read(&f.ledger_path).unwrap(), ledger_before);
    assert_eq!(f.audit_rows().await.len(), 2);
}

#[tokio::test]
async fn a_prefix_with_no_keys_is_an_empty_success() {
    let f = fixture().await;
    f.create(&["apps/foo/a"]).await;
    let outcome = f.delete(&prefix("nobody"), "cid-none").await.unwrap();
    assert_eq!(
        outcome,
        DeleteOutcome {
            key_path: "apps/nobody/".to_string(),
            deleted: vec![],
            already_deleted: vec![],
        }
    );
    assert!(f.ledger_paths().is_empty());
    f.assert_unchanged(&["apps/foo/a"]).await;
}

#[tokio::test]
async fn a_stray_deterministic_row_aborts_with_no_writes() {
    let f = fixture().await;
    f.create(&["apps/foo/a", "apps/foo/b"]).await;
    f.insert_raw("apps/foo/stray", "deterministic", false).await;

    let err = f.delete(&prefix("foo"), "cid-stray").await.unwrap_err();
    assert!(
        matches!(err, EncryptionServiceError::KeyNotDeletable),
        "{err:?}"
    );
    f.assert_unchanged(&["apps/foo/a", "apps/foo/b"]).await;
    assert!(f.audit_rows().await.is_empty());
    assert!(f.ledger_paths().is_empty());
}

#[tokio::test]
async fn a_per_key_delete_of_a_deterministic_key_is_not_deletable() {
    let f = fixture().await;
    f.create(&["docs/a"]).await;
    for path in ["docs/a", "docs/missing"] {
        let err = f.delete(&key(path), "cid-det").await.unwrap_err();
        assert!(
            matches!(err, EncryptionServiceError::KeyNotDeletable),
            "{path}: {err:?}"
        );
    }
    assert_eq!(f.row("docs/a").await.state, "active");
    assert!(f.ledger_paths().is_empty());
}

#[tokio::test]
async fn a_per_key_delete_deletes_one_key_and_is_idempotent() {
    let f = fixture().await;
    f.create(&["apps/foo/a", "apps/foo/b"]).await;

    let outcome = f.delete(&key("apps/foo/a"), "cid-k1").await.unwrap();
    assert_eq!(outcome.key_path, "apps/foo/a");
    assert_eq!(outcome.deleted, strings(&["apps/foo/a"]));
    f.assert_unchanged(&["apps/foo/b"]).await;

    let again = f.delete(&key("apps/foo/a"), "cid-k2").await.unwrap();
    assert_eq!(again.deleted, Vec::<String>::new());
    assert_eq!(again.already_deleted, strings(&["apps/foo/a"]));

    let err = f.delete(&key("apps/foo/zzz"), "cid-k3").await.unwrap_err();
    assert!(
        matches!(err, EncryptionServiceError::KeyNotFound),
        "{err:?}"
    );
}

#[tokio::test]
async fn deleted_keys_are_refused_everywhere_and_reinstall_is_a_new_version() {
    let f = fixture().await;
    let descriptor = f
        .service
        .create_key(&loc("apps/foo/a"), true)
        .await
        .unwrap();
    let wrapped = wrap_to_public_key(&descriptor.public_encryption_key, &[0x5Au8; 32]).unwrap();
    f.service
        .unwrap_named_key(&loc("apps/foo/a"), &wrapped, 1)
        .await
        .unwrap();

    f.delete(&prefix("foo"), "cid-1").await.unwrap();

    let err = f
        .service
        .unwrap_named_key(&loc("apps/foo/a"), &wrapped, 1)
        .await
        .unwrap_err();
    assert!(matches!(err, EncryptionServiceError::KeyDeleted), "{err:?}");
    for result in [
        f.service.block_key(&loc("apps/foo/a")).await,
        f.service.unblock_key(&loc("apps/foo/a")).await,
    ] {
        assert!(matches!(result, Err(EncryptionServiceError::KeyDeleted)));
    }

    // A re-create is a new key version; deleting it records that version.
    let again = f
        .service
        .create_key(&loc("apps/foo/a"), true)
        .await
        .unwrap();
    assert_eq!(again.key_version, 2);
    f.delete(&prefix("foo"), "cid-2").await.unwrap();
    let versions: Vec<i64> = ledger_keys(&f.ledger_path)
        .into_iter()
        .map(|key| key.key_version)
        .collect();
    assert_eq!(versions, vec![1, 2]);
}

#[tokio::test]
async fn a_missing_network_and_a_missing_ledger_delete_nothing() {
    let f = fixture().await;
    f.create(&["apps/foo/a"]).await;

    let other = NetworkId::new(OWNER.to_string(), "other".to_string()).unwrap();
    let target = DeleteTarget::parse(&other, "apps/foo/").unwrap();
    let err = f
        .service
        .delete_keys(&other, &target, &verified("cid-net"))
        .await
        .unwrap_err();
    assert!(
        matches!(err, EncryptionServiceError::NetworkNotFound),
        "{err:?}"
    );

    let no_ledger = service_over(f.db.clone(), None);
    let err = no_ledger
        .delete_keys(&network(), &prefix("foo"), &verified("cid-ledger"))
        .await
        .unwrap_err();
    assert!(
        matches!(err, EncryptionServiceError::DeletionLedger(_)),
        "{err:?}"
    );
    f.assert_unchanged(&["apps/foo/a"]).await;
}

#[tokio::test]
async fn a_ledger_that_cannot_be_written_rolls_the_delete_back() {
    let f = fixture().await;
    f.create(&["apps/foo/a", "apps/foo/b"]).await;
    // A ledger over a read-only handle: the append fails.
    let read_only = std::fs::File::open(&f.ledger_path).unwrap();
    let broken = Arc::new(DeletionLedger::from_file(&f.ledger_path, read_only));
    let service = service_over(f.db.clone(), Some(broken));

    let err = service
        .delete_keys(&network(), &prefix("foo"), &verified("cid-broken"))
        .await
        .unwrap_err();
    assert!(
        matches!(err, EncryptionServiceError::DeletionLedger(_)),
        "{err:?}"
    );
    f.assert_unchanged(&["apps/foo/a", "apps/foo/b"]).await;
    assert!(
        f.audit_rows().await.is_empty(),
        "the audit rows roll back too"
    );
    assert!(f.ledger_paths().is_empty());
}

#[tokio::test]
async fn a_ledger_that_was_renamed_refuses_the_delete() {
    let f = fixture().await;
    f.create(&["apps/foo/a"]).await;
    let moved = f.ledger_path.with_file_name("moved.jsonl");
    std::fs::rename(&f.ledger_path, &moved).unwrap();

    let err = f.delete(&prefix("foo"), "cid-moved").await.unwrap_err();
    assert!(
        matches!(err, EncryptionServiceError::DeletionLedger(_)),
        "{err:?}"
    );
    f.assert_unchanged(&["apps/foo/a"]).await;
    assert!(f.audit_rows().await.is_empty());
    assert!(!f.ledger_path.exists());
    assert!(deletion_ledger::read(&moved).unwrap().records.is_empty());
}

/// What the ledger holds after a delete whose commit failed: the operation
/// and what settled it, if anything.
fn ledger_records(f: &Fixture) -> Vec<Record> {
    deletion_ledger::read(&f.ledger_path).unwrap().records
}

#[tokio::test]
async fn a_commit_that_did_not_happen_is_settled_as_aborted_from_the_rows() {
    let f = fixture().await;
    f.create(&["apps/foo/a", "apps/foo/b"]).await;
    f.service
        .delete_faults
        .fail_before_commit
        .store(true, std::sync::atomic::Ordering::SeqCst);

    let err = f.delete(&prefix("foo"), "cid-abort").await.unwrap_err();
    assert!(matches!(err, EncryptionServiceError::Db(_)), "{err:?}");
    f.assert_unchanged(&["apps/foo/a", "apps/foo/b"]).await;
    assert!(f.audit_rows().await.is_empty());
    let records = ledger_records(&f);
    assert_eq!(records.len(), 2);
    assert!(matches!(&records[0], Record::Intent(i) if i.op == "cid-abort"));
    assert_eq!(records[1], Record::aborted("cid-abort"));

    // A restore replays the ledger without that operation.
    let report = deletion_ledger::replay(&f.db, &f.ledger_path)
        .await
        .unwrap();
    assert_eq!(report.aborted_operations, 1);
    assert_eq!(report.applied, 0);
    f.assert_unchanged(&["apps/foo/a", "apps/foo/b"]).await;
}

#[tokio::test]
async fn a_commit_whose_reply_was_lost_is_settled_as_committed_from_the_rows() {
    let f = fixture().await;
    f.create(&["apps/foo/a", "apps/foo/b"]).await;
    // The database commits, then the answer is lost: the call fails.
    f.service
        .delete_faults
        .lose_commit_reply
        .store(true, std::sync::atomic::Ordering::SeqCst);

    let err = f.delete(&prefix("foo"), "cid-lost").await.unwrap_err();
    assert!(matches!(err, EncryptionServiceError::Db(_)), "{err:?}");
    for path in ["apps/foo/a", "apps/foo/b"] {
        assert_eq!(f.row(path).await.state, "deleted", "{path}");
    }
    let records = ledger_records(&f);
    assert_eq!(records.len(), 2);
    assert_eq!(records[1], Record::committed("cid-lost"));
    // A restore applies it: it is not skipped as aborted.
    let report = deletion_ledger::replay(&f.db, &f.ledger_path)
        .await
        .unwrap();
    assert_eq!(report.aborted_operations, 0);
}

#[tokio::test]
async fn a_commit_error_that_cannot_be_checked_leaves_the_operation_open() {
    let f = fixture().await;
    f.create(&["apps/foo/a"]).await;
    f.service
        .delete_faults
        .fail_before_commit
        .store(true, std::sync::atomic::Ordering::SeqCst);
    f.service
        .delete_faults
        .fail_reread
        .store(true, std::sync::atomic::Ordering::SeqCst);

    let err = f.delete(&prefix("foo"), "cid-open").await.unwrap_err();
    assert!(matches!(err, EncryptionServiceError::Db(_)), "{err:?}");
    let contents = deletion_ledger::read(&f.ledger_path).unwrap();
    assert_eq!(contents.records.len(), 1, "only the operation is written");
    assert_eq!(contents.open_intents().len(), 1);
}

#[tokio::test]
async fn a_crash_between_the_intent_and_the_commit_is_applied_at_the_next_start() {
    let f = fixture().await;
    f.create(&["apps/foo/a"]).await;
    // The intent is on disk; the process died before the commit.
    let ledger = f.service.deletion_ledger.clone().unwrap();
    ledger
        .append(&Record::Intent(Intent {
            op: "cid-crash".to_string(),
            network_id: network().to_string(),
            keys: vec![LedgerKey {
                key_path: "apps/foo/a".to_string(),
                key_version: 1,
            }],
            deleted_at: "2026-10-23T12:00:00Z".to_string(),
        }))
        .unwrap();

    // The owner authorized this delete, so the start applies it.
    ledger.replay_at_start(&f.db).await.unwrap();
    assert_eq!(f.row("apps/foo/a").await.state, "deleted");
    assert_eq!(f.row("apps/foo/a").await.sealed_seed, None);
    assert!(deletion_ledger::read(&f.ledger_path)
        .unwrap()
        .open_intents()
        .is_empty());
}

#[tokio::test]
async fn a_deleted_row_that_still_holds_a_seed_is_deleted_again_with_no_seed() {
    let f = fixture().await;
    f.create(&["apps/foo/a", "apps/foo/b"]).await;
    let mut row: encryption_network_key::ActiveModel = f.row("apps/foo/a").await.into();
    row.state = Set("deleted".to_string());
    row.update(&f.db).await.unwrap();
    assert!(f.row("apps/foo/a").await.sealed_seed.is_some());

    let outcome = f.delete(&prefix("foo"), "cid-seed").await.unwrap();
    assert_eq!(outcome.deleted, strings(&["apps/foo/a", "apps/foo/b"]));
    assert!(outcome.already_deleted.is_empty());
    assert_eq!(f.row("apps/foo/a").await.sealed_seed, None);
}

#[tokio::test]
async fn a_row_of_an_unknown_kind_is_corrupt_and_nothing_is_deleted() {
    let f = fixture().await;
    f.create(&["apps/foo/a"]).await;
    f.insert_raw("apps/foo/odd", "mystery", true).await;

    let err = f.delete(&prefix("foo"), "cid-kind").await.unwrap_err();
    assert!(
        matches!(err, EncryptionServiceError::CorruptKeyRow),
        "{err:?}"
    );
    f.assert_unchanged(&["apps/foo/a"]).await;
    assert!(f.audit_rows().await.is_empty());
    assert!(f.ledger_paths().is_empty());
}

#[tokio::test]
async fn creates_racing_a_prefix_delete_are_deleted_too_or_created_after() {
    let f = fixture().await;
    let service = Arc::new(f.service);
    for path in ["apps/foo/k0", "apps/foo/k1"] {
        service.create_key(&loc(path), true).await.unwrap();
    }
    let created: Vec<String> = (0..6).map(|i| format!("apps/foo/n{i}")).collect();
    let creates = futures::future::join_all(created.iter().map(|path| {
        let service = service.clone();
        let path = path.clone();
        async move { service.create_key(&loc(&path), true).await }
    }));
    let (network, target, verified) = (network(), prefix("foo"), verified("cid-race"));
    let delete = service.delete_keys(&network, &target, &verified);
    let (creates, outcome) = tokio::join!(creates, delete);
    let outcome = outcome.unwrap();
    assert!(creates.iter().all(|r| r.is_ok()));

    let rows = encryption_network_key::Entity::find()
        .all(&f.db)
        .await
        .unwrap();
    let deleted_rows: BTreeSet<String> = rows
        .iter()
        .filter(|r| r.state == "deleted")
        .map(|r| r.key_path.clone())
        .collect();
    assert_eq!(
        deleted_rows,
        outcome.deleted.iter().cloned().collect::<BTreeSet<_>>(),
        "a key is deleted exactly when the delete listed it"
    );
    assert_eq!(
        ledger_keys(&f.ledger_path)
            .into_iter()
            .map(|key| key.key_path)
            .collect::<BTreeSet<_>>(),
        deleted_rows
    );
    for row in rows.iter().filter(|r| r.state != "deleted") {
        assert!(
            row.sealed_seed.is_some(),
            "{} was created after",
            row.key_path
        );
    }
    assert!(outcome.deleted.iter().any(|p| p == "apps/foo/k0"));
}

// PostgreSQL-backed; CI-only. The network row lock serializes creates and a
// prefix delete, so each racing create is either deleted with the prefix or
// created after it.
#[tokio::test]
async fn postgres_creates_racing_a_prefix_delete_are_deleted_too_or_created_after() {
    let Some(fixture) = PostgresTestSchema::migrated_through(
        "postgres_creates_racing_a_prefix_delete_are_deleted_too_or_created_after",
        None,
    )
    .await
    else {
        return;
    };
    let db = fixture.connect(8).await;
    let dir = tempfile::tempdir().unwrap();
    let ledger_path = dir.path().join("ledger.jsonl");
    let ledger = Arc::new(DeletionLedger::open(&ledger_path).unwrap());
    let service = Arc::new(service_over(db.clone(), Some(ledger)));
    create_network(&service).await;
    for path in ["apps/foo/k0", "apps/foo/k1"] {
        service.create_key(&loc(path), true).await.unwrap();
    }

    let created: Vec<String> = (0..6).map(|i| format!("apps/foo/n{i}")).collect();
    let creates = futures::future::join_all(created.iter().map(|path| {
        let service = service.clone();
        let path = path.clone();
        async move { service.create_key(&loc(&path), true).await }
    }));
    let (network, target, verified) = (network(), prefix("foo"), verified("cid-race"));
    let delete = service.delete_keys(&network, &target, &verified);
    let (creates, outcome) = tokio::join!(creates, delete);
    let outcome = outcome.unwrap();
    assert!(creates.iter().all(|r| r.is_ok()));

    let rows = encryption_network_key::Entity::find()
        .all(&db)
        .await
        .unwrap();
    let deleted_rows: BTreeSet<String> = rows
        .iter()
        .filter(|r| r.state == "deleted")
        .map(|r| r.key_path.clone())
        .collect();
    assert_eq!(
        deleted_rows,
        outcome.deleted.iter().cloned().collect::<BTreeSet<_>>()
    );
    for row in rows.iter().filter(|r| r.state != "deleted") {
        assert!(row.sealed_seed.is_some());
    }
}

// PostgreSQL-backed; CI-only. `delete_keys` must end its transaction before it
// returns: a dropped transaction is rolled back by a task that cannot run
// while this runtime's thread is blocked, so a call that returns without
// ending its transaction would still hold the network row lock.
#[tokio::test]
async fn postgres_delete_keys_ends_its_transaction_before_returning() {
    let Some(fixture) = PostgresTestSchema::migrated_through(
        "postgres_delete_keys_ends_its_transaction_before_returning",
        None,
    )
    .await
    else {
        return;
    };
    let db = fixture.connect(4).await;
    let dir = tempfile::tempdir().unwrap();
    let ledger = Arc::new(DeletionLedger::open(&dir.path().join("ledger.jsonl")).unwrap());
    let service = service_over(db.clone(), Some(ledger));
    create_network(&service).await;
    service.create_key(&loc("apps/foo/a"), true).await.unwrap();
    service
        .delete_keys(&network(), &prefix("foo"), &verified("cid-end"))
        .await
        .unwrap();
    // A later write on the same network does not wait for a lock.
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        service.create_key(&loc("apps/foo/b"), true),
    )
    .await
    .expect("the network row lock was released")
    .unwrap();
}

// PostgreSQL-backed; CI-only. The node does not learn how the commit ended
// while the commit is still running on the server (a deferred trigger
// stretches it to about two seconds). The settling read waits for the network
// row lock that the committing transaction holds, so the ledger ends
// `committed` and a restore plus replay deletes the key.
#[tokio::test]
async fn postgres_a_commit_still_running_is_settled_as_committed_once_it_finishes() {
    use sea_orm::ConnectionTrait;
    let Some(fixture) = PostgresTestSchema::migrated_through(
        "postgres_a_commit_still_running_is_settled_as_committed_once_it_finishes",
        None,
    )
    .await
    else {
        return;
    };
    let db = fixture.connect(4).await;
    let dir = tempfile::tempdir().unwrap();
    let ledger_path = dir.path().join("ledger.jsonl");
    let ledger = Arc::new(DeletionLedger::open(&ledger_path).unwrap());
    let service = service_over(db.clone(), Some(ledger));
    create_network(&service).await;
    service.create_key(&loc("apps/foo/a"), true).await.unwrap();
    db.execute_unprepared(
        "CREATE FUNCTION slow_commit() RETURNS trigger LANGUAGE plpgsql AS \
         $$ BEGIN PERFORM pg_sleep(2); RETURN NULL; END $$",
    )
    .await
    .unwrap();
    db.execute_unprepared(
        "CREATE CONSTRAINT TRIGGER slow_commit AFTER UPDATE ON encryption_network_key \
         DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION slow_commit()",
    )
    .await
    .unwrap();
    service
        .delete_faults
        .detach_commit
        .store(true, std::sync::atomic::Ordering::SeqCst);

    let err = service
        .delete_keys(&network(), &prefix("foo"), &verified("cid-slow"))
        .await
        .unwrap_err();
    assert!(matches!(err, EncryptionServiceError::Db(_)), "{err:?}");

    let records = deletion_ledger::read(&ledger_path).unwrap().records;
    assert_eq!(records.len(), 2, "{records:?}");
    assert!(matches!(&records[0], Record::Intent(i) if i.op == "cid-slow"));
    assert_eq!(records[1], Record::committed("cid-slow"));
    let row = encryption_network_key::Entity::find_by_id((
        network().to_string(),
        "apps/foo/a".to_string(),
    ))
    .one(&db)
    .await
    .unwrap()
    .unwrap();
    assert_eq!(row.state, "deleted");

    // A restore brings the row back as it was before the delete; the replay
    // deletes it again.
    db.execute_unprepared(
        "UPDATE encryption_network_key SET state = 'active', sealed_seed = decode('09', 'hex') \
         WHERE key_path = 'apps/foo/a'",
    )
    .await
    .unwrap();
    let report = deletion_ledger::replay(&db, &ledger_path).await.unwrap();
    assert_eq!(report.aborted_operations, 0);
    assert_eq!(report.applied, 1);
    let row = encryption_network_key::Entity::find_by_id((
        network().to_string(),
        "apps/foo/a".to_string(),
    ))
    .one(&db)
    .await
    .unwrap()
    .unwrap();
    assert_eq!(row.state, "deleted");
    assert!(row.sealed_seed.is_none());
}
