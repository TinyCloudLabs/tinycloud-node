//! The shadow uploader's publish cycle: upload-then-CAS, as a reusable
//! state machine driven by the uploader's run loop.
//!
//! Given a published frontier (may be `None` for first publish), a plan
//! to upload, the object-store client, the manifest, and a failpoint hook,
//! `publish_cycle` runs the four steps in order:
//!
//! 1. `store.put_if_absent(key, body)`: content-addressed, so a retry
//!    reuses the same object. `AlreadyPresent` is as good as `Created`.
//! 2. `manifest.record_object(record)`: INSERT-ON-CONFLICT-DO-NOTHING.
//!    An existing orphan row is revived first (the manifest does that
//!    inside `record_object` today).
//! 3. Failpoint `before_cas`: a kill -9 harness arms this for the crash
//!    matrix.
//! 4. `manifest.publish_cas(expected, publish)`: single CAS. On
//!    `Lost(current)` the caller re-plans from the new frontier.
//!
//! The function returns one of three outcomes:
//! - `PublishOutcome::Published(frontier)`: the CAS succeeded.
//! - `PublishOutcome::Lost(current)`: CAS lost; the caller re-plans.
//! - `PublishOutcome::Blocked`: HEAD after PUT reported a different
//!   length or hash. The caller stops publishing this database and
//!   alerts.
//!
//! The cycle takes no lock, holds no state across .await points, and
//! never re-issues a CAS on a lost response (publish_id disambiguates
//! that case on the next cycle's `current` read). Backoff, breaker,
//! per-DB in-flight serialisation and the timer loop are the uploader
//! driver's concerns, not this module.
//!
//! TC-1491.

use crate::sql::store::key::ObjectKey;
use crate::sql::store::manifest::{
    CasToken, Frontier, ObjectRecord, ObjectState, Publish, PublishOutcome as ManifestOutcome,
    SqlManifest,
};
use crate::sql::store::object::{PutOutcome, SqlObjectStore, SqlStoreError};
use crate::sql::store::DbRef;

/// What a publish cycle returns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CycleOutcome {
    /// The CAS succeeded; the frontier now reflects this publish.
    Published(Frontier),
    /// The CAS lost against a concurrent writer; the uploader re-reads
    /// `current()` and re-plans.
    Lost(Option<Frontier>),
    /// The object was uploaded but the follow-up HEAD showed a
    /// different length or SHA-256. The uploader marks this database
    /// `blocked`; nothing is published.
    Blocked,
}

/// Why a cycle refused to run at all. Separate from `CycleOutcome`
/// because these are transient infrastructure errors the caller's
/// backoff and breaker cover, not publish outcomes.
#[derive(Debug, thiserror::Error)]
pub enum CycleError {
    #[error("sql object store error: {0}")]
    Store(#[from] SqlStoreError),
    /// The caller handed inconsistent keys across the cycle inputs.
    /// `record.key`, `cycle.key` and `publish.object` must all be the
    /// same. This is a programming error in the caller; publish is
    /// refused before any I/O.
    #[error("cycle keys do not agree")]
    Invalid,
    /// The object was uploaded but a HEAD afterwards returned no
    /// object. That is an infrastructure failure (deleted out from
    /// under us, backend lost the write), not a benign race.
    #[error("object vanished between put and head")]
    ObjectVanished,
}

/// What the uploader hands this function per cycle. The body is passed
/// to `put_if_absent`; the record is handed to the manifest's
/// `record_object`; the publish is the CAS payload.
pub struct Cycle<'a> {
    pub db: DbRef<'a>,
    pub key: ObjectKey,
    pub body: Vec<u8>,
    pub record: ObjectRecord,
    pub expected: Option<CasToken>,
    pub publish: Publish,
}

/// Run the publish cycle. See the module doc for the contract.
pub async fn publish_cycle<'a, S: SqlObjectStore, M: SqlManifest>(
    store: &S,
    manifest: &M,
    cycle: Cycle<'a>,
) -> Result<CycleOutcome, CycleError> {
    let Cycle {
        db,
        key,
        body,
        record,
        expected,
        publish,
    } = cycle;

    // Preflight: every input that names the object must name the same
    // one. A mismatch is a caller bug; publish is refused before any
    // I/O so a stale `publish.object` cannot race ahead of its body.
    if record.key != key || publish.object != key {
        return Err(CycleError::Invalid);
    }

    let put = store.put_if_absent(&key, body.clone()).await?;
    #[cfg(feature = "sql-store-failpoints")]
    super::failpoints::hit(super::failpoints::Point::AfterPut);

    if matches!(put, PutOutcome::Created | PutOutcome::AlreadyPresent) {
        // Verify the stored object's length and hash. A HEAD that
        // returns `None` right after a successful PUT is an
        // infrastructure failure, not a benign race: the backend lost
        // the write, or something else deleted it out from under us.
        match store.head(&key).await? {
            Some(meta) => {
                if meta.bytes != record.bytes || meta.sha256 != *key.sha256() {
                    // Same key, different bytes. The content-addressed
                    // key should prevent this, but the check is cheap
                    // and the alert is loud.
                    return Ok(CycleOutcome::Blocked);
                }
            }
            None => return Err(CycleError::ObjectVanished),
        }
    }

    let state = manifest.record_object(&db, &record).await?;
    #[cfg(feature = "sql-store-failpoints")]
    super::failpoints::hit(super::failpoints::Point::AfterRecord);

    // Observed state matters:
    //
    // - Uploaded: the normal path. Proceed to the CAS.
    // - Orphan: the reconciler marked an earlier row orphan after a
    //   crash between put and the previous CAS. Revive it before the
    //   CAS, otherwise `publish_cas` fails with `ObjectNotUploaded`
    //   forever and the database's backup freezes silently.
    // - Published: someone else won the CAS with this exact object
    //   (same content-addressed key). Nothing to publish; return
    //   `Lost(current)` so the caller re-plans from the new frontier.
    match state {
        ObjectState::Uploaded => {}
        ObjectState::Orphan => {
            let revived = manifest.revive_object(&db, &key).await?;
            if !revived {
                // Someone raced us between the record and the revive;
                // re-read the current frontier and try again.
                return Ok(CycleOutcome::Lost(manifest.current(&db).await?));
            }
        }
        ObjectState::Published => {
            return Ok(CycleOutcome::Lost(manifest.current(&db).await?));
        }
    }

    #[cfg(feature = "sql-store-failpoints")]
    super::failpoints::hit(super::failpoints::Point::BeforeCas);
    let outcome = manifest
        .publish_cas(&db, expected.as_ref(), publish)
        .await?;
    #[cfg(feature = "sql-store-failpoints")]
    super::failpoints::hit(super::failpoints::Point::AfterCas);

    Ok(match outcome {
        ManifestOutcome::Published(f) => CycleOutcome::Published(f),
        ManifestOutcome::Lost(f) => CycleOutcome::Lost(f),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sea_orm::{ConnectOptions, Database};
    use crate::sea_orm_migration::MigratorTrait;
    use crate::sql::store::key::{Lineage, PublishId};
    use crate::sql::store::manifest::{DbSqlManifest, PublishKind};
    use crate::sql::store::{MemorySqlObjectStore, SqlObjectStore};

    async fn harness() -> (MemorySqlObjectStore, DbSqlManifest) {
        let db = Database::connect(ConnectOptions::new("sqlite::memory:".to_string()))
            .await
            .unwrap();
        crate::migrations::Migrator::up(&db, None).await.unwrap();
        (MemorySqlObjectStore::default(), DbSqlManifest::new(db))
    }

    fn snapshot_key() -> ObjectKey {
        ObjectKey::snapshot(
            &DbRef {
                space: "s",
                db_id: "d",
            },
            &Lineage::random(),
            7,
            &crate::sql::store::object::sha256(b"body"),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn first_publish_lands_as_a_snapshot() {
        let (store, manifest) = harness().await;
        let key = snapshot_key();
        let body = b"body".to_vec();
        let record = ObjectRecord {
            key: key.clone(),
            format: "sqlite-v1".into(),
            bytes: body.len() as u64,
            created_at: "2026-11-22T00:00:00.000000Z".into(),
        };
        let publish = Publish {
            kind: PublishKind::Snapshot,
            object: key.clone(),
            base_checkpoint_cid: "cid".into(),
            frontier_bytes: body.len() as u64,
            publish_id: PublishId::random(),
            now: "2026-11-22T00:00:00.000000Z".into(),
        };
        let outcome = publish_cycle(
            &store,
            &manifest,
            Cycle {
                db: DbRef {
                    space: "s",
                    db_id: "d",
                },
                key: key.clone(),
                body,
                record,
                expected: None,
                publish,
            },
        )
        .await
        .unwrap();
        assert!(matches!(outcome, CycleOutcome::Published(_)), "{outcome:?}");
        // The object is in the store.
        assert!(store.head(&key).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn head_mismatch_after_put_returns_blocked() {
        // Hand-craft an object store that returns a HEAD with the wrong
        // size for the stored key, to exercise the Blocked branch.
        use crate::sql::store::object::{ObjectMeta, ObjectRange};
        use async_trait::async_trait;

        struct LyingStore;
        #[async_trait]
        impl crate::sql::store::SqlObjectStore for LyingStore {
            async fn put_if_absent(
                &self,
                _key: &ObjectKey,
                _body: Vec<u8>,
            ) -> Result<PutOutcome, SqlStoreError> {
                Ok(PutOutcome::Created)
            }
            async fn get_range(
                &self,
                _key: &ObjectKey,
                _range: crate::storage::ByteRangeSpec,
            ) -> Result<Option<ObjectRange>, SqlStoreError> {
                Ok(None)
            }
            async fn head(&self, key: &ObjectKey) -> Result<Option<ObjectMeta>, SqlStoreError> {
                Ok(Some(ObjectMeta {
                    bytes: 42,
                    sha256: *key.sha256(),
                }))
            }
        }

        let (_, manifest) = harness().await;
        let store = LyingStore;
        let key = snapshot_key();
        let body = b"body".to_vec();
        let record = ObjectRecord {
            key: key.clone(),
            format: "sqlite-v1".into(),
            bytes: body.len() as u64,
            created_at: "2026-11-22T00:00:00.000000Z".into(),
        };
        let publish = Publish {
            kind: PublishKind::Snapshot,
            object: key.clone(),
            base_checkpoint_cid: "cid".into(),
            frontier_bytes: body.len() as u64,
            publish_id: PublishId::random(),
            now: "2026-11-22T00:00:00.000000Z".into(),
        };
        let outcome = publish_cycle(
            &store,
            &manifest,
            Cycle {
                db: DbRef {
                    space: "s",
                    db_id: "d",
                },
                key: key.clone(),
                body,
                record,
                expected: None,
                publish,
            },
        )
        .await
        .unwrap();
        assert_eq!(outcome, CycleOutcome::Blocked);
    }

    fn cycle_for(key: &ObjectKey, body: &[u8], publish_object: &ObjectKey) -> Cycle<'static> {
        use crate::sql::store::manifest::PublishKind;
        Cycle {
            db: DbRef {
                space: "s",
                db_id: "d",
            },
            key: key.clone(),
            body: body.to_vec(),
            record: ObjectRecord {
                key: key.clone(),
                format: "sqlite-v1".into(),
                bytes: body.len() as u64,
                created_at: "2026-11-22T00:00:00.000000Z".into(),
            },
            expected: None,
            publish: Publish {
                kind: PublishKind::Snapshot,
                object: publish_object.clone(),
                base_checkpoint_cid: "cid".into(),
                frontier_bytes: body.len() as u64,
                publish_id: PublishId::random(),
                now: "2026-11-22T00:00:00.000000Z".into(),
            },
        }
    }

    #[tokio::test]
    async fn mismatched_keys_across_inputs_are_refused_before_any_io() {
        let (store, manifest) = harness().await;
        let key_a = snapshot_key();
        let key_b = snapshot_key();
        let cycle = cycle_for(&key_a, b"body", &key_b);
        let err = publish_cycle(&store, &manifest, cycle)
            .await
            .expect_err("mismatched keys must be refused");
        assert!(matches!(err, CycleError::Invalid), "{err:?}");
        // And no object was put: the preflight runs before the PUT.
        assert!(store.head(&key_a).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn orphaned_record_is_revived_so_the_cas_can_succeed_on_retry() {
        // Simulate the crash-matrix case Bobbie flagged: a cycle lands
        // put_if_absent + record_object (state=uploaded), the process
        // dies before publish_cas, then the reconciler marks the row
        // orphan before the retry. The retry's record_object is a no-op
        // on the same content-addressed row, so observed state is
        // Orphan; without the revive, publish_cas returns
        // ObjectNotUploaded forever.
        use crate::sql::store::manifest::SqlManifest;
        let (store, manifest) = harness().await;
        let key = snapshot_key();
        let body = b"body".to_vec();
        let cycle_1 = cycle_for(&key, &body, &key);
        // First call lands the row in `uploaded`.
        let _ = store.put_if_absent(&key, body.clone()).await.unwrap();
        let state_before = manifest
            .record_object(
                &DbRef {
                    space: "s",
                    db_id: "d",
                },
                &cycle_1.record,
            )
            .await
            .unwrap();
        assert_eq!(state_before, ObjectState::Uploaded);
        // Reconciler marks it orphan.
        manifest
            .mark_orphans(
                &DbRef {
                    space: "s",
                    db_id: "d",
                },
                "9999",
            )
            .await
            .unwrap();
        // Retry.
        let cycle_2 = cycle_for(&key, &body, &key);
        let outcome = publish_cycle(&store, &manifest, cycle_2).await.unwrap();
        assert!(
            matches!(outcome, CycleOutcome::Published(_)),
            "the retry must revive the orphan and publish: {outcome:?}"
        );
    }
}
