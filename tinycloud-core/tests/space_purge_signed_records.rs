//! Database-side R1-R6 lifecycle proofs; HTTP authority/fence coverage belongs to the API suite.
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, ConnectOptions, ConnectionTrait, Database,
    DatabaseConnection, DbBackend, EntityTrait, IntoActiveModel, QueryFilter, Statement,
    TransactionTrait,
};
use std::{collections::BTreeMap, time::Duration};
use time::OffsetDateTime;
use tinycloud_auth::{
    resolver::DID_METHODS,
    ssi::{
        claims::jwt::NumericDate,
        jwk::{Algorithm, JWK},
        ucan::Payload,
    },
    ucan_capabilities_object::Capabilities,
};
use tinycloud_core::{
    encryption::{maybe_encrypt, ColumnEncryption, RowBinding},
    hash::{hash, Hash},
    migrations::Migrator,
    models::{
        self, abilities, delegation, invocation, space_purge_job, space_purge_shared_residue,
    },
    relationships::{invoked_abilities, parent_delegations},
    sea_orm_migration::MigratorTrait,
    space_purge_ledger::{LedgerKeys, LedgerRecord},
    space_purge_records as records,
    space_purge_worker::{claim_specific, complete_with_encryption, ClaimedPurge},
};

const A: &str = "tinycloud:pkh:eip155:1:0x1111111111111111111111111111111111111111:files";
const B: &str = "tinycloud:pkh:eip155:1:0x2222222222222222222222222222222222222222:files";
const SAME: &str = "tinycloud:pkh:eip155:1:0x1111111111111111111111111111111111111111:secrets";
const OWNER_A: &str = "did:pkh:eip155:1:0x1111111111111111111111111111111111111111";
const OWNER_B: &str = "did:pkh:eip155:1:0x2222222222222222222222222222222222222222";

static DATABASE_LOCK: std::sync::LazyLock<std::sync::Arc<tokio::sync::Mutex<()>>> =
    std::sync::LazyLock::new(|| std::sync::Arc::new(tokio::sync::Mutex::new(())));

struct Fixture {
    db: DatabaseConnection,
    admin: DatabaseConnection,
    schema: String,
    keys: LedgerKeys,
    signer: JWK,
    issuer: String,
    vm: String,
    encryption: Option<ColumnEncryption>,
    _isolation: tokio::sync::OwnedMutexGuard<()>,
}
struct Accepted {
    job: ClaimedPurge,
    record: LedgerRecord,
}
struct Stored {
    id: Hash,
    bytes: Vec<u8>,
}
impl Fixture {
    async fn new(encrypted: bool) -> Option<Self> {
        let url = std::env::var("TINYCLOUD_TEST_POSTGRES_URL").ok()?;
        let isolation = DATABASE_LOCK.clone().lock_owned().await;
        let admin = Database::connect(&url).await.unwrap();
        let schema = format!(
            "purge_records_{}_{}",
            std::process::id(),
            OffsetDateTime::now_utc().unix_timestamp_nanos()
        );
        admin
            .execute_unprepared(&format!("CREATE SCHEMA {schema}"))
            .await
            .unwrap();
        let mut options = ConnectOptions::new(url);
        options.set_schema_search_path(schema.clone());
        let db = Database::connect(options).await.unwrap();
        Migrator::up(&db, None).await.unwrap();
        for space in [A, B, SAME] {
            models::space::ActiveModel {
                id: Set(tinycloud_core::types::SpaceIdWrap(space.parse().unwrap())),
            }
            .insert(&db)
            .await
            .unwrap();
        }
        let keys = LedgerKeys::new(
            "test".into(),
            BTreeMap::from([("test".into(), rand::random::<[u8; 32]>().to_vec())]),
        )
        .unwrap();
        let mut signer = JWK::generate_ed25519().unwrap();
        signer.algorithm = Some(Algorithm::EdDSA);
        let issuer = DID_METHODS.generate(&signer, "key").unwrap().to_string();
        let vm = format!("{}#{}", issuer, issuer.rsplit(':').next().unwrap());
        models::actor::ActiveModel {
            id: Set(issuer.clone()),
        }
        .insert(&db)
        .await
        .unwrap();
        Some(Self {
            db,
            admin,
            schema,
            keys,
            signer,
            issuer,
            vm,
            encryption: encrypted.then(|| ColumnEncryption::new(rand::random())),
            _isolation: isolation,
        })
    }
    fn signed(&self, resources: &[String], expiry: OffsetDateTime, parents: &[Hash]) -> Vec<u8> {
        let mut caps = Capabilities::new();
        for resource in resources {
            caps.with_action(
                resource.parse().unwrap(),
                "tinycloud.kv/get".parse().unwrap(),
                [BTreeMap::<String, serde_json::Value>::new()],
            );
        }
        Payload::<serde_json::Value, serde_json::Value> {
            issuer: self.vm.parse().unwrap(),
            audience: self.issuer.parse().unwrap(),
            not_before: None,
            expiration: NumericDate::try_from_seconds(expiry.unix_timestamp() as f64).unwrap(),
            nonce: Some(format!("{}", rand::random::<u64>())),
            facts: None,
            proof: parents.iter().map(|id| id.to_cid(0x55)).collect(),
            attenuation: caps,
        }
        .sign(Algorithm::EdDSA, &self.signer)
        .unwrap()
        .encode()
        .unwrap()
        .into_bytes()
    }
    fn revocation_bytes(&self, target: Hash) -> Vec<u8> {
        let mut caps = Capabilities::new();
        caps.with_action(
            format!("urn:cid:{}", target.to_cid(0x55)).parse().unwrap(),
            "tinycloud.delegation/revoke".parse().unwrap(),
            [BTreeMap::<String, serde_json::Value>::new()],
        );
        Payload::<serde_json::Value, serde_json::Value> {
            issuer: self.vm.parse().unwrap(),
            audience: self.issuer.parse().unwrap(),
            not_before: None,
            expiration: NumericDate::try_from_seconds(
                (OffsetDateTime::now_utc().unix_timestamp() + 3600) as f64,
            )
            .unwrap(),
            nonce: Some(format!("{}", rand::random::<u64>())),
            facts: None,
            proof: vec![],
            attenuation: caps,
        }
        .sign(Algorithm::EdDSA, &self.signer)
        .unwrap()
        .encode()
        .unwrap()
        .into_bytes()
    }
    async fn stored(&self, kind: &str, resources: &[String], ttl: i64, parents: &[Hash]) -> Stored {
        let now = OffsetDateTime::now_utc();
        let expiry = OffsetDateTime::from_unix_timestamp(now.unix_timestamp() + ttl).unwrap();
        let plain = self.signed(resources, expiry, parents);
        let id = hash(&plain);
        let bytes_id: Vec<u8> = id.into();
        let bytes = maybe_encrypt(
            self.encryption.as_ref(),
            &plain,
            RowBinding::new(kind, "serialization", &[&bytes_id]),
        );
        let format = if self.encryption.is_some() { 2 } else { 0 };
        if kind == "delegation" {
            delegation::Model {
                id,
                delegator: self.issuer.clone(),
                delegatee: self.issuer.clone(),
                expiry: Some(expiry),
                issued_at: Some(now),
                not_before: None,
                facts: None,
                serialization: bytes.clone(),
                serialization_format: format,
            }
            .into_active_model()
            .insert(&self.db)
            .await
            .unwrap();
        } else {
            invocation::Model {
                id,
                invoker: self.issuer.clone(),
                issued_at: now,
                facts: None,
                serialization: bytes.clone(),
                serialization_format: format,
            }
            .into_active_model()
            .insert(&self.db)
            .await
            .unwrap();
        }
        for resource in resources {
            if kind == "delegation" {
                abilities::ActiveModel {
                    delegation: Set(id),
                    resource: Set(resource.parse().unwrap()),
                    ability: Set("tinycloud.kv/get".to_owned().try_into().unwrap()),
                    caveats: Set(Default::default()),
                }
                .insert(&self.db)
                .await
                .unwrap();
            } else {
                invoked_abilities::ActiveModel {
                    invocation: Set(id),
                    resource: Set(resource.parse().unwrap()),
                    ability: Set("tinycloud.kv/get".to_owned().try_into().unwrap()),
                }
                .insert(&self.db)
                .await
                .unwrap();
            }
        }
        for parent in parents {
            let stored_parent = models::delegation_cid_alias::Entity::find()
                .filter(models::delegation_cid_alias::Column::Canonical.eq(*parent))
                .one(&self.db)
                .await
                .unwrap()
                .map(|alias| alias.id)
                .unwrap_or(*parent);
            parent_delegations::ActiveModel {
                child: Set(id),
                parent: Set(stored_parent),
            }
            .insert(&self.db)
            .await
            .unwrap();
        }
        Stored { id, bytes }
    }
    async fn accept(&self, space: &str) -> Accepted {
        let id = format!("{}", uuid::Uuid::from_bytes(rand::random()));
        let owner = space
            .parse::<tinycloud_auth::resource::SpaceId>()
            .unwrap()
            .did()
            .to_string();
        let target = self.keys.target_hmac("test", "space", space).unwrap();
        let now = OffsetDateTime::now_utc();
        space_purge_job::ActiveModel {
            purge_id: Set(id.clone()),
            space: Set(Some(space.into())),
            tombstone_hmac: Set(target.clone()),
            hmac_key_id: Set("test".into()),
            owner_hmac: Set(self.keys.target_hmac("test", "owner", &owner).unwrap()),
            accepted_at: Set(now),
            phase: Set("objects".into()),
            fence_generation: Set(1),
            updated_at: Set(now),
            next_attempt_at: Set(now),
            attempt_count: Set(0),
            last_error_code: Set(None),
            lease_token: Set(None),
            lease_until: Set(None),
        }
        .insert(&self.db)
        .await
        .unwrap();
        let lease = format!("{}", uuid::Uuid::from_bytes(rand::random()));
        let job = claim_specific(&self.db, &lease, &id)
            .await
            .unwrap()
            .unwrap();
        let record = self
            .keys
            .sign(
                "test",
                "space",
                &target,
                &id,
                "complete",
                now.unix_timestamp(),
            )
            .unwrap();
        Accepted { job, record }
    }
    async fn finish(&self, job: &Accepted) -> bool {
        complete_with_encryption(
            &self.db,
            &job.job,
            &self.keys,
            &job.record,
            self.encryption.as_ref(),
        )
        .await
        .unwrap()
    }
    async fn retire(&self, owner: &str) {
        let tx = self.db.begin().await.unwrap();
        models::space_retirement::ActiveModel {
            owner_hmac: Set(self.keys.target_hmac("test", "owner", owner).unwrap()),
            hmac_key_id: Set("test".into()),
            retirement_id: Set(format!("{}", uuid::Uuid::from_bytes(rand::random()))),
            accepted_at: Set(OffsetDateTime::now_utc()),
        }
        .insert(&tx)
        .await
        .unwrap();
        records::request_all(&tx).await.unwrap();
        tx.commit().await.unwrap();
    }
    async fn dispose(self) {
        self.db.close().await.unwrap();
        self.admin
            .execute_unprepared(&format!("DROP SCHEMA {} CASCADE", self.schema))
            .await
            .unwrap();
    }
}
fn scopes(spaces: &[&str]) -> Vec<String> {
    spaces
        .iter()
        .map(|space| format!("{space}/kv/key"))
        .collect()
}

#[tokio::test]
async fn postgres_r1_r2_r3_retains_exact_bytes_and_deletes_last_link_in_both_orders() {
    for order in [[A, B], [B, A]] {
        let Some(f) = Fixture::new(true).await else {
            return;
        };
        let d = f.stored("delegation", &scopes(&[A, B]), 3600, &[]).await;
        let i = f
            .stored("invocation", &scopes(&[A, B]), 3600, &[d.id])
            .await;
        let first = f.accept(order[0]).await;
        assert!(f.finish(&first).await);
        assert_eq!(
            delegation::Entity::find_by_id(d.id)
                .one(&f.db)
                .await
                .unwrap()
                .unwrap()
                .serialization,
            d.bytes
        );
        assert_eq!(
            invocation::Entity::find_by_id(i.id)
                .one(&f.db)
                .await
                .unwrap()
                .unwrap()
                .serialization,
            i.bytes
        );
        for table in ["ability", "invoked_abilities"] {
            let gone =
                f.db.query_one(Statement::from_sql_and_values(
                    DbBackend::Postgres,
                    format!(
                        "SELECT count(*) AS n FROM {table} WHERE split_part(resource,'/',1)=$1"
                    ),
                    [order[0].into()],
                ))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(gone.try_get::<i64>("", "n").unwrap(), 0);
            let live =
                f.db.query_one(Statement::from_sql_and_values(
                    DbBackend::Postgres,
                    format!(
                        "SELECT count(*) AS n FROM {table} WHERE split_part(resource,'/',1)=$1"
                    ),
                    [order[1].into()],
                ))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(live.try_get::<i64>("", "n").unwrap(), 1);
        }
        assert_eq!(records::count(&f.db, &first.job.purge_id).await.unwrap(), 2);
        let hash = hex::encode(f.keys.target_hmac("test", "space", order[0]).unwrap());
        let gauge = prometheus::gather()
            .into_iter()
            .find(|family| family.get_name() == "tinycloud_space_purge_retained_signed_records")
            .unwrap();
        let sample = gauge
            .get_metric()
            .iter()
            .find(|sample| {
                sample
                    .get_label()
                    .iter()
                    .any(|label| label.get_value() == hash)
            })
            .unwrap();
        assert_eq!(sample.get_gauge().get_value(), 2.0);
        assert!(sample
            .get_label()
            .iter()
            .all(|label| label.get_name() == "purge_hash" && label.get_value().len() == 64));
        let second = f.accept(order[1]).await;
        // A failing completion rolls back the last-link deletion as well as its tombstone.
        f.db.execute_unprepared("CREATE TABLE blocker(space TEXT REFERENCES space(id))")
            .await
            .unwrap();
        f.db.execute(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "INSERT INTO blocker(space) VALUES($1)",
            [order[1].into()],
        ))
        .await
        .unwrap();
        assert!(complete_with_encryption(
            &f.db,
            &second.job,
            &f.keys,
            &second.record,
            f.encryption.as_ref()
        )
        .await
        .is_err());
        assert!(delegation::Entity::find_by_id(d.id)
            .one(&f.db)
            .await
            .unwrap()
            .is_some());
        assert_eq!(records::count(&f.db, &first.job.purge_id).await.unwrap(), 2);
        f.db.execute_unprepared("DELETE FROM blocker")
            .await
            .unwrap();
        assert!(f.finish(&second).await);
        assert!(delegation::Entity::find()
            .all(&f.db)
            .await
            .unwrap()
            .is_empty());
        assert!(invocation::Entity::find()
            .all(&f.db)
            .await
            .unwrap()
            .is_empty());
        assert!(parent_delegations::Entity::find()
            .all(&f.db)
            .await
            .unwrap()
            .is_empty());
        assert!(space_purge_shared_residue::Entity::find()
            .all(&f.db)
            .await
            .unwrap()
            .is_empty());
        assert!(models::actor::Entity::find()
            .all(&f.db)
            .await
            .unwrap()
            .is_empty());
        f.dispose().await;
    }
}

#[tokio::test]
async fn postgres_r4_expiry_sweep_schedules_no_later_than_24_hours() {
    let Some(f) = Fixture::new(false).await else {
        return;
    };
    let d = f.stored("delegation", &scopes(&[A, B]), 8, &[]).await;
    let a = f.accept(A).await;
    assert!(f.finish(&a).await);
    assert_eq!(
        records::sweep(&f.db, &a.job.purge_id, &f.keys, None)
            .await
            .unwrap(),
        1
    );
    let job = space_purge_job::Entity::find_by_id(&a.job.purge_id)
        .one(&f.db)
        .await
        .unwrap()
        .unwrap();
    assert!(
        (job.next_attempt_at - OffsetDateTime::now_utc()).whole_seconds()
            <= records::SWEEP_INTERVAL_SECONDS
    );
    let expiry = delegation::Entity::find_by_id(d.id)
        .one(&f.db)
        .await
        .unwrap()
        .unwrap()
        .expiry
        .unwrap();
    let wait = (expiry - OffsetDateTime::now_utc())
        .whole_milliseconds()
        .max(0) as u64
        + 20;
    tokio::time::sleep(Duration::from_millis(wait)).await;
    assert_eq!(
        records::sweep(&f.db, &a.job.purge_id, &f.keys, None)
            .await
            .unwrap(),
        0
    );
    assert!(delegation::Entity::find_by_id(d.id)
        .one(&f.db)
        .await
        .unwrap()
        .is_none());
    f.dispose().await;
}

#[tokio::test]
async fn postgres_r4_r5_revocation_wakes_parent_residue_but_keeps_live_proof_until_then() {
    let Some(f) = Fixture::new(false).await else {
        return;
    };
    let parent = f.stored("delegation", &scopes(&[A, B]), -60, &[]).await;
    let child = f
        .stored("delegation", &scopes(&[B]), 3600, &[parent.id])
        .await;
    let a = f.accept(A).await;
    assert!(f.finish(&a).await);
    assert_eq!(
        records::sweep(&f.db, &a.job.purge_id, &f.keys, None)
            .await
            .unwrap(),
        1
    );
    assert!(delegation::Entity::find_by_id(parent.id)
        .one(&f.db)
        .await
        .unwrap()
        .is_some());
    let tx = f.db.begin().await.unwrap();
    records::operation(&tx).await.unwrap();
    let signed_revocation = f.revocation_bytes(child.id);
    models::revocation::ActiveModel {
        id: Set(hash(&signed_revocation)),
        revoker: Set(f.issuer.clone()),
        revoked: Set(child.id),
        serialization: Set(signed_revocation),
        revoked_at: Set(Some(OffsetDateTime::now_utc())),
    }
    .insert(&tx)
    .await
    .unwrap();
    records::request_for_records(&tx, &[child.id])
        .await
        .unwrap();
    let before = space_purge_job::Entity::find_by_id(&a.job.purge_id)
        .one(&f.db)
        .await
        .unwrap()
        .unwrap();
    assert!(before.next_attempt_at > OffsetDateTime::now_utc());
    tx.commit().await.unwrap();
    assert!(records::sweep_next(&f.db, &f.keys, None).await.unwrap());
    assert!(delegation::Entity::find()
        .all(&f.db)
        .await
        .unwrap()
        .is_empty());
    assert!(models::revocation::Entity::find()
        .all(&f.db)
        .await
        .unwrap()
        .is_empty());
    assert!(parent_delegations::Entity::find()
        .all(&f.db)
        .await
        .unwrap()
        .is_empty());
    assert_eq!(records::count(&f.db, &a.job.purge_id).await.unwrap(), 0);
    f.dispose().await;
}

#[tokio::test]
async fn postgres_r6_same_owner_spaces_leave_no_shared_records() {
    let Some(f) = Fixture::new(false).await else {
        return;
    };
    f.retire(OWNER_A).await;
    let d = f.stored("delegation", &scopes(&[A, SAME]), 3600, &[]).await;
    let a = f.accept(A).await;
    assert!(f.finish(&a).await);
    assert!(delegation::Entity::find_by_id(d.id)
        .one(&f.db)
        .await
        .unwrap()
        .is_some());
    let last = f.accept(SAME).await;
    assert!(f.finish(&last).await);
    assert!(delegation::Entity::find()
        .all(&f.db)
        .await
        .unwrap()
        .is_empty());
    assert!(space_purge_shared_residue::Entity::find()
        .all(&f.db)
        .await
        .unwrap()
        .is_empty());
    f.dispose().await;
}

#[tokio::test]
async fn postgres_nonspace_resources_follow_owner_retirement_and_revisit_completed_jobs() {
    let Some(f) = Fixture::new(false).await else {
        return;
    };
    let mut same = scopes(&[A]);
    same.push(format!("urn:tinycloud:encryption:{OWNER_A}:default"));
    let d = f.stored("delegation", &same, 3600, &[]).await;
    let a = f.accept(A).await;
    assert!(f.finish(&a).await);
    assert_eq!(
        records::sweep(&f.db, &a.job.purge_id, &f.keys, None)
            .await
            .unwrap(),
        1
    );
    assert!(space_purge_job::Entity::find_by_id(&a.job.purge_id)
        .one(&f.db)
        .await
        .unwrap()
        .unwrap()
        .space
        .is_none());
    f.retire(OWNER_A).await;
    assert!(records::sweep_next(&f.db, &f.keys, None).await.unwrap());
    assert!(delegation::Entity::find_by_id(d.id)
        .one(&f.db)
        .await
        .unwrap()
        .is_none());
    f.dispose().await;
    let Some(f) = Fixture::new(false).await else {
        return;
    };
    f.retire(OWNER_A).await;
    let mut other = scopes(&[A]);
    other.push(format!("urn:tinycloud:encryption:{OWNER_B}:default"));
    let d = f.stored("delegation", &other, 3600, &[]).await;
    let a = f.accept(A).await;
    assert!(f.finish(&a).await);
    assert_eq!(
        delegation::Entity::find_by_id(d.id)
            .one(&f.db)
            .await
            .unwrap()
            .unwrap()
            .serialization,
        d.bytes
    );
    assert_eq!(
        records::sweep(&f.db, &a.job.purge_id, &f.keys, None)
            .await
            .unwrap(),
        1
    );
    f.retire(OWNER_B).await;
    assert!(records::sweep_next(&f.db, &f.keys, None).await.unwrap());
    assert!(delegation::Entity::find_by_id(d.id)
        .one(&f.db)
        .await
        .unwrap()
        .is_none());
    f.dispose().await;
}

#[tokio::test]
async fn postgres_gc_exclusive_lock_waits_for_concurrent_proof_writers() {
    let Some(f) = Fixture::new(false).await else {
        return;
    };
    let d = f.stored("delegation", &scopes(&[A, B]), 3600, &[]).await;
    let a = f.accept(A).await;
    let first = f.db.begin().await.unwrap();
    records::operation(&first).await.unwrap();
    let second = f.db.begin().await.unwrap();
    tokio::time::timeout(Duration::from_secs(1), records::operation(&second))
        .await
        .unwrap()
        .unwrap();
    let waiter = tokio::spawn({
        let db = f.db.clone();
        async move {
            let tx = db.begin().await.unwrap();
            records::lock(&tx).await.unwrap();
            tx.commit().await.unwrap();
        }
    });
    tokio::task::yield_now().await;
    assert!(!waiter.is_finished());
    first.commit().await.unwrap();
    assert!(!waiter.is_finished());
    second.commit().await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), waiter)
        .await
        .unwrap()
        .unwrap();
    assert!(f.finish(&a).await);
    assert!(delegation::Entity::find_by_id(d.id)
        .one(&f.db)
        .await
        .unwrap()
        .is_some());
    f.dispose().await;
}

#[tokio::test]
async fn postgres_current_value_keeps_expired_invocation_proof_until_its_last_live_root_is_removed()
{
    let Some(f) = Fixture::new(true).await else {
        return;
    };
    let i = f.stored("invocation", &scopes(&[A, B]), -60, &[]).await;
    models::current_kv::ActiveModel {
        space: Set(tinycloud_core::types::SpaceIdWrap(B.parse().unwrap())),
        key: Set(tinycloud_core::types::Path("key".parse().unwrap())),
        invocation: Set(i.id),
        seq: Set(1),
        epoch: Set(hash(b"epoch")),
        epoch_seq: Set(1),
        value: Set(hash(b"live bytes")),
        generation: Set(0),
        metadata: Set(tinycloud_core::types::Metadata(BTreeMap::new())),
        deleted: Set(false),
    }
    .insert(&f.db)
    .await
    .unwrap();
    let a = f.accept(A).await;
    assert!(f.finish(&a).await);
    assert_eq!(
        records::sweep(&f.db, &a.job.purge_id, &f.keys, f.encryption.as_ref())
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        invocation::Entity::find_by_id(i.id)
            .one(&f.db)
            .await
            .unwrap()
            .unwrap()
            .serialization,
        i.bytes
    );
    let tx = f.db.begin().await.unwrap();
    records::operation(&tx).await.unwrap();
    models::current_kv::Entity::delete_many()
        .exec(&tx)
        .await
        .unwrap();
    records::request_for_records(&tx, &[i.id]).await.unwrap();
    tx.commit().await.unwrap();
    assert!(records::sweep_next(&f.db, &f.keys, f.encryption.as_ref())
        .await
        .unwrap());
    assert!(invocation::Entity::find_by_id(i.id)
        .one(&f.db)
        .await
        .unwrap()
        .is_none());
    f.dispose().await;
}

#[tokio::test]
async fn postgres_canonical_alias_proof_survives_until_its_live_child_is_revoked() {
    let Some(f) = Fixture::new(true).await else {
        return;
    };
    let parent = f.stored("delegation", &scopes(&[A, B]), -60, &[]).await;
    let canonical = hash(b"canonical equivalent of persisted delegation");
    models::delegation_cid_alias::ActiveModel {
        id: Set(parent.id),
        canonical: Set(canonical),
        encrypted: Set(true),
    }
    .insert(&f.db)
    .await
    .unwrap();
    let child = f
        .stored("delegation", &scopes(&[B]), 3600, &[canonical])
        .await;
    let a = f.accept(A).await;
    assert!(f.finish(&a).await);
    assert_eq!(
        records::sweep(&f.db, &a.job.purge_id, &f.keys, f.encryption.as_ref())
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        delegation::Entity::find_by_id(parent.id)
            .one(&f.db)
            .await
            .unwrap()
            .unwrap()
            .serialization,
        parent.bytes
    );
    let tx = f.db.begin().await.unwrap();
    records::operation(&tx).await.unwrap();
    let bytes = f.revocation_bytes(child.id);
    models::revocation::ActiveModel {
        id: Set(hash(&bytes)),
        revoker: Set(f.issuer.clone()),
        revoked: Set(child.id),
        serialization: Set(bytes),
        revoked_at: Set(Some(OffsetDateTime::now_utc())),
    }
    .insert(&tx)
    .await
    .unwrap();
    records::request_for_records(&tx, &[child.id])
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert!(records::sweep_next(&f.db, &f.keys, f.encryption.as_ref())
        .await
        .unwrap());
    assert!(delegation::Entity::find()
        .all(&f.db)
        .await
        .unwrap()
        .is_empty());
    assert!(models::delegation_cid_alias::Entity::find()
        .all(&f.db)
        .await
        .unwrap()
        .is_empty());
    assert!(parent_delegations::Entity::find()
        .all(&f.db)
        .await
        .unwrap()
        .is_empty());
    f.dispose().await;
}

#[tokio::test]
async fn postgres_policy_projection_proof_keeps_expired_signed_bytes_until_policy_removal() {
    let Some(f) = Fixture::new(false).await else {
        return;
    };
    let parent = f.stored("delegation", &scopes(&[A, B]), -60, &[]).await;
    let projected = hash(b"native policy projection").to_cid(0x55).to_string();
    let policy = hash(b"policy registration").to_cid(0x55).to_string();
    let now = OffsetDateTime::now_utc();
    for cid in [&projected, &parent.id.to_cid(0x55).to_string()] {
        models::policy_delegation::ActiveModel {
            delegation_cid: Set(cid.clone()),
            role: Set("policy_authority".into()),
            delegation_mode: Set("attenuated".into()),
            artifact_json: Set(serde_json::json!({})),
            not_before: Set((now - time::Duration::hours(1))
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap()),
            expires_at: Set((now + time::Duration::hours(1))
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap()),
            status_checked_at: Set(now
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap()),
            status_fresh_until: Set(None),
            status_sequence: Set(0),
            revoked_at: Set(None),
        }
        .insert(&f.db)
        .await
        .unwrap();
    }
    models::policy_edge::ActiveModel {
        child_cid: Set(projected.clone()),
        position: Set(0),
        parent_cid: Set(parent.id.to_cid(0x55).to_string()),
        edge_kind: Set("proof".into()),
    }
    .insert(&f.db)
    .await
    .unwrap();
    let now = OffsetDateTime::now_utc();
    models::policy_v3_registration::ActiveModel {
        policy_cid: Set(policy.clone()),
        policy_bytes: Set(b"signed policy".to_vec()),
        policy_digest_hex: Set("00".repeat(32)),
        owner_did: Set(OWNER_B.into()),
        policy_root_cid: Set(projected.clone()),
        enforcement_root_cid: Set(projected),
        content_source_digest_hex: Set("01".repeat(32)),
        native_projection_hash_hex: Set("02".repeat(32)),
        attested_enforcer_binding_bytes: Set(b"binding".to_vec()),
        registered_at: Set(now
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap()),
        expires_at: Set((now + time::Duration::hours(1))
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap()),
    }
    .insert(&f.db)
    .await
    .unwrap();
    let a = f.accept(A).await;
    assert!(f.finish(&a).await);
    assert_eq!(
        records::sweep(&f.db, &a.job.purge_id, &f.keys, None)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        delegation::Entity::find_by_id(parent.id)
            .one(&f.db)
            .await
            .unwrap()
            .unwrap()
            .serialization,
        parent.bytes
    );
    let tx = f.db.begin().await.unwrap();
    records::operation(&tx).await.unwrap();
    models::policy_v3_registration::Entity::delete_by_id(policy)
        .exec(&tx)
        .await
        .unwrap();
    records::request_all(&tx).await.unwrap();
    tx.commit().await.unwrap();
    assert!(records::sweep_next(&f.db, &f.keys, None).await.unwrap());
    assert!(delegation::Entity::find_by_id(parent.id)
        .one(&f.db)
        .await
        .unwrap()
        .is_none());
    assert!(models::policy_edge::Entity::find()
        .all(&f.db)
        .await
        .unwrap()
        .is_empty());
    f.dispose().await;
}

#[tokio::test]
async fn postgres_control_grants_do_not_keep_a_revoked_unused_record_alive() {
    let Some(f) = Fixture::new(false).await else {
        return;
    };
    let parent = f.stored("delegation", &scopes(&[A, B]), 3600, &[]).await;
    let mut control = scopes(&[A]);
    control.push(format!("urn:cid:{}", parent.id.to_cid(0x55)));
    let grant = f.stored("delegation", &control, 3600, &[]).await;
    let a = f.accept(A).await;
    assert!(f.finish(&a).await);
    assert_eq!(
        records::sweep(&f.db, &a.job.purge_id, &f.keys, None)
            .await
            .unwrap(),
        2
    );
    let tx = f.db.begin().await.unwrap();
    records::operation(&tx).await.unwrap();
    let bytes = f.revocation_bytes(parent.id);
    models::revocation::ActiveModel {
        id: Set(hash(&bytes)),
        revoker: Set(f.issuer.clone()),
        revoked: Set(parent.id),
        serialization: Set(bytes),
        revoked_at: Set(Some(OffsetDateTime::now_utc())),
    }
    .insert(&tx)
    .await
    .unwrap();
    records::request_for_records(&tx, &[parent.id])
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert!(records::sweep_next(&f.db, &f.keys, None).await.unwrap());
    assert!(delegation::Entity::find_by_id(parent.id)
        .one(&f.db)
        .await
        .unwrap()
        .is_none());
    assert!(delegation::Entity::find_by_id(grant.id)
        .one(&f.db)
        .await
        .unwrap()
        .is_none());
    f.dispose().await;
}
