//! Core boundary fixtures: real signed native UCANs, persisted projections,
//! normal authorization, authenticated retirement provenance, then reader proof.
//! Synthetic did:key-owner CORE ONLY fixtures; not a managed PKH account flow.
//! HTTP/decrypt execution and production route mounting are not exercised here.
use super::*;
use crate::{
    events::{Delegation, Invocation},
    hash::hash,
    keys::StaticSecret,
    models::{abilities, delegation, delegation_cid_alias, policy_v3_session, space_retirement},
    relationships::parent_delegations,
    resource_purge_dependencies::collect_target_dependencies,
    resource_retirement_snapshot::{load_authenticated, prepare},
    space_purge_fence::SpacePurgeFence,
    space_purge_ledger::{LedgerKeys, LedgerRecord},
    storage::memory::MemoryStore,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, Database, DatabaseConnection, EntityTrait,
    IntoActiveModel, QueryFilter, TransactionTrait,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use tinycloud_auth::{
    authorization::{TinyCloudDelegation, TinyCloudInvocation},
    resolver::DID_METHODS,
    ssi::{
        claims::jwt::NumericDate,
        jwk::{Algorithm, JWK},
        ucan::Payload,
    },
    ucan_capabilities_object::Capabilities,
};

type Service = SpaceDatabase<DatabaseConnection, MemoryStore, StaticSecret>;
fn did(key: &JWK) -> String {
    DID_METHODS.generate(key, "key").unwrap().to_string()
}
fn method(key: &JWK) -> String {
    let did = did(key);
    format!("{did}#{}", did.trim_start_matches("did:key:"))
}
fn stamp(seconds: i64) -> String {
    OffsetDateTime::from_unix_timestamp(seconds)
        .unwrap()
        .format(&Rfc3339)
        .unwrap()
}
fn digest(value: &Value) -> String {
    hex::encode(Sha256::digest(serde_json::to_vec(value).unwrap()))
}
fn signed(
    key: &JWK,
    audience: &str,
    resource: &str,
    parents: &[Hash],
    facts: Option<Value>,
    start: i64,
    end: i64,
) -> Vec<u8> {
    let mut caps = Capabilities::new();
    caps.with_action(
        resource.parse().unwrap(),
        "tinycloud.encryption/decrypt".parse().unwrap(),
        [BTreeMap::<String, Value>::new()],
    );
    Payload::<Value, Value> {
        issuer: method(key).parse().unwrap(),
        audience: audience.parse().unwrap(),
        not_before: Some(NumericDate::try_from_seconds(start as f64).unwrap()),
        expiration: NumericDate::try_from_seconds(end as f64).unwrap(),
        nonce: Some(uuid::Uuid::new_v4().to_string()),
        facts: facts.map(|fact| vec![fact]),
        proof: parents.iter().map(|id| id.to_cid(0x55)).collect(),
        attenuation: caps,
    }
    .sign(Algorithm::EdDSA, key)
    .unwrap()
    .encode()
    .unwrap()
    .into_bytes()
}
async fn register(service: &Service, bytes: &[u8]) -> Hash {
    let event =
        Delegation::from_header_ser::<TinyCloudDelegation>(std::str::from_utf8(bytes).unwrap())
            .unwrap();
    service
        .delegate(event)
        .await
        .map_err(|error| error.to_string())
        .unwrap();
    hash(bytes)
}
struct Fixture {
    service: Service,
    keys: Arc<LedgerKeys>,
    fence: SpacePurgeFence,
    owner: JWK,
    recipient: JWK,
    node: JWK,
    key_target: ResourceTarget,
    network_target: ResourceTarget,
    session: Hash,
    generic_key: Hash,
    generic_network: Hash,
    facts: Value,
    start: i64,
    end: i64,
}
impl Fixture {
    async fn new(conn: DatabaseConnection) -> Self {
        let secret = StaticSecret::new(vec![41; 32]).unwrap();
        let seed = secret.derive_key(b"tinycloud/node/identity");
        let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
        let node: JWK = serde_json::from_value(json!({"kty":"OKP","crv":"Ed25519","alg":"EdDSA",
            "x":URL_SAFE_NO_PAD.encode(signing.verifying_key().to_bytes()),"d":URL_SAFE_NO_PAD.encode(seed)})).unwrap();
        assert_eq!(did(&node), secret.node_did());
        let service = SpaceDatabase::new(conn, MemoryStore::default(), secret)
            .await
            .unwrap();
        let owner = JWK::generate_ed25519().unwrap();
        let recipient = JWK::generate_ed25519().unwrap();
        let network = format!("urn:tinycloud:encryption:{}:default", did(&owner));
        let key_target = ResourceTarget::parse(&format!("{network}/named")).unwrap();
        let network_target = ResourceTarget::parse(&network).unwrap();
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let start = now - 5;
        let end = now + 600;
        let policy = json!({"ownerDid":did(&owner),"recipientDid":did(&recipient),"resource":key_target.as_str(),"action":"tinycloud.encryption/decrypt"});
        let policy_cid = hash(&serde_json::to_vec(&policy).unwrap())
            .to_cid(0x55)
            .to_string();
        let projection_digest = digest(&policy);
        let mut roots = Vec::new();
        for role in ["policy-authority", "policy-enforcement"] {
            let mut facts = json!({"role":role,"mode":if role=="policy-authority" {"policy-source"} else {"conditional-mint"},
                "ownerDid":did(&owner),"policyId":"synthetic-reader-policy","policyDigestHex":projection_digest,
                "policyCid":policy_cid,"contentSourceDigestHex":digest(&json!("synthetic content")),
                "capabilityCeilingHashHex":projection_digest,"nativeProjectionHashHex":projection_digest,"nodeAudience":did(&node)});
            if role == "policy-enforcement" {
                facts["enforcerDid"] = json!(did(&node));
            }
            let bytes = signed(
                &owner,
                &did(&node),
                key_target.as_str(),
                &[],
                Some(facts),
                now - 10,
                now + 1200,
            );
            roots.push(register(&service, &bytes).await);
        }
        let facts = json!({"profile":"policy-session-ucan/v1","ownerDid":did(&owner),
            "policyId":"synthetic-reader-policy","policyDigestHex":projection_digest,"policyCid":policy_cid,
            "policyDelegationCid":roots[0].to_cid(0x55).to_string(),"enforcementDelegationCid":roots[1].to_cid(0x55).to_string(),
            "contentSourceDigestHex":digest(&json!("synthetic content")),"capabilityCeilingHashHex":projection_digest,
            "nativeProjectionHashHex":projection_digest,"enforcerDid":did(&node),"nodeAudience":did(&node),"recipientDid":did(&recipient),
            "challengeId":"synthetic-challenge","claimDigestHex":digest(&json!("synthetic claim")),"claimJti":"synthetic-claim",
            "vpDigestHex":digest(&json!("synthetic presentation")),"credentialEvidenceDigestHex":digest(&json!("synthetic evidence")),
            "decisionContextDigestHex":digest(&policy),"issuanceAuditDigestHex":digest(&json!("synthetic issuance")),"remainingRedelegationDepth":1});
        let bytes = signed(
            &node,
            &did(&recipient),
            key_target.as_str(),
            &roots,
            Some(facts.clone()),
            start,
            end,
        );
        let session = register(&service, &bytes).await;
        policy_v3_session::Model {
            session_cid: session.to_cid(0x55).to_string(),
            policy_cid,
            authorization_bytes: bytes,
            recipient_did: did(&recipient),
            claim_jti: "synthetic-claim".into(),
            claim_digest_hex: facts["claimDigestHex"].as_str().unwrap().into(),
            vp_digest_hex: facts["vpDigestHex"].as_str().unwrap().into(),
            state: "admitted".into(),
            not_before: stamp(start),
            expires_at: stamp(end),
            admitted_at: Some(stamp(now)),
        }
        .into_active_model()
        .insert(service.connection())
        .await
        .unwrap();
        let generic_key = register(
            &service,
            &signed(
                &owner,
                &did(&recipient),
                key_target.as_str(),
                &[],
                None,
                now - 10,
                now + 1200,
            ),
        )
        .await;
        let generic_network = register(
            &service,
            &signed(
                &owner,
                &did(&recipient),
                &network,
                &[],
                None,
                now - 10,
                now + 1200,
            ),
        )
        .await;
        let keys = Arc::new(
            LedgerKeys::new(
                "test".into(),
                BTreeMap::from([("test".into(), vec![57; 32])]),
            )
            .unwrap(),
        );
        let fence = SpacePurgeFence::new(keys.clone());
        fence.set_serving_ready(true);
        Self {
            service,
            keys,
            fence,
            owner,
            recipient,
            node,
            key_target,
            network_target,
            session,
            generic_key,
            generic_network,
            facts,
            start,
            end,
        }
    }
    async fn invoke(
        &self,
        signer: &JWK,
        target: &ResourceTarget,
        proofs: &[Hash],
    ) -> crate::AdmittedInvocation {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let bytes = signed(
            signer,
            &did(&self.node),
            target.as_str(),
            proofs,
            None,
            now - 1,
            now + 45,
        );
        let event = Invocation::from_header_ser::<TinyCloudInvocation>(
            std::str::from_utf8(&bytes).unwrap(),
        )
        .unwrap();
        crate::AdmittedInvocation::admit(event, 120).await.unwrap()
    }
    async fn capture(&self) -> LedgerRecord {
        let _lifetime = self.fence.lifecycle_operation().await;
        let _owner = self.fence.retirement_drain(&did(&self.owner)).await;
        let tx = self.service.connection().begin().await.unwrap();
        let now = OffsetDateTime::from_unix_timestamp(OffsetDateTime::now_utc().unix_timestamp())
            .unwrap();
        let retirement = uuid::Uuid::new_v4().to_string();
        let mut prepared = Vec::new();
        for target in [&self.key_target, &self.network_target] {
            let check = collect_target_dependencies(
                &tx,
                target,
                &BTreeSet::from([did(&self.node)]),
                now,
                None,
                self.service.renewal_identity(),
            )
            .await
            .unwrap();
            assert!(check.proven_outside_count() >= 1);
            assert!(check.ambiguous_count() >= 1);
            assert!(!check.is_verified_zero());
            prepared.push(
                prepare(
                    &self.keys,
                    "test",
                    &retirement,
                    &check.full_union_snapshot().unwrap(),
                )
                .unwrap(),
            );
        }
        self.fence.lock_owner(&tx, &did(&self.owner)).await.unwrap();
        let owner_hmac = self
            .keys
            .target_hmac("test", "owner", &did(&self.owner))
            .unwrap();
        self.fence
            .fence_hmac(&tx, "owner", "test", &owner_hmac)
            .await
            .unwrap();
        space_retirement::ActiveModel {
            owner_hmac: Set(owner_hmac.clone()),
            hmac_key_id: Set("test".into()),
            retirement_id: Set(retirement.clone()),
            accepted_at: Set(now),
        }
        .insert(&tx)
        .await
        .unwrap();
        let record = self
            .keys
            .with_retirement_snapshots(
                self.keys
                    .sign(
                        "test",
                        "owner",
                        &owner_hmac,
                        &retirement,
                        "retired",
                        now.unix_timestamp(),
                    )
                    .unwrap(),
                prepared
                    .iter()
                    .map(|row| row.commitment().clone())
                    .collect(),
            )
            .unwrap();
        for row in prepared {
            row.persist(&tx, &self.keys, &record).await.unwrap();
        }
        crate::space_purge_ledger_copy::retain(
            &tx,
            &self.keys,
            &record.object_key().unwrap(),
            &record.to_bytes().unwrap(),
            now,
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        record
    }
}

async fn matrix(conn: DatabaseConnection) {
    let f = Fixture::new(conn).await;
    let record = f.capture().await;
    let admitted = f.invoke(&f.recipient, &f.key_target, &[f.session]).await;
    // The normal graph must authorize before the narrow extra proof can exist.
    f.service
        .authorize_admitted(&admitted, OffsetDateTime::now_utc())
        .await
        .unwrap();
    let tx = f.service.connection().begin().await.unwrap();
    let snapshot = load_authenticated(&tx, &f.keys, &record, &f.key_target)
        .await
        .unwrap();
    let proof = f
        .service
        .authorize_retired_resource_reader(
            &tx,
            &admitted,
            &f.key_target,
            &snapshot,
            OffsetDateTime::now_utc(),
        )
        .await
        .unwrap();
    assert_eq!(proof.target().as_str(), f.key_target.as_str());
    assert_eq!(
        proof.invocation_hash(),
        admitted.invocation().content_hash()
    );
    f.fence
        .recheck_retired_resource_read(&tx, &proof)
        .await
        .unwrap();
    drop(proof);
    tx.rollback().await.unwrap();
    for (signer, target, proofs) in [
        (&f.owner, &f.key_target, vec![]),
        (&f.recipient, &f.key_target, vec![f.generic_key]),
        (
            &f.recipient,
            &f.network_target,
            vec![f.generic_network, f.session],
        ),
    ] {
        let admitted = f.invoke(signer, target, &proofs).await;
        f.service
            .authorize_admitted(&admitted, OffsetDateTime::now_utc())
            .await
            .unwrap();
        let tx = f.service.connection().begin().await.unwrap();
        let snapshot = load_authenticated(&tx, &f.keys, &record, target)
            .await
            .unwrap();
        assert!(f
            .service
            .authorize_retired_resource_reader(
                &tx,
                &admitted,
                target,
                &snapshot,
                OffsetDateTime::now_utc()
            )
            .await
            .is_err());
        tx.rollback().await.unwrap();
    }
}

async fn fence_matrix(conn: DatabaseConnection, network: bool) {
    let f = Fixture::new(conn).await;
    let record = f.capture().await;
    let target = if network {
        &f.network_target
    } else {
        &f.key_target
    };
    let tx = f.service.connection().begin().await.unwrap();
    let digest = f
        .keys
        .target_hmac("test", "resource", target.as_str())
        .unwrap();
    f.fence
        .fence_hmac(&tx, "resource", "test", &digest)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let admitted = f.invoke(&f.recipient, &f.key_target, &[f.session]).await;
    let tx = f.service.connection().begin().await.unwrap();
    let snapshot = load_authenticated(&tx, &f.keys, &record, &f.key_target)
        .await
        .unwrap();
    let proof = f
        .service
        .authorize_retired_resource_reader(
            &tx,
            &admitted,
            &f.key_target,
            &snapshot,
            OffsetDateTime::now_utc(),
        )
        .await
        .unwrap();
    assert!(f
        .fence
        .recheck_retired_resource_read(&tx, &proof)
        .await
        .is_err());
    drop(proof);
    tx.rollback().await.unwrap();
}

#[tokio::test]
async fn sqlite_signed_native_reader_and_nonrecipient_matrix() {
    matrix(Database::connect("sqlite::memory:").await.unwrap()).await;
}
#[tokio::test]
async fn exact_key_fence_wins_over_valid_native_reader() {
    fence_matrix(Database::connect("sqlite::memory:").await.unwrap(), false).await;
}
#[tokio::test]
async fn network_fence_wins_over_valid_named_key_reader() {
    fence_matrix(Database::connect("sqlite::memory:").await.unwrap(), true).await;
}

#[tokio::test]
async fn postgres_signed_native_reader_and_nonrecipient_matrix() {
    use sea_orm::{ConnectOptions, ConnectionTrait};
    let Ok(url) = std::env::var("TINYCLOUD_TEST_POSTGRES_URL") else {
        return;
    };
    let admin = Database::connect(&url).await.unwrap();
    let schema = format!(
        "retired_reader_{}_{}",
        std::process::id(),
        OffsetDateTime::now_utc().unix_timestamp_nanos()
    );
    admin
        .execute_unprepared(&format!("CREATE SCHEMA {schema}"))
        .await
        .unwrap();
    let mut options = ConnectOptions::new(url);
    options.set_schema_search_path(schema.clone());
    let conn = Database::connect(options).await.unwrap();
    matrix(conn.clone()).await;
    conn.close().await.unwrap();
    admin
        .execute_unprepared(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

#[tokio::test]
async fn uncaptured_restored_descendant_cannot_inherit_reader_exception() {
    let f = Fixture::new(Database::connect("sqlite::memory:").await.unwrap()).await;
    let later_recipient = JWK::generate_ed25519().unwrap();
    let mut child_facts = f.facts.clone();
    child_facts["remainingRedelegationDepth"] = json!(0);
    let bytes = signed(
        &f.recipient,
        &did(&later_recipient),
        f.key_target.as_str(),
        &[f.session],
        Some(child_facts),
        f.start + 1,
        f.end - 1,
    );
    // Validate once through the public registration path. Retain exact rows to
    // simulate a later DB restore containing authority absent at retirement.
    let id = register(&f.service, &bytes).await;
    let conn = f.service.connection();
    let row = delegation::Entity::find_by_id(id)
        .one(conn)
        .await
        .unwrap()
        .unwrap();
    let caps = abilities::Entity::find()
        .filter(abilities::Column::Delegation.eq(id))
        .all(conn)
        .await
        .unwrap();
    let edges = parent_delegations::Entity::find()
        .filter(parent_delegations::Column::Child.eq(id))
        .all(conn)
        .await
        .unwrap();
    let alias = delegation_cid_alias::Entity::find_by_id(id)
        .one(conn)
        .await
        .unwrap();
    delegation_cid_alias::Entity::delete_by_id(id)
        .exec(conn)
        .await
        .unwrap();
    parent_delegations::Entity::delete_many()
        .filter(parent_delegations::Column::Child.eq(id))
        .exec(conn)
        .await
        .unwrap();
    abilities::Entity::delete_many()
        .filter(abilities::Column::Delegation.eq(id))
        .exec(conn)
        .await
        .unwrap();
    delegation::Entity::delete_by_id(id)
        .exec(conn)
        .await
        .unwrap();
    let record = f.capture().await;
    row.into_active_model().insert(conn).await.unwrap();
    for cap in caps {
        cap.into_active_model().insert(conn).await.unwrap();
    }
    for edge in edges {
        edge.into_active_model().insert(conn).await.unwrap();
    }
    if let Some(alias) = alias {
        alias.into_active_model().insert(conn).await.unwrap();
    }
    let admitted = f.invoke(&later_recipient, &f.key_target, &[id]).await;
    f.service
        .authorize_admitted(&admitted, OffsetDateTime::now_utc())
        .await
        .unwrap();
    let tx = conn.begin().await.unwrap();
    let snapshot = load_authenticated(&tx, &f.keys, &record, &f.key_target)
        .await
        .unwrap();
    let current = collect_target_dependencies(
        &tx,
        &f.key_target,
        &BTreeSet::from([did(&f.node)]),
        OffsetDateTime::now_utc(),
        None,
        f.service.renewal_identity(),
    )
    .await
    .unwrap();
    assert!(current
        .proven_outside()
        .identities()
        .iter()
        .any(|identity| matches!(identity,DependencyIdentity::Grant(grant) if *grant==id)));
    assert!(snapshot
        .snapshot()
        .current_subset(&current.full_union_snapshot().unwrap())
        .is_err());
    assert!(f
        .service
        .authorize_retired_resource_reader(
            &tx,
            &admitted,
            &f.key_target,
            &snapshot,
            OffsetDateTime::now_utc()
        )
        .await
        .is_err());
    tx.rollback().await.unwrap();
}
