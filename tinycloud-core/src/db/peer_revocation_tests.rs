//! TC-4321: a peer delegation A -> B that A revoked must stop authorizing B,
//! also after B posts the same signed bytes again (what a fresh Courier CLI
//! process does on every run). B's own owner -> B grant over the same prefix
//! is a separate authority and keeps working: revoking A -> B does not touch it.
use super::*;
use crate::storage::memory::{MemoryStaging, MemoryStore};
use tinycloud_auth::{
    authorization::{TinyCloudDelegation, TinyCloudRevocation},
    ipld_core::cid::Cid,
    resolver::DID_METHODS,
    ssi::{
        claims::jwt::NumericDate,
        jwk::{Algorithm, JWK},
        ucan::Payload,
    },
    ucan_capabilities_object::Capabilities,
};

type Db = SpaceDatabase<sea_orm::DatabaseConnection, MemoryStore, StaticSecret>;

fn did_vm(key: &JWK) -> (String, String) {
    let did = DID_METHODS.generate(key, "key").unwrap().to_string();
    let vm = format!("{did}#{}", did.rsplit(':').next().unwrap());
    (did, vm)
}

fn now() -> i64 {
    OffsetDateTime::now_utc().unix_timestamp()
}

fn cid_of(token: &str) -> Cid {
    crate::hash::hash(token.as_bytes()).to_cid(0x55)
}

/// `issuer` grants `audience` one `ability` on `resource`, citing `proof`.
fn ucan(
    issuer: &JWK,
    audience: &str,
    resource: &str,
    ability: &str,
    proof: Vec<Cid>,
    expiry: i64,
) -> String {
    let mut caps = Capabilities::<serde_json::Value>::new();
    caps.with_action(
        resource.parse().unwrap(),
        ability.parse().unwrap(),
        [std::collections::BTreeMap::new()],
    );
    Payload::<serde_json::Value> {
        issuer: did_vm(issuer).1.parse().unwrap(),
        audience: audience.parse().unwrap(),
        not_before: Some(NumericDate::try_from_seconds((now() - 60) as f64).unwrap()),
        expiration: NumericDate::try_from_seconds(expiry as f64).unwrap(),
        nonce: Some(format!("tc4321-{}", rand::random::<u64>())),
        facts: None,
        proof,
        attenuation: caps,
    }
    .sign(Algorithm::EdDSA, issuer)
    .unwrap()
    .encode()
    .unwrap()
}

async fn invoke(db: &Db, space: &SpaceId, key: &JWK, proof: Cid) -> Result<(), String> {
    let signed = make_invocation(
        vec![(
            space.clone().to_resource(
                "kv".parse().unwrap(),
                Some("to/b/threads/msg".parse().unwrap()),
                None,
                None,
            ),
            vec!["tinycloud.kv/get".parse().unwrap()],
        )],
        &proof,
        key,
        &did_vm(key).1,
        (now() + 120) as f64,
        InvocationOptions::default(),
    )
    .unwrap();
    let encoded = signed.encode().unwrap().into_bytes();
    let invocation = crate::events::SerializedEvent(
        crate::util::InvocationInfo::try_from(signed).unwrap(),
        encoded,
    );
    db.invoke::<MemoryStaging>(invocation, HashMap::new())
        .await
        .map(|_| ())
        .map_err(|error| error.to_string())
}

#[tokio::test]
async fn revoked_peer_delegation_stays_refused_after_repost_while_own_grant_reads() {
    let dir = tempfile::tempdir().unwrap();
    let url = format!(
        "sqlite://{}?mode=rwc",
        dir.path().join("tc4321.sqlite").display()
    );
    let db: Db = SpaceDatabase::new(
        sea_orm::Database::connect(url).await.unwrap(),
        MemoryStore::default(),
        StaticSecret::new(vec![0x42; 32]).unwrap(),
    )
    .await
    .map_err(|error| error.to_string())
    .unwrap();

    let owner = JWK::generate_ed25519().unwrap();
    let a = JWK::generate_ed25519().unwrap();
    let b = JWK::generate_ed25519().unwrap();
    let space: SpaceId = format!(
        "tinycloud:{}:agents",
        did_vm(&owner).0.strip_prefix("did:").unwrap()
    )
    .parse()
    .unwrap();
    space::ActiveModel {
        id: Set(SpaceIdWrap(space.clone())),
    }
    .insert(&db.conn)
    .await
    .unwrap();
    let kv = |path: &str| {
        space
            .clone()
            .to_resource(
                "kv".parse().unwrap(),
                Some(path.parse().unwrap()),
                None,
                None,
            )
            .to_string()
    };
    let created = now();
    let delegate = |token: String| {
        let db = &db;
        async move {
            db.delegate(Delegation::from_header_ser::<TinyCloudDelegation>(&token).unwrap())
                .await
                .map(|_| ())
                .map_err(|error| error.to_string())
        }
    };

    // Same-owner Courier: the owner grants both agents kv on every mailbox
    // under `to/` (courier AGENT_GRANT), and A grants B its mailbox prefix.
    let root_a = ucan(
        &owner,
        &did_vm(&a).0,
        &kv("to/"),
        "tinycloud.kv/get",
        vec![],
        created + 3600,
    );
    let root_b = ucan(
        &owner,
        &did_vm(&b).0,
        &kv("to/"),
        "tinycloud.kv/get",
        vec![],
        created + 3600,
    );
    let peer = ucan(
        &a,
        &did_vm(&b).0,
        &kv("to/b/threads/"),
        "tinycloud.kv/get",
        vec![cid_of(&root_a)],
        created + 1800,
    );
    for token in [&root_a, &root_b, &peer] {
        delegate(token.clone()).await.unwrap();
    }
    invoke(&db, &space, &b, cid_of(&peer)).await.unwrap();
    invoke(&db, &space, &b, cid_of(&root_b)).await.unwrap();

    // A revokes A -> B with its own root as proof (`revokeIssued`).
    let revocation = ucan(
        &a,
        &did_vm(&owner).0,
        &format!("urn:cid:{}", cid_of(&peer)),
        "tinycloud.delegation/revoke",
        vec![cid_of(&root_a)],
        created + 600,
    );
    db.revoke(Revocation::from_header_ser::<TinyCloudRevocation>(&revocation).unwrap())
        .await
        .map_err(|error| error.to_string())
        .unwrap();

    let refused = |result: Result<(), String>, what: &str| match result {
        Ok(()) => panic!("{what}: the revoked peer delegation still authorized kv/get"),
        Err(error) => assert!(
            error.starts_with("delegation-revoked: "),
            "{what}: unexpected refusal {error}"
        ),
    };
    refused(invoke(&db, &space, &b, cid_of(&peer)).await, "after revoke");

    // A fresh B process posts the revoked bytes again (the node answers Ok,
    // idempotently); the revocation stands.
    let _ = delegate(peer.clone()).await;
    refused(invoke(&db, &space, &b, cid_of(&peer)).await, "after repost");

    // What QA observed: B's own same-owner grant still reads A's mailbox.
    invoke(&db, &space, &b, cid_of(&root_b)).await.unwrap();

    // Only the owner revoking owner -> B cuts that read off.
    let owner_revocation = ucan(
        &owner,
        &did_vm(&owner).0,
        &format!("urn:cid:{}", cid_of(&root_b)),
        "tinycloud.delegation/revoke",
        vec![],
        created + 600,
    );
    db.revoke(Revocation::from_header_ser::<TinyCloudRevocation>(&owner_revocation).unwrap())
        .await
        .map_err(|error| error.to_string())
        .unwrap();
    refused(
        invoke(&db, &space, &b, cid_of(&root_b)).await,
        "owner grant revoked",
    );
    let _ = delegate(root_b.clone()).await;
    refused(
        invoke(&db, &space, &b, cid_of(&root_b)).await,
        "owner grant reposted",
    );
}
