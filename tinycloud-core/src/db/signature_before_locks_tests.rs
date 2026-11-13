//! TC-2986 (E): `/delegate` and `/revoke` check the signature before they
//! take any lock. A badly signed request is refused at once, even while
//! another writer holds the write order of every space it names.
use super::*;
use crate::storage::memory::MemoryStore;
use tinycloud_auth::{
    authorization::{TinyCloudDelegation, TinyCloudRevocation},
    resolver::DID_METHODS,
    ssi::{
        claims::jwt::NumericDate,
        jwk::{Algorithm, JWK},
        ucan::Payload,
    },
    ucan_capabilities_object::Capabilities,
};

fn verification_method(key: &JWK) -> (String, String) {
    let did = DID_METHODS.generate(key, "key").unwrap().to_string();
    let vm = format!("{did}#{}", did.rsplit(':').next().unwrap());
    (did, vm)
}

/// A UCAN issued by `issuer`'s key but signed with `signer`: when they
/// differ, the signature does not verify.
fn ucan(issuer: &JWK, signer: &JWK, audience: &str, resource: &str, ability: &str) -> String {
    let mut caps = Capabilities::<serde_json::Value>::new();
    caps.with_action(
        resource.parse().unwrap(),
        ability.parse().unwrap(),
        [std::collections::BTreeMap::new()],
    );
    let now = OffsetDateTime::now_utc().unix_timestamp();
    Payload::<serde_json::Value> {
        issuer: verification_method(issuer).1.parse().unwrap(),
        audience: audience.parse().unwrap(),
        not_before: Some(NumericDate::try_from_seconds((now - 60) as f64).unwrap()),
        expiration: NumericDate::try_from_seconds((now + 600) as f64).unwrap(),
        nonce: Some(format!("tc2986-{}", rand::random::<u64>())),
        facts: None,
        proof: vec![],
        attenuation: caps,
    }
    .sign(Algorithm::EdDSA, signer)
    .unwrap()
    .encode()
    .unwrap()
}

struct Fixture {
    db: SpaceDatabase<sea_orm::DatabaseConnection, MemoryStore, StaticSecret>,
    owner: JWK,
    holder: String,
    space: SpaceId,
    _directory: tempfile::TempDir,
}

async fn fixture() -> Fixture {
    let directory = tempfile::tempdir().unwrap();
    let url = format!(
        "sqlite://{}?mode=rwc",
        directory.path().join("signatures.sqlite").display()
    );
    let db = SpaceDatabase::new(
        sea_orm::Database::connect(url).await.unwrap(),
        MemoryStore::default(),
        StaticSecret::new(vec![0x42; 32]).unwrap(),
    )
    .await
    .map_err(|error| error.to_string())
    .unwrap();
    let owner = JWK::generate_ed25519().unwrap();
    let (owner_did, _) = verification_method(&owner);
    let (holder, _) = verification_method(&JWK::generate_ed25519().unwrap());
    let space: SpaceId = format!(
        "tinycloud:{}:signatures",
        owner_did.strip_prefix("did:").unwrap()
    )
    .parse()
    .unwrap();
    space::ActiveModel {
        id: Set(SpaceIdWrap(space.clone())),
    }
    .insert(&db.conn)
    .await
    .unwrap();
    Fixture {
        db,
        owner,
        holder,
        space,
        _directory: directory,
    }
}

fn kv_resource(space: &SpaceId) -> String {
    space
        .clone()
        .to_resource(
            "kv".parse().unwrap(),
            Some("docs".parse().unwrap()),
            None,
            None,
        )
        .to_string()
}

#[tokio::test]
async fn a_badly_signed_delegation_is_refused_without_waiting_for_its_space() {
    let fixture = fixture().await;
    let forger = JWK::generate_ed25519().unwrap();
    let token = ucan(
        &fixture.owner,
        &forger,
        &fixture.holder,
        &kv_resource(&fixture.space),
        "tinycloud.kv/get",
    );
    let delegation = Delegation::from_header_ser::<TinyCloudDelegation>(&token).unwrap();

    // Another writer holds the space's write order for the whole check.
    let _held = fixture
        .db
        .acquire_space_sequence_guards(std::slice::from_ref(&fixture.space))
        .await;
    let refused = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        fixture.db.delegate(delegation),
    )
    .await
    .expect("a bad signature is refused before the space's write order");
    assert!(
        matches!(
            refused,
            Err(TxError::InvalidDelegation(
                delegation::DelegationError::InvalidSignature
            ))
        ),
        "{:?}",
        refused.as_ref().map(|_| ()).map_err(ToString::to_string)
    );
}

#[tokio::test]
async fn a_badly_signed_revocation_is_refused_without_waiting_for_its_space() {
    let fixture = fixture().await;
    let granted = ucan(
        &fixture.owner,
        &fixture.owner,
        &fixture.holder,
        &kv_resource(&fixture.space),
        "tinycloud.kv/get",
    );
    fixture
        .db
        .delegate(Delegation::from_header_ser::<TinyCloudDelegation>(&granted).unwrap())
        .await
        .map_err(|error| error.to_string())
        .unwrap();
    let target = crate::hash::hash(granted.as_bytes()).to_cid(0x55);
    let forger = JWK::generate_ed25519().unwrap();
    let (node, _) = verification_method(&JWK::generate_ed25519().unwrap());
    let token = ucan(
        &fixture.owner,
        &forger,
        &node,
        &format!("urn:cid:{target}"),
        "tinycloud.delegation/revoke",
    );
    let revocation = Revocation::from_header_ser::<TinyCloudRevocation>(&token).unwrap();

    let _held = fixture
        .db
        .acquire_space_sequence_guards(std::slice::from_ref(&fixture.space))
        .await;
    let refused = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        fixture.db.revoke(revocation),
    )
    .await
    .expect("a bad signature is refused before the space's write order");
    assert!(
        matches!(
            refused,
            Err(TxError::InvalidRevocation(
                revocation::RevocationError::InvalidSignature
            ))
        ),
        "{:?}",
        refused.as_ref().map(|_| ()).map_err(ToString::to_string)
    );
}
