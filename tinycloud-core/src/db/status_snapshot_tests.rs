//! Commit a genuine renewal between expiry and history reads, without sleeps.
use super::*;
use crate::storage::memory::MemoryStore;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use tinycloud_auth::{
    authorization::{make_invocation_from_uris, InvocationOptions, TinyCloudInvocation},
    resolver::DID_METHODS,
    ssi::{
        claims::jwt::NumericDate,
        jwk::{Algorithm, JWK},
        ucan::Payload,
    },
    ucan_capabilities_object::Capabilities,
};

fn method(key: &JWK) -> (String, String) {
    let did = DID_METHODS.generate(key, "key").unwrap().to_string();
    let vm = format!("{did}#{}", did.rsplit(':').next().unwrap());
    (did, vm)
}

fn signed(
    key: &JWK,
    audience: &str,
    resource: &str,
    ability: &str,
    start: i64,
    end: i64,
) -> String {
    let mut caps = Capabilities::<serde_json::Value>::new();
    caps.with_action(
        resource.parse().unwrap(),
        ability.parse().unwrap(),
        [std::collections::BTreeMap::new()],
    );
    Payload::<serde_json::Value> {
        issuer: method(key).1.parse().unwrap(),
        audience: audience.parse().unwrap(),
        not_before: Some(NumericDate::try_from_seconds(start as f64).unwrap()),
        expiration: NumericDate::try_from_seconds(end as f64).unwrap(),
        nonce: Some(format!("snapshot-{}", rand::random::<u64>())),
        facts: None,
        proof: vec![],
        attenuation: caps,
    }
    .sign(Algorithm::EdDSA, key)
    .unwrap()
    .encode()
    .unwrap()
}

async fn exercise(conn: sea_orm::DatabaseConnection) {
    let secret = StaticSecret::new(vec![0x42; 32]).unwrap();
    let db = SpaceDatabase::new(conn, MemoryStore::default(), secret.clone())
        .await
        .map_err(|error| error.to_string())
        .unwrap();
    let owner_key = JWK::generate_ed25519().unwrap();
    let (owner, _) = method(&owner_key);
    let (holder, _) = method(&JWK::generate_ed25519().unwrap());
    let space: SpaceId = format!("tinycloud:{}:snapshot", owner.strip_prefix("did:").unwrap())
        .parse()
        .unwrap();
    let resource = space
        .to_resource(
            "kv".parse().unwrap(),
            Some("test".parse().unwrap()),
            None,
            None,
        )
        .to_string();
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let original = signed(
        &owner_key,
        &holder,
        &resource,
        "tinycloud.kv/get",
        now - 121,
        now + 120,
    );
    let original_id = crate::hash::hash(original.as_bytes());
    let original_cid = original_id.to_cid(0x55).to_string();
    let lease = signed(
        &owner_key,
        &secret.renewal_did(),
        &format!("urn:cid:{original_cid}"),
        "tinycloud.delegation/renew",
        now - 1,
        now + 600,
    );
    let lease_cid = crate::hash::hash(lease.as_bytes()).to_cid(0x55);
    for token in [original, lease] {
        db.delegate(Delegation::from_header_ser::<TinyCloudDelegation>(&token).unwrap())
            .await
            .map_err(|error| error.to_string())
            .unwrap();
    }
    let seed = secret.derive_key(crate::renewal::RENEWER_KEY_CONTEXT);
    let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
    let renewer_key: JWK = serde_json::from_value(serde_json::json!({
        "kty":"OKP", "crv":"Ed25519", "alg":"EdDSA",
        "x":URL_SAFE_NO_PAD.encode(signing.verifying_key().to_bytes()),
        "d":URL_SAFE_NO_PAD.encode(seed),
    }))
    .unwrap();
    let signed = make_invocation_from_uris(
        [(
            format!("urn:cid:{original_cid}").parse().unwrap(),
            ["tinycloud.delegation/renew".parse().unwrap()],
        )],
        &lease_cid,
        &renewer_key,
        &method(&renewer_key).1,
        (now + 300) as f64,
        InvocationOptions::default(),
    )
    .unwrap();
    let encoded = signed.encode().unwrap();
    let invocation = Invocation::from_header_ser::<TinyCloudInvocation>(&encoded).unwrap();
    let replay_hash = invocation.content_hash();
    let issue = crate::renewal::StampIssue {
        invocation: invocation.0,
        original_cid,
        lease_cid: lease_cid.to_string(),
        replay_hash,
        replay_expires_at: now + 300,
    };
    let snapshot = db
        .delegation_status_snapshot_inner(original_id, &owner, &[], now, async {
            // The read snapshot is established and its expiry is read. Commit on
            // another connection before the history query executes.
            db.issue_renewal_stamp(issue)
                .await
                .map_err(|error| error.to_string())
                .unwrap();
        })
        .await
        .map_err(|error| error.to_string())
        .unwrap()
        .unwrap();
    assert_eq!(snapshot.0, DelegationStatus::Active);
    assert_eq!(snapshot.1, Some(now + 120));
    assert!(
        snapshot.2.is_empty(),
        "old expiry must not be paired with newly committed history"
    );
    let next = db
        .delegation_status_snapshot(
            original_id,
            &owner,
            &[],
            OffsetDateTime::now_utc().unix_timestamp(),
        )
        .await
        .map_err(|error| error.to_string())
        .unwrap()
        .unwrap();
    assert_eq!(next.0, DelegationStatus::Active);
    assert_eq!(next.2.len(), 1);
    assert_eq!(next.1, Some(next.2[0].new_end));
    assert!(next.1.unwrap() > now + 120);
}

#[tokio::test]
async fn sqlite_status_snapshot_excludes_concurrent_renewal_commit() {
    let dir = tempfile::tempdir().unwrap();
    let mut options = sea_orm::ConnectOptions::new(format!(
        "sqlite:{}?mode=rwc",
        dir.path().join("status.db").display()
    ));
    options.max_connections(4);
    let conn = sea_orm::Database::connect(options).await.unwrap();
    conn.execute_unprepared("PRAGMA journal_mode=WAL")
        .await
        .map_err(|error| error.to_string())
        .unwrap();
    exercise(conn).await;
}

#[tokio::test]
async fn postgres_status_snapshot_excludes_concurrent_renewal_commit() {
    let Some(schema) = crate::test_support::PostgresTestSchema::new(
        "postgres_status_snapshot_excludes_concurrent_renewal_commit",
    )
    .await
    else {
        return;
    };
    exercise(schema.conn.clone()).await;
}
