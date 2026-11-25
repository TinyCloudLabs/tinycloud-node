//! TC-4366: the two encodings of an ECDSA UCAN, `(r, s)` and `(r, n - s)`,
//! name one delegation. Once one encoding is revoked, the other is refused at
//! registration, by the PostgreSQL insert guard and by the SQLite path alike.
use super::purge_readmission_tests::{cid_of, deleg, key, token};
use super::*;
use crate::models::revocation::RevocationCode;
use crate::storage::memory::MemoryStore;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use std::collections::BTreeMap;
use tinycloud_auth::{
    authorization::TinyCloudRevocation,
    resolver::DID_METHODS,
    ssi::{
        claims::jwt::NumericDate,
        jwk::{Algorithm, JWK},
        ucan::Payload,
    },
    ucan_capabilities_object::Capabilities,
};

/// The two encodings of one `tinycloud.kv/get` delegation that `jwk` signs
/// with `algorithm` (ES256 or ES256K): (low-S, high-S). Both verify; only the
/// high-S one has a canonical hash that differs from its stored id.
pub(super) fn ecdsa_encodings(
    jwk: &JWK,
    algorithm: Algorithm,
    audience: &str,
    resource: &str,
    parents: &[Hash],
    exp: i64,
) -> (String, String) {
    ecdsa_signed(
        jwk,
        algorithm,
        audience,
        resource,
        "tinycloud.kv/get",
        parents,
        &format!("{algorithm:?} child"),
        exp,
    )
}

/// The (low-S, high-S) encodings of one delegation of `ability` that `jwk`
/// signs with `algorithm`.
#[allow(clippy::too_many_arguments)]
fn ecdsa_signed(
    jwk: &JWK,
    algorithm: Algorithm,
    audience: &str,
    resource: &str,
    ability: &str,
    parents: &[Hash],
    nonce: &str,
    exp: i64,
) -> (String, String) {
    let did = DID_METHODS.generate(jwk, "key").unwrap().to_string();
    let method = format!("{did}#{}", did.rsplit(':').next().unwrap());
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let mut caps = Capabilities::<serde_json::Value>::new();
    caps.with_action(
        resource.parse().unwrap(),
        ability.parse().unwrap(),
        [BTreeMap::new()],
    );
    let token = Payload::<serde_json::Value> {
        issuer: method.parse().unwrap(),
        audience: audience.parse().unwrap(),
        not_before: Some(NumericDate::try_from_seconds((now - 5) as f64).unwrap()),
        expiration: NumericDate::try_from_seconds(exp as f64).unwrap(),
        nonce: Some(nonce.to_owned()),
        facts: None,
        proof: parents.iter().map(|id| id.to_cid(0x55)).collect(),
        attenuation: caps,
    }
    .sign(algorithm, jwk)
    .unwrap()
    .encode()
    .unwrap();
    both_encodings(&token, algorithm)
}

/// The (low-S, high-S) encodings of `token`, an ECDSA-signed JWS.
fn both_encodings(token: &str, algorithm: Algorithm) -> (String, String) {
    let (signed, signature) = token.rsplit_once('.').unwrap();
    let signature = URL_SAFE_NO_PAD.decode(signature).unwrap();
    let (low, high) = match algorithm {
        Algorithm::ES256 => {
            let signature = p256::ecdsa::Signature::from_slice(&signature).unwrap();
            let (r, s) = signature.split_scalars();
            let twin = p256::ecdsa::Signature::from_scalars(r, -s).unwrap();
            match signature.normalize_s() {
                None => (signature.to_vec(), twin.to_vec()),
                Some(_) => (twin.to_vec(), signature.to_vec()),
            }
        }
        Algorithm::ES256K => {
            let signature = k256::ecdsa::Signature::from_slice(&signature).unwrap();
            let (r, s) = signature.split_scalars();
            let twin = k256::ecdsa::Signature::from_scalars(r, -s).unwrap();
            match signature.normalize_s() {
                None => (signature.to_vec(), twin.to_vec()),
                Some(_) => (twin.to_vec(), signature.to_vec()),
            }
        }
        other => panic!("no second encoding for {other:?}"),
    };
    let encode = |signature: Vec<u8>| format!("{signed}.{}", URL_SAFE_NO_PAD.encode(signature));
    (encode(low), encode(high))
}

/// An owner grants `kv` to an ECDSA holder, the holder delegates it on in
/// one encoding, and the owner revokes that encoding. The other encoding is
/// refused as revoked and is not stored.
async fn twin_of_a_revoked_encoding_is_refused(
    conn: sea_orm::DatabaseConnection,
    jwk: JWK,
    algorithm: Algorithm,
    revoke_high: bool,
) {
    let db = SpaceDatabase::new(
        conn.clone(),
        MemoryStore::default(),
        StaticSecret::new(vec![0x42; 32]).unwrap(),
    )
    .await
    .map_err(|error| error.to_string())
    .unwrap();
    let (_, owner_did, _) = key(0x11);
    let (_, holder2, _) = key(0x22);
    let holder1 = DID_METHODS.generate(&jwk, "key").unwrap().to_string();
    let space: SpaceId = format!(
        "tinycloud:{}:default",
        owner_did.strip_prefix("did:").unwrap()
    )
    .parse()
    .unwrap();
    let kv = space
        .clone()
        .to_resource(
            "kv".parse().unwrap(),
            Some("docs".parse().unwrap()),
            None,
            None,
        )
        .to_string();
    let host = space
        .clone()
        .to_resource("space".parse().unwrap(), None, None, None)
        .to_string();
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let host_token = token(
        0x11,
        &owner_did,
        &host,
        "tinycloud.space/host",
        &[],
        "host",
        now + 3600,
    );
    let root = token(
        0x11,
        &holder1,
        &kv,
        "tinycloud.kv/get",
        &[],
        "root",
        now + 3600,
    );
    let (low, high) = ecdsa_encodings(&jwk, algorithm, &holder2, &kv, &[cid_of(&root)], now + 3000);
    let (revoked, twin) = if revoke_high {
        (high, low)
    } else {
        (low, high)
    };
    for t in [&host_token, &root, &revoked] {
        db.delegate(deleg(t))
            .await
            .map_err(|error| error.to_string())
            .unwrap();
    }
    let revocation = token(
        0x11,
        &owner_did,
        &format!("urn:cid:{}", cid_of(&revoked).to_cid(0x55)),
        "tinycloud.delegation/revoke",
        &[],
        "revoke-one-encoding",
        now + 600,
    );
    db.revoke(Revocation::from_header_ser::<TinyCloudRevocation>(&revocation).unwrap())
        .await
        .map_err(|error| error.to_string())
        .unwrap();

    let what = format!("{algorithm:?}, revoked the high-S encoding: {revoke_high}");
    match db.delegate(deleg(&twin)).await {
        Ok(_) => panic!("{what}: the twin of a revoked encoding was admitted"),
        Err(error) => assert_eq!(
            error.revocation_code(),
            Some(RevocationCode::DelegationRevoked),
            "{what}: {error}"
        ),
    }
    assert!(
        crate::models::delegation::Entity::find_by_id(cid_of(&twin))
            .one(&conn)
            .await
            .unwrap()
            .is_none(),
        "{what}: the twin is not stored"
    );
}

/// Each curve, revoking either encoding first.
const CASES: [(Algorithm, bool); 4] = [
    (Algorithm::ES256, false),
    (Algorithm::ES256, true),
    (Algorithm::ES256K, false),
    (Algorithm::ES256K, true),
];

fn generate(algorithm: Algorithm) -> JWK {
    match algorithm {
        Algorithm::ES256 => JWK::generate_p256(),
        _ => JWK::generate_secp256k1(),
    }
}

#[tokio::test]
async fn twin_of_a_revoked_encoding_is_refused_on_sqlite() {
    for (case, (algorithm, revoke_high)) in CASES.into_iter().enumerate() {
        let directory = tempfile::tempdir().unwrap();
        let url = format!(
            "sqlite://{}?mode=rwc",
            directory
                .path()
                .join(format!("twin-{case}.sqlite"))
                .display()
        );
        let conn = sea_orm::Database::connect(url).await.unwrap();
        twin_of_a_revoked_encoding_is_refused(conn, generate(algorithm), algorithm, revoke_high)
            .await;
    }
}

/// CI-only: needs `TINYCLOUD_TEST_POSTGRES_URL`. Exercises the insert guard
/// of `delegation::save`'s PostgreSQL statement.
#[tokio::test]
async fn postgres_twin_of_a_revoked_encoding_is_refused() {
    for (algorithm, revoke_high) in CASES {
        let Some(fixture) = crate::test_support::PostgresTestSchema::new(
            "postgres_twin_of_a_revoked_encoding_is_refused",
        )
        .await
        else {
            return;
        };
        twin_of_a_revoked_encoding_is_refused(
            fixture.conn.clone(),
            generate(algorithm),
            algorithm,
            revoke_high,
        )
        .await;
    }
}

/// A renewal lease must not stand while its original, or an ancestor of it,
/// is revoked in its other encoding. Two high-S chains: (a) the original is
/// the high-S encoding and its low-S twin is revoked; (b) the original's
/// parent is high-S and the parent's low-S twin is revoked. In both, the
/// lease no longer serves the original and re-registering it is refused.
async fn lease_of_an_original_whose_twin_is_revoked(conn: sea_orm::DatabaseConnection) {
    let db = SpaceDatabase::new(
        conn.clone(),
        MemoryStore::default(),
        StaticSecret::new(vec![0x42; 32]).unwrap(),
    )
    .await
    .map_err(|error| error.to_string())
    .unwrap();
    let identity = db.renewal_identity().unwrap().clone();
    let (_, owner_did, _) = key(0x11);
    let (_, holder1, _) = key(0x21);
    let (_, holder2, _) = key(0x22);
    let (_, holder3, _) = key(0x23);
    let ecdsa = JWK::generate_p256();
    let ecdsa_did = DID_METHODS.generate(&ecdsa, "key").unwrap().to_string();
    let space: SpaceId = format!(
        "tinycloud:{}:default",
        owner_did.strip_prefix("did:").unwrap()
    )
    .parse()
    .unwrap();
    let kv = space
        .clone()
        .to_resource(
            "kv".parse().unwrap(),
            Some("docs".parse().unwrap()),
            None,
            None,
        )
        .to_string();
    let host = space
        .clone()
        .to_resource("space".parse().unwrap(), None, None, None)
        .to_string();
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let host_token = token(
        0x11,
        &owner_did,
        &host,
        "tinycloud.space/host",
        &[],
        "host",
        now + 3600,
    );
    let root = token(
        0x11,
        &ecdsa_did,
        &kv,
        "tinycloud.kv/get",
        &[],
        "root",
        now + 3600,
    );
    let urn = |token: &str| format!("urn:cid:{}", cid_of(token).to_cid(0x55));
    // (a) The original is high-S.
    let (original_a_low, original_a) = ecdsa_signed(
        &ecdsa,
        Algorithm::ES256,
        &holder2,
        &kv,
        "tinycloud.kv/get",
        &[cid_of(&root)],
        "original-a",
        now + 3000,
    );
    let lease_a = ecdsa_signed(
        &ecdsa,
        Algorithm::ES256,
        &identity.renewer_did,
        &urn(&original_a),
        "tinycloud.delegation/renew",
        &[],
        "lease-a",
        now + 7200,
    )
    .0;
    // (b) The original's parent is high-S.
    let (parent_b_low, parent_b) = ecdsa_signed(
        &ecdsa,
        Algorithm::ES256,
        &holder1,
        &kv,
        "tinycloud.kv/get",
        &[cid_of(&root)],
        "parent-b",
        now + 3000,
    );
    let original_b = token(
        0x21,
        &holder3,
        &kv,
        "tinycloud.kv/get",
        &[cid_of(&parent_b)],
        "original-b",
        now + 2000,
    );
    let lease_b = token(
        0x21,
        &identity.renewer_did,
        &urn(&original_b),
        "tinycloud.delegation/renew",
        &[],
        "lease-b",
        now + 7200,
    );
    for t in [
        &host_token,
        &root,
        &original_a,
        &original_a_low,
        &lease_a,
        &parent_b,
        &parent_b_low,
        &original_b,
        &lease_b,
    ] {
        db.delegate(deleg(t))
            .await
            .map_err(|error| error.to_string())
            .unwrap();
    }
    let lease_for = |original: &str| {
        let original = cid_of(original).to_cid(0x55).to_string();
        let conn = conn.clone();
        let identity = identity.clone();
        async move {
            crate::renewal::lease_for_original(&conn, &original, &identity)
                .await
                .unwrap()
                .map(|lease| lease.lease_cid)
        }
    };
    for (original, lease) in [(&original_a, &lease_a), (&original_b, &lease_b)] {
        assert_eq!(
            lease_for(original).await,
            Some(cid_of(lease).to_cid(0x55).to_string()),
            "the lease serves its original before any revocation"
        );
    }

    for (revoked, nonce) in [(&original_a_low, "revoke-a"), (&parent_b_low, "revoke-b")] {
        let revocation = token(
            0x11,
            &owner_did,
            &urn(revoked),
            "tinycloud.delegation/revoke",
            &[],
            nonce,
            now + 600,
        );
        db.revoke(Revocation::from_header_ser::<TinyCloudRevocation>(&revocation).unwrap())
            .await
            .map_err(|error| error.to_string())
            .unwrap();
    }
    for (case, original, lease) in [
        ("(a) the original's twin", &original_a, &lease_a),
        ("(b) the parent's twin", &original_b, &lease_b),
    ] {
        assert_eq!(
            lease_for(original).await,
            None,
            "{case} is revoked: the lease no longer serves the original"
        );
        match db.delegate(deleg(lease)).await {
            Ok(_) => panic!("{case} is revoked: re-registering the lease succeeded"),
            Err(TxError::Renewal(crate::renewal::RenewalStoreError::Revoked)) => {}
            Err(error) => assert_eq!(
                error.revocation_code(),
                Some(RevocationCode::DelegationRevoked),
                "{case} is revoked: {error}"
            ),
        }
    }
}

#[tokio::test]
async fn lease_of_an_original_whose_twin_is_revoked_on_sqlite() {
    let directory = tempfile::tempdir().unwrap();
    let url = format!(
        "sqlite://{}?mode=rwc",
        directory.path().join("twin-lease.sqlite").display()
    );
    lease_of_an_original_whose_twin_is_revoked(sea_orm::Database::connect(url).await.unwrap())
        .await;
}

/// CI-only: needs `TINYCLOUD_TEST_POSTGRES_URL`.
#[tokio::test]
async fn postgres_lease_of_an_original_whose_twin_is_revoked() {
    let Some(fixture) = crate::test_support::PostgresTestSchema::new(
        "postgres_lease_of_an_original_whose_twin_is_revoked",
    )
    .await
    else {
        return;
    };
    lease_of_an_original_whose_twin_is_revoked(fixture.conn.clone()).await;
}

/// A Policy/v3 root registered under both of its encodings stops authorizing
/// under either once one encoding's registry row is revoked, and reads as
/// revoked in the status and account views. The registry rows are inserted
/// directly, as the invocation tests do.
async fn policy_root_whose_twin_is_revoked(conn: sea_orm::DatabaseConnection) {
    use crate::models::policy_v3_root;
    use sea_orm::{ActiveModelTrait, Set};
    use sea_orm_migration::MigratorTrait;
    crate::migrations::Migrator::up(&conn, None).await.unwrap();
    let (_, owner_did, _) = key(0x11);
    let holder_key = JWK::generate_p256();
    let holder = DID_METHODS
        .generate(&holder_key, "key")
        .unwrap()
        .to_string();
    let method = format!("{holder}#{}", holder.rsplit(':').next().unwrap());
    let space: SpaceId = format!(
        "tinycloud:{}:default",
        owner_did.strip_prefix("did:").unwrap()
    )
    .parse()
    .unwrap();
    let kv = space
        .clone()
        .to_resource(
            "kv".parse().unwrap(),
            Some("docs".parse().unwrap()),
            None,
            None,
        )
        .to_string();
    let now = OffsetDateTime::now_utc();
    let signed = |audience: &str, parents: Vec<_>, facts: Option<Vec<serde_json::Value>>| {
        let mut caps = Capabilities::<serde_json::Value>::new();
        caps.with_action(
            kv.parse().unwrap(),
            "tinycloud.kv/get".parse().unwrap(),
            [BTreeMap::new()],
        );
        Payload::<serde_json::Value> {
            issuer: method.parse().unwrap(),
            audience: audience.parse().unwrap(),
            not_before: Some(
                NumericDate::try_from_seconds((now.unix_timestamp() - 5) as f64).unwrap(),
            ),
            expiration: NumericDate::try_from_seconds((now.unix_timestamp() + 300) as f64).unwrap(),
            nonce: None,
            facts,
            proof: parents,
            attenuation: caps,
        }
        .sign(Algorithm::ES256, &holder_key)
        .unwrap()
        .encode()
        .unwrap()
    };
    let facts = serde_json::json!({
        "role": "policy-authority", "mode": "policy-source", "ownerDid": holder,
        "policyId": "test-policy", "policyDigestHex": "test-digest", "policyCid": "test-policy-cid",
        "contentSourceDigestHex": "test-source", "capabilityCeilingHashHex": "test-ceiling",
        "nativeProjectionHashHex": "test-projection", "nodeAudience": owner_did,
    });
    let (low, high) = both_encodings(
        &signed(&holder, vec![], Some(vec![facts])),
        Algorithm::ES256,
    );
    for root in [&low, &high] {
        crate::models::delegation::process(&conn, &deleg(root), None)
            .await
            .unwrap();
        policy_v3_root::ActiveModel {
            root_cid: Set(cid_of(root).to_cid(0x55).to_string()),
            policy_cid: Set("test-policy-cid".into()),
            role: Set("policy-authority".into()),
            authorization_bytes: Set(vec![]),
            status_checkpoint_bytes: Set(None),
            previous_checkpoint_digest_hex: Set(None),
            status_sequence: Set(1),
            admission_epoch: Set(0),
            status_checked_at: Set(None),
            status_fresh_until: Set(None),
            revoked_at: Set(None),
            revocation_bytes: Set(None),
        }
        .insert(&conn)
        .await
        .unwrap();
    }
    let invocation = |root: &str| {
        crate::util::InvocationInfo::try_from(
            tinycloud_auth::authorization::TinyCloudInvocation::decode(&signed(
                &owner_did,
                vec![cid_of(root).to_cid(0x55)],
                None,
            ))
            .unwrap(),
        )
        .unwrap()
    };
    for root in [&low, &high] {
        crate::models::invocation::verify_and_authorize(&conn, &invocation(root), now)
            .await
            .unwrap();
    }

    policy_v3_root::ActiveModel {
        root_cid: Set(cid_of(&high).to_cid(0x55).to_string()),
        revoked_at: Set(Some("2026-01-01T00:00:00Z".into())),
        revocation_bytes: Set(Some(vec![1])),
        ..Default::default()
    }
    .update(&conn)
    .await
    .unwrap();
    let mut failures = Vec::new();
    for (what, root) in [("the revoked encoding", &high), ("its twin", &low)] {
        let id = cid_of(root);
        if crate::models::invocation::verify_and_authorize(&conn, &invocation(root), now)
            .await
            .is_ok()
        {
            failures.push(format!("{what}: an invocation under it is authorized"));
        }
        if !crate::models::revocation::chain_revoked(&conn, &id, &id)
            .await
            .unwrap()
        {
            failures.push(format!("{what}: the status view reads it as not revoked"));
        }
        if !super::load_account_ancestor_state(&conn, &[id])
            .await
            .unwrap()
            .policy_revocations
            .contains(&id)
        {
            failures.push(format!("{what}: the account view reads it as not revoked"));
        }
    }
    assert!(failures.is_empty(), "revoked policy root: {failures:#?}");
}

#[tokio::test]
async fn policy_root_whose_twin_is_revoked_on_sqlite() {
    let directory = tempfile::tempdir().unwrap();
    let url = format!(
        "sqlite://{}?mode=rwc",
        directory.path().join("twin-policy-root.sqlite").display()
    );
    policy_root_whose_twin_is_revoked(sea_orm::Database::connect(url).await.unwrap()).await;
}

/// CI-only: needs `TINYCLOUD_TEST_POSTGRES_URL`.
#[tokio::test]
async fn postgres_policy_root_whose_twin_is_revoked() {
    let Some(fixture) =
        crate::test_support::PostgresTestSchema::new("postgres_policy_root_whose_twin_is_revoked")
            .await
    else {
        return;
    };
    policy_root_whose_twin_is_revoked(fixture.conn.clone()).await;
}

/// A stored UCAN the current decoder rejects keeps the alias every older image
/// computed (the boot step counts it as `undecodable`). Keeping that alias
/// cannot make its twin work: the twin shares the rejected header and payload,
/// so it cannot be parsed, admitted or cited. The row is written directly,
/// as an older decoder would have admitted it.
async fn undecodable_row_and_its_twin(conn: sea_orm::DatabaseConnection) {
    // Opening the database migrates it and applies the current alias rule.
    let _db = SpaceDatabase::new(
        conn.clone(),
        MemoryStore::default(),
        StaticSecret::new(vec![0x42; 32]).unwrap(),
    )
    .await
    .map_err(|error| error.to_string())
    .unwrap();
    let owner_key = JWK::generate_p256();
    let owner = DID_METHODS.generate(&owner_key, "key").unwrap().to_string();
    let (_, holder, _) = key(0x22);
    let space: SpaceId = format!("tinycloud:{}:default", owner.strip_prefix("did:").unwrap())
        .parse()
        .unwrap();
    let kv = space
        .clone()
        .to_resource(
            "kv".parse().unwrap(),
            Some("docs".parse().unwrap()),
            None,
            None,
        )
        .to_string();
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let (low, high) = ecdsa_signed(
        &owner_key,
        Algorithm::ES256,
        &holder,
        &kv,
        "tinycloud.kv/get",
        &[],
        "undecodable",
        now + 3600,
    );
    // The same signed header and signatures over a payload without `att`,
    // which the current decoder rejects.
    let without_att = |token: &str| {
        let mut parts = token.split('.');
        let (header, payload, signature) = (
            parts.next().unwrap(),
            parts.next().unwrap(),
            parts.next().unwrap(),
        );
        let mut payload: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap();
        payload.as_object_mut().unwrap().remove("att");
        let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
        format!("{header}.{payload}.{signature}")
    };
    let (stored, twin) = (without_att(&high), without_att(&low));
    assert!(
        <TinyCloudDelegation as tinycloud_auth::authorization::HeaderEncode>::decode(&stored)
            .is_err(),
        "the stored row is undecodable"
    );
    let id = cid_of(&stored);
    let bytes = |hash: Hash| -> sea_orm::Value { Vec::<u8>::from(hash).into() };
    let backend = conn.get_database_backend();
    for (sql, values) in [
        ("INSERT INTO actor (id) VALUES ($1)", vec![owner.clone().into()]),
        ("INSERT INTO actor (id) VALUES ($1)", vec![holder.clone().into()]),
        (
            "INSERT INTO delegation (id, delegator, delegatee, expiry, serialization, serialization_format) VALUES ($1, $2, $3, $4, $5, 0)",
            vec![
                bytes(id),
                owner.clone().into(),
                holder.clone().into(),
                OffsetDateTime::from_unix_timestamp(now + 3600).unwrap().into(),
                stored.as_bytes().to_vec().into(),
            ],
        ),
        (
            "INSERT INTO delegation_cid_alias (id, canonical, encrypted) VALUES ($1, $1, FALSE)",
            vec![bytes(id)],
        ),
        (
            "INSERT INTO ability (resource, ability, delegation, caveats) VALUES ($1, 'tinycloud.kv/get', $2, '{}')",
            vec![kv.clone().into(), bytes(id)],
        ),
        ("DELETE FROM delegation_cid_alias_rule", vec![]),
    ] {
        conn.execute(Statement::from_sql_and_values(backend, sql, values))
            .await
            .unwrap();
    }
    crate::models::delegation_cid_alias::recompute(&conn, None)
        .await
        .unwrap();
    let canonical: Vec<u8> = conn
        .query_one(Statement::from_sql_and_values(
            backend,
            "SELECT canonical FROM delegation_cid_alias WHERE id = $1",
            [bytes(id)],
        ))
        .await
        .unwrap()
        .unwrap()
        .try_get("", "canonical")
        .unwrap();
    assert_eq!(
        canonical,
        Vec::<u8>::from(id),
        "the boot step keeps the alias of an undecodable row"
    );

    assert!(
        Delegation::from_header_ser::<TinyCloudDelegation>(&twin).is_err(),
        "the twin cannot be parsed for admission"
    );
    let twin_id = cid_of(&twin);
    assert!(
        crate::models::delegation::Entity::find_by_id(twin_id)
            .one(&conn)
            .await
            .unwrap()
            .is_none(),
        "the twin is not stored"
    );
    let invoke = |parent: Hash| {
        crate::util::InvocationInfo::try_from(
            tinycloud_auth::authorization::TinyCloudInvocation::decode(&token(
                0x22,
                &owner,
                &kv,
                "tinycloud.kv/get",
                &[parent],
                "invoke",
                now + 300,
            ))
            .unwrap(),
        )
        .unwrap()
    };
    let now = OffsetDateTime::now_utc();
    assert!(
        crate::models::invocation::verify_and_authorize(&conn, &invoke(twin_id), now)
            .await
            .is_err(),
        "an invocation citing the twin is refused"
    );
}

#[tokio::test]
async fn undecodable_row_keeps_its_alias_and_its_twin_cannot_work_on_sqlite() {
    let directory = tempfile::tempdir().unwrap();
    let url = format!(
        "sqlite://{}?mode=rwc",
        directory.path().join("undecodable.sqlite").display()
    );
    undecodable_row_and_its_twin(sea_orm::Database::connect(url).await.unwrap()).await;
}

/// CI-only: needs `TINYCLOUD_TEST_POSTGRES_URL`.
#[tokio::test]
async fn postgres_undecodable_row_keeps_its_alias_and_its_twin_cannot_work() {
    let Some(fixture) = crate::test_support::PostgresTestSchema::new(
        "postgres_undecodable_row_keeps_its_alias_and_its_twin_cannot_work",
    )
    .await
    else {
        return;
    };
    undecodable_row_and_its_twin(fixture.conn.clone()).await;
}
