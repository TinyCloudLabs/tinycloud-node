//! Synthetic pre-TC-1149 policies: signed historical bytes, not mocks.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde_json::json;
use std::collections::BTreeMap;
use time::OffsetDateTime;
use tinycloud_auth::{
    authorization::{Cid, HeaderEncode},
    ssi::{
        claims::jwt::NumericDate,
        jwk::{Algorithm, JWK},
        ucan::Payload,
    },
    ucan_capabilities_object::Capabilities,
};
use tinycloud_core::{
    hash::{hash, Hash},
    keys::{public_key_to_did_key, Keypair},
    migrations::Migrator,
    models::{
        abilities, actor, delegation, delegation_cid_alias, policy_v3_registration, policy_v3_root,
        revocation,
    },
    policy_witness::{
        backfill_in_transaction, capture_in_transaction, check_revocations, dry_run_backfill,
        persist_in_transaction, WitnessError,
    },
    relationships::parent_delegations,
    sea_orm::{
        ActiveModelTrait, ActiveValue::Set, ConnectOptions, Database, DatabaseConnection,
        EntityTrait, TransactionTrait,
    },
    sea_orm_migration::MigratorTrait,
    types::{Ability, Caveats, Resource},
};

const ADMISSION: &str = "2026-01-01T00:00:10Z";
const SHORT_EXPIRY: &str = "2026-01-01T00:01:00Z";
const LONG_EXPIRY: &str = "2100-01-01T00:00:00Z";

fn date(value: &str) -> OffsetDateTime {
    OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339).unwrap()
}

fn signer(seed: u8) -> (JWK, String, String) {
    let key = Keypair::ed25519_from_bytes([seed; 32]).unwrap();
    let public = key.clone().try_into_ed25519().unwrap().public().to_bytes();
    let did = public_key_to_did_key(key.public());
    let jwk = serde_json::from_value(json!({
        "kty": "OKP", "crv": "Ed25519", "alg": "EdDSA",
        "x": URL_SAFE_NO_PAD.encode(public),
        "d": URL_SAFE_NO_PAD.encode([seed; 32]),
    }))
    .unwrap();
    let fragment = format!("{did}#{}", did.trim_start_matches("did:key:"));
    (jwk, did, fragment)
}

fn token(
    seed: u8,
    audience: &str,
    resource: &str,
    proof: &[String],
    expires: &str,
    nonce: &str,
    role: Option<&str>,
) -> String {
    let (jwk, _, issuer) = signer(seed);
    let mut caps = Capabilities::<serde_json::Value>::new();
    caps.with_action(
        resource.parse().unwrap(),
        "tinycloud.kv/list".parse().unwrap(),
        [BTreeMap::new()],
    );
    Payload::<serde_json::Value> {
        issuer: issuer.parse().unwrap(),
        audience: audience.parse().unwrap(),
        not_before: Some(
            NumericDate::try_from_seconds((date(ADMISSION).unix_timestamp() - 60) as f64).unwrap(),
        ),
        expiration: NumericDate::try_from_seconds(date(expires).unix_timestamp() as f64).unwrap(),
        nonce: Some(nonce.to_owned()),
        facts: role.map(|role| vec![json!({"xyz.tinycloud.policy/root-profile": {"role": role}})]),
        proof: proof
            .iter()
            .map(|cid| cid.parse::<Cid>().unwrap())
            .collect(),
        attenuation: caps,
    }
    .sign(Algorithm::EdDSA, &jwk)
    .unwrap()
    .encode()
    .unwrap()
}

fn cid(token: &str) -> String {
    hash(token.as_bytes()).to_cid(0x55).to_string()
}

fn canonical_id(token: &str) -> Hash {
    let (_, bytes) = tinycloud_auth::authorization::TinyCloudDelegation::decode(token).unwrap();
    hash(&bytes)
}

fn id(cid: &str) -> Hash {
    Hash::from(cid.parse::<Cid>().unwrap())
}

async fn database() -> DatabaseConnection {
    let opts = ConnectOptions::new("sqlite::memory:")
        .max_connections(1)
        .to_owned();
    let db = Database::connect(opts).await.unwrap();
    Migrator::up(&db, None).await.unwrap();
    db
}

async fn ensure_actor(db: &DatabaseConnection, did: &str) {
    if actor::Entity::find_by_id(did.to_owned())
        .one(db)
        .await
        .unwrap()
        .is_none()
    {
        actor::ActiveModel {
            id: Set(did.to_owned()),
        }
        .insert(db)
        .await
        .unwrap();
    }
}

async fn grant(
    db: &DatabaseConnection,
    seed: u8,
    audience: &str,
    resource: &str,
    proof: &[String],
    nonce: &str,
) -> String {
    let serialized = token(seed, audience, resource, proof, SHORT_EXPIRY, nonce, None);
    let (_, delegator, _) = signer(seed);
    let name = cid(&serialized);
    ensure_actor(db, &delegator).await;
    ensure_actor(db, audience).await;
    delegation::ActiveModel {
        id: Set(id(&name)),
        delegator: Set(delegator),
        delegatee: Set(audience.to_owned()),
        expiry: Set(Some(date(SHORT_EXPIRY))),
        issued_at: Set(None),
        not_before: Set(Some(date(ADMISSION) - time::Duration::seconds(60))),
        facts: Set(None),
        serialization: Set(serialized.as_bytes().to_vec()),
    }
    .insert(db)
    .await
    .unwrap();
    abilities::ActiveModel {
        resource: Set(resource.parse::<Resource>().unwrap()),
        ability: Set(Ability::try_from("tinycloud.kv/list".to_owned()).unwrap()),
        delegation: Set(id(&name)),
        caveats: Set(Caveats::default()),
    }
    .insert(db)
    .await
    .unwrap();
    delegation_cid_alias::ActiveModel {
        id: Set(id(&name)),
        canonical: Set(canonical_id(&serialized)),
        encrypted: Set(false),
    }
    .insert(db)
    .await
    .unwrap();
    for parent in proof {
        parent_delegations::ActiveModel {
            parent: Set(id(parent)),
            child: Set(id(&name)),
        }
        .insert(db)
        .await
        .unwrap();
    }
    name
}

async fn root(db: &DatabaseConnection, owner_seed: u8, resource: &str, role: &str) -> String {
    let serialized = token(
        owner_seed,
        "did:tinycloud:policy:legacy",
        resource,
        &[],
        LONG_EXPIRY,
        role,
        Some(role),
    );
    let name = cid(&serialized);
    let owner = signer(owner_seed).1;
    ensure_actor(db, &owner).await;
    ensure_actor(db, "did:tinycloud:policy:legacy").await;
    // A policy root is parentless by profile, even when its owner is an
    // authorised grantee rather than the owner of this space.
    delegation::ActiveModel {
        id: Set(id(&name)),
        delegator: Set(owner),
        delegatee: Set("did:tinycloud:policy:legacy".to_owned()),
        expiry: Set(Some(date(LONG_EXPIRY))),
        issued_at: Set(None),
        not_before: Set(Some(date(ADMISSION) - time::Duration::seconds(60))),
        facts: Set(None),
        serialization: Set(serialized.as_bytes().to_vec()),
    }
    .insert(db)
    .await
    .unwrap();
    delegation_cid_alias::ActiveModel {
        id: Set(id(&name)),
        canonical: Set(canonical_id(&serialized)),
        encrypted: Set(false),
    }
    .insert(db)
    .await
    .unwrap();
    policy_v3_root::ActiveModel {
        root_cid: Set(name.clone()),
        policy_cid: Set("legacy-policy".into()),
        role: Set(role.to_owned()),
        authorization_bytes: Set(serialized.into_bytes()),
        status_checkpoint_bytes: Set(None),
        previous_checkpoint_digest_hex: Set(None),
        status_sequence: Set(0),
        admission_epoch: Set(0),
        status_checked_at: Set(None),
        status_fresh_until: Set(None),
        revoked_at: Set(None),
        revocation_bytes: Set(None),
    }
    .insert(db)
    .await
    .unwrap();
    name
}

async fn legacy_policy(db: &DatabaseConnection) -> (String, Vec<String>, String, String) {
    let space = signer(1).1;
    let owner = signer(7).1;
    let intermediary = signer(2).1;
    let resource = format!(
        "tinycloud:key:{}:legacy/kv",
        space.trim_start_matches("did:key:")
    );
    let direct = grant(db, 1, &owner, &resource, &[], "direct").await;
    let ancestor = grant(db, 1, &intermediary, &resource, &[], "ancestor").await;
    let chain_tip = grant(db, 2, &owner, &resource, &[ancestor], "chain-tip").await;
    let policy = root(db, 7, &resource, "policy-authority").await;
    let enforcement = root(db, 7, &resource, "policy-enforcement").await;
    policy_v3_registration::ActiveModel {
        policy_cid: Set("legacy-policy".into()),
        policy_bytes: Set(b"{}".to_vec()),
        policy_digest_hex: Set("fixture".into()),
        owner_did: Set(owner.clone()),
        policy_root_cid: Set(policy.clone()),
        enforcement_root_cid: Set(enforcement.clone()),
        content_source_digest_hex: Set("fixture".into()),
        native_projection_hash_hex: Set("fixture".into()),
        attested_enforcer_binding_bytes: Set(b"{}".to_vec()),
        registered_at: Set(ADMISSION.into()),
        expires_at: Set(LONG_EXPIRY.into()),
    }
    .insert(db)
    .await
    .unwrap();
    (owner, vec![policy, enforcement], direct, chain_tip)
}

#[tokio::test]
async fn legacy_short_signin_expiry_does_not_revoke_all_historical_candidates() {
    let db = database().await;
    let (owner, roots, direct, chained) = legacy_policy(&db).await;
    let witnesses =
        capture_in_transaction(&db, "legacy-policy", &owner, &roots, date(ADMISSION), None)
            .await
            .unwrap();
    assert_eq!(witnesses.len(), 2);
    for witness in &witnesses {
        assert_eq!(witness.owner_self_classification, "unknown/legacy");
        assert_eq!(witness.candidates.len(), 2);
        assert!(witness
            .candidates
            .iter()
            .any(|closure| closure.tip_cid == direct));
        assert!(witness
            .candidates
            .iter()
            .any(|closure| closure.tip_cid == chained && closure.contributors.len() == 2));
    }
    persist_in_transaction(&db, &witnesses).await.unwrap();
    assert!(date(SHORT_EXPIRY) < OffsetDateTime::now_utc());
    check_revocations(&db, "legacy-policy", None).await.unwrap();
    let dry = dry_run_backfill(&db, None).await.unwrap();
    assert_eq!(
        (
            dry.policies,
            dry.witnesses,
            dry.missing,
            dry.ambiguous,
            dry.overflow
        ),
        (1, 2, 0, 0, 0)
    );
    let tx = db.begin().await.unwrap();
    backfill_in_transaction(&tx, None).await.unwrap();
    tx.rollback().await.unwrap();
}

#[tokio::test]
async fn expired_signed_ancestor_remains_a_revocation_dependency_without_expiry_denial() {
    let db = database().await;
    let (owner, roots, direct, chained) = legacy_policy(&db).await;
    let after_signin_expired = date(SHORT_EXPIRY) + time::Duration::seconds(1);
    let witnesses = capture_in_transaction(
        &db,
        "legacy-policy",
        &owner,
        &roots,
        after_signin_expired,
        None,
    )
    .await
    .unwrap();
    for witness in &witnesses {
        assert!(witness
            .candidates
            .iter()
            .any(|candidate| candidate.tip_cid == direct));
        assert!(witness
            .candidates
            .iter()
            .any(|candidate| candidate.tip_cid == chained && candidate.contributors.len() == 2));
    }
}

#[tokio::test]
async fn revoking_one_of_multiple_historical_candidates_denies_the_policy() {
    let db = database().await;
    let (owner, roots, direct, chained) = legacy_policy(&db).await;
    let witnesses =
        capture_in_transaction(&db, "legacy-policy", &owner, &roots, date(ADMISSION), None)
            .await
            .unwrap();
    assert!(witnesses.iter().all(|witness| witness
        .candidates
        .iter()
        .any(|candidate| candidate.tip_cid == chained)));
    persist_in_transaction(&db, &witnesses).await.unwrap();
    revocation::ActiveModel {
        id: Set(hash(b"historical-direct-cutoff")),
        revoker: Set(signer(1).1),
        revoked: Set(id(&direct)),
        serialization: Set(Vec::new()),
        revoked_at: Set(Some(OffsetDateTime::now_utc())),
    }
    .insert(&db)
    .await
    .unwrap();
    assert!(matches!(
        check_revocations(&db, "legacy-policy", None).await,
        Err(WitnessError::Revoked)
    ));
}

#[tokio::test]
async fn a_policy_cannot_borrow_another_owners_signed_candidates() {
    let db = database().await;
    let (_owner, roots, _, _) = legacy_policy(&db).await;
    let unrelated = signer(9).1;
    assert!(matches!(
        capture_in_transaction(
            &db,
            "legacy-policy",
            &unrelated,
            &roots,
            date(ADMISSION),
            None
        )
        .await,
        Err(WitnessError::Ambiguous)
    ));
}

#[tokio::test]
async fn legacy_missing_signed_dependency_fails_closed() {
    let db = database().await;
    let (owner, roots, direct, _) = legacy_policy(&db).await;
    delegation_cid_alias::Entity::delete_by_id(id(&direct))
        .exec(&db)
        .await
        .unwrap();
    assert!(matches!(
        capture_in_transaction(&db, "legacy-policy", &owner, &roots, date(ADMISSION), None).await,
        Err(WitnessError::Missing)
    ));
    let counts = dry_run_backfill(&db, None).await.unwrap();
    assert_eq!(counts.missing, 1);
}

#[tokio::test]
async fn legacy_spoofed_proof_edge_is_ambiguous() {
    let db = database().await;
    let (owner, roots, direct, _) = legacy_policy(&db).await;
    parent_delegations::ActiveModel {
        parent: Set(id(&roots[0])),
        child: Set(id(&direct)),
    }
    .insert(&db)
    .await
    .unwrap();
    assert!(matches!(
        capture_in_transaction(&db, "legacy-policy", &owner, &roots, date(ADMISSION), None).await,
        Err(WitnessError::Ambiguous)
    ));
    assert_eq!(dry_run_backfill(&db, None).await.unwrap().ambiguous, 1);
}

#[tokio::test]
async fn legacy_candidate_overflow_is_never_silently_narrowed() {
    let db = database().await;
    let (owner, roots, _, _) = legacy_policy(&db).await;
    let resource = format!(
        "tinycloud:key:{}:legacy/kv",
        signer(1).1.trim_start_matches("did:key:")
    );
    for index in 0..64 {
        grant(
            &db,
            1,
            &owner,
            &resource,
            &[],
            &format!("candidate-{index}"),
        )
        .await;
    }
    assert!(matches!(
        capture_in_transaction(&db, "legacy-policy", &owner, &roots, date(ADMISSION), None).await,
        Err(WitnessError::Overflow)
    ));
    assert_eq!(dry_run_backfill(&db, None).await.unwrap().overflow, 1);
}
