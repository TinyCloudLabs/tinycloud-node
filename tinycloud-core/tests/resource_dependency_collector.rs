use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, Database, DatabaseConnection, IntoActiveModel,
    TransactionTrait,
};
use std::collections::{BTreeMap, BTreeSet};
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
    hash::hash,
    migrations::Migrator,
    models::{abilities, actor, delegation},
    resource_purge_dependencies::collect_target_dependencies,
    resource_purge_fence::ResourceTarget,
    sea_orm_migration::MigratorTrait,
};

fn principal() -> (JWK, String) {
    let key = JWK::generate_ed25519().unwrap();
    let did = DID_METHODS.generate(&key, "key").unwrap().to_string();
    (key, did)
}
async fn db() -> DatabaseConnection {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    Migrator::up(&db, None).await.unwrap();
    db
}
async fn grant(
    db: &DatabaseConnection,
    key: &JWK,
    owner: &str,
    recipient: &str,
    resource: &str,
    ttl: i64,
) {
    for did in [owner, recipient] {
        if actor::Entity::find_by_id(did)
            .one(db)
            .await
            .unwrap()
            .is_none()
        {
            actor::ActiveModel {
                id: Set(did.into()),
            }
            .insert(db)
            .await
            .unwrap();
        }
    }
    let mut caps = Capabilities::new();
    caps.with_action(
        resource.parse().unwrap(),
        "tinycloud.encryption/decrypt".parse().unwrap(),
        [BTreeMap::<String, serde_json::Value>::new()],
    );
    let expiry = OffsetDateTime::now_utc() + time::Duration::seconds(ttl);
    let encoded = Payload::<serde_json::Value, serde_json::Value> {
        issuer: format!("{owner}#{}", owner.trim_start_matches("did:key:"))
            .parse()
            .unwrap(),
        audience: recipient.parse().unwrap(),
        not_before: None,
        expiration: NumericDate::try_from_seconds(expiry.unix_timestamp() as f64).unwrap(),
        nonce: None,
        facts: None,
        proof: vec![],
        attenuation: caps,
    }
    .sign(Algorithm::EdDSA, key)
    .unwrap()
    .encode()
    .unwrap()
    .into_bytes();
    let id = hash(&encoded);
    delegation::Model {
        id,
        delegator: owner.into(),
        delegatee: recipient.into(),
        expiry: Some(expiry),
        issued_at: None,
        not_before: None,
        facts: None,
        serialization: encoded,
        serialization_format: 0,
    }
    .into_active_model()
    .insert(db)
    .await
    .unwrap();
    abilities::ActiveModel {
        delegation: Set(id),
        resource: Set(resource.parse().unwrap()),
        ability: Set("tinycloud.encryption/decrypt"
            .to_owned()
            .try_into()
            .unwrap()),
        caveats: Set(Default::default()),
    }
    .insert(db)
    .await
    .unwrap();
}
use sea_orm::EntityTrait;

#[tokio::test]
async fn generic_grants_are_ambiguous_not_zero_and_scope_is_exact() {
    generic_matrix(&db().await).await;
}
async fn generic_matrix(db: &DatabaseConnection) {
    let (key, owner) = principal();
    let (_, recipient) = principal();
    let (_, node) = principal();
    let network = format!("urn:tinycloud:encryption:{owner}:default");
    grant(
        db,
        &key,
        &owner,
        &recipient,
        &format!("{network}/first"),
        600,
    )
    .await;
    grant(
        db,
        &key,
        &owner,
        &recipient,
        &format!("{network}/second"),
        -30,
    )
    .await;
    let nodes = BTreeSet::from([node]);
    let tx = db.begin().await.unwrap();
    let first = collect_target_dependencies(
        &tx,
        &ResourceTarget::parse(&format!("{network}/first")).unwrap(),
        &nodes,
        OffsetDateTime::now_utc(),
        None,
        None,
    )
    .await
    .unwrap();
    assert_eq!(first.ambiguous_count(), 1);
    assert_eq!(first.proven_outside_count(), 0);
    assert_eq!(first.dependent_resource_count(), 1);
    assert!(!first.is_verified_zero());
    assert_eq!(first.full_union_snapshot().unwrap().dependent_count(), 1);
    let second = collect_target_dependencies(
        &tx,
        &ResourceTarget::parse(&format!("{network}/second")).unwrap(),
        &nodes,
        OffsetDateTime::now_utc(),
        None,
        None,
    )
    .await
    .unwrap();
    assert!(second.is_verified_zero());
    let whole = collect_target_dependencies(
        &tx,
        &ResourceTarget::parse(&network).unwrap(),
        &nodes,
        OffsetDateTime::now_utc(),
        None,
        None,
    )
    .await
    .unwrap();
    assert_eq!(whole.dependent_resource_count(), 1);
    tx.rollback().await.unwrap();
}

#[tokio::test]
async fn missing_operated_node_context_refuses_instead_of_guessing() {
    let db = db().await;
    let (_, owner) = principal();
    let target =
        ResourceTarget::parse(&format!("urn:tinycloud:encryption:{owner}:default")).unwrap();
    let tx = db.begin().await.unwrap();
    assert!(collect_target_dependencies(
        &tx,
        &target,
        &BTreeSet::new(),
        OffsetDateTime::now_utc(),
        None,
        None
    )
    .await
    .is_err());
}

#[tokio::test]
async fn postgres_generic_grants_are_ambiguous_not_zero_and_scope_is_exact() {
    use sea_orm::{ConnectOptions, ConnectionTrait};
    let Ok(url) = std::env::var("TINYCLOUD_TEST_POSTGRES_URL") else {
        return;
    };
    let admin = Database::connect(&url).await.unwrap();
    let schema = format!(
        "resource_dep_{}_{}",
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
    generic_matrix(&db).await;
    db.close().await.unwrap();
    admin
        .execute_unprepared(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

#[tokio::test]
async fn trusted_host_members_are_excluded_but_other_members_are_dependencies() {
    use tinycloud_core::models::{encryption_network, encryption_network_member};
    let db = db().await;
    let (_, owner) = principal();
    let (_, node) = principal();
    let (_, outsider) = principal();
    let network = format!("urn:tinycloud:encryption:{owner}:default");
    encryption_network::Model {
        network_id: network.clone(),
        owner_did: owner,
        name: "default".into(),
        alg: "synthetic".into(),
        key_version: 1,
        public_key: vec![],
        state: "active".into(),
        threshold_n: 1,
        threshold_t: 1,
        key_backend: "synthetic".into(),
        sealed_private_key: None,
        created_at: "2026-01-01T00:00:00Z".into(),
        updated_at: "2026-01-01T00:00:00Z".into(),
    }
    .into_active_model()
    .insert(&db)
    .await
    .unwrap();
    for member in [&node, &outsider] {
        encryption_network_member::Model {
            network_id: network.clone(),
            node_id: member.clone(),
            role: "key-holder".into(),
            share_index: 1,
            joined_at: "2026-01-01T00:00:00Z".into(),
        }
        .into_active_model()
        .insert(&db)
        .await
        .unwrap();
    }
    let tx = db.begin().await.unwrap();
    let check = collect_target_dependencies(
        &tx,
        &ResourceTarget::parse(&network).unwrap(),
        &BTreeSet::from([node]),
        OffsetDateTime::now_utc(),
        None,
        None,
    )
    .await
    .unwrap();
    assert_eq!(check.proven_outside_count(), 1);
    assert_eq!(check.ambiguous_count(), 0);
    assert_eq!(check.dependent_resource_count(), 1);
    assert!(!check.is_verified_zero());
    tx.rollback().await.unwrap();
}

#[tokio::test]
async fn key_prefix_grant_is_in_exact_key_and_network_fingerprints() {
    let db = db().await;
    let (key, owner) = principal();
    let (_, recipient) = principal();
    let (_, node) = principal();
    let network = format!("urn:tinycloud:encryption:{owner}:default");
    grant(
        &db,
        &key,
        &owner,
        &recipient,
        &format!("{network}/first/"),
        600,
    )
    .await;
    let tx = db.begin().await.unwrap();
    let nodes = BTreeSet::from([node]);
    for target in [format!("{network}/first/item"), network.clone()] {
        let check = collect_target_dependencies(
            &tx,
            &ResourceTarget::parse(&target).unwrap(),
            &nodes,
            OffsetDateTime::now_utc(),
            None,
            None,
        )
        .await
        .unwrap();
        assert_eq!(check.dependent_resource_count(), 1);
        assert_eq!(check.ambiguous_count(), 1);
        assert_eq!(check.proven_outside_count(), 0);
        assert!(!check.is_verified_zero());
    }
    let unrelated = collect_target_dependencies(
        &tx,
        &ResourceTarget::parse(&format!("{network}/second/item")).unwrap(),
        &nodes,
        OffsetDateTime::now_utc(),
        None,
        None,
    )
    .await
    .unwrap();
    assert!(unrelated.is_verified_zero());
    tx.rollback().await.unwrap();
}

#[tokio::test]
async fn restored_signed_session_without_graph_rows_refuses_zero() {
    use tinycloud_core::models::policy_v3_session;
    let db = db().await;
    let (key, owner) = principal();
    let (_, recipient) = principal();
    let (_, node) = principal();
    let network = format!("urn:tinycloud:encryption:{owner}:default");
    grant(&db, &key, &owner, &recipient, &network, 600).await;
    let row = delegation::Entity::find().one(&db).await.unwrap().unwrap();
    abilities::Entity::delete_many().exec(&db).await.unwrap();
    delegation::Entity::delete_by_id(row.id)
        .exec(&db)
        .await
        .unwrap();
    policy_v3_session::Model {
        session_cid: row.id.to_cid(0x55).to_string(),
        policy_cid: hash(b"synthetic policy").to_cid(0x55).to_string(),
        authorization_bytes: row.serialization,
        recipient_did: recipient,
        claim_jti: "synthetic".into(),
        claim_digest_hex: "00".repeat(32),
        vp_digest_hex: "00".repeat(32),
        state: "admitted".into(),
        not_before: "2026-01-01T00:00:00Z".into(),
        expires_at: "2030-01-01T00:00:00Z".into(),
        admitted_at: Some("2026-01-01T00:00:00Z".into()),
    }
    .into_active_model()
    .insert(&db)
    .await
    .unwrap();
    let tx = db.begin().await.unwrap();
    assert!(collect_target_dependencies(
        &tx,
        &ResourceTarget::parse(&network).unwrap(),
        &BTreeSet::from([node]),
        OffsetDateTime::now_utc(),
        None,
        None
    )
    .await
    .is_err());
}
