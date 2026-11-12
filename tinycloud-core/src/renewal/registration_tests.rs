//! Replay the unchanged frozen bytes at their published verifier time.
use super::*;
use base64::Engine as _;
use sea_orm::{Database, TransactionTrait};
use sea_orm_migration::MigratorTrait;

#[tokio::test]
async fn frozen_proofless_owner_lease_registers_active_generation_one() {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tinycloud-node-server/tests/fixtures/renewal-lease-v1.json"
    ))
    .unwrap();
    let db = Database::connect("sqlite::memory:").await.unwrap();
    crate::migrations::Migrator::up(&db, None).await.unwrap();
    let secret = StaticSecret::new(vec![0x42; 32]).unwrap();
    let seed = secret.derive_key(RENEWER_KEY_CONTEXT);
    let (_, epoch, _) = initialize_renewal_identity(&db, seed).await.unwrap();
    let tx = db.begin().await.unwrap();
    for name in ["ownerDid", "holderDid", "renewerDid"] {
        tx.execute(Statement::from_sql_and_values(
            DatabaseBackend::Sqlite,
            "INSERT INTO actor (id) VALUES ($1)",
            [Value::String(Some(Box::new(
                fixture[name].as_str().unwrap().into(),
            )))],
        ))
        .await
        .unwrap();
    }
    for field in ["originalToken", "leaseToken"] {
        let bytes = fixture[field].as_str().unwrap().as_bytes();
        let info = signed_delegation_info(bytes).unwrap();
        let id = crate::hash::hash(bytes);
        tx.execute(Statement::from_sql_and_values(DatabaseBackend::Sqlite,
            "INSERT INTO delegation (id,delegator,delegatee,expiry,issued_at,not_before,facts,serialization,serialization_format) VALUES ($1,$2,$3,$4,NULL,NULL,NULL,$5,0)",
            [Vec::<u8>::from(id).into(),info.delegator.into(),info.delegate.into(),
             Value::TimeDateTime(Some(Box::new(db_datetime(info.expiry.unwrap().unix_timestamp()).unwrap()))),bytes.to_vec().into()])).await.unwrap();
        tx.execute(Statement::from_sql_and_values(
            DatabaseBackend::Sqlite,
            "INSERT INTO delegation_cid_alias (id,canonical,encrypted) VALUES ($1,$1,FALSE)",
            [Vec::<u8>::from(id).into()],
        ))
        .await
        .unwrap();
    }
    let lease_id = canonical_cid(fixture["leaseCid"].as_str().unwrap())
        .unwrap()
        .1;
    tx.execute(Statement::from_sql_and_values(DatabaseBackend::Sqlite,
        "INSERT INTO ability (delegation,resource,ability,caveats) VALUES ($1,$2,'tinycloud.delegation/renew',$3)",
        [Vec::<u8>::from(lease_id).into(),fixture["renewResource"].as_str().unwrap().into(),
         Value::Json(Some(Box::new(serde_json::json!({}))))])).await.unwrap();
    let lease = crate::events::Delegation::from_header_ser::<
        tinycloud_auth::authorization::TinyCloudDelegation,
    >(fixture["leaseToken"].as_str().unwrap())
    .unwrap();
    assert!(lease.0.parents.is_empty());
    register_lease_at(
        &tx,
        &lease,
        seed,
        epoch,
        fixture["nodeIdentityDid"].as_str().unwrap(),
        None,
        fixture["issuedAt"].as_i64().unwrap() + 1,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let row = db
        .query_one(Statement::from_string(
            DatabaseBackend::Sqlite,
            "SELECT state,generation FROM renewal_lease",
        ))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.try_get::<String>("", "state").unwrap(), "active");
    assert_eq!(row.try_get::<i64>("", "generation").unwrap(), 1);
}

#[derive(Clone)]
struct NoRenewalSeed;
#[async_trait::async_trait]
impl crate::keys::Secrets for NoRenewalSeed {
    type Error = std::convert::Infallible;
    async fn get_keypair(
        &self,
        _: &tinycloud_auth::resource::SpaceId,
    ) -> Result<crate::keys::Keypair, Self::Error> {
        unreachable!("no key use during refused registration")
    }
    async fn stage_keypair(
        &self,
        _: &tinycloud_auth::resource::SpaceId,
    ) -> Result<crate::keys::PublicKey, Self::Error> {
        unreachable!("no key use during refused registration")
    }
    async fn save_keypair(&self, _: &tinycloud_auth::resource::SpaceId) -> Result<(), Self::Error> {
        Ok(())
    }
    // Keep the trait default renewal_seed() == None.
}

#[tokio::test]
async fn identity_without_renewal_seed_refuses_before_saving_any_lease_graph() {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tinycloud-node-server/tests/fixtures/renewal-lease-v1.json"
    ))
    .unwrap();
    let original = tinycloud_auth::authorization::TinyCloudInvocation::decode(
        fixture["leaseToken"].as_str().unwrap(),
    )
    .unwrap();
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let mut payload = original.payload().clone();
    payload.not_before = Some(
        tinycloud_auth::ssi::claims::jwt::NumericDate::try_from_seconds((now - 1) as f64).unwrap(),
    );
    payload.expiration =
        tinycloud_auth::ssi::claims::jwt::NumericDate::try_from_seconds((now + 3600) as f64)
            .unwrap();
    let seed = [0x11; 32];
    let key = ed25519_dalek::SigningKey::from_bytes(&seed);
    let jwk: tinycloud_auth::ssi::jwk::JWK = serde_json::from_value(serde_json::json!({
        "kty":"OKP","crv":"Ed25519","alg":"EdDSA",
        "x":base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key.verifying_key().to_bytes()),
        "d":base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(seed)}))
    .unwrap();
    let token = payload
        .sign(tinycloud_auth::ssi::jwk::Algorithm::EdDSA, &jwk)
        .unwrap()
        .encode()
        .unwrap();
    let lease = crate::events::Delegation::from_header_ser::<
        tinycloud_auth::authorization::TinyCloudDelegation,
    >(&token)
    .unwrap();
    let db = Database::connect("sqlite::memory:").await.unwrap();
    crate::migrations::Migrator::up(&db, None).await.unwrap();
    let tx = db.begin().await.unwrap();
    let identity = RenewalNodeIdentity {
        stable_node_did: fixture["nodeIdentityDid"].as_str().unwrap().into(),
        renewer_did: fixture["renewerDid"].as_str().unwrap().into(),
        epoch: 1,
    };
    let result = crate::db::transact(
        &tx,
        &crate::storage::memory::MemoryStore::default(),
        &NoRenewalSeed,
        Some(&identity),
        vec![crate::events::Event::Delegation(Box::new(lease))],
        None,
        None,
        &[],
        false,
        false,
    )
    .await;
    assert!(matches!(
        result,
        Err(crate::db::TxError::Renewal(
            RenewalStoreError::LeaseUnavailable
        ))
    ));
    tx.commit().await.unwrap();
    for table in ["delegation", "renewal_lease"] {
        let row = db
            .query_one(Statement::from_string(
                DatabaseBackend::Sqlite,
                format!("SELECT count(*) AS n FROM {table}"),
            ))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.try_get::<i64>("", "n").unwrap(), 0);
    }
}
