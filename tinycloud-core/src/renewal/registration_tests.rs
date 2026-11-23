//! Replay the unchanged frozen bytes at their published verifier time.
use super::*;
use base64::Engine as _;
use sea_orm::{Database, TransactionTrait};
use sea_orm_migration::MigratorTrait;

/// The frozen original and lease rows, with the node's renewal identity,
/// inside an open transaction: everything a lease registration reads.
async fn frozen_lease_graph() -> (
    sea_orm::DatabaseConnection,
    sea_orm::DatabaseTransaction,
    serde_json::Value,
    [u8; 32],
    u64,
    crate::events::Delegation,
) {
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
    (db, tx, fixture, seed, epoch, lease)
}

#[tokio::test]
async fn frozen_proofless_owner_lease_registers_active_generation_one() {
    let (db, tx, fixture, seed, epoch, lease) = frozen_lease_graph().await;
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

    // TC-3443 F1: the active lease may renew the original up to its own
    // expiry, so a retire of the holder lasts at least that long, whatever
    // its TTL.
    let holder = fixture["holderDid"].as_str().unwrap();
    let now = fixture["issuedAt"].as_i64().unwrap() + 2;
    crate::models::session_retire::retire(
        &db,
        holder,
        unix_time(now).unwrap(),
        time::Duration::seconds(1),
    )
    .await
    .unwrap();
    let retire = <crate::models::session_retire::Entity as sea_orm::EntityTrait>::find_by_id(
        holder.to_owned(),
    )
    .one(&db)
    .await
    .unwrap()
    .unwrap();
    assert!(retire.expires_at >= crate::models::session_retire::covering(lease.0.expiry));
}

/// TC-3443 (C2): an original held by a retired session key gets no renewal
/// lease; nothing is saved.
#[tokio::test]
async fn lease_for_an_original_held_by_a_retired_session_key_is_refused() {
    let (db, tx, fixture, seed, epoch, lease) = frozen_lease_graph().await;
    let holder = fixture["holderDid"].as_str().unwrap();
    assert!(holder.starts_with("did:key:"));
    let now = fixture["issuedAt"].as_i64().unwrap() + 1;
    // Retired with a one-second TTL ten seconds ago: past its TTL, the
    // retire still holds because the original outlives it (TC-3443 F1).
    crate::models::session_retire::retire(
        &tx,
        holder,
        unix_time(now - 10).unwrap(),
        time::Duration::seconds(1),
    )
    .await
    .unwrap();
    let refused = register_lease_at(
        &tx,
        &lease,
        seed,
        epoch,
        fixture["nodeIdentityDid"].as_str().unwrap(),
        None,
        now,
    )
    .await;
    assert!(
        matches!(&refused, Err(RenewalStoreError::SessionRetired(_))),
        "{refused:?}"
    );
    tx.commit().await.unwrap();
    let leases = db
        .query_one(Statement::from_string(
            DatabaseBackend::Sqlite,
            "SELECT count(*) AS n FROM renewal_lease",
        ))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(leases.try_get::<i64>("", "n").unwrap(), 0);
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
        None,
        None,
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

/// TC-4092: a lease the owner revoked, then the space purged. Purge removes
/// the revocation rows (and the delegations they name) but keeps
/// `renewal_lease` / `renewal_stamp`, which are keyed by delegation CID. The
/// old lease must not stamp again, neither straight after the purge nor after
/// the identical original + lease are posted again.
#[tokio::test]
async fn revoked_lease_issues_no_stamp_after_space_purge_or_identical_repost() {
    let (db, tx, fixture, seed, epoch, lease_event) = frozen_lease_graph().await;
    let node_did = fixture["nodeIdentityDid"].as_str().unwrap().to_owned();
    let original_cid = fixture["originalCid"].as_str().unwrap().to_owned();
    let lease_cid = fixture["leaseCid"].as_str().unwrap().to_owned();
    let original = canonical_cid(&original_cid).unwrap().1;
    let lease = canonical_cid(&lease_cid).unwrap().1;
    let issued_at = fixture["issuedAt"].as_i64().unwrap();
    let period = fixture["renewalPeriodSeconds"].as_i64().unwrap();
    let t1 = issued_at + 1;
    let t2 = t1 + 1_000_000;
    let t3 = t2 + 1_000_000;
    assert!(t3 < fixture["leaseExpiration"].as_i64().unwrap());
    assert!(t3 < t2 + period, "t3 is inside the second stamp's window");

    register_lease_at(&tx, &lease_event, seed, epoch, &node_did, None, t1)
        .await
        .unwrap();
    tx.commit().await.unwrap();

    let secret = StaticSecret::new(vec![0x42; 32]).unwrap();
    let (renewer_did, stored_epoch, _) = current_renewal_identity_from_seed(&db, seed)
        .await
        .unwrap();
    assert_eq!(stored_epoch, epoch);
    let identity = RenewalNodeIdentity {
        stable_node_did: node_did.clone(),
        renewer_did: renewer_did.clone(),
        epoch,
    };
    let request = |label: &str, now: i64| {
        let token = tinycloud_auth::authorization::TinyCloudInvocation::decode(
            fixture["originalToken"].as_str().unwrap(),
        )
        .unwrap();
        let mut request = StampIssue {
            invocation: crate::util::InvocationInfo::try_from(token).unwrap(),
            original_cid: original_cid.clone(),
            lease_cid: lease_cid.clone(),
            replay_hash: crate::hash::hash(label.as_bytes()),
            replay_expires_at: now + 60,
        };
        request.invocation.invoker = renewer_did.clone();
        request.invocation.parents = vec![lease_cid.parse().unwrap()];
        request.invocation.capabilities = vec![crate::util::Capability {
            resource: format!("urn:cid:{original_cid}").parse().unwrap(),
            ability: "tinycloud.delegation/renew".to_owned().try_into().unwrap(),
            caveats: Default::default(),
        }];
        request
    };
    let count = |table: &'static str| {
        let db = db.clone();
        async move {
            db.query_one(Statement::from_string(
                DatabaseBackend::Sqlite,
                format!("SELECT COUNT(*) AS n FROM {table}"),
            ))
            .await
            .unwrap()
            .unwrap()
            .try_get::<i64>("", "n")
            .unwrap()
        }
    };
    let lease_state = || {
        let db = db.clone();
        async move {
            db.query_all(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT state FROM renewal_lease",
            ))
            .await
            .unwrap()
            .iter()
            .map(|row| row.try_get::<String>("", "state").unwrap())
            .collect::<Vec<_>>()
        }
    };

    // Control: the unrevoked lease renews twice, so the refusals below are
    // not an artefact of timing (the second stamp is inside the first's window).
    issue_stamp_at(&db, request("control 1", t1), &secret, &identity, t1, None)
        .await
        .expect("control: the live lease stamps");
    issue_stamp_at(&db, request("control 2", t2), &secret, &identity, t2, None)
        .await
        .expect("control: the live lease stamps again later");
    assert_eq!(count("renewal_stamp").await, 2);

    // The owner revokes the lease. Revocation is a `revocation` row only:
    // `renewal_lease.state` is not touched by it.
    let revocation = crate::hash::hash(b"TC-4092 revocation of the lease");
    db.execute(Statement::from_sql_and_values(
        DatabaseBackend::Sqlite,
        "INSERT INTO revocation (id, revoker, revoked, serialization, revoked_at) VALUES ($1,$2,$3,$4,NULL)",
        [
            Vec::<u8>::from(revocation).into(),
            fixture["ownerDid"].as_str().unwrap().into(),
            Vec::<u8>::from(lease).into(),
            vec![1_u8].into(),
        ],
    ))
    .await
    .unwrap();
    let revoked = issue_stamp_at(&db, request("after revoke", t3), &secret, &identity, t3, None).await;
    assert!(
        matches!(
            revoked,
            Err(RenewalStoreError::Revoked) | Err(RenewalStoreError::LeaseUnavailable)
        ),
        "before the purge a revoked lease must not stamp: {revoked:?}"
    );
    let state_after_revoke = lease_state().await;
    assert_eq!(count("revocation").await, 1);

    // The space purge's record deletion: the original, the lease and the
    // revocation are all records of the purged space.
    let deleted: std::collections::HashSet<Hash> =
        [original, lease, revocation].into_iter().collect();
    let purge = db.begin().await.unwrap();
    crate::space_purge_records::remove_records_for_test(&purge, &deleted)
        .await
        .unwrap();
    purge.commit().await.unwrap();
    let state_after_purge = lease_state().await;
    let revocations_after_purge = count("revocation").await;
    let delegations_after_purge = count("delegation").await;
    let stamps_after_purge = count("renewal_stamp").await;
    eprintln!(
        "TC-4092 after purge: renewal_lease.state={state_after_purge:?} (after revoke, before purge: {state_after_revoke:?}), \
         revocation rows={revocations_after_purge}, delegation rows={delegations_after_purge}, \
         renewal_lease rows={}, renewal_stamp rows={stamps_after_purge}",
        count("renewal_lease").await,
    );

    // (a) the scheduler's path for the old lease, original and lease gone.
    let after_purge =
        issue_stamp_at(&db, request("after purge", t3), &secret, &identity, t3, None).await;
    eprintln!("TC-4092 (a) stamp after purge: {after_purge:?}");
    assert!(
        after_purge.is_err(),
        "(a) a revoked, purged lease issued a stamp: {after_purge:?}"
    );
    assert_eq!(count("renewal_stamp").await, stamps_after_purge, "(a)");

    // (b) the identical original + lease are posted again: the same rows the
    // first post stored, with no revocation among them.
    let repost = db.begin().await.unwrap();
    for name in ["ownerDid", "holderDid", "renewerDid"] {
        repost
            .execute(Statement::from_sql_and_values(
                DatabaseBackend::Sqlite,
                "INSERT INTO actor (id) VALUES ($1) ON CONFLICT (id) DO NOTHING",
                [fixture[name].as_str().unwrap().into()],
            ))
            .await
            .unwrap();
    }
    for field in ["originalToken", "leaseToken"] {
        let bytes = fixture[field].as_str().unwrap().as_bytes();
        let info = signed_delegation_info(bytes).unwrap();
        let id = crate::hash::hash(bytes);
        repost.execute(Statement::from_sql_and_values(DatabaseBackend::Sqlite,
            "INSERT INTO delegation (id,delegator,delegatee,expiry,issued_at,not_before,facts,serialization,serialization_format) VALUES ($1,$2,$3,$4,NULL,NULL,NULL,$5,0)",
            [Vec::<u8>::from(id).into(), info.delegator.into(), info.delegate.into(),
             Value::TimeDateTime(Some(Box::new(db_datetime(info.expiry.unwrap().unix_timestamp()).unwrap()))), bytes.to_vec().into()])).await.unwrap();
        repost
            .execute(Statement::from_sql_and_values(
                DatabaseBackend::Sqlite,
                "INSERT INTO delegation_cid_alias (id,canonical,encrypted) VALUES ($1,$1,FALSE)",
                [Vec::<u8>::from(id).into()],
            ))
            .await
            .unwrap();
    }
    repost.execute(Statement::from_sql_and_values(DatabaseBackend::Sqlite,
        "INSERT INTO ability (delegation,resource,ability,caveats) VALUES ($1,$2,'tinycloud.delegation/renew',$3)",
        [Vec::<u8>::from(lease).into(), fixture["renewResource"].as_str().unwrap().into(),
         Value::Json(Some(Box::new(serde_json::json!({}))))])).await.unwrap();
    let admitted = register_lease_at(&repost, &lease_event, seed, epoch, &node_did, None, t3).await;
    eprintln!("TC-4092 (b) re-admission of the identical lease: {admitted:?}");
    repost.commit().await.unwrap();
    eprintln!(
        "TC-4092 after re-post: renewal_lease.state={:?}, revocation rows={}, renewal_lease rows={}",
        lease_state().await,
        count("revocation").await,
        count("renewal_lease").await,
    );
    let after_repost =
        issue_stamp_at(&db, request("after repost", t3), &secret, &identity, t3, None).await;
    eprintln!("TC-4092 (b) stamp after re-post: {after_repost:?}");
    eprintln!(
        "TC-4092 (b) effective_end after re-post: {:?}",
        effective_end(&db, &original_cid, &lease_cid, t3, &identity).await
    );
    assert!(
        after_repost.is_err(),
        "(b) a revoked, purged, re-posted lease issued a stamp: {after_repost:?}"
    );
    assert_eq!(count("renewal_stamp").await, stamps_after_purge, "(b)");
}
