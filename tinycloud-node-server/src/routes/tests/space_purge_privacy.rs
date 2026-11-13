//! Compare the same signed request and target against independent DB worlds.
use super::*;
use rocket::{
    http::{ContentType, Header, Status},
    local::asynchronous::Client,
};
use tinycloud_core::{sea_orm::TransactionTrait, space_purge_ledger::LedgerKeys};
async fn privacy_world(
    space: &SpaceId,
    hosted: bool,
    keys: Arc<tinycloud_core::space_purge_ledger::LedgerKeys>,
) -> Result<(
    Vec<TempDir>,
    rocket::Rocket<rocket::Build>,
    tinycloud_core::sea_orm::DatabaseConnection,
    Arc<tinycloud_core::space_purge_fence::SpacePurgeFence>,
)> {
    use tinycloud_core::models::space as space_model;
    use tinycloud_core::sea_orm::ActiveModelTrait;
    use tinycloud_core::sea_orm::ActiveValue::Set;
    use tinycloud_core::types::SpaceIdWrap;

    let mut config = Config::default();
    config.log.tracing.enabled = false;
    let fence = Arc::new(tinycloud_core::space_purge_fence::SpacePurgeFence::new(
        keys,
    ));
    let tempdir = TempDir::new()?;
    let db = Database::connect(ConnectOptions::new("sqlite::memory:".to_string())).await?;
    let storage = NodeFileSystemConfig::new(tempdir.path()).open().await?;
    // Mirror what `StorageSetup::create` does for a newly-hosted space:
    // normally that runs as part of a `tinycloud.space/host` delegation
    // transaction (see `new_spaces` handling in `tinycloud-core::db`).
    // This harness hosts `space` directly via a DB row instead of that
    // transaction, so the block-store directory needs the same
    // provisioning here, or a KV write 500s on a missing directory.
    std::fs::create_dir_all(
        tempdir
            .path()
            .join(space.suffix())
            .join(space.name().as_str()),
    )?;
    let tinycloud = TinyCloud::new(
        db.clone().into(),
        Either::B(storage),
        StaticSecret::new(vec![0u8; 32]).unwrap(),
    )
    .await?
    .with_delegated_sql_caveats(config.sql.delegated_caveats_enforced)
    .with_named_keys(config.encryption_network.named_keys_v1)
    .with_space_purge_fence(fence.clone());
    let conn = db;
    if hosted {
        space_model::ActiveModel {
            id: Set(SpaceIdWrap(space.clone())),
        }
        .insert(&conn)
        .await?;
    }
    fence.set_serving_ready(true);

    let replay_db = Database::connect(ConnectOptions::new("sqlite::memory:".to_string())).await?;
    Migrator::up(&replay_db, None).await?;
    let (sql_cache, sql_service) = fresh_sql_service().await;
    let hook_runtime = HookRuntime::new(HooksConfig::default(), [9u8; 32]);
    #[cfg(feature = "duckdb")]
    let duckdb_service = {
        let path = tempdir.path().join("duckdb");
        std::fs::create_dir_all(&path)?;
        let path = path.to_string_lossy().to_string();
        let db = Database::connect(ConnectOptions::new("sqlite::memory:".to_string())).await?;
        Migrator::up(&db, None).await?;
        let repo = Arc::new(SeaOrmDatabaseArtifactRepository::new(db));
        DuckDbService::new(path, u64::MAX, 300, "256MB".into(), repo)
    };
    let rocket = rocket::build()
        .mount("/", rocket::routes![invoke, info, delegate])
        .attach(crate::tracing::TracingFairing::for_test(
            &config.log.tracing,
        ))
        .attach(crate::space_lifecycle::leases::PurgeLeaseFairing)
        .manage(tinycloud)
        .manage(sql_service)
        .manage(None::<crate::tee::TeeContext>)
        .manage(config)
        .manage(QuotaCache::new(None, None))
        .manage(ReplayDb(replay_db.clone()))
        .manage(InvocationReplayCache::new(replay_db))
        .manage(hook_runtime)
        .manage(BlockStage::from(crate::config::StagingStorage::Memory));
    #[cfg(feature = "duckdb")]
    let rocket = rocket.manage(duckdb_service);
    let rocket = manage_tc405_test_state(rocket, conn.clone());
    Ok((vec![tempdir, sql_cache], rocket, conn, fence))
}

fn privacy_invocation(key: &JWK, issuer: &str, space: &SpaceId, expiration: f64) -> Result<String> {
    use tinycloud_auth::authorization::{make_invocation_from_uris, Cid, InvocationOptions};
    Ok(make_invocation_from_uris(
        [(
            format!("{space}/kv/doc").parse()?,
            ["tinycloud.kv/get".parse()?],
        )],
        &Cid::default(),
        key,
        issuer,
        expiration,
        InvocationOptions {
            not_before: None,
            nonce: Some(uuid::Uuid::new_v4().to_string()),
            facts: None,
            proof: Some(vec![]),
        },
    )?
    .encode()?)
}
async fn raw(client: &Client, jwt: &str) -> (Status, Vec<(String, String)>, Vec<u8>) {
    let response = client
        .post("/invoke")
        .header(ContentType::JSON)
        .header(Header::new("Authorization", jwt.to_owned()))
        .header(Header::new(
            "x-request-id",
            "00000000-0000-4000-8000-000000000123",
        ))
        .body("{}")
        .dispatch()
        .await;
    let status = response.status();
    let mut headers: Vec<_> = response
        .headers()
        .iter()
        .map(|h| (h.name().to_string(), h.value().to_string()))
        .collect();
    headers.sort();
    (
        status,
        headers,
        response.into_bytes().await.unwrap_or_default(),
    )
}
#[tokio::test]
async fn same_signed_non_owner_no_grant_matches_never_created_and_direct_owner_alone_gets_410(
) -> Result<()> {
    let mut owner_key = JWK::generate_secp256k1();
    owner_key.algorithm = Some(tinycloud_auth::ssi::jwk::Algorithm::ES256KR);
    let owner = tinycloud_auth::resolver::DID_METHODS
        .generate(&owner_key, "pkh:eip155")
        .unwrap()
        .to_string();
    let space = SpaceId::new(owner.parse()?, "privacy".parse()?)?;
    let keys = Arc::new(LedgerKeys::new(
        "test".into(),
        std::collections::BTreeMap::from([("test".into(), vec![7; 32])]),
    )?);
    let (_a_dirs, a, a_db, fence) = privacy_world(&space, true, keys.clone()).await?;
    let (_b_dirs, b, _, _) = privacy_world(&space, false, keys.clone()).await?;
    let tx = a_db.begin().await?;
    fence
        .fence_hmac(
            &tx,
            "space",
            "test",
            &keys.target_hmac("test", "space", &space.to_string())?,
        )
        .await?;
    tx.commit().await?;
    let a = Client::tracked(a).await?;
    let b = Client::tracked(b).await?;
    let outsider = JWK::generate_ed25519()?;
    let outsider_vm = tc341_verification_method(&outsider)?;
    let exp = OffsetDateTime::now_utc().unix_timestamp() as f64 + 300.0;
    let jwt = privacy_invocation(&outsider, &outsider_vm, &space, exp)?;
    assert!(
        raw(&a, &jwt).await == raw(&b, &jwt).await,
        "raw responses differ"
    );
    let owner_jwt = privacy_invocation(
        &owner_key,
        &format!("{owner}#blockchainAccountId"),
        &space,
        exp,
    )?;
    let owner_response = raw(&a, &owner_jwt).await;
    assert_eq!(owner_response.0, Status::Gone);
    let body: serde_json::Value = serde_json::from_slice(&owner_response.2)?;
    assert_eq!(body, serde_json::json!({"error":{"code":"space_deleted"}}));
    let mut invalid = owner_jwt.as_bytes().to_vec();
    let first_signature_byte = invalid.iter().rposition(|byte| *byte == b'.').unwrap() + 1;
    invalid[first_signature_byte] = if invalid[first_signature_byte] == b'A' {
        b'B'
    } else {
        b'A'
    };
    let invalid = String::from_utf8(invalid)?;
    let left = raw(&a, &invalid).await;
    let right = raw(&b, &invalid).await;
    assert_eq!(left.0, Status::Unauthorized);
    assert!(left == right, "raw responses differ");
    let expired = privacy_invocation(
        &owner_key,
        &format!("{owner}#blockchainAccountId"),
        &space,
        1.0,
    )?;
    let left = raw(&a, &expired).await;
    let right = raw(&b, &expired).await;
    assert_eq!(left.0, Status::Unauthorized);
    assert!(left == right, "raw responses differ");
    Ok(())
}

fn signed_grant(
    owner_key: &JWK,
    owner: &str,
    device_did: &str,
    space: &SpaceId,
) -> Result<tinycloud_core::events::Delegation> {
    use tinycloud_auth::{
        authorization::{HeaderEncode, TinyCloudDelegation},
        ssi::{dids::DIDURLBuf, ucan::Payload},
        ucan_capabilities_object::Capabilities,
    };
    let mut caps = Capabilities::new();
    caps.with_action(
        format!("{space}/kv/doc").parse()?,
        "tinycloud.kv/get".parse::<UcanAbility>()?,
        [BTreeMap::<String, serde_json::Value>::new()],
    );
    let grant = Payload {
        issuer: format!("{owner}#blockchainAccountId").parse::<DIDURLBuf>()?,
        audience: device_did.parse()?,
        not_before: None,
        expiration: test_invocation_expiration(),
        nonce: Some(uuid::Uuid::new_v4().to_string()),
        facts: None,
        proof: vec![],
        attenuation: caps,
    }
    .sign(owner_key.get_algorithm().unwrap_or_default(), owner_key)?;
    let header = TinyCloudDelegation::Ucan(Box::new(grant)).encode()?;
    Ok(tinycloud_core::events::Delegation::from_header_ser::<
        TinyCloudDelegation,
    >(&header)?)
}
fn delegated_request(
    key: &JWK,
    issuer: &str,
    space: &SpaceId,
    parent: tinycloud_core::hash::Hash,
) -> Result<String> {
    use tinycloud_auth::authorization::{make_invocation_from_uris, Cid, InvocationOptions};
    Ok(make_invocation_from_uris(
        [(
            format!("{space}/kv/doc").parse()?,
            ["tinycloud.kv/get".parse()?],
        )],
        &Cid::default(),
        key,
        issuer,
        OffsetDateTime::now_utc().unix_timestamp() as f64 + 300.0,
        InvocationOptions {
            not_before: None,
            nonce: Some(uuid::Uuid::new_v4().to_string()),
            facts: None,
            proof: Some(vec![parent.to_cid(0x55)]),
        },
    )?
    .encode()?)
}
#[tokio::test]
async fn once_valid_stored_and_revoked_chains_match_the_real_never_created_world() -> Result<()> {
    use tinycloud_core::{
        models::revocation,
        sea_orm::{ActiveModelTrait, ActiveValue::Set},
    };
    let mut owner_key = JWK::generate_secp256k1();
    owner_key.algorithm = Some(tinycloud_auth::ssi::jwk::Algorithm::ES256KR);
    let owner = tinycloud_auth::resolver::DID_METHODS
        .generate(&owner_key, "pkh:eip155")
        .unwrap()
        .to_string();
    let space = SpaceId::new(owner.parse()?, "privacy".parse()?)?;
    let keys = Arc::new(LedgerKeys::new(
        "test".into(),
        BTreeMap::from([("test".into(), vec![7; 32])]),
    )?);
    let (_a_dirs, a, a_db, fence) = privacy_world(&space, true, keys.clone()).await?;
    let (_b_dirs, b, b_db, _) = privacy_world(&space, false, keys.clone()).await?;
    let device = JWK::generate_ed25519()?;
    let device_vm = tc341_verification_method(&device)?;
    let device_did = device_vm.split('#').next().unwrap();
    let grant = signed_grant(&owner_key, &owner, device_did, &space)?;
    let parent = grant.content_hash();
    // The real registration handler validates these signed bytes in both
    // worlds. A proof can exist before its space has ever been hosted.
    a.state::<TinyCloud>()
        .unwrap()
        .delegate(grant.clone())
        .await
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    b.state::<TinyCloud>()
        .unwrap()
        .delegate(grant)
        .await
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    let tx = a_db.begin().await?;
    fence
        .fence_hmac(
            &tx,
            "space",
            "test",
            &keys.target_hmac("test", "space", &space.to_string())?,
        )
        .await?;
    tx.commit().await?;
    let a = Client::tracked(a).await?;
    let b = Client::tracked(b).await?;
    let jwt = delegated_request(&device, &device_vm, &space, parent)?;
    let left = raw(&a, &jwt).await;
    let right = raw(&b, &jwt).await;
    assert!(left == right, "raw responses differ");
    // Trusted stored revocation fixture, as used by the existing route tests;
    // the refusal itself is produced by the real request/grant verifier.
    for db in [&a_db, &b_db] {
        revocation::ActiveModel {
            id: Set(tinycloud_core::hash::hash(b"privacy-revocation")),
            revoker: Set(owner.clone()),
            revoked: Set(parent),
            serialization: Set(b"privacy-revocation".to_vec()),
            revoked_at: Set(None),
        }
        .insert(db)
        .await?;
    }
    let jwt = delegated_request(&device, &device_vm, &space, parent)?;
    let left = raw(&a, &jwt).await;
    let right = raw(&b, &jwt).await;
    assert_eq!(left.0, Status::Unauthorized);
    assert!(left == right, "raw responses differ");
    Ok(())
}

async fn raw_delegate(client: &Client, header: &str) -> (Status, Vec<(String, String)>, Vec<u8>) {
    let response = client
        .post("/delegate")
        .header(Header::new("Authorization", header.to_owned()))
        .header(Header::new(
            "x-request-id",
            "00000000-0000-4000-8000-000000000123",
        ))
        .dispatch()
        .await;
    let status = response.status();
    let mut headers: Vec<_> = response
        .headers()
        .iter()
        .map(|h| (h.name().to_string(), h.value().to_string()))
        .collect();
    headers.sort();
    (
        status,
        headers,
        response.into_bytes().await.unwrap_or_default(),
    )
}
fn child_grant(
    key: &JWK,
    issuer_vm: &str,
    device_did: &str,
    space: &SpaceId,
    parent: tinycloud_core::hash::Hash,
    parent_expiration: tinycloud_auth::ssi::claims::jwt::NumericDate,
) -> Result<String> {
    use tinycloud_auth::{
        authorization::{HeaderEncode, TinyCloudDelegation},
        ssi::{dids::DIDURLBuf, ucan::Payload},
        ucan_capabilities_object::Capabilities,
    };
    let mut caps = Capabilities::new();
    caps.with_action(
        format!("{space}/kv/doc").parse()?,
        "tinycloud.kv/get".parse::<UcanAbility>()?,
        [BTreeMap::<String, serde_json::Value>::new()],
    );
    Ok(TinyCloudDelegation::Ucan(Box::new(
        Payload {
            issuer: issuer_vm.parse::<DIDURLBuf>()?,
            audience: device_did.parse()?,
            not_before: None,
            expiration: parent_expiration,
            nonce: Some(uuid::Uuid::new_v4().to_string()),
            facts: None,
            proof: vec![parent.to_cid(0x55)],
            attenuation: caps,
        }
        .sign(key.get_algorithm().unwrap_or_default(), key)?,
    ))
    .encode()?)
}
async fn metadata_counts(db: &tinycloud_core::sea_orm::DatabaseConnection) -> Result<Vec<i64>> {
    use tinycloud_core::sea_orm::{ConnectionTrait, Statement};
    let mut counts = Vec::new();
    for table in [
        "actor",
        "delegation",
        "ability",
        "parent_delegation",
        "epoch",
        "event_order",
    ] {
        let row = db
            .query_one(Statement::from_string(
                db.get_database_backend(),
                format!("SELECT COUNT(*) AS n FROM {table}"),
            ))
            .await?
            .unwrap();
        counts.push(row.try_get("", "n")?);
    }
    Ok(counts)
}
#[tokio::test]
async fn fenced_delegate_matches_genuine_revoked_chain_without_storing_metadata() -> Result<()> {
    use tinycloud_core::{
        models::revocation,
        sea_orm::{ActiveModelTrait, ActiveValue::Set},
    };
    let mut owner_key = JWK::generate_secp256k1();
    owner_key.algorithm = Some(tinycloud_auth::ssi::jwk::Algorithm::ES256KR);
    let owner = tinycloud_auth::resolver::DID_METHODS
        .generate(&owner_key, "pkh:eip155")
        .unwrap()
        .to_string();
    let space = SpaceId::new(owner.parse()?, "privacy".parse()?)?;
    let keys = Arc::new(LedgerKeys::new(
        "test".into(),
        BTreeMap::from([("test".into(), vec![7; 32])]),
    )?);
    let (_a_dirs, a, a_db, fence) = privacy_world(&space, true, keys.clone()).await?;
    let (_b_dirs, b, b_db, _) = privacy_world(&space, true, keys.clone()).await?;
    let device = JWK::generate_ed25519()?;
    let device_vm = tc341_verification_method(&device)?;
    let device_did = device_vm.split('#').next().unwrap();
    let root = signed_grant(&owner_key, &owner, device_did, &space)?;
    let tinycloud_auth::authorization::TinyCloudDelegation::Ucan(parent_ucan) = &root.0.delegation
    else {
        anyhow::bail!("expected UCAN fixture");
    };
    let parent_expiration = parent_ucan.payload().expiration;
    let parent = root.content_hash();
    let owner_header = tinycloud_auth::authorization::HeaderEncode::encode(&root.0.delegation)?;
    let (_c_dirs, c, c_db, c_fence) = privacy_world(&space, false, keys.clone()).await?;
    c.state::<TinyCloud>()
        .unwrap()
        .delegate(root.clone())
        .await
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    let c_tx = c_db.begin().await?;
    c_fence
        .fence_hmac(
            &c_tx,
            "owner",
            "test",
            &keys.target_hmac("test", "owner", &owner)?,
        )
        .await?;
    c_tx.commit().await?;
    let c_before = metadata_counts(&c_db).await?;
    a.state::<TinyCloud>()
        .unwrap()
        .delegate(root.clone())
        .await
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    b.state::<TinyCloud>()
        .unwrap()
        .delegate(root)
        .await
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    let tx = a_db.begin().await?;
    fence
        .fence_hmac(
            &tx,
            "space",
            "test",
            &keys.target_hmac("test", "space", &space.to_string())?,
        )
        .await?;
    tx.commit().await?;
    revocation::ActiveModel {
        id: Set(tinycloud_core::hash::hash(b"privacy-delegate-revocation")),
        revoker: Set(owner.clone()),
        revoked: Set(parent),
        serialization: Set(b"privacy-delegate-revocation".to_vec()),
        revoked_at: Set(None),
    }
    .insert(&b_db)
    .await?;
    let header = child_grant(
        &device,
        &device_vm,
        device_did,
        &space,
        parent,
        parent_expiration,
    )?;
    let before = metadata_counts(&a_db).await?;
    let a = Client::tracked(a).await?;
    let b = Client::tracked(b).await?;
    let left = raw_delegate(&a, &header).await;
    let right = raw_delegate(&b, &header).await;
    assert_eq!(right.0, Status::Unauthorized);
    assert!(left == right, "raw responses differ");
    assert_eq!(metadata_counts(&a_db).await?, before);
    let owner_reply = raw_delegate(&a, &owner_header).await;
    assert_eq!(owner_reply.0, Status::Gone);
    assert_eq!(metadata_counts(&a_db).await?, before);
    let c = Client::tracked(c).await?;
    assert!(
        raw_delegate(&c, &header).await == right,
        "raw responses differ"
    );
    assert_eq!(metadata_counts(&c_db).await?, c_before);
    Ok(())
}
