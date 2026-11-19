//! The internal stamp writer must use the same deadline encoding as cleanup.
mod common;
#[allow(dead_code)]
#[path = "support/owner_lease.rs"]
mod setup;

use rocket::http::{Header, Status};
use serde_json::json;
use tinycloud_auth::{
    authorization::{make_invocation_from_uris, InvocationOptions},
    resolver::DID_METHODS,
    ssi::jwk::JWK,
};
use tinycloud_core::{
    hash::hash,
    keys::StaticSecret,
    renewal::{RenewalStoreError, StampIssue, RENEWER_KEY_CONTEXT},
    sea_orm::{ConnectionTrait, Database, DatabaseBackend, Statement},
};

async fn exercise(url: Option<&str>) {
    let f = setup::fixture(url, 0x11).await;
    let db = f.db();
    let conn = db.connection();
    let backend = conn.get_database_backend();
    let row = conn
        .query_one(Statement::from_sql_and_values(
            backend,
            "SELECT serialization FROM delegation WHERE id = $1",
            [Vec::<u8>::from(f.lease_id).into()],
        ))
        .await
        .unwrap()
        .unwrap();
    let lease_token =
        String::from_utf8(row.try_get::<Vec<u8>>("", "serialization").unwrap()).unwrap();
    let response = f
        .client
        .post("/delegate")
        .header(Header::new("Authorization", lease_token))
        .dispatch()
        .await;
    let status = response.status();
    assert_eq!(
        status,
        Status::Ok,
        "{}",
        response.into_string().await.unwrap()
    );
    let identity = db.renewal_identity().unwrap();
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let seed = StaticSecret::new(vec![0x42; 32])
        .unwrap()
        .derive_key(RENEWER_KEY_CONTEXT);
    let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
    let key: JWK = serde_json::from_value(json!({"kty":"OKP","crv":"Ed25519","alg":"EdDSA",
        "x":base64::encode_config(signing.verifying_key().to_bytes(),base64::URL_SAFE_NO_PAD),
        "d":base64::encode_config(seed,base64::URL_SAFE_NO_PAD)}))
    .unwrap();
    let did = DID_METHODS.generate(&key, "key").unwrap().to_string();
    assert_eq!(did, identity.renewer_did);
    let method = format!("{did}#{}", did.rsplit(':').next().unwrap());
    let lease_cid = f.lease_id.to_cid(0x55).to_string();
    let lease = lease_cid.parse().unwrap();
    let invocation = make_invocation_from_uris(
        [(
            format!("urn:cid:{}", f.original_cid).parse().unwrap(),
            ["tinycloud.delegation/renew".parse().unwrap()],
        )],
        &lease,
        &key,
        &method,
        (now + 60) as f64,
        InvocationOptions {
            nonce: Some("stamp-cleanup-replay".into()),
            proof: Some(vec![lease]),
            ..Default::default()
        },
    )
    .unwrap();
    let request = StampIssue {
        invocation: tinycloud_core::util::InvocationInfo::try_from(invocation).unwrap(),
        original_cid: f.original_cid.clone(),
        lease_cid,
        replay_hash: hash(b"stamp-cleanup-replay"),
        replay_expires_at: now + 60,
    };
    let stamp = db.issue_renewal_stamp(request.clone()).await.unwrap();
    let snapshot = f.snapshot().await;
    assert_eq!(snapshot["stamps"], 1);
    assert_eq!(snapshot["nonces"], 1);
    let cache = tinycloud::invocation_replay::InvocationReplayCache::new(conn.clone());
    // Explicitly execute startup's real cleanup, rather than race its background task.
    assert_eq!(
        cache
            .cleanup(time::OffsetDateTime::now_utc(), 300)
            .await
            .unwrap(),
        0
    );
    assert_eq!(f.snapshot().await, snapshot);
    assert!(matches!(
        db.issue_renewal_stamp(request).await,
        Err(RenewalStoreError::Replay)
    ));
    assert_eq!(f.snapshot().await, snapshot);
    let row = conn
        .query_one(Statement::from_string(
            backend,
            "SELECT cid,signed_bytes,signature FROM renewal_stamp",
        ))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        row.try_get::<Vec<u8>>("", "cid").unwrap(),
        Vec::<u8>::from(hash(&stamp.signed_bytes))
    );
    assert_eq!(
        row.try_get::<Vec<u8>>("", "signed_bytes").unwrap(),
        stamp.signed_bytes
    );
    assert_eq!(
        row.try_get::<Vec<u8>>("", "signature").unwrap(),
        stamp.signature
    );
    if backend == DatabaseBackend::Postgres {
        let row = conn.query_one(Statement::from_string(backend,
            "SELECT data_type FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'invocation_replay' AND column_name = 'expires_at'"))
            .await.unwrap().unwrap();
        assert_eq!(
            row.try_get::<String>("", "data_type").unwrap(),
            "timestamp with time zone"
        );
    }
}

#[tokio::test]
async fn stamp_replay_survives_cleanup_on_sqlite_and_postgres() {
    exercise(None).await;
    if let Some(url) =
        common::postgres_test_url("stamp_replay_survives_cleanup_on_sqlite_and_postgres")
    {
        let admin = Database::connect(&url).await.unwrap();
        let schema = format!("stamp_replay_{}", uuid::Uuid::new_v4().simple());
        admin
            .execute(Statement::from_string(
                DatabaseBackend::Postgres,
                format!("CREATE SCHEMA {schema}"),
            ))
            .await
            .unwrap();
        let mut scoped = reqwest::Url::parse(&url).unwrap();
        scoped
            .query_pairs_mut()
            .append_pair("options", &format!("-c search_path={schema}"));
        exercise(Some(scoped.as_str())).await;
        admin
            .execute(Statement::from_string(
                DatabaseBackend::Postgres,
                format!("DROP SCHEMA {schema} CASCADE"),
            ))
            .await
            .unwrap();
    }
}
