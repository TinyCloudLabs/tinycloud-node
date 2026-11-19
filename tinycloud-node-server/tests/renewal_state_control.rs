//! Real HTTP owner-control slice with signed artifacts and durable state.
use rocket::{
    figment::{providers::Serialized, Figment},
    http::{ContentType, Header, Status},
    local::asynchronous::Client,
};
use serde_json::{json, Value};
use std::collections::BTreeMap;
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
    keys::StaticSecret,
    sea_orm::{sea_query::Value as Sql, ConnectionTrait, Statement},
};

fn key() -> (JWK, String, String) {
    let seed = [0x11; 32];
    let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
    let key: JWK = serde_json::from_value(json!({"kty":"OKP","crv":"Ed25519","alg":"EdDSA",
        "x":base64::encode_config(signing.verifying_key().to_bytes(),base64::URL_SAFE_NO_PAD),
        "d":base64::encode_config(seed,base64::URL_SAFE_NO_PAD)}))
    .unwrap();
    let did = DID_METHODS.generate(&key, "key").unwrap().to_string();
    let method = format!("{}#{}", did, did.rsplit(':').next().unwrap());
    (key, did, method)
}
fn token(
    audience: &str,
    resource: &str,
    action: &str,
    generation: Option<u64>,
    nonce: &str,
    end: i64,
) -> String {
    let (key, _, method) = key();
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let mut caps = Capabilities::<Value>::new();
    let mut caveat = BTreeMap::new();
    if let Some(generation) = generation {
        caveat.insert("expectedGeneration".into(), json!(generation));
    }
    caps.with_action(resource.parse().unwrap(), action.parse().unwrap(), [caveat]);
    Payload::<Value> {
        issuer: method.parse().unwrap(),
        audience: audience.parse().unwrap(),
        not_before: Some(NumericDate::try_from_seconds((now - 1) as f64).unwrap()),
        expiration: NumericDate::try_from_seconds(end as f64).unwrap(),
        nonce: Some(nonce.into()),
        facts: None,
        proof: vec![],
        attenuation: caps,
    }
    .sign(Algorithm::EdDSA, &key)
    .unwrap()
    .encode()
    .unwrap()
}

#[tokio::test]
async fn owner_stop_read_enable_and_nonce_replay_are_transactional() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = tinycloud::config::Config::default();
    config.storage.datadir = dir.path().into();
    config.storage.database = Some("sqlite::memory:".into());
    config.keys = serde_json::from_value(
        json!({"type":"static","secret":base64::encode_config([0x42;32],base64::URL_SAFE_NO_PAD)}),
    )
    .unwrap();
    let figment = Figment::from(rocket::Config {
        log_level: rocket::config::LogLevel::Off,
        ..Default::default()
    })
    .merge(Serialized::defaults(&config));
    let client = Client::tracked(tinycloud::app(&figment).await.unwrap())
        .await
        .unwrap();
    let db = client.rocket().state::<tinycloud::TinyCloud>().unwrap();
    let identity = db.renewal_identity().unwrap();
    let (_, owner, _) = key();
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let original = token(
        &identity.stable_node_did,
        "urn:test:original",
        "tinycloud.kv/get",
        None,
        "original",
        now + 3600,
    );
    let original_id = hash(original.as_bytes());
    let original_cid = original_id.to_cid(0x55).to_string();
    let lease = token(
        &identity.renewer_did,
        &format!("urn:cid:{original_cid}"),
        "tinycloud.delegation/renew",
        None,
        "lease",
        now + 7200,
    );
    let lease_id = hash(lease.as_bytes());
    let lease_cid = lease_id.to_cid(0x55).to_string();
    let conn = db.connection();
    let backend = conn.get_database_backend();
    for actor in [&owner, &identity.stable_node_did, &identity.renewer_did] {
        conn.execute(Statement::from_sql_and_values(
            backend,
            "INSERT INTO actor (id) VALUES ($1) ON CONFLICT DO NOTHING",
            [Sql::String(Some(Box::new(actor.clone())))],
        ))
        .await
        .unwrap();
    }
    for (id, serialized, delegatee, expiry) in [
        (original_id, original, &identity.stable_node_did, now + 3600),
        (lease_id, lease, &identity.renewer_did, now + 7200),
    ] {
        conn.execute(Statement::from_sql_and_values(backend,
            "INSERT INTO delegation (id, delegator, delegatee, expiry, issued_at, not_before, facts, serialization, serialization_format) VALUES ($1,$2,$3,$4,NULL,NULL,NULL,$5,0)",
            [Sql::Bytes(Some(Box::new(Vec::<u8>::from(id)))),Sql::String(Some(Box::new(owner.clone()))),Sql::String(Some(Box::new(delegatee.clone()))),
             Sql::TimeDateTime(Some(Box::new(time::PrimitiveDateTime::new(time::OffsetDateTime::from_unix_timestamp(expiry).unwrap().date(),time::OffsetDateTime::from_unix_timestamp(expiry).unwrap().time())))),Sql::Bytes(Some(Box::new(serialized.into_bytes())))])).await.unwrap();
        conn.execute(Statement::from_sql_and_values(
            backend,
            "INSERT INTO delegation_cid_alias (id, canonical, encrypted) VALUES ($1,$1,FALSE)",
            [Sql::Bytes(Some(Box::new(Vec::<u8>::from(id))))],
        ))
        .await
        .unwrap();
    }
    let end = time::OffsetDateTime::from_unix_timestamp(now + 7200).unwrap();
    let original_end = time::OffsetDateTime::from_unix_timestamp(now + 3600).unwrap();
    let secret = StaticSecret::new(vec![0x42; 32]).unwrap();
    let audience_key = ed25519_dalek::SigningKey::from_bytes(
        &secret.derive_key(tinycloud_core::renewal::RENEWER_KEY_CONTEXT),
    )
    .verifying_key()
    .to_bytes();
    conn.execute(Statement::from_sql_and_values(backend,
        "INSERT INTO renewal_lease (original_canonical, lease_cid, state, generation, grantor, renewer_did, renewer_epoch, lease_expiry, original_expiry, period_seconds, audience_public_key) VALUES ($1,$2,'active',1,$3,$4,$5,$6,$7,3601,$8)",
        [Sql::Bytes(Some(Box::new(Vec::<u8>::from(original_id)))),Sql::Bytes(Some(Box::new(Vec::<u8>::from(lease_id)))),Sql::String(Some(Box::new(owner))),Sql::String(Some(Box::new(identity.renewer_did.clone()))),Sql::BigInt(Some(identity.epoch as i64)),Sql::TimeDateTime(Some(Box::new(time::PrimitiveDateTime::new(end.date(),end.time())))),Sql::TimeDateTime(Some(Box::new(time::PrimitiveDateTime::new(original_end.date(),original_end.time())))),Sql::Bytes(Some(Box::new(audience_key.to_vec())))])).await.unwrap();
    let stamp_end = time::OffsetDateTime::from_unix_timestamp(now + 3601).unwrap();
    let signer = tinycloud_core::renewal::RenewalSigner::from_seed(
        secret.derive_key(tinycloud_core::renewal::RENEWER_KEY_CONTEXT),
        identity.stable_node_did.clone(),
        identity.epoch,
    );
    let (signed, signature, stamp_cid) = signer
        .sign_stamp(
            &original_cid,
            &lease_cid,
            1,
            &lease_cid,
            &stamp_end
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap(),
        )
        .unwrap();
    let stamp_id = tinycloud_core::hash::Hash::from(
        stamp_cid
            .parse::<tinycloud_auth::authorization::Cid>()
            .unwrap(),
    );
    conn.execute(Statement::from_sql_and_values(backend,
        "INSERT INTO renewal_stamp (cid, original_canonical, lease_cid, generation, previous_stamp_cid, renewer_epoch, new_end, signed_bytes, signature, replay_hash) VALUES ($1,$2,$3,1,$3,$4,$5,$6,$7,$8)",
        [Sql::Bytes(Some(Box::new(Vec::<u8>::from(stamp_id)))),Sql::Bytes(Some(Box::new(Vec::<u8>::from(original_id)))),Sql::Bytes(Some(Box::new(Vec::<u8>::from(lease_id)))),Sql::BigInt(Some(identity.epoch as i64)),Sql::TimeDateTime(Some(Box::new(time::PrimitiveDateTime::new(stamp_end.date(),stamp_end.time())))),Sql::Bytes(Some(Box::new(signed))),Sql::Bytes(Some(Box::new(signature))),Sql::Bytes(Some(Box::new(Vec::<u8>::from(hash(b"admitted stamp")))))]
    )).await.unwrap();
    assert_eq!(
        db.delegation_effective_expiry(original_id, now)
            .await
            .unwrap()
            .unwrap(),
        now + 3601
    );
    let mut stop_token = String::new();
    for (action, generation, nonce, state, next) in [
        ("stop-renewal", Some(1), "stop", "stopped", 2),
        ("status", None, "read", "stopped", 2),
        ("enable-renewal", Some(2), "enable", "active", 3),
    ] {
        let authorization = token(
            &identity.stable_node_did,
            &format!("urn:cid:{lease_cid}"),
            &format!("tinycloud.delegation/{action}"),
            generation,
            nonce,
            now + 50,
        );
        let mut body = json!({"version":1,"leaseCid":lease_cid});
        if let Some(generation) = generation {
            body["expectedGeneration"] = json!(generation);
        }
        let response = client
            .post("/delegation/renewal/state")
            .header(ContentType::JSON)
            .header(Header::new("Authorization", authorization.clone()))
            .json(&body)
            .dispatch()
            .await;
        let status = response.status();
        let receipt: Value = response.into_json().await.unwrap();
        assert_eq!(status, Status::Ok, "{receipt}");
        assert_eq!(receipt["state"], state);
        assert_eq!(receipt["generation"], next);
        if action == "stop-renewal" {
            stop_token = authorization;
            assert_eq!(
                db.delegation_effective_expiry(original_id, now)
                    .await
                    .unwrap()
                    .unwrap(),
                now + 3601
            );
            assert!(
                tinycloud_core::renewal::active_leases_for_current_epoch(conn, identity)
                    .await
                    .unwrap()
                    .is_empty()
            );
        }
    }
    let response = client
        .post("/delegation/renewal/state")
        .header(ContentType::JSON)
        .header(Header::new("Authorization", stop_token))
        .json(&json!({"version":1,"leaseCid":lease_cid,"expectedGeneration":1}))
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Conflict);
    assert_eq!(
        response.into_json::<Value>().await.unwrap()["code"],
        "invocation_replay"
    );
    // Concurrent valid requests for the same generation can commit only once.
    let body = json!({"version":1,"leaseCid":lease_cid,"expectedGeneration":3});
    let first = token(
        &identity.stable_node_did,
        &format!("urn:cid:{lease_cid}"),
        "tinycloud.delegation/stop-renewal",
        Some(3),
        "race-first",
        now + 50,
    );
    let second = token(
        &identity.stable_node_did,
        &format!("urn:cid:{lease_cid}"),
        "tinycloud.delegation/stop-renewal",
        Some(3),
        "race-second",
        now + 50,
    );
    let a = client
        .post("/delegation/renewal/state")
        .header(ContentType::JSON)
        .header(Header::new("Authorization", first.clone()))
        .json(&body);
    let b = client
        .post("/delegation/renewal/state")
        .header(ContentType::JSON)
        .header(Header::new("Authorization", second.clone()))
        .json(&body);
    let (a, b) = tokio::join!(a.dispatch(), b.dispatch());
    let statuses = [a.status(), b.status()];
    assert_eq!(statuses.iter().filter(|s| **s == Status::Ok).count(), 1);
    assert_eq!(
        statuses.iter().filter(|s| **s == Status::Conflict).count(),
        1
    );
    // Losing CAS must roll back its nonce reservation: it can sign a valid enable.
    let loser = if statuses[0] == Status::Conflict {
        "race-first"
    } else {
        "race-second"
    };
    let enable = token(
        &identity.stable_node_did,
        &format!("urn:cid:{lease_cid}"),
        "tinycloud.delegation/enable-renewal",
        Some(4),
        loser,
        now + 50,
    );
    let response = client
        .post("/delegation/renewal/state")
        .header(ContentType::JSON)
        .header(Header::new("Authorization", enable))
        .json(&json!({"version":1,"leaseCid":lease_cid,"expectedGeneration":4}))
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Ok);
    assert_eq!(
        response.into_json::<Value>().await.unwrap()["generation"],
        5
    );
}
