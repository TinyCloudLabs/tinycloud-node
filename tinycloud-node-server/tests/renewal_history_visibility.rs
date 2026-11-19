//! Original-party status reads retain signed history and exact-target isolation.
mod common;
#[allow(dead_code)]
#[path = "support/owner_lease.rs"]
mod setup;

use rocket::{
    http::{ContentType, Header, Status},
    local::asynchronous::Client,
};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use tinycloud_auth::{
    authorization::Cid,
    resolver::DID_METHODS,
    resource::SpaceId,
    ssi::{
        claims::jwt::NumericDate,
        jwk::{Algorithm, JWK},
        ucan::Payload,
    },
    ucan_capabilities_object::Capabilities,
};
use tinycloud_core::{
    hash::{hash, Hash},
    keys::StaticSecret,
    renewal::{RenewalSigner, StampRecord, RENEWER_KEY_CONTEXT},
    sea_orm::{sea_query::Value as Sql, ConnectionTrait, Statement},
};

fn did(key: &JWK) -> String {
    DID_METHODS.generate(key, "key").unwrap().to_string()
}
fn token(key: &JWK, audience: &str, resource: &str, action: &str, start: i64, end: i64) -> String {
    let issuer = did(key);
    let method = format!("{issuer}#{}", issuer.rsplit(':').next().unwrap());
    let mut caps = Capabilities::<Value>::new();
    caps.with_action(
        resource.parse().unwrap(),
        action.parse().unwrap(),
        [BTreeMap::new()],
    );
    Payload::<Value> {
        issuer: method.parse().unwrap(),
        audience: audience.parse().unwrap(),
        not_before: Some(NumericDate::try_from_seconds(start as f64).unwrap()),
        expiration: NumericDate::try_from_seconds(end as f64).unwrap(),
        nonce: Some(uuid::Uuid::new_v4().to_string()),
        facts: None,
        proof: vec![],
        attenuation: caps,
    }
    .sign(Algorithm::EdDSA, key)
    .unwrap()
    .encode()
    .unwrap()
}
async fn register(client: &Client, authorization: String) {
    let r = client
        .post("/delegate")
        .header(Header::new("Authorization", authorization))
        .dispatch()
        .await;
    let status = r.status();
    let body = r.into_string().await.unwrap_or_default();
    assert_eq!(status, Status::Ok, "{body}");
}
struct Grant {
    id: Hash,
    cid: String,
    lease: Hash,
    lease_cid: String,
    stamps: Vec<StampRecord>,
}
async fn grant(
    client: &Client,
    owner: &JWK,
    holder: &JWK,
    name: &str,
    now: i64,
    count: usize,
) -> Grant {
    let db = client.rocket().state::<tinycloud::TinyCloud>().unwrap();
    let identity = db.renewal_identity().unwrap();
    let secret = StaticSecret::new(vec![0x42; 32]).unwrap();
    let space: SpaceId = format!(
        "tinycloud:{}:{name}",
        did(owner).strip_prefix("did:").unwrap()
    )
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
    let original = token(
        owner,
        &did(holder),
        &resource,
        "tinycloud.kv/get",
        now - 121,
        now + 240,
    );
    let id = hash(original.as_bytes());
    let cid = id.to_cid(0x55).to_string();
    register(client, original).await;
    let lease_token = token(
        owner,
        &identity.renewer_did,
        &format!("urn:cid:{cid}"),
        "tinycloud.delegation/renew",
        now - 241,
        now + 600,
    );
    let lease = hash(lease_token.as_bytes());
    let lease_cid = lease.to_cid(0x55).to_string();
    register(client, lease_token).await;
    let signer = RenewalSigner::from_seed(
        secret.derive_key(RENEWER_KEY_CONTEXT),
        identity.stable_node_did.clone(),
        identity.epoch,
    );
    let mut previous = lease_cid.clone();
    let mut stamps = Vec::new();
    for index in 0..count {
        let end = now + 300 + 60 * index as i64;
        let date = time::OffsetDateTime::from_unix_timestamp(end).unwrap();
        let (bytes, signature, stamp_cid) = signer
            .sign_stamp(
                &cid,
                &lease_cid,
                1,
                &previous,
                &date
                    .format(&time::format_description::well_known::Rfc3339)
                    .unwrap(),
            )
            .unwrap();
        let stamp_id = Hash::from(stamp_cid.parse::<Cid>().unwrap());
        let prev_id = Hash::from(previous.parse::<Cid>().unwrap());
        db.connection().execute(Statement::from_sql_and_values(db.connection().get_database_backend(),
            "INSERT INTO renewal_stamp (cid,original_canonical,lease_cid,generation,previous_stamp_cid,renewer_epoch,new_end,signed_bytes,signature,replay_hash) VALUES ($1,$2,$3,1,$4,$5,$6,$7,$8,$9)",
            [Vec::<u8>::from(stamp_id).into(),Vec::<u8>::from(id).into(),Vec::<u8>::from(lease).into(),Vec::<u8>::from(prev_id).into(),
             (identity.epoch as i64).into(),Sql::TimeDateTime(Some(Box::new(time::PrimitiveDateTime::new(date.date(),date.time())))),
             bytes.clone().into(),signature.clone().into(),Vec::<u8>::from(hash(format!("{cid}-{index}").as_bytes())).into()])).await.unwrap();
        stamps.push(StampRecord {
            cid: stamp_cid.clone(),
            lease_cid: lease_cid.clone(),
            generation: 1,
            previous_stamp_cid: previous,
            new_end: end,
            signed_bytes: bytes,
            signature,
        });
        previous = stamp_cid;
    }
    Grant {
        id,
        cid,
        lease,
        lease_cid,
        stamps,
    }
}
async fn status(client: &Client, key: &JWK, cid: &str, now: i64) -> (Status, Value) {
    let node = StaticSecret::new(vec![0x42; 32]).unwrap().node_did();
    let auth = token(
        key,
        &node,
        &format!("urn:cid:{cid}"),
        "tinycloud.delegation/status",
        now - 1,
        now + 600,
    );
    let r = client
        .post("/delegation/status")
        .header(Header::new("Authorization", auth))
        .header(ContentType::JSON)
        .body(json!({"cid":cid}).to_string())
        .dispatch()
        .await;
    let code = r.status();
    (code, r.into_json().await.unwrap())
}
fn refused(cid: &str) -> Value {
    json!({"cid":cid,"status":"not_found","exists":false,"active":false,"revoked":false,"expired":false,"effective_expiry":null,"renewal_history":[]})
}
fn history(body: &Value) -> &Vec<Value> {
    body["renewal_history"].as_array().unwrap()
}

async fn exercise(url: Option<&str>, backend: &str) {
    let (client, _dir) = setup::node(url).await;
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let owner = setup::key_for_seed(0x11).0;
    let holder_a = setup::key_for_seed(0x22).0;
    let holder_b = setup::key_for_seed(0x33).0;
    let other_owner = setup::key_for_seed(0x44).0;
    let other_holder = setup::key_for_seed(0x55).0;
    let stranger = setup::key_for_seed(0x66).0;
    let a = grant(&client, &owner, &holder_a, "hist-a", now, 2).await;
    let b = grant(&client, &owner, &holder_b, "hist-b", now, 1).await;
    let c = grant(&client, &other_owner, &other_holder, "hist-c", now, 1).await;
    let (code, holder) = status(&client, &holder_a, &a.cid, now).await;
    assert_eq!(code, Status::Ok);
    assert_eq!(holder["status"], "active");
    assert_eq!(history(&holder).len(), 2);
    assert_eq!(holder["effective_expiry"], a.stamps[1].new_end);
    let (_, owner_body) = status(&client, &owner, &a.cid, now).await;
    assert_eq!(holder, owner_body);
    let secret = StaticSecret::new(vec![0x42; 32]).unwrap();
    let public = ed25519_dalek::SigningKey::from_bytes(&secret.derive_key(RENEWER_KEY_CONTEXT))
        .verifying_key()
        .to_bytes();
    for row in history(&holder) {
        let bytes = base64::decode_config(
            row["signed_bytes"].as_str().unwrap(),
            base64::URL_SAFE_NO_PAD,
        )
        .unwrap();
        let signature =
            base64::decode_config(row["signature"].as_str().unwrap(), base64::URL_SAFE_NO_PAD)
                .unwrap();
        tinycloud_core::renewal::verify_stamp_signature(&bytes, &signature, &public).unwrap();
        assert_eq!(hash(&bytes).to_cid(0x55).to_string(), row["cid"]);
        let mut fields = row
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>();
        fields.sort_unstable();
        assert_eq!(
            fields,
            [
                "cid",
                "generation",
                "lease_cid",
                "new_end",
                "previous_stamp_cid",
                "signature",
                "signed_bytes"
            ]
        );
    }
    for (key, cid) in [
        (&stranger, &a.cid),
        (&other_owner, &a.cid),
        (&holder_a, &b.cid),
        (&holder_a, &c.cid),
        (&holder_b, &a.cid),
        (&holder_a, &a.lease_cid),
    ] {
        let (code, body) = status(&client, key, cid, now).await;
        assert_eq!(code, Status::NotFound);
        assert_eq!(body, refused(cid));
    }
    let alias = a.id.to_cid(0x71).to_string();
    let (code, alias_body) = status(&client, &holder_a, &alias, now).await;
    assert_eq!(code, Status::Ok);
    assert_eq!(history(&alias_body), history(&holder));
    assert_eq!(alias_body["effective_expiry"], holder["effective_expiry"]);
    // A signed B stamp relabelled into A's SQL group and lease must stay invisible.
    let db = client.rocket().state::<tinycloud::TinyCloud>().unwrap();
    db.connection()
        .execute(Statement::from_sql_and_values(
            db.connection().get_database_backend(),
            "UPDATE renewal_stamp SET original_canonical=$1,lease_cid=$2 WHERE cid=$3",
            [
                Vec::<u8>::from(a.id).into(),
                Vec::<u8>::from(a.lease).into(),
                Vec::<u8>::from(Hash::from(b.stamps[0].cid.parse::<Cid>().unwrap())).into(),
            ],
        ))
        .await
        .unwrap();
    let (_, bounded) = status(&client, &holder_a, &a.cid, now).await;
    assert_eq!(history(&bounded), history(&holder));
    let (_, bounded_alias) = status(&client, &holder_a, &alias, now).await;
    assert_eq!(history(&bounded_alias), history(&holder));
    if let Some(directory) = std::env::var_os("TINYCLOUD_HISTORY_SDK_FIXTURE_DIR") {
        let directory = std::path::PathBuf::from(directory);
        std::fs::create_dir_all(&directory).unwrap();
        let identity = db.renewal_identity().unwrap();
        let fixture = json!({"input":{"originalCid":a.cid,"leaseCid":a.lease_cid,"leaseExpiresAt":now+600,"now":now,
            "nodeIdentity":{"nodeDid":identity.stable_node_did,"renewerDid":identity.renewer_did,"renewerPublicKey":base64::encode_config(public,base64::URL_SAFE_NO_PAD),"renewerEpoch":identity.epoch},
            "history":holder["renewal_history"]},"expectedExpiry":holder["effective_expiry"]});
        std::fs::write(
            directory.join(format!("{backend}.json")),
            serde_json::to_vec_pretty(&fixture).unwrap(),
        )
        .unwrap();
    }
    let revoke = token(
        &owner,
        &secret.node_did(),
        &format!("urn:cid:{}", a.cid),
        "tinycloud.delegation/revoke",
        now - 1,
        now + 600,
    );
    assert_eq!(
        client
            .post("/revoke")
            .header(Header::new("Authorization", revoke))
            .dispatch()
            .await
            .status(),
        Status::Ok
    );
    for key in [&owner, &holder_a] {
        let (code, body) = status(&client, key, &a.cid, now).await;
        assert_eq!(code, Status::Ok);
        assert_eq!(body["status"], "revoked");
        assert_eq!(body["active"], false);
        assert_eq!(body["revoked"], true);
        assert_eq!(body["exists"], true);
    }
}

#[tokio::test]
async fn original_holder_history_is_exactly_scoped_and_verifiable() {
    exercise(None, "sqlite").await;
    if let Some(url) =
        common::postgres_test_url("original_holder_history_is_exactly_scoped_and_verifiable")
    {
        use tinycloud_core::sea_orm::{Database, DatabaseBackend};
        let admin = Database::connect(&url).await.unwrap();
        let schema = format!("holder_history_{}", uuid::Uuid::new_v4().simple());
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
        exercise(Some(scoped.as_str()), "postgres").await;
        admin
            .execute(Statement::from_string(
                DatabaseBackend::Postgres,
                format!("DROP SCHEMA {schema} CASCADE"),
            ))
            .await
            .unwrap();
    }
}
