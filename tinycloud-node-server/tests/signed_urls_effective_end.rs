//! Signed KV URLs use a grant's current effective end (renewal stamps
//! included), recomputed at every use (TC-3176).
#[path = "support/owner_lease.rs"]
#[allow(dead_code)]
mod support;
use rocket::{
    http::{ContentType, Header, Status},
    local::asynchronous::Client,
};
use serde_json::{json, Value};
use std::time::Duration;
use support::*;
use tinycloud_auth::{
    authorization::{
        make_invocation, make_invocation_from_uris, InvocationOptions, TinyCloudInvocation,
    },
    ipld_core::cid::Cid,
    resource::{Path, ResourceId, Service, SpaceId},
    siwe_recap::Ability,
    ssi::{dids::DIDBuf, jwk::JWK},
};
use tinycloud_core::{
    events::Invocation,
    hash::{hash, Hash},
    keys::StaticSecret,
    models::{abilities, revocation, space},
    renewal::{StampIssue, RENEWER_KEY_CONTEXT},
    sea_orm::{
        sea_query::Value as Sql, ActiveModelTrait, ActiveValue::Set, ConnectionTrait, Statement,
    },
    types::{Ability as CoreAbility, Caveats, Resource, SpaceIdWrap},
};

const OWNER: u8 = 0x33;
const AGENT: u8 = 0x11;
const PEER: u8 = 0x22;
const KV_GET: &str = "tinycloud.kv/get";

fn now() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

fn dt(ts: i64) -> Sql {
    let t = time::OffsetDateTime::from_unix_timestamp(ts).unwrap();
    Sql::TimeDateTime(Some(Box::new(time::PrimitiveDateTime::new(
        t.date(),
        t.time(),
    ))))
}

/// Sleep until the wall clock is past `ts`.
async fn sleep_past(ts: i64) {
    let wait =
        (ts + 1) as f64 - time::OffsetDateTime::now_utc().unix_timestamp_nanos() as f64 / 1e9;
    if wait > 0.0 {
        rocket::tokio::time::sleep(Duration::from_secs_f64(wait)).await;
    }
}

/// owner -> agent (parent) -> peer (child) on the owner's space, granting
/// `tinycloud.kv/get` on `kv/documents`. Seeded rows, as in
/// `owner_lease_registration.rs`.
struct Grant {
    client: Client,
    _dir: tempfile::TempDir,
    space: SpaceId,
    resource: ResourceId,
    parent_id: Hash,
    child_id: Hash,
    child_cid: String,
    child_end: i64,
}

impl Grant {
    async fn new(child_start: i64, child_end: i64) -> Self {
        let (client, dir) = node(None).await;
        let now = now();
        let (_, owner, _) = key_for_seed(OWNER);
        let (_, agent, _) = key_for_seed(AGENT);
        let (_, peer, _) = key_for_seed(PEER);
        let space =
            SpaceId::new(owner.parse::<DIDBuf>().unwrap(), "alpha".parse().unwrap()).unwrap();
        let resource = space.clone().to_resource(
            "kv".parse::<Service>().unwrap(),
            Some("documents".parse::<Path>().unwrap()),
            None,
            None,
        );
        let uri = resource.as_uri().to_string();
        let parent_end = now + 3600;
        let parent = token(&agent, &uri, KV_GET, None, "parent", parent_end);
        let parent = resign(&parent, OWNER, |c| c["nbf"] = json!(now - 1000));
        let parent_id = hash(parent.as_bytes());
        let child = token(&peer, &uri, KV_GET, None, "child", child_end);
        let child = resign(&child, AGENT, |c| {
            c["nbf"] = json!(child_start);
            c["prf"] = json!([parent_id.to_cid(0x55).to_string()]);
        });
        let child_id = hash(child.as_bytes());
        let child_cid = child_id.to_cid(0x55).to_string();

        let db = client.rocket().state::<tinycloud::TinyCloud>().unwrap();
        let identity = db.renewal_identity().unwrap().clone();
        let conn = db.connection();
        let backend = conn.get_database_backend();
        space::ActiveModel {
            id: Set(SpaceIdWrap(space.clone())),
        }
        .insert(conn)
        .await
        .unwrap();
        for actor in [
            &owner,
            &agent,
            &peer,
            &identity.stable_node_did,
            &identity.renewer_did,
        ] {
            conn.execute(Statement::from_sql_and_values(
                backend,
                "INSERT INTO actor (id) VALUES ($1) ON CONFLICT DO NOTHING",
                [Sql::String(Some(Box::new(actor.clone())))],
            ))
            .await
            .unwrap();
        }
        for (id, serialized, delegator, delegatee, expiry) in [
            (parent_id, parent, &owner, &agent, parent_end),
            (child_id, child, &agent, &peer, child_end),
        ] {
            conn.execute(Statement::from_sql_and_values(backend,
                "INSERT INTO delegation (id, delegator, delegatee, expiry, issued_at, not_before, facts, serialization, serialization_format) VALUES ($1,$2,$3,$4,NULL,NULL,NULL,$5,0)",
                [Sql::Bytes(Some(Box::new(Vec::<u8>::from(id)))), Sql::String(Some(Box::new(delegator.clone()))), Sql::String(Some(Box::new(delegatee.clone()))), dt(expiry), Sql::Bytes(Some(Box::new(serialized.into_bytes())))])).await.unwrap();
            conn.execute(Statement::from_sql_and_values(
                backend,
                "INSERT INTO delegation_cid_alias (id, canonical, encrypted) VALUES ($1,$1,FALSE)",
                [Sql::Bytes(Some(Box::new(Vec::<u8>::from(id))))],
            ))
            .await
            .unwrap();
            abilities::ActiveModel {
                delegation: Set(id),
                resource: Set(Resource::TinyCloud(resource.clone())),
                ability: Set(CoreAbility::try_from(KV_GET.to_string()).unwrap()),
                caveats: Set(Caveats::default()),
            }
            .insert(conn)
            .await
            .unwrap();
        }
        conn.execute(Statement::from_sql_and_values(
            backend,
            "INSERT INTO parent_delegation (child, parent) VALUES ($1,$2)",
            [
                Sql::Bytes(Some(Box::new(Vec::<u8>::from(child_id)))),
                Sql::Bytes(Some(Box::new(Vec::<u8>::from(parent_id)))),
            ],
        ))
        .await
        .unwrap();
        Self {
            client,
            _dir: dir,
            space,
            resource,
            parent_id,
            child_id,
            child_cid,
            child_end,
        }
    }

    /// A stamped grant: the agent registers a lease on the child over HTTP
    /// `/delegate`, and the node issues one stamp. Returns the stamp's end and
    /// the lease's id. No further stamp is issued.
    async fn stamped(period: i64, signed_in: i64) -> (Self, i64, Hash) {
        let now = now();
        let grant = Self::new(now + signed_in - period, now + signed_in).await;
        let (stamp_end, lease_id) = grant.stamp().await;
        assert!(
            stamp_end > grant.child_end,
            "stamp extends past the signed expiry"
        );
        (grant, stamp_end, lease_id)
    }

    fn db(&self) -> &tinycloud::TinyCloud {
        self.client.rocket().state().unwrap()
    }

    async fn stamp(&self) -> (i64, Hash) {
        let db = self.db();
        let identity = db.renewal_identity().unwrap().clone();
        let now = now();
        let lease = token(
            &identity.renewer_did,
            &format!("urn:cid:{}", self.child_cid),
            "tinycloud.delegation/renew",
            None,
            "lease",
            now + 7200,
        );
        let lease = resign(&lease, AGENT, |c| c["nbf"] = json!(now - 1));
        let lease_id = hash(lease.as_bytes());
        let lease_cid = lease_id.to_cid(0x55).to_string();
        let response = self
            .client
            .post("/delegate")
            .header(Header::new("Authorization", lease))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);

        let seed = StaticSecret::new(vec![0x42; 32])
            .unwrap()
            .derive_key(RENEWER_KEY_CONTEXT);
        let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
        let renewer: JWK =
            serde_json::from_value(json!({"kty":"OKP","crv":"Ed25519","alg":"EdDSA",
            "x":base64::encode_config(signing.verifying_key().to_bytes(),base64::URL_SAFE_NO_PAD),
            "d":base64::encode_config(seed,base64::URL_SAFE_NO_PAD)}))
            .unwrap();
        let method = format!(
            "{}#{}",
            identity.renewer_did,
            identity.renewer_did.rsplit(':').next().unwrap()
        );
        let lease_cid_parsed: Cid = lease_cid.parse().unwrap();
        let invocation = make_invocation_from_uris(
            [(
                format!("urn:cid:{}", self.child_cid).parse().unwrap(),
                ["tinycloud.delegation/renew".parse().unwrap()],
            )],
            &lease_cid_parsed,
            &renewer,
            &method,
            (now + 300) as f64,
            InvocationOptions {
                nonce: Some("urn:uuid:00000000-0000-4000-8000-0000000000aa".into()),
                proof: Some(vec![lease_cid_parsed]),
                ..Default::default()
            },
        )
        .unwrap();
        let event =
            Invocation::from_header_ser::<TinyCloudInvocation>(&invocation.encode().unwrap())
                .unwrap();
        let replay_hash = event.content_hash();
        let stamp = db
            .issue_renewal_stamp(StampIssue {
                invocation: event.0,
                original_cid: self.child_cid.clone(),
                lease_cid,
                replay_hash,
                replay_expires_at: now + 300,
            })
            .await
            .unwrap();
        (stamp.new_end, lease_id)
    }

    /// `POST /signed/kv` as the peer, citing the child.
    async fn mint(&self) -> (Status, Value) {
        let (jwk, _, method) = key_for_seed(PEER);
        let proof: Cid = self.child_cid.parse().unwrap();
        let header = make_invocation(
            [(self.resource.clone(), [KV_GET.parse::<Ability>().unwrap()])],
            &proof,
            &jwk,
            &method,
            (now() + 240) as f64,
            InvocationOptions {
                proof: Some(vec![proof]),
                ..Default::default()
            },
        )
        .unwrap()
        .encode()
        .unwrap();
        let response = self
            .client
            .post("/signed/kv")
            .header(Header::new("Authorization", header))
            .header(ContentType::JSON)
            .body(
                json!({
                    "space": self.space.to_string(),
                    "path": "documents/doc",
                    "ttlSeconds": 300,
                    "contentHash": hex::encode(hash(b"doc").as_ref()),
                })
                .to_string(),
            )
            .dispatch()
            .await;
        let status = response.status();
        let body = response.into_string().await.unwrap_or_default();
        (status, serde_json::from_str(&body).unwrap_or(json!(body)))
    }

    /// Returns the URL and its `expiresAt` in unix seconds.
    async fn mint_ok(&self) -> (String, i64) {
        let (status, body) = self.mint().await;
        assert_eq!(status, Status::Ok, "{body}");
        let expires_at = time::OffsetDateTime::parse(
            body["expiresAt"].as_str().unwrap(),
            &time::format_description::well_known::Rfc3339,
        )
        .unwrap();
        (
            body["url"].as_str().unwrap().to_string(),
            expires_at.unix_timestamp(),
        )
    }

    /// `GET` the URL. The object was never written, so a URL that is still
    /// valid answers 404 and a refused one 401.
    async fn get(&self, url: &str) -> Status {
        self.client.get(url).dispatch().await.status()
    }

    async fn revoke(&self, id: Hash, revoker: u8) {
        revocation::ActiveModel {
            id: Set(hash(
                &[b"revoke-".as_slice(), Vec::<u8>::from(id).as_slice()].concat(),
            )),
            revoker: Set(key_for_seed(revoker).1),
            revoked: Set(id),
            serialization: Set(b"revoke".to_vec()),
            revoked_at: Set(Some(time::OffsetDateTime::now_utc())),
        }
        .insert(self.db().connection())
        .await
        .unwrap();
    }
}

#[tokio::test]
async fn stamped_grant_url_is_valid_past_its_signed_expiry_until_the_effective_end() {
    let (grant, stamp_end, _) = Grant::stamped(20, 4).await;
    sleep_past(grant.child_end).await;
    // Before TC-3176 this was 401 "signed URL expired immediately": the URL
    // was capped at the child's signed expiry.
    let (url, expires_at) = grant.mint_ok().await;
    assert_eq!(expires_at, stamp_end);
    assert!(now() > grant.child_end);
    assert_eq!(grant.get(&url).await, Status::NotFound);
}

#[tokio::test]
async fn url_is_refused_after_the_effective_end_when_stamping_stops() {
    let (grant, stamp_end, _) = Grant::stamped(12, 4).await;
    sleep_past(grant.child_end).await;
    let (url, _) = grant.mint_ok().await;
    assert_eq!(grant.get(&url).await, Status::NotFound);
    sleep_past(stamp_end).await;
    assert_eq!(grant.get(&url).await, Status::Unauthorized);
    assert_ne!(grant.mint().await.0, Status::Ok);
}

#[tokio::test]
async fn each_use_recomputes_the_effective_end() {
    let (grant, _, lease_id) = Grant::stamped(60, 4).await;
    sleep_past(grant.child_end).await;
    let (url, expires_at) = grant.mint_ok().await;
    assert_eq!(grant.get(&url).await, Status::NotFound);
    // Revoking the lease drops its stamps: the effective end falls back to
    // the signed expiry, already past, while the stored `expiresAt` is not.
    grant.revoke(lease_id, AGENT).await;
    assert!(now() < expires_at);
    assert_eq!(grant.get(&url).await, Status::Unauthorized);
}

async fn revoked_url_is_refused(revoke_parent: bool) {
    let (grant, _, _) = Grant::stamped(60, 3).await;
    sleep_past(grant.child_end).await;
    let (url, _) = grant.mint_ok().await;
    assert_eq!(grant.get(&url).await, Status::NotFound);
    if revoke_parent {
        grant.revoke(grant.parent_id, OWNER).await;
    } else {
        grant.revoke(grant.child_id, AGENT).await;
    }
    assert_eq!(grant.get(&url).await, Status::Unauthorized);
    assert_ne!(grant.mint().await.0, Status::Ok);
}

#[tokio::test]
async fn revoking_the_child_refuses_the_url() {
    revoked_url_is_refused(false).await;
}

#[tokio::test]
async fn revoking_an_ancestor_refuses_the_url() {
    revoked_url_is_refused(true).await;
}

#[tokio::test]
async fn unstamped_grant_url_keeps_its_signed_expiry() {
    let now = now();
    let grant = Grant::new(now - 10, now + 4).await;
    let (url, expires_at) = grant.mint_ok().await;
    assert_eq!(expires_at, grant.child_end);
    assert_eq!(grant.get(&url).await, Status::NotFound);
    sleep_past(grant.child_end).await;
    assert_eq!(grant.get(&url).await, Status::Unauthorized);
    assert_ne!(grant.mint().await.0, Status::Ok);
}
