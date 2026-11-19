//! Every signed KV URL use re-checks revocation of the whole delegation
//! chain, not only the mint (TC-3177).
#[path = "support/owner_lease.rs"]
#[allow(dead_code)]
mod support;
use rocket::{
    http::{ContentType, Header, Status},
    local::asynchronous::Client,
};
use serde_json::{json, Value};
use support::*;
use tinycloud_auth::{
    authorization::{make_invocation, InvocationOptions},
    ipld_core::cid::Cid,
    resource::{Path, ResourceId, Service, SpaceId},
    siwe_recap::Ability,
    ssi::dids::DIDBuf,
};
use tinycloud_core::{
    hash::{hash, Hash},
    models::{abilities, revocation, space},
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

    fn db(&self) -> &tinycloud::TinyCloud {
        self.client.rocket().state().unwrap()
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

/// An unstamped grant well inside its signed expiry, so a refusal can only
/// come from the revocation check, never from an effective-end collapse.
async fn unstamped_url() -> (Grant, String, i64) {
    let now = now();
    let grant = Grant::new(now - 10, now + 3000).await;
    let (url, expires_at) = grant.mint_ok().await;
    assert!(expires_at > now + 200 && expires_at < grant.child_end);
    assert_eq!(grant.get(&url).await, Status::NotFound);
    (grant, url, expires_at)
}

async fn revoked_url_is_refused_at_next_use(revoke_parent: bool) {
    let (grant, url, expires_at) = unstamped_url().await;
    if revoke_parent {
        grant.revoke(grant.parent_id, OWNER).await;
    } else {
        grant.revoke(grant.child_id, AGENT).await;
    }
    assert!(now() < expires_at);
    // Before TC-3177 this was 404: authorization passed until `expiresAt`.
    assert_eq!(grant.get(&url).await, Status::Unauthorized);
}

#[tokio::test]
async fn revoking_the_child_after_mint_refuses_the_next_use() {
    revoked_url_is_refused_at_next_use(false).await;
}

#[tokio::test]
async fn revoking_an_ancestor_after_mint_refuses_the_next_use() {
    revoked_url_is_refused_at_next_use(true).await;
}

#[tokio::test]
async fn unrevoked_url_is_still_served() {
    let (grant, url, _) = unstamped_url().await;
    assert_eq!(grant.get(&url).await, Status::NotFound);
    assert_eq!(grant.get(&url).await, Status::NotFound);
}
