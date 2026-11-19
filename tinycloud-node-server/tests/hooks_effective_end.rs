//! Hook tickets and stream opens use a grant's current effective end (renewal
//! stamps included), recomputed at every open, and check the whole chain for
//! revocation (TC-3174).
#[path = "support/owner_lease.rs"]
#[allow(dead_code)]
mod support;
use rocket::{
    figment::{providers::Serialized, Figment},
    http::{ContentType, Header, Status},
    local::asynchronous::{Client, LocalResponse},
    tokio::io::AsyncReadExt,
};
use serde_json::{json, Value};
use std::time::{Duration, Instant};
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
    models::{abilities, revocation},
    renewal::{StampIssue, RENEWER_KEY_CONTEXT},
    sea_orm::{
        sea_query::Value as Sql, ActiveModelTrait, ActiveValue::Set, ConnectionTrait, Statement,
    },
    types::{Ability as CoreAbility, Caveats, Resource},
};

const OWNER: u8 = 0x33;
const AGENT: u8 = 0x11;
const PEER: u8 = 0x22;

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

async fn node(max_ticket_ttl_seconds: u64) -> (Client, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let mut config = tinycloud::config::Config::default();
    config.storage.datadir = dir.path().into();
    config.storage.database = Some("sqlite::memory:".into());
    config.hooks.max_ticket_ttl_seconds = max_ticket_ttl_seconds;
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
    (client, dir)
}

/// owner -> agent (parent) -> peer (child) on the owner's space, granting
/// `tinycloud.hooks/subscribe` on `hooks/kv/documents`. Seeded rows, as in
/// `owner_lease_registration.rs`.
struct Grant {
    client: Client,
    _dir: tempfile::TempDir,
    resource: ResourceId,
    parent_id: Hash,
    child_id: Hash,
    child_cid: String,
    child_end: i64,
}

impl Grant {
    async fn new(max_ticket_ttl_seconds: u64, child_start: i64, child_end: i64) -> Self {
        let (client, dir) = node(max_ticket_ttl_seconds).await;
        let now = now();
        let (_, owner, _) = key_for_seed(OWNER);
        let (_, agent, _) = key_for_seed(AGENT);
        let (_, peer, _) = key_for_seed(PEER);
        let space =
            SpaceId::new(owner.parse::<DIDBuf>().unwrap(), "alpha".parse().unwrap()).unwrap();
        let resource = space.to_resource(
            "hooks".parse::<Service>().unwrap(),
            Some("kv/documents".parse::<Path>().unwrap()),
            None,
            None,
        );
        let uri = resource.as_uri().to_string();
        let parent_end = now + 3600;
        let parent = token(
            &agent,
            &uri,
            "tinycloud.hooks/subscribe",
            None,
            "parent",
            parent_end,
        );
        let parent = resign(&parent, OWNER, |c| c["nbf"] = json!(now - 1000));
        let parent_id = hash(parent.as_bytes());
        let child = token(
            &peer,
            &uri,
            "tinycloud.hooks/subscribe",
            None,
            "child",
            child_end,
        );
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
                ability: Set(
                    CoreAbility::try_from("tinycloud.hooks/subscribe".to_string()).unwrap(),
                ),
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
    async fn stamped(
        max_ticket_ttl_seconds: u64,
        period: i64,
        signed_in: i64,
    ) -> (Self, i64, Hash) {
        let now = now();
        let grant = Self::new(
            max_ticket_ttl_seconds,
            now + signed_in - period,
            now + signed_in,
        )
        .await;
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

    /// `POST /hooks/tickets` as the peer, citing the child.
    async fn mint(&self) -> (Status, Value) {
        let (jwk, _, method) = key_for_seed(PEER);
        let proof: Cid = self.child_cid.parse().unwrap();
        let header = make_invocation(
            [(
                self.resource.clone(),
                ["tinycloud.hooks/subscribe".parse::<Ability>().unwrap()],
            )],
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
            .post("/hooks/tickets")
            .header(Header::new("Authorization", header))
            .header(ContentType::JSON)
            .body(
                json!({
                    "subscriptions": [{
                        "space": self.resource.space().to_string(),
                        "service": "kv",
                        "pathPrefix": "documents",
                    }],
                    "ttlSeconds": 300,
                })
                .to_string(),
            )
            .dispatch()
            .await;
        let status = response.status();
        let body = response.into_string().await.unwrap_or_default();
        (status, serde_json::from_str(&body).unwrap_or(json!(body)))
    }

    async fn mint_ok(&self) -> (String, tinycloud::hooks::HookTicketClaims) {
        let (status, body) = self.mint().await;
        assert_eq!(status, Status::Ok, "{body}");
        let ticket = body["ticket"].as_str().unwrap().to_string();
        let claims = self
            .client
            .rocket()
            .state::<tinycloud::hooks::HookRuntime>()
            .unwrap()
            .verify_ticket(&ticket)
            .unwrap();
        let expires_at = time::OffsetDateTime::parse(
            body["expiresAt"].as_str().unwrap(),
            &time::format_description::well_known::Rfc3339,
        )
        .unwrap();
        assert_eq!(expires_at.unix_timestamp(), claims.exp);
        (ticket, claims)
    }

    async fn open(&self, ticket: &str) -> LocalResponse<'_> {
        self.client
            .get(format!("/hooks/events?ticket={ticket}"))
            .dispatch()
            .await
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

/// Reads until the stream's `ready` event.
async fn read_ready(response: &mut LocalResponse<'_>) {
    let mut seen = String::new();
    let mut buf = [0u8; 1024];
    while !seen.contains("event:ready") {
        let n = rocket::tokio::time::timeout(Duration::from_secs(5), response.read(&mut buf))
            .await
            .expect("ready event")
            .unwrap();
        assert!(n > 0, "stream ended before ready: {seen}");
        seen.push_str(&String::from_utf8_lossy(&buf[..n]));
    }
}

/// Reads until the stream ends; returns when it ended.
async fn read_to_end(response: &mut LocalResponse<'_>, limit: Duration) -> Instant {
    let mut buf = [0u8; 1024];
    rocket::tokio::time::timeout(limit, async {
        while response.read(&mut buf).await.unwrap() > 0 {}
    })
    .await
    .expect("stream ended within the limit");
    Instant::now()
}

fn instant_at(ts: i64) -> Instant {
    let remaining = ts as f64 - time::OffsetDateTime::now_utc().unix_timestamp_nanos() as f64 / 1e9;
    if remaining >= 0.0 {
        Instant::now() + Duration::from_secs_f64(remaining)
    } else {
        Instant::now() - Duration::from_secs_f64(-remaining)
    }
}

#[tokio::test]
async fn stamped_grant_mints_a_ticket_and_stays_subscribed_past_its_signed_expiry() {
    let (grant, stamp_end, _) = Grant::stamped(300, 20, 4).await;
    sleep_past(grant.child_end).await;
    // Before TC-3174 this was 401 "hook ticket expired immediately": the
    // ticket was capped at the child's signed expiry.
    let (ticket, claims) = grant.mint_ok().await;
    assert_eq!(claims.parent_exp, stamp_end);
    assert_eq!(claims.exp, stamp_end);
    let mut stream = grant.open(&ticket).await;
    assert_eq!(stream.status(), Status::Ok);
    read_ready(&mut stream).await;
    assert!(now() > grant.child_end);
    let mut buf = [0u8; 64];
    // The rest of the `ready` event may still arrive; the stream must not end.
    assert!(
        rocket::tokio::time::timeout(Duration::from_secs(3), async {
            while stream.read(&mut buf).await.unwrap() > 0 {}
        })
        .await
        .is_err(),
        "stream stays open past the signed expiry"
    );
}

#[tokio::test]
async fn stream_closes_at_the_effective_end_when_stamping_stops() {
    let (grant, stamp_end, _) = Grant::stamped(300, 20, 4).await;
    sleep_past(grant.child_end).await;
    let (ticket, _) = grant.mint_ok().await;
    let mut stream = grant.open(&ticket).await;
    assert_eq!(stream.status(), Status::Ok);
    read_ready(&mut stream).await;
    let ended = read_to_end(&mut stream, Duration::from_secs(30)).await;
    let end = instant_at(stamp_end);
    assert!(
        ended + Duration::from_millis(100) >= end,
        "not before the effective end"
    );
    assert!(
        ended <= end + Duration::from_secs(2),
        "at the effective end"
    );
    // No stamp extended it: the grant is over for new tickets and reopens.
    assert_ne!(grant.mint().await.0, Status::Ok);
    assert_eq!(grant.open(&ticket).await.status(), Status::Unauthorized);
}

#[tokio::test]
async fn reopen_recomputes_the_effective_end() {
    let (grant, _, lease_id) = Grant::stamped(300, 40, 4).await;
    sleep_past(grant.child_end).await;
    let (ticket, _) = grant.mint_ok().await;
    let mut stream = grant.open(&ticket).await;
    assert_eq!(stream.status(), Status::Ok);
    read_ready(&mut stream).await;
    drop(stream);
    // Revoking the lease drops its stamps: the effective end falls back to
    // the signed expiry, already past. The still-unexpired ticket can't reopen.
    grant.revoke(lease_id, AGENT).await;
    assert_eq!(grant.open(&ticket).await.status(), Status::Unauthorized);
}

async fn revoked_stream_ends_within_the_ticket_ttl(revoke_parent: bool) {
    const TTL: u64 = 4;
    let (grant, _, _) = Grant::stamped(TTL, 60, 3).await;
    sleep_past(grant.child_end).await;
    let (ticket, claims) = grant.mint_ok().await;
    assert!(claims.exp <= now() + TTL as i64);
    let mut stream = grant.open(&ticket).await;
    assert_eq!(stream.status(), Status::Ok);
    read_ready(&mut stream).await;
    let revoked_at = Instant::now();
    if revoke_parent {
        grant.revoke(grant.parent_id, OWNER).await;
    } else {
        grant.revoke(grant.child_id, AGENT).await;
    }
    let ended = read_to_end(&mut stream, Duration::from_secs(TTL + 5)).await;
    assert!(
        ended <= revoked_at + Duration::from_secs(TTL + 1),
        "open stream ends within max_ticket_ttl_seconds of the revoke"
    );
    let reopen = grant.open(&ticket).await;
    assert_eq!(reopen.status(), Status::Unauthorized);
    let mint = grant.mint().await;
    assert_ne!(mint.0, Status::Ok, "{mint:?}");
}

#[tokio::test]
async fn revoking_the_child_ends_the_stream_within_the_ticket_ttl() {
    revoked_stream_ends_within_the_ticket_ttl(false).await;
}

#[tokio::test]
async fn revoking_an_ancestor_ends_the_stream_within_the_ticket_ttl() {
    revoked_stream_ends_within_the_ticket_ttl(true).await;
}

#[tokio::test]
async fn reopen_after_revoke_reports_the_revoked_delegation() {
    for (revoke_parent, code) in [(false, "delegation_revoked"), (true, "parent_revoked")] {
        let now = now();
        let grant = Grant::new(300, now - 10, now + 600).await;
        let (ticket, _) = grant.mint_ok().await;
        if revoke_parent {
            grant.revoke(grant.parent_id, OWNER).await;
        } else {
            grant.revoke(grant.child_id, AGENT).await;
        }
        let response = grant.open(&ticket).await;
        assert_eq!(response.status(), Status::Unauthorized);
        let body: Value =
            serde_json::from_str(&response.into_string().await.unwrap_or_default()).unwrap();
        assert_eq!(body["code"], code);
    }
}

#[tokio::test]
async fn unstamped_grant_keeps_its_signed_expiry() {
    let now = now();
    let grant = Grant::new(300, now - 10, now + 4).await;
    let (ticket, claims) = grant.mint_ok().await;
    assert_eq!(claims.parent_exp, grant.child_end);
    assert_eq!(claims.exp, grant.child_end);
    let mut stream = grant.open(&ticket).await;
    assert_eq!(stream.status(), Status::Ok);
    read_ready(&mut stream).await;
    let ended = read_to_end(&mut stream, Duration::from_secs(15)).await;
    let end = instant_at(grant.child_end);
    assert!(ended + Duration::from_millis(100) >= end);
    assert!(ended <= end + Duration::from_secs(2));
    assert_ne!(grant.mint().await.0, Status::Ok);
}

#[tokio::test]
async fn info_advertises_hooks_effective_end() {
    let (client, _dir) = node(300).await;
    let response = client.get("/info").dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    let info: Value = serde_json::from_str(&response.into_string().await.unwrap()).unwrap();
    assert!(
        info["features"]
            .as_array()
            .unwrap()
            .contains(&json!("hooks-effective-end-v1")),
        "{info}"
    );
}
