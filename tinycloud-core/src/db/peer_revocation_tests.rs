//! TC-4321: a peer delegation A -> B that A revoked must stop authorizing B,
//! also after B posts the same signed bytes again (what a fresh Courier CLI
//! process does on every run). B's own owner -> B grant over the same prefix
//! is a separate authority and keeps working: revoking A -> B does not touch it.
use super::*;
use crate::models::revocation::RevocationCode;
use crate::storage::memory::{MemoryStaging, MemoryStore};
use tinycloud_auth::{
    authorization::{TinyCloudDelegation, TinyCloudRevocation},
    ipld_core::cid::Cid,
    resolver::DID_METHODS,
    ssi::{
        claims::jwt::NumericDate,
        jwk::{Algorithm, JWK},
        ucan::Payload,
    },
    ucan_capabilities_object::Capabilities,
};

type Db = SpaceDatabase<sea_orm::DatabaseConnection, MemoryStore, StaticSecret>;
type Refusal = TxError<MemoryStore, StaticSecret>;

fn did_vm(key: &JWK) -> (String, String) {
    let did = DID_METHODS.generate(key, "key").unwrap().to_string();
    let vm = format!("{did}#{}", did.rsplit(':').next().unwrap());
    (did, vm)
}

fn did(key: &JWK) -> String {
    did_vm(key).0
}

fn now() -> i64 {
    OffsetDateTime::now_utc().unix_timestamp()
}

fn cid_of(token: &str) -> Cid {
    crate::hash::hash(token.as_bytes()).to_cid(0x55)
}

fn deleg(token: &str) -> Delegation {
    Delegation::from_header_ser::<TinyCloudDelegation>(token).unwrap()
}

/// `issuer` grants `audience` one `ability` on `resource`, citing `proof`.
fn ucan(
    issuer: &JWK,
    audience: &str,
    resource: &str,
    ability: &str,
    proof: Vec<Cid>,
    expiry: i64,
) -> String {
    let mut caps = Capabilities::<serde_json::Value>::new();
    caps.with_action(
        resource.parse().unwrap(),
        ability.parse().unwrap(),
        [std::collections::BTreeMap::new()],
    );
    Payload::<serde_json::Value> {
        issuer: did_vm(issuer).1.parse().unwrap(),
        audience: audience.parse().unwrap(),
        not_before: Some(NumericDate::try_from_seconds((now() - 60) as f64).unwrap()),
        expiration: NumericDate::try_from_seconds(expiry as f64).unwrap(),
        nonce: Some(format!("tc4321-{}", rand::random::<u64>())),
        facts: None,
        proof,
        attenuation: caps,
    }
    .sign(Algorithm::EdDSA, issuer)
    .unwrap()
    .encode()
    .unwrap()
}

/// A same-owner Courier pair: the owner grants agents A and B kv on every
/// mailbox under `to/` (courier AGENT_GRANT); A grants B its mailbox prefix.
struct Fx {
    db: Db,
    owner: JWK,
    a: JWK,
    b: JWK,
    space: SpaceId,
    created: i64,
    root_a: String,
    root_b: String,
    peer: String,
    _dir: tempfile::TempDir,
}

impl Fx {
    async fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let url = format!(
            "sqlite://{}?mode=rwc",
            dir.path().join("tc4321.sqlite").display()
        );
        let db: Db = SpaceDatabase::new(
            sea_orm::Database::connect(url).await.unwrap(),
            MemoryStore::default(),
            StaticSecret::new(vec![0x42; 32]).unwrap(),
        )
        .await
        .map_err(|error| error.to_string())
        .unwrap();
        let owner = JWK::generate_ed25519().unwrap();
        let a = JWK::generate_ed25519().unwrap();
        let b = JWK::generate_ed25519().unwrap();
        let space: SpaceId = format!(
            "tinycloud:{}:agents",
            did(&owner).strip_prefix("did:").unwrap()
        )
        .parse()
        .unwrap();
        space::ActiveModel {
            id: Set(SpaceIdWrap(space.clone())),
        }
        .insert(&db.conn)
        .await
        .unwrap();
        let created = now();
        let kv = kv_resource(&space, "to/");
        let root_a = ucan(
            &owner,
            &did(&a),
            &kv,
            "tinycloud.kv/get",
            vec![],
            created + 3600,
        );
        let root_b = ucan(
            &owner,
            &did(&b),
            &kv,
            "tinycloud.kv/get",
            vec![],
            created + 3600,
        );
        let peer = ucan(
            &a,
            &did(&b),
            &kv_resource(&space, "to/b/threads/"),
            "tinycloud.kv/get",
            vec![cid_of(&root_a)],
            created + 1800,
        );
        let fx = Fx {
            db,
            owner,
            a,
            b,
            space,
            created,
            root_a,
            root_b,
            peer,
            _dir: dir,
        };
        for token in [&fx.root_a, &fx.root_b, &fx.peer] {
            registered(fx.delegate(token).await, "setup");
        }
        fx
    }

    async fn delegate(&self, token: &str) -> Result<(), Refusal> {
        self.db.delegate(deleg(token)).await.map(|_| ())
    }

    async fn delegate_batch(&self, tokens: &[&str]) -> Result<(), Refusal> {
        self.db
            .delegate_batch(tokens.iter().map(|token| deleg(token)).collect())
            .await
            .map(|_| ())
    }

    /// `revoker` revokes `token`, carrying `proof`.
    async fn revoke(&self, revoker: &JWK, token: &str, proof: Vec<Cid>) {
        let revocation = ucan(
            revoker,
            &did(&self.owner),
            &format!("urn:cid:{}", cid_of(token)),
            "tinycloud.delegation/revoke",
            proof,
            self.created + 600,
        );
        self.db
            .revoke(Revocation::from_header_ser::<TinyCloudRevocation>(&revocation).unwrap())
            .await
            .map_err(|error| error.to_string())
            .unwrap();
    }

    /// `key` invokes `kv/get` on a message in B's mailbox under `proof`.
    async fn invoke(&self, key: &JWK, proof: Cid) -> Result<(), String> {
        let signed = make_invocation(
            vec![(
                self.space.clone().to_resource(
                    "kv".parse().unwrap(),
                    Some("to/b/threads/msg".parse().unwrap()),
                    None,
                    None,
                ),
                vec!["tinycloud.kv/get".parse().unwrap()],
            )],
            &proof,
            key,
            &did_vm(key).1,
            (now() + 120) as f64,
            InvocationOptions::default(),
        )
        .unwrap();
        let encoded = signed.encode().unwrap().into_bytes();
        let invocation = crate::events::SerializedEvent(
            crate::util::InvocationInfo::try_from(signed).unwrap(),
            encoded,
        );
        self.db
            .invoke::<MemoryStaging>(invocation, HashMap::new())
            .await
            .map(|_| ())
            .map_err(|error| error.to_string())
    }
}

fn kv_resource(space: &SpaceId, path: &str) -> String {
    space
        .clone()
        .to_resource(
            "kv".parse().unwrap(),
            Some(path.parse().unwrap()),
            None,
            None,
        )
        .to_string()
}

fn invoke_refused(result: Result<(), String>, what: &str) {
    match result {
        Ok(()) => panic!("{what}: a revoked delegation still authorized kv/get"),
        Err(error) => assert!(
            error.starts_with("delegation-revoked: "),
            "{what}: unexpected refusal {error}"
        ),
    }
}

fn registered(result: Result<(), Refusal>, what: &str) {
    if let Err(error) = result {
        panic!("{what}: refused {error}");
    }
}

fn delegate_refused(result: Result<(), Refusal>, code: RevocationCode, what: &str) {
    match result {
        Ok(()) => panic!("{what}: a revoked delegation was answered as registered"),
        Err(error) => assert_eq!(error.revocation_code(), Some(code), "{what}: {error}"),
    }
}

#[tokio::test]
async fn revoked_peer_delegation_stays_refused_after_repost_while_own_grant_reads() {
    let f = Fx::new().await;
    f.invoke(&f.b, cid_of(&f.peer)).await.unwrap();
    f.invoke(&f.b, cid_of(&f.root_b)).await.unwrap();

    // A revokes A -> B with its own root as proof (`revokeIssued`).
    f.revoke(&f.a, &f.peer, vec![cid_of(&f.root_a)]).await;
    invoke_refused(f.invoke(&f.b, cid_of(&f.peer)).await, "after revoke");

    // A fresh B process posts the revoked bytes again; whatever the answer,
    // the revocation stands.
    let _ = f.delegate(&f.peer).await;
    invoke_refused(f.invoke(&f.b, cid_of(&f.peer)).await, "after repost");

    // What QA observed: B's own same-owner grant still reads A's mailbox.
    f.invoke(&f.b, cid_of(&f.root_b)).await.unwrap();

    // Only the owner revoking owner -> B cuts that read off.
    f.revoke(&f.owner, &f.root_b, vec![]).await;
    invoke_refused(
        f.invoke(&f.b, cid_of(&f.root_b)).await,
        "owner grant revoked",
    );
    let _ = f.delegate(&f.root_b).await;
    invoke_refused(
        f.invoke(&f.b, cid_of(&f.root_b)).await,
        "owner grant reposted",
    );
}

/// `POST /delegate` of already-stored bytes answers as registered only while
/// the delegation and its chain are unrevoked: a client re-activating a
/// revoked delegation learns it is revoked instead of getting a 200.
#[tokio::test]
async fn reposting_a_revoked_delegation_is_refused() {
    let f = Fx::new().await;
    let c = JWK::generate_ed25519().unwrap();
    let child = ucan(
        &f.b,
        &did(&c),
        &kv_resource(&f.space, "to/b/threads/"),
        "tinycloud.kv/get",
        vec![cid_of(&f.peer)],
        f.created + 1200,
    );
    registered(f.delegate(&child).await, "child");

    // Never revoked: a re-post is answered as registered, on both paths.
    for token in [&f.root_a, &f.peer, &child] {
        registered(f.delegate(token).await, "unrevoked repost, single");
        registered(f.delegate_batch(&[token]).await, "unrevoked repost, batch");
    }

    f.revoke(&f.a, &f.peer, vec![cid_of(&f.root_a)]).await;

    delegate_refused(
        f.delegate(&f.peer).await,
        RevocationCode::DelegationRevoked,
        "revoked leaf, single",
    );
    delegate_refused(
        f.delegate_batch(&[&f.peer]).await,
        RevocationCode::DelegationRevoked,
        "revoked leaf, batch",
    );
    delegate_refused(
        f.delegate(&child).await,
        RevocationCode::ParentRevoked,
        "child of the revoked leaf, single",
    );
    delegate_refused(
        f.delegate_batch(&[&child]).await,
        RevocationCode::ParentRevoked,
        "child of the revoked leaf, batch",
    );

    // Unrevoked delegations next to it are still answered as registered.
    for token in [&f.root_a, &f.root_b] {
        registered(f.delegate(token).await, "sibling repost, single");
        registered(f.delegate_batch(&[token]).await, "sibling repost, batch");
    }
}
